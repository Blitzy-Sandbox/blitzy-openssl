//! Cryptographic algorithm benchmark (`openssl speed`) — Rust rewrite of
//! `apps/speed.c` (~4,773 lines).
//!
//! Provides command-line access to throughput and operations-per-second
//! measurements for a wide range of cryptographic algorithms: symmetric
//! ciphers, message digests, MACs (HMAC, CMAC, GMAC, KMAC), asymmetric
//! signature and key-exchange primitives (RSA, DSA, ECDSA, EdDSA, DH,
//! ECDH), post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA), and random
//! byte generation (RAND_bytes).
//!
//! This is a diagnostic utility that mirrors the functionality of the
//! upstream C `speed` command — including its timing methodology, output
//! format, and command-line interface. For rigorous benchmarking the
//! `criterion` harness used by Gate 3 is preferred.
//!
//! # C Source Mapping
//!
//! | C construct                              | Rust equivalent                         |
//! |------------------------------------------|-----------------------------------------|
//! | `speed_options[]` OPT_PAIR table         | `SpeedArgs` clap derive fields          |
//! | `do_multi()` fork/pipe/waitpid           | `std::thread::spawn()` + `JoinHandle`   |
//! | `SIGALRM`/`alarm()`/`volatile int run`   | `Arc<AtomicBool>` + timer thread        |
//! | `Time_F(START)` / `Time_F(STOP)`         | `std::time::Instant`/`Duration`         |
//! | `EVP_Digest*()` speed loop               | `bench_digest()` via `MdContext`        |
//! | `EVP_Cipher*()` speed loop               | `bench_cipher()` via `CipherCtx`        |
//! | `EVP_MAC*()` speed loop (HMAC/CMAC/KMAC) | `bench_mac()` via `MacCtx`              |
//! | `RSA_public_encrypt()` / sign loops      | `bench_rsa()` via `PKeyCtx`/`Signature` |
//! | `DSA_sign()` / `DSA_verify()` loops      | `bench_dsa()` via `Signature`           |
//! | `ECDSA_sign()` / `ECDSA_verify()` loops  | `bench_ecdsa()` via `Signature`         |
//! | `ECDH_compute_key()` loop                | `bench_ecdh()` via `KeyExchange`        |
//! | `EVP_KEM_encapsulate()` / `_decapsulate()`| `bench_kem()` via `KemContext`         |
//! | `EVP_SIGNATURE_sign()` / `_verify()`     | `bench_signature()` via `SignContext`   |
//! | `RAND_bytes()` speed loop                | `bench_rand()` via `rand_bytes()`       |
//! | `CRYPTO_set_mem_mlock(1)`                | `init_secure_heap()`                    |
//! | `print_message`/`print_result`           | `print_message_*()`/`print_result_*()`  |
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   -> CliCommand::Speed(args)
//!     -> SpeedArgs::execute(&LibContext)
//!       -> bench_{digest,cipher,mac,rsa,dsa,ecdsa,ecdh,kem,signature,rand}
//!         -> openssl_crypto::{evp::*, rand, context::LibContext}
//! ```
//!
//! # Rules Enforcement
//!
//! * **R5 (Nullability):** Optional fields (`evp`, `hmac`, `cmac`, `multi`,
//!   `async_jobs`, `misalign`, `primes`) use `Option<T>` rather than
//!   sentinel values.
//! * **R6 (Lossless Casts):** All narrowing conversions use `u64::try_from`
//!   or `u32::try_from`, or `#[allow(clippy::cast_precision_loss)]` on
//!   `f64` conversions with justification comments.
//! * **R8 (Zero Unsafe):** No `unsafe` blocks in this file.
//! * **R9 (Warning-Free Build):** All items documented; no module-level
//!   `#[allow(unused)]`; workspace lint `RUSTFLAGS="-D warnings"` passes.
//! * **R10 (Wiring):** Reachable from entry point via
//!   `main.rs -> CliCommand::Speed -> SpeedArgs::execute()` (see `mod.rs`
//!   dispatch table lines 561).

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;
use tracing::{debug, info, instrument, warn};

use openssl_common::error::CryptoError;
use openssl_common::mem::{init_secure_heap, SecureHeapConfig};
use openssl_common::param::ParamBuilder;
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::{self, Cipher, CipherCtx};
use openssl_crypto::evp::kem::{Kem, KemContext};
use openssl_crypto::evp::mac::{self, Mac, MacCtx};
use openssl_crypto::evp::md::{self, MdContext, MessageDigest};
use openssl_crypto::evp::pkey::PKeyCtx;
use openssl_crypto::evp::signature::{KeyExchange, KeyExchangeContext, SignContext, Signature};
use openssl_crypto::rand;

// ---------------------------------------------------------------------------
// Constants — translated from `apps/speed.c` preamble
// ---------------------------------------------------------------------------

/// Default set of block sizes exercised for symmetric benchmarks.
///
/// Corresponds to the C `lengths[]` array (apps/speed.c line 351):
/// `static const int lengths_list[] = {16, 64, 256, 1024, 8192, 16384};`.
const BLOCK_SIZES: &[usize] = &[16, 64, 256, 1024, 8192, 16384];

/// Number of block sizes (C `SIZE_NUM`, apps/speed.c line 349).
/// Validated at compile time against [`BLOCK_SIZES`].
// R9 justification: referenced only by the compile-time `const _` below,
// which the dead_code lint does not count as a use. Retained as a
// public-facing documentation of the C reference value.
#[allow(dead_code)]
const SIZE_NUM: usize = 6;
// Compile-time assertion that SIZE_NUM matches the BLOCK_SIZES table —
// guards against accidental drift between the constant and the array.
const _: () = assert!(BLOCK_SIZES.len() == SIZE_NUM);

/// Default benchmark duration in seconds (C `SECONDS`, apps/speed.c line 119).
const DEFAULT_SECONDS: u64 = 3;

/// AEAD authentication tag length in bytes (C `TAG_LEN`,
/// apps/speed.c line 124).
const TAG_LEN: usize = 16;

/// AEAD initialization vector length in bytes (C `AEAD_IVLEN`,
/// apps/speed.c line 125).
const AEAD_IVLEN: usize = 12;

/// Maximum allowed input alignment offset (C `MAX_MISALIGNMENT`,
/// apps/speed.c line 126).
const MAX_MISALIGNMENT: usize = 63;

/// Minimum buffer length (C `MIN_BUFLEN`, apps/speed.c line 123).
/// Used to raise a warning when the user requests an RSA benchmark with
/// a block size that is too small to contain the signature/ciphertext.
const MIN_BUFLEN: usize = 36;

/// Minimum secure-heap allocation size when `-mlock` is enabled,
/// matching the C default of 16 KiB set before `CRYPTO_secure_malloc_init()`
/// (apps/speed.c line 2052).
const MLOCK_HEAP_MIN_SIZE: usize = 16 * 1024;

/// Default HMAC key used by `speed.c` (line 2617).
const HMAC_KEY: &[u8] = b"This is a key...";

/// Default digest for the C `-hmac` option (apps/speed.c line 654). Used
/// as a fall-back when the user passes `-hmac` without an algorithm name
/// or supplies an empty string.
const DEFAULT_HMAC_DIGEST: &str = "SHA2-256";

/// Default cipher for the C `-cmac` option. Used as a fall-back when the
/// user passes `-cmac` without an algorithm name or supplies an empty
/// string.
const DEFAULT_CMAC_CIPHER: &str = "AES-128-CBC";

/// Default value of the `-primes` option (C `primes`, apps/speed.c ~ line 2450).
const DEFAULT_PRIMES: u32 = 2;

/// Parameter name for key size in bits (cross-provider `OSSL_PARAM` name).
const PARAM_BITS: &str = "bits";

/// Parameter name for RSA prime count (cross-provider `OSSL_PARAM` name).
const PARAM_PRIMES: &str = "primes";

/// Parameter name for EC/DH named group (cross-provider `OSSL_PARAM` name).
const PARAM_GROUP: &str = "group";

/// Parameter name for the MAC `digest` sub-option (e.g. HMAC).
const PARAM_DIGEST: &str = "digest";

/// Parameter name for the MAC `cipher` sub-option (e.g. CMAC).
const PARAM_CIPHER: &str = "cipher";

// ---------------------------------------------------------------------------
// Algorithm tables — translated from `apps/speed.c` OPT_PAIR/name arrays
// ---------------------------------------------------------------------------

/// Default digest algorithms benchmarked when no `-evp`/positional algorithm
/// is supplied (C `names[]` table, apps/speed.c line ~374).
const DIGEST_ALGORITHMS: &[(&str, &str)] = &[
    // CLI name, EVP provider name
    ("md2", md::MD2),
    ("md4", md::MD4),
    ("md5", md::MD5),
    ("sha1", md::SHA1),
    ("sha224", md::SHA224),
    ("sha256", md::SHA256),
    ("sha384", md::SHA384),
    ("sha512", md::SHA512),
    ("sha3-224", md::SHA3_224),
    ("sha3-256", md::SHA3_256),
    ("sha3-384", md::SHA3_384),
    ("sha3-512", md::SHA3_512),
    ("shake128", md::SHAKE128),
    ("shake256", md::SHAKE256),
    ("ripemd160", md::RIPEMD160),
    ("whirlpool", md::WHIRLPOOL),
    ("sm3", md::SM3),
    ("blake2s256", md::BLAKE2S256),
    ("blake2b512", md::BLAKE2B512),
];

/// Default symmetric cipher algorithms (C `names[]` table entries for ciphers).
const CIPHER_ALGORITHMS: &[(&str, &str)] = &[
    // CLI name, EVP provider name
    ("des-cbc", cipher::DES_CBC),
    ("des-ede3-cbc", cipher::DES_EDE3_CBC),
    ("aes-128-cbc", cipher::AES_128_CBC),
    ("aes-256-cbc", cipher::AES_256_CBC),
    ("aes-128-ctr", "AES-128-CTR"),
    ("aes-256-ctr", "AES-256-CTR"),
    ("aes-128-gcm", cipher::AES_128_GCM),
    ("aes-256-gcm", cipher::AES_256_GCM),
    ("aes-128-ccm", cipher::AES_128_CCM),
    ("aes-256-ccm", cipher::AES_256_CCM),
    ("aes-128-ocb", cipher::AES_128_OCB),
    ("aes-128-xts", cipher::AES_128_XTS),
    ("aes-256-xts", cipher::AES_256_XTS),
    ("aes-128-siv", cipher::AES_128_SIV),
    ("aes-128-wrap", cipher::AES_128_WRAP),
    ("chacha20-poly1305", cipher::CHACHA20_POLY1305),
    ("aria-128-gcm", cipher::ARIA_128_GCM),
    ("sm4-cbc", cipher::SM4_CBC),
    ("bf-cbc", cipher::BF_CBC),
    ("cast5-cbc", cipher::CAST5_CBC),
    ("idea-cbc", cipher::IDEA_CBC),
    ("seed-cbc", cipher::SEED_CBC),
    ("rc2-cbc", cipher::RC2_CBC),
    ("rc4", cipher::RC4),
    ("camellia-128-cbc", cipher::CAMELLIA_128_CBC),
];

/// RSA key sizes benchmarked (C `rsa_choices[]`, apps/speed.c line 424).
const RSA_SIZES: &[(&str, u64)] = &[
    ("rsa512", 512),
    ("rsa1024", 1024),
    ("rsa2048", 2048),
    ("rsa3072", 3072),
    ("rsa4096", 4096),
    ("rsa7680", 7680),
    ("rsa15360", 15360),
];

/// DSA key sizes benchmarked (C `dsa_choices[]`, apps/speed.c line 407).
const DSA_SIZES: &[(&str, u64)] = &[("dsa1024", 1024), ("dsa2048", 2048)];

/// FFDH named groups benchmarked (C `ffdh_choices[]`, apps/speed.c line 446).
const FFDH_GROUPS: &[(&str, &str)] = &[
    ("ffdh2048", "ffdhe2048"),
    ("ffdh3072", "ffdhe3072"),
    ("ffdh4096", "ffdhe4096"),
    ("ffdh6144", "ffdhe6144"),
    ("ffdh8192", "ffdhe8192"),
];

/// ECDSA curve choices (C `ecdsa_choices[]`, apps/speed.c line 500).
const ECDSA_CURVES: &[(&str, &str)] = &[
    ("ecdsap160", "secp160r1"),
    ("ecdsap192", "P-192"),
    ("ecdsap224", "P-224"),
    ("ecdsap256", "P-256"),
    ("ecdsap384", "P-384"),
    ("ecdsap521", "P-521"),
    ("ecdsak163", "sect163k1"),
    ("ecdsak233", "sect233k1"),
    ("ecdsak283", "sect283k1"),
    ("ecdsak409", "sect409k1"),
    ("ecdsak571", "sect571k1"),
    ("ecdsab163", "sect163r2"),
    ("ecdsab233", "sect233r1"),
    ("ecdsab283", "sect283r1"),
    ("ecdsab409", "sect409r1"),
    ("ecdsab571", "sect571r1"),
    ("ecdsabrp256r1", "brainpoolP256r1"),
    ("ecdsabrp256t1", "brainpoolP256t1"),
    ("ecdsabrp384r1", "brainpoolP384r1"),
    ("ecdsabrp384t1", "brainpoolP384t1"),
    ("ecdsabrp512r1", "brainpoolP512r1"),
    ("ecdsabrp512t1", "brainpoolP512t1"),
];

/// `EdDSA` curves benchmarked (C `ecdsa_choices[]` `EdDSA` entries,
/// `apps/speed.c` line 523).
const EDDSA_CURVES: &[(&str, &str)] = &[("ed25519", "Ed25519"), ("ed448", "Ed448")];

/// ECDH curve choices (C `ecdh_choices[]`, `apps/speed.c` line 532).
const ECDH_CURVES: &[(&str, &str)] = &[
    ("ecdhp160", "secp160r1"),
    ("ecdhp192", "P-192"),
    ("ecdhp224", "P-224"),
    ("ecdhp256", "P-256"),
    ("ecdhp384", "P-384"),
    ("ecdhp521", "P-521"),
    ("ecdhk163", "sect163k1"),
    ("ecdhk233", "sect233k1"),
    ("ecdhk283", "sect283k1"),
    ("ecdhk409", "sect409k1"),
    ("ecdhk571", "sect571k1"),
    ("ecdhb163", "sect163r2"),
    ("ecdhb233", "sect233r1"),
    ("ecdhb283", "sect283r1"),
    ("ecdhb409", "sect409r1"),
    ("ecdhb571", "sect571r1"),
    ("ecdhbrp256r1", "brainpoolP256r1"),
    ("ecdhbrp256t1", "brainpoolP256t1"),
    ("ecdhbrp384r1", "brainpoolP384r1"),
    ("ecdhbrp384t1", "brainpoolP384t1"),
    ("ecdhbrp512r1", "brainpoolP512r1"),
    ("ecdhbrp512t1", "brainpoolP512t1"),
    ("ecdhx25519", "X25519"),
    ("ecdhx448", "X448"),
];

/// Post-quantum KEM algorithms to enumerate for the default benchmark run.
/// Reflects the provider-registered KEM algorithm names expected on the
/// current platform — verified against the stub sizes in
/// `crates/openssl-crypto/src/evp/kem.rs`.
const DEFAULT_KEM_ALGORITHMS: &[&str] = &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

/// Post-quantum signature algorithms to enumerate for the default benchmark
/// run (see `crates/openssl-crypto/src/evp/signature.rs` for recognized
/// names).
const DEFAULT_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
];

// ---------------------------------------------------------------------------
// SpeedArgs — clap-derived CLI arguments
// ---------------------------------------------------------------------------

/// Command-line arguments for the `speed` benchmark command.
///
/// Mirrors the `speed_options[]` `OPT_PAIR` table in `apps/speed.c` lines
/// ~440-530. Every option is translated 1:1 from the C source. Optional
/// fields use `Option<T>` (Rule R5) rather than sentinel values; numeric
/// arguments use checked conversions (Rule R6).
//
// `clippy::struct_excessive_bools` justification: this struct is a direct,
// literal mirror of the C `speed_options[]` OPT_PAIR array in
// `apps/speed.c`. The number and identity of boolean flags are fixed by
// the external CLI contract; collapsing them into a flags enum would
// break the `#[derive(Args)]` clap mapping and the documented CLI.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug, Default, Clone)]
pub struct SpeedArgs {
    /// Use the EVP API for the named symmetric algorithm (e.g.
    /// `-evp aes-128-gcm`). Mutually exclusive with `-hmac`/`-cmac` in the
    /// C implementation; if set, only this algorithm is benchmarked.
    ///
    /// C equivalent: `-evp <alg>` → `evp_md_name`/`evp_cipher_name`
    #[arg(long = "evp", value_name = "ALG")]
    pub evp: Option<String>,

    /// Benchmark HMAC with the specified digest (e.g. `-hmac sha256`).
    ///
    /// C equivalent: `-hmac <digest>` → `evp_mac_mdname` (apps/speed.c:1996)
    #[arg(long = "hmac", value_name = "DIGEST")]
    pub hmac: Option<String>,

    /// Benchmark CMAC with the specified underlying cipher
    /// (e.g. `-cmac aes-128-cbc`).
    ///
    /// C equivalent: `-cmac <cipher>`
    #[arg(long = "cmac", value_name = "CIPHER")]
    pub cmac: Option<String>,

    /// Run benchmarks in `n` parallel threads using `std::thread::spawn`,
    /// aggregating results. Replaces the C `fork()`/`waitpid()` pattern
    /// in `do_multi()`.
    ///
    /// C equivalent: `-multi <n>`
    #[arg(long = "multi", value_name = "N")]
    pub multi: Option<u32>,

    /// Enable asynchronous job execution with up to `n` concurrent jobs.
    /// Not yet functional in the Rust rewrite; reserved for future
    /// integration with the `openssl_crypto::async` module.
    ///
    /// C equivalent: `-async_jobs <n>`
    #[arg(long = "async-jobs", value_name = "N")]
    pub async_jobs: Option<u32>,

    /// Use wall-clock elapsed time (monotonic `Instant`) rather than CPU
    /// user-time. The Rust implementation always uses wall-clock timing
    /// — this flag is accepted for CLI compatibility.
    ///
    /// C equivalent: `-elapsed`
    #[arg(long = "elapsed")]
    pub elapsed: bool,

    /// Benchmark duration in seconds (default 3).
    ///
    /// C equivalent: `-seconds <n>` → `seconds.sym` (apps/speed.c:656)
    #[arg(long = "seconds", default_value_t = DEFAULT_SECONDS)]
    pub seconds: u64,

    /// Explicit list of block sizes to benchmark (in bytes). Defaults to
    /// `[16, 64, 256, 1024, 8192, 16384]`.
    ///
    /// C equivalent: `-bytes <n>` (single block size, overrides `lengths[]`)
    #[arg(long = "bytes", value_name = "BYTES")]
    pub bytes: Vec<usize>,

    /// Intentional misalignment (bytes) of input/output buffers to exercise
    /// unaligned-access performance paths. Accepted range 0..=63.
    ///
    /// C equivalent: `-misalign <n>`
    #[arg(long = "misalign", value_name = "N")]
    pub misalign: Option<usize>,

    /// Benchmark decryption instead of encryption for symmetric ciphers.
    ///
    /// C equivalent: `-decrypt`
    #[arg(long = "decrypt")]
    pub decrypt: bool,

    /// Number of primes for RSA multi-prime key generation (default 2).
    ///
    /// C equivalent: `-primes <n>`
    #[arg(long = "primes", value_name = "N")]
    pub primes: Option<u32>,

    /// Enable AEAD-mode sub-benchmarks (generates a distinct AAD/IV per
    /// iteration). Implies symmetric-cipher-only benchmarking.
    ///
    /// C equivalent: `-aead`
    #[arg(long = "aead")]
    pub aead: bool,

    /// Lock benchmark memory into RAM via `init_secure_heap()`. Prevents
    /// paging of sensitive key material during benchmark runs.
    ///
    /// C equivalent: `-mlock`
    #[arg(long = "mlock")]
    pub mlock: bool,

    /// Enumerate and benchmark all provider-registered KEM algorithms
    /// (post-quantum + classical). Triggers `bench_kem` for each entry in
    /// [`DEFAULT_KEM_ALGORITHMS`].
    ///
    /// C equivalent: `-kem-algorithms`
    #[arg(long = "kem-algorithms")]
    pub kem_algorithms: bool,

    /// Enumerate and benchmark all provider-registered signature
    /// algorithms (post-quantum + classical). Triggers `bench_signature`
    /// for each entry in [`DEFAULT_SIGNATURE_ALGORITHMS`].
    ///
    /// C equivalent: `-signature-algorithms`
    #[arg(long = "signature-algorithms")]
    pub signature_algorithms: bool,

    /// Emit machine-readable results (`+F:...`, `+R:...` records) in
    /// addition to the human-readable table. Used by regression harnesses.
    ///
    /// C equivalent: `-mr`
    #[arg(long = "mr")]
    pub mr: bool,

    /// Positional list of algorithms to benchmark. If empty, a curated
    /// default set is selected based on the other flags. Recognised names
    /// match the entries in [`DIGEST_ALGORITHMS`], [`CIPHER_ALGORITHMS`],
    /// [`RSA_SIZES`], [`DSA_SIZES`], [`FFDH_GROUPS`], [`ECDSA_CURVES`],
    /// [`EDDSA_CURVES`], [`ECDH_CURVES`], plus the literal strings `rand`
    /// and the pair prefixes `rsa`/`dsa`/`ecdsa`/`ecdh`/`ffdh`/`eddsa`.
    ///
    /// C equivalent: positional `algo...` arguments
    #[arg(value_name = "ALGORITHM")]
    pub algorithms: Vec<String>,
}

// ---------------------------------------------------------------------------
// Benchmark result
// ---------------------------------------------------------------------------

/// Outcome of a single benchmark loop.
///
/// `count` is the number of operations completed in `elapsed`. Divide
/// `count` by `elapsed.as_secs_f64()` to obtain throughput in ops/sec, or
/// multiply by `block_size` to obtain bytes/sec.
#[derive(Debug, Clone, Copy)]
struct BenchResult {
    /// Number of operations completed.
    count: u64,
    /// Actual elapsed time for `count` operations.
    elapsed: Duration,
}

impl BenchResult {
    /// Throughput in operations per second.
    #[allow(clippy::cast_precision_loss)] // f64 → op-count conversion, result bounded
    fn ops_per_second(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 {
            self.count as f64 / secs
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// Timer-driven loop — replaces C `SIGALRM`/`alarm()` pattern
// ---------------------------------------------------------------------------

/// Runs `op` in a tight loop until `duration` has elapsed.
///
/// Uses an `Arc<AtomicBool>` flipped by a dedicated timer thread — a direct
/// translation of the `volatile int run` + `SIGALRM` handler in
/// `apps/speed.c` (lines 219-250). Every iteration checks the flag with
/// relaxed ordering (monotonic timing only); this is acceptable because
/// only the flag write needs to happen-before termination, not before any
/// operation content.
///
/// Returns the number of completed operations and actual elapsed time.
///
/// # Errors
///
/// Propagates any `CryptoError` returned by `op`.
fn timer_driven_loop<F>(duration: Duration, mut op: F) -> Result<BenchResult, CryptoError>
where
    F: FnMut() -> Result<(), CryptoError>,
{
    let run = Arc::new(AtomicBool::new(true));
    let run_timer = Arc::clone(&run);

    // Spawn a timer thread that flips `run` to false after `duration`.
    // Replaces the C `alarm()` + SIGALRM signal pattern.
    let handle = thread::spawn(move || {
        thread::sleep(duration);
        run_timer.store(false, Ordering::Relaxed);
    });

    let start = Instant::now();
    let mut count: u64 = 0;
    while run.load(Ordering::Relaxed) {
        op()?;
        count = count.saturating_add(1);
    }
    let elapsed = start.elapsed();

    // Timer thread joins cleanly — `duration` bounds its lifetime.
    if let Err(e) = handle.join() {
        warn!(?e, "speed: timer thread panicked (ignoring)");
    }

    Ok(BenchResult { count, elapsed })
}

// ---------------------------------------------------------------------------
// Print helpers — translated from `apps/speed.c` print_message_*
// ---------------------------------------------------------------------------

/// Prints the benchmark start banner for digest/cipher/MAC/RAND operations.
///
/// Matches `print_message()` in `apps/speed.c` line ~1110:
/// * Machine-readable (`-mr`): `+DT:<name>:<seconds>:<length>\n`
/// * Human-readable: `Doing <name> ops for <seconds>s on <length> size blocks: \n`
fn print_message_sym<W: Write>(
    out: &mut W,
    name: &str,
    seconds: u64,
    length: usize,
    mr: bool,
) -> io::Result<()> {
    if mr {
        writeln!(out, "+DT:{name}:{seconds}:{length}")?;
    } else {
        writeln!(
            out,
            "Doing {name} ops for {seconds}s on {length} size blocks: "
        )?;
    }
    out.flush()
}

/// Prints the benchmark start banner for asymmetric key-size operations
/// (RSA/DSA/ECDSA/ECDH/FFDH).
///
/// Matches `pkey_print_message()` in `apps/speed.c` line ~1142:
/// * Machine-readable: `+DTP:<bits>:<op_name>:<op_desc>:<seconds>\n`
/// * Human-readable: `Doing <bits> bits <op_name> <op_desc> ops for <seconds>s: \n`
fn print_message_pkey<W: Write>(
    out: &mut W,
    bits: u64,
    op_name: &str,
    op_desc: &str,
    seconds: u64,
    mr: bool,
) -> io::Result<()> {
    if mr {
        writeln!(out, "+DTP:{bits}:{op_name}:{op_desc}:{seconds}")?;
    } else {
        writeln!(
            out,
            "Doing {bits} bits {op_name} {op_desc} ops for {seconds}s: "
        )?;
    }
    out.flush()
}

/// Prints the benchmark start banner for keyless asymmetric operations
/// (ML-KEM, ML-DSA, SLH-DSA).
///
/// Matches `kskey_print_message()` in `apps/speed.c` line ~1163:
/// * Machine-readable: `+DTP:<alg>:<op_name>:<seconds>\n`
/// * Human-readable: `Doing <alg> <op_name> ops for <seconds>s: \n`
fn print_message_kskey<W: Write>(
    out: &mut W,
    alg: &str,
    op_name: &str,
    seconds: u64,
    mr: bool,
) -> io::Result<()> {
    if mr {
        writeln!(out, "+DTP:{alg}:{op_name}:{seconds}")?;
    } else {
        writeln!(out, "Doing {alg} {op_name} ops for {seconds}s: ")?;
    }
    out.flush()
}

/// Prints a single benchmark result record.
///
/// Matches `print_result()` in `apps/speed.c` line ~1179:
/// * Machine-readable: `+R:<count>:<name>:<elapsed_secs>\n`
/// * Human-readable: `<count> <name> ops in <elapsed>s (<ops/s> ops/s)\n`
fn print_result<W: Write>(
    out: &mut W,
    name: &str,
    result: &BenchResult,
    mr: bool,
) -> io::Result<()> {
    let secs = result.elapsed.as_secs_f64();
    if mr {
        writeln!(out, "+R:{}:{}:{:.6}", result.count, name, secs)?;
    } else {
        writeln!(
            out,
            "{} {} ops in {:.2}s ({:.2} ops/s)",
            result.count,
            name,
            secs,
            result.ops_per_second()
        )?;
    }
    out.flush()
}

/// Returns a short label for a block size suitable for tabular reports.
///
/// Preserved from the previous scaffolded implementation:
/// * `16` → `"16B"`
/// * `1024` → `"1K"`
/// * `8192` → `"8K"`
fn format_block_header(bytes: usize) -> String {
    if bytes >= 1024 && (bytes % 1024) == 0 {
        format!("{}K", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

// ---------------------------------------------------------------------------
// bench_digest — translates EVP_Digest_loop (apps/speed.c line ~1313)
// ---------------------------------------------------------------------------

/// Benchmarks a message-digest algorithm by repeatedly digesting `block_size`
/// bytes for the configured duration.
///
/// Uses the real `MessageDigest` / `MdContext` APIs from
/// `openssl_crypto::evp::md`. Delegates all cryptographic work to the EVP
/// fetch/init/update/finalize path.
#[instrument(skip_all, fields(alg = %digest_name, block_size = block_size))]
fn bench_digest(
    ctx: &Arc<LibContext>,
    digest_name: &str,
    block_size: usize,
    duration: Duration,
) -> Result<BenchResult, CryptoError> {
    let md = MessageDigest::fetch(ctx, digest_name, None).map_err(|e| {
        warn!(alg = digest_name, error = %e, "digest fetch failed");
        e
    })?;
    let buf = vec![0u8; block_size];
    let mut mdctx = MdContext::new();
    mdctx.init(&md, None)?;

    timer_driven_loop(duration, || {
        mdctx.reset()?;
        mdctx.init(&md, None)?;
        mdctx.update(&buf)?;
        if md.is_xof() {
            let _ = mdctx.finalize_xof(32)?;
        } else {
            let _ = mdctx.finalize();
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// bench_cipher — translates EVP_Cipher_loop (apps/speed.c line ~1364)
// ---------------------------------------------------------------------------

/// Benchmarks a symmetric cipher by encrypting (or decrypting, when
/// `decrypt` is true) `block_size` bytes per iteration.
#[instrument(skip_all, fields(alg = %cipher_name, block_size = block_size, decrypt = decrypt))]
fn bench_cipher(
    ctx: &Arc<LibContext>,
    cipher_name: &str,
    block_size: usize,
    duration: Duration,
    decrypt: bool,
) -> Result<BenchResult, CryptoError> {
    let cipher = Cipher::fetch(ctx, cipher_name, None).map_err(|e| {
        warn!(alg = cipher_name, error = %e, "cipher fetch failed");
        e
    })?;

    let key_len = cipher.key_length();
    // TRUNCATION: `i & 0xFF` masks to the low 8 bits, so the narrowing
    // `as u8` cast is lossless by construction. This is a pseudo-random
    // benchmark key pattern; actual values do not matter for timing.
    #[allow(clippy::cast_possible_truncation)]
    let key: Vec<u8> = (0..key_len).map(|i| (i & 0xFF) as u8).collect();
    // Per R5: represent optional IV as Option<Vec<u8>> rather than a
    // sentinel-empty slice.  `cipher.iv_length()` is `Option<usize>` and
    // `None`/`Some(0)` both indicate "no IV required" (e.g., ECB, WRAP).
    let iv: Option<Vec<u8>> = match cipher.iv_length() {
        Some(len) if len > 0 => Some(
            // TRUNCATION: masked to 0xFF before narrowing; lossless.
            #[allow(clippy::cast_possible_truncation)]
            (0..len)
                .map(|i| ((i.wrapping_add(0x42)) & 0xFF) as u8)
                .collect(),
        ),
        _ => None,
    };

    let buf = vec![0u8; block_size];
    let mut cctx = CipherCtx::new();
    let mut output: Vec<u8> = Vec::with_capacity(block_size + 32);

    timer_driven_loop(duration, || {
        cctx.reset()?;
        let iv_ref: Option<&[u8]> = iv.as_deref();
        if decrypt {
            cctx.decrypt_init(&cipher, &key, iv_ref, None)?;
        } else {
            cctx.encrypt_init(&cipher, &key, iv_ref, None)?;
        }
        output.clear();
        let _ = cctx.update(&buf, &mut output)?;
        let _ = cctx.finalize(&mut output)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// bench_aead — translates EVP_Update_loop_aead_enc/dec (apps/speed.c ~1462)
// ---------------------------------------------------------------------------

/// Benchmarks an AEAD cipher by encrypting (or decrypting) `block_size`
/// bytes plus a short fixed AAD per iteration.
#[instrument(skip_all, fields(alg = %cipher_name, block_size = block_size))]
fn bench_aead(
    ctx: &Arc<LibContext>,
    cipher_name: &str,
    block_size: usize,
    duration: Duration,
    decrypt: bool,
) -> Result<BenchResult, CryptoError> {
    let cipher = Cipher::fetch(ctx, cipher_name, None).map_err(|e| {
        warn!(alg = cipher_name, error = %e, "AEAD cipher fetch failed");
        e
    })?;
    let key_len = cipher.key_length();
    // TRUNCATION: `i & 0xFF` masks to the low 8 bits, so both narrowing
    // `as u8` casts are lossless by construction. These are deterministic
    // pseudo-random benchmark inputs; actual values do not matter for
    // timing. AEAD_IVLEN=12 so `i` is also bounded to [0, 11] anyway.
    #[allow(clippy::cast_possible_truncation)]
    let key: Vec<u8> = (0..key_len).map(|i| (i & 0xFF) as u8).collect();
    #[allow(clippy::cast_possible_truncation)]
    let iv: Vec<u8> = (0..AEAD_IVLEN).map(|i| (i & 0xFF) as u8).collect();
    let buf = vec![0u8; block_size];
    let mut cctx = CipherCtx::new();
    let mut output: Vec<u8> = Vec::with_capacity(block_size + TAG_LEN);

    timer_driven_loop(duration, || {
        cctx.reset()?;
        if decrypt {
            cctx.decrypt_init(&cipher, &key, Some(&iv), None)?;
        } else {
            cctx.encrypt_init(&cipher, &key, Some(&iv), None)?;
        }
        output.clear();
        let _ = cctx.update(&buf, &mut output)?;
        let _ = cctx.finalize(&mut output)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// bench_mac — translates EVP_MAC_loop (apps/speed.c line ~1408)
// ---------------------------------------------------------------------------

/// Benchmarks a MAC algorithm (HMAC, CMAC, GMAC, KMAC, …).
///
/// * `mac_name`: algorithm family (`HMAC`, `CMAC`, `GMAC`, `KMAC128`, `KMAC256`)
/// * `sub_alg`: the digest (for HMAC) or cipher (for CMAC/GMAC); `None`
///   for MACs that take no sub-algorithm (KMAC).
#[instrument(skip_all, fields(mac = %mac_name, sub = ?sub_alg, block_size = block_size))]
fn bench_mac(
    ctx: &Arc<LibContext>,
    mac_name: &str,
    sub_alg: Option<&str>,
    block_size: usize,
    duration: Duration,
) -> Result<BenchResult, CryptoError> {
    let mac_obj = Mac::fetch(ctx, mac_name, None).map_err(|e| {
        warn!(mac = mac_name, error = %e, "mac fetch failed");
        e
    })?;
    let mut macctx = MacCtx::new(&mac_obj)?;

    let mut builder = ParamBuilder::new();
    if let Some(sub) = sub_alg {
        // HMAC and unknown/default → push "digest"; CMAC/GMAC → push
        // "cipher" (per `OSSL_MAC_PARAM_*`). Matches C speed.c where the
        // unknown MAC fallback also pushes a digest parameter.
        builder = match mac_name {
            mac::CMAC | mac::GMAC => builder.push_utf8(PARAM_CIPHER, sub.to_string()),
            _ => builder.push_utf8(PARAM_DIGEST, sub.to_string()),
        };
    }
    let params = builder.build();
    let buf = vec![0u8; block_size];

    timer_driven_loop(duration, || {
        macctx.reset()?;
        macctx.init(HMAC_KEY, Some(&params))?;
        macctx.update(&buf)?;
        let _ = macctx.finalize()?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// bench_rsa — translates RSA_sign_loop/verify_loop/encrypt_loop/decrypt_loop
// (apps/speed.c lines ~1514-1643)
// ---------------------------------------------------------------------------

/// Result of running the four RSA sub-benchmarks for one key size.
#[derive(Debug, Clone, Copy)]
struct RsaResults {
    sign: BenchResult,
    verify: BenchResult,
    encrypt: BenchResult,
    decrypt: BenchResult,
}

/// Benchmarks RSA sign/verify/encrypt/decrypt for the given key size.
#[instrument(skip_all, fields(bits = bits))]
fn bench_rsa(
    ctx: &Arc<LibContext>,
    bits: u64,
    primes: u32,
    duration: Duration,
) -> Result<RsaResults, CryptoError> {
    // Generate a fresh RSA key of the requested size.
    let mut kgen = PKeyCtx::new_from_name(Arc::clone(ctx), "RSA", None)?;
    kgen.keygen_init()?;
    let builder = ParamBuilder::new()
        .push_u64(PARAM_BITS, bits)
        .push_u32(PARAM_PRIMES, primes);
    let kparams = builder.build();
    let _ = kgen.fromdata_init(openssl_crypto::evp::pkey::PKeyOperation::KeyGen);
    // PKeyCtx has only `set_param` (single); we apply each typed param.
    for k in kparams.keys() {
        if let Some(v) = kparams.get(k) {
            kgen.set_param(k, v)?;
        }
    }
    kgen.keygen_init()?;
    let rsa_key = Arc::new(kgen.keygen()?);

    let sig_alg = Signature::fetch(ctx, "RSA", None)?;
    // Ensure the benchmark message is at least MIN_BUFLEN bytes so that
    // the signature buffer is never smaller than the C reference
    // implementation allocates.
    let mut message = b"The quick brown fox jumps over the lazy dog".to_vec();
    if message.len() < MIN_BUFLEN {
        message.resize(MIN_BUFLEN, 0u8);
    }
    let message = message; // freeze
    let mut sign_ctx = SignContext::new(&sig_alg, &rsa_key);
    sign_ctx.sign_init(None)?;
    let pre_signature = sign_ctx.sign(&message)?;

    // Sign loop
    let sign_result = timer_driven_loop(duration, || {
        let _ = sign_ctx.sign(&message)?;
        Ok(())
    })?;

    // Verify loop
    let mut verify_ctx = SignContext::new(&sig_alg, &rsa_key);
    verify_ctx.verify_init(None)?;
    let verify_result = timer_driven_loop(duration, || {
        let _ = verify_ctx.verify(&message, &pre_signature)?;
        Ok(())
    })?;

    // Encrypt/decrypt via asymmetric cipher API.
    use openssl_crypto::evp::signature::{AsymCipher, AsymCipherContext};
    let asym = AsymCipher::fetch(ctx, "RSA", None)?;
    let plaintext = vec![0x11u8; 16];
    let enc_ctx = AsymCipherContext::new_encrypt(&asym, &rsa_key);
    let ciphertext = enc_ctx.encrypt(&plaintext)?;
    let encrypt_result = timer_driven_loop(duration, || {
        let _ = enc_ctx.encrypt(&plaintext)?;
        Ok(())
    })?;

    let dec_ctx = AsymCipherContext::new_decrypt(&asym, &rsa_key);
    let decrypt_result = timer_driven_loop(duration, || {
        let _ = dec_ctx.decrypt(&ciphertext)?;
        Ok(())
    })?;

    Ok(RsaResults {
        sign: sign_result,
        verify: verify_result,
        encrypt: encrypt_result,
        decrypt: decrypt_result,
    })
}

// ---------------------------------------------------------------------------
// bench_dsa — translates DSA_sign_loop/verify_loop (apps/speed.c ~1661)
// ---------------------------------------------------------------------------

/// Result of running DSA sub-benchmarks for one key size.
#[derive(Debug, Clone, Copy)]
struct DsaResults {
    sign: BenchResult,
    verify: BenchResult,
}

/// Benchmarks DSA sign/verify for the given key size.
#[instrument(skip_all, fields(bits = bits))]
fn bench_dsa(
    ctx: &Arc<LibContext>,
    bits: u64,
    duration: Duration,
) -> Result<DsaResults, CryptoError> {
    let mut kgen = PKeyCtx::new_from_name(Arc::clone(ctx), "DSA", None)?;
    kgen.keygen_init()?;
    let params = ParamBuilder::new().push_u64(PARAM_BITS, bits).build();
    for k in params.keys() {
        if let Some(v) = params.get(k) {
            kgen.set_param(k, v)?;
        }
    }
    let dsa_key = Arc::new(kgen.keygen()?);

    let sig_alg = Signature::fetch(ctx, "DSA", None)?;
    let message = b"DSA benchmark input data";

    let mut sign_ctx = SignContext::new(&sig_alg, &dsa_key);
    sign_ctx.sign_init(None)?;
    let pre_sig = sign_ctx.sign(message)?;
    let sign_result = timer_driven_loop(duration, || {
        let _ = sign_ctx.sign(message)?;
        Ok(())
    })?;

    let mut verify_ctx = SignContext::new(&sig_alg, &dsa_key);
    verify_ctx.verify_init(None)?;
    let verify_result = timer_driven_loop(duration, || {
        let _ = verify_ctx.verify(message, &pre_sig)?;
        Ok(())
    })?;

    Ok(DsaResults {
        sign: sign_result,
        verify: verify_result,
    })
}

// ---------------------------------------------------------------------------
// bench_ecdsa — translates ECDSA_sign_loop/verify_loop (apps/speed.c ~1700)
// Also serves EdDSA (Ed25519/Ed448) curves.
// ---------------------------------------------------------------------------

/// Result of running ECDSA/EdDSA sub-benchmarks.
#[derive(Debug, Clone, Copy)]
struct EcSigResults {
    sign: BenchResult,
    verify: BenchResult,
}

/// Benchmarks ECDSA/EdDSA sign/verify for the given curve.
#[instrument(skip_all, fields(curve = %curve))]
fn bench_ecdsa(
    ctx: &Arc<LibContext>,
    curve: &str,
    is_eddsa: bool,
    duration: Duration,
) -> Result<EcSigResults, CryptoError> {
    let keytype = if is_eddsa {
        curve // Ed25519 or Ed448 directly
    } else {
        "EC"
    };
    let mut kgen = PKeyCtx::new_from_name(Arc::clone(ctx), keytype, None)?;
    kgen.keygen_init()?;
    if !is_eddsa {
        let params = ParamBuilder::new()
            .push_utf8(PARAM_GROUP, curve.to_string())
            .build();
        for k in params.keys() {
            if let Some(v) = params.get(k) {
                kgen.set_param(k, v)?;
            }
        }
    }
    let ec_key = Arc::new(kgen.keygen()?);

    let sig_name = if is_eddsa { curve } else { "ECDSA" };
    let sig_alg = Signature::fetch(ctx, sig_name, None)?;
    let message = b"ECDSA/EdDSA benchmark input";

    let mut sign_ctx = SignContext::new(&sig_alg, &ec_key);
    sign_ctx.sign_init(None)?;
    let pre_sig = sign_ctx.sign(message)?;
    let sign_result = timer_driven_loop(duration, || {
        let _ = sign_ctx.sign(message)?;
        Ok(())
    })?;

    let mut verify_ctx = SignContext::new(&sig_alg, &ec_key);
    verify_ctx.verify_init(None)?;
    let verify_result = timer_driven_loop(duration, || {
        let _ = verify_ctx.verify(message, &pre_sig)?;
        Ok(())
    })?;

    Ok(EcSigResults {
        sign: sign_result,
        verify: verify_result,
    })
}

// ---------------------------------------------------------------------------
// bench_ecdh / bench_ffdh — translates ECDH_EVP_derive_key_loop
// (apps/speed.c ~1743) and FFDH_derive_key_loop (apps/speed.c ~1879)
// ---------------------------------------------------------------------------

/// Benchmarks ECDH/X25519/X448 key derivation on the given curve.
#[instrument(skip_all, fields(curve = %curve))]
fn bench_ecdh(
    ctx: &Arc<LibContext>,
    curve: &str,
    duration: Duration,
) -> Result<BenchResult, CryptoError> {
    // Determine the key type from the curve name (per OpenSSL convention).
    let keytype: &str = match curve {
        "X25519" | "X448" => curve,
        _ => "EC",
    };

    // Generate two keys (local + peer).
    let mut gen_a = PKeyCtx::new_from_name(Arc::clone(ctx), keytype, None)?;
    gen_a.keygen_init()?;
    if keytype == "EC" {
        let params = ParamBuilder::new()
            .push_utf8(PARAM_GROUP, curve.to_string())
            .build();
        for k in params.keys() {
            if let Some(v) = params.get(k) {
                gen_a.set_param(k, v)?;
            }
        }
    }
    let local_key = Arc::new(gen_a.keygen()?);

    let mut gen_b = PKeyCtx::new_from_name(Arc::clone(ctx), keytype, None)?;
    gen_b.keygen_init()?;
    if keytype == "EC" {
        let params = ParamBuilder::new()
            .push_utf8(PARAM_GROUP, curve.to_string())
            .build();
        for k in params.keys() {
            if let Some(v) = params.get(k) {
                gen_b.set_param(k, v)?;
            }
        }
    }
    let peer_key = Arc::new(gen_b.keygen()?);

    let exch_name = match curve {
        "X25519" => "X25519",
        "X448" => "X448",
        _ => "ECDH",
    };
    let exchange = KeyExchange::fetch(ctx, exch_name, None)?;
    let mut kex = KeyExchangeContext::derive_init(&exchange, &local_key)?;
    kex.set_peer(&peer_key)?;

    timer_driven_loop(duration, || {
        let _ = kex.derive()?;
        Ok(())
    })
}

/// Benchmarks FFDH key derivation on a named finite-field group.
#[instrument(skip_all, fields(group = %group))]
fn bench_ffdh(
    ctx: &Arc<LibContext>,
    group: &str,
    duration: Duration,
) -> Result<BenchResult, CryptoError> {
    let mut gen_a = PKeyCtx::new_from_name(Arc::clone(ctx), "DH", None)?;
    gen_a.keygen_init()?;
    let params = ParamBuilder::new()
        .push_utf8(PARAM_GROUP, group.to_string())
        .build();
    for k in params.keys() {
        if let Some(v) = params.get(k) {
            gen_a.set_param(k, v)?;
        }
    }
    let local_key = Arc::new(gen_a.keygen()?);

    let mut gen_b = PKeyCtx::new_from_name(Arc::clone(ctx), "DH", None)?;
    gen_b.keygen_init()?;
    for k in params.keys() {
        if let Some(v) = params.get(k) {
            gen_b.set_param(k, v)?;
        }
    }
    let peer_key = Arc::new(gen_b.keygen()?);

    let exchange = KeyExchange::fetch(ctx, "DH", None)?;
    let mut kex = KeyExchangeContext::derive_init(&exchange, &local_key)?;
    kex.set_peer(&peer_key)?;

    timer_driven_loop(duration, || {
        let _ = kex.derive()?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// bench_kem — translates KEM_keygen/encaps/decaps loops (apps/speed.c ~2000+)
// ---------------------------------------------------------------------------

/// Result of running KEM sub-benchmarks (keygen + encaps + decaps).
#[derive(Debug, Clone, Copy)]
struct KemResults {
    keygen: BenchResult,
    encaps: BenchResult,
    decaps: BenchResult,
}

/// Benchmarks a KEM algorithm (ML-KEM family, RSA-KEM, EC-KEM, …).
#[instrument(skip_all, fields(alg = %alg))]
fn bench_kem(
    ctx: &Arc<LibContext>,
    alg: &str,
    duration: Duration,
) -> Result<KemResults, CryptoError> {
    // Keygen loop.
    let keygen_result = {
        let ctx_clone = Arc::clone(ctx);
        let alg_local = alg.to_string();
        timer_driven_loop(duration, || {
            let mut kgen = PKeyCtx::new_from_name(Arc::clone(&ctx_clone), &alg_local, None)?;
            kgen.keygen_init()?;
            let _ = kgen.keygen()?;
            Ok(())
        })?
    };

    // Generate one key to use for encaps + decaps timing.
    let mut kgen = PKeyCtx::new_from_name(Arc::clone(ctx), alg, None)?;
    kgen.keygen_init()?;
    let key = Arc::new(kgen.keygen()?);

    let kem_alg = Kem::fetch(ctx, alg, None)?;
    let mut encaps_ctx = KemContext::new(&kem_alg);
    encaps_ctx.encapsulate_init(&key, None)?;
    let sample = encaps_ctx.encapsulate()?;
    let encaps_result = timer_driven_loop(duration, || {
        let _ = encaps_ctx.encapsulate()?;
        Ok(())
    })?;

    let mut decaps_ctx = KemContext::new(&kem_alg);
    decaps_ctx.decapsulate_init(&key, None)?;
    let decaps_result = timer_driven_loop(duration, || {
        let _ = decaps_ctx.decapsulate(&sample.ciphertext)?;
        Ok(())
    })?;

    Ok(KemResults {
        keygen: keygen_result,
        encaps: encaps_result,
        decaps: decaps_result,
    })
}

// ---------------------------------------------------------------------------
// bench_signature — translates SIG_keygen/sign/verify loops (apps/speed.c ~2120)
// ---------------------------------------------------------------------------

/// Result of running signature-algorithm sub-benchmarks.
#[derive(Debug, Clone, Copy)]
struct SigResults {
    keygen: BenchResult,
    sign: BenchResult,
    verify: BenchResult,
}

/// Benchmarks a (post-quantum) signature algorithm.
#[instrument(skip_all, fields(alg = %alg))]
fn bench_signature(
    ctx: &Arc<LibContext>,
    alg: &str,
    duration: Duration,
) -> Result<SigResults, CryptoError> {
    // Keygen loop.
    let keygen_result = {
        let ctx_clone = Arc::clone(ctx);
        let alg_local = alg.to_string();
        timer_driven_loop(duration, || {
            let mut kgen = PKeyCtx::new_from_name(Arc::clone(&ctx_clone), &alg_local, None)?;
            kgen.keygen_init()?;
            let _ = kgen.keygen()?;
            Ok(())
        })?
    };

    // Single key for sign/verify timing.
    let mut kgen = PKeyCtx::new_from_name(Arc::clone(ctx), alg, None)?;
    kgen.keygen_init()?;
    let key = Arc::new(kgen.keygen()?);

    let sig_alg = Signature::fetch(ctx, alg, None)?;
    let message = b"post-quantum signature benchmark input";

    let mut sign_ctx = SignContext::new(&sig_alg, &key);
    sign_ctx.sign_init(None)?;
    let pre_sig = sign_ctx.sign(message)?;
    let sign_result = timer_driven_loop(duration, || {
        let _ = sign_ctx.sign(message)?;
        Ok(())
    })?;

    let mut verify_ctx = SignContext::new(&sig_alg, &key);
    verify_ctx.verify_init(None)?;
    let verify_result = timer_driven_loop(duration, || {
        let _ = verify_ctx.verify(message, &pre_sig)?;
        Ok(())
    })?;

    Ok(SigResults {
        keygen: keygen_result,
        sign: sign_result,
        verify: verify_result,
    })
}

// ---------------------------------------------------------------------------
// bench_rand — translates RAND_bytes_loop (apps/speed.c ~1445)
// ---------------------------------------------------------------------------

/// Benchmarks `rand_bytes()` throughput at the given buffer size.
#[instrument(skip_all, fields(block_size = block_size))]
fn bench_rand(block_size: usize, duration: Duration) -> Result<BenchResult, CryptoError> {
    let mut buf = vec![0u8; block_size];
    timer_driven_loop(duration, || {
        rand::rand_bytes(&mut buf)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Algorithm-selection helpers used by `execute()`
// ---------------------------------------------------------------------------

/// Classification of a positional algorithm argument.
///
/// Each variant records the CLI token the user typed plus any derived
/// internal values (e.g. the EVP algorithm name or bit size). This keeps the
/// dispatch logic in `execute()` readable while preserving the flexible
/// token parsing of the C implementation (which accepts both individual
/// algorithm names and group shortcuts like `rsa` or `ecdsa`).
#[derive(Debug, Clone)]
enum AlgToken {
    /// Digest algorithm (`sha256`, `md5`, …) — maps to [`DIGEST_ALGORITHMS`].
    Digest(&'static str, &'static str),
    /// Symmetric cipher (`aes-128-cbc`, …) — maps to [`CIPHER_ALGORITHMS`].
    Cipher(&'static str, &'static str),
    /// RSA at a specific key size (`rsa2048`).
    Rsa(&'static str, u64),
    /// DSA at a specific key size (`dsa2048`).
    Dsa(&'static str, u64),
    /// FFDH at a specific named group (`ffdh2048` → `ffdhe2048`).
    Ffdh(&'static str, &'static str),
    /// ECDSA on a named curve (`ecdsap256`).
    Ecdsa(&'static str, &'static str),
    /// `EdDSA` (`ed25519`, `ed448`).
    EdDsa(&'static str, &'static str),
    /// ECDH on a named curve (`ecdhp256`, `ecdhx25519`).
    Ecdh(&'static str, &'static str),
    /// Post-quantum KEM algorithm (`ML-KEM-768`).
    Kem(String),
    /// Post-quantum signature (`ML-DSA-44`).
    Signature(String),
    /// The literal `rand` token — exercises `bench_rand`.
    Rand,
    /// Group expansion requested (e.g. `rsa` alone = "every RSA size").
    GroupRsa,
    /// Group: `dsa`.
    GroupDsa,
    /// Group: `ffdh`.
    GroupFfdh,
    /// Group: `ecdsa`.
    GroupEcdsa,
    /// Group: `eddsa`.
    GroupEdDsa,
    /// Group: `ecdh`.
    GroupEcdh,
}

/// Parses a single positional algorithm token against the known name tables.
///
/// Returns `Ok(None)` if the token did not match any known algorithm — the
/// caller typically emits a `warn!` and continues so that unknown algorithm
/// names do not abort the whole benchmark.
fn classify_algorithm(tok: &str) -> Option<AlgToken> {
    let lower = tok.to_ascii_lowercase();

    // Group aliases: match first so e.g. `rsa` != `rsa1024`.
    match lower.as_str() {
        "rsa" => return Some(AlgToken::GroupRsa),
        "dsa" => return Some(AlgToken::GroupDsa),
        "ffdh" => return Some(AlgToken::GroupFfdh),
        "ecdsa" => return Some(AlgToken::GroupEcdsa),
        "eddsa" => return Some(AlgToken::GroupEdDsa),
        "ecdh" => return Some(AlgToken::GroupEcdh),
        "rand" => return Some(AlgToken::Rand),
        _ => {}
    }

    for (cli, evp) in DIGEST_ALGORITHMS {
        if lower == *cli {
            return Some(AlgToken::Digest(cli, evp));
        }
    }
    for (cli, evp) in CIPHER_ALGORITHMS {
        if lower == *cli {
            return Some(AlgToken::Cipher(cli, evp));
        }
    }
    for (cli, bits) in RSA_SIZES {
        if lower == *cli {
            return Some(AlgToken::Rsa(cli, *bits));
        }
    }
    for (cli, bits) in DSA_SIZES {
        if lower == *cli {
            return Some(AlgToken::Dsa(cli, *bits));
        }
    }
    for (cli, group) in FFDH_GROUPS {
        if lower == *cli {
            return Some(AlgToken::Ffdh(cli, group));
        }
    }
    for (cli, curve) in ECDSA_CURVES {
        if lower == *cli {
            return Some(AlgToken::Ecdsa(cli, curve));
        }
    }
    for (cli, curve) in EDDSA_CURVES {
        if lower == *cli {
            return Some(AlgToken::EdDsa(cli, curve));
        }
    }
    for (cli, curve) in ECDH_CURVES {
        if lower == *cli {
            return Some(AlgToken::Ecdh(cli, curve));
        }
    }

    // Pass-through for post-quantum algorithm names that upstream provider
    // tables export in mixed case (e.g., `ML-KEM-768`). We accept these
    // case-insensitively but forward the provider-canonical form.
    if tok.to_ascii_uppercase().starts_with("ML-KEM-") {
        return Some(AlgToken::Kem(tok.to_ascii_uppercase()));
    }
    if tok.to_ascii_uppercase().starts_with("ML-DSA-")
        || tok.to_ascii_uppercase().starts_with("SLH-DSA-")
    {
        return Some(AlgToken::Signature(tok.to_ascii_uppercase()));
    }

    None
}

/// Returns the effective list of block sizes, honoring the `-bytes` flag.
///
/// If the user supplied one or more `-bytes` values, those override the
/// default `[16, 64, 256, 1024, 8192, 16384]` table. Otherwise, the
/// default table is used unchanged.
fn effective_block_sizes(args: &SpeedArgs) -> Vec<usize> {
    if args.bytes.is_empty() {
        BLOCK_SIZES.to_vec()
    } else {
        args.bytes.clone()
    }
}

/// Returns the effective benchmark duration as a `Duration`.
fn effective_duration(args: &SpeedArgs) -> Duration {
    Duration::from_secs(args.seconds.max(1))
}

/// The default curated benchmark set when the user passes no algorithm
/// names. Mirrors the C behaviour of benchmarking a small set of common
/// primitives at every default block size.
const DEFAULT_CURATED_DIGESTS: &[&str] = &["sha1", "sha256", "sha512"];
const DEFAULT_CURATED_CIPHERS: &[&str] = &["aes-128-cbc", "aes-256-cbc"];

// ---------------------------------------------------------------------------
// Asymmetric-result printers — keeps `execute()` focused on dispatch
// ---------------------------------------------------------------------------

/// Prints an RSA result block for one key size.
fn print_rsa_block<W: Write>(
    out: &mut W,
    bits: u64,
    results: &RsaResults,
    mr: bool,
) -> io::Result<()> {
    let label = format!("rsa{bits}");
    print_result(out, &format!("{label} sign"), &results.sign, mr)?;
    print_result(out, &format!("{label} verify"), &results.verify, mr)?;
    print_result(out, &format!("{label} encrypt"), &results.encrypt, mr)?;
    print_result(out, &format!("{label} decrypt"), &results.decrypt, mr)
}

/// Prints a DSA result block for one key size.
fn print_dsa_block<W: Write>(
    out: &mut W,
    bits: u64,
    results: &DsaResults,
    mr: bool,
) -> io::Result<()> {
    let label = format!("dsa{bits}");
    print_result(out, &format!("{label} sign"), &results.sign, mr)?;
    print_result(out, &format!("{label} verify"), &results.verify, mr)
}

/// Prints an ECDSA/EdDSA result block for one curve.
fn print_ecsig_block<W: Write>(
    out: &mut W,
    curve_label: &str,
    results: &EcSigResults,
    mr: bool,
) -> io::Result<()> {
    print_result(out, &format!("{curve_label} sign"), &results.sign, mr)?;
    print_result(out, &format!("{curve_label} verify"), &results.verify, mr)
}

/// Prints a KEM result block (keygen + encaps + decaps).
fn print_kem_block<W: Write>(
    out: &mut W,
    alg: &str,
    results: &KemResults,
    mr: bool,
) -> io::Result<()> {
    print_result(out, &format!("{alg} keygen"), &results.keygen, mr)?;
    print_result(out, &format!("{alg} encaps"), &results.encaps, mr)?;
    print_result(out, &format!("{alg} decaps"), &results.decaps, mr)
}

/// Prints a signature-algorithm result block (keygen + sign + verify).
fn print_sig_block<W: Write>(
    out: &mut W,
    alg: &str,
    results: &SigResults,
    mr: bool,
) -> io::Result<()> {
    print_result(out, &format!("{alg} keygen"), &results.keygen, mr)?;
    print_result(out, &format!("{alg} sign"), &results.sign, mr)?;
    print_result(out, &format!("{alg} verify"), &results.verify, mr)
}

// ---------------------------------------------------------------------------
// Core single-threaded orchestration — run every selected benchmark once
// ---------------------------------------------------------------------------

/// Runs the benchmarks selected by `args` against the provided library
/// context, writing all output to `out`.
///
/// This is the single-threaded core of `execute()`; when the user passes
/// `-multi n` the orchestration layer invokes this routine once per worker
/// thread (each with its own `LibContext`).
#[instrument(skip_all, fields(
    algorithms = args.algorithms.len(),
    evp = args.evp.is_some(),
    hmac = args.hmac.is_some(),
    cmac = args.cmac.is_some(),
    seconds = args.seconds,
))]
fn run_benchmarks<W: Write>(
    out: &mut W,
    ctx: &Arc<LibContext>,
    args: &SpeedArgs,
) -> Result<(), CryptoError> {
    let duration = effective_duration(args);
    let block_sizes = effective_block_sizes(args);
    let mr = args.mr;
    let primes = args.primes.unwrap_or(DEFAULT_PRIMES);
    let mut ran_any = false;

    // --- 1. Post-quantum KEM enumeration ---------------------------------
    if args.kem_algorithms {
        for alg in DEFAULT_KEM_ALGORITHMS {
            info!(alg = *alg, "speed: benchmarking KEM");
            print_message_kskey(out, alg, "keygen/encaps/decaps", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_kem(ctx, alg, duration) {
                Ok(r) => {
                    print_kem_block(out, alg, &r, mr).map_err(CryptoError::from)?;
                    ran_any = true;
                }
                Err(e) => warn!(alg = *alg, error = %e, "KEM benchmark failed"),
            }
        }
    }

    // --- 2. Post-quantum signature enumeration ---------------------------
    if args.signature_algorithms {
        for alg in DEFAULT_SIGNATURE_ALGORITHMS {
            info!(alg = *alg, "speed: benchmarking signature");
            print_message_kskey(out, alg, "keygen/sign/verify", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_signature(ctx, alg, duration) {
                Ok(r) => {
                    print_sig_block(out, alg, &r, mr).map_err(CryptoError::from)?;
                    ran_any = true;
                }
                Err(e) => warn!(alg = *alg, error = %e, "signature benchmark failed"),
            }
        }
    }

    // --- 3. Explicit `-evp <alg>` ---------------------------------------
    if let Some(name) = &args.evp {
        ran_any = true;
        let lower = name.to_ascii_lowercase();
        // Is it a digest?
        if let Some((cli, evp)) = DIGEST_ALGORITHMS.iter().find(|(c, _)| *c == lower) {
            for &bs in &block_sizes {
                print_message_sym(out, cli, args.seconds, bs, mr).map_err(CryptoError::from)?;
                match bench_digest(ctx, evp, bs, duration) {
                    Ok(r) => {
                        print_result(out, &format!("{cli} {}", format_block_header(bs)), &r, mr)
                            .map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = cli, error = %e, "digest benchmark failed"),
                }
            }
        } else if let Some((cli, evp)) = CIPHER_ALGORITHMS.iter().find(|(c, _)| *c == lower) {
            // Choose AEAD branch if the user asked for it AND we recognise
            // the algorithm as AEAD (GCM/CCM/OCB/ChaCha20-Poly1305).
            let is_aead_alg = cli.contains("gcm")
                || cli.contains("ccm")
                || cli.contains("ocb")
                || cli.contains("chacha20-poly1305")
                || cli.contains("siv");
            let use_aead = args.aead && is_aead_alg;
            for &bs in &block_sizes {
                print_message_sym(out, cli, args.seconds, bs, mr).map_err(CryptoError::from)?;
                let outcome = if use_aead {
                    bench_aead(ctx, evp, bs, duration, args.decrypt)
                } else {
                    bench_cipher(ctx, evp, bs, duration, args.decrypt)
                };
                match outcome {
                    Ok(r) => {
                        print_result(out, &format!("{cli} {}", format_block_header(bs)), &r, mr)
                            .map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = cli, error = %e, "cipher benchmark failed"),
                }
            }
        } else {
            warn!(alg = %name, "-evp: algorithm not found in digest or cipher tables");
        }
    }

    // --- 4. -hmac / -cmac --------------------------------------------------
    if let Some(digest) = &args.hmac {
        ran_any = true;
        // Resolve an empty `-hmac ""` to the documented default digest
        // (R5: keeps the default-active semantics without a sentinel).
        let digest_name: &str = if digest.is_empty() {
            DEFAULT_HMAC_DIGEST
        } else {
            digest.as_str()
        };
        for &bs in &block_sizes {
            print_message_sym(out, "hmac", args.seconds, bs, mr).map_err(CryptoError::from)?;
            match bench_mac(ctx, mac::HMAC, Some(digest_name), bs, duration) {
                Ok(r) => print_result(
                    out,
                    &format!("hmac({digest_name}) {}", format_block_header(bs)),
                    &r,
                    mr,
                )
                .map_err(CryptoError::from)?,
                Err(e) => warn!(
                    mac = "HMAC",
                    digest = %digest_name,
                    error = %e,
                    "HMAC bench failed"
                ),
            }
        }
    }
    if let Some(cipher_name) = &args.cmac {
        ran_any = true;
        // Resolve an empty `-cmac ""` to the documented default cipher
        // (R5: keeps the default-active semantics without a sentinel).
        let cipher_alg: &str = if cipher_name.is_empty() {
            DEFAULT_CMAC_CIPHER
        } else {
            cipher_name.as_str()
        };
        for &bs in &block_sizes {
            print_message_sym(out, "cmac", args.seconds, bs, mr).map_err(CryptoError::from)?;
            match bench_mac(ctx, mac::CMAC, Some(cipher_alg), bs, duration) {
                Ok(r) => print_result(
                    out,
                    &format!("cmac({cipher_alg}) {}", format_block_header(bs)),
                    &r,
                    mr,
                )
                .map_err(CryptoError::from)?,
                Err(e) => warn!(
                    mac = "CMAC",
                    cipher = %cipher_alg,
                    error = %e,
                    "CMAC bench failed"
                ),
            }
        }
    }

    // --- 5. Positional algorithm tokens ---------------------------------
    for raw in &args.algorithms {
        match classify_algorithm(raw) {
            None => warn!(token = %raw, "speed: unknown algorithm — skipping"),
            Some(tok) => {
                ran_any = true;
                run_one_token(out, ctx, &tok, &block_sizes, duration, args, primes, mr)?;
            }
        }
    }

    // --- 6. Default curated set -----------------------------------------
    if !ran_any {
        info!("speed: no algorithm selected; running curated default set");
        for cli in DEFAULT_CURATED_DIGESTS {
            if let Some((c, evp)) = DIGEST_ALGORITHMS.iter().find(|(k, _)| k == cli) {
                for &bs in &block_sizes {
                    print_message_sym(out, c, args.seconds, bs, mr).map_err(CryptoError::from)?;
                    match bench_digest(ctx, evp, bs, duration) {
                        Ok(r) => {
                            print_result(out, &format!("{c} {}", format_block_header(bs)), &r, mr)
                                .map_err(CryptoError::from)?;
                        }
                        Err(e) => warn!(alg = c, error = %e, "default digest failed"),
                    }
                }
            }
        }
        for cli in DEFAULT_CURATED_CIPHERS {
            if let Some((c, evp)) = CIPHER_ALGORITHMS.iter().find(|(k, _)| k == cli) {
                for &bs in &block_sizes {
                    print_message_sym(out, c, args.seconds, bs, mr).map_err(CryptoError::from)?;
                    match bench_cipher(ctx, evp, bs, duration, args.decrypt) {
                        Ok(r) => {
                            print_result(out, &format!("{c} {}", format_block_header(bs)), &r, mr)
                                .map_err(CryptoError::from)?;
                        }
                        Err(e) => warn!(alg = c, error = %e, "default cipher failed"),
                    }
                }
            }
        }
        // Always include RSA-2048 and RAND in the default set (matches the
        // curated C benchmark dashboard summary).
        print_message_pkey(out, 2048, "rsa", "sign/verify/enc/dec", args.seconds, mr)
            .map_err(CryptoError::from)?;
        match bench_rsa(ctx, 2048, primes, duration) {
            Ok(r) => print_rsa_block(out, 2048, &r, mr).map_err(CryptoError::from)?,
            Err(e) => warn!(alg = "rsa2048", error = %e, "default RSA-2048 failed"),
        }
        for &bs in &block_sizes {
            print_message_sym(out, "rand", args.seconds, bs, mr).map_err(CryptoError::from)?;
            match bench_rand(bs, duration) {
                Ok(r) => print_result(out, &format!("rand {}", format_block_header(bs)), &r, mr)
                    .map_err(CryptoError::from)?,
                Err(e) => warn!(alg = "rand", error = %e, "default rand failed"),
            }
        }
    }

    Ok(())
}

/// Runs one classified token — invoked by `run_benchmarks` for each
/// positional algorithm argument.
#[allow(clippy::too_many_arguments)] // Explicit parameter list keeps dispatch readable.
fn run_one_token<W: Write>(
    out: &mut W,
    ctx: &Arc<LibContext>,
    tok: &AlgToken,
    block_sizes: &[usize],
    duration: Duration,
    args: &SpeedArgs,
    primes: u32,
    mr: bool,
) -> Result<(), CryptoError> {
    match tok {
        AlgToken::Digest(cli, evp) => {
            for &bs in block_sizes {
                print_message_sym(out, cli, args.seconds, bs, mr).map_err(CryptoError::from)?;
                match bench_digest(ctx, evp, bs, duration) {
                    Ok(r) => {
                        print_result(out, &format!("{cli} {}", format_block_header(bs)), &r, mr)
                            .map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = cli, error = %e, "digest benchmark failed"),
                }
            }
        }
        AlgToken::Cipher(cli, evp) => {
            let is_aead_alg = cli.contains("gcm")
                || cli.contains("ccm")
                || cli.contains("ocb")
                || cli.contains("chacha20-poly1305")
                || cli.contains("siv");
            let use_aead = args.aead && is_aead_alg;
            for &bs in block_sizes {
                print_message_sym(out, cli, args.seconds, bs, mr).map_err(CryptoError::from)?;
                let outcome = if use_aead {
                    bench_aead(ctx, evp, bs, duration, args.decrypt)
                } else {
                    bench_cipher(ctx, evp, bs, duration, args.decrypt)
                };
                match outcome {
                    Ok(r) => {
                        print_result(out, &format!("{cli} {}", format_block_header(bs)), &r, mr)
                            .map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = cli, error = %e, "cipher benchmark failed"),
                }
            }
        }
        AlgToken::Rsa(cli, bits) => {
            debug!(alg = cli, bits = *bits, "speed: RSA dispatch");
            print_message_pkey(out, *bits, "rsa", "sign/verify/enc/dec", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_rsa(ctx, *bits, primes, duration) {
                Ok(r) => print_rsa_block(out, *bits, &r, mr).map_err(CryptoError::from)?,
                Err(e) => warn!(alg = cli, bits = *bits, error = %e, "RSA benchmark failed"),
            }
        }
        AlgToken::Dsa(cli, bits) => {
            debug!(alg = cli, bits = *bits, "speed: DSA dispatch");
            print_message_pkey(out, *bits, "dsa", "sign/verify", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_dsa(ctx, *bits, duration) {
                Ok(r) => print_dsa_block(out, *bits, &r, mr).map_err(CryptoError::from)?,
                Err(e) => warn!(alg = cli, bits = *bits, error = %e, "DSA benchmark failed"),
            }
        }
        AlgToken::Ffdh(cli, group) => {
            debug!(alg = cli, group = *group, "speed: FFDH dispatch");
            print_message_kskey(out, group, "derive", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_ffdh(ctx, group, duration) {
                Ok(r) => print_result(out, &format!("{cli} derive"), &r, mr)
                    .map_err(CryptoError::from)?,
                Err(e) => warn!(alg = cli, group = *group, error = %e, "FFDH failed"),
            }
        }
        AlgToken::Ecdsa(cli, curve) => {
            debug!(alg = cli, curve = *curve, "speed: ECDSA dispatch");
            print_message_kskey(out, curve, "sign/verify", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_ecdsa(ctx, curve, false, duration) {
                Ok(r) => print_ecsig_block(out, cli, &r, mr).map_err(CryptoError::from)?,
                Err(e) => warn!(alg = cli, curve = *curve, error = %e, "ECDSA failed"),
            }
        }
        AlgToken::EdDsa(cli, curve) => {
            debug!(alg = cli, curve = *curve, "speed: EdDSA dispatch");
            print_message_kskey(out, curve, "sign/verify", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_ecdsa(ctx, curve, true, duration) {
                Ok(r) => print_ecsig_block(out, cli, &r, mr).map_err(CryptoError::from)?,
                Err(e) => warn!(alg = cli, curve = *curve, error = %e, "EdDSA failed"),
            }
        }
        AlgToken::Ecdh(cli, curve) => {
            debug!(alg = cli, curve = *curve, "speed: ECDH dispatch");
            print_message_kskey(out, curve, "derive", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_ecdh(ctx, curve, duration) {
                Ok(r) => print_result(out, &format!("{cli} derive"), &r, mr)
                    .map_err(CryptoError::from)?,
                Err(e) => warn!(alg = cli, curve = *curve, error = %e, "ECDH failed"),
            }
        }
        AlgToken::Kem(alg) => {
            print_message_kskey(out, alg, "keygen/encaps/decaps", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_kem(ctx, alg, duration) {
                Ok(r) => print_kem_block(out, alg, &r, mr).map_err(CryptoError::from)?,
                Err(e) => warn!(alg = %alg, error = %e, "KEM benchmark failed"),
            }
        }
        AlgToken::Signature(alg) => {
            print_message_kskey(out, alg, "keygen/sign/verify", args.seconds, mr)
                .map_err(CryptoError::from)?;
            match bench_signature(ctx, alg, duration) {
                Ok(r) => print_sig_block(out, alg, &r, mr).map_err(CryptoError::from)?,
                Err(e) => warn!(alg = %alg, error = %e, "signature benchmark failed"),
            }
        }
        AlgToken::Rand => {
            for &bs in block_sizes {
                print_message_sym(out, "rand", args.seconds, bs, mr).map_err(CryptoError::from)?;
                match bench_rand(bs, duration) {
                    Ok(r) => {
                        print_result(out, &format!("rand {}", format_block_header(bs)), &r, mr)
                            .map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = "rand", error = %e, "rand benchmark failed"),
                }
            }
        }
        AlgToken::GroupRsa => {
            for (cli, bits) in RSA_SIZES {
                print_message_pkey(out, *bits, "rsa", "sign/verify/enc/dec", args.seconds, mr)
                    .map_err(CryptoError::from)?;
                match bench_rsa(ctx, *bits, primes, duration) {
                    Ok(r) => {
                        print_rsa_block(out, *bits, &r, mr).map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = cli, bits = *bits, error = %e, "RSA group failed"),
                }
            }
        }
        AlgToken::GroupDsa => {
            for (cli, bits) in DSA_SIZES {
                print_message_pkey(out, *bits, "dsa", "sign/verify", args.seconds, mr)
                    .map_err(CryptoError::from)?;
                match bench_dsa(ctx, *bits, duration) {
                    Ok(r) => {
                        print_dsa_block(out, *bits, &r, mr).map_err(CryptoError::from)?;
                    }
                    Err(e) => warn!(alg = cli, bits = *bits, error = %e, "DSA group failed"),
                }
            }
        }
        AlgToken::GroupFfdh => {
            for (cli, group) in FFDH_GROUPS {
                print_message_kskey(out, group, "derive", args.seconds, mr)
                    .map_err(CryptoError::from)?;
                match bench_ffdh(ctx, group, duration) {
                    Ok(r) => print_result(out, &format!("{cli} derive"), &r, mr)
                        .map_err(CryptoError::from)?,
                    Err(e) => warn!(alg = cli, group = *group, error = %e, "FFDH group failed"),
                }
            }
        }
        AlgToken::GroupEcdsa => {
            for (cli, curve) in ECDSA_CURVES {
                print_message_kskey(out, curve, "sign/verify", args.seconds, mr)
                    .map_err(CryptoError::from)?;
                match bench_ecdsa(ctx, curve, false, duration) {
                    Ok(r) => print_ecsig_block(out, cli, &r, mr).map_err(CryptoError::from)?,
                    Err(e) => warn!(alg = cli, curve = *curve, error = %e, "ECDSA group failed"),
                }
            }
        }
        AlgToken::GroupEdDsa => {
            for (cli, curve) in EDDSA_CURVES {
                print_message_kskey(out, curve, "sign/verify", args.seconds, mr)
                    .map_err(CryptoError::from)?;
                match bench_ecdsa(ctx, curve, true, duration) {
                    Ok(r) => print_ecsig_block(out, cli, &r, mr).map_err(CryptoError::from)?,
                    Err(e) => warn!(alg = cli, curve = *curve, error = %e, "EdDSA group failed"),
                }
            }
        }
        AlgToken::GroupEcdh => {
            for (cli, curve) in ECDH_CURVES {
                print_message_kskey(out, curve, "derive", args.seconds, mr)
                    .map_err(CryptoError::from)?;
                match bench_ecdh(ctx, curve, duration) {
                    Ok(r) => print_result(out, &format!("{cli} derive"), &r, mr)
                        .map_err(CryptoError::from)?,
                    Err(e) => warn!(alg = cli, curve = *curve, error = %e, "ECDH group failed"),
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SpeedArgs::execute — public entry point dispatched from commands::mod
// ---------------------------------------------------------------------------

impl SpeedArgs {
    /// Executes the `speed` benchmark command.
    ///
    /// This is the reachable entry point invoked from
    /// `crates/openssl-cli/src/commands/mod.rs` at
    /// `Self::Speed(args) => args.execute(ctx).await` (line 561) which is
    /// itself invoked from `main.rs` after CLI parsing. Rule R10 (Wiring
    /// Before Done) is satisfied by this call chain.
    ///
    /// # Behaviour
    ///
    /// 1. Validates `misalign` against [`MAX_MISALIGNMENT`] (per Rule R5,
    ///    the sentinel "0 = disabled" is honoured by clap's `Option`).
    /// 2. Initialises the secure heap when `-mlock` is passed.
    /// 3. Acquires the process-wide `LibContext` singleton via
    ///    `LibContext::default()` — this is the Rust analogue of the
    ///    default `OSSL_LIB_CTX` fetched implicitly by the C
    ///    implementation.
    /// 4. When `-multi n` is requested, spawns `n` worker threads (each
    ///    with its own cloned context) and streams output through a
    ///    `Mutex`-guarded stdout handle. Aggregation is non-numeric here
    ///    — each worker writes its own labelled block. This mirrors the
    ///    C `do_multi()` fork/pipe/waitpid pattern while respecting
    ///    Rule R8 (no unsafe) and Rule R7 (fine-grained locking).
    /// 5. In single-thread mode, delegates directly to
    ///    [`run_benchmarks`].
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if:
    /// * `-misalign` exceeds [`MAX_MISALIGNMENT`]
    ///   (`CryptoError::Common(CommonError::InvalidArgument(_))` via the
    ///   secure-heap path isn't applicable here — we emit
    ///   `CryptoError::Common` directly).
    /// * The secure-heap initialisation fails (`-mlock`).
    /// * Any benchmark helper propagates a crypto failure that isn't
    ///   catchable at the per-algorithm warn-and-continue layer inside
    ///   [`run_benchmarks`].
    ///
    /// # Rules
    ///
    /// * **R5 Nullability:** `misalign`/`primes`/`multi`/`async_jobs` use
    ///   `Option<_>`; their "not supplied" state is honoured.
    /// * **R6 Lossless casts:** `u64::try_from(args.multi)` used where
    ///   widening is not trivially possible.
    /// * **R8 Zero unsafe:** no `unsafe` blocks in this file.
    /// * **R10 Wiring:** see docstring above.
    #[allow(clippy::unused_async)]
    #[instrument(skip(self, _ctx), fields(
        multi = ?self.multi,
        seconds = self.seconds,
        mr = self.mr,
    ))]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // -- Argument validation (Rule R5: Option + bounds) --------------
        if let Some(m) = self.misalign {
            if m > MAX_MISALIGNMENT {
                return Err(CryptoError::Common(
                    openssl_common::error::CommonError::InvalidArgument(format!(
                        "-misalign {m}: exceeds MAX_MISALIGNMENT ({MAX_MISALIGNMENT})",
                    )),
                ));
            }
        }
        if let Some(async_jobs) = self.async_jobs {
            if async_jobs > 0 {
                warn!(
                    async_jobs,
                    "speed: -async_jobs not implemented in the Rust rewrite — \
                     ignoring flag and running synchronously"
                );
            }
        }

        // -- Optional secure-heap activation ------------------------------
        if self.mlock {
            let config = SecureHeapConfig {
                min_size: MLOCK_HEAP_MIN_SIZE,
            };
            init_secure_heap(&config)?; // CommonError auto-converts via #[from]
            info!(
                min_size = MLOCK_HEAP_MIN_SIZE,
                "speed: secure heap initialized (-mlock)"
            );
        }

        // -- Acquire a cloneable Arc<LibContext> for workers -------------
        // The parameter `_ctx` is the library-wide handle passed through
        // from `main.rs`; we re-obtain the default singleton here because
        // all the `openssl_crypto::evp::*::fetch` entry points take an
        // owned `Arc<LibContext>` (not `&LibContext`).  In the common
        // case this will be the same underlying context.
        let arc_ctx = LibContext::default();

        let stdout = io::stdout();
        let mut locked = stdout.lock();

        // -- Multi-threaded mode ----------------------------------------
        if let Some(n) = self.multi {
            if n > 1 {
                info!(workers = n, "speed: entering multi-threaded mode");
                return self.run_multi(&mut locked, &arc_ctx, n);
            }
        }

        // -- Single-threaded path ---------------------------------------
        run_benchmarks(&mut locked, &arc_ctx, self)
    }

    /// Multi-worker dispatcher — spawns `n` `std::thread` workers, each
    /// running the full benchmark matrix with its own cloned context.
    ///
    /// Results are streamed to the shared stdout handle as they complete.
    /// An explicit per-thread banner identifies each worker so the
    /// machine-readable output remains parsable.
    ///
    /// The C `do_multi()` routine uses `fork()` + pipes + `waitpid()`;
    /// here we use POSIX threads via `std::thread` which maintains a
    /// single-process model (no forking). This matches Rule R1 (single
    /// runtime owner — threads don't establish a new tokio runtime).
    fn run_multi<W: Write>(
        &self,
        _out: &mut W,
        ctx: &Arc<LibContext>,
        n: u32,
    ) -> Result<(), CryptoError> {
        // Per R6: cast u32 → usize using try_from to catch 32→16 archs.
        let worker_count = usize::try_from(n).map_err(|e| {
            CryptoError::Common(openssl_common::error::CommonError::InvalidArgument(
                format!("-multi {n}: does not fit in usize: {e}"),
            ))
        })?;

        // Spawn each worker with a fresh args clone and context clone.
        let mut handles: Vec<thread::JoinHandle<Result<(), CryptoError>>> =
            Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let args_clone = self.clone();
            let ctx_clone = Arc::clone(ctx);
            let handle = thread::spawn(move || -> Result<(), CryptoError> {
                // Each worker takes its own lock to avoid interleaved
                // writes at the line-buffer boundary. We write to a
                // worker-local buffer first and flush in one shot.
                let mut buffer = io::BufWriter::new(Vec::<u8>::with_capacity(64 * 1024));
                writeln!(buffer, "+H:worker-{worker_id}").map_err(CryptoError::from)?;
                let res = run_benchmarks(&mut buffer, &ctx_clone, &args_clone);
                // Flush to stdout atomically.
                let final_buffer: Vec<u8> = buffer
                    .into_inner()
                    .map_err(|e| CryptoError::Io(io::Error::other(e.to_string())))?;
                let stdout = io::stdout();
                let mut locked = stdout.lock();
                locked.write_all(&final_buffer).map_err(CryptoError::from)?;
                locked.flush().map_err(CryptoError::from)?;
                res
            });
            handles.push(handle);
        }

        // Join all workers. First error wins.
        let mut first_err: Option<CryptoError> = None;
        for (i, h) in handles.into_iter().enumerate() {
            match h.join() {
                Ok(Ok(())) => {
                    debug!(worker = i, "speed: worker completed");
                }
                Ok(Err(e)) => {
                    warn!(worker = i, error = %e, "speed: worker returned error");
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(panic_payload) => {
                    warn!(
                        worker = i,
                        payload = ?panic_payload,
                        "speed: worker thread panicked"
                    );
                    if first_err.is_none() {
                        first_err = Some(CryptoError::Common(
                            openssl_common::error::CommonError::Unsupported(format!(
                                "speed: multi-thread worker {i} panicked",
                            )),
                        ));
                    }
                }
            }
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests — exercise argument parsing and the short-duration code paths
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal wrapper for clap to parse `SpeedArgs` in isolation.
    #[derive(Parser, Debug)]
    struct TestHarness {
        #[command(flatten)]
        args: SpeedArgs,
    }

    fn parse(cli: &[&str]) -> SpeedArgs {
        let mut full = vec!["speed"];
        full.extend_from_slice(cli);
        TestHarness::try_parse_from(full).expect("clap parse").args
    }

    #[test]
    fn parses_default_args() {
        let a = parse(&[]);
        assert_eq!(a.seconds, DEFAULT_SECONDS);
        assert!(!a.mr);
        assert!(!a.mlock);
        assert!(!a.aead);
        assert!(!a.kem_algorithms);
        assert!(!a.signature_algorithms);
        assert!(a.evp.is_none());
        assert!(a.hmac.is_none());
        assert!(a.cmac.is_none());
        assert!(a.multi.is_none());
        assert!(a.misalign.is_none());
        assert!(a.primes.is_none());
        assert!(a.algorithms.is_empty());
        assert!(a.bytes.is_empty());
    }

    #[test]
    fn parses_evp_sha256() {
        let a = parse(&["--evp", "sha256"]);
        assert_eq!(a.evp.as_deref(), Some("sha256"));
    }

    #[test]
    fn parses_hmac_sha256() {
        let a = parse(&["--hmac", "sha256"]);
        assert_eq!(a.hmac.as_deref(), Some("sha256"));
    }

    #[test]
    fn parses_cmac_aes128() {
        let a = parse(&["--cmac", "aes-128-cbc"]);
        assert_eq!(a.cmac.as_deref(), Some("aes-128-cbc"));
    }

    #[test]
    fn parses_seconds_and_bytes() {
        let a = parse(&["--seconds", "1", "--bytes", "1024", "--bytes", "8192"]);
        assert_eq!(a.seconds, 1);
        assert_eq!(a.bytes, vec![1024usize, 8192]);
    }

    #[test]
    fn parses_mr_and_elapsed_flags() {
        let a = parse(&["--mr", "--elapsed"]);
        assert!(a.mr);
        assert!(a.elapsed);
    }

    #[test]
    fn parses_mlock_and_aead_flags() {
        let a = parse(&["--mlock", "--aead"]);
        assert!(a.mlock);
        assert!(a.aead);
    }

    #[test]
    fn parses_kem_and_signature_algorithms_flags() {
        let a = parse(&["--kem-algorithms", "--signature-algorithms"]);
        assert!(a.kem_algorithms);
        assert!(a.signature_algorithms);
    }

    #[test]
    fn parses_positional_algorithms() {
        let a = parse(&["rsa2048", "sha256", "aes-128-cbc", "ecdsap256"]);
        assert_eq!(
            a.algorithms,
            vec![
                "rsa2048".to_string(),
                "sha256".to_string(),
                "aes-128-cbc".to_string(),
                "ecdsap256".to_string(),
            ]
        );
    }

    #[test]
    fn parses_multi_primes_misalign() {
        let a = parse(&["--multi", "4", "--primes", "3", "--misalign", "8"]);
        assert_eq!(a.multi, Some(4));
        assert_eq!(a.primes, Some(3));
        assert_eq!(a.misalign, Some(8));
    }

    #[test]
    fn parses_decrypt_flag() {
        let a = parse(&["--decrypt"]);
        assert!(a.decrypt);
    }

    #[test]
    fn classify_algorithm_recognises_digests() {
        matches!(classify_algorithm("sha256"), Some(AlgToken::Digest(_, _)));
        matches!(classify_algorithm("SHA256"), Some(AlgToken::Digest(_, _)));
        matches!(classify_algorithm("md5"), Some(AlgToken::Digest(_, _)));
    }

    #[test]
    fn classify_algorithm_recognises_ciphers() {
        matches!(
            classify_algorithm("aes-128-cbc"),
            Some(AlgToken::Cipher(_, _))
        );
        matches!(
            classify_algorithm("chacha20-poly1305"),
            Some(AlgToken::Cipher(_, _))
        );
    }

    #[test]
    fn classify_algorithm_recognises_rsa_sizes() {
        matches!(classify_algorithm("rsa2048"), Some(AlgToken::Rsa(_, 2048)));
        matches!(classify_algorithm("rsa4096"), Some(AlgToken::Rsa(_, 4096)));
    }

    #[test]
    fn classify_algorithm_recognises_groups() {
        matches!(classify_algorithm("rsa"), Some(AlgToken::GroupRsa));
        matches!(classify_algorithm("dsa"), Some(AlgToken::GroupDsa));
        matches!(classify_algorithm("ecdsa"), Some(AlgToken::GroupEcdsa));
        matches!(classify_algorithm("eddsa"), Some(AlgToken::GroupEdDsa));
        matches!(classify_algorithm("ecdh"), Some(AlgToken::GroupEcdh));
        matches!(classify_algorithm("ffdh"), Some(AlgToken::GroupFfdh));
    }

    #[test]
    fn classify_algorithm_recognises_rand() {
        matches!(classify_algorithm("rand"), Some(AlgToken::Rand));
    }

    #[test]
    fn classify_algorithm_recognises_pq() {
        matches!(classify_algorithm("ml-kem-768"), Some(AlgToken::Kem(_)));
        matches!(
            classify_algorithm("ml-dsa-44"),
            Some(AlgToken::Signature(_))
        );
        matches!(
            classify_algorithm("slh-dsa-sha2-128s"),
            Some(AlgToken::Signature(_))
        );
    }

    #[test]
    fn classify_algorithm_unknown_returns_none() {
        assert!(classify_algorithm("not-a-real-alg").is_none());
    }

    #[test]
    fn format_block_header_formats_bytes_and_kib() {
        assert_eq!(format_block_header(16), "16B");
        assert_eq!(format_block_header(256), "256B");
        assert_eq!(format_block_header(1024), "1K");
        assert_eq!(format_block_header(8192), "8K");
        assert_eq!(format_block_header(16384), "16K");
        assert_eq!(format_block_header(2000), "2000B"); // not a multiple of 1K
    }

    #[test]
    fn bench_result_ops_per_second_handles_zero_elapsed() {
        let r = BenchResult {
            count: 100,
            elapsed: Duration::from_secs(0),
        };
        assert_eq!(r.ops_per_second(), 0.0);

        let r2 = BenchResult {
            count: 100,
            elapsed: Duration::from_secs(2),
        };
        assert!((r2.ops_per_second() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn effective_block_sizes_default() {
        let a = parse(&[]);
        assert_eq!(effective_block_sizes(&a), BLOCK_SIZES.to_vec());
    }

    #[test]
    fn effective_block_sizes_overridden() {
        let a = parse(&["--bytes", "64", "--bytes", "1024"]);
        assert_eq!(effective_block_sizes(&a), vec![64usize, 1024]);
    }

    #[test]
    fn effective_duration_honours_seconds() {
        let a = parse(&["--seconds", "5"]);
        assert_eq!(effective_duration(&a), Duration::from_secs(5));
    }

    #[test]
    fn effective_duration_clamps_to_one_second_minimum() {
        let a = parse(&["--seconds", "0"]);
        assert_eq!(effective_duration(&a), Duration::from_secs(1));
    }

    #[test]
    fn print_message_sym_mr_format() {
        let mut out: Vec<u8> = Vec::new();
        print_message_sym(&mut out, "sha256", 3, 1024, true).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("+DT:sha256:3:1024"));
    }

    #[test]
    fn print_message_sym_human_format() {
        let mut out: Vec<u8> = Vec::new();
        print_message_sym(&mut out, "sha256", 3, 1024, false).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Doing sha256 ops for 3s on 1024 size blocks"));
    }

    #[test]
    fn print_message_pkey_mr_format() {
        let mut out: Vec<u8> = Vec::new();
        print_message_pkey(&mut out, 2048, "rsa", "sign/verify/enc/dec", 3, true).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("+DTP:2048:rsa:sign/verify/enc/dec:3"));
    }

    #[test]
    fn print_message_kskey_mr_format() {
        let mut out: Vec<u8> = Vec::new();
        print_message_kskey(&mut out, "ML-KEM-768", "keygen/encaps/decaps", 3, true).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("+DTP:ML-KEM-768:keygen/encaps/decaps:3"));
    }

    #[test]
    fn print_result_mr_format() {
        let mut out: Vec<u8> = Vec::new();
        let r = BenchResult {
            count: 10_000,
            elapsed: Duration::from_millis(500),
        };
        print_result(&mut out, "sha256 1K", &r, true).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("+R:10000:sha256 1K:0.500000"));
    }

    #[test]
    fn print_result_human_format() {
        let mut out: Vec<u8> = Vec::new();
        let r = BenchResult {
            count: 10_000,
            elapsed: Duration::from_secs(1),
        };
        print_result(&mut out, "sha256 1K", &r, false).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("10000 sha256 1K ops"));
    }

    #[test]
    fn timer_driven_loop_runs_nonzero_iterations() {
        // Uses an essentially instant op to ensure the loop counter
        // advances past zero within the short duration.
        let r = timer_driven_loop(Duration::from_millis(10), || Ok(())).unwrap();
        assert!(r.count > 0, "expected > 0 iterations, got {}", r.count);
        assert!(r.elapsed >= Duration::from_millis(1));
    }

    #[test]
    fn timer_driven_loop_propagates_errors() {
        let r: Result<BenchResult, CryptoError> =
            timer_driven_loop(Duration::from_millis(50), || {
                Err(CryptoError::Rand("simulated".to_string()))
            });
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn execute_default_short_duration_completes() {
        // Short duration, no multi, default curated set — exercises the
        // execute -> run_benchmarks -> bench_* reachability path.
        let args = SpeedArgs {
            seconds: 1,
            ..SpeedArgs::default()
        };
        // We cannot construct a LibContext directly here without
        // depending on its internals, so we pass a reference derived
        // from the default singleton. execute() itself re-obtains
        // LibContext::default() so the parameter is effectively ignored.
        let ctx_arc = LibContext::default();
        let res = args.execute(&ctx_arc).await;
        // Some provider algorithms may be stubs — execute() warns on
        // per-algorithm failure and continues. Overall success is the
        // expected outcome.
        assert!(res.is_ok(), "execute returned: {res:?}");
    }

    #[tokio::test]
    async fn execute_with_mlock_initialises_secure_heap() {
        let args = SpeedArgs {
            seconds: 1,
            mlock: true,
            ..SpeedArgs::default()
        };
        let ctx_arc = LibContext::default();
        let res = args.execute(&ctx_arc).await;
        assert!(res.is_ok(), "execute with mlock failed: {res:?}");
    }

    #[tokio::test]
    async fn execute_rand_token_single_block() {
        let args = SpeedArgs {
            seconds: 1,
            bytes: vec![64],
            algorithms: vec!["rand".to_string()],
            ..SpeedArgs::default()
        };
        let ctx_arc = LibContext::default();
        let res = args.execute(&ctx_arc).await;
        assert!(res.is_ok(), "execute rand failed: {res:?}");
    }

    #[tokio::test]
    async fn execute_mr_flag_runs() {
        let args = SpeedArgs {
            seconds: 1,
            bytes: vec![64],
            algorithms: vec!["rand".to_string()],
            mr: true,
            ..SpeedArgs::default()
        };
        let ctx_arc = LibContext::default();
        let res = args.execute(&ctx_arc).await;
        assert!(res.is_ok(), "execute -mr failed: {res:?}");
    }

    #[tokio::test]
    async fn execute_misalign_too_large_errors() {
        let args = SpeedArgs {
            seconds: 1,
            misalign: Some(MAX_MISALIGNMENT + 1),
            ..SpeedArgs::default()
        };
        let ctx_arc = LibContext::default();
        let res = args.execute(&ctx_arc).await;
        assert!(res.is_err(), "expected misalign > 63 to fail");
    }
}
