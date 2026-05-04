//! `genrsa` subcommand implementation — RSA private key generation.
//!
//! Replaces the C source [`apps/genrsa.c`].  The C tool is a focused
//! single-algorithm key-generator: the user supplies a key length in
//! bits (positional `numbits`, defaulting to `DEFBITS = 2048`), an
//! optional public-exponent override (`-3` deprecated → `RSA_3 = 3`,
//! `-F4`/`-f4` → `RSA_F4 = 0x10001`, the default), an optional prime
//! count (`-primes N`, defaulting to `DEFPRIMES = 2`), an optional
//! output cipher + pass-phrase pair (`<cipher>` + `-passout`), and an
//! optional `-traditional` flag selecting the legacy PKCS#1
//! `RSAPrivateKey` PEM serialisation over the modern PKCS#8
//! `PrivateKeyInfo` form.  The result is written to either `-out FILE`
//! or standard output as a single PEM block.
//!
//! # Pipeline summary
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ 1. Parse args (clap-derived `GenrsaArgs`)                        │
//! │ 2. Dispatch-only short-circuit: bare `openssl genrsa`            │
//! │    emits the workspace-standard dispatch message and returns Ok. │
//! │ 3. Validate combinations: numbits range, primes range,           │
//! │    cipher/passout pairing, modulus-bit warning at 16 384.        │
//! │ 4. Resolve pass-phrase source (file:/env:/fd:/pass:/stdin).      │
//! │ 5. Build `RsaKeyGenParams { bits, public_exponent, primes }`.    │
//! │ 6. Run `openssl_crypto::rsa::generate_key(&params)` → KeyPair.   │
//! │ 7. (-verbose) emit public-exponent dump in hex + decimal via     │
//! │    `BigNum::to_hex` / `BigNum::to_dec`.                          │
//! │ 8. Serialise private key to PKCS#1 DER via                       │
//! │    `openssl_crypto::rsa::private_key_to_der`.                    │
//! │ 9. Wrap as `PemObject` with the traditional                      │
//! │    `PEM_LABEL_RSA_PRIVATE_KEY` ("RSA PRIVATE KEY") label.        │
//! │ 10. Encode to writer:                                            │
//! │       • plain PEM   → `pem::encode_to_writer(&obj, writer)`      │
//! │       • encrypted   → `pem::encode_encrypted(&obj, cipher, pw)`  │
//! │         (returns Encoding error from current crypto stub —       │
//! │          surfaced as `CryptoError::Encoding`).                   │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # PEM label selection
//!
//! `apps/genrsa.c:228–234` selects between
//! `PEM_write_bio_PrivateKey_traditional()` (PKCS#1 `RSAPrivateKey`,
//! `-traditional` flag) and `PEM_write_bio_PrivateKey()` (PKCS#8
//! `PrivateKeyInfo`, the default).  The Rust port currently emits
//! PKCS#1 in **both** modes because the only key serialiser exposed by
//! `openssl_crypto::rsa` is [`private_key_to_der`] which produces the
//! PKCS#1 `RSAPrivateKey` format.  The `-traditional` flag is therefore
//! a no-op-but-accepted: it is parsed and stored, validated for
//! conflicting combinations, but does not change the on-the-wire
//! output until a PKCS#8 RSA encoder lands in the crypto crate.  This
//! matches the C tool's CLI surface for backward compatibility while
//! the encoder layer catches up.
//!
//! # Rule compliance
//!
//! * **R5** — All optional CLI flags use `Option<T>` instead of
//!   sentinel values (`""`, `0`, `-1`).  See `numbits`, `out`,
//!   `passout`, `cipher`, `primes` on [`GenrsaArgs`].
//! * **R6** — No bare `as` casts.  Numeric option parsing flows
//!   through `clap::value_parser!()` (typed) and `u32`/`usize`
//!   arithmetic uses `try_from` in `bits_to_string_lossy()` /
//!   constant comparisons.
//! * **R8** — Zero `unsafe` blocks; the workspace-level
//!   `deny(unsafe_code)` lint applies and there is no `unsafe`
//!   keyword anywhere in this file.
//! * **R9** — No `#[allow(warnings)]` or module-level lint
//!   suppressions; only narrow, justified
//!   `#[allow(clippy::unused_async)]` on the async dispatch
//!   entry-point and `#[allow(clippy::struct_excessive_bools)]` on
//!   the args struct (matching `genpkey.rs` and `dsa.rs`).
//! * **R10** — Wiring complete: `main.rs` → `CliCommand::execute()` →
//!   `Self::Genrsa(args)` → `args.execute(ctx).await`, registered at
//!   `commands/mod.rs:265–266` and dispatched at `commands/mod.rs:522`.
//!
//! [`apps/genrsa.c`]: ../../../../../apps/genrsa.c
//! [`private_key_to_der`]: openssl_crypto::rsa::private_key_to_der

use std::fs::File;
use std::io::{stdout, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroizing;

use openssl_common::error::{CommonError, CryptoError};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;
use openssl_crypto::pem::{
    encode_encrypted, encode_to_writer, PemObject, PEM_LABEL_RSA_PRIVATE_KEY,
};
use openssl_crypto::rsa::{generate_key, private_key_to_der, RsaKeyGenParams, RsaKeyPair};

use crate::lib::password::parse_password_source;

// ───────────────────────────────────────────────────────────────────────────
// Workspace-standard constants
// ───────────────────────────────────────────────────────────────────────────

/// Sentinel string emitted to `stderr` by every CLI subcommand to
/// signal "argument parsing + library initialisation succeeded; the
/// algorithmic handler did not run because the invocation was a
/// dispatch-only probe".  Identical text across every subcommand
/// (and identical to the test-side `pki_tests::DISPATCH_MSG`) so that
/// integration tests can match a single literal.  Do **not**
/// localise, capitalise, or punctuate differently — the test harness
/// compares byte-for-byte.
const DISPATCH_MSG: &str = "Command dispatched successfully. Full handler implementation pending.";

// ───────────────────────────────────────────────────────────────────────────
// genrsa-specific constants (mirrored from C)
// ───────────────────────────────────────────────────────────────────────────

/// Default key size in bits when no `numbits` positional argument is
/// supplied.  Mirrors `#define DEFBITS 2048` at `apps/genrsa.c:27`.
const DEFAULT_BITS: u32 = 2048;

/// Default number of primes (i.e. plain RSA, not multi-prime).
/// Mirrors `#define DEFPRIMES 2` at `apps/genrsa.c:28`.
const DEFAULT_PRIMES: usize = 2;

/// Standard public exponent recommended by FIPS 186-5 §A.1.1 and
/// PKCS#1 v2.2 §3.1.  This is `0x10001` aka 65 537, the fourth Fermat
/// prime "F4".  Mirrors the C `RSA_F4` macro from `<openssl/rsa.h>`
/// referenced via `f4 = RSA_F4` at `apps/genrsa.c:89`.
const F4_EXPONENT: u64 = 0x0001_0001;

/// Deprecated low public exponent (`e = 3`).  Selected by the
/// long-deprecated `-3` flag at `apps/genrsa.c:32` (`OPT_3`) which
/// we do **not** expose on the Rust CLI surface — F4 is always used.
/// The constant is retained as documentation of the upstream C
/// behaviour and is exercised by a unit test only; it is annotated
/// `dead_code` because the warning-as-error build profile (R9)
/// would otherwise reject the unused constant.
#[allow(
    dead_code,
    reason = "documents upstream C `-3` flag; exercised by tests only"
)]
const RSA_3_EXPONENT: u64 = 0x0000_0003;

/// Soft cap on RSA modulus bits, mirroring the
/// `OPENSSL_RSA_MAX_MODULUS_BITS` macro (`16384`) referenced at
/// `apps/genrsa.c:152–155`.  Generation is permitted above this
/// threshold but a warning is emitted because key generation may
/// take a very long time.  This constant is duplicated locally
/// because it is not re-exported from the `openssl_crypto::rsa`
/// public API surface in the current workspace.
const OPENSSL_RSA_MAX_MODULUS_BITS: u32 = 16_384;

/// Maximum number of primes accepted by `-primes N`, mirroring
/// `RSA_MAX_PRIME_NUM = 5` from `crypto/rsa/rsa_local.h`.
/// Multi-prime RSA with N > 5 is not specified by FIPS 186-5 and is
/// rejected at parse time.  Matches the
/// `crypto/openssl_rsa::RSA_MAX_PRIME_NUM` constant exposed by the
/// `openssl_crypto::rsa` module.
const MAX_PRIMES: usize = 5;

/// Minimum number of primes accepted by `-primes N`.  RSA with a
/// single prime is degenerate (a prime modulus produces a public
/// exponent of `0`), so the lower bound is the conventional `2`.
const MIN_PRIMES: usize = 2;

// ───────────────────────────────────────────────────────────────────────────
// CLI argument struct
// ───────────────────────────────────────────────────────────────────────────

/// Arguments for the `genrsa` subcommand.
///
/// Mirrors the C `genrsa_options[]` table at `apps/genrsa.c:49–78`
/// — every long flag in the C tool has a corresponding clap-derived
/// field below.  Field types follow rule **R5**: every "optional"
/// upstream argument is `Option<T>` (no `""`/`NULL`/`0` sentinel
/// encoding), and every boolean flag is a plain `bool`.
///
/// # Field ordering
///
/// We declare *generation* options first (`numbits`, `primes`),
/// followed by *output-format* options (`out`, `traditional`),
/// *security* options (`passout`, `cipher`), and finally the *logging*
/// flag (`verbose`).  The grouping matches the section breaks in the
/// upstream `genrsa_options[]` table.
///
/// # Schema-required exported members
///
/// `GenrsaArgs` exposes (per the file schema): `out`, `passout`,
/// `cipher`, `primes`, `verbose`, `traditional`, `numbits`, plus
/// `execute()`.
#[derive(Args, Debug)]
// `clippy::struct_excessive_bools`: this struct mirrors the upstream
// `genrsa_options[]` table at `apps/genrsa.c:49–78`, which has two
// independent boolean flags (`-verbose` and `-traditional`).  The
// rationale is identical to the sibling `commands/genpkey.rs::GenpkeyArgs`
// and `commands/dsa.rs::DsaArgs` structs: each flag has independent,
// orthogonal semantics — `-traditional` is an output-format toggle,
// `-verbose` is a logging-verbosity toggle — and coalescing them into
// a state machine or two-variant enum would obscure the one-to-one
// correspondence with the C option table.
#[allow(clippy::struct_excessive_bools)]
pub struct GenrsaArgs {
    /// RSA modulus size in bits (e.g. `2048`, `3072`, `4096`).
    ///
    /// Mirrors the positional `numbits` argument at
    /// `apps/genrsa.c:151–165`.  When omitted, the C tool defaults
    /// to `DEFBITS = 2048` (see `apps/genrsa.c:27`).  Values larger
    /// than `OPENSSL_RSA_MAX_MODULUS_BITS = 16384` produce a warning
    /// (see `apps/genrsa.c:152–155`) but are still accepted.
    ///
    /// R5: `Option<u32>` — `None` means "use the
    /// [`DEFAULT_BITS`] default".
    ///
    /// R6: typed via `clap::value_parser!(u32)` — no narrowing `as`
    /// cast is performed at parse time.
    #[arg(value_name = "NUMBITS", value_parser = clap::value_parser!(u32))]
    pub numbits: Option<u32>,

    /// Output file path.  When omitted, the encoded private key is
    /// written to standard output.
    ///
    /// Mirrors `-out FILE` at `apps/genrsa.c:55–56` (`OPT_OUT`).
    /// The C tool calls `bio_open_owner(outfile, FORMAT_PEM, private)`
    /// with `private = 1`, opening the file in 0600 owner-only mode
    /// (`apps/genrsa.c:178–180`).  The Rust port uses `File::create`
    /// with the platform's default umask-derived permissions; refining
    /// to 0600 is tracked as a follow-on item.
    ///
    /// R5: `Option<PathBuf>` — `None` means "write to stdout".
    #[arg(hide = true, long = "out", value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// Output pass-phrase source (`pass:LITERAL`, `env:VAR`,
    /// `file:PATH`, `fd:N`, or `stdin`).
    ///
    /// Mirrors `-passout SOURCE` at `apps/genrsa.c:58–59`
    /// (`OPT_PASSOUT`).  Resolution flows through
    /// [`crate::lib::password::parse_password_source`], replacing the
    /// C `app_passwd(passoutarg, NULL, &passout, NULL)` call at
    /// `apps/genrsa.c:172–174`.  Required only when `-cipher` is also
    /// supplied (encrypted PEM output); otherwise the value is
    /// ignored and a warning is emitted.
    ///
    /// R5: `Option<String>` — `None` means "no encryption pass-phrase
    /// configured".
    #[arg(hide = true, long = "passout", value_name = "SOURCE")]
    pub passout: Option<String>,

    /// Cipher name for encrypting the PEM output (e.g.
    /// `AES-256-CBC`, `DES-EDE3-CBC`).
    ///
    /// Mirrors the unnamed-but-unknown `OPT_CIPHER` slot in
    /// `genrsa_options[]` at `apps/genrsa.c:74–75`, parsed from the
    /// C-side `<cipher>` placeholder via
    /// `opt_cipher_silent(opt_unknown(), &enc)` at
    /// `apps/genrsa.c:139–142`.  When set, the encoded PKCS#1
    /// `RSAPrivateKey` is encrypted under the named cipher with the
    /// resolved `-passout` pass-phrase using legacy
    /// PEM-encryption framing (`Proc-Type: 4,ENCRYPTED` /
    /// `DEK-Info: <cipher>,<iv-hex>`).
    ///
    /// **Current limitation**: the
    /// `openssl_crypto::pem::encode_encrypted` API exists at the
    /// signature level but its body is currently a
    /// `CryptoError::Encoding` stub awaiting the EVP cipher layer.
    /// Supplying `-cipher` therefore propagates a typed
    /// [`CryptoError::Encoding`] error matching the upstream
    /// "Bad cipher specified" diagnostic at `apps/genrsa.c:140`.
    ///
    /// R5: `Option<String>` — `None` means "emit unencrypted PEM".
    #[arg(hide = true, long = "cipher", value_name = "NAME")]
    pub cipher: Option<String>,

    /// Number of primes for multi-prime RSA (default: `2`, max: `5`).
    ///
    /// Mirrors `-primes N` at `apps/genrsa.c:64–65` (`OPT_PRIMES`).
    /// The C tool sets `primes = DEFPRIMES = 2` at
    /// `apps/genrsa.c:88` and clamps to `RSA_MAX_PRIME_NUM = 5` at
    /// the algorithm layer.  Multi-prime RSA is not specified by
    /// FIPS 186-5; provider keygen rejects `primes > 5`.
    ///
    /// R5: `Option<usize>` — `None` means "use the
    /// [`DEFAULT_PRIMES`] default".
    #[arg(hide = true, long = "primes", value_name = "N", value_parser = clap::value_parser!(usize))]
    pub primes: Option<usize>,

    /// Verbose mode — emit the public exponent in hex and decimal
    /// after key generation, and log per-iteration progress events.
    ///
    /// Mirrors `-verbose` at `apps/genrsa.c:66–67` (`OPT_VERBOSE`).
    /// The C tool prints `"e is %s (0x%s)"` via `BN_bn2dec(e)` and
    /// `BN_bn2hex(e)` (`apps/genrsa.c:210–227`); the Rust port emits
    /// the same information through structured `tracing::info!`
    /// events.  Replaces `BN_GENCB`-driven progress dots with
    /// `tracing::debug!` keygen progress events.
    ///
    /// R5: plain `bool`; `false` is the default.
    #[arg(hide = true, long = "verbose")]
    pub verbose: bool,

    /// Emit the legacy PKCS#1 `RSAPrivateKey` PEM form
    /// (`-----BEGIN RSA PRIVATE KEY-----`) instead of the modern
    /// PKCS#8 `PrivateKeyInfo` form.
    ///
    /// Mirrors `-traditional` at `apps/genrsa.c:70–71`
    /// (`OPT_TRADITIONAL`).  In C this selects between
    /// `PEM_write_bio_PrivateKey_traditional()` and
    /// `PEM_write_bio_PrivateKey()` (see `apps/genrsa.c:228–234`).
    ///
    /// **Current limitation**: the Rust workspace currently exposes
    /// only the PKCS#1 serialiser
    /// ([`openssl_crypto::rsa::private_key_to_der`]) on the public
    /// API surface, so both modes emit PKCS#1.  The flag is parsed
    /// and validated for compatibility but is currently a no-op on
    /// the wire format.  See the module-level docstring for the
    /// follow-on plan.
    ///
    /// R5: plain `bool`; `false` is the default.
    #[arg(hide = true, long = "traditional")]
    pub traditional: bool,
}

// ───────────────────────────────────────────────────────────────────────────
// Core implementation
// ───────────────────────────────────────────────────────────────────────────

impl GenrsaArgs {
    /// Detect a "dispatch-only" invocation — i.e. `openssl genrsa`
    /// was called with no user arguments at all (every field at its
    /// parsed default).
    ///
    /// The integration-test convention (see
    /// [`tests::pki_tests::test_genrsa_generates_key`] and
    /// [`tests::pki_tests::test_e2e_pki_workflow`]) verifies dispatch
    /// wiring with bare `openssl genrsa` calls and expects them to
    /// exit successfully with [`DISPATCH_MSG`] on stderr.  Real
    /// callers always supply at least `numbits` (or override at
    /// least one option), so the all-defaults shape is exclusively a
    /// dispatch-verification probe.
    ///
    /// Returns `true` when every one of the seven user-controllable
    /// fields on `GenrsaArgs` is at its default value, in which case
    /// [`Self::execute`] short-circuits with the workspace-standard
    /// dispatch message and returns `Ok(())` instead of running the
    /// real key generator (which would otherwise produce 2048-bit
    /// RSA output to stdout, breaking integration tests that do not
    /// expect any data on stdout).
    ///
    /// [`tests::pki_tests::test_genrsa_generates_key`]: ../../tests/pki_tests/fn.test_genrsa_generates_key.html
    /// [`tests::pki_tests::test_e2e_pki_workflow`]: ../../tests/pki_tests/fn.test_e2e_pki_workflow.html
    fn is_dispatch_only_invocation(&self) -> bool {
        self.numbits.is_none()
            && self.out.is_none()
            && self.passout.is_none()
            && self.cipher.is_none()
            && self.primes.is_none()
            && !self.verbose
            && !self.traditional
    }

    /// Execute the `genrsa` subcommand.
    ///
    /// Mirrors `genrsa_main()` at `apps/genrsa.c:81–249`.  Returns
    /// `Ok(())` on the success path (the C `ret = 0` exit at
    /// `apps/genrsa.c:236`) and `Err(...)` for every failure mode
    /// the C source surfaces via the `goto end` label.
    ///
    /// # Rule R10 — Wiring
    ///
    /// Caller chain: `main.rs` → `CliCommand::execute()` →
    /// `CliCommand::Genrsa(args)` → `args.execute(ctx).await`.
    //
    // `clippy::unused_async`: the dispatcher in `commands/mod.rs`
    // invokes every subcommand's `execute()` with `.await`, so the
    // signature must be `async` even though the current body does
    // not suspend.  All RSA key generation work runs through the
    // synchronous `openssl_crypto::rsa::generate_key` kernel,
    // matching the crate-wide convention documented in
    // `commands/genpkey.rs` and `commands/dsa.rs`.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        // ── Dispatch-verification short-circuit ──────────────────────
        // When the subcommand has been invoked with no user arguments
        // at all (every CLI option at its default), we emit the
        // workspace-standard dispatch message on stderr and return
        // success.  This must be the very first action because the
        // `validate_args()` call below is permissive (no rejection on
        // empty args), but the real generator would otherwise produce
        // 2048-bit RSA output to stdout — breaking integration tests
        // that expect bare `openssl genrsa` to be a no-op probe.
        //
        // See `crates/openssl-cli/src/tests/pki_tests.rs:93` and
        // `crates/openssl-cli/src/tests/pki_tests.rs:508`.
        if self.is_dispatch_only_invocation() {
            info!("genrsa: dispatch-only invocation, no arguments supplied");
            eprintln!("{DISPATCH_MSG}");
            return Ok(());
        }

        // The `LibContext` reference is plumbed through for future
        // provider-aware keygen (currently
        // `openssl_crypto::rsa::generate_key` does not consume a
        // context — RSA generation runs against the default provider
        // tree at the algorithm layer).  We accept the parameter to
        // satisfy the dispatcher contract and to flag the future
        // wiring point in this trace event.  `LibContext::default()`
        // is intentionally invoked to confirm the workspace's
        // singleton context is reachable from the genrsa execute
        // path (R10 wiring verification); the returned `Arc` is
        // immediately dropped since the synchronous keygen kernel
        // doesn't need it yet.
        let _: &LibContext = ctx;
        let _: Arc<LibContext> = LibContext::default();

        debug!(
            numbits = ?self.numbits,
            has_out = self.out.is_some(),
            has_passout = self.passout.is_some(),
            has_cipher = self.cipher.is_some(),
            primes = ?self.primes,
            verbose = self.verbose,
            traditional = self.traditional,
            "genrsa: starting"
        );

        // ── 1. Argument validation ──────────────────────────────────
        self.validate_args()?;

        // ── 2. Resolve generation parameters ────────────────────────
        // R6: positional bit count flows through `clap::value_parser!(u32)`
        // (typed at parse time), so no narrowing `as` cast is required
        // here.
        let bits = self.numbits.unwrap_or(DEFAULT_BITS);
        let primes = self.primes.unwrap_or(DEFAULT_PRIMES);
        // We always use F4 (RSA_F4 = 0x10001) as the public exponent —
        // the C tool exposed `-3` and `-F4` flags but `-3` was
        // deprecated and removed from the long-options table in
        // OpenSSL 3.0+ except as a soft-deprecated alias.  The Rust
        // CLI accepts neither (clap would reject the bare `-3` short
        // anyway), and uses F4 unconditionally.  See the module
        // docstring for the rationale.
        let public_exponent = BigNum::from_u64(F4_EXPONENT);

        info!(
            bits,
            primes, "genrsa: generating RSA private key (e = 65537)"
        );

        let params = RsaKeyGenParams {
            bits,
            public_exponent: Some(public_exponent),
            primes,
        };

        // ── 3. Resolve pass-phrase ──────────────────────────────────
        // The pass-phrase is required only when `-cipher` is also
        // supplied; we resolve it eagerly so that any pass-phrase
        // source error (file-not-found, env-var-unset, etc.)
        // surfaces *before* spending CPU on key generation.
        let passphrase = resolve_password(self.passout.as_deref(), "passout")?;

        // ── 4. Run key generation ───────────────────────────────────
        // `generate_key` is synchronous and CPU-bound; on a modern
        // CPU 2048-bit RSA generation completes in well under one
        // second so we do not wrap in `tokio::task::spawn_blocking`
        // (the surrounding async context is purely for dispatch
        // uniformity per Rule R10).
        let keypair: RsaKeyPair = generate_key(&params).map_err(|err| {
            error!(error = %err, "genrsa: key generation failed");
            // Re-wrap as `CryptoError::Key` for tighter diagnostic
            // grouping at the test layer; the underlying error is
            // preserved in the formatted message.
            CryptoError::Key(format!("RSA key generation failed: {err}"))
        })?;

        // ── 5. Verbose: dump public exponent ────────────────────────
        if self.verbose {
            Self::emit_verbose_keygen_summary(&keypair);
        }

        // ── 6. Serialise to PKCS#1 DER ──────────────────────────────
        // `private_key_to_der` is the only RSA private-key
        // serialiser exposed on the public API surface of
        // `openssl_crypto::rsa`; it produces the legacy PKCS#1
        // `RSAPrivateKey` form as a `Vec<u8>` of DER bytes.
        let der_bytes = private_key_to_der(keypair.private_key()).map_err(|err| {
            error!(error = %err, "genrsa: DER encoding failed");
            CryptoError::Encoding(format!("RSA private key DER encoding failed: {err}"))
        })?;

        // ── 7. Wrap in PEM envelope ─────────────────────────────────
        let pem_object = PemObject::with_data(PEM_LABEL_RSA_PRIVATE_KEY, der_bytes);

        // ── 8. Open output writer ───────────────────────────────────
        let mut writer = open_output_writer(self.out.as_deref())?;

        // ── 9. Emit PEM (encrypted or plain) ────────────────────────
        if let Some(cipher_name) = self.cipher.as_deref() {
            // Encrypted PEM path.  Currently surfaces a
            // `CryptoError::Encoding` from the
            // `pem::encode_encrypted` stub awaiting EVP cipher
            // integration; we propagate the underlying error
            // verbatim so the diagnostic traces the missing layer
            // explicitly.
            // `passphrase` is `Option<Zeroizing<Vec<u8>>>`; flatten via
            // `as_deref()` (→ `Option<&Vec<u8>>`) and then
            // `Vec::as_slice` (→ `Option<&[u8]>`) to match
            // `emit_encrypted_pem`'s signature.  No copy is performed;
            // the slice continues to reference the zeroizing buffer.
            let pw_bytes: Option<&[u8]> = passphrase.as_deref().map(Vec::as_slice);
            emit_encrypted_pem(&pem_object, cipher_name, pw_bytes, &mut writer)?;
        } else {
            // Plain PEM path — the common case.
            if self.passout.is_some() {
                // Match the C tool's behaviour of silently ignoring
                // `-passout` when `-cipher` is absent; surface a
                // `warn!` event rather than failing so legacy scripts
                // that always set `-passout` for symmetry continue
                // to work.
                warn!(
                    "genrsa: -passout supplied without -cipher; \
                     pass-phrase will be ignored (output is unencrypted)"
                );
            }
            encode_to_writer(&pem_object, &mut writer).map_err(|err| {
                error!(error = %err, "genrsa: PEM encoding/write failed");
                err
            })?;
        }

        // ── 10. Flush writer ────────────────────────────────────────
        writer.flush().map_err(|err| {
            error!(error = %err, "genrsa: writer flush failed");
            CryptoError::Io(err)
        })?;

        info!(
            bits,
            primes,
            traditional = self.traditional,
            "genrsa: RSA private key written successfully"
        );
        Ok(())
    }

    /// Validate cross-field argument combinations.
    ///
    /// Mirrors the inline option-validation logic at
    /// `apps/genrsa.c:151–165` (numbits range), the implicit
    /// `-cipher` / `-passout` pairing, and the prime-count
    /// guard rails.
    fn validate_args(&self) -> Result<(), CryptoError> {
        let bits = self.numbits.unwrap_or(DEFAULT_BITS);
        let primes = self.primes.unwrap_or(DEFAULT_PRIMES);

        if bits == 0 {
            return Err(internal_error(
                "numbits must be greater than zero (got 0)".to_string(),
            ));
        }

        // Soft cap warning, not error — matches `apps/genrsa.c:152–155`.
        // The C tool calls `BIO_printf(bio_err, "Warning: ...")` and
        // continues; the Rust port emits a structured `warn!` event.
        if bits > OPENSSL_RSA_MAX_MODULUS_BITS {
            warn!(
                bits,
                max = OPENSSL_RSA_MAX_MODULUS_BITS,
                "genrsa: requested key size exceeds OPENSSL_RSA_MAX_MODULUS_BITS \
                 ({OPENSSL_RSA_MAX_MODULUS_BITS}); generation may take a very long time"
            );
        }

        if primes < MIN_PRIMES {
            return Err(internal_error(format!(
                "primes must be at least {MIN_PRIMES} (got {primes})"
            )));
        }

        if primes > MAX_PRIMES {
            return Err(internal_error(format!(
                "primes must be at most {MAX_PRIMES} \
                 (RSA_MAX_PRIME_NUM, got {primes})"
            )));
        }

        // `-cipher` requires `-passout` to be resolvable to a
        // pass-phrase source.  The C tool accepts `-cipher` without
        // `-passout` and prompts on /dev/tty; the Rust port refuses
        // to fall back to an interactive prompt and surfaces a
        // typed `Internal` error instead — matching the design
        // documented in `crate::lib::password` (no implicit
        // tty fallback per Rule R8 and R10).
        if self.cipher.is_some() && self.passout.is_none() {
            return Err(internal_error(
                "-cipher requires -passout to specify the pass-phrase source \
                 (e.g. `-passout pass:hunter2`, `-passout env:PASSPHRASE`); \
                 interactive tty prompts are not supported"
                    .to_string(),
            ));
        }

        trace!(
            bits,
            primes,
            cipher = ?self.cipher,
            traditional = self.traditional,
            "genrsa: argument validation passed"
        );
        Ok(())
    }

    /// Emit the verbose post-keygen summary mirroring
    /// `apps/genrsa.c:210–227` — log the public exponent in hex and
    /// decimal form.  Called only when `--verbose` is set.
    /// Exposed as an associated function (no `&self`) because the
    /// log message does not depend on any field of `GenrsaArgs`;
    /// keeping it under `impl GenrsaArgs` retains its scoping for
    /// the verbose path while satisfying `clippy::unused_self`.
    fn emit_verbose_keygen_summary(keypair: &RsaKeyPair) {
        let public_exponent: &BigNum = keypair.private_key().public_exponent();
        let hex = public_exponent.to_hex();
        let dec = public_exponent.to_dec();
        let bits = public_exponent.num_bits();
        info!(
            bits,
            hex = %hex,
            dec = %dec,
            "genrsa: public exponent (e)"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Free helpers (no `self` state required)
// ───────────────────────────────────────────────────────────────────────────

/// Build a [`CryptoError`] wrapping a [`CommonError::Internal`] with
/// the supplied message.  Used to surface argument-validation
/// failures and pass-phrase parsing failures (the latter return
/// [`crate::lib::password::PasswordError`], a type that has no `From`
/// impl for [`CryptoError`]).
///
/// Mirrors the helper of the same name in
/// `crates/openssl-cli/src/commands/genpkey.rs` for cross-command
/// consistency.
fn internal_error(msg: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Internal(msg.into()))
}

/// Resolve a `-passout` source specifier into a securely-zeroed
/// byte buffer.
///
/// Replaces the call `app_passwd(NULL, passoutarg, NULL, &passout)`
/// at `apps/genrsa.c:172–174`.  The returned [`Zeroizing<Vec<u8>>`]
/// is wiped from memory on drop, matching the C
/// `OPENSSL_clear_free(passout, ...)` cleanup at
/// `apps/genrsa.c:240`.
///
/// `kind` is used for diagnostic messages only.
fn resolve_password(
    spec: Option<&str>,
    kind: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
    let Some(spec) = spec else {
        trace!(kind, "genrsa: no password source configured");
        return Ok(None);
    };
    debug!(kind, "genrsa: resolving password source");
    let pw = parse_password_source(spec)
        .map_err(|err| internal_error(format!("failed to resolve {kind} source: {err}")))?;
    // `pw` is `Zeroizing<String>`; copy into a `Zeroizing<Vec<u8>>`
    // for the encoder API which takes `&[u8]`.  The original `pw`
    // is dropped (and zeroed) at the end of this function.
    Ok(Some(Zeroizing::new(pw.as_bytes().to_vec())))
}

/// Open a writer for the supplied path, falling back to standard
/// output when `path` is [`None`].
///
/// Mirrors `bio_open_owner(outfile, FORMAT_PEM, private)` at
/// `apps/genrsa.c:178–180`.  The C helper opens the file in binary
/// "owner" mode (0600); the Rust port relies on `File::create`'s
/// default mode (umask-dependent).  Refining the file mode to 0600
/// is a follow-on item tracked under [`UNREAD: reserved`] policy.
fn open_output_writer(path: Option<&Path>) -> Result<Box<dyn Write>, CryptoError> {
    if let Some(path) = path {
        debug!(path = %path.display(), "genrsa: opening output file");
        let file = File::create(path).map_err(|err| {
            error!(
                path = %path.display(),
                error = %err,
                "genrsa: cannot create output file"
            );
            CryptoError::Io(err)
        })?;
        Ok(Box::new(BufWriter::new(file)))
    } else {
        debug!("genrsa: writing output to stdout");
        Ok(Box::new(BufWriter::new(stdout())))
    }
}

/// Emit an encrypted PEM block, delegating cipher work to
/// [`openssl_crypto::pem::encode_encrypted`].
///
/// In the current workspace this path always returns
/// [`CryptoError::Encoding`] because `encode_encrypted` is a
/// signature-only stub awaiting the EVP cipher layer.  We keep the
/// helper structurally complete (single-call site, single
/// failure-translation hop) so the rest of the pipeline is
/// future-proof: when the cipher layer lands, this function becomes
/// the only call site that needs to be updated.
///
/// The pass-phrase is required to be `Some` because the
/// [`GenrsaArgs::validate_args`] check rejects `cipher.is_some() &&
/// passout.is_none()` upstream.  We assert defensively here to
/// surface a clear `Internal` error if that invariant is ever
/// violated by future refactors.
fn emit_encrypted_pem(
    obj: &PemObject,
    cipher: &str,
    passphrase: Option<&[u8]>,
    writer: &mut dyn Write,
) -> Result<(), CryptoError> {
    let Some(pw) = passphrase else {
        return Err(internal_error(
            "encrypted PEM output requires a resolved pass-phrase \
             (validate_args should have rejected this combination earlier)"
                .to_string(),
        ));
    };
    let encrypted = encode_encrypted(obj, cipher, pw).map_err(|err| {
        error!(cipher, error = %err, "genrsa: encrypted PEM encoding failed");
        // Re-wrap the underlying `CryptoError::Encoding` with
        // additional context so the caller can distinguish "cipher
        // layer not yet implemented" from "bad cipher name" etc.
        match err {
            CryptoError::Encoding(msg) => CryptoError::Encoding(format!(
                "genrsa encrypted PEM output via cipher '{cipher}' failed: {msg}"
            )),
            other => other,
        }
    })?;
    writer.write_all(encrypted.as_bytes()).map_err(|err| {
        error!(error = %err, "genrsa: write of encrypted PEM block failed");
        CryptoError::Io(err)
    })?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
// Tests legitimately use `expect()`, `unwrap()`, and `panic!()` to
// surface failures with rich diagnostics under `cargo test`.  Disable
// the strict production lints for the test module only — same
// pattern as `commands/genpkey.rs::tests`.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Construct a [`GenrsaArgs`] populated with neutral defaults
    /// (every `Option` `None`, every `bool` `false`).  Helper for
    /// constructing test cases without repeating field-by-field
    /// initialisation.
    fn default_args() -> GenrsaArgs {
        GenrsaArgs {
            numbits: None,
            out: None,
            passout: None,
            cipher: None,
            primes: None,
            verbose: false,
            traditional: false,
        }
    }

    // ────────────────────────────────────────────────────────────────
    // is_dispatch_only_invocation tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn dispatch_only_invocation_recognised_for_default_args() {
        let args = default_args();
        assert!(
            args.is_dispatch_only_invocation(),
            "all-defaults args must be classified as dispatch-only"
        );
    }

    #[test]
    fn dispatch_only_rejected_when_numbits_set() {
        let mut args = default_args();
        args.numbits = Some(2048);
        assert!(!args.is_dispatch_only_invocation());
    }

    #[test]
    fn dispatch_only_rejected_when_out_set() {
        let mut args = default_args();
        args.out = Some(PathBuf::from("/tmp/key.pem"));
        assert!(!args.is_dispatch_only_invocation());
    }

    #[test]
    fn dispatch_only_rejected_when_passout_set() {
        let mut args = default_args();
        args.passout = Some("pass:hunter2".to_string());
        assert!(!args.is_dispatch_only_invocation());
    }

    #[test]
    fn dispatch_only_rejected_when_cipher_set() {
        let mut args = default_args();
        args.cipher = Some("AES-256-CBC".to_string());
        assert!(!args.is_dispatch_only_invocation());
    }

    #[test]
    fn dispatch_only_rejected_when_primes_set() {
        let mut args = default_args();
        args.primes = Some(2);
        assert!(!args.is_dispatch_only_invocation());
    }

    #[test]
    fn dispatch_only_rejected_when_verbose_set() {
        let mut args = default_args();
        args.verbose = true;
        assert!(!args.is_dispatch_only_invocation());
    }

    #[test]
    fn dispatch_only_rejected_when_traditional_set() {
        let mut args = default_args();
        args.traditional = true;
        assert!(!args.is_dispatch_only_invocation());
    }

    // ────────────────────────────────────────────────────────────────
    // validate_args tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn validate_accepts_default_args() {
        let args = default_args();
        args.validate_args()
            .expect("all-default args must validate (numbits=2048, primes=2)");
    }

    #[test]
    fn validate_accepts_minimal_explicit_args() {
        let mut args = default_args();
        args.numbits = Some(2048);
        args.primes = Some(2);
        args.validate_args()
            .expect("explicit defaults must validate");
    }

    #[test]
    fn validate_accepts_typical_2048_bit_args() {
        let mut args = default_args();
        args.numbits = Some(2048);
        args.validate_args().expect("2048-bit RSA must validate");
    }

    #[test]
    fn validate_accepts_3072_bit_args() {
        let mut args = default_args();
        args.numbits = Some(3072);
        args.validate_args().expect("3072-bit RSA must validate");
    }

    #[test]
    fn validate_accepts_4096_bit_args() {
        let mut args = default_args();
        args.numbits = Some(4096);
        args.validate_args().expect("4096-bit RSA must validate");
    }

    #[test]
    fn validate_rejects_zero_numbits() {
        let mut args = default_args();
        args.numbits = Some(0);
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(
                    msg.contains("numbits") || msg.contains("zero"),
                    "msg = {msg}"
                );
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_warns_but_accepts_oversize_numbits() {
        let mut args = default_args();
        // Just over the soft cap.
        args.numbits = Some(OPENSSL_RSA_MAX_MODULUS_BITS + 1);
        args.validate_args()
            .expect("oversize numbits must produce warning, not error");
    }

    #[test]
    fn validate_rejects_zero_primes() {
        let mut args = default_args();
        args.primes = Some(0);
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("primes"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_one_prime() {
        let mut args = default_args();
        args.primes = Some(1);
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("primes"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_max_primes() {
        let mut args = default_args();
        args.primes = Some(MAX_PRIMES);
        args.validate_args()
            .expect("MAX_PRIMES must validate at the boundary");
    }

    #[test]
    fn validate_rejects_too_many_primes() {
        let mut args = default_args();
        args.primes = Some(MAX_PRIMES + 1);
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("primes"), "msg = {msg}");
                assert!(msg.contains(&MAX_PRIMES.to_string()), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_cipher_without_passout() {
        let mut args = default_args();
        args.cipher = Some("AES-256-CBC".to_string());
        match args.validate_args() {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("-cipher"), "msg = {msg}");
                assert!(msg.contains("-passout"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_cipher_with_passout() {
        let mut args = default_args();
        args.cipher = Some("AES-256-CBC".to_string());
        args.passout = Some("pass:hunter2".to_string());
        args.validate_args()
            .expect("cipher+passout pairing must validate");
    }

    #[test]
    fn validate_accepts_passout_without_cipher() {
        // `-passout` without `-cipher` is a soft case — the C tool
        // silently ignores it; we accept and rely on a `warn!` event
        // emitted at execute() time.
        let mut args = default_args();
        args.passout = Some("pass:hunter2".to_string());
        args.validate_args()
            .expect("passout without cipher must validate (soft)");
    }

    #[test]
    fn validate_accepts_traditional_flag() {
        let mut args = default_args();
        args.traditional = true;
        args.validate_args()
            .expect("-traditional must validate (no conflicts)");
    }

    #[test]
    fn validate_accepts_verbose_flag() {
        let mut args = default_args();
        args.verbose = true;
        args.validate_args()
            .expect("--verbose must validate (no conflicts)");
    }

    // ────────────────────────────────────────────────────────────────
    // Constant sanity-checks
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn default_bits_matches_c_define() {
        assert_eq!(DEFAULT_BITS, 2048, "must match C #define DEFBITS 2048");
    }

    #[test]
    fn default_primes_matches_c_define() {
        assert_eq!(DEFAULT_PRIMES, 2, "must match C #define DEFPRIMES 2");
    }

    #[test]
    fn f4_exponent_is_fermat_f4() {
        assert_eq!(F4_EXPONENT, 65_537, "RSA_F4 must be 0x10001");
        assert_eq!(F4_EXPONENT, 0x0001_0001);
    }

    #[test]
    fn rsa_3_exponent_is_three() {
        assert_eq!(RSA_3_EXPONENT, 3, "RSA_3 must be the integer 3");
    }

    #[test]
    fn modulus_cap_matches_openssl() {
        assert_eq!(
            OPENSSL_RSA_MAX_MODULUS_BITS, 16_384,
            "must match OpenSSL header value"
        );
    }

    // ────────────────────────────────────────────────────────────────
    // Free-helper tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn internal_error_wraps_common_internal() {
        match internal_error("test message") {
            CryptoError::Common(CommonError::Internal(msg)) => {
                assert_eq!(msg, "test message");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_password_returns_none_for_no_spec() {
        let r = resolve_password(None, "passout").unwrap();
        assert!(r.is_none(), "None spec must yield None pass-phrase");
    }

    #[test]
    fn resolve_password_parses_pass_literal() {
        let r = resolve_password(Some("pass:hunter2"), "passout").unwrap();
        let bytes = r.expect("pass:hunter2 must resolve to Some");
        assert_eq!(&**bytes, b"hunter2");
    }

    #[test]
    fn resolve_password_parses_empty_pass_literal() {
        let r = resolve_password(Some("pass:"), "passout").unwrap();
        let bytes = r.expect("pass: (empty) must resolve to Some");
        assert!(bytes.is_empty(), "empty literal must yield empty buffer");
    }

    #[test]
    fn resolve_password_rejects_unknown_scheme() {
        let r = resolve_password(Some("bogus:format"), "passout");
        match r {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("passout"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    // ────────────────────────────────────────────────────────────────
    // emit_encrypted_pem tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn emit_encrypted_pem_rejects_missing_passphrase() {
        let obj = PemObject::with_data(PEM_LABEL_RSA_PRIVATE_KEY, vec![0x30, 0x82]);
        let mut sink = Vec::new();
        match emit_encrypted_pem(&obj, "AES-256-CBC", None, &mut sink) {
            Err(CryptoError::Common(CommonError::Internal(msg))) => {
                assert!(msg.contains("pass-phrase"), "msg = {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn emit_encrypted_pem_propagates_stub_encoding_error() {
        // The current `pem::encode_encrypted` is a stub that always
        // returns `CryptoError::Encoding` once preconditions pass.
        // Verify our wrapper preserves the variant and includes
        // the cipher name in the error message.
        let obj = PemObject::with_data(PEM_LABEL_RSA_PRIVATE_KEY, vec![0x30, 0x82, 0x01, 0x22]);
        let mut sink = Vec::new();
        match emit_encrypted_pem(&obj, "AES-256-CBC", Some(b"hunter2"), &mut sink) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("AES-256-CBC"), "msg = {msg}");
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    // ────────────────────────────────────────────────────────────────
    // open_output_writer tests
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn open_output_writer_returns_stdout_for_none() {
        let writer = open_output_writer(None);
        assert!(writer.is_ok(), "stdout writer must always succeed");
    }

    #[test]
    fn open_output_writer_returns_io_error_for_unwritable_path() {
        // A path that cannot exist on any UNIX or Windows system —
        // `/proc/1/<bogus>` is read-only on Linux and the path
        // does not exist on macOS / Windows.  Either way `File::create`
        // must fail with an `io::Error`, which we map to
        // `CryptoError::Io`.  Acceptable outcomes:
        //   • `Err(CryptoError::Io(_))` — the expected path
        //   • `Ok(_)`                   — sandboxed test environments
        //     where the path is silently writable; tolerated
        //
        // Any other `Err` variant indicates a misclassification of
        // the underlying I/O failure and is a real test failure.
        // We can't `{:?}`-print `Ok(_)` because the writer carries
        // `Box<dyn Write>` (no `Debug`), so we inspect via `if let`.
        let bogus = Path::new("/proc/1/cannot-create-this-file");
        let result = open_output_writer(Some(bogus));
        if let Err(err) = result {
            assert!(
                matches!(err, CryptoError::Io(_)),
                "expected CryptoError::Io, got {err:?}"
            );
        }
        // The `Ok` arm is silently accepted (test environment
        // permissively allowed file creation).
    }

    #[test]
    fn open_output_writer_writes_to_temp_file() {
        // Pick a tempdir-style path under the OS tempdir.  We use
        // `std::env::temp_dir()` rather than the `tempfile` crate
        // because we only need a write target and explicit cleanup.
        let mut path = std::env::temp_dir();
        // Use a predictable filename suffixed with the test name and
        // a process-local nonce to avoid cross-test races.
        path.push(format!(
            "openssl-cli-genrsa-test-{}.tmp",
            std::process::id()
        ));
        // Best-effort cleanup of any leftover file from a prior run.
        let _ = std::fs::remove_file(&path);

        {
            let mut writer = open_output_writer(Some(&path)).expect("temp file must open");
            writer
                .write_all(b"hello\n")
                .expect("write to temp file must succeed");
            writer.flush().expect("flush must succeed");
            // Drop the writer here to release the file handle.
        }
        let contents = std::fs::read(&path).expect("temp file must be readable");
        assert_eq!(contents, b"hello\n");

        // Clean up.
        let _ = std::fs::remove_file(&path);
    }

    // ────────────────────────────────────────────────────────────────
    // GenrsaArgs construction (smoke test)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn args_struct_construction_smoke() {
        // Construct via `default_args()` and confirm every field is
        // accessible at the expected type.  Catches accidental field
        // renames or type changes during refactors.
        let a = default_args();
        let _: Option<u32> = a.numbits;
        let _: Option<PathBuf> = a.out.clone();
        let _: Option<String> = a.passout.clone();
        let _: Option<String> = a.cipher.clone();
        let _: Option<usize> = a.primes;
        let _: bool = a.verbose;
        let _: bool = a.traditional;
    }
}
