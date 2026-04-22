//! AES-256-GCM bulk encryption/decryption benchmark (Workload 1) for Gate 3.
//!
//! This file provides the **first of ≥2 required criterion benchmarks** for
//! AAP §0.8.2 Gate 3 (Performance Baseline). It measures AES-256-GCM
//! authenticated encryption/decryption throughput at five input sizes
//! (16 B, 256 B, 1 KiB, 8 KiB, 16 KiB) through the `openssl-crypto` EVP
//! cipher abstraction — the same code path a real application would use.
//!
//! # C → Rust Translation Reference
//!
//! The benchmark mirrors the `apps/speed.c` AEAD test harness
//! (`EVP_Update_loop_aead_enc`, lines 989–1050, and `EVP_Update_loop_aead_dec`,
//! lines 1054–1140):
//!
//! | C Source (apps/speed.c) | Line(s)  | Rust Equivalent                              |
//! |-------------------------|----------|----------------------------------------------|
//! | `aead_lengths_list[]`   | 139–141  | [`BENCH_SIZES`] (per AAP: 16,256,1K,8K,16K)  |
//! | `init_evp_cipher_ctx()` | 898–932  | [`Cipher::fetch`] + [`CipherCtx::new`]        |
//! | `EVP_EncryptInit_ex()`  | 924      | [`CipherCtx::encrypt_init`]                   |
//! | `EVP_EncryptUpdate(AAD)`| 1033     | [`CipherCtx::set_aad`]                        |
//! | `EVP_EncryptUpdate`     | 1039     | [`CipherCtx::update`]                         |
//! | `EVP_EncryptFinal_ex`   | 1044     | [`CipherCtx::finalize`]                       |
//! | `EVP_CTRL_AEAD_GET_TAG` | 1046-ish | [`CipherCtx::get_aead_tag`]                   |
//! | `aad[EVP_AEAD_TLS1_AAD_LEN]` | 596 | [`AAD`] = `[0xcc; 13]`                        |
//! | `iv[MAX_BLOCK_SIZE/8]`  | 897      | [`GCM_IV`] (12-byte canonical GCM nonce)      |
//!
//! # Running
//!
//! ```bash
//! cargo bench --package openssl-crypto --bench aes_bench
//! ```
//!
//! HTML reports are emitted to `target/criterion/`.
//!
//! # Gate 3 Compliance
//!
//! Criterion reports both wall-clock (ns/op) AND throughput (MB/s) automatically
//! via [`Throughput::Bytes`]. Results feed the overall `BENCHMARK_REPORT.md`
//! artifact targeting ±20 % parity against the upstream C+perlasm baseline.
//!
//! # Rule Compliance (AAP §0.8.1)
//!
//! * **R5 (Nullability):** `Cipher::fetch(..., None)` uses `Option<&str>` not
//!   sentinel; `Some(&GCM_IV)` binds the nonce.
//! * **R6 (Lossless Casts):** All `usize → u64` conversions use
//!   [`u64::try_from`] with descriptive `expect()`.
//! * **R8 (Zero Unsafe):** Zero `unsafe` blocks in this file.
//! * **R9 (Warning-Free):** No module-level suppressions beyond
//!   `expect_used`/`unwrap_used`/`panic`, all of which are benchmark-setup
//!   conventions explicitly permitted for `benches/` per workspace lint policy.
//! * **R10 (Wiring):** Benchmarks exercise the exact EVP API path an
//!   application would use: `LibContext` → `Cipher::fetch` → `CipherCtx`.

// Benchmark code runs as a standalone harness; panics during setup or in the
// inner loop are acceptable signals of environment failure rather than library
// defects. The workspace-wide `clippy::expect_used`/`unwrap_used`/`panic` lints
// are warn-level, so scoped `#[allow]`s here document that this file
// legitimately follows the benchmark convention.
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::missing_panics_doc)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use openssl_crypto::context::LibContext;
use openssl_crypto::evp::cipher::{Cipher, CipherCtx, CipherDirection, AES_256_GCM};
use openssl_crypto::rand::rand_bytes;

// ============================================================================
// Benchmark Constants
// ============================================================================

/// Input buffer sizes (bytes) for the AES-256-GCM workload.
///
/// These values match the AAP specification exactly — 16 B, 256 B, 1 KiB,
/// 8 KiB, 16 KiB — and are a strict subset of the C baseline's
/// `aead_lengths_list[]` (`apps/speed.c` lines 139–141):
/// `{2, 31, 136, 1024, 8 * 1024, 16 * 1024}`.
const BENCH_SIZES: &[usize] = &[16, 256, 1024, 8 * 1024, 16 * 1024];

/// 256-bit AES key (32 bytes) used for all benchmarks.
///
/// The exact byte value is irrelevant to measured performance (AES key
/// schedule runs in constant time), but a fixed non-zero pattern guards
/// against opportunistic "zero key" code paths that some implementations
/// might take. Mirrors the `key32` buffer in `apps/speed.c` which is
/// populated by `RAND_bytes` at program start-up.
const AES_256_KEY: [u8; 32] = [0x42u8; 32];

/// Standard 96-bit (12-byte) GCM IV/nonce.
///
/// 12 bytes is the canonical GCM IV length recommended by NIST SP 800-38D
/// and used by TLS 1.3. The C baseline allocates
/// `iv[2 * MAX_BLOCK_SIZE / 8] = iv[32]` (`apps/speed.c` line 897) but only
/// the first 12 bytes are used for GCM.
const GCM_IV: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
];

/// 13-byte Additional Authenticated Data (AAD).
///
/// Matches `EVP_AEAD_TLS1_AAD_LEN` — the 13-byte AAD a TLS 1.2 record
/// binds to an AEAD cipher. Pattern is identical to `apps/speed.c` line 596:
/// `static unsigned char aad[EVP_AEAD_TLS1_AAD_LEN] = { 0xcc };`.
/// Using TLS-sized AAD makes the benchmark representative of real TLS traffic.
const AAD: [u8; 13] = [0xcc; 13];

/// GCM authentication tag length in bytes (128 bits — canonical).
const GCM_TAG_LEN: usize = 16;

// ============================================================================
// Helper Functions
// ============================================================================

/// Generates a buffer of `size` cryptographically random bytes.
///
/// Uses [`rand_bytes`] (the Rust equivalent of C `RAND_bytes`) to fill the
/// buffer. Random plaintext prevents the cipher implementation from taking
/// constant-input shortcuts (branch prediction on all-zero input, etc.),
/// producing more realistic throughput numbers.
///
/// Returns an empty `Vec` for `size == 0`.
fn make_random_plaintext(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    if size > 0 {
        // rand_bytes on non-empty slices must succeed in a healthy environment.
        rand_bytes(&mut buf).expect("rand_bytes: DRBG failed to produce plaintext");
    }
    buf
}

/// One-time benchmark setup: creates a [`LibContext`] and fetches the
/// AES-256-GCM [`Cipher`] descriptor.
///
/// The `LibContext` is cheap to construct but non-trivial — it initialises
/// the provider registry, the property store, the method cache, and the
/// default DRBG. Hoisting this work out of the per-iteration closure
/// concentrates measurement on the actual crypto work.
///
/// Returns an `(Arc<LibContext>, Cipher)` tuple. The `LibContext` must be
/// held for the lifetime of the benchmark so that any `Arc`-held internal
/// state remains valid through every call.
fn fetch_aes_256_gcm() -> (Arc<LibContext>, Cipher) {
    // LibContext::new() creates a fresh, non-default context; LibContext::default()
    // would return the global singleton. Using new() gives each benchmark run a
    // clean provider store, eliminating cross-test contamination when multiple
    // benchmark binaries share a process.
    let ctx = LibContext::new();
    let cipher = Cipher::fetch(&ctx, AES_256_GCM, None)
        .expect("Cipher::fetch: AES-256-GCM must be available from the default provider");
    (ctx, cipher)
}

/// Initialises a [`CipherCtx`] for the requested [`CipherDirection`] and
/// verifies the direction reflects the correct state.
///
/// Centralising the init logic through this helper:
/// 1. Exercises `CipherDirection::{Encrypt, Decrypt}` (AAP schema requires
///    both variants to be *used*, not just imported).
/// 2. Asserts the newly-set direction via
///    [`CipherCtx::direction`] — a Rule R10 wiring check that proves the
///    init propagated through the real API, not just a stubbed setter.
fn init_cipher_ctx(cipher: &Cipher, direction: CipherDirection) -> CipherCtx {
    let mut ctx = CipherCtx::new();
    match direction {
        CipherDirection::Encrypt => {
            ctx.encrypt_init(cipher, &AES_256_KEY, Some(&GCM_IV), None)
                .expect("encrypt_init: AES-256-GCM with 32-byte key and 12-byte IV");
        }
        CipherDirection::Decrypt => {
            ctx.decrypt_init(cipher, &AES_256_KEY, Some(&GCM_IV), None)
                .expect("decrypt_init: AES-256-GCM with 32-byte key and 12-byte IV");
        }
    }
    debug_assert_eq!(
        ctx.direction(),
        Some(direction),
        "CipherCtx direction mismatch after init",
    );
    ctx
}

/// Pre-encrypts `plaintext` with AES-256-GCM, returning `(ciphertext, tag)`.
///
/// Used to prepare fixture data for the decrypt benchmark: decryption must
/// be fed a valid ciphertext + 16-byte authentication tag that was produced
/// with the same key, IV, and AAD; otherwise
/// [`CipherCtx::finalize`] would fail the tag check.
///
/// This encryption happens **once per size** during benchmark setup, not
/// inside the measured loop.
fn encrypt_fixture(cipher: &Cipher, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut ctx = init_cipher_ctx(cipher, CipherDirection::Encrypt);
    ctx.set_aad(&AAD)
        .expect("set_aad: AES-256-GCM is AEAD and accepts 13-byte AAD");

    // R6: output capacity uses checked_add implicitly via with_capacity's
    // assumption that values fit; BENCH_SIZES max is 16 KiB + 16-byte tag.
    let mut ciphertext = Vec::with_capacity(plaintext.len().saturating_add(GCM_TAG_LEN));
    ctx.update(plaintext, &mut ciphertext)
        .expect("update: AES-256-GCM encryption");
    ctx.finalize(&mut ciphertext)
        .expect("finalize: AES-256-GCM encryption");
    let tag = ctx
        .get_aead_tag(GCM_TAG_LEN)
        .expect("get_aead_tag: tag retrieval after finalize");
    debug_assert_eq!(tag.len(), GCM_TAG_LEN, "GCM tag must be 16 bytes");
    (ciphertext, tag)
}

/// Converts a `usize` size to `u64` for [`Throughput::Bytes`].
///
/// Rule R6: avoids a bare `as u64` cast by routing through [`u64::try_from`].
/// `BENCH_SIZES` values are all ≤ 16 KiB, so this conversion can never fail
/// on any supported target.
#[inline]
fn size_to_u64(size: usize) -> u64 {
    u64::try_from(size).expect("BENCH_SIZES values (≤ 16 KiB) always fit in u64")
}

// ============================================================================
// Benchmark: AES-256-GCM Encrypt
// ============================================================================

/// Benchmarks AES-256-GCM encryption (seal) across [`BENCH_SIZES`].
///
/// Each iteration performs the complete TLS-like AEAD sequence:
///
/// 1. Create a fresh `CipherCtx` (mirrors C `EVP_CIPHER_CTX_new`).
/// 2. `encrypt_init(&cipher, &KEY, Some(&IV), None)` (C `EVP_EncryptInit_ex`).
/// 3. `set_aad(&AAD)` — 13-byte TLS-sized AAD (C `EVP_EncryptUpdate` with NULL out).
/// 4. `update(plaintext, &mut ciphertext)` — bulk encrypt (C `EVP_EncryptUpdate`).
/// 5. `finalize(&mut ciphertext)` — flush + compute tag (C `EVP_EncryptFinal_ex`).
/// 6. `get_aead_tag(16)` — retrieve GCM tag (C `EVP_CTRL_AEAD_GET_TAG`).
///
/// Step 1 is intentionally inside the loop: real applications (particularly
/// TLS record encryption) construct a fresh context per record. Keeping this
/// in the hot path captures context-allocation + key-schedule cost that
/// `apps/speed.c` amortises over its large `count` loop.
fn bench_aes_256_gcm_encrypt(c: &mut Criterion) {
    let (_lib_ctx, cipher) = fetch_aes_256_gcm();
    let mut group = c.benchmark_group("aes_256_gcm_encrypt");

    for &size in BENCH_SIZES {
        let plaintext = make_random_plaintext(size);

        // Throughput::Bytes drives MB/s reporting alongside ns/op wall-clock.
        group.throughput(Throughput::Bytes(size_to_u64(size)));

        group.bench_with_input(
            BenchmarkId::new("encrypt", size),
            &plaintext,
            |bencher, plaintext_ref| {
                bencher.iter(|| {
                    let mut ctx = init_cipher_ctx(&cipher, CipherDirection::Encrypt);
                    ctx.set_aad(&AAD).expect("set_aad");

                    let mut ciphertext =
                        Vec::with_capacity(plaintext_ref.len().saturating_add(GCM_TAG_LEN));
                    ctx.update(black_box(plaintext_ref), &mut ciphertext)
                        .expect("update");
                    ctx.finalize(&mut ciphertext).expect("finalize");
                    let tag = ctx.get_aead_tag(GCM_TAG_LEN).expect("get_aead_tag");

                    // black_box prevents the optimiser from eliminating the
                    // computation because the result appears unused.
                    black_box((ciphertext, tag))
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark: AES-256-GCM Decrypt
// ============================================================================

/// Benchmarks AES-256-GCM decryption (open) across [`BENCH_SIZES`].
///
/// Pre-encrypts each plaintext *once* during setup (outside the measured
/// loop) to obtain a valid `(ciphertext, tag)` pair. Each benchmark iteration
/// then performs the complete decrypt sequence:
///
/// 1. Create a fresh `CipherCtx` (C `EVP_CIPHER_CTX_new`).
/// 2. `decrypt_init(&cipher, &KEY, Some(&IV), None)` (C `EVP_DecryptInit_ex`).
/// 3. `set_aad(&AAD)` — 13-byte TLS-sized AAD.
/// 4. `set_aead_tag(&tag)` — pre-set expected tag (C `EVP_CTRL_AEAD_SET_TAG`).
/// 5. `update(ciphertext, &mut plaintext)` — bulk decrypt.
/// 6. `finalize(&mut plaintext)` — verifies tag, fails on mismatch.
///
/// Successful finalize confirms round-trip correctness at every benchmark
/// invocation (Gate 1 E2E Boundary check, implicitly).
fn bench_aes_256_gcm_decrypt(c: &mut Criterion) {
    let (_lib_ctx, cipher) = fetch_aes_256_gcm();
    let mut group = c.benchmark_group("aes_256_gcm_decrypt");

    for &size in BENCH_SIZES {
        let plaintext = make_random_plaintext(size);
        let (ciphertext, tag) = encrypt_fixture(&cipher, &plaintext);

        group.throughput(Throughput::Bytes(size_to_u64(size)));

        group.bench_with_input(
            BenchmarkId::new("decrypt", size),
            &(ciphertext, tag),
            |bencher, fixture| {
                let (ct, tag) = fixture;
                bencher.iter(|| {
                    let mut ctx = init_cipher_ctx(&cipher, CipherDirection::Decrypt);
                    ctx.set_aad(&AAD).expect("set_aad");
                    ctx.set_aead_tag(tag).expect("set_aead_tag");

                    let mut recovered = Vec::with_capacity(ct.len());
                    ctx.update(black_box(ct), &mut recovered).expect("update");
                    // finalize verifies the tag; mismatch would panic here.
                    ctx.finalize(&mut recovered).expect("finalize");

                    black_box(recovered)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark: Encrypt → Decrypt Round-Trip
// ============================================================================

/// Benchmarks a complete AES-256-GCM encrypt-then-decrypt round-trip.
///
/// Useful for end-to-end AEAD throughput assessment — the single number
/// reported here summarises total CPU cost of protecting + unprotecting a
/// message, which approximates the symmetric path length inside a TLS
/// record-layer exchange. Reports throughput relative to *plaintext size*
/// (not 2× size), so MB/s is comparable between round-trip and one-way
/// benchmarks.
fn bench_aes_256_gcm_throughput(c: &mut Criterion) {
    let (_lib_ctx, cipher) = fetch_aes_256_gcm();
    let mut group = c.benchmark_group("aes_256_gcm_round_trip");

    for &size in BENCH_SIZES {
        let plaintext = make_random_plaintext(size);

        group.throughput(Throughput::Bytes(size_to_u64(size)));

        group.bench_with_input(
            BenchmarkId::new("round_trip", size),
            &plaintext,
            |bencher, plaintext_ref| {
                bencher.iter(|| {
                    // --- Encrypt phase ---
                    let mut enc = init_cipher_ctx(&cipher, CipherDirection::Encrypt);
                    enc.set_aad(&AAD).expect("enc set_aad");
                    let mut ciphertext =
                        Vec::with_capacity(plaintext_ref.len().saturating_add(GCM_TAG_LEN));
                    enc.update(black_box(plaintext_ref), &mut ciphertext)
                        .expect("enc update");
                    enc.finalize(&mut ciphertext).expect("enc finalize");
                    let tag = enc.get_aead_tag(GCM_TAG_LEN).expect("enc get_aead_tag");

                    // --- Decrypt phase ---
                    let mut dec = init_cipher_ctx(&cipher, CipherDirection::Decrypt);
                    dec.set_aad(&AAD).expect("dec set_aad");
                    dec.set_aead_tag(&tag).expect("dec set_aead_tag");
                    let mut recovered = Vec::with_capacity(ciphertext.len());
                    dec.update(&ciphertext, &mut recovered).expect("dec update");
                    dec.finalize(&mut recovered).expect("dec finalize");

                    black_box(recovered)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Criterion Harness
// ============================================================================

criterion_group!(
    name = benches;
    // Gate 3 tuning:
    //   * 5-second measurement time is sufficient for symmetric crypto whose
    //     per-iteration wall-clock is sub-microsecond at small sizes.
    //   * 200 samples yields tight confidence intervals without exploding
    //     the total bench runtime beyond CI budget.
    //   * 2-second warm-up lets CPU-frequency scaling and JIT branch
    //     predictors reach steady state before measurements begin.
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .sample_size(200)
        .warm_up_time(Duration::from_secs(2));
    targets =
        bench_aes_256_gcm_encrypt,
        bench_aes_256_gcm_decrypt,
        bench_aes_256_gcm_throughput
);

criterion_main!(benches);
