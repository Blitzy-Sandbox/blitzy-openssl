//! Integration tests for the post-quantum cryptography module (`crate::pqc`).
//!
//! This suite exercises the four PQC submodules in lock-step with the upstream
//! C implementation in `crypto/ml_kem/`, `crypto/ml_dsa/`, `crypto/slh_dsa/`,
//! and `crypto/lms/`:
//!
//! - **ML-KEM** (FIPS 203) — Kyber-based key encapsulation mechanism with
//!   three security categories (ML-KEM-512, -768, -1024).
//! - **ML-DSA** (FIPS 204) — Dilithium-based signature scheme with three
//!   parameter sets (ML-DSA-44, -65, -87).
//! - **SLH-DSA** (FIPS 205) — SPHINCS+-based hash-based signatures with twelve
//!   parameter sets across SHA-2 / SHAKE families × 128 / 192 / 256-bit
//!   security strengths × small / fast variants.
//! - **LMS** (NIST SP 800-208 / RFC 8554) — Leighton-Micali stateful hash-based
//!   signatures (verification only — matches upstream OpenSSL behaviour).
//!
//! ## Phase outline
//!
//! 1.  ML-KEM variant metadata (algorithm names, security categories,
//!     length contracts via `MlKemParams`).
//! 2.  ML-KEM key generation (deterministic + random entropy paths).
//! 3.  ML-KEM `encap_rand → decap` roundtrip equality per variant.
//! 4.  ML-KEM `encap_seed` determinism (same entropy ⇒ same outputs).
//! 5.  ML-KEM public/private key encode/parse roundtrip.
//! 6.  ML-KEM provider flag semantics via `prov_flags::*`.
//! 7.  ML-KEM error paths (wrong-length ciphertext, missing keys).
//! 8.  ML-DSA variant metadata + length constants.
//! 9.  ML-DSA `sign → verify` roundtrip with deterministic randomiser.
//! 10. ML-DSA tamper detection (signature flip, message change, context change).
//! 11. ML-DSA `KeySelection` semantics.
//! 12. SLH-DSA variant metadata + algorithm-name dispatch via `TryFrom<&str>`.
//! 13. SLH-DSA keygen + sign + verify roundtrip (fast subset only —
//!     SHAKE-128f / SHA2-128f to keep test wall-clock manageable).
//! 14. LMS structural tests: `LmsType::from_u32` / `LmOtsType::from_u32`
//!     roundtrip; `LmsPubKey::encoded_len` and `LmsPubKey::decode` rejection
//!     of under-length input.
//! 15. Cross-cutting `proptest!` property tests for KEM consistency.
//!
//! ## Rule compliance
//!
//! - **R5** (nullability over sentinels): Tests pass `Option<&[u8; …]>` for
//!   optional seeds and randomisers; returns are `Result`/`bool`/`Option`.
//! - **R6** (lossless casts): Length assertions compare `usize` literals
//!   directly; no bare `as` narrowing.
//! - **R8** (zero unsafe): No `unsafe` blocks in this file.
//! - **R10** (wiring): Every assertion goes through the public API surface
//!   exposed by `pqc::ml_kem`, `pqc::ml_dsa`, `pqc::slh_dsa`, and `pqc::lms`,
//!   matching how a downstream caller would consume the module.
//!
//! ## KAT provenance
//!
//! Where exact length values are asserted (e.g. ML-KEM-512 public key is
//! exactly 800 bytes), these come directly from FIPS 203 §8 / FIPS 204 §4 /
//! FIPS 205 §11. Self-consistency of `encap → decap` and `sign → verify`
//! mirrors the contract enforced by the upstream C reference. Where this
//! file uses fixed test seeds, the seeds are arbitrary but documented for
//! reproducibility — they are not security-sensitive.
//!
//! Note on feature gating: this module is included from `tests/mod.rs` under
//! `#[cfg(feature = "pqc")]`, so a redundant inner `#![cfg(feature = "pqc")]`
//! is intentionally omitted.

#![allow(clippy::expect_used)] // Tests call .expect() on known-good Results.
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.

use crate::context::LibContext;
use crate::pqc::{lms, ml_dsa, ml_kem, slh_dsa};

use openssl_common::CryptoError;
use proptest::prelude::*;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Returns a fresh default library context.  `LibContext::default()` returns
/// `Arc<LibContext>` directly per `crates/openssl-crypto/src/context.rs:1249`.
fn fixture_libctx() -> Arc<LibContext> {
    LibContext::default()
}

/// Deterministic ML-KEM key generation seed (64 bytes per FIPS 203).
const ML_KEM_TEST_SEED: [u8; 64] = [0x5A; 64];

/// Alternative ML-KEM seed for divergence checks.
const ML_KEM_TEST_SEED_ALT: [u8; 64] = [0xA5; 64];

/// ML-KEM encapsulation entropy (32 bytes per FIPS 203).
const ML_KEM_ENCAP_ENTROPY: [u8; 32] = [0x77; 32];

/// Alternative ML-KEM encapsulation entropy.
const ML_KEM_ENCAP_ENTROPY_ALT: [u8; 32] = [0x88; 32];

/// Zero randomiser for ML-DSA deterministic signing.
const ML_DSA_ZERO_RAND: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Phase 1 — ML-KEM variant metadata
// ---------------------------------------------------------------------------

#[test]
fn phase_01_ml_kem_algorithm_names() {
    assert_eq!(
        ml_kem::MlKemVariant::MlKem512.algorithm_name(),
        "ML-KEM-512"
    );
    assert_eq!(
        ml_kem::MlKemVariant::MlKem768.algorithm_name(),
        "ML-KEM-768"
    );
    assert_eq!(
        ml_kem::MlKemVariant::MlKem1024.algorithm_name(),
        "ML-KEM-1024"
    );
}

#[test]
fn phase_01_ml_kem_security_categories() {
    // FIPS 203 §8 maps the three parameter sets to NIST PQC categories 1/3/5.
    assert_eq!(ml_kem::MlKemVariant::MlKem512.security_category(), 1);
    assert_eq!(ml_kem::MlKemVariant::MlKem768.security_category(), 3);
    assert_eq!(ml_kem::MlKemVariant::MlKem1024.security_category(), 5);
}

#[test]
fn phase_01_ml_kem_params_512_exact_lengths() {
    // FIPS 203 §8 Table 2.
    let p = ml_kem::ml_kem_params_get(ml_kem::MlKemVariant::MlKem512);
    assert_eq!(p.pubkey_bytes, 800);
    assert_eq!(p.prvkey_bytes, 1632);
    assert_eq!(p.ctext_bytes, 768);
    assert_eq!(p.security_category, 1);
    assert_eq!(p.rank, 2);
    assert_eq!(p.alg, "ML-KEM-512");
}

#[test]
fn phase_01_ml_kem_params_768_exact_lengths() {
    let p = ml_kem::ml_kem_params_get(ml_kem::MlKemVariant::MlKem768);
    assert_eq!(p.pubkey_bytes, 1184);
    assert_eq!(p.prvkey_bytes, 2400);
    assert_eq!(p.ctext_bytes, 1088);
    assert_eq!(p.security_category, 3);
    assert_eq!(p.rank, 3);
}

#[test]
fn phase_01_ml_kem_params_1024_exact_lengths() {
    let p = ml_kem::ml_kem_params_get(ml_kem::MlKemVariant::MlKem1024);
    assert_eq!(p.pubkey_bytes, 1568);
    assert_eq!(p.prvkey_bytes, 3168);
    assert_eq!(p.ctext_bytes, 1568);
    assert_eq!(p.security_category, 5);
    assert_eq!(p.rank, 4);
}

#[test]
fn phase_01_ml_kem_params_lookup_by_name_canonical() {
    assert!(ml_kem::ml_kem_params_get_by_name("ML-KEM-512").is_some());
    assert!(ml_kem::ml_kem_params_get_by_name("ML-KEM-768").is_some());
    assert!(ml_kem::ml_kem_params_get_by_name("ML-KEM-1024").is_some());
}

#[test]
fn phase_01_ml_kem_params_lookup_by_name_unknown() {
    // Case-sensitive: "ml-kem-512" lower-case must fail.
    assert!(ml_kem::ml_kem_params_get_by_name("ml-kem-512").is_none());
    assert!(ml_kem::ml_kem_params_get_by_name("ML-KEM-256").is_none());
    assert!(ml_kem::ml_kem_params_get_by_name("Kyber-512").is_none());
    assert!(ml_kem::ml_kem_params_get_by_name("").is_none());
}

#[test]
fn phase_01_ml_kem_constants_match_spec() {
    // FIPS 203 §2.4: degree = 256, prime q = 3329.
    assert_eq!(ml_kem::ML_KEM_DEGREE, 256);
    assert_eq!(ml_kem::ML_KEM_PRIME, 3329);
    assert_eq!(ml_kem::SHARED_SECRET_BYTES, 32);
    assert_eq!(ml_kem::RANDOM_BYTES, 32);
    assert_eq!(ml_kem::SEED_BYTES, 64);
}

// ---------------------------------------------------------------------------
// Phase 2 — ML-KEM key generation
// ---------------------------------------------------------------------------

#[test]
fn phase_02_ml_kem_generate_deterministic_with_seed() {
    let libctx = fixture_libctx();
    let key1 = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("ML-KEM-512 keygen with fixed seed should succeed");
    let key2 = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("ML-KEM-512 keygen with fixed seed should succeed");

    // Determinism: equal seeds ⇒ equal public keys.
    assert!(key1.pubkey_cmp(&key2));
    assert!(key1.have_pubkey());
    assert!(key1.have_prvkey());
}

#[test]
fn phase_02_ml_kem_generate_diverges_with_different_seeds() {
    let libctx = fixture_libctx();
    let k1 = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let k2 = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED_ALT),
    )
    .expect("keygen");

    // Different seeds ⇒ different public keys.
    assert!(!k1.pubkey_cmp(&k2));
}

#[test]
fn phase_02_ml_kem_generate_random_entropy_path() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(libctx, ml_kem::MlKemVariant::MlKem768, None)
        .expect("ML-KEM-768 random keygen should succeed");
    assert!(key.have_pubkey());
    assert!(key.have_prvkey());
    assert_eq!(key.pub_len(), 1184);
    assert_eq!(key.priv_len(), 2400);
    assert_eq!(key.ctext_len(), 1088);
    assert_eq!(key.shared_secret_len(), 32);
}

#[test]
fn phase_02_ml_kem_reset_clears_state() {
    let libctx = fixture_libctx();
    let mut key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    assert!(key.have_pubkey());
    assert!(key.have_prvkey());
    key.reset();
    assert!(!key.have_pubkey());
    assert!(!key.have_prvkey());
}

#[test]
fn phase_02_ml_kem_dup_yields_equivalent_key() {
    let libctx = fixture_libctx();
    let original = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem768,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let cloned = original.dup().expect("dup should succeed");
    assert!(original.pubkey_cmp(&cloned));
    assert_eq!(original.have_pubkey(), cloned.have_pubkey());
    assert_eq!(original.have_prvkey(), cloned.have_prvkey());
}

#[test]
fn phase_02_ml_kem_params_accessor_matches_variant() {
    let libctx = fixture_libctx();
    for variant in [
        ml_kem::MlKemVariant::MlKem512,
        ml_kem::MlKemVariant::MlKem768,
        ml_kem::MlKemVariant::MlKem1024,
    ] {
        let key = ml_kem::generate(Arc::clone(&libctx), variant, None).expect("keygen");
        assert_eq!(key.params().variant, variant);
    }
}

// ---------------------------------------------------------------------------
// Phase 3 — ML-KEM encap_rand → decap roundtrip
// ---------------------------------------------------------------------------

#[test]
fn phase_03_ml_kem_512_encap_decap_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (ctext, ss_e) = ml_kem::encap_rand(&key).expect("encap should succeed");
    let ss_d = ml_kem::decap(&key, &ctext).expect("decap should succeed");
    assert_eq!(ss_e, ss_d);
    assert_eq!(ctext.len(), 768);
    assert_eq!(ss_e.len(), 32);
}

#[test]
fn phase_03_ml_kem_768_encap_decap_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem768,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (ctext, ss_e) = ml_kem::encap_rand(&key).expect("encap");
    let ss_d = ml_kem::decap(&key, &ctext).expect("decap");
    assert_eq!(ss_e, ss_d);
    assert_eq!(ctext.len(), 1088);
}

#[test]
fn phase_03_ml_kem_1024_encap_decap_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem1024,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (ctext, ss_e) = ml_kem::encap_rand(&key).expect("encap");
    let ss_d = ml_kem::decap(&key, &ctext).expect("decap");
    assert_eq!(ss_e, ss_d);
    assert_eq!(ctext.len(), 1568);
}

#[test]
fn phase_03_ml_kem_independent_encaps_yield_independent_secrets() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (c1, s1) = ml_kem::encap_rand(&key).expect("encap-1");
    let (c2, s2) = ml_kem::encap_rand(&key).expect("encap-2");
    // Independent random encaps with overwhelming probability differ.
    assert_ne!(c1, c2);
    assert_ne!(s1, s2);
    // Each must decap to its own shared secret.
    assert_eq!(ml_kem::decap(&key, &c1).expect("decap-1"), s1);
    assert_eq!(ml_kem::decap(&key, &c2).expect("decap-2"), s2);
}

// ---------------------------------------------------------------------------
// Phase 4 — ML-KEM encap_seed determinism
// ---------------------------------------------------------------------------

#[test]
fn phase_04_ml_kem_encap_seed_is_deterministic() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (c1, s1) = ml_kem::encap_seed(&key, &ML_KEM_ENCAP_ENTROPY).expect("encap_seed-1");
    let (c2, s2) = ml_kem::encap_seed(&key, &ML_KEM_ENCAP_ENTROPY).expect("encap_seed-2");
    assert_eq!(c1, c2, "Same seed ⇒ same ciphertext");
    assert_eq!(s1, s2, "Same seed ⇒ same shared secret");
}

#[test]
fn phase_04_ml_kem_encap_seed_diverges_on_different_entropy() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem768,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (c1, s1) = ml_kem::encap_seed(&key, &ML_KEM_ENCAP_ENTROPY).expect("encap_seed-1");
    let (c2, s2) = ml_kem::encap_seed(&key, &ML_KEM_ENCAP_ENTROPY_ALT).expect("encap_seed-2");
    assert_ne!(c1, c2);
    assert_ne!(s1, s2);
}

#[test]
fn phase_04_ml_kem_encap_seed_decap_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem1024,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let (ctext, ss) = ml_kem::encap_seed(&key, &ML_KEM_ENCAP_ENTROPY).expect("encap_seed");
    let recovered = ml_kem::decap(&key, &ctext).expect("decap");
    assert_eq!(recovered, ss);
}

// ---------------------------------------------------------------------------
// Phase 5 — ML-KEM public/private key encode/parse roundtrip
// ---------------------------------------------------------------------------

#[test]
fn phase_05_ml_kem_pubkey_encode_decode_roundtrip() {
    let libctx = fixture_libctx();
    let original = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let encoded = original.encode_pubkey().expect("encode_pubkey");
    assert_eq!(encoded.len(), 800);

    let mut parsed = ml_kem::MlKemKey::new(libctx, ml_kem::MlKemVariant::MlKem512).expect("new");
    parsed.parse_pubkey(&encoded).expect("parse_pubkey");
    assert!(parsed.have_pubkey());
    assert!(!parsed.have_prvkey());
    assert!(original.pubkey_cmp(&parsed));
}

#[test]
fn phase_05_ml_kem_prvkey_encode_decode_roundtrip() {
    let libctx = fixture_libctx();
    let original = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem768,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let encoded = original.encode_prvkey().expect("encode_prvkey");
    // Length contract: encoded private key is exactly priv_len bytes.
    assert_eq!(encoded.len(), original.priv_len());

    let mut parsed = ml_kem::MlKemKey::new(libctx, ml_kem::MlKemVariant::MlKem768).expect("new");
    parsed.parse_prvkey(&encoded).expect("parse_prvkey");
    assert!(parsed.have_pubkey());
    assert!(parsed.have_prvkey());
    // The reconstructed key should encap_rand → decap correctly.
    let (ctext, ss_e) = ml_kem::encap_rand(&parsed).expect("encap on parsed key");
    let ss_d = ml_kem::decap(&parsed, &ctext).expect("decap on parsed key");
    assert_eq!(ss_e, ss_d);
}

#[test]
fn phase_05_ml_kem_pubkey_encode_length_per_variant() {
    let libctx = fixture_libctx();
    for (variant, expected_len) in [
        (ml_kem::MlKemVariant::MlKem512, 800usize),
        (ml_kem::MlKemVariant::MlKem768, 1184),
        (ml_kem::MlKemVariant::MlKem1024, 1568),
    ] {
        let key = ml_kem::generate(Arc::clone(&libctx), variant, Some(&ML_KEM_TEST_SEED))
            .expect("keygen");
        let encoded = key.encode_pubkey().expect("encode_pubkey");
        assert_eq!(encoded.len(), expected_len);
    }
}

// ---------------------------------------------------------------------------
// Phase 6 — ML-KEM provider flag semantics
// ---------------------------------------------------------------------------

#[test]
fn phase_06_ml_kem_provider_flags_default_value() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(libctx, ml_kem::MlKemVariant::MlKem512, None).expect("keygen");
    assert_eq!(key.provider_flags(), ml_kem::prov_flags::DEFAULT);
}

#[test]
fn phase_06_ml_kem_provider_flags_set_round_trip() {
    let libctx = fixture_libctx();
    let mut key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");

    key.set_provider_flags(ml_kem::prov_flags::FIXED_PCT);
    assert_eq!(key.provider_flags(), ml_kem::prov_flags::FIXED_PCT);

    key.set_provider_flags(ml_kem::prov_flags::RANDOM_PCT);
    assert_eq!(key.provider_flags(), ml_kem::prov_flags::RANDOM_PCT);
}

#[test]
fn phase_06_ml_kem_provider_flags_combined() {
    let libctx = fixture_libctx();
    let mut key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");

    let combined = ml_kem::prov_flags::PREFER_SEED | ml_kem::prov_flags::RETAIN_SEED;
    key.set_provider_flags(combined);
    assert_eq!(key.provider_flags(), combined);
}

// ---------------------------------------------------------------------------
// Phase 7 — ML-KEM error paths
// ---------------------------------------------------------------------------

#[test]
fn phase_07_ml_kem_decap_rejects_short_ciphertext() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let too_short = vec![0u8; 100];
    let res = ml_kem::decap(&key, &too_short);
    assert!(res.is_err(), "decap of short ctext must fail");
}

#[test]
fn phase_07_ml_kem_decap_rejects_long_ciphertext() {
    let libctx = fixture_libctx();
    let key = ml_kem::generate(
        libctx,
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    // ML-KEM-512 ctext is 768; pad to 1024 to overshoot.
    let too_long = vec![0u8; 1024];
    let res = ml_kem::decap(&key, &too_long);
    assert!(res.is_err(), "decap of long ctext must fail");
}

#[test]
fn phase_07_ml_kem_pubkey_only_cannot_decap() {
    let libctx = fixture_libctx();
    let original = ml_kem::generate(
        Arc::clone(&libctx),
        ml_kem::MlKemVariant::MlKem512,
        Some(&ML_KEM_TEST_SEED),
    )
    .expect("keygen");
    let pubenc = original.encode_pubkey().expect("encode_pubkey");

    let mut pubonly =
        ml_kem::MlKemKey::new(libctx, ml_kem::MlKemVariant::MlKem512).expect("new");
    pubonly.parse_pubkey(&pubenc).expect("parse_pubkey");
    assert!(pubonly.have_pubkey());
    assert!(!pubonly.have_prvkey());

    // encap_rand only requires the public key.
    let (ctext, _ss) = ml_kem::encap_rand(&pubonly).expect("encap on pubkey-only is allowed");

    // decap requires the private key — must fail.
    let res = ml_kem::decap(&pubonly, &ctext);
    assert!(res.is_err(), "decap on pubkey-only key must fail");
}

#[test]
fn phase_07_ml_kem_parse_pubkey_rejects_bad_length() {
    let libctx = fixture_libctx();
    let mut key = ml_kem::MlKemKey::new(libctx, ml_kem::MlKemVariant::MlKem512).expect("new");
    let truncated = vec![0u8; 100];
    let res = key.parse_pubkey(&truncated);
    assert!(res.is_err(), "parse_pubkey of truncated input must fail");
}

#[test]
fn phase_07_ml_kem_parse_prvkey_rejects_bad_length() {
    let libctx = fixture_libctx();
    let mut key = ml_kem::MlKemKey::new(libctx, ml_kem::MlKemVariant::MlKem768).expect("new");
    let truncated = vec![0u8; 100];
    let res = key.parse_prvkey(&truncated);
    assert!(res.is_err(), "parse_prvkey of truncated input must fail");
}

// ---------------------------------------------------------------------------
// Phase 8 — ML-DSA variant metadata + length constants
// ---------------------------------------------------------------------------

#[test]
fn phase_08_ml_dsa_algorithm_names() {
    assert_eq!(ml_dsa::MlDsaVariant::MlDsa44.algorithm_name(), "ML-DSA-44");
    assert_eq!(ml_dsa::MlDsaVariant::MlDsa65.algorithm_name(), "ML-DSA-65");
    assert_eq!(ml_dsa::MlDsaVariant::MlDsa87.algorithm_name(), "ML-DSA-87");
}

#[test]
fn phase_08_ml_dsa_security_categories() {
    // FIPS 204 Table 1 maps ML-DSA-44 → category 2 (NOT 1).
    assert_eq!(ml_dsa::MlDsaVariant::MlDsa44.security_category(), 2);
    assert_eq!(ml_dsa::MlDsaVariant::MlDsa65.security_category(), 3);
    assert_eq!(ml_dsa::MlDsaVariant::MlDsa87.security_category(), 5);
}

#[test]
fn phase_08_ml_dsa_44_length_constants() {
    assert_eq!(ml_dsa::ML_DSA_44_PRIV_LEN, 2560);
    assert_eq!(ml_dsa::ML_DSA_44_PUB_LEN, 1312);
    assert_eq!(ml_dsa::ML_DSA_44_SIG_LEN, 2420);
}

#[test]
fn phase_08_ml_dsa_65_length_constants() {
    assert_eq!(ml_dsa::ML_DSA_65_PRIV_LEN, 4032);
    assert_eq!(ml_dsa::ML_DSA_65_PUB_LEN, 1952);
    assert_eq!(ml_dsa::ML_DSA_65_SIG_LEN, 3309);
}

#[test]
fn phase_08_ml_dsa_87_length_constants() {
    assert_eq!(ml_dsa::ML_DSA_87_PRIV_LEN, 4896);
    assert_eq!(ml_dsa::ML_DSA_87_PUB_LEN, 2592);
    assert_eq!(ml_dsa::ML_DSA_87_SIG_LEN, 4627);
}

#[test]
fn phase_08_ml_dsa_static_param_tables_match_constants() {
    assert_eq!(ml_dsa::ML_DSA_44_PARAMS.sk_len, 2560);
    assert_eq!(ml_dsa::ML_DSA_44_PARAMS.pk_len, 1312);
    assert_eq!(ml_dsa::ML_DSA_44_PARAMS.sig_len, 2420);
    assert_eq!(ml_dsa::ML_DSA_44_PARAMS.security_category, 2);

    assert_eq!(ml_dsa::ML_DSA_65_PARAMS.sk_len, 4032);
    assert_eq!(ml_dsa::ML_DSA_65_PARAMS.pk_len, 1952);
    assert_eq!(ml_dsa::ML_DSA_65_PARAMS.sig_len, 3309);
    assert_eq!(ml_dsa::ML_DSA_65_PARAMS.security_category, 3);

    assert_eq!(ml_dsa::ML_DSA_87_PARAMS.sk_len, 4896);
    assert_eq!(ml_dsa::ML_DSA_87_PARAMS.pk_len, 2592);
    assert_eq!(ml_dsa::ML_DSA_87_PARAMS.sig_len, 4627);
    assert_eq!(ml_dsa::ML_DSA_87_PARAMS.security_category, 5);
}

#[test]
fn phase_08_ml_dsa_params_get_by_variant() {
    let p44 = ml_dsa::ml_dsa_params_get(ml_dsa::MlDsaVariant::MlDsa44);
    assert_eq!(p44.variant, ml_dsa::MlDsaVariant::MlDsa44);

    let p65 = ml_dsa::ml_dsa_params_get(ml_dsa::MlDsaVariant::MlDsa65);
    assert_eq!(p65.variant, ml_dsa::MlDsaVariant::MlDsa65);

    let p87 = ml_dsa::ml_dsa_params_get(ml_dsa::MlDsaVariant::MlDsa87);
    assert_eq!(p87.variant, ml_dsa::MlDsaVariant::MlDsa87);
}

#[test]
fn phase_08_ml_dsa_params_get_by_name_canonical() {
    assert!(ml_dsa::ml_dsa_params_get_by_name("ML-DSA-44").is_some());
    assert!(ml_dsa::ml_dsa_params_get_by_name("ML-DSA-65").is_some());
    assert!(ml_dsa::ml_dsa_params_get_by_name("ML-DSA-87").is_some());
}

#[test]
fn phase_08_ml_dsa_params_get_by_name_unknown() {
    assert!(ml_dsa::ml_dsa_params_get_by_name("ML-DSA-44a").is_none());
    assert!(ml_dsa::ml_dsa_params_get_by_name("Dilithium2").is_none());
    assert!(ml_dsa::ml_dsa_params_get_by_name("").is_none());
}

#[test]
fn phase_08_ml_dsa_constants_match_spec() {
    // FIPS 204 §2.4.1 sets q = 8 380 417 = 2^23 - 2^13 + 1.
    assert_eq!(ml_dsa::ML_DSA_Q, 8_380_417);
    assert_eq!(ml_dsa::NUM_POLY_COEFFICIENTS, 256);
    assert_eq!(ml_dsa::SEED_BYTES, 32);
    assert_eq!(ml_dsa::MU_BYTES, 64);
    assert_eq!(ml_dsa::MAX_CONTEXT_STRING_LEN, 255);
}

// ---------------------------------------------------------------------------
// Phase 9 — ML-DSA sign → verify roundtrip
// ---------------------------------------------------------------------------

#[test]
fn phase_09_ml_dsa_44_sign_verify_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"FIPS 204 ML-DSA-44 roundtrip test";
    let context = b"";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, context, true, Some(&ML_DSA_ZERO_RAND))
        .expect("sign should succeed");
    assert_eq!(sig.len(), ml_dsa::ML_DSA_44_SIG_LEN);

    let ok = ml_dsa::ml_dsa_verify(&key, msg, context, true, &sig).expect("verify must not error");
    assert!(ok, "Genuine signature must verify");
}

#[test]
fn phase_09_ml_dsa_65_sign_verify_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa65, None).expect("keygen");

    let msg = b"ML-DSA-65 message";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND))
        .expect("sign");
    assert_eq!(sig.len(), ml_dsa::ML_DSA_65_SIG_LEN);

    let ok = ml_dsa::ml_dsa_verify(&key, msg, b"", true, &sig).expect("verify");
    assert!(ok);
}

#[test]
fn phase_09_ml_dsa_87_sign_verify_roundtrip() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa87, None).expect("keygen");

    let msg = b"ML-DSA-87 message";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND))
        .expect("sign");
    assert_eq!(sig.len(), ml_dsa::ML_DSA_87_SIG_LEN);

    let ok = ml_dsa::ml_dsa_verify(&key, msg, b"", true, &sig).expect("verify");
    assert!(ok);
}

#[test]
fn phase_09_ml_dsa_deterministic_signing_with_zero_random() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"deterministic-signing-test";
    let sig1 =
        ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND)).expect("sign-1");
    let sig2 =
        ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND)).expect("sign-2");
    // With fixed zero randomiser, signatures must be deterministic.
    assert_eq!(sig1, sig2, "Same key + msg + zero-rand ⇒ same signature");
}

#[test]
fn phase_09_ml_dsa_sign_with_context() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"context-test";
    let context: &[u8] = b"app-id-v1";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, context, true, Some(&ML_DSA_ZERO_RAND))
        .expect("sign");
    let ok = ml_dsa::ml_dsa_verify(&key, msg, context, true, &sig).expect("verify");
    assert!(ok);
}

// ---------------------------------------------------------------------------
// Phase 10 — ML-DSA tamper detection
// ---------------------------------------------------------------------------

#[test]
fn phase_10_ml_dsa_rejects_flipped_signature() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"tamper test";
    let mut sig = ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND))
        .expect("sign");
    // Flip a single bit in the middle of the signature.
    let target_idx = sig.len() / 2;
    sig[target_idx] ^= 0x01;

    let ok = ml_dsa::ml_dsa_verify(&key, msg, b"", true, &sig).expect("verify must not error");
    assert!(!ok, "Tampered signature must NOT verify");
}

#[test]
fn phase_10_ml_dsa_rejects_modified_message() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"original message";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND)).expect("sign");

    let modified = b"modified message";
    let ok = ml_dsa::ml_dsa_verify(&key, modified, b"", true, &sig).expect("verify");
    assert!(!ok, "Signature over different message must NOT verify");
}

#[test]
fn phase_10_ml_dsa_rejects_modified_context() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"context separation test";
    let ctx_a: &[u8] = b"context-A";
    let ctx_b: &[u8] = b"context-B";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, ctx_a, true, Some(&ML_DSA_ZERO_RAND)).expect("sign");
    let ok = ml_dsa::ml_dsa_verify(&key, msg, ctx_b, true, &sig).expect("verify");
    assert!(!ok, "Cross-context verification must NOT succeed");
}

#[test]
fn phase_10_ml_dsa_rejects_truncated_signature() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");

    let msg = b"truncation test";
    let sig = ml_dsa::ml_dsa_sign(&key, msg, b"", true, Some(&ML_DSA_ZERO_RAND)).expect("sign");
    let truncated = &sig[..sig.len() - 1];

    let res = ml_dsa::ml_dsa_verify(&key, msg, b"", true, truncated);
    // Either an error or a false verdict is acceptable — must NOT return true.
    match res {
        Ok(b) => assert!(!b, "Truncated signature must not verify"),
        Err(_) => { /* explicit length-rejection path is also correct */ }
    }
}

#[test]
fn phase_10_ml_dsa_cross_key_signature_does_not_verify() {
    let libctx = fixture_libctx();
    let key1 = ml_dsa::MlDsaKey::generate(Arc::clone(&libctx), ml_dsa::MlDsaVariant::MlDsa44, None)
        .expect("keygen-1");
    let key2 = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None)
        .expect("keygen-2");

    let msg = b"cross-key test";
    let sig = ml_dsa::ml_dsa_sign(&key1, msg, b"", true, Some(&ML_DSA_ZERO_RAND)).expect("sign");
    let ok = ml_dsa::ml_dsa_verify(&key2, msg, b"", true, &sig).expect("verify");
    assert!(!ok, "Signature under key1 must not verify under key2");
}

// ---------------------------------------------------------------------------
// Phase 11 — ML-DSA KeySelection semantics
// ---------------------------------------------------------------------------

#[test]
fn phase_11_ml_dsa_key_selection_includes_helpers() {
    use ml_dsa::KeySelection;
    // Public selection contains public, not private.
    assert!(KeySelection::Public.includes_public());
    assert!(!KeySelection::Public.includes_private());
    // Private selection contains private.
    assert!(KeySelection::Private.includes_private());
    // Both contains everything.
    assert!(KeySelection::Both.includes_public());
    assert!(KeySelection::Both.includes_private());
}

#[test]
fn phase_11_ml_dsa_has_key_after_generate() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");
    assert!(key.has_key(ml_dsa::KeySelection::Public));
    assert!(key.has_key(ml_dsa::KeySelection::Private));
    assert!(key.has_key(ml_dsa::KeySelection::Both));
}

#[test]
fn phase_11_ml_dsa_dup_clones_key_state() {
    let libctx = fixture_libctx();
    let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");
    let cloned = key.dup(ml_dsa::KeySelection::Both).expect("dup");
    assert!(cloned.has_key(ml_dsa::KeySelection::Public));
    assert!(cloned.has_key(ml_dsa::KeySelection::Private));
    assert!(key.equal(&cloned, ml_dsa::KeySelection::Public));
}

#[test]
fn phase_11_ml_dsa_reset_clears_key() {
    let libctx = fixture_libctx();
    let mut key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None).expect("keygen");
    assert!(key.has_key(ml_dsa::KeySelection::Both));
    key.reset();
    assert!(!key.has_key(ml_dsa::KeySelection::Public));
    assert!(!key.has_key(ml_dsa::KeySelection::Private));
}

// ---------------------------------------------------------------------------
// Phase 12 — SLH-DSA variant metadata + algorithm name dispatch
// ---------------------------------------------------------------------------

#[test]
fn phase_12_slh_dsa_variant_algorithm_names() {
    use slh_dsa::SlhDsaVariant;
    assert_eq!(SlhDsaVariant::Sha2_128s.algorithm_name(), "SLH-DSA-SHA2-128s");
    assert_eq!(SlhDsaVariant::Sha2_128f.algorithm_name(), "SLH-DSA-SHA2-128f");
    assert_eq!(SlhDsaVariant::Shake_128s.algorithm_name(), "SLH-DSA-SHAKE-128s");
    assert_eq!(SlhDsaVariant::Shake_128f.algorithm_name(), "SLH-DSA-SHAKE-128f");
    assert_eq!(SlhDsaVariant::Sha2_192s.algorithm_name(), "SLH-DSA-SHA2-192s");
    assert_eq!(SlhDsaVariant::Sha2_192f.algorithm_name(), "SLH-DSA-SHA2-192f");
    assert_eq!(SlhDsaVariant::Shake_192s.algorithm_name(), "SLH-DSA-SHAKE-192s");
    assert_eq!(SlhDsaVariant::Shake_192f.algorithm_name(), "SLH-DSA-SHAKE-192f");
    assert_eq!(SlhDsaVariant::Sha2_256s.algorithm_name(), "SLH-DSA-SHA2-256s");
    assert_eq!(SlhDsaVariant::Sha2_256f.algorithm_name(), "SLH-DSA-SHA2-256f");
    assert_eq!(SlhDsaVariant::Shake_256s.algorithm_name(), "SLH-DSA-SHAKE-256s");
    assert_eq!(SlhDsaVariant::Shake_256f.algorithm_name(), "SLH-DSA-SHAKE-256f");
}

#[test]
fn phase_12_slh_dsa_try_from_canonical_names() {
    use std::convert::TryFrom;
    assert!(slh_dsa::SlhDsaVariant::try_from("SLH-DSA-SHA2-128s").is_ok());
    assert!(slh_dsa::SlhDsaVariant::try_from("SLH-DSA-SHAKE-128f").is_ok());
    assert!(slh_dsa::SlhDsaVariant::try_from("SLH-DSA-SHA2-256f").is_ok());
}

#[test]
fn phase_12_slh_dsa_try_from_unknown_returns_algorithm_not_found() {
    use std::convert::TryFrom;
    let res = slh_dsa::SlhDsaVariant::try_from("SLH-DSA-DUMMY-128s");
    match res {
        Err(CryptoError::AlgorithmNotFound(name)) => {
            assert_eq!(name, "SLH-DSA-DUMMY-128s");
        }
        Ok(v) => panic!("Unknown variant must not parse — got {:?}", v),
        Err(other) => panic!("Expected AlgorithmNotFound, got {:?}", other),
    }
}

#[test]
fn phase_12_slh_dsa_try_from_empty_string() {
    use std::convert::TryFrom;
    let res = slh_dsa::SlhDsaVariant::try_from("");
    assert!(res.is_err(), "Empty string must not be a valid SLH-DSA variant");
}

#[test]
fn phase_12_slh_dsa_params_get_by_canonical_name() {
    assert!(slh_dsa::slh_dsa_params_get("SLH-DSA-SHAKE-128f").is_some());
    assert!(slh_dsa::slh_dsa_params_get("SLH-DSA-SHA2-128f").is_some());
    assert!(slh_dsa::slh_dsa_params_get("SLH-DSA-SHA2-256f").is_some());
}

#[test]
fn phase_12_slh_dsa_params_get_unknown_returns_none() {
    assert!(slh_dsa::slh_dsa_params_get("Dummy-Algo").is_none());
    assert!(slh_dsa::slh_dsa_params_get("").is_none());
}

#[test]
fn phase_12_slh_dsa_constants_match_spec() {
    assert_eq!(slh_dsa::SLH_DSA_MAX_N, 32);
    assert_eq!(slh_dsa::SLH_DSA_MAX_CONTEXT_STRING_LEN, 255);
}

// ---------------------------------------------------------------------------
// Phase 13 — SLH-DSA keygen + sign + verify roundtrip
// (Subset: SHAKE-128f / SHA2-128f only — fastest variants. The "s" small
// variants and the 192/256-bit security variants take seconds-to-tens-of-
// seconds per signature and would inflate test wall-clock unacceptably.)
// ---------------------------------------------------------------------------

#[test]
fn phase_13_slh_dsa_shake_128f_sign_verify_roundtrip() {
    let libctx = fixture_libctx();
    let key = slh_dsa::SlhDsaKey::generate(libctx, "SLH-DSA-SHAKE-128f").expect("keygen");
    assert_eq!(key.algorithm_name(), "SLH-DSA-SHAKE-128f");

    let key_arc = Arc::new(key);
    let hctx = slh_dsa::SlhDsaHashCtx::new(Arc::clone(&key_arc)).expect("hash ctx");

    let msg = b"SLH-DSA-SHAKE-128f roundtrip test";
    let ctx: &[u8] = b"";
    let sig = slh_dsa::slh_dsa_sign(&hctx, msg, ctx, None, true).expect("sign");
    assert_eq!(sig.len(), key_arc.sig_len().expect("sig_len"));

    let ok = slh_dsa::slh_dsa_verify(&hctx, msg, ctx, true, &sig).expect("verify");
    assert!(ok, "Genuine SLH-DSA-SHAKE-128f signature must verify");
}

#[test]
fn phase_13_slh_dsa_sha2_128f_sign_verify_roundtrip() {
    let libctx = fixture_libctx();
    let key = slh_dsa::SlhDsaKey::generate(libctx, "SLH-DSA-SHA2-128f").expect("keygen");
    assert_eq!(key.algorithm_name(), "SLH-DSA-SHA2-128f");

    let key_arc = Arc::new(key);
    let hctx = slh_dsa::SlhDsaHashCtx::new(Arc::clone(&key_arc)).expect("hash ctx");

    let msg = b"SLH-DSA-SHA2-128f roundtrip test";
    let sig = slh_dsa::slh_dsa_sign(&hctx, msg, b"", None, true).expect("sign");
    let ok = slh_dsa::slh_dsa_verify(&hctx, msg, b"", true, &sig).expect("verify");
    assert!(ok);
}

#[test]
fn phase_13_slh_dsa_rejects_flipped_signature() {
    let libctx = fixture_libctx();
    let key = slh_dsa::SlhDsaKey::generate(libctx, "SLH-DSA-SHAKE-128f").expect("keygen");
    let key_arc = Arc::new(key);
    let hctx = slh_dsa::SlhDsaHashCtx::new(Arc::clone(&key_arc)).expect("hash ctx");

    let msg = b"tamper-test";
    let mut sig = slh_dsa::slh_dsa_sign(&hctx, msg, b"", None, true).expect("sign");
    sig[100] ^= 0x01;

    let ok = slh_dsa::slh_dsa_verify(&hctx, msg, b"", true, &sig).expect("verify");
    assert!(!ok, "Tampered SLH-DSA signature must NOT verify");
}

#[test]
fn phase_13_slh_dsa_rejects_message_modification() {
    let libctx = fixture_libctx();
    let key = slh_dsa::SlhDsaKey::generate(libctx, "SLH-DSA-SHAKE-128f").expect("keygen");
    let key_arc = Arc::new(key);
    let hctx = slh_dsa::SlhDsaHashCtx::new(Arc::clone(&key_arc)).expect("hash ctx");

    let msg = b"original";
    let modified = b"modified";
    let sig = slh_dsa::slh_dsa_sign(&hctx, msg, b"", None, true).expect("sign");
    let ok = slh_dsa::slh_dsa_verify(&hctx, modified, b"", true, &sig).expect("verify");
    assert!(!ok, "SLH-DSA signature over modified message must not verify");
}

#[test]
fn phase_13_slh_dsa_pairwise_check_succeeds_after_keygen() {
    let libctx = fixture_libctx();
    let key = slh_dsa::SlhDsaKey::generate(libctx, "SLH-DSA-SHAKE-128f").expect("keygen");
    let pwc = key.pairwise_check().expect("pairwise check must not error");
    assert!(pwc, "Freshly-generated SLH-DSA key must pass pairwise check");
}

#[test]
fn phase_13_slh_dsa_key_lengths_match_spec_128f() {
    let libctx = fixture_libctx();
    let key = slh_dsa::SlhDsaKey::generate(libctx, "SLH-DSA-SHAKE-128f").expect("keygen");
    // FIPS 205 Table 1: 128f has n=16 ⇒ pk = 32 bytes, sk = 64 bytes.
    assert_eq!(key.pub_len().expect("pub_len"), 32);
    assert_eq!(key.priv_len().expect("priv_len"), 64);
    assert_eq!(key.security_category().expect("security_category"), 1);
}

// ---------------------------------------------------------------------------
// Phase 14 — LMS structural tests
// ---------------------------------------------------------------------------

#[test]
fn phase_14_lms_type_from_u32_known_values_roundtrip() {
    use lms::LmsType;
    // RFC 8554 §3.2 allocates 0x05 .. 0x09 for SHA-256/N=32 with H = 5/10/15/20/25.
    let known: [u32; 5] = [0x05, 0x06, 0x07, 0x08, 0x09];
    for v in known {
        let parsed = LmsType::from_u32(v);
        assert!(parsed.is_some(), "LmsType::from_u32(0x{:02X}) must parse", v);
        let p = parsed.unwrap();
        let params = p.params();
        // n = 32 for SHA-256/N=32 family.
        assert_eq!(params.n, 32, "SHA-256/N=32 family must have n=32");
    }
}

#[test]
fn phase_14_lms_type_from_u32_invalid_returns_none() {
    use lms::LmsType;
    // 0x00, 0x01..=0x04, and values beyond the registered ranges must return None.
    assert!(LmsType::from_u32(0x00).is_none());
    assert!(LmsType::from_u32(0x01).is_none());
    assert!(LmsType::from_u32(0xFFFF_FFFF).is_none());
    assert!(LmsType::from_u32(0x7FFF_FFFF).is_none());
}

#[test]
fn phase_14_lms_ots_type_from_u32_known_values_roundtrip() {
    use lms::LmOtsType;
    // RFC 8554 §4.1 allocates 0x01 .. 0x04 for SHA-256/N=32 with W = 1/2/4/8.
    let known: [u32; 4] = [0x01, 0x02, 0x03, 0x04];
    for v in known {
        let parsed = LmOtsType::from_u32(v);
        assert!(
            parsed.is_some(),
            "LmOtsType::from_u32(0x{:02X}) must parse",
            v
        );
        let p = parsed.unwrap();
        let params = p.params();
        assert_eq!(params.n, 32, "SHA-256/N=32 OTS family must have n=32");
    }
}

#[test]
fn phase_14_lms_ots_type_from_u32_invalid_returns_none() {
    use lms::LmOtsType;
    assert!(LmOtsType::from_u32(0x0000).is_none());
    assert!(LmOtsType::from_u32(0xDEAD_BEEF).is_none());
}

#[test]
fn phase_14_lms_pubkey_encoded_len_for_sha256_n32_h5() {
    use lms::{LmsPubKey, LmsType};
    let lms_type = LmsType::from_u32(0x05).expect("SHA-256/N=32/H=5 must exist");
    let params = lms_type.params();
    let len = LmsPubKey::encoded_len(params);
    // Layout: 4 (LMS type) + 4 (OTS type) + 16 (I) + n bytes (K).
    // For SHA-256/N=32: 4 + 4 + 16 + 32 = 56.
    assert_eq!(len, 56);
}

#[test]
fn phase_14_lms_pubkey_decode_rejects_under_length_input() {
    use lms::LmsPubKey;
    // 0 bytes — clearly insufficient.
    let res = LmsPubKey::decode(&[]).expect("decode must not error on under-length input");
    assert!(res.is_none());

    // 47 bytes — one less than the minimum 48-byte LMS public-key prefix.
    let small = [0u8; 47];
    let res = LmsPubKey::decode(&small).expect("decode must not error on short input");
    assert!(res.is_none());
}

#[test]
fn phase_14_lms_pubkey_decode_rejects_unknown_lms_type() {
    use lms::LmsPubKey;
    // 60 bytes is enough length, but the LMS type field (first 4 bytes big-endian)
    // is 0x00000000, which is not a registered LMS type.
    let mut buf = [0u8; 60];
    // LMS type = 0 (invalid), OTS type = 0 (invalid), I = 0..16, K = 16..48
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    let res = LmsPubKey::decode(&buf).expect("decode must not error on unknown type");
    assert!(res.is_none(), "Unknown LMS type ⇒ Ok(None)");
}

#[test]
fn phase_14_lms_top_level_verify_returns_ok_false_on_short_input() {
    // Convenience wrapper `lms::verify` returns Ok(false) when the encoded
    // public key is too short to decode (decode returns Ok(None)).
    let short_pubkey = [0u8; 47];
    let msg = b"any message";
    let sig = [0u8; 100];
    let result = lms::verify(&short_pubkey, msg, &sig).expect("top-level verify must not error");
    assert!(!result, "verify(short_pubkey, ...) must return false");
}

#[test]
fn phase_14_lms_pubkey_decode_succeeds_on_well_formed_prefix() {
    use lms::LmsPubKey;
    // Build a minimal well-formed LMS public key:
    //   LMS type    = 0x00000005 (Sha256N32H5)
    //   OTS type    = 0x00000004 (Sha256N32W8)
    //   I           = [0xAA; 16]
    //   K           = [0xBB; 32]
    // Total: 4 + 4 + 16 + 32 = 56 bytes.
    let mut buf = [0u8; 56];
    buf[0..4].copy_from_slice(&5u32.to_be_bytes());
    buf[4..8].copy_from_slice(&4u32.to_be_bytes());
    buf[8..24].fill(0xAA);
    buf[24..56].fill(0xBB);
    let decoded = LmsPubKey::decode(&buf).expect("decode must not error");
    assert!(
        decoded.is_some(),
        "Well-formed 56-byte SHA-256/N=32/H=5 + W=8 prefix must decode"
    );
    let pk = decoded.unwrap();
    assert_eq!(pk.lms_params().n, 32);
    assert_eq!(pk.k().len(), 32);
    assert_eq!(pk.i(), &[0xAA; 16]);
}

// ---------------------------------------------------------------------------
// Phase 15 — Cross-cutting proptest property tests
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    // Property: For ML-KEM-512, encap_seed(key, e) -> decap(key, ctext)
    // must always recover the same shared secret, for any 32-byte entropy.
    // Limited to 6 cases to bound test wall-clock.
    #[test]
    fn phase_15_ml_kem_encap_seed_decap_recovers_shared_secret(
        entropy in proptest::array::uniform32(any::<u8>())
    ) {
        let libctx = fixture_libctx();
        let key = ml_kem::generate(
            libctx,
            ml_kem::MlKemVariant::MlKem512,
            Some(&ML_KEM_TEST_SEED),
        )
        .expect("keygen");
        let (ctext, ss_e) = ml_kem::encap_seed(&key, &entropy).expect("encap_seed");
        let ss_d = ml_kem::decap(&key, &ctext).expect("decap");
        prop_assert_eq!(ss_e, ss_d);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    // Property: For ML-DSA-44 with a fixed key, sign-then-verify must
    // always succeed for any non-empty message of bounded length.
    #[test]
    fn phase_15_ml_dsa_sign_verify_arbitrary_message(
        msg in proptest::collection::vec(any::<u8>(), 1..256)
    ) {
        let libctx = fixture_libctx();
        let key = ml_dsa::MlDsaKey::generate(libctx, ml_dsa::MlDsaVariant::MlDsa44, None)
            .expect("keygen");
        let sig = ml_dsa::ml_dsa_sign(&key, &msg, b"", true, Some(&ML_DSA_ZERO_RAND))
            .expect("sign");
        let ok = ml_dsa::ml_dsa_verify(&key, &msg, b"", true, &sig).expect("verify");
        prop_assert!(ok);
    }
}
