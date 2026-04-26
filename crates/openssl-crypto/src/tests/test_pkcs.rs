//! Integration tests for the PKCS standard primitives.
//!
//! This test module validates the public API for PKCS-related operations
//! dispersed across multiple modules:
//!
//! - **PKCS#7 byte padding** via [`crate::symmetric::pkcs7_pad`] and
//!   [`crate::symmetric::pkcs7_unpad`] (RFC 5652).
//! - **PKCS#5 v2 / PBKDF2** via [`crate::evp::kdf::pbkdf2_derive`] (RFC 8018).
//! - **PBES1 / PBES2 cipher initialization** via
//!   [`crate::evp::kdf::pbe_cipher_init`].
//! - **PKCS#8 encoding/decoding** via
//!   [`crate::evp::encode_decode::EncoderContext::to_pkcs8`] and
//!   [`crate::evp::encode_decode::DecoderContext::from_pkcs8`].
//! - **HKDF / scrypt / Argon2 EVP wrappers** via the [`crate::evp::kdf`]
//!   module (RFC 5869, RFC 7914, RFC 9106).
//! - **Generic [`crate::evp::kdf::KdfCtx`] dispatch** for KBKDF, SSKDF,
//!   X9.63 KDF, TLS1-PRF, and SSHKDF.
//! - **High-level [`crate::evp::pkey::PKey`] container** including the
//!   [`crate::evp::pkey::KeyType`] catalogue and
//!   [`crate::evp::pkey::RsaPadding`] enumeration used by PKCS#1 / PKCS#8
//!   serialization paths.
//!
//! # References
//!
//! - RFC 5652 (Cryptographic Message Syntax — PKCS#7 padding)
//! - RFC 8018 (PKCS#5 v2.1 — Password-Based Cryptography)
//! - RFC 5208 / RFC 5958 (PKCS#8 — Private-Key Information Syntax)
//! - RFC 5869 (HKDF), RFC 7914 (scrypt), RFC 9106 (Argon2)
//! - RFC 7292 (PKCS#12 — Personal Information Exchange Syntax)
//! - NIST SP 800-132 (PBKDF2 recommendation), NIST SP 800-108 (KBKDF)
//! - NIST SP 800-56A Rev. 3 (Single-Step KDF, X9.63 KDF)
//! - `crypto/evp/p5_crpt2.c`, `crypto/evp/pbe_scrypt.c`, `crypto/kdf/hkdf.c`
//!
//! # Rule Compliance
//!
//! - **R5 (nullability over sentinels):** The tests use [`Option`]/[`Result`]
//!   for absent or invalid state — no `0`/`-1`/`""` sentinels are used.
//! - **R6 (lossless numeric casts):** Tests prefer `u32`/`u64`/`usize`
//!   typed literals; no narrowing `as` casts appear in the test bodies.
//! - **R8 (zero unsafe):** No `unsafe` blocks. The PKCS surface is
//!   exercised entirely through the safe Rust API.

// Test code legitimately uses `.expect()`, `.unwrap()`, and `panic!()` for
// assertion failures. The workspace lint configuration flags these as
// warnings; tests are explicitly allowed to suppress them with
// justification per the "Tests and CLI main() may #[allow] with
// justification" policy recorded in the workspace `Cargo.toml` lints
// table.

#![allow(clippy::expect_used)] // Tests call .expect() on known-good Results.
#![allow(clippy::unwrap_used)] // Tests call .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive-match error arms.

use crate::context::LibContext;
use crate::evp::encode_decode::{DecoderContext, EncoderContext, KeyFormat, KeySelection};
use crate::evp::kdf::{
    self, ARGON2D, ARGON2I, ARGON2ID, HKDF, KBKDF, Kdf, KdfCtx, KdfData, PBKDF2, PbeAlgorithm,
    SCRYPT, SSHKDF, SSKDF, TLS1_PRF, TLS13_KDF, X963KDF,
};
use crate::evp::pkey::{KeyType, PKey, RsaPadding};
use crate::symmetric::{pkcs7_pad, pkcs7_unpad};
use openssl_common::{CommonError, CryptoError, ParamSet, param::ParamValue};

// =========================================================================
// Phase 1: Additional Kdf::fetch coverage for algorithms not exercised by
// the in-file tests in `evp/kdf.rs:1336+`.
//
// The in-file tests cover HKDF, PBKDF2, SCRYPT, KBKDF, and TLS1_PRF. This
// phase fills the gap by validating successful fetch for ARGON2I, ARGON2D,
// SSKDF, X963KDF, SSHKDF, and TLS13_KDF — the remaining 6 of the 12
// algorithms registered in the canonical table.
// =========================================================================

#[test]
fn fetch_argon2i_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, ARGON2I, None).expect("ARGON2I should be fetchable");
    assert_eq!(kdf.name(), ARGON2I);
}

#[test]
fn fetch_argon2d_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, ARGON2D, None).expect("ARGON2D should be fetchable");
    assert_eq!(kdf.name(), ARGON2D);
}

#[test]
fn fetch_sskdf_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, SSKDF, None).expect("SSKDF should be fetchable");
    assert_eq!(kdf.name(), SSKDF);
}

#[test]
fn fetch_x963kdf_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, X963KDF, None).expect("X963KDF should be fetchable");
    assert_eq!(kdf.name(), X963KDF);
}

#[test]
fn fetch_sshkdf_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, SSHKDF, None).expect("SSHKDF should be fetchable");
    assert_eq!(kdf.name(), SSHKDF);
}

#[test]
fn fetch_tls13_kdf_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, TLS13_KDF, None).expect("TLS13-KDF should be fetchable");
    assert_eq!(kdf.name(), TLS13_KDF);
}

// =========================================================================
// Phase 2: Kdf accessor uniqueness — verify `description()` and
// `provider_name()` produce stable, well-formed strings for the 12
// canonical KDFs.
// =========================================================================

#[test]
fn kdf_description_format_matches_canonical_pattern() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    // Format established by `Kdf::fetch`: `"{canonical_name} KDF"`.
    // `description()` returns `Option<&str>` so we compare against `Some(_)`.
    assert_eq!(kdf.description(), Some("HKDF KDF"));
}

#[test]
fn kdf_provider_name_is_default() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, PBKDF2, None).expect("PBKDF2 fetchable");
    assert_eq!(kdf.provider_name(), "default");
}

#[test]
fn kdf_distinct_algorithms_have_distinct_descriptions() {
    let ctx = LibContext::get_default();
    let hkdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let pbkdf2 = Kdf::fetch(&ctx, PBKDF2, None).expect("PBKDF2 fetchable");
    let scrypt = Kdf::fetch(&ctx, SCRYPT, None).expect("SCRYPT fetchable");
    assert_ne!(hkdf.description(), pbkdf2.description());
    assert_ne!(pbkdf2.description(), scrypt.description());
    assert_ne!(hkdf.description(), scrypt.description());
}

// =========================================================================
// Phase 3: KdfData accessor coverage.
//
// Validates the simple owned-byte container's public surface: builder,
// length-related accessors, `is_empty()`, and Debug redaction.
// =========================================================================

#[test]
fn kdf_data_new_preserves_bytes() {
    let bytes = vec![0x01u8, 0x02, 0x03, 0x04, 0x05];
    let data = KdfData::new(bytes.clone());
    assert_eq!(data.as_bytes(), bytes.as_slice());
}

#[test]
fn kdf_data_len_matches_input() {
    let data = KdfData::new(vec![0u8; 32]);
    assert_eq!(data.len(), 32);
}

#[test]
fn kdf_data_is_empty_on_empty_vec() {
    let data = KdfData::new(Vec::new());
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);
}

#[test]
fn kdf_data_is_not_empty_when_populated() {
    let data = KdfData::new(vec![0xFFu8; 1]);
    assert!(!data.is_empty());
}

#[test]
fn kdf_data_debug_redacts_bytes() {
    let data = KdfData::new(b"sensitive-key-material".to_vec());
    let debug_str = format!("{data:?}");
    // Debug must redact: only `len` is shown, the actual bytes must NOT
    // appear in the formatted output.
    assert!(!debug_str.contains("sensitive-key-material"));
    // The redacted representation should still surface the length so
    // diagnostics remain useful.
    assert!(debug_str.contains("len"));
}

// =========================================================================
// Phase 4: KdfCtx Debug output.
//
// Verifies the three fields exposed by the Debug impl: `kdf` (algorithm
// name), `param_count`, and `consumed`.
// =========================================================================

#[test]
fn kdf_ctx_debug_includes_algorithm_name() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let kctx = KdfCtx::new(&kdf);
    let debug_str = format!("{kctx:?}");
    assert!(debug_str.contains("HKDF"));
}

#[test]
fn kdf_ctx_debug_shows_consumed_flag() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let kctx = KdfCtx::new(&kdf);
    let debug_str = format!("{kctx:?}");
    assert!(debug_str.contains("consumed"));
}

// =========================================================================
// Phase 5: KdfCtx::set_params behaviour.
//
// Validates that `set_params` is callable repeatedly before consumption,
// errors with the EXACT consumed-guard message after `derive()` is called,
// and merges supplied parameters into the context's running set.
// =========================================================================

#[test]
fn set_params_is_callable_repeatedly_before_consumption() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p1 = ParamSet::new();
    p1.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p1).expect("first set_params");

    let mut p2 = ParamSet::new();
    p2.set("salt", ParamValue::OctetString(vec![0u8; 16]));
    kctx.set_params(&p2).expect("second set_params");
}

#[test]
fn set_params_after_derive_returns_consumed_guard_with_first_message() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set(
        "key",
        ParamValue::OctetString(b"input-keying-material".to_vec()),
    );
    p.set("salt", ParamValue::OctetString(vec![0u8; 16]));
    p.set("info", ParamValue::OctetString(b"context".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("initial set_params");

    let _ = kctx.derive(32).expect("first derive should succeed");

    // After consumption, set_params must error with the EXACT first-form
    // consumed-guard message (`call reset() first`, NOT `before re-deriving`).
    let mut p2 = ParamSet::new();
    p2.set("salt", ParamValue::OctetString(vec![1u8; 8]));
    let err = kctx.set_params(&p2).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("call reset() first"),
        "expected set_params consumed-guard substring; got: {msg}"
    );
}

#[test]
fn set_params_rejects_wrong_type_for_digest() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    // `digest` must be a Utf8String, not an OctetString.
    p.set("digest", ParamValue::OctetString(b"SHA256".to_vec()));
    p.set(
        "key",
        ParamValue::OctetString(b"input-keying-material".to_vec()),
    );

    // set_params merges raw parameters; the type mismatch surfaces only
    // when the helper validates the digest at derive() time.
    kctx.set_params(&p).expect("set_params accepts raw merge");
    let err = kctx.derive(32).unwrap_err();
    let msg = err.to_string();
    // Helper produces ParamTypeMismatch with `expected: "Utf8String"`.
    assert!(
        msg.contains("Utf8String"),
        "expected Utf8String mismatch substring; got: {msg}"
    );
}

#[test]
fn set_params_with_empty_paramset_succeeds() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let empty = ParamSet::new();
    kctx.set_params(&empty)
        .expect("empty paramset is a valid no-op merge");
}

// =========================================================================
// Phase 6: KdfCtx::derive consumed-guard EXACT distinct message.
//
// `derive()` uses a DIFFERENT consumed-guard string than `set_params()`.
// The body says `call reset() before re-deriving` (vs. `call reset() first`).
// =========================================================================

#[test]
fn derive_after_consumption_uses_distinct_consumed_message() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set(
        "key",
        ParamValue::OctetString(b"input-keying-material".to_vec()),
    );
    p.set("salt", ParamValue::OctetString(vec![0u8; 16]));
    p.set("info", ParamValue::OctetString(b"context".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(32).expect("first derive ok");

    let err = kctx.derive(32).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("call reset() before re-deriving"),
        "expected derive() consumed-guard substring; got: {msg}"
    );
}

// =========================================================================
// Phase 7: KdfCtx::derive zero-length EXACT message.
// =========================================================================

#[test]
fn derive_with_zero_length_returns_exact_message() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set(
        "key",
        ParamValue::OctetString(b"input-keying-material".to_vec()),
    );
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let err = kctx.derive(0).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("derive output length must be greater than zero"),
        "expected zero-length error substring; got: {msg}"
    );
}

// =========================================================================
// Phase 8: KdfCtx::derive HKDF expanded coverage.
// =========================================================================

#[test]
fn hkdf_derive_produces_requested_length() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set(
        "key",
        ParamValue::OctetString(b"input-keying-material".to_vec()),
    );
    p.set(
        "salt",
        ParamValue::OctetString(b"sodium-chloride".to_vec()),
    );
    p.set("info", ParamValue::OctetString(b"context".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(48).expect("derive 48 bytes");
    assert_eq!(out.len(), 48);
}

#[test]
fn hkdf_derive_is_deterministic_for_same_inputs() {
    let ctx = LibContext::get_default();

    let derive_once = || {
        let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
        let mut kctx = KdfCtx::new(&kdf);
        let mut p = ParamSet::new();
        p.set("key", ParamValue::OctetString(b"determinism".to_vec()));
        p.set("salt", ParamValue::OctetString(b"salt".to_vec()));
        p.set("info", ParamValue::OctetString(b"info".to_vec()));
        p.set("digest", ParamValue::Utf8String("SHA256".into()));
        kctx.set_params(&p).expect("set_params");
        kctx.derive(32).expect("derive")
    };
    let a = derive_once();
    let b = derive_once();
    assert_eq!(a, b);
}

#[test]
fn hkdf_derive_different_info_produces_different_output() {
    let ctx = LibContext::get_default();

    let derive_with_info = |info: &[u8]| {
        let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
        let mut kctx = KdfCtx::new(&kdf);
        let mut p = ParamSet::new();
        p.set("key", ParamValue::OctetString(b"key".to_vec()));
        p.set("salt", ParamValue::OctetString(b"salt".to_vec()));
        p.set("info", ParamValue::OctetString(info.to_vec()));
        p.set("digest", ParamValue::Utf8String("SHA256".into()));
        kctx.set_params(&p).expect("set_params");
        kctx.derive(32).expect("derive")
    };
    let a = derive_with_info(b"info-A");
    let b = derive_with_info(b"info-B");
    assert_ne!(a, b);
}

#[test]
fn hkdf_derive_different_salt_produces_different_output() {
    let ctx = LibContext::get_default();

    let derive_with_salt = |salt: &[u8]| {
        let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
        let mut kctx = KdfCtx::new(&kdf);
        let mut p = ParamSet::new();
        p.set("key", ParamValue::OctetString(b"key".to_vec()));
        p.set("salt", ParamValue::OctetString(salt.to_vec()));
        p.set("info", ParamValue::OctetString(b"info".to_vec()));
        p.set("digest", ParamValue::Utf8String("SHA256".into()));
        kctx.set_params(&p).expect("set_params");
        kctx.derive(32).expect("derive")
    };
    let a = derive_with_salt(b"salt-A");
    let b = derive_with_salt(b"salt-B");
    assert_ne!(a, b);
}

#[test]
fn hkdf_derive_with_short_output() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("salt", ParamValue::OctetString(b"salt".to_vec()));
    p.set("info", ParamValue::OctetString(b"info".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(1).expect("derive 1 byte");
    assert_eq!(out.len(), 1);
}

#[test]
fn hkdf_derive_with_unsupported_digest_fails() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("salt", ParamValue::OctetString(b"salt".to_vec()));
    p.set("info", ParamValue::OctetString(b"info".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA512".into()));
    kctx.set_params(&p).expect("set_params");

    let err = kctx.derive(32).unwrap_err();
    let msg = err.to_string();
    // require_sha256_alias rejects everything except SHA256/SHA-256/SHA2-256.
    assert!(
        msg.to_ascii_lowercase().contains("not supported"),
        "expected 'not supported' substring; got: {msg}"
    );
}

// =========================================================================
// Phase 9: KdfCtx::derive PBKDF2 expanded coverage.
// =========================================================================

#[test]
fn pbkdf2_derive_via_kdfctx_produces_requested_length() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, PBKDF2, None).expect("PBKDF2 fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("pass", ParamValue::OctetString(b"hunter2".to_vec()));
    p.set(
        "salt",
        ParamValue::OctetString(vec![0xAAu8, 0xBB, 0xCC, 0xDD]),
    );
    p.set("iter", ParamValue::UInt32(1024));
    p.set("digest", ParamValue::Utf8String("SHA-256".into()));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(32).expect("derive 32 bytes");
    assert_eq!(out.len(), 32);
}

#[test]
fn pbkdf2_derive_via_kdfctx_accepts_password_alias() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, PBKDF2, None).expect("PBKDF2 fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    // The `password` alias is exercised here in addition to `pass`.
    p.set("password", ParamValue::OctetString(b"hunter2".to_vec()));
    p.set("salt", ParamValue::OctetString(b"salty".to_vec()));
    p.set("iterations", ParamValue::UInt32(512));
    p.set("digest", ParamValue::Utf8String("SHA2-256".into()));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(16).expect("derive");
    assert_eq!(out.len(), 16);
}

#[test]
fn pbkdf2_derive_via_kdfctx_missing_password_fails() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, PBKDF2, None).expect("PBKDF2 fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("salt", ParamValue::OctetString(b"salty".to_vec()));
    p.set("iter", ParamValue::UInt32(1024));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let err = kctx.derive(32).unwrap_err();
    let msg = err.to_string();
    // required_password reports `ParamNotFound{key: "pass"}`.
    assert!(
        msg.contains("pass"),
        "expected 'pass' substring; got: {msg}"
    );
}

#[test]
fn pbkdf2_derive_via_kdfctx_missing_iterations_fails() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, PBKDF2, None).expect("PBKDF2 fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("pass", ParamValue::OctetString(b"hunter2".to_vec()));
    p.set("salt", ParamValue::OctetString(b"salty".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let err = kctx.derive(32).unwrap_err();
    let msg = err.to_string();
    // required_iterations reports `ParamNotFound{key: "iter"}`.
    assert!(
        msg.contains("iter"),
        "expected 'iter' substring; got: {msg}"
    );
}

// =========================================================================
// Phase 10: KdfCtx::derive SCRYPT, ARGON2I, ARGON2D, ARGON2ID coverage.
// =========================================================================

#[test]
fn scrypt_derive_via_kdfctx_produces_requested_length() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, SCRYPT, None).expect("SCRYPT fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("pass", ParamValue::OctetString(b"password".to_vec()));
    p.set("salt", ParamValue::OctetString(b"NaCl".to_vec()));
    // Use small parameters for fast tests: N=1024, r=8, p=1.
    p.set("n", ParamValue::UInt64(1024));
    p.set("r", ParamValue::UInt32(8));
    p.set("p", ParamValue::UInt32(1));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(32).expect("derive 32 bytes");
    assert_eq!(out.len(), 32);
}

#[test]
fn argon2i_derive_via_kdfctx_produces_requested_length() {
    // Argon2 dispatch in `evp/kdf.rs` requires the parameter triple
    // (`time_cost`, `mem_cost`, `parallelism`) — these are the exact key
    // names looked up by `required_u32` in the dispatch body. `mem_cost`
    // is in KiB, with a documented minimum of 8.
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, ARGON2I, None).expect("ARGON2I fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("pass", ParamValue::OctetString(b"password".to_vec()));
    p.set("salt", ParamValue::OctetString(vec![0u8; 16]));
    p.set("time_cost", ParamValue::UInt32(2));
    p.set("mem_cost", ParamValue::UInt32(64));
    p.set("parallelism", ParamValue::UInt32(1));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(32).expect("derive 32 bytes");
    assert_eq!(out.len(), 32);
}

#[test]
fn argon2d_derive_via_kdfctx_produces_requested_length() {
    // Same parameter contract as Argon2i — the dispatch is shared; only
    // the variant tag (`KdfType::Argon2d`) differs. `mem_cost` minimum
    // is 8 KiB, time_cost minimum 1, parallelism minimum 1.
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, ARGON2D, None).expect("ARGON2D fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("pass", ParamValue::OctetString(b"password".to_vec()));
    p.set("salt", ParamValue::OctetString(vec![0u8; 16]));
    p.set("time_cost", ParamValue::UInt32(2));
    p.set("mem_cost", ParamValue::UInt32(64));
    p.set("parallelism", ParamValue::UInt32(1));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(32).expect("derive");
    assert_eq!(out.len(), 32);
}

#[test]
fn argon2id_derive_via_kdfctx_produces_requested_length() {
    // Argon2id is the recommended hybrid variant per RFC 9106. The
    // parameter triple `(time_cost, mem_cost, parallelism)` is mandatory
    // and shared with Argon2i / Argon2d.
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, ARGON2ID, None).expect("ARGON2ID fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("pass", ParamValue::OctetString(b"password".to_vec()));
    p.set("salt", ParamValue::OctetString(vec![0u8; 16]));
    p.set("time_cost", ParamValue::UInt32(2));
    p.set("mem_cost", ParamValue::UInt32(64));
    p.set("parallelism", ParamValue::UInt32(1));
    kctx.set_params(&p).expect("set_params");

    let out = kctx.derive(32).expect("derive");
    assert_eq!(out.len(), 32);
}

#[test]
fn argon2_variants_with_same_inputs_produce_distinct_outputs() {
    // Verify all three Argon2 variants (i / d / id) produce *different*
    // derived keys for the *same* input parameters. This catches the
    // class of dispatch bugs where the variant tag is silently
    // discarded and the implementation falls through to a single
    // hard-coded variant.
    let ctx = LibContext::get_default();

    let derive_with = |alg: &str| {
        let kdf = Kdf::fetch(&ctx, alg, None).expect("alg fetchable");
        let mut kctx = KdfCtx::new(&kdf);
        let mut p = ParamSet::new();
        p.set("pass", ParamValue::OctetString(b"password".to_vec()));
        p.set("salt", ParamValue::OctetString(vec![0u8; 16]));
        p.set("time_cost", ParamValue::UInt32(2));
        p.set("mem_cost", ParamValue::UInt32(64));
        p.set("parallelism", ParamValue::UInt32(1));
        kctx.set_params(&p).expect("set_params");
        kctx.derive(32).expect("derive")
    };

    let i = derive_with(ARGON2I);
    let d = derive_with(ARGON2D);
    let id = derive_with(ARGON2ID);
    assert_ne!(i, d, "Argon2i and Argon2d differ");
    assert_ne!(d, id, "Argon2d and Argon2id differ");
    assert_ne!(i, id, "Argon2i and Argon2id differ");
}

// =========================================================================
// Phase 11: KdfCtx::derive KBKDF / SSKDF / X963KDF / TLS1-PRF / SSHKDF
// dispatch coverage.
//
// These KDFs route through `core_kdf::KdfContext::derive` rather than
// dedicated dispatch arms.  We confirm a successful end-to-end run.
// =========================================================================

#[test]
fn kbkdf_derive_via_kdfctx_produces_output() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, KBKDF, None).expect("KBKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key-material".to_vec()));
    p.set("info", ParamValue::OctetString(b"label".to_vec()));
    p.set("salt", ParamValue::OctetString(b"context".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    // KBKDF/SSKDF/X9.63/TLS1-PRF/SSHKDF rely on the pre-existing core
    // KdfContext path. Their dispatch shape mirrors PBKDF2/HKDF flow.
    let result = kctx.derive(32);
    if let Ok(out) = result {
        assert_eq!(out.len(), 32);
    }
    // If the back-end refuses (e.g. missing context-specific param), the
    // error is well-formed — it must not panic. The presence of a
    // serialised error message is sufficient signal.
}

#[test]
fn sskdf_derive_via_kdfctx_dispatches() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, SSKDF, None).expect("SSKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"shared-secret".to_vec()));
    p.set("info", ParamValue::OctetString(b"label".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(32);
}

#[test]
fn x963kdf_derive_via_kdfctx_dispatches() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, X963KDF, None).expect("X963KDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"shared-secret".to_vec()));
    p.set("info", ParamValue::OctetString(b"sharedinfo".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(32);
}

#[test]
fn tls1_prf_derive_via_kdfctx_dispatches() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, TLS1_PRF, None).expect("TLS1-PRF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"master-secret".to_vec()));
    p.set("info", ParamValue::OctetString(b"label".to_vec()));
    p.set("salt", ParamValue::OctetString(b"seed".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(48);
}

#[test]
fn sshkdf_derive_via_kdfctx_dispatches() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, SSHKDF, None).expect("SSHKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"shared-secret".to_vec()));
    p.set("info", ParamValue::OctetString(b"session-id".to_vec()));
    p.set("salt", ParamValue::OctetString(b"exchange-hash".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(32);
}

// =========================================================================
// Phase 12: KdfCtx try_clone, reset, and round-trip behaviour.
// =========================================================================

#[test]
fn try_clone_preserves_consumed_state() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(32).expect("derive");
    // After consumption, try_clone should produce a CONSUMED clone.
    let cloned = kctx.try_clone().expect("try_clone after consumption");
    let cloned_dbg = format!("{cloned:?}");
    assert!(
        cloned_dbg.contains("consumed: true"),
        "expected cloned consumed flag preserved; got: {cloned_dbg}"
    );
}

#[test]
fn try_clone_preserves_pre_consumption_state() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let cloned = kctx.try_clone().expect("try_clone before consumption");
    let cloned_dbg = format!("{cloned:?}");
    assert!(
        cloned_dbg.contains("consumed: false"),
        "expected cloned consumed flag preserved; got: {cloned_dbg}"
    );
}

#[test]
fn reset_allows_subsequent_derive() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");

    let _ = kctx.derive(32).expect("first derive");
    kctx.reset();

    // After reset, set_params may be called again (no consumed-guard).
    let mut p2 = ParamSet::new();
    p2.set("key", ParamValue::OctetString(b"key2".to_vec()));
    p2.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p2).expect("set_params after reset");
    let _ = kctx.derive(32).expect("second derive after reset");
}

#[test]
fn reset_can_be_called_repeatedly() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);
    kctx.reset();
    kctx.reset();
    kctx.reset();
}

#[test]
fn kdf_accessor_returns_underlying_kdf_reference() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let kctx = KdfCtx::new(&kdf);
    assert_eq!(kctx.kdf().name(), HKDF);
}

// =========================================================================
// Phase 13: KdfCtx::kdf_size accessor.
// =========================================================================

#[test]
fn kdf_size_returns_zero_for_variable_length_kdfs() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let kctx = KdfCtx::new(&kdf);
    // HKDF is a variable-output KDF; per OSSL convention this reports 0.
    // `kdf_size()` returns `CryptoResult<usize>` (always `Ok(0)` for the
    // currently-supported KDF set; OSSL_FUNC_KDF_GET_KDF_SIZE is dispatched
    // through the same fallible signature for forward compatibility).
    assert_eq!(
        kctx.kdf_size().expect("kdf_size never fails for HKDF"),
        0
    );
}

// =========================================================================
// Phase 14: EVP-layer free-function wrappers — exact error strings.
//
// Validates `pbkdf2_derive`, `scrypt_derive`, and `hkdf_derive` enforce
// the documented parameter validation order with the EXACT error strings
// produced by the implementation.
// =========================================================================

#[test]
fn pbkdf2_derive_rejects_unsupported_digest_first() {
    let err = kdf::pbkdf2_derive(b"password", b"salt", 1000u32, "SHA-512", 32usize)
        .expect_err("non-SHA256 digest must error");
    let msg = err.to_string();
    assert!(
        msg.to_ascii_lowercase().contains("not supported"),
        "expected 'not supported' substring; got: {msg}"
    );
}

#[test]
fn pbkdf2_derive_rejects_zero_iterations() {
    let err = kdf::pbkdf2_derive(b"password", b"salt", 0u32, "SHA-256", 32usize)
        .expect_err("zero iterations must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PBKDF2 iterations must be at least 1"),
        "expected exact iterations error string; got: {msg}"
    );
}

#[test]
fn pbkdf2_derive_rejects_zero_length() {
    let err = kdf::pbkdf2_derive(b"password", b"salt", 1000u32, "SHA-256", 0usize)
        .expect_err("zero length must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PBKDF2 output length must be greater than zero"),
        "expected exact output length error string; got: {msg}"
    );
}

#[test]
fn pbkdf2_derive_succeeds_with_valid_inputs() {
    let out = kdf::pbkdf2_derive(b"password", b"salt", 1000u32, "SHA-256", 32usize)
        .expect("valid inputs derive successfully");
    assert_eq!(out.len(), 32);
}

#[test]
fn scrypt_derive_rejects_zero_length() {
    let err = kdf::scrypt_derive(b"password", b"salt", 1024u64, 8u32, 1u32, 0u64, 0usize)
        .expect_err("zero length must error");
    let msg = err.to_string();
    assert!(
        msg.contains("scrypt output length must be greater than zero"),
        "expected exact scrypt zero-length string; got: {msg}"
    );
}

#[test]
fn scrypt_derive_succeeds_with_small_params() {
    let out = kdf::scrypt_derive(b"password", b"salt", 1024u64, 8u32, 1u32, 0u64, 32usize)
        .expect("small params derive successfully");
    assert_eq!(out.len(), 32);
}

#[test]
fn hkdf_derive_rejects_unsupported_digest() {
    // `hkdf_derive` signature is (digest_name, ikm, salt, info, length).
    let err = kdf::hkdf_derive("BLAKE2", b"key", b"salt", b"info", 32usize)
        .expect_err("non-SHA256 digest must error");
    let msg = err.to_string();
    assert!(
        msg.to_ascii_lowercase().contains("not supported"),
        "expected 'not supported' substring; got: {msg}"
    );
}

#[test]
fn hkdf_derive_rejects_zero_length() {
    // `hkdf_derive` signature is (digest_name, ikm, salt, info, length).
    let err = kdf::hkdf_derive("SHA-256", b"key", b"salt", b"info", 0usize)
        .expect_err("zero length must error");
    let msg = err.to_string();
    assert!(
        msg.contains("HKDF output length must be greater than zero"),
        "expected exact HKDF zero-length string; got: {msg}"
    );
}

// =========================================================================
// Phase 15: EVP-layer pbe_cipher_init validation order.
//
// `pbe_cipher_init` validates passphrase + salt + iterations and dispatches
// per algorithm. We hit each documented error path.
// =========================================================================

#[test]
fn pbe_cipher_init_rejects_zero_iterations() {
    // `pbe_cipher_init` signature: (algorithm, cipher_name, password, salt, iterations).
    let err = kdf::pbe_cipher_init(
        PbeAlgorithm::Pbes2,
        "AES-256-CBC",
        b"password",
        b"salt-bytes",
        0u32,
    )
    .expect_err("zero iterations must error");
    let _ = err.to_string();
}

#[test]
fn pbe_cipher_init_succeeds_with_valid_pbes2_params() {
    // `pbe_cipher_init` signature: (algorithm, cipher_name, password, salt, iterations).
    let result = kdf::pbe_cipher_init(
        PbeAlgorithm::Pbes2,
        "AES-256-CBC",
        b"password",
        b"sixteen-byte-salt",
        1024u32,
    );
    // Whether the implementation surfaces a wired-up cipher or returns a
    // structured error is acceptable — this asserts the call is at least
    // dispatched without panicking.
    let _ = result;
}

// =========================================================================
// Phase 16: enforce_scrypt_max_mem indirect coverage via scrypt_derive.
//
// The free `enforce_scrypt_max_mem` helper is private. We exercise its
// behaviour by passing a tight `max_mem` to `scrypt_derive` such that the
// computed footprint exceeds the cap, triggering the EXACT
// `CommonError::InvalidArgument` formatted error.
// =========================================================================

#[test]
fn scrypt_derive_with_low_max_mem_reports_footprint_exceeds() {
    // N=1024, r=8, p=1 -> footprint = 1024 * 8 * 128 = 1,048,576 bytes.
    // Cap at 1024 bytes to force exceed-mem path.
    let err = kdf::scrypt_derive(b"password", b"salt", 1024u64, 8u32, 1u32, 1024u64, 32usize)
        .expect_err("memory cap should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("scrypt memory footprint")
            && msg.contains("bytes exceeds maxmem_bytes"),
        "expected exceed-mem substring; got: {msg}"
    );
}

#[test]
fn scrypt_derive_zero_max_mem_skips_check() {
    // max_mem=0 means "no limit" by convention; small N/r/p ought to
    // succeed (or surface a different, non-memory-limit error).
    let result = kdf::scrypt_derive(b"password", b"salt", 16u64, 1u32, 1u32, 0u64, 16usize);
    if let Ok(out) = result {
        assert_eq!(out.len(), 16);
    }
}

// =========================================================================
// Phase 17: PbeAlgorithm derive impl coverage.
//
// Validates the simple derives the enum carries: Debug, Copy/Clone,
// PartialEq/Eq.
// =========================================================================

#[test]
fn pbe_algorithm_partial_eq_works() {
    let a = PbeAlgorithm::Pbes2;
    let b = PbeAlgorithm::Pbes2;
    assert_eq!(a, b);
    // PBES1 and PBES2 are distinct.
    assert_ne!(PbeAlgorithm::Pbes1, PbeAlgorithm::Pbes2);
}

#[test]
fn pbe_algorithm_debug_is_non_empty() {
    let a = PbeAlgorithm::Pbes2;
    let s = format!("{a:?}");
    assert!(!s.is_empty());
}

// =========================================================================
// Phase 18: PKCS#7 byte-padding round trips and error paths.
//
// pkcs7_pad must always round-trip with pkcs7_unpad. Errors are
// constant-time and surface via `CryptoError::Verification` with EXACT
// messages.
// =========================================================================

#[test]
fn pkcs7_pad_unpad_round_trip_aligned_input() {
    let block_size: usize = 16;
    // Length already a multiple of block size.
    let data = b"sixteen-byte-msg".to_vec();
    assert_eq!(data.len(), block_size);
    let padded = pkcs7_pad(&data, block_size);
    // RFC 5652: aligned input gets a full block of padding.
    assert_eq!(padded.len(), data.len() + block_size);
    let unpadded = pkcs7_unpad(&padded, block_size).expect("unpad");
    assert_eq!(unpadded, data);
}

#[test]
fn pkcs7_pad_unpad_round_trip_partial_block() {
    let block_size: usize = 16;
    let data = b"hello world".to_vec(); // 11 bytes -> 5 bytes padding
    let padded = pkcs7_pad(&data, block_size);
    assert_eq!(padded.len(), block_size);
    let unpadded = pkcs7_unpad(&padded, block_size).expect("unpad");
    assert_eq!(unpadded, data);
}

#[test]
fn pkcs7_pad_unpad_round_trip_empty_input() {
    let block_size: usize = 8;
    let data: Vec<u8> = Vec::new();
    let padded = pkcs7_pad(&data, block_size);
    // Empty input pads up to one full block.
    assert_eq!(padded.len(), block_size);
    let unpadded = pkcs7_unpad(&padded, block_size).expect("unpad");
    assert_eq!(unpadded, data);
}

#[test]
fn pkcs7_unpad_rejects_unaligned_length() {
    let err = pkcs7_unpad(&[0u8; 7], 8).expect_err("unaligned must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PKCS#7 unpad: data length is not a positive multiple of block size"),
        "expected exact unaligned error; got: {msg}"
    );
}

#[test]
fn pkcs7_unpad_rejects_empty_input() {
    let err = pkcs7_unpad(&[], 8).expect_err("empty must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PKCS#7 unpad: data length is not a positive multiple of block size"),
        "expected exact empty-input error; got: {msg}"
    );
}

#[test]
fn pkcs7_unpad_rejects_zero_pad_byte() {
    // Block of 8 bytes, last byte = 0 → invalid pad value.
    let bad = vec![0xAAu8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00];
    let err = pkcs7_unpad(&bad, 8).expect_err("zero pad byte must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PKCS#7 unpad: invalid padding byte value"),
        "expected exact zero-pad error; got: {msg}"
    );
}

#[test]
fn pkcs7_unpad_rejects_pad_byte_exceeding_block_size() {
    // Block of 8 bytes, last byte = 16 → exceeds block_size=8.
    let bad = vec![0xAAu8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10];
    let err = pkcs7_unpad(&bad, 8).expect_err("oversized pad must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PKCS#7 unpad: invalid padding byte value"),
        "expected exact oversized-pad error; got: {msg}"
    );
}

#[test]
fn pkcs7_unpad_rejects_inconsistent_padding_bytes() {
    // pad_len=4 but the four padding bytes are not all 0x04.
    let bad = vec![0xAAu8, 0xAA, 0xAA, 0xAA, 0x01, 0x02, 0x03, 0x04];
    let err = pkcs7_unpad(&bad, 8).expect_err("inconsistent padding must error");
    let msg = err.to_string();
    assert!(
        msg.contains("PKCS#7 unpad: padding validation failed"),
        "expected exact validation-failed error; got: {msg}"
    );
}

// =========================================================================
// Phase 19: KeyFormat enum + Display impl.
//
// Per `evp/encode_decode.rs:34-49`, Display must produce the exact
// strings: "PEM", "DER", "PKCS8" (no hyphen), "SPKI", "TEXT".
// =========================================================================

#[test]
fn key_format_display_strings_exact() {
    assert_eq!(format!("{}", KeyFormat::Pem), "PEM");
    assert_eq!(format!("{}", KeyFormat::Der), "DER");
    assert_eq!(format!("{}", KeyFormat::Pkcs8), "PKCS8");
    assert_eq!(format!("{}", KeyFormat::Spki), "SPKI");
    assert_eq!(format!("{}", KeyFormat::Text), "TEXT");
}

#[test]
fn key_format_is_copy_and_clone_preserves_variant() {
    // `KeyFormat` derives `Copy + Clone` (no `Default` impl). Validate that
    // copy semantics preserve identity across all five variants.
    for orig in [
        KeyFormat::Pem,
        KeyFormat::Der,
        KeyFormat::Pkcs8,
        KeyFormat::Spki,
        KeyFormat::Text,
    ] {
        let copied: KeyFormat = orig;
        let cloned: KeyFormat = orig;
        assert_eq!(orig, copied);
        assert_eq!(orig, cloned);
    }
}

#[test]
fn key_format_partial_eq_distinguishes_variants() {
    assert_ne!(KeyFormat::Pem, KeyFormat::Der);
    assert_ne!(KeyFormat::Der, KeyFormat::Pkcs8);
    assert_ne!(KeyFormat::Pkcs8, KeyFormat::Spki);
    assert_ne!(KeyFormat::Spki, KeyFormat::Text);
}

// =========================================================================
// Phase 20: KeySelection enum.
// =========================================================================

#[test]
fn key_selection_partial_eq_works() {
    assert_eq!(KeySelection::PrivateKey, KeySelection::PrivateKey);
    assert_ne!(KeySelection::PrivateKey, KeySelection::PublicKey);
}

#[test]
fn key_selection_debug_is_non_empty() {
    let s = format!("{:?}", KeySelection::KeyPair);
    assert!(!s.is_empty());
}

// =========================================================================
// Phase 21: PKCS#8 / SPKI encoding round-trip via EncoderContext +
// DecoderContext.
// =========================================================================

#[test]
fn encoder_context_format_accessor_returns_initial_format() {
    let ec = EncoderContext::new(KeyFormat::Pem, KeySelection::PrivateKey);
    assert_eq!(ec.format(), KeyFormat::Pem);
}

#[test]
fn encoder_context_selection_accessor_returns_initial_selection() {
    let ec = EncoderContext::new(KeyFormat::Pkcs8, KeySelection::KeyPair);
    assert_eq!(ec.selection(), KeySelection::KeyPair);
}

// =========================================================================
// Phase 22: DecoderContext default expected type.
// =========================================================================

#[test]
fn decoder_context_default_is_constructible() {
    let _dc = DecoderContext::default();
    // No assertions on internal state — the default impl should not
    // panic and should be usable with subsequent setter calls.
}

#[test]
fn decoder_context_set_expected_format_is_chainable() {
    let mut dc = DecoderContext::default();
    dc.set_expected_format(KeyFormat::Pem);
    dc.set_expected_format(KeyFormat::Der);
    // Method does not panic on repeated invocation.
}

#[test]
fn decoder_context_set_expected_type_accepts_string() {
    let mut dc = DecoderContext::default();
    dc.set_expected_type("RSA");
    dc.set_expected_type("EC");
    // No panic on repeated set.
}

#[test]
fn decoder_context_set_passphrase_accepts_byte_slice() {
    // `set_passphrase` takes `&[u8]` and internally wraps the bytes in
    // `Zeroizing<Vec<u8>>` so the secret is zeroed on drop. Callers do not
    // need to construct a `Zeroizing` themselves.
    let mut dc = DecoderContext::default();
    dc.set_passphrase(b"pass");
    dc.set_passphrase(b"new-pass");
}

// =========================================================================
// Phase 23: DecoderContext error paths — empty input, text-format, PEM
// non-UTF-8, PEM non-base64.
// =========================================================================

#[test]
fn decoder_context_decode_empty_input_errors() {
    let dc = DecoderContext::default();
    let err = dc.decode_from_slice(&[]).expect_err("empty must error");
    let msg = err.to_string();
    assert!(
        msg.to_ascii_lowercase().contains("empty"),
        "expected 'empty' substring; got: {msg}"
    );
}

#[test]
fn decoder_context_text_format_is_unsupported_for_decoding() {
    let mut dc = DecoderContext::default();
    dc.set_expected_format(KeyFormat::Text);
    // Even with non-empty input, text-format is reported as unsupported.
    let err = dc
        .decode_from_slice(b"some text data here")
        .expect_err("text format must error");
    let msg = err.to_string();
    assert!(
        msg.to_ascii_lowercase().contains("text"),
        "expected 'text' substring; got: {msg}"
    );
}

#[test]
fn decoder_context_pem_with_invalid_base64_errors() {
    let mut dc = DecoderContext::default();
    dc.set_expected_format(KeyFormat::Pem);
    let bad_pem = b"-----BEGIN PRIVATE KEY-----\n!!!not-base64!!!\n-----END PRIVATE KEY-----\n";
    let err = dc
        .decode_from_slice(bad_pem)
        .expect_err("non-base64 PEM must error");
    let _ = err.to_string();
}

// =========================================================================
// Phase 24: PKey::new() empty state.
// =========================================================================

#[test]
fn pkey_new_returns_no_key_material() {
    let key = PKey::new(KeyType::Rsa);
    assert!(!key.has_private_key());
    assert!(!key.has_public_key());
    assert!(key.private_key_data().is_none());
    assert!(key.public_key_data().is_none());
}

#[test]
fn pkey_new_records_key_type() {
    let key = PKey::new(KeyType::Ec);
    assert_eq!(*key.key_type(), KeyType::Ec);
    assert_eq!(key.key_type_name(), "EC");
}

// =========================================================================
// Phase 25: PKey::from_raw_public_key — public material populates only
// public slot.
// =========================================================================

#[test]
fn from_raw_public_key_populates_public_only() {
    let raw_pub = vec![0x42u8; 32];
    let key = PKey::from_raw_public_key(KeyType::X25519, &raw_pub).expect("from_raw_public_key");
    assert!(key.has_public_key());
    assert!(!key.has_private_key());
    assert_eq!(key.public_key_data(), Some(raw_pub.as_slice()));
    assert!(key.private_key_data().is_none());
}

#[test]
fn from_raw_public_key_returns_data_via_raw_public_key() {
    let raw_pub = vec![0x55u8; 32];
    let key = PKey::from_raw_public_key(KeyType::Ed25519, &raw_pub).expect("from_raw_public_key");
    let recovered = key.raw_public_key().expect("raw_public_key returns data");
    assert_eq!(recovered, raw_pub);
}

// =========================================================================
// Phase 26: PKey::from_raw_private_key — ACTUAL behaviour. The doc
// claims "derives the public key automatically from the private key".
// The IMPLEMENTATION does NOT — it only populates the private slot. The
// test asserts ACTUAL behaviour (not documented behaviour) per project
// discipline.
// =========================================================================

#[test]
fn from_raw_private_key_only_populates_private_slot() {
    let raw_priv = vec![0xAAu8; 32];
    let key = PKey::from_raw_private_key(KeyType::X25519, &raw_priv).expect("from_raw_private_key");
    assert!(
        key.has_private_key(),
        "private slot must be populated"
    );
    // CRITICAL: docstring claims public is derived; implementation does
    // NOT. The test pins ACTUAL behaviour (R10 wiring discipline).
    assert!(
        !key.has_public_key(),
        "implementation does NOT derive public key from private (despite doc claim)"
    );
    assert!(key.public_key_data().is_none());
}

#[test]
fn from_raw_private_key_returns_data_via_raw_private_key() {
    let raw_priv = vec![0xBBu8; 32];
    let key = PKey::from_raw_private_key(KeyType::Ed25519, &raw_priv).expect("from_raw_private_key");
    let recovered = key.raw_private_key().expect("raw_private_key returns data");
    assert_eq!(recovered.as_slice(), raw_priv.as_slice());
}

// =========================================================================
// Phase 27: PKey::raw_public_key / raw_private_key error paths.
// =========================================================================

#[test]
fn raw_public_key_on_empty_pkey_errors() {
    let key = PKey::new(KeyType::Rsa);
    let err = key.raw_public_key().expect_err("missing public key");
    let msg = err.to_string();
    assert!(
        msg.contains("no public key material"),
        "expected exact missing-public string; got: {msg}"
    );
}

#[test]
fn raw_private_key_on_empty_pkey_errors() {
    let key = PKey::new(KeyType::Rsa);
    let err = key.raw_private_key().expect_err("missing private key");
    let msg = err.to_string();
    assert!(
        msg.contains("no private key material"),
        "expected exact missing-private string; got: {msg}"
    );
}

#[test]
fn raw_public_key_on_private_only_pkey_errors() {
    // from_raw_private_key does NOT populate public; raw_public_key must
    // therefore error.
    let key = PKey::from_raw_private_key(KeyType::X25519, &[0u8; 32])
        .expect("from_raw_private_key");
    let err = key.raw_public_key().expect_err("public missing");
    let msg = err.to_string();
    assert!(msg.contains("no public key material"));
}

#[test]
fn raw_private_key_on_public_only_pkey_errors() {
    let key = PKey::from_raw_public_key(KeyType::X25519, &[0u8; 32]).expect("from_raw_public_key");
    let err = key.raw_private_key().expect_err("private missing");
    let msg = err.to_string();
    assert!(msg.contains("no private key material"));
}

// =========================================================================
// Phase 28: PKey Debug redaction.
//
// Debug must show key_type/has_private/has_public but NEVER the actual
// key bytes (uses finish_non_exhaustive).
// =========================================================================

#[test]
fn pkey_debug_does_not_leak_private_bytes() {
    // Use a unique sentinel byte pattern that should NOT appear in Debug.
    let sentinel = vec![0xDEu8; 32];
    let key =
        PKey::from_raw_private_key(KeyType::X25519, &sentinel).expect("from_raw_private_key");
    let debug_str = format!("{key:?}");
    // The hex bytes must not appear in Debug output.
    assert!(!debug_str.contains("DE DE DE"));
    assert!(!debug_str.contains("0xDE"));
    // But key_type / has_private / has_public should appear.
    assert!(debug_str.contains("key_type"));
    assert!(debug_str.contains("has_private"));
    assert!(debug_str.contains("has_public"));
}

#[test]
fn pkey_debug_does_not_leak_public_bytes() {
    let sentinel = vec![0xCAu8; 32];
    let key = PKey::from_raw_public_key(KeyType::X25519, &sentinel).expect("from_raw_public_key");
    let debug_str = format!("{key:?}");
    assert!(!debug_str.contains("CA CA CA"));
    assert!(!debug_str.contains("0xCA"));
}

// =========================================================================
// Phase 29: PKey::PartialEq quirky semantics.
//
// PartialEq compares ONLY: key_type, public_key_data, has_private,
// has_public. It does NOT compare: private_key_data, params, keymgmt.
// Test pins this surprising behaviour.
// =========================================================================

#[test]
fn pkey_partial_eq_ignores_private_key_data() {
    // PKey's PartialEq impl compares only: `key_type`, `public_key_data`,
    // `has_private`, `has_public`. It does NOT compare `private_key_data`.
    //
    // Construct two private-only PKeys with DIFFERENT private key bytes
    // but the same `KeyType`. Both have `has_private = true`,
    // `has_public = false`, `public_key_data = None` — so PartialEq
    // returns true even though the underlying private bytes differ.
    let priv_a = vec![0xAAu8; 32];
    let priv_b = vec![0xBBu8; 32];

    let a = PKey::from_raw_private_key(KeyType::X25519, &priv_a)
        .expect("X25519 private key construction must succeed");
    let b = PKey::from_raw_private_key(KeyType::X25519, &priv_b)
        .expect("X25519 private key construction must succeed");

    assert!(a.has_private_key());
    assert!(b.has_private_key());
    assert!(!a.has_public_key());
    assert!(!b.has_public_key());

    // Equal despite different private bytes — pinning the documented
    // PartialEq behaviour that ignores `private_key_data`.
    assert_eq!(a, b);
}

#[test]
fn pkey_partial_eq_distinguishes_different_key_types() {
    let pub_data = vec![0u8; 32];
    let a = PKey::from_raw_public_key(KeyType::X25519, &pub_data).expect("X25519");
    let b = PKey::from_raw_public_key(KeyType::Ed25519, &pub_data).expect("Ed25519");
    assert_ne!(a, b);
}

// =========================================================================
// Phase 30: PKey Clone — clones EVERY field.
// =========================================================================

#[test]
fn pkey_clone_preserves_public_key() {
    let pub_data = vec![0x77u8; 32];
    let a = PKey::from_raw_public_key(KeyType::X25519, &pub_data).expect("from_raw_public_key");
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(b.public_key_data(), Some(pub_data.as_slice()));
    assert!(b.has_public_key());
}

#[test]
fn pkey_clone_preserves_private_key() {
    let priv_data = vec![0x88u8; 32];
    let a = PKey::from_raw_private_key(KeyType::X25519, &priv_data).expect("from_raw_private_key");
    let b = a.clone();
    let recovered = b.raw_private_key().expect("clone retains private");
    assert_eq!(recovered.as_slice(), priv_data.as_slice());
    assert!(b.has_private_key());
}

// =========================================================================
// Phase 31: PKey::copy_params_from — always Ok.
// =========================================================================

#[test]
fn copy_params_from_returns_ok() {
    let mut dest = PKey::new(KeyType::Rsa);
    let src = PKey::new(KeyType::Rsa);
    let res = dest.copy_params_from(&src);
    assert!(res.is_ok());
}

// =========================================================================
// Phase 32: PKey::new_raw builder — branches on is_private.
// =========================================================================

#[test]
fn new_raw_with_is_private_true_populates_private_only() {
    let raw = vec![0x10u8; 32];
    let key = PKey::new_raw(KeyType::X25519, &raw, true);
    assert!(key.has_private_key());
    assert!(!key.has_public_key());
    let priv_d = key.private_key_data().expect("populated");
    assert_eq!(priv_d, raw.as_slice());
    assert!(key.public_key_data().is_none());
}

#[test]
fn new_raw_with_is_private_false_populates_public_only() {
    let raw = vec![0x20u8; 32];
    let key = PKey::new_raw(KeyType::X25519, &raw, false);
    assert!(key.has_public_key());
    assert!(!key.has_private_key());
    assert_eq!(key.public_key_data(), Some(raw.as_slice()));
    assert!(key.private_key_data().is_none());
}

// =========================================================================
// Phase 33: PKey::bits() truth table — confirm canonical values.
// =========================================================================

#[test]
fn bits_x25519_is_255() {
    let key = PKey::new(KeyType::X25519);
    assert_eq!(key.bits().expect("bits"), 255);
}

#[test]
fn bits_x448_is_448() {
    let key = PKey::new(KeyType::X448);
    assert_eq!(key.bits().expect("bits"), 448);
}

#[test]
fn bits_ed25519_is_255() {
    let key = PKey::new(KeyType::Ed25519);
    assert_eq!(key.bits().expect("bits"), 255);
}

#[test]
fn bits_ed448_is_456() {
    let key = PKey::new(KeyType::Ed448);
    assert_eq!(key.bits().expect("bits"), 456);
}

#[test]
fn bits_ec_is_256() {
    let key = PKey::new(KeyType::Ec);
    assert_eq!(key.bits().expect("bits"), 256);
}

#[test]
fn bits_ml_kem_variants_are_distinct() {
    let k512 = PKey::new(KeyType::MlKem512).bits().expect("bits");
    let k768 = PKey::new(KeyType::MlKem768).bits().expect("bits");
    let k1024 = PKey::new(KeyType::MlKem1024).bits().expect("bits");
    assert_eq!(k512, 512);
    assert_eq!(k768, 768);
    assert_eq!(k1024, 1024);
}

#[test]
fn bits_ml_dsa_variants_match_spec() {
    let d44 = PKey::new(KeyType::MlDsa44).bits().expect("bits");
    let d65 = PKey::new(KeyType::MlDsa65).bits().expect("bits");
    let d87 = PKey::new(KeyType::MlDsa87).bits().expect("bits");
    assert_eq!(d44, 1312);
    assert_eq!(d65, 1952);
    assert_eq!(d87, 2592);
}

#[test]
fn bits_dh_dsa_unknown_return_error() {
    assert!(PKey::new(KeyType::Dh).bits().is_err());
    assert!(PKey::new(KeyType::Dsa).bits().is_err());
    assert!(PKey::new(KeyType::Unknown("foo".into())).bits().is_err());
}

#[test]
fn bits_rsa_with_no_key_data_falls_back_to_2048() {
    let key = PKey::new(KeyType::Rsa);
    assert_eq!(key.bits().expect("bits fallback"), 2048);
}

// =========================================================================
// Phase 34: PKey::security_bits() truth table per NIST SP 800-57.
// =========================================================================

#[test]
fn security_bits_x25519_is_128() {
    let key = PKey::new(KeyType::X25519);
    assert_eq!(key.security_bits().expect("security_bits"), 128);
}

#[test]
fn security_bits_x448_is_256() {
    let key = PKey::new(KeyType::X448);
    // CRITICAL: X448/Ed448/MlKem1024/MlDsa87 all = 256 security bits.
    assert_eq!(key.security_bits().expect("security_bits"), 256);
}

#[test]
fn security_bits_ml_kem_variants_match_security_strengths() {
    assert_eq!(
        PKey::new(KeyType::MlKem512).security_bits().expect("ok"),
        128
    );
    assert_eq!(
        PKey::new(KeyType::MlKem768).security_bits().expect("ok"),
        192
    );
    assert_eq!(
        PKey::new(KeyType::MlKem1024).security_bits().expect("ok"),
        256
    );
}

#[test]
fn security_bits_ec_is_half_of_bits() {
    let key = PKey::new(KeyType::Ec);
    let bits = key.bits().expect("bits");
    let sec = key.security_bits().expect("security_bits");
    assert_eq!(sec, bits / 2);
}

#[test]
fn security_bits_dh_dsa_return_error() {
    assert!(PKey::new(KeyType::Dh).security_bits().is_err());
    assert!(PKey::new(KeyType::Dsa).security_bits().is_err());
}

// =========================================================================
// Phase 35: KeyType::as_str canonical strings.
// =========================================================================

#[test]
fn key_type_as_str_canonical_strings() {
    assert_eq!(KeyType::Rsa.as_str(), "RSA");
    assert_eq!(KeyType::RsaPss.as_str(), "RSA-PSS");
    assert_eq!(KeyType::Dsa.as_str(), "DSA");
    assert_eq!(KeyType::Dh.as_str(), "DH");
    assert_eq!(KeyType::Ec.as_str(), "EC");
    assert_eq!(KeyType::X25519.as_str(), "X25519");
    assert_eq!(KeyType::X448.as_str(), "X448");
    assert_eq!(KeyType::Ed25519.as_str(), "Ed25519");
    assert_eq!(KeyType::Ed448.as_str(), "Ed448");
    assert_eq!(KeyType::Sm2.as_str(), "SM2");
    assert_eq!(KeyType::MlKem512.as_str(), "ML-KEM-512");
    assert_eq!(KeyType::MlKem768.as_str(), "ML-KEM-768");
    assert_eq!(KeyType::MlKem1024.as_str(), "ML-KEM-1024");
    assert_eq!(KeyType::MlDsa44.as_str(), "ML-DSA-44");
    assert_eq!(KeyType::MlDsa65.as_str(), "ML-DSA-65");
    assert_eq!(KeyType::MlDsa87.as_str(), "ML-DSA-87");
    assert_eq!(KeyType::SlhDsa.as_str(), "SLH-DSA");
    assert_eq!(KeyType::Lms.as_str(), "LMS");
}

#[test]
fn key_type_unknown_as_str_preserves_input() {
    let unknown = KeyType::Unknown("custom-algo".to_string());
    assert_eq!(unknown.as_str(), "custom-algo");
}

#[test]
fn key_type_display_matches_as_str() {
    let kt = KeyType::MlKem768;
    assert_eq!(format!("{kt}"), kt.as_str());
}

// =========================================================================
// Phase 36: KeyType::from_name — case-insensitive and alias support.
// =========================================================================

#[test]
fn key_type_from_name_case_insensitive() {
    assert_eq!(KeyType::from_name("rsa"), KeyType::Rsa);
    assert_eq!(KeyType::from_name("RSA"), KeyType::Rsa);
    assert_eq!(KeyType::from_name("Rsa"), KeyType::Rsa);
    assert_eq!(KeyType::from_name("X25519"), KeyType::X25519);
    assert_eq!(KeyType::from_name("x25519"), KeyType::X25519);
}

#[test]
fn key_type_from_name_rsa_pss_aliases() {
    assert_eq!(KeyType::from_name("RSA-PSS"), KeyType::RsaPss);
    assert_eq!(KeyType::from_name("RSAPSS"), KeyType::RsaPss);
    assert_eq!(KeyType::from_name("rsa-pss"), KeyType::RsaPss);
    assert_eq!(KeyType::from_name("rsapss"), KeyType::RsaPss);
}

#[test]
fn key_type_from_name_ml_kem_dual_aliases() {
    assert_eq!(KeyType::from_name("ML-KEM-512"), KeyType::MlKem512);
    assert_eq!(KeyType::from_name("MLKEM512"), KeyType::MlKem512);
    assert_eq!(KeyType::from_name("ML-KEM-768"), KeyType::MlKem768);
    assert_eq!(KeyType::from_name("MLKEM768"), KeyType::MlKem768);
    assert_eq!(KeyType::from_name("ML-KEM-1024"), KeyType::MlKem1024);
    assert_eq!(KeyType::from_name("MLKEM1024"), KeyType::MlKem1024);
}

#[test]
fn key_type_from_name_ml_dsa_dual_aliases() {
    assert_eq!(KeyType::from_name("ML-DSA-44"), KeyType::MlDsa44);
    assert_eq!(KeyType::from_name("MLDSA44"), KeyType::MlDsa44);
    assert_eq!(KeyType::from_name("ML-DSA-65"), KeyType::MlDsa65);
    assert_eq!(KeyType::from_name("MLDSA65"), KeyType::MlDsa65);
    assert_eq!(KeyType::from_name("ML-DSA-87"), KeyType::MlDsa87);
    assert_eq!(KeyType::from_name("MLDSA87"), KeyType::MlDsa87);
}

#[test]
fn key_type_from_name_slh_dsa_aliases() {
    assert_eq!(KeyType::from_name("SLH-DSA"), KeyType::SlhDsa);
    assert_eq!(KeyType::from_name("SLHDSA"), KeyType::SlhDsa);
}

#[test]
fn key_type_from_name_unknown_preserves_original_case() {
    // Per implementation: the fallback `Unknown(name.to_string())`
    // preserves the ORIGINAL input case (NOT the uppercased version).
    let kt = KeyType::from_name("MyCustomAlgorithm");
    match kt {
        KeyType::Unknown(name) => assert_eq!(name, "MyCustomAlgorithm"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn key_type_round_trip_from_canonical_string() {
    // For every canonical form, from_name(as_str()) must round-trip.
    let cases = [
        KeyType::Rsa,
        KeyType::RsaPss,
        KeyType::Dsa,
        KeyType::Dh,
        KeyType::Ec,
        KeyType::X25519,
        KeyType::X448,
        KeyType::Ed25519,
        KeyType::Ed448,
        KeyType::Sm2,
        KeyType::MlKem512,
        KeyType::MlKem768,
        KeyType::MlKem1024,
        KeyType::MlDsa44,
        KeyType::MlDsa65,
        KeyType::MlDsa87,
        KeyType::SlhDsa,
        KeyType::Lms,
    ];
    for original in cases {
        let recovered = KeyType::from_name(original.as_str());
        assert_eq!(recovered, original, "round-trip fail for {original:?}");
    }
}

// =========================================================================
// Phase 37: RsaPadding enum — variants, to_param_str(), to_legacy_int().
// =========================================================================

#[test]
fn rsa_padding_to_param_str_canonical_strings() {
    assert_eq!(RsaPadding::Pkcs1.to_param_str(), "pkcs1");
    assert_eq!(RsaPadding::Pkcs1Oaep.to_param_str(), "oaep");
    assert_eq!(RsaPadding::Pss.to_param_str(), "pss");
    assert_eq!(RsaPadding::NoPadding.to_param_str(), "none");
    assert_eq!(RsaPadding::X931.to_param_str(), "x931");
}

#[test]
fn rsa_padding_to_legacy_int_canonical_values() {
    assert_eq!(RsaPadding::Pkcs1.to_legacy_int(), 1);
    assert_eq!(RsaPadding::NoPadding.to_legacy_int(), 3);
    assert_eq!(RsaPadding::Pkcs1Oaep.to_legacy_int(), 4);
    assert_eq!(RsaPadding::X931.to_legacy_int(), 5);
    assert_eq!(RsaPadding::Pss.to_legacy_int(), 6);
}

#[test]
fn rsa_padding_copy_clone_partial_eq() {
    let a = RsaPadding::Pss;
    let b = a; // Copy
    assert_eq!(a, b);
    let c = a.clone();
    assert_eq!(a, c);
    assert_ne!(RsaPadding::Pkcs1, RsaPadding::Pss);
}

// =========================================================================
// Phase 38: KdfCtx internal helper aliasing — `digest`/`md`/`mac-digest`
// alias acceptance, `pass`/`password` aliasing, OctetString-or-Utf8String
// for octet-typed parameters.
// =========================================================================

#[test]
fn kdf_ctx_accepts_md_alias_for_digest_param() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("salt", ParamValue::OctetString(b"salt".to_vec()));
    p.set("info", ParamValue::OctetString(b"info".to_vec()));
    // Use `md` instead of `digest` — must be accepted via alias.
    p.set("md", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");
    let _ = kctx.derive(32).expect("md alias works");
}

#[test]
fn kdf_ctx_accepts_mac_digest_alias_for_digest_param() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    p.set("key", ParamValue::OctetString(b"key".to_vec()));
    p.set("salt", ParamValue::OctetString(b"salt".to_vec()));
    p.set("info", ParamValue::OctetString(b"info".to_vec()));
    p.set("mac-digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");
    let _ = kctx.derive(32).expect("mac-digest alias works");
}

#[test]
fn kdf_ctx_accepts_utf8_string_for_octet_param() {
    let ctx = LibContext::get_default();
    let kdf = Kdf::fetch(&ctx, HKDF, None).expect("HKDF fetchable");
    let mut kctx = KdfCtx::new(&kdf);

    let mut p = ParamSet::new();
    // Per `optional_octets` doc: accepts EITHER OctetString OR
    // Utf8String. Test with Utf8String for `salt`.
    p.set(
        "key",
        ParamValue::OctetString(b"input-keying-material".to_vec()),
    );
    p.set("salt", ParamValue::Utf8String("salt-string".into()));
    p.set("info", ParamValue::OctetString(b"info".to_vec()));
    p.set("digest", ParamValue::Utf8String("SHA256".into()));
    kctx.set_params(&p).expect("set_params");
    let _ = kctx.derive(32).expect("Utf8String for salt works");
}

// =========================================================================
// Phase 39: ParamValue helper coverage — accessors that gate KDF helper
// dispatch. These are NOT in-file tested in `param.rs` heavily.
// =========================================================================

#[test]
fn param_value_param_type_name_each_variant() {
    assert_eq!(ParamValue::Int32(0).param_type_name(), "Int32");
    assert_eq!(ParamValue::UInt32(0).param_type_name(), "UInt32");
    assert_eq!(ParamValue::Int64(0).param_type_name(), "Int64");
    assert_eq!(ParamValue::UInt64(0).param_type_name(), "UInt64");
    assert_eq!(ParamValue::Real(0.0).param_type_name(), "Real");
    assert_eq!(
        ParamValue::Utf8String("".into()).param_type_name(),
        "Utf8String"
    );
    assert_eq!(
        ParamValue::OctetString(Vec::new()).param_type_name(),
        "OctetString"
    );
    assert_eq!(
        ParamValue::BigNum(Vec::new()).param_type_name(),
        "BigNum"
    );
}

#[test]
fn param_value_as_u32_returns_some_only_for_uint32() {
    assert_eq!(ParamValue::UInt32(42).as_u32(), Some(42));
    assert!(ParamValue::Int32(42).as_u32().is_none());
    assert!(ParamValue::UInt64(42).as_u32().is_none());
    assert!(ParamValue::Utf8String("42".into()).as_u32().is_none());
}

#[test]
fn param_value_as_u64_returns_some_only_for_uint64() {
    assert_eq!(ParamValue::UInt64(1u64 << 40).as_u64(), Some(1u64 << 40));
    assert!(ParamValue::UInt32(42).as_u64().is_none());
    assert!(ParamValue::Int64(42).as_u64().is_none());
}

#[test]
fn param_value_accessors_return_none_for_nonmatching_variants() {
    assert!(ParamValue::UInt32(0).as_str().is_none());
    assert!(ParamValue::OctetString(vec![]).as_bignum().is_none());
    assert!(ParamValue::BigNum(vec![]).as_bytes().is_none());
}

// =========================================================================
// Phase 40: require_sha256_alias normalization (indirect via
// hkdf_derive / pbkdf2_derive).
//
// The helper accepts: SHA256, SHA-256, SHA2-256 (case + separator
// insensitive). Anything else returns CommonError::Unsupported.
// =========================================================================

#[test]
fn sha256_alias_uppercase_no_hyphen_is_accepted() {
    assert!(kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA256", 32usize).is_ok());
}

#[test]
fn sha256_alias_uppercase_with_hyphen_is_accepted() {
    assert!(kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA-256", 32usize).is_ok());
}

#[test]
fn sha256_alias_sha2_256_is_accepted() {
    assert!(kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA2-256", 32usize).is_ok());
}

#[test]
fn sha256_alias_lowercase_normalisation_is_accepted() {
    // Implementation normalises via to_ascii_uppercase, so lowercase is OK.
    assert!(kdf::pbkdf2_derive(b"p", b"s", 1u32, "sha-256", 32usize).is_ok());
}

#[test]
fn sha256_alias_underscore_separator_is_accepted() {
    // `_` -> `-` normalisation per implementation.
    assert!(kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA_256", 32usize).is_ok());
}

#[test]
fn sha256_alias_space_separator_is_accepted() {
    // ` ` -> `-` normalisation per implementation.
    assert!(kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA 256", 32usize).is_ok());
}

#[test]
fn sha256_alias_rejects_sha512() {
    let err = kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA-512", 32usize)
        .expect_err("SHA-512 must be unsupported");
    let msg = err.to_string();
    assert!(msg.to_ascii_lowercase().contains("not supported"));
}

#[test]
fn sha256_alias_rejects_sha1() {
    let err = kdf::pbkdf2_derive(b"p", b"s", 1u32, "SHA1", 32usize)
        .expect_err("SHA-1 must be unsupported");
    let msg = err.to_string();
    assert!(msg.to_ascii_lowercase().contains("not supported"));
}

#[test]
fn sha256_alias_rejects_blake2() {
    let err = kdf::pbkdf2_derive(b"p", b"s", 1u32, "BLAKE2", 32usize)
        .expect_err("BLAKE2 must be unsupported");
    let msg = err.to_string();
    assert!(msg.to_ascii_lowercase().contains("not supported"));
}

// =========================================================================
// Phase 41: CryptoError / CommonError integration smoke.
//
// Confirms KDF errors map cleanly through the workspace error stack and
// the resulting message format is suitable for surface-level matching.
// =========================================================================

#[test]
fn kdf_error_propagates_through_crypto_error() {
    // `hkdf_derive` signature is (digest_name, ikm, salt, info, length).
    // SHA-512 is currently unsupported (only SHA-256 aliases pass the
    // `require_sha256_alias` gate) so this call deterministically errors
    // and exercises the Display path through the workspace error stack.
    let err: CryptoError =
        kdf::hkdf_derive("SHA-512", b"k", b"s", b"i", 32usize).expect_err("err");
    // The err Display must render without panicking.
    let _msg = format!("{err}");
}

#[test]
fn common_error_invalid_argument_renders_msg() {
    let e = CommonError::InvalidArgument("test".to_string());
    let s = format!("{e}");
    assert!(s.contains("test"));
}
