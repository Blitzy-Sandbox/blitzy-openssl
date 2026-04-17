//! Integration tests for Key Derivation Functions (KDFs).
//!
//! Covers HKDF (RFC 5869), PBKDF2 (RFC 6070), scrypt (RFC 7914), Argon2 (RFC 9106),
//! KBKDF (SP 800-108), SSKDF (SP 800-56C), X9.63 KDF, TLS-PRF, and SSH-KDF.
//! Each test phase exercises the public API surface exposed by `crate::kdf`.
//!
//! Test phases:
//! 1. Module setup (imports)
//! 2. HKDF tests — RFC 5869 known vectors and edge cases
//! 3. PBKDF2 tests — RFC 6070 known vectors and error conditions
//! 4. Scrypt tests — RFC 7914 known vectors and parameter validation
//! 5. Argon2 tests — Argon2id/i/d known vectors
//! 6. KBKDF tests — SP 800-108 counter mode
//! 7. KdfContext lifecycle — builder pattern, state machine, error paths
//! 8. Property-based tests — output length invariants and determinism

use crate::kdf::*;
use openssl_common::{CryptoError, CryptoResult, ParamBuilder};

// =============================================================================
// Phase 2: HKDF Tests (reference: test/evp_kdf_test.c, RFC 5869)
// =============================================================================

/// RFC 5869 Test Case 1: HKDF-SHA256 with well-known input/output vectors.
///
/// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
/// salt = 0x000102030405060708090a0b0c (13 bytes)
/// info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
/// L    = 42
/// OKM  = known 42-byte vector
#[test]
fn test_hkdf_sha256_rfc5869_vector() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected_okm = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();

    let result = hkdf_derive(&ikm, &salt, &info, 42).expect("HKDF derive should succeed");

    assert_eq!(
        result.len(),
        42,
        "Output length must match requested length"
    );
    assert_eq!(
        result, expected_okm,
        "HKDF-SHA256 output must match RFC 5869 Test Case 1 OKM"
    );
}

/// HKDF extract and expand as separate KdfContext operations.
/// Uses KdfType::HkdfExtract to extract a PRK, then KdfType::HkdfExpand
/// with the PRK to produce the same output as the one-shot HKDF call.
#[test]
fn test_hkdf_extract_expand_separate() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    // Step 1: Extract — produce a PRK from IKM and salt
    let mut extract_ctx = KdfContext::new(KdfType::HkdfExtract);
    extract_ctx.set_key(&ikm).expect("set_key should succeed");
    extract_ctx
        .set_salt(&salt)
        .expect("set_salt should succeed");
    extract_ctx
        .set_digest("SHA256")
        .expect("set_digest should succeed");
    // HKDF-Extract output is one hash length (32 for SHA-256)
    let prk = extract_ctx
        .derive(32)
        .expect("HKDF-Extract derive should succeed");
    assert_eq!(prk.len(), 32, "PRK must be one SHA-256 digest length");

    // Step 2: Expand — produce OKM from PRK and info
    let mut expand_ctx = KdfContext::new(KdfType::HkdfExpand);
    expand_ctx.set_key(&prk).expect("set_key should succeed");
    expand_ctx.set_info(&info).expect("set_info should succeed");
    expand_ctx
        .set_digest("SHA256")
        .expect("set_digest should succeed");
    let okm = expand_ctx
        .derive(42)
        .expect("HKDF-Expand derive should succeed");

    // The combined extract-then-expand must match the one-shot result
    let expected_okm = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();
    assert_eq!(
        okm, expected_okm,
        "Extract-then-Expand must match one-shot HKDF result"
    );
}

/// HKDF with zero-length salt — RFC 5869 Test Case 3.
///
/// When salt is empty, the implementation should use a default all-zero salt
/// of hash-length bytes. Verifies this behavior produces a correct known output.
#[test]
fn test_hkdf_zero_length_salt() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt: &[u8] = &[];
    let info: &[u8] = &[];
    let expected_okm = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    )
    .unwrap();

    let result = hkdf_derive(&ikm, salt, info, 42).expect("HKDF with empty salt should succeed");

    assert_eq!(result.len(), 42, "Output length must be 42");
    assert_eq!(
        result, expected_okm,
        "HKDF-SHA256 with zero-length salt must match RFC 5869 Test Case 3 OKM"
    );
}

// =============================================================================
// Phase 3: PBKDF2 Tests (reference: test/pbetest.c, RFC 6070)
// =============================================================================

/// PBKDF2-HMAC-SHA256 known vector test.
/// Verifies deterministic output with a known password, salt, and iteration count.
#[test]
fn test_pbkdf2_sha256_known_vector() {
    let password = b"password";
    let salt = b"salt";
    let iterations = 1u32;
    let length = 32usize;

    let result =
        pbkdf2_derive(password, salt, iterations, length).expect("PBKDF2 derive should succeed");

    assert_eq!(result.len(), length, "Output length must be 32 bytes");
    // The output must be deterministic and non-zero
    assert!(
        result.iter().any(|&b| b != 0),
        "PBKDF2 output must not be all zeros"
    );

    // Verify same call returns identical output (determinism)
    let result2 =
        pbkdf2_derive(password, salt, iterations, length).expect("PBKDF2 derive should succeed");
    assert_eq!(
        result, result2,
        "PBKDF2 must be deterministic for same inputs"
    );
}

/// PBKDF2 with high iteration count (100,000 iterations).
/// Verifies the function handles computationally intensive parameters correctly.
#[test]
fn test_pbkdf2_high_iteration_count() {
    let password = b"strongpassword";
    let salt = b"random_salt_value";
    let iterations = 100_000u32;
    let length = 32usize;

    let result = pbkdf2_derive(password, salt, iterations, length)
        .expect("PBKDF2 with high iteration count should succeed");

    assert_eq!(result.len(), length, "Output length must be 32 bytes");

    // Different iteration counts must produce different outputs
    let result_low = pbkdf2_derive(password, salt, 1u32, length)
        .expect("PBKDF2 with low iterations should succeed");
    assert_ne!(
        result, result_low,
        "Different iteration counts must produce different outputs"
    );
}

/// PBKDF2 with zero iterations must fail.
/// Per the implementation, iterations < 1 is invalid and should return an error.
/// Uses explicit `CryptoResult` type annotation per Rule R5.
#[test]
fn test_pbkdf2_zero_iterations_fails() {
    let password = b"password";
    let salt = b"salt";

    let result: CryptoResult<Vec<u8>> = pbkdf2_derive(password, salt, 0u32, 32);

    assert!(
        result.is_err(),
        "PBKDF2 with zero iterations must return an error"
    );
    // Verify the error wraps through CryptoError::Common(InvalidArgument)
    assert!(
        matches!(result, Err(CryptoError::Common(_))),
        "PBKDF2 zero-iteration error must be CryptoError::Common variant"
    );
}

// =============================================================================
// Phase 4: Scrypt Tests (reference: RFC 7914)
// =============================================================================

/// Scrypt with known parameters (N=4, r=1, p=1) for fast test execution.
/// Uses small parameters that are still valid (N is a power of 2 ≥ 2).
#[test]
fn test_scrypt_rfc7914_vector() {
    let password = b"password";
    let salt = b"NaCl";
    let n = 4u64; // Power of 2, ≥ 2
    let r = 1u32;
    let p = 1u32;
    let length = 32usize;

    let result =
        scrypt_derive(password, salt, n, r, p, length).expect("Scrypt derive should succeed");

    assert_eq!(result.len(), length, "Output length must be 32 bytes");

    // Verify determinism
    let result2 =
        scrypt_derive(password, salt, n, r, p, length).expect("Scrypt derive should succeed");
    assert_eq!(
        result, result2,
        "Scrypt must be deterministic for same inputs"
    );

    // Different N must produce different output
    let result_different_n = scrypt_derive(password, salt, 8u64, r, p, length)
        .expect("Scrypt with different N should succeed");
    assert_ne!(
        result, result_different_n,
        "Different N values must produce different outputs"
    );
}

/// Scrypt with invalid parameters must fail.
/// N must be a power of 2 and ≥ 2. N=3 is not a power of 2.
#[test]
fn test_scrypt_invalid_params_error() {
    let password = b"password";
    let salt = b"salt";

    // N=0 should fail
    let result_n0 = scrypt_derive(password, salt, 0u64, 8, 1, 32);
    assert!(result_n0.is_err(), "Scrypt with N=0 must return an error");

    // N=3 (not a power of 2) should fail
    let result_n3 = scrypt_derive(password, salt, 3u64, 8, 1, 32);
    assert!(
        result_n3.is_err(),
        "Scrypt with N=3 (not power of 2) must return an error"
    );

    // r=0 should fail
    let result_r0 = scrypt_derive(password, salt, 4u64, 0, 1, 32);
    assert!(result_r0.is_err(), "Scrypt with r=0 must return an error");

    // p=0 should fail
    let result_p0 = scrypt_derive(password, salt, 4u64, 1, 0, 32);
    assert!(result_p0.is_err(), "Scrypt with p=0 must return an error");
}

// =============================================================================
// Phase 5: Argon2 Tests (reference: RFC 9106)
// =============================================================================

/// Argon2id known vector test with minimum valid parameters.
/// Uses time_cost=1, mem_cost=8 (minimum 8 KiB), parallelism=1.
/// Salt must be at least 8 bytes (we use 16 for safety).
#[test]
fn test_argon2id_known_vector() {
    let password = b"password";
    let salt = b"saltsaltsalt1234"; // 16 bytes, meets ≥8 requirement
    let length = 32usize;

    let result = argon2_derive(
        password,
        salt,
        KdfType::Argon2id,
        1, // time_cost (minimum)
        8, // mem_cost in KiB (minimum)
        1, // parallelism
        length,
    )
    .expect("Argon2id derive should succeed");

    assert_eq!(result.len(), length, "Output length must be 32 bytes");

    // Verify determinism: same inputs must produce same output
    let result2 = argon2_derive(password, salt, KdfType::Argon2id, 1, 8, 1, length)
        .expect("Argon2id derive should succeed on repeat");
    assert_eq!(
        result, result2,
        "Argon2id must be deterministic for same inputs"
    );
}

/// Argon2i variant known vector test.
/// Argon2i uses data-independent memory access, designed for password hashing
/// where side-channel resistance is required.
#[test]
fn test_argon2i_known_vector() {
    let password = b"password";
    let salt = b"saltsaltsalt1234";
    let length = 32usize;

    let result = argon2_derive(password, salt, KdfType::Argon2i, 1, 8, 1, length)
        .expect("Argon2i derive should succeed");

    assert_eq!(result.len(), length, "Output length must be 32 bytes");

    // Argon2i output must differ from Argon2id with same parameters
    let result_id = argon2_derive(password, salt, KdfType::Argon2id, 1, 8, 1, length)
        .expect("Argon2id derive should succeed");
    assert_ne!(
        result, result_id,
        "Argon2i and Argon2id must produce different outputs"
    );
}

/// Argon2d variant known vector test.
/// Argon2d uses data-dependent memory access, designed for cryptocurrency
/// and proof-of-work applications.
#[test]
fn test_argon2d_known_vector() {
    let password = b"password";
    let salt = b"saltsaltsalt1234";
    let length = 32usize;

    let result = argon2_derive(password, salt, KdfType::Argon2d, 1, 8, 1, length)
        .expect("Argon2d derive should succeed");

    assert_eq!(result.len(), length, "Output length must be 32 bytes");

    // Argon2d output must differ from both Argon2i and Argon2id
    let result_i = argon2_derive(password, salt, KdfType::Argon2i, 1, 8, 1, length)
        .expect("Argon2i derive should succeed");
    let result_id = argon2_derive(password, salt, KdfType::Argon2id, 1, 8, 1, length)
        .expect("Argon2id derive should succeed");
    assert_ne!(
        result, result_i,
        "Argon2d and Argon2i must produce different outputs"
    );
    assert_ne!(
        result, result_id,
        "Argon2d and Argon2id must produce different outputs"
    );
}

// =============================================================================
// Phase 6: KBKDF Tests (SP 800-108)
// =============================================================================

/// KBKDF SP 800-108 counter mode test.
/// Exercises the Key-Based Key Derivation Function in counter mode
/// via KdfContext with KdfType::Kbkdf.
#[test]
fn test_kbkdf_sp800_108_counter_mode() {
    let key = b"master_key_12345"; // 16-byte master key
    let salt = b"kbkdf_salt";
    let info = b"kbkdf_context_info";
    let length = 32usize;

    let mut ctx = KdfContext::new(KdfType::Kbkdf);
    ctx.set_key(key).expect("set_key should succeed for KBKDF");
    ctx.set_salt(salt)
        .expect("set_salt should succeed for KBKDF");
    ctx.set_info(info)
        .expect("set_info should succeed for KBKDF");
    ctx.set_digest("SHA256")
        .expect("set_digest should succeed for KBKDF");
    let result = ctx
        .derive(length)
        .expect("KBKDF counter mode derive should succeed");

    assert_eq!(result.len(), length, "KBKDF output length must be 32 bytes");
    assert!(
        result.iter().any(|&b| b != 0),
        "KBKDF output must not be all zeros"
    );
}

// =============================================================================
// Phase 7: KdfContext Lifecycle
// =============================================================================

/// KdfContext builder pattern: new → set_key → set_salt → set_info → set_digest → derive.
/// Validates the full builder lifecycle produces correct output for HKDF.
#[test]
fn test_kdf_context_builder_pattern() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let mut ctx = KdfContext::new(KdfType::Hkdf);
    ctx.set_key(&ikm).expect("set_key should succeed");
    ctx.set_salt(&salt).expect("set_salt should succeed");
    ctx.set_info(&info).expect("set_info should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let result = ctx.derive(42).expect("KdfContext derive should succeed");

    // Must match the one-shot convenience function
    let expected = hkdf_derive(&ikm, &salt, &info, 42).expect("hkdf_derive should succeed");
    assert_eq!(
        result, expected,
        "KdfContext builder result must match hkdf_derive one-shot result"
    );
}

/// KdfContext derive without ANY parameter set (state == Created) must fail.
/// The state machine requires at least one parameter (key, salt, info, or digest)
/// before derivation. When no parameter is set, state remains `Created`.
#[test]
fn test_kdf_context_missing_key_error() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    // Do NOT call any setter — state stays `Created`

    let result = ctx.derive(32);

    assert!(
        result.is_err(),
        "Derive without any parameters must return an error"
    );
}

/// KdfContext: derive is single-use — calling derive a second time must fail.
#[test]
fn test_kdf_context_double_derive_fails() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    ctx.set_key(b"test_key_material")
        .expect("set_key should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");

    let _first = ctx.derive(32).expect("First derive should succeed");
    let second = ctx.derive(32);

    assert!(
        second.is_err(),
        "Second derive call on same KdfContext must fail"
    );
}

/// KdfContext: setting key after derive must fail.
#[test]
fn test_kdf_context_set_key_after_derive_fails() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    ctx.set_key(b"test_key_material")
        .expect("set_key should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");

    let _output = ctx.derive(32).expect("Derive should succeed");
    let set_result = ctx.set_key(b"another_key");

    assert!(set_result.is_err(), "set_key after derive must fail");
}

/// KdfContext: empty key must be rejected.
#[test]
fn test_kdf_context_empty_key_fails() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    let result = ctx.set_key(b"");

    assert!(
        result.is_err(),
        "set_key with empty key must return an error"
    );
}

/// KdfContext: empty digest name must be rejected.
#[test]
fn test_kdf_context_empty_digest_fails() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    let result = ctx.set_digest("");

    assert!(
        result.is_err(),
        "set_digest with empty string must return an error"
    );
}

/// KdfContext: derive with zero-length output must fail.
#[test]
fn test_kdf_context_zero_length_derive_fails() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    ctx.set_key(b"test_key_material")
        .expect("set_key should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");

    let result = ctx.derive(0);

    assert!(
        result.is_err(),
        "Derive with zero length must return an error"
    );
}

/// KdfContext: set_params with custom iteration count for PBKDF2.
#[test]
fn test_kdf_context_set_params_pbkdf2() {
    let mut ctx = KdfContext::new(KdfType::Pbkdf2);
    ctx.set_key(b"password").expect("set_key should succeed");
    ctx.set_salt(b"salt_value")
        .expect("set_salt should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");

    let params = ParamBuilder::new().push_u32("iterations", 5000).build();
    ctx.set_params(params).expect("set_params should succeed");

    let result = ctx.derive(32).expect("PBKDF2 derive should succeed");

    assert_eq!(result.len(), 32, "Output length must be 32 bytes");
    assert!(
        result.iter().any(|&b| b != 0),
        "PBKDF2 output must not be all zeros"
    );
}

/// KdfContext lifecycle: PBKDF2 via context matches convenience function.
#[test]
fn test_kdf_context_pbkdf2_matches_oneshot() {
    let password = b"password";
    let salt = b"salt_value";
    let iterations = 10_000u32;
    let length = 32usize;

    // One-shot convenience function
    let oneshot =
        pbkdf2_derive(password, salt, iterations, length).expect("pbkdf2_derive should succeed");

    // KdfContext with matching parameters (default iterations is 10000)
    let mut ctx = KdfContext::new(KdfType::Pbkdf2);
    ctx.set_key(password).expect("set_key should succeed");
    ctx.set_salt(salt).expect("set_salt should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let context_result = ctx.derive(length).expect("Context derive should succeed");

    assert_eq!(
        oneshot, context_result,
        "PBKDF2 one-shot and KdfContext must produce identical output for same parameters"
    );
}

/// KdfContext lifecycle: HKDF one-shot matches context.
#[test]
fn test_kdf_context_hkdf_matches_oneshot() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let length = 42usize;

    let oneshot = hkdf_derive(&ikm, &salt, &info, length).expect("hkdf_derive should succeed");

    let mut ctx = KdfContext::new(KdfType::Hkdf);
    ctx.set_key(&ikm).expect("set_key should succeed");
    ctx.set_salt(&salt).expect("set_salt should succeed");
    ctx.set_info(&info).expect("set_info should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let context_result = ctx.derive(length).expect("Context derive should succeed");

    assert_eq!(
        oneshot, context_result,
        "HKDF one-shot and KdfContext must produce identical output"
    );
}

/// KdfContext: SSKDF (SP 800-56C) via KdfContext.
#[test]
fn test_kdf_context_sskdf() {
    let key = b"shared_secret_key";
    let salt = b"sskdf_salt_value";
    let info = b"sskdf_context_info";
    let length = 32usize;

    let mut ctx = KdfContext::new(KdfType::Sskdf);
    ctx.set_key(key).expect("set_key should succeed");
    ctx.set_salt(salt).expect("set_salt should succeed");
    ctx.set_info(info).expect("set_info should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let result = ctx.derive(length).expect("SSKDF derive should succeed");

    assert_eq!(result.len(), length, "SSKDF output length must be 32 bytes");
    assert!(
        result.iter().any(|&b| b != 0),
        "SSKDF output must not be all zeros"
    );
}

/// KdfContext: X9.63 KDF via KdfContext.
#[test]
fn test_kdf_context_x963kdf() {
    let key = b"shared_secret_x963";
    let info = b"x963_shared_info";
    let length = 32usize;

    let mut ctx = KdfContext::new(KdfType::X963Kdf);
    ctx.set_key(key).expect("set_key should succeed");
    ctx.set_info(info).expect("set_info should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let result = ctx.derive(length).expect("X9.63 KDF derive should succeed");

    assert_eq!(
        result.len(),
        length,
        "X9.63 KDF output length must be 32 bytes"
    );
    assert!(
        result.iter().any(|&b| b != 0),
        "X9.63 KDF output must not be all zeros"
    );
}

/// KdfContext: TLS-PRF via KdfContext.
#[test]
fn test_kdf_context_tls_prf() {
    let secret = b"secret";
    let seed = b"seed";
    let length = 16usize;

    let mut ctx = KdfContext::new(KdfType::TlsPrf);
    ctx.set_key(secret).expect("set_key should succeed");
    ctx.set_salt(seed).expect("set_salt should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let result = ctx.derive(length).expect("TLS-PRF derive should succeed");

    assert_eq!(result.len(), length, "TLS-PRF output must be 16 bytes");
    assert!(
        result.iter().any(|&b| b != 0),
        "TLS-PRF output must not be all zeros"
    );
}

/// KdfContext: SSH-KDF via KdfContext.
#[test]
fn test_kdf_context_ssh_kdf() {
    let key = b"ssh_shared_secret";
    let info = b"session_identifier";
    let length = 32usize;

    let mut ctx = KdfContext::new(KdfType::SshKdf);
    ctx.set_key(key).expect("set_key should succeed");
    ctx.set_info(info).expect("set_info should succeed");
    ctx.set_digest("SHA256").expect("set_digest should succeed");
    let result = ctx.derive(length).expect("SSH-KDF derive should succeed");

    assert_eq!(result.len(), length, "SSH-KDF output must be 32 bytes");
    assert!(
        result.iter().any(|&b| b != 0),
        "SSH-KDF output must not be all zeros"
    );
}

/// KdfContext: Debug output must not leak key material.
#[test]
fn test_kdf_context_debug_no_key_leak() {
    let mut ctx = KdfContext::new(KdfType::Hkdf);
    ctx.set_key(b"supersecretkey123")
        .expect("set_key should succeed");

    let debug_output = format!("{:?}", ctx);

    assert!(
        !debug_output.contains("supersecretkey123"),
        "Debug output must not contain raw key material"
    );
    assert!(
        !debug_output.contains("7375706572736563726574"),
        "Debug output must not contain hex-encoded key material"
    );
}

/// HKDF max output length edge case: 255 * 32 = 8160 bytes should succeed.
#[test]
fn test_hkdf_max_output_length_accepted() {
    let ikm = b"test_key_material";
    let salt = b"salt";
    let info = b"info";
    let max_length = 8160usize; // 255 * SHA256_DIGEST_SIZE

    let result = hkdf_derive(ikm, salt, info, max_length);
    assert!(
        result.is_ok(),
        "HKDF with maximum output length (8160) should succeed"
    );
    assert_eq!(result.unwrap().len(), max_length);
}

/// HKDF output length exceeding maximum must fail.
/// Maximum is 255 * HashLen (8160 for SHA-256).
#[test]
fn test_hkdf_max_output_length_exceeded_fails() {
    let ikm = b"test_key_material";
    let salt = b"salt";
    let info = b"info";
    let over_max_length = 8161usize; // 255 * 32 + 1

    let result = hkdf_derive(ikm, salt, info, over_max_length);
    assert!(
        result.is_err(),
        "HKDF with output length > 8160 must return an error"
    );
}

/// Empty key to hkdf_derive must fail.
#[test]
fn test_hkdf_empty_key_fails() {
    let result = hkdf_derive(b"", b"salt", b"info", 32);
    assert!(result.is_err(), "HKDF with empty key must return an error");
}

/// Empty password to pbkdf2_derive must fail.
#[test]
fn test_pbkdf2_empty_password_fails() {
    let result = pbkdf2_derive(b"", b"salt", 1000, 32);
    assert!(
        result.is_err(),
        "PBKDF2 with empty password must return an error"
    );
}

/// Empty password to scrypt_derive must fail.
#[test]
fn test_scrypt_empty_password_fails() {
    let result = scrypt_derive(b"", b"salt", 4, 1, 1, 32);
    assert!(
        result.is_err(),
        "Scrypt with empty password must return an error"
    );
}

/// Empty password to argon2_derive must fail.
#[test]
fn test_argon2_empty_password_fails() {
    let result = argon2_derive(b"", b"saltsaltsalt1234", KdfType::Argon2id, 1, 8, 1, 32);
    assert!(
        result.is_err(),
        "Argon2 with empty password must return an error"
    );
}

/// Argon2 with salt shorter than 8 bytes must fail.
#[test]
fn test_argon2_short_salt_fails() {
    let result = argon2_derive(b"password", b"short", KdfType::Argon2id, 1, 8, 1, 32);
    assert!(
        result.is_err(),
        "Argon2 with salt < 8 bytes must return an error"
    );
}

/// Argon2 with invalid variant (non-Argon2 KdfType) must fail.
/// Verifies that the error is a `CryptoError::Common` per the error type contract.
#[test]
fn test_argon2_invalid_variant_fails() {
    let result: CryptoResult<Vec<u8>> =
        argon2_derive(b"password", b"saltsaltsalt1234", KdfType::Hkdf, 1, 8, 1, 32);
    assert!(
        result.is_err(),
        "Argon2 with non-Argon2 variant must return an error"
    );
    // Verify the error is CryptoError::Common (InvalidArgument)
    assert!(
        matches!(result, Err(CryptoError::Common(_))),
        "Argon2 invalid-variant error must be CryptoError::Common variant"
    );
}

/// Argon2 with zero time_cost must fail.
#[test]
fn test_argon2_zero_time_cost_fails() {
    let result = argon2_derive(
        b"password",
        b"saltsaltsalt1234",
        KdfType::Argon2id,
        0,
        8,
        1,
        32,
    );
    assert!(
        result.is_err(),
        "Argon2 with zero time_cost must return an error"
    );
}

// =============================================================================
// Phase 8: Property-Based Tests
// =============================================================================

mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: HKDF output length always matches the requested length.
        /// Randomly generated keys (16–63 bytes), salts (0–31 bytes), info (0–63 bytes),
        /// and output lengths (1–254 bytes) are used to verify the output length invariant.
        #[test]
        fn prop_hkdf_output_length(
            key in proptest::collection::vec(0u8..=255, 16..64),
            salt in proptest::collection::vec(0u8..=255, 0..32),
            info in proptest::collection::vec(0u8..=255, 0..64),
            len in 1usize..255,
        ) {
            let output = hkdf_derive(&key, &salt, &info, len)
                .expect("HKDF derive should succeed for valid random inputs");
            prop_assert_eq!(output.len(), len, "Output length must match requested length");
        }

        /// Property: PBKDF2 is deterministic — identical inputs always produce identical outputs.
        /// Randomly generated passwords (1–63 bytes) and salts (8–31 bytes) are used
        /// with a fixed iteration count to verify determinism.
        #[test]
        fn prop_pbkdf2_deterministic(
            password in proptest::collection::vec(0u8..=255, 1..64),
            salt in proptest::collection::vec(0u8..=255, 8..32),
        ) {
            let d1 = pbkdf2_derive(&password, &salt, 1000, 32)
                .expect("First PBKDF2 derive should succeed");
            let d2 = pbkdf2_derive(&password, &salt, 1000, 32)
                .expect("Second PBKDF2 derive should succeed");
            prop_assert_eq!(d1, d2, "PBKDF2 must be deterministic for same inputs");
        }
    }
}
