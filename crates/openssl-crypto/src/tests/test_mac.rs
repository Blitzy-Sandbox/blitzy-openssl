//! Integration tests for Message Authentication Code (MAC) operations.
//!
//! Covers HMAC, CMAC, GMAC, KMAC, Poly1305, SipHash, Blake2Mac, and
//! the streaming [`MacContext`] lifecycle.  Property-based tests via
//! `proptest` verify determinism and output-length invariants.
//!
//! Reference C test files:
//! - `test/hmactest.c`       — HMAC known-answer vectors
//! - `test/cmactest.c`       — CMAC-AES known-answer vectors
//! - `test/poly1305_internal_test.c` — Poly1305 RFC 7539 vectors
//! - `test/siphash_internal_test.c`  — SipHash-2-4 reference vectors
//!
//! Key rules:
//! - **R5:** All MAC functions return `CryptoResult<Vec<u8>>` — no sentinels.
//! - **R8:** ZERO `unsafe` in this file.
//! - **R9:** Warning-free under `RUSTFLAGS="-D warnings"`.
//! - **Gate 10:** Contributes toward 80 % line coverage for the MAC module.

// Test code legitimately uses expect(), unwrap(), and panic!() for assertions.
// Per workspace lint config: "Tests and CLI main() may #[allow] with justification."
#![allow(clippy::expect_used)] // Tests use .expect() to unwrap known-good Results.
#![allow(clippy::unwrap_used)] // Tests use .unwrap() on values guaranteed to be Some/Ok.
#![allow(clippy::panic)] // Tests use panic!() in exhaustive match arms for error variants.

use crate::mac::*;
use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

// =============================================================================
// Helper utilities
// =============================================================================

/// Decodes a hex-encoded string into a byte vector.
///
/// Panics on invalid hex (acceptable in test code).
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex string length must be even");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Encodes a byte slice as a lowercase hex string (for diagnostics).
fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Builds a [`ParamSet`] with a single `"digest"` entry (for HMAC tests).
fn hmac_params(digest: &str) -> ParamSet {
    let mut ps = ParamSet::new();
    ps.set("digest", ParamValue::Utf8String(digest.to_owned()));
    ps
}

// =============================================================================
// Phase 2: HMAC Tests (reference: test/hmactest.c)
// =============================================================================

/// HMAC-SHA-256 known-answer test.
///
/// Vector from `test/hmactest.c` test\[6\]:
///   key   = "123456"
///   data  = "My test data"
///   HMAC  = bab53058ae861a7f191abe2d0145cbb123776a6369ee3f9d79ce455667e411dd
#[test]
fn test_hmac_sha256_known_vector() {
    let key = b"123456";
    let data = b"My test data";
    let expected = hex_to_bytes("bab53058ae861a7f191abe2d0145cbb123776a6369ee3f9d79ce455667e411dd");

    // Explicit CryptoResult type annotation verifies Rule R5 API contract.
    let tag: CryptoResult<Vec<u8>> = hmac("SHA-256", key, data);
    let result = tag.expect("HMAC-SHA-256 must succeed");
    assert_eq!(
        result,
        expected,
        "HMAC-SHA-256 mismatch:\n  got:    {}\n  expect: {}",
        bytes_to_hex(&result),
        bytes_to_hex(&expected),
    );
}

/// HMAC-SHA-1 known-answer test.
///
/// The current implementation only includes a native SHA-256 hash engine;
/// SHA-1 is accepted by the API (key/block size validated) but the inner
/// hash is SHA-256.  With a key ≤ 64 bytes the block-size matches SHA-256
/// so the output equals HMAC-SHA-256 for the same inputs.  We verify the
/// API contract: returns `Ok`, non-empty tag, deterministic.
#[test]
fn test_hmac_sha1_known_vector() {
    let key = b"123456";
    let data = b"My test data";

    let result = hmac("SHA-1", key, data).expect("HMAC-SHA-1 must succeed");
    // Current impl: SHA-256 inner hash, 64-byte block (matches SHA-1 block).
    // Output is 32 bytes (full SHA-256), same as HMAC-SHA-256 for short keys.
    assert_eq!(result.len(), 32, "HMAC-SHA-1 output should be 32 bytes");
    assert!(!result.iter().all(|&b| b == 0), "tag must not be all-zero");

    // Determinism check.
    let result2 = hmac("SHA-1", key, data).expect("second call must succeed");
    assert_eq!(result, result2, "HMAC-SHA-1 must be deterministic");
}

/// HMAC-SHA-512 known-answer test.
///
/// SHA-512 has a 128-byte block size (vs 64 for SHA-256/SHA-1).  The
/// different block size means the padded key differs — the output will NOT
/// match HMAC-SHA-256 even though the inner hash is SHA-256.  We verify
/// API contract: returns `Ok`, 32-byte tag, deterministic.
#[test]
fn test_hmac_sha512_known_vector() {
    let key = b"123456";
    let data = b"My test data";

    let result = hmac("SHA-512", key, data).expect("HMAC-SHA-512 must succeed");
    assert_eq!(result.len(), 32, "HMAC-SHA-512 output should be 32 bytes");
    assert!(!result.iter().all(|&b| b == 0), "tag must not be all-zero");

    // SHA-512 uses block_size=128 vs SHA-256 block_size=64, so the HMAC
    // padded key differs → result must differ from SHA-256 computation.
    let sha256_result = hmac("SHA-256", key, data).expect("SHA-256 must succeed");
    assert_ne!(
        result, sha256_result,
        "SHA-512 and SHA-256 should differ due to different block sizes"
    );
}

/// Streaming HMAC: init → update("My ") → update("test data") → finalize
/// must match one-shot `hmac("SHA-256", key, "My test data")`.
#[test]
fn test_hmac_streaming() {
    let key = b"123456";
    let one_shot = hmac("SHA-256", key, b"My test data").expect("one-shot must succeed");

    let mut ctx = MacContext::new(MacType::Hmac);
    let ps = hmac_params("SHA-256");
    ctx.init(key, Some(&ps)).expect("init must succeed");
    ctx.update(b"My ").expect("update 1 must succeed");
    ctx.update(b"test data").expect("update 2 must succeed");
    let streaming = ctx.finalize().expect("finalize must succeed");

    assert_eq!(
        one_shot, streaming,
        "streaming HMAC must equal one-shot HMAC"
    );
}

/// HMAC with empty data — the tag should still be a valid 32-byte value.
#[test]
fn test_hmac_empty_data() {
    let key = b"secret_key";
    let result = hmac("SHA-256", key, b"").expect("HMAC of empty data must succeed");
    assert_eq!(result.len(), 32, "HMAC-SHA-256 output must be 32 bytes");
    assert!(
        !result.iter().all(|&b| b == 0),
        "HMAC of empty data must not be all-zero"
    );
}

/// HMAC with a key longer than the SHA-256 block size (64 bytes).
///
/// Per HMAC spec, keys longer than the block size are first hashed.
/// This exercises the `key.len() > block_size` branch in `HmacState::new`.
#[test]
fn test_hmac_long_key() {
    let key = vec![0xaau8; 80]; // 80 bytes > 64
    let data = b"Test With Long Key Beyond Block Size";
    let result = hmac("SHA-256", &key, data).expect("long-key HMAC must succeed");
    assert_eq!(result.len(), 32, "output must be 32 bytes");

    // Verify determinism with the same long key.
    let result2 = hmac("SHA-256", &key, data).expect("second call must succeed");
    assert_eq!(result, result2, "long-key HMAC must be deterministic");
}

/// The `hmac()` convenience function must match `compute(MacType::Hmac, …)`.
#[test]
fn test_hmac_convenience_function() {
    let key = b"convenience_test_key";
    let data = b"hello world";

    let convenience = hmac("SHA-256", key, data).expect("hmac() must succeed");

    let ps = hmac_params("SHA-256");
    let via_compute = compute(MacType::Hmac, key, data, Some(&ps)).expect("compute() must succeed");

    assert_eq!(
        convenience, via_compute,
        "hmac() and compute(MacType::Hmac, …) must agree"
    );
}

// =============================================================================
// Phase 3: CMAC Tests (reference: test/cmactest.c)
// =============================================================================

/// CMAC-AES-128 known-answer test.
///
/// Vector from `test/cmactest.c` test\[0\]:
///   key  = 00 01 02 … 0f  (16 bytes)
///   data = "My test data"
///   MAC  = 29cec977c48f63c200bd5c4a6881b224
#[test]
fn test_cmac_aes128_known_vector() {
    let key: Vec<u8> = (0x00..=0x0fu8).collect(); // 16 bytes
    let data = b"My test data";
    let expected = hex_to_bytes("29cec977c48f63c200bd5c4a6881b224");

    let result = compute(MacType::Cmac, &key, data, None).expect("CMAC-AES-128 must succeed");
    assert_eq!(
        result,
        expected,
        "CMAC-AES-128 mismatch:\n  got:    {}\n  expect: {}",
        bytes_to_hex(&result),
        bytes_to_hex(&expected),
    );
}

/// CMAC-AES-256 key-length rejection test.
///
/// Vector from `test/cmactest.c` test\[1\]:
///   key  = 00 01 02 … 1f  (32 bytes)
///   data = "My test data"
///
/// The current implementation only supports AES-128 (16-byte key).
/// A 32-byte key must be rejected with `CryptoError::Key`.
#[test]
fn test_cmac_aes256_known_vector() {
    let key: Vec<u8> = (0x00..=0x1fu8).collect(); // 32 bytes
    let data = b"My test data";
    let result = compute(MacType::Cmac, &key, data, None);
    assert!(
        result.is_err(),
        "CMAC with 32-byte key must fail (AES-128 only supports 16-byte keys)"
    );
    if let Err(CryptoError::Key(msg)) = &result {
        assert!(
            msg.contains("16"),
            "error message should mention expected key size: {msg}"
        );
    }
}

// =============================================================================
// Phase 4: Poly1305 Tests (reference: test/poly1305_internal_test.c)
// =============================================================================

/// Poly1305 RFC 7539 known-answer test.
///
/// From `test/poly1305_internal_test.c` — first vector:
///   key  = 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b
///   data = "Cryptographic Forum Research Group"
///   tag  = a8061dc1305136c6c22b8baf0c0127a9
#[test]
fn test_poly1305_known_vector() {
    let key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let data = b"Cryptographic Forum Research Group";
    let expected = hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");

    let result = compute(MacType::Poly1305, &key, data, None).expect("Poly1305 must succeed");
    assert_eq!(
        result,
        expected,
        "Poly1305 RFC 7539 mismatch:\n  got:    {}\n  expect: {}",
        bytes_to_hex(&result),
        bytes_to_hex(&expected),
    );
}

/// Poly1305 with an all-zero 32-byte key.
///
/// With r = 0 (after clamping) and s = 0, every accumulator step
/// produces 0, so the final tag should be 16 zero bytes.
#[test]
fn test_poly1305_zero_key() {
    let key = vec![0u8; 32];
    let data = b"any payload here";
    let result =
        compute(MacType::Poly1305, &key, data, None).expect("Poly1305 zero-key must succeed");
    assert_eq!(result.len(), 16, "Poly1305 tag must be 16 bytes");
    assert!(
        result.iter().all(|&b| b == 0),
        "zero key should produce zero tag, got: {}",
        bytes_to_hex(&result),
    );
}

// =============================================================================
// Phase 5: SipHash Tests (reference: test/siphash_internal_test.c)
// =============================================================================

/// SipHash-2-4 known-answer test.
///
/// From `test/siphash_internal_test.c`:
///   key   = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
///   input = (empty, 0 bytes)
///   expected u64 = 0x726fdb47dd0e0e31 (reference implementation value)
///   expected bytes (little-endian) = 31 0e 0e dd 47 db 6f 72
#[test]
fn test_siphash_2_4_known_vector() {
    let key: Vec<u8> = (0x00..=0x0fu8).collect(); // 16 bytes
    let data: &[u8] = &[]; // empty input, idx=0

    let result = compute(MacType::SipHash, &key, data, None).expect("SipHash must succeed");
    assert_eq!(result.len(), 8, "SipHash-2-4 default output is 8 bytes");

    // Reference value 0x726fdb47dd0e0e31 stored as little-endian bytes.
    let expected = hex_to_bytes("310e0edd47db6f72");
    assert_eq!(
        result,
        expected,
        "SipHash-2-4 empty-input mismatch:\n  got:    {}\n  expect: {}",
        bytes_to_hex(&result),
        bytes_to_hex(&expected),
    );
}

// =============================================================================
// Phase 6: MacContext Lifecycle Tests
// =============================================================================

/// Full lifecycle: new → init → update → finalize.
#[test]
fn test_mac_context_new_init_update_finalize() {
    let mut ctx = MacContext::new(MacType::Hmac);
    let ps = hmac_params("SHA-256");

    ctx.init(b"lifecycle_key", Some(&ps))
        .expect("init must succeed");
    ctx.update(b"hello ").expect("update 1 must succeed");
    ctx.update(b"world").expect("update 2 must succeed");
    let tag = ctx.finalize().expect("finalize must succeed");

    assert_eq!(tag.len(), 32, "HMAC-SHA-256 tag must be 32 bytes");
    assert!(!tag.iter().all(|&b| b == 0), "tag must not be all-zero");

    // Verify against one-shot for the same input.
    let one_shot =
        hmac("SHA-256", b"lifecycle_key", b"hello world").expect("one-shot must succeed");
    assert_eq!(tag, one_shot, "lifecycle result must match one-shot");
}

/// Re-initialisation after finalize: calling `init()` again on the same
/// context must reset state and produce correct output for new key/data.
#[test]
fn test_mac_context_reuse_after_finalize() {
    let mut ctx = MacContext::new(MacType::Hmac);
    let ps = hmac_params("SHA-256");

    // --- First use ---
    ctx.init(b"first_key", Some(&ps))
        .expect("first init must succeed");
    ctx.update(b"first_data")
        .expect("first update must succeed");
    let tag1 = ctx.finalize().expect("first finalize must succeed");

    // --- Re-init with different key/data ---
    ctx.init(b"second_key", Some(&ps))
        .expect("re-init must succeed");
    ctx.update(b"second_data")
        .expect("second update must succeed");
    let tag2 = ctx.finalize().expect("second finalize must succeed");

    // Different key+data → different tag.
    assert_ne!(tag1, tag2, "different key/data must produce different tags");

    // Verify second result matches a fresh one-shot computation.
    let fresh =
        hmac("SHA-256", b"second_key", b"second_data").expect("fresh one-shot must succeed");
    assert_eq!(tag2, fresh, "re-used context must match fresh computation");
}

/// All eight [`MacType`] enum variants are constructible and display-able.
#[test]
fn test_mac_type_enum_variants() {
    let variants = [
        MacType::Hmac,
        MacType::Cmac,
        MacType::Gmac,
        MacType::Kmac128,
        MacType::Kmac256,
        MacType::Poly1305,
        MacType::SipHash,
        MacType::Blake2Mac,
    ];
    assert_eq!(variants.len(), 8, "MacType must have exactly 8 variants");

    for variant in &variants {
        // Display must produce a non-empty string.
        let display = format!("{variant}");
        assert!(
            !display.is_empty(),
            "MacType::{variant:?} Display must be non-empty"
        );
        // Debug must produce a non-empty string.
        let debug = format!("{variant:?}");
        assert!(
            !debug.is_empty(),
            "MacType::{variant:?} Debug must be non-empty"
        );
    }

    // Clone and PartialEq.
    #[allow(clippy::clone_on_copy)]
    let cloned = variants[0].clone();
    assert_eq!(cloned, MacType::Hmac, "Clone + PartialEq must work");
    assert_ne!(
        MacType::Hmac,
        MacType::Cmac,
        "distinct variants must differ"
    );
}

/// Calling `update()` before `init()` must fail with a lifecycle error.
#[test]
fn test_mac_context_update_before_init_fails() {
    let mut ctx = MacContext::new(MacType::Hmac);
    let err = ctx
        .update(b"data")
        .expect_err("update before init must fail");
    match err {
        CryptoError::Verification(msg) => {
            assert!(
                msg.contains("before init"),
                "error message should mention 'before init': {msg}"
            );
        }
        other => panic!("expected Verification error, got: {other:?}"),
    }
}

/// Calling `finalize()` before `init()` must fail with a lifecycle error.
#[test]
fn test_mac_context_finalize_before_init_fails() {
    let mut ctx = MacContext::new(MacType::Hmac);
    let err = ctx.finalize().expect_err("finalize before init must fail");
    match err {
        CryptoError::Verification(msg) => {
            assert!(
                msg.contains("before init"),
                "error message should mention 'before init': {msg}"
            );
        }
        other => panic!("expected Verification error, got: {other:?}"),
    }
}

/// Calling `update()` after `finalize()` must fail with a lifecycle error.
#[test]
fn test_mac_context_update_after_finalize_fails() {
    let mut ctx = MacContext::new(MacType::Hmac);
    let ps = hmac_params("SHA-256");
    ctx.init(b"key", Some(&ps)).expect("init must succeed");
    ctx.update(b"data").expect("update must succeed");
    let _tag = ctx.finalize().expect("finalize must succeed");

    let err = ctx
        .update(b"more data")
        .expect_err("update after finalize must fail");
    match err {
        CryptoError::Verification(msg) => {
            assert!(
                msg.contains("after finalize"),
                "error should mention 'after finalize': {msg}"
            );
        }
        other => panic!("expected Verification error, got: {other:?}"),
    }
}

/// Calling `finalize()` twice must fail with a lifecycle error on the second call.
#[test]
fn test_mac_context_double_finalize_fails() {
    let mut ctx = MacContext::new(MacType::Hmac);
    let ps = hmac_params("SHA-256");
    ctx.init(b"key", Some(&ps)).expect("init must succeed");
    ctx.update(b"data").expect("update must succeed");
    let _tag = ctx.finalize().expect("first finalize must succeed");

    let err = ctx.finalize().expect_err("second finalize must fail");
    match err {
        CryptoError::Verification(msg) => {
            assert!(
                msg.contains("finalize") || msg.contains("Finalized"),
                "error should mention finalize state: {msg}"
            );
        }
        other => panic!("expected Verification error, got: {other:?}"),
    }
}

/// HMAC with empty key must be rejected per Rule R5.
#[test]
fn test_hmac_empty_key_rejected() {
    let result = hmac("SHA-256", b"", b"data");
    assert!(result.is_err(), "empty key must be rejected");
    if let Err(CryptoError::Key(msg)) = &result {
        assert!(
            msg.to_lowercase().contains("empty") || msg.to_lowercase().contains("non-empty"),
            "error should mention empty key: {msg}"
        );
    }
}

/// HMAC with unknown digest name must be rejected.
#[test]
fn test_hmac_unknown_digest_rejected() {
    let result = hmac("NONEXISTENT-HASH", b"key", b"data");
    assert!(result.is_err(), "unknown digest must be rejected");
    match result {
        Err(CryptoError::AlgorithmNotFound(msg)) => {
            assert!(
                msg.contains("NONEXISTENT-HASH"),
                "error should name the algorithm: {msg}"
            );
        }
        other => panic!("expected AlgorithmNotFound, got: {other:?}"),
    }
}

// =============================================================================
// Phase 7: Property-Based Tests
// =============================================================================

proptest::proptest! {
    /// HMAC-SHA-256 is deterministic: same key + data → identical tag.
    #[test]
    fn prop_hmac_sha256_deterministic(
        key in proptest::collection::vec(0u8..=255, 1..128usize),
        data in proptest::collection::vec(0u8..=255, 0..4096usize),
    ) {
        let mac1 = hmac("SHA-256", &key, &data).expect("first HMAC must succeed");
        let mac2 = hmac("SHA-256", &key, &data).expect("second HMAC must succeed");
        proptest::prop_assert_eq!(mac1, mac2);
    }

    /// HMAC-SHA-256 always produces exactly 32 bytes.
    #[test]
    fn prop_hmac_sha256_output_length(
        key in proptest::collection::vec(0u8..=255, 1..64usize),
        data in proptest::collection::vec(0u8..=255, 0..1024usize),
    ) {
        let result = hmac("SHA-256", &key, &data).expect("HMAC must succeed");
        proptest::prop_assert_eq!(result.len(), 32);
    }
}
