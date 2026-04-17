//! Integration tests for PEM encoding/decoding with snapshot testing.
//!
//! Covers the full public API surface of `crate::pem`:
//! - Phase 2: Encoding — DER → PEM conversion for certificate, RSA key, public key, CSR
//! - Phase 3: Snapshot — exact PEM format verification via `insta`
//! - Phase 4: Decoding — PEM → `PemObject` parsing with error cases
//! - Phase 5: Roundtrip — encode → decode correctness
//! - Phase 6: Encrypted PEM — passphrase-based decryption
//! - Phase 7: Property-based — randomized roundtrip via `proptest`
//!
//! Key Rules enforced:
//! - R5: `decode()` returns `CryptoResult`, not NULL/sentinel
//! - R8: Zero unsafe — base64ct is constant-time
//! - Gate 10: ≥80% line coverage target for PEM module

// RATIONALE: Test assertions use unwrap/expect/panic — panic on test failure is
// the standard intended behavior in Rust test harnesses. Tests and CLI main()
// may use #[allow] per workspace lint policy comment in Cargo.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::pem::{
    decode, decode_all, decode_encrypted, encode, encode_to_writer, PemObject,
    PEM_LABEL_CERTIFICATE, PEM_LABEL_CERTIFICATE_REQUEST, PEM_LABEL_ENCRYPTED_PRIVATE_KEY,
    PEM_LABEL_PUBLIC_KEY, PEM_LABEL_RSA_PRIVATE_KEY,
};
use openssl_common::CryptoError;

use insta::assert_snapshot;
use proptest::prelude::*;

// =============================================================================
// Test Constants & Helpers
// =============================================================================

/// Simple 11-byte test data for basic PEM encoding tests.
/// base64("hello world") = "aGVsbG8gd29ybGQ="
const TEST_DATA_SHORT: &[u8] = b"hello world";

/// Generate 96 bytes of test data (bytes 0..96).
/// 96 input bytes → 128 base64 characters → 2 base64 lines (64 + 64),
/// ensuring line-wrapping logic is exercised.
fn long_test_data() -> Vec<u8> {
    (0u8..96).collect()
}

/// Build a sample PEM-encoded CERTIFICATE block wrapping `TEST_DATA_SHORT`.
fn sample_certificate_pem() -> String {
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE, TEST_DATA_SHORT.to_vec());
    encode(&obj)
}

// =============================================================================
// PemObject Constructor Tests
// =============================================================================
// Validates `PemObject::new()`, `with_label()`, and `with_data()` constructors
// plus direct field access (`.label`, `.headers`, `.data`).

#[test]
fn test_pem_object_default_constructor() {
    let obj = PemObject::new();
    assert!(obj.label.is_empty(), "new() label must be empty");
    assert!(obj.headers.is_empty(), "new() headers must be empty");
    assert!(obj.data.is_empty(), "new() data must be empty");
}

#[test]
fn test_pem_object_with_label_constructor() {
    let obj = PemObject::with_label(PEM_LABEL_CERTIFICATE);
    assert_eq!(
        obj.label, PEM_LABEL_CERTIFICATE,
        "with_label must set label"
    );
    assert!(obj.headers.is_empty(), "with_label headers must be empty");
    assert!(obj.data.is_empty(), "with_label data must be empty");
}

#[test]
fn test_pem_object_with_data_constructor() {
    let obj = PemObject::with_data(PEM_LABEL_RSA_PRIVATE_KEY, b"key-bytes".to_vec());
    assert_eq!(
        obj.label, PEM_LABEL_RSA_PRIVATE_KEY,
        "with_data must set label"
    );
    assert!(obj.headers.is_empty(), "with_data headers must be empty");
    assert_eq!(obj.data, b"key-bytes", "with_data must set data");
}

// =============================================================================
// Phase 2: Encoding Tests (reference: test/pemtest.c)
// =============================================================================

#[test]
fn test_pem_encode_certificate() {
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE, TEST_DATA_SHORT.to_vec());
    let pem = encode(&obj);

    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "PEM must start with BEGIN CERTIFICATE header, got: {pem}"
    );
    assert!(
        pem.contains("-----END CERTIFICATE-----"),
        "PEM must contain END CERTIFICATE footer"
    );
    // Verify the base64-encoded body is present between boundary lines.
    assert!(
        pem.contains("aGVsbG8gd29ybGQ="),
        "PEM body must contain base64-encoded 'hello world'"
    );
}

#[test]
fn test_pem_encode_rsa_private_key() {
    let obj = PemObject::with_data(PEM_LABEL_RSA_PRIVATE_KEY, TEST_DATA_SHORT.to_vec());
    let pem = encode(&obj);

    assert!(
        pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"),
        "PEM must start with BEGIN RSA PRIVATE KEY header"
    );
    assert!(
        pem.contains("-----END RSA PRIVATE KEY-----"),
        "PEM must contain END RSA PRIVATE KEY footer"
    );
}

#[test]
fn test_pem_encode_public_key() {
    let obj = PemObject::with_data(PEM_LABEL_PUBLIC_KEY, TEST_DATA_SHORT.to_vec());
    let pem = encode(&obj);

    assert!(
        pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "PEM must start with BEGIN PUBLIC KEY header"
    );
    assert!(
        pem.contains("-----END PUBLIC KEY-----"),
        "PEM must contain END PUBLIC KEY footer"
    );
}

#[test]
fn test_pem_encode_certificate_request() {
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE_REQUEST, TEST_DATA_SHORT.to_vec());
    let pem = encode(&obj);

    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
        "PEM must start with BEGIN CERTIFICATE REQUEST header"
    );
    assert!(
        pem.contains("-----END CERTIFICATE REQUEST-----"),
        "PEM must contain END CERTIFICATE REQUEST footer"
    );
}

/// Validates that `encode_to_writer()` produces output identical to `encode()`.
#[test]
fn test_pem_encode_to_writer_matches_encode() {
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE, TEST_DATA_SHORT.to_vec());

    let direct = encode(&obj);

    let mut buf = Vec::new();
    encode_to_writer(&obj, &mut buf).expect("encode_to_writer should succeed");
    let writer_output = String::from_utf8(buf).expect("PEM output must be valid UTF-8");

    assert_eq!(
        direct, writer_output,
        "encode() and encode_to_writer() must produce identical output"
    );
}

// =============================================================================
// Phase 3: Snapshot Tests (insta)
// =============================================================================
// Uses `insta::assert_snapshot!` for exact PEM format regression testing.
// Snapshot files live in crates/openssl-crypto/src/tests/snapshots/.

#[test]
fn test_pem_certificate_format_snapshot() {
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE, TEST_DATA_SHORT.to_vec());
    let pem = encode(&obj);
    assert_snapshot!("pem_certificate_format", pem);
}

#[test]
fn test_pem_private_key_format_snapshot() {
    let obj = PemObject::with_data(PEM_LABEL_RSA_PRIVATE_KEY, TEST_DATA_SHORT.to_vec());
    let pem = encode(&obj);
    assert_snapshot!("pem_private_key_format", pem);
}

#[test]
fn test_pem_encoding_line_length() {
    // 96 bytes of input → 128 base64 chars → at least 2 full base64 lines.
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE, long_test_data());
    let pem = encode(&obj);

    // Verify each non-boundary line is ≤ 64 characters (PEM standard per RFC 7468 §2).
    for (i, line) in pem.lines().enumerate() {
        if line.starts_with("-----") {
            continue; // Boundary lines may exceed 64 chars.
        }
        assert!(
            line.len() <= 64,
            "Line {i} exceeds 64-character PEM limit: length={}, content={line:?}",
            line.len()
        );
    }

    // Confirm that the encoding produces at least 2 base64 body lines.
    let base64_line_count = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .count();
    assert!(
        base64_line_count >= 2,
        "Expected ≥2 base64 lines for 96-byte input, got {base64_line_count}"
    );
}

// =============================================================================
// Phase 4: Decoding Tests
// =============================================================================

#[test]
fn test_pem_decode_single_block() {
    let pem_str = sample_certificate_pem();
    let result = decode(&pem_str);

    assert!(
        result.is_ok(),
        "decode must succeed for valid PEM: {result:?}"
    );
    let obj = result.unwrap();
    assert_eq!(obj.label, PEM_LABEL_CERTIFICATE);
    assert_eq!(obj.data, TEST_DATA_SHORT);
    assert!(obj.headers.is_empty(), "Simple PEM should have no headers");
}

#[test]
fn test_pem_decode_multiple_blocks() {
    let cert1 = PemObject::with_data(PEM_LABEL_CERTIFICATE, b"first cert".to_vec());
    let cert2 = PemObject::with_data(PEM_LABEL_CERTIFICATE, b"second cert".to_vec());
    let combined = format!("{}{}", encode(&cert1), encode(&cert2));

    let result = decode_all(&combined);
    assert!(result.is_ok(), "decode_all must succeed: {result:?}");

    let objects = result.unwrap();
    assert_eq!(objects.len(), 2, "Should decode exactly 2 PEM blocks");
    assert_eq!(objects[0].data, b"first cert");
    assert_eq!(objects[1].data, b"second cert");
    assert_eq!(objects[0].label, PEM_LABEL_CERTIFICATE);
    assert_eq!(objects[1].label, PEM_LABEL_CERTIFICATE);
}

#[test]
fn test_pem_decode_invalid_base64_error() {
    let invalid_pem = "\
-----BEGIN CERTIFICATE-----\n\
!!!this-is-not-valid-base64!!!\n\
-----END CERTIFICATE-----\n";

    let result = decode(invalid_pem);
    assert!(result.is_err(), "decode must fail for invalid base64");

    let err = result.unwrap_err();
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "Expected CryptoError::Encoding for invalid base64, got: {err:?}"
    );
}

#[test]
fn test_pem_decode_missing_header_error() {
    // Body and footer without a BEGIN boundary line.
    let no_header = "aGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n";

    let result = decode(no_header);
    assert!(
        result.is_err(),
        "decode must fail when BEGIN header is missing"
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "Expected CryptoError::Encoding for missing header, got: {err:?}"
    );
}

#[test]
fn test_pem_decode_missing_footer_error() {
    // BEGIN header and body without a matching END boundary line.
    let no_footer = "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n";

    let result = decode(no_footer);
    assert!(
        result.is_err(),
        "decode must fail when END footer is missing"
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "Expected CryptoError::Encoding for missing footer, got: {err:?}"
    );
}

// =============================================================================
// Phase 5: Roundtrip Tests
// =============================================================================

#[test]
fn test_pem_encode_decode_roundtrip() {
    let original_data = b"The quick brown fox jumps over the lazy dog";
    let obj = PemObject::with_data(PEM_LABEL_CERTIFICATE, original_data.to_vec());

    let encoded = encode(&obj);
    let decoded = decode(&encoded).expect("roundtrip decode must succeed");

    assert_eq!(
        decoded.data, original_data,
        "Data must survive PEM encode/decode roundtrip"
    );
}

#[test]
fn test_pem_labels_preserved() {
    // Verify every standard label survives an encode → decode roundtrip.
    let labels = [
        PEM_LABEL_CERTIFICATE,
        PEM_LABEL_RSA_PRIVATE_KEY,
        PEM_LABEL_PUBLIC_KEY,
        PEM_LABEL_CERTIFICATE_REQUEST,
        PEM_LABEL_ENCRYPTED_PRIVATE_KEY,
    ];

    for &label in &labels {
        let obj = PemObject::with_data(label, b"test data".to_vec());
        let encoded = encode(&obj);
        let decoded =
            decode(&encoded).unwrap_or_else(|e| panic!("decode failed for label {label:?}: {e}"));
        assert_eq!(decoded.label, label, "Label must survive roundtrip exactly");
    }
}

// =============================================================================
// Phase 6: Encrypted PEM Tests
// =============================================================================

#[test]
fn test_pem_decode_encrypted_private_key() {
    // PKCS#8 encrypted private key (label "ENCRYPTED PRIVATE KEY").
    // The PEM layer returns the raw encapsulated PKCS#8 data — actual
    // decryption is handled by the PKCS#8 layer, not the PEM layer.
    let obj = PemObject::with_data(
        PEM_LABEL_ENCRYPTED_PRIVATE_KEY,
        b"pkcs8-encrypted-key-placeholder".to_vec(),
    );
    let pem = encode(&obj);

    let result = decode_encrypted(&pem, b"test-passphrase");
    assert!(
        result.is_ok(),
        "decode_encrypted must succeed for ENCRYPTED PRIVATE KEY: {result:?}"
    );

    let decoded = result.unwrap();
    assert_eq!(decoded.label, PEM_LABEL_ENCRYPTED_PRIVATE_KEY);
    assert_eq!(decoded.data, b"pkcs8-encrypted-key-placeholder");
}

#[test]
fn test_pem_decode_encrypted_wrong_passphrase_fails() {
    // --- Case 1: Legacy Proc-Type encrypted PEM ---
    // The cipher layer is not yet implemented, so any passphrase (including
    // "wrong" ones) produces a CryptoError::Encoding error.
    let proc_type_pem = "\
-----BEGIN RSA PRIVATE KEY-----\n\
Proc-Type: 4,ENCRYPTED\n\
DEK-Info: AES-256-CBC,0011223344556677\n\
\n\
aGVsbG8gd29ybGQ=\n\
-----END RSA PRIVATE KEY-----\n";

    let result = decode_encrypted(proc_type_pem, b"wrong-passphrase");
    assert!(
        result.is_err(),
        "decode_encrypted must fail for legacy Proc-Type encryption"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "Expected CryptoError::Encoding for unsupported encryption, got: {err:?}"
    );

    // --- Case 2: Empty passphrase validation ---
    let obj = PemObject::with_data(PEM_LABEL_ENCRYPTED_PRIVATE_KEY, b"some data".to_vec());
    let encrypted_pem = encode(&obj);
    let empty_result = decode_encrypted(&encrypted_pem, b"");
    assert!(
        empty_result.is_err(),
        "decode_encrypted must fail with empty passphrase"
    );
    let empty_err = empty_result.unwrap_err();
    assert!(
        matches!(empty_err, CryptoError::Encoding(_)),
        "Expected CryptoError::Encoding for empty passphrase, got: {empty_err:?}"
    );
}

// =============================================================================
// Phase 7: Property-Based Tests (proptest)
// =============================================================================
// Randomized roundtrip verification: arbitrary byte data and label strings are
// encoded to PEM, decoded back, and compared for exact equality.

proptest! {
    #[test]
    fn prop_pem_roundtrip(
        data in proptest::collection::vec(any::<u8>(), 1..1024usize),
        label in "[A-Z][A-Z ]{3,28}[A-Z]"
    ) {
        let obj = PemObject::with_data(label.clone(), data.clone());
        let encoded = encode(&obj);
        let decoded = decode(&encoded).map_err(|e| {
            proptest::test_runner::TestCaseError::fail(format!("{e}"))
        })?;
        prop_assert_eq!(decoded.data, data);
        prop_assert_eq!(decoded.label, label);
    }
}
