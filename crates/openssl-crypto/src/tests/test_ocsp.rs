//! OCSP Integration Tests — RFC 6960 Online Certificate Status Protocol.
//!
//! Validates the `crate::ocsp` module across four test phases:
//!
//! 1. **Module setup** — feature gate, imports
//! 2. **Request tests** — `OcspRequestBuilder`, `OcspCertId`, nonce handling
//! 3. **Response tests** — status parsing, `OcspSingleResponse` with Good/Revoked/Unknown
//! 4. **Validity checks** — `check_validity()` with current and expired responses
//!
//! # C Source Reference
//!
//! These tests correspond to patterns in `test/ocspapitest.c`, with Rust-idiomatic
//! adaptations.  Cert status is tested via typed enums (`OcspCertStatus`) rather
//! than integer codes — enforcing Rule R5 (Nullability over Sentinels).
//!
//! # Rules Verified
//!
//! - **R5:** `OcspCertStatus` is a typed enum — no integer codes
//! - **R8:** Zero `unsafe` blocks in this test module and the module under test

// Feature gate: only compile when the `ocsp` feature is enabled (mirrors
// the outer `#[cfg(feature = "ocsp")]` on the `mod test_ocsp` declaration
// in `tests/mod.rs`).
#![cfg(feature = "ocsp")]
// Allow `.unwrap()` and `.expect()` in test code — these are tests, and
// panicking on failure is the intended behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::ocsp::*;
use openssl_common::{CryptoError, CryptoResult, Nid};

// =============================================================================
// DER Encoding Helpers — test-private utilities for constructing OCSP DER
// =============================================================================
//
// These helpers mirror the private `encode_*` functions in `crate::ocsp` but
// are defined here so tests can construct arbitrary DER payloads for parsing
// without depending on the module's internal encoders.

/// Encodes a DER definite-form length.
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        let hi = ((len >> 8) & 0xFF) as u8;
        let lo = (len & 0xFF) as u8;
        vec![0x82, hi, lo]
    }
}

/// Wraps `content` in a DER SEQUENCE (tag 0x30).
fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encodes a DER ENUMERATED value (single-byte).
fn der_enumerated(value: u8) -> Vec<u8> {
    vec![0x0A, 0x01, value]
}

/// Encodes a DER OBJECT IDENTIFIER from raw OID bytes.
fn der_oid(oid: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06];
    out.extend_from_slice(&der_length(oid.len()));
    out.extend_from_slice(oid);
    out
}

/// Encodes a DER OCTET STRING.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Encodes a DER INTEGER from big-endian value bytes.
/// Adds a leading 0x00 if the high bit is set (positive integer).
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02];
    if !value.is_empty() && (value[0] & 0x80) != 0 {
        out.extend_from_slice(&der_length(value.len() + 1));
        out.push(0x00);
    } else {
        out.extend_from_slice(&der_length(value.len()));
    }
    out.extend_from_slice(value);
    out
}

/// Encodes a DER NULL.
fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Encodes a DER BIT STRING with 0 unused bits.
fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend_from_slice(&der_length(data.len() + 1)); // +1 for unused-bits byte
    out.push(0x00); // 0 unused bits
    out.extend_from_slice(data);
    out
}

/// Wraps `content` in a DER context-specific EXPLICIT tag `[tag_num]`.
fn der_explicit_tag(tag_num: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | (tag_num & 0x1F);
    let mut out = vec![tag];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encodes a DER GeneralizedTime from a string like `"20200101000000Z"`.
fn der_generalized_time(time_str: &str) -> Vec<u8> {
    let bytes = time_str.as_bytes();
    let mut out = vec![0x18];
    out.extend_from_slice(&der_length(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

// =============================================================================
// OCSP DER Structure Builders
// =============================================================================

/// SHA-256 OID bytes: 2.16.840.1.101.3.4.2.1
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// id-pkix-ocsp-basic OID: 1.3.6.1.5.5.7.48.1.1
const OCSP_BASIC_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11
const SHA256_RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

/// Builds a DER-encoded CertID SEQUENCE using SHA-256.
fn build_cert_id_der(name_hash: &[u8], key_hash: &[u8], serial: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
    let mut alg_content = der_oid(SHA256_OID);
    alg_content.extend_from_slice(&der_null());
    let alg_id = der_sequence(&alg_content);

    let mut cert_id_content = Vec::new();
    cert_id_content.extend_from_slice(&alg_id);
    cert_id_content.extend_from_slice(&der_octet_string(name_hash));
    cert_id_content.extend_from_slice(&der_octet_string(key_hash));
    cert_id_content.extend_from_slice(&der_integer(serial));

    der_sequence(&cert_id_content)
}

/// Builds a `CertStatus` for Good: `[0] IMPLICIT NULL`.
fn build_good_status() -> Vec<u8> {
    // Context-specific, primitive, tag 0 = 0x80, length 0
    vec![0x80, 0x00]
}

/// Builds a `CertStatus` for Revoked: `[1] IMPLICIT RevokedInfo`.
///
/// `RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }`
/// With IMPLICIT tagging, the SEQUENCE tag (0x30) is replaced by 0xA1.
fn build_revoked_status(rev_time_str: &str, reason: Option<u8>) -> Vec<u8> {
    // Content: GeneralizedTime + optional [0] EXPLICIT ENUMERATED
    let mut content = der_generalized_time(rev_time_str);
    if let Some(r) = reason {
        // [0] EXPLICIT CRLReason → A0 <len> ENUMERATED
        let reason_enum = der_enumerated(r);
        content.extend_from_slice(&der_explicit_tag(0, &reason_enum));
    }
    // [1] IMPLICIT constructed = 0xA1
    let mut out = vec![0xA1];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(&content);
    out
}

/// Builds a `CertStatus` for Unknown: `[2] IMPLICIT NULL`.
fn build_unknown_status() -> Vec<u8> {
    // Context-specific, primitive, tag 2 = 0x82, length 0
    vec![0x82, 0x00]
}

/// Builds a SingleResponse DER SEQUENCE.
fn build_single_response_der(
    cert_id_der: &[u8],
    status_der: &[u8],
    this_update: &str,
    next_update: Option<&str>,
) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(cert_id_der);
    content.extend_from_slice(status_der);
    content.extend_from_slice(&der_generalized_time(this_update));
    if let Some(nu) = next_update {
        // nextUpdate [0] EXPLICIT GeneralizedTime
        content.extend_from_slice(&der_explicit_tag(0, &der_generalized_time(nu)));
    }
    der_sequence(&content)
}

/// Builds a tbsResponseData SEQUENCE.
fn build_tbs_response_data_der(responses_der: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    // responderID: byKey [2] EXPLICIT OCTET STRING (dummy 4-byte key hash)
    content.extend_from_slice(&der_explicit_tag(
        2,
        &der_octet_string(&[0xDE, 0xAD, 0xBE, 0xEF]),
    ));
    // producedAt: GeneralizedTime
    content.extend_from_slice(&der_generalized_time("20240101000000Z"));
    // responses: SEQUENCE OF SingleResponse
    content.extend_from_slice(&der_sequence(responses_der));
    der_sequence(&content)
}

/// Builds a BasicOCSPResponse SEQUENCE.
fn build_basic_response_der(single_responses_concat: &[u8]) -> Vec<u8> {
    let tbs = build_tbs_response_data_der(single_responses_concat);

    // signatureAlgorithm: SEQUENCE { sha256WithRSAEncryption, NULL }
    let mut sig_alg_content = der_oid(SHA256_RSA_OID);
    sig_alg_content.extend_from_slice(&der_null());
    let sig_alg = der_sequence(&sig_alg_content);

    // signature: BIT STRING (dummy 64-byte signature)
    let sig = der_bit_string(&[0xFF; 64]);

    // Optional certs [0] EXPLICIT SEQUENCE OF Certificate
    // Include one dummy cert (minimal SEQUENCE) so verify_response sees certs
    let dummy_cert = der_sequence(&[0x01, 0x02, 0x03]);
    let certs_seq = der_sequence(&dummy_cert);
    let certs_tagged = der_explicit_tag(0, &certs_seq);

    let mut basic_content = Vec::new();
    basic_content.extend_from_slice(&tbs);
    basic_content.extend_from_slice(&sig_alg);
    basic_content.extend_from_slice(&sig);
    basic_content.extend_from_slice(&certs_tagged);
    der_sequence(&basic_content)
}

/// Builds a full successful OCSPResponse DER wrapping a BasicOCSPResponse.
fn build_successful_ocsp_response_der(basic_response_der: &[u8]) -> Vec<u8> {
    // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
    let mut rb_content = der_oid(OCSP_BASIC_OID);
    rb_content.extend_from_slice(&der_octet_string(basic_response_der));
    let response_bytes = der_sequence(&rb_content);

    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT }
    let mut ocsp_content = der_enumerated(0); // Successful
    ocsp_content.extend_from_slice(&der_explicit_tag(0, &response_bytes));
    der_sequence(&ocsp_content)
}

/// Builds a non-successful OCSPResponse DER (no responseBytes).
fn build_error_ocsp_response_der(status: u8) -> Vec<u8> {
    der_sequence(&der_enumerated(status))
}

/// Builds a BasicOCSPResponse SEQUENCE **without** embedded certificates.
/// Used to test `verify_response()` negative path (no signer cert available).
fn build_basic_response_no_certs_der(single_responses_concat: &[u8]) -> Vec<u8> {
    let tbs = build_tbs_response_data_der(single_responses_concat);

    // signatureAlgorithm: SEQUENCE { sha256WithRSAEncryption, NULL }
    let mut sig_alg_content = der_oid(SHA256_RSA_OID);
    sig_alg_content.extend_from_slice(&der_null());
    let sig_alg = der_sequence(&sig_alg_content);

    // signature: BIT STRING (dummy 64-byte signature)
    let sig = der_bit_string(&[0xFF; 64]);

    // NO certs section — intentionally omitted
    let mut basic_content = Vec::new();
    basic_content.extend_from_slice(&tbs);
    basic_content.extend_from_slice(&sig_alg);
    basic_content.extend_from_slice(&sig);
    der_sequence(&basic_content)
}

/// Creates a complete, parseable, successful OCSP response containing a
/// single `SingleResponse` with the given cert status and timestamps.
///
/// Returns the DER bytes ready for `OcspResponse::from_der()`.
fn make_test_response(status_der: &[u8], this_update: &str, next_update: Option<&str>) -> Vec<u8> {
    let cert_id = build_cert_id_der(&[0xAA; 32], &[0xBB; 32], &[0x01, 0x02, 0x03]);
    let single = build_single_response_der(&cert_id, status_der, this_update, next_update);
    let basic = build_basic_response_der(&single);
    build_successful_ocsp_response_der(&basic)
}

/// Same as `make_test_response` but the `BasicOCSPResponse` has no embedded
/// certificates.  Useful for testing `verify_response()` error paths.
fn make_test_response_no_certs(
    status_der: &[u8],
    this_update: &str,
    next_update: Option<&str>,
) -> Vec<u8> {
    let cert_id = build_cert_id_der(&[0xAA; 32], &[0xBB; 32], &[0x01, 0x02, 0x03]);
    let single = build_single_response_der(&cert_id, status_der, this_update, next_update);
    let basic = build_basic_response_no_certs_der(&single);
    build_successful_ocsp_response_der(&basic)
}

// =============================================================================
// Phase 2: Request Tests (reference: test/ocspapitest.c)
// =============================================================================

/// Builds an OCSP request with a single cert ID via `OcspRequestBuilder`,
/// verifies fields, and encodes to DER.
#[test]
fn test_ocsp_request_construction() {
    // Create a cert ID using SHA-256 hashes and a 3-byte serial
    let cert_id = OcspCertId::new(
        Nid::SHA256,
        &[0xAA; 32],         // issuer name hash
        &[0xBB; 32],         // issuer key hash
        &[0x01, 0x02, 0x03], // serial number
    )
    .expect("valid cert ID with SHA-256");

    // Build the request
    let request = OcspRequestBuilder::new()
        .add_cert_id(cert_id)
        .build()
        .expect("build succeeds with one cert ID");

    // Verify the request carries exactly one cert ID
    assert_eq!(request.cert_ids().len(), 1, "request should have 1 cert ID");

    // Verify the cert ID fields round-trip
    let rid = &request.cert_ids()[0];
    assert_eq!(rid.hash_algorithm(), Nid::SHA256);
    assert_eq!(rid.issuer_name_hash(), &[0xAA; 32]);
    assert_eq!(rid.issuer_key_hash(), &[0xBB; 32]);
    assert_eq!(rid.serial_number(), &[0x01, 0x02, 0x03]);

    // No nonce was set
    assert!(request.nonce().is_none(), "nonce should be None");

    // DER encoding must succeed and produce non-empty bytes
    let der = request.to_der().expect("DER encoding succeeds");
    assert!(!der.is_empty(), "DER output must not be empty");

    // The DER must start with SEQUENCE tag (0x30)
    assert_eq!(der[0], 0x30, "DER must start with SEQUENCE tag");
}

/// Builds an OCSP request with a nonce extension, verifies the nonce is
/// present and matches the original value.
#[test]
fn test_ocsp_request_with_nonce() {
    let cert_id =
        OcspCertId::new(Nid::SHA256, &[0xCC; 32], &[0xDD; 32], &[0x42]).expect("valid cert ID");

    let nonce_value = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    let request = OcspRequestBuilder::new()
        .add_cert_id(cert_id)
        .set_nonce(nonce_value.clone())
        .build()
        .expect("build succeeds with nonce");

    // Nonce must be present and match
    let nonce = request.nonce();
    assert!(nonce.is_some(), "nonce must be Some");
    assert_eq!(nonce.unwrap(), &nonce_value, "nonce value must match");

    // DER encoding must include the nonce extension
    let der = request.to_der().expect("DER encoding succeeds");
    assert!(!der.is_empty());

    // The nonce OID (1.3.6.1.5.5.7.48.1.2) bytes should appear in the DER
    let nonce_oid_bytes: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
    assert!(
        contains_subsequence(&der, nonce_oid_bytes),
        "DER must contain the OCSP nonce extension OID"
    );
}

/// Creates `OcspCertId` instances with different algorithms and data,
/// verifies all accessor methods, and tests the `matches()` comparison.
#[test]
fn test_ocsp_cert_id_creation() {
    let name_hash = [0x11; 32];
    let key_hash = [0x22; 32];
    let serial = [0x42, 0x43];

    // Create with SHA-256
    let id1 =
        OcspCertId::new(Nid::SHA256, &name_hash, &key_hash, &serial).expect("SHA-256 cert ID");

    // Verify all accessors
    assert_eq!(id1.hash_algorithm(), Nid::SHA256);
    assert_eq!(id1.issuer_name_hash(), &name_hash);
    assert_eq!(id1.issuer_key_hash(), &key_hash);
    assert_eq!(id1.serial_number(), &serial);

    // Identical cert IDs must match
    let id2 =
        OcspCertId::new(Nid::SHA256, &name_hash, &key_hash, &serial).expect("identical cert ID");
    assert!(id1.matches(&id2), "identical cert IDs must match");

    // Different issuer name hash → no match
    let id3 =
        OcspCertId::new(Nid::SHA256, &[0x33; 32], &key_hash, &serial).expect("different name hash");
    assert!(!id1.matches(&id3), "different name hash must not match");

    // Different serial → no match
    let id4 =
        OcspCertId::new(Nid::SHA256, &name_hash, &key_hash, &[0x99]).expect("different serial");
    assert!(!id1.matches(&id4), "different serial must not match");

    // Different key hash → no match
    let id5 =
        OcspCertId::new(Nid::SHA256, &name_hash, &[0x55; 32], &serial).expect("different key hash");
    assert!(!id1.matches(&id5), "different key hash must not match");

    // Create with SHA-1 to verify algorithm variety
    let id_sha1 =
        OcspCertId::new(Nid::SHA1, &[0xAA; 20], &[0xBB; 20], &[0x01]).expect("SHA-1 cert ID");
    assert_eq!(id_sha1.hash_algorithm(), Nid::SHA1);

    // Invalid: UNDEF NID must fail (per R5 — no sentinel NID allowed)
    let err = OcspCertId::new(Nid::UNDEF, &name_hash, &key_hash, &serial);
    assert!(err.is_err(), "UNDEF NID must be rejected");

    // Invalid: empty issuer name hash
    let err = OcspCertId::new(Nid::SHA256, &[], &key_hash, &serial);
    assert!(err.is_err(), "empty name hash must be rejected");

    // Invalid: empty serial
    let err = OcspCertId::new(Nid::SHA256, &name_hash, &key_hash, &[]);
    assert!(err.is_err(), "empty serial must be rejected");
}

// =============================================================================
// Phase 3: Response Tests
// =============================================================================

/// Verifies `OcspResponseStatus` enum parsing: all 6 valid status codes
/// can be obtained by parsing DER-encoded OCSP responses, `as_raw()`
/// round-trips correctly, and non-successful statuses prevent conversion
/// to `OcspBasicResponse`.
#[test]
fn test_ocsp_response_status_parsing() {
    // All 6 defined status values (RFC 6960 §4.2.1)
    let known_statuses: &[(u8, OcspResponseStatus)] = &[
        (0, OcspResponseStatus::Successful),
        (1, OcspResponseStatus::MalformedRequest),
        (2, OcspResponseStatus::InternalError),
        (3, OcspResponseStatus::TryLater),
        (5, OcspResponseStatus::SigRequired),
        (6, OcspResponseStatus::Unauthorized),
    ];

    for &(raw, expected) in known_statuses {
        // Build a DER-encoded OCSP response with this status code
        let der = if raw == 0 {
            // Successful status needs embedded responseBytes
            make_test_response(
                &build_good_status(),
                "20200101000000Z",
                Some("20401231235959Z"),
            )
        } else {
            build_error_ocsp_response_der(raw)
        };

        let response = OcspResponse::from_der(&der)
            .unwrap_or_else(|_| panic!("OCSP response with status {raw} must parse"));

        // Verify status matches expected variant
        assert_eq!(
            response.status(),
            expected,
            "status from DER with raw={raw} must match variant"
        );

        // as_raw must round-trip to the original status byte
        assert_eq!(
            response.status().as_raw(),
            raw,
            "as_raw must round-trip for {raw}"
        );

        // Display must produce non-empty string
        let display = format!("{}", expected);
        assert!(
            !display.is_empty(),
            "Display must not be empty for status {raw}"
        );
    }

    // Non-successful responses must reject into_basic()
    for &status_val in &[1u8, 2, 3, 5, 6] {
        let der = build_error_ocsp_response_der(status_val);
        let response =
            OcspResponse::from_der(&der).expect("non-successful OCSP response should parse");
        assert_eq!(response.status().as_raw(), status_val);

        // Attempting to extract BasicResponse from non-successful must fail
        let basic_result = response.into_basic();
        assert!(
            basic_result.is_err(),
            "into_basic must fail for non-successful status {status_val}"
        );
    }
}

/// Parses a successful OCSP response with a single "Good" certificate
/// status, verifying all fields of the resulting `OcspSingleResponse`.
#[test]
fn test_ocsp_single_response_good() {
    let response_der = make_test_response(
        &build_good_status(),
        "20200101000000Z",       // thisUpdate: 2020-01-01
        Some("20401231235959Z"), // nextUpdate: 2040-12-31 (far future)
    );

    let response =
        OcspResponse::from_der(&response_der).expect("successful OCSP response must parse");
    assert_eq!(response.status(), OcspResponseStatus::Successful);

    let basic = response.into_basic().expect("into_basic must succeed");
    let singles = basic.responses();
    assert_eq!(singles.len(), 1, "must have exactly 1 single response");

    let sr = &singles[0];

    // Cert status must be Good — R5: typed enum, not integer
    match sr.status() {
        OcspCertStatus::Good => { /* expected */ }
        other => panic!("expected Good status, got {other}"),
    }

    // Verify CertID was parsed correctly
    assert_eq!(sr.cert_id().hash_algorithm(), Nid::SHA256);
    assert_eq!(sr.cert_id().issuer_name_hash(), &[0xAA; 32]);
    assert_eq!(sr.cert_id().issuer_key_hash(), &[0xBB; 32]);
    assert_eq!(sr.cert_id().serial_number(), &[0x01, 0x02, 0x03]);

    // thisUpdate must be a valid timestamp (positive)
    assert!(sr.this_update() > 0, "thisUpdate must be positive");

    // nextUpdate must be present and greater than thisUpdate
    let next = sr.next_update();
    assert!(next.is_some(), "nextUpdate must be present");
    assert!(
        next.unwrap() > sr.this_update(),
        "nextUpdate must be after thisUpdate"
    );

    // Verify basic response structural fields
    assert!(!basic.signature().is_empty(), "signature must not be empty");
    assert!(
        !basic.signature_algorithm().is_empty(),
        "signature algorithm must not be empty"
    );
}

/// Parses a successful OCSP response with a Revoked certificate status,
/// verifying the revocation time and reason code.
#[test]
fn test_ocsp_single_response_revoked() {
    let revoked_status = build_revoked_status(
        "20230615120000Z", // revocation time: 2023-06-15 12:00:00
        Some(1),           // keyCompromise
    );

    let response_der = make_test_response(
        &revoked_status,
        "20230616000000Z",       // thisUpdate: day after revocation
        Some("20401231235959Z"), // nextUpdate: far future
    );

    let response = OcspResponse::from_der(&response_der)
        .expect("OCSP response with Revoked status must parse");
    let basic = response.into_basic().expect("into_basic succeeds");
    let sr = &basic.responses()[0];

    // Status must be Revoked with time and reason — R5: typed enum
    match sr.status() {
        OcspCertStatus::Revoked {
            revocation_time,
            reason,
        } => {
            // Revocation time must be positive and reasonable
            assert!(
                *revocation_time > 0,
                "revocation_time must be a valid timestamp"
            );

            // Reason must be KeyCompromise
            assert!(reason.is_some(), "revocation reason must be present");
            assert_eq!(
                *reason,
                Some(OcspRevocationReason::KeyCompromise),
                "reason must be KeyCompromise"
            );
        }
        other => panic!("expected Revoked status, got {other}"),
    }

    // thisUpdate must be valid
    assert!(sr.this_update() > 0);
}

/// Tests all `OcspCertStatus` enum variants can be constructed and
/// inspected — verifying Rule R5 (typed enums, not integer codes).
#[test]
fn test_ocsp_cert_status_enum() {
    // Good variant — simple unit variant
    let good = OcspCertStatus::Good;
    assert_eq!(good.tag_value(), 0);
    let display_good = format!("{good}");
    assert!(!display_good.is_empty());

    // Revoked variant — with time and reason
    let revoked = OcspCertStatus::Revoked {
        revocation_time: 1_687_000_000,
        reason: Some(OcspRevocationReason::CaCompromise),
    };
    assert_eq!(revoked.tag_value(), 1);
    let display_revoked = format!("{revoked}");
    assert!(!display_revoked.is_empty());

    // Revoked variant — without reason
    let revoked_no_reason = OcspCertStatus::Revoked {
        revocation_time: 1_600_000_000,
        reason: None,
    };
    assert_eq!(revoked_no_reason.tag_value(), 1);

    // Unknown variant
    let unknown = OcspCertStatus::Unknown;
    assert_eq!(unknown.tag_value(), 2);
    let display_unknown = format!("{unknown}");
    assert!(!display_unknown.is_empty());

    // Test all OcspRevocationReason variants round-trip
    let reason_pairs: &[(i32, OcspRevocationReason)] = &[
        (0, OcspRevocationReason::Unspecified),
        (1, OcspRevocationReason::KeyCompromise),
        (2, OcspRevocationReason::CaCompromise),
        (3, OcspRevocationReason::AffiliationChanged),
        (4, OcspRevocationReason::Superseded),
        (5, OcspRevocationReason::CessationOfOperation),
        (6, OcspRevocationReason::CertificateHold),
        (8, OcspRevocationReason::RemoveFromCrl),
        (9, OcspRevocationReason::PrivilegeWithdrawn),
        (10, OcspRevocationReason::AaCompromise),
    ];

    for &(raw, expected) in reason_pairs {
        let parsed = OcspRevocationReason::from_raw(raw);
        assert!(parsed.is_some(), "reason {raw} must parse");
        assert_eq!(parsed.unwrap(), expected, "reason {raw} must match");
        assert_eq!(
            parsed.unwrap().as_raw(),
            raw,
            "reason as_raw must round-trip"
        );

        // Display
        let display = format!("{}", expected);
        assert!(!display.is_empty());
    }

    // Invalid reason code
    assert!(
        OcspRevocationReason::from_raw(7).is_none(),
        "reason 7 is reserved"
    );
    assert!(
        OcspRevocationReason::from_raw(11).is_none(),
        "reason 11 is undefined"
    );
    assert!(
        OcspRevocationReason::from_raw(-1).is_none(),
        "negative reason is invalid"
    );

    // Verify Unknown status can be obtained by parsing a DER response
    let unknown_der = make_test_response(
        &build_unknown_status(),
        "20200101000000Z",
        Some("20401231235959Z"),
    );
    let resp = OcspResponse::from_der(&unknown_der).expect("Unknown status must parse");
    let basic = resp.into_basic().expect("into_basic succeeds");
    let sr = &basic.responses()[0];
    match sr.status() {
        OcspCertStatus::Unknown => { /* expected */ }
        other => panic!("expected Unknown status, got {other}"),
    }
}

// =============================================================================
// Phase 4: Validity Checks
// =============================================================================

/// Validates `check_validity()` with a response whose `thisUpdate` is in the
/// past and `nextUpdate` is far in the future — must be temporally valid.
#[test]
fn test_ocsp_check_validity_current() -> CryptoResult<()> {
    // Use dates that bracket the present:
    //   thisUpdate = 2020-01-01 (past) → well before "now"
    //   nextUpdate = 2040-12-31 (future) → well after "now"
    let response_der = make_test_response(
        &build_good_status(),
        "20200101000000Z",
        Some("20401231235959Z"),
    );

    let response = OcspResponse::from_der(&response_der)?;
    let basic = response.into_basic()?;
    let sr = &basic.responses()[0];

    // drift_seconds = 300 (5 minutes) — standard OCSP tolerance
    let result = check_validity(sr, 300)?;
    assert!(result, "response within validity window must return true");

    // Also valid with zero drift
    let result_zero = check_validity(sr, 0)?;
    assert!(result_zero, "response must be valid even with zero drift");

    // Negative drift is clamped to 0 — must still be valid
    let result_neg = check_validity(sr, -100)?;
    assert!(
        result_neg,
        "negative drift clamps to 0; response still valid"
    );

    Ok(())
}

/// Validates `check_validity()` with a response whose `nextUpdate` is in
/// the past — must report the response as expired (`Ok(false)`).
///
/// Also validates `verify_response()` structural checks for both positive
/// (embedded certs) and negative (no certs → `CryptoError::Verification`)
/// paths.
#[test]
fn test_ocsp_check_validity_expired() -> CryptoResult<()> {
    // Both thisUpdate and nextUpdate are far in the past:
    //   thisUpdate = 2010-01-01
    //   nextUpdate = 2010-01-02  (well before "now")
    let response_der = make_test_response(
        &build_good_status(),
        "20100101000000Z",
        Some("20100102000000Z"),
    );

    let response = OcspResponse::from_der(&response_der)?;
    let basic = response.into_basic()?;
    let sr = &basic.responses()[0];

    // With standard drift (300s), this must be expired
    let result = check_validity(sr, 300)?;
    assert!(
        !result,
        "expired response must return false (nextUpdate in the past)"
    );

    // Even with a generous drift of 1 hour, 2010 is too far in the past
    let result_generous = check_validity(sr, 3600)?;
    assert!(
        !result_generous,
        "expired response must return false even with 1h drift"
    );

    // verify_response structural check — the response itself is structurally
    // valid (has signature, TBS data, single responses, embedded certs)
    let response2 = OcspResponse::from_der(&response_der)?;
    let basic2 = response2.into_basic()?;
    let structural = verify_response(&basic2, &[])?;
    assert!(
        structural,
        "structurally valid response with embedded certs passes verify_response"
    );

    // Negative path: verify_response with NO embedded certs AND no trusted
    // certs must fail with CryptoError::Verification (signer not found)
    let no_certs_der = make_test_response_no_certs(
        &build_good_status(),
        "20200101000000Z",
        Some("20401231235959Z"),
    );
    let resp_nc = OcspResponse::from_der(&no_certs_der)?;
    let basic_nc = resp_nc.into_basic()?;
    let verify_err = verify_response(&basic_nc, &[]);
    match verify_err {
        Err(CryptoError::Verification(msg)) => {
            assert!(
                msg.contains("SIGNER_CERTIFICATE_NOT_FOUND")
                    || msg.contains("signer")
                    || msg.contains("certificate"),
                "Verification error must mention signer cert issue, got: {msg}"
            );
        }
        Err(other) => {
            panic!("expected CryptoError::Verification, got: {other:?}");
        }
        Ok(_) => {
            panic!("verify_response should fail when no certs available");
        }
    }

    Ok(())
}

// =============================================================================
// Utility Helpers
// =============================================================================

/// Checks if `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
