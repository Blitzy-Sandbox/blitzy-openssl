//! Integration tests for ASN.1/DER encoding and decoding with snapshot testing.
//!
//! Covers the full public API surface of `crate::asn1`:
//! - Phase 2: DER encoding — `Asn1Integer`, `Asn1Boolean`, `Asn1OctetString`,
//!   `Asn1Object`, and `Asn1Type` wrappers produce RFC 5280 / X.690 DER bytes
//! - Phase 3: DER decoding — roundtrip correctness and rejection of malformed
//!   inputs (truncated, invalid tag, overlength)
//! - Phase 4: ASN.1 time — `UTCTime` (YYMMDDHHMMSSZ) and `GeneralizedTime`
//!   (YYYYMMDDHHMMSSZ) encoding, parsing, and comparison via `Ord`
//! - Phase 5: Snapshot tests — exact DER byte sequences captured via `insta`
//!   for INTEGER, SEQUENCE (DN), and well-known OIDs
//! - Phase 6: Roundtrip tests — encode → decode correctness for all primitive
//!   and string types
//! - Phase 7: Property-based — `proptest` randomized roundtrip for INTEGER
//!   (any i64) and OCTET STRING (0..1024 bytes)
//!
//! Key Rules enforced:
//! - R5 (nullability): Decode functions return `CryptoResult<T>`; failures
//!   are `Err(CryptoError::Encoding(_))`, never sentinel values
//! - R8 (zero unsafe): Pure safe Rust; the test harness contains no `unsafe`
//! - Gate 10: ≥80% line coverage target for the `asn1` module
//!
//! Source references:
//! - `test/asn1_encode_test.c` — encoding correctness
//! - `test/asn1_decode_test.c` — decoding and error cases
//! - `test/asn1_time_test.c` — UTC/Generalized time parsing
//! - `test/asn1_string_test.c` — string type handling
//! - `test/d2i_test.c` — d2i (DER-to-internal) parsing
//! - `test/asn1_internal_test.c` — internal TLV primitives
//! - `crypto/asn1/asn1_lib.c` — foundational TLV layer

// RATIONALE: Test assertions use unwrap/expect/panic — panic on test failure is
// the standard intended behavior in Rust test harnesses. Tests and CLI main()
// may use #[allow] per workspace lint policy comment in Cargo.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::asn1::{
    parse_tlv_header, write_tlv_header, AlgorithmIdentifier, Asn1BitString, Asn1Boolean, Asn1Class,
    Asn1Enumerated, Asn1Integer, Asn1Null, Asn1Object, Asn1OctetString, Asn1String, Asn1Tag,
    Asn1Time, Asn1Type, DigestInfo, StringFlags, TimeFormat, TlvHeader, Validity,
};
use openssl_common::CryptoError;

use insta::assert_snapshot;
use proptest::prelude::*;

// =============================================================================
// Test Helpers
// =============================================================================

/// Render a byte slice as lowercase hex with no separators.
fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Every byte produces exactly two hex chars — standard `{:02x}`.
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Render a byte slice as a space-separated list of lowercase hex bytes.
fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build a plain `UTF8String` `Asn1String` populated with `text`.
fn utf8_string(text: &str) -> Asn1String {
    let mut s = Asn1String::new(Asn1Tag::Utf8String);
    s.set(text.as_bytes()).expect("Asn1String::set never fails");
    s
}

// =============================================================================
// Phase 2 — DER Encoding Tests
// =============================================================================
// Reference: test/asn1_encode_test.c.
//
// Every encoding test verifies:
//   1. `encode_der()` on the primitive returns CONTENT bytes only (no TLV
//      wrapper), matching the C-side `i2d_*_body()` contracts.
//   2. `Asn1Type::<variant>(v).encode_der()` returns a FULL TLV matching the
//      exact expected byte sequence per X.690 §8.
// The byte sequences below are derived from RFC 5280 Appendix B examples and
// manually computed from X.690 rules, not from the implementation.

#[test]
fn test_asn1_encode_integer_small_positive() {
    // 42 = 0x2A → content is single byte [0x2A].
    let i = Asn1Integer::from_i64(42);
    let content = i.encode_der().expect("Asn1Integer::encode_der");
    assert_eq!(content, vec![0x2A], "INTEGER 42 content must be [0x2A]");

    // Asn1Type wraps in full TLV: 02 01 2A.
    let tlv = Asn1Type::Integer(i)
        .encode_der()
        .expect("encode Integer TLV");
    assert_eq!(tlv, vec![0x02, 0x01, 0x2A], "INTEGER 42 full TLV");
}

#[test]
fn test_asn1_encode_integer_zero() {
    // Zero is encoded as a single byte 0x00 per X.690 §8.3.
    let i = Asn1Integer::from_i64(0);
    let content = i.encode_der().expect("encode zero");
    assert_eq!(content, vec![0x00], "INTEGER 0 content must be [0x00]");
    let tlv = Asn1Type::Integer(i).encode_der().expect("tlv");
    assert_eq!(tlv, vec![0x02, 0x01, 0x00], "INTEGER 0 TLV");
}

#[test]
fn test_asn1_encode_integer_127_single_byte() {
    // 127 = 0x7F, high bit clear → single byte, no 0x00 prepending.
    let content = Asn1Integer::from_i64(127).encode_der().unwrap();
    assert_eq!(content, vec![0x7F]);
}

#[test]
fn test_asn1_encode_integer_128_requires_padding() {
    // 128 = 0x80, high bit set → must prepend 0x00 to avoid negative reading.
    let content = Asn1Integer::from_i64(128).encode_der().unwrap();
    assert_eq!(content, vec![0x00, 0x80], "INTEGER 128 needs 0x00 padding");
}

#[test]
fn test_asn1_encode_integer_negative_small() {
    // -128 = 0x80 in two's complement, high bit set for negative.
    let content = Asn1Integer::from_i64(-128).encode_der().unwrap();
    assert_eq!(content, vec![0x80], "INTEGER -128 two's complement");
}

#[test]
fn test_asn1_encode_integer_negative_one() {
    // -1 = 0xFF in two's complement, shortest form.
    let content = Asn1Integer::from_i64(-1).encode_der().unwrap();
    assert_eq!(content, vec![0xFF], "INTEGER -1");
}

#[test]
fn test_asn1_encode_integer_large_positive_12345() {
    // 12345 = 0x3039, both bytes, high bit clear.
    let content = Asn1Integer::from_i64(12345).encode_der().unwrap();
    assert_eq!(content, vec![0x30, 0x39]);
}

#[test]
fn test_asn1_encode_integer_from_u64() {
    // u64 path: 255 → [0x00, 0xFF] (high bit set, needs padding).
    let content = Asn1Integer::from_u64(255).encode_der().unwrap();
    assert_eq!(content, vec![0x00, 0xFF]);
}

#[test]
fn test_asn1_encode_boolean_true() {
    // DER mandates 0xFF for TRUE (X.690 §11.1).
    let b = Asn1Boolean::from(true);
    let content = b.encode_der().expect("encode TRUE");
    assert_eq!(content, vec![0xFF], "DER TRUE must be 0xFF");

    // Full TLV via Asn1Type: 01 01 FF.
    let tlv = Asn1Type::Boolean(b).encode_der().unwrap();
    assert_eq!(tlv, vec![0x01, 0x01, 0xFF], "BOOLEAN TRUE TLV");
}

#[test]
fn test_asn1_encode_boolean_false() {
    let b = Asn1Boolean::from(false);
    let content = b.encode_der().expect("encode FALSE");
    assert_eq!(content, vec![0x00], "DER FALSE must be 0x00");

    let tlv = Asn1Type::Boolean(b).encode_der().unwrap();
    assert_eq!(tlv, vec![0x01, 0x01, 0x00], "BOOLEAN FALSE TLV");
}

#[test]
fn test_asn1_encode_octet_string_empty() {
    let o = Asn1OctetString::new();
    let content = o.encode_der().expect("encode empty octet string");
    assert_eq!(content, Vec::<u8>::new(), "empty OCTET STRING content");

    // Full TLV: 04 00.
    let tlv = Asn1Type::OctetString(o).encode_der().unwrap();
    assert_eq!(tlv, vec![0x04, 0x00], "OCTET STRING empty TLV");
}

#[test]
fn test_asn1_encode_octet_string_four_bytes() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let o = Asn1OctetString::from_bytes(data.clone());
    let content = o.encode_der().unwrap();
    assert_eq!(content, data, "OCTET STRING encode_der is identity");

    let tlv = Asn1Type::OctetString(o).encode_der().unwrap();
    assert_eq!(
        tlv,
        vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF],
        "OCTET STRING 4-byte TLV"
    );
}

#[test]
fn test_asn1_encode_utf8_string_hello() {
    // UTF8String 'Hello' → TLV 0C 05 48 65 6C 6C 6F.
    let s = utf8_string("Hello");
    let tlv = Asn1Type::Utf8String(s).encode_der().unwrap();
    assert_eq!(
        tlv,
        vec![0x0C, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F],
        "UTF8String 'Hello' full TLV"
    );
}

#[test]
fn test_asn1_encode_utf8_string_empty() {
    let s = utf8_string("");
    let tlv = Asn1Type::Utf8String(s).encode_der().unwrap();
    assert_eq!(tlv, vec![0x0C, 0x00], "empty UTF8String TLV");
}

#[test]
fn test_asn1_encode_oid_common_name() {
    // OID 2.5.4.3 (commonName) → content [0x55, 0x04, 0x03].
    // First arc formula: 40*2 + 5 = 85 = 0x55.
    let oid = Asn1Object::from_oid_string("2.5.4.3").expect("parse 2.5.4.3");
    let content = oid.encode_der().expect("encode OID");
    assert_eq!(content, vec![0x55, 0x04, 0x03], "commonName OID content");

    let tlv = Asn1Type::ObjectIdentifier(oid).encode_der().unwrap();
    assert_eq!(
        tlv,
        vec![0x06, 0x03, 0x55, 0x04, 0x03],
        "commonName OID full TLV"
    );
}

#[test]
fn test_asn1_encode_oid_rsa_encryption() {
    // OID 1.2.840.113549.1.1.1 (rsaEncryption) → content bytes:
    // first arc: 40*1 + 2 = 42 = 0x2A
    // 840 base-128: 0x86 0x48 (6*128 + 72 = 840)
    // 113549 base-128: 0x86 0xF7 0x0D (6*16384 + 119*128 + 13 = 113549)
    // 1, 1, 1: single bytes 0x01 0x01 0x01.
    let oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.1").expect("parse RSA OID");
    let content = oid.encode_der().unwrap();
    assert_eq!(
        content,
        vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
        "rsaEncryption OID content"
    );

    let tlv = Asn1Type::ObjectIdentifier(oid).encode_der().unwrap();
    let mut expected = vec![0x06, 0x09];
    expected.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
    assert_eq!(tlv, expected, "rsaEncryption OID full TLV");
}

#[test]
fn test_asn1_encode_null() {
    let n = Asn1Null;
    let content = n.encode_der().expect("encode NULL");
    assert!(content.is_empty(), "NULL content must be empty");

    let tlv = Asn1Type::Null(n).encode_der().unwrap();
    assert_eq!(tlv, vec![0x05, 0x00], "NULL TLV");
}

#[test]
fn test_asn1_encode_sequence_two_elements() {
    // Build SEQUENCE { INTEGER 1, INTEGER 2 } by hand: content is the TLVs of
    // its two elements concatenated, and the wrapping tag is 0x30 (constructed
    // SEQUENCE) with that combined content length.
    let child_one = Asn1Type::Integer(Asn1Integer::from_i64(1))
        .encode_der()
        .unwrap();
    let child_two = Asn1Type::Integer(Asn1Integer::from_i64(2))
        .encode_der()
        .unwrap();
    let mut content = Vec::new();
    content.extend_from_slice(&child_one);
    content.extend_from_slice(&child_two);

    let tlv = Asn1Type::Sequence(content.clone()).encode_der().unwrap();
    let mut expected = vec![0x30, u8::try_from(content.len()).unwrap()];
    expected.extend_from_slice(&content);
    assert_eq!(tlv, expected, "SEQUENCE {{ INT 1, INT 2 }} TLV");
    // Verify exact bytes: 30 06 02 01 01 02 01 02.
    assert_eq!(tlv, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
}

#[test]
fn test_asn1_encode_bit_string_zero_unused_bits() {
    // BIT STRING with 0 unused bits + content [0xA0, 0xB0] → content [0x00, 0xA0, 0xB0].
    let mut bs = Asn1BitString::new();
    bs.set_data(&[0xA0, 0xB0], 0).expect("set_data valid args");
    let content = bs.encode_der().unwrap();
    assert_eq!(content, vec![0x00, 0xA0, 0xB0], "BIT STRING content bytes");

    let tlv = Asn1Type::BitString(bs).encode_der().unwrap();
    assert_eq!(tlv, vec![0x03, 0x03, 0x00, 0xA0, 0xB0], "BIT STRING TLV");
}

// =============================================================================
// Phase 3 — DER Decoding Tests
// =============================================================================
// Reference: test/asn1_decode_test.c, test/d2i_test.c.
//
// These tests invoke `Asn1Type::decode_der()` (full TLV) and per-type
// `decode_der()` (content-only) to verify roundtrip correctness and error
// paths. Every error check asserts `CryptoError::Encoding(_)` per R5.

#[test]
fn test_asn1_decode_integer_small_positive() {
    // TLV 02 01 2A → INTEGER 42.
    let der = vec![0x02, 0x01, 0x2A];
    let decoded = Asn1Type::decode_der(&der).expect("decode INTEGER 42");
    match decoded {
        Asn1Type::Integer(i) => assert_eq!(i.to_i64().unwrap(), 42),
        other => panic!("expected Asn1Type::Integer, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_integer_zero() {
    let der = vec![0x02, 0x01, 0x00];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    match decoded {
        Asn1Type::Integer(i) => assert_eq!(i.to_i64().unwrap(), 0),
        other => panic!("expected Integer, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_integer_negative() {
    // TLV 02 01 80 → INTEGER -128.
    let der = vec![0x02, 0x01, 0x80];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    match decoded {
        Asn1Type::Integer(i) => {
            assert!(i.is_negative(), "negative");
            assert_eq!(i.to_i64().unwrap(), -128);
        }
        other => panic!("expected Integer, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_boolean_true() {
    let der = vec![0x01, 0x01, 0xFF];
    let decoded = Asn1Type::decode_der(&der).expect("decode TRUE");
    match decoded {
        Asn1Type::Boolean(b) => assert!(b.value, "BOOLEAN TRUE"),
        other => panic!("expected Boolean, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_boolean_false() {
    let der = vec![0x01, 0x01, 0x00];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    match decoded {
        Asn1Type::Boolean(b) => assert!(!b.value),
        other => panic!("expected Boolean, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_octet_string() {
    // 04 04 DE AD BE EF.
    let der = vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    match decoded {
        Asn1Type::OctetString(o) => {
            assert_eq!(o.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(o.len(), 4);
            assert!(!o.is_empty());
        }
        other => panic!("expected OctetString, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_null() {
    let der = vec![0x05, 0x00];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    assert!(matches!(decoded, Asn1Type::Null(_)));
}

#[test]
fn test_asn1_decode_oid_common_name() {
    let der = vec![0x06, 0x03, 0x55, 0x04, 0x03];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    match decoded {
        Asn1Type::ObjectIdentifier(oid) => {
            assert_eq!(oid.to_oid_string().unwrap(), "2.5.4.3");
        }
        other => panic!("expected OID, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_nested_sequence() {
    // SEQUENCE { INTEGER 1, INTEGER 2 } = 30 06 02 01 01 02 01 02.
    // After decoding, `Sequence(Vec<u8>)` holds the raw content [02 01 01 02 01 02].
    let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    let seq_content = match decoded {
        Asn1Type::Sequence(v) => v,
        other => panic!("expected Sequence, got {other:?}"),
    };
    assert_eq!(
        seq_content,
        vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
        "SEQUENCE raw content"
    );

    // Recursively decode each child.
    let first_child = Asn1Type::decode_der(&seq_content[0..3]).unwrap();
    match first_child {
        Asn1Type::Integer(i) => assert_eq!(i.to_i64().unwrap(), 1),
        other => panic!("expected first Integer, got {other:?}"),
    }
    let second_child = Asn1Type::decode_der(&seq_content[3..6]).unwrap();
    match second_child {
        Asn1Type::Integer(i) => assert_eq!(i.to_i64().unwrap(), 2),
        other => panic!("expected second Integer, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_utf8_string() {
    // 0C 05 48 65 6C 6C 6F → UTF8String 'Hello'.
    let der = vec![0x0C, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F];
    let decoded = Asn1Type::decode_der(&der).unwrap();
    match decoded {
        Asn1Type::Utf8String(s) => {
            assert_eq!(s.tag(), Asn1Tag::Utf8String);
            assert_eq!(s.data(), b"Hello");
        }
        other => panic!("expected Utf8String, got {other:?}"),
    }
}

#[test]
fn test_asn1_decode_truncated_fails() {
    // Claims 8 bytes of content but only provides 2 → TruncatedData.
    let der = vec![0x04, 0x08, 0xAA, 0xBB];
    let err = Asn1Type::decode_der(&der).expect_err("truncated DER must fail");
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "expected Encoding error for truncated DER, got {err:?}"
    );
}

#[test]
fn test_asn1_decode_truncated_empty_buffer() {
    // An empty buffer cannot hold even a single identifier byte.
    let err = Asn1Type::decode_der(&[]).expect_err("empty DER must fail");
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "expected Encoding error for empty buffer, got {err:?}"
    );
}

#[test]
fn test_asn1_decode_invalid_tag_long_form_initial_0x80_fails() {
    // Long-form tag identifier whose first subsequent byte is 0x80 violates
    // X.690 §8.1.2.4 (leading 0x80 disallowed). `parse_tlv_header` rejects.
    let der = vec![0x1F, 0x80, 0x02, 0x01, 0x00];
    let err = parse_tlv_header(&der).expect_err("invalid long-form tag");
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "expected Encoding error, got {err:?}"
    );
}

#[test]
fn test_asn1_decode_overlength_content_fails() {
    // Length header claims 0xFF bytes but buffer only has 3 content bytes.
    let der = vec![0x04, 0xFF, 0xAA, 0xBB, 0xCC];
    let err = Asn1Type::decode_der(&der).expect_err("overlength must fail");
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "expected Encoding error, got {err:?}"
    );
}

#[test]
fn test_asn1_decode_boolean_non_canonical_fails() {
    // DER mandates 0x00 / 0xFF for BOOLEAN only.
    let err = Asn1Boolean::decode_der(&[0x01]).expect_err("non-canonical BOOLEAN");
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "expected Encoding error, got {err:?}"
    );
}

#[test]
fn test_asn1_decode_boolean_wrong_length_fails() {
    // BOOLEAN body must be exactly 1 byte.
    let err_empty = Asn1Boolean::decode_der(&[]).expect_err("empty BOOLEAN");
    assert!(matches!(err_empty, CryptoError::Encoding(_)));
    let err_multi = Asn1Boolean::decode_der(&[0x00, 0x00]).expect_err("multi-byte BOOLEAN");
    assert!(matches!(err_multi, CryptoError::Encoding(_)));
}

#[test]
fn test_asn1_decode_null_non_empty_fails() {
    // NULL must have zero content.
    let err = Asn1Null::decode_der(&[0x00]).expect_err("non-empty NULL");
    assert!(
        matches!(err, CryptoError::Encoding(_)),
        "expected Encoding error, got {err:?}"
    );
}

#[test]
fn test_asn1_decode_oid_empty_fails() {
    // Empty OID content is not a valid encoding.
    let err = Asn1Object::decode_der(&[]).expect_err("empty OID");
    assert!(matches!(err, CryptoError::Encoding(_)));
}

#[test]
fn test_asn1_decode_integer_illegal_padding_fails() {
    // 00 00 : positive padded with 0x00 when not needed (second byte high bit clear).
    let err = Asn1Integer::decode_der(&[0x00, 0x00]).expect_err("illegal INTEGER padding");
    assert!(matches!(err, CryptoError::Encoding(_)));
    // FF FF : negative padded with 0xFF when not needed (second byte high bit set).
    let err2 = Asn1Integer::decode_der(&[0xFF, 0xFF]).expect_err("illegal INTEGER padding");
    assert!(matches!(err2, CryptoError::Encoding(_)));
}

// =============================================================================
// Phase 4 — ASN.1 Time Tests
// =============================================================================
// Reference: test/asn1_time_test.c.
//
// UTCTime encoding:      YYMMDDHHMMSSZ  (RFC 5280: YY>=50 ⇒ 19YY, YY<50 ⇒ 20YY)
// GeneralizedTime:       YYYYMMDDHHMMSSZ

#[test]
fn test_asn1_utctime_encoding_format() {
    // 2024-01-02 03:04:05 UTC → "240102030405Z" (13 ASCII bytes).
    let t = Asn1Time::new(2024, 1, 2, 3, 4, 5).expect("valid time");
    assert_eq!(t.format(), TimeFormat::Utc);
    assert_eq!(t.year(), 2024);
    assert_eq!(t.month(), 1);
    assert_eq!(t.day(), 2);
    assert_eq!(t.hour(), 3);
    assert_eq!(t.minute(), 4);
    assert_eq!(t.second(), 5);

    let content = t.encode_der().expect("encode UTCTime");
    assert_eq!(content, b"240102030405Z", "UTCTime body");
    assert_eq!(t.to_string(), "240102030405Z", "UTCTime Display");
}

#[test]
fn test_asn1_utctime_year_1999() {
    // RFC 5280: YY >= 50 → 19YY. Year 1999 → "99".
    let t = Asn1Time::new(1999, 12, 31, 23, 59, 58).expect("valid 1999 time");
    assert_eq!(t.format(), TimeFormat::Utc);
    assert_eq!(t.encode_der().unwrap(), b"991231235958Z");
}

#[test]
fn test_asn1_generalizedtime_encoding_format() {
    // 2099 is outside the UTCTime 1950-2049 window → GeneralizedTime.
    let t = Asn1Time::new(2099, 12, 31, 23, 59, 58).expect("valid 2099 time");
    assert_eq!(t.format(), TimeFormat::Generalized);
    let content = t.encode_der().unwrap();
    assert_eq!(content, b"20991231235958Z", "GeneralizedTime body");
    assert_eq!(t.to_string(), "20991231235958Z");
}

#[test]
fn test_asn1_generalizedtime_year_1800() {
    let t = Asn1Time::new(1800, 6, 15, 12, 0, 0).expect("1800 valid");
    assert_eq!(t.format(), TimeFormat::Generalized);
    assert_eq!(t.encode_der().unwrap(), b"18000615120000Z");
}

#[test]
fn test_asn1_time_parse_utc_roundtrip() {
    let src = "240102030405Z";
    let t = Asn1Time::parse(src).expect("parse UTCTime");
    assert_eq!(t.year(), 2024);
    assert_eq!(t.month(), 1);
    assert_eq!(t.day(), 2);
    assert_eq!(t.format(), TimeFormat::Utc);
    assert_eq!(t.to_string(), src);
}

#[test]
fn test_asn1_time_parse_generalizedtime_roundtrip() {
    let src = "20240102030405Z";
    let t = Asn1Time::parse(src).expect("parse GeneralizedTime");
    assert_eq!(t.year(), 2024);
    assert_eq!(t.format(), TimeFormat::Generalized);
    assert_eq!(t.to_string(), src);
}

#[test]
fn test_asn1_time_parse_rejects_missing_z() {
    // Without trailing 'Z' the parse must fail.
    let err = Asn1Time::parse("240102030405").expect_err("missing Z");
    assert!(matches!(err, CryptoError::Encoding(_)));
}

#[test]
fn test_asn1_time_parse_rejects_non_digit() {
    let err = Asn1Time::parse("24x102030405Z").expect_err("non-digit");
    assert!(matches!(err, CryptoError::Encoding(_)));
}

#[test]
fn test_asn1_time_parse_rejects_invalid_month() {
    let err = Asn1Time::parse("241302030405Z").expect_err("month 13");
    assert!(matches!(err, CryptoError::Encoding(_)));
}

#[test]
fn test_asn1_time_comparison_ordering() {
    let earlier = Asn1Time::new(2024, 1, 1, 0, 0, 0).unwrap();
    let later = Asn1Time::new(2024, 12, 31, 23, 59, 59).unwrap();
    assert!(earlier < later);
    assert!(later > earlier);
    assert_eq!(earlier.cmp(&earlier), std::cmp::Ordering::Equal);
}

#[test]
fn test_asn1_time_comparison_across_format_boundary() {
    // UTCTime (2049) < GeneralizedTime (2050).
    let utc = Asn1Time::new(2049, 12, 31, 23, 59, 59).unwrap();
    let gen_time = Asn1Time::new(2050, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(utc.format(), TimeFormat::Utc);
    assert_eq!(gen_time.format(), TimeFormat::Generalized);
    assert!(utc < gen_time);
}

#[test]
fn test_asn1_time_diff_returns_delta() {
    // `diff` computes t2 - t1 i.e. other - self.
    let t1 = Asn1Time::new(2024, 1, 1, 0, 0, 0).unwrap();
    let t2 = Asn1Time::new(2024, 1, 2, 0, 0, 0).unwrap();
    let diff = t1.diff(&t2).expect("diff");
    assert_eq!(diff.days, 1);
    assert_eq!(diff.seconds, 0);
}

#[test]
fn test_asn1_time_unix_timestamp_roundtrip_epoch() {
    // Unix epoch (0) → 1970-01-01 00:00:00 UTC, encoded as UTCTime.
    let t = Asn1Time::from_unix_timestamp(0).expect("from unix 0");
    assert_eq!(t.year(), 1970);
    assert_eq!(t.month(), 1);
    assert_eq!(t.day(), 1);
    assert_eq!(t.format(), TimeFormat::Utc);
    assert_eq!(t.to_unix_timestamp().unwrap(), 0);
}

#[test]
fn test_asn1_time_encode_decode_via_asn1type_utctime() {
    // Full TLV via Asn1Type. 17 = 0x17 (UTCTime), body 13 bytes.
    let t = Asn1Time::new(2024, 1, 2, 3, 4, 5).unwrap();
    let tlv = Asn1Type::UtcTime(t).encode_der().unwrap();
    let mut expected = vec![0x17, 0x0D];
    expected.extend_from_slice(b"240102030405Z");
    assert_eq!(tlv, expected);

    let decoded = Asn1Type::decode_der(&tlv).unwrap();
    match decoded {
        Asn1Type::UtcTime(d) => assert_eq!(d, t),
        other => panic!("expected UtcTime, got {other:?}"),
    }
}

#[test]
fn test_asn1_time_encode_decode_via_asn1type_generalizedtime() {
    // 0x18 = GeneralizedTime, body 15 bytes.
    let t = Asn1Time::new(2099, 12, 31, 23, 59, 58).unwrap();
    let tlv = Asn1Type::GeneralizedTime(t).encode_der().unwrap();
    let mut expected = vec![0x18, 0x0F];
    expected.extend_from_slice(b"20991231235958Z");
    assert_eq!(tlv, expected);
    let decoded = Asn1Type::decode_der(&tlv).unwrap();
    match decoded {
        Asn1Type::GeneralizedTime(d) => assert_eq!(d, t),
        other => panic!("expected GeneralizedTime, got {other:?}"),
    }
}

// =============================================================================
// Phase 5 — Snapshot Tests (insta)
// =============================================================================
// Exact DER byte sequences are captured as named snapshots so regressions in
// encoding logic are detected immediately. Snapshots are stored as hex
// strings for readable diffs — `assert_snapshot!` uses the Display impl.

#[test]
fn test_asn1_integer_der_snapshot() {
    // Snapshot INTEGER 12345 → 02 02 30 39 (hex: "02023039").
    let i = Asn1Integer::from_i64(12345);
    let der = Asn1Type::Integer(i).encode_der().unwrap();
    let hex = hex_of(&der);
    assert_snapshot!("integer_12345_der_hex", hex);
}

#[test]
fn test_asn1_sequence_der_snapshot() {
    // Build a small X.509 DN-like SEQUENCE: SEQUENCE { SET { SEQUENCE {
    // OID(2.5.4.3) , UTF8String("Example") } } }.
    //
    // Construct bottom-up, taking each `Asn1Type::encode_der` output as the
    // child TLV and wrapping in the next-outer constructed tag.
    let cn_oid = Asn1Object::from_oid_string("2.5.4.3").unwrap();
    let cn_tlv = Asn1Type::ObjectIdentifier(cn_oid).encode_der().unwrap();
    // UTF8String("Example").
    let val_tlv = Asn1Type::Utf8String(utf8_string("Example"))
        .encode_der()
        .unwrap();
    let mut attr_type_and_value = Vec::new();
    attr_type_and_value.extend_from_slice(&cn_tlv);
    attr_type_and_value.extend_from_slice(&val_tlv);
    let atav_seq = Asn1Type::Sequence(attr_type_and_value)
        .encode_der()
        .unwrap();
    let rdn_set = Asn1Type::Set(atav_seq).encode_der().unwrap();
    let name_seq = Asn1Type::Sequence(rdn_set).encode_der().unwrap();

    assert_snapshot!("x509_dn_common_name_example_der_hex", hex_of(&name_seq));
}

#[test]
fn test_asn1_oid_der_snapshot() {
    // Well-known OIDs captured as hex-spaced sequences for readable diffs.
    let commonname = Asn1Object::from_oid_string("2.5.4.3")
        .unwrap()
        .encode_der()
        .unwrap();
    let rsa_encryption = Asn1Object::from_oid_string("1.2.840.113549.1.1.1")
        .unwrap()
        .encode_der()
        .unwrap();
    let sha256_with_rsa = Asn1Object::from_oid_string("1.2.840.113549.1.1.11")
        .unwrap()
        .encode_der()
        .unwrap();
    let p256 = Asn1Object::from_oid_string("1.2.840.10045.3.1.7")
        .unwrap()
        .encode_der()
        .unwrap();

    let rendered = format!(
        "commonName        = {}\n\
         rsaEncryption     = {}\n\
         sha256WithRSA     = {}\n\
         prime256v1 (P-256)= {}",
        hex_spaced(&commonname),
        hex_spaced(&rsa_encryption),
        hex_spaced(&sha256_with_rsa),
        hex_spaced(&p256),
    );
    assert_snapshot!("well_known_oid_der_hex", rendered);
}

// =============================================================================
// Phase 6 — Roundtrip Tests
// =============================================================================
// encode → decode correctness for each primitive (minimal, curated inputs).

#[test]
fn test_asn1_integer_roundtrip_small_values() {
    for v in [-1_i64, 0, 1, 42, 127, 128, -127, -128, 65535, -65536] {
        let original = Asn1Integer::from_i64(v);
        let tlv = Asn1Type::Integer(original.clone()).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).expect("roundtrip decode");
        match decoded {
            Asn1Type::Integer(d) => {
                assert_eq!(d.to_i64().unwrap(), v, "INTEGER roundtrip mismatch for {v}");
            }
            other => panic!("expected Integer for {v}, got {other:?}"),
        }
    }
}

#[test]
fn test_asn1_integer_roundtrip_i64_min_and_max() {
    for v in [i64::MIN, i64::MAX] {
        let original = Asn1Integer::from_i64(v);
        let tlv = Asn1Type::Integer(original).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).unwrap();
        match decoded {
            Asn1Type::Integer(d) => assert_eq!(d.to_i64().unwrap(), v),
            other => panic!("expected Integer, got {other:?}"),
        }
    }
}

#[test]
fn test_asn1_integer_roundtrip_u64() {
    for v in [0_u64, 1, 128, 255, 65535, u64::from(u32::MAX), u64::MAX] {
        let original = Asn1Integer::from_u64(v);
        let tlv = Asn1Type::Integer(original.clone()).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).unwrap();
        match decoded {
            Asn1Type::Integer(d) => {
                assert_eq!(d.to_u64().unwrap(), v, "u64 roundtrip mismatch for {v}");
            }
            other => panic!("expected Integer, got {other:?}"),
        }
    }
}

#[test]
fn test_asn1_boolean_roundtrip_true() {
    for v in [true, false] {
        let original = Asn1Boolean::from(v);
        let tlv = Asn1Type::Boolean(original).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).unwrap();
        match decoded {
            Asn1Type::Boolean(b) => assert_eq!(b.value, v),
            other => panic!("expected Boolean, got {other:?}"),
        }
    }
}

#[test]
fn test_asn1_octet_string_roundtrip() {
    for bytes in [
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0xAA, 0xBB, 0xCC, 0xDD],
        (0u8..=255).collect::<Vec<_>>(),
    ] {
        let original = Asn1OctetString::from_bytes(bytes.clone());
        let tlv = Asn1Type::OctetString(original).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).unwrap();
        match decoded {
            Asn1Type::OctetString(o) => assert_eq!(o.data(), bytes.as_slice()),
            other => panic!("expected OctetString, got {other:?}"),
        }
    }
}

#[test]
fn test_asn1_string_roundtrip_utf8() {
    for text in ["", "A", "Hello, World!", "UTF-8: ½→©"] {
        let original = utf8_string(text);
        let tlv = Asn1Type::Utf8String(original).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).unwrap();
        match decoded {
            Asn1Type::Utf8String(s) => {
                assert_eq!(s.data(), text.as_bytes(), "UTF8 roundtrip for {text:?}");
                assert_eq!(s.tag(), Asn1Tag::Utf8String);
            }
            other => panic!("expected Utf8String, got {other:?}"),
        }
    }
}

#[test]
fn test_asn1_null_roundtrip() {
    let tlv = Asn1Type::Null(Asn1Null).encode_der().unwrap();
    let decoded = Asn1Type::decode_der(&tlv).unwrap();
    assert!(matches!(decoded, Asn1Type::Null(_)));
}

#[test]
fn test_asn1_oid_roundtrip() {
    for oid_str in [
        "2.5.4.3",
        "1.2.840.113549.1.1.1",
        "1.2.840.113549.1.1.11",
        "1.3.132.0.34",
        "2.16.840.1.101.3.4.2.1",
    ] {
        let original = Asn1Object::from_oid_string(oid_str).unwrap();
        let tlv = Asn1Type::ObjectIdentifier(original).encode_der().unwrap();
        let decoded = Asn1Type::decode_der(&tlv).unwrap();
        match decoded {
            Asn1Type::ObjectIdentifier(d) => {
                assert_eq!(d.to_oid_string().unwrap(), oid_str, "OID roundtrip");
            }
            other => panic!("expected OID, got {other:?}"),
        }
    }
}

// =============================================================================
// Additional TLV / header / type-level tests
// =============================================================================

#[test]
fn test_write_tlv_header_short_length() {
    // Short-form length (<128) is a single byte.
    let hdr = write_tlv_header(Asn1Tag::Integer, Asn1Class::Universal, false, 1).unwrap();
    assert_eq!(hdr, vec![0x02, 0x01], "short-form length");
}

#[test]
fn test_write_tlv_header_long_length_two_bytes() {
    // 300 requires long-form length: 0x82 0x01 0x2C (300 = 0x012C).
    let hdr = write_tlv_header(Asn1Tag::OctetString, Asn1Class::Universal, false, 300).unwrap();
    assert_eq!(hdr, vec![0x04, 0x82, 0x01, 0x2C], "long-form length (300)");
}

#[test]
fn test_write_tlv_header_long_length_one_byte() {
    // 128 requires long-form length: 0x81 0x80.
    let hdr = write_tlv_header(Asn1Tag::OctetString, Asn1Class::Universal, false, 128).unwrap();
    assert_eq!(hdr, vec![0x04, 0x81, 0x80], "long-form length (128)");
}

#[test]
fn test_write_tlv_header_constructed_sequence() {
    // SEQUENCE is constructed → identifier byte sets bit 0x20. Universal | 0x20 | tag=16 = 0x30.
    let hdr = write_tlv_header(Asn1Tag::Sequence, Asn1Class::Universal, true, 5).unwrap();
    assert_eq!(hdr, vec![0x30, 0x05]);
}

#[test]
fn test_write_tlv_header_context_specific_class() {
    // Context-specific class = 0x80 base. Tag 0, primitive, length 3.
    let hdr = write_tlv_header(Asn1Tag::Eoc, Asn1Class::ContextSpecific, false, 3).unwrap();
    assert_eq!(hdr[0], 0x80, "context-specific [0] implicit");
    assert_eq!(hdr[1], 0x03);
}

#[test]
fn test_parse_tlv_header_short_length() {
    // 02 01 2A → INTEGER tag, universal, primitive, 1 byte content.
    let header = parse_tlv_header(&[0x02, 0x01, 0x2A]).unwrap();
    assert_eq!(header.tag, Asn1Tag::Integer);
    assert_eq!(header.class, Asn1Class::Universal);
    assert!(!header.constructed);
    assert_eq!(header.content_length, Some(1));
    assert_eq!(header.header_length, 2);
}

#[test]
fn test_parse_tlv_header_long_length() {
    // 04 82 01 2C : OCTET STRING, length 300. Header length 4.
    let der = vec![0x04, 0x82, 0x01, 0x2C];
    let header = parse_tlv_header(&der).unwrap();
    assert_eq!(header.tag, Asn1Tag::OctetString);
    assert_eq!(header.content_length, Some(300));
    assert_eq!(header.header_length, 4);
}

#[test]
fn test_parse_tlv_header_constructed_sequence() {
    let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let header = parse_tlv_header(&der).unwrap();
    assert_eq!(header.tag, Asn1Tag::Sequence);
    assert!(header.constructed);
    assert_eq!(header.content_length, Some(6));
}

#[test]
fn test_asn1_tag_discriminants() {
    // Verify a handful of universal tag discriminants match X.690.
    assert_eq!(Asn1Tag::Boolean as u32, 1);
    assert_eq!(Asn1Tag::Integer as u32, 2);
    assert_eq!(Asn1Tag::BitString as u32, 3);
    assert_eq!(Asn1Tag::OctetString as u32, 4);
    assert_eq!(Asn1Tag::Null as u32, 5);
    assert_eq!(Asn1Tag::ObjectIdentifier as u32, 6);
    assert_eq!(Asn1Tag::Utf8String as u32, 12);
    assert_eq!(Asn1Tag::Sequence as u32, 16);
    assert_eq!(Asn1Tag::Set as u32, 17);
    assert_eq!(Asn1Tag::UtcTime as u32, 23);
    assert_eq!(Asn1Tag::GeneralizedTime as u32, 24);
}

#[test]
fn test_asn1_class_identifier_bytes() {
    // Class is encoded in the top two bits of the identifier byte.
    assert_eq!(Asn1Class::Universal as u8, 0x00);
    assert_eq!(Asn1Class::Application as u8, 0x40);
    assert_eq!(Asn1Class::ContextSpecific as u8, 0x80);
    assert_eq!(Asn1Class::Private as u8, 0xC0);
}

#[test]
fn test_asn1_string_flags_default_empty() {
    let s = Asn1String::new(Asn1Tag::PrintableString);
    assert_eq!(s.tag(), Asn1Tag::PrintableString);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.flags(), StringFlags::empty());
}

#[test]
fn test_asn1_string_duplicate_creates_equal_copy() {
    let mut s = Asn1String::new(Asn1Tag::Utf8String);
    s.set(b"hello").unwrap();
    let dup = s.duplicate();
    assert_eq!(s, dup, "duplicate must equal original");
    assert_eq!(dup.data(), b"hello");
    assert_eq!(dup.tag(), Asn1Tag::Utf8String);
}

#[test]
fn test_asn1_enumerated_roundtrip() {
    // Asn1Enumerated delegates to Asn1Integer underneath.
    let e = Asn1Enumerated::from_i64(17);
    let tlv = Asn1Type::Enumerated(e).encode_der().unwrap();
    assert_eq!(tlv[0], 0x0A, "ENUMERATED tag = 10 (0x0A)");
    let decoded = Asn1Type::decode_der(&tlv).unwrap();
    match decoded {
        Asn1Type::Enumerated(d) => assert_eq!(d.to_i64().unwrap(), 17),
        other => panic!("expected Enumerated, got {other:?}"),
    }
}

#[test]
fn test_asn1_bit_string_set_and_check_bit() {
    let mut bs = Asn1BitString::new();
    bs.set_bit(0, true).expect("set bit 0");
    bs.set_bit(7, true).expect("set bit 7");
    assert!(bs.check_bit(0));
    assert!(bs.check_bit(7));
    assert!(!bs.check_bit(3));
}

#[test]
fn test_asn1_bit_string_roundtrip() {
    let mut bs = Asn1BitString::new();
    bs.set_data(&[0xA0, 0xB0], 4)
        .expect("valid BIT STRING payload");
    let tlv = Asn1Type::BitString(bs.clone()).encode_der().unwrap();
    let decoded = Asn1Type::decode_der(&tlv).unwrap();
    match decoded {
        Asn1Type::BitString(d) => {
            assert_eq!(d.unused_bits(), 4);
            assert_eq!(d.data(), &[0xA0, 0xB0]);
        }
        other => panic!("expected BitString, got {other:?}"),
    }
}

#[test]
fn test_algorithm_identifier_decode_sha256_with_rsa() {
    // Construct AlgorithmIdentifier(sha256WithRSAEncryption, NULL) content bytes
    // and round-trip it.
    let algo = Asn1Object::from_oid_string("1.2.840.113549.1.1.11").unwrap();
    let params = Some(Asn1Type::Null(Asn1Null));
    let ai = AlgorithmIdentifier::new(algo.clone(), params.clone());
    let encoded = ai.encode_der().expect("encode AlgorithmIdentifier");
    let decoded = AlgorithmIdentifier::decode_der(&encoded).expect("decode");
    assert_eq!(
        decoded.algorithm.to_oid_string().unwrap(),
        algo.to_oid_string().unwrap()
    );
    assert!(matches!(decoded.parameters, Some(Asn1Type::Null(_))));
}

#[test]
fn test_digest_info_roundtrip() {
    let algo = Asn1Object::from_oid_string("2.16.840.1.101.3.4.2.1").unwrap(); // SHA-256
    let ai = AlgorithmIdentifier::new(algo, Some(Asn1Type::Null(Asn1Null)));
    let digest = Asn1OctetString::from_bytes(vec![0x11; 32]);
    let di = DigestInfo::new(ai.clone(), digest.clone());
    let encoded = di.encode_der().expect("encode DigestInfo");
    let decoded = DigestInfo::decode_der(&encoded).expect("decode DigestInfo");
    assert_eq!(
        decoded.digest_algorithm.algorithm.to_oid_string().unwrap(),
        ai.algorithm.to_oid_string().unwrap()
    );
    assert_eq!(decoded.digest.data(), &[0x11; 32]);
}

#[test]
fn test_validity_roundtrip_and_ordering() {
    let nb = Asn1Time::new(2024, 1, 1, 0, 0, 0).unwrap();
    let na = Asn1Time::new(2024, 12, 31, 23, 59, 59).unwrap();
    let v = Validity::new(nb, na);
    assert!(v.is_valid(), "not_before <= not_after");
    let encoded = v.encode_der().unwrap();
    let decoded = Validity::decode_der(&encoded).unwrap();
    assert_eq!(decoded.not_before, nb);
    assert_eq!(decoded.not_after, na);

    // Inverted validity is flagged by `is_valid()`.
    let invalid = Validity::new(na, nb);
    assert!(!invalid.is_valid());
}

#[test]
fn test_asn1_type_partial_eq_matches_der_equality() {
    // Semantics of `PartialEq` for `Asn1Type` are defined via DER equality.
    let a = Asn1Type::Integer(Asn1Integer::from_i64(42));
    let b = Asn1Type::Integer(Asn1Integer::from_i64(42));
    let c = Asn1Type::Integer(Asn1Integer::from_i64(43));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_tlv_header_struct_fields_public() {
    // Directly exercise `TlvHeader`'s public fields per the AAP API contract.
    let hdr = TlvHeader {
        tag: Asn1Tag::Integer,
        class: Asn1Class::Universal,
        constructed: false,
        content_length: Some(1),
        header_length: 2,
    };
    assert_eq!(hdr.tag, Asn1Tag::Integer);
    assert_eq!(hdr.class, Asn1Class::Universal);
    assert!(!hdr.constructed);
    assert_eq!(hdr.content_length, Some(1));
    assert_eq!(hdr.header_length, 2);
}

// =============================================================================
// Phase 7 — Property-Based Tests (proptest)
// =============================================================================
// Randomised roundtrip verification establishes that encode ∘ decode = identity
// across the full i64 / byte-vector input domains. Following test_pem.rs, we
// surface internal errors via `TestCaseError::fail` so proptest shrinks.

proptest! {
    /// For every `i64`, encoding as an INTEGER TLV and decoding must recover
    /// the original value exactly. Covers the boundary cases `i64::MIN`,
    /// `i64::MAX`, zero, and all sign/padding transitions.
    #[test]
    fn prop_asn1_integer_roundtrip(val in any::<i64>()) {
        let original = Asn1Integer::from_i64(val);
        let encoded = Asn1Type::Integer(original.clone())
            .encode_der()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        let decoded = Asn1Type::decode_der(&encoded)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        match decoded {
            Asn1Type::Integer(d) => prop_assert_eq!(d.to_i64().ok(), Some(val)),
            _ => prop_assert!(false, "expected Asn1Type::Integer"),
        }
    }
}

proptest! {
    /// For every u64 value, u64 → INTEGER encode → decode round-trips correctly.
    #[test]
    fn prop_asn1_integer_u64_roundtrip(val in any::<u64>()) {
        let original = Asn1Integer::from_u64(val);
        let encoded = Asn1Type::Integer(original)
            .encode_der()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        let decoded = Asn1Type::decode_der(&encoded)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        match decoded {
            Asn1Type::Integer(d) => prop_assert_eq!(d.to_u64().ok(), Some(val)),
            _ => prop_assert!(false, "expected Asn1Type::Integer"),
        }
    }
}

proptest! {
    /// For every byte vector of length 0..1024, encoding as an OCTET STRING
    /// TLV and decoding must recover the original bytes exactly.
    #[test]
    fn prop_asn1_octet_string_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0..1024usize)
    ) {
        let original = Asn1OctetString::from_bytes(data.clone());
        let encoded = Asn1Type::OctetString(original)
            .encode_der()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        let decoded = Asn1Type::decode_der(&encoded)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        match decoded {
            Asn1Type::OctetString(o) => prop_assert_eq!(o.data(), data.as_slice()),
            _ => prop_assert!(false, "expected Asn1Type::OctetString"),
        }
    }
}

proptest! {
    /// Boolean roundtrip is trivial but locks in the DER canonical encoding
    /// (`0xFF` for TRUE, `0x00` for FALSE).
    #[test]
    fn prop_asn1_boolean_roundtrip(val in any::<bool>()) {
        let original = Asn1Boolean::from(val);
        let encoded = Asn1Type::Boolean(original)
            .encode_der()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        let decoded = Asn1Type::decode_der(&encoded)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        match decoded {
            Asn1Type::Boolean(b) => prop_assert_eq!(b.value, val),
            _ => prop_assert!(false, "expected Asn1Type::Boolean"),
        }
    }
}

proptest! {
    /// UTF8 strings of ASCII printable characters roundtrip via `Asn1String`.
    /// The character set is restricted so the generated bytes are valid UTF-8.
    #[test]
    fn prop_asn1_utf8_string_roundtrip(text in "[ -~]{0,256}") {
        let mut s = Asn1String::new(Asn1Tag::Utf8String);
        s.set(text.as_bytes())
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        let encoded = Asn1Type::Utf8String(s)
            .encode_der()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        let decoded = Asn1Type::decode_der(&encoded)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{e}")))?;
        match decoded {
            Asn1Type::Utf8String(d) => {
                prop_assert_eq!(d.tag(), Asn1Tag::Utf8String);
                prop_assert_eq!(d.data(), text.as_bytes());
            }
            _ => prop_assert!(false, "expected Utf8String"),
        }
    }
}
