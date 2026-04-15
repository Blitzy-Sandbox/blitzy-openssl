//! Tests for the `openssl_common::types` module.
//!
//! Exercises the public API for `Nid`, `ProtocolVersion`, `PaddingMode`,
//! `KeyType`, `CipherMode`, `OperationType`, and the `AlgorithmName` trait.
//! Complements inline unit tests with cross-module integration, serde
//! serialization round-trips, and edge-case coverage.
#![allow(clippy::expect_used)]

use crate::types::{
    AlgorithmName, CipherMode, KeyType, Nid, OperationType, PaddingMode, ProtocolVersion,
};

// =============================================================================
// Nid — Newtype Wrapper
// =============================================================================

#[test]
fn nid_from_raw_and_as_raw_roundtrip() {
    for raw in [0, 4, 64, 672, 673, 674, 895, 901, 1018, 1087, 1034, 1455, i32::MAX] {
        let nid = Nid::from_raw(raw);
        assert_eq!(nid.as_raw(), raw);
    }
}

#[test]
fn nid_undef_constant_is_zero() {
    assert_eq!(Nid::UNDEF.as_raw(), 0);
    assert!(Nid::UNDEF.is_undef());
}

#[test]
fn nid_named_constants_are_not_undef() {
    let named = [
        Nid::MD5,
        Nid::SHA1,
        Nid::SHA256,
        Nid::SHA384,
        Nid::SHA512,
        Nid::SHA3_256,
        Nid::SHA3_384,
        Nid::SHA3_512,
        Nid::AES_128_GCM,
        Nid::AES_256_GCM,
        Nid::CHACHA20_POLY1305,
        Nid::RSA,
        Nid::EC,
        Nid::ED25519,
        Nid::X25519,
        Nid::ML_KEM_768,
    ];
    for nid in named {
        assert!(!nid.is_undef(), "{nid:?} should not be UNDEF");
    }
}

#[test]
fn nid_equality_and_ordering() {
    assert_eq!(Nid::SHA256, Nid::from_raw(672));
    assert_ne!(Nid::SHA256, Nid::SHA512);
    assert!(Nid::MD5 < Nid::SHA1);
    assert!(Nid::SHA1 < Nid::SHA256);
}

#[test]
fn nid_display_format() {
    assert_eq!(format!("{}", Nid::SHA256), "NID(672)");
    assert_eq!(format!("{}", Nid::UNDEF), "NID(0)");
    assert_eq!(format!("{}", Nid::from_raw(9999)), "NID(9999)");
}

#[test]
fn nid_copy_semantics() {
    let a = Nid::SHA256;
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn nid_hash_usable_in_collections() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(Nid::SHA256);
    set.insert(Nid::SHA512);
    set.insert(Nid::SHA256); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn nid_serde_roundtrip() {
    let nid = Nid::SHA256;
    let json = serde_json::to_string(&nid).expect("Nid should serialize");
    let deserialized: Nid = serde_json::from_str(&json).expect("Nid should deserialize");
    assert_eq!(nid, deserialized);
}

// =============================================================================
// ProtocolVersion — Enum Mapping
// =============================================================================

#[test]
fn protocol_version_all_variants_roundtrip() {
    let versions = [
        (ProtocolVersion::Ssl3_0, 0x0300u16),
        (ProtocolVersion::Tls1_0, 0x0301),
        (ProtocolVersion::Tls1_1, 0x0302),
        (ProtocolVersion::Tls1_2, 0x0303),
        (ProtocolVersion::Tls1_3, 0x0304),
        (ProtocolVersion::Dtls1_0, 0xFEFF),
        (ProtocolVersion::Dtls1_2, 0xFEFD),
    ];
    for (version, raw) in versions {
        assert_eq!(version.as_raw(), raw, "{version:?} raw mismatch");
        assert_eq!(
            ProtocolVersion::from_raw(raw),
            Some(version),
            "from_raw({raw:#06x}) mismatch"
        );
    }
}

#[test]
fn protocol_version_from_raw_unknown_returns_none() {
    assert_eq!(ProtocolVersion::from_raw(0x0000), None);
    assert_eq!(ProtocolVersion::from_raw(0xFFFF), None);
    assert_eq!(ProtocolVersion::from_raw(0x0305), None);
    assert_eq!(ProtocolVersion::from_raw(0x0299), None);
}

#[test]
fn protocol_version_is_tls_classification() {
    assert!(ProtocolVersion::Ssl3_0.is_tls());
    assert!(ProtocolVersion::Tls1_0.is_tls());
    assert!(ProtocolVersion::Tls1_1.is_tls());
    assert!(ProtocolVersion::Tls1_2.is_tls());
    assert!(ProtocolVersion::Tls1_3.is_tls());
    assert!(!ProtocolVersion::Dtls1_0.is_tls());
    assert!(!ProtocolVersion::Dtls1_2.is_tls());
}

#[test]
fn protocol_version_is_dtls_classification() {
    assert!(ProtocolVersion::Dtls1_0.is_dtls());
    assert!(ProtocolVersion::Dtls1_2.is_dtls());
    assert!(!ProtocolVersion::Ssl3_0.is_dtls());
    assert!(!ProtocolVersion::Tls1_3.is_dtls());
}

#[test]
fn protocol_version_display_format() {
    assert_eq!(format!("{}", ProtocolVersion::Ssl3_0), "SSLv3");
    assert_eq!(format!("{}", ProtocolVersion::Tls1_0), "TLSv1.0");
    assert_eq!(format!("{}", ProtocolVersion::Tls1_3), "TLSv1.3");
    assert_eq!(format!("{}", ProtocolVersion::Dtls1_0), "DTLSv1.0");
    assert_eq!(format!("{}", ProtocolVersion::Dtls1_2), "DTLSv1.2");
}

#[test]
fn protocol_version_serde_roundtrip() {
    let ver = ProtocolVersion::Tls1_3;
    let json = serde_json::to_string(&ver).expect("ProtocolVersion should serialize");
    let deser: ProtocolVersion =
        serde_json::from_str(&json).expect("ProtocolVersion should deserialize");
    assert_eq!(ver, deser);
}

// =============================================================================
// PaddingMode — Enum
// =============================================================================

#[test]
fn padding_mode_all_variants_distinct() {
    let modes = [
        PaddingMode::None,
        PaddingMode::Pkcs7,
        PaddingMode::OaepSha1,
        PaddingMode::OaepSha256,
        PaddingMode::Pss,
        PaddingMode::Iso10126,
        PaddingMode::Ansi923,
    ];
    // All variants are distinct from each other.
    for (i, a) in modes.iter().enumerate() {
        for (j, b) in modes.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b, "{a:?} should differ from {b:?}");
            }
        }
    }
}

#[test]
fn padding_mode_display() {
    assert_eq!(format!("{}", PaddingMode::None), "none");
    assert_eq!(format!("{}", PaddingMode::Pkcs7), "PKCS#7");
    assert_eq!(format!("{}", PaddingMode::OaepSha1), "OAEP-SHA1");
    assert_eq!(format!("{}", PaddingMode::OaepSha256), "OAEP-SHA256");
    assert_eq!(format!("{}", PaddingMode::Pss), "PSS");
    assert_eq!(format!("{}", PaddingMode::Iso10126), "ISO-10126");
    assert_eq!(format!("{}", PaddingMode::Ansi923), "ANSI-X9.23");
}

#[test]
fn padding_mode_serde_roundtrip() {
    let mode = PaddingMode::OaepSha256;
    let json = serde_json::to_string(&mode).expect("PaddingMode should serialize");
    let deser: PaddingMode = serde_json::from_str(&json).expect("PaddingMode should deserialize");
    assert_eq!(mode, deser);
}

// =============================================================================
// KeyType — Algorithm Classification
// =============================================================================

#[test]
fn key_type_to_nid_from_nid_roundtrip_all_variants() {
    let key_types = [
        KeyType::Rsa,
        KeyType::RsaPss,
        KeyType::Dh,
        KeyType::Dsa,
        KeyType::Ec,
        KeyType::Ed25519,
        KeyType::Ed448,
        KeyType::X25519,
        KeyType::X448,
        KeyType::MlKem512,
        KeyType::MlKem768,
        KeyType::MlKem1024,
        KeyType::MlDsa44,
        KeyType::MlDsa65,
        KeyType::MlDsa87,
        KeyType::SlhDsa,
        KeyType::Lms,
        KeyType::Hmac,
        KeyType::Cmac,
    ];
    for kt in key_types {
        let nid = kt.to_nid();
        let recovered = KeyType::from_nid(nid);
        assert_eq!(
            recovered,
            Some(kt),
            "KeyType::{kt:?} NID roundtrip failed"
        );
    }
}

#[test]
fn key_type_from_nid_unknown_returns_none() {
    assert_eq!(KeyType::from_nid(Nid::UNDEF), None);
    assert_eq!(KeyType::from_nid(Nid::from_raw(99999)), None);
    assert_eq!(KeyType::from_nid(Nid::from_raw(-1)), None);
}

#[test]
fn key_type_asymmetric_classification() {
    // All key types are asymmetric except Hmac and Cmac.
    let asymmetric_types = [
        KeyType::Rsa,
        KeyType::RsaPss,
        KeyType::Dh,
        KeyType::Dsa,
        KeyType::Ec,
        KeyType::Ed25519,
        KeyType::Ed448,
        KeyType::X25519,
        KeyType::X448,
        KeyType::MlKem512,
        KeyType::MlKem768,
        KeyType::MlKem1024,
        KeyType::MlDsa44,
        KeyType::MlDsa65,
        KeyType::MlDsa87,
        KeyType::SlhDsa,
        KeyType::Lms,
    ];
    for kt in asymmetric_types {
        assert!(kt.is_asymmetric(), "{kt:?} should be asymmetric");
    }

    assert!(!KeyType::Hmac.is_asymmetric(), "HMAC should not be asymmetric");
    assert!(!KeyType::Cmac.is_asymmetric(), "CMAC should not be asymmetric");
}

#[test]
fn key_type_post_quantum_classification() {
    let pq_types = [
        KeyType::MlKem512,
        KeyType::MlKem768,
        KeyType::MlKem1024,
        KeyType::MlDsa44,
        KeyType::MlDsa65,
        KeyType::MlDsa87,
        KeyType::SlhDsa,
        KeyType::Lms,
    ];
    for kt in pq_types {
        assert!(kt.is_post_quantum(), "{kt:?} should be post-quantum");
    }

    let classical = [
        KeyType::Rsa,
        KeyType::RsaPss,
        KeyType::Dh,
        KeyType::Dsa,
        KeyType::Ec,
        KeyType::Ed25519,
        KeyType::Ed448,
        KeyType::X25519,
        KeyType::X448,
        KeyType::Hmac,
        KeyType::Cmac,
    ];
    for kt in classical {
        assert!(!kt.is_post_quantum(), "{kt:?} should NOT be post-quantum");
    }
}

#[test]
fn key_type_display_format() {
    assert_eq!(format!("{}", KeyType::Rsa), "RSA");
    assert_eq!(format!("{}", KeyType::Ed25519), "Ed25519");
    assert_eq!(format!("{}", KeyType::MlKem768), "ML-KEM-768");
    assert_eq!(format!("{}", KeyType::SlhDsa), "SLH-DSA");
    assert_eq!(format!("{}", KeyType::Hmac), "HMAC");
    assert_eq!(format!("{}", KeyType::Cmac), "CMAC");
}

#[test]
fn key_type_serde_roundtrip() {
    let kt = KeyType::MlDsa65;
    let json = serde_json::to_string(&kt).expect("KeyType should serialize");
    let deser: KeyType = serde_json::from_str(&json).expect("KeyType should deserialize");
    assert_eq!(kt, deser);
}

// =============================================================================
// CipherMode — Enum
// =============================================================================

#[test]
fn cipher_mode_all_variants_distinct() {
    let modes = [
        CipherMode::Ecb,
        CipherMode::Cbc,
        CipherMode::Cfb,
        CipherMode::Ofb,
        CipherMode::Ctr,
        CipherMode::Gcm,
        CipherMode::Ccm,
        CipherMode::Xts,
        CipherMode::Wrap,
        CipherMode::WrapPad,
        CipherMode::Ocb,
        CipherMode::Siv,
        CipherMode::GcmSiv,
        CipherMode::Stream,
    ];
    for (i, a) in modes.iter().enumerate() {
        for (j, b) in modes.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "{a:?} should differ from {b:?}");
            }
        }
    }
}

#[test]
fn cipher_mode_display() {
    assert_eq!(format!("{}", CipherMode::Ecb), "ECB");
    assert_eq!(format!("{}", CipherMode::Gcm), "GCM");
    assert_eq!(format!("{}", CipherMode::Xts), "XTS");
    assert_eq!(format!("{}", CipherMode::GcmSiv), "GCM-SIV");
    assert_eq!(format!("{}", CipherMode::Stream), "STREAM");
}

#[test]
fn cipher_mode_serde_roundtrip() {
    let mode = CipherMode::Gcm;
    let json = serde_json::to_string(&mode).expect("CipherMode should serialize");
    let deser: CipherMode = serde_json::from_str(&json).expect("CipherMode should deserialize");
    assert_eq!(mode, deser);
}

// =============================================================================
// OperationType — Enum
// =============================================================================

#[test]
fn operation_type_all_variants_display() {
    let ops = [
        (OperationType::Digest, "digest"),
        (OperationType::Cipher, "cipher"),
        (OperationType::Mac, "mac"),
        (OperationType::Kdf, "kdf"),
        (OperationType::Rand, "rand"),
        (OperationType::KeyMgmt, "keymgmt"),
        (OperationType::Signature, "signature"),
        (OperationType::AsymCipher, "asymcipher"),
        (OperationType::Kem, "kem"),
        (OperationType::KeyExch, "keyexch"),
        (OperationType::EncoderDecoder, "encoder_decoder"),
        (OperationType::Store, "store"),
    ];
    for (op, expected) in ops {
        assert_eq!(format!("{op}"), expected, "{op:?} display mismatch");
    }
}

#[test]
fn operation_type_serde_roundtrip() {
    let op = OperationType::Signature;
    let json = serde_json::to_string(&op).expect("OperationType should serialize");
    let deser: OperationType =
        serde_json::from_str(&json).expect("OperationType should deserialize");
    assert_eq!(op, deser);
}

// =============================================================================
// AlgorithmName — Trait
// =============================================================================

#[test]
fn algorithm_name_trait_custom_implementation() {
    struct TestDigest;

    impl AlgorithmName for TestDigest {
        fn algorithm_name(&self) -> &'static str {
            "SHA2-256"
        }
        fn nid(&self) -> Nid {
            Nid::SHA256
        }
    }

    let d = TestDigest;
    assert_eq!(d.algorithm_name(), "SHA2-256");
    assert_eq!(d.nid(), Nid::SHA256);
    assert_eq!(d.nid().as_raw(), 672);
}

#[test]
fn algorithm_name_trait_object_usage() {
    struct MockCipher;

    impl AlgorithmName for MockCipher {
        fn algorithm_name(&self) -> &'static str {
            "AES-128-GCM"
        }
        fn nid(&self) -> Nid {
            Nid::AES_128_GCM
        }
    }

    // Verify the trait works as a trait object (dynamic dispatch).
    let algo: Box<dyn AlgorithmName> = Box::new(MockCipher);
    assert_eq!(algo.algorithm_name(), "AES-128-GCM");
    assert_eq!(algo.nid(), Nid::AES_128_GCM);
}
