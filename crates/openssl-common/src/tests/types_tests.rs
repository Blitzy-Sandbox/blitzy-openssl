//! Tests for shared type definitions in openssl-common.
//!
//! Exercises the public API for [`Nid`], [`ProtocolVersion`], [`PaddingMode`],
//! [`KeyType`], [`CipherMode`], [`OperationType`], and the [`AlgorithmName`]
//! trait. Validates round-trip conversions, enum exhaustiveness, trait derives
//! (Clone, Copy, Hash, Debug, Display, Serialize, Deserialize), and correct
//! NID constant values derived from C `include/openssl/obj_mac.h`.
//!
//! # Rules Enforced
//!
//! - **Rule R5 (Nullability):** All `from_*` methods tested for `None` on
//!   unknown input — never sentinel values.
//! - **Rule R6 (Lossless Casts):** No bare `as` casts — typed conversions only.
//! - **Rule R8 (Zero Unsafe):** Zero `unsafe` blocks in this file.
//! - **Rule R9 (Warning-Free):** Compiles with `RUSTFLAGS="-D warnings"`.
//! - **Rule R10 (Wiring):** Tests exercise the `types` module through its
//!   public API, verifying it is reachable from the workspace.
#![allow(clippy::expect_used)]

use crate::types::{
    AlgorithmName, CipherMode, KeyType, Nid, OperationType, PaddingMode, ProtocolVersion,
};
use std::collections::HashSet;

// =============================================================================
// Phase 2: Nid — Newtype Wrapper Tests
// =============================================================================

/// Verifies `Nid::UNDEF` has raw value 0 and `is_undef()` returns true.
#[test]
fn nid_undef() {
    assert_eq!(Nid::UNDEF.as_raw(), 0);
    assert!(Nid::UNDEF.is_undef());
}

/// Verifies `Nid::from_raw(672)` produces the same Nid as `Nid::SHA256`.
#[test]
fn nid_from_raw() {
    assert_eq!(Nid::from_raw(672), Nid::SHA256);
}

/// Verifies `Nid::SHA256.as_raw()` returns 672.
#[test]
fn nid_as_raw() {
    assert_eq!(Nid::SHA256.as_raw(), 672);
}

/// Verifies round-trip: `from_raw(as_raw())` identity for several values.
#[test]
fn nid_from_raw_and_as_raw_roundtrip() {
    for raw in [
        0,
        4,
        64,
        672,
        673,
        674,
        895,
        901,
        1018,
        1087,
        1034,
        1455,
        i32::MAX,
    ] {
        let nid = Nid::from_raw(raw);
        assert_eq!(nid.as_raw(), raw, "Round-trip failed for raw={raw}");
    }
}

/// Verifies `Nid::from_raw(64) == Nid::SHA1` — both represent NID 64.
#[test]
fn nid_equality() {
    assert_eq!(Nid::from_raw(64), Nid::SHA1);
    assert_eq!(Nid::SHA256, Nid::from_raw(672));
    assert_ne!(Nid::SHA256, Nid::SHA512);
}

/// Verifies `Nid::MD5 < Nid::SHA1` (NID 4 < NID 64).
#[test]
fn nid_ordering() {
    assert!(Nid::MD5 < Nid::SHA1);
    assert!(Nid::SHA1 < Nid::SHA256);
    assert!(Nid::UNDEF < Nid::MD5);
}

/// Inserts multiple Nids into a `HashSet`, verifies deduplication and lookup.
#[test]
fn nid_hash() {
    let mut set = HashSet::new();
    set.insert(Nid::SHA256);
    set.insert(Nid::SHA512);
    set.insert(Nid::MD5);
    set.insert(Nid::SHA256); // duplicate — should not increase count
    assert_eq!(set.len(), 3);
    assert!(set.contains(&Nid::SHA256));
    assert!(set.contains(&Nid::SHA512));
    assert!(set.contains(&Nid::MD5));
    assert!(!set.contains(&Nid::SHA1));
}

/// Verifies `format!("{}", Nid::SHA256)` contains "NID(672)" or similar.
#[test]
fn nid_display() {
    assert_eq!(format!("{}", Nid::SHA256), "NID(672)");
    assert_eq!(format!("{}", Nid::UNDEF), "NID(0)");
    assert_eq!(format!("{}", Nid::from_raw(9999)), "NID(9999)");
}

/// Verifies Clone and Copy semantics — assign to two variables, both valid.
#[test]
fn nid_clone_copy() {
    let a = Nid::SHA256;
    let b = a; // Copy
    let c = a; // Copy (Nid implements Copy)
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a.as_raw(), 672);
    assert_eq!(b.as_raw(), 672);
    assert_eq!(c.as_raw(), 672);
}

/// Verifies `format!("{:?}", Nid::SHA256)` produces valid Debug output.
#[test]
fn nid_debug() {
    let debug_str = format!("{:?}", Nid::SHA256);
    assert!(!debug_str.is_empty());
    // Debug repr should contain the raw value
    assert!(
        debug_str.contains("672") || debug_str.contains("Nid"),
        "Debug output '{debug_str}' should contain '672' or 'Nid'"
    );
}

/// Verifies well-known NID constants match their C `obj_mac.h` values.
#[test]
fn nid_known_constants() {
    assert_eq!(Nid::MD5.as_raw(), 4, "NID_md5");
    assert_eq!(Nid::SHA1.as_raw(), 64, "NID_sha1");
    assert_eq!(Nid::SHA256.as_raw(), 672, "NID_sha256");
    assert_eq!(Nid::RSA.as_raw(), 6, "NID_rsaEncryption");
    assert_eq!(Nid::EC.as_raw(), 408, "NID_X9_62_id_ecPublicKey");
    assert_eq!(Nid::ED25519.as_raw(), 1087, "NID_ED25519");
    assert_eq!(Nid::X25519.as_raw(), 1034, "NID_X25519");
    assert_eq!(Nid::AES_128_GCM.as_raw(), 895, "NID_aes_128_gcm");
    assert_eq!(Nid::AES_256_GCM.as_raw(), 901, "NID_aes_256_gcm");
    assert_eq!(
        Nid::CHACHA20_POLY1305.as_raw(),
        1018,
        "NID_chacha20_poly1305"
    );
}

/// Verifies named Nid constants are not UNDEF.
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

// =============================================================================
// Phase 3: ProtocolVersion — Enum Mapping Tests
// =============================================================================

/// `ProtocolVersion::from_raw(0x0304) == Some(ProtocolVersion::Tls1_3)` (Rule R5).
#[test]
fn protocol_version_from_raw_tls13() {
    assert_eq!(
        ProtocolVersion::from_raw(0x0304),
        Some(ProtocolVersion::Tls1_3)
    );
}

/// `from_raw(0x0303) == Some(Tls1_2)`.
#[test]
fn protocol_version_from_raw_tls12() {
    assert_eq!(
        ProtocolVersion::from_raw(0x0303),
        Some(ProtocolVersion::Tls1_2)
    );
}

/// `from_raw(0x0302) == Some(Tls1_1)`.
#[test]
fn protocol_version_from_raw_tls11() {
    assert_eq!(
        ProtocolVersion::from_raw(0x0302),
        Some(ProtocolVersion::Tls1_1)
    );
}

/// `from_raw(0x0301) == Some(Tls1_0)`.
#[test]
fn protocol_version_from_raw_tls10() {
    assert_eq!(
        ProtocolVersion::from_raw(0x0301),
        Some(ProtocolVersion::Tls1_0)
    );
}

/// `from_raw(0x0300) == Some(Ssl3_0)`.
#[test]
fn protocol_version_from_raw_ssl30() {
    assert_eq!(
        ProtocolVersion::from_raw(0x0300),
        Some(ProtocolVersion::Ssl3_0)
    );
}

/// `from_raw(0xFEFF) == Some(Dtls1_0)`.
#[test]
fn protocol_version_from_raw_dtls10() {
    assert_eq!(
        ProtocolVersion::from_raw(0xFEFF),
        Some(ProtocolVersion::Dtls1_0)
    );
}

/// `from_raw(0xFEFD) == Some(Dtls1_2)`.
#[test]
fn protocol_version_from_raw_dtls12() {
    assert_eq!(
        ProtocolVersion::from_raw(0xFEFD),
        Some(ProtocolVersion::Dtls1_2)
    );
}

/// `from_raw(0x9999) == None` — unknown returns None, not sentinel (Rule R5).
#[test]
fn protocol_version_from_raw_unknown() {
    assert_eq!(ProtocolVersion::from_raw(0x9999), None);
    assert_eq!(ProtocolVersion::from_raw(0x0000), None);
    assert_eq!(ProtocolVersion::from_raw(0xFFFF), None);
    assert_eq!(ProtocolVersion::from_raw(0x0305), None);
    assert_eq!(ProtocolVersion::from_raw(0x0299), None);
}

/// For each variant, verify `from_raw(v.as_raw()) == Some(v)`.
#[test]
fn protocol_version_as_raw_round_trip() {
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

/// `Tls1_0`..`Tls1_3` return `true` for `is_tls()`, Dtls variants return `false`.
#[test]
fn protocol_version_is_tls() {
    assert!(ProtocolVersion::Ssl3_0.is_tls());
    assert!(ProtocolVersion::Tls1_0.is_tls());
    assert!(ProtocolVersion::Tls1_1.is_tls());
    assert!(ProtocolVersion::Tls1_2.is_tls());
    assert!(ProtocolVersion::Tls1_3.is_tls());
    assert!(!ProtocolVersion::Dtls1_0.is_tls());
    assert!(!ProtocolVersion::Dtls1_2.is_tls());
}

/// `Dtls1_0` and `Dtls1_2` return `true` for `is_dtls()`, TLS variants return `false`.
#[test]
fn protocol_version_is_dtls() {
    assert!(ProtocolVersion::Dtls1_0.is_dtls());
    assert!(ProtocolVersion::Dtls1_2.is_dtls());
    assert!(!ProtocolVersion::Ssl3_0.is_dtls());
    assert!(!ProtocolVersion::Tls1_0.is_dtls());
    assert!(!ProtocolVersion::Tls1_1.is_dtls());
    assert!(!ProtocolVersion::Tls1_2.is_dtls());
    assert!(!ProtocolVersion::Tls1_3.is_dtls());
}

/// `Tls1_2` < `Tls1_3` (version ordering).
#[test]
fn protocol_version_ordering() {
    assert!(ProtocolVersion::Tls1_2 < ProtocolVersion::Tls1_3);
    assert!(ProtocolVersion::Ssl3_0 < ProtocolVersion::Tls1_0);
    assert!(ProtocolVersion::Tls1_0 < ProtocolVersion::Tls1_1);
    assert!(ProtocolVersion::Tls1_1 < ProtocolVersion::Tls1_2);
}

/// Verifies Display formatting for protocol versions.
#[test]
fn protocol_version_display() {
    assert_eq!(format!("{}", ProtocolVersion::Ssl3_0), "SSLv3");
    assert_eq!(format!("{}", ProtocolVersion::Tls1_0), "TLSv1.0");
    assert_eq!(format!("{}", ProtocolVersion::Tls1_1), "TLSv1.1");
    assert_eq!(format!("{}", ProtocolVersion::Tls1_2), "TLSv1.2");
    assert_eq!(format!("{}", ProtocolVersion::Tls1_3), "TLSv1.3");
    assert_eq!(format!("{}", ProtocolVersion::Dtls1_0), "DTLSv1.0");
    assert_eq!(format!("{}", ProtocolVersion::Dtls1_2), "DTLSv1.2");
}

// =============================================================================
// Phase 4: KeyType — Algorithm Classification Tests
// =============================================================================

/// `KeyType::Rsa.to_nid() == Nid::RSA`, `KeyType::Ec.to_nid() == Nid::EC`, etc.
#[test]
fn key_type_to_nid() {
    assert_eq!(KeyType::Rsa.to_nid(), Nid::RSA);
    assert_eq!(KeyType::Ec.to_nid(), Nid::EC);
    assert_eq!(KeyType::Ed25519.to_nid(), Nid::ED25519);
    assert_eq!(KeyType::X25519.to_nid(), Nid::X25519);
}

/// `KeyType::from_nid(Nid::RSA) == Some(KeyType::Rsa)` (Rule R5).
#[test]
fn key_type_from_nid() {
    assert_eq!(KeyType::from_nid(Nid::RSA), Some(KeyType::Rsa));
    assert_eq!(KeyType::from_nid(Nid::EC), Some(KeyType::Ec));
    assert_eq!(KeyType::from_nid(Nid::ED25519), Some(KeyType::Ed25519));
    assert_eq!(KeyType::from_nid(Nid::X25519), Some(KeyType::X25519));
}

/// `KeyType::from_nid(Nid::from_raw(99999)) == None`.
#[test]
fn key_type_from_nid_unknown() {
    assert_eq!(KeyType::from_nid(Nid::from_raw(99999)), None);
    assert_eq!(KeyType::from_nid(Nid::UNDEF), None);
    assert_eq!(KeyType::from_nid(Nid::from_raw(-1)), None);
}

/// Rsa, Ec, Ed25519, Dh, Dsa return `true`; Hmac, Cmac return `false`.
#[test]
fn key_type_is_asymmetric() {
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

    assert!(
        !KeyType::Hmac.is_asymmetric(),
        "HMAC should not be asymmetric"
    );
    assert!(
        !KeyType::Cmac.is_asymmetric(),
        "CMAC should not be asymmetric"
    );
}

/// ML-KEM, ML-DSA, SLH-DSA, LMS return `true`; others return `false`.
#[test]
fn key_type_is_post_quantum() {
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

/// For each `KeyType` with a defined NID, `from_nid(to_nid())` returns original.
#[test]
fn key_type_round_trip() {
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
        assert_eq!(recovered, Some(kt), "KeyType::{kt:?} NID roundtrip failed");
    }
}

/// Verifies Display formatting for key types.
#[test]
fn key_type_display() {
    assert_eq!(format!("{}", KeyType::Rsa), "RSA");
    assert_eq!(format!("{}", KeyType::Ed25519), "Ed25519");
    assert_eq!(format!("{}", KeyType::MlKem768), "ML-KEM-768");
    assert_eq!(format!("{}", KeyType::SlhDsa), "SLH-DSA");
    assert_eq!(format!("{}", KeyType::Hmac), "HMAC");
    assert_eq!(format!("{}", KeyType::Cmac), "CMAC");
}

// =============================================================================
// Phase 5: PaddingMode — Enum Tests
// =============================================================================

/// `PaddingMode::Pkcs7 == PaddingMode::Pkcs7` equality.
#[test]
fn padding_mode_equality() {
    assert_eq!(PaddingMode::Pkcs7, PaddingMode::Pkcs7);
    assert_ne!(PaddingMode::Pkcs7, PaddingMode::None);
    assert_ne!(PaddingMode::OaepSha1, PaddingMode::OaepSha256);
}

/// All `PaddingMode` variants produce valid Debug output.
#[test]
fn padding_mode_debug() {
    let modes = [
        PaddingMode::None,
        PaddingMode::Pkcs7,
        PaddingMode::OaepSha1,
        PaddingMode::OaepSha256,
        PaddingMode::Pss,
        PaddingMode::Iso10126,
        PaddingMode::Ansi923,
    ];
    for mode in modes {
        let debug_str = format!("{mode:?}");
        assert!(
            !debug_str.is_empty(),
            "Debug should produce non-empty output for {mode:?}"
        );
    }
}

/// Clone produces identical copy.
#[test]
fn padding_mode_clone() {
    let original = PaddingMode::Pkcs7;
    let cloned = original; // Copy (PaddingMode implements Copy)
    assert_eq!(original, cloned);
}

/// All `PaddingMode` variants are distinct from each other.
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

/// Display formatting for padding modes.
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

// =============================================================================
// Phase 6: CipherMode — Enum Tests
// =============================================================================

/// Exhaustive match over all `CipherMode` variants — catches missing variants at
/// compile time.
#[test]
fn cipher_mode_all_variants() {
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
    // Exhaustive match guarantees compile-time checking for new variants.
    for mode in &modes {
        match mode {
            CipherMode::Ecb
            | CipherMode::Cbc
            | CipherMode::Cfb
            | CipherMode::Ofb
            | CipherMode::Ctr
            | CipherMode::Gcm
            | CipherMode::Ccm
            | CipherMode::Xts
            | CipherMode::Wrap
            | CipherMode::WrapPad
            | CipherMode::Ocb
            | CipherMode::Siv
            | CipherMode::GcmSiv
            | CipherMode::Stream => {}
        }
    }
    // All 14 variants are accounted for.
    assert_eq!(modes.len(), 14);
}

/// Verify `CipherMode` equality comparison.
#[test]
fn cipher_mode_equality() {
    assert_eq!(CipherMode::Ecb, CipherMode::Ecb);
    assert_eq!(CipherMode::Gcm, CipherMode::Gcm);
    assert_ne!(CipherMode::Ecb, CipherMode::Cbc);
    assert_ne!(CipherMode::Gcm, CipherMode::Ccm);
}

/// Insert all `CipherMode` variants into `HashSet`, verify all present.
#[test]
fn cipher_mode_hash() {
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
    let mut set = HashSet::new();
    for mode in &modes {
        set.insert(*mode);
    }
    assert_eq!(set.len(), 14);
    // Verify lookup via contains().
    assert!(set.contains(&CipherMode::Gcm));
    assert!(set.contains(&CipherMode::Ecb));
    assert!(set.contains(&CipherMode::Stream));
    assert!(set.contains(&CipherMode::GcmSiv));
}

/// All `CipherMode` variants are distinct from each other.
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

/// Display formatting for cipher modes.
#[test]
fn cipher_mode_display() {
    assert_eq!(format!("{}", CipherMode::Ecb), "ECB");
    assert_eq!(format!("{}", CipherMode::Cbc), "CBC");
    assert_eq!(format!("{}", CipherMode::Gcm), "GCM");
    assert_eq!(format!("{}", CipherMode::Xts), "XTS");
    assert_eq!(format!("{}", CipherMode::GcmSiv), "GCM-SIV");
    assert_eq!(format!("{}", CipherMode::Stream), "STREAM");
}

// =============================================================================
// Phase 7: OperationType — Enum Tests
// =============================================================================

/// Exhaustive match over all `OperationType` variants — catches missing variants
/// at compile time.
#[test]
fn operation_type_all_variants() {
    let ops = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
        OperationType::Kdf,
        OperationType::Rand,
        OperationType::KeyMgmt,
        OperationType::Signature,
        OperationType::AsymCipher,
        OperationType::Kem,
        OperationType::KeyExch,
        OperationType::EncoderDecoder,
        OperationType::Store,
        OperationType::SKeyMgmt,
    ];
    // Exhaustive match guarantees compile-time checking for new variants.
    for op in &ops {
        match op {
            OperationType::Digest
            | OperationType::Cipher
            | OperationType::Mac
            | OperationType::Kdf
            | OperationType::Rand
            | OperationType::KeyMgmt
            | OperationType::Signature
            | OperationType::AsymCipher
            | OperationType::Kem
            | OperationType::KeyExch
            | OperationType::EncoderDecoder
            | OperationType::Store
            | OperationType::SKeyMgmt => {}
        }
    }
    assert_eq!(ops.len(), 13);
}

/// Verify `OperationType` equality comparison.
#[test]
fn operation_type_equality() {
    assert_eq!(OperationType::Digest, OperationType::Digest);
    assert_eq!(OperationType::Cipher, OperationType::Cipher);
    assert_ne!(OperationType::Digest, OperationType::Cipher);
    assert_ne!(OperationType::Mac, OperationType::Kdf);
}

/// Display formatting for all operation types.
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
        (OperationType::SKeyMgmt, "skeymgmt"),
    ];
    for (op, expected) in ops {
        assert_eq!(format!("{op}"), expected, "{op:?} display mismatch");
    }
}

// =============================================================================
// Phase 8: AlgorithmName — Trait Tests
// =============================================================================

/// Create a test struct implementing `AlgorithmName`, verify methods work.
#[test]
fn algorithm_name_trait() {
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

/// Verify the `AlgorithmName` trait works as a trait object (dynamic dispatch).
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

    let algo: Box<dyn AlgorithmName> = Box::new(MockCipher);
    assert_eq!(algo.algorithm_name(), "AES-128-GCM");
    assert_eq!(algo.nid(), Nid::AES_128_GCM);
}

// =============================================================================
// Phase 9: Serde Serialization Tests
// =============================================================================

/// Serialize `Nid::SHA256` to JSON, deserialize back, verify round-trip.
#[test]
fn nid_serialize_deserialize() {
    let nid = Nid::SHA256;
    let json = serde_json::to_string(&nid).expect("Nid should serialize to JSON");
    let deserialized: Nid = serde_json::from_str(&json).expect("Nid should deserialize from JSON");
    assert_eq!(nid, deserialized);
    assert_eq!(deserialized.as_raw(), 672);
}

/// Serialize `ProtocolVersion::Tls1_3` to JSON, verify output and round-trip.
#[test]
fn protocol_version_serialize() {
    let ver = ProtocolVersion::Tls1_3;
    let json = serde_json::to_string(&ver).expect("ProtocolVersion should serialize");
    let deser: ProtocolVersion =
        serde_json::from_str(&json).expect("ProtocolVersion should deserialize");
    assert_eq!(ver, deser);
}

/// Serialize `KeyType::Rsa` to JSON, verify round-trip.
#[test]
fn key_type_serialize() {
    let kt = KeyType::Rsa;
    let json = serde_json::to_string(&kt).expect("KeyType should serialize");
    let deser: KeyType = serde_json::from_str(&json).expect("KeyType should deserialize");
    assert_eq!(kt, deser);
}

/// Serialize `PaddingMode` to JSON, verify round-trip.
#[test]
fn padding_mode_serde_roundtrip() {
    let mode = PaddingMode::OaepSha256;
    let json = serde_json::to_string(&mode).expect("PaddingMode should serialize");
    let deser: PaddingMode = serde_json::from_str(&json).expect("PaddingMode should deserialize");
    assert_eq!(mode, deser);
}

/// Serialize `CipherMode` to JSON, verify round-trip.
#[test]
fn cipher_mode_serde_roundtrip() {
    let mode = CipherMode::Gcm;
    let json = serde_json::to_string(&mode).expect("CipherMode should serialize");
    let deser: CipherMode = serde_json::from_str(&json).expect("CipherMode should deserialize");
    assert_eq!(mode, deser);
}

/// Serialize `OperationType` to JSON, verify round-trip.
#[test]
fn operation_type_serde_roundtrip() {
    let op = OperationType::Signature;
    let json = serde_json::to_string(&op).expect("OperationType should serialize");
    let deser: OperationType =
        serde_json::from_str(&json).expect("OperationType should deserialize");
    assert_eq!(op, deser);
}

/// Additional `KeyType` serde test with a post-quantum variant.
#[test]
fn key_type_serde_roundtrip_pq() {
    let kt = KeyType::MlDsa65;
    let json = serde_json::to_string(&kt).expect("KeyType should serialize");
    let deser: KeyType = serde_json::from_str(&json).expect("KeyType should deserialize");
    assert_eq!(kt, deser);
}
