//! Integration tests for the Certificate Transparency module (`crate::ct`).
//!
//! These tests exercise the **public API surface** of the foundational CT
//! types introduced at this checkpoint, complementing any inline unit tests
//! in `ct::tests`.  They validate the full ct.rs API contract from the
//! crate boundary:
//!
//! - **Phase 1 — Smoke / wiring:** Confirms every public item is reachable
//!   from the crate boundary.
//! - **Phase 2 — `LogEntryType`:** Default value, integer round-trip,
//!   rejection of out-of-range values, exact `Display` strings, leaf
//!   predicate.
//! - **Phase 3 — `SctVersion`:** Default value, integer round-trip,
//!   rejection of out-of-range values, exact `Display` strings, v1
//!   predicate.
//! - **Phase 4 — `SctSource`:** Default value, integer round-trip,
//!   rejection of out-of-range values, exact `Display` strings, delivery
//!   mechanism predicate.
//! - **Phase 5 — `SctValidationStatus`:** Default value, integer
//!   round-trip, rejection of out-of-range values, exact `Display` strings,
//!   valid / invalid / pending predicates with disjointness.
//! - **Phase 6 — Constants:** Numeric values of `CT_V1_HASHLEN`,
//!   `MAX_SCT_EXTENSIONS_LEN`, `MAX_SCT_SIGNATURE_LEN`, and
//!   `SCT_MIN_RSA_BITS`.
//! - **Phase 7 — Validation helpers:** Boundary tests for
//!   `validate_log_id`, `validate_sct_v1_extensions`, `validate_signature`,
//!   and `validate_timestamp` with diagnostic-text assertions.
//! - **Phase 8 — `SignedCertificateTimestamp`:** Accessor pass-through,
//!   `set_validation_status` mutator, `is_valid` short-circuit.
//! - **Phase 9 — `SignedCertificateTimestampBuilder`:** Default builder,
//!   each setter, mandatory-field rejection, V1 log-id length validation,
//!   extensions / signature length validation, validation order.
//! - **Phase 10 — Module helpers:** `all_log_entry_types`,
//!   `all_sct_versions`, `all_sct_sources`, `all_sct_validation_statuses`,
//!   and `all_sct_validation_statuses_set` cardinality and contents.
//!
//! # C Source Mapping
//!
//! | C File / Symbol                                  | Rust Under Test                                                       |
//! |--------------------------------------------------|-----------------------------------------------------------------------|
//! | `crypto/ct/ct_local.h ct_log_entry_type_t`       | [`crate::ct::LogEntryType`]                                           |
//! | `crypto/ct/ct_local.h sct_version_t`             | [`crate::ct::SctVersion`]                                             |
//! | `crypto/ct/ct_local.h sct_source_t`              | [`crate::ct::SctSource`]                                              |
//! | `include/openssl/ct.h.in SCT_VALIDATION_STATUS_*`| [`crate::ct::SctValidationStatus`]                                    |
//! | `include/openssl/ct.h.in CT_V1_HASHLEN`          | [`crate::ct::CT_V1_HASHLEN`]                                          |
//! | `include/openssl/ct.h.in SCT_MIN_RSA_BITS`       | [`crate::ct::SCT_MIN_RSA_BITS`]                                       |
//! | `crypto/ct/ct_sct.c SCT_new()` / `SCT_set*()`    | [`crate::ct::SignedCertificateTimestampBuilder`]                      |
//! | `crypto/ct/ct_sct.c SCT_get*()`                  | [`crate::ct::SignedCertificateTimestamp`] accessors                   |
//! | RFC 6962 §3.1 `MerkleTreeLeaf` entry-type field  | [`crate::ct::LogEntryType::X509`] / [`crate::ct::LogEntryType::Precert`] |
//! | RFC 6962 §3.2 `SignedCertificateTimestamp`       | [`crate::ct::SignedCertificateTimestamp`]                             |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Tests assert `Option<T>` semantics on optional
//!   fields (`source`, `extensions`) and explicit error returns rather
//!   than sentinel values.
//! - **R8 (Zero unsafe):** This test file contains zero `unsafe` blocks.
//! - **R9 (Warning-free):** All assertions use stable APIs; no
//!   suppressions outside the test-only allow list below.
//! - **R10 (Wiring):** Every public item exposed by `crate::ct` is
//!   exercised by at least one test in this file.

// Test code legitimately uses expect/unwrap/panic for assertion clarity.
// The cfg(feature = "ct") gate is applied in tests/mod.rs on the `mod test_ct;`
// declaration, so an inner attribute here would be a duplicate.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashSet;

use openssl_common::error::CryptoError;

use crate::ct::{
    all_log_entry_types, all_sct_sources, all_sct_validation_statuses,
    all_sct_validation_statuses_set, all_sct_versions, validate_log_id,
    validate_sct_v1_extensions, validate_signature, validate_timestamp, LogEntryType, SctSource,
    SctValidationStatus, SctVersion, SignedCertificateTimestamp, SignedCertificateTimestampBuilder,
    CT_V1_HASHLEN, MAX_SCT_EXTENSIONS_LEN, MAX_SCT_SIGNATURE_LEN, SCT_MIN_RSA_BITS,
};

// =============================================================================
// Helpers
// =============================================================================

/// Returns a verification-error message string, panicking if the variant is
/// anything other than `CryptoError::Verification(_)`.
///
/// Used by tests that need to assert on the diagnostic text emitted by the
/// CT module.  Panicking on a wrong variant ensures the test catches the
/// case where the module switches error variants without updating the test.
fn unwrap_verification(err: CryptoError) -> String {
    match err {
        CryptoError::Verification(msg) => msg,
        other => panic!("expected CryptoError::Verification, got {other:?}"),
    }
}

/// Iterator-driven roundtrip table for [`LogEntryType`] — `(discriminant,
/// `Display` name, variant)`.
const ALL_LOG_ENTRY_TYPE_VALUES: [(i32, &str, LogEntryType); 3] = [
    (-1, "not_set", LogEntryType::NotSet),
    (0, "x509", LogEntryType::X509),
    (1, "precert", LogEntryType::Precert),
];

/// Iterator-driven roundtrip table for [`SctVersion`].
const ALL_SCT_VERSION_VALUES: [(i32, &str, SctVersion); 2] = [
    (-1, "not_set", SctVersion::NotSet),
    (0, "v1", SctVersion::V1),
];

/// Iterator-driven roundtrip table for [`SctSource`].
const ALL_SCT_SOURCE_VALUES: [(u32, &str, SctSource); 4] = [
    (0, "unknown", SctSource::Unknown),
    (1, "tls_extension", SctSource::TlsExtension),
    (2, "x509v3_extension", SctSource::X509v3Extension),
    (3, "ocsp_stapled_response", SctSource::OcspStapledResponse),
];

/// Iterator-driven roundtrip table for [`SctValidationStatus`].
const ALL_SCT_VALIDATION_STATUS_VALUES: [(u32, &str, SctValidationStatus); 6] = [
    (0, "not_set", SctValidationStatus::NotSet),
    (1, "unknown_log", SctValidationStatus::UnknownLog),
    (2, "valid", SctValidationStatus::Valid),
    (3, "invalid", SctValidationStatus::Invalid),
    (4, "unverified", SctValidationStatus::Unverified),
    (5, "unknown_version", SctValidationStatus::UnknownVersion),
];

/// Returns a 32-octet log ID populated with the given fill byte.  Used for
/// validation tests where only the length matters.
fn make_log_id(fill: u8) -> Vec<u8> {
    vec![fill; CT_V1_HASHLEN]
}

/// Returns a small non-empty signature blob.  Used for builder tests where
/// only well-formed signatures matter.
fn sample_signature() -> Vec<u8> {
    vec![0x30, 0x44, 0x02, 0x20, 0xAA]
}

// =============================================================================
// Phase 1 — Smoke / wiring tests
// =============================================================================

/// Confirms all public items are reachable from the crate boundary.
///
/// Asserts that the ct module is correctly wired through `crate::ct::*`.
#[test]
fn phase1_module_smoke_test() {
    // Construct one of every public type to prove they are reachable &
    // constructible.
    let _v: SctVersion = SctVersion::V1;
    let _l: LogEntryType = LogEntryType::X509;
    let _s: SctSource = SctSource::TlsExtension;
    let _vs: SctValidationStatus = SctValidationStatus::Valid;
    let _builder: SignedCertificateTimestampBuilder =
        SignedCertificateTimestampBuilder::new(SctVersion::V1);
    assert_eq!(CT_V1_HASHLEN, 32);
    assert_eq!(SCT_MIN_RSA_BITS, 2048);
}

/// Verifies module-level helper functions are reachable.
#[test]
fn phase1_module_helpers_reachable() {
    let entry_types = all_log_entry_types();
    assert_eq!(entry_types.len(), 3);
    let versions = all_sct_versions();
    assert_eq!(versions.len(), 2);
    let sources = all_sct_sources();
    assert_eq!(sources.len(), 4);
    let statuses = all_sct_validation_statuses();
    assert_eq!(statuses.len(), 6);
    let status_set = all_sct_validation_statuses_set();
    assert_eq!(status_set.len(), 6);
}

/// Verifies the validation helper functions are reachable from the crate
/// boundary.
#[test]
fn phase1_validation_helpers_reachable() {
    validate_log_id(&make_log_id(0)).expect("32-octet log_id is valid");
    validate_sct_v1_extensions(&[]).expect("empty extensions is valid");
    validate_signature(&[0u8]).expect("non-empty signature is valid");
    validate_timestamp(1).expect("non-zero timestamp is valid");
}

/// Constructs a `SignedCertificateTimestamp` end-to-end via the builder
/// to confirm the full type pipeline is wired.
#[test]
fn phase1_full_sct_pipeline_smoke() {
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0xAA))
        .timestamp(1_700_000_000_000)
        .signature(sample_signature())
        .build()
        .expect("smoke build must succeed");
    assert_eq!(sct.version(), SctVersion::V1);
    assert_eq!(sct.timestamp(), 1_700_000_000_000);
}

// =============================================================================
// Phase 2 — LogEntryType
// =============================================================================

#[test]
fn phase2_log_entry_type_default_is_not_set() {
    assert_eq!(LogEntryType::default(), LogEntryType::NotSet);
}

#[test]
fn phase2_log_entry_type_default_value_helper_returns_not_set() {
    assert_eq!(LogEntryType::default_value(), LogEntryType::NotSet);
}

#[test]
fn phase2_log_entry_type_as_i32_round_trip_all_variants() {
    for (raw, _name, variant) in ALL_LOG_ENTRY_TYPE_VALUES {
        assert_eq!(variant.as_i32(), raw, "as_i32 mismatch for {variant:?}");
        let parsed = LogEntryType::from_i32(raw)
            .unwrap_or_else(|_| panic!("from_i32({raw}) must succeed"));
        assert_eq!(parsed, variant, "round-trip mismatch for {raw}");
    }
}

#[test]
fn phase2_log_entry_type_name_strings() {
    for (_raw, name, variant) in ALL_LOG_ENTRY_TYPE_VALUES {
        assert_eq!(variant.name(), name, "name mismatch for {variant:?}");
    }
}

#[test]
fn phase2_log_entry_type_display_matches_name() {
    for (_raw, name, variant) in ALL_LOG_ENTRY_TYPE_VALUES {
        assert_eq!(format!("{variant}"), name);
    }
}

#[test]
fn phase2_log_entry_type_rejects_unknown_value_2() {
    let err = LogEntryType::from_i32(2).expect_err("2 must be rejected (RFC 6962 §3.1)");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("unknown CT log entry type"),
        "diagnostic must mention type: {msg}"
    );
}

#[test]
fn phase2_log_entry_type_rejects_unknown_value_negative_two() {
    LogEntryType::from_i32(-2).expect_err("-2 must be rejected");
}

#[test]
fn phase2_log_entry_type_rejects_extreme_negative() {
    LogEntryType::from_i32(i32::MIN).expect_err("i32::MIN must be rejected");
}

#[test]
fn phase2_log_entry_type_rejects_extreme_positive() {
    LogEntryType::from_i32(i32::MAX).expect_err("i32::MAX must be rejected");
}

#[test]
fn phase2_log_entry_type_diagnostic_mentions_rfc_section() {
    let err = LogEntryType::from_i32(99).expect_err("99 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("RFC 6962") || msg.contains("§3.1"),
        "diagnostic must reference RFC 6962 §3.1: {msg}"
    );
}

#[test]
fn phase2_log_entry_type_diagnostic_includes_rejected_value() {
    let err = LogEntryType::from_i32(42).expect_err("42 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("42"),
        "diagnostic must include rejected value: {msg}"
    );
}

#[test]
fn phase2_log_entry_type_is_leaf_x509() {
    assert!(LogEntryType::X509.is_leaf());
}

#[test]
fn phase2_log_entry_type_is_leaf_precert() {
    assert!(LogEntryType::Precert.is_leaf());
}

#[test]
fn phase2_log_entry_type_is_leaf_not_set_is_false() {
    assert!(!LogEntryType::NotSet.is_leaf());
}

#[test]
fn phase2_log_entry_type_equality() {
    assert_eq!(LogEntryType::X509, LogEntryType::X509);
    assert_ne!(LogEntryType::X509, LogEntryType::Precert);
}

#[test]
fn phase2_log_entry_type_ordering() {
    assert!(LogEntryType::NotSet < LogEntryType::X509);
    assert!(LogEntryType::X509 < LogEntryType::Precert);
}

#[test]
fn phase2_log_entry_type_clone_preserves_value() {
    let original = LogEntryType::Precert;
    #[allow(clippy::clone_on_copy)]
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn phase2_log_entry_type_copy_semantic() {
    let original = LogEntryType::X509;
    let copy = original;
    assert_eq!(original, copy);
}

#[test]
fn phase2_log_entry_type_hash_can_be_inserted_in_hash_set() {
    let mut set: HashSet<LogEntryType> = HashSet::new();
    set.insert(LogEntryType::X509);
    set.insert(LogEntryType::X509);
    assert_eq!(set.len(), 1);
    set.insert(LogEntryType::Precert);
    assert_eq!(set.len(), 2);
}

#[test]
fn phase2_log_entry_type_round_trip_via_iterator() {
    for variant in [
        LogEntryType::NotSet,
        LogEntryType::X509,
        LogEntryType::Precert,
    ] {
        let parsed = LogEntryType::from_i32(variant.as_i32()).expect("round-trip");
        assert_eq!(variant, parsed);
    }
}

#[test]
fn phase2_log_entry_type_from_i32_one_is_precert() {
    let parsed = LogEntryType::from_i32(1).expect("1 must parse");
    assert_eq!(parsed, LogEntryType::Precert);
}

#[test]
fn phase2_log_entry_type_from_i32_zero_is_x509() {
    let parsed = LogEntryType::from_i32(0).expect("0 must parse");
    assert_eq!(parsed, LogEntryType::X509);
}

#[test]
fn phase2_log_entry_type_from_i32_negative_one_is_not_set() {
    let parsed = LogEntryType::from_i32(-1).expect("-1 must parse");
    assert_eq!(parsed, LogEntryType::NotSet);
}

// =============================================================================
// Phase 3 — SctVersion
// =============================================================================

#[test]
fn phase3_sct_version_default_is_not_set() {
    assert_eq!(SctVersion::default(), SctVersion::NotSet);
}

#[test]
fn phase3_sct_version_default_value_helper_returns_not_set() {
    assert_eq!(SctVersion::default_value(), SctVersion::NotSet);
}

#[test]
fn phase3_sct_version_as_i32_round_trip_all_variants() {
    for (raw, _name, variant) in ALL_SCT_VERSION_VALUES {
        assert_eq!(variant.as_i32(), raw, "as_i32 mismatch for {variant:?}");
        let parsed = SctVersion::from_i32(raw)
            .unwrap_or_else(|_| panic!("from_i32({raw}) must succeed"));
        assert_eq!(parsed, variant, "round-trip mismatch for {raw}");
    }
}

#[test]
fn phase3_sct_version_name_strings() {
    for (_raw, name, variant) in ALL_SCT_VERSION_VALUES {
        assert_eq!(variant.name(), name, "name mismatch for {variant:?}");
    }
}

#[test]
fn phase3_sct_version_display_matches_name() {
    for (_raw, name, variant) in ALL_SCT_VERSION_VALUES {
        assert_eq!(format!("{variant}"), name);
    }
}

#[test]
fn phase3_sct_version_rejects_one() {
    let err = SctVersion::from_i32(1).expect_err("1 must be rejected (no v2 in RFC 6962)");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("unknown SCT version"),
        "diagnostic must mention version: {msg}"
    );
}

#[test]
fn phase3_sct_version_rejects_two() {
    SctVersion::from_i32(2).expect_err("2 must be rejected");
}

#[test]
fn phase3_sct_version_rejects_negative_two() {
    SctVersion::from_i32(-2).expect_err("-2 must be rejected");
}

#[test]
fn phase3_sct_version_rejects_extreme_negative() {
    SctVersion::from_i32(i32::MIN).expect_err("i32::MIN must be rejected");
}

#[test]
fn phase3_sct_version_rejects_extreme_positive() {
    SctVersion::from_i32(i32::MAX).expect_err("i32::MAX must be rejected");
}

#[test]
fn phase3_sct_version_diagnostic_mentions_rfc_section() {
    let err = SctVersion::from_i32(99).expect_err("99 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("RFC 6962") || msg.contains("§3.2"),
        "diagnostic must reference RFC 6962 §3.2: {msg}"
    );
}

#[test]
fn phase3_sct_version_diagnostic_includes_rejected_value() {
    let err = SctVersion::from_i32(7).expect_err("7 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("7"),
        "diagnostic must include rejected value: {msg}"
    );
}

#[test]
fn phase3_sct_version_is_v1_only_for_v1() {
    assert!(SctVersion::V1.is_v1());
    assert!(!SctVersion::NotSet.is_v1());
}

#[test]
fn phase3_sct_version_equality() {
    assert_eq!(SctVersion::V1, SctVersion::V1);
    assert_ne!(SctVersion::V1, SctVersion::NotSet);
}

#[test]
fn phase3_sct_version_ordering() {
    assert!(SctVersion::NotSet < SctVersion::V1);
}

#[test]
fn phase3_sct_version_copy_semantic() {
    let v = SctVersion::V1;
    let copy = v;
    assert_eq!(v, copy);
}

#[test]
fn phase3_sct_version_hash_set_uniqueness() {
    let mut set: HashSet<SctVersion> = HashSet::new();
    set.insert(SctVersion::V1);
    set.insert(SctVersion::V1);
    assert_eq!(set.len(), 1);
}

#[test]
fn phase3_sct_version_round_trip_via_iterator() {
    for variant in [SctVersion::NotSet, SctVersion::V1] {
        let parsed = SctVersion::from_i32(variant.as_i32()).expect("round-trip");
        assert_eq!(variant, parsed);
    }
}

// =============================================================================
// Phase 4 — SctSource
// =============================================================================

#[test]
fn phase4_sct_source_default_is_unknown() {
    assert_eq!(SctSource::default(), SctSource::Unknown);
}

#[test]
fn phase4_sct_source_default_value_helper_returns_unknown() {
    assert_eq!(SctSource::default_value(), SctSource::Unknown);
}

#[test]
fn phase4_sct_source_as_u32_round_trip_all_variants() {
    for (raw, _name, variant) in ALL_SCT_SOURCE_VALUES {
        assert_eq!(variant.as_u32(), raw, "as_u32 mismatch for {variant:?}");
        let parsed = SctSource::from_u32(raw)
            .unwrap_or_else(|_| panic!("from_u32({raw}) must succeed"));
        assert_eq!(parsed, variant, "round-trip mismatch for {raw}");
    }
}

#[test]
fn phase4_sct_source_name_strings() {
    for (_raw, name, variant) in ALL_SCT_SOURCE_VALUES {
        assert_eq!(variant.name(), name, "name mismatch for {variant:?}");
    }
}

#[test]
fn phase4_sct_source_display_matches_name() {
    for (_raw, name, variant) in ALL_SCT_SOURCE_VALUES {
        assert_eq!(format!("{variant}"), name);
    }
}

#[test]
fn phase4_sct_source_rejects_four() {
    let err = SctSource::from_u32(4).expect_err("4 must be rejected (max is 3)");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("unknown SCT source"),
        "diagnostic must mention source: {msg}"
    );
}

#[test]
fn phase4_sct_source_rejects_extreme_value() {
    SctSource::from_u32(u32::MAX).expect_err("u32::MAX must be rejected");
}

#[test]
fn phase4_sct_source_diagnostic_mentions_range() {
    let err = SctSource::from_u32(99).expect_err("99 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("0..=3") || msg.contains("RFC 6962 §3.3"),
        "diagnostic must mention valid range: {msg}"
    );
}

#[test]
fn phase4_sct_source_diagnostic_includes_rejected_value() {
    let err = SctSource::from_u32(123).expect_err("123 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("123"),
        "diagnostic must include rejected value: {msg}"
    );
}

#[test]
fn phase4_sct_source_is_delivery_mechanism_unknown_is_false() {
    assert!(!SctSource::Unknown.is_delivery_mechanism());
}

#[test]
fn phase4_sct_source_is_delivery_mechanism_tls_extension_is_true() {
    assert!(SctSource::TlsExtension.is_delivery_mechanism());
}

#[test]
fn phase4_sct_source_is_delivery_mechanism_x509v3_extension_is_true() {
    assert!(SctSource::X509v3Extension.is_delivery_mechanism());
}

#[test]
fn phase4_sct_source_is_delivery_mechanism_ocsp_is_true() {
    assert!(SctSource::OcspStapledResponse.is_delivery_mechanism());
}

#[test]
fn phase4_sct_source_equality() {
    assert_eq!(SctSource::TlsExtension, SctSource::TlsExtension);
    assert_ne!(SctSource::TlsExtension, SctSource::X509v3Extension);
}

#[test]
fn phase4_sct_source_copy_semantic() {
    let s = SctSource::OcspStapledResponse;
    let copy = s;
    assert_eq!(s, copy);
}

#[test]
fn phase4_sct_source_hash_set_uniqueness() {
    let mut set: HashSet<SctSource> = HashSet::new();
    for (_raw, _name, variant) in ALL_SCT_SOURCE_VALUES {
        set.insert(variant);
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn phase4_sct_source_round_trip_via_iterator() {
    for variant in [
        SctSource::Unknown,
        SctSource::TlsExtension,
        SctSource::X509v3Extension,
        SctSource::OcspStapledResponse,
    ] {
        let parsed = SctSource::from_u32(variant.as_u32()).expect("round-trip");
        assert_eq!(variant, parsed);
    }
}

// =============================================================================
// Phase 5 — SctValidationStatus
// =============================================================================

#[test]
fn phase5_sct_validation_status_default_is_not_set() {
    assert_eq!(SctValidationStatus::default(), SctValidationStatus::NotSet);
}

#[test]
fn phase5_sct_validation_status_default_value_helper_returns_not_set() {
    assert_eq!(
        SctValidationStatus::default_value(),
        SctValidationStatus::NotSet
    );
}

#[test]
fn phase5_sct_validation_status_as_u32_round_trip_all_variants() {
    for (raw, _name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        assert_eq!(variant.as_u32(), raw, "as_u32 mismatch for {variant:?}");
        let parsed = SctValidationStatus::from_u32(raw)
            .unwrap_or_else(|_| panic!("from_u32({raw}) must succeed"));
        assert_eq!(parsed, variant, "round-trip mismatch for {raw}");
    }
}

#[test]
fn phase5_sct_validation_status_name_strings() {
    for (_raw, name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        assert_eq!(variant.name(), name, "name mismatch for {variant:?}");
    }
}

#[test]
fn phase5_sct_validation_status_display_matches_name() {
    for (_raw, name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        assert_eq!(format!("{variant}"), name);
    }
}

#[test]
fn phase5_sct_validation_status_rejects_six() {
    let err = SctValidationStatus::from_u32(6).expect_err("6 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("unknown SCT validation status"),
        "diagnostic must mention status: {msg}"
    );
}

#[test]
fn phase5_sct_validation_status_rejects_extreme_value() {
    SctValidationStatus::from_u32(u32::MAX).expect_err("u32::MAX must be rejected");
}

#[test]
fn phase5_sct_validation_status_diagnostic_mentions_range() {
    let err = SctValidationStatus::from_u32(99).expect_err("99 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("0..=5") || msg.contains("ct.h.in"),
        "diagnostic must mention valid range or source header: {msg}"
    );
}

#[test]
fn phase5_sct_validation_status_diagnostic_includes_rejected_value() {
    let err = SctValidationStatus::from_u32(42).expect_err("42 must be rejected");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("42"),
        "diagnostic must include rejected value: {msg}"
    );
}

#[test]
fn phase5_sct_validation_status_is_valid_only_for_valid() {
    assert!(SctValidationStatus::Valid.is_valid());
    for (_raw, _name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        if variant != SctValidationStatus::Valid {
            assert!(
                !variant.is_valid(),
                "is_valid must be false for {variant:?}"
            );
        }
    }
}

#[test]
fn phase5_sct_validation_status_is_invalid_only_for_invalid() {
    assert!(SctValidationStatus::Invalid.is_invalid());
    for (_raw, _name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        if variant != SctValidationStatus::Invalid {
            assert!(
                !variant.is_invalid(),
                "is_invalid must be false for {variant:?}"
            );
        }
    }
}

#[test]
fn phase5_sct_validation_status_is_pending_only_for_not_set_and_unverified() {
    assert!(SctValidationStatus::NotSet.is_pending());
    assert!(SctValidationStatus::Unverified.is_pending());
    assert!(!SctValidationStatus::Valid.is_pending());
    assert!(!SctValidationStatus::Invalid.is_pending());
    assert!(!SctValidationStatus::UnknownLog.is_pending());
    assert!(!SctValidationStatus::UnknownVersion.is_pending());
}

/// Predicate disjointness — `is_valid` and `is_invalid` are never both
/// true for any single variant, and `is_pending` overlaps only with
/// statuses that are neither valid nor invalid.
#[test]
fn phase5_sct_validation_status_predicates_disjoint() {
    for (_raw, _name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        // valid vs invalid are mutually exclusive
        assert!(
            !(variant.is_valid() && variant.is_invalid()),
            "valid and invalid disjoint for {variant:?}"
        );
        // pending implies not valid and not invalid
        if variant.is_pending() {
            assert!(!variant.is_valid(), "pending implies not valid: {variant:?}");
            assert!(
                !variant.is_invalid(),
                "pending implies not invalid: {variant:?}"
            );
        }
    }
}

#[test]
fn phase5_sct_validation_status_equality() {
    assert_eq!(SctValidationStatus::Valid, SctValidationStatus::Valid);
    assert_ne!(SctValidationStatus::Valid, SctValidationStatus::Invalid);
}

#[test]
fn phase5_sct_validation_status_ordering() {
    assert!(SctValidationStatus::NotSet < SctValidationStatus::UnknownLog);
    assert!(SctValidationStatus::UnknownLog < SctValidationStatus::Valid);
}

#[test]
fn phase5_sct_validation_status_hash_set_uniqueness() {
    let mut set: HashSet<SctValidationStatus> = HashSet::new();
    for (_raw, _name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        set.insert(variant);
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn phase5_sct_validation_status_round_trip_via_iterator() {
    for variant in [
        SctValidationStatus::NotSet,
        SctValidationStatus::UnknownLog,
        SctValidationStatus::Valid,
        SctValidationStatus::Invalid,
        SctValidationStatus::Unverified,
        SctValidationStatus::UnknownVersion,
    ] {
        let parsed = SctValidationStatus::from_u32(variant.as_u32()).expect("round-trip");
        assert_eq!(variant, parsed);
    }
}

// =============================================================================
// Phase 6 — Constants
// =============================================================================

#[test]
fn phase6_ct_v1_hashlen_is_32() {
    assert_eq!(CT_V1_HASHLEN, 32);
}

#[test]
fn phase6_max_sct_extensions_len_is_65535() {
    assert_eq!(MAX_SCT_EXTENSIONS_LEN, 65_535);
}

#[test]
fn phase6_max_sct_signature_len_is_65535() {
    assert_eq!(MAX_SCT_SIGNATURE_LEN, 65_535);
}

#[test]
fn phase6_sct_min_rsa_bits_is_2048() {
    assert_eq!(SCT_MIN_RSA_BITS, 2048);
}

#[test]
fn phase6_extensions_and_signature_share_same_max() {
    // Both fields are encoded as RFC 5246 §4.3 vectors with 16-bit length.
    assert_eq!(MAX_SCT_EXTENSIONS_LEN, MAX_SCT_SIGNATURE_LEN);
}

// =============================================================================
// Phase 7 — Validation helpers
// =============================================================================

#[test]
fn phase7_validate_log_id_exactly_32_succeeds() {
    let log_id = make_log_id(0);
    validate_log_id(&log_id).expect("32-octet log_id must succeed");
}

#[test]
fn phase7_validate_log_id_31_fails() {
    let log_id = vec![0u8; 31];
    let err = validate_log_id(&log_id).expect_err("31-octet log_id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CT v1 log ID length"), "{msg}");
    assert!(msg.contains("31"), "{msg}");
    assert!(msg.contains("32"), "{msg}");
}

#[test]
fn phase7_validate_log_id_33_fails() {
    let log_id = vec![0u8; 33];
    let err = validate_log_id(&log_id).expect_err("33-octet log_id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CT v1 log ID length"), "{msg}");
    assert!(msg.contains("33"), "{msg}");
}

#[test]
fn phase7_validate_log_id_empty_fails() {
    let err = validate_log_id(&[]).expect_err("empty log_id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CT v1 log ID length"), "{msg}");
    assert!(msg.contains('0'), "{msg}");
}

#[test]
fn phase7_validate_log_id_diagnostic_mentions_rfc() {
    let err = validate_log_id(&[]).expect_err("empty log_id must fail");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("RFC 6962") || msg.contains("§3.2") || msg.contains("SHA-256"),
        "diagnostic must reference standard or hash: {msg}"
    );
}

#[test]
fn phase7_validate_sct_v1_extensions_empty_succeeds() {
    validate_sct_v1_extensions(&[]).expect("empty extensions must succeed");
}

#[test]
fn phase7_validate_sct_v1_extensions_at_max_succeeds() {
    let buf = vec![0u8; MAX_SCT_EXTENSIONS_LEN];
    validate_sct_v1_extensions(&buf).expect("max-length extensions must succeed");
}

#[test]
fn phase7_validate_sct_v1_extensions_one_over_fails() {
    let buf = vec![0u8; MAX_SCT_EXTENSIONS_LEN + 1];
    let err = validate_sct_v1_extensions(&buf).expect_err("oversize extensions must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT v1 extensions length"), "{msg}");
    assert!(msg.contains("65535"), "{msg}");
}

#[test]
fn phase7_validate_sct_v1_extensions_diagnostic_mentions_rfc_5246() {
    let buf = vec![0u8; MAX_SCT_EXTENSIONS_LEN + 1];
    let err = validate_sct_v1_extensions(&buf).expect_err("must fail");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("RFC 5246") || msg.contains("§4.3") || msg.contains("RFC 6962"),
        "diagnostic must reference standard: {msg}"
    );
}

#[test]
fn phase7_validate_signature_one_byte_succeeds() {
    validate_signature(&[0u8]).expect("1-byte signature must succeed");
}

#[test]
fn phase7_validate_signature_at_max_succeeds() {
    let buf = vec![0u8; MAX_SCT_SIGNATURE_LEN];
    validate_signature(&buf).expect("max-length signature must succeed");
}

#[test]
fn phase7_validate_signature_empty_fails() {
    let err = validate_signature(&[]).expect_err("empty signature must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT signature must be non-empty"), "{msg}");
}

#[test]
fn phase7_validate_signature_one_over_fails() {
    let buf = vec![0u8; MAX_SCT_SIGNATURE_LEN + 1];
    let err = validate_signature(&buf).expect_err("oversize signature must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT signature length"), "{msg}");
    assert!(msg.contains("65535"), "{msg}");
}

#[test]
fn phase7_validate_signature_empty_diagnostic_mentions_digitally_signed() {
    let err = validate_signature(&[]).expect_err("empty signature must fail");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("DigitallySigned") || msg.contains("RFC 5246") || msg.contains("RFC 6962"),
        "diagnostic must reference TLS DigitallySigned: {msg}"
    );
}

#[test]
fn phase7_validate_signature_too_long_diagnostic_mentions_digitally_signed() {
    let buf = vec![0u8; MAX_SCT_SIGNATURE_LEN + 1];
    let err = validate_signature(&buf).expect_err("must fail");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("DigitallySigned") || msg.contains("RFC 5246") || msg.contains("RFC 6962"),
        "diagnostic must reference TLS DigitallySigned: {msg}"
    );
}

#[test]
fn phase7_validate_timestamp_zero_fails() {
    let err = validate_timestamp(0).expect_err("0 must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT timestamp is 0"), "{msg}");
}

#[test]
fn phase7_validate_timestamp_one_succeeds() {
    validate_timestamp(1).expect("1 must succeed");
}

#[test]
fn phase7_validate_timestamp_max_succeeds() {
    validate_timestamp(u64::MAX).expect("u64::MAX must succeed");
}

#[test]
fn phase7_validate_timestamp_zero_diagnostic_mentions_unix_epoch() {
    let err = validate_timestamp(0).expect_err("0 must fail");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("UNIX") || msg.contains("epoch") || msg.contains("RFC 6962"),
        "diagnostic must mention UNIX epoch / RFC: {msg}"
    );
}

// =============================================================================
// Phase 8 — SignedCertificateTimestamp accessors and is_valid
// =============================================================================

/// Builds a fully-populated SCT with deterministic fields for accessor
/// pass-through tests.
fn sample_sct_v1() -> SignedCertificateTimestamp {
    SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_entry_type(LogEntryType::X509)
        .log_id(make_log_id(0xAB))
        .timestamp(1_700_000_000_000)
        .extensions(vec![0x01, 0x02, 0x03])
        .signature(sample_signature())
        .source(SctSource::TlsExtension)
        .validation_status(SctValidationStatus::NotSet)
        .build()
        .expect("sample SCT must build")
}

#[test]
fn phase8_sct_accessor_version() {
    let sct = sample_sct_v1();
    assert_eq!(sct.version(), SctVersion::V1);
}

#[test]
fn phase8_sct_accessor_log_entry_type() {
    let sct = sample_sct_v1();
    assert_eq!(sct.log_entry_type(), LogEntryType::X509);
}

#[test]
fn phase8_sct_accessor_log_id() {
    let sct = sample_sct_v1();
    assert_eq!(sct.log_id(), &make_log_id(0xAB)[..]);
    assert_eq!(sct.log_id().len(), CT_V1_HASHLEN);
}

#[test]
fn phase8_sct_accessor_timestamp() {
    let sct = sample_sct_v1();
    assert_eq!(sct.timestamp(), 1_700_000_000_000);
}

#[test]
fn phase8_sct_accessor_extensions() {
    let sct = sample_sct_v1();
    assert_eq!(sct.extensions(), &[0x01, 0x02, 0x03][..]);
}

#[test]
fn phase8_sct_accessor_signature() {
    let sct = sample_sct_v1();
    assert_eq!(sct.signature(), &sample_signature()[..]);
}

#[test]
fn phase8_sct_accessor_source_some() {
    let sct = sample_sct_v1();
    assert_eq!(sct.source(), Some(SctSource::TlsExtension));
}

#[test]
fn phase8_sct_accessor_source_default_is_none() {
    // When no source is set in the builder, accessor returns None.
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("build");
    assert_eq!(sct.source(), None);
}

#[test]
fn phase8_sct_accessor_validation_status_default_is_not_set() {
    let sct = sample_sct_v1();
    assert_eq!(sct.validation_status(), SctValidationStatus::NotSet);
}

#[test]
fn phase8_sct_set_validation_status_mutates() {
    let mut sct = sample_sct_v1();
    assert_eq!(sct.validation_status(), SctValidationStatus::NotSet);
    sct.set_validation_status(SctValidationStatus::Valid);
    assert_eq!(sct.validation_status(), SctValidationStatus::Valid);
}

#[test]
fn phase8_sct_set_validation_status_can_be_called_repeatedly() {
    let mut sct = sample_sct_v1();
    sct.set_validation_status(SctValidationStatus::UnknownLog);
    sct.set_validation_status(SctValidationStatus::Valid);
    sct.set_validation_status(SctValidationStatus::Invalid);
    assert_eq!(sct.validation_status(), SctValidationStatus::Invalid);
}

#[test]
fn phase8_sct_is_valid_false_when_not_set() {
    let sct = sample_sct_v1();
    assert!(!sct.is_valid());
}

#[test]
fn phase8_sct_is_valid_true_after_setting_valid() {
    let mut sct = sample_sct_v1();
    sct.set_validation_status(SctValidationStatus::Valid);
    assert!(sct.is_valid());
}

#[test]
fn phase8_sct_is_valid_false_when_invalid() {
    let mut sct = sample_sct_v1();
    sct.set_validation_status(SctValidationStatus::Invalid);
    assert!(!sct.is_valid());
}

#[test]
fn phase8_sct_is_valid_false_when_unknown_log() {
    let mut sct = sample_sct_v1();
    sct.set_validation_status(SctValidationStatus::UnknownLog);
    assert!(!sct.is_valid());
}

#[test]
fn phase8_sct_clone_preserves_all_fields() {
    let sct = sample_sct_v1();
    let cloned = sct.clone();
    assert_eq!(sct, cloned);
    assert_eq!(sct.version(), cloned.version());
    assert_eq!(sct.log_id(), cloned.log_id());
    assert_eq!(sct.timestamp(), cloned.timestamp());
    assert_eq!(sct.signature(), cloned.signature());
}

#[test]
fn phase8_sct_equality_distinguishes_timestamp() {
    let mut a = sample_sct_v1();
    let b = sample_sct_v1();
    assert_eq!(a, b);
    a.set_validation_status(SctValidationStatus::Valid);
    assert_ne!(a, b);
}

#[test]
fn phase8_sct_extensions_can_be_empty() {
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("build with no extensions");
    assert!(sct.extensions().is_empty());
}

// =============================================================================
// Phase 9 — SignedCertificateTimestampBuilder
// =============================================================================

#[test]
fn phase9_builder_default_uses_not_set_version() {
    let builder = SignedCertificateTimestampBuilder::default();
    let err = builder
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("default builder with NotSet version skips V1 length validation");
    assert_eq!(err.version(), SctVersion::NotSet);
}

#[test]
fn phase9_builder_new_v1_succeeds_with_minimum_fields() {
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("v1 with mandatory fields must build");
    assert_eq!(sct.version(), SctVersion::V1);
    assert_eq!(sct.log_id().len(), CT_V1_HASHLEN);
    assert_eq!(sct.timestamp(), 1);
    // Optional fields default appropriately
    assert!(sct.extensions().is_empty());
    assert_eq!(sct.source(), None);
    assert_eq!(sct.log_entry_type(), LogEntryType::NotSet);
    assert_eq!(sct.validation_status(), SctValidationStatus::NotSet);
}

#[test]
fn phase9_builder_log_entry_type_setter_round_trips() {
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_entry_type(LogEntryType::Precert)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("build");
    assert_eq!(sct.log_entry_type(), LogEntryType::Precert);
}

#[test]
fn phase9_builder_source_setter_round_trips() {
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .source(SctSource::OcspStapledResponse)
        .build()
        .expect("build");
    assert_eq!(sct.source(), Some(SctSource::OcspStapledResponse));
}

#[test]
fn phase9_builder_validation_status_setter_round_trips() {
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(sample_signature())
        .validation_status(SctValidationStatus::UnknownLog)
        .build()
        .expect("build");
    assert_eq!(sct.validation_status(), SctValidationStatus::UnknownLog);
}

#[test]
fn phase9_builder_extensions_setter_round_trips() {
    let payload = vec![0xAB, 0xCD, 0xEF];
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .extensions(payload.clone())
        .signature(sample_signature())
        .build()
        .expect("build");
    assert_eq!(sct.extensions(), payload.as_slice());
}

#[test]
fn phase9_builder_missing_log_id_fails() {
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect_err("missing log_id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT requires log_id"), "{msg}");
}

#[test]
fn phase9_builder_missing_timestamp_fails() {
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .signature(sample_signature())
        .build()
        .expect_err("missing timestamp must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT requires timestamp"), "{msg}");
}

#[test]
fn phase9_builder_missing_signature_fails() {
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .build()
        .expect_err("missing signature must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT requires signature"), "{msg}");
}

/// Validation order check — when log_id and timestamp are both missing,
/// the log_id error must surface first.
#[test]
fn phase9_builder_validation_order_log_id_first() {
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .signature(sample_signature())
        .build()
        .expect_err("missing log_id and timestamp must fail with log_id error first");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("SCT requires log_id"),
        "log_id error must surface first: {msg}"
    );
}

/// Validation order check — when timestamp and signature are both missing
/// but log_id is present, the timestamp error must surface first.
#[test]
fn phase9_builder_validation_order_timestamp_before_signature() {
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .build()
        .expect_err("missing timestamp and signature must fail with timestamp error first");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("SCT requires timestamp"),
        "timestamp error must surface first: {msg}"
    );
}

#[test]
fn phase9_builder_v1_rejects_short_log_id() {
    let short = vec![0u8; 16];
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(short)
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect_err("v1 with short log_id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CT v1 log ID length"), "{msg}");
    assert!(msg.contains("16"), "{msg}");
    assert!(msg.contains("32"), "{msg}");
}

#[test]
fn phase9_builder_v1_rejects_long_log_id() {
    let long = vec![0u8; 64];
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(long)
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect_err("v1 with long log_id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CT v1 log ID length"), "{msg}");
}

#[test]
fn phase9_builder_not_set_version_skips_log_id_length_validation() {
    // NotSet skips the V1 32-octet check — any non-empty log_id is accepted.
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::NotSet)
        .log_id(vec![0u8; 16])
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("NotSet skips V1 log_id length validation");
    assert_eq!(sct.log_id().len(), 16);
}

#[test]
fn phase9_builder_rejects_oversize_extensions() {
    let buf = vec![0u8; MAX_SCT_EXTENSIONS_LEN + 1];
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .extensions(buf)
        .signature(sample_signature())
        .build()
        .expect_err("oversize extensions must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT v1 extensions length"), "{msg}");
}

#[test]
fn phase9_builder_accepts_extensions_at_max_length() {
    let buf = vec![0u8; MAX_SCT_EXTENSIONS_LEN];
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .extensions(buf)
        .signature(sample_signature())
        .build()
        .expect("max-length extensions must succeed");
    assert_eq!(sct.extensions().len(), MAX_SCT_EXTENSIONS_LEN);
}

#[test]
fn phase9_builder_rejects_empty_signature() {
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(vec![])
        .build()
        .expect_err("empty signature must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT signature must be non-empty"), "{msg}");
}

#[test]
fn phase9_builder_rejects_oversize_signature() {
    let buf = vec![0u8; MAX_SCT_SIGNATURE_LEN + 1];
    let err = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(buf)
        .build()
        .expect_err("oversize signature must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("SCT signature length"), "{msg}");
}

#[test]
fn phase9_builder_accepts_signature_at_max_length() {
    let buf = vec![0u8; MAX_SCT_SIGNATURE_LEN];
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_id(make_log_id(0))
        .timestamp(1)
        .signature(buf)
        .build()
        .expect("max-length signature must succeed");
    assert_eq!(sct.signature().len(), MAX_SCT_SIGNATURE_LEN);
}

#[test]
fn phase9_builder_chained_setters_consume_self() {
    // The setters are #[must_use] and consume self; this test confirms
    // they chain without compilation issues.
    let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
        .log_entry_type(LogEntryType::X509)
        .log_id(make_log_id(0))
        .timestamp(2)
        .extensions(vec![0xAB])
        .signature(sample_signature())
        .source(SctSource::TlsExtension)
        .validation_status(SctValidationStatus::Valid)
        .build()
        .expect("fully chained build must succeed");
    assert_eq!(sct.version(), SctVersion::V1);
    assert_eq!(sct.log_entry_type(), LogEntryType::X509);
    assert_eq!(sct.timestamp(), 2);
    assert_eq!(sct.extensions(), &[0xAB][..]);
    assert_eq!(sct.source(), Some(SctSource::TlsExtension));
    assert_eq!(sct.validation_status(), SctValidationStatus::Valid);
}

#[test]
fn phase9_builder_clone_works() {
    let builder = SignedCertificateTimestampBuilder::new(SctVersion::V1).log_id(make_log_id(0));
    let cloned = builder.clone();
    let a = builder
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("a build");
    let b = cloned
        .timestamp(1)
        .signature(sample_signature())
        .build()
        .expect("b build");
    assert_eq!(a, b);
}

// =============================================================================
// Phase 10 — Module-level helpers
// =============================================================================

#[test]
fn phase10_all_log_entry_types_has_three_entries() {
    let v = all_log_entry_types();
    assert_eq!(v.len(), 3);
}

#[test]
fn phase10_all_log_entry_types_contains_all_variants() {
    let v = all_log_entry_types();
    assert!(v.contains(&LogEntryType::NotSet));
    assert!(v.contains(&LogEntryType::X509));
    assert!(v.contains(&LogEntryType::Precert));
}

#[test]
fn phase10_all_log_entry_types_is_in_discriminant_order() {
    let v = all_log_entry_types();
    assert_eq!(v[0], LogEntryType::NotSet);
    assert_eq!(v[1], LogEntryType::X509);
    assert_eq!(v[2], LogEntryType::Precert);
}

#[test]
fn phase10_all_sct_versions_has_two_entries() {
    let v = all_sct_versions();
    assert_eq!(v.len(), 2);
}

#[test]
fn phase10_all_sct_versions_contains_all_variants() {
    let v = all_sct_versions();
    assert!(v.contains(&SctVersion::NotSet));
    assert!(v.contains(&SctVersion::V1));
}

#[test]
fn phase10_all_sct_versions_is_in_discriminant_order() {
    let v = all_sct_versions();
    assert_eq!(v[0], SctVersion::NotSet);
    assert_eq!(v[1], SctVersion::V1);
}

#[test]
fn phase10_all_sct_sources_has_four_entries() {
    let v = all_sct_sources();
    assert_eq!(v.len(), 4);
}

#[test]
fn phase10_all_sct_sources_contains_all_variants() {
    let v = all_sct_sources();
    assert!(v.contains(&SctSource::Unknown));
    assert!(v.contains(&SctSource::TlsExtension));
    assert!(v.contains(&SctSource::X509v3Extension));
    assert!(v.contains(&SctSource::OcspStapledResponse));
}

#[test]
fn phase10_all_sct_sources_is_in_discriminant_order() {
    let v = all_sct_sources();
    assert_eq!(v[0], SctSource::Unknown);
    assert_eq!(v[1], SctSource::TlsExtension);
    assert_eq!(v[2], SctSource::X509v3Extension);
    assert_eq!(v[3], SctSource::OcspStapledResponse);
}

#[test]
fn phase10_all_sct_validation_statuses_has_six_entries() {
    let v = all_sct_validation_statuses();
    assert_eq!(v.len(), 6);
}

#[test]
fn phase10_all_sct_validation_statuses_contains_all_variants() {
    let v = all_sct_validation_statuses();
    assert!(v.contains(&SctValidationStatus::NotSet));
    assert!(v.contains(&SctValidationStatus::UnknownLog));
    assert!(v.contains(&SctValidationStatus::Valid));
    assert!(v.contains(&SctValidationStatus::Invalid));
    assert!(v.contains(&SctValidationStatus::Unverified));
    assert!(v.contains(&SctValidationStatus::UnknownVersion));
}

#[test]
fn phase10_all_sct_validation_statuses_is_in_discriminant_order() {
    let v = all_sct_validation_statuses();
    assert_eq!(v[0], SctValidationStatus::NotSet);
    assert_eq!(v[1], SctValidationStatus::UnknownLog);
    assert_eq!(v[2], SctValidationStatus::Valid);
    assert_eq!(v[3], SctValidationStatus::Invalid);
    assert_eq!(v[4], SctValidationStatus::Unverified);
    assert_eq!(v[5], SctValidationStatus::UnknownVersion);
}

#[test]
fn phase10_all_sct_validation_statuses_set_has_six_unique_entries() {
    let s = all_sct_validation_statuses_set();
    assert_eq!(s.len(), 6);
}

#[test]
fn phase10_all_sct_validation_statuses_set_matches_vec_contents() {
    let v = all_sct_validation_statuses();
    let s = all_sct_validation_statuses_set();
    let from_vec: HashSet<SctValidationStatus> = v.into_iter().collect();
    assert_eq!(s, from_vec);
}

#[test]
fn phase10_all_helpers_round_trip_with_iterator_table() {
    // The vec helpers must agree with the iterator-table test scaffolding.
    let v = all_log_entry_types();
    for (_raw, _name, variant) in ALL_LOG_ENTRY_TYPE_VALUES {
        assert!(v.contains(&variant));
    }
    let v = all_sct_versions();
    for (_raw, _name, variant) in ALL_SCT_VERSION_VALUES {
        assert!(v.contains(&variant));
    }
    let v = all_sct_sources();
    for (_raw, _name, variant) in ALL_SCT_SOURCE_VALUES {
        assert!(v.contains(&variant));
    }
    let v = all_sct_validation_statuses();
    for (_raw, _name, variant) in ALL_SCT_VALIDATION_STATUS_VALUES {
        assert!(v.contains(&variant));
    }
}
