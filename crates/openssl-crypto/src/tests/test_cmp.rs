//! Integration tests for the Certificate Management Protocol module (`crate::cmp`).
//!
//! These tests exercise the **public API surface** of the foundational CMP types
//! introduced at this checkpoint, complementing any inline unit tests in `cmp::tests`.
//! They validate the full cmp.rs API contract from the crate boundary:
//!
//! - **Phase 1 — Smoke / wiring:** Confirms every public item is reachable from
//!   the crate boundary.
//! - **Phase 2 — `PkiVersion`:** Default value, integer round-trip, rejection of
//!   v1 (RFC 2510 deprecated) and other invalid values, exact `Display` strings.
//! - **Phase 3 — `PkiStatus`:** All 10 variants (-3..=6) round-trip through
//!   `from_i32`/`as_i32`; out-of-range values produce diagnostic errors;
//!   description strings match RFC 4210 wording exactly; `is_positive` /
//!   `is_rejection` / `is_internal` predicates honour the spec.
//! - **Phase 4 — `PkiFailureInfo`:** All 27 variants (bit indices 0..=26) have
//!   the correct discriminant, `bit_mask = 1 << idx`, `name()` matches the
//!   canonical RFC short name, `from_bit_index` is exhaustive and rejects
//!   out-of-range indices.
//! - **Phase 5 — `FailureInfoBits`:** `VALID_MASK = (1<<27)-1`, `from_raw`
//!   masks high bits, `set`/`unset`/`contains`/`count`/`is_empty`/`clear`,
//!   iteration order is ascending bit index, `union` and `intersection` follow
//!   set-theoretic semantics, `Display` formats as `(none)` or comma-joined names.
//! - **Phase 6 — `PkiStatusInfo`:** Builder-style construction, accessor pattern,
//!   `with_texts` REPLACES (does not append), `Display` includes the optional
//!   `text=[…]` (semicolon-joined) and `failInfo=…` sections.
//! - **Phase 7 — `validate_transaction_id`:** Exact 16-octet success; lengths
//!   0/15/17/100 fail with diagnostic substring.
//! - **Phase 8 — `validate_nonce`:** Lengths ≥16 succeed; lengths 0/8/15 fail
//!   with diagnostic substring.
//! - **Phase 9 — `PkiHeader` / `PkiHeaderBuilder`:** Builder requires `sender`
//!   and `recipient`; transaction-ID and nonce length validation runs at build
//!   time; accessors return the correct values.
//! - **Phase 10 — Module helpers:** `all_failure_info_names()` returns all 27,
//!   `all_pki_statuses()` returns the 10-element `HashSet`.
//!
//! # C Source Mapping
//!
//! | C File / Symbol                              | Rust Under Test                                |
//! |----------------------------------------------|------------------------------------------------|
//! | `OSSL_CMP_PVNO_2 / _3` (`cmp.h.in`)          | [`PkiVersion`]                                 |
//! | `OSSL_CMP_PKISTATUS_*` (`cmp.h.in`)          | [`PkiStatus`]                                  |
//! | `OSSL_CMP_PKIFAILUREINFO_*` (`cmp.h.in`)     | [`PkiFailureInfo`]                             |
//! | `OSSL_CMP_CTX_FAILINFO_*` bitmasks           | [`FailureInfoBits`]                            |
//! | `OSSL_CMP_PKISI` (`cmp_local.h`)             | [`PkiStatusInfo`]                              |
//! | `OSSL_CMP_PKIHEADER` (`cmp_local.h`)         | [`PkiHeader`], [`PkiHeaderBuilder`]            |
//! | `crypto/cmp/cmp_status.c` reason strings     | [`PkiStatus::description`]                     |
//! | `crypto/cmp/cmp_msg.c` header construction   | [`PkiHeaderBuilder`]                           |
//! | RFC 4210 §5.1.1 transaction-ID length        | [`validate_transaction_id`]                    |
//! | RFC 4210 §5.1.1 nonce length                 | [`validate_nonce`]                             |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Every assertion uses `Result`/`Option`; no sentinel
//!   values (0, -1, "") anywhere in test data or assertions.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this file.
//! - **R9 (Warning-Free):** All items used; no dead code.
//! - **R10 (Wiring):** Reachable via `#[cfg(test)]` + `#[cfg(feature = "cmp")]`
//!   gated at the `mod test_cmp;` declaration in `src/tests/mod.rs`.

// Test code legitimately uses expect/unwrap/panic for assertion clarity.
// The cfg(feature = "cmp") gate is applied in tests/mod.rs on the `mod test_cmp;`
// declaration, so an inner attribute here would be a duplicate.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use openssl_common::error::CryptoError;

use crate::cmp::{
    all_failure_info_names, all_pki_statuses, validate_nonce, validate_transaction_id,
    FailureInfoBits, PkiFailureInfo, PkiHeaderBuilder, PkiStatus, PkiStatusInfo, PkiVersion,
    MIN_NONCE_LEN, TRANSACTION_ID_LEN,
};

// =============================================================================
// Helpers
// =============================================================================

/// Returns a verification-error message string, panicking if the variant is
/// anything other than `CryptoError::Verification(_)`.
///
/// Used by tests that need to assert on the diagnostic text emitted by the
/// CMP module.  Panicking on a wrong variant ensures the test catches the
/// case where the module switches error variants without updating the test.
fn unwrap_verification(err: CryptoError) -> String {
    match err {
        CryptoError::Verification(msg) => msg,
        other => panic!("expected CryptoError::Verification, got {other:?}"),
    }
}

/// All 10 valid `PkiStatus` discriminants in canonical order.
const ALL_PKI_STATUS_VALUES: [(i32, PkiStatus); 10] = [
    (-3, PkiStatus::Request),
    (-2, PkiStatus::Trans),
    (-1, PkiStatus::Unspecified),
    (0, PkiStatus::Accepted),
    (1, PkiStatus::GrantedWithMods),
    (2, PkiStatus::Rejection),
    (3, PkiStatus::Waiting),
    (4, PkiStatus::RevocationWarning),
    (5, PkiStatus::RevocationNotification),
    (6, PkiStatus::KeyUpdateWarning),
];

/// All 27 valid `PkiFailureInfo` variants paired with their bit indices and
/// canonical RFC short names per RFC 4210 §5.2.4 / `cmp.h.in`.
const ALL_FAILURE_INFO_VARIANTS: [(u8, &str, PkiFailureInfo); 27] = [
    (0, "badAlg", PkiFailureInfo::BadAlg),
    (1, "badMessageCheck", PkiFailureInfo::BadMessageCheck),
    (2, "badRequest", PkiFailureInfo::BadRequest),
    (3, "badTime", PkiFailureInfo::BadTime),
    (4, "badCertId", PkiFailureInfo::BadCertId),
    (5, "badDataFormat", PkiFailureInfo::BadDataFormat),
    (6, "wrongAuthority", PkiFailureInfo::WrongAuthority),
    (7, "incorrectData", PkiFailureInfo::IncorrectData),
    (8, "missingTimeStamp", PkiFailureInfo::MissingTimeStamp),
    (9, "badPOP", PkiFailureInfo::BadPop),
    (10, "certRevoked", PkiFailureInfo::CertRevoked),
    (11, "certConfirmed", PkiFailureInfo::CertConfirmed),
    (12, "wrongIntegrity", PkiFailureInfo::WrongIntegrity),
    (13, "badRecipientNonce", PkiFailureInfo::BadRecipientNonce),
    (14, "timeNotAvailable", PkiFailureInfo::TimeNotAvailable),
    (15, "unacceptedPolicy", PkiFailureInfo::UnacceptedPolicy),
    (16, "unacceptedExtension", PkiFailureInfo::UnacceptedExtension),
    (17, "addInfoNotAvailable", PkiFailureInfo::AddInfoNotAvailable),
    (18, "badSenderNonce", PkiFailureInfo::BadSenderNonce),
    (19, "badCertTemplate", PkiFailureInfo::BadCertTemplate),
    (20, "signerNotTrusted", PkiFailureInfo::SignerNotTrusted),
    (21, "transactionIdInUse", PkiFailureInfo::TransactionIdInUse),
    (22, "unsupportedVersion", PkiFailureInfo::UnsupportedVersion),
    (23, "notAuthorized", PkiFailureInfo::NotAuthorized),
    (24, "systemUnavail", PkiFailureInfo::SystemUnavail),
    (25, "systemFailure", PkiFailureInfo::SystemFailure),
    (26, "duplicateCertReq", PkiFailureInfo::DuplicateCertReq),
];

// =============================================================================
// Phase 1 — Smoke / wiring tests
// =============================================================================

/// Confirms all public items are reachable from the crate boundary.
///
/// Mirrors the equivalent smoke test in test_ts.rs and asserts that the cmp
/// module is correctly wired through `crate::cmp::*`.
#[test]
fn phase1_module_smoke_test() {
    // Construct one of every type to prove they are reachable & constructible.
    let _v: PkiVersion = PkiVersion::V2;
    let _s: PkiStatus = PkiStatus::Accepted;
    let _f: PkiFailureInfo = PkiFailureInfo::BadAlg;
    let _b: FailureInfoBits = FailureInfoBits::new();
    let _info: PkiStatusInfo = PkiStatusInfo::new(PkiStatus::Accepted);
    let _builder: PkiHeaderBuilder = PkiHeaderBuilder::new(PkiVersion::V2);
    assert_eq!(TRANSACTION_ID_LEN, 16);
    assert_eq!(MIN_NONCE_LEN, 16);
}

/// Verifies module-level helper functions are reachable.
#[test]
fn phase1_module_helpers_reachable() {
    let names = all_failure_info_names();
    assert_eq!(names.len(), 27);
    let statuses = all_pki_statuses();
    assert_eq!(statuses.len(), 10);
}

// =============================================================================
// Phase 2 — PkiVersion
// =============================================================================

#[test]
fn phase2_pki_version_default_is_v2() {
    let default = PkiVersion::default();
    assert_eq!(default, PkiVersion::V2);
}

#[test]
fn phase2_pki_version_default_version_helper_returns_v2() {
    assert_eq!(PkiVersion::default_version(), PkiVersion::V2);
}

#[test]
fn phase2_pki_version_as_i32_v2() {
    assert_eq!(PkiVersion::V2.as_i32(), 2);
}

#[test]
fn phase2_pki_version_as_i32_v3() {
    assert_eq!(PkiVersion::V3.as_i32(), 3);
}

#[test]
fn phase2_pki_version_from_i32_v2() {
    let parsed = PkiVersion::from_i32(2).expect("v2 must parse");
    assert_eq!(parsed, PkiVersion::V2);
}

#[test]
fn phase2_pki_version_from_i32_v3() {
    let parsed = PkiVersion::from_i32(3).expect("v3 must parse");
    assert_eq!(parsed, PkiVersion::V3);
}

#[test]
fn phase2_pki_version_rejects_v1_deprecated() {
    let err = PkiVersion::from_i32(1).expect_err("v1 must be rejected (RFC 2510 deprecated)");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("unsupported CMP protocol version"),
        "diagnostic must mention version: {msg}"
    );
    assert!(
        msg.contains("pvno=1") || msg.contains("=1"),
        "diagnostic must include rejected value: {msg}"
    );
}

#[test]
fn phase2_pki_version_rejects_zero() {
    let err = PkiVersion::from_i32(0).expect_err("0 must be rejected");
    let msg = unwrap_verification(err);
    assert!(msg.contains("unsupported CMP protocol version"), "{msg}");
}

#[test]
fn phase2_pki_version_rejects_four() {
    let err = PkiVersion::from_i32(4).expect_err("4 must be rejected (RFC 4210/9480 mandate 2 or 3)");
    let msg = unwrap_verification(err);
    assert!(msg.contains("unsupported CMP protocol version"), "{msg}");
}

#[test]
fn phase2_pki_version_rejects_negative() {
    let err = PkiVersion::from_i32(-1).expect_err("-1 must be rejected");
    let msg = unwrap_verification(err);
    assert!(msg.contains("unsupported CMP protocol version"), "{msg}");
}

#[test]
fn phase2_pki_version_rejects_extreme_negative() {
    PkiVersion::from_i32(i32::MIN).expect_err("i32::MIN must be rejected");
}

#[test]
fn phase2_pki_version_rejects_extreme_positive() {
    PkiVersion::from_i32(i32::MAX).expect_err("i32::MAX must be rejected");
}

#[test]
fn phase2_pki_version_round_trip_v2() {
    let v = PkiVersion::V2;
    let parsed = PkiVersion::from_i32(v.as_i32()).expect("round-trip");
    assert_eq!(v, parsed);
}

#[test]
fn phase2_pki_version_round_trip_v3() {
    let v = PkiVersion::V3;
    let parsed = PkiVersion::from_i32(v.as_i32()).expect("round-trip");
    assert_eq!(v, parsed);
}

#[test]
fn phase2_pki_version_display_v2() {
    assert_eq!(format!("{}", PkiVersion::V2), "CMP v2 (RFC 4210)");
}

#[test]
fn phase2_pki_version_display_v3() {
    assert_eq!(format!("{}", PkiVersion::V3), "CMP v3 (RFC 9480)");
}

#[test]
fn phase2_pki_version_equality() {
    assert_eq!(PkiVersion::V2, PkiVersion::V2);
    assert_ne!(PkiVersion::V2, PkiVersion::V3);
}

#[test]
fn phase2_pki_version_ordering() {
    // V2 < V3 since the discriminants are 2 and 3 and PartialOrd derives match.
    assert!(PkiVersion::V2 < PkiVersion::V3);
    assert!(PkiVersion::V3 > PkiVersion::V2);
}

// =============================================================================
// Phase 3 — PkiStatus
// =============================================================================

#[test]
fn phase3_pki_status_all_values_round_trip() {
    for (raw, status) in ALL_PKI_STATUS_VALUES {
        assert_eq!(status.as_i32(), raw, "as_i32 mismatch for {status:?}");
        let parsed = PkiStatus::from_i32(raw)
            .unwrap_or_else(|_| panic!("from_i32({raw}) must succeed"));
        assert_eq!(parsed, status, "round-trip mismatch for {raw}");
    }
}

#[test]
fn phase3_pki_status_rejects_below_min() {
    let err = PkiStatus::from_i32(-4).expect_err("-4 must be rejected");
    let msg = unwrap_verification(err);
    assert!(msg.contains("unknown PKIStatus value"), "{msg}");
    assert!(msg.contains("-3..=6") || msg.contains("RFC 4210"), "{msg}");
}

#[test]
fn phase3_pki_status_rejects_above_max() {
    let err = PkiStatus::from_i32(7).expect_err("7 must be rejected");
    let msg = unwrap_verification(err);
    assert!(msg.contains("unknown PKIStatus value"), "{msg}");
}

#[test]
fn phase3_pki_status_rejects_extreme_values() {
    PkiStatus::from_i32(i32::MIN).expect_err("i32::MIN must be rejected");
    PkiStatus::from_i32(i32::MAX).expect_err("i32::MAX must be rejected");
}

#[test]
fn phase3_pki_status_description_request() {
    assert_eq!(PkiStatus::Request.description(), "request being assembled");
}

#[test]
fn phase3_pki_status_description_trans() {
    assert_eq!(PkiStatus::Trans.description(), "request in transit");
}

#[test]
fn phase3_pki_status_description_unspecified() {
    assert_eq!(PkiStatus::Unspecified.description(), "status unspecified");
}

#[test]
fn phase3_pki_status_description_accepted() {
    assert_eq!(PkiStatus::Accepted.description(), "PKI request accepted");
}

#[test]
fn phase3_pki_status_description_granted_with_mods() {
    assert_eq!(
        PkiStatus::GrantedWithMods.description(),
        "request granted with modifications"
    );
}

#[test]
fn phase3_pki_status_description_rejection() {
    assert_eq!(PkiStatus::Rejection.description(), "PKI request rejected");
}

#[test]
fn phase3_pki_status_description_waiting() {
    assert_eq!(
        PkiStatus::Waiting.description(),
        "PKI request not yet ready (client must poll)"
    );
}

#[test]
fn phase3_pki_status_description_revocation_warning() {
    assert_eq!(
        PkiStatus::RevocationWarning.description(),
        "PKI revocation warning"
    );
}

#[test]
fn phase3_pki_status_description_revocation_notification() {
    assert_eq!(
        PkiStatus::RevocationNotification.description(),
        "PKI revocation notification"
    );
}

#[test]
fn phase3_pki_status_description_key_update_warning() {
    assert_eq!(
        PkiStatus::KeyUpdateWarning.description(),
        "PKI key-update warning"
    );
}

#[test]
fn phase3_pki_status_display_uses_description() {
    for (_, status) in ALL_PKI_STATUS_VALUES {
        assert_eq!(format!("{status}"), status.description());
    }
}

#[test]
fn phase3_pki_status_is_positive_only_accepted_and_granted_with_mods() {
    for (_, status) in ALL_PKI_STATUS_VALUES {
        let expected = matches!(status, PkiStatus::Accepted | PkiStatus::GrantedWithMods);
        assert_eq!(
            status.is_positive(),
            expected,
            "is_positive mismatch for {status:?}"
        );
    }
}

#[test]
fn phase3_pki_status_is_rejection_only_rejection() {
    for (_, status) in ALL_PKI_STATUS_VALUES {
        let expected = matches!(status, PkiStatus::Rejection);
        assert_eq!(
            status.is_rejection(),
            expected,
            "is_rejection mismatch for {status:?}"
        );
    }
}

#[test]
fn phase3_pki_status_is_internal_request_trans_unspecified() {
    for (_, status) in ALL_PKI_STATUS_VALUES {
        let expected = matches!(
            status,
            PkiStatus::Request | PkiStatus::Trans | PkiStatus::Unspecified
        );
        assert_eq!(
            status.is_internal(),
            expected,
            "is_internal mismatch for {status:?}"
        );
    }
}

#[test]
fn phase3_pki_status_predicates_are_disjoint_for_real_statuses() {
    // External status codes (0..=6) split cleanly: positive XOR rejection XOR
    // (waiting / revocation-* / key-update-warning).  Internal codes (-3..=-1)
    // are categorically internal but never positive nor a rejection.
    for (_, status) in ALL_PKI_STATUS_VALUES {
        let positive = status.is_positive();
        let rejection = status.is_rejection();
        let internal = status.is_internal();
        // No status is more than one of these three.
        let count = [positive, rejection, internal]
            .iter()
            .filter(|b| **b)
            .count();
        assert!(count <= 1, "predicates must be disjoint for {status:?}");
    }
}

#[test]
fn phase3_pki_status_equality_and_hashing() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for (_, status) in ALL_PKI_STATUS_VALUES {
        set.insert(status);
    }
    assert_eq!(set.len(), 10);
}

// =============================================================================
// Phase 4 — PkiFailureInfo
// =============================================================================

#[test]
fn phase4_failure_info_max_bit_constant() {
    assert_eq!(PkiFailureInfo::MAX_BIT, 26);
}

#[test]
fn phase4_failure_info_bit_index_matches_discriminant() {
    for (idx, _, info) in ALL_FAILURE_INFO_VARIANTS {
        assert_eq!(info.bit_index(), idx, "bit_index mismatch for {info:?}");
    }
}

#[test]
fn phase4_failure_info_bit_mask_is_one_shifted() {
    for (idx, _, info) in ALL_FAILURE_INFO_VARIANTS {
        let expected: u32 = 1u32 << idx;
        assert_eq!(info.bit_mask(), expected, "bit_mask mismatch for {info:?}");
    }
}

#[test]
fn phase4_failure_info_name_matches_canonical() {
    for (_, name, info) in ALL_FAILURE_INFO_VARIANTS {
        assert_eq!(info.name(), name, "canonical name mismatch for {info:?}");
    }
}

#[test]
fn phase4_failure_info_display_uses_name() {
    for (_, name, info) in ALL_FAILURE_INFO_VARIANTS {
        assert_eq!(format!("{info}"), name);
    }
}

#[test]
fn phase4_failure_info_from_bit_index_round_trip() {
    for (idx, _, info) in ALL_FAILURE_INFO_VARIANTS {
        let parsed =
            PkiFailureInfo::from_bit_index(idx).expect("valid bit index must parse");
        assert_eq!(parsed, info, "round-trip mismatch for index {idx}");
    }
}

#[test]
fn phase4_failure_info_from_bit_index_rejects_27() {
    let err = PkiFailureInfo::from_bit_index(27)
        .expect_err("27 must be rejected (MAX_BIT=26)");
    let msg = unwrap_verification(err);
    assert!(
        msg.contains("PKIFailureInfo bit index out of range"),
        "{msg}"
    );
    assert!(msg.contains("max = 26"), "diagnostic must report the max: {msg}");
}

#[test]
fn phase4_failure_info_from_bit_index_rejects_28() {
    PkiFailureInfo::from_bit_index(28).expect_err("28 must be rejected");
}

#[test]
fn phase4_failure_info_from_bit_index_rejects_max() {
    let err = PkiFailureInfo::from_bit_index(u8::MAX)
        .expect_err("u8::MAX must be rejected");
    let msg = unwrap_verification(err);
    assert!(msg.contains("PKIFailureInfo bit index out of range"), "{msg}");
}

#[test]
fn phase4_failure_info_all_returns_27_unique_variants() {
    use std::collections::HashSet;
    let all = PkiFailureInfo::all();
    assert_eq!(all.len(), 27);
    let unique: HashSet<_> = all.iter().copied().collect();
    assert_eq!(unique.len(), 27, "all() must return distinct variants");
}

#[test]
fn phase4_failure_info_all_in_ascending_bit_order() {
    let all = PkiFailureInfo::all();
    for (i, info) in all.iter().enumerate() {
        let expected_idx: u8 =
            u8::try_from(i).expect("array index 0..27 fits in u8");
        assert_eq!(
            info.bit_index(),
            expected_idx,
            "all()[{i}] must have bit_index {expected_idx}"
        );
    }
}

// =============================================================================
// Phase 5 — FailureInfoBits
// =============================================================================

#[test]
fn phase5_failure_info_bits_valid_mask() {
    assert_eq!(FailureInfoBits::VALID_MASK, (1u32 << 27) - 1);
}

#[test]
fn phase5_failure_info_bits_new_is_empty() {
    let bits = FailureInfoBits::new();
    assert!(bits.is_empty());
    assert_eq!(bits.count(), 0);
    assert_eq!(bits.as_raw(), 0);
}

#[test]
fn phase5_failure_info_bits_default_is_empty() {
    let bits = FailureInfoBits::default();
    assert!(bits.is_empty());
}

#[test]
fn phase5_failure_info_bits_set_then_contains() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    assert!(bits.contains(PkiFailureInfo::BadAlg));
    assert!(!bits.contains(PkiFailureInfo::BadPop));
    assert_eq!(bits.count(), 1);
    assert!(!bits.is_empty());
}

#[test]
fn phase5_failure_info_bits_set_multiple() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    bits.set(PkiFailureInfo::BadPop);
    bits.set(PkiFailureInfo::DuplicateCertReq);
    assert_eq!(bits.count(), 3);
    assert!(bits.contains(PkiFailureInfo::BadAlg));
    assert!(bits.contains(PkiFailureInfo::BadPop));
    assert!(bits.contains(PkiFailureInfo::DuplicateCertReq));
    assert!(!bits.contains(PkiFailureInfo::BadTime));
}

#[test]
fn phase5_failure_info_bits_set_idempotent() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    bits.set(PkiFailureInfo::BadAlg);
    bits.set(PkiFailureInfo::BadAlg);
    assert_eq!(bits.count(), 1);
}

#[test]
fn phase5_failure_info_bits_unset() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    bits.set(PkiFailureInfo::BadPop);
    bits.unset(PkiFailureInfo::BadAlg);
    assert!(!bits.contains(PkiFailureInfo::BadAlg));
    assert!(bits.contains(PkiFailureInfo::BadPop));
    assert_eq!(bits.count(), 1);
}

#[test]
fn phase5_failure_info_bits_unset_absent_is_noop() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    bits.unset(PkiFailureInfo::BadPop); // Not previously set
    assert_eq!(bits.count(), 1);
    assert!(bits.contains(PkiFailureInfo::BadAlg));
}

#[test]
fn phase5_failure_info_bits_clear() {
    let mut bits = FailureInfoBits::new();
    for (_, _, info) in ALL_FAILURE_INFO_VARIANTS {
        bits.set(info);
    }
    assert_eq!(bits.count(), 27);
    bits.clear();
    assert!(bits.is_empty());
    assert_eq!(bits.count(), 0);
}

#[test]
fn phase5_failure_info_bits_from_raw_round_trip() {
    let raw: u32 = 0b1010_1010;
    let bits = FailureInfoBits::from_raw(raw);
    assert_eq!(bits.as_raw(), raw);
}

#[test]
fn phase5_failure_info_bits_from_raw_masks_high_bits() {
    // u32::MAX has bits 0..=31 set; only bits 0..=26 are in VALID_MASK.
    let bits = FailureInfoBits::from_raw(u32::MAX);
    assert_eq!(bits.as_raw(), FailureInfoBits::VALID_MASK);
    assert_eq!(bits.count(), 27);
}

#[test]
fn phase5_failure_info_bits_from_raw_zero_is_empty() {
    let bits = FailureInfoBits::from_raw(0);
    assert!(bits.is_empty());
}

#[test]
fn phase5_failure_info_bits_from_raw_drops_bit_27_only() {
    let raw: u32 = 1u32 << 27;
    let bits = FailureInfoBits::from_raw(raw);
    assert_eq!(bits.as_raw(), 0);
    assert!(bits.is_empty());
}

#[test]
fn phase5_failure_info_bits_iter_ascending_order() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::DuplicateCertReq); // idx 26
    bits.set(PkiFailureInfo::BadAlg); // idx 0
    bits.set(PkiFailureInfo::BadTime); // idx 3
    bits.set(PkiFailureInfo::BadPop); // idx 9
    let collected: Vec<PkiFailureInfo> = bits.iter().collect();
    assert_eq!(
        collected,
        vec![
            PkiFailureInfo::BadAlg,
            PkiFailureInfo::BadTime,
            PkiFailureInfo::BadPop,
            PkiFailureInfo::DuplicateCertReq,
        ]
    );
}

#[test]
fn phase5_failure_info_bits_iter_empty_yields_nothing() {
    let bits = FailureInfoBits::new();
    let collected: Vec<PkiFailureInfo> = bits.iter().collect();
    assert!(collected.is_empty());
}

#[test]
fn phase5_failure_info_bits_to_vec_matches_iter() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    bits.set(PkiFailureInfo::BadPop);
    let from_iter: Vec<PkiFailureInfo> = bits.iter().collect();
    let from_to_vec = bits.to_vec();
    assert_eq!(from_iter, from_to_vec);
}

#[test]
fn phase5_failure_info_bits_to_vec_full_set() {
    let mut bits = FailureInfoBits::new();
    for (_, _, info) in ALL_FAILURE_INFO_VARIANTS {
        bits.set(info);
    }
    let v = bits.to_vec();
    assert_eq!(v.len(), 27);
    // Order must be ascending bit index.
    for (i, info) in v.iter().enumerate() {
        let expected_idx: u8 =
            u8::try_from(i).expect("0..27 fits in u8");
        assert_eq!(info.bit_index(), expected_idx);
    }
}

#[test]
fn phase5_failure_info_bits_union() {
    let mut a = FailureInfoBits::new();
    a.set(PkiFailureInfo::BadAlg);
    a.set(PkiFailureInfo::BadPop);

    let mut b = FailureInfoBits::new();
    b.set(PkiFailureInfo::BadPop);
    b.set(PkiFailureInfo::CertRevoked);

    let u = a.union(b);
    assert_eq!(u.count(), 3);
    assert!(u.contains(PkiFailureInfo::BadAlg));
    assert!(u.contains(PkiFailureInfo::BadPop));
    assert!(u.contains(PkiFailureInfo::CertRevoked));
}

#[test]
fn phase5_failure_info_bits_union_with_empty() {
    let mut a = FailureInfoBits::new();
    a.set(PkiFailureInfo::BadAlg);
    let empty = FailureInfoBits::new();
    let u = a.union(empty);
    assert_eq!(u.count(), 1);
    assert!(u.contains(PkiFailureInfo::BadAlg));
}

#[test]
fn phase5_failure_info_bits_intersection() {
    let mut a = FailureInfoBits::new();
    a.set(PkiFailureInfo::BadAlg);
    a.set(PkiFailureInfo::BadPop);

    let mut b = FailureInfoBits::new();
    b.set(PkiFailureInfo::BadPop);
    b.set(PkiFailureInfo::CertRevoked);

    let i = a.intersection(b);
    assert_eq!(i.count(), 1);
    assert!(i.contains(PkiFailureInfo::BadPop));
    assert!(!i.contains(PkiFailureInfo::BadAlg));
    assert!(!i.contains(PkiFailureInfo::CertRevoked));
}

#[test]
fn phase5_failure_info_bits_intersection_disjoint_is_empty() {
    let mut a = FailureInfoBits::new();
    a.set(PkiFailureInfo::BadAlg);
    let mut b = FailureInfoBits::new();
    b.set(PkiFailureInfo::CertRevoked);
    let i = a.intersection(b);
    assert!(i.is_empty());
}

#[test]
fn phase5_failure_info_bits_from_iterator() {
    let bits: FailureInfoBits = [
        PkiFailureInfo::BadAlg,
        PkiFailureInfo::BadPop,
        PkiFailureInfo::CertRevoked,
    ]
    .into_iter()
    .collect();
    assert_eq!(bits.count(), 3);
    assert!(bits.contains(PkiFailureInfo::BadAlg));
    assert!(bits.contains(PkiFailureInfo::BadPop));
    assert!(bits.contains(PkiFailureInfo::CertRevoked));
}

#[test]
fn phase5_failure_info_bits_from_iterator_empty() {
    let empty: [PkiFailureInfo; 0] = [];
    let bits: FailureInfoBits = empty.into_iter().collect();
    assert!(bits.is_empty());
}

#[test]
fn phase5_failure_info_bits_from_iterator_with_duplicates() {
    let bits: FailureInfoBits = [
        PkiFailureInfo::BadAlg,
        PkiFailureInfo::BadAlg,
        PkiFailureInfo::BadPop,
    ]
    .into_iter()
    .collect();
    assert_eq!(bits.count(), 2);
    assert!(bits.contains(PkiFailureInfo::BadAlg));
    assert!(bits.contains(PkiFailureInfo::BadPop));
}

#[test]
fn phase5_failure_info_bits_display_empty() {
    let bits = FailureInfoBits::new();
    assert_eq!(format!("{bits}"), "(none)");
}

#[test]
fn phase5_failure_info_bits_display_single() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    assert_eq!(format!("{bits}"), "badAlg");
}

#[test]
fn phase5_failure_info_bits_display_multiple_ascending_order() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::CertRevoked); // idx 10
    bits.set(PkiFailureInfo::BadAlg); // idx 0
    bits.set(PkiFailureInfo::BadPop); // idx 9
    // Per Display impl, ", " separator between names in ascending bit order.
    assert_eq!(format!("{bits}"), "badAlg, badPOP, certRevoked");
}

#[test]
fn phase5_failure_info_bits_equality_same_bits() {
    let mut a = FailureInfoBits::new();
    a.set(PkiFailureInfo::BadAlg);
    let mut b = FailureInfoBits::new();
    b.set(PkiFailureInfo::BadAlg);
    assert_eq!(a, b);
}

#[test]
fn phase5_failure_info_bits_equality_different_bits() {
    let mut a = FailureInfoBits::new();
    a.set(PkiFailureInfo::BadAlg);
    let mut b = FailureInfoBits::new();
    b.set(PkiFailureInfo::BadPop);
    assert_ne!(a, b);
}

#[test]
fn phase5_failure_info_bits_copy_semantics() {
    let mut original = FailureInfoBits::new();
    original.set(PkiFailureInfo::BadAlg);
    let copy = original; // FailureInfoBits is Copy
    assert!(copy.contains(PkiFailureInfo::BadAlg));
    // original is still usable due to Copy.
    assert!(original.contains(PkiFailureInfo::BadAlg));
}

// =============================================================================
// Phase 6 — PkiStatusInfo
// =============================================================================

#[test]
fn phase6_status_info_new_minimal() {
    let info = PkiStatusInfo::new(PkiStatus::Accepted);
    assert_eq!(info.status(), PkiStatus::Accepted);
    assert!(info.status_strings().is_empty());
    assert!(info.failure_info().is_none());
}

#[test]
fn phase6_status_info_with_text_appends() {
    let info = PkiStatusInfo::new(PkiStatus::Accepted)
        .with_text("first")
        .with_text("second");
    assert_eq!(info.status_strings(), &["first".to_string(), "second".to_string()]);
}

#[test]
fn phase6_status_info_with_texts_replaces_not_appends() {
    let info = PkiStatusInfo::new(PkiStatus::Accepted)
        .with_text("preexisting")
        .with_texts(["replacement-a", "replacement-b"]);
    assert_eq!(
        info.status_strings(),
        &["replacement-a".to_string(), "replacement-b".to_string()]
    );
}

#[test]
fn phase6_status_info_with_texts_empty_clears() {
    let info = PkiStatusInfo::new(PkiStatus::Accepted)
        .with_text("preexisting")
        .with_texts::<[&str; 0], &str>([]);
    assert!(info.status_strings().is_empty());
}

#[test]
fn phase6_status_info_with_failure_info() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    let info = PkiStatusInfo::new(PkiStatus::Rejection).with_failure_info(bits);
    let stored = info.failure_info().expect("failure_info must be Some");
    assert_eq!(stored, bits);
}

#[test]
fn phase6_status_info_add_text_mutates() {
    let mut info = PkiStatusInfo::new(PkiStatus::Accepted);
    info.add_text("hello");
    info.add_text("world");
    assert_eq!(info.status_strings().len(), 2);
}

#[test]
fn phase6_status_info_set_failure_info_mutates() {
    let mut info = PkiStatusInfo::new(PkiStatus::Rejection);
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    info.set_failure_info(bits);
    assert_eq!(info.failure_info().unwrap(), bits);
}

#[test]
fn phase6_status_info_clear_failure_info() {
    let mut info = PkiStatusInfo::new(PkiStatus::Rejection);
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    info.set_failure_info(bits);
    assert!(info.failure_info().is_some());
    info.clear_failure_info();
    assert!(info.failure_info().is_none());
}

#[test]
fn phase6_status_info_is_positive_delegates_to_status() {
    assert!(PkiStatusInfo::new(PkiStatus::Accepted).is_positive());
    assert!(PkiStatusInfo::new(PkiStatus::GrantedWithMods).is_positive());
    assert!(!PkiStatusInfo::new(PkiStatus::Rejection).is_positive());
    assert!(!PkiStatusInfo::new(PkiStatus::Waiting).is_positive());
}

#[test]
fn phase6_status_info_display_status_only() {
    let info = PkiStatusInfo::new(PkiStatus::Accepted);
    let formatted = format!("{info}");
    assert!(formatted.contains("status=PKI request accepted"), "{formatted}");
    assert!(!formatted.contains("text="), "{formatted}");
    assert!(!formatted.contains("failInfo="), "{formatted}");
}

#[test]
fn phase6_status_info_display_with_single_text() {
    let info = PkiStatusInfo::new(PkiStatus::Rejection).with_text("invalid algorithm");
    let formatted = format!("{info}");
    assert!(formatted.contains("text=[invalid algorithm]"), "{formatted}");
}

#[test]
fn phase6_status_info_display_text_uses_semicolon_separator() {
    let info = PkiStatusInfo::new(PkiStatus::Rejection)
        .with_text("first")
        .with_text("second")
        .with_text("third");
    let formatted = format!("{info}");
    // Per cmp.rs Display impl: ", text=[{}]" with status_strings.join("; ")
    assert!(
        formatted.contains("text=[first; second; third]"),
        "expected semicolon-joined text section, got: {formatted}"
    );
}

#[test]
fn phase6_status_info_display_with_failure_info() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    let info = PkiStatusInfo::new(PkiStatus::Rejection).with_failure_info(bits);
    let formatted = format!("{info}");
    assert!(formatted.contains("failInfo=badAlg"), "{formatted}");
}

#[test]
fn phase6_status_info_display_omits_empty_failure_info() {
    let info =
        PkiStatusInfo::new(PkiStatus::Rejection).with_failure_info(FailureInfoBits::new());
    let formatted = format!("{info}");
    // Empty FailureInfoBits should omit the section per cmp.rs Display impl.
    assert!(!formatted.contains("failInfo="), "{formatted}");
}

#[test]
fn phase6_status_info_display_with_all_sections() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    let info = PkiStatusInfo::new(PkiStatus::Rejection)
        .with_text("alpha")
        .with_text("beta")
        .with_failure_info(bits);
    let formatted = format!("{info}");
    assert!(formatted.contains("status=PKI request rejected"), "{formatted}");
    assert!(formatted.contains("text=[alpha; beta]"), "{formatted}");
    assert!(formatted.contains("failInfo=badAlg"), "{formatted}");
}

#[test]
fn phase6_status_info_equality() {
    let mut bits = FailureInfoBits::new();
    bits.set(PkiFailureInfo::BadAlg);
    let a = PkiStatusInfo::new(PkiStatus::Rejection)
        .with_text("alpha")
        .with_failure_info(bits);
    let b = PkiStatusInfo::new(PkiStatus::Rejection)
        .with_text("alpha")
        .with_failure_info(bits);
    assert_eq!(a, b);
}

#[test]
fn phase6_status_info_inequality() {
    let a = PkiStatusInfo::new(PkiStatus::Accepted);
    let b = PkiStatusInfo::new(PkiStatus::Rejection);
    assert_ne!(a, b);
}

// =============================================================================
// Phase 7 — validate_transaction_id
// =============================================================================

#[test]
fn phase7_validate_transaction_id_exactly_16_succeeds() {
    let id = vec![0u8; TRANSACTION_ID_LEN];
    validate_transaction_id(&id).expect("16-octet id must succeed");
}

#[test]
fn phase7_validate_transaction_id_pattern_succeeds() {
    let id: Vec<u8> = (0..16u8).collect();
    validate_transaction_id(&id).expect("16-octet pattern must succeed");
}

#[test]
fn phase7_validate_transaction_id_empty_fails() {
    let err = validate_transaction_id(&[]).expect_err("empty id must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP transaction ID length"), "{msg}");
}

#[test]
fn phase7_validate_transaction_id_15_octets_fails() {
    let id = vec![0u8; 15];
    let err = validate_transaction_id(&id).expect_err("15 octets must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP transaction ID length"), "{msg}");
    assert!(msg.contains("15"), "diagnostic must include actual length: {msg}");
    assert!(msg.contains("16"), "diagnostic must include required length: {msg}");
}

#[test]
fn phase7_validate_transaction_id_17_octets_fails() {
    let id = vec![0u8; 17];
    let err = validate_transaction_id(&id).expect_err("17 octets must fail (too long)");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP transaction ID length"), "{msg}");
    assert!(msg.contains("17"), "{msg}");
}

#[test]
fn phase7_validate_transaction_id_100_octets_fails() {
    let id = vec![0u8; 100];
    let err = validate_transaction_id(&id).expect_err("100 octets must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP transaction ID length"), "{msg}");
}

#[test]
fn phase7_validate_transaction_id_diagnostic_mentions_rfc() {
    let id = vec![0u8; 8];
    let err = validate_transaction_id(&id).expect_err("must fail");
    let msg = unwrap_verification(err);
    // Spec reference is included to aid debugging.
    assert!(msg.contains("RFC 4210") || msg.contains("§5.1.1"), "{msg}");
}

// =============================================================================
// Phase 8 — validate_nonce
// =============================================================================

#[test]
fn phase8_validate_nonce_exactly_16_succeeds() {
    let nonce = vec![0u8; MIN_NONCE_LEN];
    validate_nonce(&nonce).expect("16-octet nonce must succeed");
}

#[test]
fn phase8_validate_nonce_17_octets_succeeds() {
    let nonce = vec![0u8; 17];
    validate_nonce(&nonce).expect("17 octets must succeed (≥16)");
}

#[test]
fn phase8_validate_nonce_32_octets_succeeds() {
    let nonce = vec![0u8; 32];
    validate_nonce(&nonce).expect("32 octets must succeed");
}

#[test]
fn phase8_validate_nonce_256_octets_succeeds() {
    let nonce = vec![0u8; 256];
    validate_nonce(&nonce).expect("256 octets must succeed");
}

#[test]
fn phase8_validate_nonce_empty_fails() {
    let err = validate_nonce(&[]).expect_err("empty nonce must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP nonce length"), "{msg}");
}

#[test]
fn phase8_validate_nonce_8_octets_fails() {
    let nonce = vec![0u8; 8];
    let err = validate_nonce(&nonce).expect_err("8 octets must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP nonce length"), "{msg}");
    assert!(msg.contains("8"), "{msg}");
    assert!(msg.contains("16"), "{msg}");
}

#[test]
fn phase8_validate_nonce_15_octets_fails_at_boundary() {
    let nonce = vec![0u8; 15];
    let err = validate_nonce(&nonce).expect_err("15 octets must fail (1 below minimum)");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP nonce length"), "{msg}");
}

#[test]
fn phase8_validate_nonce_diagnostic_mentions_rfc() {
    let nonce = vec![0u8; 4];
    let err = validate_nonce(&nonce).expect_err("must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("RFC 4210") || msg.contains("§5.1.1"), "{msg}");
}

// =============================================================================
// Phase 9 — PkiHeader / PkiHeaderBuilder
// =============================================================================

fn sample_general_name(label: &str) -> Vec<u8> {
    label.as_bytes().to_vec()
}

#[test]
fn phase9_builder_default_is_v2() {
    let builder = PkiHeaderBuilder::default();
    let header = builder
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("default builder must build with required fields");
    assert_eq!(header.pvno(), PkiVersion::V2);
}

#[test]
fn phase9_builder_new_v2_succeeds_with_minimum_fields() {
    let header = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("v2 with sender+recipient must build");
    assert_eq!(header.pvno(), PkiVersion::V2);
    assert_eq!(header.sender(), b"CN=Sub");
    assert_eq!(header.recipient(), b"CN=CA");
    assert!(header.message_time().is_none());
    assert!(header.transaction_id().is_none());
    assert!(header.sender_nonce().is_none());
    assert!(header.recipient_nonce().is_none());
}

#[test]
fn phase9_builder_v3_carries_through_to_pvno() {
    let header = PkiHeaderBuilder::new(PkiVersion::V3)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("v3 must build");
    assert_eq!(header.pvno(), PkiVersion::V3);
}

#[test]
fn phase9_builder_with_all_fields_round_trips() {
    let txid = vec![0xAA; 16];
    let snonce = vec![0xBB; 16];
    let rnonce = vec![0xCC; 32];
    let header = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .message_time(1_700_000_000)
        .transaction_id(txid.clone())
        .sender_nonce(snonce.clone())
        .recipient_nonce(rnonce.clone())
        .build()
        .expect("full builder must build");
    assert_eq!(header.pvno(), PkiVersion::V2);
    assert_eq!(header.sender(), b"CN=Sub");
    assert_eq!(header.recipient(), b"CN=CA");
    assert_eq!(header.message_time(), Some(1_700_000_000));
    assert_eq!(header.transaction_id().unwrap(), txid.as_slice());
    assert_eq!(header.sender_nonce().unwrap(), snonce.as_slice());
    assert_eq!(header.recipient_nonce().unwrap(), rnonce.as_slice());
}

#[test]
fn phase9_builder_missing_sender_fails() {
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect_err("missing sender must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("sender"), "{msg}");
    assert!(msg.contains("RFC 4210") || msg.contains("§5.1.1"), "{msg}");
}

#[test]
fn phase9_builder_missing_recipient_fails() {
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .build()
        .expect_err("missing recipient must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("recipient"), "{msg}");
}

#[test]
fn phase9_builder_missing_both_sender_and_recipient_fails_on_sender_first() {
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .build()
        .expect_err("must fail");
    let msg = unwrap_verification(err);
    // The implementation checks sender before recipient.
    assert!(msg.contains("sender"), "{msg}");
}

#[test]
fn phase9_builder_invalid_transaction_id_15_octets_fails() {
    let bad_txid = vec![0u8; 15];
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .transaction_id(bad_txid)
        .build()
        .expect_err("15-octet txid must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP transaction ID length"), "{msg}");
}

#[test]
fn phase9_builder_invalid_transaction_id_17_octets_fails() {
    let bad_txid = vec![0u8; 17];
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .transaction_id(bad_txid)
        .build()
        .expect_err("17-octet txid must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP transaction ID length"), "{msg}");
}

#[test]
fn phase9_builder_invalid_sender_nonce_short_fails() {
    let bad_nonce = vec![0u8; 8];
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .sender_nonce(bad_nonce)
        .build()
        .expect_err("8-octet sender nonce must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP nonce length"), "{msg}");
}

#[test]
fn phase9_builder_invalid_recipient_nonce_short_fails() {
    let bad_nonce = vec![0u8; 4];
    let err = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .recipient_nonce(bad_nonce)
        .build()
        .expect_err("4-octet recipient nonce must fail");
    let msg = unwrap_verification(err);
    assert!(msg.contains("CMP nonce length"), "{msg}");
}

#[test]
fn phase9_builder_message_time_negative_passes() {
    // Negative message_time is allowed at this layer (UTC seconds since epoch
    // can be negative for pre-1970 timestamps).
    let header = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .message_time(-1)
        .build()
        .expect("negative message_time accepted");
    assert_eq!(header.message_time(), Some(-1));
}

#[test]
fn phase9_builder_long_nonce_accepted() {
    let long_nonce = vec![0u8; 256];
    let header = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .sender_nonce(long_nonce.clone())
        .build()
        .expect("256-octet nonce must succeed (≥16)");
    assert_eq!(header.sender_nonce().unwrap().len(), 256);
}

#[test]
fn phase9_header_equality() {
    let a = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("a builds");
    let b = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("b builds");
    assert_eq!(a, b);
}

#[test]
fn phase9_header_inequality_different_pvno() {
    let a = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("a builds");
    let b = PkiHeaderBuilder::new(PkiVersion::V3)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("b builds");
    assert_ne!(a, b);
}

#[test]
fn phase9_header_inequality_different_sender() {
    let a = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub-A"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("a builds");
    let b = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sample_general_name("CN=Sub-B"))
        .recipient(sample_general_name("CN=CA"))
        .build()
        .expect("b builds");
    assert_ne!(a, b);
}

#[test]
fn phase9_header_clone_preserves_fields() {
    let original = PkiHeaderBuilder::new(PkiVersion::V3)
        .sender(sample_general_name("CN=Sub"))
        .recipient(sample_general_name("CN=CA"))
        .transaction_id(vec![0xDE; 16])
        .build()
        .expect("builds");
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// =============================================================================
// Phase 10 — Module-level helpers
// =============================================================================

#[test]
fn phase10_all_failure_info_names_returns_27() {
    let names = all_failure_info_names();
    assert_eq!(names.len(), 27);
}

#[test]
fn phase10_all_failure_info_names_includes_canonical_strings() {
    let names = all_failure_info_names();
    // Spot-check several names per RFC 4210 §5.2.4.
    assert!(names.contains(&"badAlg"));
    assert!(names.contains(&"badPOP"));
    assert!(names.contains(&"badMessageCheck"));
    assert!(names.contains(&"signerNotTrusted"));
    assert!(names.contains(&"duplicateCertReq"));
}

#[test]
fn phase10_all_failure_info_names_no_duplicates() {
    use std::collections::HashSet;
    let names = all_failure_info_names();
    let unique: HashSet<&&str> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "all names must be distinct");
}

#[test]
fn phase10_all_failure_info_names_in_ascending_bit_order() {
    let names = all_failure_info_names();
    for (i, name) in names.iter().enumerate() {
        let expected = ALL_FAILURE_INFO_VARIANTS[i].1;
        assert_eq!(*name, expected, "names must follow PkiFailureInfo::all() order");
    }
}

#[test]
fn phase10_all_pki_statuses_returns_10() {
    let statuses = all_pki_statuses();
    assert_eq!(statuses.len(), 10);
}

#[test]
fn phase10_all_pki_statuses_contains_every_variant() {
    let statuses = all_pki_statuses();
    for (_, expected) in ALL_PKI_STATUS_VALUES {
        assert!(
            statuses.contains(&expected),
            "all_pki_statuses must contain {expected:?}"
        );
    }
}

#[test]
fn phase10_all_pki_statuses_is_a_set() {
    // Uniqueness is enforced by the HashSet type itself; this test simply
    // confirms by re-inserting that the count remains 10.
    let mut statuses = all_pki_statuses();
    statuses.insert(PkiStatus::Accepted); // already present
    statuses.insert(PkiStatus::Rejection); // already present
    assert_eq!(statuses.len(), 10);
}
