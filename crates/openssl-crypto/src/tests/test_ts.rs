//! Integration tests for the RFC 3161 Timestamp Protocol module (`crate::ts`).
//!
//! These tests exercise the **public API surface** of the timestamp module from
//! the crate boundary, complementing the unit tests in `ts::tests` which use
//! `super::*`.  They validate:
//!
//! - **Phase 2 — Request construction:** `TsRequest` via convenience
//!   [`new_request()`] and the fluent [`TsRequestBuilder`] API.
//! - **Phase 3 — Response status parsing:** [`TsStatus`] enum coverage and
//!   [`TsTokenInfo`] field accessors.
//! - **Phase 4 — Verification round-trip:** [`verify()`] with matching and
//!   mismatched request/response pairs, including nonce mismatch detection.
//!
//! # C Source Mapping
//!
//! | C File                 | Rust Under Test                             |
//! |------------------------|---------------------------------------------|
//! | `ts_req_utils.c`       | [`TsRequest`], [`TsRequestBuilder`]         |
//! | `ts_rsp_verify.c`      | [`verify()`], status/imprint/nonce checking  |
//! | `ts_verify_ctx.c`      | [`TsVerifyContext`]                         |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Every assertion uses `Result`/`Option`; no sentinel
//!   values (0, -1, "") anywhere in test data or assertions.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this file.
//! - **R9 (Warning-Free):** All items used; no dead code.
//! - **R10 (Wiring):** Reachable via `#[cfg(test)]` + `#[cfg(feature = "ts")]`.

// Test code legitimately uses expect/unwrap/panic for assertion clarity.
// The cfg(feature = "ts") gate is applied in tests/mod.rs on the `mod test_ts;`
// declaration, so an inner attribute here would be a duplicate.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use openssl_common::error::CryptoError;
use openssl_common::time::OsslTime;
use openssl_common::types::Nid;

use crate::ts::{
    new_request, verify, TsAccuracy, TsMessageImprint, TsRequestBuilder, TsResponse, TsStatus,
    TsStatusInfo, TsTokenInfo, TsVerifyContext, TS_VFY_IMPRINT, TS_VFY_NONCE, TS_VFY_POLICY,
    TS_VFY_VERSION,
};

// =============================================================================
// Helper: Build a well-known 32-byte SHA-256 digest for reuse across tests.
// =============================================================================

/// Returns a deterministic 32-byte SHA-256 digest value for test fixtures.
///
/// Using a fixed byte pattern (`0xAB` repeated) ensures reproducibility and
/// avoids coupling to any actual hashing implementation.
fn sha256_test_hash() -> Vec<u8> {
    vec![0xABu8; 32]
}

/// Builds a [`TsMessageImprint`] with SHA-256 and the standard test hash.
fn sha256_imprint() -> TsMessageImprint {
    TsMessageImprint::new(Nid::SHA256, sha256_test_hash())
        .expect("SHA-256 imprint with 32-byte hash must succeed")
}

/// Builds a minimal [`TsTokenInfo`] that matches the given `imprint` and
/// optional `nonce`, suitable for successful verification against a matching
/// [`TsRequest`].
///
/// The `policy` is set to `"1.2.3.4.1"`, `serial_number` to `[0,0,0,1]`,
/// `gen_time` to a fixed epoch value, and all other optional fields are `None`.
fn matching_token_info(
    imprint: &TsMessageImprint,
    nonce: Option<Vec<u8>>,
    policy: &str,
) -> TsTokenInfo {
    TsTokenInfo {
        version: 1,
        policy: policy.to_string(),
        serial_number: vec![0, 0, 0, 1],
        gen_time: OsslTime::from_seconds(1_700_000_000),
        accuracy: None,
        message_imprint: imprint.clone(),
        nonce,
        tsa_name: None,
        ordering: false,
        extensions: Vec::new(),
    }
}

/// Wraps a [`TsTokenInfo`] in a granted [`TsResponse`].
fn granted_response(token: TsTokenInfo) -> TsResponse {
    TsResponse {
        status: TsStatusInfo::new(TsStatus::Granted),
        token_info: Some(token),
    }
}

// =============================================================================
// Phase 2 — Request Tests
// =============================================================================

/// Validates basic timestamp request construction via the convenience
/// [`new_request()`] function.
///
/// Exercises:
/// - `new_request("SHA256", &hash)` — algorithm resolution and digest length
///   validation (mirrors `TS_REQ_new` + `TS_REQ_set_msg_imprint` from
///   `ts_req_utils.c`).
/// - `TsRequest::version()` — must be `1` per RFC 3161 §2.4.1.
/// - `TsRequest::message_imprint()` — hash algorithm and digest bytes.
/// - `TsRequest::nonce()` — `None` when not explicitly set (R5 compliance).
/// - `TsRequest::policy_id()` — `None` when not explicitly set.
/// - `TsRequest::cert_req()` — `false` by default.
#[test]
fn test_ts_request_construction() {
    let hash = sha256_test_hash();
    let req =
        new_request("SHA256", &hash).expect("new_request must succeed with valid SHA-256 hash");

    // Version MUST be 1 per RFC 3161 §2.4.1.
    assert_eq!(req.version(), 1, "request version must be 1");

    // Message imprint: algorithm NID and digest bytes must match input.
    let imprint = req.message_imprint();
    assert_eq!(
        imprint.hash_algorithm(),
        Nid::SHA256,
        "hash algorithm must be SHA-256"
    );
    assert_eq!(
        imprint.hashed_message(),
        hash.as_slice(),
        "hashed message must match input bytes"
    );

    // Optional fields default to None / false when using new_request().
    assert!(
        req.nonce().is_none(),
        "nonce must be None when not explicitly set"
    );
    assert!(
        req.policy_id().is_none(),
        "policy_id must be None when not explicitly set"
    );
    assert!(!req.cert_req(), "cert_req must default to false");
}

/// Validates setting an optional nonce via the [`TsRequestBuilder`].
///
/// Exercises:
/// - `TsRequestBuilder::new(imprint)` — builder initialization.
/// - `TsRequestBuilder::nonce(vec)` — fluent nonce setter.
/// - `TsRequestBuilder::build()` — finalisation.
/// - `TsRequest::nonce()` — must return `Some(&[u8])` matching input.
///
/// Corresponds to C `TS_REQ_set_nonce()` in `ts_req_utils.c` (line 99).
#[test]
fn test_ts_request_with_nonce() {
    let imprint = sha256_imprint();
    let nonce_bytes: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let req = TsRequestBuilder::new(imprint)
        .nonce(nonce_bytes.clone())
        .build()
        .expect("build with nonce must succeed");

    // The nonce must be present and equal to the supplied bytes.
    let returned_nonce = req
        .nonce()
        .expect("nonce must be Some when explicitly set via builder");
    assert_eq!(
        returned_nonce,
        &nonce_bytes[..],
        "nonce bytes must match input"
    );

    // Other optional fields remain at defaults.
    assert!(req.policy_id().is_none(), "policy_id must remain None");
    assert!(!req.cert_req(), "cert_req must remain false");
    assert_eq!(req.version(), 1, "version must be 1");
}

/// Validates setting a policy OID via the [`TsRequestBuilder`].
///
/// Exercises:
/// - `TsRequestBuilder::policy_id(String)` — fluent policy setter.
/// - `TsRequest::policy_id()` — must return `Some("1.2.3.4.5")`.
///
/// Corresponds to C `TS_REQ_set_policy_id()` in `ts_req_utils.c` (line 81).
#[test]
fn test_ts_request_with_policy() {
    let imprint = sha256_imprint();
    let policy_oid = "1.2.3.4.5".to_string();

    let req = TsRequestBuilder::new(imprint)
        .policy_id(policy_oid.clone())
        .build()
        .expect("build with policy_id must succeed");

    // The policy OID must be present and match.
    let returned_policy = req
        .policy_id()
        .expect("policy_id must be Some when explicitly set via builder");
    assert_eq!(returned_policy, "1.2.3.4.5", "policy OID must match input");

    // Nonce and cert_req remain at defaults.
    assert!(req.nonce().is_none(), "nonce must remain None");
    assert!(!req.cert_req(), "cert_req must remain false");
}

/// Validates the full fluent builder API by chaining all optional setters.
///
/// Exercises:
/// - `TsRequestBuilder::new()` → `.nonce()` → `.policy_id()` → `.cert_req()`
///   → `.build()` — ensures method chaining works due to `#[must_use]` moves.
/// - Verifies every field is correctly propagated to the built [`TsRequest`].
///
/// Mirrors the C pattern of calling `TS_REQ_set_nonce()`,
/// `TS_REQ_set_policy_id()`, and `TS_REQ_set_cert_req()` sequentially on
/// a `TS_REQ` object (from `ts_req_utils.c`).
#[test]
fn test_ts_request_builder_pattern() {
    let imprint = sha256_imprint();
    let nonce = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let policy = "2.16.840.1.101.3.4.2.1".to_string();

    let req = TsRequestBuilder::new(imprint.clone())
        .nonce(nonce.clone())
        .policy_id(policy.clone())
        .cert_req(true)
        .build()
        .expect("fully-configured builder must succeed");

    // Verify all fields.
    assert_eq!(req.version(), 1, "version must be 1");
    assert_eq!(
        req.message_imprint().hash_algorithm(),
        Nid::SHA256,
        "algorithm must be SHA-256"
    );
    assert_eq!(
        req.message_imprint().hashed_message(),
        &sha256_test_hash()[..],
        "hashed message must match"
    );
    assert_eq!(
        req.nonce().expect("nonce must be set"),
        &nonce[..],
        "nonce must match input"
    );
    assert_eq!(
        req.policy_id().expect("policy must be set"),
        policy.as_str(),
        "policy must match input"
    );
    assert!(req.cert_req(), "cert_req must be true");
}

// =============================================================================
// Phase 3 — Response Tests
// =============================================================================

/// Validates all [`TsStatus`] enum variants can be created from raw integer
/// values and that the `Display` implementation matches RFC 3161 names.
///
/// Exercises:
/// - `TsStatus::from_raw(0..=5)` — all six valid status codes.
/// - `TsStatus::from_raw(6)` / `TsStatus::from_raw(-1)` — out-of-range returns `None`.
/// - `TsStatus::is_granted()` — `true` for `Granted` and `GrantedWithMods`,
///   `false` for all others.
/// - `Display` impl — exact RFC 3161 status names.
///
/// Mirrors the status parsing logic in `ts_rsp_verify.c`
/// `ts_check_status_info()` (line 342).
#[test]
fn test_ts_response_status_enum() {
    // Exhaustive coverage of all six valid raw values.
    let cases: &[(i64, TsStatus, &str, bool)] = &[
        (0, TsStatus::Granted, "granted", true),
        (1, TsStatus::GrantedWithMods, "grantedWithMods", true),
        (2, TsStatus::Rejection, "rejection", false),
        (3, TsStatus::Waiting, "waiting", false),
        (4, TsStatus::RevocationWarning, "revocationWarning", false),
        (
            5,
            TsStatus::RevocationNotification,
            "revocationNotification",
            false,
        ),
    ];

    for &(raw, expected_variant, expected_display, expected_granted) in cases {
        let status =
            TsStatus::from_raw(raw).unwrap_or_else(|| panic!("from_raw({raw}) must return Some"));

        assert_eq!(
            status, expected_variant,
            "from_raw({raw}) must yield {expected_variant:?}"
        );

        assert_eq!(
            format!("{status}"),
            expected_display,
            "Display for raw {raw} must be \"{expected_display}\""
        );

        assert_eq!(
            status.is_granted(),
            expected_granted,
            "is_granted() for {expected_variant:?} must be {expected_granted}"
        );

        // Round-trip: as_raw must return the original value.
        assert_eq!(
            status.as_raw(),
            raw,
            "as_raw() round-trip for {expected_variant:?}"
        );
    }

    // Invalid raw values must return None (R5 compliance — no sentinel).
    assert!(
        TsStatus::from_raw(6).is_none(),
        "from_raw(6) must return None"
    );
    assert!(
        TsStatus::from_raw(-1).is_none(),
        "from_raw(-1) must return None"
    );
    assert!(
        TsStatus::from_raw(100).is_none(),
        "from_raw(100) must return None"
    );
}

/// Validates [`TsTokenInfo`] field accessors for a fully-populated token.
///
/// Exercises:
/// - `TsTokenInfo::version()` — must be `1`.
/// - `TsTokenInfo::gen_time()` — must match the set time.
/// - `TsTokenInfo::serial_number()` — must match the set serial.
/// - `TsTokenInfo::policy()` — must match the set policy OID.
/// - `TsTokenInfo::accuracy()` — must return `Some` with correct values.
/// - `TsTokenInfo::nonce()` — must return `Some` with correct bytes.
/// - `TsTokenInfo::tsa_name()` — must return `Some` with correct name.
///
/// Mirrors C accessor functions from `ts_rsp_utils.c`:
/// `TS_TST_INFO_get_version()`, `TS_TST_INFO_get_time()`, etc.
#[test]
fn test_ts_token_info_fields() {
    let imprint = sha256_imprint();
    let accuracy = TsAccuracy::new(1, 500, 100);
    let nonce_bytes = vec![0x11, 0x22, 0x33, 0x44];
    let gen_time = OsslTime::from_seconds(1_700_000_000);

    let token = TsTokenInfo {
        version: 1,
        policy: "1.3.6.1.4.1.99999.1".to_string(),
        serial_number: vec![0x00, 0x01, 0x02, 0x03],
        gen_time,
        accuracy: Some(accuracy),
        message_imprint: imprint,
        nonce: Some(nonce_bytes.clone()),
        tsa_name: Some("CN=TestTSA,O=TestOrg".to_string()),
        ordering: false,
        extensions: Vec::new(),
    };

    // version accessor
    assert_eq!(token.version(), 1, "version must be 1");

    // gen_time accessor
    assert_eq!(
        token.gen_time(),
        gen_time,
        "gen_time must match constructed value"
    );

    // serial_number accessor
    assert_eq!(
        token.serial_number(),
        &[0x00, 0x01, 0x02, 0x03],
        "serial_number must match"
    );

    // policy accessor
    assert_eq!(
        token.policy(),
        "1.3.6.1.4.1.99999.1",
        "policy OID must match"
    );

    // accuracy accessor — must be Some and contain the correct values.
    let acc = token.accuracy().expect("accuracy must be Some");
    assert_eq!(acc.seconds, 1, "accuracy seconds must be 1");
    assert_eq!(acc.milliseconds, 500, "accuracy milliseconds must be 500");
    assert_eq!(acc.microseconds, 100, "accuracy microseconds must be 100");

    // nonce accessor
    let nonce_ref = token.nonce().expect("nonce must be Some");
    assert_eq!(nonce_ref, &nonce_bytes[..], "nonce bytes must match");

    // tsa_name accessor
    let tsa = token.tsa_name().expect("tsa_name must be Some");
    assert_eq!(tsa, "CN=TestTSA,O=TestOrg", "tsa_name must match");
}

// =============================================================================
// Phase 4 — Verification Tests
// =============================================================================

/// Validates that [`verify()`] succeeds when the response matches the request
/// in all verified fields (nonce, imprint, version, policy).
///
/// Exercises:
/// - `TsVerifyContext::from_request(&request)` — populates flags and expected
///   values from the request (mirrors `TS_REQ_to_TS_VERIFY_CTX()` from
///   `ts_verify_ctx.c` line 144).
/// - `verify(&response, &request, &ctx)` — returns `Ok(true)` when all
///   flag-gated checks pass (mirrors `TS_RESP_verify_response()` from
///   `ts_rsp_verify.c` line 233).
///
/// The verification context is built from the request, which automatically
/// sets `TS_VFY_NONCE` (because nonce is present) and `TS_VFY_IMPRINT`.
/// We additionally add `TS_VFY_VERSION` and `TS_VFY_POLICY` to exercise
/// the full check suite.
#[test]
fn test_ts_verify_request_response_match() {
    let imprint = sha256_imprint();
    let nonce = vec![0x01, 0x02, 0x03, 0x04];

    // Build a request with nonce and policy.
    let request = TsRequestBuilder::new(imprint.clone())
        .nonce(nonce.clone())
        .policy_id("1.2.3.4.1".to_string())
        .build()
        .expect("request build must succeed");

    // Build a token that matches the request exactly using the helper.
    let token = matching_token_info(&imprint, Some(nonce), "1.2.3.4.1");
    let response = granted_response(token);

    // Build verify context from the request and add additional flags.
    let mut ctx = TsVerifyContext::from_request(&request);
    ctx.add_flags(TS_VFY_VERSION | TS_VFY_POLICY);

    // Verification must succeed.
    let result = verify(&response, &request, &ctx)
        .expect("verification must succeed for matching request/response");
    assert!(result, "verify must return true for matching pair");

    // Also verify the context flags are correctly populated.
    let flags = ctx.flags();
    assert_ne!(
        flags & TS_VFY_NONCE,
        0,
        "TS_VFY_NONCE flag must be set (from request nonce)"
    );
    assert_ne!(
        flags & TS_VFY_IMPRINT,
        0,
        "TS_VFY_IMPRINT flag must be set (from request imprint)"
    );
    assert_ne!(
        flags & TS_VFY_VERSION,
        0,
        "TS_VFY_VERSION flag must be set (explicitly added)"
    );
    assert_ne!(
        flags & TS_VFY_POLICY,
        0,
        "TS_VFY_POLICY flag must be set (explicitly added)"
    );
}

/// Validates that [`verify()`] detects a nonce mismatch and returns
/// [`CryptoError::Verification`].
///
/// Exercises:
/// - `TsVerifyContext::from_request(&request)` — sets `TS_VFY_NONCE` because
///   the request has a nonce.
/// - `verify()` — `check_nonces()` detects the mismatch and returns
///   `Err(CryptoError::Verification("nonce mismatch ..."))`.
/// - Pattern matching on `CryptoError::Verification(msg)` — confirms the
///   error variant and that the message indicates a nonce mismatch.
///
/// Mirrors C `ts_check_nonces()` in `ts_rsp_verify.c` (line 460) which
/// compares `TS_REQ_get_nonce(req)` against `TS_TST_INFO_get_nonce(info)`.
#[test]
fn test_ts_verify_nonce_mismatch_fails() {
    let imprint = sha256_imprint();
    let request_nonce = vec![0x01, 0x02, 0x03, 0x04];
    let response_nonce = vec![0x05, 0x06, 0x07, 0x08]; // Deliberately different.

    // Build a request with a specific nonce.
    let request = TsRequestBuilder::new(imprint.clone())
        .nonce(request_nonce)
        .build()
        .expect("request build must succeed");

    // Build a token with a DIFFERENT nonce using the helper.
    let token = matching_token_info(&imprint, Some(response_nonce), "1.2.3.4.1");
    let response = granted_response(token);

    // Build verify context from the request — TS_VFY_NONCE will be set
    // automatically because the request contains a nonce.
    let ctx = TsVerifyContext::from_request(&request);

    // Verification must fail with a nonce mismatch error.
    let err =
        verify(&response, &request, &ctx).expect_err("verification must fail when nonces differ");

    // Assert the error is a Verification variant with "nonce" in the message.
    match &err {
        CryptoError::Verification(msg) => {
            assert!(
                msg.contains("nonce"),
                "error message must mention 'nonce', got: {msg}"
            );
        }
        other => {
            panic!("expected CryptoError::Verification, got: {other:?}");
        }
    }
}
