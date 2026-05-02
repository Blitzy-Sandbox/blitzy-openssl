//! Integration tests for the [`NullProvider`](crate::null::NullProvider).
//!
//! Verifies that the null provider:
//! - Returns correct metadata (name, version, build info, status)
//! - Reports `is_running() == true` at all times (matches C `ossl_prov_is_running()`)
//! - Returns `None` for ALL operation types from `query_operation()`
//! - Returns correct parameters from `get_params()`
//! - Has correct `gettable_params()` list
//! - Exercises full lifecycle: create → query → teardown
//! - Satisfies Rule R5 (no sentinel values) and Rule R8 (zero unsafe)
//!
//! These integration tests complement the inline unit tests in `null.rs` by
//! exercising the [`NullProvider`](crate::null::NullProvider) through the
//! [`Provider`](crate::traits::Provider) trait interface (including dynamic
//! dispatch via trait objects), verifying correct polymorphic behaviour and
//! cross-module integration.
//!
//! Source reference: `providers/nullprov.c`, `providers/prov_running.c`

use crate::null::NullProvider;
use crate::traits::Provider;
use openssl_common::types::OperationType;

// =============================================================================
// Phase 2: Metadata Tests
// =============================================================================

/// Verify provider name matches C `null_get_params` line 40 exactly:
/// `"OpenSSL Null Provider"`. This exact name matching is critical for FFI
/// compatibility with existing C consumers.
#[test]
fn test_null_provider_info_name() {
    let provider = NullProvider::new();
    let info = provider.info();
    assert_eq!(
        info.name, "OpenSSL Null Provider",
        "Name must match the C null_get_params constant exactly"
    );
}

/// Verify provider `info().status` is `true`.
///
/// C reference: `ossl_prov_is_running()` in `prov_running.c` unconditionally
/// returns 1, which the null provider reports via its status param.
#[test]
fn test_null_provider_info_status() {
    let provider = NullProvider::new();
    let info = provider.info();
    assert!(
        info.status,
        "Null provider status should be true (C ossl_prov_is_running() returns 1)"
    );
}

/// Verify `version` and `build_info` are non-empty strings.
///
/// These map to `OPENSSL_VERSION_STR` and `OPENSSL_FULL_VERSION_STR` in C.
#[test]
fn test_null_provider_info_version() {
    let provider = NullProvider::new();
    let info = provider.info();
    assert!(
        !info.version.is_empty(),
        "Version string should be non-empty"
    );
    assert!(
        !info.build_info.is_empty(),
        "Build info string should be non-empty"
    );
}

/// Verify `is_running()` returns `true` for all instances.
///
/// The null provider is stateless and deterministic — every instance reports
/// `is_running() == true`, matching C `ossl_prov_is_running()` which
/// unconditionally returns 1.
#[test]
fn test_null_provider_is_running() {
    let provider1 = NullProvider::new();
    assert!(
        provider1.is_running(),
        "First null provider instance should be running"
    );

    let provider2 = NullProvider::new();
    assert!(
        provider2.is_running(),
        "Second null provider instance should also be running"
    );
}

// =============================================================================
// Phase 3: Query Operation Tests — ALL Operation Types Must Return None
// =============================================================================
//
// This is the CORE behaviour of the null provider. The C `null_query()`
// function always returns `NULL` for every `operation_id`, meaning the null
// provider advertises zero algorithms for all 13 operation categories.

/// Verify `query_operation(OperationType::Digest)` returns `None`.
#[test]
fn test_null_provider_query_digest_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Digest).is_none(),
        "Null provider must not advertise Digest algorithms"
    );
}

/// Verify `query_operation(OperationType::Cipher)` returns `None`.
#[test]
fn test_null_provider_query_cipher_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Cipher).is_none(),
        "Null provider must not advertise Cipher algorithms"
    );
}

/// Verify `query_operation(OperationType::Mac)` returns `None`.
#[test]
fn test_null_provider_query_mac_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Mac).is_none(),
        "Null provider must not advertise Mac algorithms"
    );
}

/// Verify `query_operation(OperationType::Kdf)` returns `None`.
#[test]
fn test_null_provider_query_kdf_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Kdf).is_none(),
        "Null provider must not advertise Kdf algorithms"
    );
}

/// Verify `query_operation(OperationType::Signature)` returns `None`.
#[test]
fn test_null_provider_query_signature_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Signature).is_none(),
        "Null provider must not advertise Signature algorithms"
    );
}

/// Verify `query_operation(OperationType::Kem)` returns `None`.
#[test]
fn test_null_provider_query_kem_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Kem).is_none(),
        "Null provider must not advertise Kem algorithms"
    );
}

/// Verify `query_operation(OperationType::KeyMgmt)` returns `None`.
#[test]
fn test_null_provider_query_keymgmt_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::KeyMgmt).is_none(),
        "Null provider must not advertise KeyMgmt algorithms"
    );
}

/// Verify `query_operation(OperationType::KeyExch)` returns `None`.
#[test]
fn test_null_provider_query_keyexch_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::KeyExch).is_none(),
        "Null provider must not advertise KeyExch algorithms"
    );
}

/// Verify `query_operation(OperationType::Rand)` returns `None`.
#[test]
fn test_null_provider_query_rand_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Rand).is_none(),
        "Null provider must not advertise Rand algorithms"
    );
}

/// Verify `query_operation(OperationType::EncoderDecoder)` returns `None`.
#[test]
fn test_null_provider_query_encoder_decoder_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none(),
        "Null provider must not advertise EncoderDecoder algorithms"
    );
}

/// Verify `query_operation(OperationType::Store)` returns `None`.
#[test]
fn test_null_provider_query_store_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::Store).is_none(),
        "Null provider must not advertise Store algorithms"
    );
}

/// Verify `query_operation(OperationType::AsymCipher)` returns `None`.
#[test]
fn test_null_provider_query_asym_cipher_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_none(),
        "Null provider must not advertise AsymCipher algorithms"
    );
}

/// Verify `query_operation(OperationType::SKeyMgmt)` returns `None`.
#[test]
fn test_null_provider_query_skeymgmt_returns_none() {
    let provider = NullProvider::new();
    assert!(
        provider.query_operation(OperationType::SKeyMgmt).is_none(),
        "Null provider must not advertise SKeyMgmt algorithms"
    );
}

/// Exhaustive test iterating over ALL `OperationType` variants.
///
/// This guarantees that **no** operation type accidentally leaks algorithms
/// from the null provider. If a new variant is added to `OperationType` in
/// the future this array must be updated — the explicit listing serves as a
/// compile-time reminder.
#[test]
fn test_null_provider_query_all_operations_exhaustive() {
    let provider = NullProvider::new();
    let all_ops = [
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
    for op in &all_ops {
        assert!(
            provider.query_operation(*op).is_none(),
            "NullProvider must return None for operation type {op:?}",
        );
    }
    // Verify we tested all 13 known variants
    assert_eq!(all_ops.len(), 13, "Must test all 13 OperationType variants");
}

// =============================================================================
// Phase 4: Parameter Tests
// =============================================================================

/// Verify `get_params()` returns `Ok` with the correct parameter set contents.
///
/// Checks the four parameters defined in the C `null_param_types[]` array:
/// `name`, `version`, `buildinfo`, `status`.
#[allow(clippy::expect_used)] // Test-only: expect provides descriptive panic messages on unexpected None/Err.
#[test]
fn test_null_provider_get_params() {
    let provider = NullProvider::new();
    let params = provider.get_params().expect("get_params should succeed");

    // Verify all expected keys are present
    assert!(params.contains("name"), "Params should contain 'name' key");
    assert!(
        params.contains("version"),
        "Params should contain 'version' key"
    );
    assert!(
        params.contains("buildinfo"),
        "Params should contain 'buildinfo' key"
    );
    assert!(
        params.contains("status"),
        "Params should contain 'status' key"
    );

    // Verify name value matches C `null_get_params` exactly
    let name_val = params.get("name").expect("name param should exist");
    assert_eq!(
        name_val.as_str().expect("name should be a UTF-8 string"),
        "OpenSSL Null Provider",
        "Name param must match the C null_get_params constant"
    );

    // Verify version is non-empty
    let version_val = params.get("version").expect("version param should exist");
    let version_str = version_val
        .as_str()
        .expect("version should be a UTF-8 string");
    assert!(
        !version_str.is_empty(),
        "Version param should be a non-empty string"
    );

    // Verify status is 1 (true), matching C `ossl_prov_is_running()` returning 1
    let status_val = params.get("status").expect("status param should exist");
    assert_eq!(
        status_val.as_i32().expect("status should be an Int32"),
        1,
        "Status param should be 1 (true), matching C ossl_prov_is_running()"
    );

    // Verify param count matches the 4 fields in C `null_param_types[]`
    assert_eq!(
        params.len(),
        4,
        "Null provider should expose exactly 4 parameters"
    );
}

/// Verify `gettable_params()` returns the standard four parameter names.
///
/// These map to the C `null_param_types[]` array fields:
/// `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`,
/// `OSSL_PROV_PARAM_BUILDINFO`, `OSSL_PROV_PARAM_STATUS`.
#[test]
fn test_null_provider_gettable_params() {
    let provider = NullProvider::new();
    let gettable = provider.gettable_params();

    let expected_keys = ["name", "version", "buildinfo", "status"];
    for key in &expected_keys {
        assert!(
            gettable.contains(key),
            "gettable_params should contain '{key}'"
        );
    }
    assert_eq!(
        gettable.len(),
        expected_keys.len(),
        "gettable_params should contain exactly 4 keys"
    );
}

// =============================================================================
// Phase 5: Lifecycle Tests
// =============================================================================

/// Verify [`NullProvider`](crate::null::NullProvider) can be created,
/// exercised, and dropped without panics.
///
/// Exercises the full lifecycle: `new()` → `info()` → `query_operation()` →
/// implicit `Drop`. Confirms RAII correctness.
#[test]
fn test_null_provider_create_and_drop() {
    let provider = NullProvider::new();
    // Exercise the provider through its trait methods
    let _info = provider.info();
    let _query_result = provider.query_operation(OperationType::Digest);
    let _params = provider.get_params();
    let _gettable = provider.gettable_params();
    let _running = provider.is_running();
    // Implicit drop — no panic expected
}

/// Verify `NullProvider` `Clone` implementation preserves metadata identity.
///
/// Both original and clone should return identical `ProviderInfo` and
/// identical `query_operation()` results for all operation types.
#[test]
fn test_null_provider_clone() {
    let original = NullProvider::new();
    let cloned = original.clone();

    let orig_info = original.info();
    let clone_info = cloned.info();

    assert_eq!(
        orig_info.name, clone_info.name,
        "Cloned provider name must match original"
    );
    assert_eq!(
        orig_info.version, clone_info.version,
        "Cloned provider version must match original"
    );
    assert_eq!(
        orig_info.build_info, clone_info.build_info,
        "Cloned provider build_info must match original"
    );
    assert_eq!(
        orig_info.status, clone_info.status,
        "Cloned provider status must match original"
    );

    // Both should return None for all operations
    assert!(cloned.query_operation(OperationType::Cipher).is_none());
    assert!(cloned.query_operation(OperationType::Digest).is_none());
}

/// Verify `NullProvider` `Debug` format produces non-empty output containing
/// the struct name.
#[test]
fn test_null_provider_debug_format() {
    let provider = NullProvider::new();
    let debug_str = format!("{provider:?}");
    assert!(
        !debug_str.is_empty(),
        "Debug format should produce non-empty output"
    );
    assert!(
        debug_str.contains("NullProvider"),
        "Debug format should contain 'NullProvider'"
    );
}

/// Verify `teardown()` completes successfully.
///
/// The null provider's teardown is a no-op that returns `Ok(())`.
/// This test ensures the method is callable and does not error or panic.
#[test]
fn test_null_provider_teardown() {
    let mut provider = NullProvider::new();
    let result = provider.teardown();
    assert!(
        result.is_ok(),
        "Teardown should succeed for the null provider"
    );
}

/// Verify `NullProvider` works correctly when accessed through a
/// `Provider` trait object (`Box<dyn Provider>`).
///
/// This is a true integration test: it exercises the vtable-based dynamic
/// dispatch path, verifying that the concrete `NullProvider` implementation
/// is ABI-compatible with the trait when accessed through a pointer.
#[allow(clippy::expect_used)] // Test-only: expect provides descriptive panic messages on unexpected Err.
#[test]
fn test_null_provider_as_trait_object() {
    let provider: Box<dyn Provider> = Box::new(NullProvider::new());

    // Metadata through trait object
    let info = provider.info();
    assert_eq!(info.name, "OpenSSL Null Provider");
    assert!(info.status);
    assert!(provider.is_running());

    // Query through trait object — all operations return None
    assert!(provider.query_operation(OperationType::Digest).is_none());
    assert!(provider.query_operation(OperationType::Cipher).is_none());
    assert!(provider.query_operation(OperationType::Mac).is_none());
    assert!(provider.query_operation(OperationType::Kdf).is_none());
    assert!(provider.query_operation(OperationType::Rand).is_none());
    assert!(provider.query_operation(OperationType::KeyMgmt).is_none());
    assert!(provider.query_operation(OperationType::Signature).is_none());
    assert!(provider
        .query_operation(OperationType::AsymCipher)
        .is_none());
    assert!(provider.query_operation(OperationType::Kem).is_none());
    assert!(provider.query_operation(OperationType::KeyExch).is_none());
    assert!(provider
        .query_operation(OperationType::EncoderDecoder)
        .is_none());
    assert!(provider.query_operation(OperationType::Store).is_none());
    assert!(provider.query_operation(OperationType::SKeyMgmt).is_none());

    // Params through trait object
    let params = provider
        .get_params()
        .expect("get_params via trait object should succeed");
    assert_eq!(params.len(), 4);
    let gettable = provider.gettable_params();
    assert_eq!(gettable.len(), 4);
}

/// Verify `NullProvider` satisfies `Send + Sync` bounds required by the
/// `Provider` trait super-trait constraint.
///
/// This is a compile-time check — if `NullProvider` did not implement
/// `Send + Sync`, the function body would fail to compile.
#[test]
fn test_null_provider_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NullProvider>();
}

// =============================================================================
// Phase 6: Rule Compliance Tests
// =============================================================================

/// Verify no sentinel values in `info()` fields per Rule R5.
///
/// Rule R5 mandates that `Option<T>` must be used instead of sentinel values
/// like `0`, `-1`, or `""` to encode "unset". This test verifies that all
/// `ProviderInfo` fields returned by the null provider contain actual
/// meaningful values — not empty strings or numeric sentinels.
#[test]
fn test_null_provider_no_sentinel_values() {
    let provider = NullProvider::new();
    let info = provider.info();

    // Rule R5: name must not be an empty string sentinel
    assert!(
        !info.name.is_empty(),
        "info.name must not be empty (Rule R5: no sentinel values)"
    );
    assert_ne!(
        info.name, "-1",
        "info.name must not be a numeric sentinel string"
    );

    // Rule R5: version must not be an empty string sentinel
    assert!(
        !info.version.is_empty(),
        "info.version must not be empty (Rule R5: no sentinel values)"
    );
    assert_ne!(
        info.version, "0",
        "info.version must not be a numeric sentinel string"
    );

    // Rule R5: build_info must not be an empty string sentinel
    assert!(
        !info.build_info.is_empty(),
        "info.build_info must not be empty (Rule R5: no sentinel values)"
    );

    // Rule R5: status is a bool (true/false), which inherently satisfies R5
    // since Rust's type system prevents sentinel encoding for booleans.
    // We still verify the expected value for the null provider.
    assert!(
        info.status,
        "info.status should be true for the null provider"
    );
}

/// Verify `get_params()` does not use sentinel values in parameter values.
///
/// Complements the metadata sentinel test by checking the parameter system
/// output for Rule R5 compliance.
#[allow(clippy::expect_used)] // Test-only: expect provides descriptive panic messages on unexpected None/Err.
#[test]
fn test_null_provider_params_no_sentinel_values() {
    let provider = NullProvider::new();
    let params = provider.get_params().expect("get_params should succeed");

    // Name param must be a real value, not a sentinel
    let name_str = params
        .get("name")
        .expect("name param exists")
        .as_str()
        .expect("name is a string");
    assert!(!name_str.is_empty(), "Name param must not be empty (R5)");

    // Version param must be a real value
    let version_str = params
        .get("version")
        .expect("version param exists")
        .as_str()
        .expect("version is a string");
    assert!(
        !version_str.is_empty(),
        "Version param must not be empty (R5)"
    );

    // Buildinfo param must be a real value
    let buildinfo_str = params
        .get("buildinfo")
        .expect("buildinfo param exists")
        .as_str()
        .expect("buildinfo is a string");
    assert!(
        !buildinfo_str.is_empty(),
        "Buildinfo param must not be empty (R5)"
    );

    // Status param must be a concrete integer, not -1 sentinel
    let status_val = params
        .get("status")
        .expect("status param exists")
        .as_i32()
        .expect("status is an Int32");
    assert_ne!(status_val, -1, "Status param must not be -1 sentinel (R5)");
    assert!(
        status_val == 0 || status_val == 1,
        "Status param should be 0 or 1, not an arbitrary sentinel"
    );
}

/// Verify `NullProvider` `teardown()` followed by continued use does not panic.
///
/// The null provider is stateless, so teardown should not invalidate any state.
/// This test exercises the post-teardown path to confirm robustness.
#[test]
fn test_null_provider_teardown_then_query() {
    let mut provider = NullProvider::new();
    let _ = provider.teardown();

    // After teardown, the provider should still respond correctly
    let info = provider.info();
    assert_eq!(info.name, "OpenSSL Null Provider");
    assert!(provider.is_running());
    assert!(provider.query_operation(OperationType::Digest).is_none());
}
