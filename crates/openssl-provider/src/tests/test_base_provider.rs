//! Integration tests for the `BaseProvider`.
//!
//! Verifies that the base provider:
//! - Returns correct metadata (name: "OpenSSL Base Provider")
//! - Exposes ONLY encoder, decoder, store, and RAND operations
//! - Does NOT expose digest, cipher, MAC, KDF, signature, KEM, keymgmt,
//!   exchange, asym cipher, or symmetric key management operations
//! - Returns proper algorithm descriptors with `"provider=base"` property tag
//! - Exercises full lifecycle: create → query → teardown
//!
//! Source reference: `providers/baseprov.c`

use crate::base::BaseProvider;
use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use openssl_common::types::OperationType;

// =============================================================================
// Helper utilities
// =============================================================================

/// Helper: queries the given operation type on a [`BaseProvider`] and returns
/// the resulting algorithm descriptors.
///
/// Panics with a descriptive message if the query returns `None`, which
/// would indicate the base provider does not support the given operation.
#[allow(clippy::expect_used, clippy::panic)] // Test-only helper; panic on unexpected None is intentional.
fn query_algorithms(provider: &BaseProvider, op: OperationType) -> Vec<AlgorithmDescriptor> {
    provider
        .query_operation(op)
        .unwrap_or_else(|| panic!("query_operation({op:?}) should return Some for base provider"))
}

// =============================================================================
// Phase 2: Metadata Tests
// =============================================================================

/// Verifies that `info().name` matches the exact C string from
/// `baseprov.c` line 55-56.
///
/// CRITICAL: Exact string match required for FFI compatibility.
#[test]
fn test_base_provider_info_name() {
    let provider = BaseProvider::new();
    let info: ProviderInfo = provider.info();
    assert_eq!(
        info.name, "OpenSSL Base Provider",
        "Provider name must match C baseprov.c exactly for FFI compatibility"
    );
}

/// Verifies that the base provider reports its status as active (true).
///
/// In C, `ossl_prov_is_running()` unconditionally returns 1.
#[test]
fn test_base_provider_info_status() {
    let provider = BaseProvider::new();
    let info: ProviderInfo = provider.info();
    assert!(
        info.status,
        "Base provider should report active status (true) after construction"
    );
}

/// Verifies that version and `build_info` strings are non-empty.
#[test]
fn test_base_provider_info_version() {
    let provider = BaseProvider::new();
    let info: ProviderInfo = provider.info();
    assert!(
        !info.version.is_empty(),
        "Provider version should not be empty"
    );
    assert!(
        !info.build_info.is_empty(),
        "Provider build_info should not be empty"
    );
}

/// Verifies that `is_running()` returns true for a freshly constructed provider.
#[test]
fn test_base_provider_is_running() {
    let provider = BaseProvider::new();
    assert!(
        provider.is_running(),
        "Freshly constructed BaseProvider should be running"
    );
}

// =============================================================================
// Phase 3: Positive Query Tests — Operations the Base Provider DOES Support
// =============================================================================
//
// Per C `base_query()` function, the base provider supports:
// OSSL_OP_ENCODER, OSSL_OP_DECODER, OSSL_OP_STORE, OSSL_OP_RAND.

/// Verifies that `query_operation(EncoderDecoder)` returns a non-empty
/// descriptor list and that every descriptor carries the `"provider=base"`
/// property tag.
#[test]
fn test_base_provider_query_encoder_decoder() {
    let provider = BaseProvider::new();
    let descriptors = query_algorithms(&provider, OperationType::EncoderDecoder);
    assert!(
        !descriptors.is_empty(),
        "Base provider must return encoder/decoder algorithms"
    );
    for desc in &descriptors {
        assert!(
            desc.property.contains("provider=base"),
            "Encoder/decoder algorithm property '{}' must contain 'provider=base'",
            desc.property,
        );
    }
}

/// Verifies that `query_operation(Store)` returns a non-empty descriptor
/// list containing at least a "file" store entry.
///
/// In C, `base_store[]` uses property `"provider=base,fips=yes"`.
#[test]
fn test_base_provider_query_store() {
    let provider = BaseProvider::new();
    let descriptors = query_algorithms(&provider, OperationType::Store);
    assert!(
        !descriptors.is_empty(),
        "Base provider must return store algorithms"
    );
    // Verify at least one entry references a "file" store.
    let has_file = descriptors
        .iter()
        .any(|d| d.names.iter().any(|n| n.to_lowercase().contains("file")));
    assert!(
        has_file,
        "Base provider store should include a 'file' store entry; found: {:?}",
        descriptors
            .iter()
            .map(|d| d.names.clone())
            .collect::<Vec<_>>(),
    );
    // Every store descriptor must carry the base provider property.
    for desc in &descriptors {
        assert!(
            desc.property.contains("provider=base"),
            "Store algorithm property '{}' must contain 'provider=base'",
            desc.property,
        );
    }
}

/// Verifies that `query_operation(Rand)` returns a non-empty descriptor
/// list containing the SEED-SRC entry.
#[test]
fn test_base_provider_query_rand() {
    let provider = BaseProvider::new();
    let descriptors = query_algorithms(&provider, OperationType::Rand);
    assert!(
        !descriptors.is_empty(),
        "Base provider must return RAND algorithms"
    );
    // Verify SEED-SRC is present in at least one descriptor's name list.
    let has_seed_src = descriptors
        .iter()
        .any(|d| d.names.iter().any(|n| n.contains("SEED-SRC")));
    assert!(
        has_seed_src,
        "Base provider RAND should include SEED-SRC; found: {:?}",
        descriptors
            .iter()
            .map(|d| d.names.clone())
            .collect::<Vec<_>>(),
    );
}

/// Verifies that encoder/decoder descriptors include both DER and PEM
/// format entries, reflecting the C encoder and decoder tables in
/// `baseprov.c`.
#[test]
fn test_base_provider_encoder_descriptors_non_empty() {
    let provider = BaseProvider::new();
    let descriptors = query_algorithms(&provider, OperationType::EncoderDecoder);

    // Look for DER entries (either in names or description).
    let has_der = descriptors
        .iter()
        .any(|d| d.names.iter().any(|n| n.contains("DER")) || d.description.contains("DER"));
    // Look for PEM entries.
    let has_pem = descriptors
        .iter()
        .any(|d| d.names.iter().any(|n| n.contains("PEM")) || d.description.contains("PEM"));

    assert!(
        has_der,
        "Base provider encoder/decoder list should include DER entries"
    );
    assert!(
        has_pem,
        "Base provider encoder/decoder list should include PEM entries"
    );
}

// =============================================================================
// Phase 4: Negative Query Tests — Operations the Base Provider Does NOT Support
// =============================================================================
//
// Per C `base_query()`, the base provider returns NULL for ALL other
// operation types. These tests are critical to ensure the limited scope
// is preserved.

/// Base provider must NOT support digest operations.
#[test]
fn test_base_provider_query_digest_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::Digest).is_none(),
        "Base provider must NOT support digest operations"
    );
}

/// Base provider must NOT support cipher operations.
#[test]
fn test_base_provider_query_cipher_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::Cipher).is_none(),
        "Base provider must NOT support cipher operations"
    );
}

/// Base provider must NOT support MAC operations.
#[test]
fn test_base_provider_query_mac_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::Mac).is_none(),
        "Base provider must NOT support MAC operations"
    );
}

/// Base provider must NOT support KDF operations.
#[test]
fn test_base_provider_query_kdf_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::Kdf).is_none(),
        "Base provider must NOT support KDF operations"
    );
}

/// Base provider must NOT support signature operations.
#[test]
fn test_base_provider_query_signature_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::Signature).is_none(),
        "Base provider must NOT support signature operations"
    );
}

/// Base provider must NOT support KEM operations.
#[test]
fn test_base_provider_query_kem_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::Kem).is_none(),
        "Base provider must NOT support KEM operations"
    );
}

/// Base provider must NOT support key management operations.
#[test]
fn test_base_provider_query_keymgmt_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::KeyMgmt).is_none(),
        "Base provider must NOT support key management operations"
    );
}

/// Base provider must NOT support key exchange operations.
#[test]
fn test_base_provider_query_keyexch_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::KeyExch).is_none(),
        "Base provider must NOT support key exchange operations"
    );
}

/// Base provider must NOT support asymmetric cipher operations.
#[test]
fn test_base_provider_query_asym_cipher_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_none(),
        "Base provider must NOT support asymmetric cipher operations"
    );
}

/// Base provider must NOT support symmetric key management operations.
///
/// `SKeyMgmt` (`OSSL_OP_SKEYMGMT`) is a distinct operation type from
/// `KeyMgmt`; the base provider advertises neither.
#[test]
fn test_base_provider_query_skeymgmt_returns_none() {
    let provider = BaseProvider::new();
    assert!(
        provider.query_operation(OperationType::SKeyMgmt).is_none(),
        "Base provider must NOT support symmetric key management operations"
    );
}

/// Comprehensive negative test iterating all unsupported operation types
/// in a single test to guard against accidental additions.
#[test]
fn test_base_provider_unsupported_operations_exhaustive() {
    let provider = BaseProvider::new();
    let unsupported = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
        OperationType::Kdf,
        OperationType::Signature,
        OperationType::Kem,
        OperationType::KeyMgmt,
        OperationType::KeyExch,
        OperationType::AsymCipher,
        OperationType::SKeyMgmt,
    ];
    for op in unsupported {
        assert!(
            provider.query_operation(op).is_none(),
            "Base provider must NOT support {op:?} operations"
        );
    }
}

// =============================================================================
// Phase 5: Parameter Tests
// =============================================================================

/// Verifies that `get_params()` succeeds and the returned `ParamSet`
/// contains the provider name "OpenSSL Base Provider".
#[test]
#[allow(clippy::expect_used)] // Test code: expect on known-good values is intentional.
fn test_base_provider_get_params() {
    let provider = BaseProvider::new();
    let params = provider
        .get_params()
        .expect("get_params() should succeed on a running base provider");

    // Verify "name" key is present and contains the expected value.
    let name_value = params
        .get("name")
        .expect("params should contain a 'name' key");
    assert_eq!(
        name_value.as_str(),
        Some("OpenSSL Base Provider"),
        "get_params 'name' must match provider name exactly"
    );

    // Verify "version" key is present and non-empty.
    let version_value = params
        .get("version")
        .expect("params should contain a 'version' key");
    let version_str = version_value
        .as_str()
        .expect("version should be a Utf8String");
    assert!(
        !version_str.is_empty(),
        "get_params 'version' must not be empty"
    );

    // Verify "buildinfo" key is present and non-empty.
    let buildinfo_value = params
        .get("buildinfo")
        .expect("params should contain a 'buildinfo' key");
    let buildinfo_str = buildinfo_value
        .as_str()
        .expect("buildinfo should be a Utf8String");
    assert!(
        !buildinfo_str.is_empty(),
        "get_params 'buildinfo' must not be empty"
    );

    // Verify "status" key is present and indicates running (1).
    let status_value = params
        .get("status")
        .expect("params should contain a 'status' key");
    let status_int = status_value.as_i32().expect("status should be an Int32");
    assert_eq!(
        status_int, 1,
        "get_params 'status' must be 1 for a running provider"
    );
}

/// Verifies that `gettable_params()` returns the four standard parameter
/// keys: name, version, buildinfo, status.
///
/// These match the C `base_param_types` / `null_param_types` `OSSL_PARAM`
/// descriptor arrays.
#[test]
fn test_base_provider_gettable_params() {
    let provider = BaseProvider::new();
    let keys = provider.gettable_params();
    let expected = ["name", "version", "buildinfo", "status"];
    for key in &expected {
        assert!(
            keys.contains(key),
            "gettable_params() must include '{key}'; got: {keys:?}"
        );
    }
}

// =============================================================================
// Phase 6: Lifecycle and Property Tests
// =============================================================================

/// RAII lifecycle test — create a provider, use it, and let it drop.
/// Verifies no panics occur during normal create → use → drop.
#[test]
fn test_base_provider_create_and_drop() {
    let provider = BaseProvider::new();
    // Exercise the provider to ensure it's fully initialized.
    let _info = provider.info();
    let _running = provider.is_running();
    let _enc = provider.query_operation(OperationType::EncoderDecoder);
    // Provider drops here — must not panic.
}

/// Verifies that `teardown()` transitions the provider to a non-running
/// state and that subsequent queries return `None`.
#[test]
#[allow(clippy::expect_used)] // Test code: expect on teardown Result is intentional.
fn test_base_provider_teardown_lifecycle() {
    let mut provider = BaseProvider::new();
    assert!(provider.is_running(), "Provider should start running");

    // Teardown must succeed.
    provider
        .teardown()
        .expect("teardown() should succeed on a running provider");

    // After teardown the provider reports as not running.
    assert!(
        !provider.is_running(),
        "Provider must NOT be running after teardown"
    );

    // After teardown, all queries should return None (provider no longer active).
    assert!(
        provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none(),
        "query_operation should return None after teardown"
    );
    assert!(
        provider.query_operation(OperationType::Store).is_none(),
        "query_operation should return None after teardown"
    );
    assert!(
        provider.query_operation(OperationType::Rand).is_none(),
        "query_operation should return None after teardown"
    );
}

/// Verifies that `teardown()` is idempotent — calling it twice does not
/// panic and both calls return `Ok(())`.
#[test]
#[allow(clippy::expect_used)] // Test code: expect on teardown Result is intentional.
fn test_base_provider_teardown_idempotent() {
    let mut provider = BaseProvider::new();
    provider.teardown().expect("First teardown should succeed");
    provider
        .teardown()
        .expect("Second teardown should also succeed (idempotent)");
    assert!(
        !provider.is_running(),
        "Provider must NOT be running after double teardown"
    );
}

/// Comprehensive property-tag validation: for EVERY operation that the
/// base provider supports (`EncoderDecoder`, `Store`, `Rand`), ALL returned
/// algorithm descriptors must have a property string containing
/// `"provider=base"`.
#[test]
fn test_base_provider_algorithm_property_tags() {
    let provider = BaseProvider::new();
    let supported_ops = [
        OperationType::EncoderDecoder,
        OperationType::Store,
        OperationType::Rand,
    ];

    for op in supported_ops {
        let descriptors = query_algorithms(&provider, op);
        for desc in &descriptors {
            assert!(
                desc.property.contains("provider=base"),
                "Algorithm descriptor for {op:?} has property '{}' \
                 which does not contain 'provider=base'; names: {:?}",
                desc.property,
                desc.names,
            );
        }
    }
}

/// Verifies that every supported operation returns descriptors with
/// non-empty `names` vectors containing only non-empty strings.
#[test]
fn test_base_provider_algorithm_names_non_empty() {
    let provider = BaseProvider::new();
    let supported_ops = [
        OperationType::EncoderDecoder,
        OperationType::Store,
        OperationType::Rand,
    ];

    for op in supported_ops {
        let descriptors = query_algorithms(&provider, op);
        for desc in &descriptors {
            assert!(
                !desc.names.is_empty(),
                "Algorithm descriptor for {op:?} must have at least one name"
            );
            for name in &desc.names {
                assert!(
                    !name.is_empty(),
                    "Algorithm name in {op:?} descriptor must not be empty"
                );
            }
        }
    }
}

/// Verifies the trait-object polymorphism pattern — `BaseProvider` can be
/// used through a `&dyn Provider` reference, demonstrating the Rust
/// trait-based dispatch that replaces C `OSSL_DISPATCH` function pointer
/// tables.
#[test]
fn test_base_provider_trait_object_polymorphism() {
    let provider = BaseProvider::new();
    let dyn_provider: &dyn Provider = &provider;

    let info = dyn_provider.info();
    assert_eq!(info.name, "OpenSSL Base Provider");
    assert!(dyn_provider.is_running());

    // Query through the trait object.
    let enc = dyn_provider.query_operation(OperationType::EncoderDecoder);
    assert!(
        enc.is_some(),
        "Trait object query should work for supported ops"
    );

    let digest = dyn_provider.query_operation(OperationType::Digest);
    assert!(
        digest.is_none(),
        "Trait object query should return None for unsupported ops"
    );
}

/// Verifies that `Default` trait produces a functional provider identical
/// to `BaseProvider::new()`.
#[test]
fn test_base_provider_default_trait() {
    let from_new = BaseProvider::new();
    let from_default = BaseProvider::default();

    assert_eq!(from_new.info().name, from_default.info().name);
    assert_eq!(from_new.is_running(), from_default.is_running());
}

/// Verifies that `Clone` produces an independent copy whose lifecycle
/// is decoupled from the original.
#[test]
#[allow(clippy::expect_used)] // Test code: expect on teardown Result is intentional.
fn test_base_provider_clone_independence() {
    let provider = BaseProvider::new();
    let mut cloned = provider.clone();

    // Both start running.
    assert!(provider.is_running());
    assert!(cloned.is_running());

    // Tear down the clone — original must be unaffected.
    cloned
        .teardown()
        .expect("Cloned provider teardown should succeed");
    assert!(
        !cloned.is_running(),
        "Cloned provider should stop running after teardown"
    );
    assert!(
        provider.is_running(),
        "Original provider must remain running after clone teardown"
    );
}

/// Verifies that `Debug` formatting produces a non-empty representation.
#[test]
fn test_base_provider_debug_format() {
    let provider = BaseProvider::new();
    let debug_str = format!("{provider:?}");
    assert!(
        !debug_str.is_empty(),
        "Debug format of BaseProvider should not be empty"
    );
    assert!(
        debug_str.contains("BaseProvider"),
        "Debug format should contain the type name"
    );
}
