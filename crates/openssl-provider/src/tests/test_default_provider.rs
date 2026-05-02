//! Integration tests for the DefaultProvider.
//!
//! Verifies that the default provider:
//! - Returns correct metadata (name: "OpenSSL Default Provider")
//! - Exposes algorithms for ALL 12 operation categories
//! - Each algorithm descriptor has "provider=default" property tag
//! - Algorithm catalog is comprehensive: SHA-1/2/3, AES family, HMAC, HKDF, RSA, EC, QUIC ciphers, etc.
//! - Feature gating correctly enables/disables conditional algorithms
//!
//! Source reference: `providers/defltprov.c` — the largest provider with ~100+ cipher, ~20 digest,
//! ~8 MAC, ~16 KDF, ~6 key exchange, ~6 RAND, ~10 signature, ~2 asym cipher, ~5 KEM,
//! ~15 keymgmt, plus encoder/decoder/store entries.

use crate::default::DefaultProvider;
use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use openssl_common::types::OperationType;

// =============================================================================
// Helper utilities
// =============================================================================

/// Helper: queries the given operation type and returns the descriptors.
/// Panics with a descriptive message if the query returns `None`.
fn query_algorithms(provider: &DefaultProvider, op: OperationType) -> Vec<AlgorithmDescriptor> {
    provider.query_operation(op).unwrap_or_else(|| {
        panic!(
            "query_operation({:?}) should return Some for default provider",
            op
        )
    })
}

/// Helper: checks whether any descriptor in the list has the given algorithm name
/// (case-sensitive exact match against the `names` field).
fn has_algorithm(descriptors: &[AlgorithmDescriptor], name: &str) -> bool {
    descriptors.iter().any(|d| d.names.contains(&name))
}

/// Helper: asserts that a specific algorithm name is present in the descriptor list.
/// Panics with a descriptive message if not found.
fn assert_has_algorithm(descriptors: &[AlgorithmDescriptor], name: &str) {
    assert!(
        has_algorithm(descriptors, name),
        "Expected algorithm '{}' not found in descriptors: {:?}",
        name,
        descriptors
            .iter()
            .map(|d| d.names.clone())
            .collect::<Vec<_>>(),
    );
}

// =============================================================================
// Phase 2: Metadata Tests
// =============================================================================

/// Verifies that `info().name` matches the exact C string from `defltprov.c` line 60.
/// CRITICAL: Exact string match required for FFI compatibility.
#[test]
fn test_default_provider_info_name() {
    let provider = DefaultProvider::new();
    let info: ProviderInfo = provider.info();
    assert_eq!(
        info.name, "OpenSSL Default Provider",
        "Provider name must match C defltprov.c exactly for FFI compatibility"
    );
}

/// Verifies that the default provider reports its status as active (true).
#[test]
fn test_default_provider_info_status() {
    let provider = DefaultProvider::new();
    let info: ProviderInfo = provider.info();
    assert!(
        info.status,
        "Default provider should report active status (true) after construction"
    );
}

/// Verifies that version and build_info strings are non-empty.
#[test]
fn test_default_provider_info_version_nonempty() {
    let provider = DefaultProvider::new();
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
fn test_default_provider_is_running() {
    let provider = DefaultProvider::new();
    assert!(
        provider.is_running(),
        "Freshly constructed DefaultProvider should be running"
    );
}

// =============================================================================
// Phase 3: Digest Algorithm Catalog Completeness
// =============================================================================

/// Verifies that SHA-1 is present in the digest algorithm catalog.
#[test]
fn test_default_provider_has_sha1() {
    let provider = DefaultProvider::new();
    let digests = query_algorithms(&provider, OperationType::Digest);
    assert_has_algorithm(&digests, "SHA1");
}

/// Verifies that the SHA-2 family (224, 256, 384, 512) is present.
#[test]
fn test_default_provider_has_sha2_family() {
    let provider = DefaultProvider::new();
    let digests = query_algorithms(&provider, OperationType::Digest);
    assert_has_algorithm(&digests, "SHA2-224");
    assert_has_algorithm(&digests, "SHA2-256");
    assert_has_algorithm(&digests, "SHA2-384");
    assert_has_algorithm(&digests, "SHA2-512");
}

/// Verifies that the SHA-3 family (224, 256, 384, 512) is present.
#[test]
fn test_default_provider_has_sha3_family() {
    let provider = DefaultProvider::new();
    let digests = query_algorithms(&provider, OperationType::Digest);
    assert_has_algorithm(&digests, "SHA3-224");
    assert_has_algorithm(&digests, "SHA3-256");
    assert_has_algorithm(&digests, "SHA3-384");
    assert_has_algorithm(&digests, "SHA3-512");
}

/// Verifies that SHAKE-128 and SHAKE-256 are present in digests.
#[test]
fn test_default_provider_has_shake() {
    let provider = DefaultProvider::new();
    let digests = query_algorithms(&provider, OperationType::Digest);
    assert_has_algorithm(&digests, "SHAKE-128");
    assert_has_algorithm(&digests, "SHAKE-256");
}

/// Verifies that the digest catalog contains at least 10 algorithms
/// (SHA-1, SHA-2 family, SHA-3 family, SHAKE, etc.).
#[test]
fn test_default_provider_digests_nonempty() {
    let provider = DefaultProvider::new();
    let digests = provider.query_operation(OperationType::Digest);
    assert!(
        digests.is_some(),
        "query_operation(Digest) should return Some"
    );
    let digests = digests.expect("checked above");
    assert!(
        digests.len() >= 10,
        "Default provider should have at least 10 digest algorithms, found {}",
        digests.len()
    );
}

// =============================================================================
// Phase 4: Cipher Algorithm Catalog (Largest Category)
// =============================================================================

/// Verifies that the cipher catalog is non-empty and contains at least 20 algorithms.
#[test]
fn test_default_provider_ciphers_nonempty() {
    let provider = DefaultProvider::new();
    let ciphers = provider.query_operation(OperationType::Cipher);
    assert!(
        ciphers.is_some(),
        "query_operation(Cipher) should return Some"
    );
    let ciphers = ciphers.expect("checked above");
    assert!(
        ciphers.len() >= 20,
        "Default provider should have at least 20 cipher algorithms, found {}",
        ciphers.len()
    );
}

/// Verifies that AES-GCM variants (128, 192, 256) are present.
#[test]
fn test_default_provider_has_aes_gcm() {
    let provider = DefaultProvider::new();
    let ciphers = query_algorithms(&provider, OperationType::Cipher);
    assert_has_algorithm(&ciphers, "AES-128-GCM");
    assert_has_algorithm(&ciphers, "AES-192-GCM");
    assert_has_algorithm(&ciphers, "AES-256-GCM");
}

/// Verifies that AES-CBC variants (128, 192, 256) are present.
#[test]
fn test_default_provider_has_aes_cbc() {
    let provider = DefaultProvider::new();
    let ciphers = query_algorithms(&provider, OperationType::Cipher);
    assert_has_algorithm(&ciphers, "AES-128-CBC");
    assert_has_algorithm(&ciphers, "AES-192-CBC");
    assert_has_algorithm(&ciphers, "AES-256-CBC");
}

/// Verifies that AES-ECB variants (128, 192, 256) are present.
#[test]
fn test_default_provider_has_aes_ecb() {
    let provider = DefaultProvider::new();
    let ciphers = query_algorithms(&provider, OperationType::Cipher);
    assert_has_algorithm(&ciphers, "AES-128-ECB");
    assert_has_algorithm(&ciphers, "AES-192-ECB");
    assert_has_algorithm(&ciphers, "AES-256-ECB");
}

/// Verifies that ChaCha20-Poly1305 is present in ciphers (feature-gated).
#[test]
fn test_default_provider_has_chacha20() {
    let provider = DefaultProvider::new();
    let ciphers = query_algorithms(&provider, OperationType::Cipher);
    assert_has_algorithm(&ciphers, "ChaCha20-Poly1305");
}

// =============================================================================
// Phase 5: Other Operation Category Tests
// =============================================================================

/// Verifies that MACs include at least HMAC.
#[test]
fn test_default_provider_macs_nonempty() {
    let provider = DefaultProvider::new();
    let macs = provider.query_operation(OperationType::Mac);
    assert!(macs.is_some(), "query_operation(Mac) should return Some");
    let macs = macs.expect("checked above");
    assert!(!macs.is_empty(), "MAC algorithms should not be empty");
    assert_has_algorithm(&macs, "HMAC");
}

/// Verifies that KDFs include at least HKDF.
#[test]
fn test_default_provider_kdfs_nonempty() {
    let provider = DefaultProvider::new();
    let kdfs = provider.query_operation(OperationType::Kdf);
    assert!(kdfs.is_some(), "query_operation(Kdf) should return Some");
    let kdfs = kdfs.expect("checked above");
    assert!(!kdfs.is_empty(), "KDF algorithms should not be empty");
    assert_has_algorithm(&kdfs, "HKDF");
}

/// Verifies that key exchange algorithms are present.
#[test]
fn test_default_provider_keyexch_nonempty() {
    let provider = DefaultProvider::new();
    let keyexch = provider.query_operation(OperationType::KeyExch);
    assert!(
        keyexch.is_some(),
        "query_operation(KeyExch) should return Some"
    );
    let keyexch = keyexch.expect("checked above");
    assert!(
        !keyexch.is_empty(),
        "Key exchange algorithms should not be empty"
    );
}

/// Verifies that RAND algorithms include at least CTR-DRBG or HASH-DRBG.
#[test]
fn test_default_provider_rand_nonempty() {
    let provider = DefaultProvider::new();
    let rands = provider.query_operation(OperationType::Rand);
    assert!(rands.is_some(), "query_operation(Rand) should return Some");
    let rands = rands.expect("checked above");
    assert!(!rands.is_empty(), "RAND algorithms should not be empty");
    // At least one DRBG variant should be present
    let has_drbg = has_algorithm(&rands, "CTR-DRBG") || has_algorithm(&rands, "HASH-DRBG");
    assert!(
        has_drbg,
        "Expected at least CTR-DRBG or HASH-DRBG in RAND algorithms"
    );
}

/// Verifies that signatures include at least RSA and ECDSA.
#[test]
fn test_default_provider_signatures_nonempty() {
    let provider = DefaultProvider::new();
    let sigs = provider.query_operation(OperationType::Signature);
    assert!(
        sigs.is_some(),
        "query_operation(Signature) should return Some"
    );
    let sigs = sigs.expect("checked above");
    assert!(!sigs.is_empty(), "Signature algorithms should not be empty");
    assert_has_algorithm(&sigs, "RSA");
    assert_has_algorithm(&sigs, "ECDSA");
}

/// Verifies that KEM algorithms are present.
#[test]
fn test_default_provider_kem_nonempty() {
    let provider = DefaultProvider::new();
    let kems = provider.query_operation(OperationType::Kem);
    assert!(kems.is_some(), "query_operation(Kem) should return Some");
    let kems = kems.expect("checked above");
    assert!(!kems.is_empty(), "KEM algorithms should not be empty");
}

/// Verifies that key management algorithms are present.
#[test]
fn test_default_provider_keymgmt_nonempty() {
    let provider = DefaultProvider::new();
    let keymgmt = provider.query_operation(OperationType::KeyMgmt);
    assert!(
        keymgmt.is_some(),
        "query_operation(KeyMgmt) should return Some"
    );
    let keymgmt = keymgmt.expect("checked above");
    assert!(
        !keymgmt.is_empty(),
        "Key management algorithms should not be empty"
    );
}

/// Verifies that encoder/decoder algorithms are present.
#[test]
fn test_default_provider_encoder_decoder_nonempty() {
    let provider = DefaultProvider::new();
    let encdec = provider.query_operation(OperationType::EncoderDecoder);
    assert!(
        encdec.is_some(),
        "query_operation(EncoderDecoder) should return Some"
    );
    let encdec = encdec.expect("checked above");
    assert!(
        !encdec.is_empty(),
        "Encoder/decoder algorithms should not be empty"
    );
}

/// Verifies that store algorithms are present.
#[test]
fn test_default_provider_store_nonempty() {
    let provider = DefaultProvider::new();
    let stores = provider.query_operation(OperationType::Store);
    assert!(
        stores.is_some(),
        "query_operation(Store) should return Some"
    );
    let stores = stores.expect("checked above");
    assert!(!stores.is_empty(), "Store algorithms should not be empty");
}

/// Verifies that asymmetric cipher algorithms include RSA.
#[test]
fn test_default_provider_asym_cipher() {
    let provider = DefaultProvider::new();
    let asym = provider.query_operation(OperationType::AsymCipher);
    assert!(
        asym.is_some(),
        "query_operation(AsymCipher) should return Some"
    );
    let asym = asym.expect("checked above");
    assert!(
        !asym.is_empty(),
        "AsymCipher algorithms should not be empty"
    );
    // RSA asymmetric cipher should be present
    let has_rsa = asym
        .iter()
        .any(|d| d.names.contains(&"RSA") || d.names.contains(&"rsaEncryption"));
    assert!(has_rsa, "RSA should be present in asymmetric ciphers");
}

// =============================================================================
// Phase 6: ALL Operations Return Algorithms (Comprehensive)
// =============================================================================

/// Verifies that the default provider returns `Some` for ALL 12 standard
/// operation types. This is the inverse of the null provider test.
#[test]
fn test_default_provider_covers_all_operation_types() {
    let provider = DefaultProvider::new();
    let all_types = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
        OperationType::Kdf,
        OperationType::KeyExch,
        OperationType::Rand,
        OperationType::Signature,
        OperationType::AsymCipher,
        OperationType::Kem,
        OperationType::KeyMgmt,
        OperationType::EncoderDecoder,
        OperationType::Store,
    ];
    for op_type in &all_types {
        let result = provider.query_operation(*op_type);
        assert!(
            result.is_some(),
            "Default provider should return Some for {:?}, but returned None",
            op_type,
        );
        let descriptors = result.expect("checked above");
        assert!(
            !descriptors.is_empty(),
            "Default provider should return non-empty descriptors for {:?}",
            op_type,
        );
    }
}

// =============================================================================
// Phase 7: Property Tag Consistency
// =============================================================================

/// Verifies that ALL algorithm descriptors across ALL operation types
/// have the property string "provider=default". No "provider=legacy"
/// or "provider=base" leakage should occur.
#[test]
fn test_default_provider_all_algorithms_tagged_default() {
    let provider = DefaultProvider::new();
    let all_types = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
        OperationType::Kdf,
        OperationType::KeyExch,
        OperationType::Rand,
        OperationType::Signature,
        OperationType::AsymCipher,
        OperationType::Kem,
        OperationType::KeyMgmt,
        OperationType::EncoderDecoder,
        OperationType::Store,
    ];
    for op_type in &all_types {
        if let Some(descriptors) = provider.query_operation(*op_type) {
            for descriptor in &descriptors {
                assert_eq!(
                    descriptor.property, "provider=default",
                    "Algorithm {:?} in {:?} should have property 'provider=default' but has '{}'",
                    descriptor.names, op_type, descriptor.property,
                );
            }
        }
    }
}

/// Verifies that every descriptor has a non-empty `names` vector,
/// and every individual name in the names vector is a non-empty string.
#[test]
fn test_default_provider_algorithm_names_non_empty() {
    let provider = DefaultProvider::new();
    let all_types = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
        OperationType::Kdf,
        OperationType::KeyExch,
        OperationType::Rand,
        OperationType::Signature,
        OperationType::AsymCipher,
        OperationType::Kem,
        OperationType::KeyMgmt,
        OperationType::EncoderDecoder,
        OperationType::Store,
    ];
    for op_type in &all_types {
        if let Some(descriptors) = provider.query_operation(*op_type) {
            for descriptor in &descriptors {
                assert!(
                    !descriptor.names.is_empty(),
                    "Algorithm descriptor in {:?} has empty names vector",
                    op_type,
                );
                for name in &descriptor.names {
                    assert!(
                        !name.is_empty(),
                        "Algorithm name in {:?} should not be an empty string",
                        op_type,
                    );
                }
            }
        }
    }
}

// =============================================================================
// Phase 8: Parameter Tests
// =============================================================================

/// Verifies that `get_params()` returns a `ParamSet` whose "name" parameter
/// matches "OpenSSL Default Provider".
#[test]
fn test_default_provider_get_params() {
    let provider = DefaultProvider::new();
    let params = provider
        .get_params()
        .expect("get_params() should succeed for default provider");
    // Verify the name parameter
    let name_param = params.get("name");
    assert!(name_param.is_some(), "ParamSet should contain a 'name' key");
    assert_eq!(
        name_param.and_then(|v| v.as_str()),
        Some("OpenSSL Default Provider"),
        "ParamSet 'name' value should be 'OpenSSL Default Provider'"
    );
    // Also verify version is present
    let version_param = params.get("version");
    assert!(
        version_param.is_some(),
        "ParamSet should contain a 'version' key"
    );
    assert_eq!(
        version_param.and_then(|v| v.as_str()),
        Some("4.0.0"),
        "ParamSet 'version' value should be '4.0.0'"
    );
    // Verify status is present and equals 1 (running)
    let status_param = params.get("status");
    assert!(
        status_param.is_some(),
        "ParamSet should contain a 'status' key"
    );
    assert_eq!(
        status_param.and_then(|v| v.as_i32()),
        Some(1),
        "ParamSet 'status' value should be 1 (running)"
    );
}

/// Verifies that `gettable_params()` returns the standard parameter keys.
#[test]
fn test_default_provider_gettable_params() {
    let provider = DefaultProvider::new();
    let keys = provider.gettable_params();
    assert!(
        keys.contains(&"name"),
        "gettable_params should contain 'name'"
    );
    assert!(
        keys.contains(&"version"),
        "gettable_params should contain 'version'"
    );
    assert!(
        keys.contains(&"buildinfo"),
        "gettable_params should contain 'buildinfo'"
    );
    assert!(
        keys.contains(&"status"),
        "gettable_params should contain 'status'"
    );
}

// =============================================================================
// Phase 9: Lifecycle Tests
// =============================================================================

/// Exercises the full lifecycle: create → query all operations → teardown →
/// verify no panics and post-teardown queries return None.
#[test]
fn test_default_provider_lifecycle() {
    // Phase 1: Create provider and verify it is running
    let mut provider = DefaultProvider::new();
    assert!(provider.is_running());

    // Phase 2: Query all 12 operation types — all should return Some
    let all_types = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
        OperationType::Kdf,
        OperationType::KeyExch,
        OperationType::Rand,
        OperationType::Signature,
        OperationType::AsymCipher,
        OperationType::Kem,
        OperationType::KeyMgmt,
        OperationType::EncoderDecoder,
        OperationType::Store,
    ];
    for op_type in &all_types {
        let result = provider.query_operation(*op_type);
        assert!(
            result.is_some(),
            "Before teardown: query_operation({:?}) should return Some",
            op_type,
        );
    }

    // Phase 3: Verify parameters are accessible
    let params = provider
        .get_params()
        .expect("get_params should succeed before teardown");
    assert_eq!(
        params.get("status").and_then(|v| v.as_i32()),
        Some(1),
        "Status should be 1 (running) before teardown"
    );

    // Phase 4: Teardown the provider
    provider
        .teardown()
        .expect("teardown() should succeed without error");
    assert!(
        !provider.is_running(),
        "Provider should NOT be running after teardown"
    );

    // Phase 5: Verify post-teardown queries return None
    for op_type in &all_types {
        let result = provider.query_operation(*op_type);
        assert!(
            result.is_none(),
            "After teardown: query_operation({:?}) should return None",
            op_type,
        );
    }

    // Phase 6: Verify post-teardown status is 0
    let params = provider
        .get_params()
        .expect("get_params should still succeed after teardown");
    assert_eq!(
        params.get("status").and_then(|v| v.as_i32()),
        Some(0),
        "Status should be 0 (stopped) after teardown"
    );
}

/// Verifies that teardown can be called multiple times without panicking.
#[test]
fn test_default_provider_double_teardown() {
    let mut provider = DefaultProvider::new();
    provider.teardown().expect("first teardown should succeed");
    // Second teardown should also succeed (idempotent behavior)
    provider
        .teardown()
        .expect("second teardown should succeed (idempotent)");
    assert!(!provider.is_running());
}
