//! Integration tests for the `LegacyProvider`.
//!
//! **CRITICAL:** This entire test module is gated behind `#[cfg(feature = "legacy")]`
//! because the [`LegacyProvider`] struct is only compiled when that feature is
//! enabled in `Cargo.toml`.
//!
//! Verifies that the legacy provider:
//! - Returns correct metadata (name: `"OpenSSL Legacy Provider"`)
//! - Exposes ONLY legacy digest, cipher, and KDF operations
//! - Does NOT expose signature, KEM, keymgmt, exchange, rand, encoder/decoder,
//!   store, or asymmetric cipher operations
//! - All algorithm descriptors carry the `"provider=legacy"` property tag
//! - Algorithm names are non-empty and structurally valid
//! - Parameters are retrievable and match the provider's canonical name
//! - Full lifecycle (create → query → teardown) executes without panics
//!
//! Source reference: `providers/legacyprov.c` (~230 lines in the C codebase).
//!
//! # Rules Enforced
//!
//! - **Rule R8:** ZERO `unsafe` blocks in this file
//! - **Rule R5:** All queries use `Option`, no sentinel values
//! - **Rule R10:** Tests exercise `LegacyProvider` through the `Provider` trait

// NOTE: This module is feature-gated via `#[cfg(feature = "legacy")]` on the
// `mod test_legacy_provider;` declaration in tests/mod.rs.  No inner
// `#![cfg(...)]` is needed here — the parent mod.rs handles compilation gating.

use crate::legacy::LegacyProvider;
use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use openssl_common::types::OperationType;

// =============================================================================
// Helper Utilities
// =============================================================================

/// Collects all algorithm names from a slice of [`AlgorithmDescriptor`]s into
/// a flat `Vec`, making it straightforward to search for specific algorithm
/// names across all descriptors returned by `query_operation()`.
fn collect_all_names(descriptors: &[AlgorithmDescriptor]) -> Vec<&'static str> {
    descriptors
        .iter()
        .flat_map(|d| d.names.iter().copied())
        .collect()
}

/// Asserts that `expected_name` appears in at least one descriptor's `names`
/// vec.  Provides a clear panic message listing all known names on failure.
fn assert_algorithm_present(descriptors: &[AlgorithmDescriptor], expected_name: &str) {
    let all_names = collect_all_names(descriptors);
    assert!(
        all_names.iter().any(|n| *n == expected_name),
        "Expected algorithm '{expected_name}' not found in descriptor names: {all_names:?}",
    );
}

// =============================================================================
// Phase 2: Metadata Tests
// =============================================================================

/// Verify that `info().name` matches the C provider name string exactly.
///
/// C reference: `legacyprov.c` line ~85 — `"OpenSSL Legacy Provider"`.
#[test]
fn test_legacy_provider_info_name() {
    let provider = LegacyProvider::new();
    let info: ProviderInfo = provider.info();
    assert_eq!(
        info.name, "OpenSSL Legacy Provider",
        "Legacy provider name must match C legacyprov.c exactly"
    );
}

/// Verify that a newly created legacy provider reports `status = true`.
#[test]
fn test_legacy_provider_info_status() {
    let provider = LegacyProvider::new();
    let info = provider.info();
    assert!(
        info.status,
        "Newly created legacy provider must report status=true"
    );
}

/// Verify that `is_running()` returns `true` for a newly created provider.
///
/// C reference: `ossl_prov_is_running()` in `prov_running.c` unconditionally
/// returns 1.  In Rust the state is tracked via the `running` field, and a
/// freshly constructed provider starts in the running state.
#[test]
fn test_legacy_provider_is_running() {
    let provider = LegacyProvider::new();
    assert!(
        provider.is_running(),
        "Newly created legacy provider must report is_running()=true"
    );
}

// =============================================================================
// Phase 3: Positive Query Tests — Legacy Algorithm Families
// =============================================================================
// Per C `legacy_query()` function (legacyprov.c), the legacy provider supports:
//   OSSL_OP_DIGEST  → MD2, MD4, MDC2, Whirlpool, RIPEMD-160
//   OSSL_OP_CIPHER  → Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, DES/DESX
//   OSSL_OP_KDF     → PBKDF1, PVKKDF

/// Query digest operations — must return a non-empty table of legacy-only
/// digests (MD2, MD4, MDC2, Whirlpool, RIPEMD-160) with the correct
/// `"provider=legacy"` property tag.
#[test]
fn test_legacy_provider_query_digests() {
    let provider = LegacyProvider::new();
    let digests = provider.query_operation(OperationType::Digest);
    assert!(
        digests.is_some(),
        "Legacy provider must return Some for Digest operations"
    );

    let descriptors = digests.unwrap();
    assert!(
        !descriptors.is_empty(),
        "Legacy digest table must contain at least one algorithm"
    );

    // Verify expected legacy-only digest names are present.
    // These are deprecated algorithms NOT available in the default provider.
    assert_algorithm_present(&descriptors, "MD4");
    assert_algorithm_present(&descriptors, "MDC2");
    assert_algorithm_present(&descriptors, "WHIRLPOOL");

    // Verify every descriptor carries the "provider=legacy" property tag.
    for desc in &descriptors {
        assert_eq!(
            desc.property, "provider=legacy",
            "Digest {:?} must have property 'provider=legacy', found: '{}'",
            desc.names, desc.property
        );
    }
}

/// Query cipher operations — must return the complete legacy cipher table
/// covering Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, and DES families
/// with appropriate mode variants (CBC/ECB/CFB/OFB etc.).
#[test]
fn test_legacy_provider_query_ciphers() {
    let provider = LegacyProvider::new();
    let ciphers = provider.query_operation(OperationType::Cipher);
    assert!(
        ciphers.is_some(),
        "Legacy provider must return Some for Cipher operations"
    );

    let descriptors = ciphers.unwrap();
    assert!(
        !descriptors.is_empty(),
        "Legacy cipher table must contain at least one algorithm"
    );

    let all_names = collect_all_names(&descriptors);

    // --- Verify each legacy cipher family is present ---

    // Blowfish (BF-*) family
    assert!(
        all_names.iter().any(|n| n.starts_with("BF-")),
        "Blowfish (BF-*) family must be in legacy ciphers, found: {all_names:?}",
    );
    // CAST5 family
    assert!(
        all_names.iter().any(|n| n.starts_with("CAST5-")),
        "CAST5-* family must be in legacy ciphers"
    );
    // IDEA family
    assert!(
        all_names.iter().any(|n| n.starts_with("IDEA-")),
        "IDEA-* family must be in legacy ciphers"
    );
    // SEED family
    assert!(
        all_names.iter().any(|n| n.starts_with("SEED-")),
        "SEED-* family must be in legacy ciphers"
    );
    // RC2
    assert!(
        all_names.iter().any(|n| n.starts_with("RC2")),
        "RC2 must be in legacy ciphers"
    );
    // RC4
    assert!(
        all_names.iter().any(|n| *n == "RC4"),
        "RC4 must be in legacy ciphers"
    );
    // RC5
    assert!(
        all_names.iter().any(|n| n.starts_with("RC5")),
        "RC5 family must be in legacy ciphers"
    );
    // DES variants (single-key DES and DESX, not 3DES which is in default)
    assert!(
        all_names.iter().any(|n| *n == "DES-CBC"),
        "DES-CBC must be in legacy ciphers"
    );
    assert!(
        all_names.iter().any(|n| *n == "DES-ECB"),
        "DES-ECB must be in legacy ciphers"
    );
    assert!(
        all_names.iter().any(|n| *n == "DESX-CBC"),
        "DESX-CBC must be in legacy ciphers"
    );

    // All descriptors must have "provider=legacy" property.
    for desc in &descriptors {
        assert_eq!(
            desc.property, "provider=legacy",
            "Cipher {:?} must have property 'provider=legacy', found: '{}'",
            desc.names, desc.property
        );
    }
}

/// Query KDF operations — must return PBKDF1 and PVKKDF, both tagged
/// with `"provider=legacy"`.
#[test]
fn test_legacy_provider_query_kdfs() {
    let provider = LegacyProvider::new();
    let kdfs = provider.query_operation(OperationType::Kdf);
    assert!(
        kdfs.is_some(),
        "Legacy provider must return Some for KDF operations"
    );

    let descriptors = kdfs.unwrap();
    assert!(
        !descriptors.is_empty(),
        "Legacy KDF table must contain at least one algorithm"
    );

    // Verify the two legacy KDFs are present.
    assert_algorithm_present(&descriptors, "PBKDF1");
    assert_algorithm_present(&descriptors, "PVKKDF");

    // All descriptors must have "provider=legacy" property.
    for desc in &descriptors {
        assert_eq!(
            desc.property, "provider=legacy",
            "KDF {:?} must have property 'provider=legacy', found: '{}'",
            desc.names, desc.property
        );
    }
}

/// Verify that legacy ciphers include multiple modes per algorithm family.
///
/// The C `legacy_ciphers[]` table defines four standard modes (CBC, ECB, CFB,
/// OFB) for each of the fixed-block-size cipher families.
#[test]
fn test_legacy_provider_cipher_modes() {
    let provider = LegacyProvider::new();
    let ciphers = provider
        .query_operation(OperationType::Cipher)
        .expect("Legacy provider must return cipher descriptors");
    let all_names = collect_all_names(&ciphers);

    // Blowfish — 4 standard modes.
    for mode in &["BF-CBC", "BF-ECB", "BF-CFB", "BF-OFB"] {
        assert!(
            all_names.iter().any(|n| n == mode),
            "Blowfish mode '{mode}' must be present in legacy ciphers, found: {all_names:?}",
        );
    }

    // CAST5 — 4 standard modes.
    for mode in &["CAST5-CBC", "CAST5-ECB", "CAST5-CFB", "CAST5-OFB"] {
        assert!(
            all_names.iter().any(|n| n == mode),
            "CAST5 mode '{mode}' must be present in legacy ciphers",
        );
    }
}

// =============================================================================
// Phase 4: Negative Query Tests — Operations the Legacy Provider Does NOT Support
// =============================================================================
// The legacy provider's `query_operation()` returns `None` for every operation
// type not in {Digest, Cipher, Kdf}.  Each unsupported type is tested
// individually for clarity and debuggability.

/// MAC operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_mac_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::Mac).is_none(),
        "Legacy provider must NOT support Mac operations"
    );
}

/// Signature operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_signature_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::Signature).is_none(),
        "Legacy provider must NOT support Signature operations"
    );
}

/// KEM operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_kem_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::Kem).is_none(),
        "Legacy provider must NOT support KEM operations"
    );
}

/// Key management operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_keymgmt_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::KeyMgmt).is_none(),
        "Legacy provider must NOT support KeyMgmt operations"
    );
}

/// Key exchange operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_keyexch_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::KeyExch).is_none(),
        "Legacy provider must NOT support KeyExch operations"
    );
}

/// Random number generation operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_rand_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::Rand).is_none(),
        "Legacy provider must NOT support Rand operations"
    );
}

/// Encoder/decoder operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_encoder_decoder_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none(),
        "Legacy provider must NOT support EncoderDecoder operations"
    );
}

/// Store operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_store_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider.query_operation(OperationType::Store).is_none(),
        "Legacy provider must NOT support Store operations"
    );
}

/// Asymmetric cipher operations are NOT supported by the legacy provider.
#[test]
fn test_legacy_provider_query_asym_cipher_returns_none() {
    let provider = LegacyProvider::new();
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_none(),
        "Legacy provider must NOT support AsymCipher operations"
    );
}

// =============================================================================
// Phase 5: Feature Gate and Property Tests
// =============================================================================

/// Verify that EVERY algorithm descriptor returned by the legacy provider
/// carries the `"provider=legacy"` property tag — and that NO descriptor
/// leaks the `"provider=default"` tag.
///
/// This is a comprehensive cross-operation check that supplements the
/// per-operation property assertions in Phase 3.
#[test]
fn test_legacy_provider_all_algorithms_tagged_legacy() {
    let provider = LegacyProvider::new();

    // All three operation types that the legacy provider supports.
    let supported_ops = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Kdf,
    ];

    for op in &supported_ops {
        if let Some(descriptors) = provider.query_operation(*op) {
            for desc in &descriptors {
                assert_eq!(
                    desc.property, "provider=legacy",
                    "Algorithm {:?} (op: {:?}) has wrong property: '{}'. \
                     All legacy algorithms must have property 'provider=legacy'.",
                    desc.names, op, desc.property
                );
                // Also verify no "provider=default" leakage.
                assert!(
                    !desc.property.contains("provider=default"),
                    "Algorithm {:?} must not carry 'provider=default' tag — \
                     this would indicate leakage from the default provider.",
                    desc.names
                );
            }
        }
    }
}

/// Verify that every algorithm descriptor has a non-empty `names` vec and
/// that each individual name string is non-empty.
#[test]
fn test_legacy_provider_algorithm_names_are_valid() {
    let provider = LegacyProvider::new();

    let supported_ops = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Kdf,
    ];

    for op in &supported_ops {
        if let Some(descriptors) = provider.query_operation(*op) {
            for desc in &descriptors {
                // Each descriptor must have at least one name.
                assert!(
                    !desc.names.is_empty(),
                    "Descriptor for operation {op:?} has an empty names vec",
                );
                // Each individual name must be a non-empty string.
                for name in &desc.names {
                    assert!(
                        !name.is_empty(),
                        "Empty algorithm name string found in descriptor {:?} for op {:?}",
                        desc.names, op
                    );
                }
            }
        }
    }
}

// =============================================================================
// Phase 6: Parameter and Lifecycle Tests
// =============================================================================

/// Verify that `get_params()` returns a `ParamSet` containing the provider's
/// canonical name `"OpenSSL Legacy Provider"`.
#[test]
fn test_legacy_provider_get_params() {
    let provider = LegacyProvider::new();
    let params = provider
        .get_params()
        .expect("get_params() must succeed for a running legacy provider");

    // Verify the "name" parameter is present and matches the expected value.
    let name: String = params
        .get_typed("name")
        .expect("'name' parameter must be present in legacy provider params");
    assert_eq!(
        name, "OpenSSL Legacy Provider",
        "Param 'name' must match the provider's canonical name"
    );
}

/// Exercise the complete provider lifecycle: create → use → teardown.
///
/// Verifies:
/// 1. Provider starts in running state
/// 2. All supported operations return `Some(...)` while running
/// 3. `teardown()` returns `Ok(())`
/// 4. Provider reports not-running after teardown
/// 5. All queries return `None` after teardown
#[test]
fn test_legacy_provider_lifecycle() {
    // --- Phase 1: Create and verify initial state ---
    let mut provider = LegacyProvider::new();
    assert!(
        provider.is_running(),
        "Provider must be running after creation"
    );
    assert!(
        provider.info().status,
        "Provider status must be true after creation"
    );

    // --- Phase 2: Exercise — query all supported operations ---
    let digests = provider.query_operation(OperationType::Digest);
    assert!(
        digests.is_some(),
        "Digest query must succeed on a running provider"
    );

    let ciphers = provider.query_operation(OperationType::Cipher);
    assert!(
        ciphers.is_some(),
        "Cipher query must succeed on a running provider"
    );

    let kdfs = provider.query_operation(OperationType::Kdf);
    assert!(
        kdfs.is_some(),
        "KDF query must succeed on a running provider"
    );

    // --- Phase 3: Teardown ---
    let result = provider.teardown();
    assert!(result.is_ok(), "teardown() must return Ok(())");

    // --- Phase 4: Verify post-teardown state ---
    assert!(
        !provider.is_running(),
        "Provider must NOT be running after teardown"
    );
    assert!(
        !provider.info().status,
        "Provider status must be false after teardown"
    );

    // --- Phase 5: Verify all queries return None after teardown ---
    assert!(
        provider.query_operation(OperationType::Digest).is_none(),
        "Digest query must return None after teardown"
    );
    assert!(
        provider.query_operation(OperationType::Cipher).is_none(),
        "Cipher query must return None after teardown"
    );
    assert!(
        provider.query_operation(OperationType::Kdf).is_none(),
        "KDF query must return None after teardown"
    );
}
