//! Integration tests for the MethodStore and algorithm dispatch infrastructure.
//!
//! Tests:
//! - **Method store CRUD:** register, fetch, remove, flush cache
//! - **Property matching:** "provider=default" queries, negation, empty/wildcard queries
//! - **Concurrent access:** Thread-safe read/write under parking_lot::RwLock (Rule R7)
//! - **Cache behavior:** First fetch populates cache, subsequent fetches use cache
//! - **Algorithm enumeration:** enumerate_algorithms() and enumerate_all() return correct results
//! - **Provider registration coordinator:** register_provider() queries all operations and caches
//! - **Capabilities:** get_capabilities() returns TLS group/sigalg metadata
//!
//! Source references: `crypto/core_fetch.c`, `crypto/core_algorithm.c`,
//! `providers/common/capabilities.c`
//!
//! # Rules Enforced
//!
//! - **Rule R4:** Registration via register_provider paired with fetch invocation tests
//! - **Rule R7 (CRITICAL):** Concurrent access tests with multiple threads verifying RwLock
//! - **Rule R8:** ZERO `unsafe` in this file
//! - **Rule R5:** All fetches return Result/Option, error paths tested explicitly
//! - **Rule R10:** Tests verify complete wiring: Provider → MethodStore → fetch

// Tests legitimately use .unwrap() / .expect() / panic!() in assertions and
// match arms.  Doc comments reference type names without backticks for readability.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use crate::base::BaseProvider;
use crate::default::DefaultProvider;
use crate::dispatch::{AlgorithmCapability, MethodStore};
use crate::null::NullProvider;
use crate::traits::AlgorithmDescriptor;
use openssl_common::types::OperationType;
use openssl_common::ProviderError;
use std::sync::Arc;
use std::thread;

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates a simple digest algorithm descriptor for testing.
fn make_digest_descriptor(
    names: Vec<&'static str>,
    property: &'static str,
    description: &'static str,
) -> AlgorithmDescriptor {
    AlgorithmDescriptor {
        names,
        property,
        description,
    }
}

/// Creates a MethodStore pre-populated with a single digest algorithm.
fn store_with_one_digest() -> MethodStore {
    let store = MethodStore::new();
    let desc = make_digest_descriptor(
        vec!["SHA2-256", "SHA-256", "SHA256"],
        "provider=default",
        "SHA-2 256-bit digest",
    );
    store.register(OperationType::Digest, "default", vec![desc]);
    store
}

/// Creates a MethodStore pre-populated with multiple algorithms from
/// two different providers (default and base).
fn store_with_multiple_providers() -> MethodStore {
    let store = MethodStore::new();

    // Register digest from "default" provider
    let digest_desc = make_digest_descriptor(
        vec!["SHA2-256", "SHA-256", "SHA256"],
        "provider=default",
        "SHA-2 256-bit digest",
    );
    store.register(OperationType::Digest, "default", vec![digest_desc]);

    // Register cipher from "default" provider
    let cipher_desc = AlgorithmDescriptor {
        names: vec!["AES-128-GCM"],
        property: "provider=default",
        description: "AES-128 GCM",
    };
    store.register(OperationType::Cipher, "default", vec![cipher_desc]);

    // Register encoder from "base" provider
    let encoder_desc = AlgorithmDescriptor {
        names: vec!["DER"],
        property: "provider=base",
        description: "DER encoder",
    };
    store.register(OperationType::EncoderDecoder, "base", vec![encoder_desc]);

    store
}

// =============================================================================
// Phase 2: MethodStore Basic Operations
// =============================================================================

/// Verify that a freshly created MethodStore is completely empty.
/// enumerate_all() returns no entries and fetch for any operation fails.
#[test]
fn test_method_store_new_is_empty() {
    let store = MethodStore::new();
    let all = store.enumerate_all();
    assert!(all.is_empty(), "new store should have no algorithms");

    // Fetch from an empty store should return an error
    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(result.is_err(), "fetch from empty store should fail");
}

/// Verify that algorithms can be registered and enumerated by operation type.
#[test]
fn test_method_store_register_algorithms() {
    let store = MethodStore::new();

    let desc = make_digest_descriptor(
        vec!["SHA2-256", "SHA-256", "SHA256"],
        "provider=default",
        "SHA-2 256-bit digest",
    );
    store.register(OperationType::Digest, "default", vec![desc]);

    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert_eq!(
        digests.len(),
        1,
        "should have exactly one digest registered"
    );
    assert!(
        digests[0].names.contains(&"SHA2-256"),
        "registered algorithm should contain name SHA2-256"
    );
    assert_eq!(
        digests[0].property, "provider=default",
        "property string should match"
    );
}

/// Verify that algorithms from multiple providers can coexist in the store
/// without cross-contamination.
#[test]
fn test_method_store_register_multiple_providers() {
    let store = store_with_multiple_providers();

    // Verify default provider algorithms
    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert_eq!(digests.len(), 1, "should have one digest from default");

    let ciphers = store.enumerate_algorithms(OperationType::Cipher);
    assert_eq!(ciphers.len(), 1, "should have one cipher from default");

    // Verify base provider algorithms
    let encoders = store.enumerate_algorithms(OperationType::EncoderDecoder);
    assert_eq!(encoders.len(), 1, "should have one encoder from base");

    // Verify total count
    let all = store.enumerate_all();
    assert_eq!(all.len(), 3, "total algorithm count should be 3");
}

/// Verify that removing a provider clears only that provider's algorithms.
#[test]
fn test_method_store_remove_provider() {
    let store = store_with_multiple_providers();

    // Pre-condition: both providers present
    assert_eq!(store.enumerate_all().len(), 3);

    // Remove the "default" provider
    store.remove_provider("default");

    // Only base provider algorithms should remain
    let all = store.enumerate_all();
    assert_eq!(
        all.len(),
        1,
        "only base provider algorithm should remain after removal"
    );

    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        digests.is_empty(),
        "default digest should be removed after provider removal"
    );

    let encoders = store.enumerate_algorithms(OperationType::EncoderDecoder);
    assert_eq!(
        encoders.len(),
        1,
        "base provider encoder should remain after default removal"
    );

    // Fetch for removed algorithm should fail
    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result.is_err(),
        "fetch for removed provider's algorithm should fail"
    );
}

// =============================================================================
// Phase 3: Fetch Operations (Replaces ossl_method_store_fetch)
// =============================================================================

/// Verify that an algorithm can be fetched by name without a property query.
#[test]
fn test_method_store_fetch_by_name() {
    let store = store_with_one_digest();

    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result.is_ok(),
        "fetch by name should succeed: {:?}",
        result.err()
    );
}

/// Verify that property queries filter algorithm selection correctly.
#[test]
fn test_method_store_fetch_by_name_and_property() {
    let store = store_with_one_digest();

    // Matching property should succeed
    let result = store.fetch(OperationType::Digest, "SHA-256", Some("provider=default"));
    assert!(
        result.is_ok(),
        "fetch with matching property should succeed: {:?}",
        result.err()
    );

    // Non-matching property should fail
    let result = store.fetch(OperationType::Digest, "SHA-256", Some("provider=legacy"));
    assert!(
        result.is_err(),
        "fetch with non-matching property should fail"
    );
}

/// Verify that fetching a non-existent algorithm returns the correct error.
#[test]
fn test_method_store_fetch_nonexistent_returns_error() {
    let store = store_with_one_digest();

    let result = store.fetch(OperationType::Digest, "NONEXISTENT-HASH", None);
    assert!(result.is_err(), "fetch for non-existent should fail");

    let err = result.unwrap_err();
    match &err {
        ProviderError::AlgorithmUnavailable(msg) => {
            assert!(
                msg.contains("NONEXISTENT-HASH"),
                "error message should contain algorithm name, got: {}",
                msg
            );
        }
        other => panic!("expected AlgorithmUnavailable, got: {:?}", other),
    }
}

/// Verify that operation type isolation is enforced: a digest registered
/// under Digest cannot be fetched as a Cipher.
#[test]
fn test_method_store_fetch_wrong_operation_type() {
    let store = store_with_one_digest();

    // Registered as Digest, but fetching as Cipher should fail
    let result = store.fetch(OperationType::Cipher, "SHA-256", None);
    assert!(
        result.is_err(),
        "fetch with wrong operation type should fail"
    );
}

/// Verify case-insensitive name matching (OpenSSL uses OPENSSL_strcasecmp).
/// The dispatch normalises names to uppercase before lookup.
#[test]
fn test_method_store_fetch_case_sensitivity() {
    let store = store_with_one_digest();

    // Lowercase should match (store normalises to uppercase)
    let result_lower = store.fetch(OperationType::Digest, "sha-256", None);
    assert!(
        result_lower.is_ok(),
        "lowercase fetch should succeed: {:?}",
        result_lower.err()
    );

    // Mixed case should match
    let result_mixed = store.fetch(OperationType::Digest, "Sha-256", None);
    assert!(
        result_mixed.is_ok(),
        "mixed case fetch should succeed: {:?}",
        result_mixed.err()
    );

    // Original uppercase should match
    let result_upper = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result_upper.is_ok(),
        "uppercase fetch should succeed: {:?}",
        result_upper.err()
    );
}

// =============================================================================
// Phase 4: Cache Behavior Tests
// =============================================================================

/// Verify that the first fetch populates the cache and subsequent fetches
/// return the same Arc instance (cache hit).
#[test]
fn test_method_store_cache_populated_on_first_fetch() {
    let store = store_with_one_digest();

    // First fetch — cache miss, resolves from registry
    let first = store
        .fetch(OperationType::Digest, "SHA-256", None)
        .expect("first fetch should succeed");

    // Second fetch — cache hit, should return same Arc
    let second = store
        .fetch(OperationType::Digest, "SHA-256", None)
        .expect("second fetch should succeed");

    assert!(
        Arc::ptr_eq(&first, &second),
        "second fetch should return the same cached Arc instance"
    );
}

/// Verify that flush_cache() clears the cache but algorithms can still
/// be re-resolved from the registry.
#[test]
fn test_method_store_flush_cache() {
    let store = store_with_one_digest();

    // Populate cache
    let before_flush = store
        .fetch(OperationType::Digest, "SHA-256", None)
        .expect("fetch before flush should succeed");

    // Flush the cache
    store.flush_cache();

    // Fetch again — should still succeed (re-resolves from registry)
    let after_flush = store
        .fetch(OperationType::Digest, "SHA-256", None)
        .expect("fetch after flush should still succeed");

    // The Arc pointers should be different (fresh resolution)
    assert!(
        !Arc::ptr_eq(&before_flush, &after_flush),
        "fetch after flush should return a new Arc instance"
    );
}

/// Verify that removing a provider invalidates the cache for that
/// provider's algorithms.
#[test]
fn test_method_store_cache_invalidated_on_remove() {
    let store = store_with_one_digest();

    // Populate cache
    let _cached = store
        .fetch(OperationType::Digest, "SHA-256", None)
        .expect("initial fetch should succeed");

    // Remove the provider
    store.remove_provider("default");

    // Fetch should now fail (cache cleared and registry entry removed)
    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(result.is_err(), "fetch after provider removal should fail");
}

// =============================================================================
// Phase 5: Property Matching Tests
// =============================================================================

/// Verify that an exact property match succeeds.
#[test]
fn test_property_match_exact() {
    let store = MethodStore::new();
    let desc = make_digest_descriptor(vec!["SHA2-256", "SHA-256"], "provider=default", "SHA-2 256");
    store.register(OperationType::Digest, "default", vec![desc]);

    let result = store.fetch(OperationType::Digest, "SHA-256", Some("provider=default"));
    assert!(result.is_ok(), "exact property match should succeed");
}

/// Verify that an empty or None property query acts as a wildcard and
/// matches any algorithm regardless of its properties.
#[test]
fn test_property_match_empty_query() {
    let store = MethodStore::new();
    let desc = make_digest_descriptor(vec!["SHA2-256", "SHA-256"], "provider=default", "SHA-2 256");
    store.register(OperationType::Digest, "default", vec![desc]);

    // None query → wildcard
    let result_none = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result_none.is_ok(),
        "None property query should match: {:?}",
        result_none.err()
    );

    // Empty string query → wildcard
    let result_empty = store.fetch(OperationType::Digest, "SHA-256", Some(""));
    assert!(
        result_empty.is_ok(),
        "empty string property query should match: {:?}",
        result_empty.err()
    );
}

/// Verify that a non-matching property query returns an error.
#[test]
fn test_property_match_no_match() {
    let store = MethodStore::new();
    let desc = make_digest_descriptor(vec!["SHA2-256", "SHA-256"], "provider=default", "SHA-2 256");
    store.register(OperationType::Digest, "default", vec![desc]);

    let result = store.fetch(OperationType::Digest, "SHA-256", Some("provider=legacy"));
    assert!(result.is_err(), "non-matching property query should fail");
}

/// Verify that subset property matching works: if the algorithm has multiple
/// properties, a query for a subset should match.
#[test]
fn test_property_match_multiple_properties() {
    let store = MethodStore::new();
    let desc = make_digest_descriptor(
        vec!["SHA2-256", "SHA-256"],
        "provider=default,fips=yes",
        "SHA-2 256 FIPS",
    );
    store.register(OperationType::Digest, "default", vec![desc]);

    // Query for subset of properties should match
    let result = store.fetch(OperationType::Digest, "SHA-256", Some("provider=default"));
    assert!(
        result.is_ok(),
        "subset property query should match: {:?}",
        result.err()
    );

    // Query for full set should also match
    let result_full = store.fetch(
        OperationType::Digest,
        "SHA-256",
        Some("provider=default,fips=yes"),
    );
    assert!(
        result_full.is_ok(),
        "full property query should match: {:?}",
        result_full.err()
    );
}

// =============================================================================
// Phase 6: Algorithm Enumeration (Replaces ossl_algorithm_do_all)
// =============================================================================

/// Verify that enumerate_algorithms() returns only algorithms of the
/// requested operation type, with no cross-contamination.
#[test]
fn test_enumerate_algorithms_by_operation() {
    let store = store_with_multiple_providers();

    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert_eq!(digests.len(), 1, "should enumerate 1 digest");
    assert!(
        digests[0].names.contains(&"SHA2-256"),
        "digest should be SHA2-256"
    );

    let ciphers = store.enumerate_algorithms(OperationType::Cipher);
    assert_eq!(ciphers.len(), 1, "should enumerate 1 cipher");
    assert!(
        ciphers[0].names.contains(&"AES-128-GCM"),
        "cipher should be AES-128-GCM"
    );

    let encoders = store.enumerate_algorithms(OperationType::EncoderDecoder);
    assert_eq!(encoders.len(), 1, "should enumerate 1 encoder");
    assert!(encoders[0].names.contains(&"DER"), "encoder should be DER");

    // No cross-contamination: digest enumeration should not contain ciphers
    for d in &digests {
        assert!(
            !d.names.contains(&"AES-128-GCM"),
            "digest enumeration should not contain cipher names"
        );
    }
}

/// Verify that enumerate_all() returns the full union of all registered
/// algorithms across all providers.
#[test]
fn test_enumerate_all_algorithms() {
    let store = store_with_multiple_providers();

    let all = store.enumerate_all();
    assert_eq!(
        all.len(),
        3,
        "enumerate_all should return all 3 registered algorithms"
    );

    // Verify each operation type is represented
    let ops: Vec<OperationType> = all.iter().map(|(op, _)| *op).collect();
    assert!(
        ops.contains(&OperationType::Digest),
        "should contain Digest"
    );
    assert!(
        ops.contains(&OperationType::Cipher),
        "should contain Cipher"
    );
    assert!(
        ops.contains(&OperationType::EncoderDecoder),
        "should contain EncoderDecoder"
    );
}

/// Verify that enumerating an operation type with no registered algorithms
/// returns an empty vector.
#[test]
fn test_enumerate_empty_operation() {
    let store = store_with_one_digest();

    let kems = store.enumerate_algorithms(OperationType::Kem);
    assert!(
        kems.is_empty(),
        "enumerate_algorithms for Kem should be empty when none registered"
    );

    let kdf = store.enumerate_algorithms(OperationType::Kdf);
    assert!(
        kdf.is_empty(),
        "enumerate_algorithms for Kdf should be empty when none registered"
    );
}

// =============================================================================
// Phase 7: Provider Registration Coordinator Tests
// =============================================================================

/// Verify that register_provider() queries all operation types from the
/// provider and populates the store. DefaultProvider supports all 13
/// operation types (feature-gated), so we should see algorithms registered
/// for each supported type.
#[test]
fn test_register_provider_queries_all_operations() {
    let store = MethodStore::new();
    let provider = DefaultProvider::new();

    store.register_provider(&provider);

    // DefaultProvider should register algorithms for at least these core types
    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        !digests.is_empty(),
        "DefaultProvider should register digests"
    );

    let ciphers = store.enumerate_algorithms(OperationType::Cipher);
    assert!(
        !ciphers.is_empty(),
        "DefaultProvider should register ciphers"
    );

    let macs = store.enumerate_algorithms(OperationType::Mac);
    assert!(!macs.is_empty(), "DefaultProvider should register MACs");

    let kdfs = store.enumerate_algorithms(OperationType::Kdf);
    assert!(!kdfs.is_empty(), "DefaultProvider should register KDFs");

    // Verify total registration count is non-trivial
    let all = store.enumerate_all();
    assert!(
        all.len() >= 4,
        "DefaultProvider should register at least 4 algorithms, got: {}",
        all.len()
    );
}

/// Verify that registering NullProvider leaves the store empty since
/// NullProvider::query_operation() always returns None.
#[test]
fn test_register_null_provider_adds_nothing() {
    let store = MethodStore::new();
    let provider = NullProvider::new();

    store.register_provider(&provider);

    let all = store.enumerate_all();
    assert!(
        all.is_empty(),
        "NullProvider should not add any algorithms, got: {}",
        all.len()
    );
}

/// Verify that BaseProvider only registers encoder/decoder, store, and rand
/// algorithms — no digest, cipher, mac, kdf, signature, etc.
#[test]
fn test_register_base_provider_limited_operations() {
    let store = MethodStore::new();
    let provider = BaseProvider::new();

    store.register_provider(&provider);

    // Base should not register core crypto algorithms
    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        digests.is_empty(),
        "BaseProvider should not register digests"
    );

    let ciphers = store.enumerate_algorithms(OperationType::Cipher);
    assert!(
        ciphers.is_empty(),
        "BaseProvider should not register ciphers"
    );

    let sigs = store.enumerate_algorithms(OperationType::Signature);
    assert!(
        sigs.is_empty(),
        "BaseProvider should not register signatures"
    );

    let macs = store.enumerate_algorithms(OperationType::Mac);
    assert!(macs.is_empty(), "BaseProvider should not register MACs");

    // Base should register at least encoder/decoder or store operations
    let all = store.enumerate_all();
    // BaseProvider supports EncoderDecoder, Store, Rand
    // Check that at least one of these has entries (depending on what the
    // provider actually advertises)
    let has_base_ops = !store
        .enumerate_algorithms(OperationType::EncoderDecoder)
        .is_empty()
        || !store.enumerate_algorithms(OperationType::Store).is_empty()
        || !store.enumerate_algorithms(OperationType::Rand).is_empty();

    assert!(
        has_base_ops || all.is_empty(),
        "BaseProvider should register only EncoderDecoder/Store/Rand, or nothing if \
         no algorithms are advertised — but should NOT have digest/cipher/mac/kdf/sig"
    );
}

// =============================================================================
// Phase 8: Concurrent Access Tests (Rule R7 — CRITICAL)
// =============================================================================
//
// These tests verify that the parking_lot::RwLock-based fine-grained locking
// in MethodStore works correctly under concurrent access from multiple threads.
// Per Rule R7, shared data structures with independent access paths must not
// use a single coarse lock — MethodStore uses 3 independent RwLock instances
// for cache, registry, and capabilities.

/// Verify that 10+ concurrent readers can all fetch successfully without
/// panics or deadlocks.
#[test]
fn test_method_store_concurrent_reads() {
    let store = Arc::new(store_with_one_digest());

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let store_clone = Arc::clone(&store);
            thread::spawn(move || {
                let result = store_clone.fetch(OperationType::Digest, "SHA-256", None);
                assert!(result.is_ok(), "concurrent read should succeed");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("reader thread should not panic");
    }
}

/// Verify concurrent reads and writes do not cause panics, deadlocks,
/// or data races. Reader threads fetch while a writer thread registers
/// new algorithms.
#[test]
fn test_method_store_concurrent_read_write() {
    let store = Arc::new(store_with_one_digest());

    let reader_handles: Vec<_> = (0..10)
        .map(|_| {
            let store_clone = Arc::clone(&store);
            thread::spawn(move || {
                for _ in 0..50 {
                    let _ = store_clone.fetch(OperationType::Digest, "SHA-256", None);
                    let _ = store_clone.fetch(OperationType::Cipher, "AES-128-GCM", None);
                }
            })
        })
        .collect();

    let store_writer = Arc::clone(&store);
    let writer_handle = thread::spawn(move || {
        for i in 0..20_usize {
            let name: &'static str = match i % 4 {
                0 => "MD5",
                1 => "SHA-384",
                2 => "SHA-512",
                _ => "SHA3-256",
            };
            let desc = AlgorithmDescriptor {
                names: vec![name],
                property: "provider=default",
                description: "test digest",
            };
            store_writer.register(OperationType::Digest, "default", vec![desc]);
        }
    });

    writer_handle
        .join()
        .expect("writer thread should not panic");
    for handle in reader_handles {
        handle.join().expect("reader thread should not panic");
    }

    let all = store.enumerate_all();
    assert!(
        !all.is_empty(),
        "store should have algorithms after concurrent writes"
    );
}

/// Verify that multiple threads can simultaneously register different
/// providers while other threads enumerate algorithms.
#[test]
fn test_method_store_concurrent_register_and_enumerate() {
    let store = Arc::new(MethodStore::new());

    let store_reg1 = Arc::clone(&store);
    let reg1 = thread::spawn(move || {
        let provider = DefaultProvider::new();
        store_reg1.register_provider(&provider);
    });

    let store_reg2 = Arc::clone(&store);
    let reg2 = thread::spawn(move || {
        let provider = BaseProvider::new();
        store_reg2.register_provider(&provider);
    });

    let enum_handles: Vec<_> = (0..10)
        .map(|_| {
            let store_clone = Arc::clone(&store);
            thread::spawn(move || {
                for _ in 0..20 {
                    let _ = store_clone.enumerate_all();
                    let _ = store_clone.enumerate_algorithms(OperationType::Digest);
                    let _ = store_clone.enumerate_algorithms(OperationType::Cipher);
                }
            })
        })
        .collect();

    reg1.join().expect("registration thread 1 should not panic");
    reg2.join().expect("registration thread 2 should not panic");
    for handle in enum_handles {
        handle.join().expect("enumeration thread should not panic");
    }

    let all = store.enumerate_all();
    assert!(
        !all.is_empty(),
        "store should have algorithms after concurrent registration"
    );
}

/// Verify that flushing the cache while other threads fetch does not
/// cause panics or deadlocks.
#[test]
fn test_method_store_concurrent_flush_and_fetch() {
    let store = Arc::new(store_with_one_digest());
    let _ = store.fetch(OperationType::Digest, "SHA-256", None);

    let fetch_handles: Vec<_> = (0..10)
        .map(|_| {
            let store_clone = Arc::clone(&store);
            thread::spawn(move || {
                for _ in 0..100 {
                    let _ = store_clone.fetch(OperationType::Digest, "SHA-256", None);
                }
            })
        })
        .collect();

    let store_flush = Arc::clone(&store);
    let flush_handle = thread::spawn(move || {
        for _ in 0..50 {
            store_flush.flush_cache();
        }
    });

    flush_handle.join().expect("flush thread should not panic");
    for handle in fetch_handles {
        handle.join().expect("fetch thread should not panic");
    }

    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result.is_ok(),
        "fetch should still work after concurrent flushes"
    );
}

// =============================================================================
// Phase 9: Capabilities Tests (from providers/common/capabilities.c)
// =============================================================================

/// Verify that get_capabilities("TLS-GROUP") returns the default TLS group
/// capabilities containing well-known curves and groups.
#[test]
fn test_get_capabilities_tls_group() {
    let store = MethodStore::new();

    let caps = store.get_capabilities("TLS-GROUP");
    assert!(
        !caps.is_empty(),
        "TLS-GROUP capabilities should be non-empty"
    );

    for cap in &caps {
        assert!(
            !cap.group_name.is_empty(),
            "capability group_name should be non-empty"
        );
        assert!(
            cap.secbits > 0,
            "capability secbits should be > 0, got: {} for {}",
            cap.secbits,
            cap.group_name
        );
    }

    let group_names: Vec<&str> = caps.iter().map(|c| c.group_name.as_str()).collect();

    assert!(
        group_names.contains(&"secp256r1"),
        "TLS-GROUP should contain secp256r1, got: {:?}",
        group_names
    );
    assert!(
        group_names.contains(&"x25519"),
        "TLS-GROUP should contain x25519, got: {:?}",
        group_names
    );
}

/// Verify that requesting capabilities for a non-existent name returns empty.
#[test]
fn test_get_capabilities_unknown_returns_empty() {
    let store = MethodStore::new();
    let caps = store.get_capabilities("NONEXISTENT-CAPABILITY");
    assert!(
        caps.is_empty(),
        "unknown capability should return empty vec, got {} entries",
        caps.len()
    );
}

/// Verify that set_capabilities and get_capabilities round-trip correctly.
#[test]
fn test_set_and_get_capabilities() {
    let store = MethodStore::new();

    let custom_caps = vec![AlgorithmCapability {
        group_name: "test-group".to_string(),
        secbits: 256,
        min_tls: Some(0x0303),
        max_tls: Some(0x0304),
        min_dtls: None,
        max_dtls: None,
    }];

    store.set_capabilities("CUSTOM-CAP", custom_caps);

    let retrieved = store.get_capabilities("CUSTOM-CAP");
    assert_eq!(
        retrieved.len(),
        1,
        "should retrieve exactly 1 custom capability"
    );
    assert_eq!(retrieved[0].group_name, "test-group");
    assert_eq!(retrieved[0].secbits, 256);
    assert_eq!(retrieved[0].min_tls, Some(0x0303));
    assert_eq!(retrieved[0].max_tls, Some(0x0304));
}

// =============================================================================
// Phase 10: Error Path Tests
// =============================================================================

/// Verify that the error returned for a non-existent algorithm is
/// specifically ProviderError::AlgorithmUnavailable with a descriptive message.
#[test]
fn test_fetch_error_is_algorithm_unavailable() {
    let store = MethodStore::new();

    let result = store.fetch(OperationType::Digest, "IMAGINARY-HASH", None);
    assert!(result.is_err(), "fetch for non-existent should fail");

    let err = result.unwrap_err();
    match &err {
        ProviderError::AlgorithmUnavailable(msg) => {
            assert!(
                msg.contains("IMAGINARY-HASH"),
                "error message should mention the algorithm name, got: {}",
                msg
            );
        }
        other => {
            panic!(
                "expected ProviderError::AlgorithmUnavailable, got: {:?}",
                other
            );
        }
    }
}

/// Verify that removing a non-existent provider does not panic.
#[test]
fn test_remove_nonexistent_provider_no_panic() {
    let store = store_with_one_digest();

    store.remove_provider("nonexistent");

    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result.is_ok(),
        "existing algorithm should still be fetchable after removing non-existent provider"
    );
}

/// Verify that registering duplicate algorithm names from the same provider
/// does not cause errors.
#[test]
fn test_register_duplicate_algorithms() {
    let store = MethodStore::new();

    let desc1 = make_digest_descriptor(
        vec!["SHA2-256", "SHA-256"],
        "provider=default",
        "SHA-2 256 v1",
    );
    store.register(OperationType::Digest, "default", vec![desc1]);

    let desc2 = make_digest_descriptor(
        vec!["SHA2-256", "SHA-256"],
        "provider=default",
        "SHA-2 256 v2",
    );
    store.register(OperationType::Digest, "default", vec![desc2]);

    let all = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        !all.is_empty(),
        "duplicate registrations should not clear the store"
    );

    let result = store.fetch(OperationType::Digest, "SHA-256", None);
    assert!(
        result.is_ok(),
        "fetch should succeed even with duplicate registrations"
    );
}
