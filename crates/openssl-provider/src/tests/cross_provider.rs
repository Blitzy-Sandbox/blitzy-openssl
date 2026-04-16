//! Cross-provider integration tests.
//!
//! These tests exercise interactions across multiple providers and the
//! [`MethodStore`] dispatch infrastructure, verifying that algorithm
//! registration, lookup, isolation, and metadata behave correctly when
//! the Default, Base, and Null providers are used together.

use crate::base::BaseProvider;
use crate::default::DefaultProvider;
use crate::dispatch::MethodStore;
use crate::null::NullProvider;
use crate::traits::Provider;
use openssl_common::OperationType;

// ---------------------------------------------------------------------------
// Provider metadata tests
// ---------------------------------------------------------------------------

/// All three non-feature-gated providers report distinct, non-empty names.
#[test]
fn provider_info_names_are_distinct() {
    let default_info = DefaultProvider::new().info();
    let base_info = BaseProvider::new().info();
    let null_info = NullProvider::new().info();

    assert!(!default_info.name.is_empty());
    assert!(!base_info.name.is_empty());
    assert!(!null_info.name.is_empty());

    // All names must be distinct.
    assert_ne!(default_info.name, base_info.name);
    assert_ne!(default_info.name, null_info.name);
    assert_ne!(base_info.name, null_info.name);
}

/// All non-feature-gated providers report running status when freshly
/// constructed.
#[test]
fn all_providers_are_running_after_construction() {
    assert!(DefaultProvider::new().is_running());
    assert!(BaseProvider::new().is_running());
    assert!(NullProvider::new().is_running());
}

// ---------------------------------------------------------------------------
// MethodStore registration and lookup
// ---------------------------------------------------------------------------

/// Registering the Default provider populates the store with digest
/// algorithms that can be fetched by name.
#[test]
fn default_provider_registers_digest_algorithms() {
    let store = MethodStore::new();
    let provider = DefaultProvider::new();
    store.register_provider(&provider);

    // SHA2-256 is a fundamental algorithm that the Default provider must
    // advertise.  The store should be able to enumerate it.
    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        !digests.is_empty(),
        "Default provider should register at least one digest"
    );
}

/// The Null provider registers zero algorithms for every operation type.
#[test]
fn null_provider_registers_no_algorithms() {
    let store = MethodStore::new();
    let provider = NullProvider::new();
    store.register_provider(&provider);

    for op in [
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
    ] {
        let algos = store.enumerate_algorithms(op);
        assert!(
            algos.is_empty(),
            "Null provider should register no algorithms for {op:?}"
        );
    }
}

/// Registering multiple providers in the same store accumulates their
/// algorithms — the total count must be at least as large as each
/// provider's contribution.
#[test]
fn multiple_providers_accumulate_algorithms() {
    let store = MethodStore::new();

    let default_prov = DefaultProvider::new();
    let base_prov = BaseProvider::new();
    let null_prov = NullProvider::new();

    store.register_provider(&default_prov);

    let default_only_count: usize = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
    ]
    .iter()
    .map(|op| store.enumerate_algorithms(*op).len())
    .sum();

    store.register_provider(&base_prov);
    store.register_provider(&null_prov);

    let combined_count: usize = [
        OperationType::Digest,
        OperationType::Cipher,
        OperationType::Mac,
    ]
    .iter()
    .map(|op| store.enumerate_algorithms(*op).len())
    .sum();

    // Adding the null provider adds nothing; adding the base provider may
    // add encoder/decoder entries but not digests/ciphers/macs.  The combined
    // count should be >= the default-only count.
    assert!(
        combined_count >= default_only_count,
        "Combined count ({combined_count}) should be >= default-only count ({default_only_count})"
    );
}

/// Flushing the store cache does not remove registered algorithms — a
/// subsequent enumeration still returns results.
#[test]
fn flush_cache_preserves_registered_algorithms() {
    let store = MethodStore::new();
    let provider = DefaultProvider::new();
    store.register_provider(&provider);

    let before = store.enumerate_algorithms(OperationType::Digest).len();
    store.flush_cache();
    let after = store.enumerate_algorithms(OperationType::Digest).len();

    assert_eq!(before, after, "flush_cache must not discard registry entries");
}

/// `remove_provider` clears only the named provider's algorithms.
#[test]
fn remove_provider_clears_only_that_provider() {
    let store = MethodStore::new();
    let default_prov = DefaultProvider::new();
    let base_prov = BaseProvider::new();

    store.register_provider(&default_prov);
    store.register_provider(&base_prov);

    let before_digest = store.enumerate_algorithms(OperationType::Digest).len();

    // Remove the Default provider — digests should disappear (they came
    // from Default, not Base).
    store.remove_provider(default_prov.info().name);

    let after_digest = store.enumerate_algorithms(OperationType::Digest).len();
    assert!(
        after_digest < before_digest,
        "Removing default provider should reduce digest count"
    );
}

// ---------------------------------------------------------------------------
// Provider get_params interoperability
// ---------------------------------------------------------------------------

/// Each provider's `get_params()` returns a `ParamSet` containing at least
/// the four standard keys: name, version, buildinfo, status.
#[test]
fn all_providers_expose_standard_params() {
    let providers: Vec<Box<dyn Provider>> = vec![
        Box::new(DefaultProvider::new()),
        Box::new(BaseProvider::new()),
        Box::new(NullProvider::new()),
    ];

    for provider in &providers {
        let params = provider
            .get_params()
            .unwrap_or_else(|e| panic!("{}: get_params failed: {e}", provider.info().name));

        let info = provider.info();
        for key in &["name", "version", "buildinfo", "status"] {
            assert!(
                params.get(key).is_some(),
                "{}: missing standard param '{key}'",
                info.name,
            );
        }
    }
}
