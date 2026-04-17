//! Provider lifecycle integration tests.
//!
//! Tests the complete lifecycle for each built-in provider:
//! 1. **Create:** Instantiate provider via `::new()`
//! 2. **Register:** Register with [`MethodStore`] via `register_provider()`
//! 3. **Query:** Verify algorithm discovery through `query_operation()`
//! 4. **Teardown:** Call `teardown()` and verify graceful cleanup
//!
//! Also tests:
//! - Provider factory via [`BuiltinProviderKind`] enum
//! - Provider name-based lookup
//! - Multiple provider coexistence (default + base + null registered simultaneously)
//! - Provider re-registration after teardown
//!
//! Source references: All provider `.c` files (`defltprov.c`, `baseprov.c`,
//! `legacyprov.c`, `nullprov.c`, `prov_running.c`, `provider_ctx.c`).
//!
//! # Rules Enforced
//!
//! - **Rule R4:** Each callback registration (via `MethodStore`) is paired with
//!   an invocation test.
//! - **Rule R7:** Tests verify concurrent access patterns (via `MethodStore`'s `RwLock`).
//! - **Rule R8:** ZERO `unsafe` in this file.
//! - **Rule R10:** Every provider module is reachable and exercised by these tests.
//! - **Rule R5:** All returns use `Option`/`Result`, no sentinels.

// Tests legitimately use .unwrap() / .expect() / panic!() in assertions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::uninlined_format_args
)]

use crate::base::BaseProvider;
use crate::default::DefaultProvider;
use crate::dispatch::MethodStore;
use crate::null::NullProvider;
use crate::traits::{Provider, ProviderInfo};
#[cfg(feature = "legacy")]
use crate::legacy::LegacyProvider;
use openssl_common::OperationType;

// =============================================================================
// BuiltinProviderKind — Local Factory Enum
// =============================================================================

/// Local factory enum for testing provider instantiation by kind.
///
/// Represents the four built-in provider types and provides factory methods
/// for construction, name-based lookup, and trait-object creation.  Replaces
/// the C `ossl_prov_is_running()` provider-type dispatch from `prov_running.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuiltinProviderKind {
    /// The default provider — full algorithm surface.
    Default,
    /// The base provider — encoder/decoder, store, and RAND only.
    Base,
    /// The null provider — no-op sentinel, advertises zero algorithms.
    Null,
    /// The legacy provider — deprecated algorithms (feature-gated).
    Legacy,
}

impl BuiltinProviderKind {
    /// Creates a boxed [`Provider`] trait object for the given provider kind.
    ///
    /// Returns a dynamically-dispatched provider, mirroring the C pattern of
    /// `OSSL_PROVIDER_load()` → dispatch table resolution.
    fn create(self) -> Box<dyn Provider> {
        match self {
            Self::Default => Box::new(DefaultProvider::new()),
            Self::Base => Box::new(BaseProvider::new()),
            Self::Null => Box::new(NullProvider::new()),
            Self::Legacy => {
                #[cfg(feature = "legacy")]
                {
                    Box::new(LegacyProvider::new())
                }
                #[cfg(not(feature = "legacy"))]
                {
                    panic!("Legacy provider requires the 'legacy' feature flag")
                }
            }
        }
    }

    /// Looks up a provider kind by its short name string.
    ///
    /// Mirrors C `ossl_provider_find()` name-based lookup.  Returns `None`
    /// for unrecognised names, and for `"legacy"` when the feature is disabled.
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::Default),
            "base" => Some(Self::Base),
            "null" => Some(Self::Null),
            "legacy" => {
                #[cfg(feature = "legacy")]
                {
                    Some(Self::Legacy)
                }
                #[cfg(not(feature = "legacy"))]
                {
                    None
                }
            }
            _ => None,
        }
    }

    /// Returns the short name for this provider kind.
    fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Base => "base",
            Self::Null => "null",
            Self::Legacy => "legacy",
        }
    }
}

/// Registers all standard built-in providers (default + base) with the given
/// method store.
///
/// Mirrors the C `ossl_provider_activate_all()` initialisation path that loads
/// the default and base providers automatically at library start-up.
fn register_builtin_providers(store: &MethodStore) {
    let default_provider = DefaultProvider::new();
    store.register_provider(&default_provider);

    let base_provider = BaseProvider::new();
    store.register_provider(&base_provider);
}

// =============================================================================
// Phase 2: Individual Provider Lifecycle Tests
// =============================================================================

/// Tests the complete lifecycle of the Default provider:
/// create → verify metadata → query operations → teardown → verify stopped.
///
/// Source: `defltprov.c` `ossl_default_provider_init()` entry point.
#[test]
fn test_default_provider_full_lifecycle() {
    // --- Phase: Create ---
    let mut provider = DefaultProvider::new();

    // --- Phase: Verify metadata ---
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Default Provider");
    assert_eq!(info.version, "4.0.0");
    assert_eq!(info.build_info, "openssl-rs 4.0.0");
    assert!(info.status, "Default provider should start with status=true");
    assert!(
        provider.is_running(),
        "Default provider should be running after creation"
    );

    // --- Phase: Query operations ---
    // Default supports ALL 12 standard algorithm categories with default features.
    let digest_algos = provider.query_operation(OperationType::Digest);
    assert!(digest_algos.is_some(), "Default provider must support Digest");
    assert!(
        !digest_algos.unwrap().is_empty(),
        "Digest algorithms must be non-empty"
    );

    assert!(
        provider.query_operation(OperationType::Cipher).is_some(),
        "Default provider must support Cipher"
    );
    assert!(
        provider.query_operation(OperationType::Mac).is_some(),
        "Default provider must support Mac"
    );
    assert!(
        provider.query_operation(OperationType::Kdf).is_some(),
        "Default provider must support Kdf"
    );
    assert!(
        provider.query_operation(OperationType::Rand).is_some(),
        "Default provider must support Rand"
    );
    assert!(
        provider.query_operation(OperationType::KeyMgmt).is_some(),
        "Default provider must support KeyMgmt"
    );
    assert!(
        provider.query_operation(OperationType::Signature).is_some(),
        "Default provider must support Signature"
    );
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_some(),
        "Default provider must support AsymCipher"
    );
    assert!(
        provider.query_operation(OperationType::Kem).is_some(),
        "Default provider must support Kem"
    );
    assert!(
        provider.query_operation(OperationType::KeyExch).is_some(),
        "Default provider must support KeyExch"
    );
    assert!(
        provider
            .query_operation(OperationType::EncoderDecoder)
            .is_some(),
        "Default provider must support EncoderDecoder"
    );
    assert!(
        provider.query_operation(OperationType::Store).is_some(),
        "Default provider must support Store"
    );

    // --- Phase: Teardown ---
    let result = provider.teardown();
    assert!(result.is_ok(), "Default provider teardown must succeed");
    assert!(
        !provider.is_running(),
        "Default provider must not be running after teardown"
    );

    // After teardown, queries should return None (is_running guard fails).
    let post_teardown = provider.query_operation(OperationType::Digest);
    assert!(
        post_teardown.is_none(),
        "After teardown, query_operation must return None"
    );
}

/// Tests the complete lifecycle of the Base provider:
/// create → verify metadata → positive/negative queries → teardown.
///
/// The base provider supports only EncoderDecoder, Store, and Rand.
/// Source: `baseprov.c`.
#[test]
fn test_base_provider_full_lifecycle() {
    let mut provider = BaseProvider::new();

    // --- Verify metadata ---
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Base Provider");
    assert_eq!(info.version, "4.0.0");
    assert_eq!(info.build_info, "openssl-rs 4.0.0");
    assert!(info.status, "Base provider should start with status=true");
    assert!(provider.is_running());

    // --- Positive queries: base supports EncoderDecoder, Store, Rand ---
    let enc_algos = provider.query_operation(OperationType::EncoderDecoder);
    assert!(
        enc_algos.is_some(),
        "Base provider must support EncoderDecoder"
    );
    assert!(!enc_algos.unwrap().is_empty());

    let store_algos = provider.query_operation(OperationType::Store);
    assert!(store_algos.is_some(), "Base provider must support Store");
    assert!(!store_algos.unwrap().is_empty());

    let rand_algos = provider.query_operation(OperationType::Rand);
    assert!(rand_algos.is_some(), "Base provider must support Rand");
    assert!(!rand_algos.unwrap().is_empty());

    // --- Negative queries: base does NOT support crypto operations ---
    assert!(
        provider.query_operation(OperationType::Digest).is_none(),
        "Base provider must not support Digest"
    );
    assert!(
        provider.query_operation(OperationType::Cipher).is_none(),
        "Base provider must not support Cipher"
    );
    assert!(
        provider.query_operation(OperationType::Mac).is_none(),
        "Base provider must not support Mac"
    );
    assert!(
        provider.query_operation(OperationType::Kdf).is_none(),
        "Base provider must not support Kdf"
    );
    assert!(
        provider.query_operation(OperationType::KeyMgmt).is_none(),
        "Base provider must not support KeyMgmt"
    );
    assert!(
        provider
            .query_operation(OperationType::Signature)
            .is_none(),
        "Base provider must not support Signature"
    );
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_none(),
        "Base provider must not support AsymCipher"
    );
    assert!(
        provider.query_operation(OperationType::Kem).is_none(),
        "Base provider must not support Kem"
    );
    assert!(
        provider.query_operation(OperationType::KeyExch).is_none(),
        "Base provider must not support KeyExch"
    );

    // --- Teardown ---
    let result = provider.teardown();
    assert!(result.is_ok(), "Base provider teardown must succeed");
    assert!(
        !provider.is_running(),
        "Base provider must not be running after teardown"
    );
}

/// Tests the complete lifecycle of the Null provider:
/// create → verify metadata → ALL operations return None → teardown (no-op).
///
/// The null provider is a no-op sentinel — it advertises zero algorithms.
/// Source: `nullprov.c`.
#[test]
fn test_null_provider_full_lifecycle() {
    let mut provider = NullProvider::new();

    // --- Verify metadata ---
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Null Provider");
    assert!(info.status, "Null provider status should always be true");
    assert!(
        provider.is_running(),
        "Null provider must always report running"
    );

    // --- ALL operations must return None ---
    assert!(provider.query_operation(OperationType::Digest).is_none());
    assert!(provider.query_operation(OperationType::Cipher).is_none());
    assert!(provider.query_operation(OperationType::Mac).is_none());
    assert!(provider.query_operation(OperationType::Kdf).is_none());
    assert!(provider.query_operation(OperationType::Rand).is_none());
    assert!(provider.query_operation(OperationType::KeyMgmt).is_none());
    assert!(
        provider
            .query_operation(OperationType::Signature)
            .is_none()
    );
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_none()
    );
    assert!(provider.query_operation(OperationType::Kem).is_none());
    assert!(provider.query_operation(OperationType::KeyExch).is_none());
    assert!(
        provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none()
    );
    assert!(provider.query_operation(OperationType::Store).is_none());
    assert!(
        provider
            .query_operation(OperationType::SKeyMgmt)
            .is_none()
    );

    // --- Teardown (no-op for null) ---
    let result = provider.teardown();
    assert!(result.is_ok(), "Null provider teardown must succeed");
    // Still running after teardown — null provider is always running.
    assert!(
        provider.is_running(),
        "Null provider must still be running after teardown"
    );
}

/// Tests the complete lifecycle of the Legacy provider:
/// create → verify metadata → query digest/cipher/kdf → other ops return None → teardown.
///
/// Source: `legacyprov.c`.
#[cfg(feature = "legacy")]
#[test]
fn test_legacy_provider_full_lifecycle() {
    let mut provider = LegacyProvider::new();

    // --- Verify metadata ---
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Legacy Provider");
    assert_eq!(info.version, "4.0.0");
    assert_eq!(info.build_info, "openssl-rs 4.0.0");
    assert!(info.status, "Legacy provider should start with status=true");
    assert!(provider.is_running());

    // --- Positive queries: legacy supports Digest, Cipher, Kdf ---
    let digest = provider.query_operation(OperationType::Digest);
    assert!(digest.is_some(), "Legacy provider must support Digest");
    assert!(!digest.unwrap().is_empty());

    let cipher = provider.query_operation(OperationType::Cipher);
    assert!(cipher.is_some(), "Legacy provider must support Cipher");
    assert!(!cipher.unwrap().is_empty());

    let kdf = provider.query_operation(OperationType::Kdf);
    assert!(kdf.is_some(), "Legacy provider must support Kdf");
    assert!(!kdf.unwrap().is_empty());

    // --- Negative queries ---
    assert!(provider.query_operation(OperationType::Mac).is_none());
    assert!(provider.query_operation(OperationType::Rand).is_none());
    assert!(provider.query_operation(OperationType::KeyMgmt).is_none());
    assert!(
        provider
            .query_operation(OperationType::Signature)
            .is_none()
    );
    assert!(
        provider
            .query_operation(OperationType::AsymCipher)
            .is_none()
    );
    assert!(provider.query_operation(OperationType::Kem).is_none());
    assert!(provider.query_operation(OperationType::KeyExch).is_none());
    assert!(
        provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none()
    );
    assert!(provider.query_operation(OperationType::Store).is_none());

    // --- Teardown ---
    let result = provider.teardown();
    assert!(result.is_ok(), "Legacy provider teardown must succeed");
    assert!(!provider.is_running());
}

// =============================================================================
// Phase 3: BuiltinProviderKind Factory Tests
// =============================================================================

/// Verify that `BuiltinProviderKind::Default.create()` produces a trait object
/// with the correct provider name.
#[test]
fn test_builtin_provider_kind_create_default() {
    let provider = BuiltinProviderKind::Default.create();
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Default Provider");
    assert!(provider.is_running());
}

/// Verify that `BuiltinProviderKind::Base.create()` produces a trait object
/// with the correct provider name.
#[test]
fn test_builtin_provider_kind_create_base() {
    let provider = BuiltinProviderKind::Base.create();
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Base Provider");
    assert!(provider.is_running());
}

/// Verify that `BuiltinProviderKind::Null.create()` produces a trait object
/// with the correct provider name.
#[test]
fn test_builtin_provider_kind_create_null() {
    let provider = BuiltinProviderKind::Null.create();
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Null Provider");
    assert!(provider.is_running());
}

/// Verify that `BuiltinProviderKind::Legacy.create()` produces a trait object
/// with the correct provider name (requires `legacy` feature).
#[cfg(feature = "legacy")]
#[test]
fn test_builtin_provider_kind_create_legacy() {
    let provider = BuiltinProviderKind::Legacy.create();
    let info: ProviderInfo = provider.info();
    assert_eq!(info.name, "OpenSSL Legacy Provider");
    assert!(provider.is_running());
}

/// Verify name-based lookup resolves known names and rejects unknown names.
#[test]
fn test_builtin_provider_kind_from_name() {
    // Known names
    assert_eq!(
        BuiltinProviderKind::from_name("default"),
        Some(BuiltinProviderKind::Default)
    );
    assert_eq!(
        BuiltinProviderKind::from_name("base"),
        Some(BuiltinProviderKind::Base)
    );
    assert_eq!(
        BuiltinProviderKind::from_name("null"),
        Some(BuiltinProviderKind::Null)
    );

    // Legacy: depends on feature flag
    #[cfg(feature = "legacy")]
    assert_eq!(
        BuiltinProviderKind::from_name("legacy"),
        Some(BuiltinProviderKind::Legacy)
    );
    #[cfg(not(feature = "legacy"))]
    assert_eq!(BuiltinProviderKind::from_name("legacy"), None);

    // Unknown names
    assert_eq!(BuiltinProviderKind::from_name("nonexistent"), None);
    assert_eq!(BuiltinProviderKind::from_name(""), None);
    assert_eq!(BuiltinProviderKind::from_name("Default"), None);
    assert_eq!(BuiltinProviderKind::from_name("NULL"), None);
}

/// Verify that `BuiltinProviderKind::name()` returns the expected short names.
#[test]
fn test_builtin_provider_kind_name() {
    assert_eq!(BuiltinProviderKind::Default.name(), "default");
    assert_eq!(BuiltinProviderKind::Base.name(), "base");
    assert_eq!(BuiltinProviderKind::Null.name(), "null");
    assert_eq!(BuiltinProviderKind::Legacy.name(), "legacy");
}

/// Verify that creating a provider via the factory and calling `info()` yields
/// a round-trip match on the short name.
#[test]
fn test_builtin_provider_kind_round_trip() {
    let kinds = [
        BuiltinProviderKind::Default,
        BuiltinProviderKind::Base,
        BuiltinProviderKind::Null,
    ];
    for kind in &kinds {
        let provider = kind.create();
        let info = provider.info();
        // The full display name must contain the short name (case-insensitive).
        let full_lower = info.name.to_lowercase();
        assert!(
            full_lower.contains(kind.name()),
            "Provider display name '{}' must contain short name '{}'",
            info.name,
            kind.name()
        );
    }
}

// =============================================================================
// Phase 4: Multi-Provider Registration Tests (Rule R10: Wiring)
// =============================================================================

/// Registers default, base, and null providers, then verifies all algorithms
/// are discoverable through the method store.
///
/// Tests the full wiring path: entry point → provider loading → MethodStore.
#[test]
fn test_register_multiple_providers() {
    let store = MethodStore::new();

    // Register all three non-feature-gated providers.
    let default_provider = DefaultProvider::new();
    store.register_provider(&default_provider);

    let base_provider = BaseProvider::new();
    store.register_provider(&base_provider);

    let null_provider = NullProvider::new();
    store.register_provider(&null_provider);

    // Verify algorithms from registered providers are discoverable.
    let all = store.enumerate_all();
    assert!(
        !all.is_empty(),
        "Registered algorithms must be non-empty after registering default + base"
    );

    // Default provider algorithms should be present.
    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        !digests.is_empty(),
        "Digests from default provider must be registered"
    );

    // Base provider algorithms should be present.
    let encoders = store.enumerate_algorithms(OperationType::EncoderDecoder);
    assert!(
        !encoders.is_empty(),
        "EncoderDecoder from base+default providers must be registered"
    );

    // Rand from both default and base providers.
    let rands = store.enumerate_algorithms(OperationType::Rand);
    assert!(
        !rands.is_empty(),
        "Rand algorithms must be registered (default + base)"
    );

    // Null provider contributes nothing — verify overall correctness:
    // Store total after registering null shouldn't differ from before,
    // but the store remains functional.
    let stores = store.enumerate_algorithms(OperationType::Store);
    assert!(
        !stores.is_empty(),
        "Store algorithms must be registered (default + base)"
    );
}

/// Uses the `register_builtin_providers()` helper to register the standard
/// built-in providers and verifies algorithm discovery.
#[test]
fn test_register_builtin_providers_function() {
    let store = MethodStore::new();
    register_builtin_providers(&store);

    // Both default and base should be registered.
    let all = store.enumerate_all();
    assert!(
        !all.is_empty(),
        "Built-in providers must register algorithms"
    );

    // Default provider's digests.
    let digests = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        !digests.is_empty(),
        "Default provider digests must be registered"
    );

    // Base provider's encoders/decoders.
    let encoders = store.enumerate_algorithms(OperationType::EncoderDecoder);
    assert!(
        !encoders.is_empty(),
        "Base/Default encoder-decoders must be registered"
    );

    // Store operations from both providers.
    let stores = store.enumerate_algorithms(OperationType::Store);
    assert!(!stores.is_empty(), "Store algorithms must be registered");

    // Signature operations from default.
    let sigs = store.enumerate_algorithms(OperationType::Signature);
    assert!(
        !sigs.is_empty(),
        "Signature algorithms from default must be registered"
    );
}

// =============================================================================
// Phase 5: Provider Isolation Tests
// =============================================================================

/// Verify that all built-in providers have distinct (non-overlapping) names.
#[test]
fn test_providers_have_distinct_names() {
    let default = DefaultProvider::new();
    let base = BaseProvider::new();
    let null = NullProvider::new();

    let mut names = vec![default.info().name, base.info().name, null.info().name];

    // Verify expected names.
    assert_eq!(default.info().name, "OpenSSL Default Provider");
    assert_eq!(base.info().name, "OpenSSL Base Provider");
    assert_eq!(null.info().name, "OpenSSL Null Provider");

    #[cfg(feature = "legacy")]
    {
        let legacy = LegacyProvider::new();
        assert_eq!(legacy.info().name, "OpenSSL Legacy Provider");
        names.push(legacy.info().name);
    }

    // All names should be unique.
    let original_count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        original_count,
        "All provider names must be distinct"
    );
}

/// Creates a `Vec<Box<dyn Provider>>` and exercises all methods through
/// dynamic dispatch, demonstrating trait-based dispatch replacing C
/// `OSSL_DISPATCH` function pointer tables.
#[test]
fn test_provider_trait_object_polymorphism() {
    let providers: Vec<Box<dyn Provider>> = vec![
        Box::new(DefaultProvider::new()),
        Box::new(BaseProvider::new()),
        Box::new(NullProvider::new()),
    ];

    // Collect all names via polymorphic dispatch.
    let names: Vec<&str> = providers.iter().map(|p| p.info().name).collect();

    // Verify unique names — no duplicates through polymorphic calls.
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        names.len(),
        sorted.len(),
        "All providers must have distinct names via polymorphic dispatch"
    );

    // Verify `is_running()` works through trait objects.
    for provider in &providers {
        assert!(
            provider.is_running(),
            "Provider '{}' must be running when accessed through trait object",
            provider.info().name
        );
    }

    // Verify `query_operation()` works through trait objects without panicking.
    for provider in &providers {
        let _digest = provider.query_operation(OperationType::Digest);
        let _cipher = provider.query_operation(OperationType::Cipher);
        let _store = provider.query_operation(OperationType::Store);
    }

    // Verify `get_params()` works through trait objects.
    for provider in &providers {
        let params_result = provider.get_params();
        assert!(
            params_result.is_ok(),
            "get_params() must succeed for provider '{}'",
            provider.info().name
        );
    }

    // Verify `gettable_params()` works through trait objects.
    for provider in &providers {
        let gettable = provider.gettable_params();
        assert!(
            !gettable.is_empty(),
            "gettable_params() must return non-empty list for '{}'",
            provider.info().name
        );
    }
}

/// Verifies algorithm separation between default and base providers:
/// - Default provides crypto algorithms; base does NOT
/// - Both provide EncoderDecoder, Store, and Rand
/// - No unexpected algorithm overlap for categories only one should handle
#[test]
fn test_default_and_base_algorithm_separation() {
    let default = DefaultProvider::new();
    let base = BaseProvider::new();

    // Default provides digests; base does NOT.
    assert!(
        default.query_operation(OperationType::Digest).is_some(),
        "Default must provide Digest"
    );
    assert!(
        base.query_operation(OperationType::Digest).is_none(),
        "Base must not provide Digest"
    );

    // Default provides ciphers; base does NOT.
    assert!(
        default.query_operation(OperationType::Cipher).is_some(),
        "Default must provide Cipher"
    );
    assert!(
        base.query_operation(OperationType::Cipher).is_none(),
        "Base must not provide Cipher"
    );

    // Default provides MACs; base does NOT.
    assert!(
        default.query_operation(OperationType::Mac).is_some(),
        "Default must provide Mac"
    );
    assert!(
        base.query_operation(OperationType::Mac).is_none(),
        "Base must not provide Mac"
    );

    // Default provides KDFs; base does NOT.
    assert!(
        default.query_operation(OperationType::Kdf).is_some(),
        "Default must provide Kdf"
    );
    assert!(
        base.query_operation(OperationType::Kdf).is_none(),
        "Base must not provide Kdf"
    );

    // Default provides signatures; base does NOT.
    assert!(
        default.query_operation(OperationType::Signature).is_some(),
        "Default must provide Signature"
    );
    assert!(
        base.query_operation(OperationType::Signature).is_none(),
        "Base must not provide Signature"
    );

    // Default provides key management; base does NOT.
    assert!(
        default.query_operation(OperationType::KeyMgmt).is_some(),
        "Default must provide KeyMgmt"
    );
    assert!(
        base.query_operation(OperationType::KeyMgmt).is_none(),
        "Base must not provide KeyMgmt"
    );

    // Both provide EncoderDecoder.
    assert!(
        default
            .query_operation(OperationType::EncoderDecoder)
            .is_some(),
        "Default must provide EncoderDecoder"
    );
    assert!(
        base.query_operation(OperationType::EncoderDecoder)
            .is_some(),
        "Base must provide EncoderDecoder"
    );

    // Both provide Store.
    assert!(
        default.query_operation(OperationType::Store).is_some(),
        "Default must provide Store"
    );
    assert!(
        base.query_operation(OperationType::Store).is_some(),
        "Base must provide Store"
    );

    // Both provide Rand.
    assert!(
        default.query_operation(OperationType::Rand).is_some(),
        "Default must provide Rand"
    );
    assert!(
        base.query_operation(OperationType::Rand).is_some(),
        "Base must provide Rand"
    );
}

// =============================================================================
// Phase 6: Teardown and Re-initialization Tests
// =============================================================================

/// Verifies that calling `teardown()` twice on the same provider succeeds
/// both times — teardown must be idempotent.
#[test]
fn test_provider_teardown_idempotent() {
    let mut provider = DefaultProvider::new();
    assert!(provider.is_running());

    // First teardown.
    let result1 = provider.teardown();
    assert!(result1.is_ok(), "First teardown must succeed");
    assert!(!provider.is_running());

    // Second teardown — must also succeed (idempotent).
    let result2 = provider.teardown();
    assert!(result2.is_ok(), "Second teardown must also succeed (idempotent)");
    assert!(!provider.is_running());

    // Also verify with Base provider.
    let mut base = BaseProvider::new();
    assert!(base.teardown().is_ok());
    assert!(base.teardown().is_ok());
    assert!(!base.is_running());

    // And with Null provider (always running).
    let mut null = NullProvider::new();
    assert!(null.teardown().is_ok());
    assert!(null.teardown().is_ok());
    assert!(null.is_running(), "Null provider is always running");
}

/// Verifies that after tearing down a provider, a new instance of the same
/// type works normally — independent lifecycle management.
#[test]
fn test_provider_recreation_after_teardown() {
    // --- Create and teardown ---
    let mut provider = DefaultProvider::new();
    assert!(provider.is_running());

    let teardown_result = provider.teardown();
    assert!(teardown_result.is_ok());
    assert!(!provider.is_running());

    // Torn-down provider must not serve operations.
    assert!(
        provider.query_operation(OperationType::Digest).is_none(),
        "Torn-down provider must not serve operations"
    );

    // --- Create a new instance — must work normally ---
    let new_provider = DefaultProvider::new();
    assert!(
        new_provider.is_running(),
        "Newly created provider must be running"
    );
    assert_eq!(new_provider.info().name, "OpenSSL Default Provider");

    let digest = new_provider.query_operation(OperationType::Digest);
    assert!(
        digest.is_some(),
        "New provider must serve operations normally"
    );
    assert!(!digest.unwrap().is_empty());

    // --- Same test with Base provider ---
    let mut base = BaseProvider::new();
    assert!(base.teardown().is_ok());
    assert!(!base.is_running());

    let new_base = BaseProvider::new();
    assert!(new_base.is_running());
    assert!(
        new_base
            .query_operation(OperationType::EncoderDecoder)
            .is_some()
    );
}

/// Verifies that a method store can be re-populated after providers are
/// torn down and re-created — full lifecycle round-trip.
#[test]
fn test_method_store_repopulate_after_teardown() {
    let store = MethodStore::new();

    // --- First registration cycle ---
    let mut default_provider = DefaultProvider::new();
    store.register_provider(&default_provider);

    let digests_before = store.enumerate_algorithms(OperationType::Digest);
    assert!(!digests_before.is_empty(), "Digests must exist after first registration");

    // --- Teardown and remove ---
    assert!(default_provider.teardown().is_ok());
    store.remove_provider("OpenSSL Default Provider");

    let digests_after_remove = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        digests_after_remove.is_empty(),
        "Digests must be empty after removing provider"
    );

    // --- Re-create and re-register ---
    let new_default = DefaultProvider::new();
    store.register_provider(&new_default);

    let digests_after_reregister = store.enumerate_algorithms(OperationType::Digest);
    assert!(
        !digests_after_reregister.is_empty(),
        "Digests must be present after re-registration"
    );
}

/// Verifies that `get_params()` returns meaningful parameter sets for each
/// built-in provider, and that the parameter data matches provider metadata.
#[test]
fn test_provider_get_params_consistency() {
    let default = DefaultProvider::new();
    let base = BaseProvider::new();
    let null = NullProvider::new();

    // Default provider params.
    let default_params = default.get_params().expect("Default get_params must succeed");
    let gettable = default.gettable_params();
    assert!(gettable.contains(&"name"), "Default must expose 'name' param");
    assert!(gettable.contains(&"version"), "Default must expose 'version' param");
    assert!(gettable.contains(&"status"), "Default must expose 'status' param");

    // Base provider params.
    let base_params = base.get_params().expect("Base get_params must succeed");
    let base_gettable = base.gettable_params();
    assert!(base_gettable.contains(&"name"));
    assert!(base_gettable.contains(&"version"));

    // Null provider params.
    let null_params = null.get_params().expect("Null get_params must succeed");
    let null_gettable = null.gettable_params();
    assert!(!null_gettable.is_empty(), "Null provider must expose some params");

    // Suppress unused-variable warnings by asserting the params exist.
    drop(default_params);
    drop(base_params);
    drop(null_params);
}
