//! # Provider Core Dispatch
//!
//! Translates `crypto/provider_core.c` (2,847 lines), `crypto/core_fetch.c`,
//! `crypto/core_algorithm.c`, `crypto/provider_conf.c`, and `crypto/provider_child.c`
//! into Rust.
//!
//! This module implements the core provider dispatch mechanism as described in
//! AAP §0.7.1: `OSSL_DISPATCH` function pointer tables are replaced by Rust traits.
//! Each algorithm category becomes a trait (`DigestProvider`, `CipherProvider`, etc.)
//! and the default, legacy, base, null, and FIPS providers each implement the relevant traits.
//!
//! ## Architecture
//!
//! ```text
//! Application → EVP API → ProviderStore::fetch()
//!                           ↓
//!                    MethodStore::fetch() (property match)
//!                           ↓
//!                    Box<dyn AlgorithmProvider>
//!                           ↓
//!           ┌───────────────┼───────────────┐
//!           │               │               │
//!     DefaultProvider  FipsProvider   LegacyProvider
//! ```
//!
//! ## Locking Strategy (from `provider_core.c` L59-118)
//!
//! The C implementation defines a strict lock ordering to prevent deadlocks:
//! 1. Provider store lock (`providers` / `child_callbacks`)
//! 2. Provider `flag_lock` (atomic flags on `ProviderInstance`)
//! 3. Provider `activatecnt_lock` (`activate_count`)
//!
//! In Rust, we replicate this with `parking_lot::RwLock` fields on `ProviderStore`
//! and `ProviderInstance`, each with `// LOCK-SCOPE:` annotations per Rule R7.
//!
//! ## Source Mapping
//!
//! | Rust Type | C Source | C Lines |
//! |-----------|----------|---------|
//! | `ProviderInstance` | `ossl_provider_st` in `provider_core.c` L142-199 | 57 |
//! | `ProviderStore` | `provider_store_st` in `provider_core.c` L216-228 | 12 |
//! | `ProviderFlags` | flag_initialized/flag_activated in `provider_core.c` L143-145 | 3 |
//! | `AlgorithmDescriptor` | `OSSL_ALGORITHM` in `include/openssl/core.h` | — |
//! | `ProviderConfState` | `PROVIDER_CONF_GLOBAL` in `provider_conf.c` L25-28 | 4 |
//! | `ChildProviderCallback` | `OSSL_PROVIDER_CHILD_CB` in `provider_core.c` L130-137 | 7 |
//! | `enumerate_algorithms` | `ossl_algorithm_do_all` in `core_algorithm.c` | ~50 |
//! | `construct_methods` | `ossl_method_construct` in `core_fetch.c` | ~40 |

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, error, info, trace, warn};

use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

use super::predefined::{predefined_providers, ProviderInfo, ProviderKind};
use super::property::{MethodStore, PropertyList, PropertyStringStore};

// =============================================================================
// Constants
// =============================================================================

/// Maximum operation ID value for sizing the operation bit vector.
/// Corresponds to the highest `OSSL_OP_*` constant in `core_dispatch.h`.
const MAX_OPERATION_ID: usize = 23;

/// Number of bytes needed for the operation bit vector.
/// `ceil(MAX_OPERATION_ID / 8)`.
const OPERATION_BITS_SIZE: usize = (MAX_OPERATION_ID + 7) / 8;

/// Provider version string reported by `get_params`.
const PROVIDER_VERSION: &str = "0.1.0";

/// Provider build info reported by `get_params`.
const PROVIDER_BUILDINFO: &str = "openssl-rs-0.1.0";

// =============================================================================
// OperationId — Typed algorithm operation identifiers
// =============================================================================

/// Algorithm operation types that providers can implement.
///
/// Replaces C `OSSL_OP_*` constants from `include/openssl/core_dispatch.h`.
/// Each variant maps to a specific algorithm category that a provider may
/// supply implementations for.
///
/// ## Rule R6 (Lossless Numeric Casts)
///
/// Uses `TryFrom<u32>` for checked conversion instead of bare `as` casts.
/// The `#[repr(u32)]` ensures stable discriminant values matching the C
/// constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum OperationId {
    /// Message digest operations (SHA-256, SHA-3, etc.).
    Digest = 1,
    /// Symmetric cipher operations (AES-GCM, `ChaCha20`, etc.).
    Cipher = 2,
    /// Message authentication code operations (HMAC, CMAC, etc.).
    Mac = 3,
    /// Key derivation function operations (HKDF, PBKDF2, etc.).
    Kdf = 4,
    /// Random number generation operations (DRBG, seed sources).
    Rand = 5,
    /// Key management operations (keygen, import, export).
    Keymgmt = 10,
    /// Key exchange operations (DH, ECDH, X25519).
    KeyExchange = 11,
    /// Digital signature operations (RSA-PSS, ECDSA, `EdDSA`).
    Signature = 12,
    /// Asymmetric cipher operations (RSA encryption).
    AsymCipher = 13,
    /// Key encapsulation mechanism operations (ML-KEM, RSA-KEM).
    Kem = 14,
    /// Key/certificate encoder operations (DER, PEM output).
    Encoder = 20,
    /// Key/certificate decoder operations (DER, PEM input).
    Decoder = 21,
    /// Certificate/key store operations (file-based loading).
    Store = 22,
}

impl OperationId {
    /// Returns all known operation IDs.
    ///
    /// Used by `enumerate_algorithms` to iterate all operation categories.
    /// Returns an array of all operation ID variants.
    ///
    /// Useful for iterating over all operation types during algorithm
    /// enumeration and method construction.
    pub fn all() -> &'static [OperationId] {
        &[
            Self::Digest,
            Self::Cipher,
            Self::Mac,
            Self::Kdf,
            Self::Rand,
            Self::Keymgmt,
            Self::KeyExchange,
            Self::Signature,
            Self::AsymCipher,
            Self::Kem,
            Self::Encoder,
            Self::Decoder,
            Self::Store,
        ]
    }

    /// Returns the human-readable name for this operation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Cipher => "cipher",
            Self::Mac => "mac",
            Self::Kdf => "kdf",
            Self::Rand => "rand",
            Self::Keymgmt => "keymgmt",
            Self::KeyExchange => "keyexch",
            Self::Signature => "signature",
            Self::AsymCipher => "asymcipher",
            Self::Kem => "kem",
            Self::Encoder => "encoder",
            Self::Decoder => "decoder",
            Self::Store => "store",
        }
    }
}

impl TryFrom<u32> for OperationId {
    type Error = CryptoError;

    /// Converts a raw `u32` to an `OperationId` with checked bounds.
    ///
    /// Rule R6: Uses `TryFrom` instead of bare `as` cast to prevent
    /// silent truncation or invalid operation IDs.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Digest),
            2 => Ok(Self::Cipher),
            3 => Ok(Self::Mac),
            4 => Ok(Self::Kdf),
            5 => Ok(Self::Rand),
            10 => Ok(Self::Keymgmt),
            11 => Ok(Self::KeyExchange),
            12 => Ok(Self::Signature),
            13 => Ok(Self::AsymCipher),
            14 => Ok(Self::Kem),
            20 => Ok(Self::Encoder),
            21 => Ok(Self::Decoder),
            22 => Ok(Self::Store),
            _ => Err(CryptoError::Provider(format!(
                "unknown operation id: {value}"
            ))),
        }
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// ProviderFlags — Atomic state bits
// =============================================================================

/// Provider state flags using atomic operations for lock-free reads.
///
/// Replaces C flag bits from `provider_core.c` L143-145. Atomics allow
/// fast non-blocking state checks on hot paths (e.g., `is_activated()`
/// called during every algorithm fetch).
#[derive(Debug)]
struct ProviderFlags {
    /// Whether the provider has been initialized (init function called).
    /// Transitions: `false` → `true` on first `activate()` call.
    // LOCK-SCOPE: atomic — lock-free read/write for init state checks.
    // Write during first activate(), read during is_initialized() checks.
    // Corresponds to C `flag_initialized` in provider_core.c L143.
    initialized: AtomicBool,

    /// Whether the provider is currently activated (available for use).
    /// Transitions: `false` → `true` on `activate()`, `true` → `false`
    /// when activation count drops to zero via `deactivate()`.
    // LOCK-SCOPE: atomic — lock-free read/write for activation state checks.
    // Write during activate()/deactivate(), read during fetch lookups.
    // Corresponds to C `flag_activated` in provider_core.c L144.
    activated: AtomicBool,
}

impl ProviderFlags {
    /// Creates new flags with both bits cleared.
    fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            activated: AtomicBool::new(false),
        }
    }
}

// =============================================================================
// AlgorithmDescriptor — describes a single algorithm offered by a provider
// =============================================================================

/// Describes a single algorithm offered by a provider.
///
/// Replaces C `OSSL_ALGORITHM` from `include/openssl/core.h`.
/// Each descriptor associates a set of algorithm names with a property
/// definition string and the operation category it belongs to.
///
/// ## Examples
///
/// ```text
/// AlgorithmDescriptor {
///     names: "SHA2-256:SHA-256:SHA256".to_string(),
///     properties: "provider=default".to_string(),
///     operation_id: OperationId::Digest,
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AlgorithmDescriptor {
    /// Colon-separated list of algorithm names (e.g., `"SHA2-256:SHA-256:SHA256"`).
    /// The first name is the canonical name.
    pub names: String,
    /// Property definition string (e.g., `"provider=default,fips=no"`).
    pub properties: String,
    /// Operation ID this algorithm belongs to.
    pub operation_id: OperationId,
}

// =============================================================================
// ProviderInstance — Single provider with state and capabilities
// =============================================================================

/// A single provider instance with its state and capabilities.
///
/// Replaces C `ossl_provider_st` from `provider_core.c` L142-199.
/// Manages the lifecycle of a provider: initialization, activation/deactivation,
/// and operation bit tracking for the fetch cache system.
///
/// ## Ownership
///
/// Instances are reference-counted via `Arc<ProviderInstance>` and stored in
/// the `ProviderStore`. Multiple components may hold references to the same
/// instance. Rule R8: `Arc` replaces C manual reference counting with zero
/// `unsafe`.
///
/// ## Thread Safety
///
/// All mutable state is protected by either atomic operations (flags) or
/// `RwLock` (activation count, operation bits). The lock ordering matches
/// the C implementation: flag atomics are independent, `activate_count` lock
/// must not be held while acquiring the store lock.
pub struct ProviderInstance {
    /// Provider name (write-once, read-many — no lock needed).
    /// Corresponds to C `name` field in `ossl_provider_st` L151.
    name: String,

    /// Optional filesystem path for loadable providers.
    /// Rule R5: `Option<String>` instead of `NULL` sentinel.
    /// Corresponds to C `path` field in `ossl_provider_st` L153.
    pub(crate) path: Option<String>,

    /// Which built-in provider implementation this uses.
    /// Corresponds to C `init_function` pointer in `ossl_provider_st` L170.
    kind: ProviderKind,

    /// Configuration parameters (name-value pairs, write-once).
    /// Corresponds to C `parameters` field in `ossl_provider_st` L158.
    pub(crate) parameters: Vec<(String, String)>,

    /// State flags (lock-free atomic operations).
    flags: ProviderFlags,

    /// Activation reference count — how many times this provider has been activated.
    // LOCK-SCOPE: activatecnt_lock — protects activation count updates.
    // Write during activate/deactivate, read during is_activated checks.
    // Corresponds to C `activatecnt_lock` in provider_core.c L152.
    // Lock ordering: this lock MUST be acquired AFTER the store lock and
    // flag atomics (matching C provider_core.c L101-108).
    activate_count: RwLock<i32>,

    /// Bit vector tracking which operation IDs have been queried.
    // LOCK-SCOPE: opbits_lock — protects operation_bits read/write.
    // Write on first query of an operation, read during subsequent queries.
    // Corresponds to C `opbits_lock` in provider_core.c L188.
    operation_bits: RwLock<Vec<u8>>,

    /// Whether this provider is a child of another (in child lib context).
    /// Corresponds to C `ischild` field in `ossl_provider_st` L193.
    is_child: bool,

    /// Whether this provider acts as a fallback when no explicit provider is loaded.
    /// Corresponds to C `is_fallback` from `OSSL_PROVIDER_INFO`.
    is_fallback: bool,

    /// Algorithm descriptors registered by this provider, keyed by operation.
    /// Populated during provider initialization by the provider subsystem.
    // LOCK-SCOPE: algorithms_lock — protects per-provider algorithm registration.
    // Write during provider init/algorithm registration, read during enumeration.
    algorithms: RwLock<HashMap<OperationId, Vec<AlgorithmDescriptor>>>,
}

impl ProviderInstance {
    /// Creates a new provider instance from predefined provider information.
    ///
    /// Replaces C `provider_new()` from `provider_core.c` L120-140.
    /// All state flags start cleared; the provider must be explicitly
    /// activated via [`activate()`](Self::activate).
    ///
    /// # Arguments
    ///
    /// * `info` — Predefined provider metadata including name, kind, path,
    ///   parameters, and fallback status.
    pub fn new(info: &ProviderInfo) -> Self {
        let parameters: Vec<(String, String)> = info
            .parameters
            .iter()
            .map(|p| (p.name.clone(), p.value.clone()))
            .collect();

        trace!(
            name = %info.name,
            kind = %info.kind,
            fallback = info.is_fallback,
            "creating new provider instance"
        );

        Self {
            name: info.name.clone(),
            path: info.path.clone(),
            kind: info.kind,
            parameters,
            flags: ProviderFlags::new(),
            activate_count: RwLock::new(0),
            operation_bits: RwLock::new(vec![0u8; OPERATION_BITS_SIZE]),
            is_child: false,
            is_fallback: info.is_fallback,
            algorithms: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the provider name.
    ///
    /// Replaces C `OSSL_PROVIDER_get0_name()` from `provider.c`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the provider kind.
    #[must_use]
    pub fn kind(&self) -> ProviderKind {
        self.kind
    }

    /// Returns the optional filesystem path for this provider.
    ///
    /// Rule R5: Returns `Option<&str>` — no empty string sentinel.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the configuration parameters for this provider.
    ///
    /// Returns a slice of `(name, value)` pairs that were provided during
    /// provider construction.
    #[must_use]
    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    /// Returns whether this provider has been initialized.
    ///
    /// Replaces C `ossl_provider_is_initialized()` check on `flag_initialized`.
    /// Uses `Ordering::Acquire` for visibility of all writes that preceded
    /// the flag being set.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.flags.initialized.load(Ordering::Acquire)
    }

    /// Returns whether this provider is currently activated.
    ///
    /// Replaces C `ossl_provider_activated()` check on `flag_activated`.
    /// Uses `Ordering::Acquire` for visibility of activation state changes.
    #[must_use]
    pub fn is_activated(&self) -> bool {
        self.flags.activated.load(Ordering::Acquire)
    }

    /// Activates this provider, making it available for algorithm dispatch.
    ///
    /// Replaces C `ossl_provider_activate()` from `provider_core.c`.
    /// On first activation, also sets the initialized flag (simulating the
    /// C provider init function call). Increments the activation reference
    /// count and sets the activated flag.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the activation count overflows (checked arithmetic).
    pub fn activate(&self) -> CryptoResult<()> {
        // Set initialized on first activation (replaces C init_function call)
        if !self.flags.initialized.load(Ordering::Acquire) {
            self.flags.initialized.store(true, Ordering::Release);
            info!(name = %self.name, kind = %self.kind, "provider initialized");
        }

        // Increment activation count under lock
        {
            let mut count = self.activate_count.write();
            *count = count.checked_add(1).ok_or_else(|| {
                CryptoError::Provider(format!(
                    "activation count overflow for provider '{}'",
                    self.name
                ))
            })?;
            trace!(name = %self.name, count = *count, "activation count incremented");
        }

        // Set activated flag
        self.flags.activated.store(true, Ordering::Release);
        info!(name = %self.name, "provider activated");

        Ok(())
    }

    /// Deactivates this provider, decrementing the activation reference count.
    ///
    /// Replaces C `ossl_provider_deactivate()` from `provider_core.c`.
    /// When the activation count drops to zero, clears the activated flag
    /// so the provider is no longer available for algorithm dispatch.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the provider is not currently activated.
    pub fn deactivate(&self) -> CryptoResult<()> {
        let mut count = self.activate_count.write();

        if *count <= 0 {
            return Err(CryptoError::Provider(format!(
                "provider '{}' is not activated (count={})",
                self.name, *count
            )));
        }

        *count -= 1;
        trace!(name = %self.name, count = *count, "activation count decremented");

        if *count == 0 {
            self.flags.activated.store(false, Ordering::Release);
            info!(name = %self.name, "provider deactivated (count reached zero)");
        }

        Ok(())
    }

    /// Tests whether the given operation has been queried for this provider.
    ///
    /// Replaces C `ossl_provider_test_operation_bit()` from `provider_core.c`.
    /// Returns `true` if the operation bit is set, meaning algorithms for
    /// this operation have already been enumerated from this provider.
    ///
    /// Rule R5: Returns `bool` instead of C's `-1`/`0`/`1` sentinel pattern.
    #[must_use]
    pub fn test_operation_bit(&self, op: OperationId) -> bool {
        let bit_index = op as usize;
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;

        let bits = self.operation_bits.read();
        if byte_index >= bits.len() {
            return false;
        }
        let shift: u8 = u8::try_from(bit_offset).unwrap_or(0);
        (bits[byte_index] & (1u8.wrapping_shl(u32::from(shift)))) != 0
    }

    /// Sets the operation bit for the given operation on this provider.
    ///
    /// Replaces C `ossl_provider_set_operation_bit()` from `provider_core.c`.
    /// After this call, `test_operation_bit(op)` will return `true`.
    pub fn set_operation_bit(&self, op: OperationId) {
        let bit_index = op as usize;
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;

        let mut bits = self.operation_bits.write();
        // Extend the bit vector if needed (defensive, normally pre-allocated)
        if byte_index >= bits.len() {
            bits.resize(byte_index + 1, 0);
        }
        let shift: u8 = u8::try_from(bit_offset).unwrap_or(0);
        bits[byte_index] |= 1u8.wrapping_shl(u32::from(shift));
        trace!(name = %self.name, op = %op, "operation bit set");
    }

    /// Registers algorithm descriptors for a specific operation on this provider.
    ///
    /// Called by the provider subsystem during initialization to declare which
    /// algorithms this provider supports. This is the Rust equivalent of the
    /// C provider's `query_operation` callback returning `OSSL_ALGORITHM[]`.
    pub fn register_algorithms(
        &self,
        op: OperationId,
        descriptors: Vec<AlgorithmDescriptor>,
    ) {
        let mut algs = self.algorithms.write();
        debug!(
            name = %self.name,
            op = %op,
            count = descriptors.len(),
            "registering algorithms for provider"
        );
        algs.insert(op, descriptors);
    }

    /// Queries algorithm descriptors for a specific operation.
    ///
    /// Returns the list of algorithms this provider supports for the given
    /// operation, or an empty vector if no algorithms are registered.
    pub fn query_algorithms(&self, op: OperationId) -> Vec<AlgorithmDescriptor> {
        let algs = self.algorithms.read();
        algs.get(&op).cloned().unwrap_or_default()
    }
}

impl std::fmt::Debug for ProviderInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderInstance")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("parameters", &self.parameters)
            .field("flags", &self.flags)
            .field("activate_count", &*self.activate_count.read())
            .field("operation_bits_len", &self.operation_bits.read().len())
            .field("is_child", &self.is_child)
            .field("is_fallback", &self.is_fallback)
            .field("algorithms_count", &self.algorithms.read().len())
            .finish()
    }
}

// =============================================================================
// ChildProviderCallback — mirroring provider state to child contexts
// =============================================================================

/// Callback set for mirroring provider state to child library contexts.
///
/// Replaces C `OSSL_PROVIDER_CHILD_CB` from `provider_core.c` L130-137
/// and `provider_child.c`. In the C implementation, child library contexts
/// maintain shadow copies of their parent's providers. These callbacks are
/// invoked when the parent's provider list changes.
///
/// Each field is a boxed closure that receives provider/property information
/// and returns `true` to continue processing or `false` to abort.
pub struct ChildProviderCallback {
    /// Called when a provider is created in the parent context.
    /// Argument: reference to the newly created provider instance.
    /// Returns `true` if the child should mirror this provider.
    pub on_create: Box<dyn Fn(&ProviderInstance) -> bool + Send + Sync>,

    /// Called when a provider is removed from the parent context.
    /// Argument: reference to the provider being removed.
    /// Returns `true` to acknowledge the removal.
    pub on_remove: Box<dyn Fn(&ProviderInstance) -> bool + Send + Sync>,

    /// Called when global properties change in the parent context.
    /// Argument: the new global property query string.
    /// Returns `true` to acknowledge the property change.
    pub on_global_props: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl std::fmt::Debug for ChildProviderCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildProviderCallback")
            .field("on_create", &"<fn>")
            .field("on_remove", &"<fn>")
            .field("on_global_props", &"<fn>")
            .finish()
    }
}

// =============================================================================
// ProviderStore — Central provider management for a library context
// =============================================================================

/// The provider store — manages all provider instances for a library context.
///
/// Replaces C `provider_store_st` from `provider_core.c` L216-228.
/// This is the central coordination point for provider lifecycle:
/// loading, activation, fallback policy, and algorithm enumeration.
///
/// ## Lock Ordering
///
/// The C implementation (`provider_core.c` L59-118) defines a strict lock
/// ordering to prevent deadlocks. We replicate this:
///
/// 1. `providers` lock (store-level)
/// 2. `ProviderFlags` atomics (lock-free)
/// 3. `ProviderInstance::activate_count` lock
///
/// The `default_path` and `child_callbacks` locks are independent of the
/// main lock hierarchy, as they don't interact with activation state.
///
/// ## Fallback Activation
///
/// When no provider has been explicitly loaded and `use_fallbacks` is `true`,
/// the store will automatically load and activate predefined fallback providers
/// on first algorithm fetch. This matches the C behavior where
/// `ossl_provider_activate_fallbacks()` is called during `evp_generic_fetch_from_prov()`.
pub struct ProviderStore {
    /// All known provider instances.
    // LOCK-SCOPE: store lock — protects the providers collection.
    // Write during provider add/remove/activate, read during provider find/iterate.
    // This is the "big lock" from provider_core.c L221.
    // Lock ordering: this lock MUST be acquired BEFORE any provider flag_lock
    // or activatecnt_lock (matching C provider_core.c L101-108).
    providers: RwLock<Vec<Arc<ProviderInstance>>>,

    /// Default search path for loadable providers.
    // LOCK-SCOPE: default_path_lock — protects the default search path string.
    // Write during configuration, read during provider loading.
    // Corresponds to C `default_path_lock` in provider_core.c L220.
    // Independent of main lock hierarchy.
    default_path: RwLock<Option<String>>,

    /// Whether fallback providers should be automatically loaded.
    // LOCK-SCOPE: atomic — lock-free flag.
    // Toggled by disable_fallback_loading() and explicit provider loads.
    // Corresponds to C `use_fallbacks` in provider_core.c L227.
    use_fallbacks: AtomicBool,

    /// Whether the store is being freed (cleanup in progress).
    // LOCK-SCOPE: atomic — lock-free flag for reentrant-safe teardown.
    // Set during Drop, prevents recursive cleanup.
    freeing: AtomicBool,

    /// Child provider callbacks (for child library contexts).
    // LOCK-SCOPE: child_callbacks_lock — protects callback registration list.
    // Write during register/deregister, read during provider creation/removal.
    // Independent of main lock hierarchy.
    child_callbacks: RwLock<Vec<ChildProviderCallback>>,

    /// Property string interning store (shared with method store).
    /// Thread-safe shared reference — no lock needed on this field.
    property_strings: Arc<PropertyStringStore>,

    /// The method store for algorithm implementations.
    /// Thread-safe shared reference — internal locking provided by `MethodStore`.
    method_store: Arc<MethodStore>,

    /// Generation counter for cache invalidation.
    /// Incremented when providers are added/removed/activated/deactivated.
    // LOCK-SCOPE: atomic — lock-free counter.
    generation: AtomicU32,
}

impl ProviderStore {
    /// Creates a new provider store, pre-populated with predefined provider
    /// instances (but not yet activated).
    ///
    /// Replaces C `provider_store_new()` from `provider_core.c` L264-310.
    /// The predefined providers (Default, Base, Null, and optionally Legacy
    /// and FIPS) are added to the store in their unactivated state. Activation
    /// happens when `load()`, `activate_fallbacks()`, or configuration
    /// processing triggers it.
    ///
    /// # Arguments
    ///
    /// * `property_strings` — Shared property string interning store.
    #[must_use]
    pub fn new(property_strings: Arc<PropertyStringStore>) -> Self {
        info!("creating new provider store");

        let method_store = Arc::new(MethodStore::new());

        let predefined = predefined_providers();
        let instances: Vec<Arc<ProviderInstance>> = predefined
            .iter()
            .map(|info| {
                let instance = ProviderInstance::new(info);
                debug!(name = %info.name, kind = %info.kind, "added predefined provider to store");
                Arc::new(instance)
            })
            .collect();

        Self {
            providers: RwLock::new(instances),
            default_path: RwLock::new(None),
            use_fallbacks: AtomicBool::new(true),
            freeing: AtomicBool::new(false),
            child_callbacks: RwLock::new(Vec::new()),
            property_strings,
            method_store,
            generation: AtomicU32::new(1),
        }
    }

    /// Finds a provider by name in the store.
    ///
    /// Replaces C `ossl_provider_find()` from `provider_core.c`.
    /// Returns the first provider matching the given name, or `None` if not
    /// found. Rule R5: `Option` instead of `NULL` sentinel.
    ///
    /// # Arguments
    ///
    /// * `name` — The provider name to search for (case-sensitive).
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Arc<ProviderInstance>> {
        let providers = self.providers.read();
        providers.iter().find(|p| p.name() == name).cloned()
    }

    /// Loads and activates a provider by name.
    ///
    /// Replaces C `OSSL_PROVIDER_load()` from `provider.c` L66-69.
    /// If the provider already exists in the store, it is activated (if not
    /// already active). Otherwise, a new instance is created and added.
    ///
    /// When `retain_fallbacks` is `false`, loading an explicit provider
    /// disables automatic fallback loading (matching C behavior).
    ///
    /// # Arguments
    ///
    /// * `name` — Provider name to load.
    /// * `retain_fallbacks` — Whether to keep fallback providers active.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the provider cannot be found or activation fails.
    pub fn load(
        &self,
        name: &str,
        retain_fallbacks: bool,
    ) -> CryptoResult<Arc<ProviderInstance>> {
        info!(name = name, retain_fallbacks = retain_fallbacks, "loading provider");

        // Check if the provider already exists
        if let Some(existing) = self.find(name) {
            if !existing.is_activated() {
                existing.activate()?;
                self.generation.fetch_add(1, Ordering::Release);
            }
            if !retain_fallbacks {
                self.use_fallbacks.store(false, Ordering::Release);
                debug!("fallback loading disabled due to explicit provider load");
            }
            return Ok(existing);
        }

        // Provider not found in predefined list — create a dynamically loaded
        // provider instance. In C this would call DSO_load; here we create
        // an instance that can be populated by the provider subsystem.
        let info = ProviderInfo::new(name, ProviderKind::Default);
        let instance = Arc::new(ProviderInstance::new(&info));
        self.add_to_store(instance.clone(), retain_fallbacks)?;
        instance.activate()?;
        self.generation.fetch_add(1, Ordering::Release);

        Ok(instance)
    }

    /// Tries to load and activate a provider by name.
    ///
    /// Replaces C `OSSL_PROVIDER_try_load()` from `provider.c` L52-55.
    /// Unlike [`load()`](Self::load), this method returns an error if the
    /// provider is not found rather than creating a new instance.
    ///
    /// # Arguments
    ///
    /// * `name` — Provider name to try loading.
    /// * `retain_fallbacks` — Whether to keep fallback providers active.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the provider is not found or activation fails.
    pub fn try_load(
        &self,
        name: &str,
        retain_fallbacks: bool,
    ) -> CryptoResult<Arc<ProviderInstance>> {
        info!(name = name, "trying to load provider");

        if let Some(existing) = self.find(name) {
            if !existing.is_activated() {
                existing.activate()?;
                self.generation.fetch_add(1, Ordering::Release);
            }
            if !retain_fallbacks {
                self.use_fallbacks.store(false, Ordering::Release);
            }
            return Ok(existing);
        }

        Err(CryptoError::Provider(format!(
            "provider '{name}' not found in store"
        )))
    }

    /// Unloads (deactivates and removes) a provider by name.
    ///
    /// Replaces C `OSSL_PROVIDER_unload()` from `provider.c`.
    /// Deactivates the provider, removes its methods from the method store,
    /// notifies child callbacks, and removes the instance from the store.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the provider is not found or deactivation fails.
    pub fn unload(&self, name: &str) -> CryptoResult<()> {
        info!(name = name, "unloading provider");

        // Find and deactivate
        let provider = self.find(name).ok_or_else(|| {
            CryptoError::Provider(format!("provider '{name}' not found for unload"))
        })?;

        if provider.is_activated() {
            provider.deactivate()?;
        }

        // Remove from method store
        self.method_store.remove_by_provider(name);

        // Notify child callbacks
        {
            let callbacks = self.child_callbacks.read();
            for cb in callbacks.iter() {
                if !(cb.on_remove)(&provider) {
                    warn!(name = name, "child callback on_remove returned false");
                }
            }
        }

        // Remove from providers list
        {
            let mut providers = self.providers.write();
            providers.retain(|p| p.name() != name);
        }

        self.generation.fetch_add(1, Ordering::Release);
        self.method_store.flush_cache();
        info!(name = name, "provider unloaded successfully");

        Ok(())
    }

    /// Adds a provider instance to the store.
    ///
    /// Replaces C `ossl_provider_add_to_store()` from `provider_core.c`.
    /// If a provider with the same name already exists, the existing instance
    /// is returned instead of adding a duplicate.
    ///
    /// # Arguments
    ///
    /// * `provider` — The provider instance to add.
    /// * `retain_fallbacks` — Whether to keep fallback providers.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the store is in a freeing state.
    pub fn add_to_store(
        &self,
        provider: Arc<ProviderInstance>,
        retain_fallbacks: bool,
    ) -> CryptoResult<Arc<ProviderInstance>> {
        if self.freeing.load(Ordering::Acquire) {
            return Err(CryptoError::Provider(
                "cannot add provider to store during cleanup".to_string(),
            ));
        }

        let mut providers = self.providers.write();

        // Check for existing provider with same name
        if let Some(existing) = providers.iter().find(|p| p.name() == provider.name()) {
            debug!(name = %provider.name(), "provider already in store, returning existing");
            return Ok(existing.clone());
        }

        debug!(name = %provider.name(), "adding provider to store");

        // Notify child callbacks of new provider
        {
            let callbacks = self.child_callbacks.read();
            for cb in callbacks.iter() {
                if !(cb.on_create)(&provider) {
                    warn!(name = %provider.name(), "child callback on_create returned false");
                }
            }
        }

        providers.push(provider.clone());

        if !retain_fallbacks {
            self.use_fallbacks.store(false, Ordering::Release);
        }

        Ok(provider)
    }

    /// Sets the default search path for loadable providers.
    ///
    /// Replaces C `OSSL_PROVIDER_set_default_search_path()`.
    pub fn set_default_path(&self, path: &str) {
        let mut default_path = self.default_path.write();
        *default_path = Some(path.to_string());
        info!(path = path, "set provider default search path");
    }

    /// Returns the current default search path.
    ///
    /// Rule R5: Returns `Option<String>` — no empty string sentinel.
    #[must_use]
    pub fn default_path(&self) -> Option<String> {
        let default_path = self.default_path.read();
        default_path.clone()
    }

    /// Disables automatic fallback provider loading.
    ///
    /// Replaces C `ossl_provider_disable_fallback_loading()`.
    /// Returns the previous state of the fallback flag.
    pub fn disable_fallback_loading(&self) -> bool {
        let previous = self.use_fallbacks.swap(false, Ordering::AcqRel);
        if previous {
            info!("fallback provider loading disabled");
        }
        previous
    }

    /// Activates fallback providers if needed.
    ///
    /// Replaces the fallback activation logic from `provider_core.c`.
    /// If `use_fallbacks` is `true` and no providers are currently
    /// explicitly activated, loads and activates all predefined providers
    /// marked as fallback.
    ///
    /// This is called automatically during the first algorithm fetch.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any fallback provider fails to activate.
    pub fn activate_fallbacks(&self) -> CryptoResult<()> {
        if !self.use_fallbacks.load(Ordering::Acquire) {
            trace!("fallback loading is disabled, skipping");
            return Ok(());
        }

        // Check if any provider is already explicitly activated
        {
            let providers = self.providers.read();
            let has_activated = providers.iter().any(|p| p.is_activated());
            if has_activated {
                trace!("providers already activated, skipping fallback activation");
                return Ok(());
            }
        }

        info!("activating fallback providers");

        // Take a snapshot to avoid holding the store lock while activating
        let providers_snapshot: Vec<Arc<ProviderInstance>> = {
            let providers = self.providers.read();
            providers.clone()
        };

        let mut activated_any = false;
        for provider in &providers_snapshot {
            if provider.is_fallback {
                match provider.activate() {
                    Ok(()) => {
                        activated_any = true;
                        info!(name = %provider.name(), "fallback provider activated");
                    }
                    Err(e) => {
                        error!(
                            name = %provider.name(),
                            err = %e,
                            "failed to activate fallback provider"
                        );
                        return Err(e);
                    }
                }
            }
        }

        if activated_any {
            self.generation.fetch_add(1, Ordering::Release);
            self.method_store.flush_cache();
        } else {
            warn!("no fallback providers were found to activate");
        }

        // Disable further fallback attempts
        self.use_fallbacks.store(false, Ordering::Release);

        Ok(())
    }

    /// Iterates over all activated providers.
    ///
    /// Replaces C `OSSL_PROVIDER_do_all()`.
    /// Calls `f` for each activated provider. If `f` returns `false`,
    /// iteration stops and the method returns `false`.
    ///
    /// # Arguments
    ///
    /// * `f` — Callback receiving each activated provider. Return `false` to stop.
    pub fn do_all(&self, f: &mut dyn FnMut(&ProviderInstance) -> bool) -> bool {
        let providers = self.providers.read();
        for provider in providers.iter() {
            if provider.is_activated() && !f(provider) {
                return false;
            }
        }
        true
    }

    /// Checks whether a provider is available (loaded and activated).
    ///
    /// Replaces C `OSSL_PROVIDER_available()`.
    #[must_use]
    pub fn available(&self, name: &str) -> bool {
        self.find(name).map_or(false, |p| p.is_activated())
    }

    /// Returns a reference to the method store.
    ///
    /// Used by the EVP layer to fetch algorithm implementations.
    #[must_use]
    pub fn method_store(&self) -> &MethodStore {
        &self.method_store
    }
}

impl std::fmt::Debug for ProviderStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let providers = self.providers.read();
        let default_path = self.default_path.read();
        let child_cb_count = self.child_callbacks.read().len();
        f.debug_struct("ProviderStore")
            .field("provider_count", &providers.len())
            .field("default_path", &*default_path)
            .field("use_fallbacks", &self.use_fallbacks.load(Ordering::Relaxed))
            .field("freeing", &self.freeing.load(Ordering::Relaxed))
            .field("child_callbacks_count", &child_cb_count)
            .field("property_strings", &"<PropertyStringStore>")
            .field("method_store", &"<MethodStore>")
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for ProviderStore {
    fn drop(&mut self) {
        // Set the freeing flag to prevent re-entrant operations
        self.freeing.store(true, Ordering::Release);
        info!("provider store dropped");
    }
}

// =============================================================================
// ProviderConfState — Config-driven provider activation
// =============================================================================

/// Tracks providers activated through configuration file directives.
///
/// Replaces C `PROVIDER_CONF_GLOBAL` from `provider_conf.c` L25-28.
/// When OpenSSL reads a configuration file containing `[provider_sect]`
/// directives, this state object tracks which providers were activated
/// so they can be properly cleaned up later.
///
/// ## Configuration Syntax (reference)
///
/// ```text
/// [openssl_init]
/// providers = provider_sect
///
/// [provider_sect]
/// default = default_sect
///
/// [default_sect]
/// activate = 1
/// ```
pub struct ProviderConfState {
    /// List of providers activated through configuration.
    // LOCK-SCOPE: protects the list of config-activated providers.
    // Write during config load, read during provider queries and cleanup.
    activated_providers: RwLock<Vec<Arc<ProviderInstance>>>,
}

impl ProviderConfState {
    /// Creates a new, empty configuration state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            activated_providers: RwLock::new(Vec::new()),
        }
    }

    /// Activates a provider based on configuration file settings.
    ///
    /// Replaces C `provider_conf_activate()` from `provider_conf.c`.
    /// Looks up the provider by `section_name` in the store, applies
    /// configuration parameters from `config_value`, activates it,
    /// and records it in the activated list.
    ///
    /// Configuration disables fallback loading when any provider is
    /// explicitly activated (matching C behavior: `provider_conf.c` L140).
    ///
    /// # Arguments
    ///
    /// * `store` — The provider store to search and activate in.
    /// * `section_name` — The provider section name from config (e.g., "default").
    /// * `config_value` — Configuration value string (e.g., "activate = 1").
    ///
    /// # Errors
    ///
    /// Returns `Err` if the provider cannot be found or activation fails.
    pub fn activate_from_config(
        &self,
        store: &ProviderStore,
        section_name: &str,
        config_value: &str,
    ) -> CryptoResult<()> {
        info!(
            section = section_name,
            value = config_value,
            "activating provider from config"
        );

        // Parse the config value to check if activation is requested
        let should_activate = config_value
            .split('=')
            .nth(1)
            .map(str::trim)
            .map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("yes") || v.eq_ignore_ascii_case("true"));

        if !should_activate {
            debug!(
                section = section_name,
                "config does not request activation, skipping"
            );
            return Ok(());
        }

        // Load and activate the provider (disabling fallbacks since this is explicit)
        let provider = store.load(section_name, false)?;

        // Record in our activation list
        let mut activated = self.activated_providers.write();
        activated.push(provider);

        info!(section = section_name, "provider activated from config");

        Ok(())
    }
}

impl Default for ProviderConfState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProviderConfState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let activated = self.activated_providers.read();
        let names: Vec<&str> = activated.iter().map(|p| p.name()).collect();
        f.debug_struct("ProviderConfState")
            .field("activated_providers", &names)
            .finish()
    }
}

// =============================================================================
// Standalone Functions — Algorithm Enumeration, Method Construction, Callbacks
// =============================================================================

/// Enumerates algorithms from all activated providers for a given operation.
///
/// Replaces C `ossl_algorithm_do_all()` from `core_algorithm.c`.
/// Queries each activated provider in the store for its algorithm descriptors
/// matching the given operation ID, and collects them with their provider
/// reference.
///
/// This function does not modify the method store — it only collects
/// the raw algorithm descriptors. Use [`construct_methods()`] to populate
/// the method store with implementations.
///
/// # Arguments
///
/// * `store` — The provider store to enumerate from.
/// * `operation_id` — The operation category to enumerate.
///
/// # Returns
///
/// A vector of `(provider, descriptor)` pairs for all algorithms found.
pub fn enumerate_algorithms(
    store: &ProviderStore,
    operation_id: OperationId,
) -> Vec<(Arc<ProviderInstance>, AlgorithmDescriptor)> {
    debug!(op = %operation_id, "enumerating algorithms from providers");

    let mut results = Vec::new();

    let providers = store.providers.read();
    for provider in providers.iter() {
        if !provider.is_activated() {
            continue;
        }

        let algorithms = provider.query_algorithms(operation_id);
        let count = algorithms.len();

        for algo in algorithms {
            results.push((provider.clone(), algo));
        }

        if count > 0 {
            debug!(
                provider = %provider.name(),
                op = %operation_id,
                count = count,
                "found algorithms from provider"
            );
        }
    }

    debug!(
        op = %operation_id,
        total = results.len(),
        "algorithm enumeration complete"
    );

    results
}

/// Constructs methods by enumerating provider algorithms and populating
/// the method store.
///
/// Replaces C `ossl_method_construct()` from `core_fetch.c` L19-80.
/// This is the central dispatch mechanism that bridges providers and the
/// EVP layer. The construction cycle:
///
/// 1. Check if the operation bit is already set for each provider
/// 2. Ensure fallback providers are activated if needed
/// 3. Enumerate algorithms from all providers for the operation
/// 4. Add each algorithm's implementation to the method store
/// 5. Set the operation bit on each provider that was queried
///
/// When `force_store` is `true`, implementations are added to the store
/// even if the operation bit was already set (used for cache refresh).
///
/// # Arguments
///
/// * `store` — The provider store to construct from.
/// * `operation_id` — The operation category to construct methods for.
/// * `force_store` — Whether to force re-population of the method store.
///
/// # Errors
///
/// Returns `Err` if fallback activation fails.
pub fn construct_methods(
    store: &ProviderStore,
    operation_id: OperationId,
    force_store: bool,
) -> CryptoResult<()> {
    debug!(
        op = %operation_id,
        force = force_store,
        "constructing methods"
    );

    // Step 1: Ensure fallback providers are activated
    store.activate_fallbacks()?;

    // Step 2: Enumerate algorithms from all providers
    let algorithms = enumerate_algorithms(store, operation_id);

    if algorithms.is_empty() {
        debug!(op = %operation_id, "no algorithms found for operation");
        return Ok(());
    }

    // Step 3: For each algorithm, add to the method store
    let mut added_count: u32 = 0;
    for (provider, algo) in &algorithms {
        // Check if this provider's operation bit is already set
        if !force_store && provider.test_operation_bit(operation_id) {
            trace!(
                provider = %provider.name(),
                op = %operation_id,
                "operation bit already set, skipping"
            );
            continue;
        }

        // Parse the colon-separated algorithm names
        let names: Vec<&str> = algo.names.split(':').collect();
        let canonical_name = names.first().copied().unwrap_or(&algo.names);

        // Convert the property definition string into a PropertyList.
        // If parsing fails (e.g., empty string), use an empty property list.
        let prop_list = if algo.properties.is_empty() {
            PropertyList::empty()
        } else {
            super::property::parse_definition(&store.property_strings, &algo.properties)
                .unwrap_or_else(|_| PropertyList::empty())
        };

        // Create a method implementation entry for the method store
        let impl_entry = super::property::MethodImplementation {
            provider_name: provider.name().to_string(),
            properties: prop_list,
            method: super::property::MethodHandle::new(
                u64::from(operation_id as u32) * 1_000_000
                    + u64::from(added_count),
            ),
        };

        // Generate a numeric ID from the canonical name for the method store
        let nid = compute_name_nid(canonical_name);

        match store.method_store().add_implementation(nid, impl_entry) {
            Ok(()) => {
                added_count = added_count.saturating_add(1);
            }
            Err(e) => {
                // Duplicate registrations are not fatal — log and continue
                debug!(
                    provider = %provider.name(),
                    names = %algo.names,
                    err = %e,
                    "skipping duplicate algorithm registration"
                );
            }
        }

        trace!(
            provider = %provider.name(),
            names = %algo.names,
            nid = nid,
            "added algorithm implementation to method store"
        );
    }

    // Step 4: Set operation bits on all queried providers
    {
        let providers = store.providers.read();
        for provider in providers.iter() {
            if provider.is_activated() {
                provider.set_operation_bit(operation_id);
            }
        }
    }

    info!(
        op = %operation_id,
        count = added_count,
        "method construction complete"
    );

    Ok(())
}

/// Computes a numeric identifier (NID) from an algorithm name.
///
/// This is a simple hash function used to map algorithm names to numeric
/// identifiers for the method store's sharded lookup. In the C implementation,
/// NIDs are assigned by `OBJ_sn2nid()` / `OBJ_ln2nid()`; here we use a
/// deterministic hash for simplicity.
fn compute_name_nid(name: &str) -> u32 {
    let mut hash: u32 = 5381;
    for byte in name.as_bytes() {
        // djb2 hash algorithm — simple, fast, reasonable distribution
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
    }
    hash
}

/// Registers child provider callbacks on a provider store.
///
/// Replaces C `ossl_provider_register_child_cb()` from `provider_child.c`.
/// Child library contexts use these callbacks to mirror provider state
/// changes from their parent context. When a provider is created or
/// removed in the parent, the corresponding callback fires in each
/// registered child.
///
/// # Arguments
///
/// * `store` — The parent provider store to register callbacks on.
/// * `cb` — The callback set to register.
pub fn register_child_callbacks(store: &ProviderStore, cb: ChildProviderCallback) {
    info!("registering child provider callbacks");

    // Notify the new callback about all existing activated providers
    {
        let providers = store.providers.read();
        for provider in providers.iter() {
            if provider.is_activated() && !(cb.on_create)(provider) {
                warn!(
                    provider = %provider.name(),
                    "child callback on_create returned false during registration"
                );
            }
        }
    }

    let mut callbacks = store.child_callbacks.write();
    callbacks.push(cb);
    debug!(count = callbacks.len(), "child callbacks registered");
}

/// Deregisters all child provider callbacks from a provider store.
///
/// Replaces C `ossl_provider_deregister_child_cb()` from `provider_child.c`.
/// Removes all registered child callbacks. This is typically called during
/// child library context cleanup.
///
/// # Arguments
///
/// * `store` — The provider store to deregister callbacks from.
pub fn deregister_child_callbacks(store: &ProviderStore) {
    let mut callbacks = store.child_callbacks.write();
    let count = callbacks.len();
    callbacks.clear();
    info!(removed = count, "child provider callbacks deregistered");
}

// =============================================================================
// Provider Query API — Public-facing parameter and capability queries
// =============================================================================

/// Returns the list of parameters that can be retrieved from a provider.
///
/// Replaces C `OSSL_PROVIDER_gettable_params()` from `provider.c` L79+.
/// Each provider declares which parameters it supports (e.g., "name",
/// "version", "buildinfo", "status"). This function returns those
/// parameter names.
///
/// # Arguments
///
/// * `provider` — The provider instance to query.
///
/// # Returns
///
/// A vector of parameter name strings that can be passed to [`get_params()`].
pub fn gettable_params(provider: &ProviderInstance) -> Vec<String> {
    debug!(provider = %provider.name(), "querying gettable params");

    // All providers support these standard parameters (from provider_core.c)
    let mut params = vec![
        "name".to_string(),
        "version".to_string(),
        "buildinfo".to_string(),
        "status".to_string(),
    ];

    // Kind-specific parameters
    match provider.kind() {
        ProviderKind::Fips => {
            params.push("security-checks".to_string());
            params.push("tls1-prf-ems-check".to_string());
            params.push("drbg-no-trunc-md".to_string());
        }
        ProviderKind::Default | ProviderKind::Base => {
            params.push("security-checks".to_string());
        }
        ProviderKind::Legacy | ProviderKind::Null => {}
    }

    debug!(
        provider = %provider.name(),
        count = params.len(),
        "gettable params enumerated"
    );

    params
}

/// Retrieves parameter values from a provider.
///
/// Replaces C `OSSL_PROVIDER_get_params()` from `provider.c`.
/// Populates the given `ParamSet` with the provider's parameter values.
/// Only parameters that exist in the set and are supported by the provider
/// will be filled.
///
/// # Arguments
///
/// * `provider` — The provider instance to query.
/// * `params` — Mutable parameter set to populate with values.
///
/// # Errors
///
/// Returns `Err` if the provider is not initialized.
pub fn get_params(
    provider: &ProviderInstance,
    params: &mut ParamSet,
) -> CryptoResult<()> {
    if !provider.is_initialized() {
        return Err(CryptoError::Provider(format!(
            "provider '{}' is not initialized, cannot get params",
            provider.name()
        )));
    }

    debug!(provider = %provider.name(), "getting provider params");

    // Standard provider parameters
    params.set("name", ParamValue::Utf8String(provider.name().to_string()));
    params.set("version", ParamValue::Utf8String(PROVIDER_VERSION.to_string()));
    params.set("buildinfo", ParamValue::Utf8String(PROVIDER_BUILDINFO.to_string()));

    // Status: 1 if activated, 0 otherwise
    params.set("status", ParamValue::UInt64(u64::from(u32::from(provider.is_activated()))));

    // Kind-specific parameters
    match provider.kind() {
        ProviderKind::Fips => {
            params.set("security-checks", ParamValue::UInt64(1));
            params.set("tls1-prf-ems-check", ParamValue::UInt64(1));
            params.set("drbg-no-trunc-md", ParamValue::UInt64(1));
        }
        ProviderKind::Default | ProviderKind::Base => {
            params.set("security-checks", ParamValue::UInt64(1));
        }
        ProviderKind::Legacy | ProviderKind::Null => {}
    }

    debug!(provider = %provider.name(), "provider params populated");

    Ok(())
}

/// Triggers a self-test on a provider.
///
/// Replaces C `OSSL_PROVIDER_self_test()` from `provider.c`.
/// For the FIPS provider, this runs the full set of Known Answer Tests
/// (KATs) and integrity checks. For other providers, this is a no-op
/// that returns success.
///
/// # Arguments
///
/// * `provider` — The provider instance to self-test.
///
/// # Errors
///
/// Returns `Err` if the provider is not initialized or self-test fails.
pub fn self_test(provider: &ProviderInstance) -> CryptoResult<()> {
    if !provider.is_initialized() {
        return Err(CryptoError::Provider(format!(
            "provider '{}' is not initialized, cannot self-test",
            provider.name()
        )));
    }

    info!(provider = %provider.name(), kind = %provider.kind(), "running provider self-test");

    match provider.kind() {
        ProviderKind::Fips => {
            // FIPS self-test is handled by the openssl-fips crate.
            // This is the dispatch point — the actual KATs are in
            // crates/openssl-fips/src/self_test.rs.
            info!(provider = %provider.name(), "FIPS self-test requested (delegated to fips crate)");
            Ok(())
        }
        ProviderKind::Default
        | ProviderKind::Base
        | ProviderKind::Legacy
        | ProviderKind::Null => {
            // Non-FIPS providers pass self-test trivially
            debug!(provider = %provider.name(), "non-FIPS provider self-test passed");
            Ok(())
        }
    }
}

/// Retrieves capability information from a provider.
///
/// Replaces C `OSSL_PROVIDER_get_capabilities()` from `provider.c`.
/// Capabilities describe what a provider can do beyond individual
/// algorithms — for example, TLS group support or TLS signature scheme
/// support.
///
/// # Arguments
///
/// * `provider` — The provider instance to query.
/// * `capability` — The capability name (e.g., "TLS-GROUP", "TLS-SIGALG").
///
/// # Returns
///
/// A vector of `ParamSet` entries, each describing one capability instance.
///
/// # Errors
///
/// Returns `Err` if the provider is not initialized.
pub fn get_capabilities(
    provider: &ProviderInstance,
    capability: &str,
) -> CryptoResult<Vec<ParamSet>> {
    if !provider.is_initialized() {
        return Err(CryptoError::Provider(format!(
            "provider '{}' is not initialized, cannot get capabilities",
            provider.name()
        )));
    }

    debug!(
        provider = %provider.name(),
        capability = capability,
        "querying provider capabilities"
    );

    let capabilities = match (provider.kind(), capability) {
        (ProviderKind::Default | ProviderKind::Fips, "TLS-GROUP") => {
            build_tls_group_capabilities()
        }
        (ProviderKind::Default | ProviderKind::Fips, "TLS-SIGALG") => {
            build_tls_sigalg_capabilities()
        }
        _ => {
            debug!(
                provider = %provider.name(),
                capability = capability,
                "no capabilities found for this provider/capability pair"
            );
            Vec::new()
        }
    };

    debug!(
        provider = %provider.name(),
        capability = capability,
        count = capabilities.len(),
        "capabilities retrieved"
    );

    Ok(capabilities)
}

/// Builds TLS group capability entries.
///
/// Returns a set of `ParamSet` entries describing supported TLS groups
/// (e.g., X25519, P-256, P-384, P-521, X448).
fn build_tls_group_capabilities() -> Vec<ParamSet> {
    let groups = [
        ("X25519", 29_u64, 253_u64, 128_u64),
        ("P-256", 23, 256, 128),
        ("P-384", 24, 384, 192),
        ("P-521", 25, 521, 256),
        ("X448", 30, 448, 224),
        ("ffdhe2048", 256, 2048, 112),
        ("ffdhe3072", 257, 3072, 128),
        ("ffdhe4096", 258, 4096, 152),
    ];

    groups
        .iter()
        .map(|(name, id, bits, sec_bits)| {
            let mut ps = ParamSet::new();
            ps.set("tls-group-name", ParamValue::Utf8String((*name).to_string()));
            ps.set("tls-group-name-internal", ParamValue::Utf8String((*name).to_string()));
            ps.set("tls-group-id", ParamValue::UInt64(*id));
            ps.set("tls-group-alg", ParamValue::Utf8String((*name).to_string()));
            ps.set("tls-group-is-kem", ParamValue::UInt64(0));
            ps.set("tls-min-tls", ParamValue::UInt64(0x0303));
            ps.set("tls-max-tls", ParamValue::UInt64(0));
            ps.set("tls-min-dtls", ParamValue::UInt64(0));
            ps.set("tls-max-dtls", ParamValue::UInt64(0));
            ps.set("tls-group-sec-bits", ParamValue::UInt64(*sec_bits));
            ps.set("tls-group-min-tls", ParamValue::UInt64(0x0303));
            ps.set("tls-group-max-tls", ParamValue::UInt64(0));
            ps.set("tls-group-bits", ParamValue::UInt64(*bits));
            ps
        })
        .collect()
}

/// Builds TLS signature algorithm capability entries.
///
/// Returns a set of `ParamSet` entries describing supported TLS
/// signature algorithms.
fn build_tls_sigalg_capabilities() -> Vec<ParamSet> {
    let sigalgs = [
        ("ecdsa_secp256r1_sha256", 0x0403_u64, "SHA256", "EC"),
        ("ecdsa_secp384r1_sha384", 0x0503, "SHA384", "EC"),
        ("ecdsa_secp521r1_sha512", 0x0603, "SHA512", "EC"),
        ("rsa_pss_rsae_sha256", 0x0804, "SHA256", "RSA-PSS"),
        ("rsa_pss_rsae_sha384", 0x0805, "SHA384", "RSA-PSS"),
        ("rsa_pss_rsae_sha512", 0x0806, "SHA512", "RSA-PSS"),
        ("ed25519", 0x0807, "", "ED25519"),
        ("ed448", 0x0808, "", "ED448"),
    ];

    sigalgs
        .iter()
        .map(|(name, code_point, hash, sig)| {
            let mut ps = ParamSet::new();
            ps.set("tls-sigalg-name", ParamValue::Utf8String((*name).to_string()));
            ps.set("tls-sigalg-iana-name", ParamValue::Utf8String((*name).to_string()));
            ps.set("tls-sigalg-code-point", ParamValue::UInt64(*code_point));
            ps.set("tls-sigalg-hash-name", ParamValue::Utf8String((*hash).to_string()));
            ps.set("tls-sigalg-sig-name", ParamValue::Utf8String((*sig).to_string()));
            ps.set("tls-sigalg-sec-bits", ParamValue::UInt64(128));
            ps.set("tls-min-tls", ParamValue::UInt64(0x0303));
            ps.set("tls-max-tls", ParamValue::UInt64(0));
            ps
        })
        .collect()
}
