//! Method store and algorithm dispatch infrastructure for the OpenSSL Rust workspace.
//!
//! Manages algorithm registration, lookup by name and property query, caching,
//! and provider-based algorithm fetch.  Translates C `crypto/core_fetch.c`
//! (`OSSL_METHOD_STORE`) and `crypto/core_algorithm.c` (`ossl_algorithm_do_all`)
//! into idiomatic Rust with fine-grained locking per Rule R7.
//!
//! # Architecture
//!
//! The method store sits at the centre of the provider-based dispatch
//! architecture.  Providers register their algorithm descriptors via
//! `MethodStore::register_provider`, and consumers fetch resolved
//! implementations via `MethodStore::fetch`.
//!
//! ```text
//! ┌──────────────┐     register_provider()     ┌──────────────┐
//! │   Provider    │ ─────────────────────────▶  │  MethodStore │
//! └──────────────┘                              │              │
//!                                               │  registry[]  │
//! ┌──────────────┐     fetch(op, name, prop)    │  cache{}     │
//! │  EVP layer   │ ◀────────────────────────── │              │
//! └──────────────┘                              └──────────────┘
//! ```
//!
//! # Locking Strategy (Rule R7)
//!
//! Three independent [`RwLock`](parking_lot::RwLock) instances provide
//! fine-grained concurrency control:
//!
//! - **`cache`** — read-heavy after warmup; written once per newly-fetched
//!   algorithm.
//! - **`registry`** — written during provider registration; read during fetch
//!   on cache miss.
//! - **`capabilities`** — written during provider capability registration;
//!   read during capability queries.
//!
//! This avoids a single coarse lock and reduces contention under concurrent
//! `fetch()` calls.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, trace, warn};

use crate::traits::{AlgorithmDescriptor, AlgorithmProvider, Provider};
use openssl_common::{Nid, OperationType, ParamSet, ParamValue, ProviderError, ProviderResult};

// =============================================================================
// Constants
// =============================================================================

/// All operation types, used to iterate over every category when registering
/// a provider.  Mirrors the C `OSSL_OP_*` enumeration range from
/// `include/openssl/core_dispatch.h`.
const ALL_OPERATIONS: [OperationType; 13] = [
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

// =============================================================================
// MethodKey — Cache Key
// =============================================================================

/// Composite key for the method store cache.
///
/// Combines the operation type, canonical algorithm name (normalised to
/// uppercase), and optional property query into a single hashable key.
/// This replaces the C `(nid, property)` pair used in
/// `OSSL_METHOD_STORE` from `crypto/core_fetch.c`.
///
/// # Examples
///
/// ```
/// use openssl_provider::dispatch::MethodKey;
/// use openssl_common::OperationType;
///
/// let key = MethodKey {
///     operation: OperationType::Digest,
///     name: "SHA2-256".to_string(),
///     property_query: Some("provider=default".to_string()),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodKey {
    /// The category of cryptographic operation.
    pub operation: OperationType,
    /// Canonical algorithm name (uppercase-normalised for case-insensitive lookup).
    pub name: String,
    /// Optional property query string for implementation selection.
    pub property_query: Option<String>,
}

// =============================================================================
// RegisteredAlgorithm — Registry Entry
// =============================================================================

/// An algorithm registered by a provider in the method store.
///
/// Wraps an [`AlgorithmDescriptor`] together with the name of the provider
/// that supplied it.  The internal `operation` field is used for
/// operation-type filtering during `MethodStore::fetch`.
///
/// Replaces the entries inserted by `ossl_method_store_add()` in
/// `crypto/core_fetch.c`.
#[derive(Debug, Clone)]
pub struct RegisteredAlgorithm {
    /// Metadata describing the algorithm (names, property, description).
    pub descriptor: AlgorithmDescriptor,
    /// Name of the provider that registered this algorithm.
    pub provider_name: String,
    /// Operation category (used for internal matching).
    operation: OperationType,
}

impl RegisteredAlgorithm {
    /// Returns the operation type this algorithm was registered for.
    pub fn operation(&self) -> OperationType {
        self.operation
    }
}

// =============================================================================
// ResolvedAlgorithm — Cached Implementation (module-private)
// =============================================================================

/// A resolved algorithm implementation stored in the method cache.
///
/// Wraps an [`AlgorithmDescriptor`] with its provider name, operation type,
/// and resolved numeric identifier to satisfy the [`AlgorithmProvider`]
/// marker trait required for cache storage.
///
/// This is a module-private type — callers receive it as
/// `Arc<dyn AlgorithmProvider>`.
///
/// # Fields
///
/// Fields carry algorithm identity for the `Debug` supertrait (required by
/// `AlgorithmProvider`) and for potential runtime inspection via
/// `Any::downcast`.  The `Clone` derive enables cache-value duplication.
//
// JUSTIFICATION: Fields are read by the derived `Debug` impl (which is a
// supertrait requirement of `AlgorithmProvider`) and by the derived `Clone`
// impl.  Rust's dead-code analysis intentionally ignores derived impls,
// producing a false positive.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ResolvedAlgorithm {
    /// Algorithm descriptor metadata.
    descriptor: AlgorithmDescriptor,
    /// Name of the provider that supplied this algorithm.
    provider_name: String,
    /// Operation category.
    operation: OperationType,
    /// Numeric identifier resolved from the algorithm name.
    nid: Nid,
}

impl AlgorithmProvider for ResolvedAlgorithm {}

// =============================================================================
// AlgorithmCapability — TLS Group / SigAlg Capability
// =============================================================================

/// Describes a TLS group or signature algorithm capability.
///
/// Replaces the C `TLS_GROUP_CONSTANTS` struct and `param_group_list[]`
/// from `providers/common/capabilities.c`.  Used to report algorithm
/// capabilities to the TLS layer for group and signature algorithm
/// negotiation.
///
/// # Fields
///
/// | Field | C Equivalent | Description |
/// |-------|-------------|-------------|
/// | `group_name` | `TLS_GROUP_ENTRY::group_name_internal` | Group name |
/// | `secbits` | `TLS_GROUP_CONSTANTS::secbits` | Security strength |
/// | `min_tls` | `TLS_GROUP_CONSTANTS::mintls` | Min TLS version |
/// | `max_tls` | `TLS_GROUP_CONSTANTS::maxtls` | Max TLS version |
/// | `min_dtls` | `TLS_GROUP_CONSTANTS::mindtls` | Min DTLS version |
/// | `max_dtls` | `TLS_GROUP_CONSTANTS::maxdtls` | Max DTLS version |
///
/// # Examples
///
/// ```
/// use openssl_provider::dispatch::AlgorithmCapability;
///
/// let cap = AlgorithmCapability {
///     group_name: "secp256r1".to_string(),
///     secbits: 128,
///     min_tls: Some(0x0301),
///     max_tls: None,
///     min_dtls: Some(0xFEFF),
///     max_dtls: None,
/// };
/// assert_eq!(cap.secbits, 128);
/// ```
#[derive(Debug, Clone)]
pub struct AlgorithmCapability {
    /// Human-readable group or algorithm name.
    pub group_name: String,
    /// Security strength in bits.
    pub secbits: u32,
    /// Minimum TLS protocol version, or `None` if unrestricted.
    pub min_tls: Option<u16>,
    /// Maximum TLS protocol version, or `None` if unrestricted.
    pub max_tls: Option<u16>,
    /// Minimum DTLS protocol version, or `None` if unrestricted.
    pub min_dtls: Option<u16>,
    /// Maximum DTLS protocol version, or `None` if unrestricted.
    pub max_dtls: Option<u16>,
}

impl AlgorithmCapability {
    /// Converts this capability into a `ParamSet` for parameter-based
    /// exchange with callers that operate on generic parameter bags.
    ///
    /// Mirrors the C `OSSL_PARAM` array construction in the
    /// `TLS_GROUP_ENTRY` macro from `providers/common/capabilities.c`.
    pub fn to_param_set(&self) -> ParamSet {
        let mut params = ParamSet::new();
        params.set(
            "group-name",
            ParamValue::Utf8String(self.group_name.clone()),
        );
        params.set("security-bits", ParamValue::UInt32(self.secbits));
        if let Some(v) = self.min_tls {
            params.set("min-tls", ParamValue::UInt32(u32::from(v)));
        }
        if let Some(v) = self.max_tls {
            params.set("max-tls", ParamValue::UInt32(u32::from(v)));
        }
        if let Some(v) = self.min_dtls {
            params.set("min-dtls", ParamValue::UInt32(u32::from(v)));
        }
        if let Some(v) = self.max_dtls {
            params.set("max-dtls", ParamValue::UInt32(u32::from(v)));
        }
        params
    }
}

// =============================================================================
// MethodStore — Thread-Safe Algorithm Dispatch Store
// =============================================================================

/// Thread-safe method store for cached algorithm lookups.
///
/// Replaces C `OSSL_METHOD_STORE` from `crypto/core_fetch.c`.  The store
/// caches resolved algorithm implementations keyed by
/// `(operation_type, algorithm_name, property_query)` tuples.
///
/// # Concurrency (Rule R7)
///
/// Three independent [`RwLock`] instances provide fine-grained concurrency:
///
/// | Lock | Access Pattern | Contention |
/// |------|---------------|------------|
/// | `cache` | Read-heavy after warmup | Low (write-once per algorithm) |
/// | `registry` | Write during registration, read during fetch | Low (infrequent writes) |
/// | `capabilities` | Write during registration, read during queries | Low |
///
/// # Examples
///
/// ```
/// use openssl_provider::dispatch::MethodStore;
/// use openssl_common::OperationType;
///
/// let store = MethodStore::new();
/// // After provider registration, algorithms can be fetched:
/// // let result = store.fetch(OperationType::Digest, "SHA2-256", None);
/// ```
pub struct MethodStore {
    // LOCK-SCOPE: method cache — write during first fetch, read during subsequent.
    // Contention expected: read-heavy after warmup, write-once per algorithm.
    cache: RwLock<HashMap<MethodKey, Arc<dyn AlgorithmProvider>>>,

    // LOCK-SCOPE: algorithm registry — write during provider registration, read during fetch.
    // Contention expected: write bursts at init, read-only during steady-state operation.
    registry: RwLock<Vec<RegisteredAlgorithm>>,

    // LOCK-SCOPE: capabilities — write during provider capability registration,
    // read during TLS group/sigalg capability queries.
    capabilities: RwLock<HashMap<String, Vec<AlgorithmCapability>>>,
}

impl MethodStore {
    /// Creates a new, empty method store.
    ///
    /// All internal data structures are initialised to empty state.
    /// Providers must be registered via [`register_provider`](Self::register_provider)
    /// before any algorithms can be fetched.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            registry: RwLock::new(Vec::new()),
            capabilities: RwLock::new(HashMap::new()),
        }
    }

    // ── Registration ─────────────────────────────────────────────────────

    /// Registers algorithm descriptors for a specific operation type from a
    /// named provider.
    ///
    /// Each descriptor is wrapped in a [`RegisteredAlgorithm`] and appended
    /// to the internal registry.  This **does not** invalidate the cache —
    /// call [`flush_cache`](Self::flush_cache) explicitly if stale entries
    /// may exist.
    ///
    /// Replaces `ossl_method_store_add()` from `crypto/core_fetch.c`.
    ///
    /// # Arguments
    ///
    /// * `operation` — The operation category these algorithms belong to.
    /// * `provider_name` — Human-readable provider name (e.g. `"default"`).
    /// * `algorithms` — Algorithm descriptors returned by the provider's
    ///   `query_operation()`.
    pub fn register(
        &self,
        operation: OperationType,
        provider_name: &str,
        algorithms: Vec<AlgorithmDescriptor>,
    ) {
        let count = algorithms.len();
        let mut reg = self.registry.write();
        for desc in algorithms {
            debug!(
                provider = provider_name,
                operation = %operation,
                names = ?desc.names,
                "registering algorithm"
            );
            reg.push(RegisteredAlgorithm {
                descriptor: desc,
                provider_name: provider_name.to_owned(),
                operation,
            });
        }
        debug!(
            provider = provider_name,
            operation = %operation,
            count = count,
            "registered algorithms"
        );
    }

    // ── Fetch ────────────────────────────────────────────────────────────

    /// Fetches a resolved algorithm implementation by operation type,
    /// canonical name, and optional property query.
    ///
    /// The lookup proceeds in two stages:
    ///
    /// 1. **Cache hit** — Acquires a read lock on `cache` and returns the
    ///    `Arc<dyn AlgorithmProvider>` immediately if found.
    /// 2. **Cache miss** — Acquires a read lock on `registry`, scans for a
    ///    matching entry, wraps it in a `ResolvedAlgorithm`, inserts into
    ///    `cache` under a write lock, and returns.
    ///
    /// Property matching supports:
    /// - Exact match: `"provider=default"`
    /// - Negation: `"provider!=legacy"`
    /// - Wildcard: `None` or empty string matches all.
    ///
    /// Returns `Err(ProviderError::AlgorithmUnavailable(...))` if no
    /// matching algorithm is found in the registry — never a sentinel value
    /// (Rule R5).
    ///
    /// Replaces `ossl_method_store_fetch()` from `crypto/core_fetch.c`.
    pub fn fetch(
        &self,
        op: OperationType,
        name: &str,
        property_query: Option<&str>,
    ) -> ProviderResult<Arc<dyn AlgorithmProvider>> {
        let normalised_name = name.to_ascii_uppercase();
        let key = MethodKey {
            operation: op,
            name: normalised_name.clone(),
            property_query: property_query.map(str::to_owned),
        };

        // Stage 1: cache lookup (read lock)
        {
            let cache = self.cache.read();
            if let Some(hit) = cache.get(&key) {
                trace!(
                    op = %op,
                    name = name,
                    property = ?property_query,
                    "method store cache hit"
                );
                return Ok(Arc::clone(hit));
            }
        }

        // Stage 2: registry scan (read lock on registry)
        trace!(
            op = %op,
            name = name,
            property = ?property_query,
            "method store cache miss — scanning registry"
        );

        let resolved = {
            let reg = self.registry.read();
            find_in_registry(&reg, op, &normalised_name, property_query)
        };

        if let Some(algo) = resolved {
            let arc: Arc<dyn AlgorithmProvider> = Arc::new(algo);
            // Insert into cache (write lock)
            {
                let mut cache = self.cache.write();
                cache.insert(key, Arc::clone(&arc));
            }
            trace!(
                op = %op,
                name = name,
                "method store fetch — resolved and cached"
            );
            Ok(arc)
        } else {
            warn!(
                op = %op,
                name = name,
                property = ?property_query,
                "algorithm unavailable in method store"
            );
            Err(ProviderError::AlgorithmUnavailable(format!(
                "no {} algorithm '{}' matching property '{}'",
                op,
                name,
                property_query.unwrap_or("*")
            )))
        }
    }

    // ── Cache Management ────────────────────────────────────────────────

    /// Clears the entire method cache, forcing subsequent fetches to
    /// re-resolve from the registry.
    ///
    /// Acquires a write lock on `cache`.  Typically called after a provider
    /// is loaded or unloaded.
    ///
    /// Replaces `ossl_method_store_flush_cache()` from `crypto/core_fetch.c`.
    pub fn flush_cache(&self) {
        let mut cache = self.cache.write();
        let count = cache.len();
        cache.clear();
        debug!(evicted = count, "method store cache flushed");
    }

    /// Removes all algorithms registered by the named provider from the
    /// registry **and** evicts any corresponding cache entries.
    ///
    /// This is the reverse of [`register_provider`](Self::register_provider)
    /// and is called when a provider is being unloaded.
    ///
    /// Replaces `ossl_method_store_remove_all_provided()` from
    /// `crypto/core_fetch.c`.
    pub fn remove_provider(&self, provider_name: &str) {
        // Remove from registry
        {
            let mut reg = self.registry.write();
            let before = reg.len();
            reg.retain(|entry| entry.provider_name != provider_name);
            let removed = before - reg.len();
            debug!(
                provider = provider_name,
                removed = removed,
                "removed algorithms from registry"
            );
        }
        // Evict cache entries that were resolved from this provider.
        // Since we cannot inspect the Arc<dyn AlgorithmProvider> to
        // determine the provider name (the marker trait has no methods),
        // we flush the entire cache to ensure consistency.
        self.flush_cache();
    }

    // ── Enumeration ─────────────────────────────────────────────────────

    /// Returns all registered algorithm descriptors for a given operation
    /// type.
    ///
    /// Acquires a read lock on `registry`.  The returned descriptors are
    /// clones of the stored metadata.
    ///
    /// Replaces `ossl_algorithm_do_all()` callback pattern from
    /// `crypto/core_algorithm.c`.
    pub fn enumerate_algorithms(&self, op: OperationType) -> Vec<AlgorithmDescriptor> {
        let reg = self.registry.read();
        reg.iter()
            .filter(|entry| entry.operation == op)
            .map(|entry| entry.descriptor.clone())
            .collect()
    }

    /// Returns all registered algorithms across every operation type.
    ///
    /// Each returned tuple pairs the operation type with its algorithm
    /// descriptor.  Acquires a read lock on `registry`.
    pub fn enumerate_all(&self) -> Vec<(OperationType, AlgorithmDescriptor)> {
        let reg = self.registry.read();
        reg.iter()
            .map(|entry| (entry.operation, entry.descriptor.clone()))
            .collect()
    }

    // ── Provider Registration Coordinator ────────────────────────────────

    /// Queries the provider for every operation type and registers all
    /// returned algorithm descriptors.
    ///
    /// Iterates over `ALL_OPERATIONS`, calling
    /// [`Provider::query_operation`] for each type.  Descriptors returned
    /// by the provider are passed to [`register`](Self::register).
    ///
    /// After registration the cache is flushed so that subsequent fetches
    /// pick up the newly available algorithms.
    ///
    /// Replaces the C pattern where the core calls
    /// `OSSL_FUNC_PROVIDER_QUERY_OPERATION` for each `OSSL_OP_*` and
    /// stores results via `ossl_method_store_add()`.
    pub fn register_provider(&self, provider: &dyn Provider) {
        let info = provider.info();
        let provider_name = info.name;
        debug!(provider = provider_name, "beginning provider registration");

        let mut total = 0usize;
        for &op in &ALL_OPERATIONS {
            if let Some(algorithms) = provider.query_operation(op) {
                let count = algorithms.len();
                if count > 0 {
                    self.register(op, provider_name, algorithms);
                    total += count;
                }
            }
        }

        // Flush cache so new algorithms become discoverable
        if total > 0 {
            self.flush_cache();
        }

        debug!(
            provider = provider_name,
            total_algorithms = total,
            "provider registration complete"
        );
    }

    // ── Capabilities ────────────────────────────────────────────────────

    /// Returns capabilities matching the given capability type name.
    ///
    /// Supported capability names:
    /// - `"TLS-GROUP"` — TLS key-exchange groups (EC, FFDHE, hybrid PQ)
    /// - `"TLS-SIGALG"` — TLS signature algorithms
    ///
    /// If no capabilities have been explicitly registered for the requested
    /// name, a built-in default set is returned for `"TLS-GROUP"`.
    ///
    /// Replaces `ossl_prov_get_capabilities()` from
    /// `providers/common/capabilities.c`.
    pub fn get_capabilities(&self, capability_name: &str) -> Vec<AlgorithmCapability> {
        let caps = self.capabilities.read();
        if let Some(list) = caps.get(capability_name) {
            return list.clone();
        }
        // Fall back to built-in defaults for TLS-GROUP
        if capability_name == "TLS-GROUP" {
            return default_tls_group_capabilities();
        }
        Vec::new()
    }

    /// Registers a set of capabilities under a capability type name.
    ///
    /// Acquires a write lock on the `capabilities` map.  Existing entries
    /// for the same `capability_name` are **replaced**.
    pub fn set_capabilities(&self, capability_name: &str, caps: Vec<AlgorithmCapability>) {
        let mut store = self.capabilities.write();
        debug!(
            capability = capability_name,
            count = caps.len(),
            "setting capabilities"
        );
        store.insert(capability_name.to_owned(), caps);
    }
}

impl Default for MethodStore {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Debug manually to avoid requiring Debug on trait objects
// inside HashMap values.
impl std::fmt::Debug for MethodStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache_len = self.cache.read().len();
        let registry_len = self.registry.read().len();
        let caps_len = self.capabilities.read().len();
        f.debug_struct("MethodStore")
            .field("cached_methods", &cache_len)
            .field("registered_algorithms", &registry_len)
            .field("capability_types", &caps_len)
            .finish()
    }
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Scans the registry for an algorithm matching the given operation type,
/// normalised name, and optional property query.
///
/// Returns a `ResolvedAlgorithm` wrapping the first matching entry, or
/// `None` if no match is found.
fn find_in_registry(
    registry: &[RegisteredAlgorithm],
    op: OperationType,
    normalised_name: &str,
    property_query: Option<&str>,
) -> Option<ResolvedAlgorithm> {
    for entry in registry {
        // Operation type must match
        if entry.operation != op {
            continue;
        }
        // At least one algorithm name must match (case-insensitive)
        let name_matches = entry
            .descriptor
            .names
            .iter()
            .any(|n| n.to_ascii_uppercase() == normalised_name);
        if !name_matches {
            continue;
        }
        // Property query must match (if specified)
        if let Some(query) = property_query {
            if !query.is_empty() && !matches_property(entry.descriptor.property, query) {
                continue;
            }
        }
        // Match found — resolve and return
        let nid = resolve_nid_for_name(normalised_name);
        return Some(ResolvedAlgorithm {
            descriptor: entry.descriptor.clone(),
            provider_name: entry.provider_name.clone(),
            operation: entry.operation,
            nid,
        });
    }
    None
}

/// Simple property string matching.
///
/// Evaluates whether an algorithm's property definition satisfies a
/// caller-supplied property query.
///
/// # Supported Syntax
///
/// | Query | Semantics |
/// |-------|-----------|
/// | `""` (empty) | Matches everything (wildcard) |
/// | `"provider=default"` | Exact key=value match |
/// | `"provider!=legacy"` | Negation — matches if key≠value |
/// | `"fips=yes"` | Exact key=value match |
/// | `"?key=value"` | Optional — treated as exact match (hint only) |
///
/// Multiple comma-separated terms are `AND`-ed together:
/// `"provider=default,fips=yes"` matches only if **both** terms hold.
///
/// This is a simplified subset of the full OpenSSL property query language
/// implemented in `crypto/property/property_parse.c`.  The full query
/// language supports additional operators and grouping, which can be
/// extended here as needed.
fn matches_property(algorithm_property: &str, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    // Parse comma-separated terms in the query and AND them together
    for term in query.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        // Strip optional '?' prefix (indicates "nice to have" — we treat
        // it the same as mandatory for simplicity)
        let term = term.strip_prefix('?').unwrap_or(term);

        if let Some((key, value)) = term.split_once("!=") {
            // Negation: algorithm property must NOT contain key=value
            let positive = format!("{}={}", key.trim(), value.trim());
            if property_contains(algorithm_property, &positive) {
                return false;
            }
        } else if let Some((key, value)) = term.split_once('=') {
            // Positive: algorithm property MUST contain key=value
            let positive = format!("{}={}", key.trim(), value.trim());
            if !property_contains(algorithm_property, &positive) {
                return false;
            }
        }
        // Terms without '=' are ignored (bare property names are not
        // supported in this simplified implementation).
    }
    true
}

/// Checks whether `property_def` contains the `needle` as a comma-separated
/// element (case-insensitive).
fn property_contains(property_def: &str, needle: &str) -> bool {
    let needle_upper = needle.to_ascii_uppercase();
    for part in property_def.split(',') {
        let part = part.trim().to_ascii_uppercase();
        if part == needle_upper {
            return true;
        }
    }
    false
}

/// Resolves a normalised algorithm name to its `Nid`.
///
/// Maps well-known algorithm names to their numeric identifiers as defined
/// in `include/openssl/obj_mac.h`.  Returns [`Nid::UNDEF`] for unrecognised
/// names.
///
/// This is a simplified subset of the full name map maintained by
/// `crypto/core_namemap.c`.  In production the name map would be populated
/// dynamically from the provider registry; this helper provides a static
/// fallback for commonly used algorithms.
fn resolve_nid_for_name(name: &str) -> Nid {
    match name {
        "SHA-256" | "SHA256" | "SHA2-256" => Nid::SHA256,
        "SHA-1" | "SHA1" => Nid::SHA1,
        "MD5" => Nid::MD5,
        "RSA" => Nid::RSA,
        "EC" => Nid::EC,
        "ED25519" => Nid::ED25519,
        "X25519" => Nid::X25519,
        "ML-KEM-768" | "ML_KEM_768" => Nid::ML_KEM_768,
        _ => Nid::UNDEF,
    }
}

// =============================================================================
// Default TLS Group Capabilities
// =============================================================================

/// Returns the built-in default TLS group capabilities.
///
/// This is the Rust equivalent of the static `group_list[]` array from
/// `providers/common/capabilities.c`, containing the standard EC and
/// FFDHE groups along with post-quantum hybrid groups.
///
/// TLS version constants:
/// - TLS 1.0 = 0x0301, TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
/// - DTLS 1.0 = 0xFEFF, DTLS 1.2 = 0xFEFD
fn default_tls_group_capabilities() -> Vec<AlgorithmCapability> {
    vec![
        // NIST P-256
        AlgorithmCapability {
            group_name: "secp256r1".to_owned(),
            secbits: 128,
            min_tls: Some(0x0301), // TLS 1.0
            max_tls: None,
            min_dtls: Some(0xFEFF), // DTLS 1.0
            max_dtls: None,
        },
        // NIST P-384
        AlgorithmCapability {
            group_name: "secp384r1".to_owned(),
            secbits: 192,
            min_tls: Some(0x0301),
            max_tls: None,
            min_dtls: Some(0xFEFF),
            max_dtls: None,
        },
        // NIST P-521
        AlgorithmCapability {
            group_name: "secp521r1".to_owned(),
            secbits: 256,
            min_tls: Some(0x0301),
            max_tls: None,
            min_dtls: Some(0xFEFF),
            max_dtls: None,
        },
        // X25519
        AlgorithmCapability {
            group_name: "x25519".to_owned(),
            secbits: 128,
            min_tls: Some(0x0303), // TLS 1.2 (per RFC 8446 requirement)
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // X448
        AlgorithmCapability {
            group_name: "x448".to_owned(),
            secbits: 224,
            min_tls: Some(0x0303),
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // FFDHE2048
        AlgorithmCapability {
            group_name: "ffdhe2048".to_owned(),
            secbits: 112,
            min_tls: Some(0x0303),
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // FFDHE3072
        AlgorithmCapability {
            group_name: "ffdhe3072".to_owned(),
            secbits: 128,
            min_tls: Some(0x0303),
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // FFDHE4096
        AlgorithmCapability {
            group_name: "ffdhe4096".to_owned(),
            secbits: 152,
            min_tls: Some(0x0303),
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // ML-KEM-768 (post-quantum, TLS 1.3 only)
        AlgorithmCapability {
            group_name: "mlkem768".to_owned(),
            secbits: 192,
            min_tls: Some(0x0304), // TLS 1.3
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // X25519MLKEM768 (hybrid PQ, TLS 1.3 only)
        AlgorithmCapability {
            group_name: "x25519mlkem768".to_owned(),
            secbits: 128,
            min_tls: Some(0x0304),
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
        // SecP256r1MLKEM768 (hybrid PQ, TLS 1.3 only)
        AlgorithmCapability {
            group_name: "secp256r1mlkem768".to_owned(),
            secbits: 128,
            min_tls: Some(0x0304),
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `MethodStore::new()` creates an empty store.
    #[test]
    fn new_store_is_empty() {
        let store = MethodStore::new();
        assert!(store.enumerate_all().is_empty());
    }

    /// Verify `Default` implementation matches `new()`.
    #[test]
    fn default_matches_new() {
        let store = MethodStore::default();
        assert!(store.enumerate_all().is_empty());
    }

    /// Verify basic algorithm registration and enumeration.
    #[test]
    fn register_and_enumerate() {
        let store = MethodStore::new();
        let desc = AlgorithmDescriptor {
            names: vec!["SHA2-256", "SHA-256", "SHA256"],
            property: "provider=default",
            description: "SHA-2 256-bit digest",
        };
        store.register(OperationType::Digest, "default", vec![desc.clone()]);

        let digests = store.enumerate_algorithms(OperationType::Digest);
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].names[0], "SHA2-256");

        // Ciphers should be empty
        let ciphers = store.enumerate_algorithms(OperationType::Cipher);
        assert!(ciphers.is_empty());
    }

    /// Verify `enumerate_all` returns tuples of (op, descriptor).
    #[test]
    fn enumerate_all_includes_operation() {
        let store = MethodStore::new();
        let sha = AlgorithmDescriptor {
            names: vec!["SHA2-256"],
            property: "provider=default",
            description: "SHA-2 256",
        };
        let aes = AlgorithmDescriptor {
            names: vec!["AES-256-GCM"],
            property: "provider=default",
            description: "AES-256 GCM",
        };
        store.register(OperationType::Digest, "default", vec![sha]);
        store.register(OperationType::Cipher, "default", vec![aes]);

        let all = store.enumerate_all();
        assert_eq!(all.len(), 2);
    }

    /// Verify fetch returns a resolved algorithm on hit.
    #[test]
    fn fetch_hit() {
        let store = MethodStore::new();
        let desc = AlgorithmDescriptor {
            names: vec!["SHA2-256", "SHA-256"],
            property: "provider=default",
            description: "SHA-2 256",
        };
        store.register(OperationType::Digest, "default", vec![desc]);

        let result = store.fetch(OperationType::Digest, "SHA2-256", None);
        assert!(result.is_ok());
    }

    /// Verify fetch is case-insensitive.
    #[test]
    fn fetch_case_insensitive() {
        let store = MethodStore::new();
        let desc = AlgorithmDescriptor {
            names: vec!["SHA2-256"],
            property: "provider=default",
            description: "SHA-2 256",
        };
        store.register(OperationType::Digest, "default", vec![desc]);

        let result = store.fetch(OperationType::Digest, "sha2-256", None);
        assert!(result.is_ok());
    }

    /// Verify fetch returns error for missing algorithm.
    #[test]
    fn fetch_miss() {
        let store = MethodStore::new();
        let result = store.fetch(OperationType::Digest, "NONEXISTENT", None);
        assert!(result.is_err());
        match result {
            Err(ProviderError::AlgorithmUnavailable(msg)) => {
                assert!(msg.contains("NONEXISTENT"));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    /// Verify fetch with property query filtering.
    #[test]
    fn fetch_with_property_filter() {
        let store = MethodStore::new();
        let default_sha = AlgorithmDescriptor {
            names: vec!["SHA2-256"],
            property: "provider=default",
            description: "SHA-2 256 default",
        };
        let legacy_sha = AlgorithmDescriptor {
            names: vec!["SHA2-256"],
            property: "provider=legacy",
            description: "SHA-2 256 legacy",
        };
        store.register(OperationType::Digest, "default", vec![default_sha]);
        store.register(OperationType::Digest, "legacy", vec![legacy_sha]);

        // Exact property match
        let result = store.fetch(OperationType::Digest, "SHA2-256", Some("provider=default"));
        assert!(result.is_ok());

        // Negation filter
        let result = store.fetch(OperationType::Digest, "SHA2-256", Some("provider!=legacy"));
        assert!(result.is_ok());
    }

    /// Verify cache flush empties the cache.
    #[test]
    fn flush_cache_clears() {
        let store = MethodStore::new();
        let desc = AlgorithmDescriptor {
            names: vec!["SHA2-256"],
            property: "provider=default",
            description: "SHA-2 256",
        };
        store.register(OperationType::Digest, "default", vec![desc]);

        // Fetch to populate cache
        let _ = store.fetch(OperationType::Digest, "SHA2-256", None);
        store.flush_cache();

        // Cache should be empty, but registry still has the algorithm
        let digests = store.enumerate_algorithms(OperationType::Digest);
        assert_eq!(digests.len(), 1);
    }

    /// Verify provider removal clears algorithms and cache.
    #[test]
    fn remove_provider_clears() {
        let store = MethodStore::new();
        let desc = AlgorithmDescriptor {
            names: vec!["SHA2-256"],
            property: "provider=default",
            description: "SHA-2 256",
        };
        store.register(OperationType::Digest, "default", vec![desc]);

        store.remove_provider("default");
        let digests = store.enumerate_algorithms(OperationType::Digest);
        assert!(digests.is_empty());
    }

    /// Verify property matching helper — exact match.
    #[test]
    fn property_match_exact() {
        assert!(matches_property("provider=default", "provider=default"));
        assert!(!matches_property("provider=default", "provider=legacy"));
    }

    /// Verify property matching helper — negation.
    #[test]
    fn property_match_negation() {
        assert!(matches_property("provider=default", "provider!=legacy"));
        assert!(!matches_property("provider=legacy", "provider!=legacy"));
    }

    /// Verify property matching helper — wildcard.
    #[test]
    fn property_match_wildcard() {
        assert!(matches_property("provider=default", ""));
    }

    /// Verify property matching helper — comma-separated AND.
    #[test]
    fn property_match_multi_term() {
        assert!(matches_property(
            "provider=default,fips=yes",
            "provider=default,fips=yes"
        ));
        assert!(!matches_property(
            "provider=default",
            "provider=default,fips=yes"
        ));
    }

    /// Verify NID resolution for known algorithms.
    #[test]
    fn nid_resolution() {
        assert_eq!(resolve_nid_for_name("SHA-256"), Nid::SHA256);
        assert_eq!(resolve_nid_for_name("RSA"), Nid::RSA);
        assert_eq!(resolve_nid_for_name("UNKNOWN"), Nid::UNDEF);
    }

    /// Verify default TLS group capabilities.
    #[test]
    fn default_capabilities() {
        let store = MethodStore::new();
        let caps = store.get_capabilities("TLS-GROUP");
        assert!(!caps.is_empty());
        // Should contain secp256r1
        assert!(caps.iter().any(|c| c.group_name == "secp256r1"));
        // Should contain x25519
        assert!(caps.iter().any(|c| c.group_name == "x25519"));
    }

    /// Verify custom capabilities override defaults.
    #[test]
    fn custom_capabilities() {
        let store = MethodStore::new();
        let custom = vec![AlgorithmCapability {
            group_name: "custom-group".to_owned(),
            secbits: 256,
            min_tls: None,
            max_tls: None,
            min_dtls: None,
            max_dtls: None,
        }];
        store.set_capabilities("TLS-GROUP", custom);
        let caps = store.get_capabilities("TLS-GROUP");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].group_name, "custom-group");
    }

    /// Verify `AlgorithmCapability::to_param_set()` roundtrip.
    #[test]
    fn capability_to_param_set() {
        let cap = AlgorithmCapability {
            group_name: "secp256r1".to_owned(),
            secbits: 128,
            min_tls: Some(0x0301),
            max_tls: None,
            min_dtls: Some(0xFEFF),
            max_dtls: None,
        };
        let params = cap.to_param_set();
        assert_eq!(
            params.get("group-name").and_then(|v| v.as_str()),
            Some("secp256r1")
        );
        assert_eq!(
            params.get("security-bits").and_then(|v| v.as_u32()),
            Some(128)
        );
        assert!(params.contains("min-tls"));
        assert!(!params.contains("max-tls"));
        assert!(params.contains("min-dtls"));
        assert!(!params.contains("max-dtls"));
    }

    /// Verify `MethodStore` Debug implementation.
    #[test]
    fn debug_display() {
        let store = MethodStore::new();
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("MethodStore"));
        assert!(debug_str.contains("cached_methods"));
    }

    /// Verify `MethodKey` derives Hash/Eq correctly.
    #[test]
    fn method_key_hashable() {
        let key1 = MethodKey {
            operation: OperationType::Digest,
            name: "SHA2-256".to_string(),
            property_query: None,
        };
        let key2 = key1.clone();
        assert_eq!(key1, key2);

        let mut map = HashMap::new();
        map.insert(key1, 42u32);
        assert_eq!(map.get(&key2), Some(&42));
    }

    /// Verify `RegisteredAlgorithm::operation()` accessor.
    #[test]
    fn registered_algorithm_accessor() {
        let ra = RegisteredAlgorithm {
            descriptor: AlgorithmDescriptor {
                names: vec!["SHA2-256"],
                property: "provider=default",
                description: "SHA-2 256",
            },
            provider_name: "default".to_owned(),
            operation: OperationType::Digest,
        };
        assert_eq!(ra.operation(), OperationType::Digest);
    }
}
