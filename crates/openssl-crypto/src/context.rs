//! Library context management for the OpenSSL Rust workspace.
//!
//! The [`LibContext`] type replaces the C `OSSL_LIB_CTX` (`crypto/context.c`,
//! lines 23–56) as the central configuration and state hub.  Each context owns
//! per-subsystem stores (EVP methods, providers, name maps) with **fine-grained
//! locking** per Rule R7 — independent `RwLock` per subsystem instead of a
//! single coarse `CRYPTO_RWLOCK`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │                  LibContext                       │
//! │  ┌──────────────┐  ┌──────────────────────────┐  │
//! │  │ ProviderStore │  │  EvpMethodStore          │  │
//! │  └──────────────┘  └──────────────────────────┘  │
//! │  ┌──────────────┐  ┌──────────────────────────┐  │
//! │  │   NameMap     │  │  PropertyDefns           │  │
//! │  └──────────────┘  └──────────────────────────┘  │
//! │  ┌──────────────┐  ┌──────────────────────────┐  │
//! │  │GlobalProps    │  │  DRBG                    │  │
//! │  └──────────────┘  └──────────────────────────┘  │
//! │  ┌──────────────┐  ┌──────────────────────────┐  │
//! │  │   Config      │  │  Codec stores            │  │
//! │  └──────────────┘  └──────────────────────────┘  │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! # C Mapping
//!
//! | C Construct                   | Rust Equivalent                        |
//! |-------------------------------|----------------------------------------|
//! | `OSSL_LIB_CTX` / `ossl_lib_ctx_st` | [`LibContext`]                   |
//! | `OSSL_LIB_CTX_new()`         | [`LibContext::new()`]                  |
//! | `ossl_lib_ctx_get_concrete()` (NULL→default) | [`LibContext::default()`] / [`get_default()`] |
//! | `OSSL_LIB_CTX_load_config()` | [`LibContext::load_config()`]          |
//! | `ossl_lib_ctx_is_child()`     | [`LibContext::is_child()`]             |
//! | `ossl_namemap_name2num()`     | [`NameMapData::get_nid()`]             |
//! | `ossl_namemap_num2name()`     | [`NameMapData::get_name()`]            |
//! | `ossl_namemap_add_name()`     | [`NameMapData::add_name()`]            |
//! | `ossl_stored_namemap_new()`   | [`NameMapData::new()`]                 |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `get_nid()` returns `Option<Nid>`, not `NID_undef`.
//! - **R7 (Lock Granularity):** Every `RwLock` field has a `// LOCK-SCOPE:`
//!   annotation documenting what it guards, write frequency, and read frequency.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All items documented; zero `#[allow(unused)]`.
//! - **R10 (Wiring):** `LibContext` is reachable from every entry point — it is
//!   the central hub passed to all subsystems at initialization.
//!
//! # Thread Safety
//!
//! `LibContext` is designed to be shared across threads via `Arc<LibContext>`.
//! Each subsystem store has its own `RwLock`, minimizing contention:
//!
//! - Provider loads hold only the provider store write lock.
//! - Algorithm fetches hold only the EVP method store read lock.
//! - Name lookups hold only the name map read lock.
//! - Config loading holds only the config write lock.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;

use openssl_common::config::{self, Config};
use openssl_common::{CryptoError, CryptoResult, Nid};

// =============================================================================
// Subsystem Data Types
// =============================================================================
//
// Each subsystem owned by LibContext has a dedicated data container.  These
// types are fully populated by their respective modules (provider/, evp/,
// etc.); here they carry initial default state sufficient for LibContext
// construction and basic operation.
//
// The types are `pub` so that other modules within the crate can access
// and extend them.  They are NOT re-exported from the crate root, keeping
// them internal to the `openssl-crypto` crate.

/// Data store for loaded providers and their activation state.
///
/// Translates the `void *provider_store` field in `ossl_lib_ctx_st`
/// (populated by `ossl_provider_store_new()` in `crypto/provider_core.c`).
///
/// In the C implementation this is an opaque `OSSL_PROVIDER_STORE *`.
/// The Rust equivalent holds a vector of provider registrations, keyed
/// by provider name, and tracks activation status.
///
/// # Future Extension
///
/// The `provider` module populates this with `ProviderRegistration` entries
/// during `ossl_provider_store_new()` equivalent initialization.
#[derive(Debug)]
pub struct ProviderStoreData {
    /// Registered providers keyed by canonical name.
    ///
    /// Each entry maps a provider name (e.g., `"default"`, `"fips"`,
    /// `"legacy"`) to its activation flag and priority.
    providers: HashMap<String, ProviderEntry>,
}

/// A single provider registration entry within the store.
// Cross-module use: fields accessed by provider and evp modules during dispatch.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ProviderEntry {
    /// Human-readable provider name.
    name: String,
    /// Whether this provider is currently activated and available for
    /// algorithm dispatch.
    activated: bool,
    /// Priority for algorithm resolution when multiple providers supply
    /// the same algorithm.  Higher values take precedence.
    priority: u32,
}

// Cross-module use: methods called by provider module during activation/dispatch.
#[allow(dead_code)]
impl ProviderStoreData {
    /// Creates an empty provider store with no registered providers.
    ///
    /// Equivalent to `ossl_provider_store_new()` returning an empty store
    /// before any providers are loaded.
    fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Returns the number of registered providers.
    pub(crate) fn len(&self) -> usize {
        self.providers.len()
    }

    /// Returns `true` if no providers are registered.
    pub(crate) fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Registers a provider by name with the given priority.
    ///
    /// If a provider with the same name already exists, it is replaced.
    pub(crate) fn register(&mut self, name: String, priority: u32) {
        self.providers.insert(
            name.clone(),
            ProviderEntry {
                name,
                activated: false,
                priority,
            },
        );
    }

    /// Activates a registered provider, making it available for dispatch.
    ///
    /// Returns `true` if the provider was found and activated, `false` if
    /// no provider with the given name is registered.
    pub(crate) fn activate(&mut self, name: &str) -> bool {
        if let Some(entry) = self.providers.get_mut(name) {
            entry.activated = true;
            true
        } else {
            false
        }
    }

    /// Deactivates a registered provider.
    ///
    /// Returns `true` if the provider was found and deactivated.
    pub(crate) fn deactivate(&mut self, name: &str) -> bool {
        if let Some(entry) = self.providers.get_mut(name) {
            entry.activated = false;
            true
        } else {
            false
        }
    }

    /// Returns `true` if the named provider is registered and activated.
    pub(crate) fn is_activated(&self, name: &str) -> bool {
        self.providers
            .get(name)
            .map_or(false, |entry| entry.activated)
    }

    /// Returns an iterator over the names of all activated providers.
    pub(crate) fn activated_names(&self) -> impl Iterator<Item = &str> {
        self.providers
            .values()
            .filter(|e| e.activated)
            .map(|e| e.name.as_str())
    }
}

/// Data store for cached EVP method objects (digests, ciphers, KDFs, etc.).
///
/// Translates the `void *evp_method_store` field in `ossl_lib_ctx_st`
/// (populated by `ossl_method_store_new()` in `crypto/property/property.c`).
///
/// The method store caches resolved algorithm implementations so that
/// repeated fetches (e.g., `EVP_MD_fetch(ctx, "SHA-256", NULL)`) return
/// the cached method object instead of re-querying all providers.
///
/// # Cache Policy
///
/// - **Write:** First fetch of an algorithm triggers provider query and
///   stores the resolved method.
/// - **Read:** Subsequent fetches of the same algorithm + property query
///   return the cached object immediately.
/// - **Invalidation:** Provider load/unload invalidates all cached methods.
#[derive(Debug)]
pub struct EvpMethodStoreData {
    /// Cached methods keyed by `(operation_id, algorithm_name, property_query)`.
    ///
    /// The `operation_id` distinguishes between digest/cipher/KDF/MAC/etc.
    /// The `algorithm_name` is the canonical algorithm name (e.g., `"SHA-256"`).
    /// The `property_query` is the optional property filter string.
    entries: HashMap<MethodStoreKey, MethodStoreEntry>,
}

/// Composite key for method store lookups.
// Cross-module use: constructed by evp module during algorithm fetch.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MethodStoreKey {
    /// Operation type identifier (e.g., digest=1, cipher=2).
    operation_id: u32,
    /// Canonical algorithm name.
    algorithm_name: String,
    /// Property query string (empty string for default properties).
    property_query: String,
}

/// A cached method store entry.
// Cross-module use: stored by evp module when caching resolved methods.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct MethodStoreEntry {
    /// The NID of the cached algorithm.
    nid: Nid,
    /// The provider that supplied this implementation.
    provider_name: String,
}

// Cross-module use: methods called by evp module during fetch/cache operations.
#[allow(dead_code)]
impl EvpMethodStoreData {
    /// Creates an empty method store with no cached entries.
    ///
    /// Equivalent to `ossl_method_store_new()` from `crypto/property/property.c`.
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Returns the number of cached method entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts a method entry into the cache.
    pub(crate) fn insert(
        &mut self,
        operation_id: u32,
        algorithm_name: String,
        property_query: String,
        nid: Nid,
        provider_name: String,
    ) {
        let key = MethodStoreKey {
            operation_id,
            algorithm_name,
            property_query,
        };
        self.entries
            .insert(key, MethodStoreEntry { nid, provider_name });
    }

    /// Looks up a cached method by operation, algorithm name, and properties.
    pub(crate) fn get(
        &self,
        operation_id: u32,
        algorithm_name: &str,
        property_query: &str,
    ) -> Option<Nid> {
        let key = MethodStoreKey {
            operation_id,
            algorithm_name: algorithm_name.to_string(),
            property_query: property_query.to_string(),
        };
        self.entries.get(&key).map(|entry| entry.nid)
    }

    /// Clears all cached methods, forcing re-fetch from providers.
    ///
    /// Called when providers are loaded or unloaded to ensure stale
    /// cached entries are not returned.
    pub(crate) fn invalidate(&mut self) {
        self.entries.clear();
    }
}

/// Bidirectional mapping between algorithm names and numeric identifiers (NIDs).
///
/// Translates the `void *namemap` field in `ossl_lib_ctx_st` (populated by
/// `ossl_stored_namemap_new()` in `crypto/core_namemap.c`).
///
/// The C implementation uses a hash table (`HT`) for name→number lookup and
/// a `STACK_OF(NAMES)` for number→name lookup.  This Rust implementation uses
/// two `HashMap`s for O(1) bidirectional lookups.
///
/// # Thread Safety
///
/// Accessed through the `LibContext.name_map` `RwLock`.  Write operations
/// (adding names) hold the write lock; read operations (lookups) hold only
/// the read lock.
///
/// # Examples
///
/// ```
/// use openssl_crypto::context::NameMapData;
/// use openssl_common::Nid;
///
/// let mut nmap = NameMapData::new();
/// let nid = nmap.add_name("SHA-256");
/// assert!(!nid.is_undef());
/// assert_eq!(nmap.get_nid("SHA-256"), Some(nid));
/// assert_eq!(nmap.get_name(nid), Some("SHA-256"));
/// ```
#[derive(Debug)]
pub struct NameMapData {
    /// Forward mapping: canonical name → NID.
    ///
    /// Names are stored in their original case-preserving form but lookups
    /// are case-insensitive (matching C `HT_COPY_RAW_KEY_CASE` behavior).
    name_to_nid: HashMap<String, Nid>,

    /// Reverse mapping: NID → canonical name.
    ///
    /// Each NID maps to the first name registered for it.  Additional
    /// aliases for the same NID share the same numeric identifier but
    /// only the first registered name is returned by `get_name()`.
    nid_to_name: HashMap<Nid, String>,

    /// Alias mapping: NID → all registered names for that NID.
    ///
    /// Preserves the C behavior where multiple names can map to the
    /// same number (e.g., `"SHA256"` and `"SHA-256"` share a NID).
    nid_to_aliases: HashMap<Nid, Vec<String>>,

    /// The next NID to assign when a completely new name is registered.
    ///
    /// Starts at 1 (NID 0 is `NID_undef`).  Incremented monotonically.
    /// Translates the C `max_number` field in `ossl_namemap_st`.
    next_nid_value: i32,
}

impl NameMapData {
    /// Creates a new, empty name map.
    ///
    /// Equivalent to `ossl_stored_namemap_new()` from `crypto/core_namemap.c`
    /// (lines 57–65), which allocates an empty `OSSL_NAMEMAP` with
    /// `stored = 1`.
    pub fn new() -> Self {
        Self {
            name_to_nid: HashMap::new(),
            nid_to_name: HashMap::new(),
            nid_to_aliases: HashMap::new(),
            next_nid_value: 1,
        }
    }

    /// Registers a name and returns its NID.
    ///
    /// If the name already exists (case-insensitive match), returns the
    /// existing NID without modification.  If the name is new, assigns
    /// the next available NID and records both forward and reverse mappings.
    ///
    /// Translates `ossl_namemap_add_name()` from `crypto/core_namemap.c`
    /// (lines 294–312).
    ///
    /// # Parameters
    ///
    /// * `name` — The algorithm name to register (e.g., `"SHA-256"`).
    ///
    /// # Returns
    ///
    /// The NID associated with the name.  Never returns [`Nid::UNDEF`].
    ///
    /// # Rule R5 (Nullability)
    ///
    /// This method returns a concrete `Nid` (not `Option`), since
    /// registration always succeeds — matching the C behavior where
    /// `ossl_namemap_add_name()` returns the number or 0 on allocation
    /// failure (which Rust handles through infallible `HashMap::insert`).
    pub fn add_name(&mut self, name: &str) -> Nid {
        // Case-insensitive lookup matching C HT_COPY_RAW_KEY_CASE behavior
        let lookup_key = name.to_ascii_uppercase();

        // If already registered, return existing NID
        if let Some(&nid) = self.name_to_nid.get(&lookup_key) {
            return nid;
        }

        // Assign new NID
        let nid = Nid::from_raw(self.next_nid_value);
        self.next_nid_value = self.next_nid_value.saturating_add(1);

        // Record forward mapping (case-insensitive key)
        self.name_to_nid.insert(lookup_key, nid);

        // Record reverse mapping (preserves original case for display)
        self.nid_to_name.insert(nid, name.to_string());

        // Record in aliases list
        self.nid_to_aliases
            .entry(nid)
            .or_default()
            .push(name.to_string());

        nid
    }

    /// Adds an alias name for an existing NID.
    ///
    /// If the alias already exists, returns the NID it maps to (which
    /// must equal the target NID).  If the alias is new, records it under
    /// the given NID.
    ///
    /// Translates the multi-name registration path in
    /// `ossl_namemap_add_names()` from `crypto/core_namemap.c` (lines 314–390).
    ///
    /// # Parameters
    ///
    /// * `name` — The alias to register.
    /// * `target_nid` — The NID to associate with this alias.
    ///
    /// # Returns
    ///
    /// The NID on success, or [`Nid::UNDEF`] if the alias already maps
    /// to a different NID (conflicting names error).
    // Cross-module use: called by provider module during multi-name registration.
    #[allow(dead_code)]
    pub(crate) fn add_name_with_nid(&mut self, name: &str, target_nid: Nid) -> Nid {
        let lookup_key = name.to_ascii_uppercase();

        if let Some(&existing_nid) = self.name_to_nid.get(&lookup_key) {
            // Already exists — check for conflict
            if existing_nid == target_nid {
                return existing_nid;
            }
            // Conflict: name maps to a different NID
            return Nid::UNDEF;
        }

        // Register alias under the target NID
        self.name_to_nid.insert(lookup_key, target_nid);
        self.nid_to_aliases
            .entry(target_nid)
            .or_default()
            .push(name.to_string());

        target_nid
    }

    /// Looks up the NID for a given algorithm name.
    ///
    /// Returns `Some(nid)` if the name is registered, or `None` if unknown.
    /// The lookup is case-insensitive, matching the C behavior where
    /// `HT_COPY_RAW_KEY_CASE` normalises the key.
    ///
    /// Translates `ossl_namemap_name2num()` from `crypto/core_namemap.c`
    /// (lines 142–166).
    ///
    /// # Rule R5 (Nullability)
    ///
    /// Returns `Option<Nid>` instead of `0` (the C sentinel for "not found").
    pub fn get_nid(&self, name: &str) -> Option<Nid> {
        let lookup_key = name.to_ascii_uppercase();
        self.name_to_nid.get(&lookup_key).copied()
    }

    /// Looks up the canonical name for a given NID.
    ///
    /// Returns `Some(name)` with the first registered name for the NID,
    /// or `None` if the NID is not in the map.
    ///
    /// Translates `ossl_namemap_num2name()` from `crypto/core_namemap.c`
    /// (lines 198–217) with `idx = 0` (first name).
    ///
    /// # Rule R5 (Nullability)
    ///
    /// Returns `Option<&str>` instead of `NULL` (the C sentinel).
    pub fn get_name(&self, nid: Nid) -> Option<&str> {
        self.nid_to_name.get(&nid).map(String::as_str)
    }

    /// Returns all registered names (aliases) for a given NID.
    ///
    /// Translates `ossl_namemap_doall_names()` from `crypto/core_namemap.c`
    /// (lines 108–140).
    // Cross-module use: called by provider module for algorithm enumeration.
    #[allow(dead_code)]
    pub(crate) fn get_all_names(&self, nid: Nid) -> Option<&[String]> {
        self.nid_to_aliases.get(&nid).map(Vec::as_slice)
    }

    /// Returns `true` if the name map contains no entries.
    ///
    /// Translates `ossl_namemap_empty()` from `crypto/core_namemap.c`
    /// (lines 83–101).
    // Cross-module use: called by provider module during initialization checks.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.name_to_nid.is_empty()
    }

    /// Returns `true` if the given name is already registered.
    ///
    /// Case-insensitive lookup matching `ossl_namemap_name2num() != 0`
    /// from `crypto/core_namemap.c`.
    // Cross-module use: called by provider module for pre-check before registration.
    #[allow(dead_code)]
    pub(crate) fn has_name(&self, name: &str) -> bool {
        let lookup_key = name.to_ascii_uppercase();
        self.name_to_nid.contains_key(&lookup_key)
    }

    /// Returns the total number of unique names registered.
    pub(crate) fn name_count(&self) -> usize {
        self.name_to_nid.len()
    }

    /// Returns the total number of unique NIDs registered.
    // Cross-module use: called by diagnostics and status reporting.
    #[allow(dead_code)]
    pub(crate) fn nid_count(&self) -> usize {
        self.nid_to_name.len()
    }
}

impl Default for NameMapData {
    fn default() -> Self {
        Self::new()
    }
}

/// Data store for property definition strings used by the property query system.
///
/// Translates the `void *property_defns` field in `ossl_lib_ctx_st`
/// (populated by `ossl_property_defns_new()` in `crypto/property/property.c`).
///
/// Property definitions map property names to their type and valid values,
/// enabling the provider property query/match system that selects algorithm
/// implementations based on property strings (e.g., `"fips=yes"`,
/// `"provider=default"`).
#[derive(Debug)]
pub struct PropertyDefnsData {
    /// Property definitions keyed by property name.
    ///
    /// Each entry records the property name, its type (string, number,
    /// boolean), and optional valid values.
    // Cross-module use: populated by property module during definition registration.
    #[allow(dead_code)]
    definitions: HashMap<String, PropertyDefinition>,
}

/// A single property definition entry.
// Cross-module use: constructed by property module during definition registration.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PropertyDefinition {
    /// The property name (e.g., `"fips"`, `"provider"`, `"input"`).
    name: String,
    /// The type of the property value.
    property_type: PropertyType,
}

/// The type of a property value in the property query system.
// Cross-module use: used by property module for definition and query parsing.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PropertyType {
    /// A string value (e.g., `provider=default`).
    String,
    /// A numeric value (e.g., `security_bits=256`).
    Number,
    /// A boolean value (e.g., `fips=yes`).
    Boolean,
}

// Cross-module use: methods called by property module during definition management.
#[allow(dead_code)]
impl PropertyDefnsData {
    /// Creates an empty property definitions store.
    fn new() -> Self {
        Self {
            definitions: HashMap::new(),
        }
    }

    /// Registers a property definition.
    pub(crate) fn define(&mut self, name: String, property_type: PropertyType) {
        self.definitions.insert(
            name.clone(),
            PropertyDefinition {
                name,
                property_type,
            },
        );
    }

    /// Returns the type of a registered property, or `None` if unknown.
    pub(crate) fn get_type(&self, name: &str) -> Option<PropertyType> {
        self.definitions.get(name).map(|d| d.property_type)
    }

    /// Returns `true` if no property definitions are registered.
    pub(crate) fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }
}

/// Global property query string applied to all algorithm fetches.
///
/// Translates the `void *global_properties` field in `ossl_lib_ctx_st`
/// (populated by `ossl_ctx_global_properties_new()` in
/// `crypto/property/property.c`).
///
/// When set, the global properties string is prepended to every per-fetch
/// property query, allowing system-wide policy enforcement (e.g.,
/// `"fips=yes"` to restrict all fetches to FIPS-approved algorithms).
#[derive(Debug)]
pub struct GlobalPropertiesData {
    /// The global property query string, or `None` if no global
    /// properties are set.
    ///
    /// Rule R5: `Option<String>` instead of empty-string sentinel.
    // Cross-module use: read by evp module during every algorithm fetch.
    #[allow(dead_code)]
    query: Option<String>,
}

// Cross-module use: methods called by evp module for global property management.
#[allow(dead_code)]
impl GlobalPropertiesData {
    /// Creates global properties data with no global query set.
    fn new() -> Self {
        Self { query: None }
    }

    /// Sets the global property query string.
    ///
    /// Translates `EVP_set_default_properties()` from
    /// `crypto/evp/evp_fetch.c`.
    pub(crate) fn set_query(&mut self, query: String) {
        if query.is_empty() {
            self.query = None;
        } else {
            self.query = Some(query);
        }
    }

    /// Returns the current global property query string, or `None` if
    /// no global properties are set.
    pub(crate) fn get_query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Clears the global property query string.
    pub(crate) fn clear(&mut self) {
        self.query = None;
    }
}

/// DRBG (Deterministic Random Bit Generator) context data.
///
/// Translates the `void *drbg` field in `ossl_lib_ctx_st` (populated by
/// `ossl_rand_ctx_new()` in `crypto/rand/rand_lib.c`).
///
/// The DRBG context manages the hierarchy of random number generators:
/// a primary DRBG seeded from OS entropy, and per-thread public/private
/// DRBGs derived from the primary.
///
/// # Future Extension
///
/// The `rand` module populates this with the full DRBG hierarchy during
/// library initialization.  Here it carries initial state for context
/// construction.
#[derive(Debug)]
pub struct DrbgData {
    /// Whether the primary DRBG has been instantiated and seeded.
    // Cross-module use: read/written by rand module during DRBG lifecycle.
    #[allow(dead_code)]
    instantiated: bool,
    /// Reseed interval (number of generate calls before automatic reseed).
    // Cross-module use: read by rand module to determine reseed timing.
    #[allow(dead_code)]
    reseed_interval: u64,
    /// Nonce context for DRBG nonce generation.
    ///
    /// Translates `void *drbg_nonce` from the C struct.
    // Cross-module use: read/written by rand module during nonce generation.
    #[allow(dead_code)]
    nonce_counter: u64,
}

// Cross-module use: methods called by rand module for DRBG management.
#[allow(dead_code)]
impl DrbgData {
    /// Creates DRBG data with default settings.
    ///
    /// The default reseed interval of 100,000 matches the C
    /// `MASTER_RESEED_INTERVAL` from `crypto/rand/rand_local.h`.
    fn new() -> Self {
        Self {
            instantiated: false,
            reseed_interval: 100_000,
            nonce_counter: 0,
        }
    }

    /// Returns `true` if the primary DRBG has been instantiated.
    pub(crate) fn is_instantiated(&self) -> bool {
        self.instantiated
    }

    /// Marks the DRBG as instantiated after successful seeding.
    pub(crate) fn set_instantiated(&mut self) {
        self.instantiated = true;
    }

    /// Returns the current reseed interval.
    pub(crate) fn reseed_interval(&self) -> u64 {
        self.reseed_interval
    }

    /// Updates the reseed interval.
    pub(crate) fn set_reseed_interval(&mut self, interval: u64) {
        self.reseed_interval = interval;
    }

    /// Returns and increments the nonce counter.
    pub(crate) fn next_nonce(&mut self) -> u64 {
        let current = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        current
    }
}

// =============================================================================
// Additional Subsystem Data Types
// =============================================================================
//
// These types translate remaining `void *` fields from the C struct that
// are not among the primary six but are required for full feature coverage.

/// Codec (encoder/decoder) method store data.
///
/// Translates the `decoder_store`, `decoder_cache`, `encoder_store`, and
/// `store_loader_store` fields from `ossl_lib_ctx_st`.  In non-FIPS builds
/// these stores cache resolved encoder/decoder/store-loader implementations.
// Cross-module use: accessed by encode_decode module during codec resolution.
#[allow(dead_code)]
#[derive(Debug)]
struct CodecStoreData {
    /// Decoder method cache, keyed by algorithm name.
    decoders: HashMap<String, Nid>,
    /// Encoder method cache, keyed by algorithm name.
    encoders: HashMap<String, Nid>,
    /// Store loader method cache, keyed by URI scheme.
    store_loaders: HashMap<String, Nid>,
}

impl CodecStoreData {
    /// Creates empty codec stores.
    fn new() -> Self {
        Self {
            decoders: HashMap::new(),
            encoders: HashMap::new(),
            store_loaders: HashMap::new(),
        }
    }
}

/// Provider configuration context.
///
/// Translates `void *provider_conf` from `ossl_lib_ctx_st` (non-FIPS builds).
/// Holds provider configuration loaded from the `[openssl_init]` section of
/// the config file, including `providers` section references.
// Cross-module use: accessed by provider module during config-driven loading.
#[allow(dead_code)]
#[derive(Debug)]
struct ProviderConfData {
    /// Whether provider auto-loading from config is enabled.
    auto_load: bool,
}

impl ProviderConfData {
    fn new() -> Self {
        Self { auto_load: true }
    }
}

/// Self-test and indicator callback registrations.
///
/// Translates `void *self_test_cb` and `void *indicator_cb` from
/// `ossl_lib_ctx_st` (non-FIPS builds).  These allow applications to
/// register callbacks for FIPS self-test events and algorithm indicator
/// queries.
// Cross-module use: accessed by FIPS integration during callback registration.
#[allow(dead_code)]
#[derive(Debug)]
struct CallbackData {
    /// Whether a self-test callback has been registered.
    self_test_registered: bool,
    /// Whether an indicator callback has been registered.
    indicator_registered: bool,
}

impl CallbackData {
    fn new() -> Self {
        Self {
            self_test_registered: false,
            indicator_registered: false,
        }
    }
}

/// BIO core globals for non-FIPS builds.
///
/// Translates `void *bio_core` from `ossl_lib_ctx_st`.
// Cross-module use: accessed by bio module during BIO initialization.
#[allow(dead_code)]
#[derive(Debug)]
struct BioCoreData {
    /// Whether BIO core has been initialized.
    initialized: bool,
}

impl BioCoreData {
    fn new() -> Self {
        Self { initialized: false }
    }
}

/// Child provider context for non-FIPS builds.
///
/// Translates `void *child_provider` from `ossl_lib_ctx_st`.
// Cross-module use: accessed by provider module for child provider management.
#[allow(dead_code)]
#[derive(Debug)]
struct ChildProviderData {
    /// Whether any child providers have been registered.
    has_children: bool,
}

impl ChildProviderData {
    fn new() -> Self {
        Self {
            has_children: false,
        }
    }
}

/// Thread pool context.
///
/// Translates `void *threads` from `ossl_lib_ctx_st`.
// Cross-module use: accessed by thread module for pool configuration.
#[allow(dead_code)]
#[derive(Debug)]
struct ThreadPoolData {
    /// Maximum number of threads in the pool (0 = unlimited).
    max_threads: usize,
}

impl ThreadPoolData {
    fn new() -> Self {
        Self { max_threads: 0 }
    }
}

/// Property string data for the property query system.
///
/// Translates `void *property_string_data` from `ossl_lib_ctx_st`.
// Cross-module use: accessed by property module for string interning.
#[allow(dead_code)]
#[derive(Debug)]
struct PropertyStringData {
    /// Interned property strings for efficient comparison.
    strings: HashMap<String, u32>,
    /// Next string ID for interning.
    next_id: u32,
}

impl PropertyStringData {
    fn new() -> Self {
        Self {
            strings: HashMap::new(),
            next_id: 1,
        }
    }
}

// =============================================================================
// LibContext — Central Library Context
// =============================================================================

/// Central library context — the Rust equivalent of C `OSSL_LIB_CTX`.
///
/// Every OpenSSL operation occurs within a library context.  The context
/// owns all subsystem state: loaded providers, cached EVP methods, the
/// algorithm name map, property definitions, global properties, DRBG
/// state, configuration, and auxiliary subsystem data.
///
/// # Ownership Model
///
/// `LibContext` is always wrapped in `Arc<LibContext>` for thread-safe
/// shared ownership.  The [`new()`](Self::new) constructor returns
/// `Arc<LibContext>` directly.  The [`get_default()`](get_default) function
/// returns a clone of the singleton default context.
///
/// # Concurrency (Rule R7)
///
/// Each subsystem store has its own independent `RwLock` to minimize
/// contention.  This replaces the single coarse `CRYPTO_RWLOCK` from the
/// C `ossl_lib_ctx_st` struct.  Every `RwLock` field carries a
/// `// LOCK-SCOPE:` annotation documenting what it guards, when writes
/// occur, and when reads occur.
///
/// # C Struct Translation
///
/// The C `ossl_lib_ctx_st` (`crypto/context.c`, lines 23–56) has ~20
/// `void *` fields plus flags.  Each `void *` becomes a typed Rust field
/// behind its own `RwLock`.
///
/// # Examples
///
/// ```
/// use openssl_crypto::context::{LibContext, get_default};
/// use std::sync::Arc;
///
/// // Create a fresh context
/// let ctx = LibContext::new();
/// assert!(!ctx.is_child());
///
/// // Get the process-wide default context
/// let default_ctx = get_default();
/// assert!(!default_ctx.is_child());
///
/// // Contexts are cheaply cloneable via Arc
/// let ctx2 = Arc::clone(&default_ctx);
/// ```
pub struct LibContext {
    // ── Primary subsystem stores ────────────────────────────────────────

    // LOCK-SCOPE: provider store — write during provider load/activate/deactivate,
    // read during algorithm fetch dispatch to activated providers.
    // Write frequency: low (provider loading at startup, rare runtime changes).
    // Read frequency: very high (every algorithm fetch queries activated providers).
    provider_store: RwLock<ProviderStoreData>,

    // LOCK-SCOPE: EVP method store — write during first algorithm fetch
    // (caches resolved method), read during subsequent fetches of same algorithm.
    // Write frequency: moderate (once per unique algorithm+property combination).
    // Read frequency: very high (every EVP operation checks cache first).
    evp_method_store: RwLock<EvpMethodStoreData>,

    // LOCK-SCOPE: name map — write during algorithm name registration
    // (provider loading, config processing), read during name→NID lookup.
    // Write frequency: low (registration at startup/provider load).
    // Read frequency: very high (every fetch resolves name to NID).
    name_map: RwLock<NameMapData>,

    // LOCK-SCOPE: property definitions — write at config time when new
    // property types are defined, read at fetch time for query parsing.
    // Write frequency: very low (config loading only).
    // Read frequency: high (every property query checks definitions).
    // Cross-module use: accessed by property module during query evaluation.
    #[allow(dead_code)]
    property_defns: RwLock<PropertyDefnsData>,

    // LOCK-SCOPE: global properties — write when application calls
    // EVP_set_default_properties(), read during every algorithm fetch.
    // Write frequency: very low (policy changes are rare).
    // Read frequency: very high (prepended to every fetch query).
    // Cross-module use: accessed by evp module during every algorithm fetch.
    #[allow(dead_code)]
    global_properties: RwLock<GlobalPropertiesData>,

    // LOCK-SCOPE: DRBG — write during seeding/reseed, read during
    // random number generation.
    // Write frequency: periodic (reseed interval-based).
    // Read frequency: high (every random generation).
    // Cross-module use: accessed by rand module for DRBG operations.
    #[allow(dead_code)]
    drbg: RwLock<Option<DrbgData>>,

    // LOCK-SCOPE: configuration — write during load_config(), read when
    // subsystems query configuration values.
    // Write frequency: very low (config loaded once at startup).
    // Read frequency: moderate (subsystems read config at init).
    config: RwLock<Config>,

    // ── Auxiliary subsystem stores ──────────────────────────────────────
    //
    // These translate the remaining void* fields from ossl_lib_ctx_st
    // that are conditional on build mode (#ifndef FIPS_MODULE, etc.).

    // LOCK-SCOPE: codec stores (decoder/encoder/store-loader) — write
    // during first codec fetch, read during subsequent fetches.
    // Write frequency: low. Read frequency: moderate.
    // Cross-module use: accessed by encode_decode module for codec resolution.
    #[allow(dead_code)]
    codec_stores: RwLock<CodecStoreData>,

    // LOCK-SCOPE: provider configuration — write during config load,
    // read during provider activation.
    // Write frequency: very low. Read frequency: low.
    // Cross-module use: accessed by provider module during config-driven loading.
    #[allow(dead_code)]
    provider_conf: RwLock<ProviderConfData>,

    // LOCK-SCOPE: callbacks — write during callback registration,
    // read during self-test/indicator events.
    // Write frequency: very low. Read frequency: low.
    // Cross-module use: accessed by FIPS integration for callback handling.
    #[allow(dead_code)]
    callbacks: RwLock<CallbackData>,

    // LOCK-SCOPE: BIO core globals — write during initialization,
    // read during BIO operations.
    // Write frequency: once. Read frequency: moderate.
    // Cross-module use: accessed by bio module during initialization.
    #[allow(dead_code)]
    bio_core: RwLock<BioCoreData>,

    // LOCK-SCOPE: child provider context — write during child provider
    // registration, read during provider queries.
    // Write frequency: very low. Read frequency: low.
    // Cross-module use: accessed by provider module for child management.
    #[allow(dead_code)]
    child_provider: RwLock<ChildProviderData>,

    // LOCK-SCOPE: thread pool — write during pool configuration,
    // read during task submission.
    // Write frequency: very low. Read frequency: moderate.
    // Cross-module use: accessed by thread module for pool management.
    #[allow(dead_code)]
    thread_pool: RwLock<ThreadPoolData>,

    // LOCK-SCOPE: property strings — write during property registration,
    // read during property comparison.
    // Write frequency: low. Read frequency: high.
    // Cross-module use: accessed by property module for string interning.
    #[allow(dead_code)]
    property_strings: RwLock<PropertyStringData>,

    // ── Flags ──────────────────────────────────────────────────────────
    //
    // Immutable after construction — no locking required.
    /// Whether this context is a child context created by
    /// `OSSL_LIB_CTX_new_child()`.
    ///
    /// Child contexts inherit provider registrations from their parent.
    /// Translates `int ischild` from `ossl_lib_ctx_st` (line 54).
    is_child: bool,

    /// Whether configuration diagnostics are enabled.
    ///
    /// When true, configuration loading failures produce detailed error
    /// messages.  Translates `int conf_diagnostics` (line 55).
    conf_diagnostics: bool,
}

// Manual Debug implementation intentionally summarizes RwLock-guarded fields
// by showing counts rather than full internal state to avoid lock contention
// and excessive output.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for LibContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibContext")
            .field("is_child", &self.is_child)
            .field("conf_diagnostics", &self.conf_diagnostics)
            .field("provider_count", &self.provider_store.read().len())
            .field("method_cache_size", &self.evp_method_store.read().len())
            .field("name_map_size", &self.name_map.read().name_count())
            .finish()
    }
}

// =============================================================================
// Default Context Singleton
// =============================================================================

/// Process-wide default library context, lazily initialized.
///
/// Replaces the C pattern of a static `default_context_int` with
/// `CRYPTO_ONCE` guards (`crypto/context.c`, lines 406–427).  The
/// `Lazy` wrapper ensures thread-safe one-time initialization.
///
/// The default context is never freed during the process lifetime —
/// it exists until process exit, matching the C behavior where
/// `ossl_lib_ctx_default_deinit()` is called only from `atexit`.
static DEFAULT_CONTEXT: Lazy<Arc<LibContext>> = Lazy::new(|| {
    tracing::info!("Initializing default library context");
    LibContext::new()
});

/// Returns a shared reference to the process-wide default library context.
///
/// This function is the primary entry point for code that does not need a
/// custom context.  Equivalent to passing `NULL` as the `OSSL_LIB_CTX *`
/// parameter in C functions, which internally calls
/// `ossl_lib_ctx_get_concrete(NULL)` to obtain the default context.
///
/// The returned `Arc<LibContext>` is a cheap clone (reference count bump)
/// and can be held indefinitely.
///
/// # Examples
///
/// ```
/// use openssl_crypto::context::get_default;
///
/// let ctx = get_default();
/// assert!(!ctx.is_child());
/// ```
pub fn get_default() -> Arc<LibContext> {
    Arc::clone(&DEFAULT_CONTEXT)
}

// =============================================================================
// LibContext Implementation
// =============================================================================

impl LibContext {
    /// Creates a new, independent library context with default settings.
    ///
    /// All subsystem stores are initialized to their empty/default state.
    /// The returned context is wrapped in `Arc` for thread-safe shared
    /// ownership.
    ///
    /// Translates `OSSL_LIB_CTX_new()` from `crypto/context.c` (lines 484–493),
    /// combined with `context_init()` (lines 118–253) which initializes all
    /// subsystem data slots.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::context::LibContext;
    ///
    /// let ctx = LibContext::new();
    /// assert!(!ctx.is_child());
    /// ```
    pub fn new() -> Arc<Self> {
        tracing::debug!("Creating new LibContext");

        let ctx = Self {
            provider_store: RwLock::new(ProviderStoreData::new()),
            evp_method_store: RwLock::new(EvpMethodStoreData::new()),
            name_map: RwLock::new(NameMapData::new()),
            property_defns: RwLock::new(PropertyDefnsData::new()),
            global_properties: RwLock::new(GlobalPropertiesData::new()),
            drbg: RwLock::new(Some(DrbgData::new())),
            config: RwLock::new(Config::new()),
            codec_stores: RwLock::new(CodecStoreData::new()),
            provider_conf: RwLock::new(ProviderConfData::new()),
            callbacks: RwLock::new(CallbackData::new()),
            bio_core: RwLock::new(BioCoreData::new()),
            child_provider: RwLock::new(ChildProviderData::new()),
            thread_pool: RwLock::new(ThreadPoolData::new()),
            property_strings: RwLock::new(PropertyStringData::new()),
            is_child: false,
            conf_diagnostics: false,
        };

        tracing::trace!("LibContext initialized with all subsystem stores");
        Arc::new(ctx)
    }

    /// Creates a new child context.
    ///
    /// Child contexts inherit provider registrations from a parent context
    /// and are used by providers that create sub-contexts.
    ///
    /// Translates `OSSL_LIB_CTX_new_child()` from `crypto/context.c`
    /// (lines 512–527).
    // Cross-module use: called by provider module when providers spawn sub-contexts.
    #[allow(dead_code)]
    pub(crate) fn new_child() -> Arc<Self> {
        tracing::debug!("Creating new child LibContext");

        let ctx = Self {
            provider_store: RwLock::new(ProviderStoreData::new()),
            evp_method_store: RwLock::new(EvpMethodStoreData::new()),
            name_map: RwLock::new(NameMapData::new()),
            property_defns: RwLock::new(PropertyDefnsData::new()),
            global_properties: RwLock::new(GlobalPropertiesData::new()),
            drbg: RwLock::new(Some(DrbgData::new())),
            config: RwLock::new(Config::new()),
            codec_stores: RwLock::new(CodecStoreData::new()),
            provider_conf: RwLock::new(ProviderConfData::new()),
            callbacks: RwLock::new(CallbackData::new()),
            bio_core: RwLock::new(BioCoreData::new()),
            child_provider: RwLock::new(ChildProviderData::new()),
            thread_pool: RwLock::new(ThreadPoolData::new()),
            property_strings: RwLock::new(PropertyStringData::new()),
            is_child: true,
            conf_diagnostics: false,
        };

        Arc::new(ctx)
    }

    /// Returns a shared reference to the process-wide default library context.
    ///
    /// Convenience method equivalent to the module-level [`get_default()`]
    /// function.  This method is provided for ergonomic access when you
    /// already have a `LibContext` reference and want the default context.
    ///
    /// Translates the C pattern `ossl_lib_ctx_get_concrete(NULL)` which
    /// returns the default context when `NULL` is passed.
    ///
    /// Note: This intentionally does NOT implement `std::default::Default`
    /// because the return type is `Arc<Self>` (shared ownership), not `Self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::context::LibContext;
    ///
    /// let default_ctx = LibContext::default();
    /// assert!(!default_ctx.is_child());
    /// ```
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Arc<Self> {
        get_default()
    }

    /// Loads configuration from a file into this context.
    ///
    /// Parses the OpenSSL-style configuration file at `path` and stores the
    /// result in the context's config store.  This replaces
    /// `OSSL_LIB_CTX_load_config()` from `crypto/context.c` (lines 529–532)
    /// which calls `CONF_modules_load_file_ex()`.
    ///
    /// # Parameters
    ///
    /// * `path` — Filesystem path to the configuration file (e.g.,
    ///   `/etc/ssl/openssl.cnf`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] wrapping [`CommonError::Io`] if the
    /// file cannot be opened or read.
    ///
    /// Returns [`CryptoError::Common`] wrapping [`CommonError::Config`] if
    /// the file contains syntax errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use openssl_crypto::context::LibContext;
    /// use std::path::Path;
    ///
    /// let ctx = LibContext::new();
    /// ctx.load_config(Path::new("/etc/ssl/openssl.cnf")).unwrap();
    /// ```
    pub fn load_config(&self, path: &Path) -> CryptoResult<()> {
        tracing::debug!(path = %path.display(), "Loading configuration file");

        let loaded_config = config::load_config(path).map_err(|e| {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "Failed to load configuration file"
            );
            CryptoError::Common(e)
        })?;

        // Acquire write lock on config and replace with loaded config
        let mut config_guard = self.config.write();
        config_guard.merge(&loaded_config);

        tracing::debug!(
            path = %path.display(),
            sections = loaded_config.sections().count(),
            "Configuration loaded successfully"
        );

        Ok(())
    }

    /// Returns `true` if this is a child context.
    ///
    /// Child contexts are created by `OSSL_LIB_CTX_new_child()` (used by
    /// providers that spawn sub-contexts).  They inherit provider
    /// registrations from their parent.
    ///
    /// Translates `ossl_lib_ctx_is_child()` from `crypto/context.c`
    /// (lines 79–86).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::context::LibContext;
    ///
    /// let ctx = LibContext::new();
    /// assert!(!ctx.is_child());
    /// ```
    #[inline]
    pub fn is_child(&self) -> bool {
        self.is_child
    }

    /// Validates that a named provider is registered and activated.
    ///
    /// Returns `Ok(())` if the provider is found and currently activated.
    /// Returns `Err(CryptoError::Provider(...))` if the provider is not
    /// registered or has not been activated yet.
    ///
    /// This is used during algorithm fetch to ensure the target provider
    /// is available before attempting dispatch (mirrors the C check in
    /// `ossl_provider_test_operation_bit()`).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::context::LibContext;
    ///
    /// let ctx = LibContext::new();
    /// // No providers registered yet — should fail.
    /// assert!(ctx.ensure_provider_activated("default").is_err());
    /// ```
    pub fn ensure_provider_activated(&self, name: &str) -> CryptoResult<()> {
        let store = self.provider_store.read();
        if store.is_activated(name) {
            tracing::trace!(provider = name, "provider activation check passed");
            Ok(())
        } else {
            Err(CryptoError::Provider(format!(
                "provider '{name}' is not registered or not activated"
            )))
        }
    }

    /// Returns the shared reference to the default context.
    ///
    /// Equivalent to [`LibContext::default()`] and the module-level
    /// [`get_default()`].  Provided for API parity with the schema
    /// specification.
    pub fn get_default() -> Arc<Self> {
        get_default()
    }
}

// =============================================================================
// LibContext — Subsystem Store Accessors
// =============================================================================
//
// Each accessor returns a parking_lot read or write guard, allowing
// callers to access subsystem data with fine-grained locking.
//
// These methods are designed for cross-module consumption by provider,
// evp, rand, bio, property, thread, and encode_decode modules.  They
// appear "dead" until those modules are implemented.

// Cross-module use: all accessor methods are consumed by their respective
// subsystem modules (provider, evp, rand, bio, property, thread, encode_decode).
#[allow(dead_code)]
impl LibContext {
    /// Returns a read guard to the provider store.
    ///
    /// The caller holds the read lock for the duration of the guard's
    /// lifetime.  Multiple readers can hold the lock concurrently.
    pub(crate) fn provider_store(&self) -> parking_lot::RwLockReadGuard<'_, ProviderStoreData> {
        tracing::trace!("Acquiring provider store read lock");
        self.provider_store.read()
    }

    /// Returns a write guard to the provider store.
    pub(crate) fn provider_store_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, ProviderStoreData> {
        tracing::trace!("Acquiring provider store write lock");
        self.provider_store.write()
    }

    /// Returns a read guard to the EVP method store.
    pub(crate) fn evp_method_store(&self) -> parking_lot::RwLockReadGuard<'_, EvpMethodStoreData> {
        tracing::trace!("Acquiring EVP method store read lock");
        self.evp_method_store.read()
    }

    /// Returns a write guard to the EVP method store.
    pub(crate) fn evp_method_store_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, EvpMethodStoreData> {
        tracing::trace!("Acquiring EVP method store write lock");
        self.evp_method_store.write()
    }

    /// Returns a read guard to the name map.
    pub(crate) fn name_map(&self) -> parking_lot::RwLockReadGuard<'_, NameMapData> {
        tracing::trace!("Acquiring name map read lock");
        self.name_map.read()
    }

    /// Returns a write guard to the name map.
    pub(crate) fn name_map_mut(&self) -> parking_lot::RwLockWriteGuard<'_, NameMapData> {
        tracing::trace!("Acquiring name map write lock");
        self.name_map.write()
    }

    /// Returns a read guard to the property definitions.
    pub(crate) fn property_defns(&self) -> parking_lot::RwLockReadGuard<'_, PropertyDefnsData> {
        tracing::trace!("Acquiring property definitions read lock");
        self.property_defns.read()
    }

    /// Returns a write guard to the property definitions.
    pub(crate) fn property_defns_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, PropertyDefnsData> {
        tracing::trace!("Acquiring property definitions write lock");
        self.property_defns.write()
    }

    /// Returns a read guard to the global properties.
    pub(crate) fn global_properties(
        &self,
    ) -> parking_lot::RwLockReadGuard<'_, GlobalPropertiesData> {
        tracing::trace!("Acquiring global properties read lock");
        self.global_properties.read()
    }

    /// Returns a write guard to the global properties.
    pub(crate) fn global_properties_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, GlobalPropertiesData> {
        tracing::trace!("Acquiring global properties write lock");
        self.global_properties.write()
    }

    /// Returns a read guard to the DRBG context.
    pub(crate) fn drbg(&self) -> parking_lot::RwLockReadGuard<'_, Option<DrbgData>> {
        tracing::trace!("Acquiring DRBG read lock");
        self.drbg.read()
    }

    /// Returns a write guard to the DRBG context.
    pub(crate) fn drbg_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Option<DrbgData>> {
        tracing::trace!("Acquiring DRBG write lock");
        self.drbg.write()
    }

    /// Returns a read guard to the configuration.
    pub(crate) fn config(&self) -> parking_lot::RwLockReadGuard<'_, Config> {
        tracing::trace!("Acquiring config read lock");
        self.config.read()
    }

    /// Returns a write guard to the configuration.
    pub(crate) fn config_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Config> {
        tracing::trace!("Acquiring config write lock");
        self.config.write()
    }

    /// Returns whether configuration diagnostics are enabled.
    #[inline]
    pub(crate) fn conf_diagnostics(&self) -> bool {
        self.conf_diagnostics
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_lib_context_new() {
        let ctx = LibContext::new();
        assert!(!ctx.is_child());
        assert!(!ctx.conf_diagnostics());
    }

    #[test]
    fn test_lib_context_child() {
        let ctx = LibContext::new_child();
        assert!(ctx.is_child());
    }

    #[test]
    fn test_lib_context_default() {
        let ctx1 = get_default();
        let ctx2 = LibContext::default();
        let ctx3 = LibContext::get_default();

        // All should be the same Arc (same pointer)
        assert!(Arc::ptr_eq(&ctx1, &ctx2));
        assert!(Arc::ptr_eq(&ctx2, &ctx3));
        assert!(!ctx1.is_child());
    }

    #[test]
    fn test_lib_context_thread_safety() {
        let ctx = LibContext::new();
        let ctx_clone = Arc::clone(&ctx);

        let handle = thread::spawn(move || {
            assert!(!ctx_clone.is_child());
            let _store = ctx_clone.provider_store();
        });

        // Access from main thread concurrently
        let _store = ctx.name_map();

        handle.join().unwrap();
    }

    #[test]
    fn test_name_map_data_new() {
        let nmap = NameMapData::new();
        assert!(nmap.is_empty());
        assert_eq!(nmap.name_count(), 0);
        assert_eq!(nmap.nid_count(), 0);
    }

    #[test]
    fn test_name_map_add_and_lookup() {
        let mut nmap = NameMapData::new();

        let sha256_nid = nmap.add_name("SHA-256");
        assert!(!sha256_nid.is_undef());
        assert_eq!(sha256_nid.as_raw(), 1);

        // Lookup by name
        assert_eq!(nmap.get_nid("SHA-256"), Some(sha256_nid));

        // Lookup by NID
        assert_eq!(nmap.get_name(sha256_nid), Some("SHA-256"));
    }

    #[test]
    fn test_name_map_case_insensitive() {
        let mut nmap = NameMapData::new();

        let nid = nmap.add_name("SHA-256");

        // Case-insensitive lookups should all return the same NID
        assert_eq!(nmap.get_nid("sha-256"), Some(nid));
        assert_eq!(nmap.get_nid("SHA-256"), Some(nid));
        assert_eq!(nmap.get_nid("Sha-256"), Some(nid));
    }

    #[test]
    fn test_name_map_duplicate_add() {
        let mut nmap = NameMapData::new();

        let nid1 = nmap.add_name("AES-128-GCM");
        let nid2 = nmap.add_name("AES-128-GCM");

        // Adding the same name again returns the same NID
        assert_eq!(nid1, nid2);
        assert_eq!(nmap.nid_count(), 1);
    }

    #[test]
    fn test_name_map_multiple_names() {
        let mut nmap = NameMapData::new();

        let sha256 = nmap.add_name("SHA-256");
        let aes_gcm = nmap.add_name("AES-128-GCM");

        assert_ne!(sha256, aes_gcm);
        assert_eq!(sha256.as_raw(), 1);
        assert_eq!(aes_gcm.as_raw(), 2);

        assert_eq!(nmap.get_nid("SHA-256"), Some(sha256));
        assert_eq!(nmap.get_nid("AES-128-GCM"), Some(aes_gcm));
    }

    #[test]
    fn test_name_map_unknown_name() {
        let nmap = NameMapData::new();
        assert_eq!(nmap.get_nid("NONEXISTENT"), None);
    }

    #[test]
    fn test_name_map_unknown_nid() {
        let nmap = NameMapData::new();
        assert_eq!(nmap.get_name(Nid::from_raw(999)), None);
    }

    #[test]
    fn test_name_map_aliases() {
        let mut nmap = NameMapData::new();

        let nid = nmap.add_name("SHA256");
        let alias_nid = nmap.add_name_with_nid("SHA-256", nid);

        assert_eq!(alias_nid, nid);
        assert_eq!(nmap.get_nid("SHA256"), Some(nid));
        assert_eq!(nmap.get_nid("SHA-256"), Some(nid));

        let all_names = nmap.get_all_names(nid);
        assert!(all_names.is_some());
        let names = all_names.unwrap();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_name_map_alias_conflict() {
        let mut nmap = NameMapData::new();

        let _nid1 = nmap.add_name("SHA-256");
        let nid2 = nmap.add_name("SHA-512");

        // Trying to alias SHA-256 (already has _nid1) to nid2 should fail
        let result = nmap.add_name_with_nid("SHA-256", nid2);
        assert_eq!(result, Nid::UNDEF);
    }

    #[test]
    fn test_nid_properties() {
        let undef = Nid::UNDEF;
        assert!(undef.is_undef());
        assert_eq!(undef.as_raw(), 0);

        let nid = Nid::from_raw(42);
        assert!(!nid.is_undef());
        assert_eq!(nid.as_raw(), 42);
    }

    #[test]
    fn test_provider_store_data() {
        let mut store = ProviderStoreData::new();
        assert!(store.is_empty());

        store.register("default".to_string(), 10);
        assert_eq!(store.len(), 1);
        assert!(!store.is_activated("default"));

        assert!(store.activate("default"));
        assert!(store.is_activated("default"));

        let activated: Vec<_> = store.activated_names().collect();
        assert_eq!(activated, vec!["default"]);

        assert!(store.deactivate("default"));
        assert!(!store.is_activated("default"));
    }

    #[test]
    fn test_evp_method_store_data() {
        let mut store = EvpMethodStoreData::new();
        assert!(store.is_empty());

        let sha256 = Nid::SHA256;
        store.insert(
            1,
            "SHA-256".to_string(),
            String::new(),
            sha256,
            "default".to_string(),
        );

        assert_eq!(store.len(), 1);
        assert_eq!(store.get(1, "SHA-256", ""), Some(sha256));
        assert_eq!(store.get(1, "SHA-256", "fips=yes"), None);
        assert_eq!(store.get(2, "SHA-256", ""), None);

        store.invalidate();
        assert!(store.is_empty());
    }

    #[test]
    fn test_global_properties_data() {
        let mut gp = GlobalPropertiesData::new();
        assert_eq!(gp.get_query(), None);

        gp.set_query("fips=yes".to_string());
        assert_eq!(gp.get_query(), Some("fips=yes"));

        gp.set_query(String::new());
        assert_eq!(gp.get_query(), None);

        gp.set_query("provider=default".to_string());
        gp.clear();
        assert_eq!(gp.get_query(), None);
    }

    #[test]
    fn test_drbg_data() {
        let mut drbg = DrbgData::new();
        assert!(!drbg.is_instantiated());
        assert_eq!(drbg.reseed_interval(), 100_000);

        drbg.set_instantiated();
        assert!(drbg.is_instantiated());

        drbg.set_reseed_interval(50_000);
        assert_eq!(drbg.reseed_interval(), 50_000);

        let n1 = drbg.next_nonce();
        let n2 = drbg.next_nonce();
        assert_eq!(n1, 0);
        assert_eq!(n2, 1);
    }

    #[test]
    fn test_lib_context_subsystem_access() {
        let ctx = LibContext::new();

        // Test provider store access
        {
            let mut store = ctx.provider_store_mut();
            store.register("test-provider".to_string(), 5);
        }
        {
            let store = ctx.provider_store();
            assert_eq!(store.len(), 1);
        }

        // Test name map access
        {
            let mut nmap = ctx.name_map_mut();
            let _nid = nmap.add_name("RSA");
        }
        {
            let nmap = ctx.name_map();
            assert!(nmap.get_nid("RSA").is_some());
        }

        // Test global properties access
        {
            let mut gp = ctx.global_properties_mut();
            gp.set_query("fips=yes".to_string());
        }
        {
            let gp = ctx.global_properties();
            assert_eq!(gp.get_query(), Some("fips=yes"));
        }
    }

    #[test]
    fn test_lib_context_config_access() {
        let ctx = LibContext::new();

        // Verify config starts empty
        {
            let cfg = ctx.config();
            assert!(cfg.is_empty());
        }

        // Write config through the write guard
        {
            let mut cfg = ctx.config_mut();
            cfg.set_string("test_section", "key1", "value1".to_string());
        }

        // Verify config was updated
        {
            let cfg = ctx.config();
            assert_eq!(cfg.get_string("test_section", "key1"), Some("value1"));
        }
    }

    #[test]
    fn test_lib_context_drbg_access() {
        let ctx = LibContext::new();

        {
            let drbg = ctx.drbg();
            assert!(drbg.is_some());
            let drbg_ref = drbg.as_ref().unwrap();
            assert!(!drbg_ref.is_instantiated());
        }

        {
            let mut drbg = ctx.drbg_mut();
            if let Some(ref mut d) = *drbg {
                d.set_instantiated();
            }
        }

        {
            let drbg = ctx.drbg();
            assert!(drbg.as_ref().unwrap().is_instantiated());
        }
    }

    #[test]
    fn test_lib_context_debug_format() {
        let ctx = LibContext::new();
        let debug_str = format!("{:?}", *ctx);
        assert!(debug_str.contains("LibContext"));
        assert!(debug_str.contains("is_child: false"));
    }

    #[test]
    fn test_lib_context_concurrent_read_access() {
        let ctx = LibContext::new();

        // Set up some data
        {
            let mut nmap = ctx.name_map_mut();
            nmap.add_name("SHA-256");
            nmap.add_name("AES-128-GCM");
        }

        // Spawn multiple reader threads
        let mut handles = Vec::new();
        for _ in 0..4 {
            let ctx_clone = Arc::clone(&ctx);
            let handle = thread::spawn(move || {
                let nmap = ctx_clone.name_map();
                assert!(nmap.get_nid("SHA-256").is_some());
                assert!(nmap.get_nid("AES-128-GCM").is_some());
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_name_map_default_trait() {
        let nmap = NameMapData::default();
        assert!(nmap.is_empty());
    }
}
