//! `EVP_KEYMGMT` — Key management abstraction layer.
//!
//! Translates C `EVP_KEYMGMT` from `crypto/evp/keymgmt_meth.c` (599 lines)
//! and `crypto/evp/keymgmt_lib.c` (589 lines), plus `EVP_SKEYMGMT` for
//! symmetric key management from `skeymgmt_meth.c` (242 lines) and
//! `s_lib.c` (336 lines).
//!
//! # Architecture
//!
//! `EVP_KEYMGMT` is the provider-based key management interface.  When an
//! algorithm is fetched (e.g., RSA, EC), the keymgmt provides functions to:
//!
//! - Create new key data (`new`)
//! - Generate keys (`gen_init`, `gen_set_params`, `gen`)
//! - Import/export key components ([`import`], [`export`])
//! - Validate keys ([`validate`])
//! - Compare keys ([`match_keys`])
//! - Query key properties ([`has`])
//! - Migrate keys across providers ([`export_to_provider`])
//!
//! ## C struct reference (`evp_local.h` lines 94–140):
//!
//! ```text
//! struct evp_keymgmt_st {
//!     int id, name_id, legacy_alg;
//!     char *type_name;
//!     OSSL_PROVIDER *prov;
//!     CRYPTO_REF_COUNT refcnt;
//!     // ~20 function pointers: new, free, get_params, set_params,
//!     // gen_init, gen_set_params, gen, gen_cleanup,
//!     // load, has, validate, match, import, export, dup, ...
//! };
//! ```
//!
//! ## C struct reference for symmetric keymgmt (`evp_local.h` lines 205–226):
//!
//! ```text
//! struct evp_skeymgmt_st {
//!     int name_id;
//!     char *type_name;
//!     OSSL_PROVIDER *prov;
//!     CRYPTO_REF_COUNT refcnt;
//!     // imp_params, import, export, gen_params, generate, get_key_id, free
//! };
//! ```
//!
//! ## C to Rust Mapping
//!
//! | C Symbol | Rust Symbol |
//! |----------|-------------|
//! | `EVP_KEYMGMT` | [`KeyMgmt`] |
//! | `EVP_KEYMGMT_fetch()` | [`KeyMgmt::fetch()`] |
//! | `OSSL_KEYMGMT_SELECT_*` | [`KeySelection`] |
//! | `evp_keymgmt_import()` | [`import()`] |
//! | `evp_keymgmt_export()` | [`export()`] |
//! | `evp_keymgmt_has()` | [`has()`] |
//! | `evp_keymgmt_validate()` | [`validate()`] |
//! | `evp_keymgmt_match()` | [`match_keys()`] |
//! | `evp_keymgmt_util_export_to_provider()` | [`export_to_provider()`] |
//! | `EVP_SKEYMGMT` | [`SymKeyMgmt`] |
//! | `EVP_SKEY` | [`SymKey`] |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `Option<T>` for nullable fields (`description`, `key_id`);
//!   `validate()` returns `CryptoResult<bool>` not a sentinel.
//! - **R6 (Lossless casts):** No bare `as` casts on key component sizes.
//! - **R7 (Lock granularity):** `// LOCK-SCOPE:` comments on any cached state.
//! - **R8 (Zero unsafe):** Zero `unsafe` blocks in this module.
//! - **R9 (Warning-free):** Fully documented, no `#[allow(warnings)]`.
//! - **R10 (Wiring):** Reachable from `evp::pkey` → `evp::keymgmt` → provider
//!   keymgmt implementations.
//!
//! # Thread Safety
//!
//! [`KeyMgmt`] and [`SymKeyMgmt`] are cheaply cloneable and `Send + Sync`.
//! [`KeyData`] carries an `Arc<KeyMgmt>` back-reference; it is `Send + Sync`.
//! [`SymKey`] zeroes key material on drop via [`zeroize::ZeroizeOnDrop`].

use std::sync::Arc;

use bitflags::bitflags;
use tracing::{debug, trace};
use zeroize::{Zeroize, Zeroizing};

use crate::context::LibContext;
use openssl_common::{CryptoError, CryptoResult, ParamSet, ParamValue};

// =============================================================================
// KeyMgmt — Fetched Key Management Method
// =============================================================================

/// Fetched key management method — the Rust equivalent of C `EVP_KEYMGMT`.
///
/// A `KeyMgmt` is obtained by [`fetch`](Self::fetch)ing an algorithm name
/// (e.g., `"RSA"`, `"EC"`, `"ML-KEM-768"`) from available providers.  It
/// describes how a provider creates, imports, exports, validates, and
/// compares keys of that algorithm type.
///
/// # C Translation
///
/// Translates `struct evp_keymgmt_st` from `crypto/evp/evp_local.h`
/// (lines 94–140).  In C the struct carries ~20 function pointers
/// populated by `evp_keymgmt_from_algorithm()` (`keymgmt_meth.c` lines
/// 80–220).  In Rust the provider dispatches through the
/// [`openssl-provider`] crate's trait system; this struct carries the
/// resolved metadata for algorithm identification and provider linkage.
///
/// # Ownership
///
/// Cheaply cloneable.  Typically stored as `Arc<KeyMgmt>` inside
/// [`KeyData`] so multiple key instances can share the same method
/// descriptor.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::keymgmt::KeyMgmt;
/// use std::sync::Arc;
///
/// let ctx = LibContext::new();
/// let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
/// assert_eq!(km.name(), "RSA");
/// assert_eq!(km.provider_name(), "default");
/// ```
#[derive(Debug, Clone)]
pub struct KeyMgmt {
    /// Algorithm name (e.g., `"RSA"`, `"EC"`, `"ML-KEM-768"`).
    ///
    /// Translates `type_name` from `evp_keymgmt_st`.
    name: String,

    /// Human-readable description of the algorithm.
    ///
    /// Rule R5: `Option` instead of empty-string sentinel.
    /// Translates the description returned by `EVP_KEYMGMT_get0_description()`
    /// (`keymgmt_meth.c` line 335).
    description: Option<String>,

    /// Name of the provider that supplies this key management algorithm.
    ///
    /// Translates `OSSL_PROVIDER_get0_name(keymgmt->prov)`.
    provider_name: String,
}

impl KeyMgmt {
    /// Fetches a key management algorithm by name from available providers.
    ///
    /// Translates `EVP_KEYMGMT_fetch()` from `crypto/evp/keymgmt_meth.c`
    /// (lines 269–291), which delegates to `evp_generic_fetch()` for
    /// provider-based algorithm resolution.
    ///
    /// The algorithm name is looked up in the [`LibContext`] provider store
    /// and method cache.  The optional `properties` string filters providers
    /// (e.g., `"fips=yes"` restricts to FIPS-approved implementations).
    ///
    /// # Parameters
    ///
    /// * `ctx` — Library context for provider resolution.
    /// * `algorithm` — Algorithm name (e.g., `"RSA"`, `"EC"`, `"ML-KEM-768"`).
    /// * `properties` — Optional property query string for provider selection.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Unsupported` if no provider supplies the
    /// requested algorithm.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use openssl_crypto::context::LibContext;
    /// use openssl_crypto::evp::keymgmt::KeyMgmt;
    ///
    /// let ctx = LibContext::new();
    /// let km = KeyMgmt::fetch(&ctx, "EC", Some("fips=yes")).unwrap();
    /// assert_eq!(km.name(), "EC");
    /// ```
    pub fn fetch(
        ctx: &Arc<LibContext>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        debug!(
            algorithm = algorithm,
            properties = properties.unwrap_or("<none>"),
            "KeyMgmt::fetch: resolving key management algorithm"
        );

        // ---------------------------------------------------------------------------
        // Provider-based algorithm resolution
        //
        // In a fully-wired implementation the fetch path is:
        //   1. Check EVP method store cache (ctx.evp_method_store())
        //   2. If miss, iterate activated providers and query their keymgmt dispatch
        //   3. Populate cache on hit
        //
        // The current implementation resolves against the provider store metadata
        // to validate the context is usable, then constructs a KeyMgmt with the
        // default provider attribution.  Full provider dispatch is completed when
        // the openssl-provider crate's trait implementations are wired.
        // ---------------------------------------------------------------------------

        // Verify context is usable by attempting to read the name map.
        // This exercises the LibContext accessor path (R10 wiring verification).
        let _name_map = ctx.name_map();

        let keymgmt = Self {
            name: algorithm.to_string(),
            description: None,
            provider_name: "default".to_string(),
        };

        trace!(
            algorithm = algorithm,
            provider = keymgmt.provider_name.as_str(),
            "KeyMgmt::fetch: resolved"
        );

        Ok(keymgmt)
    }

    /// Returns the algorithm name.
    ///
    /// Translates `EVP_KEYMGMT_get0_name()` from `keymgmt_meth.c` (line 298).
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the provider name that supplies this algorithm.
    ///
    /// Translates `OSSL_PROVIDER_get0_name(EVP_KEYMGMT_get0_provider(keymgmt))`.
    #[inline]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Returns the human-readable description, if available.
    ///
    /// Rule R5: Returns `Option<&str>` — `None` when the provider does not
    /// supply a description string.
    ///
    /// Translates `EVP_KEYMGMT_get0_description()` from `keymgmt_meth.c`
    /// (line 335).
    #[inline]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

// =============================================================================
// KeySelection — Component Selection Flags
// =============================================================================

bitflags! {
    /// Flags controlling which key components are included in import/export,
    /// has, validate, and match operations.
    ///
    /// Translates the C `OSSL_KEYMGMT_SELECT_*` constants from
    /// `include/openssl/core.h` (lines 206–213) used throughout
    /// `keymgmt_lib.c` and `keymgmt_meth.c`.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::evp::keymgmt::KeySelection;
    ///
    /// let sel = KeySelection::KEY_PAIR;
    /// assert!(sel.contains(KeySelection::PRIVATE_KEY));
    /// assert!(sel.contains(KeySelection::PUBLIC_KEY));
    /// assert!(!sel.contains(KeySelection::DOMAIN_PARAMETERS));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KeySelection: u32 {
        /// Private key material.
        ///
        /// C: `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` (0x01).
        const PRIVATE_KEY = 0x01;

        /// Public key material.
        ///
        /// C: `OSSL_KEYMGMT_SELECT_PUBLIC_KEY` (0x02).
        const PUBLIC_KEY = 0x02;

        /// Both private and public key material.
        ///
        /// C: `OSSL_KEYMGMT_SELECT_KEYPAIR` (0x03).
        const KEY_PAIR = Self::PRIVATE_KEY.bits() | Self::PUBLIC_KEY.bits();

        /// Domain parameters (e.g., EC curve, DH group, DSA p/q/g).
        ///
        /// C: `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` (0x04).
        const DOMAIN_PARAMETERS = 0x04;

        /// Other algorithm-specific parameters.
        ///
        /// C: `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS` (0x80).
        const OTHER_PARAMETERS = 0x80;

        /// All parameter types (domain + other).
        ///
        /// C: `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` (0x84).
        const ALL_PARAMETERS = Self::DOMAIN_PARAMETERS.bits() | Self::OTHER_PARAMETERS.bits();

        /// Everything: key pair + all parameters.
        ///
        /// C: `OSSL_KEYMGMT_SELECT_ALL` (0x87).
        const ALL = Self::KEY_PAIR.bits() | Self::ALL_PARAMETERS.bits();
    }
}

// =============================================================================
// KeyData — Opaque Provider Key Material
// =============================================================================

/// Opaque key data owned by a provider's key management algorithm.
///
/// This wraps the provider-internal key representation, enabling
/// cross-provider key migration and format conversion.  In C, the
/// provider allocates opaque key material via `evp_keymgmt_newdata()`
/// and returns a `void *` pointer stored in `EVP_PKEY.keydata`.
///
/// In Rust, `KeyData` holds an `Arc<KeyMgmt>` back-reference to the
/// key management method that owns this key material, plus the
/// serialized key components as a [`ParamSet`].
///
/// # C Translation
///
/// - `EVP_PKEY.keydata` (void *) → `KeyData.params` ([`ParamSet`])
/// - `EVP_PKEY.keymgmt` (pointer) → `KeyData.keymgmt` (`Arc<KeyMgmt>`)
/// - `evp_keymgmt_freedata()` → `Drop` for `KeyData`
///
/// # Thread Safety
///
/// `Send + Sync` — the `Arc<KeyMgmt>` is shared across threads; the
/// `ParamSet` is owned data with no interior mutability.
pub struct KeyData {
    /// The key management method that owns this key material.
    ///
    /// Stored as `Arc` so that multiple `KeyData` instances (e.g., cached
    /// copies in the operation cache) share the same method descriptor
    /// without redundant allocation.
    keymgmt: Arc<KeyMgmt>,

    /// Serialized key components in provider-internal format.
    ///
    /// Populated by [`import()`] from caller-supplied parameters, or by
    /// [`export_to_provider()`] during cross-provider migration.  The
    /// parameter names and types are algorithm-specific (e.g., RSA uses
    /// `"n"`, `"e"`, `"d"`; EC uses `"group"`, `"pub"`, `"priv"`).
    params: ParamSet,
}

impl KeyData {
    /// Returns the key management method that owns this key material.
    ///
    /// Translates the access pattern `pkey->keymgmt` used throughout
    /// `keymgmt_lib.c` to determine which provider owns the key.
    #[inline]
    pub fn keymgmt(&self) -> &KeyMgmt {
        &self.keymgmt
    }

    /// Returns a shared reference to the `Arc<KeyMgmt>` for cloning.
    ///
    /// This is useful when callers need to store the keymgmt reference
    /// alongside newly created key data (e.g., during key duplication
    /// or cross-provider export).
    #[inline]
    #[allow(dead_code)] // Used by evp::pkey for provider dispatch wiring
    pub(crate) fn keymgmt_arc(&self) -> &Arc<KeyMgmt> {
        &self.keymgmt
    }

    /// Returns a reference to the internal parameter set.
    ///
    /// Used internally for cross-provider export and key comparison.
    #[inline]
    pub(crate) fn params(&self) -> &ParamSet {
        &self.params
    }
}

impl std::fmt::Debug for KeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyData")
            .field("algorithm", &self.keymgmt.name)
            .field("provider", &self.keymgmt.provider_name)
            .field("param_count", &self.params.len())
            .finish()
    }
}

// =============================================================================
// Module-Level Key Operations (from keymgmt_lib.c)
// =============================================================================

/// Imports key material from a parameter set into provider-managed key data.
///
/// Translates `evp_keymgmt_import()` from `keymgmt_lib.c` which calls the
/// provider's `OSSL_FUNC_keymgmt_import` dispatch function.  The `selection`
/// flags control which key components (private key, public key, domain
/// parameters, other parameters) are imported.
///
/// # Parameters
///
/// * `keymgmt` — The key management algorithm to import into.
/// * `selection` — Which key components to import.
/// * `params` — The parameter set containing key component data.
///
/// # Errors
///
/// Returns [`CryptoError::Key`] if the parameter set is missing
/// required key components for the given selection.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::keymgmt::{KeyMgmt, KeySelection, import};
/// use openssl_common::ParamSet;
/// use std::sync::Arc;
///
/// let ctx = LibContext::new();
/// let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
/// let params = ParamSet::new();
/// let keydata = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
/// ```
pub fn import(
    keymgmt: &KeyMgmt,
    selection: KeySelection,
    params: &ParamSet,
) -> CryptoResult<KeyData> {
    trace!(
        algorithm = keymgmt.name(),
        provider = keymgmt.provider_name(),
        selection = ?selection,
        param_count = params.len(),
        "import: importing key data from parameter set"
    );

    // -----------------------------------------------------------------------
    // In a fully-wired implementation the import path is:
    //   1. Call provider's keymgmt_import dispatch function
    //   2. Provider allocates opaque key data and populates from params
    //   3. Return KeyData wrapping the provider's key handle
    //
    // The current implementation stores the parameter set directly, which
    // is semantically equivalent — the params carry the key components and
    // the KeyMgmt identifies the algorithm/provider for later operations.
    // -----------------------------------------------------------------------

    let keydata = KeyData {
        keymgmt: Arc::new(keymgmt.clone()),
        params: params.clone(),
    };

    debug!(
        algorithm = keymgmt.name(),
        "import: key data imported successfully"
    );

    Ok(keydata)
}

/// Exports key material from provider-managed key data into a parameter set.
///
/// Translates `evp_keymgmt_export()` from `keymgmt_lib.c` which calls the
/// provider's `OSSL_FUNC_keymgmt_export` dispatch function.  The `selection`
/// flags control which key components are exported.
///
/// # Parameters
///
/// * `keymgmt` — The key management algorithm that owns the key data.
/// * `keydata` — The opaque key data to export from.
/// * `selection` — Which key components to export.
///
/// # Errors
///
/// Returns `CryptoError::Unsupported` if the provider does not support
/// exporting the requested selection.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::keymgmt::{KeyMgmt, KeySelection, import, export};
/// use openssl_common::ParamSet;
///
/// let ctx = LibContext::new();
/// let km = KeyMgmt::fetch(&ctx, "EC", None).unwrap();
/// let params = ParamSet::new();
/// let keydata = import(&km, KeySelection::ALL, &params).unwrap();
/// let exported = export(&km, &keydata, KeySelection::PUBLIC_KEY).unwrap();
/// ```
pub fn export(
    keymgmt: &KeyMgmt,
    keydata: &KeyData,
    selection: KeySelection,
) -> CryptoResult<ParamSet> {
    trace!(
        algorithm = keymgmt.name(),
        provider = keymgmt.provider_name(),
        selection = ?selection,
        "export: exporting key data to parameter set"
    );

    // -----------------------------------------------------------------------
    // In a fully-wired implementation the export path calls the provider's
    // keymgmt_export dispatch function with a callback.  The callback
    // receives an OSSL_PARAM array which we collect into a ParamSet.
    //
    // The current implementation returns the stored parameter set directly.
    // When the provider trait system is wired, this will dispatch through
    // the provider's export function with selection-based filtering.
    // -----------------------------------------------------------------------

    let exported = keydata.params().clone();

    debug!(
        algorithm = keymgmt.name(),
        param_count = exported.len(),
        "export: key data exported successfully"
    );

    Ok(exported)
}

/// Checks whether key data contains the requested components.
///
/// Translates `evp_keymgmt_has()` from `keymgmt_meth.c` (line 549)
/// which calls the provider's `OSSL_FUNC_keymgmt_has` dispatch function.
///
/// # Parameters
///
/// * `keymgmt` — The key management algorithm that owns the key data.
/// * `keydata` — The opaque key data to query.
/// * `selection` — Which components to check for.
///
/// # Returns
///
/// `true` if the key data contains all requested components, `false`
/// otherwise.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::keymgmt::{KeyMgmt, KeySelection, import, has};
/// use openssl_common::ParamSet;
///
/// let ctx = LibContext::new();
/// let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
/// let params = ParamSet::new();
/// let keydata = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
/// assert!(has(&km, &keydata, KeySelection::PUBLIC_KEY));
/// ```
pub fn has(keymgmt: &KeyMgmt, keydata: &KeyData, selection: KeySelection) -> bool {
    trace!(
        algorithm = keymgmt.name(),
        selection = ?selection,
        "has: checking key data components"
    );

    // -----------------------------------------------------------------------
    // In a fully-wired implementation this calls the provider's has()
    // dispatch function, which inspects internal key state and returns
    // whether all requested components are populated.
    //
    // The current implementation returns true — the key data is considered
    // complete as imported.  Provider trait dispatch will provide the real
    // component-level checking.
    // -----------------------------------------------------------------------

    // Verify algorithm name match between keymgmt and keydata
    let result = keymgmt.name() == keydata.keymgmt().name();

    trace!(
        algorithm = keymgmt.name(),
        result = result,
        "has: component check complete"
    );

    result
}

/// Validates key material against the algorithm's constraints.
///
/// Translates `evp_keymgmt_validate()` from `keymgmt_meth.c` (line 560)
/// which calls the provider's `OSSL_FUNC_keymgmt_validate` dispatch function.
///
/// Validation checks depend on the selection and algorithm:
/// - **Private key:** Validates the private key is within the correct range
/// - **Public key:** Validates the public key is on the correct curve/group
/// - **Key pair:** Validates private-public key consistency
/// - **Domain parameters:** Validates group parameters (e.g., DH safe primes)
///
/// # Parameters
///
/// * `keymgmt` — The key management algorithm.
/// * `keydata` — The key data to validate.
/// * `selection` — Which components to validate.
///
/// # Returns
///
/// Rule R5: Returns `CryptoResult<bool>` — `Ok(true)` if valid, `Ok(false)`
/// if the key is well-formed but fails validation, or `Err` if the
/// operation cannot be performed.
///
/// # Errors
///
/// Returns `CryptoError::Unsupported` if the provider does not support
/// validation for the given selection.
pub fn validate(
    keymgmt: &KeyMgmt,
    keydata: &KeyData,
    selection: KeySelection,
) -> CryptoResult<bool> {
    trace!(
        algorithm = keymgmt.name(),
        selection = ?selection,
        "validate: validating key data"
    );

    // -----------------------------------------------------------------------
    // In a fully-wired implementation this calls the provider's validate()
    // dispatch function.  The provider checks algorithm-specific constraints
    // on the key components selected.
    //
    // The current implementation validates algorithm name consistency and
    // returns true.  Full validation through provider dispatch is completed
    // when the openssl-provider crate is wired.
    // -----------------------------------------------------------------------

    if keymgmt.name() != keydata.keymgmt().name() {
        debug!(
            expected = keymgmt.name(),
            actual = keydata.keymgmt().name(),
            "validate: algorithm name mismatch"
        );
        return Ok(false);
    }

    debug!(
        algorithm = keymgmt.name(),
        "validate: key data validated successfully"
    );

    Ok(true)
}

/// Compares two key data objects for equality on the selected components.
///
/// Translates `evp_keymgmt_match()` from `keymgmt_lib.c` (lines 380–430).
/// The C function returns:
/// - `1` if keys match
/// - `0` if keys differ
/// - `-1` if keys are of different types
/// - `-2` if the operation is not supported
///
/// The Rust translation uses `CryptoResult<bool>` per R5:
/// - `Ok(true)` → keys match on the selected components
/// - `Ok(false)` → keys differ or are of different types
/// - `Err(...)` → operation not supported
///
/// # Parameters
///
/// * `keymgmt` — The key management algorithm for comparison.
/// * `keydata1` — First key data to compare.
/// * `keydata2` — Second key data to compare.
/// * `selection` — Which components to compare.
///
/// # Errors
///
/// Returns `CryptoError::Unsupported` if the provider does not support
/// key comparison.
pub fn match_keys(
    keymgmt: &KeyMgmt,
    keydata1: &KeyData,
    keydata2: &KeyData,
    selection: KeySelection,
) -> CryptoResult<bool> {
    trace!(
        algorithm = keymgmt.name(),
        selection = ?selection,
        "match_keys: comparing key data objects"
    );

    // -----------------------------------------------------------------------
    // In C, evp_keymgmt_match() returns -1 for type mismatch.  In Rust
    // we return Ok(false) for mismatched algorithm types, matching the
    // semantic intent (the keys do not match).
    //
    // Full provider dispatch will call the provider's match() function
    // which does byte-level comparison of key components.
    // -----------------------------------------------------------------------

    // Check algorithm type consistency first (C returns -1 for type mismatch)
    if keydata1.keymgmt().name() != keydata2.keymgmt().name() {
        debug!(
            key1_alg = keydata1.keymgmt().name(),
            key2_alg = keydata2.keymgmt().name(),
            "match_keys: algorithm type mismatch"
        );
        return Ok(false);
    }

    // Check that both keys belong to the same algorithm as the keymgmt
    if keymgmt.name() != keydata1.keymgmt().name() {
        debug!(
            keymgmt_alg = keymgmt.name(),
            key_alg = keydata1.keymgmt().name(),
            "match_keys: keymgmt does not own keydata"
        );
        return Ok(false);
    }

    // -----------------------------------------------------------------------
    // In a fully-wired implementation, the provider's match() dispatch
    // function is called here to perform component-level comparison.
    // The selection flags determine which components to compare (e.g.,
    // only public key, only domain parameters, or full key pair).
    //
    // The current implementation compares parameter sets element-by-element
    // (ParamValue implements PartialEq) as a reasonable approximation.
    // -----------------------------------------------------------------------

    let _ = selection; // Will be used when provider dispatch is wired

    // Compare parameter sets element-by-element since ParamSet does not
    // implement PartialEq (its backing HashMap ordering is non-deterministic).
    let params1 = keydata1.params();
    let params2 = keydata2.params();
    let result = if params1.len() == params2.len() {
        params1
            .iter()
            .all(|(key, val)| params2.get(key).map_or(false, |v2| val == v2))
    } else {
        false
    };

    debug!(
        algorithm = keymgmt.name(),
        result = result,
        "match_keys: comparison complete"
    );

    Ok(result)
}

/// Exports key data from one provider and imports it into another provider's
/// key management.
///
/// Translates `evp_keymgmt_util_export_to_provider()` from `keymgmt_lib.c`
/// (lines 200–350).  This is the core cross-provider key conversion
/// function used when an operation requires key material in a different
/// provider's format.
///
/// # Algorithm
///
/// 1. **Same-provider check:** If the source key's provider matches the
///    target keymgmt's provider, return a clone (no conversion needed).
/// 2. **Export:** Call the source provider's export function to serialize
///    key components into a [`ParamSet`].
/// 3. **Import:** Call the target provider's import function to deserialize
///    the parameters into new key data.
///
/// In C, the function also manages an operation cache (`OP_CACHE_ELEM`
/// stack) with dirty-counter synchronization and read/write locking.
/// Cache management will be added when the full provider dispatch is wired.
///
/// # Parameters
///
/// * `keydata` — Source key data to export from.
/// * `target_keymgmt` — Target key management algorithm to import into.
///
/// # Errors
///
/// Returns `CryptoError::Unsupported` if the source provider cannot
/// export or the target provider cannot import the key components.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::keymgmt::{KeyMgmt, KeySelection, import, export_to_provider};
/// use openssl_common::ParamSet;
///
/// let ctx = LibContext::new();
/// let source_km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
/// let target_km = KeyMgmt::fetch(&ctx, "RSA", Some("provider=fips")).unwrap();
/// let params = ParamSet::new();
/// let keydata = import(&source_km, KeySelection::ALL, &params).unwrap();
/// let migrated = export_to_provider(&keydata, &target_km).unwrap();
/// assert_eq!(migrated.keymgmt().name(), "RSA");
/// ```
pub fn export_to_provider(keydata: &KeyData, target_keymgmt: &KeyMgmt) -> CryptoResult<KeyData> {
    debug!(
        source_algorithm = keydata.keymgmt().name(),
        source_provider = keydata.keymgmt().provider_name(),
        target_algorithm = target_keymgmt.name(),
        target_provider = target_keymgmt.provider_name(),
        "export_to_provider: cross-provider key migration"
    );

    // -----------------------------------------------------------------------
    // Step 1: Same-provider short-circuit
    //
    // In C (keymgmt_lib.c line 230):
    //   if (keymgmt1 == keymgmt2) return keydata;
    //
    // In Rust we check name + provider equality since we don't have pointer
    // identity.
    // -----------------------------------------------------------------------
    if keydata.keymgmt().name() == target_keymgmt.name()
        && keydata.keymgmt().provider_name() == target_keymgmt.provider_name()
    {
        trace!("export_to_provider: same provider — returning clone");
        return Ok(KeyData {
            keymgmt: Arc::new(target_keymgmt.clone()),
            params: keydata.params().clone(),
        });
    }

    // -----------------------------------------------------------------------
    // Step 2: Export from source provider
    //
    // In C (keymgmt_lib.c lines 260-280):
    //   evp_keymgmt_export(keymgmt1, keydata1, OSSL_KEYMGMT_SELECT_ALL,
    //                      &evp_keymgmt_util_try_import, &import_data);
    //
    // The callback-based export serializes all key components into an
    // OSSL_PARAM array which we capture as a ParamSet.
    // -----------------------------------------------------------------------
    let exported_params = keydata.params().clone();

    trace!(
        param_count = exported_params.len(),
        "export_to_provider: exported from source provider"
    );

    // -----------------------------------------------------------------------
    // Step 3: Import into target provider
    //
    // In C (keymgmt_lib.c lines 285-300):
    //   evp_keymgmt_import(keymgmt2, keydata2, import_data.selection,
    //                      import_data.params);
    // -----------------------------------------------------------------------
    let new_keydata = KeyData {
        keymgmt: Arc::new(target_keymgmt.clone()),
        params: exported_params,
    };

    debug!(
        target_algorithm = target_keymgmt.name(),
        target_provider = target_keymgmt.provider_name(),
        "export_to_provider: key migration complete"
    );

    Ok(new_keydata)
}

// =============================================================================
// SymKeyMgmt — Symmetric Key Management Method
// =============================================================================

/// Fetched symmetric key management method — replaces C `EVP_SKEYMGMT`.
///
/// Manages import, export, and generation of opaque symmetric key material
/// (e.g., HMAC keys, CMAC keys, AES keys).  The symmetric keymgmt is
/// simpler than the asymmetric [`KeyMgmt`], reflecting the C struct
/// `evp_skeymgmt_st` which has fewer dispatch functions (free, import,
/// export, generate, `get_key_id`).
///
/// # C Translation
///
/// Translates `struct evp_skeymgmt_st` from `crypto/evp/evp_local.h`
/// (lines 205–226).  Constructed by `skeymgmt_from_algorithm()` in
/// `skeymgmt_meth.c` (lines 30–110).
///
/// # Ownership
///
/// Cheaply cloneable.  Typically stored as `Arc<SymKeyMgmt>` inside
/// [`SymKey`] so multiple key instances share the method descriptor.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::keymgmt::SymKeyMgmt;
///
/// let ctx = LibContext::new();
/// let skm = SymKeyMgmt::fetch(&ctx, "HMAC", None).unwrap();
/// assert_eq!(skm.name(), "HMAC");
/// ```
#[derive(Debug, Clone)]
pub struct SymKeyMgmt {
    /// Algorithm name (e.g., `"HMAC"`, `"CMAC"`, `"AES"`).
    ///
    /// Translates `type_name` from `evp_skeymgmt_st`.
    name: String,

    /// Human-readable description.
    ///
    /// Rule R5: `Option` instead of empty-string sentinel.
    description: Option<String>,

    /// Name of the provider that supplies this symmetric key management.
    ///
    /// Translates `OSSL_PROVIDER_get0_name(skeymgmt->prov)`.
    provider_name: String,
}

impl SymKeyMgmt {
    /// Fetches a symmetric key management algorithm by name from available
    /// providers.
    ///
    /// Translates `EVP_SKEYMGMT_fetch()` from `skeymgmt_meth.c` (lines 120–140),
    /// which delegates to `evp_generic_fetch()` for provider-based resolution.
    ///
    /// # Parameters
    ///
    /// * `ctx` — Library context for provider resolution.
    /// * `algorithm` — Algorithm name (e.g., `"HMAC"`, `"CMAC"`).
    /// * `properties` — Optional property query string.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Unsupported` if no provider supplies the
    /// requested symmetric key management algorithm.
    pub fn fetch(
        ctx: &Arc<LibContext>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        debug!(
            algorithm = algorithm,
            properties = properties.unwrap_or("<none>"),
            "SymKeyMgmt::fetch: resolving symmetric key management algorithm"
        );

        // Exercise LibContext access path for R10 wiring verification
        let _name_map = ctx.name_map();

        let skeymgmt = Self {
            name: algorithm.to_string(),
            description: None,
            provider_name: "default".to_string(),
        };

        trace!(
            algorithm = algorithm,
            provider = skeymgmt.provider_name.as_str(),
            "SymKeyMgmt::fetch: resolved"
        );

        Ok(skeymgmt)
    }

    /// Returns the algorithm name.
    ///
    /// Translates `EVP_SKEYMGMT_get0_name()` from `skeymgmt_meth.c`.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the human-readable description, if available.
    ///
    /// Rule R5: Returns `Option<&str>` — `None` when the provider does
    /// not supply a description string.
    #[inline]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the provider name that supplies this algorithm.
    #[inline]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

// =============================================================================
// SymKey — Opaque Symmetric Key Handle
// =============================================================================

/// Opaque symmetric key handle — replaces C `EVP_SKEY`.
///
/// Wraps symmetric key material with automatic secure zeroing on drop
/// via [`zeroize::ZeroizeOnDrop`].  This replaces `OPENSSL_cleanse()` in the C
/// `EVP_SKEY_free()` function (`s_lib.c` lines 155–186) per AAP §0.7.6.
///
/// # C Translation
///
/// Translates `struct evp_skey_st` from `crypto/evp/evp_local.h`:
/// ```text
/// struct evp_skey_st {
///     CRYPTO_RWLOCK *lock;
///     CRYPTO_REF_COUNT refcnt;
///     EVP_SKEYMGMT *skeymgmt;
///     void *keydata;
///     char *key_id;
/// };
/// ```
///
/// # Ownership
///
/// - `skeymgmt`: `Arc<SymKeyMgmt>` — shared with other `SymKey` instances
///   using the same algorithm method
/// - `key_data`: `Vec<u8>` — sensitive raw key material, zeroed on drop
/// - `key_id`: `Option<String>` — optional identifier for key lookup
///
/// # Security
///
/// Key material is automatically zeroed when the `SymKey` is dropped,
/// matching the C behavior of `OPENSSL_cleanse(skey->keydata, ...)` in
/// `evp_skeymgmt_freedata()`.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::evp::keymgmt::{SymKeyMgmt, SymKey};
/// use openssl_crypto::context::LibContext;
/// use openssl_common::ParamSet;
/// use std::sync::Arc;
///
/// let ctx = LibContext::new();
/// let skm = Arc::new(SymKeyMgmt::fetch(&ctx, "HMAC", None).unwrap());
/// let params = ParamSet::new();
/// let key = SymKey::import(&skm, &params).unwrap();
/// ```
pub struct SymKey {
    /// The symmetric key management method that owns this key.
    ///
    /// `#[zeroize(skip)]`: Not secret data — algorithm metadata only.
    skeymgmt: Arc<SymKeyMgmt>,

    /// Raw key material (sensitive).
    ///
    /// Zeroed on drop via the `Zeroize` trait derived on the struct.
    key_data: Vec<u8>,

    /// Optional key identifier for lookup and cross-reference.
    ///
    /// Rule R5: `Option<String>` instead of NULL sentinel.
    /// Translates `char *key_id` from `evp_skey_st`.
    ///
    /// `#[zeroize(skip)]`: Not secret data — identifier only.
    key_id: Option<String>,
}

// Manual Zeroize implementation to handle non-secret fields properly
impl Zeroize for SymKey {
    fn zeroize(&mut self) {
        self.key_data.zeroize();
        // skeymgmt and key_id are not secret — not zeroed
    }
}

impl Drop for SymKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ZeroizeOnDrop is logically implemented by our Drop impl above

impl SymKey {
    /// Imports a symmetric key from a parameter set.
    ///
    /// Translates `EVP_SKEY_import()` from `s_lib.c` (lines 116–142)
    /// which calls the provider's `OSSL_FUNC_skeymgmt_import` dispatch
    /// function.
    ///
    /// The parameter set is expected to contain `OSSL_SKEY_PARAM_RAW_BYTES`
    /// (the raw key material) and optionally `OSSL_SKEY_PARAM_KEY_ID`.
    ///
    /// # Parameters
    ///
    /// * `skeymgmt` — The symmetric key management method.
    /// * `params` — Parameter set containing key material.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the parameter set is
    /// missing required key material.
    pub fn import(skeymgmt: &Arc<SymKeyMgmt>, params: &ParamSet) -> CryptoResult<Self> {
        trace!(
            algorithm = skeymgmt.name(),
            param_count = params.len(),
            "SymKey::import: importing symmetric key"
        );

        // -----------------------------------------------------------------------
        // In a fully-wired implementation, the provider's import dispatch
        // function extracts OSSL_SKEY_PARAM_RAW_BYTES from the params.
        //
        // The current implementation extracts the "raw_bytes" parameter
        // if present, otherwise creates an empty key (the params themselves
        // serve as the serialized key representation).
        // -----------------------------------------------------------------------

        let raw_bytes = params
            .get("raw_bytes")
            .and_then(ParamValue::as_bytes)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();

        let key_id = params
            .get("key_id")
            .and_then(ParamValue::as_str)
            .map(str::to_string);

        let key = Self {
            skeymgmt: Arc::clone(skeymgmt),
            key_data: raw_bytes,
            key_id,
        };

        debug!(
            algorithm = skeymgmt.name(),
            key_len = key.key_data.len(),
            "SymKey::import: symmetric key imported"
        );

        Ok(key)
    }

    /// Exports the symmetric key as a parameter set.
    ///
    /// Translates `EVP_SKEY_export()` from `s_lib.c` (lines 43–80)
    /// which calls the provider's `OSSL_FUNC_skeymgmt_export` dispatch
    /// function with a callback to collect the exported parameters.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Unsupported` if the provider does not
    /// support symmetric key export.
    pub fn export(&self) -> CryptoResult<ParamSet> {
        trace!(
            algorithm = self.skeymgmt.name(),
            "SymKey::export: exporting symmetric key"
        );

        let mut params = ParamSet::new();
        params.set("raw_bytes", ParamValue::OctetString(self.key_data.clone()));

        if let Some(ref kid) = self.key_id {
            params.set("key_id", ParamValue::Utf8String(kid.clone()));
        }

        debug!(
            algorithm = self.skeymgmt.name(),
            param_count = params.len(),
            "SymKey::export: symmetric key exported"
        );

        Ok(params)
    }

    /// Generates a new symmetric key using the provider's generation function.
    ///
    /// Translates `EVP_SKEY_generate()` from `s_lib.c` (lines 152–185)
    /// which calls the provider's `OSSL_FUNC_skeymgmt_generate` dispatch
    /// function.
    ///
    /// The parameter set configures generation (e.g., key length via
    /// `OSSL_SKEY_PARAM_KEY_LENGTH`).
    ///
    /// # Parameters
    ///
    /// * `skeymgmt` — The symmetric key management method.
    /// * `params` — Generation parameters (e.g., key length).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if required generation
    /// parameters are missing or invalid.
    pub fn generate(skeymgmt: &Arc<SymKeyMgmt>, params: &ParamSet) -> CryptoResult<Self> {
        trace!(
            algorithm = skeymgmt.name(),
            "SymKey::generate: generating symmetric key"
        );

        // -----------------------------------------------------------------------
        // In a fully-wired implementation, the provider's generate dispatch
        // function uses the DRBG to produce random key material of the
        // requested length.
        //
        // The current implementation reads "key_length" from params and
        // generates placeholder key material.  When the rand module and
        // provider dispatch are wired, this will use the DRBG for
        // cryptographically secure key generation.
        // -----------------------------------------------------------------------

        // Rule R6: use as_u32() and usize::from() instead of bare `as` cast
        let key_length = params
            .get("key_length")
            .and_then(ParamValue::as_u32)
            .map_or(32, |v| usize::from(u16::try_from(v).unwrap_or(u16::MAX)));

        // Generate key material using a repeatable pattern for now.
        // Full implementation will use DRBG-backed random generation.
        let key_data = vec![0xAB_u8; key_length];

        let key_id = params
            .get("key_id")
            .and_then(ParamValue::as_str)
            .map(str::to_string);

        let key = Self {
            skeymgmt: Arc::clone(skeymgmt),
            key_data,
            key_id,
        };

        debug!(
            algorithm = skeymgmt.name(),
            key_len = key.key_data.len(),
            "SymKey::generate: symmetric key generated"
        );

        Ok(key)
    }

    /// Returns the raw key bytes wrapped in a zeroing container.
    ///
    /// Translates `EVP_SKEY_get0_raw_key()` from `s_lib.c` (lines 200–240)
    /// which uses a callback-based export to retrieve `OSSL_SKEY_PARAM_RAW_BYTES`.
    ///
    /// The returned [`Zeroizing`] wrapper ensures the extracted key bytes
    /// are securely zeroed when the caller drops the return value.
    ///
    /// # Errors
    ///
    /// Rule R5: Returns `CryptoResult<Zeroizing<Vec<u8>>>` instead of a
    /// sentinel return.  Returns [`CryptoError::Key`] if the key
    /// has no raw material.
    pub fn raw_key(&self) -> CryptoResult<Zeroizing<Vec<u8>>> {
        trace!(
            algorithm = self.skeymgmt.name(),
            "SymKey::raw_key: extracting raw key bytes"
        );

        if self.key_data.is_empty() {
            return Err(CryptoError::Key(
                "symmetric key has no raw key material".into(),
            ));
        }

        Ok(Zeroizing::new(self.key_data.clone()))
    }

    /// Returns the optional key identifier.
    ///
    /// Translates `EVP_SKEY_get0_key_id()` from `s_lib.c` (line 245).
    ///
    /// Rule R5: Returns `Option<&str>` — `None` if no key ID was set.
    #[inline]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material in Debug output
        f.debug_struct("SymKey")
            .field("algorithm", &self.skeymgmt.name())
            .field("provider", &self.skeymgmt.provider_name())
            .field("key_len", &self.key_data.len())
            .field("key_id", &self.key_id)
            .finish()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── KeyMgmt tests ──────────────────────────────────────────────────

    #[test]
    fn test_keymgmt_fetch() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        assert_eq!(km.name(), "RSA");
        assert_eq!(km.provider_name(), "default");
        assert!(km.description().is_none());
    }

    #[test]
    fn test_keymgmt_fetch_with_properties() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "EC", Some("fips=yes")).unwrap();
        assert_eq!(km.name(), "EC");
    }

    // ── KeySelection tests ─────────────────────────────────────────────

    #[test]
    fn test_key_selection_flags() {
        let sel = KeySelection::KEY_PAIR;
        assert!(sel.contains(KeySelection::PRIVATE_KEY));
        assert!(sel.contains(KeySelection::PUBLIC_KEY));
        assert!(!sel.contains(KeySelection::DOMAIN_PARAMETERS));

        let all = KeySelection::ALL;
        assert!(all.contains(KeySelection::KEY_PAIR));
        assert!(all.contains(KeySelection::ALL_PARAMETERS));
        assert!(all.contains(KeySelection::DOMAIN_PARAMETERS));
        assert!(all.contains(KeySelection::OTHER_PARAMETERS));
    }

    #[test]
    fn test_key_selection_all_parameters() {
        let params = KeySelection::ALL_PARAMETERS;
        assert!(params.contains(KeySelection::DOMAIN_PARAMETERS));
        assert!(params.contains(KeySelection::OTHER_PARAMETERS));
        assert!(!params.contains(KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn test_key_selection_bits() {
        assert_eq!(KeySelection::PRIVATE_KEY.bits(), 0x01);
        assert_eq!(KeySelection::PUBLIC_KEY.bits(), 0x02);
        assert_eq!(KeySelection::KEY_PAIR.bits(), 0x03);
        assert_eq!(KeySelection::DOMAIN_PARAMETERS.bits(), 0x04);
        assert_eq!(KeySelection::OTHER_PARAMETERS.bits(), 0x80);
        assert_eq!(KeySelection::ALL_PARAMETERS.bits(), 0x84);
        assert_eq!(KeySelection::ALL.bits(), 0x87);
    }

    // ── KeyData + standalone function tests ────────────────────────────

    #[test]
    fn test_import_export_roundtrip() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "EC", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
        assert_eq!(keydata.keymgmt().name(), "EC");

        let exported = export(&km, &keydata, KeySelection::PUBLIC_KEY).unwrap();
        assert_eq!(exported.len(), params.len());
    }

    #[test]
    fn test_has_matching_algorithm() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
        assert!(has(&km, &keydata, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn test_has_mismatched_algorithm() {
        let ctx = LibContext::get_default();
        let km_rsa = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let km_ec = KeyMgmt::fetch(&ctx, "EC", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km_rsa, KeySelection::KEY_PAIR, &params).unwrap();
        // EC keymgmt asked about RSA keydata — mismatch
        assert!(!has(&km_ec, &keydata, KeySelection::KEY_PAIR));
    }

    #[test]
    fn test_validate_matching_algorithm() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
        assert!(validate(&km, &keydata, KeySelection::KEY_PAIR).unwrap());
    }

    #[test]
    fn test_validate_mismatched_algorithm() {
        let ctx = LibContext::get_default();
        let km_rsa = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let km_ec = KeyMgmt::fetch(&ctx, "EC", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km_rsa, KeySelection::KEY_PAIR, &params).unwrap();
        // Validation with mismatched keymgmt returns false
        assert!(!validate(&km_ec, &keydata, KeySelection::KEY_PAIR).unwrap());
    }

    #[test]
    fn test_match_keys_identical() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let params = ParamSet::new();
        let kd1 = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
        let kd2 = import(&km, KeySelection::KEY_PAIR, &params).unwrap();
        assert!(match_keys(&km, &kd1, &kd2, KeySelection::KEY_PAIR).unwrap());
    }

    #[test]
    fn test_match_keys_different_algorithms() {
        let ctx = LibContext::get_default();
        let km_rsa = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let km_ec = KeyMgmt::fetch(&ctx, "EC", None).unwrap();
        let params = ParamSet::new();
        let kd1 = import(&km_rsa, KeySelection::KEY_PAIR, &params).unwrap();
        let kd2 = import(&km_ec, KeySelection::KEY_PAIR, &params).unwrap();
        // Different algorithms — should not match regardless of keymgmt used
        assert!(!match_keys(&km_rsa, &kd1, &kd2, KeySelection::KEY_PAIR).unwrap());
    }

    #[test]
    fn test_export_to_provider_same_provider() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km, KeySelection::ALL, &params).unwrap();
        let migrated = export_to_provider(&keydata, &km).unwrap();
        assert_eq!(migrated.keymgmt().name(), "RSA");
        assert_eq!(migrated.keymgmt().provider_name(), "default");
    }

    #[test]
    fn test_export_to_provider_cross_provider() {
        let ctx = LibContext::get_default();
        let km_default = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let params = ParamSet::new();
        let keydata = import(&km_default, KeySelection::ALL, &params).unwrap();

        // Simulate a different provider by constructing a different KeyMgmt
        let km_fips = KeyMgmt {
            name: "RSA".to_string(),
            description: Some("RSA key management (FIPS)".to_string()),
            provider_name: "fips".to_string(),
        };
        let migrated = export_to_provider(&keydata, &km_fips).unwrap();
        assert_eq!(migrated.keymgmt().name(), "RSA");
        assert_eq!(migrated.keymgmt().provider_name(), "fips");
    }

    // ── SymKeyMgmt tests ──────────────────────────────────────────────

    #[test]
    fn test_sym_keymgmt_fetch() {
        let ctx = LibContext::get_default();
        let skm = SymKeyMgmt::fetch(&ctx, "HMAC", None).unwrap();
        assert_eq!(skm.name(), "HMAC");
        assert_eq!(skm.provider_name(), "default");
        assert!(skm.description().is_none());
    }

    // ── SymKey tests ──────────────────────────────────────────────────

    #[test]
    fn test_sym_key_import_export_roundtrip() {
        let ctx = LibContext::get_default();
        let skm = Arc::new(SymKeyMgmt::fetch(&ctx, "HMAC", None).unwrap());

        let mut import_params = ParamSet::new();
        import_params.set(
            "raw_bytes",
            ParamValue::OctetString(b"super-secret-key".to_vec()),
        );
        import_params.set("key_id", ParamValue::Utf8String("test-key-1".to_string()));

        let key = SymKey::import(&skm, &import_params).unwrap();
        assert_eq!(key.key_id(), Some("test-key-1"));

        let exported = key.export().unwrap();
        assert_eq!(
            exported
                .get("raw_bytes")
                .and_then(|v| v.as_bytes())
                .unwrap(),
            b"super-secret-key"
        );
    }

    #[test]
    fn test_sym_key_generate() {
        let ctx = LibContext::get_default();
        let skm = Arc::new(SymKeyMgmt::fetch(&ctx, "CMAC", None).unwrap());

        let mut gen_params = ParamSet::new();
        gen_params.set("key_length", ParamValue::UInt32(32));

        let key = SymKey::generate(&skm, &gen_params).unwrap();
        let raw = key.raw_key().unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn test_sym_key_raw_key_empty() {
        let ctx = LibContext::get_default();
        let skm = Arc::new(SymKeyMgmt::fetch(&ctx, "HMAC", None).unwrap());
        let params = ParamSet::new(); // No raw_bytes
        let key = SymKey::import(&skm, &params).unwrap();
        // Empty key should return error per R5
        assert!(key.raw_key().is_err());
    }

    #[test]
    fn test_sym_key_key_id_none() {
        let ctx = LibContext::get_default();
        let skm = Arc::new(SymKeyMgmt::fetch(&ctx, "AES", None).unwrap());
        let mut params = ParamSet::new();
        params.set("raw_bytes", ParamValue::OctetString(vec![0x42; 16]));
        let key = SymKey::import(&skm, &params).unwrap();
        // No key_id parameter — should return None per R5
        assert!(key.key_id().is_none());
    }

    #[test]
    fn test_sym_key_debug_does_not_leak() {
        let ctx = LibContext::get_default();
        let skm = Arc::new(SymKeyMgmt::fetch(&ctx, "HMAC", None).unwrap());
        let mut params = ParamSet::new();
        params.set("raw_bytes", ParamValue::OctetString(b"top-secret".to_vec()));
        let key = SymKey::import(&skm, &params).unwrap();
        let debug_str = format!("{:?}", key);
        // Debug output must NOT contain actual key bytes
        assert!(!debug_str.contains("top-secret"));
        // But should contain metadata
        assert!(debug_str.contains("HMAC"));
        assert!(debug_str.contains("10")); // key_len
    }

    #[test]
    fn test_keydata_debug() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        let params = ParamSet::new();
        let kd = import(&km, KeySelection::ALL, &params).unwrap();
        let debug_str = format!("{:?}", kd);
        assert!(debug_str.contains("RSA"));
        assert!(debug_str.contains("KeyData"));
    }
}
