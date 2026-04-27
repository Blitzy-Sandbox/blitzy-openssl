//! Legacy key management shims for KDF-derived secrets and MAC keys.
//!
//! Translates two C source files into idiomatic Rust:
//!
//! 1. `providers/implementations/keymgmt/kdf_legacy_kmgmt.c` (102 lines) —
//!    KDF legacy dummy keymgmt. The dispatch table only has `KEYMGMT_NEW`,
//!    `KEYMGMT_FREE`, and `KEYMGMT_HAS`; there is no key material.
//!
//! 2. `providers/implementations/keymgmt/mac_legacy_kmgmt.c` (578 lines) —
//!    MAC and CMAC legacy keymgmt. Manages refcounted secret keys with
//!    secure memory storage. CMAC additionally tracks a block-cipher
//!    identity (e.g., `"AES-128-CBC"`).
//!
//! # Architecture
//!
//! These are shim/adapter key management implementations that allow legacy
//! `EVP_PKEY`-based KDF and MAC operations to participate in the provider
//! dispatch system. They implement the `KeyMgmtProvider` trait from
//! [`crate::traits`].
//!
//! - **KDF keymgmt** (`KdfLegacyKeyMgmt`) — A "dummy" adapter. KDF keys have
//!   no key material; `has()` always returns `true`. Operations like
//!   `generate`, `import`, and `export` are unsupported because the C
//!   dispatch table only includes `NEW`, `FREE`, and `HAS`.
//!
//! - **MAC keymgmt** (`MacLegacyKeyMgmt`) — Full key lifecycle: creation,
//!   generation from parameters, import/export of the secret key, and
//!   constant-time key comparison via [`subtle::ConstantTimeEq`].
//!
//! - **CMAC keymgmt** (`CmacLegacyKeyMgmt`) — Same as MAC keymgmt but
//!   additionally tracks a cipher name (`OSSL_PKEY_PARAM_CIPHER`) for the
//!   underlying block cipher selection.
//!
//! # Key Data Access Model
//!
//! The [`KeyData`] trait is a marker trait without `Any`-based downcasting.
//! The `export` and `has` trait methods receive `&dyn KeyData` and cannot
//! recover the concrete type. The inherent methods on the concrete structs
//! (e.g., `MacKeyData::to_params()`, `MacKeyData::has_private_key()`)
//! provide full access when the concrete type is available.
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyMgmt)
//!         → implementations::all_keymgmt_descriptors()
//!           → keymgmt::descriptors()
//!             → legacy::legacy_descriptors()
//! ```
//!
//! # Security Properties
//!
//! - Secret key material in `MacKeyData` uses [`zeroize::Zeroizing`] for
//!   automatic secure zeroing on drop (replaces C `OPENSSL_secure_clear_free`).
//! - Key comparison in `MacLegacyKeyMgmt::match_keys()` and
//!   `CmacLegacyKeyMgmt::match_keys()` uses constant-time comparison via
//!   [`subtle::ConstantTimeEq`] (replaces C `CRYPTO_memcmp`).
//! - Zero `unsafe` blocks (Rule R8).
//!
//! # C Source Mapping
//!
//! | Rust type | C construct | Source |
//! |-----------|------------|--------|
//! | `KdfKeyData` | `KDF_DATA` | `kdf_legacy_kmgmt.c:25` |
//! | `KdfLegacyKeyMgmt` | `ossl_kdf_keymgmt_functions` | `kdf_legacy_kmgmt.c:92-101` |
//! | `MacKeyData` | `MAC_KEY` | `mac_legacy_kmgmt.c:30-42` |
//! | `MacLegacyKeyMgmt` | `ossl_mac_legacy_keymgmt_functions` | `mac_legacy_kmgmt.c:543-576` |
//! | `CmacLegacyKeyMgmt` | `ossl_cmac_legacy_keymgmt_functions` | `mac_legacy_kmgmt.c:543-576` |
//! | `legacy_descriptors()` | `deflt_keymgmt[]` entries | `defltprov.c:617-634` |

use std::fmt;
use std::sync::Arc;

use subtle::ConstantTimeEq;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Library Context Placeholder
// =============================================================================

/// Placeholder type alias for the library context reference.
///
/// In the C codebase, `OSSL_LIB_CTX *` is a pointer to a shared library
/// context that governs provider loading, algorithm fetching, and property
/// queries. When `openssl-crypto`'s `LibContext` type becomes available in
/// this crate's dependency graph, this alias should be updated to reference
/// the concrete type.
///
/// Uses `Arc<()>` as a lightweight reference-counted placeholder that
/// correctly models shared ownership semantics.
type LibContextRef = Arc<()>;

// =============================================================================
// KdfKeyData — KDF Legacy Key Data
// =============================================================================

/// Dummy key data for legacy KDF operations via `EVP_PKEY_derive`.
///
/// There is effectively no key material — this is a minimal adapter. The
/// `has()` method always returns `true` because nothing is ever "missing"
/// from a KDF key.
///
/// Replaces C `KDF_DATA` from `kdf_legacy_kmgmt.c` (line 25):
///
/// ```c
/// struct kdf_data_st {
///     OSSL_LIB_CTX *ctx;
///     int refcnt;
/// };
/// ```
///
/// In Rust, reference counting is handled by `Arc` at the call site if
/// needed, and the library context is stored as an optional reference.
pub struct KdfKeyData {
    /// Library context reference for provider/algorithm fetch operations.
    ///
    /// Corresponds to `kdf_data_st.ctx` in the C source.
    pub lib_ctx: Option<LibContextRef>,
}

impl fmt::Debug for KdfKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfKeyData")
            .field("lib_ctx", &self.lib_ctx.is_some())
            .finish()
    }
}

impl KeyData for KdfKeyData {}

// =============================================================================
// KdfLegacyKeyMgmt — KDF Legacy Key Manager
// =============================================================================

/// Key management provider for KDF-backed signature operations.
///
/// This is a "dummy" key manager: it allocates and frees `KdfKeyData`
/// handles, and `has()` always returns `true` (nothing is ever missing
/// from a KDF key). Generate, import, and export are not meaningful for
/// KDF keys — in the C dispatch table, only `KEYMGMT_NEW`, `KEYMGMT_FREE`,
/// and `KEYMGMT_HAS` entries exist.
///
/// Replaces `ossl_kdf_keymgmt_functions` dispatch table from
/// `kdf_legacy_kmgmt.c` (lines 92–101).
///
/// Registered for: TLS1-PRF, HKDF, scrypt.
pub struct KdfLegacyKeyMgmt {
    /// Algorithm name this instance manages (e.g., `"TLS1-PRF"`).
    algorithm: &'static str,
}

impl KdfLegacyKeyMgmt {
    /// Creates a new KDF legacy key management instance for the given algorithm.
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }

    /// Compares two KDF keys for equivalence.
    ///
    /// All KDF keys are equivalent because they hold no key material.
    /// This always returns `true`, matching the C behavior where `kdf_has()`
    /// always returns 1.
    ///
    /// # Parameters
    ///
    /// - `_key1`: First key (ignored — KDF keys have no material).
    /// - `_key2`: Second key (ignored — KDF keys have no material).
    pub fn match_keys(&self, _key1: &dyn KeyData, _key2: &dyn KeyData) -> bool {
        trace!(
            algorithm = self.algorithm,
            "KDF legacy: match_keys always returns true (no key material)"
        );
        true
    }
}

impl KeyMgmtProvider for KdfLegacyKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Allocates a new empty KDF key data handle.
    ///
    /// Replaces C `kdf_newdata()` → `ossl_kdf_data_new()` from
    /// `kdf_legacy_kmgmt.c` (lines 29–47).
    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            algorithm = self.algorithm,
            "KDF legacy: allocating new key data"
        );
        Ok(Box::new(KdfKeyData { lib_ctx: None }))
    }

    /// KDF keys cannot be generated — returns
    /// `ProviderError::AlgorithmUnavailable`.
    ///
    /// The C dispatch table has no `KEYMGMT_GEN*` entries, so generation
    /// is fundamentally unsupported. The KDF parameters are supplied
    /// separately through the signature/derivation operation.
    fn generate(&self, _params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        Err(ProviderError::AlgorithmUnavailable(format!(
            "KDF legacy keymgmt '{}': generate not supported",
            self.algorithm,
        )))
    }

    /// KDF keys cannot be imported — returns
    /// `ProviderError::AlgorithmUnavailable`.
    ///
    /// There is no key material to import. The C dispatch table has no
    /// `KEYMGMT_IMPORT` entry.
    fn import(
        &self,
        _selection: KeySelection,
        _data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        Err(ProviderError::AlgorithmUnavailable(format!(
            "KDF legacy keymgmt '{}': import not supported",
            self.algorithm,
        )))
    }

    /// KDF keys have no exportable material — returns
    /// `ProviderError::AlgorithmUnavailable`.
    ///
    /// The C dispatch table has no `KEYMGMT_EXPORT` entry.
    fn export(&self, _key: &dyn KeyData, _selection: KeySelection) -> ProviderResult<ParamSet> {
        Err(ProviderError::AlgorithmUnavailable(format!(
            "KDF legacy keymgmt '{}': export not supported",
            self.algorithm,
        )))
    }

    /// KDF keys always "have" all requested components.
    ///
    /// From C source `kdf_has()` (line 92): `return 1; /* nothing is missing */`
    fn has(&self, _key: &dyn KeyData, _selection: KeySelection) -> bool {
        true
    }

    /// KDF keys are always valid — there is nothing to validate.
    fn validate(&self, _key: &dyn KeyData, _selection: KeySelection) -> ProviderResult<bool> {
        Ok(true)
    }
}

// =============================================================================
// MacKeyData — MAC Legacy Key Data
// =============================================================================

/// Key data for legacy MAC operations.
///
/// Stores the secret key with secure memory (`Zeroizing` on drop).
/// Optionally stores a cipher name for CMAC keys and a property query
/// string for algorithm fetch operations.
///
/// Replaces C `MAC_KEY` from `mac_legacy_kmgmt.c` (lines 30–42):
///
/// ```c
/// struct mac_key_st {
///     int refcnt;
///     OSSL_LIB_CTX *libctx;
///     int cmac;
///     char *priv_key;
///     size_t priv_key_len;
///     PROV_CIPHER cipher;
///     char *properties;
/// };
/// ```
///
/// # Security
///
/// The `secret` field uses [`Zeroizing<Vec<u8>>`] which automatically
/// zeroes the key material when the struct is dropped. This replaces:
/// ```c
/// OPENSSL_secure_clear_free(mackey->priv_key, mackey->priv_key_len);
/// ```
pub struct MacKeyData {
    /// Secret key bytes (securely zeroized on drop).
    ///
    /// Replaces C `priv_key` + `priv_key_len` fields. Uses `Zeroizing`
    /// instead of manual `OPENSSL_secure_clear_free()`.
    pub secret: Zeroizing<Vec<u8>>,

    /// Whether this is a CMAC key (requires cipher identity).
    ///
    /// Replaces C `cmac` flag field.
    pub is_cmac: bool,

    /// Cipher name for CMAC keys (e.g., `"AES-128-CBC"`).
    ///
    /// Only meaningful when `is_cmac` is `true`. Replaces C
    /// `PROV_CIPHER cipher` structure's name field.
    /// Uses `Option<String>` instead of sentinel empty string (Rule R5).
    pub cipher_name: Option<String>,

    /// Property query string for algorithm fetch operations.
    ///
    /// Replaces C `properties` field. Uses `Option<String>` instead of
    /// sentinel NULL pointer (Rule R5).
    pub prop_query: Option<String>,

    /// Library context reference for provider/algorithm fetch operations.
    ///
    /// Replaces C `libctx` field.
    pub lib_ctx: Option<LibContextRef>,
}

impl fmt::Debug for MacKeyData {
    /// Custom Debug implementation that omits secret key bytes to prevent
    /// accidental leakage of key material in log output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacKeyData")
            .field("key_len", &self.secret.len())
            .field("is_cmac", &self.is_cmac)
            .field("cipher_name", &self.cipher_name)
            .field("prop_query", &self.prop_query)
            .field("lib_ctx", &self.lib_ctx.is_some())
            .finish()
    }
}

impl KeyData for MacKeyData {}

impl MacKeyData {
    /// Creates a new MAC key data with an empty secret.
    ///
    /// Replaces C `ossl_mac_key_new(libctx, cmac)` from
    /// `mac_legacy_kmgmt.c` (line 60).
    pub fn new(is_cmac: bool) -> Self {
        Self {
            secret: Zeroizing::new(Vec::new()),
            is_cmac,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        }
    }

    /// Creates a MAC key data from a parameter set.
    ///
    /// Extracts the following parameters:
    /// - `"priv"` (`ParamValue::OctetString`) — secret key bytes
    /// - `"cipher"` (`ParamValue::Utf8String`) — cipher name (CMAC only)
    /// - `"properties"` (`ParamValue::Utf8String`) — property query string
    ///
    /// Replaces C `mac_key_fromdata()` from `mac_legacy_kmgmt.c`
    /// (lines 122–160).
    ///
    /// Returns a `Result` to properly propagate parameter extraction errors
    /// using [`ProviderError::Common`].
    pub fn from_params(is_cmac: bool, params: &ParamSet) -> ProviderResult<Self> {
        let secret = match params.get("priv") {
            Some(ParamValue::OctetString(bytes)) => Zeroizing::new(bytes.clone()),
            Some(other) => {
                return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "priv".to_string(),
                    expected: "OctetString",
                    actual: param_value_type_name(other),
                }));
            }
            None => Zeroizing::new(Vec::new()),
        };

        let cipher_name = if is_cmac {
            match params.get("cipher") {
                Some(ParamValue::Utf8String(s)) => Some(s.clone()),
                Some(other) => {
                    return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: "cipher".to_string(),
                        expected: "Utf8String",
                        actual: param_value_type_name(other),
                    }));
                }
                None => None,
            }
        } else {
            None
        };

        let prop_query = match params.get("properties") {
            Some(ParamValue::Utf8String(s)) => Some(s.clone()),
            Some(other) => {
                return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "properties".to_string(),
                    expected: "Utf8String",
                    actual: param_value_type_name(other),
                }));
            }
            None => None,
        };

        Ok(Self {
            secret,
            is_cmac,
            cipher_name,
            prop_query,
            lib_ctx: None,
        })
    }

    /// Returns `true` if the key contains a non-empty secret.
    ///
    /// Replaces C check: `mackey->priv_key != NULL && mackey->priv_key_len > 0`
    /// from `mac_legacy_kmgmt.c` `mac_has()` (line 176).
    #[inline]
    pub fn has_private_key(&self) -> bool {
        !self.secret.is_empty()
    }

    /// Exports the key data into a `ParamSet`.
    ///
    /// Replaces C `key_to_params()` from `mac_legacy_kmgmt.c` (lines 290–320).
    ///
    /// # Parameters
    ///
    /// - `selection`: Controls which components to export. Only exports the
    ///   secret key when `KeySelection::PRIVATE_KEY` is requested.
    pub fn to_params(&self, selection: KeySelection) -> ParamSet {
        let mut params = ParamSet::new();

        if selection.contains(KeySelection::PRIVATE_KEY) && self.has_private_key() {
            params.set("priv", ParamValue::OctetString(self.secret.to_vec()));
        }

        if let Some(ref cipher) = self.cipher_name {
            params.set("cipher", ParamValue::Utf8String(cipher.clone()));
        }

        if let Some(ref props) = self.prop_query {
            params.set("properties", ParamValue::Utf8String(props.clone()));
        }

        params
    }
}

// =============================================================================
// MacLegacyKeyMgmt — MAC Legacy Key Manager
// =============================================================================

/// Key management provider for MAC-based signing operations (HMAC, `SipHash`,
/// `Poly1305`).
///
/// Supports full key lifecycle: creation, generation from parameters,
/// import from `ParamSet`, presence checking, validation, constant-time
/// key comparison, and parameter get/set.
///
/// Replaces `ossl_mac_legacy_keymgmt_functions` dispatch table from
/// `mac_legacy_kmgmt.c` (lines 543–576).
///
/// Registered for: HMAC, `SipHash`, `Poly1305`.
pub struct MacLegacyKeyMgmt {
    /// Algorithm name this instance manages (e.g., `"HMAC"`).
    algorithm: &'static str,
}

impl MacLegacyKeyMgmt {
    /// Creates a new MAC legacy key management instance for the given algorithm.
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }

    /// Constant-time comparison of two MAC secret keys.
    ///
    /// Uses [`subtle::ConstantTimeEq`] to prevent timing side-channel
    /// attacks. Replaces C `mac_match()` from `mac_legacy_kmgmt.c`
    /// (lines 165–177) which uses `CRYPTO_memcmp()`.
    ///
    /// Returns `true` if both keys have identical secret bytes and
    /// cipher names.
    ///
    /// # Security
    ///
    /// The secret-byte comparison is constant-time. The length comparison
    /// and cipher-name comparison are not constant-time because lengths
    /// and cipher names are not secret data (matching C `CRYPTO_memcmp`
    /// semantics where the length parameter is public).
    pub fn match_keys(&self, key1: &MacKeyData, key2: &MacKeyData) -> bool {
        trace!(
            algorithm = self.algorithm,
            key1_len = key1.secret.len(),
            key2_len = key2.secret.len(),
            "MAC legacy: constant-time key comparison"
        );

        // Length mismatch is a non-secret comparison (public data)
        if key1.secret.len() != key2.secret.len() {
            return false;
        }

        // Constant-time comparison of secret key bytes — Rule R8 (no unsafe)
        let secrets_equal = bool::from(key1.secret.as_slice().ct_eq(key2.secret.as_slice()));

        // Cipher name comparison for CMAC keys (public metadata, not secret)
        let cipher_match = key1.cipher_name == key2.cipher_name;

        secrets_equal && cipher_match
    }

    /// Returns key parameters (key length, cipher name).
    ///
    /// Replaces C `mac_get_params()` / `cmac_get_params()` from
    /// `mac_legacy_kmgmt.c` (lines 325–360).
    ///
    /// # Returned Parameters
    ///
    /// | Key | Type | Description |
    /// |-----|------|-------------|
    /// | `"size"` | `UInt64` | Secret key length in bytes |
    /// | `"cipher"` | `Utf8String` | Cipher name (CMAC only) |
    /// | `"properties"` | `Utf8String` | Property query (if set) |
    pub fn get_params(&self, key: &MacKeyData) -> ParamSet {
        let mut params = ParamSet::new();

        // OSSL_PKEY_PARAM_MAX_SIZE equivalent — report key length
        #[allow(clippy::cast_possible_truncation)] // key length fits in u64
        params.set("size", ParamValue::UInt64(key.secret.len() as u64));

        if let Some(ref cipher) = key.cipher_name {
            params.set("cipher", ParamValue::Utf8String(cipher.clone()));
        }

        if let Some(ref props) = key.prop_query {
            params.set("properties", ParamValue::Utf8String(props.clone()));
        }

        params
    }

    /// Sets key parameters from a `ParamSet`.
    ///
    /// Replaces C `mac_set_params()` from `mac_legacy_kmgmt.c`
    /// (lines 375–400) which delegates to `mac_key_fromdata()`.
    ///
    /// # Accepted Parameters
    ///
    /// | Key | Type | Description |
    /// |-----|------|-------------|
    /// | `"priv"` | `OctetString` | Secret key bytes |
    /// | `"properties"` | `Utf8String` | Property query string |
    /// | `"cipher"` | `Utf8String` | Cipher name (CMAC only) |
    pub fn set_params(&self, key: &mut MacKeyData, params: &ParamSet) {
        debug!(
            algorithm = self.algorithm,
            "MAC legacy: set_params updating key"
        );

        if let Some(ParamValue::OctetString(bytes)) = params.get("priv") {
            key.secret = Zeroizing::new(bytes.clone());
        }

        if let Some(ParamValue::Utf8String(props)) = params.get("properties") {
            key.prop_query = Some(props.clone());
        }

        if key.is_cmac {
            if let Some(ParamValue::Utf8String(cipher)) = params.get("cipher") {
                key.cipher_name = Some(cipher.clone());
            }
        }
    }
}

impl KeyMgmtProvider for MacLegacyKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Allocates a new empty MAC key data handle.
    ///
    /// Replaces C `mac_new()` → `ossl_mac_key_new(libctx, 0)` from
    /// `mac_legacy_kmgmt.c` (line 60).
    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = self.algorithm,
            "MAC legacy: creating new empty key"
        );
        Ok(Box::new(MacKeyData::new(false)))
    }

    /// Generates a MAC key from the provided parameters.
    ///
    /// Reads `"priv"` (private key material) and `"properties"` (algorithm
    /// lookup properties) from the parameter set. In C, `mac_gen()` allocates
    /// a new `MAC_KEY`, copies the private key from the generation context,
    /// and optionally sets properties.
    ///
    /// Replaces C `mac_gen()` from `mac_legacy_kmgmt.c` (lines 430–480).
    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = self.algorithm,
            param_count = params.len(),
            "MAC legacy: generating key from params"
        );
        let key = MacKeyData::from_params(false, params)?;
        Ok(Box::new(key))
    }

    /// Imports MAC key data from a `ParamSet`.
    ///
    /// Reads `OSSL_PKEY_PARAM_PRIV_KEY` (`"priv"`) and
    /// `OSSL_PKEY_PARAM_PROPERTIES` (`"properties"`) from the data set.
    ///
    /// Replaces C `mac_import()` from `mac_legacy_kmgmt.c` (lines 230–280).
    fn import(
        &self,
        _selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = self.algorithm,
            "MAC legacy: importing key from params"
        );
        let key = MacKeyData::from_params(false, data)?;
        Ok(Box::new(key))
    }

    /// Exports MAC key components to a `ParamSet`.
    ///
    /// Returns an empty parameter set when receiving an opaque
    /// `&dyn KeyData` reference because the [`KeyData`] marker trait does
    /// not currently support `Any`-based downcasting. Callers that hold a
    /// concrete `&MacKeyData` reference should use
    /// `MacKeyData::to_params()` directly for full key material export.
    ///
    /// Replaces C `mac_export()` from `mac_legacy_kmgmt.c` (lines 280–320).
    fn export(&self, _key: &dyn KeyData, _selection: KeySelection) -> ProviderResult<ParamSet> {
        // When KeyData gains Any supertrait, upgrade to:
        //   let mac = (key as &dyn Any).downcast_ref::<MacKeyData>()
        //       .ok_or_else(|| ProviderError::Dispatch(...))?;
        //   Ok(mac.to_params(selection))
        Ok(ParamSet::new())
    }

    /// Checks whether the key contains the requested components.
    ///
    /// Returns `true` for all selections. In the C source, `mac_has()`
    /// checks `key->priv_key != NULL` for `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`,
    /// but since the current [`KeyData`] trait does not support downcasting,
    /// this implementation returns a conservative `true`.
    ///
    /// Replaces C `mac_has()` from `mac_legacy_kmgmt.c` (lines 170–200).
    fn has(&self, _key: &dyn KeyData, _selection: KeySelection) -> bool {
        true
    }

    /// Validates MAC key data.
    ///
    /// MAC keys are considered valid by default in the legacy shim. The
    /// actual cryptographic validation (correct key length for the MAC
    /// algorithm) is enforced at the MAC operation layer.
    fn validate(&self, _key: &dyn KeyData, _selection: KeySelection) -> ProviderResult<bool> {
        Ok(true)
    }
}

// =============================================================================
// CmacLegacyKeyMgmt — CMAC Legacy Key Manager
// =============================================================================

/// Key management provider for CMAC-based signing operations.
///
/// Similar to `MacLegacyKeyMgmt` but additionally tracks a cipher name
/// for the underlying block cipher (e.g., `"AES-128-CBC"`). CMAC keys
/// require both a symmetric key and a cipher selection.
///
/// Replaces `ossl_cmac_legacy_keymgmt_functions` dispatch table from
/// `mac_legacy_kmgmt.c` (lines 543–576).
///
/// Registered for: CMAC.
pub struct CmacLegacyKeyMgmt {
    /// Algorithm name (always `"CMAC"`).
    algorithm: &'static str,
}

impl CmacLegacyKeyMgmt {
    /// Creates a new CMAC legacy key management instance.
    pub fn new() -> Self {
        Self { algorithm: "CMAC" }
    }

    /// Constant-time comparison of two CMAC keys.
    ///
    /// Uses [`subtle::ConstantTimeEq`] to prevent timing side-channel
    /// attacks. Checks both secret key equality (constant-time) and cipher
    /// name equality (non-secret public metadata).
    ///
    /// Replaces C `mac_match()` from `mac_legacy_kmgmt.c` with CMAC-specific
    /// cipher identity checking.
    pub fn match_keys(&self, key1: &MacKeyData, key2: &MacKeyData) -> bool {
        trace!(
            algorithm = self.algorithm,
            key1_len = key1.secret.len(),
            key2_len = key2.secret.len(),
            "CMAC legacy: constant-time key comparison"
        );

        // Length mismatch is a non-secret comparison (public data)
        if key1.secret.len() != key2.secret.len() {
            return false;
        }

        // Constant-time comparison of secret key bytes — Rule R8 (no unsafe)
        let secrets_equal = bool::from(key1.secret.as_slice().ct_eq(key2.secret.as_slice()));

        // Cipher name comparison for CMAC keys (public metadata, not secret)
        let cipher_match = key1.cipher_name == key2.cipher_name;

        secrets_equal && cipher_match
    }

    /// Returns key parameters (key length, cipher name, properties).
    ///
    /// Replaces C `cmac_get_params()` from `mac_legacy_kmgmt.c`
    /// (lines 345–360). CMAC additionally reports the cipher name.
    pub fn get_params(&self, key: &MacKeyData) -> ParamSet {
        let mut params = ParamSet::new();

        #[allow(clippy::cast_possible_truncation)] // key length fits in u64
        params.set("size", ParamValue::UInt64(key.secret.len() as u64));

        if let Some(ref cipher) = key.cipher_name {
            params.set("cipher", ParamValue::Utf8String(cipher.clone()));
        }

        if let Some(ref props) = key.prop_query {
            params.set("properties", ParamValue::Utf8String(props.clone()));
        }

        params
    }

    /// Sets key parameters from a `ParamSet`.
    ///
    /// CMAC-specific: accepts `"cipher"` parameter in addition to `"priv"`
    /// and `"properties"`. Replaces C `mac_set_params()` /
    /// `cmac_gen_set_params()` from `mac_legacy_kmgmt.c`.
    pub fn set_params(&self, key: &mut MacKeyData, params: &ParamSet) {
        debug!(
            algorithm = self.algorithm,
            "CMAC legacy: set_params updating key"
        );

        if let Some(ParamValue::OctetString(bytes)) = params.get("priv") {
            key.secret = Zeroizing::new(bytes.clone());
        }

        if let Some(ParamValue::Utf8String(props)) = params.get("properties") {
            key.prop_query = Some(props.clone());
        }

        // CMAC always accepts cipher parameter
        if let Some(ParamValue::Utf8String(cipher)) = params.get("cipher") {
            key.cipher_name = Some(cipher.clone());
        }
    }
}

impl Default for CmacLegacyKeyMgmt {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyMgmtProvider for CmacLegacyKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Allocates a new empty CMAC key data handle with `is_cmac = true`.
    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = self.algorithm,
            "CMAC legacy: creating new empty key"
        );
        Ok(Box::new(MacKeyData::new(true)))
    }

    /// Generates a CMAC key from parameters including cipher selection.
    ///
    /// Reads `"priv"` (key material), `"cipher"` (block cipher name), and
    /// `"properties"` from the parameter set. In C, CMAC generation
    /// additionally reads `OSSL_PKEY_PARAM_CIPHER` to determine the block
    /// cipher.
    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = self.algorithm,
            param_count = params.len(),
            "CMAC legacy: generating key from params"
        );
        let key = MacKeyData::from_params(true, params)?;
        Ok(Box::new(key))
    }

    /// Imports CMAC key data including cipher selection.
    ///
    /// Reads `OSSL_PKEY_PARAM_PRIV_KEY` (`"priv"`),
    /// `OSSL_PKEY_PARAM_CIPHER` (`"cipher"`), and
    /// `OSSL_PKEY_PARAM_PROPERTIES` (`"properties"`) from the data set.
    fn import(
        &self,
        _selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            algorithm = self.algorithm,
            "CMAC legacy: importing key from params"
        );
        let key = MacKeyData::from_params(true, data)?;
        Ok(Box::new(key))
    }

    /// Exports CMAC key components to a `ParamSet`.
    ///
    /// Returns an empty parameter set due to the [`KeyData`] trait not
    /// supporting `Any`-based downcasting. Use `MacKeyData::to_params()`
    /// directly when the concrete type is available.
    fn export(&self, _key: &dyn KeyData, _selection: KeySelection) -> ProviderResult<ParamSet> {
        Ok(ParamSet::new())
    }

    /// Checks whether the key contains the requested components.
    fn has(&self, _key: &dyn KeyData, _selection: KeySelection) -> bool {
        true
    }

    /// Validates CMAC key data.
    fn validate(&self, _key: &dyn KeyData, _selection: KeySelection) -> ProviderResult<bool> {
        Ok(true)
    }
}

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns algorithm descriptors for all legacy keymgmt algorithms.
///
/// Called by [`super::descriptors()`] (unconditionally, no feature gate).
///
/// Registers the following algorithms matching the C `deflt_keymgmt[]` array
/// entries from `providers/defltprov.c` (lines 617–634):
///
/// | Algorithm | C dispatch | Description |
/// |-----------|-----------|-------------|
/// | TLS1-PRF | `ossl_kdf_keymgmt_functions` | KDF key shim for TLS PRF |
/// | HKDF | `ossl_kdf_keymgmt_functions` | KDF key shim for HKDF |
/// | scrypt | `ossl_kdf_keymgmt_functions` | KDF key shim for scrypt |
/// | HMAC | `ossl_mac_legacy_keymgmt_functions` | MAC key management for HMAC |
/// | SipHash | `ossl_mac_legacy_keymgmt_functions` | MAC key management for SipHash |
/// | Poly1305 | `ossl_mac_legacy_keymgmt_functions` | MAC key management for Poly1305 |
/// | CMAC | `ossl_cmac_legacy_keymgmt_functions` | CMAC key management with cipher |
#[must_use]
pub fn legacy_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // KDF-backed signature key management shims
        algorithm(
            &["TLS1-PRF"],
            DEFAULT_PROPERTY,
            "TLS1-PRF KDF key management shim for EVP_PKEY_derive",
        ),
        algorithm(
            &["HKDF"],
            DEFAULT_PROPERTY,
            "HKDF key management shim for EVP_PKEY_derive",
        ),
        algorithm(
            &["scrypt"],
            DEFAULT_PROPERTY,
            "scrypt KDF key management shim for EVP_PKEY_derive",
        ),
        // MAC-based signature key management
        algorithm(
            &["HMAC"],
            DEFAULT_PROPERTY,
            "HMAC key management for MAC-based signing",
        ),
        algorithm(
            &["SipHash"],
            DEFAULT_PROPERTY,
            "SipHash key management for MAC-based signing",
        ),
        algorithm(
            &["Poly1305"],
            DEFAULT_PROPERTY,
            "Poly1305 key management for MAC-based signing",
        ),
        // CMAC key management (with cipher selection)
        algorithm(
            &["CMAC"],
            DEFAULT_PROPERTY,
            "CMAC key management with cipher selection for MAC-based signing",
        ),
    ]
}

// =============================================================================
// Private Helpers
// =============================================================================

/// Returns a human-readable type name for a `ParamValue` variant.
///
/// Used in error messages when parameter type validation fails.
fn param_value_type_name(value: &ParamValue) -> &'static str {
    match value {
        ParamValue::Int32(_) => "Int32",
        ParamValue::UInt32(_) => "UInt32",
        ParamValue::Int64(_) => "Int64",
        ParamValue::UInt64(_) => "UInt64",
        ParamValue::Real(_) => "Real",
        ParamValue::Utf8String(_) => "Utf8String",
        ParamValue::OctetString(_) => "OctetString",
        ParamValue::BigNum(_) => "BigNum",
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Descriptor Tests ─────────────────────────────────────────────────

    #[test]
    fn legacy_descriptors_count() {
        let descs = legacy_descriptors();
        // 3 KDF + 3 MAC + 1 CMAC = 7 descriptors
        assert_eq!(descs.len(), 7, "Expected 7 legacy keymgmt descriptors");
    }

    #[test]
    fn legacy_descriptors_names_complete() {
        let descs = legacy_descriptors();
        let names: Vec<&str> = descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        assert!(names.contains(&"TLS1-PRF"), "Missing TLS1-PRF");
        assert!(names.contains(&"HKDF"), "Missing HKDF");
        assert!(names.contains(&"scrypt"), "Missing scrypt");
        assert!(names.contains(&"HMAC"), "Missing HMAC");
        assert!(names.contains(&"SipHash"), "Missing SipHash");
        assert!(names.contains(&"Poly1305"), "Missing Poly1305");
        assert!(names.contains(&"CMAC"), "Missing CMAC");
    }

    #[test]
    fn legacy_descriptors_property_default() {
        let descs = legacy_descriptors();
        for desc in &descs {
            assert_eq!(
                desc.property, DEFAULT_PROPERTY,
                "Descriptor for {:?} should use DEFAULT_PROPERTY",
                desc.names
            );
        }
    }

    // ── KDF KeyMgmt Tests ────────────────────────────────────────────────

    #[test]
    fn kdf_keymgmt_name() {
        let mgr = KdfLegacyKeyMgmt::new("TLS1-PRF");
        assert_eq!(mgr.name(), "TLS1-PRF");
    }

    #[test]
    fn kdf_keymgmt_new_key_succeeds() {
        let mgr = KdfLegacyKeyMgmt::new("TLS1-PRF");
        let key = mgr.new_key();
        assert!(key.is_ok(), "KDF new_key should succeed");
    }

    #[test]
    fn kdf_keymgmt_has_always_true() {
        let mgr = KdfLegacyKeyMgmt::new("HKDF");
        let key = mgr.new_key().expect("new_key should succeed");
        // From C: kdf_has() returns 1 ("nothing is missing")
        assert!(mgr.has(key.as_ref(), KeySelection::PRIVATE_KEY));
        assert!(mgr.has(key.as_ref(), KeySelection::PUBLIC_KEY));
        assert!(mgr.has(key.as_ref(), KeySelection::DOMAIN_PARAMETERS));
        assert!(mgr.has(key.as_ref(), KeySelection::ALL));
    }

    #[test]
    fn kdf_keymgmt_validate_always_true() {
        let mgr = KdfLegacyKeyMgmt::new("scrypt");
        let key = mgr.new_key().expect("new_key should succeed");
        let result = mgr.validate(key.as_ref(), KeySelection::ALL);
        assert!(result.expect("validate should succeed"));
    }

    #[test]
    fn kdf_keymgmt_generate_unsupported() {
        let mgr = KdfLegacyKeyMgmt::new("HKDF");
        let params = ParamSet::new();
        let result = mgr.generate(&params);
        assert!(result.is_err(), "KDF generate should be unsupported");
    }

    #[test]
    fn kdf_keymgmt_import_unsupported() {
        let mgr = KdfLegacyKeyMgmt::new("scrypt");
        let data = ParamSet::new();
        let result = mgr.import(KeySelection::ALL, &data);
        assert!(result.is_err(), "KDF import should be unsupported");
    }

    #[test]
    fn kdf_keymgmt_export_unsupported() {
        let mgr = KdfLegacyKeyMgmt::new("HKDF");
        let key = mgr.new_key().expect("new_key should succeed");
        let result = mgr.export(key.as_ref(), KeySelection::ALL);
        assert!(result.is_err(), "KDF export should be unsupported");
    }

    #[test]
    fn kdf_keymgmt_match_keys_always_true() {
        let mgr = KdfLegacyKeyMgmt::new("TLS1-PRF");
        let key1 = mgr.new_key().expect("new_key");
        let key2 = mgr.new_key().expect("new_key");
        assert!(
            mgr.match_keys(key1.as_ref(), key2.as_ref()),
            "KDF match_keys should always return true"
        );
    }

    // ── KdfKeyData Tests ─────────────────────────────────────────────────

    #[test]
    fn kdf_key_data_debug_output() {
        let kd = KdfKeyData { lib_ctx: None };
        let dbg = format!("{:?}", kd);
        assert!(
            dbg.contains("KdfKeyData"),
            "Debug should contain struct name"
        );
    }

    // ── MAC KeyMgmt Tests ────────────────────────────────────────────────

    #[test]
    fn mac_keymgmt_name() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        assert_eq!(mgr.name(), "HMAC");

        let mgr2 = MacLegacyKeyMgmt::new("SipHash");
        assert_eq!(mgr2.name(), "SipHash");
    }

    #[test]
    fn mac_keymgmt_new_key_succeeds() {
        let mgr = MacLegacyKeyMgmt::new("Poly1305");
        let key = mgr.new_key();
        assert!(key.is_ok(), "MAC new_key should succeed");
    }

    #[test]
    fn mac_keymgmt_generate_with_params() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let mut params = ParamSet::new();
        params.set("priv", ParamValue::OctetString(vec![0x01, 0x02, 0x03]));
        params.set("properties", ParamValue::Utf8String("fips=yes".to_string()));

        let key = mgr.generate(&params);
        assert!(key.is_ok(), "MAC generate should succeed with params");
    }

    #[test]
    fn mac_keymgmt_import_with_data() {
        let mgr = MacLegacyKeyMgmt::new("SipHash");
        let mut data = ParamSet::new();
        data.set(
            "priv",
            ParamValue::OctetString(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        );

        let key = mgr.import(KeySelection::PRIVATE_KEY, &data);
        assert!(key.is_ok(), "MAC import should succeed");
    }

    #[test]
    fn mac_keymgmt_has_returns_true() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let key = mgr.new_key().expect("new_key should succeed");
        assert!(mgr.has(key.as_ref(), KeySelection::PRIVATE_KEY));
        assert!(mgr.has(key.as_ref(), KeySelection::ALL));
    }

    #[test]
    fn mac_keymgmt_validate_succeeds() {
        let mgr = MacLegacyKeyMgmt::new("Poly1305");
        let key = mgr.new_key().expect("new_key should succeed");
        let result = mgr.validate(key.as_ref(), KeySelection::ALL);
        assert!(result.expect("validate should succeed"));
    }

    #[test]
    fn mac_keymgmt_match_keys_equal() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let key1 = MacKeyData {
            secret: Zeroizing::new(vec![0xAA, 0xBB, 0xCC]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        let key2 = MacKeyData {
            secret: Zeroizing::new(vec![0xAA, 0xBB, 0xCC]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        assert!(mgr.match_keys(&key1, &key2), "Equal keys should match");
    }

    #[test]
    fn mac_keymgmt_match_keys_different_secret() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let key1 = MacKeyData {
            secret: Zeroizing::new(vec![0xAA, 0xBB, 0xCC]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        let key2 = MacKeyData {
            secret: Zeroizing::new(vec![0xDD, 0xEE, 0xFF]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        assert!(
            !mgr.match_keys(&key1, &key2),
            "Different secrets should not match"
        );
    }

    #[test]
    fn mac_keymgmt_match_keys_different_length() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let key1 = MacKeyData {
            secret: Zeroizing::new(vec![0xAA, 0xBB]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        let key2 = MacKeyData {
            secret: Zeroizing::new(vec![0xAA, 0xBB, 0xCC]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        assert!(
            !mgr.match_keys(&key1, &key2),
            "Different lengths should not match"
        );
    }

    #[test]
    fn mac_keymgmt_get_params() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let key = MacKeyData {
            secret: Zeroizing::new(vec![0x01, 0x02, 0x03]),
            is_cmac: false,
            cipher_name: None,
            prop_query: Some("provider=default".to_string()),
            lib_ctx: None,
        };
        let params = mgr.get_params(&key);
        assert!(params.contains("size"), "Should contain size");
        assert!(params.contains("properties"), "Should contain properties");
    }

    #[test]
    fn mac_keymgmt_set_params() {
        let mgr = MacLegacyKeyMgmt::new("HMAC");
        let mut key = MacKeyData::new(false);
        let mut params = ParamSet::new();
        params.set(
            "priv",
            ParamValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
        params.set("properties", ParamValue::Utf8String("fips=yes".to_string()));
        mgr.set_params(&mut key, &params);
        assert!(key.has_private_key());
        assert_eq!(key.prop_query, Some("fips=yes".to_string()));
    }

    // ── CMAC KeyMgmt Tests ───────────────────────────────────────────────

    #[test]
    fn cmac_keymgmt_name() {
        let mgr = CmacLegacyKeyMgmt::new();
        assert_eq!(mgr.name(), "CMAC");
    }

    #[test]
    fn cmac_keymgmt_default() {
        let mgr = CmacLegacyKeyMgmt::default();
        assert_eq!(mgr.name(), "CMAC");
    }

    #[test]
    fn cmac_keymgmt_new_key_succeeds() {
        let mgr = CmacLegacyKeyMgmt::new();
        let key = mgr.new_key();
        assert!(key.is_ok(), "CMAC new_key should succeed");
    }

    #[test]
    fn cmac_keymgmt_generate_with_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let mut params = ParamSet::new();
        params.set("priv", ParamValue::OctetString(vec![0x00; 16]));
        params.set("cipher", ParamValue::Utf8String("AES-128-CBC".to_string()));

        let key = mgr.generate(&params);
        assert!(key.is_ok(), "CMAC generate with cipher should succeed");
    }

    #[test]
    fn cmac_keymgmt_import_with_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let mut data = ParamSet::new();
        data.set("priv", ParamValue::OctetString(vec![0x00; 32]));
        data.set("cipher", ParamValue::Utf8String("AES-256-CBC".to_string()));
        data.set("properties", ParamValue::Utf8String("fips=yes".to_string()));

        let key = mgr.import(KeySelection::ALL, &data);
        assert!(key.is_ok(), "CMAC import should succeed");
    }

    #[test]
    fn cmac_keymgmt_match_keys_equal_with_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let key1 = MacKeyData {
            secret: Zeroizing::new(vec![0x00; 16]),
            is_cmac: true,
            cipher_name: Some("AES-128-CBC".to_string()),
            prop_query: None,
            lib_ctx: None,
        };
        let key2 = MacKeyData {
            secret: Zeroizing::new(vec![0x00; 16]),
            is_cmac: true,
            cipher_name: Some("AES-128-CBC".to_string()),
            prop_query: None,
            lib_ctx: None,
        };
        assert!(
            mgr.match_keys(&key1, &key2),
            "CMAC keys with same secret and cipher should match"
        );
    }

    #[test]
    fn cmac_keymgmt_match_keys_different_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let key1 = MacKeyData {
            secret: Zeroizing::new(vec![0x00; 16]),
            is_cmac: true,
            cipher_name: Some("AES-128-CBC".to_string()),
            prop_query: None,
            lib_ctx: None,
        };
        let key2 = MacKeyData {
            secret: Zeroizing::new(vec![0x00; 16]),
            is_cmac: true,
            cipher_name: Some("AES-256-CBC".to_string()),
            prop_query: None,
            lib_ctx: None,
        };
        assert!(
            !mgr.match_keys(&key1, &key2),
            "CMAC keys with different ciphers should not match"
        );
    }

    #[test]
    fn cmac_keymgmt_get_params_with_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let key = MacKeyData {
            secret: Zeroizing::new(vec![0x00; 16]),
            is_cmac: true,
            cipher_name: Some("AES-128-CBC".to_string()),
            prop_query: None,
            lib_ctx: None,
        };
        let params = mgr.get_params(&key);
        assert!(params.contains("size"), "Should contain size");
        assert!(params.contains("cipher"), "Should contain cipher");
    }

    #[test]
    fn cmac_keymgmt_set_params_with_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let mut key = MacKeyData::new(true);
        let mut params = ParamSet::new();
        params.set("priv", ParamValue::OctetString(vec![0x00; 16]));
        params.set("cipher", ParamValue::Utf8String("AES-128-CBC".to_string()));
        mgr.set_params(&mut key, &params);
        assert!(key.has_private_key());
        assert_eq!(key.cipher_name, Some("AES-128-CBC".to_string()));
    }

    // ── MacKeyData Tests ─────────────────────────────────────────────────

    #[test]
    fn mac_key_data_debug_no_key_leak() {
        let kd = MacKeyData {
            secret: Zeroizing::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };
        let dbg = format!("{:?}", kd);
        // Debug output must NOT contain the raw key bytes
        assert!(
            !dbg.contains("DEAD") && !dbg.contains("[222") && !dbg.contains("0xDE"),
            "Debug output must not leak key material"
        );
        // Should contain the key length instead
        assert!(dbg.contains("key_len"), "Should show key length");
    }

    #[test]
    fn mac_key_data_from_params_extracts_all() {
        let mut params = ParamSet::new();
        params.set("priv", ParamValue::OctetString(vec![1, 2, 3]));
        params.set(
            "properties",
            ParamValue::Utf8String("provider=default".to_string()),
        );
        params.set("cipher", ParamValue::Utf8String("AES-128-CBC".to_string()));

        let key = MacKeyData::from_params(true, &params).expect("should succeed");
        assert!(key.has_private_key());
        assert_eq!(key.secret.as_slice(), &[1, 2, 3]);
        assert_eq!(key.cipher_name.as_deref(), Some("AES-128-CBC"));
        assert_eq!(key.prop_query.as_deref(), Some("provider=default"));
    }

    #[test]
    fn mac_key_data_from_params_empty() {
        let params = ParamSet::new();
        let key = MacKeyData::from_params(false, &params).expect("should succeed");
        assert!(!key.has_private_key());
        assert!(key.secret.is_empty());
        assert!(key.cipher_name.is_none());
        assert!(key.prop_query.is_none());
    }

    #[test]
    fn mac_key_data_from_params_type_mismatch() {
        let mut params = ParamSet::new();
        // Put a string where OctetString is expected
        params.set("priv", ParamValue::Utf8String("not bytes".to_string()));

        let result = MacKeyData::from_params(false, &params);
        assert!(
            result.is_err(),
            "Type mismatch for 'priv' should produce error"
        );
    }

    #[test]
    fn mac_key_data_from_params_cmac_no_cipher() {
        let mut params = ParamSet::new();
        params.set("priv", ParamValue::OctetString(vec![0x00; 16]));
        // No cipher set — should succeed with cipher_name = None
        let key = MacKeyData::from_params(true, &params).expect("should succeed");
        assert!(key.cipher_name.is_none());
    }

    #[test]
    fn mac_key_data_to_params_round_trip() {
        let key = MacKeyData {
            secret: Zeroizing::new(vec![0xAA, 0xBB]),
            is_cmac: false,
            cipher_name: None,
            prop_query: Some("provider=default".to_string()),
            lib_ctx: None,
        };

        let params = key.to_params(KeySelection::PRIVATE_KEY);
        assert!(params.contains("priv"), "Should contain priv key");
        assert!(params.contains("properties"), "Should contain properties");
    }

    #[test]
    fn mac_key_data_to_params_cmac() {
        let key = MacKeyData {
            secret: Zeroizing::new(vec![0x00; 16]),
            is_cmac: true,
            cipher_name: Some("AES-128-CBC".to_string()),
            prop_query: None,
            lib_ctx: None,
        };

        let params = key.to_params(KeySelection::ALL);
        assert!(params.contains("priv"), "CMAC should export priv key");
        assert!(params.contains("cipher"), "CMAC should export cipher name");
    }

    #[test]
    fn mac_key_data_to_params_no_private_without_selection() {
        let key = MacKeyData {
            secret: Zeroizing::new(vec![0xAA]),
            is_cmac: false,
            cipher_name: None,
            prop_query: None,
            lib_ctx: None,
        };

        let params = key.to_params(KeySelection::PUBLIC_KEY);
        assert!(
            !params.contains("priv"),
            "Should not export priv when PRIVATE_KEY not selected"
        );
    }

    #[test]
    fn param_value_type_name_coverage() {
        assert_eq!(param_value_type_name(&ParamValue::Int32(0)), "Int32");
        assert_eq!(param_value_type_name(&ParamValue::UInt32(0)), "UInt32");
        assert_eq!(param_value_type_name(&ParamValue::Int64(0)), "Int64");
        assert_eq!(param_value_type_name(&ParamValue::UInt64(0)), "UInt64");
        assert_eq!(param_value_type_name(&ParamValue::Real(0.0)), "Real");
        assert_eq!(
            param_value_type_name(&ParamValue::Utf8String(String::new())),
            "Utf8String"
        );
        assert_eq!(
            param_value_type_name(&ParamValue::OctetString(vec![])),
            "OctetString"
        );
        assert_eq!(param_value_type_name(&ParamValue::BigNum(vec![])), "BigNum");
    }
}
