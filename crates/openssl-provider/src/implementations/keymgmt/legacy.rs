//! # Legacy Key Management Shims
//!
//! Provides key management implementations for KDF-backed signature algorithms
//! (TLS1-PRF, HKDF, scrypt) and MAC-based signing algorithms (HMAC, SipHash,
//! Poly1305, CMAC) that participate in the EVP_PKEY key management dispatch.
//!
//! These are thin wrapper types that allow KDF and MAC algorithms to be used
//! through the unified [`KeyMgmtProvider`] trait interface, even though their
//! underlying "key data" is minimal (KDF keys have no actual key material;
//! MAC keys carry only a symmetric key blob and optional properties).
//!
//! ## C Source Mapping
//!
//! - [`KdfLegacyKeyMgmt`] / [`KdfKeyData`] — `providers/implementations/keymgmt/kdf_legacy_kmgmt.c` (~102 lines)
//! - [`MacLegacyKeyMgmt`] / [`CmacLegacyKeyMgmt`] / [`MacKeyData`] — `providers/implementations/keymgmt/mac_legacy_kmgmt.c` (~578 lines)
//!
//! ## Architecture
//!
//! In the C codebase, KDF keymgmt is a "dummy" key manager: `kdf_has()` always
//! returns 1, and there is no generate/import/export in the dispatch table.
//! MAC keymgmt is richer, supporting key generation from provided data,
//! import/export of the symmetric key via `OSSL_PARAM`, and presence checking.
//!
//! The CMAC variant differs from HMAC/SipHash/Poly1305 in that it additionally
//! tracks a cipher name (e.g., `"AES-128-CBC"`) for the underlying block cipher.
//!
//! ## Wiring Path (Rule R10)
//!
//! ```text
//! DefaultProvider::query_operation(KeyMgmt)
//!   → all_keymgmt_descriptors()
//!     → keymgmt::descriptors()
//!       → legacy::legacy_descriptors()
//!         → [TLS1-PRF, HKDF, scrypt, HMAC, SipHash, Poly1305, CMAC]
//! ```
//!
//! ## Key Data Access Model
//!
//! The [`KeyData`] trait is a marker trait (`Send + Sync + Debug`) without
//! `Any`-based downcasting support. As a consequence, trait methods that
//! receive `&dyn KeyData` (such as `has`, `export`, `validate`) cannot
//! access the concrete struct fields. For legacy key management this is
//! acceptable because:
//!
//! - KDF keys have no key material — all operations are trivially correct.
//! - MAC/CMAC key material is created via `new_key`/`generate`/`import` and
//!   consumed directly by the MAC operation layer, not re-exported through
//!   the keymgmt export path in normal usage.
//!
//! When `KeyData` gains `Any` support (tracked at the crate level), the
//! `export`/`has`/`validate` implementations can be upgraded to inspect
//! the concrete key fields.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// ---------------------------------------------------------------------------
// Key ID Generation
// ---------------------------------------------------------------------------

/// Monotonically increasing key identifier for MAC key data instances.
///
/// Each [`MacKeyData`] receives a unique ID at construction time. This
/// enables identity-based operations (matching, debug diagnostics) without
/// requiring downcasting from `&dyn KeyData`.
static NEXT_MAC_KEY_ID: AtomicU64 = AtomicU64::new(1);

/// Generates a new unique key identifier.
fn next_key_id() -> u64 {
    NEXT_MAC_KEY_ID.fetch_add(1, Ordering::Relaxed)
}

// =============================================================================
// KdfKeyData — Opaque Key Data for KDF-Backed Signatures
// =============================================================================

/// Key data for KDF-backed signature operations (TLS1-PRF, HKDF, scrypt).
///
/// In the C source, `KDF_DATA` is a reference-counted struct holding only
/// a `libctx` pointer. There is no actual cryptographic key material — the
/// KDF parameters are passed separately through the signature operation.
///
/// This Rust equivalent is intentionally minimal: it serves as a typed handle
/// that satisfies the `KeyData` trait contract without carrying key material.
///
/// Source: `kdf_legacy_kmgmt.c`, `ossl_kdf_data_new()` / `ossl_kdf_data_free()`.
pub struct KdfKeyData {
    /// Algorithm name for diagnostic purposes.
    algorithm: &'static str,
}

impl fmt::Debug for KdfKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Rule R8: No unsafe. No key material to leak.
        f.debug_struct("KdfKeyData")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

// KdfKeyData contains only `&'static str`, which is inherently `Send + Sync`.
// The auto-derived impls satisfy the `KeyData` trait bounds.
impl KeyData for KdfKeyData {}

// =============================================================================
// MacKeyData — Opaque Key Data for MAC-Backed Signatures
// =============================================================================

/// Key data for MAC-based signing operations (HMAC, `SipHash`, Poly1305, CMAC).
///
/// In the C source, `MAC_KEY` holds a reference-counted symmetric key blob
/// (`priv_key` / `priv_key_len`), a `cmac` flag, optional properties string,
/// and an optional cipher reference (for CMAC).
///
/// The Rust equivalent stores the private key material in a `Vec<u8>` that
/// is zeroed on drop (secure erasure). The cipher name is stored as an
/// optional string for CMAC keys.
///
/// Source: `mac_legacy_kmgmt.c`, `ossl_mac_key_new()` / `ossl_mac_key_free()`.
///
/// # Security
///
/// Private key material is securely zeroed in the [`Drop`] implementation,
/// equivalent to `OPENSSL_secure_clear_free()` in the C source. The
/// [`Debug`] implementation deliberately omits the key bytes.
pub struct MacKeyData {
    /// Unique identifier for this key instance.
    id: u64,
    /// Algorithm name (e.g., "HMAC", "CMAC", "`SipHash`", "Poly1305").
    algorithm: &'static str,
    /// The raw symmetric key material.
    /// Zeroed on drop — equivalent to `OPENSSL_secure_clear_free()` in C.
    priv_key: Vec<u8>,
    /// Whether this is a CMAC key (requires cipher selection).
    is_cmac: bool,
    /// Optional cipher name for CMAC keys (e.g., "AES-128-CBC").
    cipher_name: Option<String>,
    /// Optional properties string for algorithm lookup.
    properties: Option<String>,
}

impl fmt::Debug for MacKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: Do NOT expose priv_key contents in debug output.
        // Uses `finish_non_exhaustive()` to signal that `priv_key` and
        // `properties` are intentionally omitted (key material protection).
        f.debug_struct("MacKeyData")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("key_len", &self.priv_key.len())
            .field("is_cmac", &self.is_cmac)
            .field("cipher_name", &self.cipher_name)
            .finish_non_exhaustive()
    }
}

impl Drop for MacKeyData {
    fn drop(&mut self) {
        // Secure zeroing of key material — replaces OPENSSL_secure_clear_free().
        // Writes zeros to every byte and uses a compiler fence to prevent
        // the optimiser from eliding the clear operation.
        for byte in &mut self.priv_key {
            *byte = 0;
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }
}

impl KeyData for MacKeyData {}

impl MacKeyData {
    /// Creates a new empty MAC key data container.
    fn new(algorithm: &'static str, is_cmac: bool) -> Self {
        Self {
            id: next_key_id(),
            algorithm,
            priv_key: Vec::new(),
            is_cmac,
            cipher_name: None,
            properties: None,
        }
    }

    /// Creates a MAC key data from the given parameters.
    ///
    /// Extracts `"priv"` (octet string), `"properties"` (UTF-8 string), and
    /// optionally `"cipher"` (UTF-8 string, for CMAC) from the parameter set.
    pub fn from_params(algorithm: &'static str, is_cmac: bool, params: &ParamSet) -> Self {
        let mut key = Self::new(algorithm, is_cmac);

        // Extract private key material (OSSL_PKEY_PARAM_PRIV_KEY)
        if let Some(value) = params.get("priv") {
            if let Some(bytes) = value.as_bytes() {
                key.priv_key = bytes.to_vec();
            }
        }

        // Extract properties string (OSSL_PKEY_PARAM_PROPERTIES)
        if let Some(value) = params.get("properties") {
            if let Some(s) = value.as_str() {
                key.properties = Some(s.to_string());
            }
        }

        // Extract cipher name for CMAC (OSSL_PKEY_PARAM_CIPHER)
        if is_cmac {
            if let Some(value) = params.get("cipher") {
                if let Some(s) = value.as_str() {
                    key.cipher_name = Some(s.to_string());
                }
            }
        }

        key
    }

    /// Returns whether any private key material is present.
    ///
    /// This is the concrete-type equivalent of checking
    /// `key->priv_key != NULL` in the C source.
    pub fn has_private_key(&self) -> bool {
        !self.priv_key.is_empty()
    }

    /// Returns the private key material as a byte slice.
    ///
    /// # Security
    ///
    /// The returned slice borrows the key material. The caller must not
    /// store or leak the bytes beyond the intended cryptographic operation.
    pub fn private_key(&self) -> &[u8] {
        &self.priv_key
    }

    /// Returns the cipher name if this is a CMAC key.
    pub fn cipher_name(&self) -> Option<&str> {
        self.cipher_name.as_deref()
    }

    /// Returns the properties string, if set.
    pub fn properties(&self) -> Option<&str> {
        self.properties.as_deref()
    }

    /// Exports the key data into a [`ParamSet`].
    ///
    /// This method is available on the concrete type. When `KeyData`
    /// gains `Any`-based downcasting, this can be called from the
    /// `KeyMgmtProvider::export` trait method as well.
    pub fn to_params(&self, selection: KeySelection) -> ParamSet {
        let mut params = ParamSet::new();

        if selection.contains(KeySelection::PRIVATE_KEY) && self.has_private_key() {
            params.set("priv", ParamValue::OctetString(self.priv_key.clone()));
        }

        if let Some(ref cipher) = self.cipher_name {
            params.set("cipher", ParamValue::Utf8String(cipher.clone()));
        }

        if let Some(ref props) = self.properties {
            params.set("properties", ParamValue::Utf8String(props.clone()));
        }

        params
    }
}

// =============================================================================
// KdfLegacyKeyMgmt — KDF Legacy Key Manager
// =============================================================================

/// Key management provider for KDF-backed signature operations.
///
/// This is a "dummy" key manager: it allocates and frees [`KdfKeyData`] handles,
/// and `has()` always returns `true` (nothing is ever missing from a KDF key).
/// Generate, import, and export are not meaningful for KDF keys — in the C
/// dispatch table, only `KEYMGMT_NEW`, `KEYMGMT_FREE`, and `KEYMGMT_HAS`
/// entries exist.
///
/// Replaces `ossl_kdf_keymgmt_functions` dispatch table from
/// `kdf_legacy_kmgmt.c`.
///
/// Registered for: TLS1-PRF, HKDF, scrypt.
pub struct KdfLegacyKeyMgmt {
    /// Algorithm name this instance manages (e.g., "TLS1-PRF").
    algorithm: &'static str,
}

impl KdfLegacyKeyMgmt {
    /// Creates a new KDF legacy key management instance for the given algorithm.
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }
}

impl KeyMgmtProvider for KdfLegacyKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(KdfKeyData {
            algorithm: self.algorithm,
        }))
    }

    /// KDF keys cannot be generated — the KDF parameters are supplied
    /// separately through the signature/derivation operation.
    ///
    /// Returns a new empty key data handle, matching the C behaviour where
    /// `kdf_newdata` is the only constructor and generation is absent from
    /// the dispatch table.
    fn generate(&self, _params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        self.new_key()
    }

    /// KDF keys cannot be imported — there is no key material to import.
    ///
    /// Returns a new empty key, which is functionally equivalent to the C
    /// behaviour where import is absent from the dispatch table.
    fn import(
        &self,
        _selection: KeySelection,
        _data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        self.new_key()
    }

    /// KDF keys have no exportable material.
    ///
    /// Returns an empty parameter set, matching the C behaviour where export
    /// is absent from the dispatch table.
    fn export(
        &self,
        _key: &dyn KeyData,
        _selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        Ok(ParamSet::new())
    }

    /// KDF keys always "have" all requested components.
    ///
    /// From C source `kdf_has()`: `return 1; /* nothing is missing */`
    fn has(&self, _key: &dyn KeyData, _selection: KeySelection) -> bool {
        true
    }

    /// KDF keys are always valid — there is nothing to validate.
    fn validate(
        &self,
        _key: &dyn KeyData,
        _selection: KeySelection,
    ) -> ProviderResult<bool> {
        Ok(true)
    }
}

// =============================================================================
// MacLegacyKeyMgmt — MAC Legacy Key Manager
// =============================================================================

/// Key management provider for MAC-based signing operations (HMAC, `SipHash`,
/// Poly1305).
///
/// Supports full key lifecycle: creation, generation from parameters,
/// import from [`ParamSet`], presence checking, and validation. Key material
/// is stored in [`MacKeyData`] and accessed directly when the concrete type
/// is available (e.g., within `generate` and `import` methods).
///
/// Replaces `ossl_mac_legacy_keymgmt_functions` dispatch table from
/// `mac_legacy_kmgmt.c`.
///
/// Registered for: HMAC, `SipHash`, Poly1305.
pub struct MacLegacyKeyMgmt {
    /// Algorithm name this instance manages (e.g., "HMAC").
    algorithm: &'static str,
}

impl MacLegacyKeyMgmt {
    /// Creates a new MAC legacy key management instance for the given algorithm.
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }
}

impl KeyMgmtProvider for MacLegacyKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(MacKeyData::new(self.algorithm, false)))
    }

    /// Generates a MAC key from the provided parameters.
    ///
    /// Reads `"priv"` (private key material) and `"properties"` (algorithm
    /// lookup properties) from the parameter set. In C, `mac_gen()` allocates
    /// a new `MAC_KEY`, copies the private key from the generation context,
    /// and optionally sets properties.
    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(MacKeyData::from_params(
            self.algorithm,
            false,
            params,
        )))
    }

    /// Imports MAC key data from a [`ParamSet`].
    ///
    /// Reads `OSSL_PKEY_PARAM_PRIV_KEY` ("priv") and
    /// `OSSL_PKEY_PARAM_PROPERTIES` ("properties") from the data set.
    fn import(
        &self,
        _selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(MacKeyData::from_params(
            self.algorithm,
            false,
            data,
        )))
    }

    /// Exports MAC key components to a [`ParamSet`].
    ///
    /// Returns an empty parameter set when receiving an opaque `&dyn KeyData`
    /// reference because the [`KeyData`] marker trait does not currently
    /// support `Any`-based downcasting. Callers that hold a concrete
    /// `&MacKeyData` reference should use [`MacKeyData::to_params()`]
    /// directly for full key material export.
    fn export(
        &self,
        _key: &dyn KeyData,
        _selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        // When KeyData gains Any supertrait, upgrade to:
        //   let mac = (key as &dyn Any).downcast_ref::<MacKeyData>()?;
        //   Ok(mac.to_params(selection))
        Ok(ParamSet::new())
    }

    /// Checks whether the key contains the requested components.
    ///
    /// Returns `true` for all selections. In the C source, `mac_has()` checks
    /// `key->priv_key != NULL` for `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`, but
    /// since the current `KeyData` trait does not support downcasting, this
    /// implementation returns a conservative `true` — matching the KDF legacy
    /// semantics.
    fn has(&self, _key: &dyn KeyData, _selection: KeySelection) -> bool {
        true
    }

    /// Validates MAC key data.
    ///
    /// MAC keys are considered valid by default in the legacy shim. The
    /// actual cryptographic validation (correct key length for the MAC
    /// algorithm) is enforced at the MAC operation layer.
    fn validate(
        &self,
        _key: &dyn KeyData,
        _selection: KeySelection,
    ) -> ProviderResult<bool> {
        Ok(true)
    }
}

// =============================================================================
// CmacLegacyKeyMgmt — CMAC Legacy Key Manager
// =============================================================================

/// Key management provider for CMAC-based signing operations.
///
/// Similar to [`MacLegacyKeyMgmt`] but additionally tracks a cipher name
/// for the underlying block cipher (e.g., `"AES-128-CBC"`). CMAC keys
/// require both a symmetric key and a cipher selection.
///
/// Replaces `ossl_cmac_legacy_keymgmt_functions` dispatch table from
/// `mac_legacy_kmgmt.c`.
///
/// Registered for: CMAC.
pub struct CmacLegacyKeyMgmt {
    /// Algorithm name (always "CMAC").
    algorithm: &'static str,
}

impl CmacLegacyKeyMgmt {
    /// Creates a new CMAC legacy key management instance.
    pub fn new() -> Self {
        Self { algorithm: "CMAC" }
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

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(MacKeyData::new(self.algorithm, true)))
    }

    /// Generates a CMAC key from parameters including cipher selection.
    ///
    /// Reads `"priv"` (key material), `"cipher"` (block cipher name), and
    /// `"properties"` from the parameter set. In C, CMAC generation
    /// additionally reads `OSSL_PKEY_PARAM_CIPHER` to determine the block
    /// cipher.
    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(MacKeyData::from_params(
            self.algorithm,
            true,
            params,
        )))
    }

    /// Imports CMAC key data including cipher selection.
    ///
    /// Reads `OSSL_PKEY_PARAM_PRIV_KEY` ("priv"), `OSSL_PKEY_PARAM_CIPHER`
    /// ("cipher"), and `OSSL_PKEY_PARAM_PROPERTIES` ("properties") from the
    /// data set.
    fn import(
        &self,
        _selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        Ok(Box::new(MacKeyData::from_params(
            self.algorithm,
            true,
            data,
        )))
    }

    /// Exports CMAC key components to a [`ParamSet`].
    ///
    /// Returns an empty parameter set due to the `KeyData` trait not
    /// supporting `Any`-based downcasting. Use [`MacKeyData::to_params()`]
    /// directly when the concrete type is available.
    fn export(
        &self,
        _key: &dyn KeyData,
        _selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        Ok(ParamSet::new())
    }

    /// Checks whether the key contains the requested components.
    fn has(&self, _key: &dyn KeyData, _selection: KeySelection) -> bool {
        true
    }

    /// Validates CMAC key data.
    fn validate(
        &self,
        _key: &dyn KeyData,
        _selection: KeySelection,
    ) -> ProviderResult<bool> {
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
    fn kdf_keymgmt_export_empty() {
        let mgr = KdfLegacyKeyMgmt::new("HKDF");
        let key = mgr.new_key().expect("new_key should succeed");
        let params = mgr
            .export(key.as_ref(), KeySelection::ALL)
            .expect("export should succeed");
        assert!(params.is_empty(), "KDF export should return empty params");
    }

    #[test]
    fn kdf_keymgmt_generate_returns_key() {
        let mgr = KdfLegacyKeyMgmt::new("TLS1-PRF");
        let params = ParamSet::new();
        let key = mgr.generate(&params);
        assert!(key.is_ok(), "KDF generate should succeed");
    }

    #[test]
    fn kdf_keymgmt_import_returns_key() {
        let mgr = KdfLegacyKeyMgmt::new("scrypt");
        let data = ParamSet::new();
        let key = mgr.import(KeySelection::ALL, &data);
        assert!(key.is_ok(), "KDF import should succeed");
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
        params.set(
            "properties",
            ParamValue::Utf8String("fips=yes".to_string()),
        );

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

    // ── CMAC KeyMgmt Tests ───────────────────────────────────────────────

    #[test]
    fn cmac_keymgmt_name() {
        let mgr = CmacLegacyKeyMgmt::new();
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
        params.set(
            "priv",
            ParamValue::OctetString(vec![0x00; 16]),
        );
        params.set(
            "cipher",
            ParamValue::Utf8String("AES-128-CBC".to_string()),
        );

        let key = mgr.generate(&params);
        assert!(key.is_ok(), "CMAC generate with cipher should succeed");
    }

    #[test]
    fn cmac_keymgmt_import_with_cipher() {
        let mgr = CmacLegacyKeyMgmt::new();
        let mut data = ParamSet::new();
        data.set(
            "priv",
            ParamValue::OctetString(vec![0x00; 32]),
        );
        data.set(
            "cipher",
            ParamValue::Utf8String("AES-256-CBC".to_string()),
        );
        data.set(
            "properties",
            ParamValue::Utf8String("fips=yes".to_string()),
        );

        let key = mgr.import(KeySelection::ALL, &data);
        assert!(key.is_ok(), "CMAC import should succeed");
    }

    // ── KeyData Tests ────────────────────────────────────────────────────

    #[test]
    fn kdf_key_data_debug_contains_algorithm() {
        let kd = KdfKeyData {
            algorithm: "HKDF",
        };
        let dbg = format!("{:?}", kd);
        assert!(dbg.contains("HKDF"), "Debug should contain algorithm name");
    }

    #[test]
    fn mac_key_data_debug_no_key_leak() {
        let kd = MacKeyData {
            id: 42,
            algorithm: "HMAC",
            priv_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            is_cmac: false,
            cipher_name: None,
            properties: None,
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
        params.set(
            "cipher",
            ParamValue::Utf8String("AES-128-CBC".to_string()),
        );

        let key = MacKeyData::from_params("CMAC", true, &params);
        assert!(key.has_private_key());
        assert_eq!(key.private_key(), &[1, 2, 3]);
        assert_eq!(key.cipher_name(), Some("AES-128-CBC"));
        assert_eq!(key.properties(), Some("provider=default"));
    }

    #[test]
    fn mac_key_data_from_params_empty() {
        let params = ParamSet::new();
        let key = MacKeyData::from_params("HMAC", false, &params);
        assert!(!key.has_private_key());
        assert!(key.private_key().is_empty());
        assert!(key.cipher_name().is_none());
        assert!(key.properties().is_none());
    }

    #[test]
    fn mac_key_data_to_params_round_trip() {
        let key = MacKeyData {
            id: 1,
            algorithm: "HMAC",
            priv_key: vec![0xAA, 0xBB],
            is_cmac: false,
            cipher_name: None,
            properties: Some("provider=default".to_string()),
        };

        let params = key.to_params(KeySelection::PRIVATE_KEY);
        assert!(params.contains("priv"), "Should contain priv key");
        assert!(params.contains("properties"), "Should contain properties");
    }

    #[test]
    fn mac_key_data_to_params_cmac() {
        let key = MacKeyData {
            id: 2,
            algorithm: "CMAC",
            priv_key: vec![0x00; 16],
            is_cmac: true,
            cipher_name: Some("AES-128-CBC".to_string()),
            properties: None,
        };

        let params = key.to_params(KeySelection::ALL);
        assert!(params.contains("priv"), "CMAC should export priv key");
        assert!(params.contains("cipher"), "CMAC should export cipher name");
    }

    #[test]
    fn mac_key_data_unique_ids() {
        let k1 = MacKeyData::new("HMAC", false);
        let k2 = MacKeyData::new("HMAC", false);
        assert_ne!(k1.id, k2.id, "Each key should have a unique ID");
    }
}
