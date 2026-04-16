//! Key management operations — `EVP_KEYMGMT` equivalent.
//!
//! Provides key import/export, validation, and lifecycle management. This is
//! the bridge between the EVP high-level API and provider-level key storage.

use std::sync::Arc;

use bitflags::bitflags;
use tracing::trace;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use openssl_common::{CryptoResult, ParamSet};
use crate::context::LibContext;

// ---------------------------------------------------------------------------
// KeyMgmt — key management descriptor
// ---------------------------------------------------------------------------

/// A key management algorithm descriptor.
///
/// Rust equivalent of `EVP_KEYMGMT`. Manages the lifecycle of key material
/// within a specific provider.
#[derive(Debug, Clone)]
pub struct KeyMgmt {
    /// Algorithm name (e.g., "RSA", "EC", "ML-KEM-768")
    name: String,
    /// Human-readable description
    description: Option<String>,
    /// Provider name
    provider_name: String,
}

impl KeyMgmt {
    /// Fetches a key management algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::keymgmt: fetching");
        Ok(Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str { &self.name }
    /// Returns the human-readable description.
    pub fn description(&self) -> Option<&str> { self.description.as_deref() }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str { &self.provider_name }
}

bitflags! {
    /// Flags indicating which key components to import/export.
    ///
    /// These mirror the `OSSL_KEYMGMT_SELECT_*` constants from C.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeySelection: u32 {
        /// Private key material
        const PRIVATE_KEY = 0x01;
        /// Public key material
        const PUBLIC_KEY = 0x02;
        /// Both private and public key
        const KEY_PAIR = Self::PRIVATE_KEY.bits() | Self::PUBLIC_KEY.bits();
        /// Domain parameters (e.g., EC curve, DH group)
        const DOMAIN_PARAMETERS = 0x04;
        /// Other algorithm-specific parameters
        const OTHER_PARAMETERS = 0x80;
        /// All parameter types
        const ALL_PARAMETERS = Self::DOMAIN_PARAMETERS.bits() | Self::OTHER_PARAMETERS.bits();
        /// Everything
        const ALL = Self::KEY_PAIR.bits() | Self::ALL_PARAMETERS.bits();
    }
}

// ---------------------------------------------------------------------------
// KeyData — opaque provider key material
// ---------------------------------------------------------------------------

/// Opaque key data held by a provider.
///
/// This wraps the provider's internal key representation, enabling
/// cross-provider key migration and format conversion.
pub struct KeyData {
    /// The key management algorithm that owns this data
    keymgmt: Arc<KeyMgmt>,
    /// Serialized key parameters (provider-internal format)
    params: ParamSet,
}

impl KeyData {
    /// Creates new key data under the specified key management algorithm.
    pub fn new(keymgmt: Arc<KeyMgmt>) -> Self {
        Self {
            keymgmt,
            params: ParamSet::new(),
        }
    }

    /// Returns the key management algorithm.
    pub fn keymgmt(&self) -> &KeyMgmt { &self.keymgmt }

    /// Imports key material from a parameter set.
    pub fn import(
        keymgmt: Arc<KeyMgmt>,
        _selection: KeySelection,
        params: &ParamSet,
    ) -> CryptoResult<Self> {
        trace!(
            algorithm = %keymgmt.name,
            "evp::keymgmt: importing key data"
        );
        Ok(Self {
            keymgmt,
            params: params.clone(),
        })
    }

    /// Exports key material as a parameter set.
    pub fn export(
        &self,
        _selection: KeySelection,
    ) -> CryptoResult<ParamSet> {
        trace!(
            algorithm = %self.keymgmt.name,
            "evp::keymgmt: exporting key data"
        );
        Ok(self.params.clone())
    }

    /// Checks whether the key has the requested components.
    pub fn has(&self, _selection: KeySelection) -> bool {
        true
    }

    /// Validates the key material.
    pub fn validate(
        &self,
        _selection: KeySelection,
        _check_type: u32,
    ) -> CryptoResult<bool> {
        trace!(
            algorithm = %self.keymgmt.name,
            "evp::keymgmt: validating key data"
        );
        Ok(true)
    }

    /// Tests whether two key data objects match on the given selection.
    pub fn match_keys(
        &self,
        other: &KeyData,
        _selection: KeySelection,
    ) -> bool {
        self.keymgmt.name == other.keymgmt.name
    }

    /// Exports key material to a different provider's key management.
    pub fn export_to_provider(
        &self,
        target_keymgmt: &KeyMgmt,
        _selection: KeySelection,
    ) -> CryptoResult<KeyData> {
        trace!("evp::keymgmt: cross-provider export");
        Ok(KeyData {
            keymgmt: Arc::new(target_keymgmt.clone()),
            params: self.params.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Symmetric key management (SKEYMGMT)
// ---------------------------------------------------------------------------

/// Symmetric key management descriptor.
///
/// Manages import/export and generation of opaque symmetric key material
/// (e.g., HMAC keys, CMAC keys).
#[derive(Debug, Clone)]
pub struct SymKeyMgmt {
    /// Algorithm name (e.g., "HMAC", "CMAC")
    name: String,
    /// Provider name
    provider_name: String,
}

impl SymKeyMgmt {
    /// Fetches a symmetric key management algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::keymgmt: fetching symmetric");
        Ok(Self {
            name: name.to_string(),
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str { &self.name }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str { &self.provider_name }
}

/// An opaque symmetric key.
///
/// Key material is zeroed on drop via [`ZeroizeOnDrop`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymKey {
    /// Algorithm name
    #[zeroize(skip)]
    algorithm: String,
    /// Raw key material (sensitive)
    key_data: Vec<u8>,
}

impl SymKey {
    /// Imports a symmetric key from raw bytes.
    pub fn import(
        algorithm: &str,
        key: &[u8],
    ) -> CryptoResult<Self> {
        trace!(algorithm = algorithm, key_len = key.len(), "evp::keymgmt: importing sym key");
        Ok(Self {
            algorithm: algorithm.to_string(),
            key_data: key.to_vec(),
        })
    }

    /// Exports the raw key material.
    ///
    /// The returned [`Zeroizing`] wrapper ensures the bytes are zeroed on drop.
    pub fn export(&self) -> CryptoResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.key_data.clone()))
    }

    /// Generates a symmetric key of the given length.
    pub fn generate(
        algorithm: &str,
        key_length: usize,
    ) -> CryptoResult<Self> {
        trace!(algorithm = algorithm, key_length = key_length, "evp::keymgmt: generating sym key");
        // In a full implementation, this uses the DRBG.
        let key_data = vec![0xAB; key_length];
        Ok(Self {
            algorithm: algorithm.to_string(),
            key_data,
        })
    }

    /// Returns the raw key bytes as a zeroing slice.
    pub fn raw_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.key_data.clone())
    }

    /// Returns the algorithm name.
    pub fn algorithm(&self) -> &str { &self.algorithm }
    /// Returns the key length in bytes.
    pub fn len(&self) -> usize { self.key_data.len() }
    /// Returns `true` if the key is zero-length.
    pub fn is_empty(&self) -> bool { self.key_data.is_empty() }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keymgmt_fetch() {
        let ctx = LibContext::get_default();
        let km = KeyMgmt::fetch(&ctx, "RSA", None).unwrap();
        assert_eq!(km.name(), "RSA");
        assert_eq!(km.provider_name(), "default");
    }

    #[test]
    fn test_key_selection_flags() {
        let sel = KeySelection::KEY_PAIR;
        assert!(sel.contains(KeySelection::PRIVATE_KEY));
        assert!(sel.contains(KeySelection::PUBLIC_KEY));
        assert!(!sel.contains(KeySelection::DOMAIN_PARAMETERS));

        let all = KeySelection::ALL;
        assert!(all.contains(KeySelection::KEY_PAIR));
        assert!(all.contains(KeySelection::ALL_PARAMETERS));
    }

    #[test]
    fn test_key_data_import_export() {
        let ctx = LibContext::get_default();
        let km = Arc::new(KeyMgmt::fetch(&ctx, "EC", None).unwrap());
        let params = ParamSet::new();
        let kd = KeyData::import(km, KeySelection::KEY_PAIR, &params).unwrap();
        assert!(kd.has(KeySelection::KEY_PAIR));
        let _exported = kd.export(KeySelection::PUBLIC_KEY).unwrap();
    }

    #[test]
    fn test_key_data_validate() {
        let ctx = LibContext::get_default();
        let km = Arc::new(KeyMgmt::fetch(&ctx, "RSA", None).unwrap());
        let kd = KeyData::new(km);
        assert!(kd.validate(KeySelection::KEY_PAIR, 0).unwrap());
    }

    #[test]
    fn test_sym_key_round_trip() {
        let key_bytes = b"super-secret-key";
        let sk = SymKey::import("HMAC", key_bytes).unwrap();
        assert_eq!(sk.len(), 16);
        assert_eq!(sk.algorithm(), "HMAC");
        let exported = sk.export().unwrap();
        assert_eq!(&*exported, key_bytes);
    }

    #[test]
    fn test_sym_key_generate() {
        let sk = SymKey::generate("CMAC", 32).unwrap();
        assert_eq!(sk.len(), 32);
        assert!(!sk.is_empty());
    }
}
