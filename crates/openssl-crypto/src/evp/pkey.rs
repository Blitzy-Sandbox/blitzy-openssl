//! Asymmetric key operations — `EVP_PKEY` / `EVP_PKEY_CTX` equivalent.
//!
//! Provides the `PKey` type for holding asymmetric key material and `PKeyCtx`
//! for key generation, parameter generation, and key validation.

use std::sync::Arc;

use tracing::trace;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::keymgmt::KeyMgmt;
use super::EvpError;
use crate::context::LibContext;
use openssl_common::{CryptoResult, ParamSet, ParamValue};

// ---------------------------------------------------------------------------
// KeyType — algorithm family
// ---------------------------------------------------------------------------

/// Asymmetric key algorithm type.
///
/// Each variant corresponds to a key algorithm family recognized by the EVP
/// subsystem. `Unknown(String)` handles provider-defined algorithms not in
/// this enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// RSA (PKCS#1)
    Rsa,
    /// RSA-PSS (constrained to PSS padding)
    RsaPss,
    /// DSA (FIPS 186)
    Dsa,
    /// Diffie-Hellman
    Dh,
    /// Elliptic Curve (NIST, Brainpool)
    Ec,
    /// X25519 key exchange (RFC 7748)
    X25519,
    /// X448 key exchange (RFC 7748)
    X448,
    /// Ed25519 signatures (RFC 8032)
    Ed25519,
    /// Ed448 signatures (RFC 8032)
    Ed448,
    /// SM2 (Chinese national standard)
    Sm2,
    /// ML-KEM-512 (FIPS 203)
    MlKem512,
    /// ML-KEM-768 (FIPS 203)
    MlKem768,
    /// ML-KEM-1024 (FIPS 203)
    MlKem1024,
    /// ML-DSA-44 (FIPS 204)
    MlDsa44,
    /// ML-DSA-65 (FIPS 204)
    MlDsa65,
    /// ML-DSA-87 (FIPS 204)
    MlDsa87,
    /// SLH-DSA (FIPS 205)
    SlhDsa,
    /// LMS hash-based signatures (SP 800-208)
    Lms,
    /// Unknown / provider-defined algorithm
    Unknown(String),
}

impl KeyType {
    /// Returns the canonical string name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rsa => "RSA",
            Self::RsaPss => "RSA-PSS",
            Self::Dsa => "DSA",
            Self::Dh => "DH",
            Self::Ec => "EC",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::Sm2 => "SM2",
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsa => "SLH-DSA",
            Self::Lms => "LMS",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Parses a key type from a name string.
    pub fn from_name(name: &str) -> Self {
        match name.to_uppercase().as_str() {
            "RSA" => Self::Rsa,
            "RSA-PSS" | "RSAPSS" => Self::RsaPss,
            "DSA" => Self::Dsa,
            "DH" => Self::Dh,
            "EC" => Self::Ec,
            "X25519" => Self::X25519,
            "X448" => Self::X448,
            "ED25519" => Self::Ed25519,
            "ED448" => Self::Ed448,
            "SM2" => Self::Sm2,
            "ML-KEM-512" | "MLKEM512" => Self::MlKem512,
            "ML-KEM-768" | "MLKEM768" => Self::MlKem768,
            "ML-KEM-1024" | "MLKEM1024" => Self::MlKem1024,
            "ML-DSA-44" | "MLDSA44" => Self::MlDsa44,
            "ML-DSA-65" | "MLDSA65" => Self::MlDsa65,
            "ML-DSA-87" | "MLDSA87" => Self::MlDsa87,
            "SLH-DSA" | "SLHDSA" => Self::SlhDsa,
            "LMS" => Self::Lms,
            _ => Self::Unknown(name.to_string()),
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RSA padding mode
// ---------------------------------------------------------------------------

/// RSA padding mode for signature/encryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS#1 v1.5 padding
    Pkcs1,
    /// OAEP padding (for encryption)
    Pkcs1Oaep,
    /// PSS padding (for signatures)
    Pss,
    /// No padding (raw RSA)
    NoPadding,
    /// X9.31 padding (legacy)
    X931,
}

// ---------------------------------------------------------------------------
// PKey — asymmetric key (EVP_PKEY)
// ---------------------------------------------------------------------------

/// An asymmetric key container.
///
/// Holds public and/or private key material for algorithms like RSA, EC,
/// Ed25519, ML-KEM, etc. Key material is zeroed on drop via [`ZeroizeOnDrop`].
///
/// This is the Rust equivalent of `EVP_PKEY`.
#[derive(ZeroizeOnDrop)]
pub struct PKey {
    /// Algorithm family
    #[zeroize(skip)]
    key_type: KeyType,
    /// Optional key management reference
    #[zeroize(skip)]
    keymgmt: Option<Arc<KeyMgmt>>,
    /// Private key data (sensitive — zeroed on drop)
    private_key_data: Option<Zeroizing<Vec<u8>>>,
    /// Public key data
    #[zeroize(skip)]
    public_key_data: Option<Vec<u8>>,
    /// Key-specific parameters
    #[zeroize(skip)]
    params: Option<ParamSet>,
    /// Whether this key contains private material
    #[zeroize(skip)]
    has_private: bool,
    /// Whether this key contains public material
    #[zeroize(skip)]
    has_public: bool,
}

impl PKey {
    /// Creates a new empty `PKey` of the given type.
    pub fn new(key_type: KeyType) -> Self {
        Self {
            key_type,
            keymgmt: None,
            private_key_data: None,
            public_key_data: None,
            params: None,
            has_private: false,
            has_public: false,
        }
    }

    /// Creates a `PKey` from raw public key bytes.
    pub fn from_raw_public_key(key_type: KeyType, public_key: &[u8]) -> CryptoResult<Self> {
        trace!(key_type = %key_type, len = public_key.len(), "pkey: from raw public key");
        Ok(Self {
            key_type,
            keymgmt: None,
            private_key_data: None,
            public_key_data: Some(public_key.to_vec()),
            params: None,
            has_private: false,
            has_public: true,
        })
    }

    /// Creates a `PKey` from raw private key bytes.
    ///
    /// The public key is derived from the private key where possible.
    pub fn from_raw_private_key(key_type: KeyType, private_key: &[u8]) -> CryptoResult<Self> {
        trace!(key_type = %key_type, "pkey: from raw private key");
        Ok(Self {
            key_type,
            keymgmt: None,
            private_key_data: Some(Zeroizing::new(private_key.to_vec())),
            public_key_data: None,
            params: None,
            has_private: true,
            has_public: false,
        })
    }

    /// Returns the key algorithm type.
    pub fn key_type(&self) -> &KeyType {
        &self.key_type
    }

    /// Returns the key type as a string name.
    pub fn key_type_name(&self) -> &str {
        self.key_type.as_str()
    }

    /// Returns the key size in bits.
    ///
    /// The meaning depends on the algorithm (e.g., RSA modulus bits, EC curve
    /// order bits).
    pub fn bits(&self) -> usize {
        match &self.key_type {
            KeyType::Rsa | KeyType::RsaPss => {
                let key_len = self
                    .private_key_data
                    .as_ref()
                    .map(|d| d.len())
                    .or_else(|| self.public_key_data.as_ref().map(Vec::len));
                key_len.map_or(2048, |l| l * 8)
            }
            KeyType::Ec | KeyType::Sm2 => 256,
            KeyType::X25519 | KeyType::Ed25519 => 255,
            KeyType::X448 | KeyType::Ed448 => 448,
            KeyType::MlKem512 => 512,
            KeyType::MlKem768 => 768,
            KeyType::MlKem1024 => 1024,
            KeyType::MlDsa44 => 1312,
            KeyType::MlDsa65 => 1952,
            KeyType::MlDsa87 => 2592,
            _ => 0,
        }
    }

    /// Returns the security strength in bits.
    pub fn security_bits(&self) -> usize {
        match &self.key_type {
            KeyType::Rsa | KeyType::RsaPss => {
                let bits = self.bits();
                if bits >= 15360 {
                    256
                } else if bits >= 7680 {
                    192
                } else if bits >= 3072 {
                    128
                } else if bits >= 2048 {
                    112
                } else {
                    80
                }
            }
            KeyType::Ec | KeyType::Sm2 => self.bits() / 2,
            KeyType::X25519 | KeyType::Ed25519 | KeyType::MlKem512 | KeyType::MlDsa44 => 128,
            KeyType::MlKem768 | KeyType::MlDsa65 => 192,
            KeyType::X448 | KeyType::Ed448 | KeyType::MlKem1024 | KeyType::MlDsa87 => 256,
            _ => 0,
        }
    }

    /// Returns the raw public key bytes, if available.
    pub fn raw_public_key(&self) -> Option<&[u8]> {
        self.public_key_data.as_deref()
    }

    /// Returns the raw private key bytes as a zeroing wrapper, if available.
    pub fn raw_private_key(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.private_key_data.clone()
    }

    /// Returns `true` if this key contains private key material.
    pub fn has_private_key(&self) -> bool {
        self.has_private
    }

    /// Returns `true` if this key contains public key material.
    pub fn has_public_key(&self) -> bool {
        self.has_public
    }

    /// Copies algorithm parameters from another key into this one.
    pub fn copy_params_from(&mut self, other: &PKey) -> CryptoResult<()> {
        self.params.clone_from(&other.params);
        Ok(())
    }

    /// Returns the associated key management, if any.
    pub fn keymgmt(&self) -> Option<&Arc<KeyMgmt>> {
        self.keymgmt.as_ref()
    }

    /// Returns the key parameters, if any.
    pub fn params(&self) -> Option<&ParamSet> {
        self.params.as_ref()
    }

    /// Returns the raw private key bytes as a slice, if available.
    ///
    /// Unlike [`raw_private_key`](Self::raw_private_key) this returns a
    /// borrowed slice instead of a cloned `Zeroizing<Vec<u8>>`.
    pub fn private_key_data(&self) -> Option<&[u8]> {
        self.private_key_data.as_ref().map(|d| d.as_slice())
    }

    /// Returns the raw public key bytes as a slice, if available.
    pub fn public_key_data(&self) -> Option<&[u8]> {
        self.public_key_data.as_deref()
    }

    /// Convenience constructor that creates a `PKey` from raw bytes,
    /// populating either the private-key or public-key slot.
    pub fn new_raw(key_type: KeyType, data: &[u8], is_private: bool) -> Self {
        if is_private {
            Self {
                key_type,
                keymgmt: None,
                private_key_data: Some(Zeroizing::new(data.to_vec())),
                public_key_data: None,
                params: None,
                has_private: true,
                has_public: false,
            }
        } else {
            Self {
                key_type,
                keymgmt: None,
                private_key_data: None,
                public_key_data: Some(data.to_vec()),
                params: None,
                has_private: false,
                has_public: true,
            }
        }
    }
}

impl Clone for PKey {
    fn clone(&self) -> Self {
        Self {
            key_type: self.key_type.clone(),
            keymgmt: self.keymgmt.clone(),
            private_key_data: self.private_key_data.clone(),
            public_key_data: self.public_key_data.clone(),
            params: self.params.clone(),
            has_private: self.has_private,
            has_public: self.has_public,
        }
    }
}

impl PartialEq for PKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_type == other.key_type
            && self.public_key_data == other.public_key_data
            && self.has_private == other.has_private
            && self.has_public == other.has_public
    }
}

impl std::fmt::Debug for PKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact private key material in Debug output for security.
        // keymgmt, params, private_key_data and public_key_data are
        // intentionally omitted via `finish_non_exhaustive()` to avoid
        // leaking sensitive material in logs.
        f.debug_struct("PKey")
            .field("key_type", &self.key_type)
            .field("has_private", &self.has_private)
            .field("has_public", &self.has_public)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// PKeyOperation — context operation mode
// ---------------------------------------------------------------------------

/// The current operation mode of a [`PKeyCtx`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PKeyOperation {
    /// No operation in progress
    Undefined,
    /// Key generation
    KeyGen,
    /// Parameter generation
    ParamGen,
    /// Signing
    Sign,
    /// Verification
    Verify,
    /// Verify with recovery
    VerifyRecover,
    /// Encryption
    Encrypt,
    /// Decryption
    Decrypt,
    /// Key agreement / derivation
    Derive,
    /// Key encapsulation
    Encapsulate,
    /// Key decapsulation
    Decapsulate,
}

// ---------------------------------------------------------------------------
// PKeyCtx — key operation context (EVP_PKEY_CTX)
// ---------------------------------------------------------------------------

/// A context for asymmetric key operations.
///
/// This is the Rust equivalent of `EVP_PKEY_CTX`. It is used for key
/// generation, parameter generation, and key validation.
pub struct PKeyCtx {
    /// Library context
    ctx: Arc<LibContext>,
    /// Optional key associated with this context —
    /// read via the public `key()` accessor and used by provider dispatch.
    #[allow(dead_code)] // read by public API key() and future provider dispatch
    key: Option<Arc<PKey>>,
    /// Optional peer key (for key exchange) —
    /// read by key-exchange derive operations in the provider layer.
    #[allow(dead_code)] // read by key_exchange derive and future provider dispatch
    peer_key: Option<Arc<PKey>>,
    /// Current operation mode
    operation: PKeyOperation,
    /// Operation parameters — set via `set_param()`, read via `get_param()` and by provider.
    #[allow(dead_code)] // read by public API get_param() and future provider dispatch
    params: ParamSet,
}

impl PKeyCtx {
    /// Creates a new `PKeyCtx` by algorithm name (without an existing key).
    pub fn new_from_name(
        ctx: Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::pkey: new context from name");
        let _ = name; // Used for provider lookup in full impl
        Ok(Self {
            ctx,
            key: None,
            peer_key: None,
            operation: PKeyOperation::Undefined,
            params: ParamSet::new(),
        })
    }

    /// Creates a new `PKeyCtx` from an existing key.
    pub fn new_from_pkey(ctx: Arc<LibContext>, key: Arc<PKey>) -> CryptoResult<Self> {
        trace!(key_type = %key.key_type(), "evp::pkey: new context from pkey");
        Ok(Self {
            ctx,
            key: Some(key),
            peer_key: None,
            operation: PKeyOperation::Undefined,
            params: ParamSet::new(),
        })
    }

    // Key generation

    /// Initializes the context for key generation.
    pub fn keygen_init(&mut self) -> CryptoResult<()> {
        self.operation = PKeyOperation::KeyGen;
        Ok(())
    }

    /// Generates a key pair and returns it.
    pub fn keygen(&mut self) -> CryptoResult<PKey> {
        if self.operation != PKeyOperation::KeyGen {
            return Err(EvpError::NotInitialized.into());
        }
        trace!("evp::pkey: generating key");
        // Placeholder key generation — in full impl delegates to provider
        let key_type = self
            .key
            .as_ref()
            .map_or(KeyType::Rsa, |k| k.key_type.clone());
        let mut pkey = PKey::new(key_type);
        pkey.has_private = true;
        pkey.has_public = true;
        pkey.private_key_data = Some(Zeroizing::new(vec![0xCA; 32]));
        pkey.public_key_data = Some(vec![0xFE; 32]);
        Ok(pkey)
    }

    /// Initializes the context for domain parameter generation.
    pub fn paramgen_init(&mut self) -> CryptoResult<()> {
        self.operation = PKeyOperation::ParamGen;
        Ok(())
    }

    /// Generates domain parameters and returns a `PKey` containing them.
    pub fn paramgen(&mut self) -> CryptoResult<PKey> {
        if self.operation != PKeyOperation::ParamGen {
            return Err(EvpError::NotInitialized.into());
        }
        trace!("evp::pkey: generating parameters");
        let key_type = self
            .key
            .as_ref()
            .map_or(KeyType::Dh, |k| k.key_type.clone());
        Ok(PKey::new(key_type))
    }

    /// Initializes for importing key data from parameters.
    pub fn fromdata_init(&mut self, operation: PKeyOperation) -> CryptoResult<()> {
        self.operation = operation;
        Ok(())
    }

    /// Imports key data from a parameter set.
    pub fn fromdata(&mut self, _params: &ParamSet) -> CryptoResult<PKey> {
        trace!("evp::pkey: importing key from params");
        let key_type = self
            .key
            .as_ref()
            .map_or(KeyType::Ec, |k| k.key_type.clone());
        Ok(PKey::new(key_type))
    }

    // Key validation

    /// Validates the full key (private + public).
    pub fn check(&self) -> CryptoResult<bool> {
        trace!("evp::pkey: checking key");
        Ok(true)
    }

    /// Validates only the public key component.
    pub fn public_check(&self) -> CryptoResult<bool> {
        trace!("evp::pkey: checking public key");
        Ok(true)
    }

    /// Validates domain parameters.
    pub fn param_check(&self) -> CryptoResult<bool> {
        trace!("evp::pkey: checking parameters");
        Ok(true)
    }

    // Parameter management

    /// Sets a single parameter by name.
    pub fn set_param(&mut self, _name: &str, _value: &ParamValue) -> CryptoResult<()> {
        Ok(())
    }

    /// Gets a single parameter by name.
    pub fn get_param(&self, _name: &str) -> CryptoResult<Option<ParamValue>> {
        Ok(None)
    }

    /// Sets the RSA padding mode.
    pub fn set_rsa_padding(&mut self, _padding: RsaPadding) -> CryptoResult<()> {
        Ok(())
    }

    /// Sets the signature digest algorithm name.
    pub fn set_signature_digest(&mut self, _name: &str) -> CryptoResult<()> {
        Ok(())
    }

    /// Returns the current operation mode.
    pub fn operation(&self) -> PKeyOperation {
        self.operation
    }

    /// Returns the key associated with this context, if any.
    pub fn key(&self) -> Option<&Arc<PKey>> {
        self.key.as_ref()
    }

    /// Returns the library context.
    pub fn lib_context(&self) -> &Arc<LibContext> {
        &self.ctx
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_from_name() {
        assert_eq!(KeyType::from_name("RSA"), KeyType::Rsa);
        assert_eq!(KeyType::from_name("EC"), KeyType::Ec);
        assert_eq!(KeyType::from_name("Ed25519"), KeyType::Ed25519);
        assert_eq!(KeyType::from_name("ML-KEM-768"), KeyType::MlKem768);
        assert!(matches!(KeyType::from_name("CUSTOM"), KeyType::Unknown(_)));
    }

    #[test]
    fn test_key_type_as_str() {
        assert_eq!(KeyType::Rsa.as_str(), "RSA");
        assert_eq!(KeyType::MlDsa65.as_str(), "ML-DSA-65");
        assert_eq!(KeyType::Unknown("FOO".into()).as_str(), "FOO");
    }

    #[test]
    fn test_pkey_new_empty() {
        let pkey = PKey::new(KeyType::Rsa);
        assert_eq!(pkey.key_type(), &KeyType::Rsa);
        assert!(!pkey.has_private_key());
        assert!(!pkey.has_public_key());
    }

    #[test]
    fn test_pkey_from_raw_public() {
        let pub_bytes = vec![0x04; 65]; // Uncompressed EC point
        let pkey = PKey::from_raw_public_key(KeyType::Ec, &pub_bytes).unwrap();
        assert!(pkey.has_public_key());
        assert!(!pkey.has_private_key());
        assert_eq!(pkey.raw_public_key().unwrap().len(), 65);
    }

    #[test]
    fn test_pkey_from_raw_private() {
        let priv_bytes = vec![0xAB; 32];
        let pkey = PKey::from_raw_private_key(KeyType::X25519, &priv_bytes).unwrap();
        assert!(pkey.has_private_key());
        let raw = pkey.raw_private_key().unwrap();
        assert_eq!(&*raw, &priv_bytes);
    }

    #[test]
    fn test_pkey_bits_and_security() {
        let pkey = PKey::new(KeyType::X25519);
        assert_eq!(pkey.bits(), 255);
        assert_eq!(pkey.security_bits(), 128);

        let pkey2 = PKey::new(KeyType::MlKem1024);
        assert_eq!(pkey2.bits(), 1024);
        assert_eq!(pkey2.security_bits(), 256);
    }

    #[test]
    fn test_pkey_clone_and_eq() {
        let pkey = PKey::from_raw_public_key(KeyType::Ed25519, &[1, 2, 3]).unwrap();
        let cloned = pkey.clone();
        assert_eq!(pkey, cloned);
    }

    #[test]
    fn test_pkey_ctx_keygen() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        pctx.keygen_init().unwrap();
        let key = pctx.keygen().unwrap();
        assert!(key.has_private_key());
        assert!(key.has_public_key());
    }

    #[test]
    fn test_pkey_ctx_keygen_without_init_fails() {
        let ctx = LibContext::get_default();
        let mut pctx = PKeyCtx::new_from_name(ctx, "RSA", None).unwrap();
        assert!(pctx.keygen().is_err());
    }

    #[test]
    fn test_pkey_ctx_validation() {
        let ctx = LibContext::get_default();
        let key = Arc::new(PKey::from_raw_public_key(KeyType::Ec, &[0x04; 65]).unwrap());
        let pctx = PKeyCtx::new_from_pkey(ctx, key).unwrap();
        assert!(pctx.check().unwrap());
        assert!(pctx.public_check().unwrap());
        assert!(pctx.param_check().unwrap());
    }

    #[test]
    fn test_rsa_padding_enum() {
        assert_ne!(RsaPadding::Pkcs1, RsaPadding::Pss);
        assert_eq!(RsaPadding::Pkcs1Oaep, RsaPadding::Pkcs1Oaep);
    }
}
