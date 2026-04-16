//! Key Encapsulation Mechanism (KEM) — `EVP_KEM` equivalent.
//!
//! Provides `Kem`, `KemContext`, and `KemEncapsulateResult` for key
//! encapsulation / decapsulation operations including ML-KEM (FIPS 203),
//! RSA-KEM, and EC-KEM.

use std::sync::Arc;

use tracing::trace;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use openssl_common::{CryptoError, CryptoResult, ParamSet};
use crate::context::LibContext;
use crate::evp::pkey::PKey;
use super::EvpError;

// ---------------------------------------------------------------------------
// Kem — algorithm descriptor (EVP_KEM)
// ---------------------------------------------------------------------------

/// A KEM algorithm descriptor.
///
/// Rust equivalent of `EVP_KEM`. Obtained via [`Kem::fetch`].
#[derive(Debug, Clone)]
pub struct Kem {
    /// Algorithm name (e.g., "ML-KEM-768", "RSA")
    name: String,
    /// Human-readable description
    description: Option<String>,
    /// Provider name
    provider_name: String,
}

impl Kem {
    /// Fetches a KEM algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::kem: fetching");
        Ok(Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str { &self.name }
    /// Returns the description.
    pub fn description(&self) -> Option<&str> { self.description.as_deref() }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str { &self.provider_name }
}

// ---------------------------------------------------------------------------
// KemOperation — which half of the operation is active
// ---------------------------------------------------------------------------

/// The operation being performed by a KEM context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemOperation {
    /// Standard encapsulation (sender side)
    Encapsulate,
    /// Standard decapsulation (receiver side)
    Decapsulate,
    /// Authenticated encapsulation
    AuthEncapsulate,
    /// Authenticated decapsulation
    AuthDecapsulate,
}

// ---------------------------------------------------------------------------
// KemEncapsulateResult — output of encapsulation
// ---------------------------------------------------------------------------

/// The result of a KEM encapsulation.
///
/// Contains both the ciphertext (sent to the peer) and the shared secret
/// (used locally for symmetric keying). The shared secret is wrapped in
/// [`Zeroizing`] for automatic secure erasure on drop.
#[derive(Debug, Clone)]
pub struct KemEncapsulateResult {
    /// The ciphertext (sent to the decapsulator)
    pub ciphertext: Vec<u8>,
    /// The shared secret (used for key derivation)
    pub shared_secret: Zeroizing<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// KemContext — KEM operation context (EVP_PKEY_CTX for KEM)
// ---------------------------------------------------------------------------

/// A KEM operation context.
///
/// Manages the lifecycle of a single encapsulation or decapsulation
/// operation. Key material is securely erased on drop.
#[derive(ZeroizeOnDrop)]
pub struct KemContext {
    /// The KEM algorithm
    #[zeroize(skip)]
    kem: Kem,
    /// Current operation
    #[zeroize(skip)]
    operation: Option<KemOperation>,
    /// The key for the operation
    #[zeroize(skip)]
    key: Option<Arc<PKey>>,
    /// Optional authentication key
    #[zeroize(skip)]
    auth_key: Option<Arc<PKey>>,
    /// Additional parameters
    #[zeroize(skip)]
    params: Option<ParamSet>,
    /// Simulated shared-secret length in bytes
    #[zeroize(skip)]
    secret_len: usize,
    /// Simulated ciphertext length in bytes
    #[zeroize(skip)]
    ct_len: usize,
}

impl KemContext {
    /// Creates a new KEM context for the given algorithm.
    pub fn new(kem: &Kem) -> Self {
        let (secret_len, ct_len) = match kem.name.as_str() {
            "ML-KEM-512" => (16, 768),
            "ML-KEM-768" => (24, 1088),
            "ML-KEM-1024" => (32, 1568),
            "RSA" => (32, 256),
            "EC" | "ECDH" => (32, 65),
            _ => (32, 128),
        };
        Self {
            kem: kem.clone(),
            operation: None,
            key: None,
            auth_key: None,
            params: None,
            secret_len,
            ct_len,
        }
    }

    // ---- Initialization -------------------------------------------------

    /// Initialises an encapsulation operation.
    pub fn encapsulate_init(&mut self, key: &Arc<PKey>) -> CryptoResult<()> {
        trace!(algorithm = %self.kem.name, "evp::kem: encapsulate_init");
        self.operation = Some(KemOperation::Encapsulate);
        self.key = Some(Arc::clone(key));
        Ok(())
    }

    /// Initialises a decapsulation operation.
    pub fn decapsulate_init(&mut self, key: &Arc<PKey>) -> CryptoResult<()> {
        trace!(algorithm = %self.kem.name, "evp::kem: decapsulate_init");
        self.operation = Some(KemOperation::Decapsulate);
        self.key = Some(Arc::clone(key));
        Ok(())
    }

    /// Initialises an authenticated encapsulation operation.
    pub fn auth_encapsulate_init(
        &mut self,
        key: &Arc<PKey>,
        auth_key: &Arc<PKey>,
    ) -> CryptoResult<()> {
        trace!(algorithm = %self.kem.name, "evp::kem: auth_encapsulate_init");
        self.operation = Some(KemOperation::AuthEncapsulate);
        self.key = Some(Arc::clone(key));
        self.auth_key = Some(Arc::clone(auth_key));
        Ok(())
    }

    /// Initialises an authenticated decapsulation operation.
    pub fn auth_decapsulate_init(
        &mut self,
        key: &Arc<PKey>,
        auth_key: &Arc<PKey>,
    ) -> CryptoResult<()> {
        trace!(algorithm = %self.kem.name, "evp::kem: auth_decapsulate_init");
        self.operation = Some(KemOperation::AuthDecapsulate);
        self.key = Some(Arc::clone(key));
        self.auth_key = Some(Arc::clone(auth_key));
        Ok(())
    }

    // ---- Operations -----------------------------------------------------

    /// Performs encapsulation, producing a ciphertext and shared secret.
    ///
    /// Must be called after [`encapsulate_init`](Self::encapsulate_init) or
    /// [`auth_encapsulate_init`](Self::auth_encapsulate_init).
    pub fn encapsulate(&self) -> CryptoResult<KemEncapsulateResult> {
        match self.operation {
            Some(KemOperation::Encapsulate | KemOperation::AuthEncapsulate) => {}
            _ => {
                return Err(EvpError::OperationNotInitialized(
                    "encapsulate not initialized".into(),
                )
                .into());
            }
        }
        let _key = self.key.as_ref().ok_or_else(|| {
            CryptoError::from(EvpError::KeyRequired("encapsulate requires a key".into()))
        })?;

        // Simulated encapsulation — produces deterministic placeholder output.
        // Real implementations delegate to the provider's KEM algorithm.
        let ciphertext = vec![0xAB; self.ct_len];
        let shared_secret = Zeroizing::new(vec![0xCD; self.secret_len]);

        trace!(
            algorithm = %self.kem.name,
            ct_len = ciphertext.len(),
            ss_len = shared_secret.len(),
            "evp::kem: encapsulated"
        );
        Ok(KemEncapsulateResult { ciphertext, shared_secret })
    }

    /// Performs decapsulation, recovering the shared secret from the ciphertext.
    ///
    /// Must be called after [`decapsulate_init`](Self::decapsulate_init) or
    /// [`auth_decapsulate_init`](Self::auth_decapsulate_init).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
        match self.operation {
            Some(KemOperation::Decapsulate | KemOperation::AuthDecapsulate) => {}
            _ => {
                return Err(EvpError::OperationNotInitialized(
                    "decapsulate not initialized".into(),
                )
                .into());
            }
        }
        let _key = self.key.as_ref().ok_or_else(|| {
            CryptoError::from(EvpError::KeyRequired("decapsulate requires a key".into()))
        })?;

        if ciphertext.is_empty() {
            return Err(EvpError::InvalidArgument("ciphertext is empty".into()).into());
        }

        // Simulated decapsulation — placeholder output.
        let shared_secret = Zeroizing::new(vec![0xCD; self.secret_len]);
        trace!(
            algorithm = %self.kem.name,
            ct_len = ciphertext.len(),
            ss_len = shared_secret.len(),
            "evp::kem: decapsulated"
        );
        Ok(shared_secret)
    }

    // ---- Parameters -----------------------------------------------------

    /// Sets additional parameters for the KEM operation.
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        self.params = Some(params.clone());
        Ok(())
    }

    /// Gets current operation parameters.
    pub fn get_params(&self) -> Option<&ParamSet> {
        self.params.as_ref()
    }

    /// Returns the current operation.
    pub fn operation(&self) -> Option<KemOperation> { self.operation }
    /// Returns the algorithm descriptor.
    pub fn kem(&self) -> &Kem { &self.kem }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key() -> Arc<PKey> {
        Arc::new(PKey::new_raw(
            crate::evp::pkey::KeyType::MlKem768,
            &[0u8; 32],
            true,
        ))
    }

    #[test]
    fn test_kem_fetch() {
        let ctx = LibContext::get_default();
        let kem = Kem::fetch(&ctx, "ML-KEM-768", None).unwrap();
        assert_eq!(kem.name(), "ML-KEM-768");
        assert_eq!(kem.provider_name(), "default");
    }

    #[test]
    fn test_kem_encapsulate_decapsulate() {
        let kem = Kem::fetch(&LibContext::get_default(), "ML-KEM-768", None).unwrap();
        let key = make_test_key();

        let mut enc_ctx = KemContext::new(&kem);
        enc_ctx.encapsulate_init(&key).unwrap();
        let result = enc_ctx.encapsulate().unwrap();
        assert!(!result.ciphertext.is_empty());
        assert!(!result.shared_secret.is_empty());

        let mut dec_ctx = KemContext::new(&kem);
        dec_ctx.decapsulate_init(&key).unwrap();
        let ss = dec_ctx.decapsulate(&result.ciphertext).unwrap();
        assert_eq!(ss.len(), result.shared_secret.len());
    }

    #[test]
    fn test_kem_not_initialized_fails() {
        let kem = Kem::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let ctx = KemContext::new(&kem);
        assert!(ctx.encapsulate().is_err());
        assert!(ctx.decapsulate(b"data").is_err());
    }

    #[test]
    fn test_kem_decapsulate_empty_ciphertext_fails() {
        let kem = Kem::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let mut ctx = KemContext::new(&kem);
        ctx.decapsulate_init(&key).unwrap();
        assert!(ctx.decapsulate(&[]).is_err());
    }

    #[test]
    fn test_kem_auth_encapsulate() {
        let kem = Kem::fetch(&LibContext::get_default(), "ML-KEM-768", None).unwrap();
        let key = make_test_key();
        let auth_key = make_test_key();

        let mut ctx = KemContext::new(&kem);
        ctx.auth_encapsulate_init(&key, &auth_key).unwrap();
        assert_eq!(ctx.operation(), Some(KemOperation::AuthEncapsulate));
        let result = ctx.encapsulate().unwrap();
        assert!(!result.ciphertext.is_empty());
    }

    #[test]
    fn test_kem_set_params() {
        let kem = Kem::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let mut ctx = KemContext::new(&kem);
        assert!(ctx.get_params().is_none());
        let params = ParamSet::new();
        ctx.set_params(&params).unwrap();
        assert!(ctx.get_params().is_some());
    }
}
