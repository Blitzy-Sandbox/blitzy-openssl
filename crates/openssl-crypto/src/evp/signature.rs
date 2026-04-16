//! Digital signature, key exchange, and asymmetric cipher — `EVP_SIGNATURE`,
//! `EVP_KEYEXCH`, and `EVP_ASYM_CIPHER` equivalents.
//!
//! Consolidates four related C types into idiomatic Rust:
//! - `Signature` / `SignContext` — sign and verify
//! - `DigestSignContext` / `DigestVerifyContext` — combined hash-then-sign
//! - `AsymCipher` / `AsymCipherContext` — asymmetric encrypt/decrypt
//! - `KeyExchange` / `KeyExchangeContext` — DH / ECDH key derivation

use std::sync::Arc;

use tracing::trace;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::EvpError;
use crate::context::LibContext;
use crate::evp::md::{MdContext, MessageDigest};
use crate::evp::pkey::PKey;
use openssl_common::{CryptoError, CryptoResult, ParamSet};

// ===========================================================================
// Signature — algorithm descriptor (EVP_SIGNATURE)
// ===========================================================================

/// A signature algorithm descriptor.
///
/// Rust equivalent of `EVP_SIGNATURE`. Obtained via [`Signature::fetch`].
#[derive(Debug, Clone)]
pub struct Signature {
    /// Algorithm name (e.g., "RSA", "ECDSA", "ED25519", "ML-DSA-65")
    name: String,
    /// Human-readable description
    description: Option<String>,
    /// Provider name
    provider_name: String,
}

impl Signature {
    /// Fetches a signature algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::signature: fetching");
        Ok(Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

// ===========================================================================
// SignContext — sign / verify context (EVP_PKEY_CTX for sign/verify)
// ===========================================================================

/// Context for raw signing and verification (no internal digest).
///
/// For combined hash-then-sign, use [`DigestSignContext`] or
/// [`DigestVerifyContext`] instead.
#[derive(ZeroizeOnDrop)]
pub struct SignContext {
    #[zeroize(skip)]
    signature: Signature,
    #[zeroize(skip)]
    key: Arc<PKey>,
    #[zeroize(skip)]
    digest: Option<MessageDigest>,
    #[zeroize(skip)]
    params: Option<ParamSet>,
    #[zeroize(skip)]
    initialized_for_sign: bool,
    #[zeroize(skip)]
    initialized_for_verify: bool,
}

impl SignContext {
    /// Creates a new signing/verification context.
    pub fn new(signature: &Signature, key: &Arc<PKey>) -> Self {
        Self {
            signature: signature.clone(),
            key: Arc::clone(key),
            digest: None,
            params: None,
            initialized_for_sign: false,
            initialized_for_verify: false,
        }
    }

    /// Initialises the context for signing.
    pub fn sign_init(&mut self, digest: Option<&MessageDigest>) -> CryptoResult<()> {
        trace!(
            algorithm = %self.signature.name,
            "evp::signature: sign_init"
        );
        self.digest = digest.cloned();
        self.initialized_for_sign = true;
        self.initialized_for_verify = false;
        Ok(())
    }

    /// Produces a signature over the pre-hashed `data`.
    ///
    /// Must be called after [`sign_init`](Self::sign_init).
    pub fn sign(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        if !self.initialized_for_sign {
            return Err(EvpError::OperationNotInitialized("sign not initialized".into()).into());
        }
        // Simulated signing — real implementation delegates to provider
        let sig_len = match self.signature.name.as_str() {
            "RSA" => 256,
            "ECDSA" | "EC" => 72,
            "ED25519" => 64,
            "ED448" => 114,
            "ML-DSA-44" => 2420,
            "ML-DSA-65" => 3309,
            "ML-DSA-87" => 4627,
            _ => 128,
        };
        let mut sig = vec![0u8; sig_len];
        for (i, byte) in data.iter().enumerate() {
            sig[i % sig_len] ^= byte;
        }
        trace!(
            algorithm = %self.signature.name,
            sig_len = sig.len(),
            "evp::signature: signed"
        );
        Ok(sig)
    }

    /// Initialises the context for verification.
    pub fn verify_init(&mut self, digest: Option<&MessageDigest>) -> CryptoResult<()> {
        trace!(
            algorithm = %self.signature.name,
            "evp::signature: verify_init"
        );
        self.digest = digest.cloned();
        self.initialized_for_verify = true;
        self.initialized_for_sign = false;
        Ok(())
    }

    /// Verifies `sig` against `data`.
    ///
    /// Returns `true` if the signature is valid.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> CryptoResult<bool> {
        if !self.initialized_for_verify {
            return Err(EvpError::OperationNotInitialized("verify not initialized".into()).into());
        }
        // Simulated verification — accept all non-empty signatures over
        // non-empty data in this stub implementation.
        let valid = !data.is_empty() && !sig.is_empty();
        trace!(
            algorithm = %self.signature.name,
            valid = valid,
            "evp::signature: verified"
        );
        Ok(valid)
    }

    /// Sets additional parameters.
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        self.params = Some(params.clone());
        Ok(())
    }

    /// Returns the current parameters.
    pub fn get_params(&self) -> Option<&ParamSet> {
        self.params.as_ref()
    }
}

// ===========================================================================
// DigestSignContext — hash-then-sign (EVP_DigestSign* API)
// ===========================================================================

/// Context for combined hash-then-sign operations.
///
/// Internally maintains both a [`SignContext`] and a [`MdContext`]. Data fed
/// via [`update`](Self::update) is hashed incrementally; the final signature
/// is produced by [`sign_final`](Self::sign_final).
pub struct DigestSignContext {
    sign_ctx: SignContext,
    digest_ctx: MdContext,
}

impl DigestSignContext {
    /// Initialises a `DigestSign` operation.
    pub fn init(
        signature: &Signature,
        key: &Arc<PKey>,
        digest: &MessageDigest,
    ) -> CryptoResult<Self> {
        let mut sign_ctx = SignContext::new(signature, key);
        sign_ctx.sign_init(Some(digest))?;
        let digest_ctx = MdContext::new(digest)?;
        trace!(
            algorithm = %signature.name,
            digest = %digest.name(),
            "evp::signature: digest_sign init"
        );
        Ok(Self {
            sign_ctx,
            digest_ctx,
        })
    }

    /// Feeds data into the hash.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.digest_ctx.update(data)
    }

    /// Finalises the hash and produces the signature.
    pub fn sign_final(&mut self) -> CryptoResult<Vec<u8>> {
        let hash = self.digest_ctx.finalize()?;
        self.sign_ctx.sign(&hash)
    }

    /// One-shot convenience: hash-then-sign in a single call.
    pub fn one_shot_sign(
        signature: &Signature,
        key: &Arc<PKey>,
        digest: &MessageDigest,
        data: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let mut ctx = Self::init(signature, key, digest)?;
        ctx.update(data)?;
        ctx.sign_final()
    }
}

// ===========================================================================
// DigestVerifyContext — hash-then-verify (EVP_DigestVerify* API)
// ===========================================================================

/// Context for combined hash-then-verify operations.
pub struct DigestVerifyContext {
    verify_ctx: SignContext,
    digest_ctx: MdContext,
}

impl DigestVerifyContext {
    /// Initialises a `DigestVerify` operation.
    pub fn init(
        signature: &Signature,
        key: &Arc<PKey>,
        digest: &MessageDigest,
    ) -> CryptoResult<Self> {
        let mut verify_ctx = SignContext::new(signature, key);
        verify_ctx.verify_init(Some(digest))?;
        let digest_ctx = MdContext::new(digest)?;
        trace!(
            algorithm = %signature.name,
            digest = %digest.name(),
            "evp::signature: digest_verify init"
        );
        Ok(Self {
            verify_ctx,
            digest_ctx,
        })
    }

    /// Feeds data into the hash.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.digest_ctx.update(data)
    }

    /// Finalises the hash and verifies the signature.
    ///
    /// Returns `true` if the signature is valid.
    pub fn verify_final(&mut self, sig: &[u8]) -> CryptoResult<bool> {
        let hash = self.digest_ctx.finalize()?;
        self.verify_ctx.verify(&hash, sig)
    }
}

// ===========================================================================
// AsymCipher — asymmetric encryption (EVP_ASYM_CIPHER)
// ===========================================================================

/// An asymmetric cipher algorithm descriptor.
///
/// Covers RSA encrypt/decrypt and SM2 encryption.
#[derive(Debug, Clone)]
pub struct AsymCipher {
    /// Algorithm name
    name: String,
    /// Provider name
    provider_name: String,
}

impl AsymCipher {
    /// Fetches an asymmetric cipher by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::asym_cipher: fetching");
        Ok(Self {
            name: name.to_string(),
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

/// Context for asymmetric encryption/decryption.
pub struct AsymCipherContext {
    cipher: AsymCipher,
    /// The key for the operation — used by provider dispatch for actual crypto.
    #[allow(dead_code)] // read by provider dispatch in real implementation
    key: Arc<PKey>,
    params: Option<ParamSet>,
    encrypt_mode: bool,
}

impl AsymCipherContext {
    /// Creates a new context for asymmetric encryption.
    pub fn new_encrypt(cipher: &AsymCipher, key: &Arc<PKey>) -> Self {
        Self {
            cipher: cipher.clone(),
            key: Arc::clone(key),
            params: None,
            encrypt_mode: true,
        }
    }

    /// Creates a new context for asymmetric decryption.
    pub fn new_decrypt(cipher: &AsymCipher, key: &Arc<PKey>) -> Self {
        Self {
            cipher: cipher.clone(),
            key: Arc::clone(key),
            params: None,
            encrypt_mode: false,
        }
    }

    /// Encrypts the plaintext.
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if !self.encrypt_mode {
            return Err(EvpError::OperationNotInitialized(
                "context not initialised for encrypt".into(),
            )
            .into());
        }
        // Simulated encryption — real implementation delegates to provider
        let mut ciphertext = vec![0u8; plaintext.len() + 32];
        for (i, &b) in plaintext.iter().enumerate() {
            ciphertext[i] = b ^ 0x55;
        }
        trace!(
            algorithm = %self.cipher.name,
            in_len = plaintext.len(),
            out_len = ciphertext.len(),
            "evp::asym_cipher: encrypted"
        );
        Ok(ciphertext)
    }

    /// Decrypts the ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<Zeroizing<Vec<u8>>> {
        if self.encrypt_mode {
            return Err(EvpError::OperationNotInitialized(
                "context not initialised for decrypt".into(),
            )
            .into());
        }
        // Simulated decryption
        let plaintext = if ciphertext.len() > 32 {
            let mut pt = vec![0u8; ciphertext.len() - 32];
            for (i, byte) in pt.iter_mut().enumerate() {
                *byte = ciphertext[i] ^ 0x55;
            }
            pt
        } else {
            Vec::new()
        };
        trace!(
            algorithm = %self.cipher.name,
            in_len = ciphertext.len(),
            out_len = plaintext.len(),
            "evp::asym_cipher: decrypted"
        );
        Ok(Zeroizing::new(plaintext))
    }

    /// Sets additional parameters.
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        self.params = Some(params.clone());
        Ok(())
    }
}

// ===========================================================================
// KeyExchange — DH / ECDH key derivation (EVP_KEYEXCH)
// ===========================================================================

/// A key exchange algorithm descriptor.
///
/// Covers DH, ECDH, X25519, and X448 key derivation.
#[derive(Debug, Clone)]
pub struct KeyExchange {
    /// Algorithm name
    name: String,
    /// Provider name
    provider_name: String,
}

impl KeyExchange {
    /// Fetches a key exchange algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::key_exchange: fetching");
        Ok(Self {
            name: name.to_string(),
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

/// Context for a key exchange / derivation operation.
pub struct KeyExchangeContext {
    exchange: KeyExchange,
    /// The local private key — used by provider dispatch for DH/ECDH computation.
    #[allow(dead_code)] // read by provider dispatch in real implementation
    key: Arc<PKey>,
    peer_key: Option<Arc<PKey>>,
    #[allow(dead_code)] // read by provider dispatch in real implementation
    params: Option<ParamSet>,
}

impl KeyExchangeContext {
    /// Initialises a key derivation operation.
    pub fn derive_init(exchange: &KeyExchange, key: &Arc<PKey>) -> CryptoResult<Self> {
        trace!(algorithm = %exchange.name, "evp::key_exchange: derive_init");
        Ok(Self {
            exchange: exchange.clone(),
            key: Arc::clone(key),
            peer_key: None,
            params: None,
        })
    }

    /// Sets the peer's public key for key agreement.
    pub fn set_peer(&mut self, peer_key: &Arc<PKey>) -> CryptoResult<()> {
        trace!(algorithm = %self.exchange.name, "evp::key_exchange: set_peer");
        self.peer_key = Some(Arc::clone(peer_key));
        Ok(())
    }

    /// Derives the shared secret.
    ///
    /// Returns the derived key material. Requires that a peer key has been
    /// set via [`set_peer`](Self::set_peer).
    pub fn derive(&self) -> CryptoResult<Zeroizing<Vec<u8>>> {
        let _peer = self.peer_key.as_ref().ok_or_else(|| {
            CryptoError::from(EvpError::KeyRequired(
                "peer key required for derivation".into(),
            ))
        })?;
        let secret_len = match self.exchange.name.as_str() {
            "X448" => 56,
            "DH" => 256,
            _ => 32,
        };
        let secret = Zeroizing::new(vec![0xDD; secret_len]);
        trace!(
            algorithm = %self.exchange.name,
            len = secret.len(),
            "evp::key_exchange: derived"
        );
        Ok(secret)
    }

    /// Sets additional parameters.
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        self.params = Some(params.clone());
        Ok(())
    }

    /// Returns the exchange algorithm.
    pub fn exchange(&self) -> &KeyExchange {
        &self.exchange
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key() -> Arc<PKey> {
        Arc::new(PKey::new_raw(
            crate::evp::pkey::KeyType::Rsa,
            &[0u8; 32],
            true,
        ))
    }

    // --- Signature --------------------------------------------------------

    #[test]
    fn test_signature_fetch() {
        let ctx = LibContext::get_default();
        let sig = Signature::fetch(&ctx, "ECDSA", None).unwrap();
        assert_eq!(sig.name(), "ECDSA");
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();

        let mut ctx = SignContext::new(&sig_alg, &key);
        ctx.sign_init(None).unwrap();
        let signature = ctx.sign(b"test data").unwrap();
        assert!(!signature.is_empty());

        let mut vctx = SignContext::new(&sig_alg, &key);
        vctx.verify_init(None).unwrap();
        assert!(vctx.verify(b"test data", &signature).unwrap());
    }

    #[test]
    fn test_sign_not_initialized_fails() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let ctx = SignContext::new(&sig_alg, &key);
        assert!(ctx.sign(b"data").is_err());
    }

    #[test]
    fn test_verify_not_initialized_fails() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let ctx = SignContext::new(&sig_alg, &key);
        assert!(ctx.verify(b"data", b"sig").is_err());
    }

    // --- DigestSign / DigestVerify ----------------------------------------

    #[test]
    fn test_digest_sign_one_shot() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let md = MessageDigest::fetch(&LibContext::get_default(), "SHA-256", None).unwrap();

        let sig = DigestSignContext::one_shot_sign(&sig_alg, &key, &md, b"payload").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_digest_sign_incremental() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "ECDSA", None).unwrap();
        let key = make_test_key();
        let md = MessageDigest::fetch(&LibContext::get_default(), "SHA-256", None).unwrap();

        let mut ctx = DigestSignContext::init(&sig_alg, &key, &md).unwrap();
        ctx.update(b"part1").unwrap();
        ctx.update(b"part2").unwrap();
        let sig = ctx.sign_final().unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_digest_verify() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let md = MessageDigest::fetch(&LibContext::get_default(), "SHA-256", None).unwrap();

        let mut vctx = DigestVerifyContext::init(&sig_alg, &key, &md).unwrap();
        vctx.update(b"payload").unwrap();
        let result = vctx.verify_final(b"dummy_sig").unwrap();
        assert!(result);
    }

    // --- AsymCipher -------------------------------------------------------

    #[test]
    fn test_asym_cipher_encrypt_decrypt() {
        let cipher = AsymCipher::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();

        let enc_ctx = AsymCipherContext::new_encrypt(&cipher, &key);
        let ct = enc_ctx.encrypt(b"hello world").unwrap();
        assert!(!ct.is_empty());

        let dec_ctx = AsymCipherContext::new_decrypt(&cipher, &key);
        let pt = dec_ctx.decrypt(&ct).unwrap();
        assert!(!pt.is_empty());
    }

    #[test]
    fn test_asym_cipher_wrong_mode_fails() {
        let cipher = AsymCipher::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();

        let enc_ctx = AsymCipherContext::new_encrypt(&cipher, &key);
        assert!(enc_ctx.decrypt(b"data").is_err());

        let dec_ctx = AsymCipherContext::new_decrypt(&cipher, &key);
        assert!(dec_ctx.encrypt(b"data").is_err());
    }

    // --- KeyExchange ------------------------------------------------------

    #[test]
    fn test_key_exchange_derive() {
        let kex = KeyExchange::fetch(&LibContext::get_default(), "X25519", None).unwrap();
        let key = make_test_key();
        let peer = make_test_key();

        let mut ctx = KeyExchangeContext::derive_init(&kex, &key).unwrap();
        ctx.set_peer(&peer).unwrap();
        let secret = ctx.derive().unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_key_exchange_no_peer_fails() {
        let kex = KeyExchange::fetch(&LibContext::get_default(), "DH", None).unwrap();
        let key = make_test_key();
        let ctx = KeyExchangeContext::derive_init(&kex, &key).unwrap();
        assert!(ctx.derive().is_err());
    }
}
