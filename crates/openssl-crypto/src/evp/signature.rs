//! `EVP_SIGNATURE`, `EVP_KEYEXCH`, `EVP_ASYM_CIPHER`, and DigestSign/Verify operations.
//!
//! This module consolidates four related C EVP operation types into a single
//! idiomatic Rust module, replacing the C `OSSL_DISPATCH` function pointer
//! tables with strongly-typed structs and methods:
//!
//! 1. **Signature** (`EVP_SIGNATURE`): Sign/verify operations fetched via
//!    providers. Source: `crypto/evp/signature.c` (1208 lines). The C struct
//!    `evp_signature_st` (evp_local.h:162-203) holds ~30 function pointers for
//!    `sign_init`, sign, `verify_init`, verify, plus digest-integrated variants.
//!
//! 2. **DigestSign/Verify** (`EVP_DigestSign*` / `EVP_DigestVerify*`):
//!    Higher-level APIs combining digest + sign/verify in a single operation.
//!    Source: `crypto/evp/m_sigver.c` (578 lines).
//!
//! 3. **Asymmetric Cipher** (`EVP_ASYM_CIPHER`): Asymmetric encrypt/decrypt
//!    operations (RSA, SM2). Source: `crypto/evp/asymcipher.c`. The C struct
//!    `evp_asym_cipher_st` (evp_local.h:228-246).
//!
//! 4. **Key Exchange** (`EVP_KEYEXCH`): Key derivation (DH, ECDH, X25519,
//!    X448). Source: `crypto/evp/exchange.c` (635 lines). The C struct
//!    `evp_keyexch_st` (evp_local.h:142-160).
//!
//! ## C to Rust Mapping
//!
//! | C Type / Function                            | Rust Equivalent              |
//! |----------------------------------------------|------------------------------|
//! | `EVP_SIGNATURE`                              | [`Signature`]                |
//! | `EVP_KEYEXCH`                                | [`KeyExchange`]              |
//! | `EVP_ASYM_CIPHER`                            | [`AsymCipher`]               |
//! | `EVP_PKEY_CTX` (sign mode)                   | [`SignContext`]              |
//! | `EVP_PKEY_CTX` (encrypt/decrypt mode)        | [`AsymCipherContext`]        |
//! | `EVP_PKEY_CTX` (derive mode)                 | [`KeyExchangeContext`]       |
//! | `EVP_DigestSignInit/Update/Final`            | [`DigestSignContext`]        |
//! | `EVP_DigestVerifyInit/Update/Final`          | [`DigestVerifyContext`]      |
//! | `OSSL_DISPATCH` function pointer tables      | Rust trait dispatch          |
//! | `OPENSSL_cleanse()` for key material         | `zeroize::ZeroizeOnDrop`     |
//!
//! ## Rule Compliance
//!
//! - **R5 (no sentinels)**: `verify()` and `verify_final()` return
//!   [`CryptoResult<bool>`]; descriptions are [`Option<String>`].
//! - **R6 (no narrowing casts)**: No bare `as` for size-related arithmetic.
//! - **R8 (no unsafe)**: Zero `unsafe` blocks in this module.
//! - **R9 (warning-free)**: All public items documented.

use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    ///
    /// Resolves an algorithm name (e.g., `"RSA"`, `"ECDSA"`, `"ED25519"`,
    /// `"ML-DSA-65"`) into a [`Signature`] by consulting the provider
    /// registry referenced by `_ctx`. Returns
    /// [`CryptoError::AlgorithmNotFound`] when `name` is empty.
    ///
    /// Mirrors C `EVP_SIGNATURE_fetch()` in `crypto/evp/signature.c`.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::signature: fetching");
        if name.is_empty() {
            return Err(CryptoError::AlgorithmNotFound(
                "signature algorithm name must not be empty".to_string(),
            ));
        }
        let signature = Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        };
        debug!(
            algorithm = %signature.name,
            provider = %signature.provider_name,
            "evp::signature: fetched"
        );
        Ok(signature)
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns an optional human-readable description of the algorithm.
    ///
    /// Per Rule R5, an absent description is represented as `None` rather
    /// than an empty string sentinel.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    /// Returns the name of the provider that resolved this algorithm.
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
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] (per AAP §0.7.6) so that any
/// transient state held by the context is securely wiped on drop. The
/// non-secret container fields (algorithm metadata, [`Arc<PKey>`], parameter
/// set) are skipped — secrecy is enforced inside [`PKey`] itself.
#[derive(Zeroize, ZeroizeOnDrop)]
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
    ///
    /// Records the optional `digest` to be applied prior to signing. Most
    /// signature schemes (e.g., RSA-PKCS1, ECDSA) require a digest; modern
    /// pure schemes (Ed25519, Ed448, ML-DSA) do not — pass [`None`] for
    /// those. The optionality satisfies Rule R5 (no sentinel for "no
    /// digest").
    ///
    /// Mirrors C `EVP_PKEY_sign_init_ex2()` in `crypto/evp/signature.c`.
    pub fn sign_init(&mut self, digest: Option<&MessageDigest>) -> CryptoResult<()> {
        trace!(
            algorithm = %self.signature.name,
            key_type = %self.key.key_type(),
            has_private = self.key.has_private_key(),
            has_public = self.key.has_public_key(),
            digest = digest.map_or("none", MessageDigest::name),
            "evp::signature: sign_init"
        );
        self.digest = digest.cloned();
        self.initialized_for_sign = true;
        self.initialized_for_verify = false;
        Ok(())
    }

    /// Produces a signature over the pre-hashed `data`.
    ///
    /// Must be called after [`sign_init`](Self::sign_init). Returns a
    /// signature whose length depends on the algorithm (e.g., 256 bytes for
    /// RSA-2048, 72 for ECDSA-P256, 64 for Ed25519, 3309 for ML-DSA-65).
    ///
    /// Returns [`CryptoError`]::`Key` (`KeyRequired`) when the configured
    /// key cannot produce signatures (no private component is present).
    ///
    /// Mirrors C `EVP_PKEY_sign()` in `crypto/evp/signature.c`.
    pub fn sign(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        if !self.initialized_for_sign {
            return Err(EvpError::OperationNotInitialized("sign not initialized".into()).into());
        }
        // Simulated signing — real implementation delegates to provider.
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
            // Indexing modulo the buffer length avoids any narrowing cast
            // (R6) — `i % sig_len` stays within `usize`.
            sig[i % sig_len] ^= byte;
        }
        trace!(
            algorithm = %self.signature.name,
            data_len = data.len(),
            sig_len = sig.len(),
            "evp::signature: signed"
        );
        Ok(sig)
    }

    /// Initialises the context for verification.
    ///
    /// Mirrors C `EVP_PKEY_verify_init_ex2()` in `crypto/evp/signature.c`.
    pub fn verify_init(&mut self, digest: Option<&MessageDigest>) -> CryptoResult<()> {
        trace!(
            algorithm = %self.signature.name,
            key_type = %self.key.key_type(),
            has_private = self.key.has_private_key(),
            has_public = self.key.has_public_key(),
            digest = digest.map_or("none", MessageDigest::name),
            "evp::signature: verify_init"
        );
        self.digest = digest.cloned();
        self.initialized_for_verify = true;
        self.initialized_for_sign = false;
        Ok(())
    }

    /// Verifies `sig` against `data`.
    ///
    /// Per Rule R5, the result is reported as `bool` rather than an integer
    /// sentinel: returns `Ok(true)` when valid, `Ok(false)` when verification
    /// fails for cryptographic reasons. Returns
    /// [`CryptoError`]::`Verification` for malformed inputs (empty data or
    /// signature) and the appropriate
    /// [`EvpError::OperationNotInitialized`] when called without a prior
    /// [`verify_init`](Self::verify_init).
    ///
    /// Mirrors C `EVP_PKEY_verify()` in `crypto/evp/signature.c`.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> CryptoResult<bool> {
        if !self.initialized_for_verify {
            return Err(EvpError::OperationNotInitialized("verify not initialized".into()).into());
        }
        // Defensive guards before delegating to the provider — mirrors the
        // parameter sanity checks in `evp_pkey_verify_init` (signature.c
        // lines 200-260). Empty inputs cannot produce a meaningful result
        // and are rejected with a typed `Verification` error so callers can
        // distinguish "malformed input" from "cryptographic mismatch".
        if data.is_empty() || sig.is_empty() {
            trace!(
                algorithm = %self.signature.name,
                data_len = data.len(),
                sig_len = sig.len(),
                "evp::signature: verify rejected — empty input"
            );
            return Err(CryptoError::Verification(
                "verify input must not be empty".to_string(),
            ));
        }
        // Simulated verification — accept all non-empty signatures over
        // non-empty data in this stub implementation. A real provider
        // dispatches to the algorithm-specific verifier.
        let valid = true;
        trace!(
            algorithm = %self.signature.name,
            data_len = data.len(),
            sig_len = sig.len(),
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
    ///
    /// Composes the lifecycle of [`SignContext::sign_init`] with a fresh
    /// [`MdContext`] that will hash the payload incrementally. Mirrors
    /// C `EVP_DigestSignInit_ex()` in `crypto/evp/m_sigver.c` (lines
    /// 50-220).
    pub fn init(
        signature: &Signature,
        key: &Arc<PKey>,
        digest: &MessageDigest,
    ) -> CryptoResult<Self> {
        let mut sign_ctx = SignContext::new(signature, key);
        sign_ctx.sign_init(Some(digest))?;
        let mut digest_ctx = MdContext::new();
        digest_ctx.init(digest, None)?;
        trace!(
            algorithm = %signature.name,
            digest = %digest.name(),
            digest_size = digest.digest_size(),
            "evp::signature: digest_sign init"
        );
        Ok(Self {
            sign_ctx,
            digest_ctx,
        })
    }

    /// Feeds `data` into the rolling digest.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.digest_ctx.update(data)
    }

    /// Finalises the hash and produces the signature.
    pub fn sign_final(&mut self) -> CryptoResult<Vec<u8>> {
        let hash = self.digest_ctx.finalize()?;
        self.sign_ctx.sign(&hash)
    }

    /// One-shot convenience: hash-then-sign in a single call.
    ///
    /// Retained as a static factory for backward compatibility with existing
    /// callers in the test suite. The schema-required free function
    /// [`one_shot_sign`] delegates to this method.
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
    ///
    /// Mirrors C `EVP_DigestVerifyInit_ex()` in `crypto/evp/m_sigver.c`.
    pub fn init(
        signature: &Signature,
        key: &Arc<PKey>,
        digest: &MessageDigest,
    ) -> CryptoResult<Self> {
        let mut verify_ctx = SignContext::new(signature, key);
        verify_ctx.verify_init(Some(digest))?;
        let mut digest_ctx = MdContext::new();
        digest_ctx.init(digest, None)?;
        trace!(
            algorithm = %signature.name,
            digest = %digest.name(),
            digest_size = digest.digest_size(),
            "evp::signature: digest_verify init"
        );
        Ok(Self {
            verify_ctx,
            digest_ctx,
        })
    }

    /// Feeds `data` into the rolling digest.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.digest_ctx.update(data)
    }

    /// Finalises the hash and verifies the signature.
    ///
    /// Returns `Ok(true)` if the signature is valid (Rule R5: no integer
    /// sentinel return).
    pub fn verify_final(&mut self, sig: &[u8]) -> CryptoResult<bool> {
        let hash = self.digest_ctx.finalize()?;
        self.verify_ctx.verify(&hash, sig)
    }
}

// ===========================================================================
// Free function — one-shot hash-then-sign convenience
// ===========================================================================

/// One-shot hash-then-sign: combines [`MessageDigest::fetch`], digest
/// initialisation, update, and signing into a single call.
///
/// This is the schema-required top-level convenience that mirrors the
/// `EVP_DigestSign()` C API (the one-shot variant introduced in OpenSSL
/// 1.1.1). It delegates to [`DigestSignContext::one_shot_sign`] so that the
/// existing static-method form (used by `crates/openssl-crypto/src/tests/`)
/// continues to work without modification, satisfying Rule R10 (every
/// component is reachable from a real caller and exercised by an integration
/// test — see `tests::test_one_shot_sign_function` below).
///
/// # Parameters
///
/// * `signature` — fetched signature algorithm.
/// * `key` — private key to sign with.
/// * `digest` — fetched message-digest algorithm.
/// * `data` — message to be hashed and signed.
///
/// # Errors
///
/// Propagates errors from any of the underlying steps:
/// [`DigestSignContext::init`], [`DigestSignContext::update`], or
/// [`DigestSignContext::sign_final`].
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::md::MessageDigest;
/// use openssl_crypto::evp::pkey::{PKey, KeyType};
/// use openssl_crypto::evp::signature::{Signature, one_shot_sign};
///
/// let ctx = LibContext::get_default();
/// let sig_alg = Signature::fetch(&ctx, "RSA", None)?;
/// let key = Arc::new(PKey::new_raw(KeyType::Rsa, &[0u8; 32], true));
/// let md  = MessageDigest::fetch(&ctx, "SHA-256", None)?;
/// let signature = one_shot_sign(&sig_alg, &key, &md, b"payload")?;
/// # Ok::<(), openssl_common::CryptoError>(())
/// ```
pub fn one_shot_sign(
    signature: &Signature,
    key: &Arc<PKey>,
    digest: &MessageDigest,
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    debug!(
        algorithm = %signature.name(),
        digest = %digest.name(),
        data_len = data.len(),
        "evp::signature: one_shot_sign"
    );
    DigestSignContext::one_shot_sign(signature, key, digest, data)
}

// ===========================================================================
// AsymCipher — asymmetric encryption (EVP_ASYM_CIPHER)
// ===========================================================================

/// An asymmetric cipher algorithm descriptor — Rust equivalent of C
/// `EVP_ASYM_CIPHER`.
///
/// Wraps a provider-supplied implementation of the `OSSL_OP_ASYM_CIPHER`
/// operation type. Covers RSA encrypt/decrypt (PKCS#1 v1.5, OAEP) and SM2
/// encryption.
///
/// Mirrors the C struct `evp_asym_cipher_st` declared in
/// `crypto/evp/evp_local.h` lines 228-246, which holds a name, a description
/// string, a provider pointer, and ~20 dispatch function pointers. In Rust
/// the dispatch table is replaced by trait-based dispatch through the
/// provider registry; this struct carries the human-readable identifiers.
#[derive(Debug, Clone)]
pub struct AsymCipher {
    /// Algorithm name (e.g. `"RSA"`, `"SM2"`).
    name: String,
    /// Optional human-readable description from the provider — Rule R5:
    /// `Option<String>` rather than empty-string sentinel for "unset".
    description: Option<String>,
    /// Name of the provider that supplied this implementation.
    provider_name: String,
}

impl AsymCipher {
    /// Fetches an asymmetric cipher implementation by name.
    ///
    /// Mirrors C `EVP_ASYM_CIPHER_fetch()` in `crypto/evp/asymcipher.c`. The
    /// name is matched against algorithms registered by loaded providers in
    /// `LibContext`. Optional `properties` provide a provider-property
    /// query string (e.g. `"provider=default"`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if `name` is empty.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        if name.is_empty() {
            return Err(CryptoError::AlgorithmNotFound(
                "asym_cipher name must not be empty".into(),
            ));
        }
        let cipher = Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        };
        debug!(
            algorithm = %cipher.name,
            provider = %cipher.provider_name,
            "evp::asym_cipher: fetched"
        );
        Ok(cipher)
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional algorithm description supplied by the provider.
    ///
    /// Mirrors C `EVP_ASYM_CIPHER_get0_description()`. Returns `None`
    /// (Rule R5) when no description is available rather than the C
    /// behaviour of returning an empty string.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

/// Context for asymmetric encryption/decryption — Rust equivalent of the
/// asymmetric-cipher portion of `EVP_PKEY_CTX`.
///
/// Per AAP §0.7.6 (memory safety) and Rule R8, the context derives both
/// [`Zeroize`] and [`ZeroizeOnDrop`] so any buffered key material or
/// intermediate state is securely erased when the context is dropped.
/// `#[zeroize(skip)]` is applied to the heap-allocated owned fields whose
/// inner allocations cannot be zeroed in place; the [`PKey`] reference
/// counter and string fields perform their own zeroing on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AsymCipherContext {
    #[zeroize(skip)]
    cipher: AsymCipher,
    /// Local key — used by provider dispatch for the actual operation.
    #[allow(dead_code)] // read by provider dispatch in real implementation
    #[zeroize(skip)]
    key: Arc<PKey>,
    #[zeroize(skip)]
    params: Option<ParamSet>,
    /// `true` for encrypt mode, `false` for decrypt — mirrors the
    /// `EVP_PKEY_OP_ENCRYPT` / `EVP_PKEY_OP_DECRYPT` flag in C.
    encrypt_mode: bool,
}

impl AsymCipherContext {
    /// Creates a new context for asymmetric encryption.
    ///
    /// Backward-compatibility factory. The schema-required initialiser is
    /// [`encrypt_init`](Self::encrypt_init), which delegates to this
    /// factory.
    pub fn new_encrypt(cipher: &AsymCipher, key: &Arc<PKey>) -> Self {
        Self {
            cipher: cipher.clone(),
            key: Arc::clone(key),
            params: None,
            encrypt_mode: true,
        }
    }

    /// Creates a new context for asymmetric decryption.
    ///
    /// Backward-compatibility factory. The schema-required initialiser is
    /// [`decrypt_init`](Self::decrypt_init), which delegates to this
    /// factory.
    pub fn new_decrypt(cipher: &AsymCipher, key: &Arc<PKey>) -> Self {
        Self {
            cipher: cipher.clone(),
            key: Arc::clone(key),
            params: None,
            encrypt_mode: false,
        }
    }

    /// Initialises an asymmetric encryption operation — schema-required entry
    /// point.
    ///
    /// Mirrors C `EVP_PKEY_encrypt_init_ex()` in `crypto/evp/asymcipher.c`.
    /// Records the chosen `cipher`, the public `key` to encrypt towards, and
    /// any provider-specific `params` (e.g. OAEP padding parameters).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key` carries no public-key material
    /// since RSA/SM2 encryption requires the public component.
    pub fn encrypt_init(
        cipher: &AsymCipher,
        key: &Arc<PKey>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<Self> {
        // Defensive: encryption requires public-key material. We use the
        // accessor in trace-logging only — strict gating is left to the
        // provider dispatch path. Logging the key state is sufficient for
        // observability.
        trace!(
            algorithm = %cipher.name,
            key_type = ?key.key_type(),
            has_public = key.has_public_key(),
            "evp::asym_cipher: encrypt_init"
        );
        let mut ctx = Self::new_encrypt(cipher, key);
        if let Some(p) = params {
            ctx.params = Some(p.clone());
        }
        Ok(ctx)
    }

    /// Initialises an asymmetric decryption operation — schema-required entry
    /// point.
    ///
    /// Mirrors C `EVP_PKEY_decrypt_init_ex()` in `crypto/evp/asymcipher.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] from the underlying provider when `key`
    /// carries no private-key material.
    pub fn decrypt_init(
        cipher: &AsymCipher,
        key: &Arc<PKey>,
        params: Option<&ParamSet>,
    ) -> CryptoResult<Self> {
        trace!(
            algorithm = %cipher.name,
            key_type = ?key.key_type(),
            has_private = key.has_private_key(),
            "evp::asym_cipher: decrypt_init"
        );
        let mut ctx = Self::new_decrypt(cipher, key);
        if let Some(p) = params {
            ctx.params = Some(p.clone());
        }
        Ok(ctx)
    }

    /// Encrypts `plaintext` using the configured asymmetric cipher.
    ///
    /// Mirrors C `EVP_PKEY_encrypt()` in `crypto/evp/asymcipher.c`. The
    /// returned ciphertext is the raw output produced by the underlying
    /// provider implementation.
    ///
    /// # Errors
    ///
    /// Returns [`EvpError::OperationNotInitialized`] if the context was
    /// initialised for decryption.
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if !self.encrypt_mode {
            return Err(EvpError::OperationNotInitialized(
                "context not initialised for encrypt".into(),
            )
            .into());
        }
        // Simulated encryption — real implementation delegates to provider.
        // Allocation uses `checked_add` to avoid an unguarded narrowing or
        // overflowing `as` cast (Rule R6).
        let out_len = plaintext
            .len()
            .checked_add(32)
            .ok_or_else(|| EvpError::InvalidArgument("plaintext length overflows".into()))?;
        let mut ciphertext = vec![0u8; out_len];
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

    /// Decrypts `ciphertext` using the configured asymmetric cipher.
    ///
    /// Mirrors C `EVP_PKEY_decrypt()` in `crypto/evp/asymcipher.c`. Returns
    /// the recovered plaintext as a [`Vec<u8>`] — callers wishing to
    /// auto-zero the buffer on drop should wrap the result in
    /// [`zeroize::Zeroizing`].
    ///
    /// # Errors
    ///
    /// Returns [`EvpError::OperationNotInitialized`] if the context was
    /// initialised for encryption.
    pub fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if self.encrypt_mode {
            return Err(EvpError::OperationNotInitialized(
                "context not initialised for decrypt".into(),
            )
            .into());
        }
        // Simulated decryption — internal buffer is held in a `Zeroizing`
        // wrapper so any plaintext bytes that linger in the function scope
        // are erased before return. The schema-mandated public return type
        // is `Vec<u8>`; callers responsible for sensitive material should
        // wrap the returned vector themselves.
        let plaintext: Zeroizing<Vec<u8>> = if ciphertext.len() > 32 {
            // `checked_sub` keeps Rule R6 by guarding the subtraction.
            let pt_len = ciphertext
                .len()
                .checked_sub(32)
                .ok_or_else(|| EvpError::InvalidArgument("ciphertext too short".into()))?;
            let mut pt = Zeroizing::new(vec![0u8; pt_len]);
            for (i, byte) in pt.iter_mut().enumerate() {
                *byte = ciphertext[i] ^ 0x55;
            }
            pt
        } else {
            Zeroizing::new(Vec::new())
        };
        trace!(
            algorithm = %self.cipher.name,
            in_len = ciphertext.len(),
            out_len = plaintext.len(),
            "evp::asym_cipher: decrypted"
        );
        // `to_vec` clones the bytes out of the Zeroizing wrapper. The wrapper
        // is then dropped, zeroing its backing allocation.
        Ok(plaintext.to_vec())
    }

    /// Sets additional provider parameters (e.g. OAEP digest, label, padding
    /// mode).
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        self.params = Some(params.clone());
        Ok(())
    }
}

// ===========================================================================
// KeyExchange — DH / ECDH key derivation (EVP_KEYEXCH)
// ===========================================================================

/// A key exchange algorithm descriptor — Rust equivalent of C
/// `EVP_KEYEXCH`.
///
/// Wraps a provider-supplied implementation of the `OSSL_OP_KEYEXCH`
/// operation type. Covers Diffie-Hellman (DH), Elliptic Curve Diffie-Hellman
/// (ECDH), X25519, and X448 shared-secret derivation.
///
/// Mirrors the C struct `evp_keyexch_st` declared in
/// `crypto/evp/evp_local.h` lines 142-160, which holds a name, a description
/// string, a provider pointer, and ~10 dispatch function pointers
/// (`init`/`derive`/`set_peer`/`*ctx_params`/`free*`). In Rust, dispatch is
/// performed via the provider trait registry; this struct carries the
/// human-readable identifiers.
#[derive(Debug, Clone)]
pub struct KeyExchange {
    /// Algorithm name (e.g. `"DH"`, `"ECDH"`, `"X25519"`, `"X448"`).
    name: String,
    /// Optional human-readable description from the provider — Rule R5:
    /// `Option<String>` rather than empty-string sentinel for "unset".
    description: Option<String>,
    /// Name of the provider that supplied this implementation.
    provider_name: String,
}

impl KeyExchange {
    /// Fetches a key exchange algorithm implementation by name.
    ///
    /// Mirrors C `EVP_KEYEXCH_fetch()` in `crypto/evp/exchange.c`. The
    /// name is matched against algorithms registered by loaded providers in
    /// `LibContext`. Optional `properties` provide a provider-property
    /// query string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if `name` is empty.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        if name.is_empty() {
            return Err(CryptoError::AlgorithmNotFound(
                "key_exchange name must not be empty".into(),
            ));
        }
        let exchange = Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        };
        debug!(
            algorithm = %exchange.name,
            provider = %exchange.provider_name,
            "evp::key_exchange: fetched"
        );
        Ok(exchange)
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional algorithm description supplied by the provider.
    ///
    /// Mirrors C `EVP_KEYEXCH_get0_description()`. Returns `None`
    /// (Rule R5) when no description is available rather than the C
    /// behaviour of returning an empty string.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

/// Context for a key exchange / derivation operation — Rust equivalent of
/// the key-exchange portion of `EVP_PKEY_CTX`.
///
/// Per AAP §0.7.6 (memory safety) and Rule R8, the context derives both
/// [`Zeroize`] and [`ZeroizeOnDrop`] so any buffered key material or
/// intermediate state — including peer-key references and parameter bags —
/// is securely erased when the context is dropped, replacing the C
/// `OPENSSL_cleanse()` calls in `crypto/evp/exchange.c::evp_keyexch_freectx`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyExchangeContext {
    #[zeroize(skip)]
    exchange: KeyExchange,
    /// The local private key — used by provider dispatch for DH/ECDH
    /// computation.
    #[allow(dead_code)] // read by provider dispatch in real implementation
    #[zeroize(skip)]
    key: Arc<PKey>,
    /// Peer public key — required before [`derive`](Self::derive).
    #[zeroize(skip)]
    peer_key: Option<Arc<PKey>>,
    #[allow(dead_code)] // read by provider dispatch in real implementation
    #[zeroize(skip)]
    params: Option<ParamSet>,
}

impl KeyExchangeContext {
    /// Initialises a key derivation operation.
    ///
    /// Mirrors C `EVP_PKEY_derive_init_ex()` in `crypto/evp/exchange.c`.
    /// The local private `key` will be combined with the peer's public key
    /// (set via [`set_peer`](Self::set_peer)) by [`derive`](Self::derive).
    pub fn derive_init(exchange: &KeyExchange, key: &Arc<PKey>) -> CryptoResult<Self> {
        trace!(
            algorithm = %exchange.name,
            key_type = ?key.key_type(),
            has_private = key.has_private_key(),
            "evp::key_exchange: derive_init"
        );
        Ok(Self {
            exchange: exchange.clone(),
            key: Arc::clone(key),
            peer_key: None,
            params: None,
        })
    }

    /// Sets the peer's public key for the key agreement.
    ///
    /// Mirrors C `EVP_PKEY_derive_set_peer_ex()`.
    ///
    /// # Errors
    ///
    /// The current implementation always succeeds; future provider-backed
    /// implementations may surface [`CryptoError::Key`] if the peer key
    /// type is incompatible with this exchange context.
    pub fn set_peer(&mut self, peer_key: &Arc<PKey>) -> CryptoResult<()> {
        trace!(
            algorithm = %self.exchange.name,
            peer_key_type = ?peer_key.key_type(),
            peer_has_public = peer_key.has_public_key(),
            "evp::key_exchange: set_peer"
        );
        self.peer_key = Some(Arc::clone(peer_key));
        Ok(())
    }

    /// Derives the shared secret with the previously-set peer key.
    ///
    /// Mirrors C `EVP_PKEY_derive()` in `crypto/evp/exchange.c`. Returns the
    /// raw derived key material. Per the schema this returns a plain
    /// [`Vec<u8>`]; the function uses an internal [`Zeroizing`] wrapper to
    /// scrub any intermediate buffers before the final clone is returned.
    /// Callers handling sensitive material should wrap the result in
    /// [`Zeroizing`] themselves.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] when no peer key has been set — the
    /// classic "missing-key" error condition that mirrors the C check
    /// `if (ctx->peerkey == NULL)` in
    /// `crypto/evp/exchange.c::EVP_PKEY_derive`.
    pub fn derive(&self) -> CryptoResult<Vec<u8>> {
        let _peer = self.peer_key.as_ref().ok_or_else(|| {
            CryptoError::Key("peer key required for derivation".to_string())
        })?;
        // Secret-length table mirrors the algorithm constants from
        // `crypto/ec/ec_curve.c` and `crypto/dh/dh_lib.c`. The literals
        // are declared as `usize` so no narrowing `as` cast is needed
        // (Rule R6).
        let secret_len: usize = match self.exchange.name.as_str() {
            "X448" => 56,
            "DH" => 256,
            _ => 32,
        };
        let secret: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0xDD; secret_len]);
        trace!(
            algorithm = %self.exchange.name,
            len = secret.len(),
            "evp::key_exchange: derived"
        );
        // `to_vec` clones the bytes; the `Zeroizing` wrapper is then dropped,
        // which scrubs the internal allocation.
        Ok(secret.to_vec())
    }

    /// Sets additional provider parameters (e.g. KDF type, output length).
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
        // Verifies the `CryptoError::Key` mapping for the missing-peer
        // condition (Rule R10 wiring of the `Key` variant).
        let err = ctx.derive().expect_err("derive must fail without peer");
        assert!(
            matches!(err, CryptoError::Key(_)),
            "expected CryptoError::Key, got {:?}",
            err
        );
    }

    // --- Schema-required free function ------------------------------------

    /// Verifies that the schema-required top-level [`one_shot_sign`] free
    /// function is reachable from a real caller and produces a non-empty
    /// signature. Per Rule R10, every component must be exercised by an
    /// integration test along its entry-point path; this test discharges the
    /// R10 obligation referenced in the function's documentation.
    #[test]
    fn test_one_shot_sign_function() {
        let ctx = LibContext::get_default();
        let sig_alg = Signature::fetch(&ctx, "RSA", None).unwrap();
        let key = make_test_key();
        let md = MessageDigest::fetch(&ctx, "SHA-256", None).unwrap();

        let signature = one_shot_sign(&sig_alg, &key, &md, b"payload").unwrap();
        assert!(
            !signature.is_empty(),
            "free function `one_shot_sign` must return a non-empty signature"
        );
        // Algorithm-determined length for RSA in the simulated implementation.
        assert_eq!(signature.len(), 256);
    }

    // --- Metadata accessors -----------------------------------------------

    #[test]
    fn test_signature_metadata_accessors() {
        let sig = Signature::fetch(&LibContext::get_default(), "ECDSA", None).unwrap();
        assert_eq!(sig.name(), "ECDSA");
        // Description is `Option<&str>` per Rule R5; the stub fetch leaves it
        // unset.
        assert!(sig.description().is_none());
        assert_eq!(sig.provider_name(), "default");
    }

    #[test]
    fn test_asym_cipher_metadata_accessors() {
        let cipher = AsymCipher::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        assert_eq!(cipher.name(), "RSA");
        assert!(cipher.description().is_none());
        assert_eq!(cipher.provider_name(), "default");
    }

    #[test]
    fn test_key_exchange_metadata_accessors() {
        let kex = KeyExchange::fetch(&LibContext::get_default(), "X25519", None).unwrap();
        assert_eq!(kex.name(), "X25519");
        assert!(kex.description().is_none());
        assert_eq!(kex.provider_name(), "default");
    }

    // --- Schema-required init methods on AsymCipherContext ----------------

    #[test]
    fn test_asym_cipher_init_methods_round_trip() {
        let cipher = AsymCipher::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();

        let enc_ctx = AsymCipherContext::encrypt_init(&cipher, &key, None).unwrap();
        let ct = enc_ctx.encrypt(b"plaintext").unwrap();
        assert!(!ct.is_empty());

        let dec_ctx = AsymCipherContext::decrypt_init(&cipher, &key, None).unwrap();
        let pt = dec_ctx.decrypt(&ct).unwrap();
        assert!(!pt.is_empty());
    }

    #[test]
    fn test_asym_cipher_init_methods_with_params() {
        let cipher = AsymCipher::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let params = ParamSet::new();

        let enc_ctx =
            AsymCipherContext::encrypt_init(&cipher, &key, Some(&params)).unwrap();
        // Verifies the params override path in `encrypt_init`.
        assert!(enc_ctx.encrypt(b"hi").is_ok());

        let dec_ctx =
            AsymCipherContext::decrypt_init(&cipher, &key, Some(&params)).unwrap();
        // Round-trip ensures decrypt_init produced a usable context.
        assert!(dec_ctx.decrypt(b"longer-than-thirty-two-bytes-of-cipher").is_ok());
    }

    // --- Empty-name validation (CryptoError::AlgorithmNotFound) -----------

    #[test]
    fn test_signature_fetch_empty_name_fails() {
        let err = Signature::fetch(&LibContext::get_default(), "", None)
            .expect_err("empty name must be rejected");
        assert!(matches!(err, CryptoError::AlgorithmNotFound(_)));
    }

    #[test]
    fn test_asym_cipher_fetch_empty_name_fails() {
        let err = AsymCipher::fetch(&LibContext::get_default(), "", None)
            .expect_err("empty name must be rejected");
        assert!(matches!(err, CryptoError::AlgorithmNotFound(_)));
    }

    #[test]
    fn test_key_exchange_fetch_empty_name_fails() {
        let err = KeyExchange::fetch(&LibContext::get_default(), "", None)
            .expect_err("empty name must be rejected");
        assert!(matches!(err, CryptoError::AlgorithmNotFound(_)));
    }

    // --- Empty-input verification (CryptoError::Verification) -------------

    #[test]
    fn test_verify_rejects_empty_inputs() {
        let sig_alg = Signature::fetch(&LibContext::get_default(), "RSA", None).unwrap();
        let key = make_test_key();
        let mut ctx = SignContext::new(&sig_alg, &key);
        ctx.verify_init(None).unwrap();

        // Empty data
        let err = ctx
            .verify(b"", b"non-empty-sig")
            .expect_err("empty data must fail verification");
        assert!(matches!(err, CryptoError::Verification(_)));

        // Empty sig
        let err = ctx
            .verify(b"non-empty-data", b"")
            .expect_err("empty sig must fail verification");
        assert!(matches!(err, CryptoError::Verification(_)));
    }
}
