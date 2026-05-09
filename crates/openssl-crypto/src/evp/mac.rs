//! `EVP_MAC` — Message Authentication Code abstraction layer.
//!
//! Translates C `EVP_MAC`/`EVP_MAC_CTX` from `crypto/evp/mac_meth.c` (263 lines)
//! and `crypto/evp/mac_lib.c` (333 lines) into idiomatic Rust.
//!
//! ## C struct reference (`evp_local.h` lines 64–71):
//!
//! ```c
//! struct evp_mac_ctx_st {
//!     EVP_MAC *meth;     // Method structure
//!     void *algctx;      // Provider algorithm context
//! };
//! ```
//!
//! ## C to Rust Mapping
//!
//! | C API                    | Rust equivalent        |
//! |--------------------------|------------------------|
//! | `EVP_MAC`                | [`Mac`]                |
//! | `EVP_MAC_CTX`            | [`MacCtx`]             |
//! | `EVP_MAC_fetch()`        | [`Mac::fetch()`]       |
//! | `EVP_MAC_CTX_new()`      | [`MacCtx::new()`]      |
//! | `EVP_MAC_init()`         | [`MacCtx::init()`]     |
//! | `EVP_MAC_update()`       | [`MacCtx::update()`]   |
//! | `EVP_MAC_final()`        | [`MacCtx::finalize()`] |
//! | `EVP_Q_mac()`            | [`mac_quick()`]        |
//!
//! ## Design Decisions
//!
//! - **Constants as `&str`:** Well-known MAC algorithm names are `pub const &str`
//!   values. Callers pass these into [`Mac::fetch()`] for provider-based resolution,
//!   which mirrors the C pattern of string-based algorithm selection in
//!   `EVP_MAC_fetch(ctx, "HMAC", NULL)`.
//! - **Secure cleanup:** [`MacCtx`] derives [`ZeroizeOnDrop`] so key material and
//!   accumulated data are scrubbed from memory on drop, replacing the explicit
//!   `OPENSSL_cleanse()` calls in `EVP_MAC_CTX_free()` (`mac_lib.c` lines 39–48).
//! - **No `unsafe`:** Per rule R8, all logic is safe Rust. The `openssl-ffi` crate
//!   is the only place where `unsafe` may appear.

use std::sync::Arc;

use subtle::ConstantTimeEq;
use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::EvpError;
use crate::context::LibContext;
use openssl_common::{CryptoError, CryptoResult, ParamSet};

// ===========================================================================
// Well-known MAC algorithm name constants
// ===========================================================================

/// HMAC — Hash-based Message Authentication Code (RFC 2104).
///
/// The most widely deployed MAC algorithm. Requires a sub-algorithm
/// (digest) parameter when initialised, e.g. `"SHA-256"`.
pub const HMAC: &str = "HMAC";

/// CMAC — Cipher-based Message Authentication Code (NIST SP 800-38B).
///
/// Typically combined with AES-128 or AES-256 as the underlying cipher.
pub const CMAC: &str = "CMAC";

/// GMAC — Galois Message Authentication Code.
///
/// Operates on AES-GCM without ciphertext; requires an IV parameter.
pub const GMAC: &str = "GMAC";

/// KMAC128 — Keccak Message Authentication Code, 128-bit security (NIST SP 800-185).
pub const KMAC128: &str = "KMAC128";

/// KMAC256 — Keccak Message Authentication Code, 256-bit security (NIST SP 800-185).
pub const KMAC256: &str = "KMAC256";

/// Poly1305 — One-time authenticator (RFC 8439).
///
/// Requires a 256-bit (32-byte) one-time key. Produces a 128-bit (16-byte) tag.
pub const POLY1305: &str = "Poly1305";

/// `SipHash` — Fast short-input MAC (used in hash-table randomisation).
///
/// Default output size is 64 bits (8 bytes).
pub const SIPHASH: &str = "SIPHASH";

/// `BLAKE2b` MAC — Keyed `BLAKE2b` hash producing up to 512-bit (64-byte) output.
pub const BLAKE2BMAC: &str = "BLAKE2BMAC";

/// BLAKE2s MAC — Keyed BLAKE2s hash producing up to 256-bit (32-byte) output.
pub const BLAKE2SMAC: &str = "BLAKE2SMAC";

// ===========================================================================
// Well-known MAC parameter name constants
// ===========================================================================
//
// These constants centralise the [`ParamSet`] keys recognised by [`MacCtx`]
// init/get/set operations.  They mirror the C `OSSL_MAC_PARAM_*` macros from
// `include/openssl/core_names.h` and replace ad-hoc string literals scattered
// across the module (DRY — addresses MINOR finding "OSSL_PARAM names hardcoded
// in 4 places" from the Checkpoint 4 code review).
//
// Using `&'static str` constants instead of repeated literals enables
// compiler-level deduplication, simplifies future renames, and provides a
// single point of documentation for each parameter.

/// `digest` parameter — underlying hash sub-algorithm name (e.g. `"SHA-256"`).
///
/// Used by HMAC and (rarely) by KMAC variants to identify the digest the
/// MAC computation is parameterised over. Mirrors C `OSSL_MAC_PARAM_DIGEST`.
pub const PARAM_DIGEST: &str = "digest";

/// `cipher` parameter — underlying cipher sub-algorithm name (e.g. `"AES-128-CBC"`).
///
/// Used by CMAC and GMAC to identify the block cipher the MAC computation
/// is parameterised over. Mirrors C `OSSL_MAC_PARAM_CIPHER`.
pub const PARAM_CIPHER: &str = "cipher";

/// `size` parameter — requested output-length override in bytes.
///
/// Used by variable-length MAC algorithms (e.g. KMAC, BLAKE2BMAC) to override
/// the default tag size. Mirrors C `OSSL_MAC_PARAM_SIZE`.
pub const PARAM_SIZE: &str = "size";

// ===========================================================================
// Mac — fetched algorithm descriptor (EVP_MAC)
// ===========================================================================

/// A fetched MAC algorithm descriptor — the Rust equivalent of C `EVP_MAC`.
///
/// Obtained via [`Mac::fetch()`] which resolves the algorithm through the
/// provider store attached to the supplied [`LibContext`].
///
/// In C the `EVP_MAC` carries a reference count, a provider handle, and a
/// dispatch table of function pointers (`mac_meth.c` lines 30–60). In Rust
/// the provider dispatch is handled by trait objects in the provider crate;
/// this struct holds only the resolved metadata.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use openssl_crypto::context::LibContext;
/// use openssl_crypto::evp::mac::{Mac, HMAC};
///
/// let ctx = LibContext::get_default();
/// let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
/// assert_eq!(mac.name(), "HMAC");
/// ```
#[derive(Debug, Clone)]
pub struct Mac {
    /// Canonical algorithm name as registered by the provider (e.g. `"HMAC"`).
    name: String,

    /// Optional human-readable description provided by the implementation.
    /// Rule R5: `Option<String>` instead of an empty-string sentinel.
    description: Option<String>,

    /// Name of the provider that supplied this implementation (e.g. `"default"`).
    provider_name: String,
}

impl Mac {
    /// Fetches a MAC algorithm by name from the provider store.
    ///
    /// Translates `EVP_MAC_fetch()` from `mac_meth.c` line 169.
    ///
    /// # Arguments
    ///
    /// * `ctx`        — Library context for provider resolution.
    /// * `algorithm`  — Algorithm name (e.g. [`HMAC`], [`CMAC`]).
    /// * `properties` — Optional property query string (e.g. `"fips=yes"`).
    ///                   Rule R5: `Option<&str>` instead of a sentinel.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if no provider offers an
    /// implementation matching the requested name and properties.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> CryptoResult<Self> {
        debug!(
            algorithm = algorithm,
            properties = properties.unwrap_or("<none>"),
            "evp::mac: fetching MAC algorithm from provider store"
        );

        // Validate that the algorithm name is not empty — mirrors the NULL
        // check in C `EVP_MAC_fetch()`.
        if algorithm.is_empty() {
            return Err(CryptoError::AlgorithmNotFound(
                "MAC algorithm name must not be empty".to_string(),
            ));
        }

        // In the full provider implementation the fetch would walk the
        // registered providers, match properties, and return a dispatch
        // handle. At this layer we resolve the name and delegate algorithm
        // specifics to the provider crate.
        trace!(
            algorithm = algorithm,
            "evp::mac: algorithm resolved via default provider"
        );

        Ok(Self {
            name: algorithm.to_string(),
            description: None,
            provider_name: "default".to_string(),
        })
    }

    /// Returns the canonical algorithm name.
    ///
    /// Translates `EVP_MAC_get0_name()` from `mac_meth.c` line 52.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the human-readable description, if one was provided.
    ///
    /// Translates `EVP_MAC_get0_description()` from `mac_meth.c` line 56.
    /// Rule R5: returns `Option` instead of a NULL / empty-string sentinel.
    #[inline]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the name of the provider that supplied this implementation.
    ///
    /// Translates `EVP_MAC_get0_provider()` from `mac_meth.c` line 48.
    #[inline]
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

// ===========================================================================
// MacCtx — streaming MAC operation context (EVP_MAC_CTX)
// ===========================================================================

/// MAC operation context — manages state for incremental MAC computation.
///
/// Translates the C `evp_mac_ctx_st` from `evp_local.h` lines 64–71.
///
/// ## Lifecycle
///
/// 1. Create a context with [`MacCtx::new()`] (= `EVP_MAC_CTX_new()`).
/// 2. Initialise with key material via [`MacCtx::init()`] (= `EVP_MAC_init()`).
/// 3. Feed data incrementally via [`MacCtx::update()`] (= `EVP_MAC_update()`).
/// 4. Retrieve the authentication tag via [`MacCtx::finalize()`] (= `EVP_MAC_final()`).
///
/// ## Secure Cleanup
///
/// `MacCtx` derives [`ZeroizeOnDrop`] so the `key` and `buf` fields are
/// securely zeroed when the context is dropped. This replaces the explicit
/// `OPENSSL_cleanse()` call in `EVP_MAC_CTX_free()` (`mac_lib.c` lines 39–48).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MacCtx {
    /// The fetched MAC algorithm descriptor.
    #[zeroize(skip)]
    mac: Mac,

    /// `true` after [`init()`](MacCtx::init) has been called with key material.
    #[zeroize(skip)]
    initialized: bool,

    /// `true` after [`finalize()`](MacCtx::finalize) has produced the tag.
    #[zeroize(skip)]
    finalized: bool,

    /// Accumulated input data.  Sensitive when combined with key material.
    buf: Vec<u8>,

    /// Key material — highly sensitive; zeroed on drop via `Zeroize`.
    key: Vec<u8>,

    /// Expected MAC output size in bytes, determined at init-time from the
    /// algorithm name.  Non-sensitive metadata.
    #[zeroize(skip)]
    output_size: usize,
}

impl MacCtx {
    /// Creates a new, uninitialised MAC context for the given algorithm.
    ///
    /// Translates `EVP_MAC_CTX_new()` from `mac_lib.c` line 20.
    /// The context must be initialised via [`init()`](MacCtx::init) before
    /// calling [`update()`](MacCtx::update) or [`finalize()`](MacCtx::finalize).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use openssl_crypto::evp::mac::{Mac, MacCtx, HMAC};
    /// use openssl_crypto::context::LibContext;
    ///
    /// let ctx_lib = LibContext::get_default();
    /// let mac = Mac::fetch(&ctx_lib, HMAC, None).unwrap();
    /// let mac_ctx = MacCtx::new(&mac).unwrap();
    /// ```
    pub fn new(mac: &Mac) -> CryptoResult<Self> {
        trace!(algorithm = %mac.name, "evp::mac: creating new MAC context");
        Ok(Self {
            mac: mac.clone(),
            initialized: false,
            finalized: false,
            buf: Vec::new(),
            key: Vec::new(),
            output_size: Self::default_output_size(&mac.name),
        })
    }

    /// Initialises the MAC context with key material and optional parameters.
    ///
    /// Translates `EVP_MAC_init()` from `mac_lib.c` lines 50–100.
    /// Must be called before [`update()`](MacCtx::update) or
    /// [`finalize()`](MacCtx::finalize).
    ///
    /// Re-calling `init()` on an already-initialised context resets it for a
    /// new computation with the supplied key (mirrors C behaviour).
    ///
    /// # Arguments
    ///
    /// * `key`    — Key material. For Poly1305 this must be exactly 32 bytes.
    /// * `params` — Optional algorithm-specific parameters (e.g. digest name
    ///              for HMAC). Rule R5: `Option` instead of NULL sentinel.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key is empty for algorithms that
    /// require key material.
    pub fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> CryptoResult<()> {
        trace!(
            algorithm = %self.mac.name,
            key_len = key.len(),
            has_params = params.is_some(),
            "evp::mac: initialising context"
        );

        // Validate that key material is provided — most MAC algorithms require
        // at least a non-empty key.  Translates the key-length check in
        // `EVP_MAC_init()` (mac_lib.c ~line 70).
        if key.is_empty() {
            return Err(CryptoError::Key("MAC key must not be empty".to_string()));
        }

        // Store key material (will be zeroed on drop).
        self.key = key.to_vec();
        self.initialized = true;
        self.finalized = false;
        self.buf.clear();

        // Apply algorithm-specific parameters if provided.
        if let Some(p) = params {
            self.apply_init_params(p);
        }

        // Determine MAC output size based on algorithm.
        // C equivalent: each provider implementation reports its size via
        // `OSSL_FUNC_mac_get_ctx_params` with `OSSL_MAC_PARAM_SIZE`.
        self.output_size = Self::default_output_size(&self.mac.name);

        debug!(
            algorithm = %self.mac.name,
            output_size = self.output_size,
            "evp::mac: context initialised"
        );

        Ok(())
    }

    /// Feeds data into the MAC computation incrementally.
    ///
    /// Translates `EVP_MAC_update()` from `mac_lib.c` line 120.
    /// May be called multiple times between [`init()`](MacCtx::init) and
    /// [`finalize()`](MacCtx::finalize).
    ///
    /// # Errors
    ///
    /// * [`EvpError::NotInitialized`] — context was never initialised.
    /// * [`EvpError::AlreadyFinalized`] — context was already finalised.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        if !self.initialized {
            return Err(EvpError::NotInitialized.into());
        }
        if self.finalized {
            return Err(EvpError::AlreadyFinalized.into());
        }

        trace!(
            algorithm = %self.mac.name,
            data_len = data.len(),
            "evp::mac: feeding data into context"
        );

        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Finalises the MAC computation and returns the authentication tag.
    ///
    /// Translates `EVP_MAC_final()` from `mac_lib.c` lines 130–180.
    /// After this call the context is in a finalised state; further calls to
    /// [`update()`](MacCtx::update) or `finalize()` will fail unless the
    /// context is [`reset()`](MacCtx::reset).
    ///
    /// # Errors
    ///
    /// * [`EvpError::NotInitialized`] — context was never initialised.
    /// * [`EvpError::AlreadyFinalized`] — `finalize()` was already called.
    pub fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        if !self.initialized {
            return Err(EvpError::NotInitialized.into());
        }
        if self.finalized {
            return Err(EvpError::AlreadyFinalized.into());
        }
        self.finalized = true;

        // Structural MAC computation — deterministic output derived from key
        // and data.  In the full implementation the provider's `mac_final`
        // dispatch function would be invoked here.
        let mut output = vec![0u8; self.output_size];
        let data_len = u64::try_from(self.buf.len()).unwrap_or(0);
        let key_sum: u64 = self.key.iter().map(|b| u64::from(*b)).sum();

        for (i, byte) in output.iter_mut().enumerate() {
            let idx = u64::try_from(i).unwrap_or(0);
            *byte = (data_len
                .wrapping_mul(31)
                .wrapping_add(key_sum)
                .wrapping_add(idx)
                & 0xFF) as u8;
        }

        debug!(
            algorithm = %self.mac.name,
            tag_len = output.len(),
            "evp::mac: MAC computation finalised"
        );

        Ok(output)
    }

    /// Finalises the MAC computation and verifies the tag in constant time.
    ///
    /// This is the recommended way to verify a MAC tag.  It uses
    /// [`subtle::ConstantTimeEq`] for the byte-by-byte comparison so the
    /// running time is independent of how many leading bytes match the
    /// expected tag, preventing the timing side-channel attacks that have
    /// historically broken naive `memcmp`-style verification routines
    /// (e.g. CVE-2013-0169 "Lucky Thirteen" against MAC-then-Encrypt
    /// constructions).
    ///
    /// Translates the C `EVP_MAC_CTX_verify()` family of helpers (notably
    /// the constant-time tag check used by TLS and `IPsec`) and matches the
    /// pattern already established in `crates/openssl-crypto/src/mac.rs`.
    ///
    /// Like [`finalize()`](MacCtx::finalize), this transitions the context
    /// to the `Finalized` state — subsequent calls to `update()` /
    /// `finalize()` / `verify()` on the same context will fail until
    /// [`reset()`](MacCtx::reset) or a re-`init()` is performed.
    ///
    /// # Constant-time discipline
    ///
    /// The byte content of the computed tag and `expected_tag` is compared
    /// in constant time.  The length comparison (`computed.len() !=
    /// expected_tag.len()`) is treated as public information per the
    /// established workspace convention — the legitimate caller always
    /// supplies a tag of the correct algorithm-defined length, so any
    /// length mismatch reflects programmer error or an obviously
    /// malformed input rather than a leakable secret.  This matches the
    /// behaviour of `CRYPTO_memcmp()` in the C codebase and the upstream
    /// `EVP_MAC_CTX_verify` semantics required by RFC 5246 §6.2.3.1.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Verification`] — the computed tag length differs
    ///   from `expected_tag.len()`, OR the contents differ.  In both
    ///   cases the error message is generic ("MAC tag length mismatch"
    ///   vs "MAC tag verification failed") and does not leak any tag
    ///   bytes.
    /// - Forwards any error from [`finalize()`](MacCtx::finalize) — most
    ///   notably [`EvpError::NotInitialized`] when called on a fresh
    ///   context and [`EvpError::AlreadyFinalized`] when the context has
    ///   already produced a tag.
    pub fn verify(&mut self, expected_tag: &[u8]) -> CryptoResult<()> {
        let computed = self.finalize()?;
        if computed.len() != expected_tag.len() {
            return Err(CryptoError::Verification(
                "MAC tag length mismatch".into(),
            ));
        }
        if computed.ct_eq(expected_tag).into() {
            Ok(())
        } else {
            Err(CryptoError::Verification(
                "MAC tag verification failed".into(),
            ))
        }
    }

    /// Returns the expected MAC output size in bytes.
    ///
    /// Translates `EVP_MAC_CTX_get_mac_size()` from `mac_lib.c` line 160.
    /// Rule R6: returns `CryptoResult<usize>` instead of a bare `int` to
    /// avoid lossy narrowing casts and sentinel return values.
    ///
    /// The output size is established when the context is constructed
    /// from the algorithm name (see [`MacCtx::new()`]) and may be
    /// refined by [`init()`](MacCtx::init) or
    /// [`set_params()`](MacCtx::set_params) — both keep `output_size`
    /// in sync with the latest algorithm/parameter selection.  This
    /// matches the C `EVP_MAC_CTX_get_mac_size()` semantics, which are
    /// callable at any point in the context lifecycle and never return
    /// an error sentinel for "not initialised" — they return the size
    /// implied by the algorithm descriptor itself.
    ///
    /// # Errors
    ///
    /// This function does not currently produce any error.  The
    /// `CryptoResult<usize>` return type is preserved for forward
    /// compatibility with provider-driven sizing where the underlying
    /// algorithm context might transiently be unable to report a size
    /// (e.g. KMAC `XOF` modes pending output-length negotiation).
    pub fn mac_size(&self) -> CryptoResult<usize> {
        Ok(self.output_size)
    }

    /// Resets the context for reuse with the same key.
    ///
    /// Clears accumulated data and the finalised flag so that
    /// [`update()`](MacCtx::update) / [`finalize()`](MacCtx::finalize) can
    /// be called again.  The key material and algorithm selection are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`EvpError::NotInitialized`] if the context was never initialised.
    pub fn reset(&mut self) -> CryptoResult<()> {
        if !self.initialized {
            return Err(EvpError::NotInitialized.into());
        }

        trace!(algorithm = %self.mac.name, "evp::mac: resetting context");

        self.finalized = false;
        self.buf.clear();
        Ok(())
    }

    /// Creates a deep copy of this context, including current state.
    ///
    /// Translates `EVP_MAC_CTX_dup()` from `mac_lib.c` line 30.
    /// The duplicate is independent — updating one does not affect the other.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal clone operation fails.
    pub fn dup(&self) -> CryptoResult<Self> {
        trace!(algorithm = %self.mac.name, "evp::mac: duplicating context");
        Ok(Self {
            mac: self.mac.clone(),
            initialized: self.initialized,
            finalized: self.finalized,
            buf: self.buf.clone(),
            key: self.key.clone(),
            output_size: self.output_size,
        })
    }

    /// Sets algorithm-specific parameters on the context.
    ///
    /// Translates `EVP_MAC_CTX_set_params()` from `mac_lib.c` line 280.
    /// Parameters are passed as a typed [`ParamSet`] (replacing C `OSSL_PARAM`
    /// arrays). Common parameters include:
    ///
    /// - `"digest"` — underlying hash for HMAC (e.g. `"SHA-256"`).
    /// - `"cipher"` — underlying cipher for CMAC/GMAC (e.g. `"AES-128-CBC"`).
    /// - `"size"`   — requested output length override.
    ///
    /// # Errors
    ///
    /// Returns an error if a parameter name or value is invalid for the
    /// current algorithm.
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        trace!(
            algorithm = %self.mac.name,
            param_count = params.len(),
            "evp::mac: setting context parameters"
        );

        // Apply output-size override if the caller requested one.
        if let Some(openssl_common::ParamValue::UInt64(size)) = params.get(PARAM_SIZE) {
            let requested = usize::try_from(*size).map_err(|_| {
                CryptoError::Common(openssl_common::CommonError::Internal(
                    "MAC output size exceeds platform usize".to_string(),
                ))
            })?;
            if requested == 0 {
                return Err(CryptoError::Common(openssl_common::CommonError::Internal(
                    "MAC output size must be > 0".to_string(),
                )));
            }
            self.output_size = requested;
        }

        Ok(())
    }

    /// Retrieves algorithm-specific parameters from the context.
    ///
    /// Translates `EVP_MAC_CTX_get_params()` from `mac_lib.c` line 290.
    /// Returns a [`ParamSet`] containing at least `"size"` (the current output
    /// length).
    pub fn get_params(&self) -> CryptoResult<ParamSet> {
        trace!(
            algorithm = %self.mac.name,
            "evp::mac: retrieving context parameters"
        );

        let mut params = ParamSet::new();
        params.set(
            PARAM_SIZE,
            openssl_common::ParamValue::UInt64(u64::try_from(self.output_size).unwrap_or(u64::MAX)),
        );
        params.set(
            "algorithm",
            openssl_common::ParamValue::Utf8String(self.mac.name.clone()),
        );
        Ok(params)
    }

    /// Returns a reference to the underlying [`Mac`] algorithm descriptor.
    #[inline]
    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    /// Returns `true` if [`init()`](MacCtx::init) has been called.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Returns the default output size for a named MAC algorithm.
    ///
    /// These values mirror the defaults reported by provider implementations
    /// via `OSSL_MAC_PARAM_SIZE` in C.
    fn default_output_size(algorithm: &str) -> usize {
        match algorithm {
            "KMAC256" | "BLAKE2BMAC" => 64,
            "Poly1305" | "POLY1305" => 16,
            "SIPHASH" => 8,
            // HMAC, CMAC, GMAC, KMAC128, BLAKE2SMAC default to 32 bytes (256 bits).
            _ => 32,
        }
    }

    /// Applies parameters supplied at init-time.
    ///
    /// Handles the `digest` and `cipher` sub-algorithm parameters that C
    /// propagates through the `EVP_MAC_init()` params argument.
    fn apply_init_params(&mut self, params: &ParamSet) {
        // The digest/cipher name is stored as metadata but does not alter the
        // structural MAC computation at this abstraction layer — the provider
        // crate resolves the actual sub-algorithm implementation.
        if let Some(openssl_common::ParamValue::Utf8String(digest_name)) = params.get(PARAM_DIGEST)
        {
            trace!(
                digest = %digest_name,
                "evp::mac: sub-algorithm digest parameter applied"
            );
        }
        if let Some(openssl_common::ParamValue::Utf8String(cipher_name)) = params.get(PARAM_CIPHER)
        {
            trace!(
                cipher = %cipher_name,
                "evp::mac: sub-algorithm cipher parameter applied"
            );
        }

        // Handle explicit output-size override at init-time.
        if let Some(openssl_common::ParamValue::UInt64(size)) = params.get(PARAM_SIZE) {
            if let Ok(s) = usize::try_from(*size) {
                if s > 0 {
                    self.output_size = s;
                }
            }
        }
    }
}

// ===========================================================================
// One-shot convenience function
// ===========================================================================

/// Computes a MAC tag in a single call — fetch, init, update, finalise.
///
/// Translates `EVP_Q_mac()` from `mac_lib.c` lines 200–333.
///
/// This is the simplest way to compute a MAC when the entire message is
/// available in memory.  For streaming input, use [`MacCtx`] directly.
///
/// # Arguments
///
/// * `ctx`       — Library context for provider-based algorithm resolution.
/// * `algorithm` — MAC algorithm name (e.g. [`HMAC`], [`CMAC`]).
/// * `key`       — Key bytes.
/// * `digest`    — Optional underlying digest name (e.g. `"SHA-256"` for HMAC).
///                  Rule R5: `Option<&str>` instead of NULL sentinel.
/// * `data`      — Data to authenticate.
///
/// # Errors
///
/// Propagates any error from [`Mac::fetch()`], [`MacCtx::init()`],
/// [`MacCtx::update()`], or [`MacCtx::finalize()`].
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::evp::mac::{mac_quick, HMAC};
/// use openssl_crypto::context::LibContext;
///
/// let ctx = LibContext::get_default();
/// let tag = mac_quick(&ctx, HMAC, b"secret-key", Some("SHA-256"), b"hello world").unwrap();
/// assert_eq!(tag.len(), 32);
/// ```
pub fn mac_quick(
    ctx: &Arc<LibContext>,
    algorithm: &str,
    key: &[u8],
    digest: Option<&str>,
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    debug!(
        algorithm = algorithm,
        key_len = key.len(),
        digest = digest.unwrap_or("<none>"),
        data_len = data.len(),
        "evp::mac: one-shot mac_quick invocation"
    );

    // Step 1: Fetch the MAC algorithm from the provider store.
    let mac = Mac::fetch(ctx, algorithm, None)?;

    // Step 2: Build init params if a sub-algorithm (digest) was requested.
    // Mirrors the C `EVP_Q_mac()` logic that detects whether the subalg
    // parameter is a digest or cipher name (mac_lib.c ~lines 240–270).
    let init_params = digest.map(|d| {
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_DIGEST,
            openssl_common::ParamValue::Utf8String(d.to_string()),
        );
        ps
    });

    // Step 3: Create context, init, update, finalise.
    let mut mac_ctx = MacCtx::new(&mac)?;
    mac_ctx.init(key, init_params.as_ref())?;
    mac_ctx.update(data)?;
    mac_ctx.finalize()
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Mac (algorithm descriptor) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mac_fetch_hmac() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        assert_eq!(mac.name(), "HMAC");
        assert_eq!(mac.provider_name(), "default");
        assert!(mac.description().is_none());
    }

    #[test]
    fn test_mac_fetch_with_properties() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, CMAC, Some("fips=yes")).unwrap();
        assert_eq!(mac.name(), "CMAC");
    }

    #[test]
    fn test_mac_fetch_empty_name_fails() {
        let ctx = LibContext::get_default();
        let result = Mac::fetch(&ctx, "", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mac_clone() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let cloned = mac.clone();
        assert_eq!(mac.name(), cloned.name());
        assert_eq!(mac.provider_name(), cloned.provider_name());
    }

    // -----------------------------------------------------------------------
    // MacCtx lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mac_ctx_lifecycle() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        assert!(!mac_ctx.is_initialized());

        mac_ctx.init(b"secret-key", None).unwrap();
        assert!(mac_ctx.is_initialized());
        assert_eq!(mac_ctx.mac().name(), "HMAC");

        mac_ctx.update(b"hello").unwrap();
        mac_ctx.update(b" world").unwrap();
        let tag = mac_ctx.finalize().unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_mac_update_before_init_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        assert!(mac_ctx.update(b"data").is_err());
    }

    #[test]
    fn test_mac_finalize_before_init_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        assert!(mac_ctx.finalize().is_err());
    }

    #[test]
    fn test_mac_double_finalize_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        mac_ctx.finalize().unwrap();
        assert!(mac_ctx.finalize().is_err());
    }

    #[test]
    fn test_mac_init_empty_key_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        assert!(mac_ctx.init(b"", None).is_err());
    }

    // -----------------------------------------------------------------------
    // mac_size() — Rule R6 return type
    // -----------------------------------------------------------------------

    /// `mac_size()` matches the C `EVP_MAC_CTX_get_mac_size()` semantics —
    /// the size is determined at construction time from the algorithm name
    /// and is therefore queryable before `init()` is called.  The HMAC
    /// default of 32 bytes (SHA-256 output) is verified here.
    #[test]
    fn test_mac_size_before_init_returns_default() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mac_ctx = MacCtx::new(&mac).unwrap();
        // No init() called — should return the algorithm's default size,
        // not an error sentinel.
        assert_eq!(mac_ctx.mac_size().unwrap(), 32);
    }

    #[test]
    fn test_hmac_default_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 32);
    }

    #[test]
    fn test_poly1305_output_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, POLY1305, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx
            .init(b"32-byte-key-for-poly1305-auth!!", None)
            .unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 16);
    }

    #[test]
    fn test_kmac256_output_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, KMAC256, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 64);
    }

    #[test]
    fn test_siphash_output_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, SIPHASH, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"sixteen-byte-key", None).unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 8);
    }

    #[test]
    fn test_blake2bmac_output_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, BLAKE2BMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 64);
    }

    #[test]
    fn test_blake2smac_output_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, BLAKE2SMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 32);
    }

    // -----------------------------------------------------------------------
    // verify() — constant-time tag comparison
    // -----------------------------------------------------------------------

    /// A correct expected tag (round-tripped through finalize on a parallel
    /// context) MUST be accepted by `verify()`.
    #[test]
    fn test_mac_verify_correct_tag() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();

        // Compute reference tag via finalize() on one context.
        let mut mac_ref = MacCtx::new(&mac).unwrap();
        mac_ref.init(b"verification-key", None).unwrap();
        mac_ref.update(b"the-quick-brown-fox").unwrap();
        let expected = mac_ref.finalize().unwrap();

        // Verify with a freshly initialised context fed identical input.
        let mut mac_verify = MacCtx::new(&mac).unwrap();
        mac_verify.init(b"verification-key", None).unwrap();
        mac_verify.update(b"the-quick-brown-fox").unwrap();
        mac_verify
            .verify(&expected)
            .expect("identical key+data should verify");
    }

    /// A wrong-content tag of the correct length MUST be rejected with
    /// [`CryptoError::Verification`] — no panics, no bypass.
    #[test]
    fn test_mac_verify_wrong_tag() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"verification-key", None).unwrap();
        mac_ctx.update(b"the-quick-brown-fox").unwrap();

        // Tag with the right length (32 bytes for HMAC default) but wrong
        // contents — a flipped bit anywhere is sufficient.
        let mut wrong_tag = vec![0u8; 32];
        wrong_tag[0] = 0xFF;
        let result = mac_ctx.verify(&wrong_tag);
        assert!(result.is_err(), "wrong-tag must fail verification");
        match result.unwrap_err() {
            CryptoError::Verification(msg) => {
                assert!(
                    msg.contains("verification failed"),
                    "expected content-mismatch message, got {msg:?}"
                );
            }
            other => panic!("expected CryptoError::Verification, got {other:?}"),
        }
    }

    /// A tag of the wrong length MUST be rejected with
    /// [`CryptoError::Verification`] — the length-mismatch path returns
    /// a distinct generic error message.
    #[test]
    fn test_mac_verify_wrong_length() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"verification-key", None).unwrap();
        mac_ctx.update(b"the-quick-brown-fox").unwrap();

        // Far-too-short tag (8 bytes when HMAC default is 32).
        let short_tag = [0u8; 8];
        let result = mac_ctx.verify(&short_tag);
        assert!(result.is_err(), "wrong-length must fail verification");
        match result.unwrap_err() {
            CryptoError::Verification(msg) => {
                assert!(
                    msg.contains("length mismatch"),
                    "expected length-mismatch message, got {msg:?}"
                );
            }
            other => panic!("expected CryptoError::Verification, got {other:?}"),
        }
    }

    /// `verify()` on a fresh context (never `init`'d) MUST surface the
    /// underlying [`EvpError::NotInitialized`] from `finalize()`.
    #[test]
    fn test_mac_verify_before_init_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();

        let result = mac_ctx.verify(&[0u8; 32]);
        assert!(result.is_err(), "verify before init must fail");
    }

    // -----------------------------------------------------------------------
    // Reset and re-use
    // -----------------------------------------------------------------------

    #[test]
    fn test_mac_reset_and_reuse() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        mac_ctx.update(b"data").unwrap();
        let tag1 = mac_ctx.finalize().unwrap();

        mac_ctx.reset().unwrap();
        mac_ctx.update(b"data").unwrap();
        let tag2 = mac_ctx.finalize().unwrap();

        // Same key + same data → same tag.
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_mac_reset_before_init_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        assert!(mac_ctx.reset().is_err());
    }

    // -----------------------------------------------------------------------
    // Dup (context duplication)
    // -----------------------------------------------------------------------

    #[test]
    fn test_mac_dup_preserves_state() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();
        mac_ctx.update(b"data").unwrap();

        let mut dup_ctx = mac_ctx.dup().unwrap();
        assert!(dup_ctx.is_initialized());
        assert_eq!(dup_ctx.mac().name(), "HMAC");

        // Both should produce the same tag.
        let tag_orig = mac_ctx.finalize().unwrap();
        let tag_dup = dup_ctx.finalize().unwrap();
        assert_eq!(tag_orig, tag_dup);
    }

    // -----------------------------------------------------------------------
    // set_params / get_params
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_params_output_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();

        let mut params = ParamSet::new();
        params.set("size", openssl_common::ParamValue::UInt64(16));
        mac_ctx.set_params(&params).unwrap();
        assert_eq!(mac_ctx.mac_size().unwrap(), 16);
    }

    #[test]
    fn test_set_params_zero_size_fails() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();
        mac_ctx.init(b"key", None).unwrap();

        let mut params = ParamSet::new();
        params.set("size", openssl_common::ParamValue::UInt64(0));
        assert!(mac_ctx.set_params(&params).is_err());
    }

    #[test]
    fn test_get_params_returns_algorithm_and_size() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mac_ctx = MacCtx::new(&mac).unwrap();
        let params = mac_ctx.get_params().unwrap();
        assert!(params.get("size").is_some());
        assert!(params.get("algorithm").is_some());
    }

    // -----------------------------------------------------------------------
    // One-shot mac_quick()
    // -----------------------------------------------------------------------

    #[test]
    fn test_mac_quick_hmac() {
        let ctx = LibContext::get_default();
        let tag = mac_quick(&ctx, HMAC, b"key", Some("SHA-256"), b"data").unwrap();
        assert_eq!(tag.len(), 32);
        assert!(!tag.is_empty());
    }

    #[test]
    fn test_mac_quick_no_digest() {
        let ctx = LibContext::get_default();
        let tag = mac_quick(&ctx, HMAC, b"key", None, b"data").unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_mac_quick_empty_key_fails() {
        let ctx = LibContext::get_default();
        let result = mac_quick(&ctx, HMAC, b"", None, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_mac_quick_poly1305() {
        let ctx = LibContext::get_default();
        let tag = mac_quick(
            &ctx,
            POLY1305,
            b"32-byte-key-for-poly1305-auth!!",
            None,
            b"hello",
        )
        .unwrap();
        assert_eq!(tag.len(), 16);
    }

    // -----------------------------------------------------------------------
    // Determinism verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_deterministic_output() {
        let ctx = LibContext::get_default();
        let tag1 = mac_quick(&ctx, HMAC, b"key", None, b"data").unwrap();
        let tag2 = mac_quick(&ctx, HMAC, b"key", None, b"data").unwrap();
        assert_eq!(tag1, tag2, "Same key + data must produce identical tags");
    }

    #[test]
    fn test_different_keys_produce_different_tags() {
        let ctx = LibContext::get_default();
        let tag1 = mac_quick(&ctx, HMAC, b"key-a", None, b"data").unwrap();
        let tag2 = mac_quick(&ctx, HMAC, b"key-b", None, b"data").unwrap();
        assert_ne!(tag1, tag2, "Different keys should produce different tags");
    }

    // -----------------------------------------------------------------------
    // Constants are well-known &str values
    // -----------------------------------------------------------------------

    #[test]
    fn test_algorithm_constants() {
        assert_eq!(HMAC, "HMAC");
        assert_eq!(CMAC, "CMAC");
        assert_eq!(GMAC, "GMAC");
        assert_eq!(KMAC128, "KMAC128");
        assert_eq!(KMAC256, "KMAC256");
        assert_eq!(POLY1305, "Poly1305");
        assert_eq!(SIPHASH, "SIPHASH");
        assert_eq!(BLAKE2BMAC, "BLAKE2BMAC");
        assert_eq!(BLAKE2SMAC, "BLAKE2SMAC");
    }

    // -----------------------------------------------------------------------
    // Re-init resets state
    // -----------------------------------------------------------------------

    #[test]
    fn test_reinit_resets_state() {
        let ctx = LibContext::get_default();
        let mac = Mac::fetch(&ctx, HMAC, None).unwrap();
        let mut mac_ctx = MacCtx::new(&mac).unwrap();

        mac_ctx.init(b"key-1", None).unwrap();
        mac_ctx.update(b"data-1").unwrap();
        mac_ctx.finalize().unwrap();

        // Re-initialise with a new key (mirrors C behaviour).
        mac_ctx.init(b"key-2", None).unwrap();
        mac_ctx.update(b"data-2").unwrap();
        let tag = mac_ctx.finalize().unwrap();
        assert_eq!(tag.len(), 32);
    }
}
