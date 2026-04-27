//! # SHA-2 Digest Provider
//!
//! Rust translation of the SHA-2 portion of
//! `providers/implementations/digests/sha2_prov.c`.
//!
//! This module implements the complete **SHA-2 family** of message digest
//! algorithms exposed by the default provider. Each variant delegates its
//! cryptographic core to [`openssl_crypto::hash::sha`], which provides the
//! audited, constant-time implementations of the SHA-256 and SHA-512
//! compression functions and message-length padding.
//!
//! ## Variants
//!
//! The SHA-2 family includes seven distinct algorithms, all sharing two
//! compression-function cores:
//!
//! | Variant       | Block Size | Digest Size | Underlying Core     | FIPS |
//! |---------------|-----------:|------------:|---------------------|:----:|
//! | SHA-224       |     64 B   |     28 B    | SHA-256 core        |  ✔️  |
//! | SHA-256       |     64 B   |     32 B    | SHA-256 core        |  ✔️  |
//! | SHA-256/192   |     64 B   |     24 B    | SHA-256 core (trunc.) |  ✖️  |
//! | SHA-384       |    128 B   |     48 B    | SHA-512 core        |  ✔️  |
//! | SHA-512       |    128 B   |     64 B    | SHA-512 core        |  ✔️  |
//! | SHA-512/224   |    128 B   |     28 B    | SHA-512 core (distinct IV) |  ✔️ |
//! | SHA-512/256   |    128 B   |     32 B    | SHA-512 core (distinct IV) |  ✔️ |
//!
//! `SHA-256/192` is a non-standard truncation of SHA-256 used internally by
//! the TLS 1.3 Encrypted Client Hello (ECH) mechanism. It is **not** FIPS
//! approved and is registered under the `provider=default` property only.
//!
//! ## Architecture
//!
//! Two distinct provider structs mirror the two underlying cores:
//!
//! * `Sha256Provider` — dispatches to SHA-256 core (SHA-224, SHA-256, SHA-256/192)
//! * `Sha512Provider` — dispatches to SHA-512 core (SHA-384, SHA-512, SHA-512/224, SHA-512/256)
//!
//! Each provider holds a `Sha256Variant` or `Sha512Variant` selector and
//! creates fresh hashing contexts via `new_ctx()`. The contexts wrap the
//! corresponding [`openssl_crypto::hash::sha::Sha256Context`] or
//! [`openssl_crypto::hash::sha::Sha512Context`] and implement the provider
//! `DigestContext` trait by delegating to the `Digest`
//! (`openssl_crypto::hash::sha::Digest`) supertrait.
//!
//! ## C Mapping
//!
//! | Rust Item                         | C Origin (`sha2_prov.c`)                       |
//! |-----------------------------------|------------------------------------------------|
//! | `Sha256Provider::new(Sha224)`     | `ossl_sha224_functions[]` dispatch table        |
//! | `Sha256Provider::new(Sha256)`     | `ossl_sha256_functions[]` dispatch table        |
//! | `Sha256Provider::new(Sha256_192)` | `ossl_sha256_192_internal_functions[]` (internal) |
//! | `Sha512Provider::new(Sha384)`     | `ossl_sha384_functions[]` dispatch table        |
//! | `Sha512Provider::new(Sha512)`     | `ossl_sha512_functions[]` dispatch table        |
//! | `Sha512Provider::new(Sha512_224)` | `ossl_sha512_224_functions[]`                   |
//! | `Sha512Provider::new(Sha512_256)` | `ossl_sha512_256_functions[]`                   |
//! | `DigestContext::update()`         | `SHA256_Update_thunk()` / `SHA512_Update_thunk()` |
//! | `DigestContext::finalize()`       | `SHA224_Final()` / `SHA256_Final()` / `SHA384_Final()` / `SHA512_Final()` |
//! | `descriptors()`                   | `IMPLEMENT_digest_functions_with_serialize()` registrations |
//!
//! ## Flags
//!
//! All SHA-2 variants are marked `PROV_DIGEST_FLAG_ALGID_ABSENT` in the
//! C source (`sha2_prov.c` line 31, `#define SHA2_FLAGS`). This indicates
//! the algorithm's ASN.1 `AlgorithmIdentifier` encoding is a bare OID
//! with no `NULL` parameters field, per RFC 5754 §2.1. In the Rust
//! rewrite the flag is expressed at the algorithm-registration level via
//! `descriptors()` rather than as a per-context queryable parameter;
//! sibling digest providers (`sha1.rs`, `sha3.rs`) follow the same
//! convention.
//!
//! ## Rules Enforced
//!
//! * **Rule R5 (Nullability over sentinels):** Context state uses a typed
//!   `Option`-friendly `bool` (`finalized`) rather than signed sentinel
//!   returns. Variant selection is a dedicated enum, not an integer code.
//! * **Rule R6 (Lossless casts):** All size conversions are explicit
//!   `usize` arithmetic with no bare `as` narrowing. Parameter values cast
//!   to `u64` for the provider parameter bag use only widening conversions.
//! * **Rule R8 (Zero `unsafe`):** No `unsafe` blocks appear in this module.
//!   Delegation to `openssl-crypto` relies entirely on the safe
//!   [`Digest`](openssl_crypto::hash::sha::Digest) trait.
//! * **Rule R9 (Warning-free):** Every public item carries a `///` doc
//!   comment; clippy lints are honoured.
//! * **Rule R10 (Wiring):** Reachable via
//!   `DefaultProvider → query_operation(Digest) → Sha256Provider / Sha512Provider`.
//!
//! ## Serialization Format Note
//!
//! The C provider supports byte-exact context serialisation with magic
//! headers `"SHA256v1"` and `"SHA512v1"` so that partially-fed contexts
//! can be exported and re-imported (e.g., across fork boundaries). In the
//! Rust rewrite, this functionality is not part of the public provider
//! surface (no `members_exposed` entry in the provider schema); partial
//! context transfer is instead expressed via the Rust-native
//! `DigestContext::duplicate` operation backed by `Clone`.

use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::hash::sha::{
    Digest as CryptoDigest, Sha256Context as CryptoSha256Context,
    Sha512Context as CryptoSha512Context,
};

// =============================================================================
// SHA-256 Family (64-byte block)
// =============================================================================

/// SHA-256 core block size in bytes (512 bits).
///
/// Shared by all variants of the SHA-256 family: SHA-224, SHA-256, and
/// SHA-256/192. Matches the C constant `SHA256_CBLOCK = 64`.
const SHA256_BLOCK_SIZE: usize = 64;

/// Variant selector for SHA-256–based message digest algorithms.
///
/// The SHA-256 compression function produces 32 bytes of output per
/// invocation. The three variants differ only in their initial hash values
/// (IVs) and the number of output bytes published:
///
/// * [`Sha256Variant::Sha224`] uses the SHA-224 IV and emits 28 bytes.
/// * [`Sha256Variant::Sha256`] uses the canonical SHA-256 IV and emits
///   the full 32 bytes.
/// * [`Sha256Variant::Sha256_192`] uses the SHA-256 IV but truncates the
///   32-byte digest to 24 bytes. This non-standard construction is used
///   by TLS 1.3 Encrypted Client Hello (ECH) and is **not** FIPS approved.
///
/// # C Mapping
///
/// Replaces the per-algorithm init-function distinction encoded via the
/// `IMPLEMENT_digest_functions_with_serialize` macro expansion for each
/// of `sha224`, `sha256`, and `sha256_192_internal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256Variant {
    /// SHA-224: 28-byte (224-bit) output using the SHA-224 IV.
    ///
    /// Defined in FIPS 180-4 §6.3. Produces the same state-update sequence
    /// as SHA-256 but starts from a distinct IV and truncates the final
    /// digest to the leftmost 28 bytes.
    Sha224,
    /// SHA-256: 32-byte (256-bit) output using the canonical SHA-256 IV.
    ///
    /// The reference SHA-256 variant defined in FIPS 180-4 §6.2.
    Sha256,
    /// SHA-256/192: 24-byte (192-bit) output, a non-standard truncation
    /// of SHA-256 used by TLS 1.3 Encrypted Client Hello (ECH).
    ///
    /// **Not FIPS approved.** Implements the same state-update sequence
    /// as SHA-256 and truncates the final digest to the leftmost 24 bytes.
    Sha256_192,
}

impl Sha256Variant {
    /// Returns the digest output size in bytes for this variant.
    ///
    /// This is the number of bytes that `DigestContext::finalize` will
    /// produce for a context initialised for this variant.
    #[inline]
    const fn digest_size(self) -> usize {
        match self {
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha256_192 => 24,
        }
    }

    /// Returns the canonical algorithm name string for this variant.
    ///
    /// Names follow the OpenSSL convention used in provider dispatch
    /// tables and ASN.1 OID registrations (e.g., `"SHA-224"` rather than
    /// the older `"sha224"` form).
    #[inline]
    const fn name(self) -> &'static str {
        match self {
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha256_192 => "SHA-256/192",
        }
    }

    /// Constructs a fresh `CryptoSha256Context` initialised for this variant.
    ///
    /// For [`Sha256Variant::Sha224`], the SHA-224 IV is installed. For the
    /// other two variants, the canonical SHA-256 IV is used; the distinction
    /// between [`Sha256Variant::Sha256`] and [`Sha256Variant::Sha256_192`]
    /// is handled entirely at `DigestContext::finalize` time via
    /// output truncation.
    #[inline]
    fn new_crypto_ctx(self) -> CryptoSha256Context {
        match self {
            Self::Sha224 => CryptoSha256Context::sha224(),
            // Sha256 and Sha256_192 share the SHA-256 IV; they differ only
            // in how many output bytes are retained by `finalize`.
            Self::Sha256 | Self::Sha256_192 => CryptoSha256Context::sha256(),
        }
    }
}

/// SHA-256–based message digest provider.
///
/// Handles the three SHA-256-core variants: SHA-224, SHA-256, and
/// SHA-256/192. The target variant is selected at construction time via
/// [`Sha256Provider::new`] and controls the IV and output truncation of
/// the `DigestContext` returned from [`DigestProvider::new_ctx`].
///
/// # C Mapping
///
/// Replaces the `ossl_sha224_functions`, `ossl_sha256_functions`, and
/// `ossl_sha256_192_internal_functions` dispatch tables declared in
/// `sha2_prov.c` via the `IMPLEMENT_digest_functions_with_serialize`
/// macro.
///
/// # Example
///
/// ```rust,ignore
/// use openssl_provider::implementations::digests::sha2::{Sha256Provider, Sha256Variant};
/// use openssl_provider::traits::DigestProvider;
///
/// let provider = Sha256Provider::new(Sha256Variant::Sha256);
/// let mut ctx = provider.new_ctx().unwrap();
/// ctx.update(b"abc").unwrap();
/// let digest = ctx.finalize().unwrap();
/// assert_eq!(digest.len(), 32);
/// ```
#[derive(Debug, Clone)]
pub struct Sha256Provider {
    /// The selected SHA-256 family variant.
    variant: Sha256Variant,
}

impl Default for Sha256Provider {
    /// Default variant is `SHA-256`.
    ///
    /// Matches the convention of OpenSSL's `EVP_sha256()` being the
    /// canonical SHA-256 family entry point.
    #[inline]
    fn default() -> Self {
        Self {
            variant: Sha256Variant::Sha256,
        }
    }
}

impl Sha256Provider {
    /// Creates a new SHA-256 family digest provider for the specified variant.
    #[inline]
    pub fn new(variant: Sha256Variant) -> Self {
        Self { variant }
    }

    /// Returns the variant this provider dispatches to.
    #[inline]
    #[must_use]
    pub fn variant(&self) -> Sha256Variant {
        self.variant
    }
}

impl DigestProvider for Sha256Provider {
    /// Returns the canonical algorithm name for this provider's variant.
    ///
    /// One of `"SHA-224"`, `"SHA-256"`, or `"SHA-256/192"`.
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    /// Returns the SHA-256 family block size: always 64 bytes.
    fn block_size(&self) -> usize {
        SHA256_BLOCK_SIZE
    }

    /// Returns the variant-specific digest output size in bytes.
    ///
    /// 28 for SHA-224, 32 for SHA-256, 24 for SHA-256/192.
    fn digest_size(&self) -> usize {
        self.variant.digest_size()
    }

    /// Creates a fresh hashing context initialised for this provider's variant.
    ///
    /// The returned context is ready to receive `DigestContext::update`
    /// calls and will produce a digest of [`Self::digest_size`] bytes when
    /// `DigestContext::finalize` is invoked.
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Sha256Context::new(self.variant)))
    }
}

/// SHA-256 family hashing context.
///
/// Wraps a `CryptoSha256Context` from `openssl-crypto` together with
/// variant-aware truncation logic. All cryptographic computation is
/// delegated to the core `CryptoDigest` trait implementation; this type
/// only adds the provider-level state machine (variant selector,
/// finalised flag, output truncation for SHA-256/192).
///
/// `Debug` is implemented manually — the inner crypto context does not
/// implement `Debug` to prevent accidental logging of sensitive hashing
/// state (partial block buffer, chaining variables).
#[derive(Clone)]
struct Sha256Context {
    /// Variant selector: determines IV and output truncation.
    variant: Sha256Variant,
    /// Delegated core context performing the actual SHA-256 compression.
    inner: CryptoSha256Context,
    /// Set to `true` after `DigestContext::finalize` completes; gates
    /// further updates to prevent producing silently-incorrect output.
    finalized: bool,
}

impl core::fmt::Debug for Sha256Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256Context")
            .field("variant", &self.variant)
            .field("inner", &"<CryptoSha256Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Sha256Context {
    /// Constructs a fresh context initialised for the given variant.
    #[inline]
    fn new(variant: Sha256Variant) -> Self {
        Self {
            variant,
            inner: variant.new_crypto_ctx(),
            finalized: false,
        }
    }

    /// Converts a lower-level `CryptoError` from [`openssl-crypto`] into a
    /// `ProviderError::Dispatch` preserving diagnostic detail.
    ///
    /// Provider-layer error surfaces do not expose `CryptoError` directly;
    /// this helper ensures the crate-local error taxonomy is respected
    /// (provider layer speaks `ProviderError`, not [`openssl_common::error::CryptoError`]).
    #[inline]
    fn map_crypto_err(variant: Sha256Variant, err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!(
            "{} crypto operation failed: {:?}",
            variant.name(),
            err
        ))
    }
}

impl DigestContext for Sha256Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        // Reset the inner crypto context to the variant's IV. This is the
        // idiomatic translation of `SHA224_Init` / `SHA256_Init` from the C
        // provider. SHA-2 contexts accept no init-time parameters.
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(format!(
                "{} context already finalized; call init() before further updates",
                self.variant.name()
            )));
        }
        // Zero-length updates are a no-op but remain a valid operation
        // (mirrors `SHA256_Update(c, p, 0)` in C).
        if data.is_empty() {
            return Ok(());
        }
        self.inner
            .update(data)
            .map_err(|e| Self::map_crypto_err(self.variant, e))
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(format!(
                "{} context already finalized",
                self.variant.name()
            )));
        }
        self.finalized = true;
        let mut digest = self
            .inner
            .finalize()
            .map_err(|e| Self::map_crypto_err(self.variant, e))?;

        // SHA-256/192 is SHA-256 truncated to the leftmost 24 bytes. The
        // crypto-level context always produces a 32-byte digest when the
        // SHA-256 IV is installed; provider-level truncation applies here.
        let target_size = self.variant.digest_size();
        if digest.len() > target_size {
            digest.truncate(target_size);
        }
        debug_assert_eq!(
            digest.len(),
            target_size,
            "SHA-256 family digest output size mismatch for {}",
            self.variant.name()
        );
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        // Full deep clone of the inner crypto context preserves all
        // compression-function state (partial block buffer, message length
        // counter, chaining variables). This translates the C
        // `OSSL_FUNC_digest_dupctx` entry.
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Report the two standard per-context digest parameters:
        // `block_size` (compression-function block size in bytes) and
        // `digest_size` (output length of this variant in bytes).
        //
        // The key names `block_size` and `digest_size` match the convention
        // used by the sibling digest providers (`sha1.rs`, `md5.rs`,
        // `sm3.rs`, `ripemd.rs`, `legacy.rs`) and the workspace-wide
        // algorithm-correctness test suite. The analogous C symbols
        // `OSSL_DIGEST_PARAM_BLOCK_SIZE` and `OSSL_DIGEST_PARAM_SIZE` use
        // the strings `"blocksize"` and `"size"`; the Rust workspace
        // standardises on the Rust-idiomatic underscored variants for
        // parameter introspection. See also Rule R5 (typed `ParamValue`
        // replaces OSSL_PARAM's type-erased pointer encoding).
        //
        // Note: `PROV_DIGEST_FLAG_ALGID_ABSENT` (see `sha2_prov.c` line 31)
        // describes the algorithm's ASN.1 `AlgorithmIdentifier` encoding
        // rather than per-context state, so it is surfaced through the
        // `AlgorithmDescriptor` registration path rather than here —
        // matching `sha1.rs`'s `get_params` implementation.
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(SHA256_BLOCK_SIZE as u64));
        params.set(
            "digest_size",
            ParamValue::UInt64(self.variant.digest_size() as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // SHA-2 contexts have no settable parameters (unlike SHA-1 which
        // accepts `SSL3_MS` for the legacy SSLv3 MAC). An empty `ParamSet`
        // is a no-op; any unexpected parameters are diagnosed.
        if params.is_empty() {
            return Ok(());
        }
        // Enumerate rejected keys for diagnostic richness (matches C
        // behaviour of silently ignoring unknown params but logs them here).
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "{} context has no settable parameters; rejected: {:?}",
            self.variant.name(),
            unknown
        )))
    }
}

// =============================================================================
// SHA-512 Family (128-byte block)
// =============================================================================

/// SHA-512 core block size in bytes (1024 bits).
///
/// Shared by all variants of the SHA-512 family: SHA-384, SHA-512,
/// SHA-512/224, and SHA-512/256. Matches the C constant
/// `SHA512_CBLOCK = 128`.
const SHA512_BLOCK_SIZE: usize = 128;

/// Variant selector for SHA-512–based message digest algorithms.
///
/// The SHA-512 compression function produces 64 bytes of output per
/// invocation. Unlike the SHA-256 family, each SHA-512 variant has its
/// own dedicated IV defined in FIPS 180-4 §5.3:
///
/// * [`Sha512Variant::Sha384`]: SHA-384 IV, emits 48 bytes
/// * [`Sha512Variant::Sha512`]: canonical SHA-512 IV, emits all 64 bytes
/// * [`Sha512Variant::Sha512_224`]: SHA-512/224 IV (§5.3.6.1), emits 28 bytes
/// * [`Sha512Variant::Sha512_256`]: SHA-512/256 IV (§5.3.6.2), emits 32 bytes
///
/// All four IVs are generated by the FIPS 180-4 §5.3.6 IV-construction
/// procedure ensuring cryptographic independence between the truncated
/// variants and full SHA-512.
///
/// # C Mapping
///
/// Replaces the per-algorithm init-function distinction encoded via the
/// `IMPLEMENT_digest_functions_with_serialize` macro expansion for each
/// of `sha384`, `sha512`, `sha512_224`, and `sha512_256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha512Variant {
    /// SHA-384: 48-byte (384-bit) output using the SHA-384 IV.
    ///
    /// Defined in FIPS 180-4 §6.5.
    Sha384,
    /// SHA-512: 64-byte (512-bit) output using the canonical SHA-512 IV.
    ///
    /// The reference SHA-512 variant defined in FIPS 180-4 §6.4.
    Sha512,
    /// SHA-512/224: 28-byte (224-bit) output using the SHA-512/224 IV.
    ///
    /// Defined in FIPS 180-4 §5.3.6.1 and §6.6.
    Sha512_224,
    /// SHA-512/256: 32-byte (256-bit) output using the SHA-512/256 IV.
    ///
    /// Defined in FIPS 180-4 §5.3.6.2 and §6.7.
    Sha512_256,
}

impl Sha512Variant {
    /// Returns the digest output size in bytes for this variant.
    #[inline]
    const fn digest_size(self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Sha512_224 => 28,
            Self::Sha512_256 => 32,
        }
    }

    /// Returns the canonical algorithm name string for this variant.
    #[inline]
    const fn name(self) -> &'static str {
        match self {
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_224 => "SHA-512/224",
            Self::Sha512_256 => "SHA-512/256",
        }
    }

    /// Constructs a fresh `CryptoSha512Context` initialised for this variant.
    ///
    /// Each variant maps to its own dedicated constructor on the core
    /// context type, installing the appropriate IV per FIPS 180-4 §5.3.
    /// No output truncation is required at the provider layer: the core
    /// context's digest size is already set per variant at construction
    /// time by the underlying implementation.
    #[inline]
    fn new_crypto_ctx(self) -> CryptoSha512Context {
        match self {
            Self::Sha384 => CryptoSha512Context::sha384(),
            Self::Sha512 => CryptoSha512Context::sha512(),
            Self::Sha512_224 => CryptoSha512Context::sha512_224(),
            Self::Sha512_256 => CryptoSha512Context::sha512_256(),
        }
    }
}

/// SHA-512–based message digest provider.
///
/// Handles the four SHA-512-core variants: SHA-384, SHA-512, SHA-512/224,
/// and SHA-512/256. The target variant is selected at construction time
/// via [`Sha512Provider::new`].
///
/// # C Mapping
///
/// Replaces the `ossl_sha384_functions`, `ossl_sha512_functions`,
/// `ossl_sha512_224_functions`, and `ossl_sha512_256_functions` dispatch
/// tables declared in `sha2_prov.c`.
///
/// # Example
///
/// ```rust,ignore
/// use openssl_provider::implementations::digests::sha2::{Sha512Provider, Sha512Variant};
/// use openssl_provider::traits::DigestProvider;
///
/// let provider = Sha512Provider::new(Sha512Variant::Sha512);
/// let mut ctx = provider.new_ctx().unwrap();
/// ctx.update(b"abc").unwrap();
/// let digest = ctx.finalize().unwrap();
/// assert_eq!(digest.len(), 64);
/// ```
#[derive(Debug, Clone)]
pub struct Sha512Provider {
    /// The selected SHA-512 family variant.
    variant: Sha512Variant,
}

impl Default for Sha512Provider {
    /// Default variant is `SHA-512`.
    ///
    /// Matches the convention of OpenSSL's `EVP_sha512()` being the
    /// canonical SHA-512 family entry point.
    #[inline]
    fn default() -> Self {
        Self {
            variant: Sha512Variant::Sha512,
        }
    }
}

impl Sha512Provider {
    /// Creates a new SHA-512 family digest provider for the specified variant.
    #[inline]
    pub fn new(variant: Sha512Variant) -> Self {
        Self { variant }
    }

    /// Returns the variant this provider dispatches to.
    #[inline]
    #[must_use]
    pub fn variant(&self) -> Sha512Variant {
        self.variant
    }
}

impl DigestProvider for Sha512Provider {
    /// Returns the canonical algorithm name for this provider's variant.
    ///
    /// One of `"SHA-384"`, `"SHA-512"`, `"SHA-512/224"`, or `"SHA-512/256"`.
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    /// Returns the SHA-512 family block size: always 128 bytes.
    fn block_size(&self) -> usize {
        SHA512_BLOCK_SIZE
    }

    /// Returns the variant-specific digest output size in bytes.
    fn digest_size(&self) -> usize {
        self.variant.digest_size()
    }

    /// Creates a fresh hashing context initialised for this provider's variant.
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Sha512Context::new(self.variant)))
    }
}

/// SHA-512 family hashing context.
///
/// Wraps a `CryptoSha512Context` from `openssl-crypto` together with
/// the variant selector. Each variant's output size is determined by the
/// underlying crypto context, so (unlike SHA-256/192) no provider-layer
/// truncation is required.
///
/// `Debug` is implemented manually — the inner crypto context does not
/// implement `Debug` to prevent accidental logging of sensitive hashing
/// state.
#[derive(Clone)]
struct Sha512Context {
    /// Variant selector: primarily for diagnostic identification and
    /// error-message formatting.
    variant: Sha512Variant,
    /// Delegated core context performing the actual SHA-512 compression.
    inner: CryptoSha512Context,
    /// Set to `true` after `DigestContext::finalize` completes.
    finalized: bool,
}

impl core::fmt::Debug for Sha512Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha512Context")
            .field("variant", &self.variant)
            .field("inner", &"<CryptoSha512Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Sha512Context {
    /// Constructs a fresh context initialised for the given variant.
    #[inline]
    fn new(variant: Sha512Variant) -> Self {
        Self {
            variant,
            inner: variant.new_crypto_ctx(),
            finalized: false,
        }
    }

    /// Converts a lower-level `CryptoError` into a `ProviderError::Dispatch`.
    #[inline]
    fn map_crypto_err(variant: Sha512Variant, err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!(
            "{} crypto operation failed: {:?}",
            variant.name(),
            err
        ))
    }
}

impl DigestContext for Sha512Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(format!(
                "{} context already finalized; call init() before further updates",
                self.variant.name()
            )));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.inner
            .update(data)
            .map_err(|e| Self::map_crypto_err(self.variant, e))
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(format!(
                "{} context already finalized",
                self.variant.name()
            )));
        }
        self.finalized = true;
        let digest = self
            .inner
            .finalize()
            .map_err(|e| Self::map_crypto_err(self.variant, e))?;
        debug_assert_eq!(
            digest.len(),
            self.variant.digest_size(),
            "SHA-512 family digest output size mismatch for {}",
            self.variant.name()
        );
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Report `block_size` (128 bytes for the SHA-512 family) and
        // `digest_size` (variant-specific: 48 for SHA-384, 64 for
        // SHA-512, 28 for SHA-512/224, 32 for SHA-512/256). See the
        // matching documentation on `Sha256Context::get_params` for the
        // rationale behind the `block_size`/`digest_size` key naming.
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(SHA512_BLOCK_SIZE as u64));
        params.set(
            "digest_size",
            ParamValue::UInt64(self.variant.digest_size() as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // SHA-2 contexts have no settable parameters (unlike SHA-1 which
        // accepts `SSL3_MS` for the legacy SSLv3 MAC). An empty `ParamSet`
        // is a no-op; any unexpected parameters are diagnosed.
        if params.is_empty() {
            return Ok(());
        }
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "{} context has no settable parameters; rejected: {:?}",
            self.variant.name(),
            unknown
        )))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for all SHA-2 family variants exposed
/// by the default provider.
///
/// Produces exactly seven `AlgorithmDescriptor` entries, one per SHA-2
/// algorithm, each listing the canonical name and common aliases used by
/// applications and the OpenSSL name-map:
///
/// 1. `SHA-224`, `SHA224`, `SHA2-224`
/// 2. `SHA-256`, `SHA256`, `SHA2-256`
/// 3. `SHA-256/192`, `SHA256/192`, `SHA2-256/192` (internal, TLS 1.3 ECH)
/// 4. `SHA-384`, `SHA384`, `SHA2-384`
/// 5. `SHA-512`, `SHA512`, `SHA2-512`
/// 6. `SHA-512/224`, `SHA512/224`, `SHA2-512/224`
/// 7. `SHA-512/256`, `SHA512/256`, `SHA2-512/256`
///
/// All descriptors carry the `provider=default` property string, matching
/// the C default-provider registration.
///
/// # C Mapping
///
/// Translates the seven `IMPLEMENT_digest_functions_with_serialize` macro
/// expansions at the tail of `sha2_prov.c` (lines 293–335 of the C source):
/// `sha224`, `sha256`, `sha256_192_internal`, `sha384`, `sha512`,
/// `sha512_224`, `sha512_256`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["SHA-224", "SHA224", "SHA2-224"],
            property: "provider=default",
            description: "SHA-224 message digest (FIPS 180-4, 224-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-256", "SHA256", "SHA2-256"],
            property: "provider=default",
            description: "SHA-256 message digest (FIPS 180-4, 256-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-256/192", "SHA256/192", "SHA2-256/192"],
            property: "provider=default",
            description:
                "SHA-256/192 truncated digest (192-bit output, TLS 1.3 ECH, not FIPS approved)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-384", "SHA384", "SHA2-384"],
            property: "provider=default",
            description: "SHA-384 message digest (FIPS 180-4, 384-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-512", "SHA512", "SHA2-512"],
            property: "provider=default",
            description: "SHA-512 message digest (FIPS 180-4, 512-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-512/224", "SHA512/224", "SHA2-512/224"],
            property: "provider=default",
            description: "SHA-512/224 truncated digest (FIPS 180-4, 224-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-512/256", "SHA512/256", "SHA2-512/256"],
            property: "provider=default",
            description: "SHA-512/256 truncated digest (FIPS 180-4, 256-bit output)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Provider construction / metadata tests
    // -------------------------------------------------------------------------

    #[test]
    fn sha256_provider_default_is_sha256() {
        let p = Sha256Provider::default();
        assert_eq!(p.name(), "SHA-256");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 32);
        assert_eq!(p.variant(), Sha256Variant::Sha256);
    }

    #[test]
    fn sha224_provider_metadata() {
        let p = Sha256Provider::new(Sha256Variant::Sha224);
        assert_eq!(p.name(), "SHA-224");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 28);
    }

    #[test]
    fn sha256_192_provider_metadata() {
        let p = Sha256Provider::new(Sha256Variant::Sha256_192);
        assert_eq!(p.name(), "SHA-256/192");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 24);
    }

    #[test]
    fn sha512_provider_default_is_sha512() {
        let p = Sha512Provider::default();
        assert_eq!(p.name(), "SHA-512");
        assert_eq!(p.block_size(), 128);
        assert_eq!(p.digest_size(), 64);
        assert_eq!(p.variant(), Sha512Variant::Sha512);
    }

    #[test]
    fn sha384_provider_metadata() {
        let p = Sha512Provider::new(Sha512Variant::Sha384);
        assert_eq!(p.name(), "SHA-384");
        assert_eq!(p.block_size(), 128);
        assert_eq!(p.digest_size(), 48);
    }

    #[test]
    fn sha512_224_provider_metadata() {
        let p = Sha512Provider::new(Sha512Variant::Sha512_224);
        assert_eq!(p.name(), "SHA-512/224");
        assert_eq!(p.block_size(), 128);
        assert_eq!(p.digest_size(), 28);
    }

    #[test]
    fn sha512_256_provider_metadata() {
        let p = Sha512Provider::new(Sha512Variant::Sha512_256);
        assert_eq!(p.name(), "SHA-512/256");
        assert_eq!(p.block_size(), 128);
        assert_eq!(p.digest_size(), 32);
    }

    // -------------------------------------------------------------------------
    // Algorithm descriptor tests
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_contains_seven_variants() {
        let descs = descriptors();
        assert_eq!(descs.len(), 7, "Should have exactly 7 SHA-2 descriptors");
    }

    #[test]
    fn descriptors_cover_all_canonical_names() {
        let descs = descriptors();
        let canonical: Vec<&str> = descs.iter().map(|d| d.names[0]).collect();
        assert!(canonical.contains(&"SHA-224"));
        assert!(canonical.contains(&"SHA-256"));
        assert!(canonical.contains(&"SHA-256/192"));
        assert!(canonical.contains(&"SHA-384"));
        assert!(canonical.contains(&"SHA-512"));
        assert!(canonical.contains(&"SHA-512/224"));
        assert!(canonical.contains(&"SHA-512/256"));
    }

    #[test]
    fn descriptors_all_use_default_provider() {
        for desc in descriptors() {
            assert_eq!(desc.property, "provider=default");
        }
    }

    #[test]
    fn descriptors_each_has_at_least_one_name() {
        for desc in descriptors() {
            assert!(
                !desc.names.is_empty(),
                "descriptor {:?} has no names",
                desc.description
            );
        }
    }

    // -------------------------------------------------------------------------
    // Known-answer tests (FIPS 180-4 vectors)
    // -------------------------------------------------------------------------

    /// Converts a lowercase hex string into a byte vector.
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// Runs one empty-input + one three-byte KAT through a freshly created
    /// provider context and returns the resulting digests as lowercase hex.
    fn run_two_kats_256(variant: Sha256Variant, input: &[u8]) -> Vec<u8> {
        let provider = Sha256Provider::new(variant);
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.update(input).expect("update");
        ctx.finalize().expect("finalize")
    }

    fn run_two_kats_512(variant: Sha512Variant, input: &[u8]) -> Vec<u8> {
        let provider = Sha512Provider::new(variant);
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.update(input).expect("update");
        ctx.finalize().expect("finalize")
    }

    #[test]
    fn sha224_kat_empty() {
        // FIPS 180-4 Appendix A.2: SHA-224("")
        let want = hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        let got = run_two_kats_256(Sha256Variant::Sha224, b"");
        assert_eq!(got, want);
    }

    #[test]
    fn sha224_kat_abc() {
        // FIPS 180-4 Appendix A.1: SHA-224("abc")
        let want = hex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
        let got = run_two_kats_256(Sha256Variant::Sha224, b"abc");
        assert_eq!(got, want);
    }

    #[test]
    fn sha256_kat_empty() {
        // SHA-256("")
        let want = hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let got = run_two_kats_256(Sha256Variant::Sha256, b"");
        assert_eq!(got, want);
    }

    #[test]
    fn sha256_kat_abc() {
        // FIPS 180-4 Appendix B.1: SHA-256("abc")
        let want = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let got = run_two_kats_256(Sha256Variant::Sha256, b"abc");
        assert_eq!(got, want);
    }

    #[test]
    fn sha256_192_is_sha256_truncated() {
        // SHA-256/192("abc") is the leftmost 24 bytes of SHA-256("abc").
        let full = run_two_kats_256(Sha256Variant::Sha256, b"abc");
        let truncated = run_two_kats_256(Sha256Variant::Sha256_192, b"abc");
        assert_eq!(truncated.len(), 24);
        assert_eq!(&truncated[..], &full[..24]);
    }

    #[test]
    fn sha384_kat_abc() {
        // FIPS 180-4 Appendix D.1: SHA-384("abc")
        let want = hex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        );
        let got = run_two_kats_512(Sha512Variant::Sha384, b"abc");
        assert_eq!(got, want);
    }

    #[test]
    fn sha512_kat_empty() {
        // SHA-512("")
        let want = hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        let got = run_two_kats_512(Sha512Variant::Sha512, b"");
        assert_eq!(got, want);
    }

    #[test]
    fn sha512_kat_abc() {
        // FIPS 180-4 Appendix C.1: SHA-512("abc")
        let want = hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        let got = run_two_kats_512(Sha512Variant::Sha512, b"abc");
        assert_eq!(got, want);
    }

    #[test]
    fn sha512_224_kat_abc() {
        // FIPS 180-4 Appendix E: SHA-512/224("abc")
        let want = hex("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
        let got = run_two_kats_512(Sha512Variant::Sha512_224, b"abc");
        assert_eq!(got, want);
    }

    #[test]
    fn sha512_256_kat_abc() {
        // FIPS 180-4 Appendix F: SHA-512/256("abc")
        let want = hex("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
        let got = run_two_kats_512(Sha512Variant::Sha512_256, b"abc");
        assert_eq!(got, want);
    }

    // -------------------------------------------------------------------------
    // Context lifecycle behavioural tests
    // -------------------------------------------------------------------------

    #[test]
    fn sha256_context_multi_update_matches_single_update() {
        let mut ctx_a = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx_a.update(b"abc").expect("update");
        let single = ctx_a.finalize().expect("finalize");

        let mut ctx_b = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx_b.update(b"a").expect("update");
        ctx_b.update(b"b").expect("update");
        ctx_b.update(b"c").expect("update");
        let multi = ctx_b.finalize().expect("finalize");

        assert_eq!(single, multi, "multi-update must match single update");
    }

    #[test]
    fn sha512_context_multi_update_matches_single_update() {
        let mut ctx_a = Sha512Provider::default().new_ctx().expect("new_ctx");
        ctx_a.update(b"abc").expect("update");
        let single = ctx_a.finalize().expect("finalize");

        let mut ctx_b = Sha512Provider::default().new_ctx().expect("new_ctx");
        ctx_b.update(b"a").expect("update");
        ctx_b.update(b"b").expect("update");
        ctx_b.update(b"c").expect("update");
        let multi = ctx_b.finalize().expect("finalize");

        assert_eq!(single, multi);
    }

    #[test]
    fn sha256_context_empty_update_is_noop() {
        let mut ctx_a = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx_a.update(b"").expect("empty update");
        ctx_a.update(b"abc").expect("update");
        ctx_a.update(b"").expect("empty update 2");
        let a = ctx_a.finalize().expect("finalize");

        let mut ctx_b = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx_b.update(b"abc").expect("update");
        let b = ctx_b.finalize().expect("finalize");

        assert_eq!(a, b);
    }

    #[test]
    fn sha256_context_finalize_twice_errors() {
        let mut ctx = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx.update(b"abc").expect("update");
        let _ = ctx.finalize().expect("first finalize");
        assert!(ctx.finalize().is_err(), "second finalize must fail");
    }

    #[test]
    fn sha512_context_update_after_finalize_errors() {
        let mut ctx = Sha512Provider::default().new_ctx().expect("new_ctx");
        ctx.update(b"abc").expect("update");
        let _ = ctx.finalize().expect("finalize");
        assert!(
            ctx.update(b"def").is_err(),
            "update after finalize must fail"
        );
    }

    #[test]
    fn sha256_context_init_resets_after_finalize() {
        let mut ctx = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx.update(b"abc").expect("update");
        let first = ctx.finalize().expect("finalize");

        // re-init and feed the same input — must produce the same digest.
        ctx.init(None).expect("reinit");
        ctx.update(b"abc").expect("update-2");
        let second = ctx.finalize().expect("finalize-2");
        assert_eq!(first, second, "init() must fully reset context");
    }

    #[test]
    fn sha256_context_duplicate_produces_same_digest() {
        let mut ctx = Sha256Provider::default().new_ctx().expect("new_ctx");
        ctx.update(b"ab").expect("update-1");

        let mut dup = ctx.duplicate().expect("duplicate");
        ctx.update(b"c").expect("update-2");
        dup.update(b"c").expect("dup-update-2");

        let original = ctx.finalize().expect("finalize original");
        let duplicate = dup.finalize().expect("finalize duplicate");
        assert_eq!(original, duplicate);
    }

    #[test]
    fn sha512_context_duplicate_independence() {
        // Verifies that mutating a duplicate does not affect the original.
        let mut ctx = Sha512Provider::default().new_ctx().expect("new_ctx");
        ctx.update(b"ab").expect("update-1");

        let mut dup = ctx.duplicate().expect("duplicate");
        dup.update(b"XYZ").expect("divergent update");

        ctx.update(b"c").expect("original continues");
        let original = ctx.finalize().expect("finalize original");

        // Fresh reference for SHA-512("abc")
        let want = hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(original, want);
    }

    // -------------------------------------------------------------------------
    // Parameter tests
    // -------------------------------------------------------------------------

    #[test]
    fn sha256_get_params_reports_correct_sizes() {
        let ctx = Sha256Provider::default().new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        // block_size == 64 for SHA-256 family (keys match sibling digest
        // providers: sha1.rs, md5.rs, sm3.rs, ripemd.rs, legacy.rs).
        assert_eq!(
            params.get("block_size").and_then(|v| v.as_u64()),
            Some(64),
            "SHA-256 must advertise block_size=64"
        );
        // digest_size == 32 for SHA-256.
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(32),
            "SHA-256 must advertise digest_size=32"
        );
        // SHA-2 contexts only expose the two standard size parameters;
        // flags such as `algid-absent` live on the `AlgorithmDescriptor`.
        assert!(params.get("blocksize").is_none());
        assert!(params.get("size").is_none());
        assert!(params.get("xof").is_none());
        assert!(params.get("algid-absent").is_none());
    }

    #[test]
    fn sha224_get_params_reports_correct_sizes() {
        let ctx = Sha256Provider::new(Sha256Variant::Sha224)
            .new_ctx()
            .expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(
            params.get("block_size").and_then(|v| v.as_u64()),
            Some(64),
            "SHA-224 shares the SHA-256 block size (64 bytes)"
        );
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(28),
            "SHA-224 must advertise digest_size=28"
        );
    }

    #[test]
    fn sha256_192_get_params_reports_correct_sizes() {
        let ctx = Sha256Provider::new(Sha256Variant::Sha256_192)
            .new_ctx()
            .expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(params.get("block_size").and_then(|v| v.as_u64()), Some(64));
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(24),
            "SHA-256/192 is a 24-byte truncation of SHA-256"
        );
    }

    #[test]
    fn sha384_get_params_reports_correct_sizes() {
        let ctx = Sha512Provider::new(Sha512Variant::Sha384)
            .new_ctx()
            .expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(
            params.get("block_size").and_then(|v| v.as_u64()),
            Some(128),
            "SHA-384 must advertise block_size=128"
        );
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(48),
            "SHA-384 must advertise digest_size=48"
        );
    }

    #[test]
    fn sha512_get_params_reports_correct_sizes() {
        let ctx = Sha512Provider::default().new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(params.get("block_size").and_then(|v| v.as_u64()), Some(128));
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(64),
            "SHA-512 must advertise digest_size=64"
        );
    }

    #[test]
    fn sha512_224_get_params_reports_correct_sizes() {
        let ctx = Sha512Provider::new(Sha512Variant::Sha512_224)
            .new_ctx()
            .expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(params.get("block_size").and_then(|v| v.as_u64()), Some(128));
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(28),
            "SHA-512/224 must advertise digest_size=28"
        );
    }

    #[test]
    fn sha512_256_get_params_reports_correct_sizes() {
        let ctx = Sha512Provider::new(Sha512Variant::Sha512_256)
            .new_ctx()
            .expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        assert_eq!(params.get("block_size").and_then(|v| v.as_u64()), Some(128));
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()),
            Some(32),
            "SHA-512/256 must advertise digest_size=32"
        );
    }

    #[test]
    fn sha256_set_params_empty_is_ok() {
        let mut ctx = Sha256Provider::default().new_ctx().expect("new_ctx");
        let empty = ParamSet::new();
        assert!(ctx.set_params(&empty).is_ok());
    }

    #[test]
    fn sha256_set_params_unknown_is_error() {
        use openssl_common::param::ParamBuilder;
        let mut ctx = Sha256Provider::default().new_ctx().expect("new_ctx");
        let params = ParamBuilder::new().push_u64("nonexistent-param", 0).build();
        assert!(
            ctx.set_params(&params).is_err(),
            "SHA-2 contexts must reject unknown settable params"
        );
    }

    // -------------------------------------------------------------------------
    // Provider trait smoke test — confirms the generic surface
    // -------------------------------------------------------------------------

    #[test]
    fn provider_trait_objects_work() {
        let providers: Vec<Box<dyn DigestProvider>> = vec![
            Box::new(Sha256Provider::new(Sha256Variant::Sha224)),
            Box::new(Sha256Provider::new(Sha256Variant::Sha256)),
            Box::new(Sha256Provider::new(Sha256Variant::Sha256_192)),
            Box::new(Sha512Provider::new(Sha512Variant::Sha384)),
            Box::new(Sha512Provider::new(Sha512Variant::Sha512)),
            Box::new(Sha512Provider::new(Sha512Variant::Sha512_224)),
            Box::new(Sha512Provider::new(Sha512Variant::Sha512_256)),
        ];
        for p in providers {
            let mut ctx = p.new_ctx().expect("new_ctx");
            ctx.update(b"abc").expect("update");
            let digest = ctx.finalize().expect("finalize");
            assert_eq!(
                digest.len(),
                p.digest_size(),
                "{} finalize length must match provider digest_size",
                p.name()
            );
        }
    }

    // -------------------------------------------------------------------------
    // Variant equality / metadata tests
    // -------------------------------------------------------------------------

    #[test]
    fn sha256_variant_names() {
        assert_eq!(Sha256Variant::Sha224.name(), "SHA-224");
        assert_eq!(Sha256Variant::Sha256.name(), "SHA-256");
        assert_eq!(Sha256Variant::Sha256_192.name(), "SHA-256/192");
    }

    #[test]
    fn sha512_variant_names() {
        assert_eq!(Sha512Variant::Sha384.name(), "SHA-384");
        assert_eq!(Sha512Variant::Sha512.name(), "SHA-512");
        assert_eq!(Sha512Variant::Sha512_224.name(), "SHA-512/224");
        assert_eq!(Sha512Variant::Sha512_256.name(), "SHA-512/256");
    }

    #[test]
    fn variant_copy_equal_reflexive() {
        let v = Sha256Variant::Sha256;
        let c = v;
        assert_eq!(v, c);
    }

    /// Ensures the `CryptoDigest` trait re-export is used (Rule R10 wiring).
    /// The [`Sha256Context::init`] implementation calls [`CryptoDigest::reset`]
    /// through the trait; this test verifies the trait is in scope by naming it.
    #[test]
    fn crypto_digest_trait_in_scope() {
        fn is_digest<T: CryptoDigest>(_t: &T) {}
        let c = CryptoSha256Context::sha256();
        is_digest(&c);

        let c2 = CryptoSha512Context::sha512();
        is_digest(&c2);
    }
}
