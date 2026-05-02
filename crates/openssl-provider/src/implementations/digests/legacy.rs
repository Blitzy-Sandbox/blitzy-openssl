//! # Legacy Message Digest Providers (MD2, MD4, MDC-2, Whirlpool)
//!
//! Translation of four legacy digest provider C source files into idiomatic
//! Rust. The provider-level wrappers in this module forward to the real
//! cryptographic implementations in
//! [`openssl_crypto::hash::legacy`] — that is, the actual hash compression
//! rounds run inside the crypto-layer
//! [`Md2Context`](openssl_crypto::hash::legacy::Md2Context),
//! [`Md4Context`](openssl_crypto::hash::legacy::Md4Context),
//! [`Mdc2Context`](openssl_crypto::hash::legacy::Mdc2Context), and
//! [`WhirlpoolContext`](openssl_crypto::hash::legacy::WhirlpoolContext)
//! types defined in `crates/openssl-crypto/src/hash/legacy.rs`.
//!
//! ## Algorithms exposed
//!
//! | Algorithm   | Block size | Digest size | Settable params      | Source / Reference                    |
//! |-------------|-----------:|------------:|----------------------|---------------------------------------|
//! | `MD2`       |  16 bytes  |  16 bytes   | (none)               | RFC 1319; `md2_prov.c`                |
//! | `MD4`       |  64 bytes  |  16 bytes   | (none)               | RFC 1320; `md4_prov.c`                |
//! | `MDC2`      |   8 bytes  |  16 bytes   | `pad` (UInt32, 1 or 2)| ISO/IEC 10118-2; `mdc2_prov.c`        |
//! | `WHIRLPOOL` |  64 bytes  |  64 bytes   | (none)               | ISO/IEC 10118-3; `wp_prov.c`          |
//!
//! **MDC-2 block size note:** The MDC-2 block size is **8 bytes**, not 16
//! and not 64. This is the DES block size used by the underlying
//! Meyer-Schilling double-DES compression. The C constant `MDC2_BLOCK` in
//! `include/openssl/mdc2.h` is `8`, and the auto-generated dispatch table
//! in `mdc2_prov.c` uses `MDC2_BLOCK` (= 8) for its block-size parameter.
//! The 16-byte value is the *digest* output (concatenation of the two
//! 8-byte chaining variables `h` and `hh`).
//!
//! ## Wiring path (Rule R10)
//!
//! ```text
//! openssl_provider::LegacyProvider::query_operation(Operation::Digest)
//!     -> openssl_provider::implementations::digests::create_legacy_provider(name)
//!         -> Box::new(legacy::Md2Provider)            // exported below
//!             -> DigestProvider::new_ctx()
//!                 -> Box::new(Md2Context { inner: CryptoMd2Context::new(), ... })
//!                     -> DigestContext::{init, update, finalize, ...}
//!                         -> CryptoDigest::{update, finalize, reset, ...}
//!                             -> md2_block() in crates/openssl-crypto
//! ```
//!
//! The same chain applies for `MD4` via [`Md4Provider`], `MDC2` via
//! [`Mdc2Provider`], and `WHIRLPOOL` via [`WhirlpoolProvider`].
//!
//! ## Property string
//!
//! All four algorithms are advertised with the property `"provider=legacy"`
//! (not `"provider=default"`) so they are selectable only when the caller
//! explicitly requests the legacy provider — matching the upstream C
//! behaviour where these algorithms live in the legacy provider, not the
//! default provider.
//!
//! ## Security notice
//!
//! **All four algorithms are deprecated.** MD2, MD4, MDC-2, and Whirlpool
//! all have known cryptanalytic weaknesses or are simply outdated. They
//! exist exclusively for backward compatibility with legacy data formats
//! (PKCS#7-MD2 signatures, NTLM, ISO 10118-2 timestamps, NESSIE-era hash
//! commitments). Production callers should select SHA-256 or SHA-3
//! instead. To make this clear at the call site, each underlying
//! `CryptoXxxContext::new()` constructor is marked `#[deprecated]`; we
//! suppress the resulting compiler warnings via `#[allow(deprecated)]`
//! only at the precise call sites that *must* invoke them, never at
//! module or crate scope.
//!
//! ## Safety (Rule R8)
//!
//! This module contains **zero** `unsafe` blocks. All hashing, parameter
//! handling, and dispatch logic is implemented in safe Rust.
//!
//! ## Replaces
//!
//! - `providers/implementations/digests/md2_prov.c`
//! - `providers/implementations/digests/md4_prov.c`
//! - `providers/implementations/digests/mdc2_prov.c`
//! - `providers/implementations/digests/wp_prov.c`

use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::hash::legacy::{
    Md2Context as CryptoMd2Context, Md4Context as CryptoMd4Context,
    Mdc2Context as CryptoMdc2Context, WhirlpoolContext as CryptoWhirlpoolContext,
};
use openssl_crypto::hash::sha::Digest as CryptoDigest;

// ===========================================================================
// Constants
// ===========================================================================

/// MD2 block size, in bytes (RFC 1319 §3.1).
const MD2_BLOCK_SIZE: usize = 16;

/// MD2 digest length, in bytes (128-bit output, RFC 1319 §3.5).
const MD2_DIGEST_SIZE: usize = 16;

/// MD4 block size, in bytes (RFC 1320 §3.4 — `MD4_CBLOCK`).
const MD4_BLOCK_SIZE: usize = 64;

/// MD4 digest length, in bytes (128-bit output, RFC 1320 §3.5).
const MD4_DIGEST_SIZE: usize = 16;

/// MDC-2 block size, in bytes.
///
/// The MDC-2 compression operates on the 8-byte DES block. The C macro
/// `MDC2_BLOCK` in `include/openssl/mdc2.h` is `8`, and the C provider
/// dispatch table in `mdc2_prov.c` uses this value verbatim.
///
/// **This is _not_ 16 — that is the *digest* size, not the block size.**
const MDC2_BLOCK_SIZE: usize = 8;

/// MDC-2 digest length, in bytes (128-bit output: 8-byte `h` || 8-byte `hh`).
///
/// Matches `MDC2_DIGEST_LENGTH` in `include/openssl/mdc2.h`.
const MDC2_DIGEST_SIZE: usize = 16;

/// Whirlpool block size, in bytes.
///
/// Matches `WHIRLPOOL_BBLOCK / 8 = 512 / 8 = 64` from `include/openssl/whrlpool.h`.
const WHIRLPOOL_BLOCK_SIZE: usize = 64;

/// Whirlpool digest length, in bytes (512-bit output, ISO/IEC 10118-3).
const WHIRLPOOL_DIGEST_SIZE: usize = 64;

/// Default MDC-2 padding mode — zero-pad the residual partial block.
///
/// The C source initialises `MDC2_CTX::pad_type = 1` in `MDC2_Init`
/// (`crypto/mdc2/mdc2dgst.c:39`). Pad type `2` (append `0x80` and zero-pad)
/// is also defined but rarely used. The underlying `CryptoMdc2Context`
/// supports only pad type 1; the wrapper still accepts and stores any
/// `u32` value the caller sets, faithfully mirroring the C contract that
/// `OSSL_PARAM_get_uint(p.pad, &ctx->pad_type)` simply *stores* the value.
const MDC2_DEFAULT_PAD_TYPE: u32 = 1;

// --- Parameter keys --------------------------------------------------------

/// `OSSL_DIGEST_PARAM_BLOCK_SIZE` parameter key (workspace convention).
///
/// The C constant is the literal `"blocksize"`; the workspace uses the
/// snake-case spelling `"block_size"` for consistency with `param.rs`,
/// `md5.rs`, and the other digest providers.
const PARAM_KEY_BLOCK_SIZE: &str = "block_size";

/// `OSSL_DIGEST_PARAM_SIZE` parameter key (workspace convention).
///
/// The C constant is the literal `"size"`; we use `"digest_size"`.
const PARAM_KEY_DIGEST_SIZE: &str = "digest_size";

/// `OSSL_DIGEST_PARAM_PAD_TYPE` parameter key for MDC-2.
///
/// The C constant is the literal `"pad"` (see `include/openssl/core_names.h`,
/// `OSSL_DIGEST_PARAM_PAD_TYPE`). MDC-2's `mdc2_set_ctx_params()` extracts
/// this value via `OSSL_PARAM_get_uint(p.pad, &ctx->pad_type)`.
const PARAM_KEY_PAD: &str = "pad";

// ===========================================================================
// Md2Provider
// ===========================================================================

/// Provider entry for the `MD2` message digest (RFC 1319).
///
/// `Md2Provider` is a zero-sized unit struct; instances are conceptually
/// indistinguishable. The dispatcher in
/// `crate::implementations::digests::create_legacy_provider` constructs
/// new instances directly via `Box::new(Md2Provider)`.
///
/// # C mapping
///
/// Replaces the `ossl_md2_functions` `OSSL_DISPATCH` table generated by
/// the `IMPLEMENT_digest_functions(md2, MD2_CTX, MD2_BLOCK,
/// MD2_DIGEST_LENGTH, 0, MD2_Init, MD2_Update, MD2_Final)` macro in
/// `md2_prov.c`.
///
/// # Security
///
/// MD2 is cryptographically broken (collision attacks are practical). Use
/// only for compatibility with legacy `RSA-MD2` PKCS signatures and
/// historic file formats. See module-level documentation.
#[derive(Debug, Clone, Copy)]
pub struct Md2Provider;

impl Default for Md2Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md2Provider {
    fn name(&self) -> &'static str {
        "MD2"
    }

    fn block_size(&self) -> usize {
        MD2_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MD2_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Md2Context::new()))
    }
}

// ---------------------------------------------------------------------------
// Md2Context — provider-level wrapper around CryptoMd2Context
// ---------------------------------------------------------------------------

/// Provider-level MD2 digest context.
///
/// Wraps the cryptographic [`CryptoMd2Context`] from the `openssl-crypto`
/// crate and tracks a `finalized` flag so misuse (double-finalize,
/// update-after-finalize) is reported as a [`ProviderError::Dispatch`]
/// rather than panicking or silently producing wrong output.
///
/// `Md2Context` is a private type; the provider system observes it only
/// through the [`DigestContext`] trait object returned by
/// [`Md2Provider::new_ctx`].
#[derive(Clone)]
struct Md2Context {
    /// The actual MD2 hash state — performs the real RFC 1319 compression.
    inner: CryptoMd2Context,
    /// Tracks whether `finalize()` has been called; once set, all further
    /// `update`/`finalize` calls return [`ProviderError::Dispatch`].
    finalized: bool,
}

impl core::fmt::Debug for Md2Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Elide the internal hash state — the working buffer can hold
        // partial plaintext that callers may not want appearing in logs.
        f.debug_struct("Md2Context")
            .field("inner", &"<CryptoMd2Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Md2Context {
    /// Construct a fresh MD2 context initialised to RFC 1319 IV constants.
    ///
    /// `CryptoMd2Context::new()` is `#[deprecated]` because MD2 is broken;
    /// this is the *one place* in the provider where invoking it is correct
    /// — the deprecation lint is suppressed exactly here.
    #[inline]
    #[allow(deprecated)] // MD2 is broken but required for legacy compat.
    fn new() -> Self {
        Self {
            inner: CryptoMd2Context::new(),
            finalized: false,
        }
    }

    /// Convert a crypto-layer error into a provider-layer
    /// [`ProviderError::Dispatch`] so the call-site can return a
    /// `ProviderResult` directly via `?`.
    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("MD2 crypto operation failed: {err:?}"))
    }
}

impl DigestContext for Md2Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        // Fully reset the underlying MD2 state and clear the finalized flag.
        // MD2 has no init-time parameters in the C dispatch (`md2_prov.c`
        // does not register `gettable_ctx_params`/`settable_ctx_params`),
        // so we ignore any caller-supplied params here — matching the C
        // behaviour of the auto-generated `md2_init` thunk.
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD2 context already finalized".to_string(),
            ));
        }
        // Empty updates are explicitly a no-op; matches the C behaviour
        // (`MD2_Update(ctx, NULL, 0)` is a documented no-op).
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD2 context already finalized".to_string(),
            ));
        }
        // Mark finalized BEFORE the call, so a panic-or-error inside
        // finalize still leaves the context in a defensible state.
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        // Crypto-layer contract: MD2 output is exactly 16 bytes.
        debug_assert_eq!(
            out.len(),
            MD2_DIGEST_SIZE,
            "MD2 finalization must produce exactly {MD2_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        // CryptoMd2Context derives Clone (and ZeroizeOnDrop); Self : Clone
        // is therefore the simplest correct duplication.
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Report the algorithm metadata exposed by the C provider's
        // `gettable_params` table: block size and digest size.
        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY_BLOCK_SIZE,
            ParamValue::UInt64(MD2_BLOCK_SIZE as u64),
        );
        params.set(
            PARAM_KEY_DIGEST_SIZE,
            ParamValue::UInt64(MD2_DIGEST_SIZE as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // MD2 has *no* settable context parameters. The C `md2_prov.c`
        // does not register a `settable_ctx_params` callback, so the
        // semantically-correct behaviour for an empty input is a no-op
        // and any non-empty input is an error.
        if params.is_empty() {
            return Ok(());
        }
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "MD2 context rejected unknown parameters: {unknown:?}"
        )))
    }
}

// ===========================================================================
// Md4Provider
// ===========================================================================

/// Provider entry for the `MD4` message digest (RFC 1320).
///
/// `Md4Provider` is a zero-sized unit struct.
///
/// # C mapping
///
/// Replaces the `ossl_md4_functions` `OSSL_DISPATCH` table generated by
/// the `IMPLEMENT_digest_functions(md4, MD4_CTX, MD4_CBLOCK,
/// MD4_DIGEST_LENGTH, 0, MD4_Init, MD4_Update, MD4_Final)` macro in
/// `md4_prov.c`.
///
/// # Security
///
/// MD4 is cryptographically broken (collisions can be produced by hand).
/// Used here only for compatibility with NTLM, S/Key, and rsync's
/// historic block hash. See module-level documentation.
#[derive(Debug, Clone, Copy)]
pub struct Md4Provider;

impl Default for Md4Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md4Provider {
    fn name(&self) -> &'static str {
        "MD4"
    }

    fn block_size(&self) -> usize {
        MD4_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MD4_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Md4Context::new()))
    }
}

// ---------------------------------------------------------------------------
// Md4Context — provider-level wrapper around CryptoMd4Context
// ---------------------------------------------------------------------------

/// Provider-level MD4 digest context.
///
/// Wraps the cryptographic [`CryptoMd4Context`] and tracks finalization.
#[derive(Clone)]
struct Md4Context {
    /// The underlying MD4 hash state — performs the real RFC 1320 rounds.
    inner: CryptoMd4Context,
    /// Tracks whether `finalize()` has been called.
    finalized: bool,
}

impl core::fmt::Debug for Md4Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Elide the internal hash state to avoid leaking buffered plaintext.
        f.debug_struct("Md4Context")
            .field("inner", &"<CryptoMd4Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Md4Context {
    #[inline]
    #[allow(deprecated)] // MD4 is broken but required for legacy compat.
    fn new() -> Self {
        Self {
            inner: CryptoMd4Context::new(),
            finalized: false,
        }
    }

    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("MD4 crypto operation failed: {err:?}"))
    }
}

impl DigestContext for Md4Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD4 context already finalized".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD4 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        debug_assert_eq!(
            out.len(),
            MD4_DIGEST_SIZE,
            "MD4 finalization must produce exactly {MD4_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY_BLOCK_SIZE,
            ParamValue::UInt64(MD4_BLOCK_SIZE as u64),
        );
        params.set(
            PARAM_KEY_DIGEST_SIZE,
            ParamValue::UInt64(MD4_DIGEST_SIZE as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // MD4 has no settable context parameters in the C provider.
        if params.is_empty() {
            return Ok(());
        }
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "MD4 context rejected unknown parameters: {unknown:?}"
        )))
    }
}

// ===========================================================================
// Mdc2Provider
// ===========================================================================

/// Provider entry for the `MDC2` (Modification Detection Code 2) digest
/// (ISO/IEC 10118-2).
///
/// MDC-2 is a Meyer-Schilling double-DES hash. Block size is **8 bytes**
/// (the DES block size); the digest is 16 bytes (the concatenation of two
/// 8-byte chaining variables `h` and `hh`).
///
/// Unlike the other three legacy digests, MDC-2 has one settable context
/// parameter, `pad`, controlling the final-block padding mode (1 or 2).
///
/// # C mapping
///
/// Replaces the `ossl_mdc2_functions` `OSSL_DISPATCH` table generated by
/// the `IMPLEMENT_digest_functions_with_settable_ctx(mdc2, MDC2_CTX,
/// MDC2_BLOCK, MDC2_DIGEST_LENGTH, 0, MDC2_Init, MDC2_Update, MDC2_Final,
/// mdc2_settable_ctx_params, mdc2_set_ctx_params)` macro in `mdc2_prov.c`.
///
/// # Security
///
/// MDC-2 was deprecated decades ago. Use only for ISO 10118-2 compliance.
#[derive(Debug, Clone, Copy)]
pub struct Mdc2Provider;

impl Default for Mdc2Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Mdc2Provider {
    fn name(&self) -> &'static str {
        "MDC2"
    }

    fn block_size(&self) -> usize {
        MDC2_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MDC2_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Mdc2Context::new()))
    }
}

// ---------------------------------------------------------------------------
// Mdc2Context — provider-level wrapper around CryptoMdc2Context
// ---------------------------------------------------------------------------

/// Provider-level MDC-2 digest context, with settable padding mode.
///
/// Wraps [`CryptoMdc2Context`] from `openssl-crypto::hash::legacy`,
/// tracks finalization, and stores the caller-set `pad_type` value
/// from the `pad` parameter.
///
/// # `pad_type` semantics
///
/// The C `MDC2_CTX::pad_type` field (defined in `include/openssl/mdc2.h`)
/// is a `u32` initialised to `1` by `MDC2_Init` (`crypto/mdc2/mdc2dgst.c:39`)
/// and consumed by `MDC2_Final` (`mdc2dgst.c:117-131`):
///
/// - `pad_type == 1` (the default): zero-pad any partial trailing block.
/// - `pad_type == 2`: prepend a `0x80` byte then zero-pad — even when the
///   message length is an exact multiple of the block size.
///
/// The underlying [`CryptoMdc2Context::finalize`](
/// openssl_crypto::hash::legacy::Mdc2Context) currently implements only
/// pad type 1 (the OpenSSL default). The wrapper still stores any
/// caller-supplied value via `set_params`, faithfully mirroring the C
/// contract `OSSL_PARAM_get_uint(p.pad, &ctx->pad_type)` — which simply
/// stores the value into the context — but pad type 2 has no observable
/// effect on the digest output. This is a known parity gap with upstream
/// OpenSSL and is documented in the `FEATURE_PARITY.md` artefact.
#[derive(Clone)]
struct Mdc2Context {
    /// The underlying MDC-2 hash state — performs the real DES rounds.
    inner: CryptoMdc2Context,
    /// Tracks whether `finalize()` has been called.
    finalized: bool,
    /// MDC-2 padding mode (`1` = zero-pad residual; `2` = always pad with
    /// `0x80`-prefix). Initialised to `1` to match `MDC2_Init`.
    ///
    /// Stored verbatim per the AAP contract; the underlying crypto layer
    /// presently consumes only pad type 1.
    pad_type: u32,
}

impl core::fmt::Debug for Mdc2Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Elide the internal hash state; expose pad_type for diagnostics.
        f.debug_struct("Mdc2Context")
            .field("inner", &"<CryptoMdc2Context>")
            .field("finalized", &self.finalized)
            .field("pad_type", &self.pad_type)
            .finish()
    }
}

impl Mdc2Context {
    #[inline]
    #[allow(deprecated)] // MDC-2 is deprecated but required for legacy compat.
    fn new() -> Self {
        Self {
            inner: CryptoMdc2Context::new(),
            finalized: false,
            pad_type: MDC2_DEFAULT_PAD_TYPE,
        }
    }

    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("MDC2 crypto operation failed: {err:?}"))
    }
}

impl DigestContext for Mdc2Context {
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()> {
        self.inner.reset();
        self.finalized = false;
        // Reinstate the documented default; an immediately-following
        // `set_params` (which the dispatcher delivers if the caller
        // supplied an `OSSL_PARAM[]`) will override.
        self.pad_type = MDC2_DEFAULT_PAD_TYPE;
        if let Some(p) = params {
            self.set_params(p)?;
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MDC2 context already finalized".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MDC2 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        debug_assert_eq!(
            out.len(),
            MDC2_DIGEST_SIZE,
            "MDC2 finalization must produce exactly {MDC2_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Report block size, digest size, and the *current* padding mode
        // — analogous to the C `mdc2_get_ctx_params()` table that the
        // upstream provider does not actually expose, so we expose a
        // strict superset for diagnosability.
        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY_BLOCK_SIZE,
            ParamValue::UInt64(MDC2_BLOCK_SIZE as u64),
        );
        params.set(
            PARAM_KEY_DIGEST_SIZE,
            ParamValue::UInt64(MDC2_DIGEST_SIZE as u64),
        );
        params.set(PARAM_KEY_PAD, ParamValue::UInt32(self.pad_type));
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Empty input is a no-op — matches the C `mdc2_set_ctx_params`
        // behaviour where an empty `OSSL_PARAM[]` array is accepted.
        if params.is_empty() {
            return Ok(());
        }

        // Extract `pad` if present. Translates the C statement
        //
        //     if (p.pad != NULL && !OSSL_PARAM_get_uint(p.pad, &ctx->pad_type))
        //         { ERR_raise(...); return 0; }
        //
        // — i.e. presence is optional, but type mismatch is fatal.
        if let Some(value) = params.get(PARAM_KEY_PAD) {
            let pad = value.as_u32().ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "MDC2 parameter '{}' must be a UInt32, got {}",
                    PARAM_KEY_PAD,
                    value.param_type_name()
                ))
            })?;
            self.pad_type = pad;
        }

        // Strict-mode rejection of unknown keys: the C provider's
        // settable-ctx-params table advertises only `pad`, so any other
        // key is a programming error. (Rule R5: surface mismatches
        // explicitly rather than silently dropping them.)
        let unknown: Vec<&str> = params.keys().filter(|k| *k != PARAM_KEY_PAD).collect();
        if !unknown.is_empty() {
            return Err(ProviderError::Dispatch(format!(
                "MDC2 context rejected unknown parameters: {unknown:?}"
            )));
        }
        Ok(())
    }
}

// ===========================================================================
// WhirlpoolProvider
// ===========================================================================

/// Provider entry for the `WHIRLPOOL` 512-bit message digest
/// (ISO/IEC 10118-3, NESSIE final design).
///
/// `WhirlpoolProvider` is a zero-sized unit struct.
///
/// # C mapping
///
/// Replaces the `ossl_wp_functions` `OSSL_DISPATCH` table generated by
/// the `IMPLEMENT_digest_functions(wp, WHIRLPOOL_CTX, WHIRLPOOL_BBLOCK / 8,
/// WHIRLPOOL_DIGEST_LENGTH, 0, WHIRLPOOL_Init, WHIRLPOOL_Update,
/// WHIRLPOOL_Final)` macro in `wp_prov.c`.
///
/// # Security
///
/// Whirlpool has no published practical attacks at the time of writing
/// but is rarely deployed; SHA-512 or SHA3-512 are universally preferred.
#[derive(Debug, Clone, Copy)]
pub struct WhirlpoolProvider;

impl Default for WhirlpoolProvider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for WhirlpoolProvider {
    fn name(&self) -> &'static str {
        "WHIRLPOOL"
    }

    fn block_size(&self) -> usize {
        WHIRLPOOL_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        WHIRLPOOL_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(WhirlpoolContext::new()))
    }
}

// ---------------------------------------------------------------------------
// WhirlpoolContext — provider-level wrapper around CryptoWhirlpoolContext
// ---------------------------------------------------------------------------

/// Provider-level Whirlpool digest context.
///
/// Wraps [`CryptoWhirlpoolContext`] and tracks finalization.
#[derive(Clone)]
struct WhirlpoolContext {
    /// The underlying Whirlpool hash state (ISO/IEC 10118-3 rounds).
    inner: CryptoWhirlpoolContext,
    /// Tracks whether `finalize()` has been called.
    finalized: bool,
}

impl core::fmt::Debug for WhirlpoolContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WhirlpoolContext")
            .field("inner", &"<CryptoWhirlpoolContext>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl WhirlpoolContext {
    #[inline]
    #[allow(deprecated)] // Whirlpool is legacy but supported for compat.
    fn new() -> Self {
        Self {
            inner: CryptoWhirlpoolContext::new(),
            finalized: false,
        }
    }

    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("WHIRLPOOL crypto operation failed: {err:?}"))
    }
}

impl DigestContext for WhirlpoolContext {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "WHIRLPOOL context already finalized".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "WHIRLPOOL context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        debug_assert_eq!(
            out.len(),
            WHIRLPOOL_DIGEST_SIZE,
            "WHIRLPOOL finalization must produce exactly {WHIRLPOOL_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY_BLOCK_SIZE,
            ParamValue::UInt64(WHIRLPOOL_BLOCK_SIZE as u64),
        );
        params.set(
            PARAM_KEY_DIGEST_SIZE,
            ParamValue::UInt64(WHIRLPOOL_DIGEST_SIZE as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Whirlpool has no settable context parameters in the C provider.
        if params.is_empty() {
            return Ok(());
        }
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "WHIRLPOOL context rejected unknown parameters: {unknown:?}"
        )))
    }
}

// ===========================================================================
// Algorithm descriptors (registration table for `LegacyProvider`)
// ===========================================================================

/// Returns the algorithm descriptors that the legacy provider should
/// register for these four digests.
///
/// All four advertise `property = "provider=legacy"`, mirroring the C
/// `OSSL_ALGORITHM` array in
/// `providers/legacyprov.c::ossl_legacy_digest_algs[]`. Each entry's
/// alternate names include the dotted-OID form for compatibility with
/// callers that look up algorithms by OID string (e.g.
/// `OBJ_obj2txt`-derived requests).
///
/// # Returned algorithms
///
/// | Provider    | Names                                  | Description                                                    |
/// |-------------|----------------------------------------|----------------------------------------------------------------|
/// | `MD2`       | `MD2`, `1.2.840.113549.2.2`            | RFC 1319 message digest (128-bit) — DEPRECATED                 |
/// | `MD4`       | `MD4`, `1.2.840.113549.2.4`            | RFC 1320 message digest (128-bit) — DEPRECATED                 |
/// | `MDC2`      | `MDC2`, `2.5.8.3.101`                  | ISO/IEC 10118-2 Modification Detection Code 2 — DEPRECATED     |
/// | `WHIRLPOOL` | `WHIRLPOOL`, `1.0.10118.3.0.55`        | ISO/IEC 10118-3 Whirlpool 512-bit digest — DEPRECATED          |
///
/// The names mirror the OID strings registered in
/// `crypto/objects/objects.txt` for each algorithm.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["MD2", "1.2.840.113549.2.2"],
            property: "provider=legacy",
            description: "MD2 message digest (RFC 1319, 128-bit output) [DEPRECATED]",
        },
        AlgorithmDescriptor {
            names: vec!["MD4", "1.2.840.113549.2.4"],
            property: "provider=legacy",
            description: "MD4 message digest (RFC 1320, 128-bit output) [DEPRECATED]",
        },
        AlgorithmDescriptor {
            names: vec!["MDC2", "2.5.8.3.101"],
            property: "provider=legacy",
            description: "MDC2 message digest (ISO/IEC 10118-2, 128-bit output) [DEPRECATED]",
        },
        AlgorithmDescriptor {
            names: vec!["WHIRLPOOL", "1.0.10118.3.0.55"],
            property: "provider=legacy",
            description: "Whirlpool message digest (ISO/IEC 10118-3, 512-bit output) [DEPRECATED]",
        },
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Decode a string of ASCII hex digits into a `Vec<u8>`. The input must
    /// have an even number of hex characters; uppercase or lowercase is fine.
    /// This helper is used to compare KAT vectors against `finalize` output.
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string length must be even");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = match bytes[i] {
                b'0'..=b'9' => bytes[i] - b'0',
                b'a'..=b'f' => bytes[i] - b'a' + 10,
                b'A'..=b'F' => bytes[i] - b'A' + 10,
                c => panic!("invalid hex digit {c:?}"),
            };
            let lo = match bytes[i + 1] {
                b'0'..=b'9' => bytes[i + 1] - b'0',
                b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
                b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
                c => panic!("invalid hex digit {c:?}"),
            };
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    /// Single-shot helper: instantiate a fresh context from `provider`,
    /// init, update with `data`, finalize, and return the digest bytes.
    fn one_shot(provider: &dyn DigestProvider, data: &[u8]) -> Vec<u8> {
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        ctx.update(data).expect("update");
        ctx.finalize().expect("finalize")
    }

    // -----------------------------------------------------------------------
    // MD2 — RFC 1319 Appendix A.5 KATs
    // -----------------------------------------------------------------------

    #[test]
    fn test_md2_provider_metadata() {
        let p = Md2Provider;
        assert_eq!(p.name(), "MD2");
        assert_eq!(p.block_size(), 16);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_md2_kat_empty() {
        let digest = one_shot(&Md2Provider, b"");
        assert_eq!(digest, hex_decode("8350e5a3e24c153df2275c9f80692773"));
    }

    #[test]
    fn test_md2_kat_a() {
        let digest = one_shot(&Md2Provider, b"a");
        assert_eq!(digest, hex_decode("32ec01ec4a6dac72c0ab96fb34c0b5d1"));
    }

    #[test]
    fn test_md2_kat_abc() {
        let digest = one_shot(&Md2Provider, b"abc");
        assert_eq!(digest, hex_decode("da853b0d3f88d99b30283a69e6ded6bb"));
    }

    #[test]
    fn test_md2_kat_message_digest() {
        let digest = one_shot(&Md2Provider, b"message digest");
        assert_eq!(digest, hex_decode("ab4f496bfb2a530b219ff33031fe06b0"));
    }

    #[test]
    fn test_md2_kat_alphabet() {
        let digest = one_shot(&Md2Provider, b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(digest, hex_decode("4e8ddff3650292ab5a4108c3aa47940b"));
    }

    #[test]
    fn test_md2_double_finalize_rejected() {
        let mut ctx = Md2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        let err = ctx.finalize().unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(
                msg.contains("already finalized"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn test_md2_update_after_finalize_rejected() {
        let mut ctx = Md2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let _ = ctx.finalize().unwrap();
        let err = ctx.update(b"x").unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("already finalized")),
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn test_md2_init_after_finalize_resets() {
        let mut ctx = Md2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        // Re-init must clear `finalized` and reset state — the second
        // hash should match the empty-input KAT.
        ctx.init(None).unwrap();
        let again = ctx.finalize().unwrap();
        assert_eq!(again, hex_decode("8350e5a3e24c153df2275c9f80692773"));
    }

    #[test]
    fn test_md2_streaming_matches_one_shot() {
        let one = one_shot(&Md2Provider, b"abcdefghijklmnopqrstuvwxyz");
        let mut ctx = Md2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        for chunk in [
            b"abc".as_ref(),
            b"defghi".as_ref(),
            b"jklmnopqrstuvwxyz".as_ref(),
        ] {
            ctx.update(chunk).unwrap();
        }
        let streamed = ctx.finalize().unwrap();
        assert_eq!(streamed, one);
    }

    #[test]
    fn test_md2_empty_update_is_noop() {
        // An empty update must not advance the hash state; the final
        // digest must still match the empty-input KAT.
        let mut ctx = Md2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"").unwrap();
        ctx.update(b"").unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(digest, hex_decode("8350e5a3e24c153df2275c9f80692773"));
    }

    #[test]
    fn test_md2_duplicate_diverges() {
        let mut a = Md2Provider.new_ctx().unwrap();
        a.init(None).unwrap();
        a.update(b"ab").unwrap();
        let mut b = a.duplicate().unwrap();
        a.update(b"c").unwrap();
        b.update(b"d").unwrap();
        let digest_a = a.finalize().unwrap();
        let digest_b = b.finalize().unwrap();
        // "abc"
        assert_eq!(digest_a, hex_decode("da853b0d3f88d99b30283a69e6ded6bb"));
        // "abd" — different input, must be a different digest
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn test_md2_get_params() {
        let ctx = Md2Provider.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_KEY_BLOCK_SIZE).and_then(|v| v.as_u64()),
            Some(MD2_BLOCK_SIZE as u64)
        );
        assert_eq!(
            params.get(PARAM_KEY_DIGEST_SIZE).and_then(|v| v.as_u64()),
            Some(MD2_DIGEST_SIZE as u64)
        );
    }

    #[test]
    fn test_md2_set_params_empty_is_ok() {
        let mut ctx = Md2Provider.new_ctx().unwrap();
        ctx.set_params(&ParamSet::new()).unwrap();
    }

    #[test]
    fn test_md2_set_params_unknown_rejected() {
        let mut ctx = Md2Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set("nonexistent_key", ParamValue::UInt32(42));
        assert!(ctx.set_params(&ps).is_err());
    }

    // -----------------------------------------------------------------------
    // MD4 — RFC 1320 Appendix A.5 KATs
    // -----------------------------------------------------------------------

    #[test]
    fn test_md4_provider_metadata() {
        let p = Md4Provider;
        assert_eq!(p.name(), "MD4");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_md4_kat_empty() {
        let digest = one_shot(&Md4Provider, b"");
        assert_eq!(digest, hex_decode("31d6cfe0d16ae931b73c59d7e0c089c0"));
    }

    #[test]
    fn test_md4_kat_a() {
        let digest = one_shot(&Md4Provider, b"a");
        assert_eq!(digest, hex_decode("bde52cb31de33e46245e05fbdbd6fb24"));
    }

    #[test]
    fn test_md4_kat_abc() {
        let digest = one_shot(&Md4Provider, b"abc");
        assert_eq!(digest, hex_decode("a448017aaf21d8525fc10ae87aa6729d"));
    }

    #[test]
    fn test_md4_kat_message_digest() {
        let digest = one_shot(&Md4Provider, b"message digest");
        assert_eq!(digest, hex_decode("d9130a8164549fe818874806e1c7014b"));
    }

    #[test]
    fn test_md4_kat_alphabet() {
        let digest = one_shot(&Md4Provider, b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(digest, hex_decode("d79e1c308aa5bbcdeea8ed63df412da9"));
    }

    #[test]
    fn test_md4_streaming_matches_one_shot() {
        // Three-block input: 64 + 64 + 64 bytes, exercises full-block path.
        let data: Vec<u8> = (0u8..=191).collect();
        let one = one_shot(&Md4Provider, &data);
        let mut ctx = Md4Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(&data[..50]).unwrap();
        ctx.update(&data[50..130]).unwrap();
        ctx.update(&data[130..]).unwrap();
        let streamed = ctx.finalize().unwrap();
        assert_eq!(streamed, one);
    }

    #[test]
    fn test_md4_double_finalize_rejected() {
        let mut ctx = Md4Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let _ = ctx.finalize().unwrap();
        assert!(ctx.finalize().is_err());
    }

    #[test]
    fn test_md4_duplicate_independent() {
        let mut a = Md4Provider.new_ctx().unwrap();
        a.init(None).unwrap();
        a.update(b"abc").unwrap();
        let b = a.duplicate().unwrap();
        let digest_a = a.finalize().unwrap();
        let mut b = b;
        let digest_b = b.finalize().unwrap();
        assert_eq!(digest_a, digest_b);
        assert_eq!(digest_a, hex_decode("a448017aaf21d8525fc10ae87aa6729d"));
    }

    #[test]
    fn test_md4_get_params() {
        let ctx = Md4Provider.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_KEY_BLOCK_SIZE).and_then(|v| v.as_u64()),
            Some(MD4_BLOCK_SIZE as u64)
        );
        assert_eq!(
            params.get(PARAM_KEY_DIGEST_SIZE).and_then(|v| v.as_u64()),
            Some(MD4_DIGEST_SIZE as u64)
        );
    }

    #[test]
    fn test_md4_set_params_unknown_rejected() {
        let mut ctx = Md4Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set("pad", ParamValue::UInt32(2));
        // MD4 does not accept any settable params — `pad` is not its.
        assert!(ctx.set_params(&ps).is_err());
    }

    // -----------------------------------------------------------------------
    // MDC-2 — historic OpenSSL-fixtures-derived KAT
    // -----------------------------------------------------------------------

    #[test]
    fn test_mdc2_sizes() {
        let p = Mdc2Provider;
        assert_eq!(p.name(), "MDC2");
        // MDC-2 block size is 8 (the DES block size). Not 16, not 64.
        assert_eq!(p.block_size(), 8);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_mdc2_kat_now_is_the_time() {
        // From OpenSSL `test/recipes/30-test_evp_data/evpmd_mdc2.txt`
        // and `crypto/mdc2/mdc2test.c`. Input length = 24 bytes.
        let input = b"Now is the time for all ";
        assert_eq!(input.len(), 24);
        let digest = one_shot(&Mdc2Provider, input);
        assert_eq!(digest, hex_decode("42e50cd224baceba760bdd2bd409281a"));
    }

    #[test]
    fn test_mdc2_streaming_matches_one_shot() {
        let input = b"Now is the time for all ";
        let one = one_shot(&Mdc2Provider, input);
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(&input[..7]).unwrap();
        ctx.update(&input[7..15]).unwrap();
        ctx.update(&input[15..]).unwrap();
        let streamed = ctx.finalize().unwrap();
        assert_eq!(streamed, one);
    }

    #[test]
    fn test_mdc2_duplicate_diverges() {
        let mut a = Mdc2Provider.new_ctx().unwrap();
        a.init(None).unwrap();
        a.update(b"Now is the time for ").unwrap();
        let mut b = a.duplicate().unwrap();
        a.update(b"all ").unwrap();
        b.update(b"some").unwrap();
        let da = a.finalize().unwrap();
        let db = b.finalize().unwrap();
        assert_eq!(da, hex_decode("42e50cd224baceba760bdd2bd409281a"));
        assert_ne!(da, db);
    }

    #[test]
    fn test_mdc2_default_pad_type_is_one() {
        let ctx = Mdc2Provider.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_KEY_PAD).and_then(|v| v.as_u32()),
            Some(MDC2_DEFAULT_PAD_TYPE)
        );
    }

    #[test]
    fn test_mdc2_set_pad_type_stored() {
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY_PAD, ParamValue::UInt32(2));
        ctx.set_params(&ps).unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_KEY_PAD).and_then(|v| v.as_u32()),
            Some(2),
            "pad_type must round-trip via get_params"
        );
    }

    #[test]
    fn test_mdc2_set_pad_type_via_init() {
        // Init may carry an `OSSL_PARAM[]`; ensure init honours `pad`.
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY_PAD, ParamValue::UInt32(2));
        ctx.init(Some(&ps)).unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(params.get(PARAM_KEY_PAD).and_then(|v| v.as_u32()), Some(2));
    }

    #[test]
    fn test_mdc2_init_resets_pad_type_to_default() {
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY_PAD, ParamValue::UInt32(2));
        ctx.set_params(&ps).unwrap();
        // Re-init with no params must restore the default pad type.
        ctx.init(None).unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_KEY_PAD).and_then(|v| v.as_u32()),
            Some(MDC2_DEFAULT_PAD_TYPE)
        );
    }

    #[test]
    fn test_mdc2_set_pad_type_wrong_type_rejected() {
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY_PAD, ParamValue::OctetString(vec![1]));
        let err = ctx.set_params(&ps).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("pad"), "unexpected message: {msg}");
                assert!(
                    msg.contains("UInt32"),
                    "expected type-mismatch message, got: {msg}"
                );
            }
            other => panic!("expected Dispatch error, got {other:?}"),
        }
    }

    #[test]
    fn test_mdc2_set_unknown_param_rejected() {
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set("nonexistent_key", ParamValue::UInt32(0));
        assert!(ctx.set_params(&ps).is_err());
    }

    #[test]
    fn test_mdc2_double_finalize_rejected() {
        let mut ctx = Mdc2Provider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        assert!(ctx.finalize().is_err());
    }

    // -----------------------------------------------------------------------
    // Whirlpool — NESSIE / ISO 10118-3 KATs
    // -----------------------------------------------------------------------

    #[test]
    fn test_whirlpool_provider_metadata() {
        let p = WhirlpoolProvider;
        assert_eq!(p.name(), "WHIRLPOOL");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 64);
    }

    #[test]
    fn test_whirlpool_kat_empty() {
        let digest = one_shot(&WhirlpoolProvider, b"");
        let expected = hex_decode(
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
             3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
        );
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_whirlpool_kat_a() {
        let digest = one_shot(&WhirlpoolProvider, b"a");
        let expected = hex_decode(
            "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42\
             d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
        );
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_whirlpool_kat_abc() {
        let digest = one_shot(&WhirlpoolProvider, b"abc");
        let expected = hex_decode(
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
             7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
        );
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_whirlpool_kat_message_digest() {
        let digest = one_shot(&WhirlpoolProvider, b"message digest");
        let expected = hex_decode(
            "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b\
             8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e",
        );
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_whirlpool_streaming_matches_one_shot() {
        // Two-block input (128 bytes), exercises the block boundary path.
        let data: Vec<u8> = (0u8..128).collect();
        let one = one_shot(&WhirlpoolProvider, &data);
        let mut ctx = WhirlpoolProvider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(&data[..30]).unwrap();
        ctx.update(&data[30..90]).unwrap();
        ctx.update(&data[90..]).unwrap();
        let streamed = ctx.finalize().unwrap();
        assert_eq!(streamed, one);
    }

    #[test]
    fn test_whirlpool_double_finalize_rejected() {
        let mut ctx = WhirlpoolProvider.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let _ = ctx.finalize().unwrap();
        assert!(ctx.finalize().is_err());
    }

    #[test]
    fn test_whirlpool_get_params() {
        let ctx = WhirlpoolProvider.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert_eq!(
            params.get(PARAM_KEY_BLOCK_SIZE).and_then(|v| v.as_u64()),
            Some(WHIRLPOOL_BLOCK_SIZE as u64)
        );
        assert_eq!(
            params.get(PARAM_KEY_DIGEST_SIZE).and_then(|v| v.as_u64()),
            Some(WHIRLPOOL_DIGEST_SIZE as u64)
        );
    }

    #[test]
    fn test_whirlpool_set_params_unknown_rejected() {
        let mut ctx = WhirlpoolProvider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set("pad", ParamValue::UInt32(1));
        assert!(ctx.set_params(&ps).is_err());
    }

    // -----------------------------------------------------------------------
    // Provider-trait surface — descriptors / Default / Debug
    // -----------------------------------------------------------------------

    #[test]
    fn test_descriptors_completeness() {
        let descs = descriptors();
        assert_eq!(descs.len(), 4);
        let names: Vec<&str> = descs.iter().map(|d| d.names[0]).collect();
        assert!(names.contains(&"MD2"));
        assert!(names.contains(&"MD4"));
        assert!(names.contains(&"MDC2"));
        assert!(names.contains(&"WHIRLPOOL"));
        for d in &descs {
            assert_eq!(
                d.property, "provider=legacy",
                "all four legacy digests must advertise provider=legacy"
            );
            assert!(
                d.description.contains("DEPRECATED"),
                "all legacy digests should be marked DEPRECATED in their description"
            );
        }
    }

    #[test]
    fn test_descriptors_oid_aliases_present() {
        let descs = descriptors();
        let md2 = descs.iter().find(|d| d.names[0] == "MD2").unwrap();
        assert!(md2.names.contains(&"1.2.840.113549.2.2"));
        let md4 = descs.iter().find(|d| d.names[0] == "MD4").unwrap();
        assert!(md4.names.contains(&"1.2.840.113549.2.4"));
        let mdc2 = descs.iter().find(|d| d.names[0] == "MDC2").unwrap();
        assert!(mdc2.names.contains(&"2.5.8.3.101"));
        let wp = descs.iter().find(|d| d.names[0] == "WHIRLPOOL").unwrap();
        assert!(wp.names.contains(&"1.0.10118.3.0.55"));
    }

    #[test]
    fn test_default_constructors() {
        // Default impls allow `Md2Provider::default()` etc. to succeed.
        let _md2 = Md2Provider;
        let _md4 = Md4Provider;
        let _mdc2 = Mdc2Provider;
        let _wp = WhirlpoolProvider;
        assert_eq!(Md2Provider.name(), Md2Provider::default().name());
        assert_eq!(Md4Provider.name(), Md4Provider::default().name());
        assert_eq!(Mdc2Provider.name(), Mdc2Provider::default().name());
        assert_eq!(
            WhirlpoolProvider.name(),
            WhirlpoolProvider::default().name()
        );
    }

    #[test]
    fn test_provider_debug_format_does_not_panic() {
        // Ensure the auto-derived `Debug` for unit-struct providers is sound.
        let _ = format!("{:?}", Md2Provider);
        let _ = format!("{:?}", Md4Provider);
        let _ = format!("{:?}", Mdc2Provider);
        let _ = format!("{:?}", WhirlpoolProvider);
    }

    #[test]
    fn test_context_debug_elides_inner_state() {
        // The custom `Debug` impl on each Context must not expose the
        // raw hash state via the `inner` field — verify by formatting.
        // We use the concrete Context types directly (in-crate access)
        // because `Box<dyn DigestContext>` does not implement `Debug`.
        let ctx = Md2Context::new();
        let s = format!("{ctx:?}");
        assert!(s.contains("CryptoMd2Context"));
        let ctx = Md4Context::new();
        let s = format!("{ctx:?}");
        assert!(s.contains("CryptoMd4Context"));
        let ctx = Mdc2Context::new();
        let s = format!("{ctx:?}");
        assert!(s.contains("CryptoMdc2Context"));
        // pad_type is part of the public configuration surface, so it's
        // intentionally exposed in Debug for diagnosability.
        assert!(s.contains("pad_type"));
        let ctx = WhirlpoolContext::new();
        let s = format!("{ctx:?}");
        assert!(s.contains("CryptoWhirlpoolContext"));
    }
}
