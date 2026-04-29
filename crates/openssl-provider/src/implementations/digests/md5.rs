//! # MD5 and MD5-SHA1 Composite Digest Providers
//!
//! Translation of `providers/implementations/digests/md5_prov.c` and
//! `providers/implementations/digests/md5_sha1_prov.c` from C into idiomatic
//! Rust. The provider-level wrappers in this module forward to the real
//! cryptographic implementations in [`openssl_crypto::hash::md5`] — that is,
//! the actual hash compression rounds run inside the crypto-layer
//! [`Md5Context`](openssl_crypto::hash::md5::Md5Context) and
//! [`Md5Sha1Context`](openssl_crypto::hash::md5::Md5Sha1Context) types
//! defined in `crates/openssl-crypto/src/hash/md5.rs`.
//!
//! ## Algorithms exposed
//!
//! | Algorithm | Block size | Digest size | Settable params         | Source / Reference                |
//! |-----------|-----------:|------------:|--------------------------|-----------------------------------|
//! | `MD5`     |  64 bytes  |  16 bytes   | (none)                   | RFC 1321; `md5_prov.c`            |
//! | `MD5-SHA1`|  64 bytes  |  36 bytes   | `ssl3-ms` (octet string) | SSLv3 §5.6.3, RFC 6101; `md5_sha1_prov.c` |
//!
//! `MD5-SHA1` is a *composite* digest — it runs MD5 and SHA-1 in lock-step
//! over the same input and concatenates the outputs as `MD5(16) || SHA-1(20)`
//! producing a 36-byte digest. It is used by SSLv3 and TLS 1.0/1.1 handshake
//! signatures and by the SSLv3 master-secret derivation (`PRF`) construction.
//! The `ssl3-ms` parameter (`OSSL_DIGEST_PARAM_SSL3_MS`) lets a TLS
//! implementation install the master secret into the digest context for the
//! SSLv3 PRF; we capture it as `Option<Vec<u8>>` per **Rule R5** (nullability
//! over sentinels) instead of the C-style empty-array sentinel.
//!
//! ## Wiring path (Rule R10)
//!
//! ```text
//! openssl_provider::DefaultProvider::digest_by_name("MD5")
//!     -> openssl_provider::implementations::digests::dispatch_digest_provider("MD5")
//!         -> Box::new(md5::Md5Provider)            // exported below
//!             -> DigestProvider::new_ctx()
//!                 -> Box::new(Md5Context { inner: CryptoMd5Context::new(), ... })
//!                     -> DigestContext::{init, update, finalize, ...}
//!                         -> CryptoDigest::{update, finalize, reset, ...}
//!                             -> md5_compress() in crates/openssl-crypto
//! ```
//!
//! The same chain applies for `MD5-SHA1` via [`Md5Sha1Provider`].
//!
//! ## Security notice
//!
//! **MD5 is cryptographically broken.** Both collision and chosen-prefix
//! attacks against MD5 are practical on commodity hardware. This module
//! exists *exclusively* for backward compatibility with legacy protocols
//! (SSLv3, TLS 1.0, RFC 6101 master-secret derivation) and historic file
//! formats. Production callers should select SHA-256 or SHA-3 instead. To
//! make this clear at the call site, the underlying `CryptoMd5Context::new()`
//! and `CryptoMd5Sha1Context::new()` constructors are marked
//! `#[deprecated]`; we suppress the resulting compiler warnings via
//! `#[allow(deprecated)]` only at the precise call sites that *must* invoke
//! them, never at module or crate scope.
//!
//! ## Safety (Rule R8)
//!
//! This module contains **zero** `unsafe` blocks. All hashing, parameter
//! handling, and dispatch logic is implemented in safe Rust.

use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::hash::md5::{
    Md5Context as CryptoMd5Context, Md5Sha1Context as CryptoMd5Sha1Context,
};
use openssl_crypto::hash::sha::Digest as CryptoDigest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// MD5 block size, in bytes (512-bit compression block, RFC 1321 §3.4).
const MD5_BLOCK_SIZE: usize = 64;

/// MD5 digest length, in bytes (128-bit output, RFC 1321 §3.5).
const MD5_DIGEST_SIZE: usize = 16;

/// SHA-1 digest length, in bytes (160-bit output, FIPS 180-4 §6.1).
const SHA1_DIGEST_SIZE: usize = 20;

/// MD5-SHA1 composite digest block size — both constituent hashes use the
/// same 512-bit block (matches `MD5_CBLOCK` and `SHA_CBLOCK` in the source C).
const MD5_SHA1_BLOCK_SIZE: usize = 64;

/// MD5-SHA1 composite digest length: `MD5(16) || SHA-1(20) = 36` bytes.
/// Matches `MD5_SHA1_DIGEST_LENGTH` from `crypto/md5/md5_sha1.c`.
const MD5_SHA1_DIGEST_SIZE: usize = MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE;

/// `OSSL_DIGEST_PARAM_BLOCK_SIZE` parameter key (Rust-idiomatic spelling).
///
/// The C constant is the literal string `"blocksize"`; the workspace-wide
/// Rust convention chosen for this codebase is `"block_size"` (matching
/// the snake-case naming used elsewhere in `crates/openssl-common/src/param.rs`
/// and the other digest provider wrappers — `sha1`, `sha2`, `sha3`).
const PARAM_KEY_BLOCK_SIZE: &str = "block_size";

/// `OSSL_DIGEST_PARAM_SIZE` parameter key (Rust-idiomatic spelling).
///
/// The C constant is the literal string `"size"`; we use `"digest_size"` for
/// clarity and consistency with the other digest providers.
const PARAM_KEY_DIGEST_SIZE: &str = "digest_size";

/// `OSSL_DIGEST_PARAM_SSL3_MS` parameter key — the `SSLv3` master secret that a
/// TLS implementation installs on the digest context to drive the `SSLv3` PRF
/// `MAC`/`HASH` computation. Matches the literal C string `"ssl3-ms"` (see
/// `include/openssl/core_names.h`, `OSSL_DIGEST_PARAM_SSL3_MS`).
const PARAM_KEY_SSL3_MS: &str = "ssl3-ms";

// ===========================================================================
// Md5Provider
// ===========================================================================

/// Provider entry for the `MD5` message digest (RFC 1321).
///
/// `Md5Provider` is a zero-sized unit struct; instances are conceptually
/// indistinguishable. The dispatcher in
/// `crate::implementations::digests::dispatch_digest_provider` constructs new
/// instances directly via `Box::new(Md5Provider)`.
///
/// # C mapping
///
/// Replaces the `ossl_md5_functions` `OSSL_DISPATCH` table generated by the
/// `IMPLEMENT_digest_functions(md5, MD5_CTX, ...)` macro in `md5_prov.c`.
///
/// # Security
///
/// MD5 is cryptographically broken. Use only for compatibility with legacy
/// protocols and file formats. See module-level documentation.
#[derive(Debug, Clone, Copy)]
pub struct Md5Provider;

impl Default for Md5Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md5Provider {
    fn name(&self) -> &'static str {
        "MD5"
    }

    fn block_size(&self) -> usize {
        MD5_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MD5_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Md5Context::new()))
    }
}

// ---------------------------------------------------------------------------
// Md5Context — provider-level wrapper around CryptoMd5Context
// ---------------------------------------------------------------------------

/// Provider-level MD5 digest context.
///
/// Wraps the cryptographic [`CryptoMd5Context`] from the `openssl-crypto`
/// crate and tracks a `finalized` flag so that misuse (double-finalize,
/// update-after-finalize) is reported as a [`ProviderError::Dispatch`]
/// rather than panicking or silently producing wrong output.
///
/// `Md5Context` is a private type; the provider system observes it only
/// through the [`DigestContext`] trait object returned by
/// [`Md5Provider::new_ctx`]. This is intentional — the dispatch
/// indirection guarantees that the context's internal state cannot leak
/// across the provider boundary.
#[derive(Clone)]
struct Md5Context {
    /// The actual MD5 hash state — performs the real RFC 1321 compression.
    inner: CryptoMd5Context,
    /// Tracks whether `finalize()` has been called; once set, all further
    /// `update`/`finalize` calls return [`ProviderError::Dispatch`].
    finalized: bool,
}

impl core::fmt::Debug for Md5Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Elide the internal hash state — the MD5 working buffer can hold
        // partial plaintext that callers may not want appearing in logs.
        f.debug_struct("Md5Context")
            .field("inner", &"<CryptoMd5Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Md5Context {
    /// Construct a fresh MD5 context initialised to RFC 1321 IV constants.
    ///
    /// `CryptoMd5Context::new()` is `#[deprecated]` because MD5 is broken;
    /// this is the *one place* in the provider where invoking it is correct
    /// — the deprecation lint is suppressed exactly here, matching the
    /// pattern in `sha1.rs`.
    #[inline]
    #[allow(deprecated)] // MD5 is broken but required for legacy compat.
    fn new() -> Self {
        Self {
            inner: CryptoMd5Context::new(),
            finalized: false,
        }
    }

    /// Convert a crypto-layer error into a provider-layer
    /// [`ProviderError::Dispatch`] so the call-site can return a
    /// `ProviderResult` directly via `?`.
    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("MD5 crypto operation failed: {err:?}"))
    }
}

#[allow(deprecated)] // The Digest trait impl on CryptoMd5Context is deprecated.
impl DigestContext for Md5Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        // Fully reset the underlying MD5 state and clear the finalized flag.
        // MD5 has no init-time parameters in the C dispatch (`md5_prov.c`
        // does not set `gettable_ctx_params`/`settable_ctx_params`), so we
        // ignore any caller-supplied params here — this matches the C
        // behaviour of the auto-generated `md5_init` thunk.
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD5 context already finalized".to_string(),
            ));
        }
        // Empty updates are explicitly a no-op; this matches both the C
        // behaviour (`MD5_Update(ctx, NULL, 0)` is a documented no-op) and
        // avoids a wasted call into the crypto layer.
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD5 context already finalized".to_string(),
            ));
        }
        // Mark finalized BEFORE the call, so a panic-or-error inside
        // finalize still leaves the context in a defensible state.
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        // Crypto-layer contract: MD5 output is exactly 16 bytes.
        debug_assert_eq!(
            out.len(),
            MD5_DIGEST_SIZE,
            "MD5 finalization must produce exactly {MD5_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        // CryptoMd5Context derives Clone (and ZeroizeOnDrop); Self : Clone
        // is therefore the simplest correct duplication.
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        // Report the algorithm metadata exposed by the C provider's
        // `gettable_params` table: block size and digest size.
        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY_BLOCK_SIZE,
            ParamValue::UInt64(MD5_BLOCK_SIZE as u64),
        );
        params.set(
            PARAM_KEY_DIGEST_SIZE,
            ParamValue::UInt64(MD5_DIGEST_SIZE as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // MD5 has *no* settable context parameters. The C `md5_prov.c`
        // does not register a `settable_ctx_params` callback, so the
        // semantically-correct behaviour for an empty input is a no-op
        // and any non-empty input is an error.
        if params.is_empty() {
            return Ok(());
        }
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "MD5 context rejected unknown parameters: {unknown:?}"
        )))
    }
}

// ===========================================================================
// Md5Sha1Provider
// ===========================================================================

/// Provider entry for the `MD5-SHA1` composite digest.
///
/// `Md5Sha1Provider` is a zero-sized unit struct; the dispatcher constructs
/// new instances directly via `Box::new(Md5Sha1Provider)`.
///
/// # C mapping
///
/// Replaces the `ossl_md5_sha1_functions` `OSSL_DISPATCH` table generated by
/// the `IMPLEMENT_digest_functions_with_settable_ctx(md5_sha1, ...)` macro in
/// `md5_sha1_prov.c`. The settable-params dispatch (`md5_sha1_set_ctx_params`
/// → `ossl_md5_sha1_ctrl(EVP_CTRL_SSL3_MASTER_SECRET, ...)`) is replaced by
/// the [`DigestContext::set_params`] implementation on [`Md5Sha1Context`].
///
/// # Security
///
/// Both MD5 *and* SHA-1 are deprecated for new deployments. This composite
/// digest is provided exclusively for `SSLv3` and TLS 1.0/1.1 backward
/// compatibility. See module-level documentation.
#[derive(Debug, Clone, Copy)]
pub struct Md5Sha1Provider;

impl Default for Md5Sha1Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md5Sha1Provider {
    fn name(&self) -> &'static str {
        "MD5-SHA1"
    }

    fn block_size(&self) -> usize {
        MD5_SHA1_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MD5_SHA1_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Md5Sha1Context::new()))
    }
}

// ---------------------------------------------------------------------------
// Md5Sha1Context — provider-level wrapper around CryptoMd5Sha1Context
// ---------------------------------------------------------------------------

/// Provider-level MD5-SHA1 composite digest context.
///
/// Wraps the cryptographic [`CryptoMd5Sha1Context`] from the
/// `openssl-crypto` crate (which itself runs an inner [`CryptoMd5Context`]
/// and `Sha1Context` in lock-step). In addition to the standard digest
/// state, this wrapper carries an optional `SSLv3` master secret as
/// `ssl3_ms: Option<Vec<u8>>` per **Rule R5** — the absence of a master
/// secret is encoded as `None`, never as an empty `Vec` sentinel.
///
/// # SSL 3.0 master-secret handling
///
/// In the C source (`crypto/md5/md5_sha1.c`, `ossl_md5_sha1_ctrl` with
/// `EVP_CTRL_SSL3_MASTER_SECRET`), the master secret is stored on the
/// composite context but is *not* mixed into the running MD5/SHA-1 state.
/// It is a *holding slot* that the `SSLv3` PRF construction reads back via
/// `EVP_MD_CTX_get_params()` later in the protocol. Our Rust translation
/// preserves this exact semantic: setting `ssl3-ms` populates `ssl3_ms`
/// without touching `inner`, and the digest output of any subsequent
/// `update`/`finalize` is identical regardless of whether `ssl3_ms` was
/// set.
#[derive(Clone)]
struct Md5Sha1Context {
    /// The composite hash state — runs MD5 and SHA-1 in lock-step over the
    /// same input and produces a 36-byte concatenated digest.
    inner: CryptoMd5Sha1Context,
    /// Optional `SSLv3` master secret installed via the `ssl3-ms` parameter.
    /// Per Rule R5, absence is encoded as `None` rather than as an empty
    /// `Vec`. The bytes are *never* mixed into the digest state — they are
    /// retained for `SSLv3` PRF read-back as in the C implementation.
    ssl3_ms: Option<Vec<u8>>,
    /// Tracks whether `finalize()` has been called; once set, all further
    /// `update`/`finalize` calls return [`ProviderError::Dispatch`].
    finalized: bool,
}

impl core::fmt::Debug for Md5Sha1Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact the SSL 3.0 master secret — leaking those bytes into a
        // log line would be a serious confidentiality failure. The hash
        // state is also elided for the same reason.
        f.debug_struct("Md5Sha1Context")
            .field("inner", &"<CryptoMd5Sha1Context>")
            .field("ssl3_ms", &self.ssl3_ms.as_ref().map(|_| "<redacted>"))
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Md5Sha1Context {
    /// Construct a fresh MD5-SHA1 composite context.
    ///
    /// `CryptoMd5Sha1Context::new()` is deprecated; suppression is local.
    #[inline]
    #[allow(deprecated)] // MD5+SHA-1 composite is legacy SSLv3/TLS 1.0 compat.
    fn new() -> Self {
        Self {
            inner: CryptoMd5Sha1Context::new(),
            ssl3_ms: None,
            finalized: false,
        }
    }

    /// Convert a crypto-layer error into a provider-layer
    /// [`ProviderError::Dispatch`].
    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("MD5-SHA1 crypto operation failed: {err:?}"))
    }
}

#[allow(deprecated)] // The Digest trait impl on CryptoMd5Sha1Context is deprecated.
impl DigestContext for Md5Sha1Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        // Reset both inner hashes, drop any previously installed SSL 3.0
        // master secret, and clear the finalized flag. The
        // `md5_sha1_prov.c` C implementation does not consume any
        // parameters at init time (only `set_ctx_params` afterwards
        // accepts `ssl3-ms`), so we ignore caller-supplied params here.
        self.inner.reset();
        self.ssl3_ms = None;
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD5-SHA1 context already finalized".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }
        // The composite update feeds both MD5 and SHA-1 in lock-step
        // (handled inside `CryptoMd5Sha1Context::update`).
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "MD5-SHA1 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        // Crypto-layer contract: MD5(16) || SHA-1(20) = 36 bytes.
        debug_assert_eq!(
            out.len(),
            MD5_SHA1_DIGEST_SIZE,
            "MD5-SHA1 finalization must produce exactly {MD5_SHA1_DIGEST_SIZE} bytes (MD5 16 + SHA-1 20)"
        );
        Ok(out)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        // The clone covers both inner hash states and the `ssl3_ms` slot.
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(
            PARAM_KEY_BLOCK_SIZE,
            ParamValue::UInt64(MD5_SHA1_BLOCK_SIZE as u64),
        );
        params.set(
            PARAM_KEY_DIGEST_SIZE,
            ParamValue::UInt64(MD5_SHA1_DIGEST_SIZE as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Empty parameter sets are a no-op (matches the C convention of
        // a NULL params pointer to `OSSL_FUNC_digest_set_ctx_params`).
        if params.is_empty() {
            return Ok(());
        }

        // Process the only known parameter: `ssl3-ms` (octet string).
        if let Some(value) = params.get(PARAM_KEY_SSL3_MS) {
            let bytes = value.as_bytes().ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "MD5-SHA1 parameter '{}' must be an OctetString, got {}",
                    PARAM_KEY_SSL3_MS,
                    value.param_type_name()
                ))
            })?;
            // Translation of `ossl_md5_sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET,
            // ms_len, ms_bytes)` from `crypto/md5/md5_sha1.c`. The C function
            // copies the master secret into a fixed-size buffer on the context;
            // we copy into a heap-allocated `Vec<u8>` (length-prefixed by
            // construction, no buffer overflow possible — Rule R8 is trivially
            // satisfied because there is no `unsafe` here).
            self.ssl3_ms = Some(bytes.to_vec());
        }

        // Strict-mode rejection of any unrecognised keys. This is stricter
        // than the C implementation (which silently ignores unknown
        // parameters); the workspace digest providers all share this
        // policy to fail-loud on protocol/implementation mismatches.
        let unknown: Vec<&str> = params.keys().filter(|k| *k != PARAM_KEY_SSL3_MS).collect();
        if !unknown.is_empty() {
            return Err(ProviderError::Dispatch(format!(
                "MD5-SHA1 context rejected unknown parameters: {unknown:?}"
            )));
        }
        Ok(())
    }
}

// ===========================================================================
// Algorithm Descriptor Registration
// ===========================================================================

/// Returns the algorithm descriptors advertised by this module.
///
/// The descriptor list contains two entries:
///
/// 1. **`MD5`** — RFC 1321 message digest (also accepts the legacy alias
///    `SSL3-MD5` used by the `SSLv3` specification's MD5 padding scheme).
/// 2. **`MD5-SHA1`** — composite digest used by `SSLv3` and TLS 1.0/1.1
///    handshake signatures (also accepts the alias `MD5SHA1` without the
///    hyphen, which appears in some legacy configurations).
///
/// Both entries advertise the `provider=default` property so they are
/// selectable from the default-provider context. The legacy MD5 algorithm
/// is intentionally *also* exposed by the default provider (matching the
/// upstream OpenSSL 4.0 behaviour) — production callers must rely on
/// FIPS-mode policy or explicit cipher-suite restrictions to prevent its
/// use.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["MD5", "SSL3-MD5"],
            property: "provider=default",
            description: "MD5 message digest (RFC 1321, 128-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["MD5-SHA1", "MD5SHA1"],
            property: "provider=default",
            description: "MD5-SHA1 composite digest (288-bit output, SSLv3 compatibility)",
        },
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Known-Answer Test vectors ---------------------------------------
    //
    // MD5 KAT values from RFC 1321 §A.5 (Test Suite).
    // `MD5("")     = d41d8cd98f00b204e9800998ecf8427e`
    // `MD5("abc")  = 900150983cd24fb0d6963f7d28e17f72`
    // `MD5("The quick brown fox jumps over the lazy dog")
    //              = 9e107d9d372bb6826bd81d3542a419d6`

    /// MD5 of the empty string (RFC 1321 §A.5).
    const MD5_KAT_EMPTY: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
    ];

    /// MD5("abc") (RFC 1321 §A.5).
    const MD5_KAT_ABC: [u8; 16] = [
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f,
        0x72,
    ];

    /// MD5 of "The quick brown fox jumps over the lazy dog" (RFC 1321 §A.5).
    const MD5_KAT_QUICK_FOX: [u8; 16] = [
        0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19,
        0xd6,
    ];

    /// SHA-1 of the empty string (FIPS 180-4 test vectors).
    const SHA1_KAT_EMPTY: [u8; 20] = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18,
        0x90, 0xaf, 0xd8, 0x07, 0x09,
    ];

    /// SHA-1("abc") (FIPS 180-4 test vectors).
    const SHA1_KAT_ABC: [u8; 20] = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];

    /// Helper: concatenate `MD5(x) || SHA-1(x)` into a 36-byte expected output.
    fn md5_sha1_concat(md5: &[u8; 16], sha1: &[u8; 20]) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..16].copy_from_slice(md5);
        out[16..].copy_from_slice(sha1);
        out
    }

    // ====================================================================
    // Md5Provider — Provider metadata tests
    // ====================================================================

    #[test]
    fn md5_provider_reports_canonical_name() {
        let p = Md5Provider;
        assert_eq!(p.name(), "MD5");
    }

    #[test]
    fn md5_provider_reports_block_size_64() {
        let p = Md5Provider::default();
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.block_size(), MD5_BLOCK_SIZE);
    }

    #[test]
    fn md5_provider_reports_digest_size_16() {
        let p = Md5Provider::default();
        assert_eq!(p.digest_size(), 16);
        assert_eq!(p.digest_size(), MD5_DIGEST_SIZE);
    }

    #[test]
    fn md5_provider_default_and_copy_produce_equal_instances() {
        // Md5Provider is a zero-sized unit struct, so copy/default produce
        // semantically identical instances — exercises the derived
        // `Default` and `Copy` impls.
        let a = Md5Provider;
        let b = Md5Provider::default();
        let c = a; // Copy
        assert_eq!(a.name(), b.name());
        assert_eq!(b.name(), c.name());
    }

    #[test]
    fn md5_provider_new_ctx_succeeds() {
        let p = Md5Provider;
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    // ====================================================================
    // Md5Provider — Lifecycle and KAT tests
    // ====================================================================

    #[test]
    fn md5_kat_empty_string_matches_rfc_1321() {
        // RFC 1321 §A.5: MD5("") = d41d8cd98f00b204e9800998ecf8427e.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        // No update — empty string.
        let out = ctx.finalize().unwrap();
        assert_eq!(out, MD5_KAT_EMPTY);
    }

    #[test]
    fn md5_kat_empty_string_via_empty_update_matches_rfc_1321() {
        // Calling update with an empty slice must not perturb the digest.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"").unwrap();
        ctx.update(b"").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, MD5_KAT_EMPTY);
    }

    #[test]
    fn md5_kat_abc_matches_rfc_1321() {
        // RFC 1321 §A.5: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, MD5_KAT_ABC);
    }

    #[test]
    fn md5_kat_quick_fox_matches_rfc_1321() {
        // RFC 1321 §A.5: MD5("The quick brown fox jumps over the lazy dog")
        // = 9e107d9d372bb6826bd81d3542a419d6.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"The quick brown fox jumps over the lazy dog")
            .unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, MD5_KAT_QUICK_FOX);
    }

    #[test]
    fn md5_kat_abc_byte_by_byte_matches_single_update() {
        // Submitting each byte separately must produce the same digest as
        // a single bulk update (verifies the buffering logic in
        // `CryptoMd5Context::update`).
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        for &b in b"abc" {
            ctx.update(&[b]).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out, MD5_KAT_ABC);
    }

    #[test]
    fn md5_multi_update_matches_single_update() {
        let input = b"The quick brown fox jumps over the lazy dog";
        // Single update.
        let p = Md5Provider;
        let mut a = p.new_ctx().unwrap();
        a.init(None).unwrap();
        a.update(input).unwrap();
        let single = a.finalize().unwrap();
        // Multi update partition.
        let mut b = p.new_ctx().unwrap();
        b.init(None).unwrap();
        b.update(&input[..10]).unwrap();
        b.update(&input[10..25]).unwrap();
        b.update(&input[25..]).unwrap();
        let multi = b.finalize().unwrap();
        assert_eq!(single, multi);
        assert_eq!(single, MD5_KAT_QUICK_FOX);
    }

    #[test]
    fn md5_long_message_spans_multiple_blocks() {
        // 1 MiB of zeros — exercises both the streaming buffer and the
        // bit-length counter beyond a single 512-bit block.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let chunk = vec![0u8; 4096];
        for _ in 0..256 {
            ctx.update(&chunk).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn md5_finalize_twice_errors() {
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        let err = ctx.finalize().unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("finalized")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_update_after_finalize_errors() {
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        let err = ctx.update(b"more").unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("finalized")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_init_resets_after_finalize() {
        // A finalized context can be re-used after explicit init().
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        assert_eq!(ctx.finalize().unwrap(), MD5_KAT_ABC);
        ctx.init(None).unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, MD5_KAT_EMPTY);
    }

    #[test]
    fn md5_duplicate_produces_same_digest() {
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"partial").unwrap();
        let mut clone = ctx.duplicate().expect("duplicate");
        clone.update(b" tail").unwrap();
        ctx.update(b" tail").unwrap();
        let orig = ctx.finalize().unwrap();
        let dup = clone.finalize().unwrap();
        assert_eq!(orig, dup);
    }

    #[test]
    fn md5_duplicate_is_independent() {
        // Two duplicates of the same context can absorb different input
        // and produce different digests.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"shared-").unwrap();
        let mut a = ctx.duplicate().unwrap();
        let mut b = ctx.duplicate().unwrap();
        a.update(b"A").unwrap();
        b.update(b"B").unwrap();
        let da = a.finalize().unwrap();
        let db = b.finalize().unwrap();
        assert_ne!(da, db);
        assert_eq!(da.len(), 16);
        assert_eq!(db.len(), 16);
    }

    // ---- Md5 get_params ---------------------------------------------------

    #[test]
    fn md5_get_params_reports_block_and_digest_size() {
        let p = Md5Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(!params.is_empty());
        assert_eq!(
            params.get("block_size").and_then(|v| v.as_u64()).unwrap(),
            64
        );
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()).unwrap(),
            16
        );
    }

    #[test]
    fn md5_get_params_uses_rust_idiomatic_keys() {
        // The Rust-idiomatic spelling is `block_size`/`digest_size`, *not*
        // the C constants `blocksize`/`size`.
        let p = Md5Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(params.get("blocksize").is_none());
        assert!(params.get("size").is_none());
        assert!(params.get("xof").is_none());
    }

    // ---- Md5 set_params (no settable params at all) -----------------------

    #[test]
    fn md5_set_params_empty_is_noop() {
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let empty = ParamSet::new();
        assert!(ctx.set_params(&empty).is_ok());
    }

    #[test]
    fn md5_set_params_rejects_any_key_including_ssl3_ms() {
        // MD5 has no settable parameters in `md5_prov.c` — it does not
        // register a `set_ctx_params` callback. The Rust wrapper must
        // reject *any* non-empty parameter set, including the
        // `ssl3-ms` key which is only valid on `MD5-SHA1`.
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("ssl3-ms", ParamValue::OctetString(vec![0u8; 48]));
        let err = ctx.set_params(&params).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("unknown")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_set_params_rejects_unknown_keys() {
        let p = Md5Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("bogus", ParamValue::UInt64(42));
        let err = ctx.set_params(&params).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("unknown")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    // ====================================================================
    // Md5Sha1Provider — Provider metadata tests
    // ====================================================================

    #[test]
    fn md5_sha1_provider_reports_canonical_name() {
        let p = Md5Sha1Provider;
        assert_eq!(p.name(), "MD5-SHA1");
    }

    #[test]
    fn md5_sha1_provider_reports_block_size_64() {
        let p = Md5Sha1Provider::default();
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.block_size(), MD5_SHA1_BLOCK_SIZE);
    }

    #[test]
    fn md5_sha1_provider_reports_digest_size_36() {
        // 36 = 16 (MD5) + 20 (SHA-1).
        let p = Md5Sha1Provider::default();
        assert_eq!(p.digest_size(), 36);
        assert_eq!(p.digest_size(), MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE);
        assert_eq!(p.digest_size(), MD5_SHA1_DIGEST_SIZE);
    }

    #[test]
    fn md5_sha1_provider_default_and_copy_produce_equal_instances() {
        let a = Md5Sha1Provider;
        let b = Md5Sha1Provider::default();
        let c = a;
        assert_eq!(a.name(), b.name());
        assert_eq!(b.name(), c.name());
    }

    #[test]
    fn md5_sha1_provider_new_ctx_succeeds() {
        let p = Md5Sha1Provider;
        assert!(p.new_ctx().is_ok());
    }

    // ====================================================================
    // Md5Sha1Provider — Lifecycle and KAT tests
    // ====================================================================

    #[test]
    fn md5_sha1_kat_empty_string_matches_concat_of_components() {
        // MD5-SHA1("") = MD5("") || SHA-1("")
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let out = ctx.finalize().unwrap();
        let expected = md5_sha1_concat(&MD5_KAT_EMPTY, &SHA1_KAT_EMPTY);
        assert_eq!(out.len(), 36);
        assert_eq!(&out[..], &expected[..]);
        // Cross-check: the first 16 bytes are the MD5 part, the next 20
        // are the SHA-1 part.
        assert_eq!(&out[..16], &MD5_KAT_EMPTY);
        assert_eq!(&out[16..], &SHA1_KAT_EMPTY);
    }

    #[test]
    fn md5_sha1_kat_abc_matches_concat_of_components() {
        // MD5-SHA1("abc") = MD5("abc") || SHA-1("abc")
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        let expected = md5_sha1_concat(&MD5_KAT_ABC, &SHA1_KAT_ABC);
        assert_eq!(out.len(), 36);
        assert_eq!(&out[..], &expected[..]);
        assert_eq!(&out[..16], &MD5_KAT_ABC);
        assert_eq!(&out[16..], &SHA1_KAT_ABC);
    }

    #[test]
    fn md5_sha1_kat_abc_byte_by_byte_matches_single_update() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        for &b in b"abc" {
            ctx.update(&[b]).unwrap();
        }
        let out = ctx.finalize().unwrap();
        let expected = md5_sha1_concat(&MD5_KAT_ABC, &SHA1_KAT_ABC);
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn md5_sha1_multi_update_matches_single_update() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let p = Md5Sha1Provider;
        let mut a = p.new_ctx().unwrap();
        a.init(None).unwrap();
        a.update(input).unwrap();
        let single = a.finalize().unwrap();
        let mut b = p.new_ctx().unwrap();
        b.init(None).unwrap();
        b.update(&input[..7]).unwrap();
        b.update(&input[7..20]).unwrap();
        b.update(&input[20..]).unwrap();
        let multi = b.finalize().unwrap();
        assert_eq!(single, multi);
        assert_eq!(single.len(), 36);
        // First 16 bytes = MD5("The quick…").
        assert_eq!(&single[..16], &MD5_KAT_QUICK_FOX);
    }

    #[test]
    fn md5_sha1_long_message_spans_multiple_blocks() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let chunk = vec![0u8; 4096];
        for _ in 0..64 {
            ctx.update(&chunk).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), 36);
    }

    #[test]
    fn md5_sha1_finalize_twice_errors() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        let err = ctx.finalize().unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("finalized")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_sha1_update_after_finalize_errors() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let _ = ctx.finalize().unwrap();
        let err = ctx.update(b"more").unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("finalized")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_sha1_init_resets_after_finalize() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let first = ctx.finalize().unwrap();
        assert_eq!(&first[..16], &MD5_KAT_ABC);
        assert_eq!(&first[16..], &SHA1_KAT_ABC);

        ctx.init(None).unwrap();
        let second = ctx.finalize().unwrap();
        assert_eq!(&second[..16], &MD5_KAT_EMPTY);
        assert_eq!(&second[16..], &SHA1_KAT_EMPTY);
    }

    #[test]
    fn md5_sha1_duplicate_produces_same_digest() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"partial").unwrap();
        let mut clone = ctx.duplicate().expect("duplicate");
        clone.update(b" tail").unwrap();
        ctx.update(b" tail").unwrap();
        let orig = ctx.finalize().unwrap();
        let dup = clone.finalize().unwrap();
        assert_eq!(orig, dup);
    }

    #[test]
    fn md5_sha1_duplicate_is_independent() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"shared-prefix-").unwrap();
        let mut a = ctx.duplicate().unwrap();
        let mut b = ctx.duplicate().unwrap();
        a.update(b"A").unwrap();
        b.update(b"B").unwrap();
        let da = a.finalize().unwrap();
        let db = b.finalize().unwrap();
        assert_ne!(da, db);
        assert_eq!(da.len(), 36);
        assert_eq!(db.len(), 36);
    }

    // ---- Md5Sha1 get_params -----------------------------------------------

    #[test]
    fn md5_sha1_get_params_reports_block_and_digest_size() {
        let p = Md5Sha1Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(!params.is_empty());
        assert_eq!(
            params.get("block_size").and_then(|v| v.as_u64()).unwrap(),
            64
        );
        assert_eq!(
            params.get("digest_size").and_then(|v| v.as_u64()).unwrap(),
            36
        );
    }

    #[test]
    fn md5_sha1_get_params_uses_rust_idiomatic_keys() {
        let p = Md5Sha1Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(params.get("blocksize").is_none());
        assert!(params.get("size").is_none());
        assert!(params.get("xof").is_none());
    }

    // ---- Md5Sha1 set_params (ssl3-ms is the only valid key) ---------------

    #[test]
    fn md5_sha1_set_params_empty_is_noop() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let empty = ParamSet::new();
        assert!(ctx.set_params(&empty).is_ok());
    }

    #[test]
    fn md5_sha1_set_params_accepts_ssl3_master_secret_octet_string() {
        // OSSL_DIGEST_PARAM_SSL3_MS takes an octet string per the SSL 3.0
        // specification (RFC 6101 §5.6.3) — a 48-byte master secret.
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let ms_bytes: Vec<u8> = (0..48u8).collect();
        let mut params = ParamSet::new();
        params.set("ssl3-ms", ParamValue::OctetString(ms_bytes.clone()));
        let r = ctx.set_params(&params);
        assert!(
            r.is_ok(),
            "SSL 3.0 master-secret octet-string must be accepted: {:?}",
            r.err()
        );
    }

    #[test]
    fn md5_sha1_set_params_rejects_ssl3_ms_with_wrong_type() {
        // A `Utf8String` value for `ssl3-ms` must be rejected.
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set(
            "ssl3-ms",
            ParamValue::Utf8String("not-octet-string".to_string()),
        );
        let err = ctx.set_params(&params).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("ssl3-ms"));
                assert!(msg.contains("OctetString"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_sha1_set_params_rejects_unknown_parameter_key() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("this-key-does-not-exist", ParamValue::UInt64(42));
        let err = ctx.set_params(&params).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => assert!(msg.contains("unknown")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn md5_sha1_set_params_rejects_mixed_known_and_unknown() {
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("ssl3-ms", ParamValue::OctetString(vec![0u8; 48]));
        params.set("bogus-extra-key", ParamValue::UInt64(0));
        let r = ctx.set_params(&params);
        assert!(
            r.is_err(),
            "unknown keys must fail the whole set_params call"
        );
    }

    #[test]
    fn md5_sha1_init_clears_previously_set_ssl3_master_secret() {
        // After installing SSL3_MS, calling init() must drop it.
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("ssl3-ms", ParamValue::OctetString(vec![0xaau8; 48]));
        ctx.set_params(&params).unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        let expected = md5_sha1_concat(&MD5_KAT_ABC, &SHA1_KAT_ABC);
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn md5_sha1_ssl3_master_secret_does_not_alter_plain_digest_output() {
        // Setting `ssl3-ms` captures the master secret into a separate
        // field but does NOT mix it into the digest state — this matches
        // the C `ossl_md5_sha1_ctrl(EVP_CTRL_SSL3_MASTER_SECRET, ...)`
        // semantic, where the master secret is held for protocol-level
        // PRF read-back rather than absorbed into the hash.
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("ssl3-ms", ParamValue::OctetString(vec![0x5au8; 48]));
        ctx.set_params(&params).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        let expected = md5_sha1_concat(&MD5_KAT_ABC, &SHA1_KAT_ABC);
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn md5_sha1_duplicate_after_set_params_preserves_ssl3_ms() {
        // The duplicated context must carry forward the `ssl3-ms` slot
        // so that branched handshakes do not lose the master secret.
        let p = Md5Sha1Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("ssl3-ms", ParamValue::OctetString(vec![0x33u8; 48]));
        ctx.set_params(&params).unwrap();
        ctx.update(b"pre-fork").unwrap();
        let mut clone = ctx.duplicate().unwrap();
        clone.update(b"-tail").unwrap();
        ctx.update(b"-tail").unwrap();
        assert_eq!(ctx.finalize().unwrap(), clone.finalize().unwrap());
    }

    // ---- Debug impl elision ----------------------------------------------

    #[test]
    fn md5_debug_impl_elides_internal_state() {
        // The manual Debug impl on Md5Context must not leak the internal
        // hash buffer.
        let ctx = Md5Context::new();
        let formatted = format!("{ctx:?}");
        assert!(formatted.contains("Md5Context"));
        assert!(formatted.contains("CryptoMd5Context"));
        assert!(formatted.contains("finalized"));
    }

    #[test]
    fn md5_sha1_debug_impl_elides_sensitive_state() {
        // Verify that the manual Debug impl does NOT leak the master
        // secret bytes nor the internal hash state.
        let mut ctx = Md5Sha1Context::new();
        ctx.ssl3_ms = Some(b"SUPER-SECRET-DO-NOT-LEAK".to_vec());
        let formatted = format!("{ctx:?}");
        assert!(formatted.contains("Md5Sha1Context"));
        assert!(formatted.contains("CryptoMd5Sha1Context"));
        assert!(formatted.contains("redacted"));
        assert!(!formatted.contains("SUPER-SECRET"));
    }

    #[test]
    fn md5_sha1_debug_impl_shows_none_when_ssl3_ms_unset() {
        let ctx = Md5Sha1Context::new();
        let formatted = format!("{ctx:?}");
        // Per the Option<&str>::None Debug formatting, expect "None".
        assert!(formatted.contains("None"));
        assert!(!formatted.contains("redacted"));
    }

    // ====================================================================
    // descriptors() — Algorithm registration
    // ====================================================================

    #[test]
    fn descriptors_returns_two_entries() {
        let d = descriptors();
        assert_eq!(d.len(), 2, "expected MD5 and MD5-SHA1 entries");
    }

    #[test]
    fn descriptors_first_entry_is_md5() {
        let d = descriptors();
        assert!(d[0].names.contains(&"MD5"));
        assert!(d[0].names.contains(&"SSL3-MD5"));
    }

    #[test]
    fn descriptors_second_entry_is_md5_sha1() {
        let d = descriptors();
        assert!(d[1].names.contains(&"MD5-SHA1"));
        assert!(d[1].names.contains(&"MD5SHA1"));
    }

    #[test]
    fn descriptors_advertise_default_provider_property() {
        for desc in descriptors() {
            assert_eq!(desc.property, "provider=default");
        }
    }

    #[test]
    fn descriptors_have_nonempty_human_descriptions() {
        let d = descriptors();
        // Each descriptor's description must be non-empty and mention
        // its algorithm name.
        assert!(!d[0].description.is_empty());
        assert!(d[0].description.contains("MD5"));
        assert!(!d[1].description.is_empty());
        assert!(d[1].description.contains("MD5-SHA1"));
    }

    #[test]
    fn descriptors_md5_does_not_include_md5_sha1_alias() {
        // Schema integrity check: the MD5 entry must not advertise
        // names belonging to the composite digest, and vice versa.
        let d = descriptors();
        assert!(!d[0].names.contains(&"MD5-SHA1"));
        assert!(!d[1].names.contains(&"MD5"));
    }
}
