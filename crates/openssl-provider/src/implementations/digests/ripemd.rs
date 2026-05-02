//! # RIPEMD-160 Digest Provider
//!
//! Translation of `providers/implementations/digests/ripemd_prov.c` to Rust.
//! That C file is a thin macro adapter:
//!
//! ```c
//! IMPLEMENT_digest_functions(ripemd160, RIPEMD160_CTX,
//!     RIPEMD160_CBLOCK, RIPEMD160_DIGEST_LENGTH, 0,
//!     RIPEMD160_Init, RIPEMD160_Update, RIPEMD160_Final)
//! ```
//!
//! - **Block size:** `RIPEMD160_CBLOCK` = 64 bytes (512 bits)
//! - **Digest size:** `RIPEMD160_DIGEST_LENGTH` = 20 bytes (160 bits)
//! - **Flags:** none (the third macro argument `0`)
//! - **No settable context parameters**
//!
//! The provider-level wrappers in this module forward to the real
//! cryptographic implementation in [`openssl_crypto::hash::legacy`], which
//! contains the actual RIPEMD-160 chaining state, dual-lane compression
//! function, padding logic, and serialisation. This module's role is to
//! adapt that streaming context to the [`DigestProvider`]/[`DigestContext`]
//! trait surface used by the OpenSSL provider framework.
//!
//! ## Algorithm
//!
//! RIPEMD-160 (RACE Integrity Primitives Evaluation Message Digest, 160-bit)
//! is a cryptographic hash function published by Hans Dobbertin, Antoon
//! Bosselaers, and Bart Preneel in 1996. It is standardised in
//! ISO/IEC 10118-3:2004 and produces a 160-bit digest using a parallel
//! dual-lane compression function over 512-bit blocks with 80 rounds in
//! each lane. Output is the concatenation (after a final cross-mix) of the
//! five 32-bit chaining words emitted in little-endian byte order.
//!
//! ## Use Cases
//!
//! - **Bitcoin and other cryptocurrencies:** the Bitcoin `HASH160` operation
//!   computes `RIPEMD160(SHA256(data))` and is used in P2PKH/P2SH address
//!   construction.
//! - **PGP / OpenPGP legacy interoperability** with old keys and signatures
//!   that selected RIPEMD-160 as the hash algorithm.
//! - **TLS legacy protocol support** for backwards compatibility with very
//!   old peers that negotiated `*_RIPEMD` cipher suites.
//!
//! ## Security Notice
//!
//! RIPEMD-160 is **not** FIPS-approved. It is provided for backward
//! compatibility and niche protocol support. New designs should prefer
//! SHA-256 or SHA-3. While no practical collision attack against full-round
//! RIPEMD-160 is publicly known as of writing, its 160-bit digest output
//! offers only ~80 bits of collision resistance, which is below modern
//! guidance (≥128 bits). The underlying [`CryptoRipemd160Context`]
//! constructor in `openssl-crypto` is therefore marked `#[deprecated]`.
//!
//! ## Wiring path (Rule R10)
//!
//! ```text
//! openssl_provider::DefaultProvider::digest_by_name("RIPEMD-160")
//!     -> openssl_provider::implementations::digests::dispatch_digest_provider("RIPEMD-160")
//!         -> Box::new(ripemd::Ripemd160Provider)
//!             -> DigestProvider::new_ctx()
//!                 -> Box::new(Ripemd160Context { inner: CryptoRipemd160Context::default(), ... })
//!                     -> DigestContext::{init, update, finalize, duplicate, get_params, set_params}
//!                         -> CryptoDigest::{update, finalize, reset, clone_box}
//!                             -> ripemd160_compress() in crates/openssl-crypto/src/hash/legacy.rs
//! ```
//!
//! ## Safety (Rule R8)
//!
//! This module contains **zero** `unsafe` blocks. All buffer accesses are
//! bounds-checked by the Rust compiler; the inner cryptographic state is
//! managed entirely through safe abstractions provided by `openssl-crypto`.
//!
//! ## C Source Reference
//!
//! Replaces `providers/implementations/digests/ripemd_prov.c` (25 lines) and
//! the corresponding `ossl_ripemd160_functions` dispatch table that the
//! `IMPLEMENT_digest_functions` macro emits.

use super::common::{default_get_params, DigestFlags};
use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::ParamSet;
use openssl_crypto::hash::legacy::Ripemd160Context as CryptoRipemd160Context;
// `Digest` is the trait that provides the streaming `update`/`finalize`/`reset`
// methods on `Ripemd160Context` listed in the schema's `members_accessed`.
// Imported via the canonical `openssl_crypto::hash` re-export path (the trait
// is defined in `sha.rs` and re-exported alongside the legacy hash contexts).
use openssl_crypto::hash::Digest as CryptoDigest;

// =============================================================================
// Constants
// =============================================================================

/// RIPEMD-160 block size in bytes — matches C `RIPEMD160_CBLOCK = 64`.
const RIPEMD160_BLOCK_SIZE: usize = 64;

/// RIPEMD-160 digest size in bytes — matches C `RIPEMD160_DIGEST_LENGTH = 20`
/// (160-bit output).
const RIPEMD160_DIGEST_SIZE: usize = 20;

// =============================================================================
// Ripemd160Provider — Public Provider Struct
// =============================================================================

/// RIPEMD-160 message digest provider.
///
/// Block size: 64 bytes, Digest size: 20 bytes (160 bits).
///
/// This is a zero-sized type. All cryptographic state lives in the
/// [`DigestContext`] returned by [`DigestProvider::new_ctx`].
///
/// # Algorithm Names
///
/// Registered under: `["RIPEMD-160", "RIPEMD160"]` with property
/// `"provider=default"`.
///
/// # C Mapping
///
/// Replaces the `ossl_ripemd160_functions` dispatch table from
/// `providers/implementations/digests/ripemd_prov.c`, generated via the
/// `IMPLEMENT_digest_functions(ripemd160, RIPEMD160_CTX, RIPEMD160_CBLOCK,
/// RIPEMD160_DIGEST_LENGTH, 0, RIPEMD160_Init, RIPEMD160_Update,
/// RIPEMD160_Final)` macro invocation.
///
/// # Examples
///
/// ```ignore
/// use openssl_provider::implementations::digests::Ripemd160Provider;
/// use openssl_provider::traits::DigestProvider;
///
/// let provider = Ripemd160Provider;
/// assert_eq!(provider.name(), "RIPEMD-160");
/// assert_eq!(provider.block_size(), 64);
/// assert_eq!(provider.digest_size(), 20);
/// let mut ctx = provider.new_ctx().unwrap();
/// ctx.init(None).unwrap();
/// ctx.update(b"abc").unwrap();
/// let digest = ctx.finalize().unwrap();
/// assert_eq!(digest.len(), 20);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Ripemd160Provider;

impl Default for Ripemd160Provider {
    /// Constructs a new `Ripemd160Provider` instance.
    ///
    /// Equivalent to `Ripemd160Provider` since this is a zero-sized type.
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Ripemd160Provider {
    /// Returns the canonical algorithm name `"RIPEMD-160"`.
    ///
    /// Translation of the `name` argument to `IMPLEMENT_digest_functions`
    /// (the C macro produces a function `ripemd160_get_params` that returns
    /// this name when queried with `OSSL_DIGEST_PARAM_NAME`).
    fn name(&self) -> &'static str {
        "RIPEMD-160"
    }

    /// Returns `64` — the RIPEMD-160 block size in bytes.
    ///
    /// Matches the C constant `RIPEMD160_CBLOCK = 64` defined in
    /// `include/openssl/ripemd.h`.
    fn block_size(&self) -> usize {
        RIPEMD160_BLOCK_SIZE
    }

    /// Returns `20` — the RIPEMD-160 digest size in bytes (160 bits).
    ///
    /// Matches the C constant `RIPEMD160_DIGEST_LENGTH = 20` defined in
    /// `include/openssl/ripemd.h`.
    fn digest_size(&self) -> usize {
        RIPEMD160_DIGEST_SIZE
    }

    /// Creates a new RIPEMD-160 context containing a freshly seeded chaining
    /// state.
    ///
    /// Translation of the C `RIPEMD160_Init` lifecycle: the chaining state
    /// is initialised to the standard IV `(0x67452301, 0xefcdab89,
    /// 0x98badcfe, 0x10325476, 0xc3d2e1f0)`, the partial block buffer is
    /// zeroed, and the byte counter is reset.
    ///
    /// # Errors
    ///
    /// This implementation never fails — `Ok(...)` is always returned.
    /// The `ProviderResult` return type is preserved to keep the trait
    /// surface uniform with digests whose initialisation may fail (e.g.
    /// FIPS-gated algorithms).
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Ripemd160Context::new()))
    }
}

// =============================================================================
// Ripemd160Context — Internal Context (Not Public)
// =============================================================================

/// RIPEMD-160 hashing context — wraps the cryptographic primitive in
/// [`openssl_crypto::hash::legacy`] and tracks provider-level lifecycle
/// state (whether `finalize` has been called).
///
/// Translation of the C `RIPEMD160_CTX` struct plus the lifecycle invariants
/// enforced by the `IMPLEMENT_digest_functions` macro.
///
/// The wrapper enforces the classical streaming digest contract:
/// - `init` resets the underlying state and clears the `finalized` flag.
/// - `update` after `finalize` returns an error rather than silently
///   corrupting state.
/// - `finalize` after `finalize` returns an error.
/// - `duplicate` produces a byte-for-byte independent copy.
///
/// `Drop` is provided implicitly by the inner [`CryptoRipemd160Context`]'s
/// `ZeroizeOnDrop` derive — any leftover plaintext residing in the partial
/// block buffer is wiped when the context is dropped, which discharges
/// the `OPENSSL_cleanse` requirement of the C implementation.
#[derive(Clone)]
struct Ripemd160Context {
    /// The underlying RIPEMD-160 cryptographic state from `openssl-crypto`.
    inner: CryptoRipemd160Context,
    /// True once `finalize` has been called; protects against
    /// update-after-finalize and double-finalize.
    finalized: bool,
}

impl core::fmt::Debug for Ripemd160Context {
    /// Custom `Debug` implementation that redacts the inner cryptographic
    /// state (it may hold partially-absorbed plaintext in the block buffer).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ripemd160Context")
            .field("inner", &"<CryptoRipemd160Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Ripemd160Context {
    /// Creates a new RIPEMD-160 context with the standard IV.
    ///
    /// Uses [`CryptoRipemd160Context::default`] which already carries an
    /// internal `#[allow(deprecated)]` and forwards to the deprecated
    /// `Ripemd160Context::new()` constructor in `openssl-crypto`. This keeps
    /// the deprecation suppression confined to `openssl-crypto` rather than
    /// spreading it through this provider crate.
    #[inline]
    fn new() -> Self {
        Self {
            inner: CryptoRipemd160Context::default(),
            finalized: false,
        }
    }

    /// Maps a cryptographic-layer error to a [`ProviderError::Dispatch`].
    ///
    /// Rule R5: structured `Result` propagation rather than sentinel return
    /// values. The original error is rendered with `Debug` so the
    /// underlying `CryptoError` variant (e.g. `LengthOverflow`) is visible
    /// in the resulting message for diagnostics.
    #[inline]
    fn map_crypto_err(err: impl core::fmt::Debug) -> ProviderError {
        ProviderError::Dispatch(format!("RIPEMD-160 crypto operation failed: {err:?}"))
    }
}

// `#[allow(deprecated)]` rationale on the `impl DigestContext` block:
//
//   The `Digest` trait method calls (`update`, `finalize`, `reset`) on
//   `CryptoRipemd160Context` are themselves *not* deprecated. Only the
//   inherent `Ripemd160Context::new` constructor in `openssl-crypto`
//   carries `#[deprecated]`, and we route around that via
//   `CryptoRipemd160Context::default()` (whose `Default` impl already
//   suppresses the warning at the source crate boundary).
//
//   This `#[allow(deprecated)]` is therefore *defensive*: it shields the
//   impl block from any future deprecation that may be added to the
//   inner trait methods (e.g. if the entire `Digest` trait is one day
//   deprecated for `Ripemd160Context`) and matches the precedent set by
//   the MD5 provider in `md5.rs`. Removing it would introduce a fragile
//   dependency on the precise deprecation status of the upstream type.
#[allow(deprecated)]
impl DigestContext for Ripemd160Context {
    /// Initialises (or re-initialises) the digest state.
    ///
    /// Translation of the C `RIPEMD160_Init` operation. RIPEMD-160 has no
    /// settable initialisation parameters — the optional `params` argument
    /// is ignored and accepted silently to match the C provider's behaviour
    /// where `ripemd160_settable_ctx_params` is not registered.
    ///
    /// **Rule R5:** Returns `Result<()>` rather than a `0`/`1` sentinel.
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    /// Absorbs `data` into the digest state.
    ///
    /// Translation of the C `RIPEMD160_Update` operation. Empty inputs are
    /// a no-op (matches the C implementation which is hot-path optimised
    /// for zero-length updates).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if `finalize` was previously called
    ///   on this context (Rule R5: explicit error rather than silent state
    ///   corruption).
    /// - [`ProviderError::Dispatch`] if the underlying cryptographic
    ///   primitive reports an overflow (input length would exceed the
    ///   64-bit message-length counter).
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "RIPEMD-160 context already finalized".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    /// Produces the 20-byte RIPEMD-160 digest, consuming the buffered bytes.
    ///
    /// Translation of the C `RIPEMD160_Final` operation:
    /// 1. Append the mandatory `0x80` marker bit.
    /// 2. Zero-pad up to a block boundary minus 8 bytes (running an extra
    ///    compression if the marker did not fit).
    /// 3. Write the 64-bit message length (in **bits**, little-endian)
    ///    into the trailing 8 bytes.
    /// 4. Run the final compression.
    /// 5. Serialise the 5-word chaining state as 20 bytes in little-endian
    ///    order.
    ///
    /// After `finalize` returns, further calls to `update` or `finalize`
    /// return [`ProviderError::Dispatch`] until [`DigestContext::init`] is
    /// called.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if `finalize` was previously called
    ///   on this context.
    /// - [`ProviderError::Dispatch`] if the underlying cryptographic
    ///   primitive reports a bit-length overflow during footer construction.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "RIPEMD-160 context already finalized".to_string(),
            ));
        }
        // Set `finalized` *before* the call so that, even if the inner
        // finalization errors, the context is in a defensible state and
        // a subsequent `finalize` call will produce the correct
        // double-finalize error rather than silently re-running.
        self.finalized = true;
        let out = self.inner.finalize().map_err(Self::map_crypto_err)?;
        debug_assert_eq!(
            out.len(),
            RIPEMD160_DIGEST_SIZE,
            "RIPEMD-160 finalization must produce exactly {RIPEMD160_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    /// Returns an independent deep copy of this context.
    ///
    /// Translation of the C `OSSL_FUNC_DIGEST_DUPCTX` dispatch entry that
    /// `IMPLEMENT_digest_functions` generates as a `memcpy` of the
    /// `RIPEMD160_CTX`. In Rust the `Clone` derive on
    /// [`CryptoRipemd160Context`] performs the same byte-for-byte copy of
    /// the chaining state, partial block buffer, and length counter.
    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    /// Returns the digest parameter set with `blocksize=64`, `size=20`,
    /// `xof=0`, and `algid-absent=0` (no flags).
    ///
    /// Delegates to [`default_get_params`] with [`DigestFlags::empty`] which
    /// mirrors the C `IMPLEMENT_digest_functions` macro behaviour calling
    /// `ossl_digest_default_get_params(64, 20, 0)` for RIPEMD-160. The
    /// keys returned use the C-style spellings (`"blocksize"`, `"size"`,
    /// `"xof"`, `"algid-absent"`) for compatibility with provider callers
    /// that query parameters via `OSSL_PARAM` arrays.
    ///
    /// # Errors
    ///
    /// This implementation never fails — `Ok(params)` is always returned.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        default_get_params(
            RIPEMD160_BLOCK_SIZE,
            RIPEMD160_DIGEST_SIZE,
            DigestFlags::empty(),
        )
    }

    /// Sets context parameters on this digest.
    ///
    /// RIPEMD-160 has no settable context parameters in the C provider —
    /// the dispatch table does not register a `set_ctx_params` callback
    /// and `ripemd160_settable_ctx_params` is not exported. An empty
    /// `params` argument succeeds silently; any non-empty argument is
    /// rejected with [`ProviderError::Dispatch`] listing the unknown keys.
    ///
    /// This stricter "reject unknown" behaviour matches the precedent set
    /// by the MD5 provider — it surfaces caller bugs (e.g. attempting to
    /// configure SSL3-style master-secret derivation on a plain digest)
    /// rather than silently ignoring them.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if `params` contains any keys.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }
        let unknown: Vec<&str> = params.keys().collect();
        Err(ProviderError::Dispatch(format!(
            "RIPEMD-160 context rejected unknown parameters: {unknown:?}"
        )))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for RIPEMD-160.
///
/// Registers the RIPEMD-160 digest under the names `["RIPEMD-160", "RIPEMD160"]`
/// with property `"provider=default"`. Called by `digests::mod::descriptors()`
/// during provider initialization to populate the default provider's
/// algorithm table.
///
/// # C Mapping
///
/// Replaces the static dispatch table entry from the C `defltprov.c`:
/// ```c
/// { PROV_NAMES_RIPEMD160, "provider=default", ossl_ripemd160_functions,
///   "RIPEMD160" },
/// ```
/// In the C source, `PROV_NAMES_RIPEMD160` expands to the colon-separated
/// alias string `"RIPEMD-160:RIPEMD160"`. In Rust the names are an explicit
/// `Vec<&'static str>` to preserve type safety and eliminate the runtime
/// string-splitting that the C provider framework performs at lookup time.
///
/// # Note on Aliases
///
/// The bare alias `"RIPEMD"` is recognised by the algorithm-name dispatcher
/// in `digests::mod::dispatch_digest_provider` for backwards compatibility
/// with very old configuration files, but it is not part of the canonical
/// alias set registered with the provider framework.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["RIPEMD-160", "RIPEMD160"],
        property: "provider=default",
        description: "RIPEMD-160 message digest (ISO/IEC 10118-3, 160-bit output)",
    }]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    // -------------------------------------------------------------------------
    // Known Answer Test (KAT) Vectors
    //
    // Test vectors are taken from the original RIPEMD-160 paper by
    // Dobbertin, Bosselaers, and Preneel (1996), Appendix B (also reproduced
    // in ISO/IEC 10118-3:2004 §C.5).
    // -------------------------------------------------------------------------

    /// `RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31`
    const KAT_EMPTY: [u8; 20] = [
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5,
        0x48, 0xb2, 0x25, 0x8d, 0x31,
    ];

    /// `RIPEMD-160("a") = 0bdc9d2d256b3ee9daae347be6f4dc835a467ffe`
    const KAT_A: [u8; 20] = [
        0x0b, 0xdc, 0x9d, 0x2d, 0x25, 0x6b, 0x3e, 0xe9, 0xda, 0xae, 0x34, 0x7b, 0xe6, 0xf4, 0xdc,
        0x83, 0x5a, 0x46, 0x7f, 0xfe,
    ];

    /// `RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc`
    const KAT_ABC: [u8; 20] = [
        0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6, 0xb0,
        0x87, 0xf1, 0x5a, 0x0b, 0xfc,
    ];

    /// `RIPEMD-160("message digest") = 5d0689ef49d2fae572b881b123a85ffa21595f36`
    const KAT_MESSAGE_DIGEST: [u8; 20] = [
        0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8, 0x81, 0xb1, 0x23, 0xa8, 0x5f,
        0xfa, 0x21, 0x59, 0x5f, 0x36,
    ];

    /// `RIPEMD-160("abcdefghijklmnopqrstuvwxyz") = f71c27109c692c1b56bbdceb5b9d2865b3708dbc`
    const KAT_ALPHABET: [u8; 20] = [
        0xf7, 0x1c, 0x27, 0x10, 0x9c, 0x69, 0x2c, 0x1b, 0x56, 0xbb, 0xdc, 0xeb, 0x5b, 0x9d, 0x28,
        0x65, 0xb3, 0x70, 0x8d, 0xbc,
    ];

    // ====================================================================
    // Ripemd160Provider — Provider metadata tests
    // ====================================================================

    /// Verifies the canonical algorithm name is `"RIPEMD-160"`.
    #[test]
    fn ripemd160_provider_reports_canonical_name() {
        let p = Ripemd160Provider;
        assert_eq!(p.name(), "RIPEMD-160");
    }

    /// Verifies the block size matches the C `RIPEMD160_CBLOCK = 64`.
    #[test]
    fn ripemd160_provider_reports_block_size_64() {
        let p = Ripemd160Provider::default();
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.block_size(), RIPEMD160_BLOCK_SIZE);
    }

    /// Verifies the digest size matches the C `RIPEMD160_DIGEST_LENGTH = 20`.
    #[test]
    fn ripemd160_provider_reports_digest_size_20() {
        let p = Ripemd160Provider::default();
        assert_eq!(p.digest_size(), 20);
        assert_eq!(p.digest_size(), RIPEMD160_DIGEST_SIZE);
    }

    /// Verifies `Default` and `Copy` produce equivalent instances (the
    /// provider is a zero-sized type).
    #[test]
    fn ripemd160_provider_default_and_copy_produce_equal_instances() {
        let a = Ripemd160Provider;
        let b = Ripemd160Provider::default();
        let c = a; // Copy
        assert_eq!(a.name(), b.name());
        assert_eq!(b.name(), c.name());
        assert_eq!(c.block_size(), 64);
    }

    /// Verifies that creating a new context succeeds.
    #[test]
    fn ripemd160_provider_new_ctx_succeeds() {
        let p = Ripemd160Provider;
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    // ====================================================================
    // Ripemd160 — KAT tests (from RIPEMD-160 paper Appendix B)
    // ====================================================================

    /// `RIPEMD-160("")` matches the original paper's empty-string vector.
    #[test]
    fn ripemd160_kat_empty_string() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        // No update — empty string.
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), RIPEMD160_DIGEST_SIZE);
        assert_eq!(out, KAT_EMPTY);
    }

    /// `RIPEMD-160("a")` matches the original paper's single-character vector.
    #[test]
    fn ripemd160_kat_a() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"a").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_A);
    }

    /// `RIPEMD-160("abc")` matches the original paper's three-character vector.
    #[test]
    fn ripemd160_kat_abc() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABC);
    }

    /// `RIPEMD-160("message digest")` matches the original paper's vector.
    #[test]
    fn ripemd160_kat_message_digest() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"message digest").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_MESSAGE_DIGEST);
    }

    /// `RIPEMD-160("abcdefghijklmnopqrstuvwxyz")` exercises a 26-byte input
    /// — sub-block size, bigger than `"abc"`.
    #[test]
    fn ripemd160_kat_alphabet() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abcdefghijklmnopqrstuvwxyz").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ALPHABET);
    }

    // ====================================================================
    // Ripemd160 — Lifecycle / Streaming tests
    // ====================================================================

    /// Verifies that calling `update` with empty data does not perturb the
    /// digest (matches the C implementation's behaviour).
    #[test]
    fn ripemd160_empty_update_does_not_perturb_digest() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"").unwrap();
        ctx.update(b"").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_EMPTY);
    }

    /// Verifies that submitting each byte separately produces the same
    /// digest as a single bulk update — exercises the streaming buffer.
    #[test]
    fn ripemd160_byte_by_byte_matches_single_update() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        for &b in b"abc" {
            ctx.update(&[b]).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABC);
    }

    /// Verifies that an arbitrary multi-update partition produces the same
    /// digest as a single update.
    #[test]
    fn ripemd160_multi_update_matches_single_update() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let p = Ripemd160Provider;
        // Single update.
        let mut a = p.new_ctx().unwrap();
        a.init(None).unwrap();
        a.update(input).unwrap();
        let single = a.finalize().unwrap();
        // Multi-update partition split at 7 and 13.
        let mut b = p.new_ctx().unwrap();
        b.init(None).unwrap();
        b.update(&input[..7]).unwrap();
        b.update(&input[7..13]).unwrap();
        b.update(&input[13..]).unwrap();
        let multi = b.finalize().unwrap();
        assert_eq!(single, multi);
        assert_eq!(single, KAT_ALPHABET);
    }

    /// Verifies that a long input spanning multiple 64-byte blocks
    /// produces a 20-byte digest (exercises the streaming buffer beyond
    /// a single block).
    #[test]
    fn ripemd160_long_message_spans_multiple_blocks() {
        // 1 MiB of zeros — exercises both the streaming buffer and the
        // 64-bit message-length counter beyond a single 512-bit block.
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let chunk = vec![0u8; 4096];
        for _ in 0..256 {
            ctx.update(&chunk).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), RIPEMD160_DIGEST_SIZE);
    }

    /// Verifies that calling `finalize` twice returns a `Dispatch` error.
    #[test]
    fn ripemd160_finalize_twice_errors() {
        let p = Ripemd160Provider;
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

    /// Verifies that calling `update` after `finalize` returns an error.
    #[test]
    fn ripemd160_update_after_finalize_errors() {
        let p = Ripemd160Provider;
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

    /// Verifies that `init` resets a finalized context, allowing reuse.
    #[test]
    fn ripemd160_init_resets_after_finalize() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        assert_eq!(ctx.finalize().unwrap(), KAT_ABC);
        // Re-initialise and reuse.
        ctx.init(None).unwrap();
        ctx.update(b"a").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_A);
    }

    /// Verifies that `init` clears a partially-absorbed buffer mid-stream.
    #[test]
    fn ripemd160_init_resets_after_partial_update() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"poison-data-that-should-be-discarded").unwrap();
        // Re-initialise without finalizing — `init` must wipe the buffer.
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABC);
    }

    /// Verifies `init` accepts both `None` and an empty `ParamSet`.
    #[test]
    fn ripemd160_init_with_empty_params_succeeds() {
        // RIPEMD-160 has no settable init parameters — None and an empty
        // ParamSet must both succeed silently.
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let empty_params = ParamSet::new();
        ctx.init(Some(&empty_params)).unwrap();
    }

    /// Verifies that `duplicate` produces a context that finalises to the
    /// same digest when the same trailing input is fed.
    #[test]
    fn ripemd160_duplicate_produces_same_digest() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"part").unwrap();
        let mut clone = ctx.duplicate().expect("duplicate");
        clone.update(b"ial").unwrap();
        ctx.update(b"ial").unwrap();
        let orig = ctx.finalize().unwrap();
        let dup = clone.finalize().unwrap();
        assert_eq!(orig, dup);
    }

    /// Verifies that two duplicates of the same context can independently
    /// absorb different input and produce different digests.
    #[test]
    fn ripemd160_duplicate_is_independent() {
        let p = Ripemd160Provider;
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
        assert_eq!(da.len(), RIPEMD160_DIGEST_SIZE);
        assert_eq!(db.len(), RIPEMD160_DIGEST_SIZE);
    }

    /// Verifies that the provider-level `Debug` impl redacts the inner
    /// crypto state — Rule R8 / observability does not leak plaintext.
    #[test]
    fn ripemd160_context_debug_redacts_inner_state() {
        // Construct the concrete `Ripemd160Context` directly (the `tests`
        // submodule has access to private items).
        let mut ctx = Ripemd160Context::new();
        ctx.update(b"plaintext-secret").unwrap();
        let dbg = format!("{ctx:?}");
        assert!(
            !dbg.contains("plaintext-secret"),
            "Debug output must not leak input plaintext: {dbg}"
        );
        // The redaction marker must be present.
        assert!(
            dbg.contains("<CryptoRipemd160Context>"),
            "Debug output should include the redaction marker: {dbg}"
        );
    }

    // ---- get_params -------------------------------------------------------

    /// Verifies that `get_params` returns the four standard digest-param
    /// keys with the expected values.
    #[test]
    fn ripemd160_get_params_reports_block_and_digest_size() {
        // `default_get_params` uses C-style keys: `blocksize`, `size`,
        // `xof`, `algid-absent`.
        let p = Ripemd160Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(!params.is_empty());
        assert_eq!(
            params.get("blocksize").and_then(|v| v.as_u64()).unwrap(),
            64
        );
        assert_eq!(params.get("size").and_then(|v| v.as_u64()).unwrap(), 20);
        assert_eq!(params.get("xof").and_then(|v| v.as_u64()).unwrap(), 0);
        assert_eq!(
            params.get("algid-absent").and_then(|v| v.as_u64()).unwrap(),
            0
        );
    }

    /// Verifies that `get_params` does not include any unexpected keys.
    #[test]
    fn ripemd160_get_params_uses_default_get_params_keys() {
        // Confirm the schema mandate: keys come from `default_get_params`,
        // not from the snake-case manual construction used by md5.rs.
        let p = Ripemd160Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(params.get("block_size").is_none());
        assert!(params.get("digest_size").is_none());
    }

    // ---- set_params (no settable params at all) -----------------------

    /// Verifies that `set_params` accepts an empty `ParamSet`.
    #[test]
    fn ripemd160_set_params_empty_is_noop() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let empty = ParamSet::new();
        assert!(ctx.set_params(&empty).is_ok());
    }

    /// Verifies that `set_params` rejects any non-empty `ParamSet`.
    #[test]
    fn ripemd160_set_params_rejects_unknown_keys() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("bogus", ParamValue::UInt64(42));
        let err = ctx.set_params(&params).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("unknown"));
                assert!(msg.contains("bogus"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// Verifies that `set_params` reports all unknown keys, not just the first.
    #[test]
    fn ripemd160_set_params_reports_all_unknown_keys() {
        let p = Ripemd160Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let mut params = ParamSet::new();
        params.set("first-unknown", ParamValue::UInt64(1));
        params.set("second-unknown", ParamValue::UInt64(2));
        let err = ctx.set_params(&params).unwrap_err();
        match err {
            ProviderError::Dispatch(msg) => {
                // Both keys must appear in the diagnostic message.
                assert!(msg.contains("first-unknown"));
                assert!(msg.contains("second-unknown"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    // ====================================================================
    // descriptors() — Algorithm registration metadata
    // ====================================================================

    /// Verifies that `descriptors` returns exactly one descriptor with the
    /// canonical algorithm names and property string.
    #[test]
    fn ripemd160_descriptors_contains_canonical_names() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        let d = &descs[0];
        assert_eq!(d.names, vec!["RIPEMD-160", "RIPEMD160"]);
        assert_eq!(d.property, "provider=default");
        assert!(d.description.contains("RIPEMD-160"));
        assert!(d.description.contains("160-bit"));
    }

    /// Verifies that `descriptors` does not include the bare "RIPEMD" alias.
    ///
    /// The bare alias is recognised by the dispatcher in `mod.rs` for
    /// backwards compatibility with very old configuration files but is
    /// not part of the canonical registration name set.
    #[test]
    fn ripemd160_descriptors_does_not_include_bare_ripemd_alias() {
        let descs = descriptors();
        assert!(!descs[0].names.contains(&"RIPEMD"));
    }

    /// Verifies that the descriptor names are non-empty static strings.
    #[test]
    fn ripemd160_descriptors_names_are_non_empty() {
        let descs = descriptors();
        for name in &descs[0].names {
            assert!(!name.is_empty());
        }
    }
}
