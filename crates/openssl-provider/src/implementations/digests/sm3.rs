//! # SM3 Digest Provider
//!
//! Translation of `providers/implementations/digests/sm3_prov.c` to Rust.
//! That C file is a thin macro adapter:
//!
//! ```c
//! IMPLEMENT_digest_functions(sm3, SM3_CTX,
//!     SM3_CBLOCK, SM3_DIGEST_LENGTH, 0,
//!     ossl_sm3_init, ossl_sm3_update, ossl_sm3_final)
//! ```
//!
//! - **Block size:** `SM3_CBLOCK` = 64 bytes (512 bits)
//! - **Digest size:** `SM3_DIGEST_LENGTH` = 32 bytes (256 bits)
//! - **Flags:** none (the third macro argument `0`)
//! - **No settable context parameters**
//!
//! The provider-level wrappers in this module forward to the real
//! cryptographic implementation in [`openssl_crypto::hash::legacy`], which
//! contains the actual SM3 chaining state, 64-round compression function
//! (`R1` rounds 0–15, `R2` rounds 16–63), padding logic (mandatory `0x80`
//! marker followed by big-endian 64-bit bit-length footer), and chaining-
//! state serialisation (big-endian 32-bit words). This module's role is to
//! adapt that streaming context to the [`DigestProvider`]/[`DigestContext`]
//! trait surface used by the OpenSSL provider framework.
//!
//! ## Algorithm
//!
//! SM3 is the Chinese national cryptographic hash function, standardised
//! in **GB/T 32905-2016** (also published as **ISO/IEC 10118-3:2018** and
//! **GM/T 0004-2012**). It produces a 256-bit digest using a Merkle-Damgård
//! construction over 512-bit input blocks with a 64-round compression
//! function. The chaining state consists of eight 32-bit words
//! `(A, B, C, D, E, F, G, H)` initialised to the standard IV
//! `(0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC,
//! 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)` per §4.1 of the standard.
//!
//! Output is the concatenation of the eight chaining words emitted in
//! big-endian byte order — a key distinguishing feature from MD5/RIPEMD-160
//! (little-endian) and SHA-2 (also big-endian).
//!
//! ## Use Cases
//!
//! - **Chinese commercial cryptography:** SM3 is the digest of choice in
//!   GM/T-standardised protocols (TLCP / GM-TLS, SSL-VPN, IPSec-VPN
//!   profiles) used by Chinese banking, payment, and government systems.
//! - **GM/T-compliant signature schemes:** SM2 signatures use SM3 as the
//!   underlying hash by default; the `SM2-with-SM3` algorithm is the
//!   pairing required by GB/T 35276-2017.
//! - **Dual-stack interoperability:** systems that must interoperate with
//!   both Western (SHA-2/SHA-3) and Chinese (SM3) cryptographic stacks.
//!
//! ## Security Notice
//!
//! SM3 is **not** FIPS-approved (it is a regional standard not part of
//! NIST's FIPS 140-3 approved algorithms list). It is provided for
//! interoperability with Chinese commercial-cryptography deployments. New
//! designs not constrained by GM/T regulatory requirements should prefer
//! SHA-256 or SHA-3/256, which offer comparable security with broader
//! international tooling support.
//!
//! No practical collision attack against full-round SM3 is publicly known
//! at the time of writing. The 256-bit digest output offers ~128 bits of
//! collision resistance, matching the modern guidance threshold. The
//! underlying [`CryptoSm3Context`] constructor in `openssl-crypto` carries
//! a `#[deprecated]` attribute solely because SM3 is regionally
//! standardised — *not* because of any known cryptographic weakness.
//!
//! ## Wiring path (Rule R10)
//!
//! ```text
//! openssl_provider::DefaultProvider::digest_by_name("SM3")
//!     -> openssl_provider::implementations::digests::dispatch_digest_provider("SM3")
//!         -> Box::new(sm3::Sm3Provider)
//!             -> DigestProvider::new_ctx()
//!                 -> Box::new(Sm3Context { inner: CryptoSm3Context::default(), ... })
//!                     -> DigestContext::{init, update, finalize, duplicate, get_params, set_params}
//!                         -> CryptoDigest::{update, finalize, reset, clone_box}
//!                             -> sm3_compress() in crates/openssl-crypto/src/hash/legacy.rs
//! ```
//!
//! ## Safety (Rule R8)
//!
//! This module contains **zero** `unsafe` blocks. All buffer accesses are
//! bounds-checked by the Rust compiler; the inner cryptographic state is
//! managed entirely through safe abstractions provided by `openssl-crypto`.
//! The inner `CryptoSm3Context` derives `Zeroize` and `ZeroizeOnDrop` so
//! that any leftover plaintext residing in the partial-block buffer is
//! wiped when the context is dropped — discharging the `OPENSSL_cleanse`
//! requirement of the C implementation.
//!
//! ## C Source Reference
//!
//! Replaces `providers/implementations/digests/sm3_prov.c` (19 lines) and
//! the corresponding `ossl_sm3_functions` dispatch table that the
//! `IMPLEMENT_digest_functions` macro emits.

use super::common::{default_get_params, DigestFlags};
use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::ParamSet;
use openssl_crypto::hash::legacy::Sm3Context as CryptoSm3Context;
// `Digest` is the trait that provides the streaming `update`/`finalize`/`reset`
// methods on `Sm3Context` listed in the schema's `members_accessed`. Imported
// via the canonical `openssl_crypto::hash` re-export path (the trait is
// defined in `sha.rs` and re-exported alongside the legacy hash contexts).
use openssl_crypto::hash::Digest as CryptoDigest;

// =============================================================================
// Constants
// =============================================================================

/// SM3 block size in bytes — matches C `SM3_CBLOCK = 64` from
/// `include/internal/sm3.h`.
const SM3_BLOCK_SIZE: usize = 64;

/// SM3 digest size in bytes — matches C `SM3_DIGEST_LENGTH = 32` (256-bit
/// output) from `include/internal/sm3.h`.
const SM3_DIGEST_SIZE: usize = 32;

// =============================================================================
// Sm3Provider — Public Provider Struct
// =============================================================================

/// SM3 message digest provider.
///
/// Block size: 64 bytes, Digest size: 32 bytes (256 bits).
///
/// This is a zero-sized type. All cryptographic state lives in the
/// [`DigestContext`] returned by [`DigestProvider::new_ctx`].
///
/// # Algorithm Names
///
/// Registered under `["SM3"]` with property `"provider=default"`. The OID
/// `1.2.156.10197.1.401` is **not** part of the canonical name set
/// registered with the provider framework — it is recognised by the
/// algorithm-name dispatcher in `digests::mod::dispatch_digest_provider`
/// for backwards compatibility with configuration files and X.509
/// signature-algorithm fields that reference SM3 by OID.
///
/// # C Mapping
///
/// Replaces the `ossl_sm3_functions` dispatch table from
/// `providers/implementations/digests/sm3_prov.c`, generated via the
/// `IMPLEMENT_digest_functions(sm3, SM3_CTX, SM3_CBLOCK, SM3_DIGEST_LENGTH,
/// 0, ossl_sm3_init, ossl_sm3_update, ossl_sm3_final)` macro invocation.
///
/// # Examples
///
/// ```ignore
/// use openssl_provider::implementations::digests::Sm3Provider;
/// use openssl_provider::traits::DigestProvider;
///
/// let provider = Sm3Provider;
/// assert_eq!(provider.name(), "SM3");
/// assert_eq!(provider.block_size(), 64);
/// assert_eq!(provider.digest_size(), 32);
/// let mut ctx = provider.new_ctx().unwrap();
/// ctx.init(None).unwrap();
/// ctx.update(b"abc").unwrap();
/// let digest = ctx.finalize().unwrap();
/// assert_eq!(digest.len(), 32);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Sm3Provider;

impl Default for Sm3Provider {
    /// Constructs a new `Sm3Provider` instance.
    ///
    /// Equivalent to `Sm3Provider` since this is a zero-sized type.
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Sm3Provider {
    /// Returns the canonical algorithm name `"SM3"`.
    ///
    /// Translation of the `name` argument to `IMPLEMENT_digest_functions`
    /// (the C macro produces a function `sm3_get_params` that returns this
    /// name when queried with `OSSL_DIGEST_PARAM_NAME`).
    fn name(&self) -> &'static str {
        "SM3"
    }

    /// Returns `64` — the SM3 block size in bytes.
    ///
    /// Matches the C constant `SM3_CBLOCK = 64` defined in
    /// `include/internal/sm3.h`.
    fn block_size(&self) -> usize {
        SM3_BLOCK_SIZE
    }

    /// Returns `32` — the SM3 digest size in bytes (256 bits).
    ///
    /// Matches the C constant `SM3_DIGEST_LENGTH = 32` defined in
    /// `include/internal/sm3.h`.
    fn digest_size(&self) -> usize {
        SM3_DIGEST_SIZE
    }

    /// Creates a new SM3 context containing a freshly seeded chaining
    /// state.
    ///
    /// Translation of the C `ossl_sm3_init` lifecycle: the chaining state
    /// is initialised to the standard IV per GB/T 32905-2016 §4.1
    /// (`0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC,
    /// 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E`), the partial-block buffer is
    /// zeroed, and the byte counter is reset.
    ///
    /// # Errors
    ///
    /// This implementation never fails — `Ok(...)` is always returned.
    /// The `ProviderResult` return type is preserved to keep the trait
    /// surface uniform with digests whose initialisation may fail (e.g.
    /// FIPS-gated algorithms).
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Sm3Context::new()))
    }
}

// =============================================================================
// Sm3Context — Internal Context (Not Public)
// =============================================================================

/// SM3 hashing context — wraps the cryptographic primitive in
/// [`openssl_crypto::hash::legacy`] and tracks provider-level lifecycle
/// state (whether `finalize` has been called).
///
/// Translation of the C `SM3_CTX` struct plus the lifecycle invariants
/// enforced by the `IMPLEMENT_digest_functions` macro.
///
/// The wrapper enforces the classical streaming digest contract:
/// - `init` resets the underlying state and clears the `finalized` flag.
/// - `update` after `finalize` returns an error rather than silently
///   corrupting state.
/// - `finalize` after `finalize` returns an error.
/// - `duplicate` produces a byte-for-byte independent copy.
///
/// `Drop` is provided implicitly by the inner [`CryptoSm3Context`]'s
/// `ZeroizeOnDrop` derive — any leftover plaintext residing in the partial
/// block buffer is wiped when the context is dropped, which discharges
/// the `OPENSSL_cleanse` requirement of the C implementation.
#[derive(Clone)]
struct Sm3Context {
    /// The underlying SM3 cryptographic state from `openssl-crypto`.
    inner: CryptoSm3Context,
    /// True once `finalize` has been called; protects against
    /// update-after-finalize and double-finalize.
    finalized: bool,
}

impl core::fmt::Debug for Sm3Context {
    /// Custom `Debug` implementation that redacts the inner cryptographic
    /// state (it may hold partially-absorbed plaintext in the block
    /// buffer). This prevents accidental disclosure of input data via
    /// `tracing` / `log` macros that emit `{:?}` formatting.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sm3Context")
            .field("inner", &"<CryptoSm3Context>")
            .field("finalized", &self.finalized)
            .finish()
    }
}

impl Sm3Context {
    /// Creates a new SM3 context with the standard IV.
    ///
    /// Uses [`CryptoSm3Context::default`] which already carries an internal
    /// `#[allow(deprecated)]` and forwards to the deprecated
    /// `Sm3Context::new()` constructor in `openssl-crypto`. This keeps the
    /// deprecation suppression confined to `openssl-crypto` rather than
    /// spreading it through this provider crate.
    #[inline]
    fn new() -> Self {
        Self {
            inner: CryptoSm3Context::default(),
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
        ProviderError::Dispatch(format!("SM3 crypto operation failed: {err:?}"))
    }
}

// `#[allow(deprecated)]` rationale on the `impl DigestContext` block:
//
//   The `Digest` trait method calls (`update`, `finalize`, `reset`) on
//   `CryptoSm3Context` are themselves *not* deprecated. Only the inherent
//   `Sm3Context::new` constructor in `openssl-crypto` carries
//   `#[deprecated]`, and we route around that via
//   `CryptoSm3Context::default()` (whose `Default` impl already suppresses
//   the warning at the source-crate boundary).
//
//   This `#[allow(deprecated)]` is therefore *defensive*: it shields the
//   impl block from any future deprecation that may be added to the inner
//   trait methods (e.g. if the entire `Digest` trait is one day deprecated
//   for `Sm3Context`) and matches the precedent set by the MD5 and
//   RIPEMD-160 provider modules. Removing it would introduce a fragile
//   dependency on the precise deprecation status of the upstream type.
#[allow(deprecated)]
impl DigestContext for Sm3Context {
    /// Initialises (or re-initialises) the digest state.
    ///
    /// Translation of the C `ossl_sm3_init` operation. SM3 has no settable
    /// initialisation parameters — the optional `params` argument is
    /// ignored and accepted silently to match the C provider's behaviour
    /// where `sm3_settable_ctx_params` is not registered.
    ///
    /// **Rule R5:** Returns `Result<()>` rather than a `0`/`1` sentinel.
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.inner.reset();
        self.finalized = false;
        Ok(())
    }

    /// Absorbs `data` into the digest state.
    ///
    /// Translation of the C `ossl_sm3_update` operation. Empty inputs are
    /// a no-op (matches the C implementation which is hot-path optimised
    /// for zero-length updates and avoids an unnecessary call into the
    /// inner length-counter increment path).
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if `finalize` was previously called
    ///   on this context (Rule R5: explicit error rather than silent state
    ///   corruption).
    /// - [`ProviderError::Dispatch`] if the underlying cryptographic
    ///   primitive reports an overflow (input length would exceed the
    ///   64-bit message-length counter — exabyte-scale inputs).
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(ProviderError::Dispatch(
                "SM3 context already finalized".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.inner.update(data).map_err(Self::map_crypto_err)
    }

    /// Produces the 32-byte SM3 digest, consuming the buffered bytes.
    ///
    /// Translation of the C `ossl_sm3_final` operation per GB/T 32905-2016 §4.1:
    /// 1. Append the mandatory `0x80` marker bit.
    /// 2. Zero-pad up to a block boundary minus 8 bytes (running an extra
    ///    compression if the marker did not fit).
    /// 3. Write the 64-bit message length (in **bits**, **big-endian** —
    ///    SM3 differs from MD5/RIPEMD-160 here, which use little-endian).
    /// 4. Run the final compression.
    /// 5. Serialise the 8-word chaining state as 32 bytes in big-endian
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
                "SM3 context already finalized".to_string(),
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
            SM3_DIGEST_SIZE,
            "SM3 finalization must produce exactly {SM3_DIGEST_SIZE} bytes"
        );
        Ok(out)
    }

    /// Returns an independent deep copy of this context.
    ///
    /// Translation of the C `OSSL_FUNC_DIGEST_DUPCTX` dispatch entry that
    /// `IMPLEMENT_digest_functions` generates as a `memcpy` of the
    /// `SM3_CTX`. In Rust the `Clone` derive on [`CryptoSm3Context`]
    /// performs the same byte-for-byte copy of the chaining state, partial
    /// block buffer, and length counter.
    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    /// Returns the digest parameter set with `blocksize=64`, `size=32`,
    /// `xof=0`, and `algid-absent=0` (no flags).
    ///
    /// Delegates to [`default_get_params`] with [`DigestFlags::empty`] which
    /// mirrors the C `IMPLEMENT_digest_functions` macro behaviour calling
    /// `ossl_digest_default_get_params(64, 32, 0)` for SM3. The keys
    /// returned use the C-style spellings (`"blocksize"`, `"size"`,
    /// `"xof"`, `"algid-absent"`) for compatibility with provider callers
    /// that query parameters via `OSSL_PARAM` arrays.
    ///
    /// # Errors
    ///
    /// This implementation never fails — `Ok(params)` is always returned.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        default_get_params(SM3_BLOCK_SIZE, SM3_DIGEST_SIZE, DigestFlags::empty())
    }

    /// Sets context parameters on this digest.
    ///
    /// SM3 has no settable context parameters in the C provider — the
    /// dispatch table does not register a `set_ctx_params` callback and
    /// `sm3_settable_ctx_params` is not exported. An empty `params`
    /// argument succeeds silently; any non-empty argument is rejected with
    /// [`ProviderError::Dispatch`] listing the unknown keys.
    ///
    /// This stricter "reject unknown" behaviour matches the precedent set
    /// by the MD5 and RIPEMD-160 providers — it surfaces caller bugs
    /// (e.g. attempting to configure SSL3-style master-secret derivation
    /// on a plain digest, which is only supported on `MD5-SHA1`) rather
    /// than silently ignoring them.
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
            "SM3 context rejected unknown parameters: {unknown:?}"
        )))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for SM3.
///
/// Registers the SM3 digest under the canonical name `["SM3"]` with
/// property `"provider=default"`. Called by `digests::mod::descriptors()`
/// during provider initialization to populate the default provider's
/// algorithm table.
///
/// # C Mapping
///
/// Replaces the static dispatch table entry from the C `defltprov.c`:
/// ```c
/// { PROV_NAMES_SM3, "provider=default", ossl_sm3_functions, "SM3" },
/// ```
/// In the C source, `PROV_NAMES_SM3` expands to `"SM3:1.2.156.10197.1.401"`
/// — a colon-separated alias string registering both the canonical name
/// and the OID. In this Rust workspace the OID is **not** included in the
/// descriptor's `names` list; the algorithm-name dispatcher in
/// `digests::mod::dispatch_digest_provider` handles OID-based lookup
/// separately to keep the descriptor's primary identification purely
/// human-readable.
///
/// # Note on OID
///
/// The OID `1.2.156.10197.1.401` is part of the official SM3 registration
/// (administered by SAC/TC 260, the Chinese cryptographic standardization
/// body). It appears in X.509 certificates, CMS structures, and PKCS#7
/// signatures that select SM3 as the digest algorithm. The dispatcher
/// recognises this OID and routes it to this provider for backwards
/// compatibility with configuration files and DER-encoded objects.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["SM3"],
        property: "provider=default",
        description: "SM3 message digest (GB/T 32905-2016, 256-bit output)",
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
    // Test vectors are taken from GB/T 32905-2016 Appendix A and from
    // independent validation against the `openssl_crypto::hash::legacy`
    // implementation (which is itself validated against the C reference
    // implementation in `crypto/sm3/sm3.c`).
    // -------------------------------------------------------------------------

    /// `SM3("") = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b`
    ///
    /// Empty-input vector — exercises the padding logic where the
    /// mandatory `0x80` marker is the only "data" placed in the block.
    const KAT_EMPTY: [u8; 32] = [
        0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a,
        0x8f, 0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82,
        0xaa, 0x2b,
    ];

    /// `SM3("a") = 623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88`
    ///
    /// Single-byte vector — exercises the streaming buffer with a
    /// sub-block input.
    const KAT_A: [u8; 32] = [
        0x62, 0x34, 0x76, 0xac, 0x18, 0xf6, 0x5a, 0x29, 0x09, 0xe4, 0x3c, 0x7f, 0xec, 0x61, 0xb4,
        0x9c, 0x7e, 0x76, 0x4a, 0x91, 0xa1, 0x8c, 0xcb, 0x82, 0xf1, 0x91, 0x7a, 0x29, 0xc8, 0x6c,
        0x5e, 0x88,
    ];

    /// `SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`
    ///
    /// Three-character vector — the canonical example from
    /// GB/T 32905-2016 Appendix A.1, used in countless SM3 reference
    /// implementations as the primary smoke-test vector.
    const KAT_ABC: [u8; 32] = [
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4,
        0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b,
        0xa8, 0xe0,
    ];

    /// `SM3("message digest") = c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77`
    ///
    /// Common test-vector input shared with MD5 / SHA-2 / RIPEMD-160
    /// test suites — exercises a 14-byte sub-block input.
    const KAT_MESSAGE_DIGEST: [u8; 32] = [
        0xc5, 0x22, 0xa9, 0x42, 0xe8, 0x9b, 0xd8, 0x0d, 0x97, 0xdd, 0x66, 0x6e, 0x7a, 0x55, 0x31,
        0xb3, 0x61, 0x88, 0xc9, 0x81, 0x71, 0x49, 0xe9, 0xb2, 0x58, 0xdf, 0xe5, 0x1e, 0xce, 0x98,
        0xed, 0x77,
    ];

    /// `SM3("abcdefghijklmnopqrstuvwxyz") = b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595`
    ///
    /// 26-byte input — exercises a sub-block input larger than the
    /// classic `"abc"` triplet.
    const KAT_ALPHABET: [u8; 32] = [
        0xb8, 0x0f, 0xe9, 0x7a, 0x4d, 0xa2, 0x4a, 0xfc, 0x27, 0x75, 0x64, 0xf6, 0x6a, 0x35, 0x9e,
        0xf4, 0x40, 0x46, 0x2a, 0xd2, 0x8d, 0xcc, 0x6d, 0x63, 0xad, 0xb2, 0x4d, 0x5c, 0x20, 0xa6,
        0x15, 0x95,
    ];

    /// `SM3("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
    ///   = debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732`
    ///
    /// 64-byte input — the second canonical example from
    /// GB/T 32905-2016 Appendix A.2, exercising exactly one full block.
    const KAT_ABCD16: [u8; 32] = [
        0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a,
        0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c,
        0x57, 0x32,
    ];

    // ====================================================================
    // Sm3Provider — Provider metadata tests
    // ====================================================================

    /// Verifies the canonical algorithm name is `"SM3"`.
    #[test]
    fn sm3_provider_reports_canonical_name() {
        let p = Sm3Provider;
        assert_eq!(p.name(), "SM3");
    }

    /// Verifies the block size matches the C `SM3_CBLOCK = 64`.
    #[test]
    fn sm3_provider_reports_block_size_64() {
        let p = Sm3Provider::default();
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.block_size(), SM3_BLOCK_SIZE);
    }

    /// Verifies the digest size matches the C `SM3_DIGEST_LENGTH = 32`.
    #[test]
    fn sm3_provider_reports_digest_size_32() {
        let p = Sm3Provider::default();
        assert_eq!(p.digest_size(), 32);
        assert_eq!(p.digest_size(), SM3_DIGEST_SIZE);
    }

    /// Verifies `Default` and `Copy` produce equivalent instances (the
    /// provider is a zero-sized type).
    #[test]
    fn sm3_provider_default_and_copy_produce_equal_instances() {
        let a = Sm3Provider;
        let b = Sm3Provider::default();
        let c = a; // Copy
        assert_eq!(a.name(), b.name());
        assert_eq!(b.name(), c.name());
        assert_eq!(c.block_size(), 64);
        assert_eq!(c.digest_size(), 32);
    }

    /// Verifies that creating a new context succeeds.
    #[test]
    fn sm3_provider_new_ctx_succeeds() {
        let p = Sm3Provider;
        let ctx = p.new_ctx();
        assert!(ctx.is_ok());
    }

    /// Verifies that the C `SM3_CBLOCK` and `SM3_DIGEST_LENGTH` constants
    /// match our Rust constants — guards against accidental edits to the
    /// algorithm specification.
    #[test]
    fn sm3_constants_match_c_definitions() {
        // C: #define SM3_CBLOCK 64
        assert_eq!(SM3_BLOCK_SIZE, 64);
        // C: #define SM3_DIGEST_LENGTH 32
        assert_eq!(SM3_DIGEST_SIZE, 32);
    }

    // ====================================================================
    // SM3 — KAT tests (from GB/T 32905-2016 + cross-validation)
    // ====================================================================

    /// `SM3("")` matches the empty-string vector.
    #[test]
    fn sm3_kat_empty_string() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        // No update — empty string.
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), SM3_DIGEST_SIZE);
        assert_eq!(out, KAT_EMPTY);
    }

    /// `SM3("a")` matches the single-character vector.
    #[test]
    fn sm3_kat_a() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"a").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_A);
    }

    /// `SM3("abc")` matches the canonical GB/T 32905-2016 Appendix A.1
    /// vector.
    #[test]
    fn sm3_kat_abc() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABC);
    }

    /// `SM3("message digest")` matches the cross-implementation vector.
    #[test]
    fn sm3_kat_message_digest() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"message digest").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_MESSAGE_DIGEST);
    }

    /// `SM3("abcdefghijklmnopqrstuvwxyz")` exercises a 26-byte input
    /// — sub-block size, larger than `"abc"`.
    #[test]
    fn sm3_kat_alphabet() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abcdefghijklmnopqrstuvwxyz").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ALPHABET);
    }

    /// `SM3("abcd" × 16)` — exactly 64 bytes — matches the canonical
    /// GB/T 32905-2016 Appendix A.2 vector. This input is exactly one
    /// full block, exercising the path where `finalize` must run an
    /// extra compression for the padding.
    #[test]
    fn sm3_kat_abcd16_one_full_block() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        ctx.update(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
            .unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABCD16);
    }

    // ====================================================================
    // SM3 — Lifecycle / Streaming tests
    // ====================================================================

    /// Verifies that calling `update` with empty data does not perturb the
    /// digest (matches the C implementation's behaviour).
    #[test]
    fn sm3_empty_update_does_not_perturb_digest() {
        let p = Sm3Provider;
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
    fn sm3_byte_by_byte_matches_single_update() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        for &b in b"abc" {
            ctx.update(&[b]).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABC);
    }

    /// Verifies that an arbitrary multi-update partition produces the same
    /// digest as a single update — exercises mid-stream block boundaries.
    #[test]
    fn sm3_multi_update_matches_single_update() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let p = Sm3Provider;
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

    /// Verifies that submitting the 64-byte test vector across multiple
    /// updates straddling the block boundary produces the same digest
    /// as a single update — exercises the partial-block buffer fill path.
    #[test]
    fn sm3_block_boundary_updates_match_single_update() {
        let input = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let p = Sm3Provider;
        // Multi-update partition split into 4-byte chunks (16 chunks total,
        // each "abcd").
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        for chunk in input.chunks(4) {
            ctx.update(chunk).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABCD16);
    }

    /// Verifies that a long input spanning multiple 64-byte blocks
    /// produces a 32-byte digest (exercises the streaming buffer beyond
    /// a single block).
    #[test]
    fn sm3_long_message_spans_multiple_blocks() {
        // 1 MiB of zeros — exercises both the streaming buffer and the
        // 64-bit message-length counter beyond a single 512-bit block.
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let chunk = vec![0u8; 4096];
        for _ in 0..256 {
            ctx.update(&chunk).unwrap();
        }
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), SM3_DIGEST_SIZE);
    }

    /// Verifies that calling `finalize` twice returns a `Dispatch` error.
    #[test]
    fn sm3_finalize_twice_errors() {
        let p = Sm3Provider;
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
    fn sm3_update_after_finalize_errors() {
        let p = Sm3Provider;
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
    fn sm3_init_resets_after_finalize() {
        let p = Sm3Provider;
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
    fn sm3_init_resets_after_partial_update() {
        let p = Sm3Provider;
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
    fn sm3_init_with_empty_params_succeeds() {
        // SM3 has no settable init parameters — None and an empty
        // ParamSet must both succeed silently.
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let empty_params = ParamSet::new();
        ctx.init(Some(&empty_params)).unwrap();
    }

    /// Verifies that `init` ignores unknown init-time parameters silently
    /// (per the C-provider behaviour where `sm3_settable_ctx_params` is
    /// not registered; the digest-init layer in C never inspects the
    /// `OSSL_PARAM` array).
    #[test]
    fn sm3_init_ignores_unknown_params() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        let mut params = ParamSet::new();
        params.set("bogus-init-key", ParamValue::UInt64(99));
        // `init` accepts unknown params silently — only `set_params` is
        // strict about unknown keys.
        ctx.init(Some(&params)).unwrap();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out, KAT_ABC);
    }

    /// Verifies that `duplicate` produces a context that finalises to the
    /// same digest when the same trailing input is fed.
    #[test]
    fn sm3_duplicate_produces_same_digest() {
        let p = Sm3Provider;
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
    fn sm3_duplicate_is_independent() {
        let p = Sm3Provider;
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
        assert_eq!(da.len(), SM3_DIGEST_SIZE);
        assert_eq!(db.len(), SM3_DIGEST_SIZE);
    }

    /// Verifies that the provider-level `Debug` impl redacts the inner
    /// crypto state — Rule R8 / observability does not leak plaintext.
    #[test]
    fn sm3_context_debug_redacts_inner_state() {
        // Construct the concrete `Sm3Context` directly (the `tests`
        // submodule has access to private items).
        let mut ctx = Sm3Context::new();
        ctx.update(b"plaintext-secret").unwrap();
        let dbg = format!("{ctx:?}");
        assert!(
            !dbg.contains("plaintext-secret"),
            "Debug output must not leak input plaintext: {dbg}"
        );
        // The redaction marker must be present.
        assert!(
            dbg.contains("<CryptoSm3Context>"),
            "Debug output should include the redaction marker: {dbg}"
        );
    }

    // ---- get_params -------------------------------------------------------

    /// Verifies that `get_params` returns the four standard digest-param
    /// keys with the expected values.
    #[test]
    fn sm3_get_params_reports_block_and_digest_size() {
        // `default_get_params` uses C-style keys: `blocksize`, `size`,
        // `xof`, `algid-absent`.
        let p = Sm3Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(!params.is_empty());
        assert_eq!(
            params.get("blocksize").and_then(|v| v.as_u64()).unwrap(),
            64
        );
        assert_eq!(params.get("size").and_then(|v| v.as_u64()).unwrap(), 32);
        assert_eq!(params.get("xof").and_then(|v| v.as_u64()).unwrap(), 0);
        assert_eq!(
            params.get("algid-absent").and_then(|v| v.as_u64()).unwrap(),
            0
        );
    }

    /// Verifies that `get_params` does not include any unexpected keys.
    #[test]
    fn sm3_get_params_uses_default_get_params_keys() {
        // Confirm the schema mandate: keys come from `default_get_params`,
        // not from the snake-case manual construction used by md5.rs.
        let p = Sm3Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        assert!(params.get("block_size").is_none());
        assert!(params.get("digest_size").is_none());
    }

    /// Verifies that `get_params` reports `xof=0` and `algid-absent=0`
    /// — SM3 has no flags per the C macro invocation
    /// `IMPLEMENT_digest_functions(sm3, SM3_CTX, SM3_CBLOCK,
    /// SM3_DIGEST_LENGTH, 0, ...)`.
    #[test]
    fn sm3_get_params_reports_no_flags() {
        let p = Sm3Provider;
        let ctx = p.new_ctx().unwrap();
        let params = ctx.get_params().unwrap();
        // SM3 is not a XOF.
        assert_eq!(params.get("xof").and_then(|v| v.as_u64()), Some(0));
        // SM3 has a standard X.509 AlgorithmIdentifier (the OID is
        // 1.2.156.10197.1.401), so algid-absent is 0.
        assert_eq!(params.get("algid-absent").and_then(|v| v.as_u64()), Some(0));
    }

    // ---- set_params (no settable params at all) -----------------------

    /// Verifies that `set_params` accepts an empty `ParamSet`.
    #[test]
    fn sm3_set_params_empty_is_noop() {
        let p = Sm3Provider;
        let mut ctx = p.new_ctx().unwrap();
        ctx.init(None).unwrap();
        let empty = ParamSet::new();
        assert!(ctx.set_params(&empty).is_ok());
    }

    /// Verifies that `set_params` rejects any non-empty `ParamSet`.
    #[test]
    fn sm3_set_params_rejects_unknown_keys() {
        let p = Sm3Provider;
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
    fn sm3_set_params_reports_all_unknown_keys() {
        let p = Sm3Provider;
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
    /// canonical algorithm name and property string.
    #[test]
    fn sm3_descriptors_contains_canonical_name() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        let d = &descs[0];
        assert_eq!(d.names, vec!["SM3"]);
        assert_eq!(d.property, "provider=default");
        assert!(d.description.contains("SM3"));
        assert!(d.description.contains("256-bit"));
        assert!(d.description.contains("GB/T 32905-2016"));
    }

    /// Verifies that the descriptor names are non-empty static strings.
    #[test]
    fn sm3_descriptors_names_are_non_empty() {
        let descs = descriptors();
        for name in &descs[0].names {
            assert!(!name.is_empty());
        }
    }

    /// Verifies that `descriptors` does not include the OID alias in the
    /// canonical names — OID-based lookup is handled by the dispatcher
    /// in `mod.rs`, not by descriptor registration.
    #[test]
    fn sm3_descriptors_does_not_include_oid_alias() {
        let descs = descriptors();
        assert!(!descs[0].names.contains(&"1.2.156.10197.1.401"));
    }

    // ====================================================================
    // Cross-validation: provider matches the underlying crypto layer
    // ====================================================================

    /// Verifies that the provider produces the same digest as the direct
    /// `openssl_crypto::hash::legacy::Sm3Context` for a representative
    /// input. This guards against accidental introduction of a wrapper-
    /// level transformation that would diverge from the reference
    /// implementation.
    #[test]
    fn sm3_provider_matches_crypto_layer() {
        // Provider path.
        let p = Sm3Provider;
        let mut prov_ctx = p.new_ctx().unwrap();
        prov_ctx.init(None).unwrap();
        prov_ctx.update(b"cross-validation").unwrap();
        let prov_out = prov_ctx.finalize().unwrap();

        // Direct crypto-layer path.
        let mut crypto_ctx = CryptoSm3Context::default();
        crypto_ctx.update(b"cross-validation").unwrap();
        let crypto_out = crypto_ctx.finalize().unwrap();

        assert_eq!(prov_out, crypto_out);
        assert_eq!(prov_out.len(), SM3_DIGEST_SIZE);
    }

    /// Verifies that the provider name matches what `CryptoSm3Context`
    /// reports via its `Digest::algorithm_name()` impl — guards against
    /// drift between the provider-level name string and the crypto-layer
    /// name string.
    #[test]
    fn sm3_provider_name_matches_crypto_algorithm_name() {
        let crypto_ctx = CryptoSm3Context::default();
        let crypto_name = crypto_ctx.algorithm_name();
        let p = Sm3Provider;
        assert_eq!(p.name(), crypto_name);
    }

    /// Verifies that the provider's reported sizes match what
    /// `CryptoSm3Context` reports via its `Digest` trait — guards
    /// against drift between the layers.
    #[test]
    fn sm3_provider_sizes_match_crypto_layer() {
        let crypto_ctx = CryptoSm3Context::default();
        let p = Sm3Provider;
        assert_eq!(p.block_size(), crypto_ctx.block_size());
        assert_eq!(p.digest_size(), crypto_ctx.digest_size());
    }
}
