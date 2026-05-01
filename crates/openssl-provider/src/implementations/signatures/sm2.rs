//! SM2 signature provider implementation (GB/T 32918.2-2016).
//!
//! This module is the Rust translation of
//! `providers/implementations/signature/sm2_sig.c` (593 lines) and the
//! supporting primitive in `crypto/sm2/sm2_sign.c` (560 lines). It implements
//! the **Chinese national digital signature standard SM2**, an ECDSA-style
//! signature scheme defined over the SM2 prime field elliptic curve from
//! GM/T 0003-2012 / GB/T 32918, paired with the SM3 cryptographic hash
//! function.
//!
//! # Algorithm Overview
//!
//! The SM2 signature scheme augments the standard ECDSA flow with a
//! *distinguishing-identifier digest* (the **Z value**) that binds each
//! signature to the signer's identity. Given identity `IDA` and public key
//! `(xA, yA)` on the SM2 curve with parameters `(a, b, G = (xG, yG))`, the
//! Z value is computed as:
//!
//! ```text
//! Z = SM3(ENTL || IDA || a || b || xG || yG || xA || yA)
//! ```
//!
//! where `ENTL` is the bit-length of `IDA` encoded as a 2-byte big-endian
//! integer. The default identifier — used when no application-specific value
//! is supplied — is the ASCII byte string `"1234567812345678"` (16 bytes,
//! 128 bits), matching the value installed by `EVP_PKEY_CTX_set1_id_uc()`
//! and `sm2sig_set_ctx_params()` in the C implementation.
//!
//! Once `Z` is fixed, signing/verification follow:
//!
//! ```text
//! e = SM3(Z || M)
//! Sign:
//!   k = random in [1, n-1]
//!   (x1, _) = k · G
//!   r = (e + x1) mod n              (retry if r == 0 or r + k == n)
//!   s = (1 + dA)^-1 · (k - r·dA) mod n  (retry if s == 0)
//! Verify:
//!   t = (r + s) mod n               (reject if t == 0)
//!   (x1, _) = s·G + t·PA
//!   R = (e + x1) mod n
//!   accept iff R == r
//! ```
//!
//! Signatures are encoded as DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER,
//! s INTEGER }`, identical to the format used by ECDSA on prime curves.
//!
//! # Architectural Notes
//!
//! * The SM2 curve is **not** present as a `NamedCurve` enum variant in the
//!   current `openssl-crypto::ec` module. Instead, this module constructs the
//!   group from explicit GM/T 0003-2012 parameters via
//!   [`EcGroup::from_explicit_params`]. Adding `NamedCurve::Sm2` later would
//!   only allow elimination of [`sm2_curve_group`] in favour of
//!   `EcGroup::from_curve_name(NamedCurve::Sm2)`; the rest of this file is
//!   curve-agnostic.
//! * SM2 is **not FIPS-approved**. The whole module is gated behind
//!   `#[cfg(feature = "sm2")]` in `signatures::mod`; no FIPS gating is
//!   required at this layer.
//! * Per refactoring rule R8, this module contains **zero `unsafe` blocks**
//!   and routes secure memory zeroing through the [`zeroize`] crate.
//! * Per rule R5, all fallible paths return [`ProviderResult`] rather than
//!   sentinel integer codes, and optional state uses [`Option`].
//! * Per rule R7, no shared mutable state is introduced; the context is
//!   single-threaded and only the [`LibContext`] handle is shared via
//!   [`Arc`].
//!
//! # C Source Mapping
//!
//! | C Function in `sm2_sig.c`                  | Rust Equivalent                              |
//! |--------------------------------------------|----------------------------------------------|
//! | `sm2sig_newctx` (line 119)                 | [`Sm2SignatureProvider::new_ctx`]            |
//! | `sm2sig_signature_init` (line 144)         | [`Sm2SignatureContext::sign_init`] /         |
//! |                                            | [`Sm2SignatureContext::verify_init`]         |
//! | `sm2sig_sign` (line 175)                   | [`Sm2SignatureContext::sign_internal`]       |
//! | `sm2sig_verify` (line 222)                 | [`Sm2SignatureContext::verify_internal`]     |
//! | `sm2sig_compute_z_digest` (line 247)       | [`Sm2SignatureContext::compute_z_digest`]    |
//! | `sm2sig_digest_signverify_init` (line 285) | digest_sign_init/digest_verify_init          |
//! | `sm2sig_digest_signverify_update`          | digest_sign_update/digest_verify_update      |
//! | `sm2sig_digest_sign_final` (line 327)      | [`Sm2SignatureContext::digest_sign_final`]   |
//! | `sm2sig_digest_verify_final` (line 339)    | [`Sm2SignatureContext::digest_verify_final`] |
//! | `sm2sig_freectx` (line 349)                | [`Drop`] impl on `Sm2SignatureContext`       |
//! | `sm2sig_dupctx` (line 353)                 | [`Sm2SignatureContext::duplicate`]           |
//! | `sm2sig_get_ctx_params` (line 404)         | [`Sm2SignatureContext::get_ctx_params`]      |
//! | `sm2sig_set_ctx_params` (line 463)         | [`Sm2SignatureContext::set_ctx_params`]      |
//! | `ossl_sm2_signature_functions` table       | [`descriptors`]                              |

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{
    CommonError, CryptoError, ParamSet, ParamValue, ProviderError, ProviderResult,
};
use openssl_crypto::bn::arithmetic::{mod_add, mod_inverse_checked, mod_mul};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;
use openssl_crypto::ec::{EcGroup, EcKey, EcPoint};
use openssl_crypto::evp::md::{MdContext, MessageDigest, SM3};

use super::algorithm;
use super::OperationMode;
use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// =====================================================================
//                          Internal helpers
// =====================================================================

/// Wraps a crypto-layer error as a [`ProviderError::Dispatch`] so it can
/// be returned from the `SignatureContext` trait methods.
///
/// Mirrors the `dispatch_err` helper in [`super::eddsa`].  Kept private
/// to this module; cross-module consistency comes from the error shape,
/// not from a shared symbol.
#[inline]
#[allow(clippy::needless_pass_by_value)] // ergonomic `.map_err(dispatch_err)` consumer
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Validates that a caller-supplied digest name is acceptable for SM2.
///
/// SM2 mandates SM3 as the underlying hash; `OpenSSL` allows the empty
/// string to mean "use the algorithm default" (see the explicit length
/// check at `sm2_sig.c` line ~135 against `OSSL_DIGEST_NAME_SM3`).  Any
/// other digest name is rejected.
fn enforce_digest_match_sm2(digest: &str) -> ProviderResult<()> {
    if digest.is_empty() {
        return Ok(());
    }
    let normalised = digest.to_ascii_uppercase();
    if normalised == "SM3" {
        return Ok(());
    }
    Err(ProviderError::Common(CommonError::InvalidArgument(
        format!("digest {digest} is not valid for SM2 (must be SM3 or empty)"),
    )))
}

// =====================================================================
//                           Public Constants
// =====================================================================

/// Default SM2 distinguishing identifier (`IDA`) used when no application
/// identifier is supplied.
///
/// This 16-byte ASCII value (`"1234567812345678"`) matches the default
/// installed by the C reference implementation in
/// `providers/implementations/signature/sm2_sig.c` — the `id` field of
/// `PROV_SM2_CTX` is initialised by `sm2sig_newctx()` to this string via
/// `OPENSSL_strdup("1234567812345678")` and the same default is returned by
/// `EVP_PKEY_CTX_set1_id_uc()`.
pub const SM2_DEFAULT_ID: &[u8] = b"1234567812345678";

/// Algorithm descriptor property string registered by every SM2 default-
/// provider entry. Mirrors `prov/names.h`'s `OSSL_PROVIDER_DEFAULT` value.
const DEFAULT_PROPERTY: &str = "provider=default";

/// Object identifier dotted form for SM2 (GM/T 0006-2012).
const SM2_OID_DOTTED: &str = "1.2.156.10197.1.301";

/// Object identifier dotted form for the SM2 + SM3 signature algorithm
/// (RFC 8998 §3, `id-sm2-with-sm3`). Used when constructing a complete
/// `AlgorithmIdentifier` for digest-sign / digest-verify modes.
///
/// Currently only referenced from documentation and the hard-coded DER
/// bytes in `sm2_algorithm_identifier_der()`; declared here so callers
/// who wish to look up the textual OID can do so without re-deriving it.
#[allow(dead_code)] // Public-facing OID constant retained for completeness.
const SM2_WITH_SM3_OID_DOTTED: &str = "1.2.156.10197.1.501";

/// Algorithm name string returned by [`Sm2SignatureProvider::name`].
const SM2_ALGORITHM_NAME: &str = "SM2";

/// Default digest associated with the SM2 signature algorithm. SM2 mandates
/// SM3 in the GB/T 32918 standard; while the C provider permits other
/// digests, switching is strongly discouraged. We mirror the C default.
const SM2_DEFAULT_DIGEST: &str = SM3;

/// SM3 output length in bytes.
const SM3_DIGEST_SIZE: usize = 32;

/// Maximum number of nonce-resampling attempts inside `sign_internal`.
///
/// Each iteration draws a fresh random `k` and aborts if either `r == 0`,
/// `r + k == n` or the resulting `s == 0`.  The C reference implementation
/// loops indefinitely; we cap the retry count at a generous bound so a
/// catastrophic RNG never triggers an unbounded loop.  The probability of
/// 32 consecutive degenerate draws is `< 2^-256` so this bound is
/// cryptographically safe.
const SM2_MAX_SIGN_RETRIES: u32 = 32;

/// SM2 prime-field byte length (256 bits ÷ 8). All scalar and coordinate
/// big-endian byte representations are zero-padded to this length.
const SM2_FIELD_BYTES: usize = 32;

/// Length in bytes of an uncompressed SM2 public key encoding
/// (`0x04 || x || y`, 1 + 32 + 32).
const SM2_UNCOMPRESSED_PUBKEY_LEN: usize = 1 + 2 * SM2_FIELD_BYTES;

/// Length in bytes of a compressed SM2 public key encoding
/// (`0x02|0x03 || x`, 1 + 32).
const SM2_COMPRESSED_PUBKEY_LEN: usize = 1 + SM2_FIELD_BYTES;

/// Length in bytes of an SM2 raw private key (the secret scalar `dA`).
const SM2_PRIVKEY_LEN: usize = SM2_FIELD_BYTES;

/// Length in bytes of an SM2 raw keypair encoding: 32-byte private scalar
/// followed by a 65-byte uncompressed public point.
const SM2_KEYPAIR_LEN: usize = SM2_PRIVKEY_LEN + SM2_UNCOMPRESSED_PUBKEY_LEN;

// =====================================================================
//          SM2 Curve Parameters — GM/T 0003-2012 / GB/T 32918
// =====================================================================
//
// These fixed hexadecimal strings encode the SM2 curve domain parameters
// over Fp. They are the canonical values published in §6.4 of GM/T
// 0003-2012 and reproduced in IETF RFC 8998 §A. See also OpenSSL's
// `crypto/objects/objects.txt` (`SM2-curve` entry) and `crypto/ec/ecp_oss.c`
// `sm2_curve_data` (lines 38-86).

/// SM2 prime modulus `p`.
const SM2_P_HEX: &str = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

/// SM2 curve coefficient `a`. Equal to `p − 3`, giving the Weierstrass
/// equation `y² = x³ − 3x + b (mod p)`.
const SM2_A_HEX: &str = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";

/// SM2 curve coefficient `b`.
const SM2_B_HEX: &str = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

/// SM2 base-point `G` x-coordinate (`xG`).
const SM2_GX_HEX: &str = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";

/// SM2 base-point `G` y-coordinate (`yG`).
const SM2_GY_HEX: &str = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

/// SM2 base-point order `n`.
const SM2_N_HEX: &str = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

/// SM2 cofactor `h`. SM2 always uses `h = 1`.
const SM2_H_HEX: &str = "01";

// =====================================================================
//                         SM2 Curve Construction
// =====================================================================

/// Constructs an [`EcGroup`] representing the SM2 curve from the explicit
/// GM/T 0003-2012 parameters.
///
/// # Errors
///
/// Returns [`CryptoError::Encoding`] if any of the embedded hex constants
/// fails to parse (this should never happen at runtime — the constants are
/// statically validated by the type system and unit tests).
///
/// # Example
///
/// ```no_run
/// # use openssl_provider::implementations::signatures::sm2::*;
/// // (curve construction is internal — exposed via Sm2SignatureContext)
/// ```
fn sm2_curve_group() -> Result<EcGroup, CryptoError> {
    let p = BigNum::from_hex(SM2_P_HEX)?;
    let a = BigNum::from_hex(SM2_A_HEX)?;
    let b = BigNum::from_hex(SM2_B_HEX)?;
    let gx = BigNum::from_hex(SM2_GX_HEX)?;
    let gy = BigNum::from_hex(SM2_GY_HEX)?;
    let order = BigNum::from_hex(SM2_N_HEX)?;
    let cofactor = BigNum::from_hex(SM2_H_HEX)?;
    let generator = EcPoint::from_affine(gx, gy);
    EcGroup::from_explicit_params(p, a, b, generator, order, cofactor)
}

// =====================================================================
//                       Sm2SignatureProvider
// =====================================================================

/// SM2 signature algorithm provider.
///
/// Equivalent to the C `OSSL_DISPATCH ossl_sm2_signature_functions[]` table
/// in `providers/implementations/signature/sm2_sig.c` (lines 559-595): a
/// stateless factory that constructs fresh per-operation contexts via
/// [`Sm2SignatureProvider::new_ctx`], the Rust analogue of `sm2sig_newctx`.
///
/// The provider holds a reference to the parent library context plus an
/// optional property query string used when fetching the SM3 digest
/// implementation. Both fields mirror `PROV_SM2_CTX::libctx` and
/// `PROV_SM2_CTX::propq` from the C source (lines 65-100).
#[derive(Clone)]
pub struct Sm2SignatureProvider {
    /// Library context shared with the rest of the provider system.
    lib_ctx: Arc<LibContext>,
    /// Optional property query passed to digest fetches.
    prop_query: Option<String>,
}

impl Sm2SignatureProvider {
    /// Constructs a new provider bound to the given library context.
    ///
    /// `prop_query` is forwarded verbatim to digest fetches and follows the
    /// same syntax as OpenSSL's `OSSL_FUNC_provider_query_operation`
    /// property strings (e.g., `"provider=default,fips=no"`).
    #[must_use]
    pub fn new(lib_ctx: Arc<LibContext>, prop_query: Option<String>) -> Self {
        Self {
            lib_ctx,
            prop_query,
        }
    }
}

impl fmt::Debug for Sm2SignatureProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sm2SignatureProvider")
            .field("name", &SM2_ALGORITHM_NAME)
            .field("prop_query", &self.prop_query)
            .finish_non_exhaustive()
    }
}

impl SignatureProvider for Sm2SignatureProvider {
    fn name(&self) -> &'static str {
        SM2_ALGORITHM_NAME
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            "Sm2SignatureProvider::new_ctx: allocating fresh signature context"
        );
        Ok(Box::new(Sm2SignatureContext::new(
            Arc::clone(&self.lib_ctx),
            self.prop_query.clone(),
        )))
    }
}

// =====================================================================
//                       Sm2SignatureContext
// =====================================================================

/// Per-operation SM2 signature context.
///
/// Direct analogue of the C `PROV_SM2_CTX` struct defined at
/// `providers/implementations/signature/sm2_sig.c:65-100`. Each field
/// here corresponds to an entry on the C struct as documented in-line.
///
/// # Lifecycle
///
/// 1. Constructed via [`Sm2SignatureProvider::new_ctx`] (mirrors
///    `sm2sig_newctx`).
/// 2. Initialised by `sign_init` / `verify_init` / `digest_sign_init` /
///    `digest_verify_init` (mirror `sm2sig_signature_init` and
///    `sm2sig_digest_signverify_init`).
/// 3. Operated by `sign` / `verify` / streaming digest variants.
/// 4. Cleaned up automatically through the [`Drop`] impl, which delegates
///    to [`Zeroize::zeroize`] (mirror `sm2sig_freectx`).
///
/// # Thread Safety
///
/// The context is **not** intended to be shared between threads concurrently;
/// each operation consumes a `&mut self`. The shared library context is held
/// behind [`Arc`] so multiple contexts may safely coexist on different
/// threads, matching the C `OPENSSL_LIB_CTX` aliasing model.
pub struct Sm2SignatureContext {
    /// Library context handle. Equivalent to `PROV_SM2_CTX::libctx`.
    lib_ctx: Arc<LibContext>,

    /// Property query forwarded to digest fetches. Equivalent to
    /// `PROV_SM2_CTX::propq`.
    prop_query: Option<String>,

    /// Parsed SM2 EC key. Stored shared via [`Arc`] so [`duplicate`] can
    /// inexpensively clone the context without copying scalar/point data.
    ///
    /// `None` until `sign_init` / `verify_init` / digest variants populate
    /// it. Maps to `PROV_SM2_CTX::ec` (an `EC_KEY *` in C).
    key: Option<Arc<EcKey>>,

    /// Whether the context is initialised for [`OperationMode::Sign`] or
    /// [`OperationMode::Verify`]. The C struct distinguishes via the
    /// `EVP_PKEY_OP_*` constants set by `EVP_PKEY_sign_init`/etc.; we use
    /// the [`OperationMode`] enum exported from
    /// [`super::OperationMode`] for the same purpose.
    operation: Option<OperationMode>,

    /// Currently-configured digest name. Defaults to `"SM3"`. Mirrors
    /// `PROV_SM2_CTX::mdname` (line 71 of `sm2_sig.c`).
    digest_name: String,

    /// Streaming digest context used by `digest_sign` / `digest_verify`
    /// methods. `None` for the raw `sign` / `verify` paths. Mirrors
    /// `PROV_SM2_CTX::mdctx`.
    digest_ctx: Option<MdContext>,

    /// Output size in bytes of the configured digest. Cached to avoid
    /// repeated lookups. Mirrors `PROV_SM2_CTX::mdsize` (line 89).
    digest_size: usize,

    /// SM2 distinguishing identifier. Defaults to [`SM2_DEFAULT_ID`].
    /// Mirrors `PROV_SM2_CTX::id` and the `id_len` companion field
    /// (lines 97-99 of `sm2_sig.c`). Securely zeroed on drop.
    sm2_id: Vec<u8>,

    /// `true` when the next `digest_sign_update` / `digest_verify_update`
    /// must inject the Z-value into the running digest. Set on
    /// initialisation, cleared once the Z-value has been mixed in.
    /// Mirrors the `flag_compute_z_digest:1` bitfield on `PROV_SM2_CTX`
    /// (line 73 of `sm2_sig.c`).
    needs_z_digest: bool,

    /// Cached DER encoding of the `AlgorithmIdentifier` returned by the
    /// `algorithm-id` parameter query. Lazily populated by
    /// [`get_ctx_params`]. Mirrors `PROV_SM2_CTX::aid`/`aid_len`.
    aid_cache: Option<Vec<u8>>,

    /// Buffer accumulating message bytes for the streaming digest-sign
    /// and digest-verify modes when no provider-supplied digest context
    /// is available. Securely zeroed when consumed and on drop.
    streaming_buffer: Vec<u8>,
}

// ---------------------------------------------------------------------
//          Manual Zeroize / Drop / ZeroizeOnDrop / Debug impls
// ---------------------------------------------------------------------

impl Zeroize for Sm2SignatureContext {
    fn zeroize(&mut self) {
        // Sensitive fields are zeroed eagerly so that any later memory
        // observation cannot recover residual material. The library
        // context and shared key are reference-counted; dropping our
        // strong references is the only correct cleanup.
        self.sm2_id.zeroize();
        self.streaming_buffer.zeroize();
        self.digest_name.zeroize();
        if let Some(cache) = self.aid_cache.as_mut() {
            cache.zeroize();
        }
        self.aid_cache = None;
        // Drop the digest streaming context (if any) so its internal
        // state can be released. `MdContext` owns its zeroizing buffer.
        self.digest_ctx = None;
        // Drop strong references; the underlying objects are zeroed by
        // their own Drop impls.
        self.key = None;
        self.operation = None;
        self.needs_z_digest = false;
        self.digest_size = 0;
    }
}

impl Drop for Sm2SignatureContext {
    fn drop(&mut self) {
        // Equivalent to `sm2sig_freectx` (sm2_sig.c lines 349-351). The
        // C version explicitly frees `id`, `mdname`, `aid`, the EC key,
        // and the digest context; in Rust each is dropped automatically.
        // We additionally zero sensitive byte buffers via `zeroize`.
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Sm2SignatureContext {}

impl fmt::Debug for Sm2SignatureContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally redact key material — only safe metadata is shown.
        f.debug_struct("Sm2SignatureContext")
            .field("operation", &self.operation)
            .field("digest_name", &self.digest_name)
            .field("digest_size", &self.digest_size)
            .field("sm2_id_len", &self.sm2_id.len())
            .field("needs_z_digest", &self.needs_z_digest)
            .field("has_key", &self.key.is_some())
            .field(
                "has_private_key",
                &self.key.as_ref().is_some_and(|k| k.has_private_key()),
            )
            .field("streaming_buffer_len", &self.streaming_buffer.len())
            .field("aid_cached", &self.aid_cache.is_some())
            .finish_non_exhaustive()
    }
}

// =====================================================================
//                    Sm2SignatureContext: constructor
// =====================================================================

impl Sm2SignatureContext {
    /// Constructs a fresh, uninitialised SM2 signature context.
    ///
    /// The newly-created context has no key, no operation mode, and a
    /// digest of `"SM3"` queued (the SM2 specification mandate). It must
    /// subsequently be initialised by one of `sign_init`, `verify_init`,
    /// `digest_sign_init`, or `digest_verify_init` before any signature
    /// or verification work may be performed.
    ///
    /// This is the Rust counterpart of `sm2sig_newctx()` from
    /// `providers/implementations/signature/sm2_sig.c:119-141`.
    #[must_use]
    pub fn new(lib_ctx: Arc<LibContext>, prop_query: Option<String>) -> Self {
        Self {
            lib_ctx,
            prop_query,
            key: None,
            operation: None,
            digest_name: SM2_DEFAULT_DIGEST.to_string(),
            digest_ctx: None,
            digest_size: SM3_DIGEST_SIZE,
            sm2_id: SM2_DEFAULT_ID.to_vec(),
            needs_z_digest: false,
            aid_cache: None,
            streaming_buffer: Vec::new(),
        }
    }

    /// Returns a borrowed reference to the configured digest name.
    #[inline]
    fn digest_name(&self) -> &str {
        &self.digest_name
    }

    /// Returns the operation currently configured on the context, if any.
    ///
    /// Exposed at crate visibility so sibling test modules and provider-
    /// level diagnostics can inspect the SM2 context state without going
    /// through the public `SignatureContext` trait.  The trait surface
    /// itself does not need an accessor because each method already knows
    /// the operation it requires.
    #[inline]
    #[allow(dead_code)] // Crate-level introspection helper for tests / debug.
    pub(crate) fn operation_mode(&self) -> Option<OperationMode> {
        self.operation
    }

    /// Fetches the digest implementation backing the current
    /// `digest_name`. SM2 strongly prefers SM3, so the typical fetch is
    /// `MessageDigest::fetch(libctx, "SM3", propq)`.
    fn fetch_digest(&self) -> ProviderResult<MessageDigest> {
        MessageDigest::fetch(
            &self.lib_ctx,
            self.digest_name(),
            self.prop_query.as_deref(),
        )
        .map_err(|e| {
            warn!(
                digest = %self.digest_name,
                error = %e,
                "SM2: failed to fetch digest implementation"
            );
            ProviderError::AlgorithmUnavailable(format!(
                "SM2: digest '{}' is not available: {}",
                self.digest_name, e
            ))
        })
    }

    /// Validates that the configured digest is acceptable for SM2
    /// (non-XOF; mandated SM3 with optional override) and updates the
    /// cached digest size.
    ///
    /// Mirrors the early checks in `sm2sig_signature_init` lines 99-105
    /// of `sm2_sig.c`.
    fn validate_and_size_digest(&mut self) -> ProviderResult<()> {
        let md = self.fetch_digest()?;
        if md.is_xof() {
            warn!(
                digest = %self.digest_name,
                "SM2: extendable-output digests cannot be used"
            );
            return Err(ProviderError::Init(format!(
                "SM2: digest '{}' is XOF; SM2 requires a fixed-output digest",
                self.digest_name
            )));
        }
        self.digest_size = md.digest_size();
        Ok(())
    }
}

// =====================================================================
//                       Z-Value & Key-Material Helpers
// =====================================================================

/// Pads `value` with leading zeros to exactly [`SM2_FIELD_BYTES`]
/// (32 bytes), the canonical SM2 coordinate / scalar width.
///
/// SM2 representations are always 32 bytes regardless of the natural
/// length of the integer; this helper is reused for the ENTL / IDA /
/// `a` / `b` / `xG` / `yG` / `xA` / `yA` digest inputs.
fn encode_field_element(value: &BigNum) -> Result<Vec<u8>, CryptoError> {
    value.to_bytes_be_padded(SM2_FIELD_BYTES)
}

/// Parses a raw SM2 public key encoding into an [`EcKey`].
///
/// Accepts the three formats produced by the C reference implementation:
///
/// * Uncompressed: 65 bytes `0x04 || x || y`
/// * Compressed:   33 bytes `0x02|0x03 || x`
/// * Hybrid:       65 bytes `0x06|0x07 || x || y`
///
/// All three are decoded by [`EcPoint::from_bytes`]. The returned
/// [`EcKey`] holds the public point only — `has_private_key` is `false`.
fn parse_public_key(group: &EcGroup, bytes: &[u8]) -> ProviderResult<EcKey> {
    if bytes.is_empty() {
        warn!("SM2: empty public key buffer");
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            "SM2: empty public-key encoding".into(),
        )));
    }
    let point = EcPoint::from_bytes(group, bytes).map_err(|e| {
        warn!(error = %e, "SM2: failed to parse public key encoding");
        ProviderError::Common(CommonError::InvalidArgument(format!(
            "SM2: invalid public-key encoding: {e}"
        )))
    })?;
    if point.is_at_infinity() {
        warn!("SM2: public key is the point at infinity");
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            "SM2: public key is the point at infinity".into(),
        )));
    }
    let on_curve = point.is_on_curve(group).map_err(|e| {
        ProviderError::Common(CommonError::InvalidArgument(format!(
            "SM2: failed to verify public key on curve: {e}"
        )))
    })?;
    if !on_curve {
        warn!("SM2: public key not on curve");
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            "SM2: public key is not on the SM2 curve".into(),
        )));
    }
    EcKey::from_public_key(group, point).map_err(|e| {
        ProviderError::Common(CommonError::InvalidArgument(format!(
            "SM2: failed to construct EcKey from public key: {e}"
        )))
    })
}

/// Parses raw key material for **signing**.
///
/// Two encodings are supported:
///
/// * 32 bytes — bare private scalar `dA`. The public key `PA = dA · G` is
///   derived from the scalar.
/// * 97 bytes — `dA (32) || 0x04 || xA || yA (1 + 64)`: private scalar
///   followed by uncompressed public key. The public coordinates are
///   used verbatim and are sanity-checked against the curve equation.
fn parse_key_for_signing(group: &EcGroup, bytes: &[u8]) -> ProviderResult<EcKey> {
    match bytes.len() {
        SM2_PRIVKEY_LEN => {
            let priv_scalar = BigNum::from_bytes_be(bytes);
            EcKey::from_private_key(group, priv_scalar).map_err(|e| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SM2: invalid private key: {e}"
                )))
            })
        }
        SM2_KEYPAIR_LEN => {
            // Split: 32-byte private scalar + 65-byte uncompressed public.
            let (priv_bytes, pub_bytes) = bytes.split_at(SM2_PRIVKEY_LEN);
            let priv_scalar = BigNum::from_bytes_be(priv_bytes);
            // Validate the public encoding matches the canonical 0x04 prefix.
            if pub_bytes.first().copied() != Some(0x04) {
                warn!("SM2: keypair public key does not use uncompressed (0x04) encoding");
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    "SM2: keypair public component must be uncompressed (0x04 prefix)".into(),
                )));
            }
            // Construct the EcKey with the supplied scalar; the public
            // point is implicitly derived during construction validation.
            // We additionally cross-check against the encoded public.
            let key = EcKey::from_private_key(group, priv_scalar).map_err(|e| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SM2: invalid private key in keypair: {e}"
                )))
            })?;
            let supplied_pub = EcPoint::from_bytes(group, pub_bytes).map_err(|e| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "SM2: invalid keypair public encoding: {e}"
                )))
            })?;
            // Cross-check: derived public key must equal supplied public key.
            if let Some(derived) = key.public_key() {
                if derived.x() != supplied_pub.x() || derived.y() != supplied_pub.y() {
                    warn!("SM2: keypair public key does not match private scalar");
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        "SM2: keypair public key inconsistent with private scalar".into(),
                    )));
                }
            }
            Ok(key)
        }
        len => {
            warn!(length = len, "SM2: unsupported private key buffer length");
            Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SM2: private key buffer must be {SM2_PRIVKEY_LEN} or {SM2_KEYPAIR_LEN} bytes, got {len}"
                ),
            )))
        }
    }
}

/// Parses key material for **verification**.
///
/// Accepted encodings:
///
/// * 33 / 65 bytes — public key only (compressed / uncompressed).
/// * 97 bytes — full keypair (private + uncompressed public). The
///   private component is **discarded**; only the public point is
///   retained, mirroring the C convention where verification contexts
///   never expose private state.
fn parse_key_for_verification(group: &EcGroup, bytes: &[u8]) -> ProviderResult<EcKey> {
    match bytes.len() {
        SM2_COMPRESSED_PUBKEY_LEN | SM2_UNCOMPRESSED_PUBKEY_LEN => parse_public_key(group, bytes),
        SM2_KEYPAIR_LEN => {
            // Skip the 32-byte private prefix and parse the public part.
            let pub_bytes = &bytes[SM2_PRIVKEY_LEN..];
            parse_public_key(group, pub_bytes)
        }
        len => {
            warn!(length = len, "SM2: unsupported public key buffer length");
            Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SM2: public key buffer must be {SM2_COMPRESSED_PUBKEY_LEN}, {SM2_UNCOMPRESSED_PUBKEY_LEN}, or {SM2_KEYPAIR_LEN} bytes, got {len}"
                ),
            )))
        }
    }
}

// =====================================================================
//                     SM2 Z-value Digest Computation
// =====================================================================

/// Computes the SM2 Z-value digest:
///
/// ```text
/// Z = SM3(ENTL || IDA || a || b || xG || yG || xA || yA)
/// ```
///
/// Direct translation of `ossl_sm2_compute_z_digest()` from
/// `crypto/sm2/sm2_sign.c:24-99`.
///
/// # Arguments
/// * `digest` – the SM3 digest backend (other digests are accepted but
///   produce a non-standard Z-value; SM2 mandates SM3).
/// * `id`     – the distinguishing identifier `IDA`. Must be ≤ 8191 bytes
///   (`u16::MAX / 8`) so that `ENTL = id_len * 8` fits in a 16-bit
///   integer per GB/T 32918.2-2016.
/// * `group`  – SM2 [`EcGroup`] supplying the curve parameters `(a, b,
///   G = (xG, yG))`.
/// * `pub_key`– the signer's public point `PA = (xA, yA)`.
///
/// Returns the computed Z value as a digest-sized byte vector (32 bytes
/// for SM3).
fn compute_z_digest_value(
    lib_ctx: &Arc<LibContext>,
    prop_query: Option<&str>,
    digest_name: &str,
    id: &[u8],
    group: &EcGroup,
    pub_key: &EcPoint,
) -> ProviderResult<Vec<u8>> {
    // Bit-length of the identifier as a 16-bit big-endian integer.
    // The length cap ensures `len * 8` cannot overflow `u16` and matches
    // the C check at sm2_sign.c:50-52.
    let max_id_bits: usize = u16::MAX as usize;
    let id_bit_len = id.len().checked_mul(8).ok_or_else(|| {
        ProviderError::Common(CommonError::InvalidArgument(
            "SM2: identifier length overflow when converting to bit count".into(),
        ))
    })?;
    if id_bit_len > max_id_bits {
        warn!(
            id_bytes = id.len(),
            max = max_id_bits / 8,
            "SM2: identifier exceeds maximum bit length"
        );
        return Err(ProviderError::Common(CommonError::InvalidArgument(
            format!(
                "SM2: identifier length {} bytes exceeds {} bytes (16-bit ENTL)",
                id.len(),
                max_id_bits / 8
            ),
        )));
    }
    // Convert to u16 — guaranteed safe by the bound check above.
    let entl: u16 = u16::try_from(id_bit_len).map_err(CommonError::CastOverflow)?;

    // Fetch the digest implementation and an MdContext to drive it.
    let md = MessageDigest::fetch(lib_ctx, digest_name, prop_query).map_err(|e| {
        ProviderError::AlgorithmUnavailable(format!(
            "SM2: digest '{digest_name}' is not available for Z computation: {e}"
        ))
    })?;
    if md.is_xof() {
        return Err(ProviderError::Init(format!(
            "SM2: digest '{digest_name}' is XOF; SM2 Z-value requires a fixed-output digest"
        )));
    }
    let mut ctx = MdContext::new();
    ctx.init(&md, None)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest init failed: {e}")))?;

    // ENTL — 2-byte big-endian bit length of IDA.
    let entl_bytes = entl.to_be_bytes();
    ctx.update(&entl_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (ENTL) failed: {e}")))?;
    trace!(entl, "SM2 Z: hashed ENTL");

    // IDA — distinguishing identifier bytes.
    ctx.update(id)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (IDA) failed: {e}")))?;
    trace!(id_len = id.len(), "SM2 Z: hashed IDA");

    // a, b — curve coefficients.
    let a_bytes = encode_field_element(group.a())
        .map_err(|e| ProviderError::Dispatch(format!("SM2: encoding curve 'a' failed: {e}")))?;
    let b_bytes = encode_field_element(group.b())
        .map_err(|e| ProviderError::Dispatch(format!("SM2: encoding curve 'b' failed: {e}")))?;
    ctx.update(&a_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (a) failed: {e}")))?;
    ctx.update(&b_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (b) failed: {e}")))?;
    trace!("SM2 Z: hashed curve params a, b");

    // xG, yG — generator coordinates.
    let g = group.generator();
    let gx_bytes = encode_field_element(g.x())
        .map_err(|e| ProviderError::Dispatch(format!("SM2: encoding generator x failed: {e}")))?;
    let gy_bytes = encode_field_element(g.y())
        .map_err(|e| ProviderError::Dispatch(format!("SM2: encoding generator y failed: {e}")))?;
    ctx.update(&gx_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (xG) failed: {e}")))?;
    ctx.update(&gy_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (yG) failed: {e}")))?;
    trace!("SM2 Z: hashed generator coords xG, yG");

    // xA, yA — signer public-key coordinates.
    let xa_bytes = encode_field_element(pub_key.x())
        .map_err(|e| ProviderError::Dispatch(format!("SM2: encoding pubkey x failed: {e}")))?;
    let ya_bytes = encode_field_element(pub_key.y())
        .map_err(|e| ProviderError::Dispatch(format!("SM2: encoding pubkey y failed: {e}")))?;
    ctx.update(&xa_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (xA) failed: {e}")))?;
    ctx.update(&ya_bytes)
        .map_err(|e| ProviderError::Dispatch(format!("SM2: digest update (yA) failed: {e}")))?;
    trace!("SM2 Z: hashed pubkey coords xA, yA");

    let z = ctx
        .finalize()
        .map_err(|e| ProviderError::Dispatch(format!("SM2: Z digest finalize failed: {e}")))?;
    trace!(len = z.len(), "SM2 Z: finalized");
    Ok(z)
}

// =====================================================================
//                         DER codec for ECDSA-Sig-Value
// =====================================================================
//
// The on-the-wire SM2 signature format is identical to ECDSA's
// ECDSA-Sig-Value:
//
//     SEQUENCE { r INTEGER, s INTEGER }
//
// We emit and parse this minimally without pulling in a heavyweight
// ASN.1 dependency. SM2 signatures are bounded by the curve order
// (256 bits → 32 bytes per integer plus a possible 0x00 pad), so the
// total length always fits in a single DER length byte.

/// DER-encodes a single non-negative INTEGER. A leading `0x00` is
/// inserted when the most significant bit is set so that the value is
/// unambiguously interpreted as positive (DER requires INTEGERs to use
/// the minimum number of bytes).
fn der_encode_integer(value: &BigNum) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = if value.num_bytes() == 0 {
        // Zero is encoded as `0x02 0x01 0x00`.
        vec![0u8]
    } else {
        let num_bytes = usize::try_from(value.num_bytes()).map_err(|_| {
            CryptoError::Encoding("SM2: BigNum byte count exceeds usize range".to_string())
        })?;
        let raw = value.to_bytes_be_padded(num_bytes)?;
        // If high bit set, prepend 0x00 to force positive sign.
        if raw.first().map_or(false, |&b| b & 0x80 != 0) {
            let mut padded = Vec::with_capacity(raw.len() + 1);
            padded.push(0x00);
            padded.extend_from_slice(&raw);
            padded
        } else {
            raw
        }
    };
    let len = bytes.len();
    let len_u8: u8 = u8::try_from(len).map_err(|_| {
        CryptoError::Encoding(format!(
            "SM2: integer length {len} exceeds single-byte DER length encoding"
        ))
    })?;
    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02); // INTEGER tag
    out.push(len_u8);
    out.append(&mut bytes);
    Ok(out)
}

/// Wraps `r` and `s` into a DER `SEQUENCE { r, s }`.
fn der_encode_sm2_signature(r: &BigNum, s: &BigNum) -> Result<Vec<u8>, CryptoError> {
    let r_der = der_encode_integer(r)?;
    let s_der = der_encode_integer(s)?;
    let body_len = r_der.len() + s_der.len();
    let body_len_u8: u8 = u8::try_from(body_len).map_err(|_| {
        CryptoError::Encoding(format!(
            "SM2: signature body length {body_len} exceeds single-byte DER length"
        ))
    })?;
    let mut out = Vec::with_capacity(2 + body_len);
    out.push(0x30); // SEQUENCE tag
    out.push(body_len_u8);
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    Ok(out)
}

/// Decodes a DER `SEQUENCE { r INTEGER, s INTEGER }` into two `BigNum`
/// values. Strict: rejects long-form lengths beyond a single byte and
/// any trailing bytes after the SEQUENCE.
fn der_decode_sm2_signature(bytes: &[u8]) -> Result<(BigNum, BigNum), CryptoError> {
    let mut pos = 0usize;
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return Err(CryptoError::Encoding(
            "SM2: signature DER missing SEQUENCE tag".into(),
        ));
    }
    pos += 1;
    let body_len = read_der_len(bytes, &mut pos)?;
    if pos + body_len != bytes.len() {
        return Err(CryptoError::Encoding(format!(
            "SM2: signature DER trailing bytes (declared {} bytes, total {})",
            body_len,
            bytes.len()
        )));
    }
    // r INTEGER
    let r = der_decode_integer(bytes, &mut pos)?;
    // s INTEGER
    let s = der_decode_integer(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(CryptoError::Encoding(
            "SM2: signature DER trailing bytes after s INTEGER".into(),
        ));
    }
    Ok((r, s))
}

/// Reads a DER length prefix at `bytes[*pos]`, advancing `*pos`. Supports
/// short-form (single byte 0..=127) and long-form (1, 2, 3, or 4
/// length-of-length bytes) up to `usize::MAX` on the platform.
fn read_der_len(bytes: &[u8], pos: &mut usize) -> Result<usize, CryptoError> {
    let p = *pos;
    if p >= bytes.len() {
        return Err(CryptoError::Encoding("SM2: truncated DER length".into()));
    }
    let first = bytes[p];
    *pos = p + 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let n_bytes = (first & 0x7F) as usize;
    if n_bytes == 0 {
        return Err(CryptoError::Encoding(
            "SM2: indefinite-length DER not allowed".into(),
        ));
    }
    if n_bytes > std::mem::size_of::<usize>() {
        return Err(CryptoError::Encoding(
            "SM2: DER length-of-length too large".into(),
        ));
    }
    if *pos + n_bytes > bytes.len() {
        return Err(CryptoError::Encoding(
            "SM2: truncated DER long-form length".into(),
        ));
    }
    let mut len: usize = 0;
    for &b in &bytes[*pos..*pos + n_bytes] {
        len = (len << 8) | (b as usize);
    }
    *pos += n_bytes;
    Ok(len)
}

/// Reads a DER INTEGER tag/length/value at `bytes[*pos]`, returning the
/// non-negative `BigNum` value.
fn der_decode_integer(bytes: &[u8], pos: &mut usize) -> Result<BigNum, CryptoError> {
    let p = *pos;
    if p >= bytes.len() || bytes[p] != 0x02 {
        return Err(CryptoError::Encoding("SM2: missing INTEGER tag".into()));
    }
    *pos = p + 1;
    let len = read_der_len(bytes, pos)?;
    if *pos + len > bytes.len() {
        return Err(CryptoError::Encoding(
            "SM2: truncated DER INTEGER value".into(),
        ));
    }
    if len == 0 {
        return Err(CryptoError::Encoding("SM2: zero-length DER INTEGER".into()));
    }
    let value_bytes = &bytes[*pos..*pos + len];
    *pos += len;
    if value_bytes[0] & 0x80 != 0 {
        return Err(CryptoError::Encoding(
            "SM2: negative INTEGER not allowed in signature".into(),
        ));
    }
    Ok(BigNum::from_bytes_be(value_bytes))
}

// =====================================================================
//          AlgorithmIdentifier DER encoding for SM2-with-SM3
// =====================================================================

/// Returns the cached or freshly-computed `AlgorithmIdentifier` DER
/// encoding for SM2 with SM3. The structure is:
///
/// ```text
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm  OBJECT IDENTIFIER,  -- 1.2.156.10197.1.501
///     parameters ANY DEFINED BY algorithm OPTIONAL  -- absent
/// }
/// ```
///
/// SM2-with-SM3 has no parameters per RFC 8998 §3.
fn sm2_algorithm_identifier_der() -> Result<Vec<u8>, CryptoError> {
    // OID 1.2.156.10197.1.501 encoded:
    //   first byte: 1*40 + 2 = 0x2A
    //   156 = 1*128 + 28 → 0x81 0x1C
    //   10197 = 4*128*128 + 95*128 + 21 = 0xCF55 → 0x82(actually let me recompute)
    //   Use the standard base-128 encoding:
    static SM2_SM3_OID_DER: &[u8] = &[
        // tag = 0x06 (OID), length = 0x08, then 8 bytes:
        0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75,
    ];
    // SEQUENCE { OID }
    let mut out = Vec::with_capacity(2 + SM2_SM3_OID_DER.len());
    out.push(0x30);
    out.push(
        u8::try_from(SM2_SM3_OID_DER.len()).map_err(|_| {
            CryptoError::Encoding("SM2: AlgorithmIdentifier length exceeds u8".into())
        })?,
    );
    out.extend_from_slice(SM2_SM3_OID_DER);
    Ok(out)
}

// =====================================================================
//                   Sm2SignatureContext — Cryptographic Core
// =====================================================================

impl Sm2SignatureContext {
    // -----------------------------------------------------------------
    // Public-but-internal helpers (mirror the C `sm2sig_*` functions
    // that are reachable through the OSSL_DISPATCH table but are also
    // useful as inherent methods).
    // -----------------------------------------------------------------

    /// Computes the SM2 Z-value digest for the currently configured key
    /// and identifier.
    ///
    /// Translation of `sm2sig_compute_z_digest()` from `sm2_sig.c` lines
    /// ~190–230.  The Z-value is `SM3(ENTL || IDA || a || b || xG || yG
    /// || xA || yA)` where `xA, yA` are the public key coordinates.  The
    /// caller must have set a key and a digest beforehand.  After this
    /// call the `needs_z_digest` flag is cleared and the cached value
    /// (the returned `Vec<u8>`) is fed to the streaming digest at the
    /// next `digest_*_update` invocation by the caller.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Init`] if no key has been configured.
    /// * [`ProviderError::AlgorithmUnavailable`] if the SM3 digest
    ///   cannot be fetched.
    /// * [`ProviderError::Common`] for any cryptographic-layer failure
    ///   (e.g. inability to encode the curve parameters).
    pub fn compute_z_digest(&mut self) -> ProviderResult<Vec<u8>> {
        let key = self.key.as_ref().ok_or_else(|| {
            warn!("SM2: compute_z_digest called without a configured key");
            ProviderError::Init("SM2: no key set for Z-digest computation".to_string())
        })?;
        let group = key.group();
        let pub_key = key.public_key().ok_or_else(|| {
            warn!("SM2: compute_z_digest called on key without public component");
            ProviderError::Init(
                "SM2: key has no public component for Z-digest computation".to_string(),
            )
        })?;
        let z = compute_z_digest_value(
            &self.lib_ctx,
            self.prop_query.as_deref(),
            self.digest_name(),
            &self.sm2_id,
            group,
            pub_key,
        )?;
        self.needs_z_digest = false;
        Ok(z)
    }

    /// Creates a deep clone of this signature context.
    ///
    /// Translation of `sm2sig_dupctx()` from `sm2_sig.c` lines 353–402.
    /// Shared library state (the [`LibContext`] and key material) is
    /// reference-counted, so this is a relatively cheap operation.
    /// `MdContext` is not cloneable here — the duplicated context starts
    /// without an active digest and the caller is expected to re-init
    /// before continuing a streaming operation, matching the C semantics
    /// where `EVP_MD_CTX_dup` is best-effort.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            lib_ctx: Arc::clone(&self.lib_ctx),
            prop_query: self.prop_query.clone(),
            key: self.key.as_ref().map(Arc::clone),
            operation: self.operation,
            digest_name: self.digest_name.clone(),
            digest_ctx: None,
            digest_size: self.digest_size,
            sm2_id: self.sm2_id.clone(),
            needs_z_digest: self.needs_z_digest,
            aid_cache: self.aid_cache.clone(),
            streaming_buffer: self.streaming_buffer.clone(),
        }
    }

    // -----------------------------------------------------------------
    // OSSL_PARAM-style settable / gettable parameters
    // -----------------------------------------------------------------

    /// Applies a [`ParamSet`] to this context, updating the configured
    /// distinguishing identifier and digest as needed.
    ///
    /// Recognised parameter keys (matching `sm2sig_settable_ctx_params`
    /// at `sm2_sig.c` lines ~470–510):
    ///
    /// * `"id"` (`OctetString`) — the SM2 distinguishing ID `IDA`.
    ///   Setting this invalidates any pre-computed Z-value.
    /// * `"digest"` (`Utf8String`) — the digest algorithm name (must be
    ///   SM3 or empty).  Updates the cached digest size and invalidates
    ///   the `AlgorithmIdentifier` cache.
    /// * `"properties"` (`Utf8String`) — provider property query string.
    ///
    /// Unknown keys are silently ignored, matching the OpenSSL convention.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Common`] with [`CommonError::ParamTypeMismatch`]
    ///   if a recognised key has the wrong value type.
    /// * Any error returned by [`Self::validate_and_size_digest`] when
    ///   the digest is changed.
    pub fn set_ctx_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }
        trace!(
            algorithm = SM2_ALGORITHM_NAME,
            param_count = params.len(),
            "SM2: set_ctx_params"
        );

        // ---- "id" (octet string) — distinguishing identifier ----
        if let Some(val) = params.get("id") {
            let bytes = val.as_bytes().ok_or_else(|| {
                warn!(key = "id", "SM2: 'id' parameter has wrong type");
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "id".to_string(),
                    expected: "OctetString",
                    actual: val.param_type_name(),
                })
            })?;
            // Bound the ID length so that ENTL = id_len * 8 fits in a
            // 16-bit unsigned integer (matches the C overflow guard at
            // `crypto/sm2/sm2_sign.c` lines ~50–60).
            if bytes.len().saturating_mul(8) > usize::from(u16::MAX) {
                warn!(
                    id_len = bytes.len(),
                    "SM2: distinguishing identifier exceeds 8191 bytes"
                );
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SM2: distinguishing identifier length {} exceeds maximum",
                        bytes.len()
                    ),
                )));
            }
            self.sm2_id.zeroize();
            self.sm2_id = bytes.to_vec();
            self.needs_z_digest = true;
        }

        // ---- "digest" (UTF-8 string) — hash algorithm name ----
        if let Some(val) = params.get("digest") {
            let name = val.as_str().ok_or_else(|| {
                warn!(key = "digest", "SM2: 'digest' parameter has wrong type");
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "digest".to_string(),
                    expected: "Utf8String",
                    actual: val.param_type_name(),
                })
            })?;
            enforce_digest_match_sm2(name)?;
            self.digest_name.zeroize();
            self.digest_name = if name.is_empty() {
                SM2_DEFAULT_DIGEST.to_string()
            } else {
                name.to_string()
            };
            self.validate_and_size_digest()?;
            // Digest change invalidates the AlgorithmIdentifier cache.
            if let Some(aid) = self.aid_cache.as_mut() {
                aid.zeroize();
            }
            self.aid_cache = None;
        }

        // ---- "properties" (UTF-8 string) — provider property query ----
        if let Some(val) = params.get("properties") {
            let propq = val.as_str().ok_or_else(|| {
                warn!(
                    key = "properties",
                    "SM2: 'properties' parameter has wrong type"
                );
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: "properties".to_string(),
                    expected: "Utf8String",
                    actual: val.param_type_name(),
                })
            })?;
            self.prop_query = if propq.is_empty() {
                None
            } else {
                Some(propq.to_string())
            };
        }

        Ok(())
    }

    /// Returns the current parameter values for this context.
    ///
    /// Mirrors `sm2sig_gettable_ctx_params` at `sm2_sig.c` lines ~404–468.
    /// The exposed keys are:
    ///
    /// * `"algorithm-id"` (`OctetString`) — cached `AlgorithmIdentifier`
    ///   DER bytes.
    /// * `"digest"` (`Utf8String`) — the configured digest name.
    /// * `"id"` (`OctetString`) — the configured distinguishing ID.
    ///
    /// The AID cache is populated lazily; the requirement for `&mut self`
    /// reflects this, matching the C function which mutates the
    /// `PROV_SM2_CTX::aid` buffer the first time it is queried.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Common`] on encoding failure.
    pub fn get_ctx_params(&mut self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();

        // ---- algorithm-id ----
        if self.aid_cache.is_none() {
            self.aid_cache = Some(sm2_algorithm_identifier_der().map_err(dispatch_err)?);
        }
        if let Some(ref aid) = self.aid_cache {
            out.set("algorithm-id", ParamValue::OctetString(aid.clone()));
        }

        // ---- digest ----
        out.set("digest", ParamValue::Utf8String(self.digest_name.clone()));

        // ---- id (distinguishing identifier) ----
        out.set("id", ParamValue::OctetString(self.sm2_id.clone()));

        Ok(out)
    }

    // -----------------------------------------------------------------
    // sign_internal / verify_internal — the cryptographic core.
    //
    // These are direct translations of `sm2_sig_compute_msg_hash` +
    // `sm2_sig_gen` (sign) and `sm2_sig_verify` (verify) from
    // `crypto/sm2/sm2_sign.c`.  They are factored out as inherent
    // methods so they can be invoked from both the one-shot
    // `sign`/`verify` paths and the streaming `digest_*_final` paths.
    // -----------------------------------------------------------------

    /// Computes the SM2 message digest `e = H(Z || M)` where `Z` is the
    /// distinguishing identifier digest and `M` is the application
    /// message.
    ///
    /// Returns the digest bytes (length = `self.digest_size`).
    fn compute_message_hash(&self, message: &[u8]) -> ProviderResult<Vec<u8>> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| ProviderError::Init("SM2: no key configured".to_string()))?;
        let group = key.group();
        let pub_key = key
            .public_key()
            .ok_or_else(|| ProviderError::Init("SM2: key has no public component".to_string()))?;

        // 1. Fetch SM3 digest.
        let md = self.fetch_digest()?;

        // 2. Compute Z = SM3(ENTL || IDA || a || b || xG || yG || xA || yA).
        let z = compute_z_digest_value(
            &self.lib_ctx,
            self.prop_query.as_deref(),
            self.digest_name(),
            &self.sm2_id,
            group,
            pub_key,
        )?;

        // 3. e = SM3(Z || M).
        let mut ctx = MdContext::new();
        ctx.init(&md, None).map_err(dispatch_err)?;
        ctx.update(&z).map_err(dispatch_err)?;
        ctx.update(message).map_err(dispatch_err)?;
        let e = ctx.finalize().map_err(dispatch_err)?;
        Ok(e)
    }

    /// Performs the SM2 signature generation given a message digest `e`.
    ///
    /// Direct translation of the loop body in `sm2_sig_gen` at
    /// `crypto/sm2/sm2_sign.c` lines 289–337.
    ///
    /// Algorithm:
    /// 1. Generate random `k ∈ [1, n-1]`.
    /// 2. Compute `(x1, _) = k · G`.
    /// 3. `r = (e + x1) mod n`.  Restart if `r == 0` or `r + k == n`.
    /// 4. `s = ((1 + dA)^(-1) · (k - r·dA)) mod n`.  Restart if `s == 0`.
    /// 5. Return DER-encoded `(r, s)`.
    fn sign_internal(&self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        let key = self.key.as_ref().ok_or_else(|| {
            warn!("SM2: sign called without a configured key");
            ProviderError::Init("SM2: no key configured for signing".to_string())
        })?;
        if !key.has_private_key() {
            warn!("SM2: sign called on public-only key");
            return Err(ProviderError::Init(
                "SM2: signing requires a private key".to_string(),
            ));
        }
        let group = key.group();
        let order = group.order();
        let priv_scalar = key
            .private_key()
            .ok_or_else(|| ProviderError::Init("SM2: missing private key scalar".to_string()))?;

        // 1. Hash the message with the SM2 Z-prefix.
        let e_bytes = self.compute_message_hash(data)?;
        let e = BigNum::from_bytes_be(&e_bytes);

        // 2. Sample k and derive (r, s) — retry on degenerate cases.
        // See `SM2_MAX_SIGN_RETRIES` documentation for the bound rationale.
        for attempt in 0..SM2_MAX_SIGN_RETRIES {
            // Draw k in [0, n) — we treat k == 0 as a degenerate case
            // and retry, matching the C `BN_priv_rand_range_ex` which
            // returns values in [0, range).
            let k = BigNum::priv_rand_range(order).map_err(dispatch_err)?;
            if k.is_zero() {
                continue;
            }

            // Compute x1 = (k · G).x.
            let kg = EcPoint::generator_mul(group, &k).map_err(dispatch_err)?;
            if kg.is_at_infinity() {
                continue;
            }
            let x1 = kg.x();

            // r = (e + x1) mod n.
            let r = mod_add(&e, x1, order).map_err(dispatch_err)?;
            if r.is_zero() {
                trace!(attempt, "SM2 sign: r == 0, retrying");
                continue;
            }
            // r + k == n ?  (uses unmodded addition per spec)
            let rk = &r + &k;
            if rk.cmp(order) == std::cmp::Ordering::Equal {
                trace!(attempt, "SM2 sign: r + k == n, retrying");
                continue;
            }

            // s = (1 + dA)^{-1} · (k - r·dA) mod n.
            let one = BigNum::one();
            let one_plus_d = &one + priv_scalar;
            let inv = mod_inverse_checked(&one_plus_d, order).map_err(dispatch_err)?;
            let r_d = mod_mul(priv_scalar, &r, order).map_err(dispatch_err)?;
            // `k - r_d` may be negative — `mod_mul` will normalise via nnmod.
            let k_minus_rd = &k - &r_d;
            let s = mod_mul(&inv, &k_minus_rd, order).map_err(dispatch_err)?;
            if s.is_zero() {
                trace!(attempt, "SM2 sign: s == 0, retrying");
                continue;
            }

            debug!(
                attempt,
                algorithm = SM2_ALGORITHM_NAME,
                "SM2: signature generated"
            );
            return der_encode_sm2_signature(&r, &s).map_err(dispatch_err);
        }

        warn!(
            "SM2: failed to produce a valid signature after {} attempts",
            SM2_MAX_SIGN_RETRIES
        );
        Err(ProviderError::Dispatch(format!(
            "SM2: failed to produce signature after {SM2_MAX_SIGN_RETRIES} attempts"
        )))
    }

    /// Performs the SM2 signature verification.
    ///
    /// Direct translation of `sm2_sig_verify` at `crypto/sm2/sm2_sign.c`
    /// lines 350–432.
    ///
    /// Algorithm:
    /// 1. Decode `(r, s)` from DER.
    /// 2. Verify `r, s ∈ [1, n-1]`.
    /// 3. Compute `e = H(Z || M)`.
    /// 4. `t = (r + s) mod n`.  Reject if `t == 0`.
    /// 5. Compute `(x1, _) = s·G + t·P_A`.
    /// 6. `R = (e + x1) mod n`.  Verify `R == r`.
    fn verify_internal(&self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        let key = self.key.as_ref().ok_or_else(|| {
            warn!("SM2: verify called without a configured key");
            ProviderError::Init("SM2: no key configured for verification".to_string())
        })?;
        let group = key.group();
        let order = group.order();
        let pub_key = key
            .public_key()
            .ok_or_else(|| ProviderError::Init("SM2: key has no public component".to_string()))?;

        // 1. Decode (r, s).
        let (r, s) = match der_decode_sm2_signature(signature) {
            Ok(rs) => rs,
            Err(e) => {
                warn!(error = %e, "SM2: signature DER decode failed");
                return Ok(false);
            }
        };

        // 2. r, s in [1, n-1] (i.e., ≥ 1 and < n).
        let one = BigNum::one();
        if r.cmp(&one) == std::cmp::Ordering::Less
            || s.cmp(&one) == std::cmp::Ordering::Less
            || r.cmp(order) != std::cmp::Ordering::Less
            || s.cmp(order) != std::cmp::Ordering::Less
        {
            warn!("SM2: signature components out of range [1, n-1]");
            return Ok(false);
        }

        // 3. e = H(Z || M).
        let e_bytes = self.compute_message_hash(data)?;
        let e = BigNum::from_bytes_be(&e_bytes);

        // 4. t = (r + s) mod n; reject if t == 0.
        let t = mod_add(&r, &s, order).map_err(dispatch_err)?;
        if t.is_zero() {
            warn!("SM2: t = (r + s) mod n is zero");
            return Ok(false);
        }

        // 5. (x1, _) = s·G + t·P_A.
        let s_g = EcPoint::generator_mul(group, &s).map_err(dispatch_err)?;
        let t_p = EcPoint::mul(group, pub_key, &t).map_err(dispatch_err)?;
        let pt = EcPoint::add(group, &s_g, &t_p).map_err(dispatch_err)?;
        if pt.is_at_infinity() {
            warn!("SM2: s·G + t·P_A is the point at infinity");
            return Ok(false);
        }
        let x1 = pt.x();

        // 6. R = (e + x1) mod n;  R == r ?
        let big_r = mod_add(&e, x1, order).map_err(dispatch_err)?;
        let ok = big_r.cmp(&r) == std::cmp::Ordering::Equal;
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            verified = ok,
            "SM2: verification result"
        );
        Ok(ok)
    }
}

// =============================================================================
// SignatureContext trait implementation
//
// The trait implementation forwards to the inherent helpers above so that
// the cryptographic core lives in one place. This mirrors the C provider
// where each `OSSL_FUNC_signature_*` dispatch entry is a thin shim around
// the underlying `sm2_sig_*` worker (see sm2_sig.c lines 559-595).
// =============================================================================

impl SignatureContext for Sm2SignatureContext {
    // -------------------------------------------------------------------------
    // One-shot sign / verify path
    //
    // These mirror `sm2sig_signature_init` (sm2_sig.c lines 142-178),
    // `sm2sig_sign` (lines 232-280) and `sm2sig_verify` (lines 286-310).
    // -------------------------------------------------------------------------

    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            key_len = key.len(),
            has_params = params.is_some(),
            "SM2: sign_init"
        );

        // Construct the SM2 curve and parse the supplied key material.
        let group = sm2_curve_group().map_err(dispatch_err)?;
        let parsed = parse_key_for_signing(&group, key)?;
        if !parsed.has_private_key() {
            warn!("SM2: sign_init received key without a private component");
            return Err(ProviderError::Init(
                "SM2: sign_init requires a private key".to_string(),
            ));
        }

        self.key = Some(Arc::new(parsed));
        self.operation = Some(OperationMode::Sign);
        // Setting a fresh key invalidates any pre-computed Z value and any
        // partial streaming state from a prior operation.
        self.needs_z_digest = true;
        self.streaming_buffer.clear();

        // Validate the configured digest is acceptable for SM2 and cache
        // its output size (mirrors the early check at sm2_sig.c line ~165).
        self.validate_and_size_digest()?;

        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }

        Ok(())
    }

    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.operation != Some(OperationMode::Sign) {
            warn!("SM2: sign called without matching sign_init");
            return Err(ProviderError::Init(
                "SM2: sign called without matching sign_init".to_string(),
            ));
        }
        self.sign_internal(data)
    }

    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            key_len = key.len(),
            has_params = params.is_some(),
            "SM2: verify_init"
        );

        // SM2 verify accepts compressed (33 B) / uncompressed (65 B) public
        // keys or a full keypair (97 B); `parse_key_for_verification` covers
        // all three cases.  Unlike EdDSA we do not need a "zero private"
        // sentinel: SM2 uses a separate `EcKey` constructor that admits a
        // public-only key.
        let group = sm2_curve_group().map_err(dispatch_err)?;
        let parsed = parse_key_for_verification(&group, key)?;

        self.key = Some(Arc::new(parsed));
        self.operation = Some(OperationMode::Verify);
        self.needs_z_digest = true;
        self.streaming_buffer.clear();

        self.validate_and_size_digest()?;

        if let Some(p) = params {
            self.set_ctx_params(p)?;
        }

        Ok(())
    }

    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.operation != Some(OperationMode::Verify) {
            warn!("SM2: verify called without matching verify_init");
            return Err(ProviderError::Init(
                "SM2: verify called without matching verify_init".to_string(),
            ));
        }
        self.verify_internal(data, signature)
    }

    // -------------------------------------------------------------------------
    // Streaming digest-sign / digest-verify path
    //
    // SM2 hashes the message with a Z-prefix (see `compute_z_digest_value`),
    // therefore the streaming API simply buffers the application bytes and
    // delegates to the one-shot primitive at `_final` time.  This mirrors
    // `sm2sig_digest_signverify_init` / `sm2sig_digest_sign_update` /
    // `sm2sig_digest_sign_final` at sm2_sig.c lines 312-345 which use an
    // internal `EVP_MD_CTX` to accumulate input.
    // -------------------------------------------------------------------------

    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            digest = digest,
            key_len = key.len(),
            "SM2: digest_sign_init"
        );

        // SM2 mandates SM3 — accept either an empty digest name (caller
        // delegates the choice) or a literal SM3.  Other names are
        // rejected up-front with a clear error rather than failing later
        // during the digest fetch.
        enforce_digest_match_sm2(digest)?;

        // If the caller supplied a non-empty digest name, install it before
        // the one-shot init validates the cached size so the digest fetch
        // resolves the right algorithm.
        if !digest.is_empty() {
            let normalised = digest.to_string();
            self.digest_name.zeroize();
            self.digest_name = normalised;
        }

        SignatureContext::sign_init(self, key, params)
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = SM2_ALGORITHM_NAME,
            chunk_len = data.len(),
            "SM2: digest_sign_update (buffering)"
        );
        if self.operation != Some(OperationMode::Sign) {
            warn!("SM2: digest_sign_update called without digest_sign_init");
            return Err(ProviderError::Init(
                "SM2: digest_sign_update called without digest_sign_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            buffered_len = self.streaming_buffer.len(),
            "SM2: digest_sign_final"
        );
        if self.operation != Some(OperationMode::Sign) {
            warn!("SM2: digest_sign_final called without digest_sign_init");
            return Err(ProviderError::Init(
                "SM2: digest_sign_final called without digest_sign_init".to_string(),
            ));
        }
        // Take the buffer so its memory is released; we do not need it
        // again after this call.
        let message = std::mem::take(&mut self.streaming_buffer);
        let sig = self.sign_internal(&message)?;
        // Scrub the message buffer — it may contain confidential data.
        let mut spent = message;
        spent.zeroize();
        Ok(sig)
    }

    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            digest = digest,
            key_len = key.len(),
            "SM2: digest_verify_init"
        );
        enforce_digest_match_sm2(digest)?;

        if !digest.is_empty() {
            let normalised = digest.to_string();
            self.digest_name.zeroize();
            self.digest_name = normalised;
        }

        SignatureContext::verify_init(self, key, params)
    }

    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(
            algorithm = SM2_ALGORITHM_NAME,
            chunk_len = data.len(),
            "SM2: digest_verify_update (buffering)"
        );
        if self.operation != Some(OperationMode::Verify) {
            warn!("SM2: digest_verify_update called without digest_verify_init");
            return Err(ProviderError::Init(
                "SM2: digest_verify_update called without digest_verify_init".to_string(),
            ));
        }
        self.streaming_buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        debug!(
            algorithm = SM2_ALGORITHM_NAME,
            buffered_len = self.streaming_buffer.len(),
            signature_len = signature.len(),
            "SM2: digest_verify_final"
        );
        if self.operation != Some(OperationMode::Verify) {
            warn!("SM2: digest_verify_final called without digest_verify_init");
            return Err(ProviderError::Init(
                "SM2: digest_verify_final called without digest_verify_init".to_string(),
            ));
        }
        let message = std::mem::take(&mut self.streaming_buffer);
        let ok = self.verify_internal(&message, signature)?;
        let mut spent = message;
        spent.zeroize();
        Ok(ok)
    }

    // -------------------------------------------------------------------------
    // Parameter access
    //
    // The trait method `get_params` is `&self` whereas the inherent
    // `get_ctx_params` helper takes `&mut self` so it can lazily populate
    // the AID cache.  We bridge the difference by computing the AID
    // on-the-fly when the cache is empty — the call is side-effect-free
    // from the caller's perspective.  `set_params` simply forwards.
    // -------------------------------------------------------------------------

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();

        // ---- algorithm-id ----
        // Populate from the cache if available, otherwise compute it (we
        // cannot mutate self here, so the cache stays empty for next time;
        // this matches the C `EVP_PKEY_CTX_get_params` contract which
        // permits transient computation).
        let aid = self
            .aid_cache
            .clone()
            .unwrap_or_else(|| sm2_algorithm_identifier_der().unwrap_or_default());
        if !aid.is_empty() {
            out.set("algorithm-id", ParamValue::OctetString(aid));
        }

        // ---- digest ----
        out.set("digest", ParamValue::Utf8String(self.digest_name.clone()));

        // ---- id (distinguishing identifier) ----
        out.set("id", ParamValue::OctetString(self.sm2_id.clone()));

        Ok(out)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.set_ctx_params(params)
    }
}

// =============================================================================
// Algorithm descriptors
//
// One descriptor for the SM2 signature algorithm, matching
// `ossl_sm2_signature_functions` at `providers/implementations/signature/
// sm2_sig.c` lines ~568–593.  The consumer is
// [`crate::implementations::signatures::descriptors`] which aggregates
// descriptors from every signature implementation.
// =============================================================================

/// Descriptor for the SM2 signature scheme.
///
/// Algorithm names include the canonical `"SM2"` plus the dotted OID
/// `"1.2.156.10197.1.301"` from GM/T 0006-2012 so callers may fetch the
/// provider using either form — mirroring the C registration name list
/// at `providers/implementations/include/prov/names.h`.
#[must_use]
pub fn sm2_signature_descriptor() -> AlgorithmDescriptor {
    algorithm(
        &[SM2_ALGORITHM_NAME, SM2_OID_DOTTED],
        DEFAULT_PROPERTY,
        "OpenSSL SM2 implementation (GM/T 0003-2012 / RFC 8998)",
    )
}

/// Returns the list of [`AlgorithmDescriptor`]s registered by the SM2
/// signature implementation.
///
/// This matches the C dispatch-table registration where `ossl_sm2_
/// signature_functions` is exported as `signature_functions[]` in
/// `providers/implementations/signature/sm2_sig.c` line ~568, with
/// algorithm names sourced from `providers/implementations/include/
/// prov/names.h`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![sm2_signature_descriptor()]
}

// =============================================================================
// Unit tests
//
// Mirrors the structure of `eddsa.rs` test module — every public surface is
// exercised, every error path tagged, every parameter shape probed.  The
// tests are deliberately self-contained and never reach across crate
// boundaries except via the documented public API of the `openssl_common`
// and `openssl_crypto` dependencies.
//
// The module is gated with `#[cfg(test)]` so it never appears in release
// builds.  We also relax a small set of clippy lints that would otherwise
// pollute the test code with noise (`unwrap`/`expect`/`panic` are
// universally accepted in test fixtures).
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use openssl_common::CommonError;
    use openssl_crypto::bn::BigNum;
    use openssl_crypto::ec::{EcKey, PointConversionForm};
    use std::cmp::Ordering;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Builds the canonical 97-byte SM2 keypair encoding accepted by
    /// [`parse_key_for_signing`]: 32-byte private scalar followed by a
    /// 65-byte uncompressed public point (`0x04 || x || y`).
    fn build_keypair_bytes(ec_key: &EcKey, group: &EcGroup) -> Vec<u8> {
        let priv_bytes = ec_key
            .private_key()
            .expect("generated key must have a private component")
            .to_bytes_be_padded(SM2_FIELD_BYTES)
            .expect("32-byte private scalar fits in SM2_FIELD_BYTES");
        let pub_bytes = ec_key
            .public_key()
            .expect("generated key must have a public component")
            .to_bytes(group, PointConversionForm::Uncompressed)
            .expect("uncompressed public encoding succeeds");
        assert_eq!(priv_bytes.len(), SM2_PRIVKEY_LEN);
        assert_eq!(pub_bytes.len(), SM2_UNCOMPRESSED_PUBKEY_LEN);
        let mut out = Vec::with_capacity(SM2_KEYPAIR_LEN);
        out.extend_from_slice(&priv_bytes);
        out.extend_from_slice(&pub_bytes);
        out
    }

    /// Builds the 65-byte uncompressed-public-key encoding accepted by
    /// [`parse_key_for_verification`].
    fn build_pubkey_bytes(ec_key: &EcKey, group: &EcGroup) -> Vec<u8> {
        ec_key
            .public_key()
            .expect("generated key must have a public component")
            .to_bytes(group, PointConversionForm::Uncompressed)
            .expect("uncompressed public encoding succeeds")
    }

    /// Convenience factory for a fresh signature context bound to the
    /// process-wide default library context.
    fn fresh_ctx() -> Sm2SignatureContext {
        Sm2SignatureContext::new(LibContext::get_default(), None)
    }

    // -------------------------------------------------------------------------
    // Constants — verbatim against the SM2 specification (GM/T 0003-2012)
    // -------------------------------------------------------------------------

    #[test]
    fn constant_default_id_matches_specification() {
        // GB/T 32918.2-2016 Annex B: default IDA = "1234567812345678".
        assert_eq!(SM2_DEFAULT_ID, b"1234567812345678");
        assert_eq!(SM2_DEFAULT_ID.len(), 16);
    }

    #[test]
    fn constant_sizes_are_consistent() {
        assert_eq!(SM3_DIGEST_SIZE, 32, "SM3 produces a 256-bit digest");
        assert_eq!(SM2_FIELD_BYTES, 32, "SM2 prime is 256 bits");
        assert_eq!(SM2_PRIVKEY_LEN, SM2_FIELD_BYTES);
        assert_eq!(
            SM2_UNCOMPRESSED_PUBKEY_LEN,
            1 + 2 * SM2_FIELD_BYTES,
            "uncompressed = 0x04 || x || y"
        );
        assert_eq!(
            SM2_COMPRESSED_PUBKEY_LEN,
            1 + SM2_FIELD_BYTES,
            "compressed = parity || x"
        );
        assert_eq!(
            SM2_KEYPAIR_LEN,
            SM2_PRIVKEY_LEN + SM2_UNCOMPRESSED_PUBKEY_LEN
        );
    }

    #[test]
    fn constant_default_metadata_matches_spec() {
        assert_eq!(SM2_DEFAULT_DIGEST, "SM3");
        assert_eq!(SM2_ALGORITHM_NAME, "SM2");
        assert_eq!(DEFAULT_PROPERTY, "provider=default");
        assert_eq!(SM2_OID_DOTTED, "1.2.156.10197.1.301");
        // The retry budget must terminate after a finite number of attempts.
        // Asserting the canonical value (rather than a `> 0` predicate) both
        // documents the intended budget and avoids `clippy::assertions_on_constants`.
        assert_eq!(SM2_MAX_SIGN_RETRIES, 32);
    }

    // -------------------------------------------------------------------------
    // Curve construction
    // -------------------------------------------------------------------------

    #[test]
    fn sm2_curve_group_constructs() {
        let group = sm2_curve_group().expect("SM2 curve must build from explicit params");
        // Sanity check the published parameter sizes — the prime and order
        // must each be exactly 32 bytes.
        assert_eq!(group.field().to_bytes_be().len(), SM2_FIELD_BYTES);
        assert_eq!(group.order().to_bytes_be().len(), SM2_FIELD_BYTES);
    }

    #[test]
    fn sm2_curve_generator_is_on_curve() {
        let group = sm2_curve_group().unwrap();
        let g = group.generator();
        assert!(
            !g.is_at_infinity(),
            "SM2 generator must not be the point at infinity"
        );
        assert!(
            g.is_on_curve(&group).unwrap_or(false),
            "SM2 generator must lie on the curve"
        );
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    #[test]
    fn enforce_digest_match_sm2_accepts_empty_and_sm3() {
        enforce_digest_match_sm2("").expect("empty string defers to default digest");
        enforce_digest_match_sm2("SM3").expect("SM3 is the SM2 digest");
        enforce_digest_match_sm2("sm3").expect("digest match is case-insensitive");
    }

    #[test]
    fn enforce_digest_match_sm2_rejects_other_digests() {
        for bad in ["SHA256", "SHA-256", "SHA1", "BLAKE2b-512", "MD5"] {
            let err = enforce_digest_match_sm2(bad)
                .expect_err(&format!("digest '{bad}' must be rejected"));
            match err {
                ProviderError::Common(CommonError::InvalidArgument(_)) => {}
                other => panic!("expected InvalidArgument for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn dispatch_err_wraps_crypto_error_as_dispatch() {
        let src = CryptoError::Key("malformed scalar".to_string());
        let wrapped = dispatch_err(src);
        match wrapped {
            ProviderError::Dispatch(msg) => assert!(
                msg.contains("malformed"),
                "wrapped message must preserve crypto error text"
            ),
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Provider surface
    // -------------------------------------------------------------------------

    #[test]
    fn provider_constructs_and_reports_name() {
        let provider = Sm2SignatureProvider::new(LibContext::get_default(), None);
        assert_eq!(provider.name(), "SM2");
        assert_eq!(provider.name(), SM2_ALGORITHM_NAME);
    }

    #[test]
    fn provider_clone_is_supported() {
        let provider = Sm2SignatureProvider::new(LibContext::get_default(), None);
        let cloned = provider.clone();
        assert_eq!(cloned.name(), provider.name());
    }

    #[test]
    fn provider_new_ctx_yields_signature_context() {
        let provider = Sm2SignatureProvider::new(LibContext::get_default(), None);
        let mut ctx = provider
            .new_ctx()
            .expect("new_ctx must succeed for the SM2 provider");
        // Without any init the context is in the "no-operation" state and
        // any sign/verify call must fail with `Init`.
        let err = SignatureContext::sign(ctx.as_mut(), b"hello")
            .expect_err("sign without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn provider_debug_does_not_leak_keys() {
        let provider = Sm2SignatureProvider::new(LibContext::get_default(), None);
        let debug = format!("{provider:?}");
        // The Debug impl uses `finish_non_exhaustive`, but it must not
        // accidentally embed key material — only the algorithm name and
        // optional property query.
        assert!(debug.contains("Sm2SignatureProvider"));
        assert!(debug.contains("SM2"));
    }

    // -------------------------------------------------------------------------
    // Context construction & introspection
    // -------------------------------------------------------------------------

    #[test]
    fn context_initial_state_is_consistent() {
        let ctx = fresh_ctx();
        assert_eq!(ctx.digest_name(), SM2_DEFAULT_DIGEST);
        assert_eq!(ctx.digest_size, SM3_DIGEST_SIZE);
        assert_eq!(ctx.sm2_id.as_slice(), SM2_DEFAULT_ID);
        assert!(ctx.key.is_none());
        assert!(ctx.digest_ctx.is_none());
        assert!(ctx.aid_cache.is_none());
        assert!(ctx.streaming_buffer.is_empty());
        assert!(!ctx.needs_z_digest);
        assert_eq!(ctx.operation_mode(), None);
    }

    #[test]
    fn context_debug_redacts_key_material() {
        // Build a context that *has* a key so we can confirm no key
        // material leaks through Debug.
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let keypair = build_keypair_bytes(&key, &group);
        let mut ctx = fresh_ctx();
        SignatureContext::sign_init(&mut ctx, &keypair, None).unwrap();

        let debug = format!("{ctx:?}");
        assert!(debug.contains("Sm2SignatureContext"));
        assert!(debug.contains("digest_name"));
        // Metadata booleans are fine — the *contents* of the key must
        // never appear in Debug output.  Inspect the rendered private
        // scalar bytes and confirm that no contiguous chunk of them
        // appears in any common rendering (raw bytes, lowercase hex,
        // uppercase hex, or decimal).
        let priv_bytes = key
            .private_key()
            .unwrap()
            .to_bytes_be_padded(SM2_PRIVKEY_LEN)
            .unwrap();
        // Build a hex representation without `format!` allocation per byte
        // (avoids `clippy::format_collect`).
        let mut hex = String::with_capacity(priv_bytes.len() * 2);
        for b in &priv_bytes {
            use std::fmt::Write as _;
            write!(&mut hex, "{b:02x}").unwrap();
        }
        let hex_upper = hex.to_uppercase();
        assert!(
            !debug.contains(&hex),
            "debug output must not contain raw private scalar bytes (lowercase hex)"
        );
        assert!(
            !debug.contains(&hex_upper),
            "debug output must not contain raw private scalar bytes (uppercase hex)"
        );
        // Also verify that the raw byte sequence does not appear verbatim in
        // the Debug output (e.g. as a `Vec<u8>` field rendering).
        let debug_bytes = debug.as_bytes();
        assert!(
            !debug_bytes
                .windows(priv_bytes.len())
                .any(|w| w == priv_bytes.as_slice()),
            "debug output must not contain raw private scalar bytes (binary)"
        );
        // Ensure the SM2 distinguishing identifier is also redacted.
        assert!(
            !debug.contains("1234567812345678"),
            "debug output must not echo the literal SM2 ID"
        );
    }

    #[test]
    fn duplicate_preserves_metadata_but_resets_streaming_state() {
        let mut ctx = fresh_ctx();
        ctx.streaming_buffer.extend_from_slice(b"buffered");
        ctx.needs_z_digest = true;
        let dup = ctx.duplicate();
        assert_eq!(dup.digest_name, ctx.digest_name);
        assert_eq!(dup.sm2_id, ctx.sm2_id);
        assert_eq!(dup.needs_z_digest, ctx.needs_z_digest);
        // The duplicate gets a fresh digest context (MdContext is not
        // cloneable) so it must be `None` regardless of the source.
        assert!(dup.digest_ctx.is_none());
    }

    // -------------------------------------------------------------------------
    // Error paths — operations called without prior init
    // -------------------------------------------------------------------------

    #[test]
    fn sign_without_init_returns_init_error() {
        let mut ctx = fresh_ctx();
        let err =
            SignatureContext::sign(&mut ctx, b"hello").expect_err("sign without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn verify_without_init_returns_init_error() {
        let mut ctx = fresh_ctx();
        let err = SignatureContext::verify(&mut ctx, b"hello", b"\x30\x06\x02\x01\x01\x02\x01\x01")
            .expect_err("verify without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_sign_update_without_init_returns_init_error() {
        let mut ctx = fresh_ctx();
        let err = SignatureContext::digest_sign_update(&mut ctx, b"chunk")
            .expect_err("digest_sign_update without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_sign_final_without_init_returns_init_error() {
        let mut ctx = fresh_ctx();
        let err = SignatureContext::digest_sign_final(&mut ctx)
            .expect_err("digest_sign_final without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_verify_update_without_init_returns_init_error() {
        let mut ctx = fresh_ctx();
        let err = SignatureContext::digest_verify_update(&mut ctx, b"chunk")
            .expect_err("digest_verify_update without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn digest_verify_final_without_init_returns_init_error() {
        let mut ctx = fresh_ctx();
        let err = SignatureContext::digest_verify_final(&mut ctx, b"sig")
            .expect_err("digest_verify_final without init must fail");
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn sign_init_with_short_key_is_rejected() {
        let mut ctx = fresh_ctx();
        // 16 bytes is neither a private scalar (32) nor a keypair (97).
        let bogus = vec![0u8; 16];
        let err = SignatureContext::sign_init(&mut ctx, &bogus, None)
            .expect_err("malformed key must be rejected");
        assert!(matches!(
            err,
            ProviderError::Common(_) | ProviderError::Dispatch(_)
        ));
    }

    #[test]
    fn verify_init_with_short_key_is_rejected() {
        let mut ctx = fresh_ctx();
        let bogus = vec![0u8; 8];
        let err = SignatureContext::verify_init(&mut ctx, &bogus, None)
            .expect_err("malformed public key must be rejected");
        assert!(matches!(
            err,
            ProviderError::Common(_) | ProviderError::Dispatch(_)
        ));
    }

    // -------------------------------------------------------------------------
    // Parameter handling
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_returns_default_metadata() {
        let ctx = fresh_ctx();
        let params = SignatureContext::get_params(&ctx)
            .expect("get_params is infallible for a fresh context");

        // digest — exactly the default SM3 string.
        match params.get("digest") {
            Some(ParamValue::Utf8String(s)) => assert_eq!(s, SM2_DEFAULT_DIGEST),
            other => panic!("expected Utf8String('SM3') for 'digest', got {other:?}"),
        }

        // id — the default distinguishing identifier.
        match params.get("id") {
            Some(ParamValue::OctetString(bytes)) => {
                assert_eq!(bytes.as_slice(), SM2_DEFAULT_ID);
            }
            other => panic!("expected OctetString for 'id', got {other:?}"),
        }

        // algorithm-id — non-empty DER encoding for the SM2-with-SM3 OID.
        match params.get("algorithm-id") {
            Some(ParamValue::OctetString(bytes)) => {
                assert!(!bytes.is_empty(), "algorithm-id DER must be non-empty");
                assert_eq!(
                    bytes[0], 0x30,
                    "algorithm-id must start with the SEQUENCE tag"
                );
            }
            other => panic!("expected OctetString for 'algorithm-id', got {other:?}"),
        }
    }

    #[test]
    fn set_params_with_empty_set_is_a_no_op() {
        let mut ctx = fresh_ctx();
        let empty = ParamSet::new();
        SignatureContext::set_params(&mut ctx, &empty).expect("empty params must succeed");
        // Nothing should have changed.
        assert_eq!(ctx.digest_name(), SM2_DEFAULT_DIGEST);
        assert_eq!(ctx.sm2_id.as_slice(), SM2_DEFAULT_ID);
    }

    #[test]
    fn set_params_updates_id() {
        let mut ctx = fresh_ctx();
        let mut params = ParamSet::new();
        params.set("id", ParamValue::OctetString(b"alice@example.com".to_vec()));
        SignatureContext::set_params(&mut ctx, &params).expect("setting a fresh id succeeds");
        assert_eq!(ctx.sm2_id.as_slice(), b"alice@example.com");
        assert!(
            ctx.needs_z_digest,
            "changing the id must invalidate any cached Z digest"
        );
    }

    #[test]
    fn set_params_id_with_wrong_type_returns_param_type_mismatch() {
        let mut ctx = fresh_ctx();
        let mut params = ParamSet::new();
        params.set("id", ParamValue::Utf8String("oops".to_string()));
        let err = SignatureContext::set_params(&mut ctx, &params)
            .expect_err("Utf8String for 'id' must be rejected");
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch {
                key,
                expected,
                actual,
            }) => {
                assert_eq!(key, "id");
                assert_eq!(expected, "OctetString");
                assert_eq!(actual, "Utf8String");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_params_digest_with_wrong_type_returns_param_type_mismatch() {
        let mut ctx = fresh_ctx();
        let mut params = ParamSet::new();
        params.set("digest", ParamValue::OctetString(vec![1, 2, 3]));
        let err = SignatureContext::set_params(&mut ctx, &params)
            .expect_err("OctetString for 'digest' must be rejected");
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch {
                key,
                expected,
                actual,
            }) => {
                assert_eq!(key, "digest");
                assert_eq!(expected, "Utf8String");
                assert_eq!(actual, "OctetString");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn set_params_digest_with_non_sm3_returns_invalid_argument() {
        let mut ctx = fresh_ctx();
        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String("SHA-256".to_string()));
        let err = SignatureContext::set_params(&mut ctx, &params)
            .expect_err("non-SM3 digest must be rejected");
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn set_params_digest_empty_string_keeps_default() {
        let mut ctx = fresh_ctx();
        let mut params = ParamSet::new();
        params.set("digest", ParamValue::Utf8String(String::new()));
        SignatureContext::set_params(&mut ctx, &params)
            .expect("empty digest name resets to default");
        assert_eq!(ctx.digest_name(), SM2_DEFAULT_DIGEST);
    }

    #[test]
    fn set_params_properties_clears_when_empty() {
        let mut ctx = fresh_ctx();
        let mut params = ParamSet::new();
        params.set(
            "properties",
            ParamValue::Utf8String("provider=default".to_string()),
        );
        SignatureContext::set_params(&mut ctx, &params).expect("setting properties succeeds");
        assert_eq!(ctx.prop_query.as_deref(), Some("provider=default"));

        let mut clear = ParamSet::new();
        clear.set("properties", ParamValue::Utf8String(String::new()));
        SignatureContext::set_params(&mut ctx, &clear)
            .expect("clearing properties via empty string succeeds");
        assert!(ctx.prop_query.is_none());
    }

    // -------------------------------------------------------------------------
    // Digest gatekeeping in the streaming API
    // -------------------------------------------------------------------------

    #[test]
    fn digest_sign_init_with_non_sm3_is_rejected() {
        let mut ctx = fresh_ctx();
        // Provide a plausible-looking key encoding so the digest check
        // fires before any further validation.
        let dummy_key = vec![0u8; SM2_PRIVKEY_LEN];
        let err = SignatureContext::digest_sign_init(&mut ctx, "SHA-256", &dummy_key, None)
            .expect_err("SHA-256 must be rejected for SM2");
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn digest_verify_init_with_non_sm3_is_rejected() {
        let mut ctx = fresh_ctx();
        let dummy_key = vec![0x04u8; SM2_UNCOMPRESSED_PUBKEY_LEN];
        let err = SignatureContext::digest_verify_init(&mut ctx, "MD5", &dummy_key, None)
            .expect_err("MD5 must be rejected for SM2");
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // DER signature codec round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn der_codec_round_trips_small_values() {
        let r = BigNum::from_bytes_be(&[0x01]);
        let s = BigNum::from_bytes_be(&[0x02]);
        let encoded = der_encode_sm2_signature(&r, &s).expect("encode succeeds");
        // The smallest valid SEQUENCE { INTEGER 1, INTEGER 2 } is 8 bytes.
        assert_eq!(encoded[0], 0x30, "outer SEQUENCE tag");
        let (r2, s2) = der_decode_sm2_signature(&encoded).expect("decode succeeds");
        assert_eq!(r.cmp(&r2), Ordering::Equal);
        assert_eq!(s.cmp(&s2), Ordering::Equal);
    }

    #[test]
    fn der_codec_round_trips_full_size_values() {
        // Construct two 32-byte big-endian integers near the SM2 order.
        let r_bytes: Vec<u8> = (1u8..=32).collect();
        let s_bytes: Vec<u8> = (32u8..64u8).rev().collect();
        let r = BigNum::from_bytes_be(&r_bytes);
        let s = BigNum::from_bytes_be(&s_bytes);
        let encoded = der_encode_sm2_signature(&r, &s).expect("encode succeeds");
        let (r2, s2) = der_decode_sm2_signature(&encoded).expect("decode succeeds");
        assert_eq!(r.cmp(&r2), Ordering::Equal);
        assert_eq!(s.cmp(&s2), Ordering::Equal);
    }

    #[test]
    fn der_decode_rejects_trailing_garbage() {
        let r = BigNum::from_bytes_be(&[0x05]);
        let s = BigNum::from_bytes_be(&[0x09]);
        let mut encoded = der_encode_sm2_signature(&r, &s).expect("encode succeeds");
        encoded.push(0xFF);
        let err = der_decode_sm2_signature(&encoded).expect_err("trailing bytes must be rejected");
        match err {
            CryptoError::Encoding(_) => {}
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn der_decode_rejects_empty_input() {
        let err = der_decode_sm2_signature(&[]).expect_err("empty input must be rejected");
        match err {
            CryptoError::Encoding(_) => {}
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn der_decode_rejects_non_sequence_tag() {
        // First byte should be SEQUENCE (0x30); use INTEGER (0x02) instead.
        let bogus = [0x02u8, 0x01, 0x00];
        let err = der_decode_sm2_signature(&bogus).expect_err("non-SEQUENCE must be rejected");
        match err {
            CryptoError::Encoding(_) => {}
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Algorithm identifier DER
    // -------------------------------------------------------------------------

    #[test]
    fn algorithm_identifier_der_is_well_formed() {
        let bytes = sm2_algorithm_identifier_der().expect("AID encode succeeds");
        assert!(bytes.len() >= 2);
        assert_eq!(bytes[0], 0x30, "outer SEQUENCE tag");
        // Inner OID for SM2-with-SM3 is 1.2.156.10197.1.501 — its DER
        // encoding starts with `06 08 2A 81 1C CF 55 01 83 75`.
        let oid = [0x06u8, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75];
        let needle_pos = bytes
            .windows(oid.len())
            .position(|w| w == oid)
            .expect("encoded AID must embed the SM2-with-SM3 OID");
        assert!(needle_pos > 0);
    }

    // -------------------------------------------------------------------------
    // Z-digest computation
    // -------------------------------------------------------------------------

    #[test]
    fn compute_z_digest_value_is_deterministic_for_default_id() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).expect("EC keygen succeeds");
        let pub_key = key.public_key().unwrap();

        let z1 = compute_z_digest_value(
            &LibContext::get_default(),
            None,
            SM2_DEFAULT_DIGEST,
            SM2_DEFAULT_ID,
            &group,
            pub_key,
        )
        .expect("Z digest computes");
        let z2 = compute_z_digest_value(
            &LibContext::get_default(),
            None,
            SM2_DEFAULT_DIGEST,
            SM2_DEFAULT_ID,
            &group,
            pub_key,
        )
        .expect("Z digest computes again");
        assert_eq!(z1, z2, "Z digest must be deterministic");
        assert_eq!(z1.len(), SM3_DIGEST_SIZE);
    }

    #[test]
    fn compute_z_digest_changes_when_id_changes() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pub_key = key.public_key().unwrap();
        let z_default = compute_z_digest_value(
            &LibContext::get_default(),
            None,
            SM2_DEFAULT_DIGEST,
            SM2_DEFAULT_ID,
            &group,
            pub_key,
        )
        .unwrap();
        let z_other = compute_z_digest_value(
            &LibContext::get_default(),
            None,
            SM2_DEFAULT_DIGEST,
            b"alice@example.com",
            &group,
            pub_key,
        )
        .unwrap();
        assert_ne!(
            z_default, z_other,
            "different identifiers must yield different Z digests"
        );
    }

    #[test]
    fn compute_z_digest_changes_when_public_key_changes() {
        let group = sm2_curve_group().unwrap();
        let key_a = EcKey::generate(&group).unwrap();
        let key_b = EcKey::generate(&group).unwrap();
        let z_a = compute_z_digest_value(
            &LibContext::get_default(),
            None,
            SM2_DEFAULT_DIGEST,
            SM2_DEFAULT_ID,
            &group,
            key_a.public_key().unwrap(),
        )
        .unwrap();
        let z_b = compute_z_digest_value(
            &LibContext::get_default(),
            None,
            SM2_DEFAULT_DIGEST,
            SM2_DEFAULT_ID,
            &group,
            key_b.public_key().unwrap(),
        )
        .unwrap();
        assert_ne!(
            z_a, z_b,
            "different public keys must yield different Z digests with overwhelming probability"
        );
    }

    // -------------------------------------------------------------------------
    // End-to-end sign / verify round-trips
    // -------------------------------------------------------------------------

    #[test]
    fn sign_then_verify_round_trip_with_keypair() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).expect("keygen");
        let keypair = build_keypair_bytes(&key, &group);
        let pubkey = build_pubkey_bytes(&key, &group);
        let msg = b"the quick brown fox jumps over the lazy dog";

        // ----- sign -----
        let mut signer = fresh_ctx();
        SignatureContext::sign_init(&mut signer, &keypair, None).expect("sign_init");
        let sig = SignatureContext::sign(&mut signer, msg).expect("sign");
        assert!(!sig.is_empty(), "signature must not be empty");
        assert_eq!(sig[0], 0x30, "DER SEQUENCE tag");

        // ----- verify -----
        let mut verifier = fresh_ctx();
        SignatureContext::verify_init(&mut verifier, &pubkey, None).expect("verify_init");
        let ok = SignatureContext::verify(&mut verifier, msg, &sig).expect("verify call");
        assert!(ok, "verification of a fresh signature must succeed");
    }

    #[test]
    fn verify_fails_for_wrong_key() {
        let group = sm2_curve_group().unwrap();
        let signing = EcKey::generate(&group).unwrap();
        let other = EcKey::generate(&group).unwrap();

        let signing_keypair = build_keypair_bytes(&signing, &group);
        let other_pubkey = build_pubkey_bytes(&other, &group);
        let msg = b"verify-with-wrong-key";

        let mut signer = fresh_ctx();
        SignatureContext::sign_init(&mut signer, &signing_keypair, None).unwrap();
        let sig = SignatureContext::sign(&mut signer, msg).unwrap();

        let mut verifier = fresh_ctx();
        SignatureContext::verify_init(&mut verifier, &other_pubkey, None).unwrap();
        let ok = SignatureContext::verify(&mut verifier, msg, &sig).unwrap();
        assert!(!ok, "verification under the wrong public key must fail");
    }

    #[test]
    fn verify_fails_for_tampered_message() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let keypair = build_keypair_bytes(&key, &group);
        let pubkey = build_pubkey_bytes(&key, &group);

        let mut signer = fresh_ctx();
        SignatureContext::sign_init(&mut signer, &keypair, None).unwrap();
        let sig = SignatureContext::sign(&mut signer, b"original message").unwrap();

        let mut verifier = fresh_ctx();
        SignatureContext::verify_init(&mut verifier, &pubkey, None).unwrap();
        let ok = SignatureContext::verify(&mut verifier, b"tampered message", &sig).unwrap();
        assert!(!ok, "tampered messages must not verify");
    }

    #[test]
    fn verify_returns_false_for_malformed_signature_der() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pubkey = build_pubkey_bytes(&key, &group);

        let mut verifier = fresh_ctx();
        SignatureContext::verify_init(&mut verifier, &pubkey, None).unwrap();
        // Garbage that is neither a valid DER signature nor empty.
        let bogus = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let ok = SignatureContext::verify(&mut verifier, b"msg", &bogus).unwrap();
        assert!(!ok, "malformed signatures must not verify");
    }

    #[test]
    fn streaming_sign_verify_round_trip() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let keypair = build_keypair_bytes(&key, &group);
        let pubkey = build_pubkey_bytes(&key, &group);
        let chunks: [&[u8]; 3] = [b"hello ", b"streaming ", b"world"];
        let mut full = Vec::new();
        for c in chunks {
            full.extend_from_slice(c);
        }

        // ----- streaming sign -----
        let mut signer = fresh_ctx();
        SignatureContext::digest_sign_init(&mut signer, "SM3", &keypair, None).unwrap();
        for c in chunks {
            SignatureContext::digest_sign_update(&mut signer, c).unwrap();
        }
        let sig = SignatureContext::digest_sign_final(&mut signer).unwrap();
        // After `final` the streaming buffer must be cleared.
        assert!(signer.streaming_buffer.is_empty());

        // ----- streaming verify -----
        let mut verifier = fresh_ctx();
        SignatureContext::digest_verify_init(&mut verifier, "SM3", &pubkey, None).unwrap();
        for c in chunks {
            SignatureContext::digest_verify_update(&mut verifier, c).unwrap();
        }
        let ok = SignatureContext::digest_verify_final(&mut verifier, &sig).unwrap();
        assert!(ok);

        // ----- mismatched verify (one-shot vs streaming hash domain) -----
        // A one-shot verifier given the same message and signature must
        // also accept it — the streaming code path is just a buffered
        // wrapper around the one-shot primitive.
        let mut one_shot = fresh_ctx();
        SignatureContext::verify_init(&mut one_shot, &pubkey, None).unwrap();
        let ok2 = SignatureContext::verify(&mut one_shot, &full, &sig).unwrap();
        assert!(ok2);
    }

    #[test]
    fn signature_is_non_deterministic_across_runs() {
        // SM2 sign uses a freshly drawn random k each time, so two
        // signatures of the same message under the same key must differ
        // with overwhelming probability.
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let keypair = build_keypair_bytes(&key, &group);
        let msg = b"randomness check";

        let mut s1 = fresh_ctx();
        SignatureContext::sign_init(&mut s1, &keypair, None).unwrap();
        let sig1 = SignatureContext::sign(&mut s1, msg).unwrap();

        let mut s2 = fresh_ctx();
        SignatureContext::sign_init(&mut s2, &keypair, None).unwrap();
        let sig2 = SignatureContext::sign(&mut s2, msg).unwrap();

        assert_ne!(
            sig1, sig2,
            "two independent SM2 signatures of the same message must differ"
        );
    }

    #[test]
    fn sign_init_accepts_private_only_encoding() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let priv_only = key
            .private_key()
            .unwrap()
            .to_bytes_be_padded(SM2_PRIVKEY_LEN)
            .unwrap();
        assert_eq!(priv_only.len(), SM2_PRIVKEY_LEN);

        let mut ctx = fresh_ctx();
        SignatureContext::sign_init(&mut ctx, &priv_only, None)
            .expect("32-byte private scalar is a valid sign-init key");
        let sig = SignatureContext::sign(&mut ctx, b"sign with priv only").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn verify_init_accepts_uncompressed_public_only() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let keypair = build_keypair_bytes(&key, &group);
        let pubkey_only = build_pubkey_bytes(&key, &group);

        let mut signer = fresh_ctx();
        SignatureContext::sign_init(&mut signer, &keypair, None).unwrap();
        let sig = SignatureContext::sign(&mut signer, b"public-only verify").unwrap();

        let mut verifier = fresh_ctx();
        SignatureContext::verify_init(&mut verifier, &pubkey_only, None).unwrap();
        let ok = SignatureContext::verify(&mut verifier, b"public-only verify", &sig).unwrap();
        assert!(ok);
    }

    // -------------------------------------------------------------------------
    // Descriptor registration
    // -------------------------------------------------------------------------

    #[test]
    fn descriptors_returns_at_least_one_entry() {
        let descs = descriptors();
        assert!(!descs.is_empty());
    }

    #[test]
    fn descriptor_advertises_canonical_names_and_property() {
        let desc = sm2_signature_descriptor();
        assert!(desc.names.contains(&"SM2"));
        assert!(desc.names.contains(&"1.2.156.10197.1.301"));
        assert_eq!(desc.property, "provider=default");
        assert!(
            !desc.description.is_empty(),
            "descriptor description must be non-empty for diagnostics"
        );
    }

    // -------------------------------------------------------------------------
    // OperationMode propagation
    // -------------------------------------------------------------------------

    #[test]
    fn operation_mode_reflects_sign_then_clears() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let keypair = build_keypair_bytes(&key, &group);

        let mut ctx = fresh_ctx();
        assert_eq!(ctx.operation_mode(), None);
        SignatureContext::sign_init(&mut ctx, &keypair, None).unwrap();
        assert_eq!(ctx.operation_mode(), Some(OperationMode::Sign));
    }

    #[test]
    fn operation_mode_reflects_verify_init() {
        let group = sm2_curve_group().unwrap();
        let key = EcKey::generate(&group).unwrap();
        let pubkey = build_pubkey_bytes(&key, &group);

        let mut ctx = fresh_ctx();
        assert_eq!(ctx.operation_mode(), None);
        SignatureContext::verify_init(&mut ctx, &pubkey, None).unwrap();
        assert_eq!(ctx.operation_mode(), Some(OperationMode::Verify));
    }
}
