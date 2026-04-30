//! ECDH (Elliptic Curve Diffie-Hellman) key exchange provider implementation.
//!
//! Provides the `KEYEXCH` interface for ECDH over Weierstrass curves:
//! NIST P-256/P-384/P-521 and the Koblitz curve secp256k1. Brainpool / SM2
//! curves are not supported by the underlying crypto layer at this time and
//! will surface as `unknown curve` errors when requested.
//!
//! Supports three derivation modes:
//! - **Plain ECDH:** Raw shared secret via [`compute_key`] / [`compute_key_with_mode`].
//! - **Cofactor ECDH:** Uses cofactor multiplication per SP800-56A r3 §5.7.1.2
//!   (selected via [`EcdhMode::CofactorDh`]).
//! - **X9.63 KDF:** Shared secret passed through ANSI X9.63 KDF
//!   ([`kdf_x963`] driven by an EVP digest).
//!
//! Also supports [`EcdhExchangeContext::derive_skey`] to package the derived
//! secret as raw bytes for downstream secret-key import.
//!
//! ## C Source Mapping
//!
//! Translated from `providers/implementations/exchange/ecdh_exch.c`:
//!
//! | C symbol                              | Rust symbol                                          |
//! |---------------------------------------|------------------------------------------------------|
//! | `PROV_ECDH_CTX`                       | [`EcdhExchangeContext`]                              |
//! | `enum kdf_type`                       | [`EcdhKdfType`]                                      |
//! | `ecdh_newctx()` (line 89)             | [`EcdhExchange::new_ctx`]                            |
//! | `ecdh_init()` (line 112)              | `<EcdhExchangeContext as KeyExchangeContext>::init`  |
//! | `ecdh_match_params()` (line 139)      | `EcdhExchangeContext::match_curves` (internal)       |
//! | `ecdh_set_peer()` (line 160)          | `<EcdhExchangeContext as KeyExchangeContext>::set_peer` |
//! | `ecdh_dupctx()` (line 197)            | `<EcdhExchangeContext as Clone>::clone`              |
//! | `ecdh_set_ctx_params()` (line 250)    | `<EcdhExchangeContext as KeyExchangeContext>::set_params` |
//! | `ecdh_get_ctx_params()` (line 353)    | `<EcdhExchangeContext as KeyExchangeContext>::get_params` |
//! | `ecdh_size()` (line 415)              | `EcdhExchangeContext::ecdh_size` (internal)          |
//! | `ecdh_plain_derive()` (line 429)      | `EcdhExchangeContext::plain_derive` (internal)       |
//! | `ecdh_X9_63_kdf_derive()` (line 533)  | `EcdhExchangeContext::x963_kdf_derive` (internal)    |
//! | `ecdh_derive()` (line 573)            | `<EcdhExchangeContext as KeyExchangeContext>::derive` |
//! | `ecdh_derive_skey()` (line 589)       | [`EcdhExchangeContext::derive_skey`]                 |
//! | `ossl_ecdh_keyexch_functions` table   | [`descriptors`]                                      |
//!
//! ## Rule Compliance
//!
//! - **R5 (Nullability over sentinels):** the C `int cofactor_mode` (`-1`, `0`,
//!   `1`) is preserved as a 3-state `i32` to match the wire-level `OSSL_PARAM`
//!   contract; per-field "unset" semantics use [`Option<T>`] (e.g.
//!   [`MessageDigest`], UKM, output length).
//! - **R6 (Lossless casts):** ECDH size derives from `EcGroup::degree()`
//!   (a `u32`) via `usize::try_from(...)?` followed by checked addition; no
//!   bare `as` narrowing.
//! - **R7 (Concurrency):** the context is a per-operation owned struct; no
//!   shared mutable state.
//! - **R8 (No unsafe outside FFI):** this file contains zero `unsafe` blocks.
//! - **R9 (Warning-free):** every public item has a doc comment.
//! - **R10 (Wired):** reachable from `openssl_cli::main()` →
//!   `openssl_crypto::evp` → provider fetch → [`EcdhExchange::new_ctx`]
//!   → [`EcdhExchangeContext::derive`].

use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, Zeroizing};

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::bn::BigNum;
use openssl_crypto::context::LibContext;
use openssl_crypto::ec::ecdh::{compute_key_with_mode, kdf_x963, EcdhMode};
use openssl_crypto::ec::{EcGroup, EcKey, EcPoint, NamedCurve, PointConversionForm};
use openssl_crypto::evp::md::MessageDigest;

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyExchangeContext, KeyExchangeProvider};

// ---------------------------------------------------------------------------
// Parameter key constants
// ---------------------------------------------------------------------------
//
// These mirror the OSSL_KDF_PARAM_* / OSSL_EXCHANGE_PARAM_* names used by the
// upstream provider so that callers wiring `OSSL_PARAM` arrays through the
// FFI shim observe identical behaviour.

/// Curve / domain parameter group selector (`OSSL_PKEY_PARAM_GROUP_NAME`).
const PARAM_GROUP: &str = "group";
/// Cofactor mode selector (`OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE`).
///
/// Wire values follow the C contract: `-1` → use key default, `0` → disabled,
/// `1` → enabled.
const PARAM_COFACTOR_MODE: &str = "ecdh-cofactor-mode";
/// KDF type selector (`OSSL_EXCHANGE_PARAM_KDF_TYPE`).
const PARAM_KDF_TYPE: &str = "kdf-type";
/// KDF digest selector (`OSSL_EXCHANGE_PARAM_KDF_DIGEST`).
const PARAM_KDF_DIGEST: &str = "kdf-digest";
/// KDF digest properties (`OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS`).
const PARAM_KDF_DIGEST_PROPS: &str = "kdf-digest-props";
/// KDF output length in bytes (`OSSL_EXCHANGE_PARAM_KDF_OUTLEN`).
const PARAM_KDF_OUTLEN: &str = "kdf-outlen";
/// User Keying Material for KDF (`OSSL_EXCHANGE_PARAM_KDF_UKM`).
const PARAM_KDF_UKM: &str = "kdf-ukm";

/// Canonical name of the X9.63 KDF (matches `OSSL_KDF_NAME_X963KDF`).
const KDF_NAME_X9_63: &str = "X963KDF";

/// Sentinel value for "use the cofactor mode configured on the key" (mirrors
/// the C wire contract for `OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE`).
const COFACTOR_MODE_USE_KEY: i32 = -1;
/// Sentinel for "force standard (non-cofactor) ECDH".
const COFACTOR_MODE_DISABLED: i32 = 0;
/// Sentinel for "force cofactor ECDH".
const COFACTOR_MODE_ENABLED: i32 = 1;

// ---------------------------------------------------------------------------
// EcdhKdfType — KDF mode enum
// ---------------------------------------------------------------------------

/// KDF mode for ECDH derivation.
///
/// Replaces the C `enum kdf_type` from `ecdh_exch.c:46-49`. The string form
/// is what gets exchanged via `OSSL_PARAM` (`""` → no KDF, `"X963KDF"` → ANSI
/// X9.63 KDF).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EcdhKdfType {
    /// No KDF — raw shared secret output. Encoded as the empty string on the
    /// wire (matches the C `PROV_ECDH_KDF_NONE` default).
    #[default]
    None,
    /// ANSI X9.63 KDF applied to the shared secret. Encoded as
    /// `"X963KDF"` on the wire.
    X963,
}

impl EcdhKdfType {
    /// Returns the wire-format string for this KDF type.
    fn as_param_string(self) -> &'static str {
        match self {
            Self::None => "",
            Self::X963 => KDF_NAME_X9_63,
        }
    }

    /// Parses the wire-format string into a KDF type.
    ///
    /// Returns [`ProviderError::Init`] if `s` is not a recognised KDF name.
    fn from_param_string(s: &str) -> ProviderResult<Self> {
        match s {
            "" => Ok(Self::None),
            KDF_NAME_X9_63 => Ok(Self::X963),
            other => Err(ProviderError::Init(format!(
                "ECDH: unknown KDF type '{other}' (expected '' or '{KDF_NAME_X9_63}')"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// EcdhExchangeContext — per-operation state
// ---------------------------------------------------------------------------

/// Per-operation context for ECDH key exchange.
///
/// Holds the local private scalar, peer public point, agreed-upon curve
/// parameters, cofactor mode override, and optional KDF configuration.
///
/// Created by [`EcdhExchange::new_ctx`].
///
/// ## Lifecycle
///
/// ```text
/// new_ctx() → init(key) → set_peer(peer) → derive(secret) → drop
/// ```
///
/// ## Why raw bytes instead of [`EcKey`]?
///
/// [`EcKey`] is intentionally not [`Clone`] (its private scalar lives behind
/// `SecureBigNum`). To support the C `ecdh_dupctx()` semantics required by
/// the provider framework, we store the private scalar (big-endian bytes)
/// inside [`Zeroizing`] and the peer public point in SEC1 form, reconstructing
/// the [`EcKey`] handles only at derivation time.
///
/// Replaces C `PROV_ECDH_CTX` from `ecdh_exch.c:57-85`.
pub struct EcdhExchangeContext {
    /// Local private scalar in big-endian bytes. `None` until [`Self::init`]
    /// has been called with a non-empty key. Wrapped in [`Zeroizing`] so the
    /// scalar is wiped on drop (replaces `OPENSSL_clear_free` for the C
    /// private key).
    our_private: Option<Zeroizing<Vec<u8>>>,
    /// Peer public point in SEC1 octet-string form (uncompressed unless the
    /// caller pre-encoded it differently). `None` until [`Self::set_peer`]
    /// has been called.
    peer_public: Option<Vec<u8>>,
    /// Shared domain parameters. Populated when [`Self::init`] succeeds; the
    /// peer key is required to live on the same curve.
    group: Option<EcGroup>,
    /// Wire-format cofactor mode (`-1` = key default, `0` = disabled,
    /// `1` = enabled). Default is `-1`.
    cofactor_mode: i32,
    /// KDF mode for [`Self::derive`].
    kdf_type: EcdhKdfType,
    /// Message digest used by the X9.63 KDF when [`Self::kdf_type`] is
    /// [`EcdhKdfType::X963`]. `None` when no KDF is configured.
    kdf_digest: Option<MessageDigest>,
    /// Property query string used when fetching the KDF digest. Stored so it
    /// can be round-tripped back through [`Self::get_params`].
    kdf_digest_props: Option<String>,
    /// User Keying Material passed as the `shared_info` parameter of the
    /// X9.63 KDF. Wrapped in [`Zeroizing`] for secure cleanup.
    kdf_ukm: Option<Zeroizing<Vec<u8>>>,
    /// Desired KDF output length in bytes. Required when
    /// [`Self::kdf_type`] is [`EcdhKdfType::X963`].
    kdf_outlen: Option<usize>,
}

impl EcdhExchangeContext {
    /// Constructs a fresh ECDH context with all fields at default values.
    ///
    /// Mirrors C `ecdh_newctx()` (`ecdh_exch.c:89`).
    fn new() -> Self {
        Self {
            our_private: None,
            peer_public: None,
            group: None,
            cofactor_mode: COFACTOR_MODE_USE_KEY,
            kdf_type: EcdhKdfType::None,
            kdf_digest: None,
            kdf_digest_props: None,
            kdf_ukm: None,
            kdf_outlen: None,
        }
    }

    // ---------------------------------------------------------------------
    // Helpers — curve parsing and key reconstruction
    // ---------------------------------------------------------------------

    /// Parses a curve name into a [`NamedCurve`], accepting both the
    /// canonical OpenSSL identifiers and a forgiving lowercase form.
    fn parse_curve_name(name: &str) -> ProviderResult<NamedCurve> {
        if let Some(curve) = NamedCurve::from_name(name) {
            return Ok(curve);
        }
        // Fallback to lowercase to forgive callers that pass `"P-256"`
        // versus `"p-256"`. NamedCurve::from_name is case-sensitive but the
        // canonical OpenSSL names are lowercase.
        let lowered = name.to_ascii_lowercase();
        if let Some(curve) = NamedCurve::from_name(&lowered) {
            return Ok(curve);
        }
        Err(ProviderError::Init(format!(
            "ECDH: unknown or unsupported curve '{name}'"
        )))
    }

    /// Returns the agreed-upon curve group, or an error if the context has
    /// not been initialised.
    fn require_group(&self) -> ProviderResult<&EcGroup> {
        self.group.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: no key/group set; call init() before derive()".to_string(),
            ))
        })
    }

    /// Computes the upper bound on the raw shared-secret length:
    /// `ceil(degree / 8)`.
    ///
    /// Mirrors C `ecdh_size()` (`ecdh_exch.c:415-427`).
    fn ecdh_size(group: &EcGroup) -> ProviderResult<usize> {
        let degree = group.degree();
        // Per Rule R6 — checked numeric conversion, no bare `as` casts.
        // `usize::try_from(u32)` returns `Result<_, TryFromIntError>`, which
        // converts cleanly into `CommonError::CastOverflow` via `#[from]`.
        let degree_usize = usize::try_from(degree)
            .map_err(|e| ProviderError::Common(CommonError::CastOverflow(e)))?;
        let bytes = degree_usize.checked_add(7).ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "ECDH: degree+7 overflowed usize",
            })
        })? / 8;
        Ok(bytes)
    }

    /// Reconstructs the local [`EcKey`] from the stored raw scalar.
    fn reconstruct_own_key(&self) -> ProviderResult<EcKey> {
        let group = self.require_group()?.clone();
        let private_bytes = self.our_private.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: missing private key (call init())".to_string(),
            ))
        })?;
        let scalar = BigNum::from_bytes_be(private_bytes);
        EcKey::from_private_key(&group, scalar).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: failed to reconstruct local EC key: {e}"
            )))
        })
    }

    /// Reconstructs the peer [`EcKey`] from the stored SEC1-encoded point.
    fn reconstruct_peer_key(&self) -> ProviderResult<EcKey> {
        let group = self.require_group()?.clone();
        let peer_bytes = self.peer_public.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: missing peer key (call set_peer())".to_string(),
            ))
        })?;
        let point = EcPoint::from_bytes(&group, peer_bytes).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: failed to decode peer public point: {e}"
            )))
        })?;
        EcKey::from_public_key(&group, point).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: failed to construct peer EC key: {e}"
            )))
        })
    }

    /// Resolves the effective cofactor multiplication mode given the wire
    /// value and the underlying group's cofactor.
    ///
    /// - `mode = -1` → use [`EcdhMode::CofactorDh`] when the curve has a
    ///   non-trivial cofactor, otherwise [`EcdhMode::Standard`].
    /// - `mode = 0`  → [`EcdhMode::Standard`].
    /// - `mode = 1`  → [`EcdhMode::CofactorDh`].
    ///
    /// Mirrors C `ecdh_plain_derive()` (`ecdh_exch.c:480-500`) cofactor
    /// dispatch logic.
    fn resolve_mode(&self, group: &EcGroup) -> EcdhMode {
        match self.cofactor_mode {
            COFACTOR_MODE_DISABLED => EcdhMode::Standard,
            COFACTOR_MODE_ENABLED => EcdhMode::CofactorDh,
            _ => {
                // Use the curve's cofactor: if cofactor != 1, default to
                // CofactorDh per SP800-56A r3 §5.7.1.2.
                let cofactor = group.cofactor();
                let one = BigNum::from_u64(1);
                if cofactor == &one {
                    EcdhMode::Standard
                } else {
                    EcdhMode::CofactorDh
                }
            }
        }
    }

    /// Compares two groups by canonical curve identifier.
    ///
    /// `EcGroup` does not derive `PartialEq`; for ECDH the contract is
    /// "domain parameters must match", which we enforce via curve name
    /// equality. Mirrors C `ecdh_match_params()` (`ecdh_exch.c:139-158`).
    fn curves_match(a: &EcGroup, b: &EcGroup) -> bool {
        match (a.curve_name(), b.curve_name()) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }

    // ---------------------------------------------------------------------
    // Helpers — derivation
    // ---------------------------------------------------------------------

    /// Plain ECDH derivation.
    ///
    /// Computes the raw shared secret (with cofactor multiplication if
    /// requested) and copies up to `secret.len()` leading bytes of it into
    /// `secret`. Returns the number of bytes written.
    ///
    /// **Note:** unlike DH, ECDH **truncates** when the destination buffer is
    /// shorter than the natural ECDH size (mirrors C `ecdh_plain_derive()`
    /// at `ecdh_exch.c:466`: `size = outlen < ecdhsize ? outlen : ecdhsize`).
    fn plain_derive(&self, secret: &mut [u8]) -> ProviderResult<usize> {
        let group = self.require_group()?;
        let ecdh_size = Self::ecdh_size(group)?;

        let own_key = self.reconstruct_own_key()?;
        let peer_key = self.reconstruct_peer_key()?;
        let peer_point = peer_key.public_key().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: peer key is missing public point".to_string(),
            ))
        })?;

        let mode = self.resolve_mode(group);
        trace!(
            curve = %group.curve_name().map_or("explicit", |c| c.name()),
            ?mode,
            ecdh_size,
            "ECDH: plain derive entry"
        );

        let shared = compute_key_with_mode(&own_key, peer_point, mode).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: scalar multiplication failed: {e}"
            )))
        })?;
        let shared_bytes = shared.as_bytes();

        // C semantics: short buffer → truncate; long buffer → write only the
        // first `ecdh_size` bytes (no zero-padding either way).
        let to_copy = secret.len().min(shared_bytes.len()).min(ecdh_size);
        secret[..to_copy].copy_from_slice(&shared_bytes[..to_copy]);
        trace!(written = to_copy, "ECDH: plain derive complete");
        Ok(to_copy)
    }

    /// X9.63 KDF derivation.
    ///
    /// Computes the raw shared secret into a [`Zeroizing`] temporary buffer
    /// and then runs the ANSI X9.63 KDF over it (with the configured digest
    /// and UKM) to produce the final derived material.
    ///
    /// Mirrors C `ecdh_X9_63_kdf_derive()` (`ecdh_exch.c:533-571`):
    ///
    /// - Validates `kdf_outlen` is set and fits the destination buffer
    ///   (`PROV_R_OUTPUT_BUFFER_TOO_SMALL` on overflow).
    /// - Derives raw shared secret first using a secure (zeroizing) buffer.
    /// - Applies X9.63 KDF with stored digest, UKM, and outlen.
    fn x963_kdf_derive(&self, secret: &mut [u8]) -> ProviderResult<usize> {
        let outlen = self.kdf_outlen.ok_or_else(|| {
            ProviderError::Init("ECDH: X9.63 KDF requested but no kdf-outlen set".to_string())
        })?;
        if outlen == 0 {
            return Err(ProviderError::Init(
                "ECDH: X9.63 KDF outlen must be greater than zero".to_string(),
            ));
        }
        if outlen > secret.len() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ECDH: X9.63 KDF outlen {outlen} exceeds output buffer length {}",
                    secret.len()
                ),
            )));
        }

        let digest = self.kdf_digest.as_ref().ok_or_else(|| {
            ProviderError::Init(
                "ECDH: X9.63 KDF requested but no kdf-digest set".to_string(),
            )
        })?;

        let group = self.require_group()?;
        let ecdh_size = Self::ecdh_size(group)?;

        // Derive raw shared secret into a zeroizing scratch buffer that lives
        // only as long as needed by the KDF, mirroring the C use of
        // `OPENSSL_secure_malloc`/`OPENSSL_secure_clear_free` at lines 536–569.
        let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; ecdh_size]);
        let written = self.plain_derive(scratch.as_mut_slice())?;
        if written == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: shared secret derivation produced zero bytes".to_string(),
            )));
        }
        // Trim to the actual length produced (so the KDF only sees real
        // shared-secret bytes).
        scratch.truncate(written);

        let ukm: &[u8] = self.kdf_ukm.as_deref().map_or(&[], Vec::as_slice);
        let digest_name = digest.name();
        trace!(
            digest = digest_name,
            ukm_len = ukm.len(),
            outlen,
            "ECDH: X9.63 KDF derive entry"
        );

        // The crypto-layer kdf_x963 wraps a SharedSecret; reconstruct one
        // from the truncated scratch without exposing crate-private APIs by
        // running compute_key + kdf_x963 sequentially via the trait helpers
        // already in scope. We re-derive directly here using the stored
        // shared bytes through the SharedSecret-typed wrapper exposed by the
        // crypto layer. Because `SharedSecret::new` is crate-private, we
        // instead invoke the high-level crypto API that does both steps.
        //
        // Specifically, we recompute the shared secret on its own (cheap
        // relative to the KDF and required by the API surface), so the
        // scratch above is only used for length validation when the caller
        // asks for the natural size via `outlen`.
        let own_key = self.reconstruct_own_key()?;
        let peer_key = self.reconstruct_peer_key()?;
        let peer_point = peer_key.public_key().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: peer key is missing public point".to_string(),
            ))
        })?;
        let mode = self.resolve_mode(group);
        let shared = compute_key_with_mode(&own_key, peer_point, mode).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: scalar multiplication failed: {e}"
            )))
        })?;

        let derived = kdf_x963(&shared, ukm, digest_name, outlen).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: X9.63 KDF failed: {e}"
            )))
        })?;
        if derived.len() != outlen {
            return Err(ProviderError::Common(CommonError::Internal(format!(
                "ECDH: X9.63 KDF produced {} bytes but {outlen} were requested",
                derived.len()
            ))));
        }
        secret[..outlen].copy_from_slice(&derived);
        // Defensive zeroing of the temporary derived buffer; `derived` is a
        // plain Vec<u8> that wouldn't otherwise be erased.
        let mut derived = derived;
        derived.zeroize();
        trace!(written = outlen, "ECDH: X9.63 KDF derive complete");
        Ok(outlen)
    }

    // ---------------------------------------------------------------------
    // derive_skey — package shared secret as raw bytes for skeymgmt import
    // ---------------------------------------------------------------------

    /// Derives the shared secret and returns it as a raw byte vector
    /// suitable for downstream secret-key import.
    ///
    /// Internally performs the C two-pass derivation (`ecdh_derive_skey`
    /// at `ecdh_exch.c:589-621`):
    ///
    /// 1. Determine the derived secret length (KDF outlen if a KDF is
    ///    configured, otherwise the natural ECDH size).
    /// 2. Derive into a zeroizing scratch buffer, truncate to the actual
    ///    length, and hand the bytes back to the caller.
    pub fn derive_skey(&self) -> ProviderResult<Vec<u8>> {
        let group = self.require_group()?;
        let target_len = match self.kdf_type {
            EcdhKdfType::None => Self::ecdh_size(group)?,
            EcdhKdfType::X963 => self.kdf_outlen.ok_or_else(|| {
                ProviderError::Init(
                    "ECDH: derive_skey: X9.63 KDF requires kdf-outlen".to_string(),
                )
            })?,
        };
        if target_len == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: derive_skey computed a zero-length secret".to_string(),
            )));
        }

        let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; target_len]);
        let written = match self.kdf_type {
            EcdhKdfType::None => self.plain_derive(scratch.as_mut_slice())?,
            EcdhKdfType::X963 => self.x963_kdf_derive(scratch.as_mut_slice())?,
        };
        if written == 0 {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: derive_skey: derivation wrote zero bytes".to_string(),
            )));
        }
        let mut out = Vec::with_capacity(written);
        out.extend_from_slice(&scratch[..written]);
        Ok(out)
    }

    // ---------------------------------------------------------------------
    // apply_param — single-key dispatcher used by set_params()
    // ---------------------------------------------------------------------

    /// Applies one OSSL_PARAM-style update to the context.
    ///
    /// Mirrors C `ecdh_set_ctx_params()` (`ecdh_exch.c:250-345`) per-key
    /// dispatch.
    fn apply_param(&mut self, key: &str, value: &ParamValue) -> ProviderResult<()> {
        match key {
            PARAM_GROUP => {
                let name = value.as_str().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be a UTF-8 string"
                    )))
                })?;
                let curve = Self::parse_curve_name(name)?;
                let group = EcGroup::from_curve_name(curve).map_err(|e| {
                    ProviderError::Init(format!(
                        "ECDH: failed to load curve '{name}': {e}"
                    ))
                })?;
                self.group = Some(group);
                Ok(())
            }
            PARAM_COFACTOR_MODE => {
                let mode = value.as_i32().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be a 32-bit integer"
                    )))
                })?;
                if !(COFACTOR_MODE_USE_KEY..=COFACTOR_MODE_ENABLED).contains(&mode) {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "ECDH: '{key}' must be -1, 0, or 1 (got {mode})"
                        ),
                    )));
                }
                self.cofactor_mode = mode;
                Ok(())
            }
            PARAM_KDF_TYPE => {
                let s = value.as_str().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be a UTF-8 string"
                    )))
                })?;
                self.kdf_type = EcdhKdfType::from_param_string(s)?;
                Ok(())
            }
            PARAM_KDF_DIGEST => {
                let name = value.as_str().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be a UTF-8 string"
                    )))
                })?;
                let ctx: Arc<LibContext> = LibContext::default();
                let digest = MessageDigest::fetch(
                    &ctx,
                    name,
                    self.kdf_digest_props.as_deref(),
                )
                .map_err(|e| {
                    ProviderError::Init(format!(
                        "ECDH: failed to fetch KDF digest '{name}': {e}"
                    ))
                })?;
                if digest.is_xof() {
                    warn!(digest = name, "ECDH: rejecting XOF digest for KDF");
                    return Err(ProviderError::Init(format!(
                        "ECDH: digest '{name}' is an XOF and cannot be used with X9.63 KDF"
                    )));
                }
                self.kdf_digest = Some(digest);
                Ok(())
            }
            PARAM_KDF_DIGEST_PROPS => {
                let s = value.as_str().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be a UTF-8 string"
                    )))
                })?;
                self.kdf_digest_props = Some(s.to_string());
                Ok(())
            }
            PARAM_KDF_OUTLEN => {
                let n = value.as_u64().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be an unsigned integer"
                    )))
                })?;
                // Per Rule R6 — checked numeric conversion. `usize::try_from`
                // returns `TryFromIntError`, which converts to
                // `CommonError::CastOverflow` via `#[from]`.
                let n = usize::try_from(n)
                    .map_err(|e| ProviderError::Common(CommonError::CastOverflow(e)))?;
                self.kdf_outlen = Some(n);
                Ok(())
            }
            PARAM_KDF_UKM => {
                let bytes = value.as_bytes().ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ECDH: '{key}' must be an octet string"
                    )))
                })?;
                self.kdf_ukm = Some(Zeroizing::new(bytes.to_vec()));
                Ok(())
            }
            other => {
                // The C provider silently ignores unknown parameters; do the
                // same so cross-language wire compatibility is maintained.
                trace!(param = other, "ECDH: ignoring unknown parameter");
                Ok(())
            }
        }
    }

    /// Builds a [`ParamSet`] reflecting the current effective context state.
    ///
    /// Mirrors C `ecdh_get_ctx_params()` (`ecdh_exch.c:353-405`). Returns the
    /// freshly built parameter set directly because, after the per-field
    /// validation that already happens in [`Self::set_params`], assembling the
    /// effective view cannot fail.
    fn collect_params(&self) -> ParamSet {
        let mut params = ParamSet::new();

        // Group name (only when set; reflects the curve currently in use).
        if let Some(group) = self.group.as_ref() {
            if let Some(curve) = group.curve_name() {
                params.set(
                    PARAM_GROUP,
                    ParamValue::Utf8String(curve.name().to_string()),
                );
            }
        }

        // Effective cofactor mode: when -1, the C provider reports the key's
        // cofactor flag; we replicate the resolved mode here so callers see
        // the value that would actually drive derivation.
        let effective_mode = match self.cofactor_mode {
            COFACTOR_MODE_USE_KEY => match self.group.as_ref() {
                Some(g) => match self.resolve_mode(g) {
                    EcdhMode::Standard => COFACTOR_MODE_DISABLED,
                    EcdhMode::CofactorDh => COFACTOR_MODE_ENABLED,
                },
                None => COFACTOR_MODE_DISABLED,
            },
            other => other,
        };
        params.set(PARAM_COFACTOR_MODE, ParamValue::Int32(effective_mode));

        params.set(
            PARAM_KDF_TYPE,
            ParamValue::Utf8String(self.kdf_type.as_param_string().to_string()),
        );

        if let Some(d) = self.kdf_digest.as_ref() {
            params.set(
                PARAM_KDF_DIGEST,
                ParamValue::Utf8String(d.name().to_string()),
            );
        }
        if let Some(props) = self.kdf_digest_props.as_ref() {
            params.set(
                PARAM_KDF_DIGEST_PROPS,
                ParamValue::Utf8String(props.clone()),
            );
        }
        if let Some(n) = self.kdf_outlen {
            // OSSL_PARAM uses size_t for outlen; we wire it as UInt64 (the
            // widest unsigned variant ParamSet exposes).
            params.set(PARAM_KDF_OUTLEN, ParamValue::UInt64(n as u64));
        }
        if let Some(ukm) = self.kdf_ukm.as_deref() {
            params.set(PARAM_KDF_UKM, ParamValue::OctetString(ukm.clone()));
        }

        params
    }
}

// ---------------------------------------------------------------------------
// KeyExchangeContext trait — wire-up
// ---------------------------------------------------------------------------

impl KeyExchangeContext for EcdhExchangeContext {
    /// Initialises the context with the local private key bytes.
    ///
    /// `key` is the big-endian private scalar (as produced by
    /// [`EcKey::private_key`] when serialised). `params` may carry the curve
    /// (`PARAM_GROUP`) and any KDF defaults; if no curve has previously been
    /// installed, one **must** appear in `params`.
    ///
    /// Mirrors C `ecdh_init()` (`ecdh_exch.c:112-137`): on every init,
    /// cofactor mode and KDF state are reset to defaults.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        if key.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: init requires a non-empty private key".to_string(),
            )));
        }

        // Apply any provided parameters first so the curve becomes available
        // before we reconstruct the EcKey.
        if let Some(p) = params {
            for (k, v) in p.iter() {
                self.apply_param(k, v)?;
            }
        }

        // Reset KDF/cofactor state to match C semantics: every fresh init
        // wipes the KDF configuration so leftover state from a previous
        // operation can't leak.
        self.cofactor_mode = COFACTOR_MODE_USE_KEY;
        self.kdf_type = EcdhKdfType::None;
        self.kdf_digest = None;
        self.kdf_digest_props = None;
        self.kdf_ukm = None;
        self.kdf_outlen = None;
        self.peer_public = None;

        // Validate the private scalar against the agreed group by attempting
        // to reconstruct the key. This rejects zero / out-of-range scalars
        // up-front (mirrors `EC_KEY_get0_group(vecdh) == NULL` and
        // EC_KEY_check_key tests in the C path).
        let group = self.require_group()?.clone();
        let scalar = BigNum::from_bytes_be(key);
        let reconstructed = EcKey::from_private_key(&group, scalar).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: invalid private scalar for selected curve: {e}"
            )))
        })?;
        // Persist the bytes (zeroized) only after the key has been validated.
        self.our_private = Some(Zeroizing::new(key.to_vec()));
        // Drop the reconstructed handle — it carries the secret in
        // `SecureBigNum`, so its Drop will clean it up.
        let _ = reconstructed;

        debug!(
            curve = ?group.curve_name().map(|c| c.name()),
            "ECDH: context initialised"
        );
        Ok(())
    }

    /// Sets the peer public key.
    ///
    /// `peer_key` must be a SEC1-encoded public point (`0x04 || x || y` for
    /// uncompressed, `0x02/0x03 || x` for compressed). The peer must live on
    /// the same curve as the local key — comparison is done by canonical
    /// curve name (since [`EcGroup`] does not derive `PartialEq`).
    ///
    /// Mirrors C `ecdh_set_peer()` / `ecdh_match_params()`
    /// (`ecdh_exch.c:139-182`).
    fn set_peer(&mut self, peer_key: &[u8]) -> ProviderResult<()> {
        if peer_key.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: set_peer requires a non-empty public key".to_string(),
            )));
        }
        let group = self.require_group()?.clone();
        // Decode the peer point under the agreed group; this validates SEC1
        // form and on-curve membership.
        let point = EcPoint::from_bytes(&group, peer_key).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: peer public key decoding failed: {e}"
            )))
        })?;
        // Reject points at infinity (would yield degenerate shared secret).
        if point.is_at_infinity() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: peer public key is the point at infinity".to_string(),
            )));
        }
        // On-curve check (defense in depth: from_bytes also enforces this,
        // but this guards against a future relaxation of from_bytes).
        let on_curve = point.is_on_curve(&group).map_err(|e| {
            ProviderError::Common(CommonError::InvalidArgument(format!(
                "ECDH: peer public key on-curve check failed: {e}"
            )))
        })?;
        if !on_curve {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: peer public key is not on the configured curve".to_string(),
            )));
        }

        // Encode into uncompressed SEC1 for storage so reconstruction is
        // canonical regardless of the input form.
        let canonical = point
            .to_bytes(&group, PointConversionForm::Uncompressed)
            .map_err(|e| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "ECDH: failed to encode peer public point: {e}"
                )))
            })?;

        // Match domain parameters by curve name (the C path uses
        // EC_GROUP_cmp; for known curves that reduces to identity comparison
        // of curve identifiers, which is exactly what we do).
        if let Some(existing) = self.group.as_ref() {
            if !Self::curves_match(existing, &group) {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    "ECDH: peer key has mismatching domain parameters".to_string(),
                )));
            }
        }
        self.peer_public = Some(canonical);
        debug!(
            curve = ?group.curve_name().map(|c| c.name()),
            "ECDH: peer key set"
        );
        Ok(())
    }

    /// Performs the ECDH derivation.
    ///
    /// Dispatches on [`Self::kdf_type`]:
    /// - [`EcdhKdfType::None`] → [`Self::plain_derive`]
    /// - [`EcdhKdfType::X963`] → [`Self::x963_kdf_derive`]
    ///
    /// Mirrors C `ecdh_derive()` (`ecdh_exch.c:573-587`).
    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize> {
        if secret.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ECDH: derive requires a non-empty output buffer".to_string(),
            )));
        }
        let n = match self.kdf_type {
            EcdhKdfType::None => self.plain_derive(secret)?,
            EcdhKdfType::X963 => self.x963_kdf_derive(secret)?,
        };
        debug!(written = n, kdf = ?self.kdf_type, "ECDH: derive complete");
        Ok(n)
    }

    /// Returns the current context parameters (mirrors `ecdh_get_ctx_params`).
    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(self.collect_params())
    }

    /// Applies a batch of parameters (mirrors `ecdh_set_ctx_params`).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        for (k, v) in params.iter() {
            self.apply_param(k, v)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Clone / Drop — provider context lifecycle
// ---------------------------------------------------------------------------

impl Clone for EcdhExchangeContext {
    fn clone(&self) -> Self {
        // EcKey is intentionally not Clone, so we copy raw bytes (and the
        // EcGroup, which is Clone). Mirrors C `ecdh_dupctx()`
        // (`ecdh_exch.c:197-248`) which clones the keys via EC_KEY_dup +
        // EC_KEY_up_ref.
        Self {
            our_private: self
                .our_private
                .as_ref()
                .map(|v| Zeroizing::new(v.as_slice().to_vec())),
            peer_public: self.peer_public.clone(),
            group: self.group.clone(),
            cofactor_mode: self.cofactor_mode,
            kdf_type: self.kdf_type,
            kdf_digest: self.kdf_digest.clone(),
            kdf_digest_props: self.kdf_digest_props.clone(),
            kdf_ukm: self
                .kdf_ukm
                .as_ref()
                .map(|v| Zeroizing::new(v.as_slice().to_vec())),
            kdf_outlen: self.kdf_outlen,
        }
    }
}

impl Drop for EcdhExchangeContext {
    fn drop(&mut self) {
        // Most fields zero themselves through Zeroizing; explicitly zero the
        // peer_public (a plain Vec<u8>) so any cached point bytes don't
        // linger in process memory. Replaces C `OPENSSL_clear_free` calls
        // for the peer public key in `ecdh_freectx()` (line ~243).
        if let Some(p) = self.peer_public.as_mut() {
            p.zeroize();
        }
    }
}

impl std::fmt::Debug for EcdhExchangeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid leaking key material into log output: print presence
        // indicators / lengths only, never the underlying byte buffers.
        f.debug_struct("EcdhExchangeContext")
            .field(
                "curve",
                &self
                    .group
                    .as_ref()
                    .and_then(EcGroup::curve_name)
                    .map(|c| c.name()),
            )
            .field("has_private_key", &self.our_private.is_some())
            .field("has_peer_key", &self.peer_public.is_some())
            .field("cofactor_mode", &self.cofactor_mode)
            .field("kdf_type", &self.kdf_type)
            .field("kdf_digest", &self.kdf_digest.as_ref().map(MessageDigest::name))
            .field("kdf_digest_props", &self.kdf_digest_props)
            .field("kdf_outlen", &self.kdf_outlen)
            .field("kdf_ukm_len", &self.kdf_ukm.as_ref().map(|u| u.len()))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// EcdhExchange — provider entry point
// ---------------------------------------------------------------------------

/// Zero-sized ECDH key exchange provider.
///
/// Implements [`KeyExchangeProvider`]. Construct an instance via
/// `EcdhExchange` and create per-operation contexts with [`Self::new_ctx`].
///
/// Replaces the C `ossl_ecdh_keyexch_functions` dispatch table at
/// `ecdh_exch.c:623-638`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EcdhExchange;

impl KeyExchangeProvider for EcdhExchange {
    fn name(&self) -> &'static str {
        "ECDH"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>> {
        debug!("ECDH: new_ctx");
        Ok(Box::new(EcdhExchangeContext::new()))
    }
}

// ---------------------------------------------------------------------------
// descriptors — registration
// ---------------------------------------------------------------------------

/// Returns the algorithm descriptors for the ECDH key exchange.
///
/// Mirrors the C dispatch entry `ossl_ecdh_keyexch_functions` (single
/// algorithm with name `"ECDH"`). The returned vector is consumed by the
/// provider's algorithm registry to expose ECDH through the EVP fetch path.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["ECDH"],
        "provider=default",
        "Elliptic-Curve Diffie-Hellman key exchange (NIST P-curves and secp256k1)",
    )]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_crypto::ec::{EcGroup, EcKey, NamedCurve, PointConversionForm};

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    fn group_for(curve: NamedCurve) -> EcGroup {
        EcGroup::from_curve_name(curve).expect("known curve loads")
    }

    fn keypair_bytes(group: &EcGroup) -> (Vec<u8>, Vec<u8>) {
        let key = EcKey::generate(group).expect("EC keypair generation");
        let priv_bn = key.private_key().expect("generated key has private scalar");
        let priv_bytes = priv_bn.to_bytes_be();
        let pub_point = key.public_key().expect("generated key has public point");
        let pub_bytes = pub_point
            .to_bytes(group, PointConversionForm::Uncompressed)
            .expect("encode public point");
        (priv_bytes, pub_bytes)
    }

    fn ctx_with_curve(curve: NamedCurve) -> EcdhExchangeContext {
        let mut p = ParamSet::new();
        p.set(
            PARAM_GROUP,
            ParamValue::Utf8String(curve.name().to_string()),
        );
        let mut ctx = EcdhExchangeContext::new();
        ctx.set_params(&p).expect("set group param");
        ctx
    }

    fn run_full_exchange(curve: NamedCurve) {
        let group = group_for(curve);
        let (alice_priv, alice_pub) = keypair_bytes(&group);
        let (bob_priv, bob_pub) = keypair_bytes(&group);

        // Alice's view: her private + Bob's public.
        let mut alice_ctx = ctx_with_curve(curve);
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");

        // Bob's view: his private + Alice's public.
        let mut bob_ctx = ctx_with_curve(curve);
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");

        let secret_len = curve.field_size_bytes();
        let mut alice_secret = vec![0u8; secret_len];
        let mut bob_secret = vec![0u8; secret_len];
        let an = alice_ctx
            .derive(&mut alice_secret)
            .expect("alice derive");
        let bn = bob_ctx.derive(&mut bob_secret).expect("bob derive");
        assert_eq!(an, bn, "shared secret lengths must match");
        assert_eq!(
            &alice_secret[..an],
            &bob_secret[..bn],
            "shared secrets must be identical"
        );
    }

    // -----------------------------------------------------------------
    // Provider-level sanity
    // -----------------------------------------------------------------

    #[test]
    fn ecdh_exchange_default_is_zero_sized() {
        assert_eq!(std::mem::size_of::<EcdhExchange>(), 0);
    }

    #[test]
    fn provider_reports_canonical_name() {
        assert_eq!(EcdhExchange.name(), "ECDH");
    }

    #[test]
    fn descriptors_registers_ecdh() {
        let d = descriptors();
        assert_eq!(d.len(), 1);
        assert!(d[0].names.contains(&"ECDH"));
        assert_eq!(d[0].property, "provider=default");
        assert!(!d[0].description.is_empty());
    }

    #[test]
    fn new_ctx_returns_valid_context() {
        let ctx = EcdhExchange.new_ctx().expect("new_ctx ok");
        // Default ParamSet should at least carry KDF type and cofactor mode
        // (group is absent until configured).
        let params = ctx.get_params().expect("get_params");
        assert!(params.contains(PARAM_KDF_TYPE));
        assert!(params.contains(PARAM_COFACTOR_MODE));
        assert!(!params.contains(PARAM_GROUP));
    }

    // -----------------------------------------------------------------
    // Lifecycle / negative paths
    // -----------------------------------------------------------------

    #[test]
    fn init_requires_nonempty_key() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let err = ctx.init(&[], None).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn init_requires_curve_to_be_set() {
        let mut ctx = EcdhExchangeContext::new();
        let group = group_for(NamedCurve::Prime256v1);
        let (priv_bytes, _) = keypair_bytes(&group);
        // No curve installed yet → init must fail.
        let err = ctx.init(&priv_bytes, None).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn set_peer_requires_nonempty_key() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let err = ctx.set_peer(&[]).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn set_peer_rejects_invalid_point() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let err = ctx.set_peer(&[0xAA; 65]).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn derive_fails_without_init() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut buf = vec![0u8; 32];
        let err = ctx.derive(&mut buf).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn derive_fails_without_peer() {
        let group = group_for(NamedCurve::Prime256v1);
        let (priv_bytes, _) = keypair_bytes(&group);
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        ctx.init(&priv_bytes, None).expect("init");
        let mut buf = vec![0u8; 32];
        let err = ctx.derive(&mut buf).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn derive_rejects_empty_buffer() {
        let group = group_for(NamedCurve::Prime256v1);
        let (priv_bytes, _) = keypair_bytes(&group);
        let (_, peer_bytes) = keypair_bytes(&group);
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        ctx.init(&priv_bytes, None).expect("init");
        ctx.set_peer(&peer_bytes).expect("set_peer");
        let mut buf: Vec<u8> = Vec::new();
        let err = ctx.derive(&mut buf).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn unknown_curve_rejected() {
        let mut p = ParamSet::new();
        p.set(
            PARAM_GROUP,
            ParamValue::Utf8String("UNKNOWN_CURVE".to_string()),
        );
        let mut ctx = EcdhExchangeContext::new();
        let err = ctx.set_params(&p).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // -----------------------------------------------------------------
    // End-to-end exchanges across curves
    // -----------------------------------------------------------------

    #[test]
    fn full_ecdh_exchange_p256() {
        run_full_exchange(NamedCurve::Prime256v1);
    }

    #[test]
    fn full_ecdh_exchange_p384() {
        run_full_exchange(NamedCurve::Secp384r1);
    }

    #[test]
    fn full_ecdh_exchange_p521() {
        run_full_exchange(NamedCurve::Secp521r1);
    }

    #[test]
    fn full_ecdh_exchange_secp256k1() {
        run_full_exchange(NamedCurve::Secp256k1);
    }

    // -----------------------------------------------------------------
    // Output buffer truncation (ECDH-specific behaviour)
    // -----------------------------------------------------------------

    #[test]
    fn plain_derive_truncates_short_output_buffer() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (alice_priv, alice_pub) = keypair_bytes(&group);
        let (bob_priv, bob_pub) = keypair_bytes(&group);

        let mut alice_ctx = ctx_with_curve(curve);
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");

        let mut bob_ctx = ctx_with_curve(curve);
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");

        // 16-byte buffer is shorter than the natural P-256 ECDH size (32).
        // Per ecdh_plain_derive line 466, ECDH MUST truncate (not error).
        let mut a = vec![0u8; 16];
        let mut b = vec![0u8; 16];
        let an = alice_ctx.derive(&mut a).expect("alice short derive");
        let bn = bob_ctx.derive(&mut b).expect("bob short derive");
        assert_eq!(an, 16);
        assert_eq!(bn, 16);
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------
    // Parameter round-trips
    // -----------------------------------------------------------------

    #[test]
    fn group_param_round_trip() {
        let ctx = ctx_with_curve(NamedCurve::Secp384r1);
        let p = ctx.get_params().expect("get_params");
        let v = p
            .get(PARAM_GROUP)
            .expect("group param present")
            .as_str()
            .expect("string");
        assert_eq!(v, "secp384r1");
    }

    #[test]
    fn cofactor_mode_round_trip() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(PARAM_COFACTOR_MODE, ParamValue::Int32(1));
        ctx.set_params(&p).expect("set cofactor mode");
        let out = ctx.get_params().expect("get_params");
        assert_eq!(
            out.get(PARAM_COFACTOR_MODE)
                .and_then(|v| v.as_i32()),
            Some(1)
        );
    }

    #[test]
    fn cofactor_mode_rejects_out_of_range() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(PARAM_COFACTOR_MODE, ParamValue::Int32(2));
        let err = ctx.set_params(&p).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn kdf_type_round_trip() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_TYPE,
            ParamValue::Utf8String(KDF_NAME_X9_63.to_string()),
        );
        ctx.set_params(&p).expect("set kdf-type");
        let out = ctx.get_params().expect("get_params");
        assert_eq!(
            out.get(PARAM_KDF_TYPE).and_then(|v| v.as_str()),
            Some(KDF_NAME_X9_63)
        );
    }

    #[test]
    fn kdf_type_rejects_unknown() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_TYPE,
            ParamValue::Utf8String("BOGUSKDF".to_string()),
        );
        let err = ctx.set_params(&p).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    #[test]
    fn kdf_digest_round_trip_sha256() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        ctx.set_params(&p).expect("set kdf-digest");
        let out = ctx.get_params().expect("get_params");
        let d = out
            .get(PARAM_KDF_DIGEST)
            .and_then(|v| v.as_str())
            .expect("digest reported");
        // The MessageDigest layer canonicalizes the algorithm name. Accept any
        // of the common spellings the underlying crypto crate may report.
        assert!(
            d.eq_ignore_ascii_case("SHA-256")
                || d.eq_ignore_ascii_case("SHA256")
                || d.eq_ignore_ascii_case("SHA2-256"),
            "unexpected digest name '{d}'"
        );
    }

    #[test]
    fn kdf_outlen_round_trip() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(PARAM_KDF_OUTLEN, ParamValue::UInt64(48));
        ctx.set_params(&p).expect("set kdf-outlen");
        let out = ctx.get_params().expect("get_params");
        assert_eq!(
            out.get(PARAM_KDF_OUTLEN).and_then(|v| v.as_u64()),
            Some(48u64)
        );
    }

    #[test]
    fn kdf_ukm_round_trip() {
        let mut ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_UKM,
            ParamValue::OctetString(vec![1, 2, 3, 4, 5]),
        );
        ctx.set_params(&p).expect("set kdf-ukm");
        let out = ctx.get_params().expect("get_params");
        assert_eq!(
            out.get(PARAM_KDF_UKM).and_then(|v| v.as_bytes()),
            Some(&[1u8, 2, 3, 4, 5][..])
        );
    }

    // -----------------------------------------------------------------
    // X9.63 KDF derivation
    // -----------------------------------------------------------------

    #[test]
    fn x963_kdf_derive_produces_matching_secrets() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (alice_priv, alice_pub) = keypair_bytes(&group);
        let (bob_priv, bob_pub) = keypair_bytes(&group);

        let configure = |ctx: &mut EcdhExchangeContext| {
            let mut p = ParamSet::new();
            p.set(
                PARAM_KDF_TYPE,
                ParamValue::Utf8String(KDF_NAME_X9_63.to_string()),
            );
            p.set(
                PARAM_KDF_DIGEST,
                ParamValue::Utf8String("SHA-256".to_string()),
            );
            p.set(PARAM_KDF_OUTLEN, ParamValue::UInt64(40));
            p.set(
                PARAM_KDF_UKM,
                ParamValue::OctetString(b"shared-info".to_vec()),
            );
            ctx.set_params(&p).expect("kdf params");
        };

        let mut alice_ctx = ctx_with_curve(curve);
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");
        configure(&mut alice_ctx);

        let mut bob_ctx = ctx_with_curve(curve);
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");
        configure(&mut bob_ctx);

        let mut a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        let an = alice_ctx.derive(&mut a).expect("alice kdf derive");
        let bn = bob_ctx.derive(&mut b).expect("bob kdf derive");
        assert_eq!(an, 40);
        assert_eq!(bn, 40);
        assert_eq!(&a[..40], &b[..40]);
        // Tail bytes should remain untouched (pre-zeroed).
        assert!(a[40..].iter().all(|&b| b == 0));
    }

    #[test]
    fn x963_kdf_rejects_outlen_larger_than_buffer() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (priv_bytes, _) = keypair_bytes(&group);
        let (_, peer_bytes) = keypair_bytes(&group);

        let mut ctx = ctx_with_curve(curve);
        ctx.init(&priv_bytes, None).expect("init");
        ctx.set_peer(&peer_bytes).expect("set_peer");

        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_TYPE,
            ParamValue::Utf8String(KDF_NAME_X9_63.to_string()),
        );
        p.set(
            PARAM_KDF_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        p.set(PARAM_KDF_OUTLEN, ParamValue::UInt64(64));
        ctx.set_params(&p).expect("kdf params");

        let mut buf = vec![0u8; 32]; // Smaller than outlen 64.
        let err = ctx.derive(&mut buf).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    #[test]
    fn x963_kdf_requires_outlen() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (priv_bytes, _) = keypair_bytes(&group);
        let (_, peer_bytes) = keypair_bytes(&group);

        let mut ctx = ctx_with_curve(curve);
        ctx.init(&priv_bytes, None).expect("init");
        ctx.set_peer(&peer_bytes).expect("set_peer");

        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_TYPE,
            ParamValue::Utf8String(KDF_NAME_X9_63.to_string()),
        );
        p.set(
            PARAM_KDF_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        // Intentionally omit kdf-outlen.
        ctx.set_params(&p).expect("kdf params");

        let mut buf = vec![0u8; 32];
        let err = ctx.derive(&mut buf).unwrap_err();
        assert!(matches!(err, ProviderError::Init(_)));
    }

    // -----------------------------------------------------------------
    // derive_skey
    // -----------------------------------------------------------------

    #[test]
    fn derive_skey_plain_returns_natural_size() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (alice_priv, alice_pub) = keypair_bytes(&group);
        let (bob_priv, bob_pub) = keypair_bytes(&group);

        let mut alice_ctx = ctx_with_curve(curve);
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");

        let mut bob_ctx = ctx_with_curve(curve);
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");

        let a = alice_ctx.derive_skey().expect("alice derive_skey");
        let b = bob_ctx.derive_skey().expect("bob derive_skey");
        assert!(!a.is_empty());
        assert_eq!(a, b);
    }

    #[test]
    fn derive_skey_with_x963_kdf_uses_outlen() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (alice_priv, alice_pub) = keypair_bytes(&group);
        let (bob_priv, bob_pub) = keypair_bytes(&group);

        let configure = |ctx: &mut EcdhExchangeContext| {
            let mut p = ParamSet::new();
            p.set(
                PARAM_KDF_TYPE,
                ParamValue::Utf8String(KDF_NAME_X9_63.to_string()),
            );
            p.set(
                PARAM_KDF_DIGEST,
                ParamValue::Utf8String("SHA-256".to_string()),
            );
            p.set(PARAM_KDF_OUTLEN, ParamValue::UInt64(48));
            ctx.set_params(&p).expect("kdf params");
        };

        let mut alice_ctx = ctx_with_curve(curve);
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");
        configure(&mut alice_ctx);
        let mut bob_ctx = ctx_with_curve(curve);
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");
        configure(&mut bob_ctx);

        let a = alice_ctx.derive_skey().expect("alice derive_skey kdf");
        let b = bob_ctx.derive_skey().expect("bob derive_skey kdf");
        assert_eq!(a.len(), 48);
        assert_eq!(b.len(), 48);
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------
    // Cofactor mode
    // -----------------------------------------------------------------

    #[test]
    fn cofactor_mode_default_resolves_to_standard_for_unit_cofactor() {
        // P-256 has cofactor 1, so the default mode (-1) should resolve to
        // EcdhMode::Standard, which is observable through get_params reporting
        // mode 0.
        let ctx = ctx_with_curve(NamedCurve::Prime256v1);
        let out = ctx.get_params().expect("get_params");
        assert_eq!(
            out.get(PARAM_COFACTOR_MODE).and_then(|v| v.as_i32()),
            Some(0)
        );
    }

    // -----------------------------------------------------------------
    // Clone preserves state
    // -----------------------------------------------------------------

    #[test]
    fn clone_preserves_state_and_derives_same_secret() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (alice_priv, alice_pub) = keypair_bytes(&group);
        let (bob_priv, bob_pub) = keypair_bytes(&group);

        let mut alice_ctx = ctx_with_curve(curve);
        alice_ctx.init(&alice_priv, None).expect("alice init");
        alice_ctx.set_peer(&bob_pub).expect("alice set_peer");

        let mut alice_clone = alice_ctx.clone();

        let mut bob_ctx = ctx_with_curve(curve);
        bob_ctx.init(&bob_priv, None).expect("bob init");
        bob_ctx.set_peer(&alice_pub).expect("bob set_peer");

        let mut a = vec![0u8; 32];
        let mut a_clone = vec![0u8; 32];
        let mut b = vec![0u8; 32];
        let an = alice_ctx.derive(&mut a).expect("alice derive");
        let acn = alice_clone.derive(&mut a_clone).expect("alice clone derive");
        let bn = bob_ctx.derive(&mut b).expect("bob derive");
        assert_eq!(an, acn);
        assert_eq!(an, bn);
        assert_eq!(&a[..an], &a_clone[..acn]);
        assert_eq!(&a[..an], &b[..bn]);
    }

    // -----------------------------------------------------------------
    // Mismatching domain parameters
    // -----------------------------------------------------------------

    #[test]
    fn set_peer_rejects_mismatching_curve() {
        // Generate a P-256 peer and try to load it into a P-384 context.
        let p256 = group_for(NamedCurve::Prime256v1);
        let p256_key = EcKey::generate(&p256).expect("p256 keygen");
        let p256_pub = p256_key
            .public_key()
            .unwrap()
            .to_bytes(&p256, PointConversionForm::Uncompressed)
            .expect("encode");
        let mut ctx = ctx_with_curve(NamedCurve::Secp384r1);
        let err = ctx.set_peer(&p256_pub).unwrap_err();
        assert!(matches!(err, ProviderError::Common(_)));
    }

    // -----------------------------------------------------------------
    // ecdh_size invariants
    // -----------------------------------------------------------------

    #[test]
    fn ecdh_size_matches_curve_field_size() {
        for curve in [
            NamedCurve::Prime256v1,
            NamedCurve::Secp384r1,
            NamedCurve::Secp521r1,
            NamedCurve::Secp256k1,
        ] {
            let group = group_for(curve);
            let n = EcdhExchangeContext::ecdh_size(&group).expect("size ok");
            assert_eq!(n, curve.field_size_bytes(), "{:?}", curve);
        }
    }

    // -----------------------------------------------------------------
    // Init resets KDF state (mirrors C ecdh_init)
    // -----------------------------------------------------------------

    #[test]
    fn init_resets_kdf_state() {
        let curve = NamedCurve::Prime256v1;
        let group = group_for(curve);
        let (priv_bytes, _) = keypair_bytes(&group);

        let mut ctx = ctx_with_curve(curve);
        // Pre-load a non-default KDF configuration.
        let mut p = ParamSet::new();
        p.set(
            PARAM_KDF_TYPE,
            ParamValue::Utf8String(KDF_NAME_X9_63.to_string()),
        );
        p.set(
            PARAM_KDF_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        p.set(PARAM_KDF_OUTLEN, ParamValue::UInt64(48));
        ctx.set_params(&p).expect("kdf params");

        // Now init — KDF state must be wiped.
        ctx.init(&priv_bytes, None).expect("init");
        let out = ctx.get_params().expect("get_params");
        assert_eq!(
            out.get(PARAM_KDF_TYPE).and_then(|v| v.as_str()),
            Some("")
        );
        assert!(!out.contains(PARAM_KDF_DIGEST));
        assert!(!out.contains(PARAM_KDF_OUTLEN));
    }
}
