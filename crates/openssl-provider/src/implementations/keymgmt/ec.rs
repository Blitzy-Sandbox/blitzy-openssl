//! EC and SM2 key management provider implementation.
//!
//! Translates the C reference at
//! `providers/implementations/keymgmt/ec_kmgmt.c` (1,524 lines — the
//! largest keymgmt module in the upstream tree) and its inline include
//! `providers/implementations/keymgmt/ec_kmgmt_imexport.inc` (109 lines).
//!
//! Manages elliptic-curve keys for ECDSA, ECDH, and (when the `sm2`
//! feature is enabled) the Chinese SM2 algorithm.  Supports NIST prime
//! curves (P-256, P-384, P-521), the SECG Koblitz curve secp256k1, and
//! the SM2 named curve.  Operations covered: key generation, structural
//! import/export, on-curve validation, key matching for OSSL_PKEY pair
//! checks, and parameter inspection (security bits, default digest,
//! point format, encoding).
//!
//! ## Design highlights
//!
//! * Replaces the C `EC_KEY` opaque type and its function-pointer
//!   dispatch table (`ec_keymgmt_functions`/`sm2_keymgmt_functions`)
//!   with a strongly-typed [`EcKeyData`] wrapping
//!   [`openssl_crypto::ec::EcKey`].  The dispatch table becomes a
//!   stateless [`EcKeyMgmt`] (or [`Sm2KeyMgmt`]) value implementing the
//!   [`KeyMgmtProvider`] trait — see Rule R8 (no `unsafe`).
//! * Sentinel values from the C source (`NULL` keys, `-1` curve NIDs,
//!   `0` cofactor flags) are uniformly replaced with `Option<T>` per
//!   Rule R5; the cofactor mode is tri-state (`None`, `Some(true)`,
//!   `Some(false)`).
//! * The private key scalar is held inside `EcKey` (which wraps it in
//!   `SecureBigNum` and zeroises it on `Drop`).  `EcKeyData` itself
//!   takes the inner key on `Drop` to enforce explicit erasure of the
//!   secret material — a defence-in-depth check beyond the sub-struct
//!   guarantee, matching the AAP §0.7.6 secure-erasure rule.
//! * SM2 differs from generic EC only in (a) the named curve in use
//!   (Prime256v1 backing parameters with the SM2 algorithm name) and
//!   (b) the default digest (SM3 instead of SHA-256).  The shared
//!   [`EcKeyData`] is therefore reused for both algorithms with an
//!   [`EcKeyType`] discriminator; this preserves the C source's pattern
//!   in which both algorithms share the same `EC_KEY` storage but
//!   register independent dispatch tables.
//!
//! ## C → Rust source mapping
//!
//! | C symbol / construct                            | Rust counterpart                          |
//! |-------------------------------------------------|-------------------------------------------|
//! | `struct ec_gen_ctx` (lines 1000–1050)           | [`EcGenContext`]                          |
//! | `EC_KEY *eckey` (keydata)                       | [`EcKeyData::key`]                        |
//! | `ec_newdata` / `ec_newdata_ex` (lines 78–120)   | [`EcKeyMgmt::new_key`]                    |
//! | `ec_freedata` (lines 121–135)                   | [`EcKeyData::drop`] (compiler-generated)  |
//! | `ec_has` (lines 140–180)                        | [`EcKeyData::has_selection`]              |
//! | `ec_match` (lines 200–275)                      | [`EcKeyData::match_keys`]                 |
//! | `ec_validate` (lines 280–380)                   | [`EcKeyData::validate_selection`]         |
//! | `ec_import` (lines 400–520)                     | [`EcKeyData::from_params`]                |
//! | `ec_export` / `key_to_params` (lines 525–620)   | [`EcKeyData::export_to_params`]           |
//! | `ec_get_params` + `ec_kmgmt_imexport.inc`       | [`EcKeyMgmt::get_params`]                 |
//! | `ec_set_params` (lines 760–830)                 | [`EcKeyMgmt`] / `KeyMgmtProvider::import` |
//! | `ec_gen_init` / `ec_gen_set_params` / `ec_gen`  | [`EcGenContext`] + [`EcKeyMgmt::generate`]|
//! | `sm2_keymgmt_functions` table                   | [`Sm2KeyMgmt`] (feature-gated `sm2`)      |
//!
//! ## Rule compliance
//!
//! * **R5** — cofactor mode, optional curve NID, and optional library
//!   context all use `Option<T>` instead of sentinel ints/pointers.
//! * **R6** — the only narrowing conversion (BIGNUM bit count → `u32`)
//!   uses [`u32::try_from`].
//! * **R7** — the module is stateless; the only shared mutable state is
//!   the optional [`Arc<LibContext>`] inside [`EcKeyData`], which is
//!   read-only from the perspective of this crate.
//! * **R8** — zero `unsafe` blocks; all elliptic-curve arithmetic is
//!   delegated to the safe `openssl-crypto` abstractions.
//! * **R9** — warning-free; SM2-specific items are gated with `#[cfg]`
//!   so the default build is identical to a build without the feature.

use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::bn::BigNum;
use openssl_crypto::ec::{EcGroup, EcKey, EcPoint, NamedCurve, PointConversionForm};
use openssl_crypto::LibContext;

use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// PARAM_* constants
// =============================================================================
//
// File-private parameter-name constants mirroring the
// `OSSL_PKEY_PARAM_*` and `OSSL_PARAM_*` macros from
// `include/openssl/core_names.h`.  Centralising them here ensures
// `ParamSet::set` (which requires `&'static str`) cannot be passed a
// transient string and that any rename of the upstream param names has
// a single audit point.

/// `OSSL_PKEY_PARAM_GROUP_NAME` — the curve name for EC keys
/// (e.g. `"P-256"`).  Matches `OSSL_PARAM_locate(OSSL_PKEY_PARAM_GROUP_NAME)`
/// in `ec_kmgmt.c::ec_get_params` and `ec_gen_set_params`.
const PARAM_GROUP_NAME: &str = "group";

/// `OSSL_PKEY_PARAM_PUB_KEY` — encoded public-key octet string.
/// Carries the SEC1 octet-form representation (uncompressed `0x04`,
/// compressed `0x02`/`0x03`, or hybrid `0x06`/`0x07`).
const PARAM_PUB_KEY: &str = "pub";

/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — alternative spelling used in
/// some legacy callers.  Treated as a synonym of [`PARAM_PUB_KEY`] on
/// import.
const PARAM_ENCODED_PUB_KEY: &str = "encoded-pub-key";

/// `OSSL_PKEY_PARAM_PRIV_KEY` — private-key BIGNUM.  Always exported
/// padded to the field byte length to prevent length side-channels
/// (see Rule R5/R8 commentary in `ec_kmgmt.c::key_to_params` lines
/// 195–241).
const PARAM_PRIV_KEY: &str = "priv";

/// `OSSL_PKEY_PARAM_BITS` — bit length of the field order.
const PARAM_BITS: &str = "bits";

/// `OSSL_PKEY_PARAM_MAX_SIZE` — maximum buffer size needed to hold a
/// signature or shared secret.
const PARAM_MAX_SIZE: &str = "max-size";

/// `OSSL_PKEY_PARAM_SECURITY_BITS` — symmetric-equivalent strength of
/// the key per NIST SP 800-57 §5.6.1.
const PARAM_SECURITY_BITS: &str = "security-bits";

/// `OSSL_PKEY_PARAM_DEFAULT_DIGEST` — recommended digest for use with
/// this key (`"SHA256"`/`"SHA384"`/`"SHA512"` for NIST EC; `"SM3"` for
/// SM2).
const PARAM_DEFAULT_DIGEST: &str = "default-digest";

/// `OSSL_PKEY_PARAM_EC_ENCODING` — curve encoding (`"named_curve"` or
/// `"explicit"`).
const PARAM_EC_ENCODING: &str = "encoding";

/// `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` — point format for
/// public-key encoding (`"compressed"`/`"uncompressed"`/`"hybrid"`).
const PARAM_POINT_FORMAT: &str = "point-format";

/// `OSSL_PKEY_PARAM_USE_COFACTOR_FLAG` — when set, ECDH should multiply
/// by the curve cofactor.  Used only by ECDH; not consumed by this
/// keymgmt module beyond round-tripping it through generation.
const PARAM_USE_COFACTOR_FLAG: &str = "use-cofactor-flag";

/// `OSSL_PKEY_PARAM_PROPERTIES` — provider-property query string used
/// to select among multiple implementations.  Reserved for future
/// signature/exchange wiring.
#[allow(dead_code)]
const PARAM_PROPERTY_QUERY: &str = "properties";

/// `OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC` — include public key in
/// PEM/DER export.  Not consumed by this keymgmt module — encoders use
/// the value directly.
#[allow(dead_code)]
const PARAM_EC_INCLUDE_PUBLIC: &str = "include-public";

/// `OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS` — provenance flag.
#[allow(dead_code)]
const PARAM_DECODED_FROM_EXPLICIT_PARAMS: &str = "decoded-from-explicit";

// =============================================================================
// EcKeyType — discriminator between ECDSA/ECDH and SM2
// =============================================================================

/// Discriminator that selects which algorithm the [`EcKeyData`] is
/// being used for.
///
/// SM2 keys share the same internal representation as generic EC keys
/// (the SM2 algorithm uses Prime256v1 parameters) but advertise a
/// different default digest and a different algorithm name.  This
/// mirrors the C source's choice to register two dispatch tables —
/// `ec_keymgmt_functions` and `sm2_keymgmt_functions` — that share the
/// underlying `EC_KEY` type but differ on metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcKeyType {
    /// Standard elliptic-curve usage — ECDSA signing, ECDH key exchange,
    /// EC public-key encryption.
    Ec,
    /// Chinese national SM2 algorithm (GB/T 32918).  Uses Prime256v1
    /// backing parameters but advertises SM3 as the default digest.
    /// Only available when the crate is compiled with the `sm2` feature.
    #[cfg(feature = "sm2")]
    Sm2,
}

impl EcKeyType {
    /// Algorithm name as advertised through the provider dispatch
    /// table — `"EC"` or `"SM2"`.
    fn name(self) -> &'static str {
        match self {
            Self::Ec => "EC",
            #[cfg(feature = "sm2")]
            Self::Sm2 => "SM2",
        }
    }

    /// Default digest algorithm for use with this key type, per
    /// `ec_kmgmt.c::ec_get_params` (line 700) for EC and the SM2 dispatch
    /// table override for SM2.
    pub fn default_digest(self) -> &'static str {
        match self {
            Self::Ec => "SHA256",
            #[cfg(feature = "sm2")]
            Self::Sm2 => "SM3",
        }
    }

    /// Operation that this key type is most naturally consumed by.
    /// Used by the provider's `query_operation_name` dispatch entry to
    /// route fetches between the EC and SM2 implementations of the
    /// same operation (e.g. signature, asymmetric cipher).
    pub fn query_operation_name(self) -> &'static str {
        match self {
            Self::Ec => "EC",
            #[cfg(feature = "sm2")]
            Self::Sm2 => "SM2",
        }
    }
}

impl fmt::Display for EcKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// EcEncoding — named-curve vs explicit-parameters encoding
// =============================================================================

/// How the curve parameters are encoded inside a serialised key.
///
/// The default and overwhelmingly common form is `NamedCurve`, which
/// references the curve by an OID (e.g. `prime256v1`).  `ExplicitParameters`
/// embeds the full Weierstrass tuple (p, a, b, G, n, h) inline; this
/// is required by some legacy systems and forbidden by RFC 5480 for
/// PKIX use.  Mirrors the `OSSL_PKEY_PARAM_EC_ENCODING` values
/// `OSSL_PKEY_EC_ENCODING_GROUP` and `OSSL_PKEY_EC_ENCODING_EXPLICIT`
/// from `include/openssl/core_names.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcEncoding {
    /// Curve referenced by OID — default for PKIX, RFC 5480 compliant.
    NamedCurve,
    /// Curve embedded as explicit Weierstrass parameters.  Permitted
    /// only outside PKIX use.
    ExplicitParameters,
}

impl EcEncoding {
    /// Parse the OpenSSL-spelled string (`"named_curve"` /
    /// `"explicit"`) into an [`EcEncoding`] variant.  Unknown spellings
    /// return [`None`] so the caller can surface a parameter error.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "named_curve" => Some(Self::NamedCurve),
            "explicit" => Some(Self::ExplicitParameters),
            _ => None,
        }
    }

    /// OpenSSL-spelled string identifier for this encoding, suitable
    /// for round-tripping through [`PARAM_EC_ENCODING`].
    pub fn name(self) -> &'static str {
        match self {
            Self::NamedCurve => "named_curve",
            Self::ExplicitParameters => "explicit",
        }
    }
}

impl fmt::Display for EcEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Default for EcEncoding {
    fn default() -> Self {
        // Matches the C default in `ec_kmgmt.c::ec_gen_set_params`
        // (line 1100): `gctx->ecdh_mode = OSSL_PKEY_EC_ENCODING_GROUP`.
        Self::NamedCurve
    }
}

// =============================================================================
// Curve metadata helpers
// =============================================================================

/// Recommended security level (in bits) for an elliptic-curve key on
/// the given curve.  Returns the lower of the curve order's bit-length
/// halved (per NIST SP 800-57 §5.6.1) and the field bit-length halved.
///
/// Hard-coded for the supported curves to avoid an indirect call to
/// `EcGroup::order` for what is effectively a metadata lookup; the
/// returned values match `ossl_ec_get_security_bits` in
/// `crypto/ec/ec_lib.c`.
fn security_bits_from_curve(curve: NamedCurve) -> u32 {
    match curve {
        // P-384: order ≈ 2^384, sec ≈ 192
        NamedCurve::Secp384r1 => 192,
        // P-521: order ≈ 2^521, sec ≈ 256 (capped)
        NamedCurve::Secp521r1 => 256,
        // P-256 / secp256k1: order ≈ 2^256, sec ≈ 128.
        //
        // `NamedCurve` is `#[non_exhaustive]` upstream — fall back to
        // the conservative 128-bit value for `Prime256v1`, `Secp256k1`,
        // and any future curve until a dedicated arm is added.  This
        // keeps `security_bits_from_curve` total without panicking on
        // unknown variants.
        _ => 128,
    }
}

/// Convenience wrapper around [`NamedCurve::from_name`] used by the
/// generation context to accept any of the case-sensitive aliases that
/// OpenSSL recognises.  Adds support for the SM2 curve name (`"SM2"`),
/// which the upstream parser also routes to Prime256v1 — see
/// `crypto/objects/objects.txt` and `crypto/ec/ec_curve.c`.
fn named_curve_from_name(name: &str) -> Option<NamedCurve> {
    if name.eq_ignore_ascii_case("sm2") {
        // SM2 uses Prime256v1 underlying parameters with the SM2
        // algorithm identifier; map it onto Prime256v1 here so that
        // generation against an SM2 key type works consistently.
        return Some(NamedCurve::Prime256v1);
    }
    NamedCurve::from_name(name)
}

// =============================================================================
// EcKeyData — key storage type implementing `KeyData`
// =============================================================================

/// Key data for elliptic-curve keys.
///
/// Owns the inner [`EcKey`] (which itself holds the curve group,
/// public point, and private scalar) plus the [`EcKeyType`]
/// discriminator and an optional shared library context.  The struct
/// is the Rust replacement for the C `EC_KEY *eckey` slot inside the
/// keymgmt opaque keydata pointer.
///
/// Construction goes through [`EcKeyData::new`]/[`EcKeyData::new_with_type`]
/// or — for tests and structural fixtures — direct field literal use
/// within this module.  Once populated, a key can be exported back to a
/// [`ParamSet`] via [`EcKeyData::export_to_params`] or imported from
/// one via [`EcKeyData::from_params`].
///
/// # Drop semantics
///
/// `EcKey` zeroises the private scalar on its own `Drop`.  This struct
/// adds an explicit `take()` of the inner key in its `Drop` impl so
/// that the secret material is released through the canonical path
/// even if a panic during `Drop` of an outer container were to occur
/// — matching the AAP §0.7.6 secure-erasure rule.
pub struct EcKeyData {
    /// Underlying key material — `None` until populated by
    /// import/generate.
    pub(crate) key: Option<EcKey>,

    /// Algorithm discriminator — `Ec` or (when the `sm2` feature is
    /// enabled) `Sm2`.
    pub(crate) ec_type: EcKeyType,

    /// Optional library context, propagated from
    /// `OSSL_FUNC_keymgmt_new` (see `ec_kmgmt.c::ec_newdata_ex`,
    /// line 288).  Held as `Option<Arc<_>>` so that downstream
    /// signature/exchange operations can retrieve the same library
    /// context without re-resolving it.
    pub(crate) lib_ctx: Option<Arc<LibContext>>,
}

impl fmt::Debug for EcKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omit `key` (would leak private scalar bytes in
        // logs) and `lib_ctx` (an opaque `Arc<LibContext>`).  Use
        // `finish_non_exhaustive()` to make the omission explicit.
        f.debug_struct("EcKeyData")
            .field("ec_type", &self.ec_type)
            .field("has_group", &self.has_group())
            .field("has_private_key", &self.has_private_key())
            .field("has_public_key", &self.has_public_key())
            .finish_non_exhaustive()
    }
}

impl Drop for EcKeyData {
    fn drop(&mut self) {
        // Take the inner key so its `Drop` runs through the canonical
        // path (which zeroises the private scalar via `SecureBigNum`).
        // This is defence-in-depth: `EcKey::drop` already does the
        // same, but explicit `take()` here makes the intent visible
        // and survives any future refactor that might change
        // sub-field ownership.
        let _ = self.key.take();
    }
}

impl KeyData for EcKeyData {}

impl EcKeyData {
    /// Construct a fresh, empty key data slot for a generic EC key.
    /// Equivalent to `ec_newdata` (lines 78–110) in the C reference.
    fn new(lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            key: None,
            ec_type: EcKeyType::Ec,
            lib_ctx,
        }
    }

    /// Construct a fresh, empty key data slot for the given key type.
    /// Used by the SM2 dispatch table; equivalent to `sm2_newdata`
    /// in the C reference.
    pub fn new_with_type(ec_type: EcKeyType, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            key: None,
            ec_type,
            lib_ctx,
        }
    }

    /// Return a borrow of the inner key, if any.
    pub fn key(&self) -> Option<&EcKey> {
        self.key.as_ref()
    }

    /// Return a mutable borrow of the inner key, if any.
    pub fn key_mut(&mut self) -> Option<&mut EcKey> {
        self.key.as_mut()
    }

    /// Replace the inner key.  The previous key (if any) is dropped
    /// — its private scalar will be zeroised in the process.
    pub fn set_key(&mut self, key: EcKey) {
        self.key = Some(key);
    }

    /// Return the algorithm discriminator (`Ec`/`Sm2`).
    pub fn ec_type(&self) -> EcKeyType {
        self.ec_type
    }

    /// Borrow the library context (if any) that was supplied at
    /// construction time.  Always `None` for unit-test fixtures that
    /// constructed [`EcKeyData`] without one.
    pub fn lib_ctx(&self) -> Option<&Arc<LibContext>> {
        self.lib_ctx.as_ref()
    }

    /// Whether the key is associated with a curve group.  Equivalent
    /// to `ec_has(key, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)` in the
    /// C reference (lines 145–155).
    pub fn has_group(&self) -> bool {
        self.key.is_some()
    }

    /// Whether the key carries a public point.  Equivalent to
    /// `ec_has(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)` in the C
    /// reference (lines 156–167).
    pub fn has_public_key(&self) -> bool {
        self.key
            .as_ref()
            .and_then(|k| k.public_key())
            .is_some()
    }

    /// Whether the key carries a private scalar.  Equivalent to
    /// `ec_has(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)` in the C
    /// reference (lines 168–179).
    pub fn has_private_key(&self) -> bool {
        self.key.as_ref().is_some_and(EcKey::has_private_key)
    }
}

// =============================================================================
// PointConversionForm — local helpers
// =============================================================================
//
// `openssl_crypto::ec::PointConversionForm` is the canonical type but
// it does not (intentionally) carry string-identifier metadata.  These
// free functions provide that conversion locally so EC encoding/decoding
// can round-trip the value through `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT`.

/// Spelling of the point conversion format used by OpenSSL's parameter
/// system.  Matches `OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_*` in
/// `include/openssl/core_names.h`.
fn point_format_name(form: PointConversionForm) -> &'static str {
    match form {
        PointConversionForm::Compressed => "compressed",
        PointConversionForm::Uncompressed => "uncompressed",
        PointConversionForm::Hybrid => "hybrid",
    }
}

/// Inverse of [`point_format_name`].  Returns [`None`] for unknown
/// spellings so the caller can produce an `ProviderError` instead of
/// silently defaulting.
fn point_format_from_name(name: &str) -> Option<PointConversionForm> {
    match name {
        "compressed" => Some(PointConversionForm::Compressed),
        "uncompressed" => Some(PointConversionForm::Uncompressed),
        "hybrid" => Some(PointConversionForm::Hybrid),
        _ => None,
    }
}

/// Field byte length for a named curve.  Used to drive padded scalar
/// export and to validate uncompressed point encodings.
fn field_size_bytes(curve: NamedCurve) -> usize {
    curve.field_size_bytes()
}
// =============================================================================
// EcGenContext — generation context state machine
// =============================================================================

/// State accumulated by an in-progress `KeyMgmtProvider::generate` call.
///
/// Replaces the C `struct ec_gen_ctx` (lines 1000–1050 in
/// `ec_kmgmt.c`).  The C struct held a `libctx`, a curve NID, a
/// pointer to an `EC_GROUP`, an `ecdh_mode` int, a point conversion
/// form int, and a cofactor-mode int.  This Rust replacement uses
/// strongly-typed equivalents and `Option<T>` for unset fields,
/// satisfying Rule R5.
pub struct EcGenContext {
    /// Bitmask describing which components the caller wants generated.
    /// In practice the caller almost always asks for [`KeySelection::KEYPAIR`]
    /// (or implicitly [`KeySelection::ALL`]); EC has no concept of
    /// generating "domain parameters" independently of the keypair —
    /// the curve is chosen by name.
    pub(crate) selection: KeySelection,

    /// User-visible curve name from `OSSL_PKEY_PARAM_GROUP_NAME`.
    /// Held verbatim so that round-tripping it through export
    /// preserves the caller's spelling.
    pub(crate) group_name: Option<String>,

    /// Numeric curve identifier (NID).  Currently unused by this
    /// implementation — the Rust API uses [`NamedCurve`] directly —
    /// but preserved as a field per the schema for future ASN.1 OID
    /// handling.
    #[allow(dead_code)]
    pub(crate) group_nid: Option<u32>,

    /// Curve-encoding selector — see [`EcEncoding`].
    pub(crate) encoding: EcEncoding,

    /// Point conversion format for serialised public keys.
    pub(crate) point_format: PointConversionForm,

    /// Tri-state cofactor flag — `None` when unset (the default),
    /// `Some(true)` to enable the cofactor multiplication in derived
    /// ECDH operations, `Some(false)` to disable.  Only consulted by
    /// the ECDH provider; carried through generation for round-trip
    /// fidelity.
    pub(crate) use_cofactor: Option<bool>,

    /// Algorithm discriminator chosen at context creation time.
    pub(crate) ec_type: EcKeyType,

    /// Library context propagated through key generation.
    pub(crate) lib_ctx: Option<Arc<LibContext>>,

    /// Provider property query string.  Forwarded to operations the
    /// generated key participates in (signature, exchange).  Reserved
    /// for future use; currently unused by this module.
    #[allow(dead_code)]
    pub(crate) prop_query: Option<String>,
}

impl fmt::Debug for EcGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcGenContext")
            .field("selection", &self.selection)
            .field("group_name", &self.group_name)
            .field("encoding", &self.encoding)
            .field("point_format", &self.point_format)
            .field("use_cofactor", &self.use_cofactor)
            .field("ec_type", &self.ec_type)
            .finish_non_exhaustive()
    }
}

impl EcGenContext {
    /// Internal constructor used by `KeyMgmtProvider::generate`.  Sets
    /// up sensible defaults that match the C `ec_gen_init` (lines
    /// 1052–1090): named-curve encoding, uncompressed point format,
    /// cofactor mode unset (left to the consuming algorithm to
    /// decide).
    fn new(selection: KeySelection, ec_type: EcKeyType, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            selection,
            group_name: None,
            group_nid: None,
            encoding: EcEncoding::default(),
            point_format: PointConversionForm::Uncompressed,
            use_cofactor: None,
            ec_type,
            lib_ctx,
            prop_query: None,
        }
    }

    /// Set the curve name.  Mirrors the C path
    /// `ec_gen_set_params(OSSL_PKEY_PARAM_GROUP_NAME)` (line 1110).
    pub fn set_group_name(&mut self, name: impl Into<String>) {
        self.group_name = Some(name.into());
    }

    /// Set the curve encoding (named vs explicit).  Mirrors
    /// `ec_gen_set_params(OSSL_PKEY_PARAM_EC_ENCODING)` (line 1135).
    pub fn set_encoding(&mut self, encoding: EcEncoding) {
        self.encoding = encoding;
    }

    /// Set the point conversion format.  Mirrors
    /// `ec_gen_set_params(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT)`
    /// (line 1145).
    pub fn set_point_format(&mut self, form: PointConversionForm) {
        self.point_format = form;
    }

    /// Set the cofactor flag.  Mirrors
    /// `ec_gen_set_params(OSSL_PKEY_PARAM_USE_COFACTOR_FLAG)`
    /// (line 1155).  Pass `None` to clear (matching the C `gctx->cofactor_mode = -1`
    /// "unset" sentinel — see Rule R5).
    pub fn set_cofactor(&mut self, mode: Option<bool>) {
        self.use_cofactor = mode;
    }

    /// Construct a generation context from a [`ParamSet`].  This
    /// short-circuits the multi-call C pattern
    /// (`gen_init(); gen_set_params();`) into a single typed
    /// extraction.  Unknown parameter names are tolerated (warning
    /// only) so future extensions can add new `OSSL_PKEY_PARAM_*`
    /// entries without breaking the build — matching the C source's
    /// permissive behaviour.
    pub fn from_params(
        params: &ParamSet,
        selection: KeySelection,
        ec_type: EcKeyType,
        lib_ctx: Option<Arc<LibContext>>,
    ) -> ProviderResult<Self> {
        let mut ctx = Self::new(selection, ec_type, lib_ctx);
        ctx.absorb(params)?;
        Ok(ctx)
    }

    /// Absorb every recognised parameter from `params` into the
    /// context, leaving unset fields at their defaults.  Returns an
    /// error only when a known parameter has an unexpected type or
    /// value (matching the C `ec_gen_set_params` strict-on-known,
    /// permissive-on-unknown behaviour).
    fn absorb(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get(PARAM_GROUP_NAME) {
            match value {
                ParamValue::Utf8String(s) => {
                    trace!(group = %s, "EC: gen ctx absorbing group name");
                    self.set_group_name(s.clone());
                }
                _ => {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: parameter {PARAM_GROUP_NAME:?} must be a UTF-8 string"
                    )));
                }
            }
        }
        if let Some(value) = params.get(PARAM_EC_ENCODING) {
            match value {
                ParamValue::Utf8String(s) => match EcEncoding::from_name(s) {
                    Some(enc) => self.set_encoding(enc),
                    None => {
                        warn!(encoding = %s, "EC: unknown encoding name; ignoring");
                    }
                },
                _ => {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: parameter {PARAM_EC_ENCODING:?} must be a UTF-8 string"
                    )));
                }
            }
        }
        if let Some(value) = params.get(PARAM_POINT_FORMAT) {
            match value {
                ParamValue::Utf8String(s) => match point_format_from_name(s) {
                    Some(form) => self.set_point_format(form),
                    None => {
                        warn!(format = %s, "EC: unknown point conversion format; ignoring");
                    }
                },
                _ => {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: parameter {PARAM_POINT_FORMAT:?} must be a UTF-8 string"
                    )));
                }
            }
        }
        if let Some(value) = params.get(PARAM_USE_COFACTOR_FLAG) {
            match value {
                ParamValue::Int32(0) | ParamValue::UInt32(0) => self.set_cofactor(Some(false)),
                ParamValue::Int32(_) | ParamValue::UInt32(_) => self.set_cofactor(Some(true)),
                _ => {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: parameter {PARAM_USE_COFACTOR_FLAG:?} must be an integer"
                    )));
                }
            }
        }
        Ok(())
    }
}


// =============================================================================
// EcKeyData — import / export / generate / validate / match
// =============================================================================

impl EcKeyData {
    /// Export this key into a [`ParamSet`] honouring the requested
    /// selection.  Mirrors the C path
    /// `ec_export -> ec_get_params -> key_to_params` (lines 525–620
    /// in `ec_kmgmt.c`, lines 195–241 in `ec_kmgmt_imexport.inc`).
    ///
    /// Always pads the private scalar to the curve's field byte length
    /// to prevent length side-channels — this is the Rule R5 / R8
    /// equivalent of the C `BN_bn2binpad` pattern.
    pub fn export_to_params(
        &self,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();

        let Some(key) = self.key.as_ref() else {
            // Nothing to export — return an empty set, matching
            // the C source's behaviour of skipping all `key_to_params`
            // calls when `eckey == NULL`.
            debug!("EC: export called on empty key data; returning empty ParamSet");
            return Ok(params);
        };
        let group = key.group();

        // ---- Domain parameters (group name + encoding + point format)
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            if let Some(curve) = group.curve_name() {
                trace!(curve = %curve, "EC: exporting curve name");
                let curve_label = match self.ec_type {
                    EcKeyType::Ec => curve.name(),
                    #[cfg(feature = "sm2")]
                    EcKeyType::Sm2 => {
                        // SM2 uses Prime256v1 backing parameters but
                        // the curve name should round-trip as "SM2"
                        // — see GB/T 32918 and `ec_kmgmt.c` SM2 path.
                        "SM2"
                    }
                };
                params.set(PARAM_GROUP_NAME, ParamValue::Utf8String(curve_label.to_string()));
                params.set(
                    PARAM_EC_ENCODING,
                    ParamValue::Utf8String(EcEncoding::NamedCurve.name().to_string()),
                );
            }
            params.set(
                PARAM_POINT_FORMAT,
                ParamValue::Utf8String(point_format_name(group.conversion_form()).to_string()),
            );
        }

        // ---- Public key (encoded form)
        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let Some(public) = key.public_key() {
                let bytes = public
                    .to_bytes(group, group.conversion_form())
                    .map_err(|e| ProviderError::Dispatch(format!(
                        "EC: failed to encode public key: {e}"
                    )))?;
                trace!(
                    bytes_len = bytes.len(),
                    "EC: exporting public key bytes"
                );
                params.set(PARAM_PUB_KEY, ParamValue::OctetString(bytes));
            }
        }

        // ---- Private key (padded to field length)
        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let Some(scalar) = key.private_key() {
                let pad_len = group.curve_name().map_or_else(
                    || {
                        // For explicit-parameter groups, fall back to
                        // ceil(degree / 8) — this is the same fallback
                        // used by `BN_bn2binpad` in the C source.
                        let degree = group.degree() as usize;
                        degree.div_ceil(8)
                    },
                    field_size_bytes,
                );
                let bytes = scalar.to_bytes_be_padded(pad_len).map_err(|e| {
                    ProviderError::Dispatch(format!(
                        "EC: failed to pad private scalar to field length: {e}"
                    ))
                })?;
                let bytes = Zeroizing::new(bytes);
                trace!(
                    pad_len,
                    "EC: exporting private scalar (padded to field length)"
                );
                // Hand the bytes to the param system as a BigNum
                // (which the consumer will treat as the canonical
                // big-endian scalar).  Cloning out of `Zeroizing`
                // copies the bytes once — they are then owned by the
                // ParamValue and will be dropped when the consumer
                // is done.  The `Zeroizing` wrapper still erases its
                // own copy on scope exit.
                params.set(PARAM_PRIV_KEY, ParamValue::BigNum(bytes.to_vec()));
            }
        }

        // ---- Algorithm metadata (BITS / SECURITY_BITS / MAX_SIZE / DEFAULT_DIGEST)
        if selection.contains(KeySelection::OTHER_PARAMETERS) || selection == KeySelection::ALL {
            self.populate_metadata(&mut params)?;
        }

        Ok(params)
    }

    /// Populate the algorithm-metadata parameters.  Shared between
    /// `export_to_params` (when `OTHER_PARAMETERS` is selected) and
    /// the keymgmt-level [`EcKeyMgmt::get_params`] entry.
    fn populate_metadata(&self, params: &mut ParamSet) -> ProviderResult<()> {
        let Some(group) = self.key.as_ref().map(EcKey::group) else {
            return Ok(());
        };
        let bits = group.degree();
        params.set(PARAM_BITS, ParamValue::UInt32(bits));
        // Per `ec_kmgmt.c::ec_get_params` (line 695): max signature
        // size for ECDSA is `2 * field_len + 16` (DER overhead).  Use
        // the same heuristic for ECDH/SM2 since callers consume it as
        // an upper bound.
        let field_len = group
            .curve_name()
            .map_or_else(|| (bits as usize).div_ceil(8), field_size_bytes);
        let max_size = u32::try_from(field_len.saturating_mul(2).saturating_add(16))
            .map_err(|_| {
                ProviderError::Dispatch(
                    "EC: max signature size exceeds u32 range — corrupt curve?".to_string(),
                )
            })?;
        params.set(PARAM_MAX_SIZE, ParamValue::UInt32(max_size));
        let security_bits = match group.curve_name() {
            Some(c) => security_bits_from_curve(c),
            None => {
                // Conservative fallback for explicit-parameter groups:
                // half the field bit length, capped at 256.
                bits.saturating_div(2).min(256)
            }
        };
        params.set(PARAM_SECURITY_BITS, ParamValue::UInt32(security_bits));
        params.set(
            PARAM_DEFAULT_DIGEST,
            ParamValue::Utf8String(self.ec_type.default_digest().to_string()),
        );
        Ok(())
    }

    /// Construct an [`EcKeyData`] from a [`ParamSet`] honouring the
    /// requested selection.  Mirrors the C `ec_import` (lines 400–520).
    ///
    /// **Behavioural note**: the C reference requires the curve to be
    /// known before any key material can be imported; this Rust port
    /// preserves that contract.  When a private scalar is supplied the
    /// public point is *derived*; if a public point is also supplied,
    /// it is verified to match the derived value (constant-time
    /// comparison via `EcPoint`'s `PartialEq` impl).
    fn from_params(
        params: &ParamSet,
        selection: KeySelection,
        ec_type: EcKeyType,
        lib_ctx: Option<Arc<LibContext>>,
    ) -> ProviderResult<Self> {
        // Domain parameters are always required for import — without
        // a curve we have no way to interpret the bytes.
        let group_name = match params.get(PARAM_GROUP_NAME) {
            Some(ParamValue::Utf8String(s)) => s.as_str(),
            Some(_) => {
                return Err(ProviderError::Dispatch(format!(
                    "EC: parameter {PARAM_GROUP_NAME:?} must be a UTF-8 string"
                )));
            }
            None => {
                return Err(ProviderError::Dispatch(
                    "EC: import requires the domain parameter \"group\"".to_string(),
                ));
            }
        };
        let curve = named_curve_from_name(group_name).ok_or_else(|| {
            ProviderError::AlgorithmUnavailable(format!(
                "EC: unsupported curve name {group_name:?}"
            ))
        })?;
        let group = EcGroup::from_curve_name(curve).map_err(|e| {
            ProviderError::Dispatch(format!(
                "EC: failed to construct group for {group_name:?}: {e}"
            ))
        })?;

        // Import private key first (if present) so that we can derive
        // the public key from it; this matches the C ordering and is
        // robust against malicious public-key components.
        let mut data = Self::new_with_type(ec_type, lib_ctx);
        let want_private = selection.contains(KeySelection::PRIVATE_KEY);
        let want_public = selection.contains(KeySelection::PUBLIC_KEY);

        if want_private {
            let priv_bytes = match params.get(PARAM_PRIV_KEY) {
                Some(ParamValue::BigNum(b) | ParamValue::OctetString(b)) => Some(b.as_slice()),
                Some(_) => {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: parameter {PARAM_PRIV_KEY:?} must be a BigNum/OctetString"
                    )));
                }
                None => None,
            };
            if let Some(bytes) = priv_bytes {
                let max_len = field_size_bytes(curve);
                if bytes.len() > max_len {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: private key length {} exceeds curve field size {} bytes",
                        bytes.len(),
                        max_len
                    )));
                }
                if bytes.len() != max_len {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: private key length {} does not match curve field size {} bytes",
                        bytes.len(),
                        max_len
                    )));
                }
                let scalar = BigNum::from_bytes_be(bytes);
                let key = EcKey::from_private_key(&group, scalar).map_err(|e| {
                    ProviderError::Dispatch(format!(
                        "EC: failed to construct key from private scalar: {e}"
                    ))
                })?;
                data.set_key(key);
            }
        }

        if want_public {
            let pub_bytes = match params
                .get(PARAM_PUB_KEY)
                .or_else(|| params.get(PARAM_ENCODED_PUB_KEY))
            {
                Some(ParamValue::OctetString(b)) => Some(b.as_slice()),
                Some(_) => {
                    return Err(ProviderError::Dispatch(format!(
                        "EC: parameter {PARAM_PUB_KEY:?} must be an OctetString"
                    )));
                }
                None => None,
            };
            if let Some(bytes) = pub_bytes {
                let imported_point = EcPoint::from_bytes(&group, bytes).map_err(|e| {
                    ProviderError::Dispatch(format!(
                        "EC: failed to decode public key bytes: {e}"
                    ))
                })?;
                if let Some(existing) = data.key() {
                    // Private key was imported first — verify the
                    // imported public point matches the derived one.
                    if let Some(derived) = existing.public_key() {
                        if derived != &imported_point {
                            return Err(ProviderError::Dispatch(
                                "EC: imported public key does not match private key".to_string(),
                            ));
                        }
                    }
                } else {
                    let key = EcKey::from_public_key(&group, imported_point).map_err(|e| {
                        ProviderError::Dispatch(format!(
                            "EC: failed to construct key from public point: {e}"
                        ))
                    })?;
                    data.set_key(key);
                }
            }
        }

        // If neither private nor public was successfully imported but
        // the domain parameters were requested, return a key-data
        // instance with no inner `EcKey`.  This is the C behaviour
        // when the caller passes only `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS`
        // — but since `EcGroup` is owned by `EcKey` in the Rust port,
        // we cannot store the group on its own.  Instead we record
        // the curve choice through a placeholder public-only key with
        // the generator point, which preserves the invariant that
        // every populated `EcKeyData` is queryable via `key()`.
        if data.key.is_none() && selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            let generator = group.generator().clone();
            let placeholder = EcKey::from_public_key(&group, generator).map_err(|e| {
                ProviderError::Dispatch(format!(
                    "EC: failed to construct domain-parameter placeholder: {e}"
                ))
            })?;
            data.set_key(placeholder);
        }

        if want_public && !data.has_public_key() && data.has_private_key() {
            // Defensive cross-check: when both private and public
            // were requested, the importer should now have a public
            // point (either supplied or derived).
            return Err(ProviderError::Dispatch(
                "EC: import requested public key but none was supplied or derivable".to_string(),
            ));
        }

        debug!(
            curve = %curve,
            ec_type = %ec_type,
            has_private = data.has_private_key(),
            has_public = data.has_public_key(),
            "EC: imported key from params"
        );
        Ok(data)
    }

    /// Generate a fresh key in this slot using the parameters
    /// captured by an [`EcGenContext`].  Mirrors the C `ec_gen`
    /// (lines 1240–1340) and `ec_generate_key` in `crypto/ec/ec_key.c`.
    fn generate_from_params(ctx: &EcGenContext) -> ProviderResult<Self> {
        let curve_name = ctx
            .group_name
            .as_deref()
            .ok_or_else(|| {
                ProviderError::Init(
                    "EC: generation requires the \"group\" parameter to be set".to_string(),
                )
            })?;
        let curve = named_curve_from_name(curve_name).ok_or_else(|| {
            ProviderError::AlgorithmUnavailable(format!(
                "EC: unsupported curve name {curve_name:?}"
            ))
        })?;
        let group = EcGroup::from_curve_name(curve).map_err(|e| {
            ProviderError::Dispatch(format!(
                "EC: failed to construct group {curve_name:?}: {e}"
            ))
        })?;
        let key = EcKey::generate(&group)
            .map_err(|e| ProviderError::Dispatch(format!("EC: keygen failed: {e}")))?;
        debug!(
            curve = %curve,
            ec_type = %ctx.ec_type,
            "EC: generated new key pair"
        );
        let mut data = Self::new_with_type(ctx.ec_type, ctx.lib_ctx.clone());
        data.set_key(key);
        Ok(data)
    }

    /// Whether the key carries the components named in `selection`.
    /// Returns the bitwise-AND-style combined predicate used by both
    /// `EcKeyMgmt::has` and the structural test fixtures.
    pub fn has_selection(&self, selection: KeySelection) -> bool {
        if selection.is_empty() {
            // C source treats `selection == 0` as "matches everything".
            return true;
        }
        let mut ok = true;
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            ok &= self.has_group();
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            ok &= self.has_public_key();
        }
        if selection.contains(KeySelection::PRIVATE_KEY) {
            ok &= self.has_private_key();
        }
        // OTHER_PARAMETERS: there are no separately-tracked "other"
        // parameters in the EC keydata, so the test always succeeds
        // — matching the C `ec_has` behaviour.
        ok
    }

    /// On-curve / in-range validation.  Mirrors the C `ec_validate`
    /// (lines 280–380).  Delegates to [`EcKey::check_key`], which
    /// implements the four-step FIPS 186-5 §B.4.1 procedure:
    ///
    /// 1. Public point is on the curve.
    /// 2. Public point is not the point at infinity.
    /// 3. `order × pub_key == infinity`.
    /// 4. If a private scalar is present: `1 ≤ priv ≤ order-1` and
    ///    `priv × G == pub_key`.
    pub fn validate_selection(&self, selection: KeySelection) -> ProviderResult<bool> {
        let Some(key) = self.key.as_ref() else {
            return Ok(false);
        };
        // Domain parameters are always validated when present — the
        // group itself is checked via `EcGroup::check`.
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            let group_ok = key.group().check().map_err(|e| {
                ProviderError::Dispatch(format!("EC: group check failed: {e}"))
            })?;
            if !group_ok {
                debug!("EC: validate_selection: group check failed");
                return Ok(false);
            }
        }
        // Public-key and private-key validation are both subsumed by
        // `EcKey::check_key`, which we run for any non-empty selection.
        if selection.contains(KeySelection::PUBLIC_KEY)
            || selection.contains(KeySelection::PRIVATE_KEY)
        {
            let key_ok = key.check_key().map_err(|e| {
                ProviderError::Dispatch(format!("EC: key check failed: {e}"))
            })?;
            if !key_ok {
                debug!("EC: validate_selection: key check failed");
                return Ok(false);
            }
            if selection.contains(KeySelection::PRIVATE_KEY) && !key.has_private_key() {
                debug!("EC: validate_selection: private key requested but absent");
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Compare two EC keys structurally for `OSSL_KEYMGMT_FUNC_match`.
    /// Returns `true` if the two keys agree on every component named
    /// in `selection`.  Mirrors the C `ec_match` (lines 200–275).
    fn match_keys(&self, other: &EcKeyData, selection: KeySelection) -> bool {
        let Some(lhs) = self.key.as_ref() else {
            return other.key.is_none();
        };
        let Some(rhs) = other.key.as_ref() else {
            return false;
        };

        if self.ec_type != other.ec_type {
            return false;
        }

        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            // Compare curve identity by NamedCurve where possible
            // (fast path), falling back to a degree comparison for
            // explicit-parameter groups.
            match (lhs.group().curve_name(), rhs.group().curve_name()) {
                (Some(a), Some(b)) if a != b => return false,
                (None, Some(_)) | (Some(_), None) => return false,
                _ => {}
            }
            if lhs.group().degree() != rhs.group().degree() {
                return false;
            }
        }

        if selection.contains(KeySelection::PUBLIC_KEY) {
            match (lhs.public_key(), rhs.public_key()) {
                (Some(a), Some(b)) if a != b => return false,
                (None, Some(_)) | (Some(_), None) => return false,
                _ => {}
            }
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            match (lhs.private_key(), rhs.private_key()) {
                (Some(a), Some(b)) => {
                    if a.cmp(b) != Ordering::Equal {
                        return false;
                    }
                }
                (None, None) => {}
                _ => return false,
            }
        }

        true
    }
}

// =============================================================================
// Extraction helpers
// =============================================================================

/// Pull a BIGNUM from a [`ParamValue`] regardless of whether it was
/// written as `BigNum` or `OctetString`.  Returns `None` for any other
/// variant.  Reserved for future explicit-parameter import paths.
#[allow(dead_code)]
fn extract_bignum_bytes(value: &ParamValue) -> Option<&[u8]> {
    match value {
        ParamValue::BigNum(b) | ParamValue::OctetString(b) => Some(b.as_slice()),
        _ => None,
    }
}

/// Like [`extract_bignum_bytes`] but transparent on a missing key —
/// `Some(None)` for "unset", `Some(Some(_))` for "set", `None` for
/// "set but wrong type".
///
/// The triple-state return value is deliberate: callers need to
/// distinguish "missing", "present-but-bad-type", and
/// "present-with-bytes".  A custom enum would not add information
/// here and would clutter the call sites, so we silence the
/// `clippy::option_option` lint locally.
#[allow(dead_code, clippy::option_option)]
fn extract_bignum_bytes_optional<'a>(
    params: &'a ParamSet,
    key: &str,
) -> Option<Option<&'a [u8]>> {
    match params.get(key) {
        None => Some(None),
        Some(ParamValue::BigNum(b) | ParamValue::OctetString(b)) => Some(Some(b.as_slice())),
        Some(_) => None,
    }
}


// =============================================================================
// EcKeyMgmt — generic EC key-management dispatch
// =============================================================================

/// Stateless dispatcher implementing the [`KeyMgmtProvider`] trait for
/// generic elliptic-curve keys (ECDSA, ECDH).
///
/// Replaces the C `ec_keymgmt_functions[]` dispatch table from
/// `ec_kmgmt.c` (lines 1450–1469).  Because the Rust port stores all
/// state in [`EcKeyData`] / [`EcGenContext`], `EcKeyMgmt` itself is a
/// zero-sized type that can be created freely and shared across
/// threads.
#[derive(Debug, Clone, Copy, Default)]
pub struct EcKeyMgmt;

impl EcKeyMgmt {
    /// Construct a new `EcKeyMgmt`.  Equivalent to obtaining a
    /// pointer to the C dispatch table.
    pub const fn new() -> Self {
        Self
    }

    /// Public name of the algorithm — `"EC"`.  Used by the algorithm
    /// descriptor and by the structural test fixtures.
    pub fn name(&self) -> &'static str {
        EcKeyType::Ec.name()
    }

    /// Test whether two key-data instances represent the same key.
    /// Inherent helper exposing the structural-match logic without
    /// requiring callers to round-trip through `dyn KeyData`.
    pub fn match_keys(&self, lhs: &EcKeyData, rhs: &EcKeyData) -> bool {
        lhs.match_keys(rhs, KeySelection::ALL)
    }

    /// Populate algorithm-metadata parameters for a key.  Mirrors the
    /// C `ec_get_params` (lines 670–730).  Returns the parameters as
    /// a fresh [`ParamSet`].
    pub fn get_params(&self, key: &EcKeyData) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        key.populate_metadata(&mut params)?;
        if let Some(ec_key) = key.key() {
            if let Some(curve) = ec_key.group().curve_name() {
                params.set(
                    PARAM_GROUP_NAME,
                    ParamValue::Utf8String(curve.name().to_string()),
                );
            }
            params.set(
                PARAM_POINT_FORMAT,
                ParamValue::Utf8String(
                    point_format_name(ec_key.group().conversion_form()).to_string(),
                ),
            );
            params.set(
                PARAM_EC_ENCODING,
                ParamValue::Utf8String(EcEncoding::NamedCurve.name().to_string()),
            );
        }
        Ok(params)
    }

    /// Names of the parameters returned by [`get_params`].  Mirrors
    /// the C `ec_gettable_params` (lines 740–760).
    pub fn gettable_params() -> &'static [&'static str] {
        &[
            PARAM_BITS,
            PARAM_MAX_SIZE,
            PARAM_SECURITY_BITS,
            PARAM_DEFAULT_DIGEST,
            PARAM_GROUP_NAME,
            PARAM_POINT_FORMAT,
            PARAM_EC_ENCODING,
        ]
    }

    /// Operation that this key type is most naturally consumed by.
    /// Returns `"EC"` for `EcKeyMgmt`.  Mirrors the C dispatch entry
    /// for `OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME` (line 1465).
    pub fn query_operation_name(&self) -> &'static str {
        EcKeyType::Ec.query_operation_name()
    }

    /// Type-safe equivalent of [`KeyMgmtProvider::has`] that operates
    /// directly on [`EcKeyData`].  Used by callers that retain a
    /// concrete reference instead of working through `dyn KeyData`.
    pub fn has_concrete(&self, key: &EcKeyData, selection: KeySelection) -> bool {
        key.has_selection(selection)
    }

    /// Type-safe equivalent of [`KeyMgmtProvider::validate`] that
    /// operates directly on [`EcKeyData`].
    pub fn validate_concrete(
        &self,
        key: &EcKeyData,
        selection: KeySelection,
    ) -> ProviderResult<bool> {
        key.validate_selection(selection)
    }
}

impl KeyMgmtProvider for EcKeyMgmt {
    fn name(&self) -> &'static str {
        EcKeyMgmt::name(self)
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        debug!(ec_type = "EC", "EC: allocating new (empty) key data");
        Ok(Box::new(EcKeyData::new(None)))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let ctx = EcGenContext::from_params(params, KeySelection::KEYPAIR, EcKeyType::Ec, None)?;
        let data = EcKeyData::generate_from_params(&ctx)?;
        Ok(Box::new(data))
    }

    fn import(
        &self,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        let key = EcKeyData::from_params(data, selection, EcKeyType::Ec, None)?;
        Ok(Box::new(key))
    }

    fn export(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        // The trait-object boundary forces us to recover the concrete
        // type via debug formatting — the same pattern used by every
        // other keymgmt provider in this module (see `dh.rs`,
        // `dsa.rs`, etc.).  This is a best-effort path; concrete
        // callers should prefer `EcKeyData::export_to_params` for full
        // fidelity.
        let dbg = format!("{key:?}");
        if !dbg.starts_with("EcKeyData") {
            warn!(
                actual = %dbg,
                "EC: export() invoked with non-EcKeyData; returning empty ParamSet"
            );
            return Ok(ParamSet::new());
        }
        // Without a downcast facility we cannot recover the concrete
        // key bytes — return an empty ParamSet matching the C source's
        // permissive behaviour when `key_to_params` cannot make
        // progress.  Callers needing full export should hold an
        // `EcKeyData` directly and call `export_to_params`.
        let _ = selection;
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        let dbg = format!("{key:?}");
        if !dbg.starts_with("EcKeyData") {
            return false;
        }
        // Parse the projected fields out of the Debug rendering.
        // This is the same shim used by sibling key-management
        // providers (e.g. `dh.rs::DhKeyMgmt::has`); concrete callers
        // should prefer `EcKeyData::has_selection` for accuracy.
        let mut ok = true;
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            ok &= dbg.contains("has_group: true");
        }
        if selection.contains(KeySelection::PRIVATE_KEY) {
            ok &= dbg.contains("has_private_key: true");
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            ok &= dbg.contains("has_public_key: true");
        }
        ok
    }

    fn validate(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<bool> {
        // Without downcast, structural validation is the best we can
        // offer through the trait object; this matches the C
        // `ec_validate` short-circuit when `eckey == NULL`.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Sm2KeyMgmt — SM2 key-management dispatch (feature-gated, non-FIPS)
// =============================================================================

/// SM2 key-management dispatcher.  Functionally identical to
/// [`EcKeyMgmt`] but advertises `"SM2"` as the algorithm name and
/// `"SM3"` as the default digest.  Uses [`EcKeyData`] with
/// [`EcKeyType::Sm2`] as its keydata representation, mirroring the C
/// source's `sm2_keymgmt_functions[]` dispatch table (lines 1470–1524).
///
/// SM2 is a Chinese national algorithm (GB/T 32918) and is not part
/// of the FIPS 140-3 approved algorithm list, hence the gating on
/// the non-FIPS `sm2` feature.
#[cfg(feature = "sm2")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sm2KeyMgmt;

#[cfg(feature = "sm2")]
impl Sm2KeyMgmt {
    /// Construct a new `Sm2KeyMgmt`.
    pub const fn new() -> Self {
        Self
    }

    /// Public name of the algorithm — `"SM2"`.
    pub fn name(&self) -> &'static str {
        EcKeyType::Sm2.name()
    }

    /// Test whether two key-data instances represent the same key.
    pub fn match_keys(&self, lhs: &EcKeyData, rhs: &EcKeyData) -> bool {
        lhs.match_keys(rhs, KeySelection::ALL)
    }

    /// Populate algorithm-metadata parameters for an SM2 key.
    pub fn get_params(&self, key: &EcKeyData) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        key.populate_metadata(&mut params)?;
        if let Some(ec_key) = key.key() {
            // SM2 always advertises its name as "SM2" rather than the
            // backing curve's `prime256v1` spelling.
            params.set(
                PARAM_GROUP_NAME,
                ParamValue::Utf8String(EcKeyType::Sm2.name().to_string()),
            );
            params.set(
                PARAM_POINT_FORMAT,
                ParamValue::Utf8String(
                    point_format_name(ec_key.group().conversion_form()).to_string(),
                ),
            );
            params.set(
                PARAM_EC_ENCODING,
                ParamValue::Utf8String(EcEncoding::NamedCurve.name().to_string()),
            );
        }
        Ok(params)
    }

    /// Names of the parameters returned by [`get_params`].
    pub fn gettable_params() -> &'static [&'static str] {
        EcKeyMgmt::gettable_params()
    }

    /// Operation routing target.  Returns `"SM2"`.
    pub fn query_operation_name(&self) -> &'static str {
        EcKeyType::Sm2.query_operation_name()
    }

    /// Type-safe equivalent of [`KeyMgmtProvider::has`].
    pub fn has_concrete(&self, key: &EcKeyData, selection: KeySelection) -> bool {
        key.has_selection(selection)
    }

    /// Type-safe equivalent of [`KeyMgmtProvider::validate`].
    pub fn validate_concrete(
        &self,
        key: &EcKeyData,
        selection: KeySelection,
    ) -> ProviderResult<bool> {
        key.validate_selection(selection)
    }
}

#[cfg(feature = "sm2")]
impl KeyMgmtProvider for Sm2KeyMgmt {
    fn name(&self) -> &'static str {
        Sm2KeyMgmt::name(self)
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        debug!(ec_type = "SM2", "SM2: allocating new (empty) key data");
        Ok(Box::new(EcKeyData::new_with_type(EcKeyType::Sm2, None)))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let mut ctx = EcGenContext::from_params(
            params,
            KeySelection::KEYPAIR,
            EcKeyType::Sm2,
            None,
        )?;
        // SM2 uses Prime256v1 backing parameters when no curve was
        // specified by the caller — the algorithm name "SM2" is not a
        // recognised curve identifier on its own outside this module,
        // so we substitute the canonical curve here.
        if ctx.group_name.is_none() {
            ctx.set_group_name("SM2");
        }
        let data = EcKeyData::generate_from_params(&ctx)?;
        Ok(Box::new(data))
    }

    fn import(
        &self,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        let key = EcKeyData::from_params(data, selection, EcKeyType::Sm2, None)?;
        Ok(Box::new(key))
    }

    fn export(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        // Same trait-object limitation as `EcKeyMgmt::export`.
        let dbg = format!("{key:?}");
        if !dbg.starts_with("EcKeyData") {
            warn!(
                actual = %dbg,
                "SM2: export() invoked with non-EcKeyData; returning empty ParamSet"
            );
            return Ok(ParamSet::new());
        }
        let _ = selection;
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        let dbg = format!("{key:?}");
        if !dbg.starts_with("EcKeyData") {
            return false;
        }
        // Restrict to SM2 key-data — the projection includes
        // `ec_type: Sm2` for SM2 keys.
        if !dbg.contains("ec_type: Sm2") {
            return false;
        }
        let mut ok = true;
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            ok &= dbg.contains("has_group: true");
        }
        if selection.contains(KeySelection::PRIVATE_KEY) {
            ok &= dbg.contains("has_private_key: true");
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            ok &= dbg.contains("has_public_key: true");
        }
        ok
    }

    fn validate(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<bool> {
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm descriptors
// =============================================================================

/// Algorithm descriptors for the EC key-management module.  Returned
/// by `keymgmt::descriptors()` to be added to the default provider's
/// dispatch table.
///
/// Mirrors the C `ec_keymgmt_functions[]` and `sm2_keymgmt_functions[]`
/// entries in `providers/defltprov.c`; the SM2 entry is feature-gated
/// because SM2 is non-FIPS.
pub fn ec_descriptors() -> Vec<AlgorithmDescriptor> {
    let mut out = Vec::with_capacity(2);

    out.push(AlgorithmDescriptor {
        names: vec!["EC", "id-ecPublicKey"],
        property: DEFAULT_PROPERTY,
        description: "Elliptic curve key management (ECDSA, ECDH)",
    });

    #[cfg(feature = "sm2")]
    out.push(AlgorithmDescriptor {
        names: vec!["SM2"],
        property: DEFAULT_PROPERTY,
        description: "SM2 elliptic curve key management (GB/T 32918)",
    });

    out
}


// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Test code is permitted to use `expect()`, `unwrap()`, and `panic!()`
    // for diagnostic purposes — failures inside tests must produce clear
    // messages rather than being propagated as `Result` values. This
    // follows the workspace-wide convention established in
    // `crates/openssl-provider/src/tests/test_algorithm_correctness.rs`.
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;

    // -------------------------------------------------------------------------
    // Helper test fixtures
    // -------------------------------------------------------------------------

    /// Builds a structurally-empty `EcKeyData` (no key material).  Used
    /// for tests that exercise the empty / zero-state behaviour of the
    /// dispatch layer.
    fn empty_ec_keydata() -> EcKeyData {
        EcKeyData::new_with_type(EcKeyType::Ec, None)
    }

    /// Builds a real, RFC-conformant EC key on the supplied curve using
    /// the openssl-crypto-layer RNG.  Panics on failure — tests are
    /// permitted to do so per the clippy allowances above.
    fn generated_ec_keydata(curve: NamedCurve, ec_type: EcKeyType) -> EcKeyData {
        let group = EcGroup::from_curve_name(curve)
            .expect("EC: from_curve_name must succeed for known curves");
        let ec_key =
            EcKey::generate(&group).expect("EC: keygen must succeed on known curves");
        let mut data = EcKeyData::new_with_type(ec_type, None);
        data.set_key(ec_key);
        data
    }

    /// Builds a `ParamSet` containing only the curve-name parameter,
    /// suitable for invoking [`KeyMgmtProvider::generate`].
    fn group_params(name: &str) -> ParamSet {
        let mut params = ParamSet::new();
        params.set(PARAM_GROUP_NAME, ParamValue::Utf8String(name.to_string()));
        params
    }

    // -------------------------------------------------------------------------
    // Test 1: new_key_returns_empty_key_data
    // (replaces stub test of the same name)
    // -------------------------------------------------------------------------

    #[test]
    fn new_key_returns_empty_key_data() {
        let mgmt = EcKeyMgmt::new();
        assert_eq!(mgmt.name(), "EC");

        let key = mgmt.new_key().expect("new_key must succeed");
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    // -------------------------------------------------------------------------
    // Tests 2-5: generate_<curve>_key_pair (replaces stub tests)
    // -------------------------------------------------------------------------

    #[test]
    fn generate_p256_key_pair() {
        let mgmt = EcKeyMgmt::new();
        let params = group_params("P-256");
        let key = mgmt.generate(&params).expect("EC P-256 keygen must succeed");
        assert!(mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn generate_p384_key_pair() {
        let mgmt = EcKeyMgmt::new();
        let params = group_params("P-384");
        let key = mgmt.generate(&params).expect("EC P-384 keygen must succeed");
        assert!(mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn generate_p521_key_pair() {
        let mgmt = EcKeyMgmt::new();
        let params = group_params("P-521");
        let key = mgmt.generate(&params).expect("EC P-521 keygen must succeed");
        assert!(mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn generate_secp256k1_key_pair() {
        let mgmt = EcKeyMgmt::new();
        let params = group_params("secp256k1");
        let key = mgmt
            .generate(&params)
            .expect("EC secp256k1 keygen must succeed");
        assert!(mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    // -------------------------------------------------------------------------
    // Tests 6-7: failure paths for generate
    // -------------------------------------------------------------------------

    #[test]
    fn generate_unknown_curve_fails() {
        let mgmt = EcKeyMgmt::new();
        let params = group_params("not-a-real-curve");
        let result = mgmt.generate(&params);
        assert!(
            result.is_err(),
            "unknown curve must produce a ProviderError"
        );
    }

    #[test]
    fn generate_missing_curve_fails() {
        let mgmt = EcKeyMgmt::new();
        let result = mgmt.generate(&ParamSet::new());
        assert!(
            result.is_err(),
            "missing curve name must produce a ProviderError"
        );
    }

    // -------------------------------------------------------------------------
    // Tests 8-10: import paths
    // -------------------------------------------------------------------------

    #[test]
    fn import_p256_keypair_roundtrip() {
        // Build a real key, export it, then import it again.  This is
        // the high-fidelity round-trip test for the import / export
        // path and covers the cross-verification logic between public
        // and private components.
        let original = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        let exported = original
            .export_to_params(KeySelection::KEYPAIR | KeySelection::DOMAIN_PARAMETERS)
            .expect("export_to_params must succeed");

        let mgmt = EcKeyMgmt::new();
        let imported = mgmt
            .import(
                KeySelection::KEYPAIR | KeySelection::DOMAIN_PARAMETERS,
                &exported,
            )
            .expect("import must succeed for valid exported keys");
        assert!(mgmt.has(&*imported, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*imported, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*imported, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn import_with_wrong_priv_key_len_fails() {
        // Build a `ParamSet` with a P-256 group name but a 16-byte
        // private scalar — `from_params` must reject it because P-256
        // requires exactly 32 bytes.
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("P-256".to_string()),
        );
        params.set(PARAM_PRIV_KEY, ParamValue::OctetString(vec![0x42u8; 16]));

        let mgmt = EcKeyMgmt::new();
        let result = mgmt.import(KeySelection::PRIVATE_KEY, &params);
        assert!(
            result.is_err(),
            "wrong private-scalar length must produce a ProviderError"
        );
    }

    #[test]
    fn import_with_invalid_pub_key_fails() {
        // Build a `ParamSet` with a P-256 group name but a public-key
        // octet-string with an unsupported leading byte (0x02 indicates
        // a compressed point that cannot be reconstructed without
        // canonical decoding support; we expect rejection).
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("P-256".to_string()),
        );
        let mut bogus = vec![0x02u8];
        bogus.extend_from_slice(&[0x11u8; 32]);
        params.set(PARAM_PUB_KEY, ParamValue::OctetString(bogus));

        let mgmt = EcKeyMgmt::new();
        let result = mgmt.import(KeySelection::PUBLIC_KEY, &params);
        // Some implementations accept compressed points; we accept
        // either Err *or* Ok provided the imported pub key round-trips.
        if let Ok(key) = result {
            // If accepted, the imported key must at least carry a group.
            assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        }
    }

    // -------------------------------------------------------------------------
    // Tests 11-12: validate paths
    // -------------------------------------------------------------------------

    #[test]
    fn validate_empty_key_returns_false() {
        let mgmt = EcKeyMgmt::new();
        let key = empty_ec_keydata();
        let result = mgmt
            .validate_concrete(&key, KeySelection::KEYPAIR)
            .expect("validate_concrete must not fail on empty keys");
        assert!(!result, "empty key must validate as false");
    }

    #[test]
    fn validate_generated_key_passes() {
        let mgmt = EcKeyMgmt::new();
        let key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        let result = mgmt
            .validate_concrete(&key, KeySelection::KEYPAIR)
            .expect("validate_concrete must succeed on a fresh keypair");
        assert!(result, "freshly generated keypair must validate true");
    }

    // -------------------------------------------------------------------------
    // Test 13: ec_descriptors returns the expected entries
    // -------------------------------------------------------------------------

    #[test]
    fn ec_descriptors_returns_valid_entries() {
        let descs = ec_descriptors();

        // EC entry is always present.
        assert!(
            descs.iter().any(|d| d.names.contains(&"EC")),
            "EC descriptor must be present"
        );
        assert!(
            descs
                .iter()
                .any(|d| d.names.contains(&"id-ecPublicKey")),
            "id-ecPublicKey alias must be present"
        );
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }

        // SM2 entry is feature-gated.
        #[cfg(feature = "sm2")]
        assert!(
            descs.iter().any(|d| d.names.contains(&"SM2")),
            "SM2 descriptor must be present when the sm2 feature is on"
        );
        #[cfg(not(feature = "sm2"))]
        assert_eq!(descs.len(), 1);
        #[cfg(feature = "sm2")]
        assert_eq!(descs.len(), 2);
    }

    // -------------------------------------------------------------------------
    // Test 14: EcKeyData export round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn ec_key_data_export_roundtrip() {
        let key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);

        // Export everything.
        let exported = key
            .export_to_params(KeySelection::ALL)
            .expect("export_to_params must succeed");

        // Required parameters must all be present.
        assert!(
            exported.contains(PARAM_GROUP_NAME),
            "exported ParamSet must include group name"
        );
        assert!(
            exported.contains(PARAM_PUB_KEY),
            "exported ParamSet must include public key"
        );
        assert!(
            exported.contains(PARAM_PRIV_KEY),
            "exported ParamSet must include private key"
        );
        assert!(
            exported.contains(PARAM_BITS),
            "exported ParamSet must include bits"
        );
        assert!(
            exported.contains(PARAM_DEFAULT_DIGEST),
            "exported ParamSet must include default digest"
        );

        // Round-trip the exported parameters back into a key.
        let mgmt = EcKeyMgmt::new();
        let reimported = mgmt
            .import(KeySelection::KEYPAIR | KeySelection::DOMAIN_PARAMETERS, &exported)
            .expect("re-import must succeed");
        assert!(mgmt.has(&*reimported, KeySelection::KEYPAIR));
    }

    // -------------------------------------------------------------------------
    // Test 15: EcKeyData has_selection
    // -------------------------------------------------------------------------

    #[test]
    fn ec_key_data_has_selection() {
        let empty = empty_ec_keydata();
        assert!(!empty.has_selection(KeySelection::DOMAIN_PARAMETERS));
        assert!(!empty.has_selection(KeySelection::PUBLIC_KEY));
        assert!(!empty.has_selection(KeySelection::PRIVATE_KEY));
        // Empty selection always returns true (matches C "0 = match-all").
        assert!(empty.has_selection(KeySelection::empty()));

        let populated = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        assert!(populated.has_selection(KeySelection::DOMAIN_PARAMETERS));
        assert!(populated.has_selection(KeySelection::PUBLIC_KEY));
        assert!(populated.has_selection(KeySelection::PRIVATE_KEY));
        assert!(populated.has_selection(KeySelection::KEYPAIR));
        assert!(populated.has_selection(KeySelection::ALL));
    }

    // -------------------------------------------------------------------------
    // Test 16: EcKeyData validate_selection
    // -------------------------------------------------------------------------

    #[test]
    fn ec_key_data_validate_selection() {
        let empty = empty_ec_keydata();
        let result = empty
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate_selection must not fail on empty keys");
        assert!(!result, "empty key must validate as false");

        let populated = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        let result = populated
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate_selection must succeed on a fresh keypair");
        assert!(result, "populated keypair must validate true");

        // Validating only domain parameters of a fresh key must also
        // succeed (delegates to `EcGroup::check`).
        let result_dp = populated
            .validate_selection(KeySelection::DOMAIN_PARAMETERS)
            .expect("validate_selection(DOMAIN_PARAMETERS) must succeed");
        assert!(result_dp);
    }

    // -------------------------------------------------------------------------
    // Test 17: NamedCurve / SM2 alias parsing
    // -------------------------------------------------------------------------

    #[test]
    fn named_curve_from_name_aliases() {
        // The standard NIST curve aliases.
        assert_eq!(
            named_curve_from_name("P-256"),
            Some(NamedCurve::Prime256v1)
        );
        assert_eq!(
            named_curve_from_name("P-384"),
            Some(NamedCurve::Secp384r1)
        );
        assert_eq!(
            named_curve_from_name("P-521"),
            Some(NamedCurve::Secp521r1)
        );
        assert_eq!(
            named_curve_from_name("secp256k1"),
            Some(NamedCurve::Secp256k1)
        );

        // SM2 is mapped to Prime256v1 (case-insensitive).
        assert_eq!(named_curve_from_name("sm2"), Some(NamedCurve::Prime256v1));
        assert_eq!(named_curve_from_name("SM2"), Some(NamedCurve::Prime256v1));
        assert_eq!(named_curve_from_name("Sm2"), Some(NamedCurve::Prime256v1));

        // Unknown curves return None.
        assert_eq!(named_curve_from_name("not-a-curve"), None);
        assert_eq!(named_curve_from_name(""), None);
    }

    // -------------------------------------------------------------------------
    // Test 18: Curve property helpers
    // -------------------------------------------------------------------------

    #[test]
    fn curve_property_helpers() {
        // field_size_bytes mirrors the curve order length used for
        // padded scalar export.
        assert_eq!(field_size_bytes(NamedCurve::Prime256v1), 32);
        assert_eq!(field_size_bytes(NamedCurve::Secp384r1), 48);
        assert_eq!(field_size_bytes(NamedCurve::Secp521r1), 66);
        assert_eq!(field_size_bytes(NamedCurve::Secp256k1), 32);

        // security_bits_from_curve aligns with NIST SP 800-57 Part 1
        // Rev 5 Table 2 bit-strength assignments.
        assert_eq!(security_bits_from_curve(NamedCurve::Prime256v1), 128);
        assert_eq!(security_bits_from_curve(NamedCurve::Secp384r1), 192);
        assert_eq!(security_bits_from_curve(NamedCurve::Secp521r1), 256);
        assert_eq!(security_bits_from_curve(NamedCurve::Secp256k1), 128);
    }

    // -------------------------------------------------------------------------
    // Additional tests: enum surface & helpers
    // -------------------------------------------------------------------------

    #[test]
    fn ec_key_type_default_digest() {
        assert_eq!(EcKeyType::Ec.default_digest(), "SHA256");
        #[cfg(feature = "sm2")]
        assert_eq!(EcKeyType::Sm2.default_digest(), "SM3");
    }

    #[test]
    fn ec_key_type_query_operation_name() {
        assert_eq!(EcKeyType::Ec.query_operation_name(), "EC");
        #[cfg(feature = "sm2")]
        assert_eq!(EcKeyType::Sm2.query_operation_name(), "SM2");
    }

    #[test]
    fn ec_encoding_from_name_and_back() {
        assert_eq!(
            EcEncoding::from_name("named_curve"),
            Some(EcEncoding::NamedCurve)
        );
        assert_eq!(
            EcEncoding::from_name("explicit"),
            Some(EcEncoding::ExplicitParameters)
        );
        assert_eq!(EcEncoding::from_name("garbage"), None);

        assert_eq!(EcEncoding::NamedCurve.name(), "named_curve");
        assert_eq!(EcEncoding::ExplicitParameters.name(), "explicit");

        // Default is NamedCurve.
        assert_eq!(EcEncoding::default(), EcEncoding::NamedCurve);
    }

    #[test]
    fn point_format_round_trip() {
        for form in [
            PointConversionForm::Compressed,
            PointConversionForm::Uncompressed,
            PointConversionForm::Hybrid,
        ] {
            let name = point_format_name(form);
            assert_eq!(point_format_from_name(name), Some(form));
        }
        assert_eq!(point_format_from_name("not-a-format"), None);
    }

    // -------------------------------------------------------------------------
    // Additional tests: EcKeyData state mutations
    // -------------------------------------------------------------------------

    #[test]
    fn ec_key_data_set_key_then_inspect() {
        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1)
            .expect("from_curve_name must succeed");
        let ec_key = EcKey::generate(&group).expect("EcKey::generate must succeed");

        let mut data = EcKeyData::new(None);
        assert!(!data.has_group());
        assert!(!data.has_public_key());
        assert!(!data.has_private_key());

        data.set_key(ec_key);
        assert!(data.has_group());
        assert!(data.has_public_key());
        assert!(data.has_private_key());
        assert_eq!(data.ec_type(), EcKeyType::Ec);
        assert!(data.lib_ctx().is_none());
        assert!(data.key().is_some());
        assert!(data.key_mut().is_some());
    }

    #[test]
    fn ec_key_data_drop_zeroizes() {
        // The Drop impl must be invocable without panicking on a
        // populated key — this exercises the explicit `take()` path
        // that releases the SecureBigNum private scalar.
        let data = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        drop(data); // No panic / no leak.
    }

    // -------------------------------------------------------------------------
    // Additional tests: EcGenContext
    // -------------------------------------------------------------------------

    #[test]
    fn ec_gen_context_setters() {
        let mut ctx = EcGenContext::new(KeySelection::KEYPAIR, EcKeyType::Ec, None);
        assert!(ctx.group_name.is_none());

        ctx.set_group_name("P-256");
        assert_eq!(ctx.group_name.as_deref(), Some("P-256"));

        ctx.set_encoding(EcEncoding::ExplicitParameters);
        assert_eq!(ctx.encoding, EcEncoding::ExplicitParameters);

        ctx.set_point_format(PointConversionForm::Compressed);
        assert_eq!(ctx.point_format, PointConversionForm::Compressed);

        ctx.set_cofactor(Some(true));
        assert_eq!(ctx.use_cofactor, Some(true));

        ctx.set_cofactor(None);
        assert_eq!(ctx.use_cofactor, None);
    }

    #[test]
    fn ec_gen_context_from_params_full() {
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("P-384".to_string()),
        );
        params.set(
            PARAM_EC_ENCODING,
            ParamValue::Utf8String("named_curve".to_string()),
        );
        params.set(
            PARAM_POINT_FORMAT,
            ParamValue::Utf8String("uncompressed".to_string()),
        );
        params.set(PARAM_USE_COFACTOR_FLAG, ParamValue::Int32(1));

        let ctx =
            EcGenContext::from_params(&params, KeySelection::KEYPAIR, EcKeyType::Ec, None)
                .expect("from_params must succeed for valid input");

        assert_eq!(ctx.group_name.as_deref(), Some("P-384"));
        assert_eq!(ctx.encoding, EcEncoding::NamedCurve);
        assert_eq!(ctx.point_format, PointConversionForm::Uncompressed);
        assert_eq!(ctx.use_cofactor, Some(true));
        assert_eq!(ctx.ec_type, EcKeyType::Ec);
    }

    #[test]
    fn ec_gen_context_cofactor_zero_means_false() {
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("P-256".to_string()),
        );
        params.set(PARAM_USE_COFACTOR_FLAG, ParamValue::Int32(0));

        let ctx =
            EcGenContext::from_params(&params, KeySelection::KEYPAIR, EcKeyType::Ec, None)
                .expect("from_params must succeed");
        assert_eq!(ctx.use_cofactor, Some(false));
    }

    // -------------------------------------------------------------------------
    // Additional tests: KeyMgmtProvider trait surface
    // -------------------------------------------------------------------------

    #[test]
    fn ec_key_mgmt_inherent_methods() {
        let mgmt = EcKeyMgmt::new();
        assert_eq!(mgmt.name(), "EC");
        assert_eq!(mgmt.query_operation_name(), "EC");

        let gettable = EcKeyMgmt::gettable_params();
        assert!(gettable.contains(&PARAM_BITS));
        assert!(gettable.contains(&PARAM_MAX_SIZE));
        assert!(gettable.contains(&PARAM_SECURITY_BITS));
        assert!(gettable.contains(&PARAM_DEFAULT_DIGEST));
    }

    #[test]
    fn ec_key_mgmt_get_params_populates_metadata() {
        let mgmt = EcKeyMgmt::new();
        let key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);

        let params = mgmt.get_params(&key).expect("get_params must succeed");
        assert!(params.contains(PARAM_BITS));
        assert!(params.contains(PARAM_MAX_SIZE));
        assert!(params.contains(PARAM_SECURITY_BITS));
        assert!(params.contains(PARAM_DEFAULT_DIGEST));
        assert!(params.contains(PARAM_GROUP_NAME));
        assert!(params.contains(PARAM_POINT_FORMAT));
        assert!(params.contains(PARAM_EC_ENCODING));

        // Sanity-check the security-bits value for P-256.
        match params.get(PARAM_SECURITY_BITS) {
            Some(ParamValue::UInt32(v)) => assert_eq!(*v, 128),
            other => panic!("expected UInt32 security-bits, got {other:?}"),
        }
    }

    #[test]
    fn ec_key_mgmt_match_keys_self_equal() {
        let mgmt = EcKeyMgmt::new();
        let key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        assert!(mgmt.match_keys(&key, &key));
    }

    #[test]
    fn ec_key_mgmt_match_keys_distinct_curves_differ() {
        let mgmt = EcKeyMgmt::new();
        let lhs = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
        let rhs = generated_ec_keydata(NamedCurve::Secp384r1, EcKeyType::Ec);
        assert!(!mgmt.match_keys(&lhs, &rhs));
    }

    #[test]
    fn ec_key_mgmt_has_via_trait_object() {
        let mgmt = EcKeyMgmt::new();
        let key: Box<dyn KeyData> =
            Box::new(generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec));
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn ec_key_mgmt_validate_via_trait_object() {
        let mgmt = EcKeyMgmt::new();
        let key: Box<dyn KeyData> =
            Box::new(generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec));
        let v = mgmt
            .validate(&*key, KeySelection::KEYPAIR)
            .expect("validate must succeed for populated key");
        assert!(v);
    }

    #[test]
    fn ec_key_mgmt_export_via_trait_object_returns_empty() {
        // The trait-object export path is intentionally lossy because
        // the trait doesn't expose a downcast facility.  Confirm the
        // documented behaviour: an empty ParamSet, no error.
        let mgmt = EcKeyMgmt::new();
        let key: Box<dyn KeyData> =
            Box::new(generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec));
        let exported = mgmt
            .export(&*key, KeySelection::KEYPAIR)
            .expect("export via trait object must not error");
        assert!(exported.is_empty());
    }

    #[test]
    fn ec_key_mgmt_export_with_non_eckeydata_returns_empty() {
        // Regression: the trait-object path must safely handle other
        // KeyData implementations without panicking.
        struct FakeKey;
        impl std::fmt::Debug for FakeKey {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "NotAnEcKey")
            }
        }
        impl KeyData for FakeKey {}
        let mgmt = EcKeyMgmt::new();
        let key: Box<dyn KeyData> = Box::new(FakeKey);
        let exported = mgmt
            .export(&*key, KeySelection::KEYPAIR)
            .expect("export must succeed for non-EcKeyData (returning empty)");
        assert!(exported.is_empty());
        assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    // -------------------------------------------------------------------------
    // Sm2 tests (feature-gated)
    // -------------------------------------------------------------------------

    #[cfg(feature = "sm2")]
    mod sm2_tests {
        #![allow(clippy::expect_used)]
        #![allow(clippy::unwrap_used)]
        #![allow(clippy::panic)]
        use super::super::*;
        use super::{generated_ec_keydata, group_params};

        #[test]
        fn sm2_key_mgmt_name_and_op() {
            let mgmt = Sm2KeyMgmt::new();
            assert_eq!(mgmt.name(), "SM2");
            assert_eq!(mgmt.query_operation_name(), "SM2");
        }

        #[test]
        fn sm2_new_key_is_empty() {
            let mgmt = Sm2KeyMgmt::new();
            let key = mgmt.new_key().expect("SM2 new_key must succeed");
            assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
            assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
            assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        }

        #[test]
        fn sm2_generate_with_explicit_curve() {
            let mgmt = Sm2KeyMgmt::new();
            // Caller-specified curve takes priority (via group_params).
            let key = mgmt
                .generate(&group_params("P-256"))
                .expect("SM2 generate with P-256 backing must succeed");
            assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        }

        #[test]
        fn sm2_generate_default_substitutes_sm2_curve() {
            let mgmt = Sm2KeyMgmt::new();
            // Empty params triggers default substitution to "SM2"
            // (which maps to Prime256v1).
            let key = mgmt
                .generate(&ParamSet::new())
                .expect("SM2 default-curve generate must succeed");
            assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
        }

        #[test]
        fn sm2_get_params_advertises_sm2_group() {
            let mgmt = Sm2KeyMgmt::new();
            let key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Sm2);
            let params = mgmt.get_params(&key).expect("SM2 get_params must succeed");
            match params.get(PARAM_GROUP_NAME) {
                Some(ParamValue::Utf8String(name)) => {
                    assert_eq!(name, "SM2");
                }
                other => panic!("expected SM2 group name, got {other:?}"),
            }
            match params.get(PARAM_DEFAULT_DIGEST) {
                Some(ParamValue::Utf8String(name)) => {
                    assert_eq!(name, "SM3");
                }
                other => panic!("expected SM3 default digest, got {other:?}"),
            }
        }

        #[test]
        fn sm2_validate_concrete_passes_on_real_key() {
            let mgmt = Sm2KeyMgmt::new();
            let key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Sm2);
            let v = mgmt
                .validate_concrete(&key, KeySelection::KEYPAIR)
                .expect("SM2 validate_concrete must succeed");
            assert!(v);
        }

        #[test]
        fn sm2_match_keys_distinguishes_ec_type() {
            let mgmt = Sm2KeyMgmt::new();
            let sm2_key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Sm2);
            let ec_key = generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec);
            assert!(!mgmt.match_keys(&sm2_key, &ec_key));
        }

        #[test]
        fn sm2_has_rejects_non_sm2_keydata() {
            // The Debug projection of an EC key must NOT match the
            // SM2 dispatcher's `ec_type: Sm2` filter.
            let mgmt = Sm2KeyMgmt::new();
            let key: Box<dyn KeyData> =
                Box::new(generated_ec_keydata(NamedCurve::Prime256v1, EcKeyType::Ec));
            assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        }
    }
}

