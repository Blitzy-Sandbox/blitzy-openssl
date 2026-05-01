//! # EC DHKEM — HPKE Key Encapsulation for NIST EC Curves (RFC 9180)
//!
//! Implementation of the Diffie-Hellman–based Key Encapsulation Mechanism
//! (DHKEM) over the NIST prime-field elliptic curves P-256, P-384 and
//! P-521, as specified by [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180).
//! Three KEM algorithms are provided:
//!
//! | KEM ID   | Name                              | Curve  | KDF           | Npk | Nsk | Nenc | Nsecret |
//! |----------|-----------------------------------|--------|---------------|----:|----:|-----:|--------:|
//! | `0x0010` | `DHKEM(P-256, HKDF-SHA256)`       | P-256  | HKDF-SHA-256  |  65 |  32 |   65 |      32 |
//! | `0x0011` | `DHKEM(P-384, HKDF-SHA384)`       | P-384  | HKDF-SHA-384  |  97 |  48 |   97 |      48 |
//! | `0x0012` | `DHKEM(P-521, HKDF-SHA512)`       | P-521  | HKDF-SHA-512  | 133 |  66 |  133 |      64 |
//!
//! Both base and authenticated modes are supported (RFC 9180 §4.1):
//!
//! - **Base mode**: [`KemContext::encapsulate`] / [`KemContext::decapsulate`]
//!   operate with only the recipient's key pair.
//! - **Authenticated mode (Auth)**: when a sender authentication key is
//!   supplied via [`KemContext::set_params`] (parameter `"authkey"`), the KEM
//!   additionally binds the shared secret to the sender's identity. The KEM
//!   context then performs `AuthEncap` / `AuthDecap` as described in RFC 9180
//!   §4.1 (`DHKEM(G).AuthEncap` / `DHKEM(G).AuthDecap`).
//!
//! ## Source Translation
//!
//! Translates C `providers/implementations/kem/ec_kem.c` (811 lines) into
//! idiomatic, safe Rust.
//!
//! ## C→Rust Transformations
//!
//! | C construct                                            | Rust equivalent                                       |
//! |--------------------------------------------------------|-------------------------------------------------------|
//! | `PROV_EC_CTX`                                          | [`EcKemContext`] (typed fields + RAII)                |
//! | `EC_KEY *recipient_key` (with `EC_KEY_up_ref`)         | `Option<EcKey>` (owned, Drop-zeroized)                |
//! | `OSSL_DISPATCH ossl_ec_asym_kem_functions[]`           | `impl KemProvider for EcDhKem` + `impl KemContext`    |
//! | `KEMID_DHKEM_P256_HKDF_SHA256` / `_P384_` / `_P521_`   | [`SupportedCurve`] + [`HpkeKem`]                      |
//! | `eckey_check`                                          | [`validate_ec_key`] (returns [`ProviderResult`])      |
//! | `ossl_ec_match_params`                                 | [`validate_matching_params`]                          |
//! | `OSSL_HPKE_KEM_INFO`                                   | [`HpkeKemInfo`]                                       |
//! | `OPENSSL_cleanse` / `OPENSSL_clear_free`               | [`zeroize::Zeroize`]                                  |
//! | `ERR_raise(ERR_LIB_PROV, ...)`                         | `Result<T, ProviderError>` (Rule R5)                  |
//! | Sentinel returns (`0`, `-1`)                           | [`ProviderResult`] / [`Option`] (Rule R5)             |
//! | `(int)len` narrowing casts                             | `u16::try_from(len)?` (Rule R6)                       |
//! | `BN_rand_range_ex`                                     | [`derive_private_key`] rejection sampling (RFC 9180 §7.1.3) |
//!
//! ## Rejection sampling (RFC 9180 §7.1.3 `DeriveKeyPair`)
//!
//! For NIST prime-field curves, a deterministic key derivation from an IKM
//! seed is performed by the HPKE-defined `DeriveKeyPair` algorithm:
//!
//! ```text
//! dkp_prk = LabeledExtract("", "dkp_prk", ikm)
//! sk      = 0
//! counter = 0
//! while sk == 0 or sk >= order:
//!     if counter > 255: error
//!     bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
//!     if curve == P-521: bytes[0] &= 0x01    (P-521 specific bitmask)
//!     sk = OS2IP(bytes)
//!     counter += 1
//! SK = sk
//! PK = SK * G
//! ```
//!
//! This module implements the rejection sampling loop in
//! [`derive_private_key`]. The C source uses `EC_KEY_set_private_key` after
//! the candidate scalar is reduced; this Rust implementation builds a
//! [`BigNum`] from the candidate bytes and validates it directly via
//! [`EcKey::from_private_key`], which performs the `1 ≤ sk < order` check.
//!
//! ## Cryptographic hygiene
//!
//! - All private-key material and input keying material (IKM) is wiped from
//!   memory on drop via [`zeroize`] (Rule R5 / FIPS cryptographic hygiene).
//! - The DH octets (`dh`) and PRK buffers are explicitly zeroized after use,
//!   matching the C source's `OPENSSL_cleanse` discipline.
//! - No `unsafe` code is used anywhere in this module (Rule R8).
//! - Every fallible operation returns a typed [`ProviderResult`]; no sentinel
//!   values escape the API surface.
//!
//! ## Note on KDF digest selection
//!
//! Each NIST curve in this module pairs with a different SHA-2 digest:
//! P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512. The KDF context is
//! created with [`KdfType::HkdfExtract`] / [`KdfType::HkdfExpand`] and
//! configured with the curve-specific digest name from
//! [`HpkeKemInfo::digest_name`] before each labeled extract/expand call.

// -----------------------------------------------------------------------------
// Imports — strictly limited to the depends_on_files whitelist + zeroize +
// tracing (workspace-approved external crates).
// -----------------------------------------------------------------------------

use tracing::{debug, trace, warn};
use zeroize::Zeroize;

use openssl_common::error::CryptoError;
use openssl_common::{ParamBuilder, ParamSet, ProviderError, ProviderResult};

use openssl_crypto::bn::BigNum;
use openssl_crypto::ec::ecdh;
use openssl_crypto::ec::{EcGroup, EcKey, EcPoint, NamedCurve, PointConversionForm};
use openssl_crypto::hpke::{HpkeKem, HpkeKemInfo};
use openssl_crypto::kdf::{KdfContext, KdfType};

use crate::traits::{AlgorithmDescriptor, KemContext, KemProvider};

use super::util::KemMode;

// -----------------------------------------------------------------------------
// Constants — RFC 9180 Section 7.1 / Section 4.1
// -----------------------------------------------------------------------------

/// RFC 9180 KEM ID for `DHKEM(P-256, HKDF-SHA256)`.
#[allow(dead_code)] // retained for RFC documentation parity (referenced in tests)
const KEMID_DHKEM_P256_HKDF_SHA256: u16 = 0x0010;

/// RFC 9180 KEM ID for `DHKEM(P-384, HKDF-SHA384)`.
#[allow(dead_code)] // retained for RFC documentation parity (referenced in tests)
const KEMID_DHKEM_P384_HKDF_SHA384: u16 = 0x0011;

/// RFC 9180 KEM ID for `DHKEM(P-521, HKDF-SHA512)`.
#[allow(dead_code)] // retained for RFC documentation parity (referenced in tests)
const KEMID_DHKEM_P521_HKDF_SHA512: u16 = 0x0012;

/// HPKE protocol versioning prefix (RFC 9180 §4 `LabeledExtract`/`LabeledExpand`).
const HPKE_V1: &[u8] = b"HPKE-v1";

/// Suite identifier label (RFC 9180 §4.1 — `KEM` || `I2OSP(kem_id, 2)`).
const LABEL_KEM: &[u8] = b"KEM";

/// `LabeledExtract` label for `DeriveKeyPair` PRK (RFC 9180 §7.1.3).
const LABEL_DKP_PRK: &[u8] = b"dkp_prk";

/// `LabeledExpand` label for the rejection-sampling candidate scalar
/// (RFC 9180 §7.1.3 — used together with a 1-octet counter).
const LABEL_CANDIDATE: &[u8] = b"candidate";

/// `LabeledExtract` label for the `eae_prk` (RFC 9180 §4.1).
const LABEL_EAE_PRK: &[u8] = b"eae_prk";

/// `LabeledExpand` label for the final shared secret (RFC 9180 §4.1).
const LABEL_SHARED_SECRET: &[u8] = b"shared_secret";

/// Maximum `DeriveKeyPair` rejection-sampling attempts before erroring out
/// (RFC 9180 §7.1.3 — counter is one octet, so 256 is the absolute upper bound).
const MAX_DKP_ATTEMPTS: u16 = 256;

/// Parameter name for the operation/mode selector (matches C `OSSL_KEM_PARAM_OPERATION`).
const PARAM_OPERATION: &str = "operation";

/// Parameter name for the IKM input keying material (matches C `OSSL_KEM_PARAM_IKME`).
const PARAM_IKME: &str = "ikme";

/// Parameter name for the sender authentication key (matches C `"authkey"` param).
const PARAM_AUTHKEY: &str = "authkey";

// =============================================================================
// SupportedCurve — public curve enumeration
// =============================================================================

/// NIST EC curve supported by this DHKEM implementation.
///
/// Each variant has a unique HPKE KEM ID (RFC 9180 Section 7.1) and pairs
/// with a fixed SHA-2 KDF. The DHKEM ciphertext (`enc`) is the recipient's
/// uncompressed public point, of length `Nenc` (= `Npk`) bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupportedCurve {
    /// NIST P-256 (`secp256r1`) with HKDF-SHA-256 (KEM ID `0x0010`).
    P256,
    /// NIST P-384 (`secp384r1`) with HKDF-SHA-384 (KEM ID `0x0011`).
    P384,
    /// NIST P-521 (`secp521r1`) with HKDF-SHA-512 (KEM ID `0x0012`).
    P521,
}

impl SupportedCurve {
    /// Returns the openssl-crypto [`NamedCurve`] identifier for this curve.
    #[inline]
    #[must_use]
    pub const fn named_curve(self) -> NamedCurve {
        match self {
            SupportedCurve::P256 => NamedCurve::Prime256v1,
            SupportedCurve::P384 => NamedCurve::Secp384r1,
            SupportedCurve::P521 => NamedCurve::Secp521r1,
        }
    }

    /// Returns the HPKE KEM suite identifier for this curve.
    #[inline]
    #[must_use]
    pub const fn hpke_kem(self) -> HpkeKem {
        match self {
            SupportedCurve::P256 => HpkeKem::DhKemP256Sha256,
            SupportedCurve::P384 => HpkeKem::DhKemP384Sha384,
            SupportedCurve::P521 => HpkeKem::DhKemP521Sha512,
        }
    }

    /// Returns the HPKE KEM suite constants (Npk, Nsk, Nenc, Nsecret, digest).
    ///
    /// Replaces the C `ossl_HPKE_KEM_INFO_find_curve()` helper used at
    /// `ec_kem.c:108`.
    #[inline]
    #[must_use]
    pub fn kem_info(self) -> &'static HpkeKemInfo {
        self.hpke_kem().info()
    }

    /// Returns the canonical algorithm name registered with the provider.
    #[inline]
    #[must_use]
    pub const fn algorithm_name(self) -> &'static str {
        match self {
            SupportedCurve::P256 => "P-256",
            SupportedCurve::P384 => "P-384",
            SupportedCurve::P521 => "P-521",
        }
    }

    /// Returns the human-readable description for provider registration.
    #[inline]
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            SupportedCurve::P256 => "DHKEM(P-256, HKDF-SHA256) per RFC 9180",
            SupportedCurve::P384 => "DHKEM(P-384, HKDF-SHA384) per RFC 9180",
            SupportedCurve::P521 => "DHKEM(P-521, HKDF-SHA512) per RFC 9180",
        }
    }

    /// Returns the bitmask applied to the leading byte of the candidate
    /// scalar bytes during `DeriveKeyPair` rejection sampling, per RFC 9180
    /// §7.1.3. Only P-521 needs a bitmask (`0x01`) because `Nsk = 66` bytes
    /// (528 bits) but the curve order has 521 bits — the leading 7 bits
    /// must be cleared. P-256 and P-384 have no bitmask (`0xff` is a no-op).
    #[inline]
    #[must_use]
    const fn dkp_bitmask(self) -> u8 {
        match self {
            SupportedCurve::P256 | SupportedCurve::P384 => 0xff,
            SupportedCurve::P521 => 0x01,
        }
    }
}

// =============================================================================
// EcKemMode — public DHKEM mode enumeration
// =============================================================================

/// KEM operation mode.
///
/// Only [`EcKemMode::DhKem`] is currently supported (RFC 9180 §4.1). This
/// enum exists to keep parity with the C provider's `KEM_MODE_*` constants
/// and to allow future modes (e.g. authenticated encapsulation modes
/// distinct from the DHKEM auth pathway, or post-quantum KEMs) to be added
/// without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcKemMode {
    /// Diffie–Hellman based KEM as defined in RFC 9180 §4.1.
    DhKem,
}

// =============================================================================
// EcKemOperation — private operation state
// =============================================================================

/// The current operation state of an [`EcKemContext`].
///
/// Selected by [`KemContext::encapsulate_init`] /
/// [`KemContext::decapsulate_init`]. The authenticated variants are chosen
/// when a sender auth key has been set via [`KemContext::set_params`] at the
/// time of `init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcKemOperation {
    /// Base-mode encapsulation (`DHKEM(G).Encap`).
    Encapsulate,
    /// Base-mode decapsulation (`DHKEM(G).Decap`).
    Decapsulate,
    /// Authenticated encapsulation (`DHKEM(G).AuthEncap`).
    AuthEncapsulate,
    /// Authenticated decapsulation (`DHKEM(G).AuthDecap`).
    AuthDecapsulate,
}

impl EcKemOperation {
    /// Returns `true` if this operation binds a sender authentication key.
    #[inline]
    const fn is_auth(self) -> bool {
        matches!(
            self,
            EcKemOperation::AuthEncapsulate | EcKemOperation::AuthDecapsulate
        )
    }

    /// Returns `true` if this operation is an encapsulation (sender side).
    #[inline]
    const fn is_encap(self) -> bool {
        matches!(
            self,
            EcKemOperation::Encapsulate | EcKemOperation::AuthEncapsulate
        )
    }
}

// =============================================================================
// EcDhKem — public KEM provider type
// =============================================================================

/// HPKE DHKEM provider for the NIST EC curves P-256, P-384, P-521.
///
/// Implements the [`KemProvider`] trait and registers the curve-specific
/// algorithm name (`"P-256"`, `"P-384"`, or `"P-521"`) with the provider
/// registry. Construct one instance per curve, or use [`descriptors`] to
/// obtain pre-configured descriptors for the provider dispatch table.
///
/// # Example
///
/// ```ignore
/// use openssl_provider::implementations::kem::ec::{SupportedCurve, EcDhKem};
/// use openssl_provider::traits::KemProvider;
///
/// let kem = EcDhKem::new(SupportedCurve::P256);
/// assert_eq!(kem.name(), "P-256");
/// let mut ctx = kem.new_ctx().unwrap();
/// // ... drive ctx through encapsulate_init / encapsulate ...
/// ```
#[derive(Debug, Clone, Copy)]
pub struct EcDhKem {
    curve: SupportedCurve,
}

impl EcDhKem {
    /// Creates a new EC DHKEM provider for the given curve.
    #[inline]
    #[must_use]
    pub const fn new(curve: SupportedCurve) -> Self {
        Self { curve }
    }
}

// =============================================================================
// EcKemContext — public KEM operation context
// =============================================================================

/// Per-operation state for an EC DHKEM encapsulation or decapsulation.
///
/// Replaces the C `PROV_EC_CTX` struct from `ec_kem.c` (lines 41–52).
///
/// # Field zeroization
///
/// Private-key material is always wiped from memory on drop:
///
/// - `recipient_key` and `sender_authkey` are [`EcKey`]s whose
///   `Drop` implementations zero out the inner `SecureBigNum` private scalar.
/// - `auth_key_bytes` and `ikm` are `Vec<u8>` wiped by the explicit
///   [`Drop`] implementation on [`EcKemContext`].
///
/// # Thread safety
///
/// A context instance is `Send + Sync` (the KEM trait bounds require it) but
/// holds exclusive state for a single in-flight KEM operation; callers must
/// not share a single context across concurrent encapsulations.
pub struct EcKemContext {
    /// The NIST curve this context operates over.
    curve: SupportedCurve,

    /// Recipient's key (public-only after `encapsulate_init`, contains the
    /// private scalar after `decapsulate_init`). `None` until initialization.
    ///
    /// In the C source this field is two separate variables
    /// (`recipient_pubkey` / `recipient_privkey`). In the Rust translation
    /// they are unified into a single [`EcKey`] which carries both the
    /// public point and (optionally) the private scalar. The
    /// `EcKey::has_private_key` predicate distinguishes the two cases.
    recipient_key: Option<EcKey>,

    /// Sender's authentication key (set via the `"authkey"` parameter).
    ///
    /// In authenticated encapsulation this is parsed as a private key; in
    /// authenticated decapsulation, as a public-only key.
    sender_authkey: Option<EcKey>,

    /// The operation mode. Only [`EcKemMode::DhKem`] is currently supported.
    mode: EcKemMode,

    /// The active operation, chosen by `encapsulate_init` / `decapsulate_init`.
    /// `None` until an `*_init` call succeeds.
    op: Option<EcKemOperation>,

    /// Optional deterministic input keying material for the ephemeral key
    /// pair. When `Some`, the ephemeral key pair is derived via RFC 9180
    /// `DeriveKeyPair` (rejection sampling) instead of being generated
    /// randomly.
    ///
    /// Wiped by the custom [`Drop`] impl.
    ikm: Option<Vec<u8>>,

    /// Cached HPKE KEM suite constants (Npk, Nsk, Nenc, Nsecret, digest).
    ///
    /// Initialised eagerly from `curve.kem_info()` in [`Self::new`] — the
    /// `Option` wrapper is retained so the existing call sites can use
    /// `.ok_or_else(…)?` consistently and so future variants without
    /// pre-registered HPKE info can be expressed without a sweeping refactor.
    kem_info: Option<&'static HpkeKemInfo>,
}

impl EcKemContext {
    /// Creates a new, uninitialised KEM context for the given curve.
    ///
    /// The context must be driven through `encapsulate_init` or
    /// `decapsulate_init` before any KEM primitive can be invoked.
    #[must_use]
    fn new(curve: SupportedCurve) -> Self {
        Self {
            curve,
            recipient_key: None,
            sender_authkey: None,
            mode: EcKemMode::DhKem,
            op: None,
            ikm: None,
            kem_info: Some(curve.kem_info()),
        }
    }
}

impl std::fmt::Debug for EcKemContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately redact secret material from Debug output.  The
        // `kem_info` field intentionally does not surface in this view —
        // it is a `&'static` reference to a fixed suite-constant table
        // resolved from `curve` and adds no diagnostic value beyond what
        // the curve already reveals — so we use `finish_non_exhaustive`.
        f.debug_struct("EcKemContext")
            .field("curve", &self.curve)
            .field("mode", &self.mode)
            .field("op", &self.op)
            .field("has_recipient_key", &self.recipient_key.is_some())
            .field(
                "recipient_has_private",
                &self
                    .recipient_key
                    .as_ref()
                    .is_some_and(EcKey::has_private_key),
            )
            .field("has_sender_authkey", &self.sender_authkey.is_some())
            .field("has_ikm", &self.ikm.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for EcKemContext {
    fn drop(&mut self) {
        // EcKey instances zero their inner `SecureBigNum` private scalar via
        // their own `Drop` impl. We only need to wipe IKM here.
        if let Some(ref mut ikm) = self.ikm {
            ikm.zeroize();
        }
    }
}

// =============================================================================
// Helper functions — RFC 9180 §4 / §7.1 primitives
// =============================================================================

/// Convert a `CryptoError` raised by `openssl_crypto` into a `ProviderError`.
///
/// Centralises error mapping so the rest of the file can simply call
/// `.map_err(dispatch_err)` without reasoning about the underlying variant.
/// Implements the C pattern of stripping low-level error context and
/// re-raising at the provider boundary (analogous to `ERR_raise(ERR_LIB_PROV, …)`).
//
// JUSTIFICATION (clippy::needless_pass_by_value): `map_err` requires a
// `FnOnce(E) -> F` closure, so the function must take ownership of the
// `CryptoError` argument even though we only invoke `.to_string()` on it.
// Taking a reference would require every `.map_err(dispatch_err)` call site
// to be rewritten as `.map_err(|e| dispatch_err(&e))`, which is strictly
// noisier without changing semantics — `e` is dropped at the end of this
// function regardless.
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Encode a 16-bit unsigned integer in big-endian (network) byte order.
///
/// Implements `I2OSP(n, 2)` from RFC 9180 §4 (and RFC 8017). Used to encode
/// the KEM identifier inside the suite ID and the labeled-expand output length.
const fn i2osp2(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// Construct the HPKE KEM suite identifier per RFC 9180 §4.1:
///
/// ```text
/// suite_id = "KEM" || I2OSP(kem_id, 2)
/// ```
///
/// This is a 5-byte slice used as a domain separator in every `LabeledExtract`
/// and `LabeledExpand` call within the DHKEM construction.
fn suite_id(kem_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(LABEL_KEM.len() + 2);
    out.extend_from_slice(LABEL_KEM);
    out.extend_from_slice(&i2osp2(kem_id));
    out
}

/// RFC 9180 §4 `LabeledExtract` operation:
///
/// ```text
/// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
/// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, labeled_ikm)
/// ```
///
/// The PRK output length equals the digest output length (`Nh`).
fn labeled_extract(
    info: &HpkeKemInfo,
    suite: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> ProviderResult<Vec<u8>> {
    // Compose labeled_ikm = "HPKE-v1" || suite_id || label || ikm
    let mut labeled_ikm = Vec::with_capacity(HPKE_V1.len() + suite.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let prk_len = digest_output_len(info.digest_name());

    let mut kdf_ctx = KdfContext::new(KdfType::HkdfExtract);
    kdf_ctx
        .set_digest(info.digest_name())
        .map_err(dispatch_err)?;
    kdf_ctx.set_salt(salt).map_err(dispatch_err)?;
    kdf_ctx.set_key(&labeled_ikm).map_err(dispatch_err)?;
    let prk = kdf_ctx.derive(prk_len).map_err(dispatch_err)?;

    // Wipe the labeled_ikm buffer — it contains `ikm` (potentially a DH share).
    labeled_ikm.zeroize();

    Ok(prk)
}

/// RFC 9180 §4 `LabeledExpand` operation:
///
/// ```text
/// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
/// LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, labeled_info, L)
/// ```
///
/// The output length `L` must fit in a `u16` per RFC 9180 / RFC 5869 (≤ 255 × Nh).
/// We enforce this at runtime via `u16::try_from` (Rule R6 — no bare narrowing
/// casts).
fn labeled_expand(
    info: &HpkeKemInfo,
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info_bytes: &[u8],
    length: usize,
) -> ProviderResult<Vec<u8>> {
    // Per RFC 9180 §4, the output length is encoded as `I2OSP(L, 2)`. Reject
    // anything that does not fit in a u16 (Rule R6).
    let length_u16 = u16::try_from(length).map_err(|_| {
        ProviderError::Dispatch(format!(
            "DHKEM LabeledExpand: requested output length {length} exceeds 65535 octets"
        ))
    })?;

    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + suite.len() + label.len() + info_bytes.len());
    labeled_info.extend_from_slice(&i2osp2(length_u16));
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info_bytes);

    let mut kdf_ctx = KdfContext::new(KdfType::HkdfExpand);
    kdf_ctx
        .set_digest(info.digest_name())
        .map_err(dispatch_err)?;
    kdf_ctx.set_key(prk).map_err(dispatch_err)?;
    kdf_ctx.set_info(&labeled_info).map_err(dispatch_err)?;
    let out = kdf_ctx.derive(length).map_err(dispatch_err)?;

    // labeled_info itself does not contain secret data, but zeroising costs
    // nothing and keeps the contract uniform with `labeled_extract`.
    labeled_info.zeroize();

    Ok(out)
}

/// Return the digest output length (`Nh`) for an HPKE digest name.
///
/// Used by `labeled_extract` to size the PRK buffer.  The accepted digest
/// names exactly match those exposed by `HpkeKemInfo::digest_name()`:
///
/// | Digest name | `Nh` (bytes) |
/// |-------------|--------------|
/// | `SHA-256`   | 32 (default — also covers any unrecognised name)|
/// | `SHA-384`   | 48           |
/// | `SHA-512`   | 64           |
///
/// The wildcard arm intentionally also covers `"SHA-256"` (the most common
/// case for HPKE — used by P-256/X25519 KEMs) so that the conservative
/// 32-byte default doubles as the SHA-256 length.  This collapses two
/// otherwise-redundant arms while preserving correctness.
fn digest_output_len(digest_name: &str) -> usize {
    match digest_name {
        "SHA-384" => 48,
        "SHA-512" => 64,
        // SHA-256 (32 bytes) and any unrecognised digest fall through to
        // this conservative default.
        _ => 32,
    }
}

/// RFC 9180 §7.1.3 — `DeriveKeyPair` for prime-order curves.
///
/// Implements *rejection sampling* for NIST P-256 / P-384 / P-521. Unlike the
/// X25519 / X448 case, which can simply clamp the IKM, NIST scalars must lie
/// in `[1, n-1]` where `n` is the group order. The algorithm:
///
/// ```text
/// dkp_prk = LabeledExtract("", "dkp_prk", ikm)
/// sk = 0
/// counter = 0
/// while sk == 0 or sk >= order:
///     if counter > 255: error
///     bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
///     bytes[0] &= bitmask     // P-521 only — top 7 bits zeroed
///     sk = OS2IP(bytes)
///     counter += 1
/// return sk
/// ```
///
/// The constructed `EcKey` already validates `1 ≤ sk < order` and derives the
/// public key via `generator_mul`, so we use `EcKey::from_private_key` as the
/// final acceptance test for each candidate (its `Err` path is the exact
/// rejection condition).
fn derive_private_key(
    curve: SupportedCurve,
    info: &HpkeKemInfo,
    ikm: &[u8],
) -> ProviderResult<EcKey> {
    // RFC 9180 §7.1.3 requires the IKM be at least Nsk bytes long.  This
    // matches the C check at `ec_kem.c` line ~415.
    if ikm.len() < info.secret_key_len() {
        return Err(ProviderError::Dispatch(format!(
            "DHKEM IKM too short: got {} bytes, need at least {} for {:?}",
            ikm.len(),
            info.secret_key_len(),
            curve
        )));
    }

    let suite = suite_id(info.kem_id());
    let dkp_prk = labeled_extract(info, &suite, b"", LABEL_DKP_PRK, ikm)?;

    let group = EcGroup::from_curve_name(curve.named_curve()).map_err(dispatch_err)?;
    let bitmask = curve.dkp_bitmask();
    let sk_len = info.secret_key_len();

    for counter in 0u16..MAX_DKP_ATTEMPTS {
        // RFC 9180 §7.1.3 — counter is encoded as a single octet I2OSP(counter, 1).
        // `counter` already ranges within 0..256, but we use `u8::try_from`
        // for explicit narrowing per Rule R6.
        let counter_byte = u8::try_from(counter).map_err(|_| {
            ProviderError::Dispatch(format!(
                "DHKEM DeriveKeyPair: counter overflow at {counter}"
            ))
        })?;
        let counter_info = [counter_byte];

        let mut bytes = labeled_expand(
            info,
            &suite,
            &dkp_prk,
            LABEL_CANDIDATE,
            &counter_info,
            sk_len,
        )?;

        // P-521 — RFC 9180 §7.1.3 mandates clearing the top 7 bits of the
        // first octet so the candidate fits in the 521-bit order.  For
        // P-256 / P-384 the bitmask is 0xff (no-op).
        if bitmask != 0xff && !bytes.is_empty() {
            bytes[0] &= bitmask;
        }

        // Convert big-endian bytes → BigNum scalar.  `from_bytes_be` is
        // infallible — validation happens via `EcKey::from_private_key` below
        // which checks `1 ≤ sk < n`.
        let scalar = BigNum::from_bytes_be(&bytes);
        bytes.zeroize();

        match EcKey::from_private_key(&group, scalar) {
            Ok(key) => {
                trace!(
                    curve = ?curve,
                    counter = counter,
                    "DHKEM DeriveKeyPair: candidate accepted"
                );
                return Ok(key);
            }
            Err(_) => {
                // Scalar was 0 or ≥ n — try the next counter.
                continue;
            }
        }
    }

    // Probability of exhausting 256 attempts on a NIST curve is astronomically
    // small (≈ 2^-1700 for P-256).  If we ever hit this, something is gravely
    // wrong with the IKM or the KDF.
    Err(ProviderError::Dispatch(format!(
        "DHKEM DeriveKeyPair: rejection sampling exhausted after {MAX_DKP_ATTEMPTS} attempts for {curve:?}"
    )))
}

/// Compute the raw ECDH shared X-coordinate `DH(sk, pk)` per RFC 9180 §7.1.1.
///
/// Returns the big-endian X-coordinate, zero-padded to `⌈degree / 8⌉` bytes
/// (32 for P-256, 48 for P-384, 66 for P-521). Delegates to
/// `openssl_crypto::ec::ecdh::compute_key`, which uses the cofactor variant
/// internally — for prime-order NIST curves the cofactor is 1, so this is
/// equivalent to plain ECDH and consistent with the C source.
fn compute_ecdh(own_key: &EcKey, peer_pubkey: &EcPoint) -> ProviderResult<Vec<u8>> {
    let secret = ecdh::compute_key(own_key, peer_pubkey).map_err(dispatch_err)?;
    Ok(secret.into_bytes())
}

/// RFC 9180 §4.1 — base-mode KEM context: `kem_context = enc || pk_rm`.
fn build_kem_context_base(enc: &[u8], pk_rm: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(enc.len() + pk_rm.len());
    out.extend_from_slice(enc);
    out.extend_from_slice(pk_rm);
    out
}

/// RFC 9180 §4.1 — auth-mode KEM context: `kem_context = enc || pk_rm || pk_sm`.
fn build_kem_context_auth(enc: &[u8], pk_rm: &[u8], pk_sm: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(enc.len() + pk_rm.len() + pk_sm.len());
    out.extend_from_slice(enc);
    out.extend_from_slice(pk_rm);
    out.extend_from_slice(pk_sm);
    out
}

/// RFC 9180 §4.1 — `ExtractAndExpand` step:
///
/// ```text
/// eae_prk        = LabeledExtract("", "eae_prk", dh)
/// shared_secret  = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
/// ```
///
/// `dh` is the (possibly concatenated) ECDH share; `kem_context` is the
/// base- or auth-mode context produced by `build_kem_context_*`.
fn extract_and_expand(
    info: &HpkeKemInfo,
    dh: &[u8],
    kem_context: &[u8],
) -> ProviderResult<Vec<u8>> {
    let suite = suite_id(info.kem_id());
    let mut eae_prk = labeled_extract(info, &suite, b"", LABEL_EAE_PRK, dh)?;
    let ss = labeled_expand(
        info,
        &suite,
        &eae_prk,
        LABEL_SHARED_SECRET,
        kem_context,
        info.shared_secret_len(),
    )?;
    eae_prk.zeroize();
    Ok(ss)
}

// =============================================================================
// DHKEM core operations — Encap / Decap (RFC 9180 §4.1, §7.1)
// =============================================================================

/// Implements RFC 9180 §4.1 `Encap` (or `AuthEncap` when `op.is_auth()`):
///
/// ```text
/// (skE, pkE)    = DeriveKeyPair(ikmE)        // or random
/// dh            = DH(skE, pkR)               // base mode
///                 || DH(skS, pkR)            // auth mode
/// enc           = SerializePublicKey(pkE)
/// kem_context   = enc || pk_rm
///                 || pk_sm                   // auth mode
/// shared_secret = ExtractAndExpand(dh, kem_context)
/// return (shared_secret, enc)
/// ```
///
/// Source equivalence: `dhkem_encap()` at `ec_kem.c` lines ~462–605.
fn dhkem_encap(ctx: &mut EcKemContext) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
    let op = ctx.op.ok_or_else(|| {
        warn!("EcKemContext::encapsulate called before encapsulate_init");
        ProviderError::Dispatch(
            "EcKemContext::encapsulate called before encapsulate_init".to_string(),
        )
    })?;

    let curve = ctx.curve;
    let info = ctx.kem_info.ok_or_else(|| {
        ProviderError::Init(format!(
            "EcKemContext: missing HPKE KEM info for curve {curve:?}"
        ))
    })?;

    // The recipient EcKey is required for encapsulate, and it must contain a
    // public key.  C reference: `ec_kem.c` line ~470.
    let recipient_key = ctx.recipient_key.as_ref().ok_or_else(|| {
        warn!(curve = ?curve, "encapsulate: recipient public key not set");
        ProviderError::Dispatch("DHKEM Encap: recipient public key not set".to_string())
    })?;
    let pk_r_point = recipient_key.public_key().ok_or_else(|| {
        warn!(curve = ?curve, "encapsulate: recipient EcKey has no public component");
        ProviderError::Dispatch("DHKEM Encap: recipient EcKey has no public component".to_string())
    })?;
    let group = recipient_key.group();

    // ---------------------------------------------------------------
    // 1. Generate or derive the ephemeral keypair.
    // ---------------------------------------------------------------
    let sk_e_key: EcKey = if let Some(ref ikm_bytes) = ctx.ikm {
        // Deterministic — DeriveKeyPair(ikmE).
        // `info` is already `&'static HpkeKemInfo`; no extra borrow needed.
        derive_private_key(curve, info, ikm_bytes)?
    } else {
        // Random — uses the CSPRNG via openssl_crypto's BigNum::priv_rand_range.
        EcKey::generate(group).map_err(dispatch_err)?
    };

    let pk_e_point = sk_e_key
        .public_key()
        .ok_or_else(|| {
            ProviderError::Dispatch(
                "DHKEM Encap: ephemeral key generation produced no public component".to_string(),
            )
        })?
        .clone();

    // SerializePublicKey(pkE) — RFC 9180 §7.1.1: uncompressed encoding
    // 0x04 || X || Y, length = Npk.
    let enc = pk_e_point
        .to_bytes(group, PointConversionForm::Uncompressed)
        .map_err(dispatch_err)?;

    debug_assert_eq!(
        enc.len(),
        info.enc_len(),
        "DHKEM Encap: SerializePublicKey produced wrong length"
    );

    // ---------------------------------------------------------------
    // 2. Compute the DH share(s).
    // ---------------------------------------------------------------
    let mut dh = compute_ecdh(&sk_e_key, pk_r_point)?;

    let kem_context = if op.is_auth() {
        // AuthEncap: dh = DH(skE, pkR) || DH(skS, pkR);  kem_context appends pk_sm.
        let auth_key = ctx.sender_authkey.as_ref().ok_or_else(|| {
            warn!(curve = ?curve, "auth-encapsulate: sender authentication key not set");
            ProviderError::Dispatch(
                "DHKEM AuthEncap: sender authentication key not set".to_string(),
            )
        })?;

        // Sender's auth key must be on the same curve as the recipient.
        validate_matching_params(auth_key, recipient_key)?;

        let mut dh2 = compute_ecdh(auth_key, pk_r_point)?;
        dh.extend_from_slice(&dh2);
        dh2.zeroize();

        let pk_s_point = auth_key.public_key().ok_or_else(|| {
            ProviderError::Dispatch(
                "DHKEM AuthEncap: sender authentication key has no public component".to_string(),
            )
        })?;
        let pk_s_bytes = pk_s_point
            .to_bytes(group, PointConversionForm::Uncompressed)
            .map_err(dispatch_err)?;

        let pk_r_bytes = pk_r_point
            .to_bytes(group, PointConversionForm::Uncompressed)
            .map_err(dispatch_err)?;

        build_kem_context_auth(&enc, &pk_r_bytes, &pk_s_bytes)
    } else {
        // Base Encap: kem_context = enc || pk_rm.
        let pk_r_bytes = pk_r_point
            .to_bytes(group, PointConversionForm::Uncompressed)
            .map_err(dispatch_err)?;
        build_kem_context_base(&enc, &pk_r_bytes)
    };

    // The ephemeral private key has served its purpose — drop it explicitly so
    // its `Drop` impl wipes the inner SecureBigNum.
    drop(sk_e_key);

    // ---------------------------------------------------------------
    // 3. Derive shared_secret = ExtractAndExpand(dh, kem_context).
    // ---------------------------------------------------------------
    // `info` is already `&'static HpkeKemInfo`; no extra borrow needed.
    let shared_secret = extract_and_expand(info, &dh, &kem_context)?;

    // Wipe the DH share — it is the most sensitive intermediate value.
    dh.zeroize();

    debug!(
        curve = ?curve,
        auth = op.is_auth(),
        enc_len = enc.len(),
        ss_len = shared_secret.len(),
        "DHKEM encapsulate succeeded"
    );

    Ok((enc, shared_secret))
}

/// Implements RFC 9180 §4.1 `Decap` (or `AuthDecap` when `op.is_auth()`):
///
/// ```text
/// pkE           = DeserializePublicKey(enc)
/// dh            = DH(skR, pkE)
///                 || DH(skR, pkS)            // auth mode
/// kem_context   = enc || pk_rm
///                 || pk_sm                   // auth mode
/// shared_secret = ExtractAndExpand(dh, kem_context)
/// return shared_secret
/// ```
///
/// Source equivalence: `dhkem_decap()` at `ec_kem.c` lines ~625–763.
fn dhkem_decap(ctx: &mut EcKemContext, enc: &[u8]) -> ProviderResult<Vec<u8>> {
    let op = ctx.op.ok_or_else(|| {
        warn!("EcKemContext::decapsulate called before decapsulate_init");
        ProviderError::Dispatch(
            "EcKemContext::decapsulate called before decapsulate_init".to_string(),
        )
    })?;

    let curve = ctx.curve;
    let info = ctx.kem_info.ok_or_else(|| {
        ProviderError::Init(format!(
            "EcKemContext: missing HPKE KEM info for curve {curve:?}"
        ))
    })?;

    // Expected length of `enc`.  RFC 9180 §7.1.1: Nenc = Npk = 2 * coord + 1
    // (uncompressed encoding).  Reject early if mismatched.
    if enc.len() != info.enc_len() {
        warn!(
            curve = ?curve,
            got = enc.len(),
            expected = info.enc_len(),
            "DHKEM Decap: ciphertext length mismatch"
        );
        return Err(ProviderError::Dispatch(format!(
            "DHKEM Decap ciphertext length {} does not match Nenc={}",
            enc.len(),
            info.enc_len()
        )));
    }

    let recipient_key = ctx.recipient_key.as_ref().ok_or_else(|| {
        warn!(curve = ?curve, "decapsulate: recipient private key not set");
        ProviderError::Dispatch("DHKEM Decap: recipient private key not set".to_string())
    })?;
    if !recipient_key.has_private_key() {
        warn!(curve = ?curve, "decapsulate: recipient EcKey has no private component");
        return Err(ProviderError::Dispatch(
            "DHKEM Decap: recipient EcKey has no private component".to_string(),
        ));
    }
    let group = recipient_key.group();

    // ---------------------------------------------------------------
    // 1. Deserialize the sender's ephemeral public key from `enc`.
    // ---------------------------------------------------------------
    let pk_e_point = EcPoint::from_bytes(group, enc).map_err(dispatch_err)?;

    // Validate the deserialised point belongs to the curve and isn't infinity.
    let pk_e_check_key = EcKey::from_public_key(group, pk_e_point.clone()).map_err(dispatch_err)?;
    pk_e_check_key.check_key().map_err(dispatch_err)?;

    // ---------------------------------------------------------------
    // 2. DH(skR, pkE)  — and DH(skR, pkS) for AuthDecap.
    // ---------------------------------------------------------------
    let mut dh = compute_ecdh(recipient_key, &pk_e_point)?;

    // Recipient public key bytes (pk_rm) — needed for kem_context.
    let pk_r_point = recipient_key.public_key().ok_or_else(|| {
        ProviderError::Dispatch("DHKEM Decap: recipient EcKey has no public component".to_string())
    })?;
    let pk_r_bytes = pk_r_point
        .to_bytes(group, PointConversionForm::Uncompressed)
        .map_err(dispatch_err)?;

    let kem_context = if op.is_auth() {
        let auth_key = ctx.sender_authkey.as_ref().ok_or_else(|| {
            warn!(curve = ?curve, "auth-decapsulate: sender authentication key not set");
            ProviderError::Dispatch(
                "DHKEM AuthDecap: sender authentication key not set".to_string(),
            )
        })?;

        // The sender's *public* auth key must be on the same curve.
        validate_matching_params(auth_key, recipient_key)?;

        let pk_s_point = auth_key.public_key().ok_or_else(|| {
            ProviderError::Dispatch(
                "DHKEM AuthDecap: sender authentication key has no public component".to_string(),
            )
        })?;

        let mut dh2 = compute_ecdh(recipient_key, pk_s_point)?;
        dh.extend_from_slice(&dh2);
        dh2.zeroize();

        let pk_s_bytes = pk_s_point
            .to_bytes(group, PointConversionForm::Uncompressed)
            .map_err(dispatch_err)?;

        build_kem_context_auth(enc, &pk_r_bytes, &pk_s_bytes)
    } else {
        build_kem_context_base(enc, &pk_r_bytes)
    };

    // ---------------------------------------------------------------
    // 3. Derive shared_secret = ExtractAndExpand(dh, kem_context).
    // ---------------------------------------------------------------
    // `info` is already `&'static HpkeKemInfo`; no extra borrow needed.
    let shared_secret = extract_and_expand(info, &dh, &kem_context)?;

    // Zeroise the DH share before returning.
    dh.zeroize();

    debug!(
        curve = ?curve,
        auth = op.is_auth(),
        ss_len = shared_secret.len(),
        "DHKEM decapsulate succeeded"
    );

    Ok(shared_secret)
}

// =============================================================================
// Key validation helpers — RFC 9180 §7.1.2 / SP 800-56A §5.6.2.3
// =============================================================================

/// Validate that the provided `EcKey` is internally consistent.
///
/// `require_private = true`  → check both private and public components are
///                             present and that the `EcKey` passes the full
///                             `check_key()` consistency test.
/// `require_private = false` → check only that a public component is present
///                             and lies on the curve.
///
/// Replaces C `eckey_check()` at `ec_kem.c` lines 68–99 and the surrounding
/// `EC_KEY_get0_public_key`/`EC_KEY_get0_private_key` NULL checks.
fn validate_ec_key(key: &EcKey, require_private: bool) -> ProviderResult<()> {
    if key.public_key().is_none() {
        warn!("EC key validation: missing public component");
        return Err(ProviderError::Dispatch(
            "EC key validation: missing public component".to_string(),
        ));
    }
    if require_private && !key.has_private_key() {
        warn!("EC key validation: missing private component");
        return Err(ProviderError::Dispatch(
            "EC key validation: missing private component".to_string(),
        ));
    }
    // `check_key()` performs: on-curve / not-at-infinity / order × pk = ∞ /
    // (when private is present) priv × G == pub.  It returns `Ok(false)` for
    // keys that fail any consistency check (vs. `Err(_)` for low-level
    // crypto errors), so we must collapse both negative outcomes into the
    // provider error type.
    let valid = key.check_key().map_err(dispatch_err)?;
    if !valid {
        warn!("EC key validation: check_key() rejected the key");
        return Err(ProviderError::Dispatch(
            "EC key validation: key failed consistency check".to_string(),
        ));
    }
    Ok(())
}

/// Verify that two `EcKey`s belong to the same elliptic-curve group.
///
/// Replaces C `ossl_ec_match_params()` at `ec_kem.c` lines 217–234.
fn validate_matching_params(key_a: &EcKey, key_b: &EcKey) -> ProviderResult<()> {
    let group_a = key_a.group();
    let group_b = key_b.group();

    // The cheapest comparison is by named curve when both keys carry one.
    match (group_a.curve_name(), group_b.curve_name()) {
        (Some(a), Some(b)) if a == b => Ok(()),
        (Some(a), Some(b)) => {
            warn!(
                a = ?a,
                b = ?b,
                "EC key parameter mismatch (named curves differ)"
            );
            Err(ProviderError::Dispatch(format!(
                "EC key parameter mismatch: {a:?} vs {b:?}"
            )))
        }
        // Fall back to a structural comparison via the curve order.
        _ => {
            if group_a.order() == group_b.order() && group_a.degree() == group_b.degree() {
                Ok(())
            } else {
                warn!("EC key parameter mismatch (custom groups differ)");
                Err(ProviderError::Dispatch(
                    "EC key parameter mismatch (custom groups differ)".to_string(),
                ))
            }
        }
    }
}

// =============================================================================
// KemProvider trait implementation for EcDhKem
// =============================================================================

impl KemProvider for EcDhKem {
    /// Returns the curve-specific algorithm name, e.g. `"DHKEM-P256-HKDF-SHA256"`.
    fn name(&self) -> &'static str {
        self.curve.algorithm_name()
    }

    /// Construct a fresh, uninitialised `EcKemContext` for this curve.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KemContext>> {
        debug!(curve = ?self.curve, "EcDhKem::new_ctx");
        Ok(Box::new(EcKemContext::new(self.curve)))
    }
}

// =============================================================================
// KemContext trait implementation for EcKemContext
// =============================================================================

impl KemContext for EcKemContext {
    fn encapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        let info = self.kem_info.ok_or_else(|| {
            ProviderError::Init(format!(
                "EcKemContext: missing HPKE KEM info for curve {:?}",
                self.curve
            ))
        })?;

        // RFC 9180 §7.1.1 — public key is the uncompressed point encoding.
        if key.len() != info.public_key_len() {
            warn!(
                curve = ?self.curve,
                got = key.len(),
                expected = info.public_key_len(),
                "encapsulate_init: recipient public key length mismatch"
            );
            return Err(ProviderError::Dispatch(format!(
                "encapsulate_init: recipient public key length {} does not match Npk={}",
                key.len(),
                info.public_key_len()
            )));
        }

        let group = EcGroup::from_curve_name(self.curve.named_curve()).map_err(dispatch_err)?;
        let pk_point = EcPoint::from_bytes(&group, key).map_err(dispatch_err)?;
        let pk = EcKey::from_public_key(&group, pk_point).map_err(dispatch_err)?;

        // Reject malformed or off-curve points up front.
        validate_ec_key(&pk, false)?;

        self.recipient_key = Some(pk);

        if let Some(p) = params {
            apply_params(self, p)?;
        }

        // Operation discriminator — auth mode iff a sender authentication key
        // has already been installed.
        self.op = Some(if self.sender_authkey.is_some() {
            EcKemOperation::AuthEncapsulate
        } else {
            EcKemOperation::Encapsulate
        });

        debug!(
            curve = ?self.curve,
            auth = self.sender_authkey.is_some(),
            has_ikm = self.ikm.is_some(),
            "EcKemContext::encapsulate_init"
        );

        Ok(())
    }

    fn encapsulate(&mut self) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
        match self.op {
            Some(op) if op.is_encap() => {}
            Some(other) => {
                return Err(ProviderError::Dispatch(format!(
                    "EcKemContext::encapsulate called in {other:?} state"
                )));
            }
            None => {
                return Err(ProviderError::Dispatch(
                    "EcKemContext::encapsulate called before init".to_string(),
                ));
            }
        }

        match self.mode {
            EcKemMode::DhKem => dhkem_encap(self),
        }
    }

    fn decapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        let info = self.kem_info.ok_or_else(|| {
            ProviderError::Init(format!(
                "EcKemContext: missing HPKE KEM info for curve {:?}",
                self.curve
            ))
        })?;

        // RFC 9180 §7.1.1 — private key is OS2IP-decodable big-endian Nsk-byte
        // scalar.  The C source allows shorter keys via DER decoding; for the
        // direct-bytes path used in this trait we require Nsk bytes.
        if key.len() != info.secret_key_len() {
            warn!(
                curve = ?self.curve,
                got = key.len(),
                expected = info.secret_key_len(),
                "decapsulate_init: recipient private key length mismatch"
            );
            return Err(ProviderError::Dispatch(format!(
                "decapsulate_init: recipient private key length {} does not match Nsk={}",
                key.len(),
                info.secret_key_len()
            )));
        }

        let group = EcGroup::from_curve_name(self.curve.named_curve()).map_err(dispatch_err)?;
        let priv_bn = BigNum::from_bytes_be(key);
        let sk = EcKey::from_private_key(&group, priv_bn).map_err(dispatch_err)?;

        validate_ec_key(&sk, true)?;

        self.recipient_key = Some(sk);

        if let Some(p) = params {
            apply_params(self, p)?;
        }

        self.op = Some(if self.sender_authkey.is_some() {
            EcKemOperation::AuthDecapsulate
        } else {
            EcKemOperation::Decapsulate
        });

        debug!(
            curve = ?self.curve,
            auth = self.sender_authkey.is_some(),
            "EcKemContext::decapsulate_init"
        );

        Ok(())
    }

    fn decapsulate(&mut self, ciphertext: &[u8]) -> ProviderResult<Vec<u8>> {
        match self.op {
            Some(op) if !op.is_encap() => {}
            Some(other) => {
                return Err(ProviderError::Dispatch(format!(
                    "EcKemContext::decapsulate called in {other:?} state"
                )));
            }
            None => {
                return Err(ProviderError::Dispatch(
                    "EcKemContext::decapsulate called before init".to_string(),
                ));
            }
        }

        match self.mode {
            EcKemMode::DhKem => dhkem_decap(self, ciphertext),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut builder =
            ParamBuilder::new().push_utf8(PARAM_OPERATION, mode_to_str(self.mode).to_string());
        if let Some(op) = self.op {
            builder = builder.push_utf8("op", op_to_str(op).to_string());
        }
        Ok(builder.build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        apply_params(self, params)
    }
}

// =============================================================================
// Parameter handling
// =============================================================================

/// Apply parameters from a `ParamSet` to the given `EcKemContext`.
///
/// Recognised parameters:
///
/// - `"operation"` (UTF-8): KEM mode name. Currently only `"DHKEM"` is
///   recognised; passes through `super::util::kem_modename_to_id`.
/// - `"ikme"`      (octet string): deterministic input keying material for
///   `DeriveKeyPair`. The previous IKM (if any) is zeroised before being
///   replaced.
/// - `"authkey"`   (octet string): sender's authentication private key,
///   encoded as an Nsk-byte big-endian scalar.  The previous auth key is
///   dropped (which zeroises it via `EcKey`'s `Drop` impl).
///
/// Source equivalence: `eckem_set_ctx_params()` at `ec_kem.c` lines 289–321.
fn apply_params(ctx: &mut EcKemContext, params: &ParamSet) -> ProviderResult<()> {
    if let Some(v) = params.get(PARAM_OPERATION) {
        let mode_name = v.as_str().ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "KEM param '{PARAM_OPERATION}' must be a UTF-8 string, got {}",
                v.param_type_name()
            ))
        })?;
        let mode = super::util::kem_modename_to_id(mode_name).ok_or_else(|| {
            warn!(mode = mode_name, "unknown KEM operation/mode name");
            ProviderError::Dispatch(format!("unknown KEM operation/mode name: {mode_name:?}"))
        })?;
        ctx.mode = match mode {
            KemMode::DhKem => EcKemMode::DhKem,
        };
    }

    if let Some(v) = params.get(PARAM_IKME) {
        let ikm_bytes = v.as_bytes().ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "KEM param '{PARAM_IKME}' must be an octet string, got {}",
                v.param_type_name()
            ))
        })?;
        // Wipe the previous IKM (if any) before installing the new one.
        if let Some(ref mut prev) = ctx.ikm {
            prev.zeroize();
        }
        ctx.ikm = Some(ikm_bytes.to_vec());
    }

    if let Some(v) = params.get(PARAM_AUTHKEY) {
        let key_bytes = v.as_bytes().ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "KEM param '{PARAM_AUTHKEY}' must be an octet string, got {}",
                v.param_type_name()
            ))
        })?;

        let info = ctx.kem_info.ok_or_else(|| {
            ProviderError::Init(format!(
                "EcKemContext: missing HPKE KEM info for curve {:?}",
                ctx.curve
            ))
        })?;

        if key_bytes.len() != info.secret_key_len() {
            warn!(
                curve = ?ctx.curve,
                got = key_bytes.len(),
                expected = info.secret_key_len(),
                "auth key length mismatch"
            );
            return Err(ProviderError::Dispatch(format!(
                "KEM param '{PARAM_AUTHKEY}' length {} does not match Nsk={}",
                key_bytes.len(),
                info.secret_key_len()
            )));
        }

        let group = EcGroup::from_curve_name(ctx.curve.named_curve()).map_err(dispatch_err)?;
        let priv_bn = BigNum::from_bytes_be(key_bytes);
        let auth_key = EcKey::from_private_key(&group, priv_bn).map_err(dispatch_err)?;
        validate_ec_key(&auth_key, true)?;

        // Replace any previous auth key — its `Drop` impl wipes the inner
        // SecureBigNum.
        ctx.sender_authkey = Some(auth_key);
    }

    Ok(())
}

// =============================================================================
// String helpers for parameter introspection
// =============================================================================

/// Human-readable name for a `EcKemMode` — used by `get_params`.
fn mode_to_str(mode: EcKemMode) -> &'static str {
    match mode {
        EcKemMode::DhKem => "DHKEM",
    }
}

/// Human-readable name for a `EcKemOperation` — used by `get_params`.
fn op_to_str(op: EcKemOperation) -> &'static str {
    match op {
        EcKemOperation::Encapsulate => "encapsulate",
        EcKemOperation::Decapsulate => "decapsulate",
        EcKemOperation::AuthEncapsulate => "auth-encapsulate",
        EcKemOperation::AuthDecapsulate => "auth-decapsulate",
    }
}

// =============================================================================
// Algorithm descriptors — entry point used by the provider registry
// =============================================================================

/// Return one [`AlgorithmDescriptor`] per supported NIST EC DHKEM variant.
///
/// Mirrors the C dispatch-table registration at `ec_kem.c` lines 793–811,
/// extended to all three NIST curves (P-256, P-384, P-521).
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec![SupportedCurve::P256.algorithm_name()],
            property: "provider=default",
            description: SupportedCurve::P256.description(),
        },
        AlgorithmDescriptor {
            names: vec![SupportedCurve::P384.algorithm_name()],
            property: "provider=default",
            description: SupportedCurve::P384.description(),
        },
        AlgorithmDescriptor {
            names: vec![SupportedCurve::P521.algorithm_name()],
            property: "provider=default",
            description: SupportedCurve::P521.description(),
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================
//
// The test suite exercises every public surface of this module plus the
// crate-private helpers that drive the RFC 9180 DHKEM specification.  Because
// the helpers (`build_kem_context_*`, `dispatch_err`, `digest_output_len`,
// `EcKemContext::new`, `EcKemOperation`, `SupportedCurve::dkp_bitmask`, …) are
// module-private, the tests live in a sibling submodule that imports `super::*`
// to access them.
//
// The end-to-end round-trip tests perform a real DHKEM encapsulation and
// decapsulation across all three NIST curves (P-256, P-384, P-521) using the
// publicly-exposed `KemProvider` / `KemContext` traits.  They verify:
//
//  - shared secret agreement (encap output == decap output),
//  - encapsulated key length (= Nenc),
//  - shared secret length (= Nsecret),
//  - deterministic operation when an IKM is supplied (encap output is bitwise
//    identical across two invocations with the same IKM),
//  - authenticated mode (`AuthEncap` / `AuthDecap`) with sender authentication.

#[cfg(test)]
mod tests {
    // Justification: Test code legitimately uses expect/unwrap/panic for clear
    // failure messages on assertion failures.  The workspace `Cargo.toml`
    // §[workspace.lints.clippy] explicitly states:
    // "Tests and CLI main() may #[allow] with justification."
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]
    // Justification: Doc-comments inside `#[test]` functions reference identifiers
    // (e.g. `EcKemContext`, `OSSL_PARAM`, `RFC 9180`) without backtick formatting —
    // acceptable in test modules where the docs serve as inline rationale.
    #![allow(clippy::doc_markdown)]

    use super::*;
    use openssl_common::ParamValue;

    // -----------------------------------------------------------------------
    // SupportedCurve helpers
    // -----------------------------------------------------------------------

    #[test]
    fn curve_named_curve_maps_correctly() {
        assert_eq!(SupportedCurve::P256.named_curve(), NamedCurve::Prime256v1);
        assert_eq!(SupportedCurve::P384.named_curve(), NamedCurve::Secp384r1);
        assert_eq!(SupportedCurve::P521.named_curve(), NamedCurve::Secp521r1);
    }

    #[test]
    fn curve_hpke_kem_maps_correctly() {
        assert_eq!(SupportedCurve::P256.hpke_kem(), HpkeKem::DhKemP256Sha256);
        assert_eq!(SupportedCurve::P384.hpke_kem(), HpkeKem::DhKemP384Sha384);
        assert_eq!(SupportedCurve::P521.hpke_kem(), HpkeKem::DhKemP521Sha512);
    }

    #[test]
    fn curve_algorithm_name_is_canonical() {
        assert_eq!(SupportedCurve::P256.algorithm_name(), "P-256");
        assert_eq!(SupportedCurve::P384.algorithm_name(), "P-384");
        assert_eq!(SupportedCurve::P521.algorithm_name(), "P-521");
    }

    #[test]
    fn curve_description_contains_curve_name() {
        let descr = SupportedCurve::P256.description();
        assert!(descr.contains("P-256"), "P-256 description: {descr}");
        let descr = SupportedCurve::P384.description();
        assert!(descr.contains("P-384"), "P-384 description: {descr}");
        let descr = SupportedCurve::P521.description();
        assert!(descr.contains("P-521"), "P-521 description: {descr}");
    }

    #[test]
    fn curve_kem_info_sizes_match_rfc9180() {
        // RFC 9180 §7.1 — DHKEM(P-256, HKDF-SHA256), kem_id = 0x0010.
        let info = SupportedCurve::P256.kem_info();
        assert_eq!(info.kem_id(), 0x0010);
        assert_eq!(info.public_key_len(), 65);
        assert_eq!(info.secret_key_len(), 32);
        assert_eq!(info.enc_len(), 65);
        assert_eq!(info.shared_secret_len(), 32);
        assert_eq!(info.digest_name(), "SHA-256");

        // RFC 9180 §7.1 — DHKEM(P-384, HKDF-SHA384), kem_id = 0x0011.
        let info = SupportedCurve::P384.kem_info();
        assert_eq!(info.kem_id(), 0x0011);
        assert_eq!(info.public_key_len(), 97);
        assert_eq!(info.secret_key_len(), 48);
        assert_eq!(info.enc_len(), 97);
        assert_eq!(info.shared_secret_len(), 48);
        assert_eq!(info.digest_name(), "SHA-384");

        // RFC 9180 §7.1 — DHKEM(P-521, HKDF-SHA512), kem_id = 0x0012.
        let info = SupportedCurve::P521.kem_info();
        assert_eq!(info.kem_id(), 0x0012);
        assert_eq!(info.public_key_len(), 133);
        assert_eq!(info.secret_key_len(), 66);
        assert_eq!(info.enc_len(), 133);
        assert_eq!(info.shared_secret_len(), 64);
        assert_eq!(info.digest_name(), "SHA-512");
    }

    #[test]
    fn curve_dkp_bitmask_matches_rfc9180() {
        // RFC 9180 §7.1.3: P-256 / P-384 use the full byte (0xff), P-521
        // masks the leading byte to a single bit (0x01) because Nsk = 66
        // octets but the order has 521 bits → high byte must be ≤ 0x01.
        assert_eq!(SupportedCurve::P256.dkp_bitmask(), 0xff);
        assert_eq!(SupportedCurve::P384.dkp_bitmask(), 0xff);
        assert_eq!(SupportedCurve::P521.dkp_bitmask(), 0x01);
    }

    // -----------------------------------------------------------------------
    // EcKemOperation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn operation_is_auth_is_correct() {
        assert!(!EcKemOperation::Encapsulate.is_auth());
        assert!(!EcKemOperation::Decapsulate.is_auth());
        assert!(EcKemOperation::AuthEncapsulate.is_auth());
        assert!(EcKemOperation::AuthDecapsulate.is_auth());
    }

    #[test]
    fn operation_is_encap_is_correct() {
        assert!(EcKemOperation::Encapsulate.is_encap());
        assert!(EcKemOperation::AuthEncapsulate.is_encap());
        assert!(!EcKemOperation::Decapsulate.is_encap());
        assert!(!EcKemOperation::AuthDecapsulate.is_encap());
    }

    // -----------------------------------------------------------------------
    // Labeled HKDF primitives
    // -----------------------------------------------------------------------

    #[test]
    fn i2osp2_encodes_big_endian_u16() {
        // RFC 9180 §4 — I2OSP(n, 2) is big-endian 2-octet encoding.
        assert_eq!(i2osp2(0x0000), [0x00, 0x00]);
        assert_eq!(i2osp2(0x0010), [0x00, 0x10]);
        assert_eq!(i2osp2(0x0011), [0x00, 0x11]);
        assert_eq!(i2osp2(0x0012), [0x00, 0x12]);
        assert_eq!(i2osp2(0x1234), [0x12, 0x34]);
        assert_eq!(i2osp2(0xffff), [0xff, 0xff]);
    }

    #[test]
    fn suite_id_is_kem_label_plus_kem_id() {
        // RFC 9180 §4.1 — suite_id = "KEM" || I2OSP(kem_id, 2).
        assert_eq!(suite_id(0x0010), b"KEM\x00\x10");
        assert_eq!(suite_id(0x0011), b"KEM\x00\x11");
        assert_eq!(suite_id(0x0012), b"KEM\x00\x12");

        // Sanity: derived from kem_info ID matches the curve constant.
        let info = SupportedCurve::P256.kem_info();
        assert_eq!(suite_id(info.kem_id()), b"KEM\x00\x10");
    }

    #[test]
    fn digest_output_len_covers_expected_digests() {
        // Branches: SHA-256 (default), SHA-384, SHA-512, anything else.
        assert_eq!(digest_output_len("SHA-256"), 32);
        assert_eq!(digest_output_len("SHA-384"), 48);
        assert_eq!(digest_output_len("SHA-512"), 64);
        // Unknown digest names fall back to 32 (defensive default).
        assert_eq!(digest_output_len("BLAKE2-256"), 32);
        assert_eq!(digest_output_len(""), 32);
    }

    #[test]
    fn labeled_expand_rejects_oversized_length() {
        // u16::MAX + 1 cannot be encoded by I2OSP(L, 2) and must be rejected.
        let info = SupportedCurve::P256.kem_info();
        let suite = suite_id(info.kem_id());
        let prk = vec![0u8; 32];
        let result = labeled_expand(info, &suite, &prk, b"some_label", b"", usize::MAX);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    // -----------------------------------------------------------------------
    // Context construction & Debug redaction
    // -----------------------------------------------------------------------

    #[test]
    fn ec_kem_context_new_is_uninitialised() {
        let ctx = EcKemContext::new(SupportedCurve::P256);
        assert_eq!(ctx.curve, SupportedCurve::P256);
        assert!(ctx.recipient_key.is_none());
        assert!(ctx.sender_authkey.is_none());
        assert_eq!(ctx.mode, EcKemMode::DhKem);
        assert!(ctx.op.is_none());
        assert!(ctx.ikm.is_none());
        // kem_info is initialised with the curve's RFC 9180 suite constants.
        let info = ctx
            .kem_info
            .expect("kem_info populated by EcKemContext::new");
        assert_eq!(info.kem_id(), 0x0010);
    }

    #[test]
    fn ec_kem_context_debug_redacts_secrets() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        // Inject a known IKM with a recognisable byte pattern.
        ctx.ikm = Some(vec![0x11; 32]);
        let formatted = format!("{ctx:?}");
        // The Debug impl must NOT leak the raw IKM bytes — only the
        // "has_ikm: true" marker is emitted.
        assert!(
            formatted.contains("has_ikm: true"),
            "Debug output should mark IKM presence: {formatted}"
        );
        assert!(
            !formatted.contains("0x11"),
            "Debug output must not leak IKM bytes: {formatted}"
        );
        assert!(
            !formatted.contains("17, 17, 17"),
            "Debug output must not leak IKM bytes (decimal form): {formatted}"
        );
        // Curve, mode and op markers must be present.
        assert!(formatted.contains("P256"), "Debug output: {formatted}");
        assert!(formatted.contains("DhKem"), "Debug output: {formatted}");
    }

    #[test]
    fn ec_kem_context_drop_wipes_secrets() {
        // We cannot directly observe wiped memory after Drop, but we can
        // exercise the Drop path with a known IKM to ensure it does not panic
        // and is reachable from regular code.
        {
            let mut ctx = EcKemContext::new(SupportedCurve::P384);
            ctx.ikm = Some(vec![0xaa; 48]);
            // Implicit drop at end of scope.
            assert_eq!(ctx.ikm.as_ref().map(Vec::len), Some(48));
        }
        // Construct another context, store IKM, then drop explicitly.
        let mut ctx = EcKemContext::new(SupportedCurve::P521);
        ctx.ikm = Some(vec![0xbb; 66]);
        drop(ctx);
        // Reaching here implies the Drop impl ran without panicking.
    }

    // -----------------------------------------------------------------------
    // EcDhKem KemProvider impl
    // -----------------------------------------------------------------------

    #[test]
    fn provider_name_is_curve_name() {
        assert_eq!(EcDhKem::new(SupportedCurve::P256).name(), "P-256");
        assert_eq!(EcDhKem::new(SupportedCurve::P384).name(), "P-384");
        assert_eq!(EcDhKem::new(SupportedCurve::P521).name(), "P-521");
    }

    #[test]
    fn provider_new_ctx_returns_box() {
        let provider = EcDhKem::new(SupportedCurve::P256);
        let ctx = provider.new_ctx().expect("new_ctx");
        // The returned context reports DHKEM as its default operation mode.
        let params = ctx.get_params().expect("get_params on fresh ctx");
        let mode = params
            .get(PARAM_OPERATION)
            .and_then(ParamValue::as_str)
            .expect("operation param present");
        assert_eq!(mode, "DHKEM");
        // No "op" key yet — context is uninitialised.
        assert!(params.get("op").is_none(), "op should be unset before init");
    }

    // -----------------------------------------------------------------------
    // descriptors()
    // -----------------------------------------------------------------------

    #[test]
    fn descriptors_returns_three_curves() {
        let descs = descriptors();
        assert_eq!(descs.len(), 3, "three NIST curves are supported");

        // Assemble the (name, property) pairs into a sorted vector for stable
        // assertion regardless of declaration order.
        let pairs: Vec<(&'static str, &'static str)> =
            descs.iter().map(|d| (d.names[0], d.property)).collect();
        assert!(pairs.contains(&("P-256", "provider=default")));
        assert!(pairs.contains(&("P-384", "provider=default")));
        assert!(pairs.contains(&("P-521", "provider=default")));

        for d in &descs {
            // Every descriptor advertises exactly one canonical name.
            assert_eq!(d.names.len(), 1, "single-name descriptor: {:?}", d.names);
            assert_eq!(d.property, "provider=default");
            // The description references the curve.
            assert!(
                d.description.contains(d.names[0]),
                "description should mention curve {}: {}",
                d.names[0],
                d.description
            );
        }
    }

    // -----------------------------------------------------------------------
    // Init validation
    // -----------------------------------------------------------------------

    #[test]
    fn encapsulate_init_rejects_wrong_key_length() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        // 16 bytes is way below Npk = 65 for P-256.
        let err = ctx
            .encapsulate_init(&[0u8; 16], None)
            .expect_err("short pk should be rejected");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(msg.contains("Npk=65"), "error message: {msg}");
    }

    #[test]
    fn decapsulate_init_rejects_wrong_key_length() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let err = ctx
            .decapsulate_init(&[0u8; 16], None)
            .expect_err("short sk should be rejected");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(msg.contains("Nsk=32"), "error message: {msg}");
    }

    #[test]
    fn encapsulate_without_init_fails() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let err = ctx
            .encapsulate()
            .expect_err("encap without init should fail");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(msg.contains("called before init"), "error message: {msg}");
    }

    #[test]
    fn decapsulate_without_init_fails() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let err = ctx
            .decapsulate(&[0u8; 65])
            .expect_err("decap without init should fail");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(msg.contains("called before init"), "error message: {msg}");
    }

    #[test]
    fn decapsulate_rejects_wrong_ciphertext_length() {
        // Generate a real recipient keypair on P-256.
        let curve = SupportedCurve::P256;
        let info = curve.kem_info();
        let group =
            EcGroup::from_curve_name(curve.named_curve()).expect("EcGroup::from_curve_name");
        let kp = EcKey::generate(&group).expect("EcKey::generate");
        let sk_bytes = kp
            .private_key()
            .expect("private_key present")
            .to_bytes_be_padded(info.secret_key_len())
            .expect("to_bytes_be_padded");

        let mut ctx = EcKemContext::new(curve);
        ctx.decapsulate_init(&sk_bytes, None)
            .expect("decap_init succeeds with valid key");

        // Provide a too-short ciphertext (not Nenc=65).
        let err = ctx
            .decapsulate(&[0u8; 32])
            .expect_err("short ciphertext should be rejected");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(msg.contains("Nenc=65"), "error message: {msg}");
    }

    // -----------------------------------------------------------------------
    // set_params / get_params
    // -----------------------------------------------------------------------

    #[test]
    fn set_params_accepts_valid_operation_mode() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let params = ParamBuilder::new()
            .push_utf8(PARAM_OPERATION, "DHKEM".to_string())
            .build();
        ctx.set_params(&params).expect("DHKEM mode is valid");
        assert_eq!(ctx.mode, EcKemMode::DhKem);
    }

    #[test]
    fn set_params_rejects_unknown_operation_mode() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let params = ParamBuilder::new()
            .push_utf8(PARAM_OPERATION, "BANANA-KEM".to_string())
            .build();
        let err = ctx
            .set_params(&params)
            .expect_err("unknown KEM mode must be rejected");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("BANANA-KEM"),
            "error should reference the offending mode name: {msg}"
        );
    }

    #[test]
    fn set_params_rejects_wrong_type_for_operation() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let mut params = ParamSet::new();
        params.set(PARAM_OPERATION, ParamValue::Int32(42));
        let err = ctx
            .set_params(&params)
            .expect_err("Int32 cannot satisfy the operation param contract");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("must be a UTF-8 string"),
            "error message: {msg}"
        );
        assert!(msg.contains("Int32"), "error message: {msg}");
    }

    #[test]
    fn set_params_stores_and_zeroizes_ikm() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let ikm1 = vec![0x11u8; 32];
        let params = ParamBuilder::new()
            .push_octet(PARAM_IKME, ikm1.clone())
            .build();
        ctx.set_params(&params).expect("first IKM accepted");
        assert_eq!(ctx.ikm.as_deref(), Some(ikm1.as_slice()));

        // Second call replaces the previous IKM.  The previous buffer is
        // zeroised internally; we cannot observe that directly, but we can
        // confirm the new IKM is installed without panicking.
        let ikm2 = vec![0x22u8; 32];
        let params2 = ParamBuilder::new()
            .push_octet(PARAM_IKME, ikm2.clone())
            .build();
        ctx.set_params(&params2).expect("second IKM accepted");
        assert_eq!(ctx.ikm.as_deref(), Some(ikm2.as_slice()));
    }

    #[test]
    fn set_params_rejects_wrong_type_for_ikme() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let mut params = ParamSet::new();
        params.set(PARAM_IKME, ParamValue::Utf8String("notbytes".to_string()));
        let err = ctx
            .set_params(&params)
            .expect_err("Utf8String cannot satisfy the ikme param contract");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("must be an octet string"),
            "error message: {msg}"
        );
    }

    #[test]
    fn set_params_authkey_validates_length() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        // 16 octets is below Nsk=32.
        let params = ParamBuilder::new()
            .push_octet(PARAM_AUTHKEY, vec![0u8; 16])
            .build();
        let err = ctx
            .set_params(&params)
            .expect_err("authkey of wrong length must be rejected");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(msg.contains("Nsk=32"), "error message: {msg}");
    }

    #[test]
    fn set_params_authkey_wrong_type_rejected() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        let mut params = ParamSet::new();
        params.set(
            PARAM_AUTHKEY,
            ParamValue::Utf8String("not-an-octet-string".to_string()),
        );
        let err = ctx
            .set_params(&params)
            .expect_err("authkey must be octet string");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("must be an octet string"),
            "error message: {msg}"
        );
    }

    #[test]
    fn set_params_ignores_unknown_keys() {
        let mut ctx = EcKemContext::new(SupportedCurve::P256);
        // Unknown keys are forward-compatible — they are simply ignored, never
        // raise an error.
        let mut params = ParamSet::new();
        params.set(
            "unknown-future-param",
            ParamValue::Utf8String("anything".to_string()),
        );
        ctx.set_params(&params).expect("unknown keys are ignored");
        // No state should have been mutated.
        assert!(ctx.ikm.is_none());
        assert!(ctx.sender_authkey.is_none());
        assert_eq!(ctx.mode, EcKemMode::DhKem);
    }

    #[test]
    fn get_params_reports_current_op_after_init() {
        // Run encap_init on a freshly-generated public key, then verify that
        // get_params reports the current operation as "encapsulate".
        let curve = SupportedCurve::P256;
        let group =
            EcGroup::from_curve_name(curve.named_curve()).expect("EcGroup::from_curve_name");
        let kp = EcKey::generate(&group).expect("EcKey::generate");
        let pk_bytes = kp
            .public_key()
            .expect("public_key present")
            .to_bytes(&group, PointConversionForm::Uncompressed)
            .expect("to_bytes(Uncompressed)");

        let mut ctx = EcKemContext::new(curve);
        ctx.encapsulate_init(&pk_bytes, None)
            .expect("encap_init succeeds with valid pk");

        let params = ctx.get_params().expect("get_params after init");
        let op_str = params
            .get("op")
            .and_then(ParamValue::as_str)
            .expect("op present after init");
        assert_eq!(op_str, "encapsulate");
        // operation (mode) is still DHKEM.
        let mode = params
            .get(PARAM_OPERATION)
            .and_then(ParamValue::as_str)
            .expect("operation present");
        assert_eq!(mode, "DHKEM");
    }

    // -----------------------------------------------------------------------
    // Validation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn validate_matching_params_accepts_same_curve() {
        let group =
            EcGroup::from_curve_name(NamedCurve::Prime256v1).expect("EcGroup::from_curve_name");
        let k1 = EcKey::generate(&group).expect("k1 generate");
        let k2 = EcKey::generate(&group).expect("k2 generate");
        validate_matching_params(&k1, &k2).expect("same curve must succeed");
    }

    #[test]
    fn validate_matching_params_rejects_different_curves() {
        let g1 = EcGroup::from_curve_name(NamedCurve::Prime256v1).expect("g1");
        let g2 = EcGroup::from_curve_name(NamedCurve::Secp384r1).expect("g2");
        let k1 = EcKey::generate(&g1).expect("k1 generate");
        let k2 = EcKey::generate(&g2).expect("k2 generate");
        let err = validate_matching_params(&k1, &k2).expect_err("different curves must fail");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("EC key parameter mismatch"),
            "error message: {msg}"
        );
    }

    #[test]
    fn validate_ec_key_accepts_valid_key() {
        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1).expect("group");
        let kp = EcKey::generate(&group).expect("EcKey::generate");
        // Full keypair: should validate with require_private = true.
        validate_ec_key(&kp, true).expect("valid keypair must pass full check");
        // Public-only check should also pass (the public component is present).
        validate_ec_key(&kp, false).expect("valid public component must pass");
    }

    // -----------------------------------------------------------------------
    // KEM context builders
    // -----------------------------------------------------------------------

    #[test]
    fn build_kem_context_base_concatenates() {
        let enc = [1u8, 2, 3];
        let pk = [10u8, 20, 30];
        let kc = build_kem_context_base(&enc, &pk);
        assert_eq!(kc, vec![1, 2, 3, 10, 20, 30]);
    }

    #[test]
    fn build_kem_context_auth_concatenates() {
        let enc = [1u8, 2, 3];
        let pk_r = [10u8, 20, 30];
        let pk_s = [40u8, 50, 60];
        let kc = build_kem_context_auth(&enc, &pk_r, &pk_s);
        assert_eq!(kc, vec![1, 2, 3, 10, 20, 30, 40, 50, 60]);
    }

    // -----------------------------------------------------------------------
    // String helpers
    // -----------------------------------------------------------------------

    #[test]
    fn mode_to_str_returns_dhkem() {
        assert_eq!(mode_to_str(EcKemMode::DhKem), "DHKEM");
    }

    #[test]
    fn op_to_str_covers_all_variants() {
        assert_eq!(op_to_str(EcKemOperation::Encapsulate), "encapsulate");
        assert_eq!(op_to_str(EcKemOperation::Decapsulate), "decapsulate");
        assert_eq!(
            op_to_str(EcKemOperation::AuthEncapsulate),
            "auth-encapsulate"
        );
        assert_eq!(
            op_to_str(EcKemOperation::AuthDecapsulate),
            "auth-decapsulate"
        );
    }

    #[test]
    fn dispatch_err_renders_crypto_error() {
        let crypto_err = CryptoError::Key("test failure".to_string());
        let provider_err = dispatch_err(crypto_err);
        let ProviderError::Dispatch(msg) = provider_err else {
            panic!("expected Dispatch variant");
        };
        // The CryptoError display goes through `thiserror`'s formatter:
        // "key error: test failure".
        assert!(msg.contains("test failure"), "rendered message: {msg}");
    }

    // -----------------------------------------------------------------------
    // End-to-end DHKEM round-trip — base mode
    // -----------------------------------------------------------------------

    /// Helper: generate a fresh recipient keypair on `curve` and return
    /// `(pk_bytes, sk_bytes)` of the lengths required by the trait surface
    /// (Npk for the public key, Nsk-padded big-endian scalar for the private
    /// key).
    fn make_keypair(curve: SupportedCurve) -> (Vec<u8>, Vec<u8>) {
        let info = curve.kem_info();
        let group =
            EcGroup::from_curve_name(curve.named_curve()).expect("EcGroup::from_curve_name");
        let kp = EcKey::generate(&group).expect("EcKey::generate");
        let pk = kp
            .public_key()
            .expect("public_key present")
            .to_bytes(&group, PointConversionForm::Uncompressed)
            .expect("public_key::to_bytes");
        let sk = kp
            .private_key()
            .expect("private_key present")
            .to_bytes_be_padded(info.secret_key_len())
            .expect("private_key::to_bytes_be_padded");
        assert_eq!(pk.len(), info.public_key_len(), "Npk mismatch");
        assert_eq!(sk.len(), info.secret_key_len(), "Nsk mismatch");
        (pk, sk)
    }

    /// Drives a full base-mode DHKEM round-trip on the given curve, asserting
    /// the encapsulator and decapsulator agree on the shared secret and that
    /// all output lengths match RFC 9180 §7.1.
    fn run_base_roundtrip(curve: SupportedCurve) {
        let info = curve.kem_info();
        let (pk_r, sk_r) = make_keypair(curve);

        // Encapsulator side.
        let mut sender = EcKemContext::new(curve);
        sender
            .encapsulate_init(&pk_r, None)
            .expect("encap_init succeeds");
        let (enc, ss_a) = sender.encapsulate().expect("encapsulate");
        assert_eq!(enc.len(), info.enc_len(), "Nenc mismatch on encap");
        assert_eq!(
            ss_a.len(),
            info.shared_secret_len(),
            "Nsecret mismatch on encap"
        );

        // Decapsulator side.
        let mut receiver = EcKemContext::new(curve);
        receiver
            .decapsulate_init(&sk_r, None)
            .expect("decap_init succeeds");
        let ss_b = receiver.decapsulate(&enc).expect("decapsulate");
        assert_eq!(
            ss_b.len(),
            info.shared_secret_len(),
            "Nsecret mismatch on decap"
        );

        // The whole point: both sides agree on the shared secret.
        assert_eq!(ss_a, ss_b, "DHKEM round-trip failed for {curve:?}");
    }

    #[test]
    fn dhkem_p256_base_roundtrip() {
        run_base_roundtrip(SupportedCurve::P256);
    }

    #[test]
    fn dhkem_p384_base_roundtrip() {
        run_base_roundtrip(SupportedCurve::P384);
    }

    #[test]
    fn dhkem_p521_base_roundtrip() {
        run_base_roundtrip(SupportedCurve::P521);
    }

    #[test]
    fn dhkem_p256_base_roundtrip_deterministic_via_ikm() {
        // With a fixed IKM, DeriveKeyPair is deterministic, hence two
        // encapsulations produce bitwise-identical (enc, ss) tuples.
        let curve = SupportedCurve::P256;
        let info = curve.kem_info();
        let (pk_r, sk_r) = make_keypair(curve);
        let ikm = vec![0x17u8; 32];

        let params = ParamBuilder::new()
            .push_octet(PARAM_IKME, ikm.clone())
            .build();

        let mut sender1 = EcKemContext::new(curve);
        sender1
            .encapsulate_init(&pk_r, Some(&params))
            .expect("encap_init #1 succeeds");
        let (enc1, ss1) = sender1.encapsulate().expect("encapsulate #1");

        let params2 = ParamBuilder::new().push_octet(PARAM_IKME, ikm).build();
        let mut sender2 = EcKemContext::new(curve);
        sender2
            .encapsulate_init(&pk_r, Some(&params2))
            .expect("encap_init #2 succeeds");
        let (enc2, ss2) = sender2.encapsulate().expect("encapsulate #2");

        // Determinism property.
        assert_eq!(enc1, enc2, "deterministic enc differs across runs");
        assert_eq!(ss1, ss2, "deterministic ss differs across runs");

        // And the receiver still recovers the same secret.
        let mut receiver = EcKemContext::new(curve);
        receiver
            .decapsulate_init(&sk_r, None)
            .expect("decap_init succeeds");
        let ss_recv = receiver.decapsulate(&enc1).expect("decapsulate");
        assert_eq!(ss_recv, ss1, "receiver disagrees with deterministic sender");
        assert_eq!(ss_recv.len(), info.shared_secret_len());
    }

    // -----------------------------------------------------------------------
    // End-to-end DHKEM round-trip — auth mode (AuthEncap / AuthDecap)
    // -----------------------------------------------------------------------

    /// Authenticated mode end-to-end test on P-256.
    ///
    /// Per `apply_params`, the `"authkey"` parameter is parsed as an Nsk-byte
    /// big-endian scalar and decoded via `EcKey::from_private_key`.  Both
    /// sides therefore install the *sender's* private scalar so that:
    ///
    /// - the encapsulator can compute `DH(skS, pkR)` (via the locally derived
    ///   `pkS`), and
    /// - the decapsulator can compute `DH(skR, pkS)` (via the locally derived
    ///   `pkS` from the same scalar).
    ///
    /// The cryptographic agreement holds because both sides observe the same
    /// `pkS` — derived from the shared scalar — when constructing
    /// `kem_context = enc || pk_rm || pk_sm`.
    #[test]
    fn dhkem_p256_auth_roundtrip() {
        let curve = SupportedCurve::P256;
        let info = curve.kem_info();

        // Generate the recipient keypair.
        let (pk_r_bytes, sk_r_bytes) = make_keypair(curve);
        // Generate the sender's authentication keypair — only the private
        // scalar is shipped via PARAM_AUTHKEY.
        let (_pk_s_bytes, sk_s_bytes) = make_keypair(curve);

        // -- Encapsulator side ----------------------------------------------
        let auth_params = ParamBuilder::new()
            .push_octet(PARAM_AUTHKEY, sk_s_bytes.clone())
            .build();
        let mut sender = EcKemContext::new(curve);
        sender
            .encapsulate_init(&pk_r_bytes, Some(&auth_params))
            .expect("auth-encap init succeeds");
        // After init, op must be AuthEncapsulate.
        assert_eq!(sender.op, Some(EcKemOperation::AuthEncapsulate));
        let (enc, ss_a) = sender.encapsulate().expect("auth-encapsulate");
        assert_eq!(enc.len(), info.enc_len());
        assert_eq!(ss_a.len(), info.shared_secret_len());

        // -- Decapsulator side ----------------------------------------------
        let auth_params2 = ParamBuilder::new()
            .push_octet(PARAM_AUTHKEY, sk_s_bytes)
            .build();
        let mut receiver = EcKemContext::new(curve);
        receiver
            .decapsulate_init(&sk_r_bytes, Some(&auth_params2))
            .expect("auth-decap init succeeds");
        assert_eq!(receiver.op, Some(EcKemOperation::AuthDecapsulate));
        let ss_b = receiver.decapsulate(&enc).expect("auth-decapsulate");

        // Cryptographic agreement.
        assert_eq!(ss_a, ss_b, "Auth DHKEM round-trip disagreement");
    }

    // -----------------------------------------------------------------------
    // State-machine guard rails
    // -----------------------------------------------------------------------

    #[test]
    fn encapsulate_after_decap_init_fails() {
        // Once the context is initialised for decapsulation, calling
        // `encapsulate()` must fail with a wrong-state error, not a
        // generic "called before init".
        let curve = SupportedCurve::P256;
        let (_pk_r, sk_r) = make_keypair(curve);

        let mut ctx = EcKemContext::new(curve);
        ctx.decapsulate_init(&sk_r, None).expect("decap_init");

        let err = ctx
            .encapsulate()
            .expect_err("encap on decap-initialised ctx must fail");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("called in") && msg.contains("Decapsulate"),
            "error message should describe the wrong state: {msg}"
        );
    }

    #[test]
    fn decapsulate_after_encap_init_fails() {
        let curve = SupportedCurve::P256;
        let (pk_r, _sk_r) = make_keypair(curve);

        let mut ctx = EcKemContext::new(curve);
        ctx.encapsulate_init(&pk_r, None).expect("encap_init");

        let err = ctx
            .decapsulate(&[0u8; 65])
            .expect_err("decap on encap-initialised ctx must fail");
        let ProviderError::Dispatch(msg) = err else {
            panic!("expected Dispatch error, got {err:?}");
        };
        assert!(
            msg.contains("called in") && msg.contains("Encapsulate"),
            "error message should describe the wrong state: {msg}"
        );
    }
}
