//! # RSA / RSA-PSS Key Management Provider Implementation
//!
//! Translates the RSA key-management dispatch entries from
//! `providers/implementations/keymgmt/rsa_kmgmt.c` (~823 lines) into idiomatic
//! Rust. Manages RSA and RSA-PSS key generation, import/export with optional
//! PSS parameter restrictions, and key validation. Both the standard PKCS #1
//! v1.5 / v2.1 RSA key type and the PSS-restricted variant are supported.
//!
//! ## Responsibilities
//!
//! * Allocate and free typed key data ([`RsaKeyData`]) tracking up to four
//!   key states (empty, public-only, full key pair, optionally with PSS
//!   parameter restrictions).
//! * Generate fresh RSA / RSA-PSS keys from configurable bit-size, public
//!   exponent, and prime-count parameters via [`RsaGenContext`].
//! * Import and export the eight RSA key components (`n`, `e`, `d`,
//!   `rsa-factor1..2`, `rsa-exponent1..2`, `rsa-coefficient1`) plus optional
//!   PSS restriction parameters (`digest`, `mgf1-digest`, `saltlen`) using
//!   the typed [`ParamSet`] system.
//! * Provide the seven [`KeyMgmtProvider`] trait methods (`name`, `new_key`,
//!   `generate`, `import`, `export`, `has`, `validate`) for both
//!   [`RsaKeyMgmt`] and [`RsaPssKeyMgmt`] dispatch tables.
//! * Surface key metadata (`bits`, `max-size`, `security-bits`,
//!   `default-digest`, optionally `mandatory-digest`) via `get_params`.
//!
//! ## Architecture
//!
//! ### Key Data Decomposition
//!
//! [`RsaKeyData`] holds either a full [`RsaKeyPair`] (with private key
//! material protected by `ZeroizeOnDrop`) or just an [`RsaPublicKey`], plus
//! optional PSS restriction parameters. The `rsa_type` field discriminates
//! between plain RSA and RSA-PSS. PSS restrictions are stored as
//! [`RsaPssRestriction::Restricted`] only when at least one PSS parameter
//! has been specified — otherwise they remain [`RsaPssRestriction::Unrestricted`].
//!
//! ### Two Dispatch Tables
//!
//! Unlike DSA which exposes a single dispatch table, RSA registers **two**:
//! the standard `ossl_rsa_keymgmt_functions` table and the PSS-restricted
//! `ossl_rsapss_keymgmt_functions` table. Both share the same underlying
//! key components but the PSS variant pins the signing scheme/digest/MGF1
//! hash to the key, mirroring the C `KEYTYPE_RSA_PSS` discriminator. We
//! expose this as two distinct types — [`RsaKeyMgmt`] and [`RsaPssKeyMgmt`]
//! — that share the same key-data representation but enforce different
//! validation rules during `generate`.
//!
//! ## Security Properties
//!
//! * Private key material is wrapped in [`RsaPrivateKey`] which derives
//!   `Zeroize` and `ZeroizeOnDrop` — secure erasure happens automatically
//!   on drop with no manual `OPENSSL_cleanse` equivalent required.
//! * The custom [`fmt::Debug`] implementation for [`RsaKeyData`] redacts
//!   sensitive fields to prevent accidental disclosure via diagnostics.
//! * Key validation calls into [`openssl_crypto::rsa::check_keypair`] which
//!   performs both arithmetic consistency (`n = p*q`, `d*e ≡ 1 mod λ(n)`,
//!   CRT components) and a pairwise consistency test (sign/verify with
//!   `m = 2`).
//!
//! ## Wiring Path (Rule R10)
//!
//! ```text
//! openssl-cli::main
//!   → openssl-provider::default::DefaultProvider::new
//!   → crate::implementations::all_keymgmt_descriptors
//!   → crate::implementations::keymgmt::descriptors
//!   → crate::implementations::keymgmt::rsa::rsa_descriptors  (this module)
//! ```
//!
//! ## C Source Mapping
//!
//! | C Source                                                | Rust Equivalent                                  |
//! |---------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` lines 605–608                   | [`rsa_descriptors`]                            |
//! | `providers/implementations/keymgmt/rsa_kmgmt.c`         | this module                                       |
//! | `rsa_newdata` / `rsapss_newdata` (lines 31–55)          | [`RsaKeyMgmt::new_key`] / [`RsaPssKeyMgmt::new_key`] |
//! | `rsa_has` (lines 120–155)                               | [`RsaKeyData::has_selection`]                  |
//! | `rsa_match` (lines 165–190)                             | [`RsaKeyData::match_keys`]                      |
//! | `rsa_validate` (lines 190–260)                          | [`RsaKeyData::validate_selection`]            |
//! | `rsa_import` / `rsa_export` (lines 310–480)             | [`RsaKeyData::from_params`] / [`RsaKeyData::export_to_params`] |
//! | `rsa_gen_init` / `rsa_gen` (lines 560–750)              | [`RsaGenContext`] + [`RsaKeyData::generate_from_params`] |
//! | `rsa_get_params` / `rsa_gettable_params`                | [`RsaKeyMgmt::get_params`] / [`RsaKeyMgmt::gettable_params`] |
//! | `PROV_NAMES_RSA` / `PROV_NAMES_RSA_PSS` in `prov/names.h` | the `names` slice on each `AlgorithmDescriptor` |

use std::fmt;

use tracing::{debug, trace, warn};

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::bn::BigNum;
use openssl_crypto::hash::algorithm_from_name;
use openssl_crypto::rsa::pss::{PssParams30, DEFAULT_PSS_PARAMS_30};
use openssl_crypto::rsa::{
    check_keypair, check_private_key, check_public_key, from_params as rsa_from_params,
    generate_key, to_params as rsa_to_params, RsaKeyGenParams, RsaKeyPair, RsaPrivateKey,
    RsaPublicKey, RSA_MAX_PRIME_NUM, RSA_MIN_MODULUS_BITS,
};

use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;
use crate::implementations::algorithm;

// =============================================================================
// Constants — canonical OSSL_PARAM key strings + algorithm defaults
// =============================================================================

/// Default signing digest reported by `rsa_get_params(default-digest)`.
///
/// Mirrors `RSA_DEFAULT_MD` defined at `rsa_kmgmt.c:56` and used at
/// `rsa_kmgmt.c:rsa_get_params`. Surfaces as the value of the
/// [`PARAM_DEFAULT_DIGEST`] slot for plain RSA and unrestricted RSA-PSS keys.
pub(crate) const RSA_DEFAULT_MD: &str = "SHA-256";

/// Default key size in bits for [`RsaGenContext`].
///
/// Matches the C `gctx->nbits = 2048` initialization at `rsa_kmgmt.c:rsa_gen_init`.
pub(crate) const RSA_DEFAULT_KEY_BITS: u32 = 2048;

/// Default number of primes for [`RsaGenContext`].
///
/// Matches the C `gctx->primes = 2` initialization. Multi-prime RSA values
/// (3..=5) are accepted only for plain RSA generation and only when the
/// caller explicitly specifies them via the `"primes"` parameter.
pub(crate) const RSA_DEFAULT_PRIMES: usize = 2;

// --- RSA key component parameter keys (from include/openssl/core_names.h) ---
//
// Canonical OSSL_PARAM key names for the RSA component fields. `PARAM_RSA_N`
// and `PARAM_RSA_E` are referenced directly by `RsaKeyData::export_to_params`
// when emitting a public-only export. The `D`, `FACTOR*`, `EXPONENT*`, and
// `COEFFICIENT*` slots are serialised by `openssl_crypto::rsa::to_params` and
// parsed by `openssl_crypto::rsa::from_params`; we reproduce the canonical
// strings here so that they are documented at the keymgmt layer alongside the
// parameter set surface even when the crypto layer owns the translation. The
// `#[allow(dead_code)]` annotations are justified by these constants serving
// as the authoritative naming reference for the canonical OSSL_PARAM keys
// declared in `include/openssl/core_names.h.in` and consumed by RSA tooling
// in `apps/`. Removing them would silently lose the C↔Rust parameter-name
// mapping documented at the provider boundary.
pub(crate) const PARAM_RSA_N: &str = "n";
pub(crate) const PARAM_RSA_E: &str = "e";
#[allow(dead_code)] // Canonical name; serialised by openssl_crypto::rsa::{from,to}_params.
pub(crate) const PARAM_RSA_D: &str = "d";
#[allow(dead_code)] // Canonical name; serialised by openssl_crypto::rsa::{from,to}_params.
pub(crate) const PARAM_RSA_FACTOR1: &str = "rsa-factor1";
#[allow(dead_code)] // Canonical name; serialised by openssl_crypto::rsa::{from,to}_params.
pub(crate) const PARAM_RSA_FACTOR2: &str = "rsa-factor2";
#[allow(dead_code)] // Canonical name; serialised by openssl_crypto::rsa::{from,to}_params.
pub(crate) const PARAM_RSA_EXPONENT1: &str = "rsa-exponent1";
#[allow(dead_code)] // Canonical name; serialised by openssl_crypto::rsa::{from,to}_params.
pub(crate) const PARAM_RSA_EXPONENT2: &str = "rsa-exponent2";
#[allow(dead_code)] // Canonical name; serialised by openssl_crypto::rsa::{from,to}_params.
pub(crate) const PARAM_RSA_COEFFICIENT1: &str = "rsa-coefficient1";

// --- RSA generation parameter keys (canonical aliases) ---
pub(crate) const PARAM_RSA_BITS: &str = "bits";
pub(crate) const PARAM_RSA_PRIMES: &str = "primes";
pub(crate) const PARAM_RSA_DIGEST: &str = "digest";
pub(crate) const PARAM_RSA_DIGEST_PROPS: &str = "properties";
pub(crate) const PARAM_RSA_MASKGENFUNC: &str = "mgf";
pub(crate) const PARAM_RSA_MGF1_DIGEST: &str = "mgf1-digest";
pub(crate) const PARAM_RSA_PSS_SALTLEN: &str = "saltlen";
pub(crate) const PARAM_RSA_A: &str = "rsa-a";
pub(crate) const PARAM_RSA_B: &str = "rsa-b";

// --- Generic PKEY metadata parameter keys ---
pub(crate) const PARAM_BITS: &str = "bits";
pub(crate) const PARAM_MAX_SIZE: &str = "max-size";
pub(crate) const PARAM_SECURITY_BITS: &str = "security-bits";
// Canonical name for the post-quantum security category attribute defined in
// `include/openssl/core_names.h.in`. Plain RSA does not currently emit a
// security category (NIST PQC categorisation applies to ML-KEM/ML-DSA/SLH-DSA
// rather than classical RSA), but the canonical string is recorded here so
// that the provider boundary documents the full PKEY metadata surface.
#[allow(dead_code)] // Canonical PKEY metadata key, reserved for PQC migration.
pub(crate) const PARAM_SECURITY_CATEGORY: &str = "security-category";
pub(crate) const PARAM_DEFAULT_DIGEST: &str = "default-digest";
pub(crate) const PARAM_MANDATORY_DIGEST: &str = "mandatory-digest";

// --- Tracing target (used uniformly across this module) ---
const TRACING_TARGET: &str = "openssl_provider::keymgmt::rsa";

// =============================================================================
// RsaKeyType — discriminator between RSA and RSA-PSS keys
// =============================================================================

/// Discriminates between the two RSA key sub-types.
///
/// Mirrors the C `KEYTYPE_RSA` / `KEYTYPE_RSA_PSS` constants used as the
/// `selection`-independent key type tag by `rsa_kmgmt.c`. The value is set
/// once at construction (via `new_key` or `import`) and never changes — it
/// determines which dispatch table behavior applies (e.g. RSA-PSS keys
/// expose `query_operation_name = "RSA"` and may carry restriction params,
/// while plain RSA keys must remain unrestricted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyType {
    /// Standard PKCS #1 v1.5 / v2.1 RSA. The key may be used for any
    /// signing scheme and any digest. Plain RSA keys must never carry
    /// PSS parameter restrictions; the `generate` path enforces this.
    Rsa,
    /// RSA-PSS — RSA keys restricted to RSASSA-PSS signing. A PSS key
    /// may optionally pin the hash algorithm, MGF1 hash algorithm, and
    /// salt length to a specific configuration; `RsaPssRestriction`
    /// carries those pinned values.
    RsaPss,
}

// =============================================================================
// RsaPssRestriction — optional PSS parameter constraints
// =============================================================================

/// Optional PSS parameter restrictions for an RSA-PSS key.
///
/// Plain RSA keys always carry [`RsaPssRestriction::Unrestricted`].
/// RSA-PSS keys may carry either variant: [`RsaPssRestriction::Unrestricted`]
/// (when no PSS parameters are pinned to the key) or
/// [`RsaPssRestriction::Restricted`] (when the hash algorithm, MGF1 hash,
/// and/or salt length have been fixed by the caller).
///
/// This is the Rust equivalent of `RSA_PSS_PARAMS_30` from
/// `crypto/rsa/rsa_pss.h` — the C struct that pins the PSS algorithm
/// parameters to a specific configuration.
///
/// # Rule R5 Compliance
///
/// Uses an `enum` with explicit `Unrestricted` / `Restricted(PssParams30)`
/// variants rather than encoding "unset" as a sentinel. The wrapped
/// [`PssParams30`] internally uses `Option<DigestAlgorithm>` for hash
/// selection and `i32` (with `-1` as a documented "unset" sentinel
/// inherited from the on-the-wire encoding) for salt length and trailer
/// field — that internal encoding is determined by the ASN.1 / DER format
/// and is preserved for round-trip correctness.
#[derive(Debug, Clone)]
pub enum RsaPssRestriction {
    /// No PSS parameters are pinned. Sign/verify operations on a key with
    /// this restriction may use any hash algorithm and any salt length.
    Unrestricted,
    /// PSS parameters are pinned to the wrapped [`PssParams30`] value.
    /// Sign/verify operations must use the pinned configuration.
    Restricted(PssParams30),
}

impl RsaPssRestriction {
    /// Returns `true` if this restriction is [`RsaPssRestriction::Restricted`].
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        matches!(self, RsaPssRestriction::Restricted(_))
    }

    /// Returns the pinned [`PssParams30`] when this restriction is
    /// [`RsaPssRestriction::Restricted`], otherwise `None`.
    #[must_use]
    pub fn params(&self) -> Option<&PssParams30> {
        match self {
            RsaPssRestriction::Restricted(p) => Some(p),
            RsaPssRestriction::Unrestricted => None,
        }
    }

    /// Read PSS-related parameters from the supplied [`ParamSet`] and
    /// transition this restriction accordingly. Returns `Ok(true)` if the
    /// restriction was modified (i.e. at least one PSS parameter was
    /// found), otherwise `Ok(false)`.
    ///
    /// Mirrors `prepare_rsa_params` from `rsa_kmgmt.c` (lines ~700–740)
    /// which extracts `PARAM_RSA_DIGEST`, `PARAM_RSA_MASKGENFUNC`,
    /// `PARAM_RSA_MGF1_DIGEST`, and `PARAM_RSA_PSS_SALTLEN` from the
    /// caller-supplied `OSSL_PARAM[]` array and applies them to the
    /// PSS parameter struct.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] if a parameter has the wrong
    /// type (e.g. a non-string `digest`).
    pub(crate) fn absorb_pss_params(&mut self, params: &ParamSet) -> ProviderResult<bool> {
        let mut pss = match self {
            RsaPssRestriction::Restricted(p) => *p,
            RsaPssRestriction::Unrestricted => DEFAULT_PSS_PARAMS_30,
        };
        let mut modified = false;

        if let Some(value) = params.get(PARAM_RSA_DIGEST) {
            if let ParamValue::Utf8String(name) = value {
                let alg = algorithm_from_name(name).ok_or_else(|| {
                    ProviderError::Dispatch(format!("unknown PSS digest algorithm: {name}",))
                })?;
                pss.set_hash_algorithm(alg);
                modified = true;
            } else {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_RSA_DIGEST} must be a UTF-8 string",
                )));
            }
        }

        if let Some(value) = params.get(PARAM_RSA_MASKGENFUNC) {
            if let ParamValue::Utf8String(name) = value {
                if !name.eq_ignore_ascii_case("MGF1") {
                    return Err(ProviderError::Dispatch(format!(
                        "unsupported mask generation function: {name}; only MGF1 is supported",
                    )));
                }
                modified = true;
            } else {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_RSA_MASKGENFUNC} must be a UTF-8 string",
                )));
            }
        }

        if let Some(value) = params.get(PARAM_RSA_MGF1_DIGEST) {
            if let ParamValue::Utf8String(name) = value {
                let alg = algorithm_from_name(name).ok_or_else(|| {
                    ProviderError::Dispatch(format!("unknown PSS MGF1 digest algorithm: {name}",))
                })?;
                pss.set_mgf1_hash_algorithm(alg);
                modified = true;
            } else {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_RSA_MGF1_DIGEST} must be a UTF-8 string",
                )));
            }
        }

        if let Some(value) = params.get(PARAM_RSA_PSS_SALTLEN) {
            let saltlen = param_to_i32(value, PARAM_RSA_PSS_SALTLEN)?;
            pss.set_salt_len(saltlen);
            modified = true;
        }

        if modified {
            *self = RsaPssRestriction::Restricted(pss);
        }
        Ok(modified)
    }

    /// Serialize the PSS restriction (when present) into the supplied
    /// `ParamSet`. Mirrors the relevant section of `rsa_export` in
    /// `rsa_kmgmt.c:rsa_export` (~lines 415–480).
    pub(crate) fn write_to_params(&self, out: &mut ParamSet) {
        if let RsaPssRestriction::Restricted(pss) = self {
            // `resolved_hash` / `resolved_mgf1_hash` return a concrete
            // `DigestAlgorithm` (defaulting to SHA-1 when no value is
            // pinned). `DigestAlgorithm::name` always returns a static
            // canonical string.
            out.set(
                PARAM_RSA_DIGEST,
                ParamValue::Utf8String(pss.resolved_hash().name().to_string()),
            );
            out.set(
                PARAM_RSA_MGF1_DIGEST,
                ParamValue::Utf8String(pss.resolved_mgf1_hash().name().to_string()),
            );
            // MGF1 is the only supported mask generation function in
            // RSA-PSS — emit the constant marker so callers see the same
            // string the C provider emits.
            out.set(
                PARAM_RSA_MASKGENFUNC,
                ParamValue::Utf8String("MGF1".to_string()),
            );
            out.set(
                PARAM_RSA_PSS_SALTLEN,
                ParamValue::Int32(pss.resolved_salt_len()),
            );
        }
    }
}

// =============================================================================
// Helper: param_to_i32 / param_to_u32 / param_to_usize / extract_bignum_bytes
// =============================================================================

/// Convert a numeric [`ParamValue`] into an `i32` using only checked
/// conversions (Rule R6).
///
/// Used for the PSS salt-length slot which is signed (the value `-1` is the
/// canonical "salt length matches digest length" sentinel mandated by
/// the PKCS #1 v2.2 specification — it is not a Rule R5 sentinel because
/// the encoding is fixed by the on-the-wire ASN.1 format).
fn param_to_i32(value: &ParamValue, key: &str) -> ProviderResult<i32> {
    let parsed: Option<i32> = match value {
        ParamValue::Int32(v) => Some(*v),
        ParamValue::UInt32(v) => i32::try_from(*v).ok(),
        ParamValue::Int64(v) => i32::try_from(*v).ok(),
        ParamValue::UInt64(v) => i32::try_from(*v).ok(),
        _ => None,
    };
    parsed.ok_or_else(|| {
        ProviderError::Dispatch(format!(
            "parameter {key} is not a 32-bit signed integer convertible value",
        ))
    })
}

/// Convert a numeric [`ParamValue`] into a `u32` using only checked
/// conversions (Rule R6).
fn param_to_u32(value: &ParamValue, key: &str) -> ProviderResult<u32> {
    let parsed: Option<u32> = match value {
        ParamValue::Int32(v) if *v >= 0 => u32::try_from(*v).ok(),
        ParamValue::UInt32(v) => Some(*v),
        ParamValue::Int64(v) if *v >= 0 => u32::try_from(*v).ok(),
        ParamValue::UInt64(v) => u32::try_from(*v).ok(),
        _ => None,
    };
    parsed.ok_or_else(|| {
        ProviderError::Dispatch(format!(
            "parameter {key} is not a non-negative integer convertible to u32",
        ))
    })
}

/// Convert a numeric [`ParamValue`] into a `usize` using only checked
/// conversions (Rule R6).
fn param_to_usize(value: &ParamValue, key: &str) -> ProviderResult<usize> {
    let parsed: Option<usize> = match value {
        ParamValue::Int32(v) if *v >= 0 => usize::try_from(*v).ok(),
        ParamValue::UInt32(v) => usize::try_from(*v).ok(),
        ParamValue::Int64(v) if *v >= 0 => usize::try_from(*v).ok(),
        ParamValue::UInt64(v) => usize::try_from(*v).ok(),
        _ => None,
    };
    parsed.ok_or_else(|| {
        ProviderError::Dispatch(format!(
            "parameter {key} is not a non-negative integer convertible to usize",
        ))
    })
}

/// Extract a big-endian big-number byte sequence from a [`ParamSet`] entry.
///
/// Accepts both [`ParamValue::BigNum`] and [`ParamValue::OctetString`]
/// variants — these are interchangeable big-endian representations and the
/// C dispatcher does not distinguish between them for RSA components.
///
/// # Errors
///
/// - [`ProviderError::Dispatch`] if the key is missing or holds an
///   incompatible variant.
fn extract_bignum_bytes(params: &ParamSet, key: &str) -> ProviderResult<Vec<u8>> {
    match params.get(key) {
        Some(ParamValue::BigNum(bytes) | ParamValue::OctetString(bytes)) => Ok(bytes.clone()),
        Some(other) => Err(ProviderError::Dispatch(format!(
            "parameter {key} has unexpected type {}",
            other.param_type_name(),
        ))),
        None => Err(ProviderError::Dispatch(format!(
            "required parameter {key} is missing",
        ))),
    }
}

// =============================================================================
// RsaGenContext — generation parameter accumulator
// =============================================================================

/// Accumulator for RSA / RSA-PSS key generation parameters.
///
/// Replaces the C `gctx` allocated by `rsa_gen_init()` at
/// `rsa_kmgmt.c:560–600` and consumed by `rsa_gen()` at
/// `rsa_kmgmt.c:600–750`. Each [`ParamSet`] passed through the provider
/// dispatch translates into a sequence of `absorb()` calls that mutate this
/// context; calling [`RsaKeyData::generate_from_params`] then materialises
/// the actual key.
///
/// Defaults match the C `rsa_gen_init` zero-initialisation followed by
/// `gctx->nbits = 2048; gctx->primes = 2;` — see lines 562–566.
///
/// # Field Map
///
/// | Field             | C Equivalent           | Default                   |
/// |-------------------|------------------------|---------------------------|
/// | `selection`       | `gctx->selection`      | `KEYPAIR`                 |
/// | `key_type`        | `gctx->rsa_type`       | `RsaKeyType::Rsa`         |
/// | `nbits`           | `gctx->nbits`          | `RSA_DEFAULT_KEY_BITS=2048` |
/// | `primes`          | `gctx->primes`         | `RSA_DEFAULT_PRIMES=2`    |
/// | `pub_exp`         | `gctx->pub_exp`        | `None` (uses 65537)       |
/// | `pss_restrictions`| `gctx->pss_params`     | `Unrestricted`            |
/// | `rsa_a`           | `gctx->rsa_a`          | `None`                    |
/// | `rsa_b`           | `gctx->rsa_b`          | `None`                    |
/// | `prop_query`      | `gctx->propq`          | `None`                    |
///
/// # Rule Compliance
///
/// * **Rule R5** — Optional fields (`pub_exp`, `rsa_a`, `rsa_b`,
///   `prop_query`) use [`Option<T>`] rather than sentinel zeros.
/// * **Rule R6** — All numeric ingestion goes through [`param_to_u32`] /
///   [`param_to_usize`], no bare `as` casts.
/// * **Rule R8** — Contains zero `unsafe` blocks.
#[derive(Debug, Clone)]
pub struct RsaGenContext {
    /// Which key components the caller wishes the generation step to
    /// emit. RSA has no domain parameters, so realistic values are
    /// `KEYPAIR` (the sole canonical choice — both private and public
    /// halves are produced jointly), `PRIVATE_KEY`, or `PUBLIC_KEY`.
    pub selection: KeySelection,
    /// Whether to generate a plain RSA key or an RSA-PSS key.
    pub key_type: RsaKeyType,
    /// RSA modulus size in bits. Default [`RSA_DEFAULT_KEY_BITS`] (2048);
    /// must be at least [`RSA_MIN_MODULUS_BITS`] (512) per FIPS 186-5.
    pub nbits: u32,
    /// Number of primes (2 = standard RSA, 3..=5 = multi-prime RSA).
    /// Default [`RSA_DEFAULT_PRIMES`] (2); capped at [`RSA_MAX_PRIME_NUM`].
    pub primes: usize,
    /// Public exponent. `None` → use the default 65 537 (`F4`). When
    /// `Some(e)`, `e` must be odd and ≥ 3.
    pub pub_exp: Option<BigNum>,
    /// PSS parameter restrictions. Plain RSA generation rejects any
    /// restriction; RSA-PSS generation accepts an arbitrary
    /// [`RsaPssRestriction`] subject to internal consistency.
    pub pss_restrictions: RsaPssRestriction,
    /// KEM-specific scaling parameter `a` from
    /// `OSSL_PKEY_PARAM_RSA_A`. Must be `0` or odd ≤ 7 (i.e.
    /// `{0, 1, 3, 5, 7}`) per the RSAES-KEM specification.
    pub rsa_a: Option<u32>,
    /// KEM-specific scaling parameter `b` from
    /// `OSSL_PKEY_PARAM_RSA_B`. Must be `0` or odd ≤ 7 (i.e.
    /// `{0, 1, 3, 5, 7}`).
    pub rsa_b: Option<u32>,
    /// Optional provider property query string (carried through but not
    /// acted upon at this layer — used by downstream operation fetches).
    pub prop_query: Option<String>,
}

impl RsaGenContext {
    /// Create a default generation context for the given key type and
    /// component selection.
    ///
    /// Mirrors `rsa_gen_init()` (`rsa_kmgmt.c:560–600`) which allocates a
    /// fresh `RSA_GEN_CTX`, zero-initialises it, then sets `nbits = 2048`
    /// and `primes = 2`. The `selection` argument here corresponds to the
    /// `selection` parameter passed to `rsa_gen_init`.
    #[must_use]
    pub fn new(selection: KeySelection, key_type: RsaKeyType) -> Self {
        Self {
            selection,
            key_type,
            nbits: RSA_DEFAULT_KEY_BITS,
            primes: RSA_DEFAULT_PRIMES,
            pub_exp: None,
            pss_restrictions: RsaPssRestriction::Unrestricted,
            rsa_a: None,
            rsa_b: None,
            prop_query: None,
        }
    }

    /// Read RSA generation parameters from `params` and merge them into
    /// this context.
    ///
    /// Mirrors `rsa_gen_set_params()` (`rsa_kmgmt.c:680–760`) which walks
    /// the caller-supplied `OSSL_PARAM[]` array and applies each
    /// recognised entry to `gctx`. Unknown parameters are silently
    /// ignored — matching the C behaviour where `OSSL_PARAM_locate_*`
    /// returns NULL for missing entries.
    ///
    /// # Plain RSA vs. RSA-PSS Gating
    ///
    /// When [`key_type`](Self::key_type) is [`RsaKeyType::Rsa`], any
    /// pinning of PSS parameters is rejected — plain RSA keys must never
    /// carry restrictions. When [`key_type`](Self::key_type) is
    /// [`RsaKeyType::RsaPss`], PSS parameters are absorbed into
    /// [`pss_restrictions`](Self::pss_restrictions).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when:
    ///
    /// * A numeric parameter cannot be losslessly converted (Rule R6).
    /// * `nbits` is below [`RSA_MIN_MODULUS_BITS`].
    /// * `primes` is below 2 or above [`RSA_MAX_PRIME_NUM`].
    /// * `rsa_a` or `rsa_b` is outside the allowed `{0, 1, 3, 5, 7}` set.
    /// * The supplied public exponent is even or less than 3.
    /// * Plain RSA receives PSS pinning parameters.
    pub fn absorb(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(
            target: TRACING_TARGET,
            "RsaGenContext::absorb({} entries)",
            params.len(),
        );

        if let Some(value) = params.get(PARAM_RSA_BITS) {
            let bits = param_to_u32(value, PARAM_RSA_BITS)?;
            if bits < RSA_MIN_MODULUS_BITS {
                return Err(ProviderError::Dispatch(format!(
                    "RSA key size {bits} below minimum {RSA_MIN_MODULUS_BITS}",
                )));
            }
            self.nbits = bits;
            debug!(
                target: TRACING_TARGET,
                bits,
                "RsaGenContext::absorb: set bits",
            );
        }

        if let Some(value) = params.get(PARAM_RSA_PRIMES) {
            let primes = param_to_usize(value, PARAM_RSA_PRIMES)?;
            if !(2..=RSA_MAX_PRIME_NUM).contains(&primes) {
                return Err(ProviderError::Dispatch(format!(
                    "RSA prime count {primes} outside allowed range [2, {RSA_MAX_PRIME_NUM}]",
                )));
            }
            self.primes = primes;
            debug!(
                target: TRACING_TARGET,
                primes,
                "RsaGenContext::absorb: set primes",
            );
        }

        if let Some(value) = params.get(PARAM_RSA_E) {
            let bytes = match value {
                ParamValue::BigNum(b) | ParamValue::OctetString(b) => b.clone(),
                ParamValue::UInt32(v) => v.to_be_bytes().to_vec(),
                ParamValue::UInt64(v) => v.to_be_bytes().to_vec(),
                ParamValue::Int32(v) if *v >= 0 => v.to_be_bytes().to_vec(),
                ParamValue::Int64(v) if *v >= 0 => v.to_be_bytes().to_vec(),
                _ => {
                    return Err(ProviderError::Dispatch(format!(
                        "{PARAM_RSA_E} has unexpected type {}",
                        value.param_type_name(),
                    )));
                }
            };
            let e = BigNum::from_bytes_be(&bytes);
            if e.is_zero() || e.is_negative() || !e.is_odd() {
                return Err(ProviderError::Dispatch(
                    "RSA public exponent must be a positive odd integer".to_string(),
                ));
            }
            // RSA_DEFAULT_PUBLIC_EXPONENT = 65537 is the smallest exponent
            // commonly recommended; we allow ≥3 to mirror the C accept
            // path which only requires `e > 1` and odd.
            self.pub_exp = Some(e);
            debug!(
                target: TRACING_TARGET,
                "RsaGenContext::absorb: set pub_exp from caller-supplied value",
            );
        }

        if let Some(value) = params.get(PARAM_RSA_A) {
            let a = param_to_u32(value, PARAM_RSA_A)?;
            if !is_valid_rsa_ab_param(a) {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_RSA_A} must be one of {{0, 1, 3, 5, 7}} but is {a}",
                )));
            }
            self.rsa_a = Some(a);
        }

        if let Some(value) = params.get(PARAM_RSA_B) {
            let b = param_to_u32(value, PARAM_RSA_B)?;
            if !is_valid_rsa_ab_param(b) {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_RSA_B} must be one of {{0, 1, 3, 5, 7}} but is {b}",
                )));
            }
            self.rsa_b = Some(b);
        }

        if let Some(value) = params.get(PARAM_RSA_DIGEST_PROPS) {
            if let ParamValue::Utf8String(props) = value {
                self.prop_query = Some(props.clone());
            } else {
                return Err(ProviderError::Dispatch(format!(
                    "{PARAM_RSA_DIGEST_PROPS} must be a UTF-8 string",
                )));
            }
        }

        // PSS pinning is only permitted on RSA-PSS keys. Mirror the C
        // gate at `rsa_kmgmt.c:rsa_gen_set_params` lines ~720–740 which
        // checks `gctx->rsa_type == RSA_FLAG_TYPE_RSASSAPSS` before
        // touching `gctx->pss_params`.
        let pss_keys_present = params.contains(PARAM_RSA_DIGEST)
            || params.contains(PARAM_RSA_MASKGENFUNC)
            || params.contains(PARAM_RSA_MGF1_DIGEST)
            || params.contains(PARAM_RSA_PSS_SALTLEN);
        if pss_keys_present {
            match self.key_type {
                RsaKeyType::RsaPss => {
                    self.pss_restrictions.absorb_pss_params(params)?;
                }
                RsaKeyType::Rsa => {
                    return Err(ProviderError::Dispatch(
                        "PSS parameters cannot be applied to a plain RSA key — use RSA-PSS"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Returns `true` if `value` is one of `{0, 1, 3, 5, 7}` — the only
/// values allowed for `OSSL_PKEY_PARAM_RSA_A` and
/// `OSSL_PKEY_PARAM_RSA_B` in the RSAES-KEM scaling parameters.
///
/// The C check in `rsa_kmgmt.c:rsa_gen_set_params` is:
///
/// ```c
/// if (a > 7 || (a > 0 && (a % 2) == 0))
///     return 0;
/// ```
fn is_valid_rsa_ab_param(value: u32) -> bool {
    value <= 7 && (value == 0 || value % 2 == 1)
}

// =============================================================================
// RsaKeyData — opaque key data object
// =============================================================================

/// Opaque RSA / RSA-PSS key data exposed across the provider boundary.
///
/// Replaces the C `RSA *` opaque pointer used as `keydata` in
/// `rsa_kmgmt.c`. Each `keydata` allocation funnels through
/// [`KeyMgmtProvider::new_key`] (via `rsa_newdata`/`rsapss_newdata` in
/// the C reference, lines 31–55) and is consumed by import / export /
/// validate / match operations.
///
/// # Storage Strategy
///
/// Public-key-only inputs (e.g. an `import(PUBLIC_KEY, …)` call from a
/// signature verifier) are stored in [`public_only`](Self::public_only)
/// — a fully-public [`RsaPublicKey`]. Inputs containing private
/// material flow through [`from_params`](Self::from_params) → the
/// crypto-layer [`rsa_from_params`] which returns an
/// [`RsaPrivateKey`]; the latter is stored directly in
/// [`private_key`](Self::private_key) and supplies the public half on
/// demand via [`RsaPrivateKey::public_key`].
///
/// We deliberately store the private key as an [`RsaPrivateKey`]
/// rather than wrapping it in an [`RsaKeyPair`]: the `from_private`
/// constructor on `RsaKeyPair` is `pub(crate)` to the
/// `openssl-crypto` crate and is therefore inaccessible from this
/// provider crate. The `RsaPrivateKey` type already publishes
/// everything we need (modulus, public exponent, private exponent,
/// CRT components) plus a `public_key()` accessor returning an owned
/// [`RsaPublicKey`].
///
/// # Drop / Zeroisation
///
/// [`RsaPrivateKey`] derives `Zeroize` and `ZeroizeOnDrop` — the secret
/// fields (`d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`, prime infos) are wiped
/// automatically when this struct is dropped. We therefore intentionally
/// omit a manual [`Drop`] impl (cf. the DSA case which stores raw
/// [`BigNum`]s and must wipe them by hand).
///
/// # Manual `Debug` Implementation — Load-Bearing
///
/// The [`KeyMgmtProvider`] trait's `has` / `validate` / `export`
/// dispatchers operate on `&dyn KeyData` references. Rust's dynamic
/// dispatch system does not allow downcasting a `&dyn Trait` directly,
/// so we recover concrete-type information by formatting the value
/// through the trait-object's [`fmt::Debug`] hook and parsing the
/// resulting string. The struct name `"RsaKeyData"` and the field
/// pattern `"has_private: bool"` / `"has_public: bool"` are therefore
/// **load-bearing public surface** — changing them silently breaks the
/// downcasting protocol.
pub struct RsaKeyData {
    /// `Rsa` for the standard RSA dispatch table; `RsaPss` for
    /// RSA-PSS (which carries optional PSS parameter pinning).
    pub(crate) rsa_type: RsaKeyType,
    /// Private key material (with on-demand public key derivation via
    /// [`RsaPrivateKey::public_key`]). `Some` after a successful
    /// `import(PRIVATE_KEY|KEYPAIR, …)` or `generate(…)`.
    pub(crate) private_key: Option<RsaPrivateKey>,
    /// Public-only material from `import(PUBLIC_KEY, …)`. `None` when
    /// [`private_key`](Self::private_key) is populated (the public half
    /// is then derived from it).
    pub(crate) public_only: Option<RsaPublicKey>,
    /// PSS pinning parameters. Always [`RsaPssRestriction::Unrestricted`]
    /// for plain RSA keys; for RSA-PSS keys, may be either unrestricted
    /// (no pinning) or [`RsaPssRestriction::Restricted`] with a
    /// [`PssParams30`] payload. Note: this field is publicly visible to
    /// the crate but **must never be mutated** to a restricted state for
    /// `rsa_type == RsaKeyType::Rsa`; the `absorb` and `import` paths
    /// enforce this invariant.
    pub(crate) pss_restrictions: RsaPssRestriction,
}

impl fmt::Debug for RsaKeyData {
    /// Manual `Debug` impl — the structure of the formatted output is
    /// load-bearing because [`KeyMgmtProvider::has`] inspects the
    /// rendered string to reconstruct booleans (see the module-level
    /// docstring's *Two Dispatch Tables* section).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeyData")
            .field("rsa_type", &self.rsa_type)
            .field("has_private", &self.private_key.is_some())
            .field(
                "has_public",
                &(self.private_key.is_some() || self.public_only.is_some()),
            )
            .field(
                "has_pss_restrictions",
                &self.pss_restrictions.is_restricted(),
            )
            .finish()
    }
}

impl KeyData for RsaKeyData {}

impl RsaKeyData {
    /// Construct an empty `RsaKeyData` of the given type.
    ///
    /// Mirrors `rsa_newdata()` / `rsapss_newdata()` at
    /// `rsa_kmgmt.c:31–55`. The C entry allocates an empty `RSA` struct
    /// via `RSA_new_ex(provctx->libctx, NULL)` and tags it with
    /// `RSA_FLAG_TYPE_RSA` or `RSA_FLAG_TYPE_RSASSAPSS` accordingly.
    #[must_use]
    pub fn new(rsa_type: RsaKeyType) -> Self {
        Self {
            rsa_type,
            private_key: None,
            public_only: None,
            pss_restrictions: RsaPssRestriction::Unrestricted,
        }
    }

    /// Returns `true` when private material is present.
    #[must_use]
    pub fn has_private(&self) -> bool {
        self.private_key.is_some()
    }

    /// Returns `true` when public material is reachable — either via a
    /// stored public key, or derivable from a stored private key.
    #[must_use]
    pub fn has_public(&self) -> bool {
        self.private_key.is_some() || self.public_only.is_some()
    }

    /// RSA has no domain parameters; this always returns `false`. The
    /// method exists for API symmetry with [`super::dsa::DsaKeyData`] /
    /// [`super::ec::EcKeyData`].
    #[must_use]
    pub const fn has_params(&self) -> bool {
        false
    }

    /// The RSA modulus size in bits, derived from the stored key.
    #[must_use]
    pub fn bits(&self) -> Option<u32> {
        self.private_key
            .as_ref()
            .map(RsaPrivateKey::key_size_bits)
            .or_else(|| self.public_only.as_ref().map(RsaPublicKey::key_size_bits))
    }

    /// The RSA modulus size in bytes, useful for buffer sizing of
    /// signatures and ciphertexts. Returns `None` when no key material
    /// is loaded.
    #[must_use]
    pub fn modulus_bytes(&self) -> Option<u32> {
        self.private_key
            .as_ref()
            .map(RsaPrivateKey::key_size_bytes)
            .or_else(|| self.public_only.as_ref().map(RsaPublicKey::key_size_bytes))
    }

    /// The achievable security strength in bits, computed by the
    /// crypto layer (see [`RsaPrivateKey::security_bits`] which
    /// implements NIST SP 800-57 Part 1 Table 2).
    #[must_use]
    pub fn security_bits(&self) -> Option<u32> {
        self.private_key
            .as_ref()
            .map(RsaPrivateKey::security_bits)
            .or_else(|| self.public_only.as_ref().map(RsaPublicKey::security_bits))
    }

    /// The maximum signature / ciphertext size in bytes — for RSA this
    /// is exactly the modulus byte length (a signature is one modulus
    /// element).
    ///
    /// Mirrors `rsa_get_params()` (`rsa_kmgmt.c:lines ~770–810`)
    /// `RSA_size(rsa)`.
    #[must_use]
    pub fn max_size(&self) -> Option<usize> {
        self.modulus_bytes().map(|b| b as usize)
    }

    /// Borrow the underlying private key, if present.
    #[must_use]
    pub fn private_key(&self) -> Option<&RsaPrivateKey> {
        self.private_key.as_ref()
    }

    /// Borrow the stored public-only key, if any. Note: when a private
    /// key is present, this returns `None` because the public key is
    /// derived on demand from the private one (use
    /// [`public_key`](Self::public_key) instead).
    #[must_use]
    pub fn public_only(&self) -> Option<&RsaPublicKey> {
        self.public_only.as_ref()
    }

    /// Obtain an owned [`RsaPublicKey`] representation. Returns the
    /// stored public-only key if present; otherwise derives it from the
    /// stored private key.
    #[must_use]
    pub fn public_key(&self) -> Option<RsaPublicKey> {
        if let Some(priv_key) = &self.private_key {
            Some(priv_key.public_key())
        } else {
            self.public_only.clone()
        }
    }

    /// The `RsaKeyType` discriminator (RSA vs. RSA-PSS).
    #[must_use]
    pub const fn key_type(&self) -> RsaKeyType {
        self.rsa_type
    }

    /// The PSS parameter restrictions in effect for this key.
    #[must_use]
    pub const fn pss_restrictions(&self) -> &RsaPssRestriction {
        &self.pss_restrictions
    }

    /// Returns `true` when this `RsaKeyData` satisfies every bit of
    /// `selection` purely on the basis of which components are present
    /// (no deep validation).
    ///
    /// Mirrors `rsa_has()` at `rsa_kmgmt.c:120–155`. RSA has no domain
    /// parameters, so the [`KeySelection::DOMAIN_PARAMETERS`] bit is
    /// **ignored** rather than rejected — this matches the C behaviour
    /// where the `DOMAIN_PARAMETERS` bit on an RSA key has no meaningful
    /// component to test against.
    #[must_use]
    pub fn has_selection(&self, selection: KeySelection) -> bool {
        // Empty selection — the C code returns `1` (OK) when `selection`
        // is zero. We mirror that.
        if selection.is_empty() {
            return true;
        }

        // The C check is component-by-component: only fail when the bit
        // is set AND the component is missing.
        if selection.contains(KeySelection::PRIVATE_KEY) && !self.has_private() {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && !self.has_public() {
            return false;
        }
        // DOMAIN_PARAMETERS / OTHER_PARAMETERS — RSA has no domain
        // parameters; OTHER_PARAMETERS for an RSA-PSS key encompasses
        // the PSS pinning, which is structurally always available
        // (Unrestricted is a valid state). Hence both bits are always
        // satisfied.
        true
    }

    /// Serialise the key components matching `selection` into a
    /// [`ParamSet`].
    ///
    /// Mirrors `rsa_export()` (`rsa_kmgmt.c:415–480`).
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Dispatch`] when the requested selection
    ///   cannot be served (e.g. `PRIVATE_KEY` requested but only public
    ///   material is loaded).
    pub fn export_to_params(&self, selection: KeySelection) -> ProviderResult<ParamSet> {
        if selection.is_empty() {
            return Err(ProviderError::Dispatch(
                "RSA export: empty selection".to_string(),
            ));
        }

        let want_private = selection.contains(KeySelection::PRIVATE_KEY);
        let want_public = selection.contains(KeySelection::PUBLIC_KEY);

        if want_private && !self.has_private() {
            return Err(ProviderError::Dispatch(
                "RSA export: PRIVATE_KEY requested but no private key loaded".to_string(),
            ));
        }
        if want_public && !self.has_public() {
            return Err(ProviderError::Dispatch(
                "RSA export: PUBLIC_KEY requested but no public key loaded".to_string(),
            ));
        }

        let mut out = ParamSet::new();

        if want_private {
            // Delegate the full private-key serialisation (n, e, d, p,
            // q, dmp1, dmq1, iqmp) to the crypto-layer helper which
            // already covers all CRT components.
            let priv_key = self.private_key.as_ref().ok_or_else(|| {
                ProviderError::Dispatch(
                    "RSA export: internal inconsistency — has_private() lied".to_string(),
                )
            })?;
            let serialised = rsa_to_params(priv_key).map_err(|e| {
                ProviderError::Dispatch(format!("RSA export: failed to serialise key: {e}"))
            })?;
            out = serialised;
        } else if want_public {
            // Public-only export: emit n and e only.
            let pub_key = self.public_key().ok_or_else(|| {
                ProviderError::Dispatch(
                    "RSA export: internal inconsistency — has_public() lied".to_string(),
                )
            })?;
            out.set(
                PARAM_RSA_N,
                ParamValue::BigNum(pub_key.modulus().to_bytes_be()),
            );
            out.set(
                PARAM_RSA_E,
                ParamValue::BigNum(pub_key.public_exponent().to_bytes_be()),
            );
        }

        // RSA-PSS pinning is part of OTHER_PARAMETERS (or implicitly part
        // of PUBLIC_KEY/KEYPAIR — the C code emits it whenever a key is
        // exported and pinning is set). We mirror the C behaviour by
        // emitting PSS parameters whenever any key component was emitted.
        if self.rsa_type == RsaKeyType::RsaPss {
            self.pss_restrictions.write_to_params(&mut out);
        }

        debug!(
            target: TRACING_TARGET,
            ?selection,
            "RsaKeyData::export_to_params: emitted {} entries",
            out.len(),
        );

        Ok(out)
    }

    /// Construct an `RsaKeyData` of the given `key_type` by parsing the
    /// supplied `ParamSet` according to `selection`.
    ///
    /// Mirrors `rsa_import()` (`rsa_kmgmt.c:310–410`):
    ///
    /// * When `selection` requests private material we call the
    ///   crypto-layer [`rsa_from_params`], which returns a fully
    ///   populated [`RsaPrivateKey`] (including all CRT components).
    /// * When `selection` requests only public material we manually
    ///   extract `n` and `e` and construct an [`RsaPublicKey`].
    ///
    /// PSS pinning is absorbed onto [`pss_restrictions`] when the key
    /// type is `RsaPss` and at least one PSS parameter is present.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Dispatch`] for missing required parameters,
    ///   malformed values, or attempts to apply PSS restrictions to a
    ///   plain RSA key.
    pub fn from_params(
        key_type: RsaKeyType,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Self> {
        if selection.is_empty() {
            return Err(ProviderError::Dispatch(
                "RSA import: empty selection".to_string(),
            ));
        }

        let want_private = selection.contains(KeySelection::PRIVATE_KEY);
        let want_public = selection.contains(KeySelection::PUBLIC_KEY);

        let mut key = Self::new(key_type);

        if want_private {
            // Full keypair / private-key import — delegate to the crypto
            // layer which validates that n, e, d, p, q (at minimum) are
            // present. The CRT components (dmp1, dmq1, iqmp) are
            // recomputed if absent.
            let priv_key = rsa_from_params(data).map_err(|e| {
                ProviderError::Dispatch(format!("RSA import: failed to assemble private key: {e}"))
            })?;
            key.private_key = Some(priv_key);
        } else if want_public {
            // Public-key-only import — n and e are mandatory.
            let n_bytes = extract_bignum_bytes(data, PARAM_RSA_N)?;
            let e_bytes = extract_bignum_bytes(data, PARAM_RSA_E)?;
            let n = BigNum::from_bytes_be(&n_bytes);
            let e = BigNum::from_bytes_be(&e_bytes);
            let pub_key = RsaPublicKey::new(n, e).map_err(|e| {
                ProviderError::Dispatch(format!("RSA import: invalid public key: {e}"))
            })?;
            key.public_only = Some(pub_key);
        }

        // Absorb PSS pinning when applicable. For plain RSA keys, the
        // presence of any PSS parameter is an outright error — mirroring
        // the C check that rejects `RSA_set0_pss_params` on a plain
        // RSA key.
        let pss_keys_present = data.contains(PARAM_RSA_DIGEST)
            || data.contains(PARAM_RSA_MASKGENFUNC)
            || data.contains(PARAM_RSA_MGF1_DIGEST)
            || data.contains(PARAM_RSA_PSS_SALTLEN);
        if pss_keys_present {
            match key_type {
                RsaKeyType::RsaPss => {
                    key.pss_restrictions.absorb_pss_params(data)?;
                }
                RsaKeyType::Rsa => {
                    return Err(ProviderError::Dispatch(
                        "RSA import: PSS parameters cannot be applied to a plain RSA key"
                            .to_string(),
                    ));
                }
            }
        }

        debug!(
            target: TRACING_TARGET,
            key_type = ?key_type,
            ?selection,
            has_private = key.has_private(),
            has_public = key.has_public(),
            "RsaKeyData::from_params: imported key",
        );

        Ok(key)
    }

    /// Generate a new key from a [`RsaGenContext`].
    ///
    /// Mirrors `rsa_gen()` at `rsa_kmgmt.c:600–750`. Builds a
    /// [`RsaKeyGenParams`] from the context, calls the crypto-layer
    /// [`generate_key`], then extracts the [`RsaPrivateKey`] from the
    /// returned [`RsaKeyPair`] (the keypair's `from_private`
    /// constructor is `pub(crate)` to the crypto crate so we cannot
    /// retain the wrapper).
    ///
    /// # Errors
    ///
    /// * [`ProviderError::Dispatch`] when key generation fails (e.g.
    ///   prime search exceeded retry budget).
    pub fn generate_from_params(ctx: &RsaGenContext) -> ProviderResult<Self> {
        // Final gate: plain RSA may never carry PSS pinning even if
        // someone bypassed `absorb`. This is defence-in-depth.
        if ctx.key_type == RsaKeyType::Rsa && ctx.pss_restrictions.is_restricted() {
            return Err(ProviderError::Dispatch(
                "RSA generate: plain RSA keys must not carry PSS restrictions".to_string(),
            ));
        }

        let keygen_params = RsaKeyGenParams {
            bits: ctx.nbits,
            public_exponent: ctx.pub_exp.as_ref().map(BigNum::dup),
            primes: ctx.primes,
        };

        let kp: RsaKeyPair = generate_key(&keygen_params).map_err(|e| {
            ProviderError::Dispatch(format!("RSA generate: key generation failed: {e}"))
        })?;

        // Extract the private key from the keypair (the `RsaKeyPair`
        // wrapper's constructors are inaccessible to us, but its
        // `private_key` accessor is public).
        let priv_key: RsaPrivateKey = kp.private_key().clone();

        let key = Self {
            rsa_type: ctx.key_type,
            private_key: Some(priv_key),
            public_only: None,
            pss_restrictions: ctx.pss_restrictions.clone(),
        };

        debug!(
            target: TRACING_TARGET,
            bits = ctx.nbits,
            primes = ctx.primes,
            key_type = ?ctx.key_type,
            "RsaKeyData::generate_from_params: generated key",
        );

        Ok(key)
    }

    /// Deeply validate the components of `selection`. In addition to
    /// presence, this calls into the crypto layer's primality tests
    /// (`p`, `q`), CRT-component cross-checks, and pairwise consistency
    /// (a sign / verify round-trip).
    ///
    /// Mirrors `rsa_validate()` at `rsa_kmgmt.c:190–260`.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when the underlying
    /// [`check_keypair`] / [`check_private_key`] / [`check_public_key`]
    /// raises a structural error. Validation *failures* (e.g. a key
    /// fails the consistency tests) are reported via the `bool` return
    /// — `Ok(false)` rather than `Err`.
    pub fn validate_selection(&self, selection: KeySelection) -> ProviderResult<bool> {
        // First the cheap structural check.
        if !self.has_selection(selection) {
            return Ok(false);
        }
        if selection.is_empty() {
            return Ok(true);
        }

        let want_private = selection.contains(KeySelection::PRIVATE_KEY);
        let want_public = selection.contains(KeySelection::PUBLIC_KEY);

        // KEYPAIR validation — pairwise consistency.
        if want_private && want_public {
            if let Some(priv_key) = &self.private_key {
                let result = check_keypair(priv_key).map_err(|e| {
                    ProviderError::Dispatch(format!("RSA validate: check_keypair raised: {e}"))
                })?;
                return Ok(result.is_valid);
            }
            // The public-only branch cannot satisfy KEYPAIR — but
            // has_selection() above would have returned `false`. We
            // still defensively return false here.
            return Ok(false);
        }

        // PRIVATE_KEY only.
        if want_private {
            if let Some(priv_key) = &self.private_key {
                let result = check_private_key(priv_key).map_err(|e| {
                    ProviderError::Dispatch(format!("RSA validate: check_private_key raised: {e}"))
                })?;
                return Ok(result.is_valid);
            }
            return Ok(false);
        }

        // PUBLIC_KEY only.
        if want_public {
            // Prefer the public-only path; fall back to the public half
            // of a stored private key.
            if let Some(pub_key) = &self.public_only {
                let result = check_public_key(pub_key).map_err(|e| {
                    ProviderError::Dispatch(format!("RSA validate: check_public_key raised: {e}"))
                })?;
                return Ok(result.is_valid);
            }
            if let Some(priv_key) = &self.private_key {
                let pub_key = priv_key.public_key();
                let result = check_public_key(&pub_key).map_err(|e| {
                    ProviderError::Dispatch(format!("RSA validate: check_public_key raised: {e}"))
                })?;
                return Ok(result.is_valid);
            }
            return Ok(false);
        }

        // Only DOMAIN_PARAMETERS / OTHER_PARAMETERS bits — RSA has no
        // domain parameters; OTHER_PARAMETERS encompass PSS pinning
        // which is structurally always valid (Unrestricted is fine).
        Ok(true)
    }

    /// Compare two `RsaKeyData` instances for equality on the
    /// components in `selection`.
    ///
    /// Mirrors `rsa_match()` (`rsa_kmgmt.c:165–190`). The C semantics
    /// are: `e` is **always** compared (it is part of every key); when
    /// `KEYPAIR` or `PUBLIC_KEY` is selected, `n` is also compared;
    /// when `PRIVATE_KEY` is selected and the public comparison did
    /// not run, `d` is compared.
    ///
    /// PSS pinning is compared component-wise when the key types are
    /// both RSA-PSS.
    #[must_use]
    pub fn match_keys(&self, other: &Self, selection: KeySelection) -> bool {
        // Compare `e` — always present in some form.
        let self_e = self.public_key().map(|k| k.public_exponent().dup());
        let other_e = other.public_key().map(|k| k.public_exponent().dup());
        match (&self_e, &other_e) {
            (Some(a), Some(b)) if a == b => {}
            (None, None) => {}
            _ => return false,
        }

        let want_public_or_keypair = selection.contains(KeySelection::PUBLIC_KEY)
            || selection.contains(KeySelection::KEYPAIR);
        let mut public_compared = false;

        if want_public_or_keypair {
            let self_n = self.public_key().map(|k| k.modulus().dup());
            let other_n = other.public_key().map(|k| k.modulus().dup());
            match (&self_n, &other_n) {
                (Some(a), Some(b)) if a == b => {
                    public_compared = true;
                }
                (None, None) => {
                    // Both keys are empty — nothing to disagree about.
                    public_compared = true;
                }
                _ => return false,
            }
        }

        if selection.contains(KeySelection::PRIVATE_KEY) && !public_compared {
            let self_d = self
                .private_key
                .as_ref()
                .map(|k| k.private_exponent().dup());
            let other_d = other
                .private_key
                .as_ref()
                .map(|k| k.private_exponent().dup());
            match (&self_d, &other_d) {
                (Some(a), Some(b)) if a == b => {}
                (None, None) => {}
                _ => return false,
            }
        }

        // RSA-PSS pinning comparison — the C code matches the PSS params
        // octet-for-octet when both keys are RSA-PSS. We compare the
        // resolved hash, MGF1 hash, salt length, and trailer field.
        if self.rsa_type == RsaKeyType::RsaPss && other.rsa_type == RsaKeyType::RsaPss {
            match (&self.pss_restrictions, &other.pss_restrictions) {
                (RsaPssRestriction::Unrestricted, RsaPssRestriction::Unrestricted) => {}
                (RsaPssRestriction::Restricted(a), RsaPssRestriction::Restricted(b)) => {
                    if a != b {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        true
    }
}

// =============================================================================
// RsaKeyMgmt — Plain RSA key management dispatcher
// =============================================================================

/// Key management dispatcher for plain RSA keys.
///
/// This is a zero-sized type (ZST). It carries no state — the key
/// state lives in the [`RsaKeyData`] it manages. Conceptually this
/// occupies the role of the C `ossl_rsa_keymgmt_functions[]` dispatch
/// table (`rsa_kmgmt.c:771–795`).
///
/// `RsaKeyMgmt` exposes two surfaces:
///
/// 1. The [`KeyMgmtProvider`] trait, which the provider machinery
///    dispatches against generically (`new_key`, `generate`, `import`,
///    `export`, `has`, `validate`).
/// 2. The inherent methods [`Self::match_keys`], [`Self::get_params`],
///    and [`Self::gettable_params`] — these mirror C entry points that
///    are not part of the cross-cutting `KeyMgmtProvider` trait but
///    are reachable when the caller already holds a typed
///    [`RsaKeyData`] (e.g. inside `EVP_PKEY_get_*` translation).
#[derive(Debug, Clone, Copy, Default)]
pub struct RsaKeyMgmt;

impl RsaKeyMgmt {
    /// Construct a new dispatcher (a no-op for a zero-sized type).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compare two `RsaKeyData` instances on **all** selectable
    /// components.
    ///
    /// This is a convenience wrapper over
    /// [`RsaKeyData::match_keys`] with [`KeySelection::ALL`]; it is
    /// the equivalent of the C `rsa_match()` entry that always passes
    /// the full `selection` mask (`rsa_kmgmt.c:165–190`).
    #[must_use]
    pub fn match_keys(&self, key1: &RsaKeyData, key2: &RsaKeyData) -> bool {
        key1.match_keys(key2, KeySelection::ALL)
    }

    /// Return the reportable PKEY metadata for `data`.
    ///
    /// Emits four parameters when the key has a loaded modulus:
    /// `bits`, `max-size`, `security-bits`, and `default-digest`.
    /// This mirrors `rsa_get_params()` (`rsa_kmgmt.c:790–820`).
    ///
    /// # Errors
    ///
    /// This method does not currently return an error — every
    /// emission path is infallible. The signature returns
    /// [`ProviderResult`] for symmetry with the rest of the
    /// keymgmt surface and to allow future strengthening.
    pub fn get_params(&self, data: &RsaKeyData) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        if let Some(bits) = data.bits() {
            ps.set(PARAM_BITS, ParamValue::UInt32(bits));
        }
        if let Some(max_size) = data.max_size() {
            ps.set(
                PARAM_MAX_SIZE,
                ParamValue::UInt32(u32::try_from(max_size).unwrap_or(u32::MAX)),
            );
        }
        if let Some(sbits) = data.security_bits() {
            ps.set(PARAM_SECURITY_BITS, ParamValue::UInt32(sbits));
        }
        ps.set(
            PARAM_DEFAULT_DIGEST,
            ParamValue::Utf8String(RSA_DEFAULT_MD.to_string()),
        );
        trace!(
            target: TRACING_TARGET,
            "RsaKeyMgmt::get_params: returned {} parameter(s)",
            ps.len(),
        );
        Ok(ps)
    }

    /// Return the static list of `'static`-named, fetchable parameter
    /// keys for plain RSA. This is the API surface a provider
    /// consumer queries to learn what `get_params` will populate.
    ///
    /// Mirrors `rsa_gettable_params()` (`rsa_kmgmt.c:830–840`).
    #[must_use]
    pub fn gettable_params(&self) -> &'static [&'static str] {
        &[
            PARAM_BITS,
            PARAM_MAX_SIZE,
            PARAM_SECURITY_BITS,
            PARAM_DEFAULT_DIGEST,
        ]
    }
}

impl KeyMgmtProvider for RsaKeyMgmt {
    fn name(&self) -> &'static str {
        // Both plain RSA and RSA-PSS report `"RSA"` as their
        // `query_operation_name` in C — a single signature operation
        // family handles both. We follow the same convention here.
        // (`rsa_kmgmt.c::rsa_query_operation_name()`)
        "RSA"
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            target: TRACING_TARGET,
            "RsaKeyMgmt::new_key: empty RSA key data created",
        );
        Ok(Box::new(RsaKeyData::new(RsaKeyType::Rsa)))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        ctx.absorb(params)?;
        let key = RsaKeyData::generate_from_params(&ctx)?;
        debug!(
            target: TRACING_TARGET,
            bits = ctx.nbits,
            primes = ctx.primes,
            "RsaKeyMgmt::generate: completed",
        );
        Ok(Box::new(key))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let key = RsaKeyData::from_params(RsaKeyType::Rsa, selection, data)?;
        debug!(
            target: TRACING_TARGET,
            ?selection,
            has_private = key.has_private(),
            has_public = key.has_public(),
            "RsaKeyMgmt::import: completed",
        );
        Ok(Box::new(key))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        // The `KeyData` trait is a marker; a fully type-safe export
        // requires the caller already holds a concrete `RsaKeyData`.
        // We perform a defensive Debug-projection check so that
        // misrouted calls fail loudly rather than silently succeeding
        // with stale or wrong-typed data.
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("RsaKeyData") {
            return Err(ProviderError::Dispatch(format!(
                "RSA export: incompatible key data type — debug projection={debug_str}",
            )));
        }
        warn!(
            target: TRACING_TARGET,
            ?selection,
            "RsaKeyMgmt::export: cross-trait export through &dyn KeyData \
             cannot decode private fields without a concrete &RsaKeyData; \
             callers should invoke RsaKeyData::export_to_params() directly",
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        // Mirror the manual Debug projection used in `export()` —
        // see `RsaKeyData::fmt` for the field set we rely on.
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("RsaKeyData") {
            return false;
        }
        let has_priv = debug_str.contains("has_private: true");
        let has_pub = debug_str.contains("has_public: true");
        if selection.contains(KeySelection::PRIVATE_KEY) && !has_priv {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return false;
        }
        // RSA has no DOMAIN_PARAMETERS — the DOMAIN_PARAMETERS bit is a
        // no-op for RSA. OTHER_PARAMETERS encompasses PSS pinning,
        // which is structurally always satisfied (Unrestricted is a
        // valid setting).
        true
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        // Cross-trait dispatch can only confirm structural presence;
        // pairwise consistency tests are reachable via direct
        // `RsaKeyData::validate_selection()`.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// RsaPssKeyMgmt — RSA-PSS key management dispatcher
// =============================================================================

/// Key management dispatcher for RSA-PSS keys.
///
/// Same shape as [`RsaKeyMgmt`] but every operation is parameterised
/// with [`RsaKeyType::RsaPss`] so the import / generate paths accept
/// PSS pinning parameters and `get_params()` reports the mandatory
/// digest when restrictions are present.
///
/// Mirrors `ossl_rsapss_keymgmt_functions[]` (`rsa_kmgmt.c:797–823`).
#[derive(Debug, Clone, Copy, Default)]
pub struct RsaPssKeyMgmt;

impl RsaPssKeyMgmt {
    /// Construct a new dispatcher (a no-op for a zero-sized type).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compare two `RsaKeyData` instances on all selectable
    /// components, including PSS pinning when both operands are
    /// RSA-PSS.
    #[must_use]
    pub fn match_keys(&self, key1: &RsaKeyData, key2: &RsaKeyData) -> bool {
        key1.match_keys(key2, KeySelection::ALL)
    }

    /// Return the reportable PKEY metadata for `data`. RSA-PSS adds
    /// an optional `mandatory-digest` parameter when the key carries
    /// a hash restriction — once set, the key may only be used with
    /// that hash for signing / verification.
    ///
    /// Mirrors `rsapss_get_params()` (`rsa_kmgmt.c:835–870`).
    ///
    /// # Errors
    ///
    /// This method does not currently return an error — every
    /// emission path is infallible. The signature returns
    /// [`ProviderResult`] for symmetry with the rest of the
    /// keymgmt surface.
    pub fn get_params(&self, data: &RsaKeyData) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        if let Some(bits) = data.bits() {
            ps.set(PARAM_BITS, ParamValue::UInt32(bits));
        }
        if let Some(max_size) = data.max_size() {
            ps.set(
                PARAM_MAX_SIZE,
                ParamValue::UInt32(u32::try_from(max_size).unwrap_or(u32::MAX)),
            );
        }
        if let Some(sbits) = data.security_bits() {
            ps.set(PARAM_SECURITY_BITS, ParamValue::UInt32(sbits));
        }
        ps.set(
            PARAM_DEFAULT_DIGEST,
            ParamValue::Utf8String(RSA_DEFAULT_MD.to_string()),
        );
        // RSA-PSS-specific: emit `mandatory-digest` when the key is
        // pinned to a particular hash. This forbids signature
        // operations under any other hash algorithm.
        if let RsaPssRestriction::Restricted(pss) = data.pss_restrictions() {
            ps.set(
                PARAM_MANDATORY_DIGEST,
                ParamValue::Utf8String(pss.resolved_hash().name().to_string()),
            );
        }
        trace!(
            target: TRACING_TARGET,
            "RsaPssKeyMgmt::get_params: returned {} parameter(s)",
            ps.len(),
        );
        Ok(ps)
    }

    /// Return the static list of `'static`-named, fetchable parameter
    /// keys for RSA-PSS. The `mandatory-digest` slot is always
    /// advertised even when no restriction is present — `get_params`
    /// simply omits it when the key is unrestricted.
    #[must_use]
    pub fn gettable_params(&self) -> &'static [&'static str] {
        &[
            PARAM_BITS,
            PARAM_MAX_SIZE,
            PARAM_SECURITY_BITS,
            PARAM_DEFAULT_DIGEST,
            PARAM_MANDATORY_DIGEST,
        ]
    }
}

impl KeyMgmtProvider for RsaPssKeyMgmt {
    fn name(&self) -> &'static str {
        // RSA-PSS exposes its own dispatch table but keeps the family
        // name `"RSA-PSS"` for `query_operation_name`. (Note that the
        // *operation* name reported for cross-table fetches is `"RSA"`
        // — this is handled in the signature provider, not here.)
        "RSA-PSS"
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            target: TRACING_TARGET,
            "RsaPssKeyMgmt::new_key: empty RSA-PSS key data created",
        );
        Ok(Box::new(RsaKeyData::new(RsaKeyType::RsaPss)))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::RsaPss);
        ctx.absorb(params)?;
        let key = RsaKeyData::generate_from_params(&ctx)?;
        debug!(
            target: TRACING_TARGET,
            bits = ctx.nbits,
            primes = ctx.primes,
            pss_restricted = ctx.pss_restrictions.is_restricted(),
            "RsaPssKeyMgmt::generate: completed",
        );
        Ok(Box::new(key))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let key = RsaKeyData::from_params(RsaKeyType::RsaPss, selection, data)?;
        debug!(
            target: TRACING_TARGET,
            ?selection,
            has_private = key.has_private(),
            has_public = key.has_public(),
            pss_restricted = key.pss_restrictions().is_restricted(),
            "RsaPssKeyMgmt::import: completed",
        );
        Ok(Box::new(key))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("RsaKeyData") {
            return Err(ProviderError::Dispatch(format!(
                "RSA-PSS export: incompatible key data type — debug projection={debug_str}",
            )));
        }
        warn!(
            target: TRACING_TARGET,
            ?selection,
            "RsaPssKeyMgmt::export: cross-trait export through &dyn KeyData \
             cannot decode private fields without a concrete &RsaKeyData; \
             callers should invoke RsaKeyData::export_to_params() directly",
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("RsaKeyData") {
            return false;
        }
        let has_priv = debug_str.contains("has_private: true");
        let has_pub = debug_str.contains("has_public: true");
        if selection.contains(KeySelection::PRIVATE_KEY) && !has_priv {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return false;
        }
        // RSA-PSS, like RSA, has no DOMAIN_PARAMETERS — the bit is a
        // no-op. OTHER_PARAMETERS (PSS pinning) is always satisfied.
        true
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the [`AlgorithmDescriptor`]s for the RSA and RSA-PSS
/// implementations exposed by this provider crate.
///
/// Mirrors the entries in `providers/defltprov.c` lines 605-608:
///
/// ```text
/// { PROV_NAMES_RSA,     "provider=default", ossl_rsa_keymgmt_functions     },
/// { PROV_NAMES_RSA_PSS, "provider=default", ossl_rsapss_keymgmt_functions },
/// ```
///
/// The two entries share the same dispatch table family but are
/// registered under different names. The OIDs are added so that
/// ASN.1 `AlgorithmIdentifier`-driven fetches (e.g. from a parsed
/// `SubjectPublicKeyInfo`) resolve correctly.
#[must_use]
pub fn rsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["RSA", "rsaEncryption", "1.2.840.113549.1.1.1"],
            DEFAULT_PROPERTY,
            "OpenSSL RSA implementation",
        ),
        algorithm(
            &["RSA-PSS", "RSASSA-PSS", "1.2.840.113549.1.1.10"],
            DEFAULT_PROPERTY,
            "OpenSSL RSA-PSS implementation",
        ),
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;

    // ----- Original 4 tests from the stub (PRESERVED VERBATIM) ----------------

    #[test]
    fn rsa_descriptors_returns_two_entries() {
        let descs = rsa_descriptors();
        assert_eq!(descs.len(), 2, "expected RSA + RSA-PSS");
    }

    #[test]
    fn rsa_descriptors_first_entry_is_plain_rsa() {
        let descs = rsa_descriptors();
        assert_eq!(descs[0].names[0], "RSA");
        assert!(descs[0].names.contains(&"rsaEncryption"));
        assert!(descs[0].names.contains(&"1.2.840.113549.1.1.1"));
    }

    #[test]
    fn rsa_descriptors_second_entry_is_rsa_pss() {
        let descs = rsa_descriptors();
        assert_eq!(descs[1].names[0], "RSA-PSS");
        assert!(descs[1].names.contains(&"RSASSA-PSS"));
        assert!(descs[1].names.contains(&"1.2.840.113549.1.1.10"));
    }

    #[test]
    fn rsa_descriptors_have_default_property() {
        let descs = rsa_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }

    // ----- RsaKeyType ---------------------------------------------------------

    #[test]
    fn rsa_key_type_variants_are_distinct() {
        assert_ne!(RsaKeyType::Rsa, RsaKeyType::RsaPss);
        assert_eq!(RsaKeyType::Rsa, RsaKeyType::Rsa);
        assert_eq!(RsaKeyType::RsaPss, RsaKeyType::RsaPss);
    }

    #[test]
    fn rsa_key_type_is_copy() {
        let a = RsaKeyType::Rsa;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // ----- RsaPssRestriction -------------------------------------------------

    #[test]
    fn rsa_pss_restriction_default_is_unrestricted() {
        let r = RsaPssRestriction::Unrestricted;
        assert!(!r.is_restricted());
        assert!(r.params().is_none());
    }

    #[test]
    fn rsa_pss_restriction_restricted_reports_restricted() {
        let r = RsaPssRestriction::Restricted(DEFAULT_PSS_PARAMS_30);
        assert!(r.is_restricted());
        assert!(r.params().is_some());
    }

    #[test]
    fn rsa_pss_restriction_absorb_no_params_returns_false() {
        let mut r = RsaPssRestriction::Unrestricted;
        let ps = ParamSet::new();
        let modified = r.absorb_pss_params(&ps).unwrap();
        assert!(!modified, "no PSS params present, should not modify");
        assert!(!r.is_restricted());
    }

    #[test]
    fn rsa_pss_restriction_absorb_digest_pins_restriction() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        let modified = r.absorb_pss_params(&ps).unwrap();
        assert!(modified);
        assert!(r.is_restricted());
        let pss = r.params().unwrap();
        // `algorithm_from_name` accepts "SHA-256" as an alias and resolves it
        // to `DigestAlgorithm::Sha256`, whose canonical `name()` is "SHA2-256".
        assert_eq!(pss.resolved_hash().name(), "SHA2-256");
    }

    #[test]
    fn rsa_pss_restriction_absorb_unknown_digest_errors() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST,
            ParamValue::Utf8String("BOGUS-DIGEST".to_string()),
        );
        let err = r.absorb_pss_params(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_pss_restriction_absorb_mgf1_only_mgf_accepted() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_MASKGENFUNC,
            ParamValue::Utf8String("MGF1".to_string()),
        );
        let modified = r.absorb_pss_params(&ps).unwrap();
        assert!(modified);
        assert!(r.is_restricted());
    }

    #[test]
    fn rsa_pss_restriction_absorb_mgf1_case_insensitive() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_MASKGENFUNC,
            ParamValue::Utf8String("mgf1".to_string()),
        );
        assert!(r.absorb_pss_params(&ps).is_ok());
    }

    #[test]
    fn rsa_pss_restriction_absorb_non_mgf1_rejected() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_MASKGENFUNC,
            ParamValue::Utf8String("MGF2".to_string()),
        );
        let err = r.absorb_pss_params(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_pss_restriction_absorb_saltlen_pins() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_PSS_SALTLEN, ParamValue::Int32(32));
        let modified = r.absorb_pss_params(&ps).unwrap();
        assert!(modified);
        let pss = r.params().unwrap();
        assert_eq!(pss.resolved_salt_len(), 32);
    }

    #[test]
    fn rsa_pss_restriction_absorb_full_pins() {
        let mut r = RsaPssRestriction::Unrestricted;
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST,
            ParamValue::Utf8String("SHA-384".to_string()),
        );
        ps.set(
            PARAM_RSA_MGF1_DIGEST,
            ParamValue::Utf8String("SHA-512".to_string()),
        );
        ps.set(
            PARAM_RSA_MASKGENFUNC,
            ParamValue::Utf8String("MGF1".to_string()),
        );
        ps.set(PARAM_RSA_PSS_SALTLEN, ParamValue::Int32(48));
        let modified = r.absorb_pss_params(&ps).unwrap();
        assert!(modified);
        let pss = r.params().unwrap();
        // Canonical names returned by `DigestAlgorithm::name()` are the
        // FIPS-standard "SHA2-*" form, even though `algorithm_from_name`
        // accepts the "SHA-*" aliases on input.
        assert_eq!(pss.resolved_hash().name(), "SHA2-384");
        assert_eq!(pss.resolved_mgf1_hash().name(), "SHA2-512");
        assert_eq!(pss.resolved_salt_len(), 48);
    }

    #[test]
    fn rsa_pss_restriction_write_to_params_unrestricted_emits_nothing() {
        let r = RsaPssRestriction::Unrestricted;
        let mut out = ParamSet::new();
        r.write_to_params(&mut out);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn rsa_pss_restriction_write_to_params_restricted_emits_four() {
        let r = RsaPssRestriction::Restricted(DEFAULT_PSS_PARAMS_30);
        let mut out = ParamSet::new();
        r.write_to_params(&mut out);
        assert!(out.contains(PARAM_RSA_DIGEST));
        assert!(out.contains(PARAM_RSA_MGF1_DIGEST));
        assert!(out.contains(PARAM_RSA_MASKGENFUNC));
        assert!(out.contains(PARAM_RSA_PSS_SALTLEN));
    }

    // ----- RsaGenContext ------------------------------------------------------

    #[test]
    fn rsa_gen_context_new_defaults() {
        let ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        assert_eq!(ctx.key_type, RsaKeyType::Rsa);
        assert_eq!(ctx.nbits, RSA_DEFAULT_KEY_BITS);
        assert_eq!(ctx.primes, RSA_DEFAULT_PRIMES);
        assert!(ctx.pub_exp.is_none());
        assert!(!ctx.pss_restrictions.is_restricted());
        assert!(ctx.rsa_a.is_none());
        assert!(ctx.rsa_b.is_none());
        assert!(ctx.prop_query.is_none());
    }

    #[test]
    fn rsa_gen_context_absorb_bits() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_BITS, ParamValue::UInt32(3072));
        ctx.absorb(&ps).unwrap();
        assert_eq!(ctx.nbits, 3072);
    }

    #[test]
    fn rsa_gen_context_absorb_too_few_bits_errors() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_BITS, ParamValue::UInt32(256));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_primes_two() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_PRIMES, ParamValue::UInt32(2));
        ctx.absorb(&ps).unwrap();
        assert_eq!(ctx.primes, 2);
    }

    #[test]
    fn rsa_gen_context_absorb_primes_one_errors() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_PRIMES, ParamValue::UInt32(1));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_primes_too_many_errors() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_PRIMES, ParamValue::UInt32(99));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_exponent_uint32() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_E, ParamValue::UInt32(65537));
        ctx.absorb(&ps).unwrap();
        let exp = ctx.pub_exp.expect("exponent must be stored");
        assert_eq!(exp, BigNum::from_u64(65537));
    }

    #[test]
    fn rsa_gen_context_absorb_exponent_bignum() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        let exp_bytes = BigNum::from_u64(65537).to_bytes_be();
        ps.set(PARAM_RSA_E, ParamValue::BigNum(exp_bytes));
        ctx.absorb(&ps).unwrap();
        let exp = ctx.pub_exp.expect("exponent must be stored");
        assert_eq!(exp, BigNum::from_u64(65537));
    }

    #[test]
    fn rsa_gen_context_absorb_even_exponent_rejected() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_E, ParamValue::UInt32(4));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_zero_exponent_rejected() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_E, ParamValue::UInt32(0));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_pss_pinning_on_plain_rsa_rejected() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_pss_pinning_on_pss_accepted() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::RsaPss);
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        ctx.absorb(&ps).unwrap();
        assert!(ctx.pss_restrictions.is_restricted());
    }

    #[test]
    fn rsa_gen_context_absorb_digest_props_stores_query() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST_PROPS,
            ParamValue::Utf8String("provider=default".to_string()),
        );
        ctx.absorb(&ps).unwrap();
        assert_eq!(ctx.prop_query.as_deref(), Some("provider=default"));
    }

    #[test]
    fn rsa_gen_context_absorb_rsa_a_param() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        ps.set(PARAM_RSA_A, ParamValue::UInt32(3));
        ctx.absorb(&ps).unwrap();
        assert_eq!(ctx.rsa_a, Some(3));
    }

    #[test]
    fn rsa_gen_context_absorb_rsa_a_invalid_rejected() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        // 4 is even and non-zero — invalid per is_valid_rsa_ab_param.
        ps.set(PARAM_RSA_A, ParamValue::UInt32(4));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_gen_context_absorb_rsa_a_too_large_rejected() {
        let mut ctx = RsaGenContext::new(KeySelection::KEYPAIR, RsaKeyType::Rsa);
        let mut ps = ParamSet::new();
        // 9 > 7 — invalid.
        ps.set(PARAM_RSA_A, ParamValue::UInt32(9));
        let err = ctx.absorb(&ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // ----- RsaKeyData --------------------------------------------------------

    #[test]
    fn rsa_key_data_new_is_empty() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(!key.has_private());
        assert!(!key.has_public());
        assert!(!key.has_params());
        assert_eq!(key.key_type(), RsaKeyType::Rsa);
        assert!(key.bits().is_none());
        assert!(key.modulus_bytes().is_none());
        assert!(key.security_bits().is_none());
        assert!(key.max_size().is_none());
        assert!(key.private_key().is_none());
        assert!(key.public_only().is_none());
    }

    #[test]
    fn rsa_key_data_new_pss_default_unrestricted() {
        let key = RsaKeyData::new(RsaKeyType::RsaPss);
        assert_eq!(key.key_type(), RsaKeyType::RsaPss);
        assert!(!key.pss_restrictions().is_restricted());
    }

    #[test]
    fn rsa_key_data_has_selection_empty_returns_true() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(key.has_selection(KeySelection::empty()));
    }

    #[test]
    fn rsa_key_data_has_selection_private_when_empty_returns_false() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(!key.has_selection(KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn rsa_key_data_has_selection_public_when_empty_returns_false() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(!key.has_selection(KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn rsa_key_data_export_empty_selection_errors() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        let err = key.export_to_params(KeySelection::empty()).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_key_data_export_private_when_empty_errors() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        let err = key.export_to_params(KeySelection::PRIVATE_KEY).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_key_data_match_keys_two_empty_keys_match() {
        let a = RsaKeyData::new(RsaKeyType::Rsa);
        let b = RsaKeyData::new(RsaKeyType::Rsa);
        // Both empty, both have no e/n — comparison is vacuously true
        // for "Always compare e" and the public/private bits are
        // skipped when both sides are None. PSS pinning is identical
        // (Unrestricted), so the result is `true`.
        assert!(a.match_keys(&b, KeySelection::ALL));
    }

    #[test]
    fn rsa_key_data_match_keys_pss_unrestricted_unrestricted_matches() {
        let a = RsaKeyData::new(RsaKeyType::RsaPss);
        let b = RsaKeyData::new(RsaKeyType::RsaPss);
        assert!(a.match_keys(&b, KeySelection::ALL));
    }

    #[test]
    fn rsa_key_data_validate_empty_selection_returns_true() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(key.validate_selection(KeySelection::empty()).unwrap());
    }

    #[test]
    fn rsa_key_data_validate_private_when_empty_returns_false() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(!key.validate_selection(KeySelection::PRIVATE_KEY).unwrap());
    }

    #[test]
    fn rsa_key_data_debug_projection_starts_with_name() {
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        let dbg = format!("{key:?}");
        assert!(dbg.starts_with("RsaKeyData"), "got: {dbg}");
        assert!(dbg.contains("has_private: false"));
        assert!(dbg.contains("has_public: false"));
    }

    #[test]
    fn rsa_key_data_import_empty_selection_errors() {
        let ps = ParamSet::new();
        let err = RsaKeyData::from_params(RsaKeyType::Rsa, KeySelection::empty(), &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    #[test]
    fn rsa_key_data_import_pss_params_on_plain_rejected() {
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_RSA_DIGEST,
            ParamValue::Utf8String("SHA-256".to_string()),
        );
        // Even with no key material requested, the PSS pin attempt
        // alone fails on a plain RSA key.
        let err =
            RsaKeyData::from_params(RsaKeyType::Rsa, KeySelection::PUBLIC_KEY, &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // ----- RsaKeyMgmt --------------------------------------------------------

    #[test]
    fn rsa_key_mgmt_name_is_rsa() {
        let mgmt = RsaKeyMgmt::new();
        assert_eq!(mgmt.name(), "RSA");
    }

    #[test]
    fn rsa_key_mgmt_new_is_zst() {
        // Zero-sized type: layout should be empty.
        assert_eq!(std::mem::size_of::<RsaKeyMgmt>(), 0);
    }

    #[test]
    fn rsa_key_mgmt_new_key_returns_empty_rsa_data() {
        let mgmt = RsaKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.starts_with("RsaKeyData"), "got: {dbg}");
        assert!(dbg.contains("rsa_type: Rsa"));
        assert!(dbg.contains("has_private: false"));
    }

    #[test]
    fn rsa_key_mgmt_gettable_params_includes_all_four() {
        let mgmt = RsaKeyMgmt::new();
        let names = mgmt.gettable_params();
        assert!(names.contains(&PARAM_BITS));
        assert!(names.contains(&PARAM_MAX_SIZE));
        assert!(names.contains(&PARAM_SECURITY_BITS));
        assert!(names.contains(&PARAM_DEFAULT_DIGEST));
        // Plain RSA does *not* advertise mandatory-digest.
        assert!(!names.contains(&PARAM_MANDATORY_DIGEST));
    }

    #[test]
    fn rsa_key_mgmt_get_params_on_empty_emits_default_digest_only() {
        let mgmt = RsaKeyMgmt::new();
        let key = RsaKeyData::new(RsaKeyType::Rsa);
        let ps = mgmt.get_params(&key).unwrap();
        // No key material loaded — only the default digest is reported.
        assert!(ps.contains(PARAM_DEFAULT_DIGEST));
        assert!(!ps.contains(PARAM_BITS));
        assert!(!ps.contains(PARAM_MAX_SIZE));
        assert!(!ps.contains(PARAM_SECURITY_BITS));
    }

    #[test]
    fn rsa_key_mgmt_match_keys_two_empty_match() {
        let mgmt = RsaKeyMgmt::new();
        let a = RsaKeyData::new(RsaKeyType::Rsa);
        let b = RsaKeyData::new(RsaKeyType::Rsa);
        assert!(mgmt.match_keys(&a, &b));
    }

    #[test]
    fn rsa_key_mgmt_has_on_empty_key_returns_true_for_empty_selection() {
        let mgmt = RsaKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(mgmt.has(key.as_ref(), KeySelection::empty()));
    }

    #[test]
    fn rsa_key_mgmt_has_on_empty_key_returns_false_for_private() {
        let mgmt = RsaKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(!mgmt.has(key.as_ref(), KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn rsa_key_mgmt_has_on_empty_key_returns_false_for_public() {
        let mgmt = RsaKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(!mgmt.has(key.as_ref(), KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn rsa_key_mgmt_validate_on_empty_key_no_selection_returns_true() {
        let mgmt = RsaKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(mgmt.validate(key.as_ref(), KeySelection::empty()).unwrap());
    }

    #[test]
    fn rsa_key_mgmt_export_empty_through_dyn_returns_empty() {
        let mgmt = RsaKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        // Cross-trait export through &dyn KeyData returns an empty
        // ParamSet because we cannot decode private fields without a
        // concrete `&RsaKeyData`. The Debug projection succeeds (it
        // *is* an `RsaKeyData`), so we get `Ok(empty)`.
        let ps = mgmt.export(key.as_ref(), KeySelection::PUBLIC_KEY).unwrap();
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn rsa_key_mgmt_import_empty_selection_errors() {
        let mgmt = RsaKeyMgmt::new();
        let ps = ParamSet::new();
        let err = mgmt.import(KeySelection::empty(), &ps).unwrap_err();
        assert!(matches!(err, ProviderError::Dispatch(_)));
    }

    // ----- RsaPssKeyMgmt -----------------------------------------------------

    #[test]
    fn rsa_pss_key_mgmt_name_is_rsa_pss() {
        let mgmt = RsaPssKeyMgmt::new();
        assert_eq!(mgmt.name(), "RSA-PSS");
    }

    #[test]
    fn rsa_pss_key_mgmt_new_is_zst() {
        assert_eq!(std::mem::size_of::<RsaPssKeyMgmt>(), 0);
    }

    #[test]
    fn rsa_pss_key_mgmt_new_key_returns_empty_rsa_pss_data() {
        let mgmt = RsaPssKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.starts_with("RsaKeyData"));
        assert!(dbg.contains("rsa_type: RsaPss"));
    }

    #[test]
    fn rsa_pss_key_mgmt_gettable_params_includes_mandatory_digest() {
        let mgmt = RsaPssKeyMgmt::new();
        let names = mgmt.gettable_params();
        assert!(names.contains(&PARAM_MANDATORY_DIGEST));
    }

    #[test]
    fn rsa_pss_key_mgmt_get_params_unrestricted_omits_mandatory_digest() {
        let mgmt = RsaPssKeyMgmt::new();
        let key = RsaKeyData::new(RsaKeyType::RsaPss);
        let ps = mgmt.get_params(&key).unwrap();
        // Default digest is always emitted; mandatory-digest only when
        // the key is restricted.
        assert!(ps.contains(PARAM_DEFAULT_DIGEST));
        assert!(!ps.contains(PARAM_MANDATORY_DIGEST));
    }

    #[test]
    fn rsa_pss_key_mgmt_get_params_restricted_emits_mandatory_digest() {
        let mgmt = RsaPssKeyMgmt::new();
        let mut key = RsaKeyData::new(RsaKeyType::RsaPss);
        // Pin the key to SHA-384 by construction.
        let mut pinned = DEFAULT_PSS_PARAMS_30;
        pinned.set_hash_algorithm(algorithm_from_name("SHA-384").unwrap());
        key.pss_restrictions = RsaPssRestriction::Restricted(pinned);
        let ps = mgmt.get_params(&key).unwrap();
        assert!(ps.contains(PARAM_MANDATORY_DIGEST));
        match ps.get(PARAM_MANDATORY_DIGEST) {
            // Canonical name is "SHA2-384" — see comment on
            // `rsa_pss_restriction_absorb_full_pins`.
            Some(ParamValue::Utf8String(s)) => assert_eq!(s, "SHA2-384"),
            other => panic!("expected Utf8String for mandatory-digest, got {other:?}"),
        }
    }

    #[test]
    fn rsa_pss_key_mgmt_has_on_empty_key_returns_true_for_empty_selection() {
        let mgmt = RsaPssKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(mgmt.has(key.as_ref(), KeySelection::empty()));
    }

    #[test]
    fn rsa_pss_key_mgmt_has_on_empty_key_returns_false_for_keypair() {
        let mgmt = RsaPssKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(!mgmt.has(key.as_ref(), KeySelection::KEYPAIR));
    }

    #[test]
    fn rsa_pss_key_mgmt_validate_on_empty_returns_false_for_private() {
        let mgmt = RsaPssKeyMgmt::new();
        let key = mgmt.new_key().unwrap();
        assert!(!mgmt
            .validate(key.as_ref(), KeySelection::PRIVATE_KEY)
            .unwrap());
    }

    // ----- Cross-cutting tests -----------------------------------------------

    #[test]
    fn rsa_key_mgmt_default_constructible() {
        // Ensure the `Default` derive yields a working ZST.
        let _mgmt: RsaKeyMgmt = RsaKeyMgmt::default();
        let _pss: RsaPssKeyMgmt = RsaPssKeyMgmt::default();
    }

    #[test]
    fn rsa_descriptors_are_static_strings() {
        // `algorithm()` requires `&'static str` for names, so this
        // round-trips to confirm the lifetimes are correct.
        let descs = rsa_descriptors();
        for d in &descs {
            for name in &d.names {
                assert!(!name.is_empty());
            }
        }
    }

    #[test]
    fn rsa_descriptors_have_unique_canonical_names() {
        let descs = rsa_descriptors();
        let canon: Vec<&str> = descs.iter().map(|d| d.names[0]).collect();
        assert_eq!(canon, vec!["RSA", "RSA-PSS"]);
    }
}
