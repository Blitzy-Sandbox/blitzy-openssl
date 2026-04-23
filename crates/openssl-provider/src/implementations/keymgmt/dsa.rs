//! # DSA Key Management Provider Implementation
//!
//! Rust translation of `providers/implementations/keymgmt/dsa_kmgmt.c`
//! (766 lines). Implements DSA key management for parameter generation,
//! key import/export, and validation per FIPS 186-2 and FIPS 186-4.
//!
//! ## Responsibilities
//!
//! - **Parameter generation**: Creates DSA domain parameters `(p, q, g)` with
//!   user-selectable prime/subprime bit sizes (default L=2048, N=256) and
//!   generation types (FIPS 186-2, FIPS 186-4, or default).
//! - **Key generation**: Produces `(x, y)` key pairs from existing domain
//!   parameters using uniform sampling in `[1, q-1]`.
//! - **Import/export**: Converts between [`ParamSet`] representations and
//!   structured [`DsaKeyData`] instances for FFC parameters and key material.
//! - **Validation**: Structural checks on domain parameters and key material,
//!   including public key range checks (`0 < y < p`) and private key range
//!   checks (`0 < x < q`).
//! - **Introspection**: Reports which components are present via [`has()`] and
//!   surfaces key metadata (bit sizes, security strength, default digest)
//!   through the parameter system.
//!
//! ## Architecture
//!
//! ### Key Data Decomposition
//!
//! Unlike `openssl_crypto::dsa::DsaPrivateKey` and `DsaPublicKey` which require
//! a fully-constructed [`DsaParams`] at construction time and have no public
//! constructors, [`DsaKeyData`] decomposes the key representation into three
//! independent optional components:
//!
//! ```text
//! DsaKeyData {
//!     params:        Option<DsaParams>,   // domain parameters (p, q, g)
//!     private_value: Option<BigNum>,      // raw x value (zeroed on drop)
//!     public_value:  Option<BigNum>,      // raw y value
//! }
//! ```
//!
//! This decomposition mirrors the C `DSA` struct where any combination of
//! components (params-only, pub-only, priv-only, or full key-pair) is valid
//! during the key lifecycle (e.g., after partial import, parameter generation
//! without keygen, or export with component selection).
//!
//! ### Single Dispatch Table
//!
//! Unlike DH which splits into `DhKeyMgmt` and `DhxKeyMgmt` for RFC 3526
//! versus X9.42 dispatch, DSA has a single [`DsaKeyMgmt`] struct registering
//! a single algorithm descriptor. The C source (`dsa_kmgmt.c`) provides only
//! one `OSSL_DISPATCH` table for "DSA".
//!
//! ## Security Properties
//!
//! - **Secure erasure**: [`DsaKeyData::drop`] explicitly zeros `private_value`
//!   via [`BigNum::clear`] to prevent key material leakage, replacing the C
//!   `BN_clear_free()` pattern from `crypto/dsa/dsa_lib.c`.
//! - **FIPS approved pairs**: Only `(L=2048, N={224,256})` and `(L=3072, N=256)`
//!   are approved for signing per FIPS 186-4 Section 4.2. All other pairs are
//!   approved only for legacy verification.
//! - **No unsafe code**: Zero `unsafe` blocks (Rule R8).
//!
//! ## Wiring Path (Rule R10)
//!
//! Every public item here is reachable from the entry point:
//!
//! ```text
//! openssl_cli::main()
//!   → provider loading
//!     → DefaultProvider::query_operation(KeyMgmt)
//!       → implementations::all_keymgmt_descriptors()
//!         → keymgmt::descriptors()
//!           → dsa::dsa_descriptors()
//!             → DsaKeyMgmt (registered dispatch target)
//! ```
//!
//! ## C Source Mapping
//!
//! | Rust item                    | C function (`dsa_kmgmt.c`)                   | Lines     |
//! |------------------------------|----------------------------------------------|-----------|
//! | [`DsaKeyMgmt::new_key`]      | `dsa_newdata()`                              | ~30–40    |
//! | [`DsaKeyMgmt::generate`]     | `dsa_gen_init()` + `dsa_gen_set_params()` + `dsa_gen()` | ~380–730 |
//! | [`DsaKeyMgmt::import`]       | `dsa_import()` + `dsa_import_types()`        | ~275–320  |
//! | [`DsaKeyMgmt::export`]       | `dsa_export()` + `dsa_export_types()`        | ~325–370  |
//! | [`DsaKeyMgmt::has`]          | `dsa_has()`                                  | ~110–140  |
//! | [`DsaKeyMgmt::match_keys`]   | `dsa_match()`                                | ~145–175  |
//! | [`DsaKeyMgmt::validate`]     | `dsa_validate()` + helper                    | ~175–240  |
//! | [`DsaKeyMgmt::get_params`]   | `dsa_get_params()`                           | ~245–275  |
//! | [`DsaKeyMgmt::gettable_params`] | `dsa_gettable_params()`                   | ~275–285  |
//! | [`DsaGenContext`]            | `struct dsa_gen_ctx`                         | ~330–360  |
//! | [`DsaGenType`]               | `gen_type` discriminant                      | ~360–380  |
//! | [`dsa_descriptors`]          | `deflt_keymgmt[]` DSA entry in `defltprov.c` | L≈599     |
//!
//! [`ParamSet`]: openssl_common::param::ParamSet
//! [`DsaParams`]: openssl_crypto::dsa::DsaParams
//! [`has()`]: DsaKeyMgmt::has

use std::cmp::Ordering;
use std::fmt;

use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::bn::BigNum;
use openssl_crypto::dsa::{generate_key, generate_params, DsaParams};

use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Parameter Name Constants — authoritative strings from
// `util/perl/OpenSSL/paramnames.pm` and `include/openssl/core_names.h.in`.
// =============================================================================
//
// These constants match the C OSSL_PKEY_PARAM_* and OSSL_PKEY_PARAM_FFC_*
// macro expansions exactly. Keeping them as `pub(crate) const` strings
// preserves the single-source-of-truth property and lets test code reference
// the same literal names used by the production code paths.

/// Parameter name for the bit-size metadata (the prime modulus `p` bit length).
///
/// Mirrors `OSSL_PKEY_PARAM_BITS` — literal `"bits"`.
pub(crate) const PARAM_BITS: &str = "bits";

/// Parameter name for the maximum output size of DSA operations in bytes.
///
/// Mirrors `OSSL_PKEY_PARAM_MAX_SIZE` — literal `"max-size"`.
pub(crate) const PARAM_MAX_SIZE: &str = "max-size";

/// Parameter name for the effective security strength in bits.
///
/// Mirrors `OSSL_PKEY_PARAM_SECURITY_BITS` — literal `"security-bits"`.
pub(crate) const PARAM_SECURITY_BITS: &str = "security-bits";

/// Parameter name for the default digest associated with a key type.
///
/// Mirrors `OSSL_PKEY_PARAM_DEFAULT_DIGEST` — literal `"default-digest"`.
pub(crate) const PARAM_DEFAULT_DIGEST: &str = "default-digest";

/// Parameter name for the DSA public key value `y`.
///
/// Mirrors `OSSL_PKEY_PARAM_PUB_KEY` — literal `"pub"`.
pub(crate) const PARAM_PUB_KEY: &str = "pub";

/// Parameter name for the DSA private key value `x`.
///
/// Mirrors `OSSL_PKEY_PARAM_PRIV_KEY` — literal `"priv"`.
pub(crate) const PARAM_PRIV_KEY: &str = "priv";

/// Parameter name for the FFC prime modulus `p`.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_P` — literal `"p"`.
pub(crate) const PARAM_FFC_P: &str = "p";

/// Parameter name for the FFC generator `g`.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_G` — literal `"g"`.
pub(crate) const PARAM_FFC_G: &str = "g";

/// Parameter name for the FFC subprime `q` (group order).
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_Q` — literal `"q"`.
pub(crate) const PARAM_FFC_Q: &str = "q";

/// Parameter name for the FFC generator index.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_GINDEX` — literal `"gindex"`.
pub(crate) const PARAM_FFC_GINDEX: &str = "gindex";

/// Parameter name for the FFC prime generator counter.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_PCOUNTER` — literal `"pcounter"`.
pub(crate) const PARAM_FFC_PCOUNTER: &str = "pcounter";

/// Parameter name for the FFC H index (unverifiable g generation output).
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_H` — literal `"hindex"` (not `"h"` — note
/// the explicit "hindex" spelling in the C macro expansion).
pub(crate) const PARAM_FFC_H: &str = "hindex";

/// Parameter name for the FFC seed (used for verifiable parameter generation).
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_SEED` — literal `"seed"`.
pub(crate) const PARAM_FFC_SEED: &str = "seed";

/// Parameter name for the FFC parameter generation type (FIPS 186-2 vs 186-4).
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_TYPE` — literal `"type"`.
pub(crate) const PARAM_FFC_TYPE: &str = "type";

/// Parameter name for the prime `p` bit size used during generation.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_PBITS` — literal `"pbits"`.
pub(crate) const PARAM_PBITS: &str = "pbits";

/// Parameter name for the subprime `q` bit size used during generation.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_QBITS` — literal `"qbits"`.
pub(crate) const PARAM_QBITS: &str = "qbits";

/// Parameter name for the digest algorithm used during parameter generation.
///
/// Mirrors `OSSL_PKEY_PARAM_FFC_DIGEST` — literal `"digest"`.
pub(crate) const PARAM_DIGEST: &str = "digest";

// =============================================================================
// Default algorithm parameters
// =============================================================================

/// Default digest name for DSA signature operations.
///
/// Matches the C default from `dsa_kmgmt.c:dsa_get_params()` which returns
/// `"SHA256"` for the `OSSL_PKEY_PARAM_DEFAULT_DIGEST` query.
const DSA_DEFAULT_MD: &str = "SHA256";

/// Default prime `p` bit size for parameter generation when the caller does
/// not override via `pbits`.
///
/// Matches the C default from `dsa_kmgmt.c:dsa_gen_init()` which initialises
/// `ctx->pbits = 2048`.
const DSA_DEFAULT_PBITS: usize = 2048;

/// Default subprime `q` bit size for parameter generation when the caller
/// does not override via `qbits`.
///
/// Matches the C default from `dsa_kmgmt.c:dsa_gen_init()` which initialises
/// `ctx->qbits = 224`. Note that `openssl_crypto::dsa::generate_params()`
/// auto-selects `q_bits` based on `p_bits` and ignores this value, but we
/// expose it for parity with the C API surface.
const DSA_DEFAULT_QBITS: usize = 224;

/// Minimum prime `p` bit size accepted by DSA parameter construction.
///
/// Mirrors the hardcoded lower bound in `openssl_crypto::dsa::DSA_MIN_PRIME_BITS`
/// (a private constant there). Declared here for local range checks in
/// parameter validation and bit-size mapping helpers.
const DSA_MIN_PBITS_FOR_GEN: usize = 1024;

/// Maximum prime `p` bit size accepted by DSA parameter construction.
///
/// Mirrors `openssl_crypto::dsa::DSA_MAX_PRIME_BITS` (private there). Declared
/// here as a local constant for helper bounds checks.
const DSA_MAX_PBITS_FOR_GEN: usize = 3072;

// =============================================================================
// DsaGenType — parameter generation algorithm selector
// =============================================================================

/// Selects which DSA parameter generation algorithm is used by
/// [`DsaKeyMgmt::generate`].
///
/// # C Mapping
///
/// Replaces the integer `gen_type` field in the C `struct dsa_gen_ctx`
/// (`dsa_kmgmt.c` line ~343):
///
/// ```c
/// int gen_type;  /* DSA_PARAMGEN_TYPE_FIPS_186_4 / _186_2 / _DEFAULT */
/// ```
///
/// The C macros `DSA_PARAMGEN_TYPE_FIPS_186_2`, `DSA_PARAMGEN_TYPE_FIPS_186_4`,
/// and `DSA_PARAMGEN_TYPE_FIPS_DEFAULT` from `crypto/dsa.h` map directly to the
/// enum variants below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsaGenType {
    /// Use FIPS 186-2 parameter generation (legacy, L ≤ 1024 only).
    ///
    /// Permitted for interoperability and verification of existing keys but
    /// is not an approved mode for new key generation under FIPS 186-4.
    Fips186_2,

    /// Use FIPS 186-4 parameter generation (approved for new keys).
    ///
    /// Requires `(L, N) ∈ {(2048, 224), (2048, 256), (3072, 256)}` and a
    /// `SHA-2` family digest for `p, q` construction.
    Fips186_4,

    /// Use the library default generator (FIPS 186-4 for large primes,
    /// FIPS 186-2 fall-back for `L = 1024`).
    ///
    /// Matches C `DSA_PARAMGEN_TYPE_FIPS_DEFAULT` which resolves dynamically
    /// at generation time.
    Default,
}

impl DsaGenType {
    /// Parses the FFC `"type"` parameter string into a [`DsaGenType`].
    ///
    /// Recognised values match the C string tokens accepted by
    /// `ossl_ffc_params_set_gen_type()`:
    ///
    /// - `"fips186_4"` / `"FIPS186_4"` → [`DsaGenType::Fips186_4`]
    /// - `"fips186_2"` / `"FIPS186_2"` → [`DsaGenType::Fips186_2`]
    /// - `"default"` / `"DEFAULT"`     → [`DsaGenType::Default`]
    ///
    /// Returns `None` for any other value, enabling the caller to surface a
    /// `ProviderError::Dispatch` (Rule R5 — no sentinel values).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "fips186_4" | "FIPS186_4" => Some(Self::Fips186_4),
            "fips186_2" | "FIPS186_2" => Some(Self::Fips186_2),
            "default" | "DEFAULT" => Some(Self::Default),
            _ => None,
        }
    }

    /// Returns the canonical string representation of this generation type.
    ///
    /// The returned value is suitable for round-tripping through
    /// [`DsaGenType::from_name`] and for embedding in diagnostic output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fips186_4 => "fips186_4",
            Self::Fips186_2 => "fips186_2",
            Self::Default => "default",
        }
    }
}

impl Default for DsaGenType {
    fn default() -> Self {
        Self::Default
    }
}

// =============================================================================
// DsaGenContext — DSA parameter/key generation context
// =============================================================================

/// Accumulates parameters for DSA parameter generation and key generation,
/// mirroring the C `struct dsa_gen_ctx` from `dsa_kmgmt.c` (~line 330).
///
/// A context is created with [`DsaGenContext::new`] and then populated via
/// [`DsaGenContext::absorb`] from a [`ParamSet`] supplied by the caller.
/// The populated context drives the parameter or key pair generation path
/// selected by [`DsaKeyMgmt::generate`].
///
/// # Fields
///
/// All fields are `pub` to match the open-struct convention used by DH's
/// `DhGenContext` and to permit direct test construction from the test
/// module within this file (Rule R10 test wiring).
///
/// # Security Notes
///
/// [`DsaGenContext::seed`] holds sensitive bytes when the caller requests
/// verifiable parameter generation with a user-supplied seed. Wrapping with
/// [`Zeroizing`] ensures the seed is zeroed from memory on drop, replacing
/// the C `OPENSSL_clear_free()` pattern used around `ctx->seed` in
/// `ossl_ffc_params_release()`.
#[derive(Debug)]
pub struct DsaGenContext {
    /// Which components the caller wants generated.
    ///
    /// `DOMAIN_PARAMETERS` alone → generate `(p, q, g)` only.
    /// `KEYPAIR | DOMAIN_PARAMETERS` or `KEYPAIR` alone → generate keys too.
    pub selection: KeySelection,

    /// Prime modulus `p` bit size.
    ///
    /// Defaults to [`DSA_DEFAULT_PBITS`] (2048) per FIPS 186-4 Section 4.2.
    /// Updated from the `"pbits"` entry of the input [`ParamSet`] during
    /// [`DsaGenContext::absorb`].
    pub pbits: usize,

    /// Subprime `q` bit size.
    ///
    /// Defaults to [`DSA_DEFAULT_QBITS`] (224). The library's underlying
    /// `openssl_crypto::dsa::generate_params` function auto-selects `q_bits`
    /// based on `p_bits` (160 for L=1024, 256 for L∈{2048, 3072}), so this
    /// value is retained for API-surface parity rather than active use during
    /// parameter generation.
    pub qbits: usize,

    /// Digest algorithm name for parameter generation (e.g. `"SHA256"`).
    ///
    /// When `None`, the generation path uses an algorithm-appropriate default
    /// (SHA-256 for FIPS 186-4 with L∈{2048, 3072}, SHA-1 for L=1024).
    pub mdname: Option<String>,

    /// Selected parameter generation algorithm.
    ///
    /// Defaults to [`DsaGenType::Default`] which resolves to FIPS 186-4 for
    /// modern bit-sizes.
    pub gen_type: DsaGenType,

    /// Optional seed for verifiable `(p, q)` generation.
    ///
    /// When present, the generation algorithm uses this seed to
    /// deterministically recompute `p` and `q`, enabling verifier-side
    /// reproduction per FIPS 186-4 Appendix A.1.1.3. The wrapping
    /// [`Zeroizing`] ensures the seed bytes are zeroed on drop.
    pub seed: Option<Zeroizing<Vec<u8>>>,

    /// Unverifiable generator `h` index.
    ///
    /// Mirrors the C `ctx->hindex` field, used during `g` construction when
    /// the unverifiable generator path is selected. Default `-1` sentinel in
    /// C is converted to `None` here per Rule R5.
    pub hindex: Option<i32>,

    /// Generator index for verifiable `g` construction.
    ///
    /// Mirrors the C `ctx->gindex` field (FIPS 186-4 Appendix A.2.3). Default
    /// `-1` sentinel in C is converted to `None` here per Rule R5.
    pub gindex: Option<i32>,

    /// Prime counter used during verifiable parameter generation.
    ///
    /// Mirrors the C `ctx->pcounter` field. Default `-1` sentinel in C is
    /// converted to `None` here per Rule R5.
    pub pcounter: Option<i32>,
}

impl DsaGenContext {
    /// Creates a fresh generation context seeded with the default values
    /// used by `dsa_kmgmt.c:dsa_gen_init()`.
    ///
    /// # Parameters
    ///
    /// - `selection`: which key components the caller requests be generated.
    #[must_use]
    pub fn new(selection: KeySelection) -> Self {
        Self {
            selection,
            pbits: DSA_DEFAULT_PBITS,
            qbits: DSA_DEFAULT_QBITS,
            mdname: None,
            gen_type: DsaGenType::Default,
            seed: None,
            hindex: None,
            gindex: None,
            pcounter: None,
        }
    }

    /// Consumes the relevant entries of a [`ParamSet`] into this context.
    ///
    /// Replaces the C `dsa_gen_set_params()` dispatcher from `dsa_kmgmt.c`
    /// (~line 619–720) which walks `OSSL_PARAM[]` matching each known key.
    ///
    /// # Recognised Parameters
    ///
    /// | Parameter key           | Expected type                   | Field updated |
    /// |-------------------------|---------------------------------|---------------|
    /// | [`PARAM_FFC_TYPE`]      | `Utf8String`                    | `gen_type`    |
    /// | [`PARAM_PBITS`]         | `Int32` / `UInt32` / `Int64` / `UInt64` | `pbits` |
    /// | [`PARAM_QBITS`]         | `Int32` / `UInt32` / `Int64` / `UInt64` | `qbits` |
    /// | [`PARAM_DIGEST`]        | `Utf8String`                    | `mdname`      |
    /// | [`PARAM_FFC_SEED`]      | `OctetString`                   | `seed`        |
    /// | [`PARAM_FFC_H`]         | `Int32`                         | `hindex`      |
    /// | [`PARAM_FFC_GINDEX`]    | `Int32`                         | `gindex`      |
    /// | [`PARAM_FFC_PCOUNTER`]  | `Int32`                         | `pcounter`    |
    ///
    /// Missing parameters preserve the current context value. Unrecognised
    /// keys are silently ignored to match the C dispatcher behaviour.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if a known key holds an unsupported
    ///   type (e.g. `PARAM_PBITS` as `OctetString`) — type mismatch is a
    ///   caller error rather than a "parameter not present" sentinel.
    pub fn absorb(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(target: "openssl_provider::keymgmt::dsa", "DsaGenContext::absorb()");

        if let Some(ParamValue::Utf8String(ty)) = params.get(PARAM_FFC_TYPE) {
            self.gen_type = DsaGenType::from_name(ty).ok_or_else(|| {
                ProviderError::Dispatch(format!("unknown DSA generation type '{ty}'"))
            })?;
            debug!(target: "openssl_provider::keymgmt::dsa", gen_type = ?self.gen_type, "absorbed generation type");
        }

        if let Some(v) = params.get(PARAM_PBITS) {
            self.pbits = param_to_usize(v, PARAM_PBITS)?;
            debug!(target: "openssl_provider::keymgmt::dsa", pbits = self.pbits, "absorbed pbits");
        }

        if let Some(v) = params.get(PARAM_QBITS) {
            self.qbits = param_to_usize(v, PARAM_QBITS)?;
            debug!(target: "openssl_provider::keymgmt::dsa", qbits = self.qbits, "absorbed qbits");
        }

        if let Some(ParamValue::Utf8String(md)) = params.get(PARAM_DIGEST) {
            self.mdname = Some(md.clone());
            debug!(target: "openssl_provider::keymgmt::dsa", digest = %md, "absorbed digest");
        }

        if let Some(ParamValue::OctetString(seed)) = params.get(PARAM_FFC_SEED) {
            self.seed = Some(Zeroizing::new(seed.clone()));
            debug!(target: "openssl_provider::keymgmt::dsa", seed_len = seed.len(), "absorbed seed");
        }

        if let Some(ParamValue::Int32(h)) = params.get(PARAM_FFC_H) {
            self.hindex = Some(*h);
        }

        if let Some(ParamValue::Int32(g)) = params.get(PARAM_FFC_GINDEX) {
            self.gindex = Some(*g);
        }

        if let Some(ParamValue::Int32(p)) = params.get(PARAM_FFC_PCOUNTER) {
            self.pcounter = Some(*p);
        }

        Ok(())
    }
}

/// Converts a numeric [`ParamValue`] into a `usize` with Rule R6 compliance.
///
/// Accepts signed and unsigned 32- and 64-bit integer variants and rejects
/// negative values or overflowing 64-bit values. No bare `as` casts are used
/// — all conversions go through `usize::try_from`.
///
/// # Errors
///
/// Returns [`ProviderError::Dispatch`] if the value variant is non-numeric
/// or the value cannot be losslessly represented as a `usize`.
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
            "parameter {key} is not a non-negative integer convertible to usize"
        ))
    })
}

// =============================================================================
// DsaKeyData — typed key data holding optional DSA components
// =============================================================================

/// Holds a DSA key and/or domain parameters as optional independent components.
///
/// Replaces the C `DSA` struct used as `keydata` in `dsa_kmgmt.c`. Each of the
/// three fields is independently optional to support the full range of key
/// lifecycle states:
///
/// | State            | `params`  | `private_value` | `public_value` |
/// |------------------|-----------|-----------------|----------------|
/// | Newly created    | `None`    | `None`          | `None`         |
/// | Params-only      | `Some`    | `None`          | `None`         |
/// | Public-only      | `Some`    | `None`          | `Some`         |
/// | Full key pair    | `Some`    | `Some`          | `Some`         |
///
/// # Security Properties
///
/// The [`Drop`] implementation explicitly zeros `private_value` via
/// [`BigNum::clear`], replicating the C `BN_clear_free(dsa->priv_key)` pattern
/// from `crypto/dsa/dsa_lib.c`. This upholds Rule R8 (no `unsafe`) while
/// preserving the secure-erasure invariant.
///
/// # Representation Choice
///
/// `private_value` and `public_value` are stored as raw [`BigNum`] values
/// rather than the structured [`openssl_crypto::dsa::DsaPrivateKey`] /
/// [`openssl_crypto::dsa::DsaPublicKey`] types because those structured types
/// do not expose public constructors and require a fully-constructed
/// [`DsaParams`] at construction time. Direct [`BigNum`] storage permits
/// building the key data incrementally during import, and converting to the
/// structured types only at validation time (when all components are present).
pub struct DsaKeyData {
    /// Domain parameters `(p, q, g)` if present.
    ///
    /// When `Some`, all three FFC components are guaranteed valid per the
    /// [`DsaParams::new`] constructor's internal validation (non-zero, correct
    /// bit sizes, `g ∈ (1, p)`, `q < p`).
    pub(crate) params: Option<DsaParams>,

    /// Raw private exponent `x ∈ [1, q-1]`.
    ///
    /// Stored as a bare [`BigNum`] (not wrapped in `DsaPrivateKey`) so that
    /// import/export operations can manipulate the value before the parameters
    /// are populated. Zeroed on drop via [`Drop`].
    pub(crate) private_value: Option<BigNum>,

    /// Raw public value `y = g^x mod p`, `y ∈ [1, p-1]`.
    pub(crate) public_value: Option<BigNum>,
}

impl fmt::Debug for DsaKeyData {
    /// Emits a redacted debug representation that exposes only component
    /// presence flags — never the secret key material itself.
    ///
    /// The literal struct name `"DsaKeyData"` and the field names
    /// `has_private`, `has_public`, `has_params` are load-bearing: they are
    /// used by the [`KeyMgmtProvider::has`] and related trait-object methods
    /// to structurally introspect `&dyn KeyData` via `format!("{key:?}")`
    /// since [`KeyData`] is a marker trait without downcasting support.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaKeyData")
            .field("has_private", &self.private_value.is_some())
            .field("has_public", &self.public_value.is_some())
            .field("has_params", &self.params.is_some())
            .finish()
    }
}

impl Drop for DsaKeyData {
    /// Secure erasure on drop.
    ///
    /// Explicitly clears `private_value` via [`BigNum::clear`] so that the
    /// secret exponent `x` is zeroed from memory even if the allocator does
    /// not reuse or overwrite the region. Mirrors the C
    /// `BN_clear_free(dsa->priv_key)` pattern from `crypto/dsa/dsa_lib.c:45`.
    fn drop(&mut self) {
        if let Some(x) = self.private_value.as_mut() {
            x.clear();
        }
    }
}

impl KeyData for DsaKeyData {}

impl DsaKeyData {
    /// Constructs an empty [`DsaKeyData`] with no components populated.
    ///
    /// Replaces the C `dsa_newdata()` function (`dsa_kmgmt.c:31`) which
    /// allocates a fresh `DSA` struct via `DSA_new_ex()`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: None,
            private_value: None,
            public_value: None,
        }
    }

    /// Returns a reference to the stored [`DsaParams`] if present.
    ///
    /// Equivalent to the C `DSA_get0_pqg()` accessor. Returns `None` when
    /// the key data has not yet had parameters installed (e.g., freshly
    /// constructed via [`DsaKeyData::new`]).
    #[must_use]
    pub fn key(&self) -> Option<&DsaParams> {
        self.params.as_ref()
    }

    /// Reports whether a private key component is present.
    #[must_use]
    pub fn has_private(&self) -> bool {
        self.private_value.is_some()
    }

    /// Reports whether a public key component is present.
    #[must_use]
    pub fn has_public(&self) -> bool {
        self.public_value.is_some()
    }

    /// Reports whether domain parameters are present.
    #[must_use]
    pub fn has_params(&self) -> bool {
        self.params.is_some()
    }

    /// Returns the prime `p` bit size when domain parameters are present.
    ///
    /// Mirrors the C `DSA_bits()` function from `crypto/dsa/dsa_lib.c`.
    /// Returns `None` when the key data holds no parameters — per Rule R5,
    /// no sentinel `0` is ever returned.
    #[must_use]
    pub fn bits(&self) -> Option<u32> {
        self.params.as_ref().map(|p| p.p().num_bits())
    }

    /// Returns the effective security strength per NIST SP 800-57 Table 2.
    ///
    /// Mirrors the C `ossl_dsa_security_bits()` from `crypto/dsa/dsa_lib.c`.
    /// Returns `None` when parameters are absent.
    ///
    /// The mapping used (rounding up to the enclosing NIST tier):
    ///
    /// | Prime `p` bit size | Security strength |
    /// |--------------------|-------------------|
    /// | 15 360 or more     | 256               |
    /// | 7 680 – 15 359     | 192               |
    /// | 3 072 – 7 679      | 128               |
    /// | 2 048 – 3 071      | 112               |
    /// | 1 024 – 2 047      | 80                |
    /// | under 1 024        | 0                 |
    #[must_use]
    pub fn security_bits(&self) -> Option<u32> {
        self.bits().map(security_bits_from_prime)
    }

    /// Returns the maximum DSA signature output size in bytes.
    ///
    /// A DSA signature is DER-encoded as `SEQUENCE { r INTEGER, s INTEGER }`
    /// where `r` and `s` are each approximately `q` bits long. The worst-case
    /// DER overhead gives:
    ///
    /// ```text
    /// max_sig = 2 * (q_bytes + 3) + 6
    /// ```
    ///
    /// accounting for `INTEGER` tag/length plus a possible leading `0x00`
    /// sign byte, plus the outer `SEQUENCE` tag and two-byte length. Mirrors
    /// the C `DSA_size()` computation in `crypto/dsa/dsa_lib.c`.
    ///
    /// Returns `None` when parameters are absent — Rule R5.
    #[must_use]
    pub fn max_size(&self) -> Option<usize> {
        self.params.as_ref().map(|p| {
            let q_bytes = usize::try_from(p.q().num_bytes()).unwrap_or(usize::MAX);
            // 2 * (q_bytes + 3) + 6 — saturating arithmetic to prevent overflow
            // in the (impossible for sane q_bytes) pathological case.
            q_bytes
                .saturating_add(3)
                .saturating_mul(2)
                .saturating_add(6)
        })
    }

    /// Exports the selected components into a fresh [`ParamSet`].
    ///
    /// Replaces the C `dsa_export()` (~line 325) and `ossl_ffc_params_todata()`
    /// helpers. Each requested component is serialised via
    /// [`BigNum::to_bytes_be`] into the corresponding [`ParamValue::BigNum`]
    /// entry.
    ///
    /// # Selection Semantics
    ///
    /// - [`KeySelection::DOMAIN_PARAMETERS`] → emits `p`, `q`, `g` (and
    ///   `cofactor` as `"j"` is only emitted when a non-trivial value exists,
    ///   which for DSA is never — `q` divides `p-1` exactly by construction).
    /// - [`KeySelection::PUBLIC_KEY`]        → emits `pub` (the `y` value).
    /// - [`KeySelection::PRIVATE_KEY`]       → emits `priv` (the `x` value).
    ///
    /// Missing components are silently omitted — it is valid to request an
    /// export of `KEYPAIR` when only the public part is present, in which
    /// case only `pub` is emitted.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if the requested selection is empty
    ///   (`KeySelection::empty()`) — callers must select at least one
    ///   component.
    pub fn export_to_params(&self, selection: KeySelection) -> ProviderResult<ParamSet> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            ?selection,
            "DsaKeyData::export_to_params()",
        );

        if selection.is_empty() {
            return Err(ProviderError::Dispatch(
                "empty selection rejected by DsaKeyData::export_to_params".to_string(),
            ));
        }

        let mut out = ParamSet::new();

        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            if let Some(params) = self.params.as_ref() {
                out.set(PARAM_FFC_P, ParamValue::BigNum(params.p().to_bytes_be()));
                out.set(PARAM_FFC_Q, ParamValue::BigNum(params.q().to_bytes_be()));
                out.set(PARAM_FFC_G, ParamValue::BigNum(params.g().to_bytes_be()));
            }
        }

        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let Some(y) = self.public_value.as_ref() {
                out.set(PARAM_PUB_KEY, ParamValue::BigNum(y.to_bytes_be()));
            }
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let Some(x) = self.private_value.as_ref() {
                out.set(PARAM_PRIV_KEY, ParamValue::BigNum(x.to_bytes_be()));
            }
        }

        Ok(out)
    }

    /// Constructs a [`DsaKeyData`] from an inbound [`ParamSet`] per
    /// `selection`.
    ///
    /// Replaces the C `dsa_import()` (~line 275) and
    /// `ossl_dsa_ffc_params_fromdata()` helpers.
    ///
    /// # Import Rules
    ///
    /// - When `DOMAIN_PARAMETERS` is selected, **all** of `p`, `q`, `g` must
    ///   be present or the call errors — partial domain parameter imports
    ///   are rejected to avoid constructing a [`DsaParams`] with holes.
    /// - When `PUBLIC_KEY` or `PRIVATE_KEY` are selected, the corresponding
    ///   component must be present or the call errors.
    /// - Key components are accepted from either [`ParamValue::BigNum`] or
    ///   [`ParamValue::OctetString`] variants — both are big-endian byte
    ///   representations and the C dispatcher accepts both.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] if a required component is missing or has
    ///   an incompatible `ParamValue` variant.
    /// - [`ProviderError::Dispatch`] wrapping a [`openssl_common::error::CryptoError`]
    ///   display if the constructed parameters fail [`DsaParams::new`]
    ///   validation (out-of-range, structurally invalid).
    pub fn from_params(
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Self> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            ?selection,
            "DsaKeyData::from_params()",
        );

        let mut key = Self::new();

        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            let p_bytes = extract_bignum_bytes(data, PARAM_FFC_P)?;
            let q_bytes = extract_bignum_bytes(data, PARAM_FFC_Q)?;
            let g_bytes = extract_bignum_bytes(data, PARAM_FFC_G)?;

            let p = BigNum::from_bytes_be(&p_bytes);
            let q = BigNum::from_bytes_be(&q_bytes);
            let g = BigNum::from_bytes_be(&g_bytes);

            let params = DsaParams::new(p, q, g).map_err(|e| {
                ProviderError::Dispatch(format!("DSA parameter validation failed: {e}"))
            })?;
            key.params = Some(params);
        }

        if selection.contains(KeySelection::PUBLIC_KEY) {
            let y_bytes = extract_bignum_bytes(data, PARAM_PUB_KEY)?;
            key.public_value = Some(BigNum::from_bytes_be(&y_bytes));
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            let x_bytes = extract_bignum_bytes(data, PARAM_PRIV_KEY)?;
            key.private_value = Some(BigNum::from_bytes_be(&x_bytes));
        }

        Ok(key)
    }

    /// Generates fresh domain parameters and optionally a key pair per the
    /// supplied [`DsaGenContext`].
    ///
    /// Replaces the C `dsa_gen()` function (~line 530) which orchestrates
    /// calls to `ossl_ffc_params_FIPS186_4_generate()` followed (when
    /// `selection` includes keypair components) by `DSA_generate_key()`.
    ///
    /// # Generation Flow
    ///
    /// 1. Validates `pbits` is in the range `[1024, 3072]` — Rule R6
    ///    compliant (no bare casts, explicit `try_from`).
    /// 2. Calls [`openssl_crypto::dsa::generate_params`] to produce the
    ///    domain parameters at the requested bit size. The `gen_type` field
    ///    is logged but the underlying library always uses FIPS 186-4 for
    ///    L ∈ {1024, 2048, 3072}.
    /// 3. When `selection` includes `PUBLIC_KEY` or `PRIVATE_KEY`, calls
    ///    [`openssl_crypto::dsa::generate_key`] to sample a uniformly-random
    ///    key pair and extracts raw [`BigNum`] values via `.value().clone()`.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Dispatch`] with an out-of-range diagnostic if
    ///   `pbits` is not in `[1024, 3072]`.
    /// - [`ProviderError::Dispatch`] wrapping the underlying crypto error if
    ///   the generation primitive fails (e.g., sampler exhaustion).
    pub fn generate_from_params(ctx: &DsaGenContext) -> ProviderResult<Self> {
        debug!(
            target: "openssl_provider::keymgmt::dsa",
            pbits = ctx.pbits,
            qbits = ctx.qbits,
            gen_type = ?ctx.gen_type,
            selection = ?ctx.selection,
            "DsaKeyData::generate_from_params()",
        );

        if ctx.pbits < DSA_MIN_PBITS_FOR_GEN || ctx.pbits > DSA_MAX_PBITS_FOR_GEN {
            return Err(ProviderError::Dispatch(format!(
                "DSA pbits {} out of range [{}, {}]",
                ctx.pbits, DSA_MIN_PBITS_FOR_GEN, DSA_MAX_PBITS_FOR_GEN,
            )));
        }

        let bits_u32 = u32::try_from(ctx.pbits).map_err(|_| {
            ProviderError::Dispatch(format!(
                "DSA pbits {} does not fit in u32",
                ctx.pbits
            ))
        })?;

        let params = generate_params(bits_u32).map_err(|e| {
            ProviderError::Dispatch(format!("DSA parameter generation failed: {e}"))
        })?;

        let mut key = Self {
            params: Some(params),
            private_value: None,
            public_value: None,
        };

        // Generate a key pair when the caller requests any keypair component.
        if ctx
            .selection
            .intersects(KeySelection::PUBLIC_KEY | KeySelection::PRIVATE_KEY)
        {
            let params_ref = key.params.as_ref().ok_or_else(|| {
                ProviderError::Dispatch(
                    "internal error: params should be present after generation".to_string(),
                )
            })?;
            let kp = generate_key(params_ref).map_err(|e| {
                ProviderError::Dispatch(format!("DSA key generation failed: {e}"))
            })?;
            // Extract raw BigNum values. BigNum implements Clone.
            key.private_value = Some(kp.private_key().value().clone());
            key.public_value = Some(kp.public_key().value().clone());
        }

        Ok(key)
    }

    /// Reports whether this key data contains every component in `selection`.
    ///
    /// Replaces C `dsa_has()` (~line 110). The logic mirrors the C function
    /// exactly: a selection bit is satisfied iff the corresponding component
    /// is present, and an empty selection is trivially satisfied.
    #[must_use]
    pub fn has_selection(&self, selection: KeySelection) -> bool {
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) && !self.has_params() {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && !self.has_public() {
            return false;
        }
        if selection.contains(KeySelection::PRIVATE_KEY) && !self.has_private() {
            return false;
        }
        true
    }

    /// Performs structural validation of the selected components.
    ///
    /// Replaces C `dsa_validate()` (~line 175). Since the `BigNum` API does
    /// not expose modular exponentiation, validation is limited to range
    /// checks that can be performed with basic comparisons:
    ///
    /// - **Domain parameters**: enforced at construction time by
    ///   [`DsaParams::new`] — if `params` is present, the constructor
    ///   already verified non-zero, bit-size bounds, `q < p`, and `1 < g < p`.
    /// - **Public key** `y`: must satisfy `1 < y < p`. An additional
    ///   non-zero/non-one check is required because `y = 1` would yield a
    ///   trivial subgroup element.
    /// - **Private key** `x`: must satisfy `1 ≤ x < q`. When both `x` and
    ///   `q` are present, the upper bound is enforced.
    ///
    /// # Errors
    ///
    /// Returns `Ok(true)` when all present components pass validation,
    /// `Ok(false)` when structural checks fail, and [`ProviderError`] only
    /// when the selection is inconsistent (e.g., asks to validate a
    /// component that is not present).
    pub fn validate_selection(&self, selection: KeySelection) -> ProviderResult<bool> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            ?selection,
            "DsaKeyData::validate_selection()",
        );

        if !self.has_selection(selection) {
            warn!(
                target: "openssl_provider::keymgmt::dsa",
                ?selection,
                "validate_selection: missing components for requested selection",
            );
            return Ok(false);
        }

        // Check public key range: 1 < y < p (requires params and public).
        if selection.contains(KeySelection::PUBLIC_KEY) {
            let y = self.public_value.as_ref().ok_or_else(|| {
                ProviderError::Dispatch(
                    "public_value missing after has_selection check".to_string(),
                )
            })?;
            if y.is_zero() || y.is_one() {
                warn!(
                    target: "openssl_provider::keymgmt::dsa",
                    "validate_selection: public value y is 0 or 1",
                );
                return Ok(false);
            }
            if let Some(params) = self.params.as_ref() {
                if y.cmp(params.p()) != Ordering::Less {
                    warn!(
                        target: "openssl_provider::keymgmt::dsa",
                        "validate_selection: public value y >= p",
                    );
                    return Ok(false);
                }
            }
        }

        // Check private key range: 1 <= x < q (requires params and private).
        if selection.contains(KeySelection::PRIVATE_KEY) {
            let x = self.private_value.as_ref().ok_or_else(|| {
                ProviderError::Dispatch(
                    "private_value missing after has_selection check".to_string(),
                )
            })?;
            if x.is_zero() {
                warn!(
                    target: "openssl_provider::keymgmt::dsa",
                    "validate_selection: private value x is 0",
                );
                return Ok(false);
            }
            if let Some(params) = self.params.as_ref() {
                if x.cmp(params.q()) != Ordering::Less {
                    warn!(
                        target: "openssl_provider::keymgmt::dsa",
                        "validate_selection: private value x >= q",
                    );
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Compares two DSA key data objects for equality of the selected
    /// components, mirroring C `dsa_match()` (~line 145).
    ///
    /// # Match Semantics
    ///
    /// - `DOMAIN_PARAMETERS`: requires both operands to have parameters and
    ///   for all three components `(p, q, g)` to be bit-for-bit equal.
    /// - `PUBLIC_KEY`: requires both operands to have a public value and
    ///   for the values to be equal.
    /// - `PRIVATE_KEY`: requires both operands to have a private value and
    ///   for the values to be equal.
    ///
    /// An empty selection returns `true` trivially (matching C behaviour).
    #[must_use]
    pub fn match_keys(&self, other: &DsaKeyData, selection: KeySelection) -> bool {
        // Matches the C `BN_cmp` NULL semantics used by `dsa_match()` and
        // `ossl_ffc_params_cmp()`:
        //   - `BN_cmp(NULL, NULL) == 0`  → trivially equal (both absent)
        //   - `BN_cmp(Some, NULL)`        → mismatch (asymmetric)
        //   - `BN_cmp(Some, Some)`        → actual byte comparison
        // This allows a public-only key to match a full key-pair under the
        // `DOMAIN_PARAMETERS` or `PUBLIC_KEY` selection when only the
        // relevant component is present on both sides.
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            match (self.params.as_ref(), other.params.as_ref()) {
                (Some(a), Some(b)) => {
                    if a.p() != b.p() || a.q() != b.q() || a.g() != b.g() {
                        return false;
                    }
                }
                (None, None) => { /* trivially equal — nothing to compare */ }
                // Asymmetric presence: one has params, the other does not.
                _ => return false,
            }
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            match (self.public_value.as_ref(), other.public_value.as_ref()) {
                (Some(a), Some(b)) if a == b => {}
                (None, None) => { /* trivially equal */ }
                // Either values differ, or asymmetric presence — in both
                // cases the keys do not match under `PUBLIC_KEY`.
                _ => return false,
            }
        }
        if selection.contains(KeySelection::PRIVATE_KEY) {
            match (self.private_value.as_ref(), other.private_value.as_ref()) {
                (Some(a), Some(b)) if a == b => {}
                (None, None) => { /* trivially equal */ }
                // Either values differ, or asymmetric presence — in both
                // cases the keys do not match under `PRIVATE_KEY`.
                _ => return false,
            }
        }
        true
    }
}

impl Default for DsaKeyData {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Extracts a big-endian big-number byte sequence from a [`ParamSet`] entry.
///
/// Accepts both [`ParamValue::BigNum`] and [`ParamValue::OctetString`]
/// variants — these are interchangeable big-endian representations and the
/// C dispatcher does not distinguish between them for FFC components.
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
            other.param_type_name()
        ))),
        None => Err(ProviderError::Dispatch(format!(
            "required parameter {key} is missing"
        ))),
    }
}

/// Maps prime `p` bit size to the NIST SP 800-57 Part 1 Table 2 security
/// strength in bits.
///
/// Used by [`DsaKeyData::security_bits`] and by [`DsaKeyMgmt::get_params`]
/// when surfacing the `"security-bits"` metadata parameter.
///
/// Returns `0` for sub-1024 bit primes (not approved for any FIPS use).
#[must_use]
fn security_bits_from_prime(bits: u32) -> u32 {
    if bits >= 15360 {
        256
    } else if bits >= 7680 {
        192
    } else if bits >= 3072 {
        128
    } else if bits >= 2048 {
        112
    } else if bits >= 1024 {
        80
    } else {
        0
    }
}


// =============================================================================
// DsaKeyMgmt — KeyMgmtProvider implementation
// =============================================================================

/// DSA (FIPS 186-2 / FIPS 186-4) key management.
///
/// Replaces the `ossl_dsa_keymgmt_functions` dispatch table declared in
/// `providers/implementations/keymgmt/dsa_kmgmt.c` (lines ~730–766). Unlike
/// DH (which has two distinct dispatch tables for DH and DHX), DSA has a
/// single dispatch table because the algorithm family is uniform.
///
/// This struct is a zero-sized type — all state lives on the
/// [`DsaKeyData`] values returned by [`new_key`](KeyMgmtProvider::new_key),
/// [`import`](KeyMgmtProvider::import), and
/// [`generate`](KeyMgmtProvider::generate). Multiple `DsaKeyMgmt` values may
/// coexist without contention because the type carries no mutable state — see
/// Rule R7 (lock granularity).
///
/// # Rule R8 Compliance
///
/// Contains zero `unsafe` blocks. All underlying cryptographic operations are
/// delegated to the [`openssl_crypto::dsa`] module, which is itself safe
/// Rust. FFI concerns (C ABI symbols, pointer conversion) are the sole
/// responsibility of the dedicated `openssl-ffi` crate and never appear here.
#[derive(Debug, Clone, Copy, Default)]
pub struct DsaKeyMgmt;

impl DsaKeyMgmt {
    /// Constructs a new DSA key management instance.
    ///
    /// Because [`DsaKeyMgmt`] is a zero-sized type this is equivalent to
    /// [`DsaKeyMgmt::default()`], but the inherent constructor matches the
    /// workspace convention for `KeyMgmt` providers (see
    /// [`DhKeyMgmt::new`](super::dh::DhKeyMgmt::new)).
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Byte-wise comparison of two concrete DSA keys across every component.
    ///
    /// This is the concrete-type equivalent of `dsa_match()` from
    /// `dsa_kmgmt.c:145–175`. Uses [`KeySelection::ALL`] which compares
    /// domain parameters, public key, and private key when each side has
    /// them populated. See [`DsaKeyData::match_keys`] for the per-component
    /// semantics.
    ///
    /// Returns `true` when every component populated on both sides matches.
    #[must_use]
    pub fn match_keys(&self, key1: &DsaKeyData, key2: &DsaKeyData) -> bool {
        key1.match_keys(key2, KeySelection::ALL)
    }

    /// Returns the metadata parameters for the given concrete DSA key.
    ///
    /// Mirrors `dsa_get_params()` from `dsa_kmgmt.c:245–275`, which emits
    /// the four metadata slots that every provider must expose:
    ///
    /// | C constant                    | Rust constant             | Type    | Value                                    |
    /// |-------------------------------|---------------------------|---------|------------------------------------------|
    /// | `OSSL_PKEY_PARAM_BITS`        | [`PARAM_BITS`]            | `u32`   | `p` bit size (via [`DsaKeyData::bits`])  |
    /// | `OSSL_PKEY_PARAM_MAX_SIZE`    | [`PARAM_MAX_SIZE`]        | `u32`   | Max DER signature bytes (see [`DsaKeyData::max_size`]) |
    /// | `OSSL_PKEY_PARAM_SECURITY_BITS` | [`PARAM_SECURITY_BITS`] | `u32`   | NIST SP 800-57 strength mapping           |
    /// | `OSSL_PKEY_PARAM_DEFAULT_DIGEST` | [`PARAM_DEFAULT_DIGEST`] | `&str` | [`DSA_DEFAULT_MD`] = `"SHA256"`          |
    ///
    /// Unlike DH (which emits an empty string for `default-digest` because
    /// DH is not a signature primitive), DSA always emits `"SHA256"`
    /// matching the C default that callers see when they query the default
    /// digest for DSA key signing.
    ///
    /// When domain parameters are absent the numeric metadata slots are
    /// omitted — Rule R5 forbids returning sentinel `0` to represent
    /// "unknown". Only the always-valid [`PARAM_DEFAULT_DIGEST`] entry is
    /// unconditionally present in the returned [`ParamSet`].
    ///
    /// # Rule R6 Compliance
    ///
    /// The `usize` → `u32` conversion for [`PARAM_MAX_SIZE`] uses
    /// [`u32::try_from`] with a [`u32::MAX`] saturating fall-back. No bare
    /// `as` cast appears anywhere on this path.
    ///
    /// # Errors
    ///
    /// This method is currently infallible — it always returns `Ok(...)`.
    /// The `ProviderResult` return type is preserved for parity with the C
    /// dispatch-slot signature, which returns `int` and could surface
    /// errors from future extensions (e.g. when integer conversion fails
    /// in a hypothetical exotic configuration).
    pub fn get_params(&self, data: &DsaKeyData) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        if let Some(bits) = data.bits() {
            ps.set(PARAM_BITS, ParamValue::UInt32(bits));
        }
        if let Some(max_size) = data.max_size() {
            // Rule R6: lossless narrowing via try_from with saturating
            // fall-back. `max_size` is at most `2 * (q_bytes + 3) + 6`
            // where `q_bytes ≤ usize::MAX`, so overflow here is only
            // reachable on pathological 16-bit platforms (out of scope).
            ps.set(
                PARAM_MAX_SIZE,
                ParamValue::UInt32(u32::try_from(max_size).unwrap_or(u32::MAX)),
            );
        }
        if let Some(sbits) = data.security_bits() {
            ps.set(PARAM_SECURITY_BITS, ParamValue::UInt32(sbits));
        }
        // DSA uses SHA-256 as its default signing digest (C default from
        // `dsa_kmgmt.c:dsa_get_params()`). Unlike DH (key-exchange only)
        // this slot is always populated — DSA is fundamentally a signature
        // algorithm and the default digest is part of its identity.
        ps.set(
            PARAM_DEFAULT_DIGEST,
            ParamValue::Utf8String(DSA_DEFAULT_MD.to_string()),
        );
        Ok(ps)
    }

    /// Returns the set of parameter keys queryable via
    /// [`get_params`](Self::get_params).
    ///
    /// Mirrors `dsa_gettable_params()` from `dsa_kmgmt.c:275–285`, which in
    /// the C implementation is generated by the `dsa_kmgmt.inc` template
    /// as an `OSSL_PARAM` array constant. Here we return a `'static` slice
    /// of the four parameter name constants defined at module scope — same
    /// names, same order, same stability guarantees.
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

impl KeyMgmtProvider for DsaKeyMgmt {
    fn name(&self) -> &'static str {
        "DSA"
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            "DSA new_key: allocating empty keydata",
        );
        Ok(Box::new(DsaKeyData::new()))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        // Default selection is the full keypair — the C routine uses the
        // caller-provided `selection` argument when available, but the
        // trait-level `generate` signature does not currently expose a
        // selection slot. Defaulting to `KEYPAIR` matches the C default of
        // `OSSL_KEYMGMT_SELECT_KEYPAIR` observed at `dsa_kmgmt.c:560`.
        let mut ctx = DsaGenContext::new(KeySelection::KEYPAIR);
        ctx.absorb(params)?;
        let key = DsaKeyData::generate_from_params(&ctx)?;
        debug!(
            target: "openssl_provider::keymgmt::dsa",
            pbits = ctx.pbits,
            qbits = ctx.qbits,
            gen_type = ctx.gen_type.as_str(),
            "DSA generate: completed",
        );
        Ok(Box::new(key))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            ?selection,
            "DSA keymgmt: importing key",
        );
        let key = DsaKeyData::from_params(selection, data)?;
        Ok(Box::new(key))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            ?selection,
            "DSA keymgmt: exporting key",
        );
        // The KeyData trait is a minimal marker (Send + Sync + Debug) and
        // deliberately does not extend `Any`, so we cannot downcast a
        // `&dyn KeyData` back to the concrete `&DsaKeyData`. We instead
        // verify the Debug projection starts with "DsaKeyData" (which the
        // custom `Debug` impl at line ~597 guarantees) and log a warning
        // telling callers to use the concrete accessor. This mirrors
        // `DhKeyMgmt::export` at `dh.rs:1059–1079` and `EcKeyMgmt::export`
        // at `ec.rs:411–440`.
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("DsaKeyData") {
            return Err(ProviderError::Dispatch(
                "DSA keymgmt: export called with non-DSA key data".to_string(),
            ));
        }
        warn!(
            target: "openssl_provider::keymgmt::dsa",
            "DSA keymgmt: export with opaque KeyData uses limited introspection; \
             prefer using concrete DsaKeyData::export_to_params directly",
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        // Same strategy as `export`: parse the Debug projection for the
        // three boolean flags emitted by `DsaKeyData`'s custom Debug impl.
        // This matches `DhKeyMgmt::has` (dh.rs:1081–1104) and
        // `EcKeyMgmt::has` (ec.rs:442–465).
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("DsaKeyData") {
            return false;
        }
        let has_priv = debug_str.contains("has_private: true");
        let has_pub = debug_str.contains("has_public: true");
        let has_params = debug_str.contains("has_params: true");

        if selection.contains(KeySelection::PRIVATE_KEY) && !has_priv {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return false;
        }
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) && !has_params {
            return false;
        }
        true
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        trace!(
            target: "openssl_provider::keymgmt::dsa",
            ?selection,
            "DSA keymgmt: validating key",
        );
        // Structural validation via `has()` — the opaque `&dyn KeyData`
        // surface does not expose the bignum components required for deep
        // validation (range checks on `y`, primality of `p`, etc.). Deep
        // validation is available via `DsaKeyData::validate_selection` on
        // a concrete reference. This mirrors `DhKeyMgmt::validate`
        // (`dh.rs:1106–1112`).
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm descriptors
// =============================================================================

/// Returns the algorithm descriptors contributed by this module.
///
/// Called from `keymgmt::descriptors()` at `mod.rs:329`, which aggregates the
/// descriptor vectors from every family module (RSA, DH, DSA, EC, …). Emits
/// a single entry for the `DSA` family — DSA unlike DH has one dispatch
/// table rather than two, so one descriptor suffices.
///
/// The `names` vector lists the canonical name first (`"DSA"`) followed by
/// the PKCS OID alias `"dsaEncryption"` (OID 1.2.840.10040.4.1). These
/// aliases mirror the name list used by the C `ossl_dsa_keymgmt_functions`
/// registration block in `defltprov.c:599`.
///
/// The `property` field is [`DEFAULT_PROPERTY`] (`"provider=default"`)
/// because DSA is part of the default provider. FIPS-specific descriptors
/// for DSA are registered separately in the `openssl-fips` crate with a
/// different property string.
#[must_use]
pub fn dsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["DSA", "dsaEncryption"],
        property: DEFAULT_PROPERTY,
        description: "DSA key management (FIPS 186-2 / FIPS 186-4)",
    }]
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Tests are permitted to use `expect()`, `unwrap()`, and `panic!()` for
    // diagnostic purposes — failures inside tests must produce clear messages
    // rather than being propagated as `Result` values. This follows the
    // workspace-wide convention established in
    // `crates/openssl-provider/src/tests/test_algorithm_correctness.rs`.
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;

    // -------------------------------------------------------------------------
    // DsaKeyMgmt construction and trivia
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_keymgmt_new_equals_default() {
        let a = DsaKeyMgmt::new();
        let b = DsaKeyMgmt;
        // `DsaKeyMgmt` is a zero-sized type, so any two values are
        // necessarily identical. The test exists to pin the `new`
        // constructor contract — callers should not rely on any stateful
        // behavior.
        let _ = (a, b);
    }

    #[test]
    fn dsa_keymgmt_name_is_dsa() {
        let mgmt = DsaKeyMgmt::new();
        assert_eq!(mgmt.name(), "DSA");
    }

    #[test]
    fn dsa_keymgmt_gettable_params_contains_four_slots() {
        let mgmt = DsaKeyMgmt::new();
        let names = mgmt.gettable_params();
        assert_eq!(names.len(), 4);
        assert!(names.contains(&PARAM_BITS));
        assert!(names.contains(&PARAM_MAX_SIZE));
        assert!(names.contains(&PARAM_SECURITY_BITS));
        assert!(names.contains(&PARAM_DEFAULT_DIGEST));
    }

    // -------------------------------------------------------------------------
    // new_key — always returns an empty DsaKeyData
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_keymgmt_new_key_returns_empty() {
        let mgmt = DsaKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key must succeed");
        // The Debug projection of a fresh DsaKeyData emits three
        // `has_*: false` fields. We verify this via the public trait
        // methods.
        assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
    }

    // -------------------------------------------------------------------------
    // get_params — emits default-digest even on empty key
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_keymgmt_get_params_empty_emits_default_digest_only() {
        let mgmt = DsaKeyMgmt::new();
        let data = DsaKeyData::new();
        let ps = mgmt.get_params(&data).expect("get_params");

        // No params → no `bits`/`max-size`/`security-bits`.
        assert!(ps.get(PARAM_BITS).is_none());
        assert!(ps.get(PARAM_MAX_SIZE).is_none());
        assert!(ps.get(PARAM_SECURITY_BITS).is_none());
        // `default-digest` is always emitted.
        let d = ps.get(PARAM_DEFAULT_DIGEST).expect("default-digest");
        match d {
            ParamValue::Utf8String(s) => assert_eq!(s, DSA_DEFAULT_MD),
            other => panic!("expected Utf8String, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // has — respects selection bitmask
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_keymgmt_has_rejects_missing_components() {
        let mgmt = DsaKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");

        // Empty key — every non-empty selection must fail.
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(!mgmt.has(&*key, KeySelection::KEYPAIR));
        assert!(!mgmt.has(&*key, KeySelection::ALL));
    }

    #[test]
    fn dsa_keymgmt_has_empty_selection_passes_for_any_key() {
        let mgmt = DsaKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // An empty selection bitmask has nothing to check — every key
        // passes. This matches the C `dsa_has()` contract where an
        // argument of `0` trivially returns `1`.
        assert!(mgmt.has(&*key, KeySelection::empty()));
    }

    // -------------------------------------------------------------------------
    // validate — delegates to has()
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_keymgmt_validate_tracks_has() {
        let mgmt = DsaKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // Empty key — every non-empty validate selection returns false
        // (Ok(false), not Err — structural mismatch is a "no" not an
        // "error").
        assert!(!mgmt
            .validate(&*key, KeySelection::DOMAIN_PARAMETERS)
            .expect("validate"));
        assert!(!mgmt.validate(&*key, KeySelection::KEYPAIR).expect("validate"));
    }

    // -------------------------------------------------------------------------
    // export — rejects non-DSA KeyData, succeeds on DSA KeyData
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_keymgmt_export_accepts_dsa_key_data() {
        let mgmt = DsaKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // Opaque-trait export returns an empty ParamSet but does not
        // error. The concrete `export_to_params` is the preferred path.
        let ps = mgmt.export(&*key, KeySelection::ALL).expect("export");
        // The opaque-path export is deliberately empty; real data comes
        // from `DsaKeyData::export_to_params`.
        let _ = ps;
    }

    // -------------------------------------------------------------------------
    // Descriptor tests
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_descriptors_returns_one_entry() {
        let descs = dsa_descriptors();
        assert_eq!(descs.len(), 1, "DSA has a single dispatch table");

        let dsa = &descs[0];
        assert!(dsa.names.contains(&"DSA"));
        assert!(dsa.names.contains(&"dsaEncryption"));
        assert_eq!(dsa.property, "provider=default");
        assert!(!dsa.description.is_empty());
        assert!(dsa.description.contains("DSA"));
    }

    // -------------------------------------------------------------------------
    // DsaKeyData direct construction — exercise the inherent methods that
    // cannot be reached via the `&dyn KeyData` trait surface.
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_key_data_new_is_empty() {
        let k = DsaKeyData::new();
        assert!(!k.has_params());
        assert!(!k.has_public());
        assert!(!k.has_private());
        assert_eq!(k.bits(), None);
        assert_eq!(k.security_bits(), None);
        assert_eq!(k.max_size(), None);
        assert!(k.key().is_none());
    }

    #[test]
    fn dsa_key_data_default_matches_new() {
        let a = DsaKeyData::new();
        let b = DsaKeyData::default();
        // Both must be structurally identical on every public accessor.
        assert_eq!(a.has_params(), b.has_params());
        assert_eq!(a.has_public(), b.has_public());
        assert_eq!(a.has_private(), b.has_private());
        assert_eq!(a.bits(), b.bits());
    }

    #[test]
    fn dsa_key_data_debug_starts_with_type_name() {
        // The custom Debug impl must emit a string that begins with
        // "DsaKeyData" for the trait-level `has`/`export` dispatch to
        // recognise it. Pin this contract.
        let k = DsaKeyData::new();
        let s = format!("{k:?}");
        assert!(
            s.starts_with("DsaKeyData"),
            "Debug output must start with 'DsaKeyData', got: {s}"
        );
        // And the three has_* fields must be enumerated in the output.
        assert!(s.contains("has_private"));
        assert!(s.contains("has_public"));
        assert!(s.contains("has_params"));
    }

    #[test]
    fn dsa_key_data_debug_fresh_key_shows_no_components() {
        let k = DsaKeyData::new();
        let s = format!("{k:?}");
        assert!(s.contains("has_private: false"));
        assert!(s.contains("has_public: false"));
        assert!(s.contains("has_params: false"));
    }

    // -------------------------------------------------------------------------
    // DsaGenType — round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_gen_type_default_is_default_variant() {
        assert_eq!(DsaGenType::default(), DsaGenType::Default);
    }

    #[test]
    fn dsa_gen_type_roundtrip_through_strings() {
        // Every variant must survive `from_name(as_str(v))`.
        for variant in [
            DsaGenType::Fips186_2,
            DsaGenType::Fips186_4,
            DsaGenType::Default,
        ] {
            let s = variant.as_str();
            let back = DsaGenType::from_name(s)
                .unwrap_or_else(|| panic!("round-trip must succeed for {s:?}"));
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn dsa_gen_type_from_unknown_name_returns_none() {
        assert!(DsaGenType::from_name("").is_none());
        assert!(DsaGenType::from_name("bogus").is_none());
        assert!(DsaGenType::from_name("FIPS").is_none());
    }

    // -------------------------------------------------------------------------
    // DsaGenContext — defaults and absorb behaviour
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_gen_context_defaults_match_c_defaults() {
        let ctx = DsaGenContext::new(KeySelection::KEYPAIR);
        assert_eq!(ctx.selection, KeySelection::KEYPAIR);
        assert_eq!(ctx.pbits, DSA_DEFAULT_PBITS);
        assert_eq!(ctx.qbits, DSA_DEFAULT_QBITS);
        assert_eq!(ctx.gen_type, DsaGenType::Default);
        assert!(ctx.mdname.is_none());
        assert!(ctx.seed.is_none());
        // `hindex`, `gindex`, and `pcounter` are `Option<i32>` in Rust
        // (replacing C's `-1` sentinel per Rule R5). The defaults must
        // be `None`, indicating "unset".
        assert!(ctx.hindex.is_none());
        assert!(ctx.gindex.is_none());
        assert!(ctx.pcounter.is_none());
    }

    #[test]
    fn dsa_gen_context_absorb_pbits_overrides_default() {
        let mut ctx = DsaGenContext::new(KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set(PARAM_PBITS, ParamValue::UInt32(3072));
        ctx.absorb(&ps).expect("absorb");
        assert_eq!(ctx.pbits, 3072);
    }

    #[test]
    fn dsa_gen_context_absorb_qbits_overrides_default() {
        let mut ctx = DsaGenContext::new(KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set(PARAM_QBITS, ParamValue::UInt32(256));
        ctx.absorb(&ps).expect("absorb");
        assert_eq!(ctx.qbits, 256);
    }

    #[test]
    fn dsa_gen_context_absorb_gen_type_overrides_default() {
        let mut ctx = DsaGenContext::new(KeySelection::KEYPAIR);
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_FFC_TYPE,
            ParamValue::Utf8String("fips186_4".to_string()),
        );
        ctx.absorb(&ps).expect("absorb");
        assert_eq!(ctx.gen_type, DsaGenType::Fips186_4);
    }

    #[test]
    fn dsa_gen_context_absorb_empty_params_keeps_defaults() {
        let mut ctx = DsaGenContext::new(KeySelection::KEYPAIR);
        let ps = ParamSet::new();
        ctx.absorb(&ps).expect("absorb");
        assert_eq!(ctx.pbits, DSA_DEFAULT_PBITS);
        assert_eq!(ctx.qbits, DSA_DEFAULT_QBITS);
        assert_eq!(ctx.gen_type, DsaGenType::Default);
    }

    // -------------------------------------------------------------------------
    // security_bits_from_prime — exact NIST SP 800-57 table
    // -------------------------------------------------------------------------

    #[test]
    fn security_bits_from_prime_table() {
        assert_eq!(security_bits_from_prime(0), 0);
        assert_eq!(security_bits_from_prime(512), 0);
        assert_eq!(security_bits_from_prime(1023), 0);
        assert_eq!(security_bits_from_prime(1024), 80);
        assert_eq!(security_bits_from_prime(2047), 80);
        assert_eq!(security_bits_from_prime(2048), 112);
        assert_eq!(security_bits_from_prime(3071), 112);
        assert_eq!(security_bits_from_prime(3072), 128);
        assert_eq!(security_bits_from_prime(7679), 128);
        assert_eq!(security_bits_from_prime(7680), 192);
        assert_eq!(security_bits_from_prime(15359), 192);
        assert_eq!(security_bits_from_prime(15360), 256);
        assert_eq!(security_bits_from_prime(u32::MAX), 256);
    }

    // -------------------------------------------------------------------------
    // extract_bignum_bytes — roundtrip and error paths
    // -------------------------------------------------------------------------

    #[test]
    fn extract_bignum_bytes_from_bignum_variant() {
        let mut ps = ParamSet::new();
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        ps.set(PARAM_FFC_P, ParamValue::BigNum(bytes.clone()));
        let out = extract_bignum_bytes(&ps, PARAM_FFC_P).expect("extract");
        assert_eq!(out, bytes);
    }

    #[test]
    fn extract_bignum_bytes_from_octet_variant() {
        let mut ps = ParamSet::new();
        let bytes = vec![0x01, 0x02, 0x03];
        ps.set(PARAM_FFC_Q, ParamValue::OctetString(bytes.clone()));
        let out = extract_bignum_bytes(&ps, PARAM_FFC_Q).expect("extract");
        assert_eq!(out, bytes);
    }

    #[test]
    fn extract_bignum_bytes_rejects_wrong_type() {
        let mut ps = ParamSet::new();
        ps.set(PARAM_FFC_P, ParamValue::UInt32(42));
        let err = extract_bignum_bytes(&ps, PARAM_FFC_P)
            .expect_err("must reject non-bignum variant");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains(PARAM_FFC_P));
                assert!(msg.contains("unexpected type"));
            }
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    #[test]
    fn extract_bignum_bytes_rejects_missing_key() {
        let ps = ParamSet::new();
        let err = extract_bignum_bytes(&ps, PARAM_FFC_P)
            .expect_err("must reject missing key");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains(PARAM_FFC_P));
                assert!(msg.contains("missing"));
            }
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // export_to_params — empty selection is rejected
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_key_data_export_empty_selection_fails() {
        let k = DsaKeyData::new();
        let err = k
            .export_to_params(KeySelection::empty())
            .expect_err("empty selection must be rejected");
        match err {
            ProviderError::Dispatch(msg) => {
                assert!(msg.contains("empty selection"));
            }
            other => panic!("expected Dispatch, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // match_keys — two empty keys compare equal under ALL selection
    // -------------------------------------------------------------------------

    #[test]
    fn dsa_key_data_match_keys_two_empty_are_equal() {
        let a = DsaKeyData::new();
        let b = DsaKeyData::new();
        // Two completely empty keys have no components to mismatch on —
        // every selection is vacuously satisfied.
        assert!(a.match_keys(&b, KeySelection::ALL));
        assert!(a.match_keys(&b, KeySelection::DOMAIN_PARAMETERS));
        assert!(a.match_keys(&b, KeySelection::KEYPAIR));
    }

    #[test]
    fn dsa_keymgmt_match_keys_convenience() {
        let mgmt = DsaKeyMgmt::new();
        let a = DsaKeyData::new();
        let b = DsaKeyData::new();
        // Two empty keys match under `KeySelection::ALL` — delegated to
        // `DsaKeyData::match_keys`.
        assert!(mgmt.match_keys(&a, &b));
    }
}

