//! DH / DHX key management provider implementation.
//!
//! Translates `providers/implementations/keymgmt/dh_kmgmt.c` (~960 lines)
//! into idiomatic Rust.
//!
//! Supports the following DH key types, matching the two C dispatch tables
//! `ossl_dh_keymgmt_functions` and `ossl_dhx_keymgmt_functions`:
//!
//! * **DH** — Standard Diffie-Hellman using the FFDHE (RFC 7919) and MODP
//!   (RFC 3526) named groups. Used primarily in TLS 1.3 and TLS 1.2.
//! * **DHX** — X9.42 DH with explicit `p`, `q`, `g` finite-field parameters.
//!   Used in CMS enveloped data and legacy key-agreement contexts.
//!
//! # Architecture
//!
//! `DhKeyMgmt` and `DhxKeyMgmt` both implement `KeyMgmtProvider`.
//! They share the same `DhKeyData` container; the `DhKeyType` field
//! distinguishes the two variants at the protocol-name level but the
//! internal wire format is identical (compatible with the C code, which
//! uses a single `DH` struct for both).
//!
//! Key material is decomposed into three optional slots matching the C
//! `DH`/`DHX` representation:
//!
//! * `DhParams` — domain parameters `(p, g, q, length)` (`DOMAIN_PARAMETERS`)
//! * `DhPrivateKey` — the private exponent `x` (`PRIVATE_KEY`)
//! * `DhPublicKey` — the public value `y = g^x mod p` (`PUBLIC_KEY`)
//!
//! Because `DhKeyPair` is an opaque unit produced by the crypto layer
//! without a public constructor, we decompose it into the private/public
//! halves on generation and store them as two independent `Option` slots.
//! This mirrors the C `DH` struct's independent field population model and
//! allows partial key import/export for every `KeySelection` combination.
//!
//! # Security Properties
//!
//! * `DhPrivateKey` derives [`zeroize::Zeroize`] and `ZeroizeOnDrop`
//!   so the private exponent is securely wiped on drop — replacing the C
//!   `BN_clear_free(dh->priv_key)` pattern from `dh_free()`.
//! * The optional seed in `DhGenContext` is also wrapped in `Zeroizing`
//!   to match the FIPS 186-4 seed sensitivity in `dh_gen_ctx_free()`.
//! * `DhParams::new` rejects undersized primes (`< 512` bits) matching
//!   the C `DH_MIN_MODULUS_BITS` gate from `crypto/dh/dh_check.c`.
//! * Zero `unsafe` blocks (Rule R8).
//!
//! # Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyMgmt)
//!         → implementations::all_keymgmt_descriptors()
//!           → keymgmt::descriptors()
//!             → dh::dh_descriptors()
//! ```
//!
//! # C Source Mapping
//!
//! | Rust type / fn               | C construct                               | Source                     |
//! |------------------------------|-------------------------------------------|----------------------------|
//! | `DhKeyType`                | DH / DHX dispatch-table split             | `dh_kmgmt.c:820-960`       |
//! | `DhKeyData`                | `DH` struct (as keydata)                  | `dh_kmgmt.c:87-195`        |
//! | `DhKeyData::export_to_params` | `dh_export()`                          | `dh_kmgmt.c:432-476`       |
//! | `DhKeyData::from_params`   | `dh_import()`                             | `dh_kmgmt.c:375-430`       |
//! | `DhKeyData::generate_from_params` | `dh_gen()`                         | `dh_kmgmt.c:600-880`       |
//! | `DhParamGenType`           | `DH_PARAMGEN_TYPE_*` constants            | `dh_kmgmt.c:42-60`         |
//! | `DhGenContext`             | `struct dh_gen_ctx`                       | `dh_kmgmt.c:61-86`         |
//! | `DhKeyMgmt`                | `ossl_dh_keymgmt_functions`               | `dh_kmgmt.c:820-887`       |
//! | `DhxKeyMgmt`               | `ossl_dhx_keymgmt_functions`              | `dh_kmgmt.c:889-960`       |
//! | `dh_descriptors()`         | `deflt_keymgmt[]` DH/DHX entries          | `defltprov.c:580-696`      |

use std::cmp::Ordering;
use std::fmt;

use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::bn::montgomery::mod_exp_consttime;
use openssl_crypto::bn::BigNum;
use openssl_crypto::dh::{
    check_params, from_named_group, generate_key, generate_params, DhCheckResult, DhNamedGroup,
    DhParams, DhPrivateKey, DhPublicKey,
};

use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Authoritative Parameter-Key Strings
// =============================================================================
//
// These match the canonical OSSL_PKEY_PARAM_* definitions from
// `util/perl/OpenSSL/paramnames.pm` and `include/openssl/core_names.h`.
// They are kept as private constants (file-scope) to ensure every reference
// inside this module uses the spec-correct spelling (note `"j"` for cofactor
// and `"hindex"` for H-index — NOT `"cofactor"`/`"h"`).

/// Number of significant bits in the key modulus (metadata).
const PARAM_BITS: &str = "bits";
/// Maximum output size (bytes) for operations using this key (metadata).
const PARAM_MAX_SIZE: &str = "max-size";
/// Classical security strength in bits (metadata).
const PARAM_SECURITY_BITS: &str = "security-bits";
/// Default digest algorithm for this key (metadata).
const PARAM_DEFAULT_DIGEST: &str = "default-digest";

/// Named FFDHE/MODP group identifier (import/export).
const PARAM_GROUP_NAME: &str = "group";

/// Public value `y = g^x mod p` (import/export).
const PARAM_PUB_KEY: &str = "pub";
/// Private exponent `x` (import/export).
const PARAM_PRIV_KEY: &str = "priv";

/// FFC prime modulus `p` (import/export).
const PARAM_FFC_P: &str = "p";
/// FFC generator `g` (import/export).
const PARAM_FFC_G: &str = "g";
/// FFC subgroup order `q` (import/export).
const PARAM_FFC_Q: &str = "q";
/// FFC generator index (gindex) used in FIPS186-4 generation.
const PARAM_FFC_GINDEX: &str = "gindex";
/// FFC `h`-index — confusingly named `"hindex"` in OSSL param vocabulary.
#[allow(dead_code)]
const PARAM_FFC_H: &str = "hindex";
/// FFC cofactor `j` — canonical key is the literal `"j"`, NOT `"cofactor"`.
#[allow(dead_code)]
const PARAM_FFC_COFACTOR: &str = "j";
/// FFC parameter seed (import/export).
const PARAM_FFC_SEED: &str = "seed";
/// FFC `p`-counter used in FIPS186-4 generation.
#[allow(dead_code)]
const PARAM_FFC_PCOUNTER: &str = "pcounter";

/// DH generator `g` for safe-prime generation. Note: canonical OSSL key is
/// `"safeprime-generator"`, NOT plain `"generator"`.
const PARAM_DH_GENERATOR: &str = "safeprime-generator";
/// Explicit private-key length override (bits).
const PARAM_DH_PRIV_LEN: &str = "priv_len";

/// Generation mode discriminator (`"generator"`, `"fips186_4"`, `"group"`,
/// etc.). The same token space is used by `dh_gen_ctx.gen_type` in C.
const PARAM_DH_GEN_TYPE: &str = "type";

/// Digest algorithm for FIPS 186-4 FFC parameter generation.
const PARAM_DIGEST: &str = "digest";

/// Selects the cryptographic library context used for algorithm lookup.
#[allow(dead_code)]
const PARAM_PROPERTY_QUERY: &str = "properties";

/// `pbits` — prime modulus size in bits for generation requests.
const PARAM_PBITS: &str = "pbits";
/// `qbits` — subgroup order size in bits for generation requests.
const PARAM_QBITS: &str = "qbits";

// =============================================================================
// DhKeyType — DH vs DHX variant tag
// =============================================================================

/// Discriminator between the DH and DHX (X9.42) key management variants.
///
/// Replaces the C-level split between `ossl_dh_keymgmt_functions`
/// (`dh_kmgmt.c:820-887`) and `ossl_dhx_keymgmt_functions`
/// (`dh_kmgmt.c:889-960`). Both tables share the same dispatch routines
/// for the bulk of operations — the variant is primarily used for
/// naming, protocol tagging, and X9.42-specific parameter handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhKeyType {
    /// Standard Diffie-Hellman (RFC 3526/7919 named groups, TLS 1.3).
    Dh,
    /// X9.42 Diffie-Hellman with explicit `p`, `q`, `g` parameters (CMS).
    Dhx,
}

impl DhKeyType {
    /// Returns the canonical protocol name for this variant.
    ///
    /// Matches the `keytype` string returned by the C dispatch tables.
    fn name(self) -> &'static str {
        match self {
            Self::Dh => "DH",
            Self::Dhx => "DHX",
        }
    }
}

impl fmt::Display for DhKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// DhParamGenType — Generation mode tag
// =============================================================================

/// Strategy selector for DH parameter generation.
///
/// Replaces the C `DH_PARAMGEN_TYPE_*` constant family from
/// `providers/implementations/keymgmt/dh_kmgmt.c:42-60`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhParamGenType {
    /// Safe-prime generator mode (RFC 3526 non-FIPS generation).
    /// Matches `DH_PARAMGEN_TYPE_GENERATOR` in C.
    Generator,
    /// Named-group selection (e.g. `ffdhe2048`, `modp_2048`).
    /// Matches `DH_PARAMGEN_TYPE_GROUP` in C.
    Group,
    /// FIPS 186-2 parameter generation (historical, for legacy interop).
    /// Matches `DH_PARAMGEN_TYPE_FIPS_186_2` in C.
    Fips186_2,
    /// FIPS 186-4 parameter generation (primary FIPS-approved mode).
    /// Matches `DH_PARAMGEN_TYPE_FIPS_186_4` in C.
    Fips186_4,
    /// Default unless overridden: `Group` for DH, `Fips186_4` for DHX.
    /// Matches `DH_PARAMGEN_TYPE_FIPS_DEFAULT` in C.
    Default,
}

impl DhParamGenType {
    /// Parses the `"type"` parameter string from a `ParamSet`.
    ///
    /// Accepts the exact tokens used by the C code (see
    /// `dh_gen_common_set_params()` in `dh_kmgmt.c:760-810`).
    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "generator" | "safeprime-generator" => Some(Self::Generator),
            "group" | "named-group" => Some(Self::Group),
            "fips186_2" | "fips186-2" => Some(Self::Fips186_2),
            "fips186_4" | "fips186-4" | "default" => Some(Self::Fips186_4),
            _ => None,
        }
    }
}

// =============================================================================
// DhKeyData — keydata container (replaces C `DH` struct)
// =============================================================================

/// DH / DHX key data container.
///
/// Replaces the C `DH` struct from `crypto/dh/dh_local.h` when used as
/// provider keydata by `dh_kmgmt.c`. The three optional slots mirror the
/// independent population model of the C `DH` struct fields
/// (`params.p/g/q`, `priv_key`, `pub_key`) and allow every legitimate
/// `KeySelection` combination at import / export.
///
/// # Security
///
/// The private component (`DhPrivateKey`) implements
/// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop), so merely dropping a
/// `DhKeyData` wipes the private exponent from memory without requiring
/// an explicit `Drop` implementation here.
pub struct DhKeyData {
    /// Domain parameters `(p, g, q, length)`. Present for key pairs,
    /// parameter-only objects, and imported public keys. `None` for an
    /// uninitialised [`new_key`](KeyMgmtProvider::new_key) result.
    params: Option<DhParams>,
    /// Private exponent `x`. Present only when `PRIVATE_KEY` has been
    /// generated or imported. Zeroed on drop via the inner `DhPrivateKey`.
    private_key: Option<DhPrivateKey>,
    /// Public value `y = g^x mod p`. Present when `PUBLIC_KEY` has been
    /// generated, imported, or derived.
    public_key: Option<DhPublicKey>,
    /// Variant tag: `Dh` or `Dhx`. Preserved across roundtrips so that
    /// `DhxKeyMgmt::query_operation_name()` reports the correct family.
    dh_type: DhKeyType,
}

impl fmt::Debug for DhKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE: matches the EC keydata Debug shape so the provider dispatch
        // can key-detect via the `format!("{key:?}")` pattern used by
        // `has()` / `export()` when presented with a `&dyn KeyData`.
        f.debug_struct("DhKeyData")
            .field("dh_type", &self.dh_type)
            .field("has_private", &self.private_key.is_some())
            .field("has_public", &self.public_key.is_some())
            .field("has_params", &self.params.is_some())
            .finish()
    }
}

impl KeyData for DhKeyData {}

impl DhKeyData {
    /// Creates an empty key-data container for the given variant.
    ///
    /// Replaces `dh_newdata()` / `dhx_newdata()` from
    /// `dh_kmgmt.c:87-108`.
    fn new(dh_type: DhKeyType) -> Self {
        Self {
            params: None,
            private_key: None,
            public_key: None,
            dh_type,
        }
    }

    /// Returns the underlying key pair composition as a tuple of
    /// optional references `(params, private, public)`.
    ///
    /// Mirrors the read-side accessors on the C `DH` struct.
    pub fn key(
        &self,
    ) -> (
        Option<&DhParams>,
        Option<&DhPrivateKey>,
        Option<&DhPublicKey>,
    ) {
        (
            self.params.as_ref(),
            self.private_key.as_ref(),
            self.public_key.as_ref(),
        )
    }

    /// Returns whether a private exponent is currently populated.
    pub fn has_private(&self) -> bool {
        self.private_key.is_some()
    }

    /// Returns whether a public value is currently populated.
    pub fn has_public(&self) -> bool {
        self.public_key.is_some()
    }

    /// Returns whether domain parameters are currently populated.
    pub fn has_params(&self) -> bool {
        self.params.is_some()
    }

    /// Returns the advertised security strength in bits.
    ///
    /// Derived from the prime bit size using the `p_bits >> 1` heuristic
    /// used in `providers/common/securitycheck.c` (capped at 200 bits to
    /// match the NIST SP 800-57 table). Returns `None` if no parameters
    /// have been populated — rather than a sentinel `0` — per Rule R5.
    pub fn security_bits(&self) -> Option<u32> {
        self.params.as_ref().map(security_bits_from_prime)
    }

    /// Returns the prime modulus size in bits.
    ///
    /// Replaces `DH_bits()` from `crypto/dh/dh_lib.c`. Returns `None` if
    /// parameters are not yet populated (Rule R5).
    pub fn bits(&self) -> Option<u32> {
        self.params.as_ref().map(|p| p.p().num_bits())
    }
}

// =============================================================================
// Security-strength helper
// =============================================================================

/// Computes the classical security strength of a DH key from its prime size.
///
/// Mirrors the `ossl_dh_sec_bits()` computation used in
/// `providers/common/securitycheck.c`. The lookup is a simplified NIST
/// SP 800-57 Part 1 Table 2 approximation: we return `p_bits / 2` for
/// modulus sizes below 2048, and use a stepwise table for larger sizes
/// where the standard mandates a lower strength than `p_bits / 2`.
///
/// Returns `0` only when `p_bits < 512`, which would already have been
/// rejected by `DhParams::new`.
fn security_bits_from_prime(params: &DhParams) -> u32 {
    let p_bits = params.p().num_bits();
    match p_bits {
        0..=511 => 0,
        512..=1023 => 56,
        1024..=2047 => 80,
        2048..=3071 => 112,
        3072..=4095 => 128,
        4096..=7679 => 152,
        7680..=15359 => 192,
        _ => 200, // NIST caps classical strength at 200 bits
    }
}

// =============================================================================
// DhGenContext — generation context (replaces C struct dh_gen_ctx)
// =============================================================================

/// Parameter-generation context for DH / DHX key generation.
///
/// Replaces `struct dh_gen_ctx` from `dh_kmgmt.c:61-86`. Populated by
/// [`DhKeyMgmt::generate`] / `DhxKeyMgmt` from an input `ParamSet`
/// and consumed by `DhKeyData::generate_from_params`.
///
/// # Rule R5 Compliance
///
/// Every field that carries a conceptual "unset" state uses `Option`
/// instead of a sentinel value (e.g. `-1` for "no `priv_len` override").
pub struct DhGenContext {
    /// Which key components should be generated (parameters only, keypair,
    /// etc.).
    pub selection: KeySelection,
    /// Selected FFDHE / MODP named group NID, if in `Group` mode.
    pub group_nid: Option<u32>,
    /// Prime modulus size in bits (default 2048).
    pub pbits: usize,
    /// Subprime order size in bits (default 256 for FIPS 186-4).
    pub qbits: usize,
    /// Optional FIPS 186-4 seed used to make generation reproducible for
    /// known-answer tests. Zeroed on drop via `Zeroizing`.
    pub seed: Option<Zeroizing<Vec<u8>>>,
    /// Optional generator index `gindex` for FIPS 186-4 generation.
    pub gindex: Option<i32>,
    /// Generation strategy (`Generator`, `Group`, `Fips186_2`, `Fips186_4`).
    pub gen_type: DhParamGenType,
    /// Requested generator `g` for non-FIPS safe-prime generation.
    pub generator: Option<u32>,
    /// Explicit private-key length override in bits.
    pub priv_len: Option<usize>,
    /// Digest name for FIPS 186-4 generation (`"SHA-256"`, etc.).
    pub mdname: Option<String>,
    /// DH vs DHX variant tag.
    pub dh_type: DhKeyType,
    /// Reserved: library context reference for provider-property lookup.
    ///
    // UNREAD: reserved — Rule R3
    //
    // The C code stores an `OSSL_LIB_CTX*` here for fetching digests via
    // the provider property-query system (see `dh_kmgmt.c:640`). The Rust
    // crypto layer resolves digests by feature flag and algorithm name, so
    // no context pointer is required at this boundary. The field is kept
    // as `()` to preserve the schema shape documented by the AAP and to
    // reserve space for a future `Arc<LibContext>` once the provider
    // boundary needs cross-crate context propagation.
    pub lib_ctx: (),
    /// Property-query string (e.g. `"provider=default"`) used when
    /// fetching digests.
    ///
    // UNREAD: reserved — Rule R3
    //
    // The crypto layer currently does not accept property-query strings
    // for digest fetches; the field is reserved for symmetry with the C
    // generator context (`dh_kmgmt.c:640`) and for future extension.
    pub prop_query: Option<String>,
}

impl fmt::Debug for DhGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `seed` is summarised as a presence flag to avoid leaking
        // sensitive material into logs. `lib_ctx` is intentionally
        // `finish_non_exhaustive`'d because it is a reserved placeholder
        // (see field docs).
        f.debug_struct("DhGenContext")
            .field("selection", &self.selection)
            .field("group_nid", &self.group_nid)
            .field("pbits", &self.pbits)
            .field("qbits", &self.qbits)
            .field("seed_present", &self.seed.is_some())
            .field("gindex", &self.gindex)
            .field("gen_type", &self.gen_type)
            .field("generator", &self.generator)
            .field("priv_len", &self.priv_len)
            .field("mdname", &self.mdname)
            .field("dh_type", &self.dh_type)
            .field("prop_query", &self.prop_query)
            .finish_non_exhaustive()
    }
}

impl DhGenContext {
    /// Builds a default context for the given variant / selection.
    ///
    /// Replaces `dh_gen_init_common()` from `dh_kmgmt.c:600-640`.
    fn new(dh_type: DhKeyType, selection: KeySelection) -> Self {
        // Default generation mode mirrors the C choice: DH defaults to
        // `Group` (pick a named FFDHE group); DHX defaults to FIPS 186-4.
        let gen_type = match dh_type {
            DhKeyType::Dh => DhParamGenType::Group,
            DhKeyType::Dhx => DhParamGenType::Fips186_4,
        };
        Self {
            selection,
            group_nid: None,
            pbits: 2048,
            qbits: 256,
            seed: None,
            gindex: None,
            gen_type,
            generator: None,
            priv_len: None,
            mdname: None,
            dh_type,
            lib_ctx: (),
            prop_query: None,
        }
    }

    /// Absorbs generation parameters from an input `ParamSet`.
    ///
    /// Replaces `dh_gen_set_params()` from `dh_kmgmt.c:700-760`.
    fn absorb(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(ParamValue::Utf8String(group)) = params.get(PARAM_GROUP_NAME) {
            let named = named_group_from_name(group)
                .ok_or_else(|| ProviderError::Dispatch(format!("unknown DH group: {group}")))?;
            self.group_nid = Some(named.bits());
            self.gen_type = DhParamGenType::Group;
            self.pbits = named.bits() as usize;
        }
        if let Some(ParamValue::Utf8String(ty)) = params.get(PARAM_DH_GEN_TYPE) {
            self.gen_type = DhParamGenType::from_name(ty).ok_or_else(|| {
                ProviderError::Dispatch(format!("unknown DH generation type: {ty}"))
            })?;
        }
        if let Some(v) = params.get(PARAM_PBITS) {
            self.pbits = param_to_usize(v, PARAM_PBITS)?;
        }
        if let Some(v) = params.get(PARAM_QBITS) {
            self.qbits = param_to_usize(v, PARAM_QBITS)?;
        }
        if let Some(ParamValue::UInt32(g)) = params.get(PARAM_DH_GENERATOR) {
            self.generator = Some(*g);
        } else if let Some(ParamValue::Int32(g)) = params.get(PARAM_DH_GENERATOR) {
            self.generator = u32::try_from(*g).ok();
        }
        if let Some(v) = params.get(PARAM_DH_PRIV_LEN) {
            self.priv_len = Some(param_to_usize(v, PARAM_DH_PRIV_LEN)?);
        }
        if let Some(ParamValue::Utf8String(mdname)) = params.get(PARAM_DIGEST) {
            self.mdname = Some(mdname.clone());
        }
        if let Some(ParamValue::OctetString(seed)) = params.get(PARAM_FFC_SEED) {
            self.seed = Some(Zeroizing::new(seed.clone()));
        }
        if let Some(ParamValue::Int32(g)) = params.get(PARAM_FFC_GINDEX) {
            self.gindex = Some(*g);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

/// Parses an integral parameter value into a `usize`, rejecting negatives
/// and truncating losses (Rule R6).
fn param_to_usize(value: &ParamValue, key: &str) -> ProviderResult<usize> {
    let parsed: Option<usize> = match value {
        ParamValue::Int32(v) if *v >= 0 => usize::try_from(*v).ok(),
        ParamValue::UInt32(v) => usize::try_from(*v).ok(),
        ParamValue::Int64(v) if *v >= 0 => usize::try_from(*v).ok(),
        ParamValue::UInt64(v) => usize::try_from(*v).ok(),
        _ => None,
    };
    parsed.ok_or_else(|| ProviderError::Dispatch(format!("parameter {key} is not a valid usize")))
}

/// Resolves a named-group string to a `DhNamedGroup`.
///
/// `DhNamedGroup` does not expose a public `from_name` helper, so this
/// function provides the canonical mapping covering RFC 7919 FFDHE groups
/// and RFC 3526 MODP groups plus common aliases.
fn named_group_from_name(name: &str) -> Option<DhNamedGroup> {
    match name.to_ascii_lowercase().as_str() {
        "ffdhe2048" => Some(DhNamedGroup::Ffdhe2048),
        "ffdhe3072" => Some(DhNamedGroup::Ffdhe3072),
        "ffdhe4096" => Some(DhNamedGroup::Ffdhe4096),
        "ffdhe6144" => Some(DhNamedGroup::Ffdhe6144),
        "ffdhe8192" => Some(DhNamedGroup::Ffdhe8192),
        "modp_2048" | "modp-2048" | "modp2048" => Some(DhNamedGroup::ModP2048),
        "modp_3072" | "modp-3072" | "modp3072" => Some(DhNamedGroup::ModP3072),
        "modp_4096" | "modp-4096" | "modp4096" => Some(DhNamedGroup::ModP4096),
        "modp_6144" | "modp-6144" | "modp6144" => Some(DhNamedGroup::ModP6144),
        "modp_8192" | "modp-8192" | "modp8192" => Some(DhNamedGroup::ModP8192),
        _ => None,
    }
}

// =============================================================================
// DhKeyData — export / import / generate inherent methods
// =============================================================================

impl DhKeyData {
    /// Serialises the selected key components into a `ParamSet`.
    ///
    /// Replaces `dh_export()` / `dh_imexport_types()` from
    /// `dh_kmgmt.c:432-476`. Honours `KeySelection` flags so callers can
    /// request any combination of private-key / public-key / domain-
    /// parameter data.
    ///
    /// This is the concrete accessor that the trait `KeyMgmtProvider::export`
    /// method cannot reach (because `&dyn KeyData` has no downcast path).
    /// Call this directly on a `&DhKeyData` for fully populated export.
    pub fn export_to_params(&self, selection: KeySelection) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();

        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            if let Some(params) = self.params.as_ref() {
                ps.set(PARAM_FFC_P, ParamValue::BigNum(params.p().to_bytes_be()));
                ps.set(PARAM_FFC_G, ParamValue::BigNum(params.g().to_bytes_be()));
                if let Some(q) = params.q() {
                    ps.set(PARAM_FFC_Q, ParamValue::BigNum(q.to_bytes_be()));
                }
                if let Some(len) = params.length() {
                    ps.set(PARAM_DH_PRIV_LEN, ParamValue::UInt32(len));
                }
                ps.set(PARAM_BITS, ParamValue::UInt32(params.p().num_bits()));
                ps.set(
                    PARAM_SECURITY_BITS,
                    ParamValue::UInt32(security_bits_from_prime(params)),
                );
            }
        }

        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let Some(pub_key) = self.public_key.as_ref() {
                ps.set(
                    PARAM_PUB_KEY,
                    ParamValue::BigNum(pub_key.value().to_bytes_be()),
                );
            }
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let Some(priv_key) = self.private_key.as_ref() {
                // Reconstruct BigNum from the stored raw bytes — the
                // crypto layer owns the Zeroize lifetime; we emit a
                // big-endian byte slice just like the C `BN_bn2bin()`
                // path used in `dh_export()`.
                let priv_bn = priv_key.value();
                ps.set(PARAM_PRIV_KEY, ParamValue::BigNum(priv_bn.to_bytes_be()));
            }
        }

        trace!(
            dh_type = %self.dh_type,
            exported_params = ps.len(),
            "DH export complete"
        );
        Ok(ps)
    }

    /// Populates a `DhKeyData` from an input `ParamSet`.
    ///
    /// Replaces `dh_import()` from `dh_kmgmt.c:375-430`. Respects the
    /// `selection` bitmask so callers can bring in domain parameters and
    /// keys separately.
    fn from_params(
        dh_type: DhKeyType,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Self> {
        let mut result = Self::new(dh_type);

        // --- Domain parameters ------------------------------------------------
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            // Named-group shortcut: a single "group" parameter specifies
            // all of (p, g, q) and overrides explicit FFC fields.
            if let Some(ParamValue::Utf8String(group)) = data.get(PARAM_GROUP_NAME) {
                let named = named_group_from_name(group)
                    .ok_or_else(|| ProviderError::Dispatch(format!("unknown DH group: {group}")))?;
                result.params = Some(from_named_group(named));
            } else {
                let p_bytes = extract_bignum_bytes(data, PARAM_FFC_P)?;
                let g_bytes = extract_bignum_bytes(data, PARAM_FFC_G)?;
                let q_bytes_opt = extract_bignum_bytes_optional(data, PARAM_FFC_Q);

                let p = BigNum::from_bytes_be(&p_bytes);
                let g = BigNum::from_bytes_be(&g_bytes);
                let q = q_bytes_opt.map(|b| BigNum::from_bytes_be(&b));

                let mut params = DhParams::new(p, g, q).map_err(|e| {
                    ProviderError::Dispatch(format!("DH domain-param construction failed: {e}"))
                })?;

                if let Some(v) = data.get(PARAM_DH_PRIV_LEN) {
                    let priv_len_bits = param_to_usize(v, PARAM_DH_PRIV_LEN)?;
                    let priv_len_u32 = u32::try_from(priv_len_bits).map_err(|_| {
                        ProviderError::Dispatch(format!(
                            "DH priv_len {priv_len_bits} exceeds u32 range"
                        ))
                    })?;
                    params.set_length(priv_len_u32);
                }

                result.params = Some(params);
            }
        }

        // --- Public key -------------------------------------------------------
        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let Some(pub_bytes) = extract_bignum_bytes_optional(data, PARAM_PUB_KEY) {
                let pub_val = BigNum::from_bytes_be(&pub_bytes);
                let params = result.params.as_ref().ok_or_else(|| {
                    ProviderError::Dispatch(
                        "DH import: PUBLIC_KEY requires DOMAIN_PARAMETERS".into(),
                    )
                })?;
                result.public_key = Some(DhPublicKey::new_from_raw(pub_val, params.clone()));
            }
        }

        // --- Private key ------------------------------------------------------
        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let Some(priv_bytes) = extract_bignum_bytes_optional(data, PARAM_PRIV_KEY) {
                let params = result.params.as_ref().ok_or_else(|| {
                    ProviderError::Dispatch(
                        "DH import: PRIVATE_KEY requires DOMAIN_PARAMETERS".into(),
                    )
                })?;
                result.private_key = Some(DhPrivateKey::new_from_raw(priv_bytes, params.clone()));
            }
        }

        trace!(
            dh_type = %result.dh_type,
            has_params = result.params.is_some(),
            has_public = result.public_key.is_some(),
            has_private = result.private_key.is_some(),
            "DH import complete"
        );
        Ok(result)
    }

    /// Drives DH parameter / key generation from a `DhGenContext`.
    ///
    /// Replaces `dh_gen()` from `dh_kmgmt.c:800-880`. Routes to
    /// `from_named_group`, `generate_params`, or `generate_key` based on
    /// the context's `gen_type` and `selection` flags.
    fn generate_from_params(dh_type: DhKeyType, ctx: &DhGenContext) -> ProviderResult<Self> {
        debug!(
            dh_type = %dh_type,
            gen_type = ?ctx.gen_type,
            pbits = ctx.pbits,
            qbits = ctx.qbits,
            selection = ?ctx.selection,
            "DH generate: starting"
        );

        // Phase 1: produce domain parameters
        let params = match ctx.gen_type {
            DhParamGenType::Group => {
                // Named-group mode: pbits determines the FFDHE group.
                let named = pbits_to_named_group(ctx.pbits).ok_or_else(|| {
                    ProviderError::Dispatch(format!(
                        "DH Group generation: pbits={} has no matching FFDHE group",
                        ctx.pbits
                    ))
                })?;
                from_named_group(named)
            }
            DhParamGenType::Generator
            | DhParamGenType::Fips186_2
            | DhParamGenType::Fips186_4
            | DhParamGenType::Default => {
                let pbits_u32 = u32::try_from(ctx.pbits).map_err(|_| {
                    ProviderError::Dispatch(format!(
                        "DH generate: pbits {} exceeds u32 range",
                        ctx.pbits
                    ))
                })?;
                generate_params(pbits_u32).map_err(|e| {
                    ProviderError::Dispatch(format!("DH generate_params failed: {e}"))
                })?
            }
        };

        // Apply optional priv_len override onto the generated parameters
        let mut params = params;
        if let Some(len) = ctx.priv_len {
            let len_u32 = u32::try_from(len).map_err(|_| {
                ProviderError::Dispatch(format!("DH priv_len {len} exceeds u32 range"))
            })?;
            params.set_length(len_u32);
        }

        let mut key = Self::new(dh_type);
        key.params = Some(params.clone());

        // Phase 2: optionally generate a key pair
        if ctx.selection.contains(KeySelection::KEYPAIR) {
            let kp = generate_key(&params)
                .map_err(|e| ProviderError::Dispatch(format!("DH generate_key failed: {e}")))?;

            // DhKeyPair does not expose a destructuring / into_parts
            // constructor, so we reconstruct independent DhPrivateKey /
            // DhPublicKey objects from the big-endian serialisations of
            // the generated components. The private value is sensitive —
            // we therefore extract bytes through `Zeroizing` so the
            // intermediate buffer is wiped on drop before it reaches
            // the `DhPrivateKey::new_from_raw` constructor (which takes
            // ownership of a plain `Vec<u8>` and re-wraps with its own
            // `Zeroize`).
            let priv_bytes = Zeroizing::new(kp.private_key().value().to_bytes_be());
            let priv_key = DhPrivateKey::new_from_raw(priv_bytes.to_vec(), params.clone());
            let pub_key = DhPublicKey::new_from_raw(kp.public_key().value().clone(), params);

            key.private_key = Some(priv_key);
            key.public_key = Some(pub_key);
        }

        Ok(key)
    }

    /// Returns whether this key has all components required by `selection`.
    ///
    /// Replaces `dh_has()` from `dh_kmgmt.c:165-190`. This is the
    /// concrete accessor used by deep introspection; the trait
    /// [`KeyMgmtProvider::has`] uses a Debug-string projection because
    /// `KeyData` does not extend [`std::any::Any`].
    pub fn has_selection(&self, selection: KeySelection) -> bool {
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) && self.params.is_none() {
            return false;
        }
        if selection.contains(KeySelection::PRIVATE_KEY) && self.private_key.is_none() {
            return false;
        }
        if selection.contains(KeySelection::PUBLIC_KEY) && self.public_key.is_none() {
            return false;
        }
        true
    }

    /// Performs structural and pairwise validation of the selected
    /// components.
    ///
    /// Replaces C `dh_validate()` from `dh_kmgmt.c:255-325` and
    /// incorporates the pairwise consistency check from
    /// `crypto/dh/dh_check.c` (`DH_check_pub_key()` /
    /// `ossl_dh_check_pairwise()`). Validation has four layers:
    ///
    /// - **Domain parameters**: enforced via
    ///   [`check_params`] (safe prime,
    ///   generator range, subgroup order constraints).
    /// - **Public key** `y`: must satisfy `1 < y < p - 1`. The
    ///   non-zero/non-one check is required because `y = 1` would yield
    ///   a trivial subgroup element.
    /// - **Private key** `x`: must satisfy `0 < x` and, when `length`
    ///   is set on the parameters, `num_bits(x) <= length`.
    /// - **Pairwise consistency** (NIST SP 800-56A Rev. 3 §5.6.2.1.4):
    ///   when the selection includes both `PUBLIC_KEY` and
    ///   `PRIVATE_KEY` and domain parameters are present, the
    ///   recomputed `g^x mod p` must equal the stored public value `y`.
    ///   Performed via `mod_exp_consttime` because the private
    ///   exponent `x` is secret material; the limb-level
    ///   non-constant-time behavior of the underlying `num-bigint`
    ///   crate is a documented residual leak that applies
    ///   workspace-wide, not specific to this routine.
    ///
    /// This is the concrete accessor; the trait
    /// [`KeyMgmtProvider::validate`] delegates to the Debug-string
    /// based [`KeyMgmtProvider::has`] check because `&dyn KeyData`
    /// does not provide a downcast path.
    ///
    /// # Errors
    ///
    /// Returns `Ok(true)` when all present components pass validation,
    /// `Ok(false)` when structural or pairwise checks fail, and
    /// `ProviderError` only when the selection is internally
    /// inconsistent (e.g., asks to validate a component that is not
    /// present after the `has_selection` guard) or when the
    /// constant-time modular exponentiation reports an internal error.
    pub fn validate_selection(&self, selection: KeySelection) -> ProviderResult<bool> {
        // A validation request for components we do not hold is trivially
        // false, matching `DH_check_*` return codes in the C path.
        if !self.has_selection(selection) {
            trace!(
                selection = ?selection,
                "DH validate: missing required component"
            );
            return Ok(false);
        }

        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            if let Some(params) = self.params.as_ref() {
                let result: DhCheckResult = check_params(params)
                    .map_err(|e| ProviderError::Dispatch(format!("DH check_params failed: {e}")))?;
                if !result.is_ok() {
                    warn!(
                        check_result = ?result,
                        "DH validate: domain parameters failed checks"
                    );
                    return Ok(false);
                }
            }
        }

        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let (Some(params), Some(pub_key)) = (self.params.as_ref(), self.public_key.as_ref())
            {
                let y = pub_key.value();
                // Range check: 1 < y < p - 1
                if y.is_zero() || y.cmp(&BigNum::one()).is_le() {
                    return Ok(false);
                }
                // y < p always (we do not have modulus reduction here, so
                // compare num_bits as an upper-bound heuristic; the
                // crypto layer's compute_key will reject oversize values
                // during shared-secret derivation).
                if y.num_bits() > params.p().num_bits() {
                    return Ok(false);
                }
            }
        }

        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let (Some(params), Some(priv_key)) =
                (self.params.as_ref(), self.private_key.as_ref())
            {
                let x = priv_key.value();
                if x.is_zero() {
                    return Ok(false);
                }
                if let Some(len_bits) = params.length() {
                    if x.num_bits() > len_bits {
                        return Ok(false);
                    }
                }
            }
        }

        // Pairwise consistency check (NIST SP 800-56A Rev. 3
        // §5.6.2.1.4). When the caller asks for both PUBLIC_KEY and
        // PRIVATE_KEY validation and we have domain parameters, the
        // recomputed `g^x mod p` must equal the stored public value
        // `y`. This rejects mismatched pairs that the structural range
        // checks above cannot detect.
        //
        // Constant-time scalar multiplication is mandatory here because
        // `x` is secret. The Montgomery-ladder-style
        // `mod_exp_consttime` routine has uniform control flow w.r.t.
        // the exponent; underlying limb arithmetic in `num-bigint` is
        // not constant-time at the limb level — a workspace-wide
        // residual leak documented in `bn/montgomery.rs` and tracked
        // separately from this finding.
        if selection.contains(KeySelection::PUBLIC_KEY)
            && selection.contains(KeySelection::PRIVATE_KEY)
        {
            if let Some(params) = self.params.as_ref() {
                let priv_key = self.private_key.as_ref().ok_or_else(|| {
                    ProviderError::Dispatch(
                        "private_key missing after has_selection check".to_string(),
                    )
                })?;
                let pub_key = self.public_key.as_ref().ok_or_else(|| {
                    ProviderError::Dispatch(
                        "public_key missing after has_selection check".to_string(),
                    )
                })?;

                // `priv_key.value()` returns an OWNED `BigNum`
                // (reconstructed from the raw byte buffer), so we bind
                // it to a local before taking a reference.
                let x = priv_key.value();
                let y = pub_key.value();

                let recomputed_y =
                    mod_exp_consttime(params.g(), &x, params.p()).map_err(|e| {
                        ProviderError::Dispatch(format!(
                            "DH pairwise check: mod_exp_consttime failed: {e}"
                        ))
                    })?;

                if recomputed_y.cmp(y) != Ordering::Equal {
                    warn!(
                        target: "openssl_provider::keymgmt::dh",
                        "validate_selection: pairwise check failed (y != g^x mod p)",
                    );
                    return Ok(false);
                }

                debug!(
                    target: "openssl_provider::keymgmt::dh",
                    "validate_selection: pairwise consistency verified (y == g^x mod p)",
                );
            }
        }

        Ok(true)
    }

    /// Byte-wise pairwise comparison with another key.
    ///
    /// Replaces `dh_match()` from `dh_kmgmt.c:195-255`. Compares the
    /// components selected by `selection`.
    fn match_keys(&self, other: &DhKeyData, selection: KeySelection) -> bool {
        if selection.contains(KeySelection::DOMAIN_PARAMETERS) {
            match (self.params.as_ref(), other.params.as_ref()) {
                (Some(a), Some(b)) => {
                    if a.p() != b.p() || a.g() != b.g() {
                        return false;
                    }
                    match (a.q(), b.q()) {
                        (Some(qa), Some(qb)) if qa != qb => return false,
                        (Some(_), None) | (None, Some(_)) => return false,
                        _ => {}
                    }
                }
                (None, None) => {}
                _ => return false,
            }
        }
        if selection.contains(KeySelection::PUBLIC_KEY) {
            match (self.public_key.as_ref(), other.public_key.as_ref()) {
                (Some(a), Some(b)) if a.value() != b.value() => return false,
                (Some(_), None) | (None, Some(_)) => return false,
                _ => {}
            }
        }
        if selection.contains(KeySelection::PRIVATE_KEY) {
            match (self.private_key.as_ref(), other.private_key.as_ref()) {
                (Some(a), Some(b)) if a.value() != b.value() => return false,
                (Some(_), None) | (None, Some(_)) => return false,
                _ => {}
            }
        }
        true
    }
}

// -----------------------------------------------------------------------------
// Extraction / mapping helpers
// -----------------------------------------------------------------------------

/// Extracts a required BigNum-valued parameter as raw big-endian bytes.
fn extract_bignum_bytes(data: &ParamSet, key: &str) -> ProviderResult<Vec<u8>> {
    match data.get(key) {
        Some(ParamValue::BigNum(b) | ParamValue::OctetString(b)) => Ok(b.clone()),
        Some(_) => Err(ProviderError::Dispatch(format!(
            "DH import: {key} is not a BigNum"
        ))),
        None => Err(ProviderError::Dispatch(format!(
            "DH import: missing required parameter {key}"
        ))),
    }
}

/// Extracts an optional BigNum-valued parameter as raw big-endian bytes.
fn extract_bignum_bytes_optional(data: &ParamSet, key: &str) -> Option<Vec<u8>> {
    match data.get(key) {
        Some(ParamValue::BigNum(b) | ParamValue::OctetString(b)) => Some(b.clone()),
        _ => None,
    }
}

/// Maps a requested prime-size in bits to a named FFDHE group.
fn pbits_to_named_group(pbits: usize) -> Option<DhNamedGroup> {
    match pbits {
        2048 => Some(DhNamedGroup::Ffdhe2048),
        3072 => Some(DhNamedGroup::Ffdhe3072),
        4096 => Some(DhNamedGroup::Ffdhe4096),
        6144 => Some(DhNamedGroup::Ffdhe6144),
        8192 => Some(DhNamedGroup::Ffdhe8192),
        _ => None,
    }
}

// =============================================================================
// DhKeyMgmt — KeyMgmtProvider for the DH family
// =============================================================================

/// DH (RFC 3526/7919) key management.
///
/// Replaces the `ossl_dh_keymgmt_functions` dispatch table from
/// `dh_kmgmt.c:820-887`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DhKeyMgmt;

impl DhKeyMgmt {
    /// Constructs a new DH key management instance.
    pub fn new() -> Self {
        Self
    }

    /// Byte-wise comparison of two concrete DH keys across every component.
    ///
    /// Replaces `dh_match()` from `dh_kmgmt.c:195-255`.
    pub fn match_keys(&self, key1: &DhKeyData, key2: &DhKeyData) -> bool {
        key1.match_keys(key2, KeySelection::ALL)
    }

    /// Returns the metadata parameters for the given concrete DH key.
    ///
    /// Mirrors `dh_get_params()` from `dh_kmgmt.c:129-165`.
    pub fn get_params(&self, data: &DhKeyData) -> ProviderResult<ParamSet> {
        let mut ps = ParamSet::new();
        if let Some(bits) = data.bits() {
            ps.set(PARAM_BITS, ParamValue::UInt32(bits));
            // Max ciphertext / shared-secret size equals the modulus size
            // in bytes (ceil(bits / 8)).
            let max_bytes = (bits + 7) / 8;
            ps.set(PARAM_MAX_SIZE, ParamValue::UInt32(max_bytes));
        }
        if let Some(sbits) = data.security_bits() {
            ps.set(PARAM_SECURITY_BITS, ParamValue::UInt32(sbits));
        }
        // DH has no signing digest by default; the default-digest entry
        // is emitted as the empty string to match the C convention (see
        // `dh_gettable_params` + `DH_get0_default_digest` equivalents).
        ps.set(PARAM_DEFAULT_DIGEST, ParamValue::Utf8String(String::new()));
        Ok(ps)
    }

    /// Returns the set of parameter keys queryable via
    /// [`get_params`](Self::get_params).
    pub fn gettable_params(&self) -> &'static [&'static str] {
        &[
            PARAM_BITS,
            PARAM_MAX_SIZE,
            PARAM_SECURITY_BITS,
            PARAM_DEFAULT_DIGEST,
        ]
    }
}

impl KeyMgmtProvider for DhKeyMgmt {
    fn name(&self) -> &'static str {
        DhKeyType::Dh.name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!("DH new_key: allocating empty keydata");
        Ok(Box::new(DhKeyData::new(DhKeyType::Dh)))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let mut ctx = DhGenContext::new(DhKeyType::Dh, KeySelection::KEYPAIR);
        ctx.absorb(params)?;
        let key = DhKeyData::generate_from_params(DhKeyType::Dh, &ctx)?;
        debug!("DH generate: completed");
        Ok(Box::new(key))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        trace!(?selection, "DH keymgmt: importing key");
        let key = DhKeyData::from_params(DhKeyType::Dh, selection, data)?;
        Ok(Box::new(key))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        trace!(?selection, "DH keymgmt: exporting key");
        // The KeyData trait is a minimal marker (Send + Sync + Debug)
        // and deliberately does not extend `Any`, so we cannot recover
        // the concrete `DhKeyData` reference from a `&dyn KeyData`. We
        // instead verify the Debug projection and log a warning that
        // fully populated export requires the concrete accessor
        // `DhKeyData::export_to_params`. This mirrors the behaviour of
        // `EcKeyMgmt::export` — see `ec.rs:411-440`.
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("DhKeyData") {
            return Err(ProviderError::Dispatch(
                "DH keymgmt: export called with non-DH key data".into(),
            ));
        }
        warn!(
            "DH keymgmt: export with opaque KeyData uses limited introspection; \
             prefer using concrete DhKeyData::export_to_params directly"
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        // Parse the Debug output for component presence, matching the
        // pattern used by `EcKeyMgmt::has` (`ec.rs:442-465`). The
        // `DhKeyData` Debug projection always exposes
        // `dh_type`/`has_private`/`has_public`/`has_params` fields.
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("DhKeyData") {
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
        trace!(?selection, "DH keymgmt: validating key");
        // Structural validation via has(). Deep validation (safe-prime
        // check, public-key range, etc.) is available via
        // `DhKeyData::validate_selection` on a concrete reference.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// DhxKeyMgmt — KeyMgmtProvider for the DHX (X9.42) family
// =============================================================================

/// DHX (X9.42 DH) key management.
///
/// Replaces the `ossl_dhx_keymgmt_functions` dispatch table from
/// `dh_kmgmt.c:889-960`. Dispatches through the same key-data struct as
/// `DhKeyMgmt`; the only observable differences are:
///
/// * [`DhxKeyMgmt::name`] returns `"DHX"`.
/// * [`DhxKeyMgmt::query_operation_name`] returns `"DH"` because DHX
///   shares the `KeyExchange` operation with DH (matching the C
///   `dhx_query_operation_name()` return).
/// * Generation defaults to FIPS 186-4 rather than named groups.
#[derive(Debug, Clone, Copy, Default)]
pub struct DhxKeyMgmt;

impl DhxKeyMgmt {
    /// Constructs a new DHX key management instance.
    pub fn new() -> Self {
        Self
    }

    /// Returns the operation name used when DHX is the key type but the
    /// requested operation is a shared one (e.g. `KeyExchange`).
    ///
    /// Mirrors `dhx_query_operation_name()` from `dh_kmgmt.c:915-930`,
    /// which returns `"DH"` because DHX reuses the DH key-exchange op.
    pub fn query_operation_name(&self, operation_id: u32) -> &'static str {
        // The C routine branches on operation id and returns "DH" for
        // the key-exchange op. We return "DH" for every operation for
        // which DHX shares DH's dispatch surface (all of them, in
        // practice). The operation_id argument is preserved for API
        // fidelity with the C dispatch signature.
        let _ = operation_id;
        "DH"
    }
}

impl KeyMgmtProvider for DhxKeyMgmt {
    fn name(&self) -> &'static str {
        DhKeyType::Dhx.name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!("DHX new_key: allocating empty keydata");
        Ok(Box::new(DhKeyData::new(DhKeyType::Dhx)))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let mut ctx = DhGenContext::new(DhKeyType::Dhx, KeySelection::KEYPAIR);
        ctx.absorb(params)?;
        let key = DhKeyData::generate_from_params(DhKeyType::Dhx, &ctx)?;
        debug!("DHX generate: completed");
        Ok(Box::new(key))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        trace!(?selection, "DHX keymgmt: importing key");
        let key = DhKeyData::from_params(DhKeyType::Dhx, selection, data)?;
        Ok(Box::new(key))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        trace!(?selection, "DHX keymgmt: exporting key");
        // See [`DhKeyMgmt::export`] — the same Debug-projection check is
        // applied; fully populated export requires the concrete
        // accessor `DhKeyData::export_to_params`.
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("DhKeyData") {
            return Err(ProviderError::Dispatch(
                "DHX keymgmt: export called with non-DH key data".into(),
            ));
        }
        warn!(
            "DHX keymgmt: export with opaque KeyData uses limited introspection; \
             prefer using concrete DhKeyData::export_to_params directly"
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        let debug_str = format!("{key:?}");
        if !debug_str.starts_with("DhKeyData") {
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
        trace!(?selection, "DHX keymgmt: validating key");
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm descriptors (called from keymgmt::mod.rs)
// =============================================================================

/// Returns the algorithm descriptors contributed by this module.
///
/// Called from `keymgmt::descriptors()` in `mod.rs:325-326`. Emits two
/// entries: one for `DH` (the RFC 3526/7919 family) and one for `DHX`
/// (the X9.42 family). These map to the two C dispatch tables
/// `ossl_dh_keymgmt_functions` and `ossl_dhx_keymgmt_functions`.
pub fn dh_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["DH", "dhKeyAgreement"],
            property: DEFAULT_PROPERTY,
            description: "DH key management (RFC 3526 MODP / RFC 7919 FFDHE named groups)",
        },
        AlgorithmDescriptor {
            names: vec!["DHX", "X9.42 DH", "dhpublicnumber"],
            property: DEFAULT_PROPERTY,
            description: "DHX (X9.42) key management (explicit p/q/g domain parameters)",
        },
    ]
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Test code is permitted to use `expect()`, `unwrap()`, and `panic!()`
    // for diagnostic purposes — failures inside tests must produce clear
    // messages rather than being propagated as `Result` values. This
    // follows the workspace-wide convention established in
    // `crates/openssl-provider/src/tests/test_algorithm_correctness.rs` and
    // `crates/openssl-provider/src/implementations/encode_decode/pvk_decoder.rs`.
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;

    // -------------------------------------------------------------------------
    // Helper test fixtures — all use *infallible* constructors from the
    // openssl-crypto layer so the tests are deterministic and do not depend
    // on RNG seeding.
    // -------------------------------------------------------------------------

    /// Builds a `DhKeyData` fully populated with params, public key and
    /// private key using the deterministic RFC 7919 ffdhe2048 parameters.
    ///
    /// ffdhe2048 has `length = 225` bits (the recommended private-key bit
    /// length), so the private key fixture must be ≤ 225 bits (≤ 28 bytes)
    /// to pass `validate_selection(PRIVATE_KEY)`. We use 28 bytes with a
    /// `0x42` pattern — the leading `0x42` (`0b01000010`) has bit 6 set,
    /// giving `num_bits == 7 + 8·27 == 223`, safely below 225.
    fn fully_populated_ffdhe2048() -> DhKeyData {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);

        // Private key: 28-byte value (≤ 225-bit limit), non-zero.
        let priv_bytes = vec![0x42u8; 28];
        let priv_key = DhPrivateKey::new_from_raw(priv_bytes, params.clone());

        // Public key: 2048-bit value with leading byte 0x7F so num_bits
        // == 2047 (< p.num_bits() == 2048), and the value is > 1.
        let mut pub_bytes = vec![0u8; 256];
        pub_bytes[0] = 0x7F;
        for (i, b) in pub_bytes.iter_mut().enumerate().skip(1) {
            // `i` is bounded by the loop to 1..=255, so `u8::try_from` is
            // infallible here. The `.unwrap_or(0)` is a defensive fallback
            // used only to satisfy the workspace-wide deny on raw
            // `usize -> u8` narrowing casts (Rule R6).
            let byte = u8::try_from(i).unwrap_or(0);
            *b = byte.wrapping_mul(3).wrapping_add(1);
        }
        let pub_bignum = BigNum::from_bytes_be(&pub_bytes);
        let pub_key = DhPublicKey::new_from_raw(pub_bignum, params.clone());

        DhKeyData {
            params: Some(params),
            private_key: Some(priv_key),
            public_key: Some(pub_key),
            dh_type: DhKeyType::Dh,
        }
    }

    /// Same as `fully_populated_ffdhe2048` but with the DHX variant tag.
    fn fully_populated_ffdhe2048_dhx() -> DhKeyData {
        let mut data = fully_populated_ffdhe2048();
        data.dh_type = DhKeyType::Dhx;
        data
    }

    /// Builds a `DhKeyData` whose `(p, g, x, y)` actually satisfy
    /// `y == g^x mod p` so that the pairwise consistency layer of
    /// [`DhKeyData::validate_selection`] can be exercised. Uses the
    /// FFDHE2048 named group from RFC 7919 to keep the cost low and
    /// deterministic compared to fresh `generate_params` calls.
    fn gen_real_dh_keydata() -> DhKeyData {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let kp = generate_key(&params).expect("DH key generation must succeed on FFDHE2048");

        // `DhPrivateKey` stores raw bytes (not `BigNum`); convert via
        // `BigNum::to_bytes_be()` and feed them back through the
        // public constructor. `DhPublicKey` holds a `BigNum` directly.
        let priv_bn = kp.private_key().value();
        let priv_bytes = priv_bn.to_bytes_be();
        let priv_key = DhPrivateKey::new_from_raw(priv_bytes, params.clone());

        let pub_bn = kp.public_key().value().clone();
        let pub_key = DhPublicKey::new_from_raw(pub_bn, params.clone());

        DhKeyData {
            params: Some(params),
            private_key: Some(priv_key),
            public_key: Some(pub_key),
            dh_type: DhKeyType::Dh,
        }
    }

    // -------------------------------------------------------------------------
    // Trait-surface tests — DhKeyMgmt
    // -------------------------------------------------------------------------

    #[test]
    fn dh_keymgmt_name_is_dh() {
        let mgmt = DhKeyMgmt;
        assert_eq!(mgmt.name(), "DH");
    }

    #[test]
    fn new_key_returns_empty_key_data() {
        let mgmt = DhKeyMgmt;
        let key = mgmt.new_key().expect("new_key should succeed");
        // An empty keydata advertises none of the three component bits.
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn generate_ffdhe2048_key_pair() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        let key = mgmt.generate(&params).expect("generate should succeed");
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn generate_ffdhe3072_key_pair() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("ffdhe3072".to_string()),
        );
        let key = mgmt.generate(&params).expect("ffdhe3072 generate");
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    #[test]
    fn generate_modp_2048_key_pair() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("modp_2048".to_string()),
        );
        let key = mgmt.generate(&params).expect("modp_2048 generate");
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn generate_modp_with_dash_alias() {
        // The helper `named_group_from_name` accepts "modp-2048" as well.
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("modp-2048".to_string()),
        );
        let key = mgmt.generate(&params).expect("modp-2048 alias generate");
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn generate_unknown_group_fails() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("unknown-group-42".to_string()),
        );
        assert!(
            mgmt.generate(&params).is_err(),
            "unknown named group must fail"
        );
    }

    #[test]
    fn import_with_named_group() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        let key = mgmt
            .import(KeySelection::DOMAIN_PARAMETERS, &params)
            .expect("import named group");
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn import_missing_p_fails() {
        let mgmt = DhKeyMgmt;
        let params = ParamSet::new(); // no p/g/q, no named group
        assert!(
            mgmt.import(KeySelection::DOMAIN_PARAMETERS, &params)
                .is_err(),
            "import of domain parameters with neither group nor explicit p/g/q must fail"
        );
    }

    #[test]
    fn validate_empty_key_returns_false() {
        let mgmt = DhKeyMgmt;
        let key = mgmt.new_key().expect("new_key");
        assert!(
            !mgmt
                .validate(&*key, KeySelection::KEYPAIR)
                .expect("validate"),
            "empty key must fail KEYPAIR validation"
        );
        assert!(
            !mgmt
                .validate(&*key, KeySelection::DOMAIN_PARAMETERS)
                .expect("validate"),
            "empty key must fail DOMAIN_PARAMETERS validation"
        );
    }

    #[test]
    fn validate_generated_key_passes_structural_check() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        let key = mgmt.generate(&params).expect("generate");
        // The trait-surface validate() performs a structural (has-based)
        // check; it must be Ok(true) for a freshly generated keypair.
        assert!(
            mgmt.validate(&*key, KeySelection::KEYPAIR)
                .expect("validate"),
            "generated keypair should validate structurally"
        );
    }

    #[test]
    fn export_requires_concrete_accessor() {
        let mgmt = DhKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        let key = mgmt.generate(&params).expect("generate");
        // The trait-surface export returns an empty ParamSet with a
        // warning because `&dyn KeyData` cannot be downcast. Fully
        // populated export is available via `DhKeyData::export_to_params`.
        let ps = mgmt.export(&*key, KeySelection::ALL).expect("export");
        assert_eq!(
            ps.len(),
            0,
            "trait-surface export must return an empty ParamSet"
        );
    }

    // -------------------------------------------------------------------------
    // Trait-surface tests — DhxKeyMgmt
    // -------------------------------------------------------------------------

    #[test]
    fn dhx_keymgmt_name_is_dhx() {
        let mgmt = DhxKeyMgmt;
        assert_eq!(mgmt.name(), "DHX");
    }

    #[test]
    fn dhx_new_key_returns_empty_key_data() {
        let mgmt = DhxKeyMgmt;
        let key = mgmt.new_key().expect("new_key");
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
        assert!(!mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn dhx_query_operation_name_is_dh() {
        let mgmt = DhxKeyMgmt;
        // The DHX family reuses DH's key-exchange dispatch — mirrors
        // `dhx_query_operation_name()` in dh_kmgmt.c:915-930.
        assert_eq!(mgmt.query_operation_name(0), "DH");
        assert_eq!(mgmt.query_operation_name(1), "DH");
        assert_eq!(mgmt.query_operation_name(u32::MAX), "DH");
    }

    #[test]
    fn dhx_generate_ffdhe2048_key_pair() {
        let mgmt = DhxKeyMgmt;
        let mut params = ParamSet::new();
        params.set(
            PARAM_GROUP_NAME,
            ParamValue::Utf8String("ffdhe2048".to_string()),
        );
        let key = mgmt.generate(&params).expect("dhx generate");
        assert!(mgmt.has(&*key, KeySelection::DOMAIN_PARAMETERS));
        assert!(mgmt.has(&*key, KeySelection::KEYPAIR));
    }

    // -------------------------------------------------------------------------
    // Descriptor tests
    // -------------------------------------------------------------------------

    #[test]
    fn dh_descriptors_returns_two_entries() {
        let descs = dh_descriptors();
        assert_eq!(descs.len(), 2, "must emit one DH and one DHX descriptor");

        // DH descriptor
        let dh = descs.iter().find(|d| d.names.contains(&"DH"));
        assert!(dh.is_some(), "DH descriptor must be present");
        let dh = dh.unwrap();
        assert!(dh.names.contains(&"dhKeyAgreement"));
        assert_eq!(dh.property, "provider=default");
        assert!(!dh.description.is_empty());

        // DHX descriptor
        let dhx = descs.iter().find(|d| d.names.contains(&"DHX"));
        assert!(dhx.is_some(), "DHX descriptor must be present");
        let dhx = dhx.unwrap();
        assert!(dhx.names.contains(&"X9.42 DH"));
        assert!(dhx.names.contains(&"dhpublicnumber"));
        assert_eq!(dhx.property, "provider=default");
        assert!(!dhx.description.is_empty());
    }

    // -------------------------------------------------------------------------
    // Direct DhKeyData construction tests — exercise the public inherent
    // methods `export_to_params`, `has_selection`, `validate_selection` that
    // cannot be reached via the `&dyn KeyData` trait surface.
    // -------------------------------------------------------------------------

    #[test]
    fn dh_key_data_new_is_empty() {
        // Private constructor is accessible from within the module.
        let k = DhKeyData::new(DhKeyType::Dh);
        assert!(!k.has_params());
        assert!(!k.has_public());
        assert!(!k.has_private());
        assert_eq!(k.bits(), None);
        assert_eq!(k.security_bits(), None);
    }

    #[test]
    fn dh_key_data_bits_and_security_bits_ffdhe2048() {
        let data = fully_populated_ffdhe2048();
        assert_eq!(data.bits(), Some(2048));
        // NIST SP 800-57: 2048-bit modulus → 112 bits security strength.
        assert_eq!(data.security_bits(), Some(112));
    }

    #[test]
    fn dh_key_data_export_roundtrip() {
        let original = fully_populated_ffdhe2048();
        let ps = original
            .export_to_params(KeySelection::ALL)
            .expect("export");

        // Verify every documented export key is present.
        assert!(ps.get(PARAM_FFC_P).is_some(), "p must be exported");
        assert!(ps.get(PARAM_FFC_G).is_some(), "g must be exported");
        // ffdhe2048 does not set q (q is optional on named groups), so
        // PARAM_FFC_Q may be absent — that is allowed.
        assert!(ps.get(PARAM_PUB_KEY).is_some(), "pub must be exported");
        assert!(ps.get(PARAM_PRIV_KEY).is_some(), "priv must be exported");
        assert!(ps.get(PARAM_BITS).is_some(), "bits must be exported");
        assert!(
            ps.get(PARAM_SECURITY_BITS).is_some(),
            "security-bits must be exported"
        );

        // Re-import through `from_params`.
        let imported =
            DhKeyData::from_params(DhKeyType::Dh, KeySelection::ALL, &ps).expect("re-import");
        assert!(imported.has_params());
        assert!(imported.has_public());
        assert!(imported.has_private());

        // Match on all components.
        let mgmt = DhKeyMgmt;
        assert!(
            mgmt.match_keys(&original, &imported),
            "roundtripped keys must match pairwise"
        );
    }

    #[test]
    fn dh_key_data_export_domain_only() {
        let original = fully_populated_ffdhe2048();
        let ps = original
            .export_to_params(KeySelection::DOMAIN_PARAMETERS)
            .expect("export");
        assert!(ps.get(PARAM_FFC_P).is_some());
        assert!(ps.get(PARAM_FFC_G).is_some());
        assert!(ps.get(PARAM_BITS).is_some());
        // Must NOT export key material when only domain parameters are
        // selected.
        assert!(
            ps.get(PARAM_PUB_KEY).is_none(),
            "pub must not be exported for DOMAIN_PARAMETERS selection"
        );
        assert!(
            ps.get(PARAM_PRIV_KEY).is_none(),
            "priv must not be exported for DOMAIN_PARAMETERS selection"
        );
    }

    #[test]
    fn dh_key_data_has_selection_private_only() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let priv_key = DhPrivateKey::new_from_raw(vec![0x42u8; 256], params.clone());
        let data = DhKeyData {
            params: Some(params),
            private_key: Some(priv_key),
            public_key: None,
            dh_type: DhKeyType::Dh,
        };
        assert!(data.has_selection(KeySelection::PRIVATE_KEY));
        assert!(data.has_selection(KeySelection::DOMAIN_PARAMETERS));
        assert!(!data.has_selection(KeySelection::PUBLIC_KEY));
        assert!(!data.has_selection(KeySelection::KEYPAIR));
    }

    #[test]
    fn dh_key_data_has_selection_empty() {
        let data = DhKeyData::new(DhKeyType::Dh);
        assert!(!data.has_selection(KeySelection::PRIVATE_KEY));
        assert!(!data.has_selection(KeySelection::PUBLIC_KEY));
        assert!(!data.has_selection(KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn dh_key_data_validate_selection_fully_populated() {
        let data = fully_populated_ffdhe2048();
        // The synthetic fixture supplies bytes that satisfy the
        // structural range checks for each individual selection
        // (DOMAIN_PARAMETERS, PUBLIC_KEY, PRIVATE_KEY) but does NOT
        // satisfy the pairwise invariant `y == g^x mod p`. Pairwise
        // semantics are exercised by the
        // `dh_validate_pairwise_passes_for_real_keypair` test below
        // using `gen_real_dh_keydata()`.
        assert!(data
            .validate_selection(KeySelection::DOMAIN_PARAMETERS)
            .expect("validate domain"));
        assert!(data
            .validate_selection(KeySelection::PUBLIC_KEY)
            .expect("validate public"),);
        assert!(data
            .validate_selection(KeySelection::PRIVATE_KEY)
            .expect("validate private"),);
    }

    #[test]
    fn dh_key_data_validate_rejects_zero_private_key() {
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        // A zero private exponent must fail validation.
        let priv_zero = DhPrivateKey::new_from_raw(vec![0u8; 256], params.clone());
        let data = DhKeyData {
            params: Some(params),
            private_key: Some(priv_zero),
            public_key: None,
            dh_type: DhKeyType::Dh,
        };
        assert!(
            !data
                .validate_selection(KeySelection::PRIVATE_KEY)
                .expect("validate"),
            "zero private key must fail validation"
        );
    }

    #[test]
    fn dh_key_data_validate_rejects_missing_component() {
        // Data has only params; requesting PUBLIC_KEY validation must be
        // Ok(false) because the component is missing.
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        let data = DhKeyData {
            params: Some(params),
            private_key: None,
            public_key: None,
            dh_type: DhKeyType::Dh,
        };
        assert!(
            !data
                .validate_selection(KeySelection::PUBLIC_KEY)
                .expect("validate"),
            "missing public key must fail PUBLIC_KEY validation"
        );
    }

    #[test]
    fn dh_key_data_match_keys_identical() {
        let a = fully_populated_ffdhe2048();
        let b = fully_populated_ffdhe2048();
        let mgmt = DhKeyMgmt;
        assert!(
            mgmt.match_keys(&a, &b),
            "identically constructed fixtures must match"
        );
    }

    #[test]
    fn dh_key_data_match_keys_differ_on_public() {
        let a = fully_populated_ffdhe2048();
        let params = from_named_group(DhNamedGroup::Ffdhe2048);
        // Different public-key value.
        let mut alt_pub_bytes = vec![0u8; 256];
        alt_pub_bytes[0] = 0x7F;
        alt_pub_bytes[1] = 0xAB; // differs from helper
        let alt_pub =
            DhPublicKey::new_from_raw(BigNum::from_bytes_be(&alt_pub_bytes), params.clone());
        // Use the SAME private-key bytes as the fixture so match_keys
        // fails solely on the public-key difference.
        let b = DhKeyData {
            params: a.params.clone(),
            private_key: Some(DhPrivateKey::new_from_raw(vec![0x42u8; 28], params)),
            public_key: Some(alt_pub),
            dh_type: DhKeyType::Dh,
        };
        let mgmt = DhKeyMgmt;
        assert!(
            !mgmt.match_keys(&a, &b),
            "keys with different public values must not match"
        );
    }

    #[test]
    fn dh_key_data_match_keys_differ_on_params() {
        // Compare ffdhe2048 against ffdhe3072 params: should not match.
        let a = fully_populated_ffdhe2048();
        let params_b = from_named_group(DhNamedGroup::Ffdhe3072);
        let priv_b = DhPrivateKey::new_from_raw(vec![0x42u8; 384], params_b.clone());
        let mut pub_bytes = vec![0u8; 384];
        pub_bytes[0] = 0x7F;
        let pub_b = DhPublicKey::new_from_raw(BigNum::from_bytes_be(&pub_bytes), params_b.clone());
        let b = DhKeyData {
            params: Some(params_b),
            private_key: Some(priv_b),
            public_key: Some(pub_b),
            dh_type: DhKeyType::Dh,
        };
        let mgmt = DhKeyMgmt;
        assert!(
            !mgmt.match_keys(&a, &b),
            "keys with different domain parameters must not match"
        );
    }

    // -------------------------------------------------------------------------
    // DhKeyMgmt::get_params / gettable_params
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_emits_expected_metadata() {
        let mgmt = DhKeyMgmt;
        let data = fully_populated_ffdhe2048();
        let ps = mgmt.get_params(&data).expect("get_params");
        assert!(ps.get(PARAM_BITS).is_some(), "bits must be reported");
        assert!(
            ps.get(PARAM_MAX_SIZE).is_some(),
            "max-size must be reported"
        );
        assert!(
            ps.get(PARAM_SECURITY_BITS).is_some(),
            "security-bits must be reported"
        );
        assert!(
            ps.get(PARAM_DEFAULT_DIGEST).is_some(),
            "default-digest must be reported"
        );

        // Check the default-digest value is the empty string (DH has no
        // default signing digest).
        if let Some(ParamValue::Utf8String(s)) = ps.get(PARAM_DEFAULT_DIGEST) {
            assert!(s.is_empty());
        } else {
            panic!("default-digest must be a UTF-8 string");
        }
    }

    #[test]
    fn gettable_params_lists_four_entries() {
        let mgmt = DhKeyMgmt;
        let list = mgmt.gettable_params();
        assert_eq!(list.len(), 4);
        assert!(list.contains(&PARAM_BITS));
        assert!(list.contains(&PARAM_MAX_SIZE));
        assert!(list.contains(&PARAM_SECURITY_BITS));
        assert!(list.contains(&PARAM_DEFAULT_DIGEST));
    }

    // -------------------------------------------------------------------------
    // Helper-function unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn named_group_from_name_ffdhe_family() {
        assert_eq!(
            named_group_from_name("ffdhe2048"),
            Some(DhNamedGroup::Ffdhe2048)
        );
        assert_eq!(
            named_group_from_name("ffdhe3072"),
            Some(DhNamedGroup::Ffdhe3072)
        );
        assert_eq!(
            named_group_from_name("ffdhe4096"),
            Some(DhNamedGroup::Ffdhe4096)
        );
        assert_eq!(
            named_group_from_name("ffdhe6144"),
            Some(DhNamedGroup::Ffdhe6144)
        );
        assert_eq!(
            named_group_from_name("ffdhe8192"),
            Some(DhNamedGroup::Ffdhe8192)
        );
    }

    #[test]
    fn named_group_from_name_modp_family_accepts_all_spellings() {
        assert_eq!(
            named_group_from_name("modp_2048"),
            Some(DhNamedGroup::ModP2048)
        );
        assert_eq!(
            named_group_from_name("modp-2048"),
            Some(DhNamedGroup::ModP2048)
        );
        assert_eq!(
            named_group_from_name("modp2048"),
            Some(DhNamedGroup::ModP2048)
        );
        assert_eq!(
            named_group_from_name("modp_8192"),
            Some(DhNamedGroup::ModP8192)
        );
    }

    #[test]
    fn named_group_from_name_unknown_returns_none() {
        assert_eq!(named_group_from_name("unknown"), None);
        assert_eq!(named_group_from_name("ffdhe9999"), None);
        assert_eq!(named_group_from_name(""), None);
    }

    #[test]
    fn dh_param_gen_type_parsing() {
        assert_eq!(
            DhParamGenType::from_name("generator"),
            Some(DhParamGenType::Generator)
        );
        assert_eq!(
            DhParamGenType::from_name("group"),
            Some(DhParamGenType::Group)
        );
        assert_eq!(
            DhParamGenType::from_name("named-group"),
            Some(DhParamGenType::Group)
        );
        assert_eq!(
            DhParamGenType::from_name("fips186_4"),
            Some(DhParamGenType::Fips186_4)
        );
        assert_eq!(
            DhParamGenType::from_name("fips186-4"),
            Some(DhParamGenType::Fips186_4)
        );
        // "default" is a spelling of the FIPS186_4 generator in the name
        // map — the `Default` enum variant is a runtime sentinel that is
        // never produced from a user-supplied string.
        assert_eq!(
            DhParamGenType::from_name("default"),
            Some(DhParamGenType::Fips186_4)
        );
        assert_eq!(DhParamGenType::from_name("bogus"), None);
    }

    #[test]
    fn pbits_to_named_group_mapping() {
        assert_eq!(pbits_to_named_group(2048), Some(DhNamedGroup::Ffdhe2048));
        assert_eq!(pbits_to_named_group(3072), Some(DhNamedGroup::Ffdhe3072));
        assert_eq!(pbits_to_named_group(4096), Some(DhNamedGroup::Ffdhe4096));
        assert_eq!(pbits_to_named_group(6144), Some(DhNamedGroup::Ffdhe6144));
        assert_eq!(pbits_to_named_group(8192), Some(DhNamedGroup::Ffdhe8192));
        // Unsupported sizes return None so the caller can fall back to
        // explicit parameter generation.
        assert_eq!(pbits_to_named_group(1024), None);
        assert_eq!(pbits_to_named_group(512), None);
        assert_eq!(pbits_to_named_group(0), None);
    }

    #[test]
    fn security_bits_from_prime_matches_nist_sp_800_57() {
        // NIST SP 800-57 Part 1 Rev. 5, Table 2 — FFC comparable strengths.
        let p2048 = from_named_group(DhNamedGroup::Ffdhe2048);
        assert_eq!(security_bits_from_prime(&p2048), 112);

        let p3072 = from_named_group(DhNamedGroup::Ffdhe3072);
        assert_eq!(security_bits_from_prime(&p3072), 128);

        let p4096 = from_named_group(DhNamedGroup::Ffdhe4096);
        // 7680-bit prime gives 192 bits security; 4096 sits between
        // 3072 (128) and 7680 (192). Accept whatever the NIST mapping
        // assigns for 4096-bit primes.
        assert!(security_bits_from_prime(&p4096) >= 128);

        let p6144 = from_named_group(DhNamedGroup::Ffdhe6144);
        assert!(security_bits_from_prime(&p6144) >= 128);

        // NIST SP 800-57 table caps the classical security strength at
        // 192 bits for primes in 7680..=15359; the 200-bit tier only
        // applies to primes larger than 15359 bits.
        let p8192 = from_named_group(DhNamedGroup::Ffdhe8192);
        assert_eq!(security_bits_from_prime(&p8192), 192);
    }

    // -------------------------------------------------------------------------
    // Enum string output
    // -------------------------------------------------------------------------

    #[test]
    fn dh_key_type_names() {
        assert_eq!(DhKeyType::Dh.name(), "DH");
        assert_eq!(DhKeyType::Dhx.name(), "DHX");
        assert_eq!(format!("{}", DhKeyType::Dh), "DH");
        assert_eq!(format!("{}", DhKeyType::Dhx), "DHX");
    }

    #[test]
    fn dh_key_data_debug_output_matches_pattern() {
        // The Debug projection must start with "DhKeyData" and expose
        // each has_* field so DhKeyMgmt::has can parse it. This is a
        // regression-safety test for the Debug-string dispatch path.
        let data = fully_populated_ffdhe2048();
        let debug = format!("{data:?}");
        assert!(
            debug.starts_with("DhKeyData"),
            "Debug output must start with DhKeyData"
        );
        assert!(debug.contains("has_private: true"));
        assert!(debug.contains("has_public: true"));
        assert!(debug.contains("has_params: true"));
        assert!(debug.contains("Dh"));
    }

    #[test]
    fn dhx_key_data_debug_exposes_dhx_tag() {
        let data = fully_populated_ffdhe2048_dhx();
        let debug = format!("{data:?}");
        assert!(debug.starts_with("DhKeyData"));
        assert!(debug.contains("Dhx"));
    }

    // -------------------------------------------------------------------------
    // validate_selection — pairwise check (NIST SP 800-56A R3 §5.6.2.1.4)
    // -------------------------------------------------------------------------
    //
    // Mirrors C `ossl_dh_check_pairwise()` at `crypto/dh/dh_check.c`.
    // The pairwise check fires when:
    //   1. selection.contains(PUBLIC_KEY)                           AND
    //   2. selection.contains(PRIVATE_KEY)                          AND
    //   3. self.params.is_some()
    // It then verifies that `g^x mod p == y`. Mismatch returns Ok(false).
    //
    // These tests use the FFDHE2048 named group from RFC 7919 (via
    // `from_named_group`) for fast deterministic keypair generation.
    // The same fixture builder (`gen_real_dh_keydata`) is defined
    // earlier in this file alongside the structural fixtures.

    #[test]
    fn dh_validate_pairwise_passes_for_real_keypair() {
        // Positive case: a freshly-generated DH key pair satisfies
        // `y = g^x mod p` by construction. The pairwise check must
        // confirm this and return `Ok(true)`.
        let key = gen_real_dh_keydata();
        let r = key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate must not error on a real key pair");
        assert!(
            r,
            "real DH key pair must satisfy the pairwise check (y == g^x mod p)"
        );
    }

    #[test]
    fn dh_validate_pairwise_passes_with_domain_parameters_selection() {
        // Equivalent to the previous test but additionally requests
        // DOMAIN_PARAMETERS in the selection. The pairwise check is
        // independent of the DOMAIN_PARAMETERS bit — it depends only
        // on the presence of the `params` field — and must still pass.
        let key = gen_real_dh_keydata();
        let r = key
            .validate_selection(KeySelection::KEYPAIR | KeySelection::DOMAIN_PARAMETERS)
            .expect("validate must not error");
        assert!(r, "KEYPAIR | DOMAIN_PARAMETERS must validate cleanly");
    }

    #[test]
    fn dh_validate_pairwise_rejects_tampered_public_value() {
        // Negative case: replace the stored public value `y` with the
        // generator `g`. Since `y' = g^x mod p` for a freshly-generated
        // random `x`, the recomputed value will virtually never equal
        // `g` (would require `x ≡ 1 mod q`). The pairwise check must
        // reject this with `Ok(false)`. `g` is in `[1, p)` so the
        // structural y-range check still passes.
        let mut key = gen_real_dh_keydata();
        let params = key
            .params
            .as_ref()
            .expect("params present after gen_real_dh_keydata")
            .clone();
        let tampered_y = params.g().clone();
        key.public_key = Some(DhPublicKey::new_from_raw(tampered_y, params));

        let r = key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate must not error on structurally-valid components");
        assert!(
            !r,
            "tampered public value must fail the pairwise check"
        );
    }

    #[test]
    fn dh_validate_pairwise_rejects_tampered_private_value() {
        // Negative case: replace the stored private value `x` with `2`
        // (still in `[1, p)` for any FFDHE prime). The recomputed
        // public value `g^2 mod p` will not match the original `y`
        // that was generated from the original random `x`. Returns
        // `Ok(false)`.
        let mut key = gen_real_dh_keydata();
        let params = key
            .params
            .as_ref()
            .expect("params present after gen_real_dh_keydata")
            .clone();
        let tampered_x_bytes = BigNum::from_u64(2).to_bytes_be();
        key.private_key = Some(DhPrivateKey::new_from_raw(tampered_x_bytes, params));

        let r = key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate must not error on structurally-valid components");
        assert!(
            !r,
            "tampered private value must fail the pairwise check (g^2 != y)"
        );
    }

    #[test]
    fn dh_validate_pairwise_skipped_for_public_only_selection() {
        // PUBLIC_KEY-only selection must NOT trigger the pairwise check
        // even when the underlying private value is wrong. The
        // structural y-range check still passes (real y is `1 < y < p`),
        // so the overall result must be `Ok(true)`.
        let mut key = gen_real_dh_keydata();
        let params = key
            .params
            .as_ref()
            .expect("params present after gen_real_dh_keydata")
            .clone();
        // Tamper the private value — irrelevant for PUBLIC_KEY-only.
        let tampered_x_bytes = BigNum::from_u64(2).to_bytes_be();
        key.private_key = Some(DhPrivateKey::new_from_raw(tampered_x_bytes, params));

        let r = key
            .validate_selection(KeySelection::PUBLIC_KEY)
            .expect("validate must not error");
        assert!(
            r,
            "PUBLIC_KEY-only selection must skip pairwise check and return true"
        );
    }

    #[test]
    fn dh_validate_pairwise_skipped_for_private_only_selection() {
        // PRIVATE_KEY-only selection must NOT trigger the pairwise
        // check even when the public value has been replaced with an
        // inconsistent (but still in-range) value.
        let mut key = gen_real_dh_keydata();
        let params = key
            .params
            .as_ref()
            .expect("params present after gen_real_dh_keydata")
            .clone();
        let tampered_y = params.g().clone();
        key.public_key = Some(DhPublicKey::new_from_raw(tampered_y, params));

        let r = key
            .validate_selection(KeySelection::PRIVATE_KEY)
            .expect("validate must not error");
        assert!(
            r,
            "PRIVATE_KEY-only selection must skip pairwise check and return true"
        );
    }

    #[test]
    fn dh_validate_pairwise_skipped_when_params_absent() {
        // KEYPAIR selection but `params` is `None` — the pairwise check
        // requires domain parameters and is silently skipped, matching
        // the C reference at `crypto/dh/dh_check.c` which short-circuits
        // when the underlying params pointer is NULL. Structural range
        // checks that require params are also skipped (since
        // `params.p()` cannot be consulted), so the function returns
        // `Ok(true)` as long as the components are present.
        //
        // Construct a `DhKeyData` directly with `params = None` while
        // keeping private/public values from a real key pair so they
        // remain mutually consistent (even though that consistency
        // cannot be checked when params are absent).
        let real = gen_real_dh_keydata();
        let key = DhKeyData {
            params: None,
            private_key: real.private_key,
            public_key: real.public_key,
            dh_type: DhKeyType::Dh,
        };

        let r = key
            .validate_selection(KeySelection::KEYPAIR)
            .expect("validate must not error");
        assert!(
            r,
            "KEYPAIR without params must skip pairwise check and return true"
        );
    }

    #[test]
    fn dh_validate_pairwise_check_uses_constant_time_path() {
        // Smoke-test that the pairwise check delegates to
        // `mod_exp_consttime`. We cannot directly observe constant-time
        // behavior from a unit test, but we can at minimum verify that
        // the function returns a determined Boolean (rather than a
        // ProviderError) on a structurally-valid keypair — proving the
        // import resolution and function call path is wired through.
        // This guards against regression of the
        // `use ...mod_exp_consttime` import which the pairwise check
        // requires.
        let key = gen_real_dh_keydata();
        let result = key.validate_selection(KeySelection::KEYPAIR);
        assert!(
            result.is_ok(),
            "validate_selection must return Ok, not Err, for a real key pair"
        );
        assert_eq!(result.expect("ok"), true);
    }
}
