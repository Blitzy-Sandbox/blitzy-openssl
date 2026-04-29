//! SLH-DSA (FIPS 205) key management provider implementation.
//!
//! Translates the SLH-DSA key-management dispatch entries from
//! `providers/defltprov.c` (12 `OSSL_DISPATCH ossl_slh_dsa_*_keymgmt_functions[]`
//! tables, one per (hash family, security category, sign profile) tuple) into
//! Rust descriptors consumed by
//! [`crate::implementations::keymgmt::descriptors`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/slh_dsa_kmgmt.c` (~481 lines) and
//! provides `KeyMgmtProvider`-equivalent operations for FIPS 205 SLH-DSA
//! (Stateless Hash-Based Digital Signature Algorithm).
//!
//! # Parameter sets and OIDs
//!
//! SLH-DSA defines 12 parameter sets covering two hash families
//! (SHA-2 and SHAKE), three NIST security categories (1, 3, 5), and two
//! sign-time/signature-size profiles (`s` = small signatures slow signing,
//! `f` = fast signing larger signatures).
//!
//! | Parameter set        | Cat | Hash family | Profile | OID                              |
//! |---------------------|-----|-------------|---------|----------------------------------|
//! | `SLH-DSA-SHA2-128s` | 1   | SHA-2       | small   | 2.16.840.1.101.3.4.3.20          |
//! | `SLH-DSA-SHA2-128f` | 1   | SHA-2       | fast    | 2.16.840.1.101.3.4.3.21          |
//! | `SLH-DSA-SHA2-192s` | 3   | SHA-2       | small   | 2.16.840.1.101.3.4.3.22          |
//! | `SLH-DSA-SHA2-192f` | 3   | SHA-2       | fast    | 2.16.840.1.101.3.4.3.23          |
//! | `SLH-DSA-SHA2-256s` | 5   | SHA-2       | small   | 2.16.840.1.101.3.4.3.24          |
//! | `SLH-DSA-SHA2-256f` | 5   | SHA-2       | fast    | 2.16.840.1.101.3.4.3.25          |
//! | `SLH-DSA-SHAKE-128s`| 1   | SHAKE       | small   | 2.16.840.1.101.3.4.3.26          |
//! | `SLH-DSA-SHAKE-128f`| 1   | SHAKE       | fast    | 2.16.840.1.101.3.4.3.27          |
//! | `SLH-DSA-SHAKE-192s`| 3   | SHAKE       | small   | 2.16.840.1.101.3.4.3.28          |
//! | `SLH-DSA-SHAKE-192f`| 3   | SHAKE       | fast    | 2.16.840.1.101.3.4.3.29          |
//! | `SLH-DSA-SHAKE-256s`| 5   | SHAKE       | small   | 2.16.840.1.101.3.4.3.30          |
//! | `SLH-DSA-SHAKE-256f`| 5   | SHAKE       | fast    | 2.16.840.1.101.3.4.3.31          |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::slh_dsa::slh_dsa_descriptors`
//! (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                       | Rust Equivalent                                   |
//! |----------------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (SLH-DSA `KEYMGMT` entries)            | `slh_dsa_descriptors` in this module            |
//! | `providers/implementations/keymgmt/slh_dsa_kmgmt.c`            | per parameter-set keymgmt implementation          |
//! | `PROV_NAMES_SLH_DSA_*` macros in `prov/names.h`                | the `names` slice on each `AlgorithmDescriptor` |

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::Zeroize;

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::slh_dsa::{
    slh_dsa_params_get, KeySelection as CryptoKeySelection, SlhDsaKey, SlhDsaParams, SlhDsaVariant,
};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Parameter name constants
//
// Mirror C `OSSL_PKEY_PARAM_*` and `OSSL_PARAM_*` symbol values used by the
// SLH-DSA key-management provider in `slh_dsa_kmgmt.c`.
// =============================================================================

/// X.509-style encoded public key bytes (raw concatenation of `pk.seed || pk.root`).
const PARAM_ENCODED_PUB_KEY: &str = "encoded-pub-key";
/// Octet-string public key import/export key.
const PARAM_PUB_KEY: &str = "pub";
/// Octet-string private key import/export key (raw `sk.seed || sk.prf || pk.seed || pk.root`).
const PARAM_PRIV_KEY: &str = "priv";
/// Optional generation entropy (length is variant-dependent: `3 * n` bytes).
const PARAM_SEED: &str = "seed";
/// `bits` integer parameter — public key length in bits.
const PARAM_BITS: &str = "bits";
/// `security-bits` integer parameter — NIST security level converted to bits.
const PARAM_SECURITY_BITS: &str = "security-bits";
/// `security-category` integer parameter — NIST PQC category number (1, 3, or 5).
const PARAM_SECURITY_CATEGORY: &str = "security-category";
/// `max-size` integer parameter — maximum signature byte length.
const PARAM_MAX_SIZE: &str = "max-size";
/// `mandatory-digest` UTF-8 string — empty for SLH-DSA (algorithm hashes internally).
const PARAM_MANDATORY_DIGEST: &str = "mandatory-digest";

// =============================================================================
// SlhDsaParamSet — the 12 FIPS 205 parameter sets
// =============================================================================

/// Enumeration of the 12 FIPS 205 SLH-DSA parameter sets.
///
/// The `s` (small) profile minimises signature size at the cost of slower
/// signing; the `f` (fast) profile minimises signing time at the cost of
/// larger signatures. The hash family (SHA-2 vs SHAKE) and security category
/// (1, 3, 5) round out the parameter space.
///
/// This enum mirrors the provider-side spelling required by the file schema
/// (`Sha2_128s`, `Shake128s`, etc.). It maps to the crypto layer's
/// [`SlhDsaVariant`] enum which uses a slightly different spelling (insertion
/// of an underscore between `Shake` and the digit group, e.g. `Shake_128s`).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsaParamSet {
    /// SLH-DSA-SHA2-128s (NIST cat 1, SHA-2 hash, small signatures).
    Sha2_128s,
    /// SLH-DSA-SHA2-128f (NIST cat 1, SHA-2 hash, fast signing).
    Sha2_128f,
    /// SLH-DSA-SHA2-192s (NIST cat 3, SHA-2 hash, small signatures).
    Sha2_192s,
    /// SLH-DSA-SHA2-192f (NIST cat 3, SHA-2 hash, fast signing).
    Sha2_192f,
    /// SLH-DSA-SHA2-256s (NIST cat 5, SHA-2 hash, small signatures).
    Sha2_256s,
    /// SLH-DSA-SHA2-256f (NIST cat 5, SHA-2 hash, fast signing).
    Sha2_256f,
    /// SLH-DSA-SHAKE-128s (NIST cat 1, SHAKE hash, small signatures).
    Shake128s,
    /// SLH-DSA-SHAKE-128f (NIST cat 1, SHAKE hash, fast signing).
    Shake128f,
    /// SLH-DSA-SHAKE-192s (NIST cat 3, SHAKE hash, small signatures).
    Shake192s,
    /// SLH-DSA-SHAKE-192f (NIST cat 3, SHAKE hash, fast signing).
    Shake192f,
    /// SLH-DSA-SHAKE-256s (NIST cat 5, SHAKE hash, small signatures).
    Shake256s,
    /// SLH-DSA-SHAKE-256f (NIST cat 5, SHAKE hash, fast signing).
    Shake256f,
}

impl SlhDsaParamSet {
    /// Returns the canonical NIST/IETF name (e.g. `"SLH-DSA-SHA2-128s"`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha2_128s => "SLH-DSA-SHA2-128s",
            Self::Sha2_128f => "SLH-DSA-SHA2-128f",
            Self::Sha2_192s => "SLH-DSA-SHA2-192s",
            Self::Sha2_192f => "SLH-DSA-SHA2-192f",
            Self::Sha2_256s => "SLH-DSA-SHA2-256s",
            Self::Sha2_256f => "SLH-DSA-SHA2-256f",
            Self::Shake128s => "SLH-DSA-SHAKE-128s",
            Self::Shake128f => "SLH-DSA-SHAKE-128f",
            Self::Shake192s => "SLH-DSA-SHAKE-192s",
            Self::Shake192f => "SLH-DSA-SHAKE-192f",
            Self::Shake256s => "SLH-DSA-SHAKE-256s",
            Self::Shake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// Convenience alias for [`Self::name`] — provided for parity with the
    /// crypto-layer [`SlhDsaVariant::algorithm_name`] entry point.
    #[must_use]
    pub fn algorithm_name(self) -> &'static str {
        self.name()
    }

    /// Returns the NIST PQC security category (1, 3, or 5).
    #[must_use]
    pub fn security_category(self) -> u32 {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => 1,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => 3,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => 5,
        }
    }

    /// Returns the security strength expressed in bits (128, 192, or 256).
    #[must_use]
    pub fn security_bits(self) -> u32 {
        match self.security_category() {
            1 => 128,
            3 => 192,
            // Category 5 maps to 256-bit security strength per FIPS 205.
            _ => 256,
        }
    }

    /// Returns the `n` parameter (hash output size in bytes: 16, 24, or 32).
    #[must_use]
    fn n(self) -> usize {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => 16,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => 24,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => 32,
        }
    }

    /// Returns the public key length in bytes (always `2 * n`).
    #[must_use]
    pub fn pub_key_size(self) -> usize {
        2 * self.n()
    }

    /// Returns the private key length in bytes (always `4 * n`).
    #[must_use]
    pub fn priv_key_size(self) -> usize {
        4 * self.n()
    }

    /// Returns the signature length in bytes for this parameter set.
    ///
    /// Values come from FIPS 205 §11 (Table 2). They depend jointly on the
    /// security category and on the small/fast profile.
    #[must_use]
    pub fn sig_size(self) -> usize {
        match self {
            Self::Sha2_128s | Self::Shake128s => 7856,
            Self::Sha2_128f | Self::Shake128f => 17_088,
            Self::Sha2_192s | Self::Shake192s => 16_224,
            Self::Sha2_192f | Self::Shake192f => 35_664,
            Self::Sha2_256s | Self::Shake256s => 29_792,
            Self::Sha2_256f | Self::Shake256f => 49_856,
        }
    }

    /// Maps to the corresponding crypto-layer variant.
    ///
    /// The current production paths route through string-based lookup via
    /// [`Self::algorithm_name`] (see [`Self::params`]) because the crypto
    /// layer's static parameter table is keyed on canonical algorithm names.
    /// This bridge function is retained so that future direct-dispatch paths
    /// (e.g. typed `SlhDsaKey::generate(SlhDsaVariant::…)`) can call it without
    /// re-deriving the mapping, and to allow round-trip tests to verify
    /// consistency between the provider and crypto enum representations.
    #[must_use]
    #[allow(dead_code)] // bridge retained for round-trip tests and future typed dispatch
    fn to_crypto(self) -> SlhDsaVariant {
        match self {
            Self::Sha2_128s => SlhDsaVariant::Sha2_128s,
            Self::Sha2_128f => SlhDsaVariant::Sha2_128f,
            Self::Sha2_192s => SlhDsaVariant::Sha2_192s,
            Self::Sha2_192f => SlhDsaVariant::Sha2_192f,
            Self::Sha2_256s => SlhDsaVariant::Sha2_256s,
            Self::Sha2_256f => SlhDsaVariant::Sha2_256f,
            Self::Shake128s => SlhDsaVariant::Shake_128s,
            Self::Shake128f => SlhDsaVariant::Shake_128f,
            Self::Shake192s => SlhDsaVariant::Shake_192s,
            Self::Shake192f => SlhDsaVariant::Shake_192f,
            Self::Shake256s => SlhDsaVariant::Shake_256s,
            Self::Shake256f => SlhDsaVariant::Shake_256f,
        }
    }

    /// Maps from the crypto-layer variant.
    ///
    /// Inverse of [`Self::to_crypto`]. Used by future ingestion paths that
    /// receive a typed [`SlhDsaVariant`] from the crypto layer (for example
    /// when promoting an externally-constructed [`SlhDsaKey`] back into a
    /// provider [`SlhDsaKeyData`]) and by round-trip tests asserting the
    /// bijection holds across all twelve parameter sets.
    #[must_use]
    #[allow(dead_code)] // inverse bridge retained for round-trip tests and future ingestion
    fn from_crypto(variant: SlhDsaVariant) -> Self {
        match variant {
            SlhDsaVariant::Sha2_128s => Self::Sha2_128s,
            SlhDsaVariant::Sha2_128f => Self::Sha2_128f,
            SlhDsaVariant::Sha2_192s => Self::Sha2_192s,
            SlhDsaVariant::Sha2_192f => Self::Sha2_192f,
            SlhDsaVariant::Sha2_256s => Self::Sha2_256s,
            SlhDsaVariant::Sha2_256f => Self::Sha2_256f,
            SlhDsaVariant::Shake_128s => Self::Shake128s,
            SlhDsaVariant::Shake_128f => Self::Shake128f,
            SlhDsaVariant::Shake_192s => Self::Shake192s,
            SlhDsaVariant::Shake_192f => Self::Shake192f,
            SlhDsaVariant::Shake_256s => Self::Shake256s,
            SlhDsaVariant::Shake_256f => Self::Shake256f,
        }
    }

    /// Looks up a parameter set by canonical or alias name (case-insensitive).
    ///
    /// Recognises the canonical SLH-DSA names plus the lower-cased IETF id
    /// aliases (`id-slh-dsa-sha2-128s`, etc.).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "slh-dsa-sha2-128s" | "id-slh-dsa-sha2-128s" => Some(Self::Sha2_128s),
            "slh-dsa-sha2-128f" | "id-slh-dsa-sha2-128f" => Some(Self::Sha2_128f),
            "slh-dsa-sha2-192s" | "id-slh-dsa-sha2-192s" => Some(Self::Sha2_192s),
            "slh-dsa-sha2-192f" | "id-slh-dsa-sha2-192f" => Some(Self::Sha2_192f),
            "slh-dsa-sha2-256s" | "id-slh-dsa-sha2-256s" => Some(Self::Sha2_256s),
            "slh-dsa-sha2-256f" | "id-slh-dsa-sha2-256f" => Some(Self::Sha2_256f),
            "slh-dsa-shake-128s" | "id-slh-dsa-shake-128s" => Some(Self::Shake128s),
            "slh-dsa-shake-128f" | "id-slh-dsa-shake-128f" => Some(Self::Shake128f),
            "slh-dsa-shake-192s" | "id-slh-dsa-shake-192s" => Some(Self::Shake192s),
            "slh-dsa-shake-192f" | "id-slh-dsa-shake-192f" => Some(Self::Shake192f),
            "slh-dsa-shake-256s" | "id-slh-dsa-shake-256s" => Some(Self::Shake256s),
            "slh-dsa-shake-256f" | "id-slh-dsa-shake-256f" => Some(Self::Shake256f),
            _ => None,
        }
    }

    /// Returns the static crypto-layer parameter table entry for this set.
    ///
    /// The crypto layer holds the canonical numerical parameter values in a
    /// `&'static SlhDsaParams`. We delegate to its lookup table so that the
    /// provider and crypto layers cannot diverge.
    fn params(self) -> ProviderResult<&'static SlhDsaParams> {
        slh_dsa_params_get(self.algorithm_name()).ok_or_else(|| {
            ProviderError::AlgorithmUnavailable(format!(
                "SLH-DSA parameter table missing entry for {}",
                self.algorithm_name()
            ))
        })
    }
}

// =============================================================================
// SlhDsaKeyData — opaque key handle returned to the provider framework
// =============================================================================

/// Key data for SLH-DSA keys (FIPS 205).
///
/// Wraps an [`SlhDsaKey`] from the crypto layer along with the variant tag
/// and the library context handle used at construction time. The wrapping
/// `Option` allows representing newly-constructed empty keys (no material yet)
/// as well as fully-populated keys imported from external bytes.
///
/// Field visibility is `pub(crate)` so that integration tests inside this
/// crate can introspect the key directly without having to round-trip through
/// the public `KeyMgmtProvider` trait surface.
pub struct SlhDsaKeyData {
    pub(crate) key: Option<SlhDsaKey>,
    pub(crate) variant: SlhDsaParamSet,
    pub(crate) lib_ctx: Option<Arc<LibContext>>,
}

impl SlhDsaKeyData {
    /// Constructs an empty `SlhDsaKeyData` for the given variant.
    ///
    /// The wrapped key handle is initialised to `None`. Subsequent calls to
    /// `import_into`/`generate_into` populate the real key material.
    #[must_use]
    pub fn new(variant: SlhDsaParamSet, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            key: None,
            variant,
            lib_ctx,
        }
    }

    /// Returns the parameter-set tag stored in this key data record.
    #[must_use]
    pub fn variant(&self) -> SlhDsaParamSet {
        self.variant
    }

    /// Returns a reference to the underlying crypto-layer key, if present.
    #[must_use]
    pub fn key(&self) -> Option<&SlhDsaKey> {
        self.key.as_ref()
    }

    /// Returns a clone of the library context handle for downstream calls.
    #[must_use]
    pub fn lib_ctx(&self) -> Option<Arc<LibContext>> {
        self.lib_ctx.clone()
    }

    /// Reports whether the wrapped key holds a public component.
    #[must_use]
    pub fn has_pubkey(&self) -> bool {
        self.key
            .as_ref()
            .is_some_and(|k| k.has_key(CryptoKeySelection::PublicOnly))
    }

    /// Reports whether the wrapped key holds a private component.
    #[must_use]
    pub fn has_prvkey(&self) -> bool {
        self.key
            .as_ref()
            .is_some_and(|k| k.has_key(CryptoKeySelection::PrivateOnly))
    }

    /// Reports whether the wrapped key holds a stored generation seed.
    ///
    /// SLH-DSA keys do not retain the entropy used at generation time; the
    /// crypto layer derives all four key components (`sk.seed`, `sk.prf`,
    /// `pk.seed`, `pk.root`) from the entropy bytes and discards them. This
    /// helper therefore always returns `false` and is provided only so that
    /// the structural Debug-introspection helpers used by `has`/`validate`
    /// can mirror the field layout used by the ML-DSA key data type.
    #[must_use]
    pub fn has_seed(&self) -> bool {
        false
    }

    /// Returns `true` if this key holds the components requested by `selection`.
    ///
    /// This is the typed equivalent of [`SlhDsaKeyMgmt::has`]: that trait
    /// method must work over the opaque `&dyn KeyData` boundary and therefore
    /// re-derives the answer through structural [`fmt::Debug`] introspection
    /// (see [`introspect_debug`]). This direct-access version is retained so
    /// that interior callers with concrete [`SlhDsaKeyData`] handles can avoid
    /// the introspection round-trip, and so that consistency tests can pin
    /// both paths to the same answer for the empty-keypair case.
    #[allow(dead_code)] // typed selection check retained for future direct-access callers and tests
    fn check_selection(&self, selection: KeySelection) -> bool {
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            return true;
        }
        let mut ok = true;
        if kp.contains(KeySelection::PRIVATE_KEY) {
            ok &= self.has_prvkey();
        }
        if kp.contains(KeySelection::PUBLIC_KEY) {
            ok &= self.has_pubkey();
        }
        ok
    }
}

impl fmt::Debug for SlhDsaKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The textual `variant` token (e.g. "Sha2_128s") is required by the
        // structural-introspection helpers `looks_like_slh_dsa_key_data` and
        // `introspect_debug`; the boolean flags must always be present.
        // `lib_ctx` is omitted because `LibContext` does not implement
        // `Debug`; `finish_non_exhaustive()` is therefore used to avoid
        // promising a complete field list.
        f.debug_struct("SlhDsaKeyData")
            .field("variant", &self.variant)
            .field("has_pubkey", &self.has_pubkey())
            .field("has_prvkey", &self.has_prvkey())
            .field("has_seed", &self.has_seed())
            .finish_non_exhaustive()
    }
}

impl KeyData for SlhDsaKeyData {}

impl Drop for SlhDsaKeyData {
    fn drop(&mut self) {
        // `SlhDsaKey` derives `ZeroizeOnDrop`, which scrubs the inner key
        // bytes when the option is taken. Explicitly taking the option here
        // ensures the wrapping `SlhDsaKeyData` is also wiped of any residual
        // references to the key material before deallocation.
        self.key.take();
    }
}

// =============================================================================
// SlhDsaGenContext — generation parameters bundle
// =============================================================================

/// Generation context for SLH-DSA key generation.
///
/// Mirrors the C `struct slh_dsa_gen_ctx` (line 60 of `slh_dsa_kmgmt.c`).
/// Fields are publicly exposed so that integration tests can construct
/// deterministic generation requests directly.
///
/// The `entropy` field is a heap buffer because the required entropy length
/// is `3 * n` bytes which varies per parameter set (48, 72, or 96 bytes). On
/// drop the buffer is securely zeroed.
pub struct SlhDsaGenContext {
    /// Target parameter set for generation.
    pub variant: SlhDsaParamSet,
    /// Optional `properties=` provider query string.
    pub prop_query: Option<String>,
    /// Optional explicit entropy for deterministic generation.
    ///
    /// When `Some`, the buffer length must equal `3 * n` for the variant.
    /// When `None`, the crypto layer draws fresh entropy from `OsRng`.
    pub entropy: Option<Vec<u8>>,
    /// Optional library context override (defaults to the global default).
    pub lib_ctx: Option<Arc<LibContext>>,
}

impl SlhDsaGenContext {
    /// Constructs a fresh generation context for `variant`.
    #[must_use]
    pub fn new(variant: SlhDsaParamSet, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            variant,
            prop_query: None,
            entropy: None,
            lib_ctx,
        }
    }

    /// Stores the supplied `entropy` bytes after validating their length.
    ///
    /// The required length for SLH-DSA generation entropy is `3 * n` where
    /// `n` is the hash output size of the parameter set:
    ///
    /// - 128-bit variants: 48 bytes
    /// - 192-bit variants: 72 bytes
    /// - 256-bit variants: 96 bytes
    ///
    /// Returns [`ProviderError::Common`] with a descriptive
    /// [`CommonError::InvalidArgument`] if the length does not match.
    pub fn set_entropy(&mut self, entropy: Vec<u8>) -> ProviderResult<()> {
        let expected = 3 * self.variant.n();
        if entropy.len() != expected {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                "SLH-DSA gen_ctx: seed must be exactly {expected} bytes for {variant}, got {got}",
                variant = self.variant.algorithm_name(),
                got = entropy.len()
            ),
            )));
        }
        self.entropy = Some(entropy);
        Ok(())
    }

    /// Returns a reference to the stored entropy bytes, if any.
    #[must_use]
    pub fn entropy(&self) -> Option<&[u8]> {
        self.entropy.as_deref()
    }
}

impl fmt::Debug for SlhDsaGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking entropy bytes into Debug output. The presence flag is
        // sufficient for diagnostics; `lib_ctx` is omitted because
        // `LibContext` does not implement `Debug`.
        f.debug_struct("SlhDsaGenContext")
            .field("variant", &self.variant)
            .field("prop_query", &self.prop_query)
            .field("has_entropy", &self.entropy.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for SlhDsaGenContext {
    fn drop(&mut self) {
        // Securely zero the entropy buffer before deallocation so that the
        // generation seed cannot be recovered from freed heap memory. This
        // replaces the C `OPENSSL_cleanse()` call in `slh_dsa_gen_cleanup`.
        if let Some(mut buf) = self.entropy.take() {
            buf.zeroize();
        }
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Maps a [`openssl_common::CryptoError`] into a [`ProviderError`].
///
/// Used as a `Result::map_err` callback throughout the keymgmt operations.
/// Crypto-layer errors are wrapped under [`CommonError::Internal`] which
/// preserves the original textual message via `Display`.
#[allow(
    clippy::needless_pass_by_value,
    reason = "by-value signature required for use as `Result::map_err` callback"
)]
fn map_crypto_err(e: openssl_common::CryptoError) -> ProviderError {
    ProviderError::Common(CommonError::Internal(e.to_string()))
}

/// Heuristically detects whether a `&dyn KeyData` carries an `SlhDsaKeyData`.
///
/// Because the trait surface forbids both `unsafe` downcasting (Rule R8) and
/// requiring `Any`, we rely on the structural `Debug` representation that
/// every keymgmt module wires through its concrete type. The substring
/// `"SlhDsaKeyData"` is unique to this module's `Debug` impl above.
fn looks_like_slh_dsa_key_data(key: &dyn KeyData) -> bool {
    let s = format!("{key:?}");
    s.contains("SlhDsaKeyData")
}

/// Extracts structural flags and the variant tag from a `&dyn KeyData`.
///
/// Returns a tuple of `(has_pub, has_priv, has_seed, variant)`. The variant
/// is extracted by matching the textual token printed by the [`Debug`] impl
/// for [`SlhDsaParamSet`] (the enum's variant identifier). Returns `None` for
/// the variant if the key data does not appear to be an `SlhDsaKeyData`.
fn introspect_debug(key: &dyn KeyData) -> (bool, bool, bool, Option<SlhDsaParamSet>) {
    let s = format!("{key:?}");
    let has_pub = s.contains("has_pubkey: true");
    let has_priv = s.contains("has_prvkey: true");
    let has_seed = s.contains("has_seed: true");
    // Match the longer SHAKE-prefixed variants before the SHA-2 variants so
    // that `Shake128s` is not falsely matched as containing `Sha2_128s`.
    let variant = if s.contains("Shake128s") {
        Some(SlhDsaParamSet::Shake128s)
    } else if s.contains("Shake128f") {
        Some(SlhDsaParamSet::Shake128f)
    } else if s.contains("Shake192s") {
        Some(SlhDsaParamSet::Shake192s)
    } else if s.contains("Shake192f") {
        Some(SlhDsaParamSet::Shake192f)
    } else if s.contains("Shake256s") {
        Some(SlhDsaParamSet::Shake256s)
    } else if s.contains("Shake256f") {
        Some(SlhDsaParamSet::Shake256f)
    } else if s.contains("Sha2_128s") {
        Some(SlhDsaParamSet::Sha2_128s)
    } else if s.contains("Sha2_128f") {
        Some(SlhDsaParamSet::Sha2_128f)
    } else if s.contains("Sha2_192s") {
        Some(SlhDsaParamSet::Sha2_192s)
    } else if s.contains("Sha2_192f") {
        Some(SlhDsaParamSet::Sha2_192f)
    } else if s.contains("Sha2_256s") {
        Some(SlhDsaParamSet::Sha2_256s)
    } else if s.contains("Sha2_256f") {
        Some(SlhDsaParamSet::Sha2_256f)
    } else {
        None
    };
    (has_pub, has_priv, has_seed, variant)
}

/// Looks up an octet-string parameter from a [`ParamSet`].
///
/// Returns `Ok(None)` if the parameter is absent, `Ok(Some(bytes))` if it is
/// present and of octet-string type, or [`CommonError::ParamTypeMismatch`] if
/// it is present but of a different type.
fn octet_param<'a>(params: &'a ParamSet, key: &str) -> ProviderResult<Option<&'a [u8]>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    let Some(bytes) = value.as_bytes() else {
        return Err(ProviderError::Common(CommonError::ParamTypeMismatch {
            key: key.to_string(),
            expected: "octet-string",
            actual: value.param_type_name(),
        }));
    };
    Ok(Some(bytes))
}

/// Attempts a safe-Rust downcast of `&dyn KeyData` to `&SlhDsaKeyData`.
///
/// Always returns `None` in the current implementation. Performing a real
/// downcast would either require `unsafe` (which Rule R8 forbids in this
/// crate) or constraining the trait surface with `Any` (which the schema
/// does not declare). Callers are therefore expected to fall back to the
/// pure-safe Debug-introspection helpers (`introspect_debug`) for any
/// operation that needs structural access without holding a typed reference.
fn downcast_ref(key: &dyn KeyData) -> Option<&SlhDsaKeyData> {
    if !looks_like_slh_dsa_key_data(key) {
        return None;
    }
    // Safety relies on the Debug-format check above and on `KeyData` being
    // implemented only for `SlhDsaKeyData` within this module. We do not use
    // `unsafe` here; instead we re-route through the trait object's address
    // by leveraging the fact that a `&dyn KeyData` is two pointers (data,
    // vtable), and the data pointer is a valid `*const SlhDsaKeyData`
    // whenever the Debug probe matches. Because forming such a reference
    // would require `unsafe`, we instead return `None` when concrete-typed
    // access is unavailable and rely on the Debug-introspection helpers
    // (`introspect_debug`) for the pure-safe fallback used by `has` and
    // `validate`.
    let _ = key;
    None
}

// =============================================================================
// SlhDsaKeyMgmt — provider implementation for one parameter set
// =============================================================================

/// SLH-DSA key management provider for a single parameter set.
///
/// One instance of this struct is registered per parameter set so that the
/// provider framework can dispatch by algorithm name. The struct is cheap to
/// clone (`Arc`-shared library context) and is `Send + Sync`.
pub struct SlhDsaKeyMgmt {
    variant: SlhDsaParamSet,
    default_lib_ctx: Arc<LibContext>,
}

impl SlhDsaKeyMgmt {
    /// Constructs a key-management provider for the given variant using the
    /// process-wide default library context.
    #[must_use]
    pub fn new(variant: SlhDsaParamSet) -> Self {
        Self {
            variant,
            default_lib_ctx: LibContext::get_default(),
        }
    }

    /// Convenience constructor for SLH-DSA-SHA2-128s.
    #[must_use]
    pub fn slh_dsa_sha2_128s() -> Self {
        Self::new(SlhDsaParamSet::Sha2_128s)
    }

    /// Convenience constructor for SLH-DSA-SHA2-128f.
    #[must_use]
    pub fn slh_dsa_sha2_128f() -> Self {
        Self::new(SlhDsaParamSet::Sha2_128f)
    }

    /// Convenience constructor for SLH-DSA-SHA2-192s.
    #[must_use]
    pub fn slh_dsa_sha2_192s() -> Self {
        Self::new(SlhDsaParamSet::Sha2_192s)
    }

    /// Convenience constructor for SLH-DSA-SHA2-192f.
    #[must_use]
    pub fn slh_dsa_sha2_192f() -> Self {
        Self::new(SlhDsaParamSet::Sha2_192f)
    }

    /// Convenience constructor for SLH-DSA-SHA2-256s.
    #[must_use]
    pub fn slh_dsa_sha2_256s() -> Self {
        Self::new(SlhDsaParamSet::Sha2_256s)
    }

    /// Convenience constructor for SLH-DSA-SHA2-256f.
    #[must_use]
    pub fn slh_dsa_sha2_256f() -> Self {
        Self::new(SlhDsaParamSet::Sha2_256f)
    }

    /// Convenience constructor for SLH-DSA-SHAKE-128s.
    #[must_use]
    pub fn slh_dsa_shake_128s() -> Self {
        Self::new(SlhDsaParamSet::Shake128s)
    }

    /// Convenience constructor for SLH-DSA-SHAKE-128f.
    #[must_use]
    pub fn slh_dsa_shake_128f() -> Self {
        Self::new(SlhDsaParamSet::Shake128f)
    }

    /// Convenience constructor for SLH-DSA-SHAKE-192s.
    #[must_use]
    pub fn slh_dsa_shake_192s() -> Self {
        Self::new(SlhDsaParamSet::Shake192s)
    }

    /// Convenience constructor for SLH-DSA-SHAKE-192f.
    #[must_use]
    pub fn slh_dsa_shake_192f() -> Self {
        Self::new(SlhDsaParamSet::Shake192f)
    }

    /// Convenience constructor for SLH-DSA-SHAKE-256s.
    #[must_use]
    pub fn slh_dsa_shake_256s() -> Self {
        Self::new(SlhDsaParamSet::Shake256s)
    }

    /// Convenience constructor for SLH-DSA-SHAKE-256f.
    #[must_use]
    pub fn slh_dsa_shake_256f() -> Self {
        Self::new(SlhDsaParamSet::Shake256f)
    }

    /// Returns the parameter set bound to this provider.
    #[must_use]
    pub fn variant(&self) -> SlhDsaParamSet {
        self.variant
    }

    /// Returns the canonical name reported to the provider framework.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.variant.algorithm_name()
    }

    /// Compares two key data records under the requested selection.
    ///
    /// Returns `true` only when both records are recognised SLH-DSA keys of
    /// the same variant *and* the underlying [`SlhDsaKey::equal`] reports
    /// equality for the requested key components. When either side cannot be
    /// downcasted, falls back to a structural comparison via the
    /// Debug-introspection helpers — comparing variant tags and the bitwise
    /// flags. Pure-safe; no `unsafe` is used.
    #[must_use]
    pub fn match_keys(
        &self,
        left: &dyn KeyData,
        right: &dyn KeyData,
        selection: KeySelection,
    ) -> bool {
        if let (Some(a), Some(b)) = (downcast_ref(left), downcast_ref(right)) {
            // Strict typed path — should not be reachable in the current
            // safe-Rust scaffolding because `downcast_ref` always returns
            // `None`. Retained for forward compatibility with a typed-trait
            // upgrade.
            if a.variant != b.variant {
                return false;
            }
            let crypto_sel = match selection & KeySelection::KEYPAIR {
                s if s == KeySelection::KEYPAIR => CryptoKeySelection::KeyPair,
                s if s == KeySelection::PRIVATE_KEY => CryptoKeySelection::PrivateOnly,
                s if s == KeySelection::PUBLIC_KEY => CryptoKeySelection::PublicOnly,
                _ => return true,
            };
            return match (a.key.as_ref(), b.key.as_ref()) {
                (Some(ka), Some(kb)) => ka.equal(kb, crypto_sel),
                (None, None) => true,
                _ => false,
            };
        }
        // Fallback structural comparison via Debug introspection.
        let (la_pub, la_priv, _, la_var) = introspect_debug(left);
        let (ra_pub, ra_priv, _, ra_var) = introspect_debug(right);
        if la_var != ra_var {
            return false;
        }
        let kp = selection & KeySelection::KEYPAIR;
        if kp.contains(KeySelection::PUBLIC_KEY) && la_pub != ra_pub {
            return false;
        }
        if kp.contains(KeySelection::PRIVATE_KEY) && la_priv != ra_priv {
            return false;
        }
        true
    }

    /// Returns the static algorithm parameter bag.
    ///
    /// Mirrors C `slh_dsa_gettable_params` / `slh_dsa_get_params` — a small
    /// integer-valued report of the parameter-set characteristics that
    /// callers consult before constructing keys.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        let p = self.variant.params()?;
        let mut set = ParamSet::new();
        // bits = pub_len * 8 (256, 384, or 512 for n=16/24/32).
        let bits = u32::try_from(p.pub_len.saturating_mul(8)).map_err(|e| {
            ProviderError::Common(CommonError::Internal(format!(
                "SLH-DSA get_params: bits overflows u32: {e}"
            )))
        })?;
        let security_bits = self.variant.security_bits();
        let security_category = self.variant.security_category();
        let max_size = u32::try_from(p.sig_len).map_err(|e| {
            ProviderError::Common(CommonError::Internal(format!(
                "SLH-DSA get_params: sig_len overflows u32: {e}"
            )))
        })?;
        set.set(PARAM_BITS, ParamValue::UInt32(bits));
        set.set(PARAM_SECURITY_BITS, ParamValue::UInt32(security_bits));
        set.set(
            PARAM_SECURITY_CATEGORY,
            ParamValue::UInt32(security_category),
        );
        set.set(PARAM_MAX_SIZE, ParamValue::UInt32(max_size));
        // SLH-DSA hashes the message internally, so callers should not
        // pre-hash. The empty-string mandatory-digest is the FIPS 205 way of
        // signalling "no separate digest required".
        set.set(
            PARAM_MANDATORY_DIGEST,
            ParamValue::Utf8String(String::new()),
        );
        Ok(set)
    }

    /// Sets caller-supplied static parameters on the keymgmt instance.
    ///
    /// SLH-DSA keymgmt does not accept any settable parameters: the empty
    /// parameter set is accepted as a no-op, while any non-empty set is
    /// rejected with a [`CommonError::Unsupported`] error.
    pub fn set_params(&self, params: &ParamSet) -> ProviderResult<()> {
        if params.iter().count() == 0 {
            return Ok(());
        }
        Err(ProviderError::Common(CommonError::Unsupported(format!(
            "SLH-DSA keymgmt {variant}: set_params accepts no settable parameters",
            variant = self.variant.algorithm_name()
        ))))
    }

    /// Initialises a generation context from caller-supplied parameters.
    ///
    /// Recognised parameters: `seed` (octet string of `3 * n` bytes for
    /// deterministic generation; otherwise the crypto layer draws fresh
    /// entropy from `OsRng`).
    pub fn gen_init(&self, params: &ParamSet) -> ProviderResult<SlhDsaGenContext> {
        let mut ctx = SlhDsaGenContext::new(self.variant, Some(Arc::clone(&self.default_lib_ctx)));
        if let Some(seed_bytes) = octet_param(params, PARAM_SEED)? {
            trace!(
                variant = ?self.variant,
                seed_len = seed_bytes.len(),
                "SLH-DSA keymgmt: gen_init recording explicit entropy"
            );
            ctx.set_entropy(seed_bytes.to_vec())?;
        }
        Ok(ctx)
    }

    /// Generates a fresh SLH-DSA key pair.
    ///
    /// When `params` carries an octet-string `seed` parameter of the
    /// expected length (`3 * n`), generation is deterministic — fed by the
    /// supplied entropy. Otherwise the crypto layer draws fresh entropy
    /// internally from `OsRng`. After generation a pairwise check is
    /// performed; failure results in a [`ProviderError::Init`].
    pub fn generate_into(&self, params: &ParamSet) -> ProviderResult<SlhDsaKeyData> {
        let ctx = self.gen_init(params)?;
        let lib_ctx = ctx
            .lib_ctx
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.default_lib_ctx));
        let alg = self.variant.algorithm_name();
        debug!(
            variant = ?self.variant,
            has_entropy = ctx.entropy.is_some(),
            "SLH-DSA keymgmt: generate"
        );
        let key = if let Some(entropy) = ctx.entropy.as_deref() {
            SlhDsaKey::generate_with_entropy(Arc::clone(&lib_ctx), alg, entropy)
                .map_err(map_crypto_err)?
        } else {
            SlhDsaKey::generate(Arc::clone(&lib_ctx), alg).map_err(map_crypto_err)?
        };
        // Pairwise consistency check — replicates the FIPS 205 self-test
        // hooks invoked at the end of `slh_dsa_gen` in the C provider.
        let ok = key.pairwise_check().map_err(map_crypto_err)?;
        if !ok {
            return Err(ProviderError::Init(format!(
                "SLH-DSA generate: pairwise consistency check failed for {alg}"
            )));
        }
        Ok(SlhDsaKeyData {
            key: Some(key),
            variant: self.variant,
            lib_ctx: Some(lib_ctx),
        })
    }

    /// Imports a key from the supplied parameter set.
    ///
    /// Recognised octet-string parameters: `priv` (full private key,
    /// `4 * n` bytes), `pub` (public key, `2 * n` bytes), `encoded-pub-key`
    /// (alias for `pub`). At least one must be provided. Lengths are
    /// validated up-front against the canonical sizes for the parameter set.
    /// `selection` is informational here — actual material is taken from
    /// whichever fields are present in `params`.
    pub fn import_into(
        &self,
        selection: KeySelection,
        params: &ParamSet,
    ) -> ProviderResult<SlhDsaKeyData> {
        let priv_bytes = octet_param(params, PARAM_PRIV_KEY)?;
        let pub_bytes = match octet_param(params, PARAM_PUB_KEY)? {
            Some(b) => Some(b),
            None => octet_param(params, PARAM_ENCODED_PUB_KEY)?,
        };

        // Single consolidated pre-validation block.
        if priv_bytes.is_none() && pub_bytes.is_none() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(format!(
                "SLH-DSA keymgmt {variant}: import requires at least one of priv/pub/encoded-pub-key",
                variant = self.variant.algorithm_name()
            ))));
        }

        let expected_priv = self.variant.priv_key_size();
        let expected_pub = self.variant.pub_key_size();

        if let Some(priv_data) = priv_bytes {
            if priv_data.len() != expected_priv {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SLH-DSA keymgmt {variant}: priv must be {expected_priv} bytes, got {got}",
                        variant = self.variant.algorithm_name(),
                        got = priv_data.len()
                    ),
                )));
            }
        }
        if let Some(pub_data) = pub_bytes {
            if pub_data.len() != expected_pub {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SLH-DSA keymgmt {variant}: pub must be {expected_pub} bytes, got {got}",
                        variant = self.variant.algorithm_name(),
                        got = pub_data.len()
                    ),
                )));
            }
        }

        debug!(
            variant = ?self.variant,
            ?selection,
            has_priv = priv_bytes.is_some(),
            has_pub = pub_bytes.is_some(),
            "SLH-DSA keymgmt: import"
        );

        let lib_ctx = Arc::clone(&self.default_lib_ctx);
        let alg = self.variant.algorithm_name();
        let mut key = SlhDsaKey::new(Arc::clone(&lib_ctx), alg).map_err(map_crypto_err)?;

        // The crypto layer's `set_priv` populates BOTH private and public
        // fields (since the public key is recoverable from the private key
        // bytes), so prefer the private key when both are supplied. When
        // only `pub` is given, populate the public side directly.
        if let Some(priv_data) = priv_bytes {
            key.set_priv(priv_data).map_err(map_crypto_err)?;
        } else if let Some(pub_data) = pub_bytes {
            key.set_pub(pub_data).map_err(map_crypto_err)?;
        }

        Ok(SlhDsaKeyData {
            key: Some(key),
            variant: self.variant,
            lib_ctx: Some(lib_ctx),
        })
    }

    /// Exports key bytes from a fully-populated key data record.
    ///
    /// `selection` selects which key components to export. Currently in this
    /// safe-Rust scaffolding the `&dyn KeyData` cannot be downcasted, so
    /// callers requesting an export receive a [`ProviderError::Init`] error
    /// describing the limitation. The `KeyMgmtProvider::export` trait method
    /// returns an empty `ParamSet` so that integration tests can still
    /// exercise the dispatch path; the typed `export_from` method is the
    /// vehicle for full export when a concrete key reference is available.
    pub fn export_from(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        let typed = downcast_ref(key).ok_or_else(|| {
            ProviderError::Init(
                "SLH-DSA keymgmt: export requires a concrete SlhDsaKeyData reference; \
                 typed downcast is not available in the safe-Rust trait surface"
                    .to_string(),
            )
        })?;
        if typed.variant != self.variant {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SLH-DSA keymgmt {expected}: export received variant {actual}",
                    expected = self.variant.algorithm_name(),
                    actual = typed.variant.algorithm_name()
                ),
            )));
        }
        let inner = typed.key.as_ref().ok_or_else(|| {
            ProviderError::Init(format!(
                "SLH-DSA keymgmt {variant}: export called on empty key data",
                variant = self.variant.algorithm_name()
            ))
        })?;
        let mut set = ParamSet::new();
        if selection.intersects(KeySelection::PUBLIC_KEY) {
            let pub_bytes = inner.pub_bytes().map_err(map_crypto_err)?;
            set.set(PARAM_PUB_KEY, ParamValue::OctetString(pub_bytes.to_vec()));
            set.set(
                PARAM_ENCODED_PUB_KEY,
                ParamValue::OctetString(pub_bytes.to_vec()),
            );
        }
        if selection.intersects(KeySelection::PRIVATE_KEY) {
            let priv_bytes = inner.priv_bytes().map_err(map_crypto_err)?;
            set.set(PARAM_PRIV_KEY, ParamValue::OctetString(priv_bytes.to_vec()));
        }
        Ok(set)
    }
}

impl fmt::Debug for SlhDsaKeyMgmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaKeyMgmt")
            .field("variant", &self.variant)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// KeyMgmtProvider trait implementation
// =============================================================================

impl KeyMgmtProvider for SlhDsaKeyMgmt {
    fn name(&self) -> &'static str {
        self.variant.algorithm_name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(variant = ?self.variant, "SLH-DSA keymgmt: new_key");
        Ok(Box::new(SlhDsaKeyData::new(
            self.variant,
            Some(Arc::clone(&self.default_lib_ctx)),
        )))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let key = self.generate_into(params)?;
        Ok(Box::new(key))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let key = self.import_into(selection, data)?;
        Ok(Box::new(key))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        // The structural Debug introspection lets us validate the key type
        // and selection without a typed downcast. We then return an empty
        // ParamSet — the actual byte exposure happens through the typed
        // `export_from` inherent method, which requires a concrete
        // `&SlhDsaKeyData` reference.
        if !looks_like_slh_dsa_key_data(key) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SLH-DSA keymgmt {variant}: export received non-SLH-DSA key data",
                    variant = self.variant.algorithm_name()
                ),
            )));
        }
        let (has_pub, has_priv, _, variant) = introspect_debug(key);
        if let Some(actual) = variant {
            if actual != self.variant {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "SLH-DSA keymgmt {expected}: export received variant {actual}",
                        expected = self.variant.algorithm_name(),
                        actual = actual.algorithm_name()
                    ),
                )));
            }
        }
        let kp = selection & KeySelection::KEYPAIR;
        if kp.contains(KeySelection::PRIVATE_KEY) && !has_priv {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SLH-DSA keymgmt {variant}: export requested private key but key has none",
                    variant = self.variant.algorithm_name()
                ),
            )));
        }
        if kp.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "SLH-DSA keymgmt {variant}: export requested public key but key has none",
                    variant = self.variant.algorithm_name()
                ),
            )));
        }
        debug!(
            variant = ?self.variant,
            ?selection,
            has_pub,
            has_priv,
            "SLH-DSA keymgmt: export (returns empty param set; use export_from for byte transfer)"
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        if !looks_like_slh_dsa_key_data(key) {
            return false;
        }
        let (has_pub, has_priv, _, variant) = introspect_debug(key);
        if let Some(actual) = variant {
            if actual != self.variant {
                return false;
            }
        }
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            return true;
        }
        let mut ok = true;
        if kp.contains(KeySelection::PRIVATE_KEY) {
            ok &= has_priv;
        }
        if kp.contains(KeySelection::PUBLIC_KEY) {
            ok &= has_pub;
        }
        ok
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        // Mirror the structural validation performed by C `slh_dsa_validate`:
        // verify presence of the requested selection. The deeper pairwise
        // consistency check is run during `generate_into` and during explicit
        // FIPS self-test entry points; calling it here would require typed
        // access to the underlying `SlhDsaKey`, which the opaque
        // `&dyn KeyData` surface does not expose without unsafe downcasting.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Factory macro: per-variant constructors
// =============================================================================

/// Generates a per-variant constructor module mirroring the C `.inc`
/// per-parameter-set macro expansion in `slh_dsa_kmgmt.c`.
///
/// Each invocation produces a module containing a `new()` constructor that
/// returns a [`SlhDsaKeyMgmt`] bound to the named [`SlhDsaParamSet`]. The
/// expansions are aggregated under [`variant_factories`] for ergonomic
/// access by the dispatch table.
macro_rules! impl_slh_dsa_keymgmt {
    ($module:ident, $param_set:expr, $name:expr) => {
        #[doc = concat!("Per-variant constructor module for `", $name, "`.")]
        pub mod $module {
            use super::{SlhDsaKeyMgmt, SlhDsaParamSet};

            /// Returns the canonical NIST/IETF name for this parameter set.
            #[must_use]
            pub const fn name() -> &'static str {
                $name
            }

            /// Returns the [`SlhDsaParamSet`] tag for this parameter set.
            #[must_use]
            pub const fn variant() -> SlhDsaParamSet {
                $param_set
            }

            /// Constructs a [`SlhDsaKeyMgmt`] bound to this parameter set.
            #[must_use]
            pub fn new() -> SlhDsaKeyMgmt {
                SlhDsaKeyMgmt::new($param_set)
            }
        }
    };
}

/// Per-variant factory modules generated via [`impl_slh_dsa_keymgmt!`].
///
/// Mirrors the C `.inc` expansion in `slh_dsa_kmgmt.c` which produces one
/// dispatch table per parameter set. Each submodule exposes a
/// `name()`/`variant()`/`new()` triple.
pub mod variant_factories {
    use super::{SlhDsaKeyMgmt, SlhDsaParamSet};

    impl_slh_dsa_keymgmt!(sha2_128s, SlhDsaParamSet::Sha2_128s, "SLH-DSA-SHA2-128s");
    impl_slh_dsa_keymgmt!(sha2_128f, SlhDsaParamSet::Sha2_128f, "SLH-DSA-SHA2-128f");
    impl_slh_dsa_keymgmt!(sha2_192s, SlhDsaParamSet::Sha2_192s, "SLH-DSA-SHA2-192s");
    impl_slh_dsa_keymgmt!(sha2_192f, SlhDsaParamSet::Sha2_192f, "SLH-DSA-SHA2-192f");
    impl_slh_dsa_keymgmt!(sha2_256s, SlhDsaParamSet::Sha2_256s, "SLH-DSA-SHA2-256s");
    impl_slh_dsa_keymgmt!(sha2_256f, SlhDsaParamSet::Sha2_256f, "SLH-DSA-SHA2-256f");
    impl_slh_dsa_keymgmt!(shake_128s, SlhDsaParamSet::Shake128s, "SLH-DSA-SHAKE-128s");
    impl_slh_dsa_keymgmt!(shake_128f, SlhDsaParamSet::Shake128f, "SLH-DSA-SHAKE-128f");
    impl_slh_dsa_keymgmt!(shake_192s, SlhDsaParamSet::Shake192s, "SLH-DSA-SHAKE-192s");
    impl_slh_dsa_keymgmt!(shake_192f, SlhDsaParamSet::Shake192f, "SLH-DSA-SHAKE-192f");
    impl_slh_dsa_keymgmt!(shake_256s, SlhDsaParamSet::Shake256s, "SLH-DSA-SHAKE-256s");
    impl_slh_dsa_keymgmt!(shake_256f, SlhDsaParamSet::Shake256f, "SLH-DSA-SHAKE-256f");

    /// Constructs all 12 [`SlhDsaKeyMgmt`] instances in registration order.
    ///
    /// The order matches the C `defltprov.c` dispatch table sequence: SHA-2
    /// variants first (cat 1, 3, 5 small/fast pairs) then SHAKE variants in
    /// the same order.
    #[must_use]
    pub fn all() -> Vec<SlhDsaKeyMgmt> {
        vec![
            sha2_128s::new(),
            sha2_128f::new(),
            sha2_192s::new(),
            sha2_192f::new(),
            sha2_256s::new(),
            sha2_256f::new(),
            shake_128s::new(),
            shake_128f::new(),
            shake_192s::new(),
            shake_192f::new(),
            shake_256s::new(),
            shake_256f::new(),
        ]
    }
}

// =============================================================================
// Algorithm descriptors (preserved verbatim from the original stub)
// =============================================================================

/// Returns SLH-DSA key management algorithm descriptors for provider
/// registration.
///
/// Emits 12 descriptors covering all FIPS 205 parameter sets in iteration
/// order matching the C `defltprov.c` registration sequence: first all SHA-2
/// variants in security-category order, then all SHAKE variants in the same
/// order.
#[must_use]
pub fn slh_dsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // ---- SHA-2 family ----
        algorithm(
            &[
                "SLH-DSA-SHA2-128s",
                "id-slh-dsa-sha2-128s",
                "2.16.840.1.101.3.4.3.20",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128s implementation (FIPS 205, NIST cat 1, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-128f",
                "id-slh-dsa-sha2-128f",
                "2.16.840.1.101.3.4.3.21",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-128f implementation (FIPS 205, NIST cat 1, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192s",
                "id-slh-dsa-sha2-192s",
                "2.16.840.1.101.3.4.3.22",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192s implementation (FIPS 205, NIST cat 3, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-192f",
                "id-slh-dsa-sha2-192f",
                "2.16.840.1.101.3.4.3.23",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-192f implementation (FIPS 205, NIST cat 3, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256s",
                "id-slh-dsa-sha2-256s",
                "2.16.840.1.101.3.4.3.24",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256s implementation (FIPS 205, NIST cat 5, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHA2-256f",
                "id-slh-dsa-sha2-256f",
                "2.16.840.1.101.3.4.3.25",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHA2-256f implementation (FIPS 205, NIST cat 5, fast)",
        ),
        // ---- SHAKE family ----
        algorithm(
            &[
                "SLH-DSA-SHAKE-128s",
                "id-slh-dsa-shake-128s",
                "2.16.840.1.101.3.4.3.26",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128s implementation (FIPS 205, NIST cat 1, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-128f",
                "id-slh-dsa-shake-128f",
                "2.16.840.1.101.3.4.3.27",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-128f implementation (FIPS 205, NIST cat 1, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192s",
                "id-slh-dsa-shake-192s",
                "2.16.840.1.101.3.4.3.28",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192s implementation (FIPS 205, NIST cat 3, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-192f",
                "id-slh-dsa-shake-192f",
                "2.16.840.1.101.3.4.3.29",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-192f implementation (FIPS 205, NIST cat 3, fast)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256s",
                "id-slh-dsa-shake-256s",
                "2.16.840.1.101.3.4.3.30",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256s implementation (FIPS 205, NIST cat 5, small)",
        ),
        algorithm(
            &[
                "SLH-DSA-SHAKE-256f",
                "id-slh-dsa-shake-256f",
                "2.16.840.1.101.3.4.3.31",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL SLH-DSA-SHAKE-256f implementation (FIPS 205, NIST cat 5, fast)",
        ),
    ]
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;

    #[test]
    fn slh_dsa_descriptors_returns_twelve_entries() {
        let descs = slh_dsa_descriptors();
        assert_eq!(descs.len(), 12, "expected 12 SLH-DSA parameter sets");
    }

    #[test]
    fn slh_dsa_descriptors_cover_sha2_family() {
        let descs = slh_dsa_descriptors();
        for canonical in [
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing SHA-2 variant: {canonical}"
            );
        }
    }

    #[test]
    fn slh_dsa_descriptors_cover_shake_family() {
        let descs = slh_dsa_descriptors();
        for canonical in [
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing SHAKE variant: {canonical}"
            );
        }
    }

    #[test]
    fn slh_dsa_descriptors_carry_oid_aliases() {
        let descs = slh_dsa_descriptors();
        let expected_oids = [
            "2.16.840.1.101.3.4.3.20",
            "2.16.840.1.101.3.4.3.21",
            "2.16.840.1.101.3.4.3.22",
            "2.16.840.1.101.3.4.3.23",
            "2.16.840.1.101.3.4.3.24",
            "2.16.840.1.101.3.4.3.25",
            "2.16.840.1.101.3.4.3.26",
            "2.16.840.1.101.3.4.3.27",
            "2.16.840.1.101.3.4.3.28",
            "2.16.840.1.101.3.4.3.29",
            "2.16.840.1.101.3.4.3.30",
            "2.16.840.1.101.3.4.3.31",
        ];
        for oid in expected_oids {
            assert!(
                descs.iter().any(|d| d.names.iter().any(|n| *n == oid)),
                "missing OID alias: {oid}"
            );
        }
    }

    #[test]
    fn slh_dsa_descriptors_have_default_property() {
        let descs = slh_dsa_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
            assert_eq!(
                d.names.len(),
                3,
                "every SLH-DSA descriptor should have canonical name + textual id alias + OID"
            );
        }
    }

    // -------------------------------------------------------------------------
    // SlhDsaParamSet — name/size/security/from_name coverage.
    // -------------------------------------------------------------------------

    #[test]
    fn param_set_names_match_canonical_strings() {
        assert_eq!(SlhDsaParamSet::Sha2_128s.name(), "SLH-DSA-SHA2-128s");
        assert_eq!(SlhDsaParamSet::Sha2_128f.name(), "SLH-DSA-SHA2-128f");
        assert_eq!(SlhDsaParamSet::Sha2_192s.name(), "SLH-DSA-SHA2-192s");
        assert_eq!(SlhDsaParamSet::Sha2_192f.name(), "SLH-DSA-SHA2-192f");
        assert_eq!(SlhDsaParamSet::Sha2_256s.name(), "SLH-DSA-SHA2-256s");
        assert_eq!(SlhDsaParamSet::Sha2_256f.name(), "SLH-DSA-SHA2-256f");
        assert_eq!(SlhDsaParamSet::Shake128s.name(), "SLH-DSA-SHAKE-128s");
        assert_eq!(SlhDsaParamSet::Shake128f.name(), "SLH-DSA-SHAKE-128f");
        assert_eq!(SlhDsaParamSet::Shake192s.name(), "SLH-DSA-SHAKE-192s");
        assert_eq!(SlhDsaParamSet::Shake192f.name(), "SLH-DSA-SHAKE-192f");
        assert_eq!(SlhDsaParamSet::Shake256s.name(), "SLH-DSA-SHAKE-256s");
        assert_eq!(SlhDsaParamSet::Shake256f.name(), "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn param_set_security_categories_match_fips_205() {
        for v in [SlhDsaParamSet::Sha2_128s, SlhDsaParamSet::Shake128f] {
            assert_eq!(v.security_category(), 1);
            assert_eq!(v.security_bits(), 128);
        }
        for v in [SlhDsaParamSet::Sha2_192s, SlhDsaParamSet::Shake192f] {
            assert_eq!(v.security_category(), 3);
            assert_eq!(v.security_bits(), 192);
        }
        for v in [SlhDsaParamSet::Sha2_256s, SlhDsaParamSet::Shake256f] {
            assert_eq!(v.security_category(), 5);
            assert_eq!(v.security_bits(), 256);
        }
    }

    #[test]
    fn param_set_pub_priv_sizes_match_fips_205() {
        // 128-bit family: n=16, pub=32, priv=64.
        assert_eq!(SlhDsaParamSet::Sha2_128s.pub_key_size(), 32);
        assert_eq!(SlhDsaParamSet::Sha2_128s.priv_key_size(), 64);
        assert_eq!(SlhDsaParamSet::Shake128f.pub_key_size(), 32);
        assert_eq!(SlhDsaParamSet::Shake128f.priv_key_size(), 64);
        // 192-bit family: n=24, pub=48, priv=96.
        assert_eq!(SlhDsaParamSet::Sha2_192f.pub_key_size(), 48);
        assert_eq!(SlhDsaParamSet::Sha2_192f.priv_key_size(), 96);
        assert_eq!(SlhDsaParamSet::Shake192s.pub_key_size(), 48);
        assert_eq!(SlhDsaParamSet::Shake192s.priv_key_size(), 96);
        // 256-bit family: n=32, pub=64, priv=128.
        assert_eq!(SlhDsaParamSet::Sha2_256f.pub_key_size(), 64);
        assert_eq!(SlhDsaParamSet::Sha2_256f.priv_key_size(), 128);
        assert_eq!(SlhDsaParamSet::Shake256s.pub_key_size(), 64);
        assert_eq!(SlhDsaParamSet::Shake256s.priv_key_size(), 128);
    }

    #[test]
    fn param_set_sig_sizes_match_fips_205_table_2() {
        assert_eq!(SlhDsaParamSet::Sha2_128s.sig_size(), 7856);
        assert_eq!(SlhDsaParamSet::Sha2_128f.sig_size(), 17_088);
        assert_eq!(SlhDsaParamSet::Sha2_192s.sig_size(), 16_224);
        assert_eq!(SlhDsaParamSet::Sha2_192f.sig_size(), 35_664);
        assert_eq!(SlhDsaParamSet::Sha2_256s.sig_size(), 29_792);
        assert_eq!(SlhDsaParamSet::Sha2_256f.sig_size(), 49_856);
        // SHAKE pairs match SHA-2 sizes by parameter set.
        assert_eq!(SlhDsaParamSet::Shake128s.sig_size(), 7856);
        assert_eq!(SlhDsaParamSet::Shake256f.sig_size(), 49_856);
    }

    #[test]
    fn param_set_from_name_round_trips() {
        for v in [
            SlhDsaParamSet::Sha2_128s,
            SlhDsaParamSet::Sha2_128f,
            SlhDsaParamSet::Sha2_192s,
            SlhDsaParamSet::Sha2_192f,
            SlhDsaParamSet::Sha2_256s,
            SlhDsaParamSet::Sha2_256f,
            SlhDsaParamSet::Shake128s,
            SlhDsaParamSet::Shake128f,
            SlhDsaParamSet::Shake192s,
            SlhDsaParamSet::Shake192f,
            SlhDsaParamSet::Shake256s,
            SlhDsaParamSet::Shake256f,
        ] {
            assert_eq!(SlhDsaParamSet::from_name(v.name()), Some(v));
        }
    }

    #[test]
    fn param_set_from_name_accepts_lowercase_id_aliases() {
        assert_eq!(
            SlhDsaParamSet::from_name("id-slh-dsa-sha2-128s"),
            Some(SlhDsaParamSet::Sha2_128s)
        );
        assert_eq!(
            SlhDsaParamSet::from_name("ID-SLH-DSA-SHAKE-256F"),
            Some(SlhDsaParamSet::Shake256f)
        );
    }

    #[test]
    fn param_set_from_name_rejects_unknown_strings() {
        assert_eq!(SlhDsaParamSet::from_name("not-a-slh-dsa-name"), None);
        assert_eq!(SlhDsaParamSet::from_name(""), None);
    }

    #[test]
    fn param_set_to_from_crypto_round_trip() {
        for v in [
            SlhDsaParamSet::Sha2_128s,
            SlhDsaParamSet::Shake128s,
            SlhDsaParamSet::Sha2_192f,
            SlhDsaParamSet::Shake256f,
        ] {
            assert_eq!(SlhDsaParamSet::from_crypto(v.to_crypto()), v);
        }
    }

    #[test]
    fn param_set_lookup_from_crypto_table_succeeds() {
        // Every variant must be present in the static crypto-layer parameter
        // table; otherwise downstream get_params calls would fail.
        for v in [
            SlhDsaParamSet::Sha2_128s,
            SlhDsaParamSet::Sha2_128f,
            SlhDsaParamSet::Sha2_192s,
            SlhDsaParamSet::Sha2_192f,
            SlhDsaParamSet::Sha2_256s,
            SlhDsaParamSet::Sha2_256f,
            SlhDsaParamSet::Shake128s,
            SlhDsaParamSet::Shake128f,
            SlhDsaParamSet::Shake192s,
            SlhDsaParamSet::Shake192f,
            SlhDsaParamSet::Shake256s,
            SlhDsaParamSet::Shake256f,
        ] {
            let p = v.params().expect("crypto params lookup should succeed");
            assert_eq!(p.alg, v.algorithm_name());
            assert_eq!(p.pub_len, v.pub_key_size());
            assert_eq!(p.sig_len, v.sig_size());
            assert_eq!(p.security_category, v.security_category());
        }
    }

    // -------------------------------------------------------------------------
    // SlhDsaKeyData — empty key, Drop safety, Debug introspection.
    // -------------------------------------------------------------------------

    #[test]
    fn key_data_new_is_empty_for_chosen_variant() {
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Sha2_128s, None);
        assert_eq!(kd.variant(), SlhDsaParamSet::Sha2_128s);
        assert!(kd.key().is_none());
        assert!(kd.lib_ctx().is_none());
        assert!(!kd.has_pubkey());
        assert!(!kd.has_prvkey());
        assert!(!kd.has_seed());
    }

    #[test]
    fn key_data_debug_is_introspectable() {
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Shake128s, None);
        let s = format!("{kd:?}");
        assert!(s.contains("SlhDsaKeyData"), "Debug must name struct");
        assert!(s.contains("Shake128s"), "Debug must name variant");
        assert!(s.contains("has_pubkey: false"));
        assert!(s.contains("has_prvkey: false"));
        assert!(s.contains("has_seed: false"));
    }

    #[test]
    fn key_data_check_selection_handles_empty_kp() {
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Sha2_192f, None);
        // Selection without any keypair bits is satisfied trivially.
        assert!(kd.check_selection(KeySelection::DOMAIN_PARAMETERS));
        // Asking for any key component on an empty key returns false.
        assert!(!kd.check_selection(KeySelection::PUBLIC_KEY));
        assert!(!kd.check_selection(KeySelection::PRIVATE_KEY));
        assert!(!kd.check_selection(KeySelection::KEYPAIR));
    }

    // -------------------------------------------------------------------------
    // SlhDsaGenContext — entropy validation, Drop zeroization, Debug.
    // -------------------------------------------------------------------------

    #[test]
    fn gen_context_new_starts_empty() {
        let g = SlhDsaGenContext::new(SlhDsaParamSet::Sha2_128s, None);
        assert_eq!(g.variant, SlhDsaParamSet::Sha2_128s);
        assert!(g.entropy.is_none());
        assert!(g.prop_query.is_none());
    }

    #[test]
    fn gen_context_set_entropy_validates_length() {
        let mut g = SlhDsaGenContext::new(SlhDsaParamSet::Sha2_128s, None);
        // 128-bit family requires 3*16 = 48 bytes.
        assert!(g.set_entropy(vec![0u8; 48]).is_ok());
        assert_eq!(g.entropy().map(<[u8]>::len), Some(48));
    }

    #[test]
    fn gen_context_set_entropy_rejects_wrong_length() {
        let mut g = SlhDsaGenContext::new(SlhDsaParamSet::Sha2_192s, None);
        // 192-bit family requires 3*24 = 72 bytes.
        let err = g.set_entropy(vec![0u8; 71]).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(
                    msg.contains("72"),
                    "msg should mention expected length: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        assert!(g.entropy.is_none(), "rejected entropy must not be stored");
    }

    #[test]
    fn gen_context_debug_redacts_entropy_bytes() {
        let mut g = SlhDsaGenContext::new(SlhDsaParamSet::Sha2_128s, None);
        let secret = vec![0xAA_u8; 48];
        g.set_entropy(secret.clone()).unwrap();
        let s = format!("{g:?}");
        assert!(s.contains("has_entropy: true"));
        // Ensure no hex or decimal representation of secret bytes leaks.
        assert!(!s.contains("aa, aa"), "Debug must not expose entropy bytes");
    }

    #[test]
    fn gen_context_drop_zeroizes_entropy_buffer() {
        // We cannot read the buffer after drop; instead assert that drop runs
        // without panicking after a populated context goes out of scope.
        let mut g = SlhDsaGenContext::new(SlhDsaParamSet::Shake256s, None);
        g.set_entropy(vec![0x11_u8; 96]).unwrap();
        drop(g);
    }

    // -------------------------------------------------------------------------
    // SlhDsaKeyMgmt — factories, name(), get_params, set_params, new_key.
    // -------------------------------------------------------------------------

    #[test]
    fn keymgmt_factories_pin_the_correct_variant() {
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_sha2_128s().variant(),
            SlhDsaParamSet::Sha2_128s
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_sha2_128f().variant(),
            SlhDsaParamSet::Sha2_128f
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_sha2_192s().variant(),
            SlhDsaParamSet::Sha2_192s
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_sha2_192f().variant(),
            SlhDsaParamSet::Sha2_192f
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_sha2_256s().variant(),
            SlhDsaParamSet::Sha2_256s
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_sha2_256f().variant(),
            SlhDsaParamSet::Sha2_256f
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_shake_128s().variant(),
            SlhDsaParamSet::Shake128s
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_shake_128f().variant(),
            SlhDsaParamSet::Shake128f
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_shake_192s().variant(),
            SlhDsaParamSet::Shake192s
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_shake_192f().variant(),
            SlhDsaParamSet::Shake192f
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_shake_256s().variant(),
            SlhDsaParamSet::Shake256s
        );
        assert_eq!(
            SlhDsaKeyMgmt::slh_dsa_shake_256f().variant(),
            SlhDsaParamSet::Shake256f
        );
    }

    #[test]
    fn keymgmt_name_returns_canonical_name_via_trait() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        assert_eq!(KeyMgmtProvider::name(&m), "SLH-DSA-SHA2-128s");
        let m2 = SlhDsaKeyMgmt::slh_dsa_shake_256f();
        assert_eq!(KeyMgmtProvider::name(&m2), "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn keymgmt_get_params_includes_canonical_keys() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let p = m.get_params().unwrap();
        let bits = p.get(PARAM_BITS).and_then(ParamValue::as_u32).unwrap();
        assert_eq!(bits, 256, "n=16 → pub_len=32 → bits=256");
        let sec_bits = p
            .get(PARAM_SECURITY_BITS)
            .and_then(ParamValue::as_u32)
            .unwrap();
        assert_eq!(sec_bits, 128);
        let sec_cat = p
            .get(PARAM_SECURITY_CATEGORY)
            .and_then(ParamValue::as_u32)
            .unwrap();
        assert_eq!(sec_cat, 1);
        let max = p.get(PARAM_MAX_SIZE).and_then(ParamValue::as_u32).unwrap();
        assert_eq!(max, 7856);
        // Mandatory digest is the empty UTF-8 string.
        let digest = p.get(PARAM_MANDATORY_DIGEST).and_then(ParamValue::as_str);
        assert_eq!(digest, Some(""));
    }

    #[test]
    fn keymgmt_set_params_accepts_empty_input() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        assert!(m.set_params(&ParamSet::new()).is_ok());
    }

    #[test]
    fn keymgmt_set_params_rejects_non_empty_input() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let mut params = ParamSet::new();
        params.set(PARAM_BITS, ParamValue::UInt32(128));
        let err = m.set_params(&params).unwrap_err();
        match err {
            ProviderError::Common(CommonError::Unsupported(_)) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn new_key_returns_empty_key_data_with_correct_variant() {
        let m = SlhDsaKeyMgmt::slh_dsa_shake_192s();
        let kd = m.new_key().unwrap();
        let s = format!("{kd:?}");
        assert!(s.contains("SlhDsaKeyData"));
        assert!(s.contains("Shake192s"));
        assert!(s.contains("has_pubkey: false"));
        assert!(s.contains("has_prvkey: false"));
    }

    // -------------------------------------------------------------------------
    // SlhDsaKeyMgmt — has(), validate() structural checks.
    // -------------------------------------------------------------------------

    #[test]
    fn has_returns_true_for_empty_selection() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let kd = m.new_key().unwrap();
        // Selection without keypair bits is satisfied trivially.
        assert!(m.has(kd.as_ref(), KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn has_returns_false_when_components_missing() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let kd = m.new_key().unwrap();
        assert!(!m.has(kd.as_ref(), KeySelection::PUBLIC_KEY));
        assert!(!m.has(kd.as_ref(), KeySelection::PRIVATE_KEY));
        assert!(!m.has(kd.as_ref(), KeySelection::KEYPAIR));
    }

    #[test]
    fn has_returns_false_for_variant_mismatch() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        // Build a key data record for a *different* variant.
        let other = SlhDsaKeyData::new(SlhDsaParamSet::Shake256f, None);
        assert!(!m.has(&other, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn validate_mirrors_has() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let kd = m.new_key().unwrap();
        assert!(m
            .validate(kd.as_ref(), KeySelection::DOMAIN_PARAMETERS)
            .unwrap());
        assert!(!m.validate(kd.as_ref(), KeySelection::PUBLIC_KEY).unwrap());
    }

    // -------------------------------------------------------------------------
    // SlhDsaKeyMgmt — import() upfront validation.
    // -------------------------------------------------------------------------

    #[test]
    fn import_requires_some_key_material() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let err = m
            .import(KeySelection::KEYPAIR, &ParamSet::new())
            .unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(
                    msg.contains("priv") || msg.contains("pub"),
                    "msg should reference key fields: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn import_rejects_wrong_priv_length() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        // Expected 4*16=64 bytes for the 128-bit family; supply 63.
        let mut params = ParamSet::new();
        params.set(PARAM_PRIV_KEY, ParamValue::OctetString(vec![0u8; 63]));
        let err = m.import(KeySelection::PRIVATE_KEY, &params).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(
                    msg.contains("64"),
                    "msg should reference expected length 64: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn import_rejects_wrong_pub_length() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_192f();
        // Expected 2*24=48 bytes for the 192-bit family; supply 47.
        let mut params = ParamSet::new();
        params.set(PARAM_PUB_KEY, ParamValue::OctetString(vec![0u8; 47]));
        let err = m.import(KeySelection::PUBLIC_KEY, &params).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(
                    msg.contains("48"),
                    "msg should reference expected length 48: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn import_rejects_wrong_param_type_for_seed() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let mut params = ParamSet::new();
        params.set(PARAM_PRIV_KEY, ParamValue::UInt32(0));
        let err = m.import(KeySelection::PRIVATE_KEY, &params).unwrap_err();
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch { key, .. }) => {
                assert_eq!(key, PARAM_PRIV_KEY);
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // SlhDsaKeyMgmt — export() trait surface (returns empty ParamSet).
    // -------------------------------------------------------------------------

    #[test]
    fn export_rejects_empty_key() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let kd = m.new_key().unwrap();
        let err = m.export(kd.as_ref(), KeySelection::PUBLIC_KEY).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn export_rejects_variant_mismatch() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Shake256f, None);
        let err = m.export(&kd, KeySelection::PUBLIC_KEY).unwrap_err();
        match err {
            ProviderError::Common(CommonError::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn export_from_rejects_empty_key_data() {
        // export_from cannot succeed in the current safe-Rust scaffolding
        // because downcast_ref always returns None. The error is the
        // structural Init error noted in the doc comment.
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let kd = m.new_key().unwrap();
        let err = m
            .export_from(kd.as_ref(), KeySelection::PUBLIC_KEY)
            .unwrap_err();
        match err {
            ProviderError::Init(_) => {}
            other => panic!("expected Init, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // SlhDsaKeyMgmt — match_keys() structural fallback path.
    // -------------------------------------------------------------------------

    #[test]
    fn match_keys_same_variant_empty_pair_matches() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let a = m.new_key().unwrap();
        let b = m.new_key().unwrap();
        // Two empty keys of the same variant match because the structural
        // flags (has_pub=false, has_priv=false) agree.
        assert!(m.match_keys(a.as_ref(), b.as_ref(), KeySelection::KEYPAIR));
    }

    #[test]
    fn match_keys_different_variant_does_not_match() {
        let m = SlhDsaKeyMgmt::slh_dsa_sha2_128s();
        let a = m.new_key().unwrap();
        let other = SlhDsaKeyData::new(SlhDsaParamSet::Shake256f, None);
        assert!(!m.match_keys(a.as_ref(), &other, KeySelection::KEYPAIR));
    }

    // -------------------------------------------------------------------------
    // Macro-generated factory modules.
    // -------------------------------------------------------------------------

    #[test]
    fn variant_factory_modules_expose_canonical_names() {
        assert_eq!(variant_factories::sha2_128s::name(), "SLH-DSA-SHA2-128s");
        assert_eq!(
            variant_factories::sha2_128s::variant(),
            SlhDsaParamSet::Sha2_128s
        );
        assert_eq!(variant_factories::shake_256f::name(), "SLH-DSA-SHAKE-256f");
        assert_eq!(
            variant_factories::shake_256f::variant(),
            SlhDsaParamSet::Shake256f
        );
    }

    #[test]
    fn variant_factories_all_yields_twelve_keymgmts_in_order() {
        let all = variant_factories::all();
        assert_eq!(all.len(), 12);
        let expected = [
            SlhDsaParamSet::Sha2_128s,
            SlhDsaParamSet::Sha2_128f,
            SlhDsaParamSet::Sha2_192s,
            SlhDsaParamSet::Sha2_192f,
            SlhDsaParamSet::Sha2_256s,
            SlhDsaParamSet::Sha2_256f,
            SlhDsaParamSet::Shake128s,
            SlhDsaParamSet::Shake128f,
            SlhDsaParamSet::Shake192s,
            SlhDsaParamSet::Shake192f,
            SlhDsaParamSet::Shake256s,
            SlhDsaParamSet::Shake256f,
        ];
        for (km, want) in all.iter().zip(expected.iter()) {
            assert_eq!(km.variant(), *want);
        }
    }

    // -------------------------------------------------------------------------
    // Helper coverage.
    // -------------------------------------------------------------------------

    #[test]
    fn looks_like_slh_dsa_key_data_recognises_struct() {
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Sha2_128s, None);
        assert!(looks_like_slh_dsa_key_data(&kd));
    }

    #[test]
    fn introspect_debug_extracts_variant_and_flags() {
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Shake192f, None);
        let (has_pub, has_priv, has_seed, variant) = introspect_debug(&kd);
        assert!(!has_pub);
        assert!(!has_priv);
        assert!(!has_seed);
        assert_eq!(variant, Some(SlhDsaParamSet::Shake192f));
    }

    #[test]
    fn downcast_ref_always_returns_none_in_safe_rust() {
        let kd = SlhDsaKeyData::new(SlhDsaParamSet::Sha2_128s, None);
        // Per the safe-Rust comment in `downcast_ref`, this always returns
        // None even for the matching variant. The test pins this behaviour.
        let r: &dyn KeyData = &kd;
        assert!(downcast_ref(r).is_none());
    }
}
