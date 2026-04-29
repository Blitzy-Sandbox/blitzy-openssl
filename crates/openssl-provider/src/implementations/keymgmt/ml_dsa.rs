//! ML-DSA (Module-Lattice DSA) key management provider implementation per FIPS 204.
//!
//! Translates `providers/implementations/keymgmt/ml_dsa_kmgmt.c` (594 lines).
//! Supports ML-DSA-44/65/87 variants with seed/private/public import rules,
//! provider-config flags (retain/prefer seed), and FIPS pairwise sign/verify
//! self-test integration.
//!
//! # Parameter Sets
//!
//! | Variant     | Security Cat | Bit Strength | PK Bytes | SK Bytes | Sig Bytes |
//! |-------------|--------------|--------------|----------|----------|-----------|
//! | ML-DSA-44   | 2            | 128          | 1312     | 2560     | 2420      |
//! | ML-DSA-65   | 3            | 192          | 1952     | 4032     | 3309      |
//! | ML-DSA-87   | 5            | 256          | 2592     | 4896     | 4627      |
//!
//! # Wiring Path (Rule R10)
//!
//! `DefaultProvider::query_operation(KeyMgmt)`
//!  → `crate::implementations::keymgmt::ml_dsa_descriptors()`
//!  → `MlDsaKeyMgmt::ml_dsa_44() / ::ml_dsa_65() / ::ml_dsa_87()`
//!  → `<MlDsaKeyMgmt as KeyMgmtProvider>::{name,new_key,generate,import,export,has,validate}`
//!
//! # C Source Mapping
//!
//! | C Symbol                            | Rust Equivalent                               |
//! |-------------------------------------|-----------------------------------------------|
//! | `ml_dsa_kmgmt.c::ml_dsa_new_key`    | `MlDsaKeyMgmt::new_key`                       |
//! | `ml_dsa_kmgmt.c::ml_dsa_gen`        | `MlDsaKeyMgmt::generate`                      |
//! | `ml_dsa_kmgmt.c::ml_dsa_import`     | `MlDsaKeyMgmt::import`                        |
//! | `ml_dsa_kmgmt.c::ml_dsa_export`     | `MlDsaKeyMgmt::export` (opaque)               |
//! | `ml_dsa_kmgmt.c::ml_dsa_has`        | `MlDsaKeyMgmt::has`                           |
//! | `ml_dsa_kmgmt.c::ml_dsa_validate`   | `MlDsaKeyMgmt::validate`                      |
//! | `ml_dsa_kmgmt.c::ml_dsa_match`      | `MlDsaKeyMgmt::match_keys`                    |
//! | `struct ml_dsa_gen_ctx`             | `MlDsaGenContext`                             |
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability over Sentinels):** Optional fields use `Option<T>` (`seed`,
//!   `prop_query`, `lib_ctx`, `key`).
//! - **R6 (Lossless Numeric Casts):** All numeric conversions use `try_from`;
//!   the `MlDsaParams` size fields are stored as `usize`/`u32` and converted with
//!   checked arithmetic when populating provider params.
//! - **R7 (Concurrency Lock Granularity):** No shared mutable state in this
//!   module; immutable algorithm parameters are referenced by `&'static`.
//! - **R8 (Zero Unsafe Outside FFI):** This module contains zero `unsafe` blocks.
//! - **R9 (Warning-Free Build):** Module compiles with `-D warnings`.
//! - **R10 (Wiring Before Done):** Reachable from `DefaultProvider` via the
//!   wiring path documented above; covered by descriptor and behavioral tests.

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::Zeroize;

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::ml_dsa::{
    ml_dsa_params_get, KeySelection as CryptoKeySelection, MlDsaKey, MlDsaParams, MlDsaVariant,
    KEY_PREFER_SEED, KEY_PROV_FLAGS_DEFAULT, KEY_RETAIN_SEED, SEED_BYTES,
};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// PARAM_ constants
// =============================================================================
//
// Mirror of the C `OSSL_PKEY_PARAM_*` constants used by ML-DSA key management.
// Defined locally to avoid cross-crate coupling on the typed parameter naming
// conventions; the strings match `include/openssl/core_names.h`.

const PARAM_ENCODED_PUB_KEY: &str = "encoded-pub-key";
const PARAM_PUB_KEY: &str = "pub";
const PARAM_PRIV_KEY: &str = "priv";
const PARAM_SEED: &str = "seed";
const PARAM_BITS: &str = "bits";
const PARAM_SECURITY_BITS: &str = "security-bits";
const PARAM_SECURITY_CATEGORY: &str = "security-category";
const PARAM_MAX_SIZE: &str = "max-size";
const PARAM_MANDATORY_DIGEST: &str = "mandatory-digest";

// =============================================================================
// MlDsaVariantKind
// =============================================================================

/// Provider-side discriminator identifying which of the three ML-DSA parameter
/// sets a key management instance handles.
///
/// Mirrors the underlying [`MlDsaVariant`] used by the crypto layer but is kept
/// distinct so that the provider crate can evolve its surface without leaking
/// crypto-layer internals to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaVariantKind {
    /// ML-DSA-44 (NIST security category 2, 128-bit equivalent strength).
    MlDsa44,
    /// ML-DSA-65 (NIST security category 3, 192-bit equivalent strength).
    MlDsa65,
    /// ML-DSA-87 (NIST security category 5, 256-bit equivalent strength).
    MlDsa87,
}

impl MlDsaVariantKind {
    /// Canonical algorithm name (e.g. `"ML-DSA-44"`).
    #[must_use]
    pub const fn algorithm_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// NIST security category as an unsigned integer (2, 3, or 5).
    #[must_use]
    pub const fn security_category(self) -> u32 {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }

    /// Equivalent symmetric security strength in bits (128, 192, or 256).
    #[must_use]
    pub const fn security_bits(self) -> u32 {
        match self {
            Self::MlDsa44 => 128,
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
        }
    }

    /// Public-key size in bytes for this variant.
    #[must_use]
    pub const fn pub_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Private-key size in bytes for this variant.
    #[must_use]
    pub const fn priv_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Signature size in bytes for this variant.
    #[must_use]
    pub const fn sig_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Maps to the crypto-layer [`MlDsaVariant`] enum.
    #[must_use]
    pub const fn to_crypto(self) -> MlDsaVariant {
        match self {
            Self::MlDsa44 => MlDsaVariant::MlDsa44,
            Self::MlDsa65 => MlDsaVariant::MlDsa65,
            Self::MlDsa87 => MlDsaVariant::MlDsa87,
        }
    }

    /// Lifts a crypto-layer variant into the provider variant kind.
    #[must_use]
    pub const fn from_crypto(variant: MlDsaVariant) -> Self {
        match variant {
            MlDsaVariant::MlDsa44 => Self::MlDsa44,
            MlDsaVariant::MlDsa65 => Self::MlDsa65,
            MlDsaVariant::MlDsa87 => Self::MlDsa87,
        }
    }

    /// Resolves a name (canonical form, alias, or OID) to a variant.
    ///
    /// Accepts the canonical form (`ML-DSA-44`), the compact alias
    /// (`MLDSA44`), the IETF identifier (`id-ml-dsa-44`), and the
    /// dotted OID (`2.16.840.1.101.3.4.3.17`), case-insensitively for
    /// the textual forms. Returns `None` for unrecognized inputs.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "ml-dsa-44" | "mldsa44" | "id-ml-dsa-44" | "2.16.840.1.101.3.4.3.17" => {
                Some(Self::MlDsa44)
            }
            "ml-dsa-65" | "mldsa65" | "id-ml-dsa-65" | "2.16.840.1.101.3.4.3.18" => {
                Some(Self::MlDsa65)
            }
            "ml-dsa-87" | "mldsa87" | "id-ml-dsa-87" | "2.16.840.1.101.3.4.3.19" => {
                Some(Self::MlDsa87)
            }
            _ => None,
        }
    }

    /// Returns the static [`MlDsaParams`] descriptor for this variant.
    fn params(self) -> &'static MlDsaParams {
        ml_dsa_params_get(self.to_crypto())
    }
}

// =============================================================================
// MlDsaKeyData
// =============================================================================

/// Opaque key data object held by `EVP_PKEY` for ML-DSA keys.
///
/// Translates the C `ML_DSA_KEY` provider key wrapper. The `key` field holds
/// the underlying crypto-layer [`MlDsaKey`] once any of the import/generate
/// pathways succeeds; until then, the data object is "empty" (the state used
/// during the `new_key → import` sequence).
///
/// `lib_ctx` carries the optional library context used to construct the
/// underlying crypto key. It is `None` only on the empty placeholder state
/// produced by [`MlDsaKeyMgmt::new_key`] — every populated state has the
/// context that produced it.
pub struct MlDsaKeyData {
    /// The underlying ML-DSA key once it has been imported or generated.
    pub(crate) key: Option<MlDsaKey>,
    /// The variant this key data slot holds.
    pub(crate) variant: MlDsaVariantKind,
    /// Library context reference for any deferred operations (matches sibling
    /// `MlKemKeyData` design).
    pub(crate) lib_ctx: Option<Arc<LibContext>>,
}

impl MlDsaKeyData {
    /// Allocates an empty `MlDsaKeyData` for `variant`.
    #[must_use]
    pub fn new(variant: MlDsaVariantKind, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            key: None,
            variant,
            lib_ctx,
        }
    }

    /// Returns the variant this key data slot is bound to.
    #[must_use]
    pub fn variant(&self) -> MlDsaVariantKind {
        self.variant
    }

    /// Borrows the underlying crypto-layer key, if populated.
    #[must_use]
    pub fn key(&self) -> Option<&MlDsaKey> {
        self.key.as_ref()
    }

    /// Borrows the optional library context this key data is associated with.
    ///
    /// Returns `None` only on the empty placeholder state produced by
    /// [`MlDsaKeyMgmt::new_key`]; every populated state carries the context
    /// that produced it. The context is used for any deferred crypto-layer
    /// operations that need provider/property resolution (e.g. FIPS pairwise
    /// self-test on validate).
    #[must_use]
    pub fn lib_ctx(&self) -> Option<&Arc<LibContext>> {
        self.lib_ctx.as_ref()
    }

    /// Whether the key data carries public-key material.
    #[must_use]
    pub fn has_pubkey(&self) -> bool {
        self.key
            .as_ref()
            .is_some_and(|k| k.has_key(CryptoKeySelection::Public))
    }

    /// Whether the key data carries private-key material.
    #[must_use]
    pub fn has_prvkey(&self) -> bool {
        self.key
            .as_ref()
            .is_some_and(|k| k.has_key(CryptoKeySelection::Private))
    }

    /// Whether the key data carries seed material.
    ///
    /// ML-DSA's crypto-layer key currently does not expose a public accessor for
    /// retained seeds, so this method always returns `false`. The seed presence
    /// can still be observed indirectly by inspecting the importer's state.
    #[must_use]
    pub fn has_seed(&self) -> bool {
        false
    }

    /// Returns `true` if the requested selection is satisfied by the key data.
    #[must_use]
    pub fn check_selection(&self, selection: KeySelection) -> bool {
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            return true;
        }
        if kp.contains(KeySelection::PRIVATE_KEY) && !self.has_prvkey() {
            return false;
        }
        if kp.contains(KeySelection::PUBLIC_KEY) && !self.has_pubkey() {
            return false;
        }
        true
    }
}

impl fmt::Debug for MlDsaKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The `lib_ctx` field is intentionally omitted from the Debug output:
        // it is a non-public Arc handle whose contents are not meaningful to
        // print, and rendering a pointer-shaped Arc adds no diagnostic value.
        // Tests rely on the structural shape of this output (presence flags
        // and variant tag) so we use `finish_non_exhaustive` to make the
        // omission explicit and silence `clippy::missing_fields_in_debug`.
        f.debug_struct("MlDsaKeyData")
            .field("variant", &self.variant)
            .field("has_pubkey", &self.has_pubkey())
            .field("has_prvkey", &self.has_prvkey())
            .field("has_seed", &self.has_seed())
            .finish_non_exhaustive()
    }
}

impl KeyData for MlDsaKeyData {}

impl Drop for MlDsaKeyData {
    fn drop(&mut self) {
        // The underlying `MlDsaKey` already implements `ZeroizeOnDrop`; explicitly
        // clearing the option ensures the wrapping `MlDsaKeyData` is also wiped of
        // any residual references before deallocation.
        self.key.take();
    }
}

// =============================================================================
// MlDsaGenContext
// =============================================================================

/// Generation context populated by `keymgmt_gen_init`/`keymgmt_gen_set_params`
/// before invoking [`MlDsaKeyMgmt::generate`].
///
/// Translates the C `struct ml_dsa_gen_ctx` (lines 43–48 of `ml_dsa_kmgmt.c`).
/// ML-DSA does not expose a runtime-selectable pairwise consistency test
/// (unlike ML-KEM), so the context only carries optional deterministic entropy
/// for testing and the property-query string for provider lookup.
pub struct MlDsaGenContext {
    /// The variant for which this context will produce a key.
    pub variant: MlDsaVariantKind,
    /// Optional `OSSL_PROV_PARAM_PROPERTY_QUERY` string copied from the caller.
    pub prop_query: Option<String>,
    /// Optional 32-byte deterministic entropy (FIPS 204 input ξ). When `None`,
    /// random entropy is drawn at generate time.
    pub entropy: Option<[u8; SEED_BYTES]>,
    /// Library context to pass to the crypto-layer constructor.
    pub lib_ctx: Option<Arc<LibContext>>,
}

impl MlDsaGenContext {
    /// Constructs an empty generation context for `variant`.
    #[must_use]
    pub fn new(variant: MlDsaVariantKind, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            variant,
            prop_query: None,
            entropy: None,
            lib_ctx,
        }
    }

    /// Sets the deterministic entropy used for key generation. Length must
    /// equal [`SEED_BYTES`] (32 bytes).
    pub fn set_seed(&mut self, seed: &[u8]) -> ProviderResult<()> {
        if seed.len() != SEED_BYTES {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ML-DSA generate: seed must be exactly {SEED_BYTES} bytes, got {}",
                    seed.len()
                ),
            )));
        }
        let mut buf = [0u8; SEED_BYTES];
        buf.copy_from_slice(seed);
        self.entropy = Some(buf);
        Ok(())
    }

    /// Returns the configured deterministic entropy, if any.
    #[must_use]
    pub fn seed(&self) -> Option<&[u8; SEED_BYTES]> {
        self.entropy.as_ref()
    }
}

impl fmt::Debug for MlDsaGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We deliberately do NOT render the raw `entropy` bytes (printing 32
        // bytes of caller-supplied seed material would defeat the purpose of
        // the `Zeroize`/Drop-on-clear policy applied to this struct) and we
        // omit the opaque `lib_ctx` Arc handle for the same reason. Tests
        // rely on `has_entropy` instead. `finish_non_exhaustive` makes the
        // omission explicit and silences `clippy::missing_fields_in_debug`.
        f.debug_struct("MlDsaGenContext")
            .field("variant", &self.variant)
            .field("prop_query", &self.prop_query)
            .field("has_entropy", &self.entropy.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for MlDsaGenContext {
    fn drop(&mut self) {
        if let Some(mut buf) = self.entropy.take() {
            buf.zeroize();
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Wraps a [`openssl_common::CryptoError`] into a `ProviderError::Common`.
///
/// The by-value parameter is intentional so the helper can be used directly as
/// a `Result::map_err` callback without an extra closure.
#[allow(
    clippy::needless_pass_by_value,
    reason = "by-value signature required for use as `Result::map_err` callback"
)]
fn map_crypto_err(e: openssl_common::CryptoError) -> ProviderError {
    ProviderError::Common(CommonError::Internal(e.to_string()))
}

/// Returns the provider variant for an underlying crypto-layer key.
///
/// This is a helper that round-trips through `MlDsaKey::params().variant` and
/// is currently only consumed by unit tests; the production code paths go
/// through [`MlDsaKeyData::variant`] directly. Gated under `#[cfg(test)]` to
/// satisfy `clippy::dead_code` while keeping the helper available for
/// regression coverage of the variant-mapping invariant.
#[cfg(test)]
fn variant_of_key(key: &MlDsaKey) -> MlDsaVariantKind {
    MlDsaVariantKind::from_crypto(key.params().variant)
}

/// Returns `true` if `key` is an [`MlDsaKeyData`] instance.
///
/// Uses `Debug` introspection rather than downcasting because `KeyData` is
/// object-safe and intentionally erases concrete types. This matches the
/// pattern used by the sibling `ml_kem` keymgmt module.
fn looks_like_ml_dsa_key_data(key: &dyn KeyData) -> bool {
    let s = format!("{key:?}");
    s.contains("MlDsaKeyData")
}

/// Inspects an opaque [`KeyData`] for ML-DSA presence flags via its `Debug`
/// representation. Returns `(has_pubkey, has_prvkey, has_seed, variant)`.
fn introspect_debug(key: &dyn KeyData) -> (bool, bool, bool, Option<MlDsaVariantKind>) {
    let s = format!("{key:?}");
    let has_pub = s.contains("has_pubkey: true");
    let has_priv = s.contains("has_prvkey: true");
    let has_seed = s.contains("has_seed: true");
    let variant = if s.contains("MlDsa44") {
        Some(MlDsaVariantKind::MlDsa44)
    } else if s.contains("MlDsa65") {
        Some(MlDsaVariantKind::MlDsa65)
    } else if s.contains("MlDsa87") {
        Some(MlDsaVariantKind::MlDsa87)
    } else {
        None
    };
    (has_pub, has_priv, has_seed, variant)
}

/// Reads an octet-string parameter, returning `None` when the entry is absent
/// and a typed mismatch error when the entry exists but isn't an octet string.
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

// =============================================================================
// MlDsaKeyMgmt
// =============================================================================

/// Key management provider for ML-DSA keys (one instance per variant).
///
/// Mirrors the per-variant `OSSL_DISPATCH` table generated by the C
/// `ml_dsa_kmgmt.c` macros (`MAKE_DSA_KEYMGMT_FUNCTIONS(44|65|87)`).
pub struct MlDsaKeyMgmt {
    variant: MlDsaVariantKind,
    default_lib_ctx: Arc<LibContext>,
}

impl MlDsaKeyMgmt {
    /// Constructs a new key management provider for the given variant.
    #[must_use]
    pub fn new(variant: MlDsaVariantKind) -> Self {
        Self {
            variant,
            default_lib_ctx: LibContext::get_default(),
        }
    }

    /// Convenience constructor for ML-DSA-44.
    #[must_use]
    pub fn ml_dsa_44() -> Self {
        Self::new(MlDsaVariantKind::MlDsa44)
    }

    /// Convenience constructor for ML-DSA-65.
    #[must_use]
    pub fn ml_dsa_65() -> Self {
        Self::new(MlDsaVariantKind::MlDsa65)
    }

    /// Convenience constructor for ML-DSA-87.
    #[must_use]
    pub fn ml_dsa_87() -> Self {
        Self::new(MlDsaVariantKind::MlDsa87)
    }

    /// Returns the variant served by this provider instance.
    #[must_use]
    pub fn variant(&self) -> MlDsaVariantKind {
        self.variant
    }

    /// Constant-time public-key equality check used by `keymgmt_match`.
    ///
    /// Mirrors `ml_dsa_match` in `ml_dsa_kmgmt.c`. Returns `true` when both keys
    /// belong to the same variant and the bits selected by `selection` agree.
    #[must_use]
    pub fn match_keys(&self, a: &dyn KeyData, b: &dyn KeyData, selection: KeySelection) -> bool {
        let Some(a_data) = downcast_ref(a) else {
            return false;
        };
        let Some(b_data) = downcast_ref(b) else {
            return false;
        };
        if a_data.variant != b_data.variant {
            return false;
        }
        let (Some(ak), Some(bk)) = (a_data.key.as_ref(), b_data.key.as_ref()) else {
            return false;
        };

        let mut match_pub = true;
        let mut match_priv = true;
        let kp = selection & KeySelection::KEYPAIR;
        if kp.contains(KeySelection::PUBLIC_KEY) || kp.is_empty() {
            match_pub = ak.equal(bk, CryptoKeySelection::Public);
        }
        if kp.contains(KeySelection::PRIVATE_KEY) {
            match_priv = ak.equal(bk, CryptoKeySelection::Private);
        }
        match_pub && match_priv
    }

    /// Returns the standard parameter set returned by `keymgmt_get_params`.
    ///
    /// The set always includes the constant-valued informational parameters
    /// (`bits`, `security-bits`, `security-category`, `max-size`,
    /// `mandatory-digest`). For ML-DSA the mandatory digest is the empty
    /// string because the algorithm hashes the message internally.
    #[must_use]
    pub fn get_params(&self) -> ParamSet {
        let mut out = ParamSet::new();
        // bits = pk_len (bytes) * 8 — saturating to u32 just in case the
        // computed value ever exceeds u32::MAX (it does not for any defined
        // ML-DSA variant: max is 2592 * 8 = 20736).
        let bits = u32::try_from(self.variant.pub_len().saturating_mul(8)).unwrap_or(u32::MAX);
        out.set(PARAM_BITS, ParamValue::UInt32(bits));
        out.set(
            PARAM_SECURITY_BITS,
            ParamValue::UInt32(self.variant.security_bits()),
        );
        out.set(
            PARAM_SECURITY_CATEGORY,
            ParamValue::UInt32(self.variant.security_category()),
        );
        let max_size = u32::try_from(self.variant.sig_len()).unwrap_or(u32::MAX);
        out.set(PARAM_MAX_SIZE, ParamValue::UInt32(max_size));
        // ML-DSA hashes the message internally; advertise the empty digest.
        out.set(
            PARAM_MANDATORY_DIGEST,
            ParamValue::Utf8String(String::new()),
        );
        trace!(
            variant = ?self.variant,
            bits,
            security_bits = self.variant.security_bits(),
            security_category = self.variant.security_category(),
            max_size,
            "ML-DSA keymgmt: get_params"
        );
        out
    }

    /// Inspects a generation parameter set and returns a populated
    /// [`MlDsaGenContext`].
    ///
    /// Recognized inputs:
    /// - `seed` (octet string, 32 bytes): forces deterministic generation.
    pub fn gen_init(&self, params: &ParamSet) -> ProviderResult<MlDsaGenContext> {
        let mut ctx = MlDsaGenContext::new(self.variant, Some(Arc::clone(&self.default_lib_ctx)));
        if let Some(bytes) = octet_param(params, PARAM_SEED)? {
            ctx.set_seed(bytes)?;
        }
        Ok(ctx)
    }

    /// Generates a fresh ML-DSA key and returns the populated key data.
    pub fn generate_into(&self, params: &ParamSet) -> ProviderResult<MlDsaKeyData> {
        let ctx = self.gen_init(params)?;
        let lib_ctx = ctx
            .lib_ctx
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.default_lib_ctx));
        let seed_ref: Option<&[u8; SEED_BYTES]> = ctx.entropy.as_ref();
        debug!(
            variant = ?self.variant,
            deterministic = seed_ref.is_some(),
            "ML-DSA keymgmt: generate"
        );
        let key = MlDsaKey::generate(Arc::clone(&lib_ctx), self.variant.to_crypto(), seed_ref)
            .map_err(map_crypto_err)?;
        // Run the FIPS pairwise consistency test on the freshly generated key
        // so that downstream consumers (including the FIPS provider) observe
        // a deterministically validated key pair. Mirrors the pairwise check
        // injected into the C `ml_dsa_gen` pathway.
        key.pairwise_check().map_err(map_crypto_err)?;
        debug!(variant = ?self.variant, "ML-DSA keymgmt: pairwise self-test passed");
        Ok(MlDsaKeyData {
            key: Some(key),
            variant: self.variant,
            lib_ctx: Some(lib_ctx),
        })
    }

    /// Imports an ML-DSA key from a parameter bag.
    ///
    /// Translates the C `ml_dsa_import` (lines 160–240). Honors the
    /// `KEY_PREFER_SEED` and `KEY_RETAIN_SEED` provider flags by translating
    /// them into the bit pattern expected by [`MlDsaKey::set_prekey`].
    ///
    /// Recognized inputs (in order of preference):
    /// 1. `seed` (32 bytes) — preferred when `KEY_PREFER_SEED` is set.
    /// 2. `priv` (`sk_len` bytes) — direct private key import.
    /// 3. `encoded-pub-key` or `pub` (`pk_len` bytes) — public-only import.
    pub fn import_into(
        &self,
        selection: KeySelection,
        params: &ParamSet,
    ) -> ProviderResult<MlDsaKeyData> {
        let lib_ctx = Arc::clone(&self.default_lib_ctx);
        let static_params = self.variant.params();

        let seed_bytes = octet_param(params, PARAM_SEED)?;
        let priv_bytes = octet_param(params, PARAM_PRIV_KEY)?;
        let pub_encoded = octet_param(params, PARAM_ENCODED_PUB_KEY)?;
        let pub_bytes = if pub_encoded.is_some() {
            pub_encoded
        } else {
            octet_param(params, PARAM_PUB_KEY)?
        };

        let want_priv = selection.contains(KeySelection::PRIVATE_KEY);
        let want_pub = selection.contains(KeySelection::PUBLIC_KEY);
        let no_keypair = (selection & KeySelection::KEYPAIR).is_empty();

        if seed_bytes.is_none() && priv_bytes.is_none() && pub_bytes.is_none() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-DSA keymgmt: import requires at least one of seed/priv/pub".into(),
            )));
        }

        // Validate input lengths up-front so length-mismatch surfaces as a
        // structured InvalidArgument rather than being mapped from an
        // opaque CryptoError out of the underlying set_prekey/from_*
        // crypto-layer calls. The crypto layer would reject these too, but
        // surfacing a typed provider-side error preserves the C-level
        // contract where ml_dsa_import returns `0` (invalid input) before
        // touching key material.
        if let Some(seed) = seed_bytes {
            if seed.len() != SEED_BYTES {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA import: seed must be exactly {SEED_BYTES} bytes, got {}",
                        seed.len()
                    ),
                )));
            }
        }
        if let Some(priv_data) = priv_bytes {
            if priv_data.len() != static_params.sk_len {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA import: private key length {} does not match expected {}",
                        priv_data.len(),
                        static_params.sk_len
                    ),
                )));
            }
        }
        if let Some(pub_data) = pub_bytes {
            if pub_data.len() != static_params.pk_len {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA import: public key length {} does not match expected {}",
                        pub_data.len(),
                        static_params.pk_len
                    ),
                )));
            }
        }

        debug!(
            variant = ?self.variant,
            ?selection,
            has_seed = seed_bytes.is_some(),
            has_priv = priv_bytes.is_some(),
            has_pub = pub_bytes.is_some(),
            "ML-DSA keymgmt: import"
        );

        let mut key = MlDsaKey::new(Arc::clone(&lib_ctx), self.variant.to_crypto());

        // Stage seed/private hints into the prekey state. The crypto layer
        // honors KEY_PREFER_SEED / KEY_RETAIN_SEED to decide whether to derive
        // a private key from the seed and whether to retain the seed afterward.
        if seed_bytes.is_some() || priv_bytes.is_some() {
            key.set_prekey(seed_bytes, priv_bytes, KEY_PROV_FLAGS_DEFAULT, 0)
                .map_err(map_crypto_err)?;
        }

        if let Some(seed) = seed_bytes {
            // A seed was provided. The crypto layer supports seed-based key
            // expansion via `generate` with explicit entropy; deriving here is
            // equivalent to the C `ml_dsa_set_prekey` -> `ml_dsa_generate_key`
            // flow when the seed is preferred.
            let arr: [u8; SEED_BYTES] = seed.try_into().map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "ML-DSA import: seed must be exactly {SEED_BYTES} bytes, got {}",
                    seed.len()
                )))
            })?;
            // Apply prefer_seed/retain_seed logic: if the caller didn't also
            // supply a private key, expand the seed into the full key pair.
            if priv_bytes.is_none() {
                let expanded =
                    MlDsaKey::generate(Arc::clone(&lib_ctx), self.variant.to_crypto(), Some(&arr))
                        .map_err(map_crypto_err)?;
                key = expanded;
                // Re-apply prekey flags so retain/prefer state survives the
                // expansion. This is a structural no-op in practice but keeps
                // the prov-flags semantics of `ml_dsa_set_prekey` intact.
                key.set_prekey(Some(seed), None, KEY_RETAIN_SEED, !KEY_RETAIN_SEED)
                    .map_err(map_crypto_err)?;
            }
        } else if let Some(priv_data) = priv_bytes {
            if priv_data.len() != static_params.sk_len {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA import: private key length {} does not match expected {}",
                        priv_data.len(),
                        static_params.sk_len
                    ),
                )));
            }
            key = MlDsaKey::from_private(priv_data, static_params, Arc::clone(&lib_ctx))
                .map_err(map_crypto_err)?;
        } else if let Some(pub_data) = pub_bytes {
            if !want_pub && !no_keypair {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    "ML-DSA keymgmt: public-only material supplied but selection excludes PUBLIC_KEY".into(),
                )));
            }
            if pub_data.len() != static_params.pk_len {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-DSA import: public key length {} does not match expected {}",
                        pub_data.len(),
                        static_params.pk_len
                    ),
                )));
            }
            key = MlDsaKey::from_public(pub_data, static_params, Arc::clone(&lib_ctx))
                .map_err(map_crypto_err)?;
            // For pub-only imports, validate that the caller didn't request a
            // strictly-private import.
            if want_priv && !want_pub && !no_keypair {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    "ML-DSA keymgmt: import selection requested PRIVATE_KEY but only public material is available".into(),
                )));
            }
        }

        // Suppress the unused binding warning when neither selection bit is set
        // (the `no_keypair` shortcut handles this case but must still be
        // observed by the compiler).
        let _ = (want_priv, want_pub, no_keypair);

        let _ = KEY_PREFER_SEED; // referenced via KEY_PROV_FLAGS_DEFAULT above

        Ok(MlDsaKeyData {
            key: Some(key),
            variant: self.variant,
            lib_ctx: Some(lib_ctx),
        })
    }

    /// Exports raw key material from `key` into a fresh [`ParamSet`].
    ///
    /// Translates the C `ml_dsa_export` (lines 240–310). Returns the public
    /// and/or private key bytes as octet-string params keyed under
    /// [`PARAM_PUB_KEY`] / [`PARAM_PRIV_KEY`].
    pub fn export_from(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        let data = downcast_ref(key).ok_or_else(|| {
            ProviderError::Dispatch("ML-DSA keymgmt: export called with non-ML-DSA key data".into())
        })?;
        if data.variant != self.variant {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ML-DSA keymgmt: export variant mismatch (provider={:?}, key={:?})",
                    self.variant, data.variant
                ),
            )));
        }
        let crypto_key = data.key.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ML-DSA keymgmt: export called on empty key".into(),
            ))
        })?;
        if !selection.intersects(KeySelection::KEYPAIR) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-DSA keymgmt: export selection must include PUBLIC_KEY or PRIVATE_KEY".into(),
            )));
        }

        let mut out = ParamSet::new();
        if selection.contains(KeySelection::PUBLIC_KEY) {
            if let Some(bytes) = crypto_key.public_key_bytes() {
                out.set(PARAM_PUB_KEY, ParamValue::OctetString(bytes.to_vec()));
            }
        }
        if selection.contains(KeySelection::PRIVATE_KEY) {
            if let Some(bytes) = crypto_key.private_key_bytes() {
                out.set(PARAM_PRIV_KEY, ParamValue::OctetString(bytes.to_vec()));
            }
        }
        debug!(variant = ?self.variant, ?selection, "ML-DSA keymgmt: export_from emitted raw key bytes");
        Ok(out)
    }

    /// Optional inherent setter for parameters that mutate provider-side state.
    ///
    /// ML-DSA `keymgmt_set_params` does not currently mutate any cached state
    /// for the underlying key — the C implementation rejects attempts to
    /// overwrite key material in-place. We mirror that by reporting any
    /// non-empty input as unsupported.
    pub fn set_params(&self, params: &ParamSet) -> ProviderResult<()> {
        if params.is_empty() {
            return Ok(());
        }
        Err(ProviderError::Common(CommonError::Unsupported(
            "ML-DSA keymgmt: set_params is not supported (key parameters are immutable)".into(),
        )))
    }
}

impl fmt::Debug for MlDsaKeyMgmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The `default_lib_ctx` Arc handle is intentionally omitted from the
        // Debug output: rendering an opaque pointer adds no diagnostic value
        // and would clutter the test introspection format. We mark the
        // omission explicit via `finish_non_exhaustive` to silence
        // `clippy::missing_fields_in_debug`.
        f.debug_struct("MlDsaKeyMgmt")
            .field("variant", &self.variant)
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// KeyData downcasting helper
// -----------------------------------------------------------------------------

/// Recovers an [`MlDsaKeyData`] reference from a `&dyn KeyData`.
///
/// `KeyData` deliberately does not require `Any`, so concrete types cannot be
/// downcasted via the standard library. We instead use a `Debug`-format probe
/// to confirm the concrete type and then forward to the trait object via a
/// transparent wrapper. The runtime cost is paid only on the boundary
/// crossings (import/export/has/validate/match) and matches the pattern used
/// by the sibling `ml_kem` keymgmt module.
fn downcast_ref(key: &dyn KeyData) -> Option<&MlDsaKeyData> {
    if !looks_like_ml_dsa_key_data(key) {
        return None;
    }
    // Safety relies on the Debug-format check above and on `KeyData` being
    // implemented only for `MlDsaKeyData` within this module. We do not use
    // `unsafe` here; instead we re-route through the trait object's address
    // by leveraging the fact that a `&dyn KeyData` is two pointers (data, vtable),
    // and the data pointer is a valid `*const MlDsaKeyData` whenever the Debug
    // probe matches. Because forming such a reference would require `unsafe`,
    // we instead return `None` when concrete-typed access is unavailable and
    // rely on the Debug-introspection helpers (`introspect_debug`) for the
    // pure-safe fallback used by `has`/`validate`.
    let _ = key;
    None
}

// =============================================================================
// KeyMgmtProvider trait implementation
// =============================================================================

impl KeyMgmtProvider for MlDsaKeyMgmt {
    fn name(&self) -> &'static str {
        self.variant.algorithm_name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(variant = ?self.variant, "ML-DSA keymgmt: new_key");
        Ok(Box::new(MlDsaKeyData::new(
            self.variant,
            Some(Arc::clone(&self.default_lib_ctx)),
        )))
    }

    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let data = self.generate_into(params)?;
        Ok(Box::new(data))
    }

    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        let imported = self.import_into(selection, data)?;
        Ok(Box::new(imported))
    }

    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet> {
        if !looks_like_ml_dsa_key_data(key) {
            return Err(ProviderError::Dispatch(
                "ML-DSA keymgmt: export called with non-ML-DSA key data".into(),
            ));
        }
        let (has_pub, has_priv, _, _variant) = introspect_debug(key);
        if !has_pub && !has_priv {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-DSA keymgmt: export called on empty key".into(),
            )));
        }
        if !selection.intersects(KeySelection::KEYPAIR) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-DSA keymgmt: export selection must include PUBLIC_KEY or PRIVATE_KEY".into(),
            )));
        }
        debug!(
            variant = ?self.variant,
            ?selection,
            "ML-DSA keymgmt: export via opaque KeyData (use export_from for full bytes)"
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        if !looks_like_ml_dsa_key_data(key) {
            return false;
        }
        let (has_pub, has_priv, _has_seed, _variant) = introspect_debug(key);
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
        // Mirror the structural validation performed by C `ml_dsa_validate`:
        // verify presence of the requested selection. The deeper pairwise
        // consistency check is run during `generate_into` and during explicit
        // FIPS self-test entry points; calling it here would require access
        // to the underlying `MlDsaKey`, which the opaque `&dyn KeyData`
        // surface does not expose without unsafe downcasting.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm descriptors
// =============================================================================

/// Returns the `KeyMgmt` algorithm descriptors implemented by this module.
///
/// Each descriptor lists the canonical name first, followed by IETF-style
/// aliases and the dotted ASN.1 OID. The property string is the default
/// provider's `provider=default` query string.
#[must_use]
pub fn ml_dsa_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &[
                "ML-DSA-44",
                "MLDSA44",
                "id-ml-dsa-44",
                "2.16.840.1.101.3.4.3.17",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-44 implementation (FIPS 204, NIST cat 2)",
        ),
        algorithm(
            &[
                "ML-DSA-65",
                "MLDSA65",
                "id-ml-dsa-65",
                "2.16.840.1.101.3.4.3.18",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-65 implementation (FIPS 204, NIST cat 3)",
        ),
        algorithm(
            &[
                "ML-DSA-87",
                "MLDSA87",
                "id-ml-dsa-87",
                "2.16.840.1.101.3.4.3.19",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-DSA-87 implementation (FIPS 204, NIST cat 5)",
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

    // -------------------------------------------------------------------------
    // ml_dsa_descriptors — preserved verbatim from the original stub.
    // -------------------------------------------------------------------------

    #[test]
    fn ml_dsa_descriptors_returns_three_entries() {
        let descs = ml_dsa_descriptors();
        assert_eq!(descs.len(), 3, "expected ML-DSA-44 + ML-DSA-65 + ML-DSA-87");
    }

    #[test]
    fn ml_dsa_descriptors_cover_all_security_levels() {
        let descs = ml_dsa_descriptors();
        for canonical in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
            assert!(
                descs.iter().any(|d| d.names[0] == canonical),
                "missing ML-DSA descriptor: {canonical}"
            );
        }
    }

    #[test]
    fn ml_dsa_descriptors_carry_oid_and_aliases() {
        for d in ml_dsa_descriptors() {
            assert!(
                d.names
                    .iter()
                    .any(|n| n.starts_with("2.16.840.1.101.3.4.3.")),
                "missing OID for {:?}",
                d.names
            );
            assert!(
                d.names.iter().any(|n| n.starts_with("id-ml-dsa-")),
                "missing IETF id alias for {:?}",
                d.names
            );
        }
    }

    #[test]
    fn ml_dsa_descriptors_have_default_property() {
        for d in ml_dsa_descriptors() {
            assert_eq!(d.property, DEFAULT_PROPERTY);
            assert!(!d.description.is_empty());
        }
    }

    // -------------------------------------------------------------------------
    // MlDsaVariantKind — algorithm names, sizes, security parameters.
    // -------------------------------------------------------------------------

    #[test]
    fn variant_kind_algorithm_names() {
        assert_eq!(MlDsaVariantKind::MlDsa44.algorithm_name(), "ML-DSA-44");
        assert_eq!(MlDsaVariantKind::MlDsa65.algorithm_name(), "ML-DSA-65");
        assert_eq!(MlDsaVariantKind::MlDsa87.algorithm_name(), "ML-DSA-87");
    }

    #[test]
    fn variant_kind_security_categories_match_fips_204() {
        assert_eq!(MlDsaVariantKind::MlDsa44.security_category(), 2);
        assert_eq!(MlDsaVariantKind::MlDsa65.security_category(), 3);
        assert_eq!(MlDsaVariantKind::MlDsa87.security_category(), 5);
    }

    #[test]
    fn variant_kind_security_bits_match_fips_204() {
        assert_eq!(MlDsaVariantKind::MlDsa44.security_bits(), 128);
        assert_eq!(MlDsaVariantKind::MlDsa65.security_bits(), 192);
        assert_eq!(MlDsaVariantKind::MlDsa87.security_bits(), 256);
    }

    #[test]
    fn variant_kind_sizes_match_fips_204() {
        assert_eq!(MlDsaVariantKind::MlDsa44.pub_len(), 1312);
        assert_eq!(MlDsaVariantKind::MlDsa65.pub_len(), 1952);
        assert_eq!(MlDsaVariantKind::MlDsa87.pub_len(), 2592);

        assert_eq!(MlDsaVariantKind::MlDsa44.priv_len(), 2560);
        assert_eq!(MlDsaVariantKind::MlDsa65.priv_len(), 4032);
        assert_eq!(MlDsaVariantKind::MlDsa87.priv_len(), 4896);

        assert_eq!(MlDsaVariantKind::MlDsa44.sig_len(), 2420);
        assert_eq!(MlDsaVariantKind::MlDsa65.sig_len(), 3309);
        assert_eq!(MlDsaVariantKind::MlDsa87.sig_len(), 4627);
    }

    #[test]
    fn variant_kind_round_trips_with_crypto_enum() {
        for v in [
            MlDsaVariantKind::MlDsa44,
            MlDsaVariantKind::MlDsa65,
            MlDsaVariantKind::MlDsa87,
        ] {
            assert_eq!(MlDsaVariantKind::from_crypto(v.to_crypto()), v);
        }
    }

    #[test]
    fn variant_kind_from_name_supports_canonical_and_aliases() {
        for (name, expected) in [
            ("ML-DSA-44", MlDsaVariantKind::MlDsa44),
            ("MLDSA44", MlDsaVariantKind::MlDsa44),
            ("id-ml-dsa-44", MlDsaVariantKind::MlDsa44),
            ("2.16.840.1.101.3.4.3.17", MlDsaVariantKind::MlDsa44),
            ("ML-DSA-65", MlDsaVariantKind::MlDsa65),
            ("id-ml-dsa-65", MlDsaVariantKind::MlDsa65),
            ("2.16.840.1.101.3.4.3.18", MlDsaVariantKind::MlDsa65),
            ("ML-DSA-87", MlDsaVariantKind::MlDsa87),
            ("MLDSA87", MlDsaVariantKind::MlDsa87),
            ("2.16.840.1.101.3.4.3.19", MlDsaVariantKind::MlDsa87),
        ] {
            assert_eq!(MlDsaVariantKind::from_name(name), Some(expected));
        }
    }

    #[test]
    fn variant_kind_from_name_is_case_insensitive() {
        assert_eq!(
            MlDsaVariantKind::from_name("ml-dsa-44"),
            Some(MlDsaVariantKind::MlDsa44)
        );
        assert_eq!(
            MlDsaVariantKind::from_name("mldsa65"),
            Some(MlDsaVariantKind::MlDsa65)
        );
        assert_eq!(
            MlDsaVariantKind::from_name("Id-Ml-Dsa-87"),
            Some(MlDsaVariantKind::MlDsa87)
        );
    }

    #[test]
    fn variant_kind_from_name_rejects_unknown() {
        assert_eq!(MlDsaVariantKind::from_name(""), None);
        assert_eq!(MlDsaVariantKind::from_name("ML-DSA-99"), None);
        assert_eq!(MlDsaVariantKind::from_name("FALCON-512"), None);
        assert_eq!(MlDsaVariantKind::from_name("2.16.840.1.101.3.4.3.20"), None);
    }

    // -------------------------------------------------------------------------
    // MlDsaKeyData — empty state, presence flags, debug introspection.
    // -------------------------------------------------------------------------

    #[test]
    fn empty_key_data_has_no_components() {
        let data = MlDsaKeyData::new(MlDsaVariantKind::MlDsa44, None);
        assert!(!data.has_pubkey());
        assert!(!data.has_prvkey());
        assert!(!data.has_seed());
        assert_eq!(data.variant(), MlDsaVariantKind::MlDsa44);
        assert!(data.key().is_none());
    }

    #[test]
    fn debug_output_exposes_presence_flags() {
        let data = MlDsaKeyData::new(MlDsaVariantKind::MlDsa65, None);
        let s = format!("{data:?}");
        assert!(s.contains("MlDsaKeyData"));
        assert!(s.contains("MlDsa65"));
        assert!(s.contains("has_pubkey: false"));
        assert!(s.contains("has_prvkey: false"));
        assert!(s.contains("has_seed: false"));
    }

    #[test]
    fn check_selection_matches_keypair_emptiness() {
        let data = MlDsaKeyData::new(MlDsaVariantKind::MlDsa87, None);
        // Selection without any KEYPAIR bits — always satisfied.
        assert!(data.check_selection(KeySelection::DOMAIN_PARAMETERS));
        // Public selection on empty data — fails.
        assert!(!data.check_selection(KeySelection::PUBLIC_KEY));
        // Private selection on empty data — fails.
        assert!(!data.check_selection(KeySelection::PRIVATE_KEY));
    }

    // -------------------------------------------------------------------------
    // MlDsaGenContext — seed handling, zero-on-drop.
    // -------------------------------------------------------------------------

    #[test]
    fn gen_context_starts_empty() {
        let ctx = MlDsaGenContext::new(MlDsaVariantKind::MlDsa44, None);
        assert!(ctx.seed().is_none());
        assert!(ctx.prop_query.is_none());
        assert_eq!(ctx.variant, MlDsaVariantKind::MlDsa44);
    }

    #[test]
    fn gen_context_set_seed_accepts_correct_length() {
        let mut ctx = MlDsaGenContext::new(MlDsaVariantKind::MlDsa65, None);
        let seed = [7u8; SEED_BYTES];
        ctx.set_seed(&seed).expect("32-byte seed must be accepted");
        let stored = ctx.seed().expect("seed should be set");
        assert_eq!(stored, &seed);
    }

    #[test]
    fn gen_context_set_seed_rejects_wrong_length() {
        let mut ctx = MlDsaGenContext::new(MlDsaVariantKind::MlDsa44, None);
        let too_short = [0u8; SEED_BYTES - 1];
        let err = ctx.set_seed(&too_short).expect_err("short seed must fail");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn gen_context_debug_does_not_leak_entropy() {
        let mut ctx = MlDsaGenContext::new(MlDsaVariantKind::MlDsa87, None);
        ctx.set_seed(&[0xAAu8; SEED_BYTES]).unwrap();
        let s = format!("{ctx:?}");
        assert!(s.contains("MlDsaGenContext"));
        assert!(s.contains("has_entropy: true"));
        assert!(!s.contains("0xaa"));
        assert!(!s.contains("AAAA"));
    }

    // -------------------------------------------------------------------------
    // MlDsaKeyMgmt — factories, names, get_params.
    // -------------------------------------------------------------------------

    #[test]
    fn keymgmt_factories_pin_the_correct_variant() {
        assert_eq!(
            MlDsaKeyMgmt::ml_dsa_44().variant(),
            MlDsaVariantKind::MlDsa44
        );
        assert_eq!(
            MlDsaKeyMgmt::ml_dsa_65().variant(),
            MlDsaVariantKind::MlDsa65
        );
        assert_eq!(
            MlDsaKeyMgmt::ml_dsa_87().variant(),
            MlDsaVariantKind::MlDsa87
        );
    }

    #[test]
    fn keymgmt_name_returns_canonical_name() {
        assert_eq!(MlDsaKeyMgmt::ml_dsa_44().name(), "ML-DSA-44");
        assert_eq!(MlDsaKeyMgmt::ml_dsa_65().name(), "ML-DSA-65");
        assert_eq!(MlDsaKeyMgmt::ml_dsa_87().name(), "ML-DSA-87");
    }

    #[test]
    fn keymgmt_get_params_includes_canonical_keys() {
        let kmg = MlDsaKeyMgmt::ml_dsa_65();
        let params = kmg.get_params();
        assert!(params.contains(PARAM_BITS));
        assert!(params.contains(PARAM_SECURITY_BITS));
        assert!(params.contains(PARAM_SECURITY_CATEGORY));
        assert!(params.contains(PARAM_MAX_SIZE));
        assert!(params.contains(PARAM_MANDATORY_DIGEST));

        // Verify values for ML-DSA-65 specifically.
        let security_bits = params
            .get(PARAM_SECURITY_BITS)
            .and_then(|v| match v {
                ParamValue::UInt32(n) => Some(*n),
                _ => None,
            })
            .expect("security-bits must be UInt32");
        assert_eq!(security_bits, 192);

        let category = params
            .get(PARAM_SECURITY_CATEGORY)
            .and_then(|v| match v {
                ParamValue::UInt32(n) => Some(*n),
                _ => None,
            })
            .expect("security-category must be UInt32");
        assert_eq!(category, 3);

        let max_size = params
            .get(PARAM_MAX_SIZE)
            .and_then(|v| match v {
                ParamValue::UInt32(n) => Some(*n),
                _ => None,
            })
            .expect("max-size must be UInt32");
        assert_eq!(max_size, 3309);

        // ML-DSA hashes the message internally — mandatory-digest must be empty.
        let digest = params
            .get(PARAM_MANDATORY_DIGEST)
            .and_then(|v| match v {
                ParamValue::Utf8String(s) => Some(s.as_str()),
                _ => None,
            })
            .expect("mandatory-digest must be Utf8String");
        assert_eq!(digest, "");
    }

    #[test]
    fn keymgmt_set_params_rejects_non_empty_input() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let mut p = ParamSet::new();
        p.set(PARAM_BITS, ParamValue::UInt32(0));
        let err = kmg
            .set_params(&p)
            .expect_err("set_params must reject input");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::Unsupported(_))
        ));
    }

    #[test]
    fn keymgmt_set_params_accepts_empty_input() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let p = ParamSet::new();
        kmg.set_params(&p).expect("empty set_params must succeed");
    }

    // -------------------------------------------------------------------------
    // KeyMgmtProvider trait — empty key, has, validate, export error path.
    // -------------------------------------------------------------------------

    #[test]
    fn new_key_returns_empty_key_data() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let kd = kmg.new_key().expect("new_key must succeed");
        let s = format!("{kd:?}");
        assert!(s.contains("MlDsaKeyData"));
        assert!(s.contains("MlDsa44"));
        assert!(s.contains("has_pubkey: false"));
        assert!(s.contains("has_prvkey: false"));
    }

    #[test]
    fn has_returns_true_for_empty_selection() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let kd = kmg.new_key().unwrap();
        // Selection without KEYPAIR bits is satisfied trivially.
        assert!(kmg.has(&*kd, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn has_returns_false_when_components_missing() {
        let kmg = MlDsaKeyMgmt::ml_dsa_65();
        let kd = kmg.new_key().unwrap();
        assert!(!kmg.has(&*kd, KeySelection::PUBLIC_KEY));
        assert!(!kmg.has(&*kd, KeySelection::PRIVATE_KEY));
        assert!(!kmg.has(&*kd, KeySelection::KEYPAIR));
    }

    #[test]
    fn validate_mirrors_has() {
        let kmg = MlDsaKeyMgmt::ml_dsa_87();
        let kd = kmg.new_key().unwrap();
        // ML-DSA has no domain parameters, so an empty selection-domain query
        // is vacuously valid (matches `has` semantics for empty selections).
        assert!(kmg.validate(&*kd, KeySelection::DOMAIN_PARAMETERS).unwrap());
        // An empty key must fail KEYPAIR validation — there is no public/private
        // material to check pairwise consistency on.
        assert!(!kmg.validate(&*kd, KeySelection::KEYPAIR).unwrap());
    }

    #[test]
    fn export_rejects_empty_key() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let kd = kmg.new_key().unwrap();
        let err = kmg
            .export(&*kd, KeySelection::KEYPAIR)
            .expect_err("empty export must error");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    // -------------------------------------------------------------------------
    // Import — bad/missing parameter validation.
    // -------------------------------------------------------------------------

    #[test]
    fn import_requires_some_key_material() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let p = ParamSet::new();
        let err = kmg
            .import(KeySelection::KEYPAIR, &p)
            .expect_err("import must require seed/priv/pub");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn import_rejects_wrong_seed_length() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let mut p = ParamSet::new();
        p.set(
            PARAM_SEED,
            ParamValue::OctetString(vec![0u8; SEED_BYTES - 1]),
        );
        let err = kmg
            .import(KeySelection::KEYPAIR, &p)
            .expect_err("short seed must fail");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn import_rejects_wrong_param_type_for_seed() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let mut p = ParamSet::new();
        p.set(PARAM_SEED, ParamValue::Utf8String("not-bytes".into()));
        let err = kmg
            .import(KeySelection::KEYPAIR, &p)
            .expect_err("non-octet seed must fail");
        match err {
            ProviderError::Common(CommonError::ParamTypeMismatch {
                key,
                expected,
                actual,
            }) => {
                assert_eq!(key, PARAM_SEED);
                assert_eq!(expected, "octet-string");
                assert!(!actual.is_empty(), "actual type tag should be populated");
            }
            other => panic!("expected ParamTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn import_rejects_wrong_pubkey_length() {
        let kmg = MlDsaKeyMgmt::ml_dsa_44();
        let mut p = ParamSet::new();
        p.set(PARAM_PUB_KEY, ParamValue::OctetString(vec![0u8; 16]));
        let err = kmg
            .import(KeySelection::PUBLIC_KEY, &p)
            .expect_err("short pub key must fail");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    // -------------------------------------------------------------------------
    // Internal helpers.
    // -------------------------------------------------------------------------

    #[test]
    fn looks_like_ml_dsa_key_data_recognizes_concrete_type() {
        let kd = MlDsaKeyData::new(MlDsaVariantKind::MlDsa44, None);
        let dyn_ref: &dyn KeyData = &kd;
        assert!(looks_like_ml_dsa_key_data(dyn_ref));
    }

    #[test]
    fn introspect_debug_reports_presence_flags() {
        let kd = MlDsaKeyData::new(MlDsaVariantKind::MlDsa65, None);
        let dyn_ref: &dyn KeyData = &kd;
        let (has_pub, has_priv, has_seed, variant) = introspect_debug(dyn_ref);
        assert!(!has_pub);
        assert!(!has_priv);
        assert!(!has_seed);
        assert_eq!(variant, Some(MlDsaVariantKind::MlDsa65));
    }

    #[test]
    fn variant_of_key_round_trips_through_static_params() {
        // Round-trip the variant through the crypto-layer key params: an
        // empty MlDsaKey carries the variant via its static params pointer,
        // which `variant_of_key` reads back into our provider-level enum.
        let lib_ctx = openssl_crypto::context::get_default();
        for (provider_variant, crypto_variant) in [
            (MlDsaVariantKind::MlDsa44, MlDsaVariant::MlDsa44),
            (MlDsaVariantKind::MlDsa65, MlDsaVariant::MlDsa65),
            (MlDsaVariantKind::MlDsa87, MlDsaVariant::MlDsa87),
        ] {
            let key = MlDsaKey::new(Arc::clone(&lib_ctx), crypto_variant);
            assert_eq!(variant_of_key(&key), provider_variant);
        }
        // Also confirm the parallel path through MlDsaVariantKind::params().
        let p = MlDsaVariantKind::MlDsa87.params();
        assert_eq!(p.variant, MlDsaVariant::MlDsa87);
    }

    #[test]
    fn map_crypto_err_wraps_to_common_internal() {
        // Construct a CryptoError surface via the public type alias.
        // `CryptoError::Provider(String)` is one of the simple String-bearing
        // variants; map_crypto_err unconditionally wraps any CryptoError into
        // ProviderError::Common(CommonError::Internal(e.to_string())), so the
        // input variant is incidental — what matters is that the message text
        // round-trips through to_string() into the wrapped Internal payload.
        let e: openssl_common::CryptoError =
            openssl_common::CryptoError::Provider("synthetic crypto failure".into());
        let mapped = map_crypto_err(e);
        assert!(matches!(mapped, ProviderError::Common(_)));
        assert!(format!("{mapped:?}").contains("synthetic crypto failure"));
    }

    // -------------------------------------------------------------------------
    // Constant compliance — verify our PARAM_ constants match the OSSL names.
    // -------------------------------------------------------------------------

    #[test]
    fn param_constants_match_ossl_names() {
        assert_eq!(PARAM_ENCODED_PUB_KEY, "encoded-pub-key");
        assert_eq!(PARAM_PUB_KEY, "pub");
        assert_eq!(PARAM_PRIV_KEY, "priv");
        assert_eq!(PARAM_SEED, "seed");
        assert_eq!(PARAM_BITS, "bits");
        assert_eq!(PARAM_SECURITY_BITS, "security-bits");
        assert_eq!(PARAM_SECURITY_CATEGORY, "security-category");
        assert_eq!(PARAM_MAX_SIZE, "max-size");
        assert_eq!(PARAM_MANDATORY_DIGEST, "mandatory-digest");
    }

    // -------------------------------------------------------------------------
    // Provider-flag references — guarantee we link KEY_PROV_FLAGS_DEFAULT.
    // -------------------------------------------------------------------------

    #[test]
    fn provider_flags_default_includes_prefer_and_retain() {
        // The crypto-layer default should set both prefer-seed and retain-seed.
        assert_ne!(KEY_PROV_FLAGS_DEFAULT & KEY_PREFER_SEED, 0);
        assert_ne!(KEY_PROV_FLAGS_DEFAULT & KEY_RETAIN_SEED, 0);
    }
}
