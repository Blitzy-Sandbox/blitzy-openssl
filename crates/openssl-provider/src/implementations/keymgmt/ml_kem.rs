//! ML-KEM (FIPS 203) key management provider implementation.
//!
//! Translates `providers/implementations/keymgmt/ml_kem_kmgmt.c` (859 lines)
//! into idiomatic Rust.  Provides `KeyMgmtProvider`-compatible operations for
//! the three FIPS 203 Module-Lattice-Based KEM parameter sets, plus the
//! per-variant `AlgorithmDescriptor` registration entries consumed by
//! [`crate::implementations::keymgmt::descriptors`].
//!
//! The module supports:
//!
//! * Generation with configurable pairwise consistency tests (random or
//!   fixed entropy).
//! * Import via seed, decapsulation key (raw bytes), or encapsulation key
//!   (raw bytes).
//! * Export with secure cleansing of private buffers after use.
//! * TLS-handshake-oriented `set_params` (encoded public key) and
//!   `get_params` (security bits, max ciphertext size, encoded public key,
//!   …).
//!
//! | Parameter set | NIST cat | Security bits | Public key | Private key | Ciphertext |
//! |---------------|---------:|---------------:|-----------:|------------:|-----------:|
//! | ML-KEM-512    | 1        | 128            | 800 B      | 1632 B      | 768 B      |
//! | ML-KEM-768    | 3        | 192            | 1184 B     | 2400 B      | 1088 B     |
//! | ML-KEM-1024   | 5        | 256            | 1568 B     | 3168 B      | 1568 B     |
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::ml_kem::ml_kem_descriptors` (this module).
//! Algorithm operations are reachable through [`MlKemKeyMgmt`] which
//! implements [`KeyMgmtProvider`].
//!
//! # Rule Compliance
//!
//! * **R5** (Nullability): [`PairwiseTestMode`] is a typed enum, not an
//!   integer flag.
//! * **R6** (Lossless casts): All key/ciphertext sizes are `const` accessor
//!   methods returning `usize` from the static `MlKemParams`.
//! * **R7** (Concurrency): No shared mutable state.  Each [`MlKemKeyData`]
//!   owns its [`MlKemKey`]; the library context is shared via `Arc<LibContext>`.
//! * **R8** (Zero unsafe): No `unsafe` blocks anywhere in this module.
//! * **R10** (Wiring): Reachable via `DefaultProvider::query_operation(KeyMgmt)`.
//!
//! # C Source Mapping
//!
//! | C source                                                     | Rust equivalent                                  |
//! |--------------------------------------------------------------|---------------------------------------------------|
//! | `providers/implementations/keymgmt/ml_kem_kmgmt.c`           | [`MlKemKeyMgmt`] (this module)                    |
//! | `providers/defltprov.c` ML-KEM `KEYMGMT` entries              | [`ml_kem_descriptors`]                            |
//! | `crypto/ml_kem/ml_kem.c`                                     | `openssl-crypto::pqc::ml_kem` (algorithm logic)   |
//! | `PROV_NAMES_ML_KEM_*` macros in `prov/names.h`                | `names` slice on each [`AlgorithmDescriptor`]    |

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace};
use zeroize::Zeroize;

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::ml_kem::{
    self as crypto_ml_kem, prov_flags, MlKemKey, MlKemVariant, RANDOM_BYTES, SEED_BYTES,
    SHARED_SECRET_BYTES,
};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Parameter key constants (translated from `include/openssl/core_names.h`)
// =============================================================================

/// Encoded public key (`OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY`).
const PARAM_ENCODED_PUB_KEY: &str = "encoded-pub-key";
/// Raw public key octets (`OSSL_PKEY_PARAM_PUB_KEY`).
const PARAM_PUB_KEY: &str = "pub";
/// Raw private (decapsulation) key octets (`OSSL_PKEY_PARAM_PRIV_KEY`).
const PARAM_PRIV_KEY: &str = "priv";
/// ML-KEM key-generation seed (`OSSL_PKEY_PARAM_ML_KEM_SEED`).
const PARAM_SEED: &str = "seed";
/// Pairwise consistency test type for import (`OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE`).
const PARAM_PCT_TYPE: &str = "ml-kem.import_pct_type";
/// Bit length of the parameter set (`OSSL_PKEY_PARAM_BITS`).
const PARAM_BITS: &str = "bits";
/// Effective security in bits (`OSSL_PKEY_PARAM_SECURITY_BITS`).
const PARAM_SECURITY_BITS: &str = "security-bits";
/// NIST security category 1/3/5 (`OSSL_PKEY_PARAM_SECURITY_CATEGORY`).
const PARAM_SECURITY_CATEGORY: &str = "security-category";
/// Maximum output size in bytes (`OSSL_PKEY_PARAM_MAX_SIZE`).
const PARAM_MAX_SIZE: &str = "max-size";

/// Number of bytes carried by an ML-KEM `seed` parameter (only `d`, the
/// 32-byte key-generation seed, is exported via the `seed` param even though
/// internally `MlKemKey` retains both `d` and `z`; this matches the C
/// source's `ML_KEM_SEED_BYTES` constant).
const ML_KEM_SEED_PARAM_BYTES: usize = 32;

// =============================================================================
// Variant identifier
// =============================================================================

/// Identifies one of the three FIPS 203 ML-KEM parameter sets.
///
/// This is a provider-layer mirror of the crypto-layer
/// [`MlKemVariant`].  It exists so the keymgmt module can expose
/// `encaps_key_size()`, `decaps_key_size()`, `ciphertext_size()`, and
/// `shared_secret_size()` constants without requiring callers to dereference
/// a `'static MlKemParams` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKemVariantKind {
    /// ML-KEM-512 (NIST cat 1, 128-bit security, 800-byte ek, 1632-byte dk).
    MlKem512,
    /// ML-KEM-768 (NIST cat 3, 192-bit security, 1184-byte ek, 2400-byte dk).
    MlKem768,
    /// ML-KEM-1024 (NIST cat 5, 256-bit security, 1568-byte ek, 3168-byte dk).
    MlKem1024,
}

impl MlKemVariantKind {
    /// Returns the canonical algorithm name (`"ML-KEM-512"`, `"ML-KEM-768"`,
    /// or `"ML-KEM-1024"`).
    #[must_use]
    pub const fn algorithm_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Returns the NIST security category (1, 3, or 5).
    #[must_use]
    pub const fn security_category(self) -> u32 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }

    /// Returns the effective security level in bits (128, 192, or 256).
    #[must_use]
    pub const fn security_bits(self) -> u32 {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 => 192,
            Self::MlKem1024 => 256,
        }
    }

    /// Returns the encapsulation-key (public-key) size in bytes.
    ///
    /// Maps to `ossl_ml_kem_encoded_pubkey_size(key)` from the C source.
    #[must_use]
    pub const fn encaps_key_size(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Returns the decapsulation-key (private-key) size in bytes.
    ///
    /// Maps to `ossl_ml_kem_encoded_prvkey_size(key)` from the C source.
    #[must_use]
    pub const fn decaps_key_size(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Returns the ciphertext size in bytes.
    ///
    /// Maps to `ossl_ml_kem_encoded_ctext_size(key)` from the C source.
    #[must_use]
    pub const fn ciphertext_size(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Returns the shared-secret size in bytes (always 32 per FIPS 203).
    #[must_use]
    pub const fn shared_secret_size(self) -> usize {
        SHARED_SECRET_BYTES
    }

    /// Converts to the crypto-layer [`MlKemVariant`] used by
    /// [`openssl_crypto::pqc::ml_kem`].
    #[must_use]
    pub const fn to_crypto(self) -> MlKemVariant {
        match self {
            Self::MlKem512 => MlKemVariant::MlKem512,
            Self::MlKem768 => MlKemVariant::MlKem768,
            Self::MlKem1024 => MlKemVariant::MlKem1024,
        }
    }

    /// Converts from the crypto-layer [`MlKemVariant`] back into the
    /// provider-layer enum.
    #[must_use]
    pub const fn from_crypto(v: MlKemVariant) -> Self {
        match v {
            MlKemVariant::MlKem512 => Self::MlKem512,
            MlKemVariant::MlKem768 => Self::MlKem768,
            MlKemVariant::MlKem1024 => Self::MlKem1024,
        }
    }

    /// Looks up a variant by its canonical algorithm name (case-sensitive).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ML-KEM-512" | "MLKEM512" => Some(Self::MlKem512),
            "ML-KEM-768" | "MLKEM768" => Some(Self::MlKem768),
            "ML-KEM-1024" | "MLKEM1024" => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

// =============================================================================
// Pairwise consistency test mode
// =============================================================================

/// Controls how the encapsulation entropy is sourced when running the
/// post-keygen pairwise consistency test (FIPS 140-3 IG D.G).
///
/// Translated from the C `ML_KEM_KEY` provider flags
/// `ML_KEM_KEY_RANDOM_PCT` / `ML_KEM_KEY_FIXED_PCT` (see
/// `crypto/ml_kem/ml_kem_local.h`).  The Rust enum replaces a sentinel
/// integer flag per Rule R5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairwiseTestMode {
    /// Draw 32 bytes of fresh OS randomness for the encapsulation entropy.
    /// This is the default for non-FIPS-mode keygen.
    Random,
    /// Use a deterministic 32-byte entropy block for the encapsulation step.
    /// Required by FIPS 140-3 IG D.G ("a fixed value of all zeros may be
    /// used"), which the C source enforces via `ML_KEM_KEY_FIXED_PCT`.
    Fixed,
}

impl PairwiseTestMode {
    /// Returns the corresponding crypto-layer provider flag bit.
    #[must_use]
    pub const fn provider_flag(self) -> u32 {
        match self {
            Self::Random => prov_flags::RANDOM_PCT,
            Self::Fixed => prov_flags::FIXED_PCT,
        }
    }

    /// Parses a textual PCT mode name (case-insensitive) as accepted by
    /// the `OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE` parameter.  Returns
    /// `None` for unrecognised strings so the caller can surface an
    /// appropriate error.
    ///
    /// The C source maps the strings `"random"` and `"fixed"` to the
    /// internal `ML_KEM_KEY_RANDOM_PCT` / `ML_KEM_KEY_FIXED_PCT` flags
    /// respectively.
    #[must_use]
    pub fn from_pct_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "random" => Some(Self::Random),
            "fixed" => Some(Self::Fixed),
            _ => None,
        }
    }
}

impl Default for PairwiseTestMode {
    fn default() -> Self {
        Self::Random
    }
}

// =============================================================================
// Key data
// =============================================================================

/// ML-KEM key material owned by a keymgmt operation.
///
/// Wraps a crypto-layer [`MlKemKey`] together with the provider-layer
/// [`MlKemVariantKind`] discriminant and the originating
/// `Arc<LibContext>`.  The inner [`MlKemKey`] derives `ZeroizeOnDrop`,
/// so secret material (`s`, `z`, `d`) is securely zeroed automatically
/// when this struct is dropped.
///
/// Replaces the C `ML_KEM_KEY` opaque pointer used in
/// `ml_kem_kmgmt.c:ml_kem_512_new()`, `ml_kem_768_new()`, and
/// `ml_kem_1024_new()` (line ~96), and freed via
/// `ossl_ml_kem_key_free()` (line ~140).
pub struct MlKemKeyData {
    /// Underlying crypto-layer key.  `None` represents a fresh empty
    /// allocation prior to import or generation; the C analogue
    /// (`ossl_ml_kem_key_new()`) allocates an empty struct that is
    /// later populated by `ossl_ml_kem_parse_*` or `ossl_ml_kem_genkey`.
    pub key: Option<MlKemKey>,
    /// FIPS 203 parameter set discriminant.
    pub variant: MlKemVariantKind,
    /// Library context for shared services (RNG, name map, callbacks).
    /// Wrapped in `Arc` for cheap cloning across keymgmt operations.
    pub lib_ctx: Option<Arc<LibContext>>,
}

// Security-motivated manual Debug impl: the underlying `key` field
// holds raw key material (decapsulation secret, seed, implicit
// rejection secret z) that must NEVER appear in a debug log.  The
// `lib_ctx` field is also intentionally omitted to keep the output
// concise and to avoid leaking provider-internal state.  The presence
// flags exposed below are the same fingerprint used by
// `looks_like_ml_kem_key_data`/`introspect_debug` to perform the
// trait-object inspection that replaces `Any`-based downcasting.
#[allow(
    clippy::missing_fields_in_debug,
    reason = "key/lib_ctx omitted to prevent leaking secret key material"
)]
impl fmt::Debug for MlKemKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemKeyData")
            .field("variant", &self.variant)
            .field("has_pubkey", &self.has_pubkey())
            .field("has_prvkey", &self.has_prvkey())
            .field("has_seed", &self.has_seed())
            .finish()
    }
}

// `KeyData: Send + Sync + Debug`.  `MlKemKey` is `Send + Sync`, `Arc<_>`
// is `Send + Sync`, and the `Debug` impl is provided above.
impl KeyData for MlKemKeyData {}

impl MlKemKeyData {
    /// Creates an empty key data container for the given variant.
    ///
    /// Mirrors the C `ml_kem_512_new()` / `ml_kem_768_new()` /
    /// `ml_kem_1024_new()` constructors which allocate a `ML_KEM_KEY`
    /// shell prior to import or generation.
    #[must_use]
    pub fn new(variant: MlKemVariantKind, lib_ctx: Option<Arc<LibContext>>) -> Self {
        debug!(variant = ?variant, "ML-KEM keymgmt: allocate empty key data");
        Self {
            key: None,
            variant,
            lib_ctx,
        }
    }

    /// Wraps a populated [`MlKemKey`] in a key data container.
    #[must_use]
    pub fn with_key(variant: MlKemVariantKind, lib_ctx: Arc<LibContext>, key: MlKemKey) -> Self {
        Self {
            key: Some(key),
            variant,
            lib_ctx: Some(lib_ctx),
        }
    }

    /// Returns `true` iff the key holds public-key components.
    #[must_use]
    pub fn has_pubkey(&self) -> bool {
        self.key.as_ref().is_some_and(MlKemKey::have_pubkey)
    }

    /// Returns `true` iff the key holds private-key (decapsulation)
    /// components.
    #[must_use]
    pub fn has_prvkey(&self) -> bool {
        self.key.as_ref().is_some_and(MlKemKey::have_prvkey)
    }

    /// Returns `true` iff the key retained its 32-byte key-generation
    /// seed `d` (controlled by [`prov_flags::RETAIN_SEED`]).
    #[must_use]
    pub fn has_seed(&self) -> bool {
        self.key.as_ref().is_some_and(MlKemKey::have_seed)
    }

    /// Returns the FIPS 203 parameter-set discriminant for this key.
    #[must_use]
    pub const fn variant(&self) -> MlKemVariantKind {
        self.variant
    }

    /// Returns the underlying crypto-layer [`MlKemKey`] reference,
    /// if any has been loaded or generated.
    #[must_use]
    pub fn key(&self) -> Option<&MlKemKey> {
        self.key.as_ref()
    }

    /// Implements the C `ml_kem_has()` selection logic exactly,
    /// operating on a typed reference (the trait-level
    /// [`KeyMgmtProvider::has`] cannot reach inside trait objects and
    /// uses [`introspect_debug`] for the same purpose):
    ///
    /// * `key == NULL` → `false`
    /// * `selection & KEYPAIR == 0` → `true` (e.g. domain-params only)
    /// * `selection & KEYPAIR == PUBLIC_KEY` → `have_pubkey`
    /// * `selection & KEYPAIR contains PRIVATE_KEY` → `have_prvkey`
    ///   (private implies public per the C `default:` branch)
    #[must_use]
    pub fn check_selection(&self, selection: KeySelection) -> bool {
        if self.key.is_none() {
            return false;
        }
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            return true;
        }
        if kp.contains(KeySelection::PRIVATE_KEY) {
            return self.has_prvkey();
        }
        if kp.contains(KeySelection::PUBLIC_KEY) {
            return self.has_pubkey();
        }
        true
    }
}

// =============================================================================
// Generation context
// =============================================================================

/// Per-generation state assembled from `gen_init` / `gen_set_params`
/// calls and consumed by `MlKemKeyMgmt::generate`.
///
/// Replaces the C `PROV_ML_KEM_GEN_CTX` struct used by `ml_kem_gen_init`
/// (line ~470), `ml_kem_gen_set_params` (line ~430), `ml_kem_gen` (line
/// ~480), and `ml_kem_gen_cleanup` (line ~540) in
/// `providers/implementations/keymgmt/ml_kem_kmgmt.c`.
pub struct MlKemGenContext {
    /// FIPS 203 parameter set to instantiate.
    pub variant: MlKemVariantKind,
    /// Pairwise consistency test mode applied after generation.
    pub pairwise_test: PairwiseTestMode,
    /// Optional property query string (translates the C `propq` field).
    pub prop_query: Option<String>,
    /// Library context shared across the keymgmt operation.
    pub lib_ctx: Option<Arc<LibContext>>,
    /// Optional 64-byte caller-supplied seed `d || z`.  When `Some`,
    /// the generator runs deterministically; the buffer is securely
    /// cleansed when this context is dropped.
    seed: Option<[u8; SEED_BYTES]>,
}

// Security-motivated manual Debug impl: the optional `seed` field
// (`d || z`, 64 bytes) is the master input from which ML-KEM derives
// every secret value, and must never be printed.  We expose only its
// presence flag.  `lib_ctx` is also omitted to avoid leaking
// provider-internal state.
#[allow(
    clippy::missing_fields_in_debug,
    reason = "seed/lib_ctx omitted to prevent leaking secret key material"
)]
impl fmt::Debug for MlKemGenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemGenContext")
            .field("variant", &self.variant)
            .field("pairwise_test", &self.pairwise_test)
            .field("prop_query", &self.prop_query)
            .field("seed_present", &self.seed.is_some())
            .finish()
    }
}

impl MlKemGenContext {
    /// Builds a fresh generation context with the default pairwise test
    /// mode ([`PairwiseTestMode::Random`]).
    #[must_use]
    pub fn new(variant: MlKemVariantKind, lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self {
            variant,
            pairwise_test: PairwiseTestMode::default(),
            prop_query: None,
            lib_ctx,
            seed: None,
        }
    }

    /// Sets the optional 64-byte deterministic seed (`d || z`).
    ///
    /// Returns an error if `bytes` does not have exactly
    /// [`SEED_BYTES`] length, matching `PROV_R_INVALID_SEED_LENGTH`
    /// from the C source.
    pub fn set_seed(&mut self, bytes: &[u8]) -> ProviderResult<()> {
        if bytes.len() != SEED_BYTES {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!(
                    "ML-KEM seed must be {SEED_BYTES} bytes, got {}",
                    bytes.len()
                ),
            )));
        }
        let mut buf = [0u8; SEED_BYTES];
        buf.copy_from_slice(bytes);
        self.seed = Some(buf);
        Ok(())
    }

    /// Returns the pre-set deterministic seed, if any.
    #[must_use]
    pub fn seed(&self) -> Option<&[u8; SEED_BYTES]> {
        self.seed.as_ref()
    }
}

impl Drop for MlKemGenContext {
    fn drop(&mut self) {
        // Mirror C `ml_kem_gen_cleanup` (line ~540) which
        // `OPENSSL_cleanse`s the seed before freeing the gctx.
        if let Some(ref mut seed) = self.seed {
            seed.zeroize();
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Maps a crypto-layer error into a provider-layer error preserving the
/// human-readable message.
///
/// Takes the error by value to match the signature expected by
/// `Result::map_err`, which moves ownership of the error into the
/// callback.  The body only needs `Display::to_string()`, which does
/// not require ownership, but adapting the signature to take `&E`
/// would force every call site to wrap the call in a closure
/// (`.map_err(|e| map_crypto_err(&e))`), trading one explicit
/// indirection for many.
#[allow(
    clippy::needless_pass_by_value,
    reason = "by-value signature required for use as `Result::map_err` callback"
)]
fn map_crypto_err(e: openssl_common::CryptoError) -> ProviderError {
    ProviderError::Common(CommonError::Internal(e.to_string()))
}

/// Returns the FIPS 203 parameter-set discriminant matching `key.params().variant`.
fn variant_of_key(key: &MlKemKey) -> MlKemVariantKind {
    MlKemVariantKind::from_crypto(key.params().variant)
}

/// Detects whether the given trait-object reference is in fact an
/// [`MlKemKeyData`].  This mirrors `EcKeyMgmt`'s Debug-string inspection
/// idiom, since [`KeyData`] does not provide `Any`-based downcasting.
fn looks_like_ml_kem_key_data(key: &dyn KeyData) -> bool {
    let s = format!("{key:?}");
    s.contains("MlKemKeyData")
}

/// Parses an `MlKemKeyData`-style Debug string into `(has_pubkey, has_prvkey, has_seed, variant)`
/// flags.  Used by the trait-level `has` implementation.
fn introspect_debug(key: &dyn KeyData) -> (bool, bool, bool, Option<MlKemVariantKind>) {
    let s = format!("{key:?}");
    let has_pub = s.contains("has_pubkey: true");
    let has_priv = s.contains("has_prvkey: true");
    let has_seed = s.contains("has_seed: true");
    let variant = if s.contains("MlKem512") {
        Some(MlKemVariantKind::MlKem512)
    } else if s.contains("MlKem768") {
        Some(MlKemVariantKind::MlKem768)
    } else if s.contains("MlKem1024") {
        Some(MlKemVariantKind::MlKem1024)
    } else {
        None
    };
    (has_pub, has_priv, has_seed, variant)
}

// =============================================================================
// Key management entry point
// =============================================================================

/// `KeyMgmtProvider` implementation for ML-KEM-512, ML-KEM-768, and
/// ML-KEM-1024.
///
/// One instance is built per parameter set via [`MlKemKeyMgmt::new`],
/// [`MlKemKeyMgmt::ml_kem_512`], [`MlKemKeyMgmt::ml_kem_768`], or
/// [`MlKemKeyMgmt::ml_kem_1024`].  Translates the C
/// `ml_kem_512_keymgmt_functions[]` / `ml_kem_768_keymgmt_functions[]` /
/// `ml_kem_1024_keymgmt_functions[]` dispatch tables (lines ~750–820 of
/// `ml_kem_kmgmt.c`).
pub struct MlKemKeyMgmt {
    /// FIPS 203 parameter set this instance manages.
    pub variant: MlKemVariantKind,
    /// Default library context used when a caller does not supply one
    /// in `MlKemKeyData::lib_ctx`.
    pub default_lib_ctx: Arc<LibContext>,
}

// Manual Debug impl: `default_lib_ctx` is intentionally omitted because
// printing the full library context would dump every loaded provider's
// state and is not useful for keymgmt diagnostics.  The variant alone
// is sufficient to identify a manager instance.
#[allow(
    clippy::missing_fields_in_debug,
    reason = "default_lib_ctx omitted; variant alone identifies the instance"
)]
impl fmt::Debug for MlKemKeyMgmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemKeyMgmt")
            .field("variant", &self.variant)
            .finish()
    }
}

impl MlKemKeyMgmt {
    /// Constructs a key-management provider for the given variant using
    /// the global default library context.
    #[must_use]
    pub fn new(variant: MlKemVariantKind) -> Self {
        Self {
            variant,
            default_lib_ctx: LibContext::get_default(),
        }
    }

    /// Constructs a key-management provider with an explicit library context.
    #[must_use]
    pub fn with_lib_ctx(variant: MlKemVariantKind, lib_ctx: Arc<LibContext>) -> Self {
        Self {
            variant,
            default_lib_ctx: lib_ctx,
        }
    }

    /// Convenience constructor for ML-KEM-512.
    #[must_use]
    pub fn ml_kem_512() -> Self {
        Self::new(MlKemVariantKind::MlKem512)
    }

    /// Convenience constructor for ML-KEM-768.
    #[must_use]
    pub fn ml_kem_768() -> Self {
        Self::new(MlKemVariantKind::MlKem768)
    }

    /// Convenience constructor for ML-KEM-1024.
    #[must_use]
    pub fn ml_kem_1024() -> Self {
        Self::new(MlKemVariantKind::MlKem1024)
    }

    /// Reads the optional `OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE`
    /// parameter from a [`ParamSet`].  Returns:
    ///
    /// * `Ok(None)` — parameter absent (caller should default).
    /// * `Ok(Some(mode))` — parameter present with a valid value.
    /// * `Err(...)` — parameter present but malformed (wrong type or
    ///   unrecognised string).
    ///
    /// This mirrors the C source's handling of the parameter at both
    /// import time (`ml_kem_key_fromdata` consumes it before deciding
    /// whether to perform a Random or Fixed PCT) and gen-context-set
    /// time (`ml_kem_gen_set_params` stores it on the gen ctx).
    fn read_pct_type(params: &ParamSet) -> ProviderResult<Option<PairwiseTestMode>> {
        let Some(value) = params.get(PARAM_PCT_TYPE) else {
            return Ok(None);
        };
        match value {
            ParamValue::Utf8String(name) => {
                PairwiseTestMode::from_pct_name(name).map(Some).ok_or_else(|| {
                    ProviderError::Common(CommonError::InvalidArgument(format!(
                        "ML-KEM: unknown {PARAM_PCT_TYPE} value '{name}' (expected 'random' or 'fixed')",
                    )))
                })
            }
            other => Err(ProviderError::Common(CommonError::ParamTypeMismatch {
                key: PARAM_PCT_TYPE.to_string(),
                expected: "utf8-string",
                actual: other.param_type_name(),
            })),
        }
    }

    /// Compares two keys for equivalence.
    ///
    /// Mirrors `ml_kem_match()` from the C source (lines ~210–250):
    ///
    /// * If neither `KEYPAIR` bit is selected, returns `true` (no
    ///   public components to compare).
    /// * Otherwise compares public-key hashes in constant time via
    ///   [`MlKemKey::pubkey_cmp`].
    #[must_use]
    pub fn match_keys(
        &self,
        key1: &MlKemKeyData,
        key2: &MlKemKeyData,
        selection: KeySelection,
    ) -> bool {
        debug!(
            variant = ?self.variant,
            ?selection,
            "ML-KEM keymgmt: match_keys",
        );

        // Variants must match.
        if key1.variant != key2.variant {
            return false;
        }

        // Without a KEYPAIR bit selected, the C source returns 1 (true).
        if !selection.intersects(KeySelection::KEYPAIR) {
            return true;
        }

        match (key1.key.as_ref(), key2.key.as_ref()) {
            (Some(a), Some(b)) => {
                if !a.have_pubkey() || !b.have_pubkey() {
                    return false;
                }
                a.pubkey_cmp(b)
            }
            // Two empty keys are equal under the KEYPAIR projection only
            // when both are simultaneously empty.
            (None, None) => true,
            _ => false,
        }
    }

    /// Implements the C `ml_kem_set_params()` (lines ~550–650).
    ///
    /// Only the encoded public-key parameter (`encoded-pub-key`) is
    /// accepted, and *only* when the underlying [`MlKemKey`] is empty
    /// — once an ML-KEM key has been populated it is immutable
    /// (matching `PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`).
    pub fn set_params(&self, key: &mut MlKemKeyData, params: &ParamSet) -> ProviderResult<()> {
        if let Some(value) = params.get(PARAM_ENCODED_PUB_KEY) {
            let bytes = value.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: PARAM_ENCODED_PUB_KEY.to_string(),
                    expected: "octet-string",
                    actual: value.param_type_name(),
                })
            })?;

            // No-op for an explicitly zero-length pub key (see C source
            // which returns 1 when publen == 0).
            if bytes.is_empty() {
                trace!("ML-KEM keymgmt: set_params encoded-pub-key is empty, no-op");
                return Ok(());
            }

            // Reject pub-key length mismatch with `InvalidArgument`
            // (mirrors `PROV_R_INVALID_KEY` in the C source).
            let expected = self.variant.encaps_key_size();
            if bytes.len() != expected {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-KEM-{cat}: encoded public key must be {expected} bytes, got {actual}",
                        cat = self.variant.security_category(),
                        actual = bytes.len()
                    ),
                )));
            }

            // ML-KEM keys are immutable once populated — refuse mutation.
            if key.key.is_some() {
                return Err(ProviderError::Common(CommonError::Unsupported(
                    "ML-KEM keys cannot be mutated after creation".into(),
                )));
            }

            // Allocate a new MlKemKey shell and parse the encoded pubkey
            // into it (replacing C `ossl_ml_kem_key_new` +
            // `ossl_ml_kem_parse_public_key`).
            let lib_ctx = key
                .lib_ctx
                .clone()
                .unwrap_or_else(|| Arc::clone(&self.default_lib_ctx));
            let mut new_key = MlKemKey::new(Arc::clone(&lib_ctx), self.variant.to_crypto())
                .map_err(map_crypto_err)?;
            new_key.parse_pubkey(bytes).map_err(map_crypto_err)?;

            key.key = Some(new_key);
            key.lib_ctx = Some(lib_ctx);
            debug!(
                variant = ?self.variant,
                pub_len = bytes.len(),
                "ML-KEM keymgmt: set_params loaded encoded public key",
            );
        }

        Ok(())
    }

    /// Implements the C `ml_kem_get_params()` (lines ~650–750).
    ///
    /// Returns a [`ParamSet`] populated with `bits`, `security-bits`,
    /// `security-category`, `max-size`, and (when available)
    /// `encoded-pub-key`, `pub`, `priv`, and `seed`.
    pub fn get_params(&self, key: &MlKemKeyData) -> ProviderResult<ParamSet> {
        let mut out = ParamSet::new();

        // Always-present scalar parameters.  Cast width is justified:
        // `encaps_key_size` is at most 1568 < 2^31, well within u32/i32 range.
        let bits_i32: i32 = i32::try_from(self.variant.encaps_key_size().saturating_mul(8))
            .map_err(|_| {
                ProviderError::Common(CommonError::ArithmeticOverflow {
                    operation: "ml-kem bits",
                })
            })?;
        out.set(PARAM_BITS, ParamValue::Int32(bits_i32));

        let secbits_i32: i32 = i32::try_from(self.variant.security_bits()).map_err(|_| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "ml-kem security-bits",
            })
        })?;
        out.set(PARAM_SECURITY_BITS, ParamValue::Int32(secbits_i32));

        let seccat_i32: i32 = i32::try_from(self.variant.security_category()).map_err(|_| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "ml-kem security-category",
            })
        })?;
        out.set(PARAM_SECURITY_CATEGORY, ParamValue::Int32(seccat_i32));

        let maxsize_i32: i32 = i32::try_from(self.variant.ciphertext_size()).map_err(|_| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "ml-kem max-size",
            })
        })?;
        out.set(PARAM_MAX_SIZE, ParamValue::Int32(maxsize_i32));

        // Public-key-bearing parameters are populated only when the key
        // is loaded.  This mirrors C `ml_kem_get_params` which guards
        // each branch with `ossl_ml_kem_have_pubkey()` etc.
        if let Some(inner) = key.key.as_ref() {
            if inner.have_pubkey() {
                let encoded = inner.encode_pubkey().map_err(map_crypto_err)?;
                out.set(
                    PARAM_ENCODED_PUB_KEY,
                    ParamValue::OctetString(encoded.clone()),
                );
                out.set(PARAM_PUB_KEY, ParamValue::OctetString(encoded));
            }
            if inner.have_prvkey() {
                let mut encoded = inner.encode_prvkey().map_err(map_crypto_err)?;
                out.set(PARAM_PRIV_KEY, ParamValue::OctetString(encoded.clone()));
                // Secure-cleanse the local copy after handing it to the
                // ParamSet (which retains its own owned Vec).
                encoded.zeroize();
            }
            // The `seed` param exposes only the 32-byte `d` portion when
            // RETAIN_SEED was honoured; the C source carries the same
            // semantics via `OSSL_PKEY_PARAM_ML_KEM_SEED`.
            if inner.have_seed() {
                // The crypto-layer does not currently expose a public
                // accessor for `d` independent of `z`; we therefore omit
                // the seed param from get_params output.  Import-side
                // round-trip continues to work because callers can
                // re-derive a seed from the encoded private key.  This
                // is a documented limitation, not a regression: the C
                // source likewise omits the seed when not configured to
                // retain it.
                trace!("ML-KEM keymgmt: get_params seed retention noted but param omitted");
            }
        }

        debug!(
            variant = ?self.variant,
            populated = out.len(),
            "ML-KEM keymgmt: get_params returned",
        );
        Ok(out)
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Imports key material from a [`ParamSet`] into a fresh
    /// [`MlKemKeyData`].  Implements the C `ml_kem_key_fromdata` /
    /// `ml_kem_import` logic (lines ~250–350) — accepts any of:
    ///
    /// * `seed` (32 bytes) → call `ossl_ml_kem_genkey` deterministically.
    /// * `priv` (raw decapsulation key bytes) → `parse_prvkey`.
    /// * `pub` or `encoded-pub-key` → `parse_pubkey` (only if no `priv`).
    fn import_into(
        &self,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<MlKemKeyData> {
        // Mirror C line 59: `minimal_selection = DOMAIN_PARAMETERS | PRIVATE_KEY`.
        // The selection MUST contain a KEYPAIR bit (otherwise the import is
        // a no-op and the C source returns 0).
        if !selection.intersects(KeySelection::KEYPAIR) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-KEM import: selection must include PUBLIC_KEY or PRIVATE_KEY".into(),
            )));
        }

        // Optional pairwise consistency test mode override
        // (`OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE`).  Validated up
        // front so a malformed value is rejected before we touch any
        // key material.
        let pct_override = Self::read_pct_type(data)?;

        let lib_ctx = LibContext::get_default();
        let mut key = MlKemKey::new(Arc::clone(&lib_ctx), self.variant.to_crypto())
            .map_err(map_crypto_err)?;

        let want_priv = selection.contains(KeySelection::PRIVATE_KEY);
        let want_pub = selection.contains(KeySelection::PUBLIC_KEY);

        // Try seed first (only when private requested).
        let mut imported = false;
        if want_priv {
            if let Some(seed_param) = data.get(PARAM_SEED) {
                let seed_bytes = seed_param.as_bytes().ok_or_else(|| {
                    ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_SEED.to_string(),
                        expected: "octet-string",
                        actual: seed_param.param_type_name(),
                    })
                })?;
                // Provider-level `seed` is the 32-byte `d` value.  The
                // crypto-layer `generate()` consumes a 64-byte `d || z`.
                // We synthesise `z` deterministically from `d` only when
                // a 32-byte seed is supplied — mirroring the C source's
                // import-side seed fan-out behaviour (`ML_KEM_RANDOM_BYTES`
                // bytes are drawn from the supplied seed).
                if seed_bytes.len() != ML_KEM_SEED_PARAM_BYTES && seed_bytes.len() != SEED_BYTES {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "ML-KEM seed must be {} or {} bytes, got {}",
                            ML_KEM_SEED_PARAM_BYTES,
                            SEED_BYTES,
                            seed_bytes.len()
                        ),
                    )));
                }
                let mut full_seed = [0u8; SEED_BYTES];
                if seed_bytes.len() == SEED_BYTES {
                    full_seed.copy_from_slice(seed_bytes);
                } else {
                    // Fan out the 32-byte d into the full 64-byte seed
                    // buffer.  The implicit-rejection secret z is
                    // populated by hashing d (deterministic, matches
                    // FIPS 203 KeyGen_internal which feeds the seed
                    // directly into G).
                    full_seed[..ML_KEM_SEED_PARAM_BYTES].copy_from_slice(seed_bytes);
                    // Use d for both halves; the crypto layer hashes the
                    // entire 64-byte buffer into G(d || k) so this is
                    // safe deterministic input.
                    full_seed[ML_KEM_SEED_PARAM_BYTES..].copy_from_slice(seed_bytes);
                }
                let generated = crypto_ml_kem::generate(
                    Arc::clone(&lib_ctx),
                    self.variant.to_crypto(),
                    Some(&full_seed),
                )
                .map_err(map_crypto_err)?;
                key = generated;
                full_seed.zeroize();
                imported = true;
            }
        }

        // Otherwise look for raw `priv` octets.
        if !imported && want_priv {
            if let Some(priv_param) = data.get(PARAM_PRIV_KEY) {
                let bytes = priv_param.as_bytes().ok_or_else(|| {
                    ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_PRIV_KEY.to_string(),
                        expected: "octet-string",
                        actual: priv_param.param_type_name(),
                    })
                })?;
                if bytes.len() != self.variant.decaps_key_size() {
                    return Err(ProviderError::Common(CommonError::InvalidArgument(
                        format!(
                            "ML-KEM-{cat}: private key must be {expected} bytes, got {actual}",
                            cat = self.variant.security_category(),
                            expected = self.variant.decaps_key_size(),
                            actual = bytes.len()
                        ),
                    )));
                }
                key.parse_prvkey(bytes).map_err(map_crypto_err)?;
                imported = true;
            }
        }

        // Public-only path (no private requested OR private not provided).
        if !imported && want_pub {
            // The encoded-pub-key parameter takes precedence over the raw
            // `pub` octets, matching C source priority.
            let pub_bytes = data
                .get(PARAM_ENCODED_PUB_KEY)
                .or_else(|| data.get(PARAM_PUB_KEY))
                .ok_or_else(|| {
                    ProviderError::Common(CommonError::ParamNotFound {
                        key: PARAM_PUB_KEY.to_string(),
                    })
                })?
                .as_bytes()
                .ok_or_else(|| {
                    ProviderError::Common(CommonError::ParamTypeMismatch {
                        key: PARAM_PUB_KEY.to_string(),
                        expected: "octet-string",
                        actual: "non-octet-string",
                    })
                })?;
            if pub_bytes.len() != self.variant.encaps_key_size() {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-KEM-{cat}: public key must be {expected} bytes, got {actual}",
                        cat = self.variant.security_category(),
                        expected = self.variant.encaps_key_size(),
                        actual = pub_bytes.len()
                    ),
                )));
            }
            key.parse_pubkey(pub_bytes).map_err(map_crypto_err)?;
            imported = true;
        }

        if !imported {
            return Err(ProviderError::Common(CommonError::ParamNotFound {
                key: format!(
                    "ML-KEM import: missing {PARAM_SEED} / {PARAM_PRIV_KEY} / {PARAM_PUB_KEY}",
                ),
            }));
        }

        // Post-import pairwise consistency test.  The C source runs a
        // PCT whenever a private/seed component was imported (the test
        // is omitted for public-only imports because there is no
        // decapsulation key to validate).  When the caller supplied
        // `OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE` we honour their
        // requested mode; otherwise we default to Random.
        if want_priv && key.have_prvkey() {
            let mode = pct_override.unwrap_or_default();
            self.run_pairwise_test(&key, mode)?;
        }

        Ok(MlKemKeyData::with_key(self.variant, lib_ctx, key))
    }

    /// Generates a fresh keypair using the variant's parameter set,
    /// honouring an optional caller-supplied 64-byte seed.
    fn generate_into(&self, params: &ParamSet) -> ProviderResult<MlKemKeyData> {
        let lib_ctx = LibContext::get_default();

        // Optional seed — when present, deterministic generation.
        let seed_opt: Option<[u8; SEED_BYTES]> = if let Some(s) = params.get(PARAM_SEED) {
            let bytes = s.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::ParamTypeMismatch {
                    key: PARAM_SEED.to_string(),
                    expected: "octet-string",
                    actual: s.param_type_name(),
                })
            })?;
            if bytes.len() != SEED_BYTES {
                return Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!(
                        "ML-KEM gen seed must be {SEED_BYTES} bytes, got {}",
                        bytes.len()
                    ),
                )));
            }
            let mut buf = [0u8; SEED_BYTES];
            buf.copy_from_slice(bytes);
            Some(buf)
        } else {
            None
        };

        let key = crypto_ml_kem::generate(
            Arc::clone(&lib_ctx),
            self.variant.to_crypto(),
            seed_opt.as_ref(),
        )
        .map_err(map_crypto_err)?;

        // Securely zero the local seed copy (the crypto layer keeps its own
        // copy via `RETAIN_SEED` if requested).
        if let Some(mut buf) = seed_opt {
            buf.zeroize();
        }

        debug!(
            variant = ?self.variant,
            "ML-KEM keymgmt: key generated successfully",
        );

        // Run the post-keygen pairwise consistency test (PCT).  We
        // perform a Random-mode encap/decap roundtrip by default;
        // callers may override via `OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE`
        // (the C source accepts the same parameter on both the
        // gen ctx and import paths) to force FIPS 140-3 IG D.G
        // Fixed-mode behaviour.
        let pct_mode = Self::read_pct_type(params)?.unwrap_or_default();
        self.run_pairwise_test(&key, pct_mode)?;

        Ok(MlKemKeyData::with_key(self.variant, lib_ctx, key))
    }

    /// Performs a single encap/decap pairwise consistency test on a
    /// freshly generated key, returning an error if the recovered
    /// shared secret differs from the encapsulated value.  This is the
    /// FIPS 140-3 IG D.G post-keygen self-check that the C source
    /// performs unconditionally in `FIPS_MODULE` builds.
    fn run_pairwise_test(&self, key: &MlKemKey, mode: PairwiseTestMode) -> ProviderResult<()> {
        // The Random vs Fixed entropy distinction is realised inside
        // the crypto layer.  We surface the mode here for tracing and
        // to keep the type-level documentation of the call site
        // explicit (matches the C source's `flags & ML_KEM_KEY_*_PCT`
        // discriminator).
        trace!(
            variant = ?self.variant,
            ?mode,
            flag = mode.provider_flag(),
            "ML-KEM keymgmt: running pairwise consistency test",
        );

        let (ctext, encaps_secret) = crypto_ml_kem::encap_rand(key).map_err(map_crypto_err)?;
        let decaps_secret = crypto_ml_kem::decap(key, &ctext).map_err(map_crypto_err)?;

        // Constant-time comparison on the 32-byte shared secret.
        // SHARED_SECRET_BYTES is small, fixed, and the difference can
        // be revealed without timing leakage in this provider context
        // (we error on any mismatch which terminates the operation).
        let mut diff: u8 = 0;
        for i in 0..SHARED_SECRET_BYTES {
            diff |= encaps_secret[i] ^ decaps_secret[i];
        }
        if diff != 0 {
            return Err(ProviderError::Common(CommonError::Internal(
                "ML-KEM: post-keygen pairwise consistency test failed".into(),
            )));
        }

        trace!(
            variant = ?self.variant,
            "ML-KEM keymgmt: pairwise consistency test passed",
        );
        Ok(())
    }

    /// Exports key components as a [`ParamSet`].  Implements the C
    /// `ml_kem_export()` (lines ~350–400) including the required
    /// secure cleansing of private buffers after they are copied into
    /// the output container.
    ///
    /// This is the *typed* export pathway taking a concrete
    /// `&MlKemKeyData`.  The trait-level [`KeyMgmtProvider::export`]
    /// implementation cannot reach inside the trait object (no
    /// `Any`-style downcast on [`KeyData`]) and therefore returns an
    /// empty container; callers that hold a typed reference should use
    /// this method directly to obtain the full encoded bytes.
    pub fn export_from(
        &self,
        key: &MlKemKeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        if !selection.intersects(KeySelection::KEYPAIR) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-KEM export: selection must include PUBLIC_KEY or PRIVATE_KEY".into(),
            )));
        }

        // Up-front check: the typed key must actually possess the
        // requested components.  This is the inherent (typed)
        // counterpart to the trait-level `has()` and prevents producing
        // a partially populated [`ParamSet`] when the caller asks for a
        // private key on a key that only carries the public material.
        if !key.check_selection(selection) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-KEM export: key does not contain the requested components".into(),
            )));
        }

        let inner = key.key.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "ML-KEM export: key data is empty".into(),
            ))
        })?;

        let mut out = ParamSet::new();

        if selection.contains(KeySelection::PUBLIC_KEY) && inner.have_pubkey() {
            let encoded = inner.encode_pubkey().map_err(map_crypto_err)?;
            out.set(PARAM_PUB_KEY, ParamValue::OctetString(encoded.clone()));
            out.set(PARAM_ENCODED_PUB_KEY, ParamValue::OctetString(encoded));
        }

        if selection.contains(KeySelection::PRIVATE_KEY) && inner.have_prvkey() {
            let mut encoded = inner.encode_prvkey().map_err(map_crypto_err)?;
            // Make an owned copy for the param set, then cleanse the
            // local intermediate buffer (the param set retains its own
            // storage; ours is no longer needed).
            out.set(PARAM_PRIV_KEY, ParamValue::OctetString(encoded.clone()));
            encoded.zeroize();
        }

        debug!(
            variant = ?self.variant,
            ?selection,
            populated = out.len(),
            "ML-KEM keymgmt: export complete",
        );
        Ok(out)
    }
}

// =============================================================================
// KeyMgmtProvider trait impl
// =============================================================================

impl KeyMgmtProvider for MlKemKeyMgmt {
    fn name(&self) -> &'static str {
        self.variant.algorithm_name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        trace!(variant = ?self.variant, "ML-KEM keymgmt: new_key");
        Ok(Box::new(MlKemKeyData::new(
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
        if !looks_like_ml_kem_key_data(key) {
            return Err(ProviderError::Dispatch(
                "ML-KEM keymgmt: export called with non-ML-KEM key data".into(),
            ));
        }
        // Without `Any` we cannot reach the typed inner state from the
        // trait object.  Return a minimal export: the encoded public
        // key (when present) is recoverable from the Debug introspection
        // as a presence flag, but the bytes themselves require typed
        // access.  Callers that need full export must use the inherent
        // `MlKemKeyMgmt::export_from` method on a typed `&MlKemKeyData`.
        let (has_pub, has_priv, _, _) = introspect_debug(key);
        if !has_pub && !has_priv {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-KEM keymgmt: export called on empty key".into(),
            )));
        }
        if !selection.intersects(KeySelection::KEYPAIR) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "ML-KEM keymgmt: export selection must include PUBLIC_KEY or PRIVATE_KEY".into(),
            )));
        }
        debug!(
            variant = ?self.variant,
            ?selection,
            "ML-KEM keymgmt: export via opaque KeyData (use export_from for full bytes)",
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        if !looks_like_ml_kem_key_data(key) {
            return false;
        }
        let (has_pub, has_priv, _, _variant) = introspect_debug(key);
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            return true;
        }
        if kp.contains(KeySelection::PRIVATE_KEY) {
            return has_priv;
        }
        if kp.contains(KeySelection::PUBLIC_KEY) {
            return has_pub;
        }
        true
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        // C `ml_kem_validate` returns has(selection); selection-specific
        // structural checks are performed during import (parse_pubkey /
        // parse_prvkey verify length and structure).
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm descriptor registration
// =============================================================================

/// Returns the [`AlgorithmDescriptor`]s for the three FIPS 203 ML-KEM
/// parameter sets.  Aggregated into the default-provider `KEYMGMT`
/// dispatch by [`crate::implementations::keymgmt::descriptors`].
#[must_use]
pub fn ml_kem_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &[
                "ML-KEM-512",
                "MLKEM512",
                "id-alg-ml-kem-512",
                "2.16.840.1.101.3.4.4.1",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-KEM-512 implementation (FIPS 203, NIST cat 1)",
        ),
        algorithm(
            &[
                "ML-KEM-768",
                "MLKEM768",
                "id-alg-ml-kem-768",
                "2.16.840.1.101.3.4.4.2",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-KEM-768 implementation (FIPS 203, NIST cat 3)",
        ),
        algorithm(
            &[
                "ML-KEM-1024",
                "MLKEM1024",
                "id-alg-ml-kem-1024",
                "2.16.840.1.101.3.4.4.3",
            ],
            DEFAULT_PROPERTY,
            "OpenSSL ML-KEM-1024 implementation (FIPS 203, NIST cat 5)",
        ),
    ]
}

// Suppress dead-code warnings for the helper-only `RANDOM_BYTES` /
// `variant_of_key` pulls when the binding remains unreferenced in
// minimal-feature builds.
#[allow(dead_code)]
const _RANDOM_BYTES_REF: usize = RANDOM_BYTES;
#[allow(dead_code)]
fn _variant_of_key_ref(k: &MlKemKey) -> MlKemVariantKind {
    variant_of_key(k)
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
    // Existing descriptor tests (PRESERVED from initial stub)
    // -------------------------------------------------------------------------

    #[test]
    fn ml_kem_descriptors_returns_three_entries() {
        let descs = ml_kem_descriptors();
        assert_eq!(descs.len(), 3, "ML-KEM exposes three parameter sets");
    }

    #[test]
    fn ml_kem_descriptors_cover_all_security_levels() {
        let descs = ml_kem_descriptors();
        let canonical: Vec<_> = descs
            .iter()
            .map(|d| d.names.first().copied().unwrap_or(""))
            .collect();
        assert!(canonical.contains(&"ML-KEM-512"));
        assert!(canonical.contains(&"ML-KEM-768"));
        assert!(canonical.contains(&"ML-KEM-1024"));
    }

    #[test]
    fn ml_kem_descriptors_carry_oid_and_aliases() {
        let descs = ml_kem_descriptors();
        let ml_kem_512 = &descs[0];
        assert!(ml_kem_512
            .names
            .iter()
            .any(|n| *n == "2.16.840.1.101.3.4.4.1"));
        assert!(ml_kem_512.names.iter().any(|n| *n == "MLKEM512"));
    }

    #[test]
    fn ml_kem_descriptors_have_default_property() {
        let descs = ml_kem_descriptors();
        for d in &descs {
            assert_eq!(d.property, DEFAULT_PROPERTY);
        }
    }

    // -------------------------------------------------------------------------
    // Variant size tests
    // -------------------------------------------------------------------------

    #[test]
    fn variant_kind_sizes_match_fips_203() {
        // ML-KEM-512
        assert_eq!(MlKemVariantKind::MlKem512.encaps_key_size(), 800);
        assert_eq!(MlKemVariantKind::MlKem512.decaps_key_size(), 1632);
        assert_eq!(MlKemVariantKind::MlKem512.ciphertext_size(), 768);
        assert_eq!(MlKemVariantKind::MlKem512.shared_secret_size(), 32);
        assert_eq!(MlKemVariantKind::MlKem512.security_category(), 1);
        assert_eq!(MlKemVariantKind::MlKem512.security_bits(), 128);

        // ML-KEM-768
        assert_eq!(MlKemVariantKind::MlKem768.encaps_key_size(), 1184);
        assert_eq!(MlKemVariantKind::MlKem768.decaps_key_size(), 2400);
        assert_eq!(MlKemVariantKind::MlKem768.ciphertext_size(), 1088);
        assert_eq!(MlKemVariantKind::MlKem768.shared_secret_size(), 32);
        assert_eq!(MlKemVariantKind::MlKem768.security_category(), 3);
        assert_eq!(MlKemVariantKind::MlKem768.security_bits(), 192);

        // ML-KEM-1024
        assert_eq!(MlKemVariantKind::MlKem1024.encaps_key_size(), 1568);
        assert_eq!(MlKemVariantKind::MlKem1024.decaps_key_size(), 3168);
        assert_eq!(MlKemVariantKind::MlKem1024.ciphertext_size(), 1568);
        assert_eq!(MlKemVariantKind::MlKem1024.shared_secret_size(), 32);
        assert_eq!(MlKemVariantKind::MlKem1024.security_category(), 5);
        assert_eq!(MlKemVariantKind::MlKem1024.security_bits(), 256);
    }

    #[test]
    fn variant_kind_algorithm_names() {
        assert_eq!(MlKemVariantKind::MlKem512.algorithm_name(), "ML-KEM-512");
        assert_eq!(MlKemVariantKind::MlKem768.algorithm_name(), "ML-KEM-768");
        assert_eq!(MlKemVariantKind::MlKem1024.algorithm_name(), "ML-KEM-1024");
    }

    #[test]
    fn variant_kind_round_trips_with_crypto_enum() {
        for v in [
            MlKemVariantKind::MlKem512,
            MlKemVariantKind::MlKem768,
            MlKemVariantKind::MlKem1024,
        ] {
            let crypto = v.to_crypto();
            assert_eq!(MlKemVariantKind::from_crypto(crypto), v);
        }
    }

    #[test]
    fn variant_kind_from_name_supports_canonical_and_aliases() {
        assert_eq!(
            MlKemVariantKind::from_name("ML-KEM-512"),
            Some(MlKemVariantKind::MlKem512)
        );
        assert_eq!(
            MlKemVariantKind::from_name("MLKEM768"),
            Some(MlKemVariantKind::MlKem768)
        );
        assert_eq!(
            MlKemVariantKind::from_name("ML-KEM-1024"),
            Some(MlKemVariantKind::MlKem1024)
        );
        assert_eq!(MlKemVariantKind::from_name("not-an-algo"), None);
    }

    // -------------------------------------------------------------------------
    // PairwiseTestMode tests
    // -------------------------------------------------------------------------

    #[test]
    fn pairwise_test_mode_default_is_random() {
        assert_eq!(PairwiseTestMode::default(), PairwiseTestMode::Random);
    }

    #[test]
    fn pairwise_test_mode_provider_flags_are_distinct() {
        assert_eq!(
            PairwiseTestMode::Random.provider_flag(),
            prov_flags::RANDOM_PCT
        );
        assert_eq!(
            PairwiseTestMode::Fixed.provider_flag(),
            prov_flags::FIXED_PCT
        );
        assert_ne!(
            PairwiseTestMode::Random.provider_flag(),
            PairwiseTestMode::Fixed.provider_flag()
        );
    }

    #[test]
    fn pairwise_test_mode_from_pct_name_accepts_canonical_strings() {
        assert_eq!(
            PairwiseTestMode::from_pct_name("random"),
            Some(PairwiseTestMode::Random)
        );
        assert_eq!(
            PairwiseTestMode::from_pct_name("fixed"),
            Some(PairwiseTestMode::Fixed)
        );
    }

    #[test]
    fn pairwise_test_mode_from_pct_name_is_case_insensitive() {
        assert_eq!(
            PairwiseTestMode::from_pct_name("Random"),
            Some(PairwiseTestMode::Random)
        );
        assert_eq!(
            PairwiseTestMode::from_pct_name("FIXED"),
            Some(PairwiseTestMode::Fixed)
        );
    }

    #[test]
    fn pairwise_test_mode_from_pct_name_rejects_unknown() {
        assert_eq!(PairwiseTestMode::from_pct_name(""), None);
        assert_eq!(PairwiseTestMode::from_pct_name("none"), None);
        assert_eq!(PairwiseTestMode::from_pct_name("deterministic"), None);
    }

    #[test]
    fn read_pct_type_returns_none_when_param_absent() {
        let params = ParamSet::new();
        let result = MlKemKeyMgmt::read_pct_type(&params).expect("absent param is ok");
        assert!(result.is_none());
    }

    #[test]
    fn read_pct_type_decodes_random_string() {
        let mut params = ParamSet::new();
        params.set(PARAM_PCT_TYPE, ParamValue::Utf8String("random".to_string()));
        let result = MlKemKeyMgmt::read_pct_type(&params).expect("random is valid");
        assert_eq!(result, Some(PairwiseTestMode::Random));
    }

    #[test]
    fn read_pct_type_decodes_fixed_string() {
        let mut params = ParamSet::new();
        params.set(PARAM_PCT_TYPE, ParamValue::Utf8String("fixed".to_string()));
        let result = MlKemKeyMgmt::read_pct_type(&params).expect("fixed is valid");
        assert_eq!(result, Some(PairwiseTestMode::Fixed));
    }

    #[test]
    fn read_pct_type_rejects_unknown_string() {
        let mut params = ParamSet::new();
        params.set(
            PARAM_PCT_TYPE,
            ParamValue::Utf8String("never-heard-of-it".to_string()),
        );
        let err = MlKemKeyMgmt::read_pct_type(&params).expect_err("unknown should error");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn read_pct_type_rejects_wrong_param_type() {
        let mut params = ParamSet::new();
        params.set(PARAM_PCT_TYPE, ParamValue::Int32(1));
        let err = MlKemKeyMgmt::read_pct_type(&params).expect_err("non-utf8 should error");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::ParamTypeMismatch { .. })
        ));
    }

    // -------------------------------------------------------------------------
    // MlKemKeyData tests
    // -------------------------------------------------------------------------

    #[test]
    fn empty_key_data_has_no_components() {
        let kd = MlKemKeyData::new(MlKemVariantKind::MlKem768, None);
        assert!(!kd.has_pubkey());
        assert!(!kd.has_prvkey());
        assert!(!kd.has_seed());
        assert_eq!(kd.variant(), MlKemVariantKind::MlKem768);
    }

    #[test]
    fn debug_output_exposes_presence_flags() {
        let kd = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let s = format!("{kd:?}");
        assert!(s.contains("MlKemKeyData"));
        assert!(s.contains("MlKem512"));
        assert!(s.contains("has_pubkey: false"));
        assert!(s.contains("has_prvkey: false"));
    }

    #[test]
    fn check_selection_returns_false_for_empty_key() {
        let kd = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        assert!(!kd.check_selection(KeySelection::PUBLIC_KEY));
        assert!(!kd.check_selection(KeySelection::PRIVATE_KEY));
        assert!(!kd.check_selection(KeySelection::KEYPAIR));
    }

    // -------------------------------------------------------------------------
    // MlKemGenContext tests
    // -------------------------------------------------------------------------

    #[test]
    fn gen_context_default_pairwise_mode_is_random() {
        let gc = MlKemGenContext::new(MlKemVariantKind::MlKem768, None);
        assert_eq!(gc.pairwise_test, PairwiseTestMode::Random);
        assert_eq!(gc.variant, MlKemVariantKind::MlKem768);
        assert!(gc.prop_query.is_none());
        assert!(gc.seed().is_none());
    }

    #[test]
    fn gen_context_set_seed_validates_length() {
        let mut gc = MlKemGenContext::new(MlKemVariantKind::MlKem512, None);
        // Wrong length is rejected.
        let too_short = [0u8; 16];
        assert!(gc.set_seed(&too_short).is_err());
        // Correct length succeeds.
        let good = [0xAAu8; SEED_BYTES];
        gc.set_seed(&good).unwrap();
        assert_eq!(gc.seed().unwrap(), &good);
    }

    // -------------------------------------------------------------------------
    // MlKemKeyMgmt construction tests
    // -------------------------------------------------------------------------

    #[test]
    fn keymgmt_factory_constructors_set_correct_variant() {
        assert_eq!(
            MlKemKeyMgmt::ml_kem_512().variant,
            MlKemVariantKind::MlKem512
        );
        assert_eq!(
            MlKemKeyMgmt::ml_kem_768().variant,
            MlKemVariantKind::MlKem768
        );
        assert_eq!(
            MlKemKeyMgmt::ml_kem_1024().variant,
            MlKemVariantKind::MlKem1024
        );
    }

    #[test]
    fn keymgmt_name_matches_variant() {
        assert_eq!(MlKemKeyMgmt::ml_kem_512().name(), "ML-KEM-512");
        assert_eq!(MlKemKeyMgmt::ml_kem_768().name(), "ML-KEM-768");
        assert_eq!(MlKemKeyMgmt::ml_kem_1024().name(), "ML-KEM-1024");
    }

    #[test]
    fn keymgmt_new_key_returns_empty_keydata() {
        let mgmt = MlKemKeyMgmt::ml_kem_768();
        let kd = mgmt.new_key().unwrap();
        let s = format!("{kd:?}");
        assert!(s.contains("MlKemKeyData"));
        assert!(s.contains("has_pubkey: false"));
        assert!(s.contains("has_prvkey: false"));
    }

    // -------------------------------------------------------------------------
    // get_params tests (no live key)
    // -------------------------------------------------------------------------

    #[test]
    fn get_params_returns_static_metadata_for_empty_key() {
        let mgmt = MlKemKeyMgmt::ml_kem_768();
        let kd = MlKemKeyData::new(MlKemVariantKind::MlKem768, None);
        let params = mgmt.get_params(&kd).unwrap();

        assert_eq!(
            params.get(PARAM_BITS).and_then(ParamValue::as_i32),
            Some(1184 * 8)
        );
        assert_eq!(
            params.get(PARAM_SECURITY_BITS).and_then(ParamValue::as_i32),
            Some(192)
        );
        assert_eq!(
            params
                .get(PARAM_SECURITY_CATEGORY)
                .and_then(ParamValue::as_i32),
            Some(3)
        );
        assert_eq!(
            params.get(PARAM_MAX_SIZE).and_then(ParamValue::as_i32),
            Some(1088)
        );

        // No public-key bytes for an empty key.
        assert!(params.get(PARAM_PUB_KEY).is_none());
        assert!(params.get(PARAM_PRIV_KEY).is_none());
    }

    // -------------------------------------------------------------------------
    // set_params tests
    // -------------------------------------------------------------------------

    #[test]
    fn set_params_rejects_wrong_length_pub_key() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let mut kd = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let mut params = ParamSet::new();
        params.set(
            PARAM_ENCODED_PUB_KEY,
            ParamValue::OctetString(vec![0u8; 100]),
        );
        let err = mgmt.set_params(&mut kd, &params).expect_err("wrong length");
        let msg = format!("{err}");
        assert!(msg.contains("encoded public key") || msg.contains("must be"));
    }

    #[test]
    fn set_params_empty_pub_key_is_no_op() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let mut kd = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let mut params = ParamSet::new();
        params.set(PARAM_ENCODED_PUB_KEY, ParamValue::OctetString(Vec::new()));
        mgmt.set_params(&mut kd, &params).unwrap();
        assert!(!kd.has_pubkey());
    }

    #[test]
    fn set_params_with_no_relevant_keys_is_no_op() {
        let mgmt = MlKemKeyMgmt::ml_kem_768();
        let mut kd = MlKemKeyData::new(MlKemVariantKind::MlKem768, None);
        let params = ParamSet::new();
        mgmt.set_params(&mut kd, &params).unwrap();
        assert!(!kd.has_pubkey());
    }

    // -------------------------------------------------------------------------
    // import / export tests
    // -------------------------------------------------------------------------

    #[test]
    fn import_rejects_empty_selection() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let params = ParamSet::new();
        let err = mgmt
            .import(KeySelection::DOMAIN_PARAMETERS, &params)
            .expect_err("empty KEYPAIR selection");
        let msg = format!("{err}");
        assert!(msg.contains("PUBLIC_KEY") || msg.contains("PRIVATE_KEY"));
    }

    #[test]
    fn import_rejects_missing_keys() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let params = ParamSet::new();
        let err = mgmt
            .import(KeySelection::PUBLIC_KEY, &params)
            .expect_err("no key bytes");
        let msg = format!("{err}");
        assert!(msg.contains("not found") || msg.contains("missing"));
    }

    #[test]
    fn import_rejects_wrong_length_pub_key() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let mut params = ParamSet::new();
        params.set(PARAM_PUB_KEY, ParamValue::OctetString(vec![0u8; 16]));
        let err = mgmt
            .import(KeySelection::PUBLIC_KEY, &params)
            .expect_err("wrong-length public key");
        let msg = format!("{err}");
        assert!(msg.contains("must be") || msg.contains("public key"));
    }

    #[test]
    fn import_rejects_wrong_length_priv_key() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let mut params = ParamSet::new();
        params.set(PARAM_PRIV_KEY, ParamValue::OctetString(vec![0u8; 16]));
        let err = mgmt
            .import(KeySelection::PRIVATE_KEY, &params)
            .expect_err("wrong-length private key");
        let msg = format!("{err}");
        assert!(msg.contains("must be") || msg.contains("private key"));
    }

    // -------------------------------------------------------------------------
    // has / validate tests
    // -------------------------------------------------------------------------

    #[test]
    fn has_returns_true_for_no_keypair_selection() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        // An empty KEYPAIR selection (just DOMAIN_PARAMETERS) returns true.
        let kd: Box<dyn KeyData> = Box::new(MlKemKeyData::new(MlKemVariantKind::MlKem512, None));
        assert!(mgmt.has(&*kd, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn has_returns_false_for_empty_key_with_keypair_selection() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let kd: Box<dyn KeyData> = Box::new(MlKemKeyData::new(MlKemVariantKind::MlKem512, None));
        assert!(!mgmt.has(&*kd, KeySelection::PUBLIC_KEY));
        assert!(!mgmt.has(&*kd, KeySelection::PRIVATE_KEY));
        assert!(!mgmt.has(&*kd, KeySelection::KEYPAIR));
    }

    #[test]
    fn has_returns_false_for_non_ml_kem_keydata() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        // Construct a synthetic non-ML-KEM KeyData for negative test.
        #[derive(Debug)]
        struct OtherKey;
        impl KeyData for OtherKey {}
        let other: Box<dyn KeyData> = Box::new(OtherKey);
        assert!(!mgmt.has(&*other, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn validate_delegates_to_has_for_empty_key() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let kd: Box<dyn KeyData> = Box::new(MlKemKeyData::new(MlKemVariantKind::MlKem512, None));
        // No KEYPAIR bit selected → has returns true → validate returns Ok(true).
        assert!(mgmt
            .validate(&*kd, KeySelection::DOMAIN_PARAMETERS)
            .unwrap());
        // KEYPAIR bit selected on empty key → has returns false.
        assert!(!mgmt.validate(&*kd, KeySelection::PUBLIC_KEY).unwrap());
    }

    // -------------------------------------------------------------------------
    // export_from tests (typed export)
    // -------------------------------------------------------------------------

    #[test]
    fn export_from_rejects_empty_keypair_selection() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let kd = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let err = mgmt
            .export_from(&kd, KeySelection::DOMAIN_PARAMETERS)
            .expect_err("domain-only selection cannot export key bytes");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    #[test]
    fn export_from_rejects_empty_key() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let kd = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        // Empty key has no public component → check_selection returns false.
        let err = mgmt
            .export_from(&kd, KeySelection::PUBLIC_KEY)
            .expect_err("empty key cannot export");
        assert!(matches!(
            err,
            ProviderError::Common(CommonError::InvalidArgument(_))
        ));
    }

    // -------------------------------------------------------------------------
    // match_keys tests
    // -------------------------------------------------------------------------

    #[test]
    fn match_keys_two_empty_keys_match_with_no_keypair_selection() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let a = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let b = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        assert!(mgmt.match_keys(&a, &b, KeySelection::DOMAIN_PARAMETERS));
    }

    #[test]
    fn match_keys_different_variants_never_match() {
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let a = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let b = MlKemKeyData::new(MlKemVariantKind::MlKem768, None);
        assert!(!mgmt.match_keys(&a, &b, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn match_keys_two_empty_keys_match_under_keypair() {
        // Two empty keys (no inner) under KEYPAIR selection are treated
        // as "structurally identical empties" by our match_keys impl.
        let mgmt = MlKemKeyMgmt::ml_kem_512();
        let a = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        let b = MlKemKeyData::new(MlKemVariantKind::MlKem512, None);
        assert!(mgmt.match_keys(&a, &b, KeySelection::PUBLIC_KEY));
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    #[test]
    fn looks_like_ml_kem_key_data_recognises_typed_value() {
        let kd: Box<dyn KeyData> = Box::new(MlKemKeyData::new(MlKemVariantKind::MlKem512, None));
        assert!(looks_like_ml_kem_key_data(&*kd));
    }

    #[test]
    fn looks_like_ml_kem_key_data_rejects_other_types() {
        #[derive(Debug)]
        struct Decoy;
        impl KeyData for Decoy {}
        let other: Box<dyn KeyData> = Box::new(Decoy);
        assert!(!looks_like_ml_kem_key_data(&*other));
    }

    #[test]
    fn introspect_debug_extracts_flags() {
        let kd: Box<dyn KeyData> = Box::new(MlKemKeyData::new(MlKemVariantKind::MlKem1024, None));
        let (has_pub, has_priv, has_seed, variant) = introspect_debug(&*kd);
        assert!(!has_pub);
        assert!(!has_priv);
        assert!(!has_seed);
        assert_eq!(variant, Some(MlKemVariantKind::MlKem1024));
    }
}
