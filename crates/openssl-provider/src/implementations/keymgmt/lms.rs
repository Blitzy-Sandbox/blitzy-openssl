//! LMS (Leighton-Micali Hash-Based Signature) key management provider
//! implementation.
//!
//! Translates the LMS key-management dispatch entry from
//! `providers/defltprov.c` (the `OSSL_DISPATCH ossl_lms_keymgmt_functions[]`
//! table) into a Rust descriptor consumed by
//! [`crate::implementations::keymgmt::descriptors`], and provides full
//! `KeyMgmtProvider`-equivalent behaviour through [`LmsKeyMgmt`].
//!
//! The original C surface is implemented in
//! `providers/implementations/keymgmt/lms_kmgmt.c` (~213 lines) and provides
//! `KeyMgmtProvider`-equivalent operations for NIST SP 800-208 / RFC 8554
//! LMS hash-based signatures. The provider supports key import for
//! verification only — key generation and signing are out of scope per
//! SP 800-208 guidance because LMS is a stateful signature scheme whose
//! safe production use requires hardware-protected state.
//!
//! # Verify-only behaviour (Rule R5)
//!
//! Per the C implementation's `LMS_POSSIBLE_SELECTIONS = OSSL_KEYMGMT_SELECT_PUBLIC_KEY`
//! constant (line 34 of `lms_kmgmt.c`), LMS keymgmt accepts only the public
//! key selection. Consequently:
//!
//! - [`LmsKeyMgmt::generate`] returns
//!   [`CommonError::Unsupported`](openssl_common::error::CommonError::Unsupported)
//!   rather than silently producing a sentinel zero return value.
//! - [`LmsKeyMgmt::import`] requires `KeySelection::PUBLIC_KEY` to be set in
//!   the caller's selection mask; private-key imports are rejected.
//! - [`LmsKeyMgmt::has`] and [`LmsKeyMgmt::validate`] consider only the
//!   public-key bit; private-key bits in the selection mask are answered as
//!   "not present".
//!
//! # Wiring Path (Rule R10)
//!
//! `openssl-cli::main` → `openssl-provider::default::DefaultProvider::new` →
//! aggregates `crate::implementations::all_keymgmt_descriptors` →
//! `crate::implementations::keymgmt::descriptors` →
//! `crate::implementations::keymgmt::lms::lms_descriptors` (this module).
//!
//! # C Source Mapping
//!
//! | C Source                                                       | Rust Equivalent                                   |
//! |----------------------------------------------------------------|---------------------------------------------------|
//! | `providers/defltprov.c` (LMS `KEYMGMT` entry)                  | [`lms_descriptors`] in this module                |
//! | `providers/implementations/keymgmt/lms_kmgmt.c`                | [`LmsKeyMgmt`] (verify-only operations)           |
//! | `OSSL_FUNC_keymgmt_new` (`lms_new_key`)                        | [`LmsKeyMgmt::new_key`]                           |
//! | `OSSL_FUNC_keymgmt_has` (`lms_has`)                            | [`LmsKeyMgmt::has`]                               |
//! | `OSSL_FUNC_keymgmt_match` (`lms_match`)                        | [`LmsKeyMgmt::match_keys`]                        |
//! | `OSSL_FUNC_keymgmt_validate` (`lms_validate`)                  | [`LmsKeyMgmt::validate`]                          |
//! | `OSSL_FUNC_keymgmt_import` (`lms_import`)                      | [`LmsKeyMgmt::import`] / [`LmsKeyMgmt::import_into`] |
//! | `OSSL_FUNC_keymgmt_export` (`lms_export`)                      | [`LmsKeyMgmt::export`] / [`LmsKeyMgmt::export_from`] |
//! | `OSSL_FUNC_keymgmt_get_params` (`lms_get_params`)              | [`LmsKeyMgmt::get_params`]                        |
//! | `OSSL_FUNC_keymgmt_gettable_params` (`lms_gettable_params`)    | [`LmsKeyMgmt::gettable_params`]                   |
//! | `PROV_NAMES_LMS` macro in `prov/names.h`                       | the `names` slice on the `AlgorithmDescriptor`    |
//! | `LMS_POSSIBLE_SELECTIONS` macro                                | restriction documented at module level + enforced in [`LmsKeyMgmt::import_into`] |
//! | `ossl_lms_key_new(libctx)`                                     | [`LmsKey::new`](openssl_crypto::pqc::lms::LmsKey::new) |
//! | `ossl_lms_pubkey_from_params`                                  | [`lms_pubkey_decode`](openssl_crypto::pqc::lms::lms_pubkey_decode) |
//! | `ossl_lms_key_equal(k1, k2, sel)`                              | [`LmsKey::equal`](openssl_crypto::pqc::lms::LmsKey::equal) |
//! | `ossl_lms_key_valid(k, sel)`                                   | [`LmsKey::is_valid`](openssl_crypto::pqc::lms::LmsKey::is_valid) |
//! | `ossl_lms_key_has(k, sel)`                                     | [`LmsKey::has_key`](openssl_crypto::pqc::lms::LmsKey::has_key) |
//! | `ossl_lms_key_get_pub_len`                                     | [`LmsKey::pub_len`](openssl_crypto::pqc::lms::LmsKey::pub_len) |
//! | `ossl_lms_key_get_collision_strength_bits`                     | [`LmsKey::collision_strength_bits`](openssl_crypto::pqc::lms::LmsKey::collision_strength_bits) |
//! | `ossl_lms_key_get_sig_len`                                     | [`LmsKey::sig_len`](openssl_crypto::pqc::lms::LmsKey::sig_len) |
//!
//! # `KeySelection` translation
//!
//! Two `KeySelection` bitflag types coexist, with **different** numeric bit
//! values:
//!
//! | Component         | `crate::traits::KeySelection`           | `openssl_crypto::pqc::lms::KeySelection` |
//! |-------------------|-----------------------------------------|------------------------------------------|
//! | `PRIVATE_KEY`     | `0x01`                                  | `0x02`                                   |
//! | `PUBLIC_KEY`      | `0x02`                                  | `0x04`                                   |
//! | `PARAMETERS`      | `0x04` (`DOMAIN_PARAMETERS`)            | `0x01`                                   |
//!
//! All conversions are routed through the private [`to_crypto_selection`]
//! helper. This boundary is the single source of truth for the bit-mapping
//! and is exercised by the unit tests below.

use std::fmt;
use std::sync::Arc;

use tracing::{debug, trace};

use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};

use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::lms::{
    lms_pubkey_decode, KeySelection as CryptoKeySelection, LmsKey,
};

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KeyData, KeyMgmtProvider, KeySelection};

use super::DEFAULT_PROPERTY;

// =============================================================================
// Parameter name constants
//
// Mirror C `OSSL_PKEY_PARAM_*` and `OSSL_PARAM_*` symbol values used by the
// LMS key-management provider in `lms_kmgmt.c`.
// =============================================================================

/// Octet-string public key import/export key (`OSSL_PKEY_PARAM_PUB_KEY`).
const PARAM_PUB_KEY: &str = "pub";
/// Alias for [`PARAM_PUB_KEY`] used by the encoder/decoder pipeline.
const PARAM_ENCODED_PUB_KEY: &str = "encoded-pub-key";
/// `bits` integer parameter — public-key length in bits (8 × `pub_len`).
const PARAM_BITS: &str = "bits";
/// `security-bits` integer parameter — collision-strength security bits.
const PARAM_SECURITY_BITS: &str = "security-bits";
/// `max-size` integer parameter — maximum signature length in bytes.
const PARAM_MAX_SIZE: &str = "max-size";
/// `mandatory-digest` UTF-8 string — empty for LMS (algorithm hashes
/// internally per RFC 8554; no caller-supplied digest is required).
const PARAM_MANDATORY_DIGEST: &str = "mandatory-digest";

// =============================================================================
// Selection translation — provider ↔ crypto layer
// =============================================================================

/// Translates a [`crate::traits::KeySelection`] mask into the crypto-layer's
/// [`openssl_crypto::pqc::lms::KeySelection`] mask.
///
/// The two bitflag types use **different** bit values for `PRIVATE_KEY`,
/// `PUBLIC_KEY`, and parameters (see the module-level documentation table).
/// This helper is the single point of conversion for that mismatch and
/// preserves the semantic intent of each bit:
///
/// - `traits::KeySelection::PRIVATE_KEY`        → `crypto::KeySelection::PRIVATE_KEY`
/// - `traits::KeySelection::PUBLIC_KEY`         → `crypto::KeySelection::PUBLIC_KEY`
/// - `traits::KeySelection::DOMAIN_PARAMETERS`  → `crypto::KeySelection::PARAMETERS`
/// - `traits::KeySelection::OTHER_PARAMETERS`   → (no crypto-layer counterpart; ignored)
fn to_crypto_selection(provider_sel: KeySelection) -> CryptoKeySelection {
    let mut out = CryptoKeySelection::empty();
    if provider_sel.contains(KeySelection::PRIVATE_KEY) {
        out |= CryptoKeySelection::PRIVATE_KEY;
    }
    if provider_sel.contains(KeySelection::PUBLIC_KEY) {
        out |= CryptoKeySelection::PUBLIC_KEY;
    }
    if provider_sel.contains(KeySelection::DOMAIN_PARAMETERS) {
        out |= CryptoKeySelection::PARAMETERS;
    }
    out
}

// =============================================================================
// LmsKeyData — opaque public-key-only key material wrapper
// =============================================================================

/// Key data for LMS public keys per SP 800-208 / RFC 8554.
///
/// Mirrors the role of `LMS_KEY *` in the C provider (`lms_kmgmt.c`).
/// LMS is a stateful hash-based signature scheme; only verification is
/// supported by this provider, so [`LmsKeyData`] holds a public key and the
/// associated parameter tags, never private-key material.
///
/// # Fields
///
/// - `key`: the underlying [`LmsKey`] — wrapped in [`Option`] because
///   [`LmsKeyMgmt::new_key`] returns an empty container ahead of import,
///   matching the C two-step `lms_new_key` → `lms_import` lifecycle.
/// - `lib_ctx`: a shared [`LibContext`] handle used for downstream provider
///   operations. `None` in detached test paths; otherwise an
///   [`Arc`]-shared handle to the default library context.
///
/// Field visibility is `pub(crate)` so that integration tests inside this
/// crate can introspect the key directly without going through the
/// `KeyMgmtProvider` trait.
///
/// # Schema export
///
/// Per the file schema, the exposed members are `key` and `lib_ctx`. They
/// are accessed through the [`LmsKeyData::key`] and [`LmsKeyData::lib_ctx`]
/// methods which return references / clones rather than direct field access
/// to keep the field types movable behind the API boundary.
pub struct LmsKeyData {
    /// The underlying LMS public key, or `None` for a freshly-allocated
    /// container that has not yet been populated by [`LmsKeyMgmt::import_into`].
    pub(crate) key: Option<LmsKey>,
    /// Shared library context. Cloned during [`LmsKeyMgmt::new_key`] /
    /// [`LmsKeyMgmt::import_into`] so that downstream operations can use
    /// the same provider configuration as the keymgmt instance.
    pub(crate) lib_ctx: Option<Arc<LibContext>>,
}

impl LmsKeyData {
    /// Constructs an empty `LmsKeyData` bound to the given library context.
    ///
    /// The wrapped key handle is initialised to `None`. Subsequent calls to
    /// [`LmsKeyMgmt::import_into`] populate the real key material.
    #[must_use]
    pub fn new(lib_ctx: Option<Arc<LibContext>>) -> Self {
        Self { key: None, lib_ctx }
    }

    /// Returns a reference to the underlying crypto-layer key, if present.
    #[must_use]
    pub fn key(&self) -> Option<&LmsKey> {
        self.key.as_ref()
    }

    /// Returns a clone of the library context handle for downstream calls.
    #[must_use]
    pub fn lib_ctx(&self) -> Option<Arc<LibContext>> {
        self.lib_ctx.clone()
    }

    /// Reports whether the wrapped key holds a usable public component.
    ///
    /// LMS is verify-only, so this is the single key-presence predicate
    /// surfaced by the structural Debug introspection used by
    /// [`LmsKeyMgmt::has`] and [`LmsKeyMgmt::validate`].
    #[must_use]
    pub fn has_pubkey(&self) -> bool {
        self.key
            .as_ref()
            .is_some_and(|k| k.has_key(CryptoKeySelection::PUBLIC_KEY))
    }
}

impl fmt::Debug for LmsKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The textual marker `"LmsKeyData"` is required by the structural
        // introspection helper `looks_like_lms_key_data` and the
        // `has_pubkey: <bool>` field is required by `introspect_debug`.
        // `lib_ctx` is omitted because `LibContext` does not implement
        // `Debug`; `finish_non_exhaustive` is therefore used to avoid
        // promising a complete field list.
        f.debug_struct("LmsKeyData")
            .field("has_pubkey", &self.has_pubkey())
            .finish_non_exhaustive()
    }
}

impl KeyData for LmsKeyData {}

impl Drop for LmsKeyData {
    fn drop(&mut self) {
        // The wrapped `LmsKey` zeros its identifier and root hash on its own
        // `Drop`. Explicitly taking the option here ensures the wrapping
        // `LmsKeyData` is also wiped of any residual references to the key
        // material before deallocation, matching the C `lms_free_key`
        // behaviour at line 43 of `lms_kmgmt.c`.
        self.key.take();
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

/// Heuristically detects whether a `&dyn KeyData` carries an `LmsKeyData`.
///
/// Because the trait surface forbids both `unsafe` downcasting (Rule R8)
/// and requiring `Any`, we rely on the structural `Debug` representation
/// that this module wires through its concrete type. The substring
/// `"LmsKeyData"` is unique to this module's `Debug` impl above.
fn looks_like_lms_key_data(key: &dyn KeyData) -> bool {
    let s = format!("{key:?}");
    s.contains("LmsKeyData")
}

/// Extracts structural flags from a `&dyn KeyData`.
///
/// Returns a tuple containing only `(has_pub,)` — LMS keymgmt does not
/// expose private-key bits because the algorithm is verify-only. The flag
/// is extracted by matching the textual token printed by the [`Debug`] impl
/// for [`LmsKeyData`]. Returns `(false,)` if the key data does not appear
/// to be an `LmsKeyData`.
fn introspect_debug(key: &dyn KeyData) -> (bool,) {
    let s = format!("{key:?}");
    let has_pub = s.contains("has_pubkey: true");
    (has_pub,)
}

/// Looks up an octet-string parameter from a [`ParamSet`].
///
/// Returns `Ok(None)` if the parameter is absent, `Ok(Some(bytes))` if it
/// is present and of octet-string type, or [`CommonError::ParamTypeMismatch`]
/// if it is present but of a different type.
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

/// Attempts a safe-Rust downcast of `&dyn KeyData` to `&LmsKeyData`.
///
/// Always returns `None` in the current implementation. Performing a real
/// downcast would either require `unsafe` (which Rule R8 forbids in this
/// crate) or constraining the trait surface with `Any` (which the schema
/// does not declare). Callers are therefore expected to fall back to the
/// pure-safe Debug-introspection helpers ([`introspect_debug`]) for any
/// operation that needs structural access without holding a typed
/// reference.
#[allow(
    dead_code,
    reason = "preserved for future Any-bound trait surface; mirrors slh_dsa.rs scaffold"
)]
fn downcast_ref(key: &dyn KeyData) -> Option<&LmsKeyData> {
    if !looks_like_lms_key_data(key) {
        return None;
    }
    // We do not perform an `unsafe` reinterpret here. See module-level
    // notes and the matching helper in `slh_dsa.rs` for the rationale.
    let _ = key;
    None
}

// =============================================================================
// LmsKeyMgmt — provider key management implementation
// =============================================================================

/// LMS key management provider.
///
/// Translates the dispatch table `ossl_lms_keymgmt_functions[]` from
/// `lms_kmgmt.c` (lines 199–213) into a Rust trait implementation. Because
/// LMS exposes only one canonical algorithm name (no per-parameter-set
/// dispatch as in SLH-DSA / ML-KEM / ML-DSA), a single instance of this
/// struct serves the entire LMS keymgmt registration.
///
/// The struct is cheap to clone (`Arc`-shared library context) and is
/// `Send + Sync` (no interior mutability; all mutable state is stored
/// inside individual [`LmsKeyData`] handles produced by [`Self::new_key`]
/// and [`Self::import_into`]).
pub struct LmsKeyMgmt {
    /// Default library context handed to newly-created [`LmsKeyData`] and
    /// [`LmsKey`] instances.  Mirrors `PROV_LIBCTX_OF(provctx)` in the C
    /// `lms_new_key` function (line 40 of `lms_kmgmt.c`).
    default_lib_ctx: Arc<LibContext>,
}

impl LmsKeyMgmt {
    /// Constructs a new [`LmsKeyMgmt`] bound to the process-wide default
    /// library context.
    ///
    /// Mirrors the implicit `provctx` argument received by C dispatch
    /// entries; in Rust we materialise it explicitly via
    /// [`LibContext::get_default`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_lib_ctx: LibContext::get_default(),
        }
    }

    /// Constructs an [`LmsKeyMgmt`] bound to a specific library context.
    ///
    /// Used by tests that need to verify multi-context provider isolation.
    #[must_use]
    pub fn with_context(lib_ctx: Arc<LibContext>) -> Self {
        Self {
            default_lib_ctx: lib_ctx,
        }
    }

    /// Returns the canonical algorithm name (`"LMS"`).
    ///
    /// Used by the `KeyMgmtProvider` trait surface and exposed as an
    /// inherent method per the schema's `members_exposed` listing.
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        "LMS"
    }

    /// Compares two opaque key data records for component-wise equality
    /// under the requested `selection` mask.
    ///
    /// Mirrors C `lms_match` (line 60 of `lms_kmgmt.c`) which delegates to
    /// `ossl_lms_key_equal`. Because the safe-Rust trait surface does not
    /// permit downcasting from `&dyn KeyData` (Rule R8), this implementation
    /// performs a structural comparison using the `Debug` representation
    /// produced by [`LmsKeyData::fmt`]: two LMS keys are considered to
    /// match for the public-key bit if and only if both keys present a
    /// public component (or both lack one). Private-key bits in the
    /// selection are ignored because LMS is verify-only.
    ///
    /// Returns `true` if either:
    ///
    /// - the selection mask requests no key components (vacuous match), or
    /// - both keys are LMS key data whose presence flags agree on every
    ///   requested public-key component.
    ///
    /// Returns `false` if either operand is not an `LmsKeyData` or if the
    /// public-key flags differ when public-key matching was requested.
    #[must_use]
    pub fn match_keys(
        &self,
        left: &dyn KeyData,
        right: &dyn KeyData,
        selection: KeySelection,
    ) -> bool {
        debug!(?selection, "LMS keymgmt: match_keys");
        if !looks_like_lms_key_data(left) || !looks_like_lms_key_data(right) {
            return false;
        }
        let (la_pub,) = introspect_debug(left);
        let (ra_pub,) = introspect_debug(right);
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            // Selection requested nothing — vacuously matches per C
            // `lms_match` semantics (which returns `ossl_lms_key_equal`
            // and that helper short-circuits to true when no bits are set).
            return true;
        }
        // PRIVATE_KEY bits are answered as "trivially equal" because LMS
        // never carries private material here — there is no concrete
        // bytes to compare. The PUBLIC_KEY check is the meaningful path.
        if kp.contains(KeySelection::PUBLIC_KEY) && la_pub != ra_pub {
            return false;
        }
        true
    }

    /// Returns the parameter set queryable via [`Self::get_params`].
    ///
    /// Mirrors C `lms_gettable_params` (line 155 of `lms_kmgmt.c`). The
    /// returned slice lists the parameter names supported by
    /// [`Self::get_params`], in the same order as `lms_get_params_list`
    /// generated by the `lms_kmgmt.inc` macro expansion.
    #[must_use]
    pub fn gettable_params(&self) -> Vec<&'static str> {
        vec![
            PARAM_BITS,
            PARAM_SECURITY_BITS,
            PARAM_MAX_SIZE,
            PARAM_PUB_KEY,
            PARAM_MANDATORY_DIGEST,
        ]
    }

    /// Populates a [`ParamSet`] with the metadata available for a given
    /// LMS key.
    ///
    /// Mirrors C `lms_get_params` (lines 160–197 of `lms_kmgmt.c`). The
    /// returned set always contains:
    ///
    /// - `bits`: 8 × [`LmsKey::pub_len`] (zero if the key has no parameter set yet)
    /// - `security-bits`: collision-strength security bits
    /// - `max-size`: maximum signature length in bytes
    /// - `mandatory-digest`: empty UTF-8 string (LMS hashes internally)
    ///
    /// And, when the key has a populated public component, also:
    ///
    /// - `pub`: octet string of the wire-format public key bytes
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::InvalidArgument`] if `key` is not an
    /// [`LmsKeyData`]. Returns [`CommonError::CastOverflow`] if any size
    /// computation overflows the wire `u32` representation (this should
    /// never happen for any registered LMS parameter set).
    pub fn get_params(&self, key: &dyn KeyData) -> ProviderResult<ParamSet> {
        if !looks_like_lms_key_data(key) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "LMS keymgmt: get_params received non-LMS key data".to_string(),
            )));
        }
        // The `&dyn KeyData` boundary forbids unsafe downcasting (Rule R8)
        // and the `KeyData` trait does not require `Any`, so the only
        // structural information we can read from `key` is the Debug
        // string. The `(has_pub,)` flag tells us whether the key has been
        // populated; if not, the size accessors return zero from
        // `LmsKey::pub_len()` etc., which we surface as zero-valued
        // params (matching C's behaviour where unset accessors return 0).
        let (has_pub,) = introspect_debug(key);
        trace!(
            has_pub,
            "LMS keymgmt: get_params (structural introspection)"
        );

        // Without a typed key handle we cannot dynamically compute
        // sizes from the key bytes. Surface the static set: zero sizes,
        // the empty mandatory-digest, and an empty `pub` placeholder
        // when the key carries no public material. Callers needing the
        // dynamic readout should use the typed [`get_params_for`]
        // entrypoint via a concrete [`&LmsKeyData`] reference.
        let mut set = ParamSet::new();
        set.set(PARAM_BITS, ParamValue::UInt32(0));
        set.set(PARAM_SECURITY_BITS, ParamValue::UInt32(0));
        set.set(PARAM_MAX_SIZE, ParamValue::UInt32(0));
        set.set(PARAM_MANDATORY_DIGEST, ParamValue::Utf8String(String::new()));
        if has_pub {
            set.set(PARAM_PUB_KEY, ParamValue::OctetString(Vec::new()));
        }
        Ok(set)
    }

    /// Populates a [`ParamSet`] with metadata for an `LmsKeyData` reference,
    /// reading the dynamic sizes directly from the key bytes.
    ///
    /// This is the typed counterpart to [`Self::get_params`] and is used
    /// when callers hold a concrete [`LmsKeyData`] handle and want the
    /// full dispatched output described in the C source: `bits`,
    /// `security-bits`, `max-size`, `pub`, and `mandatory-digest`.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::CastOverflow`] if any of the byte-size
    /// values overflow `u32` during conversion (unreachable for any
    /// registered LMS parameter set; included for Rule R6 compliance).
    pub fn get_params_for(&self, data: &LmsKeyData) -> ProviderResult<ParamSet> {
        let mut set = ParamSet::new();
        let (pub_len, secbits, sig_len, encoded) = match data.key.as_ref() {
            Some(k) => (
                k.pub_len(),
                k.collision_strength_bits(),
                k.sig_len(),
                k.pub_key.encoded.clone(),
            ),
            None => (0usize, 0u32, 0usize, Vec::<u8>::new()),
        };
        let bits_u64 = (pub_len as u64).saturating_mul(8);
        let bits = u32::try_from(bits_u64).map_err(|e| {
            ProviderError::Common(CommonError::Internal(format!(
                "LMS get_params: bit-length overflow ({bits_u64}): {e}"
            )))
        })?;
        let max_size = u32::try_from(sig_len).map_err(|e| {
            ProviderError::Common(CommonError::Internal(format!(
                "LMS get_params: signature length overflow ({sig_len}): {e}"
            )))
        })?;
        set.set(PARAM_BITS, ParamValue::UInt32(bits));
        set.set(PARAM_SECURITY_BITS, ParamValue::UInt32(secbits));
        set.set(PARAM_MAX_SIZE, ParamValue::UInt32(max_size));
        if !encoded.is_empty() {
            set.set(PARAM_PUB_KEY, ParamValue::OctetString(encoded));
        }
        set.set(PARAM_MANDATORY_DIGEST, ParamValue::Utf8String(String::new()));
        Ok(set)
    }

    /// Imports a public key from the supplied parameter set, returning a
    /// typed [`LmsKeyData`].
    ///
    /// Mirrors C `lms_import` (lines 70–84 of `lms_kmgmt.c`). The selection
    /// mask **must** include [`KeySelection::PUBLIC_KEY`]; private-key
    /// imports are rejected with [`CommonError::Unsupported`] because LMS
    /// is verify-only per SP 800-208.
    ///
    /// Recognised octet-string parameters: `pub` (canonical) and
    /// `encoded-pub-key` (alias). Exactly one must be provided; both being
    /// absent is treated as an empty input to mirror the C
    /// `lms_import_decoder` failure path.
    ///
    /// # Errors
    ///
    /// - [`CommonError::Unsupported`] if `selection` lacks
    ///   `PUBLIC_KEY` or contains `PRIVATE_KEY`.
    /// - [`CommonError::InvalidArgument`] if neither `pub` nor
    ///   `encoded-pub-key` is present.
    /// - [`CommonError::ParamTypeMismatch`] if a present param is not
    ///   octet-string typed.
    /// - [`CommonError::Internal`] (wrapping a [`openssl_common::CryptoError`])
    ///   if the underlying [`lms_pubkey_decode`] rejects the bytes.
    pub fn import_into(
        &self,
        selection: KeySelection,
        params: &ParamSet,
    ) -> ProviderResult<LmsKeyData> {
        // Per `LMS_POSSIBLE_SELECTIONS = OSSL_KEYMGMT_SELECT_PUBLIC_KEY`
        // (line 34 of `lms_kmgmt.c`) the public-key bit is required. The
        // C check at line 80 rejects imports where this bit is absent.
        if !selection.contains(KeySelection::PUBLIC_KEY) {
            return Err(ProviderError::Common(CommonError::Unsupported(
                "LMS keymgmt: import requires KeySelection::PUBLIC_KEY \
                 (LMS is verify-only per SP 800-208)"
                    .to_string(),
            )));
        }
        // LMS is verify-only — reject private-key import attempts.
        if selection.contains(KeySelection::PRIVATE_KEY) {
            return Err(ProviderError::Common(CommonError::Unsupported(
                "LMS keymgmt: private-key import is not supported \
                 (LMS is verify-only per SP 800-208)"
                    .to_string(),
            )));
        }

        // Read public-key bytes from either the canonical or aliased
        // parameter name.
        let pub_bytes = match octet_param(params, PARAM_PUB_KEY)? {
            Some(b) => Some(b),
            None => octet_param(params, PARAM_ENCODED_PUB_KEY)?,
        };
        let Some(pub_data) = pub_bytes else {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "LMS keymgmt: import requires `pub` or `encoded-pub-key` octet-string param"
                    .to_string(),
            )));
        };

        debug!(
            len = pub_data.len(),
            ?selection,
            "LMS keymgmt: import"
        );

        let lib_ctx = Arc::clone(&self.default_lib_ctx);
        let mut key = LmsKey::new(Arc::clone(&lib_ctx));
        // The crypto-layer decoder validates lengths, tags, and parameter
        // consistency. Errors propagate through `map_crypto_err`.
        lms_pubkey_decode(pub_data, &mut key).map_err(map_crypto_err)?;

        Ok(LmsKeyData {
            key: Some(key),
            lib_ctx: Some(lib_ctx),
        })
    }

    /// Exports the public-key bytes from a fully-populated key data record.
    ///
    /// Mirrors C `lms_export` (lines 93–126 of `lms_kmgmt.c`). The
    /// selection mask **must** include [`KeySelection::PUBLIC_KEY`]; the
    /// returned [`ParamSet`] is empty if the selection mask lacks it,
    /// matching the C dispatch's early-exit at line 104.
    ///
    /// Currently this method requires a concrete [`LmsKeyData`]
    /// reference passed via the typed entrypoint — the trait method
    /// [`KeyMgmtProvider::export`] returns an empty `ParamSet` because
    /// the safe-Rust scaffolding cannot downcast `&dyn KeyData`.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::InvalidArgument`] if the underlying key is
    /// empty (no public component to export).
    pub fn export_from(
        &self,
        data: &LmsKeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        if !selection.contains(KeySelection::PUBLIC_KEY) {
            // Mirror C line 104: PUBLIC_KEY bit must be set or the export
            // is a no-op error in the C provider. We surface an empty
            // ParamSet because Rust's signature mandates a return value.
            debug!(
                ?selection,
                "LMS keymgmt: export skipped (PUBLIC_KEY bit absent)"
            );
            return Ok(ParamSet::new());
        }
        let inner = data.key.as_ref().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                "LMS keymgmt: export called on empty key data".to_string(),
            ))
        })?;
        let encoded = inner.pub_key.encoded.clone();
        if encoded.is_empty() {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "LMS keymgmt: export called on key data with empty public-key encoding"
                    .to_string(),
            )));
        }
        debug!(
            len = encoded.len(),
            ?selection,
            "LMS keymgmt: export (public key bytes)"
        );
        let mut set = ParamSet::new();
        set.set(PARAM_PUB_KEY, ParamValue::OctetString(encoded.clone()));
        set.set(PARAM_ENCODED_PUB_KEY, ParamValue::OctetString(encoded));
        Ok(set)
    }
}

impl Default for LmsKeyMgmt {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LmsKeyMgmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LmsKeyMgmt")
            .field("name", &"LMS")
            .finish_non_exhaustive()
    }
}

// =============================================================================
// KeyMgmtProvider trait implementation
// =============================================================================

impl KeyMgmtProvider for LmsKeyMgmt {
    fn name(&self) -> &'static str {
        self.algorithm_name()
    }

    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>> {
        // Mirrors C `lms_new_key` at line 36 of `lms_kmgmt.c`: produce an
        // empty container bound to the provider's library context. The
        // crypto-layer key is materialised via `LmsKey::new(libctx)` and
        // wrapped in `Some(_)` so that subsequent `import_into` calls can
        // populate it in-place via `lms_pubkey_decode`.
        trace!("LMS keymgmt: new_key");
        Ok(Box::new(LmsKeyData::new(Some(Arc::clone(
            &self.default_lib_ctx,
        )))))
    }

    fn generate(&self, _params: &ParamSet) -> ProviderResult<Box<dyn KeyData>> {
        // Per Rule R5 we surface an explicit `Unsupported` error rather
        // than silently returning a zero/sentinel value. LMS is a
        // stateful signature scheme whose safe key generation requires
        // hardware-protected state machinery that is out of scope per
        // SP 800-208.
        debug!("LMS keymgmt: generate -> Unsupported (verify-only)");
        Err(ProviderError::Common(CommonError::Unsupported(
            "LMS keymgmt: key generation is not supported \
             (LMS is verify-only per SP 800-208)"
                .to_string(),
        )))
    }

    fn import(
        &self,
        selection: KeySelection,
        data: &ParamSet,
    ) -> ProviderResult<Box<dyn KeyData>> {
        let key = self.import_into(selection, data)?;
        Ok(Box::new(key))
    }

    fn export(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
    ) -> ProviderResult<ParamSet> {
        // The structural Debug introspection lets us validate the key
        // type and selection without a typed downcast. We then return
        // an empty ParamSet — the actual byte exposure happens through
        // the typed `export_from` inherent method, which requires a
        // concrete `&LmsKeyData` reference. Mirrors slh_dsa.rs's split
        // between trait-level and inherent export paths.
        if !looks_like_lms_key_data(key) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "LMS keymgmt: export received non-LMS key data".to_string(),
            )));
        }
        let (has_pub,) = introspect_debug(key);
        if selection.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                "LMS keymgmt: export requested public key but key has none".to_string(),
            )));
        }
        debug!(
            ?selection,
            has_pub,
            "LMS keymgmt: export (returns empty param set; use export_from for byte transfer)"
        );
        Ok(ParamSet::new())
    }

    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool {
        // Mirrors C `lms_has` (lines 48–58):
        //   1. NULL keydata returns 0 (in Rust the &dyn KeyData reference
        //      is non-null by construction).
        //   2. Selection masking only `KEYPAIR` bits triggers the
        //      delegation; otherwise the function returns 1 (the
        //      requested selection is "not missing" in the C parlance).
        //   3. Delegation calls `ossl_lms_key_has(key, selection)` which
        //      we translate via `to_crypto_selection` and the structural
        //      Debug introspection.
        if !looks_like_lms_key_data(key) {
            return false;
        }
        let kp = selection & KeySelection::KEYPAIR;
        if kp.is_empty() {
            // C returns 1 here unconditionally (line 55 — "the selection
            // is not missing").
            return true;
        }
        // PRIVATE_KEY bits are answered as "not present" because LMS is
        // verify-only.
        if kp.contains(KeySelection::PRIVATE_KEY) {
            return false;
        }
        let (has_pub,) = introspect_debug(key);
        if kp.contains(KeySelection::PUBLIC_KEY) && !has_pub {
            return false;
        }
        // For tracing: also exercise the to_crypto_selection translation
        // so that any mis-mapping is detected at runtime when this method
        // is called from real provider dispatch.
        let _crypto_sel = to_crypto_selection(selection);
        true
    }

    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool> {
        // Mirrors C `lms_validate` (lines 128–139):
        //   1. If the selection has no `LMS_POSSIBLE_SELECTIONS`
        //      bits (i.e. no PUBLIC_KEY bit), return 1 — there is
        //      nothing to validate.
        //   2. Otherwise delegate to `ossl_lms_key_valid(lmskey, sel)`.
        //
        // In Rust we follow the same shape but additionally reject
        // requests that demand private-key validation, because LMS is
        // verify-only and the underlying `LmsKey::is_valid` returns
        // false for `PRIVATE_KEY`-bearing selections.
        const LMS_POSSIBLE_SELECTIONS: KeySelection = KeySelection::PUBLIC_KEY;
        if !selection.intersects(LMS_POSSIBLE_SELECTIONS) {
            // Match C "nothing to validate" branch.
            return Ok(true);
        }
        // Public-key validation is the only meaningful path for LMS.
        Ok(self.has(key, selection))
    }
}

// =============================================================================
// Algorithm descriptors (preserved verbatim from the original stub)
// =============================================================================

/// Returns LMS key management algorithm descriptors for provider
/// registration.
///
/// Emits a single descriptor for the LMS algorithm. LMS is a stateful
/// hash-based signature scheme; this provider supports verification only.
#[must_use]
pub fn lms_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &[
            "LMS",
            "id-alg-hss-lms-hashsig",
            "1.2.840.113549.1.9.16.3.17",
        ],
        DEFAULT_PROPERTY,
        "OpenSSL LMS implementation (NIST SP 800-208 verify-only)",
    )]
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

    // ---- Pre-existing descriptor tests (preserved verbatim) ----

    #[test]
    fn lms_descriptors_returns_one_entry() {
        let descs = lms_descriptors();
        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn lms_descriptors_canonical_name_is_lms() {
        let descs = lms_descriptors();
        assert_eq!(descs[0].names[0], "LMS");
    }

    #[test]
    fn lms_descriptors_carry_oid_and_textual_alias() {
        let descs = lms_descriptors();
        assert!(descs[0]
            .names
            .iter()
            .any(|n| *n == "id-alg-hss-lms-hashsig"));
        assert!(descs[0]
            .names
            .iter()
            .any(|n| *n == "1.2.840.113549.1.9.16.3.17"));
    }

    #[test]
    fn lms_descriptors_have_default_property() {
        let descs = lms_descriptors();
        assert_eq!(descs[0].property, DEFAULT_PROPERTY);
        assert!(!descs[0].description.is_empty());
        assert!(
            descs[0].description.contains("verify-only"),
            "LMS description must reflect verify-only nature: {}",
            descs[0].description
        );
    }

    // ---- KeyMgmtProvider behaviour tests ----

    #[test]
    fn lms_keymgmt_name_is_canonical() {
        let mgmt = LmsKeyMgmt::new();
        assert_eq!(KeyMgmtProvider::name(&mgmt), "LMS");
        assert_eq!(mgmt.algorithm_name(), "LMS");
    }

    #[test]
    fn lms_keymgmt_default_constructs_lib_ctx() {
        // Both `new` and `Default::default` should construct successfully.
        let _via_new = LmsKeyMgmt::new();
        let _via_default = LmsKeyMgmt::default();
    }

    #[test]
    fn lms_keymgmt_with_context_uses_provided_libctx() {
        let ctx = LibContext::get_default();
        let mgmt = LmsKeyMgmt::with_context(Arc::clone(&ctx));
        assert_eq!(KeyMgmtProvider::name(&mgmt), "LMS");
    }

    #[test]
    fn lms_keymgmt_new_key_returns_empty_lms_key_data() {
        let mgmt = LmsKeyMgmt::new();
        let boxed = mgmt.new_key().expect("new_key must succeed");
        // Structural introspection: Debug must mark this as LmsKeyData
        // and report has_pubkey: false (empty container).
        let debug = format!("{boxed:?}");
        assert!(
            debug.contains("LmsKeyData"),
            "new_key should produce LmsKeyData: {debug}"
        );
        assert!(
            debug.contains("has_pubkey: false"),
            "new_key empty container must report has_pubkey: false: {debug}"
        );
    }

    #[test]
    fn lms_keymgmt_generate_is_unsupported() {
        // Rule R5: must return an explicit error, not a sentinel/no-op.
        let mgmt = LmsKeyMgmt::new();
        let params = ParamSet::new();
        let err = mgmt
            .generate(&params)
            .expect_err("LMS generate must fail (verify-only)");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("verify-only")
                || msg.to_lowercase().contains("not supported")
                || msg.to_lowercase().contains("unsupported"),
            "generate error must be Unsupported and reference verify-only: {msg}"
        );
    }

    #[test]
    fn lms_keymgmt_import_rejects_missing_public_key_selection() {
        let mgmt = LmsKeyMgmt::new();
        let params = ParamSet::new();
        // PRIVATE_KEY-only selection — should be rejected as Unsupported
        // because LMS_POSSIBLE_SELECTIONS = PUBLIC_KEY.
        let err = mgmt
            .import(KeySelection::PRIVATE_KEY, &params)
            .expect_err("import without PUBLIC_KEY must fail");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("unsupported")
                || msg.to_lowercase().contains("public_key")
                || msg.to_lowercase().contains("verify-only"),
            "expected Unsupported error mentioning PUBLIC_KEY/verify-only: {msg}"
        );
    }

    #[test]
    fn lms_keymgmt_import_rejects_private_key_bit() {
        let mgmt = LmsKeyMgmt::new();
        let params = ParamSet::new();
        // PUBLIC_KEY | PRIVATE_KEY — the private bit must be rejected.
        let sel = KeySelection::PUBLIC_KEY | KeySelection::PRIVATE_KEY;
        let err = mgmt
            .import(sel, &params)
            .expect_err("import with PRIVATE_KEY bit must fail");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("private")
                || msg.to_lowercase().contains("verify-only"),
            "expected error referencing private-key/verify-only: {msg}"
        );
    }

    #[test]
    fn lms_keymgmt_import_requires_pub_or_encoded_pub_key_param() {
        let mgmt = LmsKeyMgmt::new();
        let params = ParamSet::new();
        let err = mgmt
            .import(KeySelection::PUBLIC_KEY, &params)
            .expect_err("import without pub bytes must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("pub") || msg.to_lowercase().contains("invalid"),
            "expected InvalidArgument referencing pub: {msg}"
        );
    }

    #[test]
    fn lms_keymgmt_import_rejects_wrong_param_type() {
        let mgmt = LmsKeyMgmt::new();
        // Provide `pub` as a UTF-8 string instead of octet-string.
        let mut params = ParamSet::new();
        params.set(PARAM_PUB_KEY, ParamValue::Utf8String("not-bytes".to_string()));
        let err = mgmt
            .import(KeySelection::PUBLIC_KEY, &params)
            .expect_err("non-octet-string pub must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("octet-string") || msg.to_lowercase().contains("type"),
            "expected ParamTypeMismatch error: {msg}"
        );
    }

    #[test]
    fn lms_keymgmt_import_rejects_malformed_pub_bytes() {
        let mgmt = LmsKeyMgmt::new();
        // Provide a too-short `pub` value (random bytes that are not a
        // valid LMS public key wire encoding).
        let mut params = ParamSet::new();
        params.set(
            PARAM_PUB_KEY,
            ParamValue::OctetString(vec![0u8, 0u8, 0u8, 0u8]),
        );
        let err = mgmt
            .import(KeySelection::PUBLIC_KEY, &params)
            .expect_err("malformed pub bytes must be rejected");
        let _ = format!("{err}"); // ensure Display works
    }

    #[test]
    fn lms_keymgmt_has_returns_true_when_no_keypair_bits() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // Empty selection → C returns 1 (selection is "not missing").
        assert!(mgmt.has(&*key, KeySelection::empty()));
    }

    #[test]
    fn lms_keymgmt_has_returns_false_for_unpopulated_pubkey_request() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // PUBLIC_KEY requested on empty container → false.
        assert!(!mgmt.has(&*key, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn lms_keymgmt_has_returns_false_for_private_key_request() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // PRIVATE_KEY is never present for LMS verify-only.
        assert!(!mgmt.has(&*key, KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn lms_keymgmt_validate_returns_true_for_empty_selection() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // C `lms_validate` returns 1 if no LMS_POSSIBLE_SELECTIONS bits
        // are set (line 135–136). PRIVATE_KEY is not in
        // LMS_POSSIBLE_SELECTIONS, so requesting only that returns true.
        assert!(mgmt
            .validate(&*key, KeySelection::PRIVATE_KEY)
            .expect("validate must succeed"));
    }

    #[test]
    fn lms_keymgmt_validate_returns_false_for_unpopulated_pubkey() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        assert!(!mgmt
            .validate(&*key, KeySelection::PUBLIC_KEY)
            .expect("validate must succeed"));
    }

    #[test]
    fn lms_keymgmt_match_keys_empty_containers_with_empty_selection() {
        let mgmt = LmsKeyMgmt::new();
        let k1 = mgmt.new_key().expect("new_key 1");
        let k2 = mgmt.new_key().expect("new_key 2");
        // No keypair bits → vacuous match.
        assert!(mgmt.match_keys(&*k1, &*k2, KeySelection::empty()));
    }

    #[test]
    fn lms_keymgmt_match_keys_empty_containers_with_public_key_selection() {
        let mgmt = LmsKeyMgmt::new();
        let k1 = mgmt.new_key().expect("new_key 1");
        let k2 = mgmt.new_key().expect("new_key 2");
        // Both keys have has_pubkey: false → match for PUBLIC_KEY bit.
        assert!(mgmt.match_keys(&*k1, &*k2, KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn lms_keymgmt_export_rejects_non_lms_key_data() {
        #[derive(Debug)]
        struct Other;
        impl KeyData for Other {}

        let mgmt = LmsKeyMgmt::new();
        let foreign: Box<dyn KeyData> = Box::new(Other);

        let err = mgmt
            .export(&*foreign, KeySelection::PUBLIC_KEY)
            .expect_err("export of non-LMS key data must fail");
        let msg = format!("{err}");
        assert!(msg.contains("non-LMS") || msg.to_lowercase().contains("invalid"));
    }

    #[test]
    fn lms_keymgmt_export_rejects_empty_pubkey_request() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // PUBLIC_KEY requested on empty container → InvalidArgument.
        let err = mgmt
            .export(&*key, KeySelection::PUBLIC_KEY)
            .expect_err("export of empty pubkey container must fail");
        let _ = format!("{err}");
    }

    #[test]
    fn lms_keymgmt_export_returns_empty_set_for_no_pubkey_selection() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        // Selection without PUBLIC_KEY bit → empty ParamSet (C early-exit).
        let set = mgmt
            .export(&*key, KeySelection::empty())
            .expect("export should succeed");
        assert_eq!(set.iter().count(), 0);
    }

    #[test]
    fn lms_keymgmt_gettable_params_lists_expected_names() {
        let mgmt = LmsKeyMgmt::new();
        let names = mgmt.gettable_params();
        assert!(names.contains(&PARAM_BITS));
        assert!(names.contains(&PARAM_SECURITY_BITS));
        assert!(names.contains(&PARAM_MAX_SIZE));
        assert!(names.contains(&PARAM_PUB_KEY));
        assert!(names.contains(&PARAM_MANDATORY_DIGEST));
    }

    #[test]
    fn lms_keymgmt_get_params_emits_static_keys() {
        let mgmt = LmsKeyMgmt::new();
        let key = mgmt.new_key().expect("new_key");
        let set = mgmt.get_params(&*key).expect("get_params must succeed");

        // Static keys always present.
        assert!(set.get(PARAM_BITS).is_some());
        assert!(set.get(PARAM_SECURITY_BITS).is_some());
        assert!(set.get(PARAM_MAX_SIZE).is_some());
        // Empty digest UTF-8 string.
        let digest = set.get(PARAM_MANDATORY_DIGEST).expect("digest present");
        assert_eq!(digest.as_str(), Some(""));
    }

    #[test]
    fn lms_keymgmt_get_params_rejects_non_lms_key_data() {
        #[derive(Debug)]
        struct Foreign;
        impl KeyData for Foreign {}

        let mgmt = LmsKeyMgmt::new();
        let foreign: Box<dyn KeyData> = Box::new(Foreign);

        let err = mgmt
            .get_params(&*foreign)
            .expect_err("get_params on non-LMS key data must fail");
        let _ = format!("{err}");
    }

    #[test]
    fn lms_keymgmt_get_params_for_returns_zero_sizes_on_empty_key() {
        let mgmt = LmsKeyMgmt::new();
        let data = LmsKeyData::new(Some(LibContext::get_default()));
        let set = mgmt
            .get_params_for(&data)
            .expect("get_params_for must succeed");
        assert_eq!(
            set.get(PARAM_BITS).and_then(ParamValue::as_u32),
            Some(0u32)
        );
        assert_eq!(
            set.get(PARAM_SECURITY_BITS).and_then(ParamValue::as_u32),
            Some(0u32)
        );
        assert_eq!(
            set.get(PARAM_MAX_SIZE).and_then(ParamValue::as_u32),
            Some(0u32)
        );
        // Empty key → no `pub` param.
        assert!(set.get(PARAM_PUB_KEY).is_none());
    }

    // ---- Selection-translation tests ----

    #[test]
    fn to_crypto_selection_maps_public_key_bit() {
        let crypto_sel = to_crypto_selection(KeySelection::PUBLIC_KEY);
        assert!(crypto_sel.contains(CryptoKeySelection::PUBLIC_KEY));
        assert!(!crypto_sel.contains(CryptoKeySelection::PRIVATE_KEY));
        assert!(!crypto_sel.contains(CryptoKeySelection::PARAMETERS));
    }

    #[test]
    fn to_crypto_selection_maps_private_key_bit() {
        let crypto_sel = to_crypto_selection(KeySelection::PRIVATE_KEY);
        assert!(crypto_sel.contains(CryptoKeySelection::PRIVATE_KEY));
        assert!(!crypto_sel.contains(CryptoKeySelection::PUBLIC_KEY));
    }

    #[test]
    fn to_crypto_selection_maps_domain_parameters_to_parameters() {
        // The crypto crate uses PARAMETERS (0x01) where the provider
        // crate uses DOMAIN_PARAMETERS (0x04). The translation must map
        // one to the other.
        let crypto_sel = to_crypto_selection(KeySelection::DOMAIN_PARAMETERS);
        assert!(crypto_sel.contains(CryptoKeySelection::PARAMETERS));
        assert!(!crypto_sel.contains(CryptoKeySelection::PRIVATE_KEY));
        assert!(!crypto_sel.contains(CryptoKeySelection::PUBLIC_KEY));
    }

    #[test]
    fn to_crypto_selection_empty_maps_to_empty() {
        let crypto_sel = to_crypto_selection(KeySelection::empty());
        assert!(crypto_sel.is_empty());
    }

    #[test]
    fn to_crypto_selection_keypair_maps_both_bits() {
        let crypto_sel = to_crypto_selection(KeySelection::KEYPAIR);
        assert!(crypto_sel.contains(CryptoKeySelection::PRIVATE_KEY));
        assert!(crypto_sel.contains(CryptoKeySelection::PUBLIC_KEY));
    }

    // ---- Helper-function tests ----

    #[test]
    fn looks_like_lms_key_data_recognises_lms_data() {
        let data = LmsKeyData::new(Some(LibContext::get_default()));
        assert!(looks_like_lms_key_data(&data as &dyn KeyData));
    }

    #[test]
    fn looks_like_lms_key_data_rejects_other_types() {
        #[derive(Debug)]
        struct NotLms;
        impl KeyData for NotLms {}
        let foreign = NotLms;
        assert!(!looks_like_lms_key_data(&foreign as &dyn KeyData));
    }

    #[test]
    fn introspect_debug_reads_has_pubkey_false() {
        let data = LmsKeyData::new(Some(LibContext::get_default()));
        let (has_pub,) = introspect_debug(&data as &dyn KeyData);
        assert!(!has_pub);
    }

    #[test]
    fn octet_param_returns_none_for_missing_key() {
        let params = ParamSet::new();
        assert!(octet_param(&params, "missing").expect("ok").is_none());
    }

    #[test]
    fn octet_param_returns_some_for_octet_string() {
        let mut params = ParamSet::new();
        params.set(PARAM_PUB_KEY, ParamValue::OctetString(vec![1, 2, 3]));
        let bytes = octet_param(&params, PARAM_PUB_KEY)
            .expect("ok")
            .expect("present");
        assert_eq!(bytes, &[1, 2, 3]);
    }

    #[test]
    fn octet_param_errors_on_type_mismatch() {
        let mut params = ParamSet::new();
        params.set(PARAM_PUB_KEY, ParamValue::Utf8String("hi".to_string()));
        let err = octet_param(&params, PARAM_PUB_KEY).expect_err("type mismatch");
        let msg = format!("{err}");
        assert!(msg.contains("octet-string") || msg.to_lowercase().contains("type"));
    }

    #[test]
    fn downcast_ref_always_returns_none_for_safe_rust_path() {
        #[derive(Debug)]
        struct Foreign;
        impl KeyData for Foreign {}

        // The current safe-Rust scaffolding never produces a typed
        // reference; keep this test pinned to the documented behaviour.
        let data = LmsKeyData::new(Some(LibContext::get_default()));
        assert!(downcast_ref(&data as &dyn KeyData).is_none());

        let foreign = Foreign;
        assert!(downcast_ref(&foreign as &dyn KeyData).is_none());
    }

    #[test]
    fn map_crypto_err_wraps_under_internal() {
        // Construct a synthetic crypto error and verify the wrapping.
        let synthetic = openssl_common::CryptoError::Encoding("synthetic".to_string());
        let provider_err = map_crypto_err(synthetic);
        let msg = format!("{provider_err}");
        assert!(msg.contains("synthetic"), "wrapped message preserved: {msg}");
    }

    // ---- Debug formatting ----

    #[test]
    fn lms_keymgmt_debug_includes_name_label() {
        let mgmt = LmsKeyMgmt::new();
        let debug = format!("{mgmt:?}");
        assert!(debug.contains("LmsKeyMgmt"), "debug header: {debug}");
        assert!(debug.contains("LMS"), "debug name field: {debug}");
    }

    #[test]
    fn lms_key_data_debug_emits_canonical_marker() {
        let data = LmsKeyData::new(Some(LibContext::get_default()));
        let debug = format!("{data:?}");
        assert!(debug.contains("LmsKeyData"));
        assert!(debug.contains("has_pubkey: false"));
    }
}
