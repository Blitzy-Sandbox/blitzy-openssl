//! # ML-KEM — Module-Lattice Key Encapsulation Mechanism (FIPS 203)
//!
//! Post-quantum Key Encapsulation Mechanism at three security levels:
//!
//! | Variant      | NIST Cat. | Pubkey | Privkey | Ciphertext | Shared Secret |
//! |--------------|-----------|--------|---------|------------|---------------|
//! | ML-KEM-512   | 1         | 800    | 1632    | 768        | 32            |
//! | ML-KEM-768   | 3         | 1184   | 2400    | 1088       | 32            |
//! | ML-KEM-1024  | 5         | 1568   | 3168    | 1568       | 32            |
//!
//! Supports deterministic encapsulation via the `ikmE` parameter for testing
//! and known-answer test vector verification.
//!
//! ## Source Translation
//!
//! Translates C `providers/implementations/kem/ml_kem_kem.c` (267 lines) into
//! idiomatic, safe Rust. The FIPS deferred-self-test gate
//! (`ossl_deferred_self_test`) and provider-running gate
//! (`ossl_prov_is_running()`) are intentionally omitted because this file
//! lives in the non-FIPS `openssl-provider` crate; FIPS-specific gating is
//! enforced by the dedicated `openssl-fips` crate.
//!
//! ## C → Rust Transformation Map
//!
//! | C construct                                         | Rust equivalent                                              |
//! |-----------------------------------------------------|--------------------------------------------------------------|
//! | `PROV_ML_KEM_CTX`                                   | [`MlKemContext`] (typed fields, `ZeroizeOnDrop`)             |
//! | `ML_KEM_KEY *key`                                   | `Option<MlKemKey>` parsed from raw bytes during init         |
//! | `int op` (`EVP_PKEY_OP_ENCAPSULATE` / `_DECAPSULATE`)| `Option<MlKemOperation>` enum                                |
//! | `uint8_t entropy_buf[32]` + `entropy*`              | `Option<Vec<u8>>` zeroized on drop and after use             |
//! | `ML_KEM_RANDOM_BYTES` (32)                          | const [`ML_KEM_RANDOM_BYTES`] (re-exports `RANDOM_BYTES`)    |
//! | `ML_KEM_SHARED_SECRET_BYTES` (32)                   | `SHARED_SECRET_BYTES` from `openssl_crypto::pqc::ml_kem`     |
//! | `ml_kem_newctx`                                     | [`MlKemContext::new`]                                        |
//! | `ml_kem_freectx` (`OPENSSL_cleanse`)                | `Drop` via [`zeroize::ZeroizeOnDrop`] on entropy             |
//! | `ml_kem_encapsulate_init`                           | [`MlKemContext::encapsulate_init`]                           |
//! | `ml_kem_decapsulate_init`                           | [`MlKemContext::decapsulate_init`]                           |
//! | `ml_kem_encapsulate`                                | [`MlKemContext::encapsulate`]                                |
//! | `ml_kem_decapsulate`                                | [`MlKemContext::decapsulate`]                                |
//! | `ml_kem_set_ctx_params` (only `OSSL_KEM_PARAM_IKME`)| [`MlKemContext::set_params`]                                 |
//! | `ml_kem_settable_ctx_params`                        | implicit (param keys documented inline)                      |
//! | `ossl_ml_kem_have_pubkey`                           | [`MlKemKey::have_pubkey`]                                    |
//! | `ossl_ml_kem_have_prvkey`                           | [`MlKemKey::have_prvkey`]                                    |
//! | `ossl_ml_kem_encap_seed`                            | `crypto_ml_kem::encap_seed(&key, &entropy_arr)`              |
//! | `ossl_ml_kem_encap_rand`                            | `crypto_ml_kem::encap_rand(&key)`                            |
//! | `ossl_ml_kem_decap`                                 | `crypto_ml_kem::decap(&key, ctext)`                          |
//! | `OPENSSL_cleanse(ctx->entropy, 32)`                 | `entropy.zeroize()` + `ZeroizeOnDrop`                        |
//! | `PROV_R_MISSING_KEY`                                | [`ProviderError::Dispatch`] (with descriptive message)       |
//! | `PROV_R_INVALID_SEED_LENGTH`                        | [`ProviderError::Dispatch`] (with length detail)             |
//! | Sentinel `0` / `1` returns                          | `ProviderResult<()>` (Rule R5)                               |
//! | Size-query semantics (`ctext == NULL` returns sizes)| Direct allocation: returns `(Vec<u8>, Vec<u8>)` always       |
//!
//! ## Cryptographic Hygiene
//!
//! - The `ikmE` deterministic seed buffer ([`MlKemContext::entropy`]) is
//!   securely zeroised on drop via [`zeroize::ZeroizeOnDrop`] and explicitly
//!   one-shot zeroised after each `encapsulate()` call to match the C
//!   source's `OPENSSL_cleanse(ctx->entropy)` semantics (lines 211–215 of
//!   the C source).
//! - The `MlKemKey` itself is `ZeroizeOnDrop` in `openssl-crypto`; therefore
//!   wrapping it in `Option<MlKemKey>` automatically zeroises private-key
//!   material on context drop.
//! - All key-length validations use `usize` comparisons with no narrowing
//!   casts (Rule R6).
//! - **No `unsafe` code** — Rule R8 strictly enforced.
//! - All public items carry `///` documentation (Rule R9).
//!
//! ## Behavioural Parity with C Source
//!
//! 1. The deterministic `ikmE` parameter MUST be exactly
//!    [`ML_KEM_RANDOM_BYTES`] (32) bytes — any other length yields
//!    [`ProviderError::Dispatch`] with `PROV_R_INVALID_SEED_LENGTH` text.
//! 2. The entropy buffer is zeroised after each `encapsulate()` invocation
//!    — subsequent encapsulations without a new `set_params(ikme=...)` call
//!    will draw fresh OS randomness, matching the one-shot semantics of the
//!    C implementation (lines 207–215).
//! 3. `set_params(ikme=...)` is processed only when the operation is
//!    `Encapsulate`; in `Decapsulate` mode the parameter is silently ignored
//!    (matches C `if (ctx->op == EVP_PKEY_OP_ENCAPSULATE && p.ikme != NULL)`).
//! 4. There is no auth mode, no `dupctx`, and no gettable context params,
//!    matching the C dispatch table at lines 256–266.
//! 5. The C size-query branch (`if (ctext == NULL) { *clen = ...; return 1; }`)
//!    is unnecessary in Rust because `Vec::with_capacity` allocations are
//!    transparent to the caller; sizes are always known via
//!    [`MlKemKey::ctext_len`] and [`MlKemKey::shared_secret_len`].

// -----------------------------------------------------------------------------
// Imports — strictly limited to the depends_on_files whitelist + zeroize +
// tracing (workspace-approved external crates).
// -----------------------------------------------------------------------------

use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{ParamSet, ProviderError, ProviderResult};

use openssl_crypto::context::LibContext;
use openssl_crypto::pqc::ml_kem::{self as crypto_ml_kem, MlKemKey, MlKemVariant, RANDOM_BYTES};

use crate::traits::{AlgorithmDescriptor, KemContext, KemProvider};

// -----------------------------------------------------------------------------
// Public constants
// -----------------------------------------------------------------------------

/// Number of random bytes for the deterministic `ikmE` seed used in
/// ML-KEM encapsulation (FIPS 203, Algorithm 17 line 1).
///
/// Re-exports [`openssl_crypto::pqc::ml_kem::RANDOM_BYTES`] under the
/// historical C name `ML_KEM_RANDOM_BYTES` for translation fidelity.
pub const ML_KEM_RANDOM_BYTES: usize = RANDOM_BYTES;

// -----------------------------------------------------------------------------
// Parameter keys — mirror C `OSSL_KEM_PARAM_*` macros from
// `include/openssl/core_names.h`.
// -----------------------------------------------------------------------------

/// Parameter name for the deterministic input keying material used during
/// ML-KEM encapsulation. Mirrors `OSSL_KEM_PARAM_IKME` from
/// `include/openssl/core_names.h`.
const PARAM_IKME: &str = "ikme";

// -----------------------------------------------------------------------------
// MlKemOperation — internal operation tag
// -----------------------------------------------------------------------------

/// Internal tag identifying which ML-KEM operation a context has been
/// initialised for.
///
/// Replaces the C `int op` field in `PROV_ML_KEM_CTX`, which held one of
/// `EVP_PKEY_OP_ENCAPSULATE` or `EVP_PKEY_OP_DECAPSULATE`. Using an enum
/// (with a `Send + Sync + Copy` derive set) eliminates the possibility of
/// invalid operation codes that the original `int` field allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MlKemOperation {
    /// Context is initialised for encapsulation: holds a public key and may
    /// hold an `ikmE` entropy buffer.
    Encapsulate,
    /// Context is initialised for decapsulation: holds a private key.
    Decapsulate,
}

impl MlKemOperation {
    /// Returns a short human-readable name for the operation, used in
    /// trace output and error messages.
    #[inline]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Encapsulate => "encapsulate",
            Self::Decapsulate => "decapsulate",
        }
    }
}

// -----------------------------------------------------------------------------
// MlKemSecurityParam — provider-local security-level enumeration
// -----------------------------------------------------------------------------

/// Identifies one of the three standardised ML-KEM parameter sets.
///
/// Provider-local mirror of [`openssl_crypto::pqc::ml_kem::MlKemVariant`] —
/// kept as a separate type so the provider crate can use schema-stable
/// names (`MlKemSecurityParam`) while the underlying crypto crate uses its
/// own canonical name (`MlKemVariant`).
///
/// Each variant maps 1:1 to a single FIPS 203 security category:
///
/// | Variant       | NIST Category | Classical Strength |
/// |---------------|---------------|--------------------|
/// | `MlKem512`    | Category 1    | ≈128 bits          |
/// | `MlKem768`    | Category 3    | ≈192 bits          |
/// | `MlKem1024`   | Category 5    | ≈256 bits          |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKemSecurityParam {
    /// ML-KEM-512 — NIST PQC security category 1 (≈128-bit classical).
    MlKem512,
    /// ML-KEM-768 — NIST PQC security category 3 (≈192-bit classical).
    MlKem768,
    /// ML-KEM-1024 — NIST PQC security category 5 (≈256-bit classical).
    MlKem1024,
}

impl MlKemSecurityParam {
    /// Returns the canonical algorithm name as registered with the provider
    /// dispatch table (e.g., `"ML-KEM-768"`).
    #[must_use]
    #[inline]
    pub const fn algorithm_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Maps to the underlying crypto-crate variant used by the
    /// algorithm primitives in [`openssl_crypto::pqc::ml_kem`].
    #[must_use]
    #[inline]
    pub const fn to_variant(self) -> MlKemVariant {
        match self {
            Self::MlKem512 => MlKemVariant::MlKem512,
            Self::MlKem768 => MlKemVariant::MlKem768,
            Self::MlKem1024 => MlKemVariant::MlKem1024,
        }
    }

    /// Returns the encoded public-key length in bytes for this variant.
    ///
    /// Mirrors the `pubkey_bytes` field of the corresponding
    /// `MlKemParams` table in `openssl_crypto::pqc::ml_kem`.
    #[must_use]
    #[inline]
    pub const fn pubkey_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Returns the encoded private-key length in bytes (FIPS 203 DK format)
    /// for this variant.
    ///
    /// Mirrors the `prvkey_bytes` field of the corresponding
    /// `MlKemParams` table in `openssl_crypto::pqc::ml_kem`.
    #[must_use]
    #[inline]
    pub const fn prvkey_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Returns a short human-readable description for documentation and
    /// dispatch-table registration.
    #[must_use]
    #[inline]
    const fn description(self) -> &'static str {
        match self {
            Self::MlKem512 => "Module-Lattice KEM 512-bit security (FIPS 203)",
            Self::MlKem768 => "Module-Lattice KEM 768-bit security (FIPS 203)",
            Self::MlKem1024 => "Module-Lattice KEM 1024-bit security (FIPS 203)",
        }
    }
}

// -----------------------------------------------------------------------------
// MlKem — the provider entry struct
// -----------------------------------------------------------------------------

/// ML-KEM provider for a single security parameter set.
///
/// Acts as a factory: holds the [`MlKemSecurityParam`] this instance is
/// bound to and produces a fresh [`MlKemContext`] each time
/// [`KemProvider::new_ctx`] is called. There is one [`MlKem`] instance per
/// algorithm (i.e., three total: ML-KEM-512, ML-KEM-768, ML-KEM-1024).
///
/// Replaces the C `OSSL_DISPATCH ossl_ml_kem_asym_kem_functions[]` table at
/// `providers/implementations/kem/ml_kem_kem.c` lines 256–266 — instead of
/// a function-pointer table, dispatch is performed via Rust's trait-object
/// virtual dispatch, eliminating an entire class of memory-safety hazards.
#[derive(Debug, Clone)]
pub struct MlKem {
    /// Which ML-KEM security parameter set this provider serves.
    security_param: MlKemSecurityParam,
}

impl MlKem {
    /// Constructs a new ML-KEM provider for the given security parameter set.
    #[must_use]
    #[inline]
    pub const fn new(security_param: MlKemSecurityParam) -> Self {
        Self { security_param }
    }

    /// Convenience constructor for ML-KEM-512.
    #[must_use]
    #[inline]
    pub const fn new_512() -> Self {
        Self::new(MlKemSecurityParam::MlKem512)
    }

    /// Convenience constructor for ML-KEM-768.
    #[must_use]
    #[inline]
    pub const fn new_768() -> Self {
        Self::new(MlKemSecurityParam::MlKem768)
    }

    /// Convenience constructor for ML-KEM-1024.
    #[must_use]
    #[inline]
    pub const fn new_1024() -> Self {
        Self::new(MlKemSecurityParam::MlKem1024)
    }

    /// Returns the [`MlKemSecurityParam`] this provider is bound to.
    #[must_use]
    #[inline]
    pub const fn security_param(&self) -> MlKemSecurityParam {
        self.security_param
    }

    /// Returns the canonical algorithm name (e.g., `"ML-KEM-768"`).
    #[must_use]
    #[inline]
    pub const fn name(&self) -> &'static str {
        self.security_param.algorithm_name()
    }

    /// Constructs a fresh [`MlKemContext`] bound to this provider's
    /// security parameter set.
    ///
    /// This method exists in addition to the trait method
    /// [`KemProvider::new_ctx`] to provide a strongly-typed return
    /// without requiring a `Box<dyn KemContext>` wrapper.
    ///
    /// # Errors
    ///
    /// Currently infallible (returns `Ok(...)` always); the
    /// `ProviderResult` wrapping is reserved for future libctx-acquisition
    /// failures, matching the C behaviour where `ml_kem_newctx` could fail
    /// on `OPENSSL_zalloc`.
    pub fn new_ctx(&self) -> ProviderResult<MlKemContext> {
        MlKemContext::new(self.security_param)
    }

    /// Returns the algorithm descriptors for all three ML-KEM variants.
    ///
    /// Equivalent to the free [`descriptors`] function — exposed as an
    /// associated method for ergonomic access from registration code that
    /// already has an [`MlKem`] in scope.
    #[must_use]
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        descriptors()
    }
}

// -----------------------------------------------------------------------------
// MlKemContext — per-operation state container
// -----------------------------------------------------------------------------

/// ML-KEM encapsulation/decapsulation context.
///
/// Replaces the C `PROV_ML_KEM_CTX` struct from `ml_kem_kem.c` lines 18–25:
///
/// ```c
/// typedef struct {
///     ML_KEM_KEY *key;
///     uint8_t entropy_buf[ML_KEM_RANDOM_BYTES];
///     uint8_t *entropy;
///     int op;
/// } PROV_ML_KEM_CTX;
/// ```
///
/// Differences in the Rust translation:
///
/// - `ML_KEM_KEY *key` → `Option<MlKemKey>` because the key is parsed
///   lazily during `encapsulate_init` / `decapsulate_init` from the raw
///   key bytes passed via the [`KemContext`] trait.
/// - `entropy_buf[32]` + `entropy*` (out-of-band null indicator) →
///   `Option<Vec<u8>>` (Rule R5 — null indicators replaced with `Option`).
/// - `int op` → `Option<MlKemOperation>` (Rule R5 — sentinel `0` replaced
///   with `None`; type-state ensures invalid op codes are unrepresentable).
///
/// All key material and the `ikmE` entropy are securely zeroised on drop:
///
/// - The `entropy: Option<Vec<u8>>` field is zeroised by the
///   `#[derive(ZeroizeOnDrop)]` macro.
/// - The `key: Option<MlKemKey>` field carries its own
///   `ZeroizeOnDrop` impl (defined in `openssl_crypto::pqc::ml_kem`),
///   which propagates through the `Option` wrapper. We mark the field
///   `#[zeroize(skip)]` here only to avoid recursive zeroisation
///   conflicts — the inner type's `Drop` performs the actual wipe.
#[derive(ZeroizeOnDrop)]
pub struct MlKemContext {
    /// Parsed ML-KEM key. `None` until `encapsulate_init` /
    /// `decapsulate_init` is called.
    ///
    /// `MlKemKey` itself implements `ZeroizeOnDrop` (in `openssl-crypto`),
    /// so the inner secret material — particularly the private key
    /// polynomials — is wiped automatically when this context drops. We
    /// skip this field in our own `ZeroizeOnDrop` derive to avoid double
    /// processing.
    #[zeroize(skip)]
    key: Option<MlKemKey>,

    /// Which operation (encap/decap) the context has been initialised for.
    /// `None` until an init method is called.
    #[zeroize(skip)]
    op: Option<MlKemOperation>,

    /// The security-parameter set (e.g., `MlKem768`) this context is
    /// bound to. Determines expected key/ciphertext lengths.
    #[zeroize(skip)]
    security_param: MlKemSecurityParam,

    /// Optional deterministic encapsulation seed (`ikmE` parameter).
    /// MUST be exactly [`ML_KEM_RANDOM_BYTES`] bytes when present.
    /// One-shot: zeroised after each encapsulation.
    entropy: Option<Vec<u8>>,
}

impl core::fmt::Debug for MlKemContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never format secret fields (key material, entropy) — emit only
        // structural metadata.
        f.debug_struct("MlKemContext")
            .field("security_param", &self.security_param)
            .field("op", &self.op)
            .field("key_loaded", &self.key.is_some())
            .field("entropy_set", &self.entropy.is_some())
            .finish()
    }
}

impl MlKemContext {
    /// Constructs a fresh, empty ML-KEM context for the given security
    /// parameter set. Replaces C `ml_kem_newctx` (lines 40–55).
    ///
    /// All operational fields (`key`, `op`, `entropy`) start as `None`;
    /// the caller must invoke either [`encapsulate_init`](Self::encapsulate_init)
    /// or [`decapsulate_init`](Self::decapsulate_init) before performing
    /// any cryptographic work.
    ///
    /// # Errors
    ///
    /// Currently this is infallible (returns `Ok(...)` always), but the
    /// signature is `ProviderResult<Self>` to allow future addition of
    /// libctx-acquisition logic without an API break — matching the C
    /// behaviour where `ml_kem_newctx` could fail on `OPENSSL_zalloc`.
    pub fn new(security_param: MlKemSecurityParam) -> ProviderResult<Self> {
        debug!(
            algorithm = security_param.algorithm_name(),
            "MlKemContext::new"
        );
        Ok(Self {
            key: None,
            op: None,
            security_param,
            entropy: None,
        })
    }

    /// Returns the security parameter set this context is bound to.
    #[must_use]
    #[inline]
    pub const fn security_param(&self) -> MlKemSecurityParam {
        self.security_param
    }

    /// Returns `true` if a key has been parsed and loaded into this context.
    #[must_use]
    #[inline]
    pub const fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Returns the current operation, if any.
    ///
    /// Currently exposed only for unit tests — production callers use
    /// `encapsulate()` / `decapsulate()` directly which perform their
    /// own state validation against `self.op`. The accessor is gated
    /// to test builds to keep the public crate surface minimal.
    #[cfg(test)]
    #[must_use]
    #[inline]
    pub(crate) const fn op(&self) -> Option<MlKemOperation> {
        self.op
    }

    /// Returns `true` when a deterministic `ikmE` seed has been set.
    #[must_use]
    #[inline]
    pub const fn has_entropy(&self) -> bool {
        self.entropy.is_some()
    }

    /// Clears any previously-set `ikmE` entropy buffer, securely zeroing
    /// it before deallocation.
    ///
    /// Mirrors the C `OPENSSL_cleanse(ctx->entropy_buf, ML_KEM_RANDOM_BYTES)`
    /// call in `ml_kem_init` (lines 76–79) which always wipes the entropy
    /// buffer on init.
    #[inline]
    fn clear_entropy(&mut self) {
        if let Some(ref mut buf) = self.entropy {
            buf.zeroize();
        }
        self.entropy = None;
    }

    /// Resets the context to an uninitialised state, zeroising all
    /// associated secret material.
    ///
    /// Used by init methods to clear any previous operation's state
    /// before configuring the new one — matches C `ml_kem_init`'s
    /// behaviour of overwriting all fields unconditionally.
    fn reset_for_reinit(&mut self) {
        self.clear_entropy();
        self.op = None;
        // Drop any previously parsed key — its own `ZeroizeOnDrop` impl
        // wipes the inner secret material.
        self.key = None;
    }
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/// Converts a [`openssl_common::CryptoError`] originating from the
/// `openssl-crypto` crate into a [`ProviderError::Dispatch`] suitable for
/// returning across the provider trait boundary.
///
/// This mirrors the helper used in `kem/ecx.rs` so all KEM provider
/// implementations report low-level cryptographic failures uniformly.
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn dispatch_err(e: openssl_common::CryptoError) -> ProviderError {
    ProviderError::Dispatch(e.to_string())
}

/// Validates and stores the `ikmE` deterministic seed parameter (if
/// present) on the given context.
///
/// Replaces the C `ml_kem_set_ctx_params` body at lines 206–238 of the C
/// source. Behavioural rules — preserved exactly:
///
/// - The parameter is **only** processed when the context's operation is
///   `Encapsulate`. In any other state (including `None` and
///   `Decapsulate`), the parameter is silently ignored, matching the C
///   conditional `if (ctx->op == EVP_PKEY_OP_ENCAPSULATE && p != NULL)`.
/// - The parameter MUST be an octet string of length exactly
///   [`ML_KEM_RANDOM_BYTES`] (32) — any other length yields
///   [`ProviderError::Dispatch`] with a `PROV_R_INVALID_SEED_LENGTH` text.
/// - Any pre-existing `ikmE` buffer is zeroised before being replaced.
fn apply_ikme_param(ctx: &mut MlKemContext, params: &ParamSet) -> ProviderResult<()> {
    let Some(value) = params.get(PARAM_IKME) else {
        // No `ikmE` parameter present — nothing to do; encapsulation will
        // fall back to OS randomness.
        trace!("apply_ikme_param: no ikmE parameter present");
        return Ok(());
    };

    // Only process the parameter when in encapsulation mode (matches C
    // gating at line 211). When we're not in encap mode (either
    // uninitialised or in decap mode), silently ignore — this matches
    // upstream behaviour where set_ctx_params can be called speculatively
    // before init.
    if ctx.op != Some(MlKemOperation::Encapsulate) {
        trace!(
            current_op = ?ctx.op,
            "apply_ikme_param: ikmE parameter ignored (not in encap mode)"
        );
        return Ok(());
    }

    // Type check: must be an octet string.
    let ikm_bytes = value.as_bytes().ok_or_else(|| {
        warn!(
            param = PARAM_IKME,
            actual_type = value.param_type_name(),
            "ikmE parameter has wrong type"
        );
        ProviderError::Dispatch(format!(
            "ML-KEM param '{PARAM_IKME}' must be an OctetString, got {}",
            value.param_type_name()
        ))
    })?;

    // Length check: must be exactly ML_KEM_RANDOM_BYTES (32) — matches
    // C check at lines 219–223 emitting PROV_R_INVALID_SEED_LENGTH.
    if ikm_bytes.len() != ML_KEM_RANDOM_BYTES {
        warn!(
            param = PARAM_IKME,
            actual = ikm_bytes.len(),
            expected = ML_KEM_RANDOM_BYTES,
            "ikmE parameter has wrong length"
        );
        return Err(ProviderError::Dispatch(format!(
            "ML-KEM param '{PARAM_IKME}' must be exactly {} bytes (got {})",
            ML_KEM_RANDOM_BYTES,
            ikm_bytes.len()
        )));
    }

    // Wipe any previously-set buffer before replacing.
    if let Some(ref mut prev) = ctx.entropy {
        prev.zeroize();
    }
    ctx.entropy = Some(ikm_bytes.to_vec());
    trace!(
        len = ikm_bytes.len(),
        "apply_ikme_param: ikmE entropy stored"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// MlKemContext — operational methods
// -----------------------------------------------------------------------------

impl MlKemContext {
    /// Initialises the context for an encapsulation operation with the
    /// given encoded public key.
    ///
    /// Replaces C `ml_kem_encapsulate_init` (lines 83–102) and the
    /// shared `ml_kem_init` helper (lines 70–81).
    ///
    /// # Arguments
    ///
    /// - `pubkey_bytes` — encoded ML-KEM public key in FIPS 203 EK format.
    ///   Must be exactly [`MlKemSecurityParam::pubkey_bytes`] bytes for the
    ///   security parameter set this context is bound to.
    /// - `params` — optional parameter set; if it contains `ikmE`, the
    ///   value is validated and stored for use by the next
    ///   [`encapsulate`](Self::encapsulate) call (see [`apply_ikme_param`]).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when:
    /// - `pubkey_bytes.len()` is wrong for the variant (analogue of
    ///   `PROV_R_INVALID_KEY_LENGTH`)
    /// - The underlying [`MlKemKey::parse_pubkey`] rejects the encoded
    ///   key (e.g., malformed t̂ vector, ρ seed truncated)
    /// - The `ikmE` parameter is malformed (see [`apply_ikme_param`])
    pub fn encapsulate_init(
        &mut self,
        pubkey_bytes: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.security_param.algorithm_name(),
            pubkey_len = pubkey_bytes.len(),
            "MlKemContext::encapsulate_init"
        );

        // Reset any prior init state — match C semantics where
        // ml_kem_init unconditionally overwrites key, op, entropy.
        self.reset_for_reinit();

        // Validate length up-front for a clear error message before
        // delegating to MlKemKey::parse_pubkey (which would also catch
        // it but with a less specific error path).
        let expected = self.security_param.pubkey_bytes();
        if pubkey_bytes.len() != expected {
            warn!(
                algorithm = self.security_param.algorithm_name(),
                expected,
                actual = pubkey_bytes.len(),
                "encapsulate_init: invalid public-key length"
            );
            return Err(ProviderError::Dispatch(format!(
                "ML-KEM {}: invalid public-key length {} (expected {})",
                self.security_param.algorithm_name(),
                pubkey_bytes.len(),
                expected
            )));
        }

        // Acquire the default library context. The default LibContext is
        // a process-wide lazily-initialised singleton, so this is cheap
        // and infallible in practice.
        let libctx = LibContext::get_default();

        // Construct a fresh ML-KEM key bound to the requested variant and
        // parse the public key bytes into it. Errors from the crypto
        // crate (`CryptoError`) are mapped to provider-level errors via
        // `dispatch_err`.
        let mut key =
            MlKemKey::new(libctx, self.security_param.to_variant()).map_err(dispatch_err)?;
        key.parse_pubkey(pubkey_bytes).map_err(dispatch_err)?;

        // Sanity check — mirror C `if (!ossl_ml_kem_have_pubkey(key))`
        // (lines 92–97) emitting PROV_R_MISSING_KEY.
        if !key.have_pubkey() {
            warn!(
                algorithm = self.security_param.algorithm_name(),
                "encapsulate_init: parse_pubkey succeeded but have_pubkey() is false"
            );
            return Err(ProviderError::Dispatch(
                "ML-KEM encapsulate_init: missing public key after parse".to_string(),
            ));
        }

        // Commit state.
        self.key = Some(key);
        self.op = Some(MlKemOperation::Encapsulate);

        // Apply optional parameters (in particular, the deterministic
        // `ikmE` seed). Must come AFTER setting `self.op` because
        // `apply_ikme_param` only stores the parameter when in encap mode.
        if let Some(p) = params {
            apply_ikme_param(self, p)?;
        }

        trace!(
            algorithm = self.security_param.algorithm_name(),
            entropy_set = self.entropy.is_some(),
            "encapsulate_init: complete"
        );
        Ok(())
    }

    /// Initialises the context for a decapsulation operation with the
    /// given encoded private key.
    ///
    /// Replaces C `ml_kem_decapsulate_init` (lines 104–122) and the
    /// shared `ml_kem_init` helper (lines 70–81).
    ///
    /// # Arguments
    ///
    /// - `prvkey_bytes` — encoded ML-KEM private key in FIPS 203 DK format.
    ///   Must be exactly [`MlKemSecurityParam::prvkey_bytes`] bytes for the
    ///   security parameter set.
    /// - `params` — optional parameter set; for decapsulation the only
    ///   recognised parameter is `ikmE`, but it is silently ignored
    ///   when not in encap mode (matching the C gating).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when:
    /// - `prvkey_bytes.len()` is wrong for the variant
    /// - The underlying [`MlKemKey::parse_prvkey`] rejects the encoded
    ///   key (e.g., the embedded `H(ek)` does not match the recomputed
    ///   public-key hash, indicating tamper or corruption)
    pub fn decapsulate_init(
        &mut self,
        prvkey_bytes: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        debug!(
            algorithm = self.security_param.algorithm_name(),
            prvkey_len = prvkey_bytes.len(),
            "MlKemContext::decapsulate_init"
        );

        self.reset_for_reinit();

        let expected = self.security_param.prvkey_bytes();
        if prvkey_bytes.len() != expected {
            warn!(
                algorithm = self.security_param.algorithm_name(),
                expected,
                actual = prvkey_bytes.len(),
                "decapsulate_init: invalid private-key length"
            );
            return Err(ProviderError::Dispatch(format!(
                "ML-KEM {}: invalid private-key length {} (expected {})",
                self.security_param.algorithm_name(),
                prvkey_bytes.len(),
                expected
            )));
        }

        let libctx = LibContext::get_default();
        let mut key =
            MlKemKey::new(libctx, self.security_param.to_variant()).map_err(dispatch_err)?;
        key.parse_prvkey(prvkey_bytes).map_err(dispatch_err)?;

        // Sanity check — mirror C `if (!ossl_ml_kem_have_prvkey(key))`
        // (lines 113–117) emitting PROV_R_MISSING_KEY.
        if !key.have_prvkey() {
            warn!(
                algorithm = self.security_param.algorithm_name(),
                "decapsulate_init: parse_prvkey succeeded but have_prvkey() is false"
            );
            return Err(ProviderError::Dispatch(
                "ML-KEM decapsulate_init: missing private key after parse".to_string(),
            ));
        }

        self.key = Some(key);
        self.op = Some(MlKemOperation::Decapsulate);

        // Apply parameters; in decap mode `apply_ikme_param` will silently
        // ignore the `ikmE` value.
        if let Some(p) = params {
            apply_ikme_param(self, p)?;
        }

        trace!(
            algorithm = self.security_param.algorithm_name(),
            "decapsulate_init: complete"
        );
        Ok(())
    }

    /// Performs ML-KEM encapsulation, returning a tuple of
    /// `(ciphertext, shared_secret)`.
    ///
    /// Replaces C `ml_kem_encapsulate` (lines 124–173).
    ///
    /// If a deterministic `ikmE` seed has been set via
    /// [`set_params`](Self::set_params) since the last operation, the
    /// internal `encap_seed` primitive is used and the seed is wiped
    /// immediately afterwards (one-shot semantics matching the C source's
    /// `OPENSSL_cleanse(ctx->entropy)` at lines 211–215). Otherwise the
    /// randomised `encap_rand` primitive (which samples 32 bytes from
    /// `OsRng` internally) is used.
    ///
    /// The shared-secret element of the returned tuple is always exactly
    /// 32 bytes long (FIPS 203 §6.2 — `ML-KEM.SharedSecret_Bytes = 32`).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when:
    /// - The context has not been initialised for encapsulation (i.e.,
    ///   `encapsulate_init` was not called) — analogue of C
    ///   `PROV_R_OPERATION_NOT_INITIALIZED`.
    /// - The internal `encap_seed`/`encap_rand` primitive fails (which
    ///   only occurs if internal hashing fails, an essentially impossible
    ///   condition for SHA-3).
    pub fn encapsulate(&mut self) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
        debug!(
            algorithm = self.security_param.algorithm_name(),
            entropy_set = self.entropy.is_some(),
            "MlKemContext::encapsulate"
        );

        // Validate operation tag — analogue of C check at line 134
        // emitting PROV_R_OPERATION_NOT_INITIALIZED.
        match self.op {
            Some(MlKemOperation::Encapsulate) => {}
            Some(other) => {
                warn!(
                    current_op = other.as_str(),
                    "encapsulate called in wrong mode"
                );
                return Err(ProviderError::Dispatch(format!(
                    "ML-KEM encapsulate called while context is in {} mode",
                    other.as_str()
                )));
            }
            None => {
                warn!("encapsulate called before encapsulate_init");
                return Err(ProviderError::Dispatch(
                    "ML-KEM encapsulate called before encapsulate_init".to_string(),
                ));
            }
        }

        // Validate key state.
        let key = self.key.as_ref().ok_or_else(|| {
            warn!("encapsulate: key missing despite Encapsulate op");
            ProviderError::Dispatch(
                "ML-KEM encapsulate: no public key loaded into context".to_string(),
            )
        })?;
        if !key.have_pubkey() {
            warn!("encapsulate: have_pubkey() is false");
            return Err(ProviderError::Dispatch(
                "ML-KEM encapsulate: context key has no public component".to_string(),
            ));
        }

        // Branch on entropy presence.
        let result = if let Some(entropy_vec) = self.entropy.as_ref() {
            // Deterministic encapsulation path (C lines 153–157).
            //
            // Validate length one more time — defence in depth: the
            // length was already validated in `apply_ikme_param`, but
            // entropy could in principle be set via direct field access
            // in tests. Keep the check to make the invariant local.
            if entropy_vec.len() != ML_KEM_RANDOM_BYTES {
                return Err(ProviderError::Dispatch(format!(
                    "ML-KEM encapsulate: ikmE buffer has wrong length {} (expected {})",
                    entropy_vec.len(),
                    ML_KEM_RANDOM_BYTES
                )));
            }

            // The crypto-crate primitive expects a fixed-size array; copy
            // the bytes into a stack-allocated array so we can pass a
            // borrow. The local copy is zeroised after use to avoid
            // leaving entropy on the stack (Rule R8 — secure-memory
            // hygiene).
            let mut entropy_arr = [0u8; ML_KEM_RANDOM_BYTES];
            entropy_arr.copy_from_slice(entropy_vec.as_slice());

            trace!("encapsulate: using deterministic ikmE");
            let res = crypto_ml_kem::encap_seed(key, &entropy_arr).map_err(dispatch_err);
            entropy_arr.zeroize();
            res?
        } else {
            // Randomised encapsulation path (C lines 158–162).
            trace!("encapsulate: using OsRng entropy");
            crypto_ml_kem::encap_rand(key).map_err(dispatch_err)?
        };

        // Always zeroise the entropy buffer after use — one-shot
        // semantics matching C lines 211–215.
        self.clear_entropy();

        let (ciphertext, shared_secret_arr) = result;
        // Convert the fixed-size shared-secret array into a `Vec<u8>` to
        // match the trait return type. We use `to_vec()` rather than
        // `Vec::from(arr)` because `to_vec` is defined on `[u8]` slices.
        let shared_secret = shared_secret_arr.to_vec();

        debug!(
            algorithm = self.security_param.algorithm_name(),
            ctext_len = ciphertext.len(),
            ss_len = shared_secret.len(),
            "encapsulate: complete"
        );
        Ok((ciphertext, shared_secret))
    }

    /// Performs ML-KEM decapsulation on the given ciphertext, returning
    /// the 32-byte shared secret.
    ///
    /// Replaces C `ml_kem_decapsulate` (lines 175–204). The underlying
    /// [`crypto_ml_kem::decap`] runs the FIPS 203 Algorithm 18
    /// re-encapsulation check in **constant time** — no timing or
    /// branching side channel is introduced by this wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when:
    /// - The context has not been initialised for decapsulation
    /// - `ciphertext.len()` does not match
    ///   [`MlKemKey::ctext_len`] for the loaded key (analogue of
    ///   `PROV_R_BAD_LENGTH`)
    /// - The internal `decap` primitive fails (essentially impossible
    ///   for valid keys; the FO check returns the implicit-rejection
    ///   secret rather than an error for tampered ciphertexts)
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> ProviderResult<Vec<u8>> {
        debug!(
            algorithm = self.security_param.algorithm_name(),
            ctext_len = ciphertext.len(),
            "MlKemContext::decapsulate"
        );

        match self.op {
            Some(MlKemOperation::Decapsulate) => {}
            Some(other) => {
                warn!(
                    current_op = other.as_str(),
                    "decapsulate called in wrong mode"
                );
                return Err(ProviderError::Dispatch(format!(
                    "ML-KEM decapsulate called while context is in {} mode",
                    other.as_str()
                )));
            }
            None => {
                warn!("decapsulate called before decapsulate_init");
                return Err(ProviderError::Dispatch(
                    "ML-KEM decapsulate called before decapsulate_init".to_string(),
                ));
            }
        }

        let key = self.key.as_ref().ok_or_else(|| {
            warn!("decapsulate: key missing despite Decapsulate op");
            ProviderError::Dispatch(
                "ML-KEM decapsulate: no private key loaded into context".to_string(),
            )
        })?;
        if !key.have_prvkey() {
            warn!("decapsulate: have_prvkey() is false");
            return Err(ProviderError::Dispatch(
                "ML-KEM decapsulate: context key has no private component".to_string(),
            ));
        }

        // Pre-validate ciphertext length for a clear, provider-shaped
        // error before delegating to the crypto crate (which would also
        // catch it but as `CryptoError::Encoding`).
        let expected_ctext = key.ctext_len();
        if ciphertext.len() != expected_ctext {
            warn!(
                expected = expected_ctext,
                actual = ciphertext.len(),
                "decapsulate: invalid ciphertext length"
            );
            return Err(ProviderError::Dispatch(format!(
                "ML-KEM decapsulate: invalid ciphertext length {} (expected {})",
                ciphertext.len(),
                expected_ctext
            )));
        }

        let shared_arr = crypto_ml_kem::decap(key, ciphertext).map_err(dispatch_err)?;
        let shared_secret = shared_arr.to_vec();

        debug!(
            algorithm = self.security_param.algorithm_name(),
            ss_len = shared_secret.len(),
            "decapsulate: complete"
        );
        Ok(shared_secret)
    }

    /// Sets context parameters from a typed [`ParamSet`].
    ///
    /// Replaces C `ml_kem_set_ctx_params` (lines 206–238). The only
    /// recognised parameter for ML-KEM is `ikmE`
    /// ([`OSSL_KEM_PARAM_IKME`](PARAM_IKME)) — see [`apply_ikme_param`]
    /// for validation rules.
    ///
    /// Calling this method with an empty [`ParamSet`] (or one that
    /// contains no `ikmE` entry) is a no-op and returns `Ok(())`,
    /// matching the C source's `if (params == NULL) return 1` short-circuit.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Dispatch`] when the `ikmE` parameter is
    /// present but malformed (wrong type or wrong length).
    pub fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        trace!(param_count = params.len(), "MlKemContext::set_params");
        apply_ikme_param(self, params)
    }

    /// Retrieves context parameters as a typed [`ParamSet`].
    ///
    /// ML-KEM exposes no gettable context parameters (the C dispatch
    /// table at lines 256–266 omits `OSSL_FUNC_KEM_GET_CTX_PARAMS`), so
    /// this method always returns an empty [`ParamSet`].
    ///
    /// # Errors
    ///
    /// Currently infallible (returns `Ok(...)` always). The
    /// `ProviderResult` wrapping matches the trait signature and reserves
    /// space for future gettable parameters.
    pub fn get_params(&self) -> ProviderResult<ParamSet> {
        trace!("MlKemContext::get_params (no gettable params)");
        Ok(ParamSet::new())
    }
}

// -----------------------------------------------------------------------------
// Trait implementations
// -----------------------------------------------------------------------------

impl KemProvider for MlKem {
    /// Returns the canonical algorithm name (e.g. `"ML-KEM-768"`).
    fn name(&self) -> &'static str {
        self.security_param.algorithm_name()
    }

    /// Constructs a fresh [`MlKemContext`] boxed as a `dyn KemContext`
    /// trait object so it can participate in dynamic dispatch through
    /// the provider's method store.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KemContext>> {
        debug!(
            algorithm = self.security_param.algorithm_name(),
            "MlKem::new_ctx (KemProvider trait)"
        );
        let ctx = MlKemContext::new(self.security_param)?;
        Ok(Box::new(ctx))
    }
}

impl KemContext for MlKemContext {
    fn encapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        Self::encapsulate_init(self, key, params)
    }

    fn encapsulate(&mut self) -> ProviderResult<(Vec<u8>, Vec<u8>)> {
        Self::encapsulate(self)
    }

    fn decapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        Self::decapsulate_init(self, key, params)
    }

    fn decapsulate(&mut self, ciphertext: &[u8]) -> ProviderResult<Vec<u8>> {
        Self::decapsulate(self, ciphertext)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Self::get_params(self)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        Self::set_params(self, params)
    }
}

// -----------------------------------------------------------------------------
// Algorithm descriptors
// -----------------------------------------------------------------------------

/// Returns the [`AlgorithmDescriptor`] entries for all three ML-KEM
/// security parameter sets, registered for the `default` provider.
///
/// Replaces the C dispatch-table registration block at
/// `providers/implementations/kem/ml_kem_kem.c` lines 256–266 (the
/// `ossl_ml_kem_asym_kem_functions` table) and the algorithm-name
/// registrations in the default provider's `OSSL_ALGORITHM` array
/// (`providers/defltprov.c` — three entries: `ML-KEM-512`, `ML-KEM-768`,
/// `ML-KEM-1024`).
///
/// The returned descriptors carry:
/// - **`names`** — the canonical algorithm name (single-element vector;
///   ML-KEM aliases are intentionally not exposed because FIPS 203
///   defines exactly one canonical name per parameter set).
/// - **`property`** — `"provider=default"` so the dispatch core selects
///   these entries when no explicit property query is supplied.
/// - **`description`** — a short human-readable description suitable for
///   `openssl list -kem-algorithms` output.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec![MlKemSecurityParam::MlKem512.algorithm_name()],
            property: "provider=default",
            description: MlKemSecurityParam::MlKem512.description(),
        },
        AlgorithmDescriptor {
            names: vec![MlKemSecurityParam::MlKem768.algorithm_name()],
            property: "provider=default",
            description: MlKemSecurityParam::MlKem768.description(),
        },
        AlgorithmDescriptor {
            names: vec![MlKemSecurityParam::MlKem1024.algorithm_name()],
            property: "provider=default",
            description: MlKemSecurityParam::MlKem1024.description(),
        },
    ]
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for the ML-KEM provider implementation.
    //!
    //! Coverage targets:
    //! - Type-level invariants (security-param enum mappings, byte sizes)
    //! - Context lifecycle (new / reset / drop)
    //! - Parameter handling (`ikmE` validation: type, length, mode-gating)
    //! - Init-mode gating (encapsulate before init / decapsulate before init
    //!   / cross-mode misuse)
    //! - Round-trip encapsulation/decapsulation for all three variants
    //! - Deterministic encapsulation via `ikmE` produces stable output
    //! - Entropy is wiped after each `encapsulate()` call (one-shot)
    //! - Trait-object dispatch via [`KemProvider`] / [`KemContext`]

    use super::*;
    use openssl_common::ParamBuilder;
    use openssl_crypto::context::LibContext;
    use openssl_crypto::pqc::ml_kem::{self as crypto_ml_kem, MlKemVariant, SHARED_SECRET_BYTES};
    use std::sync::Arc;

    /// Helper to generate a fresh `(public_key_bytes, private_key_bytes)`
    /// pair for the requested variant, using the underlying crypto crate's
    /// `generate()` keygen primitive (OS-randomised when no seed is
    /// supplied).
    fn generate_keypair(variant: MlKemVariant) -> (Vec<u8>, Vec<u8>) {
        let libctx: Arc<LibContext> = LibContext::get_default();
        let key = crypto_ml_kem::generate(libctx, variant, None)
            .expect("ML-KEM keygen should succeed in tests");
        let pub_bytes = key
            .encode_pubkey()
            .expect("ML-KEM encode_pubkey should succeed in tests");
        let prv_bytes = key
            .encode_prvkey()
            .expect("ML-KEM encode_prvkey should succeed in tests");
        (pub_bytes, prv_bytes)
    }

    // --- Type-level invariants ----------------------------------------------

    #[test]
    fn algorithm_names_match_fips_203() {
        assert_eq!(MlKemSecurityParam::MlKem512.algorithm_name(), "ML-KEM-512");
        assert_eq!(MlKemSecurityParam::MlKem768.algorithm_name(), "ML-KEM-768");
        assert_eq!(
            MlKemSecurityParam::MlKem1024.algorithm_name(),
            "ML-KEM-1024"
        );
    }

    #[test]
    fn pubkey_byte_sizes_match_fips_203() {
        assert_eq!(MlKemSecurityParam::MlKem512.pubkey_bytes(), 800);
        assert_eq!(MlKemSecurityParam::MlKem768.pubkey_bytes(), 1184);
        assert_eq!(MlKemSecurityParam::MlKem1024.pubkey_bytes(), 1568);
    }

    #[test]
    fn prvkey_byte_sizes_match_fips_203() {
        assert_eq!(MlKemSecurityParam::MlKem512.prvkey_bytes(), 1632);
        assert_eq!(MlKemSecurityParam::MlKem768.prvkey_bytes(), 2400);
        assert_eq!(MlKemSecurityParam::MlKem1024.prvkey_bytes(), 3168);
    }

    #[test]
    fn variant_mapping_is_bijective() {
        assert_eq!(
            MlKemSecurityParam::MlKem512.to_variant(),
            MlKemVariant::MlKem512
        );
        assert_eq!(
            MlKemSecurityParam::MlKem768.to_variant(),
            MlKemVariant::MlKem768
        );
        assert_eq!(
            MlKemSecurityParam::MlKem1024.to_variant(),
            MlKemVariant::MlKem1024
        );
    }

    #[test]
    fn ml_kem_random_bytes_is_32() {
        assert_eq!(ML_KEM_RANDOM_BYTES, 32);
    }

    // --- Provider factory ---------------------------------------------------

    #[test]
    fn provider_name_matches_security_param() {
        let p512 = MlKem::new_512();
        let p768 = MlKem::new_768();
        let p1024 = MlKem::new_1024();
        assert_eq!(p512.name(), "ML-KEM-512");
        assert_eq!(p768.name(), "ML-KEM-768");
        assert_eq!(p1024.name(), "ML-KEM-1024");
    }

    #[test]
    fn provider_new_ctx_yields_uninitialised_context() {
        let provider = MlKem::new_512();
        let ctx = provider.new_ctx().expect("new_ctx must succeed");
        assert_eq!(ctx.security_param(), MlKemSecurityParam::MlKem512);
        assert!(!ctx.has_key());
        assert!(!ctx.has_entropy());
        assert_eq!(ctx.op(), None);
    }

    // --- Trait object dispatch ----------------------------------------------

    #[test]
    fn trait_object_dispatch_works() {
        let provider: Box<dyn KemProvider> = Box::new(MlKem::new_768());
        assert_eq!(provider.name(), "ML-KEM-768");
        let _boxed_ctx: Box<dyn KemContext> = provider.new_ctx().expect("new_ctx");
    }

    // --- Init-mode gating ---------------------------------------------------

    #[test]
    fn encapsulate_before_init_fails() {
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        let result = ctx.encapsulate();
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn decapsulate_before_init_fails() {
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        let result = ctx.decapsulate(&[0u8; 768]);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn encapsulate_after_decap_init_fails() {
        let (_pub_bytes, prv_bytes) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.decapsulate_init(&prv_bytes, None)
            .expect("decap_init should succeed");
        // Trying to encapsulate while in decap mode must fail.
        let result = ctx.encapsulate();
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    // --- Length validation --------------------------------------------------

    #[test]
    fn encapsulate_init_rejects_short_pubkey() {
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        let bad = vec![0u8; 100]; // way too short
        let result = ctx.encapsulate_init(&bad, None);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn decapsulate_init_rejects_short_prvkey() {
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem768).expect("new");
        let bad = vec![0u8; 50];
        let result = ctx.decapsulate_init(&bad, None);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn decapsulate_rejects_wrong_length_ctext() {
        let (_pub_bytes, prv_bytes) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.decapsulate_init(&prv_bytes, None).expect("decap_init");
        let bad_ctext = vec![0u8; 99];
        let result = ctx.decapsulate(&bad_ctext);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    // --- Parameter handling: ikmE ------------------------------------------

    #[test]
    fn ikme_param_wrong_length_is_rejected() {
        let (pub_bytes, _) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.encapsulate_init(&pub_bytes, None).expect("encap_init");
        // Build a ParamSet with ikmE of wrong length (16 instead of 32).
        let params = ParamBuilder::new()
            .push_octet(PARAM_IKME, vec![0u8; 16])
            .build();
        let result = ctx.set_params(&params);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn ikme_param_wrong_type_is_rejected() {
        let (pub_bytes, _) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.encapsulate_init(&pub_bytes, None).expect("encap_init");
        let params = ParamBuilder::new()
            .push_utf8(PARAM_IKME, "not bytes".to_string())
            .build();
        let result = ctx.set_params(&params);
        assert!(matches!(result, Err(ProviderError::Dispatch(_))));
    }

    #[test]
    fn ikme_param_correct_length_is_accepted() {
        let (pub_bytes, _) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.encapsulate_init(&pub_bytes, None).expect("encap_init");
        let seed = vec![0xA5u8; ML_KEM_RANDOM_BYTES];
        let params = ParamBuilder::new().push_octet(PARAM_IKME, seed).build();
        ctx.set_params(&params)
            .expect("set_params should accept 32-byte ikmE");
        assert!(ctx.has_entropy());
    }

    #[test]
    fn ikme_param_in_decap_mode_is_silently_ignored() {
        let (_pub_bytes, prv_bytes) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.decapsulate_init(&prv_bytes, None).expect("decap_init");
        // Even a wrong-length ikmE must NOT raise an error in decap mode
        // — the parameter is meant for encapsulation only.
        let params = ParamBuilder::new()
            .push_octet(PARAM_IKME, vec![0u8; 7])
            .build();
        let result = ctx.set_params(&params);
        assert!(result.is_ok(), "ikmE in decap mode should be a no-op");
        assert!(!ctx.has_entropy());
    }

    #[test]
    fn ikme_param_via_init_path_is_accepted() {
        let (pub_bytes, _) = generate_keypair(MlKemVariant::MlKem512);
        let seed = vec![0x11u8; ML_KEM_RANDOM_BYTES];
        let params = ParamBuilder::new().push_octet(PARAM_IKME, seed).build();
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.encapsulate_init(&pub_bytes, Some(&params))
            .expect("encap_init with ikmE should succeed");
        assert!(ctx.has_entropy());
    }

    // --- One-shot entropy semantics ----------------------------------------

    #[test]
    fn entropy_is_wiped_after_encapsulate() {
        let (pub_bytes, _) = generate_keypair(MlKemVariant::MlKem512);
        let seed = vec![0x42u8; ML_KEM_RANDOM_BYTES];
        let params = ParamBuilder::new().push_octet(PARAM_IKME, seed).build();
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx.encapsulate_init(&pub_bytes, Some(&params))
            .expect("encap_init");
        assert!(ctx.has_entropy());
        let _ = ctx.encapsulate().expect("encapsulate should succeed");
        assert!(
            !ctx.has_entropy(),
            "entropy must be wiped after encapsulate (one-shot semantics)"
        );
    }

    // --- Round-trip tests for all three variants ---------------------------

    fn roundtrip_test(security_param: MlKemSecurityParam) {
        let variant = security_param.to_variant();
        let (pub_bytes, prv_bytes) = generate_keypair(variant);

        // Encapsulate
        let mut enc_ctx = MlKemContext::new(security_param).expect("new enc");
        enc_ctx
            .encapsulate_init(&pub_bytes, None)
            .expect("encap_init");
        let (ciphertext, shared_secret_a) =
            enc_ctx.encapsulate().expect("encapsulate should succeed");

        assert_eq!(
            shared_secret_a.len(),
            SHARED_SECRET_BYTES,
            "shared secret must be 32 bytes per FIPS 203"
        );

        // Decapsulate
        let mut dec_ctx = MlKemContext::new(security_param).expect("new dec");
        dec_ctx
            .decapsulate_init(&prv_bytes, None)
            .expect("decap_init");
        let shared_secret_b = dec_ctx
            .decapsulate(&ciphertext)
            .expect("decapsulate should succeed");

        assert_eq!(
            shared_secret_a,
            shared_secret_b,
            "encapsulated and decapsulated shared secrets must match for {}",
            security_param.algorithm_name()
        );
    }

    #[test]
    fn roundtrip_ml_kem_512() {
        roundtrip_test(MlKemSecurityParam::MlKem512);
    }

    #[test]
    fn roundtrip_ml_kem_768() {
        roundtrip_test(MlKemSecurityParam::MlKem768);
    }

    #[test]
    fn roundtrip_ml_kem_1024() {
        roundtrip_test(MlKemSecurityParam::MlKem1024);
    }

    // --- Determinism: same ikmE → same (ciphertext, shared_secret) ---------

    #[test]
    fn deterministic_encapsulation_is_stable() {
        let (pub_bytes, _) = generate_keypair(MlKemVariant::MlKem512);
        let seed = vec![0x7Eu8; ML_KEM_RANDOM_BYTES];
        let params = ParamBuilder::new()
            .push_octet(PARAM_IKME, seed.clone())
            .build();

        // First encapsulation.
        let mut ctx1 = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx1.encapsulate_init(&pub_bytes, Some(&params))
            .expect("encap_init");
        let (ct1, ss1) = ctx1.encapsulate().expect("encap1");

        // Second encapsulation with the SAME seed and SAME public key
        // must yield byte-identical outputs (FIPS 203 ML-KEM is
        // deterministic given fixed entropy).
        let params2 = ParamBuilder::new().push_octet(PARAM_IKME, seed).build();
        let mut ctx2 = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        ctx2.encapsulate_init(&pub_bytes, Some(&params2))
            .expect("encap_init");
        let (ct2, ss2) = ctx2.encapsulate().expect("encap2");

        assert_eq!(ct1, ct2, "deterministic ciphertexts must match");
        assert_eq!(ss1, ss2, "deterministic shared secrets must match");
    }

    // --- get_params returns empty -----------------------------------------

    #[test]
    fn get_params_returns_empty() {
        let ctx = MlKemContext::new(MlKemSecurityParam::MlKem768).expect("new");
        let params = ctx.get_params().expect("get_params should succeed");
        assert!(params.is_empty());
    }

    // --- descriptors() ------------------------------------------------------

    #[test]
    fn descriptors_return_three_entries() {
        let descs = descriptors();
        assert_eq!(descs.len(), 3, "three ML-KEM variants must be registered");
        let names: Vec<_> = descs.iter().flat_map(|d| d.names.iter().copied()).collect();
        assert!(names.contains(&"ML-KEM-512"));
        assert!(names.contains(&"ML-KEM-768"));
        assert!(names.contains(&"ML-KEM-1024"));
        for d in &descs {
            assert_eq!(d.property, "provider=default");
            assert!(!d.description.is_empty());
        }
    }

    // --- Reset behaviour ---------------------------------------------------

    #[test]
    fn re_init_clears_previous_state() {
        let (pub_bytes, prv_bytes) = generate_keypair(MlKemVariant::MlKem512);
        let mut ctx = MlKemContext::new(MlKemSecurityParam::MlKem512).expect("new");
        // First, init for encapsulation with an ikmE seed.
        let params = ParamBuilder::new()
            .push_octet(PARAM_IKME, vec![0u8; 32])
            .build();
        ctx.encapsulate_init(&pub_bytes, Some(&params))
            .expect("encap_init");
        assert!(ctx.has_entropy());
        assert_eq!(ctx.op(), Some(MlKemOperation::Encapsulate));

        // Re-init for decapsulation: must clear entropy and switch op.
        ctx.decapsulate_init(&prv_bytes, None).expect("decap_init");
        assert!(!ctx.has_entropy(), "re-init must wipe entropy");
        assert_eq!(ctx.op(), Some(MlKemOperation::Decapsulate));
    }
}
