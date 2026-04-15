//! FIPS approved service indicator mechanism.
//!
//! Implements the per-algorithm-context approved/unapproved tracking with
//! configurable strict/tolerant enforcement modes. Each algorithm context
//! embeds a [`FipsIndicator`] that starts approved and may transition to
//! unapproved based on FIPS compliance checks (key size, digest strength,
//! curve approval, etc.).
//!
//! # Architecture
//!
//! The indicator follows a monotonic state transition model:
//! - An indicator starts as **approved** (`approved = true`).
//! - When a FIPS compliance check fails, [`FipsIndicator::on_unapproved`]
//!   permanently sets `approved = false`. This transition is irreversible
//!   for the lifetime of the algorithm context.
//! - Each indicator has up to [`SETTABLE_MAX`] (8) configurable enforcement
//!   slots, each of which can be independently set to [`SettableState::Strict`]
//!   or [`SettableState::Tolerant`] to control whether violations cause errors
//!   or merely warnings.
//!
//! # Enforcement Precedence
//!
//! When a FIPS check fails and [`FipsIndicator::on_unapproved`] is called:
//! 1. If the per-slot settable state is `Tolerant`, the operation proceeds
//!    (via the indicator callback).
//! 2. Otherwise, if the global configuration check returns tolerant (false),
//!    the operation also proceeds via the callback.
//! 3. If both the settable state and the config check indicate strict mode,
//!    the operation is rejected with [`FipsError::NotApproved`].
//!
//! # Translation Notes
//!
//! Translates C `providers/fips/fipsindicator.c` (129 lines) and
//! `providers/fips/include/fips/fipsindicator.h` (165 lines) into
//! idiomatic Rust with typed enums replacing integer sentinel values.

use std::fmt;

use tracing::{debug, warn};

use openssl_common::error::{CommonError, FipsError, FipsResult};
use openssl_common::param::{ParamSet, ParamValue};

// ---------------------------------------------------------------------------
// Well-known NID constants (local copies to avoid crypto crate dependency)
// ---------------------------------------------------------------------------

/// Undefined NID — indicates no algorithm selected.
const NID_UNDEF: i32 = 0;

/// SHA-1 NID — conditionally approved for signatures.
const NID_SHA1: i32 = 64;

/// SHA-512/224 NID — truncated SHA-512 variant.
const NID_SHA512_224: i32 = 1094;

/// SHA-512/256 NID — truncated SHA-512 variant.
const NID_SHA512_256: i32 = 1095;

// ---------------------------------------------------------------------------
// FIPS RSA key-size thresholds (SP 800-131A Rev. 2)
// ---------------------------------------------------------------------------

/// Minimum RSA key size (bits) for FIPS-approved protected operations.
const FIPS_RSA_MIN_KEY_BITS_PROTECTED: u32 = 2048;

/// Minimum RSA key size (bits) for FIPS legacy verification.
const FIPS_RSA_MIN_KEY_BITS_LEGACY: u32 = 1024;

// ---------------------------------------------------------------------------
// FIPS parameter name (matches C OSSL_ALG_PARAM_FIPS_APPROVED_INDICATOR)
// ---------------------------------------------------------------------------

/// The `OSSL_PARAM` name for the FIPS approved indicator flag.
/// Corresponds to `OSSL_ALG_PARAM_FIPS_APPROVED_INDICATOR` = `"fips-indicator"`.
const FIPS_APPROVED_INDICATOR_PARAM: &str = "fips-indicator";

// ---------------------------------------------------------------------------
// Settable constants (Phase 3 — fipsindicator.h lines 23-31)
// ---------------------------------------------------------------------------

/// Maximum number of configurable settable slots per indicator.
/// Matches C `OSSL_FIPS_IND_SETTABLE_MAX` (value 8).
pub const SETTABLE_MAX: usize = 8;

/// Settable slot index 0.
pub const SETTABLE0: usize = 0;
/// Settable slot index 1.
pub const SETTABLE1: usize = 1;
/// Settable slot index 2.
pub const SETTABLE2: usize = 2;
/// Settable slot index 3.
pub const SETTABLE3: usize = 3;
/// Settable slot index 4.
pub const SETTABLE4: usize = 4;
/// Settable slot index 5.
pub const SETTABLE5: usize = 5;
/// Settable slot index 6.
pub const SETTABLE6: usize = 6;
/// Settable slot index 7.
pub const SETTABLE7: usize = 7;

// ---------------------------------------------------------------------------
// SettableState enum (Phase 2 — fipsindicator.h lines 33-36)
// ---------------------------------------------------------------------------

/// Per-settable enforcement mode for FIPS indicator checks.
///
/// Replaces the C `OSSL_FIPS_IND_STATE_*` integer constants with a Rust enum.
///
/// **Rule R5**: The C sentinel value `-1` for UNKNOWN is replaced by the
/// explicit [`SettableState::Unknown`] variant — no integer sentinels are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettableState {
    /// Initial unknown state — not yet configured by the caller.
    /// In this state, enforcement falls through to the global configuration
    /// check to determine strict vs. tolerant behavior.
    Unknown,
    /// Strict enforcement — unapproved operations are rejected with an error.
    /// Corresponds to C `OSSL_FIPS_IND_STATE_STRICT` (value 1).
    Strict,
    /// Tolerant enforcement — unapproved operations proceed but the indicator
    /// is marked as unapproved. Corresponds to C `OSSL_FIPS_IND_STATE_TOLERANT`
    /// (value 0).
    Tolerant,
}

impl Default for SettableState {
    /// Returns [`SettableState::Unknown`] — the initial state before explicit
    /// configuration by the caller.
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for SettableState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Strict => write!(f, "Strict"),
            Self::Tolerant => write!(f, "Tolerant"),
        }
    }
}

impl SettableState {
    /// Converts a raw i32 value to a `SettableState`.
    ///
    /// - `0` → [`SettableState::Tolerant`] (matches C `OSSL_FIPS_IND_STATE_TOLERANT`)
    /// - `1` → [`SettableState::Strict`] (matches C `OSSL_FIPS_IND_STATE_STRICT`)
    /// - Any other value → [`SettableState::Unknown`]
    fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Tolerant,
            1 => Self::Strict,
            _ => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Indicator Callback type (Phase 6 — fipsindicator.c lines 119-129)
// ---------------------------------------------------------------------------

/// Callback type invoked when a FIPS indicator detects an unapproved
/// operation in tolerant mode.
///
/// The callback receives the algorithm name (e.g. `"RSA"`) and the operation
/// description (e.g. `"Key size"`). It returns `true` if the operation should
/// proceed, or `false` if it should be rejected.
///
/// Replaces C `OSSL_INDICATOR_CALLBACK` function pointer.
pub type IndicatorCheckCallback = dyn Fn(&str, &str) -> bool + Send + Sync;

// ---------------------------------------------------------------------------
// FipsIndicator struct (Phase 4 — fipsindicator.h lines 55-58)
// ---------------------------------------------------------------------------

/// FIPS approved service indicator for an algorithm context.
///
/// Tracks whether the current operation is FIPS-approved and provides
/// per-settable override slots for strict/tolerant enforcement.
///
/// # Usage
///
/// Each algorithm context (cipher, digest, MAC, KDF, signature, KEM, etc.)
/// embeds a `FipsIndicator`. It starts as approved and may be set to
/// unapproved during FIPS compliance checks. Once unapproved, it **cannot**
/// be re-approved (the `approved` flag only transitions from `true` → `false`).
///
/// # Lock Granularity (Rule R7)
///
/// `FipsIndicator` is NOT shared across threads — it is embedded per-algorithm
/// context and owned exclusively by that context. No locking is needed.
/// `// LOCK-SCOPE: none — owned by algorithm context, not shared.`
#[derive(Debug, Clone)]
pub struct FipsIndicator {
    /// Whether the operation is currently approved. Starts `true`, may become
    /// `false`. Once false, it cannot be re-approved (monotonic transition).
    approved: bool,
    /// Per-settable enforcement modes (up to [`SETTABLE_MAX`] configurable slots).
    settable: [SettableState; SETTABLE_MAX],
}

impl Default for FipsIndicator {
    fn default() -> Self {
        Self::new()
    }
}

impl FipsIndicator {
    /// Creates a new `FipsIndicator` with approved state and all settable
    /// slots initialized to [`SettableState::Unknown`].
    ///
    /// Replaces C `ossl_FIPS_IND_init()` (fipsindicator.c lines 16-23).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_fips::indicator::FipsIndicator;
    ///
    /// let ind = FipsIndicator::new();
    /// assert!(ind.is_approved());
    /// ```
    pub fn new() -> Self {
        Self {
            approved: true,
            settable: [SettableState::Unknown; SETTABLE_MAX],
        }
    }

    /// Resets the indicator to approved state.
    ///
    /// Called during initialization before algorithm parameters are set.
    /// This is the only way to transition from unapproved back to approved
    /// (typically only used at the start of a new operation context).
    ///
    /// Replaces C `ossl_FIPS_IND_set_approved()` (fipsindicator.c lines 25-28).
    pub fn set_approved(&mut self) {
        self.approved = true;
    }

    /// Returns whether the current operation is FIPS-approved.
    ///
    /// Returns `true` if no FIPS compliance violation has been detected,
    /// `false` if [`on_unapproved`](Self::on_unapproved) has been called at
    /// least once.
    pub fn is_approved(&self) -> bool {
        self.approved
    }

    /// Copies all state from `src` into `self`.
    ///
    /// Replaces C `ossl_FIPS_IND_copy()` / `OSSL_FIPS_IND_COPY` macro
    /// (fipsindicator.c lines 30-33).
    pub fn copy_from(&mut self, src: &FipsIndicator) {
        self.approved = src.approved;
        self.settable = src.settable;
    }

    /// Sets the enforcement state for the given settable slot.
    ///
    /// # Errors
    ///
    /// Returns [`FipsError::Common`] if `id >= SETTABLE_MAX` (bounds violation,
    /// Rule R6).
    ///
    /// Replaces C `ossl_FIPS_IND_set_settable()` (fipsindicator.c lines 35-43).
    pub fn set_settable(&mut self, id: usize, state: SettableState) -> FipsResult<()> {
        if id >= SETTABLE_MAX {
            return Err(FipsError::Common(CommonError::InvalidArgument(format!(
                "settable id {id} out of bounds (max {})",
                SETTABLE_MAX - 1
            ))));
        }
        debug!(id, %state, "FIPS indicator settable state changed");
        self.settable[id] = state;
        Ok(())
    }

    /// Returns the enforcement state for the given settable slot.
    ///
    /// # Errors
    ///
    /// Returns [`FipsError::Common`] if `id >= SETTABLE_MAX`.
    ///
    /// Replaces C `ossl_FIPS_IND_get_settable()` (fipsindicator.c lines 45-56).
    pub fn get_settable(&self, id: usize) -> FipsResult<SettableState> {
        if id >= SETTABLE_MAX {
            return Err(FipsError::Common(CommonError::InvalidArgument(format!(
                "settable id {id} out of bounds (max {})",
                SETTABLE_MAX - 1
            ))));
        }
        Ok(self.settable[id])
    }

    /// Handles an unapproved FIPS operation.
    ///
    /// This is the core enforcement decision point. It permanently marks the
    /// indicator as unapproved and then determines whether the operation should
    /// proceed (tolerant mode) or be rejected (strict mode).
    ///
    /// # Enforcement Logic
    ///
    /// 1. **Always** sets `self.approved = false` (monotonic, irreversible).
    /// 2. If the per-slot settable state is [`SettableState::Tolerant`], the
    ///    operation proceeds via the indicator callback.
    /// 3. Otherwise, if `config_check()` returns `false` (global config says
    ///    tolerant), the operation also proceeds via the callback.
    /// 4. If both the settable slot and the config check indicate strict mode,
    ///    the operation is rejected with [`FipsError::NotApproved`].
    ///
    /// # Parameters
    ///
    /// - `id`: Settable slot index to check (must be < `SETTABLE_MAX`).
    /// - `algname`: Algorithm name for diagnostics (e.g. `"RSA"`).
    /// - `opname`: Operation name for diagnostics (e.g. `"Key size"`).
    /// - `config_check`: Closure returning `true` if global config says strict,
    ///   `false` if tolerant.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — operation should proceed (tolerant mode, callback approved).
    /// - `Ok(false)` — callback explicitly rejected the operation.
    /// - `Err(FipsError::NotApproved)` — strict enforcement rejected the operation.
    ///
    /// Replaces C `ossl_FIPS_IND_on_unapproved()` (fipsindicator.c lines 58-78).
    pub fn on_unapproved(
        &mut self,
        id: usize,
        algname: &str,
        opname: &str,
        config_check: impl Fn() -> bool,
    ) -> FipsResult<bool> {
        // Permanently mark as unapproved — this transition is irreversible.
        // C: ind->approved = 0; (line 64)
        self.approved = false;

        let settable = self.get_settable(id)?;

        // C logic (lines 69-76):
        //   if (settable == TOLERANT || (config_fn != NULL && config_fn() == TOLERANT))
        //       return callback(algname, opname);
        //   return 0;  /* strict */
        //
        // In Rust: config_check() returns true for strict, false for tolerant.
        if settable == SettableState::Tolerant || !config_check() {
            warn!(
                algorithm = algname,
                operation = opname,
                "FIPS unapproved: {} {}",
                algname,
                opname
            );
            return Ok(invoke_callback(algname, opname));
        }

        // Strict mode: both settable and config indicate strict enforcement.
        debug!(
            algorithm = algname,
            operation = opname,
            ?settable,
            "FIPS strict enforcement: rejecting unapproved operation"
        );
        Err(FipsError::NotApproved(format!("{algname} {opname}")))
    }

    /// Sets a settable slot from a raw i32 value.
    ///
    /// Converts the integer to a [`SettableState`] and delegates to
    /// [`set_settable`](Self::set_settable).
    ///
    /// - `0` → [`SettableState::Tolerant`]
    /// - `1` → [`SettableState::Strict`]
    /// - Any other value → [`SettableState::Unknown`]
    ///
    /// Replaces C `ossl_FIPS_IND_set_ctx_param()` (fipsindicator.c lines 80-89).
    pub fn set_ctx_param(&mut self, id: usize, value: i32) -> FipsResult<()> {
        let state = SettableState::from_i32(value);
        self.set_settable(id, state)
    }

    /// Locates a named parameter in a [`ParamSet`] and uses its i32 value to
    /// set the enforcement state for the given settable slot.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the parameter was found and the settable slot was updated.
    /// - `Ok(false)` if the parameter was not found in the set (Rule R5: no
    ///   sentinel return values).
    ///
    /// Replaces C `ossl_FIPS_IND_set_ctx_param_locate()` (fipsindicator.c
    /// lines 90-99).
    pub fn set_ctx_param_by_name(
        &mut self,
        id: usize,
        params: &ParamSet,
        name: &str,
    ) -> FipsResult<bool> {
        match params.get(name) {
            Some(param_value) => {
                if let Some(int_val) = param_value.as_i32() {
                    self.set_ctx_param(id, int_val)?;
                    Ok(true)
                } else {
                    // Parameter found but not an i32 — treat as not found
                    // to match C behavior where OSSL_PARAM_get_int fails.
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    /// Returns the approved state as an i32 value.
    ///
    /// - `1` if the indicator is currently approved.
    /// - `0` if unapproved.
    ///
    /// This returns the **approved flag**, not the settable state.
    ///
    /// Replaces C `ossl_FIPS_IND_get_ctx_param()` (fipsindicator.c lines 101-112).
    pub fn get_ctx_param(&self) -> i32 {
        i32::from(self.approved)
    }

    /// Inserts the FIPS approved indicator value into a [`ParamSet`].
    ///
    /// Sets the `"fips-indicator"` parameter to the approved state as an i32.
    ///
    /// Replaces C `ossl_FIPS_IND_get_ctx_param_locate()` (fipsindicator.c
    /// lines 114-118).
    pub fn get_ctx_param_into(&self, params: &mut ParamSet) -> FipsResult<()> {
        let value = self.get_ctx_param();
        params.set(FIPS_APPROVED_INDICATOR_PARAM, ParamValue::Int32(value));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Display implementation (Phase 9)
// ---------------------------------------------------------------------------

impl fmt::Display for FipsIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FipsIndicator {{ approved: {}, settable: {:?} }}",
            self.approved, self.settable
        )
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Invokes the FIPS indicator callback for an unapproved operation.
///
/// In the current implementation, the callback infrastructure is provided via
/// structured logging (`tracing::warn!`). When no explicit callback is
/// registered, the default behavior is to proceed (`true`).
///
/// # Returns
///
/// - `true` if the operation should proceed (default behavior).
/// - `false` if a registered callback explicitly rejects the operation.
///
/// Replaces C `ossl_FIPS_IND_callback()` (fipsindicator.c lines 119-129).
pub fn invoke_callback(algname: &str, opname: &str) -> bool {
    // The C version retrieves a registered OSSL_INDICATOR_CALLBACK from the
    // library context. In the Rust architecture, callbacks are not yet wired
    // through the library context (that integration happens in openssl-crypto's
    // provider module). The default behavior when no callback is registered is
    // to return true (proceed), matching C: `if (cb == NULL) return 1;`.
    debug!(
        algorithm = algname,
        operation = opname,
        "FIPS indicator callback invoked (default: proceed)"
    );
    true
}

// ---------------------------------------------------------------------------
// Algorithm-specific check functions (Phase 7 — securitycheck_fips.c)
// ---------------------------------------------------------------------------

/// Checks RSA key size against FIPS requirements.
///
/// In protected mode (`protect = true`), the minimum key size is 2048 bits
/// (SP 800-131A Rev. 2). In non-protected mode (e.g., legacy verification),
/// the minimum is 1024 bits.
///
/// If the key size is below the applicable minimum, the indicator is
/// permanently set to unapproved and the enforcement mode determines whether
/// the operation proceeds or fails.
///
/// Replaces C `ossl_fips_ind_rsa_key_check()` (`securitycheck_fips.c` lines 36-50).
///
/// # Parameters
///
/// - `indicator`: The FIPS indicator for the current algorithm context.
/// - `id`: Settable slot index controlling enforcement for this check.
/// - `key_bits`: The RSA key size in bits.
/// - `desc`: Operation description for diagnostics (e.g. `"RSA Sign"`).
/// - `protect`: If `true`, enforces the stricter 2048-bit minimum.
///
/// # Returns
///
/// - `Ok(true)` if the key size is FIPS-approved or the check passed in
///   tolerant mode.
/// - `Err(FipsError::NotApproved)` if strict enforcement rejects the key size.
pub fn check_rsa_key(
    indicator: &mut FipsIndicator,
    id: usize,
    key_bits: u32,
    desc: &str,
    protect: bool,
) -> FipsResult<bool> {
    let min_bits = if protect {
        FIPS_RSA_MIN_KEY_BITS_PROTECTED
    } else {
        FIPS_RSA_MIN_KEY_BITS_LEGACY
    };

    let key_approved = key_bits >= min_bits;

    if !key_approved {
        // Key size below FIPS minimum — delegate to enforcement logic.
        // The default config_check closure returns true (strict) since the
        // actual FIPS configuration integration is handled at the provider level.
        let proceed = indicator.on_unapproved(id, desc, "Key size", || true)?;
        if !proceed {
            return Err(FipsError::NotApproved(format!(
                "{desc}: RSA key size {key_bits} bits below FIPS minimum {min_bits} bits"
            )));
        }
    }
    Ok(true)
}

/// Checks EC curve and key strength against FIPS requirements.
///
/// Validates that the curve NID corresponds to a FIPS-approved NIST curve
/// and that the security strength meets the minimum requirement for the
/// operation type.
///
/// Replaces C `ossl_fips_ind_ec_key_check()` (`securitycheck_fips.c` lines 52-78).
///
/// # Parameters
///
/// - `indicator`: The FIPS indicator for the current algorithm context.
/// - `id`: Settable slot index controlling enforcement for this check.
/// - `curve_nid`: The NID identifying the EC curve.
/// - `desc`: Operation description for diagnostics.
/// - `protect`: If `true`, enforces stricter security strength requirements.
///
/// # Returns
///
/// - `Ok(true)` if the curve is FIPS-approved or the check passed in tolerant
///   mode.
/// - `Err(FipsError::NotApproved)` if strict enforcement rejects the curve.
#[cfg(feature = "ec")]
pub fn check_ec_key(
    indicator: &mut FipsIndicator,
    id: usize,
    curve_nid: i32,
    desc: &str,
    protect: bool,
) -> FipsResult<bool> {
    // Check that the curve NID is defined (not NID_undef)
    let curve_allowed = curve_nid != NID_UNDEF;

    // FIPS-approved NIST curves (SP 800-186):
    //   P-224 (NID 713), P-256 (NID 415), P-384 (NID 715), P-521 (NID 716)
    // This is a simplified check — the full curve validation includes
    // explicit curve rejection and NIST name lookup.
    let strength_bits = ec_curve_security_bits(curve_nid);
    let min_strength = if protect { 112 } else { 80 };
    let strength_allowed = strength_bits >= min_strength;

    if !curve_allowed || !strength_allowed {
        let proceed = indicator.on_unapproved(id, desc, "EC Key", || true)?;
        if !proceed {
            return Err(FipsError::NotApproved(format!(
                "{desc}: EC curve NID {curve_nid} not FIPS-approved"
            )));
        }
    }
    Ok(true)
}

/// Checks digest algorithm suitability for key exchange operations.
///
/// Rejects `NID_undef` (no digest selected) and `NID_sha1` (insufficient
/// strength for key exchange) as unapproved for FIPS purposes.
///
/// Replaces C `ossl_fips_ind_digest_exch_check()` (`securitycheck_fips.c`
/// lines 80-95).
///
/// # Parameters
///
/// - `indicator`: The FIPS indicator for the current algorithm context.
/// - `id`: Settable slot index controlling enforcement.
/// - `digest_name`: The NID of the digest algorithm.
/// - `desc`: Operation description for diagnostics.
///
/// # Returns
///
/// - `Ok(true)` if the digest is approved or the check passed in tolerant mode.
/// - `Err(FipsError::NotApproved)` if strict enforcement rejects the digest.
pub fn check_digest_exchange(
    indicator: &mut FipsIndicator,
    id: usize,
    digest_name: i32,
    desc: &str,
) -> FipsResult<bool> {
    // C: approved = (nid != NID_undef && nid != NID_sha1);
    let approved = digest_name != NID_UNDEF && digest_name != NID_SHA1;

    if !approved {
        let proceed = indicator.on_unapproved(id, desc, "Digest", || true)?;
        if !proceed {
            return Err(FipsError::NotApproved(format!(
                "{desc}: digest NID {digest_name} not approved for key exchange"
            )));
        }
    }
    Ok(true)
}

/// Checks digest algorithm suitability for signature operations.
///
/// SHA-1 and truncated SHA-512 variants (SHA-512/224, SHA-512/256) are
/// conditionally approved based on caller-provided flags, allowing the
/// provider to control approval policy per algorithm context.
///
/// Replaces C `ossl_fips_ind_digest_sign_check()` (`securitycheck_fips.c`
/// lines 97-132).
///
/// # Parameters
///
/// - `indicator`: The FIPS indicator for the current algorithm context.
/// - `id`: Settable slot index controlling enforcement.
/// - `nid`: The NID of the digest algorithm.
/// - `sha1_allowed`: Whether SHA-1 is allowed for this specific operation.
/// - `sha512_trunc_allowed`: Whether SHA-512/224 and SHA-512/256 are allowed.
/// - `desc`: Operation description for diagnostics.
/// - `config_check`: Closure returning `true` for strict, `false` for tolerant.
///
/// # Returns
///
/// - `Ok(true)` if the digest is approved or the check passed in tolerant mode.
/// - `Err(FipsError::NotApproved)` if strict enforcement rejects the digest.
pub fn check_digest_sign(
    indicator: &mut FipsIndicator,
    id: usize,
    nid: i32,
    sha1_allowed: bool,
    sha512_trunc_allowed: bool,
    desc: &str,
    config_check: impl Fn() -> bool,
) -> FipsResult<bool> {
    // C logic (lines 107-126):
    //   switch (nid) {
    //     case NID_undef: approved = 0; break;
    //     case NID_sha512_224: case NID_sha512_256: approved = sha512_trunc; break;
    //     case NID_sha1: approved = sha1_allowed; break;
    //     default: approved = 1; break;
    //   }
    let (approved, opname) = match nid {
        NID_UNDEF => (false, "none"),
        NID_SHA512_224 | NID_SHA512_256 => (sha512_trunc_allowed, "Digest Truncated SHA512"),
        NID_SHA1 => (sha1_allowed, "Digest SHA1"),
        _ => (true, "Digest"),
    };

    if !approved {
        let proceed = indicator.on_unapproved(id, desc, opname, config_check)?;
        if !proceed {
            return Err(FipsError::NotApproved(format!(
                "{desc}: digest NID {nid} not approved for signing ({opname})"
            )));
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Helper: EC curve security bits lookup
// ---------------------------------------------------------------------------

/// Returns the approximate security strength (in bits) for a given EC curve NID.
///
/// This is a simplified lookup for FIPS-approved NIST curves. Unknown curves
/// return 0 bits of security, which will fail any minimum strength check.
#[cfg(feature = "ec")]
fn ec_curve_security_bits(curve_nid: i32) -> u32 {
    // Well-known NIST curve NIDs from include/openssl/obj_mac.h
    const NID_SECP224R1: i32 = 713;
    const NID_X9_62_PRIME256V1: i32 = 415;
    const NID_SECP384R1: i32 = 715;
    const NID_SECP521R1: i32 = 716;

    match curve_nid {
        NID_SECP224R1 => 112,        // P-224: 112 bits
        NID_X9_62_PRIME256V1 => 128, // P-256: 128 bits
        NID_SECP384R1 => 192,        // P-384: 192 bits
        NID_SECP521R1 => 256,        // P-521: 256 bits (approx)
        _ => 0,                      // Unknown curve: 0 bits
    }
}
