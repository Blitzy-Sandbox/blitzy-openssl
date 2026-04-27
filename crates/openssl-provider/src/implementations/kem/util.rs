//! # KEM Utilities — Shared Mode Name Mapping and Helpers
//!
//! Utility functions shared across KEM provider implementations.
//! Primary function: mapping textual KEM mode names (e.g., "dhkem") to numeric IDs.
//!
//! ## Source Translation
//!
//! Translates C `providers/implementations/kem/kem_util.c` (37 lines).
//!
//! ## C→Rust Transformations
//!
//! - `KEM_MODE_NAME` struct array → `KEM_MODES` const array of `(&str, KemMode)` tuples
//! - `ossl_eckem_modename2id()` → [`kem_modename_to_id()`] returning `Option<KemMode>`
//! - `OPENSSL_strcasecmp` → `str::eq_ignore_ascii_case`
//! - Sentinel return `KEM_MODE_UNDEFINED` → `None` (Rule R5)

use tracing::trace;

/// KEM operation mode identifier.
///
/// Replaces C `KEM_MODE_UNDEFINED`/`KEM_MODE_DHKEM` numeric constants from
/// `providers/implementations/kem/kem_util.c`. The C sentinel value
/// `KEM_MODE_UNDEFINED = 0` is replaced by `Option<KemMode>` returning `None`
/// for unrecognized modes (Rule R5: `Option` over sentinels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemMode {
    /// DHKEM mode per RFC 9180 (Hybrid Public Key Encryption).
    ///
    /// Corresponds to C `KEM_MODE_DHKEM = 1` and the mode name
    /// `OSSL_KEM_PARAM_OPERATION_DHKEM` (`"DHKEM"`).
    DhKem,
}

/// Mode name to ID mapping table.
///
/// Replaces C `KEM_MODE_NAME kem_modes[]` array (`kem_util.c` lines 22–26).
/// The C sentinel entry `{0, NULL}` is not needed — Rust slice length is
/// known at compile time.
const KEM_MODES: &[(&str, KemMode)] = &[("dhkem", KemMode::DhKem)];

/// Maps a textual KEM mode name to its [`KemMode`] enum value.
///
/// Performs case-insensitive comparison using [`str::eq_ignore_ascii_case`],
/// replacing C `OPENSSL_strcasecmp`. Returns `None` if the mode name is
/// unrecognized, replacing C's `KEM_MODE_UNDEFINED` sentinel (Rule R5:
/// `Option` over sentinels).
///
/// ## Source
///
/// Replaces C `ossl_eckem_modename2id()` (`kem_util.c` lines 28–37).
///
/// # Examples
///
/// ```
/// use openssl_provider::implementations::kem::util::{kem_modename_to_id, KemMode};
///
/// assert_eq!(kem_modename_to_id("dhkem"), Some(KemMode::DhKem));
/// assert_eq!(kem_modename_to_id("DHKEM"), Some(KemMode::DhKem));
/// assert_eq!(kem_modename_to_id("DhKem"), Some(KemMode::DhKem));
/// assert_eq!(kem_modename_to_id("unknown"), None);
/// assert_eq!(kem_modename_to_id(""), None);
/// ```
pub fn kem_modename_to_id(name: &str) -> Option<KemMode> {
    trace!(mode_name = name, "looking up KEM mode by name");
    KEM_MODES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, id)| *id)
}

/// Returns the canonical name for a [`KemMode`].
///
/// Provides the reverse mapping from mode ID to name string. The returned
/// name is lowercase, matching the canonical form used in the lookup table.
///
/// # Examples
///
/// ```
/// use openssl_provider::implementations::kem::util::{kem_mode_to_name, KemMode};
///
/// assert_eq!(kem_mode_to_name(KemMode::DhKem), "dhkem");
/// ```
pub fn kem_mode_to_name(mode: KemMode) -> &'static str {
    match mode {
        KemMode::DhKem => "dhkem",
    }
}
