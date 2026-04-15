//! DTLS-SRTP extension module — Rust rewrite of `ssl/d1_srtp.c`.
//!
//! Implements the DTLS-SRTP extension (RFC 5764) for negotiating SRTP
//! protection profiles during DTLS handshakes. Used by `WebRTC` and `VoIP`
//! applications to establish keying material for SRTP media encryption
//! through the DTLS key exchange.
//!
//! # Architecture
//!
//! This module provides the core SRTP profile type system, profile lookup,
//! and profile list parsing logic. The [`SrtpProtectionProfile`] struct and
//! [`SrtpProtectionProfileId`] enum map directly to the C
//! `SRTP_PROTECTION_PROFILE` struct and `SRTP_*` constants from
//! `include/openssl/srtp.h`.
//!
//! Profile string parsing (colon-separated profile names) rewrites the C
//! `ssl_ctx_make_profiles()` function. `SSL_CTX`/`SSL` integration functions
//! (`set_tlsext_use_srtp`, `get_srtp_profiles`, `get_selected_srtp_profile`)
//! provide the building blocks consumed by the SSL connection and context
//! types.
//!
//! # C Source Mapping
//!
//! | C Construct                        | Rust Equivalent                                 |
//! |------------------------------------|-------------------------------------------------|
//! | `SRTP_PROTECTION_PROFILE` struct   | [`SrtpProtectionProfile`]                       |
//! | `SRTP_AES128_CM_SHA1_80` etc.      | [`SrtpProtectionProfileId`] enum variants        |
//! | `srtp_known_profiles[]`            | [`KNOWN_PROFILES`] constant                     |
//! | `find_profile_by_name()` (static)  | [`find_profile_by_name()`]                      |
//! | `ssl_ctx_make_profiles()`          | [`parse_profile_list()`]                        |
//! | `SSL_CTX_set_tlsext_use_srtp()`    | [`set_tlsext_use_srtp()`]                       |
//! | `SSL_get_srtp_profiles()`          | [`get_srtp_profiles()`]                         |
//! | `SSL_get_selected_srtp_profile()`  | [`get_selected_srtp_profile()`]                 |
//!
//! # Feature Gating
//!
//! This module is gated behind the `srtp` Cargo feature flag, replacing the
//! C preprocessor guard `#ifndef OPENSSL_NO_SRTP`. When the feature is
//! disabled, no SRTP types or functions are compiled.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All possibly-absent values use `Option<T>`; no sentinels.
//! - **R6 (Lossless Casts):** `u16` profile IDs use `TryFrom`; no bare `as` casts.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks — this is NOT the FFI crate.
//! - **R9 (Warning-Free):** No `#[allow(warnings)]` or `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `openssl-ssl` lib.rs via `pub mod srtp`.
//!
//! # Examples
//!
//! ```rust
//! use openssl_ssl::srtp::{
//!     parse_profile_list, find_profile_by_name, find_profile_by_id,
//!     SrtpProtectionProfileId,
//! };
//!
//! // Parse a colon-separated profile list
//! let profiles = parse_profile_list("SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM")
//!     .expect("valid profiles");
//! assert_eq!(profiles.len(), 2);
//!
//! // Look up a profile by name
//! let profile = find_profile_by_name("SRTP_AES128_CM_SHA1_80");
//! assert!(profile.is_some());
//!
//! // Look up a profile by numeric ID
//! let profile = find_profile_by_id(0x0001);
//! assert!(profile.is_some());
//! assert_eq!(profile.unwrap().name(), "SRTP_AES128_CM_SHA1_80");
//! ```

use std::fmt;

use openssl_common::error::SslError;

// =============================================================================
// SrtpProtectionProfileId — SRTP Protection Profile Identifier Enum
// =============================================================================

/// IANA-registered SRTP protection profile identifier.
///
/// Each variant maps to a numeric identifier assigned by IANA in the
/// "DTLS-SRTP Protection Profiles" registry. These values are transmitted
/// on the wire during the DTLS-SRTP `use_srtp` extension negotiation
/// (RFC 5764 §4.1.2).
///
/// # Numeric Values
///
/// | Variant                                      | Value    | RFC / Reference    |
/// |----------------------------------------------|----------|--------------------|
/// | `Aes128CmSha1_80`                            | `0x0001` | RFC 5764           |
/// | `Aes128CmSha1_32`                            | `0x0002` | RFC 5764           |
/// | `NullHmacSha1_80`                             | `0x0005` | RFC 5764           |
/// | `NullHmacSha1_32`                             | `0x0006` | RFC 5764           |
/// | `AeadAes128Gcm`                               | `0x0007` | RFC 7714           |
/// | `AeadAes256Gcm`                               | `0x0008` | RFC 7714           |
/// | `DoubleAeadAes128GcmAeadAes128Gcm`            | `0x0009` | RFC 8723           |
/// | `DoubleAeadAes256GcmAeadAes256Gcm`            | `0x000A` | RFC 8723           |
/// | `Aria128CtrHmacSha1_80`                       | `0x000B` | RFC 8269           |
/// | `Aria128CtrHmacSha1_32`                       | `0x000C` | RFC 8269           |
/// | `Aria256CtrHmacSha1_80`                       | `0x000D` | RFC 8269           |
/// | `Aria256CtrHmacSha1_32`                       | `0x000E` | RFC 8269           |
///
/// # Lossless Conversion (Rule R6)
///
/// Conversion from `u16` uses [`TryFrom`], returning an error for
/// unrecognised values instead of using bare `as` casts. Conversion to
/// `u16` via [`as_u16()`](SrtpProtectionProfileId::as_u16) is infallible
/// since every variant maps to a known constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrtpProtectionProfileId {
    /// AES-128 Counter Mode with SHA-1 HMAC, 80-bit authentication tag.
    ///
    /// IANA value `0x0001`. Defined in RFC 5764 §4.1.2. This is the most
    /// widely deployed SRTP profile and the mandatory-to-implement profile
    /// for `WebRTC` (RFC 8827).
    Aes128CmSha1_80,

    /// AES-128 Counter Mode with SHA-1 HMAC, 32-bit authentication tag.
    ///
    /// IANA value `0x0002`. Defined in RFC 5764 §4.1.2. Uses a shorter
    /// authentication tag for reduced overhead in bandwidth-constrained
    /// environments. Not recommended for new deployments due to weaker
    /// authentication.
    Aes128CmSha1_32,

    /// NULL cipher with SHA-1 HMAC, 80-bit authentication tag.
    ///
    /// IANA value `0x0005`. Defined in RFC 5764. Provides authentication
    /// without encryption — used for debugging and environments where
    /// confidentiality is not required. **Not suitable for production.**
    NullHmacSha1_80,

    /// NULL cipher with SHA-1 HMAC, 32-bit authentication tag.
    ///
    /// IANA value `0x0006`. Defined in RFC 5764. Provides authentication
    /// without encryption with a shorter tag. **Not suitable for production.**
    NullHmacSha1_32,

    /// AEAD AES-128-GCM.
    ///
    /// IANA value `0x0007`. Defined in RFC 7714. Provides authenticated
    /// encryption using AES-128 in GCM mode. Recommended for new deployments
    /// as it provides both confidentiality and integrity in a single pass.
    AeadAes128Gcm,

    /// AEAD AES-256-GCM.
    ///
    /// IANA value `0x0008`. Defined in RFC 7714. Provides authenticated
    /// encryption using AES-256 in GCM mode for higher security margin.
    AeadAes256Gcm,

    /// Double AEAD: AES-128-GCM for both inner and outer encryption.
    ///
    /// IANA value `0x0009`. Defined in RFC 8723. Supports peering through
    /// media distribution devices (SFUs) that need to decrypt the outer
    /// layer while preserving end-to-end encryption of the inner payload.
    DoubleAeadAes128GcmAeadAes128Gcm,

    /// Double AEAD: AES-256-GCM for both inner and outer encryption.
    ///
    /// IANA value `0x000A`. Defined in RFC 8723. Higher security margin
    /// variant of the double AEAD profile.
    DoubleAeadAes256GcmAeadAes256Gcm,

    /// ARIA-128 Counter Mode with SHA-1 HMAC, 80-bit authentication tag.
    ///
    /// IANA value `0x000B`. Defined in RFC 8269. ARIA is a block cipher
    /// standardised by KISA (Korea) and adopted as a Korean national
    /// standard (KS X 1213).
    Aria128CtrHmacSha1_80,

    /// ARIA-128 Counter Mode with SHA-1 HMAC, 32-bit authentication tag.
    ///
    /// IANA value `0x000C`. Defined in RFC 8269.
    Aria128CtrHmacSha1_32,

    /// ARIA-256 Counter Mode with SHA-1 HMAC, 80-bit authentication tag.
    ///
    /// IANA value `0x000D`. Defined in RFC 8269.
    Aria256CtrHmacSha1_80,

    /// ARIA-256 Counter Mode with SHA-1 HMAC, 32-bit authentication tag.
    ///
    /// IANA value `0x000E`. Defined in RFC 8269.
    Aria256CtrHmacSha1_32,
}

impl SrtpProtectionProfileId {
    /// Returns the IANA-assigned numeric identifier for this profile.
    ///
    /// This is the value transmitted on the wire in the DTLS `use_srtp`
    /// extension (RFC 5764 §4.1.2). The conversion is infallible since
    /// every enum variant has a statically known value.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_ssl::srtp::SrtpProtectionProfileId;
    ///
    /// assert_eq!(SrtpProtectionProfileId::Aes128CmSha1_80.as_u16(), 0x0001);
    /// assert_eq!(SrtpProtectionProfileId::AeadAes128Gcm.as_u16(), 0x0007);
    /// ```
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Aes128CmSha1_80 => 0x0001,
            Self::Aes128CmSha1_32 => 0x0002,
            Self::NullHmacSha1_80 => 0x0005,
            Self::NullHmacSha1_32 => 0x0006,
            Self::AeadAes128Gcm => 0x0007,
            Self::AeadAes256Gcm => 0x0008,
            Self::DoubleAeadAes128GcmAeadAes128Gcm => 0x0009,
            Self::DoubleAeadAes256GcmAeadAes256Gcm => 0x000A,
            Self::Aria128CtrHmacSha1_80 => 0x000B,
            Self::Aria128CtrHmacSha1_32 => 0x000C,
            Self::Aria256CtrHmacSha1_80 => 0x000D,
            Self::Aria256CtrHmacSha1_32 => 0x000E,
        }
    }
}

/// Converts a `u16` wire value to an [`SrtpProtectionProfileId`].
///
/// Per **Rule R6** (lossless numeric casts), this uses `TryFrom` instead
/// of bare `as` casts. Returns an error string describing the unknown
/// value if the input does not match any IANA-registered profile.
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::SrtpProtectionProfileId;
/// use std::convert::TryFrom;
///
/// let id = SrtpProtectionProfileId::try_from(0x0007u16).unwrap();
/// assert_eq!(id, SrtpProtectionProfileId::AeadAes128Gcm);
///
/// let err = SrtpProtectionProfileId::try_from(0xFFFFu16);
/// assert!(err.is_err());
/// ```
impl TryFrom<u16> for SrtpProtectionProfileId {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Aes128CmSha1_80),
            0x0002 => Ok(Self::Aes128CmSha1_32),
            0x0005 => Ok(Self::NullHmacSha1_80),
            0x0006 => Ok(Self::NullHmacSha1_32),
            0x0007 => Ok(Self::AeadAes128Gcm),
            0x0008 => Ok(Self::AeadAes256Gcm),
            0x0009 => Ok(Self::DoubleAeadAes128GcmAeadAes128Gcm),
            0x000A => Ok(Self::DoubleAeadAes256GcmAeadAes256Gcm),
            0x000B => Ok(Self::Aria128CtrHmacSha1_80),
            0x000C => Ok(Self::Aria128CtrHmacSha1_32),
            0x000D => Ok(Self::Aria256CtrHmacSha1_80),
            0x000E => Ok(Self::Aria256CtrHmacSha1_32),
            other => Err(format!("unknown SRTP protection profile ID: 0x{other:04X}")),
        }
    }
}

impl fmt::Display for SrtpProtectionProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Aes128CmSha1_80 => "SRTP_AES128_CM_SHA1_80",
            Self::Aes128CmSha1_32 => "SRTP_AES128_CM_SHA1_32",
            Self::NullHmacSha1_80 => "SRTP_NULL_HMAC_SHA1_80",
            Self::NullHmacSha1_32 => "SRTP_NULL_HMAC_SHA1_32",
            Self::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            Self::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
            Self::DoubleAeadAes128GcmAeadAes128Gcm => {
                "SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM"
            }
            Self::DoubleAeadAes256GcmAeadAes256Gcm => {
                "SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM"
            }
            Self::Aria128CtrHmacSha1_80 => "SRTP_ARIA_128_CTR_HMAC_SHA1_80",
            Self::Aria128CtrHmacSha1_32 => "SRTP_ARIA_128_CTR_HMAC_SHA1_32",
            Self::Aria256CtrHmacSha1_80 => "SRTP_ARIA_256_CTR_HMAC_SHA1_80",
            Self::Aria256CtrHmacSha1_32 => "SRTP_ARIA_256_CTR_HMAC_SHA1_32",
        };
        f.write_str(name)
    }
}

// =============================================================================
// SrtpProtectionProfile — SRTP Protection Profile Descriptor
// =============================================================================

/// An SRTP protection profile descriptor pairing a human-readable name
/// with its IANA-assigned numeric identifier.
///
/// This struct is the Rust equivalent of the C `SRTP_PROTECTION_PROFILE`
/// struct defined in `include/openssl/srtp.h`. Each instance is immutable
/// and typically referenced from the static [`KNOWN_PROFILES`] array.
///
/// # Fields
///
/// - `name`: The IANA registration name (e.g., `"SRTP_AES128_CM_SHA1_80"`).
/// - `id`: The [`SrtpProtectionProfileId`] enum variant.
///
/// # Rule R5 (Nullability)
///
/// Both fields are always present — no sentinel values are used.
/// Functions that may or may not return a profile use `Option<&SrtpProtectionProfile>`.
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::KNOWN_PROFILES;
///
/// let first = &KNOWN_PROFILES[0];
/// assert_eq!(first.name(), "SRTP_AES128_CM_SHA1_80");
/// assert_eq!(first.id().as_u16(), 0x0001);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrtpProtectionProfile {
    /// The IANA-registered profile name string.
    name: &'static str,
    /// The typed profile identifier.
    id: SrtpProtectionProfileId,
}

impl SrtpProtectionProfile {
    /// Returns the IANA-registered name of this SRTP protection profile.
    ///
    /// The returned string matches the names used in the C
    /// `srtp_known_profiles[]` array and in DTLS-SRTP extension
    /// negotiation configuration strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_ssl::srtp::KNOWN_PROFILES;
    ///
    /// assert_eq!(KNOWN_PROFILES[0].name(), "SRTP_AES128_CM_SHA1_80");
    /// ```
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the [`SrtpProtectionProfileId`] identifying this profile.
    ///
    /// Use [`SrtpProtectionProfileId::as_u16()`] to obtain the numeric
    /// wire value if needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_ssl::srtp::{KNOWN_PROFILES, SrtpProtectionProfileId};
    ///
    /// assert_eq!(KNOWN_PROFILES[0].id(), SrtpProtectionProfileId::Aes128CmSha1_80);
    /// ```
    #[must_use]
    pub const fn id(&self) -> SrtpProtectionProfileId {
        self.id
    }
}

impl fmt::Display for SrtpProtectionProfile {
    /// Formats the profile as `"<name> (0x<id>)"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04X})", self.name, self.id.as_u16())
    }
}

// =============================================================================
// KNOWN_PROFILES — Static Registry of All Known SRTP Profiles
// =============================================================================

/// Static array of all IANA-registered SRTP protection profiles known
/// to this implementation.
///
/// This is the Rust equivalent of the C `srtp_known_profiles[]` array in
/// `ssl/d1_srtp.c`. The array is ordered by IANA registration value and
/// used as the authoritative lookup table for profile name resolution
/// and ID-based discovery.
///
/// # Completeness
///
/// This array contains all profiles from the IANA "DTLS-SRTP Protection
/// Profiles" registry that are supported by this implementation:
///
/// - RFC 5764 profiles: AES-128-CM, NULL cipher
/// - RFC 7714 profiles: AEAD AES-GCM
/// - RFC 8723 profiles: Double AEAD AES-GCM
/// - RFC 8269 profiles: ARIA counter mode
///
/// # Thread Safety
///
/// The array is `&'static` and immutable — safe to share across threads
/// without synchronisation.
pub const KNOWN_PROFILES: &[SrtpProtectionProfile] = &[
    SrtpProtectionProfile {
        name: "SRTP_AES128_CM_SHA1_80",
        id: SrtpProtectionProfileId::Aes128CmSha1_80,
    },
    SrtpProtectionProfile {
        name: "SRTP_AES128_CM_SHA1_32",
        id: SrtpProtectionProfileId::Aes128CmSha1_32,
    },
    SrtpProtectionProfile {
        name: "SRTP_NULL_HMAC_SHA1_80",
        id: SrtpProtectionProfileId::NullHmacSha1_80,
    },
    SrtpProtectionProfile {
        name: "SRTP_NULL_HMAC_SHA1_32",
        id: SrtpProtectionProfileId::NullHmacSha1_32,
    },
    SrtpProtectionProfile {
        name: "SRTP_AEAD_AES_128_GCM",
        id: SrtpProtectionProfileId::AeadAes128Gcm,
    },
    SrtpProtectionProfile {
        name: "SRTP_AEAD_AES_256_GCM",
        id: SrtpProtectionProfileId::AeadAes256Gcm,
    },
    SrtpProtectionProfile {
        name: "SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM",
        id: SrtpProtectionProfileId::DoubleAeadAes128GcmAeadAes128Gcm,
    },
    SrtpProtectionProfile {
        name: "SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM",
        id: SrtpProtectionProfileId::DoubleAeadAes256GcmAeadAes256Gcm,
    },
    SrtpProtectionProfile {
        name: "SRTP_ARIA_128_CTR_HMAC_SHA1_80",
        id: SrtpProtectionProfileId::Aria128CtrHmacSha1_80,
    },
    SrtpProtectionProfile {
        name: "SRTP_ARIA_128_CTR_HMAC_SHA1_32",
        id: SrtpProtectionProfileId::Aria128CtrHmacSha1_32,
    },
    SrtpProtectionProfile {
        name: "SRTP_ARIA_256_CTR_HMAC_SHA1_80",
        id: SrtpProtectionProfileId::Aria256CtrHmacSha1_80,
    },
    SrtpProtectionProfile {
        name: "SRTP_ARIA_256_CTR_HMAC_SHA1_32",
        id: SrtpProtectionProfileId::Aria256CtrHmacSha1_32,
    },
];

// =============================================================================
// Profile Lookup Functions
// =============================================================================

/// Finds an SRTP protection profile by its IANA-registered name.
///
/// Performs a case-sensitive linear scan of [`KNOWN_PROFILES`], matching
/// the exact profile name string. This is the Rust equivalent of the C
/// static `find_profile_by_name()` function in `ssl/d1_srtp.c`.
///
/// # Arguments
///
/// * `name` — The profile name to search for (e.g., `"SRTP_AES128_CM_SHA1_80"`).
///
/// # Returns
///
/// - `Some(&SrtpProtectionProfile)` if a matching profile is found.
/// - `None` if no known profile matches the given name (Rule R5).
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::find_profile_by_name;
///
/// let profile = find_profile_by_name("SRTP_AEAD_AES_128_GCM");
/// assert!(profile.is_some());
/// assert_eq!(profile.unwrap().id().as_u16(), 0x0007);
///
/// let unknown = find_profile_by_name("SRTP_NONEXISTENT");
/// assert!(unknown.is_none());
/// ```
pub fn find_profile_by_name(name: &str) -> Option<&'static SrtpProtectionProfile> {
    let result = KNOWN_PROFILES.iter().find(|p| p.name == name);
    if let Some(profile) = result {
        tracing::debug!(
            profile_name = profile.name,
            profile_id = profile.id.as_u16(),
            "SRTP profile found by name"
        );
    } else {
        tracing::debug!(
            searched_name = name,
            "SRTP profile not found by name"
        );
    }
    result
}

/// Finds an SRTP protection profile by its IANA-assigned numeric identifier.
///
/// Performs a linear scan of [`KNOWN_PROFILES`], matching the `u16` wire
/// value against each profile's [`SrtpProtectionProfileId::as_u16()`].
///
/// # Arguments
///
/// * `id` — The 16-bit IANA profile identifier to search for.
///
/// # Returns
///
/// - `Some(&SrtpProtectionProfile)` if a profile with the given ID exists.
/// - `None` if no known profile matches the given ID (Rule R5).
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::find_profile_by_id;
///
/// let profile = find_profile_by_id(0x0001);
/// assert!(profile.is_some());
/// assert_eq!(profile.unwrap().name(), "SRTP_AES128_CM_SHA1_80");
///
/// let unknown = find_profile_by_id(0xFFFF);
/// assert!(unknown.is_none());
/// ```
pub fn find_profile_by_id(id: u16) -> Option<&'static SrtpProtectionProfile> {
    let result = KNOWN_PROFILES.iter().find(|p| p.id.as_u16() == id);
    if let Some(profile) = result {
        tracing::debug!(
            profile_name = profile.name,
            profile_id = id,
            "SRTP profile found by ID"
        );
    } else {
        tracing::debug!(
            searched_id = id,
            "SRTP profile not found by ID"
        );
    }
    result
}

// =============================================================================
// Profile List Parsing
// =============================================================================

/// Parses a colon-separated string of SRTP protection profile names into
/// a validated list of [`SrtpProtectionProfile`] values.
///
/// This function is the Rust equivalent of the C `ssl_ctx_make_profiles()`
/// function in `ssl/d1_srtp.c`. It splits the input string on `:` delimiters,
/// looks up each name in [`KNOWN_PROFILES`], validates that no profile
/// appears more than once, and returns the ordered list.
///
/// # Arguments
///
/// * `profiles_str` — A colon-separated list of profile names
///   (e.g., `"SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM"`).
///
/// # Errors
///
/// Returns [`SslError::Protocol`] if:
/// - The input string is empty.
/// - Any profile name is not found in [`KNOWN_PROFILES`].
/// - A profile name appears more than once in the list.
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::parse_profile_list;
///
/// // Valid: two distinct profiles
/// let profiles = parse_profile_list("SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM")
///     .expect("valid profiles");
/// assert_eq!(profiles.len(), 2);
///
/// // Error: unknown profile name
/// let err = parse_profile_list("SRTP_NONEXISTENT");
/// assert!(err.is_err());
///
/// // Error: duplicate profile
/// let err = parse_profile_list("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_80");
/// assert!(err.is_err());
/// ```
pub fn parse_profile_list(profiles_str: &str) -> Result<Vec<SrtpProtectionProfile>, SslError> {
    if profiles_str.is_empty() {
        return Err(SslError::Protocol(
            "SRTP profile list string is empty".to_string(),
        ));
    }

    let mut profiles: Vec<SrtpProtectionProfile> = Vec::new();

    for token in profiles_str.split(':') {
        let token = token.trim();

        if token.is_empty() {
            // Skip empty tokens produced by consecutive colons (e.g., "A::B")
            continue;
        }

        // Look up the profile by name in the known profiles registry
        let profile = find_profile_by_name(token).ok_or_else(|| {
            tracing::warn!(
                profile_name = token,
                "unknown SRTP protection profile name"
            );
            SslError::Protocol(format!(
                "unknown SRTP protection profile: {token}"
            ))
        })?;

        // Check for duplicates — mirrors the C sk_SRTP_PROTECTION_PROFILE_find()
        // check in ssl_ctx_make_profiles()
        if profiles.iter().any(|existing| existing.id == profile.id) {
            return Err(SslError::Protocol(format!(
                "duplicate SRTP protection profile in list: {}",
                profile.name
            )));
        }

        profiles.push(*profile);
    }

    if profiles.is_empty() {
        return Err(SslError::Protocol(
            "SRTP profile list contains no valid profiles".to_string(),
        ));
    }

    tracing::debug!(
        profile_count = profiles.len(),
        "parsed SRTP profile list successfully"
    );

    Ok(profiles)
}

// =============================================================================
// SSL_CTX / SSL Integration Functions
// =============================================================================

/// Configures SRTP protection profiles from a colon-separated profile
/// name string, storing the result in the provided target vector.
///
/// This is the Rust equivalent of `SSL_CTX_set_tlsext_use_srtp()` and
/// `SSL_set_tlsext_use_srtp()` from `ssl/d1_srtp.c`. The caller is
/// responsible for storing the returned profiles in the appropriate
/// `SSL_CTX` or `SSL` connection structure.
///
/// # Arguments
///
/// * `profiles_str` — Colon-separated list of SRTP profile names.
/// * `target` — Mutable reference to the profile storage vector.
///   Any existing profiles in this vector are replaced on success.
///
/// # Errors
///
/// Returns [`SslError::Handshake`] if:
/// - The profile string cannot be parsed (delegates to [`parse_profile_list()`]).
///
/// # C Mapping
///
/// ```c
/// // C:
/// int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles);
/// // Rust:
/// set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80", &mut ctx.srtp_profiles)?;
/// ```
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::{set_tlsext_use_srtp, SrtpProtectionProfile};
///
/// let mut profiles: Vec<SrtpProtectionProfile> = Vec::new();
/// set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM", &mut profiles)
///     .expect("valid profiles");
/// assert_eq!(profiles.len(), 2);
/// ```
pub fn set_tlsext_use_srtp(
    profiles_str: &str,
    target: &mut Vec<SrtpProtectionProfile>,
) -> Result<(), SslError> {
    let parsed = parse_profile_list(profiles_str).map_err(|e| {
        SslError::Handshake(format!("SRTP profile configuration failed: {e}"))
    })?;

    // Replace any existing profiles — matches the C behavior where
    // ssl_ctx_make_profiles() frees the old stack before assigning new one
    *target = parsed;

    tracing::debug!(
        profile_count = target.len(),
        "SRTP profiles configured via set_tlsext_use_srtp"
    );

    Ok(())
}

/// Returns the configured SRTP protection profiles, or `None` if no
/// profiles have been set.
///
/// This is the Rust equivalent of `SSL_get_srtp_profiles()` from
/// `ssl/d1_srtp.c`. In the C implementation, this function checks the
/// `SSL` connection's profile list first, falling back to the `SSL_CTX`'s
/// list. The caller is responsible for implementing the fallback logic;
/// this function checks a single profile slice.
///
/// # Arguments
///
/// * `profiles` — The profile slice to inspect (from either `SSL` or `SSL_CTX`).
///
/// # Returns
///
/// - `Some(&[SrtpProtectionProfile])` if at least one profile is configured.
/// - `None` if the slice is empty (Rule R5 — no sentinel values).
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::{get_srtp_profiles, SrtpProtectionProfile, KNOWN_PROFILES};
///
/// // Non-empty slice
/// let profiles = vec![KNOWN_PROFILES[0]];
/// assert!(get_srtp_profiles(&profiles).is_some());
///
/// // Empty slice
/// let empty: Vec<SrtpProtectionProfile> = Vec::new();
/// assert!(get_srtp_profiles(&empty).is_none());
/// ```
pub fn get_srtp_profiles(profiles: &[SrtpProtectionProfile]) -> Option<&[SrtpProtectionProfile]> {
    if profiles.is_empty() {
        None
    } else {
        Some(profiles)
    }
}

/// Returns the selected SRTP protection profile from a DTLS-SRTP
/// negotiation, or `None` if no profile has been selected yet.
///
/// This is the Rust equivalent of `SSL_get_selected_srtp_profile()` from
/// `ssl/d1_srtp.c`. In the C implementation, this returns
/// `sc->srtp_profile` which is `NULL` (0) if no profile was selected
/// during the handshake.
///
/// # Arguments
///
/// * `selected` — An optional reference to the selected profile.
///
/// # Returns
///
/// - `Some(&SrtpProtectionProfile)` if a profile was selected during negotiation.
/// - `None` if no profile has been selected (Rule R5 — `Option<T>` instead
///   of returning `NULL` / `0`).
///
/// # Examples
///
/// ```
/// use openssl_ssl::srtp::{get_selected_srtp_profile, KNOWN_PROFILES};
///
/// // Profile selected
/// let profile = KNOWN_PROFILES[0];
/// assert!(get_selected_srtp_profile(Some(&profile)).is_some());
///
/// // No profile selected
/// assert!(get_selected_srtp_profile(None).is_none());
/// ```
pub fn get_selected_srtp_profile(
    selected: Option<&SrtpProtectionProfile>,
) -> Option<&SrtpProtectionProfile> {
    selected
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_profiles_count() {
        // The KNOWN_PROFILES array should contain exactly 12 entries
        assert_eq!(KNOWN_PROFILES.len(), 12);
    }

    #[test]
    fn test_known_profiles_unique_ids() {
        // Every profile in KNOWN_PROFILES must have a unique ID
        let mut ids: Vec<u16> = KNOWN_PROFILES.iter().map(|p| p.id.as_u16()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), KNOWN_PROFILES.len());
    }

    #[test]
    fn test_known_profiles_unique_names() {
        // Every profile in KNOWN_PROFILES must have a unique name
        let mut names: Vec<&str> = KNOWN_PROFILES.iter().map(|p| p.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), KNOWN_PROFILES.len());
    }

    #[test]
    fn test_profile_id_roundtrip() {
        // Every known profile's ID should round-trip through as_u16 and TryFrom
        for profile in KNOWN_PROFILES {
            let wire_value = profile.id.as_u16();
            let recovered = SrtpProtectionProfileId::try_from(wire_value)
                .unwrap_or_else(|e| panic!("round-trip failed for {}: {e}", profile.name));
            assert_eq!(recovered, profile.id);
        }
    }

    #[test]
    fn test_try_from_unknown_id() {
        // Unknown IDs should produce an error
        let result = SrtpProtectionProfileId::try_from(0xFFFFu16);
        assert!(result.is_err());
        let result = SrtpProtectionProfileId::try_from(0x0000u16);
        assert!(result.is_err());
        let result = SrtpProtectionProfileId::try_from(0x0003u16);
        assert!(result.is_err());
    }

    #[test]
    fn test_specific_profile_ids() {
        assert_eq!(SrtpProtectionProfileId::Aes128CmSha1_80.as_u16(), 0x0001);
        assert_eq!(SrtpProtectionProfileId::Aes128CmSha1_32.as_u16(), 0x0002);
        assert_eq!(SrtpProtectionProfileId::NullHmacSha1_80.as_u16(), 0x0005);
        assert_eq!(SrtpProtectionProfileId::NullHmacSha1_32.as_u16(), 0x0006);
        assert_eq!(SrtpProtectionProfileId::AeadAes128Gcm.as_u16(), 0x0007);
        assert_eq!(SrtpProtectionProfileId::AeadAes256Gcm.as_u16(), 0x0008);
        assert_eq!(
            SrtpProtectionProfileId::DoubleAeadAes128GcmAeadAes128Gcm.as_u16(),
            0x0009
        );
        assert_eq!(
            SrtpProtectionProfileId::DoubleAeadAes256GcmAeadAes256Gcm.as_u16(),
            0x000A
        );
        assert_eq!(SrtpProtectionProfileId::Aria128CtrHmacSha1_80.as_u16(), 0x000B);
        assert_eq!(SrtpProtectionProfileId::Aria128CtrHmacSha1_32.as_u16(), 0x000C);
        assert_eq!(SrtpProtectionProfileId::Aria256CtrHmacSha1_80.as_u16(), 0x000D);
        assert_eq!(SrtpProtectionProfileId::Aria256CtrHmacSha1_32.as_u16(), 0x000E);
    }

    #[test]
    fn test_find_profile_by_name_found() {
        let profile = find_profile_by_name("SRTP_AES128_CM_SHA1_80");
        assert!(profile.is_some());
        let p = profile.unwrap();
        assert_eq!(p.name(), "SRTP_AES128_CM_SHA1_80");
        assert_eq!(p.id(), SrtpProtectionProfileId::Aes128CmSha1_80);
    }

    #[test]
    fn test_find_profile_by_name_not_found() {
        assert!(find_profile_by_name("SRTP_NONEXISTENT").is_none());
        assert!(find_profile_by_name("").is_none());
        assert!(find_profile_by_name("srtp_aes128_cm_sha1_80").is_none()); // case-sensitive
    }

    #[test]
    fn test_find_profile_by_name_all_known() {
        for profile in KNOWN_PROFILES {
            let found = find_profile_by_name(profile.name);
            assert!(found.is_some(), "profile not found: {}", profile.name);
            assert_eq!(found.unwrap().id, profile.id);
        }
    }

    #[test]
    fn test_find_profile_by_id_found() {
        let profile = find_profile_by_id(0x0001);
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().name(), "SRTP_AES128_CM_SHA1_80");
    }

    #[test]
    fn test_find_profile_by_id_not_found() {
        assert!(find_profile_by_id(0x0000).is_none());
        assert!(find_profile_by_id(0xFFFF).is_none());
        assert!(find_profile_by_id(0x0003).is_none());
    }

    #[test]
    fn test_find_profile_by_id_all_known() {
        for profile in KNOWN_PROFILES {
            let found = find_profile_by_id(profile.id.as_u16());
            assert!(found.is_some(), "profile not found by ID: 0x{:04X}", profile.id.as_u16());
            assert_eq!(found.unwrap().name, profile.name);
        }
    }

    #[test]
    fn test_parse_profile_list_single() {
        let profiles = parse_profile_list("SRTP_AES128_CM_SHA1_80")
            .expect("single profile should parse");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name(), "SRTP_AES128_CM_SHA1_80");
    }

    #[test]
    fn test_parse_profile_list_multiple() {
        let profiles =
            parse_profile_list("SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM")
                .expect("multiple profiles should parse");
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].id(), SrtpProtectionProfileId::Aes128CmSha1_80);
        assert_eq!(profiles[1].id(), SrtpProtectionProfileId::AeadAes128Gcm);
        assert_eq!(profiles[2].id(), SrtpProtectionProfileId::AeadAes256Gcm);
    }

    #[test]
    fn test_parse_profile_list_empty_string() {
        let result = parse_profile_list("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_profile_list_unknown_profile() {
        let result = parse_profile_list("SRTP_NONEXISTENT");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_profile_list_duplicate() {
        let result = parse_profile_list("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_80");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_profile_list_with_unknown_in_middle() {
        let result = parse_profile_list("SRTP_AES128_CM_SHA1_80:SRTP_UNKNOWN:SRTP_AEAD_AES_128_GCM");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_tlsext_use_srtp_success() {
        let mut profiles = Vec::new();
        set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM", &mut profiles)
            .expect("should succeed");
        assert_eq!(profiles.len(), 2);
    }

    #[test]
    fn test_set_tlsext_use_srtp_replaces_existing() {
        let mut profiles = Vec::new();

        // First call sets two profiles
        set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM", &mut profiles)
            .expect("first set should succeed");
        assert_eq!(profiles.len(), 2);

        // Second call replaces with one profile
        set_tlsext_use_srtp("SRTP_AEAD_AES_256_GCM", &mut profiles)
            .expect("second set should succeed");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id(), SrtpProtectionProfileId::AeadAes256Gcm);
    }

    #[test]
    fn test_set_tlsext_use_srtp_error() {
        let mut profiles = Vec::new();
        let result = set_tlsext_use_srtp("SRTP_NONEXISTENT", &mut profiles);
        assert!(result.is_err());
        assert!(profiles.is_empty()); // target should not be modified on error
    }

    #[test]
    fn test_get_srtp_profiles_non_empty() {
        let profiles = vec![KNOWN_PROFILES[0], KNOWN_PROFILES[1]];
        let result = get_srtp_profiles(&profiles);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_get_srtp_profiles_empty() {
        let profiles: Vec<SrtpProtectionProfile> = Vec::new();
        assert!(get_srtp_profiles(&profiles).is_none());
    }

    #[test]
    fn test_get_selected_srtp_profile_some() {
        let profile = &KNOWN_PROFILES[0];
        let result = get_selected_srtp_profile(Some(profile));
        assert!(result.is_some());
        assert_eq!(result.unwrap().id(), SrtpProtectionProfileId::Aes128CmSha1_80);
    }

    #[test]
    fn test_get_selected_srtp_profile_none() {
        assert!(get_selected_srtp_profile(None).is_none());
    }

    #[test]
    fn test_profile_display() {
        let profile = KNOWN_PROFILES[0];
        let display = format!("{profile}");
        assert_eq!(display, "SRTP_AES128_CM_SHA1_80 (0x0001)");
    }

    #[test]
    fn test_profile_id_display() {
        let id = SrtpProtectionProfileId::AeadAes128Gcm;
        let display = format!("{id}");
        assert_eq!(display, "SRTP_AEAD_AES_128_GCM");
    }

    #[test]
    fn test_profile_clone_and_eq() {
        let p1 = KNOWN_PROFILES[0];
        let p2 = p1;
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_set_tlsext_use_srtp_empty_string() {
        let mut profiles = Vec::new();
        let result = set_tlsext_use_srtp("", &mut profiles);
        assert!(result.is_err());
    }
}
