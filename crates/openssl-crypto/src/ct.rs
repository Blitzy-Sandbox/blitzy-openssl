//! Certificate Transparency (CT) per RFC 6962 — Foundational Types.
//!
//! Provides core CT type definitions for Signed Certificate Timestamps (SCTs)
//! and Certificate Transparency log integration.  This module replaces a
//! subset of the C `SCT_*` and `CT_POLICY_EVAL_CTX_*` API surface from
//! `crypto/ct/*.c` (~10 files) and `include/openssl/ct.h.in`.
//!
//! # Scope
//!
//! This module provides **foundational CT types** sufficient to:
//!
//! - Express CT log-entry types (`LogEntryType`)
//! - Encode/decode SCT version codes (`SctVersion`)
//! - Track SCT acquisition source (`SctSource`)
//! - Track SCT validation status (`SctValidationStatus`)
//! - Construct minimal `SignedCertificateTimestamp` structures with
//!   builder-pattern field initialisation (`SignedCertificateTimestamp`,
//!   `SignedCertificateTimestampBuilder`)
//! - Validate log IDs, signatures, and timestamps against RFC 6962 length and
//!   range requirements
//!
//! Full CT validation pipeline (Merkle tree audit-path verification, log
//! consistency proofs, log fetching from URL endpoints, base64 SCT decoding,
//! integration with the X.509 chain-verification call-graph,
//! `CT_POLICY_EVAL_CTX` state machine) is **out of scope** for this
//! checkpoint.  Callers requiring the complete CT validator should use the
//! C `libcrypto` through `openssl-ffi` until those layers are translated.
//! This module is the foundation on which subsequent CT work will build.
//!
//! # C Source Mapping
//!
//! | C Symbol / File | Rust Equivalent |
//! |---|---|
//! | `ct_log_entry_type_t` (`ct.h.in`) | `LogEntryType` |
//! | `sct_version_t` (`ct.h.in`) | `SctVersion` |
//! | `sct_source_t` (`ct.h.in`) | `SctSource` |
//! | `sct_validation_status_t` (`ct.h.in`) | `SctValidationStatus` |
//! | `SCT_MIN_RSA_BITS` (`ct.h.in`) | `SCT_MIN_RSA_BITS` |
//! | `CT_V1_HASHLEN` (`ct.h.in`) | `CT_V1_HASHLEN` |
//! | `SCT` opaque struct (`ct_local.h`) | `SignedCertificateTimestamp` |
//! | `SCT_new` / `SCT_set_*` (`crypto/ct/ct_sct.c`) | `SignedCertificateTimestampBuilder` |
//! | RFC 6962 §3.2 log-id length (32 octets) | `validate_log_id` |
//! | RFC 6962 §3.2 v1 extensions length (≤65535) | `validate_sct_v1_extensions` |
//! | RFC 6962 §3.2 signature length (≥1, ≤65535) | `validate_signature` |
//!
//! # Rules Enforced
//!
//! - **R3 (Config Field Propagation):** Every field on every type has documented
//!   read-sites (accessors) and write-sites (constructors / setters).  Unread
//!   fields are annotated `// UNREAD: reserved for future RFC 6962
//!   serialised-encoding expansion`.
//! - **R5 (Nullability over Sentinels):** `Option<T>` is used for absent
//!   extension / signature / source / validation-status fields.  Status codes
//!   use typed enums; integer sentinel values (`-1` `NOT_SET`) are surfaced
//!   only through the dedicated `NotSet` enum variant rather than encoded
//!   into integer fields.
//! - **R6 (Lossless Numeric Casts):** Discriminants use the smallest sufficient
//!   primitive type (`i32` for enums with negative `NOT_SET`, `u32` for
//!   non-negative enums).  All length checks use `usize`-comparisons; no bare
//!   `as` narrowing casts.
//! - **R8 (Zero Unsafe):** This module contains zero `unsafe` blocks, verified
//!   by the workspace `forbid(unsafe_code)` lint inherited from `lib.rs`.
//! - **R9 (Warning-Free):** All public items carry `///` documentation; no
//!   module- or item-level `#[allow(unused)]`.
//! - **R10 (Wiring Before Done):** Reachable from the crate boundary via
//!   `pub mod ct;` in `lib.rs` (gated by the `ct` Cargo feature) and exercised
//!   by the feature-gated integration test suite at
//!   `crates/openssl-crypto/src/tests/test_ct.rs`.
//!
//! # Feature Gate
//!
//! Gated behind the `ct` Cargo feature flag (default-enabled, equivalent to
//! `OPENSSL_NO_CT` being undefined).  The feature is declared in
//! `crates/openssl-crypto/Cargo.toml`.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::ct::{
//!     LogEntryType, SctVersion, SctSource, SctValidationStatus,
//!     SignedCertificateTimestampBuilder, SCT_MIN_RSA_BITS, CT_V1_HASHLEN,
//! };
//!
//! // Construct an SCT with a builder.
//! let log_id = vec![0u8; CT_V1_HASHLEN];
//! let signature = vec![0u8; 64];
//! let sct = SignedCertificateTimestampBuilder::new(SctVersion::V1)
//!     .log_entry_type(LogEntryType::X509)
//!     .log_id(log_id)
//!     .timestamp(1_700_000_000_000u64)
//!     .signature(signature)
//!     .source(SctSource::TlsExtension)
//!     .build()
//!     .expect("valid SCT");
//!
//! assert_eq!(sct.version(), SctVersion::V1);
//! assert_eq!(sct.log_entry_type(), LogEntryType::X509);
//! assert_eq!(sct.timestamp(), 1_700_000_000_000u64);
//! assert_eq!(sct.source(), Some(SctSource::TlsExtension));
//! assert_eq!(sct.validation_status(), SctValidationStatus::NotSet);
//!
//! // The minimum RSA key length per RFC 6962 §2.1.4 is 2048 bits.
//! assert_eq!(SCT_MIN_RSA_BITS, 2048);
//! ```

use std::collections::HashSet;
use std::fmt;

use openssl_common::error::{CryptoError, CryptoResult};

// =============================================================================
// Module-Level Constants — RFC 6962 §2.1.4 / §3.2
// =============================================================================

/// Minimum RSA modulus bit-length required for SCT signatures, per RFC 6962
/// §2.1.4.
///
/// Mirrors the C constant:
///
/// ```c
/// /* Minimum RSA key size, from RFC6962 */
/// # define SCT_MIN_RSA_BITS 2048
/// ```
///
/// CT logs MUST sign tree-head and entry-timestamp messages with either
/// ECDSA-P256/SHA-256 or RSA-2048+/SHA-256.  This constant is consulted by
/// callers verifying RSA-signed SCTs to reject under-strength keys.
pub const SCT_MIN_RSA_BITS: usize = 2048;

/// Length in octets of the SHA-256 hash used in CT v1, per RFC 6962 §3.2.
///
/// Mirrors the C constant:
///
/// ```c
/// /* All hashes are SHA256 in v1 of Certificate Transparency */
/// # define CT_V1_HASHLEN SHA256_DIGEST_LENGTH
/// ```
///
/// Used as the length of the `LogID` field in v1 SCTs (`SHA-256(log-public-key)`).
pub const CT_V1_HASHLEN: usize = 32;

/// Maximum length of the SCT extensions field, per RFC 6962 §3.2 (encoded
/// as a 16-bit length-prefixed octet string).
///
/// CT v1 messages encode optional opaque extensions as `<0..2^16-1>` per
/// RFC 5246 §4.3 vector encoding.
pub const MAX_SCT_EXTENSIONS_LEN: usize = 65_535;

/// Maximum length of the SCT signature field, per RFC 6962 §3.2 (encoded
/// as a 16-bit length-prefixed octet string).
///
/// The signature is encoded as `DigitallySigned` per RFC 5246 §4.7 with
/// 16-bit length-prefix.  Must not exceed 65535 octets.
pub const MAX_SCT_SIGNATURE_LEN: usize = 65_535;

// =============================================================================
// LogEntryType — RFC 6962 §3.1 ct_log_entry_type_t
// =============================================================================

/// Type of certificate entry stored in a Certificate Transparency log,
/// per RFC 6962 §3.1.
///
/// Mirrors the C enum:
///
/// ```c
/// typedef enum {
///     CT_LOG_ENTRY_TYPE_NOT_SET = -1,
///     CT_LOG_ENTRY_TYPE_X509 = 0,
///     CT_LOG_ENTRY_TYPE_PRECERT = 1
/// } ct_log_entry_type_t;
/// ```
///
/// CT logs accept two `MerkleTreeLeaf` entry types: full X.509 certificates
/// (`X509`) and pre-certificates (`Precert`) — `TBSCertificate` templates from
/// which the final certificate inherits its identity.  The `NotSet` variant
/// is used as an "unset" sentinel for partially-constructed SCTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum LogEntryType {
    /// Sentinel "not set" value; mirrors `CT_LOG_ENTRY_TYPE_NOT_SET = -1`.
    ///
    /// Used by the C API to indicate an SCT has been allocated but has not
    /// yet had its log-entry type populated.  Rust callers should generally
    /// avoid this state; it is kept for FFI / parser fidelity.
    NotSet = -1,
    /// X.509 v3 leaf certificate; mirrors `CT_LOG_ENTRY_TYPE_X509 = 0`.
    X509 = 0,
    /// Pre-certificate (`TBSCertificate` template); mirrors
    /// `CT_LOG_ENTRY_TYPE_PRECERT = 1`.
    Precert = 1,
}

impl LogEntryType {
    /// Returns the default log-entry type used for newly-allocated SCTs.
    ///
    /// Matches the C `SCT_new()` initialisation behaviour where a fresh SCT
    /// has `entry_type = CT_LOG_ENTRY_TYPE_NOT_SET`.
    #[must_use]
    pub const fn default_value() -> Self {
        Self::NotSet
    }

    /// Constructs a [`LogEntryType`] from an integer discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when `value` is not `-1`, `0`,
    /// or `1` — the only values defined by RFC 6962 §3.1.
    pub fn from_i32(value: i32) -> CryptoResult<Self> {
        match value {
            -1 => Ok(Self::NotSet),
            0 => Ok(Self::X509),
            1 => Ok(Self::Precert),
            other => Err(CryptoError::Verification(format!(
                "unknown CT log entry type: {other} (RFC 6962 §3.1 defines only X509=0, Precert=1; -1 reserved for NotSet)"
            ))),
        }
    }

    /// Returns the integer discriminant for this enum variant.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns the canonical short name of this entry type (without the
    /// `CT_LOG_ENTRY_TYPE_` prefix).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotSet => "not_set",
            Self::X509 => "x509",
            Self::Precert => "precert",
        }
    }

    /// Returns `true` if this is one of the two RFC 6962 leaf types
    /// (`X509` or `Precert`); returns `false` for `NotSet`.
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        matches!(self, Self::X509 | Self::Precert)
    }
}

impl Default for LogEntryType {
    fn default() -> Self {
        Self::default_value()
    }
}

impl fmt::Display for LogEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// SctVersion — RFC 6962 §3.2 sct_version_t
// =============================================================================

/// Version code of a Signed Certificate Timestamp, per RFC 6962 §3.2.
///
/// Mirrors the C enum:
///
/// ```c
/// typedef enum {
///     SCT_VERSION_NOT_SET = -1,
///     SCT_VERSION_V1 = 0
/// } sct_version_t;
/// ```
///
/// RFC 6962 defines a single SCT version (`v1`).  RFC 9162 introduces CT
/// v2 (Static CT API) but the wire-format SCT version remains `v1`; the v2
/// log identifier is encoded out-of-band.  The `NotSet` variant is preserved
/// for FFI parity with `SCT_VERSION_NOT_SET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum SctVersion {
    /// Sentinel "not set" value; mirrors `SCT_VERSION_NOT_SET = -1`.
    NotSet = -1,
    /// Version 1 SCT, the only currently-defined wire-format version;
    /// mirrors `SCT_VERSION_V1 = 0`.
    V1 = 0,
}

impl SctVersion {
    /// Returns the default version used for newly-allocated SCTs.
    ///
    /// Matches the C `SCT_new()` initialisation behaviour where a fresh SCT
    /// has `version = SCT_VERSION_NOT_SET`.
    #[must_use]
    pub const fn default_value() -> Self {
        Self::NotSet
    }

    /// Constructs an [`SctVersion`] from an integer discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when `value` is not `-1` or `0` —
    /// the only values defined by RFC 6962 §3.2.
    pub fn from_i32(value: i32) -> CryptoResult<Self> {
        match value {
            -1 => Ok(Self::NotSet),
            0 => Ok(Self::V1),
            other => Err(CryptoError::Verification(format!(
                "unknown SCT version: {other} (RFC 6962 §3.2 defines only V1=0; -1 reserved for NotSet)"
            ))),
        }
    }

    /// Returns the integer discriminant for this enum variant.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns the canonical short name of this version (without the
    /// `SCT_VERSION_` prefix).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotSet => "not_set",
            Self::V1 => "v1",
        }
    }

    /// Returns `true` if this version represents the RFC 6962 v1 wire format.
    #[must_use]
    pub const fn is_v1(self) -> bool {
        matches!(self, Self::V1)
    }
}

impl Default for SctVersion {
    fn default() -> Self {
        Self::default_value()
    }
}

impl fmt::Display for SctVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// SctSource — sct_source_t (libcrypto-internal book-keeping)
// =============================================================================

/// Origin from which an SCT was acquired by a TLS / X.509 client.
///
/// Mirrors the C enum:
///
/// ```c
/// typedef enum {
///     SCT_SOURCE_UNKNOWN,
///     SCT_SOURCE_TLS_EXTENSION,
///     SCT_SOURCE_X509V3_EXTENSION,
///     SCT_SOURCE_OCSP_STAPLED_RESPONSE
/// } sct_source_t;
/// ```
///
/// RFC 6962 §3.3 defines three SCT delivery mechanisms: TLS extension
/// (`signed_certificate_timestamp`), X.509v3 extension embedded in the
/// leaf certificate, and OCSP stapled response.  The `Unknown` variant is
/// used by parsers that have not yet determined the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
pub enum SctSource {
    /// Source is unknown; mirrors `SCT_SOURCE_UNKNOWN`.
    Unknown = 0,
    /// SCT delivered via TLS `signed_certificate_timestamp` extension
    /// (RFC 6962 §3.3.1); mirrors `SCT_SOURCE_TLS_EXTENSION`.
    TlsExtension = 1,
    /// SCT embedded in an X.509v3 extension on the leaf certificate
    /// (RFC 6962 §3.3.2); mirrors `SCT_SOURCE_X509V3_EXTENSION`.
    X509v3Extension = 2,
    /// SCT delivered via an OCSP stapled response (RFC 6962 §3.3.3);
    /// mirrors `SCT_SOURCE_OCSP_STAPLED_RESPONSE`.
    OcspStapledResponse = 3,
}

impl SctSource {
    /// Returns the default source used for newly-allocated SCTs.
    ///
    /// Matches the C `SCT_new()` initialisation behaviour where a fresh SCT
    /// has `source = SCT_SOURCE_UNKNOWN`.
    #[must_use]
    pub const fn default_value() -> Self {
        Self::Unknown
    }

    /// Constructs an [`SctSource`] from an integer discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when `value` is not in the
    /// range `0..=3`.
    pub fn from_u32(value: u32) -> CryptoResult<Self> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::TlsExtension),
            2 => Ok(Self::X509v3Extension),
            3 => Ok(Self::OcspStapledResponse),
            other => Err(CryptoError::Verification(format!(
                "unknown SCT source: {other} (expected 0..=3 per RFC 6962 §3.3)"
            ))),
        }
    }

    /// Returns the integer discriminant for this enum variant.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the canonical short name of this source (without the
    /// `SCT_SOURCE_` prefix).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::TlsExtension => "tls_extension",
            Self::X509v3Extension => "x509v3_extension",
            Self::OcspStapledResponse => "ocsp_stapled_response",
        }
    }

    /// Returns `true` if this represents one of the three RFC 6962 §3.3
    /// delivery mechanisms (i.e. anything other than [`SctSource::Unknown`]).
    #[must_use]
    pub const fn is_delivery_mechanism(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

impl Default for SctSource {
    fn default() -> Self {
        Self::default_value()
    }
}

impl fmt::Display for SctSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// SctValidationStatus — sct_validation_status_t
// =============================================================================

/// Validation outcome for an SCT after it has been processed by the CT
/// policy evaluator.
///
/// Mirrors the C enum:
///
/// ```c
/// typedef enum {
///     SCT_VALIDATION_STATUS_NOT_SET,
///     SCT_VALIDATION_STATUS_UNKNOWN_LOG,
///     SCT_VALIDATION_STATUS_VALID,
///     SCT_VALIDATION_STATUS_INVALID,
///     SCT_VALIDATION_STATUS_UNVERIFIED,
///     SCT_VALIDATION_STATUS_UNKNOWN_VERSION
/// } sct_validation_status_t;
/// ```
///
/// `Valid` is the only outcome that satisfies an RFC 6962 verification
/// requirement; the remaining variants represent distinct failure modes
/// useful for diagnostics and policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
pub enum SctValidationStatus {
    /// SCT has not yet been evaluated by the CT policy engine; mirrors
    /// `SCT_VALIDATION_STATUS_NOT_SET`.
    NotSet = 0,
    /// SCT references a log unknown to the local trust store; mirrors
    /// `SCT_VALIDATION_STATUS_UNKNOWN_LOG`.
    UnknownLog = 1,
    /// SCT signature verifies cleanly against the named log; mirrors
    /// `SCT_VALIDATION_STATUS_VALID`.
    Valid = 2,
    /// SCT signature does not verify; mirrors
    /// `SCT_VALIDATION_STATUS_INVALID`.
    Invalid = 3,
    /// SCT has not been verified — typically because the policy evaluator
    /// did not have the necessary inputs (e.g. issuer certificate); mirrors
    /// `SCT_VALIDATION_STATUS_UNVERIFIED`.
    Unverified = 4,
    /// SCT version is recognised (e.g. an unknown future version); mirrors
    /// `SCT_VALIDATION_STATUS_UNKNOWN_VERSION`.
    UnknownVersion = 5,
}

impl SctValidationStatus {
    /// Returns the default validation status used for newly-allocated SCTs.
    ///
    /// Matches the C `SCT_new()` initialisation behaviour where a fresh SCT
    /// has `validation_status = SCT_VALIDATION_STATUS_NOT_SET`.
    #[must_use]
    pub const fn default_value() -> Self {
        Self::NotSet
    }

    /// Constructs an [`SctValidationStatus`] from an integer discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when `value` is not in the
    /// range `0..=5`.
    pub fn from_u32(value: u32) -> CryptoResult<Self> {
        match value {
            0 => Ok(Self::NotSet),
            1 => Ok(Self::UnknownLog),
            2 => Ok(Self::Valid),
            3 => Ok(Self::Invalid),
            4 => Ok(Self::Unverified),
            5 => Ok(Self::UnknownVersion),
            other => Err(CryptoError::Verification(format!(
                "unknown SCT validation status: {other} (expected 0..=5 per ct.h.in)"
            ))),
        }
    }

    /// Returns the integer discriminant for this enum variant.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the canonical short name of this validation status (without
    /// the `SCT_VALIDATION_STATUS_` prefix).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotSet => "not_set",
            Self::UnknownLog => "unknown_log",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unverified => "unverified",
            Self::UnknownVersion => "unknown_version",
        }
    }

    /// Returns `true` if this status represents a successful validation
    /// outcome ([`SctValidationStatus::Valid`]).
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if this status represents an explicit failure
    /// ([`SctValidationStatus::Invalid`]).
    #[must_use]
    pub const fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid)
    }

    /// Returns `true` if validation has not yet been performed
    /// ([`SctValidationStatus::NotSet`] or [`SctValidationStatus::Unverified`]).
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::NotSet | Self::Unverified)
    }
}

impl Default for SctValidationStatus {
    fn default() -> Self {
        Self::default_value()
    }
}

impl fmt::Display for SctValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// Validation Helpers — RFC 6962 §3.2 length / range checks
// =============================================================================

/// Validates the length of a CT v1 log identifier per RFC 6962 §3.2.
///
/// The `LogID` field of a v1 SCT is `SHA-256(log-public-key)`, exactly
/// [`CT_V1_HASHLEN`] (32) octets.
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `log_id.len() != CT_V1_HASHLEN`.
pub fn validate_log_id(log_id: &[u8]) -> CryptoResult<()> {
    if log_id.len() == CT_V1_HASHLEN {
        Ok(())
    } else {
        Err(CryptoError::Verification(format!(
            "CT v1 log ID length is {}, but RFC 6962 §3.2 requires {} octets (SHA-256 of log public key)",
            log_id.len(),
            CT_V1_HASHLEN
        )))
    }
}

/// Validates the length of an SCT v1 extensions field per RFC 6962 §3.2.
///
/// Encoded as a 16-bit length-prefixed octet string per RFC 5246 §4.3, so
/// the maximum length is [`MAX_SCT_EXTENSIONS_LEN`] (`2^16 - 1 = 65535`).
/// An empty extensions field is permitted.
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `extensions.len() >
/// MAX_SCT_EXTENSIONS_LEN`.
pub fn validate_sct_v1_extensions(extensions: &[u8]) -> CryptoResult<()> {
    if extensions.len() <= MAX_SCT_EXTENSIONS_LEN {
        Ok(())
    } else {
        Err(CryptoError::Verification(format!(
            "SCT v1 extensions length is {}, but RFC 6962 §3.2 (RFC 5246 §4.3 vector encoding) limits to {} octets",
            extensions.len(),
            MAX_SCT_EXTENSIONS_LEN
        )))
    }
}

/// Validates the length of an SCT signature blob per RFC 6962 §3.2.
///
/// Encoded as a `DigitallySigned` structure (RFC 5246 §4.7), wrapping a
/// 16-bit length-prefixed octet string.  The signature must be at least
/// 1 octet long and at most [`MAX_SCT_SIGNATURE_LEN`] (`2^16 - 1 = 65535`).
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `signature.is_empty()` or when
/// `signature.len() > MAX_SCT_SIGNATURE_LEN`.
pub fn validate_signature(signature: &[u8]) -> CryptoResult<()> {
    if signature.is_empty() {
        return Err(CryptoError::Verification(
            "SCT signature must be non-empty (RFC 6962 §3.2 / RFC 5246 §4.7 DigitallySigned)".into(),
        ));
    }
    if signature.len() > MAX_SCT_SIGNATURE_LEN {
        return Err(CryptoError::Verification(format!(
            "SCT signature length is {}, but RFC 6962 §3.2 (RFC 5246 §4.7 DigitallySigned) limits to {} octets",
            signature.len(),
            MAX_SCT_SIGNATURE_LEN
        )));
    }
    Ok(())
}

/// Validates the timestamp field of an SCT per RFC 6962 §3.2.
///
/// The timestamp is encoded as a 64-bit unsigned integer giving the
/// milliseconds since the UNIX epoch.  Any `u64` value is structurally
/// valid; this helper rejects only the sentinel `0`, which the C
/// implementation treats as "uninitialised", and signals a configuration
/// error via [`CryptoError::Verification`].
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `timestamp == 0`.
///
/// # Note on Sentinels (Rule R5)
///
/// This function exists so that callers can opt in to rejecting the
/// historic uninitialised-timestamp sentinel.  Type-safe SCT construction
/// via [`SignedCertificateTimestampBuilder`] does not require its use,
/// because the builder requires the caller to pass a `u64` explicitly.
pub fn validate_timestamp(timestamp: u64) -> CryptoResult<()> {
    if timestamp == 0 {
        Err(CryptoError::Verification(
            "SCT timestamp is 0 (RFC 6962 §3.2 timestamp = ms since UNIX epoch; \
             0 indicates uninitialised state)"
                .into(),
        ))
    } else {
        Ok(())
    }
}

// =============================================================================
// SignedCertificateTimestamp — RFC 6962 §3.2 SCT structure
// =============================================================================

/// Foundational, in-memory representation of a Signed Certificate Timestamp
/// (SCT) as defined by RFC 6962 §3.2.
///
/// All fields are validated at construction time via the
/// [`SignedCertificateTimestampBuilder`] type.  Read-only accessors are
/// provided per Rule R3 (Config Field Propagation).
///
/// # ASN.1 Reference (paraphrased from RFC 6962 §3.2)
///
/// ```text
/// struct {
///     Version sct_version;
///     LogID id;                               // 32-octet SHA-256
///     uint64 timestamp;                       // ms since UNIX epoch
///     CtExtensions extensions;                // <0..2^16-1>
///     digitally-signed struct { ... } signature;
/// } SignedCertificateTimestamp;
/// ```
///
/// This struct is **immutable** once constructed.  The C `SCT_set_*` /
/// `SCT_set0_*` mutator API surface is intentionally not replicated; CT
/// callers should construct fresh SCTs via the builder when assembling
/// proof material.  The validation status is the one mutable field
/// because policy evaluation updates it post-construction.
///
/// Field comment block reserving future RFC 6962 fields per Rule R3
/// (no field is stored before there is a read-site):
///
/// - `signature_nid` — NID of the signature algorithm (e.g. ECDSA-SHA256);
///   reserved for the eventual `SCT_get_signature_nid` translation.
/// - `signature_algorithm` — `DigitallySigned.algorithm` `SignatureAndHashAlgorithm`
///   structure; reserved for the v1 wire-format encoder/decoder.
/// - `extensions_decoded` — parsed view of `extensions` octet string;
///   reserved for the future CT extension registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCertificateTimestamp {
    version: SctVersion,
    log_entry_type: LogEntryType,
    log_id: Vec<u8>,
    timestamp: u64,
    extensions: Vec<u8>,
    signature: Vec<u8>,
    source: Option<SctSource>,
    validation_status: SctValidationStatus,
}

impl SignedCertificateTimestamp {
    /// Returns the SCT version (RFC 6962 §3.2 `sct_version`).
    #[must_use]
    pub const fn version(&self) -> SctVersion {
        self.version
    }

    /// Returns the log entry type (RFC 6962 §3.1
    /// `MerkleTreeLeaf.timestamped_entry.entry_type`).
    #[must_use]
    pub const fn log_entry_type(&self) -> LogEntryType {
        self.log_entry_type
    }

    /// Returns the log identifier (`SHA-256(log-public-key)`, 32 octets for
    /// `SctVersion::V1` SCTs).
    #[must_use]
    pub fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    /// Returns the timestamp in milliseconds since the UNIX epoch.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Returns the (possibly empty) extensions octet string.
    #[must_use]
    pub fn extensions(&self) -> &[u8] {
        &self.extensions
    }

    /// Returns the encoded `DigitallySigned` signature blob.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the source from which this SCT was acquired, if known.
    #[must_use]
    pub const fn source(&self) -> Option<SctSource> {
        self.source
    }

    /// Returns the current validation status.
    #[must_use]
    pub const fn validation_status(&self) -> SctValidationStatus {
        self.validation_status
    }

    /// Updates the validation status.  This is the only mutator on
    /// [`SignedCertificateTimestamp`]; CT callers update the status as
    /// policy evaluation proceeds.
    pub fn set_validation_status(&mut self, status: SctValidationStatus) {
        self.validation_status = status;
    }

    /// Returns `true` if the SCT has been positively validated against a
    /// known CT log.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.validation_status.is_valid()
    }
}

// =============================================================================
// SignedCertificateTimestampBuilder — fluent SCT construction
// =============================================================================

/// Builder for [`SignedCertificateTimestamp`].
///
/// Construct via [`SignedCertificateTimestampBuilder::new`], chain setters
/// for each field, then call [`SignedCertificateTimestampBuilder::build`].
///
/// Mirrors the `SCT_new` + `SCT_set_*` / `SCT_set0_*` setter functions from
/// `crypto/ct/ct_sct.c`.  Builders capture the entire mutation surface in
/// one consuming-flow type, eliminating the risk of partially-constructed
/// SCTs that the C API permits.
#[derive(Debug, Clone)]
pub struct SignedCertificateTimestampBuilder {
    version: SctVersion,
    log_entry_type: LogEntryType,
    log_id: Option<Vec<u8>>,
    timestamp: Option<u64>,
    extensions: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    source: Option<SctSource>,
    validation_status: SctValidationStatus,
}

impl SignedCertificateTimestampBuilder {
    /// Creates a new builder with the given SCT version and default values
    /// for all other fields.
    ///
    /// Default values mirror `SCT_new()`:
    /// - `log_entry_type = LogEntryType::NotSet`
    /// - `log_id = None`
    /// - `timestamp = None`
    /// - `extensions = None` (interpreted as empty)
    /// - `signature = None`
    /// - `source = None`
    /// - `validation_status = SctValidationStatus::NotSet`
    #[must_use]
    pub const fn new(version: SctVersion) -> Self {
        Self {
            version,
            log_entry_type: LogEntryType::NotSet,
            log_id: None,
            timestamp: None,
            extensions: None,
            signature: None,
            source: None,
            validation_status: SctValidationStatus::NotSet,
        }
    }

    /// Sets the log entry type field.
    #[must_use]
    pub const fn log_entry_type(mut self, entry_type: LogEntryType) -> Self {
        self.log_entry_type = entry_type;
        self
    }

    /// Sets the log identifier (32 octets of SHA-256 for v1 SCTs).
    ///
    /// The length is validated at [`build`](Self::build) time against
    /// [`CT_V1_HASHLEN`] for v1 SCTs.
    #[must_use]
    pub fn log_id(mut self, log_id: Vec<u8>) -> Self {
        self.log_id = Some(log_id);
        self
    }

    /// Sets the timestamp in milliseconds since the UNIX epoch.
    #[must_use]
    pub const fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Sets the SCT extensions octet string (may be empty).
    ///
    /// The length is validated at [`build`](Self::build) time against
    /// [`MAX_SCT_EXTENSIONS_LEN`].
    #[must_use]
    pub fn extensions(mut self, extensions: Vec<u8>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Sets the encoded `DigitallySigned` signature blob.
    ///
    /// The length is validated at [`build`](Self::build) time to be in the
    /// range `1..=MAX_SCT_SIGNATURE_LEN`.
    #[must_use]
    pub fn signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Sets the SCT source (delivery mechanism).
    #[must_use]
    pub const fn source(mut self, source: SctSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets the initial validation status.
    ///
    /// Most callers should leave this as the default
    /// [`SctValidationStatus::NotSet`] and update via
    /// [`SignedCertificateTimestamp::set_validation_status`] after
    /// policy evaluation.
    #[must_use]
    pub const fn validation_status(mut self, status: SctValidationStatus) -> Self {
        self.validation_status = status;
        self
    }

    /// Validates and constructs a [`SignedCertificateTimestamp`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when:
    ///
    /// * `log_id` is not set (mandatory per RFC 6962 §3.2)
    /// * `signature` is not set (mandatory per RFC 6962 §3.2)
    /// * `timestamp` is not set (mandatory per RFC 6962 §3.2)
    /// * `version == SctVersion::V1` but `log_id.len() != CT_V1_HASHLEN`
    /// * `extensions.len() > MAX_SCT_EXTENSIONS_LEN`
    /// * `signature` is empty or `signature.len() > MAX_SCT_SIGNATURE_LEN`
    pub fn build(self) -> CryptoResult<SignedCertificateTimestamp> {
        let log_id = self.log_id.ok_or_else(|| {
            CryptoError::Verification(
                "SCT requires log_id (RFC 6962 §3.2 mandates SHA-256 log identifier)".into(),
            )
        })?;
        let timestamp = self.timestamp.ok_or_else(|| {
            CryptoError::Verification(
                "SCT requires timestamp (RFC 6962 §3.2 mandates ms since UNIX epoch)".into(),
            )
        })?;
        let signature = self.signature.ok_or_else(|| {
            CryptoError::Verification(
                "SCT requires signature (RFC 6962 §3.2 mandates DigitallySigned blob)".into(),
            )
        })?;

        // V1 SCTs must have a 32-octet (CT_V1_HASHLEN) SHA-256 log ID.
        if self.version == SctVersion::V1 {
            validate_log_id(&log_id)?;
        }

        let extensions = self.extensions.unwrap_or_default();
        validate_sct_v1_extensions(&extensions)?;
        validate_signature(&signature)?;

        Ok(SignedCertificateTimestamp {
            version: self.version,
            log_entry_type: self.log_entry_type,
            log_id,
            timestamp,
            extensions,
            signature,
            source: self.source,
            validation_status: self.validation_status,
        })
    }
}

impl Default for SignedCertificateTimestampBuilder {
    fn default() -> Self {
        Self::new(SctVersion::default_value())
    }
}

// =============================================================================
// Module-level helpers
// =============================================================================

/// Returns every supported [`LogEntryType`] in discriminant-order.
///
/// Useful for diagnostics, completeness tests, and exhaustive parser
/// coverage.
#[must_use]
pub fn all_log_entry_types() -> Vec<LogEntryType> {
    vec![
        LogEntryType::NotSet,
        LogEntryType::X509,
        LogEntryType::Precert,
    ]
}

/// Returns every supported [`SctVersion`] in discriminant-order.
#[must_use]
pub fn all_sct_versions() -> Vec<SctVersion> {
    vec![SctVersion::NotSet, SctVersion::V1]
}

/// Returns every supported [`SctSource`] in discriminant-order.
#[must_use]
pub fn all_sct_sources() -> Vec<SctSource> {
    vec![
        SctSource::Unknown,
        SctSource::TlsExtension,
        SctSource::X509v3Extension,
        SctSource::OcspStapledResponse,
    ]
}

/// Returns every supported [`SctValidationStatus`] in discriminant-order.
#[must_use]
pub fn all_sct_validation_statuses() -> Vec<SctValidationStatus> {
    vec![
        SctValidationStatus::NotSet,
        SctValidationStatus::UnknownLog,
        SctValidationStatus::Valid,
        SctValidationStatus::Invalid,
        SctValidationStatus::Unverified,
        SctValidationStatus::UnknownVersion,
    ]
}

/// Returns a `HashSet` of every supported [`SctValidationStatus`] value.
///
/// Useful in tests that need to verify exhaustive coverage of the
/// validation-status code space.
#[must_use]
pub fn all_sct_validation_statuses_set() -> HashSet<SctValidationStatus> {
    [
        SctValidationStatus::NotSet,
        SctValidationStatus::UnknownLog,
        SctValidationStatus::Valid,
        SctValidationStatus::Invalid,
        SctValidationStatus::Unverified,
        SctValidationStatus::UnknownVersion,
    ]
    .into_iter()
    .collect()
}
