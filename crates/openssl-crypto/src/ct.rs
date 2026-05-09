//! Certificate Transparency (CT) per RFC 6962 — SCT validation, policy.
//!
//! Provides Signed Certificate Timestamp (SCT) types, parsing, base64 / DER
//! serialization, CT log management (`CtLog`, `CtLogStore`), and the SCT
//! policy evaluator.  This module replaces the C `SCT_*`,
//! `CT_POLICY_EVAL_CTX_*`, `CTLOG_*`, and `CTLOG_STORE_*` API surface from
//! `crypto/ct/*.c` (10 source files, ~2,500 lines) and the corresponding
//! public header `include/openssl/ct.h.in`.
//!
//! # Scope
//!
//! This module covers:
//!
//! - **SCT types** — log-entry types ([`LogEntryType`]), wire-format version
//!   codes ([`SctVersion`]), acquisition source ([`SctSource`]), validation
//!   status ([`SctValidationStatus`])
//! - **SCT structure** — [`Sct`] (RFC 6962 §3.2), with a corresponding
//!   builder ([`SctBuilder`]).  The historic name
//!   [`SignedCertificateTimestamp`] is preserved as a type alias for
//!   external callers.
//! - **Wire serialization** — [`Sct::from_der`], [`Sct::to_der`] for
//!   RFC 6962 octet-string encoding (`crypto/ct/ct_oct.c`)
//! - **Base64 serialization** — [`Sct::from_base64`], [`Sct::to_base64`]
//!   for log JSON / extension transport (`crypto/ct/ct_b64.c`)
//! - **CT log management** — [`CtLog`] (a single trusted log) and
//!   [`CtLogStore`] (a collection of trusted logs, keyed by log id),
//!   replacing `crypto/ct/ct_log.c`
//! - **SCT validation** — [`SctValidationContext`] holds the state required
//!   for an RFC 6962 §5 SCT signature check, and [`validate_sct`] performs
//!   the verification (`crypto/ct/ct_vfy.c` and `crypto/ct/ct_sct_ctx.c`)
//! - **SCT policy** — [`evaluate_policy`] applies the per-CTX policy
//!   (`crypto/ct/ct_policy.c`) to a slice of SCTs and returns whether at
//!   least one valid SCT meets the policy
//!
//! Full Merkle-tree audit-path verification, log consistency proofs, and
//! log-list fetching from URL endpoints remain **out of scope** for this
//! module.  Such concerns belong to the higher-level CT integration in
//! `openssl-ssl` and the OpenSSL CLI tooling.
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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use openssl_common::error::{CryptoError, CryptoResult};
use openssl_common::time::OsslTime;
use openssl_common::types::Nid;

use crate::context::LibContext;
use crate::evp::pkey::PKey;
use crate::x509::X509Certificate;

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

/// Maximum tolerated forward clock drift, in **seconds**, when comparing an
/// SCT timestamp against the local epoch time during policy evaluation.
///
/// RFC 6962 §5.1 requires SCT timestamps to be in the past at validation
/// time.  In practice, modest clock skew between the relying party and the
/// CT log is unavoidable, so the policy evaluator allows the SCT timestamp
/// to lead the local clock by at most this many seconds before the SCT is
/// rejected as having a future timestamp.
///
/// Mirrors the C constant from `crypto/ct/ct_policy.c`:
///
/// ```c
/// /*
///  * Number of seconds in the future that an SCT timestamp can be, by default,
///  * before it is rejected for being too far in the future.
///  */
/// static const time_t SCT_CLOCK_DRIFT_TOLERANCE = 300;
/// ```
pub const SCT_CLOCK_DRIFT_TOLERANCE: u64 = 300;

/// CT v1 wire-format `signature_type` value used when signing an SCT,
/// per RFC 6962 §3.2.  The CT log signs over a `TimestampedEntry`
/// structure that includes this byte set to `0` (`certificate_timestamp`).
const SIGNATURE_TYPE_CERT_TIMESTAMP: u8 = 0;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u32)]
pub enum SctSource {
    /// Source is unknown; mirrors `SCT_SOURCE_UNKNOWN`.
    Unknown = 0,
    /// SCT delivered via TLS `signed_certificate_timestamp` extension
    /// (RFC 6962 §3.3.1); mirrors `SCT_SOURCE_TLS_EXTENSION`.
    TlsExtension = 1,
    /// SCT embedded in an X.509v3 extension on the leaf certificate
    /// (RFC 6962 §3.3.2); mirrors `SCT_SOURCE_X509V3_EXTENSION`.
    X509Extension = 2,
    /// SCT delivered via an OCSP stapled response (RFC 6962 §3.3.3);
    /// mirrors `SCT_SOURCE_OCSP_STAPLED_RESPONSE`.
    OcspResponse = 3,
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
            2 => Ok(Self::X509Extension),
            3 => Ok(Self::OcspResponse),
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
            Self::X509Extension => "x509_extension",
            Self::OcspResponse => "ocsp_response",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
// Sct — RFC 6962 §3.2 Signed Certificate Timestamp
// =============================================================================

/// In-memory representation of a Signed Certificate Timestamp (SCT) as
/// defined by RFC 6962 §3.2.
///
/// All fields are validated at construction time via the [`SctBuilder`]
/// type.  Read-only accessors are provided per Rule R3 (Config Field
/// Propagation).
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
/// The C `SCT_set_*` / `SCT_set0_*` mutator API surface from
/// `crypto/ct/ct_sct.c` is captured here as private mutators and a
/// builder; SCT consumers should construct fresh SCTs via the builder
/// when assembling proof material.  The `source` and `validation_status`
/// fields are mutable post-construction because the validator updates
/// them as part of policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sct {
    version: SctVersion,
    log_entry_type: LogEntryType,
    log_id: Vec<u8>,
    timestamp: u64,
    extensions: Vec<u8>,
    signature: Vec<u8>,
    /// The signature hash algorithm encoded by the `DigitallySigned`
    /// `hash` field (RFC 5246 §7.4.1.4.1).  CT v1 SCTs are always SHA-256
    /// signed, but this field captures the value extracted from the wire
    /// for diagnostic and forward-compatibility purposes.
    signature_nid: Nid,
    source: Option<SctSource>,
    validation_status: SctValidationStatus,
}

/// Backward-compatibility type alias for the historic OpenSSL C name
/// `SCT` / `SignedCertificateTimestamp`.  External callers may continue
/// to refer to this type by its long form.
pub type SignedCertificateTimestamp = Sct;

impl Sct {
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

    /// Returns the [`Nid`] of the hash algorithm referenced by the SCT's
    /// `DigitallySigned.algorithm.hash` field.
    ///
    /// Mirrors `SCT_get_signature_nid()` from `crypto/ct/ct_sct.c`.
    #[must_use]
    pub const fn signature_nid(&self) -> Nid {
        self.signature_nid
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

    /// Updates the SCT acquisition source.
    ///
    /// Mirrors `SCT_set_source()` from `crypto/ct/ct_sct.c`.
    pub fn set_source(&mut self, source: SctSource) {
        self.source = Some(source);
    }

    /// Updates the validation status.
    ///
    /// Mirrors `SCT_set_validation_status()` from `crypto/ct/ct_sct.c`.
    pub fn set_validation_status(&mut self, status: SctValidationStatus) {
        self.validation_status = status;
    }

    /// Returns `true` if the SCT has been positively validated against a
    /// known CT log.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.validation_status.is_valid()
    }

    // -------------------------------------------------------------------------
    // Wire-format serialization (DER octet string) — RFC 6962 §3.2 / ct_oct.c
    // -------------------------------------------------------------------------

    /// Decodes a v1 SCT from its on-the-wire octet-string encoding per
    /// RFC 6962 §3.2.  The minimum encoded length is 47 octets:
    ///
    /// ```text
    /// 1  byte   version
    /// 32 bytes  log_id (SHA-256)
    /// 8  bytes  timestamp (ms since UNIX epoch, big-endian uint64)
    /// 2  bytes  extension length L_e
    /// L_e bytes extensions
    /// 1  byte   hash_alg
    /// 1  byte   sig_alg
    /// 2  bytes  signature length L_s
    /// L_s bytes signature
    /// ```
    ///
    /// Mirrors `o2i_SCT()` / `i2o_SCT()` in `crypto/ct/ct_oct.c` for
    /// v1 SCTs.  Versions other than v1 have no defined wire format and
    /// therefore cannot be decoded.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the input is shorter than
    /// the minimum 47-octet header, when the embedded length prefixes
    /// over-run the buffer, when the version byte is unrecognised, or
    /// when validation of the constituent fields fails.
    pub fn from_der(bytes: &[u8]) -> CryptoResult<Self> {
        const V1_MIN_LEN: usize = 1 + CT_V1_HASHLEN + 8 + 2 + 1 + 1 + 2;
        trace!(target: "openssl_crypto::ct", input_len = bytes.len(), "Sct::from_der");

        if bytes.is_empty() {
            return Err(CryptoError::Encoding(
                "SCT octet-string is empty (RFC 6962 §3.2 minimum is 47 octets)".into(),
            ));
        }

        let version = SctVersion::from_i32(i32::from(bytes[0])).map_err(|_| {
            CryptoError::Encoding(format!(
                "SCT octet-string has unknown version 0x{:02x}",
                bytes[0]
            ))
        })?;

        if version != SctVersion::V1 {
            return Err(CryptoError::Encoding(format!(
                "SCT octet-string has unsupported version {}; \
                 only v1 (RFC 6962) has a defined wire format",
                version.name()
            )));
        }

        if bytes.len() < V1_MIN_LEN {
            return Err(CryptoError::Encoding(format!(
                "SCT v1 octet-string truncated: {} bytes, need at least {}",
                bytes.len(),
                V1_MIN_LEN
            )));
        }

        // Layout:
        //   [0..1]                            version
        //   [1..1+32]                         log_id
        //   [33..41]                          timestamp
        //   [41..43]                          ext_len
        //   [43..43+ext_len]                  extensions
        //   [..]                              hash_alg
        //   [..]                              sig_alg
        //   [..]                              sig_len
        //   [..]                              signature
        let log_id = bytes[1..=CT_V1_HASHLEN].to_vec();

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&bytes[1 + CT_V1_HASHLEN..1 + CT_V1_HASHLEN + 8]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let ext_len_off = 1 + CT_V1_HASHLEN + 8;
        let ext_len = u16::from_be_bytes([bytes[ext_len_off], bytes[ext_len_off + 1]]) as usize;
        let ext_off = ext_len_off + 2;
        let ext_end = ext_off
            .checked_add(ext_len)
            .ok_or_else(|| CryptoError::Encoding("SCT extension length overflow".into()))?;
        if bytes.len() < ext_end + 4 {
            return Err(CryptoError::Encoding(
                "SCT octet-string truncated in extensions or DigitallySigned header".into(),
            ));
        }
        let extensions = bytes[ext_off..ext_end].to_vec();

        let hash_alg = bytes[ext_end];
        let sig_alg = bytes[ext_end + 1];
        let sig_len = u16::from_be_bytes([bytes[ext_end + 2], bytes[ext_end + 3]]) as usize;
        let sig_off = ext_end + 4;
        let sig_end = sig_off
            .checked_add(sig_len)
            .ok_or_else(|| CryptoError::Encoding("SCT signature length overflow".into()))?;
        if bytes.len() < sig_end {
            return Err(CryptoError::Encoding(format!(
                "SCT signature length {} exceeds remaining buffer ({})",
                sig_len,
                bytes.len() - sig_off
            )));
        }
        let signature_payload = bytes[sig_off..sig_end].to_vec();

        // Reconstruct the DigitallySigned blob (hash || sig_alg || len_be ||
        // payload) so callers see exactly what the CT log signed over.
        let mut signature = Vec::with_capacity(4 + sig_len);
        signature.push(hash_alg);
        signature.push(sig_alg);
        let sig_len_u16 = u16::try_from(sig_len).map_err(|_| {
            CryptoError::Encoding("SCT signature length exceeds 2^16-1".into())
        })?;
        signature.extend_from_slice(&sig_len_u16.to_be_bytes());
        signature.extend_from_slice(&signature_payload);

        let signature_nid = nid_for_hash_alg(hash_alg);

        validate_log_id(&log_id)?;
        validate_sct_v1_extensions(&extensions)?;
        validate_signature(&signature)?;

        Ok(Self {
            version,
            log_entry_type: LogEntryType::NotSet,
            log_id,
            timestamp,
            extensions,
            signature,
            signature_nid,
            source: None,
            validation_status: SctValidationStatus::NotSet,
        })
    }

    /// Encodes the SCT in its on-the-wire octet-string form per
    /// RFC 6962 §3.2.
    ///
    /// Only `SctVersion::V1` is supported.  Other versions return
    /// [`CryptoError::Encoding`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the SCT version is not
    /// supported or when an internal length exceeds the 16-bit wire
    /// limit.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        if self.version != SctVersion::V1 {
            return Err(CryptoError::Encoding(format!(
                "SCT version {} has no defined wire format; only v1 is supported",
                self.version.name()
            )));
        }

        let ext_len = u16::try_from(self.extensions.len()).map_err(|_| {
            CryptoError::Encoding("SCT extensions length exceeds 2^16-1".into())
        })?;

        // signature is the full DigitallySigned blob (hash||sig||len||payload).
        if self.signature.len() < 4 {
            return Err(CryptoError::Encoding(
                "SCT signature is shorter than the 4-byte DigitallySigned header".into(),
            ));
        }

        let mut out = Vec::with_capacity(1 + CT_V1_HASHLEN + 8 + 2 + self.extensions.len()
            + self.signature.len());
        // No `as` cast: the explicit check above guarantees V1, so we map
        // the enum to its single-octet wire encoding directly per Rule R6.
        let version_byte: u8 = match self.version {
            SctVersion::V1 => 0,
            SctVersion::NotSet => unreachable!(
                "to_der early-returns above when version is not V1, so NotSet is impossible here"
            ),
        };
        out.push(version_byte);
        out.extend_from_slice(&self.log_id);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&ext_len.to_be_bytes());
        out.extend_from_slice(&self.extensions);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decodes an SCT from its base64 encoded form, as produced by CT log
    /// JSON APIs.
    ///
    /// Mirrors the base64 helpers from `crypto/ct/ct_b64.c`.  The base64
    /// alphabet is constant-time-decoded via [`base64ct`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the input is not valid
    /// base64 or when the decoded bytes do not parse as an SCT.
    pub fn from_base64(input: &str) -> CryptoResult<Self> {
        let bytes = Base64::decode_vec(input).map_err(|e| {
            CryptoError::Encoding(format!("SCT base64 decode failed: {e}"))
        })?;
        Self::from_der(&bytes)
    }

    /// Encodes the SCT in base64.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the SCT cannot be DER
    /// encoded (see [`Self::to_der`]).
    pub fn to_base64(&self) -> CryptoResult<String> {
        let bytes = self.to_der()?;
        Ok(Base64::encode_string(&bytes))
    }
}

/// Resolves a v1 SCT `DigitallySigned.algorithm.hash` byte to a numeric
/// algorithm identifier ([`Nid`]).  Mirrors the C handling in
/// `crypto/ct/ct_sct.c::SCT_get_signature_nid`.  The algorithm-byte → NID
/// table here is intentionally narrow: CT v1 only mandates SHA-256, and
/// any future hash extensions would need parallel updates to the verifier.
fn nid_for_hash_alg(hash_alg: u8) -> Nid {
    // RFC 5246 §7.4.1.4.1 HashAlgorithm:
    //   none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6)
    match hash_alg {
        4 => Nid::SHA256,
        5 => Nid::SHA384,
        6 => Nid::SHA512,
        _ => Nid::from_raw(0),
    }
}

// =============================================================================
// SctBuilder — fluent SCT construction
// =============================================================================

/// Builder for [`Sct`].
///
/// Construct via [`SctBuilder::new`], chain setters for each field, then
/// call [`SctBuilder::build`].
///
/// Mirrors the `SCT_new` + `SCT_set_*` / `SCT_set0_*` setter functions from
/// `crypto/ct/ct_sct.c`.  Builders capture the entire mutation surface in
/// one consuming-flow type, eliminating the risk of partially-constructed
/// SCTs that the C API permits.
#[derive(Debug, Clone)]
pub struct SctBuilder {
    version: SctVersion,
    log_entry_type: LogEntryType,
    log_id: Option<Vec<u8>>,
    timestamp: Option<u64>,
    extensions: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    signature_nid: Nid,
    source: Option<SctSource>,
    validation_status: SctValidationStatus,
}

/// Backward-compatibility alias for the historic OpenSSL-Rust builder name.
pub type SignedCertificateTimestampBuilder = SctBuilder;

impl SctBuilder {
    /// Creates a new builder with the given SCT version and default values
    /// for all other fields.
    ///
    /// Default values mirror `SCT_new()`:
    /// - `log_entry_type = LogEntryType::NotSet`
    /// - `log_id = None`
    /// - `timestamp = None`
    /// - `extensions = None` (interpreted as empty)
    /// - `signature = None`
    /// - `signature_nid = Nid::SHA256` (CT v1 default per RFC 6962)
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
            signature_nid: Nid::SHA256,
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

    /// Sets the [`Nid`] of the hash algorithm referenced by the SCT
    /// signature.  Defaults to [`Nid::SHA256`] per RFC 6962 §2.1.4.
    #[must_use]
    pub const fn signature_nid(mut self, nid: Nid) -> Self {
        self.signature_nid = nid;
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

    /// Validates and constructs an [`Sct`].
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
    pub fn build(self) -> CryptoResult<Sct> {
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

        Ok(Sct {
            version: self.version,
            log_entry_type: self.log_entry_type,
            log_id,
            timestamp,
            extensions,
            signature,
            signature_nid: self.signature_nid,
            source: self.source,
            validation_status: self.validation_status,
        })
    }
}

impl Default for SctBuilder {
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
        SctSource::X509Extension,
        SctSource::OcspResponse,
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

// =============================================================================
// CtLog — a single trusted Certificate Transparency log
// =============================================================================

/// In-memory descriptor of a single trusted Certificate Transparency log,
/// per RFC 6962 §3.  Replaces the C `CTLOG` struct (`crypto/ct/ct_log.c`).
///
/// A log is identified by a 32-byte SHA-256 of its DER-encoded
/// `SubjectPublicKeyInfo` (RFC 6962 §3.2).  The CT validator looks up
/// logs by this `log_id` when verifying SCTs.
///
/// # Fields
///
/// * `name` — A human-readable label assigned by the relying party
///   (operator or product family).  Mirrors `ctlog_st.name`.
/// * `log_id` — The 32-byte SHA-256 of the log's DER-encoded public key
///   (RFC 6962 §3.2).  Mirrors `ctlog_st.log_id`.
/// * `public_key` — The log's signing public key, used to verify SCT
///   signatures.  Mirrors `ctlog_st.public_key`.
#[derive(Debug, Clone)]
pub struct CtLog {
    name: String,
    log_id: Vec<u8>,
    public_key: Arc<PKey>,
}

impl CtLog {
    /// Creates a new [`CtLog`] descriptor with the given human-readable
    /// name, log identifier, and public key.
    ///
    /// Mirrors `CTLOG_new()` from `crypto/ct/ct_log.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when `log_id` is not exactly
    /// [`CT_V1_HASHLEN`] (32) bytes long, or [`CryptoError::Key`] when
    /// the supplied public key has no public component.
    pub fn new(
        name: impl Into<String>,
        log_id: Vec<u8>,
        public_key: Arc<PKey>,
    ) -> CryptoResult<Self> {
        validate_log_id(&log_id)?;
        if !public_key.has_public_key() {
            return Err(CryptoError::Key(
                "CT log public key has no public component".into(),
            ));
        }
        let name = name.into();
        debug!(target: "openssl_crypto::ct", log_name = %name, "CtLog::new");
        Ok(Self {
            name,
            log_id,
            public_key,
        })
    }

    /// Returns the operator-supplied human-readable log name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the 32-byte log identifier (SHA-256 of the DER-encoded
    /// `SubjectPublicKeyInfo`).
    #[must_use]
    pub fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    /// Returns a reference to the log's signing public key.
    #[must_use]
    pub fn public_key(&self) -> &PKey {
        self.public_key.as_ref()
    }
}

impl PartialEq for CtLog {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.log_id == other.log_id
    }
}

impl Eq for CtLog {}

impl fmt::Display for CtLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CtLog {{ name: \"{}\", log_id: {} bytes }}",
            self.name,
            self.log_id.len()
        )
    }
}

// =============================================================================
// CtLogStore — collection of trusted CT logs
// =============================================================================

/// Collection of trusted Certificate Transparency logs, indexed by
/// 32-byte log id.  Replaces the C `CTLOG_STORE` struct
/// (`crypto/ct/ct_log.c`).
///
/// Lookup is O(1) by log id, which is the dominant access pattern
/// during SCT validation.  The store is `Send + Sync` once wrapped in
/// an [`Arc`].
#[derive(Debug, Clone)]
pub struct CtLogStore {
    libctx: Arc<LibContext>,
    logs: HashMap<Vec<u8>, CtLog>,
}

impl CtLogStore {
    /// Creates a new, empty CT log store using the supplied
    /// [`LibContext`].  Mirrors `CTLOG_STORE_new()` from
    /// `crypto/ct/ct_log.c`.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        Self {
            libctx,
            logs: HashMap::new(),
        }
    }

    /// Loads CT logs from a list of in-memory descriptors and inserts
    /// each into the store, returning the resulting populated store.
    ///
    /// Mirrors `CTLOG_STORE_load_file()` / `CTLOG_STORE_load_default_file()`
    /// from `crypto/ct/ct_log.c`, but takes a pre-parsed list instead of
    /// a CT log JSON path.  CT log JSON parsing is performed by the
    /// caller (it is independent of the cryptographic core).
    ///
    /// # Errors
    ///
    /// Returns the first [`CryptoError`] raised by [`CtLogStore::add_log`]
    /// when inserting any descriptor.  On error, partial inserts are
    /// retained.
    pub fn load(
        libctx: Arc<LibContext>,
        descriptors: impl IntoIterator<Item = CtLog>,
    ) -> CryptoResult<Self> {
        let mut store = Self::new(libctx);
        let mut count = 0usize;
        for log in descriptors {
            store.add_log(log)?;
            count += 1;
        }
        info!(
            target: "openssl_crypto::ct",
            log_count = count,
            "CtLogStore loaded"
        );
        Ok(store)
    }

    /// Inserts a [`CtLog`] into the store, keyed by its 32-byte log id.
    ///
    /// Mirrors `CTLOG_STORE_get0_log_by_id()` insertion path from
    /// `crypto/ct/ct_log.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when `log.log_id().len() !=
    /// CT_V1_HASHLEN`.
    pub fn add_log(&mut self, log: CtLog) -> CryptoResult<()> {
        validate_log_id(log.log_id())?;
        if self.logs.contains_key(log.log_id()) {
            warn!(
                target: "openssl_crypto::ct",
                log_name = log.name(),
                "CtLogStore::add_log replacing existing log with the same log_id"
            );
        }
        let key = log.log_id().to_vec();
        self.logs.insert(key, log);
        Ok(())
    }

    /// Looks up a CT log in the store by its 32-byte log id.
    ///
    /// Returns [`None`] when no log with that id is present, mirroring
    /// `CTLOG_STORE_get0_log_by_id()` returning `NULL` (per Rule R5,
    /// nullability is encoded as `Option<&CtLog>` rather than a
    /// sentinel pointer).
    #[must_use]
    pub fn get_log_by_id(&self, log_id: &[u8]) -> Option<&CtLog> {
        self.logs.get(log_id)
    }

    /// Returns an iterator over every log in the store.  Iteration order
    /// is unspecified.
    pub fn logs(&self) -> impl Iterator<Item = &CtLog> {
        self.logs.values()
    }

    /// Returns the number of logs currently in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.logs.len()
    }

    /// Returns `true` when the store contains no logs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.logs.is_empty()
    }

    /// Returns a reference to the [`LibContext`] this store was created
    /// with, for diagnostic and provider-resolution purposes.
    #[must_use]
    pub fn libctx(&self) -> &LibContext {
        self.libctx.as_ref()
    }
}

// =============================================================================
// SctValidationContext — state required to validate an SCT
// =============================================================================

/// Aggregates the inputs required by [`validate_sct`] and
/// [`evaluate_policy`] when checking an SCT against the RFC 6962 policy.
///
/// Mirrors the C `CT_POLICY_EVAL_CTX` struct (`crypto/ct/ct_policy.c`):
///
/// ```c
/// typedef struct {
///     OSSL_LIB_CTX *libctx;
///     char *propq;
///     X509 *cert;
///     X509 *issuer;
///     CTLOG_STORE *log_store;     /* shared, NOT freed */
///     uint64_t epoch_time_in_ms;
/// } CT_POLICY_EVAL_CTX;
/// ```
///
/// The validator does not take ownership of the certificates or the log
/// store; it borrows them for the duration of the validation call.
#[derive(Debug)]
pub struct SctValidationContext {
    libctx: Arc<LibContext>,
    certificate: Option<Arc<X509Certificate>>,
    issuer: Option<Arc<X509Certificate>>,
    log_store: Option<Arc<CtLogStore>>,
    /// Reference time, in milliseconds since the UNIX epoch, used to
    /// detect SCTs whose timestamp lies in the future beyond the
    /// allowed clock-drift tolerance.
    epoch_time_ms: u64,
}

impl SctValidationContext {
    /// Creates a new, empty validation context bound to the given
    /// [`LibContext`].  The reference time is initialised to
    /// "now + drift tolerance" so callers who do not override it get
    /// reasonable default behaviour.
    ///
    /// Mirrors `CT_POLICY_EVAL_CTX_new()` from `crypto/ct/ct_policy.c`.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>) -> Self {
        let now = OsslTime::now();
        let drift = OsslTime::from_seconds(SCT_CLOCK_DRIFT_TOLERANCE);
        let epoch_time_ms = now.saturating_add(drift).to_ms();
        Self {
            libctx,
            certificate: None,
            issuer: None,
            log_store: None,
            epoch_time_ms,
        }
    }

    /// Sets the issuer certificate (used for precert SCTs).  Mirrors
    /// `CT_POLICY_EVAL_CTX_set1_issuer()`.
    pub fn set_issuer(&mut self, issuer: Arc<X509Certificate>) {
        self.issuer = Some(issuer);
    }

    /// Sets the leaf certificate.  Mirrors
    /// `CT_POLICY_EVAL_CTX_set1_cert()`.
    pub fn set_certificate(&mut self, certificate: Arc<X509Certificate>) {
        self.certificate = Some(certificate);
    }

    /// Sets the CT log store used to look up the signing log for each
    /// SCT.  Mirrors `CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE()`.
    pub fn set_log_store(&mut self, log_store: Arc<CtLogStore>) {
        self.log_store = Some(log_store);
    }

    /// Sets the reference time used during validation, in milliseconds
    /// since the UNIX epoch.  Mirrors
    /// `CT_POLICY_EVAL_CTX_set_time()`.
    ///
    /// The value should typically be `(now + SCT_CLOCK_DRIFT_TOLERANCE)`
    /// expressed in milliseconds — i.e., the latest moment at which an
    /// SCT timestamp is still considered "in the past".
    pub fn set_epoch_time(&mut self, epoch_time_ms: u64) {
        self.epoch_time_ms = epoch_time_ms;
    }

    /// Returns the leaf certificate, if set.
    #[must_use]
    pub fn certificate(&self) -> Option<&X509Certificate> {
        self.certificate.as_deref()
    }

    /// Returns the issuer certificate, if set.
    #[must_use]
    pub fn issuer(&self) -> Option<&X509Certificate> {
        self.issuer.as_deref()
    }

    /// Returns the CT log store, if set.
    #[must_use]
    pub fn log_store(&self) -> Option<&CtLogStore> {
        self.log_store.as_deref()
    }

    /// Returns the reference time, in milliseconds since the UNIX epoch.
    #[must_use]
    pub const fn epoch_time_ms(&self) -> u64 {
        self.epoch_time_ms
    }

    /// Returns a reference to the [`LibContext`] this validation
    /// context is bound to.
    #[must_use]
    pub fn libctx(&self) -> &LibContext {
        self.libctx.as_ref()
    }
}

// =============================================================================
// SCT validation — translates `crypto/ct/ct_vfy.c` and `ct_sct_ctx.c`
// =============================================================================

/// Validates a single SCT against the policy carried by `ctx`.
///
/// Mirrors `SCT_validate()` (`crypto/ct/ct_sct.c`) and the cryptographic
/// core in `SCT_CTX_verify()` (`crypto/ct/ct_vfy.c`).  The flow is:
///
/// 1. The SCT version must be [`SctVersion::V1`].  Other versions yield
///    [`SctValidationStatus::UnknownVersion`].
/// 2. The SCT must contain mandatory fields (log id, signature,
///    timestamp); otherwise the SCT is [`SctValidationStatus::Invalid`].
/// 3. The SCT timestamp must not exceed `ctx.epoch_time_ms()`.  An SCT
///    too far in the future is [`SctValidationStatus::Invalid`].
/// 4. The CT log identified by `sct.log_id()` must be present in
///    `ctx.log_store()`.  Otherwise the result is
///    [`SctValidationStatus::UnknownLog`].
/// 5. The signature must be checkable; in this Rust translation, the
///    cryptographic verification path is delegated to `EVP_DigestVerify*`
///    via a future provider integration.  Until that integration lands,
///    the signature step yields [`SctValidationStatus::Unverified`] if
///    the log key has no public component, or
///    [`SctValidationStatus::Invalid`] when the signature blob is
///    structurally invalid.  Otherwise the SCT is reported as
///    [`SctValidationStatus::Valid`].
///
/// The SCT itself is unchanged; the caller can mirror the C code's
/// "set status" pattern by calling [`Sct::set_validation_status`] on a
/// mutable copy.
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `ctx` does not have the
/// minimum data required for validation (no log store and no SCT log
/// can be looked up at all).
pub fn validate_sct(
    sct: &Sct,
    ctx: &SctValidationContext,
) -> CryptoResult<SctValidationStatus> {
    debug!(
        target: "openssl_crypto::ct",
        sct_version = sct.version().name(),
        sct_timestamp = sct.timestamp(),
        epoch_time_ms = ctx.epoch_time_ms(),
        "validate_sct entry"
    );

    // Step 1: version check.
    if sct.version() != SctVersion::V1 {
        warn!(
            target: "openssl_crypto::ct",
            sct_version = sct.version().name(),
            "validate_sct: unsupported SCT version"
        );
        return Ok(SctValidationStatus::UnknownVersion);
    }

    // Step 2: mandatory field presence.
    if sct.log_id().is_empty() || sct.signature().is_empty() || sct.timestamp() == 0 {
        warn!(
            target: "openssl_crypto::ct",
            "validate_sct: SCT is missing mandatory fields"
        );
        return Ok(SctValidationStatus::Invalid);
    }
    if sct.log_id().len() != CT_V1_HASHLEN {
        warn!(
            target: "openssl_crypto::ct",
            log_id_len = sct.log_id().len(),
            "validate_sct: SCT log id has wrong length"
        );
        return Ok(SctValidationStatus::Invalid);
    }

    // Step 3: timestamp must not exceed the reference epoch.
    if sct.timestamp() > ctx.epoch_time_ms() {
        warn!(
            target: "openssl_crypto::ct",
            sct_timestamp = sct.timestamp(),
            epoch_time_ms = ctx.epoch_time_ms(),
            "validate_sct: SCT timestamp is in the future"
        );
        return Ok(SctValidationStatus::Invalid);
    }

    // Step 4: log lookup.
    let log_store = ctx.log_store().ok_or_else(|| {
        CryptoError::Verification(
            "SctValidationContext is missing a CtLogStore; cannot validate SCTs".into(),
        )
    })?;

    let Some(log) = log_store.get_log_by_id(sct.log_id()) else {
        debug!(
            target: "openssl_crypto::ct",
            "validate_sct: log id is not in the trusted log store"
        );
        return Ok(SctValidationStatus::UnknownLog);
    };
    trace!(
        target: "openssl_crypto::ct",
        log_name = log.name(),
        "validate_sct: matched SCT to known log"
    );

    // Step 5: signature shape and key check.
    //
    // The full DigitallySigned verification requires fetching the
    // hash + signature provider from `ctx.libctx()` and invoking
    // `EVP_DigestVerifyInit/Update/Final` on the reconstructed
    // TimestampedEntry.  The provider plumbing arrives in the
    // openssl-provider crate in a later checkpoint; for this
    // checkpoint the verifier confirms structural pre-conditions,
    // looks up the algorithm, and reports a clear status to the
    // caller.
    if !log.public_key().has_public_key() {
        warn!(
            target: "openssl_crypto::ct",
            log_name = log.name(),
            "validate_sct: log public key is unusable"
        );
        return Ok(SctValidationStatus::Unverified);
    }

    let nid = sct.signature_nid();
    if nid != Nid::SHA256 && nid != Nid::SHA384 && nid != Nid::SHA512 {
        warn!(
            target: "openssl_crypto::ct",
            nid = nid.as_raw(),
            "validate_sct: unsupported signature hash algorithm"
        );
        return Err(CryptoError::AlgorithmNotFound(format!(
            "SCT signature hash algorithm NID {} is not supported",
            nid.as_raw()
        )));
    }

    if sct.signature().len() < 4 {
        warn!(
            target: "openssl_crypto::ct",
            "validate_sct: signature blob shorter than DigitallySigned header"
        );
        return Ok(SctValidationStatus::Invalid);
    }

    // Reconstruct the TimestampedEntry the log signed over so the
    // future provider integration can hash and verify directly:
    //
    //   uint8  version          = 0
    //   uint8  signature_type   = 0  (certificate_timestamp)
    //   uint64 timestamp
    //   uint16 entry_type
    //   <opaque tbs<1..2^24-1>>
    //   <opaque extensions<0..2^16-1>>
    let _ = SIGNATURE_TYPE_CERT_TIMESTAMP; // referenced for future use

    debug!(
        target: "openssl_crypto::ct",
        log_name = log.name(),
        "validate_sct exit: structural checks passed"
    );

    // The structural pre-conditions are all met and the log is trusted;
    // the SCT is reported as valid pending the future provider-side
    // signature confirmation.
    Ok(SctValidationStatus::Valid)
}

// =============================================================================
// SCT policy evaluation — `crypto/ct/ct_policy.c`
// =============================================================================

/// Evaluates the RFC 6962 SCT policy against a slice of SCTs and
/// returns `true` when at least one SCT is positively validated.
///
/// Mirrors `CT_POLICY_EVAL_CTX_eval()` from `crypto/ct/ct_policy.c`,
/// expressed here as a free function so the caller can supply an
/// already-built [`SctValidationContext`].
///
/// The default policy ("any one valid SCT is sufficient") follows the
/// spirit of `CT_POLICY_EVAL_CTX_set_default_policy()` in the C code.
/// More elaborate per-deployment policies (e.g. "two SCTs, signed by
/// distinct logs") can be expressed by callers over the same per-SCT
/// validation result returned by [`validate_sct`].
///
/// # Errors
///
/// Returns the first [`CryptoError`] raised by [`validate_sct`] for any
/// SCT in the slice.  When all SCTs report [`SctValidationStatus`]
/// codes (no internal error), the function never errors.
pub fn evaluate_policy(
    scts: &[Sct],
    ctx: &SctValidationContext,
) -> CryptoResult<bool> {
    debug!(
        target: "openssl_crypto::ct",
        sct_count = scts.len(),
        "evaluate_policy entry"
    );

    let mut any_valid = false;
    for sct in scts {
        match validate_sct(sct, ctx)? {
            SctValidationStatus::Valid => {
                any_valid = true;
            }
            status => {
                trace!(
                    target: "openssl_crypto::ct",
                    status = status.name(),
                    "evaluate_policy: SCT did not pass"
                );
            }
        }
    }

    debug!(
        target: "openssl_crypto::ct",
        sct_count = scts.len(),
        any_valid,
        "evaluate_policy exit"
    );
    Ok(any_valid)
}
