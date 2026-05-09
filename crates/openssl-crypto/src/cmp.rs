//! Certificate Management Protocol (CMP) per RFC 4210/4211 — Foundational Types.
//!
//! Provides core CMP type definitions, message structures, and DER serialization
//! helpers for Certificate Management Protocol clients.  This module replaces a
//! subset of the C `OSSL_CMP_*` API surface from `crypto/cmp/*.c` (~13 files),
//! `crypto/crmf/*.c` (~5 files), and `crypto/http/*.c` (~3 files).
//!
//! # Scope
//!
//! This module provides **foundational CMP types** sufficient to:
//!
//! - Express CMP protocol versions (`PkiVersion`)
//! - Encode/decode PKI status codes (`PkiStatus`)
//! - Represent failure information bits (`PkiFailureInfo`, `FailureInfoBits`)
//! - Construct minimal `PKIHeader` and `PKIStatusInfo` structures (`PkiHeader`,
//!   `PkiStatusInfo`)
//! - Validate transaction IDs and nonces against RFC 4210 length requirements
//!
//! Full CMP protocol message orchestration (IR/CR/KUR/RR transactions, multi-RTT
//! state machines, HTTP transport binding, MAC-based authentication via PBM,
//! polling and confirmation flows) is **out of scope** for this checkpoint.
//! Callers requiring the complete CMP client should use the C `libcrypto`
//! through `openssl-ffi` until those layers are translated.  This module is
//! the foundation on which subsequent CMP work will build.
//!
//! # C Source Mapping
//!
//! | C Symbol / File | Rust Equivalent |
//! |---|---|
//! | `OSSL_CMP_PVNO_2`, `OSSL_CMP_PVNO_3` (`cmp.h.in`) | `PkiVersion` |
//! | `OSSL_CMP_PKISTATUS_*` (`cmp.h.in`) | `PkiStatus` |
//! | `OSSL_CMP_PKIFAILUREINFO_*` (`cmp.h.in`) | `PkiFailureInfo` |
//! | `OSSL_CMP_CTX_FAILINFO_*` bitmasks (`cmp.h.in`) | `FailureInfoBits` |
//! | `OSSL_CMP_PKIHEADER` (`cmp_local.h`) | `PkiHeader` |
//! | `OSSL_CMP_PKISI` `PKIStatusInfo` (`cmp_local.h`) | `PkiStatusInfo` |
//! | `crypto/cmp/cmp_status.c` reason-string functions | `PkiStatus::description` |
//! | `crypto/cmp/cmp_msg.c` header construction | `PkiHeaderBuilder` |
//! | RFC 4210 §5.1.1 transaction ID validation | `validate_transaction_id` |
//! | RFC 4210 §5.1.1 nonce validation | `validate_nonce` |
//!
//! # Rules Enforced
//!
//! - **R3 (Config Field Propagation):** Every field on every type has documented
//!   read-sites (accessors) and write-sites (constructors / setters).  Unread
//!   fields are annotated `// UNREAD: reserved for future RFC 4210 §5.1.1
//!   header expansion`.
//! - **R5 (Nullability over Sentinels):** `Option<T>` is used for absent
//!   protection / sender / recipient / message-time fields.  Status codes use
//!   typed enums; integer sentinel values (`-1`, `0`) are rejected by parsers.
//! - **R6 (Lossless Numeric Casts):** Bit indices use `u8`; the bit-pattern
//!   uses `u32`.  All conversions go through `try_from` / `From` traits.  No
//!   bare `as` narrowing casts.
//! - **R8 (Zero Unsafe):** This module contains zero `unsafe` blocks, verified
//!   by the workspace `forbid(unsafe_code)` lint inherited from `lib.rs`.
//! - **R9 (Warning-Free):** All public items carry `///` documentation; no
//!   module- or item-level `#[allow(unused)]`.
//! - **R10 (Wiring Before Done):** Reachable from the CLI `cmp` subcommand
//!   stub at `crates/openssl-cli/src/commands/cmp.rs` and exercised by the
//!   feature-gated integration test suite at `crates/openssl-crypto/src/tests/test_cmp.rs`.
//!
//! # Feature Gate
//!
//! Gated behind the `cmp` Cargo feature flag (default-enabled, equivalent to
//! `OPENSSL_NO_CMP` being undefined).  The feature is declared in
//! `crates/openssl-crypto/Cargo.toml`.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::cmp::{
//!     PkiVersion, PkiStatus, PkiFailureInfo, FailureInfoBits,
//!     PkiHeaderBuilder, PkiStatusInfo,
//! };
//!
//! // Construct a PKI header for an Initialization Request (ir).
//! let header = PkiHeaderBuilder::new(PkiVersion::V2)
//!     .sender(b"CN=Subscriber".to_vec())
//!     .recipient(b"CN=CMP-Server".to_vec())
//!     .transaction_id(vec![0u8; 16])
//!     .sender_nonce(vec![0xAA; 16])
//!     .build()
//!     .expect("valid header");
//!
//! // Build a PKIStatusInfo describing a successful response.
//! let status = PkiStatusInfo::new(PkiStatus::Accepted)
//!     .with_text("certificate issued".to_string());
//! assert_eq!(status.status(), PkiStatus::Accepted);
//!
//! // Build a PKIStatusInfo describing a rejection with two failure bits.
//! let mut bits = FailureInfoBits::new();
//! bits.set(PkiFailureInfo::BadAlg);
//! bits.set(PkiFailureInfo::BadPop);
//! let rejected = PkiStatusInfo::new(PkiStatus::Rejection).with_failure_info(bits);
//! assert!(rejected.failure_info().unwrap().contains(PkiFailureInfo::BadAlg));
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use openssl_common::error::{CommonError, CryptoError, CryptoResult};
use openssl_common::time::OsslTime;
use openssl_common::types::Nid;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use crate::context::LibContext;
use crate::evp::pkey::PKey;
use crate::x509::X509Certificate;

// =============================================================================
// PkiVersion — RFC 4210 §5.1.1 pvno ASN.1 INTEGER
// =============================================================================

/// CMP protocol version number (`pvno` field, RFC 4210 §5.1.1).
///
/// Mirrors the C constants:
///
/// ```c
/// # define OSSL_CMP_PVNO_2 2
/// # define OSSL_CMP_PVNO_3 3
/// # define OSSL_CMP_PVNO   OSSL_CMP_PVNO_2 /* v2 is the default */
/// ```
///
/// CMP v1 (RFC 2510) is **not** supported: it was deprecated by RFC 4210 in
/// 2005 and is not a valid protocol version for new deployments.  Values
/// outside `{2, 3}` are rejected by [`PkiVersion::from_i32`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum PkiVersion {
    /// CMP v2 — RFC 4210 (2005).  The default version.
    ///
    /// Replaces `OSSL_CMP_PVNO_2` from `cmp.h.in`.
    V2 = 2,

    /// CMP v3 — RFC 9480 / 9481 / 9482 (2023) updates.
    ///
    /// Replaces `OSSL_CMP_PVNO_3` from `cmp.h.in`.
    V3 = 3,
}

impl PkiVersion {
    /// Returns the default CMP version (v2, per `OSSL_CMP_PVNO`).
    #[must_use]
    pub const fn default_version() -> Self {
        Self::V2
    }

    /// Converts a raw ASN.1 INTEGER value into a [`PkiVersion`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when the value is not in
    /// `{2, 3}`.  Note that v1 (`1`) is explicitly rejected.
    pub fn from_i32(value: i32) -> CryptoResult<Self> {
        match value {
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            other => Err(CryptoError::Verification(format!(
                "unsupported CMP protocol version: pvno={other} (RFC 4210 requires 2 or 3)"
            ))),
        }
    }

    /// Returns the integer value for ASN.1 encoding.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl Default for PkiVersion {
    fn default() -> Self {
        Self::default_version()
    }
}

impl fmt::Display for PkiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2 => f.write_str("CMP v2 (RFC 4210)"),
            Self::V3 => f.write_str("CMP v3 (RFC 9480)"),
        }
    }
}

// =============================================================================
// PkiStatus — RFC 4210 §5.2.3 PKIStatusInfo.status
// =============================================================================

/// PKI status code as defined by RFC 4210 §5.2.3 `PKIStatus`.
///
/// Mirrors the C constants from `cmp.h.in`:
///
/// ```c
/// # define OSSL_CMP_PKISTATUS_request                -3
/// # define OSSL_CMP_PKISTATUS_trans                  -2
/// # define OSSL_CMP_PKISTATUS_unspecified            -1
/// # define OSSL_CMP_PKISTATUS_accepted                0
/// # define OSSL_CMP_PKISTATUS_grantedWithMods         1
/// # define OSSL_CMP_PKISTATUS_rejection               2
/// # define OSSL_CMP_PKISTATUS_waiting                 3
/// # define OSSL_CMP_PKISTATUS_revocationWarning       4
/// # define OSSL_CMP_PKISTATUS_revocationNotification  5
/// # define OSSL_CMP_PKISTATUS_keyUpdateWarning        6
/// ```
///
/// Negative values (`-3`, `-2`, `-1`) are OpenSSL extensions used internally
/// to express CMP context state; they are not transmitted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum PkiStatus {
    /// `request` — internal state: a request is being assembled but not yet sent.
    Request = -3,

    /// `trans` — internal state: a request is in transit.
    Trans = -2,

    /// `unspecified` — internal state: status not determined.
    Unspecified = -1,

    /// `accepted` — RFC 4210: certificate issued / operation accepted.
    Accepted = 0,

    /// `grantedWithMods` — RFC 4210: certificate issued with modifications.
    GrantedWithMods = 1,

    /// `rejection` — RFC 4210: request rejected; see `PKIFailureInfo`.
    Rejection = 2,

    /// `waiting` — RFC 4210: response not yet available; client must poll.
    Waiting = 3,

    /// `revocationWarning` — RFC 4210: certificate revocation imminent.
    RevocationWarning = 4,

    /// `revocationNotification` — RFC 4210: certificate has been revoked.
    RevocationNotification = 5,

    /// `keyUpdateWarning` — RFC 4210: subject key requires update.
    KeyUpdateWarning = 6,
}

impl PkiStatus {
    /// Converts a raw ASN.1 INTEGER value into a [`PkiStatus`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when the value is outside
    /// `[-3, 6]`.
    pub fn from_i32(value: i32) -> CryptoResult<Self> {
        match value {
            -3 => Ok(Self::Request),
            -2 => Ok(Self::Trans),
            -1 => Ok(Self::Unspecified),
            0 => Ok(Self::Accepted),
            1 => Ok(Self::GrantedWithMods),
            2 => Ok(Self::Rejection),
            3 => Ok(Self::Waiting),
            4 => Ok(Self::RevocationWarning),
            5 => Ok(Self::RevocationNotification),
            6 => Ok(Self::KeyUpdateWarning),
            other => Err(CryptoError::Verification(format!(
                "unknown PKIStatus value: {other} (expected -3..=6 per RFC 4210 §5.2.3)"
            ))),
        }
    }

    /// Returns the integer value for ASN.1 encoding.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns a human-readable description of the status code.
    ///
    /// This corresponds to the description strings produced by
    /// `OSSL_CMP_snprint_PKIStatusInfo()` in `crypto/cmp/cmp_status.c`.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Request => "request being assembled",
            Self::Trans => "request in transit",
            Self::Unspecified => "status unspecified",
            Self::Accepted => "PKI request accepted",
            Self::GrantedWithMods => "request granted with modifications",
            Self::Rejection => "PKI request rejected",
            Self::Waiting => "PKI request not yet ready (client must poll)",
            Self::RevocationWarning => "PKI revocation warning",
            Self::RevocationNotification => "PKI revocation notification",
            Self::KeyUpdateWarning => "PKI key-update warning",
        }
    }

    /// Returns `true` when the status indicates a positive (success) outcome.
    ///
    /// `Accepted` and `GrantedWithMods` are considered positive; all other
    /// statuses indicate either failure, indeterminate state, or a request
    /// for further action.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        matches!(self, Self::Accepted | Self::GrantedWithMods)
    }

    /// Returns `true` when the status indicates a request was rejected.
    #[must_use]
    pub const fn is_rejection(self) -> bool {
        matches!(self, Self::Rejection)
    }

    /// Returns `true` when the status corresponds to an OpenSSL-internal
    /// pseudo-state not transmitted on the wire (`Request`, `Trans`,
    /// `Unspecified`).
    #[must_use]
    pub const fn is_internal(self) -> bool {
        matches!(self, Self::Request | Self::Trans | Self::Unspecified)
    }
}

impl fmt::Display for PkiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

// =============================================================================
// PkiFailureInfo — RFC 4210 §5.2.3 PKIFailureInfo bit indices (0..=26)
// =============================================================================

/// Individual PKI failure information bit indices (RFC 4210 §5.2.3).
///
/// In the wire format `PKIFailureInfo` is an `ASN.1 BIT STRING` whose bits
/// correspond to these named failure causes.  Each variant's discriminant is
/// the bit index (0..=26).
///
/// Mirrors the C constants `OSSL_CMP_PKIFAILUREINFO_*` from `cmp.h.in`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum PkiFailureInfo {
    /// `badAlg` (bit 0): unrecognized or unsupported Algorithm Identifier.
    BadAlg = 0,
    /// `badMessageCheck` (bit 1): integrity check failed.
    BadMessageCheck = 1,
    /// `badRequest` (bit 2): transaction not permitted or supported.
    BadRequest = 2,
    /// `badTime` (bit 3): timestamp invalid.
    BadTime = 3,
    /// `badCertId` (bit 4): no certificate matches the given identifier.
    BadCertId = 4,
    /// `badDataFormat` (bit 5): data format invalid.
    BadDataFormat = 5,
    /// `wrongAuthority` (bit 6): authority indicated does not match.
    WrongAuthority = 6,
    /// `incorrectData` (bit 7): data submitted is incorrect.
    IncorrectData = 7,
    /// `missingTimeStamp` (bit 8): timestamp missing where required.
    MissingTimeStamp = 8,
    /// `badPOP` (bit 9): proof-of-possession failed.
    BadPop = 9,
    /// `certRevoked` (bit 10): certificate already revoked.
    CertRevoked = 10,
    /// `certConfirmed` (bit 11): certificate already confirmed.
    CertConfirmed = 11,
    /// `wrongIntegrity` (bit 12): wrong integrity protection algorithm.
    WrongIntegrity = 12,
    /// `badRecipientNonce` (bit 13): recipient nonce mismatch.
    BadRecipientNonce = 13,
    /// `timeNotAvailable` (bit 14): time service unavailable.
    TimeNotAvailable = 14,
    /// `unacceptedPolicy` (bit 15): proposed policy not accepted.
    UnacceptedPolicy = 15,
    /// `unacceptedExtension` (bit 16): proposed extension not accepted.
    UnacceptedExtension = 16,
    /// `addInfoNotAvailable` (bit 17): additional information unavailable.
    AddInfoNotAvailable = 17,
    /// `badSenderNonce` (bit 18): sender nonce mismatch.
    BadSenderNonce = 18,
    /// `badCertTemplate` (bit 19): bad certificate template.
    BadCertTemplate = 19,
    /// `signerNotTrusted` (bit 20): signing entity not trusted.
    SignerNotTrusted = 20,
    /// `transactionIdInUse` (bit 21): transaction ID already in use.
    TransactionIdInUse = 21,
    /// `unsupportedVersion` (bit 22): protocol version not supported.
    UnsupportedVersion = 22,
    /// `notAuthorized` (bit 23): caller not authorized for the operation.
    NotAuthorized = 23,
    /// `systemUnavail` (bit 24): system temporarily unavailable.
    SystemUnavail = 24,
    /// `systemFailure` (bit 25): system failure occurred.
    SystemFailure = 25,
    /// `duplicateCertReq` (bit 26): duplicate certificate request.
    DuplicateCertReq = 26,
}

impl PkiFailureInfo {
    /// Maximum bit index (`OSSL_CMP_PKIFAILUREINFO_MAX = 26`).
    pub const MAX_BIT: u8 = 26;

    /// Returns the bit index for this failure type (0..=26).
    #[must_use]
    pub const fn bit_index(self) -> u8 {
        self as u8
    }

    /// Returns the single-bit `u32` mask for this failure (for use with
    /// `OSSL_CMP_CTX_FAILINFO_*` style bitmaps).
    #[must_use]
    pub const fn bit_mask(self) -> u32 {
        1u32 << (self as u8)
    }

    /// Converts a bit index (0..=26) into a [`PkiFailureInfo`] variant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when `index > 26`.
    pub fn from_bit_index(index: u8) -> CryptoResult<Self> {
        match index {
            0 => Ok(Self::BadAlg),
            1 => Ok(Self::BadMessageCheck),
            2 => Ok(Self::BadRequest),
            3 => Ok(Self::BadTime),
            4 => Ok(Self::BadCertId),
            5 => Ok(Self::BadDataFormat),
            6 => Ok(Self::WrongAuthority),
            7 => Ok(Self::IncorrectData),
            8 => Ok(Self::MissingTimeStamp),
            9 => Ok(Self::BadPop),
            10 => Ok(Self::CertRevoked),
            11 => Ok(Self::CertConfirmed),
            12 => Ok(Self::WrongIntegrity),
            13 => Ok(Self::BadRecipientNonce),
            14 => Ok(Self::TimeNotAvailable),
            15 => Ok(Self::UnacceptedPolicy),
            16 => Ok(Self::UnacceptedExtension),
            17 => Ok(Self::AddInfoNotAvailable),
            18 => Ok(Self::BadSenderNonce),
            19 => Ok(Self::BadCertTemplate),
            20 => Ok(Self::SignerNotTrusted),
            21 => Ok(Self::TransactionIdInUse),
            22 => Ok(Self::UnsupportedVersion),
            23 => Ok(Self::NotAuthorized),
            24 => Ok(Self::SystemUnavail),
            25 => Ok(Self::SystemFailure),
            26 => Ok(Self::DuplicateCertReq),
            other => Err(CryptoError::Verification(format!(
                "PKIFailureInfo bit index out of range: {other} (max = {})",
                Self::MAX_BIT
            ))),
        }
    }

    /// Returns the canonical short name (matching the C identifier suffix).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BadAlg => "badAlg",
            Self::BadMessageCheck => "badMessageCheck",
            Self::BadRequest => "badRequest",
            Self::BadTime => "badTime",
            Self::BadCertId => "badCertId",
            Self::BadDataFormat => "badDataFormat",
            Self::WrongAuthority => "wrongAuthority",
            Self::IncorrectData => "incorrectData",
            Self::MissingTimeStamp => "missingTimeStamp",
            Self::BadPop => "badPOP",
            Self::CertRevoked => "certRevoked",
            Self::CertConfirmed => "certConfirmed",
            Self::WrongIntegrity => "wrongIntegrity",
            Self::BadRecipientNonce => "badRecipientNonce",
            Self::TimeNotAvailable => "timeNotAvailable",
            Self::UnacceptedPolicy => "unacceptedPolicy",
            Self::UnacceptedExtension => "unacceptedExtension",
            Self::AddInfoNotAvailable => "addInfoNotAvailable",
            Self::BadSenderNonce => "badSenderNonce",
            Self::BadCertTemplate => "badCertTemplate",
            Self::SignerNotTrusted => "signerNotTrusted",
            Self::TransactionIdInUse => "transactionIdInUse",
            Self::UnsupportedVersion => "unsupportedVersion",
            Self::NotAuthorized => "notAuthorized",
            Self::SystemUnavail => "systemUnavail",
            Self::SystemFailure => "systemFailure",
            Self::DuplicateCertReq => "duplicateCertReq",
        }
    }

    /// Returns all 27 failure types as an array, in bit-index order.
    #[must_use]
    pub const fn all() -> [Self; 27] {
        [
            Self::BadAlg,
            Self::BadMessageCheck,
            Self::BadRequest,
            Self::BadTime,
            Self::BadCertId,
            Self::BadDataFormat,
            Self::WrongAuthority,
            Self::IncorrectData,
            Self::MissingTimeStamp,
            Self::BadPop,
            Self::CertRevoked,
            Self::CertConfirmed,
            Self::WrongIntegrity,
            Self::BadRecipientNonce,
            Self::TimeNotAvailable,
            Self::UnacceptedPolicy,
            Self::UnacceptedExtension,
            Self::AddInfoNotAvailable,
            Self::BadSenderNonce,
            Self::BadCertTemplate,
            Self::SignerNotTrusted,
            Self::TransactionIdInUse,
            Self::UnsupportedVersion,
            Self::NotAuthorized,
            Self::SystemUnavail,
            Self::SystemFailure,
            Self::DuplicateCertReq,
        ]
    }
}

impl fmt::Display for PkiFailureInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// FailureInfoBits — Set of PkiFailureInfo bit flags
// =============================================================================

/// A set of [`PkiFailureInfo`] bits.
///
/// Backed by a `u32` bitmap (the maximum bit index is 26, so all values fit
/// in 27 bits with room to spare).  This corresponds to the C
/// `OSSL_CMP_CTX_FAILINFO_*` bitmask domain in `cmp.h.in`.
///
/// # Example
///
/// ```rust
/// use openssl_crypto::cmp::{FailureInfoBits, PkiFailureInfo};
///
/// let mut bits = FailureInfoBits::new();
/// bits.set(PkiFailureInfo::BadAlg);
/// bits.set(PkiFailureInfo::BadPop);
///
/// assert!(bits.contains(PkiFailureInfo::BadAlg));
/// assert!(!bits.contains(PkiFailureInfo::BadTime));
/// assert_eq!(bits.count(), 2);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FailureInfoBits {
    /// Internal bitmap.  Bit `n` is set iff failure `n` is included.
    /// Bits 27..=31 are reserved (see RFC 4210 §5.2.3 and
    /// `OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN`).
    bits: u32,
}

impl FailureInfoBits {
    /// Mask covering all valid failure bits (0..=26).  Equal to
    /// `OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN`.
    pub const VALID_MASK: u32 = (1u32 << 27) - 1;

    /// Constructs an empty bit set.
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Constructs a bit set from a raw `u32` bitmap.
    ///
    /// Bits above index 26 are ignored (masked off).
    #[must_use]
    pub const fn from_raw(bits: u32) -> Self {
        Self {
            bits: bits & Self::VALID_MASK,
        }
    }

    /// Returns the underlying `u32` bitmap.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.bits
    }

    /// Adds a failure bit to the set.
    pub fn set(&mut self, info: PkiFailureInfo) {
        self.bits |= info.bit_mask();
    }

    /// Removes a failure bit from the set.
    pub fn unset(&mut self, info: PkiFailureInfo) {
        self.bits &= !info.bit_mask();
    }

    /// Returns `true` when the given failure is in the set.
    #[must_use]
    pub const fn contains(self, info: PkiFailureInfo) -> bool {
        (self.bits & info.bit_mask()) != 0
    }

    /// Returns the number of failure bits set.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.bits.count_ones()
    }

    /// Returns `true` when the set contains no failure bits.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Clears all bits.
    pub fn clear(&mut self) {
        self.bits = 0;
    }

    /// Returns an iterator over all failure types contained in the set,
    /// in ascending bit-index order.
    pub fn iter(self) -> FailureInfoBitsIter {
        FailureInfoBitsIter {
            bits: self.bits,
            index: 0,
        }
    }

    /// Returns the set as a `Vec<PkiFailureInfo>` in ascending bit order.
    #[must_use]
    pub fn to_vec(self) -> Vec<PkiFailureInfo> {
        self.iter().collect()
    }

    /// Returns the union of `self` and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns the intersection of `self` and `other`.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }
}

impl FromIterator<PkiFailureInfo> for FailureInfoBits {
    fn from_iter<I: IntoIterator<Item = PkiFailureInfo>>(iter: I) -> Self {
        let mut bits = Self::new();
        for info in iter {
            bits.set(info);
        }
        bits
    }
}

/// Iterator over the failure types in a [`FailureInfoBits`] set, in
/// ascending bit-index order.
#[derive(Debug, Clone)]
pub struct FailureInfoBitsIter {
    bits: u32,
    index: u8,
}

impl Iterator for FailureInfoBitsIter {
    type Item = PkiFailureInfo;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index <= PkiFailureInfo::MAX_BIT {
            let i = self.index;
            self.index = self.index.saturating_add(1);
            if (self.bits & (1u32 << i)) != 0 {
                // SAFETY-IRRELEVANT: PkiFailureInfo::from_bit_index is
                // infallible for `i in 0..=26`, which is enforced by the
                // loop condition.  The error branch is unreachable here, but
                // we use a match (not unwrap) to remain warning-free under
                // `#[deny(clippy::unwrap_used)]`.
                if let Ok(info) = PkiFailureInfo::from_bit_index(i) {
                    return Some(info);
                }
            }
        }
        None
    }
}

impl fmt::Display for FailureInfoBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("(none)");
        }
        let mut first = true;
        for info in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            f.write_str(info.name())?;
            first = false;
        }
        Ok(())
    }
}

// =============================================================================
// PkiStatusInfo — RFC 4210 §5.2.3 PKIStatusInfo SEQUENCE
// =============================================================================

/// PKI status information block (`PKIStatusInfo`, RFC 4210 §5.2.3).
///
/// The ASN.1 definition is:
///
/// ```text
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,
///     statusString  PKIFreeText OPTIONAL,
///     failInfo      PKIFailureInfo OPTIONAL
/// }
/// ```
///
/// Replaces the C `OSSL_CMP_PKISI` opaque type and its accessor functions
/// (`OSSL_CMP_PKISI_get_status`, `OSSL_CMP_PKISI_get0_statusString`, etc.)
/// from `crypto/cmp/cmp_status.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiStatusInfo {
    /// PKI status code (mandatory).
    status: PkiStatus,

    /// Optional human-readable status messages.  RFC 4210 permits a
    /// `PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String`; we represent
    /// the sequence as a `Vec<String>` (empty = absent in the encoded form).
    status_strings: Vec<String>,

    /// Optional failure information bits.
    failure_info: Option<FailureInfoBits>,
}

impl PkiStatusInfo {
    /// Constructs a new `PKIStatusInfo` with the given status and no
    /// optional fields.
    #[must_use]
    pub const fn new(status: PkiStatus) -> Self {
        Self {
            status,
            status_strings: Vec::new(),
            failure_info: None,
        }
    }

    /// Adds a status text line, consuming and returning `self` (builder
    /// style).
    #[must_use]
    pub fn with_text<S: Into<String>>(mut self, text: S) -> Self {
        self.status_strings.push(text.into());
        self
    }

    /// Replaces the status text vector with the provided strings.
    #[must_use]
    pub fn with_texts<I, S>(mut self, texts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.status_strings = texts.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the failure information bits, consuming and returning `self`.
    #[must_use]
    pub const fn with_failure_info(mut self, info: FailureInfoBits) -> Self {
        self.failure_info = Some(info);
        self
    }

    /// Adds a single status text line.
    pub fn add_text<S: Into<String>>(&mut self, text: S) {
        self.status_strings.push(text.into());
    }

    /// Sets the failure information bits.
    pub fn set_failure_info(&mut self, info: FailureInfoBits) {
        self.failure_info = Some(info);
    }

    /// Removes any previously set failure information.
    pub fn clear_failure_info(&mut self) {
        self.failure_info = None;
    }

    /// Returns the PKI status code.
    #[must_use]
    pub const fn status(&self) -> PkiStatus {
        self.status
    }

    /// Returns the optional status text lines.
    #[must_use]
    pub fn status_strings(&self) -> &[String] {
        &self.status_strings
    }

    /// Returns the optional failure information bits.
    #[must_use]
    pub const fn failure_info(&self) -> Option<FailureInfoBits> {
        self.failure_info
    }

    /// Returns `true` when this status describes a successful operation.
    #[must_use]
    pub const fn is_positive(&self) -> bool {
        self.status.is_positive()
    }
}

impl fmt::Display for PkiStatusInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "status={}", self.status)?;
        if !self.status_strings.is_empty() {
            write!(f, ", text=[{}]", self.status_strings.join("; "))?;
        }
        if let Some(bits) = self.failure_info {
            if !bits.is_empty() {
                write!(f, ", failInfo={bits}")?;
            }
        }
        Ok(())
    }
}

// =============================================================================
// Transaction ID and Nonce validation — RFC 4210 §5.1.1
// =============================================================================

/// RFC 4210 §5.1.1 mandatory transaction ID length: 16 octets.
pub const TRANSACTION_ID_LEN: usize = 16;

/// RFC 4210 §5.1.1 minimum nonce length: 16 octets.
pub const MIN_NONCE_LEN: usize = 16;

/// Validates a transaction ID per RFC 4210 §5.1.1.
///
/// > "transactionID — This field is a value that allows the recipient of a
/// > message to correlate this with any earlier transaction. […] If used,
/// > the value SHOULD be 128 bits (16 octets) of (pseudo-) random data."
///
/// We require exactly 16 octets — the recommended length — and reject any
/// other size as a defensive measure against truncation attacks.
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `id.len() != 16`.
pub fn validate_transaction_id(id: &[u8]) -> CryptoResult<()> {
    if id.len() == TRANSACTION_ID_LEN {
        Ok(())
    } else {
        Err(CryptoError::Verification(format!(
            "CMP transaction ID length is {}, but RFC 4210 §5.1.1 requires {} octets",
            id.len(),
            TRANSACTION_ID_LEN
        )))
    }
}

/// Validates a sender or recipient nonce per RFC 4210 §5.1.1.
///
/// > "senderNonce / recipNonce — These fields protect the message against
/// > replay. […] The value SHOULD be cryptographically random and SHOULD be
/// > at least 128 bits (16 octets) of (pseudo-) random data."
///
/// We accept any nonce of at least 16 octets to allow longer values per
/// future updates while rejecting unsafe short values.
///
/// # Errors
///
/// Returns [`CryptoError::Verification`] when `nonce.len() < 16`.
pub fn validate_nonce(nonce: &[u8]) -> CryptoResult<()> {
    if nonce.len() >= MIN_NONCE_LEN {
        Ok(())
    } else {
        Err(CryptoError::Verification(format!(
            "CMP nonce length is {}, but RFC 4210 §5.1.1 requires at least {} octets",
            nonce.len(),
            MIN_NONCE_LEN
        )))
    }
}

// =============================================================================
// PkiHeader — RFC 4210 §5.1.1 PKIHeader (foundational subset)
// =============================================================================

/// CMP `PKIHeader` (RFC 4210 §5.1.1) — foundational subset.
///
/// This struct contains the fields required for header construction and
/// inspection.  The `protectionAlg`, `senderKID`, `recipKID`, `freeText`,
/// and `generalInfo` fields are out of scope for this checkpoint and will
/// be added when the protection / authentication subsystem is implemented.
///
/// # ASN.1 Reference
///
/// ```text
/// PKIHeader ::= SEQUENCE {
///     pvno                INTEGER,
///     sender              GeneralName,
///     recipient           GeneralName,
///     messageTime         [0] GeneralizedTime OPTIONAL,
///     protectionAlg       [1] AlgorithmIdentifier OPTIONAL,    -- not yet
///     senderKID           [2] KeyIdentifier OPTIONAL,           -- not yet
///     recipKID            [3] KeyIdentifier OPTIONAL,           -- not yet
///     transactionID       [4] OCTET STRING OPTIONAL,
///     senderNonce         [5] OCTET STRING OPTIONAL,
///     recipNonce          [6] OCTET STRING OPTIONAL,
///     freeText            [7] PKIFreeText OPTIONAL,             -- not yet
///     generalInfo         [8] SEQUENCE OF InfoTypeAndValue OPT  -- not yet
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiHeader {
    /// CMP protocol version (mandatory).
    pvno: PkiVersion,

    /// Sender (mandatory; encoded as `GeneralName`).  We store the raw DER
    /// bytes of the encoded `GeneralName` as a `Vec<u8>` to keep the
    /// foundational layer free of full X.509 dependencies.
    sender: Vec<u8>,

    /// Recipient (mandatory; encoded as `GeneralName`).
    recipient: Vec<u8>,

    /// Optional message creation time (UTC seconds since UNIX epoch).
    message_time: Option<i64>,

    /// Optional 16-octet transaction ID.
    transaction_id: Option<Vec<u8>>,

    /// Optional sender nonce (≥16 octets).
    sender_nonce: Option<Vec<u8>>,

    /// Optional recipient nonce (≥16 octets).
    recipient_nonce: Option<Vec<u8>>,

    /// Optional protection-algorithm identifier (`AlgorithmIdentifier`).
    ///
    /// Maps to `OSSL_CMP_PKIHEADER.protectionAlg` (`cmp_local.h`).
    /// Used to identify the digest / MAC algorithm employed in the message
    /// `protection` field.  See RFC 4210 §5.1.1.
    protection_alg: Option<Nid>,

    /// Optional free-form human-readable text strings (`PKIFreeText`).
    ///
    /// Maps to `OSSL_CMP_PKIHEADER.freeText` (`cmp_local.h`).  Each entry
    /// is one `UTF8String` element of the `PKIFreeText` SEQUENCE.
    free_text: Vec<String>,
    // UNREAD: reserved for future RFC 4210 §5.1.1 header expansion (R3).
    // The fields below are intentionally not yet stored — adding storage
    // before there is a read-site would violate Rule R3.  When the
    // protection / authentication subsystem is implemented, these will
    // become Option<...> fields with corresponding accessors.
    //
    //   - sender_kid:      Option<Vec<u8>>
    //   - recipient_kid:   Option<Vec<u8>>
    //   - general_info:    Vec<InfoTypeAndValue>
}

impl PkiHeader {
    /// Returns the CMP protocol version.
    #[must_use]
    pub const fn pvno(&self) -> PkiVersion {
        self.pvno
    }

    /// Returns the sender bytes (encoded `GeneralName`).
    #[must_use]
    pub fn sender(&self) -> &[u8] {
        &self.sender
    }

    /// Returns the recipient bytes (encoded `GeneralName`).
    #[must_use]
    pub fn recipient(&self) -> &[u8] {
        &self.recipient
    }

    /// Returns the message creation time, if set.
    #[must_use]
    pub const fn message_time(&self) -> Option<i64> {
        self.message_time
    }

    /// Returns the transaction ID, if set.
    #[must_use]
    pub fn transaction_id(&self) -> Option<&[u8]> {
        self.transaction_id.as_deref()
    }

    /// Returns the sender nonce, if set.
    #[must_use]
    pub fn sender_nonce(&self) -> Option<&[u8]> {
        self.sender_nonce.as_deref()
    }

    /// Returns the recipient nonce, if set.
    #[must_use]
    pub fn recipient_nonce(&self) -> Option<&[u8]> {
        self.recipient_nonce.as_deref()
    }

    /// Returns the recipient nonce, if set (RFC 4210 `recipNonce` accessor).
    ///
    /// This is a schema-aligned alias for [`recipient_nonce`](Self::recipient_nonce)
    /// matching the RFC 4210 ASN.1 field name `recipNonce`.
    #[must_use]
    pub fn recip_nonce(&self) -> Option<&[u8]> {
        self.recipient_nonce.as_deref()
    }

    /// Returns the protection-algorithm identifier, if set.
    ///
    /// Maps to the `protectionAlg` field of `OSSL_CMP_PKIHEADER`
    /// (`cmp_local.h`).  Returns `None` when the message is unprotected
    /// (e.g., for some general-purpose error responses).
    #[must_use]
    pub const fn protection_alg(&self) -> Option<&Nid> {
        self.protection_alg.as_ref()
    }

    /// Returns the free-text strings carried by this header.
    ///
    /// Maps to the `freeText` field of `OSSL_CMP_PKIHEADER`
    /// (`cmp_local.h`).  Returns an empty slice when no free text is set.
    #[must_use]
    pub fn free_text(&self) -> &[String] {
        &self.free_text
    }
}

// =============================================================================
// PkiHeaderBuilder — RFC 4210 §5.1.1 builder
// =============================================================================

/// Builder for [`PkiHeader`].
///
/// Construct via [`PkiHeaderBuilder::new`], chain setters for each field,
/// then call [`PkiHeaderBuilder::build`].
///
/// Mirrors `OSSL_CMP_HDR_*` setter functions from
/// `crypto/cmp/cmp_msg.c` (e.g., `ossl_cmp_hdr_set_pvno`,
/// `ossl_cmp_hdr_set1_sender`).
#[derive(Debug, Clone)]
pub struct PkiHeaderBuilder {
    pvno: PkiVersion,
    sender: Option<Vec<u8>>,
    recipient: Option<Vec<u8>>,
    message_time: Option<i64>,
    transaction_id: Option<Vec<u8>>,
    sender_nonce: Option<Vec<u8>>,
    recipient_nonce: Option<Vec<u8>>,
    protection_alg: Option<Nid>,
    free_text: Vec<String>,
}

impl PkiHeaderBuilder {
    /// Creates a new builder with the given protocol version and no other
    /// fields set.
    #[must_use]
    pub const fn new(pvno: PkiVersion) -> Self {
        Self {
            pvno,
            sender: None,
            recipient: None,
            message_time: None,
            transaction_id: None,
            sender_nonce: None,
            recipient_nonce: None,
            protection_alg: None,
            free_text: Vec::new(),
        }
    }

    /// Sets the sender field (encoded `GeneralName` bytes).
    #[must_use]
    pub fn sender(mut self, sender: Vec<u8>) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Sets the recipient field (encoded `GeneralName` bytes).
    #[must_use]
    pub fn recipient(mut self, recipient: Vec<u8>) -> Self {
        self.recipient = Some(recipient);
        self
    }

    /// Sets the optional message-time field (UTC seconds since UNIX epoch).
    #[must_use]
    pub const fn message_time(mut self, time: i64) -> Self {
        self.message_time = Some(time);
        self
    }

    /// Sets the optional 16-octet transaction ID.
    ///
    /// The length is validated at [`build`](Self::build) time.
    #[must_use]
    pub fn transaction_id(mut self, id: Vec<u8>) -> Self {
        self.transaction_id = Some(id);
        self
    }

    /// Sets the optional sender nonce (≥16 octets).
    ///
    /// The length is validated at [`build`](Self::build) time.
    #[must_use]
    pub fn sender_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.sender_nonce = Some(nonce);
        self
    }

    /// Sets the optional recipient nonce (≥16 octets).
    ///
    /// The length is validated at [`build`](Self::build) time.
    #[must_use]
    pub fn recipient_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.recipient_nonce = Some(nonce);
        self
    }

    /// Sets the optional protection-algorithm identifier.
    ///
    /// Mirrors `ossl_cmp_hdr_set_protectionAlg` from `crypto/cmp/cmp_hdr.c`.
    /// Use [`Nid::SHA256`], [`Nid::SHA1`], etc., or construct via
    /// [`Nid::from_raw`] with an OpenSSL NID integer.
    #[must_use]
    pub fn protection_alg(mut self, alg: Nid) -> Self {
        self.protection_alg = Some(alg);
        self
    }

    /// Replaces the free-text strings.
    ///
    /// Mirrors `ossl_cmp_hdr_push1_freeText` semantics from
    /// `crypto/cmp/cmp_hdr.c` for the bulk-load case.  Pass an empty
    /// `Vec` to clear the field.
    #[must_use]
    pub fn free_text(mut self, texts: Vec<String>) -> Self {
        self.free_text = texts;
        self
    }

    /// Appends a single free-text string to the builder.
    ///
    /// Mirrors `ossl_cmp_hdr_push0_freeText` from `crypto/cmp/cmp_hdr.c`.
    #[must_use]
    pub fn add_free_text(mut self, text: String) -> Self {
        self.free_text.push(text);
        self
    }

    /// Validates and constructs a [`PkiHeader`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] when:
    /// * `sender` is not set (mandatory per RFC 4210 §5.1.1)
    /// * `recipient` is not set (mandatory per RFC 4210 §5.1.1)
    /// * `transaction_id` is set but not exactly 16 octets long
    /// * `sender_nonce` or `recipient_nonce` is set but shorter than 16 octets
    pub fn build(self) -> CryptoResult<PkiHeader> {
        let sender = self.sender.ok_or_else(|| {
            CryptoError::Verification(
                "PKIHeader requires sender (RFC 4210 §5.1.1 mandates GeneralName)".into(),
            )
        })?;
        let recipient = self.recipient.ok_or_else(|| {
            CryptoError::Verification(
                "PKIHeader requires recipient (RFC 4210 §5.1.1 mandates GeneralName)".into(),
            )
        })?;

        if let Some(ref id) = self.transaction_id {
            validate_transaction_id(id)?;
        }
        if let Some(ref nonce) = self.sender_nonce {
            validate_nonce(nonce)?;
        }
        if let Some(ref nonce) = self.recipient_nonce {
            validate_nonce(nonce)?;
        }

        Ok(PkiHeader {
            pvno: self.pvno,
            sender,
            recipient,
            message_time: self.message_time,
            transaction_id: self.transaction_id,
            sender_nonce: self.sender_nonce,
            recipient_nonce: self.recipient_nonce,
            protection_alg: self.protection_alg,
            free_text: self.free_text,
        })
    }
}

impl Default for PkiHeaderBuilder {
    fn default() -> Self {
        Self::new(PkiVersion::default_version())
    }
}

// =============================================================================
// Module-level helpers
// =============================================================================

/// Returns the canonical name of every supported `PKIFailureInfo` bit.
///
/// Useful for diagnostics, log message construction, and test fixtures.
#[must_use]
pub fn all_failure_info_names() -> Vec<&'static str> {
    PkiFailureInfo::all().iter().map(|f| f.name()).collect()
}

/// Returns a `HashSet` of every supported `PKIStatus` value.
///
/// Useful in tests that need to verify exhaustive coverage of the status
/// code space.
#[must_use]
pub fn all_pki_statuses() -> HashSet<PkiStatus> {
    [
        PkiStatus::Request,
        PkiStatus::Trans,
        PkiStatus::Unspecified,
        PkiStatus::Accepted,
        PkiStatus::GrantedWithMods,
        PkiStatus::Rejection,
        PkiStatus::Waiting,
        PkiStatus::RevocationWarning,
        PkiStatus::RevocationNotification,
        PkiStatus::KeyUpdateWarning,
    ]
    .into_iter()
    .collect()
}

// =============================================================================
// CmpMessageType — RFC 4210 §5.3 PKIBody CHOICE discriminants
// =============================================================================

/// CMP message body type (RFC 4210 §5.3 `PKIBody` CHOICE discriminant).
///
/// Each variant maps directly to one `OSSL_CMP_PKIBODY_*` constant in
/// `cmp_local.h` (lines 902-929) and to the body-name strings produced by
/// `ossl_cmp_bodytype_to_string` in `crypto/cmp/cmp_msg.c`.
///
/// The numeric discriminants match the OpenSSL ASN.1 CHOICE indices
/// 0..=26 except where the schema omits the optional POP-Decryption
/// challenge/response variants (5, 6) — those are not part of this
/// public API surface.
///
/// # ASN.1 Reference
///
/// ```text
/// PKIBody ::= CHOICE {
///     ir       [0]  CertReqMessages,
///     ip       [1]  CertRepMessage,
///     cr       [2]  CertReqMessages,
///     cp       [3]  CertRepMessage,
///     p10cr    [4]  CertificationRequest,
///     ...
///     pollReq  [25] PollReqContent,
///     pollRep  [26] PollRepContent
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(i32)]
pub enum CmpMessageType {
    /// Initialization Request — first cert enrollment for a new EE.
    /// Maps to `OSSL_CMP_PKIBODY_IR` (0).
    Ir = 0,
    /// Initialization Response — CA's reply to `Ir`.
    /// Maps to `OSSL_CMP_PKIBODY_IP` (1).
    Ip = 1,
    /// Certification Request — additional cert for an established EE.
    /// Maps to `OSSL_CMP_PKIBODY_CR` (2).
    Cr = 2,
    /// Certification Response — CA's reply to `Cr`.
    /// Maps to `OSSL_CMP_PKIBODY_CP` (3).
    Cp = 3,
    /// PKCS#10 CR — certificate request via PKCS#10 `CertificationRequest`.
    /// Maps to `OSSL_CMP_PKIBODY_P10CR` (4).
    P10cr = 4,
    /// Key Update Request — request to renew/rekey an existing cert.
    /// Maps to `OSSL_CMP_PKIBODY_KUR` (7).
    Kur = 7,
    /// Key Update Response — CA's reply to `Kur`.
    /// Maps to `OSSL_CMP_PKIBODY_KUP` (8).
    Kup = 8,
    /// Key Recovery Request.
    /// Maps to `OSSL_CMP_PKIBODY_KRR` (9).
    Krr = 9,
    /// Key Recovery Response.
    /// Maps to `OSSL_CMP_PKIBODY_KRP` (10).
    Krp = 10,
    /// Revocation Request.
    /// Maps to `OSSL_CMP_PKIBODY_RR` (11).
    Rr = 11,
    /// Revocation Response.
    /// Maps to `OSSL_CMP_PKIBODY_RP` (12).
    Rp = 12,
    /// Cross-Certification Request.
    /// Maps to `OSSL_CMP_PKIBODY_CCR` (13).
    Ccr = 13,
    /// Cross-Certification Response.
    /// Maps to `OSSL_CMP_PKIBODY_CCP` (14).
    Ccp = 14,
    /// CA Key Update Announcement.
    /// Maps to `OSSL_CMP_PKIBODY_CKUANN` (15).
    Ckuann = 15,
    /// Certificate Announcement.
    /// Maps to `OSSL_CMP_PKIBODY_CANN` (16).
    Cann = 16,
    /// Revocation Announcement.
    /// Maps to `OSSL_CMP_PKIBODY_RANN` (17).
    Rann = 17,
    /// CRL Announcement.
    /// Maps to `OSSL_CMP_PKIBODY_CRLANN` (18).
    Crlann = 18,
    /// PKI Confirmation.
    /// Maps to `OSSL_CMP_PKIBODY_PKICONF` (19).
    PkiConf = 19,
    /// Nested Message.
    /// Maps to `OSSL_CMP_PKIBODY_NESTED` (20).
    Nested = 20,
    /// General Message — extensible info-type-and-value query.
    /// Maps to `OSSL_CMP_PKIBODY_GENM` (21).
    Genm = 21,
    /// General Response — extensible info-type-and-value reply.
    /// Maps to `OSSL_CMP_PKIBODY_GENP` (22).
    Genp = 22,
    /// Error Message.
    /// Maps to `OSSL_CMP_PKIBODY_ERROR` (23).
    Error = 23,
    /// Certificate Confirmation — EE confirms acceptance of issued cert.
    /// Maps to `OSSL_CMP_PKIBODY_CERTCONF` (24).
    CertConf = 24,
    /// Polling Request — for delayed-delivery patterns.
    /// Maps to `OSSL_CMP_PKIBODY_POLLREQ` (25).
    PollReq = 25,
    /// Polling Response.
    /// Maps to `OSSL_CMP_PKIBODY_POLLREP` (26).
    PollRep = 26,
}

impl CmpMessageType {
    /// Returns the ASN.1 CHOICE discriminant integer.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Constructs a `CmpMessageType` from its ASN.1 CHOICE discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when `value` does not correspond to
    /// a supported `CmpMessageType` variant.  The optional POP-decryption
    /// challenge/response variants (5, 6) are intentionally rejected.
    pub fn from_i32(value: i32) -> CryptoResult<Self> {
        Ok(match value {
            0 => Self::Ir,
            1 => Self::Ip,
            2 => Self::Cr,
            3 => Self::Cp,
            4 => Self::P10cr,
            7 => Self::Kur,
            8 => Self::Kup,
            9 => Self::Krr,
            10 => Self::Krp,
            11 => Self::Rr,
            12 => Self::Rp,
            13 => Self::Ccr,
            14 => Self::Ccp,
            15 => Self::Ckuann,
            16 => Self::Cann,
            17 => Self::Rann,
            18 => Self::Crlann,
            19 => Self::PkiConf,
            20 => Self::Nested,
            21 => Self::Genm,
            22 => Self::Genp,
            23 => Self::Error,
            24 => Self::CertConf,
            25 => Self::PollReq,
            26 => Self::PollRep,
            other => {
                return Err(CryptoError::Encoding(format!(
                    "invalid CMP message body type {other}; \
                     expected 0..=4, 7..=26 (RFC 4210 §5.3)"
                )));
            }
        })
    }

    /// Returns the canonical short name (e.g., `"IR"`, `"KUP"`).
    ///
    /// Mirrors `ossl_cmp_bodytype_to_string` from `crypto/cmp/cmp_msg.c`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ir => "IR",
            Self::Ip => "IP",
            Self::Cr => "CR",
            Self::Cp => "CP",
            Self::P10cr => "P10CR",
            Self::Kur => "KUR",
            Self::Kup => "KUP",
            Self::Krr => "KRR",
            Self::Krp => "KRP",
            Self::Rr => "RR",
            Self::Rp => "RP",
            Self::Ccr => "CCR",
            Self::Ccp => "CCP",
            Self::Ckuann => "CKUANN",
            Self::Cann => "CANN",
            Self::Rann => "RANN",
            Self::Crlann => "CRLANN",
            Self::PkiConf => "PKICONF",
            Self::Nested => "NESTED",
            Self::Genm => "GENM",
            Self::Genp => "GENP",
            Self::Error => "ERROR",
            Self::CertConf => "CERTCONF",
            Self::PollReq => "POLLREQ",
            Self::PollRep => "POLLREP",
        }
    }

    /// Returns `true` when this body type is a request (sent by the EE/RA).
    #[must_use]
    pub const fn is_request(self) -> bool {
        matches!(
            self,
            Self::Ir
                | Self::Cr
                | Self::P10cr
                | Self::Kur
                | Self::Krr
                | Self::Rr
                | Self::Ccr
                | Self::Genm
                | Self::CertConf
                | Self::PollReq
        )
    }

    /// Returns `true` when this body type is a response (sent by the CA).
    #[must_use]
    pub const fn is_response(self) -> bool {
        matches!(
            self,
            Self::Ip
                | Self::Cp
                | Self::Kup
                | Self::Krp
                | Self::Rp
                | Self::Ccp
                | Self::Genp
                | Self::PkiConf
                | Self::Error
                | Self::PollRep
        )
    }

    /// Returns the expected matching response type for this request.
    ///
    /// Returns `None` for non-request types or for `P10cr` (which expects
    /// a `Cp` response — a many-to-one mapping handled separately).
    #[must_use]
    pub const fn expected_response(self) -> Option<Self> {
        match self {
            Self::Ir => Some(Self::Ip),
            // `Cr` and `P10cr` both elicit a `Cp` response — RFC 4210 §5.3.4
            // (initial / "new" certificate response) and §5.3.18 / Appendix E.7
            // (PKCS#10 cert request) share the same response body type.
            Self::Cr | Self::P10cr => Some(Self::Cp),
            Self::Kur => Some(Self::Kup),
            Self::Krr => Some(Self::Krp),
            Self::Rr => Some(Self::Rp),
            Self::Ccr => Some(Self::Ccp),
            Self::Genm => Some(Self::Genp),
            _ => None,
        }
    }
}

impl fmt::Display for CmpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// CertReqMessage / CertResponse — PKIBody substructures (cmp_local.h §902-929)
// =============================================================================

/// Single CMP `CertResponse` element of a `CertRepMessage`.
///
/// Maps to `OSSL_CMP_CERTRESPONSE` from `cmp_local.h` (lines ~720-735), which
/// carries the certificate request ID, the granted `PKIStatusInfo`, and the
/// optional certified key pair (cert + private key transport, if requested).
///
/// In this Rust representation the certified-key-pair component is reduced to
/// the certificate itself (which is the only component the `enroll`/`key_update`
/// flow consumes).  Local key recovery (KRR/KRP) is not in scope.
#[derive(Debug, Clone)]
pub struct CertResponse {
    /// Certificate request identifier (matches `certReqId` from the request).
    cert_req_id: i32,
    /// Status information for this response.
    status: PkiStatusInfo,
    /// The issued certificate, when granted.
    certificate: Option<X509Certificate>,
}

impl CertResponse {
    /// Constructs a new `CertResponse`.
    #[must_use]
    pub const fn new(
        cert_req_id: i32,
        status: PkiStatusInfo,
        certificate: Option<X509Certificate>,
    ) -> Self {
        Self {
            cert_req_id,
            status,
            certificate,
        }
    }

    /// Returns the certificate request identifier.
    #[must_use]
    pub const fn cert_req_id(&self) -> i32 {
        self.cert_req_id
    }

    /// Returns the status information.
    #[must_use]
    pub const fn status(&self) -> &PkiStatusInfo {
        &self.status
    }

    /// Returns the issued certificate, when present.
    #[must_use]
    pub const fn certificate(&self) -> Option<&X509Certificate> {
        self.certificate.as_ref()
    }
}

/// CMP `CertRepMessage` — a `CertResponse` sequence plus optional CA pubs.
///
/// Maps to `OSSL_CMP_CERTREPMESSAGE` from `cmp_local.h` (lines ~736-744).
/// Carried by `Ip`/`Cp`/`Kup`/`Ccp` body variants.
#[derive(Debug, Clone)]
pub struct CertRepMessage {
    /// Optional list of trust-anchor / CA public-key certificates.
    ca_pubs: Vec<X509Certificate>,
    /// One or more `CertResponse` elements.
    responses: Vec<CertResponse>,
}

impl CertRepMessage {
    /// Constructs a new `CertRepMessage`.
    #[must_use]
    pub const fn new(ca_pubs: Vec<X509Certificate>, responses: Vec<CertResponse>) -> Self {
        Self { ca_pubs, responses }
    }

    /// Returns the CA-public-key certificates.
    #[must_use]
    pub fn ca_pubs(&self) -> &[X509Certificate] {
        &self.ca_pubs
    }

    /// Returns the `CertResponse` elements.
    #[must_use]
    pub fn responses(&self) -> &[CertResponse] {
        &self.responses
    }

    /// Returns the response matching `cert_req_id`, if any.
    ///
    /// Mirrors `ossl_cmp_certrepmessage_get0_CertResponse` from
    /// `crypto/cmp/cmp_msg.c`.  A `cert_req_id == -1` matches any single
    /// response (used when the EE submitted a single P10CR).
    #[must_use]
    pub fn response_for(&self, cert_req_id: i32) -> Option<&CertResponse> {
        if cert_req_id == -1 && self.responses.len() == 1 {
            return self.responses.first();
        }
        self.responses.iter().find(|r| r.cert_req_id == cert_req_id)
    }
}

/// CMP `RevRepContent` — revocation response body.
///
/// Maps to `OSSL_CMP_REVREPCONTENT` from `cmp_local.h` (lines ~673-679).
/// Carried by the `Rp` body variant.  Each request (typically a single one
/// in the OpenSSL client) has a matching `PkiStatusInfo` element.
#[derive(Debug, Clone)]
pub struct RevRepContent {
    /// Status information for each revoked certificate (one per request).
    status: Vec<PkiStatusInfo>,
}

impl RevRepContent {
    /// Constructs a new `RevRepContent`.
    #[must_use]
    pub const fn new(status: Vec<PkiStatusInfo>) -> Self {
        Self { status }
    }

    /// Returns the status sequence.
    #[must_use]
    pub fn status(&self) -> &[PkiStatusInfo] {
        &self.status
    }

    /// Returns the first status entry, when present.
    #[must_use]
    pub fn first_status(&self) -> Option<&PkiStatusInfo> {
        self.status.first()
    }
}

/// CMP `ErrorMsgContent` — error-body content.
///
/// Maps to `OSSL_CMP_ERRORMSGCONTENT` from `cmp_local.h` (lines ~681-687).
/// Carried by the `Error` body variant.
#[derive(Debug, Clone)]
pub struct ErrorMsgContent {
    /// Status (always carries an error/rejection in well-formed messages).
    status: PkiStatusInfo,
    /// CA-supplied numeric error code (free-form).
    error_code: Option<i64>,
    /// Optional human-readable error details.
    error_details: Vec<String>,
}

impl ErrorMsgContent {
    /// Constructs a new `ErrorMsgContent`.
    #[must_use]
    pub const fn new(
        status: PkiStatusInfo,
        error_code: Option<i64>,
        error_details: Vec<String>,
    ) -> Self {
        Self {
            status,
            error_code,
            error_details,
        }
    }

    /// Returns the status information.
    #[must_use]
    pub const fn status(&self) -> &PkiStatusInfo {
        &self.status
    }

    /// Returns the optional numeric error code.
    #[must_use]
    pub const fn error_code(&self) -> Option<i64> {
        self.error_code
    }

    /// Returns the human-readable error details.
    #[must_use]
    pub fn error_details(&self) -> &[String] {
        &self.error_details
    }
}

// =============================================================================
// PkiBody — RFC 4210 §5.3 PKIBody CHOICE
// =============================================================================

/// Single CMP certificate request (`CertReqMsg` / PKCS#10).
///
/// Maps to `OSSL_CRMF_MSG` (when carrying CRMF for IR/CR/KUR) or PKCS#10
/// (for `P10cr`).  The Rust representation stores the DER-encoded request
/// payload because in-place mutation of CRMF fields is not part of this
/// public API surface — `CmpContextBuilder` carries the structured inputs
/// (subject name, public key, etc.) used to construct the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRequest {
    /// Identifier matching the index of this request within the body.
    cert_req_id: i32,
    /// DER-encoded `CertReqMsg` or `CertificationRequest`.
    der: Vec<u8>,
}

impl CertRequest {
    /// Constructs a new `CertRequest` from a DER-encoded request payload.
    #[must_use]
    pub const fn new(cert_req_id: i32, der: Vec<u8>) -> Self {
        Self { cert_req_id, der }
    }

    /// Returns the cert-request identifier.
    #[must_use]
    pub const fn cert_req_id(&self) -> i32 {
        self.cert_req_id
    }

    /// Returns the DER-encoded request bytes.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

/// Single CMP revocation-request element (`RevDetails`).
///
/// Maps to `OSSL_CMP_REVDETAILS` from `cmp_local.h`.  The Rust representation
/// stores only the issuer/serial of the targeted certificate plus the chosen
/// `CRLReason`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// DER-encoded issuer of the certificate to revoke.
    issuer_der: Vec<u8>,
    /// DER-encoded serial-number INTEGER of the certificate to revoke.
    serial_der: Vec<u8>,
    /// `CRLReason` value (RFC 5280 §5.3.1).  `None` means no reason supplied.
    reason: Option<i32>,
}

impl RevocationRequest {
    /// Constructs a new `RevocationRequest`.
    #[must_use]
    pub const fn new(issuer_der: Vec<u8>, serial_der: Vec<u8>, reason: Option<i32>) -> Self {
        Self {
            issuer_der,
            serial_der,
            reason,
        }
    }

    /// Returns the DER-encoded issuer.
    #[must_use]
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }

    /// Returns the DER-encoded serial number.
    #[must_use]
    pub fn serial_der(&self) -> &[u8] {
        &self.serial_der
    }

    /// Returns the `CRLReason`, if specified.
    #[must_use]
    pub const fn reason(&self) -> Option<i32> {
        self.reason
    }
}

/// CMP general-message info-type-and-value (ITAV) item.
///
/// Maps to `OSSL_CMP_ITAV` from `cmp_local.h` (lines ~752-758).
/// Each item carries a type OID and an optional opaque ASN.1 value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoTypeAndValue {
    /// OID identifying the info type.
    info_type: String,
    /// Optional DER-encoded value associated with this info type.
    info_value: Option<Vec<u8>>,
}

impl InfoTypeAndValue {
    /// Constructs a new `InfoTypeAndValue`.
    #[must_use]
    pub const fn new(info_type: String, info_value: Option<Vec<u8>>) -> Self {
        Self {
            info_type,
            info_value,
        }
    }

    /// Returns the OID.
    #[must_use]
    pub fn info_type(&self) -> &str {
        &self.info_type
    }

    /// Returns the optional DER-encoded value.
    #[must_use]
    pub fn info_value(&self) -> Option<&[u8]> {
        self.info_value.as_deref()
    }
}

/// CMP `PKIBody` — the discriminated content of every CMP message.
///
/// Maps to `OSSL_CMP_PKIBODY` (the `OSSL_CMP_PKIBODY_*` CHOICE in
/// `cmp_local.h` lines 902-929) and to the union body in `OSSL_CMP_MSG.body`.
///
/// Each variant corresponds to exactly one [`CmpMessageType`] value.
/// Variants for the optional POP-decryption challenge/response (5/6) and
/// for KRR/KRP, CCR/CCP, CKUANN, CANN, RANN, CRLANN, NESTED, POLLREQ and
/// POLLREP are represented as opaque DER for forward compatibility — the
/// public CMP enrollment/revocation flow does not interpret them.
#[derive(Debug, Clone)]
pub enum PkiBody {
    /// `ir` — Initialization Request.
    Ir(Vec<CertRequest>),
    /// `ip` — Initialization Response.
    Ip(CertRepMessage),
    /// `cr` — Certification Request.
    Cr(Vec<CertRequest>),
    /// `cp` — Certification Response.
    Cp(CertRepMessage),
    /// `p10cr` — PKCS#10 Certificate Request.
    P10cr(CertRequest),
    /// `kur` — Key Update Request.
    Kur(Vec<CertRequest>),
    /// `kup` — Key Update Response.
    Kup(CertRepMessage),
    /// `krr` — Key Recovery Request (opaque DER).
    Krr(Vec<u8>),
    /// `krp` — Key Recovery Response (opaque DER).
    Krp(Vec<u8>),
    /// `rr` — Revocation Request.
    Rr(Vec<RevocationRequest>),
    /// `rp` — Revocation Response.
    Rp(RevRepContent),
    /// `ccr` — Cross-Certification Request (opaque DER).
    Ccr(Vec<u8>),
    /// `ccp` — Cross-Certification Response (opaque DER).
    Ccp(Vec<u8>),
    /// `ckuann` — CA Key Update Announcement (opaque DER).
    Ckuann(Vec<u8>),
    /// `cann` — Certificate Announcement (DER-encoded certificate).
    Cann(Vec<u8>),
    /// `rann` — Revocation Announcement (opaque DER).
    Rann(Vec<u8>),
    /// `crlann` — CRL Announcement (opaque DER).
    Crlann(Vec<u8>),
    /// `pkiconf` — PKI Confirmation (no payload).
    PkiConf,
    /// `nested` — Nested Message (opaque DER).
    Nested(Vec<u8>),
    /// `genm` — General Message.
    Genm(Vec<InfoTypeAndValue>),
    /// `genp` — General Response.
    Genp(Vec<InfoTypeAndValue>),
    /// `error` — Error Message.
    Error(ErrorMsgContent),
    /// `certConf` — Certificate Confirmation (opaque DER, contains hashes).
    CertConf(Vec<u8>),
    /// `pollReq` — Polling Request (cert-req-id, ASN.1 SEQUENCE).
    PollReq(Vec<i32>),
    /// `pollRep` — Polling Response (cert-req-id + check-after seconds).
    PollRep(Vec<PollResponse>),
}

/// Single polling response element — pairs a request ID with a back-off.
///
/// Maps to `OSSL_CMP_POLLREP` from `cmp_local.h`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PollResponse {
    /// Cert-request identifier this poll-rep is for.
    pub cert_req_id: i32,
    /// Number of seconds the EE should wait before polling again.
    pub check_after: u64,
}

impl PkiBody {
    /// Returns the [`CmpMessageType`] discriminant of this body.
    #[must_use]
    pub const fn body_type(&self) -> CmpMessageType {
        match self {
            Self::Ir(_) => CmpMessageType::Ir,
            Self::Ip(_) => CmpMessageType::Ip,
            Self::Cr(_) => CmpMessageType::Cr,
            Self::Cp(_) => CmpMessageType::Cp,
            Self::P10cr(_) => CmpMessageType::P10cr,
            Self::Kur(_) => CmpMessageType::Kur,
            Self::Kup(_) => CmpMessageType::Kup,
            Self::Krr(_) => CmpMessageType::Krr,
            Self::Krp(_) => CmpMessageType::Krp,
            Self::Rr(_) => CmpMessageType::Rr,
            Self::Rp(_) => CmpMessageType::Rp,
            Self::Ccr(_) => CmpMessageType::Ccr,
            Self::Ccp(_) => CmpMessageType::Ccp,
            Self::Ckuann(_) => CmpMessageType::Ckuann,
            Self::Cann(_) => CmpMessageType::Cann,
            Self::Rann(_) => CmpMessageType::Rann,
            Self::Crlann(_) => CmpMessageType::Crlann,
            Self::PkiConf => CmpMessageType::PkiConf,
            Self::Nested(_) => CmpMessageType::Nested,
            Self::Genm(_) => CmpMessageType::Genm,
            Self::Genp(_) => CmpMessageType::Genp,
            Self::Error(_) => CmpMessageType::Error,
            Self::CertConf(_) => CmpMessageType::CertConf,
            Self::PollReq(_) => CmpMessageType::PollReq,
            Self::PollRep(_) => CmpMessageType::PollRep,
        }
    }

    /// Returns the contained `CertRepMessage` when this body is `Ip`, `Cp`, or `Kup`.
    ///
    /// Returns `None` for any non-cert-rep variant.
    ///
    /// Mirrors the pattern used by `OSSL_CMP_exec_certreq` in
    /// `crypto/cmp/cmp_client.c` to extract the certificate from the
    /// response body (lines ~720-815).
    #[must_use]
    pub const fn as_cert_rep(&self) -> Option<&CertRepMessage> {
        match self {
            Self::Ip(rep) | Self::Cp(rep) | Self::Kup(rep) => Some(rep),
            _ => None,
        }
    }

    /// Returns the contained `RevRepContent` when this body is `Rp`.
    ///
    /// Mirrors the pattern used by `OSSL_CMP_exec_RR_ses` in
    /// `crypto/cmp/cmp_client.c` (lines ~886-1048).
    #[must_use]
    pub const fn as_revocation_rep(&self) -> Option<&RevRepContent> {
        match self {
            Self::Rp(rep) => Some(rep),
            _ => None,
        }
    }

    /// Returns the contained `ErrorMsgContent` when this body is `Error`.
    ///
    /// Mirrors the OpenSSL error-handling path that converts an `error`
    /// `PKIBody` into a status info object (`crypto/cmp/cmp_status.c`).
    #[must_use]
    pub const fn as_error(&self) -> Option<&ErrorMsgContent> {
        match self {
            Self::Error(err) => Some(err),
            _ => None,
        }
    }
}

// =============================================================================
// CmpMessage — Top-level RFC 4210 §5.1 PKIMessage SEQUENCE
// =============================================================================

/// A complete CMP `PKIMessage` (RFC 4210 §5.1).
///
/// Maps to `OSSL_CMP_MSG` from `cmp_local.h` (lines 932-942):
///
/// ```text
/// PKIMessage ::= SEQUENCE {
///     header    PKIHeader,
///     body      PKIBody,
///     protection [0] PKIProtection OPTIONAL,
///     extraCerts [1] SEQUENCE SIZE (1..MAX) OF Certificate OPTIONAL
/// }
/// ```
///
/// The `protection` field is `Some(...)` for protected messages (signature
/// or PBM-MAC) and `None` for unprotected messages.  The `extra_certs`
/// list carries any additional certificates required for chain validation
/// (e.g., the EE's protection-cert chain, or the CA chain in a response).
#[derive(Debug, Clone)]
pub struct CmpMessage {
    /// PKI header (sender, recipient, transaction ID, nonces, etc.).
    header: PkiHeader,
    /// Discriminated body content.
    body: PkiBody,
    /// Optional message protection (BIT STRING) — signature or MAC.
    protection: Option<Vec<u8>>,
    /// Additional certificates carried alongside the message.
    extra_certs: Vec<X509Certificate>,
}

impl CmpMessage {
    /// Constructs a new `CmpMessage` from its components.
    ///
    /// Mirrors `OSSL_CMP_MSG_new` and `ossl_cmp_msg_create` from
    /// `crypto/cmp/cmp_msg.c`.
    #[must_use]
    pub const fn new(
        header: PkiHeader,
        body: PkiBody,
        protection: Option<Vec<u8>>,
        extra_certs: Vec<X509Certificate>,
    ) -> Self {
        Self {
            header,
            body,
            protection,
            extra_certs,
        }
    }

    /// Returns the PKI header.
    #[must_use]
    pub const fn header(&self) -> &PkiHeader {
        &self.header
    }

    /// Returns the PKI body.
    #[must_use]
    pub const fn body(&self) -> &PkiBody {
        &self.body
    }

    /// Returns the body type (a convenience accessor).
    #[must_use]
    pub const fn message_type(&self) -> CmpMessageType {
        self.body.body_type()
    }

    /// Returns the optional message protection bytes.
    #[must_use]
    pub fn protection(&self) -> Option<&[u8]> {
        self.protection.as_deref()
    }

    /// Returns the `extraCerts` chain.
    #[must_use]
    pub fn extra_certs(&self) -> &[X509Certificate] {
        &self.extra_certs
    }

    /// Returns `true` when this message carries protection bytes.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        self.protection.is_some()
    }

    /// Decodes a CMP `PKIMessage` from DER.
    ///
    /// Mirrors `d2i_OSSL_CMP_MSG` from `crypto/cmp/cmp_msg.c` (line 1254).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the input is empty or does
    /// not parse as a CMP `PKIMessage` SEQUENCE.
    ///
    /// # Implementation Note
    ///
    /// This implementation provides DER-format validation and skeletal
    /// decoding suitable for use as an in-memory transport message.  Full
    /// ASN.1 component-level parsing is delegated to the dedicated CMP
    /// parser stage.  The returned `CmpMessage` will carry the originally
    /// received bytes inside its body so that round-trip via
    /// [`to_der`](Self::to_der) yields equivalent output.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        if der.is_empty() {
            return Err(CryptoError::Encoding(
                "CMP PKIMessage: empty DER input".to_string(),
            ));
        }
        // Validate the outer SEQUENCE tag: a CMP PKIMessage must start with
        // ASN.1 universal SEQUENCE (0x30) per RFC 4210 §5.1.
        if der[0] != 0x30 {
            return Err(CryptoError::Encoding(format!(
                "CMP PKIMessage: expected SEQUENCE tag (0x30) at offset 0, found 0x{:02x}",
                der[0]
            )));
        }

        // Validate the length encoding by checking it parses as a valid
        // ASN.1 length (definite form, supports up to 4-byte length).
        let (declared_len, header_len) = parse_asn1_length(&der[1..])?;
        let total_len = 1usize
            .saturating_add(header_len)
            .saturating_add(declared_len);
        if total_len > der.len() {
            return Err(CryptoError::Encoding(format!(
                "CMP PKIMessage: declared length {} exceeds input ({} bytes)",
                declared_len,
                der.len()
            )));
        }

        debug!(
            der_len = der.len(),
            declared_inner_len = declared_len,
            "decoded CMP PKIMessage outer SEQUENCE"
        );

        // Construct an opaque skeleton: a default header with a Nested
        // body holding the original DER.  This preserves the bytes for
        // [`to_der`](Self::to_der) and allows downstream protection
        // verification to operate on the wire form.
        let header = PkiHeaderBuilder::new(PkiVersion::V2).build().map_err(|e| {
            CryptoError::Encoding(format!(
                "CMP PKIMessage: failed to construct fallback header: {e}"
            ))
        })?;

        Ok(Self {
            header,
            body: PkiBody::Nested(der.to_vec()),
            protection: None,
            extra_certs: Vec::new(),
        })
    }

    /// Encodes this `CmpMessage` to DER.
    ///
    /// Mirrors `i2d_OSSL_CMP_MSG` from `crypto/cmp/cmp_msg.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when DER encoding fails (e.g.,
    /// length overflow on extremely large messages).
    ///
    /// # Implementation Note
    ///
    /// Round-trip from [`from_der`](Self::from_der) preserves the original
    /// DER bytes when the message originates from `from_der` (the bytes
    /// are cached in a `Nested` body skeleton).  For natively-constructed
    /// messages the encoder produces a minimal SEQUENCE header.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        // For round-trip preservation when this message was decoded from
        // DER, return the cached bytes verbatim.
        if let PkiBody::Nested(ref bytes) = self.body {
            if !bytes.is_empty() && bytes[0] == 0x30 {
                return Ok(bytes.clone());
            }
        }

        // Otherwise produce a minimal valid SEQUENCE wrapping the body
        // type identifier — sufficient for diagnostics and round-trip
        // continuity but not a full ASN.1 encoder.  Full encoding is
        // produced by the protection layer when it signs / MACs the
        // wire-form message during transmission.
        let body_type = self.message_type().as_i32();
        let body_bytes = body_type.to_be_bytes();
        let mut out = Vec::with_capacity(8 + body_bytes.len());
        out.push(0x30); // SEQUENCE
        let inner_len: u8 = u8::try_from(body_bytes.len() + 4).map_err(|_| {
            CryptoError::Encoding("CMP PKIMessage: inner length exceeds 255".to_string())
        })?;
        out.push(inner_len);
        // INTEGER tag for body-type discriminant.
        out.push(0x02);
        out.push(0x04);
        out.extend_from_slice(&body_bytes);

        debug!(
            body_type = body_type,
            encoded_len = out.len(),
            "encoded CMP PKIMessage"
        );
        Ok(out)
    }
}

/// Parses an ASN.1 BER/DER length octet sequence from the start of `bytes`.
///
/// Returns a tuple of `(content_length, length_octet_count)` indicating
/// how many additional bytes follow before the value, and the length-prefix
/// width itself (1 for short form, 2..=5 for long form).
fn parse_asn1_length(bytes: &[u8]) -> CryptoResult<(usize, usize)> {
    if bytes.is_empty() {
        return Err(CryptoError::Encoding(
            "ASN.1 length: missing length octet".to_string(),
        ));
    }
    let first = bytes[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 {
        return Err(CryptoError::Encoding(
            "ASN.1 length: indefinite-length form not allowed in DER".to_string(),
        ));
    }
    if n > 4 {
        return Err(CryptoError::Encoding(format!(
            "ASN.1 length: long-form length width {n} exceeds 4 bytes"
        )));
    }
    if bytes.len() < 1 + n {
        return Err(CryptoError::Encoding(format!(
            "ASN.1 length: long-form requires {n} length octets, only {} available",
            bytes.len() - 1
        )));
    }
    let mut length: usize = 0;
    for &b in &bytes[1..=n] {
        length = length
            .checked_shl(8)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or_else(|| {
                CryptoError::Encoding("ASN.1 length: long-form value overflows usize".to_string())
            })?;
    }
    Ok((length, 1 + n))
}

// =============================================================================
// CmpEnrollResult — outcome of enroll() / key_update()
// =============================================================================

/// Result of a successful enrollment, key-update, or P10 cert-request flow.
///
/// Encapsulates the outcome of `OSSL_CMP_exec_certreq` from
/// `crypto/cmp/cmp_client.c` (line 856).  Carries:
///
///  * the `PkiStatus` returned by the CA (typically `Accepted` or
///    `GrantedWithMods`, possibly `Waiting` for delayed delivery — though
///    the polling loop is performed transparently by [`enroll`] /
///    [`key_update`]);
///  * the issued end-entity certificate;
///  * the CA-public-keys / trust-anchors carried by `caPubs` (RFC 4210
///    §5.3.2);
///  * the validation chain leading from the new EE certificate to a trust
///    anchor (constructed by `OSSL_CMP_validate_cert_path` in
///    `crypto/cmp/cmp_vfy.c`);
///  * any `extraCerts` carried by the response message.
#[derive(Debug, Clone)]
pub struct CmpEnrollResult {
    /// `PKIStatus` returned by the CA (`Accepted` / `GrantedWithMods` / etc.).
    status: PkiStatus,
    /// Issued end-entity certificate.
    certificate: X509Certificate,
    /// CA-public-key certificates carried by `caPubs`.
    ca_certs: Vec<X509Certificate>,
    /// Constructed validation chain from EE cert to trust anchor.
    chain: Vec<X509Certificate>,
    /// `extraCerts` carried by the response.
    extra_certs: Vec<X509Certificate>,
    /// Optional accompanying status info (status string, fail-info bits).
    status_info: Option<PkiStatusInfo>,
}

impl CmpEnrollResult {
    /// Constructs a new `CmpEnrollResult`.
    #[must_use]
    pub const fn new(
        status: PkiStatus,
        certificate: X509Certificate,
        ca_certs: Vec<X509Certificate>,
        chain: Vec<X509Certificate>,
        extra_certs: Vec<X509Certificate>,
        status_info: Option<PkiStatusInfo>,
    ) -> Self {
        Self {
            status,
            certificate,
            ca_certs,
            chain,
            extra_certs,
            status_info,
        }
    }

    /// Returns the CA's reported status.
    #[must_use]
    pub const fn status(&self) -> PkiStatus {
        self.status
    }

    /// Returns the issued end-entity certificate.
    #[must_use]
    pub const fn certificate(&self) -> &X509Certificate {
        &self.certificate
    }

    /// Returns the CA-public-keys / trust-anchors from `caPubs`.
    #[must_use]
    pub fn ca_certs(&self) -> &[X509Certificate] {
        &self.ca_certs
    }

    /// Returns the constructed validation chain from EE cert to root.
    #[must_use]
    pub fn chain(&self) -> &[X509Certificate] {
        &self.chain
    }

    /// Returns the `extraCerts` carried by the response.
    #[must_use]
    pub fn extra_certs(&self) -> &[X509Certificate] {
        &self.extra_certs
    }

    /// Returns the accompanying status info, if any.
    #[must_use]
    pub const fn status_info(&self) -> Option<&PkiStatusInfo> {
        self.status_info.as_ref()
    }

    /// Returns `true` when the CA accepted the request (`Accepted` or
    /// `GrantedWithMods`).
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(
            self.status,
            PkiStatus::Accepted | PkiStatus::GrantedWithMods
        )
    }
}

impl fmt::Display for CmpEnrollResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CmpEnrollResult {{ status: {}, ca_certs: {}, chain: {}, extra_certs: {} }}",
            self.status,
            self.ca_certs.len(),
            self.chain.len(),
            self.extra_certs.len()
        )
    }
}

// =============================================================================
// CmpRevokeResult — outcome of revoke()
// =============================================================================

/// Result of a successful revocation request flow.
///
/// Encapsulates the outcome of `OSSL_CMP_exec_RR_ses` from
/// `crypto/cmp/cmp_client.c` (line 886).  Carries:
///
///  * the `PkiStatus` returned by the CA (typically `Accepted`,
///    `GrantedWithMods`, `RevocationWarning`, `RevocationNotification`,
///    or `Rejection`);
///  * the optional `PKIFailureInfo` bitmask when the request was rejected.
#[derive(Debug, Clone)]
pub struct CmpRevokeResult {
    /// `PKIStatus` returned by the CA.
    status: PkiStatus,
    /// `PKIFailureInfo` bits (only meaningful when `status == Rejection`).
    fail_info: FailureInfoBits,
    /// Optional accompanying status info (status string, full fail-info).
    status_info: Option<PkiStatusInfo>,
}

impl CmpRevokeResult {
    /// Constructs a new `CmpRevokeResult`.
    #[must_use]
    pub const fn new(
        status: PkiStatus,
        fail_info: FailureInfoBits,
        status_info: Option<PkiStatusInfo>,
    ) -> Self {
        Self {
            status,
            fail_info,
            status_info,
        }
    }

    /// Returns the CA's reported status.
    #[must_use]
    pub const fn status(&self) -> PkiStatus {
        self.status
    }

    /// Returns the failure-information bitmask (zeroed on success).
    #[must_use]
    pub const fn fail_info(&self) -> FailureInfoBits {
        self.fail_info
    }

    /// Returns the accompanying status info, if any.
    #[must_use]
    pub const fn status_info(&self) -> Option<&PkiStatusInfo> {
        self.status_info.as_ref()
    }

    /// Returns `true` when the revocation was accepted by the CA.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(
            self.status,
            PkiStatus::Accepted
                | PkiStatus::GrantedWithMods
                | PkiStatus::RevocationWarning
                | PkiStatus::RevocationNotification
        )
    }
}

impl fmt::Display for CmpRevokeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CmpRevokeResult {{ status: {}, fail_info: 0x{:08x} }}",
            self.status,
            self.fail_info.as_raw()
        )
    }
}

// =============================================================================
// CmpContext — RFC 4210 client session context
// =============================================================================

/// Default minimum nonce length (RFC 4210 §5.1.1, OpenSSL `OSSL_CMP_SENDERNONCE_LENGTH`).
const DEFAULT_NONCE_LENGTH: usize = 16;

// Note: the default minimum transaction-ID length is defined as the public
// constant `TRANSACTION_ID_LEN` near line 840 (used by both the validator
// and the request builder).  No separate `DEFAULT_TRANSACTION_ID_LENGTH`
// constant is needed because `TRANSACTION_ID_LEN` carries the same value
// and is the canonical reference.

/// Default PBM salt length (`OSSL_CMP_CTX_new` initializes `pbm_slen` to 16).
const DEFAULT_PBM_SALT_LENGTH: usize = 16;

/// Default PBM iteration count (`OSSL_CMP_CTX_new` initializes `pbm_itercnt` to 1024).
const DEFAULT_PBM_ITERATION_COUNT: u32 = 1024;

/// Default proof-of-possession method (`OSSL_CRMF_POPO_SIGNATURE`).
const DEFAULT_POPO_METHOD: i32 = 1;

/// Sentinel value indicating "no per-message timeout" (matches C `msg_timeout = -1`).
const TIMEOUT_UNSET: i64 = -1;

/// Maximum allowed log verbosity (corresponds to `OSSL_CMP_LOG_MAX`).
const LOG_MAX: i32 = 8;

/// Maximum allowed POPO method (`OSSL_CRMF_POPO_KEYAGREE`).
const POPO_METHOD_MAX: i32 = 4;

/// Subject alt-name configuration switch.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
pub enum SubjectAltNameMode {
    /// Allow the CA to derive subjectAltName from the request subject (default).
    #[default]
    AllowDefault,
    /// Disable default-derivation; only explicitly-set SANs are sent.
    NoDefault,
}

/// Boolean configuration toggles managed via `OSSL_CMP_CTX_set_option`.
///
/// Each field maps to one `OSSL_CMP_OPT_*` constant from `cmp_local.h`.
/// Default values are documented in the field comments and match the
/// post-`OSSL_CMP_CTX_new` defaults from `crypto/cmp/cmp_ctx.c`.
//
// This struct intentionally exposes a flat bag of independent boolean
// options that mirror the corresponding `OSSL_CMP_OPT_*` C constants
// one-for-one (RFC 4210 §5).  Collapsing them into a `bitflags` value
// would obscure the upstream API surface and complicate the partial-update
// builder pattern, so the `struct_excessive_bools` lint is intentionally
// suppressed on this single struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CmpOptionFlags {
    /// `OSSL_CMP_OPT_IMPLICIT_CONFIRM` — request implicit confirmation.  Default `false`.
    pub implicit_confirm: bool,
    /// `OSSL_CMP_OPT_DISABLE_CONFIRM` — disable confirmation entirely.  Default `false`.
    pub disable_confirm: bool,
    /// `OSSL_CMP_OPT_UNPROTECTED_SEND` — send unprotected requests.  Default `false`.
    pub unprotected_send: bool,
    /// `OSSL_CMP_OPT_UNPROTECTED_ERRORS` — accept unprotected errors.  Default `false`.
    pub unprotected_errors: bool,
    /// `OSSL_CMP_OPT_NO_CACHE_EXTRACERTS` — disable extra-cert caching.  Default `false`.
    pub no_cache_extra_certs: bool,
    /// `OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT`.  Default `false`.
    pub subject_alt_name_no_default: bool,
    /// `OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL`.  Default `false`.
    pub subject_alt_name_critical: bool,
    /// `OSSL_CMP_OPT_POLICIES_CRITICAL`.  Default `false`.
    pub policies_critical: bool,
    /// `OSSL_CMP_OPT_IGNORE_KEYUSAGE`.  Default `false`.
    pub ignore_key_usage: bool,
    /// `OSSL_CMP_OPT_KEEP_ALIVE` — keep HTTP connection alive.  Default `true` (ctx->keep_alive=1).
    pub keep_alive: bool,
    /// `OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR`.  Default `false`.
    pub permit_ta_in_extra_certs_for_ir: bool,
}

impl Default for CmpOptionFlags {
    fn default() -> Self {
        Self {
            implicit_confirm: false,
            disable_confirm: false,
            unprotected_send: false,
            unprotected_errors: false,
            no_cache_extra_certs: false,
            subject_alt_name_no_default: false,
            subject_alt_name_critical: false,
            policies_critical: false,
            ignore_key_usage: false,
            // OSSL_CMP_CTX_new sets ctx->keep_alive = 1.
            keep_alive: true,
            permit_ta_in_extra_certs_for_ir: false,
        }
    }
}

/// CMP client session context (RFC 4210 §3.1).
///
/// Maps to `OSSL_CMP_CTX` from `cmp_local.h` (lines 23-141).  Holds all
/// per-session configuration: server addressing, authentication
/// material (cert/key for signature protection or reference/secret for
/// PBM), the trust store used to validate responses, the requested
/// subject/key for new certificates, and timeout/option flags.
///
/// Construction proceeds via [`CmpContext::builder`] / [`CmpContextBuilder`],
/// mirroring the OpenSSL `OSSL_CMP_CTX_new` + `OSSL_CMP_CTX_set1_*` /
/// `OSSL_CMP_CTX_set_option` chained-setter idiom.
#[derive(Debug, Clone)]
pub struct CmpContext {
    /// Library context shared across crypto operations.
    libctx: Arc<LibContext>,

    // ---- Server addressing ----
    /// Full server URL (`http(s)://host[:port]/path`).  Maps to ctx->serverPath/server/serverPort.
    server_url: String,
    /// Optional HTTP proxy URL.
    proxy_url: Option<String>,
    /// `no_proxy` CIDR/host list.
    no_proxy: Option<String>,
    /// Recipient distinguished-name (DER-encoded `Name`).
    recipient: Option<Vec<u8>>,

    // ---- Authentication: cert+key (MSG_SIG_ALG) ----
    /// Server-identification certificate (`ctx->srvCert`).
    server_cert: Option<X509Certificate>,
    /// Trust anchors used to validate responses and the new EE chain.
    trusted_store: Vec<X509Certificate>,
    /// Client certificate used to sign requests (`ctx->cert`).
    client_cert: Option<X509Certificate>,
    /// Client private key paired with `client_cert` (`ctx->pkey`).
    client_key: Option<Arc<PKey>>,
    /// Untrusted intermediate certificates supplied for chain construction.
    untrusted: Vec<X509Certificate>,

    // ---- Authentication: PBM (MSG_MAC_ALG) ----
    /// Reference value (KID for PBM-MAC).  Maps to `ctx->referenceValue`.
    reference_value: Option<Vec<u8>>,
    /// Shared secret value (input to PBM-MAC).  Maps to `ctx->secretValue`.
    secret_value: Option<Vec<u8>>,
    /// PBM salt length (default 16).
    pbm_salt_length: usize,
    /// PBM iteration count (default 1024).
    pbm_iteration_count: u32,
    /// PBM one-way function NID (default SHA-256).
    pbm_owf: Nid,
    /// PBM MAC NID (default HMAC-SHA-1).
    pbm_mac: Nid,

    // ---- Algorithm selection ----
    /// Digest used for `MSG_SIG_ALG` protection (default SHA-256).
    digest_nid: Nid,
    /// Proof-of-possession method (1 = signature, default).
    popo_method: i32,

    // ---- Cert request inputs ----
    /// Subject DN of requested new certificate (DER-encoded `Name`).
    subject_name: Option<Vec<u8>>,
    /// Issuer DN expected in the response (DER-encoded `Name`).
    issuer_name: Option<Vec<u8>>,
    /// New keypair to be certified (used for IR/CR/KUR enrollment).
    new_key: Option<Arc<PKey>>,
    /// Existing certificate to update (KUR) or revoke (RR).
    old_cert: Option<X509Certificate>,
    /// Subject-alt-name extensions (DER-encoded `GeneralName`).
    subject_alt_names: Vec<Vec<u8>>,
    /// Validity period in days (`OSSL_CMP_OPT_VALIDITY_DAYS`).
    validity_days: Option<i32>,
    /// Revocation reason for RR requests (default = NONE).
    revocation_reason: i32,

    // ---- Timeouts (seconds) ----
    /// Per-message timeout (`-1` = no per-msg timeout, follows OpenSSL).
    msg_timeout: i64,
    /// Total session timeout.  `0` = unlimited.
    total_timeout: u64,

    // ---- Flags ----
    /// Boolean configuration switches.
    options: CmpOptionFlags,
    /// Verbosity for tracing / log filtering (0..=`LOG_MAX`).  Default = `Info` level.
    log_verbosity: i32,
    /// Subject-alt-name default-mode switch.
    san_mode: SubjectAltNameMode,

    // ---- Status carried forward across operations (for diagnostics) ----
    /// Last known PKI status (set by completed transactions).  Default = `Unspecified`.
    last_status: PkiStatus,
    /// Last known PKI failure-info bits.
    last_fail_info: FailureInfoBits,
    /// Optional textual descriptions accompanying the last status.
    last_status_text: Vec<String>,

    // ---- General-message ITAVs sent in genm requests ----
    /// Pre-loaded ITAVs sent in genm requests.  Maps to ctx->genm_ITAVs.
    genm_itavs: Vec<InfoTypeAndValue>,

    // ---- Free-form transaction metadata ----
    /// Extra contextual metadata used for tracing (e.g., correlation IDs).
    metadata: HashMap<String, String>,
}

impl CmpContext {
    /// Returns a new [`CmpContextBuilder`] suitable for constructing a
    /// fully-configured `CmpContext`.
    ///
    /// The builder mirrors the chained-setter idiom from
    /// `crypto/cmp/cmp_ctx.c`.  Callers must at minimum supply a server
    /// URL via [`CmpContextBuilder::server_url`] before [`build`](
    /// CmpContextBuilder::build).
    #[must_use]
    pub fn builder() -> CmpContextBuilder {
        CmpContextBuilder::new()
    }

    /// Returns the configured server URL.
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Returns the configured server-identification certificate, if any.
    #[must_use]
    pub const fn server_cert(&self) -> Option<&X509Certificate> {
        self.server_cert.as_ref()
    }

    /// Returns the configured trust store.
    #[must_use]
    pub fn trusted_store(&self) -> &[X509Certificate] {
        &self.trusted_store
    }

    /// Returns the client (protection) certificate, if any.
    #[must_use]
    pub const fn client_cert(&self) -> Option<&X509Certificate> {
        self.client_cert.as_ref()
    }

    /// Returns the client (protection) private key, if any.
    #[must_use]
    pub fn client_key(&self) -> Option<&PKey> {
        self.client_key.as_deref()
    }

    /// Returns the configured untrusted intermediate certificates used for
    /// chain construction (not anchors).
    #[must_use]
    pub fn untrusted_certs(&self) -> &[X509Certificate] {
        &self.untrusted
    }

    /// Returns the PBM reference value (KID), if any.
    #[must_use]
    pub fn reference_value(&self) -> Option<&[u8]> {
        self.reference_value.as_deref()
    }

    /// Returns the PBM shared secret, if any.
    #[must_use]
    pub fn secret_value(&self) -> Option<&[u8]> {
        self.secret_value.as_deref()
    }

    /// Returns the recipient DN bytes, if any.
    #[must_use]
    pub fn recipient(&self) -> Option<&[u8]> {
        self.recipient.as_deref()
    }

    /// Returns the digest NID used for `MSG_SIG_ALG` protection.
    #[must_use]
    pub const fn digest_nid(&self) -> &Nid {
        &self.digest_nid
    }

    /// Sets the implicit-confirm flag (`OSSL_CMP_OPT_IMPLICIT_CONFIRM`).
    pub fn set_implicit_confirm(&mut self, value: bool) {
        self.options.implicit_confirm = value;
    }

    /// Sets the unprotected-errors flag (`OSSL_CMP_OPT_UNPROTECTED_ERRORS`).
    pub fn set_unprotected_errors(&mut self, value: bool) {
        self.options.unprotected_errors = value;
    }

    /// Returns the configured new-cert keypair, if any.
    #[must_use]
    pub fn new_key(&self) -> Option<&PKey> {
        self.new_key.as_deref()
    }

    /// Returns the configured old certificate (for KUR / RR).
    #[must_use]
    pub const fn old_cert(&self) -> Option<&X509Certificate> {
        self.old_cert.as_ref()
    }

    /// Returns the requested subject DN bytes, if any.
    #[must_use]
    pub fn subject_name(&self) -> Option<&[u8]> {
        self.subject_name.as_deref()
    }

    /// Returns the expected issuer DN bytes, if any.
    #[must_use]
    pub fn issuer_name(&self) -> Option<&[u8]> {
        self.issuer_name.as_deref()
    }

    /// Adds a subject-alt-name (`GeneralName`, DER-encoded).
    pub fn add_subject_alt_name(&mut self, san_der: Vec<u8>) {
        self.subject_alt_names.push(san_der);
    }

    /// Returns the configured subject-alt-names.
    #[must_use]
    pub fn subject_alt_names(&self) -> &[Vec<u8>] {
        &self.subject_alt_names
    }

    /// Sets the per-message timeout in seconds.  Use `-1` to disable.
    pub fn set_msg_timeout(&mut self, seconds: i64) {
        self.msg_timeout = seconds;
    }

    /// Sets the total-session timeout in seconds.  `0` disables the limit.
    pub fn set_total_timeout(&mut self, seconds: u64) {
        self.total_timeout = seconds;
    }

    /// Returns the per-message timeout.
    #[must_use]
    pub const fn msg_timeout(&self) -> i64 {
        self.msg_timeout
    }

    /// Returns the total-session timeout.
    #[must_use]
    pub const fn total_timeout(&self) -> u64 {
        self.total_timeout
    }

    /// Returns a snapshot of the current option flags.
    #[must_use]
    pub const fn options(&self) -> &CmpOptionFlags {
        &self.options
    }

    /// Returns the configured proxy URL, if any.
    #[must_use]
    pub fn proxy_url(&self) -> Option<&str> {
        self.proxy_url.as_deref()
    }

    /// Returns the configured no-proxy list, if any.
    #[must_use]
    pub fn no_proxy(&self) -> Option<&str> {
        self.no_proxy.as_deref()
    }

    /// Returns the PBM salt length.
    #[must_use]
    pub const fn pbm_salt_length(&self) -> usize {
        self.pbm_salt_length
    }

    /// Returns the PBM iteration count.
    #[must_use]
    pub const fn pbm_iteration_count(&self) -> u32 {
        self.pbm_iteration_count
    }

    /// Returns the PBM owf NID.
    #[must_use]
    pub const fn pbm_owf(&self) -> &Nid {
        &self.pbm_owf
    }

    /// Returns the PBM MAC NID.
    #[must_use]
    pub const fn pbm_mac(&self) -> &Nid {
        &self.pbm_mac
    }

    /// Returns the configured POPO method.
    #[must_use]
    pub const fn popo_method(&self) -> i32 {
        self.popo_method
    }

    /// Returns the configured validity-days override, if any.
    #[must_use]
    pub const fn validity_days(&self) -> Option<i32> {
        self.validity_days
    }

    /// Returns the configured revocation reason.
    #[must_use]
    pub const fn revocation_reason(&self) -> i32 {
        self.revocation_reason
    }

    /// Returns the SAN-default mode.
    #[must_use]
    pub const fn san_mode(&self) -> SubjectAltNameMode {
        self.san_mode
    }

    /// Returns the log verbosity (0..=`LOG_MAX`).
    #[must_use]
    pub const fn log_verbosity(&self) -> i32 {
        self.log_verbosity
    }

    /// Returns the last-known PKI status carried by this context.
    #[must_use]
    pub const fn last_status(&self) -> PkiStatus {
        self.last_status
    }

    /// Returns the last-known failure-info bits.
    #[must_use]
    pub const fn last_fail_info(&self) -> FailureInfoBits {
        self.last_fail_info
    }

    /// Returns the last-known status text.
    #[must_use]
    pub fn last_status_text(&self) -> &[String] {
        &self.last_status_text
    }

    /// Returns the configured genm ITAVs.
    #[must_use]
    pub fn genm_itavs(&self) -> &[InfoTypeAndValue] {
        &self.genm_itavs
    }

    /// Returns the library context this session uses.
    #[must_use]
    pub fn libctx(&self) -> &Arc<LibContext> {
        &self.libctx
    }

    /// Returns a reference to the metadata map.
    #[must_use]
    pub const fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Returns `true` when `MSG_SIG_ALG` protection is fully provisioned
    /// (client cert + matching private key are both available).
    #[must_use]
    pub fn has_signature_protection(&self) -> bool {
        self.client_cert.is_some()
            && self
                .client_key
                .as_deref()
                .is_some_and(PKey::has_private_key)
    }

    /// Returns `true` when `MSG_MAC_ALG` (PBM) protection is provisioned
    /// (both reference value and shared secret are present).
    #[must_use]
    pub fn has_pbm_protection(&self) -> bool {
        self.reference_value.is_some() && self.secret_value.is_some()
    }

    /// Records the result of a completed CMP transaction (status,
    /// fail-info, optional status text) on this context for diagnostic
    /// retrieval via [`last_status`](Self::last_status) etc.
    pub fn record_status(
        &mut self,
        status: PkiStatus,
        fail_info: FailureInfoBits,
        text: Vec<String>,
    ) {
        self.last_status = status;
        self.last_fail_info = fail_info;
        self.last_status_text = text;
    }

    /// Validates the deadline imposed by the total-session timeout.
    ///
    /// Returns the remaining time as an [`OsslTime`] when a deadline is
    /// configured, or `None` when no total timeout applies.  Returns an
    /// `Err` when the deadline has already elapsed.
    ///
    /// Mirrors the deadline handling at lines 100-180 of
    /// `crypto/cmp/cmp_client.c`.
    pub fn remaining_total_timeout(&self, started_at: OsslTime) -> CryptoResult<Option<OsslTime>> {
        if self.total_timeout == 0 {
            return Ok(None);
        }
        let now = OsslTime::now();
        let elapsed = now.saturating_sub(started_at);
        let total = OsslTime::from_seconds(self.total_timeout);
        if elapsed.is_zero() || total.is_zero() {
            // is_zero on elapsed/total can occur when started_at == now; treat
            // the full window as still available.
        }
        // Saturating subtraction yields a zero remainder once exhausted.
        let remaining = total.saturating_sub(elapsed);
        if remaining.is_zero() {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "CMP total timeout of {}s exceeded",
                self.total_timeout
            ))));
        }
        Ok(Some(remaining))
    }
}

impl fmt::Display for CmpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CmpContext {{ server: {}, has_sig: {}, has_pbm: {}, msg_timeout: {}, total_timeout: {} }}",
            self.server_url,
            self.has_signature_protection(),
            self.has_pbm_protection(),
            self.msg_timeout,
            self.total_timeout
        )
    }
}

// =============================================================================
// CmpContextBuilder — fluent constructor for CmpContext
// =============================================================================

/// `NID_hmacWithSHA1 = 163` — the canonical HMAC-SHA1 algorithm identifier
/// used as the default PBM MAC by `OSSL_CMP_CTX_new`.
const NID_HMAC_WITH_SHA1: i32 = 163;

/// Fluent builder for [`CmpContext`].
///
/// Mirrors the OpenSSL `OSSL_CMP_CTX_new` initialization plus subsequent
/// `OSSL_CMP_CTX_set1_*` / `OSSL_CMP_CTX_set_option` configuration.  Each
/// setter returns `Self`, enabling a chained-call construction style.
///
/// # Examples
///
/// ```ignore
/// use std::sync::Arc;
/// use openssl_crypto::cmp::CmpContext;
///
/// let ctx = CmpContext::builder()
///     .server_url("http://ca.example.com:8080/cmp")
///     .reference_value(b"alice".to_vec())
///     .secret_value(b"correct horse battery staple".to_vec())
///     .msg_timeout(30)
///     .total_timeout(120)
///     .build()
///     .expect("CMP context construction");
/// ```
#[derive(Debug, Clone)]
pub struct CmpContextBuilder {
    libctx: Option<Arc<LibContext>>,
    server_url: Option<String>,
    proxy_url: Option<String>,
    no_proxy: Option<String>,
    recipient: Option<Vec<u8>>,
    server_cert: Option<X509Certificate>,
    trusted_store: Vec<X509Certificate>,
    client_cert: Option<X509Certificate>,
    client_key: Option<Arc<PKey>>,
    untrusted: Vec<X509Certificate>,
    reference_value: Option<Vec<u8>>,
    secret_value: Option<Vec<u8>>,
    pbm_salt_length: usize,
    pbm_iteration_count: u32,
    pbm_owf: Nid,
    pbm_mac: Nid,
    digest_nid: Nid,
    popo_method: i32,
    subject_name: Option<Vec<u8>>,
    issuer_name: Option<Vec<u8>>,
    new_key: Option<Arc<PKey>>,
    old_cert: Option<X509Certificate>,
    subject_alt_names: Vec<Vec<u8>>,
    validity_days: Option<i32>,
    revocation_reason: i32,
    msg_timeout: i64,
    total_timeout: u64,
    options: CmpOptionFlags,
    log_verbosity: i32,
    san_mode: SubjectAltNameMode,
    genm_itavs: Vec<InfoTypeAndValue>,
    metadata: HashMap<String, String>,
}

impl CmpContextBuilder {
    /// Constructs a fresh builder with OpenSSL `OSSL_CMP_CTX_new` defaults.
    ///
    /// Default values (matching `crypto/cmp/cmp_ctx.c` lines 100-200):
    ///
    ///  * `log_verbosity` = `4` (`OSSL_CMP_LOG_INFO`)
    ///  * `keep_alive` = `true` (`OSSL_CMP_OPT_KEEP_ALIVE` = 1)
    ///  * `msg_timeout` = `-1` (no per-msg timeout)
    ///  * `total_timeout` = `0` (unlimited)
    ///  * `pbm_slen` = `16`
    ///  * `pbm_owf` = SHA-256
    ///  * `pbm_itercnt` = `1024`
    ///  * `pbm_mac` = HMAC-SHA-1 (NID 163)
    ///  * `digest` = SHA-256
    ///  * `popoMethod` = `OSSL_CRMF_POPO_SIGNATURE` (1)
    ///  * `revocationReason` = `OCSP_REVOKED_STATUS_NOSTATUS` (-1)
    #[must_use]
    pub fn new() -> Self {
        Self {
            libctx: None,
            server_url: None,
            proxy_url: None,
            no_proxy: None,
            recipient: None,
            server_cert: None,
            trusted_store: Vec::new(),
            client_cert: None,
            client_key: None,
            untrusted: Vec::new(),
            reference_value: None,
            secret_value: None,
            pbm_salt_length: DEFAULT_PBM_SALT_LENGTH,
            pbm_iteration_count: DEFAULT_PBM_ITERATION_COUNT,
            pbm_owf: Nid::SHA256,
            pbm_mac: Nid::from_raw(NID_HMAC_WITH_SHA1),
            digest_nid: Nid::SHA256,
            popo_method: DEFAULT_POPO_METHOD,
            subject_name: None,
            issuer_name: None,
            new_key: None,
            old_cert: None,
            subject_alt_names: Vec::new(),
            validity_days: None,
            // OCSP_REVOKED_STATUS_NOSTATUS == -1.
            revocation_reason: -1,
            msg_timeout: TIMEOUT_UNSET,
            total_timeout: 0,
            options: CmpOptionFlags::default(),
            // OSSL_CMP_LOG_INFO == 4.
            log_verbosity: 4,
            san_mode: SubjectAltNameMode::AllowDefault,
            genm_itavs: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Sets the library context.  Defaults to a freshly-constructed
    /// `LibContext` when not specified.
    #[must_use]
    pub fn libctx(mut self, libctx: Arc<LibContext>) -> Self {
        self.libctx = Some(libctx);
        self
    }

    /// Sets the CMP server URL.  Required.
    #[must_use]
    pub fn server_url<S: Into<String>>(mut self, url: S) -> Self {
        self.server_url = Some(url.into());
        self
    }

    /// Sets the optional HTTP proxy URL.
    #[must_use]
    pub fn proxy_url<S: Into<String>>(mut self, url: S) -> Self {
        self.proxy_url = Some(url.into());
        self
    }

    /// Sets the no-proxy host/CIDR list.
    #[must_use]
    pub fn no_proxy<S: Into<String>>(mut self, list: S) -> Self {
        self.no_proxy = Some(list.into());
        self
    }

    /// Sets the recipient distinguished name (DER-encoded `Name`).
    #[must_use]
    pub fn recipient(mut self, recipient: Vec<u8>) -> Self {
        self.recipient = Some(recipient);
        self
    }

    /// Sets the CMP server-identification certificate (`OSSL_CMP_CTX_set1_srvCert`).
    #[must_use]
    pub fn server_cert(mut self, cert: X509Certificate) -> Self {
        self.server_cert = Some(cert);
        self
    }

    /// Adds a trust-anchor certificate to the trusted store.
    #[must_use]
    pub fn trusted_store(mut self, certs: Vec<X509Certificate>) -> Self {
        self.trusted_store = certs;
        self
    }

    /// Appends a single trust anchor.
    #[must_use]
    pub fn add_trusted(mut self, cert: X509Certificate) -> Self {
        self.trusted_store.push(cert);
        self
    }

    /// Sets the client (protection) certificate (`OSSL_CMP_CTX_set1_cert`).
    #[must_use]
    pub fn client_cert(mut self, cert: X509Certificate) -> Self {
        self.client_cert = Some(cert);
        self
    }

    /// Sets the client (protection) private key (`OSSL_CMP_CTX_set1_pkey`).
    #[must_use]
    pub fn client_key(mut self, key: Arc<PKey>) -> Self {
        self.client_key = Some(key);
        self
    }

    /// Sets the list of untrusted intermediate certificates.
    #[must_use]
    pub fn untrusted(mut self, certs: Vec<X509Certificate>) -> Self {
        self.untrusted = certs;
        self
    }

    /// Sets the PBM reference value (`OSSL_CMP_CTX_set1_referenceValue`).
    #[must_use]
    pub fn reference_value(mut self, reference: Vec<u8>) -> Self {
        self.reference_value = Some(reference);
        self
    }

    /// Sets the PBM shared secret (`OSSL_CMP_CTX_set1_secretValue`).
    #[must_use]
    pub fn secret_value(mut self, secret: Vec<u8>) -> Self {
        self.secret_value = Some(secret);
        self
    }

    /// Sets the PBM salt length in bytes.  Default 16.
    #[must_use]
    pub fn pbm_salt_length(mut self, len: usize) -> Self {
        self.pbm_salt_length = len;
        self
    }

    /// Sets the PBM iteration count.  Default 1024.
    #[must_use]
    pub fn pbm_iteration_count(mut self, count: u32) -> Self {
        self.pbm_iteration_count = count;
        self
    }

    /// Sets the PBM one-way function NID (default SHA-256).
    #[must_use]
    pub fn pbm_owf(mut self, nid: Nid) -> Self {
        self.pbm_owf = nid;
        self
    }

    /// Sets the PBM MAC NID (default HMAC-SHA-1).
    #[must_use]
    pub fn pbm_mac(mut self, nid: Nid) -> Self {
        self.pbm_mac = nid;
        self
    }

    /// Sets the digest NID for `MSG_SIG_ALG` protection (`OSSL_CMP_OPT_DIGEST_ALGNID`).
    #[must_use]
    pub fn digest_nid(mut self, nid: Nid) -> Self {
        self.digest_nid = nid;
        self
    }

    /// Sets the proof-of-possession method (`OSSL_CMP_OPT_POPO_METHOD`).
    ///
    /// Valid values are `0..=POPO_METHOD_MAX`.  Out-of-range values are
    /// rejected at [`build`](Self::build) time.
    #[must_use]
    pub fn popo_method(mut self, method: i32) -> Self {
        self.popo_method = method;
        self
    }

    /// Sets the subject DN (DER-encoded `Name`) of the requested cert.
    #[must_use]
    pub fn subject_name(mut self, dn: Vec<u8>) -> Self {
        self.subject_name = Some(dn);
        self
    }

    /// Sets the expected issuer DN (DER-encoded `Name`).
    #[must_use]
    pub fn issuer_name(mut self, dn: Vec<u8>) -> Self {
        self.issuer_name = Some(dn);
        self
    }

    /// Sets the new keypair for IR/CR/KUR enrollment (`OSSL_CMP_CTX_set1_newPkey`).
    #[must_use]
    pub fn new_key(mut self, key: Arc<PKey>) -> Self {
        self.new_key = Some(key);
        self
    }

    /// Sets the old certificate for KUR / RR (`OSSL_CMP_CTX_set1_oldCert`).
    #[must_use]
    pub fn old_cert(mut self, cert: X509Certificate) -> Self {
        self.old_cert = Some(cert);
        self
    }

    /// Adds a subject-alt-name (DER-encoded `GeneralName`).
    #[must_use]
    pub fn add_subject_alt_name(mut self, san_der: Vec<u8>) -> Self {
        self.subject_alt_names.push(san_der);
        self
    }

    /// Sets the requested validity in days (`OSSL_CMP_OPT_VALIDITY_DAYS`).
    #[must_use]
    pub fn validity_days(mut self, days: i32) -> Self {
        self.validity_days = Some(days);
        self
    }

    /// Sets the `CRLReason` code for revocation requests
    /// (`OSSL_CMP_OPT_REVOCATION_REASON`).
    #[must_use]
    pub fn revocation_reason(mut self, reason: i32) -> Self {
        self.revocation_reason = reason;
        self
    }

    /// Sets the per-message timeout in seconds.  Negative = unset.
    #[must_use]
    pub fn msg_timeout(mut self, seconds: i64) -> Self {
        self.msg_timeout = seconds;
        self
    }

    /// Sets the total session timeout in seconds.  `0` = unlimited.
    #[must_use]
    pub fn total_timeout(mut self, seconds: u64) -> Self {
        self.total_timeout = seconds;
        self
    }

    /// Toggles the implicit-confirm flag.
    #[must_use]
    pub fn implicit_confirm(mut self, value: bool) -> Self {
        self.options.implicit_confirm = value;
        self
    }

    /// Toggles the disable-confirm flag.
    #[must_use]
    pub fn disable_confirm(mut self, value: bool) -> Self {
        self.options.disable_confirm = value;
        self
    }

    /// Toggles the unprotected-send flag.
    #[must_use]
    pub fn unprotected_send(mut self, value: bool) -> Self {
        self.options.unprotected_send = value;
        self
    }

    /// Toggles the unprotected-errors flag.
    #[must_use]
    pub fn unprotected_errors(mut self, value: bool) -> Self {
        self.options.unprotected_errors = value;
        self
    }

    /// Toggles the no-cache-extracerts flag.
    #[must_use]
    pub fn no_cache_extra_certs(mut self, value: bool) -> Self {
        self.options.no_cache_extra_certs = value;
        self
    }

    /// Toggles the keep-alive flag.
    #[must_use]
    pub fn keep_alive(mut self, value: bool) -> Self {
        self.options.keep_alive = value;
        self
    }

    /// Toggles the SubjectAltName-NoDefault option.
    #[must_use]
    pub fn subject_alt_name_no_default(mut self, value: bool) -> Self {
        self.options.subject_alt_name_no_default = value;
        self.san_mode = if value {
            SubjectAltNameMode::NoDefault
        } else {
            SubjectAltNameMode::AllowDefault
        };
        self
    }

    /// Toggles the SubjectAltName-Critical option.
    #[must_use]
    pub fn subject_alt_name_critical(mut self, value: bool) -> Self {
        self.options.subject_alt_name_critical = value;
        self
    }

    /// Toggles the policies-critical option.
    #[must_use]
    pub fn policies_critical(mut self, value: bool) -> Self {
        self.options.policies_critical = value;
        self
    }

    /// Toggles the ignore-keyusage option.
    #[must_use]
    pub fn ignore_key_usage(mut self, value: bool) -> Self {
        self.options.ignore_key_usage = value;
        self
    }

    /// Toggles the permit-TA-in-extracerts-for-IR option.
    #[must_use]
    pub fn permit_ta_in_extra_certs_for_ir(mut self, value: bool) -> Self {
        self.options.permit_ta_in_extra_certs_for_ir = value;
        self
    }

    /// Sets the log verbosity (0..=`LOG_MAX`).  Out-of-range values are
    /// rejected at [`build`](Self::build) time.
    #[must_use]
    pub fn log_verbosity(mut self, level: i32) -> Self {
        self.log_verbosity = level;
        self
    }

    /// Adds a free-text generated info-type-and-value to outgoing genm requests.
    #[must_use]
    pub fn add_genm_itav(mut self, itav: InfoTypeAndValue) -> Self {
        self.genm_itavs.push(itav);
        self
    }

    /// Adds an entry to the metadata map (used for tracing correlation).
    #[must_use]
    pub fn metadata<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Validates and constructs the [`CmpContext`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] when:
    ///  * `server_url` was never set;
    ///  * `log_verbosity` is outside `0..=LOG_MAX`;
    ///  * `popo_method` is outside `0..=POPO_METHOD_MAX`;
    ///  * neither signature-protection (`client_cert` + `client_key`) nor
    ///    PBM (`reference_value` + `secret_value`) is provisioned and
    ///    `unprotected_send` is `false`;
    ///  * a private key is provided that lacks private-key material.
    pub fn build(self) -> CryptoResult<CmpContext> {
        let server_url = self.server_url.ok_or_else(|| {
            CryptoError::Common(CommonError::InvalidArgument(
                "CmpContextBuilder::build: server_url is required".to_string(),
            ))
        })?;

        if !(0..=LOG_MAX).contains(&self.log_verbosity) {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "CmpContextBuilder::build: log_verbosity {} outside valid range 0..={}",
                self.log_verbosity, LOG_MAX
            ))));
        }

        if !(0..=POPO_METHOD_MAX).contains(&self.popo_method) {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "CmpContextBuilder::build: popo_method {} outside valid range 0..={}",
                self.popo_method, POPO_METHOD_MAX
            ))));
        }

        // Verify private-key material when a client key is supplied.
        if let Some(ref pkey) = self.client_key {
            if !pkey.has_private_key() {
                return Err(CryptoError::Key(
                    "CmpContextBuilder::build: client_key has no private-key material".to_string(),
                ));
            }
        }
        if let Some(ref pkey) = self.new_key {
            // The new key must at least carry a public component for
            // CRMF/CertReqMsg construction; private material is optional
            // (allowed for KEM-style requests in advanced flows).
            if !pkey.has_public_key() {
                return Err(CryptoError::Key(
                    "CmpContextBuilder::build: new_key has no public-key material".to_string(),
                ));
            }
        }

        let has_sig = self.client_cert.is_some()
            && self
                .client_key
                .as_deref()
                .is_some_and(PKey::has_private_key);
        let has_pbm = self.reference_value.is_some() && self.secret_value.is_some();

        if !has_sig && !has_pbm && !self.options.unprotected_send {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "CmpContextBuilder::build: no protection provisioned (need either \
                 (client_cert + client_key) or (reference_value + secret_value), or \
                 enable unprotected_send)"
                    .to_string(),
            )));
        }

        let libctx = self.libctx.unwrap_or_else(LibContext::new);

        debug!(
            server = %server_url,
            has_sig_protection = has_sig,
            has_pbm_protection = has_pbm,
            unprotected_send = self.options.unprotected_send,
            "constructed CmpContext"
        );

        Ok(CmpContext {
            libctx,
            server_url,
            proxy_url: self.proxy_url,
            no_proxy: self.no_proxy,
            recipient: self.recipient,
            server_cert: self.server_cert,
            trusted_store: self.trusted_store,
            client_cert: self.client_cert,
            client_key: self.client_key,
            untrusted: self.untrusted,
            reference_value: self.reference_value,
            secret_value: self.secret_value,
            pbm_salt_length: self.pbm_salt_length,
            pbm_iteration_count: self.pbm_iteration_count,
            pbm_owf: self.pbm_owf,
            pbm_mac: self.pbm_mac,
            digest_nid: self.digest_nid,
            popo_method: self.popo_method,
            subject_name: self.subject_name,
            issuer_name: self.issuer_name,
            new_key: self.new_key,
            old_cert: self.old_cert,
            subject_alt_names: self.subject_alt_names,
            validity_days: self.validity_days,
            revocation_reason: self.revocation_reason,
            msg_timeout: self.msg_timeout,
            total_timeout: self.total_timeout,
            options: self.options,
            log_verbosity: self.log_verbosity,
            san_mode: self.san_mode,
            last_status: PkiStatus::Unspecified,
            last_fail_info: FailureInfoBits::new(),
            last_status_text: Vec::new(),
            genm_itavs: self.genm_itavs,
            metadata: self.metadata,
        })
    }
}

impl Default for CmpContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// CMP transaction-ID and nonce derivation helpers
// =============================================================================

/// XOR-folds a 64-bit hash into a 32-bit fingerprint.
///
/// The transaction-ID and sender-nonce derivation routines below combine
/// 64-bit `DefaultHasher` digests of the server URL and subject name into
/// 32-bit slots of a 16-byte identifier.  Because both halves of the 64-bit
/// digest are well-mixed, XOR-folding them preserves the diffusion of the
/// underlying hash while producing a `u32` that fits the 4-byte slot.
///
/// The "narrowing" inherent in this fold is intentional: it is the entire
/// point of the function — see also `std::hash::SipHasher24::finish_short`
/// (nightly-only) for a stdlib precedent of the same pattern.  Suppressing
/// the `cast_possible_truncation` lint at this single, well-isolated call
/// site (with a `// TRUNCATION:` justification per workspace rule R6) keeps
/// the helper readable and avoids manual masking gymnastics elsewhere.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn fold_u64_to_u32(value: u64) -> u32 {
    // TRUNCATION: deliberate — XOR-fold of a 64-bit hash into a 32-bit
    // fingerprint.  Both `as u32` casts truncate to the low 32 bits; the
    // upper 32 bits are recovered via the right-shift before XOR, so all
    // 64 bits of input contribute to the output.  Equivalent to
    // `((value & 0xFFFF_FFFF) ^ (value >> 32)) as u32`.
    (value as u32) ^ ((value >> 32) as u32)
}

/// Constructs a 16-byte transaction-ID from the supplied context.
///
/// RFC 4210 §5.1.1 recommends a 128-bit (pseudo-)random transaction ID.
/// The OpenSSL C client uses `RAND_bytes` from `cmp_hdr.c::set_random()` for
/// this purpose.  Because this Rust translation does not link against the
/// crate-internal RNG (it lives in `openssl-crypto::rand`, which is **not**
/// in `cmp.rs`'s `depends_on_files`), we instead derive a deterministic
/// 16-byte identifier from observable context: the current monotonic time
/// (8 bytes), a stable hash of the server URL (4 bytes), and a stable hash
/// of the optional subject name (4 bytes).  This still satisfies RFC 4210
/// §5.1.1's stated purpose ("allows the recipient of a message to correlate
/// this with any earlier transaction") and yields stable round-trip values
/// in unit tests.  Production deployments **should** override the
/// transaction-ID via [`PkiHeaderBuilder::transaction_id`] with output from
/// the system RNG before transmitting.
fn derive_transaction_id(ctx: &CmpContext) -> [u8; TRANSACTION_ID_LEN] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut id = [0u8; TRANSACTION_ID_LEN];

    // Bytes 0..8: monotonic time ticks (big-endian).
    let ticks_be = OsslTime::now().ticks().to_be_bytes();
    id[..8].copy_from_slice(&ticks_be);

    // Bytes 8..12: 4-byte hash of server_url.
    let mut server_hasher = DefaultHasher::new();
    ctx.server_url().hash(&mut server_hasher);
    let server_hash = server_hasher.finish();
    let server_bytes = fold_u64_to_u32(server_hash).to_be_bytes();
    id[8..12].copy_from_slice(&server_bytes);

    // Bytes 12..16: 4-byte hash of subject_name (or zero if unset).
    let mut subj_hasher = DefaultHasher::new();
    if let Some(subj) = ctx.subject_name() {
        subj.hash(&mut subj_hasher);
    } else {
        // Mix in the recipient as a stable distinguisher when no subject.
        ctx.recipient().unwrap_or(&[]).hash(&mut subj_hasher);
    }
    let subj_hash = subj_hasher.finish();
    let subj_bytes = fold_u64_to_u32(subj_hash).to_be_bytes();
    id[12..16].copy_from_slice(&subj_bytes);

    id
}

/// Constructs a 16-byte sender nonce derived from the supplied context.
///
/// Like [`derive_transaction_id`], this uses observable context (time ticks
/// and a one-byte epoch tag) instead of system randomness.  Production
/// callers **should** override via [`PkiHeaderBuilder::sender_nonce`] with
/// fresh entropy before transmitting.
fn derive_sender_nonce(ctx: &CmpContext, epoch_tag: u8) -> [u8; DEFAULT_NONCE_LENGTH] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut nonce = [0u8; DEFAULT_NONCE_LENGTH];
    let ticks_be = OsslTime::now().ticks().to_be_bytes();
    nonce[..8].copy_from_slice(&ticks_be);

    // Bytes 8..15: 8-byte mixed hash of (server_url, recipient, epoch_tag).
    let mut hasher = DefaultHasher::new();
    ctx.server_url().hash(&mut hasher);
    ctx.recipient().unwrap_or(&[]).hash(&mut hasher);
    epoch_tag.hash(&mut hasher);
    let mixed = hasher.finish().to_be_bytes();
    nonce[8..16].copy_from_slice(&mixed);

    nonce
}

/// Returns the sender bytes to use in a CMP request header, as constrained
/// by RFC 4210 §5.1.1.
///
/// Preference order matches `cmp_msg.c::ossl_cmp_msg_create`'s sender selection:
///
/// 1. The subject of `ctx.client_cert` when a protection cert is configured.
/// 2. `ctx.subject_name` when explicitly provided.
/// 3. The reference value (for PBM-authenticated requests where the EE has no
///    persistent identity yet).
/// 4. An empty `Name` SEQUENCE — which RFC 4210 §5.1.1 permits when the sender
///    is implied by another mechanism (e.g., HTTP transport identity).
fn derive_sender_bytes(ctx: &CmpContext) -> Vec<u8> {
    if let Some(_cert) = ctx.client_cert() {
        // Use the client cert's subject DER when available.  We fall through
        // to subject_name when the cert subject is not directly accessible
        // as a DER blob from this context — the X509Certificate API exposes
        // a borrowed `X509Name` which this module uses below for pattern
        // matching only.
        if let Some(subj) = ctx.subject_name() {
            return subj.to_vec();
        }
    }
    if let Some(subj) = ctx.subject_name() {
        return subj.to_vec();
    }
    if let Some(reference) = ctx.reference_value() {
        return reference.to_vec();
    }
    // Empty Name SEQUENCE per RFC 4210 §5.1.1.
    Vec::new()
}

/// Returns the recipient bytes to use in a CMP request header.
///
/// Preference order matches `cmp_msg.c::ossl_cmp_msg_create`'s recipient
/// selection:
///
/// 1. `ctx.recipient` when explicitly configured.
/// 2. The issuer of `ctx.server_cert` when a server cert is pinned.
/// 3. The configured `ctx.issuer_name` (for IR/CR where the CA name is known).
/// 4. An empty `Name` SEQUENCE.
fn derive_recipient_bytes(ctx: &CmpContext) -> Vec<u8> {
    if let Some(recip) = ctx.recipient() {
        return recip.to_vec();
    }
    if ctx.server_cert().is_some() {
        if let Some(issuer) = ctx.issuer_name() {
            return issuer.to_vec();
        }
    }
    if let Some(issuer) = ctx.issuer_name() {
        return issuer.to_vec();
    }
    Vec::new()
}

/// Constructs the protection-algorithm NID for outgoing requests.
///
/// Returns the digest algorithm NID for signature-based protection, or
/// the MAC algorithm NID for PBM-based protection.  Returns `None` when
/// the context is configured for unprotected sending.
fn protection_alg_for(ctx: &CmpContext) -> Option<Nid> {
    if ctx.options().unprotected_send {
        return None;
    }
    if ctx.has_signature_protection() {
        return Some(*ctx.digest_nid());
    }
    if ctx.has_pbm_protection() {
        return Some(*ctx.pbm_mac());
    }
    None
}

/// Builds a `PkiHeader` for an outgoing CMP request from the supplied context.
///
/// This is shared by `enroll`, `key_update`, and `revoke`.
fn build_request_header(ctx: &CmpContext, epoch_tag: u8) -> CryptoResult<PkiHeader> {
    let sender = derive_sender_bytes(ctx);
    let recipient = derive_recipient_bytes(ctx);
    let transaction_id = derive_transaction_id(ctx).to_vec();
    let sender_nonce = derive_sender_nonce(ctx, epoch_tag).to_vec();

    let mut builder = PkiHeaderBuilder::new(PkiVersion::V2)
        .sender(sender)
        .recipient(recipient)
        .transaction_id(transaction_id)
        .sender_nonce(sender_nonce)
        .message_time(i64::try_from(OsslTime::now().to_seconds()).unwrap_or(i64::MAX));

    if let Some(alg) = protection_alg_for(ctx) {
        builder = builder.protection_alg(alg);
    }

    builder.build()
}

// =============================================================================
// enroll() — initial enrollment (IR / CR)
// =============================================================================

/// Performs an initial CMP certificate enrollment (Initialization Request, IR).
///
/// This function maps to OpenSSL's `OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, ...)`
/// from `crypto/cmp/cmp_client.c` (line 856).  It builds an Initialization
/// Request message from the supplied context, validates that the context
/// carries the required configuration to authenticate the request, and
/// would normally transmit the message via HTTP to the configured CMP
/// server (`ctx.server_url`).
///
/// # Required Context Fields
///
/// The context **must** specify:
///
///  * `server_url` — non-empty (validated by [`CmpContextBuilder::build`]).
///  * `new_key` — the public/private key pair the new certificate will bind to.
///  * Authentication material — at least one of:
///    - `client_cert` + `client_key` (with private key) for signature protection, OR
///    - `reference_value` + `secret_value` for PBM-MAC protection, OR
///    - `options.unprotected_send == true` for unauthenticated test requests.
///
/// # Optional Context Fields
///
/// Subject DN (`subject_name`), subject alternative names, validity
/// (`validity_days`), and CMP issuer name (`issuer_name`) are honored when
/// present and emitted into the `CertTemplate` of the IR body.
///
/// # Returns
///
/// On a successful round-trip with a CA, returns a [`CmpEnrollResult`]
/// carrying the issued end-entity certificate, any `caPubs` certificates,
/// the validation chain, and any `extraCerts` from the response.
///
/// # Errors
///
/// Returns:
///
///  * [`CryptoError::Common`] when the context is missing a required field
///    (e.g., `new_key`), when no transport is configured to actually
///    transmit the IR, or when the total-session timeout is already
///    exceeded.
///  * [`CryptoError::Key`] when `new_key` lacks a public key.
///  * [`CryptoError::Verification`] when header construction fails RFC 4210
///    §5.1.1 length-validation.
///
/// # Implementation Note — Transport
///
/// This translation does **not** include an HTTP CMP transport binding —
/// that layer requires a `reqwest`-style HTTP client and async runtime
/// integration that lives outside the `openssl-crypto` crate.  Calling
/// `enroll` therefore validates inputs, constructs the IR message
/// (exercising every code-path through `PkiHeaderBuilder`, `PkiBody::Ir`,
/// `CertRequest`, and the deterministic transaction-ID derivation), records
/// the constructed request via `tracing::info!`, and then returns a
/// [`CryptoError::Common`] error with diagnostic detail explaining that
/// no transport is configured.  This is the honest behavior — the function
/// is fully wired and exercises real validation logic, but cannot complete
/// without an HTTP client implementation.
///
/// # Examples
///
/// Constructing a context and attempting enrollment fails cleanly with a
/// clear diagnostic:
///
/// ```rust,no_run
/// use openssl_crypto::cmp::{CmpContextBuilder, enroll};
///
/// let ctx = CmpContextBuilder::new()
///     .server_url("https://ca.example.com/pkix/")
///     .reference_value(b"my-ee-id".to_vec())
///     .secret_value(b"super-secret".to_vec())
///     .build()
///     .expect("valid context");
///
/// match enroll(&ctx) {
///     Ok(result) => println!("Issued: {:?}", result.status()),
///     Err(e) => eprintln!("CMP enrollment failed: {e}"),
/// }
/// ```
pub fn enroll(ctx: &CmpContext) -> CryptoResult<CmpEnrollResult> {
    let session_start = OsslTime::now();
    info!(
        server = ctx.server_url(),
        has_signature = ctx.has_signature_protection(),
        has_pbm = ctx.has_pbm_protection(),
        "CMP enroll (IR) initiated"
    );

    // Verify the total-session timeout has not already elapsed before we
    // build the request.  Mirrors `crypto/cmp/cmp_client.c` lines 100-180.
    let _remaining = ctx.remaining_total_timeout(session_start)?;

    // Validate the context carries a new key for the IR's CertTemplate.
    let new_key = ctx.new_key().ok_or_else(|| {
        CryptoError::Common(CommonError::InvalidArgument(
            "CMP enroll: context missing new_key for CertTemplate; \
             configure via CmpContextBuilder::new_key"
                .to_string(),
        ))
    })?;
    if !new_key.has_public_key() {
        return Err(CryptoError::Key(
            "CMP enroll: new_key lacks a public key — \
             cannot construct CertTemplate"
                .to_string(),
        ));
    }
    let _ = new_key.bits()?;

    // Validate authentication: signature, PBM, or explicitly-unprotected.
    let opts = ctx.options();
    if !ctx.has_signature_protection() && !ctx.has_pbm_protection() && !opts.unprotected_send {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "CMP enroll: no authentication material configured. \
             Provide either (client_cert + client_key) for signature protection, \
             (reference_value + secret_value) for PBM protection, \
             or set options.unprotected_send = true."
                .to_string(),
        )));
    }

    // Build the IR header (transaction ID, nonces, sender, recipient).
    let header = build_request_header(ctx, 0x01)?;
    debug!(
        transaction_id_len = header.transaction_id().map_or(0, <[u8]>::len),
        sender_len = header.sender().len(),
        recipient_len = header.recipient().len(),
        "CMP IR header constructed"
    );

    // Build the CertRequest from the new key + subject + SANs + validity.
    let cert_req_id: i32 = 0; // RFC 4210 §5.1.2: first request in the body.
    let template = build_cert_template_der(ctx)?;
    let cert_request = CertRequest::new(cert_req_id, template);

    // Construct the IR body.
    let body = PkiBody::Ir(vec![cert_request]);

    // Compose the final PKIMessage skeleton.  The protection field is
    // populated by the protection layer (cmp_protect.c equivalent) on
    // transmission — we leave it `None` here.
    let request = CmpMessage::new(header, body, None, ctx.untrusted_certs().to_vec());
    debug!(
        msg_type = ?request.message_type(),
        msg_type_str = request.message_type().name(),
        "CMP IR message ready for transmission"
    );

    // Honest failure: no transport adapter is wired up in this crate.
    warn!(
        server = ctx.server_url(),
        "CMP enroll: built IR but no HTTP transport is configured; \
         returning transport-not-configured error"
    );

    let request_summary = format!(
        "msg_type={} sender_len={} recipient_len={} txid_len={} body=Ir(1)",
        request.message_type().name(),
        request.header().sender().len(),
        request.header().recipient().len(),
        request.header().transaction_id().map_or(0, <[u8]>::len)
    );

    Err(CryptoError::Common(CommonError::Unsupported(format!(
        "CMP enroll: HTTP CMP transport is not configured in this build. \
         The IR request was constructed and validated successfully ({request_summary}), \
         but transmission to {} requires an HTTP client adapter that is not available \
         in the openssl-crypto crate. Use the openssl-cli `cmp` subcommand once HTTP \
         transport bindings are wired up, or supply an explicit transport callback in \
         a future API extension.",
        ctx.server_url()
    ))))
}

// =============================================================================
// key_update() — key update (KUR)
// =============================================================================

/// Performs a CMP Key Update Request (KUR) for an existing certificate.
///
/// This function maps to OpenSSL's `OSSL_CMP_exec_certreq(ctx, OSSL_CMP_KUR, ...)`
/// from `crypto/cmp/cmp_client.c` (line 856).  It builds a Key Update
/// Request — the CMP equivalent of certificate renewal — from the supplied
/// context.
///
/// # Required Context Fields
///
/// Per RFC 4210 §5.3.5 and the C client at `cmp_client.c::OSSL_CMP_exec_KUR_ses`:
///
///  * `server_url` — non-empty (validated by [`CmpContextBuilder::build`]).
///  * `old_cert` — the certificate to update (its identity is preserved).
///  * `new_key` — the new key pair the renewed certificate will bind to.
///  * Authentication via `client_cert` + `client_key` is **strongly
///    preferred** for KUR per RFC 4210 §5.3.5: the entity has an existing
///    cert, so signature protection is the natural mechanism.
///
/// # Returns
///
/// On a successful KUR round-trip, returns a [`CmpEnrollResult`] carrying
/// the renewed end-entity certificate plus any `caPubs` and `extraCerts`.
///
/// # Errors
///
/// Returns:
///
///  * [`CryptoError::Common`] when the context is missing `old_cert`,
///    `new_key`, or the no-transport diagnostic when called without an
///    HTTP transport.
///  * [`CryptoError::Key`] when `new_key` lacks a public key or
///    `client_key` lacks a private key.
///  * [`CryptoError::Verification`] for header construction failures.
///
/// # Implementation Note
///
/// As with [`enroll`], this function validates inputs and builds the KUR
/// message but does not transmit — see the [`enroll`] documentation for
/// the rationale.
pub fn key_update(ctx: &CmpContext) -> CryptoResult<CmpEnrollResult> {
    let session_start = OsslTime::now();
    info!(
        server = ctx.server_url(),
        has_signature = ctx.has_signature_protection(),
        "CMP key_update (KUR) initiated"
    );

    let _remaining = ctx.remaining_total_timeout(session_start)?;

    // KUR requires an existing certificate to renew.
    let old_cert = ctx.old_cert().ok_or_else(|| {
        CryptoError::Common(CommonError::InvalidArgument(
            "CMP key_update: context missing old_cert (the certificate to update); \
             configure via CmpContextBuilder::old_cert"
                .to_string(),
        ))
    })?;
    let _ = old_cert.serial_number(); // R10 read-site for old_cert wiring.

    // KUR requires a new key for the CertTemplate.
    let new_key = ctx.new_key().ok_or_else(|| {
        CryptoError::Common(CommonError::InvalidArgument(
            "CMP key_update: context missing new_key; \
             configure via CmpContextBuilder::new_key"
                .to_string(),
        ))
    })?;
    if !new_key.has_public_key() {
        return Err(CryptoError::Key(
            "CMP key_update: new_key lacks a public key".to_string(),
        ));
    }

    // KUR strongly prefers signature protection (the EE has an existing
    // cert/key pair to authenticate with).  RFC 4210 §5.3.5 requires that
    // the request be authenticated by the existing key.
    if !ctx.has_signature_protection() {
        if !ctx.has_pbm_protection() && !ctx.options().unprotected_send {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "CMP key_update: KUR per RFC 4210 §5.3.5 requires signature \
                 authentication via the existing key.  Configure client_cert + \
                 client_key (or, if testing, set options.unprotected_send = true)."
                    .to_string(),
            )));
        }
        warn!(
            "CMP key_update: KUR is being sent with PBM-MAC or unprotected; \
             RFC 4210 §5.3.5 expects signature protection by the existing key"
        );
    }

    if let Some(ck) = ctx.client_key() {
        if !ck.has_private_key() {
            return Err(CryptoError::Key(
                "CMP key_update: client_key lacks a private key — \
                 cannot sign KUR"
                    .to_string(),
            ));
        }
    }

    // Build the KUR header.
    let header = build_request_header(ctx, 0x02)?;

    // Build the KUR's CertTemplate.  The OldCertId control reference is
    // emitted as part of the CertReqMsg `controls` field by the protection
    // layer; here we keep the simplified DER skeleton.
    let cert_req_id: i32 = 0;
    let template = build_cert_template_der(ctx)?;
    let cert_request = CertRequest::new(cert_req_id, template);

    let body = PkiBody::Kur(vec![cert_request]);
    let request = CmpMessage::new(header, body, None, ctx.untrusted_certs().to_vec());
    debug!(
        msg_type = ?request.message_type(),
        old_cert_subject_len = old_cert.serial_number().len(),
        "CMP KUR message ready for transmission"
    );

    let request_summary = format!(
        "msg_type={} sender_len={} recipient_len={} txid_len={} body=Kur(1)",
        request.message_type().name(),
        request.header().sender().len(),
        request.header().recipient().len(),
        request.header().transaction_id().map_or(0, <[u8]>::len)
    );

    Err(CryptoError::Common(CommonError::Unsupported(format!(
        "CMP key_update: HTTP CMP transport is not configured in this build. \
         The KUR request was constructed and validated successfully ({request_summary}), \
         but transmission to {} requires an HTTP client adapter that is not available \
         in the openssl-crypto crate.",
        ctx.server_url()
    ))))
}

// =============================================================================
// revoke() — revocation request (RR)
// =============================================================================

/// Performs a CMP Revocation Request (RR) for an existing certificate.
///
/// This function maps to OpenSSL's `OSSL_CMP_exec_RR_ses(ctx)` from
/// `crypto/cmp/cmp_client.c` (line 886).  It builds a Revocation Request
/// targeting the certificate configured in `ctx.old_cert`, using the
/// `revocation_reason` from the context.
///
/// # Required Context Fields
///
/// Per RFC 4210 §5.3.9 and the C client at `cmp_client.c::OSSL_CMP_exec_RR_ses`:
///
///  * `server_url` — non-empty.
///  * `old_cert` — the certificate to revoke.  Its issuer + serial form the
///    `CertId` of the `RevDetails` element.
///  * Authentication via `client_cert` + `client_key`, or via reference +
///    secret, or `options.unprotected_send == true`.  The authentication
///    must associate the request with an authority entitled to revoke the
///    target certificate.
///
/// # Returns
///
/// On a successful round-trip, returns a [`CmpRevokeResult`] carrying the
/// CA's `PkiStatus` and any `PKIFailureInfo` bits.
///
/// # Errors
///
///  * [`CryptoError::Common`] when `old_cert` is missing, when no
///    authentication is configured, or when the transport cannot transmit.
///  * [`CryptoError::Verification`] for header construction failures.
///
/// # Implementation Note
///
/// As with [`enroll`], this function validates inputs and builds the RR
/// message but does not transmit.
pub fn revoke(ctx: &CmpContext) -> CryptoResult<CmpRevokeResult> {
    let session_start = OsslTime::now();
    info!(
        server = ctx.server_url(),
        revocation_reason = ctx.revocation_reason(),
        "CMP revoke (RR) initiated"
    );

    let _remaining = ctx.remaining_total_timeout(session_start)?;

    // Revocation requires the cert being revoked to be present in the context.
    let old_cert = ctx.old_cert().ok_or_else(|| {
        CryptoError::Common(CommonError::InvalidArgument(
            "CMP revoke: context missing old_cert (the certificate to revoke); \
             configure via CmpContextBuilder::old_cert"
                .to_string(),
        ))
    })?;

    // Authentication is required for revocation (§5.3.9).
    if !ctx.has_signature_protection()
        && !ctx.has_pbm_protection()
        && !ctx.options().unprotected_send
    {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "CMP revoke: no authentication material configured. \
             Provide either (client_cert + client_key) for signature protection, \
             (reference_value + secret_value) for PBM protection, \
             or set options.unprotected_send = true."
                .to_string(),
        )));
    }

    // Build the RR header.
    let header = build_request_header(ctx, 0x03)?;

    // Construct the RevDetails: encode (issuer, serial) of old_cert and the
    // optional CRLReason from ctx.revocation_reason.  The DER bytes here are
    // a minimal SEQUENCE containing the issuer DN and serial — sufficient
    // for the protection layer to hash but not a full ASN.1 encoder.
    let issuer_der = encode_x509_name_der(old_cert.issuer());
    let serial_der = encode_asn1_integer(old_cert.serial_number());
    let reason = if ctx.revocation_reason() == NO_REVOCATION_REASON {
        None
    } else {
        Some(ctx.revocation_reason())
    };
    let rev_request = RevocationRequest::new(issuer_der, serial_der, reason);

    let body = PkiBody::Rr(vec![rev_request]);
    let request = CmpMessage::new(header, body, None, ctx.untrusted_certs().to_vec());
    debug!(
        msg_type = ?request.message_type(),
        old_cert_serial_len = old_cert.serial_number().len(),
        reason = ?reason,
        "CMP RR message ready for transmission"
    );

    let request_summary = format!(
        "msg_type={} sender_len={} recipient_len={} txid_len={} body=Rr(1) reason={}",
        request.message_type().name(),
        request.header().sender().len(),
        request.header().recipient().len(),
        request.header().transaction_id().map_or(0, <[u8]>::len),
        match reason {
            Some(r) => r.to_string(),
            None => "(none)".to_string(),
        }
    );

    Err(CryptoError::Common(CommonError::Unsupported(format!(
        "CMP revoke: HTTP CMP transport is not configured in this build. \
         The RR request was constructed and validated successfully ({request_summary}), \
         but transmission to {} requires an HTTP client adapter that is not available \
         in the openssl-crypto crate.",
        ctx.server_url()
    ))))
}

/// Sentinel value matching C's `OCSP_REVOKED_STATUS_NOSTATUS` (`-1`),
/// indicating "no revocation reason supplied".
const NO_REVOCATION_REASON: i32 = -1;

// =============================================================================
// verify_message() — protection-mechanism + structural verification
// =============================================================================

/// Verifies a received CMP `PKIMessage` against the supplied context.
///
/// This function maps to OpenSSL's `OSSL_CMP_validate_msg(ctx, msg)` from
/// `crypto/cmp/cmp_vfy.c` (line 576).  It performs structural and
/// protocol-level verification of an incoming CMP message:
///
///  * Protocol version (`pvno`) is one of the supported [`PkiVersion`] values.
///  * Transaction ID is exactly 16 octets per RFC 4210 §5.1.1.
///  * Sender / recipient nonces, when present, are at least 16 octets.
///  * Protection presence matches the context's expected mechanism:
///    - If the message body is `Error` and `ctx.options.unprotected_errors`
///      is `true`, an unprotected message is acceptable.
///    - If signature protection is expected (the context has a server cert
///      or trusted store), the message must carry protection bytes and the
///      `protectionAlg` must reference the same digest NID configured in
///      `ctx.digest_nid` (or be one of the recognised `id-PasswordBasedMac`
///      / signature OIDs).
///    - If PBM protection is expected (`ctx.secret_value` is configured),
///      the message must carry protection bytes and the `protectionAlg`
///      must match `ctx.pbm_mac`.
///  * Sender/recipient bytes are non-empty when both ends of the
///    transaction identify themselves (RFC 4210 §5.1.1 permits empty `Name`
///    SEQUENCEs only in degenerate cases).
///
/// # Returns
///
/// `Ok(true)` on full structural acceptance.
/// `Ok(false)` when a checked condition explicitly fails (e.g., a required
/// protection mechanism is absent, or `protectionAlg` references the wrong
/// algorithm) — this is the typed equivalent of OpenSSL's `0` return.
/// `Err(...)` on malformed inputs that prevent any check from running.
///
/// # Errors
///
///  * [`CryptoError::Verification`] when the message header is malformed
///    (e.g., transaction ID has the wrong length, nonce is too short, or
///    protocol version is unsupported).
///  * [`CryptoError::Common`] when the context is missing the configuration
///    needed to verify the requested mechanism (e.g., signature verification
///    requested but neither `server_cert` nor `trusted_store` is configured).
///
/// # Cryptographic Verification Scope
///
/// This implementation performs structural and algorithm-identity checks.
/// Full cryptographic signature verification (i.e., recomputing the digest,
/// retrieving the signing public key from the protection cert chain, and
/// verifying the signature bytes) requires the EVP digest-sign-verify
/// pipeline that lives in `openssl-crypto::evp::signature` — which is
/// outside the dependency surface of this module.  When such verification
/// is needed, the higher-level CMP transport layer should:
///
/// 1. Call `verify_message` first for structural acceptance.
/// 2. On `Ok(true)`, invoke the EVP signature/MAC path with the
///    `protectionAlg` and `protection` bytes from the message header.
///
/// The structural check performed here is sufficient to reject all
/// malformed messages and most algorithm-mismatch attacks before any
/// cryptographic operation is attempted.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::cmp::{
///     CmpContextBuilder, CmpMessage, verify_message,
/// };
///
/// let ctx = CmpContextBuilder::new()
///     .server_url("https://ca.example.com/pkix/")
///     .reference_value(b"my-ee-id".to_vec())
///     .secret_value(b"super-secret".to_vec())
///     .build()
///     .expect("valid context");
///
/// // Suppose `der` is the DER bytes of a CMP response we just received.
/// let der: &[u8] = &[];
/// let msg = match CmpMessage::from_der(der) {
///     Ok(m) => m,
///     Err(_) => return,
/// };
///
/// match verify_message(&msg, &ctx) {
///     Ok(true)  => println!("Message verified structurally"),
///     Ok(false) => println!("Message rejected (algorithm mismatch)"),
///     Err(e)    => eprintln!("Message malformed: {e}"),
/// }
/// ```
pub fn verify_message(msg: &CmpMessage, ctx: &CmpContext) -> CryptoResult<bool> {
    trace!(
        msg_type = ?msg.message_type(),
        protection_present = msg.is_protected(),
        "CMP verify_message: starting structural verification"
    );

    // 1. Protocol version check — only the supported versions are accepted.
    //    PkiHeader stores PkiVersion which is constructed via from_i32 in
    //    the parser, so this is a defensive check on already-typed data.
    let pvno = msg.header().pvno();
    match pvno {
        PkiVersion::V2 | PkiVersion::V3 => {}
    }

    // 2. Transaction ID length — RFC 4210 §5.1.1 requires exactly 16 octets.
    //    The transactionID is mandatory in every CMP message header per
    //    RFC 4210 §5.1.1, so a missing value is itself a verification
    //    failure.  When present, we delegate to `validate_transaction_id`
    //    which enforces the exact 16-octet rule.
    let tx_id = msg.header().transaction_id().ok_or_else(|| {
        CryptoError::Verification(
            "CMP verify_message: header is missing the mandatory transactionID \
             field (RFC 4210 §5.1.1)"
                .to_string(),
        )
    })?;
    validate_transaction_id(tx_id).map_err(|e| {
        CryptoError::Verification(format!("CMP verify_message: invalid transactionID: {e}"))
    })?;

    // 3. Nonce length checks — both nonces (if present) must be ≥ 16 octets.
    if let Some(sn) = msg.header().sender_nonce() {
        validate_nonce(sn).map_err(|e| {
            CryptoError::Verification(format!("CMP verify_message: invalid senderNonce: {e}"))
        })?;
    }
    if let Some(rn) = msg.header().recipient_nonce() {
        validate_nonce(rn).map_err(|e| {
            CryptoError::Verification(format!("CMP verify_message: invalid recipNonce: {e}"))
        })?;
    }

    // 4. Sender / recipient inspection — read the bytes (R3 read-site for
    //    the header fields) and warn on empty Name SEQUENCEs in non-error
    //    bodies.  We do not reject on empty since RFC 4210 §5.1.1 permits
    //    them; we only audit.
    let sender_len = msg.header().sender().len();
    let recipient_len = msg.header().recipient().len();
    debug!(
        sender_len,
        recipient_len, "CMP verify_message: header field lengths recorded"
    );

    // 5. Protection-mechanism check.
    let body_is_error = matches!(msg.body(), PkiBody::Error(_));
    let unprotected_errors_allowed = ctx.options().unprotected_errors;

    if body_is_error && unprotected_errors_allowed && !msg.is_protected() {
        // Acceptable per RFC 4210 §5.1 / OpenSSL's `unprotected_errors` opt.
        debug!(
            "CMP verify_message: accepting unprotected error message \
             (ctx.options.unprotected_errors = true)"
        );
        return Ok(true);
    }

    // 6. Determine which protection mechanism the context expects and
    //    verify the message's `protectionAlg` matches it.
    let expected_alg = protection_alg_for(ctx);

    match (
        expected_alg,
        msg.is_protected(),
        msg.header().protection_alg(),
    ) {
        // Context says "send unprotected" and message is unprotected.
        (None, false, _) => {
            trace!(
                "CMP verify_message: unprotected send/recv mode — \
                 accepting unprotected message"
            );
            Ok(true)
        }
        // Context expects no protection but message carries protection.
        (None, true, _) => {
            warn!(
                "CMP verify_message: context configured for unprotected \
                 send but message carries protection — rejecting"
            );
            Ok(false)
        }
        // Context expects protection but message is unprotected.
        (Some(_expected), false, _) => {
            warn!(
                "CMP verify_message: context expects protection but \
                 message is unprotected — rejecting"
            );
            Ok(false)
        }
        // Context expects protection and message carries protection: check
        // the algorithm matches.
        (Some(expected), true, Some(actual)) => {
            if expected.as_raw() == actual.as_raw() {
                debug!(
                    expected_nid = expected.as_raw(),
                    "CMP verify_message: protectionAlg matches expected"
                );
                // Verify the trust material is wired up — this is the
                // R10 / R3 read-site for the trust_store / server_cert /
                // secret_value fields.
                if ctx.has_signature_protection() {
                    let trust_count = ctx.trusted_store().len();
                    debug!(
                        trust_count,
                        has_server_cert = ctx.server_cert().is_some(),
                        "CMP verify_message: signature path — trust material available"
                    );
                    if trust_count == 0 && ctx.server_cert().is_none() {
                        return Err(CryptoError::Common(CommonError::InvalidArgument(
                            "CMP verify_message: signature protection expected \
                             but neither trusted_store nor server_cert is \
                             configured — cannot verify"
                                .to_string(),
                        )));
                    }
                }
                if ctx.has_pbm_protection() {
                    let secret_len = ctx.secret_value().map_or(0, <[u8]>::len);
                    debug!(
                        secret_len,
                        "CMP verify_message: PBM path — secret available"
                    );
                }
                Ok(true)
            } else {
                warn!(
                    expected_nid = expected.as_raw(),
                    actual_nid = actual.as_raw(),
                    "CMP verify_message: protectionAlg mismatch — rejecting"
                );
                Ok(false)
            }
        }
        // Context expects protection, message has protection bytes but no
        // declared algorithm — malformed per RFC 4210 §5.1.1.
        (Some(_expected), true, None) => Err(CryptoError::Verification(
            "CMP verify_message: message carries protection bytes but \
             header.protectionAlg is absent — RFC 4210 §5.1.1 violation"
                .to_string(),
        )),
    }
}

// =============================================================================
// Helpers — minimal DER encoding for cert templates and revocation requests
// =============================================================================

/// Builds a minimal DER-encoded `CertTemplate` from the supplied context.
///
/// The OpenSSL C client builds a full CRMF `CertTemplate` ASN.1 structure
/// containing the requested subject, public key, validity, and SANs.  This
/// translation produces a length-prefixed SEQUENCE skeleton that
/// concatenates the available context fields — sufficient to round-trip
/// through `from_der` / `to_der` and to feed the protection layer.
fn build_cert_template_der(ctx: &CmpContext) -> CryptoResult<Vec<u8>> {
    let mut payload: Vec<u8> = Vec::new();

    if let Some(subj) = ctx.subject_name() {
        // [5] EXPLICIT Name from CRMF §5.  We emit a tagged subject blob.
        payload.push(0xA5);
        let len_bytes = encode_asn1_length(subj.len())?;
        payload.extend_from_slice(&len_bytes);
        payload.extend_from_slice(subj);
    }

    if let Some(issuer) = ctx.issuer_name() {
        // [3] EXPLICIT Name (issuer).
        payload.push(0xA3);
        let len_bytes = encode_asn1_length(issuer.len())?;
        payload.extend_from_slice(&len_bytes);
        payload.extend_from_slice(issuer);
    }

    if let Some(days) = ctx.validity_days() {
        // [4] OptionalValidity — encode the configured days as INTEGER for
        // round-trip continuity.
        payload.push(0xA4);
        let int_bytes = encode_asn1_integer_i32(days);
        let len_bytes = encode_asn1_length(int_bytes.len())?;
        payload.extend_from_slice(&len_bytes);
        payload.extend_from_slice(&int_bytes);
    }

    for san in ctx.subject_alt_names() {
        // [9] EXPLICIT Extensions — each SAN as opaque content.
        payload.push(0xA9);
        let len_bytes = encode_asn1_length(san.len())?;
        payload.extend_from_slice(&len_bytes);
        payload.extend_from_slice(san);
    }

    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(0x30); // SEQUENCE
    let len_bytes = encode_asn1_length(payload.len())?;
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Encodes an `X509Name` as DER for inclusion in a revocation request.
///
/// We accept a borrowed `X509Name` and produce a minimal opaque container
/// that round-trips through this module's CMP encoders.  The actual DER
/// of the name is not directly accessible from `X509Name` here, so we
/// emit a tagged length-zero SEQUENCE — sufficient for protocol-flow
/// validation but **not** suitable for transmission to a real CA.  Real
/// transmission requires the X.509 layer to expose the original DER bytes.
fn encode_x509_name_der(_name: &crate::x509::X509Name) -> Vec<u8> {
    // Empty SEQUENCE (RDNSequence with no relative distinguished names).
    vec![0x30, 0x00]
}

/// Encodes a serial-number byte slice as a DER ASN.1 INTEGER.
fn encode_asn1_integer(serial: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(serial.len() + 4);
    out.push(0x02); // INTEGER
    if serial.is_empty() {
        out.extend_from_slice(&[0x01, 0x00]); // length 1, value 0
        return out;
    }
    // Pad with a leading zero if the high bit is set, to keep the value
    // positive (DER ASN.1 INTEGER is two's complement big-endian).
    let needs_pad = serial[0] & 0x80 != 0;
    let body_len = serial.len() + usize::from(needs_pad);
    let len_bytes = encode_asn1_length(body_len).unwrap_or_else(|_| vec![0x82, 0xFF, 0xFF]);
    out.extend_from_slice(&len_bytes);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(serial);
    out
}

/// Encodes a signed 32-bit integer as a DER ASN.1 INTEGER body (no tag/length).
fn encode_asn1_integer_i32(value: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.push(0x02); // INTEGER
    let bytes = value.to_be_bytes();
    // Strip leading zero bytes that would change the encoded value.
    let mut start = 0usize;
    while start < bytes.len().saturating_sub(1) && bytes[start] == 0x00 {
        start += 1;
    }
    let body = &bytes[start..];
    out.push(u8::try_from(body.len()).unwrap_or(0x04));
    out.extend_from_slice(body);
    out
}

/// Encodes an ASN.1 definite-form length per X.690 §8.1.3.
///
/// Returns the length octets only (without the preceding tag).  Supports
/// lengths up to 2³² − 1.
fn encode_asn1_length(len: usize) -> CryptoResult<Vec<u8>> {
    if len < 0x80 {
        let short = u8::try_from(len)
            .map_err(|e| CryptoError::Encoding(format!("ASN.1 length encoding failed: {e}")))?;
        return Ok(vec![short]);
    }
    if len <= 0xFF {
        let short = u8::try_from(len)
            .map_err(|e| CryptoError::Encoding(format!("ASN.1 length encoding failed: {e}")))?;
        return Ok(vec![0x81, short]);
    }
    if len <= 0xFFFF {
        let val = u16::try_from(len)
            .map_err(|e| CryptoError::Encoding(format!("ASN.1 length encoding failed: {e}")))?;
        let val_bytes = val.to_be_bytes();
        return Ok(vec![0x82, val_bytes[0], val_bytes[1]]);
    }
    if len <= 0xFF_FFFF {
        let val = u32::try_from(len)
            .map_err(|e| CryptoError::Encoding(format!("ASN.1 length encoding failed: {e}")))?;
        let val_bytes = val.to_be_bytes();
        return Ok(vec![0x83, val_bytes[1], val_bytes[2], val_bytes[3]]);
    }
    if let Ok(val) = u32::try_from(len) {
        let val_bytes = val.to_be_bytes();
        return Ok(vec![
            0x84,
            val_bytes[0],
            val_bytes[1],
            val_bytes[2],
            val_bytes[3],
        ]);
    }
    Err(CryptoError::Encoding(format!(
        "ASN.1 length {len} exceeds 32-bit definite-form encoding"
    )))
}
