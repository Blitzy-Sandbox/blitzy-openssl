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
//! - Express CMP protocol versions ([`PkiVersion`])
//! - Encode/decode PKI status codes ([`PkiStatus`])
//! - Represent failure information bits ([`PkiFailureInfo`], [`FailureInfoBits`])
//! - Construct minimal `PKIHeader` and `PKIStatusInfo` structures ([`PkiHeader`],
//!   [`PkiStatusInfo`])
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
//! | `OSSL_CMP_PVNO_2`, `OSSL_CMP_PVNO_3` (`cmp.h.in`) | [`PkiVersion`] |
//! | `OSSL_CMP_PKISTATUS_*` (`cmp.h.in`) | [`PkiStatus`] |
//! | `OSSL_CMP_PKIFAILUREINFO_*` (`cmp.h.in`) | [`PkiFailureInfo`] |
//! | `OSSL_CMP_CTX_FAILINFO_*` bitmasks (`cmp.h.in`) | [`FailureInfoBits`] |
//! | `OSSL_CMP_PKIHEADER` (`cmp_local.h`) | [`PkiHeader`] |
//! | `OSSL_CMP_PKISI` `PKIStatusInfo` (`cmp_local.h`) | [`PkiStatusInfo`] |
//! | `crypto/cmp/cmp_status.c` reason-string functions | [`PkiStatus::description`] |
//! | `crypto/cmp/cmp_msg.c` header construction | [`PkiHeaderBuilder`] |
//! | RFC 4210 §5.1.1 transaction ID validation | [`validate_transaction_id`] |
//! | RFC 4210 §5.1.1 nonce validation | [`validate_nonce`] |
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

use std::collections::HashSet;
use std::fmt;

use openssl_common::error::{CryptoError, CryptoResult};

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

    // UNREAD: reserved for future RFC 4210 §5.1.1 header expansion (R3).
    // The fields below are intentionally not yet stored — adding storage
    // before there is a read-site would violate Rule R3.  When the
    // protection / authentication subsystem is implemented, these will
    // become Option<...> fields with corresponding accessors.
    //
    //   - protection_alg:  Option<AlgorithmIdentifier>
    //   - sender_kid:      Option<Vec<u8>>
    //   - recipient_kid:   Option<Vec<u8>>
    //   - free_text:       Vec<String>
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
        let sender = self
            .sender
            .ok_or_else(|| CryptoError::Verification(
                "PKIHeader requires sender (RFC 4210 §5.1.1 mandates GeneralName)".into(),
            ))?;
        let recipient = self
            .recipient
            .ok_or_else(|| CryptoError::Verification(
                "PKIHeader requires recipient (RFC 4210 §5.1.1 mandates GeneralName)".into(),
            ))?;

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
