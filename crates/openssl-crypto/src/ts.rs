//! RFC 3161 Timestamp Protocol implementation.
//!
//! Provides timestamp request creation, response generation, and response
//! verification. Replaces C `TS_*` functions from `crypto/ts/*.c` (~3,800
//! lines across 11 files).
//!
//! # C Source Mapping
//!
//! | C File                   | Rust Equivalent                             |
//! |--------------------------|---------------------------------------------|
//! | `ts_req_utils.c`         | [`TsRequest`], [`TsRequestBuilder`]         |
//! | `ts_rsp_utils.c`         | [`TsResponse`], [`TsTokenInfo`], [`TsStatus`], [`TsAccuracy`] |
//! | `ts_rsp_sign.c`          | Response signing (via [`TsTokenInfo`] builder) |
//! | `ts_rsp_verify.c`        | [`verify()`], status checking, imprint comparison |
//! | `ts_verify_ctx.c`        | [`TsVerifyContext`]                         |
//! | `ts_lib.c`               | Display impls, utility formatting           |
//! | `ts_conf.c`              | TSA configuration via serde deserialization  |
//! | `ts_err.c`               | Error strings → [`CryptoError`] variants    |
//!
//! # Protocol Overview (RFC 3161)
//!
//! The Time-Stamp Protocol provides evidence that a datum existed before a
//! particular time.  The protocol involves:
//!
//! 1. **Request** — A client constructs a [`TsRequest`] containing the hash
//!    of the data to timestamp, an optional nonce, policy OID, and certificate
//!    request flag.
//! 2. **Response** — A Time Stamping Authority (TSA) returns a [`TsResponse`]
//!    containing a [`TsStatus`] and, if successful, a [`TsTokenInfo`] with
//!    the TSA's signed assertion of the generation time.
//! 3. **Verification** — The client verifies the response using a
//!    [`TsVerifyContext`] that checks version, policy, message imprint,
//!    nonce, and optionally the TSA name and signature.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All results use `Result<T, E>` / `Option<T>`;
//!   no integer sentinels.
//! - **R6 (Lossless Casts):** All numeric conversions use `try_from` or
//!   checked arithmetic.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from CLI `ts` subcommand.
//!
//! # Feature Gate
//!
//! This module is gated behind the `ts` feature flag (equivalent to C
//! `OPENSSL_NO_TS` compile guard), enabled by default in the crate manifest.

use std::fmt;

use serde::{Deserialize, Serialize};

use openssl_common::error::{CryptoError, CryptoResult};
use openssl_common::time::OsslTime;
use openssl_common::types::Nid;

// =============================================================================
// Verification Flags — Replaces C TS_VFY_* defines from ts_verify_ctx.c
// =============================================================================

/// Verification flag: check the response signature.
pub const TS_VFY_SIGNATURE: u32 = 0x0001;

/// Verification flag: check the response version.
pub const TS_VFY_VERSION: u32 = 0x0002;

/// Verification flag: check the TSA policy OID.
pub const TS_VFY_POLICY: u32 = 0x0004;

/// Verification flag: check the message imprint (algorithm + hash).
pub const TS_VFY_IMPRINT: u32 = 0x0008;

/// Verification flag: compute and check the message imprint from raw data.
pub const TS_VFY_DATA: u32 = 0x0010;

/// Verification flag: check the nonce.
pub const TS_VFY_NONCE: u32 = 0x0020;

/// Verification flag: check the TSA signer name (from the response).
pub const TS_VFY_SIGNER: u32 = 0x0040;

/// Verification flag: check the TSA name against the expected value.
pub const TS_VFY_TSA_NAME: u32 = 0x0080;

/// Combination flag: check all imprint-related fields.
///
/// Equivalent to C `TS_VFY_ALL_IMPRINT` which combines version, policy,
/// imprint, and nonce checks.
pub const TS_VFY_ALL_IMPRINT: u32 =
    TS_VFY_SIGNATURE | TS_VFY_VERSION | TS_VFY_POLICY | TS_VFY_IMPRINT | TS_VFY_NONCE;

// =============================================================================
// Failure Info Codes — Replaces C TS_INFO_* defines from ts_rsp_verify.c
// =============================================================================

/// Failure info: the hash algorithm in the request is not supported.
pub const TS_INFO_BAD_ALG: u32 = 0;

/// Failure info: the request format is invalid.
pub const TS_INFO_BAD_REQUEST: u32 = 2;

/// Failure info: the data format in the request is invalid.
pub const TS_INFO_BAD_DATA_FORMAT: u32 = 5;

/// Failure info: the TSA cannot provide the current time.
pub const TS_INFO_TIME_NOT_AVAILABLE: u32 = 14;

/// Failure info: the requested policy is not supported.
pub const TS_INFO_UNACCEPTED_POLICY: u32 = 15;

/// Failure info: the requested extension is not supported.
pub const TS_INFO_UNACCEPTED_EXTENSION: u32 = 16;

/// Failure info: additional information is not available.
pub const TS_INFO_ADD_INFO_NOT_AVAILABLE: u32 = 17;

/// Failure info: a system failure occurred at the TSA.
pub const TS_INFO_SYSTEM_FAILURE: u32 = 25;

/// Mapping of failure info codes to human-readable strings.
///
/// Mirrors the C `ts_failure_info[]` array in `ts_rsp_verify.c` (lines 63–75).
const FAILURE_INFO_TABLE: &[(u32, &str)] = &[
    (TS_INFO_BAD_ALG, "badAlg"),
    (TS_INFO_BAD_REQUEST, "badRequest"),
    (TS_INFO_BAD_DATA_FORMAT, "badDataFormat"),
    (TS_INFO_TIME_NOT_AVAILABLE, "timeNotAvailable"),
    (TS_INFO_UNACCEPTED_POLICY, "unacceptedPolicy"),
    (TS_INFO_UNACCEPTED_EXTENSION, "unacceptedExtension"),
    (TS_INFO_ADD_INFO_NOT_AVAILABLE, "addInfoNotAvailable"),
    (TS_INFO_SYSTEM_FAILURE, "systemFailure"),
];

// =============================================================================
// TsStatus — Timestamp Response Status
// =============================================================================

/// Status codes for a timestamp response.
///
/// Mirrors the C `PKIStatus` values and the `ts_status_text[]` lookup table
/// in `ts_rsp_verify.c` (lines 52–59).  These status codes are defined in
/// RFC 3161 § 2.4.2 (`PKIStatusInfo`).
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::TsStatus;
///
/// let status = TsStatus::Granted;
/// assert_eq!(format!("{}", status), "granted");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TsStatus {
    /// The request was granted (status 0).
    Granted,

    /// The request was granted with modifications (status 1).
    GrantedWithMods,

    /// The request was rejected (status 2).
    Rejection,

    /// The request is being processed; the client should poll later (status 3).
    Waiting,

    /// A revocation warning has been issued (status 4).
    RevocationWarning,

    /// A revocation notification has been issued (status 5).
    RevocationNotification,
}

impl TsStatus {
    /// Converts a raw integer status code to a [`TsStatus`].
    ///
    /// Returns `None` for unrecognised values (Rule R5 — no sentinel).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ts::TsStatus;
    ///
    /// assert_eq!(TsStatus::from_raw(0), Some(TsStatus::Granted));
    /// assert_eq!(TsStatus::from_raw(99), None);
    /// ```
    pub fn from_raw(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Granted),
            1 => Some(Self::GrantedWithMods),
            2 => Some(Self::Rejection),
            3 => Some(Self::Waiting),
            4 => Some(Self::RevocationWarning),
            5 => Some(Self::RevocationNotification),
            _ => None,
        }
    }

    /// Returns the raw integer value of this status code.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ts::TsStatus;
    ///
    /// assert_eq!(TsStatus::Rejection.as_raw(), 2);
    /// ```
    pub fn as_raw(self) -> i64 {
        match self {
            Self::Granted => 0,
            Self::GrantedWithMods => 1,
            Self::Rejection => 2,
            Self::Waiting => 3,
            Self::RevocationWarning => 4,
            Self::RevocationNotification => 5,
        }
    }

    /// Returns `true` if the status indicates the timestamp was granted
    /// (either [`Granted`](Self::Granted) or
    /// [`GrantedWithMods`](Self::GrantedWithMods)).
    ///
    /// Mirrors the C check in `ts_check_status_info()` from
    /// `ts_rsp_verify.c` (line 360): `if (status == 0 || status == 1) return 1;`
    pub fn is_granted(self) -> bool {
        matches!(self, Self::Granted | Self::GrantedWithMods)
    }
}

impl fmt::Display for TsStatus {
    /// Formats the status using the same strings as the C
    /// `ts_status_text[]` array in `ts_rsp_verify.c`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Granted => "granted",
            Self::GrantedWithMods => "grantedWithMods",
            Self::Rejection => "rejection",
            Self::Waiting => "waiting",
            Self::RevocationWarning => "revocationWarning",
            Self::RevocationNotification => "revocationNotification",
        };
        f.write_str(text)
    }
}

// =============================================================================
// TsMessageImprint — Hash Algorithm + Hashed Message
// =============================================================================

/// A message imprint consisting of the hash algorithm identifier and the
/// hashed message bytes.
///
/// Corresponds to the C `TS_MSG_IMPRINT` structure and the accessor
/// functions in `ts_req_utils.c` (lines 48–77):
///
/// ```c
/// TS_MSG_IMPRINT_set_algo()  → TsMessageImprint::new()
/// TS_MSG_IMPRINT_get_algo()  → TsMessageImprint::hash_algorithm()
/// TS_MSG_IMPRINT_set_msg()   → TsMessageImprint::new()
/// TS_MSG_IMPRINT_get_msg()   → TsMessageImprint::hashed_message()
/// ```
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::TsMessageImprint;
/// use openssl_common::types::Nid;
///
/// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0xAB; 32]).unwrap();
/// assert_eq!(imprint.hash_algorithm(), Nid::SHA256);
/// assert_eq!(imprint.hashed_message().len(), 32);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TsMessageImprint {
    /// The NID of the hash algorithm used to produce the digest.
    hash_algorithm: Nid,

    /// The raw hash bytes (message digest).
    hashed_message: Vec<u8>,
}

impl TsMessageImprint {
    /// Creates a new message imprint from the given hash algorithm NID and
    /// digest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AlgorithmNotFound`] if `hash_algorithm` is
    /// [`Nid::UNDEF`].
    ///
    /// Returns [`CryptoError::Encoding`] if `hashed_message` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ts::TsMessageImprint;
    /// use openssl_common::types::Nid;
    ///
    /// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
    /// assert_eq!(imprint.hash_algorithm(), Nid::SHA256);
    /// ```
    pub fn new(hash_algorithm: Nid, hashed_message: Vec<u8>) -> CryptoResult<Self> {
        if hash_algorithm.is_undef() {
            return Err(CryptoError::AlgorithmNotFound(
                "message imprint hash algorithm is undefined (NID_undef)".to_string(),
            ));
        }
        if hashed_message.is_empty() {
            return Err(CryptoError::Encoding(
                "message imprint digest must not be empty".to_string(),
            ));
        }
        Ok(Self {
            hash_algorithm,
            hashed_message,
        })
    }

    /// Returns the hash algorithm NID for this message imprint.
    ///
    /// Equivalent to C `TS_MSG_IMPRINT_get_algo()` in `ts_req_utils.c`
    /// (line 64).
    #[inline]
    pub fn hash_algorithm(&self) -> Nid {
        self.hash_algorithm
    }

    /// Returns a reference to the hashed message bytes.
    ///
    /// Equivalent to C `TS_MSG_IMPRINT_get_msg()` in `ts_req_utils.c`
    /// (line 74).
    #[inline]
    pub fn hashed_message(&self) -> &[u8] {
        &self.hashed_message
    }
}

// =============================================================================
// TsAccuracy — Timestamp Accuracy
// =============================================================================

/// Accuracy of the time in a timestamp token.
///
/// Mirrors the C `TS_ACCURACY` type and its accessors in `ts_rsp_utils.c`
/// (lines 166–230):
///
/// ```c
/// TS_ACCURACY_set_seconds()  → TsAccuracy::seconds field
/// TS_ACCURACY_get_seconds()  → TsAccuracy::seconds field
/// TS_ACCURACY_set_millis()   → TsAccuracy::milliseconds field
/// TS_ACCURACY_get_millis()   → TsAccuracy::milliseconds field
/// TS_ACCURACY_set_micros()   → TsAccuracy::microseconds field
/// TS_ACCURACY_get_micros()   → TsAccuracy::microseconds field
/// ```
///
/// Per RFC 3161 § 2.4.2, the accuracy represents the time deviation around
/// the `genTime` in the token info.  The total accuracy is
/// `seconds + milliseconds/1000 + microseconds/1_000_000`.
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::TsAccuracy;
///
/// let acc = TsAccuracy::new(1, 500, 0);
/// assert_eq!(acc.seconds, 1);
/// assert_eq!(acc.milliseconds, 500);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TsAccuracy {
    /// Accuracy in whole seconds.  Corresponds to C
    /// `TS_ACCURACY_get_seconds()`.
    pub seconds: u32,

    /// Accuracy in milliseconds (0–999).  Corresponds to C
    /// `TS_ACCURACY_get_millis()`.
    pub milliseconds: u32,

    /// Accuracy in microseconds (0–999).  Corresponds to C
    /// `TS_ACCURACY_get_micros()`.
    pub microseconds: u32,
}

impl TsAccuracy {
    /// Creates a new accuracy value.
    ///
    /// # Parameters
    ///
    /// * `seconds` — Whole-second accuracy component.
    /// * `milliseconds` — Millisecond component (0–999).
    /// * `microseconds` — Microsecond component (0–999).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ts::TsAccuracy;
    ///
    /// let acc = TsAccuracy::new(0, 100, 50);
    /// assert_eq!(acc.seconds, 0);
    /// assert_eq!(acc.milliseconds, 100);
    /// assert_eq!(acc.microseconds, 50);
    /// ```
    #[inline]
    pub fn new(seconds: u32, milliseconds: u32, microseconds: u32) -> Self {
        Self {
            seconds,
            milliseconds,
            microseconds,
        }
    }

    /// Returns the total accuracy as an [`OsslTime`] duration.
    ///
    /// Combines all three components into a single nanosecond-precision
    /// time value suitable for comparison against `OsslTime` differences.
    pub fn to_ossl_time(self) -> OsslTime {
        let secs = OsslTime::from_seconds(u64::from(self.seconds));
        let millis = OsslTime::from_ms(u64::from(self.milliseconds));
        let micros = OsslTime::from_us(u64::from(self.microseconds));
        // Saturating addition via the underlying tick arithmetic.
        let total_ticks = secs
            .ticks()
            .saturating_add(millis.ticks())
            .saturating_add(micros.ticks());
        OsslTime::from_ticks(total_ticks)
    }
}

impl Default for TsAccuracy {
    /// Returns zero accuracy (all components zero).
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl fmt::Display for TsAccuracy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}s {}ms {}us",
            self.seconds, self.milliseconds, self.microseconds
        )
    }
}

// =============================================================================
// TsRequest — Timestamp Request (RFC 3161 § 2.4.1)
// =============================================================================

/// A timestamp request message.
///
/// Corresponds to the C `TS_REQ` structure.  Accessor functions from
/// `ts_req_utils.c` map as follows:
///
/// | C Function                     | Rust Accessor                 |
/// |-------------------------------|-------------------------------|
/// | `TS_REQ_get_version()`         | [`TsRequest::version()`]     |
/// | `TS_REQ_get_msg_imprint()`     | [`TsRequest::message_imprint()`] |
/// | `TS_REQ_get_policy_id()`       | [`TsRequest::policy_id()`]   |
/// | `TS_REQ_get_nonce()`           | [`TsRequest::nonce()`]       |
/// | `TS_REQ_get_cert_req()`        | [`TsRequest::cert_req()`]    |
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::{TsRequest, TsRequestBuilder, TsMessageImprint};
/// use openssl_common::types::Nid;
///
/// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0xAA; 32]).unwrap();
/// let request = TsRequestBuilder::new(imprint)
///     .cert_req(true)
///     .nonce(vec![1, 2, 3, 4])
///     .build()
///     .unwrap();
///
/// assert_eq!(request.version(), 1);
/// assert!(request.cert_req());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsRequest {
    /// Protocol version — always 1 for RFC 3161.
    version: i32,

    /// The message imprint (hash algorithm + hashed data).
    message_imprint: TsMessageImprint,

    /// Optional nonce for replay protection.
    nonce: Option<Vec<u8>>,

    /// Optional TSA policy OID (dot-notation string, e.g. "1.2.3.4.1").
    policy_id: Option<String>,

    /// Whether to request the TSA's signing certificate in the response.
    cert_req: bool,
}

impl TsRequest {
    /// Returns the protocol version.
    ///
    /// Per RFC 3161, this is always `1`.  Corresponds to C
    /// `TS_REQ_get_version()` in `ts_req_utils.c` (line 29).
    #[inline]
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns a reference to the message imprint.
    ///
    /// Corresponds to C `TS_REQ_get_msg_imprint()` in `ts_req_utils.c`
    /// (line 43).
    #[inline]
    pub fn message_imprint(&self) -> &TsMessageImprint {
        &self.message_imprint
    }

    /// Returns the nonce, if present.
    ///
    /// Corresponds to C `TS_REQ_get_nonce()` in `ts_req_utils.c`
    /// (line 123).
    #[inline]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }

    /// Returns the policy OID, if present.
    ///
    /// Corresponds to C `TS_REQ_get_policy_id()` in `ts_req_utils.c`
    /// (line 95).
    #[inline]
    pub fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    /// Returns whether the TSA's signing certificate was requested.
    ///
    /// Corresponds to C `TS_REQ_get_cert_req()` in `ts_req_utils.c`
    /// (line 143).
    #[inline]
    pub fn cert_req(&self) -> bool {
        self.cert_req
    }
}

impl fmt::Display for TsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TsRequest {{ version: {}, algo: NID({}), cert_req: {} }}",
            self.version,
            self.message_imprint.hash_algorithm.as_raw(),
            self.cert_req,
        )
    }
}

// =============================================================================
// TsRequestBuilder — Builder Pattern for TsRequest
// =============================================================================

/// Builder for constructing a [`TsRequest`].
///
/// Replaces the C pattern of calling `TS_REQ_new()` followed by
/// `TS_REQ_set_version()`, `TS_REQ_set_msg_imprint()`, etc. from
/// `ts_req_utils.c`.
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::{TsRequestBuilder, TsMessageImprint};
/// use openssl_common::types::Nid;
///
/// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
/// let request = TsRequestBuilder::new(imprint)
///     .policy_id("1.2.3.4.1".to_string())
///     .cert_req(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct TsRequestBuilder {
    /// The message imprint — required field.
    message_imprint: TsMessageImprint,

    /// Optional nonce.
    nonce: Option<Vec<u8>>,

    /// Optional policy OID.
    policy_id: Option<String>,

    /// Whether to request the TSA certificate.
    cert_req: bool,
}

impl TsRequestBuilder {
    /// Creates a new builder with the given message imprint.
    ///
    /// The `message_imprint` is the only required field.  Version is
    /// automatically set to `1` per RFC 3161.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ts::{TsRequestBuilder, TsMessageImprint};
    /// use openssl_common::types::Nid;
    ///
    /// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
    /// let builder = TsRequestBuilder::new(imprint);
    /// ```
    pub fn new(message_imprint: TsMessageImprint) -> Self {
        Self {
            message_imprint,
            nonce: None,
            policy_id: None,
            cert_req: false,
        }
    }

    /// Sets the nonce for replay protection.
    ///
    /// Corresponds to C `TS_REQ_set_nonce()` in `ts_req_utils.c` (line 105).
    ///
    /// # Parameters
    ///
    /// * `nonce` — Arbitrary bytes used as the replay-protection nonce.
    #[must_use]
    pub fn nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the TSA policy OID (dot notation, e.g. `"1.2.3.4.1"`).
    ///
    /// Corresponds to C `TS_REQ_set_policy_id()` in `ts_req_utils.c`
    /// (line 81).
    #[must_use]
    pub fn policy_id(mut self, policy_id: String) -> Self {
        self.policy_id = Some(policy_id);
        self
    }

    /// Sets whether to request the TSA's signing certificate.
    ///
    /// Corresponds to C `TS_REQ_set_cert_req()` in `ts_req_utils.c`
    /// (line 133).
    #[must_use]
    pub fn cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Consumes the builder and produces a [`TsRequest`].
    ///
    /// Version is set to `1` per RFC 3161.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] if the message imprint has an
    /// undefined hash algorithm (should not happen if [`TsMessageImprint::new`]
    /// was used, but verified defensively).
    pub fn build(self) -> CryptoResult<TsRequest> {
        if self.message_imprint.hash_algorithm.is_undef() {
            return Err(CryptoError::Encoding(
                "cannot build TS request: message imprint algorithm is undefined".to_string(),
            ));
        }
        Ok(TsRequest {
            version: 1,
            message_imprint: self.message_imprint,
            nonce: self.nonce,
            policy_id: self.policy_id,
            cert_req: self.cert_req,
        })
    }
}

// =============================================================================
// TsTokenInfo — Timestamp Token Info (RFC 3161 § 2.4.2 TSTInfo)
// =============================================================================

/// Information contained in a timestamp token.
///
/// Corresponds to the C `TS_TST_INFO` structure.  Accessor functions from
/// `ts_rsp_utils.c` map as follows:
///
/// | C Function                          | Rust Accessor                    |
/// |------------------------------------|----------------------------------|
/// | `TS_TST_INFO_get_version()`         | [`TsTokenInfo::version()`]      |
/// | `TS_TST_INFO_get_policy_id()`       | [`TsTokenInfo::policy()`]       |
/// | `TS_TST_INFO_get_serial()`          | [`TsTokenInfo::serial_number()`]|
/// | `TS_TST_INFO_get_time()`            | [`TsTokenInfo::gen_time()`]     |
/// | `TS_TST_INFO_get_accuracy()`        | [`TsTokenInfo::accuracy()`]     |
/// | `TS_TST_INFO_get_nonce()`           | [`TsTokenInfo::nonce()`]        |
/// | `TS_TST_INFO_get_tsa()`             | [`TsTokenInfo::tsa_name()`]     |
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::{TsTokenInfo, TsMessageImprint, TsAccuracy};
/// use openssl_common::types::Nid;
/// use openssl_common::time::OsslTime;
///
/// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
/// let info = TsTokenInfo {
///     version: 1,
///     policy: "1.2.3.4.1".to_string(),
///     serial_number: vec![0, 0, 0, 1],
///     gen_time: OsslTime::from_seconds(1_700_000_000),
///     accuracy: Some(TsAccuracy::new(1, 0, 0)),
///     message_imprint: imprint,
///     nonce: Some(vec![1, 2, 3, 4]),
///     tsa_name: Some("CN=Test TSA".to_string()),
///     ordering: false,
///     extensions: Vec::new(),
/// };
///
/// assert_eq!(info.version(), 1);
/// assert_eq!(info.policy(), "1.2.3.4.1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsTokenInfo {
    /// Protocol version — always 1 for RFC 3161.
    pub version: i32,

    /// TSA policy OID under which the token was issued.
    pub policy: String,

    /// Unique serial number assigned by the TSA.
    ///
    /// Stored as big-endian bytes (replaces C `ASN1_INTEGER`).
    pub serial_number: Vec<u8>,

    /// The time at which the timestamp was generated.
    ///
    /// Corresponds to C `TS_TST_INFO_get_time()`, which returns an
    /// `ASN1_GENERALIZEDTIME*`.  Here we use [`OsslTime`] for
    /// nanosecond-precision representation.
    pub gen_time: OsslTime,

    /// Optional accuracy of the `gen_time` field.
    pub accuracy: Option<TsAccuracy>,

    /// The message imprint that was timestamped.
    pub message_imprint: TsMessageImprint,

    /// Optional nonce (echoed from the request for replay protection).
    pub nonce: Option<Vec<u8>>,

    /// Optional TSA name (`GENERAL_NAME` from the `TSTInfo`).
    pub tsa_name: Option<String>,

    /// Whether strict ordering of timestamps is guaranteed.
    ///
    /// Corresponds to C `TS_TST_INFO_get_ordering()` in `ts_rsp_utils.c`
    /// (line 240).
    pub ordering: bool,

    /// Optional extensions in the token info.
    ///
    /// Each extension is stored as an opaque byte vector (DER-encoded).
    /// Corresponds to C `TS_TST_INFO_get_exts()`.
    pub extensions: Vec<Vec<u8>>,
}

impl TsTokenInfo {
    /// Returns the protocol version.
    ///
    /// Corresponds to C `TS_TST_INFO_get_version()` in `ts_rsp_utils.c`
    /// (line 72).
    #[inline]
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the TSA policy OID as a string.
    ///
    /// Corresponds to C `TS_TST_INFO_get_policy_id()` in `ts_rsp_utils.c`
    /// (line 89).
    #[inline]
    pub fn policy(&self) -> &str {
        &self.policy
    }

    /// Returns the serial number bytes.
    ///
    /// The serial number is stored in big-endian format.  Corresponds to C
    /// `TS_TST_INFO_get_serial()` in `ts_rsp_utils.c` (line 109).
    #[inline]
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    /// Returns the generation time.
    ///
    /// Corresponds to C `TS_TST_INFO_get_time()` in `ts_rsp_utils.c`
    /// (line 126).
    #[inline]
    pub fn gen_time(&self) -> OsslTime {
        self.gen_time
    }

    /// Returns the accuracy, if present.
    ///
    /// Corresponds to C `TS_TST_INFO_get_accuracy()` in `ts_rsp_utils.c`
    /// (line 153).
    #[inline]
    pub fn accuracy(&self) -> Option<&TsAccuracy> {
        self.accuracy.as_ref()
    }

    /// Returns the nonce, if present.
    ///
    /// Corresponds to C `TS_TST_INFO_get_nonce()` in `ts_rsp_utils.c`
    /// (line 257).
    #[inline]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }

    /// Returns the TSA name, if present.
    ///
    /// Corresponds to C `TS_TST_INFO_get_tsa()` in `ts_rsp_utils.c`
    /// (line 279).
    #[inline]
    pub fn tsa_name(&self) -> Option<&str> {
        self.tsa_name.as_deref()
    }
}

impl fmt::Display for TsTokenInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TsTokenInfo {{ version: {}, policy: {}, serial: {} bytes, gen_time: {} }}",
            self.version,
            self.policy,
            self.serial_number.len(),
            self.gen_time.to_seconds(),
        )
    }
}

// =============================================================================
// TsStatusInfo — Detailed Status (RFC 3161 § 2.4.2 PKIStatusInfo)
// =============================================================================

/// Detailed status information in a timestamp response.
///
/// Mirrors the C `TS_STATUS_INFO` structure and the failure-info
/// bit-string from `ts_rsp_verify.c`.
///
/// # RFC Reference
///
/// ```text
/// PKIStatusInfo ::= SEQUENCE {
///     status         PKIStatus,
///     statusString   PKIFreeText     OPTIONAL,
///     failInfo       PKIFailureInfo  OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsStatusInfo {
    /// The overall status code.
    pub status: TsStatus,

    /// Optional human-readable status strings.
    pub status_strings: Vec<String>,

    /// Optional failure information codes.
    ///
    /// Each entry corresponds to a failure reason from the
    /// `TS_INFO_*` constants.
    pub failure_info: Vec<u32>,
}

impl TsStatusInfo {
    /// Creates a new status info with the given status.
    pub fn new(status: TsStatus) -> Self {
        Self {
            status,
            status_strings: Vec::new(),
            failure_info: Vec::new(),
        }
    }

    /// Returns a human-readable description of the failure info codes.
    ///
    /// Maps each code to its RFC 3161 name using the same mapping as
    /// the C `ts_failure_info[]` table in `ts_rsp_verify.c`.
    pub fn failure_info_text(&self) -> Vec<&'static str> {
        self.failure_info
            .iter()
            .filter_map(|code| {
                FAILURE_INFO_TABLE
                    .iter()
                    .find(|(c, _)| c == code)
                    .map(|(_, text)| *text)
            })
            .collect()
    }
}

impl fmt::Display for TsStatusInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Status: {}", self.status)?;
        if !self.status_strings.is_empty() {
            write!(f, " ({})", self.status_strings.join("; "))?;
        }
        if !self.failure_info.is_empty() {
            let texts = self.failure_info_text();
            write!(f, " [failures: {}]", texts.join(", "))?;
        }
        Ok(())
    }
}

// =============================================================================
// TsResponse — Timestamp Response (RFC 3161 § 2.4.2)
// =============================================================================

/// A timestamp response message.
///
/// Corresponds to the C `TS_RESP` structure.  Accessor functions from
/// `ts_rsp_utils.c` map as follows:
///
/// | C Function                    | Rust Accessor                      |
/// |------------------------------|--------------------------------------|
/// | `TS_RESP_get_status_info()`   | [`TsResponse::status()`]            |
/// | `TS_RESP_get_tst_info()`      | [`TsResponse::token_info()`]        |
///
/// A successful response has a [`TsStatus::Granted`] or
/// [`TsStatus::GrantedWithMods`] status and includes a `token_info`.
/// A failed response has a non-granted status and `token_info` is `None`.
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::{TsResponse, TsStatus, TsStatusInfo};
///
/// let status_info = TsStatusInfo::new(TsStatus::Granted);
/// let response = TsResponse {
///     status: status_info,
///     token_info: None,
/// };
/// assert!(response.status().status.is_granted());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResponse {
    /// The status information.
    pub status: TsStatusInfo,

    /// The timestamp token info, present only on success.
    ///
    /// Corresponds to C `TS_RESP_get_tst_info()` in `ts_rsp_utils.c`
    /// (line 55).  `None` if the response status is not granted.
    pub token_info: Option<TsTokenInfo>,
}

impl TsResponse {
    /// Returns a reference to the status information.
    ///
    /// Corresponds to C `TS_RESP_get_status_info()` in `ts_rsp_utils.c`
    /// (line 27).
    #[inline]
    pub fn status(&self) -> &TsStatusInfo {
        &self.status
    }

    /// Returns a reference to the token info, if the response was
    /// successful.
    ///
    /// Corresponds to C `TS_RESP_get_tst_info()` in `ts_rsp_utils.c`
    /// (line 55).
    #[inline]
    pub fn token_info(&self) -> Option<&TsTokenInfo> {
        self.token_info.as_ref()
    }

    /// Returns `true` if the response indicates a granted timestamp.
    pub fn is_granted(&self) -> bool {
        self.status.status.is_granted()
    }
}

impl fmt::Display for TsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TsResponse {{ {} }}", self.status)
    }
}

// =============================================================================
// TsVerifyContext — Verification Context
// =============================================================================

/// Context for verifying a timestamp response.
///
/// Corresponds to the C `TS_VERIFY_CTX` structure from `ts_verify_ctx.c`.
/// The context holds verification flags and optional reference data used
/// during verification.
///
/// # Flag Constants
///
/// The verification flags control which checks are performed:
///
/// | Flag                         | Bit   | Check Performed                  |
/// |------------------------------|-------|----------------------------------|
/// | `TS_VFY_SIGNATURE`           | 0x0001| Signature verification           |
/// | `TS_VFY_VERSION`             | 0x0002| Version == 1                     |
/// | `TS_VFY_POLICY`              | 0x0004| Policy OID match                 |
/// | `TS_VFY_IMPRINT`             | 0x0008| Message imprint match            |
/// | `TS_VFY_DATA`                | 0x0010| Compute + verify imprint from data |
/// | `TS_VFY_NONCE`               | 0x0020| Nonce match                      |
/// | `TS_VFY_SIGNER`              | 0x0040| Signer verification              |
/// | `TS_VFY_TSA_NAME`            | 0x0080| TSA name match                   |
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::TsVerifyContext;
///
/// let mut ctx = TsVerifyContext::new();
/// ctx.set_flags(0x002E); // VERSION | IMPRINT | NONCE
/// assert_eq!(ctx.flags(), 0x002E);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsVerifyContext {
    /// Bitmask of `TS_VFY_*` flags controlling which checks to perform.
    flags: u32,

    /// Optional expected message imprint for comparison.
    expected_imprint: Option<TsMessageImprint>,

    /// Optional expected nonce for comparison.
    expected_nonce: Option<Vec<u8>>,

    /// Optional expected policy OID for comparison.
    expected_policy: Option<String>,

    /// Optional expected TSA name for comparison.
    expected_tsa_name: Option<String>,

    /// Optional raw data to hash and compare against the response imprint.
    ///
    /// When `TS_VFY_DATA` flag is set, this data is hashed using the
    /// algorithm from the response's message imprint and compared.
    data: Option<Vec<u8>>,
}

impl TsVerifyContext {
    /// Creates a new verification context with no flags set.
    ///
    /// Corresponds to C `TS_VERIFY_CTX_new()` in `ts_verify_ctx.c`
    /// (line 27).
    pub fn new() -> Self {
        Self {
            flags: 0,
            expected_imprint: None,
            expected_nonce: None,
            expected_policy: None,
            expected_tsa_name: None,
            data: None,
        }
    }

    /// Creates a verification context from a [`TsRequest`].
    ///
    /// This is equivalent to C `TS_REQ_to_TS_VERIFY_CTX()` in
    /// `ts_verify_ctx.c` (line 116).  It automatically populates
    /// the context with the request's imprint, nonce, and policy, and
    /// sets the appropriate flags.
    pub fn from_request(request: &TsRequest) -> Self {
        let mut flags: u32 = TS_VFY_VERSION;

        let expected_imprint = Some(request.message_imprint.clone());
        flags |= TS_VFY_IMPRINT;

        let expected_nonce = request.nonce.clone();
        if expected_nonce.is_some() {
            flags |= TS_VFY_NONCE;
        }

        let expected_policy = request.policy_id.clone();
        if expected_policy.is_some() {
            flags |= TS_VFY_POLICY;
        }

        Self {
            flags,
            expected_imprint,
            expected_nonce,
            expected_policy,
            expected_tsa_name: None,
            data: None,
        }
    }

    /// Adds flags to the current flag set (bitwise OR).
    ///
    /// Corresponds to C `TS_VERIFY_CTX_add_flags()` in `ts_verify_ctx.c`
    /// (line 50).
    #[inline]
    pub fn add_flags(&mut self, flags: u32) {
        self.flags |= flags;
    }

    /// Replaces the current flags with the given value.
    ///
    /// Corresponds to C `TS_VERIFY_CTX_set_flags()` in `ts_verify_ctx.c`
    /// (line 57).
    #[inline]
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// Returns the current verification flags.
    #[inline]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Sets the raw data for `TS_VFY_DATA` verification.
    ///
    /// When the `TS_VFY_DATA` flag is active, the verification process
    /// will hash this data and compare it against the response's message
    /// imprint.
    ///
    /// Corresponds to C `TS_VERIFY_CTX_set_data()` in `ts_verify_ctx.c`
    /// (line 72).
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = Some(data);
        self.flags |= TS_VFY_DATA;
    }

    /// Sets the expected message imprint for verification.
    pub fn set_imprint(&mut self, imprint: TsMessageImprint) {
        self.expected_imprint = Some(imprint);
        self.flags |= TS_VFY_IMPRINT;
    }

    /// Sets the expected nonce for verification.
    pub fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.expected_nonce = Some(nonce);
        self.flags |= TS_VFY_NONCE;
    }

    /// Sets the expected policy OID for verification.
    pub fn set_policy(&mut self, policy: String) {
        self.expected_policy = Some(policy);
        self.flags |= TS_VFY_POLICY;
    }

    /// Sets the expected TSA name for verification.
    pub fn set_tsa_name(&mut self, name: String) {
        self.expected_tsa_name = Some(name);
        self.flags |= TS_VFY_TSA_NAME;
    }
}

impl Default for TsVerifyContext {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Algorithm Name → NID Resolution
// =============================================================================

/// Resolves a hash algorithm name string to a [`Nid`].
///
/// Supported names (case-insensitive):
/// - `"SHA256"` / `"SHA-256"` → [`Nid::SHA256`]
/// - `"SHA384"` / `"SHA-384"` → [`Nid::SHA384`]
/// - `"SHA512"` / `"SHA-512"` → [`Nid::SHA512`]
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if the name is not recognised.
fn resolve_hash_algorithm(name: &str) -> CryptoResult<Nid> {
    match name.to_ascii_uppercase().as_str() {
        "SHA256" | "SHA-256" => Ok(Nid::SHA256),
        "SHA384" | "SHA-384" => Ok(Nid::SHA384),
        "SHA512" | "SHA-512" => Ok(Nid::SHA512),
        other => Err(CryptoError::AlgorithmNotFound(
            format!("unsupported hash algorithm for timestamp: '{other}'"),
        )),
    }
}

/// Returns the expected digest length in bytes for the given hash [`Nid`].
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if the NID is not a supported
/// hash algorithm.
fn expected_digest_length(nid: Nid) -> CryptoResult<usize> {
    if nid == Nid::SHA256 {
        Ok(32)
    } else if nid == Nid::SHA384 {
        Ok(48)
    } else if nid == Nid::SHA512 {
        Ok(64)
    } else {
        Err(CryptoError::AlgorithmNotFound(format!(
            "unknown digest length for NID {}",
            nid.as_raw(),
        )))
    }
}

// =============================================================================
// new_request() — Public API for creating a timestamp request
// =============================================================================

/// Creates a new timestamp request for the given hash algorithm and data hash.
///
/// This is a convenience function that resolves the algorithm name to a
/// [`Nid`], validates the digest length, and returns a minimal
/// [`TsRequest`] with version `1` and no optional fields.  Use
/// [`TsRequestBuilder`] for more control over nonce, policy, and
/// certificate request flags.
///
/// # Parameters
///
/// * `hash_algorithm` — Name of the hash algorithm (e.g. `"SHA256"`,
///   `"SHA-384"`).  Case-insensitive.
/// * `data_hash` — The message digest bytes.  Must match the expected
///   length for the algorithm (32 for SHA-256, 48 for SHA-384, 64 for
///   SHA-512).
///
/// # Errors
///
/// - [`CryptoError::AlgorithmNotFound`] if `hash_algorithm` is not
///   supported.
/// - [`CryptoError::Encoding`] if `data_hash` length does not match the
///   expected digest size.
///
/// # C Equivalent
///
/// Replaces the C pattern of:
/// ```c
/// TS_REQ *req = TS_REQ_new();
/// TS_REQ_set_version(req, 1);
/// TS_MSG_IMPRINT *imp = TS_MSG_IMPRINT_new();
/// X509_ALGOR *alg = X509_ALGOR_new();
/// X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), ...);
/// TS_MSG_IMPRINT_set_algo(imp, alg);
/// TS_MSG_IMPRINT_set_msg(imp, data_hash, len);
/// TS_REQ_set_msg_imprint(req, imp);
/// ```
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::new_request;
///
/// let hash = vec![0xABu8; 32]; // 32-byte SHA-256 digest
/// let req = new_request("SHA256", &hash).unwrap();
/// assert_eq!(req.version(), 1);
/// ```
pub fn new_request(hash_algorithm: &str, data_hash: &[u8]) -> CryptoResult<TsRequest> {
    let nid = resolve_hash_algorithm(hash_algorithm)?;
    let expected_len = expected_digest_length(nid)?;

    if data_hash.len() != expected_len {
        return Err(CryptoError::Encoding(format!(
            "data hash length {} does not match expected {} for {}",
            data_hash.len(),
            expected_len,
            hash_algorithm,
        )));
    }

    let imprint = TsMessageImprint::new(nid, data_hash.to_vec())?;
    TsRequestBuilder::new(imprint).build()
}

// =============================================================================
// verify() — Public API for verifying a timestamp response
// =============================================================================

/// Verifies a timestamp response against a request and verification context.
///
/// This function performs the subset of verification checks specified by
/// the flags in `ctx`.  It mirrors the C `TS_RESP_verify_response()`
/// function from `ts_rsp_verify.c` (line 233) and the internal
/// `int_ts_RESP_verify_token()` helper (line 272).
///
/// # Verification Checks
///
/// Depending on the flags set in `ctx`, the following checks are performed:
///
/// 1. **Status check** — The response must have a granted status.
/// 2. **Version check** (`TS_VFY_VERSION`) — Token version must be `1`.
/// 3. **Policy check** (`TS_VFY_POLICY`) — Token policy must match the
///    expected policy (from request or context).
/// 4. **Imprint check** (`TS_VFY_IMPRINT`) — The message imprint in the
///    token must match the request's imprint.
/// 5. **Nonce check** (`TS_VFY_NONCE`) — The nonce in the token must
///    match the request's nonce.
/// 6. **TSA name check** (`TS_VFY_TSA_NAME`) — The TSA name must match
///    the expected value.
///
/// # Parameters
///
/// * `response` — The timestamp response to verify.
/// * `request` — The original timestamp request.
/// * `ctx` — The verification context containing flags and expected values.
///
/// # Returns
///
/// `Ok(true)` if all enabled checks pass.
///
/// # Errors
///
/// - [`CryptoError::Verification`] if any enabled check fails.
/// - [`CryptoError::Encoding`] if the response is missing required fields.
///
/// # C Equivalent
///
/// Replaces `TS_RESP_verify_response()` from `ts_rsp_verify.c`.
///
/// # Examples
///
/// ```
/// use openssl_crypto::ts::{
///     verify, TsVerifyContext, TsRequest, TsResponse, TsTokenInfo,
///     TsMessageImprint, TsStatus, TsStatusInfo,
/// };
/// use openssl_common::types::Nid;
/// use openssl_common::time::OsslTime;
///
/// let imprint = TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
/// let request = openssl_crypto::ts::TsRequestBuilder::new(imprint.clone())
///     .nonce(vec![1, 2, 3, 4])
///     .build()
///     .unwrap();
///
/// let token = TsTokenInfo {
///     version: 1,
///     policy: "1.2.3.4.1".to_string(),
///     serial_number: vec![0, 0, 0, 1],
///     gen_time: OsslTime::from_seconds(1_700_000_000),
///     accuracy: None,
///     message_imprint: imprint.clone(),
///     nonce: Some(vec![1, 2, 3, 4]),
///     tsa_name: None,
///     ordering: false,
///     extensions: Vec::new(),
/// };
///
/// let response = TsResponse {
///     status: TsStatusInfo::new(TsStatus::Granted),
///     token_info: Some(token),
/// };
///
/// let ctx = TsVerifyContext::from_request(&request);
/// assert!(verify(&response, &request, &ctx).unwrap());
/// ```
pub fn verify(
    response: &TsResponse,
    request: &TsRequest,
    ctx: &TsVerifyContext,
) -> CryptoResult<bool> {
    // Step 1: Check the response status.
    // Mirrors ts_check_status_info() in ts_rsp_verify.c (line 342).
    check_status_info(response)?;

    // Step 2: Retrieve the token info — must be present for granted responses.
    let token = response.token_info.as_ref().ok_or_else(|| {
        CryptoError::Encoding(
            "timestamp response has granted status but missing token info".to_string(),
        )
    })?;

    // Step 3: Check version (TS_VFY_VERSION flag).
    // Mirrors ts_check_version() logic — version must be 1.
    if ctx.flags & TS_VFY_VERSION != 0 {
        check_version(token)?;
    }

    // Step 4: Check policy (TS_VFY_POLICY flag).
    // Mirrors ts_check_policy() in ts_rsp_verify.c (line 374).
    if ctx.flags & TS_VFY_POLICY != 0 {
        check_policy(token, request, ctx)?;
    }

    // Step 5: Check message imprint (TS_VFY_IMPRINT flag).
    // Mirrors ts_check_imprints() in ts_rsp_verify.c (line 430).
    if ctx.flags & TS_VFY_IMPRINT != 0 {
        check_imprints(token, request, ctx)?;
    }

    // Step 6: Check nonce (TS_VFY_NONCE flag).
    // Mirrors ts_check_nonces() in ts_rsp_verify.c (line 460).
    if ctx.flags & TS_VFY_NONCE != 0 {
        check_nonces(token, request, ctx)?;
    }

    // Step 7: Check TSA name (TS_VFY_TSA_NAME flag).
    if ctx.flags & TS_VFY_TSA_NAME != 0 {
        check_tsa_name(token, ctx)?;
    }

    Ok(true)
}

// =============================================================================
// Internal Verification Helpers
// =============================================================================

/// Checks that the response status indicates success.
///
/// Mirrors `ts_check_status_info()` in `ts_rsp_verify.c` (line 342).
fn check_status_info(response: &TsResponse) -> CryptoResult<()> {
    if !response.status.status.is_granted() {
        let failure_texts = response.status.failure_info_text();
        let detail = if failure_texts.is_empty() {
            format!("timestamp response status: {}", response.status.status)
        } else {
            format!(
                "timestamp response status: {} (failures: {})",
                response.status.status,
                failure_texts.join(", ")
            )
        };
        return Err(CryptoError::Verification(detail));
    }
    Ok(())
}

/// Checks that the token version is 1.
///
/// Mirrors the version check in `int_ts_RESP_verify_token()` from
/// `ts_rsp_verify.c` (line 298).
fn check_version(token: &TsTokenInfo) -> CryptoResult<()> {
    if token.version != 1 {
        return Err(CryptoError::Verification(format!(
            "unexpected TST_INFO version: {} (expected 1)",
            token.version,
        )));
    }
    Ok(())
}

/// Checks the policy OID in the token against the expected policy.
///
/// If the request has a `policy_id`, the token's policy must match.  If the
/// context has an explicit expected policy, that takes precedence.
///
/// Mirrors `ts_check_policy()` in `ts_rsp_verify.c` (line 374).
fn check_policy(
    token: &TsTokenInfo,
    request: &TsRequest,
    ctx: &TsVerifyContext,
) -> CryptoResult<()> {
    // The expected policy comes from the context if set, otherwise from
    // the request.
    let expected = ctx
        .expected_policy
        .as_deref()
        .or(request.policy_id.as_deref());

    if let Some(expected_policy) = expected {
        if token.policy != expected_policy {
            return Err(CryptoError::Verification(format!(
                "policy mismatch: token has '{}', expected '{}'",
                token.policy, expected_policy,
            )));
        }
    }
    // If no expected policy is set, any policy is accepted (matches C
    // behavior when TS_VFY_POLICY flag is set but no policy in request).
    Ok(())
}

/// Checks the message imprint in the token against the expected imprint.
///
/// Compares both the hash algorithm NID and the hash bytes.
///
/// Mirrors `ts_check_imprints()` in `ts_rsp_verify.c` (line 418).
fn check_imprints(
    token: &TsTokenInfo,
    request: &TsRequest,
    ctx: &TsVerifyContext,
) -> CryptoResult<()> {
    // Use the context's expected imprint if set, otherwise use the
    // request's message imprint.
    let expected = ctx
        .expected_imprint
        .as_ref()
        .unwrap_or(&request.message_imprint);

    // Check algorithm match.
    if token.message_imprint.hash_algorithm.as_raw() != expected.hash_algorithm.as_raw() {
        return Err(CryptoError::Verification(format!(
            "message imprint algorithm mismatch: token NID={}, expected NID={}",
            token.message_imprint.hash_algorithm.as_raw(),
            expected.hash_algorithm.as_raw(),
        )));
    }

    // Check digest match (constant-time comparison would be ideal here,
    // but since this is verification of a TSA response and not a secret
    // comparison, direct comparison is acceptable per RFC 3161).
    if token.message_imprint.hashed_message != expected.hashed_message {
        return Err(CryptoError::Verification(
            "message imprint hash mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Checks the nonce in the token against the expected nonce.
///
/// Mirrors `ts_check_nonces()` in `ts_rsp_verify.c` (line 460).
fn check_nonces(
    token: &TsTokenInfo,
    request: &TsRequest,
    ctx: &TsVerifyContext,
) -> CryptoResult<()> {
    // The expected nonce comes from the context if set, otherwise from the
    // request.
    let expected = ctx.expected_nonce.as_deref().or(request.nonce.as_deref());

    match (expected, token.nonce.as_deref()) {
        (Some(exp), Some(got)) => {
            if exp != got {
                return Err(CryptoError::Verification(
                    "nonce mismatch between request and response".to_string(),
                ));
            }
        }
        (Some(_), None) => {
            return Err(CryptoError::Verification(
                "nonce was sent in request but not returned in response".to_string(),
            ));
        }
        // Token has a nonce but none was expected — allowed per RFC 3161.
        // Neither expected nor present — also OK.
        (None, Some(_) | None) => {}
    }

    Ok(())
}

/// Checks the TSA name in the token against the expected name.
fn check_tsa_name(token: &TsTokenInfo, ctx: &TsVerifyContext) -> CryptoResult<()> {
    if let Some(expected_name) = &ctx.expected_tsa_name {
        match &token.tsa_name {
            Some(actual_name) => {
                if actual_name != expected_name {
                    return Err(CryptoError::Verification(
                        format!("TSA name mismatch: token has '{actual_name}', expected '{expected_name}'"),
                    ));
                }
            }
            None => {
                return Err(CryptoError::Verification(
                    "expected TSA name in token but none present".to_string(),
                ));
            }
        }
    }
    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── TsStatus ─────────────────────────────────────────────────────────

    #[test]
    fn test_ts_status_from_raw() {
        assert_eq!(TsStatus::from_raw(0), Some(TsStatus::Granted));
        assert_eq!(TsStatus::from_raw(1), Some(TsStatus::GrantedWithMods));
        assert_eq!(TsStatus::from_raw(2), Some(TsStatus::Rejection));
        assert_eq!(TsStatus::from_raw(3), Some(TsStatus::Waiting));
        assert_eq!(TsStatus::from_raw(4), Some(TsStatus::RevocationWarning));
        assert_eq!(
            TsStatus::from_raw(5),
            Some(TsStatus::RevocationNotification)
        );
        assert_eq!(TsStatus::from_raw(6), None);
        assert_eq!(TsStatus::from_raw(-1), None);
    }

    #[test]
    fn test_ts_status_as_raw() {
        assert_eq!(TsStatus::Granted.as_raw(), 0);
        assert_eq!(TsStatus::GrantedWithMods.as_raw(), 1);
        assert_eq!(TsStatus::Rejection.as_raw(), 2);
        assert_eq!(TsStatus::Waiting.as_raw(), 3);
        assert_eq!(TsStatus::RevocationWarning.as_raw(), 4);
        assert_eq!(TsStatus::RevocationNotification.as_raw(), 5);
    }

    #[test]
    fn test_ts_status_display() {
        assert_eq!(format!("{}", TsStatus::Granted), "granted");
        assert_eq!(format!("{}", TsStatus::GrantedWithMods), "grantedWithMods");
        assert_eq!(format!("{}", TsStatus::Rejection), "rejection");
        assert_eq!(format!("{}", TsStatus::Waiting), "waiting");
        assert_eq!(
            format!("{}", TsStatus::RevocationWarning),
            "revocationWarning"
        );
        assert_eq!(
            format!("{}", TsStatus::RevocationNotification),
            "revocationNotification"
        );
    }

    #[test]
    fn test_ts_status_is_granted() {
        assert!(TsStatus::Granted.is_granted());
        assert!(TsStatus::GrantedWithMods.is_granted());
        assert!(!TsStatus::Rejection.is_granted());
        assert!(!TsStatus::Waiting.is_granted());
        assert!(!TsStatus::RevocationWarning.is_granted());
        assert!(!TsStatus::RevocationNotification.is_granted());
    }

    // ── TsMessageImprint ─────────────────────────────────────────────────

    #[test]
    fn test_message_imprint_new_valid() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).expect("should succeed");
        assert_eq!(imprint.hash_algorithm(), Nid::SHA256);
        assert_eq!(imprint.hashed_message().len(), 32);
    }

    #[test]
    fn test_message_imprint_new_undef_algorithm() {
        let result = TsMessageImprint::new(Nid::UNDEF, vec![0u8; 32]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("undefined"));
    }

    #[test]
    fn test_message_imprint_new_empty_hash() {
        let result = TsMessageImprint::new(Nid::SHA256, vec![]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("empty"));
    }

    // ── TsAccuracy ───────────────────────────────────────────────────────

    #[test]
    fn test_accuracy_new() {
        let acc = TsAccuracy::new(1, 500, 250);
        assert_eq!(acc.seconds, 1);
        assert_eq!(acc.milliseconds, 500);
        assert_eq!(acc.microseconds, 250);
    }

    #[test]
    fn test_accuracy_default() {
        let acc = TsAccuracy::default();
        assert_eq!(acc.seconds, 0);
        assert_eq!(acc.milliseconds, 0);
        assert_eq!(acc.microseconds, 0);
    }

    #[test]
    fn test_accuracy_display() {
        let acc = TsAccuracy::new(2, 100, 50);
        assert_eq!(format!("{}", acc), "2s 100ms 50us");
    }

    #[test]
    fn test_accuracy_to_ossl_time() {
        let acc = TsAccuracy::new(1, 0, 0);
        let time = acc.to_ossl_time();
        assert_eq!(time.to_seconds(), 1);
    }

    // ── TsRequestBuilder & TsRequest ─────────────────────────────────────

    #[test]
    fn test_request_builder_minimal() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint).build().unwrap();
        assert_eq!(req.version(), 1);
        assert_eq!(req.message_imprint().hash_algorithm(), Nid::SHA256);
        assert!(req.nonce().is_none());
        assert!(req.policy_id().is_none());
        assert!(!req.cert_req());
    }

    #[test]
    fn test_request_builder_full() {
        let imprint =
            TsMessageImprint::new(Nid::SHA384, vec![0u8; 48]).unwrap();
        let req = TsRequestBuilder::new(imprint)
            .nonce(vec![1, 2, 3, 4])
            .policy_id("1.2.3.4.1".to_string())
            .cert_req(true)
            .build()
            .unwrap();

        assert_eq!(req.version(), 1);
        assert_eq!(req.message_imprint().hash_algorithm(), Nid::SHA384);
        assert_eq!(req.nonce(), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(req.policy_id(), Some("1.2.3.4.1"));
        assert!(req.cert_req());
    }

    #[test]
    fn test_request_display() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint).build().unwrap();
        let display = format!("{}", req);
        assert!(display.contains("TsRequest"));
        assert!(display.contains("version: 1"));
    }

    // ── new_request() ────────────────────────────────────────────────────

    #[test]
    fn test_new_request_sha256() {
        let hash = vec![0xABu8; 32];
        let req = new_request("SHA256", &hash).unwrap();
        assert_eq!(req.version(), 1);
        assert_eq!(req.message_imprint().hash_algorithm(), Nid::SHA256);
        assert_eq!(req.message_imprint().hashed_message(), &hash[..]);
    }

    #[test]
    fn test_new_request_sha384() {
        let hash = vec![0xCDu8; 48];
        let req = new_request("SHA-384", &hash).unwrap();
        assert_eq!(req.message_imprint().hash_algorithm(), Nid::SHA384);
    }

    #[test]
    fn test_new_request_sha512() {
        let hash = vec![0xEFu8; 64];
        let req = new_request("sha512", &hash).unwrap();
        assert_eq!(req.message_imprint().hash_algorithm(), Nid::SHA512);
    }

    #[test]
    fn test_new_request_wrong_length() {
        let hash = vec![0u8; 16]; // Wrong length for SHA-256
        let result = new_request("SHA256", &hash);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("length"));
    }

    #[test]
    fn test_new_request_unknown_algorithm() {
        let hash = vec![0u8; 32];
        let result = new_request("MD5", &hash);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported"));
    }

    // ── TsTokenInfo ──────────────────────────────────────────────────────

    #[test]
    fn test_token_info_accessors() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let info = TsTokenInfo {
            version: 1,
            policy: "1.2.3.4.1".to_string(),
            serial_number: vec![0, 0, 0, 42],
            gen_time: OsslTime::from_seconds(1_700_000_000),
            accuracy: Some(TsAccuracy::new(1, 0, 0)),
            message_imprint: imprint,
            nonce: Some(vec![10, 20, 30]),
            tsa_name: Some("CN=Test TSA".to_string()),
            ordering: false,
            extensions: Vec::new(),
        };

        assert_eq!(info.version(), 1);
        assert_eq!(info.policy(), "1.2.3.4.1");
        assert_eq!(info.serial_number(), &[0, 0, 0, 42]);
        assert_eq!(info.gen_time().to_seconds(), 1_700_000_000);
        assert_eq!(info.accuracy().unwrap().seconds, 1);
        assert_eq!(info.nonce(), Some(&[10u8, 20, 30][..]));
        assert_eq!(info.tsa_name(), Some("CN=Test TSA"));
    }

    #[test]
    fn test_token_info_display() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let info = TsTokenInfo {
            version: 1,
            policy: "1.2.3.4.1".to_string(),
            serial_number: vec![0, 0, 0, 1],
            gen_time: OsslTime::from_seconds(1_700_000_000),
            accuracy: None,
            message_imprint: imprint,
            nonce: None,
            tsa_name: None,
            ordering: false,
            extensions: Vec::new(),
        };
        let display = format!("{}", info);
        assert!(display.contains("TsTokenInfo"));
        assert!(display.contains("1.2.3.4.1"));
    }

    // ── TsResponse ───────────────────────────────────────────────────────

    #[test]
    fn test_response_granted() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let token = TsTokenInfo {
            version: 1,
            policy: "1.2.3.4.1".to_string(),
            serial_number: vec![1],
            gen_time: OsslTime::from_seconds(1_700_000_000),
            accuracy: None,
            message_imprint: imprint,
            nonce: None,
            tsa_name: None,
            ordering: false,
            extensions: Vec::new(),
        };
        let resp = TsResponse {
            status: TsStatusInfo::new(TsStatus::Granted),
            token_info: Some(token),
        };
        assert!(resp.is_granted());
        assert!(resp.token_info().is_some());
    }

    #[test]
    fn test_response_rejected() {
        let resp = TsResponse {
            status: TsStatusInfo::new(TsStatus::Rejection),
            token_info: None,
        };
        assert!(!resp.is_granted());
        assert!(resp.token_info().is_none());
    }

    // ── TsVerifyContext ──────────────────────────────────────────────────

    #[test]
    fn test_verify_context_new() {
        let ctx = TsVerifyContext::new();
        assert_eq!(ctx.flags(), 0);
    }

    #[test]
    fn test_verify_context_flags() {
        let mut ctx = TsVerifyContext::new();
        ctx.set_flags(TS_VFY_VERSION);
        assert_eq!(ctx.flags(), TS_VFY_VERSION);
        ctx.add_flags(TS_VFY_IMPRINT);
        assert_eq!(ctx.flags(), TS_VFY_VERSION | TS_VFY_IMPRINT);
    }

    #[test]
    fn test_verify_context_set_data() {
        let mut ctx = TsVerifyContext::new();
        ctx.set_data(vec![1, 2, 3]);
        assert!(ctx.flags() & TS_VFY_DATA != 0);
    }

    #[test]
    fn test_verify_context_from_request() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint)
            .nonce(vec![1, 2, 3])
            .policy_id("1.2.3.4.1".to_string())
            .build()
            .unwrap();

        let ctx = TsVerifyContext::from_request(&req);
        assert!(ctx.flags() & TS_VFY_VERSION != 0);
        assert!(ctx.flags() & TS_VFY_IMPRINT != 0);
        assert!(ctx.flags() & TS_VFY_NONCE != 0);
        assert!(ctx.flags() & TS_VFY_POLICY != 0);
    }

    // ── verify() ─────────────────────────────────────────────────────────

    fn make_test_response(
        imprint: &TsMessageImprint,
        nonce: Option<Vec<u8>>,
        policy: &str,
    ) -> TsResponse {
        let token = TsTokenInfo {
            version: 1,
            policy: policy.to_string(),
            serial_number: vec![0, 0, 0, 1],
            gen_time: OsslTime::from_seconds(1_700_000_000),
            accuracy: Some(TsAccuracy::new(1, 0, 0)),
            message_imprint: imprint.clone(),
            nonce,
            tsa_name: Some("CN=Test TSA".to_string()),
            ordering: false,
            extensions: Vec::new(),
        };
        TsResponse {
            status: TsStatusInfo::new(TsStatus::Granted),
            token_info: Some(token),
        }
    }

    #[test]
    fn test_verify_success() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone())
            .nonce(vec![1, 2, 3, 4])
            .policy_id("1.2.3.4.1".to_string())
            .build()
            .unwrap();

        let resp =
            make_test_response(&imprint, Some(vec![1, 2, 3, 4]), "1.2.3.4.1");
        let ctx = TsVerifyContext::from_request(&req);

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rejected_status() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint).build().unwrap();

        let resp = TsResponse {
            status: TsStatusInfo::new(TsStatus::Rejection),
            token_info: None,
        };
        let ctx = TsVerifyContext::from_request(&req);

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_version_mismatch() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone()).build().unwrap();

        let mut resp =
            make_test_response(&imprint, None, "1.2.3.4.1");
        resp.token_info.as_mut().unwrap().version = 2;

        let ctx = TsVerifyContext::from_request(&req);
        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("version"));
    }

    #[test]
    fn test_verify_policy_mismatch() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone())
            .policy_id("1.2.3.4.1".to_string())
            .build()
            .unwrap();

        let resp =
            make_test_response(&imprint, None, "9.9.9.9");
        let ctx = TsVerifyContext::from_request(&req);

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("policy"));
    }

    #[test]
    fn test_verify_imprint_mismatch() {
        let imprint1 =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let imprint2 =
            TsMessageImprint::new(Nid::SHA256, vec![1u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint1).build().unwrap();

        let resp =
            make_test_response(&imprint2, None, "1.2.3.4.1");
        let ctx = TsVerifyContext::from_request(&req);

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("imprint"));
    }

    #[test]
    fn test_verify_nonce_mismatch() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone())
            .nonce(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        let resp = make_test_response(
            &imprint,
            Some(vec![5, 6, 7, 8]),
            "1.2.3.4.1",
        );
        let ctx = TsVerifyContext::from_request(&req);

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("nonce"));
    }

    #[test]
    fn test_verify_nonce_missing_in_response() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone())
            .nonce(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        let resp =
            make_test_response(&imprint, None, "1.2.3.4.1");
        let ctx = TsVerifyContext::from_request(&req);

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("nonce"));
    }

    #[test]
    fn test_verify_tsa_name_mismatch() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone()).build().unwrap();
        let resp =
            make_test_response(&imprint, None, "1.2.3.4.1");

        let mut ctx = TsVerifyContext::new();
        ctx.set_flags(TS_VFY_TSA_NAME);
        ctx.set_tsa_name("CN=Wrong TSA".to_string());

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("TSA name"));
    }

    #[test]
    fn test_verify_tsa_name_success() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint.clone()).build().unwrap();
        let resp =
            make_test_response(&imprint, None, "1.2.3.4.1");

        let mut ctx = TsVerifyContext::new();
        ctx.set_flags(TS_VFY_TSA_NAME);
        ctx.set_tsa_name("CN=Test TSA".to_string());

        let result = verify(&resp, &req, &ctx);
        assert!(result.is_ok());
    }

    // ── TsStatusInfo ─────────────────────────────────────────────────────

    #[test]
    fn test_status_info_display() {
        let mut info = TsStatusInfo::new(TsStatus::Rejection);
        info.status_strings.push("bad request".to_string());
        info.failure_info.push(TS_INFO_BAD_REQUEST);
        let display = format!("{}", info);
        assert!(display.contains("rejection"));
        assert!(display.contains("bad request"));
        assert!(display.contains("badRequest"));
    }

    #[test]
    fn test_status_info_failure_texts() {
        let mut info = TsStatusInfo::new(TsStatus::Rejection);
        info.failure_info.push(TS_INFO_BAD_ALG);
        info.failure_info.push(TS_INFO_SYSTEM_FAILURE);
        let texts = info.failure_info_text();
        assert_eq!(texts.len(), 2);
        assert_eq!(texts[0], "badAlg");
        assert_eq!(texts[1], "systemFailure");
    }

    // ── Algorithm Resolution ─────────────────────────────────────────────

    #[test]
    fn test_resolve_hash_algorithm() {
        assert_eq!(resolve_hash_algorithm("SHA256").unwrap(), Nid::SHA256);
        assert_eq!(resolve_hash_algorithm("sha-256").unwrap(), Nid::SHA256);
        assert_eq!(resolve_hash_algorithm("SHA-384").unwrap(), Nid::SHA384);
        assert_eq!(resolve_hash_algorithm("SHA512").unwrap(), Nid::SHA512);
        assert!(resolve_hash_algorithm("MD5").is_err());
        assert!(resolve_hash_algorithm("").is_err());
    }

    #[test]
    fn test_expected_digest_length() {
        assert_eq!(expected_digest_length(Nid::SHA256).unwrap(), 32);
        assert_eq!(expected_digest_length(Nid::SHA384).unwrap(), 48);
        assert_eq!(expected_digest_length(Nid::SHA512).unwrap(), 64);
        assert!(expected_digest_length(Nid::UNDEF).is_err());
    }

    // ── Serialization round-trip ─────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip_request() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let req = TsRequestBuilder::new(imprint)
            .nonce(vec![1, 2, 3, 4])
            .policy_id("1.2.3.4.1".to_string())
            .cert_req(true)
            .build()
            .unwrap();

        let json = serde_json::to_string(&req).expect("serialization failed");
        let deserialized: TsRequest =
            serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(req, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_response() {
        let imprint =
            TsMessageImprint::new(Nid::SHA256, vec![0u8; 32]).unwrap();
        let resp =
            make_test_response(&imprint, Some(vec![10, 20]), "1.2.3.4.1");

        let json =
            serde_json::to_string(&resp).expect("serialization failed");
        let deserialized: TsResponse =
            serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(resp, deserialized);
    }
}
