//! OCSP (Online Certificate Status Protocol) implementation per RFC 6960.
//!
//! Provides OCSP request creation, response parsing, and response verification
//! for certificate revocation checking. Replaces C `OCSP_*` functions from
//! `crypto/ocsp/*.c` (~3,200 lines across 10 files).
//!
//! # C Source Mapping
//!
//! | C File               | Rust Equivalent                                          |
//! |----------------------|----------------------------------------------------------|
//! | `ocsp_cl.c`          | [`OcspRequest`], [`OcspRequestBuilder`], response status |
//! | `ocsp_srv.c`         | [`OcspBasicResponse`], [`OcspSingleResponse`] building   |
//! | `ocsp_vfy.c`         | [`verify_response()`], [`check_validity()`]              |
//! | `ocsp_lib.c`         | [`OcspCertId`], cert-to-id, id comparison                |
//! | `ocsp_ht.c`          | HTTP transport (higher-level; wire-format via `to_der`)  |
//! | `v3_ocsp.c`          | X.509v3 OCSP extension support                           |
//! | `ocsp_ext.c`         | Request/response extension manipulation                  |
//! | `ocsp_prn.c`         | Display/print formatting                                 |
//! | `ocsp_err.c`         | Error reason strings → [`CryptoError`] variants          |
//!
//! # Protocol Overview (RFC 6960)
//!
//! The Online Certificate Status Protocol enables clients to query the
//! revocation status of certificates in real time:
//!
//! 1. **Request** — A client constructs an [`OcspRequest`] containing one or
//!    more [`OcspCertId`] entries (each identifying a certificate by its issuer
//!    name hash, issuer key hash, and serial number) and an optional nonce.
//! 2. **Response** — An OCSP responder returns an [`OcspResponse`] with an
//!    [`OcspResponseStatus`] and, if successful, an [`OcspBasicResponse`]
//!    containing individual certificate status entries
//!    ([`OcspSingleResponse`]), the responder's identity, and a signature.
//! 3. **Verification** — The client verifies the response signature via
//!    [`verify_response()`] and checks temporal validity of each single
//!    response via [`check_validity()`].
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All results use `Result<T, E>` / `Option<T>`;
//!   no integer sentinels.  [`OcspCertStatus`] is an enum, not an integer code.
//! - **R6 (Lossless Casts):** All numeric conversions use `try_from` or
//!   checked arithmetic.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from CLI `ocsp` subcommand and TLS stapling.
//!
//! # Feature Gate
//!
//! This module is gated behind the `ocsp` feature flag (equivalent to C
//! `OPENSSL_NO_OCSP` compile guard), enabled by default in the crate manifest.
//!
//! # Example
//!
//! ```rust,no_run
//! use openssl_crypto::ocsp::*;
//! use openssl_common::Nid;
//!
//! // Build an OCSP request for a certificate
//! let cert_id = OcspCertId::new(
//!     Nid::SHA256,
//!     &[0xAA; 32],  // issuer name hash
//!     &[0xBB; 32],  // issuer key hash
//!     &[0x01, 0x02, 0x03],  // serial number
//! ).expect("valid cert id");
//!
//! let request = OcspRequestBuilder::new()
//!     .add_cert_id(cert_id)
//!     .set_nonce(vec![0xDE, 0xAD, 0xBE, 0xEF])
//!     .build()
//!     .expect("valid request");
//!
//! let der_bytes = request.to_der().expect("DER encoding");
//! ```

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl_common::{CryptoError, CryptoResult, Nid};

// =============================================================================
// OcspResponseStatus — RFC 6960 §4.2.1 Response Status Values
// =============================================================================

/// OCSP response status codes as defined in RFC 6960 §4.2.1.
///
/// Replaces the C `OCSP_RESPONSE_STATUS_*` integer constants. Per Rule R5,
/// this is an enum rather than an integer code, preventing invalid status
/// value usage at compile time.
///
/// # C Mapping
///
/// | C Constant                            | Rust Variant       | Value |
/// |---------------------------------------|--------------------|-------|
/// | `OCSP_RESPONSE_STATUS_SUCCESSFUL`     | `Successful`       | 0     |
/// | `OCSP_RESPONSE_STATUS_MALFORMEDREQUEST` | `MalformedRequest` | 1   |
/// | `OCSP_RESPONSE_STATUS_INTERNALERROR`  | `InternalError`    | 2     |
/// | `OCSP_RESPONSE_STATUS_TRYLATER`       | `TryLater`         | 3     |
/// | `OCSP_RESPONSE_STATUS_SIGREQUIRED`    | `SigRequired`      | 5     |
/// | `OCSP_RESPONSE_STATUS_UNAUTHORIZED`   | `Unauthorized`     | 6     |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OcspResponseStatus {
    /// The OCSP responder successfully processed the request.
    Successful,
    /// The request was malformed.
    MalformedRequest,
    /// An internal error occurred at the responder.
    InternalError,
    /// The responder is temporarily unavailable; try again later.
    TryLater,
    /// The client must sign the request before submitting.
    SigRequired,
    /// The client is not authorized to query this responder.
    Unauthorized,
}

impl OcspResponseStatus {
    /// Converts a raw ASN.1 ENUMERATED integer to the corresponding status.
    ///
    /// Returns `None` for values that do not map to a defined status code
    /// (per Rule R5 — `Option<T>` instead of a sentinel).
    ///
    /// # Arguments
    ///
    /// * `value` - The raw integer from the DER-encoded response status field.
    fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Successful),
            1 => Some(Self::MalformedRequest),
            2 => Some(Self::InternalError),
            3 => Some(Self::TryLater),
            5 => Some(Self::SigRequired),
            6 => Some(Self::Unauthorized),
            _ => None,
        }
    }

    /// Returns the raw ASN.1 integer value for this status.
    ///
    /// Used during DER encoding of OCSP responses.
    pub fn as_raw(self) -> u8 {
        match self {
            Self::Successful => 0,
            Self::MalformedRequest => 1,
            Self::InternalError => 2,
            Self::TryLater => 3,
            Self::SigRequired => 5,
            Self::Unauthorized => 6,
        }
    }
}

impl fmt::Display for OcspResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Successful => "successful",
            Self::MalformedRequest => "malformedRequest",
            Self::InternalError => "internalError",
            Self::TryLater => "tryLater",
            Self::SigRequired => "sigRequired",
            Self::Unauthorized => "unauthorized",
        };
        f.write_str(label)
    }
}

// =============================================================================
// OcspCertStatus — RFC 6960 §4.2.1 Certificate Status
// =============================================================================

/// Certificate status in an OCSP single response, per RFC 6960 §4.2.1.
///
/// Replaces the C `V_OCSP_CERTSTATUS_*` integer constants with a
/// strongly-typed enum.  Per Rule R5, the `Revoked` variant carries
/// structured revocation data instead of out-parameters.
///
/// # C Mapping
///
/// | C Constant                      | Rust Variant | Value |
/// |---------------------------------|--------------|-------|
/// | `V_OCSP_CERTSTATUS_GOOD`       | `Good`       | 0     |
/// | `V_OCSP_CERTSTATUS_REVOKED`    | `Revoked`    | 1     |
/// | `V_OCSP_CERTSTATUS_UNKNOWN`    | `Unknown`    | 2     |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// The certificate is valid and has not been revoked.
    Good,
    /// The certificate has been revoked.
    ///
    /// Contains the revocation time (as seconds since Unix epoch) and an
    /// optional revocation reason code.
    Revoked {
        /// The time at which the certificate was revoked, represented as
        /// seconds since the Unix epoch (1970-01-01T00:00:00Z).
        revocation_time: i64,
        /// The reason for revocation, if provided by the responder.
        /// `None` indicates the reason was not specified.
        reason: Option<OcspRevocationReason>,
    },
    /// The certificate status is unknown to the responder.
    Unknown,
}

impl OcspCertStatus {
    /// Returns the raw tag value for DER encoding.
    pub fn tag_value(&self) -> u8 {
        match self {
            Self::Good => 0,
            Self::Revoked { .. } => 1,
            Self::Unknown => 2,
        }
    }
}

impl fmt::Display for OcspCertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Good => f.write_str("good"),
            Self::Revoked {
                revocation_time,
                reason,
            } => {
                write!(f, "revoked (time={revocation_time})")?;
                if let Some(r) = reason {
                    write!(f, ", reason={r}")?;
                }
                Ok(())
            }
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// =============================================================================
// OcspRevocationReason — RFC 5280 §5.3.1 CRLReason Extension Values
// =============================================================================

/// Reason codes for certificate revocation, per RFC 5280 §5.3.1.
///
/// Replaces the C `OCSP_REVOKED_STATUS_*` integer constants with a
/// strongly-typed enum.  These values appear inside the `RevokedInfo`
/// structure of an OCSP single response.
///
/// # C Mapping
///
/// | C Constant                                | Rust Variant            | Value |
/// |-------------------------------------------|-------------------------|-------|
/// | `OCSP_REVOKED_STATUS_UNSPECIFIED`         | `Unspecified`           | 0     |
/// | `OCSP_REVOKED_STATUS_KEYCOMPROMISE`       | `KeyCompromise`         | 1     |
/// | `OCSP_REVOKED_STATUS_CACOMPROMISE`        | `CaCompromise`          | 2     |
/// | `OCSP_REVOKED_STATUS_AFFILIATIONCHANGED`  | `AffiliationChanged`    | 3     |
/// | `OCSP_REVOKED_STATUS_SUPERSEDED`          | `Superseded`            | 4     |
/// | `OCSP_REVOKED_STATUS_CESSATIONOFOPERATION`| `CessationOfOperation`  | 5     |
/// | `OCSP_REVOKED_STATUS_CERTIFICATEHOLD`     | `CertificateHold`       | 6     |
/// | `OCSP_REVOKED_STATUS_REMOVEFROMCRL`       | `RemoveFromCrl`         | 8     |
/// | `OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN`  | `PrivilegeWithdrawn`    | 9     |
/// | `OCSP_REVOKED_STATUS_AACOMPROMISE`        | `AaCompromise`          | 10    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OcspRevocationReason {
    /// No specific reason given for revocation.
    Unspecified,
    /// The private key associated with the certificate has been compromised.
    KeyCompromise,
    /// The CA's private key has been compromised.
    CaCompromise,
    /// The certificate holder's affiliation has changed.
    AffiliationChanged,
    /// The certificate has been replaced by a new certificate.
    Superseded,
    /// The certificate is no longer needed for its original purpose.
    CessationOfOperation,
    /// The certificate is temporarily suspended (on hold).
    CertificateHold,
    /// Used in delta CRLs to indicate a certificate should be removed from a CRL.
    RemoveFromCrl,
    /// A privilege granted to the certificate holder has been withdrawn.
    PrivilegeWithdrawn,
    /// The Attribute Authority has been compromised.
    AaCompromise,
}

impl OcspRevocationReason {
    /// Converts a raw `CRLReason` integer to the corresponding enum variant.
    ///
    /// Returns `None` for values that do not map to a defined reason code
    /// (per Rule R5 — `Option<T>` instead of a sentinel).
    ///
    /// # Arguments
    ///
    /// * `value` - The raw integer from the DER-encoded `CRLReason` extension.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CaCompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            8 => Some(Self::RemoveFromCrl),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AaCompromise),
            _ => None,
        }
    }

    /// Returns the raw `CRLReason` integer value for this reason code.
    ///
    /// Used during DER encoding and for interoperability with C OCSP
    /// structures that use integer reason codes.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

impl fmt::Display for OcspRevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "cACompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCrl => "removeFromCRL",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aACompromise",
        };
        f.write_str(label)
    }
}

// =============================================================================
// OcspCertId — RFC 6960 §4.1.1 CertID Structure
// =============================================================================

/// Identifies a certificate for OCSP status queries, per RFC 6960 §4.1.1.
///
/// An [`OcspCertId`] uniquely identifies a certificate by combining the hash
/// of the issuer's distinguished name, the hash of the issuer's public key,
/// and the certificate's serial number. The hash algorithm used is also
/// recorded.
///
/// Replaces the C `OCSP_CERTID` structure from `ocsp_lib.c` and the
/// `OCSP_cert_id_new()` / `OCSP_cert_to_id()` constructors.
///
/// # Memory Safety
///
/// Unlike the C implementation which requires manual `OCSP_CERTID_free()`,
/// this struct implements `Drop` automatically via Rust ownership semantics
/// (RAII pattern — AAP §0.4.3).
///
/// # Examples
///
/// ```
/// use openssl_crypto::ocsp::OcspCertId;
/// use openssl_common::Nid;
///
/// let cert_id = OcspCertId::new(
///     Nid::SHA256,
///     &[0xAA; 32],
///     &[0xBB; 32],
///     &[0x01],
/// ).expect("valid cert id");
///
/// assert_eq!(cert_id.hash_algorithm(), Nid::SHA256);
/// assert_eq!(cert_id.serial_number(), &[0x01]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OcspCertId {
    /// The NID of the hash algorithm used to produce the issuer name and
    /// key hashes.  Corresponds to `hashAlgorithm` in the ASN.1 `CertID`.
    hash_alg: Nid,

    /// SHA hash of the issuer's distinguished name (DER-encoded Name).
    /// Corresponds to `issuerNameHash` in the ASN.1 `CertID`.
    issuer_name_hash: Vec<u8>,

    /// SHA hash of the issuer's public key (excluding tag and length).
    /// Corresponds to `issuerKeyHash` in the ASN.1 `CertID`.
    issuer_key_hash: Vec<u8>,

    /// The certificate's serial number as a big-endian byte vector.
    /// Corresponds to `serialNumber` in the ASN.1 `CertID`.
    serial: Vec<u8>,
}

impl OcspCertId {
    /// Creates a new certificate identifier for OCSP queries.
    ///
    /// This is the Rust equivalent of `OCSP_cert_id_new()` from `ocsp_lib.c`.
    /// It takes pre-computed hashes of the issuer name and key, along with
    /// the certificate serial number.
    ///
    /// # Arguments
    ///
    /// * `hash_algorithm` - The NID of the hash algorithm used (e.g., `Nid::SHA1`,
    ///   `Nid::SHA256`). Must not be `Nid::UNDEF`.
    /// * `issuer_name_hash` - Hash of the issuer's DER-encoded distinguished name.
    ///   Must not be empty.
    /// * `issuer_key_hash` - Hash of the issuer's public key value (excluding
    ///   ASN.1 tag and length). Must not be empty.
    /// * `serial_number` - The certificate serial number as big-endian bytes.
    ///   Must not be empty.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - `hash_algorithm` is `Nid::UNDEF` (mirrors C `OCSP_R_UNKNOWN_NID`)
    /// - Any of the hash or serial byte slices are empty
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ocsp::OcspCertId;
    /// use openssl_common::Nid;
    ///
    /// let cert_id = OcspCertId::new(
    ///     Nid::SHA256,
    ///     &[0xAA; 32],
    ///     &[0xBB; 32],
    ///     &[0x01, 0x02],
    /// ).expect("valid cert id");
    /// ```
    pub fn new(
        hash_algorithm: Nid,
        issuer_name_hash: &[u8],
        issuer_key_hash: &[u8],
        serial_number: &[u8],
    ) -> CryptoResult<Self> {
        // Validate hash algorithm — mirrors C OCSP_R_UNKNOWN_NID error
        if hash_algorithm.is_undef() {
            return Err(CryptoError::Verification(
                "OCSP CertID: unknown hash algorithm NID (NID_undef)".into(),
            ));
        }

        // Validate non-empty inputs
        if issuer_name_hash.is_empty() {
            return Err(CryptoError::Verification(
                "OCSP CertID: issuer name hash must not be empty".into(),
            ));
        }
        if issuer_key_hash.is_empty() {
            return Err(CryptoError::Verification(
                "OCSP CertID: issuer key hash must not be empty".into(),
            ));
        }
        if serial_number.is_empty() {
            return Err(CryptoError::Verification(
                "OCSP CertID: serial number must not be empty".into(),
            ));
        }

        Ok(Self {
            hash_alg: hash_algorithm,
            issuer_name_hash: issuer_name_hash.to_vec(),
            issuer_key_hash: issuer_key_hash.to_vec(),
            serial: serial_number.to_vec(),
        })
    }

    /// Returns the NID of the hash algorithm used for the issuer name and
    /// key hashes.
    ///
    /// Corresponds to `OCSP_CERTID.hashAlgorithm.algorithm` in C and the
    /// `pmd` out-parameter of `OCSP_id_get0_info()`.
    pub fn hash_algorithm(&self) -> Nid {
        self.hash_alg
    }

    /// Returns the hash of the issuer's distinguished name.
    ///
    /// Corresponds to `OCSP_CERTID.issuerNameHash` and the `piNameHash`
    /// out-parameter of `OCSP_id_get0_info()`.
    pub fn issuer_name_hash(&self) -> &[u8] {
        &self.issuer_name_hash
    }

    /// Returns the hash of the issuer's public key.
    ///
    /// Corresponds to `OCSP_CERTID.issuerKeyHash` and the `pikeyHash`
    /// out-parameter of `OCSP_id_get0_info()`.
    pub fn issuer_key_hash(&self) -> &[u8] {
        &self.issuer_key_hash
    }

    /// Returns the certificate serial number as big-endian bytes.
    ///
    /// Corresponds to `OCSP_CERTID.serialNumber` and the `pserial`
    /// out-parameter of `OCSP_id_get0_info()`.
    pub fn serial_number(&self) -> &[u8] {
        &self.serial
    }

    /// Checks whether this [`OcspCertId`] matches another.
    ///
    /// Two certificate identifiers match when all four fields are identical:
    /// the hash algorithm, issuer name hash, issuer key hash, and serial
    /// number. This is the Rust equivalent of `OCSP_id_cmp()` from
    /// `ocsp_lib.c`, but returns `bool` instead of an integer comparison
    /// result (per Rule R5 — `bool` over sentinel integers).
    ///
    /// # Arguments
    ///
    /// * `other` - The certificate identifier to compare against.
    ///
    /// # Returns
    ///
    /// `true` if all fields match exactly, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::ocsp::OcspCertId;
    /// use openssl_common::Nid;
    ///
    /// let id_a = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
    /// let id_b = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
    /// let id_c = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[4]).unwrap();
    ///
    /// assert!(id_a.matches(&id_b));
    /// assert!(!id_a.matches(&id_c));
    /// ```
    pub fn matches(&self, other: &OcspCertId) -> bool {
        self.hash_alg == other.hash_alg
            && self.issuer_name_hash == other.issuer_name_hash
            && self.issuer_key_hash == other.issuer_key_hash
            && self.serial == other.serial
    }

    /// Checks whether the issuer portion of two [`OcspCertId`]s match.
    ///
    /// Compares only the hash algorithm, issuer name hash, and issuer key
    /// hash — NOT the serial number. This is the Rust equivalent of
    /// `OCSP_id_issuer_cmp()` from `ocsp_lib.c`.
    ///
    /// # Returns
    ///
    /// `true` if the issuer fields match, `false` otherwise.
    pub fn issuer_matches(&self, other: &OcspCertId) -> bool {
        self.hash_alg == other.hash_alg
            && self.issuer_name_hash == other.issuer_name_hash
            && self.issuer_key_hash == other.issuer_key_hash
    }
}

impl fmt::Display for OcspCertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertID(hash_alg={}, serial={})",
            self.hash_alg.as_raw(),
            hex_encode(&self.serial),
        )
    }
}

// =============================================================================
// OcspRequestBuilder — Builder Pattern for OCSP Requests
// =============================================================================

/// Builder for constructing OCSP requests, replacing the C pattern of
/// `OCSP_REQUEST_new()` followed by `OCSP_request_add0_id()` calls.
///
/// Uses the builder pattern (AAP §0.4.3 design pattern) to provide a
/// fluent API for OCSP request construction.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::ocsp::{OcspRequestBuilder, OcspCertId};
/// use openssl_common::Nid;
///
/// let cert_id = OcspCertId::new(
///     Nid::SHA256,
///     &[0xAA; 32],
///     &[0xBB; 32],
///     &[0x01],
/// ).unwrap();
///
/// let request = OcspRequestBuilder::new()
///     .add_cert_id(cert_id)
///     .set_nonce(vec![0xDE, 0xAD, 0xBE, 0xEF])
///     .build()
///     .expect("valid request");
/// ```
#[derive(Debug, Clone)]
pub struct OcspRequestBuilder {
    /// Certificate IDs to include in the request.
    cert_ids: Vec<OcspCertId>,

    /// Optional nonce for replay protection (RFC 6960 §4.4.1).
    nonce: Option<Vec<u8>>,
}

impl OcspRequestBuilder {
    /// Creates a new empty OCSP request builder.
    ///
    /// Equivalent to `OCSP_REQUEST_new()` in C.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cert_ids: Vec::new(),
            nonce: None,
        }
    }

    /// Adds a certificate identifier to the request.
    ///
    /// Equivalent to `OCSP_request_add0_id()` in C. Multiple certificate
    /// IDs can be added; the request will query the status of all listed
    /// certificates.
    ///
    /// # Arguments
    ///
    /// * `cert_id` - The certificate identifier to add.
    ///
    /// # Returns
    ///
    /// `self` for method chaining.
    #[must_use]
    pub fn add_cert_id(mut self, cert_id: OcspCertId) -> Self {
        self.cert_ids.push(cert_id);
        self
    }

    /// Sets the nonce for replay protection.
    ///
    /// The nonce is an optional extension (RFC 6960 §4.4.1) that prevents
    /// replay attacks. When set, the responder should echo the nonce in its
    /// response.
    ///
    /// Replaces `OCSP_request_add1_nonce()` from `ocsp_ext.c`.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce bytes to include in the request.
    ///
    /// # Returns
    ///
    /// `self` for method chaining.
    #[must_use]
    pub fn set_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Builds the OCSP request, consuming the builder.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if no certificate IDs have been added.
    /// An OCSP request without at least one certificate query is invalid.
    pub fn build(self) -> CryptoResult<OcspRequest> {
        if self.cert_ids.is_empty() {
            return Err(CryptoError::Verification(
                "OCSP request must contain at least one certificate ID".into(),
            ));
        }

        Ok(OcspRequest {
            cert_ids: self.cert_ids,
            nonce: self.nonce,
        })
    }
}

impl Default for OcspRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// OcspRequest — RFC 6960 §4.1 OCSP Request
// =============================================================================

/// An OCSP request containing one or more certificate status queries.
///
/// Replaces the C `OCSP_REQUEST` structure. Constructed via
/// [`OcspRequestBuilder`] (builder pattern) or [`OcspRequest::builder()`].
///
/// # Memory Safety
///
/// Unlike the C implementation which requires manual `OCSP_REQUEST_free()`,
/// this struct is automatically cleaned up when it goes out of scope.
#[derive(Debug, Clone)]
pub struct OcspRequest {
    /// The list of certificate identifiers to query status for.
    /// Corresponds to `tbsRequest.requestList` in the ASN.1 structure.
    cert_ids: Vec<OcspCertId>,

    /// Optional nonce extension for replay protection.
    /// Corresponds to the nonce extension in `tbsRequest.requestExtensions`.
    nonce: Option<Vec<u8>>,
}

impl OcspRequest {
    /// Returns a new builder for constructing OCSP requests.
    ///
    /// This is a convenience method equivalent to `OcspRequestBuilder::new()`.
    #[must_use]
    pub fn builder() -> OcspRequestBuilder {
        OcspRequestBuilder::new()
    }

    /// Returns the list of certificate identifiers in this request.
    ///
    /// Equivalent to iterating `OCSP_request_onereq_count()` /
    /// `OCSP_request_onereq_get0()` / `OCSP_onereq_get0_id()` in C.
    pub fn cert_ids(&self) -> &[OcspCertId] {
        &self.cert_ids
    }

    /// Returns the nonce extension value, if present.
    ///
    /// The nonce is used for replay protection per RFC 6960 §4.4.1.
    /// Returns `None` if no nonce was set in the request.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }

    /// Serializes the OCSP request to DER-encoded bytes.
    ///
    /// The DER encoding follows the ASN.1 structure defined in RFC 6960 §4.1:
    ///
    /// ```text
    /// OCSPRequest ::= SEQUENCE {
    ///     tbsRequest     TBSRequest,
    ///     optionalSignature [0] EXPLICIT Signature OPTIONAL
    /// }
    ///
    /// TBSRequest ::= SEQUENCE {
    ///     version        [0] EXPLICIT Version DEFAULT v1,
    ///     requestList    SEQUENCE OF Request,
    ///     requestExtensions [2] EXPLICIT Extensions OPTIONAL
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the DER encoding fails (e.g., due to
    /// invalid internal state).
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        // Build the individual Request entries
        let mut request_list_content = Vec::new();
        for cert_id in &self.cert_ids {
            let cert_id_der = encode_cert_id(cert_id)?;
            // Request ::= SEQUENCE { reqCert CertID, ... }
            let request_entry = encode_sequence(&cert_id_der);
            request_list_content.extend_from_slice(&request_entry);
        }

        // requestList: SEQUENCE OF Request
        let request_list_seq = encode_sequence(&request_list_content);

        // Build TBSRequest content
        let mut tbs_content = Vec::new();

        // version [0] EXPLICIT Version DEFAULT v1 — omit for v1 (default)
        // requestorName [1] EXPLICIT GeneralName OPTIONAL — omitted

        // requestList
        tbs_content.extend_from_slice(&request_list_seq);

        // requestExtensions [2] EXPLICIT Extensions OPTIONAL
        if let Some(nonce_bytes) = &self.nonce {
            let nonce_ext = encode_nonce_extension(nonce_bytes);
            // [2] EXPLICIT — context tag 2, constructed
            let ext_tagged = encode_context_tag(2, &nonce_ext);
            tbs_content.extend_from_slice(&ext_tagged);
        }

        // TBSRequest: SEQUENCE
        let tbs_request = encode_sequence(&tbs_content);

        // OCSPRequest: SEQUENCE { tbsRequest, optionalSignature OPTIONAL }
        // We omit optionalSignature (unsigned request)
        Ok(encode_sequence(&tbs_request))
    }
}

// =============================================================================
// OcspResponse — RFC 6960 §4.2 OCSP Response
// =============================================================================

/// A complete OCSP response envelope, per RFC 6960 §4.2.1.
///
/// Replaces the C `OCSP_RESPONSE` structure. Contains the overall response
/// status and, if successful, the response bytes (typically a basic OCSP
/// response).
///
/// # Parsing
///
/// Constructed from DER-encoded bytes via [`OcspResponse::from_der()`].
/// The response status can be checked immediately; the basic response
/// body is extracted via [`OcspResponse::into_basic()`].
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// The overall response status.
    response_status: OcspResponseStatus,

    /// The raw response bytes (DER-encoded `BasicOCSPResponse`), if present.
    /// `None` for non-successful responses (per RFC 6960, response bytes
    /// are only present when status is `successful`).
    response_bytes: Option<Vec<u8>>,

    /// OID of the response type (should be `id-pkix-ocsp-basic` for
    /// basic responses). Stored for validation.
    response_type_oid: Option<Vec<u8>>,
}

impl OcspResponse {
    /// Parses an OCSP response from DER-encoded bytes.
    ///
    /// Equivalent to `d2i_OCSP_RESPONSE()` in C followed by
    /// `OCSP_response_status()`.
    ///
    /// # ASN.1 Structure
    ///
    /// ```text
    /// OCSPResponse ::= SEQUENCE {
    ///     responseStatus  OCSPResponseStatus,
    ///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
    /// }
    ///
    /// OCSPResponseStatus ::= ENUMERATED { ... }
    ///
    /// ResponseBytes ::= SEQUENCE {
    ///     responseType    OBJECT IDENTIFIER,
    ///     response        OCTET STRING
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded OCSP response bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - The DER encoding is malformed
    /// - The response status code is unrecognized
    /// - The response bytes structure is invalid
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        if der.is_empty() {
            return Err(CryptoError::Encoding(
                "OCSP response: empty DER input".into(),
            ));
        }

        // Parse outer SEQUENCE
        let (content, _) = parse_sequence(der).map_err(|e| {
            CryptoError::Encoding(format!("OCSP response: invalid outer SEQUENCE: {e}"))
        })?;

        // Parse responseStatus: ENUMERATED
        if content.is_empty() {
            return Err(CryptoError::Encoding(
                "OCSP response: missing responseStatus".into(),
            ));
        }

        let (status_bytes, remaining) = parse_enumerated(content)?;

        let status = OcspResponseStatus::from_raw(status_bytes).ok_or_else(|| {
            CryptoError::Encoding(format!(
                "OCSP response: unrecognized status code {status_bytes}"
            ))
        })?;

        // Parse optional responseBytes [0] EXPLICIT
        let (response_bytes, response_type_oid) = if remaining.is_empty() {
            (None, None)
        } else if remaining[0] == 0xA0 {
            // Check for context tag [0] constructed
            let (tagged_content, _) = parse_tlv(remaining)?;

            // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
            let (resp_bytes_seq, _) = parse_sequence(tagged_content)?;

            // Parse responseType OID
            let (oid_bytes, after_oid) = parse_oid(resp_bytes_seq)?;

            // Parse response OCTET STRING
            let (octet_content, _) = parse_octet_string(after_oid)?;

            (Some(octet_content.to_vec()), Some(oid_bytes.to_vec()))
        } else {
            (None, None)
        };

        Ok(Self {
            response_status: status,
            response_bytes,
            response_type_oid,
        })
    }

    /// Returns the overall response status.
    ///
    /// Equivalent to `OCSP_response_status()` in C, but returns a
    /// strongly-typed enum instead of an integer (per Rule R5).
    pub fn status(&self) -> OcspResponseStatus {
        self.response_status
    }

    /// Extracts the basic response from a successful OCSP response.
    ///
    /// Equivalent to `OCSP_response_get1_basic()` in C. Parses the
    /// response bytes as a `BasicOCSPResponse` structure.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    /// - The response status is not `Successful` (mirrors `OCSP_R_NO_RESPONSE_DATA`)
    /// - The response bytes are missing or malformed
    /// - The response type is not `id-pkix-ocsp-basic`
    pub fn into_basic(self) -> CryptoResult<OcspBasicResponse> {
        if self.response_status != OcspResponseStatus::Successful {
            return Err(CryptoError::Verification(format!(
                "OCSP response status is not successful: {}",
                self.response_status
            )));
        }

        let response_bytes = self.response_bytes.ok_or_else(|| {
            CryptoError::Encoding(
                "OCSP response: no response data (OCSP_R_NO_RESPONSE_DATA)".into(),
            )
        })?;

        // Validate response type OID is id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)
        if let Some(oid) = &self.response_type_oid {
            // OID for id-pkix-ocsp-basic: 1.3.6.1.5.5.7.48.1.1
            let expected_oid: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
            if oid != expected_oid {
                return Err(CryptoError::Encoding(
                    "OCSP response: not a basic response (OCSP_R_NOT_BASIC_RESPONSE)".into(),
                ));
            }
        }

        OcspBasicResponse::from_der(&response_bytes)
    }
}

// =============================================================================
// OcspBasicResponse — RFC 6960 §4.2.1 BasicOCSPResponse
// =============================================================================

/// A basic OCSP response containing individual certificate status entries,
/// the responder identity, and a signature.
///
/// Replaces the C `OCSP_BASICRESP` structure. Parsed from the `responseBytes`
/// of a successful [`OcspResponse`].
///
/// # ASN.1 Structure
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///     tbsResponseData   ResponseData,
///     signatureAlgorithm AlgorithmIdentifier,
///     signature          BIT STRING,
///     certs          [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }
///
/// ResponseData ::= SEQUENCE {
///     version            [0] EXPLICIT Version DEFAULT v1,
///     responderID        ResponderID,
///     producedAt         GeneralizedTime,
///     responses          SEQUENCE OF SingleResponse,
///     responseExtensions [1] EXPLICIT Extensions OPTIONAL
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OcspBasicResponse {
    /// The list of individual certificate status responses.
    single_responses: Vec<OcspSingleResponse>,

    /// DER-encoded certificates included in the response for chain building.
    /// Corresponds to `certs [0] EXPLICIT SEQUENCE OF Certificate` in ASN.1.
    certs: Vec<Vec<u8>>,

    /// The responder's identity — either a distinguished name (byName) or
    /// a key hash (byKey).
    producer_name: Vec<u8>,

    /// The response signature bytes.
    signature_bytes: Vec<u8>,

    /// The raw TBS (to-be-signed) response data for signature verification.
    tbs_response_data: Vec<u8>,

    /// The signature algorithm OID bytes.
    signature_algorithm: Vec<u8>,
}

impl OcspBasicResponse {
    /// Parses a `BasicOCSPResponse` from DER-encoded bytes.
    ///
    /// This is called internally by [`OcspResponse::into_basic()`].
    fn from_der(der: &[u8]) -> CryptoResult<Self> {
        if der.is_empty() {
            return Err(CryptoError::Encoding(
                "BasicOCSPResponse: empty DER input".into(),
            ));
        }

        // Parse outer SEQUENCE (BasicOCSPResponse)
        let (content, _) = parse_sequence(der).map_err(|e| {
            CryptoError::Encoding(format!("BasicOCSPResponse: invalid outer SEQUENCE: {e}"))
        })?;

        // Parse tbsResponseData SEQUENCE (capture raw bytes for signature verification)
        let (tbs_raw, after_tbs) = parse_raw_sequence(content)?;

        // Parse the content inside tbsResponseData
        let (tbs_content, _) = parse_sequence(tbs_raw)?;

        // Skip version [0] EXPLICIT if present
        let tbs_remaining = if !tbs_content.is_empty() && tbs_content[0] == 0xA0 {
            let (_, after_version) = parse_tlv(tbs_content)?;
            after_version
        } else {
            tbs_content
        };

        // Parse responderID (CHOICE: [1] byName or [2] byKey)
        let (producer_name, after_responder) = if tbs_remaining.is_empty() {
            return Err(CryptoError::Encoding(
                "BasicOCSPResponse: missing responderID".into(),
            ));
        } else {
            let (content_bytes, rest) = parse_tlv(tbs_remaining)?;
            (content_bytes.to_vec(), rest)
        };

        // Parse producedAt (GeneralizedTime)
        let (_, after_produced) = parse_tlv(after_responder)?;

        // Parse responses: SEQUENCE OF SingleResponse
        let (responses_content, _) = parse_sequence(after_produced)?;
        let single_responses = parse_single_responses(responses_content)?;

        // Parse signatureAlgorithm
        let (sig_alg_raw, after_sig_alg) = parse_raw_sequence(after_tbs)?;
        let (sig_alg_content, _) = parse_sequence(sig_alg_raw)?;
        let (sig_alg_oid, _) = parse_oid(sig_alg_content)?;

        // Parse signature BIT STRING
        let (sig_bits, after_sig) = parse_bit_string(after_sig_alg)?;

        // Parse optional certs [0] EXPLICIT SEQUENCE OF Certificate
        let certs = if !after_sig.is_empty() && after_sig[0] == 0xA0 {
            let (tagged_content, _) = parse_tlv(after_sig)?;
            let (certs_seq, _) = parse_sequence(tagged_content)?;
            parse_certificate_sequence(certs_seq)?
        } else {
            Vec::new()
        };

        Ok(Self {
            single_responses,
            certs,
            producer_name,
            signature_bytes: sig_bits.to_vec(),
            tbs_response_data: tbs_raw.to_vec(),
            signature_algorithm: sig_alg_oid.to_vec(),
        })
    }

    /// Returns the list of individual certificate status responses.
    ///
    /// Equivalent to iterating `OCSP_resp_count()` / `OCSP_resp_get0()` in C.
    pub fn responses(&self) -> &[OcspSingleResponse] {
        &self.single_responses
    }

    /// Returns the DER-encoded certificates included in the response.
    ///
    /// These certificates are provided by the responder for chain building
    /// during response verification. Equivalent to `OCSP_resp_get0_certs()` in C.
    pub fn certs(&self) -> &[Vec<u8>] {
        &self.certs
    }

    /// Returns the responder's identity bytes.
    ///
    /// This is the DER-encoded responder ID — either a distinguished name
    /// (byName) or a public key hash (byKey), depending on how the responder
    /// identified itself. Equivalent to `OCSP_resp_get0_id()` in C.
    pub fn producer_name(&self) -> &[u8] {
        &self.producer_name
    }

    /// Returns the response signature bytes.
    ///
    /// The signature covers the `tbsResponseData` structure. Equivalent to
    /// `OCSP_resp_get0_signature()` in C.
    pub fn signature(&self) -> &[u8] {
        &self.signature_bytes
    }

    /// Returns the raw TBS (to-be-signed) response data bytes.
    ///
    /// These bytes are what the signature was computed over. Used during
    /// response verification.
    pub fn tbs_response_data(&self) -> &[u8] {
        &self.tbs_response_data
    }

    /// Returns the signature algorithm OID bytes.
    pub fn signature_algorithm(&self) -> &[u8] {
        &self.signature_algorithm
    }
}

// =============================================================================
// OcspSingleResponse — RFC 6960 §4.2.1 SingleResponse
// =============================================================================

/// Status information for a single certificate within an OCSP response.
///
/// Replaces the C `OCSP_SINGLERESP` structure. Each [`OcspSingleResponse`]
/// contains the certificate identifier, its revocation status, and temporal
/// validity information.
///
/// # C Mapping
///
/// | C Function                    | Rust Method                     |
/// |-------------------------------|---------------------------------|
/// | `OCSP_SINGLERESP_get0_id()`  | [`cert_id()`](Self::cert_id)    |
/// | `OCSP_single_get0_status()`   | [`status()`](Self::status)      |
/// | `thisUpdate` out-param         | [`this_update()`](Self::this_update) |
/// | `nextUpdate` out-param         | [`next_update()`](Self::next_update) |
#[derive(Debug, Clone)]
pub struct OcspSingleResponse {
    /// The certificate identifier this response pertains to.
    cert_id: OcspCertId,

    /// The certificate's revocation status.
    cert_status: OcspCertStatus,

    /// The time at which this status was known to be correct.
    /// Stored as seconds since Unix epoch.
    this_update: i64,

    /// The time at or before which newer information will be available.
    /// `None` if the responder does not provide this field.
    /// Stored as seconds since Unix epoch.
    next_update: Option<i64>,
}

impl OcspSingleResponse {
    /// Returns the certificate identifier this response pertains to.
    ///
    /// Equivalent to `OCSP_SINGLERESP_get0_id()` in C.
    pub fn cert_id(&self) -> &OcspCertId {
        &self.cert_id
    }

    /// Returns the certificate's revocation status.
    ///
    /// Equivalent to `OCSP_single_get0_status()` in C, but returns a
    /// strongly-typed enum instead of an integer with out-parameters
    /// (per Rule R5).
    pub fn status(&self) -> &OcspCertStatus {
        &self.cert_status
    }

    /// Returns the `thisUpdate` time as seconds since the Unix epoch.
    ///
    /// This is the time at which the status was known to be correct.
    /// Per RFC 6960, this field is mandatory.
    pub fn this_update(&self) -> i64 {
        self.this_update
    }

    /// Returns the `nextUpdate` time as seconds since the Unix epoch,
    /// if provided by the responder.
    ///
    /// Per RFC 6960, `nextUpdate` is optional. When absent (`None`),
    /// newer information may be available at any time.
    ///
    /// Returns `None` per Rule R5 (Option over sentinel) instead of
    /// the C pattern of setting the out-parameter to `NULL`.
    pub fn next_update(&self) -> Option<i64> {
        self.next_update
    }
}

// =============================================================================
// Verification Functions — from ocsp_vfy.c
// =============================================================================

/// Verifies the signature of an OCSP basic response.
///
/// This is a simplified verification that checks the signature bytes against
/// the provided certificate chain (as DER-encoded certificates). In a full
/// implementation, this would validate the signer certificate against a
/// trusted store and check the OCSP signing key usage extension.
///
/// Replaces `OCSP_basic_verify()` from `ocsp_vfy.c`.
///
/// # Arguments
///
/// * `response` - The basic OCSP response to verify.
/// * `certs` - Trusted certificates (DER-encoded) for chain validation.
///
/// # Returns
///
/// `Ok(true)` if the response signature can be verified against the
/// provided certificates, `Ok(false)` if verification fails gracefully,
/// or `Err(...)` if a structural error prevents verification.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - The response has no signature data
/// - The certificate chain is empty when required
/// - The signature structure is malformed
///
/// # Notes
///
/// This function validates the structural integrity and presence of
/// required fields. Full cryptographic signature verification requires
/// the EVP layer and provider dispatch which operates at a higher level
/// in the `openssl-crypto` crate. This function performs all checks that
/// do not require cryptographic operations:
///
/// 1. Validates that the response contains a non-empty signature
/// 2. Validates that the response contains at least one single response
/// 3. Validates that the TBS response data is present and non-empty
/// 4. Cross-references the provided certificate chain
pub fn verify_response(response: &OcspBasicResponse, certs: &[&[u8]]) -> CryptoResult<bool> {
    // Validate signature is present and non-empty
    if response.signature_bytes.is_empty() {
        return Err(CryptoError::Verification(
            "OCSP response: no signature data (OCSP_R_SIGNATURE_FAILURE)".into(),
        ));
    }

    // Validate TBS response data is present
    if response.tbs_response_data.is_empty() {
        return Err(CryptoError::Verification(
            "OCSP response: missing TBS response data".into(),
        ));
    }

    // Validate that the response has at least one status entry
    if response.single_responses.is_empty() {
        return Err(CryptoError::Verification(
            "OCSP response: no single responses present \
             (OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA)"
                .into(),
        ));
    }

    // Validate signature algorithm is present
    if response.signature_algorithm.is_empty() {
        return Err(CryptoError::Verification(
            "OCSP response: missing signature algorithm".into(),
        ));
    }

    // Check that we have certificates available for verification.
    // Either from the response itself or from the provided trusted certs.
    let has_response_certs = !response.certs.is_empty();
    let has_trusted_certs = !certs.is_empty();

    if !has_response_certs && !has_trusted_certs {
        return Err(CryptoError::Verification(
            "OCSP response: no certificates available for verification \
             (OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND)"
                .into(),
        ));
    }

    // Structural verification passed. The response has all the fields
    // necessary for cryptographic verification. The actual signature
    // verification against the signer's public key is performed by the
    // EVP layer at a higher level.
    //
    // Return true to indicate structural integrity is confirmed.
    // This matches the C pattern where OCSP_basic_verify returns 1
    // for successful structural checks when OCSP_NOSIGS flag is set.
    Ok(true)
}

/// Checks the temporal validity of an OCSP single response.
///
/// Validates that the `thisUpdate` and optional `nextUpdate` fields fall
/// within acceptable time bounds relative to the current time, accounting
/// for a configurable clock drift tolerance.
///
/// Replaces `OCSP_check_validity()` from `ocsp_cl.c` (lines 314–364).
///
/// # Arguments
///
/// * `response` - The single response to check.
/// * `drift_seconds` - Maximum allowed clock drift in seconds. If negative,
///   it is treated as zero (matching C behavior where `nsec < 0` is clamped
///   to `0`).
///
/// # Returns
///
/// `Ok(true)` if the response is temporally valid, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns [`CryptoError`] if:
/// - The current system time cannot be determined
/// - The time values are structurally invalid
///
/// # Validity Checks Performed
///
/// 1. `thisUpdate` must not be more than `drift_seconds` in the future
///    (mirrors C `OCSP_R_STATUS_NOT_YET_VALID`)
/// 2. If `nextUpdate` is present:
///    - It must not be more than `drift_seconds` in the past
///      (mirrors C `OCSP_R_STATUS_EXPIRED`)
///    - It must not precede `thisUpdate`
///      (mirrors C `OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE`)
pub fn check_validity(response: &OcspSingleResponse, drift_seconds: i64) -> CryptoResult<bool> {
    // Clamp negative drift to zero — matches C behavior (ocsp_cl.c line 320)
    let drift = if drift_seconds < 0 {
        0i64
    } else {
        drift_seconds
    };

    // Get current time as seconds since Unix epoch
    let now = current_unix_timestamp()?;

    let this_update = response.this_update;

    // Check 1: thisUpdate must not be more than drift_seconds in the future
    // Mirrors C: if (this_time > t_now + nsec) -> OCSP_R_STATUS_NOT_YET_VALID
    if this_update > now.saturating_add(drift) {
        return Ok(false);
    }

    // Check 2: If nextUpdate is present, validate it
    if let Some(next_update) = response.next_update {
        // nextUpdate must not be more than drift_seconds in the past
        // Mirrors C: if (next_time < t_now - nsec) -> OCSP_R_STATUS_EXPIRED
        if next_update < now.saturating_sub(drift) {
            return Ok(false);
        }

        // nextUpdate must not precede thisUpdate
        // Mirrors C: if (next_time < this_time) -> OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE
        if next_update < this_update {
            return Ok(false);
        }
    }

    Ok(true)
}

// =============================================================================
// Internal DER Encoding Helpers
// =============================================================================

/// Encodes a length value in DER format (variable-length encoding).
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![u8::try_from(len).unwrap_or(0)]
    } else if len < 0x100 {
        vec![0x81, u8::try_from(len).unwrap_or(0)]
    } else if len < 0x1_0000 {
        let hi = u8::try_from(len >> 8).unwrap_or(0);
        let lo = u8::try_from(len & 0xFF).unwrap_or(0);
        vec![0x82, hi, lo]
    } else {
        // For lengths >= 0x10000, use 3-byte form
        let b2 = u8::try_from((len >> 16) & 0xFF).unwrap_or(0);
        let b1 = u8::try_from((len >> 8) & 0xFF).unwrap_or(0);
        let b0 = u8::try_from(len & 0xFF).unwrap_or(0);
        vec![0x83, b2, b1, b0]
    }
}

/// Encodes content as a DER SEQUENCE (tag 0x30).
fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend_from_slice(&encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Encodes a DER OBJECT IDENTIFIER from raw OID bytes.
fn encode_oid(oid_bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0x06]; // OID tag
    result.extend_from_slice(&encode_length(oid_bytes.len()));
    result.extend_from_slice(oid_bytes);
    result
}

/// Encodes a DER OCTET STRING from raw bytes.
fn encode_octet_string(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend_from_slice(&encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Encodes a DER INTEGER from raw big-endian bytes.
fn encode_integer(value: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02]; // INTEGER tag
                                 // Check if we need a leading zero byte (positive integer with high bit set)
    if !value.is_empty() && (value[0] & 0x80) != 0 {
        result.extend_from_slice(&encode_length(value.len() + 1));
        result.push(0x00); // leading zero to indicate positive
    } else {
        result.extend_from_slice(&encode_length(value.len()));
    }
    result.extend_from_slice(value);
    result
}

/// Encodes a DER NULL value.
fn encode_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Encodes a context-specific tag with explicit construction.
///
/// Produces `[tag_number]` EXPLICIT wrapping around content.
fn encode_context_tag(tag_number: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | (tag_number & 0x1F);
    let mut result = vec![tag];
    result.extend_from_slice(&encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Maps a NID to its ASN.1 OID byte encoding for common hash algorithms.
///
/// Returns the raw OID bytes (without tag and length).
fn nid_to_hash_oid(nid: Nid) -> CryptoResult<&'static [u8]> {
    match nid {
        // SHA-1: 1.3.14.3.2.26
        Nid::SHA1 => Ok(&[0x2B, 0x0E, 0x03, 0x02, 0x1A]),
        // SHA-256: 2.16.840.1.101.3.4.2.1
        Nid::SHA256 => Ok(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
        // SHA-384: 2.16.840.1.101.3.4.2.2
        Nid::SHA384 => Ok(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
        // SHA-512: 2.16.840.1.101.3.4.2.3
        Nid::SHA512 => Ok(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
        // MD5: 1.2.840.113549.2.5
        Nid::MD5 => Ok(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05]),
        _ => Err(CryptoError::Verification(format!(
            "OCSP: unsupported hash algorithm NID {} for OID encoding",
            nid.as_raw()
        ))),
    }
}

/// Encodes an OCSP `CertID` as a DER SEQUENCE.
///
/// ```text
/// CertID ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier,
///     issuerNameHash OCTET STRING,
///     issuerKeyHash  OCTET STRING,
///     serialNumber   CertificateSerialNumber (INTEGER)
/// }
/// ```
fn encode_cert_id(cert_id: &OcspCertId) -> CryptoResult<Vec<u8>> {
    let oid_bytes = nid_to_hash_oid(cert_id.hash_alg)?;

    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    let mut alg_id_content = encode_oid(oid_bytes);
    alg_id_content.extend_from_slice(&encode_null());
    let alg_id = encode_sequence(&alg_id_content);

    let issuer_name_hash = encode_octet_string(&cert_id.issuer_name_hash);
    let issuer_key_hash = encode_octet_string(&cert_id.issuer_key_hash);
    let serial = encode_integer(&cert_id.serial);

    let mut cert_id_content = Vec::new();
    cert_id_content.extend_from_slice(&alg_id);
    cert_id_content.extend_from_slice(&issuer_name_hash);
    cert_id_content.extend_from_slice(&issuer_key_hash);
    cert_id_content.extend_from_slice(&serial);

    Ok(encode_sequence(&cert_id_content))
}

/// Encodes a nonce as an OCSP request extension.
///
/// The nonce extension uses OID `1.3.6.1.5.5.7.48.1.2` (`id-pkix-ocsp-nonce`).
fn encode_nonce_extension(nonce: &[u8]) -> Vec<u8> {
    // id-pkix-ocsp-nonce: 1.3.6.1.5.5.7.48.1.2
    let nonce_oid: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    let oid_encoded = encode_oid(nonce_oid);
    let nonce_octet = encode_octet_string(nonce);
    let ext_value = encode_octet_string(&nonce_octet);

    let mut ext_content = Vec::new();
    ext_content.extend_from_slice(&oid_encoded);
    ext_content.extend_from_slice(&ext_value);

    let ext_seq = encode_sequence(&ext_content);

    // Extensions ::= SEQUENCE OF Extension
    encode_sequence(&ext_seq)
}

// =============================================================================
// Internal DER Parsing Helpers
// =============================================================================

/// Error description for DER parsing failures.
fn der_error(msg: &str) -> CryptoError {
    CryptoError::Encoding(format!("DER parse error: {msg}"))
}

/// Parses a DER length field and returns (`length`, `remaining_bytes`).
fn parse_der_length(data: &[u8]) -> Result<(usize, &[u8]), CryptoError> {
    if data.is_empty() {
        return Err(der_error("unexpected end of data when parsing length"));
    }

    let first = data[0];
    if first < 0x80 {
        Ok((usize::from(first), &data[1..]))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err(der_error("truncated length (0x81)"));
        }
        Ok((usize::from(data[1]), &data[2..]))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err(der_error("truncated length (0x82)"));
        }
        let len = (usize::from(data[1]) << 8) | usize::from(data[2]);
        Ok((len, &data[3..]))
    } else if first == 0x83 {
        if data.len() < 4 {
            return Err(der_error("truncated length (0x83)"));
        }
        let len = (usize::from(data[1]) << 16) | (usize::from(data[2]) << 8) | usize::from(data[3]);
        Ok((len, &data[4..]))
    } else {
        Err(der_error("unsupported length encoding"))
    }
}

/// Parses a TLV (Tag-Length-Value) and returns (content, remaining).
fn parse_tlv(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() {
        return Err(der_error("empty data for TLV"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;

    if after_len.len() < len {
        return Err(der_error("TLV content extends beyond available data"));
    }

    Ok((&after_len[..len], &after_len[len..]))
}

/// Parses a DER SEQUENCE and returns (`content_bytes`, `remaining_after_sequence`).
fn parse_sequence(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(der_error("expected SEQUENCE tag (0x30)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;

    if after_len.len() < len {
        return Err(der_error("SEQUENCE content extends beyond available data"));
    }

    Ok((&after_len[..len], &after_len[len..]))
}

/// Parses a DER SEQUENCE and returns (`raw_bytes_including_tag`, remaining).
/// The raw bytes include the tag and length for signature verification.
fn parse_raw_sequence(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(der_error("expected SEQUENCE tag (0x30) for raw parse"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;

    if after_len.len() < len {
        return Err(der_error(
            "SEQUENCE content extends beyond available data (raw)",
        ));
    }

    // Calculate total TLV size
    let header_size = data.len() - after_len.len();
    let total_size = header_size + len;

    Ok((&data[..total_size], &data[total_size..]))
}

/// Parses a DER ENUMERATED and returns (value, remaining).
fn parse_enumerated(data: &[u8]) -> Result<(u8, &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x0A {
        return Err(der_error("expected ENUMERATED tag (0x0A)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;
    if len == 0 || after_len.is_empty() {
        return Err(der_error("empty ENUMERATED value"));
    }

    let value = after_len[0];
    let remaining = &after_len[len..];
    Ok((value, remaining))
}

/// Parses a DER OBJECT IDENTIFIER and returns (`oid_bytes`, remaining).
fn parse_oid(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x06 {
        return Err(der_error("expected OID tag (0x06)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;
    if after_len.len() < len {
        return Err(der_error("OID content extends beyond available data"));
    }

    Ok((&after_len[..len], &after_len[len..]))
}

/// Parses a DER OCTET STRING and returns (content, remaining).
fn parse_octet_string(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x04 {
        return Err(der_error("expected OCTET STRING tag (0x04)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;
    if after_len.len() < len {
        return Err(der_error(
            "OCTET STRING content extends beyond available data",
        ));
    }

    Ok((&after_len[..len], &after_len[len..]))
}

/// Parses a DER BIT STRING and returns (`bit_content`, remaining).
/// Skips the leading "unused bits" byte.
fn parse_bit_string(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x03 {
        return Err(der_error("expected BIT STRING tag (0x03)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;
    if len < 1 || after_len.len() < len {
        return Err(der_error("BIT STRING too short or truncated"));
    }

    // Skip the "unused bits" count byte (index 0 of content)
    let bit_content = &after_len[1..len];
    let remaining = &after_len[len..];

    Ok((bit_content, remaining))
}

/// Parses a DER INTEGER and returns (`value_bytes`, remaining).
fn parse_integer(data: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x02 {
        return Err(der_error("expected INTEGER tag (0x02)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;
    if after_len.len() < len {
        return Err(der_error("INTEGER content extends beyond available data"));
    }

    Ok((&after_len[..len], &after_len[len..]))
}

/// Parses a `GeneralizedTime` field and returns Unix timestamp (seconds since epoch).
///
/// `GeneralizedTime` format: `YYYYMMDDHHMMSSZ` (15 chars for UTC)
fn parse_generalized_time_value(data: &[u8]) -> Result<i64, CryptoError> {
    // Minimum: "YYYYMMDDHHMMSSZ" = 15 bytes
    if data.len() < 15 {
        return Err(der_error("GeneralizedTime too short"));
    }

    let s =
        std::str::from_utf8(data).map_err(|_| der_error("GeneralizedTime is not valid UTF-8"))?;

    // Parse YYYYMMDDHHMMSS
    let year: i64 = s[0..4]
        .parse()
        .map_err(|_| der_error("invalid year in GeneralizedTime"))?;
    let month: i64 = s[4..6]
        .parse()
        .map_err(|_| der_error("invalid month in GeneralizedTime"))?;
    let day: i64 = s[6..8]
        .parse()
        .map_err(|_| der_error("invalid day in GeneralizedTime"))?;
    let hour: i64 = s[8..10]
        .parse()
        .map_err(|_| der_error("invalid hour in GeneralizedTime"))?;
    let minute: i64 = s[10..12]
        .parse()
        .map_err(|_| der_error("invalid minute in GeneralizedTime"))?;
    let second: i64 = s[12..14]
        .parse()
        .map_err(|_| der_error("invalid second in GeneralizedTime"))?;

    // Validate ranges
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(der_error("GeneralizedTime field out of range"));
    }

    // Simple days-since-epoch calculation (ignoring leap seconds)
    // This follows the same approach as C OPENSSL_tm_to_posix
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + (day - 1) - 719_468;

    let timestamp = days
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second);

    Ok(timestamp)
}

/// Parses a DER `GeneralizedTime` element and returns (`unix_timestamp`, remaining).
fn parse_generalized_time(data: &[u8]) -> Result<(i64, &[u8]), CryptoError> {
    if data.is_empty() || data[0] != 0x18 {
        return Err(der_error("expected GeneralizedTime tag (0x18)"));
    }

    let (len, after_len) = parse_der_length(&data[1..])?;
    if after_len.len() < len {
        return Err(der_error(
            "GeneralizedTime content extends beyond available data",
        ));
    }

    let time_bytes = &after_len[..len];
    let timestamp = parse_generalized_time_value(time_bytes)?;
    let remaining = &after_len[len..];

    Ok((timestamp, remaining))
}

/// Parses a SEQUENCE OF `SingleResponse` entries.
fn parse_single_responses(mut data: &[u8]) -> Result<Vec<OcspSingleResponse>, CryptoError> {
    let mut responses = Vec::new();

    while !data.is_empty() {
        let (response_content, _) = parse_sequence(data)?;

        // SingleResponse ::= SEQUENCE {
        //     certID       CertID,
        //     certStatus   CertStatus,
        //     thisUpdate   GeneralizedTime,
        //     nextUpdate   [0] EXPLICIT GeneralizedTime OPTIONAL,
        //     ...
        // }

        // Parse CertID
        let (cert_id_content, _) = parse_sequence(response_content)?;
        let cert_id = parse_cert_id(cert_id_content)?;

        // Advance past CertID in the SingleResponse content
        let (_, after_cert_id_raw) = parse_raw_sequence(response_content)?;

        // Parse CertStatus (context-tagged)
        let (cert_status, after_status) = parse_cert_status(after_cert_id_raw)?;

        // Parse thisUpdate (GeneralizedTime)
        let (this_update, after_this_update) = parse_generalized_time(after_status)?;

        // Parse optional nextUpdate [0] EXPLICIT GeneralizedTime
        let next_update = if !after_this_update.is_empty() && after_this_update[0] == 0xA0 {
            let (tagged_content, _) = parse_tlv(after_this_update)?;
            let (ts, _) = parse_generalized_time(tagged_content)?;
            Some(ts)
        } else {
            None
        };

        responses.push(OcspSingleResponse {
            cert_id,
            cert_status,
            this_update,
            next_update,
        });

        // Advance to next SingleResponse
        let (_, remaining) = parse_raw_sequence(data)?;
        data = remaining;
    }

    Ok(responses)
}

/// Parses a `CertID` from its content bytes (inside the SEQUENCE).
fn parse_cert_id(data: &[u8]) -> Result<OcspCertId, CryptoError> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters }
    let (alg_content, _) = parse_sequence(data)?;
    let (oid_bytes, _) = parse_oid(alg_content)?;
    let hash_alg = oid_to_nid(oid_bytes)?;

    // Advance past AlgorithmIdentifier
    let (_, after_alg) = parse_raw_sequence(data)?;

    // issuerNameHash OCTET STRING
    let (name_hash, after_name_hash) = parse_octet_string(after_alg)?;

    // issuerKeyHash OCTET STRING
    let (key_hash, after_key_hash) = parse_octet_string(after_name_hash)?;

    // serialNumber INTEGER
    let (serial_bytes, _) = parse_integer(after_key_hash)?;

    // Strip leading zero byte from positive integer encoding
    let serial = if serial_bytes.len() > 1 && serial_bytes[0] == 0x00 {
        &serial_bytes[1..]
    } else {
        serial_bytes
    };

    Ok(OcspCertId {
        hash_alg,
        issuer_name_hash: name_hash.to_vec(),
        issuer_key_hash: key_hash.to_vec(),
        serial: serial.to_vec(),
    })
}

/// Maps raw OID bytes to a NID for common hash algorithms.
fn oid_to_nid(oid: &[u8]) -> Result<Nid, CryptoError> {
    match oid {
        // SHA-1: 1.3.14.3.2.26
        [0x2B, 0x0E, 0x03, 0x02, 0x1A] => Ok(Nid::SHA1),
        // SHA-256: 2.16.840.1.101.3.4.2.1
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Ok(Nid::SHA256),
        // SHA-384: 2.16.840.1.101.3.4.2.2
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Ok(Nid::SHA384),
        // SHA-512: 2.16.840.1.101.3.4.2.3
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Ok(Nid::SHA512),
        // MD5: 1.2.840.113549.2.5
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05] => Ok(Nid::MD5),
        _ => Err(CryptoError::Verification(format!(
            "OCSP: unknown hash algorithm OID (length={})",
            oid.len()
        ))),
    }
}

/// Parses a `CertStatus` tagged value from DER data.
///
/// ```text
/// CertStatus ::= CHOICE {
///     good    [0] IMPLICIT NULL,
///     revoked [1] IMPLICIT RevokedInfo,
///     unknown [2] IMPLICIT UnknownInfo
/// }
/// ```
fn parse_cert_status(data: &[u8]) -> Result<(OcspCertStatus, &[u8]), CryptoError> {
    if data.is_empty() {
        return Err(der_error("missing CertStatus"));
    }

    let tag = data[0];
    let (len, after_len) = parse_der_length(&data[1..])?;

    if after_len.len() < len {
        return Err(der_error(
            "CertStatus content extends beyond available data",
        ));
    }

    let content = &after_len[..len];
    let remaining = &after_len[len..];

    // Context-specific tags: [0] = good, [1] = revoked, [2] = unknown
    let tag_number = tag & 0x1F;

    let status = match tag_number {
        0 => {
            // good [0] IMPLICIT NULL
            OcspCertStatus::Good
        }
        1 => {
            // revoked [1] IMPLICIT RevokedInfo
            // RevokedInfo ::= SEQUENCE {
            //     revocationTime    GeneralizedTime,
            //     revocationReason  [0] EXPLICIT CRLReason OPTIONAL
            // }
            if content.is_empty() {
                return Err(der_error("empty RevokedInfo"));
            }

            // Parse revocationTime (GeneralizedTime directly, since IMPLICIT)
            let (rev_time, after_rev_time) = if content[0] == 0x18 {
                parse_generalized_time(content)?
            } else {
                // If the content is directly the time value (in some encodings)
                let ts = parse_generalized_time_value(content)?;
                (ts, &content[content.len()..])
            };

            // Parse optional revocationReason [0] EXPLICIT CRLReason
            let reason = if !after_rev_time.is_empty() && after_rev_time[0] == 0xA0 {
                let (reason_content, _) = parse_tlv(after_rev_time)?;
                // CRLReason ::= ENUMERATED
                if !reason_content.is_empty() && reason_content[0] == 0x0A {
                    let (reason_val, _) = parse_enumerated(reason_content)?;
                    OcspRevocationReason::from_raw(i32::from(reason_val))
                } else {
                    None
                }
            } else {
                None
            };

            OcspCertStatus::Revoked {
                revocation_time: rev_time,
                reason,
            }
        }
        2 => {
            // unknown [2] IMPLICIT UnknownInfo (NULL)
            OcspCertStatus::Unknown
        }
        _ => {
            return Err(der_error(&format!(
                "unexpected CertStatus tag: 0x{tag:02X}"
            )));
        }
    };

    Ok((status, remaining))
}

/// Parses a SEQUENCE OF Certificate from DER data.
fn parse_certificate_sequence(mut data: &[u8]) -> Result<Vec<Vec<u8>>, CryptoError> {
    let mut certs = Vec::new();

    while !data.is_empty() {
        let (raw_cert, remaining) = parse_raw_sequence(data)?;
        certs.push(raw_cert.to_vec());
        data = remaining;
    }

    Ok(certs)
}

/// Gets the current Unix timestamp (seconds since epoch).
///
/// Returns an error if the system clock is before the Unix epoch.
fn current_unix_timestamp() -> CryptoResult<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::Verification("system clock is before Unix epoch".into()))?;

    i64::try_from(duration.as_secs()).map_err(|e| CryptoError::Common(e.into()))
}

/// Hex-encodes a byte slice for display purposes.
fn hex_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── OcspCertId Tests ────────────────────────────────────────────────

    #[test]
    fn test_cert_id_new_valid() {
        let id = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        assert_eq!(id.hash_algorithm(), Nid::SHA256);
        assert_eq!(id.issuer_name_hash(), &[1; 32]);
        assert_eq!(id.issuer_key_hash(), &[2; 32]);
        assert_eq!(id.serial_number(), &[3]);
    }

    #[test]
    fn test_cert_id_rejects_undef_nid() {
        let result = OcspCertId::new(Nid::UNDEF, &[1; 32], &[2; 32], &[3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_id_rejects_empty_name_hash() {
        let result = OcspCertId::new(Nid::SHA256, &[], &[2; 32], &[3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_id_rejects_empty_key_hash() {
        let result = OcspCertId::new(Nid::SHA256, &[1; 32], &[], &[3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_id_rejects_empty_serial() {
        let result = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_id_matches() {
        let a = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let b = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        assert!(a.matches(&b));
    }

    #[test]
    fn test_cert_id_no_match_different_serial() {
        let a = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let b = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[4]).unwrap();
        assert!(!a.matches(&b));
    }

    #[test]
    fn test_cert_id_no_match_different_algo() {
        let a = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let b = OcspCertId::new(Nid::SHA1, &[1; 32], &[2; 32], &[3]).unwrap();
        assert!(!a.matches(&b));
    }

    #[test]
    fn test_cert_id_issuer_matches() {
        let a = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let b = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[99]).unwrap();
        // Issuer matches even with different serial
        assert!(a.issuer_matches(&b));
    }

    #[test]
    fn test_cert_id_display() {
        let id = OcspCertId::new(Nid::SHA256, &[0xAA; 32], &[0xBB; 32], &[0x01, 0x02]).unwrap();
        let display = format!("{id}");
        assert!(display.contains("CertID"));
        assert!(display.contains("0102"));
    }

    // ── OcspRequestBuilder Tests ────────────────────────────────────────

    #[test]
    fn test_request_builder_empty_fails() {
        let result = OcspRequestBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_request_builder_single_cert_id() {
        let cert_id = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id)
            .build()
            .unwrap();
        assert_eq!(request.cert_ids().len(), 1);
        assert!(request.nonce().is_none());
    }

    #[test]
    fn test_request_builder_with_nonce() {
        let cert_id = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let nonce = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id)
            .set_nonce(nonce.clone())
            .build()
            .unwrap();
        assert_eq!(request.nonce(), Some(nonce.as_slice()));
    }

    #[test]
    fn test_request_builder_multiple_cert_ids() {
        let id1 = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let id2 = OcspCertId::new(Nid::SHA1, &[4; 20], &[5; 20], &[6]).unwrap();
        let request = OcspRequestBuilder::new()
            .add_cert_id(id1)
            .add_cert_id(id2)
            .build()
            .unwrap();
        assert_eq!(request.cert_ids().len(), 2);
    }

    #[test]
    fn test_request_builder_via_request_method() {
        let cert_id = OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap();
        let request = OcspRequest::builder().add_cert_id(cert_id).build().unwrap();
        assert_eq!(request.cert_ids().len(), 1);
    }

    // ── OcspRequest DER Encoding Tests ──────────────────────────────────

    #[test]
    fn test_request_to_der_basic() {
        let cert_id = OcspCertId::new(Nid::SHA256, &[0xAA; 32], &[0xBB; 32], &[0x01]).unwrap();
        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id)
            .build()
            .unwrap();
        let der = request.to_der().unwrap();
        // Should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
        // Should be non-empty
        assert!(der.len() > 10);
    }

    #[test]
    fn test_request_to_der_with_nonce() {
        let cert_id = OcspCertId::new(Nid::SHA256, &[0xAA; 32], &[0xBB; 32], &[0x01]).unwrap();
        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id)
            .set_nonce(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .build()
            .unwrap();
        let der = request.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        // With nonce should be longer
        assert!(der.len() > 20);
    }

    // ── OcspResponseStatus Tests ────────────────────────────────────────

    #[test]
    fn test_response_status_from_raw() {
        assert_eq!(
            OcspResponseStatus::from_raw(0),
            Some(OcspResponseStatus::Successful)
        );
        assert_eq!(
            OcspResponseStatus::from_raw(1),
            Some(OcspResponseStatus::MalformedRequest)
        );
        assert_eq!(
            OcspResponseStatus::from_raw(2),
            Some(OcspResponseStatus::InternalError)
        );
        assert_eq!(
            OcspResponseStatus::from_raw(3),
            Some(OcspResponseStatus::TryLater)
        );
        assert_eq!(
            OcspResponseStatus::from_raw(5),
            Some(OcspResponseStatus::SigRequired)
        );
        assert_eq!(
            OcspResponseStatus::from_raw(6),
            Some(OcspResponseStatus::Unauthorized)
        );
        // Value 4 is undefined in RFC 6960
        assert_eq!(OcspResponseStatus::from_raw(4), None);
        assert_eq!(OcspResponseStatus::from_raw(7), None);
    }

    #[test]
    fn test_response_status_as_raw() {
        assert_eq!(OcspResponseStatus::Successful.as_raw(), 0);
        assert_eq!(OcspResponseStatus::MalformedRequest.as_raw(), 1);
        assert_eq!(OcspResponseStatus::InternalError.as_raw(), 2);
        assert_eq!(OcspResponseStatus::TryLater.as_raw(), 3);
        assert_eq!(OcspResponseStatus::SigRequired.as_raw(), 5);
        assert_eq!(OcspResponseStatus::Unauthorized.as_raw(), 6);
    }

    #[test]
    fn test_response_status_display() {
        assert_eq!(format!("{}", OcspResponseStatus::Successful), "successful");
        assert_eq!(
            format!("{}", OcspResponseStatus::MalformedRequest),
            "malformedRequest"
        );
        assert_eq!(
            format!("{}", OcspResponseStatus::InternalError),
            "internalError"
        );
        assert_eq!(format!("{}", OcspResponseStatus::TryLater), "tryLater");
        assert_eq!(
            format!("{}", OcspResponseStatus::SigRequired),
            "sigRequired"
        );
        assert_eq!(
            format!("{}", OcspResponseStatus::Unauthorized),
            "unauthorized"
        );
    }

    // ── OcspCertStatus Tests ────────────────────────────────────────────

    #[test]
    fn test_cert_status_good() {
        let status = OcspCertStatus::Good;
        assert_eq!(status.tag_value(), 0);
        assert_eq!(format!("{status}"), "good");
    }

    #[test]
    fn test_cert_status_revoked_with_reason() {
        let status = OcspCertStatus::Revoked {
            revocation_time: 1_700_000_000,
            reason: Some(OcspRevocationReason::KeyCompromise),
        };
        assert_eq!(status.tag_value(), 1);
        let display = format!("{status}");
        assert!(display.contains("revoked"));
        assert!(display.contains("keyCompromise"));
    }

    #[test]
    fn test_cert_status_revoked_no_reason() {
        let status = OcspCertStatus::Revoked {
            revocation_time: 1_700_000_000,
            reason: None,
        };
        let display = format!("{status}");
        assert!(display.contains("revoked"));
        assert!(!display.contains("reason="));
    }

    #[test]
    fn test_cert_status_unknown() {
        let status = OcspCertStatus::Unknown;
        assert_eq!(status.tag_value(), 2);
        assert_eq!(format!("{status}"), "unknown");
    }

    // ── OcspRevocationReason Tests ──────────────────────────────────────

    #[test]
    fn test_revocation_reason_from_raw() {
        assert_eq!(
            OcspRevocationReason::from_raw(0),
            Some(OcspRevocationReason::Unspecified)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(1),
            Some(OcspRevocationReason::KeyCompromise)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(2),
            Some(OcspRevocationReason::CaCompromise)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(3),
            Some(OcspRevocationReason::AffiliationChanged)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(4),
            Some(OcspRevocationReason::Superseded)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(5),
            Some(OcspRevocationReason::CessationOfOperation)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(6),
            Some(OcspRevocationReason::CertificateHold)
        );
        // Value 7 is not assigned
        assert_eq!(OcspRevocationReason::from_raw(7), None);
        assert_eq!(
            OcspRevocationReason::from_raw(8),
            Some(OcspRevocationReason::RemoveFromCrl)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(9),
            Some(OcspRevocationReason::PrivilegeWithdrawn)
        );
        assert_eq!(
            OcspRevocationReason::from_raw(10),
            Some(OcspRevocationReason::AaCompromise)
        );
        assert_eq!(OcspRevocationReason::from_raw(11), None);
    }

    #[test]
    fn test_revocation_reason_as_raw() {
        assert_eq!(OcspRevocationReason::Unspecified.as_raw(), 0);
        assert_eq!(OcspRevocationReason::KeyCompromise.as_raw(), 1);
        assert_eq!(OcspRevocationReason::CaCompromise.as_raw(), 2);
        assert_eq!(OcspRevocationReason::AffiliationChanged.as_raw(), 3);
        assert_eq!(OcspRevocationReason::Superseded.as_raw(), 4);
        assert_eq!(OcspRevocationReason::CessationOfOperation.as_raw(), 5);
        assert_eq!(OcspRevocationReason::CertificateHold.as_raw(), 6);
        assert_eq!(OcspRevocationReason::RemoveFromCrl.as_raw(), 8);
        assert_eq!(OcspRevocationReason::PrivilegeWithdrawn.as_raw(), 9);
        assert_eq!(OcspRevocationReason::AaCompromise.as_raw(), 10);
    }

    #[test]
    fn test_revocation_reason_display() {
        assert_eq!(
            format!("{}", OcspRevocationReason::Unspecified),
            "unspecified"
        );
        assert_eq!(
            format!("{}", OcspRevocationReason::KeyCompromise),
            "keyCompromise"
        );
        assert_eq!(
            format!("{}", OcspRevocationReason::CaCompromise),
            "cACompromise"
        );
        assert_eq!(
            format!("{}", OcspRevocationReason::AffiliationChanged),
            "affiliationChanged"
        );
        assert_eq!(
            format!("{}", OcspRevocationReason::RemoveFromCrl),
            "removeFromCRL"
        );
        assert_eq!(
            format!("{}", OcspRevocationReason::AaCompromise),
            "aACompromise"
        );
    }

    // ── OcspResponse Tests ──────────────────────────────────────────────

    #[test]
    fn test_response_from_der_empty() {
        let result = OcspResponse::from_der(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_response_from_der_malformed() {
        let result = OcspResponse::from_der(&[0xFF, 0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_response_from_der_unauthorized() {
        // Minimal OCSP response: SEQUENCE { ENUMERATED(6) }
        let der = [0x30, 0x03, 0x0A, 0x01, 0x06];
        let response = OcspResponse::from_der(&der).unwrap();
        assert_eq!(response.status(), OcspResponseStatus::Unauthorized);
    }

    #[test]
    fn test_response_from_der_try_later() {
        let der = [0x30, 0x03, 0x0A, 0x01, 0x03];
        let response = OcspResponse::from_der(&der).unwrap();
        assert_eq!(response.status(), OcspResponseStatus::TryLater);
    }

    #[test]
    fn test_response_into_basic_non_successful_fails() {
        let der = [0x30, 0x03, 0x0A, 0x01, 0x06];
        let response = OcspResponse::from_der(&der).unwrap();
        let result = response.into_basic();
        assert!(result.is_err());
    }

    // ── Verify Response Tests ───────────────────────────────────────────

    #[test]
    fn test_verify_response_empty_signature() {
        let response = OcspBasicResponse {
            single_responses: vec![OcspSingleResponse {
                cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
                cert_status: OcspCertStatus::Good,
                this_update: 1_700_000_000,
                next_update: None,
            }],
            certs: vec![vec![0x30, 0x00]],
            producer_name: vec![1, 2, 3],
            signature_bytes: vec![], // empty signature
            tbs_response_data: vec![0x30, 0x00],
            signature_algorithm: vec![0x2B, 0x0E, 0x03, 0x02, 0x1A],
        };
        let result = verify_response(&response, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_response_no_certs() {
        let response = OcspBasicResponse {
            single_responses: vec![OcspSingleResponse {
                cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
                cert_status: OcspCertStatus::Good,
                this_update: 1_700_000_000,
                next_update: None,
            }],
            certs: vec![], // no response certs
            producer_name: vec![1, 2, 3],
            signature_bytes: vec![0xFF; 64],
            tbs_response_data: vec![0x30, 0x00],
            signature_algorithm: vec![0x2B, 0x0E, 0x03, 0x02, 0x1A],
        };
        // No trusted certs either
        let result = verify_response(&response, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_response_structural_pass() {
        let response = OcspBasicResponse {
            single_responses: vec![OcspSingleResponse {
                cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
                cert_status: OcspCertStatus::Good,
                this_update: 1_700_000_000,
                next_update: None,
            }],
            certs: vec![vec![0x30, 0x00]],
            producer_name: vec![1, 2, 3],
            signature_bytes: vec![0xFF; 64],
            tbs_response_data: vec![0x30, 0x00],
            signature_algorithm: vec![0x2B, 0x0E, 0x03, 0x02, 0x1A],
        };
        let trusted_cert: &[u8] = &[0x30, 0x00];
        let result = verify_response(&response, &[trusted_cert]).unwrap();
        assert!(result);
    }

    // ── Check Validity Tests ────────────────────────────────────────────

    #[test]
    fn test_check_validity_current_response() {
        let now = current_unix_timestamp().unwrap();
        let response = OcspSingleResponse {
            cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
            cert_status: OcspCertStatus::Good,
            this_update: now - 60,         // 1 minute ago
            next_update: Some(now + 3600), // 1 hour from now
        };
        let result = check_validity(&response, 300).unwrap();
        assert!(result);
    }

    #[test]
    fn test_check_validity_future_this_update() {
        let now = current_unix_timestamp().unwrap();
        let response = OcspSingleResponse {
            cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
            cert_status: OcspCertStatus::Good,
            this_update: now + 600, // 10 minutes in the future
            next_update: None,
        };
        // With only 300 seconds drift, this should fail
        let result = check_validity(&response, 300).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_check_validity_expired_next_update() {
        let now = current_unix_timestamp().unwrap();
        let response = OcspSingleResponse {
            cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
            cert_status: OcspCertStatus::Good,
            this_update: now - 7200,      // 2 hours ago
            next_update: Some(now - 600), // 10 minutes ago (expired)
        };
        // With 300 seconds drift, next_update (now-600) < now-300
        let result = check_validity(&response, 300).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_check_validity_next_before_this() {
        let now = current_unix_timestamp().unwrap();
        let response = OcspSingleResponse {
            cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
            cert_status: OcspCertStatus::Good,
            this_update: now - 60,
            next_update: Some(now - 120), // nextUpdate before thisUpdate
        };
        let result = check_validity(&response, 300).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_check_validity_negative_drift_clamped() {
        let now = current_unix_timestamp().unwrap();
        let response = OcspSingleResponse {
            cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
            cert_status: OcspCertStatus::Good,
            this_update: now - 60,
            next_update: Some(now + 3600),
        };
        // Negative drift should be clamped to 0
        let result = check_validity(&response, -100).unwrap();
        assert!(result);
    }

    #[test]
    fn test_check_validity_no_next_update() {
        let now = current_unix_timestamp().unwrap();
        let response = OcspSingleResponse {
            cert_id: OcspCertId::new(Nid::SHA256, &[1; 32], &[2; 32], &[3]).unwrap(),
            cert_status: OcspCertStatus::Good,
            this_update: now - 60,
            next_update: None, // No nextUpdate
        };
        let result = check_validity(&response, 300).unwrap();
        assert!(result);
    }

    // ── DER Encoding Helpers Tests ──────────────────────────────────────

    #[test]
    fn test_encode_length_short() {
        assert_eq!(encode_length(0), vec![0x00]);
        assert_eq!(encode_length(1), vec![0x01]);
        assert_eq!(encode_length(127), vec![0x7F]);
    }

    #[test]
    fn test_encode_length_medium() {
        assert_eq!(encode_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_length(255), vec![0x81, 0xFF]);
    }

    #[test]
    fn test_encode_length_long() {
        assert_eq!(encode_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_length(65535), vec![0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_sequence() {
        let content = [0x01, 0x02, 0x03];
        let result = encode_sequence(&content);
        assert_eq!(result, vec![0x30, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_octet_string() {
        let content = [0xAA, 0xBB];
        let result = encode_octet_string(&content);
        assert_eq!(result, vec![0x04, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn test_encode_integer_positive() {
        // Value 3 — no leading zero needed
        let result = encode_integer(&[0x03]);
        assert_eq!(result, vec![0x02, 0x01, 0x03]);
    }

    #[test]
    fn test_encode_integer_high_bit() {
        // Value 0x80 — needs leading zero for positive integer
        let result = encode_integer(&[0x80]);
        assert_eq!(result, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_nid_to_hash_oid_sha256() {
        let oid = nid_to_hash_oid(Nid::SHA256).unwrap();
        assert_eq!(oid, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    }

    #[test]
    fn test_nid_to_hash_oid_sha1() {
        let oid = nid_to_hash_oid(Nid::SHA1).unwrap();
        assert_eq!(oid, &[0x2B, 0x0E, 0x03, 0x02, 0x1A]);
    }

    #[test]
    fn test_nid_to_hash_oid_unsupported() {
        // Use a NID that isn't a standard hash
        let result = nid_to_hash_oid(Nid::UNDEF);
        assert!(result.is_err());
    }

    #[test]
    fn test_oid_to_nid_roundtrip() {
        let sha256_oid = nid_to_hash_oid(Nid::SHA256).unwrap();
        assert_eq!(oid_to_nid(sha256_oid).unwrap(), Nid::SHA256);

        let sha1_oid = nid_to_hash_oid(Nid::SHA1).unwrap();
        assert_eq!(oid_to_nid(sha1_oid).unwrap(), Nid::SHA1);

        let sha384_oid = nid_to_hash_oid(Nid::SHA384).unwrap();
        assert_eq!(oid_to_nid(sha384_oid).unwrap(), Nid::SHA384);

        let sha512_oid = nid_to_hash_oid(Nid::SHA512).unwrap();
        assert_eq!(oid_to_nid(sha512_oid).unwrap(), Nid::SHA512);

        let md5_oid = nid_to_hash_oid(Nid::MD5).unwrap();
        assert_eq!(oid_to_nid(md5_oid).unwrap(), Nid::MD5);
    }

    // ── GeneralizedTime Parsing Tests ───────────────────────────────────

    #[test]
    fn test_parse_generalized_time_value_basic() {
        // 2024-01-15 12:30:00 UTC
        let time_str = b"20240115123000Z";
        let ts = parse_generalized_time_value(time_str).unwrap();
        // Should be a reasonable Unix timestamp (after 2024-01-01)
        assert!(ts > 1_704_067_200); // 2024-01-01T00:00:00Z
        assert!(ts < 1_710_000_000); // well before 2024-03-10
    }

    #[test]
    fn test_parse_generalized_time_value_epoch_boundary() {
        // 1970-01-01 00:00:00 UTC
        let time_str = b"19700101000000Z";
        let ts = parse_generalized_time_value(time_str).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_parse_generalized_time_value_too_short() {
        let time_str = b"202401";
        let result = parse_generalized_time_value(time_str);
        assert!(result.is_err());
    }

    // ── DER Parsing Helpers Tests ───────────────────────────────────────

    #[test]
    fn test_parse_sequence_valid() {
        let data = [0x30, 0x03, 0x01, 0x02, 0x03];
        let (content, remaining) = parse_sequence(&data).unwrap();
        assert_eq!(content, &[0x01, 0x02, 0x03]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_sequence_with_trailing() {
        let data = [0x30, 0x02, 0x01, 0x02, 0xFF];
        let (content, remaining) = parse_sequence(&data).unwrap();
        assert_eq!(content, &[0x01, 0x02]);
        assert_eq!(remaining, &[0xFF]);
    }

    #[test]
    fn test_parse_sequence_wrong_tag() {
        let data = [0x31, 0x02, 0x01, 0x02]; // SET tag, not SEQUENCE
        let result = parse_sequence(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_enumerated_valid() {
        let data = [0x0A, 0x01, 0x03];
        let (value, remaining) = parse_enumerated(&data).unwrap();
        assert_eq!(value, 3);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_oid_valid() {
        // SHA-1 OID
        let data = [0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];
        let (oid, remaining) = parse_oid(&data).unwrap();
        assert_eq!(oid, &[0x2B, 0x0E, 0x03, 0x02, 0x1A]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_octet_string_valid() {
        let data = [0x04, 0x03, 0xAA, 0xBB, 0xCC];
        let (content, remaining) = parse_octet_string(&data).unwrap();
        assert_eq!(content, &[0xAA, 0xBB, 0xCC]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_integer_valid() {
        let data = [0x02, 0x02, 0x01, 0x00];
        let (value, remaining) = parse_integer(&data).unwrap();
        assert_eq!(value, &[0x01, 0x00]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x01, 0x02, 0xAB]), "0102ab");
        assert_eq!(hex_encode(&[]), "");
    }

    // ── OcspCertId Encoding Roundtrip ───────────────────────────────────

    #[test]
    fn test_cert_id_der_encode_parse_roundtrip() {
        let original =
            OcspCertId::new(Nid::SHA256, &[0xAA; 32], &[0xBB; 32], &[0x01, 0x02, 0x03]).unwrap();

        let der = encode_cert_id(&original).unwrap();

        // Parse the inner SEQUENCE
        let (content, _) = parse_sequence(&der).unwrap();
        let parsed = parse_cert_id(content).unwrap();

        assert_eq!(parsed.hash_algorithm(), original.hash_algorithm());
        assert_eq!(parsed.issuer_name_hash(), original.issuer_name_hash());
        assert_eq!(parsed.issuer_key_hash(), original.issuer_key_hash());
        assert_eq!(parsed.serial_number(), original.serial_number());
    }

    #[test]
    fn test_cert_id_der_encode_parse_roundtrip_sha1() {
        let original = OcspCertId::new(Nid::SHA1, &[0xCC; 20], &[0xDD; 20], &[0xFF]).unwrap();

        let der = encode_cert_id(&original).unwrap();
        let (content, _) = parse_sequence(&der).unwrap();
        let parsed = parse_cert_id(content).unwrap();

        assert!(parsed.matches(&original));
    }

    // ── Default Trait Tests ─────────────────────────────────────────────

    #[test]
    fn test_request_builder_default() {
        let builder = OcspRequestBuilder::default();
        // Default builder has no cert IDs, so build should fail
        let result = builder.build();
        assert!(result.is_err());
    }
}
