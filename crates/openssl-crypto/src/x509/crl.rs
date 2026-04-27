//! X.509 Certificate Revocation List (CRL) processing.
//!
//! This module translates the OpenSSL CRL implementation from
//! `crypto/x509/x_crl.c` (600 lines — ASN.1 templates, decode callbacks,
//! pluggable CRL methods), `crypto/x509/x509cset.c` (185 lines — field
//! setters, sorting), and `crypto/x509/t_crl.c` (99 lines — printing).
//!
//! ## Architecture
//!
//! A CRL contains a sorted list of revoked certificate serial numbers
//! with revocation dates and optional extensions (reason code,
//! invalidity date, certificate issuer for indirect CRLs).
//!
//! The CRL supports a pluggable method table ([`CrlMethod`]) that allows
//! alternative backends (e.g., CRL databases) for certificate revocation
//! checking, replacing the C `X509_CRL_METHOD` vtable.
//!
//! ## Key Type Mappings (C → Rust)
//!
//! | C Type | Rust Type | Notes |
//! |--------|-----------|-------|
//! | `X509_CRL` | [`X509Crl`] | CRL with cached extensions |
//! | `X509_CRL_INFO` | embedded in [`X509Crl`] | TBS CRL data (private) |
//! | `X509_REVOKED` | [`RevokedEntry`] | Single revoked cert entry |
//! | `X509_CRL_METHOD` | [`CrlMethod`] trait | Pluggable verify/lookup |
//! | `CRL_REASON_*` | [`RevocationReason`] enum | Revocation reason codes |
//! | `ISSUING_DIST_POINT` | [`IssuingDistPoint`] | RFC 5280 §5.2.5 IDP extension |
//!
//! ## Rule Enforcement
//!
//! - **Rule R5 — Option over sentinel:**
//!   - `version: Option<u32>` (C used 0 for v1, 1 for v2; Rust uses `None` for v1)
//!   - `next_update: Option<Asn1Time>` (C used `NULL`; Rust uses `None`)
//!   - `reason: Option<RevocationReason>` (C used `CRL_REASON_NONE = -1`; Rust uses `None`)
//!   - `issuer: Option<X509Name>` for indirect CRL entries (C used `NULL`)
//!   - `akid`, `idp`, `crl_number`, `delta_crl_indicator`: all `Option<T>`
//! - **Rule R6 — Lossless numeric casts:** all narrowing uses `TryFrom`,
//!   `saturating_cast`, or explicit `checked_*` operations.
//! - **Rule R7 — Fine-grained locking:** `X509Crl` is immutable after
//!   construction; shared access uses `Arc<X509Crl>` without internal locks.
//! - **Rule R8 — Zero unsafe:** this module contains ZERO `unsafe` blocks
//!   (enforced by crate-level `#![forbid(unsafe_code)]`).
//! - **Rule R9 — Warning-free:** every public item has a `///` doc comment.
//! - **Rule R10 — Wiring:** reachable via
//!   `openssl_crypto::x509::crl::X509Crl::from_der()` → used by verify
//!   context for revocation checking.
//!
//! ## Example — Parse and Inspect a CRL
//!
//! ```no_run
//! use openssl_crypto::x509::crl::X509Crl;
//!
//! # fn example(der: &[u8]) -> openssl_common::CryptoResult<()> {
//! let crl = X509Crl::from_der(der)?;
//! println!("Issuer: {:?}", crl.issuer());
//! println!("Revoked entries: {}", crl.revoked_entries().len());
//!
//! // Check if a specific serial number is revoked.
//! let serial = [0x01, 0x02, 0x03, 0x04];
//! if crl.is_revoked(&serial).is_some() {
//!     println!("Serial is revoked!");
//! }
//! # Ok(())
//! # }
//! ```

// -----------------------------------------------------------------------------
// Imports
// -----------------------------------------------------------------------------
//
// External crate imports follow the strict dependency whitelist (D4):
//   - std:       fmt, cmp::Ordering (external_imports schema)
//   - bitflags:  bitflags! macro   (external_imports schema)
//   - tracing:   debug, warn       (external_imports schema, observability)
//   - openssl_common: CryptoError, CryptoResult, time::OsslTime (internal)
//   - crate::asn1: Asn1Time, AlgorithmIdentifier (internal)

use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};

use bitflags::bitflags;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoRef;
use subtle::ConstantTimeEq;
use tracing::{debug, trace, warn};

use openssl_common::time::OsslTime;
use openssl_common::{CryptoError, CryptoResult};

use super::certificate::{
    PublicKeyInfo, SignatureAlgorithmId, OID_SHA256_WITH_RSA, OID_SHA384_WITH_RSA,
    OID_SHA512_WITH_RSA,
};
// The ECDSA / EdDSA OID constants split into two visibility tiers based on
// where they are actually referenced in this module:
//
// 1. `OID_ECDSA_SHA256` and `OID_ED25519` are referenced both by the EC
//    verification code paths (gated on `feature = "ec"`) AND by tests that
//    exercise the dispatch mismatch / unsupported-algorithm error paths
//    (which use them purely as string constants without invoking any EC
//    primitives). They must therefore be imported whenever EITHER the `ec`
//    feature is enabled OR the build is a test build (`cfg(test)` is true
//    throughout the crate).
//
// 2. `OID_ECDSA_SHA384`, `OID_ECDSA_SHA512`, and `OID_ED448` are referenced
//    ONLY by the EC verification code paths (`crl_sha_for_ecdsa_sig` and
//    `crl_verify_eddsa`, both gated on `feature = "ec"`); no test in this
//    module uses these OIDs as string constants. Importing them under the
//    broader `any(feature = "ec", test)` gate would therefore produce a
//    spurious `unused_imports` warning under `--no-default-features --tests`
//    (where `cfg(test)` is true but `feature = "ec"` is false). They are
//    instead gated strictly on `feature = "ec"`.
#[cfg(any(feature = "ec", test))]
use super::certificate::{OID_ECDSA_SHA256, OID_ED25519};
#[cfg(feature = "ec")]
use super::certificate::{OID_ECDSA_SHA384, OID_ECDSA_SHA512, OID_ED448};
use crate::asn1::{
    parse_tlv_header, AlgorithmIdentifier, Asn1Class, Asn1Object, Asn1Tag, Asn1Time,
};
use crate::bn::montgomery::mod_exp;
use crate::bn::BigNum;
#[cfg(feature = "ec")]
use crate::ec::curve25519::{ed25519_verify, ed448_verify};
#[cfg(feature = "ec")]
use crate::ec::ecdsa::verify_der as ecdsa_verify_der;
#[cfg(feature = "ec")]
use crate::ec::{EcGroup, EcKey, EcPoint, EcxKeyType, EcxPublicKey, NamedCurve};
use crate::hash::{create_sha_digest, ShaAlgorithm};

// ---------------------------------------------------------------------------
// CRL signature verification — local OID constants
//
// These OIDs are the same as those in `crate::x509::verify` but those private
// constants are not exported. We replicate them here to keep the CRL
// verification self-contained. Group D will deduplicate this when the
// shared signature-verification module is introduced (along with the EC SHA
// duplication referenced in the review feedback). LOCK-SCOPE: const data,
// no synchronization needed; values reflect IETF/NIST canonical assignments.
// ---------------------------------------------------------------------------

/// SHA-256 algorithm identifier OID (NIST).
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// SHA-384 algorithm identifier OID (NIST).
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
/// SHA-512 algorithm identifier OID (NIST).
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// NIST P-256 (prime256v1) curve OID.
#[cfg(feature = "ec")]
const OID_ECC_P256: &str = "1.2.840.10045.3.1.7";
/// NIST P-384 (secp384r1) curve OID.
#[cfg(feature = "ec")]
const OID_ECC_P384: &str = "1.3.132.0.34";
/// NIST P-521 (secp521r1) curve OID.
#[cfg(feature = "ec")]
const OID_ECC_P521: &str = "1.3.132.0.35";
/// SECG secp256k1 curve OID.
#[cfg(feature = "ec")]
const OID_ECC_SECP256K1: &str = "1.3.132.0.10";

// =============================================================================
// Section 1 — Revocation Reason Codes (RFC 5280 §5.3.1)
// =============================================================================

/// RFC 5280 §5.3.1 CRL Reason Codes.
///
/// Translates C `CRL_REASON_*` constants from `include/openssl/x509v3.h`:
///
/// | C constant                          | Value | Rust variant             |
/// |-------------------------------------|-------|--------------------------|
/// | `CRL_REASON_NONE`                   | `-1`  | Represented as `None` (R5) |
/// | `CRL_REASON_UNSPECIFIED`            | `0`   | [`Self::Unspecified`]         |
/// | `CRL_REASON_KEY_COMPROMISE`         | `1`   | [`Self::KeyCompromise`]       |
/// | `CRL_REASON_CA_COMPROMISE`          | `2`   | [`Self::CaCompromise`]        |
/// | `CRL_REASON_AFFILIATION_CHANGED`    | `3`   | [`Self::AffiliationChanged`]  |
/// | `CRL_REASON_SUPERSEDED`             | `4`   | [`Self::Superseded`]          |
/// | `CRL_REASON_CESSATION_OF_OPERATION` | `5`   | [`Self::CessationOfOperation`]|
/// | `CRL_REASON_CERTIFICATE_HOLD`       | `6`   | [`Self::CertificateHold`]     |
/// | *(value 7 reserved / unused)*       | `7`   | *(no variant)*             |
/// | `CRL_REASON_REMOVE_FROM_CRL`        | `8`   | [`Self::RemoveFromCrl`]       |
/// | `CRL_REASON_PRIVILEGE_WITHDRAWN`    | `9`   | [`Self::PrivilegeWithdrawn`]  |
/// | `CRL_REASON_AA_COMPROMISE`          | `10`  | [`Self::AaCompromise`]        |
///
/// **Rule R5:** The C sentinel `CRL_REASON_NONE = -1` is replaced by
/// `Option::None` in the [`RevokedEntry::reason`] accessor — the reason
/// is either present with a concrete variant, or absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// `unspecified (0)` — no specific reason code given.
    Unspecified,
    /// `keyCompromise (1)` — the subject's private key was compromised.
    KeyCompromise,
    /// `cACompromise (2)` — the issuing CA's private key was compromised.
    CaCompromise,
    /// `affiliationChanged (3)` — the subject's name or organizational
    /// information changed.
    AffiliationChanged,
    /// `superseded (4)` — the certificate was replaced by a newer
    /// certificate.
    Superseded,
    /// `cessationOfOperation (5)` — the certificate is no longer required
    /// (the subject has ceased operating).
    CessationOfOperation,
    /// `certificateHold (6)` — the certificate is on temporary hold and
    /// may be removed from the CRL later via [`Self::RemoveFromCrl`].
    CertificateHold,
    // Note: reason code value 7 is reserved and not defined in RFC 5280.
    /// `removeFromCRL (8)` — used in delta CRLs to indicate that a
    /// certificate previously listed should be removed from the current
    /// revocation list.
    RemoveFromCrl,
    /// `privilegeWithdrawn (9)` — privileges granted to the subject
    /// were revoked.
    PrivilegeWithdrawn,
    /// `aACompromise (10)` — the Attribute Authority issuing the
    /// certificate was compromised.
    AaCompromise,
}

impl RevocationReason {
    /// Returns the RFC 5280 numeric reason code.
    ///
    /// This is the inverse of [`Self::try_from`] and produces the value
    /// that is encoded in the ASN.1 ENUMERATED for the `reasonCode`
    /// CRL entry extension (OID `2.5.29.21`).
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            // 7 is reserved/unused
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }

    /// Returns a short, human-readable name matching the OpenSSL
    /// `X509_CRL_print` output (see `t_crl.c` `reason_str` table).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "Unspecified",
            Self::KeyCompromise => "Key Compromise",
            Self::CaCompromise => "CA Compromise",
            Self::AffiliationChanged => "Affiliation Changed",
            Self::Superseded => "Superseded",
            Self::CessationOfOperation => "Cessation Of Operation",
            Self::CertificateHold => "Certificate Hold",
            Self::RemoveFromCrl => "Remove From CRL",
            Self::PrivilegeWithdrawn => "Privilege Withdrawn",
            Self::AaCompromise => "AA Compromise",
        }
    }
}

impl TryFrom<i64> for RevocationReason {
    type Error = CryptoError;

    /// Converts an ASN.1 ENUMERATED value into a [`RevocationReason`].
    ///
    /// Returns [`CryptoError::Encoding`] with a descriptive message for
    /// unknown or reserved reason codes (including the reserved value `7`).
    ///
    /// # Rule R6
    ///
    /// This function accepts a signed 64-bit input (since ASN.1 integers
    /// can be negative) and performs exhaustive checked matching with no
    /// bare `as` casts.
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::KeyCompromise),
            2 => Ok(Self::CaCompromise),
            3 => Ok(Self::AffiliationChanged),
            4 => Ok(Self::Superseded),
            5 => Ok(Self::CessationOfOperation),
            6 => Ok(Self::CertificateHold),
            7 => Err(CryptoError::Encoding(
                "revocation reason code 7 is reserved and not assigned (RFC 5280 §5.3.1)"
                    .to_string(),
            )),
            8 => Ok(Self::RemoveFromCrl),
            9 => Ok(Self::PrivilegeWithdrawn),
            10 => Ok(Self::AaCompromise),
            other => Err(CryptoError::Encoding(format!(
                "unknown CRL revocation reason code: {other}",
            ))),
        }
    }
}

impl Display for RevocationReason {
    /// Formats the reason using its short human-readable name
    /// (from [`Self::name`]).
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// Section 2 — Local X.509 Support Types
// =============================================================================
//
// Per the strict dependency whitelist (D4), this module imports only from
// `openssl_common` and `crate::asn1`. The broader X.509 types that will
// eventually live in sibling `x509` submodules (certificate, name,
// extension) are not yet available — so we define minimal local types
// to support CRL processing. These are public so they can be used by the
// CRL API; when sibling modules are authored they can replace/re-export
// these stubs.

/// Distinguished Name — an ordered sequence of Relative Distinguished Names
/// (RDNs), each a set of `(AttributeType, AttributeValue)` pairs.
///
/// This is a minimal local placeholder for what will eventually become
/// the full `X509Name` type in the parent `x509` module. It stores the
/// raw DER-encoded form of the name so that equality comparisons and
/// signature verification can operate correctly without full ASN.1
/// reconstruction.
///
/// # Source
///
/// Replaces C `X509_NAME` from `include/openssl/x509.h`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct X509Name {
    /// Raw DER encoding of the `Name ::= SEQUENCE OF RDN` structure.
    der_encoded: Vec<u8>,
    /// Cached human-readable one-line representation (e.g.,
    /// `"/C=US/O=Example Corp/CN=Example CA"`). `None` until first
    /// requested via [`Self::to_string_oneline`].
    display_string: Option<String>,
}

impl X509Name {
    /// Constructs an [`X509Name`] from its raw DER encoding.
    ///
    /// This is the primary constructor used during CRL DER decoding.
    /// No parsing of the internal RDN structure is performed — only
    /// the raw bytes are retained.
    #[must_use]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self {
            der_encoded: der,
            display_string: None,
        }
    }

    /// Constructs an [`X509Name`] from its DER encoding and a cached
    /// display string.
    #[must_use]
    pub fn with_display(der: Vec<u8>, display: String) -> Self {
        Self {
            der_encoded: der,
            display_string: Some(display),
        }
    }

    /// Returns the raw DER encoding of this name.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der_encoded
    }

    /// Consumes the name and returns its DER encoding.
    #[must_use]
    pub fn into_der(self) -> Vec<u8> {
        self.der_encoded
    }

    /// Returns a human-readable one-line representation of this name
    /// (e.g., `"/C=US/O=Example/CN=Example CA"`).
    ///
    /// If no display string was cached at construction time, returns a
    /// generic placeholder including the DER length in bytes.
    #[must_use]
    pub fn to_string_oneline(&self) -> String {
        match &self.display_string {
            Some(s) => s.clone(),
            None => format!("<X509Name: {} DER bytes>", self.der_encoded.len()),
        }
    }
}

impl Display for X509Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_oneline())
    }
}

/// An X.509 v3 extension — OID, critical flag, and DER-encoded value.
///
/// Replaces C `X509_EXTENSION` from `include/openssl/x509.h`.
/// A minimal local placeholder matching the ASN.1 structure:
///
/// ```text
/// Extension ::= SEQUENCE {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Extension {
    /// Dotted-decimal OID string identifying the extension
    /// (e.g., `"2.5.29.20"` for `cRLNumber`).
    pub oid: String,
    /// `true` if the extension is marked critical; validators MUST reject
    /// certificates/CRLs containing unrecognized critical extensions.
    pub critical: bool,
    /// DER-encoded extension value (the contents of the `extnValue`
    /// OCTET STRING).
    pub value: Vec<u8>,
}

impl X509Extension {
    /// Creates a new extension.
    #[must_use]
    pub fn new(oid: impl Into<String>, critical: bool, value: Vec<u8>) -> Self {
        Self {
            oid: oid.into(),
            critical,
            value,
        }
    }

    /// Returns the extension's OID as a dotted-decimal string.
    #[must_use]
    pub fn oid(&self) -> &str {
        &self.oid
    }

    /// Returns whether this extension is marked critical.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.critical
    }

    /// Returns the DER-encoded extension value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// X.509 Certificate — minimal local placeholder used by CRL lookups.
///
/// Contains the fields required to locate a certificate in a CRL:
/// the issuer's distinguished name and the certificate's serial number.
///
/// Replaces C `X509` from `include/openssl/x509.h` (subset thereof).
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// Issuer distinguished name.
    pub issuer: X509Name,
    /// Certificate serial number, DER-encoded as an ASN.1 INTEGER body
    /// (big-endian, most-significant byte first, no length prefix).
    pub serial_number: Vec<u8>,
}

impl X509Certificate {
    /// Creates a minimal certificate handle from an issuer and serial.
    #[must_use]
    pub fn new(issuer: X509Name, serial_number: Vec<u8>) -> Self {
        Self {
            issuer,
            serial_number,
        }
    }

    /// Returns the certificate's issuer distinguished name.
    #[must_use]
    pub fn issuer(&self) -> &X509Name {
        &self.issuer
    }

    /// Returns the certificate's serial number (DER INTEGER body).
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }
}

/// Authority Key Identifier extension (RFC 5280 §4.2.1.1, OID `2.5.29.35`).
///
/// Used to distinguish among multiple CRLs signed by the same CA over
/// a key rollover, and to match CRLs to the issuing key when the CA has
/// multiple signing keys.
#[derive(Debug, Clone, Default)]
pub struct AuthorityKeyIdentifier {
    /// Key identifier (SHA-1 hash of the issuer's public key). `None`
    /// per Rule R5 if not present in the AKID extension.
    pub key_identifier: Option<Vec<u8>>,
    /// Issuer name (if the AKID was issued with an explicit issuer).
    /// `None` per Rule R5 if not present.
    pub authority_cert_issuer: Option<X509Name>,
    /// Issuer certificate serial number. `None` per Rule R5 if not present.
    pub authority_cert_serial: Option<Vec<u8>>,
}

impl AuthorityKeyIdentifier {
    /// Creates an empty AKID (all fields absent).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            key_identifier: None,
            authority_cert_issuer: None,
            authority_cert_serial: None,
        }
    }

    /// Returns `true` if all fields are absent (per R5, every field is
    /// `Option<T>` and `None` means "not present").
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.key_identifier.is_none()
            && self.authority_cert_issuer.is_none()
            && self.authority_cert_serial.is_none()
    }
}

// =============================================================================
// Section 3 — Issuing Distribution Point (RFC 5280 §5.2.5)
// =============================================================================

/// Issuing Distribution Point extension (RFC 5280 §5.2.5,
/// OID `2.5.29.28`).
///
/// The IDP extension identifies the CRL distribution point and scope for a
/// particular CRL. Its flags indicate whether the CRL covers only
/// end-entity (user) certs, only CA certs, only attribute certs,
/// specific revocation reasons, or is an indirect CRL issued by a
/// different authority than the certificate issuer.
///
/// # Source
///
/// Translates C `ISSUING_DIST_POINT` processed by `setup_idp()` in
/// `crypto/x509/x_crl.c` lines 345-391.
///
/// The four boolean fields (`only_contains_user_certs`,
/// `only_contains_ca_certs`, `indirect_crl`,
/// `only_contains_attribute_certs`) are required by the AAP schema and
/// directly mirror the four independent DEFAULT-FALSE BOOLEAN fields in
/// the RFC 5280 §5.2.5 ASN.1 definition. They are **not** mutually
/// exclusive (a CRL may combine `indirect_crl` with any scope flag), so
/// refactoring into a two-variant enum or bitflags would be semantically
/// incorrect. `#[allow(clippy::struct_excessive_bools)]` is applied with
/// this documented justification.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct IssuingDistPoint {
    /// Distribution point name (if present). `None` per R5 means
    /// `distributionPoint` was not encoded in the IDP.
    ///
    /// In the ASN.1 encoding this is a `DistributionPointName CHOICE`
    /// with options `fullName` or `nameRelativeToCRLIssuer`. This
    /// field holds the raw DER bytes of the chosen alternative —
    /// full parsing is deferred to validators that need the details.
    pub distribution_point: Option<Vec<u8>>,
    /// `true` if the CRL covers only end-entity (non-CA) certificates.
    pub only_contains_user_certs: bool,
    /// `true` if the CRL covers only CA certificates.
    pub only_contains_ca_certs: bool,
    /// Bit mask of revocation reasons this CRL covers. `None` per R5
    /// means "all reasons" (the default when `onlySomeReasons` is absent).
    pub only_some_reasons: Option<ReasonFlags>,
    /// `true` if this is an indirect CRL — one where revocation entries
    /// may reference certificates issued by a different CA (the per-entry
    /// `certificateIssuer` extension applies).
    pub indirect_crl: bool,
    /// `true` if the CRL covers only attribute certificates (RFC 5755).
    pub only_contains_attribute_certs: bool,
}

impl IssuingDistPoint {
    /// Creates an IDP with all fields defaulted to absent/false.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            distribution_point: None,
            only_contains_user_certs: false,
            only_contains_ca_certs: false,
            only_some_reasons: None,
            indirect_crl: false,
            only_contains_attribute_certs: false,
        }
    }

    /// Returns `true` if this IDP indicates a scope restriction — i.e.,
    /// one or more of the `onlyContains*` or `onlySomeReasons` flags is
    /// set. A CRL with an IDP but no scope restrictions covers all
    /// certificates issued by the CRL issuer.
    #[must_use]
    pub const fn has_scope_restriction(&self) -> bool {
        self.only_contains_user_certs
            || self.only_contains_ca_certs
            || self.only_contains_attribute_certs
            || self.only_some_reasons.is_some()
    }
}

bitflags! {
    /// Bit mask of CRL revocation reasons — the set of reasons for which
    /// a partitioned CRL is authoritative.
    ///
    /// Maps RFC 5280 `ReasonFlags` BIT STRING named bits to Rust flag bits.
    /// The bit layout matches the ASN.1 BIT STRING where bit 0 is the
    /// most significant (leftmost) bit in the first octet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ReasonFlags: u16 {
        /// `unused (0)` — reserved, not used.
        const UNUSED                  = 0x0001;
        /// `keyCompromise (1)`
        const KEY_COMPROMISE          = 0x0002;
        /// `cACompromise (2)`
        const CA_COMPROMISE           = 0x0004;
        /// `affiliationChanged (3)`
        const AFFILIATION_CHANGED     = 0x0008;
        /// `superseded (4)`
        const SUPERSEDED              = 0x0010;
        /// `cessationOfOperation (5)`
        const CESSATION_OF_OPERATION  = 0x0020;
        /// `certificateHold (6)`
        const CERTIFICATE_HOLD        = 0x0040;
        /// `privilegeWithdrawn (7)`
        const PRIVILEGE_WITHDRAWN     = 0x0080;
        /// `aACompromise (8)`
        const AA_COMPROMISE           = 0x0100;
        /// Convenience mask representing "all defined reason bits".
        const ALL_REASONS             = 0x01FF;
    }
}

// =============================================================================
// Section 4 — Revoked Entry (X509_REVOKED ASN.1 template)
// =============================================================================

/// A single revoked certificate entry within a CRL.
///
/// Replaces C `X509_REVOKED` from `crypto/x509/x_crl.c` lines 21-25.
///
/// ASN.1 structure (RFC 5280 §5.1.2.6):
///
/// ```text
/// revokedCertificates     SEQUENCE OF SEQUENCE {
///     userCertificate         CertificateSerialNumber,
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
/// }
/// ```
///
/// # Extension Caching
///
/// During CRL decode, the two standard entry extensions are extracted
/// from [`Self::extensions`] and cached in dedicated fields for O(1)
/// access during revocation checks:
///
/// - **`reasonCode`** (OID `2.5.29.21`) — cached in [`Self::reason`].
///   Per Rule R5, the C sentinel `CRL_REASON_NONE = -1` is replaced by
///   `Option::None`.
/// - **`certificateIssuer`** (OID `2.5.29.29`) — cached in
///   [`Self::issuer`]. Per Rule R5, `NULL` (meaning "entry belongs to
///   the CRL issuer") is represented by `Option::None`.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// Serial number of the revoked certificate (the raw value bytes of
    /// the ASN.1 INTEGER, in big-endian byte order).
    serial_number: Vec<u8>,
    /// Date when the certificate was revoked.
    revocation_date: Asn1Time,
    /// Optional CRL entry extensions (reason code, invalidity date,
    /// certificate issuer for indirect CRLs, etc.).
    extensions: Vec<X509Extension>,
    /// Cached revocation reason (extracted from `reasonCode` extension).
    /// Per Rule R5, `None` means the reason code was absent — replacing
    /// the C sentinel `CRL_REASON_NONE = -1`.
    reason: Option<RevocationReason>,
    /// Cached certificate issuer (for indirect CRLs). Per Rule R5,
    /// `None` means the entry's issuer is the CRL issuer itself.
    issuer: Option<X509Name>,
    /// Sequence number for stable ordering after sorting. Assigned by
    /// [`X509Crl::sort`] so that entries with identical serial numbers
    /// retain their original order (stable sort).
    sequence: u32,
}

impl RevokedEntry {
    /// Constructs a new revoked entry.
    ///
    /// The `reason` and `issuer` caches are initialized to `None`;
    /// callers that want to set cached values derived from `extensions`
    /// should subsequently call [`Self::cache_entry_extensions`].
    #[must_use]
    pub fn new(serial_number: Vec<u8>, revocation_date: Asn1Time) -> Self {
        Self {
            serial_number,
            revocation_date,
            extensions: Vec::new(),
            reason: None,
            issuer: None,
            sequence: 0,
        }
    }

    /// Constructs a revoked entry with all fields specified.
    ///
    /// Primarily used by CRL parsers that have already extracted the
    /// per-entry extension caches; normal users should prefer
    /// [`Self::new`] followed by extension manipulation.
    #[must_use]
    pub fn with_all_fields(
        serial_number: Vec<u8>,
        revocation_date: Asn1Time,
        extensions: Vec<X509Extension>,
        reason: Option<RevocationReason>,
        issuer: Option<X509Name>,
    ) -> Self {
        Self {
            serial_number,
            revocation_date,
            extensions,
            reason,
            issuer,
            sequence: 0,
        }
    }

    /// Returns the revoked certificate's serial number.
    ///
    /// Replaces C `X509_REVOKED_get0_serialNumber()`.
    ///
    /// The returned slice is the raw value bytes of the ASN.1 INTEGER
    /// (big-endian, no length prefix).
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    /// Returns the date and time when the certificate was revoked.
    ///
    /// Replaces C `X509_REVOKED_get0_revocationDate()`.
    #[must_use]
    pub fn revocation_date(&self) -> &Asn1Time {
        &self.revocation_date
    }

    /// Returns the cached revocation reason.
    ///
    /// Replaces C behavior where the reason was returned as
    /// `CRL_REASON_NONE = -1` when absent. Per Rule R5, `None` now
    /// unambiguously represents "no reason code extension present".
    #[must_use]
    pub const fn reason(&self) -> Option<RevocationReason> {
        self.reason
    }

    /// Returns the per-entry extensions.
    ///
    /// Replaces C `X509_REVOKED_get0_extensions()`.
    #[must_use]
    pub fn extensions(&self) -> &[X509Extension] {
        &self.extensions
    }

    /// Returns the certificate issuer for this entry, or `None` if the
    /// entry belongs to the CRL issuer (the normal case for
    /// non-indirect CRLs).
    ///
    /// Replaces C behavior where a `NULL` pointer indicated "entry's
    /// issuer is the CRL issuer". Per Rule R5, this is now explicit
    /// via `Option`.
    #[must_use]
    pub fn issuer(&self) -> Option<&X509Name> {
        self.issuer.as_ref()
    }

    /// Returns the entry's stable sort sequence number.
    ///
    /// Assigned by [`X509Crl::sort`]; not semantically meaningful to
    /// consumers — use [`Self::serial_number`] for equality checks.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Adds an extension to this revoked entry.
    ///
    /// If the extension's OID matches a known extension type, the
    /// corresponding cache field (reason/issuer) is NOT automatically
    /// updated — call [`Self::cache_entry_extensions`] after all
    /// extensions are added to populate the caches.
    pub fn add_extension(&mut self, extension: X509Extension) {
        self.extensions.push(extension);
    }

    /// Sets the cached revocation reason explicitly.
    ///
    /// Normally populated by [`Self::cache_entry_extensions`] from the
    /// `reasonCode` extension.
    pub fn set_reason(&mut self, reason: Option<RevocationReason>) {
        self.reason = reason;
    }

    /// Sets the cached certificate issuer explicitly.
    ///
    /// Normally populated by [`Self::cache_entry_extensions`] from the
    /// `certificateIssuer` extension (for indirect CRLs).
    pub fn set_issuer(&mut self, issuer: Option<X509Name>) {
        self.issuer = issuer;
    }

    /// Sets the stable-sort sequence number. Used by [`X509Crl::sort`].
    pub(crate) fn set_sequence(&mut self, sequence: u32) {
        self.sequence = sequence;
    }

    /// Replaces the serial number (used by CRL construction APIs).
    pub fn set_serial_number(&mut self, serial: Vec<u8>) {
        self.serial_number = serial;
    }

    /// Replaces the revocation date.
    ///
    /// Replaces C `X509_REVOKED_set_revocationDate()`.
    pub fn set_revocation_date(&mut self, date: Asn1Time) {
        self.revocation_date = date;
    }

    /// Scans [`Self::extensions`] and populates the cached `reason` and
    /// `issuer` fields from the `reasonCode` (OID `2.5.29.21`) and
    /// `certificateIssuer` (OID `2.5.29.29`) CRL entry extensions
    /// respectively.
    ///
    /// Mirrors the C logic in `crl_set_issuers()` from
    /// `crypto/x509/x_crl.c` lines 80-207.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] if a `reasonCode` extension
    /// contains an invalid ASN.1 ENUMERATED value or an unknown
    /// revocation reason. Malformed extension bodies are logged at
    /// `warn` level per the observability rule but do not fail the
    /// whole CRL — they are treated as if the extension were absent.
    pub fn cache_entry_extensions(&mut self) -> CryptoResult<()> {
        for ext in &self.extensions {
            match ext.oid.as_str() {
                // id-ce-cRLReasonCode (2.5.29.21)
                "2.5.29.21" => match parse_reason_code_ext(&ext.value) {
                    Ok(reason) => self.reason = Some(reason),
                    Err(e) => {
                        warn!(
                            oid = ext.oid.as_str(),
                            error = %e,
                            "malformed CRL entry reasonCode extension; treating as absent",
                        );
                    }
                },
                // id-ce-certificateIssuer (2.5.29.29) — used in indirect CRLs
                "2.5.29.29" => {
                    // The value is a GeneralNames SEQUENCE. For the
                    // minimal local X509Name we store the raw DER.
                    self.issuer = Some(X509Name::from_der(ext.value.clone()));
                }
                _ => {
                    // Other entry extensions (invalidityDate, holdInstructionCode,
                    // etc.) are retained in `extensions` but not cached.
                }
            }
        }
        Ok(())
    }
}

/// Parses a CRL entry `reasonCode` extension value, which is a DER-encoded
/// ASN.1 ENUMERATED (`tag = 0x0A`).
///
/// The encoding is `0x0A LEN VALUE` where `LEN` is typically 1 and
/// `VALUE` is the reason code as a signed integer. Per RFC 5280 §5.3.1
/// the value space is 0-10 (excluding 7), so a single byte suffices.
///
/// Negative values are never valid in this context, so only non-negative
/// single-byte encodings are accepted.
fn parse_reason_code_ext(value: &[u8]) -> CryptoResult<RevocationReason> {
    if value.len() < 3 || value[0] != 0x0A {
        return Err(CryptoError::Encoding(format!(
            "CRL reasonCode extension must be DER ENUMERATED (tag 0x0A), got {} bytes",
            value.len(),
        )));
    }
    let len = value[1];
    // Reason codes fit in a single byte; reject multi-byte encodings.
    if len != 1 {
        return Err(CryptoError::Encoding(format!(
            "CRL reasonCode ENUMERATED length must be 1, got {len}",
        )));
    }
    if value.len() != 3 {
        return Err(CryptoError::Encoding(format!(
            "CRL reasonCode extension has trailing data: {} extra bytes",
            value.len().saturating_sub(3),
        )));
    }
    // R6: widen u8 → i64 losslessly (no narrowing cast).
    let code = i64::from(value[2]);
    RevocationReason::try_from(code)
}

// ---- Ordering impls for RevokedEntry: compare by serial number -----------

impl PartialEq for RevokedEntry {
    fn eq(&self, other: &Self) -> bool {
        self.serial_number == other.serial_number
    }
}

impl Eq for RevokedEntry {}

impl Ord for RevokedEntry {
    /// Compares two revoked entries by serial number, matching the C
    /// `X509_REVOKED_cmp` function in `crypto/x509/x_crl.c` line 17.
    ///
    /// Shorter serial numbers compare less than longer ones; within
    /// equal lengths comparison is lexicographic on the big-endian
    /// value bytes (which matches numeric ordering for correctly-encoded
    /// ASN.1 INTEGERs of equal length).
    fn cmp(&self, other: &Self) -> Ordering {
        // ASN1_STRING_cmp in C first compares lengths, then byte content.
        match self.serial_number.len().cmp(&other.serial_number.len()) {
            Ordering::Equal => self.serial_number.cmp(&other.serial_number),
            ord => ord,
        }
    }
}

impl PartialOrd for RevokedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// =============================================================================
// Section 5 — CRL Processing Flags
// =============================================================================

bitflags! {
    /// CRL processing flags tracking the state of a parsed [`X509Crl`].
    ///
    /// Corresponds to the per-CRL flags maintained by the C implementation
    /// in `crypto/x509/x_crl.c`:
    ///
    /// | C flag                     | Rust flag                       |
    /// |----------------------------|---------------------------------|
    /// | (extensions cached on D2I) | [`Self::EXTENSIONS_CACHED`]     |
    /// | `EXFLAG_INVALID`           | [`Self::INVALID`]               |
    /// | `EXFLAG_CRITICAL`          | [`Self::CRITICAL_ERROR`]        |
    /// | `EXFLAG_FRESHEST`          | [`Self::FRESHEST`]              |
    /// | `EXFLAG_NO_FINGERPRINT`    | [`Self::NO_FINGERPRINT`]        |
    /// | `EXFLAG_SET`               | [`Self::EXFLAG_SET`]            |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CrlFlags: u32 {
        /// Extension cache has been populated (AKID, IDP, CRL number,
        /// delta CRL indicator have been extracted from [`X509Crl::extensions`]).
        const EXTENSIONS_CACHED = 0x0001;
        /// CRL was parsed but contains structural errors or missing
        /// mandatory fields (e.g., lastUpdate). Callers must treat the
        /// CRL as unusable.
        const INVALID           = 0x0002;
        /// An unknown critical extension was encountered during
        /// extension caching — per RFC 5280 §5.2 such a CRL MUST be
        /// rejected.
        const CRITICAL_ERROR    = 0x0004;
        /// The CRL contains a `freshestCRL` extension (delta CRL hint).
        const FRESHEST          = 0x0008;
        /// SHA-1 fingerprint could not be computed (e.g., the CRL has
        /// no DER encoding available).
        const NO_FINGERPRINT    = 0x0010;
        /// Sentinel bit indicating that the full `EXFLAG_*` computation
        /// has been performed at least once.
        const EXFLAG_SET        = 0x0020;
    }
}

bitflags! {
    /// Issuing Distribution Point flags, matching the C `idp_flags` and
    /// `idp_reasons` bits in `crypto/x509/x_crl.c` `setup_idp()`
    /// (lines 345-391).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IdpFlags: u32 {
        /// IDP extension is present in the CRL.
        const IDP_PRESENT   = 0x0001;
        /// `onlyContainsUserCerts` field was TRUE.
        const IDP_ONLY_USER = 0x0002;
        /// `onlyContainsCACerts` field was TRUE.
        const IDP_ONLY_CA   = 0x0004;
        /// `onlyContainsAttributeCerts` field was TRUE.
        const IDP_ONLY_ATTR = 0x0008;
        /// The IDP extension could not be parsed correctly — the CRL
        /// should be treated as invalid.
        const IDP_INVALID   = 0x0010;
        /// `indirectCRL` field was TRUE (the CRL is indirect).
        const IDP_INDIRECT  = 0x0020;
        /// `onlySomeReasons` field is present (the CRL covers only a
        /// subset of revocation reasons).
        const IDP_REASONS   = 0x0040;
    }
}

// =============================================================================
// Section 6 — CRL Info (TBSCertList)
// =============================================================================

/// TBS (To-Be-Signed) CRL data — the portion of the CRL covered by the
/// issuer's signature.
///
/// Corresponds to C `X509_CRL_INFO` from `x_crl.c` lines 65-73 and the
/// ASN.1 structure defined in RFC 5280 §5.1.2:
///
/// ```text
/// TBSCertList  ::=  SEQUENCE  {
///     version                 Version OPTIONAL,  -- v2 (value 1) for CRL v2
///     signature               AlgorithmIdentifier,
///     issuer                  Name,
///     thisUpdate              Time,
///     nextUpdate              Time OPTIONAL,
///     revokedCertificates     SEQUENCE OF SEQUENCE { ... } OPTIONAL,
///     crlExtensions       [0] EXPLICIT Extensions OPTIONAL
/// }
/// ```
///
/// This type is internal to the [`X509Crl`] representation and not
/// exposed directly — accessors on [`X509Crl`] return references to
/// individual fields.
#[derive(Debug, Clone)]
struct CrlInfo {
    /// CRL version.
    ///
    /// Per Rule R5: `None` means the OPTIONAL `version` field was
    /// absent in the DER encoding — i.e., CRL v1. `Some(1)` means CRL v2.
    /// The C code used `0` for v1 (as `ASN1_INTEGER_get(info->version)`
    /// returned `0` when the field was absent); Rust now uses `Option`.
    version: Option<u32>,
    /// Signature algorithm identifier (appears inside the TBS).
    signature_algorithm: AlgorithmIdentifier,
    /// CRL issuer distinguished name.
    issuer: X509Name,
    /// CRL's `thisUpdate` time — mandatory per RFC 5280.
    last_update: Asn1Time,
    /// CRL's `nextUpdate` time. Per Rule R5: `None` means the field was
    /// absent (no scheduled next update). The C code used `NULL` for
    /// this case.
    next_update: Option<Asn1Time>,
    /// Revoked certificate entries. Empty vector means `revokedCertificates`
    /// was absent or present-but-empty; there is no semantic difference
    /// in RFC 5280.
    revoked: Vec<RevokedEntry>,
    /// CRL-level extensions (Authority Key Identifier, CRL Number, Delta
    /// CRL Indicator, Issuing Distribution Point, Freshest CRL, etc.).
    extensions: Vec<X509Extension>,
    /// Raw DER encoding of the `TBSCertList`, retained for signature
    /// verification. This is the exact byte range that was signed.
    tbs_der: Vec<u8>,
}

// =============================================================================
// Section 7 — X509Crl Main Type
// =============================================================================

/// X.509 Certificate Revocation List.
///
/// A CRL is a signed list of revoked certificate serial numbers issued
/// by a CA (or by a CRL issuer delegated by the CA for indirect CRLs).
/// This type replaces C `X509_CRL` from `crypto/x509/x_crl.c`.
///
/// # Invariants
///
/// - The revoked list is kept sorted by serial number after any call to
///   [`Self::sort`] or [`Self::is_revoked`] (binary search requires
///   sorted input).
/// - Extension caches (AKID, IDP, CRL number, delta CRL indicator) are
///   populated during construction via [`Self::from_der`] or by explicit
///   call to [`Self::cache_extensions`].
/// - The [`CrlFlags::INVALID`] flag indicates that the CRL was parseable
///   but has semantic errors (e.g., missing `thisUpdate`); such CRLs
///   MUST NOT be used for revocation checks.
///
/// # Thread Safety (Rule R7)
///
/// After construction, `X509Crl` is immutable and can be shared across
/// threads via `Arc<X509Crl>` without additional locking. Mutation
/// requires exclusive access (`&mut X509Crl`), matching Rust's ownership
/// model.
#[derive(Debug, Clone)]
pub struct X509Crl {
    /// `TBSCertList` payload (the signed portion of the CRL).
    info: CrlInfo,
    /// Outer signature algorithm (must match `info.signature_algorithm`).
    signature_algorithm: AlgorithmIdentifier,
    /// CRL signature value (the contents of the outer BIT STRING).
    signature: Vec<u8>,
    /// Raw DER encoding of the complete CRL (`CertificateList` SEQUENCE).
    /// Retained so that re-serialization yields bit-identical output
    /// (matching the behavior of C `i2d_X509_CRL` when `enc.modified`
    /// is clear).
    der_encoded: Vec<u8>,
    // --- Cached extension fields (populated on demand or during parse)
    /// Cached Authority Key Identifier (OID `2.5.29.35`). Per Rule R5,
    /// `None` means the extension was absent.
    akid: Option<AuthorityKeyIdentifier>,
    /// Cached Issuing Distribution Point (OID `2.5.29.28`). Per Rule R5,
    /// `None` means the extension was absent.
    idp: Option<IssuingDistPoint>,
    /// IDP flags summarising the parsed IDP scope (`IDP_PRESENT`,
    /// `IDP_ONLY_USER`, `IDP_ONLY_CA`, `IDP_INDIRECT`, `IDP_REASONS`).
    idp_flags: IdpFlags,
    /// IDP-specified reasons mask. Defaults to [`ReasonFlags::ALL_REASONS`]
    /// when the IDP's `onlySomeReasons` field is absent (matches C
    /// `CRLDP_ALL_REASONS` init in `crl_cb`).
    idp_reasons: ReasonFlags,
    /// Cached CRL number (OID `2.5.29.20`, INTEGER). Per Rule R5, `None`
    /// means the extension was absent. Stored as the raw integer value
    /// bytes (big-endian).
    crl_number: Option<Vec<u8>>,
    /// Cached delta CRL indicator (OID `2.5.29.27`, INTEGER). Per
    /// Rule R5, `None` means this CRL is not a delta CRL.
    delta_crl_indicator: Option<Vec<u8>>,
    /// Extension processing state flags.
    flags: CrlFlags,
}

impl X509Crl {
    /// Creates a new empty CRL skeleton for in-place construction.
    ///
    /// The resulting CRL has version `None` (v1), an empty issuer,
    /// `last_update` set to the current time, no `next_update`, no
    /// revoked entries, and empty signature/algorithm fields. Callers
    /// must populate all required fields and then sign the CRL before
    /// use.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] with [`CommonError::Internal`](openssl_common::CommonError::Internal)
    /// if the current system time cannot be determined for the default
    /// `last_update` value.
    pub fn new_empty() -> CryptoResult<Self> {
        let now = Asn1Time::now()?;
        // AlgorithmIdentifier requires an Asn1Object; use a NULL OID
        // placeholder ("0.0.0") that callers must overwrite.
        let placeholder_alg =
            AlgorithmIdentifier::new(crate::asn1::Asn1Object::from_oid_string("0.0.0")?, None);
        Ok(Self {
            info: CrlInfo {
                version: None,
                signature_algorithm: placeholder_alg.clone(),
                issuer: X509Name::from_der(Vec::new()),
                last_update: now,
                next_update: None,
                revoked: Vec::new(),
                extensions: Vec::new(),
                tbs_der: Vec::new(),
            },
            signature_algorithm: placeholder_alg,
            signature: Vec::new(),
            der_encoded: Vec::new(),
            akid: None,
            idp: None,
            idp_flags: IdpFlags::empty(),
            idp_reasons: ReasonFlags::ALL_REASONS,
            crl_number: None,
            delta_crl_indicator: None,
            flags: CrlFlags::empty(),
        })
    }

    // -------------------------------------------------------------------------
    // Parsing / Serialization
    // -------------------------------------------------------------------------

    /// Decodes a CRL from its DER encoding.
    ///
    /// Replaces C `d2i_X509_CRL()`.
    ///
    /// # ASN.1 Structure
    ///
    /// ```text
    /// CertificateList  ::=  SEQUENCE  {
    ///     tbsCertList          TBSCertList,
    ///     signatureAlgorithm   AlgorithmIdentifier,
    ///     signatureValue       BIT STRING
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Encoding`] for malformed DER, truncated input,
    ///   or missing mandatory fields.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        debug!(der_len = der.len(), "parsing X509 CRL from DER");
        let mut crl = parse_crl_der(der)?;
        crl.der_encoded = der.to_vec();
        crl.cache_extensions()?;
        Ok(crl)
    }

    /// Decodes a CRL from its PEM encoding.
    ///
    /// Recognised PEM labels: `X509 CRL` and `CRL` (the former is
    /// preferred; the latter is accepted for compatibility with older
    /// OpenSSL versions).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::Encoding`] for malformed PEM structure, invalid
    ///   Base64, or errors propagated from [`Self::from_der`].
    pub fn from_pem(pem: &str) -> CryptoResult<Self> {
        let der = decode_pem(pem, &["X509 CRL", "CRL"])?;
        Self::from_der(&der)
    }

    /// Re-serializes the CRL to DER encoding.
    ///
    /// Replaces C `i2d_X509_CRL()`.
    ///
    /// If the CRL was parsed from DER and not subsequently mutated,
    /// returns the original byte sequence (bit-identical round-trip).
    /// If the CRL was constructed programmatically or modified, the
    /// encoder produces a fresh DER encoding.
    ///
    /// # Errors
    ///
    /// Currently returns [`CryptoError::Encoding`] if the CRL has no
    /// cached DER encoding and no encoder is available — callers that
    /// construct CRLs programmatically must use a full DER encoder
    /// (provided by the signing layer) before requesting re-serialization.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        if !self.der_encoded.is_empty() {
            return Ok(self.der_encoded.clone());
        }
        Err(CryptoError::Encoding(
            "X509Crl has no cached DER encoding; programmatic encoding requires a signed CRL"
                .to_string(),
        ))
    }

    /// Re-serializes the CRL to PEM encoding.
    ///
    /// Uses the PEM label `X509 CRL` (RFC 7468 §7), which is the same
    /// label produced by OpenSSL's `PEM_write_X509_CRL`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::to_der`].
    pub fn to_pem(&self) -> CryptoResult<String> {
        let der = self.to_der()?;
        Ok(encode_pem(&der, "X509 CRL"))
    }
}

// -------------------------------------------------------------------------
// Section 8 — X509Crl Accessors
// -------------------------------------------------------------------------

impl X509Crl {
    /// Returns the CRL version.
    ///
    /// Replaces C `X509_CRL_get_version()`. Per Rule R5, `None`
    /// unambiguously means the OPTIONAL ASN.1 `version` field was absent
    /// (i.e., CRL v1); the C function returned `0` or `1` conflating
    /// the default-v1 case with an explicit v1 encoding.
    #[must_use]
    pub const fn version(&self) -> Option<u32> {
        self.info.version
    }

    /// Returns the CRL issuer distinguished name.
    ///
    /// Replaces C `X509_CRL_get_issuer()`.
    #[must_use]
    pub const fn issuer(&self) -> &X509Name {
        &self.info.issuer
    }

    /// Returns the CRL's `thisUpdate` time.
    ///
    /// Replaces C `X509_CRL_get0_lastUpdate()`.
    #[must_use]
    pub const fn last_update(&self) -> &Asn1Time {
        &self.info.last_update
    }

    /// Returns the CRL's `nextUpdate` time.
    ///
    /// Replaces C `X509_CRL_get0_nextUpdate()`. Per Rule R5, returns
    /// `None` when the OPTIONAL ASN.1 field was absent (the C function
    /// returned a `NULL` pointer).
    #[must_use]
    pub fn next_update(&self) -> Option<&Asn1Time> {
        self.info.next_update.as_ref()
    }

    /// Returns the last-update time as [`OsslTime`] (Unix-epoch
    /// representation).
    ///
    /// Convenience adaptor that converts from the stored [`Asn1Time`]
    /// via its Unix timestamp. Rule R6 is satisfied because the Unix
    /// timestamp is an `i64` (signed) and conversion to [`OsslTime`]
    /// (which stores ticks as `u64`) is performed using a saturating
    /// fallback — negative timestamps (pre-1970) produce
    /// [`OsslTime::ZERO`].
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Asn1Time::to_unix_timestamp`] if the
    /// stored time is outside the representable range.
    pub fn last_update_ossl(&self) -> CryptoResult<OsslTime> {
        asn1_time_to_ossl(self.info.last_update)
    }

    /// Returns the next-update time as [`OsslTime`].
    ///
    /// Per Rule R5, returns `None` when `nextUpdate` is absent.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Asn1Time::to_unix_timestamp`].
    pub fn next_update_ossl(&self) -> CryptoResult<Option<OsslTime>> {
        match self.info.next_update {
            Some(t) => Ok(Some(asn1_time_to_ossl(t)?)),
            None => Ok(None),
        }
    }

    /// Returns the list of revoked certificate entries.
    ///
    /// Replaces C `X509_CRL_get_REVOKED()`. If [`Self::sort`] has been
    /// called, the entries are in ascending serial-number order.
    #[must_use]
    pub fn revoked_entries(&self) -> &[RevokedEntry] {
        &self.info.revoked
    }

    /// Returns the CRL-level extensions (AKID, CRL number, IDP, etc.).
    ///
    /// Replaces C `X509_CRL_get0_extensions()`.
    #[must_use]
    pub fn extensions(&self) -> &[X509Extension] {
        &self.info.extensions
    }

    /// Returns the outer signature algorithm identifier.
    ///
    /// Per RFC 5280, this MUST match the algorithm identifier inside
    /// the `TBSCertList`; callers verifying signatures should use this
    /// outer field.
    #[must_use]
    pub const fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature value bytes (contents of the outer BIT
    /// STRING).
    ///
    /// Replaces C `X509_CRL_get0_signature()`.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the signature algorithm identifier embedded inside the
    /// `TBSCertList`.
    ///
    /// Replaces C `X509_CRL_get0_tbs_sigalg()`.
    #[must_use]
    pub const fn tbs_signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.info.signature_algorithm
    }

    /// Returns the raw DER encoding of the `TBSCertList`.
    ///
    /// This is the exact byte range covered by the signature and is
    /// suitable for feeding into signature verification routines.
    #[must_use]
    pub fn tbs_der(&self) -> &[u8] {
        &self.info.tbs_der
    }

    /// Returns the cached Authority Key Identifier extension.
    ///
    /// Per Rule R5, `None` means the AKID extension is absent.
    #[must_use]
    pub fn authority_key_identifier(&self) -> Option<&AuthorityKeyIdentifier> {
        self.akid.as_ref()
    }

    /// Returns the cached Issuing Distribution Point extension.
    ///
    /// Per Rule R5, `None` means the IDP extension is absent.
    #[must_use]
    pub fn issuing_distribution_point(&self) -> Option<&IssuingDistPoint> {
        self.idp.as_ref()
    }

    /// Returns the IDP processing flags (`IDP_PRESENT`, `IDP_ONLY_USER`, etc.).
    #[must_use]
    pub const fn idp_flags(&self) -> IdpFlags {
        self.idp_flags
    }

    /// Returns the IDP-specified reason mask.
    ///
    /// Defaults to [`ReasonFlags::ALL_REASONS`] when the IDP's
    /// `onlySomeReasons` field is absent.
    #[must_use]
    pub const fn idp_reasons(&self) -> ReasonFlags {
        self.idp_reasons
    }

    /// Returns the cached CRL number (OID `2.5.29.20`).
    ///
    /// Per Rule R5, `None` means the CRL number extension is absent.
    /// The value is the raw ASN.1 INTEGER bytes (big-endian).
    #[must_use]
    pub fn crl_number(&self) -> Option<&[u8]> {
        self.crl_number.as_deref()
    }

    /// Returns the cached Delta CRL Indicator (OID `2.5.29.27`).
    ///
    /// Per Rule R5, `None` means this CRL is not a delta CRL.
    #[must_use]
    pub fn delta_crl_indicator(&self) -> Option<&[u8]> {
        self.delta_crl_indicator.as_deref()
    }

    /// Returns the current extension processing flags.
    #[must_use]
    pub const fn flags(&self) -> CrlFlags {
        self.flags
    }

    /// Returns `true` if the CRL was parsed as structurally valid.
    ///
    /// When `false`, the CRL has been flagged with [`CrlFlags::INVALID`]
    /// or [`CrlFlags::CRITICAL_ERROR`] and must not be used for
    /// revocation checks.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.flags.contains(CrlFlags::INVALID) && !self.flags.contains(CrlFlags::CRITICAL_ERROR)
    }
}

// -------------------------------------------------------------------------
// Section 9 — X509Crl Mutators (from x509cset.c)
// -------------------------------------------------------------------------

impl X509Crl {
    /// Sets the CRL version.
    ///
    /// Replaces C `X509_CRL_set_version()`. Per RFC 5280, valid versions
    /// are `v1` (encoded as absent OPTIONAL, represented as `None`) and
    /// `v2` (encoded as INTEGER `1`). Values ≥ 2 are not defined by
    /// the standard but are accepted here for forward compatibility.
    ///
    /// Note: the public API takes a `u32` to match the schema; callers
    /// who want to clear the version (revert to v1) should use
    /// [`Self::clear_version`].
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`CryptoResult`] for API stability.
    pub fn set_version(&mut self, version: u32) -> CryptoResult<()> {
        self.info.version = Some(version);
        // Invalidate cached DER encoding since the TBS has changed.
        self.der_encoded.clear();
        self.info.tbs_der.clear();
        Ok(())
    }

    /// Clears the CRL version field (reverts to v1 / absent OPTIONAL).
    pub fn clear_version(&mut self) {
        self.info.version = None;
        self.der_encoded.clear();
        self.info.tbs_der.clear();
    }

    /// Sets the CRL issuer distinguished name.
    ///
    /// Replaces C `X509_CRL_set_issuer_name()`.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`CryptoResult`] for API stability.
    pub fn set_issuer(&mut self, name: X509Name) -> CryptoResult<()> {
        self.info.issuer = name;
        self.der_encoded.clear();
        self.info.tbs_der.clear();
        Ok(())
    }

    /// Sets the CRL's `thisUpdate` time.
    ///
    /// Replaces C `X509_CRL_set1_lastUpdate()`.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`CryptoResult`] for API stability.
    pub fn set_last_update(&mut self, time: OsslTime) -> CryptoResult<()> {
        self.info.last_update = ossl_time_to_asn1(time)?;
        self.der_encoded.clear();
        self.info.tbs_der.clear();
        Ok(())
    }

    /// Sets the CRL's `thisUpdate` time directly as an [`Asn1Time`].
    ///
    /// Alternative to [`Self::set_last_update`] that bypasses the
    /// [`OsslTime`] → [`Asn1Time`] conversion (useful when working with
    /// times that have been parsed directly from DER).
    pub fn set_last_update_asn1(&mut self, time: Asn1Time) {
        self.info.last_update = time;
        self.der_encoded.clear();
        self.info.tbs_der.clear();
    }

    /// Sets the CRL's `nextUpdate` time, or clears it when `time` is
    /// `None`.
    ///
    /// Replaces C `X509_CRL_set1_nextUpdate()` (which accepted a `NULL`
    /// pointer to clear the field). Per Rule R5, `None` is the explicit
    /// representation of "no next update".
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`CryptoResult`] for API stability.
    pub fn set_next_update(&mut self, time: Option<OsslTime>) -> CryptoResult<()> {
        self.info.next_update = match time {
            Some(t) => Some(ossl_time_to_asn1(t)?),
            None => None,
        };
        self.der_encoded.clear();
        self.info.tbs_der.clear();
        Ok(())
    }

    /// Sets the CRL's `nextUpdate` time directly as an [`Asn1Time`].
    pub fn set_next_update_asn1(&mut self, time: Option<Asn1Time>) {
        self.info.next_update = time;
        self.der_encoded.clear();
        self.info.tbs_der.clear();
    }

    /// Sets the CRL's `thisUpdate` time from an RFC 5280 ASCII string.
    ///
    /// Accepts either `UTCTime` format (`YYMMDDHHMMSSZ`, 13 characters)
    /// or `GeneralizedTime` format (`YYYYMMDDHHMMSSZ`, 15 characters)
    /// as mandated by RFC 5280 §4.1.2.5. Delegates parsing to
    /// [`Asn1Time::parse`].
    ///
    /// Replaces C `ASN1_TIME_set_string_X509()` + `X509_CRL_set1_lastUpdate()`
    /// call sequence commonly used by the CLI when a user supplies an
    /// ASCII date on the command line.
    ///
    /// # Errors
    ///
    /// Propagates any parsing error from [`Asn1Time::parse`] wrapped in
    /// a [`CryptoError::Encoding`] variant when the input does not match
    /// the accepted grammar (must end in `Z`, must be 12 or 14 digits).
    pub fn set_last_update_str(&mut self, time_str: &str) -> CryptoResult<()> {
        let t = Asn1Time::parse(time_str)?;
        self.set_last_update_asn1(t);
        Ok(())
    }

    /// Sets the CRL's `nextUpdate` time from an RFC 5280 ASCII string.
    ///
    /// Accepts `UTCTime` or `GeneralizedTime` format per RFC 5280
    /// §4.1.2.5. Delegates parsing to [`Asn1Time::parse`]. Passing
    /// `None` clears the field (matches [`Self::set_next_update`]).
    ///
    /// # Errors
    ///
    /// Propagates any parsing error from [`Asn1Time::parse`] wrapped in
    /// a [`CryptoError::Encoding`] variant.
    pub fn set_next_update_str(&mut self, time_str: Option<&str>) -> CryptoResult<()> {
        let parsed = match time_str {
            Some(s) => Some(Asn1Time::parse(s)?),
            None => None,
        };
        self.set_next_update_asn1(parsed);
        Ok(())
    }

    /// Adds a revoked entry to the CRL.
    ///
    /// Replaces C `X509_CRL_add0_revoked()`. Matches the behavior of
    /// the C function: the entry is appended unsorted — callers must
    /// call [`Self::sort`] when all entries have been added to restore
    /// the sort invariant before using binary search.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`CryptoResult`] for API stability.
    pub fn add_revoked(&mut self, entry: RevokedEntry) -> CryptoResult<()> {
        self.info.revoked.push(entry);
        self.der_encoded.clear();
        self.info.tbs_der.clear();
        Ok(())
    }

    /// Adds a CRL-level extension.
    pub fn add_extension(&mut self, extension: X509Extension) {
        self.info.extensions.push(extension);
        self.der_encoded.clear();
        self.info.tbs_der.clear();
        // Force re-caching on next access.
        self.flags.remove(CrlFlags::EXTENSIONS_CACHED);
    }

    /// Sets the outer signature algorithm identifier (not the inner TBS
    /// one — these are normally set together by the signing routines).
    pub fn set_signature_algorithm(&mut self, alg: AlgorithmIdentifier) {
        self.signature_algorithm = alg;
        self.der_encoded.clear();
    }

    /// Sets the signature value bytes.
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
        self.der_encoded.clear();
    }
}

// -------------------------------------------------------------------------
// Section 10 — X509Crl Operations
// -------------------------------------------------------------------------

impl X509Crl {
    /// Sorts the revoked-entry list by serial number.
    ///
    /// Replaces C `X509_CRL_sort()`. Uses a stable sort so that entries
    /// with equal serial numbers (a malformed-but-parseable case) retain
    /// their original relative order. Each entry's sequence number is
    /// updated to its new index after sorting.
    ///
    /// # Rule R6
    ///
    /// Sequence numbers are assigned via [`u32::try_from`] on the index
    /// (which is `usize`); entries beyond `u32::MAX` in a single CRL
    /// are unlikely in practice but are clamped to `u32::MAX` via
    /// `saturating`-style handling to avoid panics on degenerate input.
    pub fn sort(&mut self) {
        self.info.revoked.sort();
        for (idx, entry) in self.info.revoked.iter_mut().enumerate() {
            // R6: narrow usize -> u32 via try_from with a saturating fallback.
            let seq = u32::try_from(idx).unwrap_or(u32::MAX);
            entry.set_sequence(seq);
        }
        debug!(revoked_count = self.info.revoked.len(), "X509Crl sorted");
    }

    /// Returns `true` if the revoked-entry list appears sorted (a
    /// precondition for [`Self::is_revoked`] to work correctly).
    #[must_use]
    pub fn is_sorted(&self) -> bool {
        self.info.revoked.windows(2).all(|w| w[0] <= w[1])
    }

    /// Searches for a serial number in the revoked list using binary
    /// search.
    ///
    /// Replaces C `X509_CRL_get0_by_serial()`.
    ///
    /// # Preconditions
    ///
    /// The revoked list must be sorted ([`Self::sort`]). If the list is
    /// not sorted this method falls back to a linear scan.
    ///
    /// # Returns
    ///
    /// `Some(&entry)` if a matching serial number is found, or `None`
    /// if the serial is not in the CRL. Note that per RFC 5280 §5.3.4
    /// a `removeFromCRL` reason code means the certificate was
    /// previously revoked but is now reinstated — callers that implement
    /// delta-CRL semantics should inspect `entry.reason()` even on a
    /// successful match.
    #[must_use]
    pub fn is_revoked(&self, serial: &[u8]) -> Option<&RevokedEntry> {
        // Construct a probe entry for comparison.
        let probe = probe_serial(serial);
        if self.is_sorted() {
            match self.info.revoked.binary_search(&probe) {
                Ok(idx) => self.info.revoked.get(idx),
                Err(_) => None,
            }
        } else {
            // Fallback linear scan when caller forgot to sort.
            self.info.revoked.iter().find(|e| e.serial_number == serial)
        }
    }

    /// Convenience wrapper around [`Self::is_revoked`] that extracts
    /// the serial number from an [`X509Certificate`].
    #[must_use]
    pub fn is_revoked_by_cert(&self, cert: &X509Certificate) -> Option<&RevokedEntry> {
        self.is_revoked(cert.serial_number())
    }

    /// Verifies the CRL signature against an issuer public key.
    ///
    /// Replaces C `X509_CRL_verify()`. Delegates to the default method
    /// [`DefaultCrlMethod`]; callers that need alternative verification
    /// backends should construct a [`DefaultCrlMethod`] or implement
    /// [`CrlMethod`] directly.
    ///
    /// The `issuer_key` is the DER encoding of the issuer's
    /// `SubjectPublicKeyInfo` structure (RFC 5280 §4.1.2.7). The
    /// verification dispatches to RSASSA-PKCS1-v1_5 (RSA), ECDSA, or
    /// `EdDSA` based on the CRL's `signatureAlgorithm` OID.
    ///
    /// # Return Contract
    ///
    /// - `Ok(true)` — the signature is cryptographically valid for the
    ///   given TBS bytes and issuer public key.
    /// - `Ok(false)` — the CRL is structurally well-formed but the
    ///   signature does not verify (tampered TBS, wrong issuer key,
    ///   corrupt signature, malformed embedded EMSA-PKCS1-v1_5
    ///   encoding for RSA, etc.).
    /// - `Err(CryptoError::Verification(_))` — a structural error
    ///   prevented verification (missing cached TBS DER, missing
    ///   signature, outer/inner `signatureAlgorithm` OID mismatch
    ///   per RFC 5280 §5.1.1.2, malformed `SubjectPublicKeyInfo`,
    ///   or an unsupported signature algorithm).
    ///
    /// # Supported Algorithms
    ///
    /// - RSASSA-PKCS1-v1_5 with SHA-256 / SHA-384 / SHA-512.
    /// - ECDSA over P-256 / P-384 / P-521 / secp256k1, paired with
    ///   the corresponding SHA digest per the `signatureAlgorithm` OID.
    /// - Pure Ed25519 and pure Ed448 (RFC 8410 + RFC 8032 §5.1/§5.2;
    ///   X.509 CRL signatures are always pure, never `*ph` / `*ctx`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] for any structural error
    /// listed above. Cryptographic verification failures return
    /// `Ok(false)` and never an error variant.
    pub fn verify_signature(&self, issuer_key: &[u8]) -> CryptoResult<bool> {
        let method = DefaultCrlMethod::new();
        method.verify(self, issuer_key)
    }
}

/// Constructs a probe [`RevokedEntry`] used for binary-search lookup.
///
/// The probe contains only the serial number — all other fields are
/// placeholders (minimum-valid [`Asn1Time`]) since [`RevokedEntry`]'s
/// ordering is determined solely by `serial_number`.
fn probe_serial(serial: &[u8]) -> RevokedEntry {
    RevokedEntry {
        serial_number: serial.to_vec(),
        revocation_date: probe_time(),
        extensions: Vec::new(),
        reason: None,
        issuer: None,
        sequence: 0,
    }
}

/// Returns a minimal-valid [`Asn1Time`] for use as a placeholder in
/// comparison probes where the time field is ignored.
///
/// Uses the Unix epoch (1970-01-01T00:00:00Z) which is unconditionally
/// valid because `0` lies within [`Asn1Time`]'s supported POSIX range.
/// The `unwrap_or_else` chain avoids `.unwrap()` / `.expect()` per
/// crate-level `#![deny(clippy::unwrap_used)]` / `expect_used`.
fn probe_time() -> Asn1Time {
    Asn1Time::from_unix_timestamp(0).unwrap_or_else(|_| {
        // Secondary fallback: a direct calendar construction for epoch.
        Asn1Time::new(1970, 1, 1, 0, 0, 0).unwrap_or_else(|_| {
            // Tertiary fallback: `now()` — this branch is effectively
            // unreachable because the previous two constructors cover
            // all valid Asn1Time representations of Unix epoch.
            Asn1Time::now().unwrap_or_else(|_| probe_epoch_fallback())
        })
    })
}

/// Absolute last-resort [`Asn1Time`] fallback used only when every
/// other construction path has failed. Returns year-2000 UTC 00:00:00
/// which is always valid in both `UTCTime` and `GeneralizedTime`.
fn probe_epoch_fallback() -> Asn1Time {
    // If even this fails the Asn1Time implementation is broken; we
    // return a best-effort placeholder by repeating `from_unix_timestamp`
    // with a known-safe value. One of these calls WILL succeed.
    match Asn1Time::from_unix_timestamp(946_684_800) {
        Ok(t) => t,
        Err(_) => match Asn1Time::new(2000, 1, 1, 0, 0, 0) {
            Ok(t) => t,
            Err(_) => {
                // If we reach here the Asn1Time constructor is
                // fundamentally broken. We cannot proceed further,
                // but we must return a value. Retry the epoch — this
                // path is dead code but satisfies the type system.
                #[allow(clippy::unwrap_used)]
                Asn1Time::from_unix_timestamp(0).unwrap()
            }
        },
    }
}

// =============================================================================
// Section 11 — CRL Method Trait + Default Implementation
// =============================================================================

/// Pluggable CRL verification and lookup strategy.
///
/// Replaces C `X509_CRL_METHOD` from `crypto/x509/x509_local.h` lines
/// 83-90:
///
/// ```c
/// struct x509_crl_method_st {
///     int flags;
///     int (*crl_init)(X509_CRL *crl);
///     int (*crl_free)(X509_CRL *crl);
///     int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret,
///         const ASN1_INTEGER *ser, const X509_NAME *issuer);
///     int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk);
/// };
/// ```
///
/// The `crl_init` / `crl_free` callbacks from the C struct have no
/// Rust equivalent — object lifecycle is handled by `Drop` per Rust
/// idiom (RAII).
///
/// Implementations must be thread-safe (`Send + Sync`) so they can be
/// registered globally via a shared `Arc<dyn CrlMethod>`.
pub trait CrlMethod: Send + Sync + std::fmt::Debug {
    /// Verifies the CRL signature against an issuer public key.
    ///
    /// Replaces C `def_crl_verify()` from `x_crl.c` lines 467-472.
    ///
    /// # Parameters
    ///
    /// - `crl` — the CRL whose signature is being verified.
    /// - `issuer_key` — opaque public-key bytes; format depends on the
    ///   signature algorithm (e.g., `SubjectPublicKeyInfo`).
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is cryptographically valid;
    /// `Ok(false)` if the signature is well-formed but does not match;
    /// `Err(_)` on structural errors (missing TBS, malformed key,
    /// unsupported algorithm).
    fn verify(&self, crl: &X509Crl, issuer_key: &[u8]) -> CryptoResult<bool>;

    /// Looks up a revoked entry by serial number and optional issuer.
    ///
    /// Replaces C `def_crl_lookup()` from `x_crl.c` lines 500-538.
    ///
    /// For non-indirect CRLs, `issuer` is `None` and the search matches
    /// only by serial number. For indirect CRLs, `issuer` identifies
    /// the certificate's issuer for matching against per-entry
    /// `certificateIssuer` extensions (RFC 5280 §5.3.3).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(entry))` — the serial is revoked.
    /// - `Ok(None)` — the serial is not in the CRL.
    /// - `Err(_)` — the CRL is malformed or the lookup failed.
    fn lookup(
        &self,
        crl: &X509Crl,
        serial: &[u8],
        issuer: Option<&X509Name>,
    ) -> CryptoResult<Option<RevokedEntry>>;
}

/// Default [`CrlMethod`] implementation — performs a standard
/// signature check via the signature layer and a sorted binary search
/// over the revoked list.
///
/// Replaces C `int_crl_meth` from `crypto/x509/x_crl.c` line 32 (the
/// default method registered by `X509_CRL_set_default_method`).
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultCrlMethod {
    /// Flags matching C `X509_CRL_METHOD_DYNAMIC` (bit 0x1). The
    /// default method is static (not dynamic), so this is always `0`.
    flags: u32,
}

impl DefaultCrlMethod {
    /// Creates a new default method instance.
    #[must_use]
    pub const fn new() -> Self {
        Self { flags: 0 }
    }

    /// Returns the method flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }
}

impl CrlMethod for DefaultCrlMethod {
    /// Verifies the CRL signature.
    ///
    /// This implementation performs full cryptographic verification of
    /// `signatureValue` over `tbsCertList` per RFC 5280 §5.1.1.3, with
    /// the algorithm-consistency check from RFC 5280 §5.1.1.2 (the outer
    /// `signatureAlgorithm` MUST equal the inner `signature` field of
    /// `TBSCertList`).
    ///
    /// `issuer_key` is expected to be the DER encoding of a
    /// `SubjectPublicKeyInfo` (SPKI) — the same encoding stored under
    /// `tbs_certificate.subject_public_key_info` in the issuing
    /// certificate. Callers invoking this from the chain-verification
    /// path obtain the bytes from
    /// [`super::certificate::PublicKeyInfo::subject_public_key_info_der`].
    ///
    /// Supported signature algorithms:
    /// - RSASSA-PKCS1-v1_5 with SHA-256, SHA-384, SHA-512 (RFC 8017 §8.2)
    /// - ECDSA over P-256 / P-384 / P-521 / secp256k1 with SHA-256,
    ///   SHA-384, SHA-512 (X9.62 / RFC 5480)
    /// - Pure Ed25519 / Ed448 (RFC 8410, RFC 8032 §5.1/§5.2)
    ///
    /// Returns:
    /// - `Ok(true)` — signature verifies cryptographically.
    /// - `Ok(false)` — well-formed inputs but signature does not verify.
    /// - `Err(CryptoError::Verification(_))` — structural error
    ///   (malformed inputs, unsupported algorithm, mismatched outer/inner
    ///   algorithm, key parsing failure).
    fn verify(&self, crl: &X509Crl, issuer_key: &[u8]) -> CryptoResult<bool> {
        if !crl.is_valid() {
            return Err(CryptoError::Verification(
                "CRL is flagged invalid; signature verification skipped".to_string(),
            ));
        }
        if crl.info.tbs_der.is_empty() {
            return Err(CryptoError::Verification(
                "CRL has no cached TBS DER; cannot verify signature".to_string(),
            ));
        }
        if crl.signature.is_empty() {
            return Err(CryptoError::Verification(
                "CRL has no signature value".to_string(),
            ));
        }
        if issuer_key.is_empty() {
            return Err(CryptoError::Verification(
                "issuer public key is empty".to_string(),
            ));
        }

        debug!(
            tbs_len = crl.info.tbs_der.len(),
            sig_len = crl.signature.len(),
            key_len = issuer_key.len(),
            "DefaultCrlMethod: preconditions validated; entering crypto",
        );

        // RFC 5280 §5.1.1.2 — outer and inner signatureAlgorithm MUST match.
        let outer_oid = crl
            .signature_algorithm
            .algorithm
            .to_oid_string()
            .map_err(|e| {
                CryptoError::Verification(format!(
                    "CRL outer signatureAlgorithm OID decode: {e}"
                ))
            })?;
        let inner_oid = crl
            .info
            .signature_algorithm
            .algorithm
            .to_oid_string()
            .map_err(|e| {
                CryptoError::Verification(format!(
                    "CRL inner (TBS) signatureAlgorithm OID decode: {e}"
                ))
            })?;
        if outer_oid != inner_oid {
            return Err(CryptoError::Verification(format!(
                "CRL outer/inner signatureAlgorithm mismatch: {outer_oid} != {inner_oid}",
            )));
        }

        // Encode outer parameters back to DER for SignatureAlgorithmId.
        let parameters_der = match crl.signature_algorithm.parameters.as_ref() {
            Some(asn1_type) => Some(asn1_type.encode_der().map_err(|e| {
                CryptoError::Verification(format!(
                    "CRL signatureAlgorithm parameters encode: {e}"
                ))
            })?),
            None => None,
        };
        let sig_alg = SignatureAlgorithmId {
            oid: outer_oid,
            parameters_der,
        };

        // Parse the issuer SubjectPublicKeyInfo via the spki crate so
        // that we can route the algorithm OID and key material into the
        // RSA / ECDSA / EdDSA branches consistently with the certificate
        // verification path in `crate::x509::verify`.
        let spki = SubjectPublicKeyInfoRef::from_der(issuer_key).map_err(|e| {
            CryptoError::Verification(format!(
                "CRL issuer SubjectPublicKeyInfo decode: {e}"
            ))
        })?;
        let alg_params_der = match spki.algorithm.parameters.as_ref() {
            Some(any) => Some(any.to_der().map_err(|e| {
                CryptoError::Verification(format!(
                    "CRL issuer SPKI parameters encode: {e}"
                ))
            })?),
            None => None,
        };
        let public_key_info = PublicKeyInfo {
            algorithm_oid: spki.algorithm.oid.to_string(),
            algorithm_parameters_der: alg_params_der,
            public_key_bytes: spki.subject_public_key.raw_bytes().to_vec(),
            subject_public_key_info_der: issuer_key.to_vec(),
        };

        let tbs = crl.info.tbs_der.as_slice();
        let sig = crl.signature.as_slice();

        // Dispatch on the signature algorithm family. EC-related dispatch arms
        // (ECDSA, EdDSA) are only compiled when the `ec` feature is enabled.
        // When the `ec` feature is disabled, only RSA-family signatures are
        // supported; EC signature algorithms produce a clear "feature disabled"
        // error rather than a generic "not supported" error.
        #[cfg(feature = "ec")]
        {
            if sig_alg.is_rsa() {
                crl_verify_rsa_pkcs1_v1_5(&sig_alg, &public_key_info, tbs, sig)
            } else if sig_alg.is_ecdsa() {
                crl_verify_ecdsa(&sig_alg, &public_key_info, tbs, sig)
            } else if sig_alg.is_eddsa() {
                crl_verify_eddsa(&sig_alg, &public_key_info, tbs, sig)
            } else {
                Err(CryptoError::Verification(format!(
                    "CRL signatureAlgorithm OID {} not supported",
                    sig_alg.oid
                )))
            }
        }
        #[cfg(not(feature = "ec"))]
        {
            if sig_alg.is_rsa() {
                crl_verify_rsa_pkcs1_v1_5(&sig_alg, &public_key_info, tbs, sig)
            } else if sig_alg.is_ecdsa() || sig_alg.is_eddsa() {
                Err(CryptoError::Verification(format!(
                    "CRL signatureAlgorithm OID {} requires the `ec` feature, which is disabled",
                    sig_alg.oid
                )))
            } else {
                Err(CryptoError::Verification(format!(
                    "CRL signatureAlgorithm OID {} not supported",
                    sig_alg.oid
                )))
            }
        }
    }

    /// Looks up a revoked entry by serial number.
    ///
    /// Mirrors `def_crl_lookup()` from `x_crl.c`:
    /// 1. Ensures the revoked list is sorted.
    /// 2. Performs binary search by serial number.
    /// 3. If `issuer` is provided (indirect CRL case), filters by
    ///    matching the entry's cached certificate-issuer against the
    ///    requested issuer.
    /// 4. If the found entry has a `removeFromCRL` reason code, returns
    ///    `None` (matches C behavior of returning `2` to indicate
    ///    "remove from CRL" — the caller treats this as "not revoked").
    fn lookup(
        &self,
        crl: &X509Crl,
        serial: &[u8],
        issuer: Option<&X509Name>,
    ) -> CryptoResult<Option<RevokedEntry>> {
        let entry_ref = crl.is_revoked(serial);
        let Some(entry) = entry_ref else {
            return Ok(None);
        };

        // Issuer match for indirect CRLs (mirrors crl_revoked_issuer_match
        // from x_crl.c lines 474-498). When no issuer is provided, all
        // matches are accepted.
        if let Some(required_issuer) = issuer {
            let entry_issuer_bytes = entry
                .issuer
                .as_ref()
                .map_or_else(|| crl.info.issuer.as_der(), X509Name::as_der);
            if entry_issuer_bytes != required_issuer.as_der() {
                return Ok(None);
            }
        }

        // Handle removeFromCRL (delta CRL reinstatement) — C returns 2
        // for this case; we mirror by returning None (not revoked).
        if entry.reason == Some(RevocationReason::RemoveFromCrl) {
            return Ok(None);
        }

        Ok(Some(entry.clone()))
    }
}

// =============================================================================
// Section 11.X — CRL Signature Verification Helpers
//
// These helpers replicate the certificate signature-verification path in
// `crate::x509::verify` (RSA-PKCS1-v1_5, ECDSA, EdDSA) but adapted to the
// CRL-specific return contract:
//   - `Ok(true)`  : signature verifies cryptographically
//   - `Ok(false)` : signature is well-formed but does NOT verify (or the
//                   recovered EM is malformed for RSA, signaling a
//                   forgery / corruption)
//   - `Err(CryptoError::Verification(_))` : structural / decoding error
//                   that prevents verification from being performed
//
// They share the same OID dispatch tables, EMSA-PKCS1-v1_5 parser, and
// SubjectPublicKeyInfo plumbing as the certificate path. Group D (per
// the review feedback) will deduplicate this with the verify.rs path
// when the shared signature-verification module is introduced.
//
// LOCK-SCOPE: pure functions with no shared mutable state.
// SAFETY/UNSAFE: zero `unsafe` (R8 ABSOLUTE).
// R6: all length-narrowing conversions use checked `try_from`.
// R5: structural-failure paths return `Ok(false)`, never sentinel ints.
// =============================================================================

/// Verifies a CRL signature using RSASSA-PKCS1-v1_5 per RFC 8017 §8.2.2.
///
/// Mirrors `verify_rsa_pkcs1_v1_5` in `crate::x509::verify` (verify.rs:1192)
/// but returns `CryptoResult<bool>` for CRL semantics:
///   - `Ok(true)` if `RSAVP1(s) == EMSA-PKCS1-v1_5-encode(H(tbs))`
///   - `Ok(false)` if signature length mismatches modulus, EM is malformed,
///                 or `DigestInfo` OID/digest mismatch
///   - `Err(...)` if the SPKI cannot be decoded as `RSAPublicKey` or modular
///                 exponentiation fails for an internal reason
fn crl_verify_rsa_pkcs1_v1_5(
    sig_alg: &SignatureAlgorithmId,
    spki: &PublicKeyInfo,
    tbs: &[u8],
    sig: &[u8],
) -> CryptoResult<bool> {
    let sha = crl_sha_for_rsa_sig(&sig_alg.oid)?;
    let hash_oid = crl_sha_digest_oid(sha)?;

    let mut digest = create_sha_digest(sha)?;
    let expected_hash = digest.digest(tbs)?;

    let (modulus, exponent) = crl_parse_rsa_public_key(&spki.public_key_bytes)?;

    let modulus_byte_count = modulus.num_bytes();
    let mod_byte_len = usize::try_from(modulus_byte_count)
        .map_err(|_| CryptoError::Verification("RSA modulus size overflow".into()))?;
    if mod_byte_len == 0 {
        return Err(CryptoError::Verification(
            "RSA modulus must be non-zero".into(),
        ));
    }
    if sig.len() != mod_byte_len {
        // RFC 8017 §8.2.2 step 1: signature length MUST equal modulus length.
        return Ok(false);
    }

    // RFC 8017 §8.2.2 step 2: RSAVP1 — recovered_int = sig_int^exponent mod modulus.
    let sig_int = BigNum::from_bytes_be(sig);
    let recovered_int = mod_exp(&sig_int, &exponent, &modulus)?;
    let encoded_message = recovered_int.to_bytes_be_padded(mod_byte_len)?;

    // RFC 8017 §9.2: parse EMSA-PKCS1-v1_5 encoding and extract digest.
    let Some(embedded_digest) = crl_parse_emsa_pkcs1_v1_5(&encoded_message, hash_oid) else {
        return Ok(false);
    };

    // Constant-time compare to avoid timing side-channel on the digest.
    let digests_match = bool::from(embedded_digest.ct_eq(expected_hash.as_slice()));
    Ok(digests_match)
}

/// Verifies a CRL signature using ECDSA per ANSI X9.62 / RFC 5759.
///
/// Mirrors `verify_ecdsa` in `crate::x509::verify` (verify.rs:1097) but
/// returns `CryptoResult<bool>` directly. The `tbsCertList` is hashed
/// with the SHA variant determined from the signatureAlgorithm OID, then
/// the resulting digest is verified against the SPKI public key.
///
/// Compiled only when the `ec` feature is enabled. When EC is disabled,
/// the dispatch in `verify_signature` returns a descriptive error before
/// reaching this function.
#[cfg(feature = "ec")]
fn crl_verify_ecdsa(
    sig_alg: &SignatureAlgorithmId,
    spki: &PublicKeyInfo,
    tbs: &[u8],
    sig: &[u8],
) -> CryptoResult<bool> {
    let sha = crl_sha_for_ecdsa_sig(&sig_alg.oid)?;
    let curve_oid = crl_curve_oid_from_spki_params(spki)?;
    let curve = crl_curve_for_oid(&curve_oid)?;
    let group = EcGroup::from_curve_name(curve)?;
    let point = EcPoint::from_bytes(&group, &spki.public_key_bytes)?;
    let key = EcKey::from_public_key(&group, point)?;

    let mut digest = create_sha_digest(sha)?;
    let hash = digest.digest(tbs)?;

    // ecdsa_verify_der already returns CryptoResult<bool>: Ok(true) for
    // valid, Ok(false) for invalid-but-well-formed, Err for structural.
    ecdsa_verify_der(&key, &hash, sig)
}

/// Verifies a CRL signature using `PureEdDSA` (Ed25519 / Ed448) per RFC 8410.
///
/// Mirrors `verify_eddsa` in `crate::x509::verify` (verify.rs:1132) but
/// returns `CryptoResult<bool>` directly. RFC 8410 §6 mandates pure-mode
/// Ed25519/Ed448 for X.509 (and by extension CRL) signatures: no context
/// string is permitted, so `context = None`.
///
/// Compiled only when the `ec` feature is enabled. When EC is disabled,
/// the dispatch in `verify_signature` returns a descriptive error before
/// reaching this function.
#[cfg(feature = "ec")]
fn crl_verify_eddsa(
    sig_alg: &SignatureAlgorithmId,
    spki: &PublicKeyInfo,
    tbs: &[u8],
    sig: &[u8],
) -> CryptoResult<bool> {
    match sig_alg.oid.as_str() {
        OID_ED25519 => {
            let pk = EcxPublicKey::new(EcxKeyType::Ed25519, spki.public_key_bytes.clone())?;
            // X.509 / CRL signatures use Pure Ed25519 (RFC 8410 + RFC 8032 §5.1):
            // no context string is permitted.
            ed25519_verify(&pk, tbs, sig, None)
        }
        OID_ED448 => {
            let pk = EcxPublicKey::new(EcxKeyType::Ed448, spki.public_key_bytes.clone())?;
            ed448_verify(&pk, tbs, sig, None)
        }
        other => Err(CryptoError::Verification(format!(
            "EdDSA OID {other} not supported"
        ))),
    }
}

/// Maps an RSASSA-PKCS1-v1_5 signatureAlgorithm OID to its SHA digest variant.
fn crl_sha_for_rsa_sig(oid: &str) -> CryptoResult<ShaAlgorithm> {
    match oid {
        OID_SHA256_WITH_RSA => Ok(ShaAlgorithm::Sha256),
        OID_SHA384_WITH_RSA => Ok(ShaAlgorithm::Sha384),
        OID_SHA512_WITH_RSA => Ok(ShaAlgorithm::Sha512),
        other => Err(CryptoError::Verification(format!(
            "RSA signature hash OID {other} not supported"
        ))),
    }
}

/// Maps an ECDSA signatureAlgorithm OID to its SHA digest variant.
///
/// Compiled only when the `ec` feature is enabled, since its only caller
/// is `crl_verify_ecdsa`.
#[cfg(feature = "ec")]
fn crl_sha_for_ecdsa_sig(oid: &str) -> CryptoResult<ShaAlgorithm> {
    match oid {
        OID_ECDSA_SHA256 => Ok(ShaAlgorithm::Sha256),
        OID_ECDSA_SHA384 => Ok(ShaAlgorithm::Sha384),
        OID_ECDSA_SHA512 => Ok(ShaAlgorithm::Sha512),
        other => Err(CryptoError::Verification(format!(
            "ECDSA signature hash OID {other} not supported"
        ))),
    }
}

/// Maps a SHA variant to the digest-OID string used inside the
/// EMSA-PKCS1-v1_5 `DigestInfo` structure.
fn crl_sha_digest_oid(alg: ShaAlgorithm) -> CryptoResult<&'static str> {
    match alg {
        ShaAlgorithm::Sha256 => Ok(OID_SHA256),
        ShaAlgorithm::Sha384 => Ok(OID_SHA384),
        ShaAlgorithm::Sha512 => Ok(OID_SHA512),
        other => Err(CryptoError::Verification(format!(
            "{} not supported for PKCS1-v1.5 DigestInfo",
            other.name()
        ))),
    }
}

/// Maps an EC named-curve OID to its `NamedCurve` enum variant.
///
/// Compiled only when the `ec` feature is enabled, since its only caller
/// is `crl_verify_ecdsa` and its return type uses the EC-feature-gated
/// `NamedCurve` enum.
#[cfg(feature = "ec")]
fn crl_curve_for_oid(oid: &str) -> CryptoResult<NamedCurve> {
    match oid {
        OID_ECC_P256 => Ok(NamedCurve::Prime256v1),
        OID_ECC_P384 => Ok(NamedCurve::Secp384r1),
        OID_ECC_P521 => Ok(NamedCurve::Secp521r1),
        OID_ECC_SECP256K1 => Ok(NamedCurve::Secp256k1),
        other => Err(CryptoError::Verification(format!(
            "ECC curve OID {other} not supported"
        ))),
    }
}

/// Extracts the named-curve OID from an SPKI's algorithm parameters
/// (`ECParameters ::= namedCurve OBJECT IDENTIFIER`).
///
/// Compiled only when the `ec` feature is enabled, since its only caller
/// is `crl_verify_ecdsa`.
#[cfg(feature = "ec")]
fn crl_curve_oid_from_spki_params(pk: &PublicKeyInfo) -> CryptoResult<String> {
    let params = pk.algorithm_parameters_der.as_ref().ok_or_else(|| {
        CryptoError::Verification("ECDSA SPKI missing algorithm parameters".into())
    })?;
    let oid = der::asn1::ObjectIdentifier::from_der(params).map_err(|e| {
        CryptoError::Verification(format!("ECDSA SPKI params not an OID: {e}"))
    })?;
    Ok(oid.to_string())
}

/// Parses an `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
/// per RFC 8017 §A.1.1 from the `subject_public_key_bytes` of an SPKI.
///
/// Mirrors `parse_rsa_public_key` in `crate::x509::verify` (verify.rs:1246).
fn crl_parse_rsa_public_key(der_bytes: &[u8]) -> CryptoResult<(BigNum, BigNum)> {
    use der::{Reader, SliceReader};

    let mut root = SliceReader::new(der_bytes).map_err(|e| {
        CryptoError::Verification(format!("RSA SPKI outer read: {e}"))
    })?;
    let mut inner = root
        .sequence(|r| {
            let n = crl_decode_unsigned_integer(r)?;
            let e = crl_decode_unsigned_integer(r)?;
            Ok((n, e))
        })
        .map_err(|e| CryptoError::Verification(format!("RSA SPKI SEQ: {e}")))?;

    if !root.is_finished() {
        trace!("crl_verify: trailing bytes after RSAPublicKey sequence");
    }

    let (n_bytes, e_bytes) = (
        inner.0.take().unwrap_or_default(),
        inner.1.take().unwrap_or_default(),
    );
    if n_bytes.is_empty() || e_bytes.is_empty() {
        return Err(CryptoError::Verification(
            "RSA SPKI has empty modulus or exponent".into(),
        ));
    }
    Ok((
        BigNum::from_bytes_be(&n_bytes),
        BigNum::from_bytes_be(&e_bytes),
    ))
}

/// Decodes an ASN.1 INTEGER as an unsigned big-endian byte vector,
/// stripping the leading 0x00 sign-padding byte when present.
///
/// The reader is generic over any [`der::Reader`] so this can be invoked
/// from both top-level and inner-sequence contexts. Mirrors
/// `decode_unsigned_integer` in `crate::x509::verify` (verify.rs:1286).
fn crl_decode_unsigned_integer<'a, R: der::Reader<'a>>(
    r: &mut R,
) -> der::Result<CrlUnsignedHolder> {
    let header = r.peek_header()?;
    if header.tag != der::Tag::Integer {
        return Err(header.tag.unexpected_error(Some(der::Tag::Integer)));
    }
    let tlv = der::asn1::Int::decode(r)?;
    let bytes = tlv.as_bytes();
    // ASN.1 DER encodes unsigned INTEGERs by prepending a 0x00 sign byte
    // whenever the high bit of the first content byte is set; some encoders
    // also emit a redundant leading 0x00 even when not strictly required.
    // Both cases require stripping the leading 0x00 before treating the
    // remainder as the unsigned big-endian magnitude. RFC 8017 §4.1 / X.690
    // §8.3.3.
    let stripped: Vec<u8> = if bytes.len() > 1 && bytes[0] == 0x00 {
        bytes[1..].to_vec()
    } else {
        bytes.to_vec()
    };
    Ok(CrlUnsignedHolder(Some(stripped)))
}

/// Owning holder for an unsigned integer's stripped big-endian bytes.
/// Mirrors `UnsignedHolder` in `crate::x509::verify` (verify.rs:1309).
struct CrlUnsignedHolder(Option<Vec<u8>>);

impl CrlUnsignedHolder {
    fn take(&mut self) -> Option<Vec<u8>> {
        self.0.take()
    }
}

/// Parses an EMSA-PKCS1-v1_5 encoded message per RFC 8017 §9.2 and
/// returns the embedded digest if and only if all structural checks
/// pass and the embedded `digestAlgorithm` OID matches `expected_hash_oid`.
///
/// Returns `None` for any structural failure or OID mismatch — callers
/// translate this to `Ok(false)` (well-formed but invalid signature).
///
/// Mirrors `parse_emsa_pkcs1_v1_5` in `crate::x509::verify` (verify.rs:1328)
/// but uses `Option` for the failure path because, for CRL semantics, all
/// EM-decoding failures are treated as "signature does not verify" rather
/// than as decode-time errors (the EM is the recovered signer output, so
/// a malformed EM means the signature itself is bad).
fn crl_parse_emsa_pkcs1_v1_5(em: &[u8], expected_hash_oid: &str) -> Option<Vec<u8>> {
    if em.len() < 11 {
        return None;
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return None;
    }
    let mut idx = 2usize;
    while idx < em.len() && em[idx] == 0xFF {
        idx = idx.saturating_add(1);
    }
    // RFC 8017 §9.2: PS MUST be at least 8 bytes of 0xFF.
    if idx < 2usize.saturating_add(8) {
        return None;
    }
    if idx >= em.len() || em[idx] != 0x00 {
        return None;
    }
    let t = &em[idx.saturating_add(1)..];

    let (hash_oid, digest) = crl_parse_digest_info(t).ok()?;
    if hash_oid != expected_hash_oid {
        return None;
    }
    Some(digest)
}

/// Parses a `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`
/// structure from RFC 8017 §9.2 / RFC 5280.
///
/// Returns the digest-algorithm OID (dotted-decimal) and the digest bytes.
/// Mirrors `parse_digest_info` in `crate::x509::verify` (verify.rs:1361).
fn crl_parse_digest_info(bytes: &[u8]) -> CryptoResult<(String, Vec<u8>)> {
    use der::{Reader, SliceReader};

    let mut r = SliceReader::new(bytes).map_err(|e| {
        CryptoError::Verification(format!("DigestInfo outer read: {e}"))
    })?;
    let (oid, digest): (String, Vec<u8>) = r
        .sequence(|r| {
            let (oid, _params) = r.sequence(|ai| {
                let oid = der::asn1::ObjectIdentifier::decode(ai)?;
                let rest = ai.read_slice(ai.remaining_len())?;
                Ok((oid, rest.to_vec()))
            })?;
            let octets = der::asn1::OctetStringRef::decode(r)?;
            Ok((oid.to_string(), octets.as_bytes().to_vec()))
        })
        .map_err(|e| {
            CryptoError::Verification(format!("DigestInfo decode: {e}"))
        })?;
    Ok((oid, digest))
}

// =============================================================================
// Section 12 — Extension Cache Processing
// =============================================================================

impl X509Crl {
    /// Processes the CRL-level and per-entry extensions, populating
    /// cached fields for O(1) access during revocation checks.
    ///
    /// Mirrors the C `crl_cb()` callback in `x_crl.c` lines 213-341
    /// (the `ASN1_OP_D2I_POST` stage) and `crl_set_issuers()` from
    /// lines 80-207.
    ///
    /// # Processing Steps
    ///
    /// 1. Validate that `last_update` is present (RFC 5280 mandatory).
    ///    If absent, sets [`CrlFlags::INVALID`].
    /// 2. Extract standard CRL-level extensions:
    ///    - Authority Key Identifier (OID `2.5.29.35`)
    ///    - CRL Number (OID `2.5.29.20`)
    ///    - Delta CRL Indicator (OID `2.5.29.27`)
    ///    - Issuing Distribution Point (OID `2.5.29.28`)
    ///    - Freshest CRL (OID `2.5.29.46`)
    /// 3. For each revoked entry, extract the per-entry
    ///    `reasonCode` (OID `2.5.29.21`) and `certificateIssuer`
    ///    (OID `2.5.29.29`) extensions.
    /// 4. Propagate the "most recent issuer" to subsequent revoked
    ///    entries (RFC 5280 §5.3.3 indirect-CRL semantics).
    /// 5. Check for unknown critical extensions; sets
    ///    [`CrlFlags::CRITICAL_ERROR`] if any are found.
    /// 6. Mark [`CrlFlags::EXTENSIONS_CACHED`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] only on catastrophic failures
    /// (e.g., parser errors within the extension cache itself).
    /// Malformed individual extensions are logged at `warn` level and
    /// set [`CrlFlags::INVALID`] or [`CrlFlags::CRITICAL_ERROR`] as
    /// appropriate — the CRL is kept for diagnostic purposes but its
    /// [`Self::is_valid`] will return `false`.
    pub fn cache_extensions(&mut self) -> CryptoResult<()> {
        // Already cached? Nothing to do.
        if self.flags.contains(CrlFlags::EXTENSIONS_CACHED) {
            return Ok(());
        }

        // Step 1: Validate mandatory fields.
        // The absence of `last_update` is caught earlier during DER
        // parsing; here we detect "zero-valued" placeholder last_update
        // which can only arise from in-memory construction.
        let last_update_ts = self
            .info
            .last_update
            .to_unix_timestamp()
            .unwrap_or(i64::MIN);
        if last_update_ts == i64::MIN {
            warn!("X509Crl cache_extensions: last_update is invalid; flagging INVALID");
            self.flags.insert(CrlFlags::INVALID);
        }

        // Step 2: Extract CRL-level extensions.
        // Per the x_crl.c pattern: iterate every extension, match known
        // OIDs, and collect into dedicated fields. Unknown critical
        // extensions trigger CRITICAL_ERROR.
        let mut saw_critical_unknown = false;
        // Clone OIDs and criticality bits into a local vec so we can
        // borrow-mutate `self` below without holding `&self.info.extensions`.
        let extensions: Vec<(String, bool, Vec<u8>)> = self
            .info
            .extensions
            .iter()
            .map(|e| (e.oid.clone(), e.critical, e.value.clone()))
            .collect();

        for (oid, critical, value) in extensions {
            match oid.as_str() {
                // id-ce-authorityKeyIdentifier
                "2.5.29.35" => {
                    let akid = parse_akid_extension(&value).unwrap_or_else(|e| {
                        warn!(oid = oid.as_str(), error = %e, "malformed AKID extension");
                        AuthorityKeyIdentifier::empty()
                    });
                    self.akid = Some(akid);
                }
                // id-ce-cRLNumber
                "2.5.29.20" => match parse_integer_extension(&value) {
                    Ok(v) => self.crl_number = Some(v),
                    Err(e) => {
                        warn!(oid = oid.as_str(), error = %e, "malformed CRL Number");
                        self.flags.insert(CrlFlags::INVALID);
                    }
                },
                // id-ce-deltaCRLIndicator
                "2.5.29.27" => match parse_integer_extension(&value) {
                    Ok(v) => self.delta_crl_indicator = Some(v),
                    Err(e) => {
                        warn!(oid = oid.as_str(), error = %e, "malformed delta CRL indicator");
                        self.flags.insert(CrlFlags::INVALID);
                    }
                },
                // id-ce-issuingDistributionPoint
                "2.5.29.28" => match parse_idp_extension(&value) {
                    Ok((idp, idp_flags, reasons)) => {
                        self.idp = Some(idp);
                        self.idp_flags.insert(IdpFlags::IDP_PRESENT);
                        self.idp_flags.insert(idp_flags);
                        if let Some(r) = reasons {
                            self.idp_reasons = r;
                            self.idp_flags.insert(IdpFlags::IDP_REASONS);
                        }
                    }
                    Err(e) => {
                        warn!(oid = oid.as_str(), error = %e, "malformed IDP extension");
                        self.idp_flags.insert(IdpFlags::IDP_INVALID);
                        self.flags.insert(CrlFlags::INVALID);
                    }
                },
                // id-ce-freshestCRL (delta CRL hint)
                "2.5.29.46" => {
                    self.flags.insert(CrlFlags::FRESHEST);
                }
                // Authority Information Access (OID 1.3.6.1.5.5.7.1.1)
                // — informational; no-op for CRL processing.
                "1.3.6.1.5.5.7.1.1" => {}
                other => {
                    if critical {
                        warn!(
                            oid = other,
                            "unknown critical CRL extension; flagging CRITICAL_ERROR",
                        );
                        saw_critical_unknown = true;
                    }
                }
            }
        }

        if saw_critical_unknown {
            self.flags.insert(CrlFlags::CRITICAL_ERROR);
        }

        // Step 3: Process per-entry extensions + propagate indirect
        // issuers (RFC 5280 §5.3.3).
        self.cache_revoked_entry_extensions()?;

        // Step 4: Mark cached.
        self.flags.insert(CrlFlags::EXTENSIONS_CACHED);
        self.flags.insert(CrlFlags::EXFLAG_SET);
        Ok(())
    }

    /// Processes per-entry extensions: extracts reason codes,
    /// certificate issuers, and propagates the "most recent issuer"
    /// through the entry list per RFC 5280 §5.3.3 indirect-CRL rules.
    ///
    /// Mirrors C `crl_set_issuers()` from `x_crl.c` lines 80-207.
    fn cache_revoked_entry_extensions(&mut self) -> CryptoResult<()> {
        let is_indirect = self.idp_flags.contains(IdpFlags::IDP_INDIRECT);
        let mut most_recent_issuer: Option<X509Name> = None;

        for entry in &mut self.info.revoked {
            entry.cache_entry_extensions()?;

            // For indirect CRLs: if this entry has an explicit
            // certificateIssuer extension, update the rolling "most
            // recent issuer". If it doesn't, inherit the previous one.
            if is_indirect {
                match &entry.issuer {
                    Some(iss) => {
                        most_recent_issuer = Some(iss.clone());
                    }
                    None => {
                        // Inherit from the most recently seen issuer.
                        if let Some(inherited) = &most_recent_issuer {
                            entry.issuer = Some(inherited.clone());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// Section 13 — Display Implementation (from t_crl.c)
// =============================================================================

impl Display for X509Crl {
    /// Renders a human-readable CRL representation matching the output
    /// of OpenSSL's `X509_CRL_print_ex()` from `crypto/x509/t_crl.c`.
    ///
    /// Format:
    ///
    /// ```text
    /// Certificate Revocation List (CRL):
    ///     Version N (0xH)
    ///     Signature Algorithm: <OID>
    ///     Issuer: <name>
    ///     Last Update: <time>
    ///     Next Update: <time> | NONE
    ///     CRL extensions:
    ///         <extension list>
    /// Revoked Certificates: | No Revoked Certificates.
    ///     Serial Number: <hex>
    ///         Revocation Date: <time>
    ///         CRL entry extensions:
    ///             <extension list>
    /// ```
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Certificate Revocation List (CRL):")?;

        // Version line — matches `X509_CRL_print` which shows v1 as
        // "Version 1 (0x0)" and v2 as "Version 2 (0x1)".
        let version = self.info.version.unwrap_or(0);
        let display_version = version.saturating_add(1);
        writeln!(f, "        Version {display_version} (0x{version:x})")?;

        // Signature algorithm — display the OID bytes since we don't
        // have a full OID registry here; downstream consumers can
        // augment this with a name-lookup table.
        write!(f, "        Signature Algorithm: ")?;
        match self.info.signature_algorithm.algorithm.to_oid_string() {
            Ok(s) => writeln!(f, "{s}")?,
            Err(_) => writeln!(f, "<unknown OID>")?,
        }

        writeln!(f, "        Issuer: {}", self.info.issuer)?;

        // Last Update
        writeln!(f, "        Last Update: {}", self.info.last_update)?;

        // Next Update or NONE
        match &self.info.next_update {
            Some(t) => writeln!(f, "        Next Update: {t}")?,
            None => writeln!(f, "        Next Update: NONE")?,
        }

        // CRL extensions
        if !self.info.extensions.is_empty() {
            writeln!(f, "        CRL extensions:")?;
            for ext in &self.info.extensions {
                let crit = if ext.critical { " critical" } else { "" };
                writeln!(
                    f,
                    "            {oid}:{crit} ({len} bytes)",
                    oid = ext.oid,
                    crit = crit,
                    len = ext.value.len(),
                )?;
            }
        }

        // Revoked certificates section
        if self.info.revoked.is_empty() {
            writeln!(f, "No Revoked Certificates.")?;
        } else {
            writeln!(f, "Revoked Certificates:")?;
            for entry in &self.info.revoked {
                writeln!(f, "    Serial Number: {}", hex_encode(&entry.serial_number),)?;
                writeln!(f, "        Revocation Date: {}", entry.revocation_date)?;
                if let Some(r) = entry.reason {
                    writeln!(f, "        Reason: {r}")?;
                }
                if let Some(iss) = entry.issuer() {
                    writeln!(f, "        Certificate Issuer: {iss}")?;
                }
                if !entry.extensions.is_empty() {
                    writeln!(f, "        CRL entry extensions:")?;
                    for ext in &entry.extensions {
                        let crit = if ext.critical { " critical" } else { "" };
                        writeln!(
                            f,
                            "            {oid}:{crit} ({len} bytes)",
                            oid = ext.oid,
                            crit = crit,
                            len = ext.value.len(),
                        )?;
                    }
                }
            }
        }

        // Signature value
        writeln!(f, "    Signature Value: ({} bytes)", self.signature.len())?;

        Ok(())
    }
}

// =============================================================================
// Section 14 — Parser / Serializer Helper Functions
// =============================================================================
//
// This section implements the private helper functions used throughout the
// preceding sections for DER parsing, DER serialization, PEM encoding/decoding,
// and time-format conversion.  All helpers observe the project-wide rules:
//
//   R5  — Use `Option<T>` in place of sentinel values.
//   R6  — All numeric casts use `try_from` / checked arithmetic; no bare `as`.
//   R8  — Zero `unsafe` blocks.
//   R9  — All public items carry `///` doc comments; code is warning-free.
//
// The parser helpers leverage the generic DER/BER TLV utilities exposed by
// [`crate::asn1::parse_tlv_header`] and [`crate::asn1::write_tlv_header`],
// which provide fully validated class/tag/length handling with overflow
// detection.  See `crates/openssl-crypto/src/asn1/mod.rs` for details.
//
// Source provenance: these helpers collectively translate the decode
// callbacks and ASN.1 template glue from `crypto/x509/x_crl.c` (the
// `crl_cb`, `crl_inf_cb`, `setup_idp`, and implicit template-driven
// decoders) into explicit Rust parser code that does not rely on
// compile-time generated template machinery.

/// Convert an [`Asn1Time`] to an [`OsslTime`] (Unix-epoch seconds).
///
/// Replaces implicit `X509_CRL_TIME_*` conversions in the C tree.
///
/// # Conversion semantics
///
/// `OsslTime` stores a `u64` count of nanoseconds since the Unix epoch and
/// therefore cannot represent times earlier than 1970-01-01 00:00:00 UTC.
/// When an [`Asn1Time`] holds a negative Unix timestamp (i.e., a historical
/// time), we **saturate** to [`OsslTime::ZERO`]. This matches the OpenSSL
/// convention of treating the epoch itself as the earliest representable
/// instant; the information loss is logged via `tracing::debug!` so callers
/// can observe it if configured for debug-level diagnostics.
///
/// When the conversion from seconds to `OsslTime` ticks would overflow
/// `u64::MAX`, `OsslTime::from_seconds` saturates to `OsslTime::INFINITE`
/// — this is the OpenSSL sentinel for "no upper bound".
///
/// # Errors
///
/// Returns an error only if [`Asn1Time::to_unix_timestamp`] itself fails
/// (i.e., the ASN.1 time is outside the valid range
/// `MIN_POSIX_TIME..=MAX_POSIX_TIME`, which corresponds to the
/// `GeneralizedTime` span 0000-01-01 to 9999-12-31).
///
/// # Rule R6 compliance
///
/// The narrowing from `i64` to `u64` is performed via `u64::try_from` with
/// an explicit `.max(0)` pre-clamp — no bare `as` cast is used.
fn asn1_time_to_ossl(t: Asn1Time) -> CryptoResult<OsslTime> {
    let ts_i64 = t.to_unix_timestamp()?;
    if ts_i64 < 0 {
        debug!(
            timestamp = ts_i64,
            "asn1_time_to_ossl: saturating negative timestamp to OsslTime::ZERO"
        );
        return Ok(OsslTime::ZERO);
    }
    // `ts_i64 >= 0` is guaranteed by the branch above, so `try_from`
    // cannot fail — but we use it anyway per Rule R6 (no bare `as`).
    let ts_u64 = u64::try_from(ts_i64).map_err(|_| {
        CryptoError::Encoding(format!(
            "asn1_time_to_ossl: timestamp {ts_i64} cannot be represented as u64"
        ))
    })?;
    Ok(OsslTime::from_seconds(ts_u64))
}

/// Convert an [`OsslTime`] to an [`Asn1Time`] (`UTCTime` or
/// `GeneralizedTime`, auto-selected per RFC 5280 §4.1.2.5 by
/// [`Asn1Time::from_unix_timestamp`]).
///
/// Replaces implicit `X509_CRL_TIME_*` conversions in the C tree.
///
/// # Errors
///
/// * `CryptoError::Encoding` if the `OsslTime` value exceeds `i64::MAX`
///   seconds (i.e., the time is so far in the future it would overflow
///   ASN.1 time representations). Per Rule R6 the conversion is performed
///   via `i64::try_from` — no bare `as` cast.
/// * Any error returned by [`Asn1Time::from_unix_timestamp`] (for example
///   if the resulting timestamp is outside the representable range for
///   `GeneralizedTime`, i.e., before 0000-01-01 or after 9999-12-31).
fn ossl_time_to_asn1(t: OsslTime) -> CryptoResult<Asn1Time> {
    // `OsslTime::to_seconds` is infallible (u64 seconds), but the target
    // type `Asn1Time` holds an `i64` internally. Per R6 we convert via
    // `try_from` — a bare `as` cast could silently wrap on u64 values
    // exceeding `i64::MAX` (approximately year 292-billion).
    let ts_u64 = t.to_seconds();
    let ts_i64 = i64::try_from(ts_u64).map_err(|_| {
        CryptoError::Encoding(format!(
            "ossl_time_to_asn1: OsslTime value {ts_u64} seconds exceeds i64::MAX"
        ))
    })?;
    Asn1Time::from_unix_timestamp(ts_i64)
}

/// Encode a byte slice as a lowercase hexadecimal string without separators.
///
/// Used by the [`Display for X509Crl`] implementation (Section 13) to render
/// revoked-certificate serial numbers in the canonical OpenSSL format.
///
/// # Example
///
/// ```ignore
/// // 0x2A (42) → "2a"
/// assert_eq!(hex_encode(&[0x2a]), "2a");
/// // Multi-byte: 0x01, 0xFE → "01fe"
/// assert_eq!(hex_encode(&[0x01, 0xFE]), "01fe");
/// ```
///
/// # Rule compliance
///
/// * R6: no bare `as` cast — we use `char::from_digit` for the nibble→char
///   conversion, which returns `Option<char>` and is infallible for input
///   in `0..=15`.
/// * R8: no `unsafe`.
#[must_use]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = u32::from(b >> 4);
        let lo = u32::from(b & 0x0F);
        // `char::from_digit` returns `Some(c)` for 0..=15 (both in range),
        // never fails here; the unwrap_or fallback is defensive only and
        // never reachable in practice.
        s.push(char::from_digit(hi, 16).unwrap_or('?'));
        s.push(char::from_digit(lo, 16).unwrap_or('?'));
    }
    s
}

/// Parse the value of an X.509 extension whose payload is a DER-encoded
/// `INTEGER` and return the raw content bytes (without the TLV header).
///
/// Used for `cRLNumber` (`2.5.29.20`) and `deltaCRLIndicator` (`2.5.29.27`)
/// — both are defined as `INTEGER` per RFC 5280 §5.2.3 and §5.2.4.
///
/// # Errors
///
/// * `CryptoError::Encoding` if the value is not a valid DER INTEGER:
///   - wrong tag (not `Asn1Tag::Integer`)
///   - wrong class (not `Asn1Class::Universal`)
///   - constructed encoding (INTEGER must be primitive)
///   - truncated (content length exceeds available bytes)
///   - indefinite length (not legal for DER)
///
/// # Rule compliance
///
/// * R6: all lengths are `usize`; arithmetic uses `checked_add` to detect
///   overflow.
fn parse_integer_extension(value: &[u8]) -> CryptoResult<Vec<u8>> {
    let hdr = parse_tlv_header(value)?;
    if hdr.tag != Asn1Tag::Integer {
        return Err(CryptoError::Encoding(format!(
            "parse_integer_extension: expected INTEGER, got tag {:?}",
            hdr.tag
        )));
    }
    if hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_integer_extension: expected Universal class, got {:?}",
            hdr.class
        )));
    }
    if hdr.constructed {
        return Err(CryptoError::Encoding(
            "parse_integer_extension: INTEGER must be primitive (not constructed)".into(),
        ));
    }
    let content_len = hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding(
            "parse_integer_extension: indefinite length not allowed for DER INTEGER".into(),
        )
    })?;
    let start = hdr.header_length;
    let end = start
        .checked_add(content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_integer_extension: length overflow".into()))?;
    if end > value.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_integer_extension: truncated INTEGER (need {end} bytes, have {})",
            value.len()
        )));
    }
    Ok(value[start..end].to_vec())
}

/// Parse an X.509 `authorityKeyIdentifier` extension (OID `2.5.29.35`,
/// RFC 5280 §4.2.1.1) and return the decoded [`AuthorityKeyIdentifier`]
/// structure.
///
/// # ASN.1 structure (RFC 5280 §4.2.1.1)
///
/// ```text
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
///
/// KeyIdentifier ::= OCTET STRING
/// ```
///
/// All three fields are OPTIONAL and identified by IMPLICIT context-specific
/// tags `[0]`, `[1]`, `[2]`. Since [`crate::asn1::parse_tlv_header`] reports
/// context-specific tags by setting `tag = Asn1Tag::Eoc` and `class =
/// Asn1Class::ContextSpecific`, we dispatch on the raw identifier byte's
/// low 5 bits (the tag number) to route each field.
///
/// # Errors
///
/// Returns `CryptoError::Encoding` if:
/// - The outer TLV is not a Universal SEQUENCE.
/// - Any inner TLV length exceeds the SEQUENCE content length.
/// - The indefinite-length form is used (not legal in DER).
///
/// # Rule compliance
///
/// * R5: unpopulated fields remain `None` rather than empty/sentinel values.
/// * R6: all length arithmetic uses `checked_add`; no bare `as` casts.
/// * R8: no `unsafe`.
fn parse_akid_extension(value: &[u8]) -> CryptoResult<AuthorityKeyIdentifier> {
    let outer = parse_tlv_header(value)?;
    if outer.tag != Asn1Tag::Sequence || outer.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_akid_extension: expected Universal SEQUENCE, got tag={:?} class={:?}",
            outer.tag, outer.class
        )));
    }
    if !outer.constructed {
        return Err(CryptoError::Encoding(
            "parse_akid_extension: SEQUENCE must be constructed".into(),
        ));
    }
    let outer_content_len = outer.content_length.ok_or_else(|| {
        CryptoError::Encoding(
            "parse_akid_extension: indefinite length not allowed for DER SEQUENCE".into(),
        )
    })?;
    let content_start = outer.header_length;
    let content_end = content_start
        .checked_add(outer_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_akid_extension: length overflow".into()))?;
    if content_end > value.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_akid_extension: truncated SEQUENCE (need {content_end} bytes, have {})",
            value.len()
        )));
    }

    let mut akid = AuthorityKeyIdentifier::empty();
    let mut cursor = content_start;

    while cursor < content_end {
        let remaining = &value[cursor..content_end];
        let hdr = parse_tlv_header(remaining)?;
        let inner_content_len = hdr.content_length.ok_or_else(|| {
            CryptoError::Encoding("parse_akid_extension: indefinite length in inner field".into())
        })?;
        let inner_start = cursor
            .checked_add(hdr.header_length)
            .ok_or_else(|| CryptoError::Encoding("parse_akid_extension: overflow".into()))?;
        let inner_end = inner_start
            .checked_add(inner_content_len)
            .ok_or_else(|| CryptoError::Encoding("parse_akid_extension: overflow".into()))?;
        if inner_end > content_end {
            return Err(CryptoError::Encoding(format!(
                "parse_akid_extension: inner field exceeds SEQUENCE bounds \
                 (need {inner_end}, have {content_end})"
            )));
        }

        if hdr.class == Asn1Class::ContextSpecific {
            // Decode the raw tag number from the identifier byte. For
            // context-specific short-form tags the low 5 bits of the
            // identifier octet carry the tag number directly. If the
            // tag is in long form (all 5 low bits set) we conservatively
            // skip it — RFC 5280 only defines [0], [1], [2] here, none
            // of which requires long-form encoding.
            let tag_num = value[cursor] & 0x1F;
            match tag_num {
                0 => {
                    // [0] keyIdentifier — IMPLICIT OCTET STRING.
                    // Content bytes are the key identifier directly.
                    akid.key_identifier = Some(value[inner_start..inner_end].to_vec());
                }
                1 => {
                    // [1] authorityCertIssuer — IMPLICIT GeneralNames.
                    // We store the raw DER bytes of the content; higher
                    // layers can further decode GeneralName choices.
                    // For compatibility with the `X509Name` wrapper we
                    // stash the DER bytes in a `X509Name` created via
                    // `from_der` — this preserves the information without
                    // forcing a full GeneralNames parser at this layer.
                    let issuer_bytes = value[inner_start..inner_end].to_vec();
                    akid.authority_cert_issuer = Some(X509Name::from_der(issuer_bytes));
                }
                2 => {
                    // [2] authorityCertSerialNumber — IMPLICIT INTEGER.
                    // Store the raw content bytes (the serial number is a
                    // variable-length big-endian two's-complement integer).
                    akid.authority_cert_serial = Some(value[inner_start..inner_end].to_vec());
                }
                _ => {
                    // Unknown context-specific tag. RFC 5280 says
                    // unknown critical extensions must be rejected, but
                    // unknown sub-fields within a known extension should
                    // simply be ignored (§4.2).
                    debug!(
                        tag = tag_num,
                        "parse_akid_extension: ignoring unknown context-specific field"
                    );
                }
            }
        } else {
            // No Universal fields are defined in the AKID SEQUENCE —
            // skip unexpected encodings with a warning.
            debug!(
                tag = ?hdr.tag,
                class = ?hdr.class,
                "parse_akid_extension: ignoring unexpected non-context field"
            );
        }

        cursor = inner_end;
    }

    Ok(akid)
}

/// Parse an X.509 `issuingDistributionPoint` extension (OID `2.5.29.28`,
/// RFC 5280 §5.2.5) and return the decoded [`IssuingDistPoint`], a bitflag
/// summary of which sub-fields were present, and the optional
/// `onlySomeReasons` [`ReasonFlags`].
///
/// # ASN.1 structure (RFC 5280 §5.2.5)
///
/// ```text
/// IssuingDistributionPoint ::= SEQUENCE {
///     distributionPoint          [0] DistributionPointName OPTIONAL,
///     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
///     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
///     onlySomeReasons            [3] ReasonFlags OPTIONAL,
///     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
/// ```
///
/// All fields are OPTIONAL and use IMPLICIT context-specific tags. RFC 5280
/// §5.2.5 requires the extension to be marked CRITICAL and imposes
/// semantic constraints (e.g., only one of `onlyContains*` booleans may be
/// TRUE). These semantic checks are performed here; tagging errors
/// produce `CryptoError::Encoding`.
///
/// # Return value
///
/// A three-tuple `(idp, idp_flags, reasons)`:
/// * `idp` — the decoded [`IssuingDistPoint`] with public fields populated.
/// * `idp_flags` — [`IdpFlags`] summary of which context-specific fields
///   were present (matches the OpenSSL `IDP_*` probe flags).
/// * `reasons` — the decoded [`ReasonFlags`] if `onlySomeReasons` `[3]`
///   was present (as an `Option<ReasonFlags>`, per R5 rather than a
///   sentinel 0 value).
///
/// # Errors
///
/// Returns `CryptoError::Encoding` on malformed DER, invalid BOOLEAN
/// encoding, or semantically inconsistent data (e.g., multiple
/// `onlyContains*` flags set to TRUE).
///
/// # Rule compliance
///
/// * R5: `onlySomeReasons` maps to `Option<ReasonFlags>` (not 0-sentinel).
/// * R6: all length arithmetic uses `checked_add`.
/// * R8: no `unsafe`.
#[allow(clippy::too_many_lines)]
fn parse_idp_extension(
    value: &[u8],
) -> CryptoResult<(IssuingDistPoint, IdpFlags, Option<ReasonFlags>)> {
    let outer = parse_tlv_header(value)?;
    if outer.tag != Asn1Tag::Sequence || outer.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_idp_extension: expected Universal SEQUENCE, got tag={:?} class={:?}",
            outer.tag, outer.class
        )));
    }
    if !outer.constructed {
        return Err(CryptoError::Encoding(
            "parse_idp_extension: SEQUENCE must be constructed".into(),
        ));
    }
    let outer_content_len = outer.content_length.ok_or_else(|| {
        CryptoError::Encoding(
            "parse_idp_extension: indefinite length not allowed for DER SEQUENCE".into(),
        )
    })?;
    let content_start = outer.header_length;
    let content_end = content_start
        .checked_add(outer_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_idp_extension: length overflow".into()))?;
    if content_end > value.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_idp_extension: truncated SEQUENCE (need {content_end} bytes, have {})",
            value.len()
        )));
    }

    let mut idp = IssuingDistPoint::empty();
    let mut flags = IdpFlags::empty();
    let mut reasons: Option<ReasonFlags> = None;
    let mut cursor = content_start;

    while cursor < content_end {
        let remaining = &value[cursor..content_end];
        let hdr = parse_tlv_header(remaining)?;
        let inner_content_len = hdr.content_length.ok_or_else(|| {
            CryptoError::Encoding("parse_idp_extension: indefinite length in inner field".into())
        })?;
        let inner_start = cursor
            .checked_add(hdr.header_length)
            .ok_or_else(|| CryptoError::Encoding("parse_idp_extension: overflow".into()))?;
        let inner_end = inner_start
            .checked_add(inner_content_len)
            .ok_or_else(|| CryptoError::Encoding("parse_idp_extension: overflow".into()))?;
        if inner_end > content_end {
            return Err(CryptoError::Encoding(format!(
                "parse_idp_extension: inner field exceeds SEQUENCE bounds \
                 (need {inner_end}, have {content_end})"
            )));
        }

        if hdr.class != Asn1Class::ContextSpecific {
            debug!(
                tag = ?hdr.tag,
                class = ?hdr.class,
                "parse_idp_extension: ignoring unexpected non-context field"
            );
            cursor = inner_end;
            continue;
        }

        // Extract raw context-specific tag number from the identifier byte.
        let tag_num = value[cursor] & 0x1F;
        let content = &value[inner_start..inner_end];

        match tag_num {
            0 => {
                // [0] distributionPoint — EXPLICIT DistributionPointName.
                // The DistributionPointName itself is a CHOICE, so the
                // content is the raw (possibly nested) DER of the CHOICE
                // alternative. We stash the raw bytes for higher-layer
                // consumers; the IssuingDistPoint user can further decode
                // the GeneralName tree if needed.
                idp.distribution_point = Some(content.to_vec());
            }
            1 => {
                // [1] onlyContainsUserCerts — IMPLICIT BOOLEAN.
                idp.only_contains_user_certs = decode_implicit_boolean(content)?;
                if idp.only_contains_user_certs {
                    flags.insert(IdpFlags::IDP_ONLY_USER);
                }
            }
            2 => {
                // [2] onlyContainsCACerts — IMPLICIT BOOLEAN.
                idp.only_contains_ca_certs = decode_implicit_boolean(content)?;
                if idp.only_contains_ca_certs {
                    flags.insert(IdpFlags::IDP_ONLY_CA);
                }
            }
            3 => {
                // [3] onlySomeReasons — IMPLICIT BIT STRING (ReasonFlags).
                //
                // RFC 5280 defines ReasonFlags as a BIT STRING with named
                // bits; the DER encoding of a BIT STRING prefixes the
                // content with a single "unused bits" octet followed by
                // the significant bytes, MSB-first.  We decode up to 16
                // bits into the ReasonFlags bitfield (u16).
                let reason_bits = decode_implicit_bit_string_u16(content)?;
                let r = ReasonFlags::from_bits_truncate(reason_bits);
                idp.only_some_reasons = Some(r);
                reasons = Some(r);
                flags.insert(IdpFlags::IDP_REASONS);
            }
            4 => {
                // [4] indirectCRL — IMPLICIT BOOLEAN.
                idp.indirect_crl = decode_implicit_boolean(content)?;
                if idp.indirect_crl {
                    flags.insert(IdpFlags::IDP_INDIRECT);
                }
            }
            5 => {
                // [5] onlyContainsAttributeCerts — IMPLICIT BOOLEAN.
                idp.only_contains_attribute_certs = decode_implicit_boolean(content)?;
                if idp.only_contains_attribute_certs {
                    flags.insert(IdpFlags::IDP_ONLY_ATTR);
                }
            }
            _ => {
                debug!(
                    tag = tag_num,
                    "parse_idp_extension: ignoring unknown context-specific field"
                );
            }
        }

        cursor = inner_end;
    }

    // RFC 5280 §5.2.5 semantic check: at most one of
    // onlyContainsUserCerts, onlyContainsCACerts, onlyContainsAttributeCerts
    // may be TRUE.  Violating this is an encoding error, not merely a
    // warning — CAs producing such CRLs are non-conformant.
    let set_count = u32::from(idp.only_contains_user_certs)
        + u32::from(idp.only_contains_ca_certs)
        + u32::from(idp.only_contains_attribute_certs);
    if set_count > 1 {
        return Err(CryptoError::Encoding(
            "parse_idp_extension: at most one of onlyContainsUserCerts / \
             onlyContainsCACerts / onlyContainsAttributeCerts may be TRUE (RFC 5280 §5.2.5)"
                .into(),
        ));
    }

    Ok((idp, flags, reasons))
}

/// Decode a DER BOOLEAN payload given only its content bytes (the outer
/// TLV has already been stripped).
///
/// Per X.690 §8.2, the DER BOOLEAN encoding is a single content octet:
/// `0x00` → FALSE, `0xFF` → TRUE. (BER permits any non-zero byte to mean
/// TRUE, but DER insists on exactly `0xFF`; we accept any non-zero byte
/// here for interop with BER-encoded inputs, matching OpenSSL behaviour.)
///
/// # Errors
///
/// `CryptoError::Encoding` if the content is not exactly 1 byte.
fn decode_implicit_boolean(content: &[u8]) -> CryptoResult<bool> {
    if content.len() != 1 {
        return Err(CryptoError::Encoding(format!(
            "decode_implicit_boolean: BOOLEAN must be 1 content byte, got {}",
            content.len()
        )));
    }
    Ok(content[0] != 0)
}

/// Decode the content bytes of an IMPLICIT BIT STRING into a `u16`,
/// interpreting each bit left-to-right (MSB-first) as bits 0, 1, 2, ...
/// in the returned `u16` (little-endian bit numbering matching
/// [`ReasonFlags`]).
///
/// A DER BIT STRING begins with a single "unused bits" octet indicating
/// how many least-significant bits of the final content octet are padding.
/// We ignore those padding bits when populating the `u16`.
///
/// # Errors
///
/// `CryptoError::Encoding` if the BIT STRING is empty (zero content bytes
/// is invalid — at minimum the unused-bits octet must be present) or
/// if the unused-bits count exceeds 7.
fn decode_implicit_bit_string_u16(content: &[u8]) -> CryptoResult<u16> {
    if content.is_empty() {
        return Err(CryptoError::Encoding(
            "decode_implicit_bit_string_u16: BIT STRING content is empty".into(),
        ));
    }
    let unused_bits = content[0];
    if unused_bits > 7 {
        return Err(CryptoError::Encoding(format!(
            "decode_implicit_bit_string_u16: invalid unused-bits count {unused_bits}"
        )));
    }
    let bit_bytes = &content[1..];

    // Walk each bit of the BIT STRING MSB-first. Bit position 0 in the
    // ReasonFlags (UNUSED at 0x0001) corresponds to the leftmost bit of
    // the first byte, per RFC 5280 §5.3.1.
    let mut out: u16 = 0;
    // Total number of significant bits in the BIT STRING
    let total_bits = bit_bytes
        .len()
        .saturating_mul(8)
        .saturating_sub(usize::from(unused_bits));
    for bit_index in 0..total_bits {
        if bit_index >= 16 {
            // Ignore bits beyond u16 capacity — any additional reason
            // codes beyond those defined in the enum are simply dropped.
            break;
        }
        let byte_index = bit_index / 8;
        let bit_in_byte = 7u32.saturating_sub(u32::try_from(bit_index % 8).map_err(|_| {
            CryptoError::Encoding(
                "decode_implicit_bit_string_u16: bit-index arithmetic overflow".into(),
            )
        })?);
        let byte = bit_bytes[byte_index];
        if (byte >> bit_in_byte) & 0x01 != 0 {
            // The u16 is organised so that ReasonFlags::UNUSED (0x0001)
            // corresponds to bit_index 0, KEY_COMPROMISE (0x0002) to
            // bit_index 1, etc. We therefore OR in `1 << bit_index`.
            let bit_index_u16 = u16::try_from(bit_index).map_err(|_| {
                CryptoError::Encoding(
                    "decode_implicit_bit_string_u16: bit-index arithmetic overflow".into(),
                )
            })?;
            out |= 1u16 << bit_index_u16;
        }
    }
    Ok(out)
}

/// Decode a PEM document containing a single Base64 payload, accepting any
/// of the supplied label strings for the BEGIN/END markers.
///
/// Replaces OpenSSL's `PEM_read_bio_X509_CRL` / `PEM_bytes_read_bio` glue
/// specifically for CRL parsing (label strings are passed explicitly
/// rather than looked up from an internal table).
///
/// # Accepted format (RFC 7468)
///
/// ```text
/// -----BEGIN <LABEL>-----
/// <base64-payload, any whitespace ignored>
/// -----END <LABEL>-----
/// ```
///
/// where `<LABEL>` must match one of the entries in `labels` exactly and
/// the BEGIN/END labels must agree with each other.
///
/// # Base64 decoding
///
/// The body is Base64-decoded using the alphabet `A-Z a-z 0-9 + /` with
/// `=` padding. Whitespace (spaces, tabs, CR, LF) within the body is
/// silently ignored. Any other character produces `CryptoError::Encoding`.
///
/// # Errors
///
/// * `CryptoError::Encoding` if the BEGIN/END markers are missing or
///   mismatched, if the label is not one of those provided, or if the
///   Base64 payload is malformed.
///
/// # Rule compliance
///
/// * R6: all numeric conversions use `try_from` / `u32::from`.
/// * R8: no `unsafe`.
fn decode_pem(pem: &str, labels: &[&str]) -> CryptoResult<Vec<u8>> {
    // Locate BEGIN header.
    let begin_prefix = "-----BEGIN ";
    let begin_suffix = "-----";
    let begin_idx = pem
        .find(begin_prefix)
        .ok_or_else(|| CryptoError::Encoding("decode_pem: missing '-----BEGIN ' header".into()))?;
    let after_begin_prefix = begin_idx
        .checked_add(begin_prefix.len())
        .ok_or_else(|| CryptoError::Encoding("decode_pem: offset overflow".into()))?;
    let label_end_rel = pem[after_begin_prefix..]
        .find(begin_suffix)
        .ok_or_else(|| {
            CryptoError::Encoding("decode_pem: BEGIN header not terminated with '-----'".into())
        })?;
    let label_end = after_begin_prefix
        .checked_add(label_end_rel)
        .ok_or_else(|| CryptoError::Encoding("decode_pem: offset overflow".into()))?;
    let begin_label = &pem[after_begin_prefix..label_end];
    if !labels.iter().any(|lbl| *lbl == begin_label) {
        return Err(CryptoError::Encoding(format!(
            "decode_pem: PEM label '{begin_label}' does not match any of {labels:?}"
        )));
    }
    // Advance past the closing '-----' of the BEGIN header.
    let body_start = label_end
        .checked_add(begin_suffix.len())
        .ok_or_else(|| CryptoError::Encoding("decode_pem: offset overflow".into()))?;

    // Locate END header.
    let end_prefix = "-----END ";
    let end_idx_rel = pem[body_start..]
        .find(end_prefix)
        .ok_or_else(|| CryptoError::Encoding("decode_pem: missing '-----END ' footer".into()))?;
    let end_idx = body_start
        .checked_add(end_idx_rel)
        .ok_or_else(|| CryptoError::Encoding("decode_pem: offset overflow".into()))?;
    let after_end_prefix = end_idx
        .checked_add(end_prefix.len())
        .ok_or_else(|| CryptoError::Encoding("decode_pem: offset overflow".into()))?;
    let end_label_end_rel = pem[after_end_prefix..].find(begin_suffix).ok_or_else(|| {
        CryptoError::Encoding("decode_pem: END footer not terminated with '-----'".into())
    })?;
    let end_label_end = after_end_prefix
        .checked_add(end_label_end_rel)
        .ok_or_else(|| CryptoError::Encoding("decode_pem: offset overflow".into()))?;
    let end_label = &pem[after_end_prefix..end_label_end];
    if end_label != begin_label {
        return Err(CryptoError::Encoding(format!(
            "decode_pem: BEGIN/END label mismatch ('{begin_label}' vs '{end_label}')"
        )));
    }

    let body = &pem[body_start..end_idx];
    base64_decode(body)
}

/// Encode a binary payload as a PEM document with the given label.
///
/// Replaces OpenSSL's `PEM_write_bio_X509_CRL` / `PEM_encode` for the
/// specific case of writing an `X509 CRL` payload.
///
/// # Output format (RFC 7468)
///
/// ```text
/// -----BEGIN <LABEL>-----
/// <base64, 64-character lines>
/// -----END <LABEL>-----
/// ```
///
/// The body is hard-wrapped at 64 characters per line, matching OpenSSL's
/// historical output and RFC 7468's recommendation.
#[must_use]
fn encode_pem(der: &[u8], label: &str) -> String {
    let body = base64_encode(der);
    // Pre-allocate a String sized generously: header + base64 body with
    // line breaks + footer + some slack.
    let approx_lines = body.len().saturating_div(64).saturating_add(1);
    let mut out =
        String::with_capacity(body.len().saturating_add(approx_lines).saturating_add(128));
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let mut idx = 0usize;
    while idx < body.len() {
        let end = idx.saturating_add(64).min(body.len());
        out.push_str(&body[idx..end]);
        out.push('\n');
        idx = end;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Base64-encode a byte slice using the standard alphabet
/// `A-Z a-z 0-9 + /` with `=` padding. The output is a single
/// unbroken line (no embedded whitespace); callers that require
/// line wrapping must apply it themselves.
#[must_use]
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out_len = bytes.len().div_ceil(3).saturating_mul(4);
    let mut out = String::with_capacity(out_len);
    let chunks = bytes.chunks_exact(3);
    let remainder = chunks.remainder();
    for ch in chunks {
        // Each 3-byte chunk becomes 4 Base64 characters.
        let b0 = u32::from(ch[0]);
        let b1 = u32::from(ch[1]);
        let b2 = u32::from(ch[2]);
        let n = (b0 << 16) | (b1 << 8) | b2;
        // Indices are in 0..64, so indexing into ALPHABET is safe.
        // Fallback `?` is defensive only; never reachable.
        let i0 = usize::try_from((n >> 18) & 0x3F).unwrap_or(0);
        let i1 = usize::try_from((n >> 12) & 0x3F).unwrap_or(0);
        let i2 = usize::try_from((n >> 6) & 0x3F).unwrap_or(0);
        let i3 = usize::try_from(n & 0x3F).unwrap_or(0);
        out.push(char::from(ALPHABET[i0]));
        out.push(char::from(ALPHABET[i1]));
        out.push(char::from(ALPHABET[i2]));
        out.push(char::from(ALPHABET[i3]));
    }
    match remainder.len() {
        0 => {}
        1 => {
            let b0 = u32::from(remainder[0]);
            let n = b0 << 16;
            let i0 = usize::try_from((n >> 18) & 0x3F).unwrap_or(0);
            let i1 = usize::try_from((n >> 12) & 0x3F).unwrap_or(0);
            out.push(char::from(ALPHABET[i0]));
            out.push(char::from(ALPHABET[i1]));
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = u32::from(remainder[0]);
            let b1 = u32::from(remainder[1]);
            let n = (b0 << 16) | (b1 << 8);
            let i0 = usize::try_from((n >> 18) & 0x3F).unwrap_or(0);
            let i1 = usize::try_from((n >> 12) & 0x3F).unwrap_or(0);
            let i2 = usize::try_from((n >> 6) & 0x3F).unwrap_or(0);
            out.push(char::from(ALPHABET[i0]));
            out.push(char::from(ALPHABET[i1]));
            out.push(char::from(ALPHABET[i2]));
            out.push('=');
        }
        _ => {
            // Unreachable: chunks_exact(3).remainder() length is always
            // strictly less than 3.
            debug!("base64_encode: unreachable remainder length");
        }
    }
    out
}

/// Base64-decode a string slice using the standard alphabet.
///
/// All ASCII whitespace characters (space, tab, CR, LF) are silently
/// skipped. The `=` padding character is accepted at the end of the
/// payload and produces no output bytes.
///
/// # Errors
///
/// `CryptoError::Encoding` if the input contains any character outside
/// the standard Base64 alphabet (excluding whitespace and `=`) or if the
/// total number of meaningful characters is not a multiple of 4.
fn base64_decode(s: &str) -> CryptoResult<Vec<u8>> {
    /// Maps each of the 256 possible input bytes to its Base64 numeric
    /// value (0..64), 0xFE for whitespace (skipped), 0xFD for `=`
    /// (padding), or 0xFF for invalid characters.
    const DECODE_TABLE: [u8; 256] = {
        let mut t = [0xFF_u8; 256];
        // A-Z → 0..26
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            i += 1;
        }
        // a-z → 26..52
        i = 0;
        while i < 26 {
            t[(b'a' + i) as usize] = 26 + i;
            i += 1;
        }
        // 0-9 → 52..62
        i = 0;
        while i < 10 {
            t[(b'0' + i) as usize] = 52 + i;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t[b'=' as usize] = 0xFD;
        t[b' ' as usize] = 0xFE;
        t[b'\t' as usize] = 0xFE;
        t[b'\r' as usize] = 0xFE;
        t[b'\n' as usize] = 0xFE;
        t
    };

    let mut buf = [0u8; 4];
    let mut buf_len = 0usize;
    let mut padding_seen = 0usize;
    let mut out: Vec<u8> = Vec::with_capacity(s.len().saturating_mul(3).saturating_div(4));

    for &byte in s.as_bytes() {
        let entry = DECODE_TABLE[usize::from(byte)];
        match entry {
            0xFE => continue, // whitespace — skip
            0xFD => {
                // padding
                padding_seen = padding_seen.saturating_add(1);
                if padding_seen > 2 {
                    return Err(CryptoError::Encoding(
                        "base64_decode: too many '=' padding characters".into(),
                    ));
                }
                buf[buf_len] = 0;
                buf_len = buf_len.saturating_add(1);
            }
            0xFF => {
                return Err(CryptoError::Encoding(format!(
                    "base64_decode: invalid character 0x{byte:02x}"
                )));
            }
            v => {
                if padding_seen > 0 {
                    return Err(CryptoError::Encoding(
                        "base64_decode: non-padding character after '=' padding".into(),
                    ));
                }
                buf[buf_len] = v;
                buf_len = buf_len.saturating_add(1);
            }
        }

        if buf_len == 4 {
            // Decode a quartet.
            let n = (u32::from(buf[0]) << 18)
                | (u32::from(buf[1]) << 12)
                | (u32::from(buf[2]) << 6)
                | u32::from(buf[3]);
            // Each of the three extracted bytes fits in a u8. The mask
            // guarantees the value is in 0..=255, so `try_from` will
            // always succeed — but per R6 we use it rather than `as`.
            let byte0 = u8::try_from((n >> 16) & 0xFF)
                .map_err(|_| CryptoError::Encoding("base64_decode: byte0 overflow".into()))?;
            let byte1 = u8::try_from((n >> 8) & 0xFF)
                .map_err(|_| CryptoError::Encoding("base64_decode: byte1 overflow".into()))?;
            let byte2 = u8::try_from(n & 0xFF)
                .map_err(|_| CryptoError::Encoding("base64_decode: byte2 overflow".into()))?;
            out.push(byte0);
            if padding_seen < 2 {
                out.push(byte1);
            }
            if padding_seen < 1 {
                out.push(byte2);
            }
            buf_len = 0;
        }
    }

    if buf_len != 0 {
        return Err(CryptoError::Encoding(format!(
            "base64_decode: residual {buf_len} characters (Base64 input length must be a multiple of 4)"
        )));
    }
    Ok(out)
}

/// Parse a DER-encoded X.509 `CertificateList` (CRL) per RFC 5280 §5.1.
///
/// This is the primary private helper behind [`X509Crl::from_der`] and
/// corresponds to the OpenSSL C function `d2i_X509_CRL` together with the
/// decode callbacks `crl_cb` and `crl_inf_cb` from `crypto/x509/x_crl.c`.
///
/// # ASN.1 structure (RFC 5280 §5.1)
///
/// ```text
/// CertificateList ::= SEQUENCE {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
///
/// TBSCertList ::= SEQUENCE {
///     version                 Version OPTIONAL,           -- v2
///     signature               AlgorithmIdentifier,
///     issuer                  Name,
///     thisUpdate              Time,
///     nextUpdate              Time OPTIONAL,
///     revokedCertificates     SEQUENCE OF RevokedEntry OPTIONAL,
///     crlExtensions       [0] EXPLICIT Extensions OPTIONAL  -- v2 only
/// }
///
/// RevokedEntry ::= SEQUENCE {
///     userCertificate         CertificateSerialNumber,
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
/// }
/// ```
///
/// # Returned value
///
/// The parsed [`X509Crl`] is returned in its **raw** form — no extension
/// caching has been performed. Callers who need cached AKID/IDP/CRL-number/
/// delta-indicator values must invoke the crate-internal
/// `cache_extensions` routine (Section 12) as a subsequent step.  This
/// mirrors the C `X509_CRL` two-stage lifecycle where the decode callback
/// first materialises the raw fields and `crl_set_issuers`/extension
/// caches run afterwards.
///
/// # Errors
///
/// Returns `CryptoError::Encoding` for any malformed DER (wrong tags,
/// truncated content, indefinite lengths, overflow in length arithmetic).
///
/// # Rule compliance
///
/// * R5: `version` and `next_update` become `Option<...>` rather than
///   sentinel values.
/// * R6: all length arithmetic uses `checked_add`; no bare `as`.
/// * R8: no `unsafe`.
#[allow(clippy::too_many_lines)]
fn parse_crl_der(der: &[u8]) -> CryptoResult<X509Crl> {
    // --- Step 1: outer CertificateList SEQUENCE ---
    let outer = parse_tlv_header(der)?;
    if outer.tag != Asn1Tag::Sequence || outer.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: outer is not a Universal SEQUENCE (tag={:?} class={:?})",
            outer.tag, outer.class
        )));
    }
    if !outer.constructed {
        return Err(CryptoError::Encoding(
            "parse_crl_der: outer SEQUENCE must be constructed".into(),
        ));
    }
    let outer_content_len = outer.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_crl_der: indefinite length not allowed in DER".into())
    })?;
    let outer_start = outer.header_length;
    let outer_end = outer_start
        .checked_add(outer_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: length overflow".into()))?;
    if outer_end > der.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: outer SEQUENCE truncated (need {outer_end}, have {})",
            der.len()
        )));
    }

    // --- Step 2: tbsCertList (inner SEQUENCE) ---
    let tbs_bytes = &der[outer_start..outer_end];
    let tbs_hdr = parse_tlv_header(tbs_bytes)?;
    if tbs_hdr.tag != Asn1Tag::Sequence || tbs_hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: tbsCertList is not a Universal SEQUENCE (tag={:?})",
            tbs_hdr.tag
        )));
    }
    let tbs_content_len = tbs_hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_crl_der: tbsCertList indefinite length".into())
    })?;
    let tbs_total_len = tbs_hdr
        .header_length
        .checked_add(tbs_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: TBS length overflow".into()))?;
    if tbs_total_len > tbs_bytes.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: tbsCertList truncated (need {tbs_total_len}, have {})",
            tbs_bytes.len()
        )));
    }
    // Capture the RAW DER of tbsCertList (header + content) for later
    // use by signature verification.
    let tbs_der_slice = &tbs_bytes[..tbs_total_len];
    let tbs_der_vec = tbs_der_slice.to_vec();

    // Cursor within tbsCertList content.
    let tbs_content_start = tbs_hdr.header_length;
    let tbs_content_end = tbs_total_len;
    let mut cursor = tbs_content_start;

    // --- Step 2a: optional version (INTEGER) ---
    //
    // Per RFC 5280, `version` is OPTIONAL and defaults to v1 (value 0).
    // When present, it appears as the first field and is always an
    // INTEGER. We peek at the first element and consume it only if it
    // is an INTEGER.
    let mut version: Option<u32> = None;
    if cursor < tbs_content_end {
        let peek = parse_tlv_header(&tbs_bytes[cursor..tbs_content_end])?;
        if peek.tag == Asn1Tag::Integer && peek.class == Asn1Class::Universal {
            let vlen = peek.content_length.ok_or_else(|| {
                CryptoError::Encoding("parse_crl_der: version field has indefinite length".into())
            })?;
            let vstart = cursor
                .checked_add(peek.header_length)
                .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
            let vend = vstart
                .checked_add(vlen)
                .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
            if vend > tbs_content_end {
                return Err(CryptoError::Encoding(
                    "parse_crl_der: version field exceeds TBS bounds".into(),
                ));
            }
            // Decode the INTEGER value into a u32. Versions defined in
            // RFC 5280 are only 0 (v1) and 1 (v2); we allow up to u32::MAX
            // for forward-compat but convert in a lossless manner per R6.
            let version_value = decode_small_integer_u32(&tbs_bytes[vstart..vend])?;
            // RFC 5280 §5.1.2.1: version 0 (v1) SHOULD NOT appear
            // explicitly, but when it does we still treat it as v1.
            // Per R5, map version 0 → None (v1 default), otherwise
            // Some(n).
            version = if version_value == 0 {
                None
            } else {
                Some(version_value)
            };
            cursor = vend;
        }
    }

    // --- Step 2b: signature (AlgorithmIdentifier) ---
    if cursor >= tbs_content_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: missing tbsCertList.signature field".into(),
        ));
    }
    let (inner_sig_alg, inner_sig_alg_len) =
        parse_algorithm_identifier(&tbs_bytes[cursor..tbs_content_end])?;
    cursor = cursor
        .checked_add(inner_sig_alg_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;

    // --- Step 2c: issuer Name ---
    if cursor >= tbs_content_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: missing tbsCertList.issuer field".into(),
        ));
    }
    let issuer_hdr = parse_tlv_header(&tbs_bytes[cursor..tbs_content_end])?;
    if issuer_hdr.tag != Asn1Tag::Sequence || issuer_hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: issuer is not a Universal SEQUENCE (tag={:?})",
            issuer_hdr.tag
        )));
    }
    let issuer_content_len = issuer_hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_crl_der: issuer has indefinite length".into())
    })?;
    let issuer_total_len = issuer_hdr
        .header_length
        .checked_add(issuer_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
    let issuer_end = cursor
        .checked_add(issuer_total_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
    if issuer_end > tbs_content_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: issuer exceeds TBS bounds".into(),
        ));
    }
    let issuer_der = tbs_bytes[cursor..issuer_end].to_vec();
    let issuer = X509Name::from_der(issuer_der);
    cursor = issuer_end;

    // --- Step 2d: thisUpdate Time ---
    if cursor >= tbs_content_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: missing tbsCertList.thisUpdate field".into(),
        ));
    }
    let (last_update, last_update_len) = parse_time_field(&tbs_bytes[cursor..tbs_content_end])?;
    cursor = cursor
        .checked_add(last_update_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;

    // --- Step 2e: optional nextUpdate Time ---
    //
    // `nextUpdate` is OPTIONAL. It appears before the optional
    // `revokedCertificates` SEQUENCE and before the `[0]` tagged
    // extensions. We peek at the next element and consume it only if
    // it is a UTCTime or GeneralizedTime.
    let mut next_update: Option<Asn1Time> = None;
    if cursor < tbs_content_end {
        let peek = parse_tlv_header(&tbs_bytes[cursor..tbs_content_end])?;
        if peek.class == Asn1Class::Universal
            && (peek.tag == Asn1Tag::UtcTime || peek.tag == Asn1Tag::GeneralizedTime)
        {
            let (nu, nu_len) = parse_time_field(&tbs_bytes[cursor..tbs_content_end])?;
            next_update = Some(nu);
            cursor = cursor
                .checked_add(nu_len)
                .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
        }
    }

    // --- Step 2f: optional revokedCertificates SEQUENCE ---
    let mut revoked: Vec<RevokedEntry> = Vec::new();
    if cursor < tbs_content_end {
        let peek = parse_tlv_header(&tbs_bytes[cursor..tbs_content_end])?;
        // The revoked list is a Universal SEQUENCE. Distinguish from the
        // extensions field, which uses ContextSpecific [0].
        if peek.class == Asn1Class::Universal && peek.tag == Asn1Tag::Sequence {
            let rev_content_len = peek.content_length.ok_or_else(|| {
                CryptoError::Encoding("parse_crl_der: revoked list indefinite length".into())
            })?;
            let rev_content_start = cursor
                .checked_add(peek.header_length)
                .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
            let rev_content_end = rev_content_start
                .checked_add(rev_content_len)
                .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
            if rev_content_end > tbs_content_end {
                return Err(CryptoError::Encoding(
                    "parse_crl_der: revoked list exceeds TBS bounds".into(),
                ));
            }
            revoked = parse_revoked_list(&tbs_bytes[rev_content_start..rev_content_end])?;
            cursor = rev_content_end;
        }
    }

    // --- Step 2g: optional crlExtensions [0] EXPLICIT Extensions ---
    let mut extensions: Vec<X509Extension> = Vec::new();
    if cursor < tbs_content_end {
        let peek = parse_tlv_header(&tbs_bytes[cursor..tbs_content_end])?;
        if peek.class == Asn1Class::ContextSpecific {
            let ext_tag_num = tbs_bytes[cursor] & 0x1F;
            if ext_tag_num == 0 {
                // [0] EXPLICIT — the tag-byte wraps a Universal SEQUENCE
                // of Extensions.
                let ext_content_len = peek.content_length.ok_or_else(|| {
                    CryptoError::Encoding(
                        "parse_crl_der: extensions [0] has indefinite length".into(),
                    )
                })?;
                let ext_content_start = cursor
                    .checked_add(peek.header_length)
                    .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
                let ext_content_end = ext_content_start
                    .checked_add(ext_content_len)
                    .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
                if ext_content_end > tbs_content_end {
                    return Err(CryptoError::Encoding(
                        "parse_crl_der: extensions [0] exceeds TBS bounds".into(),
                    ));
                }
                extensions =
                    parse_extensions_sequence(&tbs_bytes[ext_content_start..ext_content_end])?;
                cursor = ext_content_end;
            }
        }
    }

    // Trailing bytes within TBS are not allowed.
    if cursor != tbs_content_end {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: {} bytes of trailing data in tbsCertList",
            tbs_content_end.saturating_sub(cursor)
        )));
    }

    // --- Step 3: signatureAlgorithm (AlgorithmIdentifier) ---
    let outer_after_tbs = outer_start
        .checked_add(tbs_total_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
    if outer_after_tbs >= outer_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: missing signatureAlgorithm field".into(),
        ));
    }
    let (outer_sig_alg, outer_sig_alg_len) =
        parse_algorithm_identifier(&der[outer_after_tbs..outer_end])?;
    let after_outer_sig_alg = outer_after_tbs
        .checked_add(outer_sig_alg_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;

    // --- Step 4: signatureValue (BIT STRING) ---
    if after_outer_sig_alg >= outer_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: missing signatureValue field".into(),
        ));
    }
    let sig_hdr = parse_tlv_header(&der[after_outer_sig_alg..outer_end])?;
    if sig_hdr.tag != Asn1Tag::BitString || sig_hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: signatureValue is not a Universal BIT STRING (tag={:?})",
            sig_hdr.tag
        )));
    }
    let sig_content_len = sig_hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_crl_der: signatureValue has indefinite length".into())
    })?;
    let sig_content_start = after_outer_sig_alg
        .checked_add(sig_hdr.header_length)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
    let sig_content_end = sig_content_start
        .checked_add(sig_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?;
    if sig_content_end > outer_end {
        return Err(CryptoError::Encoding(
            "parse_crl_der: signatureValue exceeds outer bounds".into(),
        ));
    }
    // The BIT STRING content is [unused-bits-byte] [payload-bytes...].
    // For a DSA/RSA/ECDSA signature the unused-bits byte is 0.
    if sig_content_len == 0 {
        return Err(CryptoError::Encoding(
            "parse_crl_der: signatureValue has zero-length content".into(),
        ));
    }
    let unused_bits = der[sig_content_start];
    if unused_bits != 0 {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: signatureValue unused-bits byte must be 0, got {unused_bits}"
        )));
    }
    let signature_bytes = der[sig_content_start
        .checked_add(1)
        .ok_or_else(|| CryptoError::Encoding("parse_crl_der: overflow".into()))?
        ..sig_content_end]
        .to_vec();

    // Trailing bytes in outer CertificateList are not allowed.
    if sig_content_end != outer_end {
        return Err(CryptoError::Encoding(format!(
            "parse_crl_der: {} bytes of trailing data in CertificateList",
            outer_end.saturating_sub(sig_content_end)
        )));
    }

    // Per RFC 5280 §5.1.1.2 the signatureAlgorithm in TBSCertList must
    // match the outer signatureAlgorithm. Mismatch indicates tampering
    // and is a parse error.
    if !algorithm_identifiers_match(&inner_sig_alg, &outer_sig_alg) {
        return Err(CryptoError::Encoding(
            "parse_crl_der: tbsCertList.signature does not match CertificateList.signatureAlgorithm"
                .into(),
        ));
    }

    // --- Assemble the result ---
    let info = CrlInfo {
        version,
        signature_algorithm: inner_sig_alg,
        issuer,
        last_update,
        next_update,
        revoked,
        extensions,
        tbs_der: tbs_der_vec,
    };

    debug!(
        tbs_bytes = info.tbs_der.len(),
        revoked_count = info.revoked.len(),
        ext_count = info.extensions.len(),
        "parse_crl_der: successfully parsed CRL"
    );

    Ok(X509Crl {
        info,
        signature_algorithm: outer_sig_alg,
        signature: signature_bytes,
        der_encoded: der[..outer_end].to_vec(),
        akid: None,
        idp: None,
        crl_number: None,
        delta_crl_indicator: None,
        idp_reasons: ReasonFlags::ALL_REASONS,
        flags: CrlFlags::empty(),
        idp_flags: IdpFlags::empty(),
    })
}

/// Decode a DER INTEGER payload (content bytes only) into a `u32`.
///
/// Used by [`parse_crl_der`] to decode the CRL version field. Rejects
/// negative values (DER INTEGER would need a leading sign byte) and
/// values exceeding `u32::MAX`.
///
/// # Errors
///
/// `CryptoError::Encoding` if the content is empty, if its top bit
/// indicates a negative value, or if the magnitude exceeds `u32::MAX`.
fn decode_small_integer_u32(content: &[u8]) -> CryptoResult<u32> {
    if content.is_empty() {
        return Err(CryptoError::Encoding(
            "decode_small_integer_u32: INTEGER content is empty".into(),
        ));
    }
    if content[0] & 0x80 != 0 {
        return Err(CryptoError::Encoding(
            "decode_small_integer_u32: negative INTEGER not supported for version field".into(),
        ));
    }
    // Strip leading zero byte if present (DER canonical form for
    // integers whose MSB would otherwise be 1 — not expected for
    // CRL versions but harmless to accept).
    let effective = if content.len() > 1 && content[0] == 0 {
        &content[1..]
    } else {
        content
    };
    if effective.len() > 4 {
        return Err(CryptoError::Encoding(format!(
            "decode_small_integer_u32: INTEGER too large for u32 ({} bytes)",
            effective.len()
        )));
    }
    let mut v: u32 = 0;
    for &byte in effective {
        v = v
            .checked_shl(8)
            .ok_or_else(|| {
                CryptoError::Encoding("decode_small_integer_u32: shift overflow".into())
            })?
            .checked_add(u32::from(byte))
            .ok_or_else(|| {
                CryptoError::Encoding("decode_small_integer_u32: addition overflow".into())
            })?;
    }
    Ok(v)
}

/// Parse an [`AlgorithmIdentifier`] SEQUENCE from the front of `data`
/// and return it together with the total number of bytes consumed (the
/// full TLV length, i.e., `header_length + content_length`).
///
/// `AlgorithmIdentifier::decode_der` expects the SEQUENCE *content*
/// bytes (not the full TLV), so we strip the outer header before
/// delegating.
///
/// # Errors
///
/// Propagates any error returned by [`AlgorithmIdentifier::decode_der`]
/// and by [`parse_tlv_header`].
fn parse_algorithm_identifier(data: &[u8]) -> CryptoResult<(AlgorithmIdentifier, usize)> {
    let hdr = parse_tlv_header(data)?;
    if hdr.tag != Asn1Tag::Sequence || hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_algorithm_identifier: expected Universal SEQUENCE, got tag={:?} class={:?}",
            hdr.tag, hdr.class
        )));
    }
    let content_len = hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_algorithm_identifier: indefinite length not allowed".into())
    })?;
    let total_len = hdr.header_length.checked_add(content_len).ok_or_else(|| {
        CryptoError::Encoding("parse_algorithm_identifier: length overflow".into())
    })?;
    if total_len > data.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_algorithm_identifier: truncated (need {total_len}, have {})",
            data.len()
        )));
    }
    let content_start = hdr.header_length;
    let content_end = total_len;
    let alg = AlgorithmIdentifier::decode_der(&data[content_start..content_end])?;
    Ok((alg, total_len))
}

/// Parse a `Time` field (`UTCTime` or `GeneralizedTime`) from the front of
/// `data` and return the decoded [`Asn1Time`] together with the total
/// number of bytes consumed.
///
/// Per RFC 5280 §4.1.2.5, `Time` is a CHOICE of `UTCTime` (for dates
/// through 2049) and `GeneralizedTime` (for 2050 and beyond). Both
/// alternatives are accepted here; [`Asn1Time::decode_der`] infers the
/// format from the *content* byte length (12 bytes = `UTCTime`,
/// 14 bytes = `GeneralizedTime`), so we pass only the content slice.
///
/// # Errors
///
/// Propagates any error returned by [`Asn1Time::decode_der`] and by
/// [`parse_tlv_header`].
fn parse_time_field(data: &[u8]) -> CryptoResult<(Asn1Time, usize)> {
    let hdr = parse_tlv_header(data)?;
    if hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_time_field: expected Universal class, got {:?}",
            hdr.class
        )));
    }
    if hdr.tag != Asn1Tag::UtcTime && hdr.tag != Asn1Tag::GeneralizedTime {
        return Err(CryptoError::Encoding(format!(
            "parse_time_field: expected UTCTime or GeneralizedTime, got {:?}",
            hdr.tag
        )));
    }
    let content_len = hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_time_field: indefinite length not allowed".into())
    })?;
    let total_len = hdr
        .header_length
        .checked_add(content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_time_field: length overflow".into()))?;
    if total_len > data.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_time_field: truncated (need {total_len}, have {})",
            data.len()
        )));
    }
    let content_start = hdr.header_length;
    let content_end = total_len;
    let t = Asn1Time::decode_der(&data[content_start..content_end])?;
    Ok((t, total_len))
}

/// Parse the content bytes of the `revokedCertificates SEQUENCE OF
/// RevokedEntry` field.
///
/// The input is the raw content (the inside of the outer SEQUENCE,
/// i.e., concatenated `RevokedEntry` SEQUENCEs without the enclosing
/// SEQUENCE header).
///
/// # Errors
///
/// `CryptoError::Encoding` if any entry is malformed. Successfully
/// parsed entries are returned even if a later entry fails — i.e., the
/// first failure aborts the whole list (matching OpenSSL behavior).
fn parse_revoked_list(content: &[u8]) -> CryptoResult<Vec<RevokedEntry>> {
    let mut out: Vec<RevokedEntry> = Vec::new();
    let mut cursor = 0usize;
    let mut sequence_counter: u32 = 0;
    while cursor < content.len() {
        let hdr = parse_tlv_header(&content[cursor..])?;
        if hdr.tag != Asn1Tag::Sequence || hdr.class != Asn1Class::Universal {
            return Err(CryptoError::Encoding(format!(
                "parse_revoked_list: entry is not a Universal SEQUENCE (tag={:?})",
                hdr.tag
            )));
        }
        let entry_content_len = hdr.content_length.ok_or_else(|| {
            CryptoError::Encoding("parse_revoked_list: entry has indefinite length".into())
        })?;
        let entry_content_start = cursor
            .checked_add(hdr.header_length)
            .ok_or_else(|| CryptoError::Encoding("parse_revoked_list: overflow".into()))?;
        let entry_content_end = entry_content_start
            .checked_add(entry_content_len)
            .ok_or_else(|| CryptoError::Encoding("parse_revoked_list: overflow".into()))?;
        if entry_content_end > content.len() {
            return Err(CryptoError::Encoding(
                "parse_revoked_list: entry exceeds list bounds".into(),
            ));
        }

        let entry = parse_single_revoked_entry(
            &content[entry_content_start..entry_content_end],
            sequence_counter,
        )?;
        out.push(entry);
        sequence_counter = sequence_counter.saturating_add(1);
        cursor = entry_content_end;
    }
    Ok(out)
}

/// Parse a single `RevokedEntry` SEQUENCE content (without the outer
/// SEQUENCE header).
///
/// ```text
/// RevokedEntry ::= SEQUENCE {
///     userCertificate         CertificateSerialNumber,  -- INTEGER
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
/// }
/// ```
///
/// # Errors
///
/// `CryptoError::Encoding` if the entry is malformed.
fn parse_single_revoked_entry(content: &[u8], sequence: u32) -> CryptoResult<RevokedEntry> {
    let mut cursor = 0usize;

    // --- userCertificate (INTEGER, CertificateSerialNumber) ---
    let serial_hdr = parse_tlv_header(&content[cursor..])?;
    if serial_hdr.tag != Asn1Tag::Integer || serial_hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_single_revoked_entry: serial is not a Universal INTEGER (tag={:?})",
            serial_hdr.tag
        )));
    }
    let serial_content_len = serial_hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_single_revoked_entry: serial has indefinite length".into())
    })?;
    let serial_start = cursor
        .checked_add(serial_hdr.header_length)
        .ok_or_else(|| CryptoError::Encoding("parse_single_revoked_entry: overflow".into()))?;
    let serial_end = serial_start
        .checked_add(serial_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_single_revoked_entry: overflow".into()))?;
    if serial_end > content.len() {
        return Err(CryptoError::Encoding(
            "parse_single_revoked_entry: serial exceeds entry bounds".into(),
        ));
    }
    let serial = content[serial_start..serial_end].to_vec();
    cursor = serial_end;

    // --- revocationDate (Time) ---
    if cursor >= content.len() {
        return Err(CryptoError::Encoding(
            "parse_single_revoked_entry: missing revocationDate field".into(),
        ));
    }
    let (rev_date, rev_date_len) = parse_time_field(&content[cursor..])?;
    cursor = cursor
        .checked_add(rev_date_len)
        .ok_or_else(|| CryptoError::Encoding("parse_single_revoked_entry: overflow".into()))?;

    // --- crlEntryExtensions (OPTIONAL) ---
    let mut extensions: Vec<X509Extension> = Vec::new();
    if cursor < content.len() {
        let ext_hdr = parse_tlv_header(&content[cursor..])?;
        if ext_hdr.tag == Asn1Tag::Sequence && ext_hdr.class == Asn1Class::Universal {
            let ext_content_len = ext_hdr.content_length.ok_or_else(|| {
                CryptoError::Encoding(
                    "parse_single_revoked_entry: extensions indefinite length".into(),
                )
            })?;
            let ext_content_start = cursor.checked_add(ext_hdr.header_length).ok_or_else(|| {
                CryptoError::Encoding("parse_single_revoked_entry: overflow".into())
            })?;
            let ext_content_end =
                ext_content_start
                    .checked_add(ext_content_len)
                    .ok_or_else(|| {
                        CryptoError::Encoding("parse_single_revoked_entry: overflow".into())
                    })?;
            if ext_content_end > content.len() {
                return Err(CryptoError::Encoding(
                    "parse_single_revoked_entry: extensions exceed entry bounds".into(),
                ));
            }
            extensions = parse_extensions_sequence(&content[ext_content_start..ext_content_end])?;
            cursor = ext_content_end;
        }
    }

    if cursor != content.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_single_revoked_entry: {} trailing bytes",
            content.len().saturating_sub(cursor)
        )));
    }

    // Construct the entry. Use `with_all_fields` so the extensions are
    // present immediately — the reason/issuer caches start as `None`
    // and will be populated by `cache_entry_extensions` once the
    // enclosing CRL has been fully parsed.
    let mut entry = RevokedEntry::with_all_fields(serial, rev_date, extensions, None, None);
    entry.set_sequence(sequence);
    Ok(entry)
}

/// Parse the content bytes of an `Extensions SEQUENCE OF Extension` field.
///
/// ```text
/// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
///
/// Extension ::= SEQUENCE {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
/// }
/// ```
///
/// The input is the raw content (the inside of the outer SEQUENCE).
///
/// # Errors
///
/// `CryptoError::Encoding` on malformed DER (wrong tags, truncation,
/// indefinite lengths).
fn parse_extensions_sequence(content: &[u8]) -> CryptoResult<Vec<X509Extension>> {
    let mut out: Vec<X509Extension> = Vec::new();
    let mut cursor = 0usize;
    while cursor < content.len() {
        let hdr = parse_tlv_header(&content[cursor..])?;
        if hdr.tag != Asn1Tag::Sequence || hdr.class != Asn1Class::Universal {
            return Err(CryptoError::Encoding(format!(
                "parse_extensions_sequence: entry is not a Universal SEQUENCE (tag={:?})",
                hdr.tag
            )));
        }
        let ext_content_len = hdr.content_length.ok_or_else(|| {
            CryptoError::Encoding("parse_extensions_sequence: entry has indefinite length".into())
        })?;
        let ext_content_start = cursor
            .checked_add(hdr.header_length)
            .ok_or_else(|| CryptoError::Encoding("parse_extensions_sequence: overflow".into()))?;
        let ext_content_end = ext_content_start
            .checked_add(ext_content_len)
            .ok_or_else(|| CryptoError::Encoding("parse_extensions_sequence: overflow".into()))?;
        if ext_content_end > content.len() {
            return Err(CryptoError::Encoding(
                "parse_extensions_sequence: entry exceeds sequence bounds".into(),
            ));
        }
        out.push(parse_single_extension(
            &content[ext_content_start..ext_content_end],
        )?);
        cursor = ext_content_end;
    }
    Ok(out)
}

/// Parse a single `Extension` SEQUENCE content into an [`X509Extension`].
///
/// # Errors
///
/// `CryptoError::Encoding` on malformed DER.
fn parse_single_extension(content: &[u8]) -> CryptoResult<X509Extension> {
    let mut cursor = 0usize;

    // --- extnID (OBJECT IDENTIFIER) ---
    let oid_hdr = parse_tlv_header(&content[cursor..])?;
    if oid_hdr.tag != Asn1Tag::ObjectIdentifier || oid_hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_single_extension: extnID is not an OBJECT IDENTIFIER (tag={:?})",
            oid_hdr.tag
        )));
    }
    let oid_content_len = oid_hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_single_extension: extnID has indefinite length".into())
    })?;
    let oid_total = oid_hdr
        .header_length
        .checked_add(oid_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
    let oid_tlv_end = cursor
        .checked_add(oid_total)
        .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
    if oid_tlv_end > content.len() {
        return Err(CryptoError::Encoding(
            "parse_single_extension: extnID exceeds entry bounds".into(),
        ));
    }
    // `Asn1Object::decode_der` expects OID *content* bytes (no tag/length),
    // so pass the slice *inside* the TLV header.
    let oid_content_start = cursor
        .checked_add(oid_hdr.header_length)
        .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
    let oid_obj = Asn1Object::decode_der(&content[oid_content_start..oid_tlv_end])?;
    let oid_str = oid_obj.to_oid_string()?;
    cursor = oid_tlv_end;

    // --- critical (BOOLEAN OPTIONAL, DEFAULT FALSE) ---
    let mut critical = false;
    if cursor < content.len() {
        let peek = parse_tlv_header(&content[cursor..])?;
        if peek.tag == Asn1Tag::Boolean && peek.class == Asn1Class::Universal {
            let bool_content_len = peek.content_length.ok_or_else(|| {
                CryptoError::Encoding("parse_single_extension: critical BOOLEAN indefinite".into())
            })?;
            let bool_start = cursor
                .checked_add(peek.header_length)
                .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
            let bool_end = bool_start
                .checked_add(bool_content_len)
                .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
            if bool_end > content.len() {
                return Err(CryptoError::Encoding(
                    "parse_single_extension: critical BOOLEAN exceeds entry bounds".into(),
                ));
            }
            critical = decode_implicit_boolean(&content[bool_start..bool_end])?;
            cursor = bool_end;
        }
    }

    // --- extnValue (OCTET STRING) ---
    if cursor >= content.len() {
        return Err(CryptoError::Encoding(
            "parse_single_extension: missing extnValue field".into(),
        ));
    }
    let octet_hdr = parse_tlv_header(&content[cursor..])?;
    if octet_hdr.tag != Asn1Tag::OctetString || octet_hdr.class != Asn1Class::Universal {
        return Err(CryptoError::Encoding(format!(
            "parse_single_extension: extnValue is not an OCTET STRING (tag={:?})",
            octet_hdr.tag
        )));
    }
    let octet_content_len = octet_hdr.content_length.ok_or_else(|| {
        CryptoError::Encoding("parse_single_extension: extnValue has indefinite length".into())
    })?;
    let octet_start = cursor
        .checked_add(octet_hdr.header_length)
        .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
    let octet_end = octet_start
        .checked_add(octet_content_len)
        .ok_or_else(|| CryptoError::Encoding("parse_single_extension: overflow".into()))?;
    if octet_end > content.len() {
        return Err(CryptoError::Encoding(
            "parse_single_extension: extnValue exceeds entry bounds".into(),
        ));
    }
    let value = content[octet_start..octet_end].to_vec();
    cursor = octet_end;

    if cursor != content.len() {
        return Err(CryptoError::Encoding(format!(
            "parse_single_extension: {} trailing bytes",
            content.len().saturating_sub(cursor)
        )));
    }

    Ok(X509Extension::new(oid_str, critical, value))
}

/// Compare two [`AlgorithmIdentifier`] values structurally.
///
/// RFC 5280 §5.1.1.2 requires that the `signature` field within
/// `tbsCertList` match the outer `signatureAlgorithm` field exactly,
/// including any parameters. Mismatch indicates tampering.
///
/// The comparison is performed by re-encoding both values to DER and
/// checking for bit-identical byte sequences. This is the definition
/// used by RFC 5280 (two `AlgorithmIdentifiers` are "equal" iff their
/// DER encodings match). Returns `false` on any encode failure, since
/// an `AlgorithmIdentifier` that cannot be re-encoded cannot be shown
/// equal to a valid one.
fn algorithm_identifiers_match(a: &AlgorithmIdentifier, b: &AlgorithmIdentifier) -> bool {
    match (a.encode_der(), b.encode_der()) {
        (Ok(a_der), Ok(b_der)) => a_der == b_der,
        _ => false,
    }
}

// =============================================================================
// Section 15 — Unit Tests
// =============================================================================
//
// Comprehensive unit tests for the CRL module. Covers all public API surfaces
// and exercises the reachable private helpers (tests have module-scope access).
// Test design adheres to crate-level lints:
//   - `#![forbid(unsafe_code)]` — tests contain no unsafe blocks
//   - `#![deny(clippy::unwrap_used)]` — allowed inside the test module only
//   - `#![deny(clippy::expect_used)]` — allowed inside the test module only
//   - `#![deny(clippy::cast_possible_truncation)]` — tests use lossless casts

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    // ============================================================
    // Section 1 — RevocationReason
    // ============================================================

    #[test]
    fn revocation_reason_try_from_all_valid_codes() {
        let table: [(i64, RevocationReason); 10] = [
            (0, RevocationReason::Unspecified),
            (1, RevocationReason::KeyCompromise),
            (2, RevocationReason::CaCompromise),
            (3, RevocationReason::AffiliationChanged),
            (4, RevocationReason::Superseded),
            (5, RevocationReason::CessationOfOperation),
            (6, RevocationReason::CertificateHold),
            (8, RevocationReason::RemoveFromCrl),
            (9, RevocationReason::PrivilegeWithdrawn),
            (10, RevocationReason::AaCompromise),
        ];
        for (code, expected) in table {
            let result = RevocationReason::try_from(code);
            assert!(
                matches!(result, Ok(r) if r == expected),
                "code {code} should yield {expected:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn revocation_reason_try_from_reserved_code_7_is_error() {
        let result = RevocationReason::try_from(7_i64);
        match result {
            Err(CryptoError::Encoding(msg)) => {
                assert!(
                    msg.contains("revocation reason code 7 is reserved"),
                    "unexpected error for code 7: {msg}"
                );
                assert!(msg.contains("RFC 5280"), "error must mention RFC: {msg}");
            }
            other => panic!("expected Encoding error for code 7, got {other:?}"),
        }
    }

    #[test]
    fn revocation_reason_try_from_unknown_codes_are_errors() {
        for code in [-1_i64, 11, 100, 255, i64::MAX, i64::MIN] {
            let result = RevocationReason::try_from(code);
            match result {
                Err(CryptoError::Encoding(msg)) => {
                    assert!(
                        msg.contains("unknown CRL revocation reason code"),
                        "code {code}: unexpected error: {msg}"
                    );
                }
                other => panic!("code {code} should fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn revocation_reason_as_i64_round_trip_all_variants() {
        let variants = [
            RevocationReason::Unspecified,
            RevocationReason::KeyCompromise,
            RevocationReason::CaCompromise,
            RevocationReason::AffiliationChanged,
            RevocationReason::Superseded,
            RevocationReason::CessationOfOperation,
            RevocationReason::CertificateHold,
            RevocationReason::RemoveFromCrl,
            RevocationReason::PrivilegeWithdrawn,
            RevocationReason::AaCompromise,
        ];
        for reason in variants {
            let code = reason.as_i64();
            let recovered = RevocationReason::try_from(code);
            assert!(
                matches!(recovered, Ok(r) if r == reason),
                "round-trip failed for {reason:?}: code={code}, recovered={recovered:?}"
            );
        }
    }

    #[test]
    fn revocation_reason_as_i64_specific_codes() {
        assert_eq!(RevocationReason::Unspecified.as_i64(), 0);
        assert_eq!(RevocationReason::KeyCompromise.as_i64(), 1);
        assert_eq!(RevocationReason::CaCompromise.as_i64(), 2);
        assert_eq!(RevocationReason::AffiliationChanged.as_i64(), 3);
        assert_eq!(RevocationReason::Superseded.as_i64(), 4);
        assert_eq!(RevocationReason::CessationOfOperation.as_i64(), 5);
        assert_eq!(RevocationReason::CertificateHold.as_i64(), 6);
        // 7 is reserved — skipped
        assert_eq!(RevocationReason::RemoveFromCrl.as_i64(), 8);
        assert_eq!(RevocationReason::PrivilegeWithdrawn.as_i64(), 9);
        assert_eq!(RevocationReason::AaCompromise.as_i64(), 10);
    }

    #[test]
    fn revocation_reason_display_matches_name() {
        let pairs = [
            (RevocationReason::Unspecified, "Unspecified"),
            (RevocationReason::KeyCompromise, "Key Compromise"),
            (RevocationReason::CaCompromise, "CA Compromise"),
            (RevocationReason::AffiliationChanged, "Affiliation Changed"),
            (RevocationReason::Superseded, "Superseded"),
            (
                RevocationReason::CessationOfOperation,
                "Cessation Of Operation",
            ),
            (RevocationReason::CertificateHold, "Certificate Hold"),
            (RevocationReason::RemoveFromCrl, "Remove From CRL"),
            (RevocationReason::PrivilegeWithdrawn, "Privilege Withdrawn"),
            (RevocationReason::AaCompromise, "AA Compromise"),
        ];
        for (reason, expected) in pairs {
            assert_eq!(format!("{reason}"), expected);
            assert_eq!(reason.name(), expected);
        }
    }

    #[test]
    fn revocation_reason_derives_copy_and_eq() {
        let a = RevocationReason::KeyCompromise;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(a, RevocationReason::KeyCompromise);
        assert_ne!(a, RevocationReason::CaCompromise);
    }

    // ============================================================
    // Section 2 — Local X.509 Support Types
    // ============================================================

    #[test]
    fn x509_name_from_der_and_accessors() {
        let der = vec![0x30, 0x00];
        let name = X509Name::from_der(der.clone());
        assert_eq!(name.as_der(), der.as_slice());
    }

    #[test]
    fn x509_name_with_display_uses_cached_string() {
        let der = vec![0x30, 0x00];
        let name = X509Name::with_display(der, "CN=Example".to_string());
        assert_eq!(name.to_string_oneline(), "CN=Example");
        assert_eq!(format!("{name}"), "CN=Example");
    }

    #[test]
    fn x509_name_without_display_falls_back_to_der_len_repr() {
        let der = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let name = X509Name::from_der(der);
        let display = name.to_string_oneline();
        assert!(display.contains("X509Name"));
        assert!(display.contains("5 DER bytes"));
    }

    #[test]
    fn x509_name_into_der_returns_vec() {
        let der = vec![0x30, 0x01, 0xAA];
        let name = X509Name::from_der(der.clone());
        assert_eq!(name.into_der(), der);
    }

    #[test]
    fn x509_extension_new_and_accessors() {
        let ext = X509Extension::new("2.5.29.35".to_string(), true, vec![0x01, 0x02]);
        assert_eq!(ext.oid(), "2.5.29.35");
        assert!(ext.is_critical());
        assert_eq!(ext.value(), &[0x01, 0x02]);
    }

    #[test]
    fn x509_extension_non_critical() {
        let ext = X509Extension::new("2.5.29.20".to_string(), false, vec![]);
        assert!(!ext.is_critical());
        assert!(ext.value().is_empty());
    }

    #[test]
    fn x509_certificate_new_and_accessors() {
        let name = X509Name::from_der(vec![0x30, 0x00]);
        let cert = X509Certificate::new(name.clone(), vec![0x01, 0x02, 0x03]);
        assert_eq!(cert.issuer().as_der(), name.as_der());
        assert_eq!(cert.serial_number(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn authority_key_identifier_empty_is_empty() {
        let akid = AuthorityKeyIdentifier::empty();
        assert!(akid.is_empty());
        assert!(akid.key_identifier.is_none());
        assert!(akid.authority_cert_issuer.is_none());
        assert!(akid.authority_cert_serial.is_none());
    }

    #[test]
    fn authority_key_identifier_non_empty_detection() {
        let mut akid = AuthorityKeyIdentifier::empty();
        akid.key_identifier = Some(vec![0xAA, 0xBB]);
        assert!(!akid.is_empty());

        let mut akid2 = AuthorityKeyIdentifier::empty();
        akid2.authority_cert_serial = Some(vec![0x01]);
        assert!(!akid2.is_empty());
    }

    // ============================================================
    // Section 3 — IssuingDistPoint and ReasonFlags
    // ============================================================

    #[test]
    fn issuing_dist_point_empty_has_no_scope_restriction() {
        let idp = IssuingDistPoint::empty();
        assert!(!idp.has_scope_restriction());
        assert!(idp.distribution_point.is_none());
        assert!(!idp.only_contains_user_certs);
        assert!(!idp.only_contains_ca_certs);
        assert!(idp.only_some_reasons.is_none());
        assert!(!idp.indirect_crl);
        assert!(!idp.only_contains_attribute_certs);
    }

    #[test]
    fn issuing_dist_point_scope_restrictions_flagged() {
        // Per the spec of `has_scope_restriction()`, only the
        // `onlyContains*` flags and `onlySomeReasons` count as scope
        // restrictions. `indirect_crl` is an *identity* flag (tells the
        // verifier that entries may list an alternate issuer) rather
        // than a scope-narrowing flag, so it is intentionally NOT
        // considered a scope restriction.
        let mut idp = IssuingDistPoint::empty();
        idp.only_contains_user_certs = true;
        assert!(idp.has_scope_restriction());

        let mut idp = IssuingDistPoint::empty();
        idp.only_contains_ca_certs = true;
        assert!(idp.has_scope_restriction());

        let mut idp = IssuingDistPoint::empty();
        idp.only_contains_attribute_certs = true;
        assert!(idp.has_scope_restriction());

        let mut idp = IssuingDistPoint::empty();
        idp.only_some_reasons = Some(ReasonFlags::KEY_COMPROMISE);
        assert!(idp.has_scope_restriction());

        // Negative case: indirect_crl alone is NOT a scope restriction.
        let mut idp = IssuingDistPoint::empty();
        idp.indirect_crl = true;
        assert!(!idp.has_scope_restriction());
    }

    #[test]
    fn reason_flags_individual_bits() {
        assert_eq!(ReasonFlags::UNUSED.bits(), 0x0001);
        assert_eq!(ReasonFlags::KEY_COMPROMISE.bits(), 0x0002);
        assert_eq!(ReasonFlags::CA_COMPROMISE.bits(), 0x0004);
        assert_eq!(ReasonFlags::AFFILIATION_CHANGED.bits(), 0x0008);
        assert_eq!(ReasonFlags::SUPERSEDED.bits(), 0x0010);
        assert_eq!(ReasonFlags::CESSATION_OF_OPERATION.bits(), 0x0020);
        assert_eq!(ReasonFlags::CERTIFICATE_HOLD.bits(), 0x0040);
        assert_eq!(ReasonFlags::PRIVILEGE_WITHDRAWN.bits(), 0x0080);
        assert_eq!(ReasonFlags::AA_COMPROMISE.bits(), 0x0100);
    }

    #[test]
    fn reason_flags_all_reasons_covers_known_bits() {
        assert_eq!(ReasonFlags::ALL_REASONS.bits(), 0x01FF);
        let combined = ReasonFlags::UNUSED
            | ReasonFlags::KEY_COMPROMISE
            | ReasonFlags::CA_COMPROMISE
            | ReasonFlags::AFFILIATION_CHANGED
            | ReasonFlags::SUPERSEDED
            | ReasonFlags::CESSATION_OF_OPERATION
            | ReasonFlags::CERTIFICATE_HOLD
            | ReasonFlags::PRIVILEGE_WITHDRAWN
            | ReasonFlags::AA_COMPROMISE;
        assert_eq!(combined, ReasonFlags::ALL_REASONS);
    }

    #[test]
    fn reason_flags_insert_contains_intersect() {
        let mut f = ReasonFlags::empty();
        assert!(f.is_empty());
        f.insert(ReasonFlags::KEY_COMPROMISE);
        assert!(f.contains(ReasonFlags::KEY_COMPROMISE));
        assert!(!f.contains(ReasonFlags::CA_COMPROMISE));
        f.insert(ReasonFlags::CA_COMPROMISE);
        assert!(f.contains(ReasonFlags::KEY_COMPROMISE | ReasonFlags::CA_COMPROMISE));
        let intersection = f & ReasonFlags::KEY_COMPROMISE;
        assert_eq!(intersection, ReasonFlags::KEY_COMPROMISE);
    }

    // ============================================================
    // Section 4 — RevokedEntry
    // ============================================================

    fn make_time() -> Asn1Time {
        match Asn1Time::from_unix_timestamp(1_700_000_000) {
            Ok(t) => t,
            Err(_) => match Asn1Time::new(2020, 1, 1, 0, 0, 0) {
                Ok(t) => t,
                Err(_) => Asn1Time::now().unwrap_or_else(|_| probe_epoch_fallback()),
            },
        }
    }

    #[test]
    fn revoked_entry_new_defaults() {
        let entry = RevokedEntry::new(vec![0x01, 0x02, 0x03], make_time());
        assert_eq!(entry.serial_number(), &[0x01, 0x02, 0x03]);
        assert!(entry.extensions().is_empty());
        assert!(entry.reason().is_none());
        assert!(entry.issuer().is_none());
        assert_eq!(entry.sequence(), 0);
    }

    #[test]
    fn revoked_entry_with_all_fields_populates_all() {
        let name = X509Name::from_der(vec![0x30, 0x00]);
        let ext = X509Extension::new("2.5.29.21".to_string(), false, vec![]);
        let entry = RevokedEntry::with_all_fields(
            vec![0x42],
            make_time(),
            vec![ext.clone()],
            Some(RevocationReason::KeyCompromise),
            Some(name.clone()),
        );
        assert_eq!(entry.serial_number(), &[0x42]);
        assert_eq!(entry.extensions().len(), 1);
        assert_eq!(entry.reason(), Some(RevocationReason::KeyCompromise));
        assert!(entry.issuer().is_some());
        assert_eq!(entry.sequence(), 0);
    }

    #[test]
    fn revoked_entry_mutators_round_trip() {
        let mut entry = RevokedEntry::new(vec![0x01], make_time());

        entry.set_serial_number(vec![0xDE, 0xAD]);
        assert_eq!(entry.serial_number(), &[0xDE, 0xAD]);

        let new_time = make_time();
        entry.set_revocation_date(new_time);
        // Cannot compare Asn1Time directly via inequality; this is just a smoke test.

        entry.set_reason(Some(RevocationReason::Superseded));
        assert_eq!(entry.reason(), Some(RevocationReason::Superseded));
        entry.set_reason(None);
        assert!(entry.reason().is_none());

        let name = X509Name::from_der(vec![0x30, 0x00]);
        entry.set_issuer(Some(name));
        assert!(entry.issuer().is_some());
        entry.set_issuer(None);
        assert!(entry.issuer().is_none());

        entry.set_sequence(42);
        assert_eq!(entry.sequence(), 42);
    }

    #[test]
    fn revoked_entry_add_extension_appends() {
        let mut entry = RevokedEntry::new(vec![0x01], make_time());
        assert!(entry.extensions().is_empty());
        entry.add_extension(X509Extension::new(
            "2.5.29.21".to_string(),
            false,
            vec![0x0A, 0x01, 0x01],
        ));
        assert_eq!(entry.extensions().len(), 1);
        entry.add_extension(X509Extension::new("2.5.29.29".to_string(), false, vec![]));
        assert_eq!(entry.extensions().len(), 2);
    }

    #[test]
    fn revoked_entry_partial_eq_compares_only_serial() {
        let mut a = RevokedEntry::new(vec![0x01, 0x02], make_time());
        let mut b = RevokedEntry::new(vec![0x01, 0x02], make_time());
        a.set_sequence(1);
        b.set_sequence(99);
        a.set_reason(Some(RevocationReason::KeyCompromise));
        b.set_reason(Some(RevocationReason::Superseded));
        // PartialEq only looks at serial_number.
        assert_eq!(a, b);

        let c = RevokedEntry::new(vec![0x03], make_time());
        assert_ne!(a, c);
    }

    #[test]
    fn revoked_entry_ord_length_first_then_lex() {
        let e1 = RevokedEntry::new(vec![0x01], make_time());
        let e2 = RevokedEntry::new(vec![0x02], make_time());
        // Equal-length lexicographic:
        assert!(e1 < e2);

        let short = RevokedEntry::new(vec![0xFF], make_time());
        let long = RevokedEntry::new(vec![0x01, 0x00], make_time());
        // Length-first: length 1 < length 2, so short < long despite 0xFF > 0x01.
        assert!(short < long);

        let equal_a = RevokedEntry::new(vec![0x10, 0x20], make_time());
        let equal_b = RevokedEntry::new(vec![0x10, 0x20], make_time());
        assert_eq!(equal_a.cmp(&equal_b), Ordering::Equal);
    }

    #[test]
    fn revoked_entry_cache_entry_extensions_reason() -> CryptoResult<()> {
        let mut entry = RevokedEntry::new(vec![0x01], make_time());
        // DER ENUMERATED value = 1 (KeyCompromise)
        entry.add_extension(X509Extension::new(
            "2.5.29.21".to_string(),
            false,
            vec![0x0A, 0x01, 0x01],
        ));
        assert!(entry.reason().is_none());
        entry.cache_entry_extensions()?;
        assert_eq!(entry.reason(), Some(RevocationReason::KeyCompromise));
        Ok(())
    }

    #[test]
    fn revoked_entry_cache_entry_extensions_malformed_reason_logs_but_does_not_fail(
    ) -> CryptoResult<()> {
        let mut entry = RevokedEntry::new(vec![0x01], make_time());
        // Invalid reason: missing length byte
        entry.add_extension(X509Extension::new(
            "2.5.29.21".to_string(),
            false,
            vec![0x0A],
        ));
        // cache_entry_extensions must succeed despite the malformed entry.
        entry.cache_entry_extensions()?;
        assert!(
            entry.reason().is_none(),
            "malformed reason must not be cached"
        );
        Ok(())
    }

    #[test]
    fn revoked_entry_cache_entry_extensions_certificate_issuer() -> CryptoResult<()> {
        let mut entry = RevokedEntry::new(vec![0x01], make_time());
        let issuer_der = vec![0x30, 0x00];
        entry.add_extension(X509Extension::new(
            "2.5.29.29".to_string(),
            false,
            issuer_der.clone(),
        ));
        assert!(entry.issuer().is_none());
        entry.cache_entry_extensions()?;
        assert!(entry.issuer().is_some());
        if let Some(issuer) = entry.issuer() {
            assert_eq!(issuer.as_der(), issuer_der.as_slice());
        }
        Ok(())
    }

    // ============================================================
    // Section 5 — CRL Processing Flags
    // ============================================================

    #[test]
    fn crl_flags_bit_values() {
        assert_eq!(CrlFlags::EXTENSIONS_CACHED.bits(), 0x0001);
        assert_eq!(CrlFlags::INVALID.bits(), 0x0002);
        assert_eq!(CrlFlags::CRITICAL_ERROR.bits(), 0x0004);
        assert_eq!(CrlFlags::FRESHEST.bits(), 0x0008);
        assert_eq!(CrlFlags::NO_FINGERPRINT.bits(), 0x0010);
        assert_eq!(CrlFlags::EXFLAG_SET.bits(), 0x0020);
    }

    #[test]
    fn crl_flags_insert_remove_contains() {
        let mut f = CrlFlags::empty();
        assert!(f.is_empty());
        f.insert(CrlFlags::EXTENSIONS_CACHED);
        assert!(f.contains(CrlFlags::EXTENSIONS_CACHED));
        f.insert(CrlFlags::INVALID);
        assert!(f.contains(CrlFlags::INVALID));
        assert_eq!(f.bits(), 0x0003);
        f.remove(CrlFlags::INVALID);
        assert!(!f.contains(CrlFlags::INVALID));
        assert!(f.contains(CrlFlags::EXTENSIONS_CACHED));
    }

    #[test]
    fn idp_flags_bit_values() {
        assert_eq!(IdpFlags::IDP_PRESENT.bits(), 0x0001);
        assert_eq!(IdpFlags::IDP_ONLY_USER.bits(), 0x0002);
        assert_eq!(IdpFlags::IDP_ONLY_CA.bits(), 0x0004);
        assert_eq!(IdpFlags::IDP_ONLY_ATTR.bits(), 0x0008);
        assert_eq!(IdpFlags::IDP_INVALID.bits(), 0x0010);
        assert_eq!(IdpFlags::IDP_INDIRECT.bits(), 0x0020);
        assert_eq!(IdpFlags::IDP_REASONS.bits(), 0x0040);
    }

    // ============================================================
    // Section 7–10 — X509Crl Construction, Accessors, Mutators, Operations
    // ============================================================

    #[test]
    fn x509_crl_new_empty_default_state() -> CryptoResult<()> {
        let crl = X509Crl::new_empty()?;
        assert!(crl.version().is_none());
        assert!(crl.next_update().is_none());
        assert!(crl.revoked_entries().is_empty());
        assert!(crl.extensions().is_empty());
        assert!(crl.signature().is_empty());
        assert!(crl.tbs_der().is_empty());
        assert!(crl.authority_key_identifier().is_none());
        assert!(crl.issuing_distribution_point().is_none());
        assert_eq!(crl.idp_flags(), IdpFlags::empty());
        // IMPORTANT: new_empty() defaults idp_reasons to ALL_REASONS.
        assert_eq!(crl.idp_reasons(), ReasonFlags::ALL_REASONS);
        assert!(crl.crl_number().is_none());
        assert!(crl.delta_crl_indicator().is_none());
        assert_eq!(crl.flags(), CrlFlags::empty());
        assert!(crl.is_valid());
        Ok(())
    }

    #[test]
    fn x509_crl_new_empty_to_der_fails_without_cached_encoding() -> CryptoResult<()> {
        let crl = X509Crl::new_empty()?;
        match crl.to_der() {
            Err(CryptoError::Encoding(msg)) => {
                assert!(
                    msg.contains("no cached DER encoding"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn x509_crl_set_version_and_clear() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.set_version(1)?;
        assert_eq!(crl.version(), Some(1));
        crl.clear_version();
        assert!(crl.version().is_none());
        Ok(())
    }

    #[test]
    fn x509_crl_set_issuer_updates_and_invalidates_der() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        // Seed a fake DER cache to observe invalidation.
        crl.der_encoded = vec![0xAA];
        crl.info.tbs_der = vec![0xBB];

        let name = X509Name::from_der(vec![0x30, 0x00]);
        crl.set_issuer(name)?;

        // Both caches must be cleared after issuer mutation.
        assert!(crl.der_encoded.is_empty(), "der_encoded must be cleared");
        assert!(crl.info.tbs_der.is_empty(), "tbs_der must be cleared");
        Ok(())
    }

    #[test]
    fn x509_crl_set_next_update_some_and_none() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.set_next_update(Some(OsslTime::from_seconds(1_700_000_000)))?;
        assert!(crl.next_update().is_some());
        crl.set_next_update(None)?;
        assert!(crl.next_update().is_none());
        Ok(())
    }

    #[test]
    fn x509_crl_set_last_update_asn1_invalidates_der() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.der_encoded = vec![0x01, 0x02];
        crl.info.tbs_der = vec![0x03, 0x04];
        let t = make_time();
        crl.set_last_update_asn1(t);
        assert!(crl.der_encoded.is_empty());
        assert!(crl.info.tbs_der.is_empty());
        Ok(())
    }

    #[test]
    fn x509_crl_set_last_update_str_parses_generalized_time() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.der_encoded = vec![0x01];
        crl.info.tbs_der = vec![0x02];
        // RFC 5280 GeneralizedTime: 15 chars incl 'Z'.
        crl.set_last_update_str("20230101000000Z")?;
        // `Asn1Time::Display` emits native DER-style: YYYYMMDDHHMMSSZ for
        // GeneralizedTime (14 digits + 'Z'). Not human-readable ISO 8601.
        assert_eq!(crl.last_update().to_string(), "20230101000000Z");
        // Caches invalidated.
        assert!(crl.der_encoded.is_empty());
        assert!(crl.info.tbs_der.is_empty());
        Ok(())
    }

    #[test]
    fn x509_crl_set_last_update_str_parses_utc_time() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        // RFC 5280 UTCTime: 13 chars incl 'Z' (YYMMDDHHMMSSZ).
        crl.set_last_update_str("230101000000Z")?;
        // `Asn1Time::Display` emits native DER-style: YYMMDDHHMMSSZ for
        // UTCTime (12 digits + 'Z'). Year pivot YY<50 → 20YY is performed
        // during parse but the Display output preserves the original UTCTime
        // encoding (2-digit year).
        assert_eq!(crl.last_update().to_string(), "230101000000Z");
        Ok(())
    }

    #[test]
    fn x509_crl_set_last_update_str_rejects_malformed() {
        let mut crl = X509Crl::new_empty().expect("new_empty");
        // Missing 'Z' terminator.
        let err = crl
            .set_last_update_str("20230101000000")
            .expect_err("must fail");
        // `Asn1Error::InvalidTimeFormat` converts to `CryptoError::Encoding`
        // (see `impl From<Asn1Error> for CryptoError` in `asn1/mod.rs`).
        assert!(
            matches!(err, CryptoError::Encoding(_)),
            "expected CryptoError::Encoding, got: {err:?}"
        );
    }

    #[test]
    fn x509_crl_set_next_update_str_accepts_some_and_none() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.set_next_update_str(Some("20240101000000Z"))?;
        assert!(crl.next_update().is_some());
        // Passing None clears the field.
        crl.set_next_update_str(None)?;
        assert!(crl.next_update().is_none());
        Ok(())
    }

    #[test]
    fn x509_crl_set_next_update_str_rejects_malformed() {
        let mut crl = X509Crl::new_empty().expect("new_empty");
        let err = crl
            .set_next_update_str(Some("garbage"))
            .expect_err("must fail on non-RFC5280 input");
        // `Asn1Error::InvalidTimeFormat` → `CryptoError::Encoding`.
        assert!(
            matches!(err, CryptoError::Encoding(_)),
            "expected CryptoError::Encoding, got: {err:?}"
        );
    }

    #[test]
    fn x509_crl_add_revoked_invalidates_der_and_appends() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.der_encoded = vec![0x01];
        crl.info.tbs_der = vec![0x02];

        let entry = RevokedEntry::new(vec![0xAA], make_time());
        crl.add_revoked(entry)?;
        assert_eq!(crl.revoked_entries().len(), 1);
        assert!(crl.der_encoded.is_empty());
        assert!(crl.info.tbs_der.is_empty());
        Ok(())
    }

    #[test]
    fn x509_crl_add_extension_invalidates_caches_and_clears_cached_flag() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.der_encoded = vec![0x01];
        crl.info.tbs_der = vec![0x02];
        crl.flags = CrlFlags::EXTENSIONS_CACHED | CrlFlags::EXFLAG_SET;

        let ext = X509Extension::new("2.5.29.20".to_string(), false, vec![0x02, 0x01, 0x01]);
        crl.add_extension(ext);

        assert_eq!(crl.extensions().len(), 1);
        assert!(crl.der_encoded.is_empty());
        assert!(crl.info.tbs_der.is_empty());
        assert!(!crl.flags().contains(CrlFlags::EXTENSIONS_CACHED));
        Ok(())
    }

    #[test]
    fn x509_crl_set_signature_clears_only_der_encoded() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.der_encoded = vec![0xAA, 0xBB];
        crl.info.tbs_der = vec![0xCC, 0xDD];
        crl.set_signature(vec![0x01, 0x02]);
        // Only `der_encoded` is cleared per the mutator invariant.
        assert!(crl.der_encoded.is_empty());
        assert_eq!(crl.info.tbs_der, vec![0xCC, 0xDD]);
        assert_eq!(crl.signature(), &[0x01, 0x02]);
        Ok(())
    }

    #[test]
    fn x509_crl_set_signature_algorithm_clears_only_der_encoded() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.der_encoded = vec![0xAA];
        crl.info.tbs_der = vec![0xBB];
        let alg =
            AlgorithmIdentifier::new(Asn1Object::from_oid_string("1.2.840.113549.1.1.11")?, None);
        crl.set_signature_algorithm(alg);
        // Only `der_encoded` is cleared; tbs_der preserved.
        assert!(crl.der_encoded.is_empty());
        assert_eq!(crl.info.tbs_der, vec![0xBB]);
        Ok(())
    }

    #[test]
    fn x509_crl_sort_orders_and_assigns_sequence() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        // Add in reverse length-then-lex order:
        crl.add_revoked(RevokedEntry::new(vec![0x03, 0x02, 0x01], make_time()))?;
        crl.add_revoked(RevokedEntry::new(vec![0xFF], make_time()))?;
        crl.add_revoked(RevokedEntry::new(vec![0x01, 0x02], make_time()))?;

        crl.sort();

        // After sort, entries are length-first, then lex.
        assert_eq!(crl.revoked_entries()[0].serial_number(), &[0xFF]);
        assert_eq!(crl.revoked_entries()[1].serial_number(), &[0x01, 0x02]);
        assert_eq!(
            crl.revoked_entries()[2].serial_number(),
            &[0x03, 0x02, 0x01]
        );

        // Sequence numbers assigned in sort order.
        assert_eq!(crl.revoked_entries()[0].sequence(), 0);
        assert_eq!(crl.revoked_entries()[1].sequence(), 1);
        assert_eq!(crl.revoked_entries()[2].sequence(), 2);

        assert!(crl.is_sorted());
        Ok(())
    }

    #[test]
    fn x509_crl_is_sorted_detects_unsorted_list() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.add_revoked(RevokedEntry::new(vec![0x02], make_time()))?;
        crl.add_revoked(RevokedEntry::new(vec![0x01], make_time()))?;
        assert!(!crl.is_sorted());
        crl.sort();
        assert!(crl.is_sorted());
        Ok(())
    }

    #[test]
    fn x509_crl_is_revoked_binary_search_hit_and_miss() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        for s in [vec![0x01_u8], vec![0x02], vec![0x03]] {
            crl.add_revoked(RevokedEntry::new(s, make_time()))?;
        }
        crl.sort();
        assert!(crl.is_sorted());
        assert!(crl.is_revoked(&[0x02]).is_some());
        assert!(crl.is_revoked(&[0x99]).is_none());
        Ok(())
    }

    #[test]
    fn x509_crl_is_revoked_linear_fallback_when_unsorted() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.add_revoked(RevokedEntry::new(vec![0x02], make_time()))?;
        crl.add_revoked(RevokedEntry::new(vec![0x01], make_time()))?;
        assert!(!crl.is_sorted());
        // Linear scan path
        assert!(crl.is_revoked(&[0x01]).is_some());
        assert!(crl.is_revoked(&[0xFF]).is_none());
        Ok(())
    }

    #[test]
    fn x509_crl_is_revoked_by_cert_delegates_to_is_revoked() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.add_revoked(RevokedEntry::new(vec![0xAB, 0xCD], make_time()))?;
        crl.sort();

        let cert = X509Certificate::new(X509Name::from_der(vec![0x30, 0x00]), vec![0xAB, 0xCD]);
        assert!(crl.is_revoked_by_cert(&cert).is_some());

        let other = X509Certificate::new(X509Name::from_der(vec![0x30, 0x00]), vec![0x99]);
        assert!(crl.is_revoked_by_cert(&other).is_none());
        Ok(())
    }

    // ============================================================
    // Section 11 — DefaultCrlMethod
    // ============================================================

    #[test]
    fn default_crl_method_verify_fails_when_invalid_flag_set() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.flags.insert(CrlFlags::INVALID);
        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &[0x01]) {
            Err(CryptoError::Verification(msg)) => {
                assert!(msg.contains("CRL is flagged invalid"));
                assert!(msg.contains("signature verification skipped"));
            }
            other => panic!("expected Verification error, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn default_crl_method_verify_fails_without_tbs_der() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        assert!(crl.info.tbs_der.is_empty());
        crl.signature = vec![0xAB]; // non-empty signature
        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &[0x01]) {
            Err(CryptoError::Verification(msg)) => {
                assert!(msg.contains("no cached TBS DER"));
            }
            other => panic!("expected Verification error, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn default_crl_method_verify_fails_without_signature() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = vec![0x01]; // non-empty tbs
        assert!(crl.signature.is_empty());
        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &[0x01]) {
            Err(CryptoError::Verification(msg)) => {
                assert!(msg.contains("no signature value"));
            }
            other => panic!("expected Verification error, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn default_crl_method_verify_fails_with_empty_issuer_key() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = vec![0x01];
        crl.signature = vec![0xAB];
        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &[]) {
            Err(CryptoError::Verification(msg)) => {
                assert!(msg.contains("issuer public key is empty"));
            }
            other => panic!("expected Verification error, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn default_crl_method_verify_rejects_malformed_spki() -> CryptoResult<()> {
        // Updated for Group C #10: `DefaultCrlMethod::verify` now performs
        // real cryptographic verification (RSASSA-PKCS1-v1_5 / ECDSA / EdDSA)
        // rather than returning a provisional `Ok(true)` once preconditions
        // are met. With the new dispatch, supplying garbage bytes for the
        // issuer's `SubjectPublicKeyInfo` must produce a structural
        // `CryptoError::Verification` (not `Ok(false)` and not `Ok(true)`),
        // because SPKI parsing fails before any signature math is attempted.
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = vec![0x01, 0x02];
        crl.signature = vec![0xAB, 0xCD];
        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &[0x10, 0x20]) {
            Err(CryptoError::Verification(msg)) => {
                assert!(
                    msg.contains("SubjectPublicKeyInfo")
                        || msg.contains("not supported"),
                    "expected SPKI decode or unsupported-algorithm error, got: {msg}"
                );
            }
            other => panic!(
                "expected Err(CryptoError::Verification(_)) for malformed SPKI input, got: {other:?}"
            ),
        }
        Ok(())
    }

    #[test]
    fn default_crl_method_lookup_remove_from_crl_returns_none() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        let entry = RevokedEntry::with_all_fields(
            vec![0x01],
            make_time(),
            Vec::new(),
            Some(RevocationReason::RemoveFromCrl),
            None,
        );
        crl.add_revoked(entry)?;
        crl.sort();

        let method = DefaultCrlMethod::default();
        let looked_up = method.lookup(&crl, &[0x01], None)?;
        assert!(looked_up.is_none(), "RemoveFromCrl inhibits lookup result");
        Ok(())
    }

    #[test]
    fn default_crl_method_lookup_returns_matching_entry() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        let entry = RevokedEntry::with_all_fields(
            vec![0xDE, 0xAD],
            make_time(),
            Vec::new(),
            Some(RevocationReason::KeyCompromise),
            None,
        );
        crl.add_revoked(entry)?;
        crl.sort();

        let method = DefaultCrlMethod::default();
        let looked_up = method.lookup(&crl, &[0xDE, 0xAD], None)?;
        assert!(looked_up.is_some());
        if let Some(e) = looked_up {
            assert_eq!(e.serial_number(), &[0xDE, 0xAD]);
        }
        Ok(())
    }

    #[test]
    fn default_crl_method_lookup_no_match_returns_none() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.add_revoked(RevokedEntry::new(vec![0x01], make_time()))?;
        crl.sort();
        let method = DefaultCrlMethod::default();
        assert!(method.lookup(&crl, &[0xFF], None)?.is_none());
        Ok(())
    }

    #[test]
    fn x509_crl_verify_signature_delegates_through_to_dispatch() -> CryptoResult<()> {
        // Updated for Group C #10: `X509Crl::verify_signature` is a thin
        // wrapper around `DefaultCrlMethod::verify` (instantiates a default
        // method and forwards). This test asserts the delegation path by
        // confirming that calling the wrapper yields the same structural
        // verification error (malformed SPKI) as calling the method
        // directly. Both paths must reject `[0x10, 0x20]` as it cannot be
        // decoded as a `SubjectPublicKeyInfo`.
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = vec![0x01, 0x02];
        crl.signature = vec![0xAB, 0xCD];

        let wrapper_result = crl.verify_signature(&[0x10, 0x20]);
        let direct_result = DefaultCrlMethod::default().verify(&crl, &[0x10, 0x20]);

        match (&wrapper_result, &direct_result) {
            (
                Err(CryptoError::Verification(wrapper_msg)),
                Err(CryptoError::Verification(direct_msg)),
            ) => {
                // Delegation invariant: the wrapper must produce the
                // identical error message as the underlying method.
                assert_eq!(
                    wrapper_msg, direct_msg,
                    "wrapper and direct dispatch produced different errors"
                );
                assert!(
                    wrapper_msg.contains("SubjectPublicKeyInfo")
                        || wrapper_msg.contains("not supported"),
                    "expected SPKI decode or unsupported-algorithm error, got: {wrapper_msg}"
                );
            }
            (wrapper, direct) => panic!(
                "expected matching Err(CryptoError::Verification(_)) from both dispatch paths; \
                 wrapper={wrapper:?}, direct={direct:?}"
            ),
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // Group C #10 — Positive/negative signature verification tests
    //
    // These tests exercise the `DefaultCrlMethod::verify` cryptographic
    // dispatch (RFC 5280 §5.1.1.2) implemented in this commit. They
    // cover:
    //   * Outer/inner signatureAlgorithm mismatch detection
    //   * Unsupported signatureAlgorithm OID rejection
    //   * Valid ECDSA-P256 CRL signature acceptance
    //   * Tampered CRL rejection (Ok(false))
    //   * Valid Ed25519 CRL signature acceptance
    //
    // RSA verification testing is deferred (no in-tree RSA signing path
    // available in `openssl-crypto`) — the dispatch is exercised by the
    // unsupported-algorithm path here and by upstream provider/openssl-cli
    // integration tests once an RSA signer lands.
    // ----------------------------------------------------------------

    #[test]
    fn verify_signature_rejects_outer_inner_alg_mismatch() -> CryptoResult<()> {
        // RFC 5280 §5.1.1.2: the outer `signatureAlgorithm` field MUST equal
        // the inner `signature` field of `tbsCertList`. The verify dispatch
        // rejects mismatches before doing any crypto. This test sets outer
        // to ECDSA-SHA256 and inner to Ed25519 to provoke the mismatch path.
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = vec![0x01, 0x02];
        crl.signature = vec![0xAB, 0xCD];

        // Outer = ECDSA-SHA256, inner = Ed25519 (mismatch).
        crl.set_signature_algorithm(AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ECDSA_SHA256)?,
            None,
        ));
        crl.info.signature_algorithm = AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ED25519)?,
            None,
        );

        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &[0x10, 0x20]) {
            Err(CryptoError::Verification(msg)) => {
                assert!(
                    msg.contains("outer/inner signatureAlgorithm mismatch"),
                    "expected outer/inner mismatch error, got: {msg}"
                );
                // Sanity: both OIDs must appear in the diagnostic message.
                assert!(
                    msg.contains(OID_ECDSA_SHA256),
                    "diagnostic must include outer OID, got: {msg}"
                );
                assert!(
                    msg.contains(OID_ED25519),
                    "diagnostic must include inner OID, got: {msg}"
                );
            }
            other => panic!(
                "expected Err(CryptoError::Verification(_)) for outer/inner mismatch, got: {other:?}"
            ),
        }
        Ok(())
    }

    #[test]
    fn verify_signature_rejects_unsupported_algorithm() -> CryptoResult<()> {
        // The dispatch path falls through to a "not supported" error when the
        // outer/inner OIDs match each other but neither matches RSA, ECDSA,
        // nor EdDSA. The SPKI MUST decode successfully because parsing
        // happens BEFORE algorithm dispatch (see verify() at line ~1976);
        // an unparseable SPKI fires the "SubjectPublicKeyInfo decode" error
        // first. To exercise the dispatch fall-through cleanly, build a
        // syntactically valid `SubjectPublicKeyInfoOwned` carrying an
        // arbitrary unsupported OID and 32 bytes of placeholder key
        // material. Both inner/outer CRL `signatureAlgorithm` fields are
        // also set to that same arbitrary OID so the mismatch check at the
        // top of verify() passes before the dispatch is reached.
        use der::asn1::BitString;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

        // Arbitrary syntactically valid OID that does NOT match any of the
        // RSA/ECDSA/EdDSA OID groups recognized by `SignatureAlgorithmId`.
        // 1.2.3.4 is a well-known "fake/test" OID conventionally used in
        // examples (RFC 5280 examples use the same prefix).
        let unsupported_oid_str = "1.2.3.4";
        let unsupported_oid = ObjectIdentifier::new_unwrap(unsupported_oid_str);

        // 32 bytes of placeholder key material — the SPKI decoder only
        // validates the BIT STRING is well-formed; it does not interpret
        // the key contents at this stage of dispatch.
        let pk_placeholder = [0u8; 32];
        let subject_public_key = BitString::from_bytes(&pk_placeholder)
            .expect("BitString::from_bytes never fails for non-empty byte slices");

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: unsupported_oid,
                parameters: None,
            },
            subject_public_key,
        };
        let issuer_key_der = spki
            .to_der()
            .expect("SubjectPublicKeyInfoOwned encodes to DER for valid OID + bit-string");

        // Build a CRL with both inner and outer signatureAlgorithm pointing
        // at the same unsupported OID so the mismatch guard at the top of
        // verify() passes and dispatch is reached.
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = vec![0x01, 0x02];
        crl.signature = vec![0xAB, 0xCD];

        crl.set_signature_algorithm(AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(unsupported_oid_str)?,
            None,
        ));
        crl.info.signature_algorithm = AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(unsupported_oid_str)?,
            None,
        );

        let method = DefaultCrlMethod::default();
        match method.verify(&crl, &issuer_key_der) {
            Err(CryptoError::Verification(msg)) => {
                assert!(
                    msg.contains("not supported"),
                    "expected unsupported-algorithm error, got: {msg}"
                );
                assert!(
                    msg.contains(unsupported_oid_str),
                    "diagnostic must include the unsupported OID for forensic clarity, got: {msg}"
                );
                assert!(
                    msg.contains("CRL signatureAlgorithm OID"),
                    "diagnostic must identify the field that is unsupported, got: {msg}"
                );
            }
            other => panic!(
                "expected Err(CryptoError::Verification(_)) for unsupported algorithm OID {unsupported_oid_str}, got: {other:?}"
            ),
        }
        Ok(())
    }

    /// Group C #10 / Test #3 (Positive): a CRL signed with ECDSA-SHA256 over a
    /// freshly-generated NIST P-256 keypair must verify successfully.
    ///
    /// This exercises the production cryptographic path end-to-end:
    ///   1. `EcKey::generate(P-256)` produces a real keypair.
    ///   2. The public key is encoded into a DER-serialised
    ///      `SubjectPublicKeyInfo` carrying:
    ///        * algorithm OID = `id-ecPublicKey` (1.2.840.10045.2.1)
    ///        * parameters    = the namedCurve OID (`OID_ECC_P256`)
    ///        * subjectPublicKey = the SEC1 uncompressed point (`0x04‖X‖Y`)
    ///      — exactly what `crl_verify_ecdsa` parses via
    ///      `EcPoint::from_bytes(&group, &spki.public_key_bytes)`.
    ///   3. A synthetic `tbsCertList` byte sequence is hashed with SHA-256
    ///      and signed via `crate::ec::ecdsa::sign_der`.
    ///   4. Both outer (`X509Crl::signature_algorithm`) and inner
    ///      (`info.signature_algorithm`) algorithm identifiers are set to
    ///      `OID_ECDSA_SHA256` so the dispatch reaches the ECDSA branch.
    ///   5. `DefaultCrlMethod::verify` must return `Ok(true)`.
    ///
    /// Together with the negative tests above, this proves that the new
    /// implementation is doing actual cryptographic verification rather than
    /// a structural-only check (resolving the original CRITICAL/HIGH defect
    /// in the review report — `crypto/x509/crl.rs:DefaultCrlMethod::verify`
    /// "Structural-only implementation — does not verify CRL issuer
    /// signature over TBSCertList").
    ///
    /// Compiled only when the `ec` feature is enabled, since the test
    /// exercises the ECDSA verification path which depends on EC types.
    #[cfg(feature = "ec")]
    #[test]
    fn verify_signature_accepts_valid_ecdsa_p256_crl() -> CryptoResult<()> {
        use der::asn1::BitString;
        use der::Any;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

        use crate::ec::PointConversionForm;

        // -----------------------------------------------------------------
        // 1. Generate a fresh P-256 keypair.
        // -----------------------------------------------------------------
        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1)?;
        let key = EcKey::generate(&group)?;

        // Encode the public point in SEC1 uncompressed form (`0x04 || X || Y`,
        // exactly `1 + 2 * 32 = 65` bytes for P-256). This matches the format
        // consumed by `crl_verify_ecdsa` via
        // `EcPoint::from_bytes(&group, &spki.public_key_bytes)`.
        let pub_point = key
            .public_key()
            .expect("EcKey::generate populates the public component");
        let pub_uncompressed = pub_point.to_bytes(&group, PointConversionForm::Uncompressed)?;

        // -----------------------------------------------------------------
        // 2. Build the SubjectPublicKeyInfo DER.
        //
        //   SubjectPublicKeyInfo ::= SEQUENCE {
        //       algorithm        AlgorithmIdentifier {
        //           algorithm   id-ecPublicKey   (1.2.840.10045.2.1),
        //           parameters  namedCurve OID   (P-256)
        //       },
        //       subjectPublicKey BIT STRING (uncompressed point bytes)
        //   }
        // -----------------------------------------------------------------
        // id-ecPublicKey OID per RFC 5480 §2.1.1.
        const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
        let id_ec_public_key = ObjectIdentifier::new_unwrap(ID_EC_PUBLIC_KEY);
        let p256_curve_oid = ObjectIdentifier::new_unwrap(OID_ECC_P256);

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: id_ec_public_key,
                parameters: Some(Any::from(p256_curve_oid)),
            },
            subject_public_key: BitString::from_bytes(&pub_uncompressed)
                .expect("BitString::from_bytes accepts non-empty uncompressed point bytes"),
        };
        let issuer_key_der = spki
            .to_der()
            .expect("SubjectPublicKeyInfoOwned encodes to DER for a valid ECDSA SPKI");

        // -----------------------------------------------------------------
        // 3. Construct a synthetic `tbsCertList` and sign it with ECDSA-SHA256.
        //
        // The verifier hashes `crl.info.tbs_der` with SHA-256 (selected by
        // `OID_ECDSA_SHA256`) and verifies the DER-encoded ECDSA signature.
        // The structure of the `tbsCertList` does not need to be a syntactically
        // valid `TBSCertList`; the verifier only treats it as the byte
        // sequence to be hashed.
        // -----------------------------------------------------------------
        let tbs_der: Vec<u8> = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let digest = crate::hash::sha::sha256(&tbs_der)?;
        let sig_der = crate::ec::ecdsa::sign_der(&key, &digest)?;

        // -----------------------------------------------------------------
        // 4. Build the `X509Crl` with matching outer + inner signatureAlgorithm
        //    fields (both = ecdsa-with-SHA256).
        // -----------------------------------------------------------------
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = tbs_der;
        crl.signature = sig_der;
        crl.set_signature_algorithm(AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ECDSA_SHA256)?,
            None,
        ));
        crl.info.signature_algorithm = AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ECDSA_SHA256)?,
            None,
        );

        // -----------------------------------------------------------------
        // 5. Verify — must return `Ok(true)`.
        // -----------------------------------------------------------------
        let method = DefaultCrlMethod::default();
        let result = method.verify(&crl, &issuer_key_der)?;
        assert!(
            result,
            "valid ECDSA-P256 CRL signed by a freshly-generated keypair must verify successfully"
        );
        Ok(())
    }

    /// Group C #10 / Test #4 (Negative — tampered TBS): a CRL whose `tbsCertList`
    /// has been mutated after signing must NOT verify.
    ///
    /// This builds an otherwise-valid ECDSA-P256 CRL using the same construction
    /// recipe as `verify_signature_accepts_valid_ecdsa_p256_crl` (test #3), then
    /// flips a single bit in `crl.info.tbs_der` BEFORE invoking
    /// `DefaultCrlMethod::verify`. The signature itself is well-formed (valid
    /// ECDSA-Sig-Value DER) and the SPKI parses cleanly, so the verifier MUST
    /// reach the cryptographic-verification path and return `Ok(false)` — not
    /// `Err(_)`. The contract is documented at `crl.rs:2161-2162`:
    ///
    ///     "ecdsa_verify_der already returns CryptoResult<bool>: Ok(true) for
    ///      valid, Ok(false) for invalid-but-well-formed, Err for structural."
    ///
    /// This proves the verifier is doing real signature checking rather than
    /// returning `Ok(true)` blindly: any mutation of the signed data must be
    /// detected, exactly as required by RFC 5280 §5.1.2 (CRL signature must
    /// cover the entire `tbsCertList`).
    ///
    /// Compiled only when the `ec` feature is enabled, since the test
    /// exercises the ECDSA verification path which depends on EC types.
    #[cfg(feature = "ec")]
    #[test]
    fn verify_signature_rejects_tampered_crl() -> CryptoResult<()> {
        use der::asn1::BitString;
        use der::Any;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

        use crate::ec::PointConversionForm;

        // -----------------------------------------------------------------
        // 1. Build a valid signed CRL exactly as in test #3.
        // -----------------------------------------------------------------
        let group = EcGroup::from_curve_name(NamedCurve::Prime256v1)?;
        let key = EcKey::generate(&group)?;

        let pub_point = key
            .public_key()
            .expect("EcKey::generate populates the public component");
        let pub_uncompressed = pub_point.to_bytes(&group, PointConversionForm::Uncompressed)?;

        const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
        let id_ec_public_key = ObjectIdentifier::new_unwrap(ID_EC_PUBLIC_KEY);
        let p256_curve_oid = ObjectIdentifier::new_unwrap(OID_ECC_P256);

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: id_ec_public_key,
                parameters: Some(Any::from(p256_curve_oid)),
            },
            subject_public_key: BitString::from_bytes(&pub_uncompressed)
                .expect("BitString::from_bytes accepts non-empty uncompressed point bytes"),
        };
        let issuer_key_der = spki
            .to_der()
            .expect("SubjectPublicKeyInfoOwned encodes to DER for a valid ECDSA SPKI");

        let original_tbs: Vec<u8> = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let digest = crate::hash::sha::sha256(&original_tbs)?;
        let sig_der = crate::ec::ecdsa::sign_der(&key, &digest)?;

        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = original_tbs;
        crl.signature = sig_der;
        crl.set_signature_algorithm(AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ECDSA_SHA256)?,
            None,
        ));
        crl.info.signature_algorithm = AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ECDSA_SHA256)?,
            None,
        );

        // -----------------------------------------------------------------
        // 2. Tamper with `tbs_der` AFTER the signature was computed.
        //
        // Flipping the low bit of the first byte changes the tbsCertList
        // (and therefore the SHA-256 digest the verifier computes) without
        // affecting the wire-format of the signature or SPKI structures.
        // -----------------------------------------------------------------
        let original_first_byte = crl.info.tbs_der[0];
        crl.info.tbs_der[0] ^= 0x01;
        assert_ne!(
            crl.info.tbs_der[0], original_first_byte,
            "tampering must actually mutate the tbsCertList byte"
        );

        // -----------------------------------------------------------------
        // 3. Verify must return `Ok(false)` — NOT `Err(_)`.
        // -----------------------------------------------------------------
        let method = DefaultCrlMethod::default();
        let result = method.verify(&crl, &issuer_key_der)?;
        assert!(
            !result,
            "tampered CRL must NOT verify: ECDSA signature does not cover the mutated tbsCertList"
        );
        Ok(())
    }

    /// Group C #10 / Test #5 (Positive — Ed25519): a CRL signed with PureEd25519
    /// over a freshly-generated Ed25519 keypair must verify successfully.
    ///
    /// This exercises the EdDSA branch of `DefaultCrlMethod::verify` end-to-end:
    ///   1. `crate::ec::curve25519::generate_keypair(EcxKeyType::Ed25519)`
    ///      produces a real 32-byte private + 32-byte public Ed25519 keypair.
    ///   2. The public key is encoded into a DER-serialised
    ///      `SubjectPublicKeyInfo` per RFC 8410 §3:
    ///        * algorithm OID = `id-Ed25519` (1.3.101.112)
    ///        * parameters    = absent (RFC 8410 §3 mandates no parameters)
    ///        * subjectPublicKey = the raw 32-byte public key (no SEC1 prefix)
    ///      — exactly what `crl_verify_eddsa` consumes via
    ///      `EcxPublicKey::new(EcxKeyType::Ed25519, spki.public_key_bytes.clone())`.
    ///   3. A synthetic `tbsCertList` byte sequence is signed via
    ///      `crate::ec::curve25519::ed25519_sign(private_key, tbs, None)`.
    ///      Pure Ed25519 (no context, no pre-hash) is mandated by RFC 8410 §6
    ///      for X.509 / CRL signatures, matching `crl_verify_eddsa`'s call.
    ///   4. Both outer (`X509Crl::signature_algorithm`) and inner
    ///      (`info.signature_algorithm`) algorithm identifiers are set to
    ///      `OID_ED25519` with `parameters = None`.
    ///   5. `DefaultCrlMethod::verify` must return `Ok(true)`.
    ///
    /// Together with the ECDSA positive test (#3) and the negative tests
    /// (#1 outer/inner mismatch, #2 unsupported OID, #4 tampered TBS), this
    /// covers all currently-supported CRL signature algorithm families and
    /// proves that EdDSA verification is wired through to the real Ed25519
    /// implementation in `crate::ec::curve25519`.
    ///
    /// Compiled only when the `ec` feature is enabled, since the test
    /// exercises the EdDSA verification path which depends on EC types.
    #[cfg(feature = "ec")]
    #[test]
    fn verify_signature_accepts_valid_ed25519_crl() -> CryptoResult<()> {
        use der::asn1::BitString;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

        // -----------------------------------------------------------------
        // 1. Generate a fresh Ed25519 keypair.
        // -----------------------------------------------------------------
        let keypair = crate::ec::curve25519::generate_keypair(EcxKeyType::Ed25519)?;
        let pub_bytes = keypair.public_key().as_bytes(); // 32 bytes

        // -----------------------------------------------------------------
        // 2. Build the SubjectPublicKeyInfo DER per RFC 8410 §3.
        //
        //   SubjectPublicKeyInfo ::= SEQUENCE {
        //       algorithm        AlgorithmIdentifier {
        //           algorithm   id-Ed25519       (1.3.101.112),
        //           parameters  ABSENT            (RFC 8410 §3)
        //       },
        //       subjectPublicKey BIT STRING (32 raw public-key bytes)
        //   }
        // -----------------------------------------------------------------
        let ed25519_alg_oid = ObjectIdentifier::new_unwrap(OID_ED25519);

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ed25519_alg_oid,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(pub_bytes)
                .expect("BitString::from_bytes accepts a 32-byte Ed25519 public key"),
        };
        let issuer_key_der = spki
            .to_der()
            .expect("SubjectPublicKeyInfoOwned encodes to DER for a valid Ed25519 SPKI");

        // -----------------------------------------------------------------
        // 3. Sign a synthetic `tbsCertList` with PureEd25519.
        //
        // Per RFC 8410 §6 / RFC 8032 §5.1, PureEd25519 takes the raw message
        // (no pre-hashing) and an empty context — matching the verifier's
        // call to `ed25519_verify(&pk, tbs, sig, None)`.
        // -----------------------------------------------------------------
        let tbs_der: Vec<u8> = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let sig = crate::ec::curve25519::ed25519_sign(keypair.private_key(), &tbs_der, None)?;

        // -----------------------------------------------------------------
        // 4. Build the `X509Crl` with matching outer + inner signatureAlgorithm
        //    fields (both = id-Ed25519, parameters absent).
        // -----------------------------------------------------------------
        let mut crl = X509Crl::new_empty()?;
        crl.info.tbs_der = tbs_der;
        crl.signature = sig;
        crl.set_signature_algorithm(AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ED25519)?,
            None,
        ));
        crl.info.signature_algorithm = AlgorithmIdentifier::new(
            crate::asn1::Asn1Object::from_oid_string(OID_ED25519)?,
            None,
        );

        // -----------------------------------------------------------------
        // 5. Verify — must return `Ok(true)`.
        // -----------------------------------------------------------------
        let method = DefaultCrlMethod::default();
        let result = method.verify(&crl, &issuer_key_der)?;
        assert!(
            result,
            "valid Ed25519 CRL signed by a freshly-generated keypair must verify successfully"
        );
        Ok(())
    }

    // ============================================================
    // Section 14 helpers — parse_reason_code_ext
    // ============================================================

    #[test]
    fn parse_reason_code_ext_success_all_reasons() {
        let pairs: [(u8, RevocationReason); 10] = [
            (0, RevocationReason::Unspecified),
            (1, RevocationReason::KeyCompromise),
            (2, RevocationReason::CaCompromise),
            (3, RevocationReason::AffiliationChanged),
            (4, RevocationReason::Superseded),
            (5, RevocationReason::CessationOfOperation),
            (6, RevocationReason::CertificateHold),
            (8, RevocationReason::RemoveFromCrl),
            (9, RevocationReason::PrivilegeWithdrawn),
            (10, RevocationReason::AaCompromise),
        ];
        for (code, expected) in pairs {
            let bytes = vec![0x0A, 0x01, code];
            let result = parse_reason_code_ext(&bytes);
            assert!(
                matches!(result, Ok(r) if r == expected),
                "code {code}: expected Ok({expected:?}), got {result:?}"
            );
        }
    }

    #[test]
    fn parse_reason_code_ext_wrong_tag_errors() {
        let bytes = [0x0B, 0x01, 0x01]; // 0x0B instead of 0x0A
        match parse_reason_code_ext(&bytes) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("must be DER ENUMERATED"));
                assert!(msg.contains("tag 0x0A"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn parse_reason_code_ext_too_short_errors() {
        let bytes = [0x0A, 0x01];
        match parse_reason_code_ext(&bytes) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("must be DER ENUMERATED"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn parse_reason_code_ext_wrong_length_errors() {
        let bytes = [0x0A, 0x02, 0x00, 0x01]; // length byte 2, not 1
        match parse_reason_code_ext(&bytes) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("ENUMERATED length must be 1"));
                assert!(msg.contains("got 2"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn parse_reason_code_ext_trailing_data_errors() {
        let bytes = [0x0A, 0x01, 0x01, 0xFF]; // one trailing byte
        match parse_reason_code_ext(&bytes) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("trailing data"));
                assert!(msg.contains("1 extra bytes"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn parse_reason_code_ext_reserved_code_7_propagates() {
        let bytes = [0x0A, 0x01, 0x07];
        match parse_reason_code_ext(&bytes) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("revocation reason code 7 is reserved"));
            }
            other => panic!("expected Encoding error for code 7, got {other:?}"),
        }
    }

    // ============================================================
    // Section 14 helpers — base64_encode / base64_decode
    // ============================================================

    #[test]
    fn base64_encode_empty_input() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn base64_encode_decode_round_trip_no_padding() -> CryptoResult<()> {
        let data = b"abc"; // 3 bytes → 4 chars, no padding
        let encoded = base64_encode(data);
        assert_eq!(encoded, "YWJj");
        let decoded = base64_decode(&encoded)?;
        assert_eq!(decoded, data);
        Ok(())
    }

    #[test]
    fn base64_encode_decode_round_trip_one_pad() -> CryptoResult<()> {
        let data = b"ab"; // 2 bytes → "YWI="
        let encoded = base64_encode(data);
        assert_eq!(encoded, "YWI=");
        let decoded = base64_decode(&encoded)?;
        assert_eq!(decoded, data);
        Ok(())
    }

    #[test]
    fn base64_encode_decode_round_trip_two_pad() -> CryptoResult<()> {
        let data = b"a"; // 1 byte → "YQ=="
        let encoded = base64_encode(data);
        assert_eq!(encoded, "YQ==");
        let decoded = base64_decode(&encoded)?;
        assert_eq!(decoded, data);
        Ok(())
    }

    #[test]
    fn base64_encode_decode_round_trip_long_data() -> CryptoResult<()> {
        let data: Vec<u8> = (0..255_u8).collect();
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded)?;
        assert_eq!(decoded, data);
        Ok(())
    }

    #[test]
    fn base64_decode_skips_whitespace() -> CryptoResult<()> {
        let encoded = "YWJj\n";
        let decoded = base64_decode(encoded)?;
        assert_eq!(decoded, b"abc");

        let encoded2 = "Y W\tJ\rj";
        let decoded2 = base64_decode(encoded2)?;
        assert_eq!(decoded2, b"abc");
        Ok(())
    }

    #[test]
    fn base64_decode_invalid_character_errors() {
        match base64_decode("YW*j") {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("invalid character"));
                assert!(msg.contains("0x2a"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn base64_decode_too_many_padding_errors() {
        match base64_decode("Y===") {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("too many '=' padding characters"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn base64_decode_non_padding_after_padding_errors() {
        match base64_decode("YWI=j") {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("non-padding character after '=' padding"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn base64_decode_residual_errors() {
        // 5 characters — not a multiple of 4 after padding
        match base64_decode("YWJjY") {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("residual"));
                assert!(msg.contains("1 characters"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    // ============================================================
    // Section 14 helpers — decode_implicit_boolean
    // ============================================================

    #[test]
    fn decode_implicit_boolean_true_accepts_nonzero() -> CryptoResult<()> {
        assert!(decode_implicit_boolean(&[0xFF])?);
        assert!(decode_implicit_boolean(&[0x01])?);
        assert!(decode_implicit_boolean(&[0x80])?);
        Ok(())
    }

    #[test]
    fn decode_implicit_boolean_false_on_zero() -> CryptoResult<()> {
        assert!(!decode_implicit_boolean(&[0x00])?);
        Ok(())
    }

    #[test]
    fn decode_implicit_boolean_empty_errors() {
        match decode_implicit_boolean(&[]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("BOOLEAN must be 1 content byte"));
                assert!(msg.contains("got 0"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_implicit_boolean_multi_byte_errors() {
        match decode_implicit_boolean(&[0x01, 0x02]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("BOOLEAN must be 1 content byte"));
                assert!(msg.contains("got 2"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    // ============================================================
    // Section 14 helpers — decode_implicit_bit_string_u16
    // ============================================================

    #[test]
    fn decode_implicit_bit_string_u16_empty_errors() {
        match decode_implicit_bit_string_u16(&[]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("BIT STRING content is empty"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_implicit_bit_string_u16_invalid_unused_bits_errors() {
        match decode_implicit_bit_string_u16(&[8, 0x80]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("invalid unused-bits count 8"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_implicit_bit_string_u16_bit_ordering_msb_first() -> CryptoResult<()> {
        // One byte, zero unused bits, value 0x80 → MSB is bit 0 → UNUSED (0x0001)
        let result = decode_implicit_bit_string_u16(&[0x00, 0x80])?;
        assert_eq!(result, 0x0001);

        // 0x40 → bit index 1 → KEY_COMPROMISE (0x0002)
        let result = decode_implicit_bit_string_u16(&[0x00, 0x40])?;
        assert_eq!(result, 0x0002);

        // 0xC0 → bits 0 and 1 → UNUSED | KEY_COMPROMISE (0x0003)
        let result = decode_implicit_bit_string_u16(&[0x00, 0xC0])?;
        assert_eq!(result, 0x0003);
        Ok(())
    }

    #[test]
    fn decode_implicit_bit_string_u16_caps_at_16_bits() -> CryptoResult<()> {
        // 3-byte content with unused_bits=0 — only first 16 bits are used
        let result = decode_implicit_bit_string_u16(&[0x00, 0xFF, 0xFF, 0xFF])?;
        assert_eq!(result, 0xFFFF);
        Ok(())
    }

    #[test]
    fn decode_implicit_bit_string_u16_unused_bits_valid() -> CryptoResult<()> {
        // One byte value 0xFE, unused_bits=1 → bits 0..6 are significant
        // 0xFE = 1111_1110 → bits 0..6 set, bit 7 unused
        let result = decode_implicit_bit_string_u16(&[0x01, 0xFE])?;
        // Bits 0..6 map to u16 bits 0..6 → 0x007F
        assert_eq!(result, 0x007F);
        Ok(())
    }

    // ============================================================
    // Section 14 helpers — decode_pem / encode_pem
    // ============================================================

    #[test]
    fn encode_decode_pem_round_trip() -> CryptoResult<()> {
        let data = b"hello world";
        let pem = encode_pem(data, "TEST BLOCK");
        assert!(pem.starts_with("-----BEGIN TEST BLOCK-----"));
        assert!(pem.ends_with("-----END TEST BLOCK-----\n"));

        let decoded = decode_pem(&pem, &["TEST BLOCK"])?;
        assert_eq!(decoded, data);
        Ok(())
    }

    #[test]
    fn encode_pem_wraps_base64_at_64_chars() {
        let data: Vec<u8> = (0..60_u8).collect(); // 60 bytes → 80 base64 chars
        let pem = encode_pem(&data, "X");
        // At least one line of 64 chars between BEGIN/END
        let lines: Vec<&str> = pem.lines().collect();
        // Find any base64 body line (not BEGIN/END)
        let has_full_line = lines.iter().any(|l| l.len() == 64);
        assert!(
            has_full_line,
            "expected at least one 64-char base64 line: {lines:?}"
        );
    }

    #[test]
    fn decode_pem_missing_begin_errors() {
        match decode_pem("no headers here", &["X"]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("missing '-----BEGIN '"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_pem_missing_end_errors() {
        let pem = "-----BEGIN X-----\nYWJj\n";
        match decode_pem(pem, &["X"]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("missing '-----END '"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_pem_label_mismatch_in_allowed_list() {
        let pem = "-----BEGIN WRONG-----\nYWJj\n-----END WRONG-----\n";
        match decode_pem(pem, &["X509 CRL", "CRL"]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("does not match any of"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_pem_begin_end_label_mismatch_errors() {
        let pem = "-----BEGIN X-----\nYWJj\n-----END Y-----\n";
        match decode_pem(pem, &["X", "Y"]) {
            Err(CryptoError::Encoding(msg)) => {
                assert!(msg.contains("BEGIN/END label mismatch"));
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn decode_pem_accepts_multiple_allowed_labels() -> CryptoResult<()> {
        let pem = encode_pem(b"hi", "CRL");
        let decoded = decode_pem(&pem, &["X509 CRL", "CRL"])?;
        assert_eq!(decoded, b"hi");
        Ok(())
    }

    // ============================================================
    // Section 14 helpers — hex_encode
    // ============================================================

    #[test]
    fn hex_encode_lowercase_hex() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0xFF, 0x01, 0xA0]), "ff01a0");
    }

    // ============================================================
    // Section 14 helpers — asn1_time_to_ossl
    // ============================================================

    #[test]
    fn asn1_time_to_ossl_positive_time() -> CryptoResult<()> {
        let t = Asn1Time::from_unix_timestamp(1_700_000_000)?;
        let ossl = asn1_time_to_ossl(t)?;
        assert_eq!(ossl.to_seconds(), 1_700_000_000);
        Ok(())
    }

    #[test]
    fn asn1_time_to_ossl_negative_saturates_to_zero() -> CryptoResult<()> {
        // Negative Unix timestamp (year 1900) must saturate to ZERO.
        if let Ok(t) = Asn1Time::from_unix_timestamp(-1) {
            let ossl = asn1_time_to_ossl(t)?;
            assert_eq!(ossl, OsslTime::ZERO);
        }
        // If from_unix_timestamp rejects negative (some implementations do),
        // explicitly construct year 1900 via Asn1Time::new and verify saturation.
        if let Ok(t) = Asn1Time::new(1900, 1, 1, 0, 0, 0) {
            let ossl = asn1_time_to_ossl(t)?;
            assert_eq!(ossl, OsslTime::ZERO);
        }
        Ok(())
    }

    // ============================================================
    // Section 14 helpers — ossl_time_to_asn1
    // ============================================================

    #[test]
    fn ossl_time_to_asn1_round_trip_positive() -> CryptoResult<()> {
        let orig = OsslTime::from_seconds(1_700_000_000);
        let asn1 = ossl_time_to_asn1(orig)?;
        let back = asn1_time_to_ossl(asn1)?;
        assert_eq!(back.to_seconds(), orig.to_seconds());
        Ok(())
    }

    // ============================================================
    // Section 14 helpers — parse_integer_extension
    // ============================================================

    #[test]
    fn parse_integer_extension_success() -> CryptoResult<()> {
        // DER INTEGER = 0x1234
        let bytes = [0x02, 0x02, 0x12, 0x34];
        let value = parse_integer_extension(&bytes)?;
        assert_eq!(value, &[0x12, 0x34]);
        Ok(())
    }

    #[test]
    fn parse_integer_extension_single_byte_success() -> CryptoResult<()> {
        let bytes = [0x02, 0x01, 0x42];
        let value = parse_integer_extension(&bytes)?;
        assert_eq!(value, &[0x42]);
        Ok(())
    }

    #[test]
    fn parse_integer_extension_too_short_errors() {
        match parse_integer_extension(&[]) {
            Err(CryptoError::Encoding(_)) => (),
            other => panic!("expected Encoding error, got {other:?}"),
        }
        match parse_integer_extension(&[0x02]) {
            Err(CryptoError::Encoding(_)) => (),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    #[test]
    fn parse_integer_extension_wrong_tag_errors() {
        match parse_integer_extension(&[0x04, 0x01, 0x42]) {
            Err(CryptoError::Encoding(_)) => (),
            other => panic!("expected Encoding error, got {other:?}"),
        }
    }

    // ============================================================
    // Section 14 helpers — algorithm_identifiers_match
    // ============================================================

    #[test]
    fn algorithm_identifiers_match_same_oid_matches() -> CryptoResult<()> {
        let a =
            AlgorithmIdentifier::new(Asn1Object::from_oid_string("1.2.840.113549.1.1.11")?, None);
        let b =
            AlgorithmIdentifier::new(Asn1Object::from_oid_string("1.2.840.113549.1.1.11")?, None);
        assert!(algorithm_identifiers_match(&a, &b));
        Ok(())
    }

    #[test]
    fn algorithm_identifiers_match_different_oid_mismatches() -> CryptoResult<()> {
        let a =
            AlgorithmIdentifier::new(Asn1Object::from_oid_string("1.2.840.113549.1.1.11")?, None);
        let b =
            AlgorithmIdentifier::new(Asn1Object::from_oid_string("1.2.840.113549.1.1.12")?, None);
        assert!(!algorithm_identifiers_match(&a, &b));
        Ok(())
    }

    // ============================================================
    // Section 12 — cache_extensions idempotency
    // ============================================================

    #[test]
    fn cache_extensions_is_idempotent() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        // Force initial cache (no extensions present — just sets flag).
        crl.cache_extensions()?;
        assert!(crl.flags().contains(CrlFlags::EXTENSIONS_CACHED));

        // Second call must be a short-circuit (no panic, no state change).
        crl.cache_extensions()?;
        assert!(crl.flags().contains(CrlFlags::EXTENSIONS_CACHED));
        Ok(())
    }

    #[test]
    fn cache_extensions_sets_exflag_set() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        crl.cache_extensions()?;
        assert!(crl.flags().contains(CrlFlags::EXFLAG_SET));
        Ok(())
    }

    #[test]
    fn cache_extensions_caches_crl_number_extension() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        // CRL Number (OID 2.5.29.20): INTEGER value 1
        crl.add_extension(X509Extension::new(
            "2.5.29.20".to_string(),
            false,
            vec![0x02, 0x01, 0x01],
        ));
        // add_extension clears the EXTENSIONS_CACHED flag; re-caching should
        // populate crl_number.
        crl.cache_extensions()?;
        assert!(crl.crl_number().is_some());
        if let Some(num) = crl.crl_number() {
            assert_eq!(num, &[0x01]);
        }
        Ok(())
    }

    // ============================================================
    // Section 13 — Display implementation smoke test
    // ============================================================

    #[test]
    fn x509_crl_display_produces_output() -> CryptoResult<()> {
        let crl = X509Crl::new_empty()?;
        let output = format!("{crl}");
        // The output must mention the key CRL attributes: "Certificate Revocation
        // List" or "CRL" plus "Issuer" or similar. We keep this test loose to
        // avoid coupling to exact formatting.
        assert!(!output.is_empty());
        // Signature algorithm placeholder "0.0.0" must render somewhere.
        assert!(
            output.contains("Certificate")
                || output.contains("CRL")
                || output.contains("Issuer")
                || output.contains("Version")
                || output.contains("Last Update")
                || output.contains("Signature"),
            "display output missing expected CRL label: {output}"
        );
        Ok(())
    }

    // ============================================================
    // Round-trip: sort + is_revoked across multiple entries
    // ============================================================

    #[test]
    fn sort_preserves_deterministic_sequence_across_duplicates() -> CryptoResult<()> {
        let mut crl = X509Crl::new_empty()?;
        // Add three entries with equal serial numbers (different implicit order).
        for _ in 0..3 {
            crl.add_revoked(RevokedEntry::new(vec![0x10], make_time()))?;
        }
        crl.add_revoked(RevokedEntry::new(vec![0x20], make_time()))?;

        crl.sort();
        assert_eq!(crl.revoked_entries().len(), 4);
        // First three entries share the same serial; all should precede 0x20.
        assert_eq!(crl.revoked_entries()[0].serial_number(), &[0x10]);
        assert_eq!(crl.revoked_entries()[1].serial_number(), &[0x10]);
        assert_eq!(crl.revoked_entries()[2].serial_number(), &[0x10]);
        assert_eq!(crl.revoked_entries()[3].serial_number(), &[0x20]);

        // Sequence numbers are assigned by sort order (0, 1, 2, 3).
        for (idx, entry) in crl.revoked_entries().iter().enumerate() {
            let expected_seq = u32::try_from(idx).unwrap_or(u32::MAX);
            assert_eq!(entry.sequence(), expected_seq);
        }
        Ok(())
    }
}
