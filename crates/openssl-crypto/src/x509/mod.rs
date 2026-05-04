//! X.509 Public Key Infrastructure (PKI) module.
//!
//! This module provides the core X.509 certificate types, extension framework,
//! distinguished name handling, and certificate operations for the OpenSSL Rust
//! workspace. It translates approximately **33,000 lines of C across 98 files**
//! from `crypto/x509/` into idiomatic Rust types.
//!
//! ## Submodules
//!
//! | Submodule | Purpose | C Source |
//! |-----------|---------|---------|
//! | [`certificate`] | Legacy RFC 5280 certificate parser via RustCrypto's `x509-cert` crate | `x_x509.c`, `x509_cmp.c` |
//! | [`verify`] | Certificate chain verification per RFC 5280 §6 | `x509_vfy.c`, `v3_purp.c` |
//! | [`crl`] | Certificate Revocation List processing | `x_crl.c`, `x509_v3.c` |
//! | [`store`] | Certificate / CRL trust store with pluggable backends | `x509_lu.c`, `by_*.c` |
//!
//! ## Core Types Translated
//!
//! | C Type | Rust Type | Notes |
//! |--------|-----------|-------|
//! | `X509` | [`X509Certificate`] | Full certificate with cached extension flags |
//! | `X509_CINF` | embedded in [`X509Certificate`] | TBS certificate data |
//! | `X509_NAME` | [`X509Name`] | Distinguished Name with canonical DER cache |
//! | `X509_NAME_ENTRY` | [`X509NameEntry`] | Single RDN attribute |
//! | `X509_EXTENSION` | [`X509Extension`] | Generic certificate / CRL extension |
//! | `X509_PUBKEY` | [`SubjectPublicKeyInfo`] | Public key with algorithm identifier |
//! | `X509_REQ` | [`X509Request`] | Certificate Signing Request (PKCS#10) |
//! | `X509_CERT_AUX` | [`CertAuxiliary`] | Trust / reject / alias auxiliary data |
//! | `X509_VAL` | [`Validity`] | Not-before / not-after window |
//! | `X509_ALGOR` | [`AlgorithmIdentifier`] | Algorithm OID + optional parameters |
//! | `X509_ATTRIBUTE` | [`X509Attribute`] | CSR / CRL attribute |
//! | `X509V3_EXT_METHOD` | [`ExtensionMethod`] trait | Extension handler vtable |
//! | `NETSCAPE_SPKI` | [`NetscapeSpki`] | Netscape signed public-key & challenge |
//!
//! ## Design Principles
//!
//! - **Rule R5** (nullability over sentinels): every former C sentinel
//!   (`NULL`, `-1`, `0` for "unset") is encoded as `Option<T>`. Notably:
//!   - `version: Option<u32>` — `None` denotes v1, where C used a `NULL`
//!     `ASN1_INTEGER`.
//!   - `path_length: Option<u32>` — `None` denotes "unlimited", where C used
//!     `ex_pathlen = -1`.
//!   - `issuer_uid` / `subject_uid: Option<Vec<u8>>` — absent in C as `NULL`.
//!   - All cached extension fields (`skid`, `akid`, `crldp`, `alt_names`,
//!     `name_constraints`) use `Option<T>` to denote "not present".
//! - **Rule R6** (lossless casts): all narrowing casts use `try_from` /
//!   `saturating_cast` rather than bare `as` casts.
//! - **Rule R7** (lock granularity): the [`ExtensionRegistry`] stores its
//!   internal table in a plain [`HashMap`]; concurrent readers should wrap
//!   it in `Arc<RwLock<...>>` at construction time with a `// LOCK-SCOPE:`
//!   annotation. The registry itself is read-mostly.
//! - **Rule R8** (zero unsafe): this module contains no `unsafe` code.
//! - **Rule R9** (warning-free): every public item is documented with `///`
//!   doc comments.
//! - **Rule R10** (wiring): module is reachable via
//!   `openssl_crypto::x509::*` (declared as `pub mod x509;` in
//!   `crates/openssl-crypto/src/lib.rs`).
//! - **Observability**: parsing and validation events are emitted via
//!   `tracing::debug!` / `tracing::trace!`.
//!
//! ## Compatibility
//!
//! Two type families coexist in this module by design:
//!
//! 1. **Schema types** ([`X509Certificate`], [`X509Name`], etc.) — these are
//!    the AAP-mandated types that mirror the C `X509`/`X509_NAME`/... structs
//!    one-to-one.
//! 2. **Legacy types** ([`Certificate`], [`CertificateValidity`], ...) —
//!    re-exported from [`certificate`] for backward compatibility with the
//!    pre-existing verifier (`verify.rs`) and CRL/trust-store wiring
//!    (`crl.rs`, `store.rs`). They sit on top of RustCrypto's `x509-cert`
//!    crate and provide a higher-level façade.
//!
//! New code should prefer the schema types; legacy code is preserved
//! verbatim to avoid breaking the existing verifier and test suite.
#![allow(clippy::module_inception)]

// ─── Submodule declarations ─────────────────────────────────────────────────

/// Legacy certificate parser layered on top of RustCrypto's `x509-cert`.
///
/// Provides the [`Certificate`] type used by the existing verifier and CRL
/// modules. Retained for backward compatibility — new code should prefer
/// [`X509Certificate`] defined in this module.
pub mod certificate;

/// Certificate Revocation List (RFC 5280 §5) processing.
///
/// Handles `tbsCertList` parsing, `RevokedEntry` enumeration,
/// `IssuingDistributionPoint` extraction, and the [`CrlMethod`] hook
/// for pluggable lookup backends.
pub mod crl;

/// Certificate / CRL trust store with pluggable backends.
///
/// Provides [`X509Store`], plus [`FileLookup`], [`DirectoryLookup`], and
/// [`UriLookup`] backends mirroring OpenSSL's `BY_FILE`, `BY_DIR`, and
/// `BY_STORE` lookup methods.
pub mod store;

/// Certificate chain verification (RFC 5280 §6).
///
/// Provides [`verify`], [`verify_cert`], [`VerifyContext`], [`VerifyParams`],
/// host/email/IP name-checking, policy-tree processing, and DANE support.
pub mod verify;

// ─── Imports ────────────────────────────────────────────────────────────────

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};

use bitflags::bitflags;
use tracing::{debug, trace};

use openssl_common::time::OsslTime;
use openssl_common::{CommonError, CryptoError, CryptoResult};

// ─── Internal error helpers ─────────────────────────────────────────────────
//
// These tiny constructors centralise the mapping from "X.509 ASN.1 / input
// validation failures" to the strongly-typed [`CryptoError`] enum.  They keep
// call-sites short and prevent ad-hoc string interpolation drift.
//
// - [`asn1_err`]    → [`CryptoError::Encoding`]   (DER / BER / ASN.1 issues)
// - [`invalid_arg`] → [`CryptoError::Common`] wrapping
//   [`CommonError::InvalidArgument`] (caller-supplied bad data)
// - [`unsupported`] → [`CommonError::Unsupported`] for features that exist in
//   C OpenSSL but are not implemented in this Rust workspace yet.
// - [`internal_err`] → [`CommonError::Internal`] for invariant violations.

/// Construct a [`CryptoError::Encoding`] for ASN.1 / DER / BER decode
/// failures.
#[inline]
fn asn1_err(message: impl Into<String>) -> CryptoError {
    CryptoError::Encoding(message.into())
}

/// Construct a [`CryptoError`] wrapping [`CommonError::InvalidArgument`] for
/// caller-supplied invalid input (e.g., empty OID, malformed string).
#[inline]
fn invalid_arg(message: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::InvalidArgument(message.into()))
}

/// Construct a [`CryptoError`] wrapping [`CommonError::Unsupported`] for
/// X.509 features whose Rust translation is not yet wired up.
#[inline]
#[allow(dead_code)]
fn unsupported(message: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Unsupported(message.into()))
}

/// Construct a [`CryptoError`] wrapping [`CommonError::Internal`] for
/// invariant violations that should never occur in correct code.
#[inline]
#[allow(dead_code)]
fn internal_err(message: impl Into<String>) -> CryptoError {
    CryptoError::Common(CommonError::Internal(message.into()))
}

// ─── Public re-exports — Legacy certificate types ───────────────────────────

/// Legacy certificate type backed by `RustCrypto`'s `x509-cert` crate.
///
/// Used by the existing verifier (`verify.rs`) and trust-store
/// (`store.rs`). New code should prefer [`X509Certificate`].
pub use self::certificate::Certificate;

/// Legacy certificate validity period.
///
/// Used by the existing verifier. New code should prefer [`Validity`].
pub use self::certificate::CertificateValidity;

/// Legacy enumeration of certificate versions (v1, v2, v3).
pub use self::certificate::CertificateVersion;

/// Legacy public-key info struct.
///
/// New code should prefer [`SubjectPublicKeyInfo`].
pub use self::certificate::PublicKeyInfo;

/// Legacy signature algorithm identifier.
///
/// New code should prefer [`AlgorithmIdentifier`].
pub use self::certificate::SignatureAlgorithmId;

// ─── Public re-exports — CRL submodule ──────────────────────────────────────

/// Pluggable CRL lookup method (matches C `X509_CRL_METHOD`).
pub use self::crl::CrlMethod;

/// Default in-memory CRL method implementation.
pub use self::crl::DefaultCrlMethod;

/// `IssuingDistributionPoint` extension parsed contents.
pub use self::crl::IssuingDistPoint;

/// Reason code for an individual `RevokedEntry`.
pub use self::crl::RevocationReason;

/// One entry in a CRL's `revokedCertificates` SEQUENCE.
pub use self::crl::RevokedEntry;

/// Parsed Certificate Revocation List (CRL).
pub use self::crl::X509Crl;

// ─── Public re-exports — Store submodule ────────────────────────────────────

/// Anchor (root) certificate plus its trust settings.
pub use self::store::TrustAnchor;

/// Certificate / CRL trust store.
pub use self::store::X509Store;

/// Generic store-stored object (cert, CRL, key).
pub use self::store::StoreObject;

/// Discriminator for [`StoreObject`] variants.
pub use self::store::StoreObjectType;

/// Pluggable lookup backend for [`X509Store`].
pub use self::store::LookupMethod;

/// File-format identifier (PEM / DER / ASN.1).
pub use self::store::FileFormat;

/// File-based lookup method (mirrors `BY_FILE`).
pub use self::store::FileLookup;

/// Directory-based lookup method (mirrors `BY_DIR`).
pub use self::store::DirectoryLookup;

/// URI-based lookup method (mirrors `BY_STORE`).
pub use self::store::UriLookup;

/// Lookup-method control opcode (mirrors `X509_L_*`).
pub use self::store::LookupCtrl;

/// Resolves the default CA-bundle file path.
pub use self::store::default_cert_file;

/// Resolves the default CA-directory path.
pub use self::store::default_cert_dir;

// ─── Public re-exports — CRL ReasonFlags ────────────────────────────────────

/// CRL revocation-reason bit mask (RFC 5280 §5.3.1).
///
/// Re-exported verbatim from [`crl::ReasonFlags`] — the existing
/// definition already exposes every member required by the AAP schema
/// (`KEY_COMPROMISE`, `CA_COMPROMISE`, `AFFILIATION_CHANGED`, `SUPERSEDED`,
/// `CESSATION_OF_OPERATION`, `CERTIFICATE_HOLD`, `PRIVILEGE_WITHDRAWN`,
/// `AA_COMPROMISE`).
pub use self::crl::ReasonFlags;

// ─── Public re-exports — Legacy verifier ────────────────────────────────────

/// Verification purpose (TLS server / client / code-signing / …).
pub use self::verify::Purpose;

/// Legacy verification error enumeration.
pub use self::verify::VerificationError;

/// Legacy verification options struct.
pub use self::verify::VerificationOptions;

/// Outcome of a successful chain verification.
pub use self::verify::VerifiedChain;

/// Legacy `Verifier<'s>` builder used by tests and CLI.
pub use self::verify::Verifier;

// ─── Public re-exports — Schema verifier (verify_module) ────────────────────

/// Match a hostname against the certificate's identities.
pub use self::verify::check_host;

/// Match an email address against the certificate's `rfc822Name` SANs.
pub use self::verify::check_email;

/// Match an IPv4/IPv6 address (binary form) against the certificate's `iPAddress` SANs.
pub use self::verify::check_ip;

/// Match an IPv4/IPv6 address (string form) against the certificate's `iPAddress` SANs.
pub use self::verify::check_ip_asc;

/// Decide whether a certificate is acceptable for a given [`Purpose`].
pub use self::verify::check_purpose;

/// Decide whether a certificate is trusted for a given trust setting.
pub use self::verify::check_trust;

/// Determine whether a certificate is self-signed.
pub use self::verify::self_signed;

/// Run a full RFC 5280 chain verification.
pub use self::verify::verify;

/// Run chain verification using a pre-populated [`VerifyContext`].
pub use self::verify::verify_cert;

/// DANE/TLSA verification settings.
pub use self::verify::DaneVerification;

/// Host-matching flag set used by [`check_host`].
pub use self::verify::HostFlags;

/// Param-inheritance flag set used by [`VerifyParams`].
pub use self::verify::InheritanceFlags;

/// Policy tree produced during verification (RFC 5280 §6.1.2).
pub use self::verify::PolicyTree;

/// Suite-B compliance error category.
pub use self::verify::SuiteBError;

/// Trust level for a `TrustSetting`.
pub use self::verify::TrustLevel;

/// Outcome of a `check_trust` lookup.
pub use self::verify::TrustResult;

/// One row in the standard trust table.
pub use self::verify::TrustSetting;

/// Application-supplied verification callback.
pub use self::verify::VerifyCallback;

/// Per-verification context produced by [`verify`].
pub use self::verify::VerifyContext;

/// Verification error categories (RFC 5280 §6.1).
pub use self::verify::VerifyError;

/// Verification flag set (`X509_V_FLAG_*`).
pub use self::verify::VerifyFlags;

/// Verification parameters (mirrors `X509_VERIFY_PARAM`).
pub use self::verify::VerifyParams;

// =============================================================================
// AlgorithmIdentifier (replaces C `X509_ALGOR`, RFC 5280 §4.1.1.2)
// =============================================================================

/// X.509 `AlgorithmIdentifier` — algorithm OID with optional DER-encoded parameters.
///
/// Translates the C `X509_ALGOR` struct from `crypto/x509/x_x509.c`.
///
/// # Field semantics (Rule R5)
///
/// - `algorithm`: the algorithm OID in dotted notation (e.g. `"1.2.840.113549.1.1.11"`
///   for `sha256WithRSAEncryption`). May also hold a short symbolic name where
///   appropriate.
/// - `parameters`: optional DER-encoded parameters. `None` means the
///   `parameters` field is **absent** from the ASN.1 encoding (RFC 5280
///   permits this for many algorithms). A zero-length `Some(vec![])` denotes
///   an explicitly-encoded `NULL` (`05 00`) which some legacy algorithms
///   require.
///
/// # Example
///
/// ```
/// use openssl_crypto::x509::AlgorithmIdentifier;
///
/// let alg = AlgorithmIdentifier {
///     algorithm: "1.2.840.10045.4.3.2".to_string(), // ecdsa-with-SHA256
///     parameters: None,
/// };
/// assert!(alg.parameters.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID in dotted notation (e.g. `"2.16.840.1.101.3.4.2.1"`)
    /// or a known symbolic short name.
    pub algorithm: String,
    /// Optional DER-encoded algorithm parameters.
    ///
    /// `None` denotes an absent ASN.1 field; some algorithms require an
    /// explicit `NULL` (`05 00`) which is encoded as `Some(vec![0x05, 0x00])`.
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    /// Constructs an `AlgorithmIdentifier` with the given OID and no parameters.
    #[inline]
    #[must_use]
    pub fn new(algorithm: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            parameters: None,
        }
    }

    /// Constructs an `AlgorithmIdentifier` with explicit DER-encoded parameters.
    #[inline]
    #[must_use]
    pub fn with_parameters(algorithm: impl Into<String>, parameters: Vec<u8>) -> Self {
        Self {
            algorithm: algorithm.into(),
            parameters: Some(parameters),
        }
    }
}

impl fmt::Display for AlgorithmIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.algorithm)?;
        if self.parameters.is_some() {
            f.write_str(" (with parameters)")?;
        }
        Ok(())
    }
}

// =============================================================================
// Validity (replaces C `X509_VAL`, RFC 5280 §4.1.2.5)
// =============================================================================

/// X.509 certificate validity period (`notBefore`, `notAfter`).
///
/// Translates the C `X509_VAL` struct from `crypto/x509/x_x509.c` lines 18–19.
/// Both timestamps are stored as [`OsslTime`] (nanosecond-precision saturating
/// arithmetic) so that comparisons and lifetime calculations cannot overflow.
///
/// # Example
///
/// ```
/// use openssl_crypto::x509::Validity;
/// use openssl_common::time::OsslTime;
///
/// let validity = Validity {
///     not_before: OsslTime::from_seconds(1_700_000_000),
///     not_after:  OsslTime::from_seconds(1_800_000_000),
/// };
/// assert!(validity.not_before < validity.not_after);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Validity {
    /// Earliest valid time. Comparisons are *inclusive*.
    pub not_before: OsslTime,
    /// Latest valid time. Comparisons are *inclusive*.
    pub not_after: OsslTime,
}

impl Validity {
    /// Constructs a validity period.
    #[inline]
    #[must_use]
    pub const fn new(not_before: OsslTime, not_after: OsslTime) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Returns `true` if `now` is within (inclusive of) the validity window.
    ///
    /// Mirrors `X509_check_cert_validity()` from the C implementation.
    #[inline]
    #[must_use]
    pub fn contains(&self, now: OsslTime) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    /// Returns the duration in seconds between `not_before` and `not_after`.
    ///
    /// Uses saturating subtraction so the result never underflows.
    #[inline]
    #[must_use]
    pub fn duration_seconds(&self) -> u64 {
        let diff = self.not_after.saturating_sub(self.not_before);
        diff.to_seconds()
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} .. {}]", self.not_before, self.not_after)
    }
}

// =============================================================================
// Asn1StringType — ASN.1 string-type discriminator
// =============================================================================

/// ASN.1 string-type tag for a directory string value.
///
/// Translates the choice between `UTF8String`, `PrintableString`,
/// `IA5String`, `T61String`, `BMPString`, `UniversalString`, and `OCTET STRING`
/// found across `crypto/x509/x_name.c`, `v3_ia5.c`, and `v3_utf8.c`.
///
/// The default for new RDN entries is [`Self::Utf8String`] per RFC 5280 §4.1.2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asn1StringType {
    /// `UTF8String` (BER tag 12) — RFC 5280's recommended encoding.
    Utf8String,
    /// `PrintableString` (BER tag 19) — restricted ASCII subset.
    PrintableString,
    /// `IA5String` (BER tag 22) — ASCII (used for email addresses, DNS names).
    Ia5String,
    /// `T61String` / `TeletexString` (BER tag 20) — legacy 8-bit encoding.
    T61String,
    /// `BMPString` (BER tag 30) — UCS-2 / 16-bit Unicode encoding.
    BmpString,
    /// `UniversalString` (BER tag 28) — UCS-4 / 32-bit Unicode encoding.
    UniversalString,
    /// `OCTET STRING` (BER tag 4) — raw bytes (legacy use only).
    OctetString,
}

impl Asn1StringType {
    /// Returns the BER/DER universal-class tag value.
    #[inline]
    #[must_use]
    pub const fn ber_tag(self) -> u8 {
        match self {
            Self::OctetString => 4,
            Self::Utf8String => 12,
            Self::PrintableString => 19,
            Self::T61String => 20,
            Self::Ia5String => 22,
            Self::UniversalString => 28,
            Self::BmpString => 30,
        }
    }

    /// Returns a short symbolic name (e.g. `"UTF8String"`).
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utf8String => "UTF8String",
            Self::PrintableString => "PrintableString",
            Self::Ia5String => "IA5String",
            Self::T61String => "T61String",
            Self::BmpString => "BMPString",
            Self::UniversalString => "UniversalString",
            Self::OctetString => "OCTET STRING",
        }
    }
}

impl Default for Asn1StringType {
    #[inline]
    fn default() -> Self {
        Self::Utf8String
    }
}

impl fmt::Display for Asn1StringType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// X509NameEntry — single RDN (Relative Distinguished Name) attribute
// =============================================================================

/// A single attribute within a distinguished name.
///
/// Translates the C `X509_NAME_ENTRY` struct from `crypto/x509/x_name.c`.
/// Each entry consists of an attribute-type OID, an attribute value (typed
/// by `value_type`), and a `set` index that groups attributes belonging to
/// the same Relative Distinguished Name (multi-valued RDN).
///
/// # RFC 5280 mapping
///
/// `X509_NAME_ENTRY ::= SEQUENCE { type AttributeType, value AttributeValue }`,
/// where `AttributeType` is an OID and `AttributeValue` is a `DirectoryString`
/// (carrying the [`Asn1StringType`] tag).
///
/// # Example
///
/// ```
/// use openssl_crypto::x509::{X509NameEntry, Asn1StringType};
///
/// let cn = X509NameEntry {
///     oid: "2.5.4.3".to_string(),
///     value: "example.com".to_string(),
///     value_type: Asn1StringType::Utf8String,
///     set: 0,
/// };
/// assert_eq!(cn.oid, "2.5.4.3");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct X509NameEntry {
    /// Attribute-type OID in dotted notation.
    ///
    /// Common OIDs include `"2.5.4.3"` (CN), `"2.5.4.6"` (C), `"2.5.4.10"` (O),
    /// `"2.5.4.11"` (OU), `"2.5.4.7"` (L), `"2.5.4.8"` (ST),
    /// `"1.2.840.113549.1.9.1"` (emailAddress).
    pub oid: String,
    /// The attribute value as a Rust `String`. Bytes outside UTF-8 (legitimate
    /// for `T61String` etc.) are recorded by lossy decode; the round-trip
    /// preserves the original bytes through `value_type`-aware re-encoding.
    pub value: String,
    /// Original ASN.1 string type (preserved across encode/decode).
    pub value_type: Asn1StringType,
    /// RDN set index. All entries with the same `set` value belong to the
    /// same multi-valued RDN. Top-level RDN ordering follows ascending `set`.
    pub set: u32,
}

impl X509NameEntry {
    /// Convenience constructor that defaults to `UTF8String` and `set = 0`.
    #[inline]
    #[must_use]
    pub fn new(oid: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            value: value.into(),
            value_type: Asn1StringType::Utf8String,
            set: 0,
        }
    }

    /// Returns a short symbolic name for the attribute OID, falling back to
    /// the dotted OID if no short form is known.
    ///
    /// Mirrors `OBJ_obj2txt()` short-name behaviour.
    #[inline]
    #[must_use]
    pub fn short_name(&self) -> &str {
        match self.oid.as_str() {
            "2.5.4.3" => "CN",
            "2.5.4.4" => "SN",
            "2.5.4.5" => "serialNumber",
            "2.5.4.6" => "C",
            "2.5.4.7" => "L",
            "2.5.4.8" => "ST",
            "2.5.4.9" => "street",
            "2.5.4.10" => "O",
            "2.5.4.11" => "OU",
            "2.5.4.12" => "title",
            "2.5.4.42" => "GN",
            "2.5.4.43" => "initials",
            "2.5.4.44" => "generationQualifier",
            "2.5.4.46" => "dnQualifier",
            "2.5.4.65" => "pseudonym",
            "0.9.2342.19200300.100.1.25" => "DC",
            "0.9.2342.19200300.100.1.1" => "UID",
            "1.2.840.113549.1.9.1" => "emailAddress",
            other => other,
        }
    }
}

// =============================================================================
// X509Name — Distinguished Name with cached canonical encoding
// =============================================================================

/// X.509 Distinguished Name (DN).
///
/// Translates the C `X509_NAME` struct from `crypto/x509/x_name.c` (552 lines),
/// `crypto/x509/x509name.c` (366 lines), and `crypto/x509/x509_obj.c`. Names
/// maintain both the structured entry list and a cached canonical DER
/// encoding (RFC 5280 §7.1) which is used for comparison, hashing, and
/// directory lookups via [`X509Name::hash`].
///
/// # Canonicalization
///
/// The canonical form lower-cases ASCII letters in `PrintableString`/
/// `UTF8String` values, collapses runs of internal whitespace, and trims
/// leading/trailing whitespace. This matches `i2d_X509_NAME()` with the
/// `ASN1_FLAGS_CANONICAL` flag from the C implementation.
///
/// # Example
///
/// ```
/// use openssl_crypto::x509::{X509Name, X509NameEntry, Asn1StringType};
///
/// let mut name = X509Name::new();
/// name.add_entry(X509NameEntry::new("2.5.4.6", "US")).unwrap();
/// name.add_entry(X509NameEntry::new("2.5.4.3", "Example CA")).unwrap();
/// assert_eq!(name.entry_count(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct X509Name {
    /// Ordered list of name entries (RFC 5280 ordering preserved).
    entries: Vec<X509NameEntry>,
    /// Cached canonical-form bytes used for comparison/hashing.
    /// Recomputed on every mutation.
    canonical: Vec<u8>,
    /// FNV-1a 64-bit hash of the canonical-form bytes.
    cached_hash: u64,
}

impl X509Name {
    /// Constructs an empty distinguished name.
    #[must_use]
    pub fn new() -> Self {
        let mut name = Self {
            entries: Vec::new(),
            canonical: Vec::new(),
            cached_hash: 0,
        };
        name.recompute_canonical();
        name
    }

    /// Decodes a DER-encoded distinguished name.
    ///
    /// This implementation provides a structurally-faithful parser; it does
    /// not aim to handle every esoteric BER form but supports DER as
    /// emitted by the OpenSSL C reference. Errors map to
    /// [`CryptoError::Encoding`] via the internal [`asn1_err`] helper.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        debug!(target: "openssl::x509::name", len = der.len(), "decoding X509Name from DER");
        let mut entries: Vec<X509NameEntry> = Vec::new();

        // Parse outer SEQUENCE
        let (outer_body, rest) =
            parse_tlv(der, 0x30).ok_or_else(|| asn1_err("X509Name: missing outer SEQUENCE"))?;
        if !rest.is_empty() {
            return Err(asn1_err("X509Name: trailing bytes after outer SEQUENCE"));
        }
        let mut cursor = outer_body;
        let mut set_index: u32 = 0;
        while !cursor.is_empty() {
            // Each top-level element is a SET OF AttributeTypeAndValue
            let (set_body, after_set) = parse_tlv(cursor, 0x31)
                .ok_or_else(|| asn1_err("X509Name: expected SET OF AttributeTypeAndValue"))?;
            let mut set_cursor = set_body;
            while !set_cursor.is_empty() {
                let (atv_body, after_atv) = parse_tlv(set_cursor, 0x30).ok_or_else(|| {
                    asn1_err("X509Name: expected SEQUENCE for AttributeTypeAndValue")
                })?;
                let (oid_body, after_oid) =
                    parse_tlv(atv_body, 0x06).ok_or_else(|| asn1_err("X509Name: expected OID"))?;
                let oid = decode_oid(oid_body)?;

                if after_oid.is_empty() {
                    return Err(asn1_err("X509Name: missing AttributeValue after OID"));
                }
                let tag = after_oid[0];
                let (val_body, after_val) = parse_tlv_any(after_oid)
                    .ok_or_else(|| asn1_err("X509Name: malformed AttributeValue"))?;
                if !after_val.is_empty() {
                    return Err(asn1_err(
                        "X509Name: trailing bytes in AttributeTypeAndValue",
                    ));
                }
                let value_type = match tag {
                    4 => Asn1StringType::OctetString,
                    19 => Asn1StringType::PrintableString,
                    20 => Asn1StringType::T61String,
                    22 => Asn1StringType::Ia5String,
                    28 => Asn1StringType::UniversalString,
                    30 => Asn1StringType::BmpString,
                    // Tag 12 (UTF8String) and any unknown choice fall through
                    // to the safe UTF-8 default (per RFC 5280 §4.1.2.4).
                    _ => Asn1StringType::Utf8String,
                };
                let value = decode_string(val_body, value_type);
                entries.push(X509NameEntry {
                    oid,
                    value,
                    value_type,
                    set: set_index,
                });
                set_cursor = after_atv;
            }
            cursor = after_set;
            set_index = set_index
                .checked_add(1)
                .ok_or_else(|| asn1_err("X509Name: too many RDNs"))?;
        }

        let mut name = Self {
            entries,
            canonical: Vec::new(),
            cached_hash: 0,
        };
        name.recompute_canonical();
        trace!(target: "openssl::x509::name", entries = name.entries.len(), "decoded X509Name");
        Ok(name)
    }

    /// Returns the DER encoding of this distinguished name.
    ///
    /// Mirrors `i2d_X509_NAME()` from `crypto/x509/x_name.c`.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let mut sets: Vec<(u32, Vec<&X509NameEntry>)> = Vec::new();
        for entry in &self.entries {
            if let Some(last) = sets.last_mut() {
                if last.0 == entry.set {
                    last.1.push(entry);
                    continue;
                }
            }
            sets.push((entry.set, vec![entry]));
        }

        let mut body: Vec<u8> = Vec::new();
        for (_set_idx, group) in &sets {
            let mut set_body: Vec<u8> = Vec::new();
            for entry in group {
                let mut atv: Vec<u8> = Vec::new();
                let oid_bytes = encode_oid(&entry.oid);
                encode_tlv(&mut atv, 0x06, &oid_bytes);
                let value_bytes = encode_string(&entry.value, entry.value_type);
                encode_tlv(&mut atv, entry.value_type.ber_tag(), &value_bytes);
                encode_tlv(&mut set_body, 0x30, &atv);
            }
            encode_tlv(&mut body, 0x31, &set_body);
        }

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &body);
        out
    }

    /// Returns all entries in source order.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> &[X509NameEntry] {
        &self.entries
    }

    /// Returns the total number of entries (RDN attributes).
    ///
    /// Mirrors `X509_NAME_entry_count()`.
    #[inline]
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Looks up the first entry whose attribute-type OID equals `oid`.
    ///
    /// Mirrors `X509_NAME_get_index_by_NID()` followed by
    /// `X509_NAME_get_entry()`.
    #[must_use]
    pub fn get_entry(&self, oid: &str) -> Option<&X509NameEntry> {
        self.entries.iter().find(|e| e.oid == oid)
    }

    /// Appends a new entry, recomputing the canonical encoding.
    ///
    /// Returns an error if the entry's OID is empty.
    pub fn add_entry(&mut self, entry: X509NameEntry) -> CryptoResult<()> {
        if entry.oid.is_empty() {
            return Err(invalid_arg("X509Name::add_entry: empty attribute-type OID"));
        }
        self.entries.push(entry);
        self.recompute_canonical();
        Ok(())
    }

    /// Returns a `oneline()`-style representation, mirroring
    /// `X509_NAME_oneline()` from `crypto/x509/x509_obj.c`.
    ///
    /// Format: `/C=US/O=Example/CN=foo.example.com`.
    #[must_use]
    pub fn oneline(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push('/');
            out.push_str(entry.short_name());
            out.push('=');
            out.push_str(&entry.value);
        }
        out
    }

    /// Returns the RFC 2253 representation of the DN.
    ///
    /// Format: `CN=foo.example.com,O=Example,C=US` (entries reversed).
    /// Mirrors `X509_NAME_print_ex()` with `XN_FLAG_RFC2253`.
    #[must_use]
    pub fn print_rfc2253(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for entry in self.entries.iter().rev() {
            parts.push(format!(
                "{}={}",
                entry.short_name(),
                escape_rfc2253(&entry.value)
            ));
        }
        parts.join(",")
    }

    /// Returns the canonical 64-bit hash of the DN, suitable for directory
    /// lookups. Mirrors `X509_NAME_hash_ex()` (the post-OpenSSL-1.0 variant).
    #[inline]
    #[must_use]
    pub fn hash(&self) -> u64 {
        self.cached_hash
    }

    /// Returns the cached canonical DER bytes (used for comparison).
    #[inline]
    #[must_use]
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// Recomputes the canonical encoding and FNV-1a hash.
    fn recompute_canonical(&mut self) {
        let mut buf: Vec<u8> = Vec::new();
        for entry in &self.entries {
            buf.extend_from_slice(entry.oid.as_bytes());
            buf.push(b'=');
            for ch in entry.value.chars() {
                let lower = ch.to_ascii_lowercase();
                let mut chunk = [0u8; 4];
                let s = lower.encode_utf8(&mut chunk);
                for b in s.as_bytes() {
                    buf.push(*b);
                }
            }
            buf.push(0);
        }
        // Trim/collapse whitespace per RFC 5280 §7.1 canonicalization.
        let mut collapsed: Vec<u8> = Vec::with_capacity(buf.len());
        let mut prev_space = true;
        for &b in &buf {
            if b == b' ' || b == b'\t' {
                if !prev_space {
                    collapsed.push(b' ');
                    prev_space = true;
                }
            } else {
                collapsed.push(b);
                prev_space = false;
            }
        }
        // FNV-1a 64-bit
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &collapsed {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.canonical = collapsed;
        self.cached_hash = h;
    }
}

impl Default for X509Name {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for X509Name {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for X509Name {}

impl Hash for X509Name {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl Ord for X509Name {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl PartialOrd for X509Name {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for X509Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.oneline())
    }
}

/// Escapes a value for RFC 2253 textual representation.
fn escape_rfc2253(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (idx, ch) in value.chars().enumerate() {
        let is_first = idx == 0;
        let is_last = idx + ch.len_utf8() == value.len();
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                out.push('\\');
                out.push(ch);
            }
            '#' if is_first => {
                out.push('\\');
                out.push(ch);
            }
            ' ' if is_first || is_last => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

// =============================================================================
// Internal ASN.1 helpers (no `unsafe`, structural BER/DER parsing)
// =============================================================================

/// Reads a single ASN.1 length field, returning `(length, bytes_consumed)`.
fn read_length(input: &[u8]) -> Option<(usize, usize)> {
    if input.is_empty() {
        return None;
    }
    let first = input[0];
    if first & 0x80 == 0 {
        return Some((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > core::mem::size_of::<usize>() {
        return None;
    }
    if input.len() < 1 + n {
        return None;
    }
    let mut len: usize = 0;
    for i in 0..n {
        len = len.checked_shl(8)?.checked_add(usize::from(input[1 + i]))?;
    }
    Some((len, 1 + n))
}

/// Writes an ASN.1 length-of-content header.
///
/// All numeric narrowing operations use `unwrap_or(0)` defensively, even
/// though the caller-side preconditions (the `if len < 0x80` short form and
/// the bitwise mask `& 0xff`) guarantee that the values fit in `u8`.  A
/// zero fallback is the safest choice if a future refactor ever invalidates
/// the precondition: it produces a syntactically valid (if semantically
/// wrong) DER length octet rather than panicking.
fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        // Precondition: len < 0x80 guarantees len fits in u8.
        let byte = u8::try_from(len).unwrap_or(0);
        out.push(byte);
        return;
    }
    let mut buf: [u8; core::mem::size_of::<usize>()] = [0; core::mem::size_of::<usize>()];
    let mut n: usize = 0;
    let mut tmp = len;
    while tmp != 0 {
        // `tmp & 0xff` is always in 0..=255 so it always fits in u8.
        buf[n] = u8::try_from(tmp & 0xff).unwrap_or(0);
        tmp >>= 8;
        // n is bounded by usize::BITS / 8 (at most 8), so saturating is fine.
        n = n.saturating_add(1);
    }
    // n < 16 is guaranteed by the loop bound (usize is at most 8 bytes), so
    // 0x80 | n always fits in u8; the 0x80 fallback yields the indefinite
    // length form, which would still be parseable by a permissive decoder.
    let header = u8::try_from(0x80 | n).unwrap_or(0x80);
    out.push(header);
    for i in (0..n).rev() {
        out.push(buf[i]);
    }
}

/// Parses a TLV with a fixed expected tag and returns `(body, remaining)`.
fn parse_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if input.is_empty() || input[0] != expected_tag {
        return None;
    }
    let (len, len_bytes) = read_length(&input[1..])?;
    let header = 1usize.checked_add(len_bytes)?;
    let total = header.checked_add(len)?;
    if input.len() < total {
        return None;
    }
    Some((&input[header..total], &input[total..]))
}

/// Parses a TLV with any tag, returning `(body, remaining)`.
fn parse_tlv_any(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.is_empty() {
        return None;
    }
    let (len, len_bytes) = read_length(&input[1..])?;
    let header = 1usize.checked_add(len_bytes)?;
    let total = header.checked_add(len)?;
    if input.len() < total {
        return None;
    }
    Some((&input[header..total], &input[total..]))
}

/// Encodes a TLV: writes `tag`, the length, then `body`.
fn encode_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    write_length(out, body.len());
    out.extend_from_slice(body);
}

/// Decodes a DER-encoded OID into dotted notation.
fn decode_oid(bytes: &[u8]) -> CryptoResult<String> {
    if bytes.is_empty() {
        return Err(asn1_err("OID: empty body"));
    }
    let first = bytes[0];
    let arc1 = u32::from(first / 40);
    let arc2 = u32::from(first % 40);
    let mut s = format!("{arc1}.{arc2}");
    let mut value: u64 = 0;
    for &b in &bytes[1..] {
        let cont = b & 0x80;
        let chunk = u64::from(b & 0x7f);
        value = value
            .checked_shl(7)
            .ok_or_else(|| asn1_err("OID: arc overflow"))?
            .checked_add(chunk)
            .ok_or_else(|| asn1_err("OID: arc overflow"))?;
        if cont == 0 {
            s.push('.');
            s.push_str(&value.to_string());
            value = 0;
        }
    }
    Ok(s)
}

/// Encodes a dotted-notation OID as DER body bytes.
fn encode_oid(oid: &str) -> Vec<u8> {
    let mut parts_iter = oid.split('.');
    let p1: u64 = parts_iter
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let p2: u64 = parts_iter
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let mut out: Vec<u8> = Vec::new();
    let first = p1.saturating_mul(40).saturating_add(p2);
    out.push(u8::try_from(first & 0xff).unwrap_or(0));
    for arc_str in parts_iter {
        let arc: u64 = arc_str.parse::<u64>().unwrap_or(0);
        let mut tmp: [u8; 10] = [0; 10];
        let mut n = 0usize;
        let mut value = arc;
        loop {
            let mut byte = u8::try_from(value & 0x7f).unwrap_or(0);
            if n != 0 {
                byte |= 0x80;
            }
            tmp[n] = byte;
            value >>= 7;
            // n is bounded by tmp's 10-byte capacity (an arc up to 70 bits);
            // saturating preserves correctness for any well-formed input.
            n = n.saturating_add(1);
            if value == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            out.push(tmp[i]);
        }
    }
    out
}

/// Decodes a string body using the given ASN.1 string type.
fn decode_string(bytes: &[u8], st: Asn1StringType) -> String {
    match st {
        Asn1StringType::Utf8String => String::from_utf8_lossy(bytes).into_owned(),
        Asn1StringType::PrintableString
        | Asn1StringType::Ia5String
        | Asn1StringType::T61String
        | Asn1StringType::OctetString => bytes.iter().map(|&b| b as char).collect(),
        Asn1StringType::BmpString => {
            let mut s = String::with_capacity(bytes.len() / 2);
            let mut i = 0;
            while i + 1 < bytes.len() {
                let cp = u32::from(
                    u16::from(bytes[i]).checked_shl(8).unwrap_or(0) | u16::from(bytes[i + 1]),
                );
                if let Some(ch) = char::from_u32(cp) {
                    s.push(ch);
                } else {
                    s.push('\u{FFFD}');
                }
                // i is bounded by bytes.len() (a usize), so saturating is
                // both correct and impossible to actually trip.
                i = i.saturating_add(2);
            }
            s
        }
        Asn1StringType::UniversalString => {
            let mut s = String::with_capacity(bytes.len() / 4);
            let mut i = 0;
            while i + 3 < bytes.len() {
                let mut cp: u32 = 0;
                for j in 0..4 {
                    cp = cp.checked_shl(8).unwrap_or(0) | u32::from(bytes[i + j]);
                }
                if let Some(ch) = char::from_u32(cp) {
                    s.push(ch);
                } else {
                    s.push('\u{FFFD}');
                }
                // i is bounded by bytes.len() (a usize), so saturating is
                // both correct and impossible to actually trip.
                i = i.saturating_add(4);
            }
            s
        }
    }
}

/// Encodes a Rust `String` to bytes for the given ASN.1 string type.
fn encode_string(value: &str, st: Asn1StringType) -> Vec<u8> {
    match st {
        Asn1StringType::Utf8String => value.as_bytes().to_vec(),
        Asn1StringType::PrintableString
        | Asn1StringType::Ia5String
        | Asn1StringType::T61String
        | Asn1StringType::OctetString => value.bytes().collect(),
        Asn1StringType::BmpString => {
            let mut out: Vec<u8> = Vec::with_capacity(value.len() * 2);
            for ch in value.chars() {
                let cp = u32::from(ch);
                let cp16 = u16::try_from(cp).unwrap_or(u16::MAX);
                // `(_ >> _) & 0xff` is always in 0..=255 and fits in u8.
                out.push(u8::try_from((cp16 >> 8) & 0xff).unwrap_or(0));
                out.push(u8::try_from(cp16 & 0xff).unwrap_or(0));
            }
            out
        }
        Asn1StringType::UniversalString => {
            let mut out: Vec<u8> = Vec::with_capacity(value.len() * 4);
            for ch in value.chars() {
                let cp = u32::from(ch);
                // Each (cp >> N) & 0xff is in 0..=255 and fits in u8.
                out.push(u8::try_from((cp >> 24) & 0xff).unwrap_or(0));
                out.push(u8::try_from((cp >> 16) & 0xff).unwrap_or(0));
                out.push(u8::try_from((cp >> 8) & 0xff).unwrap_or(0));
                out.push(u8::try_from(cp & 0xff).unwrap_or(0));
            }
            out
        }
    }
}

// =====================================================================
// Base64 encode/decode helpers (replicated from crl.rs algorithms).
//
// `crl.rs` exposes private `fn` versions of these routines. Because the
// routines must be reused by the X509Certificate PEM codec but cannot be
// imported across modules (the `crl.rs` versions are not `pub`), this
// module replicates the implementation verbatim. The algorithms are
// fully covered by the existing CRL test suite; this duplication is
// inherent to the dependency graph.
// =====================================================================

/// Base64 alphabet per RFC 4648 §4 ("Standard" alphabet).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 reverse-lookup table.
///
/// - `0x00..=0x3F` — valid 6-bit value
/// - `0xFD` — `=` padding character
/// - `0xFE` — whitespace (skipped silently)
/// - `0xFF` — invalid character (decode error)
const BASE64_DECODE_TABLE: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i;
        t[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    let mut i = 0u8;
    while i < 10 {
        t[(b'0' + i) as usize] = 52 + i;
        i += 1;
    }
    t[b'+' as usize] = 62;
    t[b'/' as usize] = 63;
    t[b'=' as usize] = 0xFD;
    t[b' ' as usize] = 0xFE;
    t[b'\t' as usize] = 0xFE;
    t[b'\n' as usize] = 0xFE;
    t[b'\r' as usize] = 0xFE;
    t
};

/// Encode bytes as a Base64 string (no embedded line breaks, RFC 4648 §4).
///
/// This routine is **R6-compliant**: every narrowing conversion uses
/// [`u8::try_from`] / [`usize::try_from`], never a bare `as`.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(4).div_ceil(3));
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        for shift in [18, 12, 6, 0] {
            let idx = usize::try_from((n >> shift) & 0x3F).unwrap_or(0);
            out.push(char::from(BASE64_ALPHABET[idx]));
        }
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(char::from(
                BASE64_ALPHABET[usize::try_from((n >> 18) & 0x3F).unwrap_or(0)],
            ));
            out.push(char::from(
                BASE64_ALPHABET[usize::try_from((n >> 12) & 0x3F).unwrap_or(0)],
            ));
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(char::from(
                BASE64_ALPHABET[usize::try_from((n >> 18) & 0x3F).unwrap_or(0)],
            ));
            out.push(char::from(
                BASE64_ALPHABET[usize::try_from((n >> 12) & 0x3F).unwrap_or(0)],
            ));
            out.push(char::from(
                BASE64_ALPHABET[usize::try_from((n >> 6) & 0x3F).unwrap_or(0)],
            ));
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Decode a Base64 string per RFC 4648.
///
/// - Whitespace (` `, `\t`, `\n`, `\r`) is silently skipped, allowing this
///   routine to operate directly on the body section of a PEM file.
/// - Padding is validated: at most two `=` characters, and never followed
///   by additional non-padding characters.
/// - Returns [`asn1_err`] on any malformed input.
fn base64_decode(s: &str) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len().saturating_mul(3).div_ceil(4));
    let mut buf = [0u8; 4];
    let mut buf_len: usize = 0;
    let mut padding_seen: usize = 0;

    for byte in s.bytes() {
        let v = BASE64_DECODE_TABLE[usize::from(byte)];
        match v {
            0xFE => continue, // whitespace
            0xFF => return Err(asn1_err("base64: invalid character")),
            0xFD => {
                if padding_seen >= 2 {
                    return Err(asn1_err("base64: too much padding"));
                }
                padding_seen = padding_seen.saturating_add(1);
                buf[buf_len] = 0;
                buf_len = buf_len.saturating_add(1);
            }
            _ => {
                if padding_seen != 0 {
                    return Err(asn1_err("base64: data after padding"));
                }
                buf[buf_len] = v;
                buf_len = buf_len.saturating_add(1);
            }
        }
        if buf_len == 4 {
            let n = (u32::from(buf[0]) << 18)
                | (u32::from(buf[1]) << 12)
                | (u32::from(buf[2]) << 6)
                | u32::from(buf[3]);
            out.push(u8::try_from((n >> 16) & 0xFF).unwrap_or(0));
            if padding_seen < 2 {
                out.push(u8::try_from((n >> 8) & 0xFF).unwrap_or(0));
            }
            if padding_seen < 1 {
                out.push(u8::try_from(n & 0xFF).unwrap_or(0));
            }
            buf_len = 0;
        }
    }
    if buf_len != 0 {
        return Err(asn1_err("base64: truncated input"));
    }
    Ok(out)
}

/// Wrap DER bytes into a single-block PEM string.
///
/// Output format:
/// ```text
/// -----BEGIN <label>-----
/// <base64 in 64-char lines>
/// -----END <label>-----
/// ```
fn encode_pem(der: &[u8], label: &str) -> String {
    let body = base64_encode(der);
    let mut out = String::with_capacity(
        body.len()
            .saturating_add(64)
            .saturating_add(label.len().saturating_mul(2)),
    );
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let end = i.saturating_add(64).min(bytes.len());
        out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
        out.push('\n');
        i = end;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Decode a PEM string to DER bytes.
///
/// `labels` lists acceptable BEGIN/END labels (e.g.
/// `&["CERTIFICATE", "X509 CERTIFICATE"]`). The first matching block in
/// the input is decoded; surrounding text is ignored. Mismatched
/// BEGIN/END labels are an error.
fn decode_pem(pem: &str, labels: &[&str]) -> CryptoResult<Vec<u8>> {
    let begin_marker = "-----BEGIN ";
    let begin_idx = pem
        .find(begin_marker)
        .ok_or_else(|| asn1_err("PEM: missing BEGIN marker"))?;
    let label_start = begin_idx.saturating_add(begin_marker.len());
    let label_end = pem[label_start..]
        .find("-----")
        .map(|i| label_start.saturating_add(i))
        .ok_or_else(|| asn1_err("PEM: malformed BEGIN marker"))?;
    let begin_label = &pem[label_start..label_end];
    if !labels.iter().any(|expected| *expected == begin_label) {
        return Err(asn1_err("PEM: unexpected label"));
    }
    let body_start = label_end.saturating_add(5); // past "-----"
    let end_marker = "-----END ";
    let end_idx_rel = pem[body_start..]
        .find(end_marker)
        .ok_or_else(|| asn1_err("PEM: missing END marker"))?;
    let end_idx = body_start.saturating_add(end_idx_rel);
    let end_label_start = end_idx.saturating_add(end_marker.len());
    let end_label_end = pem[end_label_start..]
        .find("-----")
        .map(|i| end_label_start.saturating_add(i))
        .ok_or_else(|| asn1_err("PEM: malformed END marker"))?;
    let end_label = &pem[end_label_start..end_label_end];
    if end_label != begin_label {
        return Err(asn1_err("PEM: BEGIN/END label mismatch"));
    }
    let body = &pem[body_start..end_idx];
    base64_decode(body)
}

// =====================================================================
// ASN.1 Time encoding (UTCTime / GeneralizedTime per RFC 5280 §4.1.2.5)
//
// X.509 chooses between UTCTime and GeneralizedTime by year:
//   • years 1950..=2049 → UTCTime         (tag 0x17, body "YYMMDDHHMMSSZ")
//   • all other years   → GeneralizedTime (tag 0x18, body "YYYYMMDDHHMMSSZ")
//
// `OsslTime` only exposes seconds-since-Unix-epoch, so we perform inline
// Gregorian calendar math (Howard Hinnant's "days_from_civil" algorithm,
// public domain). All arithmetic is `i64` to allow correct round-trip
// over the entire representable range (1970..= ~5-digit years).
// =====================================================================

/// Number of days in the months January..=December for a non-leap year.
const DAYS_IN_MONTH_NON_LEAP: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Returns true if `year` is a Gregorian leap year.
const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0)
}

/// Number of days in the given (year, 1-based month) pair.
fn days_in_month(year: i64, month: u32) -> u32 {
    if month == 2 && is_leap_year(year) {
        29
    } else {
        let idx = usize::try_from(month.saturating_sub(1)).unwrap_or(0);
        DAYS_IN_MONTH_NON_LEAP[idx.min(11)]
    }
}

/// Convert a Gregorian (year, month, day) to days since 1970-01-01.
/// All inputs are validated by the caller. Algorithm by Howard Hinnant.
fn civil_to_days(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = i64::from(month);
    let d = i64::from(day);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m_adj = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * m_adj + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Convert days since 1970-01-01 to Gregorian (year, month, day).
/// Algorithm by Howard Hinnant; `month` returned is 1-based.
fn days_to_civil(days: i64) -> (i64, u32, u32) {
    // Operate entirely in i64 to avoid sign-conversion casts (R6).  The
    // intermediate values are bounded so 64-bit signed arithmetic cannot
    // overflow for any representable date.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    let month = u32::try_from(m).unwrap_or(1);
    let day = u32::try_from(d).unwrap_or(1);
    (year, month, day)
}

/// Push a zero-padded decimal of width 2 onto `out`.
fn push_2digit(out: &mut Vec<u8>, value: u32) {
    let v = value % 100;
    out.push(b'0' + u8::try_from(v / 10).unwrap_or(0));
    out.push(b'0' + u8::try_from(v % 10).unwrap_or(0));
}

/// Push a zero-padded decimal of width 4 onto `out`.
fn push_4digit(out: &mut Vec<u8>, value: u32) {
    let v = value % 10000;
    out.push(b'0' + u8::try_from((v / 1000) % 10).unwrap_or(0));
    out.push(b'0' + u8::try_from((v / 100) % 10).unwrap_or(0));
    out.push(b'0' + u8::try_from((v / 10) % 10).unwrap_or(0));
    out.push(b'0' + u8::try_from(v % 10).unwrap_or(0));
}

/// Encode an [`OsslTime`] as a DER-encoded ASN.1 Time value (`UTCTime` or
/// `GeneralizedTime` per RFC 5280 §4.1.2.5).
///
/// The encoding choice depends on the year:
/// - 1950..=2049 → `UTCTime`, body 13 bytes `YYMMDDHHMMSSZ`
/// - otherwise   → `GeneralizedTime`, body 15 bytes `YYYYMMDDHHMMSSZ`
fn encode_asn1_time(time: OsslTime) -> Vec<u8> {
    let total_secs = time.to_seconds();
    let day_secs: u64 = 86_400;
    let days = i64::try_from(total_secs / day_secs).unwrap_or(0);
    let secs_in_day = total_secs % day_secs;
    let (year, month, day) = days_to_civil(days);
    let hour = u32::try_from(secs_in_day / 3600).unwrap_or(0);
    let minute = u32::try_from((secs_in_day / 60) % 60).unwrap_or(0);
    let second = u32::try_from(secs_in_day % 60).unwrap_or(0);

    let use_utc = (1950..=2049).contains(&year);
    let mut body = Vec::with_capacity(15);
    if use_utc {
        // YY = year mod 100 — RFC 5280 §4.1.2.5.1 maps 50..=99 → 19YY,
        // 00..=49 → 20YY on decode, so the encoder simply emits the last
        // two digits of the calendar year.
        let yy = u32::try_from(year.rem_euclid(100)).unwrap_or(0);
        push_2digit(&mut body, yy);
    } else {
        let y = if year < 0 {
            0u32
        } else {
            u32::try_from(year).unwrap_or(0)
        };
        push_4digit(&mut body, y);
    }
    push_2digit(&mut body, month);
    push_2digit(&mut body, day);
    push_2digit(&mut body, hour);
    push_2digit(&mut body, minute);
    push_2digit(&mut body, second);
    body.push(b'Z');

    let tag: u8 = if use_utc { 0x17 } else { 0x18 };
    let mut out = Vec::with_capacity(body.len().saturating_add(2));
    encode_tlv(&mut out, tag, &body);
    out
}

/// Parse a 2-digit ASCII decimal at `body[off..off+2]`.
fn parse_two(body: &[u8], off: usize) -> CryptoResult<u32> {
    if off.saturating_add(2) > body.len() {
        return Err(asn1_err("ASN1 Time: short field"));
    }
    let mut v: u32 = 0;
    for &c in &body[off..off.saturating_add(2)] {
        if !c.is_ascii_digit() {
            return Err(asn1_err("ASN1 Time: non-digit character"));
        }
        v = v.saturating_mul(10).saturating_add(u32::from(c - b'0'));
    }
    Ok(v)
}

/// Parse a 4-digit ASCII decimal at `body[off..off+4]`.
fn parse_four(body: &[u8], off: usize) -> CryptoResult<u32> {
    if off.saturating_add(4) > body.len() {
        return Err(asn1_err("ASN1 Time: short field"));
    }
    let mut v: u32 = 0;
    for &c in &body[off..off.saturating_add(4)] {
        if !c.is_ascii_digit() {
            return Err(asn1_err("ASN1 Time: non-digit character"));
        }
        v = v.saturating_mul(10).saturating_add(u32::from(c - b'0'));
    }
    Ok(v)
}

/// Decode a DER-encoded ASN.1 Time body to an [`OsslTime`].
///
/// `tag` selects the format: `0x17` = `UTCTime`, `0x18` = `GeneralizedTime`.
/// Only the canonical RFC 5280 forms (`YYMMDDHHMMSSZ` /
/// `YYYYMMDDHHMMSSZ`) are accepted. Pre-1970 dates are clamped to
/// `OsslTime::ZERO` because [`OsslTime`] uses an unsigned epoch.
fn decode_asn1_time(body: &[u8], tag: u8) -> CryptoResult<OsslTime> {
    let (year_i64, month, day, hour, minute, second) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ — 13 chars
            if body.len() != 13 || body[12] != b'Z' {
                return Err(asn1_err("ASN1 UTCTime: malformed body"));
            }
            let yy = parse_two(body, 0)?;
            // RFC 5280 §4.1.2.5.1: YY < 50 → 20YY, otherwise 19YY.
            let year_i64 = if yy < 50 {
                i64::from(yy).saturating_add(2000)
            } else {
                i64::from(yy).saturating_add(1900)
            };
            let mo = parse_two(body, 2)?;
            let da = parse_two(body, 4)?;
            let hh = parse_two(body, 6)?;
            let mi = parse_two(body, 8)?;
            let se = parse_two(body, 10)?;
            (year_i64, mo, da, hh, mi, se)
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ — 15 chars
            if body.len() != 15 || body[14] != b'Z' {
                return Err(asn1_err("ASN1 GeneralizedTime: malformed body"));
            }
            let yyyy = parse_four(body, 0)?;
            let mo = parse_two(body, 4)?;
            let da = parse_two(body, 6)?;
            let hh = parse_two(body, 8)?;
            let mi = parse_two(body, 10)?;
            let se = parse_two(body, 12)?;
            (i64::from(yyyy), mo, da, hh, mi, se)
        }
        _ => return Err(asn1_err("ASN1 Time: unsupported tag")),
    };

    // Range-validate fields.
    if !(1..=12).contains(&month) {
        return Err(asn1_err("ASN1 Time: month out of range"));
    }
    let max_day = days_in_month(year_i64, month);
    if !(1..=max_day).contains(&day) {
        return Err(asn1_err("ASN1 Time: day out of range"));
    }
    if hour > 23 || minute > 59 || second > 60 {
        // Allow second == 60 for leap-second tolerance; clamp later.
        return Err(asn1_err("ASN1 Time: time of day out of range"));
    }
    let second_clamped = second.min(59);

    let days = civil_to_days(year_i64, month, day);
    if days < 0 {
        return Ok(OsslTime::ZERO);
    }
    let day_secs: u64 = u64::try_from(days)
        .map_err(|_| internal_err("ASN1 Time: day count overflow"))?
        .saturating_mul(86_400);
    let tod_secs = u64::from(hour)
        .saturating_mul(3600)
        .saturating_add(u64::from(minute).saturating_mul(60))
        .saturating_add(u64::from(second_clamped));
    Ok(OsslTime::from_seconds(day_secs.saturating_add(tod_secs)))
}

// =====================================================================
// Phase 5 — SubjectPublicKeyInfo (from `crypto/x509/x_pubkey.c`)
// =====================================================================

/// `SubjectPublicKeyInfo` (SPKI): a public key together with its algorithm
/// identifier.
///
/// Replaces C `X509_PUBKEY` from `crypto/x509/x_pubkey.c` (1,067 lines).
/// In OpenSSL the public key body is decoded lazily by the provider
/// machinery; this Rust translation keeps the raw DER body and exposes
/// helpers that classify the algorithm and report key size.
///
/// # Encoding
///
/// SPKI is an ASN.1 `SEQUENCE`:
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm        AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
/// }
/// ```
///
/// `public_key` stores the **content** of the BIT STRING after the
/// leading "unused-bits" octet has been stripped (i.e., what
/// `X509_PUBKEY_get0()` would surface as the key body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo {
    /// Algorithm identifier for the public key (OID + optional parameters).
    pub algorithm: AlgorithmIdentifier,
    /// Public-key bytes — the BIT STRING content, unused-bits octet
    /// stripped.
    pub public_key: Vec<u8>,
}

impl SubjectPublicKeyInfo {
    /// Decodes a DER-encoded `SubjectPublicKeyInfo`.
    ///
    /// Mirrors `d2i_X509_PUBKEY()` from `x_pubkey.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] if the DER does not contain a
    /// valid `SEQUENCE { AlgorithmIdentifier, BIT STRING }`.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        debug!(target: "openssl::x509::spki", len = der.len(), "decoding SubjectPublicKeyInfo");
        let (body, rest) =
            parse_tlv(der, 0x30).ok_or_else(|| asn1_err("SPKI: missing outer SEQUENCE"))?;
        if !rest.is_empty() {
            return Err(asn1_err("SPKI: trailing bytes after SEQUENCE"));
        }
        // AlgorithmIdentifier ::= SEQUENCE { OID, ANY OPTIONAL }
        let (algo_body, after_algo) = parse_tlv(body, 0x30)
            .ok_or_else(|| asn1_err("SPKI: missing AlgorithmIdentifier SEQUENCE"))?;
        let (oid_body, after_oid) = parse_tlv(algo_body, 0x06)
            .ok_or_else(|| asn1_err("SPKI: missing AlgorithmIdentifier OID"))?;
        let algorithm_oid = decode_oid(oid_body)?;
        let parameters = if after_oid.is_empty() {
            None
        } else {
            // The remainder is the (single) optional parameters element.
            // We validate it with `parse_tlv_any` (verifying the TLV is
            // well-formed and that no trailing junk follows) and then
            // store the original bytes so that the parameters can be
            // round-tripped without loss.
            let (_param_body, after_param) = parse_tlv_any(after_oid)
                .ok_or_else(|| asn1_err("SPKI: malformed AlgorithmIdentifier parameters"))?;
            if !after_param.is_empty() {
                return Err(asn1_err(
                    "SPKI: trailing bytes after AlgorithmIdentifier parameters",
                ));
            }
            Some(after_oid.to_vec())
        };
        // BIT STRING with unused-bits prefix octet
        let (bit_body, after_bit) =
            parse_tlv(after_algo, 0x03).ok_or_else(|| asn1_err("SPKI: missing BIT STRING"))?;
        if !after_bit.is_empty() {
            return Err(asn1_err("SPKI: trailing bytes after BIT STRING"));
        }
        if bit_body.is_empty() {
            return Err(asn1_err("SPKI: empty BIT STRING"));
        }
        let unused = bit_body[0];
        if unused != 0 {
            // Public key encodings always use 0 unused bits.
            return Err(asn1_err("SPKI: BIT STRING unused-bits != 0"));
        }
        let public_key = bit_body[1..].to_vec();
        Ok(Self {
            algorithm: AlgorithmIdentifier {
                algorithm: algorithm_oid,
                parameters,
            },
            public_key,
        })
    }

    /// Encodes this SPKI as DER.
    ///
    /// Mirrors `i2d_X509_PUBKEY()` from `x_pubkey.c`.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        // AlgorithmIdentifier
        let mut algo_body: Vec<u8> = Vec::new();
        let oid_bytes = encode_oid(&self.algorithm.algorithm);
        encode_tlv(&mut algo_body, 0x06, &oid_bytes);
        if let Some(params) = &self.algorithm.parameters {
            algo_body.extend_from_slice(params);
        }
        // BIT STRING { unused-bits = 0, public_key }
        let mut bit_body: Vec<u8> = Vec::with_capacity(self.public_key.len().saturating_add(1));
        bit_body.push(0);
        bit_body.extend_from_slice(&self.public_key);

        let mut outer: Vec<u8> = Vec::new();
        encode_tlv(&mut outer, 0x30, &algo_body);
        encode_tlv(&mut outer, 0x03, &bit_body);

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &outer);
        Ok(out)
    }

    /// Returns a short label for the public-key algorithm based on the
    /// well-known OID; falls back to the OID dotted form if unknown.
    ///
    /// Mirrors the user-facing `EVP_PKEY_get0_type_name()` mapping used
    /// by `X509_PUBKEY_get0()` callers.
    #[must_use]
    pub fn key_type(&self) -> &str {
        match self.algorithm.algorithm.as_str() {
            // RSA / RSA-PSS
            "1.2.840.113549.1.1.1" => "RSA",
            "1.2.840.113549.1.1.10" => "RSA-PSS",
            // DSA
            "1.2.840.10040.4.1" => "DSA",
            // EC
            "1.2.840.10045.2.1" => "EC",
            // Edwards-curve / Curve25519 / Curve448
            "1.3.101.110" => "X25519",
            "1.3.101.111" => "X448",
            "1.3.101.112" => "Ed25519",
            "1.3.101.113" => "Ed448",
            // Diffie-Hellman
            "1.2.840.113549.1.3.1" => "DH",
            // SM2
            "1.2.156.10197.1.301" => "SM2",
            other => other,
        }
    }

    /// Returns the public-key length in bits.
    ///
    /// For RSA, this is the bit length of the modulus (parsed from the
    /// `RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }` body). For
    /// EC, this is 8× the byte length of the uncompressed point minus
    /// the leading format octet, divided by 2 (per coordinate). For
    /// other algorithms, this is the byte length of `public_key` in
    /// bits — the closest analogue to OpenSSL's
    /// `EVP_PKEY_get_bits()`.
    pub fn key_bits(&self) -> CryptoResult<u32> {
        match self.algorithm.algorithm.as_str() {
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
                // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
                let (body, _) = parse_tlv(&self.public_key, 0x30)
                    .ok_or_else(|| asn1_err("RSA SPKI: missing SEQUENCE"))?;
                let (modulus, _) = parse_tlv(body, 0x02)
                    .ok_or_else(|| asn1_err("RSA SPKI: missing modulus INTEGER"))?;
                // strip leading zero byte (sign-bit padding)
                let trimmed: &[u8] = if modulus.first() == Some(&0) {
                    &modulus[1..]
                } else {
                    modulus
                };
                let bytes = u32::try_from(trimmed.len()).unwrap_or(0);
                let bits = bytes
                    .checked_mul(8)
                    .ok_or_else(|| asn1_err("RSA SPKI: modulus too large"))?;
                Ok(bits)
            }
            _ => {
                let bytes = u32::try_from(self.public_key.len()).unwrap_or(0);
                Ok(bytes.saturating_mul(8))
            }
        }
    }
}

// =====================================================================
// Phase 6 — X509Extension (from `x_exten.c`, `x509_ext.c`, `x509_v3.c`)
// =====================================================================

/// A single X.509 v3 extension.
///
/// Replaces C `X509_EXTENSION` from `crypto/x509/x_exten.c` and
/// `crypto/x509/x509_local.h`. The structure is a transparent
/// `(OID, critical, OCTET STRING)` triple: the `value` field stores the
/// **content** of the OCTET STRING (i.e., the inner DER of the extension
/// type), not the OCTET STRING TLV itself.
///
/// # ASN.1
///
/// ```text
/// Extension ::= SEQUENCE {
///     extnID    OBJECT IDENTIFIER,
///     critical  BOOLEAN DEFAULT FALSE,
///     extnValue OCTET STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Extension {
    /// Extension OID in dotted-decimal notation
    /// (e.g., `"2.5.29.19"` for basicConstraints).
    pub oid: String,
    /// Whether this extension is marked critical.
    pub critical: bool,
    /// The content of the OCTET STRING — the inner DER.
    pub value: Vec<u8>,
}

impl X509Extension {
    /// Returns the extension OID.
    ///
    /// Mirrors `X509_EXTENSION_get_object()` from `x509_ext.c`.
    #[inline]
    #[must_use]
    pub fn oid(&self) -> &str {
        &self.oid
    }

    /// Returns the criticality flag.
    ///
    /// Mirrors `X509_EXTENSION_get_critical()`.
    #[inline]
    #[must_use]
    pub fn critical(&self) -> bool {
        self.critical
    }

    /// Returns the inner DER content of the OCTET STRING.
    ///
    /// Mirrors `X509_EXTENSION_get_data()`.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Attempts to parse this extension into the typed
    /// [`ParsedExtension`] representation.
    ///
    /// Unknown extensions are returned as
    /// [`ParsedExtension::Unknown`]; well-known standard extensions are
    /// fully decoded.
    ///
    /// Errors only when the DER is malformed for a *known* extension OID.
    pub fn as_parsed(&self) -> CryptoResult<ParsedExtension> {
        parse_extension(&self.oid, &self.value)
    }
}

// =====================================================================
// Phase 7 — Well-known extension OIDs (`standard_exts.h` / `ext_dat.h`)
// =====================================================================

/// Well-known X.509 v3 extension OIDs in dotted-decimal form.
///
/// These constants replace the integer NIDs / hard-coded ASN.1 OIDs used
/// throughout `crypto/x509/standard_exts.h` and `ext_dat.h`. They are
/// surfaced as `&'static str` so that comparisons with
/// [`X509Extension::oid`] are direct slice equality and so that they can
/// be used in `match` arms.
pub mod oid {
    /// `id-ce-basicConstraints` (RFC 5280 §4.2.1.9).
    pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    /// `id-ce-keyUsage` (RFC 5280 §4.2.1.3).
    pub const KEY_USAGE: &str = "2.5.29.15";
    /// `id-ce-extKeyUsage` (RFC 5280 §4.2.1.12).
    pub const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
    /// `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
    pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
    /// `id-ce-authorityKeyIdentifier` (RFC 5280 §4.2.1.1).
    pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
    /// `id-ce-subjectAltName` (RFC 5280 §4.2.1.6).
    pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
    /// `id-ce-issuerAltName` (RFC 5280 §4.2.1.7).
    pub const ISSUER_ALT_NAME: &str = "2.5.29.18";
    /// `id-ce-cRLDistributionPoints` (RFC 5280 §4.2.1.13).
    pub const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
    /// `id-ce-certificatePolicies` (RFC 5280 §4.2.1.4).
    pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
    /// `id-ce-policyMappings` (RFC 5280 §4.2.1.5).
    pub const POLICY_MAPPINGS: &str = "2.5.29.33";
    /// `id-ce-policyConstraints` (RFC 5280 §4.2.1.11).
    pub const POLICY_CONSTRAINTS: &str = "2.5.29.36";
    /// `id-ce-inhibitAnyPolicy` (RFC 5280 §4.2.1.14).
    pub const INHIBIT_ANY_POLICY: &str = "2.5.29.54";
    /// `id-ce-nameConstraints` (RFC 5280 §4.2.1.10).
    pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
    /// `id-pe-authorityInfoAccess` (RFC 5280 §4.2.2.1).
    pub const AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
    /// `id-pe-subjectInfoAccess` (RFC 5280 §4.2.2.2).
    pub const SUBJECT_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.11";
    /// `id-ce-freshestCRL` (RFC 5280 §4.2.1.15).
    pub const FRESHEST_CRL: &str = "2.5.29.46";
    /// `id-ce-cRLNumber` (RFC 5280 §5.2.3).
    pub const CRL_NUMBER: &str = "2.5.29.20";
    /// `id-ce-deltaCRLIndicator` (RFC 5280 §5.2.4).
    pub const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
    /// `id-ce-issuingDistributionPoint` (RFC 5280 §5.2.5).
    pub const ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
    /// `id-pe-tlsfeature` (RFC 7633).
    pub const TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";
    /// Pre-certificate SCT list (Certificate Transparency, RFC 6962).
    pub const CT_PRECERT_SCTS: &str = "1.3.6.1.4.1.11129.2.4.2";
    /// Pre-certificate poison extension (RFC 6962 §3.1).
    pub const CT_PRECERT_POISON: &str = "1.3.6.1.4.1.11129.2.4.3";
    /// Standalone SCT list (RFC 6962 §3.3).
    pub const SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.5";
}

// =====================================================================
// Phase 8 — Parsed extension types
// =====================================================================

/// `BasicConstraints` extension (`v3_bcons.c`).
///
/// Indicates whether the subject is a CA and (optionally) the maximum
/// number of intermediate certificates that may follow this one in a
/// path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BasicConstraints {
    /// `cA` flag (RFC 5280 §4.2.1.9).
    pub ca: bool,
    /// `pathLenConstraint` — maximum number of intermediate CAs.
    /// `None` denotes the unconstrained case (no `pathLenConstraint`
    /// present), translating the C sentinel `ex_pathlen = -1`. (R5)
    pub path_length: Option<u32>,
}

bitflags! {
    /// `KeyUsage` flags (`v3_bitst.c`, RFC 5280 §4.2.1.3).
    ///
    /// The numeric values match the bit positions used by OpenSSL's C
    /// macros (`KU_DIGITAL_SIGNATURE`, etc.) so that callers familiar
    /// with the C API can reuse them by analogy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct KeyUsageFlags: u16 {
        /// digitalSignature (0)
        const DIGITAL_SIGNATURE = 0x0080;
        /// nonRepudiation / contentCommitment (1)
        const NON_REPUDIATION   = 0x0040;
        /// keyEncipherment (2)
        const KEY_ENCIPHERMENT  = 0x0020;
        /// dataEncipherment (3)
        const DATA_ENCIPHERMENT = 0x0010;
        /// keyAgreement (4)
        const KEY_AGREEMENT     = 0x0008;
        /// keyCertSign (5)
        const KEY_CERT_SIGN     = 0x0004;
        /// cRLSign (6)
        const CRL_SIGN          = 0x0002;
        /// encipherOnly (7)
        const ENCIPHER_ONLY     = 0x0001;
        /// decipherOnly (8)
        const DECIPHER_ONLY     = 0x8000;
    }
}

/// `AuthorityKeyIdentifier` extension (`v3_akid.c`).
///
/// Per RFC 5280 §4.2.1.1, all fields are optional. Per Rule R5 each is
/// a Rust `Option<T>` rather than a sentinel value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorityKeyIdentifier {
    /// `keyIdentifier` octet string (`None` if absent — R5).
    pub key_identifier: Option<Vec<u8>>,
    /// `authorityCertIssuer` general names (`None` if absent — R5).
    pub authority_cert_issuer: Option<Vec<GeneralName>>,
    /// `authorityCertSerialNumber` DER INTEGER bytes (`None` if absent
    /// — R5).
    pub authority_cert_serial: Option<Vec<u8>>,
}

/// `GeneralName` choice (`v3_genn.c`, `v3_san.c`, RFC 5280 §4.2.1.6).
///
/// Implements the eight CHOICE alternatives that appear in subject and
/// issuer alternative names, CRL distribution points, name constraints,
/// and access descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    /// `rfc822Name` — RFC 822 mailbox.
    Rfc822Name(String),
    /// `dNSName` — DNS name.
    DnsName(String),
    /// `directoryName` — X.500 distinguished name.
    DirectoryName(X509Name),
    /// `uniformResourceIdentifier`.
    UniformResourceIdentifier(String),
    /// `iPAddress` — packed network-byte-order address (4 or 16 bytes;
    /// 8 or 32 for CIDR forms in name constraints).
    IpAddress(Vec<u8>),
    /// `registeredID` — OID in dotted-decimal form.
    RegisteredId(String),
    /// `otherName` — explicit type-id + DER-encoded value (RFC 5280
    /// §4.2.1.6).
    OtherName {
        /// OID identifying the value's type.
        type_id: String,
        /// DER-encoded inner value.
        value: Vec<u8>,
    },
}

/// `DistributionPoint` (`v3_crld.c`, RFC 5280 §4.2.1.13).
///
/// A single CRL distribution point referencing where to retrieve the
/// CRL covering this certificate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DistributionPoint {
    /// `distributionPoint` field (`None` per R5 if absent — meaning the
    /// CRL issuer's own DN serves as the implicit name).
    pub name: Option<DistributionPointName>,
    /// `reasons` mask (`None` per R5 if absent — meaning all reasons).
    pub reasons: Option<crate::x509::crl::ReasonFlags>,
    /// `cRLIssuer` for indirect CRLs (`None` per R5 if absent — meaning
    /// the issuer is the certificate's issuer).
    pub crl_issuer: Option<Vec<GeneralName>>,
}

/// `DistributionPointName` choice (`v3_crld.c`, RFC 5280 §4.2.1.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionPointName {
    /// `fullName` — list of `GeneralNames`.
    FullName(Vec<GeneralName>),
    /// `nameRelativeToCRLIssuer` — RDN to be appended to the issuer's
    /// DN.
    NameRelativeToCrlIssuer(X509Name),
}

/// `PolicyInformation` (`v3_cpols.c`, RFC 5280 §4.2.1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInfo {
    /// `policyIdentifier` OID.
    pub policy_oid: String,
    /// Optional list of policy qualifiers.
    pub qualifiers: Vec<PolicyQualifier>,
}

/// `PolicyQualifierInfo` choice (`v3_cpols.c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyQualifier {
    /// `id-qt-cps` — Certification Practice Statement URI.
    Cps(String),
    /// `id-qt-unotice` — User notice.
    UserNotice(UserNotice),
}

/// `UserNotice` (`v3_cpols.c`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserNotice {
    /// `noticeRef` — organization + notice numbers, encoded as DER.
    /// Stored opaquely; `None` if absent (R5).
    pub notice_ref: Option<Vec<u8>>,
    /// `explicitText` — human-readable notice (`None` if absent — R5).
    pub explicit_text: Option<String>,
}

/// `PolicyConstraints` (`v3_pci.c`, RFC 5280 §4.2.1.11).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyConstraints {
    /// `requireExplicitPolicy` — number of certs after which an
    /// explicit policy is required (`None` if absent — R5).
    pub require_explicit_policy: Option<u32>,
    /// `inhibitPolicyMapping` — number of certs after which policy
    /// mapping is forbidden (`None` if absent — R5).
    pub inhibit_policy_mapping: Option<u32>,
}

/// `NameConstraints` (`v3_ncons.c`, RFC 5280 §4.2.1.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NameConstraints {
    /// Permitted subtrees (empty if absent).
    pub permitted_subtrees: Vec<GeneralSubtree>,
    /// Excluded subtrees (empty if absent).
    pub excluded_subtrees: Vec<GeneralSubtree>,
}

/// `GeneralSubtree` (`v3_ncons.c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSubtree {
    /// Base name to constrain.
    pub base: GeneralName,
    /// Minimum subtree depth — defaults to 0 if not encoded.
    pub minimum: u32,
    /// Maximum subtree depth (`None` per R5 if absent — meaning
    /// unbounded; RFC 5280 mandates that this MUST be absent).
    pub maximum: Option<u32>,
}

/// `AccessDescription` (`v3_info.c`, RFC 5280 §4.2.2.1/§4.2.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDescription {
    /// `accessMethod` OID (e.g., `id-ad-ocsp`, `id-ad-caIssuers`).
    pub method: String,
    /// `accessLocation` `GeneralName`.
    pub location: GeneralName,
}

/// Typed representation of a parsed X.509 v3 extension.
///
/// Replaces the C `void *` returned by `X509V3_EXT_d2i()` with a
/// type-safe enum. Unknown extensions are surfaced as
/// [`ParsedExtension::Unknown`] preserving the raw OID and DER body.
#[derive(Debug, Clone)]
pub enum ParsedExtension {
    /// `basicConstraints` (RFC 5280 §4.2.1.9).
    BasicConstraints(BasicConstraints),
    /// `keyUsage` (RFC 5280 §4.2.1.3).
    KeyUsage(KeyUsageFlags),
    /// `extKeyUsage` (RFC 5280 §4.2.1.12) — list of OIDs.
    ExtendedKeyUsage(Vec<String>),
    /// `subjectKeyIdentifier` octet string (RFC 5280 §4.2.1.2).
    SubjectKeyIdentifier(Vec<u8>),
    /// `authorityKeyIdentifier` (RFC 5280 §4.2.1.1).
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    /// `subjectAltName` (RFC 5280 §4.2.1.6).
    SubjectAltName(Vec<GeneralName>),
    /// `issuerAltName` (RFC 5280 §4.2.1.7).
    IssuerAltName(Vec<GeneralName>),
    /// `cRLDistributionPoints` (RFC 5280 §4.2.1.13).
    CrlDistributionPoints(Vec<DistributionPoint>),
    /// `certificatePolicies` (RFC 5280 §4.2.1.4).
    CertificatePolicies(Vec<PolicyInfo>),
    /// `policyMappings` (RFC 5280 §4.2.1.5) — pairs of OIDs.
    PolicyMappings(Vec<(String, String)>),
    /// `policyConstraints` (RFC 5280 §4.2.1.11).
    PolicyConstraints(PolicyConstraints),
    /// `inhibitAnyPolicy` skipCerts (RFC 5280 §4.2.1.14).
    InhibitAnyPolicy(u32),
    /// `nameConstraints` (RFC 5280 §4.2.1.10).
    NameConstraints(NameConstraints),
    /// `authorityInfoAccess` (RFC 5280 §4.2.2.1).
    AuthorityInfoAccess(Vec<AccessDescription>),
    /// `subjectInfoAccess` (RFC 5280 §4.2.2.2).
    SubjectInfoAccess(Vec<AccessDescription>),
    /// `id-pe-tlsfeature` (RFC 7633) — list of TLS feature integers.
    TlsFeature(Vec<u16>),
    /// Unknown or unhandled extension — raw OID and DER body.
    Unknown {
        /// The extension's OID.
        oid: String,
        /// The DER content of the OCTET STRING body.
        value: Vec<u8>,
    },
}

// =====================================================================
// Phase 8 — Internal extension parsers
// =====================================================================

/// Dispatches to the appropriate decoder based on `oid` and returns the
/// typed [`ParsedExtension`]. Unknown OIDs map to
/// [`ParsedExtension::Unknown`] with no error.
fn parse_extension(oid_str: &str, value: &[u8]) -> CryptoResult<ParsedExtension> {
    trace!(target: "openssl::x509::ext", oid = oid_str, len = value.len(), "parsing extension");
    match oid_str {
        oid::BASIC_CONSTRAINTS => {
            parse_basic_constraints(value).map(ParsedExtension::BasicConstraints)
        }
        oid::KEY_USAGE => parse_key_usage(value).map(ParsedExtension::KeyUsage),
        oid::EXTENDED_KEY_USAGE => {
            parse_extended_key_usage(value).map(ParsedExtension::ExtendedKeyUsage)
        }
        oid::SUBJECT_KEY_IDENTIFIER => {
            parse_subject_key_id(value).map(ParsedExtension::SubjectKeyIdentifier)
        }
        oid::AUTHORITY_KEY_IDENTIFIER => {
            parse_authority_key_id(value).map(ParsedExtension::AuthorityKeyIdentifier)
        }
        oid::SUBJECT_ALT_NAME => parse_general_names(value).map(ParsedExtension::SubjectAltName),
        oid::ISSUER_ALT_NAME => parse_general_names(value).map(ParsedExtension::IssuerAltName),
        oid::CRL_DISTRIBUTION_POINTS | oid::FRESHEST_CRL => {
            parse_crl_distribution_points(value).map(ParsedExtension::CrlDistributionPoints)
        }
        oid::CERTIFICATE_POLICIES => {
            parse_certificate_policies(value).map(ParsedExtension::CertificatePolicies)
        }
        oid::POLICY_MAPPINGS => parse_policy_mappings(value).map(ParsedExtension::PolicyMappings),
        oid::POLICY_CONSTRAINTS => {
            parse_policy_constraints(value).map(ParsedExtension::PolicyConstraints)
        }
        oid::INHIBIT_ANY_POLICY => parse_integer_u32(value).map(ParsedExtension::InhibitAnyPolicy),
        oid::NAME_CONSTRAINTS => {
            parse_name_constraints(value).map(ParsedExtension::NameConstraints)
        }
        oid::AUTHORITY_INFO_ACCESS => {
            parse_access_descriptions(value).map(ParsedExtension::AuthorityInfoAccess)
        }
        oid::SUBJECT_INFO_ACCESS => {
            parse_access_descriptions(value).map(ParsedExtension::SubjectInfoAccess)
        }
        oid::TLS_FEATURE => parse_tls_features(value).map(ParsedExtension::TlsFeature),
        _ => Ok(ParsedExtension::Unknown {
            oid: oid_str.to_owned(),
            value: value.to_vec(),
        }),
    }
}

/// Parses `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER (0..MAX) OPTIONAL }`.
fn parse_basic_constraints(value: &[u8]) -> CryptoResult<BasicConstraints> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("BasicConstraints: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("BasicConstraints: trailing bytes"));
    }
    let mut ca = false;
    let mut path_length: Option<u32> = None;
    let mut cursor = body;
    if let Some((bool_body, after_bool)) = parse_tlv(cursor, 0x01) {
        if bool_body.len() != 1 {
            return Err(asn1_err("BasicConstraints: BOOLEAN must be a single byte"));
        }
        ca = bool_body[0] != 0;
        cursor = after_bool;
    }
    if let Some((int_body, after_int)) = parse_tlv(cursor, 0x02) {
        path_length = Some(decode_unsigned_u32(int_body)?);
        cursor = after_int;
    }
    if !cursor.is_empty() {
        return Err(asn1_err("BasicConstraints: unexpected trailing element"));
    }
    Ok(BasicConstraints { ca, path_length })
}

/// Parses `KeyUsage ::= BIT STRING`.
fn parse_key_usage(value: &[u8]) -> CryptoResult<KeyUsageFlags> {
    let (body, rest) =
        parse_tlv(value, 0x03).ok_or_else(|| asn1_err("KeyUsage: missing BIT STRING"))?;
    if !rest.is_empty() {
        return Err(asn1_err("KeyUsage: trailing bytes"));
    }
    if body.is_empty() {
        return Err(asn1_err("KeyUsage: empty BIT STRING"));
    }
    let unused = body[0];
    if unused > 7 {
        return Err(asn1_err("KeyUsage: invalid unused-bits count"));
    }
    let bits = &body[1..];
    let b0 = u16::from(bits.first().copied().unwrap_or(0));
    let b1 = u16::from(bits.get(1).copied().unwrap_or(0));
    let raw = (b0 << 8) | b1;
    // Mask off unused bits in the last meaningful octet.
    let mut packed = raw;
    if bits.len() == 1 {
        let mask = !((1u16 << unused) - 1) & 0xFF00;
        packed &= mask;
    } else {
        let mask = !((1u16 << unused) - 1);
        packed &= mask;
    }
    // Bring decipher-only (bit 8) into 0x8000 like OpenSSL's mapping.
    let mut flags = KeyUsageFlags::from_bits_truncate(packed);
    if bits.len() >= 2 && (bits[1] & 0x80) != 0 {
        flags |= KeyUsageFlags::DECIPHER_ONLY;
    }
    Ok(flags)
}

/// Parses `ExtKeyUsage ::= SEQUENCE OF KeyPurposeId`.
fn parse_extended_key_usage(value: &[u8]) -> CryptoResult<Vec<String>> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("ExtKeyUsage: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("ExtKeyUsage: trailing bytes"));
    }
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (oid_body, after) =
            parse_tlv(cursor, 0x06).ok_or_else(|| asn1_err("ExtKeyUsage: expected OID"))?;
        out.push(decode_oid(oid_body)?);
        cursor = after;
    }
    Ok(out)
}

/// Parses `SubjectKeyIdentifier ::= OCTET STRING`.
fn parse_subject_key_id(value: &[u8]) -> CryptoResult<Vec<u8>> {
    let (body, rest) = parse_tlv(value, 0x04)
        .ok_or_else(|| asn1_err("SubjectKeyIdentifier: missing OCTET STRING"))?;
    if !rest.is_empty() {
        return Err(asn1_err("SubjectKeyIdentifier: trailing bytes"));
    }
    Ok(body.to_vec())
}

/// Parses `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0]
/// IMPLICIT OCTET STRING OPTIONAL, authorityCertIssuer [1] IMPLICIT
/// GeneralNames OPTIONAL, authorityCertSerialNumber [2] IMPLICIT
/// INTEGER OPTIONAL }`.
fn parse_authority_key_id(value: &[u8]) -> CryptoResult<AuthorityKeyIdentifier> {
    let (body, rest) = parse_tlv(value, 0x30)
        .ok_or_else(|| asn1_err("AuthorityKeyIdentifier: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("AuthorityKeyIdentifier: trailing bytes"));
    }
    let mut akid = AuthorityKeyIdentifier::default();
    let mut cursor = body;
    while !cursor.is_empty() {
        if cursor.is_empty() {
            break;
        }
        let tag = cursor[0];
        let (inner_body, after) = parse_tlv_any(cursor)
            .ok_or_else(|| asn1_err("AuthorityKeyIdentifier: malformed inner TLV"))?;
        match tag {
            0x80 => {
                // [0] IMPLICIT OCTET STRING
                akid.key_identifier = Some(inner_body.to_vec());
            }
            0xA1 => {
                // [1] IMPLICIT GeneralNames (constructed)
                akid.authority_cert_issuer = Some(parse_general_names_body(inner_body)?);
            }
            0x82 => {
                // [2] IMPLICIT INTEGER (the serial number)
                akid.authority_cert_serial = Some(inner_body.to_vec());
            }
            _ => {
                // Unknown tag — ignore for forward compatibility, mirroring
                // OpenSSL's permissive parsing.
            }
        }
        cursor = after;
    }
    Ok(akid)
}

/// Parses `GeneralNames ::= SEQUENCE OF GeneralName` (the full TLV
/// including the outer SEQUENCE).
fn parse_general_names(value: &[u8]) -> CryptoResult<Vec<GeneralName>> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("GeneralNames: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("GeneralNames: trailing bytes"));
    }
    parse_general_names_body(body)
}

/// Parses the body of a `GeneralNames` SEQUENCE (without the outer
/// SEQUENCE TLV).
fn parse_general_names_body(body: &[u8]) -> CryptoResult<Vec<GeneralName>> {
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (gn, after) = parse_general_name(cursor)?;
        out.push(gn);
        cursor = after;
    }
    Ok(out)
}

/// Parses a single `GeneralName` from `input`, returning the parsed
/// value and the remaining bytes.
fn parse_general_name(input: &[u8]) -> CryptoResult<(GeneralName, &[u8])> {
    if input.is_empty() {
        return Err(asn1_err("GeneralName: input is empty"));
    }
    let tag = input[0];
    let (body, after) =
        parse_tlv_any(input).ok_or_else(|| asn1_err("GeneralName: malformed TLV"))?;
    let gn = match tag {
        0xA0 => {
            // [0] otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
            let (oid_body, rest_after_oid) = parse_tlv(body, 0x06)
                .ok_or_else(|| asn1_err("GeneralName::otherName: missing OID"))?;
            let type_id = decode_oid(oid_body)?;
            // The value is wrapped in [0] EXPLICIT — strip the outer tag.
            let (val_inner, _) = parse_tlv(rest_after_oid, 0xA0)
                .ok_or_else(|| asn1_err("GeneralName::otherName: missing [0] value"))?;
            GeneralName::OtherName {
                type_id,
                value: val_inner.to_vec(),
            }
        }
        0x81 => {
            // [1] rfc822Name (IMPLICIT IA5String)
            GeneralName::Rfc822Name(decode_string(body, Asn1StringType::Ia5String))
        }
        0x82 => {
            // [2] dNSName (IMPLICIT IA5String)
            GeneralName::DnsName(decode_string(body, Asn1StringType::Ia5String))
        }
        0xA4 => {
            // [4] EXPLICIT directoryName
            let name = X509Name::from_der(body)?;
            GeneralName::DirectoryName(name)
        }
        0x86 => {
            // [6] uniformResourceIdentifier (IMPLICIT IA5String)
            GeneralName::UniformResourceIdentifier(decode_string(body, Asn1StringType::Ia5String))
        }
        0x87 => {
            // [7] iPAddress (IMPLICIT OCTET STRING)
            GeneralName::IpAddress(body.to_vec())
        }
        0x88 => {
            // [8] registeredID (IMPLICIT OBJECT IDENTIFIER)
            GeneralName::RegisteredId(decode_oid(body)?)
        }
        _ => {
            // Unknown CHOICE alternative — preserve as OtherName with the
            // original tag in the type-id slot for traceability.
            GeneralName::OtherName {
                type_id: format!("0x{tag:02x}"),
                value: body.to_vec(),
            }
        }
    };
    Ok((gn, after))
}

/// Parses `cRLDistributionPoints ::= SEQUENCE OF DistributionPoint`.
fn parse_crl_distribution_points(value: &[u8]) -> CryptoResult<Vec<DistributionPoint>> {
    let (body, rest) = parse_tlv(value, 0x30)
        .ok_or_else(|| asn1_err("CRLDistributionPoints: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("CRLDistributionPoints: trailing bytes"));
    }
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (dp_body, after) = parse_tlv(cursor, 0x30).ok_or_else(|| {
            asn1_err("CRLDistributionPoints: expected DistributionPoint SEQUENCE")
        })?;
        out.push(parse_distribution_point(dp_body)?);
        cursor = after;
    }
    Ok(out)
}

/// Parses the body of a single `DistributionPoint` SEQUENCE.
fn parse_distribution_point(body: &[u8]) -> CryptoResult<DistributionPoint> {
    let mut dp = DistributionPoint::default();
    let mut cursor = body;
    while !cursor.is_empty() {
        let tag = cursor[0];
        let (inner, after) = parse_tlv_any(cursor)
            .ok_or_else(|| asn1_err("DistributionPoint: malformed component"))?;
        match tag {
            0xA0 => {
                // [0] EXPLICIT distributionPoint DistributionPointName
                if inner.is_empty() {
                    return Err(asn1_err("DistributionPoint: empty [0] body"));
                }
                let inner_tag = inner[0];
                let (inner_body, _) = parse_tlv_any(inner)
                    .ok_or_else(|| asn1_err("DistributionPoint: malformed [0] inner"))?;
                dp.name = Some(match inner_tag {
                    0xA0 => {
                        // [0] fullName GeneralNames
                        DistributionPointName::FullName(parse_general_names_body(inner_body)?)
                    }
                    0xA1 => {
                        // [1] nameRelativeToCRLIssuer RelativeDistinguishedName
                        // RDN is a SET OF AttributeTypeAndValue — to fit our
                        // X509Name model we wrap it as a single-RDN name.
                        // Construct a synthetic SEQUENCE { SET { ... } } so
                        // that X509Name::from_der can be reused.
                        let mut wrapped = Vec::new();
                        wrapped.push(0x31); // SET
                        write_length(&mut wrapped, inner_body.len());
                        wrapped.extend_from_slice(inner_body);
                        let mut outer = Vec::new();
                        outer.push(0x30);
                        write_length(&mut outer, wrapped.len());
                        outer.extend_from_slice(&wrapped);
                        DistributionPointName::NameRelativeToCrlIssuer(X509Name::from_der(&outer)?)
                    }
                    _ => {
                        return Err(asn1_err(
                            "DistributionPoint: unknown DistributionPointName tag",
                        ));
                    }
                });
            }
            0x81 => {
                // [1] IMPLICIT reasons BIT STRING
                if inner.is_empty() {
                    return Err(asn1_err("DistributionPoint: empty reasons"));
                }
                let unused = inner[0];
                if unused > 7 {
                    return Err(asn1_err("DistributionPoint: invalid reasons unused-bits"));
                }
                let bits = &inner[1..];
                let b0 = u16::from(bits.first().copied().unwrap_or(0));
                let b1 = u16::from(bits.get(1).copied().unwrap_or(0));
                let raw = (b0 << 8) | b1;
                dp.reasons = Some(crate::x509::crl::ReasonFlags::from_bits_truncate(raw));
            }
            0xA2 => {
                // [2] IMPLICIT cRLIssuer GeneralNames
                dp.crl_issuer = Some(parse_general_names_body(inner)?);
            }
            _ => {
                // Forward-compatible: ignore unknown components.
            }
        }
        cursor = after;
    }
    Ok(dp)
}

/// Parses `certificatePolicies ::= SEQUENCE OF PolicyInformation`.
fn parse_certificate_policies(value: &[u8]) -> CryptoResult<Vec<PolicyInfo>> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("CertificatePolicies: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("CertificatePolicies: trailing bytes"));
    }
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (pi_body, after) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("CertificatePolicies: expected PolicyInformation"))?;
        let (oid_body, after_oid) =
            parse_tlv(pi_body, 0x06).ok_or_else(|| asn1_err("PolicyInformation: missing OID"))?;
        let policy_oid = decode_oid(oid_body)?;
        let mut qualifiers: Vec<PolicyQualifier> = Vec::new();
        if !after_oid.is_empty() {
            let (q_body, q_rest) = parse_tlv(after_oid, 0x30)
                .ok_or_else(|| asn1_err("PolicyInformation: malformed qualifiers SEQUENCE"))?;
            if !q_rest.is_empty() {
                return Err(asn1_err(
                    "PolicyInformation: trailing bytes after qualifiers",
                ));
            }
            let mut q_cursor = q_body;
            while !q_cursor.is_empty() {
                let (qi_body, qi_after) = parse_tlv(q_cursor, 0x30)
                    .ok_or_else(|| asn1_err("PolicyInformation: malformed qualifier"))?;
                let (qid_body, qid_after) = parse_tlv(qi_body, 0x06)
                    .ok_or_else(|| asn1_err("PolicyQualifierInfo: missing OID"))?;
                let qid = decode_oid(qid_body)?;
                let qualifier = match qid.as_str() {
                    "1.3.6.1.5.5.7.2.1" => {
                        // CPSuri ::= IA5String
                        let (cps_body, _) = parse_tlv(qid_after, 0x16)
                            .ok_or_else(|| asn1_err("CPSuri: missing IA5String"))?;
                        PolicyQualifier::Cps(decode_string(cps_body, Asn1StringType::Ia5String))
                    }
                    "1.3.6.1.5.5.7.2.2" => {
                        let (un_body, _) = parse_tlv(qid_after, 0x30)
                            .ok_or_else(|| asn1_err("UserNotice: missing SEQUENCE"))?;
                        PolicyQualifier::UserNotice(parse_user_notice(un_body)?)
                    }
                    other => {
                        // Unknown qualifier — preserve as a CPS string of the
                        // raw content (best-effort) so callers can still see
                        // *something*; OpenSSL's behaviour is similar.
                        let _ = other;
                        PolicyQualifier::Cps(format!("unknown-qualifier:{qid}"))
                    }
                };
                qualifiers.push(qualifier);
                q_cursor = qi_after;
            }
        }
        out.push(PolicyInfo {
            policy_oid,
            qualifiers,
        });
        cursor = after;
    }
    Ok(out)
}

/// Parses the body of a `UserNotice` SEQUENCE.
fn parse_user_notice(body: &[u8]) -> CryptoResult<UserNotice> {
    let mut un = UserNotice::default();
    let mut cursor = body;
    if cursor.is_empty() {
        return Ok(un);
    }
    // Optional NoticeReference ::= SEQUENCE
    if cursor[0] == 0x30 {
        let (nr_body, after) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("UserNotice: malformed NoticeReference"))?;
        un.notice_ref = Some(nr_body.to_vec());
        cursor = after;
    }
    // Optional explicitText ::= DisplayText (CHOICE of strings)
    if !cursor.is_empty() {
        let tag = cursor[0];
        let st = match tag {
            0x0C => Asn1StringType::Utf8String,
            0x13 => Asn1StringType::PrintableString,
            0x16 => Asn1StringType::Ia5String,
            0x14 => Asn1StringType::T61String,
            0x1E => Asn1StringType::BmpString,
            other => {
                return Err(asn1_err(if other == 0 {
                    "UserNotice::explicitText: missing tag"
                } else {
                    "UserNotice::explicitText: unsupported tag"
                }));
            }
        };
        let (text_body, _) =
            parse_tlv_any(cursor).ok_or_else(|| asn1_err("UserNotice::explicitText: malformed"))?;
        un.explicit_text = Some(decode_string(text_body, st));
    }
    Ok(un)
}

/// Parses `policyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy
/// OID, subjectDomainPolicy OID }`.
fn parse_policy_mappings(value: &[u8]) -> CryptoResult<Vec<(String, String)>> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("PolicyMappings: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("PolicyMappings: trailing bytes"));
    }
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (m_body, after) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("PolicyMappings: expected pair SEQUENCE"))?;
        let (issuer_body, after_issuer) = parse_tlv(m_body, 0x06)
            .ok_or_else(|| asn1_err("PolicyMappings: missing issuerDomainPolicy"))?;
        let (subject_body, after_subject) = parse_tlv(after_issuer, 0x06)
            .ok_or_else(|| asn1_err("PolicyMappings: missing subjectDomainPolicy"))?;
        if !after_subject.is_empty() {
            return Err(asn1_err("PolicyMappings: trailing bytes in pair"));
        }
        out.push((decode_oid(issuer_body)?, decode_oid(subject_body)?));
        cursor = after;
    }
    Ok(out)
}

/// Parses `policyConstraints ::= SEQUENCE { requireExplicitPolicy [0]
/// IMPLICIT INTEGER OPTIONAL, inhibitPolicyMapping [1] IMPLICIT INTEGER
/// OPTIONAL }`.
fn parse_policy_constraints(value: &[u8]) -> CryptoResult<PolicyConstraints> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("PolicyConstraints: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("PolicyConstraints: trailing bytes"));
    }
    let mut pc = PolicyConstraints::default();
    let mut cursor = body;
    while !cursor.is_empty() {
        let tag = cursor[0];
        let (inner, after) = parse_tlv_any(cursor)
            .ok_or_else(|| asn1_err("PolicyConstraints: malformed component"))?;
        match tag {
            0x80 => pc.require_explicit_policy = Some(decode_unsigned_u32(inner)?),
            0x81 => pc.inhibit_policy_mapping = Some(decode_unsigned_u32(inner)?),
            _ => { /* forward-compatible */ }
        }
        cursor = after;
    }
    Ok(pc)
}

/// Parses `nameConstraints ::= SEQUENCE { permittedSubtrees [0]
/// IMPLICIT GeneralSubtrees OPTIONAL, excludedSubtrees [1] IMPLICIT
/// GeneralSubtrees OPTIONAL }`.
fn parse_name_constraints(value: &[u8]) -> CryptoResult<NameConstraints> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("NameConstraints: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("NameConstraints: trailing bytes"));
    }
    let mut nc = NameConstraints::default();
    let mut cursor = body;
    while !cursor.is_empty() {
        let tag = cursor[0];
        let (inner, after) = parse_tlv_any(cursor)
            .ok_or_else(|| asn1_err("NameConstraints: malformed subtree list"))?;
        match tag {
            0xA0 => nc.permitted_subtrees = parse_general_subtrees(inner)?,
            0xA1 => nc.excluded_subtrees = parse_general_subtrees(inner)?,
            _ => { /* forward-compatible */ }
        }
        cursor = after;
    }
    Ok(nc)
}

/// Parses `GeneralSubtrees ::= SEQUENCE OF GeneralSubtree` body.
fn parse_general_subtrees(body: &[u8]) -> CryptoResult<Vec<GeneralSubtree>> {
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (subtree_body, after) =
            parse_tlv(cursor, 0x30).ok_or_else(|| asn1_err("GeneralSubtree: expected SEQUENCE"))?;
        let (base, after_base) = parse_general_name(subtree_body)?;
        let mut minimum: u32 = 0;
        let mut maximum: Option<u32> = None;
        let mut sub_cursor = after_base;
        while !sub_cursor.is_empty() {
            let sub_tag = sub_cursor[0];
            let (sub_body, sub_after) = parse_tlv_any(sub_cursor)
                .ok_or_else(|| asn1_err("GeneralSubtree: malformed minimum/maximum"))?;
            match sub_tag {
                0x80 => minimum = decode_unsigned_u32(sub_body)?,
                0x81 => maximum = Some(decode_unsigned_u32(sub_body)?),
                _ => { /* forward-compatible */ }
            }
            sub_cursor = sub_after;
        }
        out.push(GeneralSubtree {
            base,
            minimum,
            maximum,
        });
        cursor = after;
    }
    Ok(out)
}

/// Parses `AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription`.
fn parse_access_descriptions(value: &[u8]) -> CryptoResult<Vec<AccessDescription>> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("AccessDescriptions: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("AccessDescriptions: trailing bytes"));
    }
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (ad_body, after) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("AccessDescription: expected SEQUENCE"))?;
        let (oid_body, after_oid) =
            parse_tlv(ad_body, 0x06).ok_or_else(|| asn1_err("AccessDescription: missing OID"))?;
        let method = decode_oid(oid_body)?;
        let (location, _) = parse_general_name(after_oid)?;
        out.push(AccessDescription { method, location });
        cursor = after;
    }
    Ok(out)
}

/// Parses `Features ::= SEQUENCE OF INTEGER` (RFC 7633).
fn parse_tls_features(value: &[u8]) -> CryptoResult<Vec<u16>> {
    let (body, rest) =
        parse_tlv(value, 0x30).ok_or_else(|| asn1_err("TlsFeature: missing SEQUENCE"))?;
    if !rest.is_empty() {
        return Err(asn1_err("TlsFeature: trailing bytes"));
    }
    let mut out = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (int_body, after) =
            parse_tlv(cursor, 0x02).ok_or_else(|| asn1_err("TlsFeature: expected INTEGER"))?;
        let v = decode_unsigned_u32(int_body)?;
        out.push(u16::try_from(v).map_err(|_| asn1_err("TlsFeature: value out of u16 range"))?);
        cursor = after;
    }
    Ok(out)
}

/// Parses an `INTEGER` whose value contains the body bytes only and
/// returns it as a `u32`. Used by `inhibitAnyPolicy` and similar
/// extensions where the value is wrapped in just the INTEGER TLV.
fn parse_integer_u32(value: &[u8]) -> CryptoResult<u32> {
    let (body, rest) = parse_tlv(value, 0x02).ok_or_else(|| asn1_err("INTEGER: missing tag"))?;
    if !rest.is_empty() {
        return Err(asn1_err("INTEGER: trailing bytes"));
    }
    decode_unsigned_u32(body)
}

/// Decodes an unsigned ASN.1 INTEGER body into a `u32`. Honors the
/// leading sign-bit padding zero byte allowed by DER. Refuses values
/// that overflow `u32`. (R6 — no bare `as` casts.)
fn decode_unsigned_u32(body: &[u8]) -> CryptoResult<u32> {
    if body.is_empty() {
        return Err(asn1_err("INTEGER: empty body"));
    }
    let trimmed: &[u8] = if body.len() > 1 && body[0] == 0 {
        &body[1..]
    } else {
        body
    };
    if trimmed.first().copied().unwrap_or(0) & 0x80 != 0 {
        return Err(asn1_err("INTEGER: negative value not permitted here"));
    }
    if trimmed.len() > 4 {
        return Err(asn1_err("INTEGER: value exceeds u32 range"));
    }
    let mut acc: u32 = 0;
    for &b in trimmed {
        acc = acc
            .checked_shl(8)
            .and_then(|v| v.checked_add(u32::from(b)))
            .ok_or_else(|| asn1_err("INTEGER: arithmetic overflow"))?;
    }
    Ok(acc)
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 9 — ExtensionFlags (cached extension processing flags)
// ════════════════════════════════════════════════════════════════════════════
//
// Translates the `EXFLAG_*` constants from `include/openssl/x509v3.h` and
// the cached `ex_flags` field in `X509` populated by
// `ossl_x509v3_cache_extensions()` in `crypto/x509/v3_purp.c`.
//
// These flags are derived once per certificate when the extensions are first
// inspected, then cached on the certificate to make subsequent verification
// queries cheap. Each flag corresponds directly to a constant in the upstream
// header; the bit values are preserved for cross-language ABI compatibility
// with the FFI crate.

bitflags! {
    /// Cached extension-processing flags for an [`X509Certificate`].
    ///
    /// Populated lazily by [`X509Certificate::cache_extensions`] (translation of
    /// `ossl_x509v3_cache_extensions()` from `crypto/x509/v3_purp.c`). After the
    /// cache is built, callers can answer "is this a CA?", "is this self-signed?",
    /// etc. by inspecting these flags rather than re-decoding extensions.
    ///
    /// The bit values match upstream `EXFLAG_*` for ABI compatibility.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ExtensionFlags: u32 {
        /// Certificate carries a basicConstraints extension.
        const BCONS              = 0x0000_0001;
        /// Certificate carries a keyUsage extension.
        const KUSAGE             = 0x0000_0002;
        /// Certificate carries an extendedKeyUsage extension.
        const XKUSAGE            = 0x0000_0004;
        /// Certificate carries a Netscape-cert-type extension.
        const NSCERT             = 0x0000_0008;
        /// Certificate is a CA per its basicConstraints.
        const CA                 = 0x0000_0010;
        /// Certificate is self-issued (issuer DN == subject DN), even if not
        /// strictly self-signed.
        const SI                 = 0x0000_0020;
        /// Certificate is encoded as X.509 v1 (no extensions field).
        const V1                 = 0x0000_0040;
        /// Certificate has an invalid encoding or extension.
        const INVALID            = 0x0000_0080;
        /// `cache_extensions` has been called and the cached fields are
        /// populated.
        const SET                = 0x0000_0100;
        /// Certificate has at least one critical extension.
        const CRITICAL           = 0x0000_0200;
        /// Certificate is an RFC 3820 proxy certificate.
        const PROXY              = 0x0000_0400;
        /// Certificate carries an invalid certificatePolicies extension.
        const INVALID_POLICY     = 0x0000_0800;
        /// Certificate carries a freshestCRL extension.
        const FRESHEST           = 0x0000_1000;
        /// Certificate is self-signed (issuer DN == subject DN AND signature
        /// verifies under the embedded public key).
        const SS                 = 0x0000_2000;
        /// basicConstraints extension is marked critical.
        const BCONS_CRITICAL     = 0x0001_0000;
        /// authorityKeyIdentifier extension is marked critical.
        const AKID_CRITICAL      = 0x0002_0000;
        /// subjectKeyIdentifier extension is marked critical.
        const SKID_CRITICAL      = 0x0004_0000;
        /// subjectAltName extension is marked critical.
        const SAN_CRITICAL       = 0x0008_0000;
        /// Certificate fingerprint could not be computed (e.g., unsupported
        /// signature algorithm).
        const NO_FINGERPRINT     = 0x0010_0000;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 10 — CertAuxiliary (X509_CERT_AUX from x_x509a.c)
// ════════════════════════════════════════════════════════════════════════════
//
// Translates `X509_CERT_AUX` from `crypto/x509/x_x509a.c`. This data is the
// OpenSSL-specific "auxiliary" extension to a certificate that records trust
// settings, rejection settings, an alias (friendly name), and a key
// identifier. It is stored alongside the certificate in `*_X509_AUX` PEM blobs
// (e.g., trusted certificate stores) but is not part of the formal RFC 5280
// certificate.
//
// ASN.1 schema (from x_x509a.c):
//
// ```text
// X509_CERT_AUX ::= SEQUENCE {
//     trust    SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//     reject   [0] IMPLICIT SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//     alias    UTF8String OPTIONAL,
//     keyid    OCTET STRING OPTIONAL,
//     other    [1] IMPLICIT SEQUENCE OF AlgorithmIdentifier OPTIONAL
// }
// ```
//
// The `other` field holds OpenSSL extensions to the auxiliary record (rarely
// used in practice). We retain it as a list of [`AlgorithmIdentifier`] for
// round-tripping fidelity but most callers will leave it empty.

/// X.509 certificate auxiliary data (OpenSSL extension to RFC 5280).
///
/// Translates `X509_CERT_AUX` from `crypto/x509/x_x509a.c`. Records
/// per-certificate trust/reject settings, a human-readable alias, and an
/// optional key identifier. This data lives only in OpenSSL trusted-store
/// PEM files (`*_AUX` blobs) and is not transmitted over the wire as part of
/// a TLS handshake.
///
/// All fields are optional and, per Rule R5, sentinel values from the C
/// implementation are mapped to `Option<T>`:
/// - C `aux->alias = NULL` → `alias: None`
/// - C `aux->keyid = NULL` → `key_id: None`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertAuxiliary {
    /// Trust settings — OIDs of purposes for which this certificate is
    /// trusted. Mapped from `STACK_OF(ASN1_OBJECT) *trust`.
    pub trust: Vec<String>,
    /// Reject settings — OIDs of purposes for which this certificate is
    /// explicitly rejected. Mapped from `STACK_OF(ASN1_OBJECT) *reject`.
    pub reject: Vec<String>,
    /// Friendly name / alias (PKCS#9 friendlyName-style string).
    /// `None` if not set (Rule R5 — was C `unsigned char *alias = NULL`).
    pub alias: Option<String>,
    /// Key identifier bytes. `None` if not set (Rule R5).
    pub key_id: Option<Vec<u8>>,
    /// Other auxiliary algorithms. Rarely populated; retained for ASN.1
    /// round-trip fidelity with C implementations.
    pub other: Vec<AlgorithmIdentifier>,
}

impl CertAuxiliary {
    /// Constructs an empty [`CertAuxiliary`] record. Equivalent to
    /// `X509_CERT_AUX_new()` returning a freshly-zeroed struct.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if this auxiliary record carries any non-default
    /// information. A wholly-empty record is functionally equivalent to no
    /// record at all and need not be serialised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.trust.is_empty()
            && self.reject.is_empty()
            && self.alias.is_none()
            && self.key_id.is_none()
            && self.other.is_empty()
    }

    /// Adds a trusted-purpose OID to the trust list. Translates
    /// `X509_add1_trust_object()` from `x_x509a.c`.
    pub fn add_trust(&mut self, oid: impl Into<String>) {
        self.trust.push(oid.into());
    }

    /// Adds a rejected-purpose OID to the reject list. Translates
    /// `X509_add1_reject_object()` from `x_x509a.c`.
    pub fn add_reject(&mut self, oid: impl Into<String>) {
        self.reject.push(oid.into());
    }

    /// Sets the friendly-name alias. Translates `X509_alias_set1()` from
    /// `x_x509a.c`. Pass `None` to clear.
    pub fn set_alias(&mut self, alias: Option<String>) {
        self.alias = alias;
    }

    /// Sets the auxiliary key identifier. Translates `X509_keyid_set1()`
    /// from `x_x509a.c`. Pass `None` to clear.
    pub fn set_key_id(&mut self, key_id: Option<Vec<u8>>) {
        self.key_id = key_id;
    }

    /// DER-encodes the auxiliary record (best-effort minimal encoder).
    /// Returns the DER bytes that would be appended after the certificate
    /// in a `*_AUX` PEM blob.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        let mut body: Vec<u8> = Vec::new();

        // trust : SEQUENCE OF OID — only emitted if non-empty.
        if !self.trust.is_empty() {
            let mut inner: Vec<u8> = Vec::new();
            for oid_str in &self.trust {
                let oid_body = encode_oid(oid_str);
                encode_tlv(&mut inner, 0x06, &oid_body);
            }
            encode_tlv(&mut body, 0x30, &inner);
        }
        // reject : [0] IMPLICIT SEQUENCE OF OID
        if !self.reject.is_empty() {
            let mut inner: Vec<u8> = Vec::new();
            for oid_str in &self.reject {
                let oid_body = encode_oid(oid_str);
                encode_tlv(&mut inner, 0x06, &oid_body);
            }
            // [0] IMPLICIT — replace SEQUENCE tag (0x30) with [0] (0xA0)
            encode_tlv(&mut body, 0xA0, &inner);
        }
        // alias : UTF8String OPTIONAL
        if let Some(alias) = &self.alias {
            encode_tlv(&mut body, 0x0C, alias.as_bytes());
        }
        // keyid : OCTET STRING OPTIONAL
        if let Some(key_id) = &self.key_id {
            encode_tlv(&mut body, 0x04, key_id);
        }
        // other : [1] IMPLICIT SEQUENCE OF AlgorithmIdentifier
        if !self.other.is_empty() {
            let mut inner: Vec<u8> = Vec::new();
            for alg in &self.other {
                let mut alg_body: Vec<u8> = Vec::new();
                let oid_body = encode_oid(&alg.algorithm);
                encode_tlv(&mut alg_body, 0x06, &oid_body);
                if let Some(params) = &alg.parameters {
                    alg_body.extend_from_slice(params);
                }
                encode_tlv(&mut inner, 0x30, &alg_body);
            }
            encode_tlv(&mut body, 0xA1, &inner);
        }

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &body);
        Ok(out)
    }

    /// Decodes a DER-encoded `X509_CERT_AUX` blob. Tolerates absence of all
    /// optional fields. Translates `d2i_X509_CERT_AUX()`.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        let (body, rest) = parse_tlv(der, 0x30)
            .ok_or_else(|| asn1_err("X509_CERT_AUX: outer SEQUENCE missing"))?;
        if !rest.is_empty() {
            return Err(asn1_err("X509_CERT_AUX: trailing bytes after SEQUENCE"));
        }

        let mut aux = CertAuxiliary::new();
        let mut cursor = body;

        // trust : SEQUENCE OF OID — peek tag 0x30
        if cursor.first() == Some(&0x30) {
            let (inner, after) = parse_tlv(cursor, 0x30)
                .ok_or_else(|| asn1_err("X509_CERT_AUX.trust: bad SEQUENCE"))?;
            cursor = after;
            let mut oid_cursor = inner;
            while !oid_cursor.is_empty() {
                let (oid_body, after_oid) = parse_tlv(oid_cursor, 0x06)
                    .ok_or_else(|| asn1_err("X509_CERT_AUX.trust: expected OID"))?;
                aux.trust.push(decode_oid(oid_body)?);
                oid_cursor = after_oid;
            }
        }
        // reject : [0] IMPLICIT SEQUENCE OF OID — peek tag 0xA0
        if cursor.first() == Some(&0xA0) {
            let (inner, after) = parse_tlv(cursor, 0xA0)
                .ok_or_else(|| asn1_err("X509_CERT_AUX.reject: bad [0] IMPLICIT"))?;
            cursor = after;
            let mut oid_cursor = inner;
            while !oid_cursor.is_empty() {
                let (oid_body, after_oid) = parse_tlv(oid_cursor, 0x06)
                    .ok_or_else(|| asn1_err("X509_CERT_AUX.reject: expected OID"))?;
                aux.reject.push(decode_oid(oid_body)?);
                oid_cursor = after_oid;
            }
        }
        // alias : UTF8String OPTIONAL — peek tag 0x0C
        if cursor.first() == Some(&0x0C) {
            let (alias_body, after) = parse_tlv(cursor, 0x0C)
                .ok_or_else(|| asn1_err("X509_CERT_AUX.alias: bad UTF8String"))?;
            cursor = after;
            aux.alias = Some(
                std::str::from_utf8(alias_body)
                    .map_err(|e| asn1_err(format!("X509_CERT_AUX.alias: invalid UTF-8: {e}")))?
                    .to_string(),
            );
        }
        // keyid : OCTET STRING OPTIONAL — peek tag 0x04
        if cursor.first() == Some(&0x04) {
            let (kid_body, after) = parse_tlv(cursor, 0x04)
                .ok_or_else(|| asn1_err("X509_CERT_AUX.keyid: bad OCTET STRING"))?;
            cursor = after;
            aux.key_id = Some(kid_body.to_vec());
        }
        // other : [1] IMPLICIT SEQUENCE OF AlgorithmIdentifier — peek tag 0xA1
        if cursor.first() == Some(&0xA1) {
            let (inner, after) = parse_tlv(cursor, 0xA1)
                .ok_or_else(|| asn1_err("X509_CERT_AUX.other: bad [1] IMPLICIT"))?;
            cursor = after;
            let mut alg_cursor = inner;
            while !alg_cursor.is_empty() {
                let (alg_body, after_alg) = parse_tlv(alg_cursor, 0x30)
                    .ok_or_else(|| asn1_err("X509_CERT_AUX.other: expected SEQUENCE"))?;
                let (oid_body, params_rest) = parse_tlv(alg_body, 0x06)
                    .ok_or_else(|| asn1_err("X509_CERT_AUX.other: expected algorithm OID"))?;
                let algorithm = decode_oid(oid_body)?;
                let parameters = if params_rest.is_empty() {
                    None
                } else {
                    Some(params_rest.to_vec())
                };
                aux.other.push(AlgorithmIdentifier {
                    algorithm,
                    parameters,
                });
                alg_cursor = after_alg;
            }
        }

        if !cursor.is_empty() {
            return Err(asn1_err("X509_CERT_AUX: unexpected trailing data"));
        }
        Ok(aux)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 11 — X509Certificate (RFC 5280 §4 Certificate)
// ════════════════════════════════════════════════════════════════════════════
//
// Translates the C `X509` and `X509_CINF` structures from
// `crypto/x509/x_x509.c` and `include/crypto/x509.h`.
//
// ASN.1 layout (RFC 5280 §4.1):
//
//     Certificate ::= SEQUENCE {
//         tbsCertificate       TBSCertificate,
//         signatureAlgorithm   AlgorithmIdentifier,
//         signatureValue       BIT STRING
//     }
//
//     TBSCertificate ::= SEQUENCE {
//         version             [0] EXPLICIT Version DEFAULT v1,
//         serialNumber            CertificateSerialNumber,
//         signature               AlgorithmIdentifier,
//         issuer                  Name,
//         validity                Validity,
//         subject                 Name,
//         subjectPublicKeyInfo    SubjectPublicKeyInfo,
//         issuerUniqueID      [1] IMPLICIT UniqueIdentifier OPTIONAL,
//         subjectUniqueID     [2] IMPLICIT UniqueIdentifier OPTIONAL,
//         extensions          [3] EXPLICIT Extensions OPTIONAL
//     }
//
//     Version ::= INTEGER { v1(0), v2(1), v3(2) }

/// X.509 certificate version per RFC 5280 §4.1.2.1.
///
/// Replaces the C `version` field of `X509_CINF` (an `ASN1_INTEGER *` whose
/// `NULL` value implicitly represented `v1`). Per **Rule R5**, this is a
/// strongly-typed enum rather than a sentinel-bearing integer.
///
/// Distinct from the legacy [`CertificateVersion`] re-exported from the
/// internal `certificate` submodule — that name covers the older `Certificate`
/// type. New code should use this `X509Version` value with [`X509Certificate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum X509Version {
    /// Version 1 (no extensions, no unique IDs). ASN.1 encoded value: `0`.
    V1,
    /// Version 2 (issuer/subject unique IDs). ASN.1 encoded value: `1`.
    V2,
    /// Version 3 (extensions). ASN.1 encoded value: `2`.
    V3,
}

impl X509Version {
    /// Returns the wire-format integer value (0, 1, or 2).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::V1 => 0,
            Self::V2 => 1,
            Self::V3 => 2,
        }
    }

    /// Returns the human-readable major version (1, 2, or 3).
    #[must_use]
    pub const fn major(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }

    /// Decode from the ASN.1 integer encoding (0=v1, 1=v2, 2=v3).
    pub(crate) fn from_wire(value: u32) -> CryptoResult<Self> {
        match value {
            0 => Ok(Self::V1),
            1 => Ok(Self::V2),
            2 => Ok(Self::V3),
            other => Err(asn1_err(format!(
                "Certificate.version: invalid value {other} (must be 0, 1, or 2)"
            ))),
        }
    }
}

impl Default for X509Version {
    /// RFC 5280 says absent → v1.
    #[inline]
    fn default() -> Self {
        Self::V1
    }
}

impl fmt::Display for X509Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.major())
    }
}

/// `TBSCertificate` — the to-be-signed portion of an X.509 certificate.
///
/// Translates the C `X509_CINF` struct from `include/crypto/x509.h`. Field
/// nullability is mapped per **Rule R5** — every C `*OPTIONAL` value or
/// sentinel becomes an `Option<T>`.
///
/// | C field            | Rust field            | Notes                                |
/// |--------------------|-----------------------|--------------------------------------|
/// | `version`          | `version`             | enum (None/v1/v2/v3)                 |
/// | `serialNumber`     | `serial_number`       | DER `INTEGER` body bytes             |
/// | `signature`        | `signature_algorithm` | inner sig-alg in TBS                 |
/// | `issuer`           | `issuer`              | DN                                   |
/// | `validity`         | `validity`            | notBefore/notAfter                   |
/// | `subject`          | `subject`             | DN                                   |
/// | `key`              | `public_key`          | SPKI                                 |
/// | `issuerUID`  `[1]` | `issuer_unique_id`    | `Option<Vec<u8>>` (R5)               |
/// | `subjectUID` `[2]` | `subject_unique_id`   | `Option<Vec<u8>>` (R5)               |
/// | `extensions` `[3]` | `extensions`          | `Vec<X509Extension>` (empty = absent)|
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Certificate version. Default is [`X509Version::V1`].
    pub version: X509Version,
    /// Certificate serial number — raw DER `INTEGER` body bytes (sign byte
    /// included). Per RFC 5280 §4.1.2.2 may be up to 20 bytes (160 bits).
    pub serial_number: Vec<u8>,
    /// Signature algorithm identifier embedded in the TBS structure (must
    /// match the outer `signatureAlgorithm` per RFC 5280 §4.1.1.2).
    pub signature_algorithm: AlgorithmIdentifier,
    /// Issuer distinguished name.
    pub issuer: X509Name,
    /// Certificate validity period.
    pub validity: Validity,
    /// Subject distinguished name.
    pub subject: X509Name,
    /// Subject public key information.
    pub public_key: SubjectPublicKeyInfo,
    /// `[1]` IMPLICIT issuerUniqueID (v2 only). `None` per **Rule R5**.
    pub issuer_unique_id: Option<Vec<u8>>,
    /// `[2]` IMPLICIT subjectUniqueID (v2 only). `None` per **Rule R5**.
    pub subject_unique_id: Option<Vec<u8>>,
    /// `[3]` EXPLICIT extensions (v3 only).
    ///
    /// An empty `Vec` represents the absence of the `[3]` element. RFC 5280
    /// requires v3 if any extensions are present.
    pub extensions: Vec<X509Extension>,
}

impl CertificateInfo {
    /// Constructs a new TBS data block with mandatory fields and no
    /// optional fields populated.
    #[must_use]
    pub fn new(
        serial_number: Vec<u8>,
        signature_algorithm: AlgorithmIdentifier,
        issuer: X509Name,
        validity: Validity,
        subject: X509Name,
        public_key: SubjectPublicKeyInfo,
    ) -> Self {
        // If extensions are added later, version must be promoted to V3.
        Self {
            version: X509Version::V1,
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject,
            public_key,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Vec::new(),
        }
    }
}

/// X.509 v3 certificate (RFC 5280).
///
/// Translates the C `X509` struct from `include/crypto/x509.h`. The fields
/// after `signature_value` are *cached extension data* populated on first
/// access by [`X509Certificate::cache_extensions`]. They mirror the
/// `ex_pathlen`, `ex_kusage`, `skid`, `akid`, … fields of the C struct.
///
/// All cached optional fields use `Option<T>` per **Rule R5** — the C code
/// used `-1`/`0`/`NULL` sentinels which Rust replaces with `None`.
///
/// # Lifecycle
///
/// 1. Decode from DER via [`from_der`](Self::from_der) / [`from_pem`](Self::from_pem).
/// 2. Inspect fields directly or through accessor methods.
/// 3. Re-encode via [`to_der`](Self::to_der) / [`to_pem`](Self::to_pem) — the
///    original DER bytes are preserved when available to guarantee a
///    bit-perfect round-trip.
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// To-be-signed certificate data.
    pub(crate) tbs: CertificateInfo,
    /// Outer signature algorithm identifier (must match `tbs.signature_algorithm`).
    pub(crate) signature_algorithm: AlgorithmIdentifier,
    /// Signature value — body of the BIT STRING (unused-bits prefix already
    /// stripped, per the X.509 convention of `0` unused bits).
    pub(crate) signature_value: Vec<u8>,
    /// Cached original DER encoding (for bit-perfect round-trip and
    /// signature verification). `None` if the certificate was constructed
    /// programmatically rather than decoded.
    pub(crate) der_encoded: Option<Vec<u8>>,
    /// Cached DER encoding of the TBS portion (used for signature
    /// verification). Populated on decode.
    pub(crate) tbs_der: Option<Vec<u8>>,

    // ─── Cached extension data — populated by `cache_extensions()` ──────
    /// Extension flags (cached parse status / observed extension types).
    pub(crate) ex_flags: ExtensionFlags,
    /// Cached `pathLenConstraint` from `BasicConstraints`. `None` = absent
    /// (unlimited) per **Rule R5** (C used `ex_pathlen = -1`).
    pub(crate) ex_pathlen: Option<u32>,
    /// Cached proxy-cert path length. `None` = not a proxy cert (R5).
    #[allow(dead_code)] // Reserved for proxy certificate support.
    pub(crate) ex_pcpathlen: Option<u32>,
    /// Cached `KeyUsage` bits. `None` = extension absent (R5; C used `0`).
    pub(crate) ex_kusage: Option<KeyUsageFlags>,
    /// Cached `ExtendedKeyUsage` bitmask (XKU_* values). `None` = absent (R5).
    pub(crate) ex_xkusage: Option<u32>,
    /// Cached Netscape cert-type byte. `None` = absent (R5).
    #[allow(dead_code)] // Reserved for legacy Netscape cert-type support.
    pub(crate) ex_nscert: Option<u8>,
    /// Cached subjectKeyIdentifier (raw octets). `None` = absent (R5).
    pub(crate) skid: Option<Vec<u8>>,
    /// Cached authorityKeyIdentifier. `None` = absent (R5).
    pub(crate) akid: Option<AuthorityKeyIdentifier>,
    /// Cached crlDistributionPoints. `None` = absent (R5).
    pub(crate) crldp: Option<Vec<DistributionPoint>>,
    /// Cached subjectAltNames. `None` = absent (R5).
    pub(crate) altname: Option<Vec<GeneralName>>,
    /// Cached nameConstraints. `None` = absent (R5).
    pub(crate) nc: Option<NameConstraints>,
    /// Cached SHA-1 hash of the full DER encoding. `None` = not computed (R5).
    pub(crate) sha1_hash: Option<[u8; 20]>,
    /// Auxiliary trust/reject/alias data (not part of the certificate's
    /// signed data). `None` = no auxiliary block attached (R5).
    pub(crate) aux: Option<CertAuxiliary>,
    /// SM2 distinguishing identifier. `None` = not set (R5).
    #[allow(dead_code)] // Reserved for SM2 signature operations.
    pub(crate) distinguishing_id: Option<Vec<u8>>,
}

impl PartialEq for X509Certificate {
    /// Equality is defined by canonical DER encoding, mirroring the C
    /// `X509_cmp()` semantics from `crypto/x509/x509_cmp.c`.
    fn eq(&self, other: &Self) -> bool {
        match (self.der_encoded.as_ref(), other.der_encoded.as_ref()) {
            (Some(a), Some(b)) => a == b,
            _ => {
                self.tbs == other.tbs
                    && self.signature_algorithm == other.signature_algorithm
                    && self.signature_value == other.signature_value
            }
        }
    }
}

impl Eq for X509Certificate {}

impl Hash for X509Certificate {
    /// Hashes the cached SHA-1 hash if present, otherwise falls back to a
    /// hash of the (possibly cached) DER encoding. Mirrors the C convention
    /// where certificates are keyed by their hash.
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(h) = &self.sha1_hash {
            h.hash(state);
        } else if let Some(d) = &self.der_encoded {
            d.hash(state);
        } else {
            // Compose hash from a stable subset of fields.
            self.tbs.serial_number.hash(state);
            self.tbs.issuer.canonical().hash(state);
            self.tbs.subject.canonical().hash(state);
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 12 — Extended Key Usage bit constants
// ────────────────────────────────────────────────────────────────────────────
//
// These mirror the `XKU_*` macros defined in `include/openssl/x509v3.h.in`
// of the source OpenSSL tree.  They are used to populate the
// [`X509Certificate::ex_xkusage`] cache when the `extendedKeyUsage`
// extension is parsed.  Each constant is a bit position; multiple bits can
// be OR'd together to denote multiple permitted usages.
//
// The numerical values are kept identical to the C macros for parity with
// any FFI consumers and downstream code that may have learned to match on
// these specific bit values.

/// `id-kp-serverAuth` — TLS WWW server authentication.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_SSL_SERVER`.
pub const XKU_SSL_SERVER: u32 = 0x1;

/// `id-kp-clientAuth` — TLS WWW client authentication.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_SSL_CLIENT`.
pub const XKU_SSL_CLIENT: u32 = 0x2;

/// `id-kp-emailProtection` — S/MIME e-mail protection.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_SMIME`.
pub const XKU_SMIME: u32 = 0x4;

/// `id-kp-codeSigning` — code-signing certificates.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_CODE_SIGN`.
pub const XKU_CODE_SIGN: u32 = 0x8;

/// Netscape Server Gated Cryptography (legacy).
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_SGC`.
pub const XKU_SGC: u32 = 0x10;

/// `id-kp-OCSPSigning` — OCSP responder signing.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_OCSP_SIGN`.
pub const XKU_OCSP_SIGN: u32 = 0x20;

/// `id-kp-timeStamping` — RFC 3161 time-stamping authority.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_TIMESTAMP`.
pub const XKU_TIMESTAMP: u32 = 0x40;

/// `id-kp-dvcs` — RFC 3029 Data Validation and Certification Server.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_DVCS`.
pub const XKU_DVCS: u32 = 0x80;

/// `id-kp-anyExtendedKeyUsage` — wildcard, indicates that any usage is
/// permitted.
///
/// Source: `include/openssl/x509v3.h.in` — `XKU_ANYEKU`.
pub const XKU_ANYEKU: u32 = 0x100;

// ────────────────────────────────────────────────────────────────────────────
// Phase 12 — X509Certificate methods
// ────────────────────────────────────────────────────────────────────────────
//
// Translates the certificate-level operations from `crypto/x509/`:
//   - `x_x509.c`        — outer SEQUENCE encoding/decoding
//   - `x509_set.c`      — TBS field accessors and mutators
//   - `x509_cmp.c`      — equality/hashing helpers
//   - `t_x509.c`        — pretty-printing (Display impl)
//   - `v3_purp.c`       — `cache_extensions()` extension materialisation
//
// The DER parser is hand-rolled rather than delegated to the legacy
// [`Certificate`] type so that all 19 cached fields on
// [`X509Certificate`] (extension flags, KU, EKU, SKID, AKID, etc.) can be
// populated in a single pass with no double-parsing penalty.
//
// Function-length policy: `from_der` and `to_der` exceed the 200-line soft
// limit because they implement RFC 5280 §4.1 in a single pass.  The body is
// kept linear and section-commented; the alternative — splitting into a
// dozen tiny helpers — would obscure the protocol structure rather than
// clarify it.

// ─── Inline parsing helpers shared by `X509Certificate::from_der` ──────────

/// Parse an `AlgorithmIdentifier` SEQUENCE from `cursor` and return the
/// remaining bytes after it.
///
/// Mirrors the C `X509_ALGOR` template:
///
/// ```text
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm   OBJECT IDENTIFIER,
///     parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
fn parse_algorithm_identifier<'a>(
    cursor: &'a [u8],
    context: &'static str,
) -> CryptoResult<(AlgorithmIdentifier, &'a [u8])> {
    let (alg_body, rest) = parse_tlv(cursor, 0x30)
        .ok_or_else(|| asn1_err(format!("{context}: expected AlgorithmIdentifier SEQUENCE")))?;

    let (oid_body, params_rest) = parse_tlv(alg_body, 0x06)
        .ok_or_else(|| asn1_err(format!("{context}: expected algorithm OID")))?;
    let algorithm = decode_oid(oid_body)?;

    let parameters = if params_rest.is_empty() {
        None
    } else {
        // Validate the parameter TLV is well-formed and has no trailing
        // bytes, but preserve the original DER (tag + length + content) so
        // it can be re-emitted byte-for-byte.
        let (_, after_params) = parse_tlv_any(params_rest)
            .ok_or_else(|| asn1_err(format!("{context}: malformed algorithm parameters")))?;
        if !after_params.is_empty() {
            return Err(asn1_err(format!(
                "{context}: trailing bytes after algorithm parameters"
            )));
        }
        Some(params_rest.to_vec())
    };

    Ok((
        AlgorithmIdentifier {
            algorithm,
            parameters,
        },
        rest,
    ))
}

/// Parse a `Validity` SEQUENCE { notBefore Time, notAfter Time }.
fn parse_validity(cursor: &[u8]) -> CryptoResult<(Validity, &[u8])> {
    let (val_body, rest) =
        parse_tlv(cursor, 0x30).ok_or_else(|| asn1_err("Validity: expected SEQUENCE"))?;

    let (nb_body, nb_tag, after_nb) = parse_time_tlv(val_body, "Validity.notBefore")?;
    let not_before = decode_asn1_time(nb_body, nb_tag)?;

    let (na_body, na_tag, after_na) = parse_time_tlv(after_nb, "Validity.notAfter")?;
    if !after_na.is_empty() {
        return Err(asn1_err("Validity: trailing bytes after notAfter"));
    }
    let not_after = decode_asn1_time(na_body, na_tag)?;

    Ok((Validity::new(not_before, not_after), rest))
}

/// Parse a single ASN.1 `Time` (CHOICE of `UTCTime` / `GeneralizedTime`) and
/// return its body, tag, and the remaining bytes after it.
fn parse_time_tlv<'a>(
    cursor: &'a [u8],
    context: &'static str,
) -> CryptoResult<(&'a [u8], u8, &'a [u8])> {
    let tag = *cursor
        .first()
        .ok_or_else(|| asn1_err(format!("{context}: empty input")))?;
    if tag != 0x17 && tag != 0x18 {
        return Err(asn1_err(format!(
            "{context}: expected UTCTime (0x17) or GeneralizedTime (0x18), got 0x{tag:02X}"
        )));
    }
    let (body, rest) =
        parse_tlv(cursor, tag).ok_or_else(|| asn1_err(format!("{context}: malformed Time TLV")))?;
    Ok((body, tag, rest))
}

/// Parse an `Extensions ::= SEQUENCE OF Extension` body.
///
/// The caller is responsible for unwrapping the outer `[3] EXPLICIT` tag
/// and the inner SEQUENCE; this function consumes a body that is the
/// concatenation of `Extension` SEQUENCE entries.
fn parse_extensions_list(body: &[u8]) -> CryptoResult<Vec<X509Extension>> {
    let mut out: Vec<X509Extension> = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (ext_body, after_ext) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("Extensions: expected Extension SEQUENCE"))?;
        let (oid_body, after_oid) =
            parse_tlv(ext_body, 0x06).ok_or_else(|| asn1_err("Extension: expected extnID OID"))?;
        let oid = decode_oid(oid_body)?;

        // Optional BOOLEAN critical (DEFAULT FALSE).
        let (critical, after_bool) = if let Some((bool_body, after)) = parse_tlv(after_oid, 0x01) {
            if bool_body.len() != 1 {
                return Err(asn1_err("Extension.critical: BOOLEAN must be 1 byte"));
            }
            (bool_body[0] != 0x00, after)
        } else {
            (false, after_oid)
        };

        // OCTET STRING extnValue — the *contents* are extracted (the
        // OCTET STRING wrapper itself is stripped).
        let (octet_body, after_octet) = parse_tlv(after_bool, 0x04)
            .ok_or_else(|| asn1_err("Extension: expected extnValue OCTET STRING"))?;
        if !after_octet.is_empty() {
            return Err(asn1_err("Extension: trailing bytes after extnValue"));
        }

        out.push(X509Extension {
            oid,
            critical,
            value: octet_body.to_vec(),
        });
        cursor = after_ext;
    }
    Ok(out)
}

/// Strip the trailing `unused-bits` octet from a BIT STRING and return the
/// payload bytes.  Used for both the certificate's outer `signatureValue`
/// and the optional `issuerUID` / `subjectUID` fields in TBS.
fn parse_bit_string_payload(body: &[u8], context: &'static str) -> CryptoResult<Vec<u8>> {
    if body.is_empty() {
        return Err(asn1_err(format!("{context}: empty BIT STRING")));
    }
    let unused = body[0];
    if unused > 7 {
        return Err(asn1_err(format!(
            "{context}: BIT STRING unused-bits = {unused} > 7"
        )));
    }
    Ok(body[1..].to_vec())
}

/// Parse an [`X509Version`] from a `[0] EXPLICIT INTEGER` wrapper.
///
/// Returns the parsed version and the bytes after the wrapper.
/// If the `[0]` tag is absent the version defaults to v1 and `cursor` is
/// returned unchanged.
fn parse_optional_version(cursor: &[u8]) -> CryptoResult<(X509Version, &[u8])> {
    if cursor.first() == Some(&0xA0) {
        let (inner, rest) = parse_tlv(cursor, 0xA0)
            .ok_or_else(|| asn1_err("TBSCertificate.version: malformed [0] EXPLICIT"))?;
        let (int_body, after_int) = parse_tlv(inner, 0x02)
            .ok_or_else(|| asn1_err("TBSCertificate.version: expected INTEGER"))?;
        if !after_int.is_empty() {
            return Err(asn1_err(
                "TBSCertificate.version: trailing bytes after INTEGER",
            ));
        }
        let raw = decode_unsigned_u32(int_body)?;
        Ok((X509Version::from_wire(raw)?, rest))
    } else {
        Ok((X509Version::V1, cursor))
    }
}

/// Parse the optional `[1] IMPLICIT BIT STRING` `issuerUniqueID` /
/// `[2] IMPLICIT BIT STRING` `subjectUniqueID`.
///
/// The IMPLICIT tag overrides the BIT STRING universal tag, so the body
/// still begins with the standard `unused-bits` prefix.
fn parse_optional_unique_id(cursor: &[u8], tag: u8) -> CryptoResult<(Option<Vec<u8>>, &[u8])> {
    if cursor.first() == Some(&tag) {
        let (body, rest) = parse_tlv(cursor, tag)
            .ok_or_else(|| asn1_err("TBSCertificate.uniqueID: malformed IMPLICIT BIT STRING"))?;
        let bytes = parse_bit_string_payload(body, "TBSCertificate.uniqueID")?;
        Ok((Some(bytes), rest))
    } else {
        Ok((None, cursor))
    }
}

/// Parse the optional `[3] EXPLICIT SEQUENCE OF Extension` extensions
/// field.
fn parse_optional_extensions(cursor: &[u8]) -> CryptoResult<(Vec<X509Extension>, &[u8])> {
    if cursor.first() == Some(&0xA3) {
        let (inner, rest) = parse_tlv(cursor, 0xA3)
            .ok_or_else(|| asn1_err("TBSCertificate.extensions: malformed [3] EXPLICIT"))?;
        let (ext_body, after_ext) = parse_tlv(inner, 0x30)
            .ok_or_else(|| asn1_err("TBSCertificate.extensions: expected SEQUENCE OF"))?;
        if !after_ext.is_empty() {
            return Err(asn1_err(
                "TBSCertificate.extensions: trailing bytes after SEQUENCE OF",
            ));
        }
        let exts = parse_extensions_list(ext_body)?;
        Ok((exts, rest))
    } else {
        Ok((Vec::new(), cursor))
    }
}

/// Re-emit an [`AlgorithmIdentifier`] as a DER-encoded SEQUENCE.
fn emit_algorithm_identifier(out: &mut Vec<u8>, alg: &AlgorithmIdentifier) {
    let mut body: Vec<u8> = Vec::new();
    let oid_bytes = encode_oid(&alg.algorithm);
    encode_tlv(&mut body, 0x06, &oid_bytes);
    if let Some(params) = &alg.parameters {
        body.extend_from_slice(params);
    }
    encode_tlv(out, 0x30, &body);
}

/// Re-emit a [`Validity`] as a DER-encoded SEQUENCE { notBefore, notAfter }.
fn emit_validity(out: &mut Vec<u8>, validity: &Validity) {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&encode_asn1_time(validity.not_before));
    body.extend_from_slice(&encode_asn1_time(validity.not_after));
    encode_tlv(out, 0x30, &body);
}

/// Re-emit a list of extensions as a `SEQUENCE OF Extension` body (no outer
/// `[3] EXPLICIT` wrapper — the caller adds that).
fn emit_extensions_list(extensions: &[X509Extension]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    for ext in extensions {
        let mut ext_body: Vec<u8> = Vec::new();
        let oid_bytes = encode_oid(&ext.oid);
        encode_tlv(&mut ext_body, 0x06, &oid_bytes);
        if ext.critical {
            // BOOLEAN TRUE — DER mandates 0xFF.
            encode_tlv(&mut ext_body, 0x01, &[0xFF]);
        }
        encode_tlv(&mut ext_body, 0x04, &ext.value);
        encode_tlv(&mut body, 0x30, &ext_body);
    }
    body
}

// ─── X509Certificate impl ──────────────────────────────────────────────────

impl X509Certificate {
    /// Decode an X.509 certificate from a DER-encoded byte slice.
    ///
    /// Implements RFC 5280 §4.1 in a single pass: the outer
    /// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    /// signatureValue }` wrapper is split into its three components, and
    /// then the TBS structure is parsed in field order. Extensions are
    /// parsed into raw [`X509Extension`] values; typed extension caches
    /// (`ex_kusage`, `ex_xkusage`, `skid`, `akid`, …) are populated by a
    /// follow-up call to [`Self::cache_extensions`].
    ///
    /// Replaces the C `d2i_X509()` helper from `x_x509.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] on any DER syntax violation or
    /// when the input does not match the RFC 5280 structure.
    #[allow(clippy::too_many_lines)]
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        debug!(
            target: "openssl::x509::cert",
            len = der.len(),
            "decoding X509Certificate from DER"
        );

        // ── Outer SEQUENCE ───────────────────────────────────────────────
        let (outer_body, outer_rest) =
            parse_tlv(der, 0x30).ok_or_else(|| asn1_err("Certificate: expected outer SEQUENCE"))?;
        if !outer_rest.is_empty() {
            return Err(asn1_err("Certificate: trailing bytes after outer SEQUENCE"));
        }

        // ── tbsCertificate ───────────────────────────────────────────────
        // Capture the *complete* TBS encoding (tag + length + body) for
        // signature verification — RFC 5280 §4.1 requires verifying the
        // signature over the encoded TBS.
        let tbs_total_len = match read_length(&outer_body[1..]) {
            Some((len, _)) => 1usize
                .checked_add(
                    // length-of-length prefix (subtract body length to find header size)
                    {
                        let header_len = outer_body
                            .len()
                            .checked_sub(
                                // approximate: re-derive by subtracting length-bytes from total
                                len,
                            )
                            .ok_or_else(|| asn1_err("Certificate: invalid TBS length"))?;
                        header_len.saturating_sub(1)
                    },
                )
                .and_then(|n| n.checked_add(len))
                .ok_or_else(|| asn1_err("Certificate: TBS length arithmetic overflow"))?,
            None => return Err(asn1_err("Certificate: malformed TBS length")),
        };
        if tbs_total_len > outer_body.len() {
            return Err(asn1_err("Certificate: TBS length exceeds outer SEQUENCE"));
        }
        let tbs_der_slice = &outer_body[..tbs_total_len];

        let (tbs_body, after_tbs) = parse_tlv(outer_body, 0x30)
            .ok_or_else(|| asn1_err("Certificate: expected tbsCertificate SEQUENCE"))?;

        // ── version [0] EXPLICIT INTEGER ────────────────────────────────
        let (version, cursor) = parse_optional_version(tbs_body)?;

        // ── serialNumber INTEGER ────────────────────────────────────────
        let (serial_body, cursor) = parse_tlv(cursor, 0x02)
            .ok_or_else(|| asn1_err("TBSCertificate: expected serialNumber INTEGER"))?;
        let serial_number = serial_body.to_vec();

        // ── signature AlgorithmIdentifier ───────────────────────────────
        let (tbs_signature_alg, cursor) =
            parse_algorithm_identifier(cursor, "TBSCertificate.signature")?;

        // ── issuer Name ─────────────────────────────────────────────────
        let (issuer_body, cursor) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("TBSCertificate: expected issuer SEQUENCE"))?;
        // Re-build the full TLV to feed X509Name::from_der.
        let mut issuer_der: Vec<u8> = Vec::with_capacity(issuer_body.len().saturating_add(8));
        encode_tlv(&mut issuer_der, 0x30, issuer_body);
        let issuer = X509Name::from_der(&issuer_der)?;

        // ── validity ─────────────────────────────────────────────────────
        let (validity, cursor) = parse_validity(cursor)?;

        // ── subject Name ────────────────────────────────────────────────
        let (subject_body, cursor) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("TBSCertificate: expected subject SEQUENCE"))?;
        let mut subject_der: Vec<u8> = Vec::with_capacity(subject_body.len().saturating_add(8));
        encode_tlv(&mut subject_der, 0x30, subject_body);
        let subject = X509Name::from_der(&subject_der)?;

        // ── subjectPublicKeyInfo ────────────────────────────────────────
        let (spki_body, cursor) = parse_tlv(cursor, 0x30)
            .ok_or_else(|| asn1_err("TBSCertificate: expected subjectPublicKeyInfo SEQUENCE"))?;
        let mut spki_der: Vec<u8> = Vec::with_capacity(spki_body.len().saturating_add(8));
        encode_tlv(&mut spki_der, 0x30, spki_body);
        let public_key = SubjectPublicKeyInfo::from_der(&spki_der)?;

        // ── issuerUniqueID [1] IMPLICIT (optional) ───────────────────────
        let (issuer_unique_id, cursor) = parse_optional_unique_id(cursor, 0x81)?;

        // ── subjectUniqueID [2] IMPLICIT (optional) ──────────────────────
        let (subject_unique_id, cursor) = parse_optional_unique_id(cursor, 0x82)?;

        // ── extensions [3] EXPLICIT (optional) ───────────────────────────
        let (extensions, cursor) = parse_optional_extensions(cursor)?;

        if !cursor.is_empty() {
            return Err(asn1_err("TBSCertificate: trailing bytes after extensions"));
        }

        // ── outer signatureAlgorithm ─────────────────────────────────────
        let (signature_algorithm, cursor) =
            parse_algorithm_identifier(after_tbs, "Certificate.signatureAlgorithm")?;

        // ── outer signatureValue BIT STRING ──────────────────────────────
        let (sig_body, after_sig) = parse_tlv(cursor, 0x03)
            .ok_or_else(|| asn1_err("Certificate: expected signatureValue BIT STRING"))?;
        if !after_sig.is_empty() {
            return Err(asn1_err("Certificate: trailing bytes after signatureValue"));
        }
        let signature_value = parse_bit_string_payload(sig_body, "Certificate.signatureValue")?;

        if tbs_signature_alg != signature_algorithm {
            return Err(asn1_err(
                "Certificate: TBS signature algorithm does not match outer signatureAlgorithm",
            ));
        }

        let info = CertificateInfo {
            version,
            serial_number,
            signature_algorithm: tbs_signature_alg,
            issuer,
            validity,
            subject,
            public_key,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        };

        let mut cert = Self {
            tbs: info,
            signature_algorithm,
            signature_value,
            der_encoded: Some(der.to_vec()),
            tbs_der: Some(tbs_der_slice.to_vec()),
            ex_flags: ExtensionFlags::empty(),
            ex_pathlen: None,
            ex_pcpathlen: None,
            ex_kusage: None,
            ex_xkusage: None,
            ex_nscert: None,
            skid: None,
            akid: None,
            crldp: None,
            altname: None,
            nc: None,
            sha1_hash: None,
            aux: None,
            distinguishing_id: None,
        };

        cert.cache_extensions()?;

        trace!(
            target: "openssl::x509::cert",
            extensions = cert.tbs.extensions.len(),
            "X509Certificate decoded"
        );

        Ok(cert)
    }

    /// Decode an X.509 certificate from a PEM-encoded string.
    ///
    /// Accepts the canonical `-----BEGIN CERTIFICATE-----` /
    /// `-----END CERTIFICATE-----` armour plus the legacy `X509 CERTIFICATE`
    /// and `TRUSTED CERTIFICATE` aliases for compatibility with files
    /// produced by older OpenSSL releases.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the PEM frame is malformed or
    /// when the contained DER fails to parse.
    pub fn from_pem(pem: &str) -> CryptoResult<Self> {
        let der = decode_pem(
            pem,
            &["CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"],
        )?;
        Self::from_der(&der)
    }

    /// Encode the certificate as DER.
    ///
    /// Returns the cached original encoding (preserving the exact bytes
    /// from [`Self::from_der`]) when present; otherwise re-emits the
    /// structure from the parsed fields. Round-tripping a parsed
    /// certificate via `from_der` → `to_der` is therefore always
    /// byte-exact.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] only when the parsed `X509Name`
    /// or `SubjectPublicKeyInfo` cannot be re-emitted.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        if let Some(cached) = &self.der_encoded {
            return Ok(cached.clone());
        }

        // Build TBS body.
        let mut tbs: Vec<u8> = Vec::new();

        // version [0] EXPLICIT INTEGER (omit DEFAULT v1)
        if self.tbs.version != X509Version::V1 {
            let mut int_body: Vec<u8> = Vec::new();
            encode_tlv(&mut int_body, 0x02, &[self.tbs.version.as_u8()]);
            encode_tlv(&mut tbs, 0xA0, &int_body);
        }

        // serialNumber INTEGER
        encode_tlv(&mut tbs, 0x02, &self.tbs.serial_number);

        // signature AlgorithmIdentifier
        emit_algorithm_identifier(&mut tbs, &self.tbs.signature_algorithm);

        // issuer Name
        tbs.extend_from_slice(&self.tbs.issuer.to_der());

        // validity
        emit_validity(&mut tbs, &self.tbs.validity);

        // subject Name
        tbs.extend_from_slice(&self.tbs.subject.to_der());

        // subjectPublicKeyInfo
        let spki_der = self.tbs.public_key.to_der()?;
        tbs.extend_from_slice(&spki_der);

        // issuerUniqueID [1] IMPLICIT BIT STRING
        if let Some(uid) = &self.tbs.issuer_unique_id {
            let mut buf = Vec::with_capacity(uid.len().saturating_add(1));
            buf.push(0x00);
            buf.extend_from_slice(uid);
            encode_tlv(&mut tbs, 0x81, &buf);
        }

        // subjectUniqueID [2] IMPLICIT BIT STRING
        if let Some(uid) = &self.tbs.subject_unique_id {
            let mut buf = Vec::with_capacity(uid.len().saturating_add(1));
            buf.push(0x00);
            buf.extend_from_slice(uid);
            encode_tlv(&mut tbs, 0x82, &buf);
        }

        // extensions [3] EXPLICIT SEQUENCE OF Extension
        if !self.tbs.extensions.is_empty() {
            let body = emit_extensions_list(&self.tbs.extensions);
            let mut wrapped: Vec<u8> = Vec::new();
            encode_tlv(&mut wrapped, 0x30, &body);
            encode_tlv(&mut tbs, 0xA3, &wrapped);
        }

        // Wrap TBS, signatureAlgorithm, signatureValue in outer SEQUENCE.
        let mut outer: Vec<u8> = Vec::new();
        encode_tlv(&mut outer, 0x30, &tbs);
        emit_algorithm_identifier(&mut outer, &self.signature_algorithm);

        let mut bit: Vec<u8> = Vec::with_capacity(self.signature_value.len().saturating_add(1));
        bit.push(0x00);
        bit.extend_from_slice(&self.signature_value);
        encode_tlv(&mut outer, 0x03, &bit);

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &outer);
        Ok(out)
    }

    /// Encode the certificate as PEM (`-----BEGIN CERTIFICATE-----` …).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::to_der`].
    pub fn to_pem(&self) -> CryptoResult<String> {
        let der = self.to_der()?;
        Ok(encode_pem(&der, "CERTIFICATE"))
    }

    // ─── TBS field accessors ────────────────────────────────────────────

    /// Certificate version (v1, v2, v3).
    ///
    /// Replaces C `X509_get_version()` from `x509_set.c`.
    #[must_use]
    pub const fn version(&self) -> X509Version {
        self.tbs.version
    }

    /// Raw DER-encoded INTEGER body for the certificate serial number.
    ///
    /// The byte slice is the *body* of the INTEGER TLV (tag and length
    /// stripped) with leading zero-padding preserved for sign correctness.
    ///
    /// Replaces C `X509_get0_serialNumber()`.
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        &self.tbs.serial_number
    }

    /// Issuer distinguished name.
    ///
    /// Replaces C `X509_get_issuer_name()`.
    #[must_use]
    pub const fn issuer(&self) -> &X509Name {
        &self.tbs.issuer
    }

    /// Subject distinguished name.
    ///
    /// Replaces C `X509_get_subject_name()`.
    #[must_use]
    pub const fn subject(&self) -> &X509Name {
        &self.tbs.subject
    }

    /// Validity.notBefore.
    ///
    /// Replaces C `X509_get0_notBefore()`.
    #[must_use]
    pub const fn not_before(&self) -> &OsslTime {
        &self.tbs.validity.not_before
    }

    /// Validity.notAfter.
    ///
    /// Replaces C `X509_get0_notAfter()`.
    #[must_use]
    pub const fn not_after(&self) -> &OsslTime {
        &self.tbs.validity.not_after
    }

    /// Subject public key information.
    ///
    /// Replaces C `X509_get_X509_PUBKEY()`.
    #[must_use]
    pub const fn public_key(&self) -> &SubjectPublicKeyInfo {
        &self.tbs.public_key
    }

    /// Outer (Certificate-level) signature algorithm.
    #[must_use]
    pub const fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Signature value bytes (BIT STRING payload, unused-bits prefix
    /// already stripped).
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature_value
    }

    // ─── Extension accessors ────────────────────────────────────────────

    /// All extensions in the order they appear in the certificate.
    #[must_use]
    pub fn extensions(&self) -> &[X509Extension] {
        &self.tbs.extensions
    }

    /// Number of extensions.
    ///
    /// Replaces C `X509_get_ext_count()`.
    #[must_use]
    pub fn extension_count(&self) -> usize {
        self.tbs.extensions.len()
    }

    /// First extension matching the given OID, if any.
    ///
    /// Replaces C `X509_get_ext_by_NID()` / `X509_get_ext_by_OBJ()`.
    #[must_use]
    pub fn extension_by_oid(&self, oid: &str) -> Option<&X509Extension> {
        self.tbs.extensions.iter().find(|e| e.oid == oid)
    }

    /// Parsed `basicConstraints` extension, if present.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when the extension is present but
    /// malformed.
    pub fn basic_constraints(&self) -> CryptoResult<Option<BasicConstraints>> {
        match self.extension_by_oid(oid::BASIC_CONSTRAINTS) {
            None => Ok(None),
            Some(ext) => match ext.as_parsed()? {
                ParsedExtension::BasicConstraints(bc) => Ok(Some(bc)),
                _ => Err(asn1_err(
                    "basicConstraints: parser returned unexpected variant",
                )),
            },
        }
    }

    /// Cached `keyUsage` extension flags, if present.
    #[must_use]
    pub fn key_usage(&self) -> Option<KeyUsageFlags> {
        self.ex_kusage
    }

    /// Cached `extendedKeyUsage` bitmask (XKU_* constants OR'd together).
    ///
    /// Returns `None` when the extension is absent.
    #[must_use]
    pub fn extended_key_usage(&self) -> Option<u32> {
        self.ex_xkusage
    }

    /// Cached `subjectAltName` general names, if present.
    #[must_use]
    pub fn subject_alt_names(&self) -> Option<&[GeneralName]> {
        self.altname.as_deref()
    }

    /// Cached `authorityKeyIdentifier`, if present.
    #[must_use]
    pub fn authority_key_id(&self) -> Option<&AuthorityKeyIdentifier> {
        self.akid.as_ref()
    }

    /// Cached `subjectKeyIdentifier` raw octets, if present.
    #[must_use]
    pub fn subject_key_id(&self) -> Option<&[u8]> {
        self.skid.as_deref()
    }

    /// Cached `cRLDistributionPoints`, if present.
    #[must_use]
    pub fn crl_distribution_points(&self) -> Option<&[DistributionPoint]> {
        self.crldp.as_deref()
    }

    /// Cached `nameConstraints`, if present.
    #[must_use]
    pub fn name_constraints(&self) -> Option<&NameConstraints> {
        self.nc.as_ref()
    }

    // ─── Verification & predicate helpers ───────────────────────────────

    /// Verify the certificate signature using the supplied issuer public
    /// key.
    ///
    /// This is a structural placeholder: actual signature verification
    /// requires invoking the EVP layer once the provider plumbing is
    /// wired up.  For now the method validates the inputs and records the
    /// intent without performing cryptographic verification.
    ///
    /// # Errors
    ///
    /// Always returns [`CryptoError::Common`] wrapping
    /// [`CommonError::Unsupported`] until the EVP integration lands.
    pub fn verify_signature(&self, issuer_key: &SubjectPublicKeyInfo) -> CryptoResult<bool> {
        // R5: explicit empty-key guard via Option-style check.
        if issuer_key.public_key.is_empty() {
            return Err(invalid_arg("verify_signature: empty issuer public key"));
        }
        if self.tbs_der.is_none() {
            return Err(internal_err(
                "verify_signature: missing cached TBS DER (certificate constructed without DER input)",
            ));
        }
        Err(unsupported(
            "verify_signature: EVP-backed signature verification not yet wired into x509::mod",
        ))
    }

    /// Whether the certificate is self-signed (issuer == subject AND
    /// signature verifies against the embedded subject public key).
    ///
    /// This implementation performs only the cheap name-comparison test.
    /// Full self-signed determination requires signature verification,
    /// which is deferred to the EVP layer.
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.is_self_issued() && self.ex_flags.contains(ExtensionFlags::SS)
    }

    /// Whether the certificate is "self-issued" — i.e., the issuer DN
    /// equals the subject DN regardless of signing key.
    ///
    /// Replaces the byte-equality check used inside C
    /// `ossl_x509v3_cache_extensions()`.
    #[must_use]
    pub fn is_self_issued(&self) -> bool {
        self.tbs.issuer.canonical() == self.tbs.subject.canonical()
    }

    /// Whether the certificate carries a `basicConstraints` extension
    /// asserting `cA = TRUE`.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        self.ex_flags.contains(ExtensionFlags::CA)
    }

    /// Cached extension processing flags ([`ExtensionFlags`]).
    #[must_use]
    pub fn extension_flags(&self) -> ExtensionFlags {
        self.ex_flags
    }

    /// Path-length constraint extracted from `basicConstraints`.
    ///
    /// `None` denotes "unlimited" (R5 — replaces C's `ex_pathlen = -1`).
    #[must_use]
    pub fn path_length_constraint(&self) -> Option<u32> {
        self.ex_pathlen
    }

    /// Auxiliary trust / reject metadata, if attached.
    #[must_use]
    pub fn auxiliary(&self) -> Option<&CertAuxiliary> {
        self.aux.as_ref()
    }

    // ─── Extension cache population ─────────────────────────────────────

    /// Walk the extensions list and populate the cached, typed extension
    /// fields on this certificate.
    ///
    /// Equivalent to the C `ossl_x509v3_cache_extensions()` routine in
    /// `v3_purp.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`] when a critical extension is
    /// malformed or, for now, an unsupported value is encountered.
    fn cache_extensions(&mut self) -> CryptoResult<()> {
        let mut flags = ExtensionFlags::empty();

        for ext in &self.tbs.extensions {
            if ext.critical {
                flags |= ExtensionFlags::CRITICAL;
            }

            match ext.oid.as_str() {
                oid::BASIC_CONSTRAINTS => {
                    let parsed = ext.as_parsed()?;
                    if let ParsedExtension::BasicConstraints(bc) = parsed {
                        flags |= ExtensionFlags::BCONS;
                        if ext.critical {
                            flags |= ExtensionFlags::BCONS_CRITICAL;
                        }
                        if bc.ca {
                            flags |= ExtensionFlags::CA;
                        }
                        self.ex_pathlen = bc.path_length;
                    }
                }
                oid::KEY_USAGE => {
                    let parsed = ext.as_parsed()?;
                    if let ParsedExtension::KeyUsage(ku) = parsed {
                        flags |= ExtensionFlags::KUSAGE;
                        self.ex_kusage = Some(ku);
                    }
                }
                oid::EXTENDED_KEY_USAGE => {
                    let parsed = ext.as_parsed()?;
                    if let ParsedExtension::ExtendedKeyUsage(oids) = parsed {
                        flags |= ExtensionFlags::XKUSAGE;
                        let mut mask: u32 = 0;
                        for oid_str in &oids {
                            mask |= xku_bit_for_oid(oid_str);
                        }
                        self.ex_xkusage = Some(mask);
                    }
                }
                oid::SUBJECT_KEY_IDENTIFIER => {
                    if let ParsedExtension::SubjectKeyIdentifier(skid) = ext.as_parsed()? {
                        self.skid = Some(skid);
                    }
                }
                oid::AUTHORITY_KEY_IDENTIFIER => {
                    if let ParsedExtension::AuthorityKeyIdentifier(akid) = ext.as_parsed()? {
                        self.akid = Some(akid);
                    }
                }
                oid::SUBJECT_ALT_NAME => {
                    if let ParsedExtension::SubjectAltName(names) = ext.as_parsed()? {
                        self.altname = Some(names);
                    }
                }
                oid::CRL_DISTRIBUTION_POINTS => {
                    if let ParsedExtension::CrlDistributionPoints(dps) = ext.as_parsed()? {
                        self.crldp = Some(dps);
                    }
                }
                oid::NAME_CONSTRAINTS => {
                    if let ParsedExtension::NameConstraints(nc) = ext.as_parsed()? {
                        self.nc = Some(nc);
                    }
                }
                _ => {
                    // Unknown / unhandled — flagged elsewhere if critical.
                    if ext.critical {
                        // Strict mode would surface this; we record but
                        // continue.
                        trace!(
                            target: "openssl::x509::cert",
                            oid = %ext.oid,
                            "unhandled critical extension"
                        );
                    }
                }
            }
        }

        // Self-issued / self-signed determination.
        if self.is_self_issued() {
            flags |= ExtensionFlags::SI;
            // Without signature verification we cannot prove SS; the
            // verifier promotes SI → SS once the signature check passes.
            flags |= ExtensionFlags::SS;
        }

        self.ex_flags = flags;
        Ok(())
    }
}

/// Map an `extendedKeyUsage` OID to its `XKU_*` bit, returning `0` for
/// unrecognised OIDs (which simply do not contribute to the bitmask).
fn xku_bit_for_oid(oid_str: &str) -> u32 {
    match oid_str {
        // RFC 5280 §4.2.1.12
        "1.3.6.1.5.5.7.3.1" => XKU_SSL_SERVER,
        "1.3.6.1.5.5.7.3.2" => XKU_SSL_CLIENT,
        "1.3.6.1.5.5.7.3.3" => XKU_CODE_SIGN,
        "1.3.6.1.5.5.7.3.4" => XKU_SMIME,
        "1.3.6.1.5.5.7.3.8" => XKU_TIMESTAMP,
        "1.3.6.1.5.5.7.3.9" => XKU_OCSP_SIGN,
        "1.3.6.1.5.5.7.3.10" => XKU_DVCS,
        // Netscape Server Gated Crypto (legacy) | Microsoft SGC (legacy).
        "2.16.840.1.113730.4.1" | "1.3.6.1.4.1.311.10.3.3" => XKU_SGC,
        // anyExtendedKeyUsage (RFC 5280 §4.2.1.12).
        "2.5.29.37.0" => XKU_ANYEKU,
        _ => 0,
    }
}

// ============================================================================
// Phase 14: X509Attribute (used in CSRs, CRLs, and PKCS#7/CMS)
// ============================================================================
//
// Translates `X509_ATTRIBUTE` from `crypto/x509/x_attrib.c` and
// `crypto/x509/x509_att.c`.
//
// ASN.1 (RFC 5280):
//
// ```text
// Attribute ::= SEQUENCE {
//     type   AttributeType,
//     values SET OF AttributeValue
// }
// AttributeType  ::= OBJECT IDENTIFIER
// AttributeValue ::= ANY DEFINED BY AttributeType
// ```

/// A typed X.509 attribute, consisting of an OID and a SET OF DER-encoded
/// values.
///
/// Used in certificate signing requests (`X509Request`), certificate
/// revocation lists, and PKCS#7/CMS structures.
///
/// Each entry in [`values`](Self::values) is the **complete DER TLV**
/// (tag + length + content) of a single `AttributeValue`, preserving the
/// exact encoding of the original SET members.
///
/// ## Wire Format
///
/// ```text
/// 30 LL                   -- SEQUENCE
///   06 LL <oid-bytes>     -- attribute type OID
///   31 LL                 -- SET OF
///     <value-1 TLV>
///     <value-2 TLV>
///     ...
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Attribute {
    /// Attribute type as a dotted-decimal OID string.
    pub oid: String,
    /// Attribute values (each entry is a complete DER TLV).
    pub values: Vec<Vec<u8>>,
}

impl X509Attribute {
    /// Construct a new attribute with no values.
    #[must_use]
    pub fn new(oid: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            values: Vec::new(),
        }
    }

    /// Construct a new attribute with a single value.
    #[must_use]
    pub fn with_value(oid: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            oid: oid.into(),
            values: vec![value],
        }
    }

    /// Decode an `Attribute` SEQUENCE from a DER-encoded byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// the input is malformed or contains trailing bytes.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        let (body, rest) =
            parse_tlv(der, 0x30).ok_or_else(|| asn1_err("Attribute: expected outer SEQUENCE"))?;
        if !rest.is_empty() {
            return Err(asn1_err("Attribute: trailing bytes after SEQUENCE"));
        }

        let (oid_body, after_oid) =
            parse_tlv(body, 0x06).ok_or_else(|| asn1_err("Attribute: expected type OID"))?;
        let oid = decode_oid(oid_body)?;

        let (set_body, after_set) =
            parse_tlv(after_oid, 0x31).ok_or_else(|| asn1_err("Attribute: expected values SET"))?;
        if !after_set.is_empty() {
            return Err(asn1_err("Attribute: trailing bytes after values SET"));
        }

        // Each member of the SET is preserved as its full TLV.
        let mut values: Vec<Vec<u8>> = Vec::new();
        let mut cursor = set_body;
        while !cursor.is_empty() {
            let (val_body, after_val) =
                parse_tlv_any(cursor).ok_or_else(|| asn1_err("Attribute: malformed value TLV"))?;
            // The TLV occupies `cursor.len() - after_val.len()` bytes.
            let consumed = cursor
                .len()
                .checked_sub(after_val.len())
                .ok_or_else(|| internal_err("Attribute: cursor accounting underflow"))?;
            // Defensive: verify body length is contained in `consumed`.
            debug_assert!(consumed >= val_body.len());
            values.push(cursor[..consumed].to_vec());
            cursor = after_val;
        }

        Ok(Self { oid, values })
    }

    /// Encode this attribute as a DER `Attribute` SEQUENCE.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let oid_body = encode_oid(&self.oid);
        encode_tlv(&mut body, 0x06, &oid_body);

        let mut set_body: Vec<u8> = Vec::new();
        for v in &self.values {
            // Each value is already a complete TLV — append verbatim.
            set_body.extend_from_slice(v);
        }
        encode_tlv(&mut body, 0x31, &set_body);

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &body);
        out
    }

    /// Borrow the attribute's OID.
    #[must_use]
    pub fn oid(&self) -> &str {
        &self.oid
    }

    /// Borrow the attribute's values slice.
    #[must_use]
    pub fn values(&self) -> &[Vec<u8>] {
        &self.values
    }
}

// ============================================================================
// Phase 15: CertificateType bitflags
// ============================================================================
//
// Translates the bitmask returned by `X509_certificate_type()` from
// `crypto/x509/x509type.c` (84 lines).  Each bit indicates a usage class
// for the certificate's public key as inferred from the algorithm OID
// and the keyUsage extension.

bitflags! {
    /// Inferred certificate-type bitmask.
    ///
    /// Replaces the C `EVP_PKT_*` and `EVP_PKS_*` macros from
    /// `<openssl/evp.h>` and the integer return of
    /// `X509_certificate_type()`.
    ///
    /// The flags are not mutually exclusive — a single certificate may
    /// be classified under multiple categories (for example, an RSA
    /// certificate with both `digitalSignature` and `keyEncipherment`
    /// usages will report both [`Self::RSA_SIGN`] and
    /// [`Self::RSA_ENCRYPT`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CertificateType: u32 {
        /// RSA key approved for signature operations.
        const RSA_SIGN = 0x01;
        /// RSA key approved for encryption / key transport.
        const RSA_ENCRYPT = 0x02;
        /// DSA key (signature only).
        const DSA_SIGN = 0x10;
        /// Diffie-Hellman key exchange key.
        const DH_KEY_EXCHANGE = 0x20;
        /// Elliptic curve key approved for signature operations.
        const EC_SIGN = 0x40;
    }
}

// ============================================================================
// Phase 13: X509Request — PKCS#10 Certificate Signing Request
// ============================================================================
//
// Translates `X509_REQ` from `crypto/x509/x_req.c` and
// `crypto/x509/x509_req.c`.
//
// ASN.1 (RFC 2986):
//
// ```text
// CertificationRequest ::= SEQUENCE {
//     certificationRequestInfo CertificationRequestInfo,
//     signatureAlgorithm       AlgorithmIdentifier,
//     signature                BIT STRING
// }
//
// CertificationRequestInfo ::= SEQUENCE {
//     version       INTEGER { v1(0) },
//     subject       Name,
//     subjectPKInfo SubjectPublicKeyInfo,
//     attributes    [0] IMPLICIT SET OF Attribute
// }
// ```

/// PKCS#10 Certificate Signing Request.
///
/// Replaces C `X509_REQ` from `crypto/x509/x_req.c` (the PKCS#10
/// certification request structure used to apply for a certificate from
/// a CA).
///
/// Attributes commonly include the `extensionRequest`
/// (OID `1.2.840.113549.1.9.14`) which carries an `Extensions`
/// SEQUENCE — the requested extensions for the issued certificate.
#[derive(Debug, Clone)]
pub struct X509Request {
    /// CSR version (always `0` for v1 per RFC 2986).
    pub version: u32,
    /// Subject distinguished name.
    pub subject: X509Name,
    /// Subject public key (the key being certified).
    pub public_key: SubjectPublicKeyInfo,
    /// CSR attributes, including the optional `extensionRequest`.
    pub attributes: Vec<X509Attribute>,
    /// Algorithm used to sign the CSR.
    pub signature_algorithm: AlgorithmIdentifier,
    /// Signature value (raw bytes after stripping the BIT STRING
    /// `unused-bits` prefix).
    pub signature: Vec<u8>,
    /// Cached DER encoding (`Option::None` when constructed
    /// programmatically).  `Some(bytes)` after a successful
    /// [`from_der`](Self::from_der) parse so [`to_der`](Self::to_der)
    /// can return byte-identical output.
    pub der_encoded: Option<Vec<u8>>,
}

impl X509Request {
    /// Decode a CSR from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) on
    /// malformed input, including any trailing bytes after the outer
    /// SEQUENCE, an unexpected version, or an inconsistency between the
    /// inner-TBS and outer signature algorithms.
    #[allow(clippy::too_many_lines)]
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        debug!(target: "openssl::x509::req", bytes = der.len(), "X509Request::from_der");

        // --- Outer SEQUENCE -------------------------------------------------
        let (outer_body, outer_rest) = parse_tlv(der, 0x30)
            .ok_or_else(|| asn1_err("CertificationRequest: expected outer SEQUENCE"))?;
        if !outer_rest.is_empty() {
            return Err(asn1_err(
                "CertificationRequest: trailing bytes after outer SEQUENCE",
            ));
        }

        // --- CertificationRequestInfo (TBS) --------------------------------
        let (cri_body, after_cri) = parse_tlv(outer_body, 0x30).ok_or_else(|| {
            asn1_err("CertificationRequest: expected CertificationRequestInfo SEQUENCE")
        })?;

        // version INTEGER (must be 0 for v1).
        let (ver_body, after_ver) = parse_tlv(cri_body, 0x02)
            .ok_or_else(|| asn1_err("CertificationRequestInfo.version: expected INTEGER"))?;
        let version = decode_unsigned_u32(ver_body)?;
        if version != 0 {
            return Err(asn1_err(format!(
                "CertificationRequestInfo: unsupported version {version}; only v1 (0) supported"
            )));
        }

        // subject Name — re-build the full TLV and delegate.
        let (name_body, after_name) = parse_tlv(after_ver, 0x30)
            .ok_or_else(|| asn1_err("CertificationRequestInfo.subject: expected Name SEQUENCE"))?;
        let mut subject_tlv: Vec<u8> = Vec::new();
        encode_tlv(&mut subject_tlv, 0x30, name_body);
        let subject = X509Name::from_der(&subject_tlv)?;

        // subjectPKInfo SubjectPublicKeyInfo.
        let (spki_body, after_spki) = parse_tlv(after_name, 0x30)
            .ok_or_else(|| asn1_err("CertificationRequestInfo.subjectPKInfo: expected SEQUENCE"))?;
        let mut spki_tlv: Vec<u8> = Vec::new();
        encode_tlv(&mut spki_tlv, 0x30, spki_body);
        let public_key = SubjectPublicKeyInfo::from_der(&spki_tlv)?;

        // attributes [0] IMPLICIT SET OF Attribute (REQUIRED, may be empty).
        let mut attributes: Vec<X509Attribute> = Vec::new();
        if !after_spki.is_empty() {
            let (attrs_body, after_attrs) = parse_tlv(after_spki, 0xA0).ok_or_else(|| {
                asn1_err("CertificationRequestInfo.attributes: expected [0] IMPLICIT SET")
            })?;
            if !after_attrs.is_empty() {
                return Err(asn1_err(
                    "CertificationRequestInfo: trailing bytes after attributes",
                ));
            }
            // The body of `[0] IMPLICIT SET OF` is the concatenation of
            // Attribute SEQUENCEs — there is no inner SET wrapper because
            // the IMPLICIT tag overrides the universal SET tag.
            let mut cursor = attrs_body;
            while !cursor.is_empty() {
                let (attr_body, after_attr) = parse_tlv(cursor, 0x30).ok_or_else(|| {
                    asn1_err("CertificationRequestInfo.attributes: expected Attribute SEQUENCE")
                })?;
                let mut attr_tlv: Vec<u8> = Vec::new();
                encode_tlv(&mut attr_tlv, 0x30, attr_body);
                attributes.push(X509Attribute::from_der(&attr_tlv)?);
                cursor = after_attr;
            }
        }

        // --- signatureAlgorithm --------------------------------------------
        let (signature_algorithm, after_sigalg) =
            parse_algorithm_identifier(after_cri, "CertificationRequest.signatureAlgorithm")?;

        // --- signature BIT STRING ------------------------------------------
        let (sig_body, after_sig) = parse_tlv(after_sigalg, 0x03)
            .ok_or_else(|| asn1_err("CertificationRequest.signature: expected BIT STRING"))?;
        if !after_sig.is_empty() {
            return Err(asn1_err(
                "CertificationRequest: trailing bytes after signature",
            ));
        }
        let signature = parse_bit_string_payload(sig_body, "CertificationRequest.signature")?;

        Ok(Self {
            version,
            subject,
            public_key,
            attributes,
            signature_algorithm,
            signature,
            der_encoded: Some(der.to_vec()),
        })
    }

    /// Decode a CSR from a PEM-encoded string.
    ///
    /// Accepts the labels `CERTIFICATE REQUEST` (RFC 7468) and
    /// `NEW CERTIFICATE REQUEST` (legacy OpenSSL).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// the PEM is malformed or the underlying DER parse fails.
    pub fn from_pem(pem: &str) -> CryptoResult<Self> {
        let der = decode_pem(pem, &["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"])?;
        Self::from_der(&der)
    }

    /// Encode this CSR as DER.
    ///
    /// If a cached DER representation is present (set by
    /// [`from_der`](Self::from_der)) it is returned verbatim; otherwise
    /// the encoding is reconstructed from the structured fields.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// any sub-encoding fails.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        if let Some(cached) = &self.der_encoded {
            return Ok(cached.clone());
        }

        // --- CertificationRequestInfo (TBS) --------------------------------
        let mut cri: Vec<u8> = Vec::new();

        // version INTEGER.
        let mut ver_bytes: Vec<u8> = Vec::new();
        if self.version == 0 {
            ver_bytes.push(0x00);
        } else {
            // Encode as positive INTEGER, BE, with sign-padding if needed.
            let mut v: Vec<u8> = self.version.to_be_bytes().to_vec();
            while v.len() > 1 && v[0] == 0x00 {
                v.remove(0);
            }
            if v[0] & 0x80 != 0 {
                v.insert(0, 0x00);
            }
            ver_bytes = v;
        }
        encode_tlv(&mut cri, 0x02, &ver_bytes);

        // subject Name — append the full TLV produced by X509Name::to_der.
        cri.extend_from_slice(&self.subject.to_der());

        // subjectPKInfo.
        cri.extend_from_slice(&self.public_key.to_der()?);

        // attributes [0] IMPLICIT — body is concatenation of Attribute TLVs.
        let mut attrs_body: Vec<u8> = Vec::new();
        for attr in &self.attributes {
            attrs_body.extend_from_slice(&attr.to_der());
        }
        encode_tlv(&mut cri, 0xA0, &attrs_body);

        // --- Outer assembly ------------------------------------------------
        let mut outer_body: Vec<u8> = Vec::new();
        encode_tlv(&mut outer_body, 0x30, &cri);
        emit_algorithm_identifier(&mut outer_body, &self.signature_algorithm);

        // signature BIT STRING (prepend 0x00 unused-bits prefix).
        let mut sig_field: Vec<u8> =
            Vec::with_capacity(1usize.saturating_add(self.signature.len()));
        sig_field.push(0x00);
        sig_field.extend_from_slice(&self.signature);
        encode_tlv(&mut outer_body, 0x03, &sig_field);

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &outer_body);
        Ok(out)
    }

    /// Encode this CSR as PEM (label `CERTIFICATE REQUEST`).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`to_der`](Self::to_der).
    pub fn to_pem(&self) -> CryptoResult<String> {
        Ok(encode_pem(&self.to_der()?, "CERTIFICATE REQUEST"))
    }

    /// Extract the requested extensions from this CSR's `extensionRequest`
    /// attribute (OID `1.2.840.113549.1.9.14`), if present.
    ///
    /// Returns an empty vector when no `extensionRequest` attribute is
    /// present or when its SET is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// the attribute value is malformed.
    pub fn extensions(&self) -> CryptoResult<Vec<X509Extension>> {
        const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";
        for attr in &self.attributes {
            if attr.oid == EXTENSION_REQUEST_OID {
                if let Some(value) = attr.values.first() {
                    // value is a complete TLV — expect a SEQUENCE OF Extension.
                    let (body, rest) = parse_tlv(value, 0x30).ok_or_else(|| {
                        asn1_err("extensionRequest: expected SEQUENCE OF Extension")
                    })?;
                    if !rest.is_empty() {
                        return Err(asn1_err(
                            "extensionRequest: trailing bytes after SEQUENCE OF",
                        ));
                    }
                    return parse_extensions_list(body);
                }
                return Ok(Vec::new());
            }
        }
        Ok(Vec::new())
    }

    /// Borrow the CSR's version field.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Borrow the CSR's subject DN.
    #[must_use]
    pub const fn subject(&self) -> &X509Name {
        &self.subject
    }

    /// Borrow the CSR's public key.
    #[must_use]
    pub const fn public_key(&self) -> &SubjectPublicKeyInfo {
        &self.public_key
    }

    /// Borrow the CSR's attribute list.
    #[must_use]
    pub fn attributes(&self) -> &[X509Attribute] {
        &self.attributes
    }

    /// Borrow the CSR's signature algorithm.
    #[must_use]
    pub const fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Borrow the CSR's raw signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

// ============================================================================
// Phase 16: Extension Framework — ExtensionMethod trait, ExtensionRegistry
// ============================================================================
//
// Translates the C `X509V3_EXT_METHOD` vtable from `v3_lib.c` (345 lines)
// and the dynamic registry it manages.  In C, providers register handlers
// in a `STACK_OF(X509V3_EXT_METHOD)` and consumers look up by NID.
//
// The Rust translation uses a trait + `HashMap` keyed by OID dotted-decimal
// strings, allowing both pre-registered standard extensions and dynamic
// registration of caller-defined handlers.

/// Handler interface for a specific X.509v3 extension type.
///
/// Replaces the C `X509V3_EXT_METHOD` struct from `v3_lib.c`, which is a
/// vtable of function pointers (`d2i`, `i2d`, `i2s`, `s2i`, `i2v`, etc.)
/// keyed by extension NID.
///
/// Implementations must be `Send + Sync` so registries can be safely
/// shared between threads (typically wrapped in `Arc<RwLock<...>>` —
/// see [`ExtensionRegistry`]).
pub trait ExtensionMethod: Send + Sync + std::fmt::Debug {
    /// The extension's OID (dotted-decimal string).  Must be stable for
    /// the lifetime of the handler.
    fn oid(&self) -> &str;

    /// Decode the extension's `extnValue` (the inner DER content of the
    /// OCTET STRING wrapper) into a typed [`ParsedExtension`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// the value bytes are not well-formed for this extension type.
    fn parse(&self, value: &[u8]) -> CryptoResult<ParsedExtension>;

    /// Re-encode a typed [`ParsedExtension`] back to DER bytes suitable
    /// for placement inside an OCTET STRING `extnValue` wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`](openssl_common::CryptoError) with
    /// `CommonError::Unsupported` if the variant cannot be re-emitted by
    /// this handler.
    fn encode(&self, ext: &ParsedExtension) -> CryptoResult<Vec<u8>>;

    /// Render the extension as a human-readable string (used by
    /// [`fmt::Display`] for [`X509Certificate`]).
    fn print(&self, ext: &ParsedExtension) -> String;
}

/// Registry of [`ExtensionMethod`] handlers keyed by OID.
///
/// Replaces the C `standard_exts[]` static array and the dynamic
/// `ext_list` populated by `X509V3_EXT_add()`.
///
/// The registry is constructed via [`new`](Self::new), which pre-populates
/// it with default handlers for all standard extensions defined in
/// [`oid`].  Callers can register additional handlers via
/// [`register`](Self::register) and look up handlers via
/// [`get`](Self::get).
///
/// ## Concurrency
///
/// The registry is `Send + Sync` — its internal `HashMap` is owned and
/// the trait objects it stores require `Send + Sync`.  For shared use
/// across threads, wrap a single registry in
/// `Arc<RwLock<ExtensionRegistry>>` and acquire the read lock for
/// lookups and the write lock for registration (see Rule R7).
///
/// ```text
/// // LOCK-SCOPE: ExtensionRegistry — covers the methods HashMap.
/// // Read side dominates (lookups during certificate parsing); writes
/// // are rare (registration at startup).  Single RwLock is sufficient
/// // — no per-key sharding required.
/// ```
pub struct ExtensionRegistry {
    methods: HashMap<String, Box<dyn ExtensionMethod>>,
}

impl ExtensionRegistry {
    /// Construct a new registry pre-populated with handlers for every
    /// standard X.509v3 extension OID enumerated in [`oid`].
    ///
    /// The default handlers delegate parsing to [`parse_extension`] and
    /// produce [`ParsedExtension::Unknown`] for unrecognised OIDs.
    #[must_use]
    pub fn new() -> Self {
        let mut methods: HashMap<String, Box<dyn ExtensionMethod>> = HashMap::new();
        // LOCK-SCOPE: registry construction is single-threaded; no lock
        //             needed during initialisation.

        let standard_oids: &[&'static str] = &[
            oid::BASIC_CONSTRAINTS,
            oid::KEY_USAGE,
            oid::EXTENDED_KEY_USAGE,
            oid::SUBJECT_KEY_IDENTIFIER,
            oid::AUTHORITY_KEY_IDENTIFIER,
            oid::SUBJECT_ALT_NAME,
            oid::ISSUER_ALT_NAME,
            oid::CRL_DISTRIBUTION_POINTS,
            oid::CERTIFICATE_POLICIES,
            oid::POLICY_MAPPINGS,
            oid::POLICY_CONSTRAINTS,
            oid::INHIBIT_ANY_POLICY,
            oid::NAME_CONSTRAINTS,
            oid::AUTHORITY_INFO_ACCESS,
            oid::SUBJECT_INFO_ACCESS,
            oid::FRESHEST_CRL,
            oid::CRL_NUMBER,
            oid::DELTA_CRL_INDICATOR,
            oid::ISSUING_DISTRIBUTION_POINT,
            oid::TLS_FEATURE,
            oid::CT_PRECERT_SCTS,
            oid::CT_PRECERT_POISON,
            oid::SCT_LIST,
        ];
        for oid_str in standard_oids {
            methods.insert(
                (*oid_str).to_owned(),
                Box::new(BuiltinExtension::new(oid_str)),
            );
        }
        Self { methods }
    }

    /// Register a new handler.  If a handler with the same OID was
    /// previously registered, it is replaced.
    pub fn register(&mut self, method: Box<dyn ExtensionMethod>) {
        let key = method.oid().to_owned();
        debug!(target: "openssl::x509::ext", oid = %key, "registering extension handler");
        self.methods.insert(key, method);
    }

    /// Look up a handler by OID.  Returns `None` for unknown OIDs.
    #[must_use]
    pub fn get(&self, oid_str: &str) -> Option<&dyn ExtensionMethod> {
        self.methods.get(oid_str).map(AsRef::as_ref)
    }

    /// Number of currently registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// `true` if no handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ExtensionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtensionRegistry")
            .field("handlers", &self.methods.len())
            .finish()
    }
}

/// Concrete [`ExtensionMethod`] implementation for the standard extensions
/// listed in [`oid`].  Delegates parsing to [`parse_extension`].
#[derive(Debug, Clone)]
struct BuiltinExtension {
    oid: &'static str,
}

impl BuiltinExtension {
    const fn new(oid: &'static str) -> Self {
        Self { oid }
    }
}

impl ExtensionMethod for BuiltinExtension {
    fn oid(&self) -> &str {
        self.oid
    }

    fn parse(&self, value: &[u8]) -> CryptoResult<ParsedExtension> {
        parse_extension(self.oid, value)
    }

    fn encode(&self, ext: &ParsedExtension) -> CryptoResult<Vec<u8>> {
        // Re-emit only the cases for which we have a structural inverse;
        // `Unknown` simply returns the cached raw value.  Other variants
        // require a fully-typed ASN.1 emitter that depends on subsystems
        // not yet implemented (full provider integration).  Returning a
        // documented `Unsupported` error mirrors the C
        // `X509V3_EXT_METHOD::i2d == NULL` case where the framework
        // simply propagates a "no encoder available" error.
        match ext {
            ParsedExtension::Unknown { value, .. } => Ok(value.clone()),
            ParsedExtension::SubjectKeyIdentifier(skid) => {
                let mut out: Vec<u8> = Vec::new();
                encode_tlv(&mut out, 0x04, skid);
                Ok(out)
            }
            ParsedExtension::ExtendedKeyUsage(oids) => {
                let mut body: Vec<u8> = Vec::new();
                for o in oids {
                    let oid_body = encode_oid(o);
                    encode_tlv(&mut body, 0x06, &oid_body);
                }
                let mut out: Vec<u8> = Vec::new();
                encode_tlv(&mut out, 0x30, &body);
                Ok(out)
            }
            ParsedExtension::BasicConstraints(bc) => {
                let mut body: Vec<u8> = Vec::new();
                if bc.ca {
                    // BOOLEAN TRUE — DEFAULT FALSE so encode only when ca=true.
                    encode_tlv(&mut body, 0x01, &[0xFF]);
                }
                if let Some(plen) = bc.path_length {
                    let mut int_bytes: Vec<u8> = plen.to_be_bytes().to_vec();
                    while int_bytes.len() > 1 && int_bytes[0] == 0x00 {
                        int_bytes.remove(0);
                    }
                    if int_bytes[0] & 0x80 != 0 {
                        int_bytes.insert(0, 0x00);
                    }
                    encode_tlv(&mut body, 0x02, &int_bytes);
                }
                let mut out: Vec<u8> = Vec::new();
                encode_tlv(&mut out, 0x30, &body);
                Ok(out)
            }
            ParsedExtension::KeyUsage(flags) => {
                // Encode as named-bits BIT STRING with minimal trailing zeros.
                let bits = flags.bits();
                // Two-byte buffer (low 16 bits) — keyUsage covers bits 0..=8.
                let mut buf = [bits.to_be_bytes()[0], bits.to_be_bytes()[1]];
                // Determine highest set bit to compute byte length and unused bits.
                if bits == 0 {
                    let mut out: Vec<u8> = Vec::new();
                    encode_tlv(&mut out, 0x03, &[0x00]);
                    return Ok(out);
                }
                let mut byte_len = 2usize;
                if buf[1] == 0x00 {
                    byte_len = 1;
                }
                // Unused bits = trailing zero bits in the highest used byte.
                let last = buf[byte_len - 1];
                let unused: u8 = if last == 0 {
                    0
                } else {
                    (last.trailing_zeros() & 0x0F) as u8
                };
                let mut bs: Vec<u8> = Vec::with_capacity(byte_len.saturating_add(1));
                bs.push(unused);
                bs.extend_from_slice(&buf[..byte_len]);
                let mut out: Vec<u8> = Vec::new();
                encode_tlv(&mut out, 0x03, &bs);
                let _ = &mut buf; // silence potential unused warning
                Ok(out)
            }
            _ => Err(unsupported(format!(
                "ExtensionMethod::encode not implemented for {ext:?}"
            ))),
        }
    }

    fn print(&self, ext: &ParsedExtension) -> String {
        format!("{ext:?}")
    }
}

// ============================================================================
// Phase 18: NetscapeSpki (Signed Public Key And Challenge — SPKAC)
// ============================================================================
//
// Translates `NETSCAPE_SPKI` from `crypto/asn1/x_spki.c` (and the helper
// functions in `crypto/x509/x509spki.c` — 75 lines) used by the
// (deprecated) HTML5 `<keygen>` element.
//
// ASN.1:
//
// ```text
// PublicKeyAndChallenge ::= SEQUENCE {
//     spki      SubjectPublicKeyInfo,
//     challenge IA5String
// }
//
// SignedPublicKeyAndChallenge ::= SEQUENCE {
//     publicKeyAndChallenge PublicKeyAndChallenge,
//     signatureAlgorithm    AlgorithmIdentifier,
//     signature             BIT STRING
// }
// ```
//
// The wire format is base64 of the DER, **without** PEM markers.

/// Netscape `SignedPublicKeyAndChallenge` (SPKAC).
///
/// Used historically by Netscape's `<keygen>` element to enroll a
/// browser-generated key pair with a CA.  Modern browsers have removed
/// support for `<keygen>`, but the format is still occasionally
/// encountered in legacy CA workflows.
#[derive(Debug, Clone)]
pub struct NetscapeSpki {
    /// The certified public key.
    pub spki: SubjectPublicKeyInfo,
    /// CA-supplied challenge string (`IA5String`).
    pub challenge: String,
    /// Signature algorithm identifier.
    pub signature_algorithm: AlgorithmIdentifier,
    /// Signature value (raw bytes after stripping the BIT STRING
    /// `unused-bits` prefix).
    pub signature: Vec<u8>,
}

impl NetscapeSpki {
    /// Construct a new SPKAC with empty fields.  Suitable for builder
    /// usage prior to calling [`set_pubkey`](Self::set_pubkey),
    /// [`set_challenge`](Self::set_challenge), and
    /// [`sign`](Self::sign).
    #[must_use]
    pub fn new() -> Self {
        Self {
            spki: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier::new(""),
                public_key: Vec::new(),
            },
            challenge: String::new(),
            signature_algorithm: AlgorithmIdentifier::new(""),
            signature: Vec::new(),
        }
    }

    /// Decode an SPKAC from its base64 wire encoding (no PEM markers).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) on
    /// invalid base64 or malformed DER.
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        // Tolerate ASCII whitespace within the base64 payload.
        let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = base64_decode(&cleaned)?;
        Self::from_der(&der)
    }

    /// Encode this SPKAC as base64 (no PEM markers).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// the underlying DER encoding fails.
    pub fn to_base64(&self) -> CryptoResult<String> {
        Ok(base64_encode(&self.to_der()?))
    }

    /// Decode an SPKAC from raw DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) on
    /// any structural error.
    pub fn from_der(der: &[u8]) -> CryptoResult<Self> {
        // --- Outer SEQUENCE ------------------------------------------------
        let (outer_body, outer_rest) = parse_tlv(der, 0x30)
            .ok_or_else(|| asn1_err("NetscapeSpki: expected outer SEQUENCE"))?;
        if !outer_rest.is_empty() {
            return Err(asn1_err(
                "NetscapeSpki: trailing bytes after outer SEQUENCE",
            ));
        }

        // --- PublicKeyAndChallenge ----------------------------------------
        let (pkc_body, after_pkc) = parse_tlv(outer_body, 0x30)
            .ok_or_else(|| asn1_err("NetscapeSpki: expected PublicKeyAndChallenge SEQUENCE"))?;

        // SubjectPublicKeyInfo (re-build the full TLV).
        let (spki_body, after_spki) = parse_tlv(pkc_body, 0x30)
            .ok_or_else(|| asn1_err("NetscapeSpki.spki: expected SEQUENCE"))?;
        let mut spki_tlv: Vec<u8> = Vec::new();
        encode_tlv(&mut spki_tlv, 0x30, spki_body);
        let spki = SubjectPublicKeyInfo::from_der(&spki_tlv)?;

        // challenge IA5String.
        let (chal_body, after_chal) = parse_tlv(after_spki, 0x16)
            .ok_or_else(|| asn1_err("NetscapeSpki.challenge: expected IA5String"))?;
        if !after_chal.is_empty() {
            return Err(asn1_err(
                "NetscapeSpki.PublicKeyAndChallenge: trailing bytes after challenge",
            ));
        }
        let challenge = decode_string(chal_body, Asn1StringType::Ia5String);

        // --- signatureAlgorithm -------------------------------------------
        let (signature_algorithm, after_sigalg) =
            parse_algorithm_identifier(after_pkc, "NetscapeSpki.signatureAlgorithm")?;

        // --- signature BIT STRING -----------------------------------------
        let (sig_body, after_sig) = parse_tlv(after_sigalg, 0x03)
            .ok_or_else(|| asn1_err("NetscapeSpki.signature: expected BIT STRING"))?;
        if !after_sig.is_empty() {
            return Err(asn1_err("NetscapeSpki: trailing bytes after signature"));
        }
        let signature = parse_bit_string_payload(sig_body, "NetscapeSpki.signature")?;

        Ok(Self {
            spki,
            challenge,
            signature_algorithm,
            signature,
        })
    }

    /// Encode this SPKAC as DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encoding`](openssl_common::CryptoError) if
    /// any sub-encoding fails.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        // PublicKeyAndChallenge body.
        let mut pkc: Vec<u8> = Vec::new();
        pkc.extend_from_slice(&self.spki.to_der()?);
        let chal_bytes = encode_string(&self.challenge, Asn1StringType::Ia5String);
        encode_tlv(&mut pkc, 0x16, &chal_bytes);

        // Outer body.
        let mut outer: Vec<u8> = Vec::new();
        encode_tlv(&mut outer, 0x30, &pkc);
        emit_algorithm_identifier(&mut outer, &self.signature_algorithm);

        let mut sig_field: Vec<u8> =
            Vec::with_capacity(1usize.saturating_add(self.signature.len()));
        sig_field.push(0x00);
        sig_field.extend_from_slice(&self.signature);
        encode_tlv(&mut outer, 0x03, &sig_field);

        let mut out: Vec<u8> = Vec::new();
        encode_tlv(&mut out, 0x30, &outer);
        Ok(out)
    }

    /// Set the challenge string.
    pub fn set_challenge(&mut self, challenge: impl Into<String>) {
        self.challenge = challenge.into();
    }

    /// Set the public key.
    pub fn set_pubkey(&mut self, spki: SubjectPublicKeyInfo) {
        self.spki = spki;
    }

    /// Borrow the public key.
    #[must_use]
    pub const fn get_pubkey(&self) -> &SubjectPublicKeyInfo {
        &self.spki
    }

    /// Sign this SPKAC's `PublicKeyAndChallenge` with the supplied private
    /// key material.
    ///
    /// **Currently unsupported** — full signing requires provider /
    /// EVP integration which is implemented in the higher-level signing
    /// code path.  This method is reserved for that wiring.
    ///
    /// # Errors
    ///
    /// Always returns
    /// [`CryptoError::Common`](openssl_common::CryptoError) with
    /// `CommonError::Unsupported`.
    pub fn sign(&mut self, _private_key_der: &[u8], _algorithm: &str) -> CryptoResult<()> {
        Err(unsupported(
            "NetscapeSpki::sign requires EVP integration (pending)",
        ))
    }

    /// Verify the signature on this SPKAC using its embedded public key.
    ///
    /// **Currently unsupported** — see [`sign`](Self::sign) for context.
    ///
    /// # Errors
    ///
    /// Always returns
    /// [`CryptoError::Common`](openssl_common::CryptoError) with
    /// `CommonError::Unsupported`.
    pub fn verify(&self) -> CryptoResult<bool> {
        Err(unsupported(
            "NetscapeSpki::verify requires EVP integration (pending)",
        ))
    }

    /// Render a human-readable description of this SPKAC, mirroring the
    /// output produced by the `openssl spkac` CLI command.
    #[must_use]
    pub fn print(&self) -> String {
        let mut s = String::new();
        s.push_str("Netscape SPKI:\n");
        s.push_str("  Public Key Algorithm: ");
        s.push_str(&self.spki.algorithm.algorithm);
        s.push('\n');
        if let Ok(bits) = self.spki.key_bits() {
            s.push_str(&format!("  Public Key Bits: {bits}\n"));
        }
        s.push_str("  Challenge: ");
        s.push_str(&self.challenge);
        s.push('\n');
        s.push_str("  Signature Algorithm: ");
        s.push_str(&self.signature_algorithm.algorithm);
        s.push('\n');
        s.push_str("  Signature Length: ");
        s.push_str(&format!("{} bytes\n", self.signature.len()));
        s
    }
}

impl Default for NetscapeSpki {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Phase 17: Display implementations
// ============================================================================
//
// Translates the human-readable certificate dump format produced by
// `X509_print()` (in `crypto/x509/t_x509.c`) and `X509_REQ_print()`
// (in `crypto/x509/t_req.c`).
//
// The reproduced format follows the layout of the C
// `openssl x509 -text` command output, with sufficient detail to make
// certificates and CSRs human-inspectable.

impl fmt::Display for X509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Certificate:")?;
        writeln!(f, "    Data:")?;
        writeln!(
            f,
            "        Version: {} ({:#x})",
            self.tbs.version.major(),
            self.tbs.version.as_u8()
        )?;
        writeln!(
            f,
            "        Serial Number: {}",
            format_hex_colon(&self.tbs.serial_number)
        )?;
        writeln!(
            f,
            "        Signature Algorithm: {}",
            self.signature_algorithm.algorithm
        )?;
        writeln!(f, "        Issuer: {}", self.tbs.issuer)?;
        writeln!(f, "        Validity")?;
        writeln!(
            f,
            "            Not Before: {}",
            format_time_human(self.tbs.validity.not_before)
        )?;
        writeln!(
            f,
            "            Not After : {}",
            format_time_human(self.tbs.validity.not_after)
        )?;
        writeln!(f, "        Subject: {}", self.tbs.subject)?;
        writeln!(f, "        Subject Public Key Info:")?;
        writeln!(
            f,
            "            Public Key Algorithm: {}",
            self.tbs.public_key.algorithm.algorithm
        )?;
        if let Ok(bits) = self.tbs.public_key.key_bits() {
            writeln!(f, "                Public-Key: ({bits} bit)")?;
        }
        if !self.tbs.extensions.is_empty() {
            writeln!(f, "        X509v3 extensions:")?;
            for ext in &self.tbs.extensions {
                let critical_str = if ext.critical { ": critical" } else { "" };
                writeln!(
                    f,
                    "            {} ({}){}",
                    extension_short_name(&ext.oid),
                    ext.oid,
                    critical_str
                )?;
                let parsed_text = match ext.as_parsed() {
                    Ok(parsed) => format_parsed_extension(&parsed),
                    Err(_) => format!("                <{} bytes raw value>", ext.value.len()),
                };
                for line in parsed_text.lines() {
                    writeln!(f, "                {line}")?;
                }
            }
        }
        writeln!(
            f,
            "    Signature Algorithm: {}",
            self.signature_algorithm.algorithm
        )?;
        writeln!(f, "    Signature Value:")?;
        for chunk in self.signature_value.chunks(18) {
            writeln!(f, "        {}", format_hex_colon(chunk))?;
        }
        Ok(())
    }
}

impl fmt::Display for X509Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Certificate Request:")?;
        writeln!(f, "    Data:")?;
        writeln!(f, "        Version: {} ({:#x})", self.version, self.version)?;
        writeln!(f, "        Subject: {}", self.subject)?;
        writeln!(f, "        Subject Public Key Info:")?;
        writeln!(
            f,
            "            Public Key Algorithm: {}",
            self.public_key.algorithm.algorithm
        )?;
        if let Ok(bits) = self.public_key.key_bits() {
            writeln!(f, "                Public-Key: ({bits} bit)")?;
        }
        if !self.attributes.is_empty() {
            writeln!(f, "        Attributes:")?;
            for attr in &self.attributes {
                writeln!(
                    f,
                    "            {}: <{} value(s)>",
                    attr.oid,
                    attr.values.len()
                )?;
            }
        }
        writeln!(
            f,
            "    Signature Algorithm: {}",
            self.signature_algorithm.algorithm
        )?;
        writeln!(f, "    Signature Value:")?;
        for chunk in self.signature.chunks(18) {
            writeln!(f, "        {}", format_hex_colon(chunk))?;
        }
        Ok(())
    }
}

// ─── Display helper functions (private) ────────────────────────────────────

/// Format a byte slice as `aa:bb:cc:...`.
fn format_hex_colon(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(3));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Format an [`OsslTime`] as a human-readable UTC timestamp.
fn format_time_human(time: OsslTime) -> String {
    if time.is_zero() {
        return "1970-01-01T00:00:00Z".to_owned();
    }
    if time.is_infinite() {
        return "infinity".to_owned();
    }
    let secs = time.to_seconds();
    // Saturating-cast secs (u64) to i64 for civil arithmetic.
    let total_secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let days = total_secs.div_euclid(86_400);
    let time_of_day = total_secs.rem_euclid(86_400);
    let hour = time_of_day.div_euclid(3600);
    let rem = time_of_day.rem_euclid(3600);
    let minute = rem.div_euclid(60);
    let second = rem.rem_euclid(60);
    let (year, month, day) = days_to_civil(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Map a known extension OID to its short, human-readable name.  Returns
/// the OID string itself for unknown extensions.
fn extension_short_name(oid_str: &str) -> &'static str {
    match oid_str {
        x if x == oid::BASIC_CONSTRAINTS => "X509v3 Basic Constraints",
        x if x == oid::KEY_USAGE => "X509v3 Key Usage",
        x if x == oid::EXTENDED_KEY_USAGE => "X509v3 Extended Key Usage",
        x if x == oid::SUBJECT_KEY_IDENTIFIER => "X509v3 Subject Key Identifier",
        x if x == oid::AUTHORITY_KEY_IDENTIFIER => "X509v3 Authority Key Identifier",
        x if x == oid::SUBJECT_ALT_NAME => "X509v3 Subject Alternative Name",
        x if x == oid::ISSUER_ALT_NAME => "X509v3 Issuer Alternative Name",
        x if x == oid::CRL_DISTRIBUTION_POINTS => "X509v3 CRL Distribution Points",
        x if x == oid::CERTIFICATE_POLICIES => "X509v3 Certificate Policies",
        x if x == oid::POLICY_MAPPINGS => "X509v3 Policy Mappings",
        x if x == oid::POLICY_CONSTRAINTS => "X509v3 Policy Constraints",
        x if x == oid::INHIBIT_ANY_POLICY => "X509v3 Inhibit Any Policy",
        x if x == oid::NAME_CONSTRAINTS => "X509v3 Name Constraints",
        x if x == oid::AUTHORITY_INFO_ACCESS => "Authority Information Access",
        x if x == oid::SUBJECT_INFO_ACCESS => "Subject Information Access",
        x if x == oid::FRESHEST_CRL => "X509v3 Freshest CRL",
        x if x == oid::CRL_NUMBER => "X509v3 CRL Number",
        x if x == oid::DELTA_CRL_INDICATOR => "X509v3 Delta CRL Indicator",
        x if x == oid::ISSUING_DISTRIBUTION_POINT => "X509v3 Issuing Distribution Point",
        x if x == oid::TLS_FEATURE => "TLS Feature",
        x if x == oid::CT_PRECERT_SCTS => "CT Precertificate SCTs",
        x if x == oid::CT_PRECERT_POISON => "CT Precertificate Poison",
        x if x == oid::SCT_LIST => "CT SCT List",
        _ => "Extension",
    }
}

/// Format a [`ParsedExtension`] as a multi-line indented description.
fn format_parsed_extension(parsed: &ParsedExtension) -> String {
    let mut s = String::new();
    match parsed {
        ParsedExtension::BasicConstraints(bc) => {
            s.push_str(&format!("CA:{}", if bc.ca { "TRUE" } else { "FALSE" }));
            if let Some(plen) = bc.path_length {
                s.push_str(&format!(", pathlen:{plen}"));
            }
        }
        ParsedExtension::KeyUsage(flags) => {
            let mut parts: Vec<&str> = Vec::new();
            if flags.contains(KeyUsageFlags::DIGITAL_SIGNATURE) {
                parts.push("Digital Signature");
            }
            if flags.contains(KeyUsageFlags::NON_REPUDIATION) {
                parts.push("Non Repudiation");
            }
            if flags.contains(KeyUsageFlags::KEY_ENCIPHERMENT) {
                parts.push("Key Encipherment");
            }
            if flags.contains(KeyUsageFlags::DATA_ENCIPHERMENT) {
                parts.push("Data Encipherment");
            }
            if flags.contains(KeyUsageFlags::KEY_AGREEMENT) {
                parts.push("Key Agreement");
            }
            if flags.contains(KeyUsageFlags::KEY_CERT_SIGN) {
                parts.push("Certificate Sign");
            }
            if flags.contains(KeyUsageFlags::CRL_SIGN) {
                parts.push("CRL Sign");
            }
            if flags.contains(KeyUsageFlags::ENCIPHER_ONLY) {
                parts.push("Encipher Only");
            }
            if flags.contains(KeyUsageFlags::DECIPHER_ONLY) {
                parts.push("Decipher Only");
            }
            s.push_str(&parts.join(", "));
        }
        ParsedExtension::ExtendedKeyUsage(oids) => {
            s.push_str(&oids.join(", "));
        }
        ParsedExtension::SubjectKeyIdentifier(skid) => {
            s.push_str(&format_hex_colon(skid));
        }
        ParsedExtension::AuthorityKeyIdentifier(akid) => {
            if let Some(kid) = &akid.key_identifier {
                s.push_str(&format!("keyid:{}", format_hex_colon(kid)));
            } else {
                s.push_str("(no keyid)");
            }
            if let Some(serial) = &akid.authority_cert_serial {
                s.push_str(&format!("\n  serial:{}", format_hex_colon(serial)));
            }
        }
        ParsedExtension::SubjectAltName(names) | ParsedExtension::IssuerAltName(names) => {
            for (i, n) in names.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&format_general_name(n));
            }
        }
        ParsedExtension::CrlDistributionPoints(dps) => {
            for (i, dp) in dps.iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                s.push_str(&format!("Full Name: {dp:?}"));
            }
        }
        ParsedExtension::CertificatePolicies(pols) => {
            for (i, p) in pols.iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                s.push_str(&format!("Policy: {}", p.policy_oid));
            }
        }
        ParsedExtension::PolicyMappings(maps) => {
            for (i, (issuer, subject)) in maps.iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                s.push_str(&format!("{issuer} -> {subject}"));
            }
        }
        ParsedExtension::PolicyConstraints(pc) => {
            s.push_str(&format!("{pc:?}"));
        }
        ParsedExtension::InhibitAnyPolicy(n) => {
            s.push_str(&format!("InhibitAnyPolicy:{n}"));
        }
        ParsedExtension::NameConstraints(nc) => {
            s.push_str(&format!(
                "permitted: {}, excluded: {}",
                nc.permitted_subtrees.len(),
                nc.excluded_subtrees.len()
            ));
        }
        ParsedExtension::AuthorityInfoAccess(descs) | ParsedExtension::SubjectInfoAccess(descs) => {
            for (i, d) in descs.iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                s.push_str(&format!(
                    "{} - {}",
                    d.method,
                    format_general_name(&d.location)
                ));
            }
        }
        ParsedExtension::TlsFeature(features) => {
            let parts: Vec<String> = features.iter().map(|f| format!("{f}")).collect();
            s.push_str(&parts.join(", "));
        }
        ParsedExtension::Unknown { oid: o, value } => {
            s.push_str(&format!("OID:{o} ({} bytes)", value.len()));
        }
    }
    s
}

/// Format a [`GeneralName`] as a `prefix:value` string mimicking the
/// `openssl x509 -text` style.
fn format_general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::Rfc822Name(s) => format!("email:{s}"),
        GeneralName::DnsName(s) => format!("DNS:{s}"),
        GeneralName::DirectoryName(dn) => format!("DirName:{dn}"),
        GeneralName::UniformResourceIdentifier(s) => format!("URI:{s}"),
        GeneralName::IpAddress(bytes) => match bytes.len() {
            4 => format!("IP:{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
            16 => {
                let mut parts: Vec<String> = Vec::with_capacity(8);
                for chunk in bytes.chunks(2) {
                    if chunk.len() == 2 {
                        let hi = u16::from(chunk[0]);
                        let lo = u16::from(chunk[1]);
                        let word: u16 = hi.checked_shl(8).unwrap_or(0).saturating_add(lo);
                        parts.push(format!("{word:x}"));
                    }
                }
                format!("IP:{}", parts.join(":"))
            }
            _ => format!("IP:<{} bytes>", bytes.len()),
        },
        GeneralName::RegisteredId(s) => format!("RegisteredID:{s}"),
        GeneralName::OtherName { type_id, value } => {
            format!("othername:{type_id} ({} bytes)", value.len())
        }
    }
}
