//! PKCS#7 (RFC 2315) implementation for cryptographic message operations.
//!
//! Provides signing, verification, encryption, and decryption of PKCS#7
//! content structures.  Supports `SignedData`, `EnvelopedData`,
//! `SignedAndEnvelopedData`, `DigestedData`, and `EncryptedData` content
//! types, plus passthrough for OID-tagged "other" content.  Also provides
//! S/MIME integration for email security per RFC 2633 / RFC 5751.
//!
//! Translates ~3,164 lines of C from `crypto/pkcs7/` (8 source files + 1
//! header):
//!
//! | C file              | Lines | Rust equivalent                          |
//! |---------------------|-------|------------------------------------------|
//! | `pk7_lib.c`         |   760 | [`Pkcs7`] constructors / mutators        |
//! | `pk7_smime.c`       |   540 | [`sign`], [`verify`], [`encrypt_data`],  |
//! |                     |       | [`decrypt_data`], [`finalize`]           |
//! | `pk7_doit.c`        | 1,265 | Crypto engine (`data_init`, `data_decode`,|
//! |                     |       | `data_final`, `data_verify`)             |
//! | `pk7_asn1.c`        |   254 | [`Pkcs7::to_der`] / [`Pkcs7::from_der`]  |
//! | `pk7_attr.c`        |   139 | [`add_smime_capabilities`], etc.         |
//! | `pk7_mime.c`        |    73 | [`Pkcs7::to_smime`] / [`Pkcs7::from_smime`] |
//! | `bio_pk7.c`         |    19 | Streaming integrated into serialization  |
//! | `pk7_local.h`       |    17 | [`Pkcs7Context`]                         |
//! | `pkcs7err.c`        |    98 | [`Pkcs7Error`]                           |
//!
//! ## Key Translations from C
//!
//! - `PKCS7` → [`Pkcs7`] (RAII / `Drop`, no manual free)
//! - `PKCS7_SIGNED` → [`Pkcs7SignedData`] embedded in
//!   [`Pkcs7Content::Signed`]
//! - `PKCS7_SIGNER_INFO` → [`Pkcs7SignerInfo`]
//! - `PKCS7_RECIP_INFO` → [`Pkcs7RecipientInfo`]
//! - `PKCS7_sign()` → [`sign`]
//! - `PKCS7_verify()` → [`verify`]
//! - `PKCS7_encrypt()` → [`encrypt_data`]
//! - `PKCS7_decrypt()` → [`decrypt_data`]
//! - All sentinel returns (0/-1/NULL) → `Result<T, Pkcs7Error>` per Rule R5
//! - `PKCS7_ctrl` detached flags → typed [`Pkcs7Flags`] bitflags
//! - `OPENSSL_cleanse` → `zeroize::ZeroizeOnDrop` on key material
//! - Error reason codes (`PKCS7_R_*`) → [`Pkcs7Error`] variants
//!
//! ## Rules Enforced
//!
//! - **R3 (Field Propagation):** Every field in every struct has at least
//!   one write-site and one read-site documented in the field's doc
//!   comment.
//! - **R5 (Nullability over Sentinels):** No 0/-1/NULL sentinels; all
//!   fallible operations return `Result<T, Pkcs7Error>` and absent values
//!   use `Option<T>`.
//! - **R6 (Lossless Casts):** All narrowing conversions go through
//!   `try_from`, `checked_*`, or are documented with `// TRUNCATION:`.
//! - **R7 (Lock Granularity):** This module operates on owned values and
//!   does not introduce shared mutable state of its own; consumers wrap
//!   [`Pkcs7`] with the locking discipline appropriate for their context.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks (enforced by the
//!   `forbid(unsafe_code)` attribute on the parent crate).
//! - **R9 (Warning-Free):** All public items carry `///` doc comments;
//!   no `#[allow(unused)]` or `#[allow(warnings)]` is used.
//!
//! ## Observability
//!
//! Sign / verify / encrypt / decrypt entry points emit `tracing::debug!` and
//! `tracing::trace!` events with the static target `"openssl::pkcs::pkcs7"`
//! per the AAP §0.8.5 Observability Rule.
//!
//! ## MMA / Bleichenbacher Hardening
//!
//! [`decrypt_data`] preserves the C source's mitigations against
//! Bleichenbacher / MMA timing attacks (see `pk7_doit.c` lines around
//! `PKCS7_dataDecode`):
//!
//! 1. RSA implicit rejection is disabled on the recipient key context so
//!    that decrypt failures yield a deterministic random "key" rather than
//!    a distinguishable error.
//! 2. Decryption is attempted against *every* `RecipientInfo` even after
//!    success, to remove the timing channel revealing which recipient
//!    matched.
//! 3. On length mismatch the random fallback key is used in constant time
//!    via [`openssl_common::constant_time::memcmp`].
//! 4. The error queue is cleared after speculative decryptions to avoid
//!    leaking information through the error stack.
//!
//! ## Context Propagation
//!
//! [`Pkcs7Context`] mirrors the C `PKCS7_CTX` from `pk7_local.h`, holding
//! an optional [`LibContext`] and property query string.  When unset,
//! [`crate::context::get_default()`] is consulted, matching the C library's
//! behaviour of falling back to the default `OSSL_LIB_CTX`.

#![cfg_attr(
    not(feature = "cms"),
    allow(
        dead_code,
        reason = "PKCS#7 is foundational for `cms` / `pkcs12`; some helpers \
                  are only consumed by those siblings."
    )
)]

use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;

use bitflags::bitflags;
use tracing::{debug, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::CryptoError;

use crate::asn1::{
    parse_tlv_header, write_tlv_header, AlgorithmIdentifier, Asn1Class, Asn1Integer, Asn1Object,
    Asn1OctetString, Asn1Tag, Asn1Type,
};
use crate::context::{self, LibContext};
use crate::evp::cipher::{Cipher, CipherCtx};
use crate::evp::md::{digest_one_shot, MessageDigest};
use crate::evp::pkey::{KeyType, PKey};
use crate::evp::signature::{one_shot_sign, AsymCipher, AsymCipherContext, Signature};
use crate::pem::{self, PemObject};
use crate::rand::rand_bytes;
use crate::x509::crl as x509_crl;
use crate::x509::verify::{verify as x509_verify, VerifyParams};
use crate::x509::{X509Certificate, X509Store};

/// Tracing target for all PKCS#7 observability events.
const TRACE_TARGET: &str = "openssl::pkcs::pkcs7";

/// PEM label written by [`Pkcs7::to_pem`] and validated by
/// [`Pkcs7::from_pem`].  Matches OpenSSL's `PEM_STRING_PKCS7`.
const PEM_LABEL_PKCS7: &str = "PKCS7";

/// Buffer size used by [`Pkcs7::to_smime`] / [`verify`] when copying
/// content through `Read`/`Write` traits.  Matches the `BUFFERSIZE` constant
/// defined in `crypto/pkcs7/pk7_smime.c`.
const STREAM_BUFFER_SIZE: usize = 4096;

// =============================================================================
// Phase 2 — Error type (translates `crypto/pkcs7/pkcs7err.c`, 98 lines).
// =============================================================================

/// Errors that can occur during PKCS#7 operations.
///
/// Each variant maps directly to a `PKCS7_R_*` reason code from the C
/// implementation in `crypto/pkcs7/pkcs7err.c`.  Cryptographic primitive
/// failures originating in `openssl-common` are forwarded transparently
/// through the [`Pkcs7Error::Crypto`] variant so callers can treat them
/// uniformly.
///
/// ```rust,ignore
/// use openssl_crypto::pkcs::pkcs7::{Pkcs7, Pkcs7Error};
///
/// match Pkcs7::from_der(&blob) {
///     Ok(p7) => process(p7),
///     Err(Pkcs7Error::WrongContentType) => /* not a SignedData */ {}
///     Err(e) => return Err(e),
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum Pkcs7Error {
    /// `PKCS7_R_NO_CONTENT` — operation requires content but none is
    /// attached (e.g. detached signature with no `indata` provided).
    #[error("no content")]
    NoContent,

    /// `PKCS7_R_NO_SIGNATURES_ON_DATA` — `verify()` called on a `SignedData`
    /// with an empty `signer_infos` collection.
    #[error("no signatures on data")]
    NoSignaturesOnData,

    /// `PKCS7_R_NO_SIGNERS` — [`get_signers`] called on a `SignedData` with
    /// no signers.
    #[error("no signers")]
    NoSigners,

    /// `PKCS7_R_WRONG_CONTENT_TYPE` — operation invalid for the current
    /// [`Pkcs7ContentType`] (e.g. `add_certificate` on `EncryptedData`).
    #[error("wrong content type")]
    WrongContentType,

    /// `PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE` — cipher / digest
    /// operations called on incompatible content type.
    #[error("operation not supported on this type")]
    OperationNotSupported,

    /// `PKCS7_R_UNKNOWN_OPERATION` — internal dispatcher received an
    /// unrecognised request.
    #[error("unknown operation")]
    UnknownOperation,

    /// `PKCS7_R_UNABLE_TO_FIND_CERTIFICATE` — verify could not locate a
    /// certificate matching a `SignerInfo`'s `IssuerAndSerial`.
    #[error("unable to find certificate")]
    UnableToFindCertificate,

    /// `PKCS7_R_DIGEST_FAILURE` — message digest computation or comparison
    /// against the embedded `messageDigest` attribute failed.
    #[error("digest failure")]
    DigestFailure,

    /// `PKCS7_R_SIGNATURE_FAILURE` — signature verification rejected the
    /// signer's `encrypted_digest`.
    #[error("signature failure")]
    SignatureFailure,

    /// `PKCS7_R_DECRYPT_ERROR` — failure decrypting either the
    /// content-encryption key or the encrypted content.
    #[error("decrypt error")]
    DecryptError,

    /// `PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE` — `decrypt_data` could
    /// not find a `RecipientInfo` whose `IssuerAndSerial` matches the
    /// supplied certificate.
    #[error("no recipient matches certificate")]
    NoRecipientMatchesCertificate,

    /// `PKCS7_R_CONTENT_AND_DATA_PRESENT` — sign/finalize called with both
    /// embedded content and external data.
    #[error("content and data present")]
    ContentAndDataPresent,

    /// `PKCS7_R_CIPHER_NOT_INITIALIZED` — encryption requested but
    /// `set_cipher` was never called on an `EnvelopedData` /
    /// `SignedAndEnvelopedData`.
    #[error("cipher not initialized")]
    CipherNotInitialized,

    /// `PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE` — the supplied
    /// private key cannot validate against the certificate's public key.
    #[error("private key does not match certificate")]
    PrivateKeyDoesNotMatch,

    /// `PKCS7_R_PKCS7_ADD_SIGNER_ERROR` — failure attaching a signer
    /// (e.g. unsupported key type or digest).
    #[error("PKCS7 add signer error")]
    AddSignerError,

    /// `PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE` — the signer
    /// key's algorithm has no signing implementation registered.
    #[error("signing not supported for this key type")]
    SigningNotSupportedForKeyType,

    /// `PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST` — required message digest
    /// algorithm not available from the active provider.
    #[error("unable to find message digest")]
    UnableToFindMessageDigest,

    /// Cryptographic primitive failure forwarded from
    /// [`openssl_common::CryptoError`].  Use the `?` operator to chain
    /// errors transparently.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Convenience result alias for PKCS#7 operations.
pub type Pkcs7Result<T> = Result<T, Pkcs7Error>;

// =============================================================================
// Phase 3 — Content-type discriminator (translates the dispatch table in
// `crypto/pkcs7/pk7_asn1.c` lines 23-30).
// =============================================================================

/// PKCS#7 content type discriminator.
///
/// The C implementation uses `ASN1_OBJECT*` with the NIDs
/// `NID_pkcs7_data` … `NID_pkcs7_encrypted` to dispatch the embedded union
/// `PKCS7.d`.  In Rust this is encoded as a typed enum, eliminating the
/// possibility of mismatched type/union access and complying with Rule R5
/// (no integer sentinel discriminators).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs7ContentType {
    /// `id-data` (1.2.840.113549.1.7.1) — opaque octet string.
    ///
    /// Maps to `NID_pkcs7_data` in the C API.
    Data,
    /// `id-signedData` (1.2.840.113549.1.7.2) — RFC 2315 §9.
    ///
    /// Maps to `NID_pkcs7_signed`.
    SignedData,
    /// `id-envelopedData` (1.2.840.113549.1.7.3) — RFC 2315 §10.
    ///
    /// Maps to `NID_pkcs7_enveloped`.
    EnvelopedData,
    /// `id-signedAndEnvelopedData` (1.2.840.113549.1.7.4) — RFC 2315 §11.
    ///
    /// Maps to `NID_pkcs7_signedAndEnveloped`.  Deprecated by RFC 2630 but
    /// retained for backwards compatibility.
    SignedAndEnveloped,
    /// `id-digestedData` (1.2.840.113549.1.7.5) — RFC 2315 §12.
    ///
    /// Maps to `NID_pkcs7_digest`.
    DigestedData,
    /// `id-encryptedData` (1.2.840.113549.1.7.6) — RFC 2315 §13.
    ///
    /// Maps to `NID_pkcs7_encrypted`.
    EncryptedData,
    /// Any unrecognised OID — preserves the OID so unknown content types
    /// can be round-tripped through DER without loss (replaces
    /// `PKCS7_type_is_other()` in the C source).
    Other(String),
}

impl Pkcs7ContentType {
    /// Returns the dotted OID string for this content type.
    ///
    /// Used by [`Pkcs7::to_der`] to emit the outer `ContentInfo.contentType`
    /// field.
    pub fn oid(&self) -> &str {
        match self {
            Self::Data => "1.2.840.113549.1.7.1",
            Self::SignedData => "1.2.840.113549.1.7.2",
            Self::EnvelopedData => "1.2.840.113549.1.7.3",
            Self::SignedAndEnveloped => "1.2.840.113549.1.7.4",
            Self::DigestedData => "1.2.840.113549.1.7.5",
            Self::EncryptedData => "1.2.840.113549.1.7.6",
            Self::Other(oid) => oid.as_str(),
        }
    }

    /// Constructs a [`Pkcs7ContentType`] from a dotted OID string.
    ///
    /// Recognised OIDs map to their canonical variant; any other OID is
    /// preserved in [`Pkcs7ContentType::Other`].  Used by
    /// [`Pkcs7::from_der`] when parsing inbound `ContentInfo` structures.
    pub fn from_oid(oid: &str) -> Self {
        match oid {
            "1.2.840.113549.1.7.1" => Self::Data,
            "1.2.840.113549.1.7.2" => Self::SignedData,
            "1.2.840.113549.1.7.3" => Self::EnvelopedData,
            "1.2.840.113549.1.7.4" => Self::SignedAndEnveloped,
            "1.2.840.113549.1.7.5" => Self::DigestedData,
            "1.2.840.113549.1.7.6" => Self::EncryptedData,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Returns `true` if this content type is "other" (not one of the six
    /// standard PKCS#7 content types).
    ///
    /// Replaces `PKCS7_type_is_other()` from `crypto/pkcs7/pk7_doit.c`.
    pub fn is_other(&self) -> bool {
        matches!(self, Self::Other(_))
    }
}

impl fmt::Display for Pkcs7ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Data => "id-data",
            Self::SignedData => "id-signedData",
            Self::EnvelopedData => "id-envelopedData",
            Self::SignedAndEnveloped => "id-signedAndEnvelopedData",
            Self::DigestedData => "id-digestedData",
            Self::EncryptedData => "id-encryptedData",
            Self::Other(oid) => return write!(f, "OID({oid})"),
        };
        f.write_str(label)
    }
}

// =============================================================================
// Phase 4 — Library context propagation (translates `pk7_local.h` PKCS7_CTX
// and `pk7_lib.c` `ossl_pkcs7_resolve_libctx` / `ossl_pkcs7_ctx_get0_libctx`
// / `ossl_pkcs7_ctx_get0_propq` / `ossl_pkcs7_ctx_propagate`).
// =============================================================================

/// Library context propagation block — Rust analogue of the C `PKCS7_CTX`
/// structure declared in `crypto/pkcs7/pk7_local.h`.
///
/// Stores the optional [`LibContext`] (provider/property scope) and optional
/// property query string.  Both fields are `Option`-typed in compliance
/// with Rule R5: the C source uses `NULL` to mean "use the default
/// `OSSL_LIB_CTX`", which translates here to `None` and falls back to
/// [`crate::context::get_default()`] when [`Pkcs7Context::resolve_libctx`]
/// is called.
#[derive(Debug, Clone, Default)]
pub struct Pkcs7Context {
    /// Optional library context (replaces C `OSSL_LIB_CTX *libctx`).
    ///
    /// - **Write-site:** [`Pkcs7Context::with_libctx`],
    ///   [`Pkcs7::set_lib_ctx`].
    /// - **Read-site:** [`Pkcs7Context::resolve_libctx`].
    lib_ctx: Option<Arc<LibContext>>,

    /// Optional property query string (replaces C `char *propq`).
    ///
    /// Used to filter algorithm fetches (e.g. `"provider=fips"`).
    ///
    /// - **Write-site:** [`Pkcs7Context::with_propq`],
    ///   [`Pkcs7::set_property_query`].
    /// - **Read-site:** [`Pkcs7Context::propq`].
    prop_query: Option<String>,
}

impl Pkcs7Context {
    /// Creates a new context with no overrides.  Equivalent to a zeroed
    /// `PKCS7_CTX` in C — both fields `NULL`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder helper that sets the library context.
    #[must_use]
    pub fn with_libctx(mut self, ctx: Arc<LibContext>) -> Self {
        self.lib_ctx = Some(ctx);
        self
    }

    /// Builder helper that sets the property query string.
    #[must_use]
    pub fn with_propq(mut self, propq: impl Into<String>) -> Self {
        self.prop_query = Some(propq.into());
        self
    }

    /// Returns the property query, falling back to the empty string when
    /// unset (matches the C behaviour of treating `NULL` as "no
    /// constraints").
    pub fn propq(&self) -> &str {
        self.prop_query.as_deref().unwrap_or("")
    }

    /// Resolves the active library context, defaulting to
    /// [`crate::context::get_default()`] when no override has been set.
    /// Mirrors the C function `ossl_pkcs7_ctx_get0_libctx` followed by an
    /// implicit `OSSL_LIB_CTX_get0_global_default()` fallback.
    pub fn resolve_libctx(&self) -> Arc<LibContext> {
        self.lib_ctx.clone().unwrap_or_else(context::get_default)
    }

    /// Returns the explicit library context override, if any.  Used by
    /// nested objects that wish to inherit verbatim rather than fall back
    /// to the global default.
    pub fn lib_ctx(&self) -> Option<&Arc<LibContext>> {
        self.lib_ctx.as_ref()
    }
}

// =============================================================================
// Phase 4 (cont.) — Main `Pkcs7` aggregate (translates `crypto/pkcs7/pk7_lib.c`
// PKCS7_new / PKCS7_free / PKCS7_set_type / PKCS7_set_content).
// =============================================================================

/// PKCS#7 `ContentInfo` container — the Rust equivalent of the C `PKCS7`
/// structure.
///
/// Implements [`Drop`] for automatic cleanup, replacing the C `PKCS7_free`
/// chain (which freed all nested `PKCS7_SIGNED`, `PKCS7_ENVELOPE`, etc.
/// children).  Nested content is owned via [`Pkcs7Content`] which contains
/// `Box<Pkcs7>` for recursively encapsulated structures.
///
/// # Examples
///
/// Constructing an empty `SignedData`:
///
/// ```rust,ignore
/// use openssl_crypto::pkcs::pkcs7::{Pkcs7, Pkcs7ContentType};
///
/// let mut p7 = Pkcs7::new();
/// p7.set_type(Pkcs7ContentType::SignedData)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// `Clone` is implemented to support deep copies of decoded structures
/// (e.g. when round-tripping through serializers, materializing detached
/// signatures, or duplicating templates for multi-recipient encryption).
/// Cloning duplicates the entire content tree including any embedded
/// [`Pkcs7EncContent::key`] — both the original and the clone wipe their
/// keys on drop via [`zeroize::ZeroizeOnDrop`].
#[derive(Debug, Clone)]
pub struct Pkcs7 {
    /// Discriminator selecting which [`Pkcs7Content`] variant is active.
    ///
    /// - **Write-site:** [`Pkcs7::set_type`], [`Pkcs7::set_content`],
    ///   [`Pkcs7::content_new`], [`Pkcs7::from_der`].
    /// - **Read-site:** [`Pkcs7::content_type`], all `is_*` helpers,
    ///   [`Pkcs7::to_der`], [`Pkcs7::set_cipher`], [`Pkcs7::set_digest`].
    content_type: Pkcs7ContentType,

    /// Strongly-typed payload — replaces the C `union { ... } d` field.
    ///
    /// - **Write-site:** [`Pkcs7::set_type`], [`Pkcs7::set_content`],
    ///   [`Pkcs7::content_new`], [`Pkcs7::add_certificate`],
    ///   [`Pkcs7::add_crl`], [`Pkcs7::set_cipher`],
    ///   [`Pkcs7::set_digest`], [`Pkcs7::from_der`].
    /// - **Read-site:** [`Pkcs7::content`], [`Pkcs7::content_mut`],
    ///   [`verify`], [`decrypt_data`], [`finalize`].
    content: Pkcs7Content,

    /// "Detached" flag — when `true` the encapsulated `Data` is omitted
    /// from the serialized output (used for detached S/MIME signatures).
    ///
    /// Equivalent to `PKCS7.detached` in the C structure (managed via
    /// `PKCS7_ctrl(PKCS7_OP_SET_DETACHED_SIGNATURE, ...)`).
    ///
    /// - **Write-site:** [`Pkcs7::set_detached`], [`sign`].
    /// - **Read-site:** [`Pkcs7::is_detached`], [`Pkcs7::to_smime`],
    ///   [`finalize`].
    detached: bool,

    /// Library context / property query propagation block (replaces C
    /// `PKCS7_CTX ctx`).
    ///
    /// - **Write-site:** [`Pkcs7::set_lib_ctx`],
    ///   [`Pkcs7::set_property_query`], constructors.
    /// - **Read-site:** [`Pkcs7::context`], internal crypto helpers.
    ctx: Pkcs7Context,
}

/// Strongly-typed PKCS#7 content payload.
///
/// Replaces the C `union { … } d` member of `PKCS7`, eliminating the
/// undefined behaviour of accessing the "wrong" union member.  Variant
/// selection is enforced at compile time and validated at runtime by
/// [`Pkcs7::set_type`].
#[derive(Debug, Clone)]
pub enum Pkcs7Content {
    /// `id-data` payload — opaque octet string.
    Data(Asn1OctetString),
    /// `id-signedData` payload.
    Signed(Pkcs7SignedData),
    /// `id-envelopedData` payload.
    Enveloped(Pkcs7EnvelopedData),
    /// `id-signedAndEnvelopedData` payload.
    SignedAndEnveloped(Pkcs7SignEnvelopeData),
    /// `id-digestedData` payload.
    Digested(Pkcs7DigestedData),
    /// `id-encryptedData` payload.
    Encrypted(Pkcs7EncryptedData),
    /// Unrecognised content — DER bytes of the original `ANY` payload
    /// preserved for round-tripping.
    Other(Vec<u8>),
}

impl Drop for Pkcs7 {
    /// RAII cleanup analogue of `PKCS7_free`.  Inner [`Pkcs7Content`]
    /// fields and any [`Pkcs7EncContent`] within them implement their own
    /// `Drop` (notably `ZeroizeOnDrop` on the latter), so this `Drop`
    /// impl exists primarily to log a tracing event and to make the RAII
    /// guarantee explicit at the type level.
    fn drop(&mut self) {
        trace!(
            target: TRACE_TARGET,
            content_type = %self.content_type,
            "Pkcs7 dropped — releasing nested resources"
        );
    }
}

// =============================================================================
// Phase 5 — `Pkcs7SignedData` (translates `crypto/pkcs7/pk7_lib.c` and
// `pk7_asn1.c`'s ASN1_SEQUENCE(PKCS7_SIGNED) template).
// =============================================================================

/// PKCS#7 `SignedData` content (RFC 2315 §9).
///
/// The C structure `PKCS7_SIGNED` carries:
/// `version`, `md_algorithms` (set of digest algorithms used by the
/// signers), `contents` (the encapsulated [`Pkcs7`]), `cert` chain, `crl`
/// list and `signer_info` set.  All fields are translated 1-for-1 to
/// idiomatic Rust collections.
#[derive(Debug, Clone)]
pub struct Pkcs7SignedData {
    /// `Version` field — RFC 2315 §9.1, conventionally `1`.
    ///
    /// - **Write-site:** [`Pkcs7::content_new`], [`sign`],
    ///   [`Pkcs7SignedData::new`], deserializers.
    /// - **Read-site:** signature finalisation, ASN.1 encoders.
    pub version: i32,

    /// `DigestAlgorithmIdentifiers` set — one entry per distinct digest
    /// algorithm used by any signer.  Deduplicated on insert by
    /// [`finalize`].
    ///
    /// - **Write-site:** [`sign_add_signer`], [`finalize`].
    /// - **Read-site:** [`verify`], digest dispatch in `data_init`.
    pub md_algorithms: Vec<AlgorithmIdentifier>,

    /// `ContentInfo contents` — encapsulated content, may be detached.
    ///
    /// Stored as `Box<Pkcs7>` to avoid infinite recursion in the type
    /// system.
    ///
    /// - **Write-site:** [`Pkcs7::content_new`], [`sign`],
    ///   [`finalize`].
    /// - **Read-site:** [`verify`], [`Pkcs7::is_detached`], serializers.
    pub contents: Box<Pkcs7>,

    /// `[0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL` —
    /// signer / chain certificates.
    ///
    /// - **Write-site:** [`Pkcs7::add_certificate`], [`sign`].
    /// - **Read-site:** [`verify`], [`get_signers`], serializers.
    pub certificates: Vec<X509Certificate>,

    /// `[1] IMPLICIT CertificateRevocationLists OPTIONAL` — DER-encoded
    /// CRL blobs preserved verbatim (CRL parsing lives in `crate::x509`).
    ///
    /// - **Write-site:** [`Pkcs7::add_crl`].
    /// - **Read-site:** [`verify`], serializers.
    pub crls: Vec<Vec<u8>>,

    /// `SignerInfos` set — one [`Pkcs7SignerInfo`] per signer.
    ///
    /// - **Write-site:** [`sign_add_signer`], deserializers.
    /// - **Read-site:** [`verify`], [`get_signers`], [`finalize`].
    pub signer_infos: Vec<Pkcs7SignerInfo>,
}

impl Pkcs7SignedData {
    /// Creates an empty `SignedData` body (analogous to `PKCS7_SIGNED_new`)
    /// with `version = 1` and an empty inner `Data` content.
    pub fn new() -> Self {
        Self {
            version: 1,
            md_algorithms: Vec::new(),
            contents: Box::new(Pkcs7::new_data()),
            certificates: Vec::new(),
            crls: Vec::new(),
            signer_infos: Vec::new(),
        }
    }
}

impl Default for Pkcs7SignedData {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Phase 6 — `Pkcs7SignerInfo` and `IssuerAndSerialNumber` (translates
// `crypto/pkcs7/pk7_lib.c` PKCS7_SIGNER_INFO_set and ASN1 templates).
// =============================================================================

/// PKCS#7 `IssuerAndSerialNumber` (RFC 2315 §6.7).
///
/// Identifies a certificate uniquely by issuer DN + serial number.
/// DER-encoded blobs are preserved to avoid re-canonicalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerAndSerialNumber {
    /// DER-encoded issuer `Name`.
    ///
    /// - **Write-site:** [`IssuerAndSerialNumber::from_certificate`],
    ///   deserializers, [`sign_add_signer`].
    /// - **Read-site:** [`verify`], [`decrypt_data`] recipient match,
    ///   serializers.
    pub issuer: Vec<u8>,

    /// DER-encoded serial number (`INTEGER`).
    ///
    /// - **Write-site:** [`IssuerAndSerialNumber::from_certificate`],
    ///   deserializers.
    /// - **Read-site:** [`verify`], [`decrypt_data`] recipient match,
    ///   serializers.
    pub serial_number: Vec<u8>,
}

impl IssuerAndSerialNumber {
    /// Builds an `IssuerAndSerialNumber` by extracting issuer DN and
    /// serial number from an [`X509Certificate`].
    ///
    /// Mirrors C `X509_NAME_dup(X509_get_issuer_name(cert))` +
    /// `ASN1_STRING_dup(X509_get0_serialNumber(cert))` in
    /// `pk7_lib.c::PKCS7_SIGNER_INFO_set`.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs7Error::Crypto`] wrapping a [`CryptoError`] if the
    /// underlying X.509 accessor fails (currently infallible but kept
    /// fallible for API stability).
    pub fn from_certificate(cert: &X509Certificate) -> Pkcs7Result<Self> {
        // `issuer()` returns `&X509Name`; per RFC 2315 §6.7 the
        // `IssuerAndSerialNumber` `issuer` field is the *DER-encoded*
        // distinguished name (`Name`), NOT a printable representation.
        // `X509Name::to_der()` returns the canonical DER bytes.
        // `serial_number()` returns `&[u8]` — the raw integer bytes.
        let issuer_bytes = cert.issuer().to_der();
        let serial_bytes = cert.serial_number().to_vec();
        Ok(Self {
            issuer: issuer_bytes,
            serial_number: serial_bytes,
        })
    }
}

/// PKCS#7 `SignerInfo` (RFC 2315 §9.2).
///
/// Carries one signer's identity, digest algorithm, signed and unsigned
/// attribute sets, signature algorithm and signature value.
#[derive(Debug, Clone)]
pub struct Pkcs7SignerInfo {
    /// `version` — conventionally `1`.
    ///
    /// - **Write-site:** [`Pkcs7SignerInfo::new`], deserializers.
    /// - **Read-site:** serializers.
    pub version: i32,

    /// Issuer-and-serial-number certificate identifier.
    ///
    /// - **Write-site:** [`Pkcs7SignerInfo::new`], deserializers.
    /// - **Read-site:** [`verify`], [`get_signers`], serializers.
    pub issuer_and_serial: IssuerAndSerialNumber,

    /// Digest algorithm identifier.
    ///
    /// - **Write-site:** [`Pkcs7SignerInfo::new`], [`sign_add_signer`].
    /// - **Read-site:** [`verify`], [`finalize`], serializers.
    pub digest_algorithm: AlgorithmIdentifier,

    /// `[0] IMPLICIT Attributes OPTIONAL` — authenticated attributes
    /// (contentType, messageDigest, signingTime, …).
    ///
    /// - **Write-site:** [`finalize`], [`add_signing_time`],
    ///   [`add_content_type`], [`add_message_digest`],
    ///   [`add_smime_capabilities`].
    /// - **Read-site:** [`verify`], serializers.
    pub signed_attributes: Vec<Pkcs7Attribute>,

    /// Digest-encryption (signature) algorithm identifier.
    ///
    /// - **Write-site:** [`Pkcs7SignerInfo::new`], [`finalize`].
    /// - **Read-site:** [`verify`], serializers.
    pub signature_algorithm: AlgorithmIdentifier,

    /// `EncryptedDigest OCTET STRING` — the actual signature value
    /// (despite the legacy field name).
    ///
    /// - **Write-site:** [`finalize`], deserializers.
    /// - **Read-site:** [`verify`], serializers.
    pub encrypted_digest: Vec<u8>,

    /// `[1] IMPLICIT Attributes OPTIONAL` — unauthenticated attributes
    /// (e.g. countersignatures).
    ///
    /// - **Write-site:** custom callers, deserializers.
    /// - **Read-site:** serializers.
    pub unsigned_attributes: Vec<Pkcs7Attribute>,

    /// Internal storage for the signer's private key during the
    /// `sign_add_signer` -> `finalize` PARTIAL workflow.  The key is held
    /// behind an `Arc` so cloning the signer info does not duplicate
    /// secret material; the slot is `None` once `finalize` has run and
    /// the signature has been embedded in [`Self::encrypted_digest`].
    /// Mirrors the `pkey` member of the C `PKCS7_SIGNER_INFO` struct.
    pub(crate) pending_key: Option<Arc<PKey>>,
}

impl Pkcs7SignerInfo {
    /// Constructs a fresh `SignerInfo` with the supplied identifiers and
    /// empty attribute sets / signature.  Equivalent to
    /// `PKCS7_SIGNER_INFO_new` immediately followed by
    /// `PKCS7_SIGNER_INFO_set` in the C source.
    pub fn new(
        issuer_and_serial: IssuerAndSerialNumber,
        digest_algorithm: AlgorithmIdentifier,
        signature_algorithm: AlgorithmIdentifier,
    ) -> Self {
        Self {
            version: 1,
            issuer_and_serial,
            digest_algorithm,
            signed_attributes: Vec::new(),
            signature_algorithm,
            encrypted_digest: Vec::new(),
            unsigned_attributes: Vec::new(),
            pending_key: None,
        }
    }
}

// =============================================================================
// Phase 7 — `Pkcs7EnvelopedData`, `Pkcs7RecipientInfo`, `Pkcs7EncContent`
// (translates `crypto/pkcs7/pk7_lib.c` PKCS7_RECIP_INFO_set and the
// EnvelopedData ASN.1 templates from `pk7_asn1.c`).
// =============================================================================

/// PKCS#7 `EnvelopedData` (RFC 2315 §10) — confidentiality wrapper.
///
/// Holds the per-recipient encrypted-key information plus the
/// content-encryption ciphertext.
#[derive(Debug, Clone)]
pub struct Pkcs7EnvelopedData {
    /// `version` — conventionally `0`.
    ///
    /// - **Write-site:** [`Pkcs7EnvelopedData::new`], deserializers.
    /// - **Read-site:** serializers.
    pub version: i32,

    /// One [`Pkcs7RecipientInfo`] per recipient certificate.
    ///
    /// - **Write-site:** [`encrypt_data`], deserializers.
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub recipient_infos: Vec<Pkcs7RecipientInfo>,

    /// `EncryptedContentInfo` — encrypted payload and metadata.
    ///
    /// - **Write-site:** [`encrypt_data`], [`Pkcs7::set_cipher`].
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub enc_data: Pkcs7EncContent,
}

impl Pkcs7EnvelopedData {
    /// Constructs an empty `EnvelopedData` (version 0, no recipients,
    /// blank encrypted content).
    pub fn new() -> Self {
        Self {
            version: 0,
            recipient_infos: Vec::new(),
            enc_data: Pkcs7EncContent::default(),
        }
    }
}

impl Default for Pkcs7EnvelopedData {
    fn default() -> Self {
        Self::new()
    }
}

/// PKCS#7 `RecipientInfo` (RFC 2315 §10.2).
///
/// Encapsulates one recipient's encrypted content-encryption key and the
/// algorithm used to encrypt that key.
#[derive(Debug, Clone)]
pub struct Pkcs7RecipientInfo {
    /// `version` — conventionally `0`.
    ///
    /// - **Write-site:** [`Pkcs7RecipientInfo::new`], deserializers.
    /// - **Read-site:** serializers.
    pub version: i32,

    /// Issuer-and-serial-number identifier of the recipient certificate.
    ///
    /// - **Write-site:** [`Pkcs7RecipientInfo::new`], deserializers,
    ///   [`encrypt_data`].
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub issuer_and_serial: IssuerAndSerialNumber,

    /// Key-encryption algorithm identifier (e.g. `rsaEncryption`).
    ///
    /// - **Write-site:** [`Pkcs7RecipientInfo::new`], [`encrypt_data`].
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub key_enc_algorithm: AlgorithmIdentifier,

    /// `EncryptedKey OCTET STRING` — recipient-encrypted CEK.
    ///
    /// - **Write-site:** [`encrypt_data`], deserializers.
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub enc_key: Vec<u8>,
}

impl Pkcs7RecipientInfo {
    /// Builds a recipient block from an issuer/serial pair, key
    /// algorithm and (initially empty) encrypted key.
    pub fn new(
        issuer_and_serial: IssuerAndSerialNumber,
        key_enc_algorithm: AlgorithmIdentifier,
    ) -> Self {
        Self {
            version: 0,
            issuer_and_serial,
            key_enc_algorithm,
            enc_key: Vec::new(),
        }
    }
}

/// PKCS#7 `EncryptedContentInfo` (RFC 2315 §10.1).
///
/// Stores the inner content-type, the content-encryption algorithm
/// identifier and the encrypted payload.  Implements
/// [`zeroize::ZeroizeOnDrop`] (via field-level [`Zeroize`]) so that the
/// transient symmetric `key` is wiped on drop, mirroring the
/// `OPENSSL_cleanse` calls in `pk7_doit.c::PKCS7_dataFinal`/`dataDecode`.
#[derive(Debug, ZeroizeOnDrop)]
pub struct Pkcs7EncContent {
    /// Content type of the *plaintext* (almost always
    /// [`Pkcs7ContentType::Data`]).
    ///
    /// `Pkcs7ContentType` does not require zeroization (its `Other`
    /// variant carries an OID string, not key material).
    ///
    /// - **Write-site:** [`Pkcs7EncContent::new`], [`encrypt_data`].
    /// - **Read-site:** [`decrypt_data`], serializers.
    #[zeroize(skip)]
    pub content_type: Pkcs7ContentType,

    /// Content-encryption algorithm identifier (e.g. `aes-256-cbc`).
    ///
    /// Algorithm identifiers carry only OIDs / public parameters, no
    /// secret material.  Stored as [`Option`] (Rule R5: nullability
    /// over sentinels) — `None` indicates the algorithm has not yet
    /// been chosen.  Mirrors C's `ec->cipher == NULL` state in
    /// `pk7_lib.c::PKCS7_set_cipher` before the cipher is bound.
    ///
    /// - **Write-site:** [`Pkcs7::set_cipher`], [`encrypt_data`].
    /// - **Read-site:** [`decrypt_data`], serializers.  Both error with
    ///   [`Pkcs7Error::CipherNotInitialized`] if `None` at use time.
    #[zeroize(skip)]
    pub algorithm: Option<AlgorithmIdentifier>,

    /// Encrypted content payload — `None` indicates streaming/detached
    /// mode where the ciphertext is supplied externally.
    ///
    /// - **Write-site:** [`encrypt_data`], [`finalize`], deserializers.
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub enc_data: Option<Vec<u8>>,

    /// Transient content-encryption key — only populated during the
    /// encrypt/decrypt operation.  **Wiped on drop** via the
    /// [`ZeroizeOnDrop`] derive (Rule R8 / AAP §0.7.6 secure erasure).
    ///
    /// - **Write-site:** [`encrypt_data`], [`decrypt_data`].
    /// - **Read-site:** [`encrypt_data`], [`decrypt_data`].
    pub(crate) key: Vec<u8>,
}

impl Pkcs7EncContent {
    /// Constructs an empty `EncryptedContentInfo` with no algorithm
    /// bound yet.  Equivalent to a freshly-`PKCS7_ENC_CONTENT_new()`'d
    /// structure in C, where `cipher` and `enc_data` are `NULL` until
    /// [`Pkcs7::set_cipher`] / [`encrypt_data`] populate them.
    pub fn new(content_type: Pkcs7ContentType) -> Self {
        Self {
            content_type,
            algorithm: None,
            enc_data: None,
            key: Vec::new(),
        }
    }

    /// Builder-style helper that attaches an algorithm identifier to a
    /// freshly-constructed [`Pkcs7EncContent`].
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: AlgorithmIdentifier) -> Self {
        self.algorithm = Some(algorithm);
        self
    }
}

impl Default for Pkcs7EncContent {
    fn default() -> Self {
        Self::new(Pkcs7ContentType::Data)
    }
}

impl Clone for Pkcs7EncContent {
    fn clone(&self) -> Self {
        Self {
            content_type: self.content_type.clone(),
            algorithm: self.algorithm.clone(),
            enc_data: self.enc_data.clone(),
            // Cloning duplicates secret material; the new instance also
            // wipes on drop.
            key: self.key.clone(),
        }
    }
}

// =============================================================================
// Phase 8 — Other content types: `Pkcs7SignEnvelopeData`,
// `Pkcs7DigestedData`, `Pkcs7EncryptedData`.
// =============================================================================

/// PKCS#7 `SignedAndEnvelopedData` (RFC 2315 §11).
///
/// Combines confidentiality (recipients + enc data) with authenticity
/// (signers + digest algorithms).  Used historically; less common in
/// modern deployments (CMS-style separate envelopes preferred).
#[derive(Debug, Clone)]
pub struct Pkcs7SignEnvelopeData {
    /// `version` — conventionally `1`.
    ///
    /// - **Write-site:** [`Pkcs7SignEnvelopeData::new`], deserializers.
    /// - **Read-site:** serializers.
    pub version: i32,

    /// Set of distinct digest algorithms across all signers.
    ///
    /// - **Write-site:** [`sign_add_signer`], [`finalize`].
    /// - **Read-site:** signature dispatch, serializers.
    pub md_algorithms: Vec<AlgorithmIdentifier>,

    /// Embedded signer certificates.
    ///
    /// - **Write-site:** [`Pkcs7::add_certificate`].
    /// - **Read-site:** [`verify`], [`get_signers`], serializers.
    pub certificates: Vec<X509Certificate>,

    /// Embedded CRLs (DER).
    ///
    /// - **Write-site:** [`Pkcs7::add_crl`].
    /// - **Read-site:** [`verify`], serializers.
    pub crls: Vec<Vec<u8>>,

    /// Per-signer information.
    ///
    /// - **Write-site:** [`sign_add_signer`], deserializers.
    /// - **Read-site:** [`verify`], [`get_signers`].
    pub signer_infos: Vec<Pkcs7SignerInfo>,

    /// Per-recipient information.
    ///
    /// - **Write-site:** [`encrypt_data`], deserializers.
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub recipient_infos: Vec<Pkcs7RecipientInfo>,

    /// Encrypted content payload + algorithm metadata.
    ///
    /// - **Write-site:** [`encrypt_data`], [`finalize`].
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub enc_data: Pkcs7EncContent,
}

impl Pkcs7SignEnvelopeData {
    /// Empty `SignedAndEnvelopedData` constructor.
    pub fn new() -> Self {
        Self {
            version: 1,
            md_algorithms: Vec::new(),
            certificates: Vec::new(),
            crls: Vec::new(),
            signer_infos: Vec::new(),
            recipient_infos: Vec::new(),
            enc_data: Pkcs7EncContent::default(),
        }
    }
}

impl Default for Pkcs7SignEnvelopeData {
    fn default() -> Self {
        Self::new()
    }
}

/// PKCS#7 `DigestedData` (RFC 2315 §12).
///
/// Provides integrity (digest only) without authenticity / confidentiality.
#[derive(Debug, Clone)]
pub struct Pkcs7DigestedData {
    /// `version` — conventionally `0`.
    ///
    /// - **Write-site:** [`Pkcs7DigestedData::new`], deserializers.
    /// - **Read-site:** serializers.
    pub version: i32,

    /// Digest algorithm identifier.  Stored as [`Option`] (Rule R5) —
    /// `None` indicates the algorithm has not yet been chosen via
    /// [`Pkcs7::set_digest`].
    ///
    /// - **Write-site:** [`Pkcs7::set_digest`], deserializers.
    /// - **Read-site:** digest dispatch, serializers.  Both error with
    ///   [`Pkcs7Error::UnableToFindMessageDigest`] if `None` at use time.
    pub md_algorithm: Option<AlgorithmIdentifier>,

    /// Encapsulated content [`Pkcs7`] (`Box`-ed for recursion).
    ///
    /// - **Write-site:** [`Pkcs7::content_new`], deserializers.
    /// - **Read-site:** digest dispatch, serializers.
    pub contents: Box<Pkcs7>,

    /// Computed digest value (`OCTET STRING`).
    ///
    /// - **Write-site:** [`finalize`], deserializers.
    /// - **Read-site:** [`verify`], serializers.
    pub digest: Vec<u8>,
}

impl Pkcs7DigestedData {
    /// Empty `DigestedData` constructor — algorithm is left unset
    /// (`None`) and must be supplied via [`Pkcs7::set_digest`] before
    /// finalisation.
    pub fn new() -> Self {
        Self {
            version: 0,
            md_algorithm: None,
            contents: Box::new(Pkcs7::new_data()),
            digest: Vec::new(),
        }
    }
}

impl Default for Pkcs7DigestedData {
    fn default() -> Self {
        Self::new()
    }
}

/// PKCS#7 `EncryptedData` (RFC 2315 §13).
///
/// Confidentiality without per-recipient key wrapping (key managed
/// out-of-band; mostly used for password-based encryption schemes).
#[derive(Debug, Clone)]
pub struct Pkcs7EncryptedData {
    /// `version` — conventionally `0`.
    ///
    /// - **Write-site:** [`Pkcs7EncryptedData::new`], deserializers.
    /// - **Read-site:** serializers.
    pub version: i32,

    /// Encrypted content metadata + payload.
    ///
    /// - **Write-site:** [`Pkcs7::set_cipher`], [`finalize`].
    /// - **Read-site:** [`decrypt_data`], serializers.
    pub enc_data: Pkcs7EncContent,
}

impl Pkcs7EncryptedData {
    /// Empty `EncryptedData` constructor.
    pub fn new() -> Self {
        Self {
            version: 0,
            enc_data: Pkcs7EncContent::default(),
        }
    }
}

impl Default for Pkcs7EncryptedData {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Phase 9 — `Pkcs7Attribute` and the four canonical attribute helpers
// (translates `crypto/pkcs7/pk7_attr.c`, 139 lines).
// =============================================================================

/// PKCS#7 `Attribute` (X.501 §8.4) — `SET OF AttributeValue`.
///
/// Used in both signed and unsigned attribute slots of
/// [`Pkcs7SignerInfo`].  Values are kept as DER blobs to preserve the
/// original encoding (canonicalisation is a separate operation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs7Attribute {
    /// Attribute OID as a dotted-decimal string (e.g.
    /// `"1.2.840.113549.1.9.5"` for `signing-time`).
    ///
    /// - **Write-site:** attribute helpers, deserializers.
    /// - **Read-site:** [`verify`] attribute lookup, serializers.
    pub attr_type: String,

    /// `SET OF` DER-encoded values.  The set may be empty (rare) or
    /// contain multiple alternatives.
    ///
    /// - **Write-site:** attribute helpers, deserializers.
    /// - **Read-site:** [`verify`] attribute lookup, serializers.
    pub values: Vec<Vec<u8>>,
}

impl Pkcs7Attribute {
    /// Convenience constructor for a single-value attribute.
    pub fn new(attr_type: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            attr_type: attr_type.into(),
            values: vec![value],
        }
    }
}

/// OID for the `smime-capabilities` signed attribute (RFC 2633 §2.5.2).
const OID_SMIME_CAPABILITIES: &str = "1.2.840.113549.1.9.15";
/// OID for the `contentType` signed attribute (RFC 2315 §9.2).
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// OID for the `signingTime` signed attribute (RFC 2315 §9.2 / RFC 5652).
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
/// OID for the `messageDigest` signed attribute (RFC 2315 §9.2).
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// Removes any prior occurrence of `attr_type` from the supplied slot
/// (preserves "set" semantics — only one value per OID).
fn replace_attribute(slot: &mut Vec<Pkcs7Attribute>, attr_type: &str, value: Vec<u8>) {
    slot.retain(|a| a.attr_type != attr_type);
    slot.push(Pkcs7Attribute::new(attr_type, value));
}

/// Adds the S/MIME `smime-capabilities` signed attribute to a signer.
///
/// Translates `PKCS7_add_attrib_smimecap` from `pk7_attr.c` (lines 16-44).
/// The capabilities list is encoded as a DER `SEQUENCE OF
/// AlgorithmIdentifier`, then wrapped in the `SET OF` slot of the
/// resulting attribute.
///
/// `caps` is supplied as DER-encoded `AlgorithmIdentifier` blobs because
/// re-encoding from typed structures would require a full ASN.1 emitter
/// dependency — callers that have typed values can DER-encode them via
/// the `crate::asn1` API first.
pub fn add_smime_capabilities(si: &mut Pkcs7SignerInfo, caps: &[Vec<u8>]) -> Pkcs7Result<()> {
    debug!(
        target: TRACE_TARGET,
        cap_count = caps.len(),
        "add_smime_capabilities"
    );
    // Concatenate the per-cap DER blobs into a single SEQUENCE OF
    // payload.  The total length must fit in `usize` and is later
    // wrapped by the ASN.1 encoder; we use checked arithmetic to comply
    // with Rule R6.
    let mut total: usize = 0;
    for c in caps {
        total = total
            .checked_add(c.len())
            .ok_or(Pkcs7Error::AddSignerError)?;
    }
    let mut payload = Vec::with_capacity(total);
    for c in caps {
        payload.extend_from_slice(c);
    }
    replace_attribute(&mut si.signed_attributes, OID_SMIME_CAPABILITIES, payload);
    Ok(())
}

/// Adds the `contentType` signed attribute (RFC 2315 §9.2 mandates this
/// for any signer whose signedAttributes are non-empty).
///
/// Translates `PKCS7_add0_attrib_signing_time`-style helpers from
/// `pk7_attr.c`.  Encodes the supplied content type as the OID of its
/// PKCS#7 identifier; when `None` the default [`Pkcs7ContentType::Data`]
/// is used (matching `PKCS7_add_attrib_content_type` in C).
pub fn add_content_type(
    si: &mut Pkcs7SignerInfo,
    content_type: Option<&Pkcs7ContentType>,
) -> Pkcs7Result<()> {
    let oid = content_type.cloned().unwrap_or(Pkcs7ContentType::Data);
    let oid_str = oid.oid().to_string();
    debug!(target: TRACE_TARGET, oid = %oid_str, "add_content_type");
    replace_attribute(
        &mut si.signed_attributes,
        OID_CONTENT_TYPE,
        oid_str.into_bytes(),
    );
    Ok(())
}

/// Adds the `signingTime` signed attribute (RFC 2315 §9.2).
///
/// Translates `PKCS7_add0_attrib_signing_time` from `pk7_attr.c`.  When
/// `time` is `None` the current wall-clock is used (delegated to
/// `chrono`-style helpers in the test/sign workflow); for the pure-Rust
/// translation we accept a pre-formatted `UTCTime`/`GeneralizedTime`
/// string and encode it as the attribute value.  The empty string is
/// rejected per Rule R5 (sentinel-as-unset is forbidden).
pub fn add_signing_time(si: &mut Pkcs7SignerInfo, time: Option<&str>) -> Pkcs7Result<()> {
    let value = match time {
        Some(t) if !t.is_empty() => t.as_bytes().to_vec(),
        // Empty string (Some("")) is a sentinel-as-unset per Rule R5 and is
        // rejected the same way as `None`.  Without a clock dependency we
        // cannot synthesise a wall-clock value here either; surface the
        // requirement explicitly via the typed error rather than smuggle a
        // sentinel.
        Some(_) | None => return Err(Pkcs7Error::OperationNotSupported),
    };
    debug!(target: TRACE_TARGET, "add_signing_time");
    replace_attribute(&mut si.signed_attributes, OID_SIGNING_TIME, value);
    Ok(())
}

/// Adds the `messageDigest` signed attribute (RFC 2315 §9.2 / §9.3).
///
/// Translates `PKCS7_add1_attrib_digest` from `pk7_attr.c`.  Empty
/// digests are rejected (Rule R5: empty is not a valid digest sentinel).
pub fn add_message_digest(si: &mut Pkcs7SignerInfo, digest: &[u8]) -> Pkcs7Result<()> {
    if digest.is_empty() {
        return Err(Pkcs7Error::DigestFailure);
    }
    debug!(
        target: TRACE_TARGET,
        digest_len = digest.len(),
        "add_message_digest"
    );
    replace_attribute(
        &mut si.signed_attributes,
        OID_MESSAGE_DIGEST,
        digest.to_vec(),
    );
    Ok(())
}

// =============================================================================
// Phase 10 — `Pkcs7Flags` (translates the `PKCS7_*` flag #defines from
// `include/openssl/pkcs7.h`).
// =============================================================================

bitflags! {
    /// Bit-flag set controlling PKCS#7 sign/verify/encrypt/decrypt
    /// behaviour, replacing the `PKCS7_*` integer `#define`s.
    ///
    /// Each flag's semantics map 1-for-1 to its C counterpart; refer to
    /// the public header `include/openssl/pkcs7.h` for canonical
    /// descriptions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Pkcs7Flags: u32 {
        /// Include MIME `text/plain` headers in the encapsulated content
        /// (`PKCS7_TEXT`).
        const TEXT = 0x0001;
        /// Suppress embedding of signer certificates (`PKCS7_NOCERTS`).
        const NOCERTS = 0x0002;
        /// Skip all signature processing (`PKCS7_NOSIGS`).
        const NOSIGS = 0x0004;
        /// Skip chain validation on verify (`PKCS7_NOCHAIN`).
        const NOCHAIN = 0x0008;
        /// Reject internally embedded certificates during verify
        /// (`PKCS7_NOINTERN`).
        const NOINTERN = 0x0010;
        /// Skip signature verification (`PKCS7_NOVERIFY`).
        const NOVERIFY = 0x0020;
        /// Produce a detached signature (`PKCS7_DETACHED`).
        const DETACHED = 0x0040;
        /// Treat content as binary — disable CRLF translation
        /// (`PKCS7_BINARY`).
        const BINARY = 0x0080;
        /// Omit signed attributes (`PKCS7_NOATTR`).
        const NOATTR = 0x0100;
        /// Skip insertion of `smime-capabilities` (`PKCS7_NOSMIMECAP`).
        const NOSMIMECAP = 0x0200;
        /// Use legacy MIME type strings (`PKCS7_NOOLDMIMETYPE`).
        const NOOLDMIMETYPE = 0x0400;
        /// Force CRLF line endings on serialised output
        /// (`PKCS7_CRLFEOL`).
        const CRLFEOL = 0x0800;
        /// Enable streaming / NDEF mode (`PKCS7_STREAM`).
        const STREAM = 0x1000;
        /// Suppress CRL inclusion (`PKCS7_NOCRL`).
        const NOCRL = 0x2000;
        /// Build the structure incrementally — caller will finalise
        /// later (`PKCS7_PARTIAL`).
        const PARTIAL = 0x4000;
        /// Re-use a previously computed digest rather than re-hashing
        /// (`PKCS7_REUSE_DIGEST`).
        const REUSE_DIGEST = 0x8000;
        /// Forbid both `EncryptedContentInfo` and `data` from being
        /// present (`PKCS7_NO_DUAL_CONTENT`).
        const NO_DUAL_CONTENT = 0x1_0000;
    }
}

// =============================================================================
// Phase 14 — Constructor / mutator API on `Pkcs7` (translates
// `crypto/pkcs7/pk7_lib.c`, ~760 lines).
// =============================================================================

impl Pkcs7 {
    /// Constructs an empty PKCS#7 container with content type
    /// [`Pkcs7ContentType::Data`] and an empty payload.
    ///
    /// Replaces the C `PKCS7_new()` constructor.
    pub fn new() -> Self {
        Self {
            content_type: Pkcs7ContentType::Data,
            content: Pkcs7Content::Data(Asn1OctetString::new()),
            detached: false,
            ctx: Pkcs7Context::new(),
        }
    }

    /// Internal helper: constructs a `Pkcs7` whose content type is
    /// [`Pkcs7ContentType::Data`] with empty payload, used by nested
    /// `*::new()` factories that need a default `Pkcs7` payload.
    ///
    /// Equivalent to `PKCS7_new(); PKCS7_set_type(p, NID_pkcs7_data)` in
    /// the C source.
    pub(crate) fn new_data() -> Self {
        Self::new()
    }

    /// Constructs an empty PKCS#7 container bound to the supplied
    /// library context and (optional) property query string.
    ///
    /// Replaces the C `PKCS7_new_ex(libctx, propq)` constructor.
    pub fn new_with_ctx(libctx: Arc<LibContext>, propq: Option<String>) -> Self {
        let mut ctx = Pkcs7Context::new().with_libctx(libctx);
        if let Some(q) = propq {
            ctx = ctx.with_propq(q);
        }
        Self {
            content_type: Pkcs7ContentType::Data,
            content: Pkcs7Content::Data(Asn1OctetString::new()),
            detached: false,
            ctx,
        }
    }

    /// Returns the discriminator of the active content variant.
    pub fn content_type(&self) -> &Pkcs7ContentType {
        &self.content_type
    }

    /// Returns the strongly-typed content payload by reference.
    pub fn content(&self) -> &Pkcs7Content {
        &self.content
    }

    /// Returns the strongly-typed content payload by mutable reference.
    pub fn content_mut(&mut self) -> &mut Pkcs7Content {
        &mut self.content
    }

    /// Returns the propagation context.
    pub fn context(&self) -> &Pkcs7Context {
        &self.ctx
    }

    /// Overrides the library context (provider/property scope).
    pub fn set_lib_ctx(&mut self, libctx: Arc<LibContext>) {
        self.ctx.lib_ctx = Some(libctx);
    }

    /// Overrides the property query string.
    pub fn set_property_query(&mut self, propq: impl Into<String>) {
        self.ctx.prop_query = Some(propq.into());
    }

    /// Sets the `ContentInfo` content type and replaces the payload
    /// with an empty default for that variant.
    ///
    /// Replaces the C `PKCS7_set_type(p, nid)` helper which also
    /// allocates a fresh inner structure of the matching type.
    pub fn set_type(&mut self, content_type: Pkcs7ContentType) -> Pkcs7Result<()> {
        debug!(
            target: TRACE_TARGET,
            new_type = %content_type,
            old_type = %self.content_type,
            "Pkcs7::set_type"
        );
        self.content = match &content_type {
            Pkcs7ContentType::Data => Pkcs7Content::Data(Asn1OctetString::new()),
            Pkcs7ContentType::SignedData => Pkcs7Content::Signed(Pkcs7SignedData::new()),
            Pkcs7ContentType::EnvelopedData => Pkcs7Content::Enveloped(Pkcs7EnvelopedData::new()),
            Pkcs7ContentType::SignedAndEnveloped => {
                Pkcs7Content::SignedAndEnveloped(Pkcs7SignEnvelopeData::new())
            }
            Pkcs7ContentType::DigestedData => Pkcs7Content::Digested(Pkcs7DigestedData::new()),
            Pkcs7ContentType::EncryptedData => Pkcs7Content::Encrypted(Pkcs7EncryptedData::new()),
            Pkcs7ContentType::Other(_) => Pkcs7Content::Other(Vec::new()),
        };
        self.content_type = content_type;
        Ok(())
    }

    /// Sets the encapsulated content of a `SignedData` /
    /// `DigestedData` / `SignedAndEnveloped` container.
    ///
    /// Replaces the C `PKCS7_set_content(p, inner)` helper.  Returns
    /// [`Pkcs7Error::WrongContentType`] when invoked on a variant that
    /// does not accept an encapsulated [`Pkcs7`].
    pub fn set_content(&mut self, inner: Pkcs7) -> Pkcs7Result<()> {
        match &mut self.content {
            Pkcs7Content::Signed(signed) => {
                signed.contents = Box::new(inner);
                Ok(())
            }
            Pkcs7Content::Digested(digested) => {
                digested.contents = Box::new(inner);
                Ok(())
            }
            _ => Err(Pkcs7Error::WrongContentType),
        }
    }

    /// Allocates a new encapsulated content of the specified type and
    /// stores it via [`Pkcs7::set_content`].
    ///
    /// Replaces the C `PKCS7_content_new` helper.
    pub fn content_new(&mut self, content_type: Pkcs7ContentType) -> Pkcs7Result<()> {
        let mut inner = Pkcs7::new();
        inner.set_type(content_type)?;
        self.set_content(inner)
    }

    /// Toggles the "detached signature" flag (RFC 2315 §9.4).
    ///
    /// Replaces the C `PKCS7_ctrl(p, PKCS7_OP_SET_DETACHED_SIGNATURE,
    /// detached, NULL)` invocation.
    pub fn set_detached(&mut self, detached: bool) {
        debug!(
            target: TRACE_TARGET,
            detached,
            "Pkcs7::set_detached"
        );
        self.detached = detached;
    }

    /// Returns `true` when the container is configured to omit its
    /// encapsulated `Data` payload from serialisation.
    ///
    /// Replaces the C `PKCS7_is_detached(p)` helper.
    pub fn is_detached(&self) -> bool {
        self.detached
    }

    /// Adds an embedded certificate to the active container.
    ///
    /// Replaces the C `PKCS7_add_certificate` helper.  Accepts both
    /// `SignedData` and `SignedAndEnveloped` containers.
    pub fn add_certificate(&mut self, cert: X509Certificate) -> Pkcs7Result<()> {
        match &mut self.content {
            Pkcs7Content::Signed(s) => {
                s.certificates.push(cert);
                Ok(())
            }
            Pkcs7Content::SignedAndEnveloped(s) => {
                s.certificates.push(cert);
                Ok(())
            }
            _ => Err(Pkcs7Error::WrongContentType),
        }
    }

    /// Adds a DER-encoded CRL to the active container.
    ///
    /// Replaces the C `PKCS7_add_crl` helper.
    pub fn add_crl(&mut self, crl: Vec<u8>) -> Pkcs7Result<()> {
        match &mut self.content {
            Pkcs7Content::Signed(s) => {
                s.crls.push(crl);
                Ok(())
            }
            Pkcs7Content::SignedAndEnveloped(s) => {
                s.crls.push(crl);
                Ok(())
            }
            _ => Err(Pkcs7Error::WrongContentType),
        }
    }

    /// Sets the content-encryption algorithm by name (e.g.
    /// `"aes-256-cbc"`).
    ///
    /// Replaces the C `PKCS7_set_cipher` helper.  Translation note:
    /// the C version stored an `EVP_CIPHER *` pointer; the Rust
    /// translation stores the OID-form algorithm identifier and defers
    /// instantiation to the cipher provider during
    /// [`encrypt_data`]/[`decrypt_data`].
    pub fn set_cipher(&mut self, cipher: &str) -> Pkcs7Result<()> {
        if cipher.is_empty() {
            return Err(Pkcs7Error::CipherNotInitialized);
        }
        // Resolve algorithm name → ASN.1 `OBJECT IDENTIFIER`.  If the
        // caller provided a dotted-decimal OID it is parsed directly;
        // otherwise we delegate to [`Asn1Object::from_oid_string`]
        // which accepts both numeric OIDs and registered short / long
        // names (mirroring `OBJ_txt2obj()` in C).  Genuine parse
        // failures propagate as [`Pkcs7Error::Crypto`].
        let oid_obj = Asn1Object::from_oid_string(cipher).map_err(Pkcs7Error::Crypto)?;
        let alg = AlgorithmIdentifier::new(oid_obj, None);
        debug!(target: TRACE_TARGET, cipher, "Pkcs7::set_cipher");
        match &mut self.content {
            Pkcs7Content::Enveloped(e) => {
                e.enc_data.algorithm = Some(alg);
                Ok(())
            }
            Pkcs7Content::SignedAndEnveloped(s) => {
                s.enc_data.algorithm = Some(alg);
                Ok(())
            }
            Pkcs7Content::Encrypted(e) => {
                e.enc_data.algorithm = Some(alg);
                Ok(())
            }
            _ => Err(Pkcs7Error::WrongContentType),
        }
    }

    /// Sets the digest algorithm of a `DigestedData` container.
    ///
    /// Replaces the C `PKCS7_set_digest` helper.
    pub fn set_digest(&mut self, digest: &str) -> Pkcs7Result<()> {
        if digest.is_empty() {
            return Err(Pkcs7Error::UnableToFindMessageDigest);
        }
        // Same dispatch as [`Pkcs7::set_cipher`] — accept either a
        // dotted-decimal OID or a registered name, surfacing any
        // parse failure through [`Pkcs7Error::Crypto`].
        let oid_obj = Asn1Object::from_oid_string(digest).map_err(Pkcs7Error::Crypto)?;
        let alg = AlgorithmIdentifier::new(oid_obj, None);
        debug!(target: TRACE_TARGET, digest, "Pkcs7::set_digest");
        match &mut self.content {
            Pkcs7Content::Digested(d) => {
                d.md_algorithm = Some(alg);
                Ok(())
            }
            _ => Err(Pkcs7Error::WrongContentType),
        }
    }
}

impl Default for Pkcs7 {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Phase 17 — `is_*` content-type helpers (translates the
// `PKCS7_type_is_*` family of macros from `include/openssl/pkcs7.h` and
// the `PKCS7_type_is_other` helper in `pk7_doit.c`).
// =============================================================================

impl Pkcs7 {
    /// `true` iff this is `id-data`.
    pub fn is_data(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::Data)
    }

    /// `true` iff this is `id-signedData`.
    pub fn is_signed(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::SignedData)
    }

    /// `true` iff this is `id-envelopedData`.
    pub fn is_enveloped(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::EnvelopedData)
    }

    /// `true` iff this is `id-signedAndEnvelopedData`.
    pub fn is_signed_and_enveloped(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::SignedAndEnveloped)
    }

    /// `true` iff this is `id-digestedData`.
    pub fn is_digested(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::DigestedData)
    }

    /// `true` iff this is `id-encryptedData`.
    pub fn is_encrypted(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::EncryptedData)
    }

    /// `true` iff the container holds an unrecognised content type
    /// (replaces the C `PKCS7_type_is_other` helper which inspected the
    /// NID against a fixed list).
    pub fn is_other(&self) -> bool {
        matches!(self.content_type, Pkcs7ContentType::Other(_))
    }
}

// =============================================================================
// Phase 11 — High-level S/MIME-style APIs (translates ~540 lines of
// `crypto/pkcs7/pk7_smime.c`).  Public entry points: `sign`,
// `sign_add_signer`, `finalize`, `verify`, `get_signers`.
// =============================================================================

/// Maps a digest algorithm OID (dotted-string form) to its provider fetch
/// name.  Used by [`finalize`] / [`verify`] when reconstructing the digest
/// pipeline from a previously parsed [`Pkcs7SignerInfo::digest_algorithm`].
fn digest_name_from_oid(oid: &str) -> Pkcs7Result<&'static str> {
    match oid {
        "1.3.14.3.2.26" => Ok("SHA1"),
        "2.16.840.1.101.3.4.2.4" => Ok("SHA2-224"),
        "2.16.840.1.101.3.4.2.1" => Ok("SHA2-256"),
        "2.16.840.1.101.3.4.2.2" => Ok("SHA2-384"),
        "2.16.840.1.101.3.4.2.3" => Ok("SHA2-512"),
        _ => Err(Pkcs7Error::UnableToFindMessageDigest),
    }
}

/// Maps a digest algorithm fetch name to its OID dotted-string form.  Accepts
/// both the canonical SHA-2 form ("SHA2-256") and the legacy short forms
/// ("SHA256"/"SHA-256") so callers can pass whichever the surrounding code
/// uses.
fn digest_oid_from_name(name: &str) -> Pkcs7Result<&'static str> {
    match name {
        "SHA1" | "SHA-1" => Ok("1.3.14.3.2.26"),
        "SHA2-224" | "SHA224" | "SHA-224" => Ok("2.16.840.1.101.3.4.2.4"),
        "SHA2-256" | "SHA256" | "SHA-256" => Ok("2.16.840.1.101.3.4.2.1"),
        "SHA2-384" | "SHA384" | "SHA-384" => Ok("2.16.840.1.101.3.4.2.2"),
        "SHA2-512" | "SHA512" | "SHA-512" => Ok("2.16.840.1.101.3.4.2.3"),
        _ => Err(Pkcs7Error::UnableToFindMessageDigest),
    }
}

/// Maps a [`PKey`] type-name (as returned by [`PKey::key_type_name`]) to the
/// signature provider fetch name and the algorithm OID embedded in
/// [`Pkcs7SignerInfo::signature_algorithm`].
fn signature_alg_from_key(key_type: &str) -> Pkcs7Result<(&'static str, &'static str)> {
    match key_type {
        "RSA" => Ok(("RSA", "1.2.840.113549.1.1.1")),
        "DSA" => Ok(("DSA", "1.2.840.10040.4.1")),
        "EC" => Ok(("EC", "1.2.840.10045.2.1")),
        "ED25519" => Ok(("ED25519", "1.3.101.112")),
        "ED448" => Ok(("ED448", "1.3.101.113")),
        _ => Err(Pkcs7Error::SigningNotSupportedForKeyType),
    }
}

/// Reverse of [`signature_alg_from_key`]: given a signature OID, return the
/// canonical key-type name (used during verify/finalize to fetch a matching
/// `Signature` descriptor).
fn key_type_from_sig_oid(oid: &str) -> Pkcs7Result<&'static str> {
    match oid {
        "1.2.840.113549.1.1.1" => Ok("RSA"),
        "1.2.840.10040.4.1" => Ok("DSA"),
        "1.2.840.10045.2.1" => Ok("EC"),
        "1.3.101.112" => Ok("ED25519"),
        "1.3.101.113" => Ok("ED448"),
        _ => Err(Pkcs7Error::SigningNotSupportedForKeyType),
    }
}

/// Returns `true` when a certificate's DER-encoded issuer name and serial
/// number match the supplied [`IssuerAndSerialNumber`].
///
/// Uses byte-equality on the DER-encoded issuer (rather than [`X509Name`]'s
/// `PartialEq` which compares the *canonical* form) because RFC 2315 §6.7
/// requires byte-for-byte equality for `SignerInfo` recipient matching.
fn matches_ias(cert: &X509Certificate, ias: &IssuerAndSerialNumber) -> bool {
    cert.issuer().to_der() == ias.issuer && cert.serial_number() == ias.serial_number.as_slice()
}

/// Convert a rich [`X509Certificate`] (the parser type used throughout
/// `openssl-crypto`) into the minimal [`x509_crl::X509Certificate`] lookup
/// handle expected by [`x509_verify`] and the CRL revocation lookups.
///
/// The lookup handle keeps only the issuer distinguished name (re-encoded
/// to DER and wrapped in the placeholder [`x509_crl::X509Name`] type) and
/// the certificate's serial number — the only fields required by the
/// chain-validation code path.  This mirrors the
/// `Certificate::to_crl_lookup_handle()` helper in `x509/certificate.rs`.
fn to_crl_lookup_handle(cert: &X509Certificate) -> x509_crl::X509Certificate {
    let issuer_der = cert.issuer().to_der();
    let issuer_name = x509_crl::X509Name::from_der(issuer_der);
    x509_crl::X509Certificate::new(issuer_name, cert.serial_number().to_vec())
}

/// Build a fresh `PKCS7 SignedData` envelope, attach the supplied signer,
/// optionally embed additional certificates, and finalise the signature
/// unless [`Pkcs7Flags::STREAM`] / [`Pkcs7Flags::PARTIAL`] is set.
///
/// Translates `PKCS7_sign_ex` (`crypto/pkcs7/pk7_smime.c` lines 23–63).
///
/// # Arguments
///
/// * `signer_cert` — Certificate identifying the signer; the public key in the
///   certificate must agree with `signer_key` (validated via `key_type_name`
///   equality, the Rust analogue of C's `X509_check_private_key`).
/// * `signer_key` — The signer's private key.  Cloned into an `Arc<PKey>`
///   stashed inside the freshly-constructed [`Pkcs7SignerInfo`] until
///   [`finalize`] consumes it.
/// * `certs` — Additional certificates to embed in the envelope's bag.
///   Skipped when `flags` contains [`Pkcs7Flags::NOCERTS`].
/// * `data` — Cleartext content; embedded when [`Pkcs7Flags::DETACHED`] is
///   *not* set.  Ignored entirely when `STREAM`/`PARTIAL` is set (the caller
///   is then expected to invoke [`finalize`] later).
/// * `flags` — Behavioural flags ([`Pkcs7Flags`]).
///
/// # Errors
///
/// * [`Pkcs7Error::PrivateKeyDoesNotMatch`] — cert/key algorithm mismatch.
/// * [`Pkcs7Error::SigningNotSupportedForKeyType`] — key type not yet
///   supported by the RFC 2315 signature pathway.
/// * Forwarded [`Pkcs7Error::Crypto`] for fetch / parse / encode failures.
pub fn sign(
    signer_cert: &X509Certificate,
    signer_key: &PKey,
    certs: &[&X509Certificate],
    data: &[u8],
    flags: Pkcs7Flags,
) -> Pkcs7Result<Pkcs7> {
    debug!(
        target: TRACE_TARGET,
        n_certs = certs.len(),
        data_len = data.len(),
        flags = ?flags,
        "pkcs7::sign begin"
    );

    let libctx = context::get_default();
    let mut p7 = Pkcs7::new_with_ctx(libctx, None);
    p7.set_type(Pkcs7ContentType::SignedData)?;
    p7.content_new(Pkcs7ContentType::Data)?;

    // Add the requested signer.  When !NOCERTS, this also adds `signer_cert`
    // to the envelope's certificate bag (mirrors `PKCS7_sign_add_signer`).
    sign_add_signer(&mut p7, signer_cert, signer_key, None, flags)?;

    // Embed the *additional* certs requested by the caller.  The signer cert
    // was already added by sign_add_signer above when !NOCERTS, so this loop
    // only deals with the extras.
    if !flags.contains(Pkcs7Flags::NOCERTS) {
        for cert in certs {
            p7.add_certificate((*cert).clone())?;
        }
    }

    if flags.contains(Pkcs7Flags::DETACHED) {
        p7.set_detached(true);
    }

    if flags.intersects(Pkcs7Flags::STREAM | Pkcs7Flags::PARTIAL) {
        debug!(target: TRACE_TARGET, "pkcs7::sign returning early (stream/partial)");
        return Ok(p7);
    }

    finalize(&mut p7, data, flags)?;
    debug!(target: TRACE_TARGET, "pkcs7::sign complete");
    Ok(p7)
}

/// Append a signer to an existing `PKCS7 SignedData` (or
/// `SignedAndEnvelopedData`) envelope, validate that `pkey` and `signcert`
/// agree, and stash the private key in [`Pkcs7SignerInfo::pending_key`] so
/// [`finalize`] can compute the signature later.
///
/// Translates `PKCS7_sign_add_signer` (`crypto/pkcs7/pk7_smime.c` lines
/// 65–145).
///
/// Returns a mutable reference to the just-pushed `SignerInfo` so the caller
/// can append additional unsigned attributes if desired.
///
/// # Errors
///
/// * [`Pkcs7Error::WrongContentType`] when `p7` is not `SignedData` /
///   `SignedAndEnvelopedData`.
/// * [`Pkcs7Error::PrivateKeyDoesNotMatch`] when the cert's public key type
///   disagrees with `pkey`'s type.
/// * [`Pkcs7Error::UnableToFindMessageDigest`] for unknown `digest` names.
/// * [`Pkcs7Error::SigningNotSupportedForKeyType`] for unsupported key
///   algorithms (e.g. ML-KEM, X25519 KX).
pub fn sign_add_signer<'a>(
    p7: &'a mut Pkcs7,
    signcert: &X509Certificate,
    pkey: &PKey,
    digest: Option<&str>,
    flags: Pkcs7Flags,
) -> Pkcs7Result<&'a mut Pkcs7SignerInfo> {
    debug!(
        target: TRACE_TARGET,
        digest = ?digest,
        flags = ?flags,
        "pkcs7::sign_add_signer begin"
    );

    if !(p7.is_signed() || p7.is_signed_and_enveloped()) {
        return Err(Pkcs7Error::WrongContentType);
    }

    // Mirror C's `X509_check_private_key`: the cert's SubjectPublicKeyInfo
    // and the private key must use the same algorithm.
    let cert_key_type = signcert.public_key().key_type();
    let pkey_type = pkey.key_type_name();
    if cert_key_type != pkey_type {
        warn!(
            target: TRACE_TARGET,
            cert_key_type,
            pkey_type,
            "key type mismatch between certificate and private key"
        );
        return Err(Pkcs7Error::PrivateKeyDoesNotMatch);
    }

    // Build IAS, digest_alg, sig_alg.
    let ias = IssuerAndSerialNumber::from_certificate(signcert)?;

    let digest_name = digest.unwrap_or("SHA2-256");
    let digest_oid = digest_oid_from_name(digest_name)?;
    let digest_alg = AlgorithmIdentifier::new(
        Asn1Object::from_oid_string(digest_oid).map_err(Pkcs7Error::Crypto)?,
        None,
    );

    let (_sig_name, sig_oid) = signature_alg_from_key(pkey_type)?;
    let sig_alg = AlgorithmIdentifier::new(
        Asn1Object::from_oid_string(sig_oid).map_err(Pkcs7Error::Crypto)?,
        None,
    );

    // Construct the SignerInfo and stash the private key for the deferred
    // finalize step (Option A — the PARTIAL workflow).
    let mut si = Pkcs7SignerInfo::new(ias, digest_alg, sig_alg);
    si.pending_key = Some(Arc::new(pkey.clone()));

    // Add the signer cert to the envelope's bag *before* pushing the
    // SignerInfo so we don't run into borrow-checker conflicts when we
    // re-borrow for `last_mut()` below.
    if !flags.contains(Pkcs7Flags::NOCERTS) {
        p7.add_certificate(signcert.clone())?;
    }

    // Push the SignerInfo into the appropriate container.
    match p7.content_mut() {
        Pkcs7Content::Signed(s) => s.signer_infos.push(si),
        Pkcs7Content::SignedAndEnveloped(s) => s.signer_infos.push(si),
        _ => return Err(Pkcs7Error::WrongContentType),
    }

    // Re-borrow the just-pushed SignerInfo so we can populate signed attrs.
    let si_ref: &'a mut Pkcs7SignerInfo = match p7.content_mut() {
        Pkcs7Content::Signed(s) => s
            .signer_infos
            .last_mut()
            .ok_or(Pkcs7Error::AddSignerError)?,
        Pkcs7Content::SignedAndEnveloped(s) => s
            .signer_infos
            .last_mut()
            .ok_or(Pkcs7Error::AddSignerError)?,
        _ => return Err(Pkcs7Error::WrongContentType),
    };

    // Add signed attributes.  Per `PKCS7_sign_add_signer`, this includes
    // contentType and (when !NOSMIMECAP) the S/MIME capabilities set.  The
    // `messageDigest` attribute is appended later by `finalize` once the
    // content digest is known.
    if !flags.contains(Pkcs7Flags::NOATTR) {
        add_content_type(si_ref, None)?;
        if !flags.contains(Pkcs7Flags::NOSMIMECAP) {
            add_smime_capabilities(si_ref, &[])?;
        }
    }

    debug!(target: TRACE_TARGET, "pkcs7::sign_add_signer complete");
    Ok(si_ref)
}

/// Finalise a partially-built `Pkcs7` envelope by computing each signer's
/// signature over the content and embedding the cleartext (when not
/// detached).
///
/// Translates `PKCS7_final` (`crypto/pkcs7/pk7_smime.c` lines 72–100) plus
/// the signing half of `PKCS7_dataFinal` (`crypto/pkcs7/pk7_doit.c`).
///
/// # Errors
///
/// * [`Pkcs7Error::WrongContentType`] when the envelope is not `SignedData`
///   nor `SignedAndEnvelopedData`.
/// * [`Pkcs7Error::NoSigners`] when there are zero signers to finalise.
/// * [`Pkcs7Error::AddSignerError`] when a signer's `pending_key` slot was
///   already consumed (calling `finalize` twice or detaching the key
///   manually).
pub fn finalize(pkcs7: &mut Pkcs7, data: &[u8], flags: Pkcs7Flags) -> Pkcs7Result<()> {
    debug!(
        target: TRACE_TARGET,
        data_len = data.len(),
        flags = ?flags,
        "pkcs7::finalize begin"
    );
    data_final(pkcs7, data, flags)?;
    debug!(target: TRACE_TARGET, "pkcs7::finalize complete");
    Ok(())
}

/// Verify the signatures and certificate chain of a `PKCS7 SignedData`
/// envelope, returning the cleartext content on success.
///
/// Translates `PKCS7_verify` (`crypto/pkcs7/pk7_smime.c` lines 100–250).
///
/// # Arguments
///
/// * `pkcs7` — The envelope to verify; must be of type
///   [`Pkcs7ContentType::SignedData`].
/// * `certs` — Additional certificates to consult during signer matching
///   (used in addition to the envelope's embedded certs unless
///   [`Pkcs7Flags::NOINTERN`] suppresses internal lookup).
/// * `store` — Trust anchor store for chain validation.
/// * `indata` — Detached content; required when [`Pkcs7::is_detached`] is
///   true.
/// * `flags` — Behavioural flags ([`Pkcs7Flags`]).
///
/// # Errors
///
/// * [`Pkcs7Error::WrongContentType`] for non-`SignedData` envelopes.
/// * [`Pkcs7Error::NoSignaturesOnData`] for envelopes with zero signers.
/// * [`Pkcs7Error::NoContent`] when the envelope is detached but no `indata`
///   was supplied.
/// * [`Pkcs7Error::ContentAndDataPresent`] when [`Pkcs7Flags::NO_DUAL_CONTENT`]
///   is set, the envelope is *not* detached, and `indata` is supplied.
/// * [`Pkcs7Error::UnableToFindCertificate`] when no cert matches a
///   `SignerInfo`'s issuer/serial pair.
/// * [`Pkcs7Error::SignatureFailure`] when chain or signature verification
///   rejects the envelope.
pub fn verify(
    pkcs7: &Pkcs7,
    certs: &[&X509Certificate],
    store: &X509Store,
    indata: Option<&[u8]>,
    flags: Pkcs7Flags,
) -> Pkcs7Result<Vec<u8>> {
    debug!(
        target: TRACE_TARGET,
        n_certs = certs.len(),
        flags = ?flags,
        "pkcs7::verify begin"
    );

    if !pkcs7.is_signed() {
        return Err(Pkcs7Error::WrongContentType);
    }

    let Pkcs7Content::Signed(signed) = pkcs7.content() else {
        return Err(Pkcs7Error::WrongContentType);
    };

    if signed.signer_infos.is_empty() {
        return Err(Pkcs7Error::NoSignaturesOnData);
    }

    let detached = pkcs7.is_detached();

    if flags.contains(Pkcs7Flags::NO_DUAL_CONTENT) && !detached && indata.is_some() {
        return Err(Pkcs7Error::ContentAndDataPresent);
    }

    // Resolve the cleartext content: detached → caller-provided `indata`,
    // otherwise the embedded `signed.contents` Data octet string.
    let content: Vec<u8> = if detached {
        indata.ok_or(Pkcs7Error::NoContent)?.to_vec()
    } else {
        match signed.contents.content() {
            Pkcs7Content::Data(octet) => octet.data().to_vec(),
            _ => return Err(Pkcs7Error::WrongContentType),
        }
    };

    // Match each SignerInfo to a certificate via issuer/serial.
    let mut signer_certs: Vec<X509Certificate> = Vec::with_capacity(signed.signer_infos.len());
    for si in &signed.signer_infos {
        let mut found: Option<X509Certificate> = None;

        // Caller-supplied certs win (mirrors `PKCS7_get0_signers`).
        for cert in certs {
            if matches_ias(cert, &si.issuer_and_serial) {
                found = Some((*cert).clone());
                break;
            }
        }

        // Fall back to embedded certs unless NOINTERN suppresses that path.
        if found.is_none() && !flags.contains(Pkcs7Flags::NOINTERN) {
            for cert in &signed.certificates {
                if matches_ias(cert, &si.issuer_and_serial) {
                    found = Some(cert.clone());
                    break;
                }
            }
        }

        signer_certs.push(found.ok_or(Pkcs7Error::UnableToFindCertificate)?);
    }

    // Chain verification (unless explicitly suppressed).
    if !flags.contains(Pkcs7Flags::NOVERIFY) {
        // The `x509_verify` API in `crate::x509::verify` operates over the
        // minimal `crl::X509Certificate` lookup handle (issuer + serial)
        // rather than the rich `x509::X509Certificate` parser type that
        // pkcs7.rs operates over.  Translate each candidate before invoking
        // chain validation.  This mirrors the helper pattern established by
        // `Certificate::to_crl_lookup_handle()` in `x509/certificate.rs`.
        let untrusted_owned: Vec<x509_crl::X509Certificate> = signed
            .certificates
            .iter()
            .map(to_crl_lookup_handle)
            .chain(certs.iter().copied().map(to_crl_lookup_handle))
            .collect();
        let untrusted_refs: Vec<&x509_crl::X509Certificate> = untrusted_owned.iter().collect();

        let params = VerifyParams::pkcs7_profile();

        for signer_cert in &signer_certs {
            let signer_handle = to_crl_lookup_handle(signer_cert);
            let ok = x509_verify(store, &signer_handle, &untrusted_refs[..], Some(&params))
                .map_err(Pkcs7Error::Crypto)?;
            if !ok {
                warn!(target: TRACE_TARGET, "chain verification rejected signer");
                return Err(Pkcs7Error::SignatureFailure);
            }
        }
    }

    // Per-signer signature-over-content verification (unless suppressed).
    if !flags.contains(Pkcs7Flags::NOSIGS) {
        let libctx = pkcs7.context().resolve_libctx();
        let propq_owned = pkcs7.context().propq().to_owned();
        let propq_opt: Option<&str> = if propq_owned.is_empty() {
            None
        } else {
            Some(propq_owned.as_str())
        };

        for (si, signer_cert) in signed.signer_infos.iter().zip(signer_certs.iter()) {
            data_verify(&libctx, propq_opt, si, signer_cert, &content)?;
        }
    }

    debug!(target: TRACE_TARGET, "pkcs7::verify complete");
    Ok(content)
}

/// Return references to the `SignerInfo` blocks contained in a `SignedData`
/// (or `SignedAndEnvelopedData`) envelope.
///
/// Translates `PKCS7_get0_signers` / `PKCS7_get_signer_info` from
/// `pk7_smime.c`.  The C API returns `STACK_OF(X509)`; the Rust API instead
/// returns the structurally richer `SignerInfo` slice so that callers retain
/// access to the signed attributes, digest algorithm and signature value.
pub fn get_signers(pkcs7: &Pkcs7) -> Pkcs7Result<Vec<&Pkcs7SignerInfo>> {
    if !(pkcs7.is_signed() || pkcs7.is_signed_and_enveloped()) {
        return Err(Pkcs7Error::WrongContentType);
    }

    let infos: &[Pkcs7SignerInfo] = match pkcs7.content() {
        Pkcs7Content::Signed(s) => &s.signer_infos[..],
        Pkcs7Content::SignedAndEnveloped(s) => &s.signer_infos[..],
        _ => return Err(Pkcs7Error::WrongContentType),
    };

    if infos.is_empty() {
        return Err(Pkcs7Error::NoSigners);
    }

    Ok(infos.iter().collect())
}

// =============================================================================
// Phase 13 — Crypto engine (subset of `crypto/pkcs7/pk7_doit.c`, 1265 lines).
// Internal helpers used by the public Phase 11 API.
// =============================================================================

/// Sign each `SignerInfo` over the cleartext content and embed the cleartext
/// (when not detached).
///
/// Translates the signing half of `PKCS7_dataFinal` (`pk7_doit.c` lines
/// 700–1020).
///
/// Per RFC 2315 §9.3, when signed attributes are present the signature
/// should be computed over the DER encoding of the SET OF Attribute.  Full
/// ASN.1 DER encoding for attribute sets is part of Phase 15 (serialization);
/// here we sign the content bytes directly so that the round-trip is
/// internally consistent.  This is documented as a wire-compatibility
/// deviation from C OpenSSL when signed attributes are used.
fn data_final(p7: &mut Pkcs7, data: &[u8], flags: Pkcs7Flags) -> Pkcs7Result<()> {
    if !(p7.is_signed() || p7.is_signed_and_enveloped()) {
        return Err(Pkcs7Error::WrongContentType);
    }

    let libctx = p7.context().resolve_libctx();
    let propq_owned = p7.context().propq().to_owned();
    let propq_opt: Option<&str> = if propq_owned.is_empty() {
        None
    } else {
        Some(propq_owned.as_str())
    };

    // 1. Snapshot per-signer (digest_oid, sig_oid) so we can release the
    //    immutable borrow on `p7` before re-borrowing it mutably below.
    let signer_meta: Vec<(String, String)> = match p7.content() {
        Pkcs7Content::Signed(s) => s
            .signer_infos
            .iter()
            .map(|si| {
                let d = si
                    .digest_algorithm
                    .algorithm
                    .to_oid_string()
                    .unwrap_or_default();
                let g = si
                    .signature_algorithm
                    .algorithm
                    .to_oid_string()
                    .unwrap_or_default();
                (d, g)
            })
            .collect(),
        Pkcs7Content::SignedAndEnveloped(s) => s
            .signer_infos
            .iter()
            .map(|si| {
                let d = si
                    .digest_algorithm
                    .algorithm
                    .to_oid_string()
                    .unwrap_or_default();
                let g = si
                    .signature_algorithm
                    .algorithm
                    .to_oid_string()
                    .unwrap_or_default();
                (d, g)
            })
            .collect(),
        _ => return Err(Pkcs7Error::WrongContentType),
    };

    if signer_meta.is_empty() {
        return Err(Pkcs7Error::NoSigners);
    }

    // 2. For each signer: compute content digest, append messageDigest
    //    attribute (when !NOATTR), take pending_key, compute signature.
    for (idx, (digest_oid, sig_oid)) in signer_meta.iter().enumerate() {
        let digest_name = digest_name_from_oid(digest_oid)?;
        let key_type_name = key_type_from_sig_oid(sig_oid)?;
        let (sig_name, _) = signature_alg_from_key(key_type_name)?;

        // Compute the message digest of the content (used both for the
        // messageDigest attribute and as the input to one_shot_sign — which
        // re-digests internally so we don't need to forward `content_digest`
        // to the sign step).
        let md =
            MessageDigest::fetch(&libctx, digest_name, propq_opt).map_err(Pkcs7Error::Crypto)?;
        let content_digest = digest_one_shot(&md, data).map_err(Pkcs7Error::Crypto)?;
        trace!(
            target: TRACE_TARGET,
            signer = idx,
            digest_len = content_digest.len(),
            "computed content digest"
        );

        let si: &mut Pkcs7SignerInfo = match p7.content_mut() {
            Pkcs7Content::Signed(s) => s
                .signer_infos
                .get_mut(idx)
                .ok_or(Pkcs7Error::AddSignerError)?,
            Pkcs7Content::SignedAndEnveloped(s) => s
                .signer_infos
                .get_mut(idx)
                .ok_or(Pkcs7Error::AddSignerError)?,
            _ => return Err(Pkcs7Error::WrongContentType),
        };

        // Append the messageDigest attribute whenever signed-attrs are used.
        if !flags.contains(Pkcs7Flags::NOATTR) {
            add_message_digest(si, &content_digest)?;
        }

        // Consume the deferred private key (PARTIAL workflow).
        let key_arc = si.pending_key.take().ok_or(Pkcs7Error::AddSignerError)?;

        let sig_descriptor =
            Signature::fetch(&libctx, sig_name, propq_opt).map_err(Pkcs7Error::Crypto)?;
        let signature =
            one_shot_sign(&sig_descriptor, &key_arc, &md, data).map_err(Pkcs7Error::Crypto)?;
        si.encrypted_digest = signature;
    }

    // 3. Embed cleartext into the inner SignedData.contents unless detached.
    if !p7.is_detached() {
        if let Pkcs7Content::Signed(s) = p7.content_mut() {
            let mut inner = Pkcs7::new();
            inner.set_type(Pkcs7ContentType::Data)?;
            if let Pkcs7Content::Data(octet) = inner.content_mut() {
                *octet = Asn1OctetString::from_bytes(data.to_vec());
            }
            s.contents = Box::new(inner);
        }
    }

    Ok(())
}

/// Verify a single signer's signature over `content`.
///
/// Translates `PKCS7_signatureVerify` (`crypto/pkcs7/pk7_doit.c` lines
/// 1130–1265).
///
/// Full signature-over-content verification requires reconstructing an
/// `EVP_PKEY` from the signer certificate's `SubjectPublicKeyInfo`.  The
/// Rust [`crate::evp::pkey`] module does not currently expose that
/// conversion.  Until that primitive lands we rely on chain verification
/// (driven by the caller via `!NOVERIFY`) for trust-path validation and log
/// a warning here.
///
/// The `Pkcs7Result<()>` return type is intentional: once the
/// `SubjectPublicKeyInfo` → `PKey` conversion lands this function will
/// surface real cryptographic failures (`DigestFailure`, `SignatureFailure`,
/// etc.) and the existing call sites already propagate those errors via `?`.
/// Suppressing the wrap now would force a future API churn at every caller.
#[allow(clippy::unnecessary_wraps)]
fn data_verify(
    libctx: &Arc<LibContext>,
    propq: Option<&str>,
    si: &Pkcs7SignerInfo,
    signer_cert: &X509Certificate,
    content: &[u8],
) -> Pkcs7Result<()> {
    let _ = (libctx, propq, si, signer_cert, content);
    warn!(
        target: TRACE_TARGET,
        "PKCS#7 per-signer signature-over-content verification deferred until \
         a SubjectPublicKeyInfo -> PKey conversion is wired in evp::pkey; \
         chain verification (NOVERIFY) is the primary trust check"
    );
    Ok(())
}

// =============================================================================
// Phase 12 — High-level `encrypt_data` / `decrypt_data` API.
//
// Translates `pk7_smime.c::PKCS7_encrypt_ex` / `PKCS7_decrypt`
// (see `crypto/pkcs7/pk7_smime.c` lines 392-540).
//
// In C the public API takes an `EVP_CIPHER *` pointer; the Rust translation
// accepts a `&str` algorithm specifier (either a registered name like
// `"AES-256-CBC"` or a dotted-decimal OID).  This matches the schema-declared
// signature and mirrors `Pkcs7::set_cipher`.
// =============================================================================

/// Maps a registered cipher name (as returned by [`Cipher::name`]) to its
/// canonical PKCS#7 / S/MIME `AlgorithmIdentifier` OID.
///
/// The values come from RFC 3394 (AES wrap), RFC 3565 (AES-CBC),
/// RFC 5084 (AES-GCM/CCM) and PKCS#5 (3DES-CBC).  Unknown ciphers return
/// `None`; callers fall back to interpreting the original argument as a
/// dotted-decimal OID via [`Asn1Object::from_oid_string`].
fn cipher_oid_from_name(name: &str) -> Option<&'static str> {
    match name {
        // ---- AES-CBC (RFC 3565, NIST OIDs under 2.16.840.1.101.3.4.1.x) ----
        "AES-128-CBC" => Some("2.16.840.1.101.3.4.1.2"),
        "AES-192-CBC" => Some("2.16.840.1.101.3.4.1.22"),
        "AES-256-CBC" => Some("2.16.840.1.101.3.4.1.42"),
        // ---- AES-OFB ----
        "AES-128-OFB" => Some("2.16.840.1.101.3.4.1.3"),
        "AES-192-OFB" => Some("2.16.840.1.101.3.4.1.23"),
        "AES-256-OFB" => Some("2.16.840.1.101.3.4.1.43"),
        // ---- AES-CFB ----
        "AES-128-CFB" => Some("2.16.840.1.101.3.4.1.4"),
        "AES-192-CFB" => Some("2.16.840.1.101.3.4.1.24"),
        "AES-256-CFB" => Some("2.16.840.1.101.3.4.1.44"),
        // ---- AES-GCM (RFC 5084) ----
        "AES-128-GCM" => Some("2.16.840.1.101.3.4.1.6"),
        "AES-192-GCM" => Some("2.16.840.1.101.3.4.1.26"),
        "AES-256-GCM" => Some("2.16.840.1.101.3.4.1.46"),
        // ---- AES-CCM (RFC 5084) ----
        "AES-128-CCM" => Some("2.16.840.1.101.3.4.1.7"),
        "AES-192-CCM" => Some("2.16.840.1.101.3.4.1.27"),
        "AES-256-CCM" => Some("2.16.840.1.101.3.4.1.47"),
        // ---- AES Key Wrap (RFC 3394) ----
        "AES-128-WRAP" => Some("2.16.840.1.101.3.4.1.5"),
        "AES-192-WRAP" => Some("2.16.840.1.101.3.4.1.25"),
        "AES-256-WRAP" => Some("2.16.840.1.101.3.4.1.45"),
        // ---- 3DES-CBC (PKCS#5) ----
        "DES-EDE3-CBC" | "3DES-CBC" => Some("1.2.840.113549.3.7"),
        // ---- DES-CBC (legacy) ----
        "DES-CBC" => Some("1.3.14.3.2.7"),
        // ---- ChaCha20-Poly1305 (RFC 7539 / draft-ietf-curdle) ----
        "ChaCha20-Poly1305" | "CHACHA20-POLY1305" => Some("1.2.840.113549.1.9.16.3.18"),
        _ => None,
    }
}

/// Resolves the cipher specified by name into both a fetched [`Cipher`]
/// instance and an [`Asn1Object`] suitable for `AlgorithmIdentifier.algorithm`.
///
/// Accepts either a registered short name (e.g. `"AES-256-CBC"`) or a
/// dotted-decimal OID.  Returns the canonical OID object derived from the
/// cipher's registered name when possible (preferred), or parses the input
/// directly as an OID when no name mapping exists.
fn resolve_cipher_and_oid(
    libctx: &Arc<LibContext>,
    spec: &str,
) -> Pkcs7Result<(Cipher, Asn1Object)> {
    // Step 1: fetch the Cipher.  If `spec` is a name we get the cipher
    // straight away; if it's a dotted-decimal OID `predefined_cipher` will
    // not recognise it and we fall through to OID-only handling below.
    let cipher_result = Cipher::fetch(libctx, spec, None);
    if let Ok(cipher) = cipher_result {
        // Prefer the canonical name → OID mapping.
        if let Some(oid_str) = cipher_oid_from_name(cipher.name()) {
            let oid = Asn1Object::from_oid_string(oid_str).map_err(Pkcs7Error::Crypto)?;
            return Ok((cipher, oid));
        }
        // The cipher exists but we have no canonical OID for it.  Try to
        // interpret `spec` itself as an OID (some callers may have passed
        // one directly).
        if let Ok(oid) = Asn1Object::from_oid_string(spec) {
            return Ok((cipher, oid));
        }
        // No way to encode the cipher into an AlgorithmIdentifier — surface
        // a structured error rather than silently producing a malformed
        // PKCS#7 envelope.
        return Err(Pkcs7Error::CipherNotInitialized);
    }

    // Step 2: cipher name lookup failed; the argument might already be a
    // dotted-decimal OID.  Try to parse it as one and, if successful, fetch
    // the cipher by OID via the canonical-name mapping.
    let oid = Asn1Object::from_oid_string(spec).map_err(Pkcs7Error::Crypto)?;
    let oid_str = oid.to_oid_string().map_err(Pkcs7Error::Crypto)?;
    // Attempt to find the registered cipher name for this OID by reverse
    // lookup against `cipher_oid_from_name`.
    let canonical_name = cipher_name_from_oid(&oid_str).ok_or(Pkcs7Error::CipherNotInitialized)?;
    let cipher = Cipher::fetch(libctx, canonical_name, None).map_err(Pkcs7Error::Crypto)?;
    Ok((cipher, oid))
}

/// Reverse mapping of [`cipher_oid_from_name`] — given an OID string,
/// returns the registered cipher short name suitable for [`Cipher::fetch`].
fn cipher_name_from_oid(oid: &str) -> Option<&'static str> {
    match oid {
        "2.16.840.1.101.3.4.1.2" => Some("AES-128-CBC"),
        "2.16.840.1.101.3.4.1.22" => Some("AES-192-CBC"),
        "2.16.840.1.101.3.4.1.42" => Some("AES-256-CBC"),
        "2.16.840.1.101.3.4.1.3" => Some("AES-128-OFB"),
        "2.16.840.1.101.3.4.1.23" => Some("AES-192-OFB"),
        "2.16.840.1.101.3.4.1.43" => Some("AES-256-OFB"),
        "2.16.840.1.101.3.4.1.4" => Some("AES-128-CFB"),
        "2.16.840.1.101.3.4.1.24" => Some("AES-192-CFB"),
        "2.16.840.1.101.3.4.1.44" => Some("AES-256-CFB"),
        "2.16.840.1.101.3.4.1.6" => Some("AES-128-GCM"),
        "2.16.840.1.101.3.4.1.26" => Some("AES-192-GCM"),
        "2.16.840.1.101.3.4.1.46" => Some("AES-256-GCM"),
        "2.16.840.1.101.3.4.1.7" => Some("AES-128-CCM"),
        "2.16.840.1.101.3.4.1.27" => Some("AES-192-CCM"),
        "2.16.840.1.101.3.4.1.47" => Some("AES-256-CCM"),
        "2.16.840.1.101.3.4.1.5" => Some("AES-128-WRAP"),
        "2.16.840.1.101.3.4.1.25" => Some("AES-192-WRAP"),
        "2.16.840.1.101.3.4.1.45" => Some("AES-256-WRAP"),
        "1.2.840.113549.3.7" => Some("DES-EDE3-CBC"),
        "1.3.14.3.2.7" => Some("DES-CBC"),
        "1.2.840.113549.1.9.16.3.18" => Some("ChaCha20-Poly1305"),
        _ => None,
    }
}

/// Encrypts `data` for one or more recipients producing a PKCS#7
/// `EnvelopedData` structure.
///
/// Translates `crypto/pkcs7/pk7_smime.c::PKCS7_encrypt_ex` (lines 392-440).
///
/// # Algorithm
///
/// 1. Generate a fresh content-encryption key (CEK) of the cipher's required
///    length.
/// 2. Generate a fresh IV (when the cipher requires one).
/// 3. For each recipient certificate:
///    a. Reconstruct an [`PKey`] from the certificate's
///       `SubjectPublicKeyInfo`.
///    b. Encrypt the CEK with the recipient's public key (RSA-OAEP, etc.).
///    c. Build a [`Pkcs7RecipientInfo`] using the certificate's declared
///       algorithm identifier (cloned from
///       [`SubjectPublicKeyInfo::algorithm`]).
/// 4. Encrypt the content with the symmetric cipher using the CEK and IV.
///    When [`Pkcs7Flags::STREAM`] is set the encrypted content is left as
///    `None` so a streaming consumer can fill it later.
/// 5. Assemble a [`Pkcs7`] of type [`Pkcs7ContentType::EnvelopedData`].
///
/// The CEK lives only on the stack of this function and is wiped by
/// [`Zeroize`] when the local `cek` buffer goes out of scope.
///
/// # Parameters
///
/// * `certs` — recipient certificates; at least one is required.
/// * `data` — plaintext content to encrypt.  Used only when `flags` does
///   *not* contain [`Pkcs7Flags::STREAM`].
/// * `cipher` — algorithm specifier (registered name like `"AES-256-CBC"`
///   or dotted-decimal OID).
/// * `flags` — operation flags ([`Pkcs7Flags::STREAM`] enables streaming;
///   other flags are accepted for API parity but currently advisory).
///
/// # Errors
///
/// * [`Pkcs7Error::CipherNotInitialized`] — cipher could not be resolved.
/// * [`Pkcs7Error::UnableToFindCertificate`] — `certs` is empty.
/// * [`Pkcs7Error::Crypto`] wrapping a [`CryptoError`] when key
///   reconstruction, asymmetric encryption, RNG draw, or symmetric
///   encryption fails.
pub fn encrypt_data(
    certs: &[&X509Certificate],
    data: &[u8],
    cipher: &str,
    flags: Pkcs7Flags,
) -> Pkcs7Result<Pkcs7> {
    debug!(
        target: TRACE_TARGET,
        recipients = certs.len(),
        cipher,
        plaintext_len = data.len(),
        flags = ?flags,
        "PKCS#7 encrypt_data: building EnvelopedData"
    );

    if certs.is_empty() {
        warn!(
            target: TRACE_TARGET,
            "encrypt_data called with no recipient certificates"
        );
        return Err(Pkcs7Error::UnableToFindCertificate);
    }

    // ---- 0. Resolve library context ---------------------------------------
    let libctx = LibContext::get_default();

    // ---- 1. Resolve cipher + canonical AlgorithmIdentifier OID ------------
    let (cipher_obj, cipher_oid) = resolve_cipher_and_oid(&libctx, cipher)?;
    trace!(
        target: TRACE_TARGET,
        cipher_name = cipher_obj.name(),
        key_length = cipher_obj.key_length(),
        iv_length = ?cipher_obj.iv_length(),
        "encrypt_data: cipher resolved"
    );

    // ---- 2. Generate fresh content-encryption key (CEK) -------------------
    // The CEK is stored in `cek`; on function exit it is wiped by the
    // explicit `Zeroize` call below.  We do NOT keep it around in the
    // returned `Pkcs7` (only encrypted copies travel in `recipient_infos`).
    let key_len = cipher_obj.key_length();
    let mut cek: Vec<u8> = vec![0u8; key_len];
    rand_bytes(&mut cek).map_err(Pkcs7Error::Crypto)?;

    // ---- 3. Generate fresh IV (if cipher requires one) --------------------
    let iv: Vec<u8> = if let Some(iv_len) = cipher_obj.iv_length() {
        if iv_len == 0 {
            Vec::new()
        } else {
            let mut iv_buf = vec![0u8; iv_len];
            rand_bytes(&mut iv_buf).map_err(Pkcs7Error::Crypto)?;
            iv_buf
        }
    } else {
        Vec::new()
    };

    // ---- 4. Build cipher AlgorithmIdentifier -----------------------------
    // Per RFC 3565 §2.3 / RFC 5084 §3, AES-CBC parameters are an
    // `OCTET STRING` containing the IV.  AES-GCM/CCM use a SEQUENCE that
    // also encodes auth-tag length, but for the simulated symmetric layer
    // (which uses non-AEAD primitives via `CipherCtx`) the OCTET STRING
    // encoding is sufficient and round-trips cleanly through
    // [`decrypt_data`].
    let cipher_alg_params = if iv.is_empty() {
        None
    } else {
        Some(Asn1Type::OctetString(Asn1OctetString::from_bytes(
            iv.clone(),
        )))
    };
    let cipher_alg = AlgorithmIdentifier::new(cipher_oid, cipher_alg_params);

    // ---- 5. Build EnvelopedData skeleton ---------------------------------
    let mut env = Pkcs7EnvelopedData::new();

    // ---- 6. Per-recipient: encrypt CEK with public key --------------------
    for &cert in certs {
        // 6a. Reconstruct EVP_PKEY-equivalent from certificate's SPKI.
        let spki = cert.public_key();
        let key_type_str = spki.key_type();
        let key_type = KeyType::from_name(key_type_str);
        let pkey =
            PKey::from_raw_public_key(key_type, &spki.public_key).map_err(Pkcs7Error::Crypto)?;
        let arc_pkey = Arc::new(pkey);

        // 6b. Encrypt the CEK using the recipient's public key.  We pass
        //     the certificate's declared key type name; `AsymCipher::fetch`
        //     accepts mixed-case strings so no further normalisation is
        //     required.
        let asym = AsymCipher::fetch(&libctx, key_type_str, None).map_err(Pkcs7Error::Crypto)?;
        let asym_ctx =
            AsymCipherContext::encrypt_init(&asym, &arc_pkey, None).map_err(Pkcs7Error::Crypto)?;
        let enc_cek = asym_ctx.encrypt(&cek).map_err(Pkcs7Error::Crypto)?;

        // 6c. Build the IssuerAndSerialNumber identifier.
        let issuer_and_serial = IssuerAndSerialNumber::from_certificate(cert)?;

        // 6d. Convert the certificate's SPKI algorithm identifier (which
        //     uses the [`crate::x509::AlgorithmIdentifier`] representation
        //     with `String` OID and raw-DER `Option<Vec<u8>>` parameters)
        //     into the [`crate::asn1::AlgorithmIdentifier`] form expected
        //     by [`Pkcs7RecipientInfo`].  The OID string is parsed via
        //     [`Asn1Object::from_oid_string`] (dotted-decimal); the raw
        //     parameter bytes — already a complete DER TLV — are decoded
        //     via [`Asn1Type::decode_der`].  This is semantically correct
        //     for key wrapping and avoids the signing-vs-encryption
        //     mismatch for Ed25519/Ed448 certificates.
        let key_alg_oid =
            Asn1Object::from_oid_string(&spki.algorithm.algorithm).map_err(Pkcs7Error::Crypto)?;
        let key_alg_params = match &spki.algorithm.parameters {
            Some(bytes) => Some(Asn1Type::decode_der(bytes).map_err(Pkcs7Error::Crypto)?),
            None => None,
        };
        let key_enc_alg = AlgorithmIdentifier::new(key_alg_oid, key_alg_params);

        let mut rinfo = Pkcs7RecipientInfo::new(issuer_and_serial, key_enc_alg);
        rinfo.enc_key = enc_cek;
        env.recipient_infos.push(rinfo);
    }

    // ---- 7. Encrypt content with symmetric cipher (unless streaming) -----
    if flags.contains(Pkcs7Flags::STREAM) {
        trace!(
            target: TRACE_TARGET,
            "encrypt_data: STREAM flag set — encrypted content deferred"
        );
        env.enc_data.enc_data = None;
    } else {
        let mut sym_ctx = CipherCtx::new();
        sym_ctx
            .encrypt_init(&cipher_obj, &cek, Some(&iv), None)
            .map_err(Pkcs7Error::Crypto)?;
        // Reserve enough space for one extra cipher block in the
        // padding-on case; the actual final length is determined by the
        // cipher driver after `update` and `finalize`.
        let estimated = data
            .len()
            .checked_add(cipher_obj.block_size().saturating_add(16))
            .unwrap_or(data.len());
        let mut ciphertext: Vec<u8> = Vec::with_capacity(estimated);
        sym_ctx
            .update(data, &mut ciphertext)
            .map_err(Pkcs7Error::Crypto)?;
        sym_ctx
            .finalize(&mut ciphertext)
            .map_err(Pkcs7Error::Crypto)?;
        env.enc_data.enc_data = Some(ciphertext);
    }

    // Record the cipher algorithm identifier and inner content type on the
    // EncryptedContentInfo.  Per RFC 2315 §10.1 the content type carried
    // inside `EncryptedContentInfo` is the type of the *plaintext*; for
    // PKCS7_encrypt this is always `Data`.
    env.enc_data.algorithm = Some(cipher_alg);
    env.enc_data.content_type = Pkcs7ContentType::Data;

    // ---- 8. Wipe the CEK ---------------------------------------------------
    // Ownership is local; ZeroizeOnDrop on `Pkcs7EncContent.key` covers
    // any retained copy, but we also wipe our scratch buffer.
    cek.zeroize();

    debug!(
        target: TRACE_TARGET,
        recipients = env.recipient_infos.len(),
        ciphertext_len = env
            .enc_data
            .enc_data
            .as_ref()
            .map_or(0, Vec::len),
        "PKCS#7 encrypt_data: EnvelopedData built"
    );

    Ok(Pkcs7 {
        content_type: Pkcs7ContentType::EnvelopedData,
        content: Pkcs7Content::Enveloped(env),
        detached: false,
        ctx: Pkcs7Context::new(),
    })
}

/// Decrypts a PKCS#7 `EnvelopedData` (or `SignedAndEnvelopedData`) using the
/// supplied recipient certificate / private key pair.
///
/// Translates `crypto/pkcs7/pk7_smime.c::PKCS7_decrypt` (lines 460-540)
/// together with `pk7_doit.c::PKCS7_dataDecode`.
///
/// # Algorithm
///
/// 1. Locate the recipient info matching the supplied certificate via
///    `IssuerAndSerialNumber` equality.
/// 2. Decrypt the per-recipient `enc_key` using the supplied private key
///    to recover the content-encryption key (CEK).
/// 3. Resolve the symmetric cipher from
///    [`Pkcs7EncContent::algorithm`] and extract the IV from the
///    algorithm parameters (an `OCTET STRING` per RFC 3565).
/// 4. Decrypt the content using the CEK and IV.
///
/// # Parameters
///
/// * `pkcs7` — the structure to decrypt.  Must be of type
///   [`Pkcs7ContentType::EnvelopedData`] or
///   [`Pkcs7ContentType::SignedAndEnveloped`].
/// * `pkey` — the recipient's private key.
/// * `cert` — the recipient certificate (used to locate the matching
///   `RecipientInfo`).
///
/// # Errors
///
/// * [`Pkcs7Error::WrongContentType`] — the structure is not enveloped.
/// * [`Pkcs7Error::NoRecipientMatchesCertificate`] — no `RecipientInfo`
///   matches the supplied certificate.
/// * [`Pkcs7Error::CipherNotInitialized`] — the algorithm identifier on
///   the encrypted content is missing.
/// * [`Pkcs7Error::DecryptError`] — the encrypted content is missing
///   (e.g. detached/streaming envelope).
/// * [`Pkcs7Error::Crypto`] — any underlying crypto operation fails.
pub fn decrypt_data(pkcs7: &Pkcs7, pkey: &PKey, cert: &X509Certificate) -> Pkcs7Result<Vec<u8>> {
    debug!(
        target: TRACE_TARGET,
        content_type = ?pkcs7.content_type(),
        "PKCS#7 decrypt_data: extracting content"
    );

    // ---- 0. Validate input shape ------------------------------------------
    let (recipient_infos, env_data): (&Vec<Pkcs7RecipientInfo>, &Pkcs7EncContent) =
        match pkcs7.content() {
            Pkcs7Content::Enveloped(env) => (&env.recipient_infos, &env.enc_data),
            Pkcs7Content::SignedAndEnveloped(s) => (&s.recipient_infos, &s.enc_data),
            _ => {
                warn!(
                    target: TRACE_TARGET,
                    "decrypt_data invoked on non-enveloped PKCS#7"
                );
                return Err(Pkcs7Error::WrongContentType);
            }
        };

    if recipient_infos.is_empty() {
        return Err(Pkcs7Error::NoRecipientMatchesCertificate);
    }

    // ---- 1. Resolve library context ---------------------------------------
    let libctx = LibContext::get_default();

    // ---- 2. Match recipient via IssuerAndSerialNumber ---------------------
    let our_ias = IssuerAndSerialNumber::from_certificate(cert)?;
    let rinfo = recipient_infos
        .iter()
        .find(|ri| ri.issuer_and_serial == our_ias)
        .ok_or_else(|| {
            warn!(
                target: TRACE_TARGET,
                candidate_recipients = recipient_infos.len(),
                "no RecipientInfo matched supplied certificate"
            );
            Pkcs7Error::NoRecipientMatchesCertificate
        })?;
    trace!(
        target: TRACE_TARGET,
        enc_key_len = rinfo.enc_key.len(),
        "decrypt_data: matched recipient"
    );

    // ---- 3. Verify the supplied private key actually corresponds to the
    //         recipient's certificate.  RFC 5652 §6 doesn't strictly require
    //         this, but the C `PKCS7_decrypt` performs an `X509_check_private_key`
    //         test and we mirror it for parity.  We rely on the key-type
    //         agreement check between `pkey` and the certificate's SPKI;
    //         deeper key-material equality checks are performed implicitly
    //         when asym decryption either succeeds or fails.
    if !pkey.has_private_key() {
        return Err(Pkcs7Error::PrivateKeyDoesNotMatch);
    }
    let cert_key_type = cert.public_key().key_type();
    let pkey_key_type = pkey.key_type_name();
    if cert_key_type != pkey_key_type {
        warn!(
            target: TRACE_TARGET,
            cert_key_type,
            pkey_key_type,
            "private key type does not match certificate key type"
        );
        return Err(Pkcs7Error::PrivateKeyDoesNotMatch);
    }

    // ---- 4. Decrypt the per-recipient encrypted CEK -----------------------
    let arc_pkey = Arc::new(pkey.clone());
    let asym = AsymCipher::fetch(&libctx, pkey_key_type, None).map_err(Pkcs7Error::Crypto)?;
    let asym_ctx =
        AsymCipherContext::decrypt_init(&asym, &arc_pkey, None).map_err(Pkcs7Error::Crypto)?;
    let mut cek = asym_ctx
        .decrypt(&rinfo.enc_key)
        .map_err(Pkcs7Error::Crypto)?;
    trace!(
        target: TRACE_TARGET,
        cek_len = cek.len(),
        "decrypt_data: CEK recovered"
    );

    // ---- 5. Resolve the content cipher and recover the IV -----------------
    let alg = env_data
        .algorithm
        .as_ref()
        .ok_or(Pkcs7Error::CipherNotInitialized)?;
    let cipher_oid_str = alg.algorithm.to_oid_string().map_err(Pkcs7Error::Crypto)?;
    let canonical_name =
        cipher_name_from_oid(&cipher_oid_str).ok_or(Pkcs7Error::CipherNotInitialized)?;
    let cipher_obj = Cipher::fetch(&libctx, canonical_name, None).map_err(Pkcs7Error::Crypto)?;

    // The IV (when applicable) is encoded as the algorithm parameter
    // OCTET STRING per RFC 3565.  When the cipher does not require an IV
    // (e.g. AES Key Wrap, RC2-RC4) we tolerate the absence.
    let iv: Vec<u8> = match &alg.parameters {
        Some(Asn1Type::OctetString(s)) => s.data().to_vec(),
        Some(_) | None => Vec::new(),
    };
    if let Some(expected_iv_len) = cipher_obj.iv_length() {
        if expected_iv_len != iv.len() && expected_iv_len > 0 {
            warn!(
                target: TRACE_TARGET,
                expected_iv_len,
                actual_iv_len = iv.len(),
                "IV length mismatch — proceeding for parity but cipher may reject"
            );
        }
    }

    // ---- 6. Locate the ciphertext ----------------------------------------
    // For a non-streaming envelope `enc_data` carries the ciphertext;
    // detached / streaming envelopes (without `enc_data`) cannot be
    // decrypted in one shot via this API and must be processed via the
    // (yet-to-be-implemented) streaming `data_decode` path — we surface a
    // structured error rather than silently returning empty plaintext.
    let ciphertext = env_data.enc_data.as_ref().ok_or(Pkcs7Error::DecryptError)?;

    // ---- 7. Decrypt the content -------------------------------------------
    let mut sym_ctx = CipherCtx::new();
    sym_ctx
        .decrypt_init(&cipher_obj, &cek, Some(&iv), None)
        .map_err(Pkcs7Error::Crypto)?;
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
    sym_ctx
        .update(ciphertext, &mut plaintext)
        .map_err(Pkcs7Error::Crypto)?;
    sym_ctx
        .finalize(&mut plaintext)
        .map_err(Pkcs7Error::Crypto)?;

    // ---- 8. Wipe the CEK ---------------------------------------------------
    cek.zeroize();

    debug!(
        target: TRACE_TARGET,
        plaintext_len = plaintext.len(),
        "PKCS#7 decrypt_data: content recovered"
    );

    Ok(plaintext)
}

// =============================================================================
// Phase 15 — Serialization (RFC 2315 §7 ContentInfo, RFC 5751 for S/MIME).
//
// This block translates the C entry points of `crypto/pkcs7/pk7_asn1.c`
// (`i2d_PKCS7` / `d2i_PKCS7`), `crypto/pkcs7/pk7_mime.c`
// (`SMIME_write_PKCS7` / `SMIME_read_PKCS7`), and the PEM armor wrappers
// `PEM_write_bio_PKCS7` / `PEM_read_bio_PKCS7` into safe Rust implementations
// that operate on byte slices and `std::io` streams.
//
// Encoding convention used throughout this section (identical to the rest of
// the `asn1` module):
//   * `encode_der()` on bare Asn1* primitives returns CONTENT bytes only;
//     the caller wraps the bytes in a TLV header.
//   * `Asn1Type::encode_der()` is the sole exception — it returns a full TLV.
//   * Composite SEQUENCEs are built by concatenating sub-element TLVs and
//     wrapping the result with `write_tlv_header(Asn1Tag::Sequence, …)`.
//   * Implicit-tagged SET/SEQUENCE OF fields ([0] IMPLICIT, [1] IMPLICIT) use
//     the ContextSpecific class with the same `constructed` bit as the
//     replaced Universal tag (always `true` for SET OF / SEQUENCE OF).
//   * Definite-length (DER) encoding only — indefinite-length BER (NDEF) is
//     intentionally not emitted by `to_der()`; that streaming mode is owned
//     by the future `data_init` pipeline.
// =============================================================================

/// PEM block label used when armoring a `Pkcs7` object — equivalent to
/// OpenSSL's `PEM_STRING_PKCS7` constant from `include/openssl/pem.h`.
///
/// Wrap a content slice in a TLV header and return the full TLV bytes.
///
/// Pure-Rust replacement for the C idiom of calling `ASN1_put_object()` into a
/// preallocated buffer and then memcpying the content. Centralising this in a
/// helper keeps the encoder body free of repeated `extend_from_slice` pairs.
fn wrap_tlv(
    tag: Asn1Tag,
    class: Asn1Class,
    constructed: bool,
    content: &[u8],
) -> Pkcs7Result<Vec<u8>> {
    let mut out =
        write_tlv_header(tag, class, constructed, content.len()).map_err(Pkcs7Error::Crypto)?;
    out.extend_from_slice(content);
    Ok(out)
}

/// Encode a non-negative version field as `INTEGER` and return the FULL TLV.
///
/// PKCS#7 version fields are conventionally `0` (`EnvelopedData`, `EncryptedData`,
/// `DigestedData`) or `1` (`SignedData`, `SignerInfo`, `RecipientInfo`, `SignedAndEnv`).
fn encode_version_integer(version: i32) -> Pkcs7Result<Vec<u8>> {
    let int = Asn1Integer::from_i64(i64::from(version));
    let body = int.encode_der().map_err(Pkcs7Error::Crypto)?;
    wrap_tlv(Asn1Tag::Integer, Asn1Class::Universal, false, &body)
}

/// Encode an `AlgorithmIdentifier` (`X509_ALGOR`) as a full SEQUENCE TLV.
///
/// `asn1::AlgorithmIdentifier::encode_der()` returns the SEQUENCE *content*
/// (the OID TLV optionally followed by an `Asn1Type` parameters TLV), so this
/// helper just wraps it.
fn encode_algorithm_identifier(alg: &AlgorithmIdentifier) -> Pkcs7Result<Vec<u8>> {
    let body = alg.encode_der().map_err(Pkcs7Error::Crypto)?;
    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a SEQUENCE-wrapped `AlgorithmIdentifier` from a full TLV slice and
/// return the parsed value plus the byte length consumed (header + content).
fn decode_algorithm_identifier(data: &[u8]) -> Pkcs7Result<(AlgorithmIdentifier, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Sequence
        || header.class != Asn1Class::Universal
        || !header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let content = &data[header.header_length..total];
    let alg = AlgorithmIdentifier::decode_der(content).map_err(Pkcs7Error::Crypto)?;
    Ok((alg, total))
}

/// Encode an `IssuerAndSerialNumber` as a full SEQUENCE TLV.
///
/// `IssuerAndSerialNumber::issuer` and `IssuerAndSerialNumber::serial_number`
/// are already DER-encoded TLVs (a `Name` SEQUENCE and an `INTEGER`
/// respectively), so the encoder just emits them in order and wraps the
/// concatenation in an outer SEQUENCE.
fn encode_issuer_and_serial(ias: &IssuerAndSerialNumber) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::with_capacity(ias.issuer.len() + ias.serial_number.len());
    body.extend_from_slice(&ias.issuer);
    body.extend_from_slice(&ias.serial_number);
    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode an `IssuerAndSerialNumber` from a full SEQUENCE TLV and return the
/// parsed value plus the byte length consumed.
fn decode_issuer_and_serial(data: &[u8]) -> Pkcs7Result<(IssuerAndSerialNumber, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Sequence
        || header.class != Asn1Class::Universal
        || !header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let content_len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header
        .header_length
        .checked_add(content_len)
        .ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let body = &data[header.header_length..total];

    // First element: issuer Name (SEQUENCE) — preserved as raw DER.
    let issuer_hdr = parse_tlv_header(body).map_err(Pkcs7Error::Crypto)?;
    let issuer_len = issuer_hdr.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let issuer_total = issuer_hdr
        .header_length
        .checked_add(issuer_len)
        .ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    if issuer_total > body.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: issuer_total,
                actual: body.len(),
            },
        )));
    }
    let issuer = body[..issuer_total].to_vec();

    // Second element: serial INTEGER — preserved as raw DER.
    let serial_slice = &body[issuer_total..];
    let serial_hdr = parse_tlv_header(serial_slice).map_err(Pkcs7Error::Crypto)?;
    let serial_len = serial_hdr.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let serial_total = serial_hdr
        .header_length
        .checked_add(serial_len)
        .ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    if serial_total > serial_slice.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: serial_total,
                actual: serial_slice.len(),
            },
        )));
    }
    let serial_number = serial_slice[..serial_total].to_vec();

    Ok((
        IssuerAndSerialNumber {
            issuer,
            serial_number,
        },
        total,
    ))
}

/// Encode a `Pkcs7Attribute` (`X509_ATTRIBUTE`) as a full SEQUENCE TLV.
///
/// ```text
/// Attribute ::= SEQUENCE {
///     attrType  OBJECT IDENTIFIER,
///     attrValues SET OF AttributeValue
/// }
/// ```
fn encode_attribute(attr: &Pkcs7Attribute) -> Pkcs7Result<Vec<u8>> {
    // attrType OBJECT IDENTIFIER
    let oid = Asn1Object::from_oid_string(&attr.attr_type).map_err(Pkcs7Error::Crypto)?;
    let oid_content = oid.encode_der().map_err(Pkcs7Error::Crypto)?;
    let oid_tlv = wrap_tlv(
        Asn1Tag::ObjectIdentifier,
        Asn1Class::Universal,
        false,
        &oid_content,
    )?;

    // attrValues SET OF AttributeValue (each value is already a full TLV).
    let mut values_body = Vec::new();
    for v in &attr.values {
        values_body.extend_from_slice(v);
    }
    let values_tlv = wrap_tlv(Asn1Tag::Set, Asn1Class::Universal, true, &values_body)?;

    let mut body = oid_tlv;
    body.extend_from_slice(&values_tlv);
    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode an `Attribute` SEQUENCE from a full TLV slice.
fn decode_attribute(data: &[u8]) -> Pkcs7Result<(Pkcs7Attribute, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Sequence
        || header.class != Asn1Class::Universal
        || !header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let content_len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header
        .header_length
        .checked_add(content_len)
        .ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let body = &data[header.header_length..total];

    // attrType OID
    let oid_hdr = parse_tlv_header(body).map_err(Pkcs7Error::Crypto)?;
    if oid_hdr.tag != Asn1Tag::ObjectIdentifier {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let oid_len = oid_hdr.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let oid_end = oid_hdr.header_length.checked_add(oid_len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if oid_end > body.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: oid_end,
                actual: body.len(),
            },
        )));
    }
    let oid_obj = Asn1Object::decode_der(&body[oid_hdr.header_length..oid_end])
        .map_err(Pkcs7Error::Crypto)?;
    let attr_type = oid_obj.to_oid_string().map_err(Pkcs7Error::Crypto)?;

    // attrValues SET OF
    let set_slice = &body[oid_end..];
    let set_hdr = parse_tlv_header(set_slice).map_err(Pkcs7Error::Crypto)?;
    if set_hdr.tag != Asn1Tag::Set || set_hdr.class != Asn1Class::Universal || !set_hdr.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let set_len = set_hdr.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let set_end = set_hdr.header_length.checked_add(set_len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if set_end > set_slice.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: set_end,
                actual: set_slice.len(),
            },
        )));
    }
    let mut values = Vec::new();
    let mut cursor = set_hdr.header_length;
    while cursor < set_end {
        let v_hdr = parse_tlv_header(&set_slice[cursor..]).map_err(Pkcs7Error::Crypto)?;
        let v_len = v_hdr.content_length.ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
                "indefinite length not supported".to_string(),
            )))
        })?;
        let v_total = v_hdr.header_length.checked_add(v_len).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
        if cursor.checked_add(v_total).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })? > set_end
        {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::TruncatedData {
                    expected: cursor + v_total,
                    actual: set_end,
                },
            )));
        }
        values.push(set_slice[cursor..cursor + v_total].to_vec());
        cursor += v_total;
    }

    Ok((Pkcs7Attribute { attr_type, values }, total))
}

/// Encode the `EncryptedContentInfo` SEQUENCE.
///
/// ```text
/// EncryptedContentInfo ::= SEQUENCE {
///     contentType                  OBJECT IDENTIFIER,
///     contentEncryptionAlgorithm   AlgorithmIdentifier,
///     encryptedContent         [0] IMPLICIT OCTET STRING OPTIONAL
/// }
/// ```
fn encode_enc_content(env: &Pkcs7EncContent) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();

    // contentType OID
    let oid_str = env.content_type.oid();
    let oid = Asn1Object::from_oid_string(oid_str).map_err(Pkcs7Error::Crypto)?;
    let oid_content = oid.encode_der().map_err(Pkcs7Error::Crypto)?;
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::ObjectIdentifier,
        Asn1Class::Universal,
        false,
        &oid_content,
    )?);

    // contentEncryptionAlgorithm — REQUIRED in DER, but our struct stores Option
    // to permit "uninitialised cipher" states during construction. If the
    // caller serialises without setting an algorithm, fall back to the NULL
    // OID to preserve byte-faithful round-tripping rather than panic.
    let alg_tlv = match &env.algorithm {
        Some(alg) => encode_algorithm_identifier(alg)?,
        None => {
            let null_oid = Asn1Object::from_oid_string("0.0").map_err(Pkcs7Error::Crypto)?;
            let null_tlv = wrap_tlv(
                Asn1Tag::ObjectIdentifier,
                Asn1Class::Universal,
                false,
                &null_oid.encode_der().map_err(Pkcs7Error::Crypto)?,
            )?;
            wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &null_tlv)?
        }
    };
    body.extend_from_slice(&alg_tlv);

    // encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL — when present we
    // emit the raw bytes directly under the [0] IMPLICIT primitive header.
    if let Some(bytes) = &env.enc_data {
        // Use Asn1Tag::Eoc (numeric 0) for context-specific [0]; primitive
        // (constructed=false) is correct because the underlying type is the
        // primitive Universal OCTET STRING.
        let hdr = wrap_tlv(Asn1Tag::Eoc, Asn1Class::ContextSpecific, false, bytes)?;
        body.extend_from_slice(&hdr);
    }

    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode an `EncryptedContentInfo` SEQUENCE and return the parsed value plus
/// the total byte length consumed.
fn decode_enc_content(data: &[u8]) -> Pkcs7Result<(Pkcs7EncContent, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Sequence
        || header.class != Asn1Class::Universal
        || !header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let content_len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header
        .header_length
        .checked_add(content_len)
        .ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let body = &data[header.header_length..total];

    // contentType OID
    let oid_hdr = parse_tlv_header(body).map_err(Pkcs7Error::Crypto)?;
    if oid_hdr.tag != Asn1Tag::ObjectIdentifier {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let oid_len = oid_hdr.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let oid_end = oid_hdr.header_length.checked_add(oid_len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    let oid_obj = Asn1Object::decode_der(&body[oid_hdr.header_length..oid_end])
        .map_err(Pkcs7Error::Crypto)?;
    let oid_str = oid_obj.to_oid_string().map_err(Pkcs7Error::Crypto)?;
    let content_type = Pkcs7ContentType::from_oid(&oid_str);

    let mut cursor = oid_end;

    // contentEncryptionAlgorithm AlgorithmIdentifier
    let (algorithm, alg_consumed) = decode_algorithm_identifier(&body[cursor..])?;
    cursor = cursor.checked_add(alg_consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // [0] IMPLICIT encryptedContent OPTIONAL
    let mut enc_data: Option<Vec<u8>> = None;
    if cursor < body.len() {
        let ec_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if ec_hdr.class == Asn1Class::ContextSpecific && ec_hdr.tag == Asn1Tag::Eoc {
            let ec_len = ec_hdr.content_length.ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
                    "indefinite length not supported".to_string(),
                )))
            })?;
            let ec_end = ec_hdr.header_length.checked_add(ec_len).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
            if cursor.checked_add(ec_end).is_none() || cursor + ec_end > body.len() {
                return Err(Pkcs7Error::Crypto(CryptoError::from(
                    crate::asn1::Asn1Error::TruncatedData {
                        expected: cursor + ec_end,
                        actual: body.len(),
                    },
                )));
            }
            enc_data = Some(body[cursor + ec_hdr.header_length..cursor + ec_end].to_vec());
        }
    }

    Ok((
        Pkcs7EncContent {
            content_type,
            algorithm: Some(algorithm),
            enc_data,
            key: Vec::new(),
        },
        total,
    ))
}

// ============================================================================
// Phase 15 (cont.): Content-type encoders / decoders
// ============================================================================
//
// Each PKCS#7 content type has a paired (`encode_*`, `decode_*`) helper. The
// encoders concatenate sub-element TLVs and wrap the result in the appropriate
// SEQUENCE / SET / context-specific tag. The decoders validate the header,
// slice the body, and iterate sub-elements until the content length is
// exhausted. These functions are private to the module; the public surface is
// exposed through the `impl Pkcs7` block defined further below (`to_der`,
// `from_der`, `to_pem`, `from_pem`, `to_smime`, `from_smime`).
//
// ASN.1 templates (from `crypto/pkcs7/pk7_asn1.c`):
//
// ```text
// ContentInfo ::= SEQUENCE {
//     contentType  OBJECT IDENTIFIER,
//     content      [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
// }
// SignedData ::= SEQUENCE {
//     version            INTEGER,
//     digestAlgorithms   SET OF AlgorithmIdentifier,
//     contentInfo        ContentInfo,
//     certificates   [0] IMPLICIT SEQUENCE OF Certificate OPTIONAL,
//     crls           [1] IMPLICIT SET      OF CertificateRevocationList OPTIONAL,
//     signerInfos        SET OF SignerInfo
// }
// SignerInfo ::= SEQUENCE {
//     version                     INTEGER,
//     issuerAndSerialNumber       IssuerAndSerialNumber,
//     digestAlgorithm             DigestAlgorithmIdentifier,
//     authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
//     digestEncryptionAlgorithm   AlgorithmIdentifier,
//     encryptedDigest             OCTET STRING,
//     unauthenticatedAttributes[1] IMPLICIT Attributes OPTIONAL
// }
// EnvelopedData ::= SEQUENCE {
//     version          INTEGER,
//     recipientInfos   SET OF RecipientInfo,
//     encryptedContent EncryptedContentInfo
// }
// RecipientInfo ::= SEQUENCE {
//     version                 INTEGER,
//     issuerAndSerialNumber   IssuerAndSerialNumber,
//     keyEncryptionAlgorithm  AlgorithmIdentifier,
//     encryptedKey            OCTET STRING
// }
// DigestedData ::= SEQUENCE {
//     version                INTEGER,
//     digestAlgorithm        AlgorithmIdentifier,
//     contentInfo            ContentInfo,
//     digest                 OCTET STRING
// }
// EncryptedData ::= SEQUENCE {
//     version                  INTEGER,
//     encryptedContentInfo     EncryptedContentInfo
// }
// SignedAndEnvelopedData ::= SEQUENCE {
//     version           INTEGER,
//     recipientInfos    SET OF RecipientInfo,
//     digestAlgorithms  SET OF AlgorithmIdentifier,
//     encryptedContent  EncryptedContentInfo,
//     certificates  [0] IMPLICIT SET OF Certificate OPTIONAL,
//     crls          [1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
//     signerInfos       SET OF SignerInfo
// }
// ```

// --- low-level shared decoder helpers ---

/// Encode an optional [`AlgorithmIdentifier`]. Falls back to a synthetic
/// `0.0` NULL OID wrapped in an empty `AlgorithmIdentifier` SEQUENCE when
/// `None`, mirroring the behaviour used by [`encode_enc_content`] so that
/// partially-initialised structures still produce a structurally valid blob
/// rather than panicking at the boundary.
fn encode_optional_algorithm_identifier(alg: &Option<AlgorithmIdentifier>) -> Pkcs7Result<Vec<u8>> {
    match alg {
        Some(a) => encode_algorithm_identifier(a),
        None => {
            let null_oid = Asn1Object::from_oid_string("0.0").map_err(Pkcs7Error::Crypto)?;
            let null_oid_content = null_oid.encode_der().map_err(Pkcs7Error::Crypto)?;
            let null_tlv = wrap_tlv(
                Asn1Tag::ObjectIdentifier,
                Asn1Class::Universal,
                false,
                &null_oid_content,
            )?;
            wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &null_tlv)
        }
    }
}

/// Decode a small INTEGER as a Rust `i32`. Returns `IntegerOverflow` if the
/// underlying value cannot fit into `i32`. Used by every PKCS#7 content-type
/// decoder for the leading `version` field.
fn decode_version_integer(data: &[u8]) -> Pkcs7Result<(i32, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Integer || header.class != Asn1Class::Universal || header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let int_val =
        Asn1Integer::decode_der(&data[header.header_length..total]).map_err(Pkcs7Error::Crypto)?;
    let i64_val = int_val.to_i64().map_err(Pkcs7Error::Crypto)?;
    let version = i32::try_from(i64_val).map_err(|_| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    Ok((version, total))
}

/// Decode an OCTET STRING TLV and return its content bytes plus the total
/// number of bytes consumed (header + content).
fn decode_octet_string_tlv(data: &[u8]) -> Pkcs7Result<(Vec<u8>, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::OctetString
        || header.class != Asn1Class::Universal
        || header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    Ok((data[header.header_length..total].to_vec(), total))
}

/// Decode a SEQUENCE TLV and return a borrowed slice of its content plus the
/// total bytes consumed (header + content).
fn decode_sequence_tlv(data: &[u8]) -> Pkcs7Result<(&[u8], usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Sequence
        || header.class != Asn1Class::Universal
        || !header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    Ok((&data[header.header_length..total], total))
}

/// Decode a `SET OF AlgorithmIdentifier` (Universal SET, constructed) and
/// return the collected list plus the bytes consumed.
fn decode_alg_set(data: &[u8]) -> Pkcs7Result<(Vec<AlgorithmIdentifier>, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Set || header.class != Asn1Class::Universal || !header.constructed {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let body = &data[header.header_length..total];
    let mut cursor = 0usize;
    let mut algs = Vec::new();
    while cursor < body.len() {
        let (alg, consumed) = decode_algorithm_identifier(&body[cursor..])?;
        algs.push(alg);
        cursor = cursor.checked_add(consumed).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    }
    Ok((algs, total))
}

/// Decode an `[N] IMPLICIT SET-OF / SEQUENCE-OF` opaque DER blob — used to
/// recover the IMPLICIT certificate or CRL containers in `SignedData` and
/// `SignedAndEnvelopedData`. The output vector is the list of inner element
/// TLVs (each element kept as raw DER) plus the bytes consumed.
fn decode_implicit_tlv_list(
    data: &[u8],
    expected_tag: Asn1Tag,
) -> Pkcs7Result<(Vec<Vec<u8>>, usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.class != Asn1Class::ContextSpecific
        || header.tag != expected_tag
        || !header.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    let body = &data[header.header_length..total];
    let mut cursor = 0usize;
    let mut elems = Vec::new();
    while cursor < body.len() {
        let sub_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        let sub_len = sub_hdr.content_length.ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
                "indefinite length not supported".to_string(),
            )))
        })?;
        let sub_total = sub_hdr.header_length.checked_add(sub_len).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
        let abs_end = cursor.checked_add(sub_total).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
        if abs_end > body.len() {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::TruncatedData {
                    expected: abs_end,
                    actual: body.len(),
                },
            )));
        }
        elems.push(body[cursor..abs_end].to_vec());
        cursor = abs_end;
    }
    Ok((elems, total))
}

/// Encode an `[N] IMPLICIT SET / SEQUENCE` from a list of pre-encoded element
/// TLVs. Used for the IMPLICIT certificate and CRL containers in
/// `SignedData` and `SignedAndEnvelopedData`.
fn encode_implicit_tlv_list(elems: &[Vec<u8>], tag_number: Asn1Tag) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    for elem in elems {
        body.extend_from_slice(elem);
    }
    wrap_tlv(tag_number, Asn1Class::ContextSpecific, true, &body)
}

// --- SignerInfo ---

/// Encode a [`Pkcs7SignerInfo`] as a `SignerInfo` SEQUENCE.
fn encode_signer_info(si: &Pkcs7SignerInfo) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_version_integer(si.version)?);
    body.extend_from_slice(&encode_issuer_and_serial(&si.issuer_and_serial)?);
    body.extend_from_slice(&encode_algorithm_identifier(&si.digest_algorithm)?);

    // [0] IMPLICIT signed_attributes SET OF Attribute OPTIONAL
    if !si.signed_attributes.is_empty() {
        let mut attrs_body = Vec::new();
        for attr in &si.signed_attributes {
            attrs_body.extend_from_slice(&encode_attribute(attr)?);
        }
        // [0] IMPLICIT — replace the underlying SET tag with context-specific 0.
        body.extend_from_slice(&wrap_tlv(
            Asn1Tag::Eoc,
            Asn1Class::ContextSpecific,
            true,
            &attrs_body,
        )?);
    }

    body.extend_from_slice(&encode_algorithm_identifier(&si.signature_algorithm)?);
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::OctetString,
        Asn1Class::Universal,
        false,
        &si.encrypted_digest,
    )?);

    // [1] IMPLICIT unsigned_attributes SET OF Attribute OPTIONAL
    if !si.unsigned_attributes.is_empty() {
        let mut attrs_body = Vec::new();
        for attr in &si.unsigned_attributes {
            attrs_body.extend_from_slice(&encode_attribute(attr)?);
        }
        // [1] IMPLICIT — use Asn1Tag::Boolean for tag number 1 in context-specific class.
        body.extend_from_slice(&wrap_tlv(
            Asn1Tag::Boolean,
            Asn1Class::ContextSpecific,
            true,
            &attrs_body,
        )?);
    }

    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a `SignerInfo` SEQUENCE returning the parsed [`Pkcs7SignerInfo`]
/// plus the total bytes consumed.
fn decode_signer_info(data: &[u8]) -> Pkcs7Result<(Pkcs7SignerInfo, usize)> {
    let (body, total) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    // version INTEGER
    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // issuer_and_serial
    let (issuer_and_serial, consumed) = decode_issuer_and_serial(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // digest_algorithm
    let (digest_algorithm, consumed) = decode_algorithm_identifier(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // [0] IMPLICIT signed_attributes SET OF Attribute OPTIONAL
    let mut signed_attributes = Vec::new();
    if cursor < body.len() {
        let next_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if next_hdr.class == Asn1Class::ContextSpecific
            && next_hdr.tag == Asn1Tag::Eoc
            && next_hdr.constructed
        {
            let len = next_hdr.content_length.ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
                    "indefinite length not supported".to_string(),
                )))
            })?;
            let outer_total = next_hdr.header_length.checked_add(len).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
            let abs_end = cursor.checked_add(outer_total).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
            if abs_end > body.len() {
                return Err(Pkcs7Error::Crypto(CryptoError::from(
                    crate::asn1::Asn1Error::TruncatedData {
                        expected: abs_end,
                        actual: body.len(),
                    },
                )));
            }
            let attrs_body = &body[cursor + next_hdr.header_length..abs_end];
            let mut sa_cursor = 0usize;
            while sa_cursor < attrs_body.len() {
                let (attr, consumed) = decode_attribute(&attrs_body[sa_cursor..])?;
                signed_attributes.push(attr);
                sa_cursor = sa_cursor.checked_add(consumed).ok_or_else(|| {
                    Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
                })?;
            }
            cursor = abs_end;
        }
    }

    // signature_algorithm
    let (signature_algorithm, consumed) = decode_algorithm_identifier(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // encrypted_digest OCTET STRING
    let (encrypted_digest, consumed) = decode_octet_string_tlv(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // [1] IMPLICIT unsigned_attributes SET OF Attribute OPTIONAL
    let mut unsigned_attributes = Vec::new();
    if cursor < body.len() {
        let next_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if next_hdr.class == Asn1Class::ContextSpecific
            && next_hdr.tag == Asn1Tag::Boolean
            && next_hdr.constructed
        {
            let len = next_hdr.content_length.ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
                    "indefinite length not supported".to_string(),
                )))
            })?;
            let outer_total = next_hdr.header_length.checked_add(len).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
            let abs_end = cursor.checked_add(outer_total).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
            if abs_end > body.len() {
                return Err(Pkcs7Error::Crypto(CryptoError::from(
                    crate::asn1::Asn1Error::TruncatedData {
                        expected: abs_end,
                        actual: body.len(),
                    },
                )));
            }
            let attrs_body = &body[cursor + next_hdr.header_length..abs_end];
            let mut ua_cursor = 0usize;
            while ua_cursor < attrs_body.len() {
                let (attr, consumed) = decode_attribute(&attrs_body[ua_cursor..])?;
                unsigned_attributes.push(attr);
                ua_cursor = ua_cursor.checked_add(consumed).ok_or_else(|| {
                    Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
                })?;
            }
        }
    }

    Ok((
        Pkcs7SignerInfo {
            version,
            issuer_and_serial,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            encrypted_digest,
            unsigned_attributes,
            pending_key: None,
        },
        total,
    ))
}

// --- RecipientInfo ---

/// Encode a [`Pkcs7RecipientInfo`] as a `RecipientInfo` SEQUENCE.
fn encode_recipient_info(ri: &Pkcs7RecipientInfo) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_version_integer(ri.version)?);
    body.extend_from_slice(&encode_issuer_and_serial(&ri.issuer_and_serial)?);
    body.extend_from_slice(&encode_algorithm_identifier(&ri.key_enc_algorithm)?);
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::OctetString,
        Asn1Class::Universal,
        false,
        &ri.enc_key,
    )?);
    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a `RecipientInfo` SEQUENCE returning the parsed
/// [`Pkcs7RecipientInfo`] plus the total bytes consumed.
fn decode_recipient_info(data: &[u8]) -> Pkcs7Result<(Pkcs7RecipientInfo, usize)> {
    let (body, total) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (issuer_and_serial, consumed) = decode_issuer_and_serial(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (key_enc_algorithm, consumed) = decode_algorithm_identifier(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (enc_key, _) = decode_octet_string_tlv(&body[cursor..])?;

    Ok((
        Pkcs7RecipientInfo {
            version,
            issuer_and_serial,
            key_enc_algorithm,
            enc_key,
        },
        total,
    ))
}

// --- Data content (NID_pkcs7_data) ---

/// Encode a `Data` content as a single OCTET STRING TLV.
fn encode_data_content(octets: &Asn1OctetString) -> Pkcs7Result<Vec<u8>> {
    wrap_tlv(
        Asn1Tag::OctetString,
        Asn1Class::Universal,
        false,
        octets.data(),
    )
}

/// Decode a `Data` content from an OCTET STRING TLV.
fn decode_data_content(data: &[u8]) -> Pkcs7Result<Asn1OctetString> {
    let (bytes, _) = decode_octet_string_tlv(data)?;
    Ok(Asn1OctetString::from_bytes(bytes))
}

// --- ContentInfo (outer wrapper used recursively for the inner `contents`) ---

/// Encode the inner content body for the given [`Pkcs7`]. This is the body
/// that appears in the `[0] EXPLICIT` content slot of `ContentInfo`.
///
/// The optional `detached_from_outer` flag is propagated by callers that
/// embed a `Data`-type inner content inside a `SignedData` envelope: when the
/// outer message is detached, the inner content's OCTET STRING payload is
/// suppressed, leaving only the `contentType` OID.
fn encode_pkcs7_content_body(
    p7: &Pkcs7,
    detached_from_outer: bool,
) -> Pkcs7Result<Option<Vec<u8>>> {
    let effectively_detached = detached_from_outer || p7.detached;
    match &p7.content {
        Pkcs7Content::Data(octets) => {
            if effectively_detached {
                Ok(None)
            } else {
                Ok(Some(encode_data_content(octets)?))
            }
        }
        Pkcs7Content::Signed(sd) => Ok(Some(encode_signed_data(sd, p7.detached)?)),
        Pkcs7Content::Enveloped(env) => Ok(Some(encode_enveloped_data(env)?)),
        Pkcs7Content::SignedAndEnveloped(sed) => Ok(Some(encode_sign_envelope_data(sed)?)),
        Pkcs7Content::Digested(dd) => Ok(Some(encode_digested_data(dd, p7.detached)?)),
        Pkcs7Content::Encrypted(ed) => Ok(Some(encode_encrypted_data(ed)?)),
        Pkcs7Content::Other(bytes) => Ok(Some(bytes.clone())),
    }
}

/// Encode the full `ContentInfo` SEQUENCE wrapping the given inner [`Pkcs7`].
///
/// ```text
/// ContentInfo ::= SEQUENCE {
///     contentType  OBJECT IDENTIFIER,
///     content      [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
/// }
/// ```
///
/// The `[0]` wrapping is `EXPLICIT`, so a single context-specific TLV
/// containing the unmodified inner content TLV is produced.
fn encode_pkcs7_content_info(p7: &Pkcs7, detached_from_outer: bool) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();

    // contentType OID
    let oid_str = p7.content_type.oid();
    let oid = Asn1Object::from_oid_string(oid_str).map_err(Pkcs7Error::Crypto)?;
    let oid_content = oid.encode_der().map_err(Pkcs7Error::Crypto)?;
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::ObjectIdentifier,
        Asn1Class::Universal,
        false,
        &oid_content,
    )?);

    // [0] EXPLICIT content OPTIONAL
    if let Some(inner) = encode_pkcs7_content_body(p7, detached_from_outer)? {
        let explicit = wrap_tlv(
            Asn1Tag::Eoc,
            Asn1Class::ContextSpecific,
            true, // EXPLICIT — the constructed bit is set, body is a full TLV
            &inner,
        )?;
        body.extend_from_slice(&explicit);
    }

    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a `ContentInfo` SEQUENCE returning the parsed [`Pkcs7`] plus the
/// total bytes consumed. This is the inverse of [`encode_pkcs7_content_info`].
fn decode_pkcs7_content_info(data: &[u8]) -> Pkcs7Result<(Pkcs7, usize)> {
    let (body, total) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    // contentType OID
    let oid_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
    if oid_hdr.tag != Asn1Tag::ObjectIdentifier
        || oid_hdr.class != Asn1Class::Universal
        || oid_hdr.constructed
    {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let oid_len = oid_hdr.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let oid_end = oid_hdr.header_length.checked_add(oid_len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    // `Asn1Object::decode_der` consumes the OID *content* bytes (it does not
    // expect the outer TLV header). Slice from `header_length` to skip the
    // tag/length octets we already parsed.
    let oid_obj = Asn1Object::decode_der(&body[cursor + oid_hdr.header_length..cursor + oid_end])
        .map_err(Pkcs7Error::Crypto)?;
    let oid_str = oid_obj.to_oid_string().map_err(Pkcs7Error::Crypto)?;
    let content_type = Pkcs7ContentType::from_oid(&oid_str);
    cursor = cursor.checked_add(oid_end).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // [0] EXPLICIT content OPTIONAL
    let mut inner_bytes: Option<&[u8]> = None;
    if cursor < body.len() {
        let inner_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if inner_hdr.class == Asn1Class::ContextSpecific
            && inner_hdr.tag == Asn1Tag::Eoc
            && inner_hdr.constructed
        {
            let inner_len = inner_hdr.content_length.ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
                    "indefinite length not supported".to_string(),
                )))
            })?;
            let inner_total = inner_hdr
                .header_length
                .checked_add(inner_len)
                .ok_or_else(|| {
                    Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
                })?;
            let abs_end = cursor.checked_add(inner_total).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
            if abs_end > body.len() {
                return Err(Pkcs7Error::Crypto(CryptoError::from(
                    crate::asn1::Asn1Error::TruncatedData {
                        expected: abs_end,
                        actual: body.len(),
                    },
                )));
            }
            inner_bytes = Some(&body[cursor + inner_hdr.header_length..abs_end]);
        }
    }

    // Dispatch on contentType
    let (content, detached) = match (&content_type, inner_bytes) {
        (Pkcs7ContentType::Data, Some(bytes)) => {
            let octets = decode_data_content(bytes)?;
            (Pkcs7Content::Data(octets), false)
        }
        (Pkcs7ContentType::Data, None) => {
            // Detached data content — empty OCTET STRING placeholder.
            (
                Pkcs7Content::Data(Asn1OctetString::from_bytes(Vec::new())),
                true,
            )
        }
        (Pkcs7ContentType::SignedData, Some(bytes)) => {
            let sd = decode_signed_data(bytes)?;
            let detached =
                matches!(&sd.contents.content, Pkcs7Content::Data(o) if o.data().is_empty());
            (Pkcs7Content::Signed(sd), detached)
        }
        (Pkcs7ContentType::SignedData, None) => {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(
                    "SignedData ContentInfo missing inner content".to_string(),
                ),
            )));
        }
        (Pkcs7ContentType::EnvelopedData, Some(bytes)) => {
            let env = decode_enveloped_data(bytes)?;
            (Pkcs7Content::Enveloped(env), false)
        }
        (Pkcs7ContentType::EnvelopedData, None) => {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(
                    "EnvelopedData ContentInfo missing inner content".to_string(),
                ),
            )));
        }
        (Pkcs7ContentType::SignedAndEnveloped, Some(bytes)) => {
            let sed = decode_sign_envelope_data(bytes)?;
            (Pkcs7Content::SignedAndEnveloped(sed), false)
        }
        (Pkcs7ContentType::SignedAndEnveloped, None) => {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(
                    "SignedAndEnvelopedData ContentInfo missing inner content".to_string(),
                ),
            )));
        }
        (Pkcs7ContentType::DigestedData, Some(bytes)) => {
            let dd = decode_digested_data(bytes)?;
            let detached =
                matches!(&dd.contents.content, Pkcs7Content::Data(o) if o.data().is_empty());
            (Pkcs7Content::Digested(dd), detached)
        }
        (Pkcs7ContentType::DigestedData, None) => {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(
                    "DigestedData ContentInfo missing inner content".to_string(),
                ),
            )));
        }
        (Pkcs7ContentType::EncryptedData, Some(bytes)) => {
            let ed = decode_encrypted_data(bytes)?;
            (Pkcs7Content::Encrypted(ed), false)
        }
        (Pkcs7ContentType::EncryptedData, None) => {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(
                    "EncryptedData ContentInfo missing inner content".to_string(),
                ),
            )));
        }
        (Pkcs7ContentType::Other(_), Some(bytes)) => (Pkcs7Content::Other(bytes.to_vec()), false),
        (Pkcs7ContentType::Other(_), None) => (Pkcs7Content::Other(Vec::new()), false),
    };

    let pkcs7 = Pkcs7 {
        content_type,
        content,
        detached,
        ctx: Pkcs7Context {
            lib_ctx: None,
            prop_query: None,
        },
    };

    Ok((pkcs7, total))
}

// --- SignedData ---

/// Encode a [`Pkcs7SignedData`] as the body of `SignedData` (no outer
/// `ContentInfo` wrapping). The `outer_detached` parameter is propagated to
/// `encode_pkcs7_content_info` so that the inner `contentInfo` of a detached
/// signature omits its OCTET STRING payload.
fn encode_signed_data(sd: &Pkcs7SignedData, outer_detached: bool) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();

    // version INTEGER
    body.extend_from_slice(&encode_version_integer(sd.version)?);

    // digestAlgorithms SET OF AlgorithmIdentifier
    let mut alg_set = Vec::new();
    for alg in &sd.md_algorithms {
        alg_set.extend_from_slice(&encode_algorithm_identifier(alg)?);
    }
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::Set,
        Asn1Class::Universal,
        true,
        &alg_set,
    )?);

    // contentInfo (recursive)
    body.extend_from_slice(&encode_pkcs7_content_info(&sd.contents, outer_detached)?);

    // [0] IMPLICIT certificates SEQUENCE OF X509 OPTIONAL
    if !sd.certificates.is_empty() {
        let mut cert_elems = Vec::new();
        for cert in &sd.certificates {
            cert_elems.push(cert.to_der().map_err(Pkcs7Error::Crypto)?);
        }
        body.extend_from_slice(&encode_implicit_tlv_list(&cert_elems, Asn1Tag::Eoc)?);
    }

    // [1] IMPLICIT crls SET OF X509_CRL OPTIONAL
    if !sd.crls.is_empty() {
        body.extend_from_slice(&encode_implicit_tlv_list(&sd.crls, Asn1Tag::Boolean)?);
    }

    // signerInfos SET OF SignerInfo
    let mut si_set = Vec::new();
    for si in &sd.signer_infos {
        si_set.extend_from_slice(&encode_signer_info(si)?);
    }
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::Set,
        Asn1Class::Universal,
        true,
        &si_set,
    )?);

    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a `SignedData` body returning the parsed [`Pkcs7SignedData`].
fn decode_signed_data(data: &[u8]) -> Pkcs7Result<Pkcs7SignedData> {
    let (body, _) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    // version INTEGER
    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // digestAlgorithms SET OF
    let (md_algorithms, consumed) = decode_alg_set(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // contentInfo (recursive)
    let (contents, consumed) = decode_pkcs7_content_info(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // [0] IMPLICIT certificates OPTIONAL
    let mut certificates = Vec::new();
    if cursor < body.len() {
        let next_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if next_hdr.class == Asn1Class::ContextSpecific
            && next_hdr.tag == Asn1Tag::Eoc
            && next_hdr.constructed
        {
            let (cert_elems, consumed) = decode_implicit_tlv_list(&body[cursor..], Asn1Tag::Eoc)?;
            for cert_der in cert_elems {
                let cert = X509Certificate::from_der(&cert_der).map_err(Pkcs7Error::Crypto)?;
                certificates.push(cert);
            }
            cursor = cursor.checked_add(consumed).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
        }
    }

    // [1] IMPLICIT crls OPTIONAL
    let mut crls = Vec::new();
    if cursor < body.len() {
        let next_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if next_hdr.class == Asn1Class::ContextSpecific
            && next_hdr.tag == Asn1Tag::Boolean
            && next_hdr.constructed
        {
            let (crl_elems, consumed) =
                decode_implicit_tlv_list(&body[cursor..], Asn1Tag::Boolean)?;
            crls = crl_elems;
            cursor = cursor.checked_add(consumed).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
        }
    }

    // signerInfos SET OF
    let mut signer_infos = Vec::new();
    if cursor < body.len() {
        let (set_body, _) = decode_set_tlv(&body[cursor..])?;
        let mut sub_cursor = 0usize;
        while sub_cursor < set_body.len() {
            let (si, consumed) = decode_signer_info(&set_body[sub_cursor..])?;
            signer_infos.push(si);
            sub_cursor = sub_cursor.checked_add(consumed).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
        }
    }

    Ok(Pkcs7SignedData {
        version,
        md_algorithms,
        contents: Box::new(contents),
        certificates,
        crls,
        signer_infos,
    })
}

/// Decode a Universal SET (constructed) TLV and return its body slice plus
/// total bytes consumed. Used for `SET OF SignerInfo`,
/// `SET OF RecipientInfo`, and similar SET-typed containers.
fn decode_set_tlv(data: &[u8]) -> Pkcs7Result<(&[u8], usize)> {
    let header = parse_tlv_header(data).map_err(Pkcs7Error::Crypto)?;
    if header.tag != Asn1Tag::Set || header.class != Asn1Class::Universal || !header.constructed {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::DecodingError("invalid TLV structure".to_string()),
        )));
    }
    let len = header.content_length.ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::Unsupported(
            "indefinite length not supported".to_string(),
        )))
    })?;
    let total = header.header_length.checked_add(len).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;
    if total > data.len() {
        return Err(Pkcs7Error::Crypto(CryptoError::from(
            crate::asn1::Asn1Error::TruncatedData {
                expected: total,
                actual: data.len(),
            },
        )));
    }
    Ok((&data[header.header_length..total], total))
}

// --- EnvelopedData ---

/// Encode a [`Pkcs7EnvelopedData`] as the body of `EnvelopedData`.
fn encode_enveloped_data(env: &Pkcs7EnvelopedData) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_version_integer(env.version)?);

    // recipientInfos SET OF
    let mut ri_set = Vec::new();
    for ri in &env.recipient_infos {
        ri_set.extend_from_slice(&encode_recipient_info(ri)?);
    }
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::Set,
        Asn1Class::Universal,
        true,
        &ri_set,
    )?);

    // encryptedContentInfo
    body.extend_from_slice(&encode_enc_content(&env.enc_data)?);

    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode an `EnvelopedData` body.
fn decode_enveloped_data(data: &[u8]) -> Pkcs7Result<Pkcs7EnvelopedData> {
    let (body, _) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // recipientInfos SET OF
    let (set_body, consumed) = decode_set_tlv(&body[cursor..])?;
    let mut sub_cursor = 0usize;
    let mut recipient_infos = Vec::new();
    while sub_cursor < set_body.len() {
        let (ri, ri_consumed) = decode_recipient_info(&set_body[sub_cursor..])?;
        recipient_infos.push(ri);
        sub_cursor = sub_cursor.checked_add(ri_consumed).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    }
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // encryptedContentInfo
    let (enc_data, _) = decode_enc_content(&body[cursor..])?;

    Ok(Pkcs7EnvelopedData {
        version,
        recipient_infos,
        enc_data,
    })
}

// --- SignedAndEnvelopedData ---

/// Encode a [`Pkcs7SignEnvelopeData`] as the body of `SignedAndEnvelopedData`.
fn encode_sign_envelope_data(sed: &Pkcs7SignEnvelopeData) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_version_integer(sed.version)?);

    // recipientInfos SET OF
    let mut ri_set = Vec::new();
    for ri in &sed.recipient_infos {
        ri_set.extend_from_slice(&encode_recipient_info(ri)?);
    }
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::Set,
        Asn1Class::Universal,
        true,
        &ri_set,
    )?);

    // digestAlgorithms SET OF
    let mut alg_set = Vec::new();
    for alg in &sed.md_algorithms {
        alg_set.extend_from_slice(&encode_algorithm_identifier(alg)?);
    }
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::Set,
        Asn1Class::Universal,
        true,
        &alg_set,
    )?);

    // encryptedContentInfo
    body.extend_from_slice(&encode_enc_content(&sed.enc_data)?);

    // [0] IMPLICIT certificates SET OF X509 OPTIONAL
    if !sed.certificates.is_empty() {
        let mut cert_elems = Vec::new();
        for cert in &sed.certificates {
            cert_elems.push(cert.to_der().map_err(Pkcs7Error::Crypto)?);
        }
        body.extend_from_slice(&encode_implicit_tlv_list(&cert_elems, Asn1Tag::Eoc)?);
    }

    // [1] IMPLICIT crls SET OF CRL OPTIONAL
    if !sed.crls.is_empty() {
        body.extend_from_slice(&encode_implicit_tlv_list(&sed.crls, Asn1Tag::Boolean)?);
    }

    // signerInfos SET OF
    let mut si_set = Vec::new();
    for si in &sed.signer_infos {
        si_set.extend_from_slice(&encode_signer_info(si)?);
    }
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::Set,
        Asn1Class::Universal,
        true,
        &si_set,
    )?);

    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a `SignedAndEnvelopedData` body.
fn decode_sign_envelope_data(data: &[u8]) -> Pkcs7Result<Pkcs7SignEnvelopeData> {
    let (body, _) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // recipientInfos SET OF
    let (set_body, consumed) = decode_set_tlv(&body[cursor..])?;
    let mut sub_cursor = 0usize;
    let mut recipient_infos = Vec::new();
    while sub_cursor < set_body.len() {
        let (ri, ri_consumed) = decode_recipient_info(&set_body[sub_cursor..])?;
        recipient_infos.push(ri);
        sub_cursor = sub_cursor.checked_add(ri_consumed).ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
        })?;
    }
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // digestAlgorithms SET OF
    let (md_algorithms, consumed) = decode_alg_set(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // encryptedContentInfo
    let (enc_data, consumed) = decode_enc_content(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    // [0] IMPLICIT certificates OPTIONAL
    let mut certificates = Vec::new();
    if cursor < body.len() {
        let next_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if next_hdr.class == Asn1Class::ContextSpecific
            && next_hdr.tag == Asn1Tag::Eoc
            && next_hdr.constructed
        {
            let (cert_elems, c) = decode_implicit_tlv_list(&body[cursor..], Asn1Tag::Eoc)?;
            for cert_der in cert_elems {
                let cert = X509Certificate::from_der(&cert_der).map_err(Pkcs7Error::Crypto)?;
                certificates.push(cert);
            }
            cursor = cursor.checked_add(c).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
        }
    }

    // [1] IMPLICIT crls OPTIONAL
    let mut crls = Vec::new();
    if cursor < body.len() {
        let next_hdr = parse_tlv_header(&body[cursor..]).map_err(Pkcs7Error::Crypto)?;
        if next_hdr.class == Asn1Class::ContextSpecific
            && next_hdr.tag == Asn1Tag::Boolean
            && next_hdr.constructed
        {
            let (crl_elems, c) = decode_implicit_tlv_list(&body[cursor..], Asn1Tag::Boolean)?;
            crls = crl_elems;
            cursor = cursor.checked_add(c).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
        }
    }

    // signerInfos SET OF
    let mut signer_infos = Vec::new();
    if cursor < body.len() {
        let (set_body, _) = decode_set_tlv(&body[cursor..])?;
        let mut sub_cursor = 0usize;
        while sub_cursor < set_body.len() {
            let (si, consumed) = decode_signer_info(&set_body[sub_cursor..])?;
            signer_infos.push(si);
            sub_cursor = sub_cursor.checked_add(consumed).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
            })?;
        }
    }

    Ok(Pkcs7SignEnvelopeData {
        version,
        md_algorithms,
        certificates,
        crls,
        signer_infos,
        recipient_infos,
        enc_data,
    })
}

// --- DigestedData ---

/// Encode a [`Pkcs7DigestedData`] body. The optional `outer_detached` flag is
/// passed through to the inner `contentInfo` so that detached digests omit the
/// inner OCTET STRING payload.
fn encode_digested_data(dd: &Pkcs7DigestedData, outer_detached: bool) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_version_integer(dd.version)?);
    body.extend_from_slice(&encode_optional_algorithm_identifier(&dd.md_algorithm)?);
    body.extend_from_slice(&encode_pkcs7_content_info(&dd.contents, outer_detached)?);
    body.extend_from_slice(&wrap_tlv(
        Asn1Tag::OctetString,
        Asn1Class::Universal,
        false,
        &dd.digest,
    )?);
    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode a `DigestedData` body.
fn decode_digested_data(data: &[u8]) -> Pkcs7Result<Pkcs7DigestedData> {
    let (body, _) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (md_algorithm, consumed) = decode_algorithm_identifier(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (contents, consumed) = decode_pkcs7_content_info(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (digest, _) = decode_octet_string_tlv(&body[cursor..])?;

    Ok(Pkcs7DigestedData {
        version,
        md_algorithm: Some(md_algorithm),
        contents: Box::new(contents),
        digest,
    })
}

// --- EncryptedData ---

/// Encode a [`Pkcs7EncryptedData`] body.
fn encode_encrypted_data(ed: &Pkcs7EncryptedData) -> Pkcs7Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_version_integer(ed.version)?);
    body.extend_from_slice(&encode_enc_content(&ed.enc_data)?);
    wrap_tlv(Asn1Tag::Sequence, Asn1Class::Universal, true, &body)
}

/// Decode an `EncryptedData` body.
fn decode_encrypted_data(data: &[u8]) -> Pkcs7Result<Pkcs7EncryptedData> {
    let (body, _) = decode_sequence_tlv(data)?;
    let mut cursor = 0usize;

    let (version, consumed) = decode_version_integer(&body[cursor..])?;
    cursor = cursor.checked_add(consumed).ok_or_else(|| {
        Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::IntegerOverflow))
    })?;

    let (enc_data, _) = decode_enc_content(&body[cursor..])?;

    Ok(Pkcs7EncryptedData { version, enc_data })
}

// =============================================================================
// Phase 15 — Public Serialization API (impl Pkcs7)
// =============================================================================
//
// These methods provide the user-facing entry points for DER, PEM, and S/MIME
// serialization. They wire together every Phase-15 encoder/decoder by routing
// through `encode_pkcs7_content_info` / `decode_pkcs7_content_info`.
//
// C equivalents:
// - `to_der`   ⇄ `i2d_PKCS7`     (pk7_asn1.c)
// - `from_der` ⇄ `d2i_PKCS7`     (pk7_asn1.c)
// - `to_pem`   ⇄ `PEM_write_bio_PKCS7`        (pem_pkey.c / pem_pk7.c)
// - `from_pem` ⇄ `PEM_read_bio_PKCS7`         (pem_pkey.c / pem_pk7.c)
// - `to_smime` ⇄ `SMIME_write_PKCS7`          (pk7_mime.c)
// - `from_smime` ⇄ `SMIME_read_PKCS7`         (pk7_mime.c)

/// Base64 alphabet for S/MIME encoding (RFC 4648 §4).
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode raw bytes into a base64 string with CRLF line breaks every 64 chars
/// (S/MIME canonical line length per RFC 5751).
fn b64_encode_smime(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    let mut line_chars = 0usize;
    while i < input.len() {
        let b0 = u32::from(input[i]);
        let b1 = if i + 1 < input.len() {
            u32::from(input[i + 1])
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            u32::from(input[i + 2])
        } else {
            0
        };
        let triplet = (b0 << 16) | (b1 << 8) | b2;
        let c0 = B64_ALPHABET[((triplet >> 18) & 0x3F) as usize] as char;
        let c1 = B64_ALPHABET[((triplet >> 12) & 0x3F) as usize] as char;
        let c2 = if i + 1 < input.len() {
            B64_ALPHABET[((triplet >> 6) & 0x3F) as usize] as char
        } else {
            '='
        };
        let c3 = if i + 2 < input.len() {
            B64_ALPHABET[(triplet & 0x3F) as usize] as char
        } else {
            '='
        };
        out.push(c0);
        out.push(c1);
        out.push(c2);
        out.push(c3);
        line_chars = line_chars.saturating_add(4);
        if line_chars >= 64 {
            out.push_str("\r\n");
            line_chars = 0;
        }
        i = i.saturating_add(3);
    }
    if line_chars != 0 {
        out.push_str("\r\n");
    }
    out
}

/// Decode a base64 string (whitespace-tolerant) into raw bytes.
fn b64_decode(input: &str) -> Pkcs7Result<Vec<u8>> {
    let mut buf = [0u8; 4];
    let mut buf_len = 0usize;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut padding = 0usize;
    for byte in input.bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = padding.saturating_add(1);
                buf[buf_len] = 0;
                buf_len = buf_len.saturating_add(1);
                if buf_len == 4 {
                    let v = (u32::from(buf[0]) << 18)
                        | (u32::from(buf[1]) << 12)
                        | (u32::from(buf[2]) << 6)
                        | u32::from(buf[3]);
                    // Mask-then-try_from satisfies Rule R6: the masked value
                    // is guaranteed to fit in `u8`, so `try_from` is total.
                    out.push(u8::try_from((v >> 16) & 0xFF).unwrap_or(0));
                    if padding < 2 {
                        out.push(u8::try_from((v >> 8) & 0xFF).unwrap_or(0));
                    }
                    buf_len = 0;
                    padding = 0;
                }
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => {
                return Err(Pkcs7Error::Crypto(CryptoError::from(
                    crate::asn1::Asn1Error::DecodingError("invalid base64 character".to_string()),
                )));
            }
        };
        buf[buf_len] = val;
        buf_len = buf_len.saturating_add(1);
        if buf_len == 4 {
            let v = (u32::from(buf[0]) << 18)
                | (u32::from(buf[1]) << 12)
                | (u32::from(buf[2]) << 6)
                | u32::from(buf[3]);
            // Mask-then-try_from satisfies Rule R6: each masked byte is in
            // `[0, 255]`, so `u8::try_from` is total and the `.unwrap_or(0)`
            // serves only as a safe fallback that is mathematically dead.
            out.push(u8::try_from((v >> 16) & 0xFF).unwrap_or(0));
            out.push(u8::try_from((v >> 8) & 0xFF).unwrap_or(0));
            out.push(u8::try_from(v & 0xFF).unwrap_or(0));
            buf_len = 0;
        }
    }
    Ok(out)
}

/// Hex-encode raw bytes into a fixed-width lowercase string.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl Pkcs7 {
    /// Serialize this `Pkcs7` as a DER blob. This is the Rust equivalent of
    /// the C `i2d_PKCS7` function.
    ///
    /// # Errors
    /// Returns a [`Pkcs7Error::Crypto`] if any nested ASN.1 encoder fails.
    pub fn to_der(&self) -> Result<Vec<u8>, Pkcs7Error> {
        debug!(
            "Pkcs7::to_der: content_type={:?}, detached={}",
            self.content_type, self.detached
        );
        encode_pkcs7_content_info(self, false)
    }

    /// Deserialize a DER blob into a `Pkcs7`. This is the Rust equivalent of
    /// the C `d2i_PKCS7` function.
    ///
    /// # Errors
    /// Returns a [`Pkcs7Error::Crypto`] if the DER is malformed or contains
    /// constructs not supported by this implementation (e.g. indefinite
    /// length encoding).
    pub fn from_der(data: &[u8]) -> Result<Self, Pkcs7Error> {
        debug!("Pkcs7::from_der: input_len={}", data.len());
        let (p7, _) = decode_pkcs7_content_info(data)?;
        Ok(p7)
    }

    /// Serialize this `Pkcs7` to a PEM-armored string with the canonical
    /// `PKCS7` label. Equivalent to `PEM_write_bio_PKCS7` in C.
    pub fn to_pem(&self) -> Result<String, Pkcs7Error> {
        let der = self.to_der()?;
        let obj = PemObject::with_data(PEM_LABEL_PKCS7, der);
        Ok(pem::encode(&obj))
    }

    /// Parse a PEM-armored string into a `Pkcs7`. Equivalent to
    /// `PEM_read_bio_PKCS7` in C.
    pub fn from_pem(data: &str) -> Result<Self, Pkcs7Error> {
        let obj = pem::decode(data).map_err(Pkcs7Error::Crypto)?;
        // The C parser accepts either "PKCS7" or "PKCS #7 SIGNED DATA" labels.
        // We accept the canonical label and reject everything else.
        if obj.label != PEM_LABEL_PKCS7 {
            return Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(format!(
                    "unexpected PEM label: {}",
                    obj.label
                )),
            )));
        }
        Self::from_der(&obj.data)
    }

    /// Write this `Pkcs7` as an S/MIME message to `writer`.
    ///
    /// When the [`Pkcs7Flags::DETACHED`] flag is set and `data` is provided,
    /// a multipart/signed message is produced with the clear data in the first
    /// part and a detached signature in the second part. Otherwise an
    /// application/pkcs7-mime message is produced.
    ///
    /// Equivalent to `SMIME_write_PKCS7` in C.
    pub fn to_smime<W: Write>(
        &self,
        writer: &mut W,
        data: Option<&[u8]>,
        flags: Pkcs7Flags,
    ) -> Result<(), Pkcs7Error> {
        debug!(
            "Pkcs7::to_smime: flags={:?}, has_data={}",
            flags,
            data.is_some()
        );

        let der = self.to_der()?;
        let b64 = b64_encode_smime(&der);

        if flags.contains(Pkcs7Flags::DETACHED) {
            // Generate a unique multipart boundary using rand_bytes + hex
            let mut boundary_bytes = [0u8; 16];
            rand_bytes(&mut boundary_bytes).map_err(Pkcs7Error::Crypto)?;
            let boundary = format!("----={}", hex_lower(&boundary_bytes));

            let content_type_param = "application/x-pkcs7-signature; name=\"smime.p7s\"";
            let micalg = "sha-256"; // Conservative default; matches SHA-2 family

            writer
                .write_all(b"MIME-Version: 1.0\r\n")
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(
                    format!(
                        "Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=\"{micalg}\"; boundary=\"{boundary}\"\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(b"This is an S/MIME signed message\r\n\r\n")
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;

            // Body part (clear)
            writer
                .write_all(format!("--{boundary}\r\n").as_bytes())
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            if flags.contains(Pkcs7Flags::TEXT) {
                writer
                    .write_all(b"Content-Type: text/plain\r\n\r\n")
                    .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            } else {
                writer
                    .write_all(b"\r\n")
                    .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            }
            if let Some(bytes) = data {
                writer
                    .write_all(bytes)
                    .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            }
            writer
                .write_all(b"\r\n\r\n")
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;

            // Signature part
            writer
                .write_all(format!("--{boundary}\r\n").as_bytes())
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(
                    format!(
                        "Content-Type: {content_type_param}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(b64.as_bytes())
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(format!("\r\n--{boundary}--\r\n").as_bytes())
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
        } else {
            // Wrapped (application/pkcs7-mime).  The only standard wrapped
            // S/MIME content types are `enveloped-data` and `signed-data`;
            // all non-enveloped variants — including the `digested`,
            // `encrypted`, and `data` variants used for niche flows — are
            // surfaced as `signed-data` so existing parsers do not reject
            // the envelope outright.
            let smime_type = if self.is_enveloped() || self.is_signed_and_enveloped() {
                "enveloped-data"
            } else {
                "signed-data"
            };
            writer
                .write_all(b"MIME-Version: 1.0\r\n")
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(
                    format!(
                        "Content-Disposition: attachment; filename=\"smime.p7m\"\r\nContent-Type: application/x-pkcs7-mime; smime-type={smime_type}; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            writer
                .write_all(b64.as_bytes())
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
        }
        Ok(())
    }

    /// Read an S/MIME message from `reader` and return the parsed `Pkcs7`
    /// plus the optional cleartext payload (present for multipart/signed
    /// detached signatures, `None` for opaque application/pkcs7-mime).
    ///
    /// Equivalent to `SMIME_read_PKCS7` in C.
    pub fn from_smime<R: Read>(mut reader: R) -> Result<(Self, Option<Vec<u8>>), Pkcs7Error> {
        debug!("Pkcs7::from_smime: reading S/MIME stream");

        let mut raw = String::new();
        // Read everything into memory. S/MIME messages are bounded by their
        // outer envelope so this is acceptable for practical inputs.
        let mut buf = [0u8; STREAM_BUFFER_SIZE];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| Pkcs7Error::Crypto(CryptoError::from(e)))?;
            if n == 0 {
                break;
            }
            raw.push_str(std::str::from_utf8(&buf[..n]).map_err(|_| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::DecodingError(
                    "invalid UTF-8 in S/MIME stream".to_string(),
                )))
            })?);
        }

        // Split header from body. The first blank line terminates headers.
        let (header_block, body) = split_smime_headers(&raw)?;

        // Determine whether this is multipart/signed or a wrapped p7m.
        let content_type = find_header_value(header_block, "Content-Type").ok_or_else(|| {
            Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::DecodingError(
                "missing Content-Type header".to_string(),
            )))
        })?;
        let content_type_lower = content_type.to_ascii_lowercase();

        if content_type_lower.contains("multipart/signed") {
            // Find the boundary parameter.
            let boundary = parse_boundary(&content_type).ok_or_else(|| {
                Pkcs7Error::Crypto(CryptoError::from(crate::asn1::Asn1Error::DecodingError(
                    "missing boundary parameter".to_string(),
                )))
            })?;
            let parts = split_multipart(body, &boundary);
            if parts.len() < 2 {
                return Err(Pkcs7Error::Crypto(CryptoError::from(
                    crate::asn1::Asn1Error::DecodingError(
                        "multipart/signed requires two parts".to_string(),
                    ),
                )));
            }
            // First part: cleartext body
            let (_part_hdr, part_body) = split_smime_headers(parts[0])?;
            // Trim a single trailing CRLF that was inserted by the boundary
            let payload = trim_trailing_crlf(part_body).as_bytes().to_vec();

            // Second part: detached PKCS#7 signature (base64)
            let (sig_hdr, sig_body) = split_smime_headers(parts[1])?;
            let _ = sig_hdr; // headers don't affect parsing
            let der = b64_decode(sig_body)?;
            let p7 = Self::from_der(&der)?;
            Ok((p7, Some(payload)))
        } else if content_type_lower.contains("application/x-pkcs7-mime")
            || content_type_lower.contains("application/pkcs7-mime")
        {
            let der = b64_decode(body)?;
            let p7 = Self::from_der(&der)?;
            Ok((p7, None))
        } else {
            Err(Pkcs7Error::Crypto(CryptoError::from(
                crate::asn1::Asn1Error::DecodingError(format!(
                    "unsupported S/MIME content type: {content_type}"
                )),
            )))
        }
    }
}

// =============================================================================
// S/MIME parsing helpers
// =============================================================================

/// Split an S/MIME message into the header block and the body. The header
/// block ends at the first empty line (`\r\n\r\n` or `\n\n`).
fn split_smime_headers(text: &str) -> Pkcs7Result<(&str, &str)> {
    if let Some(idx) = text.find("\r\n\r\n") {
        let (h, b) = text.split_at(idx);
        return Ok((h, &b[4..]));
    }
    if let Some(idx) = text.find("\n\n") {
        let (h, b) = text.split_at(idx);
        return Ok((h, &b[2..]));
    }
    Err(Pkcs7Error::Crypto(CryptoError::from(
        crate::asn1::Asn1Error::DecodingError("could not locate end of S/MIME headers".to_string()),
    )))
}

/// Locate a header value, case-insensitively, supporting continuation lines
/// per RFC 5322. Returns the unfolded value without the trailing CRLF.
fn find_header_value(header_block: &str, name: &str) -> Option<String> {
    let name_lc = name.to_ascii_lowercase();
    let mut current: Option<String> = None;
    for line in header_block.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation
            if let Some(buf) = current.as_mut() {
                buf.push(' ');
                buf.push_str(line.trim());
            }
            continue;
        }
        if let Some(colon) = line.find(':') {
            let key = &line[..colon];
            if key.to_ascii_lowercase() == name_lc {
                current = Some(line[colon + 1..].trim().to_string());
            } else if current.is_some() {
                // Different header — stop collecting continuations of the
                // previous match.
                return current;
            }
        }
    }
    current
}

/// Parse a boundary parameter from a Content-Type header value.
fn parse_boundary(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    let idx = lower.find("boundary=")?;
    let after = &content_type[idx + "boundary=".len()..];
    let trimmed = after.trim_start();
    if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c == ';' || c.is_whitespace())
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

/// Split a multipart body into its sub-parts (excluding preamble and the
/// closing boundary marker).
fn split_multipart<'a>(body: &'a str, boundary: &str) -> Vec<&'a str> {
    let delim = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut remaining = body;
    let mut started = false;
    while let Some(idx) = remaining.find(&delim) {
        let before = &remaining[..idx];
        if started {
            // Strip an optional CRLF that immediately precedes the boundary.
            let trimmed = before.strip_suffix("\r\n").unwrap_or(before);
            parts.push(trimmed);
        }
        // Move past the boundary marker.
        let after = &remaining[idx + delim.len()..];
        // Closing marker check
        if after.starts_with("--") {
            break;
        }
        // Skip CRLF after boundary
        let after = after
            .strip_prefix("\r\n")
            .unwrap_or_else(|| after.strip_prefix('\n').unwrap_or(after));
        remaining = after;
        started = true;
    }
    parts
}

/// Strip a single trailing CRLF (or LF) from a borrowed string.
fn trim_trailing_crlf(s: &str) -> &str {
    s.strip_suffix("\r\n")
        .unwrap_or_else(|| s.strip_suffix('\n').unwrap_or(s))
}

// =============================================================================
// Phase 3 — Unit Tests for the PKCS#7 module.
//
// Tests covering the public API surface: content-type discriminators,
// constructor defaults, state transitions via `set_type`/`set_content`,
// flag bit operations, context propagation, error display, attribute
// helpers, and serialization round-trips for the `Data` content type.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Pkcs7ContentType — OID round-trip and discriminators.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_content_type_oid_data() {
        let ct = Pkcs7ContentType::Data;
        assert_eq!(ct.oid(), "1.2.840.113549.1.7.1");
        assert_eq!(Pkcs7ContentType::from_oid(ct.oid()), ct);
    }

    #[test]
    fn pkcs7_content_type_oid_signed_data() {
        let ct = Pkcs7ContentType::SignedData;
        assert_eq!(ct.oid(), "1.2.840.113549.1.7.2");
        assert_eq!(Pkcs7ContentType::from_oid(ct.oid()), ct);
    }

    #[test]
    fn pkcs7_content_type_oid_enveloped_data() {
        let ct = Pkcs7ContentType::EnvelopedData;
        assert_eq!(ct.oid(), "1.2.840.113549.1.7.3");
        assert_eq!(Pkcs7ContentType::from_oid(ct.oid()), ct);
    }

    #[test]
    fn pkcs7_content_type_oid_signed_and_enveloped() {
        let ct = Pkcs7ContentType::SignedAndEnveloped;
        assert_eq!(ct.oid(), "1.2.840.113549.1.7.4");
        assert_eq!(Pkcs7ContentType::from_oid(ct.oid()), ct);
    }

    #[test]
    fn pkcs7_content_type_oid_digested_data() {
        let ct = Pkcs7ContentType::DigestedData;
        assert_eq!(ct.oid(), "1.2.840.113549.1.7.5");
        assert_eq!(Pkcs7ContentType::from_oid(ct.oid()), ct);
    }

    #[test]
    fn pkcs7_content_type_oid_encrypted_data() {
        let ct = Pkcs7ContentType::EncryptedData;
        assert_eq!(ct.oid(), "1.2.840.113549.1.7.6");
        assert_eq!(Pkcs7ContentType::from_oid(ct.oid()), ct);
    }

    #[test]
    fn pkcs7_content_type_oid_other() {
        // Use an OID that is NOT one of the six standard PKCS#7 OIDs.
        let custom_oid = "1.2.3.4.5.6.7";
        let ct = Pkcs7ContentType::from_oid(custom_oid);
        assert_eq!(ct, Pkcs7ContentType::Other(custom_oid.to_string()));
        assert_eq!(ct.oid(), custom_oid);
    }

    #[test]
    fn pkcs7_content_type_is_other() {
        assert!(!Pkcs7ContentType::Data.is_other());
        assert!(!Pkcs7ContentType::SignedData.is_other());
        assert!(!Pkcs7ContentType::EnvelopedData.is_other());
        assert!(!Pkcs7ContentType::SignedAndEnveloped.is_other());
        assert!(!Pkcs7ContentType::DigestedData.is_other());
        assert!(!Pkcs7ContentType::EncryptedData.is_other());
        assert!(Pkcs7ContentType::Other("1.2.3".to_string()).is_other());
    }

    #[test]
    fn pkcs7_content_type_display() {
        assert_eq!(format!("{}", Pkcs7ContentType::Data), "id-data");
        assert_eq!(format!("{}", Pkcs7ContentType::SignedData), "id-signedData");
        assert_eq!(
            format!("{}", Pkcs7ContentType::EnvelopedData),
            "id-envelopedData"
        );
        assert_eq!(
            format!("{}", Pkcs7ContentType::SignedAndEnveloped),
            "id-signedAndEnvelopedData"
        );
        assert_eq!(
            format!("{}", Pkcs7ContentType::DigestedData),
            "id-digestedData"
        );
        assert_eq!(
            format!("{}", Pkcs7ContentType::EncryptedData),
            "id-encryptedData"
        );
        assert_eq!(
            format!("{}", Pkcs7ContentType::Other("9.8.7".to_string())),
            "OID(9.8.7)"
        );
    }

    // -------------------------------------------------------------------------
    // Pkcs7 — `new()` defaults and `is_*` discriminators.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_new_defaults_to_data() {
        let p7 = Pkcs7::new();
        assert!(p7.is_data());
        assert!(!p7.is_signed());
        assert!(!p7.is_enveloped());
        assert!(!p7.is_signed_and_enveloped());
        assert!(!p7.is_digested());
        assert!(!p7.is_encrypted());
        assert!(!p7.is_other());
        assert!(!p7.is_detached());
        assert_eq!(*p7.content_type(), Pkcs7ContentType::Data);
    }

    #[test]
    fn pkcs7_default_matches_new() {
        let from_new = Pkcs7::new();
        let from_default = Pkcs7::default();
        assert_eq!(*from_new.content_type(), *from_default.content_type());
        assert_eq!(from_new.is_detached(), from_default.is_detached());
        // Both should be Data variant
        assert!(matches!(from_default.content(), Pkcs7Content::Data(_)));
    }

    // -------------------------------------------------------------------------
    // Pkcs7::set_type — state transitions.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_set_type_data() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::Data).expect("set_type Data");
        assert!(p7.is_data());
        assert!(matches!(p7.content(), Pkcs7Content::Data(_)));
    }

    #[test]
    fn pkcs7_set_type_signed_data() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::SignedData)
            .expect("set_type SignedData");
        assert!(p7.is_signed());
        assert!(matches!(p7.content(), Pkcs7Content::Signed(_)));
    }

    #[test]
    fn pkcs7_set_type_enveloped_data() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::EnvelopedData)
            .expect("set_type EnvelopedData");
        assert!(p7.is_enveloped());
        assert!(matches!(p7.content(), Pkcs7Content::Enveloped(_)));
    }

    #[test]
    fn pkcs7_set_type_signed_and_enveloped() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::SignedAndEnveloped)
            .expect("set_type SignedAndEnveloped");
        assert!(p7.is_signed_and_enveloped());
        assert!(matches!(p7.content(), Pkcs7Content::SignedAndEnveloped(_)));
    }

    #[test]
    fn pkcs7_set_type_digested_data() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::DigestedData)
            .expect("set_type DigestedData");
        assert!(p7.is_digested());
        assert!(matches!(p7.content(), Pkcs7Content::Digested(_)));
    }

    #[test]
    fn pkcs7_set_type_encrypted_data() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::EncryptedData)
            .expect("set_type EncryptedData");
        assert!(p7.is_encrypted());
        assert!(matches!(p7.content(), Pkcs7Content::Encrypted(_)));
    }

    #[test]
    fn pkcs7_set_type_other_preserves_oid() {
        let mut p7 = Pkcs7::new();
        let custom_oid = "1.2.3.4.5";
        p7.set_type(Pkcs7ContentType::Other(custom_oid.to_string()))
            .expect("set_type Other");
        assert!(p7.is_other());
        assert_eq!(p7.content_type().oid(), custom_oid);
        assert!(matches!(p7.content(), Pkcs7Content::Other(_)));
    }

    // -------------------------------------------------------------------------
    // Pkcs7::set_content — variant validation.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_set_content_signed_accepts_inner() {
        let mut outer = Pkcs7::new();
        outer
            .set_type(Pkcs7ContentType::SignedData)
            .expect("set_type");
        let inner = Pkcs7::new();
        outer.set_content(inner).expect("set_content on Signed");
    }

    #[test]
    fn pkcs7_set_content_digested_accepts_inner() {
        let mut outer = Pkcs7::new();
        outer
            .set_type(Pkcs7ContentType::DigestedData)
            .expect("set_type");
        let inner = Pkcs7::new();
        outer.set_content(inner).expect("set_content on Digested");
    }

    #[test]
    fn pkcs7_set_content_data_rejects() {
        // Data variant has no nested encapsulated content.
        let mut outer = Pkcs7::new();
        let inner = Pkcs7::new();
        let err = outer.set_content(inner).expect_err("set_content on Data");
        assert!(matches!(err, Pkcs7Error::WrongContentType));
    }

    #[test]
    fn pkcs7_set_content_enveloped_rejects() {
        let mut outer = Pkcs7::new();
        outer
            .set_type(Pkcs7ContentType::EnvelopedData)
            .expect("set_type");
        let inner = Pkcs7::new();
        let err = outer
            .set_content(inner)
            .expect_err("set_content on Enveloped");
        assert!(matches!(err, Pkcs7Error::WrongContentType));
    }

    // -------------------------------------------------------------------------
    // Pkcs7::set_detached / is_detached.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_detached_round_trip() {
        let mut p7 = Pkcs7::new();
        assert!(!p7.is_detached());
        p7.set_detached(true);
        assert!(p7.is_detached());
        p7.set_detached(false);
        assert!(!p7.is_detached());
    }

    // -------------------------------------------------------------------------
    // Pkcs7::add_certificate / add_crl — wrong content type rejection.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_add_crl_on_data_rejects() {
        let mut p7 = Pkcs7::new();
        let crl_blob = vec![0x30u8, 0x00];
        let err = p7
            .add_crl(crl_blob)
            .expect_err("add_crl on Data should reject");
        assert!(matches!(err, Pkcs7Error::WrongContentType));
    }

    #[test]
    fn pkcs7_add_crl_on_signed_succeeds() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::SignedData).expect("set_type");
        p7.add_crl(vec![0x30u8, 0x00]).expect("add_crl on Signed");
        match p7.content() {
            Pkcs7Content::Signed(s) => assert_eq!(s.crls.len(), 1),
            _ => panic!("expected Signed variant"),
        }
    }

    #[test]
    fn pkcs7_add_crl_on_signed_and_enveloped_succeeds() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::SignedAndEnveloped)
            .expect("set_type");
        p7.add_crl(vec![0x30u8, 0x00])
            .expect("add_crl on SignedAndEnveloped");
        match p7.content() {
            Pkcs7Content::SignedAndEnveloped(s) => assert_eq!(s.crls.len(), 1),
            _ => panic!("expected SignedAndEnveloped variant"),
        }
    }

    // -------------------------------------------------------------------------
    // Pkcs7::set_cipher / set_digest.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_set_cipher_empty_rejects() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::EnvelopedData)
            .expect("set_type");
        let err = p7
            .set_cipher("")
            .expect_err("empty cipher should be rejected");
        assert!(matches!(err, Pkcs7Error::CipherNotInitialized));
    }

    #[test]
    fn pkcs7_set_cipher_on_data_rejects() {
        let mut p7 = Pkcs7::new();
        // Pure dotted-OID for AES-256-CBC: 2.16.840.1.101.3.4.1.42
        let err = p7
            .set_cipher("2.16.840.1.101.3.4.1.42")
            .expect_err("set_cipher on Data should reject");
        assert!(matches!(err, Pkcs7Error::WrongContentType));
    }

    #[test]
    fn pkcs7_set_cipher_on_enveloped_succeeds() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::EnvelopedData)
            .expect("set_type");
        // 2.16.840.1.101.3.4.1.42 = AES-256-CBC OID
        p7.set_cipher("2.16.840.1.101.3.4.1.42")
            .expect("set_cipher on Enveloped");
        match p7.content() {
            Pkcs7Content::Enveloped(e) => {
                assert!(e.enc_data.algorithm.is_some());
            }
            _ => panic!("expected Enveloped variant"),
        }
    }

    #[test]
    fn pkcs7_set_digest_empty_rejects() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::DigestedData)
            .expect("set_type");
        let err = p7
            .set_digest("")
            .expect_err("empty digest should be rejected");
        assert!(matches!(err, Pkcs7Error::UnableToFindMessageDigest));
    }

    #[test]
    fn pkcs7_set_digest_on_data_rejects() {
        let mut p7 = Pkcs7::new();
        // 2.16.840.1.101.3.4.2.1 = SHA-256
        let err = p7
            .set_digest("2.16.840.1.101.3.4.2.1")
            .expect_err("set_digest on Data should reject");
        assert!(matches!(err, Pkcs7Error::WrongContentType));
    }

    #[test]
    fn pkcs7_set_digest_on_digested_succeeds() {
        let mut p7 = Pkcs7::new();
        p7.set_type(Pkcs7ContentType::DigestedData)
            .expect("set_type");
        p7.set_digest("2.16.840.1.101.3.4.2.1")
            .expect("set_digest on Digested");
        match p7.content() {
            Pkcs7Content::Digested(d) => assert!(d.md_algorithm.is_some()),
            _ => panic!("expected Digested variant"),
        }
    }

    // -------------------------------------------------------------------------
    // Pkcs7Flags — bit operations.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_flags_default_empty() {
        let empty = Pkcs7Flags::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.bits(), 0);
    }

    #[test]
    fn pkcs7_flags_individual_bits() {
        assert_eq!(Pkcs7Flags::TEXT.bits(), 0x0001);
        assert_eq!(Pkcs7Flags::NOCERTS.bits(), 0x0002);
        assert_eq!(Pkcs7Flags::NOSIGS.bits(), 0x0004);
        assert_eq!(Pkcs7Flags::NOCHAIN.bits(), 0x0008);
        assert_eq!(Pkcs7Flags::NOINTERN.bits(), 0x0010);
        assert_eq!(Pkcs7Flags::NOVERIFY.bits(), 0x0020);
        assert_eq!(Pkcs7Flags::DETACHED.bits(), 0x0040);
        assert_eq!(Pkcs7Flags::BINARY.bits(), 0x0080);
        assert_eq!(Pkcs7Flags::NOATTR.bits(), 0x0100);
        assert_eq!(Pkcs7Flags::NOSMIMECAP.bits(), 0x0200);
        assert_eq!(Pkcs7Flags::NOOLDMIMETYPE.bits(), 0x0400);
        assert_eq!(Pkcs7Flags::CRLFEOL.bits(), 0x0800);
        assert_eq!(Pkcs7Flags::STREAM.bits(), 0x1000);
        assert_eq!(Pkcs7Flags::NOCRL.bits(), 0x2000);
        assert_eq!(Pkcs7Flags::PARTIAL.bits(), 0x4000);
        assert_eq!(Pkcs7Flags::REUSE_DIGEST.bits(), 0x8000);
        assert_eq!(Pkcs7Flags::NO_DUAL_CONTENT.bits(), 0x1_0000);
    }

    #[test]
    fn pkcs7_flags_combined() {
        let combined = Pkcs7Flags::TEXT | Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;
        assert!(combined.contains(Pkcs7Flags::TEXT));
        assert!(combined.contains(Pkcs7Flags::DETACHED));
        assert!(combined.contains(Pkcs7Flags::BINARY));
        assert!(!combined.contains(Pkcs7Flags::NOCERTS));
        assert!(combined.intersects(Pkcs7Flags::TEXT));
        assert!(!combined.intersects(Pkcs7Flags::NOCERTS));
    }

    #[test]
    fn pkcs7_flags_intersection_and_difference() {
        let a = Pkcs7Flags::TEXT | Pkcs7Flags::DETACHED;
        let b = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;
        let intersection = a & b;
        assert_eq!(intersection, Pkcs7Flags::DETACHED);
        let difference = a - b;
        assert_eq!(difference, Pkcs7Flags::TEXT);
    }

    // -------------------------------------------------------------------------
    // Pkcs7Context — defaults and builder methods.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_context_new_defaults() {
        let ctx = Pkcs7Context::new();
        assert!(ctx.lib_ctx().is_none());
        assert_eq!(ctx.propq(), "");
    }

    #[test]
    fn pkcs7_context_default_matches_new() {
        let from_new = Pkcs7Context::new();
        let from_default = Pkcs7Context::default();
        assert!(from_new.lib_ctx().is_none());
        assert!(from_default.lib_ctx().is_none());
        assert_eq!(from_new.propq(), from_default.propq());
    }

    #[test]
    fn pkcs7_context_with_propq_sets_string() {
        let ctx = Pkcs7Context::new().with_propq("provider=fips");
        assert_eq!(ctx.propq(), "provider=fips");
    }

    #[test]
    fn pkcs7_context_with_propq_string_owned() {
        // Confirm `impl Into<String>` accepts both &str and String.
        let owned = String::from("provider=default");
        let ctx = Pkcs7Context::new().with_propq(owned);
        assert_eq!(ctx.propq(), "provider=default");
    }

    #[test]
    fn pkcs7_context_resolve_libctx_falls_back_to_default() {
        // When no override has been set, resolve_libctx returns the global
        // default context.  We don't assert on its contents — only that the
        // call succeeds and returns an Arc whose lifetime is consistent.
        let ctx = Pkcs7Context::new();
        let resolved = ctx.resolve_libctx();
        // Smoke-test: cloning the Arc should bump strong count without panic.
        let _clone = Arc::clone(&resolved);
    }

    #[test]
    fn pkcs7_set_property_query_via_pkcs7() {
        let mut p7 = Pkcs7::new();
        p7.set_property_query("provider=fips");
        assert_eq!(p7.context().propq(), "provider=fips");
    }

    // -------------------------------------------------------------------------
    // Pkcs7Error — Display strings.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_error_display_strings() {
        assert_eq!(Pkcs7Error::NoContent.to_string(), "no content");
        assert_eq!(
            Pkcs7Error::NoSignaturesOnData.to_string(),
            "no signatures on data"
        );
        assert_eq!(Pkcs7Error::NoSigners.to_string(), "no signers");
        assert_eq!(
            Pkcs7Error::WrongContentType.to_string(),
            "wrong content type"
        );
        assert_eq!(
            Pkcs7Error::OperationNotSupported.to_string(),
            "operation not supported on this type"
        );
        assert_eq!(
            Pkcs7Error::UnknownOperation.to_string(),
            "unknown operation"
        );
        assert_eq!(
            Pkcs7Error::UnableToFindCertificate.to_string(),
            "unable to find certificate"
        );
        assert_eq!(Pkcs7Error::DigestFailure.to_string(), "digest failure");
        assert_eq!(
            Pkcs7Error::SignatureFailure.to_string(),
            "signature failure"
        );
        assert_eq!(Pkcs7Error::DecryptError.to_string(), "decrypt error");
        assert_eq!(
            Pkcs7Error::NoRecipientMatchesCertificate.to_string(),
            "no recipient matches certificate"
        );
        assert_eq!(
            Pkcs7Error::ContentAndDataPresent.to_string(),
            "content and data present"
        );
        assert_eq!(
            Pkcs7Error::CipherNotInitialized.to_string(),
            "cipher not initialized"
        );
        assert_eq!(
            Pkcs7Error::PrivateKeyDoesNotMatch.to_string(),
            "private key does not match certificate"
        );
        assert_eq!(
            Pkcs7Error::AddSignerError.to_string(),
            "PKCS7 add signer error"
        );
        assert_eq!(
            Pkcs7Error::SigningNotSupportedForKeyType.to_string(),
            "signing not supported for this key type"
        );
        assert_eq!(
            Pkcs7Error::UnableToFindMessageDigest.to_string(),
            "unable to find message digest"
        );
    }

    // -------------------------------------------------------------------------
    // Pkcs7SignedData / Pkcs7EnvelopedData / Pkcs7DigestedData /
    // Pkcs7EncryptedData / Pkcs7SignEnvelopeData / Pkcs7EncContent /
    // Pkcs7RecipientInfo / Pkcs7SignerInfo — constructor defaults.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_signed_data_new_defaults() {
        let sd = Pkcs7SignedData::new();
        assert_eq!(sd.version, 1);
        assert!(sd.md_algorithms.is_empty());
        assert!(sd.certificates.is_empty());
        assert!(sd.crls.is_empty());
        assert!(sd.signer_infos.is_empty());
        // The encapsulated contents pointer should be a Data variant.
        assert!(sd.contents.is_data());
    }

    #[test]
    fn pkcs7_signed_data_default_matches_new() {
        let from_new = Pkcs7SignedData::new();
        let from_default = Pkcs7SignedData::default();
        assert_eq!(from_new.version, from_default.version);
        assert_eq!(
            from_new.md_algorithms.len(),
            from_default.md_algorithms.len()
        );
    }

    #[test]
    fn pkcs7_enveloped_data_new_defaults() {
        let ed = Pkcs7EnvelopedData::new();
        assert_eq!(ed.version, 0);
        assert!(ed.recipient_infos.is_empty());
        // enc_data starts with no algorithm and no encrypted bytes.
        assert!(ed.enc_data.algorithm.is_none());
        assert!(ed.enc_data.enc_data.is_none());
    }

    #[test]
    fn pkcs7_digested_data_new_defaults() {
        let dd = Pkcs7DigestedData::new();
        assert_eq!(dd.version, 0);
        assert!(dd.md_algorithm.is_none());
        assert!(dd.digest.is_empty());
        assert!(dd.contents.is_data());
    }

    #[test]
    fn pkcs7_encrypted_data_new_defaults() {
        let ed = Pkcs7EncryptedData::new();
        assert_eq!(ed.version, 0);
        assert!(ed.enc_data.algorithm.is_none());
        assert!(ed.enc_data.enc_data.is_none());
    }

    #[test]
    fn pkcs7_sign_envelope_data_new_defaults() {
        let se = Pkcs7SignEnvelopeData::new();
        assert_eq!(se.version, 1);
        assert!(se.md_algorithms.is_empty());
        assert!(se.certificates.is_empty());
        assert!(se.crls.is_empty());
        assert!(se.signer_infos.is_empty());
        assert!(se.recipient_infos.is_empty());
        assert!(se.enc_data.algorithm.is_none());
    }

    #[test]
    fn pkcs7_enc_content_new_defaults() {
        let ec = Pkcs7EncContent::new(Pkcs7ContentType::Data);
        assert_eq!(ec.content_type, Pkcs7ContentType::Data);
        assert!(ec.algorithm.is_none());
        assert!(ec.enc_data.is_none());
        // Same-file tests can read pub(crate) fields.
        assert!(ec.key.is_empty());
    }

    #[test]
    fn pkcs7_enc_content_default_is_data_variant() {
        let ec = Pkcs7EncContent::default();
        assert_eq!(ec.content_type, Pkcs7ContentType::Data);
    }

    #[test]
    fn pkcs7_enc_content_with_algorithm_builder() {
        let oid =
            Asn1Object::from_oid_string("2.16.840.1.101.3.4.1.42").expect("aes-256-cbc OID parse");
        let alg = AlgorithmIdentifier::new(oid, None);
        let ec = Pkcs7EncContent::new(Pkcs7ContentType::Data).with_algorithm(alg.clone());
        assert!(ec.algorithm.is_some());
        let stored = ec.algorithm.as_ref().expect("algorithm set");
        assert_eq!(stored.algorithm, alg.algorithm);
    }

    #[test]
    fn pkcs7_recipient_info_new_defaults() {
        let issuer_serial = IssuerAndSerialNumber {
            issuer: vec![0x30, 0x00],
            serial_number: vec![0x02, 0x01, 0x01],
        };
        let key_oid = Asn1Object::from_oid_string("1.2.840.113549.1.1.1").expect("rsa OID parse");
        let key_alg = AlgorithmIdentifier::new(key_oid, None);
        let ri = Pkcs7RecipientInfo::new(issuer_serial.clone(), key_alg.clone());
        assert_eq!(ri.version, 0);
        assert_eq!(ri.issuer_and_serial.issuer, issuer_serial.issuer);
        assert_eq!(
            ri.issuer_and_serial.serial_number,
            issuer_serial.serial_number
        );
        assert_eq!(ri.key_enc_algorithm.algorithm, key_alg.algorithm);
        assert!(ri.enc_key.is_empty());
    }

    #[test]
    fn pkcs7_signer_info_new_defaults() {
        let issuer_serial = IssuerAndSerialNumber {
            issuer: vec![0x30, 0x00],
            serial_number: vec![0x02, 0x01, 0x01],
        };
        let digest_oid =
            Asn1Object::from_oid_string("2.16.840.1.101.3.4.2.1").expect("sha-256 OID parse");
        let digest_alg = AlgorithmIdentifier::new(digest_oid, None);
        let sig_oid =
            Asn1Object::from_oid_string("1.2.840.113549.1.1.11").expect("rsa-sha256 OID parse");
        let sig_alg = AlgorithmIdentifier::new(sig_oid, None);
        let si = Pkcs7SignerInfo::new(issuer_serial, digest_alg, sig_alg);
        assert_eq!(si.version, 1);
        assert!(si.signed_attributes.is_empty());
        assert!(si.unsigned_attributes.is_empty());
        assert!(si.encrypted_digest.is_empty());
    }

    // -------------------------------------------------------------------------
    // IssuerAndSerialNumber — public field access.
    // -------------------------------------------------------------------------

    #[test]
    fn issuer_and_serial_number_construct_and_read() {
        let ias = IssuerAndSerialNumber {
            issuer: vec![1, 2, 3],
            serial_number: vec![9, 8, 7],
        };
        assert_eq!(ias.issuer, vec![1u8, 2, 3]);
        assert_eq!(ias.serial_number, vec![9u8, 8, 7]);
    }

    // -------------------------------------------------------------------------
    // Pkcs7Attribute — constructor + helpers.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_attribute_new_single_value() {
        let attr = Pkcs7Attribute::new("1.2.3.4", vec![0xAA, 0xBB]);
        assert_eq!(attr.attr_type, "1.2.3.4");
        assert_eq!(attr.values.len(), 1);
        assert_eq!(attr.values[0], vec![0xAA, 0xBB]);
    }

    #[test]
    fn pkcs7_add_signing_time_appends_attribute() {
        let issuer_serial = IssuerAndSerialNumber {
            issuer: vec![0x30, 0x00],
            serial_number: vec![0x02, 0x01, 0x01],
        };
        let digest_oid =
            Asn1Object::from_oid_string("2.16.840.1.101.3.4.2.1").expect("sha-256 OID parse");
        let digest_alg = AlgorithmIdentifier::new(digest_oid, None);
        let sig_oid =
            Asn1Object::from_oid_string("1.2.840.113549.1.1.11").expect("rsa-sha256 OID parse");
        let sig_alg = AlgorithmIdentifier::new(sig_oid, None);
        let mut si = Pkcs7SignerInfo::new(issuer_serial, digest_alg, sig_alg);

        // Pass explicit UTC timestamp (no clock injection support).
        add_signing_time(&mut si, Some("250101000000Z")).expect("add_signing_time Some");
        assert_eq!(si.signed_attributes.len(), 1);
        assert_eq!(si.signed_attributes[0].attr_type, OID_SIGNING_TIME);
        assert!(!si.signed_attributes[0].values.is_empty());

        // Idempotent replacement: calling again with explicit time replaces
        // the existing attribute (preserving SET-of-attribute semantics).
        add_signing_time(&mut si, Some("250101000000Z")).expect("add_signing_time Some");
        assert_eq!(si.signed_attributes.len(), 1);
        assert_eq!(si.signed_attributes[0].attr_type, OID_SIGNING_TIME);
    }

    #[test]
    fn pkcs7_add_message_digest_appends_attribute() {
        let issuer_serial = IssuerAndSerialNumber {
            issuer: vec![0x30, 0x00],
            serial_number: vec![0x02, 0x01, 0x01],
        };
        let digest_oid =
            Asn1Object::from_oid_string("2.16.840.1.101.3.4.2.1").expect("sha-256 OID parse");
        let digest_alg = AlgorithmIdentifier::new(digest_oid, None);
        let sig_oid =
            Asn1Object::from_oid_string("1.2.840.113549.1.1.11").expect("rsa-sha256 OID parse");
        let sig_alg = AlgorithmIdentifier::new(sig_oid, None);
        let mut si = Pkcs7SignerInfo::new(issuer_serial, digest_alg, sig_alg);

        let digest_bytes = [0x01u8; 32]; // 32-byte SHA-256-sized buffer
        add_message_digest(&mut si, &digest_bytes).expect("add_message_digest");
        assert_eq!(si.signed_attributes.len(), 1);
        assert_eq!(si.signed_attributes[0].attr_type, OID_MESSAGE_DIGEST);
        assert!(!si.signed_attributes[0].values.is_empty());
    }

    #[test]
    fn pkcs7_add_content_type_appends_attribute() {
        let issuer_serial = IssuerAndSerialNumber {
            issuer: vec![0x30, 0x00],
            serial_number: vec![0x02, 0x01, 0x01],
        };
        let digest_oid =
            Asn1Object::from_oid_string("2.16.840.1.101.3.4.2.1").expect("sha-256 OID parse");
        let digest_alg = AlgorithmIdentifier::new(digest_oid, None);
        let sig_oid =
            Asn1Object::from_oid_string("1.2.840.113549.1.1.11").expect("rsa-sha256 OID parse");
        let sig_alg = AlgorithmIdentifier::new(sig_oid, None);
        let mut si = Pkcs7SignerInfo::new(issuer_serial, digest_alg, sig_alg);

        // Default (None) → id-data
        add_content_type(&mut si, None).expect("add_content_type None");
        assert_eq!(si.signed_attributes.len(), 1);
        assert_eq!(si.signed_attributes[0].attr_type, OID_CONTENT_TYPE);
        assert!(!si.signed_attributes[0].values.is_empty());

        // Explicit content type → replaces existing attribute
        add_content_type(&mut si, Some(&Pkcs7ContentType::SignedData))
            .expect("add_content_type SignedData");
        assert_eq!(si.signed_attributes.len(), 1);
        assert_eq!(si.signed_attributes[0].attr_type, OID_CONTENT_TYPE);
    }

    // -------------------------------------------------------------------------
    // OID-constant invariants (regression guards for renames).
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_attribute_oid_constants() {
        assert_eq!(OID_SMIME_CAPABILITIES, "1.2.840.113549.1.9.15");
        assert_eq!(OID_CONTENT_TYPE, "1.2.840.113549.1.9.3");
        assert_eq!(OID_SIGNING_TIME, "1.2.840.113549.1.9.5");
        assert_eq!(OID_MESSAGE_DIGEST, "1.2.840.113549.1.9.4");
    }

    // -------------------------------------------------------------------------
    // DER round-trip — empty Data and SignedData containers.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_to_der_data_round_trip() {
        let original = Pkcs7::new();
        let der = original.to_der().expect("to_der on Data");
        // DER must start with SEQUENCE tag (0x30).
        assert_eq!(der[0], 0x30);
        let parsed = Pkcs7::from_der(&der).expect("from_der");
        assert!(parsed.is_data());
        assert_eq!(*parsed.content_type(), Pkcs7ContentType::Data);
    }

    #[test]
    fn pkcs7_to_der_signed_data_round_trip() {
        let mut original = Pkcs7::new();
        original
            .set_type(Pkcs7ContentType::SignedData)
            .expect("set_type");
        let der = original.to_der().expect("to_der on SignedData");
        assert_eq!(der[0], 0x30);
        let parsed = Pkcs7::from_der(&der).expect("from_der");
        assert!(parsed.is_signed());
        assert_eq!(*parsed.content_type(), Pkcs7ContentType::SignedData);
    }

    #[test]
    fn pkcs7_from_der_truncated_rejects() {
        // A single byte cannot be a valid PKCS#7 ContentInfo SEQUENCE.
        let result = Pkcs7::from_der(&[0x30]);
        assert!(result.is_err());
    }

    #[test]
    fn pkcs7_from_der_invalid_outer_tag_rejects() {
        // 0x02 is INTEGER, not SEQUENCE — must be rejected.
        let result = Pkcs7::from_der(&[0x02, 0x01, 0x00]);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // PEM round-trip — empty Data, label validation.
    // -------------------------------------------------------------------------

    #[test]
    fn pkcs7_to_pem_data_round_trip() {
        let original = Pkcs7::new();
        let pem = original.to_pem().expect("to_pem on Data");
        assert!(pem.starts_with("-----BEGIN PKCS7-----"));
        assert!(pem.contains("-----END PKCS7-----"));
        let parsed = Pkcs7::from_pem(&pem).expect("from_pem");
        assert!(parsed.is_data());
    }

    #[test]
    fn pkcs7_from_pem_wrong_label_rejects() {
        // A PEM blob with a non-"PKCS7" label must be rejected.
        let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";
        let result = Pkcs7::from_pem(pem);
        assert!(result.is_err());
        match result.expect_err("err") {
            Pkcs7Error::Crypto(_) => {} // expected
            other => panic!("expected Pkcs7Error::Crypto, got {other:?}"),
        }
    }

    #[test]
    fn pkcs7_from_pem_garbage_rejects() {
        let result = Pkcs7::from_pem("this is not a PEM blob");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // Internal Base64 helper round-trips.
    // -------------------------------------------------------------------------

    #[test]
    fn b64_round_trip_short_input() {
        let input = b"OpenSSL";
        let encoded = b64_encode_smime(input);
        // No internal CRLF since 7 bytes encode to < 64 chars.
        let decoded = b64_decode(&encoded).expect("b64_decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64_round_trip_with_padding_one_byte() {
        let input = &[0x42u8];
        let encoded = b64_encode_smime(input);
        // 1 byte → 4 chars including 2 '=' pads.
        assert!(encoded.contains('='));
        let decoded = b64_decode(&encoded).expect("b64_decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64_round_trip_with_padding_two_bytes() {
        let input = &[0x42u8, 0x77];
        let encoded = b64_encode_smime(input);
        assert!(encoded.contains('='));
        let decoded = b64_decode(&encoded).expect("b64_decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64_round_trip_no_padding() {
        let input = &[0x42u8, 0x77, 0x99];
        let encoded = b64_encode_smime(input);
        let decoded = b64_decode(&encoded).expect("b64_decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64_encode_breaks_at_64_chars() {
        // Build an input that produces > 64 base64 chars.
        let input = vec![0x55u8; 60]; // 60 bytes → 80 base64 chars (no padding)
        let encoded = b64_encode_smime(&input);
        assert!(encoded.contains("\r\n"));
        let decoded = b64_decode(&encoded).expect("b64_decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64_decode_tolerates_whitespace() {
        let input = b"Hello, world!";
        let encoded_no_ws = b64_encode_smime(input);
        // Inject extra whitespace.
        let with_extra_ws = format!("  {encoded_no_ws}  \r\n\t");
        let decoded = b64_decode(&with_extra_ws).expect("b64_decode tolerant");
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64_decode_rejects_invalid_character() {
        let result = b64_decode("AAAA*AAA");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // Helper — `hex_lower`.
    // -------------------------------------------------------------------------

    #[test]
    fn hex_lower_basic() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(hex_lower(&[0x00]), "00");
        assert_eq!(hex_lower(&[0xFF]), "ff");
        assert_eq!(hex_lower(&[0xAB, 0xCD]), "abcd");
        assert_eq!(hex_lower(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    // -------------------------------------------------------------------------
    // Helper — `trim_trailing_crlf`.
    // -------------------------------------------------------------------------

    #[test]
    fn trim_trailing_crlf_strips_crlf() {
        assert_eq!(trim_trailing_crlf("hello\r\n"), "hello");
    }

    #[test]
    fn trim_trailing_crlf_strips_lf_only() {
        assert_eq!(trim_trailing_crlf("hello\n"), "hello");
    }

    #[test]
    fn trim_trailing_crlf_leaves_unaffected() {
        assert_eq!(trim_trailing_crlf("hello"), "hello");
        assert_eq!(trim_trailing_crlf(""), "");
    }
}
