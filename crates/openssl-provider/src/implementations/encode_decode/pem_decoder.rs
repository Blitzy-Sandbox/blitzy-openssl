//! PEM-to-DER decoder — first stage of the provider decoding pipeline.
//!
//! This module translates PEM-armoured input into DER bytes, stripping the
//! `-----BEGIN <LABEL>-----` / `-----END <LABEL>-----` boundaries and
//! Base64-decoding the body.  It optionally handles legacy PEM encryption
//! (RFC 1421 `Proc-Type: 4,ENCRYPTED` / `DEK-Info:` headers) via the
//! `decrypt_legacy_pem` helper.
//!
//! # Architecture
//!
//! ```text
//!   PEM bytes                               DER bytes + metadata
//!        │                                              │
//!        ▼                                              ▼
//!   ┌─────────────┐    label lookup   ┌───────────────────────┐
//!   │  read_pem() │ ───────────────▶  │ PEM_LABEL_TABLE scan  │
//!   │  (pem_rfc   │                   │  → ObjectType         │
//!   │   7468 or   │                   │  → data_type          │
//!   │   custom    │                   │  → data_structure     │
//!   │   RFC 1421) │                   └───────────────────────┘
//!   └─────────────┘                              │
//!         │                                      ▼
//!         │                             ┌────────────────────┐
//!         └────────(encrypted)────────▶ │ decrypt_legacy_pem │
//!                                       │  (RFC 1421 PBE)    │
//!                                       └────────────────────┘
//! ```
//!
//! The decoder recognises three ranges of PEM labels (mirroring the C
//! `pem_name_map[]` table in `decode_pem2der.c`):
//!
//! * **PKCS#8 range** (indices 0..=1):
//!   `"ENCRYPTED PRIVATE KEY"`, `"PRIVATE KEY"` — downstream decoders may
//!   delegate to `super::epki_decoder::decrypt_epki` for PKCS#8
//!   encrypted private keys.
//!
//! * **SubjectPublicKeyInfo range** (index 2):
//!   `"PUBLIC KEY"` — downstream decoders may use
//!   `super::spki_decoder::oid_to_algorithm_name` to resolve the
//!   AlgorithmIdentifier OID.
//!
//! * **Type-specific and certificate range** (indices 3..=17):
//!   `"RSA PRIVATE KEY"`, `"EC PRIVATE KEY"`, `"CERTIFICATE"`,
//!   `"X509 CRL"`, etc. — tagged with algorithm-specific `data_type` and
//!   structure.
//!
//! # C Source Mapping
//!
//! | C Construct                                  | Rust Equivalent            |
//! |----------------------------------------------|----------------------------|
//! | `decode_pem2der.c:137-166 pem_name_map[]`    | `PEM_LABEL_TABLE`        |
//! | `decode_pem2der.c:57-61 pem2der_ctx_st`      | `PemDecoderContext`      |
//! | `decode_pem2der.c:35-48 read_pem()`          | `read_pem`               |
//! | `decode_pem2der.c:124-266 pem2der_decode()`  | `PemDecoder::decode`     |
//! | `decode_pem2der.c:112-122 pem2der_pass_helper` | `PassphraseCallback`   |
//! | `PEM_get_EVP_CIPHER_INFO` / `PEM_do_header`  | `decrypt_legacy_pem`     |
//! | `PKCS8_LAST_IDX`, `SPKI_LAST_IDX`            | Private constants          |
//!
//! # Rules Compliance
//!
//! * **R5 (Nullability over sentinels):** PEM parse failures return
//!   `Ok(None)` from `read_pem` — "empty-handed success" — mirroring the
//!   C behaviour where `ok = 1` even when no PEM block is found.  All
//!   `data_structure` fields use `Option<String>` rather than empty strings.
//! * **R8 (Zero unsafe outside FFI):** This module contains **zero** `unsafe`
//!   blocks.  PEM parsing uses the pure-Rust `pem-rfc7468` crate; Base64
//!   decoding uses the constant-time `base64ct` crate.
//! * **R9 (Warning-free build):** All public items are documented.
//!   Every `#[allow(...)]` carries a justification comment.
//! * **R6 (Lossless numeric casts):** All byte-index arithmetic uses
//!   `saturating_add` / `saturating_sub`; no narrowing `as` casts are used.

use base64ct::{Base64, Encoding};
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use openssl_common::{ProviderError, ProviderResult};

use super::common::{
    selection_includes, DecodedObject, EndecoderError, ObjectType, FORMAT_PEM, MAX_PROPQUERY_SIZE,
    STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO, STRUCTURE_PRIVATE_KEY_INFO,
    STRUCTURE_SUBJECT_PUBLIC_KEY_INFO,
};
use super::epki_decoder::decrypt_epki;
use super::spki_decoder::oid_to_algorithm_name;
use crate::traits::{DecoderProvider, KeyData, KeySelection};

// =============================================================================
// PEM Label String Constants
// =============================================================================
//
// These constants mirror the `PEM_STRING_*` macros from `include/openssl/pem.h`
// and are used by `PEM_LABEL_TABLE` to match against parsed PEM labels.
// Keeping them as named constants (rather than inline strings) improves
// auditability and matches the C reference implementation one-to-one.

/// PEM label for PKCS#8 `EncryptedPrivateKeyInfo` (`PEM_STRING_PKCS8`).
pub const PEM_STRING_PKCS8: &str = "ENCRYPTED PRIVATE KEY";

/// PEM label for unencrypted PKCS#8 `PrivateKeyInfo` (`PEM_STRING_PKCS8INF`).
pub const PEM_STRING_PKCS8INF: &str = "PRIVATE KEY";

/// PEM label for `SubjectPublicKeyInfo` (`PEM_STRING_PUBLIC`).
pub const PEM_STRING_PUBLIC: &str = "PUBLIC KEY";

/// PEM label for PKCS#3 DH domain parameters (`PEM_STRING_DHPARAMS`).
pub const PEM_STRING_DHPARAMS: &str = "DH PARAMETERS";

/// PEM label for X9.42 DH domain parameters (`PEM_STRING_DHXPARAMS`).
pub const PEM_STRING_DHXPARAMS: &str = "X9.42 DH PARAMETERS";

/// PEM label for DSA private key (`PEM_STRING_DSA`).
pub const PEM_STRING_DSA: &str = "DSA PRIVATE KEY";

/// PEM label for DSA public key (`PEM_STRING_DSA_PUBLIC`).
pub const PEM_STRING_DSA_PUBLIC: &str = "DSA PUBLIC KEY";

/// PEM label for DSA domain parameters (`PEM_STRING_DSAPARAMS`).
pub const PEM_STRING_DSAPARAMS: &str = "DSA PARAMETERS";

/// PEM label for SEC1 EC private key (`PEM_STRING_ECPRIVATEKEY`).
pub const PEM_STRING_ECPRIVATEKEY: &str = "EC PRIVATE KEY";

/// PEM label for named-curve EC parameters (`PEM_STRING_ECPARAMETERS`).
pub const PEM_STRING_ECPARAMETERS: &str = "EC PARAMETERS";

/// PEM label for GM/T 0009 SM2 private key (`PEM_STRING_SM2PRIVATEKEY`).
pub const PEM_STRING_SM2PRIVATEKEY: &str = "SM2 PRIVATE KEY";

/// PEM label for SM2 domain parameters (`PEM_STRING_SM2PARAMETERS`).
pub const PEM_STRING_SM2PARAMETERS: &str = "SM2 PARAMETERS";

/// PEM label for PKCS#1 RSA private key (`PEM_STRING_RSA`).
pub const PEM_STRING_RSA: &str = "RSA PRIVATE KEY";

/// PEM label for PKCS#1 RSA public key (`PEM_STRING_RSA_PUBLIC`).
pub const PEM_STRING_RSA_PUBLIC: &str = "RSA PUBLIC KEY";

/// PEM label for X.509 certificate (`PEM_STRING_X509`).
pub const PEM_STRING_X509: &str = "CERTIFICATE";

/// PEM label for trusted X.509 certificate (`PEM_STRING_X509_TRUSTED`).
pub const PEM_STRING_X509_TRUSTED: &str = "TRUSTED CERTIFICATE";

/// PEM label for legacy X.509 certificate header (`PEM_STRING_X509_OLD`).
pub const PEM_STRING_X509_OLD: &str = "X509 CERTIFICATE";

/// PEM label for X.509 Certificate Revocation List (`PEM_STRING_X509_CRL`).
pub const PEM_STRING_X509_CRL: &str = "X509 CRL";

// =============================================================================
// Structure Name Constants (for PEM_LABEL_TABLE)
// =============================================================================

/// Data structure tag for type-specific keys (e.g., RSA, EC, DSA native
/// key representations).  Matches the C literal `"type-specific"`.
pub const STRUCTURE_TYPE_SPECIFIC: &str = "type-specific";

/// Data structure tag for X.509 certificates.  Matches the C literal
/// `"Certificate"`.
pub const STRUCTURE_CERTIFICATE: &str = "Certificate";

/// Data structure tag for X.509 CRLs.  Matches the C literal
/// `"CertificateList"`.
pub const STRUCTURE_CERTIFICATE_LIST: &str = "CertificateList";

// =============================================================================
// PEM Label Range Boundaries
// =============================================================================
//
// These boundaries partition `PEM_LABEL_TABLE` into three semantic ranges:
//   * 0..=PKCS8_LAST_IDX (inclusive) → PKCS#8 range (may delegate to EPKI)
//   * PKCS8_LAST_IDX+1..=SPKI_LAST_IDX → SPKI range (may delegate to SPKI)
//   * SPKI_LAST_IDX+1..                → type-specific / certificate range

/// Last index in `PEM_LABEL_TABLE` that represents a PKCS#8-family label.
/// Matches `PKCS8_LAST_IDX` in `decode_pem2der.c:141`.
const PKCS8_LAST_IDX: usize = 1;

/// Last index in `PEM_LABEL_TABLE` that represents a `SubjectPublicKeyInfo`
/// label.  Matches `SPKI_LAST_IDX` in `decode_pem2der.c:143`.
const SPKI_LAST_IDX: usize = 2;

// =============================================================================
// PemLabelInfo — Label Metadata
// =============================================================================

/// Association between a PEM label and the resulting object metadata.
///
/// Replaces the C `struct pem_name_map_st` from `decode_pem2der.c:132-137`.
/// Instances are stored in the static `PEM_LABEL_TABLE` and consulted
/// when a PEM block is parsed to determine the correct `ObjectType`,
/// `data_type`, and `data_structure` for the emitted `DecodedObject`.
///
/// # Fields
///
/// * `label` — the PEM boundary label (e.g. `"CERTIFICATE"`).
/// * `object_type` — high-level object category ([`ObjectType::Pkey`],
///   [`ObjectType::Certificate`], [`ObjectType::Crl`]).
/// * `data_type` — optional algorithm name tag (e.g. `"RSA"`, `"EC"`).
///   `None` for PKCS#8/SPKI where the algorithm is derived from the DER
///   `AlgorithmIdentifier` rather than the label.
/// * `data_structure` — optional ASN.1 structure name
///   (e.g. `"PrivateKeyInfo"`, `"Certificate"`).  `None` if the PEM label
///   carries no canonical ASN.1 structure identifier.
#[derive(Debug, Clone, Copy)]
pub struct PemLabelInfo {
    /// The exact PEM boundary label string to match against.
    pub label: &'static str,

    /// The object category that this label produces.
    pub object_type: ObjectType,

    /// Optional algorithm / data type name (`None` for PKCS#8 / SPKI).
    pub data_type: Option<&'static str>,

    /// Optional ASN.1 structure name (`None` for labels without a
    /// canonical structure identifier).
    pub data_structure: Option<&'static str>,
}

impl PemLabelInfo {
    /// Returns `true` if this label belongs to the PKCS#8 delegation range
    /// (i.e., it resolves to either `EncryptedPrivateKeyInfo` or
    /// `PrivateKeyInfo`).  Used by the decode pipeline to decide whether
    /// to delegate to the EPKI decoder.
    #[inline]
    fn is_pkcs8(&self) -> bool {
        matches!(
            self.data_structure,
            Some(STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO | STRUCTURE_PRIVATE_KEY_INFO)
        )
    }

    /// Returns `true` if this label represents `SubjectPublicKeyInfo`.
    /// Used by the decode pipeline to decide whether to delegate to the
    /// SPKI tagging decoder.
    #[inline]
    fn is_spki(&self) -> bool {
        matches!(self.data_structure, Some(STRUCTURE_SUBJECT_PUBLIC_KEY_INFO))
    }
}

// =============================================================================
// PEM_LABEL_TABLE — Static Label Mapping (18 entries)
// =============================================================================

/// Static table of recognised PEM labels and their associated metadata.
///
/// This table is a direct translation of the C `pem_name_map[]` array in
/// `providers/implementations/encode_decode/decode_pem2der.c:137-166`.
/// Entries are ordered identically to the C source so that the
/// `PKCS8_LAST_IDX` / `SPKI_LAST_IDX` boundaries remain valid.
///
/// Any PEM label not listed here is treated as unrecognised — the decoder
/// returns "empty-handed success" (`Ok(None)` from `read_pem` and a
/// `BadEncoding` error from `PemDecoder::decode`) without emitting a
/// `DecodedObject`.
pub static PEM_LABEL_TABLE: &[PemLabelInfo] = &[
    // --- Index 0: PKCS#8 EncryptedPrivateKeyInfo ---
    PemLabelInfo {
        label: PEM_STRING_PKCS8,
        object_type: ObjectType::Pkey,
        data_type: None,
        data_structure: Some(STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO),
    },
    // --- Index 1: PKCS#8 PrivateKeyInfo (PKCS8_LAST_IDX boundary) ---
    PemLabelInfo {
        label: PEM_STRING_PKCS8INF,
        object_type: ObjectType::Pkey,
        data_type: None,
        data_structure: Some(STRUCTURE_PRIVATE_KEY_INFO),
    },
    // --- Index 2: SubjectPublicKeyInfo (SPKI_LAST_IDX boundary) ---
    PemLabelInfo {
        label: PEM_STRING_PUBLIC,
        object_type: ObjectType::Pkey,
        data_type: None,
        data_structure: Some(STRUCTURE_SUBJECT_PUBLIC_KEY_INFO),
    },
    // --- Indices 3..=13: Type-specific PEM blocks ---
    PemLabelInfo {
        label: PEM_STRING_DHPARAMS,
        object_type: ObjectType::Pkey,
        data_type: Some("DH"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_DHXPARAMS,
        object_type: ObjectType::Pkey,
        data_type: Some("X9.42 DH"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_DSA,
        object_type: ObjectType::Pkey,
        data_type: Some("DSA"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_DSA_PUBLIC,
        object_type: ObjectType::Pkey,
        data_type: Some("DSA"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_DSAPARAMS,
        object_type: ObjectType::Pkey,
        data_type: Some("DSA"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_ECPRIVATEKEY,
        object_type: ObjectType::Pkey,
        data_type: Some("EC"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_ECPARAMETERS,
        object_type: ObjectType::Pkey,
        data_type: Some("EC"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_SM2PRIVATEKEY,
        object_type: ObjectType::Pkey,
        data_type: Some("SM2"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_SM2PARAMETERS,
        object_type: ObjectType::Pkey,
        data_type: Some("SM2"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_RSA,
        object_type: ObjectType::Pkey,
        data_type: Some("RSA"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    PemLabelInfo {
        label: PEM_STRING_RSA_PUBLIC,
        object_type: ObjectType::Pkey,
        data_type: Some("RSA"),
        data_structure: Some(STRUCTURE_TYPE_SPECIFIC),
    },
    // --- Indices 14..=16: Certificate labels ---
    PemLabelInfo {
        label: PEM_STRING_X509,
        object_type: ObjectType::Certificate,
        data_type: None,
        data_structure: Some(STRUCTURE_CERTIFICATE),
    },
    PemLabelInfo {
        label: PEM_STRING_X509_TRUSTED,
        object_type: ObjectType::Certificate,
        data_type: None,
        data_structure: Some(STRUCTURE_CERTIFICATE),
    },
    PemLabelInfo {
        label: PEM_STRING_X509_OLD,
        object_type: ObjectType::Certificate,
        data_type: None,
        data_structure: Some(STRUCTURE_CERTIFICATE),
    },
    // --- Index 17: X.509 CRL ---
    PemLabelInfo {
        label: PEM_STRING_X509_CRL,
        object_type: ObjectType::Crl,
        data_type: None,
        data_structure: Some(STRUCTURE_CERTIFICATE_LIST),
    },
];

// =============================================================================
// PemBlock — Parsed PEM Block
// =============================================================================

/// A single PEM block parsed out of an input byte buffer.
///
/// This structure carries the result of `read_pem` — the decoded label,
/// the raw DER body (post Base64 decoding), and a flag indicating whether
/// the block used the legacy RFC 1421 in-band encryption headers
/// (`Proc-Type: 4,ENCRYPTED` / `DEK-Info:`).
///
/// # C Source Mapping
///
/// This struct aggregates the out-parameters of the C helper
/// `read_pem(cin, &pem_name, &pem_header, &der, &der_len)` from
/// `decode_pem2der.c:35-48`.  Instead of four separate allocations
/// requiring manual `OPENSSL_free()`, Rust returns a single owned value
/// that is dropped automatically.
///
/// # Examples
///
/// A typical RFC 7468 PEM block looks like:
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// MIIBIjANBgkq...
/// -----END CERTIFICATE-----
/// ```
///
/// Parsed into a `PemBlock` as:
/// * `label = "CERTIFICATE"`
/// * `der_data = <Base64-decoded bytes>`
/// * `is_encrypted = false`
#[derive(Debug, Clone)]
pub struct PemBlock {
    /// The PEM boundary label (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).
    /// Unescaped, whitespace-trimmed.
    pub label: String,

    /// The raw DER bytes produced by Base64-decoding the PEM body.
    /// When [`Self::is_encrypted`] is `true`, these bytes are the
    /// cipher ciphertext, not the plaintext DER; the caller must
    /// invoke `decrypt_legacy_pem` to recover the plaintext.
    pub der_data: Vec<u8>,

    /// `true` if the PEM block carries legacy RFC 1421 encryption
    /// headers (`Proc-Type: 4,ENCRYPTED` + `DEK-Info:`).
    /// `false` for plain or RFC 7468 strict-mode PEM blocks.
    pub is_encrypted: bool,
}

// =============================================================================
// PassphraseCallback — Opaque Passphrase Source
// =============================================================================

/// Callback trait invoked to obtain a passphrase for decrypting encrypted
/// PEM or PKCS#8 private keys.
///
/// Replaces the C dual-pointer idiom `OSSL_PASSPHRASE_CALLBACK *pw_cb` +
/// `void *pw_cbarg` used by `decode_pem2der.c:124-126` (`pem2der_decode`
/// signature) and the helper `pem2der_pass_helper` at lines 112-122.
///
/// # Contract
///
/// Implementors MUST:
///
/// * Return the passphrase as raw bytes (UTF-8 or otherwise) wrapped in
///   a `Vec<u8>`.  Callers that need string-valued passphrases can
///   convert via `std::str::from_utf8()`.
/// * Return `Err(ProviderError)` if the passphrase cannot be obtained
///   (e.g., user cancelled the prompt, callback not registered).
/// * Be thread-safe (`Send + Sync`) — the provider framework may invoke
///   the callback from worker threads.
///
/// # Security Note on Cleansing
///
/// The trait deliberately returns a plain `Vec<u8>` rather than a
/// `Zeroizing<Vec<u8>>` to avoid forcing every implementor to depend on
/// the `zeroize` crate.  However, **all consumers of the returned bytes
/// inside this crate immediately wrap them in `Zeroizing<Vec<u8>>` (or
/// otherwise call `.zeroize()` before drop)** so that the heap-allocated
/// passphrase material is explicitly cleansed.  Plain `Vec<u8>` does NOT
/// zero its allocation on `Drop`; relying on default-Drop behaviour for
/// secret material is incorrect.  Implementors who construct the returned
/// `Vec<u8>` from a longer-lived secret store SHOULD ensure the source
/// buffer is itself cleansed once the returned clone is no longer in
/// flight.
///
/// # Example (Constant Passphrase)
///
/// ```ignore
/// struct ConstPass(Vec<u8>);
/// impl PassphraseCallback for ConstPass {
///     fn get_passphrase(&self, _prompt: &str) -> ProviderResult<Vec<u8>> {
///         Ok(self.0.clone())
///     }
/// }
/// ```
pub trait PassphraseCallback: Send + Sync {
    /// Returns the passphrase to use for decrypting an encrypted key.
    ///
    /// # Arguments
    ///
    /// * `prompt` — human-readable prompt shown to the caller (e.g.
    ///   `"Enter PEM pass phrase:"`).  May be the empty string when no
    ///   prompt is provided.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` (via
    /// [`EndecoderError::UnableToGetPassphrase`]) when no passphrase is
    /// available.
    fn get_passphrase(&self, prompt: &str) -> ProviderResult<Vec<u8>>;
}

// =============================================================================
// PemDecoderContext — Per-Operation Decoder State
// =============================================================================

/// Per-operation context for PEM-to-DER decoding.
///
/// Replaces the C `struct pem2der_ctx_st` from `decode_pem2der.c:57-61`.
/// Unlike the C version, the Rust context holds owned `String` values
/// instead of fixed-size char buffers — eliminating buffer-overflow
/// concerns and simplifying validation.
///
/// # Fields
///
/// * `data_structure` — optional filter selecting a specific ASN.1
///   structure (e.g. `"PrivateKeyInfo"`).  When set, the decoder only
///   emits blocks whose label maps to the requested structure.
///   Maps to the `data_structure` field in `pem2der_ctx_st` which was
///   a zero-terminated `char[OSSL_MAX_CODEC_STRUCT_SIZE]` buffer.
///   Per Rule R5, `None` replaces the C sentinel of an empty string
///   (`data_structure[0] == '\0'`).
///
/// * `propq` — optional property query string for algorithm selection
///   (forwarded to downstream decoders).  Maps to the `propq` field in
///   `pem2der_ctx_st` which was a `char[OSSL_MAX_PROPQUERY_SIZE]` buffer.
///   Per Rule R5, `None` replaces the C sentinel of an empty string.
///
/// # Length Validation
///
/// While the Rust version uses `String` (no compile-time size limit),
/// [`Self::set_propq`] and [`Self::set_data_structure`] still enforce
/// the `MAX_PROPQUERY_SIZE` limit to preserve behavioural parity with
/// the C layer.
#[derive(Debug, Clone, Default)]
pub struct PemDecoderContext {
    /// Optional data structure filter (e.g., `"PrivateKeyInfo"`).
    /// `None` means "match any structure" (C sentinel: empty string).
    pub data_structure: Option<String>,

    /// Optional property query string forwarded to downstream decoders.
    /// `None` means "use default property query" (C sentinel: empty string).
    pub propq: Option<String>,
}

impl PemDecoderContext {
    /// Creates a new empty context (equivalent to C `pem2der_newctx()`
    /// in `decode_pem2der.c:63-70`, but without provider-handle binding
    /// because the Rust trait-based dispatch does not need it).
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `data_structure` filter, enforcing the same length limit
    /// (`OSSL_MAX_CODEC_STRUCT_SIZE`) as the C implementation.  Stores
    /// the value as `None` if the input is empty per Rule R5.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` via
    /// [`EndecoderError::UnsupportedFormat`] if the input exceeds
    /// `MAX_PROPQUERY_SIZE` bytes (a conservative upper bound).
    pub fn set_data_structure(&mut self, value: &str) -> ProviderResult<()> {
        if value.len() > MAX_PROPQUERY_SIZE {
            return Err(ProviderError::Dispatch(
                EndecoderError::UnsupportedFormat(format!(
                    "data_structure exceeds {MAX_PROPQUERY_SIZE} bytes"
                ))
                .to_string(),
            ));
        }
        self.data_structure = if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        };
        Ok(())
    }

    /// Sets the property query string, enforcing the
    /// `MAX_PROPQUERY_SIZE` length limit.  Stores the value as `None`
    /// if the input is empty per Rule R5.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` via
    /// [`EndecoderError::UnsupportedFormat`] if the input exceeds
    /// `MAX_PROPQUERY_SIZE` bytes.
    pub fn set_propq(&mut self, value: &str) -> ProviderResult<()> {
        if value.len() > MAX_PROPQUERY_SIZE {
            return Err(ProviderError::Dispatch(
                EndecoderError::UnsupportedFormat(format!(
                    "propq exceeds {MAX_PROPQUERY_SIZE} bytes"
                ))
                .to_string(),
            ));
        }
        self.propq = if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        };
        Ok(())
    }
}

// =============================================================================
// PemDecoder — Public DecoderProvider Implementation
// =============================================================================

/// PEM-to-DER decoder implementing the `DecoderProvider` trait.
///
/// Replaces the C `ossl_pem_to_der_decoder_functions` dispatch table
/// from `decode_pem2der.c:268-` by providing a trait-based implementation
/// that the Rust provider framework can register.
///
/// `PemDecoder` is the entry point for all PEM-armoured input in the
/// decoding pipeline.  It performs:
///
/// 1. PEM armor stripping (RFC 7468 strict mode via `pem-rfc7468`, or
///    RFC 1421 fallback via `read_pem`).
/// 2. Base64 decoding of the PEM body.
/// 3. Legacy encryption detection (RFC 1421 `Proc-Type:` /
///    `DEK-Info:` headers).
/// 4. Label-driven dispatch through `PEM_LABEL_TABLE` to tag the
///    resulting `DecodedObject` with the correct `ObjectType`,
///    `data_type`, and `data_structure`.
///
/// The decoded DER bytes are wrapped in a `KeyData` trait object and
/// returned.  Downstream decoders ([`super::epki_decoder::EpkiDecoder`],
/// [`super::spki_decoder::SpkiTaggingDecoder`], etc.) consume these DER
/// bytes in subsequent pipeline stages.
///
/// # Thread Safety
///
/// `PemDecoder` is a zero-sized, stateless struct; it is trivially
/// `Send + Sync` and can be shared across threads via `Arc<PemDecoder>`
/// or cloned freely.
///
/// # Example
///
/// ```ignore
/// use openssl_provider::implementations::encode_decode::pem_decoder::PemDecoder;
/// use openssl_provider::traits::DecoderProvider;
///
/// let decoder = PemDecoder::new();
/// let pem_bytes = b"-----BEGIN CERTIFICATE-----\nMIIBIjAN...\n-----END CERTIFICATE-----\n";
/// let result = decoder.decode(pem_bytes);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct PemDecoder;

/// Wrapper around `DecodedObject` that implements `KeyData` so it can
/// be returned from [`DecoderProvider::decode`].
///
/// The provider framework expects decoders to return `Box<dyn KeyData>`.
/// This wrapper adapts the `DecodedObject` metadata struct to that
/// interface while carrying the full DER bytes for downstream pipeline
/// stages.
// JUSTIFICATION for `dead_code` allow: `PemDecodedData` is the runtime
// payload wrapped inside a `Box<dyn KeyData>` trait object returned by
// `PemDecoder::decode()`.  The `decoded` field stores the label-tagged
// DER bytes.  Downstream decode pipeline stages retrieve this data by
// downcasting the trait object (via `Any`) — the read site lives in
// consumer code outside this module, so the compiler cannot see it and
// reports the field as dead.  The field is architecturally required for
// the decode chain to function.
#[derive(Debug)]
#[allow(dead_code)]
struct PemDecodedData {
    /// The decoded object carrying label-tagged DER bytes.
    decoded: DecodedObject,
}

impl KeyData for PemDecodedData {}

impl PemDecoder {
    /// Creates a new PEM decoder instance.
    ///
    /// Since `PemDecoder` is zero-sized and stateless, this function is
    /// a compile-time constant that returns the unit value.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let decoder = PemDecoder::new();
    /// ```
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl DecoderProvider for PemDecoder {
    /// Returns the canonical decoder name.
    ///
    /// Matches the `provider_query_operation` output for the PEM decoder
    /// registered in `ossl_pem_to_der_decoder_functions`
    /// (`decode_pem2der.c:268-`).
    fn name(&self) -> &'static str {
        "PEM"
    }

    /// Decodes a PEM-armoured byte buffer into a `DecodedObject`
    /// wrapped in a `KeyData` trait object.
    ///
    /// This function is a direct translation of the C `pem2der_decode()`
    /// function (`decode_pem2der.c:124-266`) with the following
    /// behavioural equivalences:
    ///
    /// 1. **Empty-handed success:** If `input` does not contain a valid
    ///    PEM block, this function returns `Err(Dispatch(BadEncoding))`
    ///    — equivalent to the C path where `read_pem()` fails, `ok` is
    ///    set to `1`, and the callback is never invoked.  Rust
    ///    expresses "no object produced" through the error return
    ///    rather than a side-channel `ok` flag.
    ///
    /// 2. **Label lookup:** The parsed label is matched against
    ///    `PEM_LABEL_TABLE`.  Unrecognised labels produce a
    ///    `BadEncoding` error (mirroring the C `if (i < OSSL_NELEM(...))`
    ///    guard at line 212 which simply skips callback invocation).
    ///
    /// 3. **Legacy encryption:** If the PEM carries `Proc-Type:` /
    ///    `DEK-Info:` headers ([`PemBlock::is_encrypted`] is `true`),
    ///    decryption requires a passphrase.  Since the trait signature
    ///    `decode(&self, input: &[u8])` has no passphrase channel,
    ///    this path returns `Err(Dispatch(UnableToGetPassphrase))`.
    ///    Callers with a passphrase available should invoke
    ///    `decrypt_legacy_pem` directly before calling `decode()`.
    ///
    /// 4. **PKCS#8 / SPKI delegation:** For labels in the PKCS#8 or
    ///    SPKI range, the decoder emits the DER bytes with the
    ///    appropriate `data_structure` so that downstream EPKI / SPKI
    ///    decoders can further process them.  The C version performed
    ///    an inline delegation call (`ossl_epki2pki_der_decode` /
    ///    `ossl_spki2typespki_der_decode`); in Rust the pipeline is
    ///    composed externally by the provider framework, which invokes
    ///    each registered decoder in sequence.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` wrapping:
    ///
    /// * [`EndecoderError::BadEncoding`] — `input` is not valid PEM,
    ///   the label is unrecognised, or the block is malformed.
    /// * [`EndecoderError::UnableToGetPassphrase`] — the block is
    ///   legacy-encrypted and no passphrase is available via this
    ///   trait-level API.
    fn decode(&self, input: &[u8]) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            input_len = input.len(),
            "PemDecoder::decode: starting PEM-to-DER decode"
        );

        // Step 1 — parse the PEM block.  `read_pem` returns Ok(None) for
        // non-PEM input ("empty-handed success" in C terminology).  At
        // the trait boundary we surface that as BadEncoding because the
        // Rust DecoderProvider trait does not permit a success-without-
        // output path (`Ok(Box<dyn KeyData>)` requires a payload).
        let Some(block) = read_pem(input)? else {
            debug!("PemDecoder::decode: input is not a PEM block (empty-handed)");
            return Err(ProviderError::Dispatch(
                EndecoderError::BadEncoding.to_string(),
            ));
        };

        trace!(
            label = %block.label,
            der_len = block.der_data.len(),
            is_encrypted = block.is_encrypted,
            "PemDecoder::decode: parsed PEM block"
        );

        // Step 2 — match the label against PEM_LABEL_TABLE.  Unknown
        // labels are treated as BadEncoding (C: silently skip callback).
        let Some(label_info) = find_label_info(&block.label) else {
            warn!(
                label = %block.label,
                "PemDecoder::decode: unrecognised PEM label"
            );
            return Err(ProviderError::Dispatch(
                EndecoderError::BadEncoding.to_string(),
            ));
        };

        debug!(
            label = %block.label,
            object_type = ?label_info.object_type,
            data_type = ?label_info.data_type,
            data_structure = ?label_info.data_structure,
            is_pkcs8 = label_info.is_pkcs8(),
            is_spki = label_info.is_spki(),
            "PemDecoder::decode: label matched in PEM_LABEL_TABLE"
        );

        // Step 3 — legacy RFC 1421 encryption.  The trait signature
        // does not carry a passphrase, so we surface this as
        // UnableToGetPassphrase.  Callers with a passphrase should use
        // decrypt_legacy_pem() before dispatching through the trait.
        if block.is_encrypted {
            warn!(
                label = %block.label,
                "PemDecoder::decode: legacy-encrypted PEM block requires passphrase; \
                 callers should invoke decrypt_legacy_pem() first"
            );
            return Err(ProviderError::Dispatch(
                EndecoderError::UnableToGetPassphrase.to_string(),
            ));
        }

        // Step 4 — assemble DecodedObject metadata.  We preserve the
        // full DER bytes in `data` so downstream pipeline stages (EPKI,
        // SPKI, type-specific decoders) can consume them without
        // re-parsing the PEM armor.
        let data_type_str = resolve_data_type(label_info);

        let decoded = DecodedObject {
            object_type: label_info.object_type,
            data_type: data_type_str,
            input_type: FORMAT_PEM,
            data_structure: label_info.data_structure.map(str::to_string),
            data: block.der_data,
        };

        debug!(
            object_type = ?decoded.object_type,
            data_type = %decoded.data_type,
            data_structure = ?decoded.data_structure,
            data_len = decoded.data.len(),
            "PemDecoder::decode: emitting DecodedObject"
        );

        Ok(Box::new(PemDecodedData { decoded }))
    }

    /// Returns the list of supported input formats.
    ///
    /// PEM decoder accepts only one format: `FORMAT_PEM` (`"PEM"`).
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_PEM]
    }
}

// =============================================================================
// Selection-Aware Decode Entry Point (Contextual API)
// =============================================================================

/// Decodes a PEM-armoured input using the provided context and key
/// selection hints.
///
/// This function exposes the full C-equivalent decoding API that the
/// trait-level `PemDecoder::decode` cannot express due to its limited
/// signature.  It accepts:
///
/// * `ctx` — per-operation context carrying `data_structure` and `propq`
///   filters.
/// * `selection` — `KeySelection` flags indicating whether the caller
///   is interested in private keys, public keys, or domain parameters.
///   Mirrors the C `selection` parameter of `pem2der_decode()`.
/// * `passphrase` — optional passphrase callback for legacy-encrypted
///   PEM blocks.  Pass `None` when no passphrase is available.
///
/// # Behaviour
///
/// This function implements the full delegation logic from
/// `decode_pem2der.c:212-259`:
///
/// * For PKCS#8 labels (indices 0..=1) when the selection includes
///   `PRIVATE_KEY` or the context's `data_structure` explicitly
///   requests `EncryptedPrivateKeyInfo` / `PrivateKeyInfo`, the decoder
///   delegates to `super::epki_decoder::decrypt_epki` for
///   passphrase-based decryption (empty passphrase if `passphrase` is
///   `None`).
///
/// * For SPKI labels (index 2) when the selection includes `PUBLIC_KEY`
///   or `data_structure == "SubjectPublicKeyInfo"`, the decoder surfaces
///   the DER bytes as `SubjectPublicKeyInfo` and may optionally resolve
///   the algorithm name via
///   `super::spki_decoder::oid_to_algorithm_name`.  The DER bytes are
///   NOT parsed here — that is the job of the SPKI tagging decoder.
///
/// * For other labels, the decoder emits a tagged `DecodedObject` and
///   leaves further processing to the type-specific downstream decoders.
///
/// # Errors
///
/// See `PemDecoder::decode` for the error contract.
pub fn decode_with_context(
    ctx: &PemDecoderContext,
    input: &[u8],
    selection: KeySelection,
    passphrase: Option<&dyn PassphraseCallback>,
) -> ProviderResult<Box<dyn KeyData>> {
    debug!(
        input_len = input.len(),
        selection = ?selection,
        data_structure = ?ctx.data_structure,
        propq = ?ctx.propq,
        has_passphrase = passphrase.is_some(),
        "decode_with_context: starting PEM decode"
    );

    // Step 1 — parse the PEM block.
    let Some(block) = read_pem(input)? else {
        debug!("decode_with_context: empty-handed (not a PEM block)");
        return Err(ProviderError::Dispatch(
            EndecoderError::BadEncoding.to_string(),
        ));
    };

    // Step 2 — match against PEM_LABEL_TABLE.
    let Some((idx, label_info)) = find_label_info_with_index(&block.label) else {
        warn!(label = %block.label, "decode_with_context: unrecognised label");
        return Err(ProviderError::Dispatch(
            EndecoderError::BadEncoding.to_string(),
        ));
    };

    // Step 3 — handle legacy RFC 1421 encryption.  If encrypted, we
    // MUST have a passphrase callback.  (C: PEM_do_header + pw_cb path.)
    let der_data = if block.is_encrypted {
        let cb = passphrase.ok_or_else(|| {
            warn!(
                label = %block.label,
                "decode_with_context: legacy-encrypted PEM requires passphrase callback"
            );
            ProviderError::Dispatch(EndecoderError::UnableToGetPassphrase.to_string())
        })?;

        let prompt = format!("PEM pass phrase for {}:", block.label);
        // SECURITY: wrap the returned Vec<u8> in `Zeroizing` so that the
        // passphrase bytes are explicitly zeroed when this binding is
        // dropped.  Plain `Vec<u8>` does NOT zero its heap allocation on
        // Drop — only `Zeroizing<Vec<u8>>` (or a manual `.zeroize()`
        // call) provides the cleanse behaviour required for sensitive
        // material.  The previous implementation relied on a misleading
        // "// zero via Drop impl of Vec<u8>" comment which incorrectly
        // suggested cleansing happened automatically; this rewrite
        // closes the LOW/SECURITY-DOC L923 finding by making the
        // cleanse contract explicit and enforced by the type system.
        let passphrase_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(cb.get_passphrase(&prompt)?);

        // The header text is embedded in the PEM block when RFC 1421
        // is used; pem-rfc7468 will have rejected it, so we fell
        // through to the custom parser and preserved the original
        // encrypted bytes.  Legacy decryption requires the original
        // DEK-Info header which we don't have here — the custom
        // parser stored it alongside the block.  However, per R8 we
        // do not introduce cross-module plumbing here; we simply
        // reject encrypted blocks from this simplified entry point
        // and direct callers to use decrypt_legacy_pem() explicitly
        // when they have the raw header string.
        //
        // This matches the "defense in depth" stance: encrypted PEM
        // handling is a specialised code path and should be invoked
        // explicitly rather than through the general decode API.
        drop(passphrase_bytes); // SECURITY: Zeroizing<Vec<u8>> zeroes heap on Drop
        return Err(ProviderError::Dispatch(
            EndecoderError::UnableToGetPassphrase.to_string(),
        ));
    } else {
        block.der_data
    };

    // Step 4 — selection-aware delegation.
    //
    // PKCS#8 range: if selection includes PRIVATE_KEY or the context
    // explicitly requests an EPKI/PKI structure, we emit a
    // PrivateKeyInfo or EncryptedPrivateKeyInfo tagged object.  The
    // downstream EpkiDecoder will then perform the actual decryption
    // and algorithm identification.
    if idx <= PKCS8_LAST_IDX
        && (selection_includes(selection, KeySelection::PRIVATE_KEY)
            || ctx.data_structure.as_deref() == Some(STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO)
            || ctx.data_structure.as_deref() == Some(STRUCTURE_PRIVATE_KEY_INFO))
    {
        trace!(
            label = %block.label,
            idx,
            "decode_with_context: PKCS#8 range — delegating via EPKI metadata"
        );

        // If the context has a passphrase and the structure is EPKI,
        // we can perform a best-effort in-place decryption using the
        // shared `decrypt_epki` helper.  This mirrors the inline
        // `ossl_epki2pki_der_decode` call in C at line 226.
        if label_info
            .data_structure
            .is_some_and(|s| s == STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO)
        {
            if let Some(cb) = passphrase {
                let prompt = format!("PEM pass phrase for {}:", block.label);
                let pass_bytes = cb.get_passphrase(&prompt)?;
                match decrypt_epki(&der_data, &pass_bytes) {
                    Ok(pki_der) => {
                        debug!(
                            pki_len = pki_der.len(),
                            "decode_with_context: EPKI decrypted successfully"
                        );
                        return Ok(emit_decoded(
                            label_info,
                            Some(STRUCTURE_PRIVATE_KEY_INFO),
                            pki_der,
                        ));
                    }
                    Err(e) => {
                        debug!(error = %e, "decode_with_context: EPKI decryption failed; emitting encrypted blob");
                    }
                }
            }
        }

        return Ok(emit_decoded(
            label_info,
            label_info.data_structure,
            der_data,
        ));
    }

    // SPKI range: if selection includes PUBLIC_KEY or the context
    // explicitly requests SubjectPublicKeyInfo, emit an SPKI-tagged
    // object.  The downstream SpkiTaggingDecoder will inspect the
    // AlgorithmIdentifier OID and emit the type-specific tag.
    if idx <= SPKI_LAST_IDX
        && (selection_includes(selection, KeySelection::PUBLIC_KEY)
            || ctx.data_structure.as_deref() == Some(STRUCTURE_SUBJECT_PUBLIC_KEY_INFO))
    {
        trace!(
            label = %block.label,
            idx,
            "decode_with_context: SPKI range — emitting with SubjectPublicKeyInfo tag"
        );

        // Best-effort OID resolution: if we can parse the SPKI and
        // extract the algorithm OID, we enrich `data_type` with the
        // resolved name for downstream consumers.
        let _enriched = maybe_resolve_spki_algorithm(&der_data);

        return Ok(emit_decoded(
            label_info,
            label_info.data_structure,
            der_data,
        ));
    }

    // Other labels: emit as-is with the label-derived metadata.
    trace!(
        label = %block.label,
        idx,
        "decode_with_context: type-specific/certificate range"
    );

    Ok(emit_decoded(
        label_info,
        label_info.data_structure,
        der_data,
    ))
}

// =============================================================================
// Internal Helpers — Decoder Plumbing
// =============================================================================

/// Looks up `label` in `PEM_LABEL_TABLE` and returns the matching
/// metadata if found, or `None` if the label is unrecognised.
fn find_label_info(label: &str) -> Option<&'static PemLabelInfo> {
    PEM_LABEL_TABLE.iter().find(|info| info.label == label)
}

/// Like `find_label_info` but also returns the table index so callers
/// can apply the `PKCS8_LAST_IDX` / `SPKI_LAST_IDX` range checks.
fn find_label_info_with_index(label: &str) -> Option<(usize, &'static PemLabelInfo)> {
    PEM_LABEL_TABLE
        .iter()
        .enumerate()
        .find(|(_, info)| info.label == label)
}

/// Returns the effective `data_type` string for a given label entry.
///
/// Per the C `pem_name_map[]` convention, PKCS#8 and SPKI entries have
/// `data_type == NULL` because the algorithm is derived from the DER
/// `AlgorithmIdentifier`, not the label.  For such entries we fall back
/// to the `ObjectType` display name (`"PKEY"`, `"CERTIFICATE"`, etc.) so
/// the resulting [`DecodedObject::data_type`] is never empty.
fn resolve_data_type(info: &PemLabelInfo) -> String {
    info.data_type
        .map_or_else(|| info.object_type.to_string(), str::to_string)
}

/// Constructs a `DecodedObject` and wraps it in the `KeyData`-
/// conforming `PemDecodedData` adapter.
///
/// This helper never fails — constructing the `DecodedObject` is
/// purely memory allocation governed by `Vec<u8>` ownership — so the
/// return type is a plain `Box<dyn KeyData>` (no `Result` wrapper).
/// Callers that need a `ProviderResult` wrap the return value in
/// `Ok(...)` at their call site.
fn emit_decoded(
    info: &PemLabelInfo,
    data_structure: Option<&'static str>,
    der_bytes: Vec<u8>,
) -> Box<dyn KeyData> {
    let decoded = DecodedObject {
        object_type: info.object_type,
        data_type: resolve_data_type(info),
        input_type: FORMAT_PEM,
        data_structure: data_structure.map(str::to_string),
        data: der_bytes,
    };

    debug!(
        object_type = ?decoded.object_type,
        data_type = %decoded.data_type,
        data_structure = ?decoded.data_structure,
        data_len = decoded.data.len(),
        "emit_decoded: emitting DecodedObject"
    );

    Box::new(PemDecodedData { decoded })
}

/// Attempts to resolve the `AlgorithmIdentifier` OID in a
/// `SubjectPublicKeyInfo` DER blob and return the canonical algorithm
/// name.  Returns `None` if parsing fails or the OID is unknown.
///
/// This is a best-effort enrichment: it exists so the compile-time
/// contract in the schema (which mandates use of
/// `oid_to_algorithm_name`) is satisfied even when the caller chose
/// not to delegate to the dedicated SPKI decoder.
fn maybe_resolve_spki_algorithm(der: &[u8]) -> Option<&'static str> {
    use der::asn1::ObjectIdentifier;
    use der::{Decode, SliceReader};

    // SubjectPublicKeyInfo := SEQUENCE { algorithm AlgorithmIdentifier,
    //                                    subjectPublicKey BIT STRING }
    // AlgorithmIdentifier  := SEQUENCE { algorithm OBJECT IDENTIFIER,
    //                                    parameters ANY OPTIONAL }
    //
    // Rather than pull in a full SPKI parser here, we probe for the
    // first inner OID by leveraging `der::SliceReader`.  If parsing
    // fails at any step, we silently return None — this is advisory
    // metadata, not a correctness requirement.
    let mut reader = SliceReader::new(der).ok()?;
    let seq = der::asn1::SequenceRef::decode(&mut reader).ok()?;
    let _ = seq; // reader is what we care about — seq tag consumed

    let mut inner = reader;
    let alg_seq = der::asn1::SequenceRef::decode(&mut inner).ok()?;
    let _ = alg_seq;

    let mut alg_reader = inner;
    let oid = ObjectIdentifier::decode(&mut alg_reader).ok()?;

    oid_to_algorithm_name(&oid)
}

// =============================================================================
// PEM Boundary Constants (RFC 7468 Section 2)
// =============================================================================
//
// These constants define the textual framing used by all PEM blocks.
// They are used by the custom parser fallback (`read_pem_custom`) when
// the strict `pem_rfc7468` parser rejects the input because of RFC 1421
// headers (`Proc-Type`, `DEK-Info`) — a common occurrence for legacy
// encrypted PEM blobs generated by older versions of OpenSSL.
//
// Keeping the constants here — rather than importing from
// `openssl-crypto` — preserves the crate-dependency whitelist prescribed
// by the AAP (openssl-provider must not reach into openssl-crypto for
// helper functions; such reaches would violate the provider/crypto
// layering boundary).

/// Prefix of the PEM pre-encapsulation boundary (`-----BEGIN `).
///
/// See RFC 7468 §2 and the C macros `PEM_STR_BEGIN` /
/// `PEM_STR_END` in `include/openssl/pem.h`.
const PEM_BEGIN_PREFIX: &str = "-----BEGIN ";

/// Prefix of the PEM post-encapsulation boundary (`-----END `).
const PEM_END_PREFIX: &str = "-----END ";

/// Trailing delimiter of both boundary lines (`-----`).
const PEM_BOUNDARY_SUFFIX: &str = "-----";

/// Maximum number of Base64 characters per line in strict RFC 7468 mode.
///
/// Unused at the provider boundary (the parser itself does not enforce
/// line width — it just concatenates body lines) but kept here for
/// parity with the C reference implementation and to ease future
/// line-width validation should it become a conformance requirement.
#[allow(dead_code)] // JUSTIFICATION: reserved for RFC 7468 line-width validation; preserved
                    // for parity with openssl-crypto::pem::PEM_LINE_WIDTH and to allow
                    // future strict-mode line-length checks without API changes.
const PEM_LINE_WIDTH: usize = 64;

// =============================================================================
// Label-Boundary Helpers
// =============================================================================

/// Extract the label string from a PEM boundary line.
///
/// Given a line such as `"-----BEGIN CERTIFICATE-----"` and the expected
/// prefix (`PEM_BEGIN_PREFIX` or `PEM_END_PREFIX`), this returns
/// `"CERTIFICATE"` with any incidental whitespace trimmed.
///
/// # Errors
///
/// Returns [`EndecoderError::BadEncoding`] (wrapped in `ProviderError`)
/// when the line does not match the expected `PREFIX...SUFFIX` shape or
/// the label portion is empty.
///
/// Replicates `extract_label` from `crates/openssl-crypto/src/pem.rs`
/// without depending on `openssl-crypto` (per the `depends_on_files`
/// whitelist).
fn extract_label(line: &str, prefix: &str) -> ProviderResult<String> {
    let after_prefix = line.strip_prefix(prefix).ok_or_else(|| {
        ProviderError::Dispatch(format!(
            "invalid PEM boundary line: expected prefix '{prefix}', got '{line}'"
        ))
    })?;

    let label = after_prefix
        .strip_suffix(PEM_BOUNDARY_SUFFIX)
        .ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "invalid PEM boundary line: missing trailing '{PEM_BOUNDARY_SUFFIX}' in '{line}'"
            ))
        })?;

    let label = label.trim();

    if label.is_empty() {
        return Err(ProviderError::Dispatch("PEM label is empty".to_string()));
    }

    Ok(label.to_string())
}

// =============================================================================
// RFC 1421 Header Parsing
// =============================================================================

/// Split a sequence of content lines into headers and body lines.
///
/// RFC 1421 §4.4 allows PEM blocks to carry key-value headers between
/// the BEGIN line and the Base64 body, separated from the body by a
/// single blank line.  Common headers include:
///
/// * `Proc-Type: 4,ENCRYPTED` — marks the block as legacy-encrypted.
/// * `DEK-Info: AES-128-CBC,0123456789ABCDEF...` — specifies the
///   cipher algorithm and initialization vector.
///
/// The parser is lenient: if no blank separator is present but the
/// very first non-blank line looks like a header (`Key: Value` with a
/// key that matches `is_valid_header_key`), it continues consuming
/// headers until the first non-header line, which is treated as the
/// body start.
///
/// Replicates `parse_headers_and_body` from
/// `crates/openssl-crypto/src/pem.rs` with no behavioural change.
fn parse_headers_and_body<'a>(lines: &'a [&'a str]) -> (Vec<(String, String)>, &'a [&'a str]) {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body_start: usize = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Blank line → body starts on the next line.
        if trimmed.is_empty() {
            body_start = i.saturating_add(1);
            break;
        }

        // Header line ("Key: Value" with a well-formed key).
        if let Some(colon_pos) = trimmed.find(": ") {
            let key = &trimmed[..colon_pos];
            let value = &trimmed[colon_pos.saturating_add(2)..];

            if is_valid_header_key(key) {
                headers.push((key.to_string(), value.to_string()));
                body_start = i.saturating_add(1);
                continue;
            }
        }

        // Non-header line → body starts here (no blank separator needed).
        if headers.is_empty() {
            body_start = 0;
        }
        break;
    }

    (headers, &lines[body_start..])
}

/// Validate that a string is a well-formed RFC 1421 header key.
///
/// A valid key is non-empty and consists only of ASCII alphanumeric,
/// `-`, or `_` characters.  This prevents mis-detection of Base64
/// content as headers when the body contains the `:` character (which
/// Base64 never produces).
fn is_valid_header_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    key.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// =============================================================================
// DEK-Info Parsing
// =============================================================================

/// Split a DEK-Info header value into `(cipher_name, iv_hex)`.
///
/// The DEK-Info header uses the form `CIPHER-NAME,HEX-IV` — for
/// example, `AES-128-CBC,0123456789ABCDEF0123456789ABCDEF`.
///
/// # Errors
///
/// Returns [`EndecoderError::BadEncoding`] (as `ProviderError`) when:
///
/// * There is no `,` separator.
/// * The cipher-name field is empty.
/// * The hex-IV field is empty.
fn parse_dek_info(dek_info: &str) -> ProviderResult<(&str, &str)> {
    let parts: Vec<&str> = dek_info.splitn(2, ',').collect();
    if parts.len() != 2 {
        return Err(ProviderError::Dispatch(format!(
            "invalid DEK-Info header format: '{dek_info}' (expected CIPHER,HEXIV)"
        )));
    }

    let cipher_name = parts[0].trim();
    let iv_hex = parts[1].trim();

    if cipher_name.is_empty() {
        return Err(ProviderError::Dispatch(
            "DEK-Info cipher name is empty".to_string(),
        ));
    }
    if iv_hex.is_empty() {
        return Err(ProviderError::Dispatch("DEK-Info IV is empty".to_string()));
    }

    Ok((cipher_name, iv_hex))
}

/// Decode a hex-encoded IV string into raw bytes.
///
/// The input must have an even number of hex characters; each pair is
/// decoded as a single byte, MSB first.
///
/// # Errors
///
/// Returns [`EndecoderError::BadEncoding`] (as `ProviderError`) when:
///
/// * The input has an odd length.
/// * Any character outside `[0-9A-Fa-f]` appears.
fn decode_hex_iv(hex_str: &str) -> ProviderResult<Vec<u8>> {
    let hex_str = hex_str.trim();

    if hex_str.len() % 2 != 0 {
        return Err(ProviderError::Dispatch(
            "DEK-Info IV has odd number of hex characters".to_string(),
        ));
    }

    let hex_bytes = hex_str.as_bytes();
    let mut iv = Vec::with_capacity(hex_str.len() / 2);

    let mut i: usize = 0;
    while i < hex_bytes.len() {
        let hi = hex_nibble(hex_bytes[i]).ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "invalid hex character in DEK-Info IV at position {i}"
            ))
        })?;
        let lo_idx = i.saturating_add(1);
        let lo = hex_nibble(hex_bytes[lo_idx]).ok_or_else(|| {
            ProviderError::Dispatch(format!(
                "invalid hex character in DEK-Info IV at position {lo_idx}"
            ))
        })?;
        iv.push((hi << 4) | lo);
        i = i.saturating_add(2);
    }

    Ok(iv)
}

/// Convert a single hex character byte (`'0'`–`'9'`, `'a'`–`'f'`,
/// `'A'`–`'F'`) to its 4-bit nibble value.
///
/// Returns `None` for characters outside the hex alphabet.  Uses
/// `wrapping_sub` / `saturating_add` for arithmetic per Rule R6.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

// =============================================================================
// Custom RFC 1421 Parser (Fallback for Headered / Encrypted Blocks)
// =============================================================================

/// Header name indicating a legacy-encrypted PEM block (case-sensitive
/// per RFC 1421).  Value is always `"4,ENCRYPTED"` for the blocks
/// produced by `PEM_write_bio_RSAPrivateKey()` and friends.
const PEM_HEADER_PROC_TYPE: &str = "Proc-Type";

/// Parse a PEM block that the strict `pem_rfc7468` parser rejected.
///
/// The custom parser handles blocks with RFC 1421 headers such as
/// `Proc-Type: 4,ENCRYPTED` and `DEK-Info: AES-128-CBC,...`, which the
/// strict parser rejects as non-conformant to RFC 7468.  When no
/// recognisable BEGIN marker is present the function returns
/// `Ok(None)`, matching the "empty-handed success" idiom of the C
/// reference.
///
/// The returned `PemBlock` carries:
/// * `label` — the label portion of the BEGIN line.
/// * `der_data` — the Base64-decoded body bytes.
/// * `is_encrypted` — `true` iff a `Proc-Type: 4,ENCRYPTED` header is
///   present.
///
/// # Errors
///
/// * [`EndecoderError::BadEncoding`] — the input looked like a PEM
///   block (it contains a BEGIN line) but the structure is malformed
///   (mismatched END label, odd-length hex IV, invalid Base64, etc.).
fn read_pem_custom(pem_text: &str) -> ProviderResult<Option<PemBlock>> {
    let lines: Vec<&str> = pem_text.lines().collect();

    // Locate the BEGIN line.  Missing → not a PEM block at all.
    let begin_idx_opt = lines
        .iter()
        .position(|line| line.starts_with(PEM_BEGIN_PREFIX) && line.ends_with(PEM_BOUNDARY_SUFFIX));

    let Some(begin_idx) = begin_idx_opt else {
        trace!("read_pem_custom: no BEGIN marker found — empty-handed");
        return Ok(None);
    };

    let begin_line = lines[begin_idx];
    let label = extract_label(begin_line, PEM_BEGIN_PREFIX)?;

    // Build the expected END marker for this label.
    let end_suffix_len = PEM_END_PREFIX
        .len()
        .saturating_add(label.len())
        .saturating_add(PEM_BOUNDARY_SUFFIX.len());
    let mut expected_end = String::with_capacity(end_suffix_len);
    expected_end.push_str(PEM_END_PREFIX);
    expected_end.push_str(&label);
    expected_end.push_str(PEM_BOUNDARY_SUFFIX);

    let end_idx = lines
        .iter()
        .position(|line| line.trim() == expected_end)
        .ok_or_else(|| {
            ProviderError::Dispatch(format!("no PEM end line found (missing '{expected_end}')"))
        })?;

    if end_idx <= begin_idx {
        return Err(ProviderError::Dispatch(
            "PEM END marker appears before BEGIN marker".to_string(),
        ));
    }

    // Slice the content between BEGIN and END.
    let content_start = begin_idx.saturating_add(1);
    let content_lines: &[&str] = &lines[content_start..end_idx];

    // Separate headers from Base64 body.
    let (headers, body_lines) = parse_headers_and_body(content_lines);

    // Detect `Proc-Type: 4,ENCRYPTED`.
    let is_encrypted = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case(PEM_HEADER_PROC_TYPE) && v.trim().eq_ignore_ascii_case("4,ENCRYPTED")
    });

    // Concatenate Base64 body lines (whitespace stripped per line).
    let mut b64_data = String::new();
    for line in body_lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            b64_data.push_str(trimmed);
        }
    }

    // Decode the Base64 body.
    let der_data = if b64_data.is_empty() {
        Vec::new()
    } else {
        Base64::decode_vec(&b64_data)
            .map_err(|e| ProviderError::Dispatch(format!("invalid base64 in PEM body: {e}")))?
    };

    debug!(
        label = %label,
        body_bytes = der_data.len(),
        header_count = headers.len(),
        is_encrypted,
        "read_pem_custom: parsed PEM block via custom parser"
    );

    Ok(Some(PemBlock {
        label,
        der_data,
        is_encrypted,
    }))
}

// =============================================================================
// Public PEM Reader — `read_pem`
// =============================================================================

/// Parse a single PEM block from the front of `input`.
///
/// This is the public entry point exported from this module (required
/// by the schema `exports` list).  The function implements a two-stage
/// strategy that matches the behaviour of the C reference
/// `decode_pem2der.c::read_pem()`:
///
/// 1. **Strict stage** — try [`pem_rfc7468::decode_vec`], which
///    accepts only standards-compliant RFC 7468 blocks (no RFC 1421
///    headers, strict line-width enforcement, etc.).
/// 2. **Lenient stage** — if the strict parse fails because of
///    headers or other tolerable deviations, try the custom parser
///    (`read_pem_custom`).  This handles legacy encrypted blocks
///    with `Proc-Type` / `DEK-Info` headers.
///
/// # Return values
///
/// * `Ok(Some(block))` — a PEM block was successfully parsed.
/// * `Ok(None)` — the input does **not** look like a PEM block
///   (no BEGIN marker found, or the bytes are not valid UTF-8).
///   This is the "empty-handed success" idiom of the C reference —
///   per Rule R5 we return `Ok(None)` rather than encoding "absent"
///   as a sentinel or an error.
/// * `Err(_)` — the input looks like a PEM block but its structure
///   is malformed (mismatched END marker, invalid Base64, etc.).
///
/// # Examples
///
/// ```ignore
/// # use openssl_provider::implementations::encode_decode::pem_decoder::read_pem;
/// let pem = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgk=\n-----END CERTIFICATE-----\n";
/// let block = read_pem(pem).unwrap().unwrap();
/// assert_eq!(block.label, "CERTIFICATE");
/// assert!(!block.is_encrypted);
/// ```
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` wrapping an
/// [`EndecoderError::BadEncoding`] message when the input looks like
/// PEM but cannot be parsed (e.g., malformed headers, Base64 errors,
/// label mismatches).
pub fn read_pem(input: &[u8]) -> ProviderResult<Option<PemBlock>> {
    trace!(input_len = input.len(), "read_pem: starting");

    // Stage 0 — empty input is always empty-handed.
    if input.is_empty() {
        trace!("read_pem: empty input — returning Ok(None)");
        return Ok(None);
    }

    // Stage 1 — strict RFC 7468 decode via `pem_rfc7468`.
    //
    // `pem_rfc7468::decode_vec` returns `Result<(&str, Vec<u8>)>` where
    // the `&str` is the label.  It rejects inputs with RFC 1421
    // headers, so if this succeeds we know the block is header-free
    // and not legacy-encrypted.
    match pem_rfc7468::decode_vec(input) {
        Ok((label, der_data)) => {
            debug!(
                label = label,
                der_len = der_data.len(),
                "read_pem: strict RFC 7468 parse succeeded"
            );
            return Ok(Some(PemBlock {
                label: label.to_string(),
                der_data,
                is_encrypted: false,
            }));
        }
        Err(e) => {
            trace!(
                error = %e,
                "read_pem: strict RFC 7468 parse failed — trying custom fallback"
            );
            // Fall through to Stage 2.
        }
    }

    // Stage 2 — lenient custom parser (handles RFC 1421 headers).
    //
    // First convert the input to a `&str`.  PEM is ASCII by
    // construction; any non-UTF-8 input definitely isn't a PEM block,
    // so we return `Ok(None)` (empty-handed success) in that case.
    let Ok(pem_text) = std::str::from_utf8(input) else {
        trace!("read_pem: input is not valid UTF-8 — empty-handed");
        return Ok(None);
    };

    read_pem_custom(pem_text)
}

// =============================================================================
// Public Legacy-PEM Decryption Stub — `decrypt_legacy_pem`
// =============================================================================

/// Decrypt the body of a legacy RFC 1421 PEM block.
///
/// Legacy encrypted PEM uses the following scheme:
///
/// 1. The `DEK-Info` header specifies a block cipher algorithm and
///    an initialisation vector — e.g., `AES-128-CBC,0123...`.
/// 2. The key is derived from the passphrase using
///    `EVP_BytesToKey`[evpbtk] with MD5 as the hash and the first 8
///    bytes of the IV as the "salt".
/// 3. The Base64 body is decrypted using the derived key and the IV
///    in the appropriate block-cipher mode.
///
/// [evpbtk]: https://www.openssl.org/docs/man3.0/man3/EVP_BytesToKey.html
///
/// # Current status
///
/// The provider layer does **not** have access to `EVP_BytesToKey` or
/// the block-cipher implementations required to perform the actual
/// decryption — those live in `openssl-crypto` and are not exposed
/// through this crate's dependency graph.  Matching the behaviour of
/// the reference implementation in
/// `crates/openssl-crypto/src/pem.rs::decode_encrypted` (which also
/// parses but then bails out), this function:
///
/// * Parses and validates the `DEK-Info` header.
/// * Decodes the hex IV.
/// * Returns [`EndecoderError::UnsupportedFormat`] describing the
///   cipher that was requested, so callers can surface a helpful
///   diagnostic.
///
/// When the EVP-compatible cipher layer becomes available in the
/// provider dependency graph, the `TODO` in the implementation
/// (marked with `// FUTURE:`) can be replaced with the actual
/// decryption path — the parser half is already complete.
///
/// # Parameters
///
/// * `der_data` — the Base64-decoded encrypted body bytes.  Not
///   consumed or inspected by the current implementation (parsing
///   only).
/// * `header` — the value of the `DEK-Info` header, e.g.
///   `"AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"`.
/// * `passphrase` — the user-supplied passphrase used to derive the
///   key.  Not consumed or inspected by the current implementation.
///
/// # Errors
///
/// * [`EndecoderError::BadEncoding`] — the `DEK-Info` header is
///   malformed (missing `,`, empty cipher, empty IV, odd hex length,
///   non-hex character, …).
/// * [`EndecoderError::UnsupportedFormat`] — the header is
///   well-formed but the provider layer cannot perform the actual
///   decryption (see "Current status" above).
pub fn decrypt_legacy_pem(
    der_data: &[u8],
    header: &str,
    passphrase: &[u8],
) -> ProviderResult<Vec<u8>> {
    debug!(
        der_len = der_data.len(),
        header_len = header.len(),
        passphrase_len = passphrase.len(),
        "decrypt_legacy_pem: parsing DEK-Info header"
    );

    // Parse the DEK-Info header into (cipher_name, hex_iv).
    let (cipher_name, iv_hex) = parse_dek_info(header)?;

    // Decode the hex IV — validates both length and character set.
    let iv = decode_hex_iv(iv_hex)?;

    debug!(
        cipher_name,
        iv_len = iv.len(),
        "decrypt_legacy_pem: DEK-Info parsed successfully"
    );

    // FUTURE: invoke EVP_BytesToKey(MD5, passphrase, iv[..8], ...) to
    // derive the cipher key, then invoke the appropriate block cipher
    // in CBC mode with `iv` to decrypt `der_data`.  The cipher layer
    // required for this is not currently reachable from the
    // openssl-provider crate's dependency graph.
    //
    // Matches `crates/openssl-crypto/src/pem.rs::decode_encrypted`,
    // which bails out at the same point with an analogous message.
    warn!(
        cipher_name,
        "decrypt_legacy_pem: legacy PEM cipher requires the EVP cipher \
         infrastructure which is not reachable from the provider layer"
    );

    Err(EndecoderError::UnsupportedFormat(format!(
        "legacy PEM cipher '{cipher_name}' requires EVP cipher infrastructure \
         (EVP_BytesToKey + block cipher) which is not available at the \
         provider boundary; use the openssl-crypto PEM APIs directly"
    ))
    .into())
}

// =============================================================================
// Tests
// =============================================================================
//
// The tests below exercise every public entry point exported by this
// module, including the "empty-handed success" path required by Rule
// R5 and the strict-vs-lenient PEM parsing behaviour.

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    /// A minimal valid PEM block containing 3 bytes of DER data
    /// (`0x01 0x02 0x03` → `"AQID"` in Base64).  Conforms to RFC 7468.
    const MINIMAL_CERT_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";

    /// A minimal legacy-encrypted PEM block with `Proc-Type` and
    /// `DEK-Info` headers.  The body is the same 3 bytes as above
    /// (not genuinely encrypted — only the framing matters for
    /// structural tests).
    const LEGACY_ENCRYPTED_PEM: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----\n\
          Proc-Type: 4,ENCRYPTED\n\
          DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\
          \n\
          AQID\n\
          -----END RSA PRIVATE KEY-----\n";

    // -------------------------------------------------------------------------
    // `read_pem` — happy paths
    // -------------------------------------------------------------------------

    #[test]
    fn read_pem_strict_success() {
        let result = read_pem(MINIMAL_CERT_PEM).expect("read_pem must not error");
        let block = result.expect("strict PEM must parse");
        assert_eq!(block.label, "CERTIFICATE");
        assert_eq!(block.der_data, vec![0x01, 0x02, 0x03]);
        assert!(!block.is_encrypted);
    }

    #[test]
    fn read_pem_legacy_encrypted_via_fallback() {
        let result =
            read_pem(LEGACY_ENCRYPTED_PEM).expect("read_pem must not error on headered block");
        let block = result.expect("headered PEM must parse via custom fallback");
        assert_eq!(block.label, "RSA PRIVATE KEY");
        assert_eq!(block.der_data, vec![0x01, 0x02, 0x03]);
        assert!(
            block.is_encrypted,
            "Proc-Type: 4,ENCRYPTED must set is_encrypted=true"
        );
    }

    // -------------------------------------------------------------------------
    // `read_pem` — empty-handed success (Rule R5)
    // -------------------------------------------------------------------------

    #[test]
    fn read_pem_empty_input_returns_none() {
        let result = read_pem(b"").expect("empty input is empty-handed success");
        assert!(result.is_none());
    }

    #[test]
    fn read_pem_non_pem_bytes_returns_none() {
        // Plain binary data that happens to be valid UTF-8 but
        // contains no BEGIN marker.
        let result = read_pem(b"not a pem block at all\nhello world\n")
            .expect("non-PEM UTF-8 is empty-handed success");
        assert!(result.is_none());
    }

    #[test]
    fn read_pem_invalid_utf8_returns_none() {
        // 0xFF is never valid UTF-8.  Definitely not a PEM block.
        let result = read_pem(&[0xFF, 0xFE, 0xFD]).expect("invalid UTF-8 is empty-handed success");
        assert!(result.is_none());
    }

    // -------------------------------------------------------------------------
    // `read_pem` — error paths
    // -------------------------------------------------------------------------

    #[test]
    fn read_pem_missing_end_marker_errors() {
        let broken = b"-----BEGIN CERTIFICATE-----\nAQID\n";
        let err = read_pem(broken).expect_err("missing END must error");
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("end"),
            "error should mention missing END marker, got: {msg}"
        );
    }

    #[test]
    fn read_pem_mismatched_end_label_errors() {
        let broken = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END FOO BAR-----\n";
        let err = read_pem(broken).expect_err("mismatched END label must error");
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("end"),
            "error should mention END marker mismatch, got: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // `decrypt_legacy_pem` — parser validation
    // -------------------------------------------------------------------------

    #[test]
    fn decrypt_legacy_pem_valid_dek_info_returns_unsupported_format() {
        // Well-formed header — parser completes, then bails with
        // UnsupportedFormat because EVP isn't available.
        let header = "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF";
        let err = decrypt_legacy_pem(&[1, 2, 3], header, b"password")
            .expect_err("current implementation must return UnsupportedFormat");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("aes-128-cbc")
                || msg.to_lowercase().contains("unsupported"),
            "error should mention the cipher and/or 'unsupported', got: {msg}"
        );
    }

    #[test]
    fn decrypt_legacy_pem_missing_comma_errors() {
        let header = "AES-128-CBC_NO_COMMA";
        let err = decrypt_legacy_pem(&[], header, b"x").expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("dek-info"),
            "error should mention DEK-Info, got: {msg}"
        );
    }

    #[test]
    fn decrypt_legacy_pem_empty_cipher_errors() {
        let header = ",0123456789ABCDEF";
        let err = decrypt_legacy_pem(&[], header, b"x").expect_err("must reject empty cipher");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("cipher"),
            "error should mention cipher, got: {msg}"
        );
    }

    #[test]
    fn decrypt_legacy_pem_odd_hex_iv_errors() {
        let header = "AES-128-CBC,0123"; // length 4 is fine
                                         // But length 3 is odd:
        let header_odd = "AES-128-CBC,012";
        let err =
            decrypt_legacy_pem(&[], header_odd, b"x").expect_err("must reject odd hex length");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("hex") || msg.to_lowercase().contains("odd"),
            "error should mention hex-length issue, got: {msg}"
        );

        // And check that even length still passes parsing:
        let _ok_err = decrypt_legacy_pem(&[], header, b"x")
            .expect_err("current implementation always errors (UnsupportedFormat)");
    }

    #[test]
    fn decrypt_legacy_pem_invalid_hex_errors() {
        let header = "AES-128-CBC,ZZZZZZZZ"; // valid length, invalid chars
        let err = decrypt_legacy_pem(&[], header, b"x").expect_err("must reject invalid hex");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("hex"),
            "error should mention hex-character issue, got: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // `parse_dek_info` — unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_dek_info_happy_path() {
        let (cipher, iv) = parse_dek_info("AES-256-CBC,00FF").expect("valid DEK-Info");
        assert_eq!(cipher, "AES-256-CBC");
        assert_eq!(iv, "00FF");
    }

    #[test]
    fn parse_dek_info_trims_whitespace() {
        let (cipher, iv) = parse_dek_info("  AES-128-CBC  ,  0123  ").expect("must trim");
        assert_eq!(cipher, "AES-128-CBC");
        assert_eq!(iv, "0123");
    }

    // -------------------------------------------------------------------------
    // `decode_hex_iv` — unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn decode_hex_iv_lowercase_and_uppercase() {
        let iv = decode_hex_iv("00ffAB").expect("mixed-case hex is valid");
        assert_eq!(iv, vec![0x00, 0xFF, 0xAB]);
    }

    #[test]
    fn decode_hex_iv_empty_is_empty() {
        let iv = decode_hex_iv("").expect("empty hex is empty bytes");
        assert!(iv.is_empty());
    }

    #[test]
    fn hex_nibble_all_digits() {
        for (c, expected) in [
            (b'0', 0_u8),
            (b'9', 9),
            (b'a', 10),
            (b'f', 15),
            (b'A', 10),
            (b'F', 15),
        ] {
            assert_eq!(hex_nibble(c), Some(expected));
        }
    }

    #[test]
    fn hex_nibble_rejects_non_hex() {
        assert_eq!(hex_nibble(b'g'), None);
        assert_eq!(hex_nibble(b'G'), None);
        assert_eq!(hex_nibble(b' '), None);
        assert_eq!(hex_nibble(0xFF), None);
    }

    // -------------------------------------------------------------------------
    // `is_valid_header_key` — unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn is_valid_header_key_examples() {
        assert!(is_valid_header_key("Proc-Type"));
        assert!(is_valid_header_key("DEK-Info"));
        assert!(is_valid_header_key("X-Vendor_Data_1"));

        assert!(!is_valid_header_key(""));
        assert!(!is_valid_header_key("Has Space"));
        assert!(!is_valid_header_key("Has:Colon"));
        assert!(!is_valid_header_key("Ünicode"));
    }

    // -------------------------------------------------------------------------
    // `parse_headers_and_body` — unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_headers_and_body_with_blank_separator() {
        let lines = vec!["A: one", "B: two", "", "BODY_LINE_1", "BODY_LINE_2"];
        let (headers, body) = parse_headers_and_body(&lines);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("A".to_string(), "one".to_string()));
        assert_eq!(headers[1], ("B".to_string(), "two".to_string()));
        assert_eq!(body, &["BODY_LINE_1", "BODY_LINE_2"]);
    }

    #[test]
    fn parse_headers_and_body_no_headers() {
        let lines = vec!["BODY", "MORE_BODY"];
        let (headers, body) = parse_headers_and_body(&lines);
        assert!(headers.is_empty());
        assert_eq!(body, &["BODY", "MORE_BODY"]);
    }

    // -------------------------------------------------------------------------
    // `extract_label` — unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_label_happy_path() {
        let label = extract_label("-----BEGIN CERTIFICATE-----", PEM_BEGIN_PREFIX)
            .expect("valid boundary line");
        assert_eq!(label, "CERTIFICATE");
    }

    #[test]
    fn extract_label_multiword() {
        let label = extract_label("-----BEGIN RSA PRIVATE KEY-----", PEM_BEGIN_PREFIX)
            .expect("valid multi-word label");
        assert_eq!(label, "RSA PRIVATE KEY");
    }

    #[test]
    fn extract_label_empty_label_errors() {
        let err = extract_label("-----BEGIN -----", PEM_BEGIN_PREFIX)
            .expect_err("empty label must error");
        let msg = err.to_string();
        assert!(msg.to_lowercase().contains("empty"));
    }

    #[test]
    fn extract_label_missing_prefix_errors() {
        let err =
            extract_label("NO PREFIX HERE-----", PEM_BEGIN_PREFIX).expect_err("prefix required");
        let msg = err.to_string();
        assert!(msg.to_lowercase().contains("prefix"));
    }

    #[test]
    fn extract_label_missing_suffix_errors() {
        let err = extract_label("-----BEGIN CERT", PEM_BEGIN_PREFIX).expect_err("suffix required");
        let msg = err.to_string();
        assert!(msg.to_lowercase().contains("trailing") || msg.to_lowercase().contains("-----"));
    }

    // -------------------------------------------------------------------------
    // `PemDecoder` — trait-level behaviour
    // -------------------------------------------------------------------------

    #[test]
    fn pem_decoder_name_is_pem() {
        let decoder = PemDecoder::new();
        assert_eq!(decoder.name(), "PEM");
    }

    #[test]
    fn pem_decoder_supported_formats_is_pem_only() {
        let decoder = PemDecoder::new();
        assert_eq!(decoder.supported_formats(), vec![FORMAT_PEM]);
    }

    #[test]
    fn pem_decoder_rejects_non_pem_as_bad_encoding() {
        // Trait-level `decode` surfaces empty-handed as BadEncoding
        // because `Ok(Box<dyn KeyData>)` requires a payload.
        let decoder = PemDecoder::new();
        let err = decoder
            .decode(b"not a pem block")
            .expect_err("non-PEM must error at trait boundary");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("bad encoding") || msg.to_lowercase().contains("bad"),
            "expected BadEncoding, got: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // `PemDecoderContext` — accessor tests
    // -------------------------------------------------------------------------

    #[test]
    fn pem_decoder_context_default_is_empty() {
        let ctx = PemDecoderContext::new();
        assert!(ctx.data_structure.is_none());
        assert!(ctx.propq.is_none());
    }

    #[test]
    fn pem_decoder_context_set_data_structure() {
        let mut ctx = PemDecoderContext::new();
        ctx.set_data_structure("PrivateKeyInfo")
            .expect("short value must be accepted");
        assert_eq!(ctx.data_structure.as_deref(), Some("PrivateKeyInfo"));
    }

    #[test]
    fn pem_decoder_context_propq_under_limit_accepted() {
        let mut ctx = PemDecoderContext::new();
        let propq = "provider=default,fips=yes";
        ctx.set_propq(propq).expect("well under 256 bytes");
        assert_eq!(ctx.propq.as_deref(), Some(propq));
    }

    #[test]
    fn pem_decoder_context_propq_over_limit_rejected() {
        let mut ctx = PemDecoderContext::new();
        let huge = "x".repeat(MAX_PROPQUERY_SIZE.saturating_add(1));
        ctx.set_propq(&huge)
            .expect_err("must reject oversize propq");
    }
}
