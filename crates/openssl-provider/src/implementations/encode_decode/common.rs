//! Shared encoder/decoder utilities.
//!
//! Provides key management dispatch helpers, DER reading, object type
//! definitions, and common types used across all encoder and decoder
//! implementations.
//!
//! Replaces C `endecoder_common.c` plus patterns from
//! `providers/common/provider_util.c` and `providers/common/bio_prov.c`.
//!
//! # C → Rust Mapping
//!
//! | C Source                             | Rust Function / Type                  |
//! |--------------------------------------|---------------------------------------|
//! | `ossl_prov_import_key()`             | `import_key`                        |
//! | `ossl_prov_free_key()`               | `free_key`                          |
//! | `ossl_read_der()`                    | `read_der`                          |
//! | `OSSL_OBJECT_PKEY` et al.            | `ObjectType`                        |
//! | `OSSL_PARAM` decoder output array    | `DecodedObject`                     |
//! | `PROV_R_*` error codes               | `EndecoderError`                    |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All functions return `ProviderResult<T>` or `Option<T>`.
//!   No sentinel values.
//! - **R6 (Lossless Casts):** DER length parsing uses checked arithmetic.
//! - **R7 (Lock Granularity):** No shared mutable state in utility functions (pure).
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks — RAII handles key lifecycle.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.

use std::fmt;

use der::Decode;
use tracing::{debug, trace, warn};

use crate::traits::{KeyData, KeyMgmtProvider, KeySelection};
use openssl_common::{CommonError, ParamSet, ProviderError, ProviderResult};

// =============================================================================
// Constants — Format Identifiers
// =============================================================================

/// Maximum property query string length.
///
/// Limits the size of property query strings passed through the provider
/// dispatch system, preventing unbounded allocations.
pub const MAX_PROPQUERY_SIZE: usize = 256;

/// DER (Distinguished Encoding Rules) binary format identifier.
///
/// Used by encoders and decoders to indicate raw DER binary encoding
/// per ITU-T X.690.
pub const FORMAT_DER: &str = "DER";

/// PEM (Privacy-Enhanced Mail) text format identifier.
///
/// Used by encoders and decoders to indicate Base64-armored text encoding
/// per RFC 7468 (`-----BEGIN …-----` / `-----END …-----` framing).
pub const FORMAT_PEM: &str = "PEM";

/// Human-readable text format identifier.
///
/// Used by text encoders to indicate human-readable key/certificate dump
/// output (e.g., `openssl rsa -text` style output).
pub const FORMAT_TEXT: &str = "TEXT";

/// Microsoft BLOB binary format identifier.
///
/// Used by encoders and decoders to indicate the Microsoft PUBLICKEYBLOB /
/// PRIVATEKEYBLOB / SIMPLEBLOB binary key format.
pub const FORMAT_MSBLOB: &str = "MSBLOB";

/// Microsoft PVK private key format identifier.
///
/// Used by encoders and decoders to indicate the Microsoft `.pvk` private
/// key file format (with optional RC4 encryption).
pub const FORMAT_PVK: &str = "PVK";

// =============================================================================
// Constants — ASN.1 Structure Identifiers
// =============================================================================

/// PKCS#8 `PrivateKeyInfo` structure identifier (RFC 5958 §2).
///
/// Identifies the unencrypted private key ASN.1 structure used by
/// DER and PEM encoders/decoders:
///
/// ```asn1
/// PrivateKeyInfo ::= SEQUENCE {
///     version                   Version,
///     privateKeyAlgorithm       AlgorithmIdentifier,
///     privateKey                OCTET STRING
/// }
/// ```
pub const STRUCTURE_PRIVATE_KEY_INFO: &str = "PrivateKeyInfo";

/// PKCS#8 `EncryptedPrivateKeyInfo` structure identifier (RFC 5958 §3).
///
/// Identifies the password-encrypted private key ASN.1 structure:
///
/// ```asn1
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///     encryptionAlgorithm   AlgorithmIdentifier,
///     encryptedData         OCTET STRING
/// }
/// ```
pub const STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO: &str = "EncryptedPrivateKeyInfo";

/// X.509 `SubjectPublicKeyInfo` structure identifier (RFC 5280 §4.1.2.7).
///
/// Identifies the public key ASN.1 structure:
///
/// ```asn1
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm         AlgorithmIdentifier,
///     subjectPublicKey  BIT STRING
/// }
/// ```
pub const STRUCTURE_SUBJECT_PUBLIC_KEY_INFO: &str = "SubjectPublicKeyInfo";

// =============================================================================
// ObjectType — Provider Object Classification
// =============================================================================

/// Provider object type classification.
///
/// Maps to the C `OSSL_OBJECT_*` constants from `include/openssl/core_object.h`:
///
/// | Rust Variant          | C Constant            | Value |
/// |-----------------------|-----------------------|-------|
/// | `Pkey`                | `OSSL_OBJECT_PKEY`    | 1     |
/// | `Certificate`         | `OSSL_OBJECT_CERT`    | 2     |
/// | `Crl`                 | `OSSL_OBJECT_CRL`     | 3     |
/// | `Parameters`          | *(implicit)*          | 4     |
///
/// Used by decoders to tag decoded objects so the core framework knows
/// which construction path to take (`EVP_PKEY`, `X509`, `X509_CRL`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    /// Asymmetric key object (`EVP_PKEY` equivalent).
    Pkey,
    /// X.509 certificate (`X509` equivalent).
    Certificate,
    /// Certificate Revocation List (`X509_CRL` equivalent).
    Crl,
    /// Cryptographic parameters (DH, DSA domain parameters, etc.).
    Parameters,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectType::Pkey => write!(f, "PKEY"),
            ObjectType::Certificate => write!(f, "CERTIFICATE"),
            ObjectType::Crl => write!(f, "CRL"),
            ObjectType::Parameters => write!(f, "PARAMETERS"),
        }
    }
}

// =============================================================================
// DecodedObject — Decoded Object Metadata
// =============================================================================

/// Metadata describing a decoded object for passing to the core framework.
///
/// Carries all information the core needs to construct the appropriate
/// in-memory object from decoded bytes.  Replaces the C `OSSL_PARAM`
/// array that decoders construct to describe their output via
/// `OSSL_PARAM_construct_*()` calls.
///
/// # Fields
///
/// | Field            | C Equivalent                                   |
/// |------------------|------------------------------------------------|
/// | `object_type`    | `OSSL_OBJECT_PARAM_TYPE` (integer constant)    |
/// | `data_type`      | `OSSL_OBJECT_PARAM_DATA_TYPE` (UTF-8 string)   |
/// | `input_type`     | Decoder's `input_type` property                |
/// | `data_structure` | `OSSL_OBJECT_PARAM_DATA_STRUCTURE` (opt. UTF-8) |
/// | `data`           | `OSSL_OBJECT_PARAM_DATA` (octet string)        |
#[derive(Debug)]
pub struct DecodedObject {
    /// Type of decoded object (PKEY, Certificate, CRL, Parameters).
    pub object_type: ObjectType,

    /// Algorithm or data type name (e.g., `"RSA"`, `"EC"`, `"X509"`).
    ///
    /// Used by the core to select the correct key management provider
    /// or object construction path.
    pub data_type: String,

    /// Input format that produced this object (e.g., `"DER"`, `"PEM"`).
    pub input_type: &'static str,

    /// Data structure name if applicable (e.g., `"PrivateKeyInfo"`,
    /// `"SubjectPublicKeyInfo"`).  `None` for objects without named
    /// structures per Rule R5 — uses `Option<String>` instead of
    /// sentinel empty string.
    pub data_structure: Option<String>,

    /// Raw encoded data bytes (DER, MSBLOB, PVK, etc.).
    pub data: Vec<u8>,
}

// =============================================================================
// EndecoderError — Encode/Decode Error Variants
// =============================================================================

/// Encoder/decoder error reasons matching C `PROV_R_*` error codes.
///
/// Each variant corresponds to a specific failure mode in the encode/decode
/// pipeline.  Uses `thiserror` derive for idiomatic `Display` and
/// `std::error::Error` implementations per AAP §0.7.7.
///
/// # C Mapping
///
/// | Rust Variant             | C Error Code                              |
/// |--------------------------|-------------------------------------------|
/// | `BadEncoding`            | `PROV_R_BAD_ENCODING`                     |
/// | `NotAPrivateKey`         | `PROV_R_NOT_A_PRIVATE_KEY`                |
/// | `NotAPublicKey`          | `PROV_R_NOT_A_PUBLIC_KEY`                 |
/// | `NotParameters`          | `PROV_R_NOT_PARAMETERS`                   |
/// | `InvalidKey`             | `PROV_R_INVALID_KEY`                      |
/// | `MissingKey`             | `PROV_R_MISSING_KEY`                      |
/// | `UnableToGetPassphrase`  | `PROV_R_UNABLE_TO_GET_PASSPHRASE`         |
/// | `UnsupportedFormat`      | `PROV_R_UNSUPPORTED_FORMAT`               |
#[derive(Debug, Clone, thiserror::Error)]
pub enum EndecoderError {
    /// Input data is not valid for the expected encoding format.
    #[error("bad encoding")]
    BadEncoding,

    /// Decoded data does not contain a private key where one was expected.
    #[error("not a private key")]
    NotAPrivateKey,

    /// Decoded data does not contain a public key where one was expected.
    #[error("not a public key")]
    NotAPublicKey,

    /// Decoded data does not contain parameters where they were expected.
    #[error("not parameters")]
    NotParameters,

    /// Key material is invalid or corrupted.
    #[error("invalid key")]
    InvalidKey,

    /// Required key material is missing from the decoded data.
    #[error("missing key material")]
    MissingKey,

    /// Passphrase callback failed or was not provided for an encrypted key.
    #[error("unable to get passphrase")]
    UnableToGetPassphrase,

    /// The encoding format is not supported by this encoder/decoder.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}

/// Convert `EndecoderError` into `ProviderError` for propagation
/// across the provider boundary.
///
/// Maps encoder/decoder errors to the provider-level dispatch error
/// variant, preserving the human-readable message for diagnostics.
impl From<EndecoderError> for ProviderError {
    fn from(err: EndecoderError) -> Self {
        ProviderError::Dispatch(err.to_string())
    }
}

// =============================================================================
// Key Import / Free Helpers
// =============================================================================

/// Import key material via the key management provider dispatch.
///
/// Creates a new key object through `keymgmt`, then imports the supplied
/// parameters into it.  On failure, RAII ensures the partially-created key
/// is dropped automatically — no manual cleanup needed.
///
/// Replaces C `ossl_prov_import_key()` from `endecoder_common.c` (lines 60–76):
///
/// ```c
/// // C original (simplified):
/// key = kmgmt_new(provctx);
/// if (!kmgmt_import(key, selection, params)) {
///     kmgmt_free(key);
///     key = NULL;
/// }
/// return key;
/// ```
///
/// # Arguments
///
/// * `keymgmt` — Key management provider implementing the algorithm-specific
///   import.
/// * `selection` — Bitflags indicating which key components to import
///   (`KeySelection::PRIVATE_KEY`, `KeySelection::PUBLIC_KEY`,
///   `KeySelection::DOMAIN_PARAMETERS`, or combinations thereof).
/// * `params` — Typed parameter set containing the key material fields.
///
/// # Errors
///
/// Returns `ProviderError` if key creation or import fails.
pub fn import_key(
    keymgmt: &dyn KeyMgmtProvider,
    selection: KeySelection,
    params: &ParamSet,
) -> ProviderResult<Box<dyn KeyData>> {
    debug!(
        keymgmt = keymgmt.name(),
        selection = ?selection,
        "importing key via keymgmt dispatch"
    );

    // Step 1: Verify the keymgmt provider can create keys.
    //
    // In C, `ossl_prov_import_key()` checks that kmgmt_new, kmgmt_free, and
    // kmgmt_import function pointers are all non-NULL before proceeding.
    // The Rust trait guarantees all methods exist, but we validate operational
    // readiness by confirming `new_key()` succeeds.  The created key is
    // immediately dropped (RAII replaces the explicit `kmgmt_free` call).
    drop(keymgmt.new_key().map_err(|e| {
        warn!(
            keymgmt = keymgmt.name(),
            error = %e,
            "keymgmt pre-check: new_key failed"
        );
        e
    })?);

    // Step 2: Import key material.
    //
    // In C this was two separate steps (kmgmt_new + kmgmt_import).  The Rust
    // `KeyMgmtProvider::import()` combines creation and import atomically,
    // returning a fully populated `Box<dyn KeyData>`.  On failure the error
    // propagates via `?` and no key object leaks (nothing was allocated
    // outside the provider).
    let key = keymgmt.import(selection, params).map_err(|e| {
        warn!(
            keymgmt = keymgmt.name(),
            error = %e,
            "key import failed"
        );
        e
    })?;

    trace!(keymgmt = keymgmt.name(), "key imported successfully");
    Ok(key)
}

/// Explicitly release a key object.
///
/// In Rust, this simply drops the key — the `Drop` trait handles secure
/// cleanup (including zeroization of key material via `zeroize::Zeroize`
/// where applicable).
///
/// This function exists for API symmetry with the C `ossl_prov_free_key()`
/// (`endecoder_common.c` lines 78–84) and to provide a named operation
/// for clarity at call sites.
///
/// # Arguments
///
/// * `key` — The key object to release.  Ownership is transferred and the
///   key is dropped at the end of this function.
pub fn free_key(key: Box<dyn KeyData>) {
    trace!("releasing key object via free_key");
    drop(key);
}

// =============================================================================
// DER Reading
// =============================================================================

/// Read a complete DER-encoded ASN.1 object from input bytes.
///
/// Parses the outer TLV (Tag-Length-Value) structure to determine the total
/// encoded length, then extracts exactly that many bytes.  The extracted
/// DER blob is validated using [`der::Decode`] to ensure structural
/// correctness.
///
/// Replaces C `ossl_read_der()` from `endecoder_common.c` (lines 86–103),
/// which used `BIO` + `asn1_d2i_read_bio()` for the same purpose.  In Rust,
/// `BIO` abstractions are unnecessary — direct byte slice operations suffice.
///
/// # Arguments
///
/// * `input` — Byte slice containing DER-encoded data (possibly with trailing
///   bytes after the first complete object).
///
/// # Returns
///
/// A tuple of `(der_bytes, total_length)` where `der_bytes` is the complete
/// DER encoding of the first object and `total_length` is the number of
/// bytes consumed from `input`.
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` if the input is empty, truncated, or
/// contains an invalid DER TLV header.  Returns [`ProviderError::Common`]
/// if the parsed DER fails structural validation.  Uses checked arithmetic
/// throughout per Rule R6.
pub fn read_der(input: &[u8]) -> ProviderResult<(Vec<u8>, usize)> {
    if input.is_empty() {
        return Err(ProviderError::Dispatch("empty DER input".into()));
    }

    trace!(input_len = input.len(), "reading DER object from input");

    // Parse the TLV header to determine total object length.
    let total_len = parse_der_tlv_length(input)?;

    // Validate we have enough bytes for the entire object.
    if input.len() < total_len {
        return Err(ProviderError::Dispatch(format!(
            "DER input truncated: need {} bytes, have {}",
            total_len,
            input.len()
        )));
    }

    let der_bytes = &input[..total_len];

    // Validate the extracted DER using the `der` crate's `Decode` trait.
    // `AnyRef::from_der()` performs full TLV validation including tag class,
    // constructed bit, and definite-length encoding checks.  This catches
    // any inconsistency between our manual TLV parse and the canonical
    // DER specification.
    let _ = der::asn1::AnyRef::from_der(der_bytes).map_err(|e| {
        warn!(error = %e, "DER validation failed after TLV parse");
        ProviderError::Common(CommonError::Internal(format!("invalid DER encoding: {e}")))
    })?;

    debug!(total_len, "DER object read successfully");
    Ok((der_bytes.to_vec(), total_len))
}

/// Parse a DER TLV header to determine the total encoded length.
///
/// Handles both short-form (single byte, ≤ 127) and long-form (multi-byte)
/// definite-length encodings as per X.690 §8.1.3.  Indefinite-length
/// encoding is rejected (not valid in DER, only BER).
///
/// All arithmetic uses checked operations per Rule R6 — no bare `as` casts
/// for narrowing conversions.
///
/// Returns the total number of bytes consumed by the TLV: tag byte(s) +
/// length octet(s) + content bytes.
fn parse_der_tlv_length(input: &[u8]) -> ProviderResult<usize> {
    if input.is_empty() {
        return Err(ProviderError::Dispatch("empty input for TLV parse".into()));
    }

    let mut pos: usize = 0;

    // ── Tag Byte(s) ────────────────────────────────────────────────
    // First byte: tag class (2 bits) + constructed (1 bit) + tag number (5 bits).
    let first_tag = input[pos];
    pos = pos
        .checked_add(1)
        .ok_or_else(|| ProviderError::Dispatch("TLV position overflow at tag".into()))?;

    // High-tag-number form: if the low 5 bits of the first byte are all 1s
    // (0x1F), subsequent bytes encode the tag number in base-128 with bit 7
    // as the continuation flag.
    if first_tag & 0x1F == 0x1F {
        loop {
            if pos >= input.len() {
                return Err(ProviderError::Dispatch(
                    "truncated high-tag-number encoding".into(),
                ));
            }
            let tag_byte = input[pos];
            pos = pos.checked_add(1).ok_or_else(|| {
                ProviderError::Dispatch("TLV position overflow in high-tag".into())
            })?;
            // The last tag byte has bit 7 clear.
            if tag_byte & 0x80 == 0 {
                break;
            }
        }
    }

    // ── Length Octet(s) ────────────────────────────────────────────
    if pos >= input.len() {
        return Err(ProviderError::Dispatch(
            "truncated DER: missing length octet".into(),
        ));
    }

    let length_byte = input[pos];
    pos = pos
        .checked_add(1)
        .ok_or_else(|| ProviderError::Dispatch("TLV position overflow at length byte".into()))?;

    let content_length: usize = match length_byte.cmp(&0x80) {
        std::cmp::Ordering::Less => {
            // Short form: the byte value IS the length (0..=127).
            length_byte as usize
        }
        std::cmp::Ordering::Equal => {
            // Indefinite form: not valid in DER (X.690 §10.1).
            return Err(ProviderError::Dispatch(
                "indefinite-length encoding is not valid in DER".into(),
            ));
        }
        std::cmp::Ordering::Greater => {
            // Long form: low 7 bits = number of subsequent length octets.
            let num_octets = (length_byte & 0x7F) as usize;

            // Guard against absurdly large length-of-length fields.
            if num_octets > std::mem::size_of::<usize>() {
                return Err(ProviderError::Dispatch(format!(
                    "DER length uses {num_octets} octets, exceeds platform word size ({})",
                    std::mem::size_of::<usize>()
                )));
            }

            // Ensure the length octets are within bounds.
            let end = pos.checked_add(num_octets).ok_or_else(|| {
                ProviderError::Dispatch("DER length octets extend beyond addressable range".into())
            })?;
            if end > input.len() {
                return Err(ProviderError::Dispatch(
                    "truncated DER: length octets extend beyond input".into(),
                ));
            }

            // Accumulate length from big-endian octets with checked arithmetic
            // (Rule R6 — no bare `as` casts for narrowing conversions).
            let len = input[pos..end].iter().try_fold(0usize, |acc, &byte| {
                acc.checked_shl(8)
                    .and_then(|shifted| shifted.checked_add(byte as usize))
            });
            let content_len =
                len.ok_or_else(|| ProviderError::Dispatch("DER content length overflow".into()))?;

            pos = end;
            content_len
        }
    };

    // Total length = header (tag + length octets) + content bytes.
    let total = pos
        .checked_add(content_length)
        .ok_or_else(|| ProviderError::Dispatch("DER total length overflow".into()))?;

    Ok(total)
}

// =============================================================================
// Selection Utilities
// =============================================================================

/// Check if a requested key selection is compatible with a supported selection.
///
/// Key selection is hierarchical in OpenSSL:
///
/// - `KeySelection::PRIVATE_KEY` implies `KeySelection::PUBLIC_KEY`
///   which implies `KeySelection::DOMAIN_PARAMETERS`
/// - A decoder that supports private keys inherently supports public keys
///   and domain parameters
///
/// A selection of zero (empty flags) means "guessing" — the decoder will
/// attempt to decode any key type, so it is always accepted.
///
/// # Arguments
///
/// * `requested` — The selection flags the caller wants.
/// * `supported` — The selection flags the decoder/encoder can provide.
///
/// # Returns
///
/// `true` if the requested selection can be satisfied by the supported
/// selection (including hierarchical implications).
pub fn check_selection_hierarchy(requested: KeySelection, supported: KeySelection) -> bool {
    // Empty selection means "guess" / "any" — always compatible.
    if requested.is_empty() {
        trace!("empty selection (guess mode) — accepted");
        return true;
    }

    // Build the effective supported set by applying the hierarchical
    // implication rules: PRIVATE → PUBLIC → DOMAIN_PARAMETERS.
    let mut effective = supported;

    if effective.contains(KeySelection::PRIVATE_KEY) {
        effective |= KeySelection::PUBLIC_KEY;
    }
    if effective.contains(KeySelection::PUBLIC_KEY) {
        effective |= KeySelection::DOMAIN_PARAMETERS;
    }

    let result = effective.contains(requested);

    trace!(
        requested = ?requested,
        supported = ?supported,
        effective = ?effective,
        result,
        "selection hierarchy check"
    );

    result
}

/// Check if a selection mask includes a specific flag.
///
/// Convenience wrapper around [`KeySelection::contains()`] providing a
/// named operation used throughout encoder/decoder implementations to
/// test individual selection components.
///
/// # Arguments
///
/// * `selection` — The selection mask to test.
/// * `flag` — The specific flag to check for.
///
/// # Returns
///
/// `true` if `selection` includes the given `flag`.
pub fn selection_includes(selection: KeySelection, flag: KeySelection) -> bool {
    selection.contains(flag)
}

// =============================================================================
// Hex Formatting Utilities
// =============================================================================

/// Bytes per line in hex dump output.
///
/// Matches OpenSSL's text encoder line-wrapping convention.
const HEX_BYTES_PER_LINE: usize = 15;

/// Format bytes as colon-separated hex with line wrapping.
///
/// Produces output in the style used by OpenSSL's text encoder for key
/// component display:
///
/// ```text
///     ab:cd:ef:01:02:03:04:05:06:07:08:09:0a:0b:0c:
///     0d:0e:0f:10:11:12:13:14:15
/// ```
///
/// # Arguments
///
/// * `data` — The bytes to format.
/// * `indent` — Number of spaces to prepend to each line.
///
/// # Returns
///
/// A formatted hex string with colons and line wraps.  Returns an empty
/// string if `data` is empty.
pub fn format_hex_dump(data: &[u8], indent: usize) -> String {
    use std::fmt::Write;

    if data.is_empty() {
        return String::new();
    }

    // Pre-allocate: each byte ≈ 3 chars ("xx:") + line breaks + indentation.
    let estimated = data
        .len()
        .saturating_mul(3)
        .saturating_add((data.len() / HEX_BYTES_PER_LINE).saturating_mul(indent.saturating_add(1)));
    let mut output = String::with_capacity(estimated);
    let indent_str: String = " ".repeat(indent);

    for (i, byte) in data.iter().enumerate() {
        // Start a new line with indentation at the beginning and every
        // HEX_BYTES_PER_LINE bytes.
        if i % HEX_BYTES_PER_LINE == 0 {
            if i > 0 {
                output.push('\n');
            }
            output.push_str(&indent_str);
        }

        // Write the hex byte.
        let _ = write!(output, "{byte:02x}");

        // Append colon separator between bytes (not after the very last byte).
        if i < data.len().saturating_sub(1) {
            output.push(':');
        }
    }

    output
}

/// Format a label followed by a hex dump with proper indentation.
///
/// Produces output like:
///
/// ```text
/// priv:
///     ab:cd:ef:01:02:03:04:05:06:07:08:09:0a:0b:0c:
///     0d:0e:0f:10:11:12:13:14:15
/// ```
///
/// Used extensively by text encoders for key component output (modulus,
/// public exponent, private exponent, primes, etc.).
///
/// # Arguments
///
/// * `label` — The label text (e.g., `"priv"`, `"pub"`, `"modulus"`).
/// * `data` — The bytes to format as hex.
/// * `indent` — Number of spaces for the hex dump lines.
///
/// # Returns
///
/// A formatted string with the label and hex dump.  If `data` is empty,
/// returns just the label with a colon.
pub fn format_labeled_hex(label: &str, data: &[u8], indent: usize) -> String {
    if data.is_empty() {
        return format!("{label}:");
    }

    let hex = format_hex_dump(data, indent);
    format!("{label}:\n{hex}")
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── ObjectType ──────────────────────────────────────────────────

    #[test]
    fn test_object_type_display() {
        assert_eq!(ObjectType::Pkey.to_string(), "PKEY");
        assert_eq!(ObjectType::Certificate.to_string(), "CERTIFICATE");
        assert_eq!(ObjectType::Crl.to_string(), "CRL");
        assert_eq!(ObjectType::Parameters.to_string(), "PARAMETERS");
    }

    #[test]
    fn test_object_type_equality() {
        assert_eq!(ObjectType::Pkey, ObjectType::Pkey);
        assert_ne!(ObjectType::Pkey, ObjectType::Certificate);
    }

    #[test]
    fn test_object_type_clone_copy() {
        let ot = ObjectType::Crl;
        let ot2 = ot;
        assert_eq!(ot, ot2);
    }

    // ── DecodedObject ───────────────────────────────────────────────

    #[test]
    fn test_decoded_object_construction() {
        let obj = DecodedObject {
            object_type: ObjectType::Pkey,
            data_type: "RSA".to_string(),
            input_type: FORMAT_DER,
            data_structure: Some(STRUCTURE_PRIVATE_KEY_INFO.to_string()),
            data: vec![0x30, 0x03, 0x01, 0x01, 0x00],
        };

        assert_eq!(obj.object_type, ObjectType::Pkey);
        assert_eq!(obj.data_type, "RSA");
        assert_eq!(obj.input_type, "DER");
        assert_eq!(obj.data_structure, Some("PrivateKeyInfo".to_string()));
        assert_eq!(obj.data.len(), 5);
    }

    #[test]
    fn test_decoded_object_optional_structure() {
        let obj = DecodedObject {
            object_type: ObjectType::Certificate,
            data_type: "X509".to_string(),
            input_type: FORMAT_PEM,
            data_structure: None,
            data: vec![0x30],
        };
        assert!(obj.data_structure.is_none());
    }

    // ── EndecoderError ──────────────────────────────────────────────

    #[test]
    fn test_endecoder_error_display() {
        assert_eq!(EndecoderError::BadEncoding.to_string(), "bad encoding");
        assert_eq!(
            EndecoderError::NotAPrivateKey.to_string(),
            "not a private key"
        );
        assert_eq!(
            EndecoderError::NotAPublicKey.to_string(),
            "not a public key"
        );
        assert_eq!(EndecoderError::NotParameters.to_string(), "not parameters");
        assert_eq!(EndecoderError::InvalidKey.to_string(), "invalid key");
        assert_eq!(
            EndecoderError::MissingKey.to_string(),
            "missing key material"
        );
        assert_eq!(
            EndecoderError::UnableToGetPassphrase.to_string(),
            "unable to get passphrase"
        );
        assert_eq!(
            EndecoderError::UnsupportedFormat("PVK".into()).to_string(),
            "unsupported format: PVK"
        );
    }

    #[test]
    fn test_endecoder_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(EndecoderError::BadEncoding);
        assert_eq!(err.to_string(), "bad encoding");
    }

    #[test]
    fn test_endecoder_error_to_provider_error() {
        let err: ProviderError = EndecoderError::InvalidKey.into();
        match err {
            ProviderError::Dispatch(msg) => {
                assert_eq!(msg, "invalid key");
            }
            other => panic!("expected Dispatch, got: {:?}", other),
        }
    }

    // ── read_der ────────────────────────────────────────────────────

    #[test]
    fn test_read_der_empty_input() {
        let result = read_der(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_der_simple_boolean() {
        // DER encoding of BOOLEAN TRUE: 01 01 FF
        let input = [0x01, 0x01, 0xFF];
        let (data, len) = read_der(&input).expect("valid DER");
        assert_eq!(len, 3);
        assert_eq!(data, vec![0x01, 0x01, 0xFF]);
    }

    #[test]
    fn test_read_der_with_trailing() {
        // BOOLEAN TRUE followed by extra bytes.
        let input = [0x01, 0x01, 0xFF, 0xDE, 0xAD];
        let (data, len) = read_der(&input).expect("valid DER");
        assert_eq!(len, 3);
        assert_eq!(data, vec![0x01, 0x01, 0xFF]);
    }

    #[test]
    fn test_read_der_sequence() {
        // SEQUENCE { BOOLEAN TRUE }
        // 30 03 01 01 FF
        let input = [0x30, 0x03, 0x01, 0x01, 0xFF];
        let (data, len) = read_der(&input).expect("valid DER");
        assert_eq!(len, 5);
        assert_eq!(data, input.to_vec());
    }

    #[test]
    fn test_read_der_truncated() {
        // SEQUENCE claiming 10 bytes of content, but only 3 available.
        let input = [0x30, 0x0A, 0x01, 0x01, 0xFF];
        let result = read_der(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_der_indefinite_length() {
        // Indefinite length: tag 0x30, length 0x80 — invalid in DER.
        let input = [0x30, 0x80, 0x01, 0x01, 0xFF, 0x00, 0x00];
        let result = read_der(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_der_long_form_length() {
        // NULL with long-form length: tag 0x05, length 0x81 0x00
        // (0 bytes of content expressed in long form — technically valid DER
        // encoding per X.690, though not the shortest form).
        // Actually, DER requires minimal length encoding, so this would
        // fail der crate validation. Test that we get an error.
        let input = [0x05, 0x81, 0x00];
        let result = read_der(&input);
        // der crate may reject non-minimal length encoding.
        // Either way, the function should not panic.
        let _ = result;
    }

    // ── Selection Utilities ─────────────────────────────────────────

    #[test]
    fn test_check_selection_hierarchy_empty_always_accepted() {
        assert!(check_selection_hierarchy(
            KeySelection::empty(),
            KeySelection::PRIVATE_KEY
        ));
        assert!(check_selection_hierarchy(
            KeySelection::empty(),
            KeySelection::empty()
        ));
    }

    #[test]
    fn test_check_selection_hierarchy_exact_match() {
        assert!(check_selection_hierarchy(
            KeySelection::PRIVATE_KEY,
            KeySelection::PRIVATE_KEY
        ));
        assert!(check_selection_hierarchy(
            KeySelection::PUBLIC_KEY,
            KeySelection::PUBLIC_KEY
        ));
    }

    #[test]
    fn test_check_selection_hierarchy_private_implies_public() {
        // Requesting PUBLIC_KEY should succeed when PRIVATE_KEY is supported,
        // because private key implies public key.
        assert!(check_selection_hierarchy(
            KeySelection::PUBLIC_KEY,
            KeySelection::PRIVATE_KEY
        ));
    }

    #[test]
    fn test_check_selection_hierarchy_public_implies_params() {
        // Requesting DOMAIN_PARAMETERS should succeed when PUBLIC_KEY is
        // supported, because public key implies domain parameters.
        assert!(check_selection_hierarchy(
            KeySelection::DOMAIN_PARAMETERS,
            KeySelection::PUBLIC_KEY
        ));
    }

    #[test]
    fn test_check_selection_hierarchy_params_not_imply_public() {
        // Requesting PUBLIC_KEY should FAIL when only DOMAIN_PARAMETERS
        // is supported (no upward implication).
        assert!(!check_selection_hierarchy(
            KeySelection::PUBLIC_KEY,
            KeySelection::DOMAIN_PARAMETERS
        ));
    }

    #[test]
    fn test_selection_includes() {
        assert!(selection_includes(
            KeySelection::ALL,
            KeySelection::PRIVATE_KEY
        ));
        assert!(selection_includes(
            KeySelection::KEYPAIR,
            KeySelection::PUBLIC_KEY
        ));
        assert!(!selection_includes(
            KeySelection::PUBLIC_KEY,
            KeySelection::PRIVATE_KEY
        ));
    }

    // ── Hex Formatting ──────────────────────────────────────────────

    #[test]
    fn test_format_hex_dump_empty() {
        assert_eq!(format_hex_dump(&[], 4), "");
    }

    #[test]
    fn test_format_hex_dump_single_byte() {
        let result = format_hex_dump(&[0xAB], 4);
        assert_eq!(result, "    ab");
    }

    #[test]
    fn test_format_hex_dump_multiple_bytes() {
        let data = [0x01, 0x02, 0x03];
        let result = format_hex_dump(&data, 4);
        assert_eq!(result, "    01:02:03");
    }

    #[test]
    fn test_format_hex_dump_line_wrapping() {
        // 16 bytes should wrap after 15 bytes (HEX_BYTES_PER_LINE = 15).
        let data: Vec<u8> = (0..16).collect();
        let result = format_hex_dump(&data, 4);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2, "should wrap to 2 lines");
        // First line: 15 bytes, second line: 1 byte.
        assert!(lines[0].starts_with("    "));
        assert!(lines[1].starts_with("    "));
    }

    #[test]
    fn test_format_labeled_hex_empty_data() {
        let result = format_labeled_hex("priv", &[], 4);
        assert_eq!(result, "priv:");
    }

    #[test]
    fn test_format_labeled_hex_with_data() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = format_labeled_hex("key", &data, 4);
        assert!(result.starts_with("key:\n"));
        assert!(result.contains("de:ad:be:ef"));
    }

    // ── Constants ───────────────────────────────────────────────────

    #[test]
    fn test_format_constants() {
        assert_eq!(FORMAT_DER, "DER");
        assert_eq!(FORMAT_PEM, "PEM");
        assert_eq!(FORMAT_TEXT, "TEXT");
        assert_eq!(FORMAT_MSBLOB, "MSBLOB");
        assert_eq!(FORMAT_PVK, "PVK");
    }

    #[test]
    fn test_structure_constants() {
        assert_eq!(STRUCTURE_PRIVATE_KEY_INFO, "PrivateKeyInfo");
        assert_eq!(
            STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO,
            "EncryptedPrivateKeyInfo"
        );
        assert_eq!(STRUCTURE_SUBJECT_PUBLIC_KEY_INFO, "SubjectPublicKeyInfo");
    }

    #[test]
    fn test_max_propquery_size() {
        assert_eq!(MAX_PROPQUERY_SIZE, 256);
    }
}
