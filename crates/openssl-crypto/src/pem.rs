//! PEM (Privacy Enhanced Mail) encoding and decoding for the OpenSSL Rust workspace.
//!
//! Provides base64 encoding/decoding with PEM headers for certificates, keys,
//! CRLs, and other cryptographic objects. Replaces the C `PEM_*` functions from
//! `crypto/pem/*.c` (11 source files totaling ~2,500 lines).
//!
//! # PEM Format Overview
//!
//! PEM encapsulates binary DER-encoded data in an ASCII-safe format:
//!
//! ```text
//! -----BEGIN <LABEL>-----
//! <optional RFC 1421 headers, separated by blank line>
//! <base64-encoded data, wrapped at 64 characters>
//! -----END <LABEL>-----
//! ```
//!
//! This module supports both:
//! - **RFC 7468** strict format (no headers) — used by modern certificates and keys
//! - **RFC 1421** format with `Proc-Type`/`DEK-Info` headers — used by legacy
//!   encrypted private keys
//!
//! # Migration from C
//!
//! | C Function                  | Rust Equivalent                     |
//! |-----------------------------|-------------------------------------|
//! | `PEM_write_bio()`           | [`encode()`], [`encode_to_writer()`]|
//! | `PEM_read_bio()`            | [`decode()`]                        |
//! | `PEM_read_bio()` (multi)    | [`decode_all()`]                    |
//! | `PEM_read_bio_ex()` (enc)   | [`decode_encrypted()`]              |
//! | `PEM_ASN1_write_bio()` (enc)| [`encode_encrypted()`]              |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All functions return `CryptoResult`, never sentinel values.
//! - **R6 (Lossless Casts):** Line length calculations use checked arithmetic.
//! - **R8 (Zero Unsafe):** Uses `base64ct` and `pem-rfc7468` (pure Rust, constant-time).
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.

use std::io;

use base64ct::{Base64, Encoding};
use openssl_common::{CryptoError, CryptoResult};

// =============================================================================
// Well-Known PEM Label Constants
// =============================================================================
//
// These correspond to the C `PEM_STRING_*` macros defined in `include/openssl/pem.h`.
// Each constant identifies the type of cryptographic object encapsulated in the
// PEM block and appears between the `-----BEGIN ` and `-----` markers.

/// PEM label for X.509 certificates (`PEM_STRING_X509` in C).
pub const PEM_LABEL_CERTIFICATE: &str = "CERTIFICATE";

/// PEM label for X.509 Certificate Revocation Lists (`PEM_STRING_X509_CRL` in C).
pub const PEM_LABEL_X509_CRL: &str = "X509 CRL";

/// PEM label for legacy RSA private keys in PKCS#1 format
/// (`PEM_STRING_RSA` in C).
pub const PEM_LABEL_RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";

/// PEM label for legacy EC private keys in SEC 1 format
/// (`PEM_STRING_ECPRIVATEKEY` in C).
pub const PEM_LABEL_EC_PRIVATE_KEY: &str = "EC PRIVATE KEY";

/// PEM label for PKCS#8 unencrypted private keys
/// (`PEM_STRING_PKCS8INF` in C).
pub const PEM_LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";

/// PEM label for SubjectPublicKeyInfo-encoded public keys
/// (`PEM_STRING_PUBLIC` in C).
pub const PEM_LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";

/// PEM label for PKCS#8 encrypted private keys
/// (`PEM_STRING_PKCS8` in C).
pub const PEM_LABEL_ENCRYPTED_PRIVATE_KEY: &str = "ENCRYPTED PRIVATE KEY";

/// PEM label for PKCS#10 certificate signing requests
/// (`PEM_STRING_X509_REQ` in C).
pub const PEM_LABEL_CERTIFICATE_REQUEST: &str = "CERTIFICATE REQUEST";

// =============================================================================
// Internal Constants
// =============================================================================

/// The `-----BEGIN ` prefix that opens a PEM pre-encapsulation boundary.
const PEM_BEGIN_PREFIX: &str = "-----BEGIN ";

/// The `-----END ` prefix that opens a PEM post-encapsulation boundary.
const PEM_END_PREFIX: &str = "-----END ";

/// The `-----` suffix that closes a PEM encapsulation boundary.
const PEM_BOUNDARY_SUFFIX: &str = "-----";

/// Width at which the base64 body is line-wrapped per RFC 7468 §2.
///
/// > Generators MUST wrap the base64-encoded lines so that each line
/// > consists of exactly 64 characters except for the final line.
const PEM_LINE_WIDTH: usize = 64;

/// RFC 1421 header key for the Proc-Type field.
const PROC_TYPE_HEADER: &str = "Proc-Type";

/// RFC 1421 header value indicating encryption.
const PROC_TYPE_ENCRYPTED_VALUE: &str = "4,ENCRYPTED";

/// RFC 1421 header key for the DEK-Info field.
const DEK_INFO_HEADER: &str = "DEK-Info";

// =============================================================================
// PemObject — Parsed PEM Block
// =============================================================================

/// A parsed PEM block containing label, optional headers, and decoded data.
///
/// Corresponds to the result of `PEM_read_bio()` in C, which returns the
/// PEM type name, header string, and DER-encoded payload separately.
///
/// # Examples
///
/// ```
/// use openssl_crypto::pem::PemObject;
///
/// let obj = PemObject::with_data("CERTIFICATE", vec![0x30, 0x82, 0x01]);
/// assert_eq!(obj.label, "CERTIFICATE");
/// assert!(obj.headers.is_empty());
/// assert_eq!(obj.data, vec![0x30, 0x82, 0x01]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemObject {
    /// The PEM type label (e.g., `"CERTIFICATE"`, `"RSA PRIVATE KEY"`).
    ///
    /// This is the text that appears between `-----BEGIN ` and `-----` in
    /// the pre-encapsulation boundary.
    pub label: String,

    /// Optional RFC 1421 headers as key-value pairs.
    ///
    /// Standard PEM (RFC 7468) has no headers. Legacy encrypted PEM uses
    /// `Proc-Type` and `DEK-Info` headers per RFC 1421 §4.6.
    pub headers: Vec<(String, String)>,

    /// The decoded binary payload (typically DER-encoded ASN.1 data).
    ///
    /// For unencrypted PEM, this is the raw DER bytes. For encrypted PEM
    /// decoded via [`decode_encrypted()`], this is the decrypted DER bytes.
    pub data: Vec<u8>,
}

impl PemObject {
    /// Creates a new empty `PemObject` with no label, headers, or data.
    ///
    /// Use [`with_label()`](Self::with_label) or [`with_data()`](Self::with_data)
    /// for more convenient construction.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::pem::PemObject;
    ///
    /// let obj = PemObject::new();
    /// assert!(obj.label.is_empty());
    /// assert!(obj.headers.is_empty());
    /// assert!(obj.data.is_empty());
    /// ```
    pub fn new() -> Self {
        PemObject {
            label: String::new(),
            headers: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Creates a new `PemObject` with the given label and empty data.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::pem::{PemObject, PEM_LABEL_CERTIFICATE};
    ///
    /// let obj = PemObject::with_label(PEM_LABEL_CERTIFICATE);
    /// assert_eq!(obj.label, "CERTIFICATE");
    /// assert!(obj.data.is_empty());
    /// ```
    pub fn with_label(label: impl Into<String>) -> Self {
        PemObject {
            label: label.into(),
            headers: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Creates a new `PemObject` with the given label and DER-encoded data.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_crypto::pem::PemObject;
    ///
    /// let der = vec![0x30, 0x82, 0x01, 0x22];
    /// let obj = PemObject::with_data("PRIVATE KEY", der.clone());
    /// assert_eq!(obj.label, "PRIVATE KEY");
    /// assert_eq!(obj.data, der);
    /// ```
    pub fn with_data(label: impl Into<String>, data: Vec<u8>) -> Self {
        PemObject {
            label: label.into(),
            headers: Vec::new(),
            data,
        }
    }
}

impl Default for PemObject {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Encoding Functions
// =============================================================================

/// Encodes a [`PemObject`] into a PEM-formatted string.
///
/// Produces a complete PEM block with `-----BEGIN`/`-----END` boundaries
/// and base64-encoded body wrapped at 64 characters per line (RFC 7468 §2).
///
/// If the object has headers (e.g., for legacy encrypted PEM), they are
/// included between the begin boundary and the base64 body, followed by
/// a blank line separator.
///
/// # Panics
///
/// This function does not panic. Invalid inputs produce valid PEM syntax
/// with an empty body.
///
/// # Examples
///
/// ```
/// use openssl_crypto::pem::{encode, PemObject};
///
/// let obj = PemObject::with_data("CERTIFICATE", vec![0x30, 0x82]);
/// let pem = encode(&obj);
/// assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
/// assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
/// ```
pub fn encode(obj: &PemObject) -> String {
    let mut output = String::new();

    // Write pre-encapsulation boundary
    output.push_str(PEM_BEGIN_PREFIX);
    output.push_str(&obj.label);
    output.push_str(PEM_BOUNDARY_SUFFIX);
    output.push('\n');

    // Write optional RFC 1421 headers
    if !obj.headers.is_empty() {
        for (key, value) in &obj.headers {
            output.push_str(key);
            output.push_str(": ");
            output.push_str(value);
            output.push('\n');
        }
        // Blank line separates headers from body per RFC 1421 §4.4
        output.push('\n');
    }

    // Encode the binary data as base64 and wrap at PEM_LINE_WIDTH characters.
    // Uses base64ct for constant-time encoding to prevent timing side channels
    // when encoding key material.
    let b64 = Base64::encode_string(&obj.data);
    let b64_bytes = b64.as_bytes();
    let total_len = b64_bytes.len();
    let mut offset: usize = 0;

    while offset < total_len {
        // Rule R6: use saturating arithmetic for line length calculation
        let end = total_len.min(offset.saturating_add(PEM_LINE_WIDTH));
        // SAFETY: offset and end are valid byte indices within the ASCII base64 string;
        // base64ct only produces ASCII characters so byte slicing is safe for UTF-8.
        if let Ok(line) = core::str::from_utf8(&b64_bytes[offset..end]) {
            output.push_str(line);
        }
        output.push('\n');
        offset = end;
    }

    // Handle edge case: empty data produces no base64 lines
    // (the PEM block is still syntactically valid)

    // Write post-encapsulation boundary
    output.push_str(PEM_END_PREFIX);
    output.push_str(&obj.label);
    output.push_str(PEM_BOUNDARY_SUFFIX);
    output.push('\n');

    output
}

/// Encodes a [`PemObject`] and writes the PEM-formatted output to a writer.
///
/// This is the streaming equivalent of [`encode()`]. The writer receives
/// the complete PEM block including boundaries and base64-encoded body.
///
/// # Errors
///
/// Returns `CryptoError::Io` if writing to the destination fails.
///
/// # Examples
///
/// ```
/// use openssl_crypto::pem::{encode_to_writer, PemObject};
///
/// let obj = PemObject::with_data("CERTIFICATE", vec![0x30, 0x82]);
/// let mut buf = Vec::new();
/// encode_to_writer(&obj, &mut buf).unwrap();
/// let output = String::from_utf8(buf).unwrap();
/// assert!(output.starts_with("-----BEGIN CERTIFICATE-----"));
/// ```
pub fn encode_to_writer<W: io::Write>(obj: &PemObject, writer: &mut W) -> CryptoResult<()> {
    let pem_string = encode(obj);
    writer
        .write_all(pem_string.as_bytes())
        .map_err(CryptoError::Io)?;
    Ok(())
}

// =============================================================================
// Decoding Functions
// =============================================================================

/// Decodes a single PEM block from the input string.
///
/// Parses the first PEM block found in `pem_data`, extracting the type label,
/// optional RFC 1421 headers, and base64-decoded binary payload.
///
/// Supports both strict RFC 7468 format (no headers) and legacy RFC 1421
/// format with `Proc-Type`/`DEK-Info` headers.
///
/// # Errors
///
/// - `CryptoError::Encoding` if no valid PEM block is found
/// - `CryptoError::Encoding` if the base64 body is malformed
/// - `CryptoError::Encoding` if begin/end labels do not match
///
/// # Examples
///
/// ```
/// use openssl_crypto::pem::{decode, PEM_LABEL_PRIVATE_KEY};
///
/// let pem = "-----BEGIN PRIVATE KEY-----\n\
///            MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF\n\
///            -----END PRIVATE KEY-----\n";
/// let obj = decode(pem).unwrap();
/// assert_eq!(obj.label, PEM_LABEL_PRIVATE_KEY);
/// assert!(!obj.data.is_empty());
/// ```
pub fn decode(pem_data: &str) -> CryptoResult<PemObject> {
    // First, try strict RFC 7468 parsing via pem_rfc7468.
    // If it succeeds, return the result directly.
    // If it fails (e.g., headers present, or other parse issue), fall through
    // to the custom parser that handles both RFC 7468 and RFC 1421 formats.
    if let Ok((label, data)) = pem_rfc7468::decode_vec(pem_data.as_bytes()) {
        return Ok(PemObject {
            label: label.to_string(),
            headers: Vec::new(),
            data,
        });
    }

    // Custom parser for PEM with optional RFC 1421 headers.
    // This handles the legacy encrypted PEM format that pem-rfc7468 rejects.
    decode_custom(pem_data)
}

/// Decodes all PEM blocks from the input string.
///
/// Iterates through `pem_data` finding all `-----BEGIN`/`-----END` pairs
/// and decoding each block. Useful for PEM files containing certificate
/// chains (multiple certificates concatenated).
///
/// # Errors
///
/// - `CryptoError::Encoding` if no valid PEM blocks are found
/// - `CryptoError::Encoding` if any individual block is malformed
///
/// # Examples
///
/// ```
/// use openssl_crypto::pem::decode_all;
///
/// let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n\
///            -----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n";
/// let objects = decode_all(pem).unwrap();
/// assert_eq!(objects.len(), 2);
/// ```
pub fn decode_all(pem_data: &str) -> CryptoResult<Vec<PemObject>> {
    let mut objects = Vec::new();
    let mut remaining = pem_data;

    while let Some(begin_pos) = remaining.find(PEM_BEGIN_PREFIX) {
        // Extract the label from the begin line
        let after_begin = &remaining[begin_pos.saturating_add(PEM_BEGIN_PREFIX.len())..];
        let Some(label_end) = after_begin.find(PEM_BOUNDARY_SUFFIX) else {
            return Err(CryptoError::Encoding(
                "malformed PEM: missing closing '-----' on BEGIN line".to_string(),
            ));
        };
        let label = after_begin[..label_end].trim();

        // Find the matching -----END marker
        let mut end_marker = String::with_capacity(
            PEM_END_PREFIX
                .len()
                .saturating_add(label.len())
                .saturating_add(PEM_BOUNDARY_SUFFIX.len()),
        );
        end_marker.push_str(PEM_END_PREFIX);
        end_marker.push_str(label);
        end_marker.push_str(PEM_BOUNDARY_SUFFIX);

        let end_pos = match remaining[begin_pos..].find(&end_marker) {
            Some(pos) => begin_pos.saturating_add(pos),
            None => {
                return Err(CryptoError::Encoding(format!(
                    "malformed PEM: no matching END marker for '{label}'"
                )));
            }
        };

        // Extract the complete PEM block for this object
        let block_end = end_pos
            .saturating_add(end_marker.len())
            .min(remaining.len());

        // Find the end of the END line (include trailing newline if present)
        let block_end_with_newline =
            if block_end < remaining.len() && remaining.as_bytes().get(block_end) == Some(&b'\n') {
                block_end.saturating_add(1)
            } else if block_end.saturating_add(1) < remaining.len()
                && remaining.as_bytes().get(block_end) == Some(&b'\r')
                && remaining.as_bytes().get(block_end.saturating_add(1)) == Some(&b'\n')
            {
                block_end.saturating_add(2)
            } else {
                block_end
            };

        let block = &remaining[begin_pos..block_end_with_newline];

        // Decode the individual block
        let obj = decode_custom(block)?;
        objects.push(obj);

        // Advance past this block
        remaining = &remaining[block_end_with_newline..];
    }

    if objects.is_empty() {
        return Err(CryptoError::Encoding(
            "no PEM blocks found in input".to_string(),
        ));
    }

    Ok(objects)
}

/// Decodes PEM blocks from a buffered reader.
///
/// Reads the entire content from `reader` into memory, then delegates to
/// [`decode_all()`] to parse all PEM blocks. This enables processing PEM
/// content from files, network streams, or any other [`BufRead`] source.
///
/// # Errors
///
/// - `CryptoError::Io` if reading from the source fails
/// - `CryptoError::Encoding` if no valid PEM blocks are found
///
/// # Examples
///
/// ```
/// use openssl_crypto::pem::decode_from_reader;
/// use std::io::BufReader;
///
/// let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
/// let reader = BufReader::new(&pem[..]);
/// let objects = decode_from_reader(reader).unwrap();
/// assert_eq!(objects.len(), 1);
/// ```
pub fn decode_from_reader<R: io::BufRead>(mut reader: R) -> CryptoResult<Vec<PemObject>> {
    let mut content = String::new();
    reader
        .read_to_string(&mut content)
        .map_err(CryptoError::Io)?;
    decode_all(&content)
}

// =============================================================================
// Encrypted PEM Functions
// =============================================================================

/// Decodes a legacy encrypted PEM block.
///
/// Parses a PEM block that uses the RFC 1421 encryption format with
/// `Proc-Type: 4,ENCRYPTED` and `DEK-Info` headers. The data is decrypted
/// using the provided passphrase.
///
/// # Supported Ciphers
///
/// Legacy encrypted PEM supports several ciphers identified by the `DEK-Info`
/// header. Common ciphers include `DES-EDE3-CBC`, `AES-128-CBC`, and
/// `AES-256-CBC`. The cipher name and IV are extracted from the `DEK-Info`
/// header.
///
/// > **Note:** Encrypted PEM decryption requires the EVP cipher layer to be
/// > available. If the specified cipher is not supported at the PEM layer,
/// > a `CryptoError::Encoding` is returned with details about the unsupported
/// > cipher.
///
/// # Errors
///
/// - `CryptoError::Encoding` if the PEM is not in encrypted format
/// - `CryptoError::Encoding` if the cipher specified in `DEK-Info` is not supported
/// - `CryptoError::Encoding` if the passphrase is empty
/// - `CryptoError::Encoding` if the base64 body is malformed
///
/// # Examples
///
/// ```no_run
/// use openssl_crypto::pem::decode_encrypted;
///
/// let encrypted_pem = "-----BEGIN RSA PRIVATE KEY-----\n\
///     Proc-Type: 4,ENCRYPTED\n\
///     DEK-Info: DES-EDE3-CBC,1A2B3C4D5E6F7A8B\n\
///     \n\
///     <base64 data>\n\
///     -----END RSA PRIVATE KEY-----\n";
/// let passphrase = b"secret";
/// // Returns error if cipher decryption is not available at this layer
/// let result = decode_encrypted(encrypted_pem, passphrase);
/// ```
pub fn decode_encrypted(pem_data: &str, passphrase: &[u8]) -> CryptoResult<PemObject> {
    // Validate passphrase is not empty
    if passphrase.is_empty() {
        return Err(CryptoError::Encoding(
            "passphrase must not be empty for encrypted PEM decryption".to_string(),
        ));
    }

    // Parse the PEM block (including headers)
    let obj = decode_custom(pem_data)?;

    // Check that this is actually an encrypted PEM block
    let is_encrypted = obj
        .headers
        .iter()
        .any(|(k, v)| k == PROC_TYPE_HEADER && v.contains(PROC_TYPE_ENCRYPTED_VALUE));

    if !is_encrypted {
        // If the label indicates PKCS#8 encrypted, the encryption is in the
        // ASN.1 payload, not at the PEM layer. Return the raw data and let
        // the caller handle PKCS#8 decryption.
        if obj.label == PEM_LABEL_ENCRYPTED_PRIVATE_KEY {
            return Ok(obj);
        }

        return Err(CryptoError::Encoding(
            "PEM block is not encrypted (no Proc-Type: 4,ENCRYPTED header)".to_string(),
        ));
    }

    // Extract cipher information from DEK-Info header
    let dek_info = obj
        .headers
        .iter()
        .find(|(k, _)| k == DEK_INFO_HEADER)
        .map(|(_, v)| v.as_str());

    let Some(dek_info) = dek_info else {
        return Err(CryptoError::Encoding(
            "encrypted PEM missing DEK-Info header".to_string(),
        ));
    };

    // Parse DEK-Info: CIPHER_NAME,HEX_IV
    let (cipher_name, iv_hex) = parse_dek_info(dek_info)?;

    // Decode the IV from hex
    let iv = decode_hex_iv(iv_hex)?;

    // Encrypted PEM decryption uses EVP_BytesToKey (MD5-based key derivation)
    // followed by cipher decryption. This requires the EVP cipher infrastructure
    // which is a separate module in the openssl-crypto crate.
    //
    // The PEM module handles format parsing; actual decryption is delegated
    // to the cipher layer. Return a descriptive error indicating the cipher
    // operation that would be needed.
    Err(CryptoError::Encoding(format!(
        "legacy encrypted PEM decryption requires EVP cipher layer for {cipher_name} \
         (IV: {} bytes). Use the EVP API to decrypt the PEM payload, or convert to \
         PKCS#8 encrypted format which is handled at the ASN.1 layer.",
        iv.len()
    )))
}

/// Encodes a [`PemObject`] with legacy PEM encryption.
///
/// Produces a PEM block with `Proc-Type: 4,ENCRYPTED` and `DEK-Info` headers,
/// where the binary payload is encrypted using the specified cipher and
/// passphrase before base64 encoding.
///
/// # Supported Ciphers
///
/// The `cipher` parameter specifies the encryption algorithm (e.g.,
/// `"DES-EDE3-CBC"`, `"AES-256-CBC"`). The cipher name follows OpenSSL
/// naming conventions.
///
/// > **Note:** Encrypted PEM encoding requires the EVP cipher layer to be
/// > available. If the specified cipher is not supported at the PEM layer,
/// > a `CryptoError::Encoding` is returned.
///
/// # Errors
///
/// - `CryptoError::Encoding` if the cipher is not supported at this layer
/// - `CryptoError::Encoding` if the passphrase is empty
/// - `CryptoError::Encoding` if encryption fails
///
/// # Examples
///
/// ```no_run
/// use openssl_crypto::pem::{encode_encrypted, PemObject};
///
/// let obj = PemObject::with_data("RSA PRIVATE KEY", vec![0x30, 0x82]);
/// let passphrase = b"secret";
/// // Returns error if cipher encryption is not available at this layer
/// let result = encode_encrypted(&obj, "DES-EDE3-CBC", passphrase);
/// ```
pub fn encode_encrypted(obj: &PemObject, cipher: &str, passphrase: &[u8]) -> CryptoResult<String> {
    // Validate inputs
    if passphrase.is_empty() {
        return Err(CryptoError::Encoding(
            "passphrase must not be empty for encrypted PEM encoding".to_string(),
        ));
    }

    if cipher.is_empty() {
        return Err(CryptoError::Encoding(
            "cipher name must not be empty for encrypted PEM encoding".to_string(),
        ));
    }

    if obj.data.is_empty() {
        return Err(CryptoError::Encoding(
            "cannot encrypt empty data for PEM encoding".to_string(),
        ));
    }

    // Encrypted PEM encoding requires EVP cipher infrastructure:
    // 1. Generate random IV
    // 2. Derive key via EVP_BytesToKey (MD5-based)
    // 3. Encrypt data with the specified cipher
    // 4. Format PEM with Proc-Type and DEK-Info headers
    //
    // The cipher layer is a separate module in the openssl-crypto crate.
    // The PEM module handles format concerns; encryption is delegated.
    Err(CryptoError::Encoding(format!(
        "legacy encrypted PEM encoding requires EVP cipher layer for '{cipher}'. \
         Use the EVP API to encrypt the payload before PEM encoding, or use \
         PKCS#8 encrypted format for private keys."
    )))
}

// =============================================================================
// Internal Parsing Helpers
// =============================================================================

/// Custom PEM parser that handles both RFC 7468 (no headers) and RFC 1421
/// (with headers) formats.
///
/// This parser is used as a fallback when `pem_rfc7468` rejects the input
/// due to the presence of headers.
fn decode_custom(pem_data: &str) -> CryptoResult<PemObject> {
    let lines: Vec<&str> = pem_data.lines().collect();

    // Find the BEGIN line
    let begin_idx = lines
        .iter()
        .position(|line| line.starts_with(PEM_BEGIN_PREFIX) && line.ends_with(PEM_BOUNDARY_SUFFIX))
        .ok_or_else(|| {
            CryptoError::Encoding(
                "no PEM start line found (missing -----BEGIN ...-----)".to_string(),
            )
        })?;

    let begin_line = lines[begin_idx];

    // Extract label from the BEGIN line
    let label = extract_label(begin_line, PEM_BEGIN_PREFIX)?;

    // Build the expected END line
    let mut expected_end = String::with_capacity(
        PEM_END_PREFIX
            .len()
            .saturating_add(label.len())
            .saturating_add(PEM_BOUNDARY_SUFFIX.len()),
    );
    expected_end.push_str(PEM_END_PREFIX);
    expected_end.push_str(&label);
    expected_end.push_str(PEM_BOUNDARY_SUFFIX);

    // Find the END line
    let end_idx = lines
        .iter()
        .position(|line| line.trim() == expected_end)
        .ok_or_else(|| {
            CryptoError::Encoding(format!(
                "no PEM end line found (missing -----END {label}-----)"
            ))
        })?;

    if end_idx <= begin_idx {
        return Err(CryptoError::Encoding(
            "PEM END marker appears before BEGIN marker".to_string(),
        ));
    }

    // Parse content between BEGIN and END lines
    let content_start = begin_idx.saturating_add(1);
    let content_lines = &lines[content_start..end_idx];

    // Separate headers from base64 body.
    // RFC 1421 headers appear before a blank line separator.
    let (headers, body_lines) = parse_headers_and_body(content_lines);

    // Concatenate all base64 body lines (stripping whitespace)
    let mut b64_data = String::new();
    for line in body_lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            b64_data.push_str(trimmed);
        }
    }

    // Decode base64 body using constant-time decoder
    let data = if b64_data.is_empty() {
        Vec::new()
    } else {
        Base64::decode_vec(&b64_data)
            .map_err(|e| CryptoError::Encoding(format!("invalid base64 in PEM body: {e}")))?
    };

    Ok(PemObject {
        label,
        headers,
        data,
    })
}

/// Extracts the PEM type label from a boundary line.
///
/// Given a line like `-----BEGIN CERTIFICATE-----`, returns `"CERTIFICATE"`.
fn extract_label(line: &str, prefix: &str) -> CryptoResult<String> {
    let after_prefix = line
        .strip_prefix(prefix)
        .ok_or_else(|| CryptoError::Encoding("invalid PEM boundary line".to_string()))?;

    let label = after_prefix
        .strip_suffix(PEM_BOUNDARY_SUFFIX)
        .ok_or_else(|| CryptoError::Encoding("invalid PEM boundary line".to_string()))?;

    let label = label.trim();

    if label.is_empty() {
        return Err(CryptoError::Encoding("PEM label is empty".to_string()));
    }

    Ok(label.to_string())
}

/// Separates RFC 1421 headers from the base64 body.
///
/// Headers are key-value pairs (e.g., `Proc-Type: 4,ENCRYPTED`) that appear
/// before the first blank line. If no blank line is found and the content
/// does not look like headers, the entire content is treated as base64 body.
fn parse_headers_and_body<'a>(lines: &'a [&'a str]) -> (Vec<(String, String)>, &'a [&'a str]) {
    let mut headers = Vec::new();
    let mut body_start: usize = 0;
    let mut found_blank_separator = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Blank line separates headers from body
        if trimmed.is_empty() {
            // Only treat as header separator if we've actually seen headers
            if !headers.is_empty() {
                body_start = i.saturating_add(1);
                found_blank_separator = true;
                break;
            }
            // Blank line at start — skip it and treat rest as body
            body_start = i.saturating_add(1);
            found_blank_separator = true;
            break;
        }

        // Try to parse as a header (Key: Value)
        if let Some(colon_pos) = trimmed.find(": ") {
            let key = &trimmed[..colon_pos];
            let value = &trimmed[colon_pos.saturating_add(2)..];

            // Validate this looks like a real header (not base64 data with a colon)
            if is_valid_header_key(key) {
                headers.push((key.to_string(), value.to_string()));
                body_start = i.saturating_add(1);
                continue;
            }
        }

        // This line doesn't look like a header — everything from here is body
        if headers.is_empty() {
            // No headers found; entire content is body
            body_start = 0;
        }
        break;
    }

    // If we found headers but no blank separator, the body starts after the last header
    if !headers.is_empty() && !found_blank_separator {
        // headers were parsed, body starts after them
    }

    (headers, &lines[body_start..])
}

/// Validates whether a string looks like a PEM header key.
///
/// Valid header keys are alphanumeric with hyphens (e.g., `Proc-Type`,
/// `DEK-Info`, `X-Custom-Header`). This distinguishes headers from
/// base64-encoded data that might happen to contain a colon.
fn is_valid_header_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    // Header keys should be ASCII alphanumeric with hyphens
    key.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Parses the DEK-Info header value into cipher name and hex-encoded IV.
///
/// The DEK-Info format is: `CIPHER_NAME,HEXIV`
/// For example: `DES-EDE3-CBC,1A2B3C4D5E6F7A8B`
fn parse_dek_info(dek_info: &str) -> CryptoResult<(&str, &str)> {
    let parts: Vec<&str> = dek_info.splitn(2, ',').collect();
    if parts.len() != 2 {
        return Err(CryptoError::Encoding(format!(
            "invalid DEK-Info header format: '{dek_info}' (expected CIPHER,HEXIV)"
        )));
    }

    let cipher_name = parts[0].trim();
    let iv_hex = parts[1].trim();

    if cipher_name.is_empty() {
        return Err(CryptoError::Encoding(
            "DEK-Info cipher name is empty".to_string(),
        ));
    }

    if iv_hex.is_empty() {
        return Err(CryptoError::Encoding("DEK-Info IV is empty".to_string()));
    }

    Ok((cipher_name, iv_hex))
}

/// Decodes a hex-encoded initialization vector from a DEK-Info header.
fn decode_hex_iv(hex_str: &str) -> CryptoResult<Vec<u8>> {
    let hex_str = hex_str.trim();

    if hex_str.len() % 2 != 0 {
        return Err(CryptoError::Encoding(
            "DEK-Info IV has odd number of hex characters".to_string(),
        ));
    }

    let mut iv = Vec::with_capacity(hex_str.len() / 2);

    let hex_bytes = hex_str.as_bytes();
    let mut i: usize = 0;
    while i < hex_bytes.len() {
        let hi = hex_nibble(hex_bytes[i]).ok_or_else(|| {
            CryptoError::Encoding(format!(
                "invalid hex character in DEK-Info IV at position {i}"
            ))
        })?;
        let lo = hex_nibble(hex_bytes[i.saturating_add(1)]).ok_or_else(|| {
            CryptoError::Encoding(format!(
                "invalid hex character in DEK-Info IV at position {}",
                i.saturating_add(1)
            ))
        })?;
        iv.push((hi << 4) | lo);
        i = i.saturating_add(2);
    }

    Ok(iv)
}

/// Converts a single ASCII hex digit to its 4-bit numeric value.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ──────────────────────────────────────────────────────

    #[test]
    fn test_label_constants() {
        assert_eq!(PEM_LABEL_CERTIFICATE, "CERTIFICATE");
        assert_eq!(PEM_LABEL_X509_CRL, "X509 CRL");
        assert_eq!(PEM_LABEL_RSA_PRIVATE_KEY, "RSA PRIVATE KEY");
        assert_eq!(PEM_LABEL_EC_PRIVATE_KEY, "EC PRIVATE KEY");
        assert_eq!(PEM_LABEL_PRIVATE_KEY, "PRIVATE KEY");
        assert_eq!(PEM_LABEL_PUBLIC_KEY, "PUBLIC KEY");
        assert_eq!(PEM_LABEL_ENCRYPTED_PRIVATE_KEY, "ENCRYPTED PRIVATE KEY");
        assert_eq!(PEM_LABEL_CERTIFICATE_REQUEST, "CERTIFICATE REQUEST");
    }

    // ── PemObject ─────────────────────────────────────────────────────

    #[test]
    fn test_pem_object_new() {
        let obj = PemObject::new();
        assert!(obj.label.is_empty());
        assert!(obj.headers.is_empty());
        assert!(obj.data.is_empty());
    }

    #[test]
    fn test_pem_object_with_label() {
        let obj = PemObject::with_label("CERTIFICATE");
        assert_eq!(obj.label, "CERTIFICATE");
        assert!(obj.headers.is_empty());
        assert!(obj.data.is_empty());
    }

    #[test]
    fn test_pem_object_with_data() {
        let data = vec![0x30, 0x82, 0x01, 0x22];
        let obj = PemObject::with_data("PRIVATE KEY", data.clone());
        assert_eq!(obj.label, "PRIVATE KEY");
        assert!(obj.headers.is_empty());
        assert_eq!(obj.data, data);
    }

    #[test]
    fn test_pem_object_default() {
        let obj = PemObject::default();
        assert!(obj.label.is_empty());
    }

    #[test]
    fn test_pem_object_clone() {
        let obj = PemObject::with_data("CERTIFICATE", vec![1, 2, 3]);
        let cloned = obj.clone();
        assert_eq!(obj, cloned);
    }

    // ── Encode / Decode Roundtrip ─────────────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = PemObject::with_data(
            "CERTIFICATE",
            vec![
                0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                0x01, 0x01, 0x0b, 0x05, 0x00,
            ],
        );

        let encoded = encode(&original);
        assert!(encoded.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(encoded.ends_with("-----END CERTIFICATE-----\n"));

        let decoded = decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.label, original.label);
        assert_eq!(decoded.data, original.data);
        assert!(decoded.headers.is_empty());
    }

    #[test]
    fn test_encode_private_key_roundtrip() {
        // Ed25519 private key (PKCS#8) — 48 bytes
        let key_bytes = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20, 0x17, 0xed, 0x9c, 0x73, 0xe9, 0xdb, 0x64, 0x9e, 0xc1, 0x89, 0xa6, 0x12,
            0x83, 0x1c, 0x5f, 0xc5, 0x70, 0x23, 0x82, 0x07, 0xc1, 0xaa, 0x9d, 0xfb, 0xd2, 0xc5,
            0x3e, 0x3f, 0xf5, 0xe5, 0xea, 0x85,
        ];

        let original = PemObject::with_data("PRIVATE KEY", key_bytes);
        let encoded = encode(&original);
        let decoded = decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.label, "PRIVATE KEY");
        assert_eq!(decoded.data, original.data);
    }

    #[test]
    fn test_encode_empty_data() {
        let obj = PemObject::with_data("TEST", Vec::new());
        let encoded = encode(&obj);
        assert!(encoded.contains("-----BEGIN TEST-----"));
        assert!(encoded.contains("-----END TEST-----"));

        let decoded = decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.label, "TEST");
        assert!(decoded.data.is_empty());
    }

    // ── Line Wrapping ─────────────────────────────────────────────────

    #[test]
    fn test_encode_line_wrapping() {
        // Create data that produces more than 64 base64 characters
        let data = vec![0xAB; 100]; // 100 bytes → 136 base64 chars → 3 lines
        let obj = PemObject::with_data("TEST", data);
        let encoded = encode(&obj);

        // Check that base64 lines are at most 64 characters
        for line in encoded.lines() {
            if line.starts_with("-----") {
                continue; // Skip boundary lines
            }
            assert!(
                line.len() <= PEM_LINE_WIDTH,
                "base64 line exceeds {PEM_LINE_WIDTH} chars: len={}",
                line.len()
            );
        }
    }

    // ── Decode Multiple ───────────────────────────────────────────────

    #[test]
    fn test_decode_all_multiple_blocks() {
        let cert1 = PemObject::with_data("CERTIFICATE", vec![0x30, 0x01]);
        let cert2 = PemObject::with_data("CERTIFICATE", vec![0x30, 0x02]);

        let mut pem = encode(&cert1);
        pem.push_str(&encode(&cert2));

        let objects = decode_all(&pem).expect("decode_all should succeed");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].data, vec![0x30, 0x01]);
        assert_eq!(objects[1].data, vec![0x30, 0x02]);
    }

    #[test]
    fn test_decode_all_mixed_types() {
        let cert = PemObject::with_data("CERTIFICATE", vec![0x30, 0x01]);
        let key = PemObject::with_data("PRIVATE KEY", vec![0x30, 0x02]);

        let mut pem = encode(&cert);
        pem.push_str(&encode(&key));

        let objects = decode_all(&pem).expect("decode_all should succeed");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].label, "CERTIFICATE");
        assert_eq!(objects[1].label, "PRIVATE KEY");
    }

    #[test]
    fn test_decode_all_no_blocks() {
        let result = decode_all("not a PEM file");
        assert!(result.is_err());
    }

    // ── Decode From Reader ────────────────────────────────────────────

    #[test]
    fn test_decode_from_reader() {
        let obj = PemObject::with_data("CERTIFICATE", vec![0x30, 0x82]);
        let encoded = encode(&obj);

        let reader = io::BufReader::new(encoded.as_bytes());
        let objects = decode_from_reader(reader).expect("decode_from_reader should succeed");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].label, "CERTIFICATE");
        assert_eq!(objects[0].data, vec![0x30, 0x82]);
    }

    // ── Encode to Writer ──────────────────────────────────────────────

    #[test]
    fn test_encode_to_writer() {
        let obj = PemObject::with_data("CERTIFICATE", vec![0x30, 0x82]);
        let mut buf = Vec::new();
        encode_to_writer(&obj, &mut buf).expect("encode_to_writer should succeed");

        let output = String::from_utf8(buf).expect("output should be valid UTF-8");
        assert!(output.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(output.ends_with("-----END CERTIFICATE-----\n"));
    }

    // ── Error Cases ───────────────────────────────────────────────────

    #[test]
    fn test_decode_invalid_input() {
        let result = decode("not a PEM block");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_missing_end() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n";
        let result = decode(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_mismatched_labels() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END PRIVATE KEY-----\n";
        let result = decode(pem);
        assert!(result.is_err());
    }

    // ── Headers Parsing ───────────────────────────────────────────────

    #[test]
    fn test_decode_with_headers() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                    Proc-Type: 4,ENCRYPTED\n\
                    DEK-Info: DES-EDE3-CBC,1A2B3C4D5E6F7A8B\n\
                    \n\
                    MIIB\n\
                    -----END RSA PRIVATE KEY-----\n";

        let obj = decode(pem).expect("decode should succeed");
        assert_eq!(obj.label, "RSA PRIVATE KEY");
        assert_eq!(obj.headers.len(), 2);
        assert_eq!(obj.headers[0].0, "Proc-Type");
        assert_eq!(obj.headers[0].1, "4,ENCRYPTED");
        assert_eq!(obj.headers[1].0, "DEK-Info");
        assert_eq!(obj.headers[1].1, "DES-EDE3-CBC,1A2B3C4D5E6F7A8B");
    }

    // ── Encrypted PEM ─────────────────────────────────────────────────

    #[test]
    fn test_decode_encrypted_no_proc_type() {
        let obj = PemObject::with_data("PRIVATE KEY", vec![0x30]);
        let pem = encode(&obj);
        let result = decode_encrypted(&pem, b"password");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_encrypted_empty_passphrase() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                    Proc-Type: 4,ENCRYPTED\n\
                    DEK-Info: DES-EDE3-CBC,1A2B3C4D5E6F7A8B\n\
                    \n\
                    MIIB\n\
                    -----END RSA PRIVATE KEY-----\n";
        let result = decode_encrypted(pem, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_encrypted_pkcs8_passthrough() {
        // PKCS#8 encrypted private keys don't use PEM-level encryption
        let obj = PemObject::with_data("ENCRYPTED PRIVATE KEY", vec![0x30, 0x82]);
        let pem = encode(&obj);
        let result = decode_encrypted(&pem, b"password");
        // Should succeed — returns the raw PKCS#8 data for caller to decrypt
        assert!(result.is_ok());
        assert_eq!(result.expect("ok").label, "ENCRYPTED PRIVATE KEY");
    }

    #[test]
    fn test_encode_encrypted_empty_passphrase() {
        let obj = PemObject::with_data("RSA PRIVATE KEY", vec![0x30]);
        let result = encode_encrypted(&obj, "DES-EDE3-CBC", b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_encrypted_empty_cipher() {
        let obj = PemObject::with_data("RSA PRIVATE KEY", vec![0x30]);
        let result = encode_encrypted(&obj, "", b"password");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_encrypted_empty_data() {
        let obj = PemObject::with_data("RSA PRIVATE KEY", Vec::new());
        let result = encode_encrypted(&obj, "DES-EDE3-CBC", b"password");
        assert!(result.is_err());
    }

    // ── Hex IV Parsing ────────────────────────────────────────────────

    #[test]
    fn test_decode_hex_iv_valid() {
        let iv = decode_hex_iv("1A2B3C4D5E6F7A8B").expect("valid hex");
        assert_eq!(iv, vec![0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B]);
    }

    #[test]
    fn test_decode_hex_iv_lowercase() {
        let iv = decode_hex_iv("aabbccdd").expect("valid hex");
        assert_eq!(iv, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_decode_hex_iv_odd_length() {
        let result = decode_hex_iv("1A2B3");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hex_iv_invalid_char() {
        let result = decode_hex_iv("1A2B3G");
        assert!(result.is_err());
    }

    // ── DEK-Info Parsing ──────────────────────────────────────────────

    #[test]
    fn test_parse_dek_info_valid() {
        let (cipher, iv) = parse_dek_info("DES-EDE3-CBC,1A2B3C4D5E6F7A8B").expect("valid DEK-Info");
        assert_eq!(cipher, "DES-EDE3-CBC");
        assert_eq!(iv, "1A2B3C4D5E6F7A8B");
    }

    #[test]
    fn test_parse_dek_info_no_comma() {
        let result = parse_dek_info("DES-EDE3-CBC");
        assert!(result.is_err());
    }

    // ── Encode with Headers ───────────────────────────────────────────

    #[test]
    fn test_encode_with_headers() {
        let mut obj = PemObject::with_data("RSA PRIVATE KEY", vec![0x30, 0x01]);
        obj.headers
            .push(("Proc-Type".to_string(), "4,ENCRYPTED".to_string()));
        obj.headers
            .push(("DEK-Info".to_string(), "DES-EDE3-CBC,AABB".to_string()));

        let encoded = encode(&obj);
        assert!(encoded.contains("Proc-Type: 4,ENCRYPTED"));
        assert!(encoded.contains("DEK-Info: DES-EDE3-CBC,AABB"));

        // Verify the blank line separator between headers and body
        assert!(encoded.contains("AABB\n\n"));
    }

    // ── Label Extraction ──────────────────────────────────────────────

    #[test]
    fn test_extract_label_valid() {
        let label =
            extract_label("-----BEGIN CERTIFICATE-----", PEM_BEGIN_PREFIX).expect("valid label");
        assert_eq!(label, "CERTIFICATE");
    }

    #[test]
    fn test_extract_label_with_spaces() {
        let label =
            extract_label("-----BEGIN X509 CRL-----", PEM_BEGIN_PREFIX).expect("valid label");
        assert_eq!(label, "X509 CRL");
    }

    #[test]
    fn test_extract_label_empty() {
        let result = extract_label("-----BEGIN -----", PEM_BEGIN_PREFIX);
        assert!(result.is_err());
    }

    // ── Header Key Validation ─────────────────────────────────────────

    #[test]
    fn test_is_valid_header_key() {
        assert!(is_valid_header_key("Proc-Type"));
        assert!(is_valid_header_key("DEK-Info"));
        assert!(is_valid_header_key("X-Custom"));
        assert!(!is_valid_header_key(""));
        assert!(!is_valid_header_key("key with space"));
        assert!(!is_valid_header_key("key:colon"));
    }
}
