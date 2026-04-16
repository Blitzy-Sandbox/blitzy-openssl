//! # Any-to-Object Decoder Chain Passthrough
//!
//! Internal "last resort" decoder that turns unrecognized binary content
//! into generic `StoreObject` types for further processing in the decoder
//! chain. Bridges between the store loader and the encoder/decoder subsystem.
//!
//! **This MUST be the last decoder in a chain**, leaving more specialized
//! decoders to recognise and process their content first.
//!
//! ## Supported Input Formats
//!
//! - **DER** — Generic ASN.1 DER-encoded blobs → [`ObjectType::Unknown`]
//! - **MSBLOB** — Microsoft BLOB key format (16-byte header) → [`ObjectType::Pkey`] (RSA/DSA)
//! - **PVK** — Microsoft PVK private key format (24-byte header) → [`ObjectType::Pkey`] (RSA/DSA)
//! - **RAW** — Raw binary data (up to 2048 bytes) → [`ObjectType::Skey`]
//!
//! ## Error Handling (Rule R5)
//!
//! All decode functions return `ProviderResult<Option<DecodedObject>>`:
//! - `Ok(Some(obj))` — successfully decoded
//! - `Ok(None)` — data not recognized / empty-handed (not an error)
//! - `Err(_)` — reserved for truly unrecoverable internal errors
//!
//! This matches the C convention where decoders return success (1) even
//! when they cannot recognize the data, allowing the next decoder in the
//! chain to attempt processing.
//!
//! ## Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → file_store::FileStore::open()
//!       → FileStoreContext::load()
//!         → any2obj::decode()
//! ```
//!
//! ## Source
//!
//! Replaces C `providers/implementations/storemgmt/file_store_any2obj.c` (368 lines).
//! Uses C `MAKE_DECODER` macro pattern → Rust enum-based dispatch via [`InputFormat`].

use crate::traits::AlgorithmDescriptor;
use openssl_common::error::ProviderResult;

// =============================================================================
// Constants
// =============================================================================

/// Maximum size for raw key data in bytes.
///
/// Matches C `#define MAX_RAW_KEY_SIZE 2048` from `file_store_any2obj.c`.
/// Raw key data exceeding this limit is truncated (matching the C behavior
/// of reading at most `MAX_RAW_KEY_SIZE` bytes from the BIO).
const MAX_RAW_KEY_SIZE: usize = 2048;

// ---------------------------------------------------------------------------
// Microsoft BLOB (MSBLOB) format constants
// ---------------------------------------------------------------------------
// The MSBLOB format is a legacy Windows key serialization format used by
// CryptoAPI. The 16-byte header consists of a BLOBHEADER (8 bytes) followed
// by an algorithm-specific header containing magic and bitlen (8 bytes).
//
// Reference: Microsoft PUBLICKEYSTRUC / BLOBHEADER documentation.

/// Size of the MSBLOB header in bytes (BLOBHEADER + magic + bitlen).
const MSBLOB_HEADER_SIZE: usize = 16;

/// BLOBHEADER `bType` value indicating a public key BLOB.
const PUBLICKEYBLOB: u8 = 0x06;

/// BLOBHEADER `bType` value indicating a private key BLOB.
const PRIVATEKEYBLOB: u8 = 0x07;

/// RSA public key magic: ASCII "RSA1" in little-endian.
const RSA1_MAGIC: u32 = 0x3141_5352;

/// RSA private key magic: ASCII "RSA2" in little-endian.
const RSA2_MAGIC: u32 = 0x3241_5352;

/// DSA public key magic: ASCII "DSS1" in little-endian.
const DSS1_MAGIC: u32 = 0x3153_5344;

/// DSA private key magic: ASCII "DSS2" in little-endian.
const DSS2_MAGIC: u32 = 0x3253_5344;

/// Maximum reasonable bit-length for MSBLOB keys.
///
/// Used as a sanity-check upper bound for the `bitlen` field parsed from
/// the header. Keys exceeding 65536 bits are rejected as implausible.
const MSBLOB_MAX_BITLEN: u32 = 65536;

// ---------------------------------------------------------------------------
// Microsoft PVK format constants
// ---------------------------------------------------------------------------
// PVK is a legacy proprietary format for storing private keys, used by
// older Microsoft tools. It has a fixed 24-byte header followed by an
// optional salt and the encrypted/unencrypted key data.

/// Size of the PVK header in bytes.
const PVK_HEADER_SIZE: usize = 24;

/// PVK file magic number at offset 0.
const PVK_MAGIC: u32 = 0xB0B5_F11E;

/// PVK key type value indicating a signature key (DSA).
/// Key type 1 = `AT_KEYEXCHANGE` (RSA), key type 2 = `AT_SIGNATURE` (DSA).
const PVK_AT_SIGNATURE: u32 = 2;

// =============================================================================
// Enums
// =============================================================================

/// Object type classification for decoded content.
///
/// Replaces C constants `OSSL_OBJECT_UNKNOWN`, `OSSL_OBJECT_PKEY`, and
/// `OSSL_OBJECT_SKEY` from `include/openssl/core_dispatch.h`.
///
/// Each variant maps to a specific category of cryptographic material
/// that the decoder chain can further process:
///
/// | Variant   | C Constant           | Usage                      |
/// |-----------|----------------------|----------------------------|
/// | `Unknown` | `OSSL_OBJECT_UNKNOWN`| DER blobs of unknown type  |
/// | `Pkey`    | `OSSL_OBJECT_PKEY`   | Asymmetric key material    |
/// | `Skey`    | `OSSL_OBJECT_SKEY`   | Symmetric key material     |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// Unrecognized or generic binary content whose type cannot be
    /// determined by the any-to-object decoder. Downstream decoders
    /// will attempt to classify this further.
    Unknown,
    /// Public or private key material (asymmetric). Produced by the
    /// MSBLOB and PVK decoders which can identify RSA/DSA keys.
    Pkey,
    /// Secret key material (symmetric). Produced by the RAW decoder
    /// for opaque binary key data.
    Skey,
}

/// Supported input format types for the any-to-object decoder.
///
/// Each variant corresponds to one of the four decoder functions in the
/// C source, and to one entry in the [`algorithm_descriptors()`] table.
///
/// | Variant  | C Decoder              | Input Property  |
/// |----------|------------------------|-----------------|
/// | `Der`    | `der2obj_decode()`     | `input=DER`     |
/// | `MsBlob` | `msblob2obj_decode()`  | `input=MSBLOB`  |
/// | `Pvk`    | `pvk2obj_decode()`     | `input=PVK`     |
/// | `Raw`    | `raw2obj_decode()`     | `input=RAW`     |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    /// ASN.1 DER encoded data.
    Der,
    /// Microsoft BLOB key format (`CryptoAPI`).
    MsBlob,
    /// Microsoft PVK private key format.
    Pvk,
    /// Raw binary data (opaque symmetric keys).
    Raw,
}

// =============================================================================
// Structs
// =============================================================================

/// Decoded object result produced by the any-to-object decoder.
///
/// Contains the raw data bytes and metadata about the object's type and
/// format. This struct is the Rust equivalent of the `OSSL_PARAM` array
/// that the C `any2obj_decode_final()` builds with:
///
/// - `OSSL_OBJECT_PARAM_DATA_TYPE` → [`data_type`](DecodedObject::data_type)
/// - `OSSL_OBJECT_PARAM_INPUT_TYPE` → [`input_type`](DecodedObject::input_type)
/// - `OSSL_OBJECT_PARAM_DATA_STRUCTURE` → [`data_structure`](DecodedObject::data_structure)
/// - `OSSL_OBJECT_PARAM_TYPE` → [`object_type`](DecodedObject::object_type)
/// - `OSSL_OBJECT_PARAM_DATA` → [`data`](DecodedObject::data)
#[derive(Debug, Clone)]
pub struct DecodedObject {
    /// The classification of the decoded content.
    pub object_type: ObjectType,

    /// The input format identifier (e.g., `"msblob"`, `"pvk"`, `"raw"`).
    /// `None` for DER objects where the format is implicit.
    pub input_type: Option<String>,

    /// The algorithm/data type string (e.g., `"RSA"`, `"DSA"`, `"SKEY"`).
    /// `None` for generic DER blobs where the algorithm is unknown.
    pub data_type: Option<String>,

    /// Optional data structure hint provided by the caller via the
    /// decoder context. Propagated from [`Any2ObjContext::data_structure()`].
    pub data_structure: Option<String>,

    /// The raw decoded data bytes (header + body for MSBLOB/PVK, or
    /// the full DER element, or raw bytes).
    pub data: Vec<u8>,
}

/// Decoder context for the any-to-object passthrough.
///
/// Replaces C `struct any2obj_ctx_st` which holds a `PROV_CTX*` provider
/// context pointer and a fixed-size `data_structure` hint buffer
/// (`char data_structure[OSSL_MAX_CODEC_STRUCT_SIZE]`).
///
/// In Rust, the provider context is managed externally (by the caller),
/// and the data structure hint uses `Option<String>` instead of a
/// fixed-size C char buffer — per Rule R5 (no sentinel values for
/// "unset"; use `Option<T>` instead).
///
/// # Lifecycle
///
/// Replaces C `any2obj_newctx()` / `any2obj_freectx()` with Rust's
/// ownership model: creation via [`Any2ObjContext::new()`] and automatic
/// cleanup via `Drop`.
#[derive(Debug, Clone, Default)]
pub struct Any2ObjContext {
    /// Optional data structure hint set by the caller.
    ///
    /// Replaces C `char data_structure[OSSL_MAX_CODEC_STRUCT_SIZE]`
    /// set via `any2obj_set_ctx_params()` with the
    /// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` parameter.
    data_structure: Option<String>,
}

impl Any2ObjContext {
    /// Creates a new decoder context with no data structure hint.
    ///
    /// Replaces C `any2obj_newctx()`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ctx = Any2ObjContext::new();
    /// assert!(ctx.data_structure().is_none());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the data structure hint for this decoder context.
    ///
    /// Replaces C `any2obj_set_ctx_params()` which reads the
    /// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` parameter.
    ///
    /// Pass `None` to clear a previously set hint. Pass `Some("...")` to
    /// set a hint that will be propagated to all [`DecodedObject`] results
    /// produced by this context.
    ///
    /// # Arguments
    ///
    /// * `structure` — The data structure hint string, or `None` to clear.
    pub fn set_data_structure(&mut self, structure: Option<&str>) {
        self.data_structure = structure.map(String::from);
    }

    /// Returns the current data structure hint, if set.
    ///
    /// This value is propagated to the `data_structure` field of every
    /// [`DecodedObject`] produced by the decode functions when this
    /// context is used.
    #[must_use]
    pub fn data_structure(&self) -> Option<&str> {
        self.data_structure.as_deref()
    }
}

// =============================================================================
// Private Helpers — DER Parsing
// =============================================================================

/// Parses the total length of a DER (Distinguished Encoding Rules) element
/// from the beginning of the input buffer.
///
/// Returns the total byte count of the TLV (Tag-Length-Value) element
/// including the tag, length encoding, and content bytes. Returns `None`
/// if the data is not valid DER or the buffer is too short.
///
/// This is a minimal DER parser sufficient for the any-to-object decoder.
/// It handles:
/// - Single-byte tags (most common)
/// - Multi-byte (high) tag numbers
/// - Short-form length (< 128 bytes)
/// - Long-form length (up to 4 length-of-length bytes)
/// - Rejects indefinite-length encoding (BER-only, not valid DER)
///
/// All arithmetic is checked per Rule R6 (no bare `as` casts).
fn parse_der_element_length(input: &[u8]) -> Option<usize> {
    if input.is_empty() {
        return None;
    }

    let mut pos: usize = 0;

    // --- Parse tag ---
    // Tag byte format: class (2 bits) | constructed (1 bit) | tag number (5 bits)
    // If tag number bits are all 1 (0x1F), the tag is multi-byte.
    let tag_byte = *input.get(pos)?;
    pos = pos.checked_add(1)?;

    if tag_byte & 0x1F == 0x1F {
        // High tag number form: subsequent bytes have continuation bit (bit 7).
        // The last byte has bit 7 = 0.
        loop {
            let b = *input.get(pos)?;
            pos = pos.checked_add(1)?;
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    // --- Parse length ---
    let length_byte = *input.get(pos)?;
    pos = pos.checked_add(1)?;

    let content_length: usize = match length_byte.cmp(&0x80) {
        std::cmp::Ordering::Less => {
            // Short form: length_byte IS the length.
            usize::from(length_byte)
        }
        std::cmp::Ordering::Equal => {
            // Indefinite length — not valid DER, only BER. Reject.
            return None;
        }
        std::cmp::Ordering::Greater => {
            // Long form: low 7 bits = number of subsequent length bytes.
            let num_length_bytes = usize::from(length_byte & 0x7F);
            // Sanity: more than 4 length bytes would encode >4 GiB — reject.
            if num_length_bytes > 4 {
                return None;
            }
            let end = pos.checked_add(num_length_bytes)?;
            if end > input.len() {
                return None;
            }
            let mut len: usize = 0;
            for &b in &input[pos..end] {
                len = len.checked_mul(256)?.checked_add(usize::from(b))?;
            }
            pos = end;
            len
        }
    };

    // Total element length = tag bytes + length encoding bytes + content bytes
    pos.checked_add(content_length)
}

// =============================================================================
// Private Helpers — MSBLOB Parsing
// =============================================================================

/// Parses a 16-byte MSBLOB header and returns key metadata.
///
/// Replaces C `ossl_do_blob_header()` from `crypto/pem/pvkfmt.c`.
///
/// # Header Layout (16 bytes, little-endian)
///
/// | Offset | Size | Field       | Description                                    |
/// |--------|------|-------------|------------------------------------------------|
/// | 0      | 1    | `bType`     | `0x06` = public, `0x07` = private              |
/// | 1      | 1    | `bVersion`  | Version (expected: 2)                          |
/// | 2      | 2    | `reserved`  | Reserved (ignored)                             |
/// | 4      | 4    | `aiAlgId`   | Algorithm identifier (ignored for type detect) |
/// | 8      | 4    | `magic`     | Key type magic (RSA1/RSA2/DSS1/DSS2)          |
/// | 12     | 4    | `bitlen`    | Key size in bits                               |
///
/// # Returns
///
/// `Some((is_dss, is_public, bitlen))` if the header is valid,
/// `None` if the header is malformed or has unrecognized magic.
fn parse_msblob_header(header: &[u8]) -> Option<(bool, bool, u32)> {
    if header.len() < MSBLOB_HEADER_SIZE {
        return None;
    }

    let btype = header[0];

    // Parse magic and bitlen as little-endian u32 values.
    // Using array indexing with bounds already checked above.
    let magic = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let bitlen = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);

    // Determine if DSA or RSA from the magic value.
    let is_dss = match magic {
        DSS1_MAGIC | DSS2_MAGIC => true,
        RSA1_MAGIC | RSA2_MAGIC => false,
        _ => return None, // Unrecognized magic — not a valid MSBLOB.
    };

    // Determine if public or private from the bType field.
    let is_public = match btype {
        PUBLICKEYBLOB => true,
        PRIVATEKEYBLOB => false,
        _ => return None, // Unrecognized bType.
    };

    // Sanity check: bitlen must be non-zero and reasonable.
    if bitlen == 0 || bitlen > MSBLOB_MAX_BITLEN {
        return None;
    }

    Some((is_dss, is_public, bitlen))
}

/// Calculates the expected key data length after the 16-byte MSBLOB header.
///
/// Replaces C `ossl_blob_length()` from `crypto/pem/pvkfmt.c`.
///
/// The formulas compute the byte sizes of the key components stored
/// after the header, based on the algorithm type and key visibility:
///
/// | Algorithm | Visibility | Formula                   | Components                          |
/// |-----------|-----------|---------------------------|-------------------------------------|
/// | RSA       | Public    | `4 + nbyte`               | pubexp(4) + modulus(n)              |
/// | RSA       | Private   | `4 + 2*nbyte + 5*hnbyte`  | pubexp(4) + mod(n) + CRT(5*hn) + d(n) |
/// | DSA       | Public    | `44 + 3*nbyte`            | p(n) + q(20) + g(n) + y(n) + seed(24) |
/// | DSA       | Private   | `68 + 3*nbyte`            | p(n) + q(20) + g(n) + y(n) + x(20) + seed(24+4) |
///
/// All arithmetic is checked per Rule R6.
///
/// # Arguments
///
/// * `bitlen` — Key size in bits (from MSBLOB header).
/// * `is_dss` — `true` for DSA, `false` for RSA.
/// * `is_public` — `true` for public key, `false` for private key.
///
/// # Returns
///
/// `Some(length)` on success, `None` on arithmetic overflow.
fn msblob_key_length(bitlen: u32, is_dss: bool, is_public: bool) -> Option<usize> {
    // nbyte = ceil(bitlen / 8)
    let nbyte = usize::try_from(bitlen.checked_add(7)? >> 3).ok()?;
    // hnbyte = ceil(bitlen / 16) — half-byte count for RSA CRT components
    let hnbyte = usize::try_from(bitlen.checked_add(15)? >> 4).ok()?;

    if is_dss {
        // DSA key components after header.
        // Formulas match OpenSSL's ossl_blob_length() exactly.
        let three_n = nbyte.checked_mul(3)?;
        if is_public {
            // p(n) + q(20) + g(n) + y(n) + DSSSEED(24) = 3n + 44
            three_n.checked_add(44)
        } else {
            // p(n) + q(20) + g(n) + y(n) + x(20) + DSSSEED(24+4) = 3n + 68
            three_n.checked_add(48)?.checked_add(20)
        }
    } else {
        // RSA key components after header.
        if is_public {
            // pubexp(4) + modulus(n) = n + 4
            nbyte.checked_add(4)
        } else {
            // pubexp(4) + modulus(n) + p(hn) + q(hn) + dmp1(hn) + dmq1(hn) +
            // iqmp(hn) + d(n) = 2n + 5hn + 4
            let two_n = nbyte.checked_mul(2)?;
            let five_hn = hnbyte.checked_mul(5)?;
            two_n.checked_add(five_hn)?.checked_add(4)
        }
    }
}

// =============================================================================
// Private Helpers — PVK Parsing
// =============================================================================

/// Parses a 24-byte PVK header and returns key metadata.
///
/// Replaces C `ossl_do_PVK_header()` from `crypto/pem/pvkfmt.c`.
///
/// # Header Layout (24 bytes, little-endian)
///
/// | Offset | Size | Field       | Description                                    |
/// |--------|------|-------------|------------------------------------------------|
/// | 0      | 4    | `magic`     | Must be `0xB0B5F11E`                          |
/// | 4      | 4    | `reserved`  | Reserved (ignored)                             |
/// | 8      | 4    | `keytype`   | `1` = RSA (exchange), `2` = DSA (signature)    |
/// | 12     | 4    | `encrypted` | `0` = plaintext, `1` = encrypted               |
/// | 16     | 4    | `saltlen`   | Salt length in bytes (0 if not encrypted)      |
/// | 20     | 4    | `keylen`    | Key data length in bytes                       |
///
/// # Returns
///
/// `Some((is_dss, saltlen, keylen))` if the header is valid,
/// `None` if the magic doesn't match or the header is too short.
fn parse_pvk_header(header: &[u8]) -> Option<(bool, u32, u32)> {
    if header.len() < PVK_HEADER_SIZE {
        return None;
    }

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != PVK_MAGIC {
        return None;
    }

    // reserved at header[4..8] — ignored
    let keytype = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    // encrypted at header[12..16] — not needed for type detection
    let saltlen = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let keylen = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);

    let is_dss = keytype == PVK_AT_SIGNATURE;

    Some((is_dss, saltlen, keylen))
}

// =============================================================================
// Private Helper — Core Decode Funnel
// =============================================================================

/// Core function that wraps decoded binary data into a [`DecodedObject`].
///
/// Replaces C `any2obj_decode_final()` which builds an `OSSL_PARAM` array
/// with `data_type`, `input_type`, `data_structure`, `object_type`, and data,
/// then invokes the callback. In Rust, we return the structured result
/// directly.
///
/// If `data` is `None` or empty, returns `None` — ending up
/// "empty handed" is not an error, per the C convention (returns 1).
///
/// # Arguments
///
/// * `ctx` — Decoder context (provides the `data_structure` hint).
/// * `object_type` — Classification of the decoded content.
/// * `input_type` — Format identifier (e.g., `"msblob"`, `"pvk"`, `"raw"`).
/// * `data_type` — Algorithm/data type (e.g., `"RSA"`, `"DSA"`, `"SKEY"`).
/// * `data` — The raw decoded bytes (ownership transferred), or `None`.
fn decode_final(
    ctx: &Any2ObjContext,
    object_type: ObjectType,
    input_type: Option<&str>,
    data_type: Option<&str>,
    data: Option<Vec<u8>>,
) -> Option<DecodedObject> {
    match data {
        // No data available — empty handed, not an error.
        None => None,
        // Empty data — also empty handed.
        Some(ref bytes) if bytes.is_empty() => None,
        // Valid data — wrap with metadata.
        Some(bytes) => Some(DecodedObject {
            object_type,
            input_type: input_type.map(String::from),
            data_type: data_type.map(String::from),
            data_structure: ctx.data_structure.clone(),
            data: bytes,
        }),
    }
}

// =============================================================================
// Public Decode Functions
// =============================================================================

/// DER decoder — reads a complete ASN.1 DER element from input bytes.
///
/// Replaces C `der2obj_decode()` which uses `asn1_d2i_read_bio()`.
///
/// Attempts to parse the input as a DER TLV (Tag-Length-Value) structure
/// and extract the complete element. If the data is not valid DER, returns
/// `Ok(None)` (not an error), matching the C semantics where
/// `ERR_set_mark()` / `ERR_pop_to_mark()` silently discard parse errors.
///
/// The decoded object has type [`ObjectType::Unknown`] because the DER
/// decoder does not inspect the content — it merely validates the
/// structural envelope and passes the data through.
///
/// # Arguments
///
/// * `ctx` — Decoder context with optional data structure hint.
/// * `input` — Raw input bytes that may contain a DER element.
///
/// # Returns
///
/// - `Ok(Some(obj))` — A complete DER element was extracted.
/// - `Ok(None)` — Input was empty or not valid DER.
pub fn decode_der(ctx: &Any2ObjContext, input: &[u8]) -> ProviderResult<Option<DecodedObject>> {
    if input.is_empty() {
        return Ok(None);
    }

    // Attempt to parse the DER element length.
    // If parsing fails, the data is not valid DER — return empty handed.
    let total_len = match parse_der_element_length(input) {
        Some(len) if len <= input.len() => len,
        _ => return Ok(None),
    };

    let data = input[..total_len].to_vec();
    Ok(decode_final(
        ctx,
        ObjectType::Unknown,
        None,
        None,
        Some(data),
    ))
}

/// MSBLOB decoder — reads a Microsoft BLOB key format.
///
/// Replaces C `msblob2obj_decode()`.
///
/// Reads the 16-byte MSBLOB header to determine the algorithm (RSA or DSA)
/// and whether the key is public or private. Then reads the expected body
/// length and returns the complete BLOB (header + body).
///
/// Always returns [`ObjectType::Pkey`] with input type `"msblob"` and a
/// data type of `"RSA"` or `"DSA"` based on the header magic value.
///
/// If the header is invalid or the input is too short, returns `Ok(None)`.
///
/// # Arguments
///
/// * `ctx` — Decoder context with optional data structure hint.
/// * `input` — Raw input bytes that may contain an MSBLOB.
///
/// # Returns
///
/// - `Ok(Some(obj))` — A valid MSBLOB was decoded.
/// - `Ok(None)` — Input was too short or not a valid MSBLOB.
pub fn decode_msblob(ctx: &Any2ObjContext, input: &[u8]) -> ProviderResult<Option<DecodedObject>> {
    if input.len() < MSBLOB_HEADER_SIZE {
        return Ok(None);
    }

    // Parse the 16-byte header.
    let Some((is_dss, is_public, bitlen)) = parse_msblob_header(input) else {
        return Ok(None);
    };

    // Calculate the expected body length from the key parameters.
    let Some(body_len) = msblob_key_length(bitlen, is_dss, is_public) else {
        return Ok(None);
    };

    // Verify the input has enough data for header + body.
    let total_len = match MSBLOB_HEADER_SIZE.checked_add(body_len) {
        Some(total) if total <= input.len() => total,
        _ => return Ok(None),
    };

    let data = input[..total_len].to_vec();
    let data_type = if is_dss { "DSA" } else { "RSA" };

    Ok(decode_final(
        ctx,
        ObjectType::Pkey,
        Some("msblob"),
        Some(data_type),
        Some(data),
    ))
}

/// PVK decoder — reads a Microsoft PVK private key format.
///
/// Replaces C `pvk2obj_decode()`.
///
/// Reads the 24-byte PVK header to determine the algorithm (RSA or DSA),
/// the salt length, and the key data length. Returns the complete PVK
/// file content (header + salt + key data).
///
/// Returns [`ObjectType::Pkey`] with input type `"pvk"` and a data type
/// of `"RSA"` or `"DSA"` based on the `keytype` field.
///
/// If the header is invalid or the input is too short, returns `Ok(None)`.
///
/// # Arguments
///
/// * `ctx` — Decoder context with optional data structure hint.
/// * `input` — Raw input bytes that may contain a PVK file.
///
/// # Returns
///
/// - `Ok(Some(obj))` — A valid PVK file was decoded.
/// - `Ok(None)` — Input was too short or not a valid PVK.
pub fn decode_pvk(ctx: &Any2ObjContext, input: &[u8]) -> ProviderResult<Option<DecodedObject>> {
    if input.len() < PVK_HEADER_SIZE {
        return Ok(None);
    }

    // Parse the 24-byte PVK header.
    let Some((is_dss, saltlen, keylen)) = parse_pvk_header(input) else {
        return Ok(None);
    };

    // Convert u32 lengths to usize using checked conversion (Rule R6).
    let Ok(saltlen_usize) = usize::try_from(saltlen) else {
        return Ok(None);
    };
    let Ok(keylen_usize) = usize::try_from(keylen) else {
        return Ok(None);
    };

    // Calculate total data length after header: salt + key data.
    let Some(datalen) = saltlen_usize.checked_add(keylen_usize) else {
        return Ok(None);
    };

    // Verify the input has enough data for header + salt + key.
    let total_len = match PVK_HEADER_SIZE.checked_add(datalen) {
        Some(total) if total <= input.len() => total,
        _ => return Ok(None),
    };

    let data = input[..total_len].to_vec();
    let data_type = if is_dss { "DSA" } else { "RSA" };

    Ok(decode_final(
        ctx,
        ObjectType::Pkey,
        Some("pvk"),
        Some(data_type),
        Some(data),
    ))
}

/// RAW decoder — reads raw binary data up to [`MAX_RAW_KEY_SIZE`] bytes.
///
/// Replaces C `raw2obj_decode()`.
///
/// Treats the input as opaque symmetric key material. The C implementation
/// reads at most `MAX_RAW_KEY_SIZE` (2048) bytes from the BIO; this Rust
/// version truncates inputs exceeding that limit to match the C behavior.
///
/// Returns [`ObjectType::Skey`] with input type `"raw"` and data type
/// `"SKEY"`. Rejects empty input by returning `Ok(None)`.
///
/// # Arguments
///
/// * `ctx` — Decoder context with optional data structure hint.
/// * `input` — Raw input bytes representing symmetric key material.
///
/// # Returns
///
/// - `Ok(Some(obj))` — Raw key data was captured (possibly truncated).
/// - `Ok(None)` — Input was empty.
pub fn decode_raw(ctx: &Any2ObjContext, input: &[u8]) -> ProviderResult<Option<DecodedObject>> {
    if input.is_empty() {
        return Ok(None);
    }

    // Truncate to MAX_RAW_KEY_SIZE, matching C read_data(cin, mem, MAX_RAW_KEY_SIZE)
    // which reads at most MAX_RAW_KEY_SIZE bytes from the BIO stream.
    let len = if input.len() > MAX_RAW_KEY_SIZE {
        MAX_RAW_KEY_SIZE
    } else {
        input.len()
    };

    let data = input[..len].to_vec();

    Ok(decode_final(
        ctx,
        ObjectType::Skey,
        Some("raw"),
        Some("SKEY"),
        Some(data),
    ))
}

// =============================================================================
// Public Dispatch Function
// =============================================================================

/// Main dispatch function that routes decoding to the appropriate
/// format-specific decoder based on the [`InputFormat`].
///
/// Replaces the C `OSSL_DISPATCH` function pointer tables created by
/// the `MAKE_DECODER` macro in `file_store_any2obj.c`. In Rust, the
/// dispatch is a simple `match` on the [`InputFormat`] enum, eliminating
/// function pointer indirection while preserving runtime format selection.
///
/// # Arguments
///
/// * `ctx` — Decoder context with optional data structure hint.
/// * `format` — The input format to decode.
/// * `input` — Raw input bytes to decode.
///
/// # Returns
///
/// - `Ok(Some(obj))` — The data was successfully decoded.
/// - `Ok(None)` — The data was not recognized or was empty.
pub fn decode(
    ctx: &Any2ObjContext,
    format: InputFormat,
    input: &[u8],
) -> ProviderResult<Option<DecodedObject>> {
    match format {
        InputFormat::Der => decode_der(ctx, input),
        InputFormat::MsBlob => decode_msblob(ctx, input),
        InputFormat::Pvk => decode_pvk(ctx, input),
        InputFormat::Raw => decode_raw(ctx, input),
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns the algorithm descriptors for the any-to-object decoders.
///
/// Replaces C `ossl_any_to_obj_algorithm[]` static array from
/// `file_store_any2obj.c`:
///
/// ```c
/// const OSSL_ALGORITHM ossl_any_to_obj_algorithm[] = {
///     { "obj", "provider=base,input=DER",    ... },
///     { "obj", "provider=base,input=MSBLOB", ... },
///     { "obj", "provider=base,input=PVK",    ... },
///     { "obj", "provider=base,input=RAW",    ... },
///     { NULL, NULL, NULL }
/// };
/// ```
///
/// Returns exactly 4 descriptors, one for each supported input format.
/// All descriptors use name `"obj"` and are associated with the base
/// provider (`provider=base`).
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` with 4 entries corresponding to the
/// DER, MSBLOB, PVK, and RAW decoders.
#[must_use]
pub fn algorithm_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["obj"],
            property: "provider=base,input=DER",
            description: "Any-to-object DER decoder passthrough",
        },
        AlgorithmDescriptor {
            names: vec!["obj"],
            property: "provider=base,input=MSBLOB",
            description: "Any-to-object MSBLOB decoder passthrough",
        },
        AlgorithmDescriptor {
            names: vec!["obj"],
            property: "provider=base,input=PVK",
            description: "Any-to-object PVK decoder passthrough",
        },
        AlgorithmDescriptor {
            names: vec!["obj"],
            property: "provider=base,input=RAW",
            description: "Any-to-object RAW decoder passthrough",
        },
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new_defaults() {
        let ctx = Any2ObjContext::new();
        assert_eq!(ctx.data_structure(), None);
    }

    #[test]
    fn test_context_set_data_structure() {
        let mut ctx = Any2ObjContext::new();
        ctx.set_data_structure(Some("PrivateKeyInfo"));
        assert_eq!(ctx.data_structure(), Some("PrivateKeyInfo"));
    }

    #[test]
    fn test_context_clear_data_structure() {
        let mut ctx = Any2ObjContext::new();
        ctx.set_data_structure(Some("PrivateKeyInfo"));
        ctx.set_data_structure(None);
        assert_eq!(ctx.data_structure(), None);
    }

    #[test]
    fn test_context_default_trait() {
        let ctx = Any2ObjContext::default();
        assert_eq!(ctx.data_structure(), None);
    }

    #[test]
    fn test_object_type_equality() {
        assert_eq!(ObjectType::Unknown, ObjectType::Unknown);
        assert_eq!(ObjectType::Pkey, ObjectType::Pkey);
        assert_eq!(ObjectType::Skey, ObjectType::Skey);
        assert_ne!(ObjectType::Unknown, ObjectType::Pkey);
    }

    #[test]
    fn test_input_format_equality() {
        assert_eq!(InputFormat::Der, InputFormat::Der);
        assert_ne!(InputFormat::Der, InputFormat::Raw);
    }

    #[test]
    fn test_object_type_debug() {
        let s = format!("{:?}", ObjectType::Pkey);
        assert!(s.contains("Pkey"));
    }

    #[test]
    fn test_input_format_debug() {
        let s = format!("{:?}", InputFormat::MsBlob);
        assert!(s.contains("MsBlob"));
    }

    // -- decode_der --

    #[test]
    fn test_decode_der_empty_input() {
        let ctx = Any2ObjContext::new();
        assert!(decode_der(&ctx, &[]).unwrap().is_none());
    }

    #[test]
    fn test_decode_der_too_short() {
        let ctx = Any2ObjContext::new();
        assert!(decode_der(&ctx, &[0x30]).unwrap().is_none());
    }

    #[test]
    fn test_decode_der_simple_sequence() {
        let der = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let ctx = Any2ObjContext::new();
        let obj = decode_der(&ctx, &der).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Unknown);
        assert_eq!(obj.input_type, None);
        assert_eq!(obj.data_type, None);
        assert_eq!(obj.data, der);
    }

    #[test]
    fn test_decode_der_with_hint() {
        let der = vec![0x30, 0x02, 0xAA, 0xBB];
        let mut ctx = Any2ObjContext::new();
        ctx.set_data_structure(Some("PrivateKeyInfo"));
        let obj = decode_der(&ctx, &der).unwrap().unwrap();
        assert_eq!(obj.data_structure, Some("PrivateKeyInfo".to_string()));
    }

    #[test]
    fn test_decode_der_long_form_length() {
        let mut der = vec![0x30, 0x81, 0x80];
        der.extend(vec![0x00; 128]);
        let ctx = Any2ObjContext::new();
        let obj = decode_der(&ctx, &der).unwrap().unwrap();
        assert_eq!(obj.data.len(), 131);
    }

    #[test]
    fn test_decode_der_truncated_content() {
        let der = vec![0x30, 0x0A, 0x01, 0x02, 0x03];
        let ctx = Any2ObjContext::new();
        assert!(decode_der(&ctx, &der).unwrap().is_none());
    }

    #[test]
    fn test_decode_der_indefinite_length() {
        let der = vec![0x30, 0x80, 0x01, 0x02, 0x00, 0x00];
        let ctx = Any2ObjContext::new();
        assert!(decode_der(&ctx, &der).unwrap().is_none());
    }

    #[test]
    fn test_decode_der_primitive_integer() {
        let der = vec![0x02, 0x01, 0x05];
        let ctx = Any2ObjContext::new();
        let obj = decode_der(&ctx, &der).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Unknown);
        assert_eq!(obj.data, der);
    }

    // -- decode_msblob --

    fn make_msblob_header(btype: u8, magic: u32, bitlen: u32) -> Vec<u8> {
        let mut h = Vec::with_capacity(16);
        h.push(btype);
        h.push(0x02);
        h.extend_from_slice(&[0x00, 0x00]);
        h.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        h.extend_from_slice(&magic.to_le_bytes());
        h.extend_from_slice(&bitlen.to_le_bytes());
        h
    }

    #[test]
    fn test_decode_msblob_empty() {
        let ctx = Any2ObjContext::new();
        assert!(decode_msblob(&ctx, &[]).unwrap().is_none());
    }

    #[test]
    fn test_decode_msblob_short() {
        let ctx = Any2ObjContext::new();
        assert!(decode_msblob(&ctx, &[0x06, 0x02, 0x00]).unwrap().is_none());
    }

    #[test]
    fn test_decode_msblob_bad_magic() {
        let h = make_msblob_header(0x06, 0xDEADBEEF, 512);
        let ctx = Any2ObjContext::new();
        assert!(decode_msblob(&ctx, &h).unwrap().is_none());
    }

    #[test]
    fn test_decode_msblob_rsa_pub() {
        let bitlen: u32 = 512;
        // RSA public key body = pubexp(4) + modulus(nbyte) = 4 + 64 = 68
        let body = (bitlen / 8) as usize + 4;
        let mut d = make_msblob_header(0x06, 0x31415352, bitlen);
        d.extend(vec![0xAA; body]);
        let ctx = Any2ObjContext::new();
        let obj = decode_msblob(&ctx, &d).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Pkey);
        assert_eq!(obj.input_type, Some("msblob".to_string()));
        assert_eq!(obj.data_type, Some("RSA".to_string()));
        assert_eq!(obj.data.len(), 16 + body);
    }

    #[test]
    fn test_decode_msblob_rsa_priv() {
        let bitlen: u32 = 512;
        let body = (bitlen as usize * 9 / 16) + 20;
        let mut d = make_msblob_header(0x07, 0x32415352, bitlen);
        d.extend(vec![0xBB; body]);
        let ctx = Any2ObjContext::new();
        let obj = decode_msblob(&ctx, &d).unwrap().unwrap();
        assert_eq!(obj.data_type, Some("RSA".to_string()));
    }

    #[test]
    fn test_decode_msblob_dss_pub() {
        let bitlen: u32 = 1024;
        let bl = bitlen as usize / 8;
        let body = 44 + 3 * bl + 24;
        let mut d = make_msblob_header(0x06, 0x31535344, bitlen);
        d.extend(vec![0xCC; body]);
        let ctx = Any2ObjContext::new();
        let obj = decode_msblob(&ctx, &d).unwrap().unwrap();
        assert_eq!(obj.data_type, Some("DSA".to_string()));
    }

    #[test]
    fn test_decode_msblob_truncated() {
        let d = make_msblob_header(0x06, 0x31415352, 512);
        let ctx = Any2ObjContext::new();
        assert!(decode_msblob(&ctx, &d).unwrap().is_none());
    }

    // -- decode_pvk --

    fn make_pvk_header(keytype: u32, saltlen: u32, keylen: u32) -> Vec<u8> {
        let mut h = Vec::with_capacity(24);
        h.extend_from_slice(&0xB0B5F11E_u32.to_le_bytes());
        h.extend_from_slice(&[0x00; 4]);
        h.extend_from_slice(&keytype.to_le_bytes());
        h.extend_from_slice(&0_u32.to_le_bytes());
        h.extend_from_slice(&saltlen.to_le_bytes());
        h.extend_from_slice(&keylen.to_le_bytes());
        h
    }

    #[test]
    fn test_decode_pvk_empty() {
        let ctx = Any2ObjContext::new();
        assert!(decode_pvk(&ctx, &[]).unwrap().is_none());
    }

    #[test]
    fn test_decode_pvk_short() {
        let ctx = Any2ObjContext::new();
        assert!(decode_pvk(&ctx, &[0xB0, 0xB5, 0xF1]).unwrap().is_none());
    }

    #[test]
    fn test_decode_pvk_bad_magic() {
        let mut h = make_pvk_header(1, 0, 64);
        h[0] = 0xFF;
        let ctx = Any2ObjContext::new();
        assert!(decode_pvk(&ctx, &h).unwrap().is_none());
    }

    #[test]
    fn test_decode_pvk_rsa() {
        let mut d = make_pvk_header(1, 0, 64);
        d.extend(vec![0xDD; 64]);
        let ctx = Any2ObjContext::new();
        let obj = decode_pvk(&ctx, &d).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Pkey);
        assert_eq!(obj.input_type, Some("pvk".to_string()));
        assert_eq!(obj.data_type, Some("RSA".to_string()));
        assert_eq!(obj.data.len(), 24 + 64);
    }

    #[test]
    fn test_decode_pvk_dsa() {
        let mut d = make_pvk_header(2, 16, 48);
        d.extend(vec![0xEE; 64]);
        let ctx = Any2ObjContext::new();
        let obj = decode_pvk(&ctx, &d).unwrap().unwrap();
        assert_eq!(obj.data_type, Some("DSA".to_string()));
        assert_eq!(obj.data.len(), 24 + 16 + 48);
    }

    #[test]
    fn test_decode_pvk_truncated() {
        let d = make_pvk_header(1, 0, 64);
        let ctx = Any2ObjContext::new();
        assert!(decode_pvk(&ctx, &d).unwrap().is_none());
    }

    // -- decode_raw --

    #[test]
    fn test_decode_raw_empty() {
        let ctx = Any2ObjContext::new();
        assert!(decode_raw(&ctx, &[]).unwrap().is_none());
    }

    #[test]
    fn test_decode_raw_small() {
        let key = vec![0x42; 32];
        let ctx = Any2ObjContext::new();
        let obj = decode_raw(&ctx, &key).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Skey);
        assert_eq!(obj.input_type, Some("raw".to_string()));
        assert_eq!(obj.data_type, Some("SKEY".to_string()));
        assert_eq!(obj.data, key);
    }

    #[test]
    fn test_decode_raw_max() {
        let key = vec![0x55; 2048];
        let ctx = Any2ObjContext::new();
        let obj = decode_raw(&ctx, &key).unwrap().unwrap();
        assert_eq!(obj.data.len(), 2048);
    }

    #[test]
    fn test_decode_raw_truncates() {
        let key = vec![0x66; 3000];
        let ctx = Any2ObjContext::new();
        let obj = decode_raw(&ctx, &key).unwrap().unwrap();
        assert_eq!(obj.data.len(), 2048);
    }

    // -- decode dispatch --

    #[test]
    fn test_dispatch_der() {
        let der = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let ctx = Any2ObjContext::new();
        let obj = decode(&ctx, InputFormat::Der, &der).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Unknown);
    }

    #[test]
    fn test_dispatch_raw() {
        let key = vec![0x77; 16];
        let ctx = Any2ObjContext::new();
        let obj = decode(&ctx, InputFormat::Raw, &key).unwrap().unwrap();
        assert_eq!(obj.object_type, ObjectType::Skey);
    }

    #[test]
    fn test_dispatch_msblob_empty() {
        let ctx = Any2ObjContext::new();
        assert!(decode(&ctx, InputFormat::MsBlob, &[]).unwrap().is_none());
    }

    #[test]
    fn test_dispatch_pvk_empty() {
        let ctx = Any2ObjContext::new();
        assert!(decode(&ctx, InputFormat::Pvk, &[]).unwrap().is_none());
    }

    // -- algorithm_descriptors --

    #[test]
    fn test_descriptors_count() {
        assert_eq!(algorithm_descriptors().len(), 4);
    }

    #[test]
    fn test_descriptors_names() {
        for d in &algorithm_descriptors() {
            assert_eq!(d.names, vec!["obj"]);
        }
    }

    #[test]
    fn test_descriptors_properties() {
        let descs = algorithm_descriptors();
        let props: Vec<&str> = descs.iter().map(|d| d.property).collect();
        assert!(props.contains(&"provider=base,input=DER"));
        assert!(props.contains(&"provider=base,input=MSBLOB"));
        assert!(props.contains(&"provider=base,input=PVK"));
        assert!(props.contains(&"provider=base,input=RAW"));
    }

    #[test]
    fn test_descriptors_nonempty_desc() {
        for d in &algorithm_descriptors() {
            assert!(!d.description.is_empty());
        }
    }

    // -- DecodedObject --

    #[test]
    fn test_decoded_object_clone() {
        let obj = DecodedObject {
            object_type: ObjectType::Pkey,
            input_type: Some("msblob".to_string()),
            data_type: Some("RSA".to_string()),
            data_structure: None,
            data: vec![1, 2, 3],
        };
        let c = obj.clone();
        assert_eq!(c.object_type, obj.object_type);
        assert_eq!(c.input_type, obj.input_type);
        assert_eq!(c.data, obj.data);
    }

    #[test]
    fn test_decoded_object_debug() {
        let obj = DecodedObject {
            object_type: ObjectType::Skey,
            input_type: Some("raw".to_string()),
            data_type: Some("SKEY".to_string()),
            data_structure: None,
            data: vec![0xFF],
        };
        let s = format!("{:?}", obj);
        assert!(s.contains("Skey"));
        assert!(s.contains("raw"));
    }
}
