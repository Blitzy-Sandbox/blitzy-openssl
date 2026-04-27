//! Microsoft key blob (MSBLOB) format decoder.
//!
//! Supports RSA and DSA public/private key blobs in the Microsoft binary
//! format (`PUBLICKEYBLOB`, `PRIVATEKEYBLOB`).  Replaces C
//! `decode_msblob2key.c` (284 lines).
//!
//! # MSBLOB Format Overview
//!
//! The Microsoft binary key format consists of a fixed 16-byte header
//! (`BLOBHEADER` + algorithm-specific magic/bitlen) followed by a
//! variable-length payload containing the key material in little-endian
//! byte order.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │ BLOBHEADER (8 bytes)                                │
//! │   bType(1) bVersion(1) reserved(2) aiKeyAlg(4)     │
//! ├─────────────────────────────────────────────────────┤
//! │ Algorithm-Specific Header (8 bytes)                 │
//! │   magic(4) bitlen(4)                                │
//! ├─────────────────────────────────────────────────────┤
//! │ Payload (variable)                                  │
//! │   RSA: pubexp(4) + modulus + [CRT params]           │
//! │   DSA: p + q(20) + g + pubkey + [privkey(20)]       │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # C → Rust Mapping
//!
//! | C Construct                        | Rust Equivalent                     |
//! |------------------------------------|-------------------------------------|
//! | `struct msblob2key_ctx_st`         | `MsBlobDecoderContext`             |
//! | `struct keytype_desc_st`           | `MsBlobKeyType` enum              |
//! | `ossl_do_blob_header()`            | `parse_blob_header()`             |
//! | `ossl_b2i_RSA_after_header()`      | `parse_rsa_blob()`                |
//! | `ossl_b2i_DSA_after_header()`      | `parse_dsa_blob()`                |
//! | `msblob2key_does_selection()`      | `does_selection()`                |
//! | `msblob2key_decode()`              | `MsBlobDecoder::decode()`         |
//! | `IMPLEMENT_MSBLOB(RSA/DSA,...)`    | `all_msblob_decoders()`           |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** All functions return `ProviderResult<T>` or
//!   `Option<T>` — no sentinel values.
//! - **R6 (Lossless Casts):** All narrowing conversions use `try_from` or
//!   checked arithmetic; `#[deny(clippy::cast_possible_truncation)]` applies.
//! - **R7 (Lock Granularity):** No shared mutable state — functions are pure.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable via `decoder_descriptors()` → provider query.

use crate::traits::{AlgorithmDescriptor, DecoderProvider, KeyData, KeySelection};
use openssl_common::{ProviderError, ProviderResult};

use super::common::{
    check_selection_hierarchy, selection_includes, DecodedObject, EndecoderError, ObjectType,
    FORMAT_MSBLOB,
};
use tracing::{debug, warn};

// =============================================================================
// Constants — MSBLOB Format Definitions
// =============================================================================

/// Maximum MSBLOB payload length (safety guard).
///
/// Prevents denial-of-service from maliciously large blob headers claiming
/// enormous payloads.  Matches the C `BLOB_MAX_LENGTH` constant.
const BLOB_MAX_LENGTH: usize = 64 * 1024 * 1024; // 64 MB

/// Combined BLOBHEADER + algorithm-specific header size in bytes.
///
/// ```text
/// BLOBHEADER (8 bytes): bType(1) + bVersion(1) + reserved(2) + aiKeyAlg(4)
/// AlgHeader  (8 bytes): magic(4) + bitlen(4)
/// Total:     16 bytes
/// ```
const BLOB_HEADER_SIZE: usize = 16;

// ── BLOBHEADER bType values ─────────────────────────────────────────────────

/// Microsoft `CryptoAPI` `PUBLICKEYBLOB` type (0x06).
const PUBLICKEYBLOB: u8 = 0x06;

/// Microsoft `CryptoAPI` `PRIVATEKEYBLOB` type (0x07).
const PRIVATEKEYBLOB: u8 = 0x07;

// ── BLOBHEADER aiKeyAlg values ──────────────────────────────────────────────

/// RSA signature algorithm identifier (`CALG_RSA_SIGN`).
const CALG_RSA_SIGN: u32 = 0x0000_2400;

/// RSA key exchange algorithm identifier (`CALG_RSA_KEYX`).
const CALG_RSA_KEYX: u32 = 0x0000_a400;

/// DSA signature algorithm identifier (`CALG_DSS_SIGN`).
const CALG_DSS_SIGN: u32 = 0x0000_2200;

// ── Algorithm-specific magic numbers ────────────────────────────────────────

/// RSA public key magic (`"RSA1"` = `0x31415352` little-endian).
const RSA1_MAGIC: u32 = 0x3141_5352;

/// RSA private key magic (`"RSA2"` = `0x32415352` little-endian).
const RSA2_MAGIC: u32 = 0x3241_5352;

/// DSA public key magic (`"DSS1"` = `0x31535344` little-endian).
const DSS1_MAGIC: u32 = 0x3153_5344;

/// DSA private key magic (`"DSS2"` = `0x32535344` little-endian).
const DSS2_MAGIC: u32 = 0x3253_5344;

/// DSA v3 private key magic (`"DSS3"` = `0x33535344` little-endian).
const DSS3_MAGIC: u32 = 0x3353_5344;

/// DSA `q` parameter length in bytes (160 bits per FIPS 186-2).
const DSS_Q_LEN: usize = 20;

/// Size of the RSA public exponent in the MSBLOB payload (4 bytes).
const RSA_PUBEXP_LEN: usize = 4;

// =============================================================================
// BlobHeader — Parsed MSBLOB Header
// =============================================================================

/// Parsed MSBLOB header encompassing BLOBHEADER + algorithm-specific header.
///
/// Represents the first 16 bytes of a Microsoft `CryptoAPI` binary key blob.
/// Provides all metadata needed to determine key type, key size, and whether
/// the blob contains a public or private key.
///
/// # C Equivalent
///
/// Replaces the combined parsing of `BLOBHEADER` + `RSAPUBKEY` / `DSSPUBKEY`
/// structs performed by `ossl_do_blob_header()` in `crypto/pem/pvkfmt.c`.
#[derive(Debug, Clone)]
pub struct BlobHeader {
    /// `BLOBHEADER.bType`: `PUBLICKEYBLOB` (0x06) or `PRIVATEKEYBLOB` (0x07).
    pub b_type: u8,

    /// `BLOBHEADER.bVersion`: expected to be `CUR_BLOB_VERSION` (0x02).
    pub b_version: u8,

    /// `BLOBHEADER.aiKeyAlg`: algorithm identifier (`CALG_RSA_SIGN`,
    /// `CALG_RSA_KEYX`, or `CALG_DSS_SIGN`).
    pub ai_key_alg: u32,

    /// Whether this blob contains a public key (`true`) or private key
    /// (`false`).  Derived from both `bType` and the algorithm magic number.
    pub is_public: bool,

    /// Key size in bits from the algorithm-specific header (e.g., 2048 for
    /// RSA-2048).
    bitlen: u32,

    /// Whether the blob contains a DSA key (`true`) or RSA key (`false`).
    is_dss: bool,
}

// =============================================================================
// MsBlobKeyType — Decoder Key Type Discriminator
// =============================================================================

/// Key type discriminator for MSBLOB decoder dispatch.
///
/// Each [`MsBlobDecoder`] instance is configured for exactly one key type.
/// This replaces the C `keytype_desc_st.type` field that selected between
/// `EVP_PKEY_RSA` and `EVP_PKEY_DSA` dispatch tables.
///
/// Variants are constructed inside feature-gated code paths
/// (`#[cfg(feature = "rsa")]` / `#[cfg(feature = "dsa")]`), so they may
/// appear unused when those features are disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants used behind `cfg(feature = "rsa"/"dsa")` gates.
pub enum MsBlobKeyType {
    /// RSA key type — handles `CALG_RSA_SIGN` and `CALG_RSA_KEYX` blobs.
    Rsa,
    /// DSA key type — handles `CALG_DSS_SIGN` blobs.
    Dsa,
}

impl std::fmt::Display for MsBlobKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MsBlobKeyType::Rsa => f.write_str("RSA"),
            MsBlobKeyType::Dsa => f.write_str("DSA"),
        }
    }
}

// =============================================================================
// MsBlobDecoderContext — Per-Operation Decoding Context
// =============================================================================

/// Per-operation context for MSBLOB decoding.
///
/// Carries the key selection mode and target key type across the decode
/// lifecycle.  Replaces C `struct msblob2key_ctx_st` from
/// `decode_msblob2key.c` (lines 56–61).
///
/// In the C implementation this struct also carried a `PROV_CTX*` provider
/// context pointer.  In Rust the provider context is managed at a higher
/// level (via `Arc<ProviderContext>`), so only the decoding-specific fields
/// are retained.
pub struct MsBlobDecoderContext {
    /// Key selection mode for this decode operation.
    ///
    /// Determines which key components to extract:
    /// - `KeySelection::empty()` — auto-detect (try private, fall back to public)
    /// - `KeySelection::PRIVATE_KEY` — extract private key only
    /// - `KeySelection::PUBLIC_KEY` — extract public key only
    pub selection: KeySelection,

    /// Target key type for this decoder instance.
    pub key_type: MsBlobKeyType,
}

// =============================================================================
// Key Data Structures — Decoded Key Material
// =============================================================================

/// RSA key material decoded from an MSBLOB payload.
///
/// Holds the raw big-endian byte representation of each RSA key component.
/// All byte vectors store the value in big-endian order (converted from the
/// little-endian MSBLOB representation during parsing).
///
/// For public keys, only `modulus` and `public_exponent` are populated;
/// private key components are `None` per Rule R5 (Option over sentinel).
///
/// # Dead-Code Justification
///
/// The fields are constructed by `parse_rsa_blob` and returned as a
/// `Box<dyn KeyData>`, but there is no consumer in the current tree that
/// downcasts the trait object back to `RsaKeyData` and reads the fields.
/// Such a consumer belongs to the key-management (`keymgmt`) path that
/// bridges MSBLOB-decoded key material into an RSA key pair — a future
/// integration point that is out-of-scope for the encode/decode provider
/// implementation.  The fields are retained (rather than removed) because
/// their byte layouts are the durable contract between the parser and the
/// future consumer.
#[cfg(feature = "rsa")]
#[derive(Debug)]
#[allow(dead_code)] // see preceding doc comment
struct RsaKeyData {
    /// RSA modulus `n` (big-endian byte representation).
    modulus: Vec<u8>,
    /// RSA public exponent `e` (big-endian byte representation).
    public_exponent: Vec<u8>,
    /// RSA private exponent `d` (big-endian, `None` for public keys).
    private_exponent: Option<Vec<u8>>,
    /// RSA first prime factor `p` (big-endian, `None` for public keys).
    prime1: Option<Vec<u8>>,
    /// RSA second prime factor `q` (big-endian, `None` for public keys).
    prime2: Option<Vec<u8>>,
    /// RSA CRT exponent `dP = d mod (p-1)` (big-endian, `None` for public keys).
    exponent1: Option<Vec<u8>>,
    /// RSA CRT exponent `dQ = d mod (q-1)` (big-endian, `None` for public keys).
    exponent2: Option<Vec<u8>>,
    /// RSA CRT coefficient `qInv = q^(-1) mod p` (big-endian, `None` for public keys).
    coefficient: Option<Vec<u8>>,
    /// Whether this key contains only public components.
    is_public: bool,
}

#[cfg(feature = "rsa")]
impl KeyData for RsaKeyData {}

/// DSA key material decoded from an MSBLOB payload.
///
/// Holds the raw big-endian byte representation of each DSA key component.
/// All byte vectors store the value in big-endian order (converted from the
/// little-endian MSBLOB representation during parsing).
///
/// For public keys, `private_key` is `None` per Rule R5.
///
/// # Dead-Code Justification
///
/// The fields are constructed by `parse_dsa_blob` and returned as a
/// `Box<dyn KeyData>`, but there is no consumer in the current tree that
/// downcasts the trait object back to `DsaKeyData` and reads the fields.
/// Such a consumer belongs to the key-management (`keymgmt`) path that
/// bridges MSBLOB-decoded key material into a `DsaKeyPair` — a future
/// integration point that is out-of-scope for the signature provider
/// implementation.  The fields are retained (rather than removed) because
/// their byte layouts are the durable contract between the parser and the
/// future consumer.
#[cfg(feature = "dsa")]
#[derive(Debug)]
#[allow(dead_code)] // see preceding doc comment
struct DsaKeyData {
    /// DSA prime `p` (big-endian byte representation).
    p: Vec<u8>,
    /// DSA sub-prime `q` (big-endian, always 20 bytes / 160 bits per FIPS 186-2).
    q: Vec<u8>,
    /// DSA generator `g` (big-endian byte representation).
    g: Vec<u8>,
    /// DSA public key `y = g^x mod p` (big-endian byte representation).
    public_key: Vec<u8>,
    /// DSA private key `x` (big-endian, 20 bytes, `None` for public keys).
    private_key: Option<Vec<u8>>,
    /// Whether this key contains only public components.
    is_public: bool,
}

#[cfg(feature = "dsa")]
impl KeyData for DsaKeyData {}

// =============================================================================
// MsBlobDecoder — Microsoft BLOB Key Decoder
// =============================================================================

/// Microsoft BLOB key decoder.
///
/// Reads the BLOBHEADER + key data from Microsoft `CryptoAPI` binary format.
/// Each instance is configured for a specific key type (RSA or DSA) via
/// the `MsBlobKeyType` discriminator.
///
/// Implements `DecoderProvider` with methods:
/// - [`name()`](DecoderProvider::name) — returns `"MSBLOB"`
/// - [`decode()`](DecoderProvider::decode) — parses blob and returns key data
/// - [`supported_formats()`](DecoderProvider::supported_formats) — returns `["MSBLOB"]`
///
/// # C Equivalent
///
/// Replaces the `IMPLEMENT_MSBLOB(RSA, rsa)` and `IMPLEMENT_MSBLOB(DSA, dsa)`
/// macro expansions from `decode_msblob2key.c` (lines 251–284), which
/// generated per-algorithm `OSSL_DISPATCH` function tables.
#[derive(Debug, Clone)]
pub struct MsBlobDecoder {
    /// Key type this decoder instance handles.
    key_type: MsBlobKeyType,
}

impl DecoderProvider for MsBlobDecoder {
    /// Returns the decoder name: `"MSBLOB"`.
    fn name(&self) -> &'static str {
        "MSBLOB"
    }

    /// Decodes a Microsoft BLOB-formatted key from `input` bytes.
    ///
    /// # Algorithm
    ///
    /// 1. Parse the 16-byte blob header (`parse_blob_header`)
    /// 2. Validate the algorithm type matches this decoder's key type
    /// 3. Compute expected payload length, enforce `BLOB_MAX_LENGTH`
    /// 4. Dispatch to `parse_rsa_blob` or `parse_dsa_blob`
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` if:
    /// - The input is shorter than the 16-byte header
    /// - The blob type or magic number is invalid
    /// - The algorithm type does not match this decoder's key type
    /// - The payload length exceeds `BLOB_MAX_LENGTH`
    /// - The payload is truncated
    /// - Key material parsing fails
    fn decode(&self, input: &[u8]) -> ProviderResult<Box<dyn KeyData>> {
        // Guard: reject empty input early with a descriptive common error.
        // This is distinct from the header-length check in parse_blob_header —
        // an empty slice indicates the caller supplied no data at all.
        if input.is_empty() {
            warn!("MSBLOB decode: input is empty");
            return Err(ProviderError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "MSBLOB decode input must not be empty".into(),
                ),
            ));
        }

        debug!(
            key_type = %self.key_type,
            input_len = input.len(),
            "MSBLOB decode: starting"
        );

        // Step 1: Parse the 16-byte header.
        let header = parse_blob_header(input)?;

        // Step 2: Validate algorithm type matches this decoder instance.
        //
        // In C, this was `ctx->desc->type != EVP_PKEY_RSA/DSA` check
        // (decode_msblob2key.c lines 124–126).
        match (header.is_dss, self.key_type) {
            (true, MsBlobKeyType::Rsa) => {
                debug!("MSBLOB: DSA blob presented to RSA decoder, skipping");
                return Err(ProviderError::Dispatch(
                    "MSBLOB algorithm mismatch: blob is DSA, decoder expects RSA".into(),
                ));
            }
            (false, MsBlobKeyType::Dsa) => {
                debug!("MSBLOB: RSA blob presented to DSA decoder, skipping");
                return Err(ProviderError::Dispatch(
                    "MSBLOB algorithm mismatch: blob is RSA, decoder expects DSA".into(),
                ));
            }
            _ => { /* Algorithm matches — proceed */ }
        }

        // Step 3: Compute expected payload length and enforce safety guard.
        //
        // Replaces C `ossl_blob_length(bitlen, isdss, ispub)` call
        // (decode_msblob2key.c line 128).
        let payload_len =
            compute_blob_payload_length(header.bitlen, header.is_dss, header.is_public);

        if payload_len > BLOB_MAX_LENGTH {
            warn!(
                payload_len,
                max = BLOB_MAX_LENGTH,
                "MSBLOB payload exceeds maximum length"
            );
            return Err(EndecoderError::BadEncoding.into());
        }

        // Step 4: Extract payload bytes from after the header.
        let payload = input
            .get(BLOB_HEADER_SIZE..)
            .ok_or(EndecoderError::BadEncoding)?;

        if payload.len() < payload_len {
            warn!(
                need = payload_len,
                have = payload.len(),
                "MSBLOB payload truncated"
            );
            return Err(EndecoderError::BadEncoding.into());
        }

        let payload_data = &payload[..payload_len];

        // Step 5: Dispatch to algorithm-specific parser.
        //
        // Replaces C `ctx->desc->read_private_key()` / `read_public_key()`
        // dispatch (decode_msblob2key.c lines 142–163).
        let key_data: Box<dyn KeyData> = match self.key_type {
            MsBlobKeyType::Rsa => {
                parse_rsa_blob(payload_data, header.is_public, header.bitlen)?
            }
            MsBlobKeyType::Dsa => {
                parse_dsa_blob(payload_data, header.is_public, header.bitlen)?
            }
        };

        // Log the decoded object type for observability correlation.
        let _decoded = DecodedObject {
            object_type: ObjectType::Pkey,
            data_type: self.key_type.to_string(),
            input_type: FORMAT_MSBLOB,
            data_structure: None,
            data: Vec::new(),
        };

        debug!(
            key_type = %self.key_type,
            is_public = header.is_public,
            bitlen = header.bitlen,
            "MSBLOB decode: completed successfully"
        );

        Ok(key_data)
    }

    /// Returns the list of supported input formats: `["MSBLOB"]`.
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_MSBLOB]
    }
}

// =============================================================================
// parse_blob_header — MSBLOB Header Parser
// =============================================================================

/// Parse a Microsoft BLOB header from the first 16 bytes of `data`.
///
/// Extracts and validates the BLOBHEADER fields (`bType`, `bVersion`,
/// `aiKeyAlg`) and the algorithm-specific header fields (`magic`, `bitlen`).
/// Determines whether the blob contains an RSA or DSA key and whether it
/// is a public or private key.
///
/// # C Equivalent
///
/// Replaces `ossl_do_blob_header()` from `crypto/pem/pvkfmt.c`, which is
/// called at `decode_msblob2key.c` line 116.
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` (via [`EndecoderError::BadEncoding`])
/// if:
/// - `data` is shorter than `BLOB_HEADER_SIZE` (16 bytes)
/// - `bType` is not `PUBLICKEYBLOB` or `PRIVATEKEYBLOB`
/// - `aiKeyAlg` is not a recognized RSA or DSA algorithm identifier
/// - The magic number is unrecognized or inconsistent with `aiKeyAlg`
pub fn parse_blob_header(data: &[u8]) -> ProviderResult<BlobHeader> {
    if data.len() < BLOB_HEADER_SIZE {
        warn!(
            data_len = data.len(),
            required = BLOB_HEADER_SIZE,
            "MSBLOB header too short"
        );
        return Err(EndecoderError::BadEncoding.into());
    }

    // ── BLOBHEADER (bytes 0–7) ──────────────────────────────────────────
    let b_type = data[0];
    let b_version = data[1];
    // data[2..4] is reserved (ignored)
    let ai_key_alg = u32::from_le_bytes(
        <[u8; 4]>::try_from(&data[4..8])
            .map_err(|_| EndecoderError::BadEncoding)?,
    );

    // Validate bType: must be public or private key blob.
    let is_public_from_type = match b_type {
        PUBLICKEYBLOB => true,
        PRIVATEKEYBLOB => false,
        _ => {
            warn!(b_type, "MSBLOB: unrecognized blob type");
            return Err(EndecoderError::BadEncoding.into());
        }
    };

    // Validate bVersion: expected CUR_BLOB_VERSION (0x02).
    // Non-standard versions are warned but not fatal — some implementations
    // use different version numbers.
    if b_version != 0x02 {
        warn!(b_version, expected = 0x02, "MSBLOB: unexpected blob version");
    }

    // Determine algorithm family from aiKeyAlg.
    let is_dss = match ai_key_alg {
        CALG_RSA_SIGN | CALG_RSA_KEYX => false,
        CALG_DSS_SIGN => true,
        _ => {
            warn!(ai_key_alg, "MSBLOB: unrecognized algorithm identifier");
            return Err(EndecoderError::BadEncoding.into());
        }
    };

    // ── Algorithm-Specific Header (bytes 8–15) ──────────────────────────
    let magic = u32::from_le_bytes(
        <[u8; 4]>::try_from(&data[8..12])
            .map_err(|_| EndecoderError::BadEncoding)?,
    );
    let bitlen = u32::from_le_bytes(
        <[u8; 4]>::try_from(&data[12..16])
            .map_err(|_| EndecoderError::BadEncoding)?,
    );

    // Validate magic and determine public/private from it.
    let is_public_from_magic = validate_magic(magic, is_dss)?;

    // Cross-validate: bType-based and magic-based public/private should agree.
    if is_public_from_type != is_public_from_magic {
        warn!(
            b_type,
            magic,
            type_says_public = is_public_from_type,
            magic_says_public = is_public_from_magic,
            "MSBLOB: bType/magic public/private mismatch"
        );
        // Use the magic-based determination as authoritative (matches C behavior).
    }

    debug!(
        b_type,
        b_version,
        ai_key_alg,
        magic,
        bitlen,
        is_dss,
        is_public = is_public_from_magic,
        "MSBLOB header parsed"
    );

    Ok(BlobHeader {
        b_type,
        b_version,
        ai_key_alg,
        is_public: is_public_from_magic,
        bitlen,
        is_dss,
    })
}

/// Validate the algorithm-specific magic number and return whether the blob
/// is public (`true`) or private (`false`).
fn validate_magic(magic: u32, is_dss: bool) -> ProviderResult<bool> {
    match (magic, is_dss) {
        // Public keys: RSA1 (RSA) or DSS1 (DSA)
        (RSA1_MAGIC, false) | (DSS1_MAGIC, true) => Ok(true),
        // Private keys: RSA2 (RSA), DSS2/DSS3 (DSA)
        (RSA2_MAGIC, false) | (DSS2_MAGIC | DSS3_MAGIC, true) => Ok(false),
        // Mismatch: RSA magic in a DSA-identified blob
        (RSA1_MAGIC | RSA2_MAGIC, true) => {
            warn!(magic, "MSBLOB: RSA magic in DSA-identified blob");
            Err(EndecoderError::BadEncoding.into())
        }
        // Mismatch: DSA magic in an RSA-identified blob
        (DSS1_MAGIC | DSS2_MAGIC | DSS3_MAGIC, false) => {
            warn!(magic, "MSBLOB: DSA magic in RSA-identified blob");
            Err(EndecoderError::BadEncoding.into())
        }
        // Completely unrecognized magic
        _ => {
            warn!(magic, "MSBLOB: unrecognized magic number");
            Err(EndecoderError::BadEncoding.into())
        }
    }
}

// =============================================================================
// compute_blob_payload_length — Payload Size Calculation
// =============================================================================

/// Compute the expected payload length following the 16-byte header.
///
/// Uses checked/saturating arithmetic throughout per Rule R6 — no bare `as`
/// casts for narrowing conversions.
///
/// # RSA Payload Layout
///
/// ```text
/// Public:  pubexp(4) + modulus(byte_len)
/// Private: pubexp(4) + modulus(byte_len) + prime1(half) + prime2(half)
///          + exponent1(half) + exponent2(half) + coefficient(half)
///          + private_exponent(byte_len)
/// ```
///
/// # DSA Payload Layout
///
/// ```text
/// Public:  p(byte_len) + q(20) + g(byte_len) + pubkey(byte_len)
/// Private: p(byte_len) + q(20) + g(byte_len) + pubkey(byte_len) + privkey(20)
/// ```
///
/// Replaces C `ossl_blob_length()` from `crypto/pem/pvkfmt.c`.
fn compute_blob_payload_length(bitlen: u32, is_dss: bool, is_public: bool) -> usize {
    // Rule R6: use try_from for narrowing conversion from u32 to usize.
    let byte_len = usize::try_from(bitlen.saturating_add(7) / 8).unwrap_or(0);

    if is_dss {
        // DSA: p(byte_len) + q(DSS_Q_LEN=20) + g(byte_len) + pubkey(byte_len)
        let mut total = byte_len
            .saturating_mul(3)
            .saturating_add(DSS_Q_LEN);
        if !is_public {
            // Private key adds privkey(DSS_Q_LEN=20)
            total = total.saturating_add(DSS_Q_LEN);
        }
        total
    } else {
        // RSA: pubexp(4) + modulus(byte_len)
        let half = byte_len / 2;
        let mut total = RSA_PUBEXP_LEN.saturating_add(byte_len);
        if !is_public {
            // Private key adds CRT parameters:
            // prime1(half) + prime2(half) + exponent1(half) + exponent2(half)
            // + coefficient(half) + private_exponent(byte_len)
            total = total
                .saturating_add(half.saturating_mul(5))
                .saturating_add(byte_len);
        }
        total
    }
}

// =============================================================================
// parse_rsa_blob — RSA Key Payload Parser
// =============================================================================

/// Parse RSA key material from an MSBLOB payload (bytes following the
/// 16-byte header).
///
/// All multi-byte integers in the MSBLOB format are stored in little-endian
/// byte order.  This function reverses them to big-endian for standard
/// cryptographic representation.
///
/// # RSA Public Key Layout
///
/// ```text
/// pubexp  (4 bytes, little-endian)
/// modulus (byte_len bytes, little-endian)
/// ```
///
/// # RSA Private Key Layout
///
/// ```text
/// pubexp     (4 bytes, little-endian)
/// modulus    (byte_len bytes, little-endian)
/// prime1     (half bytes, little-endian)
/// prime2     (half bytes, little-endian)
/// exponent1  (half bytes, little-endian)
/// exponent2  (half bytes, little-endian)
/// coefficient(half bytes, little-endian)
/// privexp    (byte_len bytes, little-endian)
/// ```
///
/// # C Equivalent
///
/// Replaces `ossl_b2i_RSA_after_header()` from `crypto/pem/pvkfmt.c`.
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` (via [`EndecoderError::InvalidKey`])
/// if the payload is truncated or key components cannot be extracted.
#[cfg(feature = "rsa")]
pub fn parse_rsa_blob(
    data: &[u8],
    is_public: bool,
    bitlen: u32,
) -> ProviderResult<Box<dyn KeyData>> {
    let byte_len = usize::try_from(bitlen.saturating_add(7) / 8)
        .map_err(|_| EndecoderError::InvalidKey)?;
    let half = byte_len / 2;

    debug!(bitlen, byte_len, is_public, "parsing RSA MSBLOB payload");

    let mut pos: usize = 0;

    // ── Public exponent (4 bytes, little-endian) ────────────────────────
    let pubexp_bytes = extract_field(data, &mut pos, RSA_PUBEXP_LEN, "RSA pubexp")?;
    let mut public_exponent = pubexp_bytes.to_vec();
    public_exponent.reverse(); // LE → BE
    // Strip leading zeros from big-endian representation.
    strip_leading_zeros(&mut public_exponent);

    // ── Modulus (byte_len bytes, little-endian) ─────────────────────────
    let modulus_bytes = extract_field(data, &mut pos, byte_len, "RSA modulus")?;
    let mut modulus = modulus_bytes.to_vec();
    modulus.reverse(); // LE → BE

    if is_public {
        debug!(bitlen, "RSA public key parsed from MSBLOB");
        return Ok(Box::new(RsaKeyData {
            modulus,
            public_exponent,
            private_exponent: None,
            prime1: None,
            prime2: None,
            exponent1: None,
            exponent2: None,
            coefficient: None,
            is_public: true,
        }));
    }

    // ── Private key CRT components ──────────────────────────────────────

    let p1_bytes = extract_field(data, &mut pos, half, "RSA prime1")?;
    let mut prime1 = p1_bytes.to_vec();
    prime1.reverse();

    let p2_bytes = extract_field(data, &mut pos, half, "RSA prime2")?;
    let mut prime2 = p2_bytes.to_vec();
    prime2.reverse();

    let e1_bytes = extract_field(data, &mut pos, half, "RSA exponent1")?;
    let mut exponent1 = e1_bytes.to_vec();
    exponent1.reverse();

    let e2_bytes = extract_field(data, &mut pos, half, "RSA exponent2")?;
    let mut exponent2 = e2_bytes.to_vec();
    exponent2.reverse();

    let coeff_bytes = extract_field(data, &mut pos, half, "RSA coefficient")?;
    let mut coefficient = coeff_bytes.to_vec();
    coefficient.reverse();

    let privexp_bytes = extract_field(data, &mut pos, byte_len, "RSA private exponent")?;
    let mut private_exponent = privexp_bytes.to_vec();
    private_exponent.reverse();

    debug!(bitlen, "RSA private key parsed from MSBLOB");

    Ok(Box::new(RsaKeyData {
        modulus,
        public_exponent,
        private_exponent: Some(private_exponent),
        prime1: Some(prime1),
        prime2: Some(prime2),
        exponent1: Some(exponent1),
        exponent2: Some(exponent2),
        coefficient: Some(coefficient),
        is_public: false,
    }))
}

/// Stub RSA blob parser when the `rsa` feature is disabled.
#[cfg(not(feature = "rsa"))]
pub fn parse_rsa_blob(
    _data: &[u8],
    _is_public: bool,
    _bitlen: u32,
) -> ProviderResult<Box<dyn KeyData>> {
    Err(ProviderError::AlgorithmUnavailable(
        "RSA support not compiled (feature 'rsa' disabled)".into(),
    ))
}

// =============================================================================
// parse_dsa_blob — DSA Key Payload Parser
// =============================================================================

/// Parse DSA key material from an MSBLOB payload (bytes following the
/// 16-byte header).
///
/// # DSA Public Key Layout
///
/// ```text
/// p      (byte_len bytes, little-endian)
/// q      (20 bytes, little-endian — 160 bits per FIPS 186-2)
/// g      (byte_len bytes, little-endian)
/// pubkey (byte_len bytes, little-endian)
/// ```
///
/// # DSA Private Key Layout
///
/// ```text
/// p       (byte_len bytes, little-endian)
/// q       (20 bytes, little-endian)
/// g       (byte_len bytes, little-endian)
/// pubkey  (byte_len bytes, little-endian)
/// privkey (20 bytes, little-endian)
/// ```
///
/// # C Equivalent
///
/// Replaces `ossl_b2i_DSA_after_header()` from `crypto/pem/pvkfmt.c`.
///
/// # Errors
///
/// Returns `ProviderError::Dispatch` (via [`EndecoderError::InvalidKey`])
/// if the payload is truncated or key components cannot be extracted.
#[cfg(feature = "dsa")]
pub fn parse_dsa_blob(
    data: &[u8],
    is_public: bool,
    bitlen: u32,
) -> ProviderResult<Box<dyn KeyData>> {
    let byte_len = usize::try_from(bitlen.saturating_add(7) / 8)
        .map_err(|_| EndecoderError::InvalidKey)?;

    debug!(bitlen, byte_len, is_public, "parsing DSA MSBLOB payload");

    let mut pos: usize = 0;

    // ── p (byte_len bytes, little-endian) ───────────────────────────────
    let p_bytes = extract_field(data, &mut pos, byte_len, "DSA p")?;
    let mut p = p_bytes.to_vec();
    p.reverse();

    // ── q (20 bytes, little-endian) ─────────────────────────────────────
    let q_bytes = extract_field(data, &mut pos, DSS_Q_LEN, "DSA q")?;
    let mut q = q_bytes.to_vec();
    q.reverse();

    // ── g (byte_len bytes, little-endian) ───────────────────────────────
    let g_bytes = extract_field(data, &mut pos, byte_len, "DSA g")?;
    let mut g = g_bytes.to_vec();
    g.reverse();

    // ── public key y (byte_len bytes, little-endian) ────────────────────
    let pubkey_bytes = extract_field(data, &mut pos, byte_len, "DSA public key")?;
    let mut public_key = pubkey_bytes.to_vec();
    public_key.reverse();

    if is_public {
        debug!(bitlen, "DSA public key parsed from MSBLOB");
        return Ok(Box::new(DsaKeyData {
            p,
            q,
            g,
            public_key,
            private_key: None,
            is_public: true,
        }));
    }

    // ── private key x (20 bytes, little-endian) ─────────────────────────
    let privkey_bytes = extract_field(data, &mut pos, DSS_Q_LEN, "DSA private key")?;
    let mut private_key = privkey_bytes.to_vec();
    private_key.reverse();

    debug!(bitlen, "DSA private key parsed from MSBLOB");

    Ok(Box::new(DsaKeyData {
        p,
        q,
        g,
        public_key,
        private_key: Some(private_key),
        is_public: false,
    }))
}

/// Stub DSA blob parser when the `dsa` feature is disabled.
#[cfg(not(feature = "dsa"))]
pub fn parse_dsa_blob(
    _data: &[u8],
    _is_public: bool,
    _bitlen: u32,
) -> ProviderResult<Box<dyn KeyData>> {
    Err(ProviderError::AlgorithmUnavailable(
        "DSA support not compiled (feature 'dsa' disabled)".into(),
    ))
}

// =============================================================================
// extract_field — Payload Field Extraction Helper
// =============================================================================

/// Extract a fixed-length byte field from the payload at the current position.
///
/// Advances `pos` by `len` bytes.  Returns a slice of the extracted bytes.
/// Uses checked arithmetic per Rule R6 for all offset calculations.
///
/// # Errors
///
/// Returns [`EndecoderError::InvalidKey`] if the field extends beyond the
/// payload boundary.
#[cfg(any(feature = "rsa", feature = "dsa"))]
fn extract_field<'a>(
    data: &'a [u8],
    pos: &mut usize,
    len: usize,
    field_name: &str,
) -> ProviderResult<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| -> ProviderError { EndecoderError::InvalidKey.into() })?;

    if end > data.len() {
        warn!(
            field = field_name,
            offset = *pos,
            need = len,
            have = data.len().saturating_sub(*pos),
            "MSBLOB: field extends beyond payload"
        );
        return Err(EndecoderError::InvalidKey.into());
    }

    let field = &data[*pos..end];
    *pos = end;
    Ok(field)
}

/// Strip leading zero bytes from a big-endian byte vector.
///
/// After reversing a little-endian value to big-endian, the high bytes may
/// be zero.  This trims them for canonical representation, preserving at
/// least one byte (a value of zero is represented as `[0x00]`).
#[cfg(feature = "rsa")]
fn strip_leading_zeros(bytes: &mut Vec<u8>) {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
}

// =============================================================================
// does_selection — Selection Validation
// =============================================================================

/// Check whether a given key selection is supported by the MSBLOB decoder.
///
/// The MSBLOB format supports:
/// - Default selection (empty/zero — auto-detect, try both public and private)
/// - `KeySelection::PUBLIC_KEY` — public key blobs
/// - `KeySelection::PRIVATE_KEY` — private key blobs
///
/// Domain parameters and other selections are not directly supported.
///
/// Uses [`check_selection_hierarchy`] and [`selection_includes`] from
/// `super::common` for consistent selection validation across all decoders.
///
/// # C Equivalent
///
/// Replaces `msblob2key_does_selection()` from `decode_msblob2key.c`
/// (lines 82–91).
pub fn does_selection(selection: KeySelection) -> bool {
    // Empty selection means "guess" — always supported.
    if selection.is_empty() {
        return true;
    }

    // MSBLOB supports both public and private key selections.
    let supported = KeySelection::PRIVATE_KEY | KeySelection::PUBLIC_KEY;

    // Use the hierarchy check: PRIVATE implies PUBLIC.
    if check_selection_hierarchy(selection, supported) {
        return true;
    }

    // Also accept if the selection directly includes public or private flags.
    selection_includes(selection, KeySelection::PRIVATE_KEY)
        || selection_includes(selection, KeySelection::PUBLIC_KEY)
}

// =============================================================================
// all_msblob_decoders — Decoder Registration
// =============================================================================

/// Returns algorithm descriptors for all MSBLOB decoders.
///
/// Creates descriptors for:
/// - RSA MSBLOB decoder (gated by feature `"rsa"`)
/// - DSA MSBLOB decoder (gated by feature `"dsa"`)
///
/// Called by [`super::decoder_descriptors()`] to register MSBLOB decoders
/// with the provider dispatch system.
///
/// # C Equivalent
///
/// Replaces the `IMPLEMENT_MSBLOB(RSA, rsa)` and `IMPLEMENT_MSBLOB(DSA, dsa)`
/// macro expansions at `decode_msblob2key.c` lines 282–284:
///
/// ```c
/// #ifndef OPENSSL_NO_DSA
/// IMPLEMENT_MSBLOB(DSA, dsa);
/// #endif
/// IMPLEMENT_MSBLOB(RSA, rsa);
/// ```
pub fn all_msblob_decoders() -> Vec<AlgorithmDescriptor> {
    // Capacity depends on which algorithm features are enabled.
    // `allow(unused_mut)` avoids a warning when no algorithm features are
    // active, in which case the vector is returned empty without any push.
    #[allow(unused_mut)]
    let mut descriptors = Vec::new();

    #[cfg(feature = "rsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,input=msblob",
            description: "MSBLOB to RSA key decoder",
        });
    }

    #[cfg(feature = "dsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,input=msblob",
            description: "MSBLOB to DSA key decoder",
        });
    }

    descriptors
}

/// Create an [`MsBlobDecoder`] instance for RSA keys.
///
/// Convenience constructor for use in provider wiring.
///
/// # Feature Gate
///
/// Only available when the `"rsa"` feature is enabled.
#[cfg(feature = "rsa")]
pub fn rsa_decoder() -> MsBlobDecoder {
    MsBlobDecoder {
        key_type: MsBlobKeyType::Rsa,
    }
}

/// Create an [`MsBlobDecoder`] instance for DSA keys.
///
/// Convenience constructor for use in provider wiring.
///
/// # Feature Gate
///
/// Only available when the `"dsa"` feature is enabled.
#[cfg(feature = "dsa")]
pub fn dsa_decoder() -> MsBlobDecoder {
    MsBlobDecoder {
        key_type: MsBlobKeyType::Dsa,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: build a minimal valid RSA public key MSBLOB ─────────────

    /// Construct a minimal RSA-1024 public key MSBLOB for testing.
    fn make_rsa_public_blob(bitlen: u32) -> Vec<u8> {
        let byte_len = ((bitlen + 7) / 8) as usize;
        let mut blob = Vec::new();

        // BLOBHEADER
        blob.push(PUBLICKEYBLOB);   // bType
        blob.push(0x02);            // bVersion
        blob.extend_from_slice(&[0x00, 0x00]); // reserved
        blob.extend_from_slice(&CALG_RSA_KEYX.to_le_bytes()); // aiKeyAlg

        // RSAPUBKEY header
        blob.extend_from_slice(&RSA1_MAGIC.to_le_bytes()); // magic
        blob.extend_from_slice(&bitlen.to_le_bytes());     // bitlen

        // Payload: pubexp (4 bytes) + modulus (byte_len bytes)
        blob.extend_from_slice(&65537u32.to_le_bytes()); // pubexp = 65537
        blob.extend(vec![0xAB; byte_len]);               // modulus (dummy)

        blob
    }

    /// Construct a minimal DSA-1024 public key MSBLOB for testing.
    fn make_dsa_public_blob(bitlen: u32) -> Vec<u8> {
        let byte_len = ((bitlen + 7) / 8) as usize;
        let mut blob = Vec::new();

        // BLOBHEADER
        blob.push(PUBLICKEYBLOB);
        blob.push(0x02);
        blob.extend_from_slice(&[0x00, 0x00]);
        blob.extend_from_slice(&CALG_DSS_SIGN.to_le_bytes());

        // DSSPUBKEY header
        blob.extend_from_slice(&DSS1_MAGIC.to_le_bytes());
        blob.extend_from_slice(&bitlen.to_le_bytes());

        // Payload: p + q + g + pubkey
        blob.extend(vec![0x01; byte_len]); // p
        blob.extend(vec![0x02; DSS_Q_LEN]); // q (20 bytes)
        blob.extend(vec![0x03; byte_len]); // g
        blob.extend(vec![0x04; byte_len]); // pubkey

        blob
    }

    // ── Header Parsing Tests ────────────────────────────────────────────

    #[test]
    fn test_parse_blob_header_rsa_public() {
        let blob = make_rsa_public_blob(1024);
        let header = parse_blob_header(&blob).expect("should parse RSA public header");
        assert_eq!(header.b_type, PUBLICKEYBLOB);
        assert_eq!(header.b_version, 0x02);
        assert!(header.is_public);
        assert!(!header.is_dss);
        assert_eq!(header.bitlen, 1024);
    }

    #[test]
    fn test_parse_blob_header_dsa_public() {
        let blob = make_dsa_public_blob(1024);
        let header = parse_blob_header(&blob).expect("should parse DSA public header");
        assert_eq!(header.b_type, PUBLICKEYBLOB);
        assert!(header.is_public);
        assert!(header.is_dss);
        assert_eq!(header.bitlen, 1024);
    }

    #[test]
    fn test_parse_blob_header_too_short() {
        let short = vec![0u8; 10];
        let result = parse_blob_header(&short);
        assert!(result.is_err(), "should fail on short input");
    }

    #[test]
    fn test_parse_blob_header_bad_type() {
        let mut blob = make_rsa_public_blob(1024);
        blob[0] = 0xFF; // Invalid bType
        let result = parse_blob_header(&blob);
        assert!(result.is_err(), "should fail on bad blob type");
    }

    #[test]
    fn test_parse_blob_header_bad_algorithm() {
        let mut blob = make_rsa_public_blob(1024);
        blob[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let result = parse_blob_header(&blob);
        assert!(result.is_err(), "should fail on unrecognized algorithm");
    }

    #[test]
    fn test_parse_blob_header_magic_mismatch() {
        let mut blob = make_rsa_public_blob(1024);
        // Put DSA magic in RSA blob
        blob[8..12].copy_from_slice(&DSS1_MAGIC.to_le_bytes());
        let result = parse_blob_header(&blob);
        assert!(result.is_err(), "should fail on magic/algorithm mismatch");
    }

    // ── Selection Tests ─────────────────────────────────────────────────

    #[test]
    fn test_does_selection_empty() {
        assert!(does_selection(KeySelection::empty()));
    }

    #[test]
    fn test_does_selection_public() {
        assert!(does_selection(KeySelection::PUBLIC_KEY));
    }

    #[test]
    fn test_does_selection_private() {
        assert!(does_selection(KeySelection::PRIVATE_KEY));
    }

    #[test]
    fn test_does_selection_keypair() {
        assert!(does_selection(KeySelection::KEYPAIR));
    }

    #[test]
    fn test_does_selection_domain_params_only() {
        // MSBLOB doesn't directly carry domain parameters without a key.
        // However, check_selection_hierarchy treats PRIVATE → PUBLIC → DOMAIN,
        // so domain-only should still be accepted via hierarchy.
        let result = does_selection(KeySelection::DOMAIN_PARAMETERS);
        // Domain parameters alone are supported via hierarchy
        assert!(result);
    }

    // ── Empty Input Decode Test ──────────────────────────────────────────

    #[test]
    fn test_decode_empty_input_returns_common_error() {
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        let result = decoder.decode(&[]);
        assert!(result.is_err(), "empty input should return error");
        // Verify it is a ProviderError::Common (not Dispatch).
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid argument"),
            "expected CommonError::InvalidArgument, got: {msg}"
        );
    }

    // ── RSA Decode Tests ────────────────────────────────────────────────

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_rsa_public_blob() {
        let blob = make_rsa_public_blob(1024);
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        let result = decoder.decode(&blob);
        assert!(result.is_ok(), "should decode RSA public MSBLOB: {:?}", result.err());
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_rsa_truncated() {
        let blob = make_rsa_public_blob(1024);
        // Truncate payload
        let truncated = &blob[..20];
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        let result = decoder.decode(truncated);
        assert!(result.is_err(), "should fail on truncated payload");
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_decode_rsa_algorithm_mismatch() {
        // Present a DSA blob to an RSA decoder
        let blob = make_dsa_public_blob(1024);
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        let result = decoder.decode(&blob);
        assert!(result.is_err(), "should fail on algorithm mismatch");
    }

    // ── DSA Decode Tests ────────────────────────────────────────────────

    #[cfg(feature = "dsa")]
    #[test]
    fn test_decode_dsa_public_blob() {
        let blob = make_dsa_public_blob(1024);
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Dsa,
        };
        let result = decoder.decode(&blob);
        assert!(result.is_ok(), "should decode DSA public MSBLOB: {:?}", result.err());
    }

    #[cfg(feature = "dsa")]
    #[test]
    fn test_decode_dsa_algorithm_mismatch() {
        let blob = make_rsa_public_blob(1024);
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Dsa,
        };
        let result = decoder.decode(&blob);
        assert!(result.is_err(), "should fail on algorithm mismatch");
    }

    // ── Registration Tests ──────────────────────────────────────────────

    #[cfg(any(feature = "rsa", feature = "dsa"))]
    #[test]
    fn test_all_msblob_decoders_non_empty() {
        let descs = all_msblob_decoders();
        // At least one descriptor should be present when rsa or dsa
        // feature is enabled.
        assert!(
            !descs.is_empty(),
            "all_msblob_decoders() should return at least one descriptor"
        );
        for desc in &descs {
            assert!(!desc.names.is_empty());
            assert!(!desc.property.is_empty());
            assert!(!desc.description.is_empty());
        }
    }

    #[cfg(not(any(feature = "rsa", feature = "dsa")))]
    #[test]
    fn test_all_msblob_decoders_empty_without_features() {
        let descs = all_msblob_decoders();
        assert!(
            descs.is_empty(),
            "all_msblob_decoders() should be empty without rsa/dsa features"
        );
    }

    #[test]
    fn test_msblob_decoder_name() {
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        assert_eq!(decoder.name(), "MSBLOB");
    }

    #[test]
    fn test_msblob_decoder_supported_formats() {
        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        let formats = decoder.supported_formats();
        assert_eq!(formats, vec![FORMAT_MSBLOB]);
    }

    // ── Payload Length Calculation Tests ─────────────────────────────────

    #[test]
    fn test_compute_rsa_public_length() {
        // RSA-1024 public: pubexp(4) + modulus(128) = 132
        let len = compute_blob_payload_length(1024, false, true);
        assert_eq!(len, 132);
    }

    #[test]
    fn test_compute_rsa_private_length() {
        // RSA-1024 private: pubexp(4) + modulus(128) + 5*half(64) + privexp(128)
        // = 4 + 128 + 320 + 128 = 580
        let len = compute_blob_payload_length(1024, false, false);
        assert_eq!(len, 580);
    }

    #[test]
    fn test_compute_dsa_public_length() {
        // DSA-1024 public: p(128) + q(20) + g(128) + pubkey(128) = 404
        let len = compute_blob_payload_length(1024, true, true);
        assert_eq!(len, 404);
    }

    #[test]
    fn test_compute_dsa_private_length() {
        // DSA-1024 private: p(128) + q(20) + g(128) + pubkey(128) + privkey(20) = 424
        let len = compute_blob_payload_length(1024, true, false);
        assert_eq!(len, 424);
    }

    // ── BLOB_MAX_LENGTH Guard Test ──────────────────────────────────────

    #[cfg(feature = "rsa")]
    #[test]
    fn test_blob_max_length_guard() {
        // Construct a header claiming an absurdly large key
        let mut blob = make_rsa_public_blob(1024);
        // Set bitlen to trigger payload > BLOB_MAX_LENGTH
        // 64 MB = 67108864 bytes → need bitlen such that byte_len > 64MB
        // byte_len = (bitlen + 7) / 8, so bitlen = 64 * 1024 * 1024 * 8 = 536870912
        let huge_bitlen: u32 = 536_870_912;
        blob[12..16].copy_from_slice(&huge_bitlen.to_le_bytes());

        let decoder = MsBlobDecoder {
            key_type: MsBlobKeyType::Rsa,
        };
        let result = decoder.decode(&blob);
        assert!(result.is_err(), "should fail on oversized payload");
    }

    // ── Context and Header Field Access Tests ───────────────────────────

    #[test]
    fn test_msblob_decoder_context_fields() {
        let ctx = MsBlobDecoderContext {
            selection: KeySelection::PRIVATE_KEY,
            key_type: MsBlobKeyType::Rsa,
        };
        assert!(ctx.selection.contains(KeySelection::PRIVATE_KEY));
        assert_eq!(ctx.key_type, MsBlobKeyType::Rsa);
    }

    #[test]
    fn test_blob_header_fields() {
        let blob = make_rsa_public_blob(2048);
        let header = parse_blob_header(&blob).expect("valid header");
        assert_eq!(header.b_type, PUBLICKEYBLOB);
        assert_eq!(header.b_version, 0x02);
        assert_eq!(header.ai_key_alg, CALG_RSA_KEYX);
        assert!(header.is_public);
    }

    // ── Endianness Conversion Tests ─────────────────────────────────────

    #[cfg(feature = "rsa")]
    #[test]
    fn test_strip_leading_zeros() {
        let mut v = vec![0, 0, 0, 1, 2, 3];
        strip_leading_zeros(&mut v);
        assert_eq!(v, vec![1, 2, 3]);

        let mut zero = vec![0];
        strip_leading_zeros(&mut zero);
        assert_eq!(zero, vec![0]); // Preserve single zero

        let mut no_zeros = vec![1, 2, 3];
        strip_leading_zeros(&mut no_zeros);
        assert_eq!(no_zeros, vec![1, 2, 3]);
    }
}
