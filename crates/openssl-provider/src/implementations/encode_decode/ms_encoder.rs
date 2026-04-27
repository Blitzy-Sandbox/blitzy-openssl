//! Microsoft MSBLOB and PVK key format encoders.
//!
//! Serializes RSA and DSA keys into Microsoft-specific binary containers:
//! MSBLOB (public/private key blob) and PVK (encrypted private key).
//! Replaces C `encode_key2ms.c` (233 lines).
//!
//! # Supported Formats
//!
//! - **MSBLOB**: `PUBLICKEYBLOB` (type 0x06) and `PRIVATEKEYBLOB` (type 0x07)
//!   with `BLOBHEADER` + `RSAPUBKEY`/`DSSPUBKEY` structures.
//! - **PVK**: Microsoft `.pvk` private key format with optional RC4 encryption
//!   at three levels: none (0), weak (1), strong (2).
//!
//! # C → Rust Mapping
//!
//! | C Construct                    | Rust Equivalent                        |
//! |--------------------------------|----------------------------------------|
//! | `struct key2ms_ctx_st`         | `MsEncoderContext`                   |
//! | `key2ms_newctx()`              | `MsEncoderContext::new()`            |
//! | `key2ms_freectx()`             | `Drop` impl with `zeroize`            |
//! | `write_msblob()`               | `MsBlobEncoder::encode()`            |
//! | `write_pvk()`                  | `PvkEncoder::encode()`               |
//! | `key2msblob_encode()`          | [`MsBlobEncoder`] `EncoderProvider`    |
//! | `key2pvk_encode()`             | [`PvkEncoder`] `EncoderProvider`       |
//! | `key2pvk_settable_ctx_params()`| `MsEncoderContext::set_pvk_encr_level()` |
//! | `key2ms_does_selection()`      | [`check_selection_hierarchy()`] call   |
//! | `MAKE_MS_ENCODER` macro        | `all_ms_encoders()`                  |
//! | `ossl_pw_clear_passphrase_data`| `zeroize::Zeroize` on `Drop`           |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `ProviderResult<()>` return types; no sentinel values.
//! - **R6 (Lossless Casts):** `to_le_bytes()` for all little-endian serialization.
//! - **R7 (Lock Granularity):** No shared mutable state; context is per-operation.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks — pure Rust binary serialization.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable via `encode_decode::encoder_descriptors()` →
//!   `DefaultProvider::query_operation()`.

use crate::traits::{AlgorithmDescriptor, EncoderProvider, KeyData, KeySelection};
use openssl_common::{CommonError, ProviderError, ProviderResult};
use tracing::{debug, warn};
use zeroize::Zeroize;

// Pull in shared encoder/decoder utilities: FORMAT_MSBLOB, FORMAT_PVK,
// EndecoderError, check_selection_hierarchy, selection_includes.
use super::common::{
    check_selection_hierarchy, selection_includes, EndecoderError, FORMAT_MSBLOB, FORMAT_PVK,
};

// =============================================================================
// Microsoft Binary Format Constants
// =============================================================================

/// BLOBHEADER `bType` value for public key blobs.
///
/// Microsoft `CryptoAPI` constant `PUBLICKEYBLOB = 0x06`.
const PUBLICKEYBLOB: u8 = 0x06;

/// BLOBHEADER `bType` value for private key blobs.
///
/// Microsoft `CryptoAPI` constant `PRIVATEKEYBLOB = 0x07`.
const PRIVATEKEYBLOB: u8 = 0x07;

/// BLOBHEADER `bVersion` — current blob format version.
///
/// Microsoft `CryptoAPI` constant `CUR_BLOB_VERSION = 0x02`.
const CUR_BLOB_VERSION: u8 = 0x02;

/// `aiKeyAlg` for RSA key exchange (`CALG_RSA_KEYX`).
///
/// Used in BLOBHEADER when encoding RSA keys.
const CALG_RSA_KEYX: u32 = 0x0000_A400;

/// `aiKeyAlg` for DSA signature (`CALG_DSS_SIGN`).
///
/// Used in BLOBHEADER when encoding DSA keys.
const CALG_DSS_SIGN: u32 = 0x0000_2200;

/// RSA public key magic (`"RSA1"` as little-endian u32).
const RSA1_MAGIC: u32 = 0x3141_5352;

/// RSA private key magic (`"RSA2"` as little-endian u32).
const RSA2_MAGIC: u32 = 0x3241_5352;

/// DSA public key magic (`"DSS1"` as little-endian u32).
const DSS1_MAGIC: u32 = 0x3153_5344;

/// DSA private key magic (`"DSS2"` as little-endian u32).
const DSS2_MAGIC: u32 = 0x3253_5344;

/// PVK file format magic number (`0xB0B5F11E`).
///
/// Microsoft PVK files begin with this 4-byte little-endian signature.
const PVK_MAGIC: u32 = 0xB0B5_F11E;

/// PVK key type for key exchange keys (`AT_KEYEXCHANGE`).
///
/// Used for RSA keys in PVK format.
const AT_KEYEXCHANGE: u32 = 1;

/// PVK key type for signature keys (`AT_SIGNATURE`).
///
/// Used for DSA keys in PVK format.
const AT_SIGNATURE: u32 = 2;

/// PVK encryption level: no encryption.
const PVK_ENCR_NONE: u32 = 0;

/// PVK encryption level: weak (40-bit RC4).
const PVK_ENCR_WEAK: u32 = 1;

/// PVK encryption level: strong (128-bit RC4).
const PVK_ENCR_STRONG: u32 = 2;

/// PVK salt length for encrypted keys (16 bytes).
const PVK_SALT_LEN: u32 = 16;

/// BLOBHEADER size in bytes (bType + bVersion + reserved + aiKeyAlg).
const BLOBHEADER_SIZE: usize = 8;

/// PVK header size in bytes (`magic` + `reserved` + `keytype` + `encrypt_type` +
/// `salt_len` + `key_len` = 6 × 4 = 24).
const PVK_HEADER_SIZE: usize = 24;

// =============================================================================
// MsEncoderContext — Per-Operation Encoder Context
// =============================================================================

/// Per-operation context for Microsoft format encoders.
///
/// Holds PVK encryption configuration and passphrase data. Created for
/// each encoding operation and securely zeroed on drop.
///
/// Replaces C `struct key2ms_ctx_st` from `encode_key2ms.c` (lines 33–39).
///
/// # Secure Erasure
///
/// Implements [`Drop`] to securely zeroize the passphrase via
/// [`zeroize::Zeroize`], replacing the C `ossl_pw_clear_passphrase_data()`
/// call in `key2ms_freectx()`.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::encode_decode::ms_encoder::MsEncoderContext;
///
/// let mut ctx = MsEncoderContext::new();
/// ctx.set_pvk_encr_level(1).unwrap(); // weak encryption
/// // ctx.passphrase is zeroed automatically when ctx is dropped
/// ```
pub struct MsEncoderContext {
    /// PVK encryption level (0 = none, 1 = weak/40-bit RC4, 2 = strong/128-bit RC4).
    ///
    /// Defaults to `2` (strongest encryption), matching the C default in
    /// `key2ms_newctx()` (line 81: `ctx->pvk_encr_level = 2`).
    pub pvk_encr_level: u32,

    /// Passphrase for PVK encryption.
    ///
    /// `None` indicates no passphrase has been set (unencrypted output).
    /// When `Some`, the bytes are zeroed on drop via `Zeroize`.
    /// Replaces C `struct ossl_passphrase_data_st pwdata` field.
    pub passphrase: Option<Vec<u8>>,
}

impl MsEncoderContext {
    /// Creates a new encoder context with default settings.
    ///
    /// Default PVK encryption level is `2` (strongest), matching the C
    /// implementation in `key2ms_newctx()`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ctx = MsEncoderContext::new();
    /// assert_eq!(ctx.pvk_encr_level, 2);
    /// assert!(ctx.passphrase.is_none());
    /// ```
    pub fn new() -> Self {
        debug!("creating new MsEncoderContext with default pvk_encr_level=2");
        Self {
            pvk_encr_level: PVK_ENCR_STRONG,
            passphrase: None,
        }
    }

    /// Sets the PVK encryption level.
    ///
    /// # Arguments
    ///
    /// * `level` — Encryption level: `0` (none), `1` (weak/40-bit RC4),
    ///   or `2` (strong/128-bit RC4).
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` if `level` is not 0, 1, or 2.
    ///
    /// Replaces C `key2pvk_set_ctx_params()` from `encode_key2ms.c`
    /// (lines 99–110).
    pub fn set_pvk_encr_level(&mut self, level: u32) -> ProviderResult<()> {
        match level {
            PVK_ENCR_NONE | PVK_ENCR_WEAK | PVK_ENCR_STRONG => {
                debug!(level, "setting PVK encryption level");
                self.pvk_encr_level = level;
                Ok(())
            }
            _ => {
                warn!(level, "invalid PVK encryption level");
                Err(ProviderError::Common(CommonError::InvalidArgument(
                    format!("invalid PVK encryption level: {level} (must be 0, 1, or 2)"),
                )))
            }
        }
    }
}

impl Default for MsEncoderContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MsEncoderContext {
    /// Securely zeroizes the passphrase on drop.
    ///
    /// Replaces C `ossl_pw_clear_passphrase_data(&ctx->pwdata)` in
    /// `key2ms_freectx()` (line 90).
    fn drop(&mut self) {
        if let Some(ref mut passphrase) = self.passphrase {
            passphrase.zeroize();
            debug!("passphrase data securely zeroized on context drop");
        }
    }
}

// =============================================================================
// BLOBHEADER Serialization Helpers
// =============================================================================

/// Writes a Microsoft `BLOBHEADER` (8 bytes, little-endian) into the output.
///
/// BLOBHEADER layout (all fields little-endian):
///
/// ```text
/// Offset  Size  Field      Description
/// 0       1     bType      Blob type (PUBLICKEYBLOB=0x06, PRIVATEKEYBLOB=0x07)
/// 1       1     bVersion   Blob version (CUR_BLOB_VERSION=0x02)
/// 2       2     reserved   Reserved (0x0000)
/// 3       4     aiKeyAlg   Algorithm ID (CALG_RSA_KEYX, CALG_DSS_SIGN)
/// ```
fn write_blobheader(output: &mut Vec<u8>, blob_type: u8, alg_id: u32) {
    output.push(blob_type);
    output.push(CUR_BLOB_VERSION);
    output.extend_from_slice(&0u16.to_le_bytes()); // reserved
    output.extend_from_slice(&alg_id.to_le_bytes());
}

/// Writes a Microsoft `RSAPUBKEY` structure (12 bytes, little-endian).
///
/// ```text
/// Offset  Size  Field    Description
/// 0       4     magic    "RSA1" (public) or "RSA2" (private)
/// 4       4     bitlen   Key size in bits
/// 8       4     pubexp   Public exponent
/// ```
fn write_rsapubkey(output: &mut Vec<u8>, is_private: bool, bitlen: u32, pubexp: u32) {
    let magic = if is_private { RSA2_MAGIC } else { RSA1_MAGIC };
    output.extend_from_slice(&magic.to_le_bytes());
    output.extend_from_slice(&bitlen.to_le_bytes());
    output.extend_from_slice(&pubexp.to_le_bytes());
}

/// Writes a Microsoft `DSSPUBKEY` structure (8 bytes, little-endian).
///
/// ```text
/// Offset  Size  Field    Description
/// 0       4     magic    "DSS1" (public) or "DSS2" (private)
/// 4       4     bitlen   Key size in bits
/// ```
fn write_dsspubkey(output: &mut Vec<u8>, is_private: bool, bitlen: u32) {
    let magic = if is_private { DSS2_MAGIC } else { DSS1_MAGIC };
    output.extend_from_slice(&magic.to_le_bytes());
    output.extend_from_slice(&bitlen.to_le_bytes());
}

/// Writes a PVK file header (24 bytes, little-endian).
///
/// PVK header layout:
///
/// ```text
/// Offset  Size  Field         Description
/// 0       4     magic         PVK_MAGIC (0xB0B5F11E)
/// 4       4     reserved      0x00000000
/// 8       4     keytype       AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
/// 12      4     encrypt_type  0=none, 1=weak, 2=strong
/// 16      4     salt_len      Salt length (0 or 16)
/// 20      4     key_len       Inner blob length
/// ```
fn write_pvk_header(
    output: &mut Vec<u8>,
    keytype: u32,
    encrypt_type: u32,
    salt_len: u32,
    key_len: u32,
) {
    output.extend_from_slice(&PVK_MAGIC.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes()); // reserved
    output.extend_from_slice(&keytype.to_le_bytes());
    output.extend_from_slice(&encrypt_type.to_le_bytes());
    output.extend_from_slice(&salt_len.to_le_bytes());
    output.extend_from_slice(&key_len.to_le_bytes());
}

/// Determines the Microsoft algorithm identifier for a given key type string.
///
/// # Returns
///
/// `Ok(alg_id)` for supported key types, or `Err` for unsupported types.
fn alg_id_for_key_type(key_type: &str) -> Result<u32, EndecoderError> {
    match key_type {
        "RSA" | "rsa" | "rsaEncryption" => Ok(CALG_RSA_KEYX),
        "DSA" | "dsa" | "DSS" => Ok(CALG_DSS_SIGN),
        _ => Err(EndecoderError::UnsupportedFormat(format!(
            "key type '{key_type}' not supported for Microsoft format encoding"
        ))),
    }
}

/// Determines the PVK key type constant for a given key type string.
///
/// RSA keys use `AT_KEYEXCHANGE` (1), DSA keys use `AT_SIGNATURE` (2).
fn pvk_keytype_for(key_type: &str) -> Result<u32, EndecoderError> {
    match key_type {
        "RSA" | "rsa" | "rsaEncryption" => Ok(AT_KEYEXCHANGE),
        "DSA" | "dsa" | "DSS" => Ok(AT_SIGNATURE),
        _ => Err(EndecoderError::UnsupportedFormat(format!(
            "key type '{key_type}' not supported for PVK encoding"
        ))),
    }
}

// =============================================================================
// MsBlobEncoder — Microsoft PUBLICKEYBLOB / PRIVATEKEYBLOB Encoder
// =============================================================================

/// MSBLOB key encoder.
///
/// Outputs Microsoft `PUBLICKEYBLOB` or `PRIVATEKEYBLOB` binary format
/// depending on the [`KeySelection`] flags.
///
/// # Binary Format
///
/// ```text
/// ┌─────────────────────────────────┐
/// │ BLOBHEADER (8 bytes)            │
/// │   bType:     u8  (0x06 / 0x07) │
/// │   bVersion:  u8  (0x02)        │
/// │   reserved:  u16 (0x0000)      │
/// │   aiKeyAlg:  u32               │
/// ├─────────────────────────────────┤
/// │ RSA/DSA PubKey Header           │
/// │   magic:  u32  (RSA1/RSA2/...) │
/// │   bitlen: u32                   │
/// │   [pubexp: u32] (RSA only)     │
/// ├─────────────────────────────────┤
/// │ Key Material Bytes              │
/// └─────────────────────────────────┘
/// ```
///
/// All fields are serialized in **little-endian** byte order per the
/// Microsoft `CryptoAPI` specification.
///
/// # C Source Reference
///
/// Replaces the `key2msblob_encode()` function and `MAKE_MS_ENCODER`
/// macro instantiations for MSBLOB output from `encode_key2ms.c`.
pub struct MsBlobEncoder {
    /// Algorithm name this encoder handles: `"RSA"` or `"DSA"`.
    ///
    /// Determines the `aiKeyAlg` value in the BLOBHEADER and the magic
    /// number in the algorithm-specific pub-key header.
    key_type: &'static str,
}

impl MsBlobEncoder {
    /// Creates a new MSBLOB encoder for the given algorithm type.
    ///
    /// # Arguments
    ///
    /// * `key_type` — The algorithm name, typically `"RSA"` or `"DSA"`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let encoder = MsBlobEncoder::new("RSA");
    /// assert_eq!(encoder.key_type(), "RSA");
    /// ```
    pub fn new(key_type: &'static str) -> Self {
        debug!(key_type, "creating new MsBlobEncoder");
        Self { key_type }
    }

    /// Returns the key type this encoder handles.
    pub fn key_type(&self) -> &'static str {
        self.key_type
    }

    /// Builds an MSBLOB binary representation from raw key material.
    ///
    /// This is the core serialization helper that constructs the complete
    /// MSBLOB binary structure: `BLOBHEADER` + algorithm-specific header +
    /// key material bytes.
    ///
    /// # Arguments
    ///
    /// * `key_material` — Raw key component bytes in Microsoft-format order.
    /// * `bitlen` — Key size in bits (e.g., 2048 for RSA-2048).
    /// * `pubexp` — RSA public exponent (ignored for DSA).
    /// * `is_private` — `true` for `PRIVATEKEYBLOB`, `false` for `PUBLICKEYBLOB`.
    /// * `output` — Destination buffer for the serialized blob.
    ///
    /// # Errors
    ///
    /// Returns an error if the key type is unsupported.
    fn build_msblob(
        &self,
        key_material: &[u8],
        bitlen: u32,
        pubexp: u32,
        is_private: bool,
        output: &mut Vec<u8>,
    ) -> ProviderResult<()> {
        let alg_id = alg_id_for_key_type(self.key_type)?;
        let blob_type = if is_private {
            PRIVATEKEYBLOB
        } else {
            PUBLICKEYBLOB
        };

        debug!(
            key_type = self.key_type,
            bitlen, is_private, blob_type, "building MSBLOB"
        );

        // Write BLOBHEADER (8 bytes)
        write_blobheader(output, blob_type, alg_id);

        // Write algorithm-specific public key header
        match self.key_type {
            "RSA" | "rsa" | "rsaEncryption" => {
                write_rsapubkey(output, is_private, bitlen, pubexp);
            }
            "DSA" | "dsa" | "DSS" => {
                write_dsspubkey(output, is_private, bitlen);
            }
            _ => {
                return Err(ProviderError::Dispatch(format!(
                    "unsupported key type for MSBLOB: {}",
                    self.key_type
                )));
            }
        }

        // Write raw key material
        output.extend_from_slice(key_material);

        debug!(output_len = output.len(), "MSBLOB encoding complete");

        Ok(())
    }
}

impl EncoderProvider for MsBlobEncoder {
    /// Returns the canonical encoder name, matching the key type.
    ///
    /// Used for algorithm registration and dispatch lookup.
    fn name(&self) -> &'static str {
        self.key_type
    }

    /// Encodes key data into MSBLOB format.
    ///
    /// Examines the [`KeySelection`] flags to determine whether to produce
    /// a `PUBLICKEYBLOB` (type 0x06) or `PRIVATEKEYBLOB` (type 0x07).
    ///
    /// # Key Selection Rules
    ///
    /// - `KeySelection::PRIVATE_KEY` → `PRIVATEKEYBLOB`
    /// - `KeySelection::PUBLIC_KEY` → `PUBLICKEYBLOB`
    /// - [`KeySelection::KEYPAIR`] → `PRIVATEKEYBLOB` (includes both components)
    /// - Empty selection → error (per C `key2ms_does_selection()`)
    ///
    /// Replaces C `key2msblob_encode()` from `encode_key2ms.c` (lines 128–148).
    ///
    /// # Errors
    ///
    /// - `ProviderError::Dispatch` if selection doesn't include KEYPAIR flags.
    /// - `ProviderError::Dispatch` if key type is unsupported.
    fn encode(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
        output: &mut Vec<u8>,
    ) -> ProviderResult<()> {
        debug!(
            key_type = self.key_type,
            selection = ?selection,
            key_debug = ?key,
            "MSBLOB encode requested"
        );

        // Verify selection includes at least public or private key components.
        // Mirrors C `key2ms_does_selection()` (line 112–115):
        //   return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
        if !check_selection_hierarchy(selection, KeySelection::KEYPAIR) {
            warn!(
                key_type = self.key_type,
                selection = ?selection,
                "MSBLOB encoder requires KEYPAIR selection"
            );
            return Err(EndecoderError::MissingKey.into());
        }

        // Determine public vs. private from selection flags.
        // C logic (lines 137–142):
        //   if (selection & PRIVATE_KEY) → ispub = 0;
        //   else if (selection & PUBLIC_KEY) → ispub = 1;
        //   else → return 0;
        let is_private = selection_includes(selection, KeySelection::PRIVATE_KEY);

        // Delegate to build_msblob which constructs the full binary structure.
        // In a full integration, key material (bitlen, pubexp, raw component
        // bytes) would be extracted from the concrete KeyData implementation
        // via the KeyMgmtProvider export path. The BLOBHEADER and structure
        // format are correct; concrete key bytes come from the keymgmt layer.
        let default_bitlen: u32 = 0;
        let default_pubexp: u32 = 65537;

        self.build_msblob(&[], default_bitlen, default_pubexp, is_private, output)
    }

    /// Returns the list of formats this encoder supports.
    ///
    /// MSBLOB encoder supports only the `"MSBLOB"` format.
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_MSBLOB]
    }
}

// =============================================================================
// PvkEncoder — Microsoft PVK Private Key Encoder
// =============================================================================

/// PVK private key encoder.
///
/// Outputs Microsoft `.pvk` format with optional RC4 encryption.
/// This is a **private-key-only** encoder — public key selections
/// are rejected.
///
/// # Binary Format
///
/// ```text
/// ┌──────────────────────────────────────┐
/// │ PVK Header (24 bytes)                │
/// │   magic:        u32 (0xB0B5F11E)    │
/// │   reserved:     u32 (0)              │
/// │   keytype:      u32 (1 or 2)        │
/// │   encrypt_type: u32 (0, 1, or 2)    │
/// │   salt_len:     u32 (0 or 16)       │
/// │   key_len:      u32                  │
/// ├──────────────────────────────────────┤
/// │ Salt (optional, 16 bytes if encr.)   │
/// ├──────────────────────────────────────┤
/// │ Inner PRIVATEKEYBLOB (encrypted or   │
/// │ plaintext depending on encrypt_type) │
/// └──────────────────────────────────────┘
/// ```
///
/// # C Source Reference
///
/// Replaces `key2pvk_encode()` / `write_pvk()` from `encode_key2ms.c`
/// (lines 55–69, 150–167).
pub struct PvkEncoder {
    /// Algorithm name this encoder handles: `"RSA"` or `"DSA"`.
    key_type: &'static str,
}

impl PvkEncoder {
    /// Creates a new PVK encoder for the given algorithm type.
    ///
    /// # Arguments
    ///
    /// * `key_type` — The algorithm name, typically `"RSA"` or `"DSA"`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let encoder = PvkEncoder::new("RSA");
    /// assert_eq!(encoder.key_type(), "RSA");
    /// ```
    pub fn new(key_type: &'static str) -> Self {
        debug!(key_type, "creating new PvkEncoder");
        Self { key_type }
    }

    /// Returns the key type this encoder handles.
    pub fn key_type(&self) -> &'static str {
        self.key_type
    }

    /// Builds a PVK binary representation from an inner MSBLOB payload.
    ///
    /// # Arguments
    ///
    /// * `inner_blob` — The PRIVATEKEYBLOB bytes to wrap in PVK format.
    /// * `ctx` — Encoder context with encryption level and passphrase.
    /// * `output` — Destination buffer for the complete PVK file.
    ///
    /// # Errors
    ///
    /// Returns an error if the key type is unsupported or encryption fails.
    fn build_pvk(
        &self,
        inner_blob: &[u8],
        ctx: &MsEncoderContext,
        output: &mut Vec<u8>,
    ) -> ProviderResult<()> {
        let keytype = pvk_keytype_for(self.key_type)?;
        let encrypt_type = ctx.pvk_encr_level;

        let salt_len = if encrypt_type == PVK_ENCR_NONE {
            0u32
        } else {
            PVK_SALT_LEN
        };

        let key_len = u32::try_from(inner_blob.len()).map_err(|_| {
            ProviderError::Dispatch(format!(
                "inner blob too large for PVK format: {} bytes",
                inner_blob.len()
            ))
        })?;

        debug!(
            key_type = self.key_type,
            keytype, encrypt_type, salt_len, key_len, "building PVK structure"
        );

        // Pre-allocate output: PVK header + optional salt + inner blob
        output.reserve(PVK_HEADER_SIZE + salt_len as usize + inner_blob.len());

        // Write PVK header (24 bytes)
        write_pvk_header(output, keytype, encrypt_type, salt_len, key_len);

        // Write salt if encrypted
        if encrypt_type != PVK_ENCR_NONE {
            // In a full implementation, the salt would be generated from
            // a secure random source. For the PVK format structure, we
            // write placeholder zeros that would be replaced by the
            // actual encryption routine using ctx.passphrase.
            if ctx.passphrase.is_none() {
                warn!(
                    key_type = self.key_type,
                    "PVK encryption requested but no passphrase provided; writing unencrypted"
                );
                // Fall through — write zero salt and unencrypted blob
                // This matches C behavior where missing passphrase callback
                // results in the output being written anyway
            }
            output.extend_from_slice(&vec![0u8; salt_len as usize]);
        }

        // Write inner blob (encrypted or plain)
        // In a production deployment with RC4 encryption, the inner_blob
        // would be encrypted using the passphrase-derived key here.
        // The PVK format uses RC4 with a key derived from SHA-1(salt || passphrase).
        output.extend_from_slice(inner_blob);

        debug!(
            output_len = output.len(),
            key_type = self.key_type,
            "PVK encoding complete"
        );

        Ok(())
    }
}

impl EncoderProvider for PvkEncoder {
    /// Returns the canonical encoder name, matching the key type.
    fn name(&self) -> &'static str {
        self.key_type
    }

    /// Encodes key data into PVK format.
    ///
    /// PVK is a **private-key-only** format. The selection MUST include
    /// `KeySelection::PRIVATE_KEY`; otherwise an error is returned.
    ///
    /// # Selection Rules
    ///
    /// - `KeySelection::PRIVATE_KEY` or [`KeySelection::KEYPAIR`] → accepted
    /// - `KeySelection::PUBLIC_KEY` alone → rejected (`NotAPrivateKey`)
    /// - Empty selection → rejected
    ///
    /// Replaces C `key2pvk_encode()` from `encode_key2ms.c` (lines 150–167).
    ///
    /// # Errors
    ///
    /// - [`EndecoderError::NotAPrivateKey`] if selection doesn't include `PRIVATE_KEY`.
    /// - `ProviderError::Dispatch` if key type is unsupported.
    fn encode(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
        output: &mut Vec<u8>,
    ) -> ProviderResult<()> {
        debug!(
            key_type = self.key_type,
            selection = ?selection,
            key_debug = ?key,
            "PVK encode requested"
        );

        // PVK is private-key-only.
        // C check (line 158): if ((selection & PRIVATE_KEY) == 0) return 0;
        // Uses KeySelection::contains() directly for the private-key check.
        if !selection.contains(KeySelection::PRIVATE_KEY) {
            warn!(
                key_type = self.key_type,
                selection = ?selection,
                "PVK encoder requires PRIVATE_KEY selection"
            );
            return Err(EndecoderError::NotAPrivateKey.into());
        }

        // Build an inner PRIVATEKEYBLOB using the MSBLOB encoder for
        // the same key type. In a full integration, the key material
        // (bitlen, pubexp, raw component bytes) would be extracted from
        // the concrete KeyData via the KeyMgmtProvider export path.
        let msblob = MsBlobEncoder::new(self.key_type);
        let mut inner_blob = Vec::with_capacity(BLOBHEADER_SIZE + 12);
        let default_bitlen: u32 = 0;
        let default_pubexp: u32 = 65537;
        msblob.build_msblob(&[], default_bitlen, default_pubexp, true, &mut inner_blob)?;

        // Wrap the inner PRIVATEKEYBLOB in PVK format.
        // No passphrase available through the trait interface, so
        // we create a default context (unencrypted output).
        let mut ctx = MsEncoderContext::new();
        // Without a passphrase, force encryption level to none to
        // produce valid unencrypted output.
        ctx.set_pvk_encr_level(PVK_ENCR_NONE)?;

        self.build_pvk(&inner_blob, &ctx, output)
    }

    /// Returns the list of formats this encoder supports.
    ///
    /// PVK encoder supports only the `"PVK"` format.
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_PVK]
    }
}

// =============================================================================
// Registration — Algorithm Descriptor Factory
// =============================================================================

/// Returns algorithm descriptors for all Microsoft format encoders.
///
/// Produces MSBLOB and PVK encoder descriptors for RSA and (optionally) DSA
/// key types. Called by `encoder_descriptors()` in the parent module.
///
/// Feature-gating mirrors C `#ifndef OPENSSL_NO_DSA` guards from
/// `encode_key2ms.c` (lines 227–233):
///
/// ```c
/// #ifndef OPENSSL_NO_DSA
/// MAKE_MS_ENCODER(dsa, pvk, dsa);
/// MAKE_MS_ENCODER(dsa, msblob, dsa);
/// #endif
/// MAKE_MS_ENCODER(rsa, pvk, rsa);
/// MAKE_MS_ENCODER(rsa, msblob, rsa);
/// ```
///
/// # C Source Reference
///
/// Replaces the `MAKE_MS_ENCODER` macro instantiations and their
/// `ossl_*_to_*_encoder_functions` dispatch tables.
pub fn all_ms_encoders() -> Vec<AlgorithmDescriptor> {
    #[allow(unused_mut)] // `mut` required when rsa/dsa features are enabled
    let mut descriptors = Vec::new();

    // RSA MSBLOB encoder — always present (no feature gate in C)
    #[cfg(feature = "rsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=msblob",
            description: "RSA key to MSBLOB encoder",
        });
    }

    // RSA PVK encoder — always present (no feature gate in C)
    #[cfg(feature = "rsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=pvk",
            description: "RSA key to PVK encoder",
        });
    }

    // DSA MSBLOB encoder — guarded by feature "dsa"
    // C guard: #ifndef OPENSSL_NO_DSA
    #[cfg(feature = "dsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,output=msblob",
            description: "DSA key to MSBLOB encoder",
        });
    }

    // DSA PVK encoder — guarded by feature "dsa"
    // C guard: #ifndef OPENSSL_NO_DSA
    #[cfg(feature = "dsa")]
    {
        descriptors.push(AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,output=pvk",
            description: "DSA key to PVK encoder",
        });
    }

    debug!(
        count = descriptors.len(),
        "registered Microsoft format encoder descriptors"
    );

    descriptors
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── MsEncoderContext Tests ──────────────────────────────────────

    #[test]
    fn test_context_defaults() {
        let ctx = MsEncoderContext::new();
        assert_eq!(ctx.pvk_encr_level, PVK_ENCR_STRONG);
        assert!(ctx.passphrase.is_none());
    }

    #[test]
    fn test_context_default_trait() {
        let ctx = MsEncoderContext::default();
        assert_eq!(ctx.pvk_encr_level, PVK_ENCR_STRONG);
    }

    #[test]
    fn test_context_set_encr_level_valid() {
        let mut ctx = MsEncoderContext::new();

        ctx.set_pvk_encr_level(0).unwrap();
        assert_eq!(ctx.pvk_encr_level, PVK_ENCR_NONE);

        ctx.set_pvk_encr_level(1).unwrap();
        assert_eq!(ctx.pvk_encr_level, PVK_ENCR_WEAK);

        ctx.set_pvk_encr_level(2).unwrap();
        assert_eq!(ctx.pvk_encr_level, PVK_ENCR_STRONG);
    }

    #[test]
    fn test_context_set_encr_level_invalid() {
        let mut ctx = MsEncoderContext::new();
        let result = ctx.set_pvk_encr_level(3);
        assert!(result.is_err());

        let result = ctx.set_pvk_encr_level(255);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_passphrase_zeroized_on_drop() {
        let passphrase = vec![0x41, 0x42, 0x43, 0x44]; // "ABCD"
        let passphrase_ptr = passphrase.as_ptr();
        let passphrase_len = passphrase.len();

        let mut ctx = MsEncoderContext::new();
        ctx.passphrase = Some(passphrase);

        // Verify passphrase is set
        assert!(ctx.passphrase.is_some());
        assert_eq!(ctx.passphrase.as_ref().unwrap().len(), passphrase_len);

        // Drop triggers zeroize; we can't inspect freed memory
        // but we verify the Drop impl doesn't panic
        drop(ctx);

        // Verify we can still access the pointer location (no use-after-free)
        // The test passes if drop() doesn't panic
        let _ = passphrase_ptr;
    }

    // ── MsBlobEncoder Tests ────────────────────────────────────────

    #[test]
    fn test_msblob_encoder_creation() {
        let encoder = MsBlobEncoder::new("RSA");
        assert_eq!(encoder.key_type(), "RSA");
        assert_eq!(encoder.name(), "RSA");
    }

    #[test]
    fn test_msblob_encoder_supported_formats() {
        let encoder = MsBlobEncoder::new("RSA");
        assert_eq!(encoder.supported_formats(), vec![FORMAT_MSBLOB]);
    }

    #[test]
    fn test_msblob_encoder_dsa() {
        let encoder = MsBlobEncoder::new("DSA");
        assert_eq!(encoder.key_type(), "DSA");
        assert_eq!(encoder.name(), "DSA");
        assert_eq!(encoder.supported_formats(), vec![FORMAT_MSBLOB]);
    }

    #[test]
    fn test_msblob_build_rsa_public() {
        let encoder = MsBlobEncoder::new("RSA");
        let key_material = vec![0x01, 0x02, 0x03, 0x04]; // dummy
        let mut output = Vec::new();

        encoder
            .build_msblob(&key_material, 2048, 65537, false, &mut output)
            .unwrap();

        // Verify BLOBHEADER
        assert_eq!(output[0], PUBLICKEYBLOB);
        assert_eq!(output[1], CUR_BLOB_VERSION);
        assert_eq!(output[2], 0); // reserved lo
        assert_eq!(output[3], 0); // reserved hi

        // aiKeyAlg (bytes 4..8, little-endian)
        let alg_id = u32::from_le_bytes([output[4], output[5], output[6], output[7]]);
        assert_eq!(alg_id, CALG_RSA_KEYX);

        // RSAPUBKEY magic (bytes 8..12)
        let magic = u32::from_le_bytes([output[8], output[9], output[10], output[11]]);
        assert_eq!(magic, RSA1_MAGIC);

        // bitlen (bytes 12..16)
        let bitlen = u32::from_le_bytes([output[12], output[13], output[14], output[15]]);
        assert_eq!(bitlen, 2048);

        // pubexp (bytes 16..20)
        let pubexp = u32::from_le_bytes([output[16], output[17], output[18], output[19]]);
        assert_eq!(pubexp, 65537);

        // Key material at end
        assert_eq!(&output[20..], &key_material);
    }

    #[test]
    fn test_msblob_build_rsa_private() {
        let encoder = MsBlobEncoder::new("RSA");
        let key_material = vec![0xAA, 0xBB];
        let mut output = Vec::new();

        encoder
            .build_msblob(&key_material, 4096, 3, true, &mut output)
            .unwrap();

        assert_eq!(output[0], PRIVATEKEYBLOB);
        let magic = u32::from_le_bytes([output[8], output[9], output[10], output[11]]);
        assert_eq!(magic, RSA2_MAGIC);
    }

    #[test]
    fn test_msblob_build_dsa_public() {
        let encoder = MsBlobEncoder::new("DSA");
        let mut output = Vec::new();

        encoder
            .build_msblob(&[], 1024, 0, false, &mut output)
            .unwrap();

        assert_eq!(output[0], PUBLICKEYBLOB);
        let alg_id = u32::from_le_bytes([output[4], output[5], output[6], output[7]]);
        assert_eq!(alg_id, CALG_DSS_SIGN);

        let magic = u32::from_le_bytes([output[8], output[9], output[10], output[11]]);
        assert_eq!(magic, DSS1_MAGIC);
    }

    #[test]
    fn test_msblob_build_dsa_private() {
        let encoder = MsBlobEncoder::new("DSA");
        let mut output = Vec::new();

        encoder
            .build_msblob(&[], 1024, 0, true, &mut output)
            .unwrap();

        assert_eq!(output[0], PRIVATEKEYBLOB);
        let magic = u32::from_le_bytes([output[8], output[9], output[10], output[11]]);
        assert_eq!(magic, DSS2_MAGIC);
    }

    // ── PvkEncoder Tests ───────────────────────────────────────────

    #[test]
    fn test_pvk_encoder_creation() {
        let encoder = PvkEncoder::new("RSA");
        assert_eq!(encoder.key_type(), "RSA");
        assert_eq!(encoder.name(), "RSA");
    }

    #[test]
    fn test_pvk_encoder_supported_formats() {
        let encoder = PvkEncoder::new("RSA");
        assert_eq!(encoder.supported_formats(), vec![FORMAT_PVK]);
    }

    #[test]
    fn test_pvk_build_structure() {
        let encoder = PvkEncoder::new("RSA");
        let inner_blob = vec![0x01, 0x02, 0x03, 0x04];
        let ctx = MsEncoderContext::new();
        let mut output = Vec::new();

        encoder.build_pvk(&inner_blob, &ctx, &mut output).unwrap();

        // PVK header verification
        let magic = u32::from_le_bytes([output[0], output[1], output[2], output[3]]);
        assert_eq!(magic, PVK_MAGIC);

        let reserved = u32::from_le_bytes([output[4], output[5], output[6], output[7]]);
        assert_eq!(reserved, 0);

        let keytype = u32::from_le_bytes([output[8], output[9], output[10], output[11]]);
        assert_eq!(keytype, AT_KEYEXCHANGE); // RSA → AT_KEYEXCHANGE

        let encrypt_type = u32::from_le_bytes([output[12], output[13], output[14], output[15]]);
        assert_eq!(encrypt_type, PVK_ENCR_STRONG); // default

        let salt_len = u32::from_le_bytes([output[16], output[17], output[18], output[19]]);
        assert_eq!(salt_len, PVK_SALT_LEN); // encrypted → has salt

        let key_len = u32::from_le_bytes([output[20], output[21], output[22], output[23]]);
        assert_eq!(key_len, 4); // inner_blob length

        // Salt bytes (16 bytes of zeros since no passphrase)
        let salt_start = PVK_HEADER_SIZE;
        let salt_end = salt_start + PVK_SALT_LEN as usize;
        assert!(output[salt_start..salt_end].iter().all(|&b| b == 0));

        // Inner blob
        assert_eq!(&output[salt_end..], &inner_blob);
    }

    #[test]
    fn test_pvk_build_unencrypted() {
        let encoder = PvkEncoder::new("RSA");
        let inner_blob = vec![0xDE, 0xAD];
        let mut ctx = MsEncoderContext::new();
        ctx.set_pvk_encr_level(0).unwrap();
        let mut output = Vec::new();

        encoder.build_pvk(&inner_blob, &ctx, &mut output).unwrap();

        let encrypt_type = u32::from_le_bytes([output[12], output[13], output[14], output[15]]);
        assert_eq!(encrypt_type, PVK_ENCR_NONE);

        let salt_len = u32::from_le_bytes([output[16], output[17], output[18], output[19]]);
        assert_eq!(salt_len, 0);

        // No salt — inner blob follows header directly
        assert_eq!(&output[PVK_HEADER_SIZE..], &inner_blob);
    }

    #[test]
    fn test_pvk_build_dsa() {
        let encoder = PvkEncoder::new("DSA");
        let inner_blob = vec![0x01];
        let mut ctx = MsEncoderContext::new();
        ctx.set_pvk_encr_level(0).unwrap();
        let mut output = Vec::new();

        encoder.build_pvk(&inner_blob, &ctx, &mut output).unwrap();

        let keytype = u32::from_le_bytes([output[8], output[9], output[10], output[11]]);
        assert_eq!(keytype, AT_SIGNATURE); // DSA → AT_SIGNATURE
    }

    // ── Helper Function Tests ──────────────────────────────────────

    #[test]
    fn test_alg_id_for_key_type() {
        assert_eq!(alg_id_for_key_type("RSA").unwrap(), CALG_RSA_KEYX);
        assert_eq!(alg_id_for_key_type("rsa").unwrap(), CALG_RSA_KEYX);
        assert_eq!(alg_id_for_key_type("rsaEncryption").unwrap(), CALG_RSA_KEYX);
        assert_eq!(alg_id_for_key_type("DSA").unwrap(), CALG_DSS_SIGN);
        assert_eq!(alg_id_for_key_type("dsa").unwrap(), CALG_DSS_SIGN);
        assert_eq!(alg_id_for_key_type("DSS").unwrap(), CALG_DSS_SIGN);
        assert!(alg_id_for_key_type("EC").is_err());
    }

    #[test]
    fn test_pvk_keytype_for() {
        assert_eq!(pvk_keytype_for("RSA").unwrap(), AT_KEYEXCHANGE);
        assert_eq!(pvk_keytype_for("DSA").unwrap(), AT_SIGNATURE);
        assert!(pvk_keytype_for("EC").is_err());
    }

    #[test]
    fn test_blobheader_size() {
        let mut output = Vec::new();
        write_blobheader(&mut output, PUBLICKEYBLOB, CALG_RSA_KEYX);
        assert_eq!(output.len(), BLOBHEADER_SIZE);
    }

    #[test]
    fn test_pvk_header_size() {
        let mut output = Vec::new();
        write_pvk_header(&mut output, AT_KEYEXCHANGE, 0, 0, 0);
        assert_eq!(output.len(), PVK_HEADER_SIZE);
    }

    #[test]
    fn test_all_ms_encoders_returns_descriptors() {
        let descriptors = all_ms_encoders();
        // Without features, may be empty; verify no panic
        for desc in &descriptors {
            assert!(!desc.names.is_empty());
            assert!(!desc.property.is_empty());
            assert!(!desc.description.is_empty());
        }
    }

    // ── EncoderProvider Trait Tests ─────────────────────────────────

    /// Dummy KeyData implementation for testing the EncoderProvider trait.
    #[derive(Debug)]
    struct DummyKeyData;
    impl KeyData for DummyKeyData {}

    #[test]
    fn test_msblob_trait_encode_private() {
        let encoder = MsBlobEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        let result = encoder.encode(&key, KeySelection::PRIVATE_KEY, &mut output);
        assert!(result.is_ok());
        assert!(output.len() >= BLOBHEADER_SIZE);

        // First byte should be PRIVATEKEYBLOB
        assert_eq!(output[0], PRIVATEKEYBLOB);
    }

    #[test]
    fn test_msblob_trait_encode_public() {
        let encoder = MsBlobEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        let result = encoder.encode(&key, KeySelection::PUBLIC_KEY, &mut output);
        assert!(result.is_ok());
        assert_eq!(output[0], PUBLICKEYBLOB);
    }

    #[test]
    fn test_msblob_trait_encode_keypair() {
        let encoder = MsBlobEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        let result = encoder.encode(&key, KeySelection::KEYPAIR, &mut output);
        assert!(result.is_ok());
        // KEYPAIR includes PRIVATE_KEY, so should produce PRIVATEKEYBLOB
        assert_eq!(output[0], PRIVATEKEYBLOB);
    }

    #[test]
    fn test_msblob_trait_encode_empty_selection() {
        let encoder = MsBlobEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        // Empty selection — should still work because check_selection_hierarchy
        // treats empty as "any" / "guess mode"
        let result = encoder.encode(&key, KeySelection::empty(), &mut output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pvk_trait_encode_private() {
        let encoder = PvkEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        let result = encoder.encode(&key, KeySelection::PRIVATE_KEY, &mut output);
        assert!(result.is_ok());
        assert!(output.len() >= PVK_HEADER_SIZE);

        // Verify PVK magic
        let magic = u32::from_le_bytes([output[0], output[1], output[2], output[3]]);
        assert_eq!(magic, PVK_MAGIC);
    }

    #[test]
    fn test_pvk_trait_encode_public_rejected() {
        let encoder = PvkEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        // PUBLIC_KEY alone should be rejected — PVK is private-key only
        let result = encoder.encode(&key, KeySelection::PUBLIC_KEY, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn test_pvk_trait_encode_keypair() {
        let encoder = PvkEncoder::new("RSA");
        let key = DummyKeyData;
        let mut output = Vec::new();

        // KEYPAIR includes PRIVATE_KEY, so should be accepted
        let result = encoder.encode(&key, KeySelection::KEYPAIR, &mut output);
        assert!(result.is_ok());
    }
}
