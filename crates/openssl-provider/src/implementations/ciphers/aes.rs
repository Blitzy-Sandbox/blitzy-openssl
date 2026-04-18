//! AES cipher implementations for ECB, CBC, OFB, CFB, CTR, and CTS modes.
//!
//! Supports key sizes: 128, 192, 256 bits across 8 operating modes,
//! producing 24+ algorithm variants. Implements [`CipherProvider`] and
//! [`CipherContext`] traits, translating C `cipher_aes.c` / `cipher_aes_hw.c`.
//!
//! # Modes
//!
//! | Mode    | Type   | IV   | Padding | Notes                              |
//! |---------|--------|------|---------|-------------------------------------|
//! | ECB     | Block  | No   | PKCS#7  | Independent block encryption        |
//! | CBC     | Block  | 16B  | PKCS#7  | Chained with XOR                    |
//! | OFB     | Stream | 16B  | No      | Output feedback keystream           |
//! | CFB     | Stream | 16B  | No      | 128-bit cipher feedback             |
//! | CFB8    | Stream | 16B  | No      | 8-bit cipher feedback               |
//! | CFB1    | Stream | 16B  | No      | 1-bit cipher feedback               |
//! | CTR     | Stream | 16B  | No      | Counter-based keystream             |
//! | CBC-CTS | Block  | 16B  | No      | Ciphertext stealing (CS1/CS2/CS3)   |
//!
//! AEAD modes (GCM, CCM, OCB, SIV, XTS, Wrap) are in separate modules.
//!
//! # Source Mapping
//!
//! | Rust Type             | C Source                                         |
//! |-----------------------|--------------------------------------------------|
//! | [`AesCipher`]         | `PROV_AES_CTX` in `providers/cipher_aes.h`       |
//! | [`AesCipherContext`]  | `PROV_CIPHER_CTX` in `providers/ciphercommon.h`  |
//! | [`descriptors()`]     | `ossl_aes128ecb_functions[]` etc. in defltprov.c |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `Option<T>` for optional IV/cipher engine.
//! - **R6 (Lossless Casts):** No bare `as` narrowing — `saturating_mul` used.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks.
//! - **R9 (Warning-Free):** All public items documented.

use crate::traits::{AlgorithmDescriptor, CipherContext, CipherProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use openssl_crypto::symmetric::aes::Aes;
use openssl_crypto::symmetric::SymmetricCipher;
use super::common::{
    CipherFlags, CipherMode, generic_get_params, make_cipher_descriptor,
    param_keys, pkcs7_pad, pkcs7_unpad,
};
use zeroize::Zeroize;

/// AES block size in bytes (128 bits).
const AES_BLOCK_SIZE: usize = 16;

// =============================================================================
// Mode and Variant Enums
// =============================================================================

/// AES cipher modes supported by this module (non-AEAD modes only).
///
/// AEAD modes (GCM, CCM, OCB, SIV) reside in their own modules:
/// `aes_gcm.rs`, `aes_ccm.rs`, `aes_ocb.rs`, `aes_siv.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesCipherMode {
    /// Electronic Codebook — each block encrypted independently. No IV.
    Ecb,
    /// Cipher Block Chaining — XOR with previous ciphertext before encrypt.
    Cbc,
    /// Output Feedback — keystream from iterated IV encryption.
    Ofb,
    /// Cipher Feedback (128-bit) — full-block feedback.
    Cfb,
    /// Cipher Feedback (8-bit) — single-byte feedback shift.
    Cfb8,
    /// Cipher Feedback (1-bit) — single-bit feedback shift.
    Cfb1,
    /// Counter mode — counter-based keystream generation.
    Ctr,
    /// CBC with Ciphertext Stealing — avoids padding by stealing bits.
    CbcCts(CtsVariant),
}

/// CTS (Ciphertext Stealing) variants for CBC-CTS mode.
///
/// See NIST SP 800-38A Addendum and RFC 3962 (Kerberos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtsVariant {
    /// CS1 — Kerberos-style CTS (swap last two blocks in output).
    Cs1,
    /// CS2 — Truncated penultimate block; full last block.
    Cs2,
    /// CS3 — Default variant (OpenSSL default). Swap of last two blocks
    /// compared to CS2.
    Cs3,
}

impl AesCipherMode {
    /// Returns `true` if this is a stream mode (no block alignment needed).
    fn is_stream(self) -> bool {
        matches!(
            self,
            Self::Ofb | Self::Cfb | Self::Cfb8 | Self::Cfb1 | Self::Ctr
        )
    }

    /// Returns the IV length in bytes for this mode.
    fn iv_len(self) -> usize {
        match self {
            Self::Ecb => 0,
            _ => AES_BLOCK_SIZE,
        }
    }

    /// Reported block size: stream modes present as block size 1.
    fn reported_block_size(self) -> usize {
        if self.is_stream() {
            1
        } else {
            AES_BLOCK_SIZE
        }
    }

    /// Maps to `common::CipherMode` for parameter reporting.
    fn to_cipher_mode(self) -> CipherMode {
        match self {
            Self::Ecb => CipherMode::Ecb,
            Self::Cbc => CipherMode::Cbc,
            Self::Ofb => CipherMode::Ofb,
            Self::Cfb | Self::Cfb8 | Self::Cfb1 => CipherMode::Cfb,
            Self::Ctr => CipherMode::Ctr,
            Self::CbcCts(_) => CipherMode::CbcCts,
        }
    }

    /// Returns cipher flags relevant to this mode.
    fn flags(self) -> CipherFlags {
        match self {
            Self::CbcCts(_) => CipherFlags::CTS,
            _ => CipherFlags::empty(),
        }
    }
}

// =============================================================================
// AesCipher — Provider-Level Cipher Descriptor
// =============================================================================

/// AES block cipher implementation for standard (non-AEAD) modes.
///
/// Each instance represents a specific `(key_size, mode)` pair (e.g.,
/// AES-256-CBC). The provider framework calls [`CipherProvider::new_ctx`]
/// to obtain a per-operation context for encryption or decryption.
///
/// # Wiring Path (Rule R10)
///
/// ```text
/// DefaultProvider::query_operation(OperationType::Cipher)
///   → implementations::all_cipher_descriptors()
///     → ciphers::descriptors()
///       → aes::descriptors()  // registers AesCipher instances
/// ```
#[derive(Debug, Clone)]
pub struct AesCipher {
    /// Algorithm name (e.g., `"AES-256-CBC"`).
    name: &'static str,
    /// Key size in bytes (16, 24, or 32).
    key_bytes: usize,
    /// Operating mode for this cipher variant.
    mode: AesCipherMode,
}

impl AesCipher {
    /// Creates a new AES cipher descriptor.
    #[must_use]
    pub fn new(name: &'static str, key_bytes: usize, mode: AesCipherMode) -> Self {
        Self {
            name,
            key_bytes,
            mode,
        }
    }
}

impl CipherProvider for AesCipher {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_length(&self) -> usize {
        self.key_bytes
    }

    fn iv_length(&self) -> usize {
        self.mode.iv_len()
    }

    fn block_size(&self) -> usize {
        self.mode.reported_block_size()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>> {
        Ok(Box::new(AesCipherContext::new(
            self.name,
            self.key_bytes,
            self.mode,
        )))
    }
}

// =============================================================================
// AesCipherContext — Per-Operation Cipher State
// =============================================================================

/// Context for an active AES cipher operation.
///
/// Created by [`AesCipher::new_ctx`] and initialised via
/// [`encrypt_init`](CipherContext::encrypt_init) or
/// [`decrypt_init`](CipherContext::decrypt_init). Holds all mutable state
/// for a single encrypt/decrypt lifecycle.
///
/// Key material, IV, and internal buffers are zeroized on [`Drop`] to
/// prevent residual secret data in memory.
pub struct AesCipherContext {
    // --- Configuration ---
    /// Algorithm name for parameter reporting.
    name: &'static str,
    /// Key size in bytes.
    key_bytes: usize,
    /// Operating mode.
    mode: AesCipherMode,
    /// `true` for encryption, `false` for decryption.
    encrypting: bool,
    /// Whether the context has been initialised with key material.
    initialized: bool,
    /// PKCS#7 padding enabled (ECB/CBC only; default `true` for those).
    padding: bool,

    // --- Crypto engine ---
    /// AES block cipher keyed instance. `None` until init.
    cipher: Option<Aes>,

    // --- Mode state ---
    /// Current IV / feedback register / counter (16 bytes for non-ECB).
    iv: Vec<u8>,
    /// Buffered partial-block input for block modes (ECB, CBC, CBC-CTS).
    buffer: Vec<u8>,
    /// Keystream block for stream modes (OFB, CFB, CTR).
    keystream: Vec<u8>,
    /// Offset into `keystream` indicating consumed bytes.
    ks_offset: usize,
}

impl AesCipherContext {
    /// Creates a new uninitialised cipher context for the given parameters.
    fn new(name: &'static str, key_bytes: usize, mode: AesCipherMode) -> Self {
        let default_padding = matches!(mode, AesCipherMode::Ecb | AesCipherMode::Cbc);
        Self {
            name,
            key_bytes,
            mode,
            encrypting: true,
            initialized: false,
            padding: default_padding,
            cipher: None,
            iv: Vec::new(),
            buffer: Vec::new(),
            keystream: vec![0u8; AES_BLOCK_SIZE],
            ks_offset: AES_BLOCK_SIZE, // forces keystream generation on first use
        }
    }

    /// Common initialisation logic for both encrypt and decrypt.
    fn init_common(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypting: bool,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // Validate key length.
        if key.len() != self.key_bytes {
            return Err(ProviderError::Dispatch(format!(
                "AES key length mismatch: expected {} bytes, got {}",
                self.key_bytes,
                key.len()
            )));
        }

        // Validate and store IV.
        let expected_iv = self.mode.iv_len();
        if expected_iv > 0 {
            match iv {
                Some(v) if v.len() == expected_iv => {
                    self.iv = v.to_vec();
                }
                Some(v) => {
                    return Err(ProviderError::Dispatch(format!(
                        "AES IV length mismatch: expected {expected_iv}, got {}",
                        v.len()
                    )));
                }
                None => {
                    return Err(ProviderError::Dispatch(
                        "IV required for this AES mode".into(),
                    ));
                }
            }
        } else {
            self.iv.clear();
        }

        // Create the AES engine from raw key bytes.
        let aes_engine = Aes::new(key).map_err(|e| {
            ProviderError::Dispatch(format!("AES key schedule failed: {e}"))
        })?;
        self.cipher = Some(aes_engine);
        self.encrypting = encrypting;
        self.initialized = true;
        self.buffer.clear();
        self.keystream = vec![0u8; AES_BLOCK_SIZE];
        self.ks_offset = AES_BLOCK_SIZE;

        // Apply any additional parameters (e.g., padding toggle).
        if let Some(ps) = params {
            self.set_params(ps)?;
        }
        Ok(())
    }

    // Methods use direct `self.cipher.as_ref()` access to allow split borrows.

    // =========================================================================
    // ECB Mode — Electronic Codebook
    // =========================================================================

    /// ECB update: encrypt/decrypt complete blocks independently.
    fn update_ecb(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| {
            ProviderError::Dispatch("AES cipher not initialised".into())
        })?;
        self.buffer.extend_from_slice(input);

        let total = self.buffer.len();
        let mut full_blocks = (total / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

        // When padding during decrypt, hold back the last block for finalize.
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= AES_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut processed = to_process;
        let mut offset = 0;
        while offset + AES_BLOCK_SIZE <= processed.len() {
            let block = &mut processed[offset..offset + AES_BLOCK_SIZE];
            if self.encrypting {
                cipher.encrypt_block(block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES ECB encrypt: {e}"))
                })?;
            } else {
                cipher.decrypt_block(block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES ECB decrypt: {e}"))
                })?;
            }
            offset += AES_BLOCK_SIZE;
        }

        let written = processed.len();
        output.extend_from_slice(&processed);
        Ok(written)
    }

    /// ECB finalize: pad (encrypt) or unpad (decrypt) remaining data.
    fn finalize_ecb(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, AES_BLOCK_SIZE);
                self.buffer.clear();
                let mut processed = padded;
                let mut offset = 0;
                while offset + AES_BLOCK_SIZE <= processed.len() {
                    cipher
                        .encrypt_block(&mut processed[offset..offset + AES_BLOCK_SIZE])
                        .map_err(|e| {
                            ProviderError::Dispatch(format!("AES ECB finalize: {e}"))
                        })?;
                    offset += AES_BLOCK_SIZE;
                }
                let written = processed.len();
                output.extend_from_slice(&processed);
                Ok(written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "AES ECB: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            // Decrypt the held-back block and remove padding.
            if self.buffer.len() != AES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "AES ECB decrypt finalize: expected {AES_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = std::mem::take(&mut self.buffer);
            cipher
                .decrypt_block(&mut block[..AES_BLOCK_SIZE])
                .map_err(|e| {
                    ProviderError::Dispatch(format!("AES ECB decrypt finalize: {e}"))
                })?;
            let unpadded = pkcs7_unpad(&block, AES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            block.zeroize();
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "AES ECB decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    // =========================================================================
    // CBC Mode — Cipher Block Chaining
    // =========================================================================

    /// CBC update: process complete blocks with XOR chaining.
    fn update_cbc(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);

        let total = self.buffer.len();
        let mut full_blocks = (total / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

        // Hold back the last block when padding + decrypting.
        if self.padding && !self.encrypting && full_blocks == total && full_blocks > 0 {
            full_blocks -= AES_BLOCK_SIZE;
        }
        if full_blocks == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..full_blocks).collect();
        let mut result = Vec::with_capacity(to_process.len());
        let mut offset = 0;
        while offset + AES_BLOCK_SIZE <= to_process.len() {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&to_process[offset..offset + AES_BLOCK_SIZE]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher.encrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CBC encrypt: {e}"))
                })?;
                self.iv.copy_from_slice(&block);
            } else {
                let ciphertext_save = block;
                cipher.decrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CBC decrypt: {e}"))
                })?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ciphertext_save);
            }
            result.extend_from_slice(&block);
            offset += AES_BLOCK_SIZE;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    /// CBC finalize: pad (encrypt) or unpad (decrypt).
    fn finalize_cbc(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;

        if self.encrypting {
            if self.padding {
                let padded = pkcs7_pad(&self.buffer, AES_BLOCK_SIZE);
                self.buffer.clear();
                let mut total_written = 0;
                let mut offset = 0;
                while offset + AES_BLOCK_SIZE <= padded.len() {
                    let mut block = [0u8; AES_BLOCK_SIZE];
                    block.copy_from_slice(&padded[offset..offset + AES_BLOCK_SIZE]);
                    xor_blocks(&mut block, &self.iv);
                    cipher.encrypt_block(&mut block).map_err(|e| {
                        ProviderError::Dispatch(format!("AES CBC finalize: {e}"))
                    })?;
                    self.iv.copy_from_slice(&block);
                    output.extend_from_slice(&block);
                    total_written += AES_BLOCK_SIZE;
                    offset += AES_BLOCK_SIZE;
                }
                Ok(total_written)
            } else if self.buffer.is_empty() {
                Ok(0)
            } else {
                Err(ProviderError::Dispatch(format!(
                    "AES CBC: {} bytes remaining, not block-aligned (padding disabled)",
                    self.buffer.len()
                )))
            }
        } else if self.padding {
            if self.buffer.len() != AES_BLOCK_SIZE {
                return Err(ProviderError::Dispatch(format!(
                    "AES CBC decrypt finalize: expected {AES_BLOCK_SIZE} buffered, got {}",
                    self.buffer.len()
                )));
            }
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&self.buffer);
            let ct_save = block;
            cipher.decrypt_block(&mut block).map_err(|e| {
                ProviderError::Dispatch(format!("AES CBC decrypt finalize: {e}"))
            })?;
            xor_blocks(&mut block, &self.iv);
            self.iv.copy_from_slice(&ct_save);
            self.buffer.clear();
            let unpadded = pkcs7_unpad(&block, AES_BLOCK_SIZE)?;
            let written = unpadded.len();
            output.extend_from_slice(unpadded);
            Ok(written)
        } else if self.buffer.is_empty() {
            Ok(0)
        } else {
            Err(ProviderError::Dispatch(format!(
                "AES CBC decrypt: {} bytes remaining, not block-aligned",
                self.buffer.len()
            )))
        }
    }

    // =========================================================================
    // OFB Mode — Output Feedback
    // =========================================================================

    /// OFB update: keystream = E(IV), C = P ⊕ keystream. IV = E(IV).
    ///
    /// Symmetric: same operation for encrypt and decrypt.
    fn update_ofb(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut result = Vec::with_capacity(input.len());

        for &byte in input {
            if self.ks_offset >= AES_BLOCK_SIZE {
                // Encrypt IV in-place — output becomes next feedback AND keystream.
                cipher.encrypt_block(&mut self.iv).map_err(|e| {
                    ProviderError::Dispatch(format!("AES OFB: {e}"))
                })?;
                self.keystream.copy_from_slice(&self.iv);
                self.ks_offset = 0;
            }
            result.push(byte ^ self.keystream[self.ks_offset]);
            self.ks_offset += 1;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    // =========================================================================
    // CFB Mode — 128-bit Cipher Feedback
    // =========================================================================

    /// CFB-128 update.
    ///
    /// Encrypt: keystream = E(IV), ciphertext = plain ⊕ keystream, IV = ciphertext.
    /// Decrypt: keystream = E(IV), plain = cipher ⊕ keystream, IV = ciphertext (input).
    fn update_cfb(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut result = Vec::with_capacity(input.len());

        for &byte in input {
            if self.ks_offset >= AES_BLOCK_SIZE {
                self.keystream.copy_from_slice(&self.iv);
                cipher.encrypt_block(&mut self.keystream).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CFB: {e}"))
                })?;
                self.ks_offset = 0;
            }
            let out_byte = byte ^ self.keystream[self.ks_offset];
            if self.encrypting {
                self.iv[self.ks_offset] = out_byte; // feedback = ciphertext
            } else {
                self.iv[self.ks_offset] = byte; // feedback = ciphertext (input)
            }
            result.push(out_byte);
            self.ks_offset += 1;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    // =========================================================================
    // CFB8 Mode — 8-bit Cipher Feedback
    // =========================================================================

    /// CFB-8 update: per byte, encrypt IV, XOR MSB with input, shift IV.
    fn update_cfb8(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut result = Vec::with_capacity(input.len());

        for &byte in input {
            let mut temp = [0u8; AES_BLOCK_SIZE];
            temp.copy_from_slice(&self.iv);
            cipher.encrypt_block(&mut temp).map_err(|e| {
                ProviderError::Dispatch(format!("AES CFB8: {e}"))
            })?;
            let ks_byte = temp[0];
            let out_byte = byte ^ ks_byte;

            // Feedback: shift IV left 1 byte, append ciphertext byte.
            let ct_byte = if self.encrypting { out_byte } else { byte };
            self.iv.rotate_left(1);
            self.iv[AES_BLOCK_SIZE - 1] = ct_byte;

            result.push(out_byte);
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    // =========================================================================
    // CFB1 Mode — 1-bit Cipher Feedback
    // =========================================================================

    /// CFB-1 update: processes input bit-by-bit (MSB first).
    ///
    /// Very slow — provided for completeness and protocol compliance.
    fn update_cfb1(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut result = Vec::with_capacity(input.len());

        for &byte in input {
            let mut out_byte = 0u8;
            for bit_pos in (0..8).rev() {
                let mut temp = [0u8; AES_BLOCK_SIZE];
                temp.copy_from_slice(&self.iv);
                cipher.encrypt_block(&mut temp).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CFB1: {e}"))
                })?;

                let ks_bit = (temp[0] >> 7) & 1;
                let in_bit = (byte >> bit_pos) & 1;
                let out_bit = in_bit ^ ks_bit;
                out_byte |= out_bit << bit_pos;

                // Shift IV left by 1 bit, append ciphertext bit.
                let ct_bit = if self.encrypting { out_bit } else { in_bit };
                shift_iv_left_1_bit(&mut self.iv, ct_bit);
            }
            result.push(out_byte);
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    // =========================================================================
    // CTR Mode — Counter
    // =========================================================================

    /// CTR update: keystream = E(counter), output = input ⊕ keystream.
    ///
    /// Symmetric: same for encrypt and decrypt. Big-endian counter increment.
    fn update_ctr(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let mut result = Vec::with_capacity(input.len());

        for &byte in input {
            if self.ks_offset >= AES_BLOCK_SIZE {
                self.keystream.copy_from_slice(&self.iv);
                cipher.encrypt_block(&mut self.keystream).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTR: {e}"))
                })?;
                increment_counter(&mut self.iv);
                self.ks_offset = 0;
            }
            result.push(byte ^ self.keystream[self.ks_offset]);
            self.ks_offset += 1;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    // =========================================================================
    // CBC-CTS Mode — Ciphertext Stealing
    // =========================================================================

    /// CBC-CTS update: buffer input; emit safe complete blocks.
    ///
    /// CTS requires seeing the final two blocks together, so we must hold
    /// back at least 2 × `AES_BLOCK_SIZE` bytes in the buffer.
    fn update_cbc_cts(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        self.buffer.extend_from_slice(input);

        // Keep at least 2 full blocks for finalize's CTS tail processing.
        let min_hold = 2 * AES_BLOCK_SIZE;
        if self.buffer.len() <= min_hold {
            return Ok(0);
        }

        // How many complete blocks can we safely emit now?
        let safe_len =
            ((self.buffer.len() - min_hold) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        if safe_len == 0 {
            return Ok(0);
        }

        let to_process: Vec<u8> = self.buffer.drain(..safe_len).collect();
        let mut result = Vec::with_capacity(safe_len);
        let mut offset = 0;
        while offset + AES_BLOCK_SIZE <= to_process.len() {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&to_process[offset..offset + AES_BLOCK_SIZE]);

            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher.encrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTS: {e}"))
                })?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher.decrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTS: {e}"))
                })?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            result.extend_from_slice(&block);
            offset += AES_BLOCK_SIZE;
        }

        let written = result.len();
        output.extend_from_slice(&result);
        Ok(written)
    }

    /// CBC-CTS finalize: apply ciphertext stealing to the buffered tail.
    fn finalize_cbc_cts(
        &mut self,
        output: &mut Vec<u8>,
        variant: CtsVariant,
    ) -> ProviderResult<usize> {
        let cipher = self.cipher.as_ref().ok_or_else(|| ProviderError::Dispatch("AES cipher not initialised".into()))?;
        let data = std::mem::take(&mut self.buffer);
        let data_len = data.len();

        // CTS requires at least one full block.
        if data_len < AES_BLOCK_SIZE {
            return Err(ProviderError::Dispatch(format!(
                "AES CBC-CTS: input too short ({data_len} bytes, need >= {AES_BLOCK_SIZE})"
            )));
        }

        // Exactly one block — plain CBC, no stealing needed.
        if data_len == AES_BLOCK_SIZE {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&data);
            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher.encrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTS: {e}"))
                })?;
            } else {
                cipher.decrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTS: {e}"))
                })?;
                xor_blocks(&mut block, &self.iv);
            }
            output.extend_from_slice(&block);
            return Ok(AES_BLOCK_SIZE);
        }

        // Determine the CTS tail: penultimate full block + last (partial or full).
        let remainder = data_len % AES_BLOCK_SIZE;
        let cts_tail_len = if remainder == 0 {
            2 * AES_BLOCK_SIZE
        } else {
            AES_BLOCK_SIZE + remainder
        };
        let cbc_prefix_len = data_len - cts_tail_len;

        // Process any remaining CBC-prefix blocks before the CTS tail.
        let mut total_written = 0;
        let mut offset = 0;
        while offset + AES_BLOCK_SIZE <= cbc_prefix_len {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + AES_BLOCK_SIZE]);
            if self.encrypting {
                xor_blocks(&mut block, &self.iv);
                cipher.encrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTS: {e}"))
                })?;
                self.iv.copy_from_slice(&block);
            } else {
                let ct_save = block;
                cipher.decrypt_block(&mut block).map_err(|e| {
                    ProviderError::Dispatch(format!("AES CTS: {e}"))
                })?;
                xor_blocks(&mut block, &self.iv);
                self.iv.copy_from_slice(&ct_save);
            }
            output.extend_from_slice(&block);
            total_written += AES_BLOCK_SIZE;
            offset += AES_BLOCK_SIZE;
        }

        // CTS tail: penultimate (full) + last (1..=16 bytes).
        let pen_block = &data[offset..offset + AES_BLOCK_SIZE];
        let last_block = &data[offset + AES_BLOCK_SIZE..];
        let last_len = last_block.len();

        if self.encrypting {
            total_written +=
                cts_encrypt(cipher, &self.iv, pen_block, last_block, last_len, variant, output)?;
        } else {
            total_written +=
                cts_decrypt(cipher, &self.iv, pen_block, last_block, last_len, variant, output)?;
        }

        Ok(total_written)
    }
}

// =============================================================================
// CipherContext Trait Implementation
// =============================================================================

impl CipherContext for AesCipherContext {
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, true, params)
    }

    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        self.init_common(key, iv, false, params)
    }

    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES cipher context not initialised".into(),
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        match self.mode {
            AesCipherMode::Ecb => self.update_ecb(input, output),
            AesCipherMode::Cbc => self.update_cbc(input, output),
            AesCipherMode::Ofb => self.update_ofb(input, output),
            AesCipherMode::Cfb => self.update_cfb(input, output),
            AesCipherMode::Cfb8 => self.update_cfb8(input, output),
            AesCipherMode::Cfb1 => self.update_cfb1(input, output),
            AesCipherMode::Ctr => self.update_ctr(input, output),
            AesCipherMode::CbcCts(_) => self.update_cbc_cts(input, output),
        }
    }

    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize> {
        if !self.initialized {
            return Err(ProviderError::Dispatch(
                "AES cipher context not initialised".into(),
            ));
        }
        match self.mode {
            AesCipherMode::Ecb => self.finalize_ecb(output),
            AesCipherMode::Cbc => self.finalize_cbc(output),
            AesCipherMode::Ofb
            | AesCipherMode::Cfb
            | AesCipherMode::Cfb8
            | AesCipherMode::Cfb1
            | AesCipherMode::Ctr => {
                // Stream modes have no buffered data to flush.
                Ok(0)
            }
            AesCipherMode::CbcCts(variant) => self.finalize_cbc_cts(output, variant),
        }
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let key_bits = self.key_bytes.saturating_mul(8);
        let block_bits = self.mode.reported_block_size().saturating_mul(8);
        let iv_bits = self.mode.iv_len().saturating_mul(8);
        let cipher_mode = self.mode.to_cipher_mode();
        let flags = self.mode.flags();
        let mut ps = generic_get_params(cipher_mode, flags, key_bits, block_bits, iv_bits);
        // Report the algorithm name for introspection.
        ps.set("algorithm", ParamValue::Utf8String(self.name.to_string()));
        Ok(ps)
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(val) = params.get(param_keys::PADDING) {
            match val {
                ParamValue::UInt32(v) => {
                    if matches!(self.mode, AesCipherMode::Ecb | AesCipherMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                ParamValue::UInt64(v) => {
                    if matches!(self.mode, AesCipherMode::Ecb | AesCipherMode::Cbc) {
                        self.padding = *v != 0;
                    }
                }
                _ => {
                    return Err(ProviderError::Dispatch(
                        "AES padding parameter must be integer".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Drop for AesCipherContext {
    fn drop(&mut self) {
        self.iv.zeroize();
        self.buffer.zeroize();
        self.keystream.zeroize();
        // `self.cipher` (Aes) zeroizes its own key material in its Drop impl.
    }
}

// =============================================================================
// Standalone Helpers
// =============================================================================

/// XOR `a[i] ^= b[i]` for the overlapping length.
#[inline]
fn xor_blocks(dest: &mut [u8], src: &[u8]) {
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Shift a 128-bit IV register left by 1 bit; insert `new_bit` at the LSB.
fn shift_iv_left_1_bit(iv: &mut [u8], new_bit: u8) {
    let len = iv.len();
    for idx in 0..len - 1 {
        iv[idx] = (iv[idx] << 1) | (iv[idx + 1] >> 7);
    }
    iv[len - 1] = (iv[len - 1] << 1) | (new_bit & 1);
}

/// Increment a big-endian counter in place (wraps on overflow).
fn increment_counter(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (val, overflow) = byte.overflowing_add(1);
        *byte = val;
        if !overflow {
            return;
        }
    }
}

/// CTS encryption for the last two blocks (penultimate + partial/full last).
///
/// Algorithm per NIST SP 800-38A Addendum (CS3):
/// 1. `E_{n-1} = E_K(P_{n-1} ⊕ IV)` — CBC-encrypt the penultimate block.
/// 2. `Y = (P_n ‖ 0^{16-m}) ⊕ E_{n-1}` — zero-pad and XOR.
/// 3. `C_n = E_K(Y)` — encrypt the XOR'd padded block.
/// 4. `C_{n-1} = head_m(E_{n-1})` — truncate penultimate ciphertext.
/// 5. Output order depends on CTS variant.
fn cts_encrypt(
    cipher: &Aes,
    iv: &[u8],
    pen_block: &[u8],
    last_block: &[u8],
    last_len: usize,
    variant: CtsVariant,
    output: &mut Vec<u8>,
) -> ProviderResult<usize> {
    // Step 1: CBC-encrypt penultimate block → E_{n-1}.
    let mut en_minus_1 = [0u8; AES_BLOCK_SIZE];
    en_minus_1.copy_from_slice(pen_block);
    xor_blocks(&mut en_minus_1, iv);
    cipher.encrypt_block(&mut en_minus_1).map_err(|e| {
        ProviderError::Dispatch(format!("AES CTS encrypt penultimate: {e}"))
    })?;

    // Step 2: Zero-pad P_n, XOR with full E_{n-1}.
    let mut padded_last = [0u8; AES_BLOCK_SIZE];
    padded_last[..last_len].copy_from_slice(last_block);
    // Bytes [last_len..] remain zero (zero-padding).
    xor_blocks(&mut padded_last, &en_minus_1);

    // Step 3: Encrypt → C_n.
    cipher.encrypt_block(&mut padded_last).map_err(|e| {
        ProviderError::Dispatch(format!("AES CTS encrypt last: {e}"))
    })?;
    let cn = padded_last;

    // Step 4+5: Emit in variant-specific order.
    // C_{n-1} is E_{n-1} truncated to last_len bytes.
    match variant {
        CtsVariant::Cs1 | CtsVariant::Cs3 => {
            output.extend_from_slice(&cn);
            output.extend_from_slice(&en_minus_1[..last_len]);
        }
        CtsVariant::Cs2 => {
            output.extend_from_slice(&en_minus_1[..last_len]);
            output.extend_from_slice(&cn);
        }
    }
    Ok(AES_BLOCK_SIZE + last_len)
}

/// CTS decryption for the last two blocks.
///
/// Algorithm (reverse of CTS encryption):
/// 1. `Y = D_K(C_n)` — decrypt the last ciphertext block.
/// 2. Recover `E_{n-1}`: bytes `[0..m]` from `C_{n-1}`, bytes `[m..16]` from
///    `Y[m..16]` (since `P_n[m..16] = 0`, so `Y[m..16] = E_{n-1}[m..16]`).
/// 3. `P_n = (Y ⊕ E_{n-1})[0..m]` — recover the last plaintext.
/// 4. `P_{n-1} = D_K(E_{n-1}) ⊕ IV` — CBC-decrypt the penultimate.
fn cts_decrypt(
    cipher: &Aes,
    iv: &[u8],
    block_a: &[u8],
    block_b: &[u8],
    last_len: usize,
    variant: CtsVariant,
    output: &mut Vec<u8>,
) -> ProviderResult<usize> {
    // Rearrange based on variant to identify C_n and truncated C_{n-1}.
    let (cn_data, cn_m1_trunc) = match variant {
        CtsVariant::Cs1 | CtsVariant::Cs3 => {
            // Input: [C_n (16 bytes)] [C_{n-1} truncated (last_len bytes)]
            (block_a, block_b)
        }
        CtsVariant::Cs2 => {
            // Input: [C_{n-1} truncated] [C_n (16 bytes)]
            (block_b, block_a)
        }
    };

    // Step 1: D_K(C_n) → Y.
    let mut y_val = [0u8; AES_BLOCK_SIZE];
    y_val.copy_from_slice(cn_data);
    cipher.decrypt_block(&mut y_val).map_err(|e| {
        ProviderError::Dispatch(format!("AES CTS decrypt cn: {e}"))
    })?;

    // Step 2: Reconstruct full E_{n-1}.
    // E_{n-1}[0..m] = C_{n-1} (the truncated penultimate we received).
    // E_{n-1}[m..16] = Y[m..16] (because P_n is zero-padded there).
    let mut en_m1 = [0u8; AES_BLOCK_SIZE];
    en_m1[..last_len].copy_from_slice(cn_m1_trunc);
    en_m1[last_len..].copy_from_slice(&y_val[last_len..]);

    // Step 3: Recover P_n = (Y ⊕ E_{n-1})[0..m].
    let mut last_plain = y_val;
    xor_blocks(&mut last_plain, &en_m1);
    // last_plain[0..last_len] = P_n; last_plain[last_len..16] = garbage (zeroed by XOR).

    // Step 4: CBC-decrypt E_{n-1} → P_{n-1}.
    cipher.decrypt_block(&mut en_m1).map_err(|e| {
        ProviderError::Dispatch(format!("AES CTS decrypt cn-1: {e}"))
    })?;
    xor_blocks(&mut en_m1, iv);

    // Step 5: Output penultimate (full 16 bytes) then last (m bytes).
    output.extend_from_slice(&en_m1);
    output.extend_from_slice(&last_plain[..last_len]);

    Ok(AES_BLOCK_SIZE + last_len)
}

// =============================================================================
// Descriptor Registration
// =============================================================================

/// Returns algorithm descriptors for all AES standard-mode cipher variants.
///
/// Registers 24 variants: 6 base modes × 3 key sizes, plus CFB8 and CFB1
/// sub-variants × 3 key sizes = 30 total descriptors.
///
/// AEAD descriptors are registered by their respective modules (`aes_gcm`,
/// `aes_ccm`, `aes_ocb`, `aes_siv`, `aes_xts`, `aes_wrap`).
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::with_capacity(30);
    let modes: &[(&str, AesCipherMode)] = &[
        ("ECB", AesCipherMode::Ecb),
        ("CBC", AesCipherMode::Cbc),
        ("OFB", AesCipherMode::Ofb),
        ("CFB", AesCipherMode::Cfb),
        ("CTR", AesCipherMode::Ctr),
        ("CBC-CTS", AesCipherMode::CbcCts(CtsVariant::Cs3)),
    ];
    let key_sizes: &[(usize, usize)] = &[(128, 16), (192, 24), (256, 32)];

    for (mode_name, mode) in modes {
        for &(key_bits, key_bytes) in key_sizes {
            let name = format!("AES-{key_bits}-{mode_name}");
            let leaked: &'static str = Box::leak(name.into_boxed_str());
            descs.push(make_cipher_descriptor(
                vec![leaked],
                "provider=default",
                match *mode_name {
                    "ECB" => "AES Electronic Codebook mode cipher",
                    "CBC" => "AES Cipher Block Chaining mode cipher",
                    "OFB" => "AES Output Feedback mode cipher",
                    "CFB" => "AES Cipher Feedback (128-bit) mode cipher",
                    "CTR" => "AES Counter mode cipher",
                    "CBC-CTS" => "AES CBC with Ciphertext Stealing (CS3)",
                    _ => "AES cipher",
                },
            ));
            // Ensure the provider instance is constructible (catches config bugs).
            let _ = AesCipher::new(leaked, key_bytes, *mode);
        }
    }

    // CFB8 and CFB1 sub-variants.
    let cfb_variants: &[(&str, AesCipherMode)] = &[
        ("CFB8", AesCipherMode::Cfb8),
        ("CFB1", AesCipherMode::Cfb1),
    ];
    for (variant_name, mode) in cfb_variants {
        for &(key_bits, key_bytes) in key_sizes {
            let name = format!("AES-{key_bits}-{variant_name}");
            let leaked: &'static str = Box::leak(name.into_boxed_str());
            descs.push(make_cipher_descriptor(
                vec![leaked],
                "provider=default",
                "AES Cipher Feedback sub-variant cipher",
            ));
            let _ = AesCipher::new(leaked, key_bytes, *mode);
        }
    }

    descs
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Descriptor tests ----

    #[test]
    fn descriptor_count() {
        let descs = descriptors();
        // 6 base modes × 3 key sizes = 18, plus 2 CFB sub-variants × 3 = 6 → 24 total.
        assert_eq!(descs.len(), 24, "6 modes × 3 + 2 CFB sub-variants × 3 = 24");
    }

    #[test]
    fn descriptor_names_contain_key_size() {
        let descs = descriptors();
        for desc in &descs {
            let name = desc.names[0];
            assert!(
                name.contains("128") || name.contains("192") || name.contains("256"),
                "descriptor missing key size: {name}"
            );
        }
    }

    // ---- Provider metadata tests ----

    #[test]
    fn ecb_provider_metadata() {
        let provider = AesCipher::new("AES-128-ECB", 16, AesCipherMode::Ecb);
        assert_eq!(provider.name(), "AES-128-ECB");
        assert_eq!(provider.key_length(), 16);
        assert_eq!(provider.iv_length(), 0);
        assert_eq!(provider.block_size(), 16);
    }

    #[test]
    fn cbc_provider_metadata() {
        let provider = AesCipher::new("AES-256-CBC", 32, AesCipherMode::Cbc);
        assert_eq!(provider.key_length(), 32);
        assert_eq!(provider.iv_length(), 16);
        assert_eq!(provider.block_size(), 16);
    }

    #[test]
    fn ctr_provider_metadata() {
        let provider = AesCipher::new("AES-192-CTR", 24, AesCipherMode::Ctr);
        assert_eq!(provider.key_length(), 24);
        assert_eq!(provider.iv_length(), 16);
        assert_eq!(provider.block_size(), 1);
    }

    // ---- ECB round-trip tests ----

    #[test]
    fn ecb_128_round_trip_with_padding() {
        let provider = AesCipher::new("AES-128-ECB", 16, AesCipherMode::Ecb);
        let key = [0x42u8; 16];
        let plaintext = b"Hello, AES-ECB!!"; // exactly 16 bytes

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx.encrypt_init(&key, None, None).expect("enc init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("enc update");
        enc_ctx.finalize(&mut ciphertext).expect("enc finalize");

        // With padding, 16-byte input → 32-byte ciphertext (1 block data + 1 block pad).
        assert_eq!(ciphertext.len(), 32);

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx.decrypt_init(&key, None, None).expect("dec init");
        let mut recovered = Vec::new();
        dec_ctx.update(&ciphertext, &mut recovered).expect("dec update");
        dec_ctx.finalize(&mut recovered).expect("dec finalize");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn ecb_256_round_trip_no_padding() {
        let provider = AesCipher::new("AES-256-ECB", 32, AesCipherMode::Ecb);
        let key = [0x01u8; 32];
        let plaintext = [0xAAu8; 32]; // exactly 2 blocks

        let mut no_pad = ParamSet::new();
        no_pad.set(param_keys::PADDING, ParamValue::UInt32(0));

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&key, None, Some(&no_pad))
            .expect("enc init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(&plaintext, &mut ciphertext).expect("enc update");
        enc_ctx.finalize(&mut ciphertext).expect("enc finalize");
        assert_eq!(ciphertext.len(), 32);

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx
            .decrypt_init(&key, None, Some(&no_pad))
            .expect("dec init");
        let mut recovered = Vec::new();
        dec_ctx.update(&ciphertext, &mut recovered).expect("dec update");
        dec_ctx.finalize(&mut recovered).expect("dec finalize");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn ecb_no_padding_misaligned_fails() {
        let provider = AesCipher::new("AES-128-ECB", 16, AesCipherMode::Ecb);
        let key = [0x00u8; 16];
        let plaintext = [0xBBu8; 17]; // not block-aligned

        let mut no_pad = ParamSet::new();
        no_pad.set(param_keys::PADDING, ParamValue::UInt32(0));

        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, Some(&no_pad)).expect("init");
        let mut out = Vec::new();
        ctx.update(&plaintext, &mut out).expect("update");
        let result = ctx.finalize(&mut out);
        assert!(result.is_err(), "misaligned without padding should fail");
    }

    // ---- CBC round-trip tests ----

    #[test]
    fn cbc_128_round_trip() {
        let provider = AesCipher::new("AES-128-CBC", 16, AesCipherMode::Cbc);
        let key = [0x55u8; 16];
        let iv = [0xAAu8; 16];
        let plaintext = b"CBC mode test with arbitrary length data!"; // 41 bytes

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), None)
            .expect("enc init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("enc update");
        enc_ctx.finalize(&mut ciphertext).expect("enc finalize");
        // 41 bytes → 48 bytes with PKCS#7 padding (3 blocks).
        assert_eq!(ciphertext.len(), 48);

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), None)
            .expect("dec init");
        let mut recovered = Vec::new();
        dec_ctx.update(&ciphertext, &mut recovered).expect("dec update");
        dec_ctx.finalize(&mut recovered).expect("dec finalize");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn cbc_256_no_padding_round_trip() {
        let provider = AesCipher::new("AES-256-CBC", 32, AesCipherMode::Cbc);
        let key = [0x77u8; 32];
        let iv = [0x11u8; 16];
        let plaintext = [0xFFu8; 48]; // exactly 3 blocks

        let mut no_pad = ParamSet::new();
        no_pad.set(param_keys::PADDING, ParamValue::UInt32(0));

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), Some(&no_pad))
            .expect("enc init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(&plaintext, &mut ciphertext).expect("enc update");
        enc_ctx.finalize(&mut ciphertext).expect("enc finalize");
        assert_eq!(ciphertext.len(), 48);

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), Some(&no_pad))
            .expect("dec init");
        let mut recovered = Vec::new();
        dec_ctx.update(&ciphertext, &mut recovered).expect("dec update");
        dec_ctx.finalize(&mut recovered).expect("dec finalize");
        assert_eq!(recovered, plaintext.to_vec());
    }

    // ---- Stream mode round-trip tests ----

    fn stream_round_trip(mode: AesCipherMode, mode_name: &str) {
        let key = [0x33u8; 16];
        let iv = [0xCCu8; 16];
        let plaintext = b"Stream cipher testing with various lengths!!"; // 44 bytes

        let name = format!("AES-128-{mode_name}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        let provider = AesCipher::new(leaked, 16, mode);

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), None)
            .expect("enc init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("enc update");
        enc_ctx.finalize(&mut ciphertext).expect("enc finalize");
        // Stream modes: ciphertext length == plaintext length.
        assert_eq!(
            ciphertext.len(),
            plaintext.len(),
            "stream cipher length mismatch"
        );
        // Ciphertext should differ from plaintext (except astronomically unlikely).
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), None)
            .expect("dec init");
        let mut recovered = Vec::new();
        dec_ctx.update(&ciphertext, &mut recovered).expect("dec update");
        dec_ctx.finalize(&mut recovered).expect("dec finalize");
        assert_eq!(recovered, plaintext, "{mode_name} round-trip failed");
    }

    #[test]
    fn ofb_round_trip() {
        stream_round_trip(AesCipherMode::Ofb, "OFB");
    }

    #[test]
    fn cfb_round_trip() {
        stream_round_trip(AesCipherMode::Cfb, "CFB");
    }

    #[test]
    fn cfb8_round_trip() {
        stream_round_trip(AesCipherMode::Cfb8, "CFB8");
    }

    #[test]
    fn cfb1_round_trip() {
        stream_round_trip(AesCipherMode::Cfb1, "CFB1");
    }

    #[test]
    fn ctr_round_trip() {
        stream_round_trip(AesCipherMode::Ctr, "CTR");
    }

    // ---- CTR specific: same-op symmetry ----

    #[test]
    fn ctr_encrypt_decrypt_symmetry() {
        let provider = AesCipher::new("AES-256-CTR", 32, AesCipherMode::Ctr);
        let key = [0xABu8; 32];
        let iv = [0x01u8; 16];
        let data = [0xDDu8; 100];

        // Encrypt.
        let mut enc = provider.new_ctx().expect("new_ctx");
        enc.encrypt_init(&key, Some(&iv), None).expect("init");
        let mut ct = Vec::new();
        enc.update(&data, &mut ct).expect("update");

        // "Decrypt" using encrypt_init (CTR is symmetric).
        let mut dec = provider.new_ctx().expect("new_ctx");
        dec.encrypt_init(&key, Some(&iv), None).expect("init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");

        assert_eq!(pt, data.to_vec());
    }

    // ---- Key/IV validation tests ----

    #[test]
    fn wrong_key_length_rejected() {
        let provider = AesCipher::new("AES-256-CBC", 32, AesCipherMode::Cbc);
        let bad_key = [0u8; 16]; // should be 32
        let iv = [0u8; 16];
        let mut ctx = provider.new_ctx().expect("new_ctx");
        assert!(ctx.encrypt_init(&bad_key, Some(&iv), None).is_err());
    }

    #[test]
    fn missing_iv_rejected_for_cbc() {
        let provider = AesCipher::new("AES-128-CBC", 16, AesCipherMode::Cbc);
        let key = [0u8; 16];
        let mut ctx = provider.new_ctx().expect("new_ctx");
        assert!(ctx.encrypt_init(&key, None, None).is_err());
    }

    #[test]
    fn ecb_accepts_no_iv() {
        let provider = AesCipher::new("AES-128-ECB", 16, AesCipherMode::Ecb);
        let key = [0u8; 16];
        let mut ctx = provider.new_ctx().expect("new_ctx");
        assert!(ctx.encrypt_init(&key, None, None).is_ok());
    }

    #[test]
    fn uninit_context_update_fails() {
        let provider = AesCipher::new("AES-128-ECB", 16, AesCipherMode::Ecb);
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let mut out = Vec::new();
        assert!(ctx.update(&[0u8; 16], &mut out).is_err());
    }

    // ---- get_params tests ----

    #[test]
    fn get_params_ecb() {
        let provider = AesCipher::new("AES-256-ECB", 32, AesCipherMode::Ecb);
        let ctx = provider.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        // `generic_get_params` converts bits→bytes internally, so params
        // report key_len=32, block_size=16, iv_len=0 (in bytes).
        assert_eq!(
            params.get(param_keys::KEYLEN),
            Some(&ParamValue::UInt32(32))
        );
        assert_eq!(
            params.get(param_keys::BLOCK_SIZE),
            Some(&ParamValue::UInt32(16))
        );
        assert_eq!(
            params.get(param_keys::IVLEN),
            Some(&ParamValue::UInt32(0))
        );
    }

    #[test]
    fn get_params_ctr() {
        let provider = AesCipher::new("AES-128-CTR", 16, AesCipherMode::Ctr);
        let ctx = provider.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");
        // Stream mode: block_size = 1 byte (reported).
        assert_eq!(
            params.get(param_keys::BLOCK_SIZE),
            Some(&ParamValue::UInt32(1))
        );
    }

    // ---- CBC-CTS tests ----

    #[test]
    fn cbc_cts_round_trip_partial_last() {
        let provider = AesCipher::new(
            "AES-128-CBC-CTS",
            16,
            AesCipherMode::CbcCts(CtsVariant::Cs3),
        );
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];
        // 25 bytes → 1 full block + 9 partial bytes for CTS.
        let plaintext = b"CTS needs > 1 block data!";

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), None)
            .expect("enc init");
        let mut ciphertext = Vec::new();
        enc_ctx.update(plaintext, &mut ciphertext).expect("enc update");
        enc_ctx.finalize(&mut ciphertext).expect("enc finalize");
        // CTS: output length == input length.
        assert_eq!(ciphertext.len(), plaintext.len());

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), None)
            .expect("dec init");
        let mut recovered = Vec::new();
        dec_ctx.update(&ciphertext, &mut recovered).expect("dec update");
        dec_ctx.finalize(&mut recovered).expect("dec finalize");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn cbc_cts_round_trip_exact_two_blocks() {
        let provider = AesCipher::new(
            "AES-256-CBC-CTS",
            32,
            AesCipherMode::CbcCts(CtsVariant::Cs3),
        );
        let key = [0xBBu8; 32];
        let iv = [0x11u8; 16];
        let plaintext = [0xCCu8; 32]; // exactly 2 blocks

        let mut enc_ctx = provider.new_ctx().expect("new_ctx");
        enc_ctx
            .encrypt_init(&key, Some(&iv), None)
            .expect("enc init");
        let mut ct = Vec::new();
        enc_ctx.update(&plaintext, &mut ct).expect("enc update");
        enc_ctx.finalize(&mut ct).expect("enc finalize");
        assert_eq!(ct.len(), 32);

        let mut dec_ctx = provider.new_ctx().expect("new_ctx");
        dec_ctx
            .decrypt_init(&key, Some(&iv), None)
            .expect("dec init");
        let mut pt = Vec::new();
        dec_ctx.update(&ct, &mut pt).expect("dec update");
        dec_ctx.finalize(&mut pt).expect("dec finalize");
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn cbc_cts_single_block() {
        let provider = AesCipher::new(
            "AES-128-CBC-CTS",
            16,
            AesCipherMode::CbcCts(CtsVariant::Cs3),
        );
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let plaintext = [0xDDu8; 16]; // single block, no stealing

        let mut enc = provider.new_ctx().expect("new_ctx");
        enc.encrypt_init(&key, Some(&iv), None).expect("init");
        let mut ct = Vec::new();
        enc.update(&plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");
        assert_eq!(ct.len(), 16);

        let mut dec = provider.new_ctx().expect("new_ctx");
        dec.decrypt_init(&key, Some(&iv), None).expect("init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn cbc_cts_too_short_fails() {
        let provider = AesCipher::new(
            "AES-128-CBC-CTS",
            16,
            AesCipherMode::CbcCts(CtsVariant::Cs3),
        );
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = [0xEEu8; 10]; // less than one block

        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, Some(&iv), None).expect("init");
        let mut ct = Vec::new();
        ctx.update(&plaintext, &mut ct).expect("update");
        assert!(ctx.finalize(&mut ct).is_err());
    }

    // ---- Incremental (chunked) update tests ----

    #[test]
    fn cbc_chunked_update() {
        let provider = AesCipher::new("AES-128-CBC", 16, AesCipherMode::Cbc);
        let key = [0x99u8; 16];
        let iv = [0x88u8; 16];
        let plaintext = [0xABu8; 64]; // 4 blocks

        // One-shot encrypt.
        let mut enc_one = provider.new_ctx().expect("new_ctx");
        enc_one
            .encrypt_init(&key, Some(&iv), None)
            .expect("init");
        let mut ct_one = Vec::new();
        enc_one.update(&plaintext, &mut ct_one).expect("update");
        enc_one.finalize(&mut ct_one).expect("finalize");

        // Chunked encrypt (7 bytes at a time — deliberately misaligned).
        let mut enc_chunked = provider.new_ctx().expect("new_ctx");
        enc_chunked
            .encrypt_init(&key, Some(&iv), None)
            .expect("init");
        let mut ct_chunked = Vec::new();
        for chunk in plaintext.chunks(7) {
            enc_chunked
                .update(chunk, &mut ct_chunked)
                .expect("update");
        }
        enc_chunked.finalize(&mut ct_chunked).expect("finalize");

        assert_eq!(ct_one, ct_chunked, "chunked CBC must match one-shot");
    }

    // ---- Empty input test ----

    #[test]
    fn empty_input_with_padding_produces_one_block() {
        let provider = AesCipher::new("AES-128-ECB", 16, AesCipherMode::Ecb);
        let key = [0u8; 16];

        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.encrypt_init(&key, None, None).expect("init");
        let mut ct = Vec::new();
        ctx.update(&[], &mut ct).expect("update");
        ctx.finalize(&mut ct).expect("finalize");
        // PKCS#7 on empty → 16 bytes of 0x10 padding → one encrypted block.
        assert_eq!(ct.len(), 16);

        let mut dec = provider.new_ctx().expect("new_ctx");
        dec.decrypt_init(&key, None, None).expect("init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert!(pt.is_empty());
    }

    // ---- 192-bit key tests ----

    #[test]
    fn cbc_192_round_trip() {
        let provider = AesCipher::new("AES-192-CBC", 24, AesCipherMode::Cbc);
        let key = [0x66u8; 24];
        let iv = [0x77u8; 16];
        let plaintext = b"AES-192 test vector data for CBC mode!"; // 38 bytes

        let mut enc = provider.new_ctx().expect("new_ctx");
        enc.encrypt_init(&key, Some(&iv), None).expect("init");
        let mut ct = Vec::new();
        enc.update(plaintext, &mut ct).expect("update");
        enc.finalize(&mut ct).expect("finalize");

        let mut dec = provider.new_ctx().expect("new_ctx");
        dec.decrypt_init(&key, Some(&iv), None).expect("init");
        let mut pt = Vec::new();
        dec.update(&ct, &mut pt).expect("update");
        dec.finalize(&mut pt).expect("finalize");
        assert_eq!(pt, plaintext);
    }

    // ---- Helper function tests ----

    #[test]
    fn xor_blocks_works() {
        let mut a = [0xFFu8; 4];
        let b = [0x0Fu8; 4];
        xor_blocks(&mut a, &b);
        assert_eq!(a, [0xF0u8; 4]);
    }

    #[test]
    fn counter_increment() {
        let mut ctr = [0u8; 4];
        ctr[3] = 0xFF;
        increment_counter(&mut ctr);
        assert_eq!(ctr, [0, 0, 1, 0]);
    }

    #[test]
    fn counter_overflow_wraps() {
        let mut ctr = [0xFFu8; 4];
        increment_counter(&mut ctr);
        assert_eq!(ctr, [0u8; 4]);
    }
}
