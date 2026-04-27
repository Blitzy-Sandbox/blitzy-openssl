//! GMAC (Galois Message Authentication Code) provider implementation.
//!
//! GMAC is derived from AES-GCM — it processes data as Additional
//! Authenticated Data (AAD) only, with no ciphertext, and produces the
//! GCM authentication tag.  Translated from C source:
//! `providers/implementations/macs/gmac_prov.c` (256 lines).
//!
//! # Algorithm Details
//!
//! - Tag size: 16 bytes (128-bit GCM authentication tag)
//! - Requires a GCM-mode cipher (e.g., `AES-128-GCM`, `AES-256-GCM`)
//! - IV is required; default length is 12 bytes (96 bits per NIST SP 800-38D)
//! - Data is processed as AAD only — no encryption output is produced
//!
//! # Usage
//!
//! ```ignore
//! use openssl_provider::implementations::macs::gmac::{GmacProvider, GMAC_TAG_SIZE};
//! use openssl_provider::traits::MacProvider;
//! use openssl_common::{ParamSet, ParamValue};
//!
//! let provider = GmacProvider::new();
//! let mut ctx = provider.new_ctx()?;
//! let mut params = ParamSet::new();
//! params.set("cipher", ParamValue::Utf8String("AES-128-GCM".into()));
//! params.set("iv", ParamValue::OctetString(vec![0u8; 12]));
//! ctx.init(&[0u8; 16], Some(&params))?;
//! ctx.update(b"authenticated data")?;
//! let tag = ctx.finalize()?;
//! assert_eq!(tag.len(), GMAC_TAG_SIZE);
//! ```

use crate::traits::{AlgorithmDescriptor, MacContext, MacProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::{ParamBuilder, ParamSet, ParamValue, ProviderResult};
use tracing::{debug, trace};
use zeroize::Zeroize;

// =============================================================================
// Constants
// =============================================================================

/// GCM authentication tag size in bytes (128 bits).
/// Equivalent to `EVP_GCM_TLS_TAG_LEN` in the C source.
pub const GMAC_TAG_SIZE: usize = 16;

/// Default GCM IV length in bytes (96 bits, as recommended by NIST SP 800-38D).
const DEFAULT_IV_LEN: usize = 12;

/// AES block size in bytes (128 bits).
const AES_BLOCK_SIZE: usize = 16;

// Parameter name constants matching OpenSSL `OSSL_MAC_PARAM_*` keys.
const PARAM_SIZE: &str = "size";
const PARAM_CIPHER: &str = "cipher";
const PARAM_PROPERTIES: &str = "properties";
const PARAM_IV: &str = "iv";
const PARAM_IVLEN: &str = "ivlen";

// =============================================================================
// GmacParams — Configuration parameters for GMAC
// =============================================================================

/// GMAC configuration parameters.
///
/// Replaces the C `OSSL_PARAM` tables from `gmac_prov.c`.
/// Uses `Option<T>` for nullable fields per Rule R5 (no sentinel values).
#[derive(Debug, Clone, Default)]
pub struct GmacParams {
    /// Cipher algorithm name (must be a GCM-mode cipher, e.g., `"AES-128-GCM"`).
    pub cipher: Option<String>,
    /// Property query for cipher fetch (e.g., `"provider=default"`).
    pub properties: Option<String>,
    /// Initialization vector (required for GMAC computation).
    pub iv: Option<Vec<u8>>,
    /// IV length override (default: 12 bytes for GCM).
    pub iv_len: Option<usize>,
}

impl GmacParams {
    /// Converts GMAC parameters to a `ParamSet` for storage and transport.
    pub fn to_param_set(&self) -> ParamSet {
        let mut builder = ParamBuilder::new();
        if let Some(ref cipher) = self.cipher {
            builder = builder.push_utf8(PARAM_CIPHER, cipher.clone());
        }
        if let Some(ref properties) = self.properties {
            builder = builder.push_utf8(PARAM_PROPERTIES, properties.clone());
        }
        if let Some(ref iv) = self.iv {
            builder = builder.push_octet(PARAM_IV, iv.clone());
        }
        if let Some(iv_len) = self.iv_len {
            // usize always fits in u64 on supported 32/64-bit platforms.
            builder = builder.push_u64(PARAM_IVLEN, iv_len as u64);
        }
        builder.build()
    }
}

// =============================================================================
// AES Implementation — encrypt-only, internal to GMAC tag computation
// =============================================================================

/// FIPS 197 AES S-box — `SubBytes` transformation lookup table.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// AES round constants for key expansion (FIPS 197 §5.2).
const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

/// Apply the S-box to each byte of a 32-bit word.
fn sub_word(word: u32) -> u32 {
    let b = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[usize::from(b[0])],
        SBOX[usize::from(b[1])],
        SBOX[usize::from(b[2])],
        SBOX[usize::from(b[3])],
    ])
}

/// Rotate a 32-bit word left by one byte position.
fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// GF(2^8) multiplication by x (the polynomial indeterminate).
///
/// If the MSB is set, reduce by the AES irreducible polynomial
/// x^8 + x^4 + x^3 + x + 1 (0x11B, low byte 0x1B).
fn xtime(val: u8) -> u8 {
    (val << 1) ^ if val & 0x80 != 0 { 0x1B } else { 0x00 }
}

/// AES `SubBytes`: replace each state byte with its S-box value.
fn sub_bytes(state: &mut [u8; AES_BLOCK_SIZE]) {
    for byte in state.iter_mut() {
        *byte = SBOX[usize::from(*byte)];
    }
}

/// AES `ShiftRows`: cyclically shift rows of the column-major state matrix.
///
/// State layout: `state[row + 4*col]` for row ∈ 0..4, col ∈ 0..4.
fn shift_rows(state: &mut [u8; AES_BLOCK_SIZE]) {
    // Row 1: left-shift by 1
    let tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2: left-shift by 2
    let (t0, t1) = (state[2], state[6]);
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;

    // Row 3: left-shift by 3 (equivalent to right-shift by 1)
    let tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

/// AES `MixColumns`: matrix-multiply each column in GF(2^8).
///
/// Applies the fixed polynomial c(x) = 3x^3 + x^2 + x + 2 to each column.
fn mix_columns(state: &mut [u8; AES_BLOCK_SIZE]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];

        // Each new byte = 2·a ⊕ 3·b ⊕ c ⊕ d (in GF(2^8))
        state[base] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
        state[base + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
        state[base + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
        state[base + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
    }
}

/// AES `AddRoundKey`: XOR the state with a 128-bit round key.
fn add_round_key(state: &mut [u8; AES_BLOCK_SIZE], key: &[u8; AES_BLOCK_SIZE]) {
    for (s, k) in state.iter_mut().zip(key.iter()) {
        *s ^= k;
    }
}

/// Internal AES key schedule and single-block encryption.
///
/// Supports AES-128 (16-byte key, 10 rounds), AES-192 (24-byte, 12 rounds),
/// and AES-256 (32-byte, 14 rounds).  Only encryption is implemented —
/// decryption is not needed for GMAC/GCM tag computation.
#[derive(Clone)]
struct AesKey {
    /// Expanded round keys: 11 for AES-128, 13 for AES-192, 15 for AES-256.
    round_keys: Vec<[u8; AES_BLOCK_SIZE]>,
    /// Number of encryption rounds: 10, 12, or 14.
    num_rounds: usize,
}

impl AesKey {
    /// Create an AES key schedule from raw key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if the key length is not 16, 24, or 32.
    fn new(key: &[u8]) -> ProviderResult<Self> {
        let (nk, nr) = match key.len() {
            16 => (4, 10),  // AES-128
            24 => (6, 12),  // AES-192
            32 => (8, 14),  // AES-256
            other => {
                return Err(ProviderError::Init(format!(
                    "Invalid AES key length: {other} bytes (expected 16, 24, or 32)"
                )));
            }
        };

        let total_words = 4 * (nr + 1);
        let mut words: Vec<u32> = Vec::with_capacity(total_words);

        // Load initial key words in big-endian byte order
        for i in 0..nk {
            let off = i * 4;
            words.push(u32::from_be_bytes([
                key[off],
                key[off + 1],
                key[off + 2],
                key[off + 3],
            ]));
        }

        // FIPS 197 §5.2 key expansion
        for i in nk..total_words {
            let mut temp = words[i - 1];
            if i % nk == 0 {
                temp = sub_word(rot_word(temp)) ^ (u32::from(RCON[i / nk - 1]) << 24);
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            words.push(words[i - nk] ^ temp);
        }

        // Pack 32-bit words into 16-byte round keys
        let mut round_keys = Vec::with_capacity(nr + 1);
        for r in 0..=nr {
            let mut rk = [0u8; AES_BLOCK_SIZE];
            for j in 0..4 {
                let w = words[4 * r + j].to_be_bytes();
                let off = j * 4;
                rk[off] = w[0];
                rk[off + 1] = w[1];
                rk[off + 2] = w[2];
                rk[off + 3] = w[3];
            }
            round_keys.push(rk);
        }

        Ok(Self { round_keys, num_rounds: nr })
    }

    /// Encrypt a single 128-bit block using the AES cipher.
    fn encrypt_block(&self, input: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
        let mut state = *input;

        // Initial round key addition
        add_round_key(&mut state, &self.round_keys[0]);

        // Main rounds: SubBytes → ShiftRows → MixColumns → AddRoundKey
        for round in 1..self.num_rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
        }

        // Final round (no MixColumns)
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[self.num_rounds]);

        state
    }
}

impl Zeroize for AesKey {
    fn zeroize(&mut self) {
        for rk in &mut self.round_keys {
            rk.zeroize();
        }
        self.round_keys.clear();
        self.num_rounds = 0;
    }
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// GF(2^128) Multiplication and GHASH — NIST SP 800-38D §6.3–6.4
// =============================================================================

/// Reduction polynomial R for GCM's GF(2^128) field.
///
/// R = 11100001 || 0^120 (the bit-reflected representation of the
/// polynomial x^128 + x^7 + x^2 + x + 1).
const GF128_R: [u8; AES_BLOCK_SIZE] = [
    0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// XOR two 128-bit blocks in place: `a ^= b`.
fn xor_block(a: &mut [u8; AES_BLOCK_SIZE], b: &[u8; AES_BLOCK_SIZE]) {
    for (ai, bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= bi;
    }
}

/// Right-shift a 128-bit block by one bit (big-endian byte order).
///
/// The vacated MSB is filled with zero.
fn right_shift_block(block: &mut [u8; AES_BLOCK_SIZE]) {
    let mut carry = 0u8;
    for byte in block.iter_mut() {
        let new_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = new_carry;
    }
}

/// GF(2^128) multiplication using the schoolbook (bit-by-bit) algorithm.
///
/// Implements Algorithm 1 from NIST SP 800-38D §6.3.
/// Both operands and the result use GCM bit ordering: byte\[0\] MSB = x₀,
/// byte\[15\] LSB = x₁₂₇.
fn gf128_mul(x: &[u8; AES_BLOCK_SIZE], y: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let mut z = [0u8; AES_BLOCK_SIZE];
    let mut v = *y;

    for i in 0..128 {
        // Extract bit x_i:  byte index = i / 8, bit position = 7 - (i % 8)
        let byte_idx = i / 8;
        let bit_pos = 7 - (i % 8);
        let x_bit = (x[byte_idx] >> bit_pos) & 1;

        if x_bit == 1 {
            xor_block(&mut z, &v);
        }

        // Check rightmost bit of V (v₁₂₇ = byte[15] bit 0)
        let v_lsb = v[AES_BLOCK_SIZE - 1] & 1;

        // V = rightshift(V)
        right_shift_block(&mut v);

        // If the old LSB was 1, reduce: V ^= R
        if v_lsb == 1 {
            xor_block(&mut v, &GF128_R);
        }
    }

    z
}

// =============================================================================
// GHASH Incremental Computer
// =============================================================================

/// Incremental GHASH computer with internal 128-bit block buffering.
///
/// Processes arbitrary-length input through the GHASH function defined
/// in NIST SP 800-38D §6.4.  Used for both AAD hashing and initial
/// counter block (J0) computation for non-96-bit IVs.
#[derive(Clone)]
struct GhashComputer {
    /// Hash subkey `H = E_K(0^128)`.
    h: [u8; AES_BLOCK_SIZE],
    /// Running GHASH accumulator Y (128 bits).
    acc: [u8; AES_BLOCK_SIZE],
    /// Partial block buffer for incomplete 128-bit blocks.
    buf: [u8; AES_BLOCK_SIZE],
    /// Number of valid bytes currently buffered.
    buf_len: usize,
}

impl GhashComputer {
    /// Creates a new GHASH computer with hash subkey `h`.
    fn new(h: [u8; AES_BLOCK_SIZE]) -> Self {
        Self {
            h,
            acc: [0u8; AES_BLOCK_SIZE],
            buf: [0u8; AES_BLOCK_SIZE],
            buf_len: 0,
        }
    }

    /// Process one complete 128-bit block: Y = (Y ⊕ block) · H.
    fn process_block(&mut self, block: &[u8; AES_BLOCK_SIZE]) {
        xor_block(&mut self.acc, block);
        self.acc = gf128_mul(&self.acc, &self.h);
    }

    /// Feed data into the GHASH computation with internal buffering.
    ///
    /// Handles arbitrary-length input by buffering partial blocks and
    /// processing complete 128-bit blocks as they become available.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill the partial-block buffer first
        if self.buf_len > 0 {
            let space = AES_BLOCK_SIZE - self.buf_len;
            let n = data.len().min(space);
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            offset = n;

            if self.buf_len == AES_BLOCK_SIZE {
                let block = self.buf;
                self.process_block(&block);
                self.buf = [0u8; AES_BLOCK_SIZE];
                self.buf_len = 0;
            }
        }

        // Process complete 128-bit blocks directly
        while offset + AES_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + AES_BLOCK_SIZE]);
            self.process_block(&block);
            offset += AES_BLOCK_SIZE;
        }

        // Buffer any remaining bytes (< 16)
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Flush the partial-block buffer by zero-padding to 128 bits.
    ///
    /// Must be called before appending the GHASH length block to ensure
    /// the AAD data boundary is properly padded.
    fn pad_flush(&mut self) {
        if self.buf_len > 0 {
            // Zero-pad the remaining buffer bytes
            for byte in &mut self.buf[self.buf_len..] {
                *byte = 0;
            }
            let block = self.buf;
            self.process_block(&block);
            self.buf = [0u8; AES_BLOCK_SIZE];
            self.buf_len = 0;
        }
    }

    /// Returns the current GHASH accumulator value.
    fn result(&self) -> [u8; AES_BLOCK_SIZE] {
        self.acc
    }
}

impl Zeroize for GhashComputer {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.acc.zeroize();
        self.buf.zeroize();
        self.buf_len = 0;
    }
}

impl Drop for GhashComputer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// GCM-GMAC Internal State
// =============================================================================

/// Complete GCM state for GMAC (AAD-only) tag computation.
///
/// Combines the AES key schedule, GHASH computer, and initial counter block
/// (J0) to compute the GCM authentication tag over AAD-only input.
/// Replaces the internal state of `struct gmac_data_st` from `gmac_prov.c`.
#[derive(Clone)]
struct GcmGmacState {
    /// AES key schedule for `E_K` operations (H computation, J0 encryption).
    aes: AesKey,
    /// GHASH computer for AAD accumulation.
    ghash: GhashComputer,
    /// Initial counter block J0 (derived from IV per NIST SP 800-38D §7.1).
    j0: [u8; AES_BLOCK_SIZE],
    /// Total AAD bytes processed (for the GHASH length block).
    total_aad_bytes: u64,
}

impl GcmGmacState {
    /// Initialise the GCM-GMAC state with an AES key schedule and IV.
    ///
    /// Computes the hash subkey `H = E_K(0^128)` and the initial counter
    /// block J0 per NIST SP 800-38D §7.1 step 2.
    fn new(aes: AesKey, iv: &[u8]) -> Self {
        // H = E_K(0^128) — the GHASH hash subkey
        let zero_block = [0u8; AES_BLOCK_SIZE];
        let h = aes.encrypt_block(&zero_block);

        // J0 = initial counter block (algorithm depends on IV length)
        let j0 = Self::compute_j0(&h, iv);

        let ghash = GhashComputer::new(h);
        Self {
            aes,
            ghash,
            j0,
            total_aad_bytes: 0,
        }
    }

    /// Compute J0 from the IV per NIST SP 800-38D §7.1 step 2.
    ///
    /// - If `|IV| == 96` bits (12 bytes): J0 = IV ‖ 0³¹ ‖ 1
    /// - Otherwise: `J0 = GHASH_H(IV ‖ 0^s ‖ [0]_64 ‖ [len(IV)·8]_64)`
    fn compute_j0(h: &[u8; AES_BLOCK_SIZE], iv: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        if iv.len() == DEFAULT_IV_LEN {
            // Optimised path for standard 96-bit IV
            let mut j0 = [0u8; AES_BLOCK_SIZE];
            j0[..DEFAULT_IV_LEN].copy_from_slice(iv);
            j0[AES_BLOCK_SIZE - 1] = 1; // Counter = 0x00000001
            j0
        } else {
            // General path for non-96-bit IVs
            let mut computer = GhashComputer::new(*h);
            computer.update(iv);
            computer.pad_flush();

            // Length block: [0]₆₄ ‖ [len(IV) * 8]₆₄  (IV length in bits)
            let mut len_block = [0u8; AES_BLOCK_SIZE];
            let iv_bits = (iv.len() as u64).saturating_mul(8);
            len_block[8..AES_BLOCK_SIZE].copy_from_slice(&iv_bits.to_be_bytes());
            computer.update(&len_block);

            computer.result()
        }
    }

    /// Process AAD data through the GHASH computation.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` if the total AAD length overflows u64.
    fn update_aad(&mut self, data: &[u8]) -> ProviderResult<()> {
        // Rule R6: checked arithmetic for AAD length accumulation.
        let data_len = data.len() as u64;
        self.total_aad_bytes = self.total_aad_bytes.checked_add(data_len).ok_or_else(|| {
            ProviderError::Dispatch("Total AAD length overflow exceeds u64 range".to_string())
        })?;
        self.ghash.update(data);
        Ok(())
    }

    /// Finalise the GMAC computation and return the 16-byte authentication tag.
    ///
    /// Pads the AAD, appends the GHASH length block
    /// `[len(A)·8]_64 ‖ [len(C)·8]_64`, and XORs the GHASH result with `E_K(J0)`.
    /// For GMAC, ciphertext length is always zero.
    fn finalize_tag(&mut self) -> [u8; AES_BLOCK_SIZE] {
        // Pad any partial AAD block to a 128-bit boundary
        self.ghash.pad_flush();

        // Append length block: [len(A)*8]₆₄ ‖ [len(C)*8]₆₄
        // For GMAC: len(C) = 0, so bytes 8..16 are zero.
        let mut len_block = [0u8; AES_BLOCK_SIZE];
        let aad_bits = self.total_aad_bytes.saturating_mul(8);
        len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
        self.ghash.update(&len_block);

        let s = self.ghash.result();

        // Tag = S ⊕ E_K(J0)
        let ej0 = self.aes.encrypt_block(&self.j0);
        let mut tag = s;
        xor_block(&mut tag, &ej0);
        tag
    }
}

impl Zeroize for GcmGmacState {
    fn zeroize(&mut self) {
        self.aes.zeroize();
        self.ghash.zeroize();
        self.j0.zeroize();
        self.total_aad_bytes = 0;
    }
}

impl Drop for GcmGmacState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// GMAC Lifecycle State Machine
// =============================================================================

/// Internal state machine tracking the GMAC context lifecycle.
///
/// Prevents misuse (e.g., calling `update()` before `init()` or after
/// `finalize()`).
#[derive(Clone)]
enum GmacComputeState {
    /// Context created but not yet initialised with key and IV.
    Uninitialized,
    /// Actively computing — ready for `update()` or `finalize()`.
    Ready(GcmGmacState),
    /// Tag has been retrieved — must call `init()` to reset before reuse.
    Finalized,
}

// =============================================================================
// GmacProvider — Factory for GMAC contexts
// =============================================================================

/// GMAC provider implementation.
///
/// Galois MAC derived from AES-GCM AEAD tag computation.
/// Processes data as AAD only (no ciphertext produced).
/// Output is the GCM authentication tag (16 bytes).
///
/// Replaces C `ossl_gmac_functions` dispatch table from `gmac_prov.c`.
pub struct GmacProvider;

impl Default for GmacProvider {
    fn default() -> Self {
        Self
    }
}

impl GmacProvider {
    /// Creates a new GMAC provider instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Returns algorithm descriptors for provider registration.
    ///
    /// GMAC is registered under the default provider with a single
    /// canonical name and no aliases.
    #[must_use]
    pub fn descriptors() -> Vec<AlgorithmDescriptor> {
        vec![AlgorithmDescriptor {
            names: vec!["GMAC"],
            property: "provider=default",
            description: "GMAC - Galois Message Authentication Code",
        }]
    }
}

impl MacProvider for GmacProvider {
    fn name(&self) -> &'static str {
        "GMAC"
    }

    fn size(&self) -> usize {
        GMAC_TAG_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>> {
        debug!("Creating new GMAC context");
        Ok(Box::new(GmacContext {
            cipher_name: None,
            properties: None,
            iv: None,
            iv_len: DEFAULT_IV_LEN,
            state: GmacComputeState::Uninitialized,
        }))
    }
}

// =============================================================================
// GmacContext — Streaming GMAC computation context
// =============================================================================

/// GMAC computation context.
///
/// Replaces C `struct gmac_data_st` from `gmac_prov.c`.
/// All data is processed as AAD using an internal GCM cipher context.
///
/// # Lifecycle
///
/// ```text
/// new_ctx() → set_params(cipher, iv) → init(key) → update(aad)* → finalize()
/// ```
///
/// The context can be re-initialised by calling `init()` again with a new key.
#[derive(Clone)]
pub struct GmacContext {
    /// Selected cipher name (must be a GCM-mode cipher, Rule R5: `Option`).
    cipher_name: Option<String>,
    /// Property query string for cipher selection.
    properties: Option<String>,
    /// Initialization vector (required before computation starts).
    iv: Option<Vec<u8>>,
    /// IV length in bytes (default: 12).
    iv_len: usize,
    /// Internal computation state.
    state: GmacComputeState,
}

impl MacContext for GmacContext {
    /// Initialise (or reset) the GMAC context with a key and optional params.
    ///
    /// The cipher must be set (either in `params` or via a prior `set_params`
    /// call) and must be a GCM-mode cipher.  The IV must also be configured.
    ///
    /// Replaces C `gmac_init` from `gmac_prov.c`.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        // Apply parameters if provided (cipher, IV, properties)
        if let Some(p) = params {
            self.apply_params(p)?;
        }

        // Validate that a GCM cipher has been configured
        let cipher_name = self.cipher_name.as_ref().ok_or_else(|| {
            ProviderError::Init(
                "GMAC requires a GCM cipher to be set before init".to_string(),
            )
        })?;
        validate_gcm_mode(cipher_name)?;
        debug!(cipher = %cipher_name, "GMAC init: validated GCM cipher");

        // Validate key is non-empty
        if key.is_empty() {
            return Err(ProviderError::Init(
                "GMAC requires a non-empty key".to_string(),
            ));
        }

        // Validate key length against the selected cipher (if determinable)
        if let Some(expected) = infer_key_length(cipher_name) {
            if key.len() != expected {
                return Err(ProviderError::Init(format!(
                    "Key length {} does not match cipher {cipher_name} (expected {expected})",
                    key.len(),
                )));
            }
        }

        // Retrieve the IV (required for GMAC)
        let iv = self.iv.as_ref().ok_or_else(|| {
            ProviderError::Init("GMAC requires an IV to be set before init".to_string())
        })?;

        // Create AES key schedule and initialise GCM-GMAC state
        let aes = AesKey::new(key)?;
        let gcm_state = GcmGmacState::new(aes, iv);
        self.state = GmacComputeState::Ready(gcm_state);

        debug!("GMAC context initialised successfully");
        Ok(())
    }

    /// Feed AAD data into the GMAC computation.
    ///
    /// All data is processed as Additional Authenticated Data — no ciphertext
    /// is produced.  May be called multiple times before `finalize()`.
    ///
    /// Replaces C `gmac_update` from `gmac_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        trace!(data_len = data.len(), "GMAC update: processing AAD");
        match self.state {
            GmacComputeState::Ready(ref mut gcm) => gcm.update_aad(data),
            GmacComputeState::Uninitialized => Err(ProviderError::Dispatch(
                "GMAC context not initialised — call init() first".to_string(),
            )),
            GmacComputeState::Finalized => Err(ProviderError::Dispatch(
                "GMAC context already finalised — call init() to reset".to_string(),
            )),
        }
    }

    /// Finalise the GMAC computation and return the 16-byte authentication tag.
    ///
    /// The tag is the GCM authentication tag computed over the AAD-only input.
    /// After calling `finalize()`, call `init()` to reset the context.
    ///
    /// Replaces C `gmac_final` from `gmac_prov.c`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        trace!("GMAC finalize: retrieving authentication tag");
        // Move the state out so we can consume the GCM state and drop it
        let state = std::mem::replace(&mut self.state, GmacComputeState::Finalized);
        match state {
            GmacComputeState::Ready(mut gcm) => {
                let tag = gcm.finalize_tag();
                trace!(tag_len = tag.len(), "GMAC finalize: tag computed");
                Ok(tag.to_vec())
            }
            GmacComputeState::Uninitialized => Err(ProviderError::Dispatch(
                "GMAC context not initialised — call init() first".to_string(),
            )),
            GmacComputeState::Finalized => Err(ProviderError::Dispatch(
                "GMAC context already finalised — call init() to reset".to_string(),
            )),
        }
    }

    /// Retrieve current context parameters.
    ///
    /// Returns: output size, cipher name, IV, IV length.
    /// Replaces C `gmac_get_params` / `gmac_get_ctx_params`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        // usize always fits in u64 on supported platforms.
        let mut builder = ParamBuilder::new().push_u64(PARAM_SIZE, GMAC_TAG_SIZE as u64);

        if let Some(ref cipher) = self.cipher_name {
            builder = builder.push_utf8(PARAM_CIPHER, cipher.clone());
        }
        if let Some(ref iv) = self.iv {
            builder = builder.push_octet(PARAM_IV, iv.clone());
        }

        let mut params = builder.build();
        params.set(PARAM_IVLEN, ParamValue::UInt64(self.iv_len as u64));
        Ok(params)
    }

    /// Set context parameters (cipher, IV, IV length, properties).
    ///
    /// Supports the following parameters:
    /// - `"cipher"` — GCM cipher name (UTF-8 string, required)
    /// - `"iv"` — initialization vector (octet string, required)
    /// - `"ivlen"` — IV length override (unsigned integer)
    /// - `"properties"` — property query (UTF-8 string, optional)
    ///
    /// Replaces C `gmac_set_ctx_params` from `gmac_prov.c`.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

impl GmacContext {
    /// Apply parameters from a `ParamSet` to internal configuration.
    ///
    /// Shared between `init()` and `set_params()` to avoid duplication.
    /// Replaces the parameter-handling section of C `gmac_set_ctx_params`.
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Cipher name parameter
        if let Some(val) = params.get(PARAM_CIPHER) {
            let cipher = val.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "cipher parameter must be a UTF-8 string".to_string(),
                ))
            })?;
            debug!(cipher = %cipher, "GMAC: setting cipher");
            self.cipher_name = Some(cipher.to_string());
        }

        // Properties parameter
        if let Some(val) = params.get(PARAM_PROPERTIES) {
            let props = val.as_str().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "properties parameter must be a UTF-8 string".to_string(),
                ))
            })?;
            self.properties = Some(props.to_string());
        }

        // IV length parameter
        if let Some(val) = params.get(PARAM_IVLEN) {
            let iv_len_u64 = val.as_u64().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "ivlen parameter must be a numeric value".to_string(),
                ))
            })?;
            // Rule R6: use try_from for potentially narrowing u64 → usize cast.
            self.iv_len = usize::try_from(iv_len_u64).map_err(|_| {
                ProviderError::Common(CommonError::InvalidArgument(format!(
                    "IV length {iv_len_u64} exceeds platform address space"
                )))
            })?;
        }

        // IV value parameter
        if let Some(val) = params.get(PARAM_IV) {
            let iv = val.as_bytes().ok_or_else(|| {
                ProviderError::Common(CommonError::InvalidArgument(
                    "iv parameter must be an octet string".to_string(),
                ))
            })?;
            self.iv = Some(iv.to_vec());
            // Update iv_len to match actual IV data length
            self.iv_len = iv.len();
        }

        Ok(())
    }
}

impl Zeroize for GmacContext {
    fn zeroize(&mut self) {
        if let Some(ref mut name) = self.cipher_name {
            name.zeroize();
        }
        self.cipher_name = None;
        if let Some(ref mut props) = self.properties {
            props.zeroize();
        }
        self.properties = None;
        if let Some(ref mut iv) = self.iv {
            iv.zeroize();
        }
        self.iv = None;
        self.iv_len = 0;
        if let GmacComputeState::Ready(ref mut gcm) = self.state {
            gcm.zeroize();
        }
        self.state = GmacComputeState::Uninitialized;
    }
}

impl Drop for GmacContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// GCM Mode Validation and Cipher Helpers
// =============================================================================

/// Validate that the given cipher name identifies a GCM-mode cipher.
///
/// GMAC is only valid with GCM ciphers (e.g., `AES-128-GCM`, `AES-256-GCM`).
/// Returns an error if the cipher name does not contain `"GCM"`.
///
/// Replaces C validation:
/// `EVP_CIPHER_get_mode(cipher) != EVP_CIPH_GCM_MODE` (`gmac_prov.c` line 217).
fn validate_gcm_mode(cipher_name: &str) -> ProviderResult<()> {
    let upper = cipher_name.to_uppercase();
    if upper.contains("GCM") {
        debug!(cipher = %cipher_name, "GCM mode validation passed");
        Ok(())
    } else {
        Err(ProviderError::Common(CommonError::InvalidArgument(
            format!("GMAC requires a GCM-mode cipher, got '{cipher_name}'"),
        )))
    }
}

/// Infer the expected AES key length in bytes from a cipher name.
///
/// Returns `None` if the key length cannot be determined from the name
/// (e.g., for non-AES GCM ciphers).
fn infer_key_length(cipher_name: &str) -> Option<usize> {
    let upper = cipher_name.to_uppercase();
    if upper.contains("256") {
        Some(32)
    } else if upper.contains("192") {
        Some(24)
    } else if upper.contains("128") {
        Some(16)
    } else {
        None
    }
}
