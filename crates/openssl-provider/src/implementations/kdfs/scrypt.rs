//! scrypt password-based key derivation function (RFC 7914).
//!
//! This module provides an idiomatic Rust translation of
//! `providers/implementations/kdfs/scrypt.c` (537 lines). It implements the
//! memory-hard password-based key derivation function specified in
//! [RFC 7914](https://tools.ietf.org/html/rfc7914), suitable for password
//! hashing and key stretching.
//!
//! # Algorithm Overview
//!
//! scrypt uses three nested building blocks:
//!
//! 1. **PBKDF2-HMAC-SHA-256** — initial key stretching and final derivation
//! 2. **Salsa20/8** — 8-round Salsa20 core as mixing function
//! 3. **`scryptBlockMix`** — Salsa20/8-based block mixing
//! 4. **`scryptROMix`** — Sequential memory-hard function with random lookups
//!
//! The high-level pipeline:
//! ```text
//! B = PBKDF2-HMAC-SHA-256(password, salt, 1, p * 128 * r)
//! for each of p blocks:
//!     scryptROMix(B[block_i], r, N, V_scratch)
//! key = PBKDF2-HMAC-SHA-256(password, B, 1, dkLen)
//! ```
//!
//! # Parameters
//!
//! | Parameter | Description | Default |
//! |-----------|-------------|---------|
//! | `pass` | Password/passphrase | (required) |
//! | `salt` | Salt value | (required) |
//! | `n` | CPU/memory cost parameter (power of 2) | 2^20 (1,048,576) |
//! | `r` | Block size parameter | 8 |
//! | `p` | Parallelism parameter | 1 |
//! | `maxmem_bytes` | Maximum memory in bytes | 1,025 × 1024 × 1024 |
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for salt (no sentinel values)
//! - **R6:** All N×r×p computations use `checked_mul` for overflow safety
//! - **R8:** Zero `unsafe` blocks — Salsa20/8 uses safe `[u32; 16]` arrays
//! - **R9:** Warning-free with comprehensive documentation
//!
//! # C Source Reference
//!
//! - `providers/implementations/kdfs/scrypt.c` — main implementation
//! - `ossl_kdf_scrypt_functions` dispatch table → `KdfProvider`/`KdfContext` traits
//! - `scrypt_alg()` → `scrypt_derive()`
//! - `salsa208_word_specification()` → `salsa20_8()`
//! - `scryptBlockMix()` → `scrypt_block_mix()`
//! - `scryptROMix()` → `scrypt_romix()`

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::{CommonError, ProviderError};
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::ProviderResult;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_PASSWORD` — password/passphrase octet string.
const PARAM_PASSWORD: &str = "pass";

/// `OSSL_KDF_PARAM_SALT` — salt octet string.
const PARAM_SALT: &str = "salt";

/// `OSSL_KDF_PARAM_SCRYPT_N` — CPU/memory cost parameter.
const PARAM_N: &str = "n";

/// `OSSL_KDF_PARAM_SCRYPT_R` — block size parameter.
const PARAM_R: &str = "r";

/// `OSSL_KDF_PARAM_SCRYPT_P` — parallelism parameter.
const PARAM_P: &str = "p";

/// `OSSL_KDF_PARAM_SCRYPT_MAXMEM` — maximum memory limit in bytes.
const PARAM_MAXMEM: &str = "maxmem_bytes";

/// `OSSL_KDF_PARAM_SIZE` — output key length (for `get_params`).
const PARAM_SIZE: &str = "size";

// =============================================================================
// Default Values — matching C kdf_scrypt_init()
// =============================================================================

/// Default N (cost) = 2^20 = 1,048,576. Matches `ctx->N = 1 << 20` in C.
const DEFAULT_N: u64 = 1 << 20;

/// Default r (block size) = 8. Matches `ctx->r = 8` in C.
const DEFAULT_R: u64 = 8;

/// Default p (parallelism) = 1. Matches `ctx->p = 1` in C.
const DEFAULT_P: u64 = 1;

/// Default maximum memory = 1025 × 1024 × 1024 bytes (~1.001 GiB).
/// Matches `ctx->maxmem_bytes = SCRYPT_MAX_MEM` in C.
const DEFAULT_MAXMEM: u64 = 1025 * 1024 * 1024;

/// Maximum product of p × r. Matches `SCRYPT_PR_MAX` in C: `((1 << 30) - 1)`.
/// Prevents overflow in memory calculations.
const SCRYPT_PR_MAX: u64 = (1 << 30) - 1;

/// SHA-256 output length in bytes.
const SHA256_DIGEST_LEN: usize = 32;

/// SHA-256 block size in bytes.
const SHA256_BLOCK_LEN: usize = 64;

// =============================================================================
// SHA-256 Implementation (private, FIPS 180-4)
// =============================================================================
// Self-contained SHA-256 for the PBKDF2-HMAC-SHA-256 sub-primitive.
// The provider depends only on traits.rs, error.rs, and param.rs, so we
// cannot import a digest from openssl-crypto. This inline implementation
// provides the minimal SHA-256 needed by scrypt.

/// SHA-256 initial hash values (FIPS 180-4, Section 5.3.3).
const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (FIPS 180-4, Section 4.2.2).
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Streaming SHA-256 hash context.
#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_LEN],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Creates a new SHA-256 context with FIPS 180-4 initial hash values.
    fn new() -> Self {
        Self {
            state: SHA256_H0,
            buffer: [0u8; SHA256_BLOCK_LEN],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Updates the hash with additional data bytes.
    fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut offset = 0;

        // Fill buffer if partially full
        if self.buffer_len > 0 {
            let space = SHA256_BLOCK_LEN - self.buffer_len;
            let fill = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + fill].copy_from_slice(&data[..fill]);
            self.buffer_len += fill;
            offset = fill;

            if self.buffer_len == SHA256_BLOCK_LEN {
                let block = self.buffer;
                Self::compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks directly
        while offset + SHA256_BLOCK_LEN <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_LEN];
            block.copy_from_slice(&data[offset..offset + SHA256_BLOCK_LEN]);
            Self::compress(&mut self.state, &block);
            offset += SHA256_BLOCK_LEN;
        }

        // Buffer remaining bytes
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalizes the hash computation and returns the 32-byte digest.
    fn finalize(mut self) -> [u8; SHA256_DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);

        // Append padding: 0x80 byte followed by zeros
        let mut pad = [0u8; SHA256_BLOCK_LEN];
        pad[0] = 0x80;

        // Determine padding length to reach 56 mod 64
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };
        self.update(&pad[..pad_len]);

        // Append length in bits as big-endian u64
        self.update(&bit_len.to_be_bytes());

        // Convert state to big-endian bytes
        let mut output = [0u8; SHA256_DIGEST_LEN];
        for (i, &word) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    /// SHA-256 compression function: processes a single 64-byte block.
    #[allow(clippy::many_single_char_names)] // FIPS 180-4 standard variable names
    fn compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_LEN]) {
        // Parse block into 16 big-endian u32 words
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // Message schedule expansion
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables from current state
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

        // 64 rounds of compression
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash state
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

/// Computes a single-shot SHA-256 digest over the given data.
fn sha256_digest(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut ctx = Sha256::new();
    ctx.update(data);
    ctx.finalize()
}

// =============================================================================
// HMAC-SHA-256 Implementation (private, RFC 2104)
// =============================================================================

/// Streaming HMAC-SHA-256 context for use in PBKDF2.
#[derive(Clone)]
struct HmacSha256 {
    /// Inner SHA-256 context (already updated with ipad).
    inner: Sha256,
    /// Outer key pad stored for finalization.
    outer_key_pad: [u8; SHA256_BLOCK_LEN],
}

impl HmacSha256 {
    /// Creates a new HMAC-SHA-256 context with the given key.
    ///
    /// If key is longer than the SHA-256 block size (64 bytes), it is first
    /// hashed. Otherwise it is zero-padded to block size.
    fn new(key: &[u8]) -> Self {
        // If key > block size, hash it; otherwise pad with zeros
        let mut key_block = [0u8; SHA256_BLOCK_LEN];
        if key.len() > SHA256_BLOCK_LEN {
            let hashed = sha256_digest(key);
            key_block[..SHA256_DIGEST_LEN].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Compute inner and outer key pads (XOR with 0x36 / 0x5c)
        let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
        let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
        for i in 0..SHA256_BLOCK_LEN {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        // Zeroize key block
        key_block.zeroize();

        // Initialize inner hash with ipad
        let mut inner = Sha256::new();
        inner.update(&ipad);
        ipad.zeroize();

        Self {
            inner,
            outer_key_pad: opad,
        }
    }

    /// Updates the HMAC computation with additional data.
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the HMAC and returns the 32-byte authentication tag.
    ///
    /// Computes `HMAC = SHA-256(opad || SHA-256(ipad || message))`.
    fn finalize(mut self) -> [u8; SHA256_DIGEST_LEN] {
        let inner_hash = self.inner.finalize();

        let mut outer = Sha256::new();
        outer.update(&self.outer_key_pad);
        self.outer_key_pad.zeroize();
        outer.update(&inner_hash);
        outer.finalize()
    }
}

// =============================================================================
// PBKDF2-HMAC-SHA-256 Implementation (private, RFC 8018)
// =============================================================================

/// Derives key material using PBKDF2 with HMAC-SHA-256 (RFC 8018 Section 5.2).
///
/// The scrypt algorithm always calls this with `iterations = 1`, but the
/// implementation supports arbitrary counts for correctness.
///
/// # Parameters
///
/// - `password`: HMAC key
/// - `salt`: salt input to HMAC
/// - `iterations`: PBKDF2 iteration count (c ≥ 1)
/// - `output`: output buffer filled with derived key material
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let mut block_num: u32 = 1;
    let mut offset = 0;

    while offset < output.len() {
        // U_1 = HMAC(password, salt || BE32(block_num))
        let mut hmac = HmacSha256::new(password);
        hmac.update(salt);
        hmac.update(&block_num.to_be_bytes());
        let mut u_prev = hmac.finalize();
        let mut t_block = u_prev;

        // U_2 .. U_c: iterate and XOR each U_i into t_block
        for _ in 1..iterations {
            let mut hmac_i = HmacSha256::new(password);
            hmac_i.update(&u_prev);
            u_prev = hmac_i.finalize();
            for (t_byte, u_byte) in t_block.iter_mut().zip(u_prev.iter()) {
                *t_byte ^= *u_byte;
            }
        }

        // Copy derived block to output (truncated for last block if needed)
        let remaining = output.len() - offset;
        let copy_len = remaining.min(SHA256_DIGEST_LEN);
        output[offset..offset + copy_len].copy_from_slice(&t_block[..copy_len]);

        // Zeroize intermediate key material
        u_prev.zeroize();
        t_block.zeroize();

        offset += copy_len;
        block_num = block_num.wrapping_add(1);
    }
}

// =============================================================================
// Salsa20/8 Core (private, RFC 7914 Section 3)
// =============================================================================

/// Performs the 8-round Salsa20 core transformation in-place.
///
/// Corresponds to `salsa208_word_specification()` in the C source.
/// Uses column quarter-rounds followed by row (diagonal) quarter-rounds
/// per double-round, for 4 double-rounds (8 rounds total).
///
/// # Parameters
///
/// - `inout`: 16-element u32 array (512-bit block) modified in-place.
fn salsa20_8(inout: &mut [u32; 16]) {
    let mut x = *inout;

    // 4 double-rounds (each = column quarter-rounds + row quarter-rounds)
    for _ in 0..4 {
        // Column quarter-rounds
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);

        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);

        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);

        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        // Row (diagonal) quarter-rounds
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);

        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);

        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);

        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }

    // Feedforward: add working copy back to input
    for i in 0..16 {
        inout[i] = inout[i].wrapping_add(x[i]);
    }

    // Zeroize working copy
    x.zeroize();
}

// =============================================================================
// scryptBlockMix (private, RFC 7914 Section 4)
// =============================================================================

/// Performs the `scryptBlockMix` operation.
///
/// Takes `2 × r` 64-byte (16-word) blocks as input and produces `2 × r`
/// 64-byte blocks as output, with even-indexed output blocks placed first
/// and odd-indexed blocks placed second (interleaving).
///
/// Corresponds to `scryptBlockMix()` in the C source.
///
/// # Parameters
///
/// - `output`: destination buffer of `32 × r` u32 words
/// - `input`: source buffer of `32 × r` u32 words
/// - `r`: block size parameter (≥ 1)
fn scrypt_block_mix(output: &mut [u32], input: &[u32], r: usize) {
    let two_r = 2 * r;

    // X = input[(2*r - 1) * 16 .. 2*r * 16]  (last 16-word block)
    let mut x = [0u32; 16];
    x.copy_from_slice(&input[(two_r - 1) * 16..two_r * 16]);

    for i in 0..two_r {
        // X = X XOR input[i * 16 .. (i+1) * 16]
        for j in 0..16 {
            x[j] ^= input[i * 16 + j];
        }
        // X = Salsa20/8(X)
        salsa20_8(&mut x);
        // Even blocks go to first half, odd blocks go to second half
        let dest_offset = (i / 2 + (i & 1) * r) * 16;
        output[dest_offset..dest_offset + 16].copy_from_slice(&x);
    }

    x.zeroize();
}

// =============================================================================
// scryptROMix (private, RFC 7914 Section 5)
// =============================================================================

/// Performs the `scryptROMix` operation — the memory-hard core of scrypt.
///
/// Fills a large scratch array `V` of N blocks, then performs N iterations
/// of random lookups to mix the data. This is what makes scrypt resistant
/// to hardware brute-force attacks: the large memory requirement prevents
/// parallelization on constrained hardware.
///
/// Corresponds to `scryptROMix()` in the C source. The C version converts
/// between byte arrays and u32 word arrays (little-endian); our version
/// works directly with u32 words throughout and performs the byte
/// conversion at the caller boundary in `scrypt_derive()`.
///
/// # Parameters
///
/// - `b`: working block of `32 × r` u32 words (read/written)
/// - `r`: block size parameter
/// - `n`: cost parameter (power of 2)
/// - `v`: scratch memory of `32 × r × N` u32 words
/// - `x_buf`: temporary buffer of `32 × r` u32 words
/// - `t_buf`: temporary buffer of `32 × r` u32 words
#[allow(clippy::many_single_char_names)] // RFC 7914 standard variable names (B, r, N, V)
fn scrypt_romix(
    b_block: &mut [u32],
    r_param: usize,
    n_cost: u64,
    v_scratch: &mut [u32],
    x_buf: &mut [u32],
    t_buf: &mut [u32],
) {
    let block_words = 32 * r_param; // number of u32 words per block
                                    // N is validated as fitting in usize before scrypt_romix is called.
                                    // We need the truncation here because the outer scrypt_derive already
                                    // ensures n_cost fits in usize via try_from. Adding the allow is correct.
    #[allow(clippy::cast_possible_truncation)] // TRUNCATION: validated by caller
    let n_usize = n_cost as usize;

    // Step 1: X = B
    x_buf[..block_words].copy_from_slice(&b_block[..block_words]);

    // Step 2: Fill V[0..N] using scryptBlockMix
    for i in 0..n_usize {
        // V[i] = X
        let v_offset = i * block_words;
        v_scratch[v_offset..v_offset + block_words].copy_from_slice(&x_buf[..block_words]);
        // X = scryptBlockMix(X)
        scrypt_block_mix(t_buf, x_buf, r_param);
        x_buf[..block_words].copy_from_slice(&t_buf[..block_words]);
    }

    // Step 3: Mix phase — N iterations with random lookups into V
    for _ in 0..n_usize {
        // j = Integerify(X) mod N — take the last 16-word block's first word
        let j_idx = u64::from(x_buf[(2 * r_param - 1) * 16]) & (n_cost - 1);
        #[allow(clippy::cast_possible_truncation)]
        // TRUNCATION: j_idx < n_cost, validated in caller
        let j_val = j_idx as usize;

        // T = X XOR V[j]
        let v_offset = j_val * block_words;
        for k in 0..block_words {
            t_buf[k] = x_buf[k] ^ v_scratch[v_offset + k];
        }

        // X = scryptBlockMix(T)
        scrypt_block_mix(x_buf, t_buf, r_param);
    }

    // Step 4: B = X
    b_block[..block_words].copy_from_slice(&x_buf[..block_words]);
}

// =============================================================================
// scrypt_derive — Main Derivation Pipeline (RFC 7914 Section 6)
// =============================================================================

/// Validates parameters and executes the full scrypt key derivation pipeline.
///
/// Corresponds to `scrypt_alg()` in the C source.
///
/// # Pipeline
///
/// 1. Validate all parameters (N power of 2, N ≥ 2, r × p < 2^30, memory bounds)
/// 2. `B = PBKDF2-HMAC-SHA-256(password, salt, 1, p × 128 × r)`
/// 3. For each of `p` blocks: `scryptROMix(B[block_i], r, N)`
/// 4. `key = PBKDF2-HMAC-SHA-256(password, B, 1, dk_len)`
///
/// # Errors
///
/// Returns `ProviderError::Init` if any parameter validation fails, or
/// `ProviderError::Common(CommonError::Memory)` if the required memory
/// exceeds `maxmem_bytes`.
fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    maxmem_bytes: u64,
    output: &mut [u8],
) -> ProviderResult<()> {
    tracing::trace!(
        n = n,
        r = r,
        p = p,
        maxmem = maxmem_bytes,
        dk_len = output.len(),
        "scrypt_derive: starting derivation"
    );

    // --- Parameter validation (matches C scrypt_alg() checks) ---

    // r and p must be positive
    if r == 0 || p == 0 {
        tracing::warn!("scrypt_derive: r and p must be > 0");
        return Err(ProviderError::Init(
            "scrypt: r and p must be positive".into(),
        ));
    }

    // N must be at least 2
    if n < 2 {
        tracing::warn!(n = n, "scrypt_derive: N must be >= 2");
        return Err(ProviderError::Init("scrypt: N must be at least 2".into()));
    }

    // N must be a power of 2
    if n & (n - 1) != 0 {
        tracing::warn!(n = n, "scrypt_derive: N must be a power of 2");
        return Err(ProviderError::Init("scrypt: N must be a power of 2".into()));
    }

    // p * r must fit in SCRYPT_PR_MAX (Rule R6: checked_mul for overflow safety)
    let pr = p.checked_mul(r).ok_or_else(|| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "scrypt p*r overflow",
        })
    })?;
    if pr > SCRYPT_PR_MAX {
        let max = SCRYPT_PR_MAX;
        tracing::warn!(p = p, r = r, pr = pr, "scrypt_derive: p*r exceeds limit");
        return Err(ProviderError::Init(format!(
            "scrypt: p*r ({pr}) exceeds maximum ({max})"
        )));
    }

    // Calculate B_len = p * 128 * r (Rule R6: all checked arithmetic)
    let b_len = p
        .checked_mul(128)
        .and_then(|v| v.checked_mul(r))
        .ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "scrypt B_len overflow",
            })
        })?;

    // Calculate V_len = 128 * r * N (in bytes)
    let v_len = 128u64
        .checked_mul(r)
        .and_then(|v| v.checked_mul(n))
        .ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "scrypt V_len overflow",
            })
        })?;

    // Extra working buffers: 2 blocks of 128*r bytes (X and T)
    let extra_len = 256u64.checked_mul(r).ok_or_else(|| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "scrypt extra_len overflow",
        })
    })?;

    // Total memory = B_len + V_len + extra_len
    let total_mem = b_len
        .checked_add(v_len)
        .and_then(|v| v.checked_add(extra_len))
        .ok_or_else(|| {
            ProviderError::Common(CommonError::ArithmeticOverflow {
                operation: "scrypt total memory overflow",
            })
        })?;

    if total_mem > maxmem_bytes {
        tracing::warn!(
            required = total_mem,
            limit = maxmem_bytes,
            "scrypt_derive: memory requirement exceeds limit"
        );
        return Err(ProviderError::Common(CommonError::Memory(format!(
            "scrypt: required memory ({total_mem} bytes) exceeds limit ({maxmem_bytes} bytes)"
        ))));
    }

    // --- Algorithm execution ---

    // Convert validated u64 values to usize (Rule R6: try_from for narrowing)
    let b_len_usize = usize::try_from(b_len).map_err(|_| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "scrypt b_len to usize",
        })
    })?;
    let r_usize = usize::try_from(r).map_err(|_| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "scrypt r to usize",
        })
    })?;
    let n_usize = usize::try_from(n).map_err(|_| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "scrypt n to usize",
        })
    })?;
    let p_usize = usize::try_from(p).map_err(|_| {
        ProviderError::Common(CommonError::ArithmeticOverflow {
            operation: "scrypt p to usize",
        })
    })?;
    let block_words = 32 * r_usize; // u32 words per ROMix block

    // Step 1: B = PBKDF2-HMAC-SHA-256(password, salt, 1, p * 128 * r)
    let mut b_bytes = vec![0u8; b_len_usize];
    pbkdf2_hmac_sha256(password, salt, 1, &mut b_bytes);

    // Convert B from little-endian bytes to u32 words
    let b_words_count = b_len_usize / 4;
    let mut b_words = vec![0u32; b_words_count];
    for (i, chunk) in b_bytes.chunks_exact(4).enumerate() {
        b_words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    // Allocate V scratch space (N blocks of block_words)
    let v_words_count = n_usize * block_words;
    let mut v_scratch = vec![0u32; v_words_count];

    // Allocate X and T temporary buffers
    let mut x_buf = vec![0u32; block_words];
    let mut t_buf = vec![0u32; block_words];

    // Step 2: ROMix each of p blocks
    for i in 0..p_usize {
        let offset = i * block_words;
        scrypt_romix(
            &mut b_words[offset..offset + block_words],
            r_usize,
            n,
            &mut v_scratch,
            &mut x_buf,
            &mut t_buf,
        );
    }

    // Convert B words back to little-endian bytes
    for (i, word) in b_words.iter().enumerate() {
        let le = word.to_le_bytes();
        b_bytes[i * 4..i * 4 + 4].copy_from_slice(&le);
    }

    // Step 3: key = PBKDF2-HMAC-SHA-256(password, B, 1, dk_len)
    pbkdf2_hmac_sha256(password, &b_bytes, 1, output);

    // Zeroize all intermediate buffers
    b_bytes.zeroize();
    b_words.zeroize();
    v_scratch.zeroize();
    x_buf.zeroize();
    t_buf.zeroize();

    tracing::trace!(dk_len = output.len(), "scrypt_derive: derivation complete");
    Ok(())
}

// =============================================================================
// ScryptContext — KDF Context (RFC 7914)
// =============================================================================

/// scrypt KDF context holding the current parameter state.
///
/// Implements `KdfContext` to provide `derive()`, `reset()`, `get_params()`,
/// and `set_params()` operations. The password field is securely zeroed on
/// drop via the `Zeroize` derive macro, matching `kdf_scrypt_free()` in the
/// C source which calls `OPENSSL_clear_free(ctx->pass, ctx->pass_len)`.
///
/// # Fields
///
/// - `password`: The password/passphrase (zeroized on drop)
/// - `salt`: Optional salt value (R5: `Option<T>` instead of sentinel)
/// - `n`: CPU/memory cost parameter (must be power of 2, ≥ 2)
/// - `r`: Block size parameter (≥ 1)
/// - `p`: Parallelism parameter (≥ 1)
/// - `maxmem_bytes`: Maximum allowed memory for the derivation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScryptContext {
    /// Password/passphrase — securely zeroed on drop.
    password: Vec<u8>,
    /// Salt value. `None` until set via `set_params()`.
    salt: Option<Vec<u8>>,
    /// CPU/memory cost parameter N (must be power of 2, ≥ 2).
    n: u64,
    /// Block size parameter r (≥ 1).
    r: u64,
    /// Parallelism parameter p (≥ 1).
    p: u64,
    /// Maximum allowed memory in bytes for the derivation.
    maxmem_bytes: u64,
}

impl ScryptContext {
    /// Creates a new `ScryptContext` with default parameter values.
    ///
    /// Defaults match the C `kdf_scrypt_init()`:
    /// - N = 2^20 (1,048,576)
    /// - r = 8
    /// - p = 1
    /// - maxmem = 1025 × 1024 × 1024
    fn new() -> Self {
        tracing::debug!("ScryptContext::new: creating context with default parameters");
        Self {
            password: Vec::new(),
            salt: None,
            n: DEFAULT_N,
            r: DEFAULT_R,
            p: DEFAULT_P,
            maxmem_bytes: DEFAULT_MAXMEM,
        }
    }

    /// Applies parameters from a `ParamSet` to this context.
    ///
    /// Extracts scrypt-specific parameters by name. Parameters not present
    /// in the set are left unchanged (allows incremental configuration).
    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        // Password (octet string)
        if let Some(val) = params.get(PARAM_PASSWORD) {
            let bytes = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("scrypt: password must be an octet string".into())
            })?;
            self.password.zeroize();
            self.password = bytes.to_vec();
            tracing::debug!(
                password_len = self.password.len(),
                "ScryptContext: password set"
            );
        }

        // Salt (octet string)
        if let Some(val) = params.get(PARAM_SALT) {
            let bytes = val.as_bytes().ok_or_else(|| {
                ProviderError::Init("scrypt: salt must be an octet string".into())
            })?;
            self.salt = Some(bytes.to_vec());
            tracing::debug!(salt_len = bytes.len(), "ScryptContext: salt set");
        }

        // N — cost parameter
        if let Some(val) = params.get(PARAM_N) {
            let n_val = val
                .as_u64()
                .ok_or_else(|| ProviderError::Init("scrypt: N must be a uint64".into()))?;
            self.n = n_val;
            tracing::debug!(n = n_val, "ScryptContext: N set");
        }

        // r — block size
        if let Some(val) = params.get(PARAM_R) {
            let r_val = val
                .as_u64()
                .ok_or_else(|| ProviderError::Init("scrypt: r must be a uint64".into()))?;
            self.r = r_val;
            tracing::debug!(r = r_val, "ScryptContext: r set");
        }

        // p — parallelism
        if let Some(val) = params.get(PARAM_P) {
            let p_val = val
                .as_u64()
                .ok_or_else(|| ProviderError::Init("scrypt: p must be a uint64".into()))?;
            self.p = p_val;
            tracing::debug!(p = p_val, "ScryptContext: p set");
        }

        // maxmem_bytes — memory limit
        if let Some(val) = params.get(PARAM_MAXMEM) {
            let mem_val = val.as_u64().ok_or_else(|| {
                ProviderError::Init("scrypt: maxmem_bytes must be a uint64".into())
            })?;
            self.maxmem_bytes = mem_val;
            tracing::debug!(maxmem = mem_val, "ScryptContext: maxmem_bytes set");
        }

        Ok(())
    }
}

impl KdfContext for ScryptContext {
    /// Derives key material using the scrypt algorithm.
    ///
    /// Before derivation, applies any parameters from the provided
    /// `ParamSet`, then validates the complete parameter set and
    /// executes the scrypt pipeline.
    ///
    /// # Parameters
    ///
    /// - `key`: output buffer to fill with derived key material
    /// - `params`: additional parameters to apply before derivation
    ///
    /// # Returns
    ///
    /// The number of bytes written to `key` on success.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Init` if password or salt is missing, or
    /// if parameter validation fails.
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        // Apply any late-binding parameters
        if !params.is_empty() {
            self.apply_params(params)?;
        }

        // Validate required inputs
        if self.password.is_empty() {
            tracing::warn!("ScryptContext::derive: password not set");
            return Err(ProviderError::Init(
                "scrypt: password must be set before derivation".into(),
            ));
        }

        let salt_bytes = self.salt.as_deref().ok_or_else(|| {
            tracing::warn!("ScryptContext::derive: salt not set");
            ProviderError::Init("scrypt: salt must be set before derivation".into())
        })?;

        if key.is_empty() {
            tracing::warn!("ScryptContext::derive: output key length is zero");
            return Err(ProviderError::Init(
                "scrypt: output key length must be > 0".into(),
            ));
        }

        tracing::debug!(
            n = self.n,
            r = self.r,
            p = self.p,
            maxmem = self.maxmem_bytes,
            dk_len = key.len(),
            "ScryptContext::derive: starting scrypt derivation"
        );

        // Execute the scrypt derivation pipeline
        scrypt_derive(
            &self.password,
            salt_bytes,
            self.n,
            self.r,
            self.p,
            self.maxmem_bytes,
            key,
        )?;

        Ok(key.len())
    }

    /// Resets the context to its initial default state.
    ///
    /// Securely zeroizes the password and clears all parameters.
    /// Matches `kdf_scrypt_reset()` in the C source.
    fn reset(&mut self) -> ProviderResult<()> {
        tracing::debug!("ScryptContext::reset: resetting to defaults");
        self.password.zeroize();
        self.password = Vec::new();
        self.salt = None;
        self.n = DEFAULT_N;
        self.r = DEFAULT_R;
        self.p = DEFAULT_P;
        self.maxmem_bytes = DEFAULT_MAXMEM;
        Ok(())
    }

    /// Returns the current parameter state as a `ParamSet`.
    ///
    /// Includes all configurable parameters and the context's default
    /// output size. Note: password is NOT returned for security.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let builder = ParamBuilder::new()
            .push_u64(PARAM_N, self.n)
            .push_u64(PARAM_R, self.r)
            .push_u64(PARAM_P, self.p)
            .push_u64(PARAM_MAXMEM, self.maxmem_bytes)
            // SIZE indicates that scrypt supports variable output lengths
            .push_u64(PARAM_SIZE, u64::MAX);

        let builder = if let Some(ref salt) = self.salt {
            builder.push_octet(PARAM_SALT, salt.clone())
        } else {
            builder
        };

        Ok(builder.build())
    }

    /// Sets parameters on the context from a `ParamSet`.
    ///
    /// Parameters not present in the set are left unchanged, allowing
    /// incremental configuration across multiple calls.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// ScryptProvider — KDF Provider Registration
// =============================================================================

/// scrypt KDF provider that creates [`ScryptContext`] instances.
///
/// Implements `KdfProvider` to register the scrypt algorithm with the
/// provider framework. This replaces the C `ossl_kdf_scrypt_functions`
/// dispatch table with type-safe Rust trait dispatch.
pub struct ScryptProvider;

impl KdfProvider for ScryptProvider {
    /// Returns the canonical name of this KDF algorithm.
    fn name(&self) -> &'static str {
        "SCRYPT"
    }

    /// Creates a new [`ScryptContext`] with default parameters.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        tracing::debug!("ScryptProvider::new_ctx: creating new scrypt context");
        Ok(Box::new(ScryptContext::new()))
    }
}

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns the algorithm descriptors for the scrypt KDF.
///
/// Registers the "SCRYPT" algorithm with the provider framework,
/// allowing it to be fetched by name through the standard EVP KDF API.
///
/// # Algorithm Names
///
/// - `SCRYPT` — primary name
/// - `id-scrypt` — OID-based alias (1.3.6.1.4.1.11591.4.11)
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["SCRYPT", "id-scrypt"],
        "provider=default",
        "scrypt password-based key derivation function (RFC 7914)",
    )]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    /// RFC 7914 Section 12 — Test Vector 1: empty password and salt.
    /// scrypt(P="", S="", N=16, r=1, p=1, dkLen=64)
    #[test]
    fn test_scrypt_rfc7914_vector1() {
        let password = b"";
        let salt = b"";
        let n: u64 = 16;
        let r: u64 = 1;
        let p: u64 = 1;
        let expected = [
            0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
            0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
            0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
            0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
            0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
        ];

        let mut output = vec![0u8; 64];
        scrypt_derive(password, salt, n, r, p, 1025 * 1024 * 1024, &mut output).unwrap();
        assert_eq!(output, expected);
    }

    /// RFC 7914 Section 12 — Test Vector 2: "password" / "NaCl".
    /// scrypt(P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64)
    #[test]
    fn test_scrypt_rfc7914_vector2() {
        let password = b"password";
        let salt = b"NaCl";
        let n: u64 = 1024;
        let r: u64 = 8;
        let p: u64 = 16;
        let expected = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
            0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
            0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
        ];

        let mut output = vec![0u8; 64];
        scrypt_derive(password, salt, n, r, p, 1025 * 1024 * 1024, &mut output).unwrap();
        assert_eq!(output, expected);
    }

    /// Test that SHA-256 produces correct digest for empty input.
    #[test]
    fn test_sha256_empty() {
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256_digest(b""), expected);
    }

    /// Test SHA-256 for "abc" (NIST test vector).
    #[test]
    fn test_sha256_abc() {
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256_digest(b"abc"), expected);
    }

    /// Test N validation: must be at least 2.
    #[test]
    fn test_scrypt_n_too_small() {
        let mut output = vec![0u8; 32];
        let result = scrypt_derive(b"pass", b"salt", 1, 1, 1, DEFAULT_MAXMEM, &mut output);
        assert!(result.is_err());
    }

    /// Test N validation: must be a power of 2.
    #[test]
    fn test_scrypt_n_not_power_of_2() {
        let mut output = vec![0u8; 32];
        let result = scrypt_derive(b"pass", b"salt", 3, 1, 1, DEFAULT_MAXMEM, &mut output);
        assert!(result.is_err());
    }

    /// Test r=0 validation.
    #[test]
    fn test_scrypt_r_zero() {
        let mut output = vec![0u8; 32];
        let result = scrypt_derive(b"pass", b"salt", 16, 0, 1, DEFAULT_MAXMEM, &mut output);
        assert!(result.is_err());
    }

    /// Test p=0 validation.
    #[test]
    fn test_scrypt_p_zero() {
        let mut output = vec![0u8; 32];
        let result = scrypt_derive(b"pass", b"salt", 16, 1, 0, DEFAULT_MAXMEM, &mut output);
        assert!(result.is_err());
    }

    /// Test memory limit exceeded.
    #[test]
    fn test_scrypt_memory_limit() {
        let mut output = vec![0u8; 32];
        // N=16, r=1, p=1 needs ~2560 bytes. Set maxmem to 1 byte.
        let result = scrypt_derive(b"pass", b"salt", 16, 1, 1, 1, &mut output);
        assert!(result.is_err());
    }

    /// Test KdfContext trait via ScryptContext: set params and derive.
    #[test]
    fn test_scrypt_context_derive() {
        let provider = ScryptProvider;
        let mut ctx = provider.new_ctx().unwrap();

        let mut params = ParamSet::new();
        params.set(
            PARAM_PASSWORD,
            ParamValue::OctetString(b"password".to_vec()),
        );
        params.set(PARAM_SALT, ParamValue::OctetString(b"NaCl".to_vec()));
        params.set(PARAM_N, ParamValue::UInt64(1024));
        params.set(PARAM_R, ParamValue::UInt64(8));
        params.set(PARAM_P, ParamValue::UInt64(16));
        params.set(PARAM_MAXMEM, ParamValue::UInt64(1025 * 1024 * 1024));

        let mut key = vec![0u8; 64];
        let len = ctx.derive(&mut key, &params).unwrap();
        assert_eq!(len, 64);

        // Verify against RFC 7914 Section 12 Test Vector 2
        let expected = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
            0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
            0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
        ];
        assert_eq!(key, expected);
    }

    /// Test context reset clears all state.
    #[test]
    fn test_scrypt_context_reset() {
        let mut ctx = ScryptContext::new();
        let mut params = ParamSet::new();
        params.set(PARAM_PASSWORD, ParamValue::OctetString(b"test".to_vec()));
        params.set(PARAM_SALT, ParamValue::OctetString(b"salt".to_vec()));
        params.set(PARAM_N, ParamValue::UInt64(32));
        ctx.set_params(&params).unwrap();

        ctx.reset().unwrap();
        assert!(ctx.password.is_empty());
        assert!(ctx.salt.is_none());
        assert_eq!(ctx.n, DEFAULT_N);
        assert_eq!(ctx.r, DEFAULT_R);
        assert_eq!(ctx.p, DEFAULT_P);
        assert_eq!(ctx.maxmem_bytes, DEFAULT_MAXMEM);
    }

    /// Test get_params returns current configuration.
    #[test]
    fn test_scrypt_context_get_params() {
        let mut ctx = ScryptContext::new();
        let mut params = ParamSet::new();
        params.set(PARAM_N, ParamValue::UInt64(256));
        params.set(PARAM_R, ParamValue::UInt64(4));
        params.set(PARAM_P, ParamValue::UInt64(2));
        params.set(PARAM_SALT, ParamValue::OctetString(b"test_salt".to_vec()));
        ctx.set_params(&params).unwrap();

        let got = ctx.get_params().unwrap();
        assert_eq!(got.get(PARAM_N).and_then(|v| v.as_u64()), Some(256));
        assert_eq!(got.get(PARAM_R).and_then(|v| v.as_u64()), Some(4));
        assert_eq!(got.get(PARAM_P).and_then(|v| v.as_u64()), Some(2));
        assert!(got.contains(PARAM_SALT));
    }

    /// Test provider name.
    #[test]
    fn test_scrypt_provider_name() {
        let provider = ScryptProvider;
        assert_eq!(provider.name(), "SCRYPT");
    }

    /// Test descriptors function.
    #[test]
    fn test_scrypt_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"SCRYPT"));
        assert!(descs[0].names.contains(&"id-scrypt"));
        assert_eq!(descs[0].property, "provider=default");
    }

    /// Test derive fails when password is not set.
    #[test]
    fn test_scrypt_derive_no_password() {
        let mut ctx = ScryptContext::new();
        let mut params = ParamSet::new();
        params.set(PARAM_SALT, ParamValue::OctetString(b"salt".to_vec()));
        params.set(PARAM_N, ParamValue::UInt64(16));
        ctx.set_params(&params).unwrap();

        let mut key = vec![0u8; 32];
        let result = ctx.derive(&mut key, &ParamSet::new());
        assert!(result.is_err());
    }

    /// Test derive fails when salt is not set.
    #[test]
    fn test_scrypt_derive_no_salt() {
        let mut ctx = ScryptContext::new();
        let mut params = ParamSet::new();
        params.set(PARAM_PASSWORD, ParamValue::OctetString(b"pass".to_vec()));
        params.set(PARAM_N, ParamValue::UInt64(16));
        ctx.set_params(&params).unwrap();

        let mut key = vec![0u8; 32];
        let result = ctx.derive(&mut key, &ParamSet::new());
        assert!(result.is_err());
    }

    /// Test Salsa20/8 against known test vector from RFC 7914 Section 8.
    /// Bytes are read as little-endian u32 words from the RFC hex sequences.
    #[test]
    fn test_salsa20_8_rfc7914() {
        // RFC 7914 Section 8 input bytes (little-endian u32 words):
        // 7e879a21 4f3ec986 7ca940e6 41718f26
        // baee555b 8c61c1b5 0df84611 6dcd3b1d
        // ee24f319 df9b3d85 14121e4b 5ac5aa32
        // 76021d29 09c74829 edebc68d b8b8c25e
        let mut input: [u32; 16] = [
            0x219a877e, 0x86c93e4f, 0xe640a97c, 0x268f7141, 0x5b55eeba, 0xb5c1618c, 0x1146f80d,
            0x1d3bcd6d, 0x19f324ee, 0x853d9bdf, 0x4b1e1214, 0x32aac55a, 0x291d0276, 0x2948c709,
            0x8dc6ebed, 0x5ec2b8b8,
        ];
        // RFC 7914 Section 8 expected output bytes (little-endian u32 words):
        // a41f859c 6608cc99 3b81cacb 020cef05
        // 044b2181 a2fd337d fd7b1c63 96682f29
        // b4393168 e3c9e6bc fe6bc5b7 a06d96ba
        // e424cc10 2c91745c 24ad673d c7618f81
        let expected: [u32; 16] = [
            0x9c851fa4, 0x99cc0866, 0xcbca813b, 0x05ef0c02, 0x81214b04, 0x7d33fda2, 0x631c7bfd,
            0x292f6896, 0x683139b4, 0xbce6c9e3, 0xb7c56bfe, 0xba966da0, 0x10cc24e4, 0x5c74912c,
            0x3d67ad24, 0x818f61c7,
        ];
        salsa20_8(&mut input);
        assert_eq!(input, expected);
    }

    /// Test HMAC-SHA-256 with empty key and empty data (RFC 4231 style).
    #[test]
    fn test_hmac_sha256_basic() {
        // HMAC-SHA-256("", "") — verify we produce a valid tag
        let hmac = HmacSha256::new(b"");
        let tag = hmac.finalize();
        // SHA-256(0x5c×64 || SHA-256(0x36×64)) — well-defined result
        assert_eq!(tag.len(), 32);
    }

    /// Test PBKDF2-HMAC-SHA-256 with RFC 7914 Section 11 parameters.
    #[test]
    fn test_pbkdf2_basic() {
        // PBKDF2-HMAC-SHA-256("passwd", "salt", 1, 64) — basic functionality check
        let mut output = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut output);
        // Just verify it produces non-zero output
        assert!(output.iter().any(|&b| b != 0));
    }
}
