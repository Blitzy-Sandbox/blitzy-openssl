//! # `BLAKE2b` and `BLAKE2s` Message Digest Provider Implementations
//!
//! `BLAKE2b` produces up to 64-byte digests with 128-byte blocks.
//! `BLAKE2s` produces up to 32-byte digests with 64-byte blocks.
//! Both support configurable output size via context parameters.
//!
//! ## Source Mapping
//!
//! | Rust item | C source |
//! |-----------|----------|
//! | [`Blake2bProvider`] | `blake2_prov.c` dispatch + `blake2b_prov.c` core |
//! | [`Blake2sProvider`] | `blake2_prov.c` dispatch + `blake2s_prov.c` core |
//! | `Blake2bContext` | `BLAKE2B_CTX` (compression, streaming, parameter block) |
//! | `Blake2sContext` | `BLAKE2S_CTX` (compression, streaming, parameter block) |
//! | Helper functions | `blake2_impl.h` (load/store/rotate → Rust native ops) |
//! | [`descriptors()`] | `defltprov.c` `OSSL_ALGORITHM` entries for BLAKE2 |
//!
//! ## Algorithm Properties
//!
//! | Variant | Block size | Default digest | Max digest | Word | Rounds |
//! |---------|-----------|----------------|------------|------|--------|
//! | `BLAKE2b` | 128 bytes | 64 bytes | 64 bytes | u64 | 12 |
//! | `BLAKE2s` | 64 bytes | 32 bytes | 32 bytes | u32 | 10 |
//!
//! ## Configurable Output Size
//!
//! Both variants support configurable digest output length via
//! `set_params()` with the `"size"` parameter key:
//!
//! - `BLAKE2b`: 1 ≤ size ≤ 64
//! - `BLAKE2s`: 1 ≤ size ≤ 32
//!
//! This replaces the C `blake2_set_ctx_params()` bounds checking from
//! `blake2_prov.c` which validated `size >= 1 && size <= max_outbytes`.
//!
//! ## Security
//!
//! All context types derive [`Zeroize`] and [`ZeroizeOnDrop`] to ensure
//! cryptographic state (chaining values, counters, key material, buffer)
//! is securely erased from memory on drop. This replaces C
//! `OPENSSL_cleanse()` calls from `blake2b_prov.c` and `blake2s_prov.c`.
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).
//! Endian handling uses `u32::from_le_bytes()` / `u64::from_le_bytes()`
//! instead of C conditional macros. Rotations use `u32::rotate_right()`
//! and `u64::rotate_right()` instead of C `rotr32` / `rotr64`.

use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::{CommonError, ProviderError, ProviderResult};
use openssl_common::param::ParamSet;
use super::common::{DigestFlags, default_get_params};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// BLAKE2b Constants
// =============================================================================

/// `BLAKE2b` block size in bytes (128).
const BLAKE2B_BLOCKBYTES: usize = 128;

/// `BLAKE2b` maximum (and default) output size in bytes (64).
const BLAKE2B_OUTBYTES: usize = 64;

/// `BLAKE2b` initialization vectors — the first 8 words of the fractional
/// parts of the square roots of the first 8 primes (same as SHA-512 IV).
///
/// Source: `blake2b_prov.c` `blake2b_IV[8]`.
const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// `BLAKE2b` sigma permutation table — 12 rounds × 16 entries.
///
/// The table defines the message word schedule for each round of the
/// compression function. Rounds 10 and 11 reuse rounds 0 and 1
/// respectively (`BLAKE2b` uses 12 rounds, while the sigma table has
/// only 10 unique permutations).
///
/// Source: `blake2b_prov.c` `blake2b_sigma[12][16]`.
const BLAKE2B_SIGMA: [[u8; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    // Rounds 10-11 reuse sigma[0] and sigma[1]
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// =============================================================================
// BLAKE2s Constants
// =============================================================================

/// `BLAKE2s` block size in bytes (64).
const BLAKE2S_BLOCKBYTES: usize = 64;

/// `BLAKE2s` maximum (and default) output size in bytes (32).
const BLAKE2S_OUTBYTES: usize = 32;

/// `BLAKE2s` initialization vectors — the first 8 words of the fractional
/// parts of the square roots of the first 8 primes (same as SHA-256 IV).
///
/// Stored as `u32` values matching the `BLAKE2s` word size.
///
/// Source: `blake2s_prov.c` `blake2s_IV[8]`.
const BLAKE2S_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// `BLAKE2s` sigma permutation table — 10 rounds × 16 entries.
///
/// Source: `blake2s_prov.c` `blake2s_sigma[10][16]`.
const BLAKE2S_SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// =============================================================================
// BLAKE2b Context
// =============================================================================

/// Internal `BLAKE2b` streaming hash context.
///
/// Maintains the full compression state for `BLAKE2b`:
/// - `h`: 8 × u64 chaining values (initialized from IV ⊕ parameter block)
/// - `t`: 2 × u64 byte counter (total bytes processed, low word first)
/// - `f`: 2 × u64 finalization flags (`f[0]` = last block flag)
/// - `buf`: 128-byte input buffer for incomplete blocks
/// - `buflen`: number of valid bytes currently in `buf`
/// - `outlen`: configured output digest length in bytes (1..=64)
///
/// All fields derive [`Zeroize`] and [`ZeroizeOnDrop`] to ensure
/// cryptographic state is securely erased on drop, replacing C
/// `OPENSSL_cleanse()` calls from `blake2b_prov.c`.
///
/// ## C Mapping
///
/// Replaces `BLAKE2B_CTX` from `blake2b_prov.c` which contained
/// `h[8]`, `t[2]`, `f[2]`, `buf[BLAKE2B_BLOCKBYTES]`, `buflen`,
/// and `outlen` fields plus `BLAKE2B_PARAM` initialization.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Blake2bContext {
    /// Chaining values (8 × u64). Initialized as IV ⊕ parameter block.
    h: [u64; 8],
    /// Byte counter. `t[0]` = low 64 bits, `t[1]` = high 64 bits.
    t: [u64; 2],
    /// Finalization flags. `f[0]` set to `u64::MAX` for last block.
    f: [u64; 2],
    /// Input buffer for incomplete blocks (128 bytes).
    buf: [u8; BLAKE2B_BLOCKBYTES],
    /// Number of valid bytes in `buf`.
    buflen: usize,
    /// Configured output digest length (1..=64 bytes).
    outlen: usize,
}

impl Blake2bContext {
    /// Creates a new `BLAKE2b` context with the specified output length.
    ///
    /// Initializes the chaining values from the `BLAKE2b` IV XOR-ed with
    /// a parameter block encoding `outlen`, `keylen=0`, `fanout=1`,
    /// `depth=1` (sequential mode, no keying).
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_init()` from `blake2b_prov.c` which constructs
    /// a `BLAKE2B_PARAM` struct with `digest_length`, `key_length=0`,
    /// `fanout=1`, `depth=1`, then XOR-s the 64-byte parameter block
    /// (loaded as 8 × `load64()`) against the IV.
    ///
    /// ## Parameters
    ///
    /// * `outlen` — Desired output digest length in bytes (1..=64).
    ///   Caller is responsible for bounds validation before construction.
    fn new(outlen: usize) -> Self {
        // Build the 64-byte parameter block:
        //   byte  0: digest_length (outlen)
        //   byte  1: key_length (0)
        //   byte  2: fanout (1 — sequential)
        //   byte  3: depth (1 — sequential)
        //   bytes 4..63: 0
        let mut param_block = [0u8; 64];
        // outlen is validated to 1..=64 before calling new(), fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        {
            param_block[0] = outlen as u8;
        }
        param_block[2] = 1; // fanout
        param_block[3] = 1; // depth

        // XOR parameter block (loaded as 8 × little-endian u64) against IV
        let mut h = BLAKE2B_IV;
        for (i, h_val) in h.iter_mut().enumerate() {
            let start = i * 8;
            let p = u64::from_le_bytes([
                param_block[start],
                param_block[start + 1],
                param_block[start + 2],
                param_block[start + 3],
                param_block[start + 4],
                param_block[start + 5],
                param_block[start + 6],
                param_block[start + 7],
            ]);
            *h_val ^= p;
        }

        Self {
            h,
            t: [0, 0],
            f: [0, 0],
            buf: [0u8; BLAKE2B_BLOCKBYTES],
            buflen: 0,
            outlen,
        }
    }

    /// Increments the byte counter `t` by `inc` bytes.
    ///
    /// Handles overflow from `t[0]` into `t[1]` for inputs exceeding
    /// 2^64 bytes. Uses wrapping arithmetic per the BLAKE2 specification.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_increment_counter()` from `blake2b_prov.c`.
    #[inline]
    fn increment_counter(&mut self, inc: u64) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    /// Sets the last-block flag, indicating the final compression.
    ///
    /// Sets `f[0]` to `u64::MAX` (all ones), which the compression function
    /// uses to invert `v[14]`.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_set_lastblock()` from `blake2b_prov.c`.
    #[inline]
    fn set_lastblock(&mut self) {
        self.f[0] = u64::MAX;
    }

    /// Performs the `BLAKE2b` compression function on a single 128-byte block.
    ///
    /// The compression function operates on 16 working variables (`v[0..15]`)
    /// initialized from the chaining values (`h`), IV, counter (`t`), and
    /// finalization flags (`f`). It applies 12 rounds of the G mixing
    /// function using the sigma permutation schedule.
    ///
    /// ## G Mixing Function
    ///
    /// Each round applies 8 calls to G (4 column + 4 diagonal) with
    /// rotation constants: 32, 24, 16, 63.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_compress()` from `blake2b_prov.c` which uses
    /// the `G(r,i,a,b,c,d)` macro over 12 rounds. The C version uses
    /// `load64()` from `blake2_impl.h` for message word loading; here
    /// we use `u64::from_le_bytes()`.
    fn compress(&mut self, block: &[u8; BLAKE2B_BLOCKBYTES]) {
        // Load 16 message words from block (little-endian)
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let start = i * 8;
            *word = u64::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
                block[start + 4],
                block[start + 5],
                block[start + 6],
                block[start + 7],
            ]);
        }

        // Initialize working variables
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8] = BLAKE2B_IV[0];
        v[9] = BLAKE2B_IV[1];
        v[10] = BLAKE2B_IV[2];
        v[11] = BLAKE2B_IV[3];
        v[12] = BLAKE2B_IV[4] ^ self.t[0];
        v[13] = BLAKE2B_IV[5] ^ self.t[1];
        v[14] = BLAKE2B_IV[6] ^ self.f[0];
        v[15] = BLAKE2B_IV[7] ^ self.f[1];

        // 12 rounds of compression
        for s in &BLAKE2B_SIGMA {
            // Column step
            blake2b_g(&mut v, 0, 4, 8, 12, m[s[0] as usize], m[s[1] as usize]);
            blake2b_g(&mut v, 1, 5, 9, 13, m[s[2] as usize], m[s[3] as usize]);
            blake2b_g(&mut v, 2, 6, 10, 14, m[s[4] as usize], m[s[5] as usize]);
            blake2b_g(&mut v, 3, 7, 11, 15, m[s[6] as usize], m[s[7] as usize]);

            // Diagonal step
            blake2b_g(&mut v, 0, 5, 10, 15, m[s[8] as usize], m[s[9] as usize]);
            blake2b_g(&mut v, 1, 6, 11, 12, m[s[10] as usize], m[s[11] as usize]);
            blake2b_g(&mut v, 2, 7, 8, 13, m[s[12] as usize], m[s[13] as usize]);
            blake2b_g(&mut v, 3, 4, 9, 14, m[s[14] as usize], m[s[15] as usize]);
        }

        // Finalize: XOR columns of v into chaining values
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// `BLAKE2b` G mixing function.
///
/// Operates on four working variables indexed by `a`, `b`, `c`, `d` in the
/// `v` array, mixing in two message words `x` and `y`. Uses wrapping
/// addition and right-rotation with `BLAKE2b` rotation constants:
/// 32, 24, 16, 63.
///
/// ## C Mapping
///
/// Replaces the `G(r,i,a,b,c,d)` macro from `blake2b_prov.c`.
/// Uses `u64::wrapping_add()` per Rule R6 (no bare `as` casts for
/// narrowing) and `u64::rotate_right()` instead of C `rotr64()`.
#[inline]
#[allow(clippy::many_single_char_names)] // Standard BLAKE2 spec parameter names (a,b,c,d,x,y)
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

// =============================================================================
// BLAKE2s Context
// =============================================================================

/// Internal `BLAKE2s` streaming hash context.
///
/// Maintains the full compression state for `BLAKE2s`:
/// - `h`: 8 × u32 chaining values (initialized from IV ⊕ parameter block)
/// - `t`: 2 × u32 byte counter (total bytes processed, low word first)
/// - `f`: 2 × u32 finalization flags (`f[0]` = last block flag)
/// - `buf`: 64-byte input buffer for incomplete blocks
/// - `buflen`: number of valid bytes currently in `buf`
/// - `outlen`: configured output digest length in bytes (1..=32)
///
/// All fields derive [`Zeroize`] and [`ZeroizeOnDrop`] to ensure
/// cryptographic state is securely erased on drop, replacing C
/// `OPENSSL_cleanse()` calls from `blake2s_prov.c`.
///
/// ## C Mapping
///
/// Replaces `BLAKE2S_CTX` from `blake2s_prov.c`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Blake2sContext {
    /// Chaining values (8 × u32). Initialized as IV ⊕ parameter block.
    h: [u32; 8],
    /// Byte counter. `t[0]` = low 32 bits, `t[1]` = high 32 bits.
    t: [u32; 2],
    /// Finalization flags. `f[0]` set to `u32::MAX` for last block.
    f: [u32; 2],
    /// Input buffer for incomplete blocks (64 bytes).
    buf: [u8; BLAKE2S_BLOCKBYTES],
    /// Number of valid bytes in `buf`.
    buflen: usize,
    /// Configured output digest length (1..=32 bytes).
    outlen: usize,
}

impl Blake2sContext {
    /// Creates a new `BLAKE2s` context with the specified output length.
    ///
    /// Initializes chaining values from the `BLAKE2s` IV XOR-ed with a
    /// 32-byte parameter block encoding `outlen`, `keylen=0`, `fanout=1`,
    /// `depth=1` (sequential mode, no keying).
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_init()` from `blake2s_prov.c`.
    fn new(outlen: usize) -> Self {
        // Build 32-byte parameter block:
        //   byte 0: digest_length (outlen)
        //   byte 1: key_length (0)
        //   byte 2: fanout (1)
        //   byte 3: depth (1)
        //   bytes 4..31: 0
        let mut param_block = [0u8; 32];
        // outlen is validated to 1..=32 before calling new(), fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        {
            param_block[0] = outlen as u8;
        }
        param_block[2] = 1; // fanout
        param_block[3] = 1; // depth

        // XOR parameter block (loaded as 8 × little-endian u32) against IV
        let mut h = [0u32; 8];
        for i in 0..8 {
            let start = i * 4;
            let p = u32::from_le_bytes([
                param_block[start],
                param_block[start + 1],
                param_block[start + 2],
                param_block[start + 3],
            ]);
            h[i] = BLAKE2S_IV[i] ^ p;
        }

        Self {
            h,
            t: [0, 0],
            f: [0, 0],
            buf: [0u8; BLAKE2S_BLOCKBYTES],
            buflen: 0,
            outlen,
        }
    }

    /// Increments the byte counter `t` by `inc` bytes.
    ///
    /// Handles overflow from `t[0]` into `t[1]`. Uses wrapping arithmetic
    /// per the BLAKE2 specification.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_increment_counter()` from `blake2s_prov.c`.
    #[inline]
    fn increment_counter(&mut self, inc: u32) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    /// Sets the last-block flag for the final compression.
    ///
    /// Sets `f[0]` to `u32::MAX` (all ones).
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_set_lastblock()` from `blake2s_prov.c`.
    #[inline]
    fn set_lastblock(&mut self) {
        self.f[0] = u32::MAX;
    }

    /// Performs the `BLAKE2s` compression function on a single 64-byte block.
    ///
    /// Operates on 16 working variables (`v[0..15]`) with 10 rounds of
    /// the G mixing function using rotation constants: 16, 12, 8, 7.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_compress()` from `blake2s_prov.c`. Message word
    /// loading uses `u32::from_le_bytes()` instead of C `load32()`.
    fn compress(&mut self, block: &[u8; BLAKE2S_BLOCKBYTES]) {
        // Load 16 message words from block (little-endian)
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let start = i * 4;
            *word = u32::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }

        // Initialize working variables
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8] = BLAKE2S_IV[0];
        v[9] = BLAKE2S_IV[1];
        v[10] = BLAKE2S_IV[2];
        v[11] = BLAKE2S_IV[3];
        v[12] = BLAKE2S_IV[4] ^ self.t[0];
        v[13] = BLAKE2S_IV[5] ^ self.t[1];
        v[14] = BLAKE2S_IV[6] ^ self.f[0];
        v[15] = BLAKE2S_IV[7] ^ self.f[1];

        // 10 rounds of compression
        for s in &BLAKE2S_SIGMA {
            // Column step
            blake2s_g(&mut v, 0, 4, 8, 12, m[s[0] as usize], m[s[1] as usize]);
            blake2s_g(&mut v, 1, 5, 9, 13, m[s[2] as usize], m[s[3] as usize]);
            blake2s_g(&mut v, 2, 6, 10, 14, m[s[4] as usize], m[s[5] as usize]);
            blake2s_g(&mut v, 3, 7, 11, 15, m[s[6] as usize], m[s[7] as usize]);

            // Diagonal step
            blake2s_g(&mut v, 0, 5, 10, 15, m[s[8] as usize], m[s[9] as usize]);
            blake2s_g(&mut v, 1, 6, 11, 12, m[s[10] as usize], m[s[11] as usize]);
            blake2s_g(&mut v, 2, 7, 8, 13, m[s[12] as usize], m[s[13] as usize]);
            blake2s_g(&mut v, 3, 4, 9, 14, m[s[14] as usize], m[s[15] as usize]);
        }

        // Finalize: XOR columns of v into chaining values
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// `BLAKE2s` G mixing function.
///
/// Operates on four working variables indexed by `a`, `b`, `c`, `d` in the
/// `v` array, mixing in two message words `x` and `y`. Uses wrapping
/// addition and right-rotation with `BLAKE2s` rotation constants:
/// 16, 12, 8, 7.
///
/// ## C Mapping
///
/// Replaces the `G(r,i,a,b,c,d)` macro from `blake2s_prov.c`.
/// Uses `u32::wrapping_add()` per Rule R6 and `u32::rotate_right()`
/// instead of C `rotr32()`.
#[inline]
#[allow(clippy::many_single_char_names)] // Standard BLAKE2 spec parameter names (a,b,c,d,x,y)
fn blake2s_g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

// =============================================================================
// Helper: bounds-checked size extraction from ParamSet
// =============================================================================

/// Extracts and validates the `"size"` parameter for digest output length.
///
/// Returns the validated size as `usize`, or an appropriate error if the
/// parameter is not a valid `u32` or is outside the range `1..=max_outbytes`.
///
/// ## Parameters
///
/// * `params` — Parameter set to extract `"size"` from
/// * `variant` — Algorithm name for error messages (e.g., `"BLAKE2b"`)
/// * `max_outbytes` — Maximum allowed output size
///
/// ## Returns
///
/// `Some(Ok(size))` if `"size"` is present and valid,
/// `Some(Err(_))` if present but invalid,
/// `None` if `"size"` is not present.
fn extract_size_param(
    params: &ParamSet,
    variant: &str,
    max_outbytes: usize,
) -> Option<ProviderResult<usize>> {
    params.get("size").map(|val| {
        let size = val.as_u32().ok_or_else(|| {
            ProviderError::Common(CommonError::InvalidArgument(
                format!("{variant} 'size' parameter must be a u32"),
            ))
        })?;
        let size_usize = size as usize;
        if !(1..=max_outbytes).contains(&size_usize) {
            return Err(ProviderError::Common(CommonError::InvalidArgument(
                format!("{variant} digest size must be 1..={max_outbytes}, got {size}"),
            )));
        }
        Ok(size_usize)
    })
}

// =============================================================================
// DigestContext Implementation — BLAKE2b
// =============================================================================

impl DigestContext for Blake2bContext {
    /// Initializes (or re-initializes) the `BLAKE2b` context.
    ///
    /// If `params` contains a `"size"` key, the output length is
    /// reconfigured (must be 1..=64). Otherwise the existing `outlen`
    /// is preserved.
    ///
    /// Re-initialization resets the entire state to the fresh IV ⊕ param
    /// block, discarding any buffered or compressed data.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_internal_init()` from `blake2b_prov.c`.
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()> {
        let outlen = if let Some(ps) = params {
            match extract_size_param(ps, "BLAKE2b", BLAKE2B_OUTBYTES) {
                Some(result) => result?,
                None => self.outlen,
            }
        } else {
            self.outlen
        };

        // Re-initialize from scratch with the (possibly updated) outlen
        let fresh = Blake2bContext::new(outlen);
        self.h = fresh.h;
        self.t = fresh.t;
        self.f = fresh.f;
        self.buf = fresh.buf;
        self.buflen = fresh.buflen;
        self.outlen = fresh.outlen;
        Ok(())
    }

    /// Absorbs input data into the `BLAKE2b` hash.
    ///
    /// Data is buffered internally. When the buffer is full (128 bytes),
    /// the compression function is called. The last incomplete block is
    /// always stashed in the buffer for finalization.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_update()` from `blake2b_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0usize;
        let datalen = data.len();

        // If we have buffered data, try to fill the buffer first
        if self.buflen > 0 {
            let fill = BLAKE2B_BLOCKBYTES - self.buflen;
            if datalen > fill {
                // Fill buffer and compress
                self.buf[self.buflen..BLAKE2B_BLOCKBYTES].copy_from_slice(&data[..fill]);
                self.buflen = BLAKE2B_BLOCKBYTES;
                self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
                let block: [u8; BLAKE2B_BLOCKBYTES] = self.buf;
                self.compress(&block);
                self.buflen = 0;
                offset = fill;
            } else {
                // Not enough to fill the buffer
                self.buf[self.buflen..self.buflen + datalen].copy_from_slice(data);
                self.buflen += datalen;
                return Ok(());
            }
        }

        // Process full blocks from the remaining input.
        // Always keep at least one block in the buffer for finalization.
        while datalen - offset > BLAKE2B_BLOCKBYTES {
            self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
            let mut block = [0u8; BLAKE2B_BLOCKBYTES];
            block.copy_from_slice(&data[offset..offset + BLAKE2B_BLOCKBYTES]);
            self.compress(&block);
            offset += BLAKE2B_BLOCKBYTES;
        }

        // Buffer remaining bytes
        let remaining = datalen - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buflen = remaining;
        }

        Ok(())
    }

    /// Finalizes the `BLAKE2b` digest, producing the output hash.
    ///
    /// Pads the last block with zeros, sets the last-block flag,
    /// performs the final compression, then extracts `outlen` bytes
    /// from the chaining values in little-endian order.
    ///
    /// After finalization the context state is left in an undefined
    /// state (it should be re-initialized via `init()` before reuse).
    /// The `ZeroizeOnDrop` derive ensures secure cleanup when the
    /// context is dropped.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_final()` from `blake2b_prov.c` which sets
    /// the lastblock flag, pads with zeros, compresses, then stores
    /// `outlen` bytes via `store64()`. The C version also calls
    /// `OPENSSL_cleanse()` on the context; here we rely on `ZeroizeOnDrop`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        // Increment counter by buffered bytes (the last block)
        self.increment_counter(self.buflen as u64);
        self.set_lastblock();

        // Zero-pad the buffer beyond the valid bytes
        for byte in &mut self.buf[self.buflen..] {
            *byte = 0;
        }

        // Compress the final (padded) block
        let block: [u8; BLAKE2B_BLOCKBYTES] = self.buf;
        self.compress(&block);

        // Extract output bytes from chaining values (little-endian)
        let mut out = vec![0u8; self.outlen];
        let full_bytes = self.h.iter().flat_map(|w| w.to_le_bytes());
        for (dst, src) in out.iter_mut().zip(full_bytes) {
            *dst = src;
        }

        Ok(out)
    }

    /// Creates a deep copy of this `BLAKE2b` context.
    ///
    /// All state (chaining values, counters, buffer contents, output length)
    /// is duplicated, allowing independent continuation of hashing from
    /// the same intermediate state.
    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    /// Returns the current digest parameters as a [`ParamSet`].
    ///
    /// Reports block size (128), current digest size (`outlen`), and
    /// flags (empty — BLAKE2 has no XOF, no `ALGID_ABSENT`, no CUSTOM).
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2b_get_ctx_params()` from `blake2_prov.c` which
    /// calls `ossl_digest_default_get_params(BLAKE2B_BLOCKBYTES, outlen, 0)`
    /// and then overrides the `"size"` param with the context's current
    /// `outlen`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        default_get_params(BLAKE2B_BLOCKBYTES, self.outlen, DigestFlags::empty())
    }

    /// Sets context parameters, supporting configurable digest output size.
    ///
    /// Recognizes the `"size"` key to change the output digest length.
    /// The new size must satisfy 1 ≤ size ≤ 64 (`BLAKE2b` maximum).
    /// Returns an error if the size is out of bounds.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2_set_ctx_params()` from `blake2_prov.c` which
    /// extracts `OSSL_DIGEST_PARAM_SIZE` via `OSSL_PARAM_get_uint()` and
    /// validates `size >= 1 && size <= max_outbytes`.
    ///
    /// ## Rule R5
    ///
    /// Returns `ProviderResult<()>` with a descriptive error on bounds
    /// violation instead of using sentinel return values.
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(result) = extract_size_param(params, "BLAKE2b", BLAKE2B_OUTBYTES) {
            self.outlen = result?;
        }
        Ok(())
    }
}

// =============================================================================
// DigestContext Implementation — BLAKE2s
// =============================================================================

impl DigestContext for Blake2sContext {
    /// Initializes (or re-initializes) the `BLAKE2s` context.
    ///
    /// If `params` contains a `"size"` key, the output length is
    /// reconfigured (must be 1..=32). Otherwise the existing `outlen`
    /// is preserved.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_internal_init()` from `blake2s_prov.c`.
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()> {
        let outlen = if let Some(ps) = params {
            match extract_size_param(ps, "BLAKE2s", BLAKE2S_OUTBYTES) {
                Some(result) => result?,
                None => self.outlen,
            }
        } else {
            self.outlen
        };

        let fresh = Blake2sContext::new(outlen);
        self.h = fresh.h;
        self.t = fresh.t;
        self.f = fresh.f;
        self.buf = fresh.buf;
        self.buflen = fresh.buflen;
        self.outlen = fresh.outlen;
        Ok(())
    }

    /// Absorbs input data into the `BLAKE2s` hash.
    ///
    /// Data is buffered internally. When the buffer is full (64 bytes),
    /// the compression function is called. The last incomplete block is
    /// always stashed in the buffer for finalization.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_update()` from `blake2s_prov.c`.
    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0usize;
        let datalen = data.len();

        // Fill buffer from incoming data
        if self.buflen > 0 {
            let fill = BLAKE2S_BLOCKBYTES - self.buflen;
            if datalen > fill {
                self.buf[self.buflen..BLAKE2S_BLOCKBYTES].copy_from_slice(&data[..fill]);
                self.buflen = BLAKE2S_BLOCKBYTES;
                // BLAKE2S_BLOCKBYTES = 64 which fits in u32; truncation is safe.
                #[allow(clippy::cast_possible_truncation)]
                self.increment_counter(BLAKE2S_BLOCKBYTES as u32);
                let block: [u8; BLAKE2S_BLOCKBYTES] = self.buf;
                self.compress(&block);
                self.buflen = 0;
                offset = fill;
            } else {
                self.buf[self.buflen..self.buflen + datalen].copy_from_slice(data);
                self.buflen += datalen;
                return Ok(());
            }
        }

        // Process full blocks, keeping the last one for finalization
        while datalen - offset > BLAKE2S_BLOCKBYTES {
            #[allow(clippy::cast_possible_truncation)]
            self.increment_counter(BLAKE2S_BLOCKBYTES as u32);
            let mut block = [0u8; BLAKE2S_BLOCKBYTES];
            block.copy_from_slice(&data[offset..offset + BLAKE2S_BLOCKBYTES]);
            self.compress(&block);
            offset += BLAKE2S_BLOCKBYTES;
        }

        // Buffer remaining bytes
        let remaining = datalen - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buflen = remaining;
        }

        Ok(())
    }

    /// Finalizes the `BLAKE2s` digest, producing the output hash.
    ///
    /// ## C Mapping
    ///
    /// Replaces `blake2s_final()` from `blake2s_prov.c`.
    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        // buflen is at most BLAKE2S_BLOCKBYTES = 64, fits in u32
        #[allow(clippy::cast_possible_truncation)]
        self.increment_counter(self.buflen as u32);
        self.set_lastblock();

        // Zero-pad the buffer
        for byte in &mut self.buf[self.buflen..] {
            *byte = 0;
        }

        let block: [u8; BLAKE2S_BLOCKBYTES] = self.buf;
        self.compress(&block);

        // Extract output bytes from chaining values (little-endian)
        let mut out = vec![0u8; self.outlen];
        let full_bytes = self.h.iter().flat_map(|w| w.to_le_bytes());
        for (dst, src) in out.iter_mut().zip(full_bytes) {
            *dst = src;
        }

        Ok(out)
    }

    /// Creates a deep copy of this `BLAKE2s` context.
    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    /// Returns current digest parameters.
    ///
    /// Reports block size (64), current digest size (`outlen`), and
    /// empty flags.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        default_get_params(BLAKE2S_BLOCKBYTES, self.outlen, DigestFlags::empty())
    }

    /// Sets context parameters. Supports `"size"` key for configurable
    /// output (1..=32 bytes).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(result) = extract_size_param(params, "BLAKE2s", BLAKE2S_OUTBYTES) {
            self.outlen = result?;
        }
        Ok(())
    }
}

// =============================================================================
// Blake2bProvider — Public Provider Struct
// =============================================================================

/// `BLAKE2b`-512 message digest provider.
///
/// Default digest size: 64 bytes, configurable 1–64 bytes via context
/// parameters. Block size: 128 bytes.
///
/// ## Algorithm Names
///
/// Registered under: `["BLAKE2B-512", "BLAKE2b512"]` with property
/// `"provider=default"`.
///
/// ## C Mapping
///
/// Replaces the `ossl_blake2b512_functions` dispatch table from
/// `blake2_prov.c` (generated by `IMPLEMENT_BLAKE_functions(2b, 2B, 2b512)`).
///
/// ## Wiring Path (Rule R10)
///
/// ```text
/// openssl_cli::main()
///   → provider loading
///     → DefaultProvider::query_operation(OperationType::Digest)
///       → digests::descriptors()
///         → blake2::descriptors()
///           → AlgorithmDescriptor { names: ["BLAKE2B-512", "BLAKE2b512"], .. }
/// ```
#[derive(Debug, Clone)]
pub struct Blake2bProvider;

impl DigestProvider for Blake2bProvider {
    /// Returns the canonical algorithm name `"BLAKE2B-512"`.
    fn name(&self) -> &'static str {
        "BLAKE2B-512"
    }

    /// Returns `128` — the `BLAKE2b` internal block size in bytes.
    fn block_size(&self) -> usize {
        BLAKE2B_BLOCKBYTES
    }

    /// Returns `64` — the default `BLAKE2b` output digest size in bytes.
    ///
    /// The actual output size is configurable via `set_params("size", n)`
    /// on the created context (1..=64 bytes).
    fn digest_size(&self) -> usize {
        BLAKE2B_OUTBYTES
    }

    /// Creates a new `Blake2bContext` with the default 64-byte output.
    ///
    /// The returned context is ready for `init()` → `update()` → `finalize()`
    /// lifecycle. Output size can be reconfigured via `set_params()` or
    /// by passing a `"size"` parameter to `init()`.
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Blake2bContext::new(BLAKE2B_OUTBYTES)))
    }
}

// =============================================================================
// Blake2sProvider — Public Provider Struct
// =============================================================================

/// `BLAKE2s`-256 message digest provider.
///
/// Default digest size: 32 bytes, configurable 1–32 bytes via context
/// parameters. Block size: 64 bytes.
///
/// ## Algorithm Names
///
/// Registered under: `["BLAKE2S-256", "BLAKE2s256"]` with property
/// `"provider=default"`.
///
/// ## C Mapping
///
/// Replaces the `ossl_blake2s256_functions` dispatch table from
/// `blake2_prov.c` (generated by `IMPLEMENT_BLAKE_functions(2s, 2S, 2s256)`).
///
/// ## Wiring Path (Rule R10)
///
/// ```text
/// openssl_cli::main()
///   → provider loading
///     → DefaultProvider::query_operation(OperationType::Digest)
///       → digests::descriptors()
///         → blake2::descriptors()
///           → AlgorithmDescriptor { names: ["BLAKE2S-256", "BLAKE2s256"], .. }
/// ```
#[derive(Debug, Clone)]
pub struct Blake2sProvider;

impl DigestProvider for Blake2sProvider {
    /// Returns the canonical algorithm name `"BLAKE2S-256"`.
    fn name(&self) -> &'static str {
        "BLAKE2S-256"
    }

    /// Returns `64` — the `BLAKE2s` internal block size in bytes.
    fn block_size(&self) -> usize {
        BLAKE2S_BLOCKBYTES
    }

    /// Returns `32` — the default `BLAKE2s` output digest size in bytes.
    ///
    /// The actual output size is configurable via `set_params("size", n)`
    /// on the created context (1..=32 bytes).
    fn digest_size(&self) -> usize {
        BLAKE2S_OUTBYTES
    }

    /// Creates a new `Blake2sContext` with the default 32-byte output.
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Blake2sContext::new(BLAKE2S_OUTBYTES)))
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for `BLAKE2b`-512 and `BLAKE2s`-256.
///
/// Registers both BLAKE2 variants under the `"provider=default"` property
/// with their canonical and alias names. Called by
/// `digests::mod::descriptors()` during provider initialization.
///
/// ## Descriptor Details
///
/// | Algorithm | Names | Property |
/// |-----------|-------|----------|
/// | `BLAKE2b`-512 | `["BLAKE2B-512", "BLAKE2b512"]` | `"provider=default"` |
/// | `BLAKE2s`-256 | `["BLAKE2S-256", "BLAKE2s256"]` | `"provider=default"` |
///
/// ## C Mapping
///
/// Replaces the static dispatch table entries from `defltprov.c`:
/// ```c
/// { "BLAKE2B-512:BLAKE2b512", "provider=default", ossl_blake2b512_functions }
/// { "BLAKE2S-256:BLAKE2s256", "provider=default", ossl_blake2s256_functions }
/// ```
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["BLAKE2B-512", "BLAKE2b512"],
            property: "provider=default",
            description: "BLAKE2b-512 message digest (64-byte output, 128-byte block)",
        },
        AlgorithmDescriptor {
            names: vec!["BLAKE2S-256", "BLAKE2s256"],
            property: "provider=default",
            description: "BLAKE2s-256 message digest (32-byte output, 64-byte block)",
        },
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamBuilder;

    // =========================================================================
    // Provider Property Tests
    // =========================================================================

    /// Verify `BLAKE2b` provider metadata matches specification.
    #[test]
    fn test_blake2b_provider_properties() {
        let provider = Blake2bProvider;
        assert_eq!(provider.name(), "BLAKE2B-512");
        assert_eq!(provider.block_size(), 128);
        assert_eq!(provider.digest_size(), 64);
    }

    /// Verify `BLAKE2s` provider metadata matches specification.
    #[test]
    fn test_blake2s_provider_properties() {
        let provider = Blake2sProvider;
        assert_eq!(provider.name(), "BLAKE2S-256");
        assert_eq!(provider.block_size(), 64);
        assert_eq!(provider.digest_size(), 32);
    }

    // =========================================================================
    // BLAKE2b Digest Tests — RFC 7693 Test Vectors
    // =========================================================================

    /// `BLAKE2b`-512 empty input test vector.
    #[test]
    fn test_blake2b_empty_input() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        let digest = ctx.finalize().expect("finalize");

        assert_eq!(digest.len(), 64);
        let expected = [
            0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
            0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
            0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
            0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
            0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
            0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
            0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
            0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
        ];
        assert_eq!(digest, expected);
    }

    /// `BLAKE2b`-512 "abc" test vector (verified against Python `hashlib.blake2b`).
    #[test]
    fn test_blake2b_abc() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        ctx.update(b"abc").expect("update");
        let digest = ctx.finalize().expect("finalize");

        assert_eq!(digest.len(), 64);
        // BLAKE2b-512("abc") = ba80a53f981c4d0d...d4009923
        let expected = [
            0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
            0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
            0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
            0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
            0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
            0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
            0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
            0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
        ];
        assert_eq!(digest, expected);
    }

    // =========================================================================
    // BLAKE2s Digest Tests — RFC 7693 Test Vectors
    // =========================================================================

    /// `BLAKE2s`-256 empty input test vector.
    #[test]
    fn test_blake2s_empty_input() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        let digest = ctx.finalize().expect("finalize");

        assert_eq!(digest.len(), 32);
        let expected = [
            0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
            0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
            0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
            0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
        ];
        assert_eq!(digest, expected);
    }

    /// `BLAKE2s`-256 "abc" test vector.
    #[test]
    fn test_blake2s_abc() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        ctx.update(b"abc").expect("update");
        let digest = ctx.finalize().expect("finalize");

        assert_eq!(digest.len(), 32);
        let expected = [
            0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
            0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
            0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
            0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
        ];
        assert_eq!(digest, expected);
    }

    // =========================================================================
    // Context Lifecycle Tests
    // =========================================================================

    /// Test incremental update produces same result as single update.
    #[test]
    fn test_blake2b_incremental_update() {
        let provider = Blake2bProvider;

        // Single update
        let mut ctx1 = provider.new_ctx().expect("new_ctx");
        ctx1.init(None).expect("init");
        ctx1.update(b"abcdef").expect("update");
        let digest1 = ctx1.finalize().expect("finalize");

        // Incremental updates
        let mut ctx2 = provider.new_ctx().expect("new_ctx");
        ctx2.init(None).expect("init");
        ctx2.update(b"ab").expect("update 1");
        ctx2.update(b"cd").expect("update 2");
        ctx2.update(b"ef").expect("update 3");
        let digest2 = ctx2.finalize().expect("finalize");

        assert_eq!(digest1, digest2);
    }

    /// Test incremental update for `BLAKE2s`.
    #[test]
    fn test_blake2s_incremental_update() {
        let provider = Blake2sProvider;

        let mut ctx1 = provider.new_ctx().expect("new_ctx");
        ctx1.init(None).expect("init");
        ctx1.update(b"abcdef").expect("update");
        let digest1 = ctx1.finalize().expect("finalize");

        let mut ctx2 = provider.new_ctx().expect("new_ctx");
        ctx2.init(None).expect("init");
        ctx2.update(b"ab").expect("update 1");
        ctx2.update(b"cd").expect("update 2");
        ctx2.update(b"ef").expect("update 3");
        let digest2 = ctx2.finalize().expect("finalize");

        assert_eq!(digest1, digest2);
    }

    /// Test context duplication produces identical output.
    #[test]
    fn test_blake2b_duplicate() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        ctx.update(b"some data").expect("update");

        let mut dup = ctx.duplicate().expect("duplicate");

        let digest1 = ctx.finalize().expect("finalize original");
        let digest2 = dup.finalize().expect("finalize duplicate");
        assert_eq!(digest1, digest2);
    }

    /// Test context duplication for `BLAKE2s`.
    #[test]
    fn test_blake2s_duplicate() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");
        ctx.update(b"some data").expect("update");

        let mut dup = ctx.duplicate().expect("duplicate");

        let digest1 = ctx.finalize().expect("finalize original");
        let digest2 = dup.finalize().expect("finalize duplicate");
        assert_eq!(digest1, digest2);
    }

    // =========================================================================
    // Configurable Digest Size Tests
    // =========================================================================

    /// Test `BLAKE2b` with reduced output size (32 bytes).
    #[test]
    fn test_blake2b_configurable_size() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");

        let params = ParamBuilder::new().push_u32("size", 32).build();
        ctx.init(Some(&params)).expect("init with size=32");
        ctx.update(b"test").expect("update");
        let digest = ctx.finalize().expect("finalize");
        assert_eq!(digest.len(), 32);
    }

    /// Test `BLAKE2s` with reduced output size (16 bytes).
    #[test]
    fn test_blake2s_configurable_size() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");

        let params = ParamBuilder::new().push_u32("size", 16).build();
        ctx.init(Some(&params)).expect("init with size=16");
        ctx.update(b"test").expect("update");
        let digest = ctx.finalize().expect("finalize");
        assert_eq!(digest.len(), 16);
    }

    /// Test `BLAKE2b` `set_params` for size change.
    #[test]
    fn test_blake2b_set_params_size() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        let params = ParamBuilder::new().push_u32("size", 48).build();
        ctx.set_params(&params).expect("set_params size=48");

        // Verify `get_params` reflects the change
        let got = ctx.get_params().expect("get_params");
        let size_val = got.get("size").expect("size key exists");
        assert_eq!(size_val.as_u64(), Some(48));
    }

    /// Test `BLAKE2b` bounds checking — size too large.
    #[test]
    fn test_blake2b_set_params_size_too_large() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        let params = ParamBuilder::new().push_u32("size", 65).build();
        let result = ctx.set_params(&params);
        assert!(result.is_err(), "size=65 should fail for BLAKE2b");
    }

    /// Test `BLAKE2b` bounds checking — size zero.
    #[test]
    fn test_blake2b_set_params_size_zero() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        let params = ParamBuilder::new().push_u32("size", 0).build();
        let result = ctx.set_params(&params);
        assert!(result.is_err(), "size=0 should fail for BLAKE2b");
    }

    /// Test `BLAKE2s` bounds checking — size too large.
    #[test]
    fn test_blake2s_set_params_size_too_large() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        let params = ParamBuilder::new().push_u32("size", 33).build();
        let result = ctx.set_params(&params);
        assert!(result.is_err(), "size=33 should fail for BLAKE2s");
    }

    /// Test `BLAKE2s` bounds checking — size zero.
    #[test]
    fn test_blake2s_set_params_size_zero() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        let params = ParamBuilder::new().push_u32("size", 0).build();
        let result = ctx.set_params(&params);
        assert!(result.is_err(), "size=0 should fail for BLAKE2s");
    }

    // =========================================================================
    // get_params Tests
    // =========================================================================

    /// Test `BLAKE2b` `get_params` returns correct defaults.
    #[test]
    fn test_blake2b_get_params() {
        let provider = Blake2bProvider;
        let ctx = provider.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");

        let blocksize = params.get("blocksize").expect("blocksize key");
        assert_eq!(blocksize.as_u64(), Some(128));

        let size = params.get("size").expect("size key");
        assert_eq!(size.as_u64(), Some(64));
    }

    /// Test `BLAKE2s` `get_params` returns correct defaults.
    #[test]
    fn test_blake2s_get_params() {
        let provider = Blake2sProvider;
        let ctx = provider.new_ctx().expect("new_ctx");
        let params = ctx.get_params().expect("get_params");

        let blocksize = params.get("blocksize").expect("blocksize key");
        assert_eq!(blocksize.as_u64(), Some(64));

        let size = params.get("size").expect("size key");
        assert_eq!(size.as_u64(), Some(32));
    }

    // =========================================================================
    // Descriptor Tests
    // =========================================================================

    /// Verify descriptor registration produces two entries with correct names.
    #[test]
    fn test_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 2);

        // BLAKE2b descriptor
        assert_eq!(descs[0].names, vec!["BLAKE2B-512", "BLAKE2b512"]);
        assert_eq!(descs[0].property, "provider=default");

        // BLAKE2s descriptor
        assert_eq!(descs[1].names, vec!["BLAKE2S-256", "BLAKE2s256"]);
        assert_eq!(descs[1].property, "provider=default");
    }

    // =========================================================================
    // Large Input Tests
    // =========================================================================

    /// Test `BLAKE2b` with input larger than one block (128 bytes).
    #[test]
    fn test_blake2b_multi_block() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        // Feed 256 bytes — two full blocks
        let data = [0x61u8; 256];
        ctx.update(&data).expect("update");
        let digest = ctx.finalize().expect("finalize");
        assert_eq!(digest.len(), 64);
        assert_ne!(digest, vec![0u8; 64]);
    }

    /// Test `BLAKE2s` with input larger than one block (64 bytes).
    #[test]
    fn test_blake2s_multi_block() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init");

        // Feed 128 bytes — two full blocks
        let data = [0x61u8; 128];
        ctx.update(&data).expect("update");
        let digest = ctx.finalize().expect("finalize");
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, vec![0u8; 32]);
    }

    /// Test `BLAKE2b` with empty update calls interspersed.
    #[test]
    fn test_blake2b_empty_update() {
        let provider = Blake2bProvider;

        let mut ctx1 = provider.new_ctx().expect("new_ctx");
        ctx1.init(None).expect("init");
        ctx1.update(b"data").expect("update");
        let digest1 = ctx1.finalize().expect("finalize");

        let mut ctx2 = provider.new_ctx().expect("new_ctx");
        ctx2.init(None).expect("init");
        ctx2.update(b"").expect("empty update 1");
        ctx2.update(b"data").expect("update");
        ctx2.update(b"").expect("empty update 2");
        let digest2 = ctx2.finalize().expect("finalize");

        assert_eq!(digest1, digest2);
    }

    /// Test that re-initialization produces the same result as fresh context.
    #[test]
    fn test_blake2b_reinit() {
        let provider = Blake2bProvider;

        // Hash once
        let mut ctx = provider.new_ctx().expect("new_ctx");
        ctx.init(None).expect("init 1");
        ctx.update(b"first message").expect("update 1");
        let _digest1 = ctx.finalize().expect("finalize 1");

        // Re-init and hash "abc"
        ctx.init(None).expect("re-init");
        ctx.update(b"abc").expect("update 2");
        let digest2 = ctx.finalize().expect("finalize 2");

        // Fresh context with "abc"
        let mut fresh = provider.new_ctx().expect("new_ctx");
        fresh.init(None).expect("init");
        fresh.update(b"abc").expect("update");
        let digest_fresh = fresh.finalize().expect("finalize");

        assert_eq!(digest2, digest_fresh);
    }

    /// Minimum configurable size: 1-byte output.
    #[test]
    fn test_blake2b_min_output_size() {
        let provider = Blake2bProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let params = ParamBuilder::new().push_u32("size", 1).build();
        ctx.init(Some(&params)).expect("init");
        ctx.update(b"test").expect("update");
        let digest = ctx.finalize().expect("finalize");
        assert_eq!(digest.len(), 1);
    }

    /// Minimum configurable size: 1-byte output for `BLAKE2s`.
    #[test]
    fn test_blake2s_min_output_size() {
        let provider = Blake2sProvider;
        let mut ctx = provider.new_ctx().expect("new_ctx");
        let params = ParamBuilder::new().push_u32("size", 1).build();
        ctx.init(Some(&params)).expect("init");
        ctx.update(b"test").expect("update");
        let digest = ctx.finalize().expect("finalize");
        assert_eq!(digest.len(), 1);
    }
}
