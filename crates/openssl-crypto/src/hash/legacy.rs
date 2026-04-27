//! Legacy cryptographic hash algorithms.
//!
//! This module implements six historically important hash algorithms retained
//! for backwards-compatibility with legacy protocols, file formats, and test
//! vectors:
//!
//! | Algorithm    | Digest | Block | Source module              | Status             |
//! |--------------|--------|-------|----------------------------|--------------------|
//! | MD2          |  16 B  |  16 B | `crypto/md2/md2_dgst.c`    | **BROKEN**         |
//! | MD4          |  16 B  |  64 B | `crypto/md4/md4_dgst.c`    | **BROKEN**         |
//! | MDC2         |  16 B  |   8 B | `crypto/mdc2/mdc2dgst.c`   | DES-based, legacy  |
//! | RIPEMD-160   |  20 B  |  64 B | `crypto/ripemd/rmd_dgst.c` | Limited security   |
//! | SM3          |  32 B  |  64 B | `crypto/sm3/sm3.c`         | Chinese national std |
//! | Whirlpool    |  64 B  |  64 B | `crypto/whrlpool/wp_*.c`   | NESSIE/ISO 10118-3 |
//!
//! # Security Warning
//!
//! Every algorithm in this module is either cryptographically broken (MD2/MD4)
//! or provides substantially less security margin than modern alternatives.
//! Use SHA-256, SHA-384, SHA-512, or SHA-3 (from [`super::sha`]) for any new
//! code.
//!
//! # C Source Mapping (AAP §0.5.1)
//!
//! This file consolidates the Rust translation of the following upstream C
//! files, preserving their algorithm semantics byte-for-byte:
//!
//! * `crypto/md2/{md2_dgst.c, md2_local.h}`
//! * `crypto/md4/{md4_dgst.c, md4_local.h}`
//! * `crypto/mdc2/{mdc2dgst.c, mdc2.h}` (with DES via `DesKeySchedule`,
//!   gated by the `"des"` feature)
//! * `crypto/ripemd/{rmd_dgst.c, rmd_local.h, rmdconst.h}`
//! * `crypto/sm3/{sm3.c, sm3_local.h}`
//! * `crypto/whrlpool/{wp_block.c, wp_dgst.c, wp_local.h}`
//!
//! BLAKE2 variants are delegated to the `openssl-provider` crate (module
//! `implementations::digests::blake2`, feature-gated by `"blake2"`) and are
//! deliberately not enumerated in [`LegacyAlgorithm`].
//!
//! # Rule Compliance
//!
//! * **R5** — `Option<T>` is used throughout; no sentinel returns.
//! * **R6** — Narrowing numeric conversions use [`u64::try_from`] / [`u32::try_from`]
//!   or fixed lookup tables. No bare `as` truncating casts.
//! * **R8** — Zero `unsafe` blocks in this file. Verified by `#![forbid]`
//!   via workspace-level `unsafe_code` lint.
//! * **R9** — All public items are documented and compile warning-free.

#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]

use super::sha::Digest;
#[cfg(feature = "des")]
use crate::symmetric::des::DesKeySchedule;
use openssl_common::{CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Shared constants and helpers
// =============================================================================

/// DES key size (bytes) — local duplicate (upstream constant is module-private).
#[cfg(feature = "des")]
const MDC2_DES_KEY_BYTES: usize = 8;

/// DES block size (bytes) — local duplicate (upstream constant is module-private).
#[cfg(feature = "des")]
const MDC2_DES_BLOCK_BYTES: usize = 8;

/// Load a little-endian `u32` from `data` at the given byte offset.
///
/// MD4 and RIPEMD-160 read their 64-byte block as 16 little-endian 32-bit
/// words, matching the `HOST_c2l` macro in `crypto/*/md_local.h`.
#[inline]
fn load_le_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Load a big-endian `u32` from `data` at the given byte offset.
///
/// SM3 reads its 64-byte block as 16 big-endian 32-bit words.
#[inline]
fn load_be_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Load a big-endian `u64` from `data` at the given byte offset.
///
/// Whirlpool loads its 64-byte block as 8 big-endian 64-bit words.
#[inline]
fn load_be_u64(data: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

/// Convert an input byte length to a bit count with overflow checking.
///
/// Rule R6: avoids bare `as` casts; propagates overflow via [`CryptoError`].
#[inline]
fn bytes_to_bits(len: u64) -> CryptoResult<u64> {
    len.checked_mul(8)
        .ok_or_else(|| CryptoError::AlgorithmNotFound("bit-length overflow".into()))
}

/// Accumulate bytes into a running `u64` length counter with overflow checking.
#[inline]
fn add_length(total: u64, delta: usize) -> CryptoResult<u64> {
    let delta_u64 = u64::try_from(delta)
        .map_err(|_| CryptoError::AlgorithmNotFound("length cast overflow".into()))?;
    total
        .checked_add(delta_u64)
        .ok_or_else(|| CryptoError::AlgorithmNotFound("total length overflow".into()))
}

// =============================================================================
// MD2 — RFC 1319 (Rivest, April 1992). **BROKEN** for new cryptographic use.
//
// Source: crypto/md2/md2_dgst.c, crypto/md2/md2_local.h
// =============================================================================

/// MD2 S-table from RFC 1319 Appendix A.  Verbatim from `crypto/md2/md2_dgst.c`.
#[rustfmt::skip]
const MD2_S_TABLE: [u8; 256] = [
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
];

/// MD2 block size in bytes (RFC 1319 §3.1).
const MD2_BLOCK_BYTES: usize = 16;

/// MD2 digest size in bytes (RFC 1319 §3.5).
const MD2_DIGEST_BYTES: usize = 16;

/// MD2 hash context — implements RFC 1319.
///
/// # Security Warning
///
/// MD2 is **cryptographically broken**. Preimage and collision attacks exist
/// that defeat its 128-bit security claim. Retained solely for parsing legacy
/// certificates (some old X.509 profiles) and interoperability tests.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Md2Context {
    /// 48-byte accumulator state (`state` in RFC 1319 §3.4).
    state: [u8; 48],
    /// Checksum register `C` (RFC 1319 §3.2).
    checksum: [u8; MD2_BLOCK_BYTES],
    /// Partial-block buffer.
    data: [u8; MD2_BLOCK_BYTES],
    /// Number of valid bytes currently buffered in `data`.
    num: usize,
}

impl Md2Context {
    /// Construct a fresh MD2 context with all fields zeroed.
    ///
    /// **Deprecated:** MD2 is cryptographically broken. Use SHA-256 or later
    /// for new code.
    #[deprecated(note = "MD2 is cryptographically broken; use SHA-256 or SHA-3")]
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: [0u8; 48],
            checksum: [0u8; MD2_BLOCK_BYTES],
            data: [0u8; MD2_BLOCK_BYTES],
            num: 0,
        }
    }

    /// Run the 18-round MD2 mix over a full 16-byte block.
    ///
    /// Updates `state` using the standard 48-byte expansion:
    /// * `state[0..16]`  — previous chaining state
    /// * `state[16..32]` — current input block
    /// * `state[32..48]` — XOR of previous state and current block
    ///
    /// Then applies 18 mixing rounds, each of which updates all 48 bytes using
    /// the S-table `MD2_S_TABLE`. Translates the body of `md2_block()` in
    /// `crypto/md2/md2_dgst.c`.
    fn block(&mut self, block: &[u8; MD2_BLOCK_BYTES]) {
        for i in 0..MD2_BLOCK_BYTES {
            self.state[16 + i] = block[i];
            self.state[32 + i] = self.state[i] ^ block[i];
        }

        let mut t: u8 = 0;
        for j in 0..18u8 {
            for k in 0..48 {
                self.state[k] ^= MD2_S_TABLE[usize::from(t)];
                t = self.state[k];
            }
            t = t.wrapping_add(j);
        }

        // Update checksum register:
        //   L = C[15]; for i in 0..16: L = C[i] ^= S[block[i] ^ L]
        // (RFC 1319 §3.2)
        let mut l = self.checksum[MD2_BLOCK_BYTES - 1];
        for i in 0..MD2_BLOCK_BYTES {
            l = self.checksum[i] ^ MD2_S_TABLE[usize::from(block[i] ^ l)];
            self.checksum[i] = l;
        }
    }
}

#[allow(deprecated)]
impl Default for Md2Context {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(deprecated)]
impl Digest for Md2Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let mut off = 0usize;

        // Complete any partially-buffered block first.
        if self.num > 0 {
            let space = MD2_BLOCK_BYTES - self.num;
            if data.len() < space {
                self.data[self.num..self.num + data.len()].copy_from_slice(data);
                self.num += data.len();
                return Ok(());
            }
            self.data[self.num..MD2_BLOCK_BYTES].copy_from_slice(&data[..space]);
            let mut block = [0u8; MD2_BLOCK_BYTES];
            block.copy_from_slice(&self.data);
            self.block(&block);
            self.num = 0;
            off = space;
        }

        // Process full 16-byte blocks directly from the input slice.
        while off + MD2_BLOCK_BYTES <= data.len() {
            let mut block = [0u8; MD2_BLOCK_BYTES];
            block.copy_from_slice(&data[off..off + MD2_BLOCK_BYTES]);
            self.block(&block);
            off += MD2_BLOCK_BYTES;
        }

        // Buffer any trailing bytes.
        let rem = data.len() - off;
        if rem > 0 {
            self.data[..rem].copy_from_slice(&data[off..]);
            self.num = rem;
        }
        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // RFC 1319 §3.3: pad so that total length ≡ 0 (mod 16). Padding value
        // = number of padding bytes.
        let pad_len = MD2_BLOCK_BYTES - self.num;
        let pad_value = u8::try_from(pad_len)
            .map_err(|_| CryptoError::AlgorithmNotFound("MD2 padding overflow".into()))?;
        for i in self.num..MD2_BLOCK_BYTES {
            self.data[i] = pad_value;
        }
        let mut block = [0u8; MD2_BLOCK_BYTES];
        block.copy_from_slice(&self.data);
        self.block(&block);

        // RFC 1319 §3.4: append the 16-byte checksum as a final block.
        let mut cksum_block = [0u8; MD2_BLOCK_BYTES];
        cksum_block.copy_from_slice(&self.checksum);
        self.block(&cksum_block);

        // The digest is the first 16 bytes of state.
        Ok(self.state[..MD2_DIGEST_BYTES].to_vec())
    }

    fn digest_size(&self) -> usize {
        MD2_DIGEST_BYTES
    }

    fn block_size(&self) -> usize {
        MD2_BLOCK_BYTES
    }

    fn algorithm_name(&self) -> &'static str {
        "MD2"
    }

    fn reset(&mut self) {
        self.state.fill(0);
        self.checksum.fill(0);
        self.data.fill(0);
        self.num = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

/// One-shot MD2 digest of `data` (legacy, deprecated).
///
/// # Errors
///
/// Returns [`CryptoError`] on internal arithmetic overflow (unreachable on
/// 64-bit targets).
#[deprecated(note = "MD2 is cryptographically broken; use SHA-256 or SHA-3")]
pub fn md2(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Md2Context::new();
    ctx.update(data)?;
    ctx.finalize()
}

// ---------------------------------------------------------------------------
// MD4 — RFC 1320 (1992). DEPRECATED: cryptographically broken (collisions).
// ---------------------------------------------------------------------------

/// MD4 block size in bytes (512 bits).
pub const MD4_BLOCK_BYTES: usize = 64;

/// MD4 digest size in bytes (128 bits).
pub const MD4_DIGEST_BYTES: usize = 16;

/// MD4 initial chaining values (RFC 1320 §3.3).
const MD4_IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// MD4 round 2 constant (RFC 1320 §3.4).
const MD4_K2: u32 = 0x5A827999;

/// MD4 round 3 constant (RFC 1320 §3.4).
const MD4_K3: u32 = 0x6ED9EBA1;

/// MD4 auxiliary function F: `F(X,Y,Z) = (X & Y) | (!X & Z)`.
#[inline]
const fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

/// MD4 auxiliary function G: `G(X,Y,Z) = (X & Y) | (X & Z) | (Y & Z)`.
#[inline]
const fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

/// MD4 auxiliary function H: `H(X,Y,Z) = X ^ Y ^ Z`.
#[inline]
const fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// MD4 compression: 3 rounds of 16 operations each (RFC 1320 §3.4).
fn md4_compress(state: &mut [u32; 4], block: &[u8; MD4_BLOCK_BYTES]) {
    // Load 16 little-endian words from the message block.
    let mut x = [0u32; 16];
    for (i, word) in x.iter_mut().enumerate() {
        *word = load_le_u32(block, i * 4);
    }

    let [mut a, mut b, mut c, mut d] = *state;

    // Round 1: F(b,c,d). Order: (a,b,c,d) (d,a,b,c) (c,d,a,b) (b,c,d,a).
    // Rotations cycle [3, 7, 11, 19] per sub-step, indices 0..15 in order.
    macro_rules! md4_round1 {
        ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(md4_f($b, $c, $d))
                .wrapping_add(x[$k])
                .rotate_left($s);
        };
    }
    md4_round1!(a, b, c, d, 0, 3);
    md4_round1!(d, a, b, c, 1, 7);
    md4_round1!(c, d, a, b, 2, 11);
    md4_round1!(b, c, d, a, 3, 19);
    md4_round1!(a, b, c, d, 4, 3);
    md4_round1!(d, a, b, c, 5, 7);
    md4_round1!(c, d, a, b, 6, 11);
    md4_round1!(b, c, d, a, 7, 19);
    md4_round1!(a, b, c, d, 8, 3);
    md4_round1!(d, a, b, c, 9, 7);
    md4_round1!(c, d, a, b, 10, 11);
    md4_round1!(b, c, d, a, 11, 19);
    md4_round1!(a, b, c, d, 12, 3);
    md4_round1!(d, a, b, c, 13, 7);
    md4_round1!(c, d, a, b, 14, 11);
    md4_round1!(b, c, d, a, 15, 19);

    // Round 2: G(b,c,d), add constant 0x5A827999. Rotations [3, 5, 9, 13].
    macro_rules! md4_round2 {
        ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(md4_g($b, $c, $d))
                .wrapping_add(x[$k])
                .wrapping_add(MD4_K2)
                .rotate_left($s);
        };
    }
    md4_round2!(a, b, c, d, 0, 3);
    md4_round2!(d, a, b, c, 4, 5);
    md4_round2!(c, d, a, b, 8, 9);
    md4_round2!(b, c, d, a, 12, 13);
    md4_round2!(a, b, c, d, 1, 3);
    md4_round2!(d, a, b, c, 5, 5);
    md4_round2!(c, d, a, b, 9, 9);
    md4_round2!(b, c, d, a, 13, 13);
    md4_round2!(a, b, c, d, 2, 3);
    md4_round2!(d, a, b, c, 6, 5);
    md4_round2!(c, d, a, b, 10, 9);
    md4_round2!(b, c, d, a, 14, 13);
    md4_round2!(a, b, c, d, 3, 3);
    md4_round2!(d, a, b, c, 7, 5);
    md4_round2!(c, d, a, b, 11, 9);
    md4_round2!(b, c, d, a, 15, 13);

    // Round 3: H(b,c,d), add constant 0x6ED9EBA1. Rotations [3, 9, 11, 15].
    macro_rules! md4_round3 {
        ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(md4_h($b, $c, $d))
                .wrapping_add(x[$k])
                .wrapping_add(MD4_K3)
                .rotate_left($s);
        };
    }
    md4_round3!(a, b, c, d, 0, 3);
    md4_round3!(d, a, b, c, 8, 9);
    md4_round3!(c, d, a, b, 4, 11);
    md4_round3!(b, c, d, a, 12, 15);
    md4_round3!(a, b, c, d, 2, 3);
    md4_round3!(d, a, b, c, 10, 9);
    md4_round3!(c, d, a, b, 6, 11);
    md4_round3!(b, c, d, a, 14, 15);
    md4_round3!(a, b, c, d, 1, 3);
    md4_round3!(d, a, b, c, 9, 9);
    md4_round3!(c, d, a, b, 5, 11);
    md4_round3!(b, c, d, a, 13, 15);
    md4_round3!(a, b, c, d, 3, 3);
    md4_round3!(d, a, b, c, 11, 9);
    md4_round3!(c, d, a, b, 7, 11);
    md4_round3!(b, c, d, a, 15, 15);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);

    x.zeroize();
}

/// Streaming MD4 digest context (RFC 1320).
///
/// **DEPRECATED — MD4 is cryptographically broken and MUST NOT be used for
/// new designs.** Retained only for legacy interoperability (e.g., CIFS/SMB,
/// Kerberos RC4-HMAC, NT hash).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Md4Context {
    /// Chaining state `(A, B, C, D)`.
    h: [u32; 4],
    /// Residual buffer for partial blocks.
    block: [u8; MD4_BLOCK_BYTES],
    /// Bytes currently buffered in `block`.
    num: usize,
    /// Total message length in bytes.
    total_len: u64,
}

impl Md4Context {
    /// Creates a new MD4 context initialised with RFC 1320 §3.3 IV.
    #[deprecated(note = "MD4 is cryptographically broken; use SHA-256 or SHA-3")]
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: MD4_IV,
            block: [0; MD4_BLOCK_BYTES],
            num: 0,
            total_len: 0,
        }
    }

    /// Runs one full-block compression.
    fn compress(&mut self) {
        md4_compress(&mut self.h, &self.block);
    }
}

impl Default for Md4Context {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

impl Digest for Md4Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.total_len = add_length(self.total_len, data.len())?;

        let mut offset = 0;

        // Fill an in-flight partial block if present.
        if self.num > 0 {
            let need = MD4_BLOCK_BYTES - self.num;
            let take = need.min(data.len());
            self.block[self.num..self.num + take].copy_from_slice(&data[..take]);
            self.num += take;
            offset += take;
            if self.num == MD4_BLOCK_BYTES {
                self.compress();
                self.num = 0;
            }
        }

        // Process full blocks directly from the caller's buffer.
        while data.len() - offset >= MD4_BLOCK_BYTES {
            self.block
                .copy_from_slice(&data[offset..offset + MD4_BLOCK_BYTES]);
            self.compress();
            offset += MD4_BLOCK_BYTES;
        }

        // Buffer the tail.
        let tail = data.len() - offset;
        if tail > 0 {
            self.block[..tail].copy_from_slice(&data[offset..]);
            self.num = tail;
        }

        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Append the 0x80 padding byte.
        let bit_len = bytes_to_bits(self.total_len)?;
        self.block[self.num] = 0x80;
        self.num += 1;

        // If there is not enough room for the 64-bit length field, pad to the
        // end of this block, compress, and begin a fresh one.
        if self.num > MD4_BLOCK_BYTES - 8 {
            for byte in &mut self.block[self.num..] {
                *byte = 0;
            }
            self.compress();
            self.num = 0;
        }

        // Zero-pad up to the length field.
        for byte in &mut self.block[self.num..MD4_BLOCK_BYTES - 8] {
            *byte = 0;
        }

        // Write the 64-bit message length in LITTLE-ENDIAN (RFC 1320 §3.2).
        self.block[MD4_BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_le_bytes());
        self.compress();

        // Serialise the state as little-endian 32-bit words.
        let mut out = Vec::with_capacity(MD4_DIGEST_BYTES);
        for word in &self.h {
            out.extend_from_slice(&word.to_le_bytes());
        }

        // Wipe the context before returning.
        self.reset();
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        MD4_DIGEST_BYTES
    }

    fn block_size(&self) -> usize {
        MD4_BLOCK_BYTES
    }

    fn algorithm_name(&self) -> &'static str {
        "MD4"
    }

    fn reset(&mut self) {
        self.h = MD4_IV;
        self.block.zeroize();
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

/// One-shot MD4 digest of `data` (legacy, deprecated).
///
/// # Errors
///
/// Returns [`CryptoError`] on internal arithmetic overflow (unreachable on
/// 64-bit targets).
#[deprecated(note = "MD4 is cryptographically broken; use SHA-256 or SHA-3")]
pub fn md4(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Md4Context::new();
    ctx.update(data)?;
    ctx.finalize()
}


// ---------------------------------------------------------------------------
// MDC-2 — Meyer/Schilling Modification Detection Code (ISO/IEC 10118-2).
// DEPRECATED: 64-bit pair of DES gives only ~2^55 collision resistance.
// Gated behind the `"des"` feature: MDC-2 is constructed from DES.
// ---------------------------------------------------------------------------

/// MDC-2 block size in bytes (equals DES block).
#[cfg(feature = "des")]
pub const MDC2_BLOCK_BYTES: usize = MDC2_DES_BLOCK_BYTES;

/// MDC-2 digest size in bytes (two concatenated DES blocks).
#[cfg(feature = "des")]
pub const MDC2_DIGEST_BYTES: usize = 2 * MDC2_DES_BLOCK_BYTES;

/// MDC-2 initial value for the first chaining variable `h` (all `0x52`).
#[cfg(feature = "des")]
const MDC2_IV_H: [u8; MDC2_DES_KEY_BYTES] = [0x52; MDC2_DES_KEY_BYTES];

/// MDC-2 initial value for the second chaining variable `hh` (all `0x25`).
#[cfg(feature = "des")]
const MDC2_IV_HH: [u8; MDC2_DES_KEY_BYTES] = [0x25; MDC2_DES_KEY_BYTES];

/// Streaming MDC-2 digest context.
///
/// **DEPRECATED** — MDC-2 provides only 64-bit collision resistance in the
/// best case (and ~55-bit in practice due to DES complementation properties).
/// Retained exclusively for legacy interoperability.
#[cfg(feature = "des")]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mdc2Context {
    /// Upper chaining half (serves as DES key after bit-masking).
    h: [u8; MDC2_DES_KEY_BYTES],
    /// Lower chaining half (serves as DES key after bit-masking).
    hh: [u8; MDC2_DES_KEY_BYTES],
    /// Residual buffer for partial blocks.
    block: [u8; MDC2_BLOCK_BYTES],
    /// Bytes currently buffered in `block`.
    num: usize,
}

#[cfg(feature = "des")]
impl Mdc2Context {
    /// Creates a new MDC-2 context with the ISO 10118-2 initial values.
    #[deprecated(note = "MDC-2 is deprecated; use SHA-256 or SHA-3")]
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: MDC2_IV_H,
            hh: MDC2_IV_HH,
            block: [0; MDC2_BLOCK_BYTES],
            num: 0,
        }
    }

    /// Applies one Meyer-Schilling compression step to `self.block`.
    ///
    /// The current 8-byte message block is encrypted twice under the two DES
    /// key halves (after forcing their top nibbles to `0100xxxx` / `0010xxxx`
    /// per the MDC-2 specification). The two ciphertexts are `XORed` with the
    /// plaintext (`Matyas-Meyer-Oseas`) and the right halves are swapped to
    /// produce the new chaining values.
    fn compress(&mut self) {
        // Derive DES keys from current chaining state with the MDC-2
        // required bit-fix on the first byte.
        let mut h_key = self.h;
        let mut hh_key = self.hh;
        h_key[0] = (h_key[0] & 0x9f) | 0x40;
        hh_key[0] = (hh_key[0] & 0x9f) | 0x20;

        // `set_key_unchecked` skips weak-key detection — required by MDC-2
        // because the bit-fix patterns above deliberately select keys that
        // would otherwise be rejected as weak.
        let ks_h = DesKeySchedule::set_key_unchecked(&h_key);
        let ks_hh = DesKeySchedule::set_key_unchecked(&hh_key);

        // Encrypt the block under each key.
        let mut d: [u8; MDC2_DES_BLOCK_BYTES] = self.block;
        let mut dd: [u8; MDC2_DES_BLOCK_BYTES] = self.block;
        ks_h.encrypt_block(&mut d);
        ks_hh.encrypt_block(&mut dd);

        // Matyas-Meyer-Oseas: output halves = message XOR ciphertext.
        let mut t = [0u8; MDC2_DES_BLOCK_BYTES];
        let mut tt = [0u8; MDC2_DES_BLOCK_BYTES];
        for i in 0..MDC2_DES_BLOCK_BYTES {
            t[i] = self.block[i] ^ d[i];
            tt[i] = self.block[i] ^ dd[i];
        }

        // Meyer-Schilling mix: swap the right halves between the two MDCs.
        self.h[..4].copy_from_slice(&t[..4]);
        self.h[4..].copy_from_slice(&tt[4..]);
        self.hh[..4].copy_from_slice(&tt[..4]);
        self.hh[4..].copy_from_slice(&t[4..]);

        // Wipe local secrets.
        h_key.zeroize();
        hh_key.zeroize();
        d.zeroize();
        dd.zeroize();
        t.zeroize();
        tt.zeroize();
    }
}

#[cfg(feature = "des")]
impl Default for Mdc2Context {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

#[cfg(feature = "des")]
impl Digest for Mdc2Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let mut offset = 0;

        if self.num > 0 {
            let need = MDC2_BLOCK_BYTES - self.num;
            let take = need.min(data.len());
            self.block[self.num..self.num + take].copy_from_slice(&data[..take]);
            self.num += take;
            offset += take;
            if self.num == MDC2_BLOCK_BYTES {
                self.compress();
                self.num = 0;
            }
        }

        while data.len() - offset >= MDC2_BLOCK_BYTES {
            self.block
                .copy_from_slice(&data[offset..offset + MDC2_BLOCK_BYTES]);
            self.compress();
            offset += MDC2_BLOCK_BYTES;
        }

        let tail = data.len() - offset;
        if tail > 0 {
            self.block[..tail].copy_from_slice(&data[offset..]);
            self.num = tail;
        }

        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Pad type 1 (OpenSSL default): zero-pad any residual partial block.
        // Length is NOT appended — MDC-2 does not include Merkle-Damgård
        // strengthening. This matches `MDC2_Final` in `crypto/mdc2/mdc2dgst.c`.
        if self.num > 0 {
            for byte in &mut self.block[self.num..] {
                *byte = 0;
            }
            self.compress();
            self.num = 0;
        }

        let mut out = Vec::with_capacity(MDC2_DIGEST_BYTES);
        out.extend_from_slice(&self.h);
        out.extend_from_slice(&self.hh);
        self.reset();
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        MDC2_DIGEST_BYTES
    }

    fn block_size(&self) -> usize {
        MDC2_BLOCK_BYTES
    }

    fn algorithm_name(&self) -> &'static str {
        "MDC-2"
    }

    fn reset(&mut self) {
        self.h = MDC2_IV_H;
        self.hh = MDC2_IV_HH;
        self.block.zeroize();
        self.num = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

/// One-shot MDC-2 digest of `data` (legacy, deprecated).
///
/// # Errors
///
/// Returns [`CryptoError`] only on pathological internal arithmetic overflow.
#[cfg(feature = "des")]
#[deprecated(note = "MDC-2 is deprecated; use SHA-256 or SHA-3")]
pub fn mdc2(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Mdc2Context::new();
    ctx.update(data)?;
    ctx.finalize()
}

// ======================================================================
// RIPEMD-160 — RACE Integrity Primitives Evaluation Message Digest
// ======================================================================
//
// ISO/IEC 10118-3; RFC 2286 (test vectors); specified by Dobbertin, Bosselaers,
// and Preneel (1996). 160-bit digest produced by two parallel 80-round lanes
// (left and right) combined via a rotation-and-add mixing scheme. Widely used
// in Bitcoin address derivation (`HASH160 = RIPEMD-160(SHA-256(pubkey))`).
//
// RIPEMD-160 operates on 512-bit (64-byte) blocks, reads message words in
// little-endian order, and appends a 64-bit little-endian bit-length at the
// end of padding (analogous to MD4/MD5).
//
// Source reference: `crypto/ripemd/rmd_dgst.c`, `crypto/ripemd/rmdconst.h`
// (the round constants KL/KR, word-selection tables WL/WR, and rotation tables
// SL/SR are reproduced verbatim here).

/// Block size of RIPEMD-160 in bytes.
pub const RIPEMD160_BLOCK_BYTES: usize = 64;

/// Digest size of RIPEMD-160 in bytes.
pub const RIPEMD160_DIGEST_BYTES: usize = 20;

/// Initial chaining value (h0..h4) for RIPEMD-160.
const RIPEMD160_IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Per-round-group additive constants for the left lane.
const RIPEMD160_KL: [u32; 5] = [
    0x0000_0000,
    0x5a82_7999,
    0x6ed9_eba1,
    0x8f1b_bcdc,
    0xa953_fd4e,
];

/// Per-round-group additive constants for the right lane.
const RIPEMD160_KR: [u32; 5] = [
    0x50a2_8be6,
    0x5c4d_d124,
    0x6d70_3ef3,
    0x7a6d_76e9,
    0x0000_0000,
];

/// Word-selection schedule for the left lane (80 rounds × 1 word index).
const RIPEMD160_WL: [usize; 80] = [
    // Round 1 (f1)
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    // Round 2 (f2)
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    // Round 3 (f3)
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    // Round 4 (f4)
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    // Round 5 (f5)
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// Word-selection schedule for the right lane (80 rounds × 1 word index).
const RIPEMD160_WR: [usize; 80] = [
    // Round 1 (f5)
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    // Round 2 (f4)
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    // Round 3 (f3)
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    // Round 4 (f2)
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    // Round 5 (f1)
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Rotation-amount schedule for the left lane.
const RIPEMD160_SL: [u32; 80] = [
    // Round 1
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    // Round 2
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    // Round 3
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    // Round 4
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    // Round 5
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// Rotation-amount schedule for the right lane.
const RIPEMD160_SR: [u32; 80] = [
    // Round 1
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    // Round 2
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    // Round 3
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    // Round 4
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    // Round 5
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// RIPEMD-160 boolean function 1 (rounds 0..15 left / 64..79 right).
#[inline]
const fn rmd_f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// RIPEMD-160 boolean function 2 (rounds 16..31 left / 48..63 right).
#[inline]
const fn rmd_f2(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// RIPEMD-160 boolean function 3 (rounds 32..47 left and right).
#[inline]
const fn rmd_f3(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

/// RIPEMD-160 boolean function 4 (rounds 48..63 left / 16..31 right).
#[inline]
const fn rmd_f4(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

/// RIPEMD-160 boolean function 5 (rounds 64..79 left / 0..15 right).
#[inline]
const fn rmd_f5(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

/// Evaluate the RIPEMD-160 boolean function for the given round index on the
/// **left lane** (f1 → f2 → f3 → f4 → f5 every 16 rounds).
#[inline]
const fn rmd_fl(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j / 16 {
        0 => rmd_f1(x, y, z),
        1 => rmd_f2(x, y, z),
        2 => rmd_f3(x, y, z),
        3 => rmd_f4(x, y, z),
        _ => rmd_f5(x, y, z),
    }
}

/// Evaluate the RIPEMD-160 boolean function for the given round index on the
/// **right lane** (f5 → f4 → f3 → f2 → f1 every 16 rounds).
#[inline]
const fn rmd_fr(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j / 16 {
        0 => rmd_f5(x, y, z),
        1 => rmd_f4(x, y, z),
        2 => rmd_f3(x, y, z),
        3 => rmd_f2(x, y, z),
        _ => rmd_f1(x, y, z),
    }
}

/// RIPEMD-160 block compression function.
///
/// Processes a single 64-byte block through two parallel 80-round lanes
/// (left and right) and mixes them back into the state via the RIPEMD-160
/// final-combination rule.
#[inline]
fn ripemd160_compress(state: &mut [u32; 5], block: &[u8; RIPEMD160_BLOCK_BYTES]) {
    // Expand block into 16 little-endian 32-bit message words.
    let mut x = [0u32; 16];
    for (i, word) in x.iter_mut().enumerate() {
        *word = load_le_u32(block, i * 4);
    }

    // Left lane working variables.
    let mut al = state[0];
    let mut bl = state[1];
    let mut cl = state[2];
    let mut dl = state[3];
    let mut el = state[4];

    // Right lane working variables (same initial values as the left lane).
    let mut ar = state[0];
    let mut br = state[1];
    let mut cr = state[2];
    let mut dr = state[3];
    let mut er = state[4];

    // 80-round interleaved execution — both lanes advance in lockstep.
    for j in 0..80usize {
        let group = j / 16;

        // --- Left lane round j ---
        let fl = rmd_fl(j, bl, cl, dl);
        let tl = al
            .wrapping_add(fl)
            .wrapping_add(x[RIPEMD160_WL[j]])
            .wrapping_add(RIPEMD160_KL[group])
            .rotate_left(RIPEMD160_SL[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = tl;

        // --- Right lane round j ---
        let fr = rmd_fr(j, br, cr, dr);
        let tr = ar
            .wrapping_add(fr)
            .wrapping_add(x[RIPEMD160_WR[j]])
            .wrapping_add(RIPEMD160_KR[group])
            .rotate_left(RIPEMD160_SR[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = tr;
    }

    // Final combination — shifted chaining variables mix left and right lanes.
    let t = state[1].wrapping_add(cl).wrapping_add(dr);
    state[1] = state[2].wrapping_add(dl).wrapping_add(er);
    state[2] = state[3].wrapping_add(el).wrapping_add(ar);
    state[3] = state[4].wrapping_add(al).wrapping_add(br);
    state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
    state[0] = t;

    x.zeroize();
}

/// RIPEMD-160 streaming context.
///
/// Reproduces the semantics of OpenSSL's `RIPEMD160_CTX` / `RIPEMD160_Init` /
/// `RIPEMD160_Update` / `RIPEMD160_Final` trio.
///
/// The context holds the 160-bit chaining state, a 512-bit block buffer,
/// the count of buffered bytes, and the cumulative message length in bits
/// (updated via the overflow-checked `add_length` helper per rule R6).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ripemd160Context {
    h: [u32; 5],
    block: [u8; RIPEMD160_BLOCK_BYTES],
    num: usize,
    total_len: u64,
}

impl Ripemd160Context {
    /// Construct a new RIPEMD-160 context seeded with the standard IV.
    ///
    /// Marked `#[deprecated]` because RIPEMD-160 is a legacy algorithm. It
    /// should only be used where required for interoperability (e.g. Bitcoin
    /// `HASH160`, PGP legacy compatibility).
    #[deprecated(note = "RIPEMD-160 is a legacy algorithm; use SHA-256 or SHA-3 for new designs")]
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: RIPEMD160_IV,
            block: [0; RIPEMD160_BLOCK_BYTES],
            num: 0,
            total_len: 0,
        }
    }

    /// Process the currently buffered block and reset the buffer offset.
    fn compress(&mut self) {
        ripemd160_compress(&mut self.h, &self.block);
        self.num = 0;
    }
}

impl Default for Ripemd160Context {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

impl Digest for Ripemd160Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.total_len = add_length(self.total_len, data.len())?;

        let mut rest = data;

        // Fill any existing partial block first.
        if self.num > 0 {
            let need = RIPEMD160_BLOCK_BYTES - self.num;
            if rest.len() < need {
                self.block[self.num..self.num + rest.len()].copy_from_slice(rest);
                self.num += rest.len();
                return Ok(());
            }
            self.block[self.num..].copy_from_slice(&rest[..need]);
            self.compress();
            rest = &rest[need..];
        }

        // Process aligned 64-byte chunks in place without an intermediate copy.
        while rest.len() >= RIPEMD160_BLOCK_BYTES {
            let chunk = &rest[..RIPEMD160_BLOCK_BYTES];
            // Copy into the local buffer so compression can operate on an array.
            self.block.copy_from_slice(chunk);
            ripemd160_compress(&mut self.h, &self.block);
            rest = &rest[RIPEMD160_BLOCK_BYTES..];
        }

        // Retain the remaining tail bytes for the next update/finalize call.
        if !rest.is_empty() {
            self.block[..rest.len()].copy_from_slice(rest);
            self.num = rest.len();
        }

        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Total message length in bits (little-endian 64-bit footer).
        let bit_len = bytes_to_bits(self.total_len)?;

        // Append the mandatory 0x80 marker.
        self.block[self.num] = 0x80;
        self.num += 1;

        // If there is no room for the 64-bit length footer in this block,
        // zero-pad and compress a full block first.
        if self.num > RIPEMD160_BLOCK_BYTES - 8 {
            for byte in &mut self.block[self.num..] {
                *byte = 0;
            }
            self.compress();
        }

        // Zero-pad up to the length field.
        for byte in &mut self.block[self.num..RIPEMD160_BLOCK_BYTES - 8] {
            *byte = 0;
        }

        // Write the 64-bit bit-length in little-endian at the block tail.
        self.block[RIPEMD160_BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_le_bytes());
        self.compress();

        // Serialize the chaining state as little-endian bytes.
        let mut out = Vec::with_capacity(RIPEMD160_DIGEST_BYTES);
        for word in &self.h {
            out.extend_from_slice(&word.to_le_bytes());
        }

        self.reset();
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        RIPEMD160_DIGEST_BYTES
    }

    fn block_size(&self) -> usize {
        RIPEMD160_BLOCK_BYTES
    }

    fn algorithm_name(&self) -> &'static str {
        "RIPEMD-160"
    }

    fn reset(&mut self) {
        self.h = RIPEMD160_IV;
        self.block.zeroize();
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

/// One-shot RIPEMD-160 digest computation.
///
/// # Errors
///
/// Returns [`CryptoError`] only if the total message length would overflow
/// 64-bit unsigned bits on an extremely large input (exabyte scale).
#[deprecated(note = "RIPEMD-160 is a legacy algorithm; use SHA-256 or SHA-3 for new designs")]
pub fn ripemd160(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Ripemd160Context::new();
    ctx.update(data)?;
    ctx.finalize()
}


// =============================================================================
// SM3 — Chinese national-standard hash function (GB/T 32905-2016 / GM/T 0004)
// =============================================================================
//
// SM3 is a cryptographic hash designated by the Chinese State Cryptography
// Administration (OSCCA) as a Chinese National Standard. It produces a 256-bit
// digest via a Merkle-Damgard structure with 64-byte (512-bit) blocks and 64
// rounds of compression.
//
// SM3 is used by SM2 digital signatures and SM9 identity-based cryptography,
// and appears in TLS cipher suites such as `TLS_SM4_GCM_SM3`.
//
// Source: `crypto/sm3/sm3.c` + `crypto/sm3/sm3_local.h` from the OpenSSL C
// reference (preserved alongside this Rust translation as the validation
// baseline).
//
// Standards references:
// * GB/T 32905-2016 — "Information security technology — SM3 cryptographic
//   hash algorithm" (Chinese national standard).
// * RFC 8998 — ShangMi (SM) Cipher Suites for TLS 1.3 (test vectors).
//
// **Regional standard**: SM3 is regionally standardized by the Chinese State
// Cryptography Administration. Interoperable global designs should prefer
// SHA-256 or SHA-3/256.

/// SM3 block size in bytes (512 bits).
pub const SM3_BLOCK_BYTES: usize = 64;

/// SM3 digest size in bytes (256 bits).
pub const SM3_DIGEST_BYTES: usize = 32;

/// SM3 initial hash values (GB/T 32905-2016 §5.1).
///
/// The eight 32-bit initial chaining registers `A..H` are interpreted as
/// big-endian words throughout the algorithm.
const SM3_IV: [u32; 8] = [
    0x7380_166F,
    0x4914_B2B9,
    0x1724_42D7,
    0xDA8A_0600,
    0xA96F_30BC,
    0x1631_38AA,
    0xE38D_EE4D,
    0xB0FB_0E4E,
];

/// Pre-computed, pre-rotated SM3 round constants `T[j] <<< (j mod 32)`.
///
/// The base constants per GB/T 32905-2016 §5.2 are:
/// * `T[0..=15]  = 0x79CC4519`
/// * `T[16..=63] = 0x7A879D8A`
///
/// Pre-rotating at compile time removes a data-dependent rotate from every
/// round of the hot compression loop.
// TRUNCATION: `j % 32` is always in `[0, 32)`, safely representable in `u32`
// and necessary to satisfy the `u32::rotate_left` parameter type.
#[allow(clippy::cast_possible_truncation)]
const SM3_T_ROTATED: [u32; 64] = {
    let mut t = [0u32; 64];
    let mut j = 0usize;
    while j < 64 {
        let base = if j < 16 { 0x79CC_4519_u32 } else { 0x7A87_9D8A_u32 };
        t[j] = base.rotate_left((j % 32) as u32);
        j += 1;
    }
    t
};

/// Boolean function `FF_j` for rounds `0..=15` — bitwise XOR.
#[inline]
const fn sm3_ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Boolean function `FF_j` for rounds `16..=63` — bitwise majority.
#[inline]
const fn sm3_ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

/// Boolean function `GG_j` for rounds `0..=15` — bitwise XOR.
#[inline]
const fn sm3_gg0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Boolean function `GG_j` for rounds `16..=63` — bitwise choice.
#[inline]
const fn sm3_gg1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// Permutation `P_0(X) = X XOR (X <<< 9) XOR (X <<< 17)`.
#[inline]
const fn sm3_p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// Permutation `P_1(X) = X XOR (X <<< 15) XOR (X <<< 23)`.
#[inline]
const fn sm3_p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// SM3 compression — processes exactly one 64-byte block.
///
/// Translates `sm3_block_data_order` from `crypto/sm3/sm3_local.h` in the
/// upstream C source.
///
/// RATIONALE: GB/T 32905-2016 §5.3.3 specifies the working registers `A`
/// through `H` by single-letter identifiers. Using the spec's names preserves
/// implementation fidelity and aids cross-referencing against the standard
/// and the upstream C implementation.
#[allow(clippy::many_single_char_names)]
fn sm3_compress(state: &mut [u32; 8], block: &[u8; SM3_BLOCK_BYTES]) {
    // --- Message expansion (GB/T 32905-2016 §5.3.2) ---

    // Load the 16 big-endian 32-bit message words.
    let mut w = [0u32; 68];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = load_be_u32(block, i * 4);
    }
    // Extend to W[16..=67] via the P_1 mixing permutation.
    for j in 16..68usize {
        w[j] = sm3_p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }
    // Derive W'[0..64] = W[j] ^ W[j+4].
    let mut w_prime = [0u32; 64];
    for (j, slot) in w_prime.iter_mut().enumerate() {
        *slot = w[j] ^ w[j + 4];
    }

    // --- Compression (GB/T 32905-2016 §5.3.3) ---

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for j in 0..64usize {
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(SM3_T_ROTATED[j])
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let (tt1, tt2) = if j < 16 {
            (
                sm3_ff0(a, b, c)
                    .wrapping_add(d)
                    .wrapping_add(ss2)
                    .wrapping_add(w_prime[j]),
                sm3_gg0(e, f, g)
                    .wrapping_add(h)
                    .wrapping_add(ss1)
                    .wrapping_add(w[j]),
            )
        } else {
            (
                sm3_ff1(a, b, c)
                    .wrapping_add(d)
                    .wrapping_add(ss2)
                    .wrapping_add(w_prime[j]),
                sm3_gg1(e, f, g)
                    .wrapping_add(h)
                    .wrapping_add(ss1)
                    .wrapping_add(w[j]),
            )
        };
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = sm3_p0(tt2);
    }

    // XOR feedback (GB/T 32905-2016 §5.3.3 step 4) — distinct from the ADD
    // feedback used in MD4 / RIPEMD-160 / SHA-256.
    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;

    // Wipe the temporary message schedule to limit key / plaintext residue.
    w.zeroize();
    w_prime.zeroize();
}

/// SM3 streaming context (GB/T 32905-2016).
///
/// Reproduces the semantics of OpenSSL's `SM3_CTX` / `ossl_sm3_init` /
/// `ossl_sm3_update` / `ossl_sm3_final` trio.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sm3Context {
    /// Chaining state `(A, B, C, D, E, F, G, H)`.
    h: [u32; 8],
    /// Residual buffer for partial blocks.
    block: [u8; SM3_BLOCK_BYTES],
    /// Number of bytes currently buffered in `block`.
    num: usize,
    /// Total message length in bytes (updated via `add_length`).
    total_len: u64,
}

impl Sm3Context {
    /// Constructs a new SM3 context seeded with the GB/T 32905-2016 IV.
    #[deprecated(
        note = "SM3 is a regionally standardized algorithm; prefer SHA-256 or SHA-3/256 for interoperable designs"
    )]
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: SM3_IV,
            block: [0u8; SM3_BLOCK_BYTES],
            num: 0,
            total_len: 0,
        }
    }

    /// Processes the currently buffered block and resets the buffer offset.
    fn compress(&mut self) {
        sm3_compress(&mut self.h, &self.block);
        self.num = 0;
    }
}

impl Default for Sm3Context {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

impl Digest for Sm3Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.total_len = add_length(self.total_len, data.len())?;

        let mut rest = data;

        // Fill any existing partial block first.
        if self.num > 0 {
            let need = SM3_BLOCK_BYTES - self.num;
            if rest.len() < need {
                self.block[self.num..self.num + rest.len()].copy_from_slice(rest);
                self.num += rest.len();
                return Ok(());
            }
            self.block[self.num..].copy_from_slice(&rest[..need]);
            self.compress();
            rest = &rest[need..];
        }

        // Process aligned 64-byte chunks straight from the caller's buffer.
        while rest.len() >= SM3_BLOCK_BYTES {
            let chunk = &rest[..SM3_BLOCK_BYTES];
            self.block.copy_from_slice(chunk);
            sm3_compress(&mut self.h, &self.block);
            rest = &rest[SM3_BLOCK_BYTES..];
        }

        // Retain the trailing bytes for the next update / finalize call.
        if !rest.is_empty() {
            self.block[..rest.len()].copy_from_slice(rest);
            self.num = rest.len();
        }

        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Total message length in bits (big-endian 64-bit footer per §4.1).
        let bit_len = bytes_to_bits(self.total_len)?;

        // Append the mandatory 0x80 marker.
        self.block[self.num] = 0x80;
        self.num += 1;

        // If there is no room for the 64-bit length footer in this block,
        // zero-pad and compress a full block first.
        if self.num > SM3_BLOCK_BYTES - 8 {
            for byte in &mut self.block[self.num..] {
                *byte = 0;
            }
            self.compress();
        }

        // Zero-pad up to the length field.
        for byte in &mut self.block[self.num..SM3_BLOCK_BYTES - 8] {
            *byte = 0;
        }

        // Write the 64-bit bit-length in BIG-ENDIAN (GB/T 32905-2016 §4.1).
        self.block[SM3_BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_be_bytes());
        self.compress();

        // Serialize the chaining state as big-endian 32-bit words.
        let mut out = Vec::with_capacity(SM3_DIGEST_BYTES);
        for word in &self.h {
            out.extend_from_slice(&word.to_be_bytes());
        }

        self.reset();
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        SM3_DIGEST_BYTES
    }

    fn block_size(&self) -> usize {
        SM3_BLOCK_BYTES
    }

    fn algorithm_name(&self) -> &'static str {
        "SM3"
    }

    fn reset(&mut self) {
        self.h = SM3_IV;
        self.block.zeroize();
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

/// One-shot SM3 digest computation.
///
/// # Errors
///
/// Returns [`CryptoError`] only if the total message length would overflow
/// 64-bit unsigned bits on an extremely large input (exabyte scale).
#[deprecated(
    note = "SM3 is a regionally standardized algorithm; prefer SHA-256 or SHA-3/256 for interoperable designs"
)]
pub fn sm3(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Sm3Context::new();
    ctx.update(data)?;
    ctx.finalize()
}


// =============================================================================
// Whirlpool — 512-bit NESSIE / ISO/IEC 10118-3 hash function
// =============================================================================
//
// Whirlpool is a 512-bit cryptographic hash function designed by Paulo Barreto
// and Vincent Rijmen. It was selected by the NESSIE project in 2003 and later
// standardized in ISO/IEC 10118-3:2018. The algorithm is built from a 10-round
// block cipher (the "W" cipher operating over GF(2^8)) composed with the
// `Miyaguchi-Preneel` construction to extract a 512-bit chaining value.
//
// The round function applies, in sequence:
//   1. SubBytes     — non-linear S-box substitution
//   2. ShiftColumns — cyclic byte shift within columns
//   3. MixRows      — MDS diffusion over GF(2^8)
//   4. AddRoundKey  — XOR with the derived round key
//
// Combined with the fixed MDS vector `(1, 1, 4, 1, 8, 5, 2, 9)`, the entire
// SubBytes+MixRows step can be expressed as a single table lookup per byte.
// Column `j` of the table is `column 0` rotated right by `8 * j` bits, so only
// a single 2 KiB `C_0` lookup table is needed; columns `C_1..=C_7` are derived
// at runtime via `u64::rotate_right`.
//
// Source: `crypto/whrlpool/wp_block.c` + `crypto/whrlpool/wp_dgst.c` from the
// OpenSSL C reference (preserved alongside this Rust translation as the
// validation baseline).
//
// Standards references:
// * ISO/IEC 10118-3:2018 — "Information technology — Security techniques —
//   Hash-functions — Part 3: Dedicated hash-functions".
// * NESSIE final report, 2003.
// * P. Barreto and V. Rijmen, "The Whirlpool Hashing Function", 2003.
//
// **Legacy status**: Whirlpool is retained for legacy interoperability with
// ISO 10118-3 applications. Prefer SHA-256, SHA-384, SHA-512, or SHA-3 for
// new designs.

/// Whirlpool block size in bytes (512 bits).
pub const WHIRLPOOL_BLOCK_BYTES: usize = 64;

/// Whirlpool digest size in bytes (512 bits).
pub const WHIRLPOOL_DIGEST_BYTES: usize = 64;

/// Number of Whirlpool rounds.
const WHIRLPOOL_ROUNDS: usize = 10;

/// Whirlpool S-box (256 bytes).
///
/// Produced from the non-linear `E`, `E^-1`, and `R` mappings specified in
/// the Whirlpool design document. The bytes are transcribed verbatim from
/// `crypto/whrlpool/wp_block.c` in the upstream OpenSSL C reference.
const WHIRLPOOL_S: [u8; 256] = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f,
    0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35,
    0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda,
    0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67,
    0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e,
    0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9,
    0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48,
    0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12,
    0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b,
    0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0,
    0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96,
    0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61,
    0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24,
    0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3,
    0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c,
    0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed,
    0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
];

/// Multiply a byte by 2 in GF(2^8) using the Whirlpool reduction polynomial
/// `0x11d` (i.e. `x^8 + x^4 + x^3 + x^2 + 1`).
///
/// The left shift `n << 1` discards the most-significant bit of the input
/// within `u8` arithmetic. When that bit was set, the reduction polynomial's
/// low byte `0x1d` is `XORed` to fold the overflow back into the field.
#[inline]
const fn whirlpool_gf_mul2(n: u8) -> u8 {
    if n & 0x80 != 0 {
        (n << 1) ^ 0x1d
    } else {
        n << 1
    }
}

/// Pre-computed MDS-multiplied substitution table (column 0 only).
///
/// Each entry `WHIRLPOOL_C0[b]` packs the eight MDS-multiplied outputs for
/// S-box value `S[b]` into a big-endian `u64` with byte layout
/// `[v1, v1, v4, v1, v8, v5, v2, v9]`, where `v_k = S[b] * k` in GF(2^8).
///
/// Columns `C_1..=C_7` are recovered at runtime via
/// `WHIRLPOOL_C0[b].rotate_right(8 * j)`, exploiting the circulant structure
/// of the MDS matrix. This is the `N=1` layout from `wp_block.c`; it
/// minimises cache footprint at the cost of one rotate per byte lookup.
const WHIRLPOOL_C0: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        let c = WHIRLPOOL_S[i];
        let v1 = c;
        let v2 = whirlpool_gf_mul2(c);
        let v4 = whirlpool_gf_mul2(v2);
        let v5 = v4 ^ v1;
        let v8 = whirlpool_gf_mul2(v4);
        let v9 = v8 ^ v1;
        table[i] = u64::from_be_bytes([v1, v1, v4, v1, v8, v5, v2, v9]);
        i += 1;
    }
    table
};

/// Whirlpool round constants `RC[0..10]`.
///
/// Each `RC[r]` packs `WHIRLPOOL_S[8*r..8*r + 8]` as a big-endian `u64`, as
/// specified in the Whirlpool design document §5.1.  The first ten round
/// constants coincide with bytes 0..80 of the S-box.
const WHIRLPOOL_RC: [u64; WHIRLPOOL_ROUNDS] = {
    let mut rc = [0u64; WHIRLPOOL_ROUNDS];
    let mut r = 0usize;
    while r < WHIRLPOOL_ROUNDS {
        rc[r] = u64::from_be_bytes([
            WHIRLPOOL_S[8 * r],
            WHIRLPOOL_S[8 * r + 1],
            WHIRLPOOL_S[8 * r + 2],
            WHIRLPOOL_S[8 * r + 3],
            WHIRLPOOL_S[8 * r + 4],
            WHIRLPOOL_S[8 * r + 5],
            WHIRLPOOL_S[8 * r + 6],
            WHIRLPOOL_S[8 * r + 7],
        ]);
        r += 1;
    }
    rc
};

/// Extract byte at column `col` (0..8) from a big-endian `u64`.
///
/// `col = 0` returns the most-significant byte (bit positions 56..=63),
/// matching the spec's 8x8 state-matrix column ordering.
#[inline]
fn whirlpool_be_byte(word: u64, col: usize) -> u8 {
    word.to_be_bytes()[col]
}

/// Apply one Whirlpool round to the 8-word state `state`, `XORing` `rc` into
/// word 0 prior to the `MixRows` step. Returns the new 8-word state.
///
/// Implements the kernel
/// ```text
///     L[i] = (RC[r] if i==0 else 0) ^ sum_{j=0..8} C_j[ state_byte(i-j mod 8, j) ]
/// ```
/// where `state_byte(row, col)` is byte `col` of big-endian word `row` and
/// `C_j[b] = WHIRLPOOL_C0[b].rotate_right(8 * j)`.
#[inline]
fn whirlpool_round(state: &[u64; 8], rc: u64) -> [u64; 8] {
    let mut new_state = [0u64; 8];
    for i in 0..8 {
        // `row_j = (i - j) mod 8`, expressed as `(i + 8 - j) & 7` so all
        // intermediate values stay in unsigned `usize` range.
        let row0 = i & 7;
        let row1 = (i + 7) & 7;
        let row2 = (i + 6) & 7;
        let row3 = (i + 5) & 7;
        let row4 = (i + 4) & 7;
        let row5 = (i + 3) & 7;
        let row6 = (i + 2) & 7;
        let row7 = (i + 1) & 7;

        // Column-wise XOR sum.  RC is absorbed only into word 0 per the
        // Whirlpool spec's integrated key schedule.
        let mut acc = if i == 0 { rc } else { 0 };
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row0], 0))];
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row1], 1))].rotate_right(8);
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row2], 2))].rotate_right(16);
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row3], 3))].rotate_right(24);
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row4], 4))].rotate_right(32);
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row5], 5))].rotate_right(40);
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row6], 6))].rotate_right(48);
        acc ^= WHIRLPOOL_C0[usize::from(whirlpool_be_byte(state[row7], 7))].rotate_right(56);
        new_state[i] = acc;
    }
    new_state
}

/// Whirlpool block compression — processes exactly one 64-byte block.
///
/// Implements the Miyaguchi-Preneel construction over the W block cipher:
///
/// 1. Seed key schedule `K := H` and cipher state `S := H XOR block`.
/// 2. For `r` in `0..10`:
///    * `K := WhirlpoolRound(K, RC[r])`
///    * `S := WhirlpoolRound(S, 0) XOR K`
/// 3. Feedback `H := H XOR S XOR block`.
///
/// Translates `whirlpool_block_data_order` / `processBuffer` from
/// `crypto/whrlpool/wp_block.c`.
fn whirlpool_compress(h: &mut [u64; 8], block: &[u8; WHIRLPOOL_BLOCK_BYTES]) {
    // Load the 8 big-endian 64-bit block words.
    let mut block_words = [0u64; 8];
    for (i, word) in block_words.iter_mut().enumerate() {
        *word = load_be_u64(block, i * 8);
    }

    // Seed the key schedule and cipher state.
    let mut k: [u64; 8] = *h;
    let mut s: [u64; 8] = [0u64; 8];
    for i in 0..8 {
        s[i] = h[i] ^ block_words[i];
    }

    // Ten rounds with integrated key schedule.
    for r in 0..WHIRLPOOL_ROUNDS {
        let new_k = whirlpool_round(&k, WHIRLPOOL_RC[r]);
        let new_s = whirlpool_round(&s, 0);
        k = new_k;
        for i in 0..8 {
            s[i] = new_s[i] ^ k[i];
        }
    }

    // Miyaguchi-Preneel feedback: H := H XOR S XOR block.
    for i in 0..8 {
        h[i] ^= s[i] ^ block_words[i];
    }

    // Wipe transient state to reduce key/plaintext residue in case an
    // attacker recovers freed stack memory.
    k.zeroize();
    s.zeroize();
    block_words.zeroize();
}

/// Whirlpool streaming context (NESSIE / ISO/IEC 10118-3).
///
/// Reproduces the semantics of OpenSSL's `WHIRLPOOL_CTX` /
/// `WHIRLPOOL_Init` / `WHIRLPOOL_Update` / `WHIRLPOOL_Final` trio.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WhirlpoolContext {
    /// Chaining state (8 big-endian-interpreted 64-bit words). The initial
    /// value is all-zero per `WHIRLPOOL_Init`.
    h: [u64; 8],
    /// Residual buffer for partial blocks.
    block: [u8; WHIRLPOOL_BLOCK_BYTES],
    /// Number of bytes currently buffered in `block`.
    num: usize,
    /// 256-bit message bit-length counter. `bitlen[0]` is the least
    /// significant 64-bit word; `bitlen[3]` is the most significant.
    bitlen: [u64; 4],
}

impl WhirlpoolContext {
    /// Constructs a new Whirlpool context with the all-zero initial state.
    ///
    /// Matches the behaviour of OpenSSL's `WHIRLPOOL_Init`, which zeroes the
    /// entire context.
    #[deprecated(
        note = "Whirlpool is a legacy hash function; prefer SHA-256, SHA-384, SHA-512, or SHA-3 for modern designs"
    )]
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: [0u64; 8],
            block: [0u8; WHIRLPOOL_BLOCK_BYTES],
            num: 0,
            bitlen: [0u64; 4],
        }
    }

    /// Processes the currently buffered block and resets the buffer offset.
    fn compress(&mut self) {
        whirlpool_compress(&mut self.h, &self.block);
        self.num = 0;
    }
}

impl Default for WhirlpoolContext {
    fn default() -> Self {
        #[allow(deprecated)]
        Self::new()
    }
}

/// Accumulate `n_bytes * 8` bits into a 256-bit little-endian-word counter.
///
/// The counter layout matches OpenSSL's `WHIRLPOOL_CTX.bitlen` union:
/// `bitlen[0]` holds the least-significant 64 bits, `bitlen[3]` the most.
///
/// The product `n_bytes * 8` requires up to 67 bits, which this function
/// splits into a 64-bit low word and a 3-bit high word without any narrowing
/// cast, then ripples the carry through `bitlen[1..=3]`.
#[inline]
fn whirlpool_add_byte_length(bitlen: &mut [u64; 4], n_bytes: u64) {
    // Split `n_bytes * 8` into its low 64 bits and 3-bit overflow.
    let low_bits = n_bytes.wrapping_shl(3);
    let high_bits = n_bytes >> 61; // always in 0..=7

    // Add low 64 bits into `bitlen[0]` and track carry.
    let (w0, carry0) = bitlen[0].overflowing_add(low_bits);
    bitlen[0] = w0;

    // Add high 3 bits + carry into `bitlen[1]`. Each overflow contributes 1
    // to the carry propagated into `bitlen[2]` (cumulative carry max 2).
    let (tmp, carry1a) = bitlen[1].overflowing_add(high_bits);
    let (w1, carry1b) = tmp.overflowing_add(u64::from(carry0));
    bitlen[1] = w1;
    let carry_to_2 = u64::from(carry1a).wrapping_add(u64::from(carry1b));

    if carry_to_2 != 0 {
        let (w2, carry2) = bitlen[2].overflowing_add(carry_to_2);
        bitlen[2] = w2;
        if carry2 {
            // Beyond 2^256 bits — physically unreachable, wrap silently.
            bitlen[3] = bitlen[3].wrapping_add(1);
        }
    }
}

impl Digest for WhirlpoolContext {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        // Accumulate the bit-length counter (256-bit, little-endian-word).
        let len = u64::try_from(data.len())
            .map_err(|_| CryptoError::AlgorithmNotFound("length cast overflow".into()))?;
        whirlpool_add_byte_length(&mut self.bitlen, len);

        let mut rest = data;

        // Fill any existing partial block first.
        if self.num > 0 {
            let need = WHIRLPOOL_BLOCK_BYTES - self.num;
            if rest.len() < need {
                self.block[self.num..self.num + rest.len()].copy_from_slice(rest);
                self.num += rest.len();
                return Ok(());
            }
            self.block[self.num..].copy_from_slice(&rest[..need]);
            self.compress();
            rest = &rest[need..];
        }

        // Process aligned 64-byte chunks straight from the caller's buffer.
        while rest.len() >= WHIRLPOOL_BLOCK_BYTES {
            let chunk = &rest[..WHIRLPOOL_BLOCK_BYTES];
            self.block.copy_from_slice(chunk);
            whirlpool_compress(&mut self.h, &self.block);
            rest = &rest[WHIRLPOOL_BLOCK_BYTES..];
        }

        // Retain the trailing bytes for the next update / finalize call.
        if !rest.is_empty() {
            self.block[..rest.len()].copy_from_slice(rest);
            self.num = rest.len();
        }

        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Append the mandatory 0x80 marker (the single 1-bit terminator).
        self.block[self.num] = 0x80;
        self.num += 1;

        // If there is no room for the 256-bit (32-byte) length footer,
        // zero-pad the rest of this block and compress first.
        if self.num > WHIRLPOOL_BLOCK_BYTES - 32 {
            for byte in &mut self.block[self.num..] {
                *byte = 0;
            }
            self.compress();
        }

        // Zero-pad up to the length field (bytes 32..64).
        for byte in &mut self.block[self.num..WHIRLPOOL_BLOCK_BYTES - 32] {
            *byte = 0;
        }

        // Write the 256-bit bit-length in big-endian order across bytes
        // 32..64: most-significant word first, least-significant last.
        self.block[32..40].copy_from_slice(&self.bitlen[3].to_be_bytes());
        self.block[40..48].copy_from_slice(&self.bitlen[2].to_be_bytes());
        self.block[48..56].copy_from_slice(&self.bitlen[1].to_be_bytes());
        self.block[56..64].copy_from_slice(&self.bitlen[0].to_be_bytes());
        self.compress();

        // Serialize the 512-bit chaining state as 8 big-endian 64-bit words.
        let mut out = Vec::with_capacity(WHIRLPOOL_DIGEST_BYTES);
        for word in &self.h {
            out.extend_from_slice(&word.to_be_bytes());
        }

        self.reset();
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        WHIRLPOOL_DIGEST_BYTES
    }

    fn block_size(&self) -> usize {
        WHIRLPOOL_BLOCK_BYTES
    }

    fn algorithm_name(&self) -> &'static str {
        "Whirlpool"
    }

    fn reset(&mut self) {
        self.h = [0u64; 8];
        self.block.zeroize();
        self.num = 0;
        self.bitlen = [0u64; 4];
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

/// One-shot Whirlpool digest computation.
///
/// # Errors
///
/// Returns [`CryptoError`] only if the input length cannot be represented in
/// a 64-bit unsigned integer (exabyte-scale inputs on 64-bit hosts).
#[deprecated(
    note = "Whirlpool is a legacy hash function; prefer SHA-256, SHA-384, SHA-512, or SHA-3 for modern designs"
)]
pub fn whirlpool(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = WhirlpoolContext::new();
    ctx.update(data)?;
    ctx.finalize()
}


// =============================================================================
// LegacyAlgorithm Enum + Factory
// =============================================================================

/// Enumeration of all legacy (pre-SHA-2) and national-standard digest
/// algorithms implemented in this module.
///
/// Used by [`create_legacy_digest`] to construct the appropriate hash context
/// at runtime. Every variant corresponds to an algorithm that is either
/// cryptographically broken or retained only for backwards compatibility with
/// legacy protocols, file formats, or national standards. **New designs MUST
/// use SHA-256, SHA-384, SHA-512, or SHA-3 from [`super::sha`].**
///
/// # Variant naming
///
/// Variants follow the upstream OpenSSL name used on the wire and in
/// `OSSL_PARAM` dispatch tables so that provider lookups and parity tests
/// line up with the C implementation.
///
/// # Rule compliance
///
/// * **R5** — every variant is a distinct discriminant; no sentinel overloads.
/// * **R6** — enum arms carry no numeric casts.
/// * **R8** — construction is entirely safe Rust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyAlgorithm {
    /// MD2 (RFC 1319) — 128-bit Merkle-Damgård hash designed for 8-bit CPUs
    /// (**cryptographically broken**; retained only for decoding legacy
    /// certificates and PGP key rings).
    Md2,
    /// MD4 (RFC 1320) — 128-bit unkeyed hash (**cryptographically broken**;
    /// still encountered inside NTLM, S/MIME compatibility, and `NetNTLMv1`).
    Md4,
    /// MDC-2 (ISO/IEC 10118-2) — 128-bit DES-based Modification Detection
    /// Code. Retained for interoperability with legacy banking and
    /// government protocols. Requires the `DES` symmetric engine.
    #[cfg(feature = "des")]
    Mdc2,
    /// RIPEMD-160 (RFC 4231 reference; original Bosselaers/Dobbertin/Preneel
    /// design 1996) — 160-bit hash used by Bitcoin address derivation and
    /// some GPG key-ID calculations.
    Ripemd160,
    /// SM3 (GB/T 32905-2016) — 256-bit Chinese national-standard hash
    /// mandatory for GM-compliant TLS suites, SM2 signatures, and Chinese
    /// government PKI.
    Sm3,
    /// Whirlpool (NESSIE 2003, ISO/IEC 10118-3:2018) — 512-bit hash built
    /// from a dedicated 10-round block cipher with the Miyaguchi-Preneel
    /// construction.
    Whirlpool,
}

impl LegacyAlgorithm {
    /// Return the canonical textual name for this algorithm, matching the
    /// upstream OpenSSL `OSSL_DIGEST_NAME_*` macro values and the output of
    /// `EVP_MD_get0_name()`.
    ///
    /// The returned strings are intentionally stable so they can serve as
    /// `OSSL_PARAM` dispatch keys and as log/trace span attributes.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            LegacyAlgorithm::Md2 => "MD2",
            LegacyAlgorithm::Md4 => "MD4",
            #[cfg(feature = "des")]
            LegacyAlgorithm::Mdc2 => "MDC2",
            LegacyAlgorithm::Ripemd160 => "RIPEMD160",
            LegacyAlgorithm::Sm3 => "SM3",
            LegacyAlgorithm::Whirlpool => "WHIRLPOOL",
        }
    }

    /// Return the digest size in bytes.
    ///
    /// This mirrors `EVP_MD_get_size()` in upstream C and allows callers to
    /// pre-allocate output buffers without constructing a context first.
    // R9 justification: each arm is a distinct algorithm with independent
    // semantic meaning; merging arms via `|` would obscure the per-algorithm
    // dispatch and complicate future size changes (e.g., adding a hardware
    // variant with a different digest size).
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn digest_size(&self) -> usize {
        match self {
            LegacyAlgorithm::Md2 => 16,
            LegacyAlgorithm::Md4 => 16,
            #[cfg(feature = "des")]
            LegacyAlgorithm::Mdc2 => 16,
            LegacyAlgorithm::Ripemd160 => 20,
            LegacyAlgorithm::Sm3 => 32,
            LegacyAlgorithm::Whirlpool => WHIRLPOOL_DIGEST_BYTES,
        }
    }

    /// Return the compression-function block size in bytes.
    ///
    /// This mirrors `EVP_MD_get_block_size()` in upstream C. MDC-2 reports
    /// `8` because it operates on 8-byte DES blocks; all other algorithms
    /// operate on 64-byte blocks.
    // R9 justification: identical numeric block-sizes for different algorithms
    // are a coincidence of historical design, not an intrinsic identity. The
    // exhaustive per-variant arm keeps the dispatch readable and makes future
    // divergence (e.g., a hardware MDC-2 with a larger block) straightforward.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn block_size(&self) -> usize {
        match self {
            LegacyAlgorithm::Md2 => 16,
            LegacyAlgorithm::Md4 => 64,
            #[cfg(feature = "des")]
            LegacyAlgorithm::Mdc2 => 8,
            LegacyAlgorithm::Ripemd160 => 64,
            LegacyAlgorithm::Sm3 => 64,
            LegacyAlgorithm::Whirlpool => WHIRLPOOL_BLOCK_BYTES,
        }
    }
}

/// Factory function: construct a boxed [`Digest`] trait object for the given
/// legacy algorithm.
///
/// This is the runtime-dispatched entry point into the legacy hash module,
/// parallel to [`super::sha::create_sha_digest`] for modern SHA-family hashes.
/// The factory is intended for use by the provider layer
/// (`openssl-provider::implementations::digests`) and by test harnesses that
/// need to instantiate multiple algorithms from a single `match`.
///
/// Every returned context type carries a `#[deprecated]` attribute on its
/// `new()` constructor; the `#[allow(deprecated)]` on this function
/// propagates to cover all match arms so that callers do not need to
/// sprinkle local allow-attributes at each call site.
///
/// Emits a `tracing::trace!` span attribute for AAP §0.8.5 observability so
/// operators can correlate algorithm selection with upstream requests.
///
/// # Errors
///
/// This function currently handles every [`LegacyAlgorithm`] variant and
/// therefore never returns an error. The `CryptoResult` return type is
/// preserved for forward-compatibility with future variants that might
/// require a feature gate (e.g., a hardware-backed MDC-2) and for ABI
/// consistency with [`super::sha::create_sha_digest`].
///
/// # Examples
///
/// ```no_run
/// use openssl_crypto::hash::legacy::{create_legacy_digest, LegacyAlgorithm};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut ctx = create_legacy_digest(LegacyAlgorithm::Sm3)?;
/// ctx.update(b"abc")?;
/// let digest = ctx.finalize()?;
/// assert_eq!(digest.len(), 32);
/// # Ok(())
/// # }
/// ```
#[allow(deprecated)]
pub fn create_legacy_digest(alg: LegacyAlgorithm) -> CryptoResult<Box<dyn Digest>> {
    tracing::trace!(algorithm = %alg.name(), "Creating legacy digest context");
    match alg {
        LegacyAlgorithm::Md2 => Ok(Box::new(Md2Context::new())),
        LegacyAlgorithm::Md4 => Ok(Box::new(Md4Context::new())),
        #[cfg(feature = "des")]
        LegacyAlgorithm::Mdc2 => Ok(Box::new(Mdc2Context::new())),
        LegacyAlgorithm::Ripemd160 => Ok(Box::new(Ripemd160Context::new())),
        LegacyAlgorithm::Sm3 => Ok(Box::new(Sm3Context::new())),
        LegacyAlgorithm::Whirlpool => Ok(Box::new(WhirlpoolContext::new())),
    }
}


// =============================================================================
// Unit tests — RFC / ISO / NIST / NESSIE / GB/T test vectors
// =============================================================================
//
// Test vector provenance:
//   * MD2         — RFC 1319 Appendix A.5.
//   * MD4         — RFC 1320 Appendix A.5.
//   * MDC-2       — OpenSSL upstream `test/mdc2test.c` (pad_type 1 — the
//                    default padding exposed by `EVP_mdc2()`).
//   * RIPEMD-160  — Dobbertin/Bosselaers/Preneel reference paper (1996);
//                    ISO/IEC 10118-3:2018 Table B.3.
//   * SM3         — GB/T 32905-2016 Appendix A; GM/T 0004-2012.
//   * Whirlpool   — NESSIE test vectors (2003, Barreto/Rijmen reference
//                    implementation); ISO/IEC 10118-3:2018 Table B.7.
//
// Every test drives both the one-shot convenience functions and the
// incremental `Context` types through `super::*`. A single module-level
// `#[allow(deprecated)]` covers the `#[deprecated]` `new()` constructors and
// one-shot helpers, matching the precedent in [`super::md5`] tests (see
// `crates/openssl-crypto/src/hash/md5.rs` tests).
//
// R9 JUSTIFICATION for the additional clippy allows on this test module:
//
//   The `openssl-crypto` crate root denies `clippy::unwrap_used`,
//   `clippy::expect_used`, and `clippy::panic` to enforce explicit error
//   propagation throughout production code. Test modules, however,
//   legitimately rely on `.unwrap()` / `.expect("…")` / `panic!(…)` to fail
//   the test harness concisely when an assertion pre-condition cannot be met
//   (e.g., a one-shot digest helper that *must* succeed on a fixed known-good
//   input). Per the explicit guidance in
//   `crates/openssl-crypto/src/lib.rs` lines 154-157:
//
//       "Test modules that legitimately need `.unwrap()` / `.expect()` /
//        `panic!()` must add a targeted `#[allow(clippy::unwrap_used,
//        clippy::expect_used, clippy::panic)]` at the module or function
//        level with a justification comment — NOT at the crate root."
//
//   This module-scoped allow is therefore the sanctioned pattern.

#[cfg(test)]
#[allow(
    deprecated,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    /// Format a byte slice as lowercase hex for comparison with canonical
    /// published test vectors.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // -------------------------------------------------------------------------
    // MD2 — RFC 1319 Appendix A.5
    // -------------------------------------------------------------------------

    #[test]
    fn md2_rfc1319_empty_string() {
        let out = md2(b"").expect("MD2 one-shot must succeed");
        assert_eq!(hex(&out), "8350e5a3e24c153df2275c9f80692773");
        assert_eq!(out.len(), MD2_DIGEST_BYTES);
    }

    #[test]
    fn md2_rfc1319_single_a() {
        let out = md2(b"a").expect("MD2 one-shot must succeed");
        assert_eq!(hex(&out), "32ec01ec4a6dac72c0ab96fb34c0b5d1");
    }

    #[test]
    fn md2_rfc1319_abc() {
        let out = md2(b"abc").expect("MD2 one-shot must succeed");
        assert_eq!(hex(&out), "da853b0d3f88d99b30283a69e6ded6bb");
    }

    #[test]
    fn md2_rfc1319_message_digest() {
        let out = md2(b"message digest").expect("MD2 one-shot must succeed");
        assert_eq!(hex(&out), "ab4f496bfb2a530b219ff33031fe06b0");
    }

    #[test]
    fn md2_rfc1319_alphabet() {
        let out = md2(b"abcdefghijklmnopqrstuvwxyz").expect("MD2 one-shot must succeed");
        assert_eq!(hex(&out), "4e8ddff3650292ab5a4108c3aa47940b");
    }

    #[test]
    fn md2_streaming_matches_oneshot() {
        let data: Vec<u8> = (0..=100u8).collect();
        let mut ctx = Md2Context::new();
        for chunk in data.chunks(7) {
            ctx.update(chunk).expect("MD2 update must succeed");
        }
        let streamed = ctx.finalize().expect("MD2 finalize must succeed");
        let oneshot = md2(&data).expect("MD2 one-shot must succeed");
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn md2_default_matches_new() {
        let mut a = Md2Context::default();
        let mut b = Md2Context::new();
        a.update(b"abc").expect("update must succeed");
        b.update(b"abc").expect("update must succeed");
        assert_eq!(
            a.finalize().expect("finalize must succeed"),
            b.finalize().expect("finalize must succeed")
        );
    }

    #[test]
    fn md2_reset_restores_initial_state() {
        let mut ctx = Md2Context::new();
        ctx.update(b"contaminated input").expect("update must succeed");
        ctx.reset();
        ctx.update(b"abc").expect("update must succeed");
        assert_eq!(
            hex(&ctx.finalize().expect("finalize must succeed")),
            "da853b0d3f88d99b30283a69e6ded6bb"
        );
    }

    #[test]
    fn md2_context_metadata() {
        let ctx = Md2Context::new();
        assert_eq!(ctx.digest_size(), MD2_DIGEST_BYTES);
        assert_eq!(ctx.block_size(), MD2_BLOCK_BYTES);
        assert_eq!(ctx.algorithm_name(), "MD2");
    }

    // -------------------------------------------------------------------------
    // MD4 — RFC 1320 Appendix A.5
    // -------------------------------------------------------------------------

    #[test]
    fn md4_rfc1320_empty_string() {
        let out = md4(b"").expect("MD4 one-shot must succeed");
        assert_eq!(hex(&out), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(out.len(), MD4_DIGEST_BYTES);
    }

    #[test]
    fn md4_rfc1320_single_a() {
        let out = md4(b"a").expect("MD4 one-shot must succeed");
        assert_eq!(hex(&out), "bde52cb31de33e46245e05fbdbd6fb24");
    }

    #[test]
    fn md4_rfc1320_abc() {
        let out = md4(b"abc").expect("MD4 one-shot must succeed");
        assert_eq!(hex(&out), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn md4_rfc1320_message_digest() {
        let out = md4(b"message digest").expect("MD4 one-shot must succeed");
        assert_eq!(hex(&out), "d9130a8164549fe818874806e1c7014b");
    }

    #[test]
    fn md4_rfc1320_alphabet() {
        let out = md4(b"abcdefghijklmnopqrstuvwxyz").expect("MD4 one-shot must succeed");
        assert_eq!(hex(&out), "d79e1c308aa5bbcdeea8ed63df412da9");
    }

    #[test]
    fn md4_streaming_matches_oneshot() {
        let data: Vec<u8> = (0..=200u8).collect();
        let mut ctx = Md4Context::new();
        for chunk in data.chunks(13) {
            ctx.update(chunk).expect("MD4 update must succeed");
        }
        let streamed = ctx.finalize().expect("MD4 finalize must succeed");
        let oneshot = md4(&data).expect("MD4 one-shot must succeed");
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn md4_block_boundary_55_bytes() {
        // 55 bytes: the 0x80 pad byte + 64-bit length = 9 bytes fit into the
        // first (and only) 64-byte block — no spillover.
        let input = [0x61u8; 55];
        let out = md4(&input).expect("MD4 one-shot must succeed");
        assert_eq!(out.len(), MD4_DIGEST_BYTES);
    }

    #[test]
    fn md4_block_boundary_56_bytes() {
        // 56 bytes: the 0x80 pad + 64-bit length does NOT fit in the first
        // block → spills to a second block.
        let input = [0x61u8; 56];
        let out = md4(&input).expect("MD4 one-shot must succeed");
        assert_eq!(out.len(), MD4_DIGEST_BYTES);
    }

    #[test]
    fn md4_block_boundary_64_bytes() {
        let input = [0x61u8; 64];
        let out = md4(&input).expect("MD4 one-shot must succeed");
        assert_eq!(out.len(), MD4_DIGEST_BYTES);
    }

    #[test]
    fn md4_default_matches_new() {
        let mut a = Md4Context::default();
        let mut b = Md4Context::new();
        a.update(b"test").expect("update must succeed");
        b.update(b"test").expect("update must succeed");
        assert_eq!(
            a.finalize().expect("finalize must succeed"),
            b.finalize().expect("finalize must succeed")
        );
    }

    #[test]
    fn md4_reset_restores_initial_state() {
        let mut ctx = Md4Context::new();
        ctx.update(b"bogus seed").expect("update must succeed");
        ctx.reset();
        ctx.update(b"abc").expect("update must succeed");
        assert_eq!(
            hex(&ctx.finalize().expect("finalize must succeed")),
            "a448017aaf21d8525fc10ae87aa6729d"
        );
    }

    #[test]
    fn md4_context_metadata() {
        let ctx = Md4Context::new();
        assert_eq!(ctx.digest_size(), MD4_DIGEST_BYTES);
        assert_eq!(ctx.block_size(), MD4_BLOCK_BYTES);
        assert_eq!(ctx.algorithm_name(), "MD4");
    }

    // -------------------------------------------------------------------------
    // MDC-2 — OpenSSL upstream `test/mdc2test.c` (pad_type 1, the default)
    // -------------------------------------------------------------------------

    #[cfg(feature = "des")]
    #[test]
    fn mdc2_openssl_pad1_reference() {
        // Input: "Now is the time for all " (24 bytes, note trailing space).
        // Reference vector from OpenSSL's `test/mdc2test.c` pad1 (default).
        let out = mdc2(b"Now is the time for all ").expect("MDC-2 one-shot must succeed");
        assert_eq!(hex(&out), "42e50cd224baceba760bdd2bd409281a");
        assert_eq!(out.len(), MDC2_DIGEST_BYTES);
    }

    #[cfg(feature = "des")]
    #[test]
    fn mdc2_streaming_matches_oneshot() {
        let input: &[u8] = b"Now is the time for all ";
        let mut ctx = Mdc2Context::new();
        for chunk in input.chunks(3) {
            ctx.update(chunk).expect("MDC-2 update must succeed");
        }
        let streamed = ctx.finalize().expect("MDC-2 finalize must succeed");
        let oneshot = mdc2(input).expect("MDC-2 one-shot must succeed");
        assert_eq!(streamed, oneshot);
    }

    #[cfg(feature = "des")]
    #[test]
    fn mdc2_default_matches_new_metadata() {
        // Internal IVs are not externally observable, so compare metadata as
        // a structural sanity check between `Default::default()` and `new()`.
        let a = Mdc2Context::default();
        let b = Mdc2Context::new();
        assert_eq!(a.digest_size(), b.digest_size());
        assert_eq!(a.block_size(), b.block_size());
        assert_eq!(a.algorithm_name(), b.algorithm_name());
    }

    #[cfg(feature = "des")]
    #[test]
    fn mdc2_reset_restores_initial_state() {
        let mut ctx = Mdc2Context::new();
        ctx.update(b"before reset").expect("update must succeed");
        ctx.reset();
        ctx.update(b"Now is the time for all ")
            .expect("update must succeed");
        assert_eq!(
            hex(&ctx.finalize().expect("finalize must succeed")),
            "42e50cd224baceba760bdd2bd409281a"
        );
    }

    #[cfg(feature = "des")]
    #[test]
    fn mdc2_context_metadata() {
        let ctx = Mdc2Context::new();
        assert_eq!(ctx.digest_size(), MDC2_DIGEST_BYTES);
        assert_eq!(ctx.block_size(), MDC2_BLOCK_BYTES);
        assert_eq!(ctx.algorithm_name(), "MDC-2");
    }

    // -------------------------------------------------------------------------
    // RIPEMD-160 — Dobbertin/Bosselaers/Preneel original paper
    // -------------------------------------------------------------------------

    #[test]
    fn ripemd160_empty_string() {
        let out = ripemd160(b"").expect("RIPEMD-160 one-shot must succeed");
        assert_eq!(hex(&out), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        assert_eq!(out.len(), RIPEMD160_DIGEST_BYTES);
    }

    #[test]
    fn ripemd160_single_a() {
        let out = ripemd160(b"a").expect("RIPEMD-160 one-shot must succeed");
        assert_eq!(hex(&out), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    }

    #[test]
    fn ripemd160_abc() {
        let out = ripemd160(b"abc").expect("RIPEMD-160 one-shot must succeed");
        assert_eq!(hex(&out), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    }

    #[test]
    fn ripemd160_message_digest() {
        let out = ripemd160(b"message digest").expect("RIPEMD-160 one-shot must succeed");
        assert_eq!(hex(&out), "5d0689ef49d2fae572b881b123a85ffa21595f36");
    }

    #[test]
    fn ripemd160_alphabet() {
        let out =
            ripemd160(b"abcdefghijklmnopqrstuvwxyz").expect("RIPEMD-160 one-shot must succeed");
        assert_eq!(hex(&out), "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    }

    #[test]
    fn ripemd160_streaming_matches_oneshot() {
        let data: Vec<u8> = (0..=200u8).collect();
        let mut ctx = Ripemd160Context::new();
        for chunk in data.chunks(11) {
            ctx.update(chunk).expect("RIPEMD-160 update must succeed");
        }
        let streamed = ctx.finalize().expect("RIPEMD-160 finalize must succeed");
        let oneshot = ripemd160(&data).expect("RIPEMD-160 one-shot must succeed");
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn ripemd160_default_matches_new() {
        let mut a = Ripemd160Context::default();
        let mut b = Ripemd160Context::new();
        a.update(b"abc").expect("update must succeed");
        b.update(b"abc").expect("update must succeed");
        assert_eq!(
            a.finalize().expect("finalize must succeed"),
            b.finalize().expect("finalize must succeed")
        );
    }

    #[test]
    fn ripemd160_reset_restores_initial_state() {
        let mut ctx = Ripemd160Context::new();
        ctx.update(b"bogus seed").expect("update must succeed");
        ctx.reset();
        ctx.update(b"abc").expect("update must succeed");
        assert_eq!(
            hex(&ctx.finalize().expect("finalize must succeed")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn ripemd160_context_metadata() {
        let ctx = Ripemd160Context::new();
        assert_eq!(ctx.digest_size(), RIPEMD160_DIGEST_BYTES);
        assert_eq!(ctx.block_size(), RIPEMD160_BLOCK_BYTES);
        assert_eq!(ctx.algorithm_name(), "RIPEMD-160");
    }

    // -------------------------------------------------------------------------
    // SM3 — GB/T 32905-2016 Appendix A
    // -------------------------------------------------------------------------

    #[test]
    fn sm3_gbt_abc() {
        let out = sm3(b"abc").expect("SM3 one-shot must succeed");
        assert_eq!(
            hex(&out),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
        assert_eq!(out.len(), SM3_DIGEST_BYTES);
    }

    #[test]
    fn sm3_gbt_64byte_abcd_pattern() {
        // 64-byte input "abcd" × 16 — reference vector from GB/T 32905-2016.
        let input =
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let out = sm3(input).expect("SM3 one-shot must succeed");
        assert_eq!(
            hex(&out),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        );
    }

    #[test]
    fn sm3_streaming_matches_oneshot() {
        let data: Vec<u8> = (0..=200u8).collect();
        let mut ctx = Sm3Context::new();
        for chunk in data.chunks(9) {
            ctx.update(chunk).expect("SM3 update must succeed");
        }
        let streamed = ctx.finalize().expect("SM3 finalize must succeed");
        let oneshot = sm3(&data).expect("SM3 one-shot must succeed");
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn sm3_default_matches_new() {
        let mut a = Sm3Context::default();
        let mut b = Sm3Context::new();
        a.update(b"abc").expect("update must succeed");
        b.update(b"abc").expect("update must succeed");
        assert_eq!(
            a.finalize().expect("finalize must succeed"),
            b.finalize().expect("finalize must succeed")
        );
    }

    #[test]
    fn sm3_reset_restores_initial_state() {
        let mut ctx = Sm3Context::new();
        ctx.update(b"bogus seed").expect("update must succeed");
        ctx.reset();
        ctx.update(b"abc").expect("update must succeed");
        assert_eq!(
            hex(&ctx.finalize().expect("finalize must succeed")),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    #[test]
    fn sm3_context_metadata() {
        let ctx = Sm3Context::new();
        assert_eq!(ctx.digest_size(), SM3_DIGEST_BYTES);
        assert_eq!(ctx.block_size(), SM3_BLOCK_BYTES);
        assert_eq!(ctx.algorithm_name(), "SM3");
    }

    // -------------------------------------------------------------------------
    // Whirlpool — NESSIE test vectors / ISO/IEC 10118-3:2018 Table B.7
    // -------------------------------------------------------------------------

    #[test]
    fn whirlpool_empty_string() {
        let out = whirlpool(b"").expect("Whirlpool one-shot must succeed");
        assert_eq!(
            hex(&out),
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
             3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
        );
        assert_eq!(out.len(), WHIRLPOOL_DIGEST_BYTES);
    }

    #[test]
    fn whirlpool_single_a() {
        let out = whirlpool(b"a").expect("Whirlpool one-shot must succeed");
        assert_eq!(
            hex(&out),
            "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42\
             d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a"
        );
    }

    #[test]
    fn whirlpool_abc() {
        let out = whirlpool(b"abc").expect("Whirlpool one-shot must succeed");
        assert_eq!(
            hex(&out),
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
             7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
        );
    }

    #[test]
    fn whirlpool_message_digest() {
        let out = whirlpool(b"message digest").expect("Whirlpool one-shot must succeed");
        assert_eq!(
            hex(&out),
            "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b\
             8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e"
        );
    }

    #[test]
    fn whirlpool_streaming_matches_oneshot() {
        let data: Vec<u8> = (0..=255u8).collect();
        let mut ctx = WhirlpoolContext::new();
        for chunk in data.chunks(17) {
            ctx.update(chunk).expect("Whirlpool update must succeed");
        }
        let streamed = ctx.finalize().expect("Whirlpool finalize must succeed");
        let oneshot = whirlpool(&data).expect("Whirlpool one-shot must succeed");
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn whirlpool_default_matches_new() {
        let mut a = WhirlpoolContext::default();
        let mut b = WhirlpoolContext::new();
        a.update(b"abc").expect("update must succeed");
        b.update(b"abc").expect("update must succeed");
        assert_eq!(
            a.finalize().expect("finalize must succeed"),
            b.finalize().expect("finalize must succeed")
        );
    }

    #[test]
    fn whirlpool_reset_restores_initial_state() {
        let mut ctx = WhirlpoolContext::new();
        ctx.update(b"bogus seed").expect("update must succeed");
        ctx.reset();
        ctx.update(b"abc").expect("update must succeed");
        assert_eq!(
            hex(&ctx.finalize().expect("finalize must succeed")),
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
             7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
        );
    }

    #[test]
    fn whirlpool_context_metadata() {
        let ctx = WhirlpoolContext::new();
        assert_eq!(ctx.digest_size(), WHIRLPOOL_DIGEST_BYTES);
        assert_eq!(ctx.block_size(), WHIRLPOOL_BLOCK_BYTES);
        assert_eq!(ctx.algorithm_name(), "Whirlpool");
    }

    // -------------------------------------------------------------------------
    // `LegacyAlgorithm` enum — `name()` / `digest_size()` / `block_size()`
    // -------------------------------------------------------------------------
    //
    // Note: `LegacyAlgorithm::name()` returns the OSSL canonical names
    // (`"MDC2"`, `"RIPEMD160"`, `"WHIRLPOOL"`) used for provider-dispatch
    // table lookup. This intentionally differs from `Digest::algorithm_name()`
    // returned from the concrete context types (`"MDC-2"`, `"RIPEMD-160"`,
    // `"Whirlpool"`). Both paths are tested separately to prevent accidental
    // conflation of the two name spaces during refactors.

    #[test]
    fn legacy_algorithm_names_match_ossl_canonical() {
        assert_eq!(LegacyAlgorithm::Md2.name(), "MD2");
        assert_eq!(LegacyAlgorithm::Md4.name(), "MD4");
        #[cfg(feature = "des")]
        assert_eq!(LegacyAlgorithm::Mdc2.name(), "MDC2");
        assert_eq!(LegacyAlgorithm::Ripemd160.name(), "RIPEMD160");
        assert_eq!(LegacyAlgorithm::Sm3.name(), "SM3");
        assert_eq!(LegacyAlgorithm::Whirlpool.name(), "WHIRLPOOL");
    }

    #[test]
    fn legacy_algorithm_digest_sizes() {
        assert_eq!(LegacyAlgorithm::Md2.digest_size(), MD2_DIGEST_BYTES);
        assert_eq!(LegacyAlgorithm::Md4.digest_size(), MD4_DIGEST_BYTES);
        #[cfg(feature = "des")]
        assert_eq!(LegacyAlgorithm::Mdc2.digest_size(), MDC2_DIGEST_BYTES);
        assert_eq!(
            LegacyAlgorithm::Ripemd160.digest_size(),
            RIPEMD160_DIGEST_BYTES
        );
        assert_eq!(LegacyAlgorithm::Sm3.digest_size(), SM3_DIGEST_BYTES);
        assert_eq!(
            LegacyAlgorithm::Whirlpool.digest_size(),
            WHIRLPOOL_DIGEST_BYTES
        );
    }

    #[test]
    fn legacy_algorithm_block_sizes() {
        assert_eq!(LegacyAlgorithm::Md2.block_size(), MD2_BLOCK_BYTES);
        assert_eq!(LegacyAlgorithm::Md4.block_size(), MD4_BLOCK_BYTES);
        #[cfg(feature = "des")]
        assert_eq!(LegacyAlgorithm::Mdc2.block_size(), MDC2_BLOCK_BYTES);
        assert_eq!(
            LegacyAlgorithm::Ripemd160.block_size(),
            RIPEMD160_BLOCK_BYTES
        );
        assert_eq!(LegacyAlgorithm::Sm3.block_size(), SM3_BLOCK_BYTES);
        assert_eq!(
            LegacyAlgorithm::Whirlpool.block_size(),
            WHIRLPOOL_BLOCK_BYTES
        );
    }

    #[test]
    fn legacy_algorithm_equality_and_copy() {
        let a = LegacyAlgorithm::Sm3;
        // Copy semantics: `a` must still be usable after assignment.
        let b = a;
        assert_eq!(a, b);
        // Distinct variants are unequal.
        assert_ne!(LegacyAlgorithm::Md2, LegacyAlgorithm::Md4);
        #[cfg(feature = "des")]
        assert_ne!(LegacyAlgorithm::Mdc2, LegacyAlgorithm::Ripemd160);
    }

    // -------------------------------------------------------------------------
    // `create_legacy_digest` factory — exhaustive variant coverage
    // -------------------------------------------------------------------------

    #[test]
    fn factory_md2_produces_correct_digest() {
        let mut ctx = create_legacy_digest(LegacyAlgorithm::Md2).expect("factory must succeed");
        ctx.update(b"abc").expect("update must succeed");
        let out = ctx.finalize().expect("finalize must succeed");
        assert_eq!(hex(&out), "da853b0d3f88d99b30283a69e6ded6bb");
        assert_eq!(out.len(), LegacyAlgorithm::Md2.digest_size());
    }

    #[test]
    fn factory_md4_produces_correct_digest() {
        let mut ctx = create_legacy_digest(LegacyAlgorithm::Md4).expect("factory must succeed");
        ctx.update(b"abc").expect("update must succeed");
        let out = ctx.finalize().expect("finalize must succeed");
        assert_eq!(hex(&out), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(out.len(), LegacyAlgorithm::Md4.digest_size());
    }

    #[cfg(feature = "des")]
    #[test]
    fn factory_mdc2_produces_correct_digest() {
        let mut ctx = create_legacy_digest(LegacyAlgorithm::Mdc2).expect("factory must succeed");
        ctx.update(b"Now is the time for all ")
            .expect("update must succeed");
        let out = ctx.finalize().expect("finalize must succeed");
        assert_eq!(hex(&out), "42e50cd224baceba760bdd2bd409281a");
        assert_eq!(out.len(), LegacyAlgorithm::Mdc2.digest_size());
    }

    #[test]
    fn factory_ripemd160_produces_correct_digest() {
        let mut ctx =
            create_legacy_digest(LegacyAlgorithm::Ripemd160).expect("factory must succeed");
        ctx.update(b"abc").expect("update must succeed");
        let out = ctx.finalize().expect("finalize must succeed");
        assert_eq!(hex(&out), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        assert_eq!(out.len(), LegacyAlgorithm::Ripemd160.digest_size());
    }

    #[test]
    fn factory_sm3_produces_correct_digest() {
        let mut ctx = create_legacy_digest(LegacyAlgorithm::Sm3).expect("factory must succeed");
        ctx.update(b"abc").expect("update must succeed");
        let out = ctx.finalize().expect("finalize must succeed");
        assert_eq!(
            hex(&out),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
        assert_eq!(out.len(), LegacyAlgorithm::Sm3.digest_size());
    }

    #[test]
    fn factory_whirlpool_produces_correct_digest() {
        let mut ctx =
            create_legacy_digest(LegacyAlgorithm::Whirlpool).expect("factory must succeed");
        ctx.update(b"abc").expect("update must succeed");
        let out = ctx.finalize().expect("finalize must succeed");
        assert_eq!(
            hex(&out),
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
             7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
        );
        assert_eq!(out.len(), LegacyAlgorithm::Whirlpool.digest_size());
    }

    #[test]
    fn factory_digest_method_roundtrips_for_all_variants() {
        // `Digest::digest()` is a default-provided trait method (it resets,
        // updates, and finalizes in one call). We verify it works correctly
        // through the `Box<dyn Digest>` fat pointer returned by the factory.
        //
        // We use a `Vec` (rather than a fixed-size array) and `#[cfg]` on the
        // MDC-2 element so the MDC-2 entry is included only when the `des`
        // feature is enabled (MDC-2 is implemented on top of the DES block
        // cipher and therefore requires the `des` feature to be available).
        let variants: Vec<(LegacyAlgorithm, &[u8], &str)> = vec![
            (
                LegacyAlgorithm::Md2,
                b"abc",
                "da853b0d3f88d99b30283a69e6ded6bb",
            ),
            (
                LegacyAlgorithm::Md4,
                b"abc",
                "a448017aaf21d8525fc10ae87aa6729d",
            ),
            #[cfg(feature = "des")]
            (
                LegacyAlgorithm::Mdc2,
                b"Now is the time for all ",
                "42e50cd224baceba760bdd2bd409281a",
            ),
            (
                LegacyAlgorithm::Ripemd160,
                b"abc",
                "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            ),
            (
                LegacyAlgorithm::Sm3,
                b"abc",
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            ),
        ];
        for (alg, input, expected) in variants {
            let mut ctx = create_legacy_digest(alg).expect("factory must succeed");
            let out = ctx.digest(input).expect("digest must succeed");
            assert_eq!(hex(&out), expected, "factory digest mismatch for {alg:?}");
        }
    }

    #[test]
    fn factory_metadata_matches_concrete_contexts() {
        // We use a `Vec` (rather than a fixed-size array) and `#[cfg]` on the
        // MDC-2 element so the MDC-2 variant is included only when the `des`
        // feature is enabled (MDC-2 is implemented on top of the DES block
        // cipher and therefore requires the `des` feature to be available).
        let algs: Vec<LegacyAlgorithm> = vec![
            LegacyAlgorithm::Md2,
            LegacyAlgorithm::Md4,
            #[cfg(feature = "des")]
            LegacyAlgorithm::Mdc2,
            LegacyAlgorithm::Ripemd160,
            LegacyAlgorithm::Sm3,
            LegacyAlgorithm::Whirlpool,
        ];
        for alg in algs {
            let ctx = create_legacy_digest(alg).expect("factory must succeed");
            assert_eq!(
                ctx.digest_size(),
                alg.digest_size(),
                "digest_size mismatch for {alg:?}"
            );
            assert_eq!(
                ctx.block_size(),
                alg.block_size(),
                "block_size mismatch for {alg:?}"
            );
        }
    }

    #[test]
    fn factory_covers_all_enum_variants() {
        // This test will break compilation if a new `LegacyAlgorithm` variant
        // is added without an accompanying arm in `create_legacy_digest`.
        // Match exhaustiveness is enforced at the call site.
        //
        // We use a `Vec` (rather than a fixed-size array) and `#[cfg]` on the
        // MDC-2 element so the MDC-2 variant is included only when the `des`
        // feature is enabled (MDC-2 is implemented on top of the DES block
        // cipher and therefore requires the `des` feature to be available).
        let algs: Vec<LegacyAlgorithm> = vec![
            LegacyAlgorithm::Md2,
            LegacyAlgorithm::Md4,
            #[cfg(feature = "des")]
            LegacyAlgorithm::Mdc2,
            LegacyAlgorithm::Ripemd160,
            LegacyAlgorithm::Sm3,
            LegacyAlgorithm::Whirlpool,
        ];
        for alg in algs {
            assert!(
                create_legacy_digest(alg).is_ok(),
                "factory must accept variant {alg:?}"
            );
        }
    }
}

