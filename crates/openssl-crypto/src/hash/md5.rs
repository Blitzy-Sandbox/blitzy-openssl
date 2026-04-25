//! MD5 message digest implementation (RFC 1321).
//!
//! # Security Warning
//!
//! **MD5 is cryptographically broken and MUST NOT be used for security-sensitive
//! applications.** It is retained for backward compatibility with legacy
//! protocols (`SSLv3`, TLS 1.0/1.1 with the MD5+SHA-1 composite digest, PKCS#1 v1.5
//! signatures over legacy certificates, etc.).
//!
//! This module translates the C implementation from `crypto/md5/*.c`
//! (`md5_dgst.c`, `md5_local.h`, `md5_one.c`, `md5_sha1.c`, `md5_riscv.c`)
//! into a pure-Rust, `#[forbid(unsafe_code)]`-compatible implementation.
//!
//! # Design Notes
//!
//! * MD5 is **little-endian** (unlike SHA-1/SHA-256 which are big-endian):
//!   message words are loaded via [`u32::from_le_bytes`], the digest is
//!   serialised via [`u32::to_le_bytes`], and the 64-bit message-length
//!   trailer is appended as little-endian.
//! * All digest APIs return [`CryptoResult<Vec<u8>>`] per Rule R5 — no sentinel
//!   return values.
//! * All context types derive [`Zeroize`]/[`ZeroizeOnDrop`] for secure erasure
//!   of cryptographic state (replacing the C `OPENSSL_cleanse()` calls from
//!   `crypto/md5/md5_one.c`).
//! * All arithmetic uses [`u32::wrapping_add`] / [`u32::rotate_left`] /
//!   [`u64::checked_add`] / [`u64::checked_mul`] — no bare `as` narrowing
//!   casts per Rule R6.
//! * No `unsafe` is used anywhere in this module (Rule R8).
//!
//! # MD5 Algorithm Summary (RFC 1321)
//!
//! * Block size: 64 bytes (512 bits)
//! * Output size: 16 bytes (128 bits)
//! * State: four 32-bit chaining variables (A, B, C, D)
//! * Compression function: 64 steps divided into 4 rounds of 16, each using
//!   a different non-linear boolean function (F, G, H, I) and a per-step
//!   additive constant from the `T` table (`floor(2^32 * abs(sin(i + 1)))`).

// MD5 round constants (T-table) and IV constants are written exactly as they
// appear in RFC 1321 / the C source without underscore separators to facilitate
// direct cross-reference.
#![allow(clippy::unreadable_literal)]
// The compression function uses single-character working variables (a, b, c, d)
// that correspond directly to the RFC 1321 specification notation.
#![allow(clippy::many_single_char_names)]
// Index-based iteration inside the compression function mirrors the C reference
// layout (four rounds of 16 steps each) and the RFC pseudocode.
#![allow(clippy::needless_range_loop)]

use openssl_common::{CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::sha::{Digest, Sha1Context};

// =============================================================================
// MD5 Constants (RFC 1321 / crypto/md5/md5_dgst.c)
// =============================================================================

/// MD5 initial chaining values A0..D0 (RFC 1321 §3.3).
///
/// Matches `INIT_DATA_A..INIT_DATA_D` from `crypto/md5/md5_dgst.c`:
/// ```text
/// A = 0x67452301   B = 0xefcdab89
/// C = 0x98badcfe   D = 0x10325476
/// ```
const MD5_IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// MD5 block size in bytes (`MD5_CBLOCK` in C).
const MD5_CBLOCK: usize = 64;

/// MD5 digest length in bytes (`MD5_DIGEST_LENGTH` in C).
const MD5_DIGEST_LENGTH: usize = 16;

// =============================================================================
// Little-endian helper (MD5 uses little-endian byte order, unlike SHA-2)
// =============================================================================

/// Load a little-endian `u32` from `data` at the given byte offset.
///
/// Used by the MD5 compression function to convert the 64-byte input block
/// into 16 little-endian 32-bit words (corresponds to `HOST_c2l` with
/// `DATA_ORDER_IS_LITTLE_ENDIAN` defined in `crypto/md5/md5_local.h`).
#[inline]
fn load_le_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

// =============================================================================
// MD5 Boolean Functions (Wei Dai / Peter Gutmann / Rich Schroeppel forms)
//
// These are the optimised equivalents of the RFC 1321 definitions:
//   F(x,y,z) = (x & y) | (~x & z)   -->  ((y ^ z) & x) ^ z
//   G(x,y,z) = (x & z) | (y & ~z)   -->  ((x ^ y) & z) ^ y
//   H(x,y,z) = x ^ y ^ z
//   I(x,y,z) = y ^ (x | ~z)         -->  (!z | x) ^ y
//
// The optimised forms match `F`, `G`, `H`, `I` macros in
// `crypto/md5/md5_local.h` (lines 61-64).
// =============================================================================

#[inline]
fn md5_f(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}

#[inline]
fn md5_g(b: u32, c: u32, d: u32) -> u32 {
    ((b ^ c) & d) ^ c
}

#[inline]
fn md5_h(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

#[inline]
fn md5_i(b: u32, c: u32, d: u32) -> u32 {
    (!d | b) ^ c
}

// =============================================================================
// MD5 Compression Function
//
// Processes a single 64-byte block and updates the chaining state. The C
// reference fully unrolls all 64 steps (see `crypto/md5/md5_dgst.c` lines
// 62-168). The Rust version preserves that unrolled structure to keep the
// per-step additive constants (T-table) and rotation amounts directly
// inline-verifiable against RFC 1321 Appendix A.3.
//
// Round 0 (F, rot {7,12,17,22}): X indices 0..15 in natural order.
// Round 1 (G, rot {5, 9,14,20}): X indices (1,6,11,0, 5,10,15,4,
//                                             9,14, 3,8, 13, 2, 7,12).
// Round 2 (H, rot {4,11,16,23}): X indices (5,8,11,14, 1,4, 7,10,
//                                            13,0, 3, 6,  9,12,15, 2).
// Round 3 (I, rot {6,10,15,21}): X indices (0,7,14, 5, 12,3,10, 1,
//                                             8,15, 6,13,  4,11, 2, 9).
// =============================================================================

/// MD5 compression function: one 64-byte block, 64 steps (4 rounds × 16).
///
/// Implements `md5_block_data_order()` (for `num == 1` block) from
/// `crypto/md5/md5_dgst.c` in pure Rust using
/// [`u32::wrapping_add`] / [`u32::rotate_left`] for the modular-arithmetic
/// round semantics. All constants are taken verbatim from the C source.
fn md5_compress(state: &mut [u32; 4], block: &[u8]) {
    debug_assert!(block.len() >= MD5_CBLOCK);

    // Load 16 little-endian 32-bit words from the input block.
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = load_le_u32(block, i * 4);
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

    // -------- Round 0 (F, rotations 7, 12, 17, 22) --------
    // R0(a, b, c, d, X[k], s, T): a = b + ((a + F(b,c,d) + X[k] + T) <<< s)
    a = b.wrapping_add(
        a.wrapping_add(md5_f(b, c, d))
            .wrapping_add(x[0])
            .wrapping_add(0xd76aa478)
            .rotate_left(7),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_f(a, b, c))
            .wrapping_add(x[1])
            .wrapping_add(0xe8c7b756)
            .rotate_left(12),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_f(d, a, b))
            .wrapping_add(x[2])
            .wrapping_add(0x242070db)
            .rotate_left(17),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_f(c, d, a))
            .wrapping_add(x[3])
            .wrapping_add(0xc1bdceee)
            .rotate_left(22),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_f(b, c, d))
            .wrapping_add(x[4])
            .wrapping_add(0xf57c0faf)
            .rotate_left(7),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_f(a, b, c))
            .wrapping_add(x[5])
            .wrapping_add(0x4787c62a)
            .rotate_left(12),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_f(d, a, b))
            .wrapping_add(x[6])
            .wrapping_add(0xa8304613)
            .rotate_left(17),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_f(c, d, a))
            .wrapping_add(x[7])
            .wrapping_add(0xfd469501)
            .rotate_left(22),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_f(b, c, d))
            .wrapping_add(x[8])
            .wrapping_add(0x698098d8)
            .rotate_left(7),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_f(a, b, c))
            .wrapping_add(x[9])
            .wrapping_add(0x8b44f7af)
            .rotate_left(12),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_f(d, a, b))
            .wrapping_add(x[10])
            .wrapping_add(0xffff5bb1)
            .rotate_left(17),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_f(c, d, a))
            .wrapping_add(x[11])
            .wrapping_add(0x895cd7be)
            .rotate_left(22),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_f(b, c, d))
            .wrapping_add(x[12])
            .wrapping_add(0x6b901122)
            .rotate_left(7),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_f(a, b, c))
            .wrapping_add(x[13])
            .wrapping_add(0xfd987193)
            .rotate_left(12),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_f(d, a, b))
            .wrapping_add(x[14])
            .wrapping_add(0xa679438e)
            .rotate_left(17),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_f(c, d, a))
            .wrapping_add(x[15])
            .wrapping_add(0x49b40821)
            .rotate_left(22),
    );

    // -------- Round 1 (G, rotations 5, 9, 14, 20) --------
    a = b.wrapping_add(
        a.wrapping_add(md5_g(b, c, d))
            .wrapping_add(x[1])
            .wrapping_add(0xf61e2562)
            .rotate_left(5),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_g(a, b, c))
            .wrapping_add(x[6])
            .wrapping_add(0xc040b340)
            .rotate_left(9),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_g(d, a, b))
            .wrapping_add(x[11])
            .wrapping_add(0x265e5a51)
            .rotate_left(14),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_g(c, d, a))
            .wrapping_add(x[0])
            .wrapping_add(0xe9b6c7aa)
            .rotate_left(20),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_g(b, c, d))
            .wrapping_add(x[5])
            .wrapping_add(0xd62f105d)
            .rotate_left(5),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_g(a, b, c))
            .wrapping_add(x[10])
            .wrapping_add(0x02441453)
            .rotate_left(9),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_g(d, a, b))
            .wrapping_add(x[15])
            .wrapping_add(0xd8a1e681)
            .rotate_left(14),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_g(c, d, a))
            .wrapping_add(x[4])
            .wrapping_add(0xe7d3fbc8)
            .rotate_left(20),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_g(b, c, d))
            .wrapping_add(x[9])
            .wrapping_add(0x21e1cde6)
            .rotate_left(5),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_g(a, b, c))
            .wrapping_add(x[14])
            .wrapping_add(0xc33707d6)
            .rotate_left(9),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_g(d, a, b))
            .wrapping_add(x[3])
            .wrapping_add(0xf4d50d87)
            .rotate_left(14),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_g(c, d, a))
            .wrapping_add(x[8])
            .wrapping_add(0x455a14ed)
            .rotate_left(20),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_g(b, c, d))
            .wrapping_add(x[13])
            .wrapping_add(0xa9e3e905)
            .rotate_left(5),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_g(a, b, c))
            .wrapping_add(x[2])
            .wrapping_add(0xfcefa3f8)
            .rotate_left(9),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_g(d, a, b))
            .wrapping_add(x[7])
            .wrapping_add(0x676f02d9)
            .rotate_left(14),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_g(c, d, a))
            .wrapping_add(x[12])
            .wrapping_add(0x8d2a4c8a)
            .rotate_left(20),
    );

    // -------- Round 2 (H, rotations 4, 11, 16, 23) --------
    a = b.wrapping_add(
        a.wrapping_add(md5_h(b, c, d))
            .wrapping_add(x[5])
            .wrapping_add(0xfffa3942)
            .rotate_left(4),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_h(a, b, c))
            .wrapping_add(x[8])
            .wrapping_add(0x8771f681)
            .rotate_left(11),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_h(d, a, b))
            .wrapping_add(x[11])
            .wrapping_add(0x6d9d6122)
            .rotate_left(16),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_h(c, d, a))
            .wrapping_add(x[14])
            .wrapping_add(0xfde5380c)
            .rotate_left(23),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_h(b, c, d))
            .wrapping_add(x[1])
            .wrapping_add(0xa4beea44)
            .rotate_left(4),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_h(a, b, c))
            .wrapping_add(x[4])
            .wrapping_add(0x4bdecfa9)
            .rotate_left(11),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_h(d, a, b))
            .wrapping_add(x[7])
            .wrapping_add(0xf6bb4b60)
            .rotate_left(16),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_h(c, d, a))
            .wrapping_add(x[10])
            .wrapping_add(0xbebfbc70)
            .rotate_left(23),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_h(b, c, d))
            .wrapping_add(x[13])
            .wrapping_add(0x289b7ec6)
            .rotate_left(4),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_h(a, b, c))
            .wrapping_add(x[0])
            .wrapping_add(0xeaa127fa)
            .rotate_left(11),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_h(d, a, b))
            .wrapping_add(x[3])
            .wrapping_add(0xd4ef3085)
            .rotate_left(16),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_h(c, d, a))
            .wrapping_add(x[6])
            .wrapping_add(0x04881d05)
            .rotate_left(23),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_h(b, c, d))
            .wrapping_add(x[9])
            .wrapping_add(0xd9d4d039)
            .rotate_left(4),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_h(a, b, c))
            .wrapping_add(x[12])
            .wrapping_add(0xe6db99e5)
            .rotate_left(11),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_h(d, a, b))
            .wrapping_add(x[15])
            .wrapping_add(0x1fa27cf8)
            .rotate_left(16),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_h(c, d, a))
            .wrapping_add(x[2])
            .wrapping_add(0xc4ac5665)
            .rotate_left(23),
    );

    // -------- Round 3 (I, rotations 6, 10, 15, 21) --------
    a = b.wrapping_add(
        a.wrapping_add(md5_i(b, c, d))
            .wrapping_add(x[0])
            .wrapping_add(0xf4292244)
            .rotate_left(6),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_i(a, b, c))
            .wrapping_add(x[7])
            .wrapping_add(0x432aff97)
            .rotate_left(10),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_i(d, a, b))
            .wrapping_add(x[14])
            .wrapping_add(0xab9423a7)
            .rotate_left(15),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_i(c, d, a))
            .wrapping_add(x[5])
            .wrapping_add(0xfc93a039)
            .rotate_left(21),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_i(b, c, d))
            .wrapping_add(x[12])
            .wrapping_add(0x655b59c3)
            .rotate_left(6),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_i(a, b, c))
            .wrapping_add(x[3])
            .wrapping_add(0x8f0ccc92)
            .rotate_left(10),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_i(d, a, b))
            .wrapping_add(x[10])
            .wrapping_add(0xffeff47d)
            .rotate_left(15),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_i(c, d, a))
            .wrapping_add(x[1])
            .wrapping_add(0x85845dd1)
            .rotate_left(21),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_i(b, c, d))
            .wrapping_add(x[8])
            .wrapping_add(0x6fa87e4f)
            .rotate_left(6),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_i(a, b, c))
            .wrapping_add(x[15])
            .wrapping_add(0xfe2ce6e0)
            .rotate_left(10),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_i(d, a, b))
            .wrapping_add(x[6])
            .wrapping_add(0xa3014314)
            .rotate_left(15),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_i(c, d, a))
            .wrapping_add(x[13])
            .wrapping_add(0x4e0811a1)
            .rotate_left(21),
    );
    a = b.wrapping_add(
        a.wrapping_add(md5_i(b, c, d))
            .wrapping_add(x[4])
            .wrapping_add(0xf7537e82)
            .rotate_left(6),
    );
    d = a.wrapping_add(
        d.wrapping_add(md5_i(a, b, c))
            .wrapping_add(x[11])
            .wrapping_add(0xbd3af235)
            .rotate_left(10),
    );
    c = d.wrapping_add(
        c.wrapping_add(md5_i(d, a, b))
            .wrapping_add(x[2])
            .wrapping_add(0x2ad7d2bb)
            .rotate_left(15),
    );
    b = c.wrapping_add(
        b.wrapping_add(md5_i(c, d, a))
            .wrapping_add(x[9])
            .wrapping_add(0xeb86d391)
            .rotate_left(21),
    );

    // Accumulate into chaining state (mod 2^32).
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

// =============================================================================
// Md5Context
// =============================================================================

/// MD5 hash context (RFC 1321).
///
/// # Security Warning
///
/// MD5 is cryptographically broken (collision attacks are practical). It MUST
/// NOT be used for new security-sensitive applications. Use SHA-256 or SHA-3
/// for digital signatures, certificate fingerprints, and integrity protection.
///
/// MD5 is retained in this crate solely for compatibility with legacy
/// protocols (e.g., the SSLv3/TLS 1.0 MD5+SHA-1 composite handshake digest)
/// and legacy file formats.
///
/// # State Layout
///
/// Mirrors `MD5_CTX` from `include/openssl/md5.h`:
/// * `h`       — chaining variables `{A, B, C, D}` (little-endian output order)
/// * `block`   — 64-byte buffer holding an in-progress block
/// * `num`     — number of valid bytes currently buffered in `block`
/// * `total_len` — total message byte count processed so far
///
/// The underlying bytes are zeroised on drop via [`Zeroize`]/[`ZeroizeOnDrop`],
/// replacing `OPENSSL_cleanse()` in the C one-shot `MD5()` (see
/// `crypto/md5/md5_one.c`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Md5Context {
    /// Chaining variables {A, B, C, D}.
    h: [u32; 4],
    /// Block buffer (64 bytes per RFC 1321).
    block: [u8; MD5_CBLOCK],
    /// Number of valid bytes currently buffered in `block`.
    num: usize,
    /// Total number of message bytes absorbed so far.
    total_len: u64,
}

impl Md5Context {
    /// Create a new MD5 hash context initialised to the RFC 1321 IV.
    ///
    /// **Deprecated:** MD5 is cryptographically broken. Prefer SHA-256 or SHA-3
    /// for any new code. Retained only for legacy protocol compatibility.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # #![allow(deprecated)]
    /// use openssl_crypto::hash::md5::Md5Context;
    /// use openssl_crypto::hash::Digest;
    ///
    /// let mut ctx = Md5Context::new();
    /// ctx.update(b"hello").unwrap();
    /// let digest = ctx.finalize().unwrap();
    /// assert_eq!(digest.len(), 16);
    /// ```
    #[deprecated(note = "MD5 is cryptographically broken; use SHA-256 or SHA-3")]
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: MD5_IV,
            block: [0u8; MD5_CBLOCK],
            num: 0,
            total_len: 0,
        }
    }

    /// Compress a single 64-byte block into this context's state.
    ///
    /// Exposes the raw compression function for composite digests that need
    /// to drive MD5 in lock-step with another hash (e.g., the
    /// [`Md5Sha1Context`] used for SSLv3/TLS 1.0 handshakes).
    ///
    /// Corresponds to `md5_block_data_order()` (for a single block) from
    /// `crypto/md5/md5_dgst.c`.
    ///
    /// # Panics (debug builds only)
    ///
    /// Panics in debug builds if `block.len() < 64`; release builds read
    /// exactly 64 bytes from the start of the slice via safe indexing.
    pub fn compress(&mut self, block: &[u8; MD5_CBLOCK]) {
        md5_compress(&mut self.h, block);
    }
}

#[allow(deprecated)]
impl Default for Md5Context {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(deprecated)]
impl Digest for Md5Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        // Accumulate total-length (overflow-checked per Rule R6).
        let dlen = u64::try_from(data.len())
            .map_err(|_| CryptoError::AlgorithmNotFound("data length overflow".into()))?;
        self.total_len = self
            .total_len
            .checked_add(dlen)
            .ok_or_else(|| CryptoError::AlgorithmNotFound("MD5 total length overflow".into()))?;

        let mut off = 0usize;

        // If we have a partial block in the buffer, try to fill it.
        if self.num > 0 {
            let space = MD5_CBLOCK - self.num;
            if data.len() < space {
                self.block[self.num..self.num + data.len()].copy_from_slice(data);
                self.num += data.len();
                return Ok(());
            }
            self.block[self.num..MD5_CBLOCK].copy_from_slice(&data[..space]);
            md5_compress(&mut self.h, &self.block);
            self.num = 0;
            off = space;
        }

        // Process full 64-byte blocks directly from the input slice.
        while off + MD5_CBLOCK <= data.len() {
            md5_compress(&mut self.h, &data[off..off + MD5_CBLOCK]);
            off += MD5_CBLOCK;
        }

        // Buffer any trailing bytes.
        let rem = data.len() - off;
        if rem > 0 {
            self.block[..rem].copy_from_slice(&data[off..]);
            self.num = rem;
        }
        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Convert total bytes to a bit count (overflow-checked per Rule R6).
        let bit_len = self
            .total_len
            .checked_mul(8)
            .ok_or_else(|| CryptoError::AlgorithmNotFound("MD5 bit-length overflow".into()))?;

        // Append the mandatory 0x80 terminator.
        self.block[self.num] = 0x80;
        self.num += 1;

        // If there is not enough space for the 8-byte length trailer in the
        // current block (i.e., fewer than 8 free bytes remain), pad the rest
        // of this block with zeroes, compress it, and start a fresh block.
        if self.num > MD5_CBLOCK - 8 {
            for b in &mut self.block[self.num..MD5_CBLOCK] {
                *b = 0;
            }
            md5_compress(&mut self.h, &self.block);
            self.num = 0;
        }

        // Zero-pad up to byte offset 56 (first byte of the 64-bit length).
        for b in &mut self.block[self.num..MD5_CBLOCK - 8] {
            *b = 0;
        }

        // Append the bit-length as a little-endian 64-bit value (MD5 is
        // little-endian, differing from SHA-1/SHA-2).
        self.block[MD5_CBLOCK - 8..MD5_CBLOCK].copy_from_slice(&bit_len.to_le_bytes());
        md5_compress(&mut self.h, &self.block);

        // Serialise the digest A||B||C||D in little-endian form.
        let mut out = Vec::with_capacity(MD5_DIGEST_LENGTH);
        for &w in &self.h {
            out.extend_from_slice(&w.to_le_bytes());
        }
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        MD5_DIGEST_LENGTH
    }

    fn block_size(&self) -> usize {
        MD5_CBLOCK
    }

    fn algorithm_name(&self) -> &'static str {
        "MD5"
    }

    fn reset(&mut self) {
        self.h = MD5_IV;
        self.block = [0u8; MD5_CBLOCK];
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

// =============================================================================
// Md5Sha1Context — composite MD5 || SHA-1 digest (legacy TLS/SSLv3)
// =============================================================================

/// Algorithm name reported by [`Md5Sha1Context::algorithm_name`].
const MD5_SHA1_ALGORITHM_NAME: &str = "MD5-SHA1";

/// Combined output length in bytes: MD5 (16) || SHA-1 (20) = 36.
const MD5_SHA1_DIGEST_LENGTH: usize = MD5_DIGEST_LENGTH + 20;

/// Composite MD5 + SHA-1 digest used by legacy TLS (TLS 1.0 / TLS 1.1 PRF and
/// `SSLv3` handshake transcript). Runs MD5 and SHA-1 in lock-step over the same
/// input and concatenates their outputs: **MD5(16) || SHA-1(20) = 36 bytes**.
///
/// Translates `ossl_md5_sha1_{init,update,final}` from
/// `crypto/md5/md5_sha1.c`. Both constituent hashes are cryptographically
/// broken; this context exists solely to preserve wire-format compatibility
/// with legacy peers.
///
/// # Security Warning
///
/// Do not use for new cryptographic purposes. The individual hashes admit
/// practical collisions and MD5+SHA-1 no longer offers meaningful preimage
/// resistance. Prefer TLS 1.2/1.3 with SHA-256/SHA-384.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Md5Sha1Context {
    md5: Md5Context,
    sha1: Sha1Context,
}

impl Md5Sha1Context {
    /// Create a fresh MD5+SHA-1 composite context.
    ///
    /// **Deprecated:** both MD5 and SHA-1 are cryptographically broken. This
    /// constructor exists only for legacy protocol compatibility.
    #[deprecated(note = "MD5+SHA-1 composite is legacy; use TLS 1.2+ with SHA-256 or SHA-384")]
    #[must_use]
    pub fn new() -> Self {
        #[allow(deprecated)]
        Self {
            md5: Md5Context::new(),
            sha1: Sha1Context::new(),
        }
    }
}

#[allow(deprecated)]
impl Default for Md5Sha1Context {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(deprecated)]
impl Digest for Md5Sha1Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        // Run both hashes in lock-step over the same input
        // (matches `ossl_md5_sha1_update` from crypto/md5/md5_sha1.c).
        self.md5.update(data)?;
        self.sha1.update(data)
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        // Finalise MD5 then SHA-1, concatenate MD5(16) || SHA-1(20) = 36 bytes
        // (matches `ossl_md5_sha1_final` from crypto/md5/md5_sha1.c).
        let md5_out = self.md5.finalize()?;
        let sha1_out = self.sha1.finalize()?;

        let mut out = Vec::with_capacity(MD5_SHA1_DIGEST_LENGTH);
        out.extend_from_slice(&md5_out);
        out.extend_from_slice(&sha1_out);
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        MD5_SHA1_DIGEST_LENGTH
    }

    fn block_size(&self) -> usize {
        // Both constituent hashes use a 64-byte block.
        MD5_CBLOCK
    }

    fn algorithm_name(&self) -> &'static str {
        MD5_SHA1_ALGORITHM_NAME
    }

    fn reset(&mut self) {
        self.md5.reset();
        self.sha1.reset();
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

// =============================================================================
// One-shot convenience function
// =============================================================================

/// One-shot MD5 digest of `data`.
///
/// Equivalent to:
///
/// ```ignore
/// # #![allow(deprecated)]
/// use openssl_crypto::hash::md5::Md5Context;
/// use openssl_crypto::hash::Digest;
/// let mut ctx = Md5Context::new();
/// ctx.update(data)?;
/// ctx.finalize()
/// # ;
/// ```
///
/// Translates the legacy `MD5()` C function from `crypto/md5/md5_one.c`,
/// with automatic secure erasure of the context on drop (replacing the
/// explicit `OPENSSL_cleanse()` call).
///
/// **Deprecated:** MD5 is cryptographically broken.
///
/// # Errors
///
/// Returns [`CryptoError`] if the input length overflows internal
/// 64-bit counters (only reachable with `data.len()` above `u64::MAX / 8`
/// bytes, i.e., never on 64-bit targets).
#[deprecated(note = "MD5 is cryptographically broken; use SHA-256 or SHA-3")]
pub fn md5(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Md5Context::new();
    ctx.update(data)?;
    ctx.finalize()
}

// =============================================================================
// Unit tests — RFC 1321 Appendix A.5 test vectors
// =============================================================================

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// Format a byte slice as lowercase hex for comparison with RFC 1321.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn md5_rfc1321_empty_string() {
        // RFC 1321 Appendix A.5: MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let out = md5(b"").unwrap();
        assert_eq!(hex(&out), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn md5_rfc1321_single_letter() {
        // MD5("a") = 0cc175b9c0f1b6a831c399e269772661
        let out = md5(b"a").unwrap();
        assert_eq!(hex(&out), "0cc175b9c0f1b6a831c399e269772661");
    }

    #[test]
    fn md5_rfc1321_abc() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let out = md5(b"abc").unwrap();
        assert_eq!(hex(&out), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn md5_rfc1321_message_digest() {
        // MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
        let out = md5(b"message digest").unwrap();
        assert_eq!(hex(&out), "f96b697d7cb7938d525a2f31aaf161d0");
    }

    #[test]
    fn md5_rfc1321_alphabet() {
        // MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
        let out = md5(b"abcdefghijklmnopqrstuvwxyz").unwrap();
        assert_eq!(hex(&out), "c3fcd3d76192e4007dfb496cca67e13b");
    }

    #[test]
    fn md5_rfc1321_alphanumeric() {
        // MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        //   = d174ab98d277d9f5a5611c2c9f419d9f
        let out = md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").unwrap();
        assert_eq!(hex(&out), "d174ab98d277d9f5a5611c2c9f419d9f");
    }

    #[test]
    fn md5_rfc1321_long_digits() {
        // MD5("1234567890" * 8) = 57edf4a22be3c955ac49da2e2107b67a
        let input =
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        let out = md5(input).unwrap();
        assert_eq!(hex(&out), "57edf4a22be3c955ac49da2e2107b67a");
    }

    #[test]
    fn md5_streaming_matches_oneshot() {
        // Streaming update() in small chunks must match one-shot md5().
        let data: Vec<u8> = (0..=255u8).collect();
        let full = md5(&data).unwrap();

        let mut ctx = Md5Context::new();
        for chunk in data.chunks(7) {
            ctx.update(chunk).unwrap();
        }
        let incremental = ctx.finalize().unwrap();
        assert_eq!(full, incremental);
    }

    #[test]
    fn md5_block_boundary_exact_64_bytes() {
        // A single exact-block input exercises the "pad into the next block"
        // path, since after appending 0x80 there is insufficient room for
        // the length trailer in the current block.
        let input = [0x61u8; 64]; // 64 × 'a'
        let out = md5(&input).unwrap();
        // Reference computed via RFC 1321 / OpenSSL:
        //   echo -n "aaaa..." (64 a's) | openssl md5
        assert_eq!(hex(&out), "014842d480b571495a4a0363793f7367");
    }

    #[test]
    fn md5_block_boundary_55_bytes() {
        // 55 bytes: the 0x80 terminator at offset 55 leaves exactly 8 bytes
        // free for the length trailer — single-block finalisation path.
        let input = [0x61u8; 55];
        let out = md5(&input).unwrap();
        // Cross-checked with Python hashlib.md5(b'a'*55).
        assert_eq!(hex(&out), "ef1772b6dff9a122358552954ad0df65");
    }

    #[test]
    fn md5_block_boundary_56_bytes() {
        // 56 bytes: after 0x80 only 7 bytes remain free — forces the pad
        // to spill into a second block.
        let input = [0x61u8; 56];
        let out = md5(&input).unwrap();
        // Cross-checked with Python hashlib.md5(b'a'*56).
        assert_eq!(hex(&out), "3b0c8ac703f828b04c6c197006d17218");
    }

    #[test]
    fn md5_digest_method_resets_state() {
        // `Digest::digest` resets, updates, and finalises — calling it
        // repeatedly on the same context must produce identical output.
        let mut ctx = Md5Context::new();
        let first = ctx.digest(b"hello world").unwrap();
        let second = ctx.digest(b"hello world").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn md5_reset_restores_initial_state() {
        let mut ctx = Md5Context::new();
        ctx.update(b"contaminate").unwrap();
        ctx.reset();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(hex(&out), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn md5_context_metadata() {
        let ctx = Md5Context::new();
        assert_eq!(ctx.digest_size(), 16);
        assert_eq!(ctx.block_size(), 64);
        assert_eq!(ctx.algorithm_name(), "MD5");
    }

    #[test]
    fn md5_compress_raw_block() {
        // Compressing the all-'a' block directly must match the full
        // streaming pipeline for an aligned 64-byte input (without padding).
        // We validate this indirectly by computing MD5(aaa...64) and
        // confirming the compression function accepts a 64-byte array slice.
        let mut ctx = Md5Context::new();
        let block = [0x61u8; 64];
        ctx.compress(&block);
        // The internal state is now (IV transformed); finalising with an
        // empty tail adds only a padding block representing "0 bytes total",
        // since compress() does not update total_len. This is the expected
        // raw-compress semantics (used by composite/legacy callers).
        // We just ensure the method is callable and mutates state.
        let before = Md5Context::new();
        assert_ne!(ctx.h, before.h);
    }

    // -------- Md5Sha1Context --------

    #[test]
    fn md5_sha1_empty_string() {
        // MD5+SHA-1 composite of "" is the concatenation of:
        //   MD5("")  = d41d8cd98f00b204e9800998ecf8427e
        //   SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let mut ctx = Md5Sha1Context::new();
        ctx.update(b"").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), 36);
        assert_eq!(
            hex(&out),
            "d41d8cd98f00b204e9800998ecf8427eda39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn md5_sha1_abc() {
        // MD5("abc")  = 900150983cd24fb0d6963f7d28e17f72
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let mut ctx = Md5Sha1Context::new();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(out.len(), 36);
        assert_eq!(
            hex(&out),
            "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn md5_sha1_streaming() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut ctx = Md5Sha1Context::new();
        for chunk in data.chunks(5) {
            ctx.update(chunk).unwrap();
        }
        let streaming = ctx.finalize().unwrap();

        let mut oneshot_ctx = Md5Sha1Context::new();
        oneshot_ctx.update(data).unwrap();
        let oneshot = oneshot_ctx.finalize().unwrap();

        assert_eq!(streaming, oneshot);
    }

    #[test]
    fn md5_sha1_metadata() {
        let ctx = Md5Sha1Context::new();
        assert_eq!(ctx.digest_size(), 36);
        assert_eq!(ctx.block_size(), 64);
        assert_eq!(ctx.algorithm_name(), "MD5-SHA1");
    }

    #[test]
    fn md5_sha1_reset_restores_initial_state() {
        let mut ctx = Md5Sha1Context::new();
        ctx.update(b"contaminate").unwrap();
        ctx.reset();
        ctx.update(b"abc").unwrap();
        let out = ctx.finalize().unwrap();
        assert_eq!(
            hex(&out),
            "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn md5_clone_independence() {
        // Cloning a context must produce an independent copy.
        let mut a = Md5Context::new();
        a.update(b"abc").unwrap();
        let mut b = a.clone();

        let out_a = a.finalize().unwrap();
        let out_b = b.finalize().unwrap();
        assert_eq!(out_a, out_b);

        // After finalising, the original is in an indeterminate state,
        // but the clone finalised independently should still match abc.
        assert_eq!(hex(&out_b), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn md5_large_input_1mb_a() {
        // MD5 of one megabyte of 'a' characters.
        // Cross-checked via Python `hashlib.md5(b'a' * 1_048_576)`.
        let input = vec![b'a'; 1_048_576];
        let out = md5(&input).unwrap();
        assert_eq!(hex(&out), "7202826a7791073fe2787f0c94603278");
    }
}
