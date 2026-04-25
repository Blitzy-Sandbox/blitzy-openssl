//! SHA family hash implementations: SHA-1 (legacy), SHA-2 (SHA-224/256/384/512),
//! SHA-3 (SHA3-224/256/384/512), and SHAKE (SHAKE128/256) XOF.
//!
//! Translates C implementations from `crypto/sha/*.c` (9 source files).
//! SHA-1 is retained for TLS compatibility but marked as legacy/deprecated.
//! SHA-3/SHAKE uses the Keccak-F\[1600\] sponge construction per FIPS 202.
//!
//! All digest APIs return [`CryptoResult<Vec<u8>>`] per Rule R5 — no sentinel
//! return values. All context types derive [`Zeroize`]/[`ZeroizeOnDrop`] for
//! secure erasure of cryptographic state, replacing C `OPENSSL_cleanse()`.

// Cryptographic constants (IVs, round constants) are written exactly as published
// in FIPS 180-4/202 without underscore separators to facilitate direct verification
// against the standards and cross-reference with the original C source.
#![allow(clippy::unreadable_literal)]
// Compression-function working variables (a–h, w, t1/t2) use single-character
// names that directly correspond to the FIPS 180-4/202 specification notation.
#![allow(clippy::many_single_char_names)]
// Index-based iteration in compression functions mirrors the FIPS reference
// pseudocode (e.g., "for i = 0 to 79") for verifiability against the standard.
#![allow(clippy::needless_range_loop)]

use openssl_common::{CryptoError, CryptoResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Digest Trait
// =============================================================================

/// Common interface for cryptographic hash functions.
///
/// Provides streaming ([`update`](Digest::update) + [`finalize`](Digest::finalize))
/// and one-shot ([`digest`](Digest::digest)) hashing. All fallible operations
/// return [`CryptoResult`] per Rule R5 — no sentinel return values.
pub trait Digest: Send + Sync {
    /// Feed data into the hash context. Can be called multiple times.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()>;

    /// Finalize the hash computation, applying padding and returning the digest.
    ///
    /// After calling `finalize`, the context is in an indeterminate state;
    /// call [`reset`](Digest::reset) before reusing.
    fn finalize(&mut self) -> CryptoResult<Vec<u8>>;

    /// Returns the output digest size in bytes.
    fn digest_size(&self) -> usize;

    /// Returns the internal block size in bytes.
    fn block_size(&self) -> usize;

    /// Returns the algorithm name (e.g., `"SHA-256"`, `"SHA3-512"`).
    fn algorithm_name(&self) -> &'static str;

    /// Reset the context to its initial state, ready for a new computation.
    fn reset(&mut self);

    /// One-shot convenience: reset, update with data, and finalize.
    fn digest(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        self.reset();
        self.update(data)?;
        self.finalize()
    }

    /// Clone this digest into a new boxed instance.
    ///
    /// Required to support `Clone` for types that hold a `Box<dyn Digest>`
    /// such as the HMAC state in [`crate::mac`]. Because `Box<dyn Digest>`
    /// cannot automatically derive `Clone` (the trait is not object-safe for
    /// `Clone`), each concrete digest implementation must provide an
    /// explicit `clone_box` returning a fresh boxed copy.
    ///
    /// Implementations are expected to clone the full internal state so the
    /// returned digest produces identical output for any subsequent
    /// `update` + `finalize` sequence as the original.
    fn clone_box(&self) -> Box<dyn Digest>;
}

// =============================================================================
// Byte-order helper functions (no unsafe, per Rule R8)
// =============================================================================

/// Load a big-endian `u32` from `data` at the given byte offset.
#[inline]
fn load_be_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Load a big-endian `u64` from `data` at the given byte offset.
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

/// Load a little-endian `u64` from `data` at the given byte offset.
#[inline]
fn load_le_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
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

// =============================================================================
// SHA-1 Constants (from crypto/sha/sha_local.h)
// =============================================================================

/// SHA-1 initial hash values H0..H4 (FIPS 180-4 §5.3.1).
const SHA1_IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

// =============================================================================
// SHA-256 Constants (from crypto/sha/sha256.c)
// =============================================================================

/// SHA-256 round constants K\[0..63\] (FIPS 180-4 §4.2.2).
#[rustfmt::skip]
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-224 initial hash values (FIPS 180-4 §5.3.2).
#[rustfmt::skip]
const SHA224_IV: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
#[rustfmt::skip]
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// =============================================================================
// SHA-512 Constants (from crypto/sha/sha512.c)
// =============================================================================

/// SHA-512 round constants K\[0..79\] (FIPS 180-4 §4.2.3).
#[rustfmt::skip]
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-384 initial hash values (FIPS 180-4 §5.3.4).
#[rustfmt::skip]
const SHA384_IV: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

/// SHA-512 initial hash values (FIPS 180-4 §5.3.5).
#[rustfmt::skip]
const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// SHA-512/224 initial hash values (FIPS 180-4 §5.3.6.1).
#[rustfmt::skip]
const SHA512_224_IV: [u64; 8] = [
    0x8c3d37c819544da2, 0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
    0x0f6d2b697bd44da8, 0x77e36f7304c48942,
    0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
];

/// SHA-512/256 initial hash values (FIPS 180-4 §5.3.6.2).
#[rustfmt::skip]
const SHA512_256_IV: [u64; 8] = [
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
    0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
];

// =============================================================================
// Keccak-F[1600] Constants (from crypto/sha/keccak1600.c)
// =============================================================================

/// Keccak-F\[1600\] round constants (24 rounds).
#[rustfmt::skip]
const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Keccak-F\[1600\] lane rotation offsets indexed as `RHOTATES[y][x]`.
#[rustfmt::skip]
const KECCAK_RHOTATES: [[u32; 5]; 5] = [
    [ 0,  1, 62, 28, 27],
    [36, 44,  6, 55, 20],
    [ 3, 10, 43, 25, 39],
    [41, 45, 15, 21,  8],
    [18,  2, 61, 56, 14],
];

// =============================================================================
// SHA-1 Implementation (from crypto/sha/sha_local.h, sha1dgst.c)
// =============================================================================

/// SHA-1 hash context (160-bit / 20-byte digest).
///
/// **Warning:** SHA-1 is cryptographically broken. Use [`Sha256Context`] or
/// [`Sha3Context`] for new applications. SHA-1 is retained only for legacy
/// TLS compatibility (e.g., `SSLv3` master-secret derivation).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha1Context {
    h: [u32; 5],
    block: [u8; 64],
    num: usize,
    total_len: u64,
}

impl Sha1Context {
    /// Create a new SHA-1 context.
    ///
    /// **Deprecated:** SHA-1 is cryptographically broken. Prefer SHA-256 or SHA-3.
    #[deprecated(note = "SHA-1 is cryptographically broken; use SHA-256 or SHA-3")]
    pub fn new() -> Self {
        Self {
            h: SHA1_IV,
            block: [0u8; 64],
            num: 0,
            total_len: 0,
        }
    }
}

#[allow(deprecated)]
impl Default for Sha1Context {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-1 compression function: 80 rounds over a single 64-byte block.
///
/// Implements the SHA-1 round function with four groups of 20 rounds each,
/// using boolean functions `F_00_19` (Ch), `F_20_39` (Parity), `F_40_59` (Maj),
/// and `F_60_79` (Parity), per FIPS 180-4 §6.1.2.
fn sha1_compress(state: &mut [u32; 5], block: &[u8]) {
    // Load 16 big-endian words and expand to 80-word schedule
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = load_be_u32(block, i * 4);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);

    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => (((c ^ d) & b) ^ d, 0x5a82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
            40..=59 => ((b & c) | ((b | c) & d), 0x8f1b_bcdcu32),
            _ => (b ^ c ^ d, 0xca62_c1d6u32),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[allow(deprecated)]
impl Digest for Sha1Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let dlen = u64::try_from(data.len())
            .map_err(|_| CryptoError::AlgorithmNotFound("data length overflow".into()))?;
        self.total_len = self
            .total_len
            .checked_add(dlen)
            .ok_or_else(|| CryptoError::AlgorithmNotFound("SHA-1 total length overflow".into()))?;

        let mut off = 0usize;
        if self.num > 0 {
            let space = 64 - self.num;
            if data.len() < space {
                self.block[self.num..self.num + data.len()].copy_from_slice(data);
                self.num += data.len();
                return Ok(());
            }
            self.block[self.num..64].copy_from_slice(&data[..space]);
            sha1_compress(&mut self.h, &self.block);
            self.num = 0;
            off = space;
        }
        while off + 64 <= data.len() {
            sha1_compress(&mut self.h, &data[off..off + 64]);
            off += 64;
        }
        let rem = data.len() - off;
        if rem > 0 {
            self.block[..rem].copy_from_slice(&data[off..]);
            self.num = rem;
        }
        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        let bit_len = self
            .total_len
            .checked_mul(8)
            .ok_or_else(|| CryptoError::AlgorithmNotFound("SHA-1 bit-length overflow".into()))?;
        self.block[self.num] = 0x80;
        self.num += 1;
        if self.num > 56 {
            for b in &mut self.block[self.num..64] {
                *b = 0;
            }
            sha1_compress(&mut self.h, &self.block);
            self.num = 0;
        }
        for b in &mut self.block[self.num..56] {
            *b = 0;
        }
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_compress(&mut self.h, &self.block);

        let mut out = Vec::with_capacity(20);
        for &w in &self.h {
            out.extend_from_slice(&w.to_be_bytes());
        }
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        20
    }
    fn block_size(&self) -> usize {
        64
    }
    fn algorithm_name(&self) -> &'static str {
        "SHA-1"
    }

    fn reset(&mut self) {
        self.h = SHA1_IV;
        self.block = [0u8; 64];
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

// =============================================================================
// SHA-256 Implementation (from crypto/sha/sha256.c)
// =============================================================================

/// SHA-224 / SHA-256 hash context.
///
/// SHA-224 and SHA-256 share the same compression function but differ in
/// initial hash values and output length (28 vs 32 bytes). Use the named
/// constructors [`sha224`](Sha256Context::sha224) or [`sha256`](Sha256Context::sha256).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha256Context {
    h: [u32; 8],
    block: [u8; 64],
    num: usize,
    total_len: u64,
    md_len: usize,
}

impl Sha256Context {
    /// Create a SHA-224 context (28-byte / 224-bit digest).
    pub fn sha224() -> Self {
        Self {
            h: SHA224_IV,
            block: [0u8; 64],
            num: 0,
            total_len: 0,
            md_len: 28,
        }
    }

    /// Create a SHA-256 context (32-byte / 256-bit digest).
    pub fn sha256() -> Self {
        Self {
            h: SHA256_IV,
            block: [0u8; 64],
            num: 0,
            total_len: 0,
            md_len: 32,
        }
    }
}

/// SHA-256 helper functions (FIPS 180-4 §4.1.2).
#[inline]
fn sha256_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[inline]
fn sha256_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
#[inline]
fn sha256_lsigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[inline]
fn sha256_lsigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
#[inline]
fn ch32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
#[inline]
fn maj32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-256 compression function: 64 rounds over a single 64-byte block.
fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = load_be_u32(block, i * 4);
    }
    for i in 16..64 {
        w[i] = sha256_lsigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(sha256_lsigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h_var) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    for i in 0..64 {
        let t1 = h_var
            .wrapping_add(sha256_sigma1(e))
            .wrapping_add(ch32(e, f, g))
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let t2 = sha256_sigma0(a).wrapping_add(maj32(a, b, c));
        h_var = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h_var);
}

impl Digest for Sha256Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let dlen = u64::try_from(data.len())
            .map_err(|_| CryptoError::AlgorithmNotFound("data length overflow".into()))?;
        self.total_len = self.total_len.checked_add(dlen).ok_or_else(|| {
            CryptoError::AlgorithmNotFound("SHA-256 total length overflow".into())
        })?;

        let mut off = 0usize;
        if self.num > 0 {
            let space = 64 - self.num;
            if data.len() < space {
                self.block[self.num..self.num + data.len()].copy_from_slice(data);
                self.num += data.len();
                return Ok(());
            }
            self.block[self.num..64].copy_from_slice(&data[..space]);
            sha256_compress(&mut self.h, &self.block);
            self.num = 0;
            off = space;
        }
        while off + 64 <= data.len() {
            sha256_compress(&mut self.h, &data[off..off + 64]);
            off += 64;
        }
        let rem = data.len() - off;
        if rem > 0 {
            self.block[..rem].copy_from_slice(&data[off..]);
            self.num = rem;
        }
        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        let bit_len = self
            .total_len
            .checked_mul(8)
            .ok_or_else(|| CryptoError::AlgorithmNotFound("SHA-256 bit-length overflow".into()))?;
        self.block[self.num] = 0x80;
        self.num += 1;
        if self.num > 56 {
            for b in &mut self.block[self.num..64] {
                *b = 0;
            }
            sha256_compress(&mut self.h, &self.block);
            self.num = 0;
        }
        for b in &mut self.block[self.num..56] {
            *b = 0;
        }
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut self.h, &self.block);

        let mut out = Vec::with_capacity(self.md_len);
        for &w in &self.h {
            let bytes = w.to_be_bytes();
            let remaining = self.md_len.saturating_sub(out.len());
            if remaining >= 4 {
                out.extend_from_slice(&bytes);
            } else if remaining > 0 {
                out.extend_from_slice(&bytes[..remaining]);
            }
        }
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        self.md_len
    }
    fn block_size(&self) -> usize {
        64
    }
    fn algorithm_name(&self) -> &'static str {
        if self.md_len == 28 {
            "SHA-224"
        } else {
            "SHA-256"
        }
    }

    fn reset(&mut self) {
        if self.md_len == 28 {
            self.h = SHA224_IV;
        } else {
            self.h = SHA256_IV;
        }
        self.block = [0u8; 64];
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

// =============================================================================
// SHA-512 Implementation (from crypto/sha/sha512.c)
// =============================================================================

/// SHA-384 / SHA-512 / SHA-512/224 / SHA-512/256 hash context.
///
/// All four variants share the same 80-round compression function operating
/// on 64-bit words and 128-byte blocks, differing only in IVs and output
/// truncation. Use the named constructors.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha512Context {
    h: [u64; 8],
    block: [u8; 128],
    num: usize,
    total_len: u128,
    md_len: usize,
    /// Stored IV for reset (index: 0=SHA-384, 1=SHA-512, 2=SHA-512/224, 3=SHA-512/256).
    iv_id: u8,
}

impl Sha512Context {
    /// Create a SHA-384 context (48-byte / 384-bit digest).
    pub fn sha384() -> Self {
        Self {
            h: SHA384_IV,
            block: [0u8; 128],
            num: 0,
            total_len: 0,
            md_len: 48,
            iv_id: 0,
        }
    }

    /// Create a SHA-512 context (64-byte / 512-bit digest).
    pub fn sha512() -> Self {
        Self {
            h: SHA512_IV,
            block: [0u8; 128],
            num: 0,
            total_len: 0,
            md_len: 64,
            iv_id: 1,
        }
    }

    /// Create a SHA-512/224 context (28-byte / 224-bit digest).
    pub fn sha512_224() -> Self {
        Self {
            h: SHA512_224_IV,
            block: [0u8; 128],
            num: 0,
            total_len: 0,
            md_len: 28,
            iv_id: 2,
        }
    }

    /// Create a SHA-512/256 context (32-byte / 256-bit digest).
    pub fn sha512_256() -> Self {
        Self {
            h: SHA512_256_IV,
            block: [0u8; 128],
            num: 0,
            total_len: 0,
            md_len: 32,
            iv_id: 3,
        }
    }

    /// Look up the IV set for reset.
    fn iv_for_reset(&self) -> [u64; 8] {
        match self.iv_id {
            0 => SHA384_IV,
            1 => SHA512_IV,
            2 => SHA512_224_IV,
            _ => SHA512_256_IV,
        }
    }
}

/// SHA-512 helper functions (FIPS 180-4 §4.1.3).
#[inline]
fn sha512_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
#[inline]
fn sha512_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
#[inline]
fn sha512_lsigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
#[inline]
fn sha512_lsigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
#[inline]
fn ch64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}
#[inline]
fn maj64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-512 compression function: 80 rounds over a single 128-byte block.
fn sha512_compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = load_be_u64(block, i * 8);
    }
    for i in 16..80 {
        w[i] = sha512_lsigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(sha512_lsigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hv) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    for i in 0..80 {
        let t1 = hv
            .wrapping_add(sha512_sigma1(e))
            .wrapping_add(ch64(e, f, g))
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let t2 = sha512_sigma0(a).wrapping_add(maj64(a, b, c));
        hv = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(hv);
}

impl Digest for Sha512Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let dlen = u128::try_from(data.len())
            .map_err(|_| CryptoError::AlgorithmNotFound("data length overflow".into()))?;
        self.total_len = self.total_len.checked_add(dlen).ok_or_else(|| {
            CryptoError::AlgorithmNotFound("SHA-512 total length overflow".into())
        })?;

        let mut off = 0usize;
        if self.num > 0 {
            let space = 128 - self.num;
            if data.len() < space {
                self.block[self.num..self.num + data.len()].copy_from_slice(data);
                self.num += data.len();
                return Ok(());
            }
            self.block[self.num..128].copy_from_slice(&data[..space]);
            sha512_compress(&mut self.h, &self.block);
            self.num = 0;
            off = space;
        }
        while off + 128 <= data.len() {
            sha512_compress(&mut self.h, &data[off..off + 128]);
            off += 128;
        }
        let rem = data.len() - off;
        if rem > 0 {
            self.block[..rem].copy_from_slice(&data[off..]);
            self.num = rem;
        }
        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        let bit_len = self
            .total_len
            .checked_mul(8)
            .ok_or_else(|| CryptoError::AlgorithmNotFound("SHA-512 bit-length overflow".into()))?;
        self.block[self.num] = 0x80;
        self.num += 1;
        if self.num > 112 {
            for b in &mut self.block[self.num..128] {
                *b = 0;
            }
            sha512_compress(&mut self.h, &self.block);
            self.num = 0;
        }
        for b in &mut self.block[self.num..112] {
            *b = 0;
        }
        self.block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        sha512_compress(&mut self.h, &self.block);

        let mut out = Vec::with_capacity(self.md_len);
        for &w in &self.h {
            let bytes = w.to_be_bytes();
            let remaining = self.md_len.saturating_sub(out.len());
            if remaining >= 8 {
                out.extend_from_slice(&bytes);
            } else if remaining > 0 {
                out.extend_from_slice(&bytes[..remaining]);
            }
        }
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        self.md_len
    }
    fn block_size(&self) -> usize {
        128
    }
    fn algorithm_name(&self) -> &'static str {
        match self.iv_id {
            0 => "SHA-384",
            1 => "SHA-512",
            2 => "SHA-512/224",
            _ => "SHA-512/256",
        }
    }

    fn reset(&mut self) {
        self.h = self.iv_for_reset();
        self.block = [0u8; 128];
        self.num = 0;
        self.total_len = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

// =============================================================================
// Keccak-F[1600] Permutation (from crypto/sha/keccak1600.c)
// =============================================================================

/// Keccak-F\[1600\] state: a 5×5 array of 64-bit lanes (1600 bits total).
///
/// Internally stored as a flat `[u64; 25]` with index mapping `state[y*5 + x]`
/// corresponding to the C `A[y][x]` convention. State material is securely
/// zeroed on drop via [`Zeroize`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeccakState {
    a: [u64; 25],
}

impl KeccakState {
    /// Create a zero-initialized Keccak state.
    fn new() -> Self {
        Self { a: [0u64; 25] }
    }

    /// Run the full Keccak-F\[1600\] permutation (24 rounds).
    ///
    /// Implements θ (theta), ρ (rho), π (pi), χ (chi), ι (iota) steps per
    /// FIPS 202 §3.3. Pure Rust, no unsafe.
    fn permute(&mut self) {
        for round in 0..24 {
            // θ (theta): column parity + diffusion
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = self.a[x] ^ self.a[5 + x] ^ self.a[10 + x] ^ self.a[15 + x] ^ self.a[20 + x];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for y in 0..5 {
                for x in 0..5 {
                    self.a[y * 5 + x] ^= d[x];
                }
            }

            // ρ (rho) + π (pi): combined lane rotation and position permutation
            // FIPS 202 Algorithm 2: B[y, 2x+3y mod 5] = ROT(A[x,y], r[x,y])
            // With flat indexing a[y*5+x] → b[((2x+3y)%5)*5 + y]
            let mut b = [0u64; 25];
            for y in 0..5 {
                for x in 0..5 {
                    let rot = KECCAK_RHOTATES[y][x];
                    b[((2 * x + 3 * y) % 5) * 5 + y] = self.a[y * 5 + x].rotate_left(rot);
                }
            }

            // χ (chi): non-linear per-row mixing
            for y in 0..5 {
                for x in 0..5 {
                    self.a[y * 5 + x] =
                        b[y * 5 + x] ^ ((!b[y * 5 + (x + 1) % 5]) & b[y * 5 + (x + 2) % 5]);
                }
            }

            // ι (iota): round constant XOR
            self.a[0] ^= KECCAK_RC[round];
        }
    }
}

/// Absorb `data` into the Keccak state at the given `rate` (in bytes).
///
/// XORs input bytes into the state lane-by-lane (little-endian), applying
/// the permutation after each full block.
fn keccak_absorb(state: &mut KeccakState, rate: usize, buf: &mut Vec<u8>, data: &[u8]) {
    let mut off = 0usize;

    // Fill partial buffer
    if !buf.is_empty() {
        let space = rate - buf.len();
        if data.len() < space {
            buf.extend_from_slice(data);
            return;
        }
        buf.extend_from_slice(&data[..space]);
        // XOR full block into state and permute
        xor_block_into_state(state, buf, rate);
        state.permute();
        buf.clear();
        off = space;
    }

    // Process full blocks directly
    while off + rate <= data.len() {
        xor_block_into_state(state, &data[off..off + rate], rate);
        state.permute();
        off += rate;
    }

    // Buffer remaining
    let rem = data.len() - off;
    if rem > 0 {
        buf.extend_from_slice(&data[off..]);
    }
}

/// XOR a full block into the Keccak state lanes (little-endian byte order).
fn xor_block_into_state(state: &mut KeccakState, block: &[u8], rate: usize) {
    let lanes = rate / 8;
    for i in 0..lanes {
        state.a[i] ^= load_le_u64(block, i * 8);
    }
}

/// Squeeze bytes from the Keccak state at the given `rate`.
///
/// `squeeze_offset` tracks the byte position within the current block so
/// that multiple calls can continue from where the last one left off.
fn keccak_squeeze(
    state: &mut KeccakState,
    rate: usize,
    out: &mut [u8],
    squeeze_offset: &mut usize,
) {
    let mut written = 0usize;
    while written < out.len() {
        // If current block exhausted, permute for more output
        if *squeeze_offset >= rate {
            state.permute();
            *squeeze_offset = 0;
        }
        let available = rate - *squeeze_offset;
        let to_copy = core::cmp::min(available, out.len() - written);

        // Extract bytes from state lanes
        let lane_start = *squeeze_offset / 8;
        let byte_off_in_lane = *squeeze_offset % 8;
        let mut copied = 0usize;

        // Handle partial first lane
        if byte_off_in_lane != 0 {
            let lane_bytes = state.a[lane_start].to_le_bytes();
            let avail_in_lane = 8 - byte_off_in_lane;
            let n = core::cmp::min(avail_in_lane, to_copy);
            out[written..written + n]
                .copy_from_slice(&lane_bytes[byte_off_in_lane..byte_off_in_lane + n]);
            copied += n;
        }

        // Copy full lanes
        while copied + 8 <= to_copy {
            let lane_idx = (*squeeze_offset + copied) / 8;
            let dst = &mut out[written + copied..written + copied + 8];
            dst.copy_from_slice(&state.a[lane_idx].to_le_bytes());
            copied += 8;
        }

        // Handle partial last lane
        if copied < to_copy {
            let lane_idx = (*squeeze_offset + copied) / 8;
            let lane_bytes = state.a[lane_idx].to_le_bytes();
            let n = to_copy - copied;
            out[written + copied..written + copied + n].copy_from_slice(&lane_bytes[..n]);
            copied += n;
        }

        written += copied;
        *squeeze_offset += copied;

        // Safety valve: should not happen, but prevent infinite loop
        if copied == 0 {
            break;
        }
    }
}

// =============================================================================
// SHA-3 Context (from crypto/sha/sha3.c)
// =============================================================================

/// Internal state for the SHA-3 / SHAKE absorb-squeeze state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XofState {
    /// Absorbing input data.
    Absorb,
    /// Squeeze phase (after padding has been applied).
    Squeeze,
}

impl Zeroize for XofState {
    fn zeroize(&mut self) {
        *self = XofState::Absorb;
    }
}

/// SHA-3 (Keccak-based) hash context for SHA3-224/256/384/512.
///
/// Uses the sponge construction with the Keccak-F\[1600\] permutation (FIPS 202).
/// SHA-3 variants differ in capacity (and thus rate = 200 − 2×digest\_bytes)
/// and padding byte (`0x06` for SHA-3, `0x1F` for SHAKE).
///
/// State material is securely zeroed on drop via [`Zeroize`]/[`ZeroizeOnDrop`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha3Context {
    state: KeccakState,
    buf: Vec<u8>,
    block_size: usize,
    md_size: usize,
    pad: u8,
    xof_state: XofState,
    squeeze_offset: usize,
}

impl Sha3Context {
    /// Internal constructor for all SHA-3 / SHAKE variants.
    fn new_with(md_size: usize, pad: u8) -> Self {
        let block_size = 200usize.saturating_sub(2 * md_size);
        Self {
            state: KeccakState::new(),
            buf: Vec::with_capacity(block_size),
            block_size,
            md_size,
            pad,
            xof_state: XofState::Absorb,
            squeeze_offset: 0,
        }
    }

    /// Create a SHA3-224 context (28-byte / 224-bit digest, rate = 144).
    pub fn sha3_224() -> Self {
        Self::new_with(28, 0x06)
    }

    /// Create a SHA3-256 context (32-byte / 256-bit digest, rate = 136).
    pub fn sha3_256() -> Self {
        Self::new_with(32, 0x06)
    }

    /// Create a SHA3-384 context (48-byte / 384-bit digest, rate = 104).
    pub fn sha3_384() -> Self {
        Self::new_with(48, 0x06)
    }

    /// Create a SHA3-512 context (64-byte / 512-bit digest, rate = 72).
    pub fn sha3_512() -> Self {
        Self::new_with(64, 0x06)
    }

    /// Create a generic SHA-3 / Keccak context with specified output size
    /// and padding byte.
    pub fn new(md_size: usize, pad: u8) -> Self {
        Self::new_with(md_size, pad)
    }

    /// Apply 10*1 padding, absorb the final block, and transition to
    /// squeeze phase. Called once internally before extracting output.
    fn pad_and_finalize(&mut self) {
        let mut last_block = vec![0u8; self.block_size];
        let buf_len = self.buf.len();
        last_block[..buf_len].copy_from_slice(&self.buf);
        last_block[buf_len] = self.pad;
        last_block[self.block_size - 1] |= 0x80;

        xor_block_into_state(&mut self.state, &last_block, self.block_size);
        self.state.permute();
        self.buf.clear();
        self.xof_state = XofState::Squeeze;
        self.squeeze_offset = 0;
    }
}

impl Digest for Sha3Context {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        if self.xof_state != XofState::Absorb {
            return Err(CryptoError::AlgorithmNotFound(
                "SHA-3 context already finalized; call reset() first".into(),
            ));
        }
        keccak_absorb(&mut self.state, self.block_size, &mut self.buf, data);
        Ok(())
    }

    fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        if self.xof_state != XofState::Absorb {
            return Err(CryptoError::AlgorithmNotFound(
                "SHA-3 context already finalized; call reset() first".into(),
            ));
        }
        self.pad_and_finalize();
        let mut out = vec![0u8; self.md_size];
        keccak_squeeze(
            &mut self.state,
            self.block_size,
            &mut out,
            &mut self.squeeze_offset,
        );
        Ok(out)
    }

    fn digest_size(&self) -> usize {
        self.md_size
    }
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn algorithm_name(&self) -> &'static str {
        match self.md_size {
            28 => "SHA3-224",
            32 => "SHA3-256",
            48 => "SHA3-384",
            64 => "SHA3-512",
            _ => "SHA3-custom",
        }
    }

    fn reset(&mut self) {
        self.state = KeccakState::new();
        self.buf.clear();
        self.xof_state = XofState::Absorb;
        self.squeeze_offset = 0;
    }

    fn clone_box(&self) -> Box<dyn Digest> {
        Box::new(self.clone())
    }
}

// =============================================================================
// SHAKE XOF Context (from crypto/sha/sha3.c squeeze path)
// =============================================================================

/// SHAKE128 / SHAKE256 extendable-output function (XOF) context.
///
/// SHAKE is a Keccak-based XOF that can produce arbitrary-length output.
/// After calling [`update`](ShakeContext::update) with input, use
/// [`squeeze`](ShakeContext::squeeze) to extract output bytes incrementally,
/// or [`finalize_xof`](ShakeContext::finalize_xof) for one-shot extraction.
///
/// State material is securely zeroed on drop via [`Zeroize`]/[`ZeroizeOnDrop`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShakeContext {
    inner: Sha3Context,
}

impl ShakeContext {
    /// Create a SHAKE128 context (security strength 128 bits, rate = 168 bytes).
    pub fn shake128() -> Self {
        // SHAKE128: capacity = 256 bits (32 bytes), rate = 200 - 32 = 168
        // md_size for new_with controls rate; SHAKE128 → 200 - 2*16 = 168
        Self {
            inner: Sha3Context::new_with(16, 0x1f),
        }
    }

    /// Create a SHAKE256 context (security strength 256 bits, rate = 136 bytes).
    pub fn shake256() -> Self {
        // SHAKE256: capacity = 512 bits (64 bytes), rate = 200 - 64 = 136
        // md_size for new_with controls rate; SHAKE256 → 200 - 2*32 = 136
        Self {
            inner: Sha3Context::new_with(32, 0x1f),
        }
    }

    /// Absorb input data. Can be called multiple times before squeezing.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        if self.inner.xof_state != XofState::Absorb {
            return Err(CryptoError::AlgorithmNotFound(
                "SHAKE context already in squeeze phase; call reset first".into(),
            ));
        }
        keccak_absorb(
            &mut self.inner.state,
            self.inner.block_size,
            &mut self.inner.buf,
            data,
        );
        Ok(())
    }

    /// Squeeze `output.len()` bytes from the XOF. Can be called repeatedly
    /// to extract an arbitrary amount of output.
    ///
    /// On the first call, padding is applied and the state transitions to
    /// squeeze mode.
    pub fn squeeze(&mut self, output: &mut [u8]) -> CryptoResult<()> {
        if self.inner.xof_state == XofState::Absorb {
            self.inner.pad_and_finalize();
        }
        keccak_squeeze(
            &mut self.inner.state,
            self.inner.block_size,
            output,
            &mut self.inner.squeeze_offset,
        );
        Ok(())
    }

    /// One-shot squeeze: apply padding and extract exactly `length` bytes.
    pub fn finalize_xof(&mut self, length: usize) -> CryptoResult<Vec<u8>> {
        let mut out = vec![0u8; length];
        self.squeeze(&mut out)?;
        Ok(out)
    }

    /// Reset the context to its initial state.
    pub fn reset(&mut self) {
        self.inner.reset();
    }

    /// Returns the algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        if self.inner.block_size == 168 {
            "SHAKE128"
        } else {
            "SHAKE256"
        }
    }
}

// =============================================================================
// SP 800-185 Encoding Functions (from crypto/sha/sha3_encode.c)
// =============================================================================

/// NIST SP 800-185 `right_encode(x)`: encode a non-negative integer `x` as a
/// byte string with the length appended at the end.
///
/// Used by cSHAKE and KMAC constructions.
pub fn right_encode(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00, 0x01];
    }
    let mut n = 0u8;
    let mut v = value;
    let mut tmp = [0u8; 8];
    while v > 0 {
        tmp[usize::from(n)] = (v & 0xff) as u8;
        v >>= 8;
        n += 1;
    }
    let mut out = Vec::with_capacity(usize::from(n) + 1);
    for i in (0..usize::from(n)).rev() {
        out.push(tmp[i]);
    }
    out.push(n);
    out
}

/// NIST SP 800-185 `left_encode(x)`: encode a non-negative integer `x` as a
/// byte string with the length prepended at the front.
///
/// Used by cSHAKE and KMAC constructions.
pub fn left_encode(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x01, 0x00];
    }
    let mut n = 0u8;
    let mut v = value;
    let mut tmp = [0u8; 8];
    while v > 0 {
        tmp[usize::from(n)] = (v & 0xff) as u8;
        v >>= 8;
        n += 1;
    }
    let mut out = Vec::with_capacity(usize::from(n) + 1);
    out.push(n);
    for i in (0..usize::from(n)).rev() {
        out.push(tmp[i]);
    }
    out
}

/// NIST SP 800-185 `encode_string(S)`: prepend `left_encode(len(S)*8)` to `S`.
///
/// Used in cSHAKE function-name and customization-string encoding.
pub fn encode_string(s: &[u8]) -> Vec<u8> {
    let bit_len = (s.len() as u64).saturating_mul(8);
    let mut out = left_encode(bit_len);
    out.extend_from_slice(s);
    out
}

/// NIST SP 800-185 `bytepad(X, w)`: pad the byte string `X` to a multiple
/// of `w` bytes.
///
/// Prepends `left_encode(w)` to `X`, then appends zero bytes until the
/// total length is a multiple of `w`.
pub fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let prefix = left_encode(w as u64);
    let total_unpadded = prefix.len() + x.len();
    let padded_len = if w == 0 {
        total_unpadded
    } else {
        ((total_unpadded + w - 1) / w) * w
    };
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(x);
    out.resize(padded_len, 0);
    out
}

// =============================================================================
// One-Shot Convenience Functions
// =============================================================================

/// Compute SHA-1 digest of `data` (20 bytes).
///
/// **Deprecated:** SHA-1 is cryptographically broken. Use [`sha256`] or [`sha3_256`].
#[deprecated(note = "SHA-1 is cryptographically broken; use sha256 or sha3_256")]
pub fn sha1(data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[allow(deprecated)]
    let mut ctx = Sha1Context::new();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA-224 digest of `data` (28 bytes).
pub fn sha224(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha256Context::sha224();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA-256 digest of `data` (32 bytes).
pub fn sha256(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha256Context::sha256();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA-384 digest of `data` (48 bytes).
pub fn sha384(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha512Context::sha384();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA-512 digest of `data` (64 bytes).
pub fn sha512(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha512Context::sha512();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA-512/224 digest of `data` (28 bytes).
pub fn sha512_224(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha512Context::sha512_224();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA-512/256 digest of `data` (32 bytes).
pub fn sha512_256(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha512Context::sha512_256();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA3-224 digest of `data` (28 bytes).
pub fn sha3_224(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha3Context::sha3_224();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA3-256 digest of `data` (32 bytes).
pub fn sha3_256(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha3Context::sha3_256();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA3-384 digest of `data` (48 bytes).
pub fn sha3_384(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha3Context::sha3_384();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHA3-512 digest of `data` (64 bytes).
pub fn sha3_512(data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = Sha3Context::sha3_512();
    ctx.update(data)?;
    ctx.finalize()
}

/// Compute SHAKE128 XOF of `data`, producing `output_len` bytes.
pub fn shake128(data: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let mut ctx = ShakeContext::shake128();
    ctx.update(data)?;
    ctx.finalize_xof(output_len)
}

/// Compute SHAKE256 XOF of `data`, producing `output_len` bytes.
pub fn shake256(data: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let mut ctx = ShakeContext::shake256();
    ctx.update(data)?;
    ctx.finalize_xof(output_len)
}

// =============================================================================
// ShaAlgorithm Enum + Factory
// =============================================================================

/// Enumeration of all supported SHA-family digest algorithms.
///
/// Used by [`create_sha_digest`] to construct the appropriate hash context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShaAlgorithm {
    /// SHA-1 (160-bit, legacy — cryptographically broken).
    Sha1,
    /// SHA-224 (224-bit truncation of SHA-256).
    Sha224,
    /// SHA-256 (256-bit).
    Sha256,
    /// SHA-384 (384-bit truncation of SHA-512).
    Sha384,
    /// SHA-512 (512-bit).
    Sha512,
    /// SHA-512/224 (224-bit truncation of SHA-512).
    Sha512_224,
    /// SHA-512/256 (256-bit truncation of SHA-512).
    Sha512_256,
    /// SHA3-224 (224-bit, Keccak-based).
    Sha3_224,
    /// SHA3-256 (256-bit, Keccak-based).
    Sha3_256,
    /// SHA3-384 (384-bit, Keccak-based).
    Sha3_384,
    /// SHA3-512 (512-bit, Keccak-based).
    Sha3_512,
}

impl ShaAlgorithm {
    /// Returns the canonical name of the algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_224 => "SHA-512/224",
            Self::Sha512_256 => "SHA-512/256",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
        }
    }
}

/// Factory function: create a boxed [`Digest`] for the given SHA algorithm.
///
/// Uses `tracing::trace!` to log algorithm selection for observability per
/// AAP §0.8.5.
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] only for forward-compatibility
/// extensions; all current `ShaAlgorithm` variants are handled.
#[allow(deprecated)]
pub fn create_sha_digest(alg: ShaAlgorithm) -> CryptoResult<Box<dyn Digest>> {
    tracing::trace!(algorithm = %alg.name(), "Creating SHA digest context");
    match alg {
        ShaAlgorithm::Sha1 => Ok(Box::new(Sha1Context::new())),
        ShaAlgorithm::Sha224 => Ok(Box::new(Sha256Context::sha224())),
        ShaAlgorithm::Sha256 => Ok(Box::new(Sha256Context::sha256())),
        ShaAlgorithm::Sha384 => Ok(Box::new(Sha512Context::sha384())),
        ShaAlgorithm::Sha512 => Ok(Box::new(Sha512Context::sha512())),
        ShaAlgorithm::Sha512_224 => Ok(Box::new(Sha512Context::sha512_224())),
        ShaAlgorithm::Sha512_256 => Ok(Box::new(Sha512Context::sha512_256())),
        ShaAlgorithm::Sha3_224 => Ok(Box::new(Sha3Context::sha3_224())),
        ShaAlgorithm::Sha3_256 => Ok(Box::new(Sha3Context::sha3_256())),
        ShaAlgorithm::Sha3_384 => Ok(Box::new(Sha3Context::sha3_384())),
        ShaAlgorithm::Sha3_512 => Ok(Box::new(Sha3Context::sha3_512())),
    }
}
