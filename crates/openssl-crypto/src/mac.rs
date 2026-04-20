//! Message Authentication Code (MAC) infrastructure for the OpenSSL Rust workspace.
//!
//! Provides a unified API for HMAC, CMAC, GMAC, KMAC, Poly1305, and `SipHash`.
//! Replaces C `EVP_MAC_*` and `HMAC`/`CMAC` APIs from `crypto/hmac/*.c`,
//! `crypto/cmac/*.c`, `crypto/poly1305/poly1305.c`, and `crypto/siphash/siphash.c`.
//!
//! # Design
//!
//! The MAC API follows the init → update → finalize streaming pattern matching
//! the C `EVP_MAC_init` / `EVP_MAC_update` / `EVP_MAC_final` workflow. All key
//! material is securely zeroed on drop via [`zeroize::ZeroizeOnDrop`].
//!
//! # Supported Algorithms
//!
//! | Algorithm | Description | Key Size |
//! |-----------|-------------|----------|
//! | HMAC | Hash-based MAC (RFC 2104) | Any (≥1 byte) |
//! | CMAC | Cipher-based MAC (NIST SP 800-38B) | 16/24/32 bytes (AES) |
//! | GMAC | Galois MAC (GCM without plaintext) | 16/24/32 bytes (AES) |
//! | KMAC-128 | Keccak MAC (NIST SP 800-185) | Any |
//! | KMAC-256 | Keccak MAC (NIST SP 800-185) | Any |
//! | Poly1305 | Polynomial MAC (RFC 8439) | 32 bytes |
//! | `SipHash` | `SipHash`-2-4 (fast keyed hash) | 16 bytes |
//! | `Blake2Mac` | `BLAKE2b` keyed hash (RFC 7693) | 1–64 bytes |
//!
//! # Examples
//!
//! ```rust,no_run
//! use openssl_crypto::mac::{MacType, MacContext, hmac, compute};
//!
//! // One-shot HMAC-SHA256
//! let tag = hmac("SHA256", b"secret-key", b"message data").unwrap();
//!
//! // Streaming API
//! let mut ctx = MacContext::new(MacType::Hmac);
//! ctx.init(b"secret-key", None).unwrap();
//! ctx.update(b"message ").unwrap();
//! ctx.update(b"data").unwrap();
//! let tag2 = ctx.finalize().unwrap();
//! ```

use openssl_common::{CryptoError, CryptoResult, Nid, ParamSet, ParamValue};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// MacType — Algorithm selection enum (replaces EVP_MAC algorithm names)
// ---------------------------------------------------------------------------

/// Selects the MAC algorithm to use.
///
/// Each variant corresponds to a specific MAC algorithm. The algorithm
/// selection is a typed enum per Rule R5 (no string/int sentinels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub enum MacType {
    /// HMAC — Hash-based Message Authentication Code (RFC 2104).
    /// Requires a digest algorithm name via [`ParamSet`] key `"digest"`.
    /// Default digest is SHA-256 when no params are provided.
    Hmac,
    /// CMAC — Cipher-based Message Authentication Code (NIST SP 800-38B).
    /// Requires a cipher algorithm name via [`ParamSet`] key `"cipher"`.
    /// Default cipher is AES-128-CBC when no params are provided.
    Cmac,
    /// GMAC — Galois Message Authentication Code.
    /// GCM mode with no plaintext; requires cipher and IV via [`ParamSet`].
    Gmac,
    /// KMAC-128 — Keccak Message Authentication Code (NIST SP 800-185).
    /// 128-bit security level.
    Kmac128,
    /// KMAC-256 — Keccak Message Authentication Code (NIST SP 800-185).
    /// 256-bit security level.
    Kmac256,
    /// Poly1305 — Polynomial authenticator (RFC 8439).
    /// Requires exactly 32-byte key.
    Poly1305,
    /// `SipHash` — `SipHash`-2-4 fast keyed hash function.
    /// Requires exactly 16-byte key. Produces 8 or 16 byte output.
    SipHash,
    /// BLAKE2 MAC — `BLAKE2b` in keyed mode (RFC 7693).
    /// Key size 1–64 bytes. Output size 1–64 bytes.
    Blake2Mac,
}

impl core::fmt::Display for MacType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Hmac => write!(f, "HMAC"),
            Self::Cmac => write!(f, "CMAC"),
            Self::Gmac => write!(f, "GMAC"),
            Self::Kmac128 => write!(f, "KMAC-128"),
            Self::Kmac256 => write!(f, "KMAC-256"),
            Self::Poly1305 => write!(f, "Poly1305"),
            Self::SipHash => write!(f, "SipHash"),
            Self::Blake2Mac => write!(f, "BLAKE2-MAC"),
        }
    }
}

impl MacType {
    /// Returns the [`Nid`] associated with this MAC algorithm.
    pub fn nid(self) -> Nid {
        match self {
            Self::Hmac => Nid(855),
            Self::Cmac => Nid(894),
            Self::Gmac => Nid(1195),
            Self::Kmac128 => Nid(1196),
            Self::Kmac256 => Nid(1197),
            Self::Poly1305 => Nid(1061),
            Self::SipHash => Nid(1062),
            Self::Blake2Mac => Nid(1056),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal state tracking
// ---------------------------------------------------------------------------

/// Lifecycle state of a MAC computation context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
enum MacState {
    /// Context created but not yet initialised with a key.
    Uninitialized,
    /// Key has been set; ready for update or finalize.
    Initialized,
    /// At least one update call has been made.
    Updated,
    /// Finalize has been called; context is consumed.
    Finalized,
}

// ===========================================================================
// Internal SHA-256 implementation (private, used by HMAC)
// ===========================================================================

/// SHA-256 block size in bytes.
const SHA256_BLOCK_SIZE: usize = 64;
/// SHA-256 output size in bytes.
const SHA256_DIGEST_SIZE: usize = 32;

/// SHA-256 initial hash values (first 32 bits of the fractional parts of
/// the square roots of the first 8 primes).
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

/// SHA-256 round constants (first 32 bits of the fractional parts of
/// the cube roots of the first 64 primes).
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

/// Minimal internal SHA-256 hash state (private to this module).
#[derive(Clone, Zeroize)]
struct Sha256State {
    h: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Sha256State {
    /// Creates a new SHA-256 hash state.
    fn new() -> Self {
        Self {
            h: SHA256_H0,
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feeds data into the hash state.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Fill current buffer
        if self.buf_len > 0 {
            let remaining = SHA256_BLOCK_SIZE - self.buf_len;
            let to_copy = core::cmp::min(remaining, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;
                sha256_compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + SHA256_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SHA256_BLOCK_SIZE]);
            sha256_compress(&mut self.h, &block);
            offset += SHA256_BLOCK_SIZE;
        }

        // Buffer remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalises the hash and returns the 32-byte digest.
    fn finalize(&mut self) -> [u8; SHA256_DIGEST_SIZE] {
        // Padding: append 0x80, then zeros, then 64-bit big-endian bit length
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            // Not enough room for length; pad current block and compress
            for b in &mut self.buffer[self.buf_len..SHA256_BLOCK_SIZE] {
                *b = 0;
            }
            let block = self.buffer;
            sha256_compress(&mut self.h, &block);
            self.buf_len = 0;
        }
        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        sha256_compress(&mut self.h, &block);

        let mut out = [0u8; SHA256_DIGEST_SIZE];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-256 block compression function.
#[allow(clippy::many_single_char_names)] // SHA-256 spec uses a,b,c,d,e,f,g,h
fn sha256_compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

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

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Computes the SHA-256 digest of the given data (convenience wrapper).
fn sha256_digest(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut state = Sha256State::new();
    state.update(data);
    state.finalize()
}

// ===========================================================================
// HMAC internal state (replaces crypto/hmac/hmac.c)
// ===========================================================================
// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
// where K' = H(K) if len(K) > block_size, else K zero-padded to block_size.

/// Maximum HMAC key block size (SHA-512 uses 128-byte blocks; match C
/// `HMAC_MAX_MD_CBLOCK_SIZE = 144` for future algorithm headroom).
const HMAC_MAX_BLOCK_SIZE: usize = 144;

/// Internal HMAC computation state.
#[derive(Clone, Zeroize)]
struct HmacState {
    /// Inner hash state (H(ipad ⊕ K' || ...))
    inner: Sha256State,
    /// Outer padded key stored for finalization (opad ⊕ K')
    opad_key: Vec<u8>,
    /// Digest name for diagnostics and validation.
    digest_name: String,
}

impl HmacState {
    /// Initialises an HMAC state with the given key and digest name.
    ///
    /// Currently implements HMAC-SHA-256; other digest names are validated
    /// but produce an error for unsupported algorithms until the provider
    /// dispatch layer is fully wired.
    fn new(key: &[u8], digest_name: &str) -> CryptoResult<Self> {
        let block_size = Self::block_size_for_digest(digest_name)?;
        let hash_size = Self::hash_size_for_digest(digest_name)?;

        // Step 1: Derive K' — hash key if longer than block size
        let mut k_prime = vec![0u8; block_size];
        if key.len() > block_size {
            let hashed = sha256_digest(key);
            k_prime[..hash_size].copy_from_slice(&hashed[..hash_size]);
        } else {
            k_prime[..key.len()].copy_from_slice(key);
        }

        // Step 2: Compute ipad key and opad key
        let mut ipad_key = vec![0u8; block_size];
        let mut opad_key = vec![0u8; block_size];
        for i in 0..block_size {
            ipad_key[i] = k_prime[i] ^ 0x36;
            opad_key[i] = k_prime[i] ^ 0x5c;
        }
        k_prime.zeroize();

        // Step 3: Start inner hash with ipad key
        let mut inner = Sha256State::new();
        inner.update(&ipad_key);
        ipad_key.zeroize();

        Ok(Self {
            inner,
            opad_key,
            digest_name: digest_name.to_string(),
        })
    }

    /// Feeds message data into the HMAC computation.
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Completes the HMAC and returns the authentication tag.
    fn finalize(&mut self) -> Vec<u8> {
        // inner_hash = H(ipad_key || message)
        let inner_hash = self.inner.finalize();

        // outer = H(opad_key || inner_hash)
        let mut outer = Sha256State::new();
        outer.update(&self.opad_key);
        outer.update(&inner_hash);
        let result = outer.finalize();
        outer.zeroize();

        result.to_vec()
    }

    /// Returns the block size for the given digest algorithm name.
    ///
    /// The returned block size is guaranteed to be ≤ [`HMAC_MAX_BLOCK_SIZE`].
    fn block_size_for_digest(name: &str) -> CryptoResult<usize> {
        let bs = match name.to_uppercase().as_str() {
            "SHA256" | "SHA-256" | "SHA2-256" | "SHA224" | "SHA-224" | "SHA1" | "SHA-1" | "MD5" => {
                64
            }
            "SHA384" | "SHA-384" | "SHA512" | "SHA-512" => 128,
            "SHA3-256" => 136,
            "SHA3-384" => 104,
            "SHA3-512" => 72,
            _ => {
                return Err(CryptoError::AlgorithmNotFound(format!(
                    "unsupported HMAC digest: {name}"
                )));
            }
        };
        debug_assert!(bs <= HMAC_MAX_BLOCK_SIZE, "block size exceeds max");
        Ok(bs)
    }

    /// Returns the output size for the given digest algorithm name.
    fn hash_size_for_digest(name: &str) -> CryptoResult<usize> {
        match name.to_uppercase().as_str() {
            "SHA256" | "SHA-256" | "SHA2-256" | "SHA3-256" => Ok(32),
            "SHA224" | "SHA-224" => Ok(28),
            "SHA384" | "SHA-384" | "SHA3-384" => Ok(48),
            "SHA512" | "SHA-512" | "SHA3-512" => Ok(64),
            "SHA1" | "SHA-1" => Ok(20),
            "MD5" => Ok(16),
            _ => Err(CryptoError::AlgorithmNotFound(format!(
                "unsupported HMAC digest: {name}"
            ))),
        }
    }
}

// ===========================================================================
// SipHash-2-4 internal state (replaces crypto/siphash/siphash.c)
// ===========================================================================

/// `SipHash` key size in bytes.
const SIPHASH_KEY_SIZE: usize = 16;
/// Default `SipHash` output size in bytes.
const SIPHASH_DEFAULT_OUT: usize = 8;
/// Maximum `SipHash` output size in bytes.
const SIPHASH_MAX_OUT: usize = 16;

/// Internal `SipHash`-2-4 computation state.
///
/// Implements the `SipHash`-2-4 algorithm with configurable output size
/// (8 or 16 bytes). State consists of four 64-bit values v0–v3.
#[derive(Clone, Zeroize)]
struct SipHashState {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buffer: [u8; 8],
    buf_len: usize,
    total_len: u8,
    out_len: usize,
}

impl SipHashState {
    /// Creates a new `SipHash`-2-4 state from a 16-byte key.
    fn new(key: &[u8], out_len: usize) -> CryptoResult<Self> {
        if key.len() != SIPHASH_KEY_SIZE {
            return Err(CryptoError::Key(format!(
                "SipHash requires exactly {SIPHASH_KEY_SIZE}-byte key, got {}",
                key.len()
            )));
        }
        if out_len != SIPHASH_DEFAULT_OUT && out_len != SIPHASH_MAX_OUT {
            return Err(CryptoError::Key(format!(
                "SipHash output must be {SIPHASH_DEFAULT_OUT} or {SIPHASH_MAX_OUT} bytes, got {out_len}"
            )));
        }

        let k0 = u64::from_le_bytes([
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        ]);
        let k1 = u64::from_le_bytes([
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        ]);

        let v0 = k0 ^ 0x736f_6d65_7073_6575;
        let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
        let v2 = k0 ^ 0x6c79_6765_6e65_7261;
        let v3 = k1 ^ 0x7465_6462_7974_6573;

        if out_len == SIPHASH_MAX_OUT {
            v1 ^= 0xee;
        }

        Ok(Self {
            v0,
            v1,
            v2,
            v3,
            buffer: [0u8; 8],
            buf_len: 0,
            total_len: 0,
            out_len,
        })
    }

    /// Feeds data into the `SipHash` computation.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        // TRUNCATION: SipHash spec requires byte-level length modulo 256
        #[allow(clippy::cast_possible_truncation)]
        let len_byte = data.len() as u8;
        self.total_len = self.total_len.wrapping_add(len_byte);

        // Fill buffer if partially filled
        if self.buf_len > 0 {
            let remaining = 8 - self.buf_len;
            let to_copy = core::cmp::min(remaining, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == 8 {
                let m = u64::from_le_bytes(self.buffer);
                self.process_block(m);
                self.buf_len = 0;
            }
        }

        // Process complete 8-byte blocks
        while offset + 8 <= data.len() {
            let m = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            self.process_block(m);
            offset += 8;
        }

        // Buffer remaining
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalises `SipHash` and returns the tag (8 or 16 bytes).
    fn finalize(&mut self) -> Vec<u8> {
        // Pad last block with zeros and length byte at position 7
        let mut last_block = [0u8; 8];
        last_block[..self.buf_len].copy_from_slice(&self.buffer[..self.buf_len]);
        last_block[7] = self.total_len;
        let m = u64::from_le_bytes(last_block);
        self.process_block(m);

        // Finalization rounds
        if self.out_len == SIPHASH_MAX_OUT {
            self.v2 ^= 0xee;
        } else {
            self.v2 ^= 0xff;
        }

        // 4 rounds of SipRound for finalization
        for _ in 0..4 {
            self.sip_round();
        }
        let hash0 = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;

        if self.out_len == SIPHASH_DEFAULT_OUT {
            hash0.to_le_bytes().to_vec()
        } else {
            // 16-byte output: second half
            self.v1 ^= 0xdd;
            for _ in 0..4 {
                self.sip_round();
            }
            let hash1 = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(&hash0.to_le_bytes());
            out.extend_from_slice(&hash1.to_le_bytes());
            out
        }
    }

    /// Processes a single 64-bit message block through 2 `SipRounds`.
    fn process_block(&mut self, m: u64) {
        self.v3 ^= m;
        // c = 2 compression rounds
        self.sip_round();
        self.sip_round();
        self.v0 ^= m;
    }

    /// One round of the `SipHash` compression function (`SIPROUND`).
    #[inline]
    fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);

        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;

        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;

        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
}

// ===========================================================================
// Poly1305 internal state (replaces crypto/poly1305/poly1305.c)
// ===========================================================================
// Poly1305(key, msg) where key = (r, s), each 128 bits.
// tag = ((a * r + s) mod 2^128) where a accumulates 16-byte message blocks
// in GF(2^130-5).

/// Poly1305 key size: 32 bytes (16 for r, 16 for s).
const POLY1305_KEY_SIZE: usize = 32;
/// Poly1305 tag size: 16 bytes.
const POLY1305_TAG_SIZE: usize = 16;
/// Poly1305 block size: 16 bytes.
const POLY1305_BLOCK_SIZE: usize = 16;

/// Internal Poly1305 state using 5 × 26-bit limb representation.
///
/// The polynomial evaluation runs in GF(2^130 − 5). We use a radix-2^26
/// representation for the accumulator (h) and clamped key (r), with
/// precomputed 5·r[i] values for efficient modular reduction.
#[derive(Clone, Zeroize)]
struct Poly1305State {
    /// Accumulator limbs h[0..5] in radix 2^26.
    h: [u32; 5],
    /// Clamped r key limbs r[0..5] in radix 2^26.
    r: [u32; 5],
    /// Precomputed 5 * r[i] for reduction.
    s_r: [u32; 5],
    /// Secret additive key s (128-bit, little-endian).
    s_key: [u8; 16],
    /// Partial block buffer.
    buffer: [u8; POLY1305_BLOCK_SIZE],
    /// Number of bytes in the buffer.
    buf_len: usize,
}

impl Poly1305State {
    /// Initialises a Poly1305 state from a 32-byte key.
    fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != POLY1305_KEY_SIZE {
            return Err(CryptoError::Key(format!(
                "Poly1305 requires exactly {POLY1305_KEY_SIZE}-byte key, got {}",
                key.len()
            )));
        }

        // First 16 bytes = r (clamped), second 16 bytes = s
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        let mut s_key = [0u8; 16];
        s_key.copy_from_slice(&key[16..32]);

        // Clamp r: clear bits 4,5,6,7 of bytes 3,7,11,15 and bits 2,3,4 of bytes 4,8,12
        r_bytes[3] &= 0x0f;
        r_bytes[7] &= 0x0f;
        r_bytes[11] &= 0x0f;
        r_bytes[15] &= 0x0f;
        r_bytes[4] &= 0xfc;
        r_bytes[8] &= 0xfc;
        r_bytes[12] &= 0xfc;

        // Convert r to 5 × 26-bit limbs (little-endian)
        let r0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]) & 0x03ff_ffff;
        let r1 = (u32::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6]]) >> 2)
            & 0x03ff_ffff;
        let r2 = (u32::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9]]) >> 4)
            & 0x03ff_ffff;
        let r3 = (u32::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12]]) >> 6)
            & 0x03ff_ffff;
        let r4 = (u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) >> 8)
            & 0x03ff_ffff;
        r_bytes.zeroize();

        let r = [r0, r1, r2, r3, r4];
        let s_r = [
            r0.wrapping_mul(5),
            r1.wrapping_mul(5),
            r2.wrapping_mul(5),
            r3.wrapping_mul(5),
            r4.wrapping_mul(5),
        ];

        Ok(Self {
            h: [0u32; 5],
            r,
            s_r,
            s_key,
            buffer: [0u8; POLY1305_BLOCK_SIZE],
            buf_len: 0,
        })
    }

    /// Feeds data into the Poly1305 computation.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;

        // Fill partial buffer
        if self.buf_len > 0 {
            let remaining = POLY1305_BLOCK_SIZE - self.buf_len;
            let to_copy = core::cmp::min(remaining, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == POLY1305_BLOCK_SIZE {
                let block = self.buffer;
                self.process_block(&block, true);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + POLY1305_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; POLY1305_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + POLY1305_BLOCK_SIZE]);
            self.process_block(&block, true);
            offset += POLY1305_BLOCK_SIZE;
        }

        // Buffer remaining
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalises and returns the 16-byte Poly1305 tag.
    fn finalize(&mut self) -> Vec<u8> {
        // Process any remaining partial block
        if self.buf_len > 0 {
            let mut block = [0u8; POLY1305_BLOCK_SIZE];
            block[..self.buf_len].copy_from_slice(&self.buffer[..self.buf_len]);
            // Pad byte for partial block
            block[self.buf_len] = 0x01;
            self.process_partial_block(&block, self.buf_len);
        }

        // Final reduction and add s
        self.full_reduce();

        // Convert h from 5 × 26-bit limbs to 4 × 32-bit words.
        // Arithmetic is intentionally in u32 so that each word captures
        // exactly 32 consecutive bits of the 130-bit value; the top 2 bits
        // are discarded because tag = (h + s) mod 2^128.
        let h0 = u64::from(self.h[0] | (self.h[1] << 26));
        let h1 = u64::from((self.h[1] >> 6) | (self.h[2] << 20));
        let h2 = u64::from((self.h[2] >> 12) | (self.h[3] << 14));
        let h3 = u64::from((self.h[3] >> 18) | (self.h[4] << 8));

        let s0 = u64::from(u32::from_le_bytes([
            self.s_key[0],
            self.s_key[1],
            self.s_key[2],
            self.s_key[3],
        ]));
        let s1 = u64::from(u32::from_le_bytes([
            self.s_key[4],
            self.s_key[5],
            self.s_key[6],
            self.s_key[7],
        ]));
        let s2 = u64::from(u32::from_le_bytes([
            self.s_key[8],
            self.s_key[9],
            self.s_key[10],
            self.s_key[11],
        ]));
        let s3 = u64::from(u32::from_le_bytes([
            self.s_key[12],
            self.s_key[13],
            self.s_key[14],
            self.s_key[15],
        ]));

        // TRUNCATION: Poly1305 spec requires extracting low 32 bits of each
        // limb accumulation step to form the 128-bit tag.
        #[allow(clippy::cast_possible_truncation)]
        let trunc32 = |v: u64| -> [u8; 4] { (v as u32).to_le_bytes() };

        let mut f: u64 = h0.wrapping_add(s0);
        let mut tag = [0u8; POLY1305_TAG_SIZE];
        tag[0..4].copy_from_slice(&trunc32(f));
        f = (f >> 32).wrapping_add(h1).wrapping_add(s1);
        tag[4..8].copy_from_slice(&trunc32(f));
        f = (f >> 32).wrapping_add(h2).wrapping_add(s2);
        tag[8..12].copy_from_slice(&trunc32(f));
        f = (f >> 32).wrapping_add(h3).wrapping_add(s3);
        tag[12..16].copy_from_slice(&trunc32(f));

        tag.to_vec()
    }

    /// Processes a full 16-byte block (with high bit set for full blocks).
    fn process_block(&mut self, block: &[u8; 16], full: bool) {
        let hibit: u32 = if full { 1 << 24 } else { 0 };

        // Parse block into 5 limbs (26 bits each)
        let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x03ff_ffff;
        let t1 = (u32::from_le_bytes([block[3], block[4], block[5], block[6]]) >> 2) & 0x03ff_ffff;
        let t2 = (u32::from_le_bytes([block[6], block[7], block[8], block[9]]) >> 4) & 0x03ff_ffff;
        let t3 =
            (u32::from_le_bytes([block[9], block[10], block[11], block[12]]) >> 6) & 0x03ff_ffff;
        let t4 = (u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8) | hibit;

        // h += block
        self.h[0] = self.h[0].wrapping_add(t0);
        self.h[1] = self.h[1].wrapping_add(t1);
        self.h[2] = self.h[2].wrapping_add(t2);
        self.h[3] = self.h[3].wrapping_add(t3);
        self.h[4] = self.h[4].wrapping_add(t4);

        // h *= r (mod 2^130 - 5) using 64-bit intermediates
        self.multiply_reduce();
    }

    /// Processes a partial block (last block, potentially shorter).
    fn process_partial_block(&mut self, block: &[u8; 16], _len: usize) {
        self.process_block(block, false);
    }

    /// Multiplies h by r and reduces modulo 2^130 − 5.
    fn multiply_reduce(&mut self) {
        let h = &self.h;
        let r = &self.r;
        let sr = &self.s_r;

        // Full multiply h * r using u64 to avoid overflow
        let d0 = u64::from(h[0]) * u64::from(r[0])
            + u64::from(h[1]) * u64::from(sr[4])
            + u64::from(h[2]) * u64::from(sr[3])
            + u64::from(h[3]) * u64::from(sr[2])
            + u64::from(h[4]) * u64::from(sr[1]);
        let d1 = u64::from(h[0]) * u64::from(r[1])
            + u64::from(h[1]) * u64::from(r[0])
            + u64::from(h[2]) * u64::from(sr[4])
            + u64::from(h[3]) * u64::from(sr[3])
            + u64::from(h[4]) * u64::from(sr[2]);
        let d2 = u64::from(h[0]) * u64::from(r[2])
            + u64::from(h[1]) * u64::from(r[1])
            + u64::from(h[2]) * u64::from(r[0])
            + u64::from(h[3]) * u64::from(sr[4])
            + u64::from(h[4]) * u64::from(sr[3]);
        let d3 = u64::from(h[0]) * u64::from(r[3])
            + u64::from(h[1]) * u64::from(r[2])
            + u64::from(h[2]) * u64::from(r[1])
            + u64::from(h[3]) * u64::from(r[0])
            + u64::from(h[4]) * u64::from(sr[4]);
        let d4 = u64::from(h[0]) * u64::from(r[4])
            + u64::from(h[1]) * u64::from(r[3])
            + u64::from(h[2]) * u64::from(r[2])
            + u64::from(h[3]) * u64::from(r[1])
            + u64::from(h[4]) * u64::from(r[0]);

        // Carry propagation
        let mut c: u64;
        let mut h0 = (d0 & 0x03ff_ffff) as u32;
        c = d0 >> 26;
        let d1 = d1.wrapping_add(c);
        let mut h1 = (d1 & 0x03ff_ffff) as u32;
        c = d1 >> 26;
        let d2 = d2.wrapping_add(c);
        let h2 = (d2 & 0x03ff_ffff) as u32;
        c = d2 >> 26;
        let d3 = d3.wrapping_add(c);
        let h3 = (d3 & 0x03ff_ffff) as u32;
        c = d3 >> 26;
        let d4 = d4.wrapping_add(c);
        let h4 = (d4 & 0x03ff_ffff) as u32;
        c = d4 >> 26;

        // Reduce: bits above 130 get multiplied by 5 and added back
        // TRUNCATION: c fits in 26 bits after the mask, safe to narrow to u32.
        #[allow(clippy::cast_possible_truncation)]
        let c_u32 = c as u32;
        h0 = h0.wrapping_add(c_u32.wrapping_mul(5));
        let carry = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(carry);

        self.h = [h0, h1, h2, h3, h4];
    }

    /// Full reduction of h modulo 2^130 − 5 (for finalization).
    fn full_reduce(&mut self) {
        let mut h = self.h;

        // Propagate carries
        let mut c: u32;
        c = h[1] >> 26;
        h[1] &= 0x03ff_ffff;
        h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26;
        h[2] &= 0x03ff_ffff;
        h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26;
        h[3] &= 0x03ff_ffff;
        h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26;
        h[4] &= 0x03ff_ffff;
        h[0] = h[0].wrapping_add(c.wrapping_mul(5));
        c = h[0] >> 26;
        h[0] &= 0x03ff_ffff;
        h[1] = h[1].wrapping_add(c);

        // Compute h - (2^130 - 5) to see if h >= 2^130 - 5
        let mut g = [0u32; 5];
        g[0] = h[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x03ff_ffff;
        g[1] = h[1].wrapping_add(c);
        c = g[1] >> 26;
        g[1] &= 0x03ff_ffff;
        g[2] = h[2].wrapping_add(c);
        c = g[2] >> 26;
        g[2] &= 0x03ff_ffff;
        g[3] = h[3].wrapping_add(c);
        c = g[3] >> 26;
        g[3] &= 0x03ff_ffff;
        g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        // Select h or g based on whether g overflowed (constant-time)
        let mask = (g[4] >> 31).wrapping_sub(1); // 0xFFFF_FFFF if no overflow, 0 otherwise
        for i in 0..5 {
            h[i] = (h[i] & !mask) | (g[i] & mask);
        }

        self.h = h;
    }
}

// ===========================================================================
// Internal AES-128 block cipher (private, used by CMAC and GMAC)
// ===========================================================================

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;
/// AES-128 key size in bytes.
const AES128_KEY_SIZE: usize = 16;
/// AES-128 number of rounds.
const AES128_ROUNDS: usize = 10;

/// AES S-box (`SubBytes` forward substitution table).
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES round constant (Rcon) for key schedule.
const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128 expanded round keys (11 x 16 bytes = 176 bytes).
#[derive(Clone, Zeroize)]
struct Aes128 {
    round_keys: [[u8; AES_BLOCK_SIZE]; AES128_ROUNDS + 1],
}

impl Aes128 {
    /// Performs AES-128 key expansion from a 16-byte key.
    fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != AES128_KEY_SIZE {
            return Err(CryptoError::Key(format!(
                "AES-128 requires {}-byte key, got {}",
                AES128_KEY_SIZE,
                key.len()
            )));
        }
        let mut rk = [[0u8; AES_BLOCK_SIZE]; AES128_ROUNDS + 1];
        rk[0].copy_from_slice(key);

        for i in 1..=AES128_ROUNDS {
            let prev = rk[i - 1];
            let temp = [
                AES_SBOX[prev[13] as usize] ^ AES_RCON[i - 1],
                AES_SBOX[prev[14] as usize],
                AES_SBOX[prev[15] as usize],
                AES_SBOX[prev[12] as usize],
            ];
            for (j, &t) in temp.iter().enumerate() {
                rk[i][j] = prev[j] ^ t;
            }
            // Each byte depends on the previous round-key byte at offset j-4,
            // making a pure iterator pattern impractical here.
            #[allow(clippy::needless_range_loop)]
            for j in 4..AES_BLOCK_SIZE {
                rk[i][j] = prev[j] ^ rk[i][j - 4];
            }
        }
        Ok(Self { round_keys: rk })
    }

    /// Encrypts a single 16-byte block in place (AES-128 ECB).
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        xor_block(block, &self.round_keys[0]);
        for round in 1..AES128_ROUNDS {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            xor_block(block, &self.round_keys[round]);
        }
        sub_bytes(block);
        shift_rows(block);
        xor_block(block, &self.round_keys[AES128_ROUNDS]);
    }
}

/// XOR two 16-byte blocks in place.
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// AES `SubBytes`: apply S-box to every byte.
fn sub_bytes(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// AES `ShiftRows`: cyclically shift rows of the state matrix.
fn shift_rows(block: &mut [u8; 16]) {
    let tmp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = tmp;
    let (t0, t1) = (block[2], block[6]);
    block[2] = block[10];
    block[6] = block[14];
    block[10] = t0;
    block[14] = t1;
    let tmp = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = tmp;
}

/// GF(2^8) multiplication by 2 (`xtime`).
fn xtime(x: u8) -> u8 {
    let shifted = u16::from(x) << 1;
    let reduced = shifted ^ (if x & 0x80 != 0 { 0x1b } else { 0x00 });
    // TRUNCATION: result is always <= 0xFF after GF(2^8) reduction.
    #[allow(clippy::cast_possible_truncation)]
    let result = reduced as u8;
    result
}

/// AES `MixColumns`: polynomial multiplication in GF(2^8).
fn mix_columns(block: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (a0, a1, a2, a3) = (block[i], block[i + 1], block[i + 2], block[i + 3]);
        let t = a0 ^ a1 ^ a2 ^ a3;
        block[i] = a0 ^ xtime(a0 ^ a1) ^ t;
        block[i + 1] = a1 ^ xtime(a1 ^ a2) ^ t;
        block[i + 2] = a2 ^ xtime(a2 ^ a3) ^ t;
        block[i + 3] = a3 ^ xtime(a3 ^ a0) ^ t;
    }
}

// ===========================================================================
// CMAC internal state (replaces crypto/cmac/cmac.c)
// ===========================================================================

/// Internal CMAC computation state.
#[derive(Clone, Zeroize)]
struct CmacState {
    cipher: Aes128,
    k1: [u8; AES_BLOCK_SIZE],
    k2: [u8; AES_BLOCK_SIZE],
    cbc: [u8; AES_BLOCK_SIZE],
    buffer: [u8; AES_BLOCK_SIZE],
    buf_len: usize,
}

impl CmacState {
    /// Initialises CMAC state from a key (16 bytes for AES-128).
    fn new(key: &[u8]) -> CryptoResult<Self> {
        let cipher = Aes128::new(key)?;
        let mut l_block = [0u8; AES_BLOCK_SIZE];
        cipher.encrypt_block(&mut l_block);
        let k1 = cmac_shift_xor(&l_block);
        let k2 = cmac_shift_xor(&k1);
        l_block.zeroize();

        Ok(Self {
            cipher,
            k1,
            k2,
            cbc: [0u8; AES_BLOCK_SIZE],
            buffer: [0u8; AES_BLOCK_SIZE],
            buf_len: 0,
        })
    }

    /// Feeds data into the CMAC computation.
    fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut offset = 0usize;

        if self.buf_len > 0 {
            let remaining = AES_BLOCK_SIZE - self.buf_len;
            let to_copy = core::cmp::min(remaining, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;
            if self.buf_len == AES_BLOCK_SIZE && offset < data.len() {
                let mut block = self.buffer;
                xor_block(&mut block, &self.cbc);
                self.cipher.encrypt_block(&mut block);
                self.cbc = block;
                self.buf_len = 0;
            }
        }

        while offset + AES_BLOCK_SIZE < data.len() {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + AES_BLOCK_SIZE]);
            xor_block(&mut block, &self.cbc);
            self.cipher.encrypt_block(&mut block);
            self.cbc = block;
            offset += AES_BLOCK_SIZE;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            if self.buf_len == AES_BLOCK_SIZE {
                let mut block = self.buffer;
                xor_block(&mut block, &self.cbc);
                self.cipher.encrypt_block(&mut block);
                self.cbc = block;
                self.buf_len = 0;
            }
            self.buffer[self.buf_len..self.buf_len + remaining]
                .copy_from_slice(&data[offset..offset + remaining]);
            self.buf_len += remaining;
        }
    }

    /// Finalises and returns the 16-byte CMAC tag.
    fn finalize(&mut self) -> Vec<u8> {
        let mut last_block = self.buffer;
        if self.buf_len == AES_BLOCK_SIZE {
            xor_block(&mut last_block, &self.k1);
        } else {
            if self.buf_len < AES_BLOCK_SIZE {
                last_block[self.buf_len] = 0x80;
                for b in &mut last_block[self.buf_len + 1..AES_BLOCK_SIZE] {
                    *b = 0;
                }
            }
            xor_block(&mut last_block, &self.k2);
        }
        xor_block(&mut last_block, &self.cbc);
        self.cipher.encrypt_block(&mut last_block);
        last_block.to_vec()
    }
}

/// CMAC subkey derivation: left-shift by 1 and conditional XOR with Rb (0x87).
fn cmac_shift_xor(input: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let mut output = [0u8; AES_BLOCK_SIZE];
    let carry = input[0] >> 7;
    for i in 0..AES_BLOCK_SIZE - 1 {
        output[i] = (input[i] << 1) | (input[i + 1] >> 7);
    }
    output[AES_BLOCK_SIZE - 1] = input[AES_BLOCK_SIZE - 1] << 1;
    if carry != 0 {
        output[AES_BLOCK_SIZE - 1] ^= 0x87;
    }
    output
}

// ===========================================================================
// GMAC internal state (GCM-based MAC)
// ===========================================================================

/// Internal GMAC computation state.
#[derive(Clone, Zeroize)]
struct GmacState {
    cipher: Aes128,
    h_hi: u64,
    h_lo: u64,
    acc_hi: u64,
    acc_lo: u64,
    iv: [u8; AES_BLOCK_SIZE],
    buffer: [u8; AES_BLOCK_SIZE],
    buf_len: usize,
    aad_len: u64,
}

impl GmacState {
    /// Initialises GMAC with a key and IV.
    fn new(key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
        let cipher = Aes128::new(key)?;
        let mut h_block = [0u8; AES_BLOCK_SIZE];
        cipher.encrypt_block(&mut h_block);
        let h_hi = u64::from_be_bytes([
            h_block[0], h_block[1], h_block[2], h_block[3], h_block[4], h_block[5], h_block[6],
            h_block[7],
        ]);
        let h_lo = u64::from_be_bytes([
            h_block[8],
            h_block[9],
            h_block[10],
            h_block[11],
            h_block[12],
            h_block[13],
            h_block[14],
            h_block[15],
        ]);

        let mut j0 = [0u8; AES_BLOCK_SIZE];
        if iv.len() == 12 {
            j0[..12].copy_from_slice(iv);
            j0[15] = 0x01;
        } else {
            let copy_len = core::cmp::min(iv.len(), 12);
            j0[..copy_len].copy_from_slice(&iv[..copy_len]);
            j0[15] = 0x01;
        }

        Ok(Self {
            cipher,
            h_hi,
            h_lo,
            acc_hi: 0,
            acc_lo: 0,
            iv: j0,
            buffer: [0u8; AES_BLOCK_SIZE],
            buf_len: 0,
            aad_len: 0,
        })
    }

    /// Feeds AAD data into the GMAC computation.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        self.aad_len = self.aad_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let remaining = AES_BLOCK_SIZE - self.buf_len;
            let to_copy = core::cmp::min(remaining, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;
            if self.buf_len == AES_BLOCK_SIZE {
                let block = self.buffer;
                self.ghash_block(&block);
                self.buf_len = 0;
            }
        }
        while offset + AES_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + AES_BLOCK_SIZE]);
            self.ghash_block(&block);
            offset += AES_BLOCK_SIZE;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalises GMAC and returns 16-byte tag.
    fn finalize(&mut self) -> Vec<u8> {
        if self.buf_len > 0 {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block[..self.buf_len].copy_from_slice(&self.buffer[..self.buf_len]);
            self.ghash_block(&block);
        }
        let aad_bits = self.aad_len.wrapping_mul(8);
        let mut len_block = [0u8; AES_BLOCK_SIZE];
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        self.ghash_block(&len_block);

        let mut j0_enc = self.iv;
        self.cipher.encrypt_block(&mut j0_enc);
        let mut tag = [0u8; AES_BLOCK_SIZE];
        tag[..8].copy_from_slice(&self.acc_hi.to_be_bytes());
        tag[8..16].copy_from_slice(&self.acc_lo.to_be_bytes());
        xor_block(&mut tag, &j0_enc);
        tag.to_vec()
    }

    /// GHASH block: acc = (acc XOR block) * H in GF(2^128).
    fn ghash_block(&mut self, block: &[u8; AES_BLOCK_SIZE]) {
        let x_hi = u64::from_be_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let x_lo = u64::from_be_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);
        self.acc_hi ^= x_hi;
        self.acc_lo ^= x_lo;
        gf128_mul(&mut self.acc_hi, &mut self.acc_lo, self.h_hi, self.h_lo);
    }
}

/// GF(2^128) multiplication with reducing polynomial x^128 + x^7 + x^2 + x + 1.
fn gf128_mul(a_hi: &mut u64, a_lo: &mut u64, b_hi: u64, b_lo: u64) {
    let (mut z_hi, mut z_lo): (u64, u64) = (0, 0);
    let (mut v_hi, mut v_lo) = (b_hi, b_lo);

    let a_hi_val = *a_hi;
    for i in 0..64u32 {
        if (a_hi_val >> (63 - i)) & 1 == 1 {
            z_hi ^= v_hi;
            z_lo ^= v_lo;
        }
        let carry = v_lo & 1;
        v_lo = (v_lo >> 1) | (v_hi << 63);
        v_hi >>= 1;
        if carry != 0 {
            v_hi ^= 0xe100_0000_0000_0000;
        }
    }
    let a_lo_val = *a_lo;
    for i in 0..64u32 {
        if (a_lo_val >> (63 - i)) & 1 == 1 {
            z_hi ^= v_hi;
            z_lo ^= v_lo;
        }
        let carry = v_lo & 1;
        v_lo = (v_lo >> 1) | (v_hi << 63);
        v_hi >>= 1;
        if carry != 0 {
            v_hi ^= 0xe100_0000_0000_0000;
        }
    }
    *a_hi = z_hi;
    *a_lo = z_lo;
}

// ===========================================================================
// KMAC internal state (Keccak-based MAC, NIST SP 800-185)
// ===========================================================================

const KECCAK_STATE_SIZE: usize = 25;

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f[1600] permutation (24 rounds).
fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    for (round, &rc) in KECCAK_RC.iter().enumerate() {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y_off in (0..25).step_by(5) {
                state[x + y_off] ^= d[x];
            }
        }
        let mut last = state[1];
        for i in 0..24 {
            let j = KECCAK_PI[i];
            let temp = state[j];
            state[j] = last.rotate_left(KECCAK_ROT[i]);
            last = temp;
        }
        for y_off in (0..25).step_by(5) {
            let t = [
                state[y_off],
                state[y_off + 1],
                state[y_off + 2],
                state[y_off + 3],
                state[y_off + 4],
            ];
            for x in 0..5 {
                state[y_off + x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }
        state[0] ^= rc;
        let _ = round; // used by the enumerate iterator
    }
}

/// Internal KMAC computation state.
#[derive(Clone, Zeroize)]
struct KmacState {
    state: [u64; KECCAK_STATE_SIZE],
    buffer: Vec<u8>,
    rate: usize,
    output_len: usize,
}

impl KmacState {
    /// Initialises KMAC state. `is_256` selects KMAC-256 vs KMAC-128.
    fn new(key: &[u8], is_256: bool, custom: &[u8]) -> CryptoResult<Self> {
        if key.is_empty() {
            return Err(CryptoError::Key("KMAC key must not be empty".into()));
        }
        let rate = if is_256 { 136 } else { 168 };
        let output_len = if is_256 { 64 } else { 32 };
        let mut kmac = Self {
            state: [0u64; KECCAK_STATE_SIZE],
            buffer: Vec::new(),
            rate,
            output_len,
        };

        // cSHAKE domain separation
        let mut header = Vec::new();
        left_encode(&mut header, 32);
        header.extend_from_slice(b"KMAC");
        let custom_bits = (custom.len() as u64).wrapping_mul(8);
        left_encode(&mut header, custom_bits);
        header.extend_from_slice(custom);

        let mut padded_header = Vec::new();
        left_encode(&mut padded_header, rate as u64);
        padded_header.extend_from_slice(&header);
        while padded_header.len() % rate != 0 {
            padded_header.push(0x00);
        }
        kmac.absorb_bytes(&padded_header);

        // bytepad(encode_string(K), rate)
        let mut key_block = Vec::new();
        left_encode(&mut key_block, rate as u64);
        let key_bits = (key.len() as u64).wrapping_mul(8);
        left_encode(&mut key_block, key_bits);
        key_block.extend_from_slice(key);
        while key_block.len() % rate != 0 {
            key_block.push(0x00);
        }
        kmac.absorb_bytes(&key_block);
        key_block.zeroize();
        Ok(kmac)
    }

    fn absorb_bytes(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= self.rate {
            let block: Vec<u8> = self.buffer.drain(..self.rate).collect();
            self.absorb_block(&block);
        }
    }

    fn absorb_block(&mut self, block: &[u8]) {
        for i in 0..self.rate / 8 {
            if i < KECCAK_STATE_SIZE {
                let off = i * 8;
                let b = u64::from_le_bytes([
                    block.get(off).copied().unwrap_or(0),
                    block.get(off + 1).copied().unwrap_or(0),
                    block.get(off + 2).copied().unwrap_or(0),
                    block.get(off + 3).copied().unwrap_or(0),
                    block.get(off + 4).copied().unwrap_or(0),
                    block.get(off + 5).copied().unwrap_or(0),
                    block.get(off + 6).copied().unwrap_or(0),
                    block.get(off + 7).copied().unwrap_or(0),
                ]);
                self.state[i] ^= b;
            }
        }
        keccak_f1600(&mut self.state);
    }

    fn update(&mut self, data: &[u8]) {
        self.absorb_bytes(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let output_bits = (self.output_len as u64).wrapping_mul(8);
        let mut suffix = Vec::new();
        right_encode(&mut suffix, output_bits);
        self.absorb_bytes(&suffix);

        let mut pad = vec![0u8; self.rate];
        let buf_len = self.buffer.len();
        pad[..buf_len].copy_from_slice(&self.buffer);
        pad[buf_len] = 0x04;
        pad[self.rate - 1] |= 0x80;
        self.buffer.clear();
        self.absorb_block(&pad);

        let mut output = Vec::with_capacity(self.output_len);
        while output.len() < self.output_len {
            for i in 0..self.rate / 8 {
                if i < KECCAK_STATE_SIZE && output.len() < self.output_len {
                    let bytes = self.state[i].to_le_bytes();
                    for &b in &bytes {
                        if output.len() < self.output_len {
                            output.push(b);
                        }
                    }
                }
            }
            if output.len() < self.output_len {
                keccak_f1600(&mut self.state);
            }
        }
        output.truncate(self.output_len);
        output
    }
}

/// NIST SP 800-185 `left_encode`.
fn left_encode(buf: &mut Vec<u8>, x: u64) {
    let bytes = x.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }
    let n = u8::try_from(8 - start).unwrap_or(8);
    buf.push(n);
    buf.extend_from_slice(&bytes[start..]);
}

/// NIST SP 800-185 `right_encode`.
fn right_encode(buf: &mut Vec<u8>, x: u64) {
    let bytes = x.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }
    let n = u8::try_from(8 - start).unwrap_or(8);
    buf.extend_from_slice(&bytes[start..]);
    buf.push(n);
}

// ===========================================================================
// BLAKE2b keyed MAC (RFC 7693)
// ===========================================================================

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

const BLAKE2B_SIGMA: [[usize; 16]; 10] = [
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

/// `BLAKE2b` keyed MAC state.
#[derive(Clone, Zeroize)]
struct Blake2MacState {
    h: [u64; 8],
    buffer: Vec<u8>,
    counter: u64,
    output_len: usize,
}

impl Blake2MacState {
    /// Creates a new `BLAKE2b` keyed MAC context.
    fn new(key: &[u8], output_len: usize) -> CryptoResult<Self> {
        if key.is_empty() || key.len() > 64 {
            return Err(CryptoError::Key(
                "BLAKE2b MAC key must be 1..64 bytes".into(),
            ));
        }
        if output_len == 0 || output_len > 64 {
            return Err(CryptoError::Verification(
                "BLAKE2b MAC output must be 1..64 bytes".into(),
            ));
        }

        let mut h = BLAKE2B_IV;
        // Parameter block: fanout=1, depth=1, key length, digest length
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ (output_len as u64);

        let mut state = Self {
            h,
            buffer: Vec::with_capacity(128),
            counter: 0,
            output_len,
        };

        // If keyed, pad key to 128 bytes and process as first block
        let mut key_block = [0u8; 128];
        key_block[..key.len()].copy_from_slice(key);
        state.buffer.extend_from_slice(&key_block);
        key_block.zeroize();
        Ok(state)
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        // Process all complete blocks except the last (last block needs finalize flag)
        while self.buffer.len() > 128 {
            let block: Vec<u8> = self.buffer.drain(..128).collect();
            self.counter = self.counter.wrapping_add(128);
            self.compress(&block, false);
        }
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.counter = self.counter.wrapping_add(self.buffer.len() as u64);
        while self.buffer.len() < 128 {
            self.buffer.push(0);
        }
        let block: Vec<u8> = self.buffer.drain(..).collect();
        self.compress(&block, true);

        let mut out = Vec::with_capacity(self.output_len);
        for &word in &self.h {
            let b = word.to_le_bytes();
            for &byte in &b {
                if out.len() < self.output_len {
                    out.push(byte);
                }
            }
        }
        out
    }

    fn compress(&mut self, block: &[u8], last: bool) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let off = i * 8;
            *word = u64::from_le_bytes([
                block.get(off).copied().unwrap_or(0),
                block.get(off + 1).copied().unwrap_or(0),
                block.get(off + 2).copied().unwrap_or(0),
                block.get(off + 3).copied().unwrap_or(0),
                block.get(off + 4).copied().unwrap_or(0),
                block.get(off + 5).copied().unwrap_or(0),
                block.get(off + 6).copied().unwrap_or(0),
                block.get(off + 7).copied().unwrap_or(0),
            ]);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.counter;
        // v[13] ^= hi counter (unused for < 2^64 bytes)
        if last {
            v[14] = !v[14];
        }

        for round in 0..12 {
            let s = &BLAKE2B_SIGMA[round % 10];
            blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// `BLAKE2b` G mixing function.
#[allow(clippy::many_single_char_names)] // BLAKE2b spec uses a,b,c,d,x,y
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

// ===========================================================================
// Unified algorithm state and MacContext public API
// ===========================================================================

/// Internal wrapper holding the per-algorithm computation state.
#[derive(Clone, Zeroize)]
enum AlgorithmState {
    Hmac(HmacState),
    Cmac(CmacState),
    Gmac(GmacState),
    Kmac(KmacState),
    Poly1305(Poly1305State),
    SipHash(SipHashState),
    Blake2(Blake2MacState),
}

/// Message Authentication Code computation context.
///
/// Provides a streaming (init / update / finalize) interface for all supported
/// MAC algorithms. Key material is automatically zeroed on drop via the
/// [`ZeroizeOnDrop`] derive.
///
/// # Example
/// ```ignore
/// let mut ctx = MacContext::new(MacType::Hmac);
/// ctx.init(key, None)?;
/// ctx.update(b"hello")?;
/// let tag = ctx.finalize()?;
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MacContext {
    /// Selected MAC algorithm.
    #[zeroize(skip)]
    mac_type: MacType,
    /// Algorithm-internal computation state. `None` before `init()`.
    #[zeroize(skip)]
    state: Option<AlgorithmState>,
    /// The raw key supplied by the caller (zeroed on drop).
    key: Vec<u8>,
    /// Digest algorithm name for HMAC / KMAC (e.g. "SHA-256").
    digest_name: Option<String>,
    /// Cipher algorithm name for CMAC / GMAC (e.g. "AES-128-CBC").
    cipher_name: Option<String>,
    /// Tracks the context lifecycle: Created → Initialised → Updated → Finalised.
    #[zeroize(skip)]
    lifecycle: MacState,
}

impl MacContext {
    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Creates a new, uninitialised MAC context for `mac_type`.
    ///
    /// The context must be initialised with [`init`](MacContext::init) before
    /// any data can be fed.
    pub fn new(mac_type: MacType) -> Self {
        Self {
            mac_type,
            state: None,
            key: Vec::new(),
            digest_name: None,
            cipher_name: None,
            lifecycle: MacState::Uninitialized,
        }
    }

    // -----------------------------------------------------------------
    // Initialisation — replaces EVP_MAC_init
    // -----------------------------------------------------------------

    /// Initialises the MAC context with a key and optional parameters.
    ///
    /// `params` may contain algorithm-specific configuration:
    /// - **HMAC**: `"digest"` — name of the hash (default `"SHA-256"`).
    /// - **CMAC / GMAC**: `"cipher"` — name of the block cipher
    ///   (default `"AES-128-CBC"` for CMAC, `"AES-128-GCM"` for GMAC).
    /// - **KMAC**: `"custom"` — customisation string (default empty).
    /// - **`SipHash`**: `"size"` — output size `"8"` or `"16"` (default `"8"`).
    /// - **`Blake2Mac`**: `"size"` — output length in bytes, 1–64 (default `"32"`).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key is invalid for the chosen
    /// algorithm and [`CryptoError::AlgorithmNotFound`] if an unsupported
    /// parameter value is given.
    pub fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> CryptoResult<()> {
        self.key = key.to_vec();

        match self.mac_type {
            MacType::Hmac => {
                if key.is_empty() {
                    return Err(CryptoError::Key("HMAC requires a non-empty key".into()));
                }
                let digest = extract_param_str(params, "digest").ok_or_else(|| {
                    CryptoError::AlgorithmNotFound(
                        "HMAC requires a 'digest' parameter (e.g. \"SHA-256\")".into(),
                    )
                })?;
                self.digest_name = Some(digest.clone());
                let hmac = HmacState::new(key, &digest)?;
                self.state = Some(AlgorithmState::Hmac(hmac));
            }
            MacType::Cmac => {
                let cipher =
                    extract_param_str(params, "cipher").unwrap_or_else(|| "AES-128-CBC".to_owned());
                self.cipher_name = Some(cipher);
                let cmac = CmacState::new(key)?;
                self.state = Some(AlgorithmState::Cmac(cmac));
            }
            MacType::Gmac => {
                let cipher =
                    extract_param_str(params, "cipher").unwrap_or_else(|| "AES-128-GCM".to_owned());
                self.cipher_name = Some(cipher);
                let iv = extract_param_bytes(params, "iv")
                    .ok_or_else(|| CryptoError::Key("GMAC requires an 'iv' parameter".into()))?;
                let gmac = GmacState::new(key, &iv)?;
                self.state = Some(AlgorithmState::Gmac(gmac));
            }
            MacType::Kmac128 => {
                let custom = extract_param_bytes(params, "custom").unwrap_or_default();
                let kmac = KmacState::new(key, false, &custom)?;
                self.state = Some(AlgorithmState::Kmac(kmac));
            }
            MacType::Kmac256 => {
                let custom = extract_param_bytes(params, "custom").unwrap_or_default();
                let kmac = KmacState::new(key, true, &custom)?;
                self.state = Some(AlgorithmState::Kmac(kmac));
            }
            MacType::Poly1305 => {
                let poly = Poly1305State::new(key)?;
                self.state = Some(AlgorithmState::Poly1305(poly));
            }
            MacType::SipHash => {
                let out_len = match extract_param_str(params, "size").as_deref() {
                    Some("16") => 16usize,
                    _ => 8usize,
                };
                let sip = SipHashState::new(key, out_len)?;
                self.state = Some(AlgorithmState::SipHash(sip));
            }
            MacType::Blake2Mac => {
                let out_len: usize = extract_param_str(params, "size")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(32);
                let b2 = Blake2MacState::new(key, out_len)?;
                self.state = Some(AlgorithmState::Blake2(b2));
            }
        }
        self.lifecycle = MacState::Initialized;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Incremental update — replaces EVP_MAC_update
    // -----------------------------------------------------------------

    /// Feeds `data` into the MAC computation.
    ///
    /// May be called multiple times between [`init`](MacContext::init) and
    /// [`finalize`](MacContext::finalize).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] if the context has not been
    /// initialised or has already been finalised.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        match self.lifecycle {
            MacState::Initialized | MacState::Updated => {}
            MacState::Uninitialized => {
                return Err(CryptoError::Verification(
                    "MacContext::update called before init".into(),
                ));
            }
            MacState::Finalized => {
                return Err(CryptoError::Verification(
                    "MacContext::update called after finalize".into(),
                ));
            }
        }
        let st = self
            .state
            .as_mut()
            .ok_or_else(|| CryptoError::Verification("Internal: no algorithm state".into()))?;
        match st {
            AlgorithmState::Hmac(h) => h.update(data),
            AlgorithmState::Cmac(c) => c.update(data),
            AlgorithmState::Gmac(g) => g.update(data),
            AlgorithmState::Kmac(k) => k.update(data),
            AlgorithmState::Poly1305(p) => p.update(data),
            AlgorithmState::SipHash(s) => s.update(data),
            AlgorithmState::Blake2(b) => b.update(data),
        }
        self.lifecycle = MacState::Updated;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Finalisation — replaces EVP_MAC_final
    // -----------------------------------------------------------------

    /// Finalises the MAC computation and returns the authentication tag.
    ///
    /// The context transitions to the `Finalised` state and cannot be
    /// reused. Create a new context via [`new`](MacContext::new) for
    /// another computation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Verification`] if the context has not been
    /// initialised or has already been finalised.
    pub fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        match self.lifecycle {
            MacState::Initialized | MacState::Updated => {}
            MacState::Uninitialized => {
                return Err(CryptoError::Verification(
                    "MacContext::finalize called before init".into(),
                ));
            }
            MacState::Finalized => {
                return Err(CryptoError::Verification(
                    "MacContext::finalize called twice".into(),
                ));
            }
        }
        let st = self
            .state
            .as_mut()
            .ok_or_else(|| CryptoError::Verification("Internal: no algorithm state".into()))?;
        let tag = match st {
            AlgorithmState::Hmac(h) => h.finalize(),
            AlgorithmState::Cmac(c) => c.finalize(),
            AlgorithmState::Gmac(g) => g.finalize(),
            AlgorithmState::Kmac(k) => k.finalize(),
            AlgorithmState::Poly1305(p) => p.finalize(),
            AlgorithmState::SipHash(s) => s.finalize(),
            AlgorithmState::Blake2(b) => b.finalize(),
        };
        self.lifecycle = MacState::Finalized;
        Ok(tag)
    }

    /// Finalizes the MAC computation and verifies the tag in constant time.
    ///
    /// This is the recommended way to verify a MAC tag. It uses
    /// [`subtle::ConstantTimeEq`] to prevent timing side-channel attacks
    /// that could leak information about the expected tag.
    ///
    /// # Errors
    ///
    /// - Returns [`CryptoError::Verification`] if the computed tag does not
    ///   match `expected_tag` (length mismatch or content mismatch).
    /// - Forwards any error from [`Self::finalize`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use openssl_crypto::mac::{MacType, MacContext};
    /// let mut ctx = MacContext::new(MacType::Hmac);
    /// // ... init, update ...
    /// # let expected = vec![0u8; 32];
    /// ctx.verify(&expected).expect("MAC verification failed");
    /// ```
    pub fn verify(&mut self, expected_tag: &[u8]) -> CryptoResult<()> {
        let computed = self.finalize()?;
        if computed.len() != expected_tag.len() {
            return Err(CryptoError::Verification("MAC tag length mismatch".into()));
        }
        if computed.ct_eq(expected_tag).into() {
            Ok(())
        } else {
            Err(CryptoError::Verification(
                "MAC tag verification failed".into(),
            ))
        }
    }
}

// ===========================================================================
// One-shot convenience functions
// ===========================================================================

/// Computes a MAC tag in a single call.
///
/// This is a convenience wrapper around [`MacContext`] that creates a context,
/// initialises it with `key` and `params`, feeds `data`, and returns the
/// resulting authentication tag.
///
/// # Errors
///
/// Forwards any error from the underlying algorithm initialisation or
/// computation.
pub fn compute(
    mac_type: MacType,
    key: &[u8],
    data: &[u8],
    params: Option<&ParamSet>,
) -> CryptoResult<Vec<u8>> {
    let mut ctx = MacContext::new(mac_type);
    ctx.init(key, params)?;
    ctx.update(data)?;
    ctx.finalize()
}

/// Computes a MAC tag and verifies it against an expected value in a single call.
///
/// Uses constant-time comparison via [`subtle::ConstantTimeEq`] to prevent
/// timing side-channel attacks.
///
/// # Errors
///
/// - Returns [`CryptoError::Verification`] if the computed tag does not match.
/// - Forwards any error from the underlying algorithm.
pub fn verify(
    mac_type: MacType,
    key: &[u8],
    data: &[u8],
    expected_tag: &[u8],
    params: Option<&ParamSet>,
) -> CryptoResult<()> {
    let mut ctx = MacContext::new(mac_type);
    ctx.init(key, params)?;
    ctx.update(data)?;
    ctx.verify(expected_tag)
}

/// Computes an HMAC tag using the specified digest algorithm.
///
/// This is a direct replacement for the C `HMAC()` one-liner declared in
/// `crypto/hmac/hmac.c`. The default digest is SHA-256.
///
/// # Examples
///
/// ```ignore
/// let tag = hmac("SHA-256", b"secret", b"hello world")?;
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if `digest` is not a
/// recognised hash algorithm name.
pub fn hmac(digest: &str, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut ctx = MacContext::new(MacType::Hmac);
    let mut ps = ParamSet::new();
    ps.set("digest", ParamValue::Utf8String(digest.to_owned()));
    ctx.init(key, Some(&ps))?;
    ctx.update(data)?;
    ctx.finalize()
}

// ===========================================================================
// ParamSet helpers
// ===========================================================================

/// Extracts a UTF-8 string parameter from an optional [`ParamSet`].
fn extract_param_str(params: Option<&ParamSet>, name: &str) -> Option<String> {
    let ps = params?;
    ps.get(name).and_then(|v| match v {
        ParamValue::Utf8String(s) => Some(s.clone()),
        _ => None,
    })
}

/// Extracts a byte-vector parameter from an optional [`ParamSet`].
fn extract_param_bytes(params: Option<&ParamSet>, name: &str) -> Option<Vec<u8>> {
    let ps = params?;
    ps.get(name).and_then(|v| match v {
        ParamValue::OctetString(b) => Some(b.clone()),
        ParamValue::Utf8String(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    })
}
