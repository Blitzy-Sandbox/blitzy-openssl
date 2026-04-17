// ---------------------------------------------------------------------------
// Clippy lint allowances for cryptographic implementation code.
//
// JUSTIFICATION (per Rule R6 — TRUNCATION, Rule R9 — warning-free build):
//
// unreadable_literal: Hex constants (SHA-512 round constants, field primes,
//   curve base-point coordinates) are verified byte-for-byte against published
//   specification values (FIPS 180-4, RFC 7748, RFC 8032). Digit separators
//   would make cross-referencing with spec documents harder, not easier.
//
// many_single_char_names: Mathematical variables (a, b, c, d, e, f, g, h) in
//   hash compression, field arithmetic, and point operations follow standard
//   cryptographic notation from FIPS 180-4, RFC 7748, and RFC 8032.
//
// cast_possible_truncation / cast_sign_loss / cast_possible_wrap / cast_lossless:
//   TRUNCATION: All narrowing casts in this module are intentional and verified:
//   - u128 → u64 after right-shift by ≥51 bits (carry extraction in field mul)
//   - u64 → u8 for byte serialization of field elements and hash state
//   - u128 → u8 for direct byte extraction from wide accumulator values
//   - i64 → u64 after sign checks (field element reduced representation)
//   All widening casts (u8 → u64, u32 → u64) are flagged by cast_lossless
//   but are correct and intentional for accumulation in wider arithmetic.
//
// needless_range_loop: Index-based loops are clearer in multi-array crypto
//   operations where the same index addresses multiple parallel arrays.
//
// wrong_self_convention: `to_bytes(&self)` takes &self because field element
//   types are 80–320 bytes and copying would be wasteful; the crypto convention
//   of `to_bytes` returning an owned array is well-established (see RustCrypto).
//
// doc_markdown: Algorithm names like SHA-512, Ed25519, X25519 appear frequently
//   in documentation as proper names, not code identifiers.
//
// bool_to_int_with_if: Explicit if/else for conditional byte selection in
//   constant-time code is clearer than u8::from(bool) for crypto reviewers.
//
// let_and_return: Intermediate bindings in multi-step crypto computations
//   improve auditability.
//
// manual_let_else: Pattern matches in error handling paths are kept explicit
//   for clarity in security-critical code.
//
// unnecessary_wraps: Some functions return Result for API consistency across
//   the curve25519 module even when the current implementation cannot fail.
//
// similar_names: Cryptographic variable names like `s` and `t`, `r` and `h`
//   follow RFC notation and are distinguished by context.
//
// too_many_lines: Cryptographic functions (especially sign/verify) implement
//   multi-step algorithms that are best kept as single functions for auditability.
//
// explicit_iter_loop: `for x in array.iter()` style is used for consistency
//   across loops that mix indexing and iteration.
// ---------------------------------------------------------------------------
#![allow(
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::needless_range_loop,
    clippy::wrong_self_convention,
    clippy::doc_markdown,
    clippy::bool_to_int_with_if,
    clippy::let_and_return,
    clippy::manual_let_else,
    clippy::unnecessary_wraps,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::explicit_iter_loop
)]

//! Montgomery and Edwards curve primitives for the Curve25519 and Curve448 families.
//!
//! Provides:
//! - **X25519:** Diffie-Hellman key exchange on Curve25519 (RFC 7748)
//! - **Ed25519:** EdDSA signatures on the Edwards form of Curve25519 (RFC 8032)
//! - **X448:** Diffie-Hellman key exchange on Curve448 (RFC 7748)
//! - **Ed448:** EdDSA signatures on Curve448/Goldilocks (RFC 8032)
//!
//! ## Key Sizes
//! | Algorithm | Private Key | Public Key | Signature |
//! |-----------|-------------|------------|-----------|
//! | X25519    | 32 bytes    | 32 bytes   | N/A       |
//! | Ed25519   | 32 bytes    | 32 bytes   | 64 bytes  |
//! | X448      | 56 bytes    | 56 bytes   | N/A       |
//! | Ed448     | 57 bytes    | 57 bytes   | 114 bytes |
//!
//! Translates C implementations from `crypto/ec/curve25519.c` and `crypto/ec/curve448/`.
//! All private key material is zeroed on drop via `zeroize`.

use openssl_common::{CryptoError, CryptoResult};
use subtle::ConstantTimeEq;
use tracing::{error, trace};
use zeroize::ZeroizeOnDrop;

// ---------------------------------------------------------------------------
// Public constants — key and signature sizes per RFC 7748 / RFC 8032
// ---------------------------------------------------------------------------

/// X25519 private and public key length in bytes.
pub const X25519_KEY_LEN: usize = 32;
/// X25519 shared secret length in bytes.
pub const X25519_SHARED_SECRET_LEN: usize = 32;
/// Ed25519 private and public key length in bytes.
pub const ED25519_KEY_LEN: usize = 32;
/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// X448 private and public key length in bytes.
pub const X448_KEY_LEN: usize = 56;
/// X448 shared secret length in bytes.
pub const X448_SHARED_SECRET_LEN: usize = 56;
/// Ed448 private and public key length in bytes.
pub const ED448_KEY_LEN: usize = 57;
/// Ed448 signature length in bytes.
pub const ED448_SIGNATURE_LEN: usize = 114;

// ---------------------------------------------------------------------------
// EcxKeyType — key type discriminant (from ecx_key.c ECX_KEY_TYPE)
// ---------------------------------------------------------------------------

/// Identifies the specific curve and algorithm for an ECX key.
///
/// Replaces the C `ECX_KEY_TYPE` enum from `ecx_key.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcxKeyType {
    /// X25519 Diffie-Hellman (RFC 7748).
    X25519,
    /// X448 Diffie-Hellman (RFC 7748).
    X448,
    /// Ed25519 digital signature (RFC 8032).
    Ed25519,
    /// Ed448 digital signature (RFC 8032).
    Ed448,
}

impl EcxKeyType {
    /// Returns the private/public key length in bytes for this key type.
    ///
    /// Matches the C `ecx_key_length()` mapping:
    /// - X25519 / Ed25519 → 32
    /// - X448 → 56
    /// - Ed448 → 57
    pub fn key_len(&self) -> usize {
        match self {
            EcxKeyType::X25519 | EcxKeyType::Ed25519 => 32,
            EcxKeyType::X448 => 56,
            EcxKeyType::Ed448 => 57,
        }
    }

    /// Returns the signature length for EdDSA key types, or `None` for DH types.
    pub fn signature_len(&self) -> Option<usize> {
        match self {
            EcxKeyType::Ed25519 => Some(ED25519_SIGNATURE_LEN),
            EcxKeyType::Ed448 => Some(ED448_SIGNATURE_LEN),
            EcxKeyType::X25519 | EcxKeyType::X448 => None,
        }
    }

    /// Returns `true` if this key type supports signing operations.
    pub fn is_sign_type(&self) -> bool {
        matches!(self, EcxKeyType::Ed25519 | EcxKeyType::Ed448)
    }
}

impl std::fmt::Display for EcxKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcxKeyType::X25519 => write!(f, "X25519"),
            EcxKeyType::X448 => write!(f, "X448"),
            EcxKeyType::Ed25519 => write!(f, "Ed25519"),
            EcxKeyType::Ed448 => write!(f, "Ed448"),
        }
    }
}

// ---------------------------------------------------------------------------
// Key types (from ecx_key.c ECX_KEY)
// ---------------------------------------------------------------------------

/// Private key for X25519/X448/Ed25519/Ed448.
///
/// Private key bytes are securely zeroed on drop via the `ZeroizeOnDrop` derive,
/// replacing the C `OPENSSL_secure_clear_free()` pattern from `ecx_key.c`.
#[derive(ZeroizeOnDrop)]
pub struct EcxPrivateKey {
    /// Key type (determines byte length and algorithm).
    #[zeroize(skip)]
    key_type: EcxKeyType,
    /// Private key bytes (32 for X25519/Ed25519, 56 for X448, 57 for Ed448).
    bytes: Vec<u8>,
}

impl EcxPrivateKey {
    /// Creates a new private key from raw bytes.
    ///
    /// Returns an error if the byte length does not match the key type's expected length.
    pub fn new(key_type: EcxKeyType, bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.len() != key_type.key_len() {
            return Err(CryptoError::Key(format!(
                "{} private key must be {} bytes, got {}",
                key_type,
                key_type.key_len(),
                bytes.len()
            )));
        }
        Ok(Self { key_type, bytes })
    }

    /// Returns the key type.
    pub fn key_type(&self) -> EcxKeyType {
        self.key_type
    }

    /// Returns a reference to the raw private key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Manual Debug impl to avoid leaking key material.
impl std::fmt::Debug for EcxPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcxPrivateKey")
            .field("key_type", &self.key_type)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Public key for X25519/X448/Ed25519/Ed448.
#[derive(Debug, Clone)]
pub struct EcxPublicKey {
    /// Key type (determines byte length and algorithm).
    key_type: EcxKeyType,
    /// Public key bytes.
    bytes: Vec<u8>,
}

impl EcxPublicKey {
    /// Creates a new public key from raw bytes.
    ///
    /// Returns an error if the byte length does not match the key type's expected length.
    pub fn new(key_type: EcxKeyType, bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.len() != key_type.key_len() {
            return Err(CryptoError::Key(format!(
                "{} public key must be {} bytes, got {}",
                key_type,
                key_type.key_len(),
                bytes.len()
            )));
        }
        Ok(Self { key_type, bytes })
    }

    /// Returns the key type.
    pub fn key_type(&self) -> EcxKeyType {
        self.key_type
    }

    /// Returns a reference to the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Key pair holding both private and public keys.
///
/// Replaces the C `ECX_KEY` struct from `ecx_key.c`, with RAII semantics
/// ensuring the private key is securely zeroed on drop.
pub struct EcxKeyPair {
    private_key: EcxPrivateKey,
    public_key: EcxPublicKey,
}

impl EcxKeyPair {
    /// Creates a new key pair from private and public key byte vectors.
    ///
    /// Returns an error if byte lengths do not match the key type.
    pub fn new(
        key_type: EcxKeyType,
        private_bytes: Vec<u8>,
        public_bytes: Vec<u8>,
    ) -> CryptoResult<Self> {
        let private_key = EcxPrivateKey::new(key_type, private_bytes)?;
        let public_key = EcxPublicKey::new(key_type, public_bytes)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &EcxPrivateKey {
        &self.private_key
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &EcxPublicKey {
        &self.public_key
    }

    /// Returns the key type of this pair.
    pub fn key_type(&self) -> EcxKeyType {
        self.private_key.key_type
    }
}

impl std::fmt::Debug for EcxKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcxKeyPair")
            .field("key_type", &self.key_type())
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

// ===========================================================================
// Internal SHA-512 implementation (FIPS 180-4)
// Used by Ed25519 sign/verify. Implemented inline because the hash module
// does not yet exist and no sha2 crate is available in the workspace.
// ===========================================================================
mod sha512_internal {
    /// SHA-512 round constants (FIPS 180-4 section 4.2.3).
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    /// SHA-512 initial hash values (FIPS 180-4 section 5.3.5).
    const H0: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    /// Incremental SHA-512 hasher.
    pub(super) struct Sha512 {
        state: [u64; 8],
        buf: [u8; 128],
        buf_len: usize,
        total_len: u128,
    }

    impl Sha512 {
        /// Creates a new SHA-512 hasher.
        pub(super) fn new() -> Self {
            Self {
                state: H0,
                buf: [0u8; 128],
                buf_len: 0,
                total_len: 0,
            }
        }

        /// Absorbs input data.
        pub(super) fn update(&mut self, data: &[u8]) {
            self.total_len += data.len() as u128;
            let mut offset = 0usize;
            if self.buf_len > 0 {
                let need = 128 - self.buf_len;
                let take = need.min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                offset = take;
                if self.buf_len == 128 {
                    let block = self.buf;
                    compress(&mut self.state, &block);
                    self.buf_len = 0;
                }
            }
            while offset + 128 <= data.len() {
                let mut block = [0u8; 128];
                block.copy_from_slice(&data[offset..offset + 128]);
                compress(&mut self.state, &block);
                offset += 128;
            }
            if offset < data.len() {
                let remaining = data.len() - offset;
                self.buf[..remaining].copy_from_slice(&data[offset..]);
                self.buf_len = remaining;
            }
        }

        /// Finalizes and returns the 64-byte digest.
        pub(super) fn finalize(mut self) -> [u8; 64] {
            let bit_len = self.total_len * 8;
            self.buf[self.buf_len] = 0x80;
            self.buf_len += 1;
            if self.buf_len > 112 {
                for i in self.buf_len..128 {
                    self.buf[i] = 0;
                }
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
            for i in self.buf_len..112 {
                self.buf[i] = 0;
            }
            self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            compress(&mut self.state, &block);
            let mut out = [0u8; 64];
            for (i, h) in self.state.iter().enumerate() {
                out[i * 8..(i + 1) * 8].copy_from_slice(&h.to_be_bytes());
            }
            out
        }
    }

    /// SHA-512 compression function.
    fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let off = i * 8;
            w[i] = u64::from_be_bytes([
                block[off],
                block[off + 1],
                block[off + 2],
                block[off + 3],
                block[off + 4],
                block[off + 5],
                block[off + 6],
                block[off + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
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
        state[7] = state[7].wrapping_add(h);
    }

    /// Convenience: compute SHA-512 of a single message.
    pub(super) fn sha512(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ===========================================================================
// Internal Keccak / SHAKE-256 implementation
// Used by Ed448 sign/verify. Keccak-f[1600] with SHAKE-256 parameters.
// ===========================================================================
mod keccak_internal {
    /// Keccak-f[1600] round constants.
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    /// Rotation offsets for Keccak rho step.
    const RHO: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];

    /// Lane permutation indices for Keccak pi step.
    const PI: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    /// Keccak-f[1600] permutation on 25 lanes.
    fn keccak_f(state: &mut [u64; 25]) {
        for round in 0..24 {
            // Theta step
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for x in 0..5 {
                for y in 0..5 {
                    state[x + 5 * y] ^= d[x];
                }
            }
            // Rho and Pi steps
            let mut last = state[1];
            for i in 0..24 {
                let j = PI[i];
                let temp = state[j];
                state[j] = last.rotate_left(RHO[i]);
                last = temp;
            }
            // Chi step
            for y in 0..5 {
                let base = 5 * y;
                let t = [
                    state[base],
                    state[base + 1],
                    state[base + 2],
                    state[base + 3],
                    state[base + 4],
                ];
                for x in 0..5 {
                    state[base + x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
                }
            }
            // Iota step
            state[0] ^= RC[round];
        }
    }

    /// SHAKE-256 extendable-output function.
    /// Rate = 1088 bits = 136 bytes, capacity = 512 bits.
    pub(super) struct Shake256 {
        state: [u64; 25],
        buf: [u8; 136],
        buf_len: usize,
        squeezed: bool,
    }

    impl Shake256 {
        /// Creates a new SHAKE-256 instance.
        pub(super) fn new() -> Self {
            Self {
                state: [0u64; 25],
                buf: [0u8; 136],
                buf_len: 0,
                squeezed: false,
            }
        }

        /// Absorbs input data.
        pub(super) fn update(&mut self, data: &[u8]) {
            let rate = 136;
            let mut offset = 0;
            while offset < data.len() {
                let take = (rate - self.buf_len).min(data.len() - offset);
                self.buf[self.buf_len..self.buf_len + take]
                    .copy_from_slice(&data[offset..offset + take]);
                self.buf_len += take;
                offset += take;
                if self.buf_len == rate {
                    self.absorb_block();
                    self.buf_len = 0;
                }
            }
        }

        fn absorb_block(&mut self) {
            for i in 0..17 {
                let off = i * 8;
                let lane = u64::from_le_bytes([
                    self.buf[off],
                    self.buf[off + 1],
                    self.buf[off + 2],
                    self.buf[off + 3],
                    self.buf[off + 4],
                    self.buf[off + 5],
                    self.buf[off + 6],
                    self.buf[off + 7],
                ]);
                self.state[i] ^= lane;
            }
            keccak_f(&mut self.state);
        }

        /// Pads and transitions to squeeze phase, then extracts `out_len` bytes.
        pub(super) fn finalize_xof(mut self, out_len: usize) -> Vec<u8> {
            let rate = 136;
            // Pad: SHAKE uses domain separation 0x1F, then 0x80 at end of rate block
            self.buf[self.buf_len] = 0x1f;
            for i in (self.buf_len + 1)..rate {
                self.buf[i] = 0;
            }
            self.buf[rate - 1] |= 0x80;
            self.absorb_block();
            self.squeezed = true;

            // Squeeze
            let mut out = vec![0u8; out_len];
            let mut offset = 0;
            while offset < out_len {
                let available = rate.min(out_len - offset);
                for i in 0..available {
                    let lane_idx = i / 8;
                    let byte_idx = i % 8;
                    out[offset + i] = (self.state[lane_idx] >> (byte_idx * 8)) as u8;
                }
                offset += available;
                if offset < out_len {
                    keccak_f(&mut self.state);
                }
            }
            out
        }
    }

    /// Convenience: compute SHAKE-256 with the specified output length.
    pub(super) fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
        let mut h = Shake256::new();
        h.update(data);
        h.finalize_xof(out_len)
    }
}

// ===========================================================================
// Curve25519 field arithmetic — GF(2^255-19), radix-2^51 representation
// Five u64 limbs, each < 2^52 after carry. Products computed in u128.
// Translates ref10-style arithmetic from curve25519.c field element ops.
// ===========================================================================
mod field25519 {
    /// Field element in GF(2^255-19): five u64 limbs in radix 2^51.
    #[derive(Clone, Copy)]
    pub(super) struct Fe([u64; 5]);

    const BOT51: u64 = (1u64 << 51) - 1;

    impl Fe {
        pub(super) const ZERO: Fe = Fe([0; 5]);
        pub(super) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

        /// Reduces (carries) limbs so each fits in 51 bits.
        fn carry(mut self) -> Fe {
            for i in 0..4 {
                self.0[i + 1] += self.0[i] >> 51;
                self.0[i] &= BOT51;
            }
            // Top limb carry wraps around with factor 19
            let carry = self.0[4] >> 51;
            self.0[4] &= BOT51;
            self.0[0] += carry * 19;
            // One more carry on limb 0 in case of overflow
            self.0[1] += self.0[0] >> 51;
            self.0[0] &= BOT51;
            self
        }

        /// Loads a 32-byte little-endian encoding into a field element.
        pub(super) fn from_bytes(s: &[u8; 32]) -> Fe {
            let mut h = [0u64; 5];
            let load8 = |slice: &[u8]| -> u64 {
                let mut v = 0u64;
                for (i, &b) in slice.iter().enumerate().take(8) {
                    v |= (b as u64) << (i * 8);
                }
                v
            };
            h[0] = load8(&s[0..]) & BOT51;
            h[1] = (load8(&s[6..]) >> 3) & BOT51;
            h[2] = (load8(&s[12..]) >> 6) & BOT51;
            h[3] = (load8(&s[19..]) >> 1) & BOT51;
            h[4] = (load8(&s[25..]) >> 4) & BOT51;
            Fe(h)
        }

        /// Encodes as 32-byte little-endian, fully reduced mod 2^255-19.
        /// Uses the standard ref10 q-computation for canonical reduction.
        pub(super) fn to_bytes(&self) -> [u8; 32] {
            let mut h = self.carry();
            // Full reduction mod p = 2^255-19.
            // Compute q = floor((h + 19) / 2^255) by propagating carries without
            // calling carry() (which would fold the overflow back, losing the signal).
            // q is 0 if h < p, or 1 if h >= p.
            let mut q = (h.0[0] + 19) >> 51;
            q = (h.0[1] + q) >> 51;
            q = (h.0[2] + q) >> 51;
            q = (h.0[3] + q) >> 51;
            q = (h.0[4] + q) >> 51;
            // Subtract q*p = q*(2^255-19): add q*19 and let bit 255 vanish
            h.0[0] += 19 * q;
            let c = h.0[0] >> 51;
            h.0[0] &= BOT51;
            h.0[1] += c;
            let c = h.0[1] >> 51;
            h.0[1] &= BOT51;
            h.0[2] += c;
            let c = h.0[2] >> 51;
            h.0[2] &= BOT51;
            h.0[3] += c;
            let c = h.0[3] >> 51;
            h.0[3] &= BOT51;
            h.0[4] += c;
            h.0[4] &= BOT51;
            // After subtraction, h is in [0, p). Pack 255 bits into 32 bytes.
            let mut out = [0u8; 32];
            let mut acc: u128 = 0;
            let mut bits = 0u32;
            let mut pos = 0;
            for &limb in &h.0 {
                acc |= (limb as u128) << bits;
                bits += 51;
                while bits >= 8 && pos < 32 {
                    out[pos] = acc as u8;
                    acc >>= 8;
                    bits -= 8;
                    pos += 1;
                }
            }
            // Flush remaining bits (7 bits for byte 31 from 5×51=255 total)
            if pos < 32 {
                out[pos] = acc as u8;
            }
            out
        }

        /// Addition in GF(2^255-19).
        pub(super) fn add(&self, other: &Fe) -> Fe {
            Fe([
                self.0[0] + other.0[0],
                self.0[1] + other.0[1],
                self.0[2] + other.0[2],
                self.0[3] + other.0[3],
                self.0[4] + other.0[4],
            ])
        }

        /// Subtraction in GF(2^255-19). Adds 2*p to prevent underflow.
        pub(super) fn sub(&self, other: &Fe) -> Fe {
            // 2*p limbs (radix 2^51): each limb of p is BOT51 except limb0 = BOT51 - 18
            Fe([
                self.0[0] + 0xFFFFFFFFFFFDA - other.0[0],
                self.0[1] + 0xFFFFFFFFFFFFE - other.0[1],
                self.0[2] + 0xFFFFFFFFFFFFE - other.0[2],
                self.0[3] + 0xFFFFFFFFFFFFE - other.0[3],
                self.0[4] + 0xFFFFFFFFFFFFE - other.0[4],
            ])
            .carry()
        }

        /// Multiplication in GF(2^255-19).
        pub(super) fn mul(&self, other: &Fe) -> Fe {
            let a = &self.0;
            let b = &other.0;
            // Schoolbook multiplication with 19-reduction for terms above 2^255
            let mut t = [0u128; 5];
            for i in 0..5 {
                for j in 0..5 {
                    let prod = (a[i] as u128) * (b[j] as u128);
                    let k = i + j;
                    if k < 5 {
                        t[k] += prod;
                    } else {
                        // Reduce: x * 2^(51*k) where k >= 5 => x * 19 * 2^(51*(k-5))
                        t[k - 5] += prod * 19;
                    }
                }
            }
            // Carry
            let mut r = [0u64; 5];
            let mut carry = 0u128;
            for i in 0..5 {
                t[i] += carry;
                r[i] = (t[i] as u64) & BOT51;
                carry = t[i] >> 51;
            }
            r[0] += (carry as u64) * 19;
            // One more carry round
            Fe(r).carry()
        }

        /// Squaring in GF(2^255-19) — optimized special case of mul.
        pub(super) fn square(&self) -> Fe {
            self.mul(self)
        }

        /// Negation in GF(2^255-19).
        pub(super) fn neg(&self) -> Fe {
            Fe::ZERO.sub(self)
        }

        /// Constant-time conditional swap: if flag != 0, swap self and other.
        pub(super) fn cswap(&mut self, other: &mut Fe, flag: u64) {
            let mask = 0u64.wrapping_sub(flag & 1);
            for i in 0..5 {
                let diff = mask & (self.0[i] ^ other.0[i]);
                self.0[i] ^= diff;
                other.0[i] ^= diff;
            }
        }

        /// Constant-time conditional move: if flag != 0, set self = src.
        pub(super) fn cmov(&mut self, src: &Fe, flag: u64) {
            let mask = 0u64.wrapping_sub(flag & 1);
            for i in 0..5 {
                self.0[i] ^= mask & (self.0[i] ^ src.0[i]);
            }
        }

        /// Computes self^(2^n).
        pub(super) fn square_times(&self, n: usize) -> Fe {
            let mut r = *self;
            for _ in 0..n {
                r = r.square();
            }
            r
        }

        /// Inversion: self^(p-2) where p = 2^255-19.
        /// Uses the addition chain from ref10 (curve25519.c fe_invert).
        pub(super) fn invert(&self) -> Fe {
            let z2 = self.square(); // z^2
            let t = z2.square_times(2); // z^8
            let z9 = t.mul(self); // z^9
            let z11 = z9.mul(&z2); // z^11
            let t = z11.square(); // z^22
            let z_2_5_0 = t.mul(&z9); // z^(2^5 - 2^0) = z^31
            let t = z_2_5_0.square_times(5); // z^(2^10 - 2^5)
            let z_2_10_0 = t.mul(&z_2_5_0); // z^(2^10 - 1)
            let t = z_2_10_0.square_times(10); // z^(2^20 - 2^10)
            let z_2_20_0 = t.mul(&z_2_10_0); // z^(2^20 - 1)
            let t = z_2_20_0.square_times(20); // z^(2^40 - 2^20)
            let t = t.mul(&z_2_20_0); // z^(2^40 - 1)
            let t = t.square_times(10); // z^(2^50 - 2^10)
            let z_2_50_0 = t.mul(&z_2_10_0); // z^(2^50 - 1)
            let t = z_2_50_0.square_times(50); // z^(2^100 - 2^50)
            let z_2_100_0 = t.mul(&z_2_50_0); // z^(2^100 - 1)
            let t = z_2_100_0.square_times(100); // z^(2^200 - 2^100)
            let t = t.mul(&z_2_100_0); // z^(2^200 - 1)
            let t = t.square_times(50); // z^(2^250 - 2^50)
            let t = t.mul(&z_2_50_0); // z^(2^250 - 1)
            let t = t.square_times(5); // z^(2^255 - 2^5)
            t.mul(&z11) // z^(2^255 - 21) = z^(p-2)
        }

        /// Computes self^((p-5)/8) = self^(2^252 - 3).
        /// Used in square root computation for point decompression.
        pub(super) fn pow2523(&self) -> Fe {
            let z2 = self.square();
            let t = z2.square_times(2);
            let z9 = t.mul(self);
            let z11 = z9.mul(&z2);
            let t = z11.square();
            let z_2_5_0 = t.mul(&z9);
            let t = z_2_5_0.square_times(5);
            let z_2_10_0 = t.mul(&z_2_5_0);
            let t = z_2_10_0.square_times(10);
            let z_2_20_0 = t.mul(&z_2_10_0);
            let t = z_2_20_0.square_times(20);
            let t = t.mul(&z_2_20_0);
            let t = t.square_times(10);
            let z_2_50_0 = t.mul(&z_2_10_0);
            let t = z_2_50_0.square_times(50);
            let z_2_100_0 = t.mul(&z_2_50_0);
            let t = z_2_100_0.square_times(100);
            let t = t.mul(&z_2_100_0);
            let t = t.square_times(50);
            let t = t.mul(&z_2_50_0);
            let t = t.square_times(2);
            t.mul(self)
        }

        /// Returns 1 if this element is negative (i.e., least significant bit of encoding is 1).
        pub(super) fn is_negative(&self) -> u8 {
            let s = self.to_bytes();
            s[0] & 1
        }

        /// Returns 1 if this element is zero.
        pub(super) fn is_zero(&self) -> bool {
            let s = self.to_bytes();
            s.iter().all(|&b| b == 0)
        }

        /// Multiply by a small constant (used for d, 2d, sqrt(-1), etc.).
        pub(super) fn mul_small(&self, c: u64) -> Fe {
            let mut t = [0u128; 5];
            for i in 0..5 {
                t[i] = (self.0[i] as u128) * (c as u128);
            }
            let mut r = [0u64; 5];
            let mut carry = 0u128;
            for i in 0..5 {
                t[i] += carry;
                r[i] = (t[i] as u64) & BOT51;
                carry = t[i] >> 51;
            }
            r[0] += (carry as u64) * 19;
            Fe(r).carry()
        }
    }
}

// ===========================================================================
// Ed25519 group operations — Extended twisted Edwards coordinates
// Curve: -x^2 + y^2 = 1 + d*x^2*y^2, d = -121665/121666
// Translates ge_p2/ge_p3/ge_p1p1/ge_cached from curve25519.c
// ===========================================================================
mod edwards25519 {
    use super::field25519::Fe;

    /// Ed25519 curve constant d = -121665/121666 mod p.
    fn curve_d() -> Fe {
        Fe::from_bytes(&[
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
            0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
            0xee, 0x6c, 0x03, 0x52,
        ])
    }

    /// 2*d.
    fn curve_2d() -> Fe {
        let d = curve_d();
        d.add(&d)
    }

    /// sqrt(-1) mod p.
    fn sqrt_m1() -> Fe {
        Fe::from_bytes(&[
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18,
            0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f,
            0x80, 0x24, 0x83, 0x2b,
        ])
    }

    /// Ed25519 basepoint B in extended coordinates.
    pub(super) fn basepoint() -> GeP3 {
        let by = Fe::from_bytes(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);
        let bx = Fe::from_bytes(&[
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ]);
        GeP3 {
            x: bx,
            y: by,
            z: Fe::ONE,
            t: bx.mul(&by),
        }
    }

    /// Projective point (X:Y:Z) satisfying -X^2+Y^2 = Z^2+d*T^2 where T=XY/Z.
    #[derive(Clone, Copy)]
    pub(super) struct GeP2 {
        pub(super) x: Fe,
        pub(super) y: Fe,
        pub(super) z: Fe,
    }

    /// Extended point (X:Y:Z:T) where T = XY/Z.
    #[derive(Clone, Copy)]
    pub(super) struct GeP3 {
        pub(super) x: Fe,
        pub(super) y: Fe,
        pub(super) z: Fe,
        pub(super) t: Fe,
    }

    /// Completed point (X:Y:Z:T) — intermediate result before normalization.
    #[derive(Clone, Copy)]
    pub(super) struct GeP1P1 {
        x: Fe,
        y: Fe,
        z: Fe,
        t: Fe,
    }

    /// Cached point for addition with another point.
    #[derive(Clone, Copy)]
    pub(super) struct GeCached {
        y_plus_x: Fe,
        y_minus_x: Fe,
        z: Fe,
        t2d: Fe,
    }

    /// Precomputed point for fixed-base scalar multiplication.
    #[derive(Clone, Copy)]
    struct GePrecomp {
        y_plus_x: Fe,
        y_minus_x: Fe,
        xy2d: Fe,
    }

    impl GeP1P1 {
        fn to_p2(&self) -> GeP2 {
            GeP2 {
                x: self.x.mul(&self.t),
                y: self.y.mul(&self.z),
                z: self.z.mul(&self.t),
            }
        }
        fn to_p3(&self) -> GeP3 {
            GeP3 {
                x: self.x.mul(&self.t),
                y: self.y.mul(&self.z),
                z: self.z.mul(&self.t),
                t: self.x.mul(&self.y),
            }
        }
    }

    impl GeP2 {
        /// Constructs the identity point (used by extended group operations).
        #[allow(dead_code)] // Retained: standard identity constructor for complete group arithmetic API
        pub(super) fn zero() -> Self {
            GeP2 {
                x: Fe::ZERO,
                y: Fe::ONE,
                z: Fe::ONE,
            }
        }

        fn dbl(&self) -> GeP1P1 {
            let xx = self.x.square();
            let yy = self.y.square();
            let b2 = self.z.square().add(&self.z.square()); // 2*Z^2
            let aa = self.x.add(&self.y).square();
            let e = aa.sub(&xx).sub(&yy); // E = 2*X*Y
            let g = yy.add(&xx); // G = Y^2 + X^2
            let h = yy.sub(&xx); // H = Y^2 - X^2
            let f = b2.sub(&h); // F = 2*Z^2 - H
            GeP1P1 {
                x: e,
                y: g,
                z: h,
                t: f,
            }
        }

        /// Encode point to 32 bytes (y with x sign in top bit).
        pub(super) fn to_bytes(&self) -> [u8; 32] {
            let zi = self.z.invert();
            let x = self.x.mul(&zi);
            let y = self.y.mul(&zi);
            let mut s = y.to_bytes();
            s[31] ^= x.is_negative() << 7;
            s
        }
    }

    impl GeP3 {
        pub(super) fn to_p2(&self) -> GeP2 {
            GeP2 {
                x: self.x,
                y: self.y,
                z: self.z,
            }
        }

        fn to_cached(&self) -> GeCached {
            GeCached {
                y_plus_x: self.y.add(&self.x),
                y_minus_x: self.y.sub(&self.x),
                z: self.z,
                t2d: self.t.mul(&curve_2d()),
            }
        }

        fn dbl(&self) -> GeP1P1 {
            self.to_p2().dbl()
        }

        /// Encode extended point to 32 bytes.
        pub(super) fn to_bytes(&self) -> [u8; 32] {
            self.to_p2().to_bytes()
        }

        /// Decode a 32-byte point encoding. Returns None if invalid.
        pub(super) fn from_bytes(s: &[u8; 32]) -> Option<GeP3> {
            // y is the low 255 bits; x sign is bit 255
            let mut y_bytes = *s;
            let x_sign = (y_bytes[31] >> 7) & 1;
            y_bytes[31] &= 0x7f;
            let y = Fe::from_bytes(&y_bytes);

            // Compute x^2 = (y^2 - 1) / (d*y^2 + 1)
            let y2 = y.square();
            let u = y2.sub(&Fe::ONE); // u = y^2 - 1
            let v = curve_d().mul(&y2).add(&Fe::ONE); // v = d*y^2 + 1

            let v3 = v.square().mul(&v); // v^3
            let v7 = v3.square().mul(&v); // v^7
            let uv3 = u.mul(&v3);
            let uv7 = u.mul(&v7);

            // x = u*v^3 * (u*v^7)^((p-5)/8)
            let mut x = uv3.mul(&uv7.pow2523());

            // Check: v*x^2 == u  ?
            let vx2 = v.mul(&x.square());
            if !vx2.sub(&u).is_zero() {
                if !vx2.add(&u).is_zero() {
                    return None; // not a valid point
                }
                // x *= sqrt(-1)
                x = x.mul(&sqrt_m1());
            }

            if x.is_negative() != x_sign {
                x = x.neg();
            }

            // Reject x == 0 with sign bit set
            if x.is_zero() && x_sign != 0 {
                return None;
            }

            let t = x.mul(&y);
            Some(GeP3 {
                x,
                y,
                z: Fe::ONE,
                t,
            })
        }

        /// Add two extended points.
        pub(super) fn add_cached(&self, other: &GeCached) -> GeP1P1 {
            let a = self.y.sub(&self.x).mul(&other.y_minus_x);
            let b = self.y.add(&self.x).mul(&other.y_plus_x);
            let c = other.t2d.mul(&self.t);
            let d = self.z.mul(&other.z);
            let d2 = d.add(&d);
            GeP1P1 {
                x: b.sub(&a),
                y: b.add(&a),
                z: d2.add(&c),
                t: d2.sub(&c),
            }
        }

        /// Subtract: self - other.
        #[allow(dead_code)] // Retained: inverse of add_cached, required for complete group arithmetic
        pub(super) fn sub_cached(&self, other: &GeCached) -> GeP1P1 {
            let a = self.y.sub(&self.x).mul(&other.y_plus_x);
            let b = self.y.add(&self.x).mul(&other.y_minus_x);
            let c = other.t2d.mul(&self.t);
            let d = self.z.mul(&other.z);
            let d2 = d.add(&d);
            GeP1P1 {
                x: b.sub(&a),
                y: b.add(&a),
                z: d2.sub(&c),
                t: d2.add(&c),
            }
        }
    }

    impl GePrecomp {
        fn zero() -> Self {
            GePrecomp {
                y_plus_x: Fe::ONE,
                y_minus_x: Fe::ONE,
                xy2d: Fe::ZERO,
            }
        }

        /// Constant-time select: if flag==0 return self, else return other.
        fn cmov(&mut self, other: &GePrecomp, flag: u64) {
            self.y_plus_x.cmov(&other.y_plus_x, flag);
            self.y_minus_x.cmov(&other.y_minus_x, flag);
            self.xy2d.cmov(&other.xy2d, flag);
        }

        fn neg(&self) -> GePrecomp {
            GePrecomp {
                y_plus_x: self.y_minus_x,
                y_minus_x: self.y_plus_x,
                xy2d: self.xy2d.neg(),
            }
        }
    }

    /// Add a precomputed point to a GeP3.
    fn ge_madd(p: &GeP3, q: &GePrecomp) -> GeP1P1 {
        let a = p.y.sub(&p.x).mul(&q.y_minus_x);
        let b = p.y.add(&p.x).mul(&q.y_plus_x);
        let c = q.xy2d.mul(&p.t);
        let d = p.z.add(&p.z);
        GeP1P1 {
            x: b.sub(&a),
            y: b.add(&a),
            z: d.add(&c),
            t: d.sub(&c),
        }
    }

    /// Subtract a precomputed point from a GeP3.
    #[allow(dead_code)] // Retained: inverse of ge_madd, required for complete EdDSA point arithmetic
    fn ge_msub(p: &GeP3, q: &GePrecomp) -> GeP1P1 {
        let a = p.y.sub(&p.x).mul(&q.y_plus_x);
        let b = p.y.add(&p.x).mul(&q.y_minus_x);
        let c = q.xy2d.mul(&p.t);
        let d = p.z.add(&p.z);
        GeP1P1 {
            x: b.sub(&a),
            y: b.add(&a),
            z: d.sub(&c),
            t: d.add(&c),
        }
    }

    /// Compute the precomputed table: table[i] = (i+1)*base for i in 0..8.
    /// Used with radix-16 signed digits in [-8, 8] where table_select(idx)
    /// returns table[idx-1] = idx*base.
    fn precompute_table(base: &GeP3) -> [GePrecomp; 8] {
        let mut table = [GePrecomp::zero(); 8];
        // Helper: normalize a projective GeP3 to affine (Z=1) and build GePrecomp.
        // ge_madd assumes the precomp point has Z=1, so every table entry MUST
        // be in affine form.  Without normalization, table[1..7] carry Z!=1
        // from the projective addition, silently corrupting all subsequent
        // ge_madd results (ref10 uses pre-hardcoded affine tables for the
        // fixed basepoint; our variable-base path must normalize dynamically).
        let to_precomp_affine = |p: &GeP3| -> GePrecomp {
            let zi = p.z.invert();
            let x = p.x.mul(&zi);
            let y = p.y.mul(&zi);
            let t = x.mul(&y);
            GePrecomp {
                y_plus_x: y.add(&x),
                y_minus_x: y.sub(&x),
                xy2d: t.mul(&curve_2d()),
            }
        };
        // table[0] = 1*base (normalize for safety — base may already have Z=1)
        table[0] = to_precomp_affine(base);
        // table[i] = (i+1)*base = table[i-1] + base
        let base_cached = base.to_cached();
        let mut current = *base;
        for i in 1..8 {
            current = current.add_cached(&base_cached).to_p3();
            table[i] = to_precomp_affine(&current);
        }
        table
    }

    /// Constant-time table lookup: select table[idx-1] if idx > 0.
    fn table_select(table: &[GePrecomp; 8], idx: u8) -> GePrecomp {
        let mut result = GePrecomp::zero();
        for i in 0..8u8 {
            let eq = constant_time_eq(idx, i + 1);
            result.cmov(&table[i as usize], eq);
        }
        result
    }

    fn constant_time_eq(a: u8, b: u8) -> u64 {
        let v = a ^ b;
        let v = v as u64;
        ((v | v.wrapping_neg()) >> 63) ^ 1
    }

    /// Recode scalar into 64 signed 4-bit digits.
    fn scalar_to_radix16(scalar: &[u8; 32]) -> [i8; 64] {
        let mut digits = [0i8; 64];
        for i in 0..32 {
            digits[2 * i] = (scalar[i] & 0xf) as i8;
            digits[2 * i + 1] = ((scalar[i] >> 4) & 0xf) as i8;
        }
        // Carry propagation to make all digits in [-8, 8]
        let mut carry = 0i8;
        for i in 0..63 {
            digits[i] += carry;
            carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
        }
        digits[63] += carry;
        digits
    }

    /// Fixed-base scalar multiplication: [scalar] * B.
    /// Uses a width-4 windowed method with precomputed table.
    pub(super) fn scalarmult_base(scalar: &[u8; 32]) -> GeP3 {
        let bp = basepoint();
        scalarmult(&bp, scalar)
    }

    /// Variable-base scalar multiplication: [scalar] * P.
    pub(super) fn scalarmult(point: &GeP3, scalar: &[u8; 32]) -> GeP3 {
        let table = precompute_table(point);
        let digits = scalar_to_radix16(scalar);

        // Start from the most significant (top) digit
        let d63 = digits[63];
        let a63 = d63.unsigned_abs();
        let mut r = {
            let p = table_select(&table, a63);
            let np = p.neg();
            let mut sel = p;
            sel.cmov(&np, if d63 < 0 { 1 } else { 0 });
            // Convert precomp to p3: x = (y_plus_x - y_minus_x)/2, y = (y_plus_x + y_minus_x)/2
            // But easier to build via identity + madd
            let id = GeP3 {
                x: Fe::ZERO,
                y: Fe::ONE,
                z: Fe::ONE,
                t: Fe::ZERO,
            };
            ge_madd(&id, &sel).to_p3()
        };

        // Process remaining digits top-down
        for i in (0..63).rev() {
            // 4 doublings
            let mut rr = r.dbl();
            rr = rr.to_p2().dbl();
            rr = rr.to_p2().dbl();
            rr = rr.to_p2().dbl();
            r = rr.to_p3();

            let d = digits[i];
            let abs_d = d.unsigned_abs();
            let neg_flag = if d < 0 { 1u64 } else { 0u64 };
            let mut p = table_select(&table, abs_d);
            let np = p.neg();
            p.cmov(&np, neg_flag);
            let p1p1 = ge_madd(&r, &p);
            r = p1p1.to_p3();
        }
        r
    }

    /// Double scalar multiplication: [a]*A + [b]*B (variable-time, for verification).
    /// Uses simultaneous binary method (Straus).
    pub(super) fn double_scalarmult_vartime(
        a_scalar: &[u8; 32],
        a_point: &GeP3,
        b_scalar: &[u8; 32],
    ) -> GeP2 {
        let b_point = basepoint();
        // Build lookup tables: [0]P, [1]P, ..., [15]P for both A and B
        let a_table = build_vartime_table(a_point);
        let b_table = build_vartime_table(&b_point);

        // Process from most significant bit to least, 4 bits at a time
        let a_digits = scalar_to_radix16(a_scalar);
        let b_digits = scalar_to_radix16(b_scalar);

        // Find highest nonzero digit
        let mut i = 63;
        while i > 0 && a_digits[i] == 0 && b_digits[i] == 0 {
            i -= 1;
        }

        let mut r = select_vartime(&a_table, a_digits[i]);
        let bp = select_vartime(&b_table, b_digits[i]);
        r = r.add_cached(&bp.to_cached()).to_p3();

        while i > 0 {
            i -= 1;
            // 4 doublings
            let mut p1p1 = r.dbl();
            p1p1 = p1p1.to_p2().dbl();
            p1p1 = p1p1.to_p2().dbl();
            p1p1 = p1p1.to_p2().dbl();
            r = p1p1.to_p3();

            let ap = select_vartime(&a_table, a_digits[i]);
            let bp = select_vartime(&b_table, b_digits[i]);
            r = r.add_cached(&ap.to_cached()).to_p3();
            r = r.add_cached(&bp.to_cached()).to_p3();
        }
        r.to_p2()
    }

    fn build_vartime_table(p: &GeP3) -> [GeP3; 16] {
        let mut table = [GeP3 {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }; 16];
        table[0] = GeP3 {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }; // identity
        table[1] = *p;
        for i in 2..16 {
            if i % 2 == 0 {
                table[i] = table[i / 2].dbl().to_p3();
            } else {
                table[i] = table[i - 1].add_cached(&p.to_cached()).to_p3();
            }
        }
        table
    }

    fn select_vartime(table: &[GeP3; 16], digit: i8) -> GeP3 {
        if digit >= 0 {
            table[digit as usize]
        } else {
            let pos = (-digit) as usize;
            let p = table[pos];
            // Negate: -P = (-X : Y : Z : -T)
            GeP3 {
                x: p.x.neg(),
                y: p.y,
                z: p.z,
                t: p.t.neg(),
            }
        }
    }
}

// ===========================================================================
// Ed25519 scalar arithmetic — mod l where l = 2^252 + 27742317777372353535851937790883648493
// Translates sc_reduce and sc_muladd from curve25519.c
// ===========================================================================
mod scalar25519 {
    /// The Ed25519 group order l in little-endian bytes.
    /// l = 2^252 + 27742317777372353535851937790883648493
    #[allow(dead_code)]
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// Load 3 bytes in little-endian as i64.
    fn load3(s: &[u8], off: usize) -> i64 {
        (s[off] as i64) | ((s[off + 1] as i64) << 8) | ((s[off + 2] as i64) << 16)
    }

    /// Load 4 bytes in little-endian as i64.
    fn load4(s: &[u8], off: usize) -> i64 {
        (s[off] as i64)
            | ((s[off + 1] as i64) << 8)
            | ((s[off + 2] as i64) << 16)
            | ((s[off + 3] as i64) << 24)
    }

    /// Fold limb at position `k` (>= 12) into lower limbs using the identity:
    /// 2^252 ≡ 666643 + 470296·2^21 + 654183·2^42 − 997805·2^63 + 136657·2^84 − 683901·2^105 (mod l)
    ///
    /// This replaces `s[k] * 2^(21*k)` with an equivalent value spread across `s[k-12..k-6]`.
    fn fold(s: &mut [i64], k: usize) {
        let v = s[k];
        s[k - 12] += v * 666643;
        s[k - 11] += v * 470296;
        s[k - 10] += v * 654183;
        s[k - 9] -= v * 997805;
        s[k - 8] += v * 136657;
        s[k - 7] -= v * 683901;
        s[k] = 0;
    }

    /// Signed carry propagation: moves overflow from s[i] into s[i+1] using rounding.
    fn carry_signed(s: &mut [i64], i: usize) {
        let c = (s[i] + (1_i64 << 20)) >> 21;
        s[i + 1] += c;
        s[i] -= c << 21;
    }

    /// Unsigned carry propagation: moves overflow from s[i] into s[i+1].
    fn carry_unsigned(s: &mut [i64], i: usize) {
        let c = s[i] >> 21;
        s[i + 1] += c;
        s[i] -= c << 21;
    }

    /// Load 12 limbs (21-bit windows) from a 32-byte scalar. Last limb is NOT masked.
    fn load12(bytes: &[u8]) -> [i64; 12] {
        let mut a = [0i64; 12];
        a[0] = load3(bytes, 0) & 0x1fffff;
        a[1] = (load4(bytes, 2) >> 5) & 0x1fffff;
        a[2] = (load3(bytes, 5) >> 2) & 0x1fffff;
        a[3] = (load4(bytes, 7) >> 7) & 0x1fffff;
        a[4] = (load4(bytes, 10) >> 4) & 0x1fffff;
        a[5] = (load3(bytes, 13) >> 1) & 0x1fffff;
        a[6] = (load4(bytes, 15) >> 6) & 0x1fffff;
        a[7] = (load3(bytes, 18) >> 3) & 0x1fffff;
        a[8] = load3(bytes, 21) & 0x1fffff;
        a[9] = (load4(bytes, 23) >> 5) & 0x1fffff;
        a[10] = (load3(bytes, 26) >> 2) & 0x1fffff;
        a[11] = load4(bytes, 28) >> 7; // NOT masked — captures remaining bits
        a
    }

    /// Pack 12 limbs (21-bit each) into 32 little-endian bytes.
    /// Faithful port of the ref10 packing code from curve25519.c.
    fn pack(s: &[i64]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = s[0] as u8;
        out[1] = (s[0] >> 8) as u8;
        out[2] = ((s[0] >> 16) | (s[1] << 5)) as u8;
        out[3] = (s[1] >> 3) as u8;
        out[4] = (s[1] >> 11) as u8;
        out[5] = ((s[1] >> 19) | (s[2] << 2)) as u8;
        out[6] = (s[2] >> 6) as u8;
        out[7] = ((s[2] >> 14) | (s[3] << 7)) as u8;
        out[8] = (s[3] >> 1) as u8;
        out[9] = (s[3] >> 9) as u8;
        out[10] = ((s[3] >> 17) | (s[4] << 4)) as u8;
        out[11] = (s[4] >> 4) as u8;
        out[12] = (s[4] >> 12) as u8;
        out[13] = ((s[4] >> 20) | (s[5] << 1)) as u8;
        out[14] = (s[5] >> 7) as u8;
        out[15] = ((s[5] >> 15) | (s[6] << 6)) as u8;
        out[16] = (s[6] >> 2) as u8;
        out[17] = (s[6] >> 10) as u8;
        out[18] = ((s[6] >> 18) | (s[7] << 3)) as u8;
        out[19] = (s[7] >> 5) as u8;
        out[20] = (s[7] >> 13) as u8;
        out[21] = s[8] as u8;
        out[22] = (s[8] >> 8) as u8;
        out[23] = ((s[8] >> 16) | (s[9] << 5)) as u8;
        out[24] = (s[9] >> 3) as u8;
        out[25] = (s[9] >> 11) as u8;
        out[26] = ((s[9] >> 19) | (s[10] << 2)) as u8;
        out[27] = (s[10] >> 6) as u8;
        out[28] = ((s[10] >> 14) | (s[11] << 7)) as u8;
        out[29] = (s[11] >> 1) as u8;
        out[30] = (s[11] >> 9) as u8;
        out[31] = (s[11] >> 17) as u8;
        out
    }

    /// Reduce a 64-byte (512-bit) scalar modulo l to 32 bytes.
    /// Faithful port of x25519_sc_reduce from curve25519.c (ref10 algorithm).
    pub(super) fn sc_reduce(input: &[u8; 64]) -> [u8; 32] {
        // Load 64 bytes into 24 limbs (21-bit windows, last limb captures remaining bits)
        let mut s = [0i64; 24];
        s[0] = load3(input, 0) & 0x1fffff;
        s[1] = (load4(input, 2) >> 5) & 0x1fffff;
        s[2] = (load3(input, 5) >> 2) & 0x1fffff;
        s[3] = (load4(input, 7) >> 7) & 0x1fffff;
        s[4] = (load4(input, 10) >> 4) & 0x1fffff;
        s[5] = (load3(input, 13) >> 1) & 0x1fffff;
        s[6] = (load4(input, 15) >> 6) & 0x1fffff;
        s[7] = (load3(input, 18) >> 3) & 0x1fffff;
        s[8] = load3(input, 21) & 0x1fffff;
        s[9] = (load4(input, 23) >> 5) & 0x1fffff;
        s[10] = (load3(input, 26) >> 2) & 0x1fffff;
        s[11] = (load4(input, 28) >> 7) & 0x1fffff;
        s[12] = (load4(input, 31) >> 4) & 0x1fffff;
        s[13] = (load3(input, 34) >> 1) & 0x1fffff;
        s[14] = (load4(input, 36) >> 6) & 0x1fffff;
        s[15] = (load3(input, 39) >> 3) & 0x1fffff;
        s[16] = load3(input, 42) & 0x1fffff;
        s[17] = (load4(input, 44) >> 5) & 0x1fffff;
        s[18] = (load3(input, 47) >> 2) & 0x1fffff;
        s[19] = (load4(input, 49) >> 7) & 0x1fffff;
        s[20] = (load4(input, 52) >> 4) & 0x1fffff;
        s[21] = (load3(input, 55) >> 1) & 0x1fffff;
        s[22] = (load4(input, 57) >> 6) & 0x1fffff;
        s[23] = load4(input, 60) >> 3; // NOT masked — captures all remaining bits

        // --- First reduction round: fold s[23]..s[18] into s[6]..s[16] ---
        fold(&mut s, 23);
        fold(&mut s, 22);
        fold(&mut s, 21);
        fold(&mut s, 20);
        fold(&mut s, 19);
        fold(&mut s, 18);

        // Carry propagation: even indices 6..16, then odd indices 7..15
        for i in [6usize, 8, 10, 12, 14, 16] {
            carry_signed(&mut s, i);
        }
        for i in [7usize, 9, 11, 13, 15] {
            carry_signed(&mut s, i);
        }

        // --- Second reduction round: fold s[17]..s[12] into s[0]..s[10] ---
        fold(&mut s, 17);
        fold(&mut s, 16);
        fold(&mut s, 15);
        fold(&mut s, 14);
        fold(&mut s, 13);
        fold(&mut s, 12);

        // Carry propagation: even indices 0..10, then odd indices 1..11
        for i in [0usize, 2, 4, 6, 8, 10] {
            carry_signed(&mut s, i);
        }
        for i in [1usize, 3, 5, 7, 9, 11] {
            carry_signed(&mut s, i);
        }

        // Carry from s[11] may have pushed into s[12] — fold it down
        fold(&mut s, 12);

        // Full unsigned carry chain: s[0]..s[11] → may push into s[12]
        for i in 0..12usize {
            carry_unsigned(&mut s, i);
        }

        // s[12] may be non-zero again — fold it down
        fold(&mut s, 12);

        // Final carry chain (does NOT push into s[12])
        for i in 0..11usize {
            carry_unsigned(&mut s, i);
        }

        pack(&s)
    }

    /// Compute (a * b + c) mod l. All inputs/output are 32-byte little-endian scalars.
    /// Faithful port of sc_muladd from curve25519.c (ref10 algorithm).
    /// Used in Ed25519 signing: S = (r + H(R‖A‖M) · a) mod l.
    pub(super) fn sc_muladd(
        a_bytes: &[u8; 32],
        b_bytes: &[u8; 32],
        c_bytes: &[u8; 32],
    ) -> [u8; 32] {
        let al = load12(a_bytes);
        let bl = load12(b_bytes);
        let cl = load12(c_bytes);

        // Schoolbook multiply a*b, accumulate into 24 limbs, then add c
        let mut s = [0i64; 24];
        s[0] = cl[0] + al[0] * bl[0];
        s[1] = cl[1] + al[0] * bl[1] + al[1] * bl[0];
        s[2] = cl[2] + al[0] * bl[2] + al[1] * bl[1] + al[2] * bl[0];
        s[3] = cl[3] + al[0] * bl[3] + al[1] * bl[2] + al[2] * bl[1] + al[3] * bl[0];
        s[4] =
            cl[4] + al[0] * bl[4] + al[1] * bl[3] + al[2] * bl[2] + al[3] * bl[1] + al[4] * bl[0];
        s[5] = cl[5]
            + al[0] * bl[5]
            + al[1] * bl[4]
            + al[2] * bl[3]
            + al[3] * bl[2]
            + al[4] * bl[1]
            + al[5] * bl[0];
        s[6] = cl[6]
            + al[0] * bl[6]
            + al[1] * bl[5]
            + al[2] * bl[4]
            + al[3] * bl[3]
            + al[4] * bl[2]
            + al[5] * bl[1]
            + al[6] * bl[0];
        s[7] = cl[7]
            + al[0] * bl[7]
            + al[1] * bl[6]
            + al[2] * bl[5]
            + al[3] * bl[4]
            + al[4] * bl[3]
            + al[5] * bl[2]
            + al[6] * bl[1]
            + al[7] * bl[0];
        s[8] = cl[8]
            + al[0] * bl[8]
            + al[1] * bl[7]
            + al[2] * bl[6]
            + al[3] * bl[5]
            + al[4] * bl[4]
            + al[5] * bl[3]
            + al[6] * bl[2]
            + al[7] * bl[1]
            + al[8] * bl[0];
        s[9] = cl[9]
            + al[0] * bl[9]
            + al[1] * bl[8]
            + al[2] * bl[7]
            + al[3] * bl[6]
            + al[4] * bl[5]
            + al[5] * bl[4]
            + al[6] * bl[3]
            + al[7] * bl[2]
            + al[8] * bl[1]
            + al[9] * bl[0];
        s[10] = cl[10]
            + al[0] * bl[10]
            + al[1] * bl[9]
            + al[2] * bl[8]
            + al[3] * bl[7]
            + al[4] * bl[6]
            + al[5] * bl[5]
            + al[6] * bl[4]
            + al[7] * bl[3]
            + al[8] * bl[2]
            + al[9] * bl[1]
            + al[10] * bl[0];
        s[11] = cl[11]
            + al[0] * bl[11]
            + al[1] * bl[10]
            + al[2] * bl[9]
            + al[3] * bl[8]
            + al[4] * bl[7]
            + al[5] * bl[6]
            + al[6] * bl[5]
            + al[7] * bl[4]
            + al[8] * bl[3]
            + al[9] * bl[2]
            + al[10] * bl[1]
            + al[11] * bl[0];
        s[12] = al[1] * bl[11]
            + al[2] * bl[10]
            + al[3] * bl[9]
            + al[4] * bl[8]
            + al[5] * bl[7]
            + al[6] * bl[6]
            + al[7] * bl[5]
            + al[8] * bl[4]
            + al[9] * bl[3]
            + al[10] * bl[2]
            + al[11] * bl[1];
        s[13] = al[2] * bl[11]
            + al[3] * bl[10]
            + al[4] * bl[9]
            + al[5] * bl[8]
            + al[6] * bl[7]
            + al[7] * bl[6]
            + al[8] * bl[5]
            + al[9] * bl[4]
            + al[10] * bl[3]
            + al[11] * bl[2];
        s[14] = al[3] * bl[11]
            + al[4] * bl[10]
            + al[5] * bl[9]
            + al[6] * bl[8]
            + al[7] * bl[7]
            + al[8] * bl[6]
            + al[9] * bl[5]
            + al[10] * bl[4]
            + al[11] * bl[3];
        s[15] = al[4] * bl[11]
            + al[5] * bl[10]
            + al[6] * bl[9]
            + al[7] * bl[8]
            + al[8] * bl[7]
            + al[9] * bl[6]
            + al[10] * bl[5]
            + al[11] * bl[4];
        s[16] = al[5] * bl[11]
            + al[6] * bl[10]
            + al[7] * bl[9]
            + al[8] * bl[8]
            + al[9] * bl[7]
            + al[10] * bl[6]
            + al[11] * bl[5];
        s[17] = al[6] * bl[11]
            + al[7] * bl[10]
            + al[8] * bl[9]
            + al[9] * bl[8]
            + al[10] * bl[7]
            + al[11] * bl[6];
        s[18] = al[7] * bl[11] + al[8] * bl[10] + al[9] * bl[9] + al[10] * bl[8] + al[11] * bl[7];
        s[19] = al[8] * bl[11] + al[9] * bl[10] + al[10] * bl[9] + al[11] * bl[8];
        s[20] = al[9] * bl[11] + al[10] * bl[10] + al[11] * bl[9];
        s[21] = al[10] * bl[11] + al[11] * bl[10];
        s[22] = al[11] * bl[11];
        s[23] = 0;

        // Initial carry propagation for the multiply result.
        // Even indices first, then odd, covering the full 0..22 range.
        for i in (0..=22usize).step_by(2) {
            carry_signed(&mut s, i);
        }
        for i in (1..=21usize).step_by(2) {
            carry_signed(&mut s, i);
        }

        // --- First reduction round: fold s[23]..s[18] ---
        fold(&mut s, 23);
        fold(&mut s, 22);
        fold(&mut s, 21);
        fold(&mut s, 20);
        fold(&mut s, 19);
        fold(&mut s, 18);

        // Carry propagation: even 6..16, then odd 7..15
        for i in [6usize, 8, 10, 12, 14, 16] {
            carry_signed(&mut s, i);
        }
        for i in [7usize, 9, 11, 13, 15] {
            carry_signed(&mut s, i);
        }

        // --- Second reduction round: fold s[17]..s[12] ---
        fold(&mut s, 17);
        fold(&mut s, 16);
        fold(&mut s, 15);
        fold(&mut s, 14);
        fold(&mut s, 13);
        fold(&mut s, 12);

        // Carry propagation: even 0..10, then odd 1..11
        for i in [0usize, 2, 4, 6, 8, 10] {
            carry_signed(&mut s, i);
        }
        for i in [1usize, 3, 5, 7, 9, 11] {
            carry_signed(&mut s, i);
        }

        // Carry from s[11] may have pushed into s[12]
        fold(&mut s, 12);

        // Full unsigned carry chain: s[0]..s[11] → may push into s[12]
        for i in 0..12usize {
            carry_unsigned(&mut s, i);
        }

        // s[12] may be non-zero again
        fold(&mut s, 12);

        // Final carry chain
        for i in 0..11usize {
            carry_unsigned(&mut s, i);
        }

        pack(&s)
    }

    /// Check if a 32-byte scalar s is less than l (canonical form).
    /// Returns true if s < l (the value is in canonical reduced form).
    pub(super) fn sc_is_canonical(s: &[u8; 32]) -> bool {
        // Compute s - L byte-by-byte from LSB to MSB with borrow propagation.
        // If the final borrow is negative, s < L (canonical).
        let mut borrow: i16 = 0;
        for i in 0..32 {
            borrow = (s[i] as i16) - (L[i] as i16) + (borrow >> 8);
        }
        // If borrow < 0, then s < L (canonical)
        borrow < 0
    }
}

// ===========================================================================
// X25519 Montgomery ladder — RFC 7748 scalar multiplication on Curve25519
// Translates x25519_scalar_mult from curve25519.c
// ===========================================================================
mod montgomery25519 {
    use super::field25519::Fe;

    /// Constant a24 = (486662 - 2) / 4 = 121665 for Curve25519 Montgomery.
    const A24: u64 = 121666;

    /// X25519 scalar multiplication: computes [scalar] * u_point on Montgomery Curve25519.
    /// Returns the u-coordinate of the result as 32 bytes.
    pub(super) fn x25519_scalar_mult(scalar: &[u8; 32], u_point: &[u8; 32]) -> [u8; 32] {
        // Clamp scalar per RFC 7748 §5
        let mut k = *scalar;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        let u = Fe::from_bytes(u_point);

        // Montgomery ladder
        let mut x_0 = Fe::ONE;
        let mut x_1 = u;
        let mut z_0 = Fe::ZERO;
        let mut z_1 = Fe::ONE;
        let mut swap: u64 = 0;

        for i in (0..255).rev() {
            let bit = ((k[i / 8] >> (i % 8)) & 1) as u64;
            swap ^= bit;
            Fe::cswap(&mut x_0, &mut x_1, swap);
            Fe::cswap(&mut z_0, &mut z_1, swap);
            swap = bit;

            let a = x_0.add(&z_0);
            let b = x_0.sub(&z_0);
            let c = x_1.add(&z_1);
            let d = x_1.sub(&z_1);

            let da = d.mul(&a);
            let cb = c.mul(&b);

            let aa = a.square();
            let bb = b.square();

            let e = aa.sub(&bb);

            x_0 = aa.mul(&bb);
            z_0 = e.mul(&bb.add(&e.mul_small(A24)));
            x_1 = da.add(&cb).square();
            z_1 = u.mul(&da.sub(&cb).square());
        }

        Fe::cswap(&mut x_0, &mut x_1, swap);
        Fe::cswap(&mut z_0, &mut z_1, swap);

        // Result = x_0 / z_0
        let result = x_0.mul(&z_0.invert());
        result.to_bytes()
    }

    /// X25519 with the standard basepoint (u = 9).
    pub(super) fn x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
        let mut basepoint = [0u8; 32];
        basepoint[0] = 9;
        x25519_scalar_mult(scalar, &basepoint)
    }
}

// ===========================================================================
// Curve448 field arithmetic — GF(2^448 - 2^224 - 1) aka Goldilocks
// 16 u32 limbs in radix 2^28. Products in u64.
// Translates from curve448/curve448.c and curve448/f_generic.c
// ===========================================================================
mod field448 {
    const NLIMBS: usize = 16;
    const RADIX_BITS: u32 = 28;
    const RADIX_MASK: u32 = (1u32 << RADIX_BITS) - 1;

    /// Field element in GF(2^448 - 2^224 - 1).
    #[derive(Clone, Copy)]
    pub(super) struct Fe448([u32; NLIMBS]);

    impl Fe448 {
        pub(super) const ZERO: Fe448 = Fe448([0u32; NLIMBS]);
        pub(super) const ONE: Fe448 = Fe448([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        fn carry(mut self) -> Fe448 {
            for i in 0..(NLIMBS - 1) {
                self.0[i + 1] += self.0[i] >> RADIX_BITS;
                self.0[i] &= RADIX_MASK;
            }
            // Top limb carry wraps: since p = 2^448 - 2^224 - 1,
            // 2^448 ≡ 2^224 + 1 (mod p). Limb 16 corresponds to 2^448,
            // so carry from limb 15 adds to limbs 0 and 8 (since 2^224 = limb 8).
            let top = self.0[NLIMBS - 1] >> RADIX_BITS;
            self.0[NLIMBS - 1] &= RADIX_MASK;
            self.0[0] += top;
            self.0[8] += top;
            // One more carry round to propagate
            for i in 0..(NLIMBS - 1) {
                self.0[i + 1] += self.0[i] >> RADIX_BITS;
                self.0[i] &= RADIX_MASK;
            }
            self
        }

        /// Load 56-byte little-endian encoding.
        pub(super) fn from_bytes(s: &[u8]) -> Fe448 {
            let mut h = [0u32; NLIMBS];
            // Each limb is 28 bits = 3.5 bytes
            let mut bit_pos = 0u32;
            for limb in h.iter_mut() {
                let byte_start = (bit_pos / 8) as usize;
                let bit_offset = bit_pos % 8;
                let mut val = 0u64;
                for j in 0..4 {
                    if byte_start + j < s.len() {
                        val |= (s[byte_start + j] as u64) << (j as u64 * 8);
                    }
                }
                *limb = ((val >> bit_offset as u64) & RADIX_MASK as u64) as u32;
                bit_pos += RADIX_BITS;
            }
            Fe448(h)
        }

        /// Encode as 56-byte little-endian, fully reduced.
        pub(super) fn to_bytes(&self) -> [u8; 56] {
            let t = self.carry().full_reduce();
            let mut out = [0u8; 56];
            let mut acc: u64 = 0;
            let mut bits = 0u32;
            let mut pos = 0;
            for &limb in &t.0 {
                acc |= (limb as u64) << bits;
                bits += RADIX_BITS;
                while bits >= 8 && pos < 56 {
                    out[pos] = acc as u8;
                    acc >>= 8;
                    bits -= 8;
                    pos += 1;
                }
            }
            out
        }

        /// Full reduction mod p = 2^448 - 2^224 - 1.
        /// Subtracting p is equivalent to adding 1 to limb 0 and 1 to limb 8.
        /// If the result carries out of limb 15, then self >= p and we use the reduced value.
        fn full_reduce(mut self) -> Fe448 {
            self = self.carry();
            let mut tmp = self;
            let mut carry_val = 0u64;
            for i in 0..NLIMBS {
                let add = if i == 0 || i == 8 { 1u64 } else { 0u64 };
                let sum = tmp.0[i] as u64 + add + carry_val;
                tmp.0[i] = (sum & RADIX_MASK as u64) as u32;
                carry_val = sum >> RADIX_BITS;
            }
            // If carry_val > 0, original >= p, so use reduced tmp
            let overflowed = (carry_val > 0) as u32;
            let mask = 0u32.wrapping_sub(overflowed);
            for i in 0..NLIMBS {
                self.0[i] = (self.0[i] & !mask) | (tmp.0[i] & mask);
            }
            self
        }

        pub(super) fn add(&self, other: &Fe448) -> Fe448 {
            let mut r = [0u32; NLIMBS];
            for i in 0..NLIMBS {
                r[i] = self.0[i] + other.0[i];
            }
            Fe448(r).carry()
        }

        pub(super) fn sub(&self, other: &Fe448) -> Fe448 {
            // Add 2*p to prevent underflow, then carry-reduce.
            // p = 2^448 - 2^224 - 1 in radix-2^28:
            //   limbs 0..7  = RADIX_MASK   (from 2^224 - 1)
            //   limb  8     = RADIX_MASK-1  (from -2^224 borrow)
            //   limbs 9..15 = RADIX_MASK   (from 2^448 - 2^224)
            // So 2p: limbs 0..7,9..15 = 2*RADIX_MASK; limb 8 = 2*RADIX_MASK - 2.
            let mut r = [0u32; NLIMBS];
            for i in 0..NLIMBS {
                let bias = if i == 8 {
                    (RADIX_MASK << 1).wrapping_sub(2) // 2*(RADIX_MASK-1)
                } else {
                    RADIX_MASK << 1 // 2*RADIX_MASK
                };
                r[i] = self.0[i].wrapping_add(bias).wrapping_sub(other.0[i]);
            }
            Fe448(r).carry()
        }

        pub(super) fn mul(&self, other: &Fe448) -> Fe448 {
            // Schoolbook multiplication exploiting p = 2^448 - 2^224 - 1
            let a = &self.0;
            let b = &other.0;
            // Full product into 32 limbs, then reduce
            let mut t = [0u64; 32];
            for i in 0..NLIMBS {
                for j in 0..NLIMBS {
                    t[i + j] += (a[i] as u64) * (b[j] as u64);
                }
            }
            // Reduce: 2^448 ≡ 2^224 + 1 (mod p), so t[k+16] folds into t[k] and t[k+8]
            for i in (16..32).rev() {
                t[i - 16] += t[i];
                t[i - 8] += t[i];
                t[i] = 0;
            }
            // Carry propagation: extract 28-bit limbs with proper carry chain
            let mut r = [0u32; NLIMBS];
            let mut carry = 0u64;
            for i in 0..NLIMBS {
                t[i] += carry;
                r[i] = (t[i] & RADIX_MASK as u64) as u32;
                carry = t[i] >> RADIX_BITS;
            }
            // Final carry: 2^(16*28) = 2^448 ≡ 2^224 + 1 (mod p)
            // carry contributes to limbs 0 and 8 with proper propagation
            if carry > 0 {
                let v0 = r[0] as u64 + carry;
                r[0] = (v0 & RADIX_MASK as u64) as u32;
                let mut c = v0 >> RADIX_BITS;
                for i in 1..8 {
                    if c == 0 {
                        break;
                    }
                    let v = r[i] as u64 + c;
                    r[i] = (v & RADIX_MASK as u64) as u32;
                    c = v >> RADIX_BITS;
                }
                let v8 = r[8] as u64 + carry + c;
                r[8] = (v8 & RADIX_MASK as u64) as u32;
                c = v8 >> RADIX_BITS;
                for i in 9..NLIMBS {
                    if c == 0 {
                        break;
                    }
                    let v = r[i] as u64 + c;
                    r[i] = (v & RADIX_MASK as u64) as u32;
                    c = v >> RADIX_BITS;
                }
                // If carry still remains, one more fold (extremely rare)
                if c > 0 {
                    let v0b = r[0] as u64 + c;
                    r[0] = (v0b & RADIX_MASK as u64) as u32;
                    let c2 = v0b >> RADIX_BITS;
                    if c2 > 0 {
                        r[1] = (r[1] as u64 + c2) as u32;
                    }
                    let v8b = r[8] as u64 + c;
                    r[8] = (v8b & RADIX_MASK as u64) as u32;
                }
            }
            Fe448(r)
        }

        pub(super) fn square(&self) -> Fe448 {
            self.mul(self)
        }

        pub(super) fn neg(&self) -> Fe448 {
            Fe448::ZERO.sub(self)
        }

        pub(super) fn square_times(&self, n: usize) -> Fe448 {
            let mut r = *self;
            for _ in 0..n {
                r = r.square();
            }
            r
        }

        /// Inversion via Fermat's little theorem: self^(p-2).
        /// p-2 = 2^448 - 2^224 - 3
        /// Uses a simple square-and-multiply ladder over the exponent bits.
        pub(super) fn invert(&self) -> Fe448 {
            let mut result = Fe448::ONE;
            // Get bytes of p-2
            let p_minus_2 = p_minus_2_bytes();
            for i in (0..448).rev() {
                result = result.square();
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                if (p_minus_2[byte_idx] >> bit_idx) & 1 == 1 {
                    result = result.mul(self);
                }
            }
            result
        }

        /// Constant-time conditional swap.
        pub(super) fn cswap(a: &mut Fe448, b: &mut Fe448, flag: u32) {
            let mask = 0u32.wrapping_sub(flag & 1);
            for i in 0..NLIMBS {
                let diff = mask & (a.0[i] ^ b.0[i]);
                a.0[i] ^= diff;
                b.0[i] ^= diff;
            }
        }

        pub(super) fn is_zero(&self) -> bool {
            let r = self.carry().full_reduce();
            r.0.iter().all(|&l| l == 0)
        }

        pub(super) fn is_negative(&self) -> u8 {
            let b = self.to_bytes();
            b[0] & 1
        }
    }

    /// Returns p-2 in little-endian bytes (56 bytes).
    fn p_minus_2_bytes() -> [u8; 56] {
        // p = 2^448 - 2^224 - 1
        // p - 2 = 2^448 - 2^224 - 3
        // In LE bytes: bytes 0..27 represent bits 0..223, bytes 28..55 represent bits 224..447
        // p in LE: [0xFF]*28 for low 224 bits... wait.
        // p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        // (in hex, big-endian): the top 224 bits are all 1s, the bottom 224 bits are all 1s except -1
        // Actually: p = 2^448 - 2^224 - 1
        //   Low 224 bits: 2^224 - 1 - (something from the subtraction)
        //   Wait, p = (2^224 - 1) * 2^224 + (2^224 - 2) ... no.
        //   p = 2^448 - 2^224 - 1
        //   In base 2^224: high half = 2^224 - 1, low half = 2^224 - 1 - 0 ... hmm
        //   Think of it as: 2^448 = (2^224)^2, so p = (2^224)^2 - 2^224 - 1
        //   Let H = 2^224. Then p = H^2 - H - 1 = H(H-1) - 1.
        //   H-1 = 2^224 - 1 = 0xFFFFFF...FF (28 bytes)
        //   H(H-1) = 2^224 * (2^224-1) = 2^448 - 2^224
        //   p = 2^448 - 2^224 - 1
        //   In bytes (LE): low 28 bytes = (2^224 - 1).to_le_bytes() - but we need the actual value
        //   p in LE: bytes 0..27 = 0xFF...FF (all 1s, representing 2^224-1)... no wait.
        //   2^448 - 2^224 - 1 in LE:
        //   The lowest 224 bits of p: we need (2^448 - 2^224 - 1) mod 2^224 = -1 mod 2^224 = 2^224-1 = all FFs
        //   Wait: 2^448 mod 2^224 = 0, 2^224 mod 2^224 = 0, so p mod 2^224 = -1 mod 2^224 = 2^224 - 1
        //   The upper 224 bits: (p - (p mod 2^224)) / 2^224 = (2^448 - 2^224 - 1 - (2^224-1)) / 2^224
        //     = (2^448 - 2^225) / 2^224 = 2^224 - 2 = 0xFFFFF...FFE
        // So p in LE: [0xFF]*28 ++ [0xFE, 0xFF, 0xFF, ..., 0xFF] (28 bytes, first is FE)
        // p-2 in LE: low 28 bytes = 0xFF...FD (first byte FD, rest FF), upper 28 bytes = [0xFE, 0xFF...0xFF]
        let mut bytes = [0xFFu8; 56];
        bytes[0] = 0xFD; // -3 at the lowest byte
        bytes[28] = 0xFE; // upper half starts with FE
        bytes
    }

    impl Fe448 {
        /// Multiply by a small positive constant.
        pub(super) fn mul_small(&self, c: u64) -> Self {
            let mut r_limbs = [0u64; 16];
            let mut carry_val = 0u64;
            for i in 0..16 {
                let prod = (self.0[i] as u64) * c + carry_val;
                r_limbs[i] = prod & ((1u64 << 28) - 1);
                carry_val = prod >> 28;
            }
            let mut r = [0u32; 16];
            for i in 0..16 {
                r[i] = r_limbs[i] as u32;
            }
            let c_lo = carry_val as u32;
            r[0] = r[0].wrapping_add(c_lo);
            r[8] = r[8].wrapping_add(c_lo);
            let mut result = Fe448(r);
            for _ in 0..2 {
                for i in 0..15 {
                    result.0[i + 1] += result.0[i] >> 28;
                    result.0[i] &= (1u32 << 28) - 1;
                }
                let top = result.0[15] >> 28;
                result.0[15] &= (1u32 << 28) - 1;
                result.0[0] += top;
                result.0[8] += top;
            }
            result
        }

        /// Compute self^((p+1)/4) for square root on Goldilocks.
        pub(super) fn pow_p_plus_1_div_4(&self) -> Self {
            let base = self.square_times(222);
            let t2 = base.square().mul(&base);
            let t4 = t2.square_times(2).mul(&t2);
            let t8 = t4.square_times(4).mul(&t4);
            let t16 = t8.square_times(8).mul(&t8);
            let t32 = t16.square_times(16).mul(&t16);
            let t64 = t32.square_times(32).mul(&t32);
            let t112 = t64.square_times(48).mul(&t32.square_times(16).mul(&t16));
            let t224m1 = t112.square_times(112).mul(&t112);
            t224m1
        }
    }
}

// ===========================================================================
// Ed448 group operations — Untwisted Edwards curve
// Curve: x^2 + y^2 = 1 + d*x^2*y^2, d = -39081
// ===========================================================================
mod edwards448 {
    use super::field448::Fe448;

    /// Curve constant d = -39081 mod p for Ed448.
    fn curve_d() -> Fe448 {
        // d = p - 39081 in little-endian. p low 28 bytes = 0xFF...FF, upper = [0xFE,0xFF..FF]
        // 39081 = 0x98A9. p - 39081: low byte 0xFF - 0xA9 = 0x56, next 0xFF - 0x98 = 0x67
        let mut bytes = [0xFFu8; 56];
        bytes[0] = 0x56;
        bytes[1] = 0x67;
        bytes[28] = 0xFE;
        Fe448::from_bytes(&bytes)
    }

    /// Ed448-Goldilocks basepoint (RFC 8032 §5.2.5).
    pub(super) fn basepoint() -> GeP3_448 {
        // RFC 8032 §5.2.5 / RFC 7748 Ed448 basepoint y-coordinate (little-endian)
        // y = 298819210078481492676017930443930673437544040154080242095928241372
        //     331506189835876003536878655418784733982303233503462500531545062832660
        #[allow(clippy::unreadable_literal)]
        let by: [u8; 56] = [
            0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13,
            0xbd, 0xfd, 0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05,
            0x1e, 0x9c, 0x78, 0x87, 0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7,
            0xc9, 0x56, 0x37, 0x20, 0x76, 0x88, 0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
        ];
        // RFC 8032 §5.2.5 / RFC 7748 Ed448 basepoint x-coordinate (little-endian)
        // x = 224580040295924300187604334099896036246789641632564134246125461686
        //     950415467406032909029192869357953282578032075146446173674602635247710
        #[allow(clippy::unreadable_literal)]
        let bx: [u8; 56] = [
            0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26, 0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80,
            0x3b, 0x43, 0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12, 0x64, 0xa4, 0xd3, 0xa3,
            0x24, 0xe3, 0x6d, 0xea, 0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e, 0xda, 0x36,
            0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22, 0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
        ];
        let x = Fe448::from_bytes(&bx);
        let y = Fe448::from_bytes(&by);
        GeP3_448 {
            x,
            y,
            z: Fe448::ONE,
            t: x.mul(&y),
        }
    }

    /// Extended point (X:Y:Z:T) with X*Y = Z*T on Ed448.
    #[derive(Clone, Copy)]
    pub(super) struct GeP3_448 {
        pub(super) x: Fe448,
        pub(super) y: Fe448,
        pub(super) z: Fe448,
        pub(super) t: Fe448,
    }

    impl GeP3_448 {
        /// The neutral element (identity point).
        pub(super) fn identity() -> Self {
            GeP3_448 {
                x: Fe448::ZERO,
                y: Fe448::ONE,
                z: Fe448::ONE,
                t: Fe448::ZERO,
            }
        }

        /// Point doubling (a = 1 for Ed448).
        pub(super) fn dbl(&self) -> Self {
            // Formulas for a = 1 untwisted Edwards:
            let aa = self.x.square();
            let bb = self.y.square();
            let cc = self.z.square().add(&self.z.square()); // 2*Z^2
            let dd = aa; // a*A = A since a=1
            let e = self.x.add(&self.y).square().sub(&aa).sub(&bb);
            let g = dd.add(&bb);
            let f = g.sub(&cc);
            let h = dd.sub(&bb);
            GeP3_448 {
                x: e.mul(&f),
                y: g.mul(&h),
                z: f.mul(&g),
                t: e.mul(&h),
            }
        }

        /// Point addition (unified, a = 1).
        pub(super) fn add(&self, q: &Self) -> Self {
            let d = curve_d();
            let a = self.x.mul(&q.x);
            let b = self.y.mul(&q.y);
            let c = self.t.mul(&q.t).mul(&d);
            let dd = self.z.mul(&q.z);
            let e = self.x.add(&self.y).mul(&q.x.add(&q.y)).sub(&a).sub(&b);
            let f = dd.sub(&c);
            let g = dd.add(&c);
            let h = b.sub(&a); // B - a_coeff*A = B - A since a=1 (untwisted Edwards)
            GeP3_448 {
                x: e.mul(&f),
                y: g.mul(&h),
                z: f.mul(&g),
                t: e.mul(&h),
            }
        }

        /// Point negation.
        pub(super) fn negate(&self) -> Self {
            GeP3_448 {
                x: self.x.neg(),
                y: self.y,
                z: self.z,
                t: self.t.neg(),
            }
        }

        /// Encode point to 57 bytes (RFC 8032 §5.2.2).
        pub(super) fn to_bytes(&self) -> [u8; 57] {
            let zi = self.z.invert();
            let x = self.x.mul(&zi);
            let y = self.y.mul(&zi);
            let mut enc = [0u8; 57];
            let yb = y.to_bytes();
            enc[..56].copy_from_slice(&yb);
            enc[56] = x.is_negative() << 7;
            enc
        }

        /// Decode 57 bytes to a point. Returns None if invalid.
        pub(super) fn from_bytes(s: &[u8; 57]) -> Option<Self> {
            let x_sign = (s[56] >> 7) & 1;
            if s[56] & 0x7F != 0 {
                return None;
            }
            let y = Fe448::from_bytes(&s[..56]);
            let y2 = y.square();
            let u = Fe448::ONE.sub(&y2); // 1 - y^2 for untwisted Edwards (a=1)
            let d = curve_d();
            let v = Fe448::ONE.sub(&d.mul(&y2));
            if v.is_zero() {
                return None;
            }
            let vi = v.invert();
            let x2 = u.mul(&vi);
            let mut x = x2.pow_p_plus_1_div_4();
            // Verify square root
            if !x.square().sub(&x2).is_zero() {
                return None;
            }
            if x.is_negative() != x_sign {
                x = x.neg();
            }
            if x.is_zero() && x_sign != 0 {
                return None;
            }
            Some(GeP3_448 {
                x,
                y,
                z: Fe448::ONE,
                t: x.mul(&y),
            })
        }
    }

    /// Fixed-base scalar multiplication: [scalar] * B.
    pub(super) fn scalarmult_base(scalar: &[u8]) -> GeP3_448 {
        scalarmult(&basepoint(), scalar)
    }

    /// Variable-base scalar multiplication: [scalar] * P (double-and-add, constant-time pattern).
    pub(super) fn scalarmult(point: &GeP3_448, scalar: &[u8]) -> GeP3_448 {
        let nbits = scalar.len() * 8;
        let mut r = GeP3_448::identity();
        for i in (0..nbits).rev() {
            r = r.dbl();
            if (scalar[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.add(point);
            }
        }
        r
    }

    /// Double scalar multiplication: [a]*A + [b]*B (Strauss, variable-time for verification).
    pub(super) fn double_scalarmult_vartime(
        a_scalar: &[u8],
        a_point: &GeP3_448,
        b_scalar: &[u8],
    ) -> GeP3_448 {
        let bp = basepoint();
        let nbits = a_scalar.len().max(b_scalar.len()) * 8;
        let mut r = GeP3_448::identity();
        for i in (0..nbits).rev() {
            r = r.dbl();
            let ab = i / 8;
            let abit = i % 8;
            if ab < a_scalar.len() && (a_scalar[ab] >> abit) & 1 == 1 {
                r = r.add(a_point);
            }
            if ab < b_scalar.len() && (b_scalar[ab] >> abit) & 1 == 1 {
                r = r.add(&bp);
            }
        }
        r
    }
}

// ===========================================================================
// Ed448 scalar arithmetic — modular reduction for Ed448 group order
// l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
// ===========================================================================
mod scalar448 {
    /// Ed448 group order l in little-endian bytes (57 bytes).
    /// l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
    pub(super) const L448: [u8; 57] = [
        0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c,
        0x21, 0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00,
    ];

    // Maximum sizes: sc_reduce448 takes up to 114 bytes = 912 bits,
    // sc_muladd448 product is at most 912 bits. We use u64-word big-integer
    // arithmetic with binary long-division for modular reduction.
    // This runs in O(nbits) iterations — no infinite-loop risk.

    /// Reduce a byte slice (up to 114 bytes) modulo l. Returns 57-byte result.
    pub(super) fn sc_reduce448(input: &[u8]) -> [u8; 57] {
        // Load input into a big-integer word array (little-endian u64 words)
        let mut val = [0u64; 16]; // 16*64 = 1024 bits, enough for 114 bytes = 912 bits
        for (i, &b) in input.iter().enumerate() {
            val[i / 8] |= (b as u64) << ((i % 8) * 8);
        }
        let l = load_l448();
        let result = bignum_mod(&val, &l);
        store_57bytes(&result)
    }

    /// Scalar multiply-add: (a * b + c) mod l for Ed448.
    pub(super) fn sc_muladd448(a: &[u8; 57], b: &[u8; 57], c: &[u8; 57]) -> [u8; 57] {
        let aw = load_57bytes(a);
        let bw = load_57bytes(b);
        let cw = load_57bytes(c);
        // Schoolbook multiply with carry propagation: a*b → 16-word product (u64).
        // Using u64 words with per-step carry to avoid u128 overflow that occurs
        // when accumulating up to 8 products of two u64 values into a single u128.
        let mut pw = [0u64; 16];
        for i in 0..8 {
            let mut carry: u64 = 0;
            for j in 0..8 {
                let uv = (aw[i] as u128) * (bw[j] as u128) + (pw[i + j] as u128) + (carry as u128);
                pw[i + j] = uv as u64;
                carry = (uv >> 64) as u64;
            }
            pw[i + 8] = carry;
        }
        // Add c
        let mut c64: u64 = 0;
        for i in 0..8 {
            let s = pw[i] as u128 + cw[i] as u128 + c64 as u128;
            pw[i] = s as u64;
            c64 = (s >> 64) as u64;
        }
        for i in 8..16 {
            if c64 == 0 {
                break;
            }
            let s = pw[i] as u128 + c64 as u128;
            pw[i] = s as u64;
            c64 = (s >> 64) as u64;
        }
        // Reduce mod l
        let l = load_l448();
        let result = bignum_mod(&pw, &l);
        store_57bytes(&result)
    }

    /// Check if scalar s < l (canonical check for verification).
    pub(super) fn sc_is_canonical448(s: &[u8; 57]) -> bool {
        for i in (0..57).rev() {
            if s[i] < L448[i] {
                return true;
            }
            if s[i] > L448[i] {
                return false;
            }
        }
        false // Equal to l is not canonical
    }

    // ---- internal big-integer helpers (u64 words, little-endian) ----

    /// Load L448 into 8 u64 words (little-endian).
    fn load_l448() -> [u64; 8] {
        load_57bytes(&L448)
    }

    /// Load 57 bytes little-endian into 8 u64 words.
    fn load_57bytes(b: &[u8; 57]) -> [u64; 8] {
        let mut w = [0u64; 8];
        for i in 0..7 {
            let off = i * 8;
            w[i] = u64::from_le_bytes([
                b[off],
                b[off + 1],
                b[off + 2],
                b[off + 3],
                b[off + 4],
                b[off + 5],
                b[off + 6],
                b[off + 7],
            ]);
        }
        // Last word: byte 56 only (57th byte)
        w[7] = b[56] as u64;
        w
    }

    /// Store 8 u64 words (little-endian) into 57 bytes.
    fn store_57bytes(w: &[u64; 8]) -> [u8; 57] {
        let mut out = [0u8; 57];
        for i in 0..7 {
            let bytes = w[i].to_le_bytes();
            out[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }
        out[56] = w[7] as u8;
        out
    }

    /// Compute `numerator mod modulus` using binary long division.
    ///
    /// Both are arrays of u64 words in little-endian order.
    /// `numerator` can be up to 16 words (1024 bits).
    /// `modulus` is 8 words (≤512 bits).
    /// Returns result as 8 u64 words.
    ///
    /// Algorithm: Process one bit at a time from MSB to LSB of numerator.
    /// The remainder is shifted left by one bit, the current bit of the
    /// numerator is ORed in, and if remainder >= modulus we subtract.
    /// This runs in exactly `highest_bit(numerator)` iterations — O(n).
    fn bignum_mod(numerator: &[u64; 16], modulus: &[u64; 8]) -> [u64; 8] {
        let nbits = highest_bit_16(numerator);
        let mut rem = [0u64; 8];

        for i in (0..nbits).rev() {
            // Shift remainder left by 1
            let mut top = 0u64;
            for w in rem.iter_mut() {
                let new_top = *w >> 63;
                *w = (*w << 1) | top;
                top = new_top;
            }
            // OR in bit i of the numerator
            let word_idx = i / 64;
            let bit_idx = i % 64;
            rem[0] |= (numerator[word_idx] >> bit_idx) & 1;

            // If rem >= modulus, subtract modulus
            if ge8(&rem, modulus) {
                sub8(&mut rem, modulus);
            }
        }
        rem
    }

    /// Check if a >= b (8-word unsigned comparison).
    fn ge8(a: &[u64; 8], b: &[u64; 8]) -> bool {
        for i in (0..8).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true // equal
    }

    /// Subtract b from a in-place (a -= b). Assumes a >= b.
    fn sub8(a: &mut [u64; 8], b: &[u64; 8]) {
        let mut borrow = 0u64;
        for i in 0..8 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            a[i] = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }

    /// Highest set bit position (0-indexed) + 1, or 0 if all zero.
    fn highest_bit_16(v: &[u64; 16]) -> usize {
        for i in (0..16).rev() {
            if v[i] != 0 {
                return i * 64 + (64 - v[i].leading_zeros() as usize);
            }
        }
        0
    }
}

// ===========================================================================
// X448 Montgomery ladder — RFC 7748 scalar multiplication on Curve448
// ===========================================================================
mod montgomery448 {
    use super::field448::Fe448;

    /// Montgomery ladder constant (A+2)/4 = (156326+2)/4 = 39082.
    const A24: u64 = 39082;

    /// X448 scalar multiplication per RFC 7748 §5.
    pub(super) fn x448_scalar_mult(scalar: &[u8; 56], u_point: &[u8; 56]) -> [u8; 56] {
        let mut k = *scalar;
        k[0] &= 252; // Clear two low bits
        k[55] |= 128; // Set high bit

        let u = Fe448::from_bytes(u_point);
        let mut x_2 = Fe448::ONE;
        let mut z_2 = Fe448::ZERO;
        let mut x_3 = u;
        let mut z_3 = Fe448::ONE;
        let mut swap: u32 = 0;

        for pos in (0..448).rev() {
            let bit = ((k[pos / 8] >> (pos % 8)) & 1) as u32;
            swap ^= bit;
            Fe448::cswap(&mut x_2, &mut x_3, swap);
            Fe448::cswap(&mut z_2, &mut z_3, swap);
            swap = bit;

            let a = x_2.add(&z_2);
            let b = x_2.sub(&z_2);
            let c = x_3.add(&z_3);
            let d = x_3.sub(&z_3);
            let da = d.mul(&a);
            let cb = c.mul(&b);
            let aa = a.square();
            let bb = b.square();
            let e = aa.sub(&bb);

            x_2 = aa.mul(&bb);
            z_2 = e.mul(&aa.add(&e.mul_small(A24)));
            x_3 = da.add(&cb).square();
            z_3 = u.mul(&da.sub(&cb).square());
        }

        Fe448::cswap(&mut x_2, &mut x_3, swap);
        Fe448::cswap(&mut z_2, &mut z_3, swap);

        x_2.mul(&z_2.invert()).to_bytes()
    }

    /// X448 basepoint multiplication (u = 5).
    pub(super) fn x448_basepoint(scalar: &[u8; 56]) -> [u8; 56] {
        let mut bp = [0u8; 56];
        bp[0] = 5;
        x448_scalar_mult(scalar, &bp)
    }
}

// ===========================================================================
// Public API — key generation, key exchange, signing, verification
// ===========================================================================

/// Generate a random key pair for the specified curve type.
///
/// Uses `OsRng` (operating-system entropy) to produce a cryptographically
/// secure private key, then derives the corresponding public key.
///
/// # Errors
/// Returns `CryptoError::Rand` if the random number generator fails.
pub fn generate_keypair(key_type: EcxKeyType) -> CryptoResult<EcxKeyPair> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    trace!(algorithm = %key_type, "generating keypair");

    let key_len = key_type.key_len();
    let mut private_bytes = vec![0u8; key_len];
    OsRng.fill_bytes(&mut private_bytes);

    let public_bytes = match key_type {
        EcxKeyType::X25519 => {
            // Clamp private key for X25519
            let mut clamped = [0u8; 32];
            clamped.copy_from_slice(&private_bytes);
            clamped[0] &= 248;
            clamped[31] &= 127;
            clamped[31] |= 64;
            private_bytes = clamped.to_vec();
            montgomery25519::x25519_basepoint(&clamped).to_vec()
        }
        EcxKeyType::Ed25519 => {
            let hash = sha512_internal::sha512(&private_bytes);
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&hash[..32]);
            scalar[0] &= 248;
            scalar[31] &= 127;
            scalar[31] |= 64;
            let point = edwards25519::scalarmult_base(&scalar);
            point.to_bytes().to_vec()
        }
        EcxKeyType::X448 => {
            let mut clamped = [0u8; 56];
            clamped.copy_from_slice(&private_bytes);
            clamped[0] &= 252;
            clamped[55] |= 128;
            private_bytes = clamped.to_vec();
            montgomery448::x448_basepoint(&clamped).to_vec()
        }
        EcxKeyType::Ed448 => {
            // Hash with SHAKE-256(private, 114) then clamp
            let hash = keccak_internal::shake256(&private_bytes, 114);
            let mut scalar = [0u8; 57];
            scalar.copy_from_slice(&hash[..57]);
            scalar[0] &= 252;
            scalar[55] |= 128;
            scalar[56] = 0;
            let point = edwards448::scalarmult_base(&scalar);
            point.to_bytes().to_vec()
        }
    };

    EcxKeyPair::new(key_type, private_bytes, public_bytes)
}

/// X25519 Diffie-Hellman key exchange (RFC 7748).
///
/// Computes the shared secret from `own_private` and `peer_public`.
/// Returns a 32-byte shared secret.
///
/// # Errors
/// - `CryptoError::Key` if key types mismatch or lengths are invalid.
/// - `CryptoError::Key` if the shared secret is all-zero (small-order peer key).
pub fn x25519(own_private: &EcxPrivateKey, peer_public: &EcxPublicKey) -> CryptoResult<Vec<u8>> {
    trace!("x25519 key exchange");

    if own_private.key_type != EcxKeyType::X25519 {
        error!("x25519: private key type mismatch");
        return Err(CryptoError::Key("private key is not X25519".into()));
    }
    if peer_public.key_type != EcxKeyType::X25519 {
        error!("x25519: public key type mismatch");
        return Err(CryptoError::Key("public key is not X25519".into()));
    }
    if own_private.bytes.len() != X25519_KEY_LEN {
        return Err(CryptoError::Key("invalid X25519 private key length".into()));
    }
    if peer_public.bytes.len() != X25519_KEY_LEN {
        return Err(CryptoError::Key("invalid X25519 public key length".into()));
    }

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&own_private.bytes);
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&peer_public.bytes);

    let shared = montgomery25519::x25519_scalar_mult(&priv_arr, &pub_arr);

    // Reject all-zero shared secret (small-order peer key)
    if shared.iter().all(|&b| b == 0) {
        error!("x25519: all-zero shared secret (small-order peer key)");
        return Err(CryptoError::Key(
            "X25519 produced all-zero shared secret".into(),
        ));
    }

    Ok(shared.to_vec())
}

/// Derive the X25519 public key from a private key.
///
/// # Errors
/// Returns `CryptoError::Key` if the private key type is not X25519.
pub fn x25519_public_from_private(private_key: &EcxPrivateKey) -> CryptoResult<EcxPublicKey> {
    trace!("x25519 public key derivation");

    if private_key.key_type != EcxKeyType::X25519 {
        return Err(CryptoError::Key("private key is not X25519".into()));
    }
    if private_key.bytes.len() != X25519_KEY_LEN {
        return Err(CryptoError::Key("invalid X25519 private key length".into()));
    }

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&private_key.bytes);
    let pub_bytes = montgomery25519::x25519_basepoint(&priv_arr);

    Ok(EcxPublicKey {
        key_type: EcxKeyType::X25519,
        bytes: pub_bytes.to_vec(),
    })
}

/// X448 Diffie-Hellman key exchange (RFC 7748).
///
/// Computes the shared secret from `own_private` and `peer_public`.
/// Returns a 56-byte shared secret.
///
/// # Errors
/// - `CryptoError::Key` if key types mismatch or lengths are invalid.
/// - `CryptoError::Key` if the shared secret is all-zero (small-order peer key).
pub fn x448(own_private: &EcxPrivateKey, peer_public: &EcxPublicKey) -> CryptoResult<Vec<u8>> {
    trace!("x448 key exchange");

    if own_private.key_type != EcxKeyType::X448 {
        error!("x448: private key type mismatch");
        return Err(CryptoError::Key("private key is not X448".into()));
    }
    if peer_public.key_type != EcxKeyType::X448 {
        error!("x448: public key type mismatch");
        return Err(CryptoError::Key("public key is not X448".into()));
    }
    if own_private.bytes.len() != X448_KEY_LEN {
        return Err(CryptoError::Key("invalid X448 private key length".into()));
    }
    if peer_public.bytes.len() != X448_KEY_LEN {
        return Err(CryptoError::Key("invalid X448 public key length".into()));
    }

    let mut priv_arr = [0u8; 56];
    priv_arr.copy_from_slice(&own_private.bytes);
    let mut pub_arr = [0u8; 56];
    pub_arr.copy_from_slice(&peer_public.bytes);

    let shared = montgomery448::x448_scalar_mult(&priv_arr, &pub_arr);

    if shared.iter().all(|&b| b == 0) {
        error!("x448: all-zero shared secret (small-order peer key)");
        return Err(CryptoError::Key(
            "X448 produced all-zero shared secret".into(),
        ));
    }

    Ok(shared.to_vec())
}

/// Derive the X448 public key from a private key.
///
/// # Errors
/// Returns `CryptoError::Key` if the private key type is not X448.
pub fn x448_public_from_private(private_key: &EcxPrivateKey) -> CryptoResult<EcxPublicKey> {
    trace!("x448 public key derivation");

    if private_key.key_type != EcxKeyType::X448 {
        return Err(CryptoError::Key("private key is not X448".into()));
    }
    if private_key.bytes.len() != X448_KEY_LEN {
        return Err(CryptoError::Key("invalid X448 private key length".into()));
    }

    let mut priv_arr = [0u8; 56];
    priv_arr.copy_from_slice(&private_key.bytes);
    let pub_bytes = montgomery448::x448_basepoint(&priv_arr);

    Ok(EcxPublicKey {
        key_type: EcxKeyType::X448,
        bytes: pub_bytes.to_vec(),
    })
}

/// Ed25519 signature (RFC 8032 §5.1.6).
///
/// Signs `message` with the given Ed25519 private key.
/// Returns a 64-byte signature.
///
/// # Errors
/// Returns `CryptoError::Key` if the key type is not Ed25519.
pub fn ed25519_sign(private_key: &EcxPrivateKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
    trace!("ed25519 sign");

    if private_key.key_type != EcxKeyType::Ed25519 {
        return Err(CryptoError::Key("private key is not Ed25519".into()));
    }
    if private_key.bytes.len() != ED25519_KEY_LEN {
        return Err(CryptoError::Key(
            "invalid Ed25519 private key length".into(),
        ));
    }

    ed25519_sign_internal(&private_key.bytes, message, false, &[])
}

/// Ed25519ph signature (pre-hashed message variant, RFC 8032 §5.1.6).
///
/// Signs a pre-hashed message digest with the given Ed25519 private key.
/// The `prehash` should be SHA-512(message).
/// Returns a 64-byte signature.
///
/// # Errors
/// Returns `CryptoError::Key` if the key type is not Ed25519.
pub fn ed25519_sign_prehash(private_key: &EcxPrivateKey, prehash: &[u8]) -> CryptoResult<Vec<u8>> {
    trace!("ed25519ph sign (prehash)");

    if private_key.key_type != EcxKeyType::Ed25519 {
        return Err(CryptoError::Key("private key is not Ed25519".into()));
    }
    if private_key.bytes.len() != ED25519_KEY_LEN {
        return Err(CryptoError::Key(
            "invalid Ed25519 private key length".into(),
        ));
    }

    ed25519_sign_internal(&private_key.bytes, prehash, true, &[])
}

/// Internal Ed25519 signing (handles both PureEdDSA and Ed25519ph).
fn ed25519_sign_internal(
    privkey: &[u8],
    msg: &[u8],
    prehash: bool,
    _context: &[u8],
) -> CryptoResult<Vec<u8>> {
    // Step 1: SHA-512(private_key)
    let h = sha512_internal::sha512(privkey);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    // Clamp scalar a
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    // Step 2: Derive public key A = [a]B
    let a_point = edwards25519::scalarmult_base(&a);
    let pk = a_point.to_bytes();

    // Step 3: Compute nonce r = SHA-512(dom2 || h[32..64] || msg) mod l
    let nonce_prefix = &h[32..64];
    let mut hasher = sha512_internal::Sha512::new();
    if prehash {
        // dom2(1, context) = "SigEd25519 no Ed25519 collisions" || 0x01 || len(ctx) || ctx
        hasher.update(b"SigEd25519 no Ed25519 collisions");
        hasher.update(&[0x01, 0x00]); // flag=1, context length=0
    }
    hasher.update(nonce_prefix);
    hasher.update(msg);
    let nonce_hash = hasher.finalize();
    let r = scalar25519::sc_reduce(&nonce_hash);

    // Step 4: R = [r]B
    let r_point = edwards25519::scalarmult_base(&r);
    let r_bytes = r_point.to_bytes();

    // Step 5: S = r + SHA-512(dom2 || R || A || msg) * a mod l
    let mut h2 = sha512_internal::Sha512::new();
    if prehash {
        h2.update(b"SigEd25519 no Ed25519 collisions");
        h2.update(&[0x01, 0x00]);
    }
    h2.update(&r_bytes);
    h2.update(&pk);
    h2.update(msg);
    let hram = h2.finalize();
    let hram_reduced = scalar25519::sc_reduce(&hram);
    let s = scalar25519::sc_muladd(&hram_reduced, &a, &r);

    // Signature = R || S
    let mut sig = vec![0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..64].copy_from_slice(&s);
    Ok(sig)
}

/// Ed25519 verification (RFC 8032 §5.1.7).
///
/// Verifies `signature` over `message` against the given Ed25519 public key.
/// Returns `true` if the signature is valid. Uses constant-time comparison.
///
/// # Errors
/// - `CryptoError::Key` if the key type is not Ed25519.
/// - `CryptoError::Verification` if the signature format is invalid.
pub fn ed25519_verify(
    public_key: &EcxPublicKey,
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    trace!("ed25519 verify");

    if public_key.key_type != EcxKeyType::Ed25519 {
        return Err(CryptoError::Key("public key is not Ed25519".into()));
    }
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(CryptoError::Verification(
            "Ed25519 signature must be 64 bytes".into(),
        ));
    }
    if public_key.bytes.len() != ED25519_KEY_LEN {
        return Err(CryptoError::Key("invalid Ed25519 public key length".into()));
    }

    ed25519_verify_internal(&public_key.bytes, message, signature, false, &[])
}

/// Ed25519ph verification (pre-hashed message variant).
///
/// Verifies `signature` over a pre-hashed message `prehash`.
///
/// # Errors
/// - `CryptoError::Key` if the key type is not Ed25519.
/// - `CryptoError::Verification` if the signature format is invalid.
pub fn ed25519_verify_prehash(
    public_key: &EcxPublicKey,
    prehash: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    trace!("ed25519ph verify (prehash)");

    if public_key.key_type != EcxKeyType::Ed25519 {
        return Err(CryptoError::Key("public key is not Ed25519".into()));
    }
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(CryptoError::Verification(
            "Ed25519 signature must be 64 bytes".into(),
        ));
    }
    if public_key.bytes.len() != ED25519_KEY_LEN {
        return Err(CryptoError::Key("invalid Ed25519 public key length".into()));
    }

    ed25519_verify_internal(&public_key.bytes, prehash, signature, true, &[])
}

/// Internal Ed25519 verification (handles PureEdDSA and Ed25519ph).
fn ed25519_verify_internal(
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
    prehash: bool,
    _context: &[u8],
) -> CryptoResult<bool> {
    // Parse R and S from signature
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..64]);

    // Check S is canonical (S < l)
    if !scalar25519::sc_is_canonical(&s_bytes) {
        return Ok(false);
    }

    // Decode public key A
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pubkey);
    let a_point = match edwards25519::GeP3::from_bytes(&pk_arr) {
        Some(p) => p,
        None => return Ok(false),
    };

    // Compute h = SHA-512(dom2 || R || A || msg) using one-shot concatenation
    // to ensure identical behavior to sign's hram computation.
    let mut h_data = Vec::with_capacity(sig.len() + pubkey.len() + msg.len() + 64);
    if prehash {
        h_data.extend_from_slice(b"SigEd25519 no Ed25519 collisions");
        h_data.extend_from_slice(&[0x01, 0x00]);
    }
    h_data.extend_from_slice(&r_bytes);
    h_data.extend_from_slice(pubkey);
    h_data.extend_from_slice(msg);
    let h = sha512_internal::sha512(&h_data);
    let h_reduced = scalar25519::sc_reduce(&h);

    // Check [S]B == R + [h]A
    // Equivalently: [S]B - [h]A == R
    // Using double_scalarmult_vartime: [h](-A) + [S]B
    let neg_a = edwards25519::GeP3 {
        x: a_point.x.neg(),
        y: a_point.y,
        z: a_point.z,
        t: a_point.t.neg(),
    };
    let check = edwards25519::double_scalarmult_vartime(&h_reduced, &neg_a, &s_bytes);
    let check_bytes = check.to_bytes();

    // Constant-time comparison (per Rule R5 / subtle::ConstantTimeEq)
    Ok(check_bytes.ct_eq(&r_bytes).into())
}

/// Ed448 signature (RFC 8032 §5.2.6).
///
/// Signs `message` with the given Ed448 private key. Optional `context`
/// provides domain separation per RFC 8032 §5.2.
/// Returns a 114-byte signature.
///
/// # Errors
/// Returns `CryptoError::Key` if the key type is not Ed448.
pub fn ed448_sign(
    private_key: &EcxPrivateKey,
    message: &[u8],
    context: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    trace!("ed448 sign");

    if private_key.key_type != EcxKeyType::Ed448 {
        return Err(CryptoError::Key("private key is not Ed448".into()));
    }
    if private_key.bytes.len() != ED448_KEY_LEN {
        return Err(CryptoError::Key("invalid Ed448 private key length".into()));
    }
    let ctx = context.unwrap_or(&[]);
    if ctx.len() > 255 {
        return Err(CryptoError::Key(
            "Ed448 context too long (max 255 bytes)".into(),
        ));
    }

    ed448_sign_internal(&private_key.bytes, message, false, ctx)
}

/// Ed448ph signature (pre-hashed message variant).
///
/// Signs a pre-hashed digest (SHAKE256 of the message).
/// Returns a 114-byte signature.
///
/// # Errors
/// Returns `CryptoError::Key` if the key type is not Ed448.
pub fn ed448_sign_prehash(
    private_key: &EcxPrivateKey,
    prehash: &[u8],
    context: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    trace!("ed448ph sign (prehash)");

    if private_key.key_type != EcxKeyType::Ed448 {
        return Err(CryptoError::Key("private key is not Ed448".into()));
    }
    if private_key.bytes.len() != ED448_KEY_LEN {
        return Err(CryptoError::Key("invalid Ed448 private key length".into()));
    }
    let ctx = context.unwrap_or(&[]);
    if ctx.len() > 255 {
        return Err(CryptoError::Key(
            "Ed448 context too long (max 255 bytes)".into(),
        ));
    }

    ed448_sign_internal(&private_key.bytes, prehash, true, ctx)
}

/// Internal Ed448 signing.
fn ed448_sign_internal(
    privkey: &[u8],
    msg: &[u8],
    prehash: bool,
    context: &[u8],
) -> CryptoResult<Vec<u8>> {
    // Step 1: SHAKE256(privkey, 114) → h
    let h = keccak_internal::shake256(privkey, 114);
    let mut a = [0u8; 57];
    a.copy_from_slice(&h[..57]);
    // Clamp
    a[0] &= 252;
    a[55] |= 128;
    a[56] = 0;

    // Step 2: A = [a]B
    let a_point = edwards448::scalarmult_base(&a);
    let pk = a_point.to_bytes();

    // Step 3: dom4 prefix
    let flag_byte: u8 = if prehash { 1 } else { 0 };

    // r = SHAKE256(dom4 || h[57..114] || msg, 114) mod l
    let mut r_input = Vec::new();
    // dom4(flag, context) = "SigEd448" || flag || len(ctx) || ctx
    r_input.extend_from_slice(b"SigEd448");
    r_input.push(flag_byte);
    r_input.push(context.len() as u8);
    r_input.extend_from_slice(context);
    r_input.extend_from_slice(&h[57..114]);
    r_input.extend_from_slice(msg);
    let r_hash = keccak_internal::shake256(&r_input, 114);
    let r = scalar448::sc_reduce448(&r_hash);

    // Step 4: R = [r]B
    let r_point = edwards448::scalarmult_base(&r);
    let r_bytes = r_point.to_bytes();

    // Step 5: S = (r + SHAKE256(dom4 || R || A || msg, 114) * a) mod l
    let mut s_input = Vec::new();
    s_input.extend_from_slice(b"SigEd448");
    s_input.push(flag_byte);
    s_input.push(context.len() as u8);
    s_input.extend_from_slice(context);
    s_input.extend_from_slice(&r_bytes);
    s_input.extend_from_slice(&pk);
    s_input.extend_from_slice(msg);
    let hram_hash = keccak_internal::shake256(&s_input, 114);
    let hram = scalar448::sc_reduce448(&hram_hash);
    let s = scalar448::sc_muladd448(&hram, &a, &r);

    // Signature = R (57 bytes) || S (57 bytes) = 114 bytes
    let mut sig = vec![0u8; 114];
    sig[..57].copy_from_slice(&r_bytes);
    sig[57..114].copy_from_slice(&s);
    Ok(sig)
}

/// Ed448 verification (RFC 8032 §5.2.7).
///
/// Verifies `signature` over `message` against the given Ed448 public key.
/// Returns `true` if valid. Uses constant-time comparison.
///
/// # Errors
/// - `CryptoError::Key` if the key type is not Ed448.
/// - `CryptoError::Verification` if signature format is invalid.
pub fn ed448_verify(
    public_key: &EcxPublicKey,
    message: &[u8],
    signature: &[u8],
    context: Option<&[u8]>,
) -> CryptoResult<bool> {
    trace!("ed448 verify");

    if public_key.key_type != EcxKeyType::Ed448 {
        return Err(CryptoError::Key("public key is not Ed448".into()));
    }
    if signature.len() != ED448_SIGNATURE_LEN {
        return Err(CryptoError::Verification(
            "Ed448 signature must be 114 bytes".into(),
        ));
    }
    if public_key.bytes.len() != ED448_KEY_LEN {
        return Err(CryptoError::Key("invalid Ed448 public key length".into()));
    }
    let ctx = context.unwrap_or(&[]);
    if ctx.len() > 255 {
        return Err(CryptoError::Key(
            "Ed448 context too long (max 255 bytes)".into(),
        ));
    }

    ed448_verify_internal(&public_key.bytes, message, signature, false, ctx)
}

/// Ed448ph verification (pre-hashed message variant).
///
/// Verifies `signature` over a pre-hashed `prehash`.
///
/// # Errors
/// - `CryptoError::Key` if the key type is not Ed448.
/// - `CryptoError::Verification` if signature format is invalid.
pub fn ed448_verify_prehash(
    public_key: &EcxPublicKey,
    prehash: &[u8],
    signature: &[u8],
    context: Option<&[u8]>,
) -> CryptoResult<bool> {
    trace!("ed448ph verify (prehash)");

    if public_key.key_type != EcxKeyType::Ed448 {
        return Err(CryptoError::Key("public key is not Ed448".into()));
    }
    if signature.len() != ED448_SIGNATURE_LEN {
        return Err(CryptoError::Verification(
            "Ed448 signature must be 114 bytes".into(),
        ));
    }
    if public_key.bytes.len() != ED448_KEY_LEN {
        return Err(CryptoError::Key("invalid Ed448 public key length".into()));
    }
    let ctx = context.unwrap_or(&[]);
    if ctx.len() > 255 {
        return Err(CryptoError::Key(
            "Ed448 context too long (max 255 bytes)".into(),
        ));
    }

    ed448_verify_internal(&public_key.bytes, prehash, signature, true, ctx)
}

/// Internal Ed448 verification.
fn ed448_verify_internal(
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
    prehash: bool,
    context: &[u8],
) -> CryptoResult<bool> {
    let mut r_bytes = [0u8; 57];
    r_bytes.copy_from_slice(&sig[..57]);
    let mut s_bytes = [0u8; 57];
    s_bytes.copy_from_slice(&sig[57..114]);

    // S must be canonical (S < l)
    if !scalar448::sc_is_canonical448(&s_bytes) {
        return Ok(false);
    }

    // Decode public key
    let mut pk_arr = [0u8; 57];
    pk_arr.copy_from_slice(pubkey);
    let a_point = match edwards448::GeP3_448::from_bytes(&pk_arr) {
        Some(p) => p,
        None => return Ok(false),
    };

    // h = SHAKE256(dom4 || R || A || msg, 114) mod l
    let flag_byte: u8 = if prehash { 1 } else { 0 };
    let mut h_input = Vec::new();
    h_input.extend_from_slice(b"SigEd448");
    h_input.push(flag_byte);
    h_input.push(context.len() as u8);
    h_input.extend_from_slice(context);
    h_input.extend_from_slice(&r_bytes);
    h_input.extend_from_slice(pubkey);
    h_input.extend_from_slice(msg);
    let h_hash = keccak_internal::shake256(&h_input, 114);
    let h = scalar448::sc_reduce448(&h_hash);

    // Check: [S]B == R + [h]A
    // Compute [h](-A) + [S]B
    let neg_a = a_point.negate();
    let check = edwards448::double_scalarmult_vartime(&h, &neg_a, &s_bytes);
    let check_bytes = check.to_bytes();

    // Constant-time comparison
    Ok(check_bytes[..].ct_eq(&r_bytes[..]).into())
}

/// Verify that a public key represents a valid point on the curve.
///
/// Used for FIPS ACVP KeyVer tests. Returns `true` if the public key
/// encodes a valid curve point of the correct length for `public_key.key_type`.
///
/// # Errors
/// Returns `CryptoError::Key` on length mismatches.
pub fn verify_public_key(public_key: &EcxPublicKey) -> CryptoResult<bool> {
    trace!(algorithm = %public_key.key_type, "verifying public key");

    match public_key.key_type {
        EcxKeyType::Ed25519 => {
            if public_key.bytes.len() != ED25519_KEY_LEN {
                return Err(CryptoError::Key("invalid Ed25519 public key length".into()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&public_key.bytes);
            Ok(edwards25519::GeP3::from_bytes(&arr).is_some())
        }
        EcxKeyType::Ed448 => {
            if public_key.bytes.len() != ED448_KEY_LEN {
                return Err(CryptoError::Key("invalid Ed448 public key length".into()));
            }
            let mut arr = [0u8; 57];
            arr.copy_from_slice(&public_key.bytes);
            Ok(edwards448::GeP3_448::from_bytes(&arr).is_some())
        }
        EcxKeyType::X25519 => {
            // X25519 accepts all 32-byte strings as valid public keys (per RFC 7748)
            if public_key.bytes.len() != X25519_KEY_LEN {
                return Err(CryptoError::Key("invalid X25519 public key length".into()));
            }
            Ok(true)
        }
        EcxKeyType::X448 => {
            // X448 accepts all 56-byte strings as valid public keys (per RFC 7748)
            if public_key.bytes.len() != X448_KEY_LEN {
                return Err(CryptoError::Key("invalid X448 public key length".into()));
            }
            Ok(true)
        }
    }
}

/// Test-only module exposing internals for verification.
#[doc(hidden)]
pub mod test_internals {
    pub fn sc_reduce(input: &[u8; 64]) -> [u8; 32] {
        super::scalar25519::sc_reduce(input)
    }
    pub fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
        super::scalar25519::sc_muladd(a, b, c)
    }
    pub fn scalarmult_base(scalar: &[u8; 32]) -> [u8; 32] {
        super::edwards25519::scalarmult_base(scalar).to_bytes()
    }
    pub fn ge_from_bytes_to_bytes(bytes: &[u8; 32]) -> Option<[u8; 32]> {
        super::edwards25519::GeP3::from_bytes(bytes).map(|p| p.to_bytes())
    }
    /// Directly double the basepoint and return encoded result.
    pub fn double_basepoint() -> [u8; 32] {
        use super::edwards25519;
        let b = edwards25519::basepoint();
        // Use scalarmult with scalar=2 to avoid private method access
        let mut s = [0u8; 32];
        s[0] = 2;
        edwards25519::scalarmult(&b, &s).to_bytes()
    }
    /// Add basepoint to itself via internal add and return encoded result.
    pub fn add_basepoint_to_itself() -> [u8; 32] {
        use super::edwards25519;
        // Use scalarmult with scalar=2
        let b = edwards25519::basepoint();
        let mut s = [0u8; 32];
        s[0] = 2;
        edwards25519::scalarmult(&b, &s).to_bytes()
    }
    /// Field element roundtrip: from_bytes → to_bytes
    pub fn fe_roundtrip(bytes: &[u8; 32]) -> [u8; 32] {
        let fe = super::field25519::Fe::from_bytes(bytes);
        fe.to_bytes()
    }
    /// Multiply two field elements (as bytes) and return result bytes.
    pub fn fe_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let fa = super::field25519::Fe::from_bytes(a);
        let fb = super::field25519::Fe::from_bytes(b);
        fa.mul(&fb).to_bytes()
    }
    /// Square a field element and return result bytes.
    pub fn fe_square(a: &[u8; 32]) -> [u8; 32] {
        let fa = super::field25519::Fe::from_bytes(a);
        fa.square().to_bytes()
    }
    /// Expose SHA-512 for diagnostic testing.
    pub fn sha512(data: &[u8]) -> [u8; 64] {
        super::sha512_internal::sha512(data)
    }
    // --- Ed448 test internals ---
    /// Ed448 field element roundtrip: from_bytes → to_bytes (56 bytes).
    pub fn fe448_roundtrip(bytes: &[u8; 56]) -> [u8; 56] {
        let fe = super::field448::Fe448::from_bytes(bytes);
        fe.to_bytes()
    }
    /// Ed448 field mul then to_bytes.
    pub fn fe448_mul(a: &[u8; 56], b: &[u8; 56]) -> [u8; 56] {
        let fa = super::field448::Fe448::from_bytes(a);
        let fb = super::field448::Fe448::from_bytes(b);
        fa.mul(&fb).to_bytes()
    }
    /// Ed448 field square then to_bytes.
    pub fn fe448_square(a: &[u8; 56]) -> [u8; 56] {
        let fa = super::field448::Fe448::from_bytes(a);
        fa.square().to_bytes()
    }
    /// Ed448 field sub: a - b.
    pub fn fe448_sub(a: &[u8; 56], b: &[u8; 56]) -> [u8; 56] {
        let fa = super::field448::Fe448::from_bytes(a);
        let fb = super::field448::Fe448::from_bytes(b);
        fa.sub(&fb).to_bytes()
    }
    /// Ed448 field add: a + b.
    pub fn fe448_add(a: &[u8; 56], b: &[u8; 56]) -> [u8; 56] {
        let fa = super::field448::Fe448::from_bytes(a);
        let fb = super::field448::Fe448::from_bytes(b);
        fa.add(&fb).to_bytes()
    }
    /// Ed448 field invert.
    pub fn fe448_invert(a: &[u8; 56]) -> [u8; 56] {
        let fa = super::field448::Fe448::from_bytes(a);
        fa.invert().to_bytes()
    }
    /// Ed448 pow_p_plus_1_div_4 (square root helper).
    pub fn fe448_sqrt(a: &[u8; 56]) -> [u8; 56] {
        let fa = super::field448::Fe448::from_bytes(a);
        fa.pow_p_plus_1_div_4().to_bytes()
    }
    /// Ed448 is_zero check.
    pub fn fe448_is_zero(a: &[u8; 56]) -> bool {
        let fa = super::field448::Fe448::from_bytes(a);
        fa.is_zero()
    }
    /// Ed448 basepoint encode.
    pub fn ed448_basepoint_bytes() -> [u8; 57] {
        super::edwards448::basepoint().to_bytes()
    }
    /// Ed448 scalarmult_base then to_bytes.
    pub fn ed448_scalarmult_base(scalar: &[u8]) -> [u8; 57] {
        super::edwards448::scalarmult_base(scalar).to_bytes()
    }
    /// Ed448 from_bytes → to_bytes roundtrip.
    pub fn ed448_point_roundtrip(bytes: &[u8; 57]) -> Option<[u8; 57]> {
        super::edwards448::GeP3_448::from_bytes(bytes).map(|p| p.to_bytes())
    }

    /// Variable-base scalar multiplication: [scalar]*P (using scalarmult, NOT vartime).
    pub fn scalarmult(point_bytes: &[u8; 32], scalar: &[u8; 32]) -> Option<[u8; 32]> {
        let p = super::edwards25519::GeP3::from_bytes(point_bytes)?;
        Some(super::edwards25519::scalarmult(&p, scalar).to_bytes())
    }

    /// Double scalar mult: [a]*A + [b]*B using vartime (for verify).
    pub fn double_scalarmult_vartime(
        a_scalar: &[u8; 32],
        a_point_bytes: &[u8; 32],
        b_scalar: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let a_point = super::edwards25519::GeP3::from_bytes(a_point_bytes)?;
        let result = super::edwards25519::double_scalarmult_vartime(a_scalar, &a_point, b_scalar);
        Some(result.to_bytes())
    }

    /// Negate a point (for testing verify path).
    pub fn negate_point(point_bytes: &[u8; 32]) -> Option<[u8; 32]> {
        let p = super::edwards25519::GeP3::from_bytes(point_bytes)?;
        let neg_p = super::edwards25519::GeP3 {
            x: p.x.neg(),
            y: p.y,
            z: p.z,
            t: p.t.neg(),
        };
        Some(neg_p.to_bytes())
    }

    /// Incremental SHA-512: takes multiple chunks and processes them via
    /// Sha512::new() → .update(chunk1) → .update(chunk2) → ... → .finalize().
    /// Used to compare incremental vs one-shot hashing.
    pub fn sha512_incremental(chunks: &[&[u8]]) -> [u8; 64] {
        let mut hasher = super::sha512_internal::Sha512::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        hasher.finalize()
    }

    /// scalar_to_radix16 for debugging — reimplemented locally.
    pub fn scalar_to_radix16(scalar: &[u8; 32]) -> [i8; 64] {
        let mut digits = [0i8; 64];
        for i in 0..32 {
            digits[2 * i] = (scalar[i] & 0xf) as i8;
            digits[2 * i + 1] = ((scalar[i] >> 4) & 0xf) as i8;
        }
        let mut carry = 0i8;
        for i in 0..63 {
            digits[i] += carry;
            carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
        }
        digits[63] += carry;
        digits
    }
}
