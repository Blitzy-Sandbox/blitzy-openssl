//! AES (Advanced Encryption Standard) block cipher with all modes.
//!
//! Provides AES-128/192/256 with ECB, CBC, CTR, GCM, CCM, OCB, SIV, XTS,
//! CFB, OFB, and Key Wrap (RFC 3394/5649) modes.
//!
//! ## Source Mapping
//!
//! | Rust Type/Fn            | C Source                           | Notes                                             |
//! |-------------------------|------------------------------------|---------------------------------------------------|
//! | [`Aes`]                 | `crypto/aes/aes_core.c`            | Core block primitive + key schedule (~3,624 LoC)  |
//! | [`AesKey`]              | `crypto/aes/aes_core.c`            | `AES_set_encrypt_key` / `AES_set_decrypt_key`     |
//! | [`AesGcm`]              | `crypto/modes/gcm128.c`            | CTR encryption + GHASH authentication             |
//! | [`GHashTable`]          | `crypto/modes/gcm128.c`            | `gcm_init_4bit` / `gcm_gmult_4bit`                |
//! | [`AesCcm`]              | `crypto/modes/ccm128.c`            | CBC-MAC + CTR                                     |
//! | [`AesXts`]              | `crypto/modes/xts128.c`            | Tweakable encryption with ciphertext stealing     |
//! | [`AesOcb`]              | `crypto/modes/ocb128.c`            | Single-pass AEAD with offset codebook             |
//! | [`AesSiv`]              | `crypto/modes/siv128.c`            | Deterministic AEAD (RFC 5297)                     |
//! | [`aes_key_wrap`]        | `crypto/modes/wrap128.c`           | RFC 3394 key wrap                                 |
//! | [`aes_key_wrap_pad`]    | `crypto/modes/wrap128.c`           | RFC 5649 key wrap with padding                    |
//! | [`aes_cbc_encrypt`]     | `crypto/aes/aes_cbc.c`             | Thin wrapper composing CBC engine                 |
//! | [`aes_ctr_encrypt`]     | `crypto/modes/ctr128.c`            | Thin wrapper composing CTR engine                 |
//! | [`aes_cfb_encrypt`]     | `crypto/aes/aes_cfb.c`             | Thin wrapper composing CFB engine                 |
//! | [`aes_ofb_encrypt`]     | `crypto/aes/aes_ofb.c`             | Thin wrapper composing OFB engine                 |
//!
//! ## Design Notes
//!
//! - AES block primitive uses table-driven T-box implementation (Te0–Te3 /
//!   Td0–Td3). Sibling tables are derived from Te0/Td0 by byte rotation at
//!   runtime to reduce binary size while preserving constant-time access.
//! - AEAD modes (GCM, CCM, OCB, SIV) provide authentication + encryption.
//! - GCM uses a 4-bit precomputed `GHashTable` for portable, table-free
//!   polynomial multiplication in GF(2^128).
//! - All key material and intermediate working buffers are zeroed on drop
//!   via [`zeroize::ZeroizeOnDrop`] (replaces C `OPENSSL_cleanse()`).
//! - All AEAD tag comparisons use [`subtle::ConstantTimeEq`] to defeat
//!   timing side-channel attacks (replaces hand-rolled constant-time
//!   comparisons from C `constant_time.h`).
//! - All operations return [`CryptoResult<Vec<u8>>`] per Rule R5 — no
//!   sentinel return values.
//! - Zero `unsafe` blocks (Rule R8).
//!
//! ## Rules Enforced
//!
//! | Rule | Enforcement                                                           |
//! |------|------------------------------------------------------------------------|
//! | R5   | `Option<T>` / `CryptoResult<T>` throughout — no sentinel values.       |
//! | R6   | `u32::from_be_bytes()` / `to_be_bytes()`; `& 0xFF` for index masking.  |
//! | R8   | Zero `unsafe` blocks.                                                  |
//! | R9   | All public items documented.                                           |

use crate::symmetric::{
    cbc_encrypt, cfb_encrypt, ctr_encrypt, ofb_encrypt, AeadCipher, BlockSize, CipherAlgorithm,
    CipherDirection, SymmetricCipher,
};
use openssl_common::{CommonError, CryptoError, CryptoResult};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants — AES Round Count, Block Size, Default IVs
// =============================================================================

/// AES block size in bytes (128 bits).
const AES_BLOCK_SIZE: usize = 16;

/// Default Integrity Check Value for AES Key Wrap (RFC 3394 §2.2.3.1).
///
/// Initial Value A[0] for unpadded key wrapping. Correctly unwrapped keys
/// produce this value as the plaintext prefix; constant-time comparison
/// against this array detects integrity failures.
pub const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Default Alternative Initial Value for AES Key Wrap with Padding
/// (RFC 5649 §3). Prefix for the 8-byte AIV; the trailing 4 bytes are the
/// big-endian input length.
pub const DEFAULT_AIV: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// AES round-constant array for key expansion.
///
/// Values are `0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36`
/// in the high byte — each `XORed` into the high byte of `temp` during key
/// expansion. Translates the `rcon[]` table from `crypto/aes/aes_core.c`.
const RCON: [u32; 10] = [
    0x0100_0000, 0x0200_0000, 0x0400_0000, 0x0800_0000, 0x1000_0000, 0x2000_0000, 0x4000_0000,
    0x8000_0000, 0x1B00_0000, 0x3600_0000,
];

// =============================================================================
// AES Forward S-box (Te4 from crypto/aes/aes_core.c line 3435)
// =============================================================================

/// AES forward S-box — 256-byte substitution table.
///
/// Used for the final round of encryption and for key schedule byte
/// substitution. Translates `Te4[]` from `crypto/aes/aes_core.c`.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// =============================================================================
// AES Inverse S-box (Td4 from crypto/aes/aes_core.c)
// =============================================================================

/// AES inverse S-box — 256-byte inverse substitution table.
///
/// Used for the final round of decryption. Translates `Td4[]` from
/// `crypto/aes/aes_core.c`.
#[rustfmt::skip]
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// =============================================================================
// AES Key Size Enumeration
// =============================================================================

/// Supported AES key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesKeySize {
    /// 128-bit key (16 bytes, 10 rounds).
    Aes128,
    /// 192-bit key (24 bytes, 12 rounds).
    Aes192,
    /// 256-bit key (32 bytes, 14 rounds).
    Aes256,
}

impl AesKeySize {
    /// Returns the key length in bytes.
    #[must_use]
    pub fn bytes(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// Returns the number of cipher rounds.
    #[must_use]
    pub fn rounds(self) -> usize {
        match self {
            Self::Aes128 => 10,
            Self::Aes192 => 12,
            Self::Aes256 => 14,
        }
    }

    /// Decodes a key length into the corresponding [`AesKeySize`] variant.
    fn from_bytes(len: usize) -> CryptoResult<Self> {
        match len {
            16 => Ok(Self::Aes128),
            24 => Ok(Self::Aes192),
            32 => Ok(Self::Aes256),
            other => Err(CryptoError::Key(format!(
                "invalid AES key length: {other} (expected 16, 24, or 32)"
            ))),
        }
    }
}

// =============================================================================
// GF(2^8) Arithmetic Helpers (for compile-time T-table construction)
// =============================================================================

/// Multiplies `b` by `x` in GF(2^8) modulo AES polynomial `0x11B`.
///
/// This is the classical `xtime()` operation: shift left by 1, XOR with
/// `0x1B` if the high bit was set.
const fn xtime(b: u8) -> u8 {
    // Narrowing from bool*u8 is a 0/1 multiplication — no data-dependent branch.
    (b << 1) ^ (((b >> 7) & 1) * 0x1B)
}

/// Multiplies `a * b` in GF(2^8) modulo AES polynomial `0x11B`.
///
/// Used to derive the forward/inverse T-tables from the S-boxes at compile
/// time.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut i = 0;
    while i < 8 {
        if (b & 1) != 0 {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
        i += 1;
    }
    result
}

// =============================================================================
// AES Forward T-Table Te0 (from crypto/aes/aes_core.c line 706)
// =============================================================================
//
// Te0[x] = [S(x)·02, S(x)·01, S(x)·01, S(x)·03] stored big-endian as u32.
//
// Te1/Te2/Te3 are byte-rotations of Te0:
//     Te1[x] = Te0[x].rotate_right(8)
//     Te2[x] = Te0[x].rotate_right(16)
//     Te3[x] = Te0[x].rotate_right(24)
//
// Storing only Te0 and deriving rotations inline saves 3 KiB of rodata
// while preserving the same constant-time access pattern (every lookup
// remains a single indexed array read).

/// Computes the forward T-table at compile time from [`SBOX`].
const fn compute_te0() -> [u32; 256] {
    let mut te = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        let s2 = gf_mul(s, 2);
        let s3 = gf_mul(s, 3);
        // Big-endian packing: [s·02, s, s, s·03]
        te[i] = ((s2 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (s3 as u32);
        i += 1;
    }
    te
}

/// AES forward T-table (Te0).
const TE0: [u32; 256] = compute_te0();

// =============================================================================
// AES Inverse T-Table Td0 (from crypto/aes/aes_core.c)
// =============================================================================

/// Computes the inverse T-table at compile time from [`INV_SBOX`].
const fn compute_td0() -> [u32; 256] {
    let mut td = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = INV_SBOX[i];
        let s9 = gf_mul(s, 0x09);
        let sb = gf_mul(s, 0x0B);
        let sd = gf_mul(s, 0x0D);
        let se = gf_mul(s, 0x0E);
        // Big-endian packing: [s·0e, s·09, s·0d, s·0b]
        td[i] = ((se as u32) << 24) | ((s9 as u32) << 16) | ((sd as u32) << 8) | (sb as u32);
        i += 1;
    }
    td
}

/// AES inverse T-table (Td0).
const TD0: [u32; 256] = compute_td0();

// =============================================================================
// Te0/Td0 Rotation Helpers
// =============================================================================

#[inline]
fn te1(x: usize) -> u32 {
    TE0[x].rotate_right(8)
}

#[inline]
fn te2(x: usize) -> u32 {
    TE0[x].rotate_right(16)
}

#[inline]
fn te3(x: usize) -> u32 {
    TE0[x].rotate_right(24)
}

#[inline]
fn td1(x: usize) -> u32 {
    TD0[x].rotate_right(8)
}

#[inline]
fn td2(x: usize) -> u32 {
    TD0[x].rotate_right(16)
}

#[inline]
fn td3(x: usize) -> u32 {
    TD0[x].rotate_right(24)
}

// =============================================================================
// Endian Helpers (GETU32 / PUTU32 from crypto/aes/aes_local.h)
// =============================================================================

/// Reads a big-endian u32 from `bytes[offset..offset + 4]`.
#[inline]
fn getu32(bytes: &[u8], offset: usize) -> u32 {
    let arr: [u8; 4] = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    u32::from_be_bytes(arr)
}

/// Writes `value` as a big-endian u32 into `bytes[offset..offset + 4]`.
#[inline]
fn putu32(bytes: &mut [u8], offset: usize, value: u32) {
    let be = value.to_be_bytes();
    bytes[offset] = be[0];
    bytes[offset + 1] = be[1];
    bytes[offset + 2] = be[2];
    bytes[offset + 3] = be[3];
}

/// Masks a u32 down to the low 8 bits, returning a `usize` safe for indexing.
#[inline]
fn lo8(x: u32) -> usize {
    (x & 0xFF) as usize
}

/// Extracts a single byte from a u32 by right-shifting and masking.
#[inline]
fn byte(x: u32, shift: u32) -> usize {
    ((x >> shift) & 0xFF) as usize
}


// =============================================================================
// AesKey — Expanded AES Key Schedule
// =============================================================================

/// AES expanded key schedule.
///
/// Contains `(Nr + 1) * 4` round key words where `Nr = 10/12/14` for
/// AES-128/192/256 respectively, laid out contiguously as 32-bit words.
///
/// Separate encrypt and decrypt schedules are required: the decrypt
/// schedule is the encrypt schedule in reversed order with
/// `InvMixColumns` applied to intermediate round keys (see
/// [`AesKey::expand_decrypt_key`]).
///
/// Translates the `AES_KEY` struct and
/// `AES_set_{encrypt,decrypt}_key` functions from `crypto/aes/aes_core.c`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AesKey {
    /// Contiguous round-key words: `(rounds + 1) * 4` entries.
    round_keys: Vec<u32>,
    /// Number of rounds: 10, 12, or 14.
    rounds: usize,
}

impl core::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never leak key material into log output.
        f.debug_struct("AesKey")
            .field("rounds", &self.rounds)
            .field("round_keys", &"<redacted>")
            .finish()
    }
}

impl AesKey {
    /// Expands a user-supplied key into an encryption key schedule.
    ///
    /// Translates `AES_set_encrypt_key` from `crypto/aes/aes_core.c`. Key
    /// must be 16, 24, or 32 bytes long (AES-128/192/256).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is invalid.
    pub fn expand_encrypt_key(user_key: &[u8]) -> CryptoResult<Self> {
        let size = AesKeySize::from_bytes(user_key.len())?;
        let rounds = size.rounds();
        let total_words = (rounds + 1) * 4;

        let mut rk: Vec<u32> = vec![0u32; total_words];

        match size {
            AesKeySize::Aes128 => {
                rk[0] = getu32(user_key, 0);
                rk[1] = getu32(user_key, 4);
                rk[2] = getu32(user_key, 8);
                rk[3] = getu32(user_key, 12);
                for (i, &rcon_val) in RCON.iter().enumerate() {
                    let base = i * 4;
                    let temp = rk[base + 3];
                    let rot = temp.rotate_left(8);
                    let rot_sub = (u32::from(SBOX[byte(rot, 24)]) << 24)
                        | (u32::from(SBOX[byte(rot, 16)]) << 16)
                        | (u32::from(SBOX[byte(rot, 8)]) << 8)
                        | u32::from(SBOX[byte(rot, 0)]);
                    rk[base + 4] = rk[base] ^ rot_sub ^ rcon_val;
                    rk[base + 5] = rk[base + 1] ^ rk[base + 4];
                    rk[base + 6] = rk[base + 2] ^ rk[base + 5];
                    rk[base + 7] = rk[base + 3] ^ rk[base + 6];
                }
            }
            AesKeySize::Aes192 => {
                rk[0] = getu32(user_key, 0);
                rk[1] = getu32(user_key, 4);
                rk[2] = getu32(user_key, 8);
                rk[3] = getu32(user_key, 12);
                rk[4] = getu32(user_key, 16);
                rk[5] = getu32(user_key, 20);
                // AES-192: 8 iterations; last iteration only writes 4 new words.
                let mut base: usize = 0;
                for (i, &rcon_val) in RCON.iter().take(8).enumerate() {
                    let temp = rk[base + 5];
                    let rot = temp.rotate_left(8);
                    let rot_sub = (u32::from(SBOX[byte(rot, 24)]) << 24)
                        | (u32::from(SBOX[byte(rot, 16)]) << 16)
                        | (u32::from(SBOX[byte(rot, 8)]) << 8)
                        | u32::from(SBOX[byte(rot, 0)]);
                    rk[base + 6] = rk[base] ^ rot_sub ^ rcon_val;
                    rk[base + 7] = rk[base + 1] ^ rk[base + 6];
                    rk[base + 8] = rk[base + 2] ^ rk[base + 7];
                    rk[base + 9] = rk[base + 3] ^ rk[base + 8];
                    if i == 7 {
                        break;
                    }
                    rk[base + 10] = rk[base + 4] ^ rk[base + 9];
                    rk[base + 11] = rk[base + 5] ^ rk[base + 10];
                    base += 6;
                }
            }
            AesKeySize::Aes256 => {
                for (w, rk_slot) in rk.iter_mut().take(8).enumerate() {
                    *rk_slot = getu32(user_key, w * 4);
                }
                // AES-256: 7 iterations; iteration 6 only writes 4 new words.
                let mut base: usize = 0;
                for (i, &rcon_val) in RCON.iter().take(7).enumerate() {
                    let temp = rk[base + 7];
                    let rot = temp.rotate_left(8);
                    let rot_sub = (u32::from(SBOX[byte(rot, 24)]) << 24)
                        | (u32::from(SBOX[byte(rot, 16)]) << 16)
                        | (u32::from(SBOX[byte(rot, 8)]) << 8)
                        | u32::from(SBOX[byte(rot, 0)]);
                    rk[base + 8] = rk[base] ^ rot_sub ^ rcon_val;
                    rk[base + 9] = rk[base + 1] ^ rk[base + 8];
                    rk[base + 10] = rk[base + 2] ^ rk[base + 9];
                    rk[base + 11] = rk[base + 3] ^ rk[base + 10];
                    if i == 6 {
                        break;
                    }
                    // Extra SubWord (no RotWord) at 4th position for AES-256.
                    let temp2 = rk[base + 11];
                    let sub = (u32::from(SBOX[byte(temp2, 24)]) << 24)
                        | (u32::from(SBOX[byte(temp2, 16)]) << 16)
                        | (u32::from(SBOX[byte(temp2, 8)]) << 8)
                        | u32::from(SBOX[byte(temp2, 0)]);
                    rk[base + 12] = rk[base + 4] ^ sub;
                    rk[base + 13] = rk[base + 5] ^ rk[base + 12];
                    rk[base + 14] = rk[base + 6] ^ rk[base + 13];
                    rk[base + 15] = rk[base + 7] ^ rk[base + 14];
                    base += 8;
                }
            }
        }

        Ok(Self {
            round_keys: rk,
            rounds,
        })
    }

    /// Expands a user-supplied key into a decryption key schedule.
    ///
    /// Translates `AES_set_decrypt_key` from `crypto/aes/aes_core.c`.
    /// Internally: generates the encrypt schedule first, reverses the
    /// round-key order in 4-word blocks, then applies `InvMixColumns` to
    /// every intermediate round key (skipping the first and last).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is invalid.
    pub fn expand_decrypt_key(user_key: &[u8]) -> CryptoResult<Self> {
        let mut key = Self::expand_encrypt_key(user_key)?;
        let rounds = key.rounds;

        // Step 1: reverse round keys in 4-word blocks.
        // rk[0..4] <-> rk[4*rounds..4*rounds + 4]
        // rk[4..8] <-> rk[4*(rounds-1)..4*(rounds-1) + 4]
        // etc.
        let mut i: usize = 0;
        let mut j: usize = 4 * rounds;
        while i < j {
            key.round_keys.swap(i, j);
            key.round_keys.swap(i + 1, j + 1);
            key.round_keys.swap(i + 2, j + 2);
            key.round_keys.swap(i + 3, j + 3);
            i += 4;
            j -= 4;
        }

        // Step 2: apply InvMixColumns to intermediate round keys.
        //
        // For each 4-word block at indices 4..4*rounds:
        //     rk[k] = Td0[S[b3]] ^ td1(S[b2]) ^ td2(S[b1]) ^ td3(S[b0])
        // where b3, b2, b1, b0 are the 4 bytes of the original rk[k]
        // (MSB to LSB). The inner SBOX cancels the InvSBOX inside Td,
        // leaving pure InvMixColumns.
        for r in 1..rounds {
            let base = r * 4;
            for k in 0..4 {
                let old = key.round_keys[base + k];
                let new_key = TD0[SBOX[byte(old, 24)] as usize]
                    ^ td1(SBOX[byte(old, 16)] as usize)
                    ^ td2(SBOX[byte(old, 8)] as usize)
                    ^ td3(SBOX[byte(old, 0)] as usize);
                key.round_keys[base + k] = new_key;
            }
        }

        Ok(key)
    }

    /// Returns the number of cipher rounds.
    #[must_use]
    pub fn rounds(&self) -> usize {
        self.rounds
    }
}

// =============================================================================
// Core AES Block Primitive
// =============================================================================

/// Encrypts a single 16-byte block in place using the given encrypt schedule.
///
/// Translates `AES_encrypt` from `crypto/aes/aes_core.c` (non-unrolled
/// reference path). Uses the `ShiftRows` index pattern `(s0, s1, s2, s3)`.
fn aes_encrypt_block_inner(block: &mut [u8; 16], key: &AesKey) {
    let rk = &key.round_keys;
    let nr = key.rounds;

    // Load input and XOR with round 0 subkey.
    let mut s0 = getu32(block, 0) ^ rk[0];
    let mut s1 = getu32(block, 4) ^ rk[1];
    let mut s2 = getu32(block, 8) ^ rk[2];
    let mut s3 = getu32(block, 12) ^ rk[3];

    // Rounds 1..Nr-1: combined SubBytes + ShiftRows + MixColumns via T-tables.
    let mut rk_off: usize = 4;
    for _ in 0..(nr - 1) {
        let t0 = TE0[byte(s0, 24)]
            ^ te1(byte(s1, 16))
            ^ te2(byte(s2, 8))
            ^ te3(lo8(s3))
            ^ rk[rk_off];
        let t1 = TE0[byte(s1, 24)]
            ^ te1(byte(s2, 16))
            ^ te2(byte(s3, 8))
            ^ te3(lo8(s0))
            ^ rk[rk_off + 1];
        let t2 = TE0[byte(s2, 24)]
            ^ te1(byte(s3, 16))
            ^ te2(byte(s0, 8))
            ^ te3(lo8(s1))
            ^ rk[rk_off + 2];
        let t3 = TE0[byte(s3, 24)]
            ^ te1(byte(s0, 16))
            ^ te2(byte(s1, 8))
            ^ te3(lo8(s2))
            ^ rk[rk_off + 3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
        rk_off += 4;
    }

    // Final round: SubBytes + ShiftRows only (no MixColumns).
    let f0 = (u32::from(SBOX[byte(s0, 24)]) << 24)
        | (u32::from(SBOX[byte(s1, 16)]) << 16)
        | (u32::from(SBOX[byte(s2, 8)]) << 8)
        | u32::from(SBOX[lo8(s3)]);
    let f1 = (u32::from(SBOX[byte(s1, 24)]) << 24)
        | (u32::from(SBOX[byte(s2, 16)]) << 16)
        | (u32::from(SBOX[byte(s3, 8)]) << 8)
        | u32::from(SBOX[lo8(s0)]);
    let f2 = (u32::from(SBOX[byte(s2, 24)]) << 24)
        | (u32::from(SBOX[byte(s3, 16)]) << 16)
        | (u32::from(SBOX[byte(s0, 8)]) << 8)
        | u32::from(SBOX[lo8(s1)]);
    let f3 = (u32::from(SBOX[byte(s3, 24)]) << 24)
        | (u32::from(SBOX[byte(s0, 16)]) << 16)
        | (u32::from(SBOX[byte(s1, 8)]) << 8)
        | u32::from(SBOX[lo8(s2)]);

    let out0 = f0 ^ rk[rk_off];
    let out1 = f1 ^ rk[rk_off + 1];
    let out2 = f2 ^ rk[rk_off + 2];
    let out3 = f3 ^ rk[rk_off + 3];

    putu32(block, 0, out0);
    putu32(block, 4, out1);
    putu32(block, 8, out2);
    putu32(block, 12, out3);
}

/// Decrypts a single 16-byte block in place using the given decrypt schedule.
///
/// Translates `AES_decrypt` from `crypto/aes/aes_core.c` (non-unrolled
/// reference path). Uses the `InvShiftRows` index pattern `(s0, s3, s2, s1)`.
fn aes_decrypt_block_inner(block: &mut [u8; 16], key: &AesKey) {
    let rk = &key.round_keys;
    let nr = key.rounds;

    // Load input and XOR with round 0 subkey of decrypt schedule.
    let mut s0 = getu32(block, 0) ^ rk[0];
    let mut s1 = getu32(block, 4) ^ rk[1];
    let mut s2 = getu32(block, 8) ^ rk[2];
    let mut s3 = getu32(block, 12) ^ rk[3];

    // Rounds 1..Nr-1: combined InvSubBytes + InvShiftRows + InvMixColumns.
    let mut rk_off: usize = 4;
    for _ in 0..(nr - 1) {
        let t0 = TD0[byte(s0, 24)]
            ^ td1(byte(s3, 16))
            ^ td2(byte(s2, 8))
            ^ td3(lo8(s1))
            ^ rk[rk_off];
        let t1 = TD0[byte(s1, 24)]
            ^ td1(byte(s0, 16))
            ^ td2(byte(s3, 8))
            ^ td3(lo8(s2))
            ^ rk[rk_off + 1];
        let t2 = TD0[byte(s2, 24)]
            ^ td1(byte(s1, 16))
            ^ td2(byte(s0, 8))
            ^ td3(lo8(s3))
            ^ rk[rk_off + 2];
        let t3 = TD0[byte(s3, 24)]
            ^ td1(byte(s2, 16))
            ^ td2(byte(s1, 8))
            ^ td3(lo8(s0))
            ^ rk[rk_off + 3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
        rk_off += 4;
    }

    // Final round: InvSubBytes + InvShiftRows only (no InvMixColumns).
    let f0 = (u32::from(INV_SBOX[byte(s0, 24)]) << 24)
        | (u32::from(INV_SBOX[byte(s3, 16)]) << 16)
        | (u32::from(INV_SBOX[byte(s2, 8)]) << 8)
        | u32::from(INV_SBOX[lo8(s1)]);
    let f1 = (u32::from(INV_SBOX[byte(s1, 24)]) << 24)
        | (u32::from(INV_SBOX[byte(s0, 16)]) << 16)
        | (u32::from(INV_SBOX[byte(s3, 8)]) << 8)
        | u32::from(INV_SBOX[lo8(s2)]);
    let f2 = (u32::from(INV_SBOX[byte(s2, 24)]) << 24)
        | (u32::from(INV_SBOX[byte(s1, 16)]) << 16)
        | (u32::from(INV_SBOX[byte(s0, 8)]) << 8)
        | u32::from(INV_SBOX[lo8(s3)]);
    let f3 = (u32::from(INV_SBOX[byte(s3, 24)]) << 24)
        | (u32::from(INV_SBOX[byte(s2, 16)]) << 16)
        | (u32::from(INV_SBOX[byte(s1, 8)]) << 8)
        | u32::from(INV_SBOX[lo8(s0)]);

    let out0 = f0 ^ rk[rk_off];
    let out1 = f1 ^ rk[rk_off + 1];
    let out2 = f2 ^ rk[rk_off + 2];
    let out3 = f3 ^ rk[rk_off + 3];

    putu32(block, 0, out0);
    putu32(block, 4, out1);
    putu32(block, 8, out2);
    putu32(block, 12, out3);
}


// =============================================================================
// Aes — High-Level Block Cipher Handle
// =============================================================================

/// AES block cipher (128-bit block, 128/192/256-bit key).
///
/// Pre-computes both encrypt and decrypt key schedules at construction so a
/// single `Aes` instance can service both directions without re-expanding
/// the user key. This mirrors the C `AES_KEY` usage pattern where the same
/// object is passed to `AES_encrypt` and `AES_decrypt`.
///
/// ## Lifecycle
///
/// - Construct via [`Aes::new`] which validates the key length and runs the
///   key schedule.
/// - Drop zeros both internal key schedules via [`zeroize::ZeroizeOnDrop`].
///
/// ## Example
///
/// ```ignore
/// use openssl_crypto::symmetric::{Aes, SymmetricCipher};
///
/// let key = [0u8; 16];
/// let aes = Aes::new(&key).expect("valid key");
/// let mut block = [0u8; 16];
/// aes.encrypt_block(&mut block).unwrap();
/// ```
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Aes {
    /// Expanded encryption key schedule.
    encrypt_key: AesKey,
    /// Expanded decryption key schedule (reversed, `InvMixColumns` applied).
    decrypt_key: AesKey,
    /// Original key size (128/192/256), cached for fast algorithm dispatch.
    ///
    /// `AesKeySize` is a plain `Copy` tag enum — it holds no key material,
    /// so we can safely skip zeroization for this field. The sensitive
    /// fields (`encrypt_key`, `decrypt_key`) continue to zeroize on drop.
    #[zeroize(skip)]
    key_size: AesKeySize,
}

impl Aes {
    /// Creates a new AES cipher from a 16-, 24-, or 32-byte user key.
    ///
    /// Expands both the encrypt and decrypt key schedules.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if the key length is not one of
    /// `{16, 24, 32}` bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let key_size = AesKeySize::from_bytes(key.len())?;
        let encrypt_key = AesKey::expand_encrypt_key(key)?;
        let decrypt_key = AesKey::expand_decrypt_key(key)?;
        Ok(Self {
            encrypt_key,
            decrypt_key,
            key_size,
        })
    }

    /// Returns the [`AesKeySize`] this cipher was constructed with.
    #[must_use]
    pub fn key_size(&self) -> AesKeySize {
        self.key_size
    }

    /// Encrypts a fixed 16-byte block in place.
    ///
    /// Convenience wrapper that bypasses the slice-length check used by the
    /// [`SymmetricCipher`] trait implementation.
    #[inline]
    pub(super) fn encrypt_block_array(&self, block: &mut [u8; 16]) {
        aes_encrypt_block_inner(block, &self.encrypt_key);
    }

    /// Decrypts a fixed 16-byte block in place.
    #[inline]
    pub(super) fn decrypt_block_array(&self, block: &mut [u8; 16]) {
        aes_decrypt_block_inner(block, &self.decrypt_key);
    }
}

impl SymmetricCipher for Aes {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block128
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        let block_len = block.len();
        let arr: &mut [u8; AES_BLOCK_SIZE] = block.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES encrypt_block: expected {AES_BLOCK_SIZE}-byte block, got {block_len}"
            )))
        })?;
        aes_encrypt_block_inner(arr, &self.encrypt_key);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        let block_len = block.len();
        let arr: &mut [u8; AES_BLOCK_SIZE] = block.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES decrypt_block: expected {AES_BLOCK_SIZE}-byte block, got {block_len}"
            )))
        })?;
        aes_decrypt_block_inner(arr, &self.decrypt_key);
        Ok(())
    }

    fn algorithm(&self) -> CipherAlgorithm {
        match self.key_size {
            AesKeySize::Aes128 => CipherAlgorithm::Aes128,
            AesKeySize::Aes192 => CipherAlgorithm::Aes192,
            AesKeySize::Aes256 => CipherAlgorithm::Aes256,
        }
    }
}


// =============================================================================
// GHashTable — Precomputed 4-bit GHASH Multiplication Table
// =============================================================================
//
// Translates `gcm_init_4bit`, `gcm_gmult_4bit` and `gcm_ghash_4bit` from
// `crypto/modes/gcm128.c`. GHASH is the universal hash function underlying
// AES-GCM. It operates in GF(2^128) with the polynomial
// `x^128 + x^7 + x^2 + x + 1`.
//
// **Byte / bit convention.** The AES-GCM specification (NIST SP 800-38D §6.3)
// treats a 128-bit block as a polynomial with the leftmost bit being the
// coefficient of `x^0`. Multiplication by `x` corresponds to a shift **right**
// with reduction. When we load a 16-byte block as `u128::from_be_bytes`, the
// leftmost byte (byte 0) maps to the most-significant byte of the `u128` and
// the leftmost bit of the block (the "GHASH bit 0", i.e. coefficient of `x^0`)
// maps to `u128` bit 127 — the MSB. Therefore:
//   * GHASH "shift right by 1" is `u128 >> 1` (MSB-to-LSB direction matches).
//   * The reduction polynomial bit-string `11100001 || 0^120` is the
//     `u128` constant `0xe100_0000_..._0000` (the leading byte 0xE1 sits in
//     the top byte of the `u128`).
//   * "LSB" (the bit that carries out on shift-right) is the lowest-order bit
//     of the `u128`, i.e. `z & 1`.
//
// **Table construction.** The table stores `Htable[i] = i · H` for the
// 16 possible 4-bit values `i = 0..=15`, but `i` is indexed in **bit-reversed
// nibble order** so that the nibble-wise gmult loop can use the index
// directly. The C reference builds the table recursively:
//
//   Htable[ 0]  = 0
//   Htable[ 8]  = H
//   Htable[ 4]  = H >> 1      (reduce_1bit)
//   Htable[ 2]  = H >> 2
//   Htable[ 1]  = H >> 3
//   Htable[ 3]  = Htable[1] ⊕ Htable[2]
//   Htable[ 5]  = Htable[4] ⊕ Htable[1]
//   … (XOR combinations for the remaining entries)
//
// **rem_4bit.** When we shift `Z` right by 4 bits, the four LSBs fall off.
// Those four bits represent a degree-3 polynomial. Multiplying that polynomial
// by `x^124 · 1` (the reduction effect of shifting 4 bits over the top) and
// taking modulo the GHASH polynomial yields a 16-bit residue. The residue is
// placed in the top 16 bits of a `u128` (bits 112..=127), which in GHASH
// order maps to the leftmost two bytes of the block. The 16 precomputed
// residues are `rem_4bit` below.
//
// The algorithm (`gcm_gmult_4bit`) processes `X` nibble-by-nibble from the
// last byte (`X[15]`) to the first (`X[0]`), low-nibble before high-nibble of
// each byte. Each shift-right-4 operation multiplies the accumulated `Z` by
// `x^4`, matching the nibble stride.

/// 4-bit reduction lookup table.
///
/// `REM_4BIT[r]` equals `r · P(x)` in GF(2^128) where `P(x)` is the
/// residue produced by shifting four bits out across the GHASH modulus
/// `x^128 + x^7 + x^2 + x + 1`. The 16-bit polynomial sits in the top 16
/// bits of the `u128` (bits 112..=127), matching the byte-order convention
/// used when loading blocks via `u128::from_be_bytes`.
///
/// These constants are byte-for-byte identical to the `rem_4bit` table in
/// `crypto/modes/gcm128.c` (PACK'd into a `u128` instead of a `size_t`).
const REM_4BIT: [u128; 16] = [
    0x0000_u128 << 112,
    0x1C20_u128 << 112,
    0x3840_u128 << 112,
    0x2460_u128 << 112,
    0x7080_u128 << 112,
    0x6CA0_u128 << 112,
    0x48C0_u128 << 112,
    0x54E0_u128 << 112,
    0xE100_u128 << 112,
    0xFD20_u128 << 112,
    0xD940_u128 << 112,
    0xC560_u128 << 112,
    0x9180_u128 << 112,
    0x8DA0_u128 << 112,
    0xA9C0_u128 << 112,
    0xB5E0_u128 << 112,
];

/// GHASH reduction polynomial (top byte) placed in the MSB of a `u128`.
///
/// Equal to `0xE1 << 120`. See the module comment for the byte-order
/// derivation — this value represents the bit-string `11100001 || 0^120`
/// that is XOR'd in when a `1` bit carries out of the LSB during shift-right.
const GHASH_REDUCTION_MASK: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000_u128;

/// Halve `v` in GF(2^128) — i.e. compute `v · x^(-1)` modulo the GHASH
/// polynomial. Translates the `REDUCE1BIT(V)` macro from `gcm128.c`.
///
/// If the LSB of `v` is set, a `1` coefficient carries out of the polynomial;
/// we XOR in the reduction mask to preserve the modulus.
#[inline]
fn ghash_reduce_1bit(v: u128) -> u128 {
    let carry = (v & 1) != 0;
    let shifted = v >> 1;
    if carry {
        shifted ^ GHASH_REDUCTION_MASK
    } else {
        shifted
    }
}

/// Precomputed GHASH multiplication table keyed on a hash subkey `H`.
///
/// GHASH's subkey `H` is derived as `H = AES_K(0^128)` (see `AesGcm::new`).
/// `GHashTable` stores sixteen precomputed multiples of `H` so that
/// GHASH's repeated `Z = Z · H` computations can be performed with
/// nibble-indexed table lookups and 4-bit shifts — mirroring the portable,
/// constant-time C implementation in `crypto/modes/gcm128.c`.
///
/// ## Security
///
/// The table entries are direct functions of the GHASH subkey `H`. Any
/// disclosure of the table contents leaks `H`, which is catastrophic for
/// GCM authentication. `GHashTable` therefore derives `ZeroizeOnDrop` so
/// the entries are securely erased when the value is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GHashTable {
    /// `h_table[i] = i · H` in GF(2^128), stored in GHASH byte order.
    ///
    /// The index `i` is interpreted as a 4-bit quantity with bit-reversed
    /// nibble semantics, chosen to align with the nibble-wise iteration in
    /// [`GHashTable::multiply`].
    h_table: [u128; 16],
}

impl core::fmt::Debug for GHashTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Key-derived material: redact to avoid accidental exposure in logs.
        f.debug_struct("GHashTable")
            .field("h_table", &"<redacted>")
            .finish()
    }
}

impl GHashTable {
    /// Construct a new GHASH table from a 16-byte subkey `H`.
    ///
    /// Translates `gcm_init_4bit` from `crypto/modes/gcm128.c`. Recursively
    /// computes `H >> 1`, `H >> 2`, `H >> 3` via [`ghash_reduce_1bit`], then
    /// fills the remaining table entries via XOR combinations.
    #[must_use]
    pub fn new(h: &[u8; AES_BLOCK_SIZE]) -> Self {
        // Load H as a big-endian u128: byte 0 → u128 bits 120..=127.
        let h_val = u128::from_be_bytes(*h);

        let mut htable = [0_u128; 16];

        // Htable[0] = 0 (initializer)
        htable[8] = h_val;

        let v = ghash_reduce_1bit(h_val);
        htable[4] = v;
        let v = ghash_reduce_1bit(v);
        htable[2] = v;
        let v = ghash_reduce_1bit(v);
        htable[1] = v;

        // Fill the remaining entries using XOR combinations of the
        // recursively-halved values. The pattern matches the C reference
        // exactly.
        htable[3] = htable[1] ^ htable[2];
        // V = Htable[4]
        htable[5] = htable[4] ^ htable[1];
        htable[6] = htable[4] ^ htable[2];
        htable[7] = htable[4] ^ htable[3];
        // V = Htable[8]
        htable[9] = htable[8] ^ htable[1];
        htable[10] = htable[8] ^ htable[2];
        htable[11] = htable[8] ^ htable[3];
        htable[12] = htable[8] ^ htable[4];
        htable[13] = htable[8] ^ htable[5];
        htable[14] = htable[8] ^ htable[6];
        htable[15] = htable[8] ^ htable[7];

        // `v` falls out of scope — its value (H >> 3) is still live in
        // Htable[1]; that is expected and consistent with the C reference.
        let _ = v;

        Self { h_table: htable }
    }

    /// Multiply `x` by `H` in GF(2^128), storing the result in place.
    ///
    /// Translates `gcm_gmult_4bit` from `crypto/modes/gcm128.c`. The nibble
    /// iteration, shift-by-4, and reduction lookup faithfully mirror the C
    /// reference to preserve exact bit-level equivalence and avoid any timing
    /// side channels introduced by table indexing on secret data (the table
    /// itself is derived from the secret `H`, but the access *pattern* is
    /// data-dependent only on the public `x`).
    pub fn multiply(&self, x: &mut [u8; AES_BLOCK_SIZE]) {
        // Extract high/low nibbles of the last byte of x.
        let byte15 = x[15];
        let mut nhi = usize::from(byte15 >> 4);
        let mut nlo = usize::from(byte15 & 0x0f);

        // Z starts as H · low_nibble(x[15]).
        let mut z = self.h_table[nlo];

        // Process the remaining 31 nibbles. Each loop iteration handles at
        // most two nibbles: first the high-nibble of the "current" byte
        // (loaded before entering the iteration), then the low-nibble of the
        // next byte (loaded inside the iteration for the following pass).
        //
        // Iteration count = 16. On iteration `iter`:
        //   * Part A processes `nhi` of byte `x[15 - (iter - 1)]`.
        //   * If iter == 16, break (last byte's high nibble already handled).
        //   * Otherwise Part D processes `nlo` of byte `x[15 - iter]`.
        for iter in 1..=16 {
            // Part A: Z = (Z >> 4) ⊕ REM_4BIT[rem]; Z ⊕= Htable[nhi].
            // The "rem" captures the four bits shifted out of the low end,
            // which become the reduction lookup index.
            let rem = usize::from(z.to_be_bytes()[15] & 0x0f);
            z = (z >> 4) ^ REM_4BIT[rem];
            z ^= self.h_table[nhi];

            if iter == 16 {
                break;
            }

            // Load the next byte (moving towards index 0) and split it.
            // 15 - iter is in 0..=14 for iter in 1..=15.
            let byte = x[15 - iter];
            nhi = usize::from(byte >> 4);
            nlo = usize::from(byte & 0x0f);

            // Part D: Z = (Z >> 4) ⊕ REM_4BIT[rem]; Z ⊕= Htable[nlo].
            let rem = usize::from(z.to_be_bytes()[15] & 0x0f);
            z = (z >> 4) ^ REM_4BIT[rem];
            z ^= self.h_table[nlo];
        }

        // Write Z back to x in big-endian order.
        *x = z.to_be_bytes();
    }

    /// Apply the GHASH update function over `data` starting from `x`.
    ///
    /// For each 16-byte chunk `B` of `data`, performs `x ← (x ⊕ B) · H`.
    /// A trailing partial block is **zero-padded** on the right before the
    /// multiplication (this is the GCM convention — *not* PKCS#7 padding).
    ///
    /// This is the main "absorb" primitive used by [`AesGcm::seal`] and
    /// [`AesGcm::open`] to fold AAD and ciphertext into the GHASH state.
    pub fn ghash(&self, x: &mut [u8; AES_BLOCK_SIZE], data: &[u8]) {
        let mut chunks = data.chunks_exact(AES_BLOCK_SIZE);
        for chunk in chunks.by_ref() {
            // Safe: chunks_exact yields exactly AES_BLOCK_SIZE-length slices.
            for (dst, src) in x.iter_mut().zip(chunk.iter()) {
                *dst ^= *src;
            }
            self.multiply(x);
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            // Zero-pad the trailing partial block by XOR-ing only the
            // present bytes; the remainder of `x` is XOR-ed with implicit 0
            // (a no-op), giving the same result as if `data` had been
            // right-padded with zeros.
            for (dst, src) in x.iter_mut().zip(remainder.iter()) {
                *dst ^= *src;
            }
            self.multiply(x);
        }
    }
}


// =============================================================================
// AES-GCM — Galois/Counter Mode Authenticated Encryption
// =============================================================================
//
// Translates `CRYPTO_gcm128_*` from `crypto/modes/gcm128.c` (~1,627 lines).
// GCM = CTR encryption + GHASH authentication, both keyed by the AES key.
//
// **Structure** (NIST SP 800-38D):
//   1. `H = AES_K(0^128)` — GHASH subkey, derived once per key.
//   2. `J_0` — initial counter block:
//        * 96-bit nonce: `J_0 = nonce || 0x00 00 00 01`
//        * other length: `J_0 = GHASH_H(nonce || 0^s+64 || [|nonce|·8]_64)`
//   3. `CTR` encryption of plaintext with counter starting at `inc_32(J_0)`.
//      Only the low 32 bits of the counter are incremented (big-endian).
//   4. `GHASH_H` absorbs `AAD || zero-pad || CT || zero-pad || [|A|·8]_64 || [|C|·8]_64`.
//   5. `Tag = GHASH_H(...) ⊕ AES_K(J_0)`, truncated to the tag length.
//
// This implementation supports the **canonical 12-byte nonce and 16-byte
// tag** — the recommended and overwhelmingly common form. The AEAD trait
// implementation enforces these sizes.

/// Length of the GCM nonce (IV) in bytes.
pub(super) const GCM_NONCE_LEN: usize = 12;
/// Length of the GCM authentication tag in bytes.
pub(super) const GCM_TAG_LEN: usize = 16;

/// Increment the low 32 bits of a 16-byte counter in place.
///
/// Implements the `inc_32` operation from NIST SP 800-38D §6.2: the rightmost
/// 32 bits of `counter` are interpreted as a big-endian integer, incremented
/// modulo `2^32`, and written back. The high 96 bits (the nonce portion) are
/// untouched.
#[inline]
fn gcm_inc32(counter: &mut [u8; AES_BLOCK_SIZE]) {
    let last_be = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    let next = last_be.wrapping_add(1).to_be_bytes();
    counter[12] = next[0];
    counter[13] = next[1];
    counter[14] = next[2];
    counter[15] = next[3];
}

/// GCTR — the GCM CTR-mode variant.
///
/// Encrypts `input` into `output` using `aes` under the counter sequence
/// starting at `inc_32(icb)` (i.e., the counter is incremented **before** the
/// first block is encrypted, since counter-block 0 is reserved for the tag).
///
/// `input` and `output` must have equal length. `icb` (Initial Counter Block)
/// is the `J_0` derived during seal/open; it is copied locally and not
/// mutated.
fn gctr_crypt(aes: &Aes, icb: &[u8; AES_BLOCK_SIZE], input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(input.len(), output.len());

    let mut counter = *icb;
    let mut produced = 0usize;

    while produced < input.len() {
        // Advance to the next counter value BEFORE producing this block —
        // counter-block 0 (= J_0) is reserved for the tag computation.
        gcm_inc32(&mut counter);

        // Encrypt the counter to produce 16 bytes of keystream.
        let mut keystream = counter;
        aes.encrypt_block_array(&mut keystream);

        let remaining = input.len() - produced;
        let take = if remaining < AES_BLOCK_SIZE {
            remaining
        } else {
            AES_BLOCK_SIZE
        };

        for idx in 0..take {
            output[produced + idx] = input[produced + idx] ^ keystream[idx];
        }

        produced += take;
    }
}

/// Compute the initial counter block `J_0` per NIST SP 800-38D §7.1.
///
/// For a 96-bit (12-byte) nonce this is simply `nonce || 0x00 00 00 01`.
#[inline]
fn gcm_j0_from_nonce12(nonce: &[u8; GCM_NONCE_LEN]) -> [u8; AES_BLOCK_SIZE] {
    let mut j0 = [0u8; AES_BLOCK_SIZE];
    j0[..GCM_NONCE_LEN].copy_from_slice(nonce);
    // Trailing four bytes: big-endian integer 0x00_00_00_01.
    j0[GCM_NONCE_LEN] = 0x00;
    j0[GCM_NONCE_LEN + 1] = 0x00;
    j0[GCM_NONCE_LEN + 2] = 0x00;
    j0[GCM_NONCE_LEN + 3] = 0x01;
    j0
}

/// Build the GHASH length block: `[|AAD|·8]_64 || [|CT|·8]_64`.
///
/// Converts the byte counts of AAD and ciphertext to a pair of 64-bit
/// big-endian bit counts. Returns an error on overflow — GCM's specification
/// limits AAD to `< 2^61` bytes and ciphertext to `< 2^36` bytes, so any
/// overflow here indicates a caller supplying inputs well beyond the
/// admissible range.
fn gcm_length_block(aad_len: usize, ct_len: usize) -> CryptoResult<[u8; AES_BLOCK_SIZE]> {
    let aad_bits = u64::try_from(aad_len)
        .map_err(|_| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "AES-GCM AAD length exceeds u64::MAX bytes",
            })
        })?
        .checked_mul(8)
        .ok_or(CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "AES-GCM AAD length × 8 overflowed u64",
        }))?;

    let ct_bits = u64::try_from(ct_len)
        .map_err(|_| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "AES-GCM ciphertext length exceeds u64::MAX bytes",
            })
        })?
        .checked_mul(8)
        .ok_or(CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "AES-GCM ciphertext length × 8 overflowed u64",
        }))?;

    let mut block = [0u8; AES_BLOCK_SIZE];
    block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    Ok(block)
}

/// AES-GCM authenticated encryption context.
///
/// Supports all three AES key sizes (128/192/256). Uses the canonical
/// 96-bit nonce and 128-bit tag profile of GCM.
///
/// Implements [`AeadCipher`] for generic use.
///
/// # Example
///
/// ```
/// # use openssl_crypto::symmetric::{AesGcm, AeadCipher};
/// let key = [0u8; 32];
/// let nonce = [0u8; 12];
/// let gcm = AesGcm::new(&key).unwrap();
///
/// let ct = gcm.seal(&nonce, b"header", b"secret").unwrap();
/// let pt = gcm.open(&nonce, b"header", &ct).unwrap();
/// assert_eq!(pt, b"secret");
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesGcm {
    /// Underlying AES block cipher.
    aes: Aes,
    /// GHASH subkey `H = AES_K(0^128)`. Secret — leaks tag-forging power.
    h: [u8; AES_BLOCK_SIZE],
    /// Precomputed 4-bit GHASH multiplication table keyed on `H`.
    h_table: GHashTable,
}

impl core::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesGcm")
            .field("aes", &self.aes)
            .field("h", &"<redacted>")
            .field("h_table", &self.h_table)
            .finish()
    }
}

impl AesGcm {
    /// Construct a new GCM context from an AES key (16, 24, or 32 bytes).
    ///
    /// Derives the GHASH subkey `H = AES_K(0)` and precomputes the 4-bit
    /// multiplication table.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Key`] if `key` is not a valid AES key length.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let aes = Aes::new(key)?;

        // GHASH subkey: H = AES_K(0^128).
        let mut h = [0u8; AES_BLOCK_SIZE];
        aes.encrypt_block_array(&mut h);
        let h_table = GHashTable::new(&h);

        Ok(Self { aes, h, h_table })
    }

    /// Returns the GCM authentication tag length (always 16 bytes).
    #[must_use]
    pub fn tag_length() -> usize {
        GCM_TAG_LEN
    }

    /// Encrypt `plaintext` and authenticate `(aad, ciphertext)` under
    /// `nonce`.
    ///
    /// Returns `ciphertext || tag` (ciphertext length = plaintext length,
    /// tag length = 16 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common(CommonError::ArithmeticOverflow)`] if
    /// the AAD or plaintext lengths would overflow the 64-bit length field
    /// used by GHASH.
    pub fn seal(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Step 1: derive J_0 and the tag pad AES_K(J_0).
        let j0 = gcm_j0_from_nonce12(nonce);
        let mut tag_pad = j0;
        self.aes.encrypt_block_array(&mut tag_pad);

        // Step 2: GCTR-encrypt plaintext into ciphertext.
        let mut output = vec![0u8; plaintext.len() + GCM_TAG_LEN];
        let (ct_out, tag_out) = output.split_at_mut(plaintext.len());
        gctr_crypt(&self.aes, &j0, plaintext, ct_out);

        // Step 3: compute GHASH over (AAD || zero-pad || CT || zero-pad || L).
        let mut x = [0u8; AES_BLOCK_SIZE];
        self.h_table.ghash(&mut x, aad);
        self.h_table.ghash(&mut x, ct_out);

        let length_block = gcm_length_block(aad.len(), ct_out.len())?;
        self.h_table.ghash(&mut x, &length_block);

        // Step 4: T = GHASH_result ⊕ AES_K(J_0).
        for idx in 0..GCM_TAG_LEN {
            tag_out[idx] = x[idx] ^ tag_pad[idx];
        }

        Ok(output)
    }

    /// Decrypt `ciphertext_with_tag` and verify authenticity against
    /// `(aad, nonce)`.
    ///
    /// Returns the plaintext on success. On authentication failure returns
    /// [`CryptoError::Verification`] and never exposes decrypted data — any
    /// intermediate buffers are zeroed before the error is returned.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] if the input
    ///   is shorter than the tag length (16 bytes).
    /// * [`CryptoError::Verification`] if the tag does not match.
    /// * [`CryptoError::Common(CommonError::ArithmeticOverflow)`] on length
    ///   overflow (as in [`seal`](Self::seal)).
    pub fn open(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext_with_tag.len() < GCM_TAG_LEN {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-GCM open: input too short ({} < {})",
                ciphertext_with_tag.len(),
                GCM_TAG_LEN
            ))));
        }
        let split_at = ciphertext_with_tag.len() - GCM_TAG_LEN;
        let (ciphertext_in, tag_in) = ciphertext_with_tag.split_at(split_at);

        // Step 1: derive J_0 and the tag pad.
        let j0 = gcm_j0_from_nonce12(nonce);
        let mut tag_pad = j0;
        self.aes.encrypt_block_array(&mut tag_pad);

        // Step 2: recompute expected tag over (AAD || CT || L) — note we do
        // NOT decrypt yet; authenticity must be confirmed first.
        let mut x = [0u8; AES_BLOCK_SIZE];
        self.h_table.ghash(&mut x, aad);
        self.h_table.ghash(&mut x, ciphertext_in);

        let length_block = gcm_length_block(aad.len(), ciphertext_in.len())?;
        self.h_table.ghash(&mut x, &length_block);

        let mut expected_tag = [0u8; GCM_TAG_LEN];
        for idx in 0..GCM_TAG_LEN {
            expected_tag[idx] = x[idx] ^ tag_pad[idx];
        }

        // Step 3: constant-time tag comparison. We must not branch on the
        // comparison result in a way that reveals bits of the expected tag.
        if !bool::from(expected_tag.ct_eq(tag_in)) {
            // Zero local secrets before returning.
            expected_tag.zeroize();
            tag_pad.zeroize();
            return Err(CryptoError::Verification(
                "AES-GCM authentication tag mismatch".to_string(),
            ));
        }

        // Step 4: tag verified — decrypt.
        let mut plaintext = vec![0u8; ciphertext_in.len()];
        gctr_crypt(&self.aes, &j0, ciphertext_in, &mut plaintext);

        // Scrub local tag material.
        expected_tag.zeroize();
        tag_pad.zeroize();

        Ok(plaintext)
    }
}

impl AeadCipher for AesGcm {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr: &[u8; GCM_NONCE_LEN] = nonce.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-GCM nonce must be {GCM_NONCE_LEN} bytes, got {}",
                nonce.len()
            )))
        })?;
        AesGcm::seal(self, nonce_arr, aad, plaintext)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce_arr: &[u8; GCM_NONCE_LEN] = nonce.try_into().map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-GCM nonce must be {GCM_NONCE_LEN} bytes, got {}",
                nonce.len()
            )))
        })?;
        AesGcm::open(self, nonce_arr, aad, ciphertext_with_tag)
    }

    fn nonce_length(&self) -> usize {
        GCM_NONCE_LEN
    }

    fn tag_length(&self) -> usize {
        GCM_TAG_LEN
    }

    fn algorithm(&self) -> CipherAlgorithm {
        self.aes.algorithm()
    }
}



// =============================================================================
// AES-CCM — Counter with CBC-MAC (NIST SP 800-38C, RFC 3610)
// =============================================================================
//
// Translates `CRYPTO_ccm128_*` from `crypto/modes/ccm128.c` (~442 lines).
// CCM = CTR mode encryption + CBC-MAC authentication, both keyed by the
// same AES key. Unlike GCM, CCM is *two-pass*: tag is computed over AAD
// and plaintext, then the ciphertext and the encrypted tag are emitted.
//
// **Parameters**:
//   * `M` (tag length): 4, 6, 8, 10, 12, 14, or 16 bytes
//   * `L` (length-field size): 2..=8 bytes → nonce is `15 - L` bytes long
//   * `N` (nonce length): 7..=13 bytes
//
// **Formatting** (RFC 3610 §2.2):
//   B_0 = `Flags || N || Q`
//     Flags byte = `(Adata<<6) | (((M-2)/2)<<3) | (L-1)`
//     Adata = 1 if AAD non-empty, else 0
//     Q = plaintext length in L big-endian bytes
//
//   AAD length prefix:
//     0 < |A| < 2^16-2^8   → 2 BE bytes of |A|
//     2^16-2^8 ≤ |A| < 2^32 → `0xFF 0xFE` + 4 BE bytes
//     2^32 ≤ |A| < 2^64    → `0xFF 0xFF` + 8 BE bytes
//
//   Counter block A_i = `(L-1) || N || i` (i in L BE bytes).
//
// **CBC-MAC**: X_0 = 0; X_{j+1} = AES_K(X_j ⊕ B_j) for each 16-byte
// formatted block of (B_0 || formatted_AAD || plaintext), each trailing
// partial block is zero-padded. T = MSB_M(X_last).
//
// **CTR encryption**: i=1,2,... used for plaintext blocks; i=0 is used
// for tag encryption. Tag = T ⊕ MSB_M(AES_K(A_0)).

/// Encode the CCM additional-authenticated-data length prefix (RFC 3610 §2.2).
///
/// Returns a fixed 10-byte buffer and the number of bytes that are
/// meaningful (2, 6, or 10), chosen according to `alen`.
fn encode_ccm_aad_len(alen: usize) -> CryptoResult<([u8; 10], usize)> {
    let alen_u64 = u64::try_from(alen).map_err(|_| {
        CryptoError::Common(CommonError::InvalidArgument(format!(
            "AES-CCM AAD length {alen} exceeds u64::MAX"
        )))
    })?;

    let mut buf = [0u8; 10];
    if alen_u64 < 0xFF00 {
        // 2-byte encoding. We have verified alen_u64 < 0xFF00 < u16::MAX,
        // so the conversion is lossless; the `unwrap_or` path is
        // statically unreachable.
        let alen_u16 = u16::try_from(alen_u64).unwrap_or(u16::MAX);
        buf[0..2].copy_from_slice(&alen_u16.to_be_bytes());
        Ok((buf, 2))
    } else if alen_u64 < (1u64 << 32) {
        // 6-byte encoding: 0xFF 0xFE || 4 BE bytes.
        let alen_u32 = u32::try_from(alen_u64).unwrap_or(u32::MAX);
        buf[0] = 0xFF;
        buf[1] = 0xFE;
        buf[2..6].copy_from_slice(&alen_u32.to_be_bytes());
        Ok((buf, 6))
    } else {
        // 10-byte encoding: 0xFF 0xFF || 8 BE bytes.
        buf[0] = 0xFF;
        buf[1] = 0xFF;
        buf[2..10].copy_from_slice(&alen_u64.to_be_bytes());
        Ok((buf, 10))
    }
}

/// Increment the counter portion of a CCM `A_i` block in place.
///
/// Treats `ctr` as a big-endian integer and increments by 1 modulo
/// `2^(8·ctr.len())`. Overflow wraps silently, consistent with the C
/// implementation `ctr128_inc`.
#[inline]
fn ccm_increment_ctr(ctr: &mut [u8]) {
    for byte in ctr.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

/// AES-CCM authenticated encryption context.
///
/// Configured at construction with a tag length (4..=16, even) and a
/// nonce length (7..=13). Translates C `CRYPTO_ccm128_init` +
/// `CRYPTO_ccm128_setiv` + `CRYPTO_ccm128_encrypt` + decrypt/tag flow.
///
/// Implements [`AeadCipher`] for generic use.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesCcm {
    aes: Aes,
    /// M parameter — tag length in bytes: 4, 6, 8, 10, 12, 14, or 16.
    #[zeroize(skip)]
    tag_len: usize,
    /// N parameter — nonce length in bytes: 7..=13.
    #[zeroize(skip)]
    nonce_len: usize,
}

impl core::fmt::Debug for AesCcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesCcm")
            .field("aes", &self.aes)
            .field("tag_len", &self.tag_len)
            .field("nonce_len", &self.nonce_len)
            .finish()
    }
}

impl AesCcm {
    /// Construct a new CCM context.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes)
    /// * `tag_len` — desired tag length (∈ {4, 6, 8, 10, 12, 14, 16})
    /// * `nonce_len` — desired nonce length (∈ {7, 8, 9, 10, 11, 12, 13})
    ///
    /// # Errors
    /// * [`CryptoError::Key`] — invalid AES key length
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] — invalid
    ///   tag or nonce length
    pub fn new(key: &[u8], tag_len: usize, nonce_len: usize) -> CryptoResult<Self> {
        if !matches!(tag_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-CCM: invalid tag length {tag_len}; must be 4, 6, 8, 10, 12, 14, or 16"
            ))));
        }
        if !(7..=13).contains(&nonce_len) {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-CCM: invalid nonce length {nonce_len}; must be 7..=13"
            ))));
        }
        let aes = Aes::new(key)?;
        Ok(Self {
            aes,
            tag_len,
            nonce_len,
        })
    }

    /// Compute `L = 15 - nonce_len` — the number of bytes used to encode
    /// the message length field `Q`.
    #[inline]
    fn l_bytes(&self) -> usize {
        15 - self.nonce_len
    }

    /// Construct the initial counter block `A_0 = (L-1) || N || 0^L`.
    ///
    /// Caller increments the trailing L bytes before encrypting
    /// plaintext; `A_0` itself is reserved for tag encryption.
    fn build_counter_block(&self, nonce: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        let l_bytes = self.l_bytes();
        let mut a = [0u8; AES_BLOCK_SIZE];
        // Counter flags: just (L-1) in low bits, no adata, no tag bits.
        // l_bytes ∈ {2..=8}, so l_bytes - 1 ∈ {1..=7} — fits in u8.
        a[0] = u8::try_from(l_bytes - 1).unwrap_or(u8::MAX);
        a[1..=nonce.len()].copy_from_slice(nonce);
        // Trailing l_bytes already zero (from initializer).
        a
    }

    /// Compute the CBC-MAC tag `T` over the formatted input
    /// `B_0 || formatted_AAD || data`, each trailing partial block
    /// zero-padded.
    ///
    /// The `data` argument is the plaintext (on seal) or the already-
    /// decrypted plaintext (on open). Returns the 16-byte CBC-MAC
    /// output; caller truncates to `tag_len` and XORs with AES(K, `A_0`).
    fn compute_mac(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &[u8],
    ) -> CryptoResult<[u8; AES_BLOCK_SIZE]> {
        let l_bytes = self.l_bytes();

        // Verify data length fits in L bytes.
        let data_len_u64 = u64::try_from(data.len()).map_err(|_| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "AES-CCM data length exceeds u64::MAX",
            })
        })?;
        if l_bytes < 8 {
            let max_data = 1u64 << (8 * l_bytes);
            if data_len_u64 >= max_data {
                return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                    "AES-CCM: data length {} exceeds 2^{} bytes for L={l_bytes}",
                    data.len(),
                    8 * l_bytes
                ))));
            }
        }

        // Flags byte for B_0: Adata (0x40) | ((M-2)/2)<<3 | (L-1).
        let adata_flag: u8 = if aad.is_empty() { 0 } else { 0x40 };
        // (tag_len-2)/2 ∈ {1..=7} for valid tag_len — fits in u8.
        let m_shifted = u8::try_from((self.tag_len - 2) / 2).unwrap_or(u8::MAX) << 3;
        let l_flag = u8::try_from(l_bytes - 1).unwrap_or(u8::MAX);
        let flags = adata_flag | m_shifted | l_flag;

        // Build B_0 = flags || N || Q (Q = data length in L BE bytes).
        let mut b0 = [0u8; AES_BLOCK_SIZE];
        b0[0] = flags;
        b0[1..=nonce.len()].copy_from_slice(nonce);
        let q_be = data_len_u64.to_be_bytes(); // 8 BE bytes
        // Place the rightmost l_bytes of q_be into the last l_bytes of b0.
        // Since data_len_u64 fits in L bytes when L<8, the upper bytes of
        // q_be are zero; when L=8 we take the full 8 bytes.
        b0[AES_BLOCK_SIZE - l_bytes..].copy_from_slice(&q_be[8 - l_bytes..]);

        // X_1 = AES(K, X_0 ⊕ B_0) = AES(K, B_0), since X_0 = 0.
        let mut x = b0;
        self.aes.encrypt_block_array(&mut x);

        // Process formatted AAD (length prefix concatenated with AAD,
        // zero-padded to a multiple of 16) if present.
        if !aad.is_empty() {
            let (a_len_buf, a_len_size) = encode_ccm_aad_len(aad.len())?;

            // First block: a_len_prefix || first chunk of AAD, zero-padded.
            let first_aad_capacity = AES_BLOCK_SIZE - a_len_size;
            let first_aad_take = first_aad_capacity.min(aad.len());

            let mut block = [0u8; AES_BLOCK_SIZE];
            block[0..a_len_size].copy_from_slice(&a_len_buf[0..a_len_size]);
            block[a_len_size..a_len_size + first_aad_take]
                .copy_from_slice(&aad[0..first_aad_take]);
            // Remainder of block is zero-padded implicitly.

            for idx in 0..AES_BLOCK_SIZE {
                x[idx] ^= block[idx];
            }
            self.aes.encrypt_block_array(&mut x);

            // Remaining AAD processed in 16-byte chunks.
            let rest_aad = &aad[first_aad_take..];
            let mut chunks = rest_aad.chunks_exact(AES_BLOCK_SIZE);
            for chunk in chunks.by_ref() {
                for idx in 0..AES_BLOCK_SIZE {
                    x[idx] ^= chunk[idx];
                }
                self.aes.encrypt_block_array(&mut x);
            }
            let remainder = chunks.remainder();
            if !remainder.is_empty() {
                let mut last = [0u8; AES_BLOCK_SIZE];
                last[0..remainder.len()].copy_from_slice(remainder);
                for idx in 0..AES_BLOCK_SIZE {
                    x[idx] ^= last[idx];
                }
                self.aes.encrypt_block_array(&mut x);
            }
        }

        // Process plaintext (zero-padded to a multiple of 16).
        let mut chunks = data.chunks_exact(AES_BLOCK_SIZE);
        for chunk in chunks.by_ref() {
            for idx in 0..AES_BLOCK_SIZE {
                x[idx] ^= chunk[idx];
            }
            self.aes.encrypt_block_array(&mut x);
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut last = [0u8; AES_BLOCK_SIZE];
            last[0..remainder.len()].copy_from_slice(remainder);
            for idx in 0..AES_BLOCK_SIZE {
                x[idx] ^= last[idx];
            }
            self.aes.encrypt_block_array(&mut x);
        }

        Ok(x)
    }

    /// Apply CCM CTR-mode encryption/decryption (symmetric): writes
    /// `data_in ⊕ keystream` into `data_out`.
    ///
    /// Counter blocks `A_1, A_2, ...` are derived from `A_0` by
    /// incrementing the trailing L bytes as a big-endian integer.
    /// `A_0` is not used here — caller handles tag encryption
    /// separately.
    fn ctr_apply(&self, nonce: &[u8], data_in: &[u8], data_out: &mut [u8]) {
        debug_assert_eq!(data_in.len(), data_out.len());
        let l_bytes = self.l_bytes();
        let mut a_i = self.build_counter_block(nonce);
        let mut produced = 0usize;

        while produced < data_in.len() {
            // Advance counter portion (last L bytes) by 1 BEFORE
            // producing each block: A_1, A_2, ... (A_0 reserved for tag).
            ccm_increment_ctr(&mut a_i[AES_BLOCK_SIZE - l_bytes..]);

            let mut keystream = a_i;
            self.aes.encrypt_block_array(&mut keystream);

            let remaining = data_in.len() - produced;
            let take = remaining.min(AES_BLOCK_SIZE);
            for idx in 0..take {
                data_out[produced + idx] = data_in[produced + idx] ^ keystream[idx];
            }
            produced += take;
        }
    }

    /// Compute `AES_K(A_0)` — the keystream block used to encrypt the
    /// authentication tag.
    fn compute_tag_pad(&self, nonce: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        let mut a_0 = self.build_counter_block(nonce);
        self.aes.encrypt_block_array(&mut a_0);
        a_0
    }

    /// Encrypt `plaintext` and authenticate `(aad, ciphertext)` under
    /// `nonce`.
    ///
    /// Returns `ciphertext || tag` where `ciphertext.len() == plaintext.len()`
    /// and `tag.len() == tag_len`.
    ///
    /// # Errors
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] — nonce
    ///   length mismatch, plaintext exceeds `2^(8·L)` bytes, or AAD
    ///   length exceeds `u64::MAX`.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if nonce.len() != self.nonce_len {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-CCM nonce must be {} bytes, got {}",
                self.nonce_len,
                nonce.len()
            ))));
        }

        // Compute MAC over (B_0 || formatted_AAD || plaintext).
        let mac = self.compute_mac(nonce, aad, plaintext)?;

        // Prepare output buffer: ciphertext || tag.
        let mut output = vec![0u8; plaintext.len() + self.tag_len];
        let (ct_out, tag_out) = output.split_at_mut(plaintext.len());

        // CTR-encrypt plaintext (counters A_1, A_2, ...).
        self.ctr_apply(nonce, plaintext, ct_out);

        // Tag = MSB_tag_len(MAC ⊕ AES_K(A_0)).
        let mut tag_pad = self.compute_tag_pad(nonce);
        for idx in 0..self.tag_len {
            tag_out[idx] = mac[idx] ^ tag_pad[idx];
        }
        tag_pad.zeroize();

        Ok(output)
    }

    /// Decrypt `ciphertext_with_tag` and verify authenticity against
    /// `(aad, nonce)`.
    ///
    /// On success returns the plaintext. On authentication failure
    /// returns [`CryptoError::Verification`] and never exposes
    /// decrypted data — intermediate plaintext and expected tag are
    /// zeroized before the error is returned.
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce.len() != self.nonce_len {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-CCM nonce must be {} bytes, got {}",
                self.nonce_len,
                nonce.len()
            ))));
        }
        if ciphertext_with_tag.len() < self.tag_len {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-CCM open: input too short ({} < {})",
                ciphertext_with_tag.len(),
                self.tag_len
            ))));
        }

        let split_at = ciphertext_with_tag.len() - self.tag_len;
        let (ct_in, tag_in) = ciphertext_with_tag.split_at(split_at);

        // Decrypt ciphertext (CTR is symmetric).
        let mut plaintext = vec![0u8; ct_in.len()];
        self.ctr_apply(nonce, ct_in, &mut plaintext);

        // Compute MAC over recovered plaintext.
        let mac = match self.compute_mac(nonce, aad, &plaintext) {
            Ok(m) => m,
            Err(e) => {
                plaintext.zeroize();
                return Err(e);
            }
        };

        // Compute expected tag = MSB_tag_len(MAC ⊕ AES_K(A_0)).
        let mut tag_pad = self.compute_tag_pad(nonce);
        let mut expected_tag = vec![0u8; self.tag_len];
        for idx in 0..self.tag_len {
            expected_tag[idx] = mac[idx] ^ tag_pad[idx];
        }
        tag_pad.zeroize();

        // Constant-time tag comparison.
        if !bool::from(expected_tag.ct_eq(tag_in)) {
            plaintext.zeroize();
            expected_tag.zeroize();
            return Err(CryptoError::Verification(
                "AES-CCM authentication tag mismatch".to_string(),
            ));
        }

        expected_tag.zeroize();
        Ok(plaintext)
    }
}

impl AeadCipher for AesCcm {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        AesCcm::seal(self, nonce, aad, plaintext)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        AesCcm::open(self, nonce, aad, ciphertext_with_tag)
    }

    fn nonce_length(&self) -> usize {
        self.nonce_len
    }

    fn tag_length(&self) -> usize {
        self.tag_len
    }

    fn algorithm(&self) -> CipherAlgorithm {
        self.aes.algorithm()
    }
}



// =============================================================================
// AES-XTS — XEX-based Tweaked-codebook with Ciphertext Stealing
// (IEEE Std 1619-2007, NIST SP 800-38E)
// =============================================================================
//
// Translates `CRYPTO_xts128_encrypt` from `crypto/modes/xts128.c` (~161 lines).
// XTS is the standard mode for *sector-based storage encryption*
// (e.g., full-disk encryption, LUKS, BitLocker). It provides
// confidentiality without authentication, parallelisable block
// encryption with a per-block tweak, and supports data units that are
// not a multiple of the 128-bit block size via ciphertext stealing
// (CTS).
//
// **Key material** (2·|K| bytes): the caller supplies a single key
// buffer of length 32, 48, or 64 bytes. The first half is the data
// key `K1` (used for plaintext encryption); the second half is the
// tweak key `K2` (used to derive the initial tweak from the IV).
// IEEE 1619 mandates `K1 ≠ K2`.
//
// **Encryption** for data unit of length `len = M·16 + r` with
// `M ≥ 1` blocks and `r ∈ {0..=15}`:
//
//   1. `T = AES_K2(IV)` (initial tweak).
//   2. For `i ∈ 0..M-1` (or 0..M-1 if r > 0, else 0..M):
//        `C_i = AES_K1(P_i ⊕ T^i) ⊕ T^i`, advance `T ← α·T`.
//   3. If `r > 0`, apply ciphertext stealing on the final full and
//      partial blocks: compute `CC = AES_K1(P_{M-1} ⊕ T^{M-1}) ⊕ T^{M-1}`,
//      advance `T ← α·T`; then `C_M = CC[0..r]` (partial ciphertext),
//      and `C_{M-1} = AES_K1(P'⊕T^M) ⊕ T^M` where
//      `P' = P_M || CC[r..16]` (partial plaintext extended with the
//      stolen bytes from `CC`).
//
// The tweak advance `α·T` is multiplication by `x` in `GF(2^128)` with
// reduction polynomial `x^128 + x^7 + x^2 + x + 1`. The tweak is
// interpreted in **little-endian** byte order (byte 0 is the least
// significant).

/// Advance an XTS tweak by one step: multiply by the generator α in
/// `GF(2^128)`.
///
/// The tweak is treated as a 128-bit integer in little-endian byte
/// order. The whole value is shifted left by one bit; if bit 127
/// (the MSB of `tweak[15]`) overflows, the low byte `tweak[0]` is
/// XOR-reduced with `0x87` to enforce the polynomial.
#[inline]
fn xts_advance_tweak(tweak: &mut [u8; AES_BLOCK_SIZE]) {
    let mut carry: u8 = 0;
    for byte in tweak.iter_mut() {
        let next_carry = (*byte >> 7) & 1;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

/// AES-XTS tweakable encryption context.
///
/// Holds two independent AES subkeys: `data_key` (K1) is used to
/// encrypt the XOR-masked plaintext blocks, while `tweak_key` (K2)
/// is used to derive the initial tweak from the IV.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct AesXts {
    data_key: Aes,
    tweak_key: Aes,
}

impl AesXts {
    /// Construct a new XTS context from a concatenated key.
    ///
    /// The combined `key` must be 32, 48, or 64 bytes — the first
    /// half is assigned to `K1` (data key) and the second half to
    /// `K2` (tweak key). Per IEEE 1619, `K1 ≠ K2` is enforced with
    /// a constant-time comparison.
    ///
    /// # Errors
    /// * [`CryptoError::Key`] — invalid combined key length or
    ///   `K1 == K2`.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if !matches!(key.len(), 32 | 48 | 64) {
            return Err(CryptoError::Key(format!(
                "AES-XTS key must be 32, 48, or 64 bytes (two concatenated AES keys), got {}",
                key.len()
            )));
        }
        let half = key.len() / 2;
        let (k1, k2) = key.split_at(half);
        // IEEE 1619: data key and tweak key must differ.
        if bool::from(k1.ct_eq(k2)) {
            return Err(CryptoError::Key(
                "AES-XTS: data key and tweak key must differ (IEEE 1619-2007)".to_string(),
            ));
        }
        let data_key = Aes::new(k1)?;
        let tweak_key = Aes::new(k2)?;
        Ok(Self {
            data_key,
            tweak_key,
        })
    }

    /// Encrypt `plaintext` under the supplied 128-bit tweak (IV).
    ///
    /// Supports data unit lengths `len ≥ 16`, including non-multiples
    /// of the block size via ciphertext stealing. Returns ciphertext
    /// of identical length.
    ///
    /// # Errors
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] —
    ///   plaintext shorter than 16 bytes.
    pub fn encrypt(
        &self,
        iv: &[u8; AES_BLOCK_SIZE],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if plaintext.len() < AES_BLOCK_SIZE {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-XTS: plaintext must be at least {AES_BLOCK_SIZE} bytes, got {}",
                plaintext.len()
            ))));
        }

        // Derive initial tweak: T^0 = AES_K2(IV).
        let mut current_tweak = *iv;
        self.tweak_key.encrypt_block_array(&mut current_tweak);

        let mut output = vec![0u8; plaintext.len()];
        let full_blocks = plaintext.len() / AES_BLOCK_SIZE;
        let remainder = plaintext.len() % AES_BLOCK_SIZE;
        // Number of blocks processed normally (before the CTS pair).
        // If `remainder == 0`, all `full_blocks` are normal; otherwise
        // the last full block is part of the CTS pair.
        let normal_blocks = if remainder == 0 {
            full_blocks
        } else {
            full_blocks - 1
        };

        // Normal XTS block encryption: C_i = AES_K1(P_i ⊕ T^i) ⊕ T^i.
        for i in 0..normal_blocks {
            let offset = i * AES_BLOCK_SIZE;
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&plaintext[offset..offset + AES_BLOCK_SIZE]);
            for idx in 0..AES_BLOCK_SIZE {
                block[idx] ^= current_tweak[idx];
            }
            self.data_key.encrypt_block_array(&mut block);
            for idx in 0..AES_BLOCK_SIZE {
                block[idx] ^= current_tweak[idx];
            }
            output[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&block);
            xts_advance_tweak(&mut current_tweak);
        }

        if remainder == 0 {
            return Ok(output);
        }

        // Ciphertext stealing. After the normal loop, `current_tweak`
        // is `T^{M-1}` (tweak for the last full block). Compute
        // `CC = AES_K1(P_{M-1} ⊕ T^{M-1}) ⊕ T^{M-1}` — this is what the
        // last full ciphertext block would be without stealing.
        let offset = normal_blocks * AES_BLOCK_SIZE;
        let mut cc = [0u8; AES_BLOCK_SIZE];
        cc.copy_from_slice(&plaintext[offset..offset + AES_BLOCK_SIZE]);
        for idx in 0..AES_BLOCK_SIZE {
            cc[idx] ^= current_tweak[idx];
        }
        self.data_key.encrypt_block_array(&mut cc);
        for idx in 0..AES_BLOCK_SIZE {
            cc[idx] ^= current_tweak[idx];
        }

        // Advance tweak to `T^M` for the stolen block.
        xts_advance_tweak(&mut current_tweak);

        // Build `P' = P_M (partial r bytes) || CC[r..16]` and encrypt
        // with `T^M`: this yields the final 16-byte ciphertext block
        // that is stored at offset `(M-1)·16`.
        let partial_offset = (normal_blocks + 1) * AES_BLOCK_SIZE;
        let mut pp = [0u8; AES_BLOCK_SIZE];
        pp[0..remainder].copy_from_slice(&plaintext[partial_offset..partial_offset + remainder]);
        pp[remainder..].copy_from_slice(&cc[remainder..]);

        for idx in 0..AES_BLOCK_SIZE {
            pp[idx] ^= current_tweak[idx];
        }
        self.data_key.encrypt_block_array(&mut pp);
        for idx in 0..AES_BLOCK_SIZE {
            pp[idx] ^= current_tweak[idx];
        }

        // Output layout: C_0 .. C_{M-2} (already written) || PP || CC[0..r].
        output[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&pp);
        output[partial_offset..partial_offset + remainder].copy_from_slice(&cc[0..remainder]);

        // Scrub intermediate material.
        cc.zeroize();
        pp.zeroize();
        current_tweak.zeroize();

        Ok(output)
    }

    /// Decrypt `ciphertext` under the supplied 128-bit tweak (IV).
    ///
    /// Inverse of [`AesXts::encrypt`]. Supports ciphertext lengths
    /// `len ≥ 16`, including non-multiples of the block size.
    ///
    /// # Errors
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] —
    ///   ciphertext shorter than 16 bytes.
    pub fn decrypt(
        &self,
        iv: &[u8; AES_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < AES_BLOCK_SIZE {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-XTS: ciphertext must be at least {AES_BLOCK_SIZE} bytes, got {}",
                ciphertext.len()
            ))));
        }

        let mut current_tweak = *iv;
        self.tweak_key.encrypt_block_array(&mut current_tweak);

        let mut output = vec![0u8; ciphertext.len()];
        let full_blocks = ciphertext.len() / AES_BLOCK_SIZE;
        let remainder = ciphertext.len() % AES_BLOCK_SIZE;
        let normal_blocks = if remainder == 0 {
            full_blocks
        } else {
            full_blocks - 1
        };

        for i in 0..normal_blocks {
            let offset = i * AES_BLOCK_SIZE;
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(&ciphertext[offset..offset + AES_BLOCK_SIZE]);
            for idx in 0..AES_BLOCK_SIZE {
                block[idx] ^= current_tweak[idx];
            }
            self.data_key.decrypt_block_array(&mut block);
            for idx in 0..AES_BLOCK_SIZE {
                block[idx] ^= current_tweak[idx];
            }
            output[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&block);
            xts_advance_tweak(&mut current_tweak);
        }

        if remainder == 0 {
            return Ok(output);
        }

        // Ciphertext stealing on decryption: the last two tweaks are
        // applied in *reversed* order. After the loop, `current_tweak`
        // is `T^{M-1}`. Save it; advance to `T^M` for the first
        // decryption step.
        let tweak_m_minus_1 = current_tweak;
        xts_advance_tweak(&mut current_tweak); // now `T^M`

        // Decrypt `C_{M-1}` (last full ciphertext block) with `T^M`.
        let offset = normal_blocks * AES_BLOCK_SIZE;
        let mut dd = [0u8; AES_BLOCK_SIZE];
        dd.copy_from_slice(&ciphertext[offset..offset + AES_BLOCK_SIZE]);
        for idx in 0..AES_BLOCK_SIZE {
            dd[idx] ^= current_tweak[idx];
        }
        self.data_key.decrypt_block_array(&mut dd);
        for idx in 0..AES_BLOCK_SIZE {
            dd[idx] ^= current_tweak[idx];
        }

        // Build `PC = C_M (partial r bytes) || DD[r..16]` and decrypt
        // with `T^{M-1}`: this recovers the `M-1`th plaintext block.
        let partial_offset = (normal_blocks + 1) * AES_BLOCK_SIZE;
        let mut pc = [0u8; AES_BLOCK_SIZE];
        pc[0..remainder].copy_from_slice(&ciphertext[partial_offset..partial_offset + remainder]);
        pc[remainder..].copy_from_slice(&dd[remainder..]);

        for idx in 0..AES_BLOCK_SIZE {
            pc[idx] ^= tweak_m_minus_1[idx];
        }
        self.data_key.decrypt_block_array(&mut pc);
        for idx in 0..AES_BLOCK_SIZE {
            pc[idx] ^= tweak_m_minus_1[idx];
        }

        // Output layout: P_0 .. P_{M-2} (already written) || PC || DD[0..r].
        output[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&pc);
        output[partial_offset..partial_offset + remainder].copy_from_slice(&dd[0..remainder]);

        dd.zeroize();
        pc.zeroize();
        current_tweak.zeroize();

        Ok(output)
    }
}





// =============================================================================
// AES-OCB — Offset Codebook Mode (RFC 7253)
// =============================================================================
//
// Translates `CRYPTO_ocb128_*` from `crypto/modes/ocb128.c` (~563 lines).
// OCB is a high-performance single-pass AEAD that uses a gray-code sequence
// of offset values (derived by doubling a master `L` value) to provide
// authenticated encryption in one block-cipher invocation per 16 bytes of
// data.
//
// **Setup** (ctx init + setiv):
//   L_*     = AES_K(0^128)
//   L_$     = double(L_*)
//   L_0     = double(L_$)
//   L_i     = double(L_{i-1}) for i ≥ 1
//
//   Nonce  = num2str(TAGLEN mod 128, 7) || zeros(120-8·|N|) || 1 || N
//   Top    = nonce with low 6 bits cleared
//   Ktop   = AES_K(Top)
//   Stretch[24] = Ktop || (Ktop[0..8] XOR Ktop[1..9])
//   bottom = nonce[15] & 0x3f
//   Offset_0 = Stretch[1+bottom .. 128+bottom]   (bit-level sub-string)
//
// **AAD (HASH-then-fold)**:
//   For full 16-byte AAD block A_i:
//     Offset_aad ← Offset_aad XOR L_{ntz(i)}
//     Sum        ← Sum XOR AES_K(A_i XOR Offset_aad)
//   For partial AAD block A_*:
//     Offset_aad ← Offset_aad XOR L_*
//     Sum        ← Sum XOR AES_K((A_* || 0x80 || 0-pad) XOR Offset_aad)
//
// **Encryption (seal)**:
//   For full 16-byte plaintext block P_i (i ≥ 1):
//     Offset      ← Offset XOR L_{ntz(i)}
//     Checksum    ← Checksum XOR P_i
//     C_i         ← Offset XOR AES_K(P_i XOR Offset)
//   For partial block P_*:
//     Offset_*    ← Offset XOR L_*
//     Pad         ← AES_K(Offset_*)
//     C_*         ← P_* XOR Pad[0..|P_*|]
//     Checksum    ← Checksum XOR (P_* || 0x80 || 0-pad)
//
// **Decryption (open)** — mirror of seal, with two crucial asymmetries:
//   For full 16-byte ciphertext block C_i:
//     Offset      ← Offset XOR L_{ntz(i)}
//     P_i         ← Offset XOR AES^-1_K(C_i XOR Offset)
//     Checksum    ← Checksum XOR P_i
//   For partial block C_*:
//     Offset_*    ← Offset XOR L_*
//     Pad         ← AES_K(Offset_*)              [encrypt, NOT decrypt]
//     P_*         ← C_* XOR Pad[0..|C_*|]
//     Checksum    ← Checksum XOR (P_* || 0x80 || 0-pad)   [uses P_*, NOT C_*]
//
// **Tag**:
//   Tag = AES_K(Checksum XOR Offset_final XOR L_$) XOR Sum
//         (truncated to `tag_len` bytes)

/// Maximum nonce length accepted by AES-OCB (RFC 7253 §4.2).
pub const OCB_MAX_NONCE_LEN: usize = 15;

/// Maximum tag length accepted by AES-OCB (RFC 7253 §4.2).
pub const OCB_MAX_TAG_LEN: usize = AES_BLOCK_SIZE;

/// Default tag length for AES-OCB (128 bits per RFC 7253 §3).
pub const OCB_DEFAULT_TAG_LEN: usize = 16;

/// Default nonce length for AES-OCB (96 bits — common choice).
pub const OCB_DEFAULT_NONCE_LEN: usize = 12;

/// Variable-width left shift of a 16-byte big-endian block.
///
/// Translates `ocb_block_lshift` from `crypto/modes/ocb128.c`. Used only
/// during `Offset_0` derivation where `shift` ∈ 0..=7 (caller's
/// responsibility to uphold).
fn ocb_block_lshift(
    input: &[u8; AES_BLOCK_SIZE],
    shift: usize,
    output: &mut [u8; AES_BLOCK_SIZE],
) {
    debug_assert!(shift < 8, "ocb_block_lshift: shift must be < 8, got {shift}");
    let shift_u32 = u32::try_from(shift).unwrap_or(0);
    let inv_shift = 8u32.saturating_sub(shift_u32);
    let mut carry: u8 = 0;
    for i in (0..AES_BLOCK_SIZE).rev() {
        // `checked_shr` returns `None` when inv_shift == 8 (shift == 0),
        // which yields the correct zero-carry behaviour for the
        // identity-shift case. For inv_shift ∈ 1..=7 it returns
        // `Some(value)` with the normal shifted result.
        let carry_next = input[i].checked_shr(inv_shift).unwrap_or(0);
        output[i] = input[i].wrapping_shl(shift_u32) | carry;
        carry = carry_next;
    }
}

/// GF(2^128) doubling for the offset-codebook master sequence.
///
/// Translates `ocb_double` from `crypto/modes/ocb128.c`. Treats `input`
/// as a big-endian 128-bit value over the polynomial
/// `x^128 + x^7 + x^2 + x + 1`. If the MSB of `input` is set, XOR the
/// reduction constant `0x87` into the low byte after the 1-bit left shift.
///
/// The mask computation uses a constant-time pattern
/// `mask = -(msb) & 0x87` to avoid a secret-dependent branch.
fn ocb_double(input: &[u8; AES_BLOCK_SIZE], output: &mut [u8; AES_BLOCK_SIZE]) {
    // Constant-time mask: 0x87 if MSB(input[0]) set, else 0.
    let top_bit = (input[0] & 0x80) >> 7;
    let mask = 0u8.wrapping_sub(top_bit) & 0x87;

    // Specialised 1-bit big-endian left shift (inline for hot path).
    let mut carry: u8 = 0;
    for i in (0..AES_BLOCK_SIZE).rev() {
        let carry_next = (input[i] >> 7) & 1;
        output[i] = input[i].wrapping_shl(1) | carry;
        carry = carry_next;
    }
    output[15] ^= mask;
}

/// Lazy-extend an L-values vector by doubling until index `idx` is
/// covered.
///
/// Used by [`AesOcb::seal`] / [`AesOcb::open`] to cover messages whose
/// block count exceeds the precomputed `L_0..L_4` cache (up to 496
/// bytes). Extension happens in a per-call `Vec` so that `self` remains
/// shareable / read-only.
fn ocb_extend_l(l: &mut Vec<[u8; AES_BLOCK_SIZE]>, idx: usize) {
    while idx >= l.len() {
        // `l` is seeded with `AesOcb::l_values` (5 entries), so
        // `l.len() >= 1` is always true when this is called.
        let last_idx = l.len() - 1;
        let mut next = [0u8; AES_BLOCK_SIZE];
        ocb_double(&l[last_idx], &mut next);
        l.push(next);
    }
}

/// AES-OCB authenticated encryption (RFC 7253).
///
/// Single-pass AEAD: every 16-byte block requires exactly one AES call
/// for encryption plus one for the tag. A small cache `L_*, L_$,
/// L_0..L_4` is precomputed at construction; messages beyond 496 bytes
/// extend the L sequence lazily per-call without mutating `self`.
///
/// Implements [`AeadCipher`].
///
/// # Example
///
/// ```
/// # use openssl_crypto::symmetric::aes::AesOcb;
/// # use openssl_crypto::symmetric::AeadCipher;
/// let key = [0u8; 16];
/// let nonce = [0u8; 12];
/// let ocb = AesOcb::new(&key, 16, 12).unwrap();
///
/// let ct = ocb.seal(&nonce, b"header", b"secret message").unwrap();
/// let pt = ocb.open(&nonce, b"header", &ct).unwrap();
/// assert_eq!(pt, b"secret message");
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesOcb {
    /// Underlying AES block cipher.
    aes: Aes,
    /// Configured tag length in bytes (∈ 1..=16).
    #[zeroize(skip)]
    tag_len: usize,
    /// Configured nonce length in bytes (∈ 1..=15).
    #[zeroize(skip)]
    nonce_len: usize,
    /// `L_* = AES_K(0^128)`. Used for partial blocks and AAD tail.
    l_star: [u8; AES_BLOCK_SIZE],
    /// `L_$ = double(L_*)`. Used for the tag computation.
    l_dollar: [u8; AES_BLOCK_SIZE],
    /// `L_0..L_4 = double^{i+1}(L_*)`. Covers messages up to 496 bytes
    /// without extending; larger messages extend a local vec in
    /// [`seal`](Self::seal) / [`open`](Self::open).
    l_values: [[u8; AES_BLOCK_SIZE]; 5],
}

impl core::fmt::Debug for AesOcb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesOcb")
            .field("aes", &self.aes)
            .field("tag_len", &self.tag_len)
            .field("nonce_len", &self.nonce_len)
            .field("l_star", &"<redacted>")
            .field("l_dollar", &"<redacted>")
            .field("l_values", &"<redacted>")
            .finish()
    }
}

impl AesOcb {
    /// Construct a new AES-OCB context.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes)
    /// * `tag_len` — tag length in bytes (∈ 1..=16)
    /// * `nonce_len` — nonce length in bytes (∈ 1..=15)
    ///
    /// # Errors
    /// * [`CryptoError::Key`] — invalid AES key length
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] — invalid
    ///   tag or nonce length
    pub fn new(key: &[u8], tag_len: usize, nonce_len: usize) -> CryptoResult<Self> {
        if !(1..=OCB_MAX_TAG_LEN).contains(&tag_len) {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-OCB: invalid tag length {tag_len}; must be 1..={OCB_MAX_TAG_LEN}"
            ))));
        }
        if !(1..=OCB_MAX_NONCE_LEN).contains(&nonce_len) {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-OCB: invalid nonce length {nonce_len}; must be 1..={OCB_MAX_NONCE_LEN}"
            ))));
        }

        let aes = Aes::new(key)?;

        // L_* = AES_K(0^128).
        let mut l_star = [0u8; AES_BLOCK_SIZE];
        aes.encrypt_block_array(&mut l_star);

        // L_$ = double(L_*).
        let mut l_dollar = [0u8; AES_BLOCK_SIZE];
        ocb_double(&l_star, &mut l_dollar);

        // L_0 = double(L_$), L_i = double(L_{i-1}) for 1 ≤ i ≤ 4.
        let mut l_values = [[0u8; AES_BLOCK_SIZE]; 5];
        ocb_double(&l_dollar, &mut l_values[0]);
        for i in 1..5 {
            let prev = l_values[i - 1];
            ocb_double(&prev, &mut l_values[i]);
        }

        Ok(Self {
            aes,
            tag_len,
            nonce_len,
            l_star,
            l_dollar,
            l_values,
        })
    }

    /// Derive `Offset_0` from a nonce per RFC 7253 §4.2.
    ///
    /// Preconditions (verified by callers): `nonce.len() == self.nonce_len`.
    fn derive_offset_zero(&self, nonce: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        // Step 1: build the formatted nonce block.
        //   nonce[0]         = ((tag_len·8) mod 128) << 1
        //   nonce[1..=14]    = 0 (already zero from initializer)
        //   nonce[15-|N|]   |= 1
        //   nonce[16-|N|..] = N
        let mut nonce_block = [0u8; AES_BLOCK_SIZE];
        let tag_bits = (self.tag_len * 8) % 128;
        nonce_block[0] = u8::try_from(tag_bits).unwrap_or(0).wrapping_shl(1);
        let delim_byte = AES_BLOCK_SIZE - self.nonce_len - 1;
        let nonce_start = AES_BLOCK_SIZE - self.nonce_len;
        nonce_block[delim_byte] |= 1;
        nonce_block[nonce_start..].copy_from_slice(nonce);

        // Step 2: Ktop = AES_K(nonce_block with low 6 bits cleared).
        let mut tmp = nonce_block;
        tmp[15] &= 0xc0;
        self.aes.encrypt_block_array(&mut tmp);
        let ktop = tmp;

        // Step 3: Stretch[24] = Ktop || (Ktop[0..8] XOR Ktop[1..9]).
        let mut stretch = [0u8; 24];
        stretch[0..AES_BLOCK_SIZE].copy_from_slice(&ktop);
        for i in 0..8 {
            stretch[AES_BLOCK_SIZE + i] = ktop[i] ^ ktop[i + 1];
        }

        // Step 4: bottom ∈ 0..=63 selects a bit-offset within Stretch.
        let bottom = usize::from(nonce_block[15] & 0x3f);
        let shift_amt = bottom % 8;
        let byte_offset = bottom / 8;

        // Step 5: Offset_0 = Stretch[byte_offset..byte_offset+16] shifted
        // left by `shift_amt` bits, with the top `shift_amt` bits of the
        // next byte grafted into the low end of Offset_0[15].
        let mut offset_0 = [0u8; AES_BLOCK_SIZE];
        let mut window = [0u8; AES_BLOCK_SIZE];
        window.copy_from_slice(&stretch[byte_offset..byte_offset + AES_BLOCK_SIZE]);
        ocb_block_lshift(&window, shift_amt, &mut offset_0);
        if shift_amt > 0 {
            let shift_u32 = u32::try_from(shift_amt).unwrap_or(0);
            let inv_shift = 8u32.saturating_sub(shift_u32);
            // mask = 0xff << (8 - shift) keeps the top `shift` bits of
            // the next byte, which are then shifted into the low
            // `shift` bits of Offset_0[15].
            let hi_mask: u8 = 0xff_u8.wrapping_shl(inv_shift);
            let trailing = stretch[byte_offset + AES_BLOCK_SIZE] & hi_mask;
            offset_0[15] |= trailing.wrapping_shr(inv_shift);
        }

        offset_0
    }

    /// Compute `Sum` = OCB-HASH over AAD (RFC 7253 §4.1).
    ///
    /// Does not mutate `self`; reseeds its internal offset-AAD chain to
    /// zero on every call.
    fn process_aad(&self, aad: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        let mut sum = [0u8; AES_BLOCK_SIZE];
        let mut offset = [0u8; AES_BLOCK_SIZE];
        let num_blocks = aad.len() / AES_BLOCK_SIZE;
        let last_len = aad.len() % AES_BLOCK_SIZE;

        // Lazy-extend L for large AAD (> 496 bytes, rare but legal).
        let mut l_vec: Vec<[u8; AES_BLOCK_SIZE]> = self.l_values.to_vec();

        for i in 1..=num_blocks {
            let ntz = usize::try_from(i.trailing_zeros()).unwrap_or(0);
            ocb_extend_l(&mut l_vec, ntz);
            let l = &l_vec[ntz];
            // Offset_aad ← Offset_aad XOR L_{ntz(i)}.
            for k in 0..AES_BLOCK_SIZE {
                offset[k] ^= l[k];
            }
            // tmp = A_i XOR Offset_aad.
            let mut tmp = [0u8; AES_BLOCK_SIZE];
            tmp.copy_from_slice(&aad[(i - 1) * AES_BLOCK_SIZE..i * AES_BLOCK_SIZE]);
            for k in 0..AES_BLOCK_SIZE {
                tmp[k] ^= offset[k];
            }
            // Sum ← Sum XOR AES_K(tmp).
            self.aes.encrypt_block_array(&mut tmp);
            for k in 0..AES_BLOCK_SIZE {
                sum[k] ^= tmp[k];
            }
            tmp.zeroize();
        }

        if last_len > 0 {
            // Offset_aad ← Offset_aad XOR L_*.
            for (o, l) in offset.iter_mut().zip(self.l_star.iter()) {
                *o ^= *l;
            }
            // tmp = (A_* || 0x80 || zeros) XOR Offset_aad.
            let mut tmp = [0u8; AES_BLOCK_SIZE];
            tmp[..last_len].copy_from_slice(&aad[num_blocks * AES_BLOCK_SIZE..]);
            tmp[last_len] = 0x80;
            for k in 0..AES_BLOCK_SIZE {
                tmp[k] ^= offset[k];
            }
            self.aes.encrypt_block_array(&mut tmp);
            for k in 0..AES_BLOCK_SIZE {
                sum[k] ^= tmp[k];
            }
            tmp.zeroize();
        }

        offset.zeroize();
        sum
    }

    /// Encrypt `plaintext` and authenticate `(aad, ciphertext)` under
    /// `nonce`.
    ///
    /// Returns `ciphertext || tag` where `ciphertext.len() ==
    /// plaintext.len()` and `tag.len() == self.tag_len`.
    ///
    /// # Errors
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] if the
    ///   nonce length does not match the configured `nonce_len`.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if nonce.len() != self.nonce_len {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-OCB nonce must be {} bytes, got {}",
                self.nonce_len,
                nonce.len()
            ))));
        }

        let mut offset = self.derive_offset_zero(nonce);
        let sum = self.process_aad(aad);
        let mut checksum = [0u8; AES_BLOCK_SIZE];

        let num_blocks = plaintext.len() / AES_BLOCK_SIZE;
        let last_len = plaintext.len() % AES_BLOCK_SIZE;

        let mut output = vec![0u8; plaintext.len() + self.tag_len];

        // Lazy-extend L for messages > 496 bytes.
        let mut l_vec: Vec<[u8; AES_BLOCK_SIZE]> = self.l_values.to_vec();

        // Full-block encrypt loop.
        for i in 1..=num_blocks {
            let ntz = usize::try_from(i.trailing_zeros()).unwrap_or(0);
            ocb_extend_l(&mut l_vec, ntz);
            let l = &l_vec[ntz];
            // Offset ← Offset XOR L_{ntz(i)}.
            for k in 0..AES_BLOCK_SIZE {
                offset[k] ^= l[k];
            }
            let block_start = (i - 1) * AES_BLOCK_SIZE;
            let block_end = block_start + AES_BLOCK_SIZE;
            let mut tmp = [0u8; AES_BLOCK_SIZE];
            tmp.copy_from_slice(&plaintext[block_start..block_end]);
            // Checksum ← Checksum XOR P_i.
            for k in 0..AES_BLOCK_SIZE {
                checksum[k] ^= tmp[k];
            }
            // C_i = Offset XOR AES_K(P_i XOR Offset).
            for k in 0..AES_BLOCK_SIZE {
                tmp[k] ^= offset[k];
            }
            self.aes.encrypt_block_array(&mut tmp);
            for k in 0..AES_BLOCK_SIZE {
                tmp[k] ^= offset[k];
            }
            output[block_start..block_end].copy_from_slice(&tmp);
            tmp.zeroize();
        }

        // Partial-block handling.
        if last_len > 0 {
            // Offset_* = Offset XOR L_*.
            for (o, l) in offset.iter_mut().zip(self.l_star.iter()) {
                *o ^= *l;
            }
            // Pad = AES_K(Offset_*).
            let mut pad = offset;
            self.aes.encrypt_block_array(&mut pad);
            // C_* = P_* XOR Pad[0..last_len].
            let pt_offset = num_blocks * AES_BLOCK_SIZE;
            for idx in 0..last_len {
                output[pt_offset + idx] = plaintext[pt_offset + idx] ^ pad[idx];
            }
            // Checksum ← Checksum XOR (P_* || 0x80 || zeros).
            let mut padded = [0u8; AES_BLOCK_SIZE];
            padded[..last_len].copy_from_slice(&plaintext[pt_offset..]);
            padded[last_len] = 0x80;
            for k in 0..AES_BLOCK_SIZE {
                checksum[k] ^= padded[k];
            }
            pad.zeroize();
            padded.zeroize();
            // `offset` is now Offset_* — used in tag calculation below.
        }

        // Tag = AES_K(Checksum XOR Offset_final XOR L_$) XOR Sum,
        // truncated to self.tag_len bytes.
        let mut tag_block = [0u8; AES_BLOCK_SIZE];
        for k in 0..AES_BLOCK_SIZE {
            tag_block[k] = checksum[k] ^ offset[k] ^ self.l_dollar[k];
        }
        self.aes.encrypt_block_array(&mut tag_block);
        for k in 0..AES_BLOCK_SIZE {
            tag_block[k] ^= sum[k];
        }
        output[plaintext.len()..].copy_from_slice(&tag_block[..self.tag_len]);

        // Scrub transient values before returning.
        offset.zeroize();
        checksum.zeroize();
        tag_block.zeroize();

        Ok(output)
    }

    /// Decrypt `ciphertext_with_tag` and verify authenticity against
    /// `(aad, nonce)`.
    ///
    /// On success returns the plaintext. On authentication failure
    /// returns [`CryptoError::Verification`] and never exposes decrypted
    /// data — the plaintext buffer is zeroized before the error
    /// returns.
    ///
    /// # Errors
    /// * [`CryptoError::Common(CommonError::InvalidArgument)`] — nonce
    ///   length mismatch or input shorter than `tag_len`
    /// * [`CryptoError::Verification`] — authentication tag mismatch
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce.len() != self.nonce_len {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-OCB nonce must be {} bytes, got {}",
                self.nonce_len,
                nonce.len()
            ))));
        }
        if ciphertext_with_tag.len() < self.tag_len {
            return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                "AES-OCB open: input too short ({} < {})",
                ciphertext_with_tag.len(),
                self.tag_len
            ))));
        }

        let split_at = ciphertext_with_tag.len() - self.tag_len;
        let (ct_in, tag_in) = ciphertext_with_tag.split_at(split_at);

        let mut offset = self.derive_offset_zero(nonce);
        let sum = self.process_aad(aad);
        let mut checksum = [0u8; AES_BLOCK_SIZE];

        let num_blocks = ct_in.len() / AES_BLOCK_SIZE;
        let last_len = ct_in.len() % AES_BLOCK_SIZE;

        let mut plaintext = vec![0u8; ct_in.len()];
        let mut l_vec: Vec<[u8; AES_BLOCK_SIZE]> = self.l_values.to_vec();

        // Full-block decrypt loop.
        for i in 1..=num_blocks {
            let ntz = usize::try_from(i.trailing_zeros()).unwrap_or(0);
            ocb_extend_l(&mut l_vec, ntz);
            let l = &l_vec[ntz];
            // Offset ← Offset XOR L_{ntz(i)}.
            for k in 0..AES_BLOCK_SIZE {
                offset[k] ^= l[k];
            }
            let block_start = (i - 1) * AES_BLOCK_SIZE;
            let block_end = block_start + AES_BLOCK_SIZE;
            let mut tmp = [0u8; AES_BLOCK_SIZE];
            tmp.copy_from_slice(&ct_in[block_start..block_end]);
            // P_i = Offset XOR AES^-1_K(C_i XOR Offset).
            for k in 0..AES_BLOCK_SIZE {
                tmp[k] ^= offset[k];
            }
            self.aes.decrypt_block_array(&mut tmp);
            for k in 0..AES_BLOCK_SIZE {
                tmp[k] ^= offset[k];
            }
            // Checksum ← Checksum XOR P_i.
            for k in 0..AES_BLOCK_SIZE {
                checksum[k] ^= tmp[k];
            }
            plaintext[block_start..block_end].copy_from_slice(&tmp);
            tmp.zeroize();
        }

        // Partial-block handling.
        //
        // Asymmetry #1: Pad is derived via ENCRYPT (not decrypt) — the
        // keystream that XORs ciphertext back to plaintext is produced
        // symmetrically in both directions.
        //
        // Asymmetry #2: Checksum accumulates over the RECOVERED
        // plaintext (`plaintext`), not the ciphertext (`ct_in`).
        if last_len > 0 {
            for (o, l) in offset.iter_mut().zip(self.l_star.iter()) {
                *o ^= *l;
            }
            let mut pad = offset;
            self.aes.encrypt_block_array(&mut pad);
            let ct_offset = num_blocks * AES_BLOCK_SIZE;
            for idx in 0..last_len {
                plaintext[ct_offset + idx] = ct_in[ct_offset + idx] ^ pad[idx];
            }
            // Checksum ← Checksum XOR (P_* || 0x80 || zeros) — uses
            // recovered plaintext.
            let mut padded = [0u8; AES_BLOCK_SIZE];
            padded[..last_len].copy_from_slice(&plaintext[ct_offset..]);
            padded[last_len] = 0x80;
            for k in 0..AES_BLOCK_SIZE {
                checksum[k] ^= padded[k];
            }
            pad.zeroize();
            padded.zeroize();
        }

        // Compute expected tag.
        let mut tag_block = [0u8; AES_BLOCK_SIZE];
        for k in 0..AES_BLOCK_SIZE {
            tag_block[k] = checksum[k] ^ offset[k] ^ self.l_dollar[k];
        }
        self.aes.encrypt_block_array(&mut tag_block);
        for k in 0..AES_BLOCK_SIZE {
            tag_block[k] ^= sum[k];
        }

        // Constant-time tag comparison. We MUST scrub all secrets
        // before returning, whether on success or failure.
        let tag_ok = bool::from(tag_block[..self.tag_len].ct_eq(tag_in));

        offset.zeroize();
        checksum.zeroize();
        tag_block.zeroize();

        if !tag_ok {
            plaintext.zeroize();
            return Err(CryptoError::Verification(
                "AES-OCB authentication tag mismatch".to_string(),
            ));
        }

        Ok(plaintext)
    }
}

impl AeadCipher for AesOcb {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        AesOcb::seal(self, nonce, aad, plaintext)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        AesOcb::open(self, nonce, aad, ciphertext_with_tag)
    }

    fn nonce_length(&self) -> usize {
        self.nonce_len
    }

    fn tag_length(&self) -> usize {
        self.tag_len
    }

    fn algorithm(&self) -> CipherAlgorithm {
        self.aes.algorithm()
    }
}


// =============================================================================
// AES-SIV — Synthetic Initialization Vector (RFC 5297)
// =============================================================================
//
// AES-SIV is a deterministic authenticated encryption mode. Unlike GCM/CCM
// which require a unique nonce per invocation to be secure, SIV is
// misuse-resistant: repeating a (key, nonce, associated data, plaintext)
// tuple reveals that identical plaintexts were encrypted, but does not
// compromise confidentiality of distinct plaintexts.
//
// The key K is split into two halves K1 (CMAC key) and K2 (CTR key). For
// AES-128-SIV the total key length is 32 bytes, for AES-192-SIV 48 bytes,
// and for AES-256-SIV 64 bytes.
//
// ## Algorithm — Seal
//
// 1. V = S2V(K1, aad, nonce, plaintext)    // 128-bit synthetic IV
// 2. Q = V with bits 63 and 127 cleared    // initial counter block
// 3. C = AES-CTR-K2(Q) XOR plaintext        // encryption
// 4. Output: V || C
//
// ## Algorithm — Open
//
// 1. Split input into V (first 16 bytes) and C (remainder).
// 2. Q = V with bits 63 and 127 cleared
// 3. P = AES-CTR-K2(Q) XOR C                // decryption
// 4. V' = S2V(K1, aad, nonce, P)
// 5. If V' != V (constant-time compare): zeroize P, reject; else return P.
//
// ## Algorithm — S2V(K, S1, ..., Sn)
//
// 1. D = CMAC(K, <zero>)
// 2. For i = 1..n-1:  D = dbl(D) XOR CMAC(K, Si)
// 3. If |Sn| >= 128 bits:  T = Sn with last 128 bits XOR D;  V = CMAC(K, T)
//    Else:                T = dbl(D) XOR pad(Sn);           V = CMAC(K, T)
//
// ## Source mapping
//
// - `crypto/modes/siv128.c` — complete C reference (394 lines)
// - RFC 5297 §2.4 for the S2V construction
// - NIST SP 800-38B for CMAC (subkey derivation, padding)

/// AES-SIV tag length (fixed at 128 bits).
const SIV_TAG_LEN: usize = AES_BLOCK_SIZE;

/// Doubles a 128-bit block modulo the GF(2^128) polynomial x^128 + x^7 + x^2 + x + 1.
///
/// This is the `dbl` operation used by both CMAC subkey derivation and SIV S2V.
/// Input interpreted as a 128-bit integer in big-endian (byte 0 is MSB).
/// Shifts left by 1 bit; if the top bit was 1, XORs the reduction polynomial
/// 0x87 into the LSB (byte 15).
///
/// Constant-time: the reduction mask is derived from the top bit via arithmetic
/// negation, avoiding data-dependent branches.
fn siv_block_dbl(input: &[u8; AES_BLOCK_SIZE], output: &mut [u8; AES_BLOCK_SIZE]) {
    // Constant-time reduction mask: 0x87 if top bit set, 0x00 otherwise.
    let top_bit = (input[0] & 0x80) >> 7;
    let mask = 0u8.wrapping_sub(top_bit) & 0x87;

    // Big-endian 1-bit left shift: propagate carry from less-significant bytes
    // into more-significant ones.
    let mut carry: u8 = 0;
    for i in (0..AES_BLOCK_SIZE).rev() {
        let new_carry = (input[i] & 0x80) >> 7;
        output[i] = (input[i] << 1) | carry;
        carry = new_carry;
    }
    // Apply reduction on the LSB byte.
    output[AES_BLOCK_SIZE - 1] ^= mask;
}

/// One-shot CMAC-AES computation (NIST SP 800-38B).
///
/// Produces a 128-bit tag authenticating `data` under the AES key `aes`.
/// Returns `[u8; AES_BLOCK_SIZE]` containing the tag.
///
/// ## Subkey Derivation
///
/// L  = AES-K(0^128)
/// K1 = dbl(L)
/// K2 = dbl(K1)
///
/// ## Tag Computation
///
/// Split `data` into 128-bit blocks `M_1`, `M_2`, ..., `M_n`.
/// - If `data` is empty or the final block is incomplete: pad the last
///   block with `0x80 || 0^*` to 128 bits, then XOR with K2.
/// - If the final block is a complete 128 bits: XOR with K1.
///
/// State = 0; for each block (including the masked last block):
///   State = AES-K(State XOR `M_i`)
///
/// The final State is the tag.
fn aes_cmac(aes: &Aes, data: &[u8]) -> [u8; AES_BLOCK_SIZE] {
    // Step 1: Derive subkeys K1, K2.
    let mut l_block = [0u8; AES_BLOCK_SIZE];
    aes.encrypt_block_array(&mut l_block);

    let mut k1 = [0u8; AES_BLOCK_SIZE];
    siv_block_dbl(&l_block, &mut k1);

    let mut k2 = [0u8; AES_BLOCK_SIZE];
    siv_block_dbl(&k1, &mut k2);

    // Step 2: Process full intermediate blocks (all except the last block).
    // The last block is always masked with K1 or K2 depending on completeness.
    let full_blocks = data.len() / AES_BLOCK_SIZE;
    let tail_len = data.len() % AES_BLOCK_SIZE;
    // Last block is complete if data is non-empty and evenly divisible.
    let last_is_complete = tail_len == 0 && !data.is_empty();
    // Number of "intermediate" full blocks (excludes the final block).
    let intermediate_count = if last_is_complete {
        full_blocks - 1
    } else {
        full_blocks
    };

    let mut state = [0u8; AES_BLOCK_SIZE];
    for i in 0..intermediate_count {
        let start = i * AES_BLOCK_SIZE;
        for j in 0..AES_BLOCK_SIZE {
            state[j] ^= data[start + j];
        }
        aes.encrypt_block_array(&mut state);
    }

    // Step 3: Build the masked final block.
    let mut last = [0u8; AES_BLOCK_SIZE];
    if last_is_complete {
        // Final block is a complete 128 bits: XOR with K1.
        let start = intermediate_count * AES_BLOCK_SIZE;
        last.copy_from_slice(&data[start..start + AES_BLOCK_SIZE]);
        for j in 0..AES_BLOCK_SIZE {
            last[j] ^= k1[j];
        }
    } else {
        // Final block is incomplete (or empty data): pad with 10* then XOR K2.
        let start = intermediate_count * AES_BLOCK_SIZE;
        last[..tail_len].copy_from_slice(&data[start..start + tail_len]);
        last[tail_len] = 0x80;
        for j in 0..AES_BLOCK_SIZE {
            last[j] ^= k2[j];
        }
    }

    // Step 4: Final CMAC step — State = AES-K(State XOR last).
    for j in 0..AES_BLOCK_SIZE {
        state[j] ^= last[j];
    }
    aes.encrypt_block_array(&mut state);

    // Zeroize subkeys and intermediates.
    l_block.zeroize();
    k1.zeroize();
    k2.zeroize();
    last.zeroize();

    state
}

/// AES-SIV authenticated encryption (RFC 5297, misuse-resistant AEAD).
///
/// AES-SIV splits the user key into two halves: K1 drives the CMAC-based
/// S2V construction producing the synthetic IV (SIV), and K2 drives
/// AES-CTR encryption using the SIV as the initial counter. Output format
/// is `V || C` where V is the 16-byte synthetic IV (acting as both tag
/// and IV) and C is the ciphertext of the same length as the plaintext.
///
/// Total key length must be 32 (AES-128), 48 (AES-192), or 64 (AES-256)
/// bytes. Tag length is always 128 bits.
///
/// Source: `crypto/modes/siv128.c`.
///
/// ## Example
///
/// ```
/// use openssl_crypto::symmetric::aes::AesSiv;
///
/// let key = [0x42u8; 32];             // AES-128-SIV key (32 bytes total)
/// let nonce = [0u8; 16];
/// let aad = b"associated data";
/// let plaintext = b"confidential";
///
/// let siv = AesSiv::new(&key).unwrap();
/// let ciphertext = siv.seal(&nonce, aad, plaintext).unwrap();
/// let recovered = siv.open(&nonce, aad, &ciphertext).unwrap();
/// assert_eq!(recovered, plaintext);
/// ```
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct AesSiv {
    /// K1 — AES key for CMAC (S2V) operations.
    mac_key: Aes,
    /// K2 — AES key for CTR-mode encryption.
    ctr_key: Aes,
}

impl AesSiv {
    /// Constructs a new AES-SIV cipher from a combined key.
    ///
    /// The key is split into two equal halves: the first half becomes K1
    /// (CMAC/S2V key), the second half becomes K2 (CTR key).
    ///
    /// Valid total key lengths: 32 bytes (AES-128), 48 bytes (AES-192),
    /// or 64 bytes (AES-256).
    ///
    /// ## Errors
    ///
    /// Returns `CryptoError::Key` if the key length is not one of the three
    /// valid sizes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let half_key_len = match key.len() {
            32 => 16,
            48 => 24,
            64 => 32,
            other => {
                return Err(CryptoError::Key(format!(
                    "AES-SIV: invalid key length {other}; expected 32, 48, or 64 bytes"
                )));
            }
        };
        let mac_key = Aes::new(&key[..half_key_len])?;
        let ctr_key = Aes::new(&key[half_key_len..])?;
        Ok(Self { mac_key, ctr_key })
    }

    /// Computes the 128-bit synthetic IV V = S2V(K1, aad, nonce, plaintext).
    ///
    /// Follows RFC 5297 §2.4 with the AD vector ordered as [aad, nonce] and
    /// plaintext as the final (distinguished) input.
    ///
    /// The implementation treats both `aad` and `nonce` as AD components
    /// processed via the `D = dbl(D) XOR CMAC(K1, AD_i)` loop. The plaintext
    /// is the final input to S2V, receiving the special `xorend`/`pad` treatment.
    fn s2v(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        // Step 1: D = CMAC(K1, <zero>).
        let zero_block = [0u8; AES_BLOCK_SIZE];
        let mut d = aes_cmac(&self.mac_key, &zero_block);

        // Step 2: Process AD components (aad, nonce). Each iteration:
        //   D = dbl(D) XOR CMAC(K1, AD_i)
        let mut d_tmp = [0u8; AES_BLOCK_SIZE];

        // -- AAD --
        siv_block_dbl(&d, &mut d_tmp);
        let aad_mac = aes_cmac(&self.mac_key, aad);
        for j in 0..AES_BLOCK_SIZE {
            d[j] = d_tmp[j] ^ aad_mac[j];
        }

        // -- Nonce --
        siv_block_dbl(&d, &mut d_tmp);
        let nonce_mac = aes_cmac(&self.mac_key, nonce);
        for j in 0..AES_BLOCK_SIZE {
            d[j] = d_tmp[j] ^ nonce_mac[j];
        }

        // Step 3: Finalize with plaintext (treated as the "last" S_n).
        let v = if plaintext.len() >= AES_BLOCK_SIZE {
            // Case: |S_n| >= 128 bits. Construct T = prefix || (last16 XOR D),
            // then V = CMAC(K1, T).
            let split_point = plaintext.len() - AES_BLOCK_SIZE;
            let mut mac_buffer = Vec::with_capacity(plaintext.len());
            mac_buffer.extend_from_slice(&plaintext[..split_point]);
            // Append last 16 bytes XORed with D.
            for j in 0..AES_BLOCK_SIZE {
                mac_buffer.push(plaintext[split_point + j] ^ d[j]);
            }
            let result = aes_cmac(&self.mac_key, &mac_buffer);
            mac_buffer.zeroize();
            result
        } else {
            // Case: |S_n| < 128 bits. Construct T = dbl(D) XOR pad(S_n),
            // then V = CMAC(K1, T). pad(x) = x || 0x80 || 0^*.
            let mut padded = [0u8; AES_BLOCK_SIZE];
            padded[..plaintext.len()].copy_from_slice(plaintext);
            padded[plaintext.len()] = 0x80;
            // D' = dbl(D)
            let mut d_doubled = [0u8; AES_BLOCK_SIZE];
            siv_block_dbl(&d, &mut d_doubled);
            // T = D' XOR pad(S_n)
            for j in 0..AES_BLOCK_SIZE {
                padded[j] ^= d_doubled[j];
            }
            let result = aes_cmac(&self.mac_key, &padded);
            padded.zeroize();
            d_doubled.zeroize();
            result
        };

        // Zeroize sensitive intermediates.
        d.zeroize();
        d_tmp.zeroize();

        v
    }

    /// Seals (authenticates and encrypts) `plaintext` with the given
    /// `nonce` and `aad`, producing `V || C` where V is the 128-bit
    /// synthetic IV and C is the ciphertext.
    ///
    /// The output length is `plaintext.len() + 16`.
    ///
    /// AES-SIV accepts nonces of any length; the caller is responsible for
    /// uniqueness if misuse-resistance is not desired.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Step 1: Compute V = S2V(K1, aad, nonce, plaintext).
        let v = self.s2v(aad, nonce, plaintext);

        // Step 2: Q = V with bits 63 and 127 cleared.
        // Per RFC 5297 §2.5: "the 31st and 63rd bits (where the rightmost is
        // the 0th bit) of the counter are zeroed prior to use by CTR".
        // In 128-bit big-endian layout: bit 31 is MSB of byte 12; bit 63 is
        // MSB of byte 8. Clearing each via AND with 0x7f.
        let mut q = v;
        q[8] &= 0x7f;
        q[12] &= 0x7f;

        // Step 3: C = AES-CTR-K2(Q) XOR plaintext.
        let ciphertext = ctr_encrypt(&self.ctr_key, plaintext, &q)?;

        // Zeroize the counter (it shares sensitivity with V in that the
        // top bits are cleared; we rely on `v` being plaintext-authenticating).
        q.zeroize();

        // Output: V || C.
        let mut out = Vec::with_capacity(SIV_TAG_LEN + ciphertext.len());
        out.extend_from_slice(&v);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens (decrypts and verifies) `V || C`, returning the plaintext if
    /// authentication succeeds.
    ///
    /// ## Errors
    ///
    /// - `CryptoError::Verification` if the input is shorter than the 16-byte
    ///   tag, or if authentication fails (recomputed V' != received V).
    ///
    /// On authentication failure the recovered plaintext buffer is zeroized
    /// before returning the error, ensuring no partial plaintext is leaked.
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext_with_tag.len() < SIV_TAG_LEN {
            return Err(CryptoError::Verification(format!(
                "AES-SIV open: input too short ({} < {})",
                ciphertext_with_tag.len(),
                SIV_TAG_LEN
            )));
        }

        // Format: V || C.
        let (v_in, c_in) = ciphertext_with_tag.split_at(SIV_TAG_LEN);

        // Step 1: Q = V with bits 63 and 127 cleared.
        let mut q = [0u8; AES_BLOCK_SIZE];
        q.copy_from_slice(v_in);
        q[8] &= 0x7f;
        q[12] &= 0x7f;

        // Step 2: Decrypt P = AES-CTR-K2(Q) XOR C.
        // CTR is symmetric, so decryption is the same operation as encryption.
        let mut plaintext = ctr_encrypt(&self.ctr_key, c_in, &q)?;

        q.zeroize();

        // Step 3: Recompute V' = S2V(K1, aad, nonce, P).
        let v_prime = self.s2v(aad, nonce, &plaintext);

        // Step 4: Constant-time compare V' == V.
        let tag_ok = bool::from(v_prime.ct_eq(v_in));

        if !tag_ok {
            // Zeroize recovered plaintext on authentication failure to
            // prevent partial plaintext leakage.
            plaintext.zeroize();
            return Err(CryptoError::Verification(
                "AES-SIV authentication tag mismatch".to_string(),
            ));
        }

        Ok(plaintext)
    }

    /// Returns the tag length in bytes (fixed at 16 for AES-SIV).
    pub fn tag_length(&self) -> usize {
        SIV_TAG_LEN
    }
}

impl AeadCipher for AesSiv {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        AesSiv::seal(self, nonce, aad, plaintext)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext_with_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        AesSiv::open(self, nonce, aad, ciphertext_with_tag)
    }

    fn nonce_length(&self) -> usize {
        // AES-SIV accepts nonces of any length; 16 bytes is the conventional
        // default and what the provider contract reports.
        AES_BLOCK_SIZE
    }

    fn tag_length(&self) -> usize {
        SIV_TAG_LEN
    }

    fn algorithm(&self) -> CipherAlgorithm {
        // CipherAlgorithm enum has no dedicated SIV variant; delegate to the
        // underlying AES-{128,192,256} marker based on the MAC key's size.
        self.mac_key.algorithm()
    }
}


// =============================================================================
// Free-function AES mode wrappers
// =============================================================================
//
// These helpers compose `Aes::new()` with the generic block-mode engines
// exported from the parent `symmetric` module (`cbc_encrypt`, `ctr_encrypt`,
// `cfb_encrypt`, `ofb_encrypt`). They are thin convenience layers for
// callers who do not want to explicitly construct an `Aes` instance.
//
// Each function validates the key length (16/24/32 bytes) by delegating to
// `Aes::new`, and validates the IV length via the engine's internal checks.
//
// Source mapping:
// - `crypto/aes/aes_cbc.c`  — wrapper calling AES_encrypt/AES_decrypt
// - `crypto/aes/aes_cfb.c`  — wrapper around CRYPTO_cfb128_encrypt
// - `crypto/aes/aes_ofb.c`  — wrapper around CRYPTO_ofb128_encrypt
// - `crypto/modes/cbc128.c` — generic CBC engine
// - `crypto/modes/ctr128.c` — generic CTR engine
// - `crypto/modes/cfb128.c` — generic CFB engine (8-bit and 128-bit variants)
// - `crypto/modes/ofb128.c` — generic OFB engine

/// AES-CBC encryption with PKCS#7 padding.
///
/// Constructs an `Aes` from `key` (16, 24, or 32 bytes), then delegates to
/// the generic `cbc_encrypt` engine with `CipherDirection::Encrypt`.
///
/// ## Parameters
///
/// - `key`: AES key, 16/24/32 bytes.
/// - `iv`:  16-byte IV (AES block size).
/// - `plaintext`: Arbitrary-length plaintext; the engine applies PKCS#7 padding.
///
/// ## Returns
///
/// Ciphertext whose length is a multiple of 16 bytes (a full padding block is
/// appended when the input is already block-aligned).
///
/// ## Errors
///
/// - `CryptoError::Key` if the key length is invalid.
/// - Propagates any engine errors.
pub fn aes_cbc_encrypt(
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let aes = Aes::new(key)?;
    cbc_encrypt(&aes, plaintext, iv, CipherDirection::Encrypt)
}

/// AES-CBC decryption with PKCS#7 unpadding.
///
/// Constructs an `Aes` from `key` and delegates to the generic `cbc_encrypt`
/// engine with `CipherDirection::Decrypt`.
///
/// ## Parameters
///
/// - `key`: AES key, 16/24/32 bytes.
/// - `iv`:  16-byte IV (must match the IV used for encryption).
/// - `ciphertext`: Block-aligned ciphertext (multiple of 16 bytes).
///
/// ## Returns
///
/// Plaintext with PKCS#7 padding removed.
///
/// ## Errors
///
/// - `CryptoError::Key` if the key length is invalid.
/// - `CryptoError::Encoding` if padding is malformed (from the engine).
/// - Propagates any engine errors.
pub fn aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let aes = Aes::new(key)?;
    cbc_encrypt(&aes, ciphertext, iv, CipherDirection::Decrypt)
}

/// AES-CTR encryption / decryption.
///
/// CTR mode is symmetric — the same operation performs both encryption
/// and decryption. Constructs an `Aes` from `key` and delegates to the
/// generic `ctr_encrypt` engine.
///
/// ## Parameters
///
/// - `key`:   AES key, 16/24/32 bytes.
/// - `nonce`: 16-byte initial counter block. For compatibility with common
///            deployments (e.g., TLS record layer), callers typically split
///            the 128-bit block into a fixed nonce prefix and a monotonically
///            incrementing counter suffix before invoking this function.
/// - `data`:  Arbitrary-length input (plaintext when encrypting, ciphertext
///            when decrypting).
///
/// ## Returns
///
/// Output buffer with `data.len()` bytes.
///
/// ## Errors
///
/// - `CryptoError::Key` if the key length is invalid.
/// - Propagates any engine errors.
pub fn aes_ctr_encrypt(
    key: &[u8],
    nonce: &[u8; AES_BLOCK_SIZE],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let aes = Aes::new(key)?;
    ctr_encrypt(&aes, data, nonce)
}

/// AES-CFB encryption (128-bit feedback width).
///
/// Constructs an `Aes` from `key` and delegates to the generic `cfb_encrypt`
/// engine with `CipherDirection::Encrypt`.
///
/// CFB is a self-synchronizing stream mode; no padding is required and
/// ciphertext length equals plaintext length.
///
/// ## Parameters
///
/// - `key`:       AES key, 16/24/32 bytes.
/// - `iv`:        16-byte IV (initial feedback register).
/// - `plaintext`: Arbitrary-length plaintext.
///
/// ## Errors
///
/// - `CryptoError::Key` if the key length is invalid.
/// - Propagates any engine errors.
pub fn aes_cfb_encrypt(
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let aes = Aes::new(key)?;
    cfb_encrypt(&aes, plaintext, iv, CipherDirection::Encrypt)
}

/// AES-OFB encryption / decryption.
///
/// OFB is symmetric — the same operation performs both encryption and
/// decryption (the IV is used to generate a keystream `XORed` with the input).
/// Constructs an `Aes` from `key` and delegates to the generic `ofb_encrypt`
/// engine.
///
/// ## Parameters
///
/// - `key`:  AES key, 16/24/32 bytes.
/// - `iv`:   16-byte IV (initial feedback register).
/// - `data`: Arbitrary-length input (plaintext when encrypting, ciphertext
///           when decrypting).
///
/// ## Errors
///
/// - `CryptoError::Key` if the key length is invalid.
/// - Propagates any engine errors.
pub fn aes_ofb_encrypt(
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let aes = Aes::new(key)?;
    ofb_encrypt(&aes, data, iv)
}



// =============================================================================
// AES Key Wrap / Key Unwrap (RFC 3394 and RFC 5649)
// -----------------------------------------------------------------------------
// Source: `crypto/modes/wrap128.c` (~339 LoC).
//
// Two algorithms are implemented here:
//
//   * RFC 3394 — AES Key Wrap. Wraps a key consisting of `n >= 2` 64-bit
//     semiblocks. Produces (n + 1) semiblocks of ciphertext using a fixed
//     six-round Feistel-like schedule.
//
//   * RFC 5649 — AES Key Wrap with Padding. Extends RFC 3394 to cover
//     arbitrary-length plaintexts (1 octet and above) by prepending an
//     Alternative Initial Value (AIV) that encodes the plaintext length
//     ("Message Length Indicator" / MLI) and padding the plaintext with
//     zero octets to the next 64-bit boundary.
//
// Both pairs (wrap/unwrap and wrap_pad/unwrap_pad) return
// [`CryptoResult<Vec<u8>>`] per Rule R5 — there are no sentinel return
// values. On unwrap-time authentication failure (IV mismatch, AIV magic
// mismatch, MLI out of range, or non-zero padding bytes) the recovered
// plaintext buffer is wiped with `zeroize` before returning
// [`CryptoError::Verification`]. All IV / AIV magic comparisons go
// through [`subtle::ConstantTimeEq`] to defeat timing side channels.
// =============================================================================

// RFC 3394 default IV and RFC 5649 AIV magic are declared once near the
// module header (`DEFAULT_IV` at ~line 71, `DEFAULT_AIV` at ~line 76) and
// reused by the wrap/unwrap helpers below.

/// Size of a single RFC 3394 semiblock in bytes (64 bits).
const AES_WRAP_SEMIBLOCK: usize = 8;

/// Input-size limit matching upstream C (`CRYPTO128_WRAP_MAX`).
///
/// Far larger than anything used in practice but guarantees the wrap
/// counter never exceeds the 32-bit range that the algorithm actually XORs
/// into the `A` register.
const CRYPTO128_WRAP_MAX: usize = 1usize << 31;

/// RFC 3394 Key Wrap — see section 2.2.1.
///
/// Wraps `plaintext` (an integer multiple of eight octets, at least two
/// semiblocks) under `kek` with the supplied 64-bit Initial Value. The
/// returned ciphertext is exactly eight bytes longer than the plaintext.
///
/// # Parameters
///
/// * `kek` — Key Encryption Key. Must be 16, 24, or 32 bytes.
/// * `iv`  — 64-bit Initial Value. For interoperability with callers that
///   do not specify an IV, pass [`&DEFAULT_IV`](DEFAULT_IV).
/// * `plaintext` — data to wrap. Length must be a positive multiple of
///   eight bytes and at least 16 bytes (i.e. at least two 64-bit
///   semiblocks).
///
/// # Errors
///
/// Returns [`CryptoError::Key`] when the KEK length is invalid, the
/// plaintext length is not a valid multiple of eight, or the plaintext is
/// shorter than 16 bytes.
///
/// # Security
///
/// All transient state (the `A` and `B` registers) is zeroed with
/// `zeroize` before the function returns.
pub fn aes_key_wrap(
    kek: &[u8],
    iv: &[u8; AES_WRAP_SEMIBLOCK],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let inlen = plaintext.len();
    if inlen % AES_WRAP_SEMIBLOCK != 0 {
        return Err(CryptoError::Key(format!(
            "AES key wrap: plaintext length {inlen} is not a multiple of {AES_WRAP_SEMIBLOCK}"
        )));
    }
    if inlen < 2 * AES_WRAP_SEMIBLOCK {
        return Err(CryptoError::Key(format!(
            "AES key wrap: plaintext length {inlen} must be at least {} bytes (two semiblocks)",
            2 * AES_WRAP_SEMIBLOCK
        )));
    }
    if inlen > CRYPTO128_WRAP_MAX {
        return Err(CryptoError::Key(format!(
            "AES key wrap: plaintext length {inlen} exceeds maximum {CRYPTO128_WRAP_MAX}"
        )));
    }

    let aes = Aes::new(kek)?;

    // Output layout: 8-byte IV prefix followed by n encrypted semiblocks.
    let mut out = vec![0u8; inlen + AES_WRAP_SEMIBLOCK];
    out[AES_WRAP_SEMIBLOCK..].copy_from_slice(plaintext);

    // `A` — running integrity register; starts as the IV.
    let mut a = [0u8; AES_WRAP_SEMIBLOCK];
    a.copy_from_slice(iv);

    // `B` — 16-byte AES block used as scratch: B = A || R[i].
    let mut b = [0u8; AES_BLOCK_SIZE];

    // `n` — number of 64-bit semiblocks in the plaintext.
    // `n <= CRYPTO128_WRAP_MAX / 8 = 2^28`, so `n` and `t = 6 * n` both fit
    // comfortably in `u64`.
    let n = inlen / AES_WRAP_SEMIBLOCK;
    let mut t: u64 = 0;

    for _j in 0..6 {
        for i in 0..n {
            // t = (n * j) + i + 1, counted incrementally.
            t = t.wrapping_add(1);

            // Load R[i] into the low half of B; high half already holds A.
            b[..AES_WRAP_SEMIBLOCK].copy_from_slice(&a);
            let r_start = AES_WRAP_SEMIBLOCK + i * AES_WRAP_SEMIBLOCK;
            b[AES_WRAP_SEMIBLOCK..]
                .copy_from_slice(&out[r_start..r_start + AES_WRAP_SEMIBLOCK]);

            // B = AES_Encrypt_KEK(B).
            aes.encrypt_block_array(&mut b);

            // A = MSB(64, B) XOR t. t is XORed in as an 8-byte big-endian
            // value; the upper four bytes of t are always zero for
            // `n * 6 <= 6 * 2^28 = 3 * 2^29 < 2^32`, so this is equivalent
            // to the C implementation which only XORs the low four bytes.
            a.copy_from_slice(&b[..AES_WRAP_SEMIBLOCK]);
            let t_bytes = t.to_be_bytes();
            for k in 0..AES_WRAP_SEMIBLOCK {
                a[k] ^= t_bytes[k];
            }

            // R[i] = LSB(64, B).
            out[r_start..r_start + AES_WRAP_SEMIBLOCK]
                .copy_from_slice(&b[AES_WRAP_SEMIBLOCK..]);
        }
    }

    // Final: C[0] = A.
    out[..AES_WRAP_SEMIBLOCK].copy_from_slice(&a);

    // Zeroize transient state.
    a.zeroize();
    b.zeroize();

    Ok(out)
}

/// RFC 3394 raw unwrap — section 2.2.2 steps 1-2.
///
/// Runs the six-round inverse schedule and returns the recovered IV
/// together with the recovered plaintext buffer. The caller is responsible
/// for verifying the IV (and zeroizing both buffers on failure if
/// necessary). This helper is shared between [`aes_key_unwrap`] and
/// [`aes_key_unwrap_pad`].
fn aes_key_unwrap_raw(
    aes: &Aes,
    ciphertext: &[u8],
) -> CryptoResult<([u8; AES_WRAP_SEMIBLOCK], Vec<u8>)> {
    let clen = ciphertext.len();
    if clen % AES_WRAP_SEMIBLOCK != 0 {
        return Err(CryptoError::Key(format!(
            "AES key unwrap: ciphertext length {clen} is not a multiple of {AES_WRAP_SEMIBLOCK}"
        )));
    }
    if clen < 3 * AES_WRAP_SEMIBLOCK {
        return Err(CryptoError::Key(format!(
            "AES key unwrap: ciphertext length {clen} must be at least {} bytes \
             (three semiblocks = one IV + two payload)",
            3 * AES_WRAP_SEMIBLOCK
        )));
    }
    // Payload length = clen - 8. Must not exceed CRYPTO128_WRAP_MAX.
    let inlen = clen - AES_WRAP_SEMIBLOCK;
    if inlen > CRYPTO128_WRAP_MAX {
        return Err(CryptoError::Key(format!(
            "AES key unwrap: payload length {inlen} exceeds maximum {CRYPTO128_WRAP_MAX}"
        )));
    }

    let n = inlen / AES_WRAP_SEMIBLOCK;

    // Working buffer for the recovered plaintext (payload only).
    let mut out = vec![0u8; inlen];
    out.copy_from_slice(&ciphertext[AES_WRAP_SEMIBLOCK..]);

    // `A` — running integrity register; starts as C[0].
    let mut a = [0u8; AES_WRAP_SEMIBLOCK];
    a.copy_from_slice(&ciphertext[..AES_WRAP_SEMIBLOCK]);

    // `B` — scratch block.
    let mut b = [0u8; AES_BLOCK_SIZE];

    // t counts down from 6 * n to 1 (inclusive).
    let mut t: u64 = 6u64 * (n as u64);

    for _j in 0..6 {
        // Process semiblocks in reverse order: R[n-1] first, then R[n-2], …
        for i in (0..n).rev() {
            // A ^= t (big-endian, 8 bytes).
            let t_bytes = t.to_be_bytes();
            for k in 0..AES_WRAP_SEMIBLOCK {
                a[k] ^= t_bytes[k];
            }

            // B = A || R[i].
            b[..AES_WRAP_SEMIBLOCK].copy_from_slice(&a);
            let r_start = i * AES_WRAP_SEMIBLOCK;
            b[AES_WRAP_SEMIBLOCK..]
                .copy_from_slice(&out[r_start..r_start + AES_WRAP_SEMIBLOCK]);

            // B = AES_Decrypt_KEK(B).
            aes.decrypt_block_array(&mut b);

            // A = MSB(64, B); R[i] = LSB(64, B).
            a.copy_from_slice(&b[..AES_WRAP_SEMIBLOCK]);
            out[r_start..r_start + AES_WRAP_SEMIBLOCK]
                .copy_from_slice(&b[AES_WRAP_SEMIBLOCK..]);

            t = t.wrapping_sub(1);
        }
    }

    // Zeroize the scratch block; `a` is returned to the caller (who zeroizes
    // it after the constant-time IV comparison).
    b.zeroize();

    Ok((a, out))
}

/// RFC 3394 Key Unwrap — see section 2.2.2 including the IV check.
///
/// Unwraps `ciphertext` under `kek` and verifies the recovered IV in
/// constant time. On failure the recovered plaintext buffer is zeroized.
///
/// # Parameters
///
/// * `kek` — Key Encryption Key. Must be 16, 24, or 32 bytes.
/// * `iv`  — 64-bit Initial Value expected to match the one used during
///   wrapping. For interoperability with callers that do not specify an
///   IV, pass [`&DEFAULT_IV`](DEFAULT_IV).
/// * `ciphertext` — wrapped data. Length must be a positive multiple of
///   eight bytes and at least 24 bytes (IV + two payload semiblocks).
///
/// # Errors
///
/// Returns [`CryptoError::Key`] when the KEK length is invalid or the
/// ciphertext length is not structurally valid. Returns
/// [`CryptoError::Verification`] when the recovered IV does not match the
/// supplied one — the recovered plaintext is wiped before the error is
/// returned.
pub fn aes_key_unwrap(
    kek: &[u8],
    iv: &[u8; AES_WRAP_SEMIBLOCK],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let aes = Aes::new(kek)?;
    let (mut got_iv, mut out) = aes_key_unwrap_raw(&aes, ciphertext)?;

    // Constant-time comparison of the recovered IV against the expected
    // IV. Mismatch is the only authentication signal in RFC 3394.
    let iv_ok: bool = got_iv.ct_eq(iv).into();

    // Always zeroize the recovered IV — it is not returned to the caller.
    got_iv.zeroize();

    if !iv_ok {
        // Wipe the recovered plaintext — it could otherwise leak partial
        // information about the wrong-KEK or tampered-ciphertext case.
        out.zeroize();
        return Err(CryptoError::Verification(
            "AES key unwrap: IV mismatch".to_string(),
        ));
    }

    Ok(out)
}

/// RFC 5649 Key Wrap with Padding — see section 4.1.
///
/// Wraps `plaintext` of any non-zero length by prepending an Alternative
/// Initial Value (AIV) and padding the plaintext with zero octets to a
/// multiple of eight bytes. When the padded plaintext is exactly eight
/// bytes the function performs a single AES ECB encryption of the AIV
/// concatenated with the padded plaintext; otherwise it delegates to
/// [`aes_key_wrap`] with the AIV serving as the IV.
///
/// # Parameters
///
/// * `kek` — Key Encryption Key. Must be 16, 24, or 32 bytes.
/// * `plaintext` — data to wrap. Length must be non-zero and strictly less
///   than 2 GiB.
///
/// # Errors
///
/// Returns [`CryptoError::Key`] when the KEK length is invalid or the
/// plaintext is empty or exceeds the length limit. Returns
/// [`CryptoError::Common`] wrapping [`CommonError::ArithmeticOverflow`] if
/// ceiling-division of the input length would overflow (in practice
/// unreachable thanks to the `CRYPTO128_WRAP_MAX` guard).
///
/// # Security
///
/// Transient buffers including the AIV and the padded plaintext are
/// zeroized before the function returns.
pub fn aes_key_wrap_pad(kek: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let inlen = plaintext.len();
    if inlen == 0 {
        return Err(CryptoError::Key(
            "AES key wrap (padded): plaintext must be non-empty".to_string(),
        ));
    }
    if inlen >= CRYPTO128_WRAP_MAX {
        return Err(CryptoError::Key(format!(
            "AES key wrap (padded): plaintext length {inlen} exceeds maximum {}",
            CRYPTO128_WRAP_MAX - 1
        )));
    }

    // RFC 5649 §4.1 step 1: CEILING(m / 8) padded semiblocks.
    let blocks_padded = inlen
        .checked_add(AES_WRAP_SEMIBLOCK - 1)
        .ok_or(CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "aes_key_wrap_pad: inlen + 7",
        }))?
        / AES_WRAP_SEMIBLOCK;
    let padded_len = blocks_padded
        .checked_mul(AES_WRAP_SEMIBLOCK)
        .ok_or(CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "aes_key_wrap_pad: blocks_padded * 8",
        }))?;
    let padding_len = padded_len - inlen;

    // Build the AIV: magic || MLI (big-endian 32-bit).
    // The MLI is the *unpadded* plaintext length — `inlen` itself.
    let mut aiv = [0u8; AES_WRAP_SEMIBLOCK];
    aiv[..4].copy_from_slice(&DEFAULT_AIV);
    // `inlen < 2^31` by the guard above, so truncation to u32 is lossless.
    let mli: u32 = u32::try_from(inlen).map_err(|_| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "aes_key_wrap_pad: inlen -> u32",
        })
    })?;
    aiv[4..8].copy_from_slice(&mli.to_be_bytes());

    let aes = Aes::new(kek)?;

    let result = if padded_len == AES_WRAP_SEMIBLOCK {
        // RFC 5649 §4.1 step 2 — special case: padded plaintext is a
        // single semiblock. Prepend the AIV and encrypt the resulting
        // 16-byte block directly.
        let mut block = [0u8; AES_BLOCK_SIZE];
        block[..AES_WRAP_SEMIBLOCK].copy_from_slice(&aiv);
        // block[8..8+inlen] = plaintext; remaining bytes in block[8+inlen..]
        // are zero — padding.
        block[AES_WRAP_SEMIBLOCK..AES_WRAP_SEMIBLOCK + inlen].copy_from_slice(plaintext);
        // The `padding_len` trailing bytes of `block` are already zero from
        // the `[0u8; AES_BLOCK_SIZE]` initializer — no explicit memset
        // needed.
        debug_assert_eq!(padding_len, AES_WRAP_SEMIBLOCK - inlen);
        aes.encrypt_block_array(&mut block);
        let out = block.to_vec();
        block.zeroize();
        out
    } else {
        // General case — padded_len >= 16. Zero-pad the plaintext to a
        // multiple of eight bytes and delegate to RFC 3394 wrap with the
        // AIV as the IV.
        let mut padded = vec![0u8; padded_len];
        padded[..inlen].copy_from_slice(plaintext);
        // `padded[inlen..]` is already zero from the allocation — this is
        // the RFC 5649 §4.1 step 1 zero padding.
        let wrapped = aes_key_wrap(kek, &aiv, &padded);
        padded.zeroize();
        wrapped?
    };

    aiv.zeroize();
    Ok(result)
}

/// RFC 5649 Key Unwrap with Padding — see section 4.2.
///
/// Unwraps `ciphertext` produced by [`aes_key_wrap_pad`]. All three
/// authentication checks (AIV magic, MLI in range, padding is all zero)
/// are combined with bitwise-AND on `bool` to fold all branches into a
/// single final decision; this gives the compiled code a control-flow
/// shape that does not early-exit on the first failing check. The
/// comparisons themselves go through [`subtle::ConstantTimeEq`].
///
/// # Parameters
///
/// * `kek` — Key Encryption Key. Must be 16, 24, or 32 bytes.
/// * `ciphertext` — wrapped data. Length must be a positive multiple of
///   eight bytes and at least 16 bytes.
///
/// # Errors
///
/// Returns [`CryptoError::Key`] when the KEK length is invalid or the
/// ciphertext length is not structurally valid. Returns
/// [`CryptoError::Verification`] when any authentication check fails — a
/// single generic message is used to avoid leaking which check failed.
///
/// # Security
///
/// The recovered plaintext buffer is wiped on failure. Intermediate AIV
/// and single-block scratch are always zeroized.
pub fn aes_key_unwrap_pad(kek: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    let clen = ciphertext.len();
    if clen % AES_WRAP_SEMIBLOCK != 0 {
        return Err(CryptoError::Key(format!(
            "AES key unwrap (padded): ciphertext length {clen} is not a multiple of \
             {AES_WRAP_SEMIBLOCK}"
        )));
    }
    if clen < 2 * AES_WRAP_SEMIBLOCK {
        return Err(CryptoError::Key(format!(
            "AES key unwrap (padded): ciphertext length {clen} must be at least {} bytes",
            2 * AES_WRAP_SEMIBLOCK
        )));
    }
    if clen >= CRYPTO128_WRAP_MAX {
        return Err(CryptoError::Key(format!(
            "AES key unwrap (padded): ciphertext length {clen} exceeds maximum {}",
            CRYPTO128_WRAP_MAX - 1
        )));
    }

    let aes = Aes::new(kek)?;

    // Buffers recovered from either the single-block ECB decrypt or the
    // six-round RFC 3394 unwrap. `aiv` holds the 8-byte recovered AIV;
    // `plaintext_buf` holds `padded_len` bytes of recovered plaintext.
    let mut aiv = [0u8; AES_WRAP_SEMIBLOCK];
    let (plaintext_buf, padded_len): (Vec<u8>, usize) = if clen == 2 * AES_WRAP_SEMIBLOCK {
        // RFC 5649 §4.2 step 1 — special case n = 1: two ciphertext
        // semiblocks are decrypted as a single AES block. AIV occupies the
        // high 8 bytes, padded plaintext the low 8 bytes.
        let mut buff = [0u8; AES_BLOCK_SIZE];
        buff.copy_from_slice(ciphertext);
        aes.decrypt_block_array(&mut buff);
        aiv.copy_from_slice(&buff[..AES_WRAP_SEMIBLOCK]);
        let mut plaintext = vec![0u8; AES_WRAP_SEMIBLOCK];
        plaintext.copy_from_slice(&buff[AES_WRAP_SEMIBLOCK..]);
        buff.zeroize();
        (plaintext, AES_WRAP_SEMIBLOCK)
    } else {
        // General case — ciphertext length >= 24 semiblocks.
        let (got_iv, plaintext) = aes_key_unwrap_raw(&aes, ciphertext)?;
        aiv.copy_from_slice(&got_iv);
        // The raw IV buffer is no longer needed in a form distinct from
        // `aiv`; overwrite it. (The `got_iv` local was copy-returned from
        // `aes_key_unwrap_raw`; it does not implement `Drop`, so wipe
        // manually.)
        let mut got_iv_copy = got_iv;
        got_iv_copy.zeroize();
        (plaintext, clen - AES_WRAP_SEMIBLOCK)
    };

    let mut plaintext_buf = plaintext_buf;

    // `n` — number of padded semiblocks. n >= 1 always holds.
    let n = padded_len / AES_WRAP_SEMIBLOCK;

    // ---- Authentication Checks (combined constant-time) ----------------

    // Check 1 — AIV magic equals `DEFAULT_AIV`. `ct_eq` returns a
    // `subtle::Choice`; convert to bool so we can combine with `&`.
    let magic_ok: bool = aiv[..4].ct_eq(&DEFAULT_AIV[..]).into();

    // Extract MLI. Always compute, even if magic check failed — this keeps
    // the subsequent arithmetic side-effect-free.
    let mli_u32 = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]);
    let mli = mli_u32 as usize;

    // Check 2 — MLI in valid range: 8 * (n - 1) < MLI <= 8 * n. Use
    // saturating arithmetic because `n == 1` would give `8 * (n - 1) = 0`
    // and `n` is guaranteed >= 1. `padded_len = 8 * n` can never overflow
    // because it originates from `clen - 8` which is bounded by
    // `CRYPTO128_WRAP_MAX`.
    let lower_bound = AES_WRAP_SEMIBLOCK.saturating_mul(n.saturating_sub(1));
    let mli_lower_ok = mli > lower_bound;
    let mli_upper_ok = mli <= padded_len;

    // Check 3 — padding bytes at `plaintext_buf[mli..padded_len]` are all
    // zero. Clamp `mli` to `padded_len` so we never index out of bounds
    // even when the range check above would ultimately fail. The OR
    // accumulator is byte-wise data-dependent-free; the final
    // `acc == 0` comparison is folded through `ct_eq` to defeat any
    // compiler shenanigans.
    let effective_mli = mli.min(padded_len);
    let mut pad_acc: u8 = 0;
    for &byte in &plaintext_buf[effective_mli..padded_len] {
        pad_acc |= byte;
    }
    let pad_ok: bool = pad_acc.ct_eq(&0u8).into();

    // Combine all checks with bitwise AND (no short-circuit).
    let all_ok: bool = magic_ok & mli_lower_ok & mli_upper_ok & pad_ok;

    // Wipe the recovered AIV — not returned to the caller.
    aiv.zeroize();

    if !all_ok {
        plaintext_buf.zeroize();
        return Err(CryptoError::Verification(
            "AES key unwrap (padded): authentication failed".to_string(),
        ));
    }

    // RFC 5649 §4.2 step 3 — remove padding. `mli <= padded_len` holds
    // because `all_ok` is true.
    plaintext_buf.truncate(mli);
    Ok(plaintext_buf)
}


// =============================================================================
// Unit Tests — RFC/NIST Test Vectors
// =============================================================================
//
// This module exercises every public AES export against published test
// vectors from FIPS 197, NIST SP 800-38A/D, RFC 3394, RFC 3610, RFC 5297,
// RFC 5649, and RFC 7253. Round-trip and tamper-detection tests are also
// provided for all AEAD modes to guarantee the `seal`/`open` contract and
// the constant-time verification path.

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    reason = "Cryptographic test vectors are inherently long and use single-letter names to match their source RFCs/NIST publications."
)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------

    /// Parse a hex string (whitespace tolerated) into a byte vector.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            clean.len() % 2 == 0,
            "hex_to_bytes: odd number of nibbles ({})",
            clean.len()
        );
        (0..clean.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&clean[i..i + 2], 16)
                    .unwrap_or_else(|_| panic!("hex_to_bytes: invalid hex pair at byte {}", i / 2))
            })
            .collect()
    }

    /// Convenience: parse hex into a fixed-size array.
    fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
        let v = hex_to_bytes(hex);
        assert_eq!(
            v.len(),
            N,
            "hex_to_array: expected {} bytes, got {}",
            N,
            v.len()
        );
        let mut arr = [0u8; N];
        arr.copy_from_slice(&v);
        arr
    }

    // =========================================================================
    // FIPS 197 — Block Cipher Test Vectors (Appendix B / C)
    // =========================================================================
    //
    // Source: NIST FIPS 197 "Advanced Encryption Standard (AES)", Appendix B
    // (AES-128 example) and Appendix C (AES-128/192/256 example vectors).
    // These vectors validate the bare block primitive — key expansion plus a
    // single encryption/decryption — which is the foundation for every mode.

    /// FIPS 197 Appendix B / C.1 — AES-128 forward direction.
    #[test]
    fn fips197_aes128_encrypt_block() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_array::<16>("00112233445566778899aabbccddeeff");
        let expected_ct = hex_to_array::<16>("69c4e0d86a7b0430d8cdb78070b4c55a");

        let cipher = Aes::new(&key).expect("AES-128 key expansion must succeed");
        assert_eq!(cipher.key_size(), AesKeySize::Aes128);

        let mut block = pt;
        cipher.encrypt_block_array(&mut block);
        assert_eq!(block, expected_ct, "AES-128 encrypt-block mismatch");
    }

    /// FIPS 197 Appendix C.2 — AES-192 forward direction.
    #[test]
    fn fips197_aes192_encrypt_block() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = hex_to_array::<16>("00112233445566778899aabbccddeeff");
        let expected_ct = hex_to_array::<16>("dda97ca4864cdfe06eaf70a0ec0d7191");

        let cipher = Aes::new(&key).expect("AES-192 key expansion must succeed");
        assert_eq!(cipher.key_size(), AesKeySize::Aes192);

        let mut block = pt;
        cipher.encrypt_block_array(&mut block);
        assert_eq!(block, expected_ct, "AES-192 encrypt-block mismatch");
    }

    /// FIPS 197 Appendix C.3 — AES-256 forward direction.
    #[test]
    fn fips197_aes256_encrypt_block() {
        let key = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let pt = hex_to_array::<16>("00112233445566778899aabbccddeeff");
        let expected_ct = hex_to_array::<16>("8ea2b7ca516745bfeafc49904b496089");

        let cipher = Aes::new(&key).expect("AES-256 key expansion must succeed");
        assert_eq!(cipher.key_size(), AesKeySize::Aes256);

        let mut block = pt;
        cipher.encrypt_block_array(&mut block);
        assert_eq!(block, expected_ct, "AES-256 encrypt-block mismatch");
    }

    /// Inverse direction — round-trip validates decrypt schedule + inverse
    /// T-tables for all three key sizes.
    #[test]
    fn fips197_decrypt_round_trip_all_sizes() {
        for key_hex in [
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ] {
            let key = hex_to_bytes(key_hex);
            let pt = hex_to_array::<16>("00112233445566778899aabbccddeeff");
            let cipher = Aes::new(&key).expect("key expansion");

            let mut ct = pt;
            cipher.encrypt_block_array(&mut ct);
            assert_ne!(ct, pt, "ciphertext must differ from plaintext");

            let mut recovered = ct;
            cipher.decrypt_block_array(&mut recovered);
            assert_eq!(recovered, pt, "decrypt must recover plaintext");
        }
    }

    /// FIPS 197 Appendix B — AES-128 reverse direction, explicit vector.
    #[test]
    fn fips197_aes128_decrypt_block() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let ct = hex_to_array::<16>("69c4e0d86a7b0430d8cdb78070b4c55a");
        let expected_pt = hex_to_array::<16>("00112233445566778899aabbccddeeff");

        let cipher = Aes::new(&key).expect("key expansion");
        let mut block = ct;
        cipher.decrypt_block_array(&mut block);
        assert_eq!(block, expected_pt, "AES-128 decrypt-block mismatch");
    }

    // =========================================================================
    // Key Schedule Tests — Round counts and error paths
    // =========================================================================

    #[test]
    fn key_schedule_aes128_has_10_rounds() {
        let key = [0u8; 16];
        let sched = AesKey::expand_encrypt_key(&key).expect("expand");
        assert_eq!(sched.rounds(), 10);
    }

    #[test]
    fn key_schedule_aes192_has_12_rounds() {
        let key = [0u8; 24];
        let sched = AesKey::expand_encrypt_key(&key).expect("expand");
        assert_eq!(sched.rounds(), 12);
    }

    #[test]
    fn key_schedule_aes256_has_14_rounds() {
        let key = [0u8; 32];
        let sched = AesKey::expand_encrypt_key(&key).expect("expand");
        assert_eq!(sched.rounds(), 14);
    }

    #[test]
    fn key_schedule_rejects_invalid_lengths() {
        for bad_len in [0usize, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48, 64] {
            let key = vec![0u8; bad_len];
            let err = AesKey::expand_encrypt_key(&key)
                .expect_err("expansion must reject non-{16,24,32} length");
            assert!(matches!(err, CryptoError::Key(_)));

            let err2 = AesKey::expand_decrypt_key(&key)
                .expect_err("decrypt expansion must reject non-{16,24,32} length");
            assert!(matches!(err2, CryptoError::Key(_)));
        }
    }

    #[test]
    fn aes_new_rejects_invalid_key_length() {
        let err = Aes::new(&[0u8; 10]).expect_err("Aes::new must reject 10-byte key");
        assert!(matches!(err, CryptoError::Key(_)));
    }

    #[test]
    fn aes_keysize_helpers() {
        assert_eq!(AesKeySize::Aes128.bytes(), 16);
        assert_eq!(AesKeySize::Aes192.bytes(), 24);
        assert_eq!(AesKeySize::Aes256.bytes(), 32);

        assert_eq!(AesKeySize::Aes128.rounds(), 10);
        assert_eq!(AesKeySize::Aes192.rounds(), 12);
        assert_eq!(AesKeySize::Aes256.rounds(), 14);
    }

    // =========================================================================
    // AES-CBC — NIST SP 800-38A Appendix F.2.1 (CBC-AES128-Encrypt)
    // =========================================================================
    //
    // Source: NIST SP 800-38A "Recommendation for Block Cipher Modes of
    // Operation: Methods and Techniques", December 2001.
    //
    // Note: `aes_cbc_encrypt` in this crate applies PKCS#7 padding, so the
    // ciphertext is 16 bytes longer than the NIST vector (which uses raw
    // CBC without padding). We compare only the first 64 bytes (four blocks
    // of the NIST plaintext). Round-trip decryption must recover the full
    // plaintext.

    #[test]
    fn nist_cbc_aes128_f_2_1_encrypt_matches_first_four_blocks() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_array::<16>("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected_ct_no_padding = hex_to_bytes(
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             3ff1caa1681fac09120eca307586e1a7",
        );

        let ct = aes_cbc_encrypt(&key, &iv, &plaintext).expect("cbc encrypt");
        assert_eq!(
            ct.len(),
            plaintext.len() + AES_BLOCK_SIZE,
            "PKCS#7 padding must add exactly one block when plaintext is block-aligned"
        );
        assert_eq!(
            &ct[..plaintext.len()],
            &expected_ct_no_padding[..],
            "CBC ciphertext (pre-padding bytes) must match NIST F.2.1"
        );

        // Round-trip: encrypt then decrypt recovers original plaintext.
        let recovered = aes_cbc_decrypt(&key, &iv, &ct).expect("cbc decrypt");
        assert_eq!(recovered, plaintext, "CBC round-trip mismatch");
    }

    #[test]
    fn cbc_round_trip_non_block_aligned() {
        let key = [0x42u8; 16];
        let iv = [0x99u8; 16];
        // Various lengths that exercise PKCS#7 padding branches.
        for &len in &[0usize, 1, 15, 16, 17, 31, 32, 33, 48, 50, 100, 255] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let ct = aes_cbc_encrypt(&key, &iv, &plaintext).expect("encrypt");
            // PKCS#7 pads to next block boundary (adds a full block when aligned).
            assert!(ct.len() > plaintext.len());
            assert_eq!(ct.len() % AES_BLOCK_SIZE, 0);

            let pt = aes_cbc_decrypt(&key, &iv, &ct).expect("decrypt");
            assert_eq!(pt, plaintext, "round-trip failed for length {len}");
        }
    }

    #[test]
    fn cbc_decrypt_rejects_invalid_padding() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        // An all-zero ciphertext cannot be valid PKCS#7 padded output.
        let bad_ct = [0u8; 16];
        let err = aes_cbc_decrypt(&key, &iv, &bad_ct).expect_err("must reject invalid padding");
        // pkcs7_unpad returns CryptoError::Verification on padding failure.
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn cbc_decrypt_rejects_non_block_aligned_input() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let err = aes_cbc_decrypt(&key, &iv, &[0u8; 15])
            .expect_err("must reject non-block-aligned ciphertext");
        // Non-block-aligned length is detected by pkcs7_unpad → Verification.
        assert!(matches!(err, CryptoError::Verification(_) | CryptoError::Common(_)));
    }

    // =========================================================================
    // AES-CTR — RFC 3686 Test Vector #2 (AES-128 CTR, 32-byte plaintext)
    // =========================================================================
    //
    // Source: RFC 3686 "Using Advanced Encryption Standard (AES) Counter Mode
    // With IPsec Encapsulating Security Payload", Section 6, Test Vector #2.
    //
    // The initial counter block is formed as: Nonce(4) || IV(8) || 0x00000001.
    // We construct the full 16-byte counter explicitly because our API
    // accepts a 16-byte nonce (full block) rather than 4+8 split.

    #[test]
    fn rfc3686_aes128_ctr_test_vector_2() {
        let key = hex_to_bytes("7e24067817fae0d743d6ce1f32539163");
        // Nonce (4) || IV (8) || Counter = 0x00000001 (4)
        let counter = hex_to_array::<16>(
            "006cb6dbc0543b59da48d90b\
             00000001",
        );
        let plaintext = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
        );
        let expected_ct = hex_to_bytes(
            "5104a106168a72d9790d41ee8edad388\
             eb2e1efc46da57c8fce630df9141be28",
        );

        let ct = aes_ctr_encrypt(&key, &counter, &plaintext).expect("ctr encrypt");
        assert_eq!(ct, expected_ct, "RFC 3686 CTR vector #2 mismatch");

        // CTR is symmetric: encrypt(encrypt(p)) == p.
        let round_trip = aes_ctr_encrypt(&key, &counter, &ct).expect("ctr decrypt");
        assert_eq!(round_trip, plaintext, "CTR symmetry broken");
    }

    #[test]
    fn rfc3686_aes128_ctr_test_vector_3() {
        // RFC 3686 §6 Test Vector #3 — AES-128, 36-byte plaintext.
        let key = hex_to_bytes("7691be035e5020a8ac6e618529f9a0dc");
        let counter = hex_to_array::<16>(
            "00e0017b27777f3f4a1786f0\
             00000001",
        );
        let plaintext = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             20212223",
        );
        let expected_ct = hex_to_bytes(
            "c1cf48a89f2ffdd9cf4652e9efdb72d7\
             4540a42bde6d7836d59a5ceaaef31053\
             25b2072f",
        );

        let ct = aes_ctr_encrypt(&key, &counter, &plaintext).expect("ctr encrypt");
        assert_eq!(ct, expected_ct, "RFC 3686 CTR vector #3 mismatch");
    }

    #[test]
    fn ctr_round_trip_edge_sizes() {
        let key = [0xabu8; 32]; // AES-256
        let counter = [0x00u8; 16];
        for &len in &[0usize, 1, 15, 16, 17, 31, 32, 64, 100, 1024] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i ^ 0x5A) as u8).collect();
            let ct = aes_ctr_encrypt(&key, &counter, &plaintext).expect("encrypt");
            assert_eq!(ct.len(), plaintext.len(), "CTR length preservation");
            let recovered = aes_ctr_encrypt(&key, &counter, &ct).expect("decrypt");
            assert_eq!(recovered, plaintext, "CTR round-trip length {len}");
        }
    }

    // =========================================================================
    // AES-CFB — NIST SP 800-38A Appendix F.3.13 (CFB128-AES128-Encrypt)
    // =========================================================================

    #[test]
    fn nist_cfb128_aes128_f_3_13_encrypt() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_array::<16>("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected_ct = hex_to_bytes(
            "3b3fd92eb72dad20333449f8e83cfb4a\
             c8a64537a0b3a93fcde3cdad9f1ce58b\
             26751f67a3cbb140b1808cf187a4f4df\
             c04b05357c5d1c0eeac4c66f9ff7f2e6",
        );

        let ct = aes_cfb_encrypt(&key, &iv, &plaintext).expect("cfb encrypt");
        assert_eq!(ct, expected_ct, "NIST F.3.13 CFB128-AES128 mismatch");
    }

    #[test]
    fn cfb_round_trip() {
        // aes_cfb_encrypt is used for both directions via the generic
        // cfb_encrypt mode engine. Verify a single forward application
        // followed by a decryption call in the mode engine recovers input.
        let key = [0x77u8; 24]; // AES-192
        let iv = [0x33u8; 16];
        for &len in &[0usize, 1, 16, 17, 64, 100] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i + 11) as u8).collect();
            let ct = aes_cfb_encrypt(&key, &iv, &plaintext).expect("encrypt");
            assert_eq!(ct.len(), plaintext.len());

            // Verify via mod::cfb_encrypt in decrypt direction.
            // Signature: cfb_encrypt(cipher, data, iv, direction)
            let cipher = Aes::new(&key).expect("cipher");
            let pt = crate::symmetric::cfb_encrypt(&cipher, &ct, &iv, CipherDirection::Decrypt)
                .expect("decrypt");
            assert_eq!(pt, plaintext, "CFB round-trip length {len}");
        }
    }

    // =========================================================================
    // AES-OFB — NIST SP 800-38A Appendix F.4.1 (OFB-AES128-Encrypt)
    // =========================================================================

    #[test]
    fn nist_ofb_aes128_f_4_1_encrypt() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_array::<16>("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected_ct = hex_to_bytes(
            "3b3fd92eb72dad20333449f8e83cfb4a\
             7789508d16918f03f53c52dac54ed825\
             9740051e9c5fecf64344f7a82260edcc\
             304c6528f659c77866a510d9c1d6ae5e",
        );

        let ct = aes_ofb_encrypt(&key, &iv, &plaintext).expect("ofb encrypt");
        assert_eq!(ct, expected_ct, "NIST F.4.1 OFB-AES128 mismatch");
    }

    #[test]
    fn ofb_is_symmetric() {
        // OFB keystream is independent of data → encrypt(encrypt(p)) == p.
        let key = [0x55u8; 16];
        let iv = [0xaau8; 16];
        let pt = hex_to_bytes("0123456789abcdef0123456789abcdef0123");
        let ct = aes_ofb_encrypt(&key, &iv, &pt).expect("encrypt");
        let back = aes_ofb_encrypt(&key, &iv, &ct).expect("decrypt");
        assert_eq!(back, pt, "OFB is not symmetric");
    }

    // =========================================================================
    // AES-GCM — McGrew/Viega "The Galois/Counter Mode of Operation (GCM)"
    // =========================================================================
    //
    // Source: "The Galois/Counter Mode of Operation (GCM)", David McGrew
    // and John Viega (NIST submission) — the canonical AES-GCM test vector
    // reference, also reproduced in NIST SP 800-38D Appendix B.
    //
    // Test Case 1: Empty plaintext, empty AAD, all-zero key/nonce.
    // Test Case 2: Single 16-byte plaintext block, all-zero key/nonce.
    // Test Case 3: 60-byte plaintext, 12-byte IV, 128-bit key.
    // Test Case 4: 60-byte plaintext, 12-byte IV, 20-byte AAD.

    #[test]
    fn gcm_test_case_1_empty() {
        // K = 0^128, IV = 0^96, P = empty, A = empty.
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let gcm = AesGcm::new(&key).expect("gcm new");

        let out = gcm.seal(&iv, &[], &[]).expect("seal");
        // Expected tag: 58e2fccefa7e3061367f1d57a4e7455a
        let expected_tag = hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a");
        assert_eq!(out.len(), 16, "empty GCM output must be 16-byte tag only");
        assert_eq!(out, expected_tag, "GCM Test Case 1 tag mismatch");

        // open() must recover empty plaintext.
        let pt = gcm.open(&iv, &[], &out).expect("open");
        assert!(pt.is_empty());
    }

    #[test]
    fn gcm_test_case_2_single_block() {
        // K = 0^128, IV = 0^96, P = 0^128, A = empty.
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let pt = [0u8; 16];
        let gcm = AesGcm::new(&key).expect("gcm new");

        let out = gcm.seal(&iv, &[], &pt).expect("seal");
        let expected = hex_to_bytes(
            "0388dace60b6a392f328c2b971b2fe78\
             ab6e47d42cec13bdf53a67b21257bddf",
        );
        assert_eq!(out, expected, "GCM Test Case 2 mismatch");

        let recovered = gcm.open(&iv, &[], &out).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn gcm_test_case_3_aes128() {
        // K = feffe9928665731c6d6a8f9467308308
        // P = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
        // IV = cafebabefacedbaddecaf888
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_array::<12>("cafebabefacedbaddecaf888");
        let pt = hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b391aafd255",
        );
        let expected_ct = hex_to_bytes(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091473f5985",
        );
        let expected_tag = hex_to_bytes("4d5c2af327cd64a62cf35abd2ba6fab4");

        let gcm = AesGcm::new(&key).expect("gcm new");
        let out = gcm.seal(&iv, &[], &pt).expect("seal");
        assert_eq!(out[..pt.len()], expected_ct[..], "GCM TC3 ciphertext mismatch");
        assert_eq!(&out[pt.len()..], &expected_tag[..], "GCM TC3 tag mismatch");

        let recovered = gcm.open(&iv, &[], &out).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn gcm_test_case_4_aes128_with_aad() {
        // Same K/IV as TC3, but with A = feedfacedeadbeeffeedfacedeadbeefabaddad2
        // and P truncated (60 bytes instead of 64).
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_array::<12>("cafebabefacedbaddecaf888");
        let pt = hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let expected_ct = hex_to_bytes(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );
        let expected_tag = hex_to_bytes("5bc94fbc3221a5db94fae95ae7121a47");

        let gcm = AesGcm::new(&key).expect("gcm new");
        let out = gcm.seal(&iv, &aad, &pt).expect("seal");
        assert_eq!(out[..pt.len()], expected_ct[..], "GCM TC4 ciphertext mismatch");
        assert_eq!(&out[pt.len()..], &expected_tag[..], "GCM TC4 tag mismatch");

        let recovered = gcm.open(&iv, &aad, &out).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn gcm_tag_length_is_16() {
        // AesGcm::tag_length is an associated function (not method).
        assert_eq!(AesGcm::tag_length(), 16);
    }

    #[test]
    fn gcm_open_rejects_tampered_ciphertext() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let pt = b"authenticate me".to_vec();
        let gcm = AesGcm::new(&key).expect("gcm new");

        let mut sealed = gcm.seal(&iv, &[], &pt).expect("seal");
        // Flip a bit in the ciphertext.
        sealed[0] ^= 0x01;
        let err = gcm.open(&iv, &[], &sealed).expect_err("must reject tampered ct");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn gcm_open_rejects_tampered_tag() {
        let key = [1u8; 16];
        let iv = [2u8; 12];
        let pt = b"secret".to_vec();
        let gcm = AesGcm::new(&key).expect("gcm new");

        let mut sealed = gcm.seal(&iv, &[], &pt).expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        let err = gcm.open(&iv, &[], &sealed).expect_err("must reject tampered tag");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn gcm_open_rejects_tampered_aad() {
        let key = [3u8; 16];
        let iv = [4u8; 12];
        let aad = b"context".to_vec();
        let pt = b"payload".to_vec();
        let gcm = AesGcm::new(&key).expect("gcm new");

        let sealed = gcm.seal(&iv, &aad, &pt).expect("seal");
        let wrong_aad = b"contexu".to_vec();
        let err = gcm
            .open(&iv, &wrong_aad, &sealed)
            .expect_err("must reject wrong aad");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn gcm_open_rejects_short_input() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let gcm = AesGcm::new(&key).expect("gcm new");
        let err = gcm.open(&iv, &[], &[0u8; 10]).expect_err("too short");
        assert!(matches!(err, CryptoError::Common(_)));
    }

    // =========================================================================
    // AES-CCM — RFC 3610 Packet Vector #1
    // =========================================================================
    //
    // Source: RFC 3610 "Counter with CBC-MAC (CCM)", Section 8 Packet
    // Vector #1. Key, nonce, AAD, plaintext, ciphertext are extracted
    // verbatim. RFC 3610 packet layout is:
    //
    //     <aad_bytes> <ciphertext> <tag>
    //
    // But our AesCcm::seal returns only <ciphertext> <tag> (no AAD prefix).
    // Packet #1 constants:
    //   Key    = C0 C1 C2 ... CF  (16 bytes)
    //   Nonce  = 00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5  (13 bytes)
    //   AAD    = 00 01 02 03 04 05 06 07  (8 bytes)
    //   PT     = 08 09 0A 0B ... 1E  (23 bytes)
    //   Mlen   = 8-byte tag
    //   Packet = AAD || CT || Tag = 08 09 ... 1E 58 8C 97 9A 61 C6 63 D2 F0 66 D0 C2 C0 F9 89 80 6D 5F 6B 61 DA C3 84 17 E8 D1 2C FD F9 26 E0

    #[test]
    fn rfc3610_packet_vector_1() {
        let key = hex_to_bytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce = hex_to_bytes("00000003020100a0a1a2a3a4a5");
        let aad = hex_to_bytes("0001020304050607");
        let pt = hex_to_bytes(
            "08090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e",
        );
        // RFC 3610 full packet: AAD + CT + 8-byte tag
        //   58 8C 97 9A 61 C6 63 D2 F0 66 D0 C2 C0 F9 89 80 6D 5F 6B 61 DA C3 84   <- CT (23 bytes)
        //   17 E8 D1 2C FD F9 26 E0                                                 <- Tag (8 bytes)
        let expected_ct = hex_to_bytes(
            "588c979a61c663d2f066d0c2c0f98980\
             6d5f6b61dac384",
        );
        let expected_tag = hex_to_bytes("17e8d12cfdf926e0");

        let ccm = AesCcm::new(&key, 8, 13).expect("ccm new");
        let out = ccm.seal(&nonce, &aad, &pt).expect("seal");
        assert_eq!(out.len(), pt.len() + 8, "output = CT || 8-byte tag");
        assert_eq!(&out[..pt.len()], &expected_ct[..], "RFC 3610 PV#1 CT mismatch");
        assert_eq!(&out[pt.len()..], &expected_tag[..], "RFC 3610 PV#1 tag mismatch");

        let recovered = ccm.open(&nonce, &aad, &out).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn ccm_open_rejects_tampered_ciphertext() {
        let key = [0u8; 16];
        let nonce = [0u8; 13];
        let pt = b"hello ccm".to_vec();
        let ccm = AesCcm::new(&key, 16, 13).expect("ccm new");

        let mut sealed = ccm.seal(&nonce, &[], &pt).expect("seal");
        sealed[0] ^= 0x01;
        let err = ccm.open(&nonce, &[], &sealed).expect_err("tampered ct");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn ccm_open_rejects_tampered_tag() {
        let key = [0u8; 16];
        let nonce = [0u8; 13];
        let pt = b"payload".to_vec();
        let ccm = AesCcm::new(&key, 12, 13).expect("ccm new");

        let mut sealed = ccm.seal(&nonce, &[], &pt).expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        let err = ccm.open(&nonce, &[], &sealed).expect_err("tampered tag");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn ccm_new_rejects_invalid_tag_length() {
        // Valid tag lengths: {4, 6, 8, 10, 12, 14, 16}.
        for bad in [0usize, 1, 2, 3, 5, 7, 9, 11, 13, 15, 17, 32] {
            let err = AesCcm::new(&[0u8; 16], bad, 13).expect_err("invalid tag");
            assert!(matches!(err, CryptoError::Common(_)));
        }
    }

    #[test]
    fn ccm_new_rejects_invalid_nonce_length() {
        // Valid nonce range: 7..=13.
        for bad in [0usize, 1, 2, 5, 6, 14, 15, 32] {
            let err = AesCcm::new(&[0u8; 16], 16, bad).expect_err("invalid nonce len");
            assert!(matches!(err, CryptoError::Common(_)));
        }
    }

    #[test]
    fn ccm_round_trip_various_tag_lengths() {
        let key = [0x42u8; 16];
        let nonce = [0x99u8; 13];
        let aad = b"associated".to_vec();
        let pt = b"Message payload for CCM round-trip test".to_vec();

        for tag_len in [4usize, 6, 8, 10, 12, 14, 16] {
            let ccm = AesCcm::new(&key, tag_len, 13).expect("ccm new");
            let sealed = ccm.seal(&nonce, &aad, &pt).expect("seal");
            assert_eq!(sealed.len(), pt.len() + tag_len);
            let recovered = ccm.open(&nonce, &aad, &sealed).expect("open");
            assert_eq!(recovered, pt, "round-trip failed for tag_len={tag_len}");
        }
    }

    // =========================================================================
    // AES-XTS — Round-trip correctness tests
    // =========================================================================
    //
    // XTS mode is complex and its IEEE 1619 test vectors require precise
    // sector-alignment and tweak encoding. We verify correctness via
    // round-trip tests across block-aligned and ciphertext-stealing paths
    // (non-block-aligned lengths ≥ 16). The K1 != K2 safety check is also
    // exercised.

    #[test]
    fn xts_round_trip_block_aligned_aes256() {
        // XTS-AES-256 uses a 64-byte combined key: K1 (32) || K2 (32).
        let combined_key: Vec<u8> = (0u8..64u8).collect();
        let tweak = [0x33u8; 16];
        let xts = AesXts::new(&combined_key).expect("xts new");

        // 4 blocks (64 bytes) — exercise pure block path (no stealing).
        let pt: Vec<u8> = (0u8..64u8).map(|b| b.wrapping_mul(3).wrapping_add(7)).collect();
        let ct = xts.encrypt(&tweak, &pt).expect("encrypt");
        assert_eq!(ct.len(), pt.len());
        assert_ne!(ct, pt, "ciphertext must differ from plaintext");

        let recovered = xts.decrypt(&tweak, &ct).expect("decrypt");
        assert_eq!(recovered, pt, "XTS round-trip failed for block-aligned input");
    }

    #[test]
    fn xts_round_trip_aes128_combined_key() {
        // XTS-AES-128 uses a 32-byte combined key: K1 (16) || K2 (16).
        let mut combined_key = [0u8; 32];
        for (i, b) in combined_key.iter_mut().enumerate() {
            // Ensure K1 != K2 by construction.
            *b = i as u8;
        }
        let tweak = [0x11u8; 16];
        let xts = AesXts::new(&combined_key).expect("xts new");

        // 2-block plaintext.
        let pt: Vec<u8> = (0u8..32u8).collect();
        let ct = xts.encrypt(&tweak, &pt).expect("encrypt");
        let recovered = xts.decrypt(&tweak, &ct).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn xts_ciphertext_stealing_non_block_aligned() {
        // Lengths that are ≥ 16 but not multiples of 16 trigger the
        // ciphertext-stealing branch.
        let combined_key: Vec<u8> = (0u8..64u8).collect();
        let tweak = [0x77u8; 16];
        let xts = AesXts::new(&combined_key).expect("xts new");

        for &len in &[17usize, 20, 31, 33, 47, 63, 65, 100, 129] {
            let pt: Vec<u8> = (0..len).map(|i| (i ^ 0xA5) as u8).collect();
            let ct = xts.encrypt(&tweak, &pt).expect("encrypt");
            assert_eq!(ct.len(), pt.len(), "XTS length preservation at {len}");
            let recovered = xts.decrypt(&tweak, &ct).expect("decrypt");
            assert_eq!(recovered, pt, "XTS stealing round-trip failed at len {len}");
        }
    }

    #[test]
    fn xts_rejects_equal_halves() {
        // IEEE 1619-2007 §5.1 mandates K1 != K2. Using a combined key
        // consisting of two identical halves must be rejected.
        let combined_key = [0x42u8; 32]; // K1 == K2
        let err = AesXts::new(&combined_key).expect_err("must reject K1 == K2");
        assert!(matches!(err, CryptoError::Key(_)));
    }

    #[test]
    fn xts_rejects_invalid_combined_key_length() {
        for bad_len in [0usize, 1, 15, 16, 24, 30, 33, 48, 63, 65, 96, 128] {
            let key = vec![0u8; bad_len];
            let err = AesXts::new(&key).expect_err("must reject invalid combined len");
            assert!(matches!(err, CryptoError::Key(_) | CryptoError::Common(_)));
        }
    }

    #[test]
    fn xts_rejects_plaintext_shorter_than_one_block() {
        let combined_key: Vec<u8> = (0u8..64u8).collect();
        let tweak = [0u8; 16];
        let xts = AesXts::new(&combined_key).expect("xts new");
        let err = xts.encrypt(&tweak, &[0u8; 15]).expect_err("< 1 block must fail");
        assert!(matches!(err, CryptoError::Common(_) | CryptoError::Key(_)));
    }

    // =========================================================================
    // AES-OCB — Round-trip correctness (RFC 7253 algorithms)
    // =========================================================================
    //
    // OCB (Offset CodeBook) is an AEAD mode defined in RFC 7253. We exercise
    // the OCB engine with round-trip tests across multiple key/nonce/AAD/PT
    // combinations and validate tamper detection. Exact RFC 7253 Appendix A
    // test vectors require a byte-exact tag-length and nonce interpretation
    // which this implementation supports; we prioritise correctness
    // verification via round-trip and tamper tests here.

    #[test]
    fn ocb_round_trip_empty_plaintext() {
        let key = [0x07u8; 16];
        let nonce = [0x11u8; 12];
        let ocb = AesOcb::new(&key, 16, 12).expect("ocb new");
        let sealed = ocb.seal(&nonce, &[], &[]).expect("seal");
        // output = 16-byte tag only for empty PT.
        assert_eq!(sealed.len(), 16);
        let recovered = ocb.open(&nonce, &[], &sealed).expect("open");
        assert!(recovered.is_empty());
    }

    #[test]
    fn ocb_round_trip_with_aad_and_pt() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let nonce = hex_to_bytes("bbaa99887766554433221100");
        let aad = hex_to_bytes("0001020304050607");
        let pt = hex_to_bytes("0001020304050607");

        let ocb = AesOcb::new(&key, 16, 12).expect("ocb new");
        let sealed = ocb.seal(&nonce, &aad, &pt).expect("seal");
        assert_eq!(sealed.len(), pt.len() + 16);

        let recovered = ocb.open(&nonce, &aad, &sealed).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn ocb_round_trip_various_tag_lengths() {
        // OCB supports any tag length in 1..=16.
        let key = [0x42u8; 16];
        let nonce = [0x99u8; 12];
        let aad = b"context".to_vec();
        let pt = b"OCB multi-tag round-trip payload message".to_vec();

        for tag_len in [8usize, 12, 14, 16] {
            let ocb = AesOcb::new(&key, tag_len, 12).expect("ocb new");
            let sealed = ocb.seal(&nonce, &aad, &pt).expect("seal");
            assert_eq!(sealed.len(), pt.len() + tag_len);
            let recovered = ocb.open(&nonce, &aad, &sealed).expect("open");
            assert_eq!(recovered, pt, "OCB round-trip at tag_len={tag_len}");
        }
    }

    #[test]
    fn ocb_round_trip_various_nonce_lengths() {
        // OCB supports nonces in 1..=15 bytes.
        let key = [0x55u8; 16];
        let pt = b"nonce-length variance".to_vec();

        for nonce_len in [1usize, 7, 8, 12, 15] {
            let nonce = vec![0xABu8; nonce_len];
            let ocb = AesOcb::new(&key, 16, nonce_len).expect("ocb new");
            let sealed = ocb.seal(&nonce, &[], &pt).expect("seal");
            let recovered = ocb.open(&nonce, &[], &sealed).expect("open");
            assert_eq!(recovered, pt, "OCB nonce_len={nonce_len}");
        }
    }

    #[test]
    fn ocb_open_rejects_tampered_ciphertext() {
        let key = [0x31u8; 16];
        let nonce = [0x77u8; 12];
        let pt = b"tamper me".to_vec();
        let ocb = AesOcb::new(&key, 16, 12).expect("ocb new");

        let mut sealed = ocb.seal(&nonce, &[], &pt).expect("seal");
        sealed[0] ^= 0x01;
        let err = ocb.open(&nonce, &[], &sealed).expect_err("tampered ct");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn ocb_open_rejects_tampered_tag() {
        let key = [0x31u8; 16];
        let nonce = [0x77u8; 12];
        let pt = b"tamper me tag".to_vec();
        let ocb = AesOcb::new(&key, 16, 12).expect("ocb new");

        let mut sealed = ocb.seal(&nonce, &[], &pt).expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        let err = ocb.open(&nonce, &[], &sealed).expect_err("tampered tag");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn ocb_open_rejects_tampered_aad() {
        let key = [0x31u8; 16];
        let nonce = [0x77u8; 12];
        let aad_good = b"context".to_vec();
        let aad_bad = b"wronger".to_vec();
        let pt = b"payload".to_vec();
        let ocb = AesOcb::new(&key, 16, 12).expect("ocb new");

        let sealed = ocb.seal(&nonce, &aad_good, &pt).expect("seal");
        let err = ocb
            .open(&nonce, &aad_bad, &sealed)
            .expect_err("wrong aad");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn ocb_new_rejects_invalid_tag_length() {
        for bad in [0usize, 17, 32, 64] {
            let err = AesOcb::new(&[0u8; 16], bad, 12).expect_err("invalid tag len");
            assert!(matches!(err, CryptoError::Common(_)));
        }
    }

    #[test]
    fn ocb_new_rejects_invalid_nonce_length() {
        for bad in [0usize, 16, 17, 32] {
            let err = AesOcb::new(&[0u8; 16], 16, bad).expect_err("invalid nonce len");
            assert!(matches!(err, CryptoError::Common(_)));
        }
    }

    // =========================================================================
    // AES-SIV — Round-trip correctness tests
    // =========================================================================
    //
    // AES-SIV (RFC 5297) is a nonce-misuse-resistant deterministic AEAD.
    // The public seal/open API accepts (nonce, aad, plaintext) and computes
    // S2V over the AD vector [aad, nonce] with plaintext as the final
    // (distinguished) input. The output is V || C where V is the 128-bit
    // synthetic IV and C is the ciphertext.
    //
    // Since our API signature differs slightly from RFC 5297 Appendix A.1/A.2
    // (which use a variable-length AD vector), we verify correctness via
    // round-trip tests at all three valid key sizes (256/384/512-bit keys
    // corresponding to AES-128/192/256 under SIV) and tamper detection.

    #[test]
    fn siv_round_trip_aes128() {
        // 32-byte combined key: K1 (16) || K2 (16) for SIV-AES-128.
        let key: Vec<u8> = (0u8..32u8).collect();
        let nonce = b"1234567890123456".to_vec();
        let aad = b"Associated data for SIV mode".to_vec();
        let pt = b"This is some plaintext to encrypt using SIV-AES".to_vec();

        let siv = AesSiv::new(&key).expect("siv new");
        let sealed = siv.seal(&nonce, &aad, &pt).expect("seal");
        // Output: V (16) || C (pt.len()).
        assert_eq!(sealed.len(), 16 + pt.len());

        let recovered = siv.open(&nonce, &aad, &sealed).expect("open");
        assert_eq!(recovered, pt, "SIV-AES-128 round-trip failed");
    }

    #[test]
    fn siv_round_trip_aes192() {
        // 48-byte combined key: K1 (24) || K2 (24) for SIV-AES-192.
        let key: Vec<u8> = (0u8..48u8).collect();
        let nonce = b"nonce-192-bits-12".to_vec();
        let aad = b"".to_vec(); // empty AAD
        let pt = b"payload".to_vec();

        let siv = AesSiv::new(&key).expect("siv new");
        let sealed = siv.seal(&nonce, &aad, &pt).expect("seal");
        let recovered = siv.open(&nonce, &aad, &sealed).expect("open");
        assert_eq!(recovered, pt, "SIV-AES-192 round-trip failed");
    }

    #[test]
    fn siv_round_trip_aes256() {
        // 64-byte combined key: K1 (32) || K2 (32) for SIV-AES-256.
        let key: Vec<u8> = (0u8..64u8).collect();
        let nonce = b"Q".to_vec();
        let aad = b"context".to_vec();
        let pt: Vec<u8> = (0u8..100u8).collect();

        let siv = AesSiv::new(&key).expect("siv new");
        let sealed = siv.seal(&nonce, &aad, &pt).expect("seal");
        assert_eq!(sealed.len(), 16 + 100);
        let recovered = siv.open(&nonce, &aad, &sealed).expect("open");
        assert_eq!(recovered, pt, "SIV-AES-256 round-trip failed");
    }

    #[test]
    fn siv_round_trip_empty_plaintext() {
        let key: Vec<u8> = (0u8..32u8).collect();
        let siv = AesSiv::new(&key).expect("siv new");
        let sealed = siv.seal(&[], &[], &[]).expect("seal");
        // V (16) || empty C.
        assert_eq!(sealed.len(), 16);
        let recovered = siv.open(&[], &[], &sealed).expect("open");
        assert!(recovered.is_empty());
    }

    #[test]
    fn siv_round_trip_short_plaintext_pad_path() {
        // Plaintext < 16 bytes triggers the "pad" branch in S2V.
        let key: Vec<u8> = (0u8..32u8).collect();
        let nonce = b"nonceA".to_vec();
        let aad = b"AD".to_vec();
        let pt = b"short".to_vec(); // 5 bytes < 16

        let siv = AesSiv::new(&key).expect("siv new");
        let sealed = siv.seal(&nonce, &aad, &pt).expect("seal");
        let recovered = siv.open(&nonce, &aad, &sealed).expect("open");
        assert_eq!(recovered, pt, "SIV pad-path round-trip failed");
    }

    #[test]
    fn siv_deterministic_with_same_inputs() {
        // SIV is deterministic (nonce-misuse-resistant): identical inputs
        // yield identical sealed outputs.
        let key: Vec<u8> = (0u8..32u8).collect();
        let nonce = b"fixed_nonce_12".to_vec();
        let aad = b"some aad".to_vec();
        let pt = b"deterministic plaintext".to_vec();

        let siv = AesSiv::new(&key).expect("siv new");
        let s1 = siv.seal(&nonce, &aad, &pt).expect("seal 1");
        let s2 = siv.seal(&nonce, &aad, &pt).expect("seal 2");
        assert_eq!(s1, s2, "SIV must be deterministic");
    }

    #[test]
    fn siv_open_rejects_tampered_ciphertext() {
        let key: Vec<u8> = (0u8..32u8).collect();
        let nonce = b"n".to_vec();
        let pt = b"tamper me SIV".to_vec();
        let siv = AesSiv::new(&key).expect("siv new");
        let mut sealed = siv.seal(&nonce, &[], &pt).expect("seal");
        // Flip bit in ciphertext (after 16-byte V).
        sealed[17] ^= 0x01;
        let err = siv.open(&nonce, &[], &sealed).expect_err("tampered ct");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn siv_open_rejects_tampered_synthetic_iv() {
        let key: Vec<u8> = (0u8..32u8).collect();
        let nonce = b"n".to_vec();
        let pt = b"tamper me V".to_vec();
        let siv = AesSiv::new(&key).expect("siv new");
        let mut sealed = siv.seal(&nonce, &[], &pt).expect("seal");
        // Flip bit in the synthetic IV (first 16 bytes of output).
        sealed[0] ^= 0x80;
        let err = siv.open(&nonce, &[], &sealed).expect_err("tampered V");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn siv_open_rejects_short_input() {
        let key: Vec<u8> = (0u8..32u8).collect();
        let siv = AesSiv::new(&key).expect("siv new");
        let err = siv.open(&[], &[], &[0u8; 10]).expect_err("too short");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn siv_new_rejects_invalid_key_length() {
        // Valid lengths: 32, 48, 64.
        for bad in [0usize, 1, 16, 24, 31, 33, 40, 47, 49, 63, 65, 80, 96, 128] {
            let key = vec![0u8; bad];
            let err = AesSiv::new(&key).expect_err("invalid siv key len");
            assert!(matches!(err, CryptoError::Key(_)));
        }
    }

    // =========================================================================
    // AES Key Wrap — RFC 3394 §4.1–§4.6 test vectors
    // =========================================================================
    //
    // Source: RFC 3394 "Advanced Encryption Standard (AES) Key Wrap
    // Algorithm", Appendix 4 "Test Vectors". All six cases are covered.

    #[test]
    fn rfc3394_section_4_1_wrap_128bit_key_with_128bit_kek() {
        // §4.1: KEK=128, key data=128
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
        let expected_ct = hex_to_bytes(
            "1FA68B0A8112B447\
             AEF34BD8FB5A7B82\
             9D3E862371D2CFE5",
        );
        let out = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        assert_eq!(out, expected_ct, "RFC 3394 §4.1 wrap mismatch");

        let recovered = aes_key_unwrap(&kek, &DEFAULT_IV, &out).expect("unwrap");
        assert_eq!(recovered, key_data, "RFC 3394 §4.1 unwrap mismatch");
    }

    #[test]
    fn rfc3394_section_4_2_wrap_128bit_key_with_192bit_kek() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F1011121314151617");
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
        let expected_ct = hex_to_bytes(
            "96778B25AE6CA435\
             F92B5B97C050AED2\
             468AB8A17AD84E5D",
        );
        let out = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        assert_eq!(out, expected_ct, "RFC 3394 §4.2 wrap mismatch");

        let recovered = aes_key_unwrap(&kek, &DEFAULT_IV, &out).expect("unwrap");
        assert_eq!(recovered, key_data, "RFC 3394 §4.2 unwrap mismatch");
    }

    #[test]
    fn rfc3394_section_4_3_wrap_128bit_key_with_256bit_kek() {
        let kek = hex_to_bytes(
            "000102030405060708090A0B0C0D0E0F\
             101112131415161718191A1B1C1D1E1F",
        );
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
        let expected_ct = hex_to_bytes(
            "64E8C3F9CE0F5BA2\
             63E9777905818A2A\
             93C8191E7D6E8AE7",
        );
        let out = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        assert_eq!(out, expected_ct, "RFC 3394 §4.3 wrap mismatch");

        let recovered = aes_key_unwrap(&kek, &DEFAULT_IV, &out).expect("unwrap");
        assert_eq!(recovered, key_data);
    }

    #[test]
    fn rfc3394_section_4_4_wrap_192bit_key_with_192bit_kek() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F1011121314151617");
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected_ct = hex_to_bytes(
            "031D33264E15D332\
             68F24EC260743EDC\
             E1C6C7DDEE725A93\
             6BA814915C6762D2",
        );
        let out = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        assert_eq!(out, expected_ct, "RFC 3394 §4.4 wrap mismatch");

        let recovered = aes_key_unwrap(&kek, &DEFAULT_IV, &out).expect("unwrap");
        assert_eq!(recovered, key_data);
    }

    #[test]
    fn rfc3394_section_4_5_wrap_192bit_key_with_256bit_kek() {
        let kek = hex_to_bytes(
            "000102030405060708090A0B0C0D0E0F\
             101112131415161718191A1B1C1D1E1F",
        );
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected_ct = hex_to_bytes(
            "A8F9BC1612C68B3F\
             F6E6F4FBE30E71E4\
             769C8B80A32CB895\
             8CD5D17D6B254DA1",
        );
        let out = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        assert_eq!(out, expected_ct, "RFC 3394 §4.5 wrap mismatch");

        let recovered = aes_key_unwrap(&kek, &DEFAULT_IV, &out).expect("unwrap");
        assert_eq!(recovered, key_data);
    }

    #[test]
    fn rfc3394_section_4_6_wrap_256bit_key_with_256bit_kek() {
        let kek = hex_to_bytes(
            "000102030405060708090A0B0C0D0E0F\
             101112131415161718191A1B1C1D1E1F",
        );
        let key_data = hex_to_bytes(
            "00112233445566778899AABBCCDDEEFF\
             000102030405060708090A0B0C0D0E0F",
        );
        let expected_ct = hex_to_bytes(
            "28C9F404C4B810F4\
             CBCCB35CFB87F826\
             3F5786E2D80ED326\
             CBC7F0E71A99F43B\
             FB988B9B7A02DD21",
        );
        let out = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        assert_eq!(out, expected_ct, "RFC 3394 §4.6 wrap mismatch");

        let recovered = aes_key_unwrap(&kek, &DEFAULT_IV, &out).expect("unwrap");
        assert_eq!(recovered, key_data);
    }

    #[test]
    fn aes_key_unwrap_rejects_tampered_ciphertext() {
        // Standard §4.1 setup.
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
        let mut ct = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        // Flip bit in the 8-byte IV prefix (corrupts integrity check).
        ct[0] ^= 0x01;
        let err = aes_key_unwrap(&kek, &DEFAULT_IV, &ct).expect_err("tampered");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn aes_key_unwrap_rejects_tampered_body() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
        let mut ct = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        // Flip bit in the ciphertext body.
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        let err = aes_key_unwrap(&kek, &DEFAULT_IV, &ct).expect_err("tampered body");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn aes_key_unwrap_rejects_wrong_iv() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        let key_data = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
        let ct = aes_key_wrap(&kek, &DEFAULT_IV, &key_data).expect("wrap");
        // Unwrap with a different expected IV.
        let wrong_iv = [0xBBu8; 8];
        let err = aes_key_unwrap(&kek, &wrong_iv, &ct).expect_err("wrong IV");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn aes_key_wrap_rejects_non_aligned_plaintext() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        for bad_len in [1usize, 7, 9, 15, 17, 23] {
            let pt = vec![0u8; bad_len];
            let err = aes_key_wrap(&kek, &DEFAULT_IV, &pt).expect_err("non-aligned");
            assert!(matches!(err, CryptoError::Key(_)));
        }
    }

    #[test]
    fn aes_key_wrap_rejects_plaintext_under_two_semiblocks() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        // 8-byte (one semiblock) is too short; RFC 3394 requires n ≥ 2.
        let err = aes_key_wrap(&kek, &DEFAULT_IV, &[0u8; 8]).expect_err("one semiblock");
        assert!(matches!(err, CryptoError::Key(_)));
    }

    #[test]
    fn aes_key_unwrap_rejects_short_input() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        // Input must be at least 3 semiblocks (24 bytes) for valid unwrap.
        let err = aes_key_unwrap(&kek, &DEFAULT_IV, &[0u8; 16]).expect_err("too short");
        assert!(matches!(err, CryptoError::Key(_) | CryptoError::Verification(_)));
    }

    // =========================================================================
    // AES Key Wrap with Padding — RFC 5649
    // =========================================================================
    //
    // RFC 5649 extends RFC 3394 to handle arbitrary-length plaintexts
    // (including non-multiples of 8). The default AIV = `A6 59 59 A6 || MLI`
    // is appended with a 32-bit big-endian length prefix.

    #[test]
    fn aes_key_wrap_pad_round_trip_various_lengths() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        for len in [1usize, 2, 7, 8, 9, 15, 16, 17, 20, 31, 32, 33, 48, 64, 100, 255] {
            let pt: Vec<u8> = (0..len).map(|i| (i ^ 0x5A) as u8).collect();
            let ct = aes_key_wrap_pad(&kek, &pt).expect("wrap pad");
            // Output length: padded up to next multiple of 8, + 8 for AIV.
            let expected_len = ct.len();
            let padded = len.div_ceil(8) * 8;
            assert_eq!(expected_len, padded + 8, "wrap_pad length at input {len}");

            let recovered = aes_key_unwrap_pad(&kek, &ct).expect("unwrap pad");
            assert_eq!(recovered, pt, "wrap_pad round-trip failed at len {len}");
        }
    }

    #[test]
    fn aes_key_wrap_pad_rfc5649_20_octet_vector() {
        // RFC 5649 §6 example (20-octet plaintext with 192-bit KEK):
        //   KEK  = 5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8
        //   Key  = c37b7e6492584340 bed12207808941155068f738
        //   CT   = 138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a
        let kek = hex_to_bytes("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let key_data = hex_to_bytes("c37b7e6492584340bed12207808941155068f738");
        let expected_ct = hex_to_bytes(
            "138bdeaa9b8fa7fc\
             61f97742e72248ee\
             5ae6ae5360d1ae6a\
             5f54f373fa543b6a",
        );
        let ct = aes_key_wrap_pad(&kek, &key_data).expect("wrap pad");
        assert_eq!(ct, expected_ct, "RFC 5649 20-octet wrap mismatch");

        let recovered = aes_key_unwrap_pad(&kek, &ct).expect("unwrap pad");
        assert_eq!(recovered, key_data);
    }

    #[test]
    fn aes_key_wrap_pad_rfc5649_7_octet_vector() {
        // RFC 5649 §6 example (7-octet plaintext with 192-bit KEK):
        //   KEK  = 5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8
        //   Key  = 466f7250617369 (ASCII "ForPasi")
        //   CT   = afbeb0f07dfbf541 9200f2ccb50bb24f
        let kek = hex_to_bytes("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let key_data = hex_to_bytes("466f7250617369");
        let expected_ct = hex_to_bytes("afbeb0f07dfbf5419200f2ccb50bb24f");
        let ct = aes_key_wrap_pad(&kek, &key_data).expect("wrap pad");
        assert_eq!(ct, expected_ct, "RFC 5649 7-octet wrap mismatch");

        let recovered = aes_key_unwrap_pad(&kek, &ct).expect("unwrap pad");
        assert_eq!(recovered, key_data);
    }

    #[test]
    fn aes_key_unwrap_pad_rejects_tampered_input() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        let pt = b"some payload".to_vec();
        let mut ct = aes_key_wrap_pad(&kek, &pt).expect("wrap pad");
        ct[0] ^= 0x01;
        let err = aes_key_unwrap_pad(&kek, &ct).expect_err("tampered");
        assert!(matches!(err, CryptoError::Verification(_)));
    }

    #[test]
    fn aes_key_wrap_pad_rejects_empty_plaintext() {
        let kek = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
        let err = aes_key_wrap_pad(&kek, &[]).expect_err("empty");
        assert!(matches!(err, CryptoError::Key(_)));
    }
}

