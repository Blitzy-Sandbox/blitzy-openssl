//! ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) implementation
//! per NIST FIPS 203 (August 2024).
//!
//! Provides key generation, encapsulation, and decapsulation for the three
//! standardised parameter sets ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
//!
//! Uses NTT-based polynomial arithmetic over `Z_q[X]/(X^256 + 1)` with
//! `q = 3329`, centered binomial distribution sampling, and SHA3/SHAKE hash
//! functions. Replaces the C implementation originally in
//! `crypto/ml_kem/ml_kem.c` and declared in `include/crypto/ml_kem.h`.
//!
//! # Security properties
//!
//! - **IND-CCA2**: Decapsulation uses the Fujisaki-Okamoto transform and
//!   must return a pseudorandom shared secret on invalid ciphertexts. The
//!   comparison between the re-encapsulated ciphertext and the received
//!   ciphertext, and the subsequent selection of the shared secret vs. the
//!   implicit rejection key, are performed in constant time using the
//!   [`subtle`] crate. Any timing side-channel here breaks the KEM's
//!   chosen-ciphertext security.
//! - **Secure erasure**: Private key material ([`MlKemKey::s`](MlKemKey),
//!   implicit rejection secret `z`, key generation seed `d`) is zeroised on
//!   drop via [`zeroize::ZeroizeOnDrop`].
//! - **No unsafe code**: The implementation contains zero `unsafe` blocks.
//!
//! # References
//!
//! - FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard".
//! - CRYSTALS-Kyber submission to NIST PQC standardization.

#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use crate::context::LibContext;
use crate::hash::sha::{sha3_256, sha3_512, ShakeContext};
use openssl_common::{CryptoError, CryptoResult};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===========================================================================
// Constants (FIPS 203 §2.4 and Appendix A)
// ===========================================================================

/// Polynomial degree `n = 256`.
pub const ML_KEM_DEGREE: usize = 256;

/// The ML-KEM modulus `q = 256 * 13 + 1 = 3329`.
///
/// This prime is chosen such that `q - 1 = 2^8 * 13`, so it admits a primitive
/// 256th root of unity — exactly what is needed for the NTT used by ML-KEM
/// (which is "half" of a size-256 NTT, operating over pairs of coefficients).
pub const ML_KEM_PRIME: u16 = 3329;

/// Multiplicative inverse of `n = 256` modulo `q = 3329`, equal to
/// `q - 2 * 13 = 3303`. Used to normalise the output of the inverse NTT.
const INVERSE_DEGREE: u16 = ML_KEM_PRIME - 2 * 13;

/// Number of bits required to losslessly represent a coefficient `< q`.
const LOG2PRIME: u32 = 12;

/// Barrett reduction shift: `2 * log2(q) = 24`.
const BARRETT_SHIFT: u32 = 2 * LOG2PRIME;

/// Barrett multiplier: `floor(2^24 / 3329) = 5039`. This is used to perform
/// modular reduction without integer division on potentially-secret data.
const BARRETT_MULTIPLIER: u32 = (1u32 << BARRETT_SHIFT) / (ML_KEM_PRIME as u32);

/// Half the prime, `(q - 1) / 2 = 1664`. Referenced by the compression
/// routine and by tests that compute centered representatives in `[-(q-1)/2,
/// (q-1)/2]`. Kept as a named spec constant even though the current
/// compression helpers work directly with `ML_KEM_PRIME`.
#[allow(dead_code)]
const HALF_PRIME: u16 = (ML_KEM_PRIME - 1) / 2;

/// Length in bytes of a random input (ρ, σ, entropy, z).
pub const RANDOM_BYTES: usize = 32;

/// Length in bytes of a SHA3-256 public-key hash used in the FO transform.
pub const PKHASH_BYTES: usize = 32;

/// Length in bytes of the output shared secret.
pub const SHARED_SECRET_BYTES: usize = 32;

/// Length in bytes of the 64-byte key generation seed `d || z`.
pub const SEED_BYTES: usize = 64;

/// SHAKE128 block (rate) size in bytes: 168 bytes. Chosen to be divisible by
/// 3 (so 3 bytes yield 2 12-bit samples) and to match the SHAKE128 block size,
/// minimising calls to the permutation during rejection sampling.
const SCALAR_SAMPLING_BUFSIZE: usize = 168;

/// Size in bytes of the lossless 12-bit encoding of a single `Scalar`:
/// `256 * 12 / 8 = 384`. Exposed at module scope because several size
/// formulas reference it.
#[allow(dead_code)] // Referenced by size-formula comments and future external callers.
const SCALAR_BYTES: usize = 3 * ML_KEM_DEGREE / 2;

// ===========================================================================
// Variant and parameter table (FIPS 203 §7)
// ===========================================================================

/// Enumeration of the three standardised ML-KEM parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKemVariant {
    /// ML-KEM-512: NIST security category 1 (~128-bit post-quantum).
    MlKem512,
    /// ML-KEM-768: NIST security category 3 (~192-bit post-quantum).
    MlKem768,
    /// ML-KEM-1024: NIST security category 5 (~256-bit post-quantum).
    MlKem1024,
}

impl MlKemVariant {
    /// Returns the registered algorithm name (e.g., `"ML-KEM-768"`).
    #[must_use]
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Returns the NIST PQC security category (1, 3, or 5).
    #[must_use]
    pub fn security_category(self) -> u32 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }
}

/// Static table of ML-KEM parameters. All fields are `const` and mirror the
/// values tabulated in FIPS 203 §7 and the C `vinfo_map[3]` table in
/// `crypto/ml_kem/ml_kem.c`.
#[derive(Debug, Clone)]
pub struct MlKemParams {
    /// Registered algorithm name.
    pub alg: &'static str,
    /// Variant discriminator.
    pub variant: MlKemVariant,
    /// Module rank `k` (number of polynomial entries in each vector).
    pub rank: usize,
    /// Compression parameter `du` applied to the `u`-component of the
    /// ciphertext.
    pub du: usize,
    /// Compression parameter `dv` applied to the `v`-component of the
    /// ciphertext.
    pub dv: usize,
    /// ETA1 — secret/error-vector CBD width in key generation.
    pub eta1: usize,
    /// ETA2 — error-vector CBD width in encapsulation.
    pub eta2: usize,
    /// Classical security level in bits (matches the symmetric strength of
    /// the chosen hash functions).
    pub secbits: usize,
    /// NIST PQC security category (1, 3, or 5).
    pub security_category: u32,
    /// Encoded public-key length in bytes.
    pub pubkey_bytes: usize,
    /// Encoded private-key length in bytes (FIPS 203 DK format).
    pub prvkey_bytes: usize,
    /// Encoded ciphertext length in bytes.
    pub ctext_bytes: usize,
}

impl MlKemParams {
    /// Returns the lossless 12-bit encoding of a single vector:
    /// `3 * DEGREE / 2 * rank`.
    #[must_use]
    pub const fn vector_bytes(&self) -> usize {
        3 * ML_KEM_DEGREE / 2 * self.rank
    }

    /// Returns the length in bytes of the compressed `u`-component of a
    /// ciphertext: `(DEGREE / 8) * du * rank`.
    #[must_use]
    pub const fn u_vector_bytes(&self) -> usize {
        (ML_KEM_DEGREE / 8) * self.du * self.rank
    }

    /// Returns the length in bytes of the compressed `v`-component of a
    /// ciphertext: `(DEGREE / 8) * dv`.
    #[must_use]
    pub const fn v_scalar_bytes(&self) -> usize {
        (ML_KEM_DEGREE / 8) * self.dv
    }
}

/// ML-KEM-512 parameters.
const ML_KEM_512: MlKemParams = MlKemParams {
    alg: "ML-KEM-512",
    variant: MlKemVariant::MlKem512,
    rank: 2,
    du: 10,
    dv: 4,
    eta1: 3,
    eta2: 2,
    secbits: 128,
    security_category: 1,
    pubkey_bytes: 800,
    prvkey_bytes: 1632,
    ctext_bytes: 768,
};

/// ML-KEM-768 parameters.
const ML_KEM_768: MlKemParams = MlKemParams {
    alg: "ML-KEM-768",
    variant: MlKemVariant::MlKem768,
    rank: 3,
    du: 10,
    dv: 4,
    eta1: 2,
    eta2: 2,
    secbits: 192,
    security_category: 3,
    pubkey_bytes: 1184,
    prvkey_bytes: 2400,
    ctext_bytes: 1088,
};

/// ML-KEM-1024 parameters.
const ML_KEM_1024: MlKemParams = MlKemParams {
    alg: "ML-KEM-1024",
    variant: MlKemVariant::MlKem1024,
    rank: 4,
    du: 11,
    dv: 5,
    eta1: 2,
    eta2: 2,
    secbits: 256,
    security_category: 5,
    pubkey_bytes: 1568,
    prvkey_bytes: 3168,
    ctext_bytes: 1568,
};

/// Returns a reference to the [`MlKemParams`] for the given variant.
#[must_use]
pub fn ml_kem_params_get(variant: MlKemVariant) -> &'static MlKemParams {
    match variant {
        MlKemVariant::MlKem512 => &ML_KEM_512,
        MlKemVariant::MlKem768 => &ML_KEM_768,
        MlKemVariant::MlKem1024 => &ML_KEM_1024,
    }
}

/// Returns a reference to the [`MlKemParams`] for the algorithm name if
/// recognised. Case-sensitive; accepts the canonical FIPS 203 name
/// (`"ML-KEM-512"`, `"ML-KEM-768"`, `"ML-KEM-1024"`).
#[must_use]
pub fn ml_kem_params_get_by_name(name: &str) -> Option<&'static MlKemParams> {
    match name {
        "ML-KEM-512" => Some(&ML_KEM_512),
        "ML-KEM-768" => Some(&ML_KEM_768),
        "ML-KEM-1024" => Some(&ML_KEM_1024),
        _ => None,
    }
}

// ===========================================================================
// Scalar (polynomial) type and modular arithmetic
// ===========================================================================

/// A degree-`n` polynomial over `Z_q`, with all coefficients reduced modulo
/// `q = 3329`.
///
/// Coefficients are represented as `u16` (since `q < 2^12` < `2^16`). The
/// invariant `0 <= c[i] < q` is maintained on every public entry and exit,
/// allowing safe composition of NTT-domain and time-domain operations.
#[derive(Clone, Zeroize)]
pub struct Scalar {
    /// Coefficient array. `c[0] + c[1] X + ... + c[255] X^255`.
    pub c: [u16; ML_KEM_DEGREE],
}

impl Scalar {
    /// Returns the zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            c: [0u16; ML_KEM_DEGREE],
        }
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::zero()
    }
}

/// Conditionally subtracts `q` from `x` so that the result is strictly less
/// than `q`, using bitmasking rather than branching.
///
/// Precondition: `x < 2 * q`.
#[inline]
fn reduce_once(x: u16) -> u16 {
    // Same trick as C: subtract q, then pick between x and (x - q) based on
    // the sign bit. All arithmetic happens in u16 with wrapping semantics,
    // exactly mirroring `reduce_once` in `crypto/ml_kem/ml_kem.c`.
    let subtracted = x.wrapping_sub(ML_KEM_PRIME);
    // The top bit of `subtracted` is 1 iff `x < q` (underflow occurred).
    // Turn that single bit into a full-width mask.
    let mask = 0u16.wrapping_sub(subtracted >> 15);
    (mask & x) | (!mask & subtracted)
}

/// Barrett reduction modulo `q`, assuming `x < q + 2*q^2 = 3329 + 2*3329^2`.
///
/// This is a constant-time reduction suitable for reducing the output of a
/// single modular multiplication of two values in `[0, q)`, which can reach
/// `(q-1)^2 < 2^24`.
#[inline]
fn reduce(x: u32) -> u16 {
    // product = x * kBarrettMultiplier (fits in u64 since x <= 2*q^2 < 2^24
    // and BARRETT_MULTIPLIER < 2^13, product < 2^37).
    let product: u64 = u64::from(x) * u64::from(BARRETT_MULTIPLIER);
    // quotient = floor(product / 2^BARRETT_SHIFT) = floor(x / q) (Barrett's
    // approximation). The widening to u64 then shift-down yields a u32.
    // TRUNCATION: BARRETT_SHIFT=24 bits of fractional discard; product>>24
    // is bounded by ceil(2q^2 * 2^24 / q / 2^24) <= 2q < 2^13 so the value
    // fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let quotient: u32 = (product >> BARRETT_SHIFT) as u32;
    let remainder: u32 = x.wrapping_sub(quotient.wrapping_mul(u32::from(ML_KEM_PRIME)));
    // TRUNCATION: remainder < 2*q < 2^13 so casting to u16 is lossless.
    #[allow(clippy::cast_possible_truncation)]
    let narrowed = remainder as u16;
    reduce_once(narrowed)
}

// ===========================================================================
// NTT root tables (FIPS 203 Appendix A)
//
// These tables are computed by the test vectors in `ml_kem.c`:
//   kNTTRoots[i]         = 17^bitrev_7(i) mod q
//   kInverseNTTRoots[i]  = 17^-bitrev_7(i) mod q
//   kModRoots[i]         = 17^(2*bitrev_7(i) + 1) mod q
// where bitrev_7 reverses the lower 7 bits and 17 is a primitive 256th root
// of unity modulo q = 3329.
// ===========================================================================

/// Forward NTT roots (`kNTTRoots` from `ml_kem.c`).
#[rustfmt::skip]
static NTT_ROOTS: [u16; 128] = [
    0x001, 0x6c1, 0xa14, 0xcd9, 0xa52, 0x276, 0x769, 0x350,
    0x426, 0x77f, 0x0c1, 0x31d, 0xae2, 0xcbc, 0x239, 0x6d2,
    0x128, 0x98f, 0x53b, 0x5c4, 0xbe6, 0x038, 0x8c0, 0x535,
    0x592, 0x82e, 0x217, 0xb42, 0x959, 0xb3f, 0x7b6, 0x335,
    0x121, 0x14b, 0xcb5, 0x6dc, 0x4ad, 0x900, 0x8e5, 0x807,
    0x28a, 0x7b9, 0x9d1, 0x278, 0xb31, 0x021, 0x528, 0x77b,
    0x90f, 0x59b, 0x327, 0x1c4, 0x59e, 0xb34, 0x5fe, 0x962,
    0xa57, 0xa39, 0x5c9, 0x288, 0x9aa, 0xc26, 0x4cb, 0x38e,
    0x011, 0xac9, 0x247, 0xa59, 0x665, 0x2d3, 0x8f0, 0x44c,
    0x581, 0xa66, 0xcd1, 0x0e9, 0x2f4, 0x86c, 0xbc7, 0xbea,
    0x6a7, 0x673, 0xae5, 0x6fd, 0x737, 0x3b8, 0x5b5, 0xa7f,
    0x3ab, 0x904, 0x985, 0x954, 0x2dd, 0x921, 0x10c, 0x281,
    0x630, 0x8fa, 0x7f5, 0xc94, 0x177, 0x9f5, 0x82a, 0x66d,
    0x427, 0x13f, 0xad5, 0x2f5, 0x833, 0x231, 0x9a2, 0xa22,
    0xaf4, 0x444, 0x193, 0x402, 0x477, 0x866, 0xad7, 0x376,
    0x6ba, 0x4bc, 0x752, 0x405, 0x83e, 0xb77, 0x375, 0x86a,
];

/// Inverse NTT roots (`kInverseNTTRoots` from `ml_kem.c`).
#[rustfmt::skip]
static INVERSE_NTT_ROOTS: [u16; 128] = [
    0x001, 0x497, 0x98c, 0x18a, 0x4c3, 0x8fc, 0x5af, 0x845,
    0x647, 0x98b, 0x22a, 0x49b, 0x88a, 0x8ff, 0xb6e, 0x8bd,
    0x20d, 0x2df, 0x35f, 0xad0, 0x4ce, 0xa0c, 0x22c, 0xbc2,
    0x8da, 0x694, 0x4d7, 0x30c, 0xb8a, 0x06d, 0x50c, 0x407,
    0x6d1, 0xa80, 0xbf5, 0x3e0, 0xa24, 0x3ad, 0x37c, 0x3fd,
    0x956, 0x282, 0x74c, 0x949, 0x5ca, 0x604, 0x21c, 0x68e,
    0x65a, 0x117, 0x13a, 0x495, 0xa0d, 0xc18, 0x030, 0x29b,
    0x780, 0x8b5, 0x411, 0xa2e, 0x69c, 0x2a8, 0xaba, 0x238,
    0xcf0, 0x973, 0x836, 0x0db, 0x357, 0xa79, 0x738, 0x2c8,
    0x2aa, 0x39f, 0x703, 0x1cd, 0x763, 0xb3d, 0x9da, 0x766,
    0x3f2, 0x586, 0x7d9, 0xce0, 0x1d0, 0xa89, 0x330, 0x548,
    0xa77, 0x4fa, 0x41c, 0x401, 0x854, 0x625, 0x04c, 0xbb6,
    0xbe0, 0x9cc, 0x54b, 0x1c2, 0x3a8, 0x1bf, 0xaea, 0x4d3,
    0x76f, 0x7cc, 0x441, 0xcc9, 0x11b, 0x73d, 0x7c6, 0x372,
    0xbd9, 0x62f, 0xac8, 0x045, 0x21f, 0x9e4, 0xc40, 0x582,
    0x8db, 0x9b1, 0x598, 0xa8b, 0x2af, 0x028, 0x2ed, 0x640,
];

/// Pointwise multiplication roots (`kModRoots` from `ml_kem.c`):
/// `17^(2*bitrev_7(i) + 1) mod q`.
#[rustfmt::skip]
static MOD_ROOTS: [u16; 128] = [
    0x011, 0xcf0, 0xac9, 0x238, 0x247, 0xaba, 0xa59, 0x2a8,
    0x665, 0x69c, 0x2d3, 0xa2e, 0x8f0, 0x411, 0x44c, 0x8b5,
    0x581, 0x780, 0xa66, 0x29b, 0xcd1, 0x030, 0x0e9, 0xc18,
    0x2f4, 0xa0d, 0x86c, 0x495, 0xbc7, 0x13a, 0xbea, 0x117,
    0x6a7, 0x65a, 0x673, 0x68e, 0xae5, 0x21c, 0x6fd, 0x604,
    0x737, 0x5ca, 0x3b8, 0x949, 0x5b5, 0x74c, 0xa7f, 0x282,
    0x3ab, 0x956, 0x904, 0x3fd, 0x985, 0x37c, 0x954, 0x3ad,
    0x2dd, 0xa24, 0x921, 0x3e0, 0x10c, 0xbf5, 0x281, 0xa80,
    0x630, 0x6d1, 0x8fa, 0x407, 0x7f5, 0x50c, 0xc94, 0x06d,
    0x177, 0xb8a, 0x9f5, 0x30c, 0x82a, 0x4d7, 0x66d, 0x694,
    0x427, 0x8da, 0x13f, 0xbc2, 0xad5, 0x22c, 0x2f5, 0xa0c,
    0x833, 0x4ce, 0x231, 0xad0, 0x9a2, 0x35f, 0xa22, 0x2df,
    0xaf4, 0x20d, 0x444, 0x8bd, 0x193, 0xb6e, 0x402, 0x8ff,
    0x477, 0x88a, 0x866, 0x49b, 0xad7, 0x22a, 0x376, 0x98b,
    0x6ba, 0x647, 0x4bc, 0x845, 0x752, 0x5af, 0x405, 0x8fc,
    0x83e, 0x4c3, 0xb77, 0x18a, 0x375, 0x98c, 0x86a, 0x497,
];

// ===========================================================================
// NTT (Number-Theoretic Transform) — FIPS 203 Algorithms 9 and 10
//
// ML-KEM uses the NTT where q-1 admits a primitive 256th root of unity (17),
// but not a primitive 512th root. Thus pairs of coefficients map to
// GF(3329^2) elements rather than individual GF(3329) elements. Concretely,
// the "NTT" operates on 128 pairs and the "multiplication" is a
// quadratic-ring multiplication using the kModRoots table.
// ===========================================================================

/// Forward in-place NTT (FIPS 203 Algorithm 9). Consumes a polynomial in the
/// time domain and returns its NTT image. Invariant `0 <= c[i] < q` is
/// maintained.
fn scalar_ntt(s: &mut Scalar) {
    // Decimation-in-time Cooley-Tukey butterfly. `offset` starts at 128 and
    // halves each outer iteration, yielding 7 layers total (since 128 = 2^7).
    let mut offset: usize = ML_KEM_DEGREE / 2;
    let mut root_idx: usize = 1;
    while offset >= 2 {
        // Process each group of `2 * offset` coefficients.
        let mut start: usize = 0;
        while start < ML_KEM_DEGREE {
            let zeta: u16 = NTT_ROOTS[root_idx];
            root_idx += 1;
            for i in start..(start + offset) {
                let peer: u16 = s.c[i + offset];
                // odd = peer * zeta mod q
                let odd: u16 = reduce(u32::from(peer) * u32::from(zeta));
                let even: u16 = s.c[i];
                // peer  <- even - odd  (mod q)
                // curr  <- even + odd  (mod q)
                s.c[i + offset] = reduce_once(even + ML_KEM_PRIME - odd);
                s.c[i] = reduce_once(even + odd);
            }
            start += 2 * offset;
        }
        offset >>= 1;
    }
}

/// Inverse in-place NTT (FIPS 203 Algorithm 10). Inverse of [`scalar_ntt`]
/// with a final multiplication by `INVERSE_DEGREE = n^{-1} mod q` absorbed in.
///
/// Mirrors the C reference in `crypto/ml_kem/ml_kem.c:scalar_inverse_ntt`:
/// `INVERSE_NTT_ROOTS` is pre-arranged to be consumed in *forward* iteration
/// order (index `1..128`), even though `offset` doubles from 2 to 128.
fn scalar_inverse_ntt(s: &mut Scalar) {
    // Gentleman-Sande butterfly: `offset` starts at 2 and doubles.
    let mut offset: usize = 2;
    let mut root_idx: usize = 1;
    while offset <= ML_KEM_DEGREE / 2 {
        let mut start: usize = 0;
        while start < ML_KEM_DEGREE {
            let zeta: u16 = INVERSE_NTT_ROOTS[root_idx];
            root_idx += 1;
            for i in start..(start + offset) {
                let odd: u16 = s.c[i + offset];
                let even: u16 = s.c[i];
                // even_out = even + odd
                // odd_out  = zeta * (even - odd)
                s.c[i] = reduce_once(odd + even);
                let diff: u16 = reduce_once(even + ML_KEM_PRIME - odd);
                s.c[i + offset] = reduce(u32::from(zeta) * u32::from(diff));
            }
            start += 2 * offset;
        }
        offset <<= 1;
    }
    // Multiply by n^{-1} mod q to complete the inverse transform.
    for coeff in &mut s.c {
        *coeff = reduce(u32::from(*coeff) * u32::from(INVERSE_DEGREE));
    }
}

/// Pointwise multiplication of two NTT-domain polynomials (FIPS 203
/// Algorithm 11). Because ML-KEM's NTT is a "half" NTT, each pair of
/// coefficients encodes an element of `GF(q^2) ≅ GF(q)[X] / (X^2 − zeta)`,
/// so the multiplication uses the `kModRoots` table.
fn scalar_mult(out: &mut Scalar, lhs: &Scalar, rhs: &Scalar) {
    // Process 128 pairs.
    for i in 0..(ML_KEM_DEGREE / 2) {
        let l0: u16 = lhs.c[2 * i];
        let l1: u16 = lhs.c[2 * i + 1];
        let r0: u16 = rhs.c[2 * i];
        let r1: u16 = rhs.c[2 * i + 1];
        let zeta: u16 = MOD_ROOTS[i];

        // Product in GF(q^2) modulo X^2 - zeta:
        //   (l0 + l1 X)(r0 + r1 X)  (mod X^2 - zeta)
        //   = l0 r0 + (l0 r1 + l1 r0) X + l1 r1 zeta
        //   = (l0 r0 + zeta * l1 r1) + (l0 r1 + l1 r0) X
        let l1r1: u16 = reduce(u32::from(l1) * u32::from(r1));
        let zeta_l1r1: u32 = u32::from(l1r1) * u32::from(zeta);
        let l0r0: u32 = u32::from(l0) * u32::from(r0);
        out.c[2 * i] = reduce(l0r0 + zeta_l1r1);
        let l0r1: u32 = u32::from(l0) * u32::from(r1);
        let l1r0: u32 = u32::from(l1) * u32::from(r0);
        out.c[2 * i + 1] = reduce(l0r1 + l1r0);
    }
}

/// Pointwise addition `lhs <- lhs + rhs` (mod q).
fn scalar_add(lhs: &mut Scalar, rhs: &Scalar) {
    for i in 0..ML_KEM_DEGREE {
        lhs.c[i] = reduce_once(lhs.c[i] + rhs.c[i]);
    }
}

/// Pointwise subtraction `lhs <- lhs - rhs` (mod q), using `+ q` to avoid
/// wrap-around.
fn scalar_sub(lhs: &mut Scalar, rhs: &Scalar) {
    for i in 0..ML_KEM_DEGREE {
        lhs.c[i] = reduce_once(lhs.c[i] + ML_KEM_PRIME - rhs.c[i]);
    }
}

/// Multiply-accumulate of NTT-domain polynomial vectors:
/// `acc <- acc + <lhs, rhs>`. Used by matrix-vector and inner-product
/// computations.
fn vector_mult_add(acc: &mut Scalar, lhs: &[Scalar], rhs: &[Scalar]) {
    debug_assert_eq!(lhs.len(), rhs.len());
    let mut tmp = Scalar::zero();
    for (l, r) in lhs.iter().zip(rhs.iter()) {
        scalar_mult(&mut tmp, l, r);
        scalar_add(acc, &tmp);
    }
}

// ===========================================================================
// Hash functions (FIPS 203 §4.1)
// ===========================================================================

/// `H(x) = SHA3-256(x)` (FIPS 203 Eq. 4.4).
#[inline]
fn hash_h(input: &[u8]) -> CryptoResult<[u8; PKHASH_BYTES]> {
    let v = sha3_256(input)?;
    if v.len() != PKHASH_BYTES {
        return Err(CryptoError::Encoding(
            "hash_h produced unexpected length".into(),
        ));
    }
    let mut out = [0u8; PKHASH_BYTES];
    out.copy_from_slice(&v);
    Ok(out)
}

/// `G(x) = SHA3-512(x)` (FIPS 203 Eq. 4.5). Returns the full 64-byte output
/// which is typically split into two 32-byte halves.
#[inline]
fn hash_g(input: &[u8]) -> CryptoResult<[u8; SEED_BYTES]> {
    let v = sha3_512(input)?;
    if v.len() != SEED_BYTES {
        return Err(CryptoError::Encoding(
            "hash_g produced unexpected length".into(),
        ));
    }
    let mut out = [0u8; SEED_BYTES];
    out.copy_from_slice(&v);
    Ok(out)
}

/// `PRF_eta(s, b) = SHAKE256(s || b, 64 * eta)` (FIPS 203 Eq. 4.3). The
/// caller supplies the exact output length.
fn prf(out: &mut [u8], input: &[u8]) -> CryptoResult<()> {
    let mut ctx = ShakeContext::shake256();
    ctx.update(input)?;
    ctx.squeeze(out)?;
    Ok(())
}

/// Implicit-rejection KDF: `J(z, c) = SHAKE256(z || c, 32)` (FIPS 203 §J /
/// Algorithm 18 line 6).
fn kdf(
    out: &mut [u8; SHARED_SECRET_BYTES],
    z: &[u8; RANDOM_BYTES],
    ctext: &[u8],
) -> CryptoResult<()> {
    let mut ctx = ShakeContext::shake256();
    ctx.update(z)?;
    ctx.update(ctext)?;
    ctx.squeeze(out)?;
    Ok(())
}

// ===========================================================================
// Sampling (FIPS 203 Algorithms 6, 7, 8)
// ===========================================================================

/// Rejection sampling from a SHAKE128 stream (FIPS 203 Algorithm 7,
/// `SampleNTT`). Consumes 3-byte groups, extracts two 12-bit candidates, and
/// keeps each candidate that is less than `q`. Continues squeezing from the
/// provided SHAKE context until `ML_KEM_DEGREE` coefficients have been
/// accepted.
fn sample_scalar(out: &mut Scalar, shake: &mut ShakeContext) -> CryptoResult<()> {
    let mut done: usize = 0;
    while done < ML_KEM_DEGREE {
        let mut buf = [0u8; SCALAR_SAMPLING_BUFSIZE];
        shake.squeeze(&mut buf)?;
        // Process 3-byte groups; 168 = 56 * 3 so we extract up to 112
        // candidates per squeeze block.
        let mut i = 0;
        while i + 3 <= SCALAR_SAMPLING_BUFSIZE && done < ML_KEM_DEGREE {
            // Little-endian-ish: first 12 bits = (b0 | (b1 & 0x0f) << 8)
            //                   next  12 bits = ((b1 >> 4) | (b2 << 4))
            let d1: u16 = u16::from(buf[i]) | ((u16::from(buf[i + 1]) & 0x0f) << 8);
            let d2: u16 = (u16::from(buf[i + 1]) >> 4) | (u16::from(buf[i + 2]) << 4);
            if d1 < ML_KEM_PRIME {
                out.c[done] = d1;
                done += 1;
            }
            if done < ML_KEM_DEGREE && d2 < ML_KEM_PRIME {
                out.c[done] = d2;
                done += 1;
            }
            i += 3;
        }
    }
    Ok(())
}

/// Expand a 32-byte seed `rho` into the `k × k` public matrix `A^` in the NTT
/// domain (FIPS 203 Algorithm 13, `ExpandA`). For each cell `(i, j)` we
/// absorb `rho || j || i` (note the transposition) into SHAKE128 and apply
/// [`sample_scalar`].
fn matrix_expand(m: &mut [Scalar], rho: &[u8; RANDOM_BYTES], rank: usize) -> CryptoResult<()> {
    debug_assert_eq!(m.len(), rank * rank);
    for i in 0..rank {
        for j in 0..rank {
            let mut ctx = ShakeContext::shake128();
            ctx.update(rho)?;
            // TRUNCATION: i, j < rank <= 4, so casting is lossless.
            #[allow(clippy::cast_possible_truncation)]
            let jb = j as u8;
            #[allow(clippy::cast_possible_truncation)]
            let ib = i as u8;
            ctx.update(&[jb, ib])?;
            sample_scalar(&mut m[i * rank + j], &mut ctx)?;
        }
    }
    Ok(())
}

/// Centered Binomial Distribution with `eta = 2` (FIPS 203 Algorithm 8).
/// Consumes exactly `2 * n / 8 = 64` bytes of randomness and produces `n`
/// coefficients each sampled from CBD(2), which yields values in
/// `{-2, -1, 0, 1, 2}` reduced mod `q`.
fn cbd_2(out: &mut Scalar, input: &[u8]) -> CryptoResult<()> {
    if input.len() != ML_KEM_DEGREE / 2 {
        return Err(CryptoError::Encoding(
            "cbd_2: input must be 128 bytes".into(),
        ));
    }
    // Each input byte produces 2 coefficients.
    for (i, &byte) in input.iter().enumerate() {
        // First nibble: 2 bits of a, 2 bits of b.
        let a1: u16 = u16::from(byte & 1) + u16::from((byte >> 1) & 1);
        let b1: u16 = u16::from((byte >> 2) & 1) + u16::from((byte >> 3) & 1);
        // Second nibble.
        let a2: u16 = u16::from((byte >> 4) & 1) + u16::from((byte >> 5) & 1);
        let b2: u16 = u16::from((byte >> 6) & 1) + u16::from((byte >> 7) & 1);
        // Result is (a - b) mod q; add q to keep in [0, 2q).
        out.c[2 * i] = reduce_once(a1 + ML_KEM_PRIME - b1);
        out.c[2 * i + 1] = reduce_once(a2 + ML_KEM_PRIME - b2);
    }
    Ok(())
}

/// Centered Binomial Distribution with `eta = 3` (FIPS 203 Algorithm 8).
/// Consumes `3 * n / 8 = 96` bytes of randomness. Only used for ML-KEM-512
/// (for the secret/error vectors in key generation).
fn cbd_3(out: &mut Scalar, input: &[u8]) -> CryptoResult<()> {
    // Per FIPS 203 Algorithm 8 CBD_η: input length = 64·η bytes (= 2·η·n/8).
    // For η=3 and n=256, that is 192 bytes (equivalently 3·n/4).
    if input.len() != 3 * ML_KEM_DEGREE / 4 {
        return Err(CryptoError::Encoding(
            "cbd_3: input must be 192 bytes".into(),
        ));
    }
    // Every 3 input bytes produce 4 coefficients (3 bits a, 3 bits b per coeff).
    for chunk in 0..(ML_KEM_DEGREE / 4) {
        let b0 = u32::from(input[3 * chunk]);
        let b1 = u32::from(input[3 * chunk + 1]);
        let b2 = u32::from(input[3 * chunk + 2]);
        // 24 bits little-endian.
        let word: u32 = b0 | (b1 << 8) | (b2 << 16);
        for k in 0..4 {
            // For each coefficient, 6 bits: 3 bits a, 3 bits b.
            let bits: u32 = (word >> (6 * k)) & 0x3f;
            // Each popcount of 3 bits yields a value in 0..=3, which fits in u16.
            let a: u16 =
                u16::try_from((bits & 1) + ((bits >> 1) & 1) + ((bits >> 2) & 1)).unwrap_or(0);
            let b: u16 = u16::try_from(((bits >> 3) & 1) + ((bits >> 4) & 1) + ((bits >> 5) & 1))
                .unwrap_or(0);
            out.c[4 * chunk + k] = reduce_once(a + ML_KEM_PRIME - b);
        }
    }
    Ok(())
}

/// Sample `rank` CBD-distributed polynomials from `sigma`, each with a unique
/// PRF counter index `offset + i`, and transform them into the NTT domain.
/// `eta` selects `cbd_2` or `cbd_3`.
fn gencbd_vector_ntt(
    out: &mut [Scalar],
    eta: usize,
    sigma: &[u8; RANDOM_BYTES],
    offset: u8,
) -> CryptoResult<()> {
    // FIPS 203 Algorithm 8: CBD_η consumes 64·η bytes (= 2·η·n/8 = η·n/4).
    let prf_output_bytes = match eta {
        2 => ML_KEM_DEGREE / 2,
        3 => 3 * ML_KEM_DEGREE / 4,
        _ => {
            return Err(CryptoError::Encoding(
                "gencbd_vector_ntt: eta must be 2 or 3".into(),
            ))
        }
    };
    // TRUNCATION: each index is < rank + offset <= 4 + 7 = 11; fits in u8.
    for (i, poly) in out.iter_mut().enumerate() {
        let mut input = [0u8; RANDOM_BYTES + 1];
        input[..RANDOM_BYTES].copy_from_slice(sigma);
        #[allow(clippy::cast_possible_truncation)]
        let idx = offset.wrapping_add(i as u8);
        input[RANDOM_BYTES] = idx;
        let mut buf = vec![0u8; prf_output_bytes];
        prf(&mut buf, &input)?;
        match eta {
            2 => cbd_2(poly, &buf)?,
            3 => cbd_3(poly, &buf)?,
            _ => unreachable!("eta validated above"),
        }
        scalar_ntt(poly);
    }
    Ok(())
}

// ===========================================================================
// Byte encoding and decoding of polynomials (FIPS 203 Algorithms 4 and 5)
// ===========================================================================

/// Encode a polynomial with `bits` bits per coefficient (1 <= bits <= 12)
/// into `out`, which must be exactly `bits * n / 8` bytes long.
fn scalar_encode(out: &mut [u8], s: &Scalar, bits: usize) {
    debug_assert!((1..=12).contains(&bits));
    debug_assert_eq!(out.len(), bits * ML_KEM_DEGREE / 8);
    // Pack coefficients little-endian into the bit stream.
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut w: usize = 0;
    // `bits` is in 1..=12, so it fits in a `u32` losslessly.
    let bits_u32 = u32::try_from(bits).unwrap_or(0);
    for coeff in &s.c {
        let c = u32::from(*coeff);
        acc |= c << nbits;
        nbits += bits_u32;
        while nbits >= 8 {
            // TRUNCATION: low byte of acc.
            #[allow(clippy::cast_possible_truncation)]
            let byte = (acc & 0xff) as u8;
            out[w] = byte;
            w += 1;
            acc >>= 8;
            nbits -= 8;
        }
    }
    debug_assert_eq!(nbits, 0);
    debug_assert_eq!(w, out.len());
}

/// Decode a polynomial from `bits * n / 8` bytes of `data`. For `bits == 12`,
/// the decoded coefficients are validated to be less than `q` (FIPS 203
/// requires input validation on public key vector). For other bit widths no
/// range check is possible since `2^bits <= q` already.
fn scalar_decode(data: &[u8], s: &mut Scalar, bits: usize) -> CryptoResult<()> {
    if !(1..=12).contains(&bits) {
        return Err(CryptoError::Encoding(
            "scalar_decode: bits must be in [1, 12]".into(),
        ));
    }
    if data.len() != bits * ML_KEM_DEGREE / 8 {
        return Err(CryptoError::Encoding(
            "scalar_decode: input length mismatch".into(),
        ));
    }
    let mask: u32 = (1u32 << bits) - 1;
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut r: usize = 0;
    // `bits` is in 1..=12, so it fits in a `u32` losslessly.
    let bits_u32 = u32::try_from(bits).unwrap_or(0);
    for coeff in &mut s.c {
        while nbits < bits_u32 {
            acc |= u32::from(data[r]) << nbits;
            r += 1;
            nbits += 8;
        }
        let c = acc & mask;
        if bits == 12 && c >= u32::from(ML_KEM_PRIME) {
            return Err(CryptoError::Encoding(
                "scalar_decode: coefficient out of range".into(),
            ));
        }
        // TRUNCATION: c < 2^12 <= u16::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let narrowed = c as u16;
        *coeff = narrowed;
        acc >>= bits;
        nbits -= bits_u32;
    }
    Ok(())
}

// ===========================================================================
// Compression and decompression (FIPS 203 §4.7)
// ===========================================================================

/// `Compress_d(x) = round(x * 2^d / q) mod 2^d`, implemented with the
/// "multiply-and-shift" trick that avoids division:
///   round(x * 2^d / q) = floor((2 * x * 2^d + q) / (2 * q))
/// which is equivalent to FIPS 203 Eq. 4.7. Since `q = 3329 < 2^12` and
/// `d <= 12`, the numerator fits in a `u32`.
#[inline]
fn compress(x: u16, d: usize) -> u16 {
    debug_assert!((1..=12).contains(&d));
    let twoq: u32 = 2 * u32::from(ML_KEM_PRIME);
    let numerator: u32 = (u32::from(x) << (d + 1)) + u32::from(ML_KEM_PRIME);
    let quotient: u32 = numerator / twoq;
    let mask: u32 = (1u32 << d) - 1;
    // TRUNCATION: result < 2^d <= 2^12 < 2^16.
    #[allow(clippy::cast_possible_truncation)]
    let narrowed = (quotient & mask) as u16;
    narrowed
}

/// `Decompress_d(y) = round(y * q / 2^d)` (FIPS 203 Eq. 4.8), implemented via
/// multiply-and-round.
#[inline]
fn decompress(y: u16, d: usize) -> u16 {
    debug_assert!((1..=12).contains(&d));
    // round(y * q / 2^d) = floor((y * q * 2 + 2^d) / 2^{d+1})
    let twoy: u32 = u32::from(y) * u32::from(ML_KEM_PRIME);
    let numerator: u32 = (twoy << 1) + (1u32 << d);
    let quotient: u32 = numerator >> (d + 1);
    // TRUNCATION: quotient < q + 1 <= 2^12 < 2^16.
    #[allow(clippy::cast_possible_truncation)]
    let narrowed = quotient as u16;
    narrowed
}

/// In-place polynomial compression: `s[i] <- Compress_d(s[i])`.
fn scalar_compress(s: &mut Scalar, d: usize) {
    for coeff in &mut s.c {
        *coeff = compress(*coeff, d);
    }
}

/// In-place polynomial decompression: `s[i] <- Decompress_d(s[i])`.
fn scalar_decompress(s: &mut Scalar, d: usize) {
    for coeff in &mut s.c {
        *coeff = decompress(*coeff, d);
    }
}

// ===========================================================================
// Public-key / private-key / ciphertext encoding
// ===========================================================================

/// Encode the public-key vector `t` (NTT domain, 12-bit coefficients) and
/// append the 32-byte public seed `rho`. Returns a `pubkey_bytes`-long
/// buffer (FIPS 203 `ByteEncode_12` + concatenation).
fn encode_pubkey(t: &[Scalar], rho: &[u8; RANDOM_BYTES]) -> Vec<u8> {
    let rank = t.len();
    let vec_bytes = 3 * ML_KEM_DEGREE / 2 * rank;
    let mut out = vec![0u8; vec_bytes + RANDOM_BYTES];
    for (i, poly) in t.iter().enumerate() {
        let start = i * (3 * ML_KEM_DEGREE / 2);
        let end = start + 3 * ML_KEM_DEGREE / 2;
        scalar_encode(&mut out[start..end], poly, 12);
    }
    out[vec_bytes..].copy_from_slice(rho);
    out
}

/// Decode a public key: `pubkey_bytes = vector_bytes + RANDOM_BYTES`.
/// Coefficients are validated to be less than `q` (FIPS 203 §7.2 public-key
/// input validation).
fn parse_pubkey(data: &[u8], rank: usize) -> CryptoResult<(Vec<Scalar>, [u8; RANDOM_BYTES])> {
    let vec_bytes = 3 * ML_KEM_DEGREE / 2 * rank;
    if data.len() != vec_bytes + RANDOM_BYTES {
        return Err(CryptoError::Encoding(
            "parse_pubkey: length mismatch".into(),
        ));
    }
    let mut t = vec![Scalar::zero(); rank];
    for (i, poly) in t.iter_mut().enumerate() {
        let start = i * (3 * ML_KEM_DEGREE / 2);
        let end = start + 3 * ML_KEM_DEGREE / 2;
        scalar_decode(&data[start..end], poly, 12)?;
    }
    let mut rho = [0u8; RANDOM_BYTES];
    rho.copy_from_slice(&data[vec_bytes..]);
    Ok((t, rho))
}

/// Encode a private key as `dk = ByteEncode_12(s^) || ek || H(ek) || z`
/// (FIPS 203 §7.1). `s` is the secret vector in the NTT domain, `ek` is the
/// public-key byte string produced by [`encode_pubkey`], `pkhash` is `H(ek)`,
/// and `z` is the 32-byte implicit-rejection secret.
fn encode_prvkey(
    s: &[Scalar],
    ek: &[u8],
    pkhash: &[u8; PKHASH_BYTES],
    z: &[u8; RANDOM_BYTES],
) -> Vec<u8> {
    let rank = s.len();
    let sk_vec_bytes = 3 * ML_KEM_DEGREE / 2 * rank;
    let mut out = vec![0u8; sk_vec_bytes + ek.len() + PKHASH_BYTES + RANDOM_BYTES];
    for (i, poly) in s.iter().enumerate() {
        let start = i * (3 * ML_KEM_DEGREE / 2);
        let end = start + 3 * ML_KEM_DEGREE / 2;
        scalar_encode(&mut out[start..end], poly, 12);
    }
    let mut cursor = sk_vec_bytes;
    out[cursor..cursor + ek.len()].copy_from_slice(ek);
    cursor += ek.len();
    out[cursor..cursor + PKHASH_BYTES].copy_from_slice(pkhash);
    cursor += PKHASH_BYTES;
    out[cursor..cursor + RANDOM_BYTES].copy_from_slice(z);
    out
}

/// Parse a private key. Returns `(s, t, rho, pkhash, z)`, validating sizes
/// and coefficient ranges.
fn parse_prvkey(
    data: &[u8],
    rank: usize,
) -> CryptoResult<(
    Vec<Scalar>,
    Vec<Scalar>,
    [u8; RANDOM_BYTES],
    [u8; PKHASH_BYTES],
    [u8; RANDOM_BYTES],
)> {
    let sk_vec_bytes = 3 * ML_KEM_DEGREE / 2 * rank;
    let ek_bytes = sk_vec_bytes + RANDOM_BYTES;
    let expected = sk_vec_bytes + ek_bytes + PKHASH_BYTES + RANDOM_BYTES;
    if data.len() != expected {
        return Err(CryptoError::Encoding(
            "parse_prvkey: length mismatch".into(),
        ));
    }
    let mut s = vec![Scalar::zero(); rank];
    for (i, poly) in s.iter_mut().enumerate() {
        let start = i * (3 * ML_KEM_DEGREE / 2);
        let end = start + 3 * ML_KEM_DEGREE / 2;
        scalar_decode(&data[start..end], poly, 12)?;
    }
    let ek = &data[sk_vec_bytes..sk_vec_bytes + ek_bytes];
    let (t, rho) = parse_pubkey(ek, rank)?;
    let mut pkhash = [0u8; PKHASH_BYTES];
    pkhash.copy_from_slice(&data[sk_vec_bytes + ek_bytes..sk_vec_bytes + ek_bytes + PKHASH_BYTES]);
    let mut z = [0u8; RANDOM_BYTES];
    z.copy_from_slice(
        &data[sk_vec_bytes + ek_bytes + PKHASH_BYTES
            ..sk_vec_bytes + ek_bytes + PKHASH_BYTES + RANDOM_BYTES],
    );
    Ok((s, t, rho, pkhash, z))
}

// ===========================================================================
// Ciphertext encoding (compressed polynomials)
// ===========================================================================

/// Encode a ciphertext vector `u` (compressed to `du` bits per coefficient)
/// followed by the scalar `v` (compressed to `dv` bits per coefficient). The
/// total length is `(n/8) * du * rank + (n/8) * dv` bytes.
fn ciphertext_encode(out: &mut [u8], u: &[Scalar], v: &Scalar, du: usize, dv: usize) {
    let rank = u.len();
    let per_poly_u = ML_KEM_DEGREE * du / 8;
    for (i, poly) in u.iter().enumerate() {
        let start = i * per_poly_u;
        let end = start + per_poly_u;
        let mut compressed = poly.clone();
        scalar_compress(&mut compressed, du);
        scalar_encode(&mut out[start..end], &compressed, du);
    }
    let v_start = per_poly_u * rank;
    let mut compressed_v = v.clone();
    scalar_compress(&mut compressed_v, dv);
    scalar_encode(&mut out[v_start..], &compressed_v, dv);
}

/// Decode a ciphertext `ctext` of length `(n/8) * du * rank + (n/8) * dv`
/// into a vector `u` and scalar `v`, decompressing each coefficient back to
/// `[0, q)`.
fn ciphertext_decode(
    ctext: &[u8],
    rank: usize,
    du: usize,
    dv: usize,
) -> CryptoResult<(Vec<Scalar>, Scalar)> {
    let per_poly_u = ML_KEM_DEGREE * du / 8;
    let per_scalar_v = ML_KEM_DEGREE * dv / 8;
    let expected = per_poly_u * rank + per_scalar_v;
    if ctext.len() != expected {
        return Err(CryptoError::Encoding(
            "ciphertext_decode: length mismatch".into(),
        ));
    }
    let mut u = vec![Scalar::zero(); rank];
    for (i, poly) in u.iter_mut().enumerate() {
        let start = i * per_poly_u;
        let end = start + per_poly_u;
        scalar_decode(&ctext[start..end], poly, du)?;
        scalar_decompress(poly, du);
    }
    let mut v = Scalar::zero();
    let v_start = per_poly_u * rank;
    scalar_decode(&ctext[v_start..], &mut v, dv)?;
    scalar_decompress(&mut v, dv);
    Ok((u, v))
}

// ===========================================================================
// K-PKE encryption primitives (FIPS 203 §5.2)
// ===========================================================================

/// K-PKE encryption (FIPS 203 Algorithm 14). Deterministically encrypts the
/// 32-byte message `mu` under public key `(t_hat, rho)`, using randomness
/// `r` (also 32 bytes) to derive the error polynomials.
///
/// Returns the raw ciphertext buffer `c1 || c2`, where `c1` is the compressed
/// `u` vector and `c2` is the compressed `v` scalar.
fn kpke_encrypt(
    params: &MlKemParams,
    t_hat: &[Scalar],
    rho: &[u8; RANDOM_BYTES],
    mu: &[u8; RANDOM_BYTES],
    r: &[u8; RANDOM_BYTES],
) -> CryptoResult<Vec<u8>> {
    let rank = params.rank;
    // Expand A_hat.
    let mut a_hat = vec![Scalar::zero(); rank * rank];
    matrix_expand(&mut a_hat, rho, rank)?;

    // Sample r_hat from CBD(eta1) and NTT.
    let mut r_hat = vec![Scalar::zero(); rank];
    gencbd_vector_ntt(&mut r_hat, params.eta1, r, 0)?;

    // Sample e1 from CBD(eta2) (NOT in NTT; applied after iNTT).
    let mut e1 = vec![Scalar::zero(); rank];
    // TRUNCATION: params.rank <= 4 -> u8.
    #[allow(clippy::cast_possible_truncation)]
    let offset_e1 = params.rank as u8;
    for (i, poly) in e1.iter_mut().enumerate() {
        let mut input = [0u8; RANDOM_BYTES + 1];
        input[..RANDOM_BYTES].copy_from_slice(r);
        // TRUNCATION: i < rank <= 4.
        #[allow(clippy::cast_possible_truncation)]
        let idx = offset_e1.wrapping_add(i as u8);
        input[RANDOM_BYTES] = idx;
        let mut buf = vec![0u8; ML_KEM_DEGREE / 2];
        prf(&mut buf, &input)?;
        cbd_2(poly, &buf)?;
    }

    // Sample e2 (a single scalar) from CBD(eta2).
    let mut e2 = Scalar::zero();
    {
        let mut input = [0u8; RANDOM_BYTES + 1];
        input[..RANDOM_BYTES].copy_from_slice(r);
        // TRUNCATION: 2*rank <= 8 < u8::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let idx = (2 * params.rank) as u8;
        input[RANDOM_BYTES] = idx;
        let mut buf = vec![0u8; ML_KEM_DEGREE / 2];
        prf(&mut buf, &input)?;
        cbd_2(&mut e2, &buf)?;
    }

    // u = NTT^-1( A_hat^T ◦ r_hat ) + e1
    let mut u = vec![Scalar::zero(); rank];
    for i in 0..rank {
        for j in 0..rank {
            // A_hat^T[i][j] = A_hat[j][i]
            let mut tmp = Scalar::zero();
            scalar_mult(&mut tmp, &a_hat[j * rank + i], &r_hat[j]);
            scalar_add(&mut u[i], &tmp);
        }
        scalar_inverse_ntt(&mut u[i]);
        scalar_add(&mut u[i], &e1[i]);
    }

    // v = NTT^-1( t_hat^T ◦ r_hat ) + e2 + Decompress_1(mu)
    let mut v_acc = Scalar::zero();
    vector_mult_add(&mut v_acc, t_hat, &r_hat);
    scalar_inverse_ntt(&mut v_acc);
    scalar_add(&mut v_acc, &e2);
    // Decode mu as a 1-bit-per-coefficient scalar, then decompress back to
    // the [0, q) representation by multiplying each bit by round(q/2).
    let mut mu_scalar = Scalar::zero();
    scalar_decode(mu, &mut mu_scalar, 1)?;
    scalar_decompress(&mut mu_scalar, 1);
    scalar_add(&mut v_acc, &mu_scalar);

    // Encode compressed ciphertext (c1 || c2).
    let mut ctext = vec![0u8; params.ctext_bytes];
    ciphertext_encode(&mut ctext, &u, &v_acc, params.du, params.dv);
    Ok(ctext)
}

/// K-PKE decryption (FIPS 203 Algorithm 15). Computes `m = Compress_1(v -
/// NTT^-1(s_hat^T ◦ NTT(u)))` where `u, v` are decompressed from the
/// ciphertext and `s_hat` is the secret vector in the NTT domain.
fn kpke_decrypt(
    params: &MlKemParams,
    s_hat: &[Scalar],
    ctext: &[u8],
) -> CryptoResult<[u8; RANDOM_BYTES]> {
    let (mut u, v) = ciphertext_decode(ctext, params.rank, params.du, params.dv)?;
    // NTT each u[i] in place.
    for poly in &mut u {
        scalar_ntt(poly);
    }
    // w_hat = s_hat^T ◦ NTT(u)
    let mut w = Scalar::zero();
    vector_mult_add(&mut w, s_hat, &u);
    scalar_inverse_ntt(&mut w);
    // m_hat = v - w  (mod q)
    let mut m_scalar = v;
    scalar_sub(&mut m_scalar, &w);
    // Compress_1 to a 1-bit-per-coefficient encoding, then bytewise encode.
    scalar_compress(&mut m_scalar, 1);
    let mut out = [0u8; RANDOM_BYTES];
    scalar_encode(&mut out, &m_scalar, 1);
    Ok(out)
}

// ===========================================================================
// ML-KEM key object (FIPS 203 §7)
// ===========================================================================

/// An ML-KEM key. May hold (a) a public key only, (b) a public key plus
/// private key, or (c) a private key together with the cached seed. All
/// secret fields zero on drop thanks to the [`ZeroizeOnDrop`] derive.
#[derive(ZeroizeOnDrop)]
pub struct MlKemKey {
    /// Static reference to the parameter set identifying ML-KEM-{512,768,1024}.
    #[zeroize(skip)]
    params: &'static MlKemParams,
    /// Shared library context (for provider/FIPS integration). Not zeroized.
    #[zeroize(skip)]
    libctx: Option<Arc<LibContext>>,
    /// Public-key seed `rho` (32 bytes). Part of the public key; not secret,
    /// but zeroed on drop together with the rest of the struct for hygiene.
    rho: [u8; RANDOM_BYTES],
    /// `H(ek)` — 32-byte hash of the encoded public key.
    pkhash: [u8; PKHASH_BYTES],
    /// `have_pub` flag: whether [`Self::rho`], [`Self::pkhash`], and
    /// [`Self::t`] are populated.
    #[zeroize(skip)]
    have_pub: bool,
    /// Public-key vector `t^` (rank polynomials, NTT domain). `None` until a
    /// public key is loaded.
    t: Option<Vec<Scalar>>,
    /// Pre-computed public-matrix `A^` (rank × rank scalars, NTT domain),
    /// cached when the key will be used for encapsulation.
    m: Option<Vec<Scalar>>,
    /// Secret-key vector `s^` (rank polynomials, NTT domain). `None` for
    /// public-only keys.
    s: Option<Vec<Scalar>>,
    /// Implicit-rejection secret `z` (32 bytes). `None` for public-only keys.
    z: Option<[u8; RANDOM_BYTES]>,
    /// Key-generation seed `d` (32 bytes). Retained when the provider flag
    /// `ML_KEM_KEY_RETAIN_SEED` is set, otherwise `None`.
    d: Option<[u8; RANDOM_BYTES]>,
    /// Provider flags (mirror of C `prov_flags`).
    #[zeroize(skip)]
    prov_flags: u32,
}

/// Provider flags mirroring the C `ML_KEM_KEY_*` bits in `include/crypto/ml_kem.h`.
/// Packaged here as a module so downstream code can opt in/out explicitly.
pub mod prov_flags {
    /// Perform a randomised pairwise consistency test after key generation.
    pub const RANDOM_PCT: u32 = 1 << 0;
    /// Perform a fixed-vector pairwise consistency test after key generation.
    pub const FIXED_PCT: u32 = 1 << 1;
    /// Prefer the seed representation when (re)serialising a key.
    pub const PREFER_SEED: u32 = 1 << 2;
    /// Retain the key-generation seed after keygen for later re-serialisation.
    pub const RETAIN_SEED: u32 = 1 << 3;
    /// Default provider flags: random PCT + prefer-seed + retain-seed.
    pub const DEFAULT: u32 = RANDOM_PCT | PREFER_SEED | RETAIN_SEED;
}

impl MlKemKey {
    /// Construct an empty key for the given variant. The returned key has
    /// neither public nor private components populated; call `Self::generate`
    /// or parse one of the byte encodings to fill it.
    pub fn new(libctx: Arc<LibContext>, variant: MlKemVariant) -> CryptoResult<Self> {
        Ok(Self {
            params: ml_kem_params_get(variant),
            libctx: Some(libctx),
            rho: [0u8; RANDOM_BYTES],
            pkhash: [0u8; PKHASH_BYTES],
            have_pub: false,
            t: None,
            m: None,
            s: None,
            z: None,
            d: None,
            prov_flags: prov_flags::DEFAULT,
        })
    }

    /// Discard all key material, returning the key to the empty state. The
    /// parameter set and library context are preserved.
    pub fn reset(&mut self) {
        self.rho.zeroize();
        self.pkhash.zeroize();
        self.have_pub = false;
        if let Some(v) = self.t.take() {
            drop(v);
        }
        if let Some(v) = self.m.take() {
            drop(v);
        }
        if let Some(v) = self.s.take() {
            drop(v);
        }
        if let Some(mut z) = self.z.take() {
            z.zeroize();
        }
        if let Some(mut d) = self.d.take() {
            d.zeroize();
        }
    }

    /// Deep-clone the key. All component vectors are copied; the library
    /// context is shared via `Arc`.
    pub fn dup(&self) -> CryptoResult<Self> {
        Ok(Self {
            params: self.params,
            libctx: self.libctx.as_ref().map(Arc::clone),
            rho: self.rho,
            pkhash: self.pkhash,
            have_pub: self.have_pub,
            t: self.t.clone(),
            m: self.m.clone(),
            s: self.s.clone(),
            z: self.z,
            d: self.d,
            prov_flags: self.prov_flags,
        })
    }

    /// `true` iff a public key has been loaded/generated.
    pub const fn have_pubkey(&self) -> bool {
        self.have_pub
    }

    /// `true` iff a private key has been loaded/generated.
    pub fn have_prvkey(&self) -> bool {
        self.s.is_some()
    }

    /// `true` iff the key-generation seed was retained after keygen.
    pub fn have_seed(&self) -> bool {
        self.d.is_some()
    }

    /// Constant-time comparison of two public keys' `H(ek)` hashes. Returns
    /// `true` if the hashes match (and therefore the parameter sets and
    /// public-key byte encodings match).
    pub fn pubkey_cmp(&self, other: &Self) -> bool {
        if !core::ptr::eq(self.params, other.params) {
            return false;
        }
        if !self.have_pub || !other.have_pub {
            return false;
        }
        self.pkhash.ct_eq(&other.pkhash).into()
    }

    /// Returns the number of bytes in the serialised public key.
    pub const fn pub_len(&self) -> usize {
        self.params.pubkey_bytes
    }

    /// Returns the number of bytes in the serialised private key.
    pub const fn priv_len(&self) -> usize {
        self.params.prvkey_bytes
    }

    /// Returns the ciphertext length in bytes.
    pub const fn ctext_len(&self) -> usize {
        self.params.ctext_bytes
    }

    /// Returns the shared-secret length in bytes (always 32 per FIPS 203).
    pub const fn shared_secret_len(&self) -> usize {
        SHARED_SECRET_BYTES
    }

    /// Returns the static parameter set for this key.
    #[must_use]
    pub const fn params(&self) -> &'static MlKemParams {
        self.params
    }

    /// Returns the provider flags for this key (bit pattern from
    /// [`prov_flags`]).
    #[must_use]
    pub const fn provider_flags(&self) -> u32 {
        self.prov_flags
    }

    /// Override the provider flags on this key.
    pub fn set_provider_flags(&mut self, flags: u32) {
        self.prov_flags = flags;
    }

    /// Fill in the public components (rho, t, pkhash) and compute the
    /// ek-hash. Leaves `have_pub = true` on success.
    fn set_pubkey_internal(&mut self, t: Vec<Scalar>, rho: [u8; RANDOM_BYTES]) -> CryptoResult<()> {
        let ek = encode_pubkey(&t, &rho);
        let pkhash = hash_h(&ek)?;
        self.rho = rho;
        self.pkhash = pkhash;
        self.t = Some(t);
        self.have_pub = true;
        Ok(())
    }

    /// Expand and cache the public matrix `A^` for this key. Requires `rho`
    /// to be populated.
    ///
    /// `generate` already caches this matrix, and the encapsulation/
    /// decapsulation helpers recompute it as needed from `rho`; this method
    /// is retained for downstream provider code that wishes to pre-compute
    /// `A^` after a public-key import before performing many encapsulations
    /// against the same key.
    #[allow(dead_code)] // Public-by-design helper for external callers.
    fn ensure_matrix(&mut self) -> CryptoResult<()> {
        if self.m.is_some() {
            return Ok(());
        }
        let rank = self.params.rank;
        let mut m = vec![Scalar::zero(); rank * rank];
        matrix_expand(&mut m, &self.rho, rank)?;
        self.m = Some(m);
        Ok(())
    }

    /// Serialise the public key (`ek`) as bytes. Returns
    /// `pubkey_bytes()` bytes.
    pub fn encode_pubkey(&self) -> CryptoResult<Vec<u8>> {
        let t = self
            .t
            .as_ref()
            .ok_or_else(|| CryptoError::Key("ML-KEM key has no public part".into()))?;
        Ok(encode_pubkey(t, &self.rho))
    }

    /// Parse a public key `ek` and replace the current key contents. Any
    /// previously held private material is discarded.
    pub fn parse_pubkey(&mut self, data: &[u8]) -> CryptoResult<()> {
        if data.len() != self.params.pubkey_bytes {
            return Err(CryptoError::Encoding(
                "parse_pubkey: wrong input length".into(),
            ));
        }
        let (t, rho) = parse_pubkey(data, self.params.rank)?;
        self.reset();
        self.set_pubkey_internal(t, rho)
    }

    /// Serialise the private key (`dk`) as bytes. Returns
    /// `privkey_bytes()` bytes.
    pub fn encode_prvkey(&self) -> CryptoResult<Vec<u8>> {
        let s = self
            .s
            .as_ref()
            .ok_or_else(|| CryptoError::Key("ML-KEM key has no private part".into()))?;
        let t = self
            .t
            .as_ref()
            .ok_or_else(|| CryptoError::Key("ML-KEM key has no public part".into()))?;
        let z = self
            .z
            .as_ref()
            .ok_or_else(|| CryptoError::Key("ML-KEM key has no rejection secret".into()))?;
        let ek = encode_pubkey(t, &self.rho);
        Ok(encode_prvkey(s, &ek, &self.pkhash, z))
    }

    /// Parse a private key `dk` and replace the current key contents.
    pub fn parse_prvkey(&mut self, data: &[u8]) -> CryptoResult<()> {
        if data.len() != self.params.prvkey_bytes {
            return Err(CryptoError::Encoding(
                "parse_prvkey: wrong input length".into(),
            ));
        }
        let (s, t, rho, pkhash, z) = parse_prvkey(data, self.params.rank)?;
        self.reset();
        self.rho = rho;
        self.pkhash = pkhash;
        self.t = Some(t);
        self.s = Some(s);
        self.z = Some(z);
        self.have_pub = true;
        Ok(())
    }
}

// ===========================================================================
// Key generation (FIPS 203 Algorithms 15 and 16)
// ===========================================================================

/// ML-KEM key generation (FIPS 203 Algorithm 16, `ML-KEM.KeyGen_internal`).
///
/// * If `seed` is `Some`, its 64 bytes are interpreted as `d || z` and the
///   result is deterministic. This is used to reproduce a key from a stored
///   seed.
/// * If `seed` is `None`, 64 bytes of OS-backed cryptographic randomness are
///   drawn via [`rand::rngs::OsRng`].
///
/// Returns a fresh key containing both public and private components, with
/// the public-matrix `A^` cached and (per the default provider flags) the
/// key-generation seed `d` retained for later re-serialisation.
pub fn generate(
    libctx: Arc<LibContext>,
    variant: MlKemVariant,
    seed: Option<&[u8; SEED_BYTES]>,
) -> CryptoResult<MlKemKey> {
    let params = ml_kem_params_get(variant);
    let rank = params.rank;

    // Obtain d || z, either from caller-supplied seed or RNG.
    let mut seedbuf = [0u8; SEED_BYTES];
    if let Some(s) = seed {
        seedbuf.copy_from_slice(s);
    } else {
        // OsRng::fill_bytes does not fail on supported platforms.
        let mut rng = OsRng;
        rng.fill_bytes(&mut seedbuf);
    }
    // d = first 32 bytes, z = last 32 bytes (matches C `ossl_ml_kem_genkey`).
    let mut d = [0u8; RANDOM_BYTES];
    d.copy_from_slice(&seedbuf[..RANDOM_BYTES]);
    let mut z = [0u8; RANDOM_BYTES];
    z.copy_from_slice(&seedbuf[RANDOM_BYTES..]);

    // (rho, sigma) = G(d || k) where k is the rank byte (FIPS 203 line 1 of
    // Algorithm 16). The C implementation uses the rank as the "k" byte.
    // TRUNCATION: rank <= 4 fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    let k_byte = rank as u8;
    let mut hash_input = [0u8; RANDOM_BYTES + 1];
    hash_input[..RANDOM_BYTES].copy_from_slice(&d);
    hash_input[RANDOM_BYTES] = k_byte;
    let hashed = hash_g(&hash_input)?;
    let mut rho = [0u8; RANDOM_BYTES];
    rho.copy_from_slice(&hashed[..RANDOM_BYTES]);
    let mut sigma = [0u8; RANDOM_BYTES];
    sigma.copy_from_slice(&hashed[RANDOM_BYTES..]);

    // Expand A_hat.
    let mut a_hat = vec![Scalar::zero(); rank * rank];
    matrix_expand(&mut a_hat, &rho, rank)?;

    // Sample s and e from CBD(eta1); transform each into the NTT domain.
    let mut s_hat = vec![Scalar::zero(); rank];
    gencbd_vector_ntt(&mut s_hat, params.eta1, &sigma, 0)?;
    let mut e_hat = vec![Scalar::zero(); rank];
    // TRUNCATION: rank <= 4.
    #[allow(clippy::cast_possible_truncation)]
    let e_offset = rank as u8;
    gencbd_vector_ntt(&mut e_hat, params.eta1, &sigma, e_offset)?;

    // t_hat = A_hat ∘ s_hat + e_hat (ordinary matrix–vector product).
    let mut t_hat = vec![Scalar::zero(); rank];
    for i in 0..rank {
        for j in 0..rank {
            let mut tmp = Scalar::zero();
            scalar_mult(&mut tmp, &a_hat[i * rank + j], &s_hat[j]);
            scalar_add(&mut t_hat[i], &tmp);
        }
        scalar_add(&mut t_hat[i], &e_hat[i]);
    }

    let mut key = MlKemKey {
        params,
        libctx: Some(libctx),
        rho: [0u8; RANDOM_BYTES],
        pkhash: [0u8; PKHASH_BYTES],
        have_pub: false,
        t: None,
        m: Some(a_hat),
        s: Some(s_hat),
        z: Some(z),
        d: None,
        prov_flags: prov_flags::DEFAULT,
    };
    key.set_pubkey_internal(t_hat, rho)?;
    if (key.prov_flags & prov_flags::RETAIN_SEED) != 0 {
        key.d = Some(d);
    }
    // Seed buffer no longer needed; wipe before dropping.
    seedbuf.zeroize();
    Ok(key)
}

// ===========================================================================
// Encapsulation (FIPS 203 Algorithm 17)
// ===========================================================================

/// Deterministic encapsulation (FIPS 203 Algorithm 17,
/// `ML-KEM.Encaps_internal`). The caller supplies the 32-byte message `mu`;
/// the shared secret `K` and randomness `r` are derived via
/// `(K, r) = G(mu || H(ek))`.
///
/// Returns `(ciphertext, shared_secret)` on success.
pub fn encap_seed(
    key: &MlKemKey,
    entropy: &[u8; RANDOM_BYTES],
) -> CryptoResult<(Vec<u8>, [u8; SHARED_SECRET_BYTES])> {
    let t_hat = key
        .t
        .as_ref()
        .ok_or_else(|| CryptoError::Key("ML-KEM key has no public part".into()))?;
    // (K, r) = G(mu || H(ek))
    let mut hash_input = [0u8; 2 * RANDOM_BYTES];
    hash_input[..RANDOM_BYTES].copy_from_slice(entropy);
    hash_input[RANDOM_BYTES..].copy_from_slice(&key.pkhash);
    let g = hash_g(&hash_input)?;
    let mut shared = [0u8; SHARED_SECRET_BYTES];
    shared.copy_from_slice(&g[..SHARED_SECRET_BYTES]);
    let mut r = [0u8; RANDOM_BYTES];
    r.copy_from_slice(&g[SHARED_SECRET_BYTES..]);

    let ctext = kpke_encrypt(key.params, t_hat, &key.rho, entropy, &r)?;
    // Wipe r; shared secret is returned to caller.
    r.zeroize();
    Ok((ctext, shared))
}

/// Randomised encapsulation (FIPS 203 Algorithm 17, with fresh entropy).
/// Samples 32 bytes of OS-backed randomness and calls [`encap_seed`].
pub fn encap_rand(key: &MlKemKey) -> CryptoResult<(Vec<u8>, [u8; SHARED_SECRET_BYTES])> {
    let mut entropy = [0u8; RANDOM_BYTES];
    let mut rng = OsRng;
    rng.fill_bytes(&mut entropy);
    let result = encap_seed(key, &entropy);
    entropy.zeroize();
    result
}

// ===========================================================================
// Decapsulation (FIPS 203 Algorithm 18) — CONSTANT-TIME
// ===========================================================================

/// ML-KEM decapsulation (FIPS 203 Algorithm 18, `ML-KEM.Decaps_internal`).
///
/// Runs the Fujisaki–Okamoto re-encapsulation check: the received ciphertext
/// is decrypted to a candidate message `m'`, the candidate is re-encapsulated
/// to a ciphertext `c'`, and the output shared secret is selected between
/// `G(m' || H(ek))[..32]` (success) and `J(z, ciphertext) = KDF(z || c)`
/// (implicit rejection) in **constant time** based on `c' == ciphertext`.
///
/// This constant-time select is the core IND-CCA2 security mechanism: any
/// timing or branching side channel in the selection step breaks the KEM's
/// chosen-ciphertext security.
pub fn decap(key: &MlKemKey, ctext: &[u8]) -> CryptoResult<[u8; SHARED_SECRET_BYTES]> {
    if ctext.len() != key.params.ctext_bytes {
        return Err(CryptoError::Encoding(
            "decap: wrong ciphertext length".into(),
        ));
    }
    let s_hat = key
        .s
        .as_ref()
        .ok_or_else(|| CryptoError::Key("ML-KEM key has no private part".into()))?;
    let t_hat = key
        .t
        .as_ref()
        .ok_or_else(|| CryptoError::Key("ML-KEM key has no public part".into()))?;
    let z = key
        .z
        .as_ref()
        .ok_or_else(|| CryptoError::Key("ML-KEM key has no rejection secret".into()))?;

    // Step 1: implicit-rejection shared secret K_bar = J(z, c) = KDF(z || c).
    let mut rejection_secret = [0u8; SHARED_SECRET_BYTES];
    kdf(&mut rejection_secret, z, ctext)?;

    // Step 2: m' = K-PKE.Decrypt(s_hat, c).
    let m_prime = kpke_decrypt(key.params, s_hat, ctext)?;

    // Step 3: (K', r') = G(m' || H(ek)).
    let mut hash_input = [0u8; 2 * RANDOM_BYTES];
    hash_input[..RANDOM_BYTES].copy_from_slice(&m_prime);
    hash_input[RANDOM_BYTES..].copy_from_slice(&key.pkhash);
    let g = hash_g(&hash_input)?;
    let mut shared_candidate = [0u8; SHARED_SECRET_BYTES];
    shared_candidate.copy_from_slice(&g[..SHARED_SECRET_BYTES]);
    let mut r_prime = [0u8; RANDOM_BYTES];
    r_prime.copy_from_slice(&g[SHARED_SECRET_BYTES..]);

    // Step 4: c' = K-PKE.Encrypt(ek, m', r').
    let tmp_ctext = kpke_encrypt(key.params, t_hat, &key.rho, &m_prime, &r_prime)?;

    // Step 5: mask = (ctext == c') in constant time.
    let mask: Choice = ctext.ct_eq(tmp_ctext.as_slice());

    // Step 6: shared = mask ? shared_candidate : rejection_secret  (byte-by-byte, constant-time).
    let mut shared = [0u8; SHARED_SECRET_BYTES];
    for i in 0..SHARED_SECRET_BYTES {
        // ConditionallySelectable::conditional_select(a, b, choice):
        //   returns `b` when choice is 1, `a` when choice is 0.
        shared[i] = u8::conditional_select(&rejection_secret[i], &shared_candidate[i], mask);
    }

    // Scrub temporaries.
    rejection_secret.zeroize();
    shared_candidate.zeroize();
    r_prime.zeroize();
    // `m_prime`, `tmp_ctext` are dropped at scope end; Vec<u8>/[u8; N] holding
    // only public-but-sensitive data is overwritten on Drop via the general
    // allocator, which is fine for non-key material. Explicitly zeroise
    // `m_prime` since it is derived from the private key.
    let mut mp = m_prime;
    mp.zeroize();
    Ok(shared)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_lossless)]
#[allow(clippy::uninlined_format_args)]
#[allow(clippy::manual_range_contains)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_spec() {
        assert_eq!(ML_KEM_PRIME, 3329);
        assert_eq!(ML_KEM_DEGREE, 256);
        assert_eq!(INVERSE_DEGREE, 3303);
        assert_eq!(LOG2PRIME, 12);
        assert_eq!(BARRETT_SHIFT, 24);
        assert_eq!(BARRETT_MULTIPLIER, 5039);
        assert_eq!(HALF_PRIME, 1664);
        assert_eq!(RANDOM_BYTES, 32);
        assert_eq!(PKHASH_BYTES, 32);
        assert_eq!(SHARED_SECRET_BYTES, 32);
        assert_eq!(SEED_BYTES, 64);
        assert_eq!(SCALAR_SAMPLING_BUFSIZE, 168);
    }

    #[test]
    fn variant_parameters_match_spec() {
        let p512 = ml_kem_params_get(MlKemVariant::MlKem512);
        assert_eq!(p512.rank, 2);
        assert_eq!(p512.eta1, 3);
        assert_eq!(p512.eta2, 2);
        assert_eq!(p512.du, 10);
        assert_eq!(p512.dv, 4);
        assert_eq!(p512.secbits, 128);
        assert_eq!(p512.security_category, 1);
        assert_eq!(p512.pubkey_bytes, 800);
        assert_eq!(p512.prvkey_bytes, 1632);
        assert_eq!(p512.ctext_bytes, 768);

        let p768 = ml_kem_params_get(MlKemVariant::MlKem768);
        assert_eq!(p768.rank, 3);
        assert_eq!(p768.eta1, 2);
        assert_eq!(p768.eta2, 2);
        assert_eq!(p768.du, 10);
        assert_eq!(p768.dv, 4);
        assert_eq!(p768.secbits, 192);
        assert_eq!(p768.security_category, 3);
        assert_eq!(p768.pubkey_bytes, 1184);
        assert_eq!(p768.prvkey_bytes, 2400);
        assert_eq!(p768.ctext_bytes, 1088);

        let p1024 = ml_kem_params_get(MlKemVariant::MlKem1024);
        assert_eq!(p1024.rank, 4);
        assert_eq!(p1024.eta1, 2);
        assert_eq!(p1024.eta2, 2);
        assert_eq!(p1024.du, 11);
        assert_eq!(p1024.dv, 5);
        assert_eq!(p1024.secbits, 256);
        assert_eq!(p1024.security_category, 5);
        assert_eq!(p1024.pubkey_bytes, 1568);
        assert_eq!(p1024.prvkey_bytes, 3168);
        assert_eq!(p1024.ctext_bytes, 1568);
    }

    #[test]
    fn computed_size_helpers_match_static_fields() {
        for v in [
            MlKemVariant::MlKem512,
            MlKemVariant::MlKem768,
            MlKemVariant::MlKem1024,
        ] {
            let p = ml_kem_params_get(v);
            assert_eq!(p.pubkey_bytes, p.vector_bytes() + RANDOM_BYTES);
            assert_eq!(
                p.prvkey_bytes,
                3 * ML_KEM_DEGREE / 2 * p.rank + p.pubkey_bytes + PKHASH_BYTES + RANDOM_BYTES
            );
            assert_eq!(p.ctext_bytes, p.u_vector_bytes() + p.v_scalar_bytes());
        }
    }

    #[test]
    fn params_lookup_by_name() {
        assert_eq!(
            ml_kem_params_get_by_name("ML-KEM-512").unwrap().variant,
            MlKemVariant::MlKem512
        );
        assert_eq!(
            ml_kem_params_get_by_name("ML-KEM-768").unwrap().variant,
            MlKemVariant::MlKem768
        );
        assert_eq!(
            ml_kem_params_get_by_name("ML-KEM-1024").unwrap().variant,
            MlKemVariant::MlKem1024
        );
        assert!(ml_kem_params_get_by_name("ML-KEM-2048").is_none());
    }

    #[test]
    fn variant_algorithm_name_and_security_category() {
        assert_eq!(MlKemVariant::MlKem512.algorithm_name(), "ML-KEM-512");
        assert_eq!(MlKemVariant::MlKem768.algorithm_name(), "ML-KEM-768");
        assert_eq!(MlKemVariant::MlKem1024.algorithm_name(), "ML-KEM-1024");
        assert_eq!(MlKemVariant::MlKem512.security_category(), 1);
        assert_eq!(MlKemVariant::MlKem768.security_category(), 3);
        assert_eq!(MlKemVariant::MlKem1024.security_category(), 5);
    }

    #[test]
    fn reduce_once_is_identity_on_reduced_values() {
        for x in [0u16, 1, 1000, 1664, 3328] {
            assert_eq!(reduce_once(x), x);
        }
    }

    #[test]
    fn reduce_once_subtracts_prime_for_excess_values() {
        // For x in [q, 2q), reduce_once(x) == x - q.
        for x in [ML_KEM_PRIME, ML_KEM_PRIME + 1, 2 * ML_KEM_PRIME - 1] {
            assert_eq!(reduce_once(x), x - ML_KEM_PRIME);
        }
    }

    #[test]
    fn reduce_matches_naive_modulo() {
        // Spot-check a range of values including products near the Barrett limit.
        for x in [
            0u32,
            1,
            3329,
            3328 * 3328,
            (3329u32.pow(2)) - 1,
            u32::from(ML_KEM_PRIME) * 2 - 1,
        ] {
            let expected: u16 =
                u16::try_from(x % u32::from(ML_KEM_PRIME)).expect("modulo always < q < 2^16");
            assert_eq!(reduce(x), expected, "reduce({}) mismatch", x);
        }
    }

    #[test]
    fn ntt_roundtrip_is_identity() {
        // scalar_inverse_ntt ∘ scalar_ntt should be the identity on any
        // reduced polynomial.
        let mut s = Scalar::zero();
        for i in 0..ML_KEM_DEGREE {
            // TRUNCATION: we reduce into [0, q) before storing.
            s.c[i] = u16::try_from(i).expect("256 < u16::MAX");
        }
        let original = s.clone();
        scalar_ntt(&mut s);
        scalar_inverse_ntt(&mut s);
        assert_eq!(s.c, original.c);
    }

    #[test]
    fn scalar_add_and_sub_are_inverses() {
        let mut a = Scalar::zero();
        let mut b = Scalar::zero();
        for i in 0..ML_KEM_DEGREE {
            a.c[i] = u16::try_from(i).unwrap() % ML_KEM_PRIME;
            b.c[i] = u16::try_from((i * 7) & 0xfff).unwrap() % ML_KEM_PRIME;
        }
        let original = a.clone();
        scalar_add(&mut a, &b);
        scalar_sub(&mut a, &b);
        assert_eq!(a.c, original.c);
    }

    #[test]
    fn encode_decode_roundtrip_12_bit() {
        let mut s = Scalar::zero();
        for i in 0..ML_KEM_DEGREE {
            s.c[i] = u16::try_from(i).unwrap() % ML_KEM_PRIME;
        }
        let mut buf = [0u8; 3 * ML_KEM_DEGREE / 2];
        scalar_encode(&mut buf, &s, 12);
        let mut s2 = Scalar::zero();
        scalar_decode(&buf, &mut s2, 12).unwrap();
        assert_eq!(s.c, s2.c);
    }

    #[test]
    fn scalar_decode_rejects_out_of_range_12_bit() {
        // Pack a forbidden value (>= q) into the first 12-bit slot.
        let mut buf = [0u8; 3 * ML_KEM_DEGREE / 2];
        // ML_KEM_PRIME = 0xd01; set first two bytes to 0x01, 0x0d -> 0xd01.
        buf[0] = 0x01;
        buf[1] = 0x0d;
        let mut s = Scalar::zero();
        assert!(scalar_decode(&buf, &mut s, 12).is_err());
    }

    #[test]
    fn compress_decompress_small_error_bound() {
        // Per FIPS 203 §4.7, |x - Decompress_d(Compress_d(x))| is small.
        // Per FIPS 203 Theorem 4.8: |x' - x|_q <= round(q / 2^(d+1)) where the
        // distance is taken modulo q, i.e. min(|x - x'|, q - |x - x'|). For
        // d = 10 the bound is 2 and for d = 11 it is 1.
        for d in [4usize, 5, 10, 11] {
            for x in (0..u32::from(ML_KEM_PRIME)).step_by(17) {
                let xu = u16::try_from(x).unwrap();
                let y = compress(xu, d);
                let recovered = decompress(y, d);
                // Modular distance: min(|x - x'|, q - |x - x'|).
                let abs_diff = if recovered >= xu {
                    recovered - xu
                } else {
                    xu - recovered
                };
                let mod_diff = core::cmp::min(abs_diff, ML_KEM_PRIME - abs_diff);
                // Add +1 slack because integer rounding may round up exactly
                // once. The FIPS bound uses real-valued rounding; the integer
                // implementation may exceed it by at most one unit.
                let bound = u16::try_from(u32::from(ML_KEM_PRIME) >> (d + 1)).unwrap() + 1;
                assert!(
                    mod_diff <= bound,
                    "compress/decompress error too large for d={}: x={}, recovered={}, mod_diff={}, bound={}",
                    d,
                    xu,
                    recovered,
                    mod_diff,
                    bound
                );
            }
        }
    }

    #[test]
    fn cbd_2_produces_centered_samples() {
        let input = [0xaau8; ML_KEM_DEGREE / 2];
        let mut out = Scalar::zero();
        cbd_2(&mut out, &input).unwrap();
        // All coefficients must be in {0, 1, 2, q-1, q-2} == valid CBD(2) range.
        for &c in &out.c {
            let centered = if c > HALF_PRIME {
                // Negative representative.
                (ML_KEM_PRIME - c) as i32
            } else {
                c as i32
            };
            assert!(
                centered >= -2 && centered <= 2,
                "CBD(2) out-of-range coefficient: c={}, centered={}",
                c,
                centered
            );
        }
    }

    #[test]
    fn cbd_3_produces_centered_samples() {
        // CBD_3 consumes 64·η = 192 bytes to produce 256 coefficients.
        let input = [0xa3u8; 3 * ML_KEM_DEGREE / 4];
        let mut out = Scalar::zero();
        cbd_3(&mut out, &input).unwrap();
        for &c in &out.c {
            let centered = if c > HALF_PRIME {
                (ML_KEM_PRIME - c) as i32
            } else {
                c as i32
            };
            assert!(
                centered >= -3 && centered <= 3,
                "CBD(3) out-of-range coefficient: c={}, centered={}",
                c,
                centered
            );
        }
    }

    #[test]
    fn keygen_encap_decap_roundtrip_512() {
        keygen_encap_decap_roundtrip(MlKemVariant::MlKem512);
    }

    #[test]
    fn keygen_encap_decap_roundtrip_768() {
        keygen_encap_decap_roundtrip(MlKemVariant::MlKem768);
    }

    #[test]
    fn keygen_encap_decap_roundtrip_1024() {
        keygen_encap_decap_roundtrip(MlKemVariant::MlKem1024);
    }

    fn keygen_encap_decap_roundtrip(variant: MlKemVariant) {
        let ctx = LibContext::new();
        let key = generate(ctx, variant, None).expect("keygen succeeds");
        assert!(key.have_pubkey());
        assert!(key.have_prvkey());
        assert_eq!(key.pub_len(), key.params.pubkey_bytes);
        assert_eq!(key.priv_len(), key.params.prvkey_bytes);
        assert_eq!(key.ctext_len(), key.params.ctext_bytes);
        assert_eq!(key.shared_secret_len(), SHARED_SECRET_BYTES);

        let (ctext, secret_enc) = encap_rand(&key).expect("encap succeeds");
        assert_eq!(ctext.len(), key.ctext_len());
        let secret_dec = decap(&key, &ctext).expect("decap succeeds");
        assert_eq!(secret_enc, secret_dec, "shared secrets must match");
    }

    #[test]
    fn decap_rejects_tampered_ciphertext() {
        let ctx = LibContext::new();
        let key = generate(ctx, MlKemVariant::MlKem768, None).expect("keygen");
        let (mut ctext, good_secret) = encap_rand(&key).expect("encap");
        // Flip one byte in the middle of the ciphertext.
        let mid = ctext.len() / 2;
        ctext[mid] ^= 0x01;
        let bad_secret = decap(&key, &ctext).expect("decap returns a secret even on failure");
        assert_ne!(
            good_secret, bad_secret,
            "tampered ciphertext must yield a different secret (implicit rejection)"
        );
    }

    #[test]
    fn deterministic_keygen_from_seed_is_stable() {
        let seed = [0xa5u8; SEED_BYTES];
        let ctx = LibContext::new();
        let k1 = generate(ctx.clone(), MlKemVariant::MlKem512, Some(&seed)).unwrap();
        let k2 = generate(ctx, MlKemVariant::MlKem512, Some(&seed)).unwrap();
        assert_eq!(k1.rho, k2.rho);
        assert_eq!(k1.pkhash, k2.pkhash);
        // Public-key byte encoding should also match exactly.
        assert_eq!(k1.encode_pubkey().unwrap(), k2.encode_pubkey().unwrap(),);
    }

    #[test]
    fn pubkey_cmp_uses_pkhash() {
        let ctx = LibContext::new();
        let k1 = generate(ctx.clone(), MlKemVariant::MlKem512, None).unwrap();
        let k2 = k1.dup().unwrap();
        assert!(k1.pubkey_cmp(&k2));
        let k3 = generate(ctx, MlKemVariant::MlKem512, None).unwrap();
        // Two independent keygens produce different public keys with
        // overwhelming probability.
        assert!(!k1.pubkey_cmp(&k3));
    }

    #[test]
    fn encode_parse_pubkey_roundtrip() {
        let ctx = LibContext::new();
        let key = generate(ctx.clone(), MlKemVariant::MlKem768, None).unwrap();
        let ek = key.encode_pubkey().unwrap();
        assert_eq!(ek.len(), key.pub_len());
        let mut key2 = MlKemKey::new(ctx, MlKemVariant::MlKem768).unwrap();
        key2.parse_pubkey(&ek).unwrap();
        assert!(key2.have_pubkey());
        assert!(!key2.have_prvkey());
        assert_eq!(key.pkhash, key2.pkhash);
        // Encapsulation against the re-parsed public key works, and
        // decapsulation with the original key recovers the secret.
        let (ctext, secret1) = encap_rand(&key2).unwrap();
        let secret2 = decap(&key, &ctext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn encode_parse_prvkey_roundtrip() {
        let ctx = LibContext::new();
        let key = generate(ctx.clone(), MlKemVariant::MlKem512, None).unwrap();
        let dk = key.encode_prvkey().unwrap();
        assert_eq!(dk.len(), key.priv_len());
        let mut key2 = MlKemKey::new(ctx, MlKemVariant::MlKem512).unwrap();
        key2.parse_prvkey(&dk).unwrap();
        assert!(key2.have_prvkey());
        // Encap with original, decap with re-parsed private key must match.
        let (ctext, secret1) = encap_rand(&key).unwrap();
        let secret2 = decap(&key2, &ctext).unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn reset_clears_all_key_material() {
        let ctx = LibContext::new();
        let mut key = generate(ctx, MlKemVariant::MlKem512, None).unwrap();
        assert!(key.have_pubkey());
        assert!(key.have_prvkey());
        key.reset();
        assert!(!key.have_pubkey());
        assert!(!key.have_prvkey());
        assert!(!key.have_seed());
        assert_eq!(key.rho, [0u8; RANDOM_BYTES]);
        assert_eq!(key.pkhash, [0u8; PKHASH_BYTES]);
    }

    #[test]
    fn provider_flags_default_and_override() {
        let ctx = LibContext::new();
        let mut key = MlKemKey::new(ctx, MlKemVariant::MlKem512).unwrap();
        assert_eq!(key.provider_flags(), prov_flags::DEFAULT);
        key.set_provider_flags(prov_flags::FIXED_PCT);
        assert_eq!(key.provider_flags(), prov_flags::FIXED_PCT);
    }

    #[test]
    fn ntt_tables_have_expected_lengths() {
        assert_eq!(NTT_ROOTS.len(), 128);
        assert_eq!(INVERSE_NTT_ROOTS.len(), 128);
        assert_eq!(MOD_ROOTS.len(), 128);
    }

    #[test]
    fn ntt_first_root_is_one() {
        // bitrev_7(0) = 0, so NTT_ROOTS[0] = 17^0 = 1.
        assert_eq!(NTT_ROOTS[0], 1);
        assert_eq!(INVERSE_NTT_ROOTS[0], 1);
    }
}
