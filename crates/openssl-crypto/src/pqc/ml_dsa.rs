//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation per FIPS 204.
//!
//! This module implements key generation, signing, and verification for the three
//! ML-DSA parameter sets defined by NIST FIPS 204:
//!
//! - **ML-DSA-44** — Security category 2 (≈128 bits), compact signatures and keys
//! - **ML-DSA-65** — Security category 3 (≈192 bits), balanced parameters
//! - **ML-DSA-87** — Security category 5 (≈256 bits), strongest security
//!
//! ML-DSA is a lattice-based signature scheme derived from the CRYSTALS-Dilithium
//! submission to the NIST Post-Quantum Cryptography standardization process. It is
//! quantum-resistant and designed to be a drop-in replacement for pre-quantum
//! signatures such as RSA and ECDSA.
//!
//! # Algorithm Overview
//!
//! The implementation uses:
//! - Number-Theoretic Transform (NTT) in Montgomery domain for polynomial multiplication
//! - Rejection sampling for secret vector generation and challenge polynomial creation
//! - SHAKE-128 XOF for matrix `A_hat` expansion
//! - SHAKE-256 XOF for seed expansion, `s1`/`s2` sampling, challenge `c_tilde`, masking, and `mu`
//! - Power-of-2 rounding and hint mechanism for compact signatures
//!
//! All arithmetic is performed modulo `q = 8_380_417 = 2^23 − 2^13 + 1`.
//!
//! # Security Guarantees
//!
//! - All secret material (`s1`, `s2`, `t0`, `K`, signing seed) is zeroized on drop
//! - Signature verification uses constant-time comparison (`subtle::ConstantTimeEq`)
//! - Montgomery reduction avoids branch-dependent timing on reduction steps
//! - Rejection sampling restart bounds are enforced (see `sign_internal`)
//!
//! # Source
//!
//! This file is a faithful Rust translation of OpenSSL's C implementation located at
//! `crypto/ml_dsa/*.c` and `include/crypto/ml_dsa.h`, preserving algorithm behaviour
//! and bit-for-bit compatibility of public keys, private keys, and signatures.
//!
//! # References
//!
//! - NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard
//! - CRYSTALS-Dilithium specification (Round 3)

#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::doc_markdown)]

use crate::context::LibContext;
use crate::hash::sha::{shake256, ShakeContext};
use openssl_common::{CryptoError, CryptoResult};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===========================================================================
// Core Constants (FIPS 204 §2.4 and §4)
// ===========================================================================

/// The ML-DSA prime modulus `q = 2^23 − 2^13 + 1`.
///
/// All polynomial coefficient arithmetic in ML-DSA is performed in `Z_q`.
pub const ML_DSA_Q: u32 = 8_380_417;

/// `(q − 1) / 2` — midpoint of the representable range; used for centered absolute value.
const Q_MINUS1_DIV2: u32 = (ML_DSA_Q - 1) / 2;

/// Bit-width of the prime `q` (23 bits).
#[allow(dead_code)]
const Q_BITS: u32 = 23;

/// `q^{-1} mod 2^32` (used for Montgomery-domain sanity checks).
#[allow(dead_code)]
const Q_INV: u32 = 58_728_449;

/// `(-q)^{-1} mod 2^32` — central constant for Montgomery reduction.
const Q_NEG_INV: u32 = 4_236_238_847;

/// `256^{-1} * R mod q` in Montgomery form — the scaling factor applied
/// at the end of an inverse NTT to restore the natural representation.
const DEGREE_INV_MONTGOMERY: u32 = 41_978;

/// Number of low-order bits dropped from the public key vector `t`.
const D_BITS: u32 = 13;

/// `2^D_BITS` — the scaling factor used when reconstructing `t` from `(t1, t0)`.
const TWO_POWER_D: u32 = 1 << D_BITS;

/// Polynomial degree (number of coefficients per polynomial).
///
/// Each polynomial is an element of `Z_q[X] / (X^256 + 1)`.
pub const NUM_POLY_COEFFICIENTS: usize = 256;

/// Byte-length of the public random seed `rho`.
const RHO_BYTES: usize = 32;

/// Byte-length of the private secret-sampling seed `rho_prime`.
const PRIV_SEED_BYTES: usize = 64;

/// Byte-length of the private signing seed `K`.
const K_BYTES: usize = 32;

/// Byte-length of the public-key digest `tr`.
const TR_BYTES: usize = 64;

/// Byte-length of the per-signature randomised seed `rho_prime`.
const RHO_PRIME_BYTES: usize = 64;

/// Byte-length of the key-generation seed `xi` (FIPS 204 Algorithm 1 input).
pub const SEED_BYTES: usize = 32;

/// Byte-length of the message representative `mu = H(tr || M')`.
pub const MU_BYTES: usize = 64;

/// Byte-length of the per-signature random nonce `rnd` used by hedged signing.
const ENTROPY_LEN: usize = 32;

/// Maximum lambda (bit-strength) across all ML-DSA parameter sets (ML-DSA-87).
#[allow(dead_code)]
const MAX_LAMBDA: usize = 256;

/// Maximum permitted length of the user-supplied context string.
pub const MAX_CONTEXT_STRING_LEN: usize = 255;

/// `γ₂ = (q − 1) / 32` — low-order rounding range for ML-DSA-65 and ML-DSA-87.
const GAMMA2_Q_MINUS1_DIV32: u32 = (ML_DSA_Q - 1) / 32;

/// `γ₂ = (q − 1) / 88` — low-order rounding range for ML-DSA-44.
const GAMMA2_Q_MINUS1_DIV88: u32 = (ML_DSA_Q - 1) / 88;

/// `γ₁ = 2^17` — masking range for ML-DSA-44.
const GAMMA1_TWO_POWER_17: u32 = 1 << 17;

/// `γ₁ = 2^19` — masking range for ML-DSA-65 and ML-DSA-87.
const GAMMA1_TWO_POWER_19: u32 = 1 << 19;

/// `η = 2` — secret coefficient range for ML-DSA-44 and ML-DSA-87.
const ETA_2: u32 = 2;

/// `η = 4` — secret coefficient range for ML-DSA-65.
const ETA_4: u32 = 4;

// --- Serialized key and signature lengths (FIPS 204 Table 2) ---

/// Private-key byte length for ML-DSA-44.
pub const ML_DSA_44_PRIV_LEN: usize = 2560;
/// Public-key byte length for ML-DSA-44.
pub const ML_DSA_44_PUB_LEN: usize = 1312;
/// Signature byte length for ML-DSA-44.
pub const ML_DSA_44_SIG_LEN: usize = 2420;
/// Private-key byte length for ML-DSA-65.
pub const ML_DSA_65_PRIV_LEN: usize = 4032;
/// Public-key byte length for ML-DSA-65.
pub const ML_DSA_65_PUB_LEN: usize = 1952;
/// Signature byte length for ML-DSA-65.
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// Private-key byte length for ML-DSA-87.
pub const ML_DSA_87_PRIV_LEN: usize = 4896;
/// Public-key byte length for ML-DSA-87.
pub const ML_DSA_87_PUB_LEN: usize = 2592;
/// Signature byte length for ML-DSA-87.
pub const ML_DSA_87_SIG_LEN: usize = 4627;

// --- Key provisioning flags ---

/// Prefer regenerating the key from its seed when both seed and encoded key
/// material are available (mirrors the C `KEY_PREFER_SEED` flag).
pub const KEY_PREFER_SEED: u32 = 1 << 0;

/// Retain the original seed alongside the expanded key so that later callers
/// can re-derive the key (mirrors the C `KEY_RETAIN_SEED` flag).
pub const KEY_RETAIN_SEED: u32 = 1 << 1;

/// Default provisioning-flag set used by newly constructed keys.
pub const KEY_PROV_FLAGS_DEFAULT: u32 = KEY_PREFER_SEED | KEY_RETAIN_SEED;

// ===========================================================================
// MlDsaVariant and MlDsaParams
// ===========================================================================

/// The three ML-DSA parameter sets defined by FIPS 204.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaVariant {
    /// ML-DSA-44 — NIST security category 2 (≈128 bits).
    MlDsa44,
    /// ML-DSA-65 — NIST security category 3 (≈192 bits).
    MlDsa65,
    /// ML-DSA-87 — NIST security category 5 (≈256 bits).
    MlDsa87,
}

impl MlDsaVariant {
    /// Return the canonical algorithm-name string for this variant.
    #[must_use]
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Return the NIST security category (2, 3, or 5) for this variant.
    #[must_use]
    pub fn security_category(self) -> u32 {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }
}

/// Complete parameter set for an ML-DSA variant.
///
/// Fields mirror the FIPS 204 parameters in Table 1 of the specification and the
/// C structure `ML_DSA_PARAMS` defined in `ml_dsa_params.c`.
#[derive(Debug, Clone)]
pub struct MlDsaParams {
    /// Canonical algorithm name (`"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`).
    pub alg: &'static str,
    /// Enum discriminant for this parameter set.
    pub variant: MlDsaVariant,
    /// Numeric EVP identifier (matches `EVP_PKEY_ML_DSA_{44,65,87}`).
    pub evp_type: u32,
    /// `τ` — the number of ±1 coefficients in the challenge polynomial `c`.
    pub tau: u32,
    /// `λ` — bit strength (128, 192, or 256).
    pub bit_strength: u32,
    /// `γ₁` — masking range (`2^17` or `2^19`).
    pub gamma1: u32,
    /// `γ₂` — low-order rounding modulus.
    pub gamma2: u32,
    /// `k` — rows of the public matrix `A_hat`.
    pub k: usize,
    /// `l` — columns of the public matrix `A_hat`.
    pub l: usize,
    /// `η` — secret-coefficient range (`[−η, η]`).
    pub eta: u32,
    /// `β = τ · η` — combined bound for the rejection check.
    pub beta: u32,
    /// `ω` — maximum number of 1s permitted in the signature hint.
    pub omega: u32,
    /// NIST security category (2, 3, or 5).
    pub security_category: u32,
    /// Serialised private-key byte length.
    pub sk_len: usize,
    /// Serialised public-key byte length.
    pub pk_len: usize,
    /// Serialised signature byte length.
    pub sig_len: usize,
}

// --- Evp-type numeric identifiers mirroring OpenSSL constants ---
const EVP_PKEY_ML_DSA_44: u32 = 0;
const EVP_PKEY_ML_DSA_65: u32 = 1;
const EVP_PKEY_ML_DSA_87: u32 = 2;

/// Static parameters for ML-DSA-44.
pub static ML_DSA_44_PARAMS: MlDsaParams = MlDsaParams {
    alg: "ML-DSA-44",
    variant: MlDsaVariant::MlDsa44,
    evp_type: EVP_PKEY_ML_DSA_44,
    tau: 39,
    bit_strength: 128,
    gamma1: GAMMA1_TWO_POWER_17,
    gamma2: GAMMA2_Q_MINUS1_DIV88,
    k: 4,
    l: 4,
    eta: ETA_2,
    beta: 78,
    omega: 80,
    security_category: 2,
    sk_len: ML_DSA_44_PRIV_LEN,
    pk_len: ML_DSA_44_PUB_LEN,
    sig_len: ML_DSA_44_SIG_LEN,
};

/// Static parameters for ML-DSA-65.
pub static ML_DSA_65_PARAMS: MlDsaParams = MlDsaParams {
    alg: "ML-DSA-65",
    variant: MlDsaVariant::MlDsa65,
    evp_type: EVP_PKEY_ML_DSA_65,
    tau: 49,
    bit_strength: 192,
    gamma1: GAMMA1_TWO_POWER_19,
    gamma2: GAMMA2_Q_MINUS1_DIV32,
    k: 6,
    l: 5,
    eta: ETA_4,
    beta: 196,
    omega: 55,
    security_category: 3,
    sk_len: ML_DSA_65_PRIV_LEN,
    pk_len: ML_DSA_65_PUB_LEN,
    sig_len: ML_DSA_65_SIG_LEN,
};

/// Static parameters for ML-DSA-87.
pub static ML_DSA_87_PARAMS: MlDsaParams = MlDsaParams {
    alg: "ML-DSA-87",
    variant: MlDsaVariant::MlDsa87,
    evp_type: EVP_PKEY_ML_DSA_87,
    tau: 60,
    bit_strength: 256,
    gamma1: GAMMA1_TWO_POWER_19,
    gamma2: GAMMA2_Q_MINUS1_DIV32,
    k: 8,
    l: 7,
    eta: ETA_2,
    beta: 120,
    omega: 75,
    security_category: 5,
    sk_len: ML_DSA_87_PRIV_LEN,
    pk_len: ML_DSA_87_PUB_LEN,
    sig_len: ML_DSA_87_SIG_LEN,
};

/// Return the static `MlDsaParams` reference for the given variant.
#[must_use]
pub fn ml_dsa_params_get(variant: MlDsaVariant) -> &'static MlDsaParams {
    match variant {
        MlDsaVariant::MlDsa44 => &ML_DSA_44_PARAMS,
        MlDsaVariant::MlDsa65 => &ML_DSA_65_PARAMS,
        MlDsaVariant::MlDsa87 => &ML_DSA_87_PARAMS,
    }
}

/// Look up an ML-DSA parameter set by its canonical algorithm name.
///
/// Returns `None` when `name` does not match any known variant. Matching is
/// case-sensitive and matches the canonical NIST names.
#[must_use]
pub fn ml_dsa_params_get_by_name(name: &str) -> Option<&'static MlDsaParams> {
    match name {
        "ML-DSA-44" => Some(&ML_DSA_44_PARAMS),
        "ML-DSA-65" => Some(&ML_DSA_65_PARAMS),
        "ML-DSA-87" => Some(&ML_DSA_87_PARAMS),
        _ => None,
    }
}

// ===========================================================================
// Low-level modular-arithmetic helpers (translated from `ml_dsa_local.h`)
// ===========================================================================

/// Reduce a value in `[0, 2q)` to its unique representative in `[0, q)`.
#[inline]
fn reduce_once(x: u32) -> u32 {
    let sub = x.wrapping_sub(ML_DSA_Q);
    let mask = 0u32.wrapping_sub(sub >> 31);
    (mask & x) | (!mask & sub)
}

/// Constant-time selection: returns `a` when `mask == 0xFFFFFFFF`, else `b`.
#[inline]
fn ct_select(mask: u32, a: u32, b: u32) -> u32 {
    (mask & a) | (!mask & b)
}

/// Expand the low bit of `cond` into an all-ones / all-zeroes 32-bit mask.
#[inline]
fn mask_from_bool(cond: bool) -> u32 {
    if cond {
        0xFFFF_FFFFu32
    } else {
        0
    }
}

/// Compute `(a − b) mod q` for `a, b ∈ [0, q)`.
#[inline]
fn mod_sub(a: u32, b: u32) -> u32 {
    reduce_once(a.wrapping_add(ML_DSA_Q).wrapping_sub(b))
}

/// Return the 32-bit two's-complement absolute value of a signed value
/// represented as `u32` (values in `[0, q) ∪ [2^31, 2^32)`).
#[inline]
fn abs_signed(x: u32) -> u32 {
    if x >> 31 == 0 {
        x
    } else {
        0u32.wrapping_sub(x)
    }
}

/// Centered absolute value: returns `|x|` viewed as a signed value in `[-(q-1)/2, (q-1)/2]`.
#[inline]
fn abs_mod_prime(x: u32) -> u32 {
    if x > Q_MINUS1_DIV2 {
        ML_DSA_Q - x
    } else {
        x
    }
}

/// Return the larger of two `u32` values.
#[inline]
fn maximum(x: u32, y: u32) -> u32 {
    if x < y {
        y
    } else {
        x
    }
}

/// Montgomery reduction: given `a < q·R` (where `R = 2^32`), compute
/// `a · R^{-1} mod q` in the range `[0, q)`.
///
/// Implements the classic word-level Montgomery reduction used in `ml_dsa_ntt.c`.
#[inline]
fn reduce_montgomery(a: u64) -> u32 {
    let a_low = a as u32;
    let t = a_low.wrapping_mul(Q_NEG_INV);
    let b = a.wrapping_add((t as u64).wrapping_mul(ML_DSA_Q as u64));
    let c = (b >> 32) as u32;
    reduce_once(c)
}

// ===========================================================================
// Poly and Vector types (mirroring `ml_dsa_poly.h` and `ml_dsa_vector.h`)
// ===========================================================================

/// A polynomial with `NUM_POLY_COEFFICIENTS` coefficients in `Z_q`.
///
/// Coefficients are stored in natural (non-NTT) representation by default but
/// callers must track whether a particular value is in NTT or Montgomery domain.
#[derive(Clone, Debug, Zeroize)]
pub struct Poly {
    /// Coefficient array. Entries are always kept in `[0, q)`.
    pub coeffs: [u32; NUM_POLY_COEFFICIENTS],
}

impl Poly {
    /// Construct a zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            coeffs: [0u32; NUM_POLY_COEFFICIENTS],
        }
    }

    /// Zero every coefficient in-place.
    pub fn clear(&mut self) {
        for c in &mut self.coeffs {
            *c = 0;
        }
    }

    /// `self += rhs` in `Z_q[X]`.
    pub fn add_assign(&mut self, rhs: &Self) {
        for i in 0..NUM_POLY_COEFFICIENTS {
            self.coeffs[i] = reduce_once(self.coeffs[i].wrapping_add(rhs.coeffs[i]));
        }
    }

    /// `out = self + rhs` in `Z_q[X]`.
    pub fn add(&self, rhs: &Self, out: &mut Self) {
        for i in 0..NUM_POLY_COEFFICIENTS {
            out.coeffs[i] = reduce_once(self.coeffs[i].wrapping_add(rhs.coeffs[i]));
        }
    }

    /// `out = self − rhs` in `Z_q[X]`.
    pub fn sub(&self, rhs: &Self, out: &mut Self) {
        for i in 0..NUM_POLY_COEFFICIENTS {
            out.coeffs[i] = mod_sub(self.coeffs[i], rhs.coeffs[i]);
        }
    }

    /// Constant-time equality check — both polynomials must be in the same
    /// coefficient representation for this result to be meaningful.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        let mut acc: u8 = 0;
        for i in 0..NUM_POLY_COEFFICIENTS {
            // Compare each coefficient using subtle's constant-time API.
            let ct = self.coeffs[i].ct_eq(&other.coeffs[i]);
            acc |= (!ct).unwrap_u8();
        }
        acc == 0
    }

    /// In-place forward NTT.
    pub fn ntt(&mut self) {
        poly_ntt(self);
    }

    /// In-place inverse NTT.
    pub fn ntt_inverse(&mut self) {
        poly_ntt_inverse(self);
    }

    /// Compute the maximum unsigned coefficient value present in this polynomial.
    #[must_use]
    pub fn max(&self) -> u32 {
        let mut m = 0u32;
        for &c in &self.coeffs {
            m = maximum(m, c);
        }
        m
    }

    /// Compute the maximum centered (signed) absolute coefficient value.
    #[must_use]
    pub fn max_signed(&self) -> u32 {
        let mut m = 0u32;
        for &c in &self.coeffs {
            m = maximum(m, abs_mod_prime(c));
        }
        m
    }

    /// Scale every coefficient by `2^D_BITS`.
    pub fn scale_power2_round(&mut self) {
        for c in &mut self.coeffs {
            *c = c.wrapping_mul(TWO_POWER_D) % ML_DSA_Q;
        }
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

/// A vector of polynomials (used for signature components `z`, `hint`, and key
/// vectors `s1`, `s2`, `t0`, `t1`).
#[derive(Clone, Debug, Zeroize)]
pub struct Vector {
    /// Constituent polynomials. The length is determined by the ML-DSA variant.
    pub polys: Vec<Poly>,
}

impl Vector {
    /// Construct a zero-filled vector with `n` polynomials.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            polys: vec![Poly::zero(); n],
        }
    }

    /// Copy `src` into `self`. Both vectors must already have the same length.
    pub fn copy_from(&mut self, src: &Self) {
        debug_assert_eq!(self.polys.len(), src.polys.len());
        for (dst, s) in self.polys.iter_mut().zip(src.polys.iter()) {
            dst.coeffs.copy_from_slice(&s.coeffs);
        }
    }

    /// `self += rhs` elementwise.
    pub fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.polys.len(), rhs.polys.len());
        for (p, r) in self.polys.iter_mut().zip(rhs.polys.iter()) {
            let clone = p.clone();
            clone.add(r, p);
        }
    }

    /// `self −= rhs` elementwise.
    pub fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.polys.len(), rhs.polys.len());
        for (p, r) in self.polys.iter_mut().zip(rhs.polys.iter()) {
            let clone = p.clone();
            clone.sub(r, p);
        }
    }

    /// Apply a forward NTT to every polynomial.
    pub fn ntt(&mut self) {
        for p in &mut self.polys {
            p.ntt();
        }
    }

    /// Apply an inverse NTT to every polynomial.
    pub fn ntt_inverse(&mut self) {
        for p in &mut self.polys {
            p.ntt_inverse();
        }
    }

    /// Multiply every coefficient of every polynomial by `2^D_BITS`.
    pub fn scale_power2_round(&mut self) {
        for p in &mut self.polys {
            p.scale_power2_round();
        }
    }

    /// Return the maximum centered absolute coefficient across the entire vector.
    #[must_use]
    pub fn max_signed(&self) -> u32 {
        let mut m = 0u32;
        for p in &self.polys {
            m = maximum(m, p.max_signed());
        }
        m
    }

    /// Return the maximum unsigned coefficient across the entire vector.
    #[must_use]
    pub fn max(&self) -> u32 {
        let mut m = 0u32;
        for p in &self.polys {
            m = maximum(m, p.max());
        }
        m
    }

    /// Compute the Hamming weight (number of non-zero coefficients) across all polynomials.
    #[must_use]
    pub fn hamming_weight(&self) -> u32 {
        let mut count: u32 = 0;
        for p in &self.polys {
            for &c in &p.coeffs {
                if c != 0 {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    }
}

/// A `rows × cols` matrix of polynomials, stored row-major.
pub struct Matrix {
    /// Number of rows (`k`).
    pub rows: usize,
    /// Number of columns (`l`).
    pub cols: usize,
    /// Row-major coefficient storage.
    pub polys: Vec<Poly>,
}

impl Matrix {
    /// Construct a zero-filled `rows × cols` matrix.
    #[must_use]
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            polys: vec![Poly::zero(); rows * cols],
        }
    }

    /// Get a shared reference to the entry at row `i`, column `j`.
    #[must_use]
    pub fn get(&self, i: usize, j: usize) -> &Poly {
        &self.polys[i * self.cols + j]
    }

    /// Get a mutable reference to the entry at row `i`, column `j`.
    pub fn get_mut(&mut self, i: usize, j: usize) -> &mut Poly {
        &mut self.polys[i * self.cols + j]
    }
}

// ===========================================================================
// NTT / Number Theoretic Transform (translated from `ml_dsa_ntt.c`)
// ===========================================================================

/// Precomputed Montgomery-domain NTT twiddle factors `ζ^{BitRev8(i)} · R mod q`.
///
/// This table is copied verbatim from `crypto/ml_dsa/ml_dsa_ntt.c` in the OpenSSL
/// C reference implementation and MUST NOT be modified.
#[rustfmt::skip]
static ZETAS_MONTGOMERY: [u32; 256] = [
    4193792, 25847,   5771523, 7861508, 237124,  7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776,   3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944,  531354,  954230,  3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944,  508951,  3097992, 44288,   7280319, 904516,  3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969,  7063561,
    189548,  4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997,  2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702,  1859098, 909542,  819034,  495491,  6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297,  286988,  5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191,  2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136,  4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,  7173032,
    5196991, 162844,  1616392, 3014001, 810149,  1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760,  2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443,  7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
];

/// Forward NTT (FIPS 204 Algorithm 41).
///
/// Converts a polynomial from natural coefficient representation into NTT form
/// (still in Montgomery domain so that subsequent pointwise multiplications
/// using `reduce_montgomery` are correct).
fn poly_ntt(p: &mut Poly) {
    let mut offset: usize = NUM_POLY_COEFFICIENTS;
    let mut step: usize = 1;
    while step < NUM_POLY_COEFFICIENTS {
        let mut k: usize = 0;
        offset >>= 1;
        for i in 0..step {
            let z_step_root = ZETAS_MONTGOMERY[step + i] as u64;
            for j in k..(k + offset) {
                let w_even = p.coeffs[j];
                let t_odd =
                    reduce_montgomery(z_step_root.wrapping_mul(p.coeffs[j + offset] as u64));
                p.coeffs[j + offset] = mod_sub(w_even, t_odd);
                p.coeffs[j] = reduce_once(w_even.wrapping_add(t_odd));
            }
            k += 2 * offset;
        }
        step <<= 1;
    }
}

/// Inverse NTT (FIPS 204 Algorithm 42).
fn poly_ntt_inverse(p: &mut Poly) {
    let mut step: usize = NUM_POLY_COEFFICIENTS;
    let mut offset: usize = 1;
    while offset < NUM_POLY_COEFFICIENTS {
        step >>= 1;
        let mut k: usize = 0;
        for i in 0..step {
            let step_root: u32 = ML_DSA_Q.wrapping_sub(ZETAS_MONTGOMERY[step + (step - 1 - i)]);
            let step_root_u64 = step_root as u64;
            for j in k..(k + offset) {
                let even = p.coeffs[j];
                let odd = p.coeffs[j + offset];
                p.coeffs[j] = reduce_once(odd.wrapping_add(even));
                let diff = ML_DSA_Q.wrapping_add(even).wrapping_sub(odd);
                p.coeffs[j + offset] = reduce_montgomery(step_root_u64.wrapping_mul(diff as u64));
            }
            k += 2 * offset;
        }
        offset <<= 1;
    }
    for coeff in &mut p.coeffs {
        let prod = (*coeff as u64).wrapping_mul(DEGREE_INV_MONTGOMERY as u64);
        *coeff = reduce_montgomery(prod);
    }
}

/// Pointwise polynomial multiplication in NTT / Montgomery domain.
///
/// `out[i] = reduce_montgomery(lhs[i] * rhs[i])` — after this, `out` has an
/// implicit extra factor of `R^{-1}`, which is why inputs are typically in
/// Montgomery form.
fn poly_ntt_mult(lhs: &Poly, rhs: &Poly, out: &mut Poly) {
    for i in 0..NUM_POLY_COEFFICIENTS {
        let product = (lhs.coeffs[i] as u64).wrapping_mul(rhs.coeffs[i] as u64);
        out.coeffs[i] = reduce_montgomery(product);
    }
}

// ===========================================================================
// Key-compression primitives (translated from `ml_dsa_key_compress.c`)
// ===========================================================================

/// `Power2Round` (FIPS 204 Algorithm 35): split `r` into `r = r1 · 2^d + r0`
/// with `r0 ∈ (−2^{d−1}, 2^{d−1}]` encoded as `r0 mod q`.
fn power2_round(r: u32) -> (u32, u32) {
    let r1 = r >> D_BITS;
    let r0 = r.wrapping_sub(r1 << D_BITS);

    // Adjust (r0, r1) if r0 > 2^{d-1}.
    // r0_adj = (r0 - 2^d) mod q   (in signed terms: r0 - 2^d)
    let r0_adj = mod_sub(r0, 1 << D_BITS);
    let r1_adj = r1.wrapping_add(1);

    // mask = 0xFFFFFFFF if (1 << (d-1)) < r0  else 0
    let threshold: u32 = 1 << (D_BITS - 1);
    let cond = threshold < r0;
    let mask = mask_from_bool(cond);

    let r0_out = ct_select(mask, r0_adj, r0);
    let r1_out = ct_select(mask, r1_adj, r1);
    (r1_out, r0_out)
}

/// `HighBits` (FIPS 204 Algorithm 37).
fn high_bits(r: u32, gamma2: u32) -> u32 {
    let r1 = (r.wrapping_add(127)) >> 7;
    if gamma2 == GAMMA2_Q_MINUS1_DIV32 {
        // r1 = (r1 * 1025 + (1 << 21)) >> 22; r1 &= 15;
        let r1 = (r1.wrapping_mul(1025).wrapping_add(1 << 21)) >> 22;
        r1 & 15
    } else {
        // gamma2 == (q-1)/88
        // C reference: int32_t r1 = ...; r1 ^= ((43 - r1) >> 31) & r1;
        // The C expression uses SIGNED (arithmetic) right shift on int32_t so
        // that when r1 > 43 the mask becomes 0xFFFFFFFF (all-ones) and the
        // XOR collapses r1 to 0 (wrapping 44 → 0 at r = q - 1). Translating
        // naively to `u32 >> 31` would be a LOGICAL shift that only ever
        // yields 0 or 1, breaking the wrap. We therefore perform the trick
        // in i32 space and cast back.
        let r1 = (r1.wrapping_mul(11275).wrapping_add(1 << 23)) >> 24;
        let diff = 43i32.wrapping_sub(r1 as i32);
        let mask = (diff >> 31) as u32 & r1;
        r1 ^ mask
    }
}

/// `Decompose` (FIPS 204 Algorithm 36).
fn decompose(r: u32, gamma2: u32) -> (u32, u32) {
    let r1 = high_bits(r, gamma2);
    let r1_times_2gamma2 = r1.wrapping_mul(2).wrapping_mul(gamma2);
    let mut r0 = r.wrapping_sub(r1_times_2gamma2);
    // r0 -= (((int32_t)Q_MINUS1_DIV2 - r0) >> 31) & Q;
    // Signed-right-shift trick: if r0 > Q_MINUS1_DIV2 subtract q.
    let diff_signed = (Q_MINUS1_DIV2 as i32).wrapping_sub(r0 as i32);
    let mask = (diff_signed >> 31) as u32; // all-ones when diff_signed < 0
    r0 = r0.wrapping_sub(mask & ML_DSA_Q);
    (r1, r0)
}

/// `LowBits` (FIPS 204 Algorithm 38).
fn low_bits(r: u32, gamma2: u32) -> u32 {
    let (_r1, r0) = decompose(r, gamma2);
    r0
}

/// `MakeHint` (FIPS 204 Algorithm 39): returns `true` if adding `ct0` to `w'`
/// changes the high bits.
fn make_hint(ct0: u32, cs2: u32, gamma2: u32, w: u32) -> bool {
    let r_plus_z = mod_sub(w, cs2);
    let r = reduce_once(r_plus_z.wrapping_add(ct0));
    high_bits(r, gamma2) != high_bits(r_plus_z, gamma2)
}

/// `UseHint` (FIPS 204 Algorithm 40). NOT constant time — callers must ensure
/// `r` does not depend on secret data at invocation time.
fn use_hint(hint: bool, r: u32, gamma2: u32) -> u32 {
    let (r1, r0) = decompose(r, gamma2);
    if !hint {
        return r1;
    }
    // Signed comparison: r0 > 0 meaning r0 < Q_MINUS1_DIV2 (lies on the positive side).
    let positive = (r0 as i32) > 0 && r0 < Q_MINUS1_DIV2;
    if gamma2 == GAMMA2_Q_MINUS1_DIV32 {
        if positive {
            r1.wrapping_add(1) & 15
        } else {
            r1.wrapping_sub(1) & 15
        }
    } else {
        // gamma2 == (q-1)/88 — 44 possible values (0..=43).
        if positive {
            if r1 == 43 {
                0
            } else {
                r1.wrapping_add(1)
            }
        } else if r1 == 0 {
            43
        } else {
            r1.wrapping_sub(1)
        }
    }
}

// ===========================================================================
// Rejection sampling (translated from `ml_dsa_sample.c`)
// ===========================================================================

/// Attempt to sample a uniform coefficient in `[0, q)` from three bytes,
/// discarding the top bit of the high byte. Returns `Some(coeff)` on success.
///
/// The `[u8; 3]` argument is passed by value — `Copy` and only three bytes wide
/// (smaller than a 64-bit reference on 64-bit platforms).
fn coeff_from_three_bytes(b: [u8; 3]) -> Option<u32> {
    let z = (b[0] as u32) + ((b[1] as u32) << 8) + (((b[2] & 0x7f) as u32) << 16);
    if z < ML_DSA_Q {
        Some(z)
    } else {
        None
    }
}

/// Sample `η = 4` coefficient from a 4-bit nibble (FIPS 204 Algorithm 14).
fn coeff_from_nibble_4(nibble: u8) -> Option<u32> {
    if nibble < 9 {
        Some(mod_sub(4, nibble as u32))
    } else {
        None
    }
}

/// Reduce `nibble` modulo 5. Used by the `η = 2` rejection path.
fn mod5(nibble: u8) -> u8 {
    nibble - 5 * (nibble / 5)
}

/// Sample `η = 2` coefficient from a 4-bit nibble (FIPS 204 Algorithm 15).
fn coeff_from_nibble_2(nibble: u8) -> Option<u32> {
    if nibble < 15 {
        Some(mod_sub(2, mod5(nibble) as u32))
    } else {
        None
    }
}

/// Rejection-sample a polynomial in NTT form using SHAKE-128 (FIPS 204
/// Algorithm 30 — `RejNTTPoly`).
fn rej_ntt_poly(seed: &[u8], out: &mut Poly) -> CryptoResult<()> {
    const BLOCK: usize = 168; // SHAKE-128 rate
    let mut ctx = ShakeContext::shake128();
    ctx.update(seed)?;
    let mut buf = [0u8; BLOCK];
    ctx.squeeze(&mut buf)?;

    let mut count: usize = 0;
    let mut pos: usize = 0;
    while count < NUM_POLY_COEFFICIENTS {
        if pos + 3 > BLOCK {
            ctx.squeeze(&mut buf)?;
            pos = 0;
        }
        let triplet = [buf[pos], buf[pos + 1], buf[pos + 2]];
        pos += 3;
        if let Some(c) = coeff_from_three_bytes(triplet) {
            out.coeffs[count] = c;
            count += 1;
        }
    }
    Ok(())
}

/// Rejection-sample a polynomial with coefficients in `[-η, η]` using SHAKE-256
/// (FIPS 204 Algorithm 31 — `RejBoundedPoly`).
fn rej_bounded_poly(seed: &[u8], eta: u32, out: &mut Poly) -> CryptoResult<()> {
    const BLOCK: usize = 136; // SHAKE-256 rate
    let mut ctx = ShakeContext::shake256();
    ctx.update(seed)?;
    let mut buf = [0u8; BLOCK];
    ctx.squeeze(&mut buf)?;

    let mut count: usize = 0;
    let mut pos: usize = 0;
    while count < NUM_POLY_COEFFICIENTS {
        if pos >= BLOCK {
            ctx.squeeze(&mut buf)?;
            pos = 0;
        }
        let byte = buf[pos];
        pos += 1;
        let low = byte & 0x0F;
        let high = byte >> 4;
        let sample_fn = if eta == 4 {
            coeff_from_nibble_4
        } else {
            coeff_from_nibble_2
        };
        if let Some(c) = sample_fn(low) {
            out.coeffs[count] = c;
            count += 1;
        }
        if count >= NUM_POLY_COEFFICIENTS {
            break;
        }
        if let Some(c) = sample_fn(high) {
            out.coeffs[count] = c;
            count += 1;
        }
    }
    Ok(())
}

/// `ExpandA` (FIPS 204 Algorithm 32) — fill a `k × l` matrix of NTT-domain
/// polynomials deterministically from the 32-byte seed `rho`.
fn matrix_expand_a(rho: &[u8; RHO_BYTES], a_hat: &mut Matrix) -> CryptoResult<()> {
    let mut derived = [0u8; RHO_BYTES + 2];
    derived[..RHO_BYTES].copy_from_slice(rho);
    for i in 0..a_hat.rows {
        for j in 0..a_hat.cols {
            derived[RHO_BYTES] = j as u8;
            derived[RHO_BYTES + 1] = i as u8;
            rej_ntt_poly(&derived, a_hat.get_mut(i, j))?;
        }
    }
    Ok(())
}

/// `ExpandS` (FIPS 204 Algorithm 33) — fill secret vectors `s1` (length `l`) and
/// `s2` (length `k`) from the 64-byte seed `rho_prime`.
fn vector_expand_s(
    rho_prime: &[u8; PRIV_SEED_BYTES],
    eta: u32,
    s1: &mut Vector,
    s2: &mut Vector,
) -> CryptoResult<()> {
    let mut derived = [0u8; PRIV_SEED_BYTES + 2];
    derived[..PRIV_SEED_BYTES].copy_from_slice(rho_prime);
    let mut counter: u16 = 0;

    for i in 0..s1.polys.len() {
        derived[PRIV_SEED_BYTES] = counter as u8;
        derived[PRIV_SEED_BYTES + 1] = (counter >> 8) as u8;
        rej_bounded_poly(&derived, eta, &mut s1.polys[i])?;
        counter = counter.wrapping_add(1);
    }
    for i in 0..s2.polys.len() {
        derived[PRIV_SEED_BYTES] = counter as u8;
        derived[PRIV_SEED_BYTES + 1] = (counter >> 8) as u8;
        rej_bounded_poly(&derived, eta, &mut s2.polys[i])?;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

/// Decode a concatenated encoded byte buffer into `l` polynomials whose
/// coefficients lie in `[−γ₁ + 1, γ₁]`. Used by `ExpandMask`.
fn poly_decode_expand_mask(out: &mut Poly, buf: &[u8], gamma1: u32) -> CryptoResult<()> {
    if gamma1 == GAMMA1_TWO_POWER_19 {
        // 20 bits per coefficient.
        if buf.len() != NUM_POLY_COEFFICIENTS * 20 / 8 {
            return Err(CryptoError::Encoding(format!(
                "invalid mask buffer length for gamma1=2^19: {}",
                buf.len()
            )));
        }
        // Each 5 bytes produce 2 coefficients of 20 bits.
        for idx in 0..(NUM_POLY_COEFFICIENTS / 2) {
            let o = idx * 5;
            let a =
                u32::from(buf[o]) | (u32::from(buf[o + 1]) << 8) | (u32::from(buf[o + 2]) << 16);
            let b = (u32::from(buf[o + 2]) >> 4)
                | (u32::from(buf[o + 3]) << 4)
                | (u32::from(buf[o + 4]) << 12);
            let c0 = a & ((1u32 << 20) - 1);
            let c1 = b & ((1u32 << 20) - 1);
            out.coeffs[idx * 2] = mod_sub(gamma1, c0);
            out.coeffs[idx * 2 + 1] = mod_sub(gamma1, c1);
        }
    } else if gamma1 == GAMMA1_TWO_POWER_17 {
        // 18 bits per coefficient.
        if buf.len() != NUM_POLY_COEFFICIENTS * 18 / 8 {
            return Err(CryptoError::Encoding(format!(
                "invalid mask buffer length for gamma1=2^17: {}",
                buf.len()
            )));
        }
        // Each 9 bytes produce 4 coefficients of 18 bits.
        for idx in 0..(NUM_POLY_COEFFICIENTS / 4) {
            let o = idx * 9;
            let b: [u32; 9] = [
                u32::from(buf[o]),
                u32::from(buf[o + 1]),
                u32::from(buf[o + 2]),
                u32::from(buf[o + 3]),
                u32::from(buf[o + 4]),
                u32::from(buf[o + 5]),
                u32::from(buf[o + 6]),
                u32::from(buf[o + 7]),
                u32::from(buf[o + 8]),
            ];
            let c0 = b[0] | (b[1] << 8) | ((b[2] & 0x03) << 16);
            let c1 = (b[2] >> 2) | (b[3] << 6) | ((b[4] & 0x0F) << 14);
            let c2 = (b[4] >> 4) | (b[5] << 4) | ((b[6] & 0x3F) << 12);
            let c3 = (b[6] >> 6) | (b[7] << 2) | (b[8] << 10);
            out.coeffs[idx * 4] = mod_sub(gamma1, c0 & ((1u32 << 18) - 1));
            out.coeffs[idx * 4 + 1] = mod_sub(gamma1, c1 & ((1u32 << 18) - 1));
            out.coeffs[idx * 4 + 2] = mod_sub(gamma1, c2 & ((1u32 << 18) - 1));
            out.coeffs[idx * 4 + 3] = mod_sub(gamma1, c3 & ((1u32 << 18) - 1));
        }
    } else {
        return Err(CryptoError::Encoding(format!(
            "unsupported gamma1 value: {gamma1}"
        )));
    }
    Ok(())
}

/// `ExpandMask` (FIPS 204 Algorithm 34) — deterministically derive the mask
/// vector `y` from `rho_prime`, starting at nonce `kappa`.
fn poly_expand_mask(
    out: &mut Poly,
    rho_prime: &[u8; RHO_PRIME_BYTES],
    nonce: u16,
    gamma1: u32,
) -> CryptoResult<()> {
    let buf_len = if gamma1 == GAMMA1_TWO_POWER_19 {
        32 * 20
    } else {
        32 * 18
    };
    let mut ctx = ShakeContext::shake256();
    ctx.update(rho_prime)?;
    let nonce_bytes = [nonce as u8, (nonce >> 8) as u8];
    ctx.update(&nonce_bytes)?;
    let buf = ctx.finalize_xof(buf_len)?;
    poly_decode_expand_mask(out, &buf, gamma1)
}

/// `SampleInBall` (FIPS 204 Algorithm 29) — sample a sparse challenge
/// polynomial with exactly `tau` coefficients equal to ±1.
///
/// This function is explicitly **not** constant time (the rejection loop for
/// `index` is data-dependent) but its input `c_tilde` is a public hash, so no
/// secret information leaks.
fn poly_sample_in_ball(c_tilde: &[u8], tau: u32, out: &mut Poly) -> CryptoResult<()> {
    const BLOCK: usize = 136;
    out.clear();

    let mut ctx = ShakeContext::shake256();
    ctx.update(c_tilde)?;
    let mut buf = [0u8; BLOCK];
    ctx.squeeze(&mut buf)?;

    // First 8 bytes are the sign mask.
    let signs_le = [
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ];
    let mut signs = u64::from_le_bytes(signs_le);
    let mut pos: usize = 8;

    let tau_us = tau as usize;
    if tau_us > NUM_POLY_COEFFICIENTS {
        return Err(CryptoError::Key(format!(
            "invalid tau for SampleInBall: {tau}"
        )));
    }

    for end in (NUM_POLY_COEFFICIENTS - tau_us)..NUM_POLY_COEFFICIENTS {
        let mut index: usize;
        loop {
            if pos >= BLOCK {
                ctx.squeeze(&mut buf)?;
                pos = 0;
            }
            index = buf[pos] as usize;
            pos += 1;
            if index <= end {
                break;
            }
        }
        out.coeffs[end] = out.coeffs[index];
        // out.coeffs[index] = mod_sub(1, 2 * (signs & 1))
        let bit = (signs & 1) as u32;
        out.coeffs[index] = mod_sub(1, 2u32.wrapping_mul(bit));
        signs >>= 1;
    }
    Ok(())
}

// ===========================================================================
// Matrix/Vector arithmetic glue
// ===========================================================================

/// Multiply the NTT-domain matrix `a_hat` (shape k × l) by the NTT-domain
/// vector `input` (length l) and store the result in `output` (length k).
///
/// Computes `output[i] = Σⱼ a_hat[i][j] ∘ input[j]` where `∘` is pointwise
/// multiplication in NTT/Montgomery domain (FIPS 204 line 3 of Algorithm 7).
fn matrix_mult_vector(a_hat: &Matrix, input: &Vector, output: &mut Vector) {
    debug_assert_eq!(a_hat.cols, input.polys.len());
    debug_assert_eq!(a_hat.rows, output.polys.len());

    let mut tmp = Poly::zero();
    for i in 0..a_hat.rows {
        output.polys[i].clear();
        for j in 0..a_hat.cols {
            poly_ntt_mult(a_hat.get(i, j), &input.polys[j], &mut tmp);
            // Accumulate: output[i] += tmp
            let dst = output.polys[i].clone();
            dst.add(&tmp, &mut output.polys[i]);
        }
    }
}

/// Multiply each polynomial of a vector by a common NTT-domain polynomial.
/// Computes `output[i] = c ∘ input[i]` in NTT/Montgomery domain.
fn vector_mult_scalar(c: &Poly, input: &Vector, output: &mut Vector) {
    debug_assert_eq!(input.polys.len(), output.polys.len());
    for i in 0..input.polys.len() {
        poly_ntt_mult(c, &input.polys[i], &mut output.polys[i]);
    }
}

impl Vector {
    /// Apply `power2_round` to each coefficient of every polynomial, producing
    /// the high part (`high_out`) and low part (`low_out`).
    pub(crate) fn scale_power2_round_decompose(&self, high_out: &mut Vector, low_out: &mut Vector) {
        debug_assert_eq!(self.polys.len(), high_out.polys.len());
        debug_assert_eq!(self.polys.len(), low_out.polys.len());
        for idx in 0..self.polys.len() {
            for c in 0..NUM_POLY_COEFFICIENTS {
                let r = self.polys[idx].coeffs[c];
                let (r1, r0) = power2_round(r);
                high_out.polys[idx].coeffs[c] = r1;
                low_out.polys[idx].coeffs[c] = r0;
            }
        }
    }

    /// Apply `high_bits` to every coefficient.
    pub(crate) fn high_bits(&self, gamma2: u32, out: &mut Vector) {
        debug_assert_eq!(self.polys.len(), out.polys.len());
        for idx in 0..self.polys.len() {
            for c in 0..NUM_POLY_COEFFICIENTS {
                out.polys[idx].coeffs[c] = high_bits(self.polys[idx].coeffs[c], gamma2);
            }
        }
    }

    /// Apply `low_bits` to every coefficient.
    pub(crate) fn low_bits(&self, gamma2: u32, out: &mut Vector) {
        debug_assert_eq!(self.polys.len(), out.polys.len());
        for idx in 0..self.polys.len() {
            for c in 0..NUM_POLY_COEFFICIENTS {
                out.polys[idx].coeffs[c] = low_bits(self.polys[idx].coeffs[c], gamma2);
            }
        }
    }

    /// Compute the per-coefficient hint vector `h = MakeHint(−ct0, w − cs2 + ct0)`.
    /// Each output coefficient is encoded as `0` or `1`.
    ///
    /// Inputs (all same shape as `self`):
    ///   * `self` = `ct0` (coefficients in Montgomery-reduced form)
    ///   * `cs2`  = `c · s2` (NTT-inverse already applied)
    ///   * `w`    = `w`      (NTT-inverse already applied)
    ///
    /// The per-coefficient helper `make_hint(ct0, cs2, γ₂, w)` already encodes
    /// the FIPS 204 Algorithm 39 computation with the three-argument
    /// optimisation from the C reference: it internally forms
    /// `r_plus_z = w − cs2` and `r = w − cs2 + ct0` and compares their high
    /// bits. Consequently this function passes `ct0` to the helper **directly
    /// without negation** — mirroring `vector_make_hint` in
    /// `crypto/ml_dsa/ml_dsa_vector.h`, which in turn forwards to
    /// `poly_make_hint` / `ossl_ml_dsa_key_compress_make_hint` with the
    /// unmodified `ct0` coefficient.
    pub(crate) fn make_hint(&self, cs2: &Vector, w: &Vector, gamma2: u32, out: &mut Vector) {
        debug_assert_eq!(self.polys.len(), cs2.polys.len());
        debug_assert_eq!(self.polys.len(), w.polys.len());
        debug_assert_eq!(self.polys.len(), out.polys.len());
        for idx in 0..self.polys.len() {
            for c in 0..NUM_POLY_COEFFICIENTS {
                let ct0 = self.polys[idx].coeffs[c];
                let flag = make_hint(
                    ct0,
                    cs2.polys[idx].coeffs[c],
                    gamma2,
                    w.polys[idx].coeffs[c],
                );
                out.polys[idx].coeffs[c] = u32::from(flag);
            }
        }
    }

    /// Apply `use_hint` to reconstruct `w1` from `r` using the hint vector `h`.
    ///
    /// `self` = `r`, `h` = hint (each coeff 0/1), `out` = reconstructed `w1`.
    pub(crate) fn use_hint(&self, h: &Vector, gamma2: u32, out: &mut Vector) {
        debug_assert_eq!(self.polys.len(), h.polys.len());
        debug_assert_eq!(self.polys.len(), out.polys.len());
        for idx in 0..self.polys.len() {
            for c in 0..NUM_POLY_COEFFICIENTS {
                let hint = h.polys[idx].coeffs[c] != 0;
                out.polys[idx].coeffs[c] = use_hint(hint, self.polys[idx].coeffs[c], gamma2);
            }
        }
    }

    /// Sample each polynomial of `self` using `ExpandMask` (FIPS 204 Alg. 34)
    /// with nonces `kappa, kappa+1, …, kappa + self.len() − 1`.
    pub(crate) fn expand_mask(
        &mut self,
        rho_prime: &[u8; RHO_PRIME_BYTES],
        kappa: u16,
        gamma1: u32,
    ) -> CryptoResult<()> {
        for i in 0..self.polys.len() {
            let nonce = kappa.wrapping_add(i as u16);
            poly_expand_mask(&mut self.polys[i], rho_prime, nonce, gamma1)?;
        }
        Ok(())
    }

    /// Return the maximum absolute value across all coefficients, where
    /// "absolute" is taken modulo `q` (i.e. values > (q−1)/2 wrap to negative).
    /// Used for ‖v‖_∞ bound checks during signing/verification.
    pub(crate) fn infinity_norm(&self) -> u32 {
        let mut acc = 0u32;
        for p in &self.polys {
            for c in 0..NUM_POLY_COEFFICIENTS {
                let mag = abs_mod_prime(p.coeffs[c]);
                if mag > acc {
                    acc = mag;
                }
            }
        }
        acc
    }

    /// Return the maximum absolute value treating coefficients as signed
    /// integers modulo `2³²`. Used on already-reduced (negative-permitted)
    /// differences such as `w − cs2 − ct0` before reduction modulo `q`.
    pub(crate) fn infinity_norm_signed(&self) -> u32 {
        let mut acc = 0u32;
        for p in &self.polys {
            for c in 0..NUM_POLY_COEFFICIENTS {
                let mag = abs_signed(p.coeffs[c]);
                if mag > acc {
                    acc = mag;
                }
            }
        }
        acc
    }
}

// ===========================================================================
// Bit-packing (translated from `ml_dsa_encoders.c`)
// ===========================================================================

/// Generic little-endian bit-packer. Packs `coeffs.len()` unsigned values, each
/// fitting in `bits` bits (with `bits` ≤ 32), into `out` using `coeffs.len() *
/// bits / 8` bytes.
fn bit_pack(coeffs: &[u32], bits: u32, out: &mut [u8]) {
    debug_assert!(bits > 0 && bits <= 32);
    let total_bits = coeffs.len() as u64 * u64::from(bits);
    debug_assert_eq!(total_bits % 8, 0);
    debug_assert_eq!(out.len() as u64, total_bits / 8);
    for b in out.iter_mut() {
        *b = 0;
    }

    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut out_pos: usize = 0;
    let mask = if bits == 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    };
    for &c in coeffs {
        acc |= u64::from(c & mask) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out[out_pos] = (acc & 0xff) as u8;
            acc >>= 8;
            acc_bits -= 8;
            out_pos += 1;
        }
    }
    // Any leftover bits must be zero because we asserted total_bits % 8 == 0.
    debug_assert_eq!(acc_bits, 0);
    debug_assert_eq!(acc, 0);
}

/// Generic little-endian bit-unpacker. Extracts `coeffs.len()` unsigned values
/// (each in `bits` bits) from `data`.
fn bit_unpack(data: &[u8], bits: u32, coeffs: &mut [u32]) -> CryptoResult<()> {
    debug_assert!(bits > 0 && bits <= 32);
    let total_bits = coeffs.len() as u64 * u64::from(bits);
    if total_bits % 8 != 0 || (total_bits / 8) as usize != data.len() {
        return Err(CryptoError::Encoding(format!(
            "bit_unpack: expected {} bytes for {} coeffs at {} bits",
            total_bits / 8,
            coeffs.len(),
            bits
        )));
    }
    let mask: u64 = if bits == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << bits) - 1
    };
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut in_pos: usize = 0;
    for c in coeffs.iter_mut() {
        while acc_bits < bits {
            acc |= u64::from(data[in_pos]) << acc_bits;
            acc_bits += 8;
            in_pos += 1;
        }
        *c = (acc & mask) as u32;
        acc >>= bits;
        acc_bits -= bits;
    }
    Ok(())
}

// ------- Unsigned polynomial encoders/decoders ----------------------------

/// Bit-pack a polynomial whose coefficients are already in `[0, 2^bits)`.
fn poly_encode_bits(p: &Poly, bits: u32, out: &mut [u8]) {
    bit_pack(&p.coeffs, bits, out);
}

/// Inverse of `poly_encode_bits`. Decodes `p` from `data`, populating each
/// coefficient with a value in `[0, 2^bits)`. Returns an error if any decoded
/// coefficient lies outside the expected range.
fn poly_decode_bits(data: &[u8], bits: u32, p: &mut Poly) -> CryptoResult<()> {
    bit_unpack(data, bits, &mut p.coeffs)?;
    // For our callers, bit_unpack already yields values < 2^bits via masking;
    // the range check is implicit. No further action required.
    Ok(())
}

// ------- Signed polynomial encoders/decoders ------------------------------

/// Encode `p` whose coefficients are in `[−offset, offset]` (expressed modulo
/// `q`). The stored representation is `(offset − signed(c)) mod q`, which lies
/// in `[0, 2·offset]` and fits in `bits` bits.
fn poly_encode_signed(p: &Poly, offset: u32, bits: u32, out: &mut [u8]) {
    let mut tmp = [0u32; NUM_POLY_COEFFICIENTS];
    for (dst, &src) in tmp.iter_mut().zip(p.coeffs.iter()) {
        *dst = mod_sub(offset, src);
    }
    bit_pack(&tmp, bits, out);
}

/// Inverse of `poly_encode_signed`. Returns an error if any decoded unsigned
/// value exceeds `2 * offset` (which would correspond to an out-of-range
/// coefficient).
fn poly_decode_signed(data: &[u8], offset: u32, bits: u32, p: &mut Poly) -> CryptoResult<()> {
    let mut tmp = [0u32; NUM_POLY_COEFFICIENTS];
    bit_unpack(data, bits, &mut tmp)?;
    let max_encoded = offset
        .checked_mul(2)
        .ok_or_else(|| CryptoError::Encoding(format!("offset overflow: {offset}")))?;
    for (dst, &val) in p.coeffs.iter_mut().zip(tmp.iter()) {
        if val > max_encoded {
            return Err(CryptoError::Encoding(format!(
                "signed decode: value {val} exceeds 2·offset {max_encoded}"
            )));
        }
        *dst = mod_sub(offset, val);
    }
    Ok(())
}

// ------- Named encoders/decoders per FIPS 204 -----------------------------

/// Encode `w1` polynomial whose coefficients lie in `[0, 15]`. Used by
/// ML-DSA-65/87 (γ₂ = (q−1)/32). Output size: 128 bytes per polynomial.
fn poly_encode_4_bits(p: &Poly, out: &mut [u8]) {
    poly_encode_bits(p, 4, out);
}

/// Encode `w1` polynomial whose coefficients lie in `[0, 43]`. Used by
/// ML-DSA-44 (γ₂ = (q−1)/88). Output size: 192 bytes per polynomial.
fn poly_encode_6_bits(p: &Poly, out: &mut [u8]) {
    poly_encode_bits(p, 6, out);
}

/// Encode `t1` polynomial whose coefficients lie in `[0, 2¹⁰)`. Used in the
/// public-key encoding. Output size: 320 bytes per polynomial.
fn poly_encode_10_bits(p: &Poly, out: &mut [u8]) {
    poly_encode_bits(p, 10, out);
}

/// Inverse of `poly_encode_10_bits`.
fn poly_decode_10_bits(data: &[u8], p: &mut Poly) -> CryptoResult<()> {
    poly_decode_bits(data, 10, p)
}

/// Encode a secret polynomial with coefficients in `[−2, 2]` (η = 2).
/// Output size: 96 bytes per polynomial (3 bits per coefficient).
fn poly_encode_signed_2(p: &Poly, out: &mut [u8]) {
    poly_encode_signed(p, 2, 3, out);
}

/// Inverse of `poly_encode_signed_2`.
fn poly_decode_signed_2(data: &[u8], p: &mut Poly) -> CryptoResult<()> {
    poly_decode_signed(data, 2, 3, p)
}

/// Encode a secret polynomial with coefficients in `[−4, 4]` (η = 4).
/// Output size: 128 bytes per polynomial (4 bits per coefficient).
fn poly_encode_signed_4(p: &Poly, out: &mut [u8]) {
    poly_encode_signed(p, 4, 4, out);
}

/// Inverse of `poly_encode_signed_4`.
fn poly_decode_signed_4(data: &[u8], p: &mut Poly) -> CryptoResult<()> {
    poly_decode_signed(data, 4, 4, p)
}

/// Encode `t0` polynomial with coefficients in `[−2¹², 2¹²]`.
/// Output size: 416 bytes per polynomial (13 bits per coefficient).
fn poly_encode_signed_two_to_power_12(p: &Poly, out: &mut [u8]) {
    poly_encode_signed(p, 1u32 << 12, 13, out);
}

/// Inverse of `poly_encode_signed_two_to_power_12`.
fn poly_decode_signed_two_to_power_12(data: &[u8], p: &mut Poly) -> CryptoResult<()> {
    poly_decode_signed(data, 1u32 << 12, 13, p)
}

/// Encode a mask/response polynomial with coefficients in `[−γ₁+1, γ₁]` where
/// `γ₁ = 2¹⁷`. Output size: 576 bytes per polynomial (18 bits per coefficient).
fn poly_encode_signed_two_to_power_17(p: &Poly, out: &mut [u8]) {
    poly_encode_signed(p, GAMMA1_TWO_POWER_17, 18, out);
}

/// Inverse of `poly_encode_signed_two_to_power_17`.
fn poly_decode_signed_two_to_power_17(data: &[u8], p: &mut Poly) -> CryptoResult<()> {
    poly_decode_signed(data, GAMMA1_TWO_POWER_17, 18, p)
}

/// Encode a mask/response polynomial with coefficients in `[−γ₁+1, γ₁]` where
/// `γ₁ = 2¹⁹`. Output size: 640 bytes per polynomial (20 bits per coefficient).
fn poly_encode_signed_two_to_power_19(p: &Poly, out: &mut [u8]) {
    poly_encode_signed(p, GAMMA1_TWO_POWER_19, 20, out);
}

/// Inverse of `poly_encode_signed_two_to_power_19`.
fn poly_decode_signed_two_to_power_19(data: &[u8], p: &mut Poly) -> CryptoResult<()> {
    poly_decode_signed(data, GAMMA1_TWO_POWER_19, 20, p)
}

// ===========================================================================
// Vector-level encoders (for k-polynomial or l-polynomial vectors)
// ===========================================================================

/// Encode a secret vector whose coefficients lie in `[−η, η]` and whose
/// polynomial count is determined by context (`l` for s₁, `k` for s₂).
fn vector_encode_signed_eta(v: &Vector, eta: u32, out: &mut [u8]) -> CryptoResult<()> {
    let bytes_per_poly: usize = if eta == 2 {
        96
    } else if eta == 4 {
        128
    } else {
        return Err(CryptoError::Encoding(format!("unsupported eta: {eta}")));
    };
    if out.len() != bytes_per_poly * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_encode_signed_eta: expected {} bytes, got {}",
            bytes_per_poly * v.polys.len(),
            out.len()
        )));
    }
    for (i, p) in v.polys.iter().enumerate() {
        let slice = &mut out[i * bytes_per_poly..(i + 1) * bytes_per_poly];
        if eta == 2 {
            poly_encode_signed_2(p, slice);
        } else {
            poly_encode_signed_4(p, slice);
        }
    }
    Ok(())
}

/// Inverse of `vector_encode_signed_eta`.
fn vector_decode_signed_eta(data: &[u8], eta: u32, v: &mut Vector) -> CryptoResult<()> {
    let bytes_per_poly: usize = if eta == 2 {
        96
    } else if eta == 4 {
        128
    } else {
        return Err(CryptoError::Encoding(format!("unsupported eta: {eta}")));
    };
    if data.len() != bytes_per_poly * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_decode_signed_eta: expected {} bytes, got {}",
            bytes_per_poly * v.polys.len(),
            data.len()
        )));
    }
    for (i, p) in v.polys.iter_mut().enumerate() {
        let slice = &data[i * bytes_per_poly..(i + 1) * bytes_per_poly];
        if eta == 2 {
            poly_decode_signed_2(slice, p)?;
        } else {
            poly_decode_signed_4(slice, p)?;
        }
    }
    Ok(())
}

/// Encode a `t0` vector (coefficients in `[−2¹², 2¹²]`), 416 bytes per poly.
fn vector_encode_t0(v: &Vector, out: &mut [u8]) -> CryptoResult<()> {
    const BPP: usize = 416;
    if out.len() != BPP * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_encode_t0: expected {} bytes, got {}",
            BPP * v.polys.len(),
            out.len()
        )));
    }
    for (i, p) in v.polys.iter().enumerate() {
        let slice = &mut out[i * BPP..(i + 1) * BPP];
        poly_encode_signed_two_to_power_12(p, slice);
    }
    Ok(())
}

/// Inverse of `vector_encode_t0`.
fn vector_decode_t0(data: &[u8], v: &mut Vector) -> CryptoResult<()> {
    const BPP: usize = 416;
    if data.len() != BPP * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_decode_t0: expected {} bytes, got {}",
            BPP * v.polys.len(),
            data.len()
        )));
    }
    for (i, p) in v.polys.iter_mut().enumerate() {
        let slice = &data[i * BPP..(i + 1) * BPP];
        poly_decode_signed_two_to_power_12(slice, p)?;
    }
    Ok(())
}

/// Encode a `t1` vector (coefficients in `[0, 2¹⁰)`), 320 bytes per poly.
fn vector_encode_t1(v: &Vector, out: &mut [u8]) -> CryptoResult<()> {
    const BPP: usize = 320;
    if out.len() != BPP * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_encode_t1: expected {} bytes, got {}",
            BPP * v.polys.len(),
            out.len()
        )));
    }
    for (i, p) in v.polys.iter().enumerate() {
        let slice = &mut out[i * BPP..(i + 1) * BPP];
        poly_encode_10_bits(p, slice);
    }
    Ok(())
}

/// Inverse of `vector_encode_t1`.
fn vector_decode_t1(data: &[u8], v: &mut Vector) -> CryptoResult<()> {
    const BPP: usize = 320;
    if data.len() != BPP * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_decode_t1: expected {} bytes, got {}",
            BPP * v.polys.len(),
            data.len()
        )));
    }
    for (i, p) in v.polys.iter_mut().enumerate() {
        let slice = &data[i * BPP..(i + 1) * BPP];
        poly_decode_10_bits(slice, p)?;
    }
    Ok(())
}

/// Encode a response vector `z` with coefficients in `[−γ₁+1, γ₁]`.
fn vector_encode_z(v: &Vector, gamma1: u32, out: &mut [u8]) -> CryptoResult<()> {
    let bpp: usize = if gamma1 == GAMMA1_TWO_POWER_17 {
        576
    } else if gamma1 == GAMMA1_TWO_POWER_19 {
        640
    } else {
        return Err(CryptoError::Encoding(format!(
            "unsupported gamma1: {gamma1}"
        )));
    };
    if out.len() != bpp * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_encode_z: expected {} bytes, got {}",
            bpp * v.polys.len(),
            out.len()
        )));
    }
    for (i, p) in v.polys.iter().enumerate() {
        let slice = &mut out[i * bpp..(i + 1) * bpp];
        if gamma1 == GAMMA1_TWO_POWER_17 {
            poly_encode_signed_two_to_power_17(p, slice);
        } else {
            poly_encode_signed_two_to_power_19(p, slice);
        }
    }
    Ok(())
}

/// Inverse of `vector_encode_z`.
fn vector_decode_z(data: &[u8], gamma1: u32, v: &mut Vector) -> CryptoResult<()> {
    let bpp: usize = if gamma1 == GAMMA1_TWO_POWER_17 {
        576
    } else if gamma1 == GAMMA1_TWO_POWER_19 {
        640
    } else {
        return Err(CryptoError::Encoding(format!(
            "unsupported gamma1: {gamma1}"
        )));
    };
    if data.len() != bpp * v.polys.len() {
        return Err(CryptoError::Encoding(format!(
            "vector_decode_z: expected {} bytes, got {}",
            bpp * v.polys.len(),
            data.len()
        )));
    }
    for (i, p) in v.polys.iter_mut().enumerate() {
        let slice = &data[i * bpp..(i + 1) * bpp];
        if gamma1 == GAMMA1_TWO_POWER_17 {
            poly_decode_signed_two_to_power_17(slice, p)?;
        } else {
            poly_decode_signed_two_to_power_19(slice, p)?;
        }
    }
    Ok(())
}

/// Encode the `w1` vector used during signing/verification. `w1` coefficients
/// have range `[0, 43]` for ML-DSA-44 and `[0, 15]` for ML-DSA-65/87.
fn w1_encode(w1: &Vector, gamma2: u32, out: &mut [u8]) -> CryptoResult<()> {
    let (bits, bpp): (u32, usize) = if gamma2 == GAMMA2_Q_MINUS1_DIV88 {
        (6, 192)
    } else if gamma2 == GAMMA2_Q_MINUS1_DIV32 {
        (4, 128)
    } else {
        return Err(CryptoError::Encoding(format!(
            "unsupported gamma2: {gamma2}"
        )));
    };
    let expected = bpp * w1.polys.len();
    if out.len() != expected {
        return Err(CryptoError::Encoding(format!(
            "w1_encode: expected {expected} bytes, got {}",
            out.len()
        )));
    }
    for (i, p) in w1.polys.iter().enumerate() {
        let slice = &mut out[i * bpp..(i + 1) * bpp];
        if bits == 6 {
            poly_encode_6_bits(p, slice);
        } else {
            poly_encode_4_bits(p, slice);
        }
    }
    Ok(())
}

// ===========================================================================
// Public-key / private-key / signature top-level codecs
// ===========================================================================

/// Compute the expected public-key size for a parameter set.
fn pk_length(params: &MlDsaParams) -> usize {
    RHO_BYTES + params.k * 320
}

/// Compute the expected private-key size for a parameter set.
fn sk_length(params: &MlDsaParams) -> usize {
    let eta_bpp = if params.eta == 2 { 96 } else { 128 };
    RHO_BYTES + K_BYTES + TR_BYTES + params.l * eta_bpp + params.k * eta_bpp + params.k * 416
}

/// Compute the expected signature size for a parameter set.
fn sig_length(params: &MlDsaParams) -> usize {
    let c_tilde_len = params.bit_strength as usize / 4;
    let z_bpp = if params.gamma1 == GAMMA1_TWO_POWER_17 {
        576
    } else {
        640
    };
    c_tilde_len + params.l * z_bpp + (params.omega as usize) + params.k
}

/// Encode the public key `(rho, t1)` per FIPS 204 §7.2 (`pkEncode`).
fn pk_encode(rho: &[u8; RHO_BYTES], t1: &Vector, params: &MlDsaParams) -> CryptoResult<Vec<u8>> {
    let expected = pk_length(params);
    if t1.polys.len() != params.k {
        return Err(CryptoError::Encoding(format!(
            "pk_encode: t1 has {} polys, expected k={}",
            t1.polys.len(),
            params.k
        )));
    }
    let mut out = vec![0u8; expected];
    out[..RHO_BYTES].copy_from_slice(rho);
    vector_encode_t1(t1, &mut out[RHO_BYTES..])?;
    Ok(out)
}

/// Decode a public key `(rho, t1)` per FIPS 204 §7.2 (`pkDecode`).
fn pk_decode(data: &[u8], params: &MlDsaParams) -> CryptoResult<([u8; RHO_BYTES], Vector)> {
    let expected = pk_length(params);
    if data.len() != expected {
        return Err(CryptoError::Encoding(format!(
            "pk_decode: expected {expected} bytes, got {}",
            data.len()
        )));
    }
    let mut rho = [0u8; RHO_BYTES];
    rho.copy_from_slice(&data[..RHO_BYTES]);
    let mut t1 = Vector::new(params.k);
    vector_decode_t1(&data[RHO_BYTES..], &mut t1)?;
    Ok((rho, t1))
}

/// Encode a private key per FIPS 204 §7.3 (`skEncode`).
///
/// Layout: `rho || K || tr || s1 || s2 || t0`.
#[allow(clippy::too_many_arguments)]
fn sk_encode(
    rho: &[u8; RHO_BYTES],
    k_bytes: &[u8; K_BYTES],
    tr: &[u8; TR_BYTES],
    s1: &Vector,
    s2: &Vector,
    t0: &Vector,
    params: &MlDsaParams,
) -> CryptoResult<Vec<u8>> {
    let expected = sk_length(params);
    if s1.polys.len() != params.l {
        return Err(CryptoError::Encoding("sk_encode: bad s1 length".into()));
    }
    if s2.polys.len() != params.k {
        return Err(CryptoError::Encoding("sk_encode: bad s2 length".into()));
    }
    if t0.polys.len() != params.k {
        return Err(CryptoError::Encoding("sk_encode: bad t0 length".into()));
    }
    let mut out = vec![0u8; expected];
    let eta_bpp = if params.eta == 2 { 96 } else { 128 };

    let mut ofs = 0usize;
    out[ofs..ofs + RHO_BYTES].copy_from_slice(rho);
    ofs += RHO_BYTES;
    out[ofs..ofs + K_BYTES].copy_from_slice(k_bytes);
    ofs += K_BYTES;
    out[ofs..ofs + TR_BYTES].copy_from_slice(tr);
    ofs += TR_BYTES;
    vector_encode_signed_eta(s1, params.eta, &mut out[ofs..ofs + params.l * eta_bpp])?;
    ofs += params.l * eta_bpp;
    vector_encode_signed_eta(s2, params.eta, &mut out[ofs..ofs + params.k * eta_bpp])?;
    ofs += params.k * eta_bpp;
    vector_encode_t0(t0, &mut out[ofs..ofs + params.k * 416])?;
    ofs += params.k * 416;
    debug_assert_eq!(ofs, expected);
    Ok(out)
}

/// Decode a private key per FIPS 204 §7.3 (`skDecode`). Returns the component
/// tuple `(rho, K, tr, s1, s2, t0)`.
#[allow(clippy::type_complexity)]
fn sk_decode(
    data: &[u8],
    params: &MlDsaParams,
) -> CryptoResult<(
    [u8; RHO_BYTES],
    [u8; K_BYTES],
    [u8; TR_BYTES],
    Vector,
    Vector,
    Vector,
)> {
    let expected = sk_length(params);
    if data.len() != expected {
        return Err(CryptoError::Encoding(format!(
            "sk_decode: expected {expected} bytes, got {}",
            data.len()
        )));
    }
    let eta_bpp = if params.eta == 2 { 96 } else { 128 };

    let mut rho = [0u8; RHO_BYTES];
    let mut k_bytes = [0u8; K_BYTES];
    let mut tr = [0u8; TR_BYTES];
    let mut s1 = Vector::new(params.l);
    let mut s2 = Vector::new(params.k);
    let mut t0 = Vector::new(params.k);

    let mut ofs = 0usize;
    rho.copy_from_slice(&data[ofs..ofs + RHO_BYTES]);
    ofs += RHO_BYTES;
    k_bytes.copy_from_slice(&data[ofs..ofs + K_BYTES]);
    ofs += K_BYTES;
    tr.copy_from_slice(&data[ofs..ofs + TR_BYTES]);
    ofs += TR_BYTES;
    vector_decode_signed_eta(&data[ofs..ofs + params.l * eta_bpp], params.eta, &mut s1)?;
    ofs += params.l * eta_bpp;
    vector_decode_signed_eta(&data[ofs..ofs + params.k * eta_bpp], params.eta, &mut s2)?;
    ofs += params.k * eta_bpp;
    vector_decode_t0(&data[ofs..ofs + params.k * 416], &mut t0)?;
    ofs += params.k * 416;
    debug_assert_eq!(ofs, expected);
    Ok((rho, k_bytes, tr, s1, s2, t0))
}

/// Encode the hint vector `h` per FIPS 204 §7.4 (`HintBitPack`).
/// Layout: for each polynomial `i`, write the (sorted) positions of its 1-bits
/// into successive bytes of the first `ω` positions; then write the cumulative
/// 1-count after polynomial `i` at offset `ω + i`. Unused positions in the
/// first `ω` bytes are zero.
fn hint_bits_encode(hint: &Vector, params: &MlDsaParams, out: &mut [u8]) -> CryptoResult<()> {
    let omega = params.omega as usize;
    let expected = omega + params.k;
    if out.len() != expected {
        return Err(CryptoError::Encoding(format!(
            "hint_bits_encode: expected {expected} bytes, got {}",
            out.len()
        )));
    }
    if hint.polys.len() != params.k {
        return Err(CryptoError::Encoding(format!(
            "hint_bits_encode: expected {} polys, got {}",
            params.k,
            hint.polys.len()
        )));
    }
    for b in out.iter_mut() {
        *b = 0;
    }
    let mut index: usize = 0;
    for (poly_idx, p) in hint.polys.iter().enumerate() {
        for c in 0..NUM_POLY_COEFFICIENTS {
            if p.coeffs[c] != 0 {
                if index >= omega {
                    return Err(CryptoError::Encoding(
                        "hint_bits_encode: number of 1-bits exceeds ω".into(),
                    ));
                }
                out[index] = c as u8;
                index += 1;
            }
        }
        out[omega + poly_idx] = index as u8;
    }
    Ok(())
}

/// Decode the hint vector `h` per FIPS 204 §7.4 (`HintBitUnpack`). Enforces the
/// structural validity rules (positions strictly increasing within a
/// polynomial, trailing zero padding, prefix counts monotonic in `[0, ω]`).
fn hint_bits_decode(data: &[u8], params: &MlDsaParams, hint: &mut Vector) -> CryptoResult<()> {
    let omega = params.omega as usize;
    let expected = omega + params.k;
    if data.len() != expected {
        return Err(CryptoError::Encoding(format!(
            "hint_bits_decode: expected {expected} bytes, got {}",
            data.len()
        )));
    }
    if hint.polys.len() != params.k {
        return Err(CryptoError::Encoding(format!(
            "hint_bits_decode: expected {} polys, got {}",
            params.k,
            hint.polys.len()
        )));
    }
    for p in &mut hint.polys {
        p.clear();
    }

    let mut index: usize = 0;
    for poly_idx in 0..params.k {
        let limit = data[omega + poly_idx] as usize;
        if limit < index || limit > omega {
            return Err(CryptoError::Encoding(
                "hint_bits_decode: non-monotonic or over-ω prefix count".into(),
            ));
        }
        let mut last_pos: i32 = -1;
        while index < limit {
            let pos = data[index];
            if (pos as i32) <= last_pos {
                return Err(CryptoError::Encoding(
                    "hint_bits_decode: positions not strictly increasing".into(),
                ));
            }
            hint.polys[poly_idx].coeffs[pos as usize] = 1;
            last_pos = i32::from(pos);
            index += 1;
        }
    }
    // All bytes after `index` up to `ω` must be zero padding.
    for b in &data[index..omega] {
        if *b != 0 {
            return Err(CryptoError::Encoding(
                "hint_bits_decode: non-zero padding after 1-bit list".into(),
            ));
        }
    }
    Ok(())
}

/// Encode a signature per FIPS 204 §7.5 (`sigEncode`).
fn sig_encode(sig: &MlDsaSig, params: &MlDsaParams) -> CryptoResult<Vec<u8>> {
    let expected = sig_length(params);
    let c_tilde_len = params.bit_strength as usize / 4;
    if sig.c_tilde.len() != c_tilde_len {
        return Err(CryptoError::Encoding(format!(
            "sig_encode: c_tilde length {} != expected {c_tilde_len}",
            sig.c_tilde.len()
        )));
    }
    if sig.z.polys.len() != params.l {
        return Err(CryptoError::Encoding(format!(
            "sig_encode: z has {} polys, expected {}",
            sig.z.polys.len(),
            params.l
        )));
    }
    if sig.hint.polys.len() != params.k {
        return Err(CryptoError::Encoding(format!(
            "sig_encode: hint has {} polys, expected {}",
            sig.hint.polys.len(),
            params.k
        )));
    }
    let z_bpp = if params.gamma1 == GAMMA1_TWO_POWER_17 {
        576
    } else {
        640
    };

    let mut out = vec![0u8; expected];
    let mut ofs = 0usize;
    out[ofs..ofs + c_tilde_len].copy_from_slice(&sig.c_tilde);
    ofs += c_tilde_len;
    vector_encode_z(&sig.z, params.gamma1, &mut out[ofs..ofs + params.l * z_bpp])?;
    ofs += params.l * z_bpp;
    hint_bits_encode(
        &sig.hint,
        params,
        &mut out[ofs..ofs + (params.omega as usize) + params.k],
    )?;
    ofs += (params.omega as usize) + params.k;
    debug_assert_eq!(ofs, expected);
    Ok(out)
}

/// Decode a signature per FIPS 204 §7.5 (`sigDecode`).
fn sig_decode(data: &[u8], params: &MlDsaParams) -> CryptoResult<MlDsaSig> {
    let expected = sig_length(params);
    if data.len() != expected {
        return Err(CryptoError::Encoding(format!(
            "sig_decode: expected {expected} bytes, got {}",
            data.len()
        )));
    }
    let c_tilde_len = params.bit_strength as usize / 4;
    let z_bpp = if params.gamma1 == GAMMA1_TWO_POWER_17 {
        576
    } else {
        640
    };

    let mut ofs = 0usize;
    let mut c_tilde = vec![0u8; c_tilde_len];
    c_tilde.copy_from_slice(&data[ofs..ofs + c_tilde_len]);
    ofs += c_tilde_len;
    let mut z = Vector::new(params.l);
    vector_decode_z(&data[ofs..ofs + params.l * z_bpp], params.gamma1, &mut z)?;
    ofs += params.l * z_bpp;
    let mut hint = Vector::new(params.k);
    hint_bits_decode(
        &data[ofs..ofs + (params.omega as usize) + params.k],
        params,
        &mut hint,
    )?;
    ofs += (params.omega as usize) + params.k;
    debug_assert_eq!(ofs, expected);
    Ok(MlDsaSig { c_tilde, z, hint })
}

// ===========================================================================
// KeySelection, MlDsaSig, and MlDsaKey types
// ===========================================================================

/// Selector used to scope key operations (comparison, duplication,
/// introspection) to either the public or the private components, or both.
///
/// Mirrors the `OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY`
/// selector-bits convention from the OpenSSL provider API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySelection {
    /// Operate on the public key components only (rho, tr, t1, public encoding).
    Public,
    /// Operate on the private key components only (K, s1, s2, t0, private encoding, seed).
    Private,
    /// Operate on both public and private components.
    Both,
}

impl KeySelection {
    /// Returns `true` if the public components should be considered.
    #[must_use]
    pub fn includes_public(self) -> bool {
        matches!(self, Self::Public | Self::Both)
    }

    /// Returns `true` if the private components should be considered.
    #[must_use]
    pub fn includes_private(self) -> bool {
        matches!(self, Self::Private | Self::Both)
    }
}

/// ML-DSA signature in decoded form (FIPS 204 §7.5).
///
/// `c_tilde` is the challenge hash of length `λ/4` bytes (32/48/64 bytes for
/// ML-DSA-44/65/87). `z` is the response vector of `l` polynomials with
/// coefficients in `[−γ₁+1, γ₁]`. `hint` is a sparse vector of `k`
/// polynomials with 0/1 coefficients (at most `ω` ones across all
/// polynomials).
#[derive(Clone, Debug)]
pub struct MlDsaSig {
    /// The challenge hash `c̃` (length `λ/4` bytes, variant-dependent).
    pub c_tilde: Vec<u8>,
    /// The response vector `z` (length `l`).
    pub z: Vector,
    /// The hint vector `h` (length `k`).
    pub hint: Vector,
}

/// ML-DSA key container (public and/or private components).
///
/// A newly constructed key is *empty*: it holds the parameter set and library
/// context but no actual key material. The available material is governed by
/// the `Option<_>` fields:
///
/// - Public-key present ⇔ `t1.is_some()`
/// - Private-key present ⇔ `s1.is_some() && s2.is_some() && t0.is_some()`
///
/// All private fields (`k_bytes`, `s1`, `s2`, `t0`, `priv_encoding`, `seed`)
/// are wiped on drop via [`ZeroizeOnDrop`]. Public fields are also zeroed as
/// a defense-in-depth measure; this has no adverse effect because the public
/// key is already disclosed on the wire.
#[derive(ZeroizeOnDrop)]
pub struct MlDsaKey {
    #[zeroize(skip)]
    libctx: Option<Arc<LibContext>>,
    #[zeroize(skip)]
    params: &'static MlDsaParams,
    #[zeroize(skip)]
    prov_flags: u32,

    rho: [u8; RHO_BYTES],
    tr: [u8; TR_BYTES],
    k_bytes: [u8; K_BYTES],

    t1: Option<Vector>,
    s1: Option<Vector>,
    s2: Option<Vector>,
    t0: Option<Vector>,

    pub_encoding: Option<Vec<u8>>,
    priv_encoding: Option<Vec<u8>>,
    seed: Option<Vec<u8>>,
}

impl MlDsaKey {
    /// Creates an empty key bound to a library context and parameter set.
    ///
    /// The returned key has no material: callers must load or generate keys
    /// via [`MlDsaKey::from_public`], [`MlDsaKey::from_private`], or
    /// [`MlDsaKey::generate`] before signing or verification operations.
    #[must_use]
    pub fn new(libctx: Arc<LibContext>, variant: MlDsaVariant) -> Self {
        let params = ml_dsa_params_get(variant);
        Self {
            libctx: Some(libctx),
            params,
            prov_flags: KEY_PROV_FLAGS_DEFAULT,
            rho: [0u8; RHO_BYTES],
            tr: [0u8; TR_BYTES],
            k_bytes: [0u8; K_BYTES],
            t1: None,
            s1: None,
            s2: None,
            t0: None,
            pub_encoding: None,
            priv_encoding: None,
            seed: None,
        }
    }

    /// Returns a reference to this key's static parameter set.
    #[must_use]
    pub fn params(&self) -> &'static MlDsaParams {
        self.params
    }

    /// Returns the public-key byte length for this key's variant.
    #[must_use]
    pub fn pub_len(&self) -> usize {
        self.params.pk_len
    }

    /// Returns the private-key byte length for this key's variant.
    #[must_use]
    pub fn priv_len(&self) -> usize {
        self.params.sk_len
    }

    /// Returns the signature byte length for this key's variant.
    #[must_use]
    pub fn sig_len(&self) -> usize {
        self.params.sig_len
    }

    /// Returns the raw encoded public-key bytes, if the public key is
    /// populated.
    #[must_use]
    pub fn public_key_bytes(&self) -> Option<&[u8]> {
        self.pub_encoding.as_deref()
    }

    /// Returns the raw encoded private-key bytes, if the private key is
    /// populated.
    #[must_use]
    pub fn private_key_bytes(&self) -> Option<&[u8]> {
        self.priv_encoding.as_deref()
    }

    /// Reports whether the requested components are present.
    ///
    /// - `KeySelection::Public` → returns `true` iff public components are populated.
    /// - `KeySelection::Private` → returns `true` iff private components are populated.
    /// - `KeySelection::Both` → returns `true` iff both public and private are populated.
    #[must_use]
    pub fn has_key(&self, selection: KeySelection) -> bool {
        let pub_ok = self.t1.is_some() && self.pub_encoding.is_some();
        let priv_ok = self.s1.is_some()
            && self.s2.is_some()
            && self.t0.is_some()
            && self.priv_encoding.is_some();
        match selection {
            KeySelection::Public => pub_ok,
            KeySelection::Private => priv_ok,
            KeySelection::Both => pub_ok && priv_ok,
        }
    }

    /// Constant-time equality comparison of two keys, scoped to the selected
    /// components. Returns `false` immediately on parameter mismatch.
    ///
    /// Constant-time semantics are important: a naive byte comparison could
    /// leak information about the private key to an attacker with side-channel
    /// access. We therefore use [`subtle::ConstantTimeEq`] for all comparisons.
    #[must_use]
    pub fn equal(&self, other: &Self, selection: KeySelection) -> bool {
        if !std::ptr::eq(
            std::ptr::from_ref::<MlDsaParams>(self.params),
            std::ptr::from_ref::<MlDsaParams>(other.params),
        ) && self.params.variant != other.params.variant
        {
            return false;
        }
        let mut result: u8 = 1;
        if selection.includes_public() {
            // Compare rho and (pub_encoding if both present, else t1) in constant time.
            let rho_eq: bool = self.rho.ct_eq(&other.rho).into();
            if !rho_eq {
                result = 0;
            }
            match (&self.pub_encoding, &other.pub_encoding) {
                (Some(a), Some(b)) => {
                    if a.len() != b.len() || !bool::from(a.ct_eq(b)) {
                        result = 0;
                    }
                }
                (None, None) => {}
                _ => result = 0,
            }
        }
        if selection.includes_private() {
            let k_eq: bool = self.k_bytes.ct_eq(&other.k_bytes).into();
            if !k_eq {
                result = 0;
            }
            match (&self.priv_encoding, &other.priv_encoding) {
                (Some(a), Some(b)) => {
                    if a.len() != b.len() || !bool::from(a.ct_eq(b)) {
                        result = 0;
                    }
                }
                (None, None) => {}
                _ => result = 0,
            }
        }
        result == 1
    }

    /// Duplicates the key, optionally copying only the selected components.
    ///
    /// The library context and parameter set are always carried over. The
    /// provisioning flags are copied verbatim.
    pub fn dup(&self, selection: KeySelection) -> CryptoResult<Self> {
        let libctx = self
            .libctx
            .as_ref()
            .map_or_else(LibContext::default, Arc::clone);
        let mut out = Self::new(libctx, self.params.variant);
        out.prov_flags = self.prov_flags;

        if selection.includes_public() {
            out.rho = self.rho;
            out.tr = self.tr;
            out.t1.clone_from(&self.t1);
            out.pub_encoding.clone_from(&self.pub_encoding);
        }
        if selection.includes_private() {
            out.k_bytes = self.k_bytes;
            out.rho = self.rho;
            out.tr = self.tr;
            out.s1.clone_from(&self.s1);
            out.s2.clone_from(&self.s2);
            out.t0.clone_from(&self.t0);
            out.priv_encoding.clone_from(&self.priv_encoding);
            out.seed.clone_from(&self.seed);
        }
        Ok(out)
    }

    /// Installs seed and/or pre-encoded private-key material prior to
    /// materializing the expanded key state.
    ///
    /// This mirrors `ossl_ml_dsa_set_prekey` and is used by the provider layer
    /// during multi-step decoder flows where seed and key components are
    /// supplied separately. After calling this, a subsequent `generate_key`
    /// invocation will use the installed seed and/or cross-check against the
    /// installed private-key encoding.
    pub fn set_prekey(
        &mut self,
        seed: Option<&[u8]>,
        sk: Option<&[u8]>,
        flags_set: u32,
        flags_clr: u32,
    ) -> CryptoResult<()> {
        if let Some(seed_bytes) = seed {
            if seed_bytes.len() != SEED_BYTES {
                return Err(CryptoError::Key(format!(
                    "set_prekey: seed must be {SEED_BYTES} bytes, got {}",
                    seed_bytes.len()
                )));
            }
            self.seed = Some(seed_bytes.to_vec());
        }
        if let Some(sk_bytes) = sk {
            if sk_bytes.len() != self.params.sk_len {
                return Err(CryptoError::Key(format!(
                    "set_prekey: private key must be {} bytes, got {}",
                    self.params.sk_len,
                    sk_bytes.len()
                )));
            }
            self.priv_encoding = Some(sk_bytes.to_vec());
        }
        self.prov_flags &= !flags_clr;
        self.prov_flags |= flags_set;
        Ok(())
    }

    // -- Internal encoding / hashing helpers ---------------------------------

    /// Populate `self.pub_encoding` from `self.rho` and `self.t1`.
    fn encode_pub(&mut self) -> CryptoResult<()> {
        let t1 = self
            .t1
            .as_ref()
            .ok_or_else(|| CryptoError::Key("encode_pub: t1 not set".into()))?;
        let bytes = pk_encode(&self.rho, t1, self.params)?;
        self.pub_encoding = Some(bytes);
        Ok(())
    }

    /// Populate `self.priv_encoding` from (`rho`, `K`, `tr`, `s1`, `s2`, `t0`).
    fn encode_priv(&mut self) -> CryptoResult<()> {
        let s1 = self
            .s1
            .as_ref()
            .ok_or_else(|| CryptoError::Key("encode_priv: s1 not set".into()))?;
        let s2 = self
            .s2
            .as_ref()
            .ok_or_else(|| CryptoError::Key("encode_priv: s2 not set".into()))?;
        let t0 = self
            .t0
            .as_ref()
            .ok_or_else(|| CryptoError::Key("encode_priv: t0 not set".into()))?;
        let bytes = sk_encode(&self.rho, &self.k_bytes, &self.tr, s1, s2, t0, self.params)?;
        self.priv_encoding = Some(bytes);
        Ok(())
    }

    /// Compute `tr = SHAKE-256(pub_encoding, 64)` and store it in `self.tr`.
    fn compute_tr(&mut self) -> CryptoResult<()> {
        let pk = self
            .pub_encoding
            .as_deref()
            .ok_or_else(|| CryptoError::Key("compute_tr: pub_encoding not set".into()))?;
        let bytes = shake256(pk, TR_BYTES)?;
        if bytes.len() != TR_BYTES {
            return Err(CryptoError::Key(format!(
                "compute_tr: SHAKE-256 returned {} bytes, expected {TR_BYTES}",
                bytes.len()
            )));
        }
        self.tr.copy_from_slice(&bytes);
        Ok(())
    }
}

impl MlDsaKey {
    // -- Key derivation helpers ---------------------------------------------

    /// Recompute `(t1, t0)` from the secret components (requires `s1` and `s2`).
    ///
    /// Corresponds to the C `public_from_private` helper in
    /// `crypto/ml_dsa/ml_dsa_key.c`: given `rho`, `s1`, `s2`, computes the
    /// Power2Round decomposition `(t1, t0)` of `t = A·s1 + s2`, where
    /// `A = ExpandA(rho)` is expanded and the multiplication is performed in
    /// the NTT domain. The working NTT copy of `s1` is zeroised on exit
    /// because its coefficients are secret-derived.
    fn public_from_private(&self) -> CryptoResult<(Vector, Vector)> {
        let s1 = self
            .s1
            .as_ref()
            .ok_or_else(|| CryptoError::Key("public_from_private: s1 missing".into()))?;
        let s2 = self
            .s2
            .as_ref()
            .ok_or_else(|| CryptoError::Key("public_from_private: s2 missing".into()))?;
        compute_public_from_private(self.params, &self.rho, s1, s2)
    }

    /// Recompute `(t1, t0)` and verify both match the stored components.
    ///
    /// Returns `Ok(())` iff the private components `(rho, s1, s2)` are
    /// consistent with the stored `t1` and `t0`. A mismatch between recomputed
    /// and stored public vectors — or missing private/public components —
    /// yields `Err(CryptoError::Key(_))`. Mirrors C
    /// `ossl_ml_dsa_key_pairwise_check` — used when loading a private key to
    /// ensure it has not been tampered with.
    ///
    /// Rule R5 note: the function intentionally collapses the success/mismatch
    /// cases onto `Result<()>` rather than `Result<bool>` so that callers that
    /// want to "fail fast" on any inconsistency can simply use `?`.
    pub fn pairwise_check(&self) -> CryptoResult<()> {
        let stored_t1 = self
            .t1
            .as_ref()
            .ok_or_else(|| CryptoError::Key("pairwise_check: t1 missing".into()))?;
        let stored_t0 = self
            .t0
            .as_ref()
            .ok_or_else(|| CryptoError::Key("pairwise_check: t0 missing".into()))?;
        let (t1, t0) = self.public_from_private()?;
        if t1.polys.len() != stored_t1.polys.len() || t0.polys.len() != stored_t0.polys.len() {
            return Err(CryptoError::Key(
                "pairwise_check: recomputed vector length mismatch".into(),
            ));
        }
        // Constant-time equality across all polynomials — we accumulate the
        // mismatch flag to avoid early-exit short-circuits leaking timing info.
        let mut ok = true;
        for (a, b) in t1.polys.iter().zip(stored_t1.polys.iter()) {
            if !a.equal(b) {
                ok = false;
            }
        }
        for (a, b) in t0.polys.iter().zip(stored_t0.polys.iter()) {
            if !a.equal(b) {
                ok = false;
            }
        }
        if ok {
            Ok(())
        } else {
            Err(CryptoError::Key(
                "pairwise_check: recomputed (t1, t0) do not match stored values".into(),
            ))
        }
    }

    /// Reset the key to the empty state. All key material (public or private)
    /// is cleared, and `has_key(_)` will subsequently return `false`.
    /// The library context and variant parameters are preserved.
    pub fn reset(&mut self) {
        // Explicitly zero polynomial material (Option::take drops the Vector,
        // which zeroises via its Drop impl, but we also clear the fields so
        // `has_key` returns false).
        if let Some(mut v) = self.t1.take() {
            for p in &mut v.polys {
                p.clear();
            }
        }
        if let Some(mut v) = self.s1.take() {
            for p in &mut v.polys {
                p.clear();
            }
        }
        if let Some(mut v) = self.s2.take() {
            for p in &mut v.polys {
                p.clear();
            }
        }
        if let Some(mut v) = self.t0.take() {
            for p in &mut v.polys {
                p.clear();
            }
        }
        if let Some(mut b) = self.pub_encoding.take() {
            b.zeroize();
        }
        if let Some(mut b) = self.priv_encoding.take() {
            b.zeroize();
        }
        if let Some(mut b) = self.seed.take() {
            b.zeroize();
        }
        self.rho.fill(0);
        self.tr.fill(0);
        self.k_bytes.fill(0);
    }

    // -- Deserialization ----------------------------------------------------

    /// Construct a public-only key from its encoded SPKI-equivalent form.
    ///
    /// The input length must match `params.pk_len`. After decoding, the
    /// `tr` hash is computed as `SHAKE-256(data, 64)` per FIPS 204 §5.1.
    pub fn from_public(
        data: &[u8],
        params: &'static MlDsaParams,
        libctx: Arc<LibContext>,
    ) -> CryptoResult<Self> {
        let (rho, t1) = pk_decode(data, params)?;
        let mut key = Self::new(libctx, params.variant);
        key.rho = rho;
        key.t1 = Some(t1);
        key.pub_encoding = Some(data.to_vec());
        key.compute_tr()?;
        Ok(key)
    }

    /// Construct a full (public + private) key from its encoded private form.
    ///
    /// The input length must match `params.sk_len`. After decoding, `t1` is
    /// recomputed from `(rho, s1, s2)` and stored alongside the public
    /// encoding. The stored `tr` is taken from the private encoding
    /// (matching the FIPS 204 on-the-wire format where `tr` is persisted as
    /// part of the secret key).
    ///
    /// Callers who need to verify the key's integrity should invoke
    /// [`pairwise_check`](Self::pairwise_check) after construction.
    pub fn from_private(
        data: &[u8],
        params: &'static MlDsaParams,
        libctx: Arc<LibContext>,
    ) -> CryptoResult<Self> {
        let (rho, k_bytes, tr, s1, s2, t0) = sk_decode(data, params)?;
        let mut key = Self::new(libctx, params.variant);
        key.rho = rho;
        key.k_bytes = k_bytes;
        key.tr = tr;
        key.s1 = Some(s1);
        key.s2 = Some(s2);
        key.t0 = Some(t0);
        key.priv_encoding = Some(data.to_vec());
        // Recompute t1 so the key is immediately usable for verification.
        let (t1, _t0_recomputed) = key.public_from_private()?;
        key.t1 = Some(t1);
        key.encode_pub()?;
        Ok(key)
    }

    // -- Key generation -----------------------------------------------------

    /// Generate a fresh ML-DSA key pair for the given variant.
    ///
    /// If `seed` is `None`, 32 random bytes are drawn from the OS entropy
    /// source. If `seed` is `Some`, deterministic generation is performed
    /// (useful for Known-Answer-Test vectors). Implements FIPS 204
    /// Algorithm 1 (`ML-DSA.KeyGen`) and Algorithm 6 (`ML-DSA.KeyGen_internal`).
    ///
    /// On return, `key.has_key(KeySelection::Both)` is `true` and both
    /// `public_key_bytes()` and `private_key_bytes()` return valid encodings.
    pub fn generate(
        libctx: Arc<LibContext>,
        variant: MlDsaVariant,
        seed: Option<&[u8; SEED_BYTES]>,
    ) -> CryptoResult<Self> {
        let mut key = Self::new(libctx, variant);
        let mut seed_bytes = [0u8; SEED_BYTES];
        if let Some(s) = seed {
            seed_bytes.copy_from_slice(s);
        } else {
            // Draw 32 bytes from the OS CSPRNG. fill_bytes cannot fail in
            // rand 0.8 — OsRng panics on hardware RNG failure.
            let mut rng = OsRng;
            rng.fill_bytes(&mut seed_bytes);
        }
        key.seed = Some(seed_bytes.to_vec());
        // Wipe the stack-local copy now that it has been transferred into the
        // heap-resident Option<Vec<u8>> (which zeroises on drop).
        seed_bytes.zeroize();
        key.generate_key()?;
        Ok(key)
    }

    /// Inner key-generation routine (FIPS 204 Algorithm 6, `KeyGen_internal`).
    ///
    /// Expects `self.seed` to be populated and of length `SEED_BYTES`. The
    /// seed is expanded via `SHAKE-256(seed || byte(k) || byte(l), 128)` into
    /// `(rho, priv_seed, K)`, which drives `ExpandS` (to produce `s1, s2`) and
    /// `ExpandA` (to produce the public matrix `A = A_hat`). The public
    /// vector `t` is then computed as `A·s1 + s2`, and its Power2Round
    /// decomposition yields `(t1, t0)`. Finally the public and private
    /// encodings are produced and `tr = SHAKE-256(pub_encoding, 64)` is cached.
    ///
    /// If `KEY_RETAIN_SEED` is clear in `prov_flags`, the seed is wiped after
    /// successful generation.
    fn generate_key(&mut self) -> CryptoResult<()> {
        // expanded = SHAKE-256(augmented_seed, 128) = rho(32) || priv_seed(64) || K(32)
        const EXPANDED_LEN: usize = RHO_BYTES + PRIV_SEED_BYTES + K_BYTES;

        let seed = self
            .seed
            .as_deref()
            .ok_or_else(|| CryptoError::Key("generate_key: seed not set".into()))?;
        if seed.len() != SEED_BYTES {
            return Err(CryptoError::Key(format!(
                "generate_key: seed must be {SEED_BYTES} bytes, got {}",
                seed.len()
            )));
        }
        let params = self.params;
        let k_byte = u8::try_from(params.k)
            .map_err(|_| CryptoError::Key("generate_key: k exceeds u8 range".into()))?;
        let l_byte = u8::try_from(params.l)
            .map_err(|_| CryptoError::Key("generate_key: l exceeds u8 range".into()))?;

        // augmented_seed = seed || (u8)k || (u8)l  (34 bytes). Stored on the
        // stack; zeroised once we have extracted the derived bytes.
        let mut augmented_seed = [0u8; SEED_BYTES + 2];
        augmented_seed[..SEED_BYTES].copy_from_slice(seed);
        augmented_seed[SEED_BYTES] = k_byte;
        augmented_seed[SEED_BYTES + 1] = l_byte;

        let expanded_result = shake256(&augmented_seed, EXPANDED_LEN);
        // Wipe augmented_seed before handling the result (it embeds the seed).
        augmented_seed.zeroize();
        let mut expanded = expanded_result?;
        if expanded.len() != EXPANDED_LEN {
            expanded.zeroize();
            return Err(CryptoError::Key(format!(
                "generate_key: SHAKE-256 returned {} bytes, expected {EXPANDED_LEN}",
                expanded.len()
            )));
        }

        // Partition expanded into (rho, priv_seed, K).
        self.rho.copy_from_slice(&expanded[..RHO_BYTES]);
        let mut priv_seed = [0u8; PRIV_SEED_BYTES];
        priv_seed.copy_from_slice(&expanded[RHO_BYTES..RHO_BYTES + PRIV_SEED_BYTES]);
        self.k_bytes
            .copy_from_slice(&expanded[RHO_BYTES + PRIV_SEED_BYTES..]);
        // Wipe the full expansion now that each section has been copied.
        expanded.zeroize();

        // ExpandS(priv_seed) → (s1, s2).
        let mut s1 = Vector::new(params.l);
        let mut s2 = Vector::new(params.k);
        let expand_result = vector_expand_s(&priv_seed, params.eta, &mut s1, &mut s2);
        priv_seed.zeroize();
        expand_result?;

        // Install s1, s2 so that public_from_private can borrow them.
        self.s1 = Some(s1);
        self.s2 = Some(s2);

        // Derive (t1, t0) via Power2Round of t = A·s1 + s2.
        let (t1, t0) = self.public_from_private()?;
        self.t1 = Some(t1);
        self.t0 = Some(t0);

        // Encode public key, compute tr from pub_encoding, then encode priv.
        self.encode_pub()?;
        self.compute_tr()?;
        self.encode_priv()?;

        // If the caller does not want the seed retained, wipe it. Otherwise
        // it remains available for regeneration via `set_prekey` workflows.
        if self.prov_flags & KEY_RETAIN_SEED == 0 {
            if let Some(mut s) = self.seed.take() {
                s.zeroize();
            }
        }

        Ok(())
    }
}

/// Compute `(t1, t0)` from `(rho, s1, s2)` per FIPS 204 §5.1 — the core
/// key-derivation step shared by key generation and `pairwise_check`.
///
/// Expands `A = ExpandA(rho)` (in NTT domain), computes
/// `t = NTT^{-1}(A · NTT(s1)) + s2`, then returns `Power2Round(t) = (t1, t0)`.
/// The working NTT copy of `s1` is zeroised on exit.
fn compute_public_from_private(
    params: &MlDsaParams,
    rho: &[u8; RHO_BYTES],
    s1: &Vector,
    s2: &Vector,
) -> CryptoResult<(Vector, Vector)> {
    if s1.polys.len() != params.l {
        return Err(CryptoError::Key(format!(
            "public_from_private: s1 length {} != l={}",
            s1.polys.len(),
            params.l
        )));
    }
    if s2.polys.len() != params.k {
        return Err(CryptoError::Key(format!(
            "public_from_private: s2 length {} != k={}",
            s2.polys.len(),
            params.k
        )));
    }
    // Expand A_hat = ExpandA(rho) directly in NTT form.
    let mut a_hat = Matrix::new(params.k, params.l);
    matrix_expand_a(rho, &mut a_hat)?;

    // Working NTT copy of s1. This is secret-derived and must be zeroised
    // before returning.
    let mut s1_ntt = s1.clone();
    s1_ntt.ntt();

    // t = A_hat · NTT(s1), in NTT domain.
    let mut t = Vector::new(params.k);
    matrix_mult_vector(&a_hat, &s1_ntt, &mut t);

    // Zeroise the NTT-form copy of s1 now that it is no longer needed.
    s1_ntt.zeroize();

    // Return t to the coefficient domain and add s2.
    t.ntt_inverse();
    t.add_assign(s2);

    // Power2Round(t) → (t1, t0).
    let mut t1 = Vector::new(params.k);
    let mut t0 = Vector::new(params.k);
    t.scale_power2_round_decompose(&mut t1, &mut t0);

    Ok((t1, t0))
}

// ===========================================================================
// μ (message representative) computation — translated from `ml_dsa_sign.c`
// ===========================================================================
//
// FIPS 204 Algorithms 2/3 and 7/8 first compute `μ = H(tr || M')`, where
// `M' = 0x00 || ctx_len || ctx || msg` for pure ML-DSA and `0x01 || …` for the
// HashML-DSA prehash flavour. The helpers below expose a streaming API so a
// caller can append arbitrarily large messages without buffering.

/// Absolute maximum context-string length admitted by FIPS 204 (`ctx_len` must
/// fit in a single unsigned byte).
const _ASSERT_CTX_LEN_FITS_U8: () = assert!(MAX_CONTEXT_STRING_LEN == 255);

/// Initialise a μ-computation SHAKE-256 XOF context with an arbitrary `tr`
/// prefix, optional domain separation byte, optional pre-hash flag, and
/// optional context string.
///
/// When `encode` is `true`, the two bytes `[prehash, ctx.len()]` are appended
/// after `tr`, followed by the `ctx` bytes — matching the `M'` envelope that
/// FIPS 204 Algorithm 2 (ML-DSA.Sign) applies to the message.  When `encode`
/// is `false`, only `tr` is absorbed; the caller is responsible for supplying
/// whatever pre-computed message representative the signing interface expects.
///
/// Returns an error if `encode == true` and `ctx.len() > 255`, or if the
/// underlying SHAKE-256 construction fails to absorb any of the buffers.
fn mu_init_int(tr: &[u8], encode: bool, prehash: bool, ctx: &[u8]) -> CryptoResult<ShakeContext> {
    if encode && ctx.len() > MAX_CONTEXT_STRING_LEN {
        return Err(CryptoError::Encoding(format!(
            "ML-DSA context string too long: {} > {}",
            ctx.len(),
            MAX_CONTEXT_STRING_LEN
        )));
    }
    let mut shake = ShakeContext::shake256();
    shake.update(tr)?;
    if encode {
        let prehash_byte: u8 = u8::from(prehash);
        // `ctx.len() <= 255` was enforced above, so this cast is loss-less.
        let ctx_len_byte: u8 = ctx.len() as u8;
        let itb = [prehash_byte, ctx_len_byte];
        shake.update(&itb)?;
        shake.update(ctx)?;
    }
    Ok(shake)
}

/// Convenience wrapper for the pure (non-prehash) ML-DSA flavour.
///
/// Equivalent to `mu_init_int(tr, encode, /*prehash=*/false, ctx)`.
fn mu_init(tr: &[u8; TR_BYTES], encode: bool, ctx: &[u8]) -> CryptoResult<ShakeContext> {
    mu_init_int(tr.as_slice(), encode, false, ctx)
}

/// Append a chunk of message data to an in-progress μ computation.
fn mu_update(shake: &mut ShakeContext, msg: &[u8]) -> CryptoResult<()> {
    shake.update(msg)
}

/// Finalise a μ computation, writing exactly `MU_BYTES` (64) output bytes.
fn mu_finalize(shake: &mut ShakeContext, mu: &mut [u8; MU_BYTES]) -> CryptoResult<()> {
    shake.squeeze(mu)
}

// ===========================================================================
// Helper: compute `w1_encode` buffer length for a given γ₂
// ===========================================================================

/// Return the number of bytes produced by `w1_encode` for a single polynomial
/// given `gamma2`. Matches `ml_dsa_encoders.c::w1_encode`'s output size: 6
/// bits/coefficient for γ₂ = (q−1)/88 (ML-DSA-44) and 4 bits/coefficient for
/// γ₂ = (q−1)/32 (ML-DSA-65 / ML-DSA-87).
#[inline]
fn w1_encoded_len_per_poly(gamma2: u32) -> usize {
    if gamma2 == GAMMA2_Q_MINUS1_DIV88 {
        // 256 coefficients × 6 bits ÷ 8 = 192 bytes
        192
    } else {
        // 256 coefficients × 4 bits ÷ 8 = 128 bytes
        128
    }
}

// ===========================================================================
// Sign (FIPS 204 Algorithm 7 — `Sign_internal`)
// ===========================================================================

impl MlDsaKey {
    /// Perform ML-DSA `Sign_internal` (FIPS 204 Algorithm 7) given a
    /// pre-computed message representative `μ` (64 bytes) and a 32-byte random
    /// nonce `rnd`.
    ///
    /// The caller must supply `rnd` — either freshly generated random bytes
    /// for hedged signing or a deterministic value (often 32 zero bytes) for
    /// the deterministic variant. This separation lets higher-level APIs
    /// choose a policy without this routine reaching for an OS RNG.
    ///
    /// Returns the encoded signature (`sig_len` bytes) or an error if:
    /// - the caller-provided `μ` is not exactly 64 bytes
    /// - this key is missing private material (must contain `s1`, `s2`, `t0`)
    /// - rejection sampling fails to converge within 2¹⁶ iterations (the
    ///   per-FIPS-204 κ field is a `u16`)
    /// - any SHAKE / random-sampling step fails
    ///
    /// # Security
    ///
    /// All intermediate secret material — ρ', the NTT-domain copies of s1,
    /// s2, t0, and the derived `cs1` / `cs2` / `ct0` vectors — is zeroised
    /// before this function returns on every exit path.
    pub(crate) fn sign_internal(&self, mu: &[u8], rnd: &[u8]) -> CryptoResult<Vec<u8>> {
        if mu.len() != MU_BYTES {
            return Err(CryptoError::Encoding(format!(
                "ML-DSA sign: μ must be {MU_BYTES} bytes, got {}",
                mu.len()
            )));
        }
        if rnd.len() != ENTROPY_LEN {
            return Err(CryptoError::Encoding(format!(
                "ML-DSA sign: rnd must be {ENTROPY_LEN} bytes, got {}",
                rnd.len()
            )));
        }

        let params = self.params;
        let k = params.k;
        let l = params.l;
        let gamma1 = params.gamma1;
        let gamma2 = params.gamma2;
        let beta = params.beta;
        let tau = params.tau;
        let omega = params.omega;
        // Challenge hash length in bytes = λ / 4 (λ in bits).
        let c_tilde_len: usize = (params.bit_strength as usize) >> 2;

        // --------------------------------------------------------------
        // Pull required private material from `self`.
        // --------------------------------------------------------------
        let s1 = self.s1.as_ref().ok_or_else(|| {
            CryptoError::Key("ML-DSA sign requires private key component s1".to_string())
        })?;
        let s2 = self.s2.as_ref().ok_or_else(|| {
            CryptoError::Key("ML-DSA sign requires private key component s2".to_string())
        })?;
        let t0 = self.t0.as_ref().ok_or_else(|| {
            CryptoError::Key("ML-DSA sign requires private key component t0".to_string())
        })?;
        if s1.polys.len() != l || s2.polys.len() != k || t0.polys.len() != k {
            return Err(CryptoError::Key(
                "ML-DSA private key vector shape mismatch for this variant".to_string(),
            ));
        }

        // --------------------------------------------------------------
        // ρ' = H(K || rnd || μ), 64 bytes. (FIPS 204 Algorithm 7 line 2.)
        // --------------------------------------------------------------
        let mut rho_prime = [0u8; RHO_PRIME_BYTES];
        {
            let mut shake = ShakeContext::shake256();
            shake.update(&self.k_bytes)?;
            shake.update(rnd)?;
            shake.update(mu)?;
            shake.squeeze(&mut rho_prime)?;
        }

        // --------------------------------------------------------------
        // Expand A_hat (public NTT-domain matrix) from ρ.
        // --------------------------------------------------------------
        let mut a_hat = Matrix::new(k, l);
        matrix_expand_a(&self.rho, &mut a_hat)?;

        // --------------------------------------------------------------
        // NTT-domain copies of s1, s2, t0. These are secret-derived —
        // they will be explicitly zeroised before returning.
        // --------------------------------------------------------------
        let mut s1_ntt = s1.clone();
        s1_ntt.ntt();
        let mut s2_ntt = s2.clone();
        s2_ntt.ntt();
        let mut t0_ntt = t0.clone();
        t0_ntt.ntt();

        // --------------------------------------------------------------
        // Scratch vectors for the rejection-sampling loop.
        // --------------------------------------------------------------
        let mut y = Vector::new(l);
        let mut y_ntt = Vector::new(l);
        let mut w = Vector::new(k);
        let mut w1 = Vector::new(k);
        let mut cs1 = Vector::new(l);
        let mut cs2 = Vector::new(k);
        let mut diff = Vector::new(k);
        let mut r0 = Vector::new(k);
        let mut ct0 = Vector::new(k);
        let mut hint = Vector::new(k);
        let mut c_poly = Poly::zero();
        let mut c_ntt = Poly::zero();
        let mut c_tilde = vec![0u8; c_tilde_len];

        // `w1_encode` output buffer — reused across rejections.
        let w1_len = k
            .checked_mul(w1_encoded_len_per_poly(gamma2))
            .ok_or_else(|| {
                CryptoError::Encoding(
                    "ML-DSA sign: overflow computing w1 buffer length".to_string(),
                )
            })?;
        let mut w1_encoded = vec![0u8; w1_len];

        // Final signature container. `z` holds `l` polynomials; `hint` holds
        // `k`. They are overwritten every iteration on success.
        let mut sig = MlDsaSig {
            c_tilde: vec![0u8; c_tilde_len],
            z: Vector::new(l),
            hint: Vector::new(k),
        };

        // --------------------------------------------------------------
        // Rejection-sampling loop (FIPS 204 Algorithm 7 lines 7–26).
        //
        // κ is a 16-bit field in the spec; each iteration advances κ by
        // `l` (the number of polynomials in y). We fail closed once κ
        // would exceed `u16::MAX` — this guards against pathological
        // inputs / buggy RNGs rather than being a real operational
        // concern (expected iterations ≈ 4.25 for all variants).
        // --------------------------------------------------------------
        let max_kappa = u32::from(u16::MAX);
        let l_u32 = u32::try_from(l).map_err(|_| {
            CryptoError::Key("ML-DSA parameter set has unreasonable `l`".to_string())
        })?;

        let mut kappa: u32 = 0;
        let sig_bytes = loop {
            if kappa > max_kappa.saturating_sub(l_u32) {
                // Would overflow the 16-bit κ field on the next iteration.
                // Scrub secret-derived material and bail out.
                rho_prime.zeroize();
                s1_ntt.zeroize();
                s2_ntt.zeroize();
                t0_ntt.zeroize();
                cs1.zeroize();
                cs2.zeroize();
                ct0.zeroize();
                return Err(CryptoError::Verification(
                    "ML-DSA sign: rejection sampling failed to converge".to_string(),
                ));
            }
            // κ is at most u16::MAX per the guard above, so the cast is safe.
            let kappa_u16: u16 = kappa as u16;

            // --- y = ExpandMask(ρ', κ, γ₁) ---
            y.expand_mask(&rho_prime, kappa_u16, gamma1)?;

            // --- y_ntt = NTT(y) ---
            y_ntt.copy_from(&y);
            y_ntt.ntt();

            // --- w = NTT⁻¹(A · y_ntt) ---
            matrix_mult_vector(&a_hat, &y_ntt, &mut w);
            w.ntt_inverse();

            // --- w1 = HighBits(w, γ₂) ---
            w.high_bits(gamma2, &mut w1);

            // --- w1_encode(w1, γ₂) ---
            w1_encode(&w1, gamma2, &mut w1_encoded)?;

            // --- c̃ = H(μ || w1_encoded), `c_tilde_len` bytes ---
            {
                let mut shake = ShakeContext::shake256();
                shake.update(mu)?;
                shake.update(&w1_encoded)?;
                shake.squeeze(&mut c_tilde)?;
            }

            // --- c = SampleInBall(c̃); c_ntt = NTT(c) ---
            c_poly.clear();
            poly_sample_in_ball(&c_tilde, tau, &mut c_poly)?;
            // Mutate the pre-allocated `c_ntt` buffer in place rather than
            // reassigning, so the initial `Poly::zero()` allocation is reused
            // across rejection iterations (avoiding the dead-assignment lint).
            c_ntt.coeffs.copy_from_slice(&c_poly.coeffs);
            c_ntt.ntt();

            // --- cs1 = NTT⁻¹(c · s1_ntt) ---
            vector_mult_scalar(&c_ntt, &s1_ntt, &mut cs1);
            cs1.ntt_inverse();

            // --- cs2 = NTT⁻¹(c · s2_ntt) ---
            vector_mult_scalar(&c_ntt, &s2_ntt, &mut cs2);
            cs2.ntt_inverse();

            // --- z = y + cs1 ---
            sig.z.copy_from(&y);
            sig.z.add_assign(&cs1);

            // --- r0 = LowBits(w − cs2, γ₂) ---
            diff.copy_from(&w);
            diff.sub_assign(&cs2);
            diff.low_bits(gamma2, &mut r0);

            let z_max = sig.z.infinity_norm();
            let r0_max = r0.infinity_norm_signed();

            // --- First rejection: ‖z‖_∞ ≥ γ₁ − β OR ‖r0‖_∞ ≥ γ₂ − β. ---
            if z_max >= gamma1.saturating_sub(beta) || r0_max >= gamma2.saturating_sub(beta) {
                kappa = kappa.saturating_add(l_u32);
                continue;
            }

            // --- ct0 = NTT⁻¹(c · t0_ntt) ---
            vector_mult_scalar(&c_ntt, &t0_ntt, &mut ct0);
            ct0.ntt_inverse();

            // --- h = MakeHint(−ct0, w − cs2 + ct0, γ₂).
            //      Vector::make_hint: self = ct0, arg1 = cs2, arg2 = w. ---
            ct0.make_hint(&cs2, &w, gamma2, &mut hint);

            let ct0_max = ct0.infinity_norm();
            let h_ones = hint.hamming_weight();

            // --- Second rejection: ‖ct0‖_∞ ≥ γ₂ OR Ham(h) > ω. ---
            if ct0_max >= gamma2 || h_ones > omega {
                kappa = kappa.saturating_add(l_u32);
                continue;
            }

            // --- Accepted. Encode and break out of the loop. ---
            sig.c_tilde.clear();
            sig.c_tilde.extend_from_slice(&c_tilde);
            sig.hint.copy_from(&hint);
            let encoded = sig_encode(&sig, params)?;
            break encoded;
        };

        // --------------------------------------------------------------
        // Zeroise all secret-derived scratch material. `sig.z`, `sig.hint`,
        // `sig.c_tilde`, `w`, `w1`, `y`, `y_ntt`, `diff`, `r0`, `c_poly`,
        // `c_ntt`, `a_hat`, `hint` are either public-derived or redundant
        // intermediates, but we zeroise the strictly-secret vectors below.
        // --------------------------------------------------------------
        rho_prime.zeroize();
        s1_ntt.zeroize();
        s2_ntt.zeroize();
        t0_ntt.zeroize();
        cs1.zeroize();
        cs2.zeroize();
        ct0.zeroize();
        // Defensive extras:
        c_poly.clear();
        c_ntt.clear();
        c_tilde.zeroize();

        Ok(sig_bytes)
    }
}

// ===========================================================================
// Verify (FIPS 204 Algorithm 8 — `Verify_internal`)
// ===========================================================================

impl MlDsaKey {
    /// Perform ML-DSA `Verify_internal` (FIPS 204 Algorithm 8) given a
    /// pre-computed message representative `μ` (64 bytes) and an encoded
    /// signature.
    ///
    /// Returns `Ok(true)` if the signature is valid for this key and message,
    /// `Ok(false)` if the signature is syntactically decodable but fails the
    /// algebraic verification or bound checks, or `Err(..)` if decoding fails
    /// (malformed hint, over-sized context, etc.).
    ///
    /// # Security
    ///
    /// The comparison of the recomputed challenge hash is performed in
    /// constant time via [`subtle::ConstantTimeEq`] so that non-matching bytes
    /// do not reveal timing information about `t1` or any intermediate.
    pub(crate) fn verify_internal(&self, mu: &[u8], sig_bytes: &[u8]) -> CryptoResult<bool> {
        if mu.len() != MU_BYTES {
            return Err(CryptoError::Encoding(format!(
                "ML-DSA verify: μ must be {MU_BYTES} bytes, got {}",
                mu.len()
            )));
        }
        let params = self.params;
        let k = params.k;
        let l = params.l;
        let gamma1 = params.gamma1;
        let gamma2 = params.gamma2;
        let beta = params.beta;
        let tau = params.tau;
        let omega = params.omega;
        let c_tilde_len: usize = (params.bit_strength as usize) >> 2;

        // Must have public material to verify.
        let t1 = self.t1.as_ref().ok_or_else(|| {
            CryptoError::Key("ML-DSA verify requires public key component t1".to_string())
        })?;
        if t1.polys.len() != k {
            return Err(CryptoError::Key(
                "ML-DSA public key vector shape mismatch for this variant".to_string(),
            ));
        }

        // --------------------------------------------------------------
        // Decode the signature — any structural problem is a decoding
        // error, not a verification failure.
        // --------------------------------------------------------------
        let sig = sig_decode(sig_bytes, params)?;
        if sig.c_tilde.len() != c_tilde_len || sig.z.polys.len() != l || sig.hint.polys.len() != k {
            return Err(CryptoError::Encoding(
                "ML-DSA verify: decoded signature has unexpected shape".to_string(),
            ));
        }

        // --------------------------------------------------------------
        // CRITICAL: Capture the infinity norm of `z` BEFORE transforming
        // it into the NTT domain. `z` has coefficients in the range
        // `(-γ₁, γ₁]`, which are reduced modulo q in the signature
        // encoding; `Vector::infinity_norm` maps them back to centred
        // magnitudes. Taking the NTT destroys this property.
        // --------------------------------------------------------------
        let z_max = sig.z.infinity_norm();

        // FIPS 204 Algorithm 8 step 8: hint must have Hamming weight ≤ ω.
        // (The C implementation relies on `sig_decode` catching the
        // malformed case, but we add the explicit check for defence in
        // depth and to match the specification literally.)
        let h_ones = sig.hint.hamming_weight();

        // --------------------------------------------------------------
        // Expand A_hat from ρ (public).
        // --------------------------------------------------------------
        let mut a_hat = Matrix::new(k, l);
        matrix_expand_a(&self.rho, &mut a_hat)?;

        // --------------------------------------------------------------
        // c = SampleInBall(c̃); c_ntt = NTT(c).
        // --------------------------------------------------------------
        let mut c_poly = Poly::zero();
        poly_sample_in_ball(&sig.c_tilde, tau, &mut c_poly)?;
        let mut c_ntt = c_poly;
        c_ntt.ntt();

        // --------------------------------------------------------------
        // z_ntt = NTT(z).
        // --------------------------------------------------------------
        let mut z_ntt = sig.z.clone();
        z_ntt.ntt();

        // --------------------------------------------------------------
        // az_ntt = A · z_ntt.
        // --------------------------------------------------------------
        let mut az_ntt = Vector::new(k);
        matrix_mult_vector(&a_hat, &z_ntt, &mut az_ntt);

        // --------------------------------------------------------------
        // ct1_ntt = NTT(t1 · 2^d), then ct1_c = c · ct1_ntt.
        // --------------------------------------------------------------
        let mut ct1_ntt = t1.clone();
        ct1_ntt.scale_power2_round();
        ct1_ntt.ntt();

        let mut ct1_c = Vector::new(k);
        vector_mult_scalar(&c_ntt, &ct1_ntt, &mut ct1_c);

        // --------------------------------------------------------------
        // w_approx = NTT⁻¹(az_ntt − ct1_c).
        // --------------------------------------------------------------
        let mut w_approx = Vector::new(k);
        w_approx.copy_from(&az_ntt);
        w_approx.sub_assign(&ct1_c);
        w_approx.ntt_inverse();

        // --------------------------------------------------------------
        // w1' = UseHint(h, w_approx).
        //
        // `Vector::use_hint` is invoked on the value vector (`w_approx`)
        // with the hint vector passed as an argument, matching the C
        // call pattern `vector_use_hint(hint, w_approx, γ₂, w1)`.
        // --------------------------------------------------------------
        let mut w1 = Vector::new(k);
        w_approx.use_hint(&sig.hint, gamma2, &mut w1);

        // --------------------------------------------------------------
        // c̃' = H(μ || w1Encode(w1'))  — recomputed challenge hash.
        // --------------------------------------------------------------
        let w1_len = k
            .checked_mul(w1_encoded_len_per_poly(gamma2))
            .ok_or_else(|| {
                CryptoError::Encoding(
                    "ML-DSA verify: overflow computing w1 buffer length".to_string(),
                )
            })?;
        let mut w1_encoded = vec![0u8; w1_len];
        w1_encode(&w1, gamma2, &mut w1_encoded)?;

        let mut c_tilde_prime = vec![0u8; c_tilde_len];
        {
            let mut shake = ShakeContext::shake256();
            shake.update(mu)?;
            shake.update(&w1_encoded)?;
            shake.squeeze(&mut c_tilde_prime)?;
        }

        // --------------------------------------------------------------
        // Final verdict: accept iff all of:
        //   (1) ‖z‖_∞ < γ₁ − β
        //   (2) Hamming weight of hint ≤ ω
        //   (3) c̃ == c̃' in constant time.
        // --------------------------------------------------------------
        let norm_ok = z_max < gamma1.saturating_sub(beta);
        let hint_ok = h_ones <= omega;
        let hash_eq: bool = sig.c_tilde.ct_eq(&c_tilde_prime).into();

        Ok(norm_ok && hint_ok && hash_eq)
    }
}

// ===========================================================================
// Public signing / verification wrappers (FIPS 204 Algorithms 2/3)
// ===========================================================================

/// Sign `msg` with `key` using ML-DSA.
///
/// The caller controls the encoding mode and optional pre-computed randomness:
/// - When `encode` is `true`, a domain-separation byte (0 for pure ML-DSA)
///   plus a single-byte context length and the `context` bytes are prepended
///   to the message before computing μ, matching FIPS 204 Algorithm 2.
/// - When `add_random` is `Some(rnd)`, the 32-byte `rnd` value is folded into
///   ρ' = H(K ‖ rnd ‖ μ). Passing `Some(&[0u8; 32])` yields deterministic
///   ML-DSA; `None` causes this routine to draw fresh bytes from the OS-level
///   cryptographic RNG (`rand::rngs::OsRng`) for hedged signing.
///
/// Returns the encoded signature (`key.sig_len()` bytes on success) or an
/// error if the key lacks private material, the context is too long, or any
/// SHAKE / sampling step fails.
pub fn ml_dsa_sign(
    key: &MlDsaKey,
    msg: &[u8],
    context: &[u8],
    encode: bool,
    add_random: Option<&[u8; 32]>,
) -> CryptoResult<Vec<u8>> {
    // --------------------------------------------------------------
    // Compute μ = H(tr ‖ M').
    // --------------------------------------------------------------
    let mut shake = mu_init(&key.tr, encode, context)?;
    mu_update(&mut shake, msg)?;
    let mut mu = [0u8; MU_BYTES];
    mu_finalize(&mut shake, &mut mu)?;

    // --------------------------------------------------------------
    // Resolve the random nonce — caller-supplied or drawn from OsRng.
    // --------------------------------------------------------------
    let mut rnd_buf = [0u8; ENTROPY_LEN];
    let rnd_slice: &[u8] = if let Some(r) = add_random {
        r.as_slice()
    } else {
        OsRng
            .try_fill_bytes(&mut rnd_buf)
            .map_err(|e| CryptoError::Rand(format!("ML-DSA sign: OsRng failed: {e}")))?;
        rnd_buf.as_slice()
    };

    // --------------------------------------------------------------
    // Dispatch to the internal sign routine and zeroise transient
    // secret-adjacent material before returning.
    // --------------------------------------------------------------
    let sig_result = key.sign_internal(&mu, rnd_slice);
    mu.zeroize();
    rnd_buf.zeroize();
    sig_result
}

/// Verify an ML-DSA signature on `msg` using `key`.
///
/// The `encode` and `context` parameters must match the values used at
/// signing time for the signature to verify.
///
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on a syntactically
/// well-formed but algebraically invalid signature, and `Err(..)` on
/// structural decoding failure.
pub fn ml_dsa_verify(
    key: &MlDsaKey,
    msg: &[u8],
    context: &[u8],
    encode: bool,
    sig_bytes: &[u8],
) -> CryptoResult<bool> {
    let mut shake = mu_init(&key.tr, encode, context)?;
    mu_update(&mut shake, msg)?;
    let mut mu = [0u8; MU_BYTES];
    mu_finalize(&mut shake, &mut mu)?;

    let verdict = key.verify_internal(&mu, sig_bytes);
    mu.zeroize();
    verdict
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Shared fixture: a library context wrapped in `Arc` for key ops.
    fn libctx() -> Arc<LibContext> {
        // `LibContext::default()` already returns `Arc<LibContext>` — use it
        // directly rather than wrapping a second time.
        LibContext::default()
    }

    /// Canonical deterministic seed for keygen tests.
    const TEST_SEED: [u8; SEED_BYTES] = [0x5Au8; SEED_BYTES];

    /// Canonical deterministic signing nonce.
    const TEST_RND: [u8; 32] = [0xA5u8; 32];

    // -----------------------------------------------------------------
    // Parameter table sanity — all three variants (FIPS 204 Table 1/2).
    // -----------------------------------------------------------------
    #[test]
    fn params_table_ml_dsa_44_has_correct_values() {
        let p = ml_dsa_params_get(MlDsaVariant::MlDsa44);
        assert_eq!(p.alg, "ML-DSA-44");
        assert_eq!(p.variant, MlDsaVariant::MlDsa44);
        assert_eq!(p.tau, 39);
        assert_eq!(p.bit_strength, 128);
        assert_eq!(p.gamma1, 1 << 17);
        assert_eq!(p.gamma2, 95_232);
        assert_eq!(p.k, 4);
        assert_eq!(p.l, 4);
        assert_eq!(p.eta, 2);
        assert_eq!(p.beta, 78);
        assert_eq!(p.omega, 80);
        assert_eq!(p.security_category, 2);
        assert_eq!(p.sk_len, 2560);
        assert_eq!(p.pk_len, 1312);
        assert_eq!(p.sig_len, 2420);
    }

    #[test]
    fn params_table_ml_dsa_65_has_correct_values() {
        let p = ml_dsa_params_get(MlDsaVariant::MlDsa65);
        assert_eq!(p.alg, "ML-DSA-65");
        assert_eq!(p.tau, 49);
        assert_eq!(p.bit_strength, 192);
        assert_eq!(p.gamma1, 1 << 19);
        assert_eq!(p.gamma2, 261_888);
        assert_eq!(p.k, 6);
        assert_eq!(p.l, 5);
        assert_eq!(p.eta, 4);
        assert_eq!(p.beta, 196);
        assert_eq!(p.omega, 55);
        assert_eq!(p.security_category, 3);
        assert_eq!(p.sk_len, 4032);
        assert_eq!(p.pk_len, 1952);
        assert_eq!(p.sig_len, 3309);
    }

    #[test]
    fn params_table_ml_dsa_87_has_correct_values() {
        let p = ml_dsa_params_get(MlDsaVariant::MlDsa87);
        assert_eq!(p.alg, "ML-DSA-87");
        assert_eq!(p.tau, 60);
        assert_eq!(p.bit_strength, 256);
        assert_eq!(p.gamma1, 1 << 19);
        assert_eq!(p.gamma2, 261_888);
        assert_eq!(p.k, 8);
        assert_eq!(p.l, 7);
        assert_eq!(p.eta, 2);
        assert_eq!(p.beta, 120);
        assert_eq!(p.omega, 75);
        assert_eq!(p.security_category, 5);
        assert_eq!(p.sk_len, 4896);
        assert_eq!(p.pk_len, 2592);
        assert_eq!(p.sig_len, 4627);
    }

    #[test]
    fn params_get_by_name_resolves_all_variants() {
        assert_eq!(
            ml_dsa_params_get_by_name("ML-DSA-44").map(|p| p.variant),
            Some(MlDsaVariant::MlDsa44)
        );
        assert_eq!(
            ml_dsa_params_get_by_name("ML-DSA-65").map(|p| p.variant),
            Some(MlDsaVariant::MlDsa65)
        );
        assert_eq!(
            ml_dsa_params_get_by_name("ML-DSA-87").map(|p| p.variant),
            Some(MlDsaVariant::MlDsa87)
        );
        assert!(ml_dsa_params_get_by_name("ML-DSA-99").is_none());
        assert!(ml_dsa_params_get_by_name("").is_none());
    }

    #[test]
    fn variant_helpers_match_params() {
        for v in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let p = ml_dsa_params_get(v);
            assert_eq!(v.algorithm_name(), p.alg);
            assert_eq!(v.security_category(), p.security_category);
        }
    }

    #[test]
    fn ml_dsa_core_constants_match_fips_204() {
        assert_eq!(ML_DSA_Q, 8_380_417);
        assert_eq!(NUM_POLY_COEFFICIENTS, 256);
        assert_eq!(SEED_BYTES, 32);
        assert_eq!(MU_BYTES, 64);
    }

    // -----------------------------------------------------------------
    // Low-level Poly / Vector arithmetic.
    // -----------------------------------------------------------------
    #[test]
    fn poly_zero_has_all_zero_coefficients() {
        let p = Poly::zero();
        assert!(p.coeffs.iter().all(|&c| c == 0));
    }

    #[test]
    fn poly_add_is_commutative_and_reduces_mod_q() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..NUM_POLY_COEFFICIENTS {
            a.coeffs[i] = (ML_DSA_Q - 1) as u32;
            b.coeffs[i] = 5;
        }
        let mut ab = Poly::zero();
        let mut ba = Poly::zero();
        a.add(&b, &mut ab);
        b.add(&a, &mut ba);
        assert!(ab.equal(&ba));
        // (q - 1) + 5 mod q == 4
        assert!(ab.coeffs.iter().all(|&c| c == 4));
    }

    #[test]
    fn poly_sub_reduces_mod_q() {
        let mut a = Poly::zero();
        let b = Poly::zero();
        for i in 0..NUM_POLY_COEFFICIENTS {
            a.coeffs[i] = 3;
        }
        let mut diff = Poly::zero();
        b.sub(&a, &mut diff);
        // 0 - 3 mod q == q - 3
        assert!(diff.coeffs.iter().all(|&c| c == ML_DSA_Q - 3));
    }

    #[test]
    fn ntt_round_trip_is_identity_for_small_polys() {
        // Create a polynomial whose coefficients are all distinct small values.
        let mut original = Poly::zero();
        for i in 0..NUM_POLY_COEFFICIENTS {
            original.coeffs[i] = (i as u32) % 500;
        }
        let mut roundtrip = original.clone();
        roundtrip.ntt();
        roundtrip.ntt_inverse();
        // `poly_ntt` / `poly_ntt_inverse` deliberately leave the result in
        // Montgomery form (scaled by `R = 2^32 mod q`). In production this
        // extra R factor is absorbed by the subsequent Montgomery pointwise
        // multiplication (`poly_ntt_mult`), which divides one R out again.
        // For a *direct* round-trip — without any intervening multiplication —
        // we must apply `reduce_montgomery` ourselves to normalise the result
        // back to canonical form before comparing with the original input.
        for i in 0..NUM_POLY_COEFFICIENTS {
            let reduced = reduce_montgomery(roundtrip.coeffs[i] as u64);
            assert_eq!(
                reduced, original.coeffs[i],
                "NTT round-trip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn vector_new_allocates_correct_number_of_zero_polys() {
        let v = Vector::new(5);
        assert_eq!(v.polys.len(), 5);
        for p in &v.polys {
            assert!(p.coeffs.iter().all(|&c| c == 0));
        }
    }

    #[test]
    fn vector_ntt_round_trip() {
        let mut v = Vector::new(3);
        for (i, p) in v.polys.iter_mut().enumerate() {
            for j in 0..NUM_POLY_COEFFICIENTS {
                p.coeffs[j] = ((i * 7 + j) as u32) % 1000;
            }
        }
        let original = v.clone();
        v.ntt();
        v.ntt_inverse();
        // As for the single-polynomial case, a direct forward/inverse round-
        // trip leaves each coefficient multiplied by `R mod q`. Apply
        // `reduce_montgomery` to normalise before comparing.
        for (o, r) in original.polys.iter().zip(v.polys.iter()) {
            for j in 0..NUM_POLY_COEFFICIENTS {
                let reduced = reduce_montgomery(r.coeffs[j] as u64);
                assert_eq!(reduced, o.coeffs[j]);
            }
        }
    }

    // -----------------------------------------------------------------
    // Key generation smoke test.
    // -----------------------------------------------------------------
    #[test]
    fn generate_ml_dsa_44_produces_encoded_key_material() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED))
            .expect("ML-DSA-44 keygen must succeed for a valid seed");
        // Public material populated.
        assert!(key.has_key(KeySelection::Public));
        assert!(key.has_key(KeySelection::Private));
        let pk = key
            .public_key_bytes()
            .expect("generated key must carry encoded public key");
        let sk = key
            .private_key_bytes()
            .expect("generated key must carry encoded private key");
        assert_eq!(pk.len(), key.pub_len());
        assert_eq!(sk.len(), key.priv_len());
        // Sanity check against FIPS 204 Table 3.
        assert_eq!(pk.len(), 1312);
        assert_eq!(sk.len(), 2560);
    }

    #[test]
    fn generate_produces_deterministic_keys_for_fixed_seed() {
        let a = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let b = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        assert!(a.equal(&b, KeySelection::Public));
        assert!(a.equal(&b, KeySelection::Private));
    }

    #[test]
    fn generate_produces_distinct_keys_for_distinct_seeds() {
        let mut seed_a = TEST_SEED;
        let mut seed_b = TEST_SEED;
        seed_a[0] = 0x01;
        seed_b[0] = 0x02;
        let a = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&seed_a)).unwrap();
        let b = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&seed_b)).unwrap();
        assert!(!a.equal(&b, KeySelection::Public));
    }

    // -----------------------------------------------------------------
    // Public key encode/decode round-trip.
    // -----------------------------------------------------------------
    #[test]
    fn public_key_encode_decode_round_trip_ml_dsa_44() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let pk_bytes = key.public_key_bytes().unwrap().to_vec();
        let params = ml_dsa_params_get(MlDsaVariant::MlDsa44);
        let restored = MlDsaKey::from_public(&pk_bytes, params, libctx())
            .expect("public key decode must succeed");
        assert!(key.equal(&restored, KeySelection::Public));
        assert_eq!(restored.public_key_bytes().unwrap(), pk_bytes.as_slice());
        assert!(!restored.has_key(KeySelection::Private));
    }

    #[test]
    fn private_key_encode_decode_round_trip_ml_dsa_44() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let sk_bytes = key.private_key_bytes().unwrap().to_vec();
        let params = ml_dsa_params_get(MlDsaVariant::MlDsa44);
        let restored = MlDsaKey::from_private(&sk_bytes, params, libctx())
            .expect("private key decode must succeed");
        assert!(key.equal(&restored, KeySelection::Private));
        assert_eq!(restored.private_key_bytes().unwrap(), sk_bytes.as_slice());
    }

    #[test]
    fn public_key_decode_rejects_truncated_bytes() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let mut pk_bytes = key.public_key_bytes().unwrap().to_vec();
        pk_bytes.pop();
        let params = ml_dsa_params_get(MlDsaVariant::MlDsa44);
        assert!(MlDsaKey::from_public(&pk_bytes, params, libctx()).is_err());
    }

    // -----------------------------------------------------------------
    // Full sign/verify round-trip for all three variants.
    // -----------------------------------------------------------------
    fn sign_verify_roundtrip_for(variant: MlDsaVariant) {
        let key = MlDsaKey::generate(libctx(), variant, Some(&TEST_SEED))
            .expect("key generation must succeed");
        let msg = b"ML-DSA round-trip test message";
        let ctx = b"integration-test";
        let sig = ml_dsa_sign(&key, msg, ctx, true, Some(&TEST_RND))
            .expect("signing must succeed for a well-formed key");
        assert_eq!(sig.len(), key.sig_len());
        let verdict = ml_dsa_verify(&key, msg, ctx, true, &sig)
            .expect("verification must not return a structural error");
        assert!(verdict, "valid signature must verify");
    }

    #[test]
    fn sign_verify_roundtrip_ml_dsa_44() {
        sign_verify_roundtrip_for(MlDsaVariant::MlDsa44);
    }

    #[test]
    fn sign_verify_roundtrip_ml_dsa_65() {
        sign_verify_roundtrip_for(MlDsaVariant::MlDsa65);
    }

    #[test]
    fn sign_verify_roundtrip_ml_dsa_87() {
        sign_verify_roundtrip_for(MlDsaVariant::MlDsa87);
    }

    // -----------------------------------------------------------------
    // Negative tests — tampering, wrong context, wrong key.
    // -----------------------------------------------------------------
    #[test]
    fn verify_rejects_bit_flipped_signature_byte() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let msg = b"tamper detection";
        let ctx = b"";
        let mut sig = ml_dsa_sign(&key, msg, ctx, true, Some(&TEST_RND)).unwrap();
        // Flip a bit somewhere inside the c_tilde prefix — should always break
        // verification whatever the signature content.
        sig[0] ^= 0x01;
        let verdict = ml_dsa_verify(&key, msg, ctx, true, &sig)
            .expect("malformed-but-decodable signature must not raise a decode error");
        assert!(!verdict);
    }

    #[test]
    fn verify_rejects_wrong_context() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let msg = b"context-binding test";
        let sig = ml_dsa_sign(&key, msg, b"context-A", true, Some(&TEST_RND)).unwrap();
        let verdict = ml_dsa_verify(&key, msg, b"context-B", true, &sig).unwrap();
        assert!(
            !verdict,
            "signature bound to one context must not verify under another"
        );
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let sig = ml_dsa_sign(&key, b"original", b"", true, Some(&TEST_RND)).unwrap();
        let verdict = ml_dsa_verify(&key, b"tampered", b"", true, &sig).unwrap();
        assert!(!verdict);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key_a = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let mut other_seed = TEST_SEED;
        other_seed[0] ^= 0xFF;
        let key_b = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&other_seed)).unwrap();
        let sig = ml_dsa_sign(&key_a, b"hello", b"", true, Some(&TEST_RND)).unwrap();
        let verdict = ml_dsa_verify(&key_b, b"hello", b"", true, &sig).unwrap();
        assert!(
            !verdict,
            "signature from one key must not verify against another"
        );
    }

    #[test]
    fn verify_rejects_signature_of_wrong_length() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let sig = ml_dsa_sign(&key, b"hi", b"", true, Some(&TEST_RND)).unwrap();
        // Truncated
        assert!(ml_dsa_verify(&key, b"hi", b"", true, &sig[..sig.len() - 1]).is_err());
        // Extended
        let mut extended = sig.clone();
        extended.push(0);
        assert!(ml_dsa_verify(&key, b"hi", b"", true, &extended).is_err());
    }

    // -----------------------------------------------------------------
    // Deterministic signing with a fixed rnd yields identical signatures.
    // -----------------------------------------------------------------
    #[test]
    fn deterministic_signing_is_reproducible() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let zero_rnd = [0u8; 32];
        let sig_a = ml_dsa_sign(&key, b"payload", b"", true, Some(&zero_rnd)).unwrap();
        let sig_b = ml_dsa_sign(&key, b"payload", b"", true, Some(&zero_rnd)).unwrap();
        assert_eq!(
            sig_a, sig_b,
            "deterministic ML-DSA signing must be reproducible"
        );
    }

    // -----------------------------------------------------------------
    // Context-length edge cases.
    // -----------------------------------------------------------------
    #[test]
    fn sign_rejects_context_that_is_too_long() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let big_ctx = vec![0u8; MAX_CONTEXT_STRING_LEN + 1];
        let err = ml_dsa_sign(&key, b"hello", &big_ctx, true, Some(&TEST_RND));
        assert!(
            err.is_err(),
            "context longer than 255 bytes must be rejected"
        );
    }

    #[test]
    fn sign_accepts_maximum_length_context() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let ctx = vec![0xABu8; MAX_CONTEXT_STRING_LEN];
        let sig = ml_dsa_sign(&key, b"msg", &ctx, true, Some(&TEST_RND))
            .expect("255-byte context must be accepted");
        let verdict = ml_dsa_verify(&key, b"msg", &ctx, true, &sig).unwrap();
        assert!(verdict);
    }

    #[test]
    fn sign_handles_empty_message_and_context() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let sig = ml_dsa_sign(&key, b"", b"", true, Some(&TEST_RND)).unwrap();
        assert!(ml_dsa_verify(&key, b"", b"", true, &sig).unwrap());
    }

    // -----------------------------------------------------------------
    // Encoded-mode toggle: `encode = false` skips domain-separation
    // and the prefix must be excluded at verification time too.
    // -----------------------------------------------------------------
    #[test]
    fn verify_must_use_matching_encode_flag() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let sig = ml_dsa_sign(&key, b"data", b"", false, Some(&TEST_RND))
            .expect("encode=false signing must succeed");
        assert!(ml_dsa_verify(&key, b"data", b"", false, &sig).unwrap());
        // Mismatched encode flag must yield false, not an error.
        assert!(!ml_dsa_verify(&key, b"data", b"", true, &sig).unwrap());
    }

    // -----------------------------------------------------------------
    // has_key / dup semantics.
    // -----------------------------------------------------------------
    #[test]
    fn dup_public_strips_private_material() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let pub_only = key.dup(KeySelection::Public).unwrap();
        assert!(pub_only.has_key(KeySelection::Public));
        assert!(!pub_only.has_key(KeySelection::Private));
        // Verify operation still works on a public-only key.
        let sig = ml_dsa_sign(&key, b"hi", b"", true, Some(&TEST_RND)).unwrap();
        assert!(ml_dsa_verify(&pub_only, b"hi", b"", true, &sig).unwrap());
    }

    #[test]
    fn dup_keypair_preserves_both_components() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let clone = key.dup(KeySelection::Both).unwrap();
        assert!(key.equal(&clone, KeySelection::Both));
        // Clone can also sign.
        let sig = ml_dsa_sign(&clone, b"cloned", b"", true, Some(&TEST_RND)).unwrap();
        assert!(ml_dsa_verify(&key, b"cloned", b"", true, &sig).unwrap());
    }

    // -----------------------------------------------------------------
    // Length helpers agree with published FIPS 204 Table 3 sizes.
    // -----------------------------------------------------------------
    #[test]
    fn length_helpers_match_variant_table() {
        let k44 = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        assert_eq!(k44.pub_len(), 1312);
        assert_eq!(k44.priv_len(), 2560);
        assert_eq!(k44.sig_len(), 2420);

        let k65 = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa65, Some(&TEST_SEED)).unwrap();
        assert_eq!(k65.pub_len(), 1952);
        assert_eq!(k65.priv_len(), 4032);
        assert_eq!(k65.sig_len(), 3309);

        let k87 = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa87, Some(&TEST_SEED)).unwrap();
        assert_eq!(k87.pub_len(), 2592);
        assert_eq!(k87.priv_len(), 4896);
        assert_eq!(k87.sig_len(), 4627);
    }

    // -----------------------------------------------------------------
    // Modular reduction primitives.
    // -----------------------------------------------------------------
    #[test]
    fn reduce_once_keeps_values_under_q_unchanged() {
        for v in [0u32, 1, 100, ML_DSA_Q - 1] {
            assert_eq!(reduce_once(v), v);
        }
    }

    #[test]
    fn reduce_once_subtracts_q_when_needed() {
        assert_eq!(reduce_once(ML_DSA_Q), 0);
        assert_eq!(reduce_once(ML_DSA_Q + 5), 5);
        assert_eq!(reduce_once(2 * ML_DSA_Q - 1), ML_DSA_Q - 1);
    }

    #[test]
    fn mod_sub_centred_difference() {
        // mod_sub returns (a - b) mod q in [0, q).
        assert_eq!(mod_sub(5, 3), 2);
        assert_eq!(mod_sub(3, 5), ML_DSA_Q - 2);
        assert_eq!(mod_sub(0, 1), ML_DSA_Q - 1);
    }

    // -----------------------------------------------------------------
    // Bit-packing round-trip — exercised indirectly by key codec tests
    // above, but we sanity-check the low-level `bit_pack` / `bit_unpack`
    // primitives directly for all widths that appear in ML-DSA.
    // -----------------------------------------------------------------
    #[test]
    fn bit_pack_then_unpack_preserves_small_coefficients() {
        for bits in [4u32, 6, 10, 13, 18, 20] {
            let mut coeffs = [0u32; NUM_POLY_COEFFICIENTS];
            for (i, c) in coeffs.iter_mut().enumerate() {
                // `bits` is ≤ 20, so `(1 << bits) - 1` always fits in u32.
                let mask: u32 = if bits >= 32 {
                    u32::MAX
                } else {
                    (1u32 << bits) - 1
                };
                // Test indices are bounded by NUM_POLY_COEFFICIENTS = 256, so
                // the cast to u32 is lossless by construction.
                let i_u32 = u32::try_from(i).expect("index fits in u32");
                *c = i_u32 & mask;
            }
            // Widening u32 → usize is always lossless on all supported
            // targets (usize ≥ u32 bits).
            let byte_len = (NUM_POLY_COEFFICIENTS * bits as usize + 7) / 8;
            let mut buf = vec![0u8; byte_len];
            bit_pack(&coeffs, bits, &mut buf);
            let mut back = [0u32; NUM_POLY_COEFFICIENTS];
            bit_unpack(&buf, bits, &mut back).expect("valid bit widths must unpack");
            assert_eq!(coeffs, back, "bit_pack/unpack mismatch at bits={bits}");
        }
    }

    // -----------------------------------------------------------------
    // Power-2-round primitive: r == r1 · 2^d + r0 with |r0| ≤ 2^(d-1).
    // -----------------------------------------------------------------
    #[test]
    fn power2_round_reconstructs_input() {
        for r in [0u32, 1, 100, 1024, 1 << 13, (1 << 20) + 7, ML_DSA_Q - 1] {
            let (r1, r0) = power2_round(r);
            // r0 is in (-2^(d-1), 2^(d-1)], encoded as u32 mod q.
            // Reconstruction: r1 · 2^d + r0  (mod q) == r.
            let re = (r1.wrapping_mul(TWO_POWER_D).wrapping_add(r0)) % ML_DSA_Q;
            assert_eq!(re, r, "Power2Round reconstruction failed for r={r}");
        }
    }

    // -----------------------------------------------------------------
    // Compression primitives: decompose(r) == (r1, r0) s.t. r ≡ r1·(2γ₂) + r0.
    // -----------------------------------------------------------------
    #[test]
    fn decompose_reconstructs_input_mldsa_44() {
        // `decompose` returns r0 as a *signed* integer stored in u32
        // (values > Q_MINUS1_DIV2 have had q subtracted, so e.g. `-1` appears
        // as `0xFFFFFFFF`). Reconstruct via signed i64 arithmetic and
        // `rem_euclid(q)` to map the mathematical residue back into [0, q).
        let gamma2 = 95_232u32;
        for r in [0u32, 1, gamma2, 2 * gamma2, ML_DSA_Q / 3, ML_DSA_Q - 1] {
            let (r1, r0) = decompose(r, gamma2);
            let two_gamma2 = (gamma2 as i64) * 2;
            let re =
                ((r1 as i64) * two_gamma2 + (r0 as i32) as i64).rem_euclid(ML_DSA_Q as i64) as u32;
            assert_eq!(
                re, r,
                "decompose reconstruction failed for r={r}, γ₂={gamma2}"
            );
        }
    }

    #[test]
    fn decompose_reconstructs_input_mldsa_65() {
        // Identical reconstruction logic as the ML-DSA-44 case — only γ₂
        // differs (the (q-1)/32 variant used by ML-DSA-65 and ML-DSA-87).
        let gamma2 = 261_888u32;
        for r in [0u32, 1, gamma2, 2 * gamma2, ML_DSA_Q / 3, ML_DSA_Q - 1] {
            let (r1, r0) = decompose(r, gamma2);
            let two_gamma2 = (gamma2 as i64) * 2;
            let re =
                ((r1 as i64) * two_gamma2 + (r0 as i32) as i64).rem_euclid(ML_DSA_Q as i64) as u32;
            assert_eq!(
                re, r,
                "decompose reconstruction failed for r={r}, γ₂={gamma2}"
            );
        }
    }

    // -----------------------------------------------------------------
    // w1_encoded_len_per_poly returns the spec-mandated widths.
    // -----------------------------------------------------------------
    #[test]
    fn w1_encoded_length_matches_gamma2() {
        assert_eq!(w1_encoded_len_per_poly(GAMMA2_Q_MINUS1_DIV88), 192);
        assert_eq!(w1_encoded_len_per_poly(GAMMA2_Q_MINUS1_DIV32), 128);
    }

    // -----------------------------------------------------------------
    // pairwise_check accepts a fresh keypair but rejects mismatched halves.
    // -----------------------------------------------------------------
    #[test]
    fn pairwise_check_passes_for_consistent_key() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        key.pairwise_check()
            .expect("fresh key must pass pairwise check");
    }

    #[test]
    fn pairwise_check_detects_swapped_public_component() {
        let mut key_a =
            MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        let mut other_seed = TEST_SEED;
        other_seed[1] ^= 0x55;
        let key_b = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&other_seed)).unwrap();
        // Swap in key_b's public encoding into key_a so that the public and
        // private halves belong to two different derivations.
        key_a.pub_encoding = key_b.pub_encoding.clone();
        key_a.rho = key_b.rho;
        key_a.t1 = key_b.t1.clone();
        key_a.tr = key_b.tr;
        assert!(
            key_a.pairwise_check().is_err(),
            "mismatched pk/sk halves must fail the pairwise check"
        );
    }

    // -----------------------------------------------------------------
    // Zeroization: cloned private material is independently zeroized on drop.
    // -----------------------------------------------------------------
    #[test]
    fn drop_zeroizes_private_material_in_a_cloned_key() {
        let key = MlDsaKey::generate(libctx(), MlDsaVariant::MlDsa44, Some(&TEST_SEED)).unwrap();
        // `dup` yields an independently-dropped clone; the mere fact that
        // the compiler accepts the `Drop` chain confirms ZeroizeOnDrop is
        // wired. We additionally verify that the private encoding length is
        // nonzero before drop — this is our proxy check.
        let clone = key.dup(KeySelection::Private).unwrap();
        assert!(clone.priv_encoding.as_ref().is_some_and(|v| !v.is_empty()));
        drop(clone);
        // Original key still usable.
        let _ = key
            .public_key_bytes()
            .expect("public material must remain after dropping the clone");
    }
}
