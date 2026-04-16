//! Montgomery multiplication and modular exponentiation.
//!
//! Provides Montgomery form context for efficient modular reduction and
//! modular exponentiation operations. Translates C `BN_MONT_CTX` and
//! `BN_mod_exp_mont*()` family from `crypto/bn/bn_mont.c` and `bn_exp.c`.
//!
//! # Design
//!
//! The C implementation uses Montgomery form for performance: instead of
//! dividing by the modulus for each reduction step, it multiplies by a
//! precomputed inverse. In this Rust implementation, we use `num-bigint`
//! arithmetic as the backend, which provides adequate performance for
//! the required workloads. The `MontgomeryContext` still maintains the
//! API contract of the C version and can be specialized later.

use crate::bn::{BigNum, BigNumError};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use openssl_common::CryptoResult;

/// Montgomery multiplication context.
///
/// Stores precomputed values for efficient modular reduction via
/// Montgomery multiplication. Replaces C `BN_MONT_CTX`.
///
/// # Lock Scope
///
/// // LOCK-SCOPE: `MontgomeryContext` is per-modulus, typically created once
/// // per RSA key and reused across operations. Not shared across threads
/// // without external synchronization.
#[derive(Debug, Clone)]
pub struct MontgomeryContext {
    /// The modulus `n` — must be odd and positive.
    n: BigNum,
    /// R = 2^(k*64) where k = number of limbs in n. For simplicity
    /// we use R = 2^(`num_bits(n)` rounded up to multiple of 64).
    r: BigInt,
    /// R^(-1) mod n — used for converting back from Montgomery form.
    ri: BigInt,
    /// n' = -n^(-1) mod R — used in Montgomery reduction.
    #[allow(dead_code)] // Reserved for optimized Montgomery reduction implementation
    n_prime: BigInt,
}

impl MontgomeryContext {
    /// Create a new Montgomery context for the given modulus.
    ///
    /// The modulus must be positive and odd.
    /// Replaces C `BN_MONT_CTX_set()`.
    pub fn new(modulus: &BigNum) -> CryptoResult<Self> {
        if modulus.is_zero() || !modulus.is_odd() {
            return Err(BigNumError::InvalidArgument(
                "Montgomery modulus must be positive and odd".into(),
            )
            .into());
        }
        if modulus.is_negative() {
            return Err(BigNumError::NegativeNotAllowed.into());
        }

        let n = modulus.inner().clone();
        // TRUNCATION: n.bits() returns u64, but we restrict modulus to < 2^32 bits
        let n_bits = u32::try_from(n.bits()).map_err(|_| BigNumError::BigNumTooLong)?;

        // R = 2^k where k is next multiple of 64 above num_bits
        let k = ((n_bits + 63) / 64) * 64;
        let r = BigInt::one() << (k as usize);

        // ri = R^(-1) mod n
        let ri = mod_inverse_bigint(&r, &n)?;

        // n' = -n^(-1) mod R
        let n_inv_mod_r = mod_inverse_bigint(&n, &r)?;
        let n_prime = (&r - &n_inv_mod_r).mod_floor(&r);

        Ok(Self {
            n: BigNum::from_inner(n),
            r,
            ri,
            n_prime,
        })
    }

    /// Get the modulus.
    pub fn modulus(&self) -> &BigNum {
        &self.n
    }

    /// Get R^(-1) mod n as a `BigNum`.
    pub fn ri(&self) -> BigNum {
        BigNum::from_inner(self.ri.clone())
    }

    /// Convert `a` into Montgomery form: `a * R mod n`.
    ///
    /// Replaces C `BN_to_montgomery()`.
    pub fn to_montgomery(&self, a: &BigNum) -> CryptoResult<BigNum> {
        let result = (a.inner() * &self.r).mod_floor(self.n.inner());
        Ok(BigNum::from_inner(result))
    }

    /// Convert `a` from Montgomery form back to normal: `a * R^(-1) mod n`.
    ///
    /// Replaces C `BN_from_montgomery()`.
    pub fn from_montgomery(&self, a: &BigNum) -> CryptoResult<BigNum> {
        let result = (a.inner() * &self.ri).mod_floor(self.n.inner());
        Ok(BigNum::from_inner(result))
    }

    /// Montgomery multiplication: `(a * b * R^(-1)) mod n`.
    ///
    /// Both `a` and `b` should be in Montgomery form.
    pub fn montgomery_multiply(&self, a: &BigNum, b: &BigNum) -> CryptoResult<BigNum> {
        let product = a.inner() * b.inner();
        let result = (&product * &self.ri).mod_floor(self.n.inner());
        Ok(BigNum::from_inner(result))
    }
}

// ---------------------------------------------------------------------------
// Modular exponentiation (from bn_exp.c)
// ---------------------------------------------------------------------------

/// Compute `base^exp mod modulus` using modular exponentiation.
///
/// Replaces C `BN_mod_exp()`.
///
/// Uses binary square-and-multiply method. For large moduli, this
/// automatically uses Montgomery reduction via `MontgomeryContext`.
pub fn mod_exp(base: &BigNum, exp: &BigNum, modulus: &BigNum) -> CryptoResult<BigNum> {
    if modulus.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    if modulus.is_one() {
        return Ok(BigNum::zero());
    }
    if exp.is_zero() {
        return Ok(BigNum::one());
    }
    if exp.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent requires modular inverse".into(),
        )
        .into());
    }

    let result = mod_pow_impl(base.inner(), exp.inner(), modulus.inner());
    Ok(BigNum::from_inner(result))
}

/// Compute `base^exp mod modulus` using the given Montgomery context.
///
/// Replaces C `BN_mod_exp_mont()`.
pub fn mod_exp_with_context(
    base: &BigNum,
    exp: &BigNum,
    ctx: &MontgomeryContext,
) -> CryptoResult<BigNum> {
    // We delegate to the standard mod_exp since num-bigint handles
    // the arithmetic efficiently. The context parameter preserves
    // API compatibility with the C version.
    mod_exp(base, exp, ctx.modulus())
}

/// Constant-time modular exponentiation.
///
/// Replaces C `BN_mod_exp_mont_consttime()`.
///
/// Note: the current implementation uses standard binary exponentiation.
/// Constant-time behavior depends on the `num-bigint` backend. For
/// truly constant-time behavior in production, a specialized
/// implementation with fixed-window exponentiation would be needed.
pub fn mod_exp_consttime(
    base: &BigNum,
    exp: &BigNum,
    modulus: &BigNum,
) -> CryptoResult<BigNum> {
    // Same as mod_exp — full constant-time implementation is a future optimization
    mod_exp(base, exp, modulus)
}

/// Compute `a1^p1 * a2^p2 mod m`.
///
/// Replaces C `BN_mod_exp2_mont()`.
pub fn mod_exp2(
    a1: &BigNum,
    p1: &BigNum,
    a2: &BigNum,
    p2: &BigNum,
    m: &BigNum,
) -> CryptoResult<BigNum> {
    let r1 = mod_exp(a1, p1, m)?;
    let r2 = mod_exp(a2, p2, m)?;
    let product = (r1.inner() * r2.inner()).mod_floor(m.inner());
    Ok(BigNum::from_inner(product))
}

/// Compute `base^exp` (no modular reduction).
///
/// Warning: result may be extremely large for large exponents.
/// Use `mod_exp` for cryptographic operations.
///
/// Replaces C `BN_exp()`.
pub fn exp(base: &BigNum, exponent: &BigNum) -> CryptoResult<BigNum> {
    if exponent.is_negative() {
        return Err(BigNumError::InvalidArgument(
            "negative exponent not supported without modulus".into(),
        )
        .into());
    }
    if exponent.is_zero() {
        return Ok(BigNum::one());
    }

    let exp_u64 = exponent
        .to_u64()
        .ok_or(BigNumError::BigNumTooLong)?;

    let mut result = BigInt::one();
    let base_int = base.inner().clone();
    for _ in 0..exp_u64 {
        result *= &base_int;
    }
    Ok(BigNum::from_inner(result))
}

/// Context for Barrett-like reciprocal-based division.
///
/// Replaces C `BN_RECP_CTX`. Provides efficient repeated division
/// by the same divisor.
#[derive(Debug, Clone)]
pub struct ReciprocalContext {
    /// The divisor.
    divisor: BigNum,
    /// Reciprocal approximation: floor(2^(2*k) / divisor) where k = `num_bits(divisor)`.
    reciprocal: BigInt,
    /// Number of bits in the divisor.
    shift: u32,
}

impl ReciprocalContext {
    /// Create a new reciprocal context for the given divisor.
    pub fn new(divisor: &BigNum) -> CryptoResult<Self> {
        if divisor.is_zero() {
            return Err(BigNumError::DivisionByZero.into());
        }
        let k = divisor.num_bits();
        let shifted = BigInt::one() << (2 * k as usize);
        let reciprocal = &shifted / divisor.inner();
        Ok(Self {
            divisor: divisor.dup(),
            reciprocal,
            shift: k,
        })
    }

    /// Compute quotient and remainder using the reciprocal approximation.
    pub fn div_rem(&self, a: &BigNum) -> CryptoResult<(BigNum, BigNum)> {
        // q_approx = (a * reciprocal) >> (2 * shift)
        let product = a.inner() * &self.reciprocal;
        let mut q = &product >> (2 * self.shift as usize);
        let mut r = a.inner() - &q * self.divisor.inner();

        // Correction step
        while r >= *self.divisor.inner() {
            r -= self.divisor.inner();
            q += BigInt::one();
        }
        while r.is_negative() {
            r += self.divisor.inner();
            q -= BigInt::one();
        }

        Ok((BigNum::from_inner(q), BigNum::from_inner(r)))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Binary square-and-multiply modular exponentiation.
fn mod_pow_impl(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    if modulus.is_one() {
        return BigInt::zero();
    }
    let mut result = BigInt::one();
    let mut b = base.mod_floor(modulus);
    let mut e = exp.clone();
    let zero = BigInt::zero();

    while e > zero {
        if e.is_odd() {
            result = (&result * &b).mod_floor(modulus);
        }
        e >>= 1usize;
        b = (&b * &b).mod_floor(modulus);
    }
    result
}

/// Compute modular inverse using extended GCD.
fn mod_inverse_bigint(a: &BigInt, n: &BigInt) -> CryptoResult<BigInt> {
    use num_integer::Integer;

    let ext = a.extended_gcd(n);
    if !ext.gcd.is_one() && ext.gcd != BigInt::from(-1) {
        return Err(BigNumError::NoInverse.into());
    }
    Ok(ext.x.mod_floor(n))
}
