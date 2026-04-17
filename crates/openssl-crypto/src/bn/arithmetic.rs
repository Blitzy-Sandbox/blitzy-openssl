//! Big number arithmetic operations for the OpenSSL Rust workspace.
//!
//! Provides addition, subtraction, multiplication, division, modular arithmetic,
//! bit-shifting, GCD, modular inverse, Kronecker symbol, and modular square root.
//! All operations use `num-bigint` as the backend with checked arithmetic per Rule R6.
//!
//! Translates C functions from `crypto/bn/bn_add.c`, `bn_mul.c`, `bn_div.c`,
//! `bn_mod.c`, `bn_shift.c`, `bn_word.c`, `bn_gcd.c`, `bn_kron.c`, `bn_sqrt.c`.

use crate::bn::{BigNum, BigNumError};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use openssl_common::CryptoResult;

// ---------------------------------------------------------------------------
// Basic addition and subtraction (from bn_add.c)
// ---------------------------------------------------------------------------

/// Compute `a + b`.
///
/// Replaces C `BN_add()`.
pub fn add(a: &BigNum, b: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() + b.inner())
}

/// Compute `a - b`.
///
/// Replaces C `BN_sub()`.
pub fn sub(a: &BigNum, b: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() - b.inner())
}

/// Unsigned addition: `|a| + |b|`.
///
/// Replaces C `BN_uadd()`.
pub fn uadd(a: &BigNum, b: &BigNum) -> BigNum {
    let mag_a = a.inner().magnitude();
    let mag_b = b.inner().magnitude();
    BigNum::from_inner(BigInt::from(mag_a + mag_b))
}

/// Unsigned subtraction: `|a| - |b|`.
///
/// Returns error if `|a| < |b|`.
/// Replaces C `BN_usub()`.
pub fn usub(a: &BigNum, b: &BigNum) -> CryptoResult<BigNum> {
    let mag_a = a.inner().magnitude();
    let mag_b = b.inner().magnitude();
    if mag_a < mag_b {
        return Err(
            BigNumError::InvalidArgument("|a| < |b| in unsigned subtraction".into()).into(),
        );
    }
    BigNum::from_inner(BigInt::from(mag_a - mag_b));
    Ok(BigNum::from_inner(BigInt::from(
        a.inner().magnitude() - b.inner().magnitude(),
    )))
}

// ---------------------------------------------------------------------------
// Multiplication and squaring (from bn_mul.c, bn_sqr.c)
// ---------------------------------------------------------------------------

/// Compute `a * b`.
///
/// Replaces C `BN_mul()`.
pub fn mul(a: &BigNum, b: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() * b.inner())
}

/// Compute `a²` (optimized squaring).
///
/// Replaces C `BN_sqr()`.
pub fn sqr(a: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() * a.inner())
}

// ---------------------------------------------------------------------------
// Division (from bn_div.c)
// ---------------------------------------------------------------------------

/// Compute quotient and remainder: `a = q * d + r`.
///
/// Returns `(quotient, remainder)`.
/// Replaces C `BN_div()`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `divisor` is zero.
pub fn div_rem(a: &BigNum, divisor: &BigNum) -> CryptoResult<(BigNum, BigNum)> {
    if divisor.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let (q, r) = a.inner().div_rem(divisor.inner());
    Ok((BigNum::from_inner(q), BigNum::from_inner(r)))
}

/// Compute `a / d` (quotient only).
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `divisor` is zero.
pub fn div(a: &BigNum, divisor: &BigNum) -> CryptoResult<BigNum> {
    if divisor.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    Ok(BigNum::from_inner(a.inner() / divisor.inner()))
}

/// Compute `a mod d` (remainder only, Rust `%` semantics).
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `divisor` is zero.
pub fn rem(a: &BigNum, divisor: &BigNum) -> CryptoResult<BigNum> {
    if divisor.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    Ok(BigNum::from_inner(a.inner() % divisor.inner()))
}

// ---------------------------------------------------------------------------
// Modular arithmetic (from bn_mod.c)
// ---------------------------------------------------------------------------

/// Non-negative modular reduction: result in `[0, |m|)`.
///
/// Unlike Rust's `%` operator which may return negative values for negative
/// dividends, this always returns a non-negative result.
/// Replaces C `BN_nnmod()`.
pub fn nnmod(a: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let result = a.inner().mod_floor(m.inner());
    Ok(BigNum::from_inner(result))
}

/// Modular addition: `(a + b) mod m`, result in `[0, m)`.
///
/// Replaces C `BN_mod_add()`.
pub fn mod_add(a: &BigNum, b: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let sum = a.inner() + b.inner();
    Ok(BigNum::from_inner(sum.mod_floor(m.inner())))
}

/// Modular subtraction: `(a - b) mod m`, result in `[0, m)`.
///
/// Replaces C `BN_mod_sub()`.
pub fn mod_sub(a: &BigNum, b: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let diff = a.inner() - b.inner();
    Ok(BigNum::from_inner(diff.mod_floor(m.inner())))
}

/// Modular multiplication: `(a * b) mod m`.
///
/// Replaces C `BN_mod_mul()`.
pub fn mod_mul(a: &BigNum, b: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let product = a.inner() * b.inner();
    Ok(BigNum::from_inner(product.mod_floor(m.inner())))
}

/// Modular squaring: `a² mod m`.
///
/// Replaces C `BN_mod_sqr()`.
pub fn mod_sqr(a: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    mod_mul(a, a, m)
}

/// Modular left shift: `(a << n) mod m`.
///
/// Replaces C `BN_mod_lshift()`.
pub fn mod_lshift(a: &BigNum, n: u32, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let shifted = a.inner() << (n as usize);
    Ok(BigNum::from_inner(shifted.mod_floor(m.inner())))
}

// ---------------------------------------------------------------------------
// Bit shifting (from bn_shift.c)
// ---------------------------------------------------------------------------

/// Left shift by `n` bits: `a << n`.
///
/// Replaces C `BN_lshift()`.
pub fn lshift(a: &BigNum, n: u32) -> CryptoResult<BigNum> {
    Ok(BigNum::from_inner(a.inner() << (n as usize)))
}

/// Right shift by `n` bits: `a >> n`.
///
/// Replaces C `BN_rshift()`.
pub fn rshift(a: &BigNum, n: u32) -> BigNum {
    BigNum::from_inner(a.inner() >> (n as usize))
}

/// Left shift by 1 bit: `a << 1`.
///
/// Replaces C `BN_lshift1()`.
pub fn lshift1(a: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() << 1usize)
}

/// Right shift by 1 bit: `a >> 1`.
///
/// Replaces C `BN_rshift1()`.
pub fn rshift1(a: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() >> 1usize)
}

// ---------------------------------------------------------------------------
// Single-word operations (from bn_word.c)
// ---------------------------------------------------------------------------

/// Add a `u64` value to a `BigNum`: `a + w`.
///
/// Replaces C `BN_add_word()`.
pub fn add_word(a: &BigNum, w: u64) -> BigNum {
    BigNum::from_inner(a.inner() + BigInt::from(w))
}

/// Subtract a `u64` value from a `BigNum`: `a - w`.
///
/// Replaces C `BN_sub_word()`.
pub fn sub_word(a: &BigNum, w: u64) -> CryptoResult<BigNum> {
    Ok(BigNum::from_inner(a.inner() - BigInt::from(w)))
}

/// Multiply a `BigNum` by a `u64` value: `a * w`.
///
/// Replaces C `BN_mul_word()`.
pub fn mul_word(a: &BigNum, w: u64) -> BigNum {
    BigNum::from_inner(a.inner() * BigInt::from(w))
}

/// Compute `a mod w` (returns the remainder as `u64`).
///
/// Replaces C `BN_mod_word()`.
pub fn mod_word(a: &BigNum, w: u64) -> CryptoResult<u64> {
    if w == 0 {
        return Err(BigNumError::DivisionByZero.into());
    }
    let bw = BigInt::from(w);
    let r = a.inner().mod_floor(&bw);
    // The result of mod_floor with positive w is in [0, w), which fits in u64.
    r.to_u64().ok_or_else(|| BigNumError::Overflow.into())
}

/// Divide `a` by `w`, returning the quotient.
///
/// Replaces C `BN_div_word()`.
pub fn div_word(a: &BigNum, w: u64) -> CryptoResult<BigNum> {
    if w == 0 {
        return Err(BigNumError::DivisionByZero.into());
    }
    Ok(BigNum::from_inner(a.inner() / BigInt::from(w)))
}

// ---------------------------------------------------------------------------
// GCD and modular inverse (from bn_gcd.c)
// ---------------------------------------------------------------------------

/// Compute the greatest common divisor of `a` and `b`.
///
/// Replaces C `BN_gcd()`.
pub fn gcd(a: &BigNum, b: &BigNum) -> BigNum {
    let g = a.inner().gcd(b.inner());
    BigNum::from_inner(g)
}

/// Compute the modular inverse: `a⁻¹ mod n`.
///
/// Returns `Ok(inverse)` if the inverse exists (i.e., `gcd(a, n) == 1`).
/// Returns [`BigNumError::NoInverse`] if the inverse does not exist.
///
/// Replaces C `BN_mod_inverse()`.
pub fn mod_inverse(a: &BigNum, n: &BigNum) -> CryptoResult<BigNum> {
    if n.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let ext = a.inner().extended_gcd(n.inner());
    if !ext.gcd.is_one() && ext.gcd != BigInt::from(-1) {
        return Err(BigNumError::NoInverse.into());
    }
    // x * a + y * n = gcd => x * a ≡ 1 (mod n)
    // Reduce x modulo n to get positive result
    let result = ext.x.mod_floor(n.inner());
    Ok(BigNum::from_inner(result))
}

/// Check if `a` and `b` are coprime (`gcd(a, b) == 1`).
///
/// Replaces C `BN_are_coprime()`.
pub fn are_coprime(a: &BigNum, b: &BigNum) -> bool {
    gcd(a, b).is_one()
}

/// Compute `LCM(a, b) = |a * b| / gcd(a, b)`.
pub fn lcm(a: &BigNum, b: &BigNum) -> CryptoResult<BigNum> {
    let g = gcd(a, b);
    if g.is_zero() {
        return Ok(BigNum::zero());
    }
    let product = BigNum::from_inner(a.inner() * b.inner());
    let result = div(&product.abs(), &g)?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Kronecker symbol (from bn_kron.c)
// ---------------------------------------------------------------------------

/// Compute the Kronecker symbol `(a/b)`, a generalization of the Jacobi symbol.
///
/// Returns `-1`, `0`, or `1`.
/// Replaces C `BN_kronecker()`.
pub fn kronecker(a: &BigNum, b: &BigNum) -> CryptoResult<i32> {
    // Handle b == 0
    if b.is_zero() {
        return if a.abs().is_one() { Ok(1) } else { Ok(0) };
    }

    // Handle b == 1
    if b.is_one() {
        return Ok(1);
    }

    // Handle even b: factor out powers of 2
    let mut a_val = a.inner().clone();
    let mut b_val = b.inner().magnitude().clone();

    // If b is negative, flip sign of result if a is negative
    let b_neg = b.is_negative();
    let mut result = 1i32;

    if b_neg && a.is_negative() {
        result = -1;
    }

    // Remove factors of 2 from b
    let mut v = 0u32;
    while b_val.is_even() {
        b_val >>= 1usize;
        v += 1;
    }

    // Handle Kronecker extension for (a/2^v)
    if v > 0 {
        let a_mod8 = {
            use num_traits::ToPrimitive;
            let m = a.inner().magnitude() & num_bigint::BigUint::from(7u32);
            m.to_u32().unwrap_or(0)
        };
        if v % 2 == 1 {
            // (a/2) depends on a mod 8
            match a_mod8 {
                1 | 7 => {} // result *= 1
                3 | 5 => result = -result,
                _ => return Ok(0),
            }
        }
    }

    if b_val.is_one() {
        return Ok(result);
    }

    // Now compute Jacobi symbol (a / b_val) where b_val is odd
    // Reduce a mod b_val
    let b_int = BigInt::from(b_val.clone());
    a_val = a_val.mod_floor(&b_int);

    // Iterative Jacobi computation using quadratic reciprocity
    let mut a_work = a_val.magnitude().clone();
    let mut b_work = b_val;

    loop {
        if a_work.is_zero() {
            return if b_work.is_one() { Ok(result) } else { Ok(0) };
        }

        // Remove factors of 2 from a_work
        let mut s = 0u32;
        while a_work.is_even() {
            a_work >>= 1usize;
            s += 1;
        }

        if s % 2 == 1 {
            use num_traits::ToPrimitive;
            let b_mod8 = (&b_work & num_bigint::BigUint::from(7u32))
                .to_u32()
                .unwrap_or(0);
            if b_mod8 == 3 || b_mod8 == 5 {
                result = -result;
            }
        }

        // Quadratic reciprocity
        {
            use num_traits::ToPrimitive;
            let a_mod4 = (&a_work & num_bigint::BigUint::from(3u32))
                .to_u32()
                .unwrap_or(0);
            let b_mod4 = (&b_work & num_bigint::BigUint::from(3u32))
                .to_u32()
                .unwrap_or(0);
            if a_mod4 == 3 && b_mod4 == 3 {
                result = -result;
            }
        }

        // Swap and reduce
        let temp = a_work;
        a_work = b_work.mod_floor(&temp);
        b_work = temp;
    }
}

// ---------------------------------------------------------------------------
// Modular square root (from bn_sqrt.c) — Tonelli-Shanks
// ---------------------------------------------------------------------------

/// Compute the modular square root: `r² ≡ a (mod p)`.
///
/// Uses the Tonelli-Shanks algorithm. Returns the square root if `a` is a
/// quadratic residue modulo `p`. Returns [`BigNumError::NoInverse`] if no
/// square root exists.
///
/// Replaces C `BN_mod_sqrt()`.
///
/// # Preconditions
///
/// - `p` must be an odd prime.
/// - `a` must be in range `[0, p)`.
#[allow(clippy::many_single_char_names)] // Tonelli-Shanks standard mathematical notation
pub fn mod_sqrt(value: &BigNum, prime: &BigNum) -> CryptoResult<Option<BigNum>> {
    if prime.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    if value.is_zero() {
        return Ok(Some(BigNum::zero()));
    }

    let one = BigInt::one();
    let two = BigInt::from(2);
    let prime_inner = prime.inner();

    // Check if value is a quadratic residue using Euler's criterion:
    // value^((prime-1)/2) mod prime == 1
    let prime_minus_1 = prime_inner - &one;
    let half_exp = &prime_minus_1 / &two;
    let euler = mod_pow_bigint(value.inner(), &half_exp, prime_inner);
    if euler != one {
        return Ok(None); // Not a quadratic residue
    }

    // Special case: prime ≡ 3 (mod 4)
    let prime_mod4 = prime_inner & BigInt::from(3);
    if prime_mod4 == BigInt::from(3) {
        let direct_exp = (prime_inner + &one) / BigInt::from(4);
        let result = mod_pow_bigint(value.inner(), &direct_exp, prime_inner);
        return Ok(Some(BigNum::from_inner(result)));
    }

    // General Tonelli-Shanks algorithm
    // Factor prime-1 = odd_part * 2^two_factor where odd_part is odd
    let mut odd_part = prime_minus_1.clone();
    let mut two_factor: u32 = 0;
    while odd_part.is_even() {
        odd_part >>= 1usize;
        two_factor += 1;
    }

    // Find a quadratic non-residue
    let mut non_residue = BigInt::from(2);
    loop {
        let test_exp = &prime_minus_1 / &two;
        let test = mod_pow_bigint(&non_residue, &test_exp, prime_inner);
        if test == &prime_minus_1 % prime_inner || test == prime_inner - &one {
            break;
        }
        non_residue += &one;
        if non_residue >= *prime_inner {
            return Ok(None);
        }
    }

    let mut order = two_factor;
    let mut root_of_unity = mod_pow_bigint(&non_residue, &odd_part, prime_inner);
    let mut target = mod_pow_bigint(value.inner(), &odd_part, prime_inner);
    let mut candidate = {
        let candidate_exp = (&odd_part + &one) / &two;
        mod_pow_bigint(value.inner(), &candidate_exp, prime_inner)
    };

    loop {
        if target.is_zero() {
            return Ok(Some(BigNum::zero()));
        }
        if target.is_one() {
            return Ok(Some(BigNum::from_inner(candidate)));
        }

        // Find the least least_idx such that target^(2^least_idx) ≡ 1 (mod prime)
        let mut least_idx: u32 = 1;
        let mut temp = (&target * &target).mod_floor(prime_inner);
        while !temp.is_one() {
            temp = (&temp * &temp).mod_floor(prime_inner);
            least_idx += 1;
            if least_idx >= order {
                return Ok(None);
            }
        }

        // Update using Tonelli-Shanks step
        let power = BigInt::one() << ((order - least_idx - 1) as usize);
        let factor = mod_pow_bigint(&root_of_unity, &power, prime_inner);
        order = least_idx;
        root_of_unity = (&factor * &factor).mod_floor(prime_inner);
        target = (&target * &root_of_unity).mod_floor(prime_inner);
        candidate = (&candidate * &factor).mod_floor(prime_inner);
    }
}

/// Internal helper: compute `base^exp mod modulus` using binary exponentiation.
///
/// This is a simple square-and-multiply implementation for use within this module.
fn mod_pow_bigint(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    if modulus.is_one() {
        return BigInt::zero();
    }
    if exp.is_zero() {
        return BigInt::one();
    }

    let mut result = BigInt::one();
    let mut base = base.mod_floor(modulus);
    let mut exp = exp.clone();

    while exp > BigInt::zero() {
        if exp.is_odd() {
            result = (&result * &base).mod_floor(modulus);
        }
        exp >>= 1usize;
        base = (&base * &base).mod_floor(modulus);
    }
    result
}
