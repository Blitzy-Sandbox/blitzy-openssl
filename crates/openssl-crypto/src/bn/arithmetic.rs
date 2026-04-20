//! Big number arithmetic operations for the OpenSSL Rust workspace.
//!
//! Provides addition, subtraction, multiplication, division, modular arithmetic,
//! bit-shifting, GCD, modular inverse, Kronecker symbol, and modular square root.
//! All operations use `num-bigint` as the backend with checked arithmetic per Rule R6.
//!
//! Translates C functions from `crypto/bn/bn_add.c`, `bn_mul.c`, `bn_div.c`,
//! `bn_mod.c`, `bn_shift.c`, `bn_word.c`, `bn_gcd.c`, `bn_kron.c`, `bn_sqrt.c`.
//!
//! # Design Decisions
//!
//! - Operations return `CryptoResult<BigNum>` instead of modifying output parameters
//!   (Rust ownership model replaces C pointer-based output params)
//! - Division by zero returns `Err(BigNumError::DivisionByZero)` instead of
//!   `ERR_raise(ERR_LIB_BN, BN_R_DIV_BY_ZERO)`
//! - All narrowing casts use `try_from` or `saturating_cast` per Rule R6
//! - The `num-bigint` crate handles internal limb-level operations, replacing
//!   C hand-rolled limb arithmetic in `bn_asm.c`
//! - `mod_inverse` and `mod_sqrt` return `Option<BigNum>` per Rule R5 instead
//!   of `NULL` sentinel values used by C `BN_mod_inverse()` / `BN_mod_sqrt()`

use crate::bn::{BigNum, BigNumError};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};
use openssl_common::{CryptoError, CryptoResult};
use tracing::trace;

// ---------------------------------------------------------------------------
// Lookup table for Kronecker symbol computation.
// For any odd BIGNUM n, tab[n & 7] = (-1)^((n²-1)/8).
// Matches the C `tab[8]` in bn_kron.c (Cohen algorithm 1.4.10).
// ---------------------------------------------------------------------------
const KRONECKER_TAB: [i32; 8] = [0, 1, 0, -1, 0, -1, 0, 1];

// ---------------------------------------------------------------------------
// Basic addition and subtraction (from bn_add.c)
// ---------------------------------------------------------------------------

/// Compute `a + b`.
///
/// Replaces C `BN_add()`. The `num-bigint` backend handles sign propagation
/// automatically, covering all sign combinations that the C implementation
/// dispatches manually (same-sign → uadd, different-sign → ucmp + usub).
pub fn add(a: &BigNum, b: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() + b.inner())
}

/// Compute `a - b`.
///
/// Replaces C `BN_sub()`. Sign-aware subtraction is handled by `BigInt`.
pub fn sub(a: &BigNum, b: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() - b.inner())
}

/// Unsigned addition: `|a| + |b|`.
///
/// Replaces C `BN_uadd()`. Operates on magnitudes only, discarding signs.
/// The result is always non-negative.
pub fn uadd(a: &BigNum, b: &BigNum) -> BigNum {
    let mag_a = a.inner().magnitude();
    let mag_b = b.inner().magnitude();
    BigNum::from_inner(BigInt::from(mag_a + mag_b))
}

/// Unsigned subtraction: `|a| - |b|`.
///
/// Returns error if `|a| < |b|` (unsigned subtraction would underflow).
/// Replaces C `BN_usub()`, which returns 0 on error when `|a| < |b|`.
pub fn usub(a: &BigNum, b: &BigNum) -> CryptoResult<BigNum> {
    let mag_a = a.inner().magnitude();
    let mag_b = b.inner().magnitude();
    if mag_a < mag_b {
        return Err(
            BigNumError::InvalidArgument("|a| < |b| in unsigned subtraction".into()).into(),
        );
    }
    Ok(BigNum::from_inner(BigInt::from(mag_a - mag_b)))
}

// ---------------------------------------------------------------------------
// Multiplication and squaring (from bn_mul.c, bn_sqr.c)
// ---------------------------------------------------------------------------

/// Compute `a * b`.
///
/// Replaces C `BN_mul()`. Uses `num-bigint`'s internal multiplication
/// which automatically selects Karatsuba/Toom-Cook for large operands,
/// replacing the manual algorithm selection in the C implementation's
/// `BN_mul()` → `bn_mul_normal()` / `bn_mul_recursive()` dispatch.
pub fn mul(a: &BigNum, b: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() * b.inner())
}

/// Compute `a²` (optimized squaring).
///
/// Replaces C `BN_sqr()`. Squaring is typically ~1.5x faster than general
/// multiplication because intermediate cross-products can be doubled instead
/// of recomputed. The `num-bigint` backend uses `a * a` which the compiler
/// and library may optimize.
pub fn sqr(a: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() * a.inner())
}

// ---------------------------------------------------------------------------
// Division (from bn_div.c)
// ---------------------------------------------------------------------------

/// Compute quotient and remainder: `a = q * divisor + r`.
///
/// Returns `(quotient, remainder)`.
/// Replaces C `BN_div()` which uses Knuth's long division with normalization.
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

/// Compute `a / divisor` (quotient only).
///
/// Replaces C `BN_div()` when the remainder is discarded.
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

/// Compute `a mod divisor` (remainder only, Rust `%` semantics).
///
/// The sign of the result matches the sign of `a`, consistent with Rust's
/// `%` operator and the C `BN_mod()` macro.
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
/// Replaces C `BN_nnmod()` from `bn_mod.c`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `m` is zero.
pub fn nnmod(a: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let result = a.inner().mod_floor(m.inner());
    Ok(BigNum::from_inner(result))
}

/// Modular addition: `(a + b) mod m`, result in `[0, m)`.
///
/// Replaces C `BN_mod_add()` which computes `BN_add()` then `BN_nnmod()`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `m` is zero.
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
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `m` is zero.
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
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `m` is zero.
pub fn mod_mul(a: &BigNum, b: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    let product = a.inner() * b.inner();
    Ok(BigNum::from_inner(product.mod_floor(m.inner())))
}

/// Modular squaring: `a² mod m`.
///
/// Replaces C `BN_mod_sqr()`, which is defined as `BN_mod_mul(r, a, a, m, ctx)`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `m` is zero.
pub fn mod_sqr(a: &BigNum, m: &BigNum) -> CryptoResult<BigNum> {
    mod_mul(a, a, m)
}

/// Modular left shift: `(a << n) mod m`.
///
/// Replaces C `BN_mod_lshift()`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `m` is zero.
/// Returns [`BigNumError::Overflow`] if `n` cannot be converted to `usize`.
pub fn mod_lshift(a: &BigNum, n: u32, m: &BigNum) -> CryptoResult<BigNum> {
    if m.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    // Rule R6: lossless cast from u32 to usize via try_from
    let shift_amount = usize::try_from(n).map_err(|_| BigNumError::Overflow)?;
    let shifted = a.inner() << shift_amount;
    Ok(BigNum::from_inner(shifted.mod_floor(m.inner())))
}

// ---------------------------------------------------------------------------
// Bit shifting (from bn_shift.c)
// ---------------------------------------------------------------------------

/// Left shift by `n` bits: `a << n`.
///
/// Replaces C `BN_lshift()`.
///
/// # Errors
///
/// Returns [`BigNumError::Overflow`] if `n` exceeds reasonable bounds
/// (cannot be converted to `usize` on this platform).
pub fn lshift(a: &BigNum, n: u32) -> CryptoResult<BigNum> {
    // Rule R6: lossless cast from u32 to usize via try_from
    let shift_amount = usize::try_from(n).map_err(|_| BigNumError::Overflow)?;
    Ok(BigNum::from_inner(a.inner() << shift_amount))
}

/// Right shift by `n` bits: `a >> n`.
///
/// Replaces C `BN_rshift()`. Always succeeds — shifting right by more than
/// the bit length produces zero.
pub fn rshift(a: &BigNum, n: u32) -> BigNum {
    // Rule R6: checked conversion from u32 to usize. On all supported 32-bit+
    // platforms this is infallible. If it somehow fails (hypothetical 16-bit
    // platform), shifting right by usize::MAX produces zero, which is
    // mathematically correct (right-shifting by more than the bit width gives 0).
    let shift_amount = usize::try_from(n).unwrap_or(usize::MAX);
    BigNum::from_inner(a.inner() >> shift_amount)
}

/// Left shift by 1 bit: `a << 1`.
///
/// Replaces C `BN_lshift1()`. Equivalent to `a * 2`.
pub fn lshift1(a: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() << 1usize)
}

/// Right shift by 1 bit: `a >> 1`.
///
/// Replaces C `BN_rshift1()`. Equivalent to integer division by 2.
pub fn rshift1(a: &BigNum) -> BigNum {
    BigNum::from_inner(a.inner() >> 1usize)
}

// ---------------------------------------------------------------------------
// Single-word operations (from bn_word.c)
// ---------------------------------------------------------------------------

/// Add a `u64` value to a `BigNum`: `a + w`.
///
/// Replaces C `BN_add_word()`, which modifies `a` in place. The Rust version
/// returns a new `BigNum` following Rust ownership conventions.
pub fn add_word(a: &BigNum, w: u64) -> BigNum {
    BigNum::from_inner(a.inner() + BigInt::from(w))
}

/// Subtract a `u64` value from a `BigNum`: `a - w`.
///
/// Replaces C `BN_sub_word()`. Unlike the C version which modifies `a` in
/// place and may toggle the sign bit, this returns a new `BigNum` that may
/// be negative if `a < w`.
///
/// # Errors
///
/// This function is infallible in Rust since `BigInt` supports negative
/// values. Wrapped in `CryptoResult` for API consistency with the error-
/// returning pattern used by the wider BN module.
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
/// The result is always in `[0, w)`, matching C `BN_mod_word()` semantics.
///
/// Replaces C `BN_mod_word()`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `w` is zero.
/// Returns [`BigNumError::Overflow`] if the result exceeds `u64` range
/// (should not happen for valid inputs since result < w).
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
/// The remainder can be obtained via [`mod_word`].
/// Replaces C `BN_div_word()`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `w` is zero.
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
/// The result is always non-negative: `gcd(a, b) == gcd(|a|, |b|)`.
/// Replaces C `BN_gcd()`.
pub fn gcd(a: &BigNum, b: &BigNum) -> BigNum {
    let g = a.inner().gcd(b.inner());
    BigNum::from_inner(g)
}

/// Compute the modular inverse: `a⁻¹ mod n`.
///
/// Returns `Ok(Some(inverse))` if the inverse exists (i.e., `gcd(a, n) == 1`).
/// Returns `Ok(None)` if the inverse does not exist (i.e., `a` and `n` are
/// not coprime).
///
/// Uses the extended Euclidean algorithm via `num_integer::Integer::extended_gcd()`.
///
/// Replaces C `BN_mod_inverse()`, which returns `NULL` when no inverse exists.
/// Per Rule R5, we use `Option<BigNum>` instead of a null sentinel.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `n` is zero.
pub fn mod_inverse(a: &BigNum, n: &BigNum) -> CryptoResult<Option<BigNum>> {
    if n.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }

    trace!(
        a_bits = a.num_bits(),
        n_bits = n.num_bits(),
        "computing modular inverse"
    );

    let ext = a.inner().extended_gcd(n.inner());

    // gcd must be ±1 for the inverse to exist.
    // extended_gcd may return a negative gcd if inputs are negative.
    if !ext.gcd.is_one() && ext.gcd != BigInt::from(-1) {
        // The inverse does not exist — log this event. Callers who require
        // the inverse to exist should convert `None` to
        // `BigNumError::NoInverse` via `.ok_or(BigNumError::NoInverse)`.
        trace!("modular inverse does not exist (gcd != 1)");
        return Ok(None);
    }

    // x * a + y * n = gcd  ⇒  x * a ≡ 1 (mod n)
    // Reduce x modulo n to get a positive result in [0, |n|).
    let mut result = BigNum::from_inner(ext.x);
    // Use inner_mut() to apply in-place modular reduction, avoiding an
    // extra allocation compared to `from_inner(ext.x.mod_floor(...))`.
    *result.inner_mut() = result.inner().mod_floor(n.inner());
    Ok(Some(result))
}

/// Convenience wrapper around [`mod_inverse`] that returns an error instead of
/// `None` when the modular inverse does not exist.
///
/// This is useful for callers that treat a missing inverse as a hard error
/// (e.g., DSA signing, RSA key generation, blinding).
///
/// # Errors
///
/// Returns [`BigNumError::NoInverse`] if `gcd(a, n) != 1`.
/// Returns [`BigNumError::DivisionByZero`] if `n` is zero.
pub fn mod_inverse_checked(a: &BigNum, n: &BigNum) -> CryptoResult<BigNum> {
    mod_inverse(a, n)?.ok_or_else(|| {
        let err: CryptoError = BigNumError::NoInverse.into();
        err
    })
}

/// Check if `a` and `b` are coprime (`gcd(a, b) == 1`).
///
/// Replaces C `BN_are_coprime()`.
pub fn are_coprime(a: &BigNum, b: &BigNum) -> bool {
    gcd(a, b).is_one()
}

/// Compute `LCM(a, b) = |a * b| / gcd(a, b)`.
///
/// Returns zero if either `a` or `b` is zero.
/// Uses `Integer::lcm()` from the `num-integer` crate for the core computation,
/// with `Signed::abs()` to ensure the result is non-negative.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if the internal division fails
/// (should not happen unless both inputs are zero, which is handled).
pub fn lcm(a: &BigNum, b: &BigNum) -> CryptoResult<BigNum> {
    // Delegate to num-integer's Integer::lcm() for the core computation.
    // This internally uses gcd to compute lcm = |a * b| / gcd(a, b).
    let raw_lcm = a.inner().lcm(b.inner());
    // Use Signed::abs() to guarantee non-negative result
    // (Integer::lcm on BigInt already returns non-negative, but we make it
    // explicit for clarity and to satisfy the Signed trait usage contract).
    Ok(BigNum::from_inner(raw_lcm.abs()))
}

// ---------------------------------------------------------------------------
// Kronecker symbol (from bn_kron.c)
// ---------------------------------------------------------------------------

/// Compute the Kronecker symbol `(a/b)`, a generalization of the Jacobi symbol.
///
/// Returns `-1`, `0`, or `1`.
/// Replaces C `BN_kronecker()` which implements Henri Cohen's algorithm 1.4.10
/// from "A Course in Computational Algebraic Number Theory".
///
/// # Errors
///
/// Returns an error on internal arithmetic failure (should not occur for
/// valid inputs). The C version returns `-2` as an error sentinel; the Rust
/// version uses `CryptoResult` per Rule R5.
pub fn kronecker(a: &BigNum, b: &BigNum) -> CryptoResult<i32> {
    trace!(
        a_bits = a.num_bits(),
        b_bits = b.num_bits(),
        "computing Kronecker symbol"
    );

    // Cohen's step 1: Handle b == 0
    if b.is_zero() {
        return if a.abs().is_one() { Ok(1) } else { Ok(0) };
    }

    // Cohen's step 2: Both even → result is 0
    let a_even = !a.inner().magnitude().bit(0);
    let b_even = !b.inner().magnitude().bit(0);
    if a_even && b_even {
        return Ok(0);
    }

    // Factor out powers of 2 from b: b = b_odd * 2^v
    let mut b_val = b.inner().magnitude().clone();
    let mut v = 0u32;
    while b_val.is_even() {
        b_val >>= 1usize;
        v += 1;
    }

    // Compute the contribution from powers of 2 in b.
    // For odd v, use tab[a & 7] = (-1)^((a²-1)/8).
    let mut result: i32 = if v & 1 == 1 {
        let a_mod8 = a.inner().magnitude() & BigUint::from(7u32);
        let idx = a_mod8.to_usize().unwrap_or(0);
        // idx is guaranteed in 0..8 since we masked with 7
        KRONECKER_TAB[idx]
    } else {
        1
    };

    // If b was negative and a is negative, flip sign.
    // Uses Sign enum for sign inspection (per schema: Sign from num_bigint)
    // and Signed::is_negative() for trait-based sign checking.
    if b.inner().sign() == Sign::Minus && a.inner().is_negative() {
        result = -result;
    }

    // b_val is now positive and odd
    if b_val.is_one() {
        return Ok(result);
    }

    // Compute Jacobi symbol (a / b_val) iteratively using quadratic reciprocity.
    // Reduce a mod b_val first.
    let b_int = BigInt::from(b_val.clone());
    let a_reduced = a.inner().mod_floor(&b_int);
    let mut a_work = a_reduced.magnitude().clone();
    let mut b_work = b_val;

    loop {
        // Step 3: If a_work == 0
        if a_work.is_zero() {
            return if b_work.is_one() { Ok(result) } else { Ok(0) };
        }

        // Remove factors of 2 from a_work
        let mut s = 0u32;
        while a_work.is_even() {
            a_work >>= 1usize;
            s += 1;
        }

        // Apply (2/b_work) contribution for odd number of 2-factors
        if s & 1 == 1 {
            let b_mod8 = (&b_work & BigUint::from(7u32)).to_u32().unwrap_or(0);
            // tab[b_mod8] gives (-1)^((b²-1)/8) for odd b
            if b_mod8 == 3 || b_mod8 == 5 {
                result = -result;
            }
        }

        // Apply quadratic reciprocity: if both a_work ≡ 3 (mod 4) and
        // b_work ≡ 3 (mod 4), flip the sign.
        let a_mod4 = (&a_work & BigUint::from(3u32)).to_u32().unwrap_or(0);
        let b_mod4 = (&b_work & BigUint::from(3u32)).to_u32().unwrap_or(0);
        if a_mod4 == 3 && b_mod4 == 3 {
            result = -result;
        }

        // Swap and reduce: (a_work, b_work) = (b_work mod a_work, a_work)
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
/// Uses the Tonelli-Shanks algorithm with a special fast path for
/// `p ≡ 3 (mod 4)`. Returns `Ok(Some(root))` if `a` is a quadratic residue
/// modulo `p`, or `Ok(None)` if no square root exists (i.e., `a` is a
/// quadratic non-residue).
///
/// Replaces C `BN_mod_sqrt()` from `bn_sqrt.c`, which implements algorithm
/// 1.5.1 from Henri Cohen's "A Course in Computational Algebraic Number
/// Theory".
///
/// Per Rule R5, we use `Option<BigNum>` instead of the C convention of
/// returning `NULL` for non-residues.
///
/// # Preconditions
///
/// - `p` must be an odd prime.
/// - `a` must be in range `[0, p)`.
///
/// # Errors
///
/// Returns [`BigNumError::DivisionByZero`] if `p` is zero.
/// Returns [`BigNumError::InvalidRange`] if `p` is negative or if `value` is
/// negative (preconditions require non-negative inputs).
#[allow(clippy::many_single_char_names)] // Tonelli-Shanks standard mathematical notation
pub fn mod_sqrt(value: &BigNum, prime: &BigNum) -> CryptoResult<Option<BigNum>> {
    if prime.is_zero() {
        return Err(BigNumError::DivisionByZero.into());
    }
    // Validate that prime is positive — Tonelli-Shanks requires a positive odd prime.
    if prime.is_negative() {
        return Err(BigNumError::InvalidRange.into());
    }
    // Validate that value is non-negative — square root is defined for [0, p).
    if value.is_negative() {
        return Err(BigNumError::InvalidRange.into());
    }

    // Trivial case: value ≡ 0 (mod p)
    if value.is_zero() {
        return Ok(Some(BigNum::zero()));
    }

    trace!(
        value_bits = value.num_bits(),
        prime_bits = prime.num_bits(),
        "computing modular square root (Tonelli-Shanks)"
    );

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
    // Direct formula: root = value^((prime+1)/4) mod prime
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

    // Find a quadratic non-residue z such that z^((p-1)/2) ≡ -1 (mod p)
    let mut non_residue = BigInt::from(2);
    loop {
        let test = mod_pow_bigint(&non_residue, &half_exp, prime_inner);
        // Check if test ≡ -1 (mod p), which is (p-1)
        if test == &prime_minus_1 % prime_inner || test == prime_inner - &one {
            break;
        }
        non_residue += &one;
        if non_residue >= *prime_inner {
            // No non-residue found (shouldn't happen for prime p > 2)
            return Ok(None);
        }
    }

    // Initialize Tonelli-Shanks iteration variables:
    //   order     = two_factor (current 2-adic order)
    //   root_of_unity = z^odd_part mod p
    //   target    = value^odd_part mod p
    //   candidate = value^((odd_part+1)/2) mod p
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

        // Find the least i such that target^(2^i) ≡ 1 (mod prime)
        let mut least_idx: u32 = 1;
        let mut temp = (&target * &target).mod_floor(prime_inner);
        while !temp.is_one() {
            temp = (&temp * &temp).mod_floor(prime_inner);
            least_idx += 1;
            if least_idx >= order {
                return Ok(None); // Should not happen for valid prime
            }
        }

        // Update using Tonelli-Shanks step:
        //   factor = root_of_unity^(2^(order - least_idx - 1)) mod p
        //   candidate = candidate * factor mod p
        //   root_of_unity = factor² mod p
        //   target = target * factor² mod p
        //   order = least_idx
        // Rule R6: safe u32 subtraction (least_idx < order guaranteed by loop guard)
        let power_exp = order - least_idx - 1;
        // Rule R6: checked u32 → usize conversion (infallible on 32-bit+ platforms)
        let power_shift = usize::try_from(power_exp).unwrap_or(usize::MAX);
        let power = BigInt::one() << power_shift;
        let factor = mod_pow_bigint(&root_of_unity, &power, prime_inner);
        order = least_idx;
        root_of_unity = (&factor * &factor).mod_floor(prime_inner);
        target = (&target * &root_of_unity).mod_floor(prime_inner);
        candidate = (&candidate * &factor).mod_floor(prime_inner);
    }
}

/// Internal helper: compute `base^exp mod modulus` using binary exponentiation
/// (square-and-multiply).
///
/// This is used by [`mod_sqrt`] and [`kronecker`] for modular power computations
/// within this module. It does not replace the full `BN_mod_exp()` which lives
/// in the Montgomery module.
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

// ---------------------------------------------------------------------------
// Additional operator trait implementations for BigNum
// ---------------------------------------------------------------------------
//
// Note: Add, Sub, Mul, Neg (owned), Shl, Shr, and their Assign variants are
// already implemented in `bn/mod.rs`. We add only Div, Rem, and Neg for
// reference (&BigNum) here, since these are not defined elsewhere.
// Fallible operations (Div, Rem) panic on division by zero — callers who
// need error handling should use the function forms (div, rem) directly.

impl std::ops::Div for &BigNum {
    type Output = BigNum;

    /// Division operator. Panics on division by zero — use [`div()`] for
    /// a fallible version.
    #[allow(clippy::expect_used)] // Operator trait cannot return Result; panic is standard
    fn div(self, rhs: &BigNum) -> BigNum {
        self::div(self, rhs).expect("division by zero in BigNum Div operator")
    }
}

impl std::ops::Rem for &BigNum {
    type Output = BigNum;

    /// Remainder operator. Panics on division by zero — use [`rem()`] for
    /// a fallible version.
    #[allow(clippy::expect_used)] // Operator trait cannot return Result; panic is standard
    fn rem(self, rhs: &BigNum) -> BigNum {
        self::rem(self, rhs).expect("division by zero in BigNum Rem operator")
    }
}

impl std::ops::Neg for &BigNum {
    type Output = BigNum;

    fn neg(self) -> BigNum {
        BigNum::from_inner(-self.inner().clone())
    }
}
