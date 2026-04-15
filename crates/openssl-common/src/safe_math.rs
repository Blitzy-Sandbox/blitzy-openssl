//! Overflow-checked arithmetic primitives for the OpenSSL Rust workspace.
//!
//! Replaces the C `safe_math.h` macro system with Rust's native
//! checked/saturating/overflowing arithmetic operations. All functions
//! in this module enforce Rule R6 (lossless numeric casts).
//!
//! # C Source Reference
//!
//! This module translates `include/internal/safe_math.h` (444 lines of
//! macro-generated inline functions). The C macros generate type-specific
//! functions via `OSSL_SAFE_MATH_SIGNED` and `OSSL_SAFE_MATH_UNSIGNED`
//! composite macros, each expanding to add/sub/mul/div/mod/neg operations
//! with overflow detection.
//!
//! # Design
//!
//! The C API pattern `result = safe_op(a, b, &err)` where `err` is OR'd
//! with `1` on overflow is replaced by [`SafeResult<T>`], a value-and-flag
//! pair that can be converted to `Result<T, CommonError>` via
//! [`SafeResult::into_result`].
//!
//! # Macro Families Translated
//!
//! | C Macro Family               | Rust Equivalent                     |
//! |------------------------------|-------------------------------------|
//! | `OSSL_SAFE_MATH_ADDU/ADDS`  | `safe_add_u*` / `safe_add_i*`      |
//! | `OSSL_SAFE_MATH_SUBU/SUBS`  | `safe_sub_u*` / `safe_sub_i*`      |
//! | `OSSL_SAFE_MATH_MULU/MULS`  | `safe_mul_u*` / `safe_mul_i*`      |
//! | `OSSL_SAFE_MATH_DIVU/DIVS`  | `safe_div_u*` / `safe_div_i*`      |
//! | `OSSL_SAFE_MATH_MODU/MODS`  | `safe_mod_u*` / `safe_mod_i*`      |
//! | `OSSL_SAFE_MATH_NEGS`       | `safe_neg_i*`                       |
//! | `OSSL_SAFE_MATH_MULDIVU`    | `safe_muldiv_u64`                   |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`SafeResult`] carries an explicit overflow
//!   flag; no sentinel integers.
//! - **R6 (Lossless Casts):** [`checked_cast`] and `saturating_cast_*`
//!   functions replace all bare `as` narrowing conversions.
//! - **R8 (Zero Unsafe):** No `unsafe` code — uses only Rust's native
//!   checked arithmetic.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.

use std::num::TryFromIntError;

use crate::error::CommonError;

// =============================================================================
// SafeResult — Overflow-Aware Arithmetic Result
// =============================================================================

/// Result of an overflow-checked arithmetic operation.
///
/// Mirrors the C `safe_math.h` pattern where a function returns a value
/// **and** sets an `int *err` flag on overflow. In Rust, both pieces of
/// information are bundled into a single struct.
///
/// # Overflow Value Semantics
///
/// When overflow occurs the `value` field contains:
/// - **Unsigned ops:** The wrapping result (matching C unsigned overflow
///   semantics) for add/mul, or `0` for sub underflow.
/// - **Signed ops:** The saturating result (`MIN` or `MAX`), matching the
///   C macros which return `min` or `max` on overflow.
/// - **Division/modulus by zero:** `0` for the overflow sentinel.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::{SafeResult, safe_add_u64};
///
/// let r = safe_add_u64(u64::MAX, 1);
/// assert!(r.overflowed);
///
/// let r = safe_add_u64(1, 2);
/// assert!(!r.overflowed);
/// assert_eq!(r.value, 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeResult<T> {
    /// The result value.
    ///
    /// On success this is the mathematically correct result. On overflow
    /// it contains the wrapping (unsigned) or saturating (signed) result,
    /// depending on the operation.
    pub value: T,

    /// Whether the operation overflowed (or encountered a domain error
    /// such as division by zero).
    pub overflowed: bool,
}

impl<T> SafeResult<T> {
    /// Creates a successful (non-overflowed) result.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::safe_math::SafeResult;
    ///
    /// let r = SafeResult::ok(42u64);
    /// assert_eq!(r.value, 42);
    /// assert!(!r.overflowed);
    /// ```
    #[inline]
    pub fn ok(value: T) -> Self {
        Self {
            value,
            overflowed: false,
        }
    }

    /// Creates an overflowed result carrying the given saturated/wrapped
    /// fallback value.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::safe_math::SafeResult;
    ///
    /// let r = SafeResult::<u64>::overflow(u64::MAX);
    /// assert!(r.overflowed);
    /// assert_eq!(r.value, u64::MAX);
    /// ```
    #[inline]
    pub fn overflow(saturated_value: T) -> Self {
        Self {
            value: saturated_value,
            overflowed: true,
        }
    }

    /// Converts to `Result<T, CommonError>`.
    ///
    /// Returns `Ok(value)` when the operation succeeded, or
    /// `Err(CommonError::ArithmeticOverflow { .. })` when overflow was
    /// detected.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::safe_math::SafeResult;
    ///
    /// let ok_result = SafeResult::ok(10u32);
    /// assert_eq!(ok_result.into_result().unwrap(), 10);
    ///
    /// let overflow_result = SafeResult::<u32>::overflow(0);
    /// assert!(overflow_result.into_result().is_err());
    /// ```
    #[inline]
    pub fn into_result(self) -> Result<T, CommonError> {
        if self.overflowed {
            Err(CommonError::ArithmeticOverflow {
                operation: "safe arithmetic",
            })
        } else {
            Ok(self.value)
        }
    }
}

// =============================================================================
// Unsigned 64-bit Arithmetic (replaces OSSL_SAFE_MATH_UNSIGNED for u64)
// =============================================================================

/// Checked addition of two `u64` values.
///
/// On overflow, returns the wrapping sum with the overflow flag set,
/// matching the C `OSSL_SAFE_MATH_ADDU` behavior where `a + b` wraps
/// and `*err` is OR'd with `1`.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_add_u64;
///
/// let r = safe_add_u64(10, 20);
/// assert_eq!(r.value, 30);
/// assert!(!r.overflowed);
///
/// let r = safe_add_u64(u64::MAX, 1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, 0); // wrapping
/// ```
#[inline]
pub fn safe_add_u64(a: u64, b: u64) -> SafeResult<u64> {
    match a.checked_add(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.wrapping_add(b)),
    }
}

/// Checked subtraction of two `u64` values.
///
/// On underflow (when `b > a`), returns `0` with the overflow flag set.
/// This differs from the C `OSSL_SAFE_MATH_SUBU` which returns the
/// wrapping result; Rust returns the saturating floor of `0` for unsigned
/// underflow.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_sub_u64;
///
/// let r = safe_sub_u64(10, 3);
/// assert_eq!(r.value, 7);
/// assert!(!r.overflowed);
///
/// let r = safe_sub_u64(3, 10);
/// assert!(r.overflowed);
/// assert_eq!(r.value, 0);
/// ```
#[inline]
pub fn safe_sub_u64(a: u64, b: u64) -> SafeResult<u64> {
    match a.checked_sub(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

/// Checked multiplication of two `u64` values.
///
/// On overflow, returns the wrapping product with the overflow flag set,
/// matching C `OSSL_SAFE_MATH_MULU` behavior.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_mul_u64;
///
/// let r = safe_mul_u64(6, 7);
/// assert_eq!(r.value, 42);
/// assert!(!r.overflowed);
///
/// let r = safe_mul_u64(u64::MAX, 2);
/// assert!(r.overflowed);
/// ```
#[inline]
pub fn safe_mul_u64(a: u64, b: u64) -> SafeResult<u64> {
    match a.checked_mul(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.wrapping_mul(b)),
    }
}

/// Checked division of two `u64` values.
///
/// Division by zero returns `SafeResult::overflow(0)` with the flag set,
/// matching the C `OSSL_SAFE_MATH_DIVU` domain error path.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_div_u64;
///
/// let r = safe_div_u64(42, 7);
/// assert_eq!(r.value, 6);
/// assert!(!r.overflowed);
///
/// let r = safe_div_u64(42, 0);
/// assert!(r.overflowed);
/// assert_eq!(r.value, 0);
/// ```
#[inline]
pub fn safe_div_u64(a: u64, b: u64) -> SafeResult<u64> {
    match a.checked_div(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

/// Checked modulus of two `u64` values.
///
/// Modulus by zero returns `SafeResult::overflow(0)` with the flag set,
/// matching the C `OSSL_SAFE_MATH_MODU` domain error path.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_mod_u64;
///
/// let r = safe_mod_u64(10, 3);
/// assert_eq!(r.value, 1);
/// assert!(!r.overflowed);
///
/// let r = safe_mod_u64(10, 0);
/// assert!(r.overflowed);
/// assert_eq!(r.value, 0);
/// ```
#[inline]
pub fn safe_mod_u64(a: u64, b: u64) -> SafeResult<u64> {
    match a.checked_rem(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

// =============================================================================
// Unsigned 32-bit Arithmetic (replaces OSSL_SAFE_MATH_UNSIGNED for u32)
// =============================================================================

/// Checked addition of two `u32` values.
///
/// On overflow, returns the wrapping sum with the overflow flag set.
/// See [`safe_add_u64`] for detailed semantics.
#[inline]
pub fn safe_add_u32(a: u32, b: u32) -> SafeResult<u32> {
    match a.checked_add(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.wrapping_add(b)),
    }
}

/// Checked subtraction of two `u32` values.
///
/// On underflow, returns `0` with the overflow flag set.
/// See [`safe_sub_u64`] for detailed semantics.
#[inline]
pub fn safe_sub_u32(a: u32, b: u32) -> SafeResult<u32> {
    match a.checked_sub(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

/// Checked multiplication of two `u32` values.
///
/// On overflow, returns the wrapping product with the overflow flag set.
/// See [`safe_mul_u64`] for detailed semantics.
#[inline]
pub fn safe_mul_u32(a: u32, b: u32) -> SafeResult<u32> {
    match a.checked_mul(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.wrapping_mul(b)),
    }
}

/// Checked division of two `u32` values.
///
/// Division by zero returns `SafeResult::overflow(0)`.
/// See [`safe_div_u64`] for detailed semantics.
#[inline]
pub fn safe_div_u32(a: u32, b: u32) -> SafeResult<u32> {
    match a.checked_div(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

/// Checked modulus of two `u32` values.
///
/// Modulus by zero returns `SafeResult::overflow(0)`.
/// See [`safe_mod_u64`] for detailed semantics.
#[inline]
pub fn safe_mod_u32(a: u32, b: u32) -> SafeResult<u32> {
    match a.checked_rem(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

// =============================================================================
// Unsigned usize Arithmetic (replaces OSSL_SAFE_MATH_UNSIGNED for size_t)
// =============================================================================

/// Checked addition of two `usize` values.
///
/// On overflow, returns the wrapping sum with the overflow flag set.
/// See [`safe_add_u64`] for detailed semantics.
#[inline]
pub fn safe_add_usize(a: usize, b: usize) -> SafeResult<usize> {
    match a.checked_add(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.wrapping_add(b)),
    }
}

/// Checked subtraction of two `usize` values.
///
/// On underflow, returns `0` with the overflow flag set.
/// See [`safe_sub_u64`] for detailed semantics.
#[inline]
pub fn safe_sub_usize(a: usize, b: usize) -> SafeResult<usize> {
    match a.checked_sub(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

/// Checked multiplication of two `usize` values.
///
/// On overflow, returns the wrapping product with the overflow flag set.
/// See [`safe_mul_u64`] for detailed semantics.
#[inline]
pub fn safe_mul_usize(a: usize, b: usize) -> SafeResult<usize> {
    match a.checked_mul(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.wrapping_mul(b)),
    }
}

// =============================================================================
// Signed 64-bit Arithmetic (replaces OSSL_SAFE_MATH_SIGNED for i64)
// =============================================================================

/// Checked addition of two `i64` values.
///
/// On overflow, returns the saturating sum with the overflow flag set:
/// positive overflow yields [`i64::MAX`], negative overflow yields
/// [`i64::MIN`], matching C `OSSL_SAFE_MATH_ADDS` behavior.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_add_i64;
///
/// let r = safe_add_i64(10, 20);
/// assert_eq!(r.value, 30);
/// assert!(!r.overflowed);
///
/// let r = safe_add_i64(i64::MAX, 1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, i64::MAX);
///
/// let r = safe_add_i64(i64::MIN, -1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, i64::MIN);
/// ```
#[inline]
pub fn safe_add_i64(a: i64, b: i64) -> SafeResult<i64> {
    match a.checked_add(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.saturating_add(b)),
    }
}

/// Checked subtraction of two `i64` values.
///
/// On overflow, returns the saturating difference with the overflow flag
/// set. See [`safe_add_i64`] for overflow value semantics.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_sub_i64;
///
/// let r = safe_sub_i64(10, 3);
/// assert_eq!(r.value, 7);
/// assert!(!r.overflowed);
///
/// let r = safe_sub_i64(i64::MIN, 1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, i64::MIN);
/// ```
#[inline]
pub fn safe_sub_i64(a: i64, b: i64) -> SafeResult<i64> {
    match a.checked_sub(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.saturating_sub(b)),
    }
}

/// Checked multiplication of two `i64` values.
///
/// On overflow, returns the saturating product with the overflow flag set.
/// The sign of the saturated result follows the standard rule: if the
/// operand signs differ the result is [`i64::MIN`], otherwise
/// [`i64::MAX`], matching C `OSSL_SAFE_MATH_MULS`.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_mul_i64;
///
/// let r = safe_mul_i64(6, 7);
/// assert_eq!(r.value, 42);
/// assert!(!r.overflowed);
///
/// let r = safe_mul_i64(i64::MAX, 2);
/// assert!(r.overflowed);
/// assert_eq!(r.value, i64::MAX);
/// ```
#[inline]
pub fn safe_mul_i64(a: i64, b: i64) -> SafeResult<i64> {
    match a.checked_mul(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.saturating_mul(b)),
    }
}

/// Checked division of two `i64` values.
///
/// Handles two overflow cases:
/// - **Division by zero:** Returns `SafeResult::overflow(0)`.
/// - **`i64::MIN / -1`:** Returns `SafeResult::overflow(i64::MAX)`,
///   matching C `OSSL_SAFE_MATH_DIVS` which returns `max`.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_div_i64;
///
/// let r = safe_div_i64(42, 7);
/// assert_eq!(r.value, 6);
/// assert!(!r.overflowed);
///
/// let r = safe_div_i64(42, 0);
/// assert!(r.overflowed);
///
/// let r = safe_div_i64(i64::MIN, -1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, i64::MAX);
/// ```
#[inline]
pub fn safe_div_i64(a: i64, b: i64) -> SafeResult<i64> {
    match a.checked_div(b) {
        Some(v) => SafeResult::ok(v),
        None => {
            // Two failure modes: division by zero, or i64::MIN / -1.
            // For MIN / -1, the mathematical result is i64::MAX + 1, so
            // we saturate to i64::MAX (matching C OSSL_SAFE_MATH_DIVS).
            // For division by zero, return 0 as the sentinel.
            if b == 0 {
                SafeResult::overflow(0)
            } else {
                // b == -1 && a == i64::MIN
                SafeResult::overflow(i64::MAX)
            }
        }
    }
}

/// Checked modulus of two `i64` values.
///
/// Handles two overflow cases:
/// - **Modulus by zero:** Returns `SafeResult::overflow(0)`.
/// - **`i64::MIN % -1`:** Returns `SafeResult::overflow(0)` since the
///   mathematically correct remainder is zero (any integer mod ±1 is 0).
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_mod_i64;
///
/// let r = safe_mod_i64(10, 3);
/// assert_eq!(r.value, 1);
/// assert!(!r.overflowed);
///
/// let r = safe_mod_i64(10, 0);
/// assert!(r.overflowed);
/// assert_eq!(r.value, 0);
///
/// let r = safe_mod_i64(i64::MIN, -1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, 0);
/// ```
#[inline]
pub fn safe_mod_i64(a: i64, b: i64) -> SafeResult<i64> {
    match a.checked_rem(b) {
        Some(v) => SafeResult::ok(v),
        None => {
            // Both division-by-zero and MIN % -1 produce a
            // mathematically-zero remainder (or an undefined result for
            // div-by-zero). Return 0 as the overflow sentinel.
            SafeResult::overflow(0)
        }
    }
}

/// Checked negation of an `i64` value.
///
/// The only overflow case is `i64::MIN` which cannot be negated in
/// two's complement. Returns `SafeResult::overflow(i64::MIN)` matching
/// C `OSSL_SAFE_MATH_NEGS` which returns `min` on failure.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_neg_i64;
///
/// let r = safe_neg_i64(42);
/// assert_eq!(r.value, -42);
/// assert!(!r.overflowed);
///
/// let r = safe_neg_i64(i64::MIN);
/// assert!(r.overflowed);
/// assert_eq!(r.value, i64::MIN);
/// ```
#[inline]
pub fn safe_neg_i64(a: i64) -> SafeResult<i64> {
    match a.checked_neg() {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(i64::MIN),
    }
}

// =============================================================================
// Signed 32-bit Arithmetic (replaces OSSL_SAFE_MATH_SIGNED for i32)
// =============================================================================

/// Checked addition of two `i32` values.
///
/// On overflow, returns the saturating sum with the overflow flag set.
/// See [`safe_add_i64`] for detailed semantics.
#[inline]
pub fn safe_add_i32(a: i32, b: i32) -> SafeResult<i32> {
    match a.checked_add(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.saturating_add(b)),
    }
}

/// Checked subtraction of two `i32` values.
///
/// On overflow, returns the saturating difference with the overflow flag
/// set. See [`safe_sub_i64`] for detailed semantics.
#[inline]
pub fn safe_sub_i32(a: i32, b: i32) -> SafeResult<i32> {
    match a.checked_sub(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.saturating_sub(b)),
    }
}

/// Checked multiplication of two `i32` values.
///
/// On overflow, returns the saturating product with the overflow flag
/// set. See [`safe_mul_i64`] for detailed semantics.
#[inline]
pub fn safe_mul_i32(a: i32, b: i32) -> SafeResult<i32> {
    match a.checked_mul(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(a.saturating_mul(b)),
    }
}

/// Checked division of two `i32` values.
///
/// Handles division by zero and `i32::MIN / -1` overflow.
/// See [`safe_div_i64`] for detailed semantics.
#[inline]
pub fn safe_div_i32(a: i32, b: i32) -> SafeResult<i32> {
    match a.checked_div(b) {
        Some(v) => SafeResult::ok(v),
        None => {
            if b == 0 {
                SafeResult::overflow(0)
            } else {
                // b == -1 && a == i32::MIN
                SafeResult::overflow(i32::MAX)
            }
        }
    }
}

/// Checked modulus of two `i32` values.
///
/// Handles modulus by zero and `i32::MIN % -1` overflow.
/// See [`safe_mod_i64`] for detailed semantics.
#[inline]
pub fn safe_mod_i32(a: i32, b: i32) -> SafeResult<i32> {
    match a.checked_rem(b) {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(0),
    }
}

/// Checked negation of an `i32` value.
///
/// The only overflow case is `i32::MIN`. Returns
/// `SafeResult::overflow(i32::MIN)` matching C `OSSL_SAFE_MATH_NEGS`.
/// See [`safe_neg_i64`] for detailed semantics.
#[inline]
pub fn safe_neg_i32(a: i32) -> SafeResult<i32> {
    match a.checked_neg() {
        Some(v) => SafeResult::ok(v),
        None => SafeResult::overflow(i32::MIN),
    }
}

// =============================================================================
// Combined Multiply-Divide (replaces OSSL_SAFE_MATH_MULDIVU)
// =============================================================================

/// Fused multiply-divide: computes `(a * b) / c` for `u64` operands
/// using a `u128` intermediate to avoid intermediate overflow.
///
/// This replaces the C `OSSL_SAFE_MATH_MULDIVU` macro which uses a
/// multi-step decomposition to avoid overflow. The Rust version is
/// simpler because `u128` is a native type, allowing the full product
/// to be computed exactly.
///
/// # Overflow Cases
///
/// - **`c == 0`:** Returns `SafeResult::overflow(0)`.
/// - **Result exceeds `u64::MAX`:** Returns
///   `SafeResult::overflow(u64::MAX)`.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::safe_muldiv_u64;
///
/// // (1_000_000 * 1_000_000) / 1_000 = 1_000_000_000
/// let r = safe_muldiv_u64(1_000_000, 1_000_000, 1_000);
/// assert_eq!(r.value, 1_000_000_000);
/// assert!(!r.overflowed);
///
/// // Division by zero
/// let r = safe_muldiv_u64(10, 20, 0);
/// assert!(r.overflowed);
///
/// // Result too large for u64
/// let r = safe_muldiv_u64(u64::MAX, u64::MAX, 1);
/// assert!(r.overflowed);
/// assert_eq!(r.value, u64::MAX);
/// ```
#[inline]
pub fn safe_muldiv_u64(a: u64, b: u64, c: u64) -> SafeResult<u64> {
    if c == 0 {
        return SafeResult::overflow(0);
    }

    // Widen to u128 to hold the full product without overflow.
    let product = u128::from(a) * u128::from(b);
    let quotient = product / u128::from(c);

    // Check whether the quotient fits in a u64.
    match u64::try_from(quotient) {
        Ok(v) => SafeResult::ok(v),
        Err(_) => SafeResult::overflow(u64::MAX),
    }
}

// =============================================================================
// Saturating Convenience Functions
// =============================================================================

/// Saturating addition of two `u64` values.
///
/// Returns `u64::MAX` on overflow instead of wrapping. This is a
/// convenience wrapper for callers that only need the clamped result
/// without explicit overflow detection.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::saturating_add_u64;
///
/// assert_eq!(saturating_add_u64(10, 20), 30);
/// assert_eq!(saturating_add_u64(u64::MAX, 1), u64::MAX);
/// ```
#[inline]
pub fn saturating_add_u64(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// Saturating subtraction of two `u64` values.
///
/// Returns `0` on underflow instead of wrapping.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::saturating_sub_u64;
///
/// assert_eq!(saturating_sub_u64(10, 3), 7);
/// assert_eq!(saturating_sub_u64(3, 10), 0);
/// ```
#[inline]
pub fn saturating_sub_u64(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

/// Saturating multiplication of two `u64` values.
///
/// Returns `u64::MAX` on overflow instead of wrapping.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::saturating_mul_u64;
///
/// assert_eq!(saturating_mul_u64(6, 7), 42);
/// assert_eq!(saturating_mul_u64(u64::MAX, 2), u64::MAX);
/// ```
#[inline]
pub fn saturating_mul_u64(a: u64, b: u64) -> u64 {
    a.saturating_mul(b)
}

// =============================================================================
// Lossless Cast Utilities (Rule R6 Enforcement)
// =============================================================================

/// Generic checked numeric cast.
///
/// Converts `value` from type `From` to type `To` using [`TryFrom`],
/// returning `Err(CommonError::CastOverflow(..))` if the value does not
/// fit in the target type. This is the **primary enforcement mechanism**
/// for Rule R6 (lossless numeric casts) — every narrowing conversion in
/// the workspace should use this function instead of a bare `as` cast.
///
/// # Type Constraint
///
/// The `To` type must implement `TryFrom<From>` with
/// `Error = TryFromIntError`, which is satisfied by all standard integer
/// type pairs.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::checked_cast;
///
/// let v: u32 = checked_cast::<u64, u32>(42u64).unwrap();
/// assert_eq!(v, 42);
///
/// // Value too large for u32
/// let err = checked_cast::<u64, u32>(u64::from(u32::MAX) + 1);
/// assert!(err.is_err());
/// ```
#[inline]
pub fn checked_cast<From, To>(value: From) -> Result<To, CommonError>
where
    To: TryFrom<From, Error = TryFromIntError>,
{
    To::try_from(value).map_err(CommonError::CastOverflow)
}

/// Saturating cast from `u64` to `u32`.
///
/// Returns `u32::MAX` if the value exceeds `u32::MAX`, otherwise
/// returns the value as `u32`. This avoids a bare `as u32` cast
/// (forbidden by Rule R6) while providing a safe fallback.
///
/// # TRUNCATION
///
/// Saturating to `u32::MAX` — used for buffer sizes, counters, and
/// index values where exceeding 2^32 − 1 is a limit condition.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::saturating_cast_u64_to_u32;
///
/// assert_eq!(saturating_cast_u64_to_u32(42), 42);
/// assert_eq!(saturating_cast_u64_to_u32(u64::MAX), u32::MAX);
/// ```
#[inline]
pub fn saturating_cast_u64_to_u32(value: u64) -> u32 {
    // TRUNCATION: saturating to u32::MAX for values exceeding 32-bit range
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Saturating cast from `u64` to `usize`.
///
/// On 64-bit platforms this is a lossless conversion. On 32-bit
/// platforms, values exceeding `usize::MAX` are clamped to
/// `usize::MAX`.
///
/// # TRUNCATION
///
/// Saturating to `usize::MAX` — ensures portability across 32-bit and
/// 64-bit targets without bare `as` casts.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::saturating_cast_u64_to_usize;
///
/// assert_eq!(saturating_cast_u64_to_usize(42), 42usize);
/// ```
#[inline]
pub fn saturating_cast_u64_to_usize(value: u64) -> usize {
    // TRUNCATION: saturating to usize::MAX for 32-bit platform safety
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Saturating cast from `usize` to `u32`.
///
/// Returns `u32::MAX` if the value exceeds `u32::MAX`. On 32-bit
/// platforms this is always lossless; on 64-bit platforms values
/// above 2^32 − 1 are clamped.
///
/// # TRUNCATION
///
/// Saturating to `u32::MAX` — used for interop with APIs expecting
/// 32-bit sizes.
///
/// # Examples
///
/// ```
/// use openssl_common::safe_math::saturating_cast_usize_to_u32;
///
/// assert_eq!(saturating_cast_usize_to_u32(42), 42u32);
/// ```
#[inline]
pub fn saturating_cast_usize_to_u32(value: usize) -> u32 {
    // TRUNCATION: saturating to u32::MAX for values exceeding 32-bit range
    u32::try_from(value).unwrap_or(u32::MAX)
}
