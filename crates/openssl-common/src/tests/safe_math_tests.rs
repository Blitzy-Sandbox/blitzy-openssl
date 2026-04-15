//! Tests for overflow-checked arithmetic primitives in openssl-common.
//!
//! Comprehensive unit tests for the [`crate::safe_math`] module, verifying
//! [`SafeResult`] overflow detection, all six C macro families
//! (`ADD`/`SUB`/`MUL`/`DIV`/`MOD`/`NEG`) for both signed and unsigned types,
//! [`safe_muldiv_u64`] with `u128` intermediate, saturating convenience
//! functions, and Rule R6 [`checked_cast`]/[`saturating_cast_u64_to_u32`]
//! enforcement.
//!
//! Derived from C `include/internal/safe_math.h` macro-generated inline
//! functions (444 lines) and the AAP specification for this test file.
//!
//! # Coverage
//!
//! - [`SafeResult`] constructors and conversion: `ok`, `overflow`, `into_result`
//! - Unsigned 64-bit: `safe_add_u64`, `safe_sub_u64`, `safe_mul_u64`,
//!   `safe_div_u64`, `safe_mod_u64`
//! - Unsigned 32-bit: `safe_add_u32`, `safe_sub_u32`, `safe_mul_u32`
//! - Unsigned usize: `safe_add_usize`
//! - Signed 64-bit: `safe_add_i64`, `safe_sub_i64`, `safe_mul_i64`,
//!   `safe_div_i64`, `safe_mod_i64`, `safe_neg_i64`
//! - Signed 32-bit: `safe_add_i32`, `safe_sub_i32`
//! - Combined: `safe_muldiv_u64` (u128 intermediate)
//! - Saturating: `saturating_add_u64`, `saturating_sub_u64`, `saturating_mul_u64`
//! - Cast utilities: `checked_cast`, `saturating_cast_u64_to_u32`
//!
//! # Rules Enforced
//!
//! - **Rule R5:** `SafeResult.into_result()` returns `Result`, never sentinel values.
//! - **Rule R6 (CRITICAL):** `checked_cast` and `saturating_cast_u64_to_u32` fully tested.
//! - **Rule R8:** ZERO `unsafe` code in this file.
//! - **Rule R9:** Warning-free build under `RUSTFLAGS="-D warnings"`.
//! - **Rule R10:** Tests exercise `safe_math` module through public API.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_literal_unwrap
)]

use crate::error::CommonError;
use crate::safe_math::{
    checked_cast, safe_add_i32, safe_add_i64, safe_add_u32, safe_add_u64, safe_add_usize,
    safe_div_i64, safe_div_u64, safe_mod_i64, safe_mod_u64, safe_mul_i64, safe_mul_u32,
    safe_mul_u64, safe_muldiv_u64, safe_neg_i64, safe_sub_i32, safe_sub_i64, safe_sub_u32,
    safe_sub_u64, saturating_add_u64, saturating_cast_u64_to_u32, saturating_mul_u64,
    saturating_sub_u64, SafeResult,
};

// =============================================================================
// Phase 2: SafeResult Type Tests
// =============================================================================

#[test]
fn safe_result_ok() {
    let r = SafeResult::ok(42u64);
    assert_eq!(r.value, 42);
    assert!(!r.overflowed);
}

#[test]
fn safe_result_overflow() {
    let r = SafeResult::<u64>::overflow(u64::MAX);
    assert!(r.overflowed);
    assert_eq!(r.value, u64::MAX);
}

#[test]
fn safe_result_into_result_ok() {
    let r = SafeResult::ok(42u64);
    let result = r.into_result();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn safe_result_into_result_overflow() {
    let r = SafeResult::<u64>::overflow(0);
    let result = r.into_result();
    assert!(result.is_err());
    match result {
        Err(CommonError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "safe arithmetic");
        }
        other => panic!("expected ArithmeticOverflow, got {other:?}"),
    }
}

// =============================================================================
// Phase 3: Unsigned Addition Tests (replaces OSSL_SAFE_MATH_ADDU)
// =============================================================================

#[test]
fn safe_add_u64_normal() {
    let r = safe_add_u64(3, 4);
    assert_eq!(r.value, 7);
    assert!(!r.overflowed);
}

#[test]
fn safe_add_u64_overflow() {
    let r = safe_add_u64(u64::MAX, 1);
    assert!(r.overflowed);
    // Wrapping addition: u64::MAX + 1 wraps to 0
    assert_eq!(r.value, 0);
}

#[test]
fn safe_add_u64_zero() {
    let r = safe_add_u64(5, 0);
    assert_eq!(r.value, 5);
    assert!(!r.overflowed);
}

#[test]
fn safe_add_u64_max_boundary() {
    // Exact boundary: u64::MAX - 1 + 1 = u64::MAX (no overflow)
    let r = safe_add_u64(u64::MAX - 1, 1);
    assert_eq!(r.value, u64::MAX);
    assert!(!r.overflowed);
}

#[test]
fn safe_add_u32_normal() {
    let r = safe_add_u32(100, 200);
    assert_eq!(r.value, 300);
    assert!(!r.overflowed);
}

#[test]
fn safe_add_u32_overflow() {
    let r = safe_add_u32(u32::MAX, 1);
    assert!(r.overflowed);
    // Wrapping addition: u32::MAX + 1 wraps to 0
    assert_eq!(r.value, 0);
}

#[test]
fn safe_add_usize_normal() {
    let r = safe_add_usize(10, 20);
    assert_eq!(r.value, 30);
    assert!(!r.overflowed);
}

// =============================================================================
// Phase 4: Unsigned Subtraction Tests (replaces OSSL_SAFE_MATH_SUBU)
// =============================================================================

#[test]
fn safe_sub_u64_normal() {
    let r = safe_sub_u64(10, 3);
    assert_eq!(r.value, 7);
    assert!(!r.overflowed);
}

#[test]
fn safe_sub_u64_underflow() {
    // Underflow: 3 - 10 cannot be represented in u64
    let r = safe_sub_u64(3, 10);
    assert!(r.overflowed);
    // Rust implementation returns 0 as the underflow sentinel
    assert_eq!(r.value, 0);
}

#[test]
fn safe_sub_u64_zero() {
    let r = safe_sub_u64(5, 0);
    assert_eq!(r.value, 5);
    assert!(!r.overflowed);
}

#[test]
fn safe_sub_u64_equal() {
    let r = safe_sub_u64(5, 5);
    assert_eq!(r.value, 0);
    assert!(!r.overflowed);
}

#[test]
fn safe_sub_u32_underflow() {
    let r = safe_sub_u32(0, 1);
    assert!(r.overflowed);
    assert_eq!(r.value, 0);
}

// =============================================================================
// Phase 5: Unsigned Multiplication Tests (replaces OSSL_SAFE_MATH_MULU)
// =============================================================================

#[test]
fn safe_mul_u64_normal() {
    let r = safe_mul_u64(7, 6);
    assert_eq!(r.value, 42);
    assert!(!r.overflowed);
}

#[test]
fn safe_mul_u64_overflow() {
    let r = safe_mul_u64(u64::MAX, 2);
    assert!(r.overflowed);
    // Wrapping multiplication: u64::MAX * 2 wraps to u64::MAX - 1
    assert_eq!(r.value, u64::MAX.wrapping_mul(2));
}

#[test]
fn safe_mul_u64_by_zero() {
    let r = safe_mul_u64(u64::MAX, 0);
    assert_eq!(r.value, 0);
    assert!(!r.overflowed);
}

#[test]
fn safe_mul_u64_by_one() {
    let r = safe_mul_u64(42, 1);
    assert_eq!(r.value, 42);
    assert!(!r.overflowed);
}

#[test]
fn safe_mul_u32_overflow() {
    let r = safe_mul_u32(u32::MAX, 2);
    assert!(r.overflowed);
    assert_eq!(r.value, u32::MAX.wrapping_mul(2));
}

// =============================================================================
// Phase 6: Unsigned Division Tests (replaces OSSL_SAFE_MATH_DIVU)
// =============================================================================

#[test]
fn safe_div_u64_normal() {
    let r = safe_div_u64(42, 6);
    assert_eq!(r.value, 7);
    assert!(!r.overflowed);
}

#[test]
fn safe_div_u64_by_zero() {
    let r = safe_div_u64(42, 0);
    assert!(r.overflowed);
    assert_eq!(r.value, 0);
}

#[test]
fn safe_div_u64_by_one() {
    let r = safe_div_u64(42, 1);
    assert_eq!(r.value, 42);
    assert!(!r.overflowed);
}

#[test]
fn safe_div_u64_truncation() {
    // Integer division truncates: 7 / 2 = 3
    let r = safe_div_u64(7, 2);
    assert_eq!(r.value, 3);
    assert!(!r.overflowed);
}

// =============================================================================
// Phase 7: Unsigned Modulo Tests (replaces OSSL_SAFE_MATH_MODU)
// =============================================================================

#[test]
fn safe_mod_u64_normal() {
    let r = safe_mod_u64(7, 3);
    assert_eq!(r.value, 1);
    assert!(!r.overflowed);
}

#[test]
fn safe_mod_u64_by_zero() {
    let r = safe_mod_u64(7, 0);
    assert!(r.overflowed);
    assert_eq!(r.value, 0);
}

#[test]
fn safe_mod_u64_no_remainder() {
    let r = safe_mod_u64(6, 3);
    assert_eq!(r.value, 0);
    assert!(!r.overflowed);
}

// =============================================================================
// Phase 8: Signed Arithmetic Tests
// (replaces OSSL_SAFE_MATH_ADDS/SUBS/MULS/DIVS/MODS/NEGS)
// =============================================================================

// --- i64 Addition ---

#[test]
fn safe_add_i64_normal() {
    let r = safe_add_i64(3, -1);
    assert_eq!(r.value, 2);
    assert!(!r.overflowed);
}

#[test]
fn safe_add_i64_positive_overflow() {
    let r = safe_add_i64(i64::MAX, 1);
    assert!(r.overflowed);
    // Saturating addition: positive overflow saturates to i64::MAX
    assert_eq!(r.value, i64::MAX);
}

#[test]
fn safe_add_i64_negative_overflow() {
    let r = safe_add_i64(i64::MIN, -1);
    assert!(r.overflowed);
    // Saturating addition: negative overflow saturates to i64::MIN
    assert_eq!(r.value, i64::MIN);
}

// --- i64 Subtraction ---

#[test]
fn safe_sub_i64_normal() {
    let r = safe_sub_i64(5, 3);
    assert_eq!(r.value, 2);
    assert!(!r.overflowed);
}

#[test]
fn safe_sub_i64_underflow() {
    let r = safe_sub_i64(i64::MIN, 1);
    assert!(r.overflowed);
    // Saturating subtraction: negative overflow saturates to i64::MIN
    assert_eq!(r.value, i64::MIN);
}

// --- i64 Multiplication ---

#[test]
fn safe_mul_i64_normal() {
    let r = safe_mul_i64(-3, 4);
    assert_eq!(r.value, -12);
    assert!(!r.overflowed);
}

#[test]
fn safe_mul_i64_overflow() {
    let r = safe_mul_i64(i64::MAX, 2);
    assert!(r.overflowed);
    // Saturating multiplication: positive overflow saturates to i64::MAX
    assert_eq!(r.value, i64::MAX);
}

// --- i64 Division ---

#[test]
fn safe_div_i64_normal() {
    let r = safe_div_i64(-12, 4);
    assert_eq!(r.value, -3);
    assert!(!r.overflowed);
}

#[test]
fn safe_div_i64_by_zero() {
    let r = safe_div_i64(42, 0);
    assert!(r.overflowed);
    assert_eq!(r.value, 0);
}

#[test]
fn safe_div_i64_min_div_neg1() {
    // i64::MIN / -1 would overflow (result is i64::MAX + 1)
    let r = safe_div_i64(i64::MIN, -1);
    assert!(r.overflowed);
    // C macro returns max on MIN / -1
    assert_eq!(r.value, i64::MAX);
}

// --- i64 Modulo ---

#[test]
fn safe_mod_i64_normal() {
    let r = safe_mod_i64(7, 3);
    assert_eq!(r.value, 1);
    assert!(!r.overflowed);
}

#[test]
fn safe_mod_i64_by_zero() {
    let r = safe_mod_i64(7, 0);
    assert!(r.overflowed);
    assert_eq!(r.value, 0);
}

// --- i64 Negation ---

#[test]
fn safe_neg_i64_normal() {
    let r = safe_neg_i64(42);
    assert_eq!(r.value, -42);
    assert!(!r.overflowed);
}

#[test]
fn safe_neg_i64_min() {
    // i64::MIN cannot be negated in two's complement
    let r = safe_neg_i64(i64::MIN);
    assert!(r.overflowed);
    // C macro returns min on failure
    assert_eq!(r.value, i64::MIN);
}

#[test]
fn safe_neg_i64_zero() {
    let r = safe_neg_i64(0);
    assert_eq!(r.value, 0);
    assert!(!r.overflowed);
}

// --- i32 Boundary Tests ---

#[test]
fn safe_add_i32_overflow() {
    let r = safe_add_i32(i32::MAX, 1);
    assert!(r.overflowed);
    // Saturating addition: positive overflow saturates to i32::MAX
    assert_eq!(r.value, i32::MAX);
}

#[test]
fn safe_sub_i32_underflow() {
    let r = safe_sub_i32(i32::MIN, 1);
    assert!(r.overflowed);
    // Saturating subtraction: negative overflow saturates to i32::MIN
    assert_eq!(r.value, i32::MIN);
}

// =============================================================================
// Phase 9: Combined Operation Tests (safe_muldiv_u64)
// Used by time.h for converting between time units without intermediate overflow.
// =============================================================================

#[test]
fn safe_muldiv_u64_normal() {
    // (100 * 3) / 2 = 150
    let r = safe_muldiv_u64(100, 3, 2);
    assert_eq!(r.value, 150);
    assert!(!r.overflowed);
}

#[test]
fn safe_muldiv_u64_large_intermediate() {
    // (u64::MAX / 2) * 2 = u64::MAX - 1 (since u64::MAX is odd)
    // The u128 intermediate handles this without overflow
    let half = u64::MAX / 2;
    let r = safe_muldiv_u64(half, 2, 1);
    assert_eq!(r.value, u64::MAX - 1);
    assert!(!r.overflowed);
}

#[test]
fn safe_muldiv_u64_overflow() {
    // u64::MAX * u64::MAX = huge u128 value, divided by 1 exceeds u64
    let r = safe_muldiv_u64(u64::MAX, u64::MAX, 1);
    assert!(r.overflowed);
    assert_eq!(r.value, u64::MAX);
}

#[test]
fn safe_muldiv_u64_div_by_zero() {
    let r = safe_muldiv_u64(100, 3, 0);
    assert!(r.overflowed);
    assert_eq!(r.value, 0);
}

#[test]
fn safe_muldiv_u64_zero_numerator() {
    // 0 * u64::MAX / 1 = 0
    let r = safe_muldiv_u64(0, u64::MAX, 1);
    assert_eq!(r.value, 0);
    assert!(!r.overflowed);
}

// =============================================================================
// Phase 10: Saturating Convenience Function Tests
// =============================================================================

#[test]
fn saturating_add_u64_normal() {
    assert_eq!(saturating_add_u64(3, 4), 7);
}

#[test]
fn saturating_add_u64_capped() {
    assert_eq!(saturating_add_u64(u64::MAX, 1), u64::MAX);
}

#[test]
fn saturating_sub_u64_normal() {
    assert_eq!(saturating_sub_u64(10, 3), 7);
}

#[test]
fn saturating_sub_u64_capped() {
    assert_eq!(saturating_sub_u64(3, 10), 0);
}

#[test]
fn saturating_mul_u64_normal() {
    assert_eq!(saturating_mul_u64(6, 7), 42);
}

#[test]
fn saturating_mul_u64_capped() {
    assert_eq!(saturating_mul_u64(u64::MAX, 2), u64::MAX);
}

// =============================================================================
// Phase 11: checked_cast Tests (Rule R6 enforcement)
// =============================================================================

#[test]
fn checked_cast_u64_to_u32_success() {
    let result = checked_cast::<u64, u32>(100);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 100u32);
}

#[test]
fn checked_cast_u64_to_u32_overflow() {
    let result = checked_cast::<u64, u32>(u64::from(u32::MAX) + 1);
    assert!(result.is_err());
    match result {
        Err(CommonError::CastOverflow(_)) => { /* expected */ }
        other => panic!("expected CastOverflow, got {other:?}"),
    }
}

#[test]
fn checked_cast_i64_to_i32_success() {
    let result = checked_cast::<i64, i32>(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42i32);
}

#[test]
fn checked_cast_i64_to_i32_overflow() {
    let result = checked_cast::<i64, i32>(i64::MAX);
    assert!(result.is_err());
    match result {
        Err(CommonError::CastOverflow(_)) => { /* expected */ }
        other => panic!("expected CastOverflow, got {other:?}"),
    }
}

#[test]
fn checked_cast_u32_to_u8_success() {
    let result = checked_cast::<u32, u8>(255);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 255u8);
}

#[test]
fn checked_cast_u32_to_u8_overflow() {
    let result = checked_cast::<u32, u8>(256);
    assert!(result.is_err());
    match result {
        Err(CommonError::CastOverflow(_)) => { /* expected */ }
        other => panic!("expected CastOverflow, got {other:?}"),
    }
}

#[test]
fn checked_cast_usize_to_u32_success() {
    // Platform-safe test: 100 always fits in u32 on any platform
    let result = checked_cast::<usize, u32>(100usize);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 100u32);
}

#[test]
fn saturating_cast_u64_to_u32_normal() {
    assert_eq!(saturating_cast_u64_to_u32(100), 100u32);
}

#[test]
fn saturating_cast_u64_to_u32_capped() {
    assert_eq!(saturating_cast_u64_to_u32(u64::MAX), u32::MAX);
}
