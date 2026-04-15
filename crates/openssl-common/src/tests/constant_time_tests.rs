//! Tests for constant-time comparison and selection primitives in openssl-common.
//!
//! Exercises every public function in the [`crate::constant_time`] module through
//! the crate's public API, verifying bitmask correctness, selection semantics,
//! memory comparison, and mask cleanliness invariants.
//!
//! Derived from the C `include/internal/constant_time.h` inline function behavior
//! (lines 32-250+) and the AAP specification for this test file.
//!
//! # Coverage
//!
//! - MSB extraction: [`constant_time_msb`], [`constant_time_msb_64`]
//! - Less-than: [`constant_time_lt`], [`constant_time_lt_8`], [`constant_time_lt_64`]
//! - Greater-or-equal: [`constant_time_ge`], [`constant_time_ge_8`]
//! - Zero check: [`constant_time_is_zero`], [`constant_time_is_zero_8`]
//! - Equality: [`constant_time_eq`], [`constant_time_eq_8`], [`constant_time_eq_int`],
//!   [`constant_time_eq_int_8`]
//! - Selection: [`constant_time_select`], [`constant_time_select_8`],
//!   [`constant_time_select_64`], [`constant_time_select_int`]
//! - Memory comparison: [`memcmp`], [`memcmp_choice`]
//! - Conditional copy: [`constant_time_copy_if_choice`]
//! - Bitmask pattern validation (all-ones or all-zeros invariant)
//!
//! # Rules Enforced
//!
//! - **Rule R5:** Functions return typed mask values (u32/u64/u8), bool for memcmp.
//! - **Rule R6:** Narrowing from u32 to u8 in `*_8` variants is intentional.
//! - **Rule R8:** ZERO `unsafe` code in this file.
//! - **Rule R9:** Warning-free build under `RUSTFLAGS="-D warnings"`.
//! - **Rule R10:** Tests exercise constant_time module through public API.

use crate::constant_time::{
    constant_time_copy_if_choice, constant_time_eq, constant_time_eq_8, constant_time_eq_int,
    constant_time_eq_int_8, constant_time_ge, constant_time_ge_8, constant_time_is_zero,
    constant_time_is_zero_32, constant_time_is_zero_8, constant_time_lt, constant_time_lt_64,
    constant_time_lt_8, constant_time_msb, constant_time_msb_64, constant_time_select,
    constant_time_select_64, constant_time_select_8, constant_time_select_int, memcmp,
    memcmp_choice, Choice,
};

// =============================================================================
// Phase 2: MSB (Most Significant Bit) Extraction Tests
// From C constant_time.h lines 102-119: constant_time_msb() returns all-ones
// if MSB set, 0 otherwise.
// =============================================================================

#[test]
fn msb_zero() {
    // MSB not set for zero.
    assert_eq!(constant_time_msb(0), 0);
}

#[test]
fn msb_one() {
    // MSB not set for small positive value.
    assert_eq!(constant_time_msb(1), 0);
}

#[test]
fn msb_high_bit_set() {
    // MSB set → all ones (0xFFFFFFFF).
    assert_eq!(constant_time_msb(0x8000_0000), 0xFFFF_FFFF);
}

#[test]
fn msb_max() {
    // All bits set → MSB set → all ones.
    assert_eq!(constant_time_msb(u32::MAX), 0xFFFF_FFFF);
}

#[test]
fn msb_just_below_high_bit() {
    // 0x7FFFFFFF has MSB clear → returns zero.
    assert_eq!(constant_time_msb(0x7FFF_FFFF), 0);
}

#[test]
fn msb_high_bit_plus_one() {
    // 0x80000001 has MSB set → all ones.
    assert_eq!(constant_time_msb(0x8000_0001), 0xFFFF_FFFF);
}

#[test]
fn msb_mid_range() {
    // 0x40000000 — bit 30 set, bit 31 clear → returns zero.
    assert_eq!(constant_time_msb(0x4000_0000), 0);
}

#[test]
fn msb_dead_beef() {
    // 0xDEADBEEF has MSB set (bit 31 = 1) → all ones.
    assert_eq!(constant_time_msb(0xDEAD_BEEF), 0xFFFF_FFFF);
}

// --- 64-bit MSB ---

#[test]
fn msb_64_zero() {
    assert_eq!(constant_time_msb_64(0u64), 0);
}

#[test]
fn msb_64_high_bit() {
    // Bit 63 set → all ones (u64::MAX).
    assert_eq!(constant_time_msb_64(1u64 << 63), u64::MAX);
}

#[test]
fn msb_64_max() {
    assert_eq!(constant_time_msb_64(u64::MAX), u64::MAX);
}

#[test]
fn msb_64_just_below_high_bit() {
    assert_eq!(constant_time_msb_64(0x7FFF_FFFF_FFFF_FFFF), 0);
}

#[test]
fn msb_64_one() {
    assert_eq!(constant_time_msb_64(1u64), 0);
}

// =============================================================================
// Phase 3: Less-Than Comparison Tests
// From C constant_time_lt(): returns 0xFFFFFFFF if a < b, 0 otherwise.
// =============================================================================

#[test]
fn lt_true() {
    // 5 < 10 is true → all ones mask.
    assert_eq!(constant_time_lt(5, 10), 0xFFFF_FFFF);
}

#[test]
fn lt_false_equal() {
    // 5 < 5 is false → zero mask.
    assert_eq!(constant_time_lt(5, 5), 0);
}

#[test]
fn lt_false_greater() {
    // 10 < 5 is false → zero mask.
    assert_eq!(constant_time_lt(10, 5), 0);
}

#[test]
fn lt_zero_less_than_one() {
    assert_eq!(constant_time_lt(0, 1), 0xFFFF_FFFF);
}

#[test]
fn lt_boundary_max() {
    // u32::MAX - 1 < u32::MAX is true.
    assert_eq!(constant_time_lt(u32::MAX - 1, u32::MAX), 0xFFFF_FFFF);
}

#[test]
fn lt_max_not_less_than_zero() {
    assert_eq!(constant_time_lt(u32::MAX, 0), 0);
}

#[test]
fn lt_max_not_less_than_max() {
    assert_eq!(constant_time_lt(u32::MAX, u32::MAX), 0);
}

#[test]
fn lt_zero_not_less_than_zero() {
    assert_eq!(constant_time_lt(0, 0), 0);
}

#[test]
fn lt_zero_less_than_max() {
    assert_eq!(constant_time_lt(0, u32::MAX), 0xFFFF_FFFF);
}

// --- 8-bit less-than ---

#[test]
fn lt_8_true() {
    // 3 < 7 → 0xFF.
    assert_eq!(constant_time_lt_8(3, 7), 0xFF);
}

#[test]
fn lt_8_false() {
    // 7 < 3 → 0x00.
    assert_eq!(constant_time_lt_8(7, 3), 0);
}

#[test]
fn lt_8_equal() {
    assert_eq!(constant_time_lt_8(5, 5), 0x00);
}

// --- 64-bit less-than ---

#[test]
fn lt_64_true() {
    assert_eq!(constant_time_lt_64(5u64, 10u64), u64::MAX);
}

#[test]
fn lt_64_false() {
    assert_eq!(constant_time_lt_64(10u64, 5u64), 0);
}

#[test]
fn lt_64_equal() {
    assert_eq!(constant_time_lt_64(5u64, 5u64), 0);
}

#[test]
fn lt_64_boundary_values() {
    assert_eq!(constant_time_lt_64(0, u64::MAX), u64::MAX);
    assert_eq!(constant_time_lt_64(u64::MAX, 0), 0);
    assert_eq!(constant_time_lt_64(u64::MAX - 1, u64::MAX), u64::MAX);
}

// =============================================================================
// Phase 4: Greater-or-Equal Comparison Tests
// From C constant_time_ge(): returns 0xFFFFFFFF if a >= b, 0 otherwise.
// =============================================================================

#[test]
fn ge_true_greater() {
    assert_eq!(constant_time_ge(10, 5), 0xFFFF_FFFF);
}

#[test]
fn ge_true_equal() {
    assert_eq!(constant_time_ge(5, 5), 0xFFFF_FFFF);
}

#[test]
fn ge_false() {
    assert_eq!(constant_time_ge(5, 10), 0);
}

#[test]
fn ge_boundary_values() {
    assert_eq!(constant_time_ge(u32::MAX, 0), 0xFFFF_FFFF);
    assert_eq!(constant_time_ge(0, u32::MAX), 0);
    assert_eq!(constant_time_ge(u32::MAX, u32::MAX), 0xFFFF_FFFF);
    assert_eq!(constant_time_ge(0, 0), 0xFFFF_FFFF);
}

// --- 8-bit greater-or-equal ---

#[test]
fn ge_8_true() {
    assert_eq!(constant_time_ge_8(5, 5), 0xFF);
}

#[test]
fn ge_8_false() {
    assert_eq!(constant_time_ge_8(3, 7), 0);
}

#[test]
fn ge_8_greater() {
    assert_eq!(constant_time_ge_8(7, 3), 0xFF);
}

// =============================================================================
// Phase 5: Is-Zero Tests
// From C constant_time_is_zero(): returns 0xFFFFFFFF if a == 0, else 0.
// =============================================================================

#[test]
fn is_zero_true() {
    assert_eq!(constant_time_is_zero(0), 0xFFFF_FFFF);
}

#[test]
fn is_zero_false_one() {
    assert_eq!(constant_time_is_zero(1), 0);
}

#[test]
fn is_zero_false_max() {
    assert_eq!(constant_time_is_zero(u32::MAX), 0);
}

#[test]
fn is_zero_false_high_bit() {
    assert_eq!(constant_time_is_zero(0x8000_0000), 0);
}

#[test]
fn is_zero_false_arbitrary() {
    assert_eq!(constant_time_is_zero(42), 0);
}

// --- 8-bit is-zero ---

#[test]
fn is_zero_8_true() {
    assert_eq!(constant_time_is_zero_8(0), 0xFF);
}

#[test]
fn is_zero_8_false() {
    assert_eq!(constant_time_is_zero_8(42), 0);
}

#[test]
fn is_zero_8_false_one() {
    assert_eq!(constant_time_is_zero_8(1), 0x00);
}

#[test]
fn is_zero_8_false_max() {
    assert_eq!(constant_time_is_zero_8(u32::MAX), 0x00);
}

// --- 32-bit alias ---

#[test]
fn is_zero_32_matches_is_zero() {
    assert_eq!(constant_time_is_zero_32(0), constant_time_is_zero(0));
    assert_eq!(constant_time_is_zero_32(1), constant_time_is_zero(1));
    assert_eq!(
        constant_time_is_zero_32(u32::MAX),
        constant_time_is_zero(u32::MAX)
    );
}

// =============================================================================
// Phase 6: Equality Tests
// From C constant_time_eq(): returns 0xFFFFFFFF if a == b, else 0.
// =============================================================================

#[test]
fn eq_true() {
    assert_eq!(constant_time_eq(42, 42), 0xFFFF_FFFF);
}

#[test]
fn eq_false() {
    assert_eq!(constant_time_eq(42, 43), 0);
}

#[test]
fn eq_zeros() {
    assert_eq!(constant_time_eq(0, 0), 0xFFFF_FFFF);
}

#[test]
fn eq_max_values() {
    assert_eq!(constant_time_eq(u32::MAX, u32::MAX), 0xFFFF_FFFF);
}

#[test]
fn eq_max_vs_zero() {
    assert_eq!(constant_time_eq(u32::MAX, 0), 0);
}

// --- 8-bit equality ---

#[test]
fn eq_8_true() {
    assert_eq!(constant_time_eq_8(42, 42), 0xFF);
}

#[test]
fn eq_8_false() {
    assert_eq!(constant_time_eq_8(42, 43), 0);
}

// --- Signed integer equality ---

#[test]
fn eq_int_true() {
    assert_eq!(constant_time_eq_int(42, 42), 0xFFFF_FFFF);
}

#[test]
fn eq_int_false() {
    // 42 != -42.
    assert_eq!(constant_time_eq_int(42, -42), 0);
}

#[test]
fn eq_int_negative() {
    assert_eq!(constant_time_eq_int(-1, -1), 0xFFFF_FFFF);
}

#[test]
fn eq_int_zeros() {
    assert_eq!(constant_time_eq_int(0, 0), 0xFFFF_FFFF);
}

#[test]
fn eq_int_min_values() {
    assert_eq!(constant_time_eq_int(i32::MIN, i32::MIN), 0xFFFF_FFFF);
}

#[test]
fn eq_int_min_vs_max() {
    assert_eq!(constant_time_eq_int(i32::MIN, i32::MAX), 0);
}

#[test]
fn eq_int_different_signs() {
    assert_eq!(constant_time_eq_int(-1, 1), 0);
}

// --- 8-bit signed equality ---

#[test]
fn eq_int_8_true() {
    assert_eq!(constant_time_eq_int_8(42, 42), 0xFF);
}

#[test]
fn eq_int_8_false() {
    assert_eq!(constant_time_eq_int_8(42, -42), 0);
}

#[test]
fn eq_int_8_negative_equal() {
    assert_eq!(constant_time_eq_int_8(-1, -1), 0xFF);
}

#[test]
fn eq_int_8_different_signs() {
    assert_eq!(constant_time_eq_int_8(-1, 1), 0x00);
}

// =============================================================================
// Phase 7: Selection Function Tests
// From C constant_time_select() lines 76-100: (mask & a) | (~mask & b).
// =============================================================================

#[test]
fn select_mask_all_ones() {
    // mask true → returns a.
    assert_eq!(constant_time_select(0xFFFF_FFFF, 10, 20), 10);
}

#[test]
fn select_mask_all_zeros() {
    // mask false → returns b.
    assert_eq!(constant_time_select(0, 10, 20), 20);
}

#[test]
fn select_extreme_values() {
    assert_eq!(constant_time_select(0xFFFF_FFFF, 0, u32::MAX), 0);
    assert_eq!(constant_time_select(0, 0, u32::MAX), u32::MAX);
}

// --- 8-bit select ---

#[test]
fn select_8_true() {
    assert_eq!(constant_time_select_8(0xFF, 0xAA, 0xBB), 0xAA);
}

#[test]
fn select_8_false() {
    assert_eq!(constant_time_select_8(0, 0xAA, 0xBB), 0xBB);
}

#[test]
fn select_8_zero_values() {
    assert_eq!(constant_time_select_8(0xFF, 0, 0xFF), 0);
    assert_eq!(constant_time_select_8(0, 0, 0xFF), 0xFF);
}

// --- 64-bit select ---

#[test]
fn select_64_true() {
    assert_eq!(constant_time_select_64(u64::MAX, 100, 200), 100);
}

#[test]
fn select_64_false() {
    assert_eq!(constant_time_select_64(0, 100, 200), 200);
}

#[test]
fn select_64_extreme_values() {
    assert_eq!(constant_time_select_64(u64::MAX, 0, u64::MAX), 0);
    assert_eq!(constant_time_select_64(0, 0, u64::MAX), u64::MAX);
}

// --- Signed integer select ---

#[test]
fn select_int_true() {
    assert_eq!(constant_time_select_int(0xFFFF_FFFF, -5, 10), -5);
}

#[test]
fn select_int_false() {
    assert_eq!(constant_time_select_int(0, -5, 10), 10);
}

#[test]
fn select_int_extreme_values() {
    assert_eq!(
        constant_time_select_int(0xFFFF_FFFF, i32::MIN, i32::MAX),
        i32::MIN
    );
    assert_eq!(
        constant_time_select_int(0, i32::MIN, i32::MAX),
        i32::MAX
    );
}

// --- Chained selection: use lt result as mask ---

#[test]
fn select_chained() {
    // Use constant_time_lt result as mask for constant_time_select.
    // 3 < 7 → mask is all ones → select returns first arg (100).
    let mask = constant_time_lt(3, 7);
    assert_eq!(constant_time_select(mask, 100, 200), 100);
}

#[test]
fn select_chained_false() {
    // 7 < 3 → mask is all zeros → select returns second arg (200).
    let mask = constant_time_lt(7, 3);
    assert_eq!(constant_time_select(mask, 100, 200), 200);
}

// =============================================================================
// Phase 8: Memory Comparison (memcmp) Tests
// Replaces CRYPTO_memcmp().
// =============================================================================

#[test]
fn memcmp_equal() {
    assert!(memcmp(&[1, 2, 3], &[1, 2, 3]));
}

#[test]
fn memcmp_different() {
    assert!(!memcmp(&[1, 2, 3], &[1, 2, 4]));
}

#[test]
fn memcmp_different_lengths() {
    assert!(!memcmp(&[1, 2, 3], &[1, 2]));
}

#[test]
fn memcmp_empty() {
    assert!(memcmp(&[], &[]));
}

#[test]
fn memcmp_single_byte_equal() {
    assert!(memcmp(&[0xFF], &[0xFF]));
}

#[test]
fn memcmp_single_byte_different() {
    assert!(!memcmp(&[0xFF], &[0xFE]));
}

#[test]
fn memcmp_all_zeros() {
    assert!(memcmp(&[0, 0, 0], &[0, 0, 0]));
}

#[test]
fn memcmp_differs_at_end() {
    // Ensures all bytes are checked — difference is in the last byte.
    assert!(!memcmp(&[1, 2, 3, 4, 5], &[1, 2, 3, 4, 6]));
}

#[test]
fn memcmp_large_equal() {
    assert!(memcmp(&[0xFF; 256], &[0xFF; 256]));
}

#[test]
fn memcmp_single_bit_difference() {
    let a = [0b1111_1111u8];
    let b = [0b1111_1110u8];
    assert!(!memcmp(&a, &b));
}

#[test]
fn memcmp_empty_vs_nonempty() {
    assert!(!memcmp(&[], &[0x00]));
}

// =============================================================================
// memcmp_choice — Choice-Returning Comparison
// =============================================================================

#[test]
fn memcmp_choice_equal() {
    let result = memcmp_choice(b"secret", b"secret");
    assert!(bool::from(result));
}

#[test]
fn memcmp_choice_unequal() {
    let result = memcmp_choice(b"secret", b"public");
    assert!(!bool::from(result));
}

#[test]
fn memcmp_choice_different_length_returns_false() {
    let result = memcmp_choice(b"ab", b"abc");
    assert!(!bool::from(result));
}

#[test]
fn memcmp_choice_empty_slices_equal() {
    let result = memcmp_choice(b"", b"");
    assert!(bool::from(result));
}

// =============================================================================
// constant_time_copy_if_choice — Conditional Byte Copy
// =============================================================================

#[test]
fn copy_if_choice_true_copies() {
    let src = [1u8, 2, 3, 4];
    let mut dst = [0u8; 4];
    constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
    assert_eq!(dst, [1, 2, 3, 4]);
}

#[test]
fn copy_if_choice_false_preserves_dst() {
    let src = [1u8, 2, 3, 4];
    let mut dst = [0xAA; 4];
    constant_time_copy_if_choice(Choice::from(0), &mut dst, &src);
    assert_eq!(dst, [0xAA; 4]);
}

#[test]
fn copy_if_choice_empty_slices() {
    let src: [u8; 0] = [];
    let mut dst: [u8; 0] = [];
    constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
    assert_eq!(dst.len(), 0);
}

#[test]
fn copy_if_choice_large_buffer() {
    let src: Vec<u8> = (0..=255).collect();
    let mut dst = vec![0u8; 256];
    constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
    assert_eq!(dst, src);
}

// =============================================================================
// Phase 9: Bitmask Pattern Validation Tests
// Verify that mask operations always produce all-ones or all-zeros, never
// partial bit patterns.
// =============================================================================

/// Helper: asserts a u32 mask is either all-ones or all-zeros.
fn assert_clean_mask_u32(mask: u32, context: &str) {
    assert!(
        mask == 0 || mask == 0xFFFF_FFFF,
        "Dirty mask detected in {context}: got {mask:#010X}, expected 0x00000000 or 0xFFFFFFFF"
    );
}

/// Helper: asserts a u64 mask is either all-ones or all-zeros.
fn assert_clean_mask_u64(mask: u64, context: &str) {
    assert!(
        mask == 0 || mask == u64::MAX,
        "Dirty mask detected in {context}: got {mask:#018X}"
    );
}

/// Helper: asserts a u8 mask is either 0xFF or 0x00.
fn assert_clean_mask_u8(mask: u8, context: &str) {
    assert!(
        mask == 0 || mask == 0xFF,
        "Dirty mask detected in {context}: got {mask:#04X}"
    );
}

/// Test values covering boundary conditions and typical ranges.
const TEST_VALUES_U32: &[u32] = &[
    0,
    1,
    2,
    42,
    127,
    128,
    255,
    256,
    1000,
    0x7FFF_FFFF,
    0x8000_0000,
    0x8000_0001,
    0xDEAD_BEEF,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
];

#[test]
fn mask_is_clean_lt() {
    // For various (a, b) pairs, verify constant_time_lt produces a clean mask.
    for &a in TEST_VALUES_U32 {
        for &b in TEST_VALUES_U32 {
            let mask = constant_time_lt(a, b);
            assert_clean_mask_u32(mask, &format!("constant_time_lt({a}, {b})"));

            // Also verify correctness: mask should be all-ones iff a < b.
            let expected = if a < b { 0xFFFF_FFFF } else { 0 };
            assert_eq!(
                mask, expected,
                "constant_time_lt({a}, {b}) = {mask:#010X}, expected {expected:#010X}"
            );
        }
    }
}

#[test]
fn mask_is_clean_ge() {
    for &a in TEST_VALUES_U32 {
        for &b in TEST_VALUES_U32 {
            let mask = constant_time_ge(a, b);
            assert_clean_mask_u32(mask, &format!("constant_time_ge({a}, {b})"));

            let expected = if a >= b { 0xFFFF_FFFF } else { 0 };
            assert_eq!(
                mask, expected,
                "constant_time_ge({a}, {b}) = {mask:#010X}, expected {expected:#010X}"
            );
        }
    }
}

#[test]
fn mask_is_clean_eq() {
    for &a in TEST_VALUES_U32 {
        for &b in TEST_VALUES_U32 {
            let mask = constant_time_eq(a, b);
            assert_clean_mask_u32(mask, &format!("constant_time_eq({a}, {b})"));

            let expected = if a == b { 0xFFFF_FFFF } else { 0 };
            assert_eq!(
                mask, expected,
                "constant_time_eq({a}, {b}) = {mask:#010X}, expected {expected:#010X}"
            );
        }
    }
}

#[test]
fn mask_is_clean_is_zero() {
    for &a in TEST_VALUES_U32 {
        let mask = constant_time_is_zero(a);
        assert_clean_mask_u32(mask, &format!("constant_time_is_zero({a})"));

        let expected = if a == 0 { 0xFFFF_FFFF } else { 0 };
        assert_eq!(
            mask, expected,
            "constant_time_is_zero({a}) = {mask:#010X}, expected {expected:#010X}"
        );
    }
}

#[test]
fn comprehensive_lt_ge_inverse() {
    // For a range of (a, b) values, verify that constant_time_lt(a, b) is
    // the bitwise complement of constant_time_ge(a, b).
    for &a in TEST_VALUES_U32 {
        for &b in TEST_VALUES_U32 {
            let lt_mask = constant_time_lt(a, b);
            let ge_mask = constant_time_ge(a, b);

            assert_eq!(
                lt_mask, !ge_mask,
                "lt/ge inverse violated for ({a}, {b}): lt={lt_mask:#010X}, ge={ge_mask:#010X}"
            );
        }
    }
}

#[test]
fn mask_is_clean_msb() {
    // Verify constant_time_msb produces clean masks for all test values.
    for &a in TEST_VALUES_U32 {
        let mask = constant_time_msb(a);
        assert_clean_mask_u32(mask, &format!("constant_time_msb({a})"));
    }
}

#[test]
fn mask_is_clean_lt_8() {
    // 8-bit variant: verify masks are 0xFF or 0x00.
    for &a in TEST_VALUES_U32 {
        for &b in TEST_VALUES_U32 {
            let mask = constant_time_lt_8(a, b);
            assert_clean_mask_u8(mask, &format!("constant_time_lt_8({a}, {b})"));
        }
    }
}

#[test]
fn mask_is_clean_lt_64() {
    // 64-bit variant: verify masks are u64::MAX or 0.
    let test_values_u64: &[u64] = &[0, 1, 42, u64::MAX / 2, u64::MAX - 1, u64::MAX];
    for &a in test_values_u64 {
        for &b in test_values_u64 {
            let mask = constant_time_lt_64(a, b);
            assert_clean_mask_u64(mask, &format!("constant_time_lt_64({a}, {b})"));
        }
    }
}

// =============================================================================
// Integration Tests: Common Cryptographic Patterns
// =============================================================================

#[test]
fn lt_and_select_pattern_minimum() {
    // Use constant-time primitives to find the minimum of two values
    // without branching — a common cryptographic pattern.
    let a: u32 = 42;
    let b: u32 = 99;
    let mask = constant_time_lt(a, b); // 0xFFFF_FFFF because a < b
    let min_val = constant_time_select(mask, a, b);
    assert_eq!(min_val, 42);

    let mask2 = constant_time_lt(b, a); // 0 because b > a
    let min_val2 = constant_time_select(mask2, b, a);
    assert_eq!(min_val2, 42);
}

#[test]
fn eq_and_select_pattern_conditional_swap() {
    // Conditional swap: if values are equal, return first; otherwise second.
    let a = 10u32;
    let b = 20u32;
    let mask = constant_time_eq(a, b); // 0 because a != b
    let result = constant_time_select(mask, a, b);
    assert_eq!(result, b); // selects b when not equal
}

#[test]
fn ge_and_select_clamp() {
    // Clamp a value: if val >= threshold, use threshold; else use val.
    let val: u32 = 200;
    let threshold: u32 = 100;
    let mask = constant_time_ge(val, threshold); // all ones: val >= threshold
    let clamped = constant_time_select(mask, threshold, val);
    assert_eq!(clamped, 100);

    let val2: u32 = 50;
    let mask2 = constant_time_ge(val2, threshold); // all zeros: val2 < threshold
    let clamped2 = constant_time_select(mask2, threshold, val2);
    assert_eq!(clamped2, 50);
}

#[test]
fn is_zero_and_select_default_value() {
    // Use is_zero to select a default value when the input is zero.
    let input: u32 = 0;
    let default_val: u32 = 42;
    let mask = constant_time_is_zero(input); // all ones: input is zero
    let result = constant_time_select(mask, default_val, input);
    assert_eq!(result, 42);

    let input2: u32 = 7;
    let mask2 = constant_time_is_zero(input2); // all zeros: input is nonzero
    let result2 = constant_time_select(mask2, default_val, input2);
    assert_eq!(result2, 7);
}

#[test]
fn eq_int_mixed_positive_negative() {
    // Verify signed equality across a range of values.
    let test_pairs: &[(i32, i32, u32)] = &[
        (0, 0, 0xFFFF_FFFF),
        (1, 1, 0xFFFF_FFFF),
        (-1, -1, 0xFFFF_FFFF),
        (i32::MIN, i32::MIN, 0xFFFF_FFFF),
        (i32::MAX, i32::MAX, 0xFFFF_FFFF),
        (1, -1, 0),
        (0, 1, 0),
        (i32::MIN, i32::MAX, 0),
        (42, -42, 0),
    ];
    for &(a, b, expected) in test_pairs {
        assert_eq!(
            constant_time_eq_int(a, b),
            expected,
            "constant_time_eq_int({a}, {b})"
        );
    }
}

#[test]
fn select_64_chained_with_lt_64() {
    // Use 64-bit lt result as mask for 64-bit select.
    let a: u64 = 100;
    let b: u64 = 200;
    let mask = constant_time_lt_64(a, b); // a < b → all ones
    let result = constant_time_select_64(mask, a, b);
    assert_eq!(result, 100);
}

#[test]
fn memcmp_and_eq_consistency() {
    // Verify memcmp and constant_time_eq produce consistent results for
    // single-element byte slices.
    let a_val: u32 = 42;
    let b_val: u32 = 42;
    let eq_mask = constant_time_eq(a_val, b_val);
    let a_bytes = a_val.to_ne_bytes();
    let b_bytes = b_val.to_ne_bytes();
    let mem_result = memcmp(&a_bytes, &b_bytes);

    // Both should indicate equality.
    assert_eq!(eq_mask, 0xFFFF_FFFF);
    assert!(mem_result);
}
