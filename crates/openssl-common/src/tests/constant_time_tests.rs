//! Tests for the `openssl_common::constant_time` module.
//!
//! Exercises the constant-time comparison, selection, and memory operations
//! through the crate's public API. Complements the inline unit tests in
//! `constant_time.rs` with additional edge-case coverage and API-level
//! integration tests.

use crate::constant_time::{
    constant_time_copy_if_choice, constant_time_eq, constant_time_eq_8, constant_time_eq_int,
    constant_time_eq_int_8, constant_time_ge, constant_time_ge_8, constant_time_is_zero,
    constant_time_is_zero_32, constant_time_is_zero_8, constant_time_lt, constant_time_lt_64,
    constant_time_lt_8, constant_time_msb, constant_time_msb_64, constant_time_select,
    constant_time_select_64, constant_time_select_8, constant_time_select_int, memcmp,
    memcmp_choice, Choice,
};

// =============================================================================
// constant_time_msb — 32-bit MSB Propagation
// =============================================================================

#[test]
fn msb_set_returns_all_ones() {
    assert_eq!(constant_time_msb(0x8000_0000), 0xFFFF_FFFF);
    assert_eq!(constant_time_msb(0xFFFF_FFFF), 0xFFFF_FFFF);
    assert_eq!(constant_time_msb(0x8000_0001), 0xFFFF_FFFF);
    assert_eq!(constant_time_msb(0xDEAD_BEEF), 0xFFFF_FFFF);
}

#[test]
fn msb_clear_returns_zero() {
    assert_eq!(constant_time_msb(0), 0);
    assert_eq!(constant_time_msb(1), 0);
    assert_eq!(constant_time_msb(0x7FFF_FFFF), 0);
    assert_eq!(constant_time_msb(0x4000_0000), 0);
}

// =============================================================================
// constant_time_msb_64 — 64-bit MSB Propagation
// =============================================================================

#[test]
fn msb_64_set_returns_all_ones() {
    assert_eq!(constant_time_msb_64(0x8000_0000_0000_0000), u64::MAX);
    assert_eq!(constant_time_msb_64(u64::MAX), u64::MAX);
}

#[test]
fn msb_64_clear_returns_zero() {
    assert_eq!(constant_time_msb_64(0), 0);
    assert_eq!(constant_time_msb_64(0x7FFF_FFFF_FFFF_FFFF), 0);
    assert_eq!(constant_time_msb_64(1), 0);
}

// =============================================================================
// constant_time_lt — 32-bit Less-Than
// =============================================================================

#[test]
fn lt_basic_cases() {
    assert_eq!(constant_time_lt(0, 1), 0xFFFF_FFFF);
    assert_eq!(constant_time_lt(3, 5), 0xFFFF_FFFF);
    assert_eq!(constant_time_lt(5, 3), 0);
    assert_eq!(constant_time_lt(5, 5), 0); // equal → not less
}

#[test]
fn lt_boundary_values() {
    assert_eq!(constant_time_lt(0, u32::MAX), 0xFFFF_FFFF);
    assert_eq!(constant_time_lt(u32::MAX - 1, u32::MAX), 0xFFFF_FFFF);
    assert_eq!(constant_time_lt(u32::MAX, 0), 0);
    assert_eq!(constant_time_lt(u32::MAX, u32::MAX), 0);
}

// =============================================================================
// constant_time_lt_64 — 64-bit Less-Than
// =============================================================================

#[test]
fn lt_64_basic_cases() {
    assert_eq!(constant_time_lt_64(3, 5), u64::MAX);
    assert_eq!(constant_time_lt_64(5, 3), 0);
    assert_eq!(constant_time_lt_64(5, 5), 0);
}

#[test]
fn lt_64_boundary_values() {
    assert_eq!(constant_time_lt_64(0, u64::MAX), u64::MAX);
    assert_eq!(constant_time_lt_64(u64::MAX, 0), 0);
    assert_eq!(constant_time_lt_64(u64::MAX - 1, u64::MAX), u64::MAX);
}

// =============================================================================
// constant_time_ge — 32-bit Greater-or-Equal
// =============================================================================

#[test]
fn ge_basic_cases() {
    assert_eq!(constant_time_ge(5, 3), 0xFFFF_FFFF);
    assert_eq!(constant_time_ge(5, 5), 0xFFFF_FFFF); // equal → true
    assert_eq!(constant_time_ge(3, 5), 0);
    assert_eq!(constant_time_ge(0, 0), 0xFFFF_FFFF);
}

#[test]
fn ge_boundary_values() {
    assert_eq!(constant_time_ge(u32::MAX, 0), 0xFFFF_FFFF);
    assert_eq!(constant_time_ge(0, u32::MAX), 0);
    assert_eq!(constant_time_ge(u32::MAX, u32::MAX), 0xFFFF_FFFF);
}

// =============================================================================
// constant_time_is_zero — 32-bit Zero Test
// =============================================================================

#[test]
fn is_zero_true_for_zero() {
    assert_eq!(constant_time_is_zero(0), 0xFFFF_FFFF);
}

#[test]
fn is_zero_false_for_nonzero() {
    assert_eq!(constant_time_is_zero(1), 0);
    assert_eq!(constant_time_is_zero(42), 0);
    assert_eq!(constant_time_is_zero(u32::MAX), 0);
    assert_eq!(constant_time_is_zero(0x8000_0000), 0);
}

// =============================================================================
// constant_time_is_zero_32 — Alias
// =============================================================================

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
// constant_time_eq — 32-bit Equality
// =============================================================================

#[test]
fn eq_equal_values() {
    assert_eq!(constant_time_eq(0, 0), 0xFFFF_FFFF);
    assert_eq!(constant_time_eq(42, 42), 0xFFFF_FFFF);
    assert_eq!(constant_time_eq(u32::MAX, u32::MAX), 0xFFFF_FFFF);
}

#[test]
fn eq_unequal_values() {
    assert_eq!(constant_time_eq(0, 1), 0);
    assert_eq!(constant_time_eq(42, 43), 0);
    assert_eq!(constant_time_eq(u32::MAX, 0), 0);
}

// =============================================================================
// constant_time_eq_int — Signed 32-bit Equality
// =============================================================================

#[test]
fn eq_int_positive_equal() {
    assert_eq!(constant_time_eq_int(42, 42), 0xFFFF_FFFF);
    assert_eq!(constant_time_eq_int(0, 0), 0xFFFF_FFFF);
}

#[test]
fn eq_int_negative_equal() {
    assert_eq!(constant_time_eq_int(-1, -1), 0xFFFF_FFFF);
    assert_eq!(constant_time_eq_int(i32::MIN, i32::MIN), 0xFFFF_FFFF);
}

#[test]
fn eq_int_different_signs() {
    assert_eq!(constant_time_eq_int(-1, 1), 0);
    assert_eq!(constant_time_eq_int(i32::MIN, i32::MAX), 0);
}

// =============================================================================
// constant_time_select — Conditional Value Selection
// =============================================================================

#[test]
fn select_mask_all_ones_returns_a() {
    assert_eq!(constant_time_select(0xFFFF_FFFF, 100, 200), 100);
    assert_eq!(constant_time_select(0xFFFF_FFFF, 0, u32::MAX), 0);
}

#[test]
fn select_mask_zero_returns_b() {
    assert_eq!(constant_time_select(0, 100, 200), 200);
    assert_eq!(constant_time_select(0, 0, u32::MAX), u32::MAX);
}

// =============================================================================
// constant_time_select_8 — 8-bit Selection
// =============================================================================

#[test]
fn select_8_mask_ff_returns_a() {
    assert_eq!(constant_time_select_8(0xFF, 0xAA, 0xBB), 0xAA);
}

#[test]
fn select_8_mask_00_returns_b() {
    assert_eq!(constant_time_select_8(0x00, 0xAA, 0xBB), 0xBB);
}

// =============================================================================
// constant_time_select_64 — 64-bit Selection
// =============================================================================

#[test]
fn select_64_mask_all_ones_returns_a() {
    assert_eq!(constant_time_select_64(u64::MAX, 100, 200), 100);
}

#[test]
fn select_64_mask_zero_returns_b() {
    assert_eq!(constant_time_select_64(0, 100, 200), 200);
}

// =============================================================================
// constant_time_select_int — Signed Integer Selection
// =============================================================================

#[test]
fn select_int_positive_and_negative() {
    assert_eq!(constant_time_select_int(0xFFFF_FFFF, -10, 20), -10);
    assert_eq!(constant_time_select_int(0, -10, 20), 20);
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

// =============================================================================
// 8-bit Wrappers
// =============================================================================

#[test]
fn lt_8_returns_correct_byte_masks() {
    assert_eq!(constant_time_lt_8(3, 5), 0xFF);
    assert_eq!(constant_time_lt_8(5, 3), 0x00);
    assert_eq!(constant_time_lt_8(5, 5), 0x00);
}

#[test]
fn ge_8_returns_correct_byte_masks() {
    assert_eq!(constant_time_ge_8(5, 3), 0xFF);
    assert_eq!(constant_time_ge_8(5, 5), 0xFF);
    assert_eq!(constant_time_ge_8(3, 5), 0x00);
}

#[test]
fn is_zero_8_returns_correct_byte_masks() {
    assert_eq!(constant_time_is_zero_8(0), 0xFF);
    assert_eq!(constant_time_is_zero_8(1), 0x00);
    assert_eq!(constant_time_is_zero_8(u32::MAX), 0x00);
}

#[test]
fn eq_8_returns_correct_byte_masks() {
    assert_eq!(constant_time_eq_8(42, 42), 0xFF);
    assert_eq!(constant_time_eq_8(42, 43), 0x00);
}

#[test]
fn eq_int_8_returns_correct_byte_masks() {
    assert_eq!(constant_time_eq_int_8(-1, -1), 0xFF);
    assert_eq!(constant_time_eq_int_8(-1, 1), 0x00);
}

// =============================================================================
// memcmp — Constant-Time Memory Comparison
// =============================================================================

#[test]
fn memcmp_equal_slices() {
    assert!(memcmp(b"hello", b"hello"));
    assert!(memcmp(b"", b""));
    assert!(memcmp(&[0xFF; 256], &[0xFF; 256]));
}

#[test]
fn memcmp_unequal_same_length() {
    assert!(!memcmp(b"hello", b"world"));
    assert!(!memcmp(b"hello", b"hellp"));
    assert!(!memcmp(&[0x00], &[0x01]));
}

#[test]
fn memcmp_different_lengths() {
    assert!(!memcmp(b"short", b"longer"));
    assert!(!memcmp(b"abc", b"ab"));
    assert!(!memcmp(b"", b"x"));
}

#[test]
fn memcmp_single_bit_difference() {
    let a = [0b1111_1111u8];
    let b = [0b1111_1110u8];
    assert!(!memcmp(&a, &b));
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
// Integration: lt + select pattern (common crypto pattern)
// =============================================================================

#[test]
fn lt_and_select_pattern_minimum() {
    // Use constant-time primitives to find the minimum of two values
    // without branching, mimicking a common cryptographic pattern.
    let a: u32 = 42;
    let b: u32 = 99;
    let mask = constant_time_lt(a, b); // 0xFFFF_FFFF if a < b
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
