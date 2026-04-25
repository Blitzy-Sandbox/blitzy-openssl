//! Constant-time comparison and selection primitives for cryptographic operations.
//!
//! Wraps the [`subtle`] crate to provide API-compatible replacements for the C
//! `constant_time_*` functions from `include/internal/constant_time.h`.
//!
//! # Design
//!
//! The boolean methods return a bitmask of all ones (`0xFFFF_FFFF` for [`u32`],
//! `0xFFFF_FFFF_FFFF_FFFF` for [`u64`], `0xFF` for [`u8`]) for **true** and `0`
//! for **false**. This is useful for choosing a value based on the result of a
//! conditional in constant time. For example:
//!
//! ```
//! use openssl_common::constant_time::{constant_time_lt, constant_time_select};
//!
//! let lt = constant_time_lt(3, 5);
//! let c = constant_time_select(lt, 3, 5);
//! assert_eq!(c, 3); // 3 < 5, so lt is all-ones, select returns first argument
//! ```
//!
//! # Timing Safety
//!
//! All functions in this module execute in constant time with respect to their
//! inputs. Selection and comparison functions use value barriers (via
//! [`core::hint::black_box`]) to prevent compiler optimizations that could
//! introduce timing side-channels.
//!
//! Memory comparison uses [`subtle::ConstantTimeEq`] to ensure byte-by-byte
//! comparison without early exit.
//!
//! # Safety
//!
//! This module contains zero `unsafe` code (Rule R8). All constant-time operations
//! are implemented using the [`subtle`] crate's safe abstractions or through
//! wrapping arithmetic that Rust performs safely.
//!
//! # Source Reference
//!
//! Translated from `include/internal/constant_time.h` (OpenSSL 4.0, 480 lines).

use subtle::{ConditionallySelectable, ConstantTimeEq};

// Re-export subtle types used in public API signatures so that callers
// do not need a direct `subtle` dependency to work with this module's API.
pub use subtle::{Choice, CtOption};

// ===========================================================================
// Value barrier — prevents the compiler from optimizing away constant-time
// properties by observing that `mask` and `!mask` are complementary.
// Equivalent to the C `value_barrier()` using inline assembly or volatile.
// ===========================================================================

/// Prevents compiler optimizations on the given `u32` value.
///
/// This is the Rust equivalent of the C `value_barrier()` function which uses
/// inline assembly or volatile reads to prevent the compiler from deducing
/// that `mask` and `!mask` are complements and optimizing the constant-time
/// select into a conditional branch.
#[inline]
fn value_barrier_u32(a: u32) -> u32 {
    core::hint::black_box(a)
}

/// Prevents compiler optimizations on the given `u64` value.
///
/// 64-bit equivalent of [`value_barrier_u32`].
#[inline]
fn value_barrier_u64(a: u64) -> u64 {
    core::hint::black_box(a)
}

// ===========================================================================
// Core Functions — 32-bit bitmask operations
// ===========================================================================

/// Returns the given value with the MSB copied to all other bits.
///
/// If the most significant bit of `a` is set, returns `0xFFFF_FFFF` (all ones).
/// Otherwise returns `0x0000_0000`.
///
/// This is the Rust equivalent of:
/// ```c
/// unsigned int constant_time_msb(unsigned int a) {
///     return 0 - (a >> (sizeof(a) * 8 - 1));
/// }
/// ```
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_msb;
///
/// assert_eq!(constant_time_msb(0x8000_0000), 0xFFFF_FFFF);
/// assert_eq!(constant_time_msb(0x7FFF_FFFF), 0x0000_0000);
/// assert_eq!(constant_time_msb(0), 0);
/// ```
#[inline]
pub fn constant_time_msb(a: u32) -> u32 {
    // Shift MSB to bit 0 (logical right shift on unsigned), then negate.
    // If MSB was 1: 0u32 - 1 = 0xFFFF_FFFF (wrapping).
    // If MSB was 0: 0u32 - 0 = 0x0000_0000.
    0u32.wrapping_sub(a >> 31)
}

/// Returns `0xFFFF_FFFF` if `a < b` in constant time, `0` otherwise.
///
/// Uses the bitmask technique from the C implementation:
/// `constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)))`.
///
/// The expression works by extracting the borrow bit from `a - b` through
/// XOR operations, producing a result with MSB set if and only if `a < b`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_lt;
///
/// assert_eq!(constant_time_lt(3, 5), 0xFFFF_FFFF);
/// assert_eq!(constant_time_lt(5, 3), 0);
/// assert_eq!(constant_time_lt(5, 5), 0);
/// ```
#[inline]
pub fn constant_time_lt(a: u32, b: u32) -> u32 {
    // Wrapping subtraction handles the case where a < b (underflow produces
    // a large value with MSB set after the XOR chain).
    constant_time_msb(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)))
}

/// Returns `0xFFFF_FFFF` if `a >= b` in constant time, `0` otherwise.
///
/// Equivalent to the bitwise complement of [`constant_time_lt`].
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_ge;
///
/// assert_eq!(constant_time_ge(5, 3), 0xFFFF_FFFF);
/// assert_eq!(constant_time_ge(5, 5), 0xFFFF_FFFF);
/// assert_eq!(constant_time_ge(3, 5), 0);
/// ```
#[inline]
pub fn constant_time_ge(a: u32, b: u32) -> u32 {
    !constant_time_lt(a, b)
}

/// Returns `0xFFFF_FFFF` if `a == 0` in constant time, `0` otherwise.
///
/// Uses the bitmask technique: `constant_time_msb(!a & (a - 1))`.
///
/// When `a` is 0: `!0 = 0xFFFF_FFFF` and `0 - 1 = 0xFFFF_FFFF` (wrapping),
/// so `!a & (a-1) = 0xFFFF_FFFF` which has MSB set, producing all-ones.
///
/// For any non-zero `a`, the MSB of `!a & (a-1)` is always 0.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_is_zero;
///
/// assert_eq!(constant_time_is_zero(0), 0xFFFF_FFFF);
/// assert_eq!(constant_time_is_zero(1), 0);
/// assert_eq!(constant_time_is_zero(42), 0);
/// ```
#[inline]
pub fn constant_time_is_zero(a: u32) -> u32 {
    constant_time_msb(!a & a.wrapping_sub(1))
}

/// Returns `0xFFFF_FFFF` if `a == b` in constant time, `0` otherwise.
///
/// Computed as `constant_time_is_zero(a ^ b)` — if `a` and `b` are equal,
/// their XOR is zero.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_eq;
///
/// assert_eq!(constant_time_eq(42, 42), 0xFFFF_FFFF);
/// assert_eq!(constant_time_eq(42, 43), 0);
/// ```
#[inline]
pub fn constant_time_eq(a: u32, b: u32) -> u32 {
    constant_time_is_zero(a ^ b)
}

/// Returns `0xFFFF_FFFF` if `a == b` in constant time for signed integers,
/// `0` otherwise.
///
/// Performs bitwise reinterpretation to unsigned and delegates to
/// [`constant_time_eq`]. This matches the C behavior of
/// `constant_time_eq_int(int a, int b)` which casts both operands to
/// `unsigned int`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_eq_int;
///
/// assert_eq!(constant_time_eq_int(-1, -1), 0xFFFF_FFFF);
/// assert_eq!(constant_time_eq_int(1, -1), 0);
/// ```
#[inline]
pub fn constant_time_eq_int(a: i32, b: i32) -> u32 {
    // Bitwise reinterpretation from i32 to u32 via byte round-trip.
    // Avoids `as u32` which triggers clippy::cast_sign_loss (Rule R6).
    let a_unsigned = u32::from_ne_bytes(a.to_ne_bytes());
    let b_unsigned = u32::from_ne_bytes(b.to_ne_bytes());
    constant_time_eq(a_unsigned, b_unsigned)
}

// ===========================================================================
// Selection Functions — constant-time conditional value selection
// ===========================================================================

/// Returns `a` if `mask` is all ones, `b` if `mask` is all zeros.
///
/// Computes `(mask & a) | (~mask & b)` with a value barrier to prevent the
/// compiler from recognizing the complementary mask pattern and introducing
/// a branch.
///
/// # Preconditions
///
/// `mask` must be either `0xFFFF_FFFF` (all ones) or `0x0000_0000` (all zeros).
/// Values produced by the comparison functions in this module satisfy this
/// requirement.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::{constant_time_lt, constant_time_select};
///
/// let mask = constant_time_lt(3, 5); // all ones
/// assert_eq!(constant_time_select(mask, 10, 20), 10);
///
/// let mask = constant_time_lt(5, 3); // all zeros
/// assert_eq!(constant_time_select(mask, 10, 20), 20);
/// ```
#[inline]
pub fn constant_time_select(mask: u32, a: u32, b: u32) -> u32 {
    (value_barrier_u32(mask) & a) | (value_barrier_u32(!mask) & b)
}

/// 8-bit version of [`constant_time_select`].
///
/// Widens inputs to [`u32`], performs the selection, and extracts the low byte
/// from the result. This matches the C implementation which casts through
/// `unsigned int`.
///
/// # Preconditions
///
/// `mask` must be either `0xFF` or `0x00`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_select_8;
///
/// assert_eq!(constant_time_select_8(0xFF, 0xAA, 0xBB), 0xAA);
/// assert_eq!(constant_time_select_8(0x00, 0xAA, 0xBB), 0xBB);
/// ```
#[inline]
pub fn constant_time_select_8(mask: u8, a: u8, b: u8) -> u8 {
    // Widen to u32 for the select operation. When both `a` and `b` originate
    // from u8, the upper 24 bits are zero, so extracting the low byte of the
    // u32 result recovers the correct u8 value without information loss.
    let result = constant_time_select(u32::from(mask), u32::from(a), u32::from(b));
    // Extract low byte via to_le_bytes() to avoid a narrowing `as u8` cast
    // that would trigger clippy::cast_possible_truncation (Rule R6).
    result.to_le_bytes()[0]
}

/// 64-bit version of [`constant_time_select`].
///
/// Returns `a` if `mask` is all ones (`0xFFFF_FFFF_FFFF_FFFF`), `b` if all
/// zeros.
///
/// # Preconditions
///
/// `mask` must be `0xFFFF_FFFF_FFFF_FFFF` or `0x0000_0000_0000_0000`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_select_64;
///
/// assert_eq!(constant_time_select_64(u64::MAX, 100, 200), 100);
/// assert_eq!(constant_time_select_64(0, 100, 200), 200);
/// ```
#[inline]
pub fn constant_time_select_64(mask: u64, a: u64, b: u64) -> u64 {
    (value_barrier_u64(mask) & a) | (value_barrier_u64(!mask) & b)
}

/// Signed integer version of [`constant_time_select`].
///
/// Reinterprets [`i32`] values as [`u32`] for the selection operation, then
/// reinterprets the result back to [`i32`]. This matches the C implementation:
/// ```c
/// return (int)constant_time_select(mask, (unsigned)(a), (unsigned)(b));
/// ```
///
/// # Preconditions
///
/// `mask` must be either `0xFFFF_FFFF` or `0x0000_0000`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_select_int;
///
/// assert_eq!(constant_time_select_int(0xFFFF_FFFF, -10, 20), -10);
/// assert_eq!(constant_time_select_int(0, -10, 20), 20);
/// ```
#[inline]
pub fn constant_time_select_int(mask: u32, a: i32, b: i32) -> i32 {
    // Bitwise reinterpretation via byte round-trip to avoid cast lints (Rule R6).
    let a_unsigned = u32::from_ne_bytes(a.to_ne_bytes());
    let b_unsigned = u32::from_ne_bytes(b.to_ne_bytes());
    let result = constant_time_select(mask, a_unsigned, b_unsigned);
    i32::from_ne_bytes(result.to_ne_bytes())
}

// ===========================================================================
// Memory Comparison — CRYPTO_memcmp equivalent
// ===========================================================================

/// Constant-time memory comparison.
///
/// Returns `true` if slices `a` and `b` are equal in both length and content.
/// Returns `false` if they differ in content or have different lengths.
///
/// Uses [`subtle::ConstantTimeEq`] internally to ensure the comparison does not
/// short-circuit on the first differing byte. This replaces `CRYPTO_memcmp()`
/// from the C codebase.
///
/// # Note on Length Comparison
///
/// The length comparison is **not** constant-time. Buffer lengths are typically
/// not secret data, matching the C `CRYPTO_memcmp()` semantics where the length
/// parameter is public.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::memcmp;
///
/// assert!(memcmp(b"hello", b"hello"));
/// assert!(!memcmp(b"hello", b"world"));
/// assert!(!memcmp(b"short", b"longer"));
/// ```
#[inline]
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // subtle::ConstantTimeEq::ct_eq for &[u8] performs byte-by-byte
    // constant-time comparison and requires equal-length slices.
    bool::from(a.ct_eq(b))
}

/// Constant-time memory comparison returning a [`Choice`].
///
/// Returns `Choice::from(1)` if slices are equal in both length and content,
/// `Choice::from(0)` otherwise. The [`Choice`] type can be used directly in
/// conditional selection chains without converting to `bool`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::memcmp_choice;
///
/// let result = memcmp_choice(b"secret", b"secret");
/// assert_eq!(bool::from(result), true);
///
/// let result = memcmp_choice(b"secret", b"public");
/// assert_eq!(bool::from(result), false);
/// ```
#[inline]
pub fn memcmp_choice(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0);
    }
    a.ct_eq(b)
}

// ===========================================================================
// 8-bit Convenience Wrappers
// ===========================================================================
// These match the C `*_8` variants that return `unsigned char` masks
// (0xFF for true, 0x00 for false).

/// Returns `0xFF` if `a < b`, `0x00` otherwise.
///
/// 8-bit convenience wrapper around [`constant_time_lt`]. The result of the
/// 32-bit comparison (either `0xFFFF_FFFF` or `0x0000_0000`) is truncated
/// to the low byte, yielding `0xFF` or `0x00`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_lt_8;
///
/// assert_eq!(constant_time_lt_8(3, 5), 0xFF);
/// assert_eq!(constant_time_lt_8(5, 3), 0x00);
/// ```
#[inline]
pub fn constant_time_lt_8(a: u32, b: u32) -> u8 {
    // Extract the low byte via to_le_bytes() to avoid a narrowing `as u8` cast.
    // The source value is either 0xFFFF_FFFF or 0x0000_0000, so the low byte
    // is either 0xFF or 0x00, making this truncation lossless.
    constant_time_lt(a, b).to_le_bytes()[0]
}

/// Returns `0xFF` if `a >= b`, `0x00` otherwise.
///
/// 8-bit convenience wrapper around [`constant_time_ge`].
#[inline]
pub fn constant_time_ge_8(a: u32, b: u32) -> u8 {
    constant_time_ge(a, b).to_le_bytes()[0]
}

/// Returns `0xFF` if `a == 0`, `0x00` otherwise.
///
/// 8-bit convenience wrapper around [`constant_time_is_zero`].
#[inline]
pub fn constant_time_is_zero_8(a: u32) -> u8 {
    constant_time_is_zero(a).to_le_bytes()[0]
}

/// Returns `0xFF` if `a == b`, `0x00` otherwise.
///
/// 8-bit convenience wrapper around [`constant_time_eq`].
#[inline]
pub fn constant_time_eq_8(a: u32, b: u32) -> u8 {
    constant_time_eq(a, b).to_le_bytes()[0]
}

/// Returns `0xFF` if `a == b`, `0x00` otherwise (signed variant).
///
/// 8-bit convenience wrapper around [`constant_time_eq_int`].
#[inline]
pub fn constant_time_eq_int_8(a: i32, b: i32) -> u8 {
    constant_time_eq_int(a, b).to_le_bytes()[0]
}

// ===========================================================================
// 64-bit Variants
// ===========================================================================

/// Returns the given 64-bit value with the MSB copied to all other bits.
///
/// If the most significant bit of `a` is set, returns
/// `0xFFFF_FFFF_FFFF_FFFF`. Otherwise returns `0`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_msb_64;
///
/// assert_eq!(constant_time_msb_64(0x8000_0000_0000_0000), u64::MAX);
/// assert_eq!(constant_time_msb_64(0x7FFF_FFFF_FFFF_FFFF), 0);
/// assert_eq!(constant_time_msb_64(0), 0);
/// ```
#[inline]
pub fn constant_time_msb_64(a: u64) -> u64 {
    0u64.wrapping_sub(a >> 63)
}

/// Returns `0xFFFF_FFFF_FFFF_FFFF` if `a < b` in constant time, `0` otherwise.
///
/// 64-bit version of [`constant_time_lt`] using the same bitmask technique.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_lt_64;
///
/// assert_eq!(constant_time_lt_64(3, 5), u64::MAX);
/// assert_eq!(constant_time_lt_64(5, 3), 0);
/// assert_eq!(constant_time_lt_64(5, 5), 0);
/// ```
#[inline]
pub fn constant_time_lt_64(a: u64, b: u64) -> u64 {
    constant_time_msb_64(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)))
}

/// Returns `0xFFFF_FFFF_FFFF_FFFF` if `a >= b` in constant time, `0` otherwise.
///
/// 64-bit version of [`constant_time_ge`]. Equivalent to the bitwise complement
/// of [`constant_time_lt_64`].
///
/// This is the Rust equivalent of the C `constant_time_ge_s(size_t, size_t)`
/// when `size_t` is 64-bit (the typical case on modern platforms). Used by the
/// Lucky13 padding-oracle defense (RFC 5246 §6.2.3.2, CVE-2013-0169).
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_ge_64;
///
/// assert_eq!(constant_time_ge_64(5, 3), u64::MAX);
/// assert_eq!(constant_time_ge_64(5, 5), u64::MAX);
/// assert_eq!(constant_time_ge_64(3, 5), 0);
/// ```
#[inline]
pub fn constant_time_ge_64(a: u64, b: u64) -> u64 {
    !constant_time_lt_64(a, b)
}

/// Returns `0xFFFF_FFFF_FFFF_FFFF` if `a == 0` in constant time, `0` otherwise.
///
/// 64-bit version of [`constant_time_is_zero`] using the same bitmask
/// technique: `constant_time_msb_64(!a & (a - 1))`.
///
/// When `a` is 0: `!0u64 = u64::MAX` and `0 - 1 = u64::MAX` (wrapping), so
/// `!a & (a-1) = u64::MAX` which has MSB set, producing all-ones.
///
/// For any non-zero `a`, the MSB of `!a & (a-1)` is always 0.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_is_zero_64;
///
/// assert_eq!(constant_time_is_zero_64(0), u64::MAX);
/// assert_eq!(constant_time_is_zero_64(1), 0);
/// assert_eq!(constant_time_is_zero_64(u64::MAX), 0);
/// ```
#[inline]
pub fn constant_time_is_zero_64(a: u64) -> u64 {
    constant_time_msb_64(!a & a.wrapping_sub(1))
}

/// Returns `0xFFFF_FFFF_FFFF_FFFF` if `a == b` in constant time, `0` otherwise.
///
/// 64-bit version of [`constant_time_eq`]. Computed as
/// `constant_time_is_zero_64(a ^ b)` — if `a` and `b` are equal, their XOR is
/// zero.
///
/// This is the Rust equivalent of the C `constant_time_eq_s(size_t, size_t)`
/// when `size_t` is 64-bit. Used by the Lucky13 padding-oracle defense.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_eq_64;
///
/// assert_eq!(constant_time_eq_64(42, 42), u64::MAX);
/// assert_eq!(constant_time_eq_64(42, 43), 0);
/// assert_eq!(constant_time_eq_64(0, 0), u64::MAX);
/// ```
#[inline]
pub fn constant_time_eq_64(a: u64, b: u64) -> u64 {
    constant_time_is_zero_64(a ^ b)
}

/// Returns `0xFF` if `a >= b` in constant time, `0x00` otherwise (8-bit
/// mask from a 64-bit comparison).
///
/// This is the Rust equivalent of the C `constant_time_ge_8_s(size_t, size_t)`
/// when `size_t` is 64-bit. Used by the Lucky13 padding-oracle defense to
/// produce per-byte masks during the fixed-iteration padding scan in
/// `tls1_cbc_remove_padding_and_mac` (`ssl/record/methods/tls_pad.c`).
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_ge_8_64;
///
/// assert_eq!(constant_time_ge_8_64(5, 3), 0xFF);
/// assert_eq!(constant_time_ge_8_64(5, 5), 0xFF);
/// assert_eq!(constant_time_ge_8_64(3, 5), 0x00);
/// ```
#[inline]
pub fn constant_time_ge_8_64(a: u64, b: u64) -> u8 {
    // Source value is u64::MAX or 0; low byte is therefore 0xFF or 0x00.
    constant_time_ge_64(a, b).to_le_bytes()[0]
}

/// Returns `0xFF` if `a == b` in constant time, `0x00` otherwise (8-bit
/// mask from a 64-bit comparison).
///
/// 8-bit convenience wrapper around [`constant_time_eq_64`]. The result of the
/// 64-bit comparison (either `u64::MAX` or `0`) is truncated to the low byte,
/// yielding `0xFF` or `0x00`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_eq_8_64;
///
/// assert_eq!(constant_time_eq_8_64(42, 42), 0xFF);
/// assert_eq!(constant_time_eq_8_64(42, 43), 0x00);
/// ```
#[inline]
pub fn constant_time_eq_8_64(a: u64, b: u64) -> u8 {
    constant_time_eq_64(a, b).to_le_bytes()[0]
}

// ===========================================================================
// 32-bit Aliases
// ===========================================================================

/// Returns `0xFFFF_FFFF` if `a == 0`, `0` otherwise.
///
/// This is an explicit 32-bit alias for [`constant_time_is_zero`], matching
/// the C function `constant_time_is_zero_32(uint32_t a)`.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_is_zero_32;
///
/// assert_eq!(constant_time_is_zero_32(0), 0xFFFF_FFFF);
/// assert_eq!(constant_time_is_zero_32(1), 0);
/// ```
#[inline]
pub fn constant_time_is_zero_32(a: u32) -> u32 {
    constant_time_is_zero(a)
}

// ===========================================================================
// Byte-level Conditional Copy
// ===========================================================================

/// Conditionally copies `src` into `dst` based on `mask`.
///
/// If `mask` represents true (`Choice::from(1)`), each byte of `src` is
/// copied into the corresponding byte of `dst`. If `mask` represents false
/// (`Choice::from(0)`), `dst` is left unchanged. The operation is
/// constant-time with respect to `mask`.
///
/// Uses [`subtle::ConditionallySelectable::conditional_select`] for each
/// byte to ensure no branches are introduced.
///
/// # Panics
///
/// In debug builds, panics if `dst.len() != src.len()`. In release builds,
/// silently processes only the overlapping prefix.
///
/// # Examples
///
/// ```
/// use openssl_common::constant_time::constant_time_copy_if_choice;
/// use openssl_common::constant_time::Choice;
///
/// let src = [1u8, 2, 3, 4];
/// let mut dst = [0u8; 4];
/// constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
/// assert_eq!(dst, [1, 2, 3, 4]);
///
/// let mut dst = [0u8; 4];
/// constant_time_copy_if_choice(Choice::from(0), &mut dst, &src);
/// assert_eq!(dst, [0, 0, 0, 0]);
/// ```
#[inline]
pub fn constant_time_copy_if_choice(mask: Choice, dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(
        dst.len(),
        src.len(),
        "constant_time_copy_if_choice: dst and src must have equal length"
    );

    // Process only the overlapping region to avoid out-of-bounds access.
    let len = core::cmp::min(dst.len(), src.len());
    for i in 0..len {
        // ConditionallySelectable::conditional_select(a, b, choice):
        //   - choice == 1  →  returns b (src byte)
        //   - choice == 0  →  returns a (dst byte, unchanged)
        dst[i] = u8::conditional_select(&dst[i], &src[i], mask);
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant_time_msb ---

    #[test]
    fn test_msb_set_high_bit() {
        assert_eq!(constant_time_msb(0x8000_0000), 0xFFFF_FFFF);
    }

    #[test]
    fn test_msb_all_ones() {
        assert_eq!(constant_time_msb(0xFFFF_FFFF), 0xFFFF_FFFF);
    }

    #[test]
    fn test_msb_high_bit_plus_one() {
        assert_eq!(constant_time_msb(0x8000_0001), 0xFFFF_FFFF);
    }

    #[test]
    fn test_msb_zero() {
        assert_eq!(constant_time_msb(0), 0);
    }

    #[test]
    fn test_msb_one() {
        assert_eq!(constant_time_msb(1), 0);
    }

    #[test]
    fn test_msb_max_without_high_bit() {
        assert_eq!(constant_time_msb(0x7FFF_FFFF), 0);
    }

    // --- constant_time_lt ---

    #[test]
    fn test_lt_true_basic() {
        assert_eq!(constant_time_lt(0, 1), 0xFFFF_FFFF);
        assert_eq!(constant_time_lt(3, 5), 0xFFFF_FFFF);
    }

    #[test]
    fn test_lt_true_extreme() {
        assert_eq!(constant_time_lt(0, 0xFFFF_FFFF), 0xFFFF_FFFF);
        assert_eq!(constant_time_lt(0xFFFF_FFFE, 0xFFFF_FFFF), 0xFFFF_FFFF);
    }

    #[test]
    fn test_lt_false_basic() {
        assert_eq!(constant_time_lt(1, 0), 0);
        assert_eq!(constant_time_lt(5, 3), 0);
    }

    #[test]
    fn test_lt_false_equal() {
        assert_eq!(constant_time_lt(5, 5), 0);
        assert_eq!(constant_time_lt(0, 0), 0);
        assert_eq!(constant_time_lt(0xFFFF_FFFF, 0xFFFF_FFFF), 0);
    }

    #[test]
    fn test_lt_false_extreme() {
        assert_eq!(constant_time_lt(0xFFFF_FFFF, 0), 0);
    }

    // --- constant_time_ge ---

    #[test]
    fn test_ge_greater() {
        assert_eq!(constant_time_ge(5, 3), 0xFFFF_FFFF);
        assert_eq!(constant_time_ge(0xFFFF_FFFF, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn test_ge_equal() {
        assert_eq!(constant_time_ge(5, 5), 0xFFFF_FFFF);
        assert_eq!(constant_time_ge(0, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn test_ge_less() {
        assert_eq!(constant_time_ge(3, 5), 0);
        assert_eq!(constant_time_ge(0, 1), 0);
    }

    // --- constant_time_is_zero ---

    #[test]
    fn test_is_zero_true() {
        assert_eq!(constant_time_is_zero(0), 0xFFFF_FFFF);
    }

    #[test]
    fn test_is_zero_false() {
        assert_eq!(constant_time_is_zero(1), 0);
        assert_eq!(constant_time_is_zero(42), 0);
        assert_eq!(constant_time_is_zero(0xFFFF_FFFF), 0);
        assert_eq!(constant_time_is_zero(0x8000_0000), 0);
    }

    // --- constant_time_eq ---

    #[test]
    fn test_eq_true() {
        assert_eq!(constant_time_eq(42, 42), 0xFFFF_FFFF);
        assert_eq!(constant_time_eq(0, 0), 0xFFFF_FFFF);
        assert_eq!(constant_time_eq(0xFFFF_FFFF, 0xFFFF_FFFF), 0xFFFF_FFFF);
    }

    #[test]
    fn test_eq_false() {
        assert_eq!(constant_time_eq(42, 43), 0);
        assert_eq!(constant_time_eq(0, 1), 0);
        assert_eq!(constant_time_eq(0xFFFF_FFFF, 0), 0);
    }

    // --- constant_time_eq_int ---

    #[test]
    fn test_eq_int_equal_positive() {
        assert_eq!(constant_time_eq_int(42, 42), 0xFFFF_FFFF);
        assert_eq!(constant_time_eq_int(0, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn test_eq_int_equal_negative() {
        assert_eq!(constant_time_eq_int(-1, -1), 0xFFFF_FFFF);
        assert_eq!(constant_time_eq_int(i32::MIN, i32::MIN), 0xFFFF_FFFF);
    }

    #[test]
    fn test_eq_int_not_equal() {
        assert_eq!(constant_time_eq_int(1, -1), 0);
        assert_eq!(constant_time_eq_int(-1, 1), 0);
        assert_eq!(constant_time_eq_int(0, 1), 0);
    }

    // --- constant_time_select ---

    #[test]
    fn test_select_mask_all_ones() {
        assert_eq!(constant_time_select(0xFFFF_FFFF, 10, 20), 10);
        assert_eq!(constant_time_select(0xFFFF_FFFF, 0, 0xFFFF_FFFF), 0);
    }

    #[test]
    fn test_select_mask_all_zeros() {
        assert_eq!(constant_time_select(0, 10, 20), 20);
        assert_eq!(constant_time_select(0, 0, 0xFFFF_FFFF), 0xFFFF_FFFF);
    }

    // --- constant_time_select_8 ---

    #[test]
    fn test_select_8_true() {
        assert_eq!(constant_time_select_8(0xFF, 0xAA, 0xBB), 0xAA);
    }

    #[test]
    fn test_select_8_false() {
        assert_eq!(constant_time_select_8(0x00, 0xAA, 0xBB), 0xBB);
    }

    // --- constant_time_select_64 ---

    #[test]
    fn test_select_64_true() {
        assert_eq!(constant_time_select_64(u64::MAX, 100, 200), 100);
    }

    #[test]
    fn test_select_64_false() {
        assert_eq!(constant_time_select_64(0, 100, 200), 200);
    }

    // --- constant_time_select_int ---

    #[test]
    fn test_select_int_true() {
        assert_eq!(constant_time_select_int(0xFFFF_FFFF, -10, 20), -10);
        assert_eq!(
            constant_time_select_int(0xFFFF_FFFF, i32::MIN, i32::MAX),
            i32::MIN
        );
    }

    #[test]
    fn test_select_int_false() {
        assert_eq!(constant_time_select_int(0, -10, 20), 20);
        assert_eq!(constant_time_select_int(0, i32::MIN, i32::MAX), i32::MAX);
    }

    // --- memcmp ---

    #[test]
    fn test_memcmp_equal() {
        assert!(memcmp(b"hello", b"hello"));
        assert!(memcmp(&[], &[]));
        assert!(memcmp(&[0u8; 256], &[0u8; 256]));
    }

    #[test]
    fn test_memcmp_not_equal_content() {
        assert!(!memcmp(b"hello", b"world"));
        assert!(!memcmp(&[0, 0, 0, 1], &[0, 0, 0, 2]));
    }

    #[test]
    fn test_memcmp_not_equal_length() {
        assert!(!memcmp(b"short", b"longer"));
        assert!(!memcmp(b"", b"x"));
    }

    // --- memcmp_choice ---

    #[test]
    fn test_memcmp_choice_equal() {
        let c = memcmp_choice(b"secret", b"secret");
        assert!(bool::from(c));
    }

    #[test]
    fn test_memcmp_choice_not_equal() {
        let c = memcmp_choice(b"secret", b"public");
        assert!(!bool::from(c));
    }

    #[test]
    fn test_memcmp_choice_different_length() {
        let c = memcmp_choice(b"short", b"longer");
        assert!(!bool::from(c));
    }

    #[test]
    fn test_memcmp_choice_empty() {
        let c = memcmp_choice(&[], &[]);
        assert!(bool::from(c));
    }

    // --- 8-bit wrappers ---

    #[test]
    fn test_lt_8() {
        assert_eq!(constant_time_lt_8(3, 5), 0xFF);
        assert_eq!(constant_time_lt_8(5, 3), 0x00);
        assert_eq!(constant_time_lt_8(5, 5), 0x00);
    }

    #[test]
    fn test_ge_8() {
        assert_eq!(constant_time_ge_8(5, 3), 0xFF);
        assert_eq!(constant_time_ge_8(5, 5), 0xFF);
        assert_eq!(constant_time_ge_8(3, 5), 0x00);
    }

    #[test]
    fn test_is_zero_8() {
        assert_eq!(constant_time_is_zero_8(0), 0xFF);
        assert_eq!(constant_time_is_zero_8(1), 0x00);
        assert_eq!(constant_time_is_zero_8(255), 0x00);
    }

    #[test]
    fn test_eq_8() {
        assert_eq!(constant_time_eq_8(42, 42), 0xFF);
        assert_eq!(constant_time_eq_8(42, 43), 0x00);
    }

    #[test]
    fn test_eq_int_8() {
        assert_eq!(constant_time_eq_int_8(-1, -1), 0xFF);
        assert_eq!(constant_time_eq_int_8(1, -1), 0x00);
    }

    // --- 64-bit variants ---

    #[test]
    fn test_msb_64_set() {
        assert_eq!(constant_time_msb_64(0x8000_0000_0000_0000), u64::MAX);
        assert_eq!(constant_time_msb_64(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_msb_64_clear() {
        assert_eq!(constant_time_msb_64(0x7FFF_FFFF_FFFF_FFFF), 0);
        assert_eq!(constant_time_msb_64(0), 0);
        assert_eq!(constant_time_msb_64(1), 0);
    }

    #[test]
    fn test_lt_64_true() {
        assert_eq!(constant_time_lt_64(3, 5), u64::MAX);
        assert_eq!(constant_time_lt_64(0, 1), u64::MAX);
        assert_eq!(constant_time_lt_64(u64::MAX - 1, u64::MAX), u64::MAX);
    }

    #[test]
    fn test_lt_64_false() {
        assert_eq!(constant_time_lt_64(5, 3), 0);
        assert_eq!(constant_time_lt_64(5, 5), 0);
        assert_eq!(constant_time_lt_64(u64::MAX, 0), 0);
    }

    #[test]
    fn test_ge_64_true() {
        assert_eq!(constant_time_ge_64(5, 3), u64::MAX);
        assert_eq!(constant_time_ge_64(5, 5), u64::MAX);
        assert_eq!(constant_time_ge_64(u64::MAX, 0), u64::MAX);
        assert_eq!(constant_time_ge_64(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn test_ge_64_false() {
        assert_eq!(constant_time_ge_64(3, 5), 0);
        assert_eq!(constant_time_ge_64(0, 1), 0);
        assert_eq!(constant_time_ge_64(0, u64::MAX), 0);
    }

    #[test]
    fn test_is_zero_64() {
        assert_eq!(constant_time_is_zero_64(0), u64::MAX);
        assert_eq!(constant_time_is_zero_64(1), 0);
        assert_eq!(constant_time_is_zero_64(u64::MAX), 0);
        assert_eq!(constant_time_is_zero_64(0x8000_0000_0000_0000), 0);
    }

    #[test]
    fn test_eq_64_true() {
        assert_eq!(constant_time_eq_64(0, 0), u64::MAX);
        assert_eq!(constant_time_eq_64(42, 42), u64::MAX);
        assert_eq!(constant_time_eq_64(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn test_eq_64_false() {
        assert_eq!(constant_time_eq_64(42, 43), 0);
        assert_eq!(constant_time_eq_64(0, 1), 0);
        assert_eq!(constant_time_eq_64(0, u64::MAX), 0);
    }

    #[test]
    fn test_ge_8_64_true() {
        assert_eq!(constant_time_ge_8_64(5, 3), 0xFF);
        assert_eq!(constant_time_ge_8_64(5, 5), 0xFF);
        assert_eq!(constant_time_ge_8_64(u64::MAX, 0), 0xFF);
    }

    #[test]
    fn test_ge_8_64_false() {
        assert_eq!(constant_time_ge_8_64(3, 5), 0x00);
        assert_eq!(constant_time_ge_8_64(0, 1), 0x00);
        assert_eq!(constant_time_ge_8_64(0, u64::MAX), 0x00);
    }

    #[test]
    fn test_eq_8_64_true() {
        assert_eq!(constant_time_eq_8_64(42, 42), 0xFF);
        assert_eq!(constant_time_eq_8_64(0, 0), 0xFF);
        assert_eq!(constant_time_eq_8_64(u64::MAX, u64::MAX), 0xFF);
    }

    #[test]
    fn test_eq_8_64_false() {
        assert_eq!(constant_time_eq_8_64(42, 43), 0x00);
        assert_eq!(constant_time_eq_8_64(0, u64::MAX), 0x00);
    }

    // --- constant_time_is_zero_32 ---

    #[test]
    fn test_is_zero_32() {
        assert_eq!(constant_time_is_zero_32(0), 0xFFFF_FFFF);
        assert_eq!(constant_time_is_zero_32(1), 0);
        assert_eq!(constant_time_is_zero_32(0xFFFF_FFFF), 0);
    }

    // --- constant_time_copy_if_choice ---

    #[test]
    fn test_copy_if_choice_true() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [0u8; 4];
        constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
        assert_eq!(dst, [1, 2, 3, 4]);
    }

    #[test]
    fn test_copy_if_choice_false() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [0u8; 4];
        constant_time_copy_if_choice(Choice::from(0), &mut dst, &src);
        assert_eq!(dst, [0, 0, 0, 0]);
    }

    #[test]
    fn test_copy_if_choice_preserves_dst_on_false() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [0xAA_u8; 4];
        constant_time_copy_if_choice(Choice::from(0), &mut dst, &src);
        assert_eq!(dst, [0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn test_copy_if_choice_empty_slices() {
        let src: [u8; 0] = [];
        let mut dst: [u8; 0] = [];
        constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
        // No panic, no-op on empty slices.
    }

    #[test]
    fn test_copy_if_choice_large() {
        let src: Vec<u8> = (0..=255).collect();
        let mut dst = vec![0u8; 256];
        constant_time_copy_if_choice(Choice::from(1), &mut dst, &src);
        assert_eq!(dst, src);
    }

    // --- Integration / usage pattern tests ---

    #[test]
    fn test_integration_lt_select_pattern() {
        // Mimics the C usage pattern from the header comment:
        // if (a < b) { c = a; } else { c = b; }
        let a = 3u32;
        let b = 5u32;
        let lt = constant_time_lt(a, b);
        let c = constant_time_select(lt, a, b);
        assert_eq!(c, 3);

        let a = 5u32;
        let b = 3u32;
        let lt = constant_time_lt(a, b);
        let c = constant_time_select(lt, a, b);
        assert_eq!(c, 3); // b is selected since a >= b
    }

    #[test]
    fn test_integration_eq_memcmp_consistency() {
        // Verify that memcmp and eq produce consistent results.
        let a = 42u32;
        let b = 42u32;
        let eq_mask = constant_time_eq(a, b);
        let mem_result = memcmp(&a.to_le_bytes(), &b.to_le_bytes());
        assert_eq!(eq_mask, 0xFFFF_FFFF);
        assert!(mem_result);
    }

    #[test]
    fn test_ct_option_re_export() {
        // Verify CtOption re-export works for downstream usage.
        let some_val: CtOption<u32> = CtOption::new(42, Choice::from(1));
        assert!(bool::from(some_val.is_some()));
        assert_eq!(some_val.unwrap_or(0), 42);

        let none_val: CtOption<u32> = CtOption::new(0, Choice::from(0));
        assert!(!bool::from(none_val.is_some()));
        assert_eq!(none_val.unwrap_or(99), 99);
    }

    // --- Boundary value tests ---

    #[test]
    fn test_lt_boundary_u32_max() {
        assert_eq!(constant_time_lt(u32::MAX - 1, u32::MAX), 0xFFFF_FFFF);
        assert_eq!(constant_time_lt(u32::MAX, u32::MAX - 1), 0);
        assert_eq!(constant_time_lt(0, u32::MAX), 0xFFFF_FFFF);
        assert_eq!(constant_time_lt(u32::MAX, 0), 0);
    }

    #[test]
    fn test_eq_int_boundary_values() {
        assert_eq!(constant_time_eq_int(i32::MIN, i32::MAX), 0);
        assert_eq!(constant_time_eq_int(i32::MAX, i32::MAX), 0xFFFF_FFFF);
        assert_eq!(constant_time_eq_int(i32::MIN, i32::MIN), 0xFFFF_FFFF);
    }

    #[test]
    fn test_select_int_boundary_values() {
        assert_eq!(
            constant_time_select_int(0xFFFF_FFFF, i32::MIN, i32::MAX),
            i32::MIN
        );
        assert_eq!(constant_time_select_int(0, i32::MIN, i32::MAX), i32::MAX);
    }
}
