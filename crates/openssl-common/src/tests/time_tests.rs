//! Tests for the `OsslTime` type and time arithmetic in openssl-common.
//!
//! Verifies `OsslTime` saturating arithmetic (add overflow → `INFINITE`,
//! sub underflow → `ZERO`), `now()` returns non-zero, conversion round-trips
//! (seconds / ms / µs / ticks / `Duration`), comparison ordering, `Display`
//! formatting, and operator overloads (`Add`, `Sub`).
//!
//! Derived from C `include/internal/time.h` and `crypto/time.c`.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `to_duration()` returns `Option<Duration>`, not sentinel.
//! - **R6 (Lossless Casts):** All arithmetic is checked / saturating. No bare `as` casts.
//! - **R8 (Zero Unsafe):** ZERO `unsafe` code in this test module.
//! - **R9 (Warning-Free):** Compiles with `RUSTFLAGS="-D warnings"`.
//! - **R10 (Wiring):** Tests exercise the time module through its public API.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_literal_unwrap
)]

use std::convert::TryFrom;
use std::time::Duration;

use crate::time::OsslTime;

// =============================================================================
// Phase 2: Constants Tests
// Verify constants match C defines from `include/internal/time.h` lines 31–40.
// =============================================================================

#[test]
fn time_constants() {
    // C: OSSL_TIME_SECOND = 1_000_000_000
    assert_eq!(OsslTime::SECOND, 1_000_000_000_u64);
    // C: OSSL_TIME_MS = OSSL_TIME_SECOND / 1000 = 1_000_000
    assert_eq!(OsslTime::MS, 1_000_000_u64);
    // C: OSSL_TIME_US = OSSL_TIME_MS / 1000 = 1_000
    assert_eq!(OsslTime::US, 1_000_u64);
    // C: OSSL_TIME_NS = OSSL_TIME_US / 1000 = 1
    assert_eq!(OsslTime::NS, 1_u64);
}

#[test]
fn time_zero_constant() {
    // C: ossl_time_zero() → ticks == 0
    assert_eq!(OsslTime::ZERO.ticks(), 0);
    assert!(OsslTime::ZERO.is_zero());
}

#[test]
fn time_infinite_constant() {
    // C: ossl_time_infinite() → ticks == ~(uint64_t)0 == u64::MAX
    assert_eq!(OsslTime::INFINITE.ticks(), u64::MAX);
    assert!(OsslTime::INFINITE.is_infinite());
}

#[test]
fn time_zero_not_infinite() {
    assert!(!OsslTime::ZERO.is_infinite());
}

#[test]
fn time_infinite_not_zero() {
    assert!(!OsslTime::INFINITE.is_zero());
}

// =============================================================================
// Phase 3: Constructor and Conversion Round-Trip Tests
// Mirror C macros: ossl_seconds2time, ossl_time2seconds, ossl_ms2time, etc.
// =============================================================================

#[test]
fn from_ticks_to_ticks_round_trip() {
    // C: ossl_ticks2time(12345) → ossl_time2ticks() == 12345
    assert_eq!(OsslTime::from_ticks(12345).ticks(), 12345);
}

#[test]
fn from_seconds_to_seconds() {
    // C: ossl_seconds2time(5) → ossl_time2seconds() == 5
    assert_eq!(OsslTime::from_seconds(5).to_seconds(), 5);
}

#[test]
fn from_seconds_ticks_calculation() {
    // C: ossl_seconds2time(1) → ticks == OSSL_TIME_SECOND == 1_000_000_000
    assert_eq!(OsslTime::from_seconds(1).ticks(), 1_000_000_000);
}

#[test]
fn from_ms_to_ms() {
    // C: ossl_ms2time(1500) → ossl_time2ms() == 1500
    assert_eq!(OsslTime::from_ms(1500).to_ms(), 1500);
}

#[test]
fn from_ms_ticks_calculation() {
    // C: ossl_ms2time(1) → ticks == OSSL_TIME_MS == 1_000_000
    assert_eq!(OsslTime::from_ms(1).ticks(), 1_000_000);
}

#[test]
fn from_us_to_us() {
    // C: ossl_us2time(2500) → ossl_time2us() == 2500
    assert_eq!(OsslTime::from_us(2500).to_us(), 2500);
}

#[test]
fn from_us_ticks_calculation() {
    // C: ossl_us2time(1) → ticks == OSSL_TIME_US == 1_000
    assert_eq!(OsslTime::from_us(1).ticks(), 1_000);
}

#[test]
fn seconds_truncation() {
    // Integer division truncates: 1.5 seconds → 1 second
    // C: ossl_time2seconds(ossl_ticks2time(1_500_000_000)) == 1
    assert_eq!(OsslTime::from_ticks(1_500_000_000).to_seconds(), 1);
}

#[test]
fn ms_truncation() {
    // Integer division truncates: 1.5 ms → 1 ms
    // C: ossl_time2ms(ossl_ticks2time(1_500_000)) == 1
    assert_eq!(OsslTime::from_ticks(1_500_000).to_ms(), 1);
}

// =============================================================================
// Phase 4: Duration Conversion Tests
// =============================================================================

#[test]
fn from_duration() {
    // 3 seconds → 3 * SECOND ticks
    let t = OsslTime::from_duration(Duration::from_secs(3));
    assert_eq!(t.ticks(), 3 * OsslTime::SECOND);
}

#[test]
fn from_duration_with_nanos() {
    // Duration(1s, 500_000_000ns) → 1_500_000_000 ticks
    let t = OsslTime::from_duration(Duration::new(1, 500_000_000));
    assert_eq!(t.ticks(), 1_500_000_000);
}

#[test]
fn to_duration_some() {
    // Non-infinite time converts to Some(Duration)
    let t = OsslTime::from_seconds(10);
    let d = t.to_duration();
    assert!(d.is_some());
    let dur = d.unwrap();
    assert_eq!(dur, Duration::from_nanos(10_000_000_000));
}

#[test]
fn to_duration_infinite_none() {
    // Rule R5: INFINITE → None (no sentinel)
    assert_eq!(OsslTime::INFINITE.to_duration(), None);
}

#[test]
fn to_duration_zero() {
    // ZERO → Some(Duration::ZERO)
    assert_eq!(OsslTime::ZERO.to_duration(), Some(Duration::ZERO));
}

#[test]
fn from_into_duration_trait() {
    // Test From<Duration> for OsslTime
    let d = Duration::from_secs(5);
    let t: OsslTime = d.into();
    assert_eq!(t.to_seconds(), 5);

    // Test TryFrom<OsslTime> for Duration — success case
    let t2 = OsslTime::from_seconds(10);
    let d2 = Duration::try_from(t2);
    assert!(d2.is_ok());
    assert_eq!(d2.unwrap(), Duration::from_nanos(10_000_000_000));

    // Test TryFrom<OsslTime> for Duration — failure case (INFINITE)
    let d3 = Duration::try_from(OsslTime::INFINITE);
    assert!(d3.is_err());
}

// =============================================================================
// Phase 5: now() Tests
// =============================================================================

#[test]
fn now_returns_nonzero() {
    // Unless system clock is at epoch (extremely unlikely), now() > 0
    let now = OsslTime::now();
    assert!(now.ticks() > 0, "now() should return a non-zero time");
}

#[test]
fn now_is_not_infinite() {
    let now = OsslTime::now();
    assert!(!now.is_infinite(), "now() should not be infinite");
}

#[test]
fn now_monotonic_ish() {
    // Two consecutive now() calls: t1 <= t2 (overwhelming probability)
    let t1 = OsslTime::now();
    let t2 = OsslTime::now();
    assert!(t1 <= t2, "expected t1 <= t2, got t1={t1}, t2={t2}");
}

// =============================================================================
// Phase 6: Saturating Arithmetic Tests
// CRITICAL: All arithmetic is saturating per C include/internal/time.h
//           lines 49–53 and 159–221.
// =============================================================================

// ---- Addition (replaces ossl_time_add()) ----

#[test]
fn saturating_add_normal() {
    let result = OsslTime::from_seconds(2).saturating_add(OsslTime::from_seconds(3));
    assert_eq!(result.to_seconds(), 5);
}

#[test]
fn saturating_add_overflow_to_infinite() {
    // Overflow saturates to INFINITE (u64::MAX), matching C behaviour
    let near_max = OsslTime::from_ticks(u64::MAX - 1);
    let two = OsslTime::from_ticks(2);
    let result = near_max.saturating_add(two);
    assert!(
        result.is_infinite(),
        "overflow should saturate to INFINITE, got ticks={}",
        result.ticks()
    );
}

#[test]
fn saturating_add_zero() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(t.saturating_add(OsslTime::ZERO), t);
}

#[test]
fn saturating_add_infinite() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(
        t.saturating_add(OsslTime::INFINITE),
        OsslTime::INFINITE
    );
}

// ---- Subtraction (replaces ossl_time_subtract()) ----

#[test]
fn saturating_sub_normal() {
    let result = OsslTime::from_seconds(5).saturating_sub(OsslTime::from_seconds(3));
    assert_eq!(result.to_seconds(), 2);
}

#[test]
fn saturating_sub_underflow_to_zero() {
    // Underflow saturates to ZERO, matching C behaviour
    let result = OsslTime::from_seconds(2).saturating_sub(OsslTime::from_seconds(5));
    assert_eq!(result, OsslTime::ZERO);
}

#[test]
fn saturating_sub_zero() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(t.saturating_sub(OsslTime::ZERO), t);
}

#[test]
fn saturating_sub_equal() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(t.saturating_sub(t), OsslTime::ZERO);
}

// ---- Absolute difference (replaces ossl_time_abs_difference()) ----

#[test]
fn abs_difference_a_gt_b() {
    let result = OsslTime::from_seconds(5).abs_difference(OsslTime::from_seconds(3));
    assert_eq!(result.to_seconds(), 2);
}

#[test]
fn abs_difference_b_gt_a() {
    let result = OsslTime::from_seconds(3).abs_difference(OsslTime::from_seconds(5));
    assert_eq!(result.to_seconds(), 2);
}

#[test]
fn abs_difference_equal() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(t.abs_difference(t), OsslTime::ZERO);
}

// ---- Multiplication (replaces ossl_time_multiply()) ----

#[test]
fn saturating_mul_normal() {
    let result = OsslTime::from_seconds(3).saturating_mul(4);
    assert_eq!(result.to_seconds(), 12);
}

#[test]
fn saturating_mul_overflow_to_infinite() {
    // Large multiplication overflows → saturates to INFINITE
    let result = OsslTime::from_ticks(u64::MAX / 2).saturating_mul(3);
    assert!(
        result.is_infinite(),
        "overflow should saturate to INFINITE, got ticks={}",
        result.ticks()
    );
}

#[test]
fn saturating_mul_by_zero() {
    assert_eq!(OsslTime::from_seconds(5).saturating_mul(0), OsslTime::ZERO);
}

#[test]
fn saturating_mul_by_one() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(t.saturating_mul(1), t);
}

// ---- Division (replaces ossl_time_divide()) ----

#[test]
fn checked_div_normal() {
    let result = OsslTime::from_seconds(12).checked_div(3);
    assert_eq!(result.to_seconds(), 4);
}

#[test]
fn checked_div_by_zero() {
    // Division by zero gives ZERO, matching C behaviour
    assert_eq!(OsslTime::from_seconds(5).checked_div(0), OsslTime::ZERO);
}

#[test]
fn checked_div_by_one() {
    let t = OsslTime::from_seconds(5);
    assert_eq!(t.checked_div(1), t);
}

// ---- Min / Max (replaces ossl_time_min() / ossl_time_max()) ----

#[test]
fn time_min() {
    let a = OsslTime::from_seconds(3);
    let b = OsslTime::from_seconds(5);
    assert_eq!(a.min(b).to_seconds(), 3);
    assert_eq!(b.min(a).to_seconds(), 3);
}

#[test]
fn time_max() {
    let a = OsslTime::from_seconds(3);
    let b = OsslTime::from_seconds(5);
    assert_eq!(a.max(b).to_seconds(), 5);
    assert_eq!(b.max(a).to_seconds(), 5);
}

// =============================================================================
// Phase 7: Comparison Ordering Tests
// =============================================================================

#[test]
fn time_ordering() {
    let one = OsslTime::from_seconds(1);
    let two = OsslTime::from_seconds(2);
    assert!(one < two);
    assert!(two > one);
}

#[test]
fn time_equality() {
    let a = OsslTime::from_seconds(5);
    let b = OsslTime::from_seconds(5);
    assert_eq!(a, b);
}

#[test]
fn time_zero_lt_any() {
    assert!(OsslTime::ZERO < OsslTime::from_seconds(1));
}

#[test]
fn time_any_lt_infinite() {
    // The largest representable non-infinite time must be < INFINITE
    let large = OsslTime::from_seconds(u64::MAX / OsslTime::SECOND);
    assert!(large < OsslTime::INFINITE);
}

#[test]
fn time_ord_consistent() {
    // Verify Ord implementation is consistent with PartialOrd
    let a = OsslTime::from_seconds(3);
    let b = OsslTime::from_seconds(7);
    assert_eq!(
        a.cmp(&b),
        a.partial_cmp(&b).unwrap(),
        "Ord and PartialOrd must agree"
    );
    assert_eq!(
        b.cmp(&a),
        b.partial_cmp(&a).unwrap(),
        "Ord and PartialOrd must agree (reversed)"
    );
    // Reflexive case
    assert_eq!(
        a.cmp(&a),
        a.partial_cmp(&a).unwrap(),
        "Ord and PartialOrd must agree (equal)"
    );
}

// =============================================================================
// Phase 8: Display Tests
// =============================================================================

#[test]
fn display_zero() {
    let s = format!("{}", OsslTime::ZERO);
    assert!(s.contains('0'), "display of ZERO should contain '0', got: {s}");
    assert_eq!(s, "0s");
}

#[test]
fn display_infinite() {
    let s = format!("{}", OsslTime::INFINITE);
    assert!(
        s.contains('∞') || s.to_lowercase().contains("infinite"),
        "display of INFINITE should contain '∞' or 'infinite', got: {s}"
    );
    assert_eq!(s, "∞");
}

#[test]
fn display_normal() {
    let s = format!("{}", OsslTime::from_seconds(42));
    // Implementation formats as "42.000s"
    assert!(s.contains("42"), "display should show seconds, got: {s}");
    assert_eq!(s, "42.000s");
}

// =============================================================================
// Phase 9: Operator Overload Tests
// =============================================================================

#[test]
fn add_operator() {
    // Via std::ops::Add — delegates to saturating_add
    let result = OsslTime::from_seconds(2) + OsslTime::from_seconds(3);
    assert_eq!(result, OsslTime::from_seconds(5));
}

#[test]
fn sub_operator() {
    // Via std::ops::Sub — delegates to saturating_sub
    let result = OsslTime::from_seconds(5) - OsslTime::from_seconds(3);
    assert_eq!(result, OsslTime::from_seconds(2));
}
