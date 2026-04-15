//! Time representation and arithmetic for the OpenSSL Rust workspace,
//! replacing C `OSSL_TIME`. Uses nanosecond precision since Unix epoch
//! with saturating arithmetic.
//!
//! # C Source Mapping
//!
//! | C Construct                      | Rust Equivalent                      |
//! |----------------------------------|--------------------------------------|
//! | `OSSL_TIME { uint64_t t; }`      | [`OsslTime`] (newtype over `u64`)    |
//! | `OSSL_TIME_SECOND`               | [`OsslTime::SECOND`]                 |
//! | `OSSL_TIME_MS`                   | [`OsslTime::MS`]                     |
//! | `OSSL_TIME_US`                   | [`OsslTime::US`]                     |
//! | `OSSL_TIME_NS`                   | [`OsslTime::NS`]                     |
//! | `ossl_time_zero()`               | [`OsslTime::ZERO`] / [`OsslTime::zero()`] |
//! | `ossl_time_infinite()`           | [`OsslTime::INFINITE`] / [`OsslTime::infinite()`] |
//! | `ossl_ticks2time(t)`             | [`OsslTime::from_ticks()`]           |
//! | `ossl_time2ticks(t)`             | [`OsslTime::ticks()`]                |
//! | `ossl_seconds2time(s)`           | [`OsslTime::from_seconds()`]         |
//! | `ossl_time2seconds(t)`           | [`OsslTime::to_seconds()`]           |
//! | `ossl_ms2time(ms)`               | [`OsslTime::from_ms()`]              |
//! | `ossl_time2ms(t)`                | [`OsslTime::to_ms()`]                |
//! | `ossl_us2time(us)`               | [`OsslTime::from_us()`]              |
//! | `ossl_time2us(t)`                | [`OsslTime::to_us()`]                |
//! | `ossl_time_now()`                | [`OsslTime::now()`]                  |
//! | `ossl_time_add(a, b)`            | [`OsslTime::saturating_add()`]       |
//! | `ossl_time_subtract(a, b)`       | [`OsslTime::saturating_sub()`]       |
//! | `ossl_time_abs_difference(a, b)` | [`OsslTime::abs_difference()`]       |
//! | `ossl_time_multiply(a, b)`       | [`OsslTime::saturating_mul()`]       |
//! | `ossl_time_divide(a, b)`         | [`OsslTime::checked_div()`]          |
//! | `ossl_time_min(a, b)`            | [`OsslTime::min()`]                  |
//! | `ossl_time_max(a, b)`            | [`OsslTime::max()`]                  |
//! | `ossl_time_compare(a, b)`        | [`Ord`] impl on [`OsslTime`]         |
//! | `ossl_time_is_zero(t)`           | [`OsslTime::is_zero()`]              |
//! | `ossl_time_is_infinite(t)`       | [`OsslTime::is_infinite()`]          |
//!
//! # Saturating Arithmetic
//!
//! All arithmetic on [`OsslTime`] is **saturating**: overflow clamps to
//! [`OsslTime::INFINITE`] and underflow clamps to [`OsslTime::ZERO`].
//! This matches the C `safe_math.h` behaviour where overflow sets the error
//! flag and returns the maximum or zero sentinel respectively.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** [`to_duration()`](OsslTime::to_duration) returns
//!   `Option<Duration>`; [`from_system_time()`](OsslTime::from_system_time)
//!   returns `Result`. No sentinel values.
//! - **R6 (Lossless Casts):** All conversions use `checked_*` / `saturating_*`.
//!   No bare `as` casts for narrowing.
//! - **R8 (Zero Unsafe):** No `unsafe` code in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable via QUIC reactor tick scheduling
//!   (`openssl_ssl::quic::reactor`) and session expiry
//!   (`openssl_ssl::session`).

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;
use std::ops::{Add, Sub};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::CommonError;

// =============================================================================
// OsslTime — Nanosecond-Precision Time Type
// =============================================================================

/// A nanosecond-precision time value measured from the Unix epoch
/// (1970-01-01 00:00:00 UTC).
///
/// This is the Rust equivalent of the C `OSSL_TIME` type defined in
/// `include/internal/time.h` (line 26–28):
///
/// ```c
/// typedef struct {
///     uint64_t t; /* Ticks since the epoch */
/// } OSSL_TIME;
/// ```
///
/// At nanosecond precision, the representable range covers approximately
/// 584 years from the epoch (through ~2554 CE), matching the original C
/// implementation.
///
/// # Saturating Semantics
///
/// All arithmetic operations saturate rather than panic:
/// - **Overflow** → [`OsslTime::INFINITE`] (`u64::MAX` ticks)
/// - **Underflow** → [`OsslTime::ZERO`] (0 ticks)
///
/// This matches the C `safe_math.h` overflow-checked arithmetic used by
/// `ossl_time_add()`, `ossl_time_subtract()`, and `ossl_time_multiply()`.
///
/// # Examples
///
/// ```
/// use openssl_common::time::OsslTime;
///
/// let t = OsslTime::from_seconds(42);
/// assert_eq!(t.to_seconds(), 42);
/// assert!(!t.is_zero());
/// assert!(!t.is_infinite());
///
/// let sum = t.saturating_add(OsslTime::from_seconds(8));
/// assert_eq!(sum.to_seconds(), 50);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct OsslTime {
    /// Ticks (nanoseconds) since Unix epoch.
    ticks: u64,
}

// =============================================================================
// Constants
// =============================================================================

impl OsslTime {
    /// Number of nanosecond ticks per second (1,000,000,000).
    ///
    /// Equivalent to C `OSSL_TIME_SECOND` (`include/internal/time.h` line 31).
    pub const SECOND: u64 = 1_000_000_000;

    /// Number of nanosecond ticks per millisecond (1,000,000).
    ///
    /// Equivalent to C `OSSL_TIME_MS` (`include/internal/time.h` line 34).
    pub const MS: u64 = 1_000_000;

    /// Number of nanosecond ticks per microsecond (1,000).
    ///
    /// Equivalent to C `OSSL_TIME_US` (`include/internal/time.h` line 37).
    pub const US: u64 = 1_000;

    /// Number of nanosecond ticks per nanosecond (1).
    ///
    /// Equivalent to C `OSSL_TIME_NS` (`include/internal/time.h` line 40).
    pub const NS: u64 = 1;

    /// The zero time value (epoch itself: 0 nanoseconds).
    ///
    /// Equivalent to C `ossl_time_zero()` (`include/internal/time.h` line 75–78).
    pub const ZERO: OsslTime = OsslTime { ticks: 0 };

    /// The infinite (maximum) time value (`u64::MAX` nanoseconds).
    ///
    /// Used as a sentinel for "no timeout" or "never expires". Equivalent
    /// to C `ossl_time_infinite()` which returns `~(uint64_t)0`
    /// (`include/internal/time.h` line 80–83).
    pub const INFINITE: OsslTime = OsslTime { ticks: u64::MAX };
}

// =============================================================================
// Constructors and Conversions
// =============================================================================

impl OsslTime {
    /// Creates an [`OsslTime`] from a raw nanosecond tick count.
    ///
    /// Equivalent to C `ossl_ticks2time()` (`include/internal/time.h` line 57–63).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_ticks(5_000_000_000);
    /// assert_eq!(t.to_seconds(), 5);
    /// ```
    #[inline]
    pub const fn from_ticks(ticks: u64) -> Self {
        OsslTime { ticks }
    }

    /// Returns the raw nanosecond tick count.
    ///
    /// Equivalent to C `ossl_time2ticks()` (`include/internal/time.h` line 66–69).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_seconds(3);
    /// assert_eq!(t.ticks(), 3_000_000_000);
    /// ```
    #[inline]
    pub const fn ticks(self) -> u64 {
        self.ticks
    }

    /// Creates an [`OsslTime`] from a count of whole seconds.
    ///
    /// Uses saturating multiplication: if `s * SECOND` would overflow `u64`,
    /// returns [`OsslTime::INFINITE`].
    ///
    /// Equivalent to C `ossl_seconds2time()` (`include/internal/time.h` line 42).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_seconds(10);
    /// assert_eq!(t.ticks(), 10_000_000_000);
    ///
    /// // Overflow saturates to INFINITE
    /// let huge = OsslTime::from_seconds(u64::MAX);
    /// assert!(huge.is_infinite());
    /// ```
    #[inline]
    pub fn from_seconds(s: u64) -> Self {
        OsslTime {
            ticks: s.checked_mul(Self::SECOND).unwrap_or(u64::MAX),
        }
    }

    /// Converts this time value to whole seconds (truncating sub-second
    /// nanosecond ticks).
    ///
    /// Equivalent to C `ossl_time2seconds()` (`include/internal/time.h` line 43).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_ticks(2_500_000_000);
    /// assert_eq!(t.to_seconds(), 2); // truncated
    /// ```
    #[inline]
    pub const fn to_seconds(self) -> u64 {
        self.ticks / Self::SECOND
    }

    /// Creates an [`OsslTime`] from a count of milliseconds.
    ///
    /// Uses saturating multiplication: if `ms * MS` would overflow,
    /// returns [`OsslTime::INFINITE`].
    ///
    /// Equivalent to C `ossl_ms2time()` (`include/internal/time.h` line 44).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_ms(1500);
    /// assert_eq!(t.to_seconds(), 1);
    /// assert_eq!(t.to_ms(), 1500);
    /// ```
    #[inline]
    pub fn from_ms(ms: u64) -> Self {
        OsslTime {
            ticks: ms.checked_mul(Self::MS).unwrap_or(u64::MAX),
        }
    }

    /// Converts this time value to whole milliseconds (truncating sub-ms ticks).
    ///
    /// Equivalent to C `ossl_time2ms()` (`include/internal/time.h` line 45).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_ticks(1_500_000_000);
    /// assert_eq!(t.to_ms(), 1500);
    /// ```
    #[inline]
    pub const fn to_ms(self) -> u64 {
        self.ticks / Self::MS
    }

    /// Creates an [`OsslTime`] from a count of microseconds.
    ///
    /// Uses saturating multiplication: if `us * US` would overflow,
    /// returns [`OsslTime::INFINITE`].
    ///
    /// Equivalent to C `ossl_us2time()` (`include/internal/time.h` line 46).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_us(1_500_000);
    /// assert_eq!(t.to_seconds(), 1);
    /// assert_eq!(t.to_us(), 1_500_000);
    /// ```
    #[inline]
    pub fn from_us(us: u64) -> Self {
        OsslTime {
            ticks: us.checked_mul(Self::US).unwrap_or(u64::MAX),
        }
    }

    /// Converts this time value to whole microseconds (truncating sub-µs ticks).
    ///
    /// Equivalent to C `ossl_time2us()` (`include/internal/time.h` line 47).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_ms(42);
    /// assert_eq!(t.to_us(), 42_000);
    /// ```
    #[inline]
    pub const fn to_us(self) -> u64 {
        self.ticks / Self::US
    }

    /// Creates an [`OsslTime`] from a [`std::time::Duration`].
    ///
    /// Converts the `Duration`'s total nanoseconds (via [`Duration::as_nanos()`])
    /// to the internal tick count. If the duration exceeds `u64::MAX` nanoseconds
    /// (approximately 584 years), the result saturates to [`OsslTime::INFINITE`].
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    /// use std::time::Duration;
    ///
    /// let d = Duration::from_secs(5);
    /// let t = OsslTime::from_duration(d);
    /// assert_eq!(t.to_seconds(), 5);
    /// ```
    #[inline]
    pub fn from_duration(d: Duration) -> Self {
        let nanos = d.as_nanos();
        // Duration::as_nanos() returns u128; clamp to u64::MAX.
        // Rule R6: use try_from for lossless narrowing, not bare `as`.
        match u64::try_from(nanos) {
            Ok(t) => OsslTime { ticks: t },
            Err(_) => Self::INFINITE,
        }
    }

    /// Converts this time value to a [`std::time::Duration`].
    ///
    /// Returns `None` if this time is [`OsslTime::INFINITE`], since infinite
    /// time cannot be represented as a bounded `Duration`. This enforces
    /// **Rule R5** (nullability over sentinels).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    /// use std::time::Duration;
    ///
    /// let t = OsslTime::from_seconds(10);
    /// assert_eq!(t.to_duration(), Some(Duration::from_nanos(10_000_000_000)));
    ///
    /// assert_eq!(OsslTime::INFINITE.to_duration(), None);
    /// ```
    #[inline]
    pub fn to_duration(self) -> Option<Duration> {
        if self.is_infinite() {
            None
        } else {
            Some(Duration::from_nanos(self.ticks))
        }
    }

    /// Creates an [`OsslTime`] from a [`std::time::SystemTime`].
    ///
    /// Computes the duration since the Unix epoch and converts to nanosecond
    /// ticks. Returns an error if the system time is before the epoch (which
    /// would yield a negative duration).
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::Internal`] if the system clock reports a time
    /// before the Unix epoch.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    /// use std::time::{SystemTime, UNIX_EPOCH, Duration};
    ///
    /// let system_t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    /// let t = OsslTime::from_system_time(system_t).unwrap();
    /// assert_eq!(t.to_seconds(), 1_700_000_000);
    /// ```
    pub fn from_system_time(t: SystemTime) -> Result<Self, CommonError> {
        let d = t
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CommonError::Internal("system clock is before Unix epoch".to_string()))?;
        Ok(Self::from_duration(d))
    }

    /// Returns the current wall-clock time as an [`OsslTime`].
    ///
    /// Uses [`SystemTime::now()`] for cross-platform time retrieval,
    /// replacing the C implementation's platform-specific `gettimeofday()`
    /// (Unix) and `GetSystemTime()` (Windows) calls in `crypto/time.c`.
    ///
    /// On error (system clock before Unix epoch), returns [`OsslTime::ZERO`],
    /// matching the C fallback behaviour (`crypto/time.c` line 41–42).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let now = OsslTime::now();
    /// assert!(!now.is_zero()); // should be after the epoch
    /// ```
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Self::from_duration(d),
            Err(_) => Self::ZERO,
        }
    }

    /// Returns the zero time value.
    ///
    /// Convenience method equivalent to [`OsslTime::ZERO`]. Replaces C
    /// `ossl_time_zero()` (`include/internal/time.h` line 75–78).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// assert_eq!(OsslTime::zero(), OsslTime::ZERO);
    /// assert!(OsslTime::zero().is_zero());
    /// ```
    #[inline]
    pub const fn zero() -> Self {
        Self::ZERO
    }

    /// Returns the infinite (maximum) time value.
    ///
    /// Convenience method equivalent to [`OsslTime::INFINITE`]. Replaces C
    /// `ossl_time_infinite()` (`include/internal/time.h` line 80–83).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// assert_eq!(OsslTime::infinite(), OsslTime::INFINITE);
    /// assert!(OsslTime::infinite().is_infinite());
    /// ```
    #[inline]
    pub const fn infinite() -> Self {
        Self::INFINITE
    }
}

// =============================================================================
// Comparison
// =============================================================================

impl Ord for OsslTime {
    /// Compares two time values by their underlying tick counts.
    ///
    /// Equivalent to C `ossl_time_compare()` (`include/internal/time.h`
    /// line 138–145).
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.ticks.cmp(&other.ticks)
    }
}

impl PartialOrd for OsslTime {
    /// Partial ordering derived from the total [`Ord`] implementation.
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl OsslTime {
    /// Returns `true` if this time value equals [`OsslTime::ZERO`].
    ///
    /// Equivalent to C `ossl_time_is_zero()` (`include/internal/time.h`
    /// line 148–151).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// assert!(OsslTime::ZERO.is_zero());
    /// assert!(!OsslTime::from_seconds(1).is_zero());
    /// ```
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.ticks == 0
    }

    /// Returns `true` if this time value equals [`OsslTime::INFINITE`].
    ///
    /// Equivalent to C `ossl_time_is_infinite()` (`include/internal/time.h`
    /// line 154–157).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// assert!(OsslTime::INFINITE.is_infinite());
    /// assert!(!OsslTime::from_seconds(1).is_infinite());
    /// ```
    #[inline]
    pub const fn is_infinite(self) -> bool {
        self.ticks == u64::MAX
    }
}

// =============================================================================
// Saturating Arithmetic
// =============================================================================

impl OsslTime {
    /// Adds two time values with saturation: overflow → [`OsslTime::INFINITE`].
    ///
    /// Equivalent to C `ossl_time_add()` (`include/internal/time.h` line 159–166)
    /// which uses `safe_add_time()` and returns `ossl_time_infinite()` on overflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let a = OsslTime::from_seconds(3);
    /// let b = OsslTime::from_seconds(7);
    /// assert_eq!(a.saturating_add(b).to_seconds(), 10);
    ///
    /// // Overflow saturates to INFINITE
    /// let max = OsslTime::INFINITE;
    /// assert!(max.saturating_add(OsslTime::from_ticks(1)).is_infinite());
    /// ```
    #[inline]
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        OsslTime {
            ticks: self.ticks.checked_add(other.ticks).unwrap_or(u64::MAX),
        }
    }

    /// Subtracts one time value from another with saturation:
    /// underflow → [`OsslTime::ZERO`].
    ///
    /// Equivalent to C `ossl_time_subtract()` (`include/internal/time.h`
    /// line 168–175) which uses `safe_sub_time()` and returns
    /// `ossl_time_zero()` on underflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let a = OsslTime::from_seconds(10);
    /// let b = OsslTime::from_seconds(3);
    /// assert_eq!(a.saturating_sub(b).to_seconds(), 7);
    ///
    /// // Underflow saturates to ZERO
    /// let small = OsslTime::from_seconds(1);
    /// let big = OsslTime::from_seconds(100);
    /// assert!(small.saturating_sub(big).is_zero());
    /// ```
    #[inline]
    #[must_use]
    pub fn saturating_sub(self, other: Self) -> Self {
        OsslTime {
            ticks: self.ticks.saturating_sub(other.ticks),
        }
    }

    /// Computes the absolute difference between two time values: `|self − other|`.
    ///
    /// Equivalent to C `ossl_time_abs_difference()` (`include/internal/time.h`
    /// line 178–182).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let a = OsslTime::from_seconds(10);
    /// let b = OsslTime::from_seconds(3);
    /// assert_eq!(a.abs_difference(b).to_seconds(), 7);
    /// assert_eq!(b.abs_difference(a).to_seconds(), 7);
    /// ```
    #[inline]
    #[must_use]
    pub fn abs_difference(self, other: Self) -> Self {
        if self.ticks > other.ticks {
            self.saturating_sub(other)
        } else {
            other.saturating_sub(self)
        }
    }

    /// Multiplies a time value by an integer factor with saturation:
    /// overflow → [`OsslTime::INFINITE`].
    ///
    /// Equivalent to C `ossl_time_multiply()` (`include/internal/time.h`
    /// line 184–191) which uses `safe_mul_time()` and returns
    /// `ossl_time_infinite()` on overflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_seconds(5);
    /// assert_eq!(t.saturating_mul(3).to_seconds(), 15);
    ///
    /// // Overflow saturates to INFINITE
    /// assert!(OsslTime::INFINITE.saturating_mul(2).is_infinite());
    /// ```
    #[inline]
    #[must_use]
    pub fn saturating_mul(self, factor: u64) -> Self {
        OsslTime {
            ticks: self.ticks.checked_mul(factor).unwrap_or(u64::MAX),
        }
    }

    /// Divides a time value by an integer divisor.
    ///
    /// If `divisor` is zero, returns [`OsslTime::ZERO`] (matching the C
    /// behaviour of `ossl_time_divide()` in `include/internal/time.h`
    /// line 193–200, where division error yields `ossl_time_zero()`).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let t = OsslTime::from_seconds(15);
    /// assert_eq!(t.checked_div(3).to_seconds(), 5);
    ///
    /// // Division by zero yields ZERO
    /// assert!(OsslTime::from_seconds(10).checked_div(0).is_zero());
    /// ```
    #[inline]
    #[must_use]
    pub fn checked_div(self, divisor: u64) -> Self {
        self.ticks
            .checked_div(divisor)
            .map_or(Self::ZERO, OsslTime::from_ticks)
    }

    /// Returns the smaller of two time values.
    ///
    /// Equivalent to C `ossl_time_min()` (`include/internal/time.h`
    /// line 218–221).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let a = OsslTime::from_seconds(3);
    /// let b = OsslTime::from_seconds(7);
    /// assert_eq!(OsslTime::min(a, b), a);
    /// ```
    #[inline]
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        if self.ticks < other.ticks {
            self
        } else {
            other
        }
    }

    /// Returns the larger of two time values.
    ///
    /// Equivalent to C `ossl_time_max()` (`include/internal/time.h`
    /// line 212–215).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// let a = OsslTime::from_seconds(3);
    /// let b = OsslTime::from_seconds(7);
    /// assert_eq!(OsslTime::max(a, b), b);
    /// ```
    #[inline]
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if self.ticks > other.ticks {
            self
        } else {
            other
        }
    }
}

// =============================================================================
// Display
// =============================================================================

impl fmt::Display for OsslTime {
    /// Formats the time value as a human-readable string.
    ///
    /// - [`OsslTime::ZERO`] → `"0s"`
    /// - [`OsslTime::INFINITE`] → `"∞"`
    /// - Otherwise → `"X.XXXs"` (seconds with millisecond precision)
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    ///
    /// assert_eq!(format!("{}", OsslTime::ZERO), "0s");
    /// assert_eq!(format!("{}", OsslTime::INFINITE), "∞");
    /// assert_eq!(format!("{}", OsslTime::from_seconds(42)), "42.000s");
    /// assert_eq!(format!("{}", OsslTime::from_ms(1500)), "1.500s");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinite() {
            f.write_str("∞")
        } else if self.is_zero() {
            f.write_str("0s")
        } else {
            let secs = self.ticks / Self::SECOND;
            let ms_remainder = (self.ticks % Self::SECOND) / Self::MS;
            write!(f, "{secs}.{ms_remainder:03}s")
        }
    }
}

// =============================================================================
// Operator Trait Implementations
// =============================================================================

impl Add for OsslTime {
    type Output = Self;

    /// Adds two [`OsslTime`] values, delegating to [`OsslTime::saturating_add()`].
    ///
    /// Overflow saturates to [`OsslTime::INFINITE`].
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl Sub for OsslTime {
    type Output = Self;

    /// Subtracts one [`OsslTime`] from another, delegating to
    /// [`OsslTime::saturating_sub()`].
    ///
    /// Underflow saturates to [`OsslTime::ZERO`].
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

// =============================================================================
// Conversion Trait Implementations
// =============================================================================

impl From<Duration> for OsslTime {
    /// Converts a [`Duration`] to an [`OsslTime`], delegating to
    /// [`OsslTime::from_duration()`].
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    /// use std::time::Duration;
    ///
    /// let t: OsslTime = Duration::from_secs(5).into();
    /// assert_eq!(t.to_seconds(), 5);
    /// ```
    #[inline]
    fn from(d: Duration) -> Self {
        Self::from_duration(d)
    }
}

impl TryFrom<OsslTime> for Duration {
    type Error = CommonError;

    /// Attempts to convert an [`OsslTime`] to a [`Duration`].
    ///
    /// Fails with [`CommonError::InvalidArgument`] if the time value is
    /// [`OsslTime::INFINITE`], since infinite time cannot be represented
    /// as a bounded `Duration`.
    ///
    /// # Errors
    ///
    /// Returns [`CommonError::InvalidArgument`] when the time is infinite.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_common::time::OsslTime;
    /// use std::convert::TryFrom;
    /// use std::time::Duration;
    ///
    /// let t = OsslTime::from_seconds(10);
    /// let d = Duration::try_from(t).unwrap();
    /// assert_eq!(d, Duration::from_nanos(10_000_000_000));
    ///
    /// // INFINITE fails conversion
    /// assert!(Duration::try_from(OsslTime::INFINITE).is_err());
    /// ```
    fn try_from(t: OsslTime) -> Result<Self, Self::Error> {
        if t.is_infinite() {
            Err(CommonError::InvalidArgument(
                "cannot convert INFINITE OsslTime to Duration".to_string(),
            ))
        } else {
            Ok(Duration::from_nanos(t.ticks))
        }
    }
}
