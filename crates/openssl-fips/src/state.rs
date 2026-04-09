//! FIPS module state machine and per-test state tracking.
//!
//! Defines the core state types for the FIPS 140-3 compliance module:
//! module-level operational state (Init → `SelfTesting` → Running | Error)
//! and per-test execution state (Init → `InProgress` → Passed | Failed |
//! Implicit | Deferred). All state transitions are atomic for thread safety.
//!
//! # Architecture
//!
//! This module provides two layers of state management:
//!
//! 1. **Module-level state** ([`FipsState`]): Tracks the overall FIPS module
//!    lifecycle from initialization through self-testing to operational or
//!    error states. Stored in [`FIPS_MODULE_STATE`] as an [`AtomicU8`] for
//!    lock-free thread-safe access.
//!
//! 2. **Per-test state** ([`TestState`]): Tracks the execution state of each
//!    individual Known Answer Test (KAT) in the FIPS test catalog. Stored in
//!    the [`TEST_STATES`] array with a [`parking_lot::Mutex`] guard for writes.
//!
//! # C Source Mapping
//!
//! - `FipsState` ← `FIPS_STATE_*` defines (`self_test.c` lines 36–39)
//! - `TestState` ← `enum st_test_state` (`self_test.h` lines 62–69)
//! - `TestCategory` ← `enum st_test_category` (`self_test.h` lines 48–60)
//! - `FIPS_MODULE_STATE` ← `TSAN_QUALIFIER int FIPS_state` (`self_test.c` line 187)
//! - `set_fips_state` / `get_fips_state` ← (`self_test.c` lines 267–276)
//! - `get_test_state` / `set_test_state` ← `ossl_get/set_self_test_state` (`self_test.c` lines 81–91)
//! - `ErrorRateLimiter` ← rate-limited error reporting (`self_test.c` line 45, lines 458–469)

use std::fmt;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use parking_lot::Mutex;

// ---------------------------------------------------------------------------
// Module-Level FIPS State (self_test.c lines 36–39)
// ---------------------------------------------------------------------------

/// FIPS module operational state.
///
/// Represents the lifecycle of the FIPS module from initialization through
/// self-testing to either operational or error states.
///
/// # State Machine
///
/// ```text
/// Init ──→ SelfTesting ──→ Running  (POST succeeded)
///                      └──→ Error    (POST or runtime failure)
/// ```
///
/// Once in the [`Error`](FipsState::Error) state, the module cannot recover
/// without full re-initialization via [`reset_fips_state`].
///
/// # C Equivalence
///
/// Replaces the C `#define` constants:
/// - `FIPS_STATE_INIT     0`
/// - `FIPS_STATE_SELFTEST 1`
/// - `FIPS_STATE_RUNNING  2`
/// - `FIPS_STATE_ERROR    3`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FipsState {
    /// Module loaded but Power-On Self-Test (POST) not yet executed.
    Init = 0,
    /// Power-On Self-Test is currently executing. During this state,
    /// crypto operations are permitted internally (for KAT execution).
    SelfTesting = 1,
    /// POST completed successfully — module is fully operational.
    Running = 2,
    /// POST or runtime failure — module is non-operational.
    /// All crypto operations will be refused until re-initialization.
    Error = 3,
}

impl FipsState {
    /// Converts a raw `u8` value to a `FipsState` variant.
    ///
    /// Returns `None` for values outside the valid range (0–3),
    /// enforcing Rule R5 (nullability over sentinels).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_fips::state::FipsState;
    ///
    /// assert_eq!(FipsState::from_u8(0), Some(FipsState::Init));
    /// assert_eq!(FipsState::from_u8(2), Some(FipsState::Running));
    /// assert_eq!(FipsState::from_u8(99), None);
    /// ```
    #[inline]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Init),
            1 => Some(Self::SelfTesting),
            2 => Some(Self::Running),
            3 => Some(Self::Error),
            _ => None, // Rule R5: None instead of sentinel value
        }
    }

    /// Returns the `u8` representation of this state.
    ///
    /// This is a lossless conversion guaranteed by `#[repr(u8)]`.
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the module is in an operational state.
    ///
    /// Both [`Running`](FipsState::Running) and
    /// [`SelfTesting`](FipsState::SelfTesting) are considered operational
    /// because the self-test itself needs to use crypto operations internally
    /// to execute Known Answer Tests.
    ///
    /// This mirrors the C `ossl_prov_is_running()` function behavior
    /// (`self_test.c` line 464) where both `FIPS_STATE_RUNNING` and
    /// `FIPS_STATE_SELFTEST` return `1`.
    #[inline]
    pub fn is_operational(self) -> bool {
        matches!(self, Self::Running | Self::SelfTesting)
    }
}

impl fmt::Display for FipsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => f.write_str("init"),
            Self::SelfTesting => f.write_str("self-testing"),
            Self::Running => f.write_str("running"),
            Self::Error => f.write_str("error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-Test Execution State (self_test.h lines 62–69)
// ---------------------------------------------------------------------------

/// Per-test execution state in the KAT catalog.
///
/// Tracks the lifecycle of each individual Known Answer Test from initial
/// state through execution to completion.
///
/// # State Machine
///
/// ```text
/// Init ──→ InProgress ──→ Passed    (test output matched expected)
///                     ├──→ Failed    (test output mismatch or error)
///                     ├──→ Implicit  (dependency chain completed)
///                     └──→ Deferred  (lazy execution on first use)
/// ```
///
/// # C Equivalence
///
/// Replaces `enum st_test_state` from `self_test.h` lines 62–69:
/// - `SELF_TEST_STATE_INIT       = 0`
/// - `SELF_TEST_STATE_IN_PROGRESS = 1`
/// - `SELF_TEST_STATE_PASSED     = 2`
/// - `SELF_TEST_STATE_FAILED     = 3`
/// - `SELF_TEST_STATE_IMPLICIT   = 4`
/// - `SELF_TEST_STATE_DEFER      = 5`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TestState {
    /// Test has not yet been executed.
    Init = 0,
    /// Test execution is currently in progress.
    InProgress = 1,
    /// Test completed successfully — output matched expected value.
    Passed = 2,
    /// Test failed — output did not match expected value or an error occurred.
    Failed = 3,
    /// Test implicitly passed because its dependency chain completed
    /// successfully (no explicit execution needed for this test).
    Implicit = 4,
    /// Test deferred for lazy execution on first algorithm use.
    /// Used when `is_deferred_test` is set in POST parameters.
    Deferred = 5,
}

impl TestState {
    /// Converts a raw `u8` value to a `TestState` variant.
    ///
    /// Returns `None` for values outside the valid range (0–5),
    /// enforcing Rule R5 (nullability over sentinels).
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_fips::state::TestState;
    ///
    /// assert_eq!(TestState::from_u8(0), Some(TestState::Init));
    /// assert_eq!(TestState::from_u8(5), Some(TestState::Deferred));
    /// assert_eq!(TestState::from_u8(6), None);
    /// ```
    #[inline]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Init),
            1 => Some(Self::InProgress),
            2 => Some(Self::Passed),
            3 => Some(Self::Failed),
            4 => Some(Self::Implicit),
            5 => Some(Self::Deferred),
            _ => None, // Rule R5: None instead of sentinel value
        }
    }

    /// Returns the `u8` representation of this state.
    ///
    /// This is a lossless conversion guaranteed by `#[repr(u8)]`.
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the test has reached a terminal state.
    ///
    /// A test is complete when it has passed, failed, or been implicitly
    /// resolved. Tests that are still in `Init`, `InProgress`, or `Deferred`
    /// state are not considered complete.
    #[inline]
    pub fn is_complete(self) -> bool {
        matches!(self, Self::Passed | Self::Failed | Self::Implicit)
    }

    /// Returns `true` if the test completed successfully.
    ///
    /// Both [`Passed`](TestState::Passed) and [`Implicit`](TestState::Implicit)
    /// are considered successful outcomes.
    #[inline]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Passed | Self::Implicit)
    }
}

impl fmt::Display for TestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => f.write_str("init"),
            Self::InProgress => f.write_str("in-progress"),
            Self::Passed => f.write_str("passed"),
            Self::Failed => f.write_str("failed"),
            Self::Implicit => f.write_str("implicit"),
            Self::Deferred => f.write_str("deferred"),
        }
    }
}

// ---------------------------------------------------------------------------
// KAT Test Category (self_test.h lines 48–60)
// ---------------------------------------------------------------------------

/// KAT test category identifying the type of algorithm being tested.
///
/// Each test in the FIPS KAT catalog belongs to exactly one category,
/// which determines which executor function handles its execution.
///
/// # C Equivalence
///
/// Replaces `enum st_test_category` from `self_test.h` lines 48–60:
/// - `SELF_TEST_INTEGRITY`
/// - `SELF_TEST_KAT_DIGEST`
/// - `SELF_TEST_KAT_CIPHER`
/// - `SELF_TEST_KAT_SIGNATURE`
/// - `SELF_TEST_KAT_KDF`
/// - `SELF_TEST_KAT_DRBG`
/// - `SELF_TEST_KAT_KAS`
/// - `SELF_TEST_KAT_ASYM_KEYGEN`
/// - `SELF_TEST_KAT_KEM`
/// - `SELF_TEST_KAT_ASYM_CIPHER`
/// - `SELF_TEST_KAT_MAC`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestCategory {
    /// Module integrity verification using HMAC-SHA256 over the module binary.
    Integrity,
    /// Known Answer Test for digest algorithms (SHA-1, SHA-2, SHA-3, SHAKE).
    Digest,
    /// Known Answer Test for cipher algorithms (AES-GCM, AES-CBC, etc.).
    Cipher,
    /// Known Answer Test for signature algorithms (RSA, ECDSA, `EdDSA`, ML-DSA, SLH-DSA).
    Signature,
    /// Known Answer Test for key derivation functions (HKDF, PBKDF2, KBKDF, etc.).
    Kdf,
    /// Known Answer Test for deterministic random bit generators
    /// (CTR-DRBG, HASH-DRBG, HMAC-DRBG).
    Drbg,
    /// Known Answer Test for key agreement schemes (DH, ECDH).
    Kas,
    /// Known Answer Test for asymmetric key generation (ML-DSA, SLH-DSA).
    AsymKeygen,
    /// Known Answer Test for key encapsulation mechanisms (ML-KEM).
    Kem,
    /// Known Answer Test for asymmetric ciphers (RSA encrypt/decrypt).
    AsymCipher,
    /// Known Answer Test for message authentication codes (HMAC, CMAC, KMAC).
    Mac,
}

impl TestCategory {
    /// Returns the human-readable display name for this test category.
    ///
    /// These names match the C string constants used in FIPS self-test
    /// event reporting and error messages.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_fips::state::TestCategory;
    ///
    /// assert_eq!(TestCategory::Integrity.display_name(), "Verify_Integrity");
    /// assert_eq!(TestCategory::Digest.display_name(), "KAT_Digest");
    /// ```
    #[inline]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Integrity => "Verify_Integrity",
            Self::Digest => "KAT_Digest",
            Self::Cipher => "KAT_Cipher",
            Self::Signature => "KAT_Signature",
            Self::Kdf => "KAT_KDF",
            Self::Drbg => "DRBG",
            Self::Kas => "KAT_KA",
            Self::AsymKeygen => "KAT_AsymmetricKeyGen",
            Self::Kem => "KAT_KEM",
            Self::AsymCipher => "KAT_AsymmetricCipher",
            Self::Mac => "KAT_MAC",
        }
    }
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of tests in the FIPS KAT catalog.
///
/// This is a conservative upper bound matching the C `ST_ID_MAX` from
/// `self_test.h`. The actual number of tests may be smaller, but this
/// value must be large enough to accommodate all defined KATs plus
/// future additions.
pub const MAX_TEST_COUNT: usize = 64;

/// Maximum number of FIPS error state reports before rate limiting kicks in.
///
/// Matches the C constant `FIPS_ERROR_REPORTING_RATE_LIMIT = 10` from
/// `self_test.c` line 45. After this many error reports, subsequent errors
/// are silently counted to prevent log flooding.
pub const ERROR_REPORT_LIMIT: u32 = 10;

// ---------------------------------------------------------------------------
// Global Module State (self_test.c line 187)
// ---------------------------------------------------------------------------

/// Global FIPS module state. Uses [`AtomicU8`] for lock-free thread-safe access.
///
/// Replaces the C `TSAN_QUALIFIER int FIPS_state` with Rust atomics.
///
/// [`Ordering::SeqCst`] is used because state transitions are critical for
/// FIPS compliance — a relaxed read of a stale state could allow non-approved
/// operations during the [`Error`](FipsState::Error) state, which would
/// constitute a FIPS 140-3 compliance violation.
pub static FIPS_MODULE_STATE: AtomicU8 = AtomicU8::new(FipsState::Init as u8);

// ---------------------------------------------------------------------------
// Per-Test State Array (replaces st_all_tests[].state)
// ---------------------------------------------------------------------------

/// Per-test state tracking array. Each element is an [`AtomicU8`] encoding
/// a [`TestState`].
///
/// Uses atomic operations for lock-free concurrent state reads with locked
/// writes (via [`TEST_STATES_LOCK`]). The array is indexed by test ID
/// (0..`MAX_TEST_COUNT`).
///
/// # Concurrency Model
///
/// - **Reads** use [`Ordering::Relaxed`] for performance. Benign races on
///   reads are acceptable — the worst case is a redundant test execution,
///   not incorrect results.
/// - **Writes** require holding [`TEST_STATES_LOCK`] to prevent concurrent
///   state corruption when multiple threads attempt to update the same test.
pub static TEST_STATES: [AtomicU8; MAX_TEST_COUNT] = {
    // Justification: This const is used solely to initialize a static array
    // of AtomicU8 values. The interior mutability is intentional — the static
    // array IS the mutable state. This is the idiomatic Rust pattern for
    // initializing arrays of atomic types, as AtomicU8::new() is const.
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: AtomicU8 = AtomicU8::new(TestState::Init as u8);
    [INIT; MAX_TEST_COUNT]
};

/// Lock protecting test state write operations.
///
// LOCK-SCOPE: TEST_STATES_LOCK guards writes to the TEST_STATES array.
// Reads use relaxed atomic loads for performance (benign races:
// worst case is redundant test execution, not incorrect results).
// Writes require the lock to prevent concurrent state corruption
// when multiple threads attempt to update the same test's state.
// Contention is low: writes happen only during POST execution
// (at most MAX_TEST_COUNT writes in sequence) and deferred test
// execution (one write per first-use algorithm invocation).
static TEST_STATES_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Module State Accessors (self_test.c lines 267–276)
// ---------------------------------------------------------------------------

/// Sets the FIPS module state atomically.
///
/// Uses [`Ordering::SeqCst`] to ensure all threads observe the state
/// transition immediately. Emits a structured debug trace event for
/// observability.
///
/// # C Equivalence
///
/// Replaces `set_fips_state()` from `self_test.c` lines 267–270:
/// ```c
/// static void set_fips_state(int state) {
///     tsan_store(&FIPS_state, state);
/// }
/// ```
pub fn set_fips_state(state: FipsState) {
    FIPS_MODULE_STATE.store(state.as_u8(), Ordering::SeqCst);
    tracing::debug!(
        state = %state,
        state_u8 = state.as_u8(),
        "FIPS module state transition"
    );
}

/// Gets the current FIPS module state atomically.
///
/// Uses [`Ordering::SeqCst`] to ensure a consistent view of the module
/// state across all threads. If the stored value is invalid (which should
/// never happen in practice since only valid values are stored), defaults
/// to [`FipsState::Error`] as a conservative safety measure.
///
/// # C Equivalence
///
/// Replaces direct reads of `FIPS_state` and the `ossl_fips_self_testing()`
/// check from `self_test.c` lines 272–276.
pub fn get_fips_state() -> FipsState {
    let raw = FIPS_MODULE_STATE.load(Ordering::SeqCst);
    // Safety rationale for unwrap_or: Only valid u8 values (0–3) are ever
    // stored via set_fips_state(). However, if an invalid value were somehow
    // present, returning Error is the safest default — it prevents any
    // crypto operations from proceeding, which is the correct FIPS behavior
    // for an inconsistent state.
    FipsState::from_u8(raw).unwrap_or(FipsState::Error)
}

/// Resets the FIPS module state to [`FipsState::Init`].
///
/// This is used during module re-initialization to return the module
/// to its initial state. After calling this, a new POST must be run
/// before the module can be used for crypto operations.
///
/// Also resets all per-test states to [`TestState::Init`] via
/// [`reset_all_states`].
pub fn reset_fips_state() {
    reset_all_states();
    FIPS_MODULE_STATE.store(FipsState::Init as u8, Ordering::SeqCst);
    tracing::debug!("FIPS module state reset to Init");
}

// ---------------------------------------------------------------------------
// Per-Test State Accessors (self_test.c lines 81–91)
// ---------------------------------------------------------------------------

/// Gets the execution state of a specific test by ID.
///
/// Returns `None` if the test ID is out of bounds (>= [`MAX_TEST_COUNT`])
/// or if the stored value is not a valid [`TestState`] variant.
/// Rule R5: Uses `Option` for out-of-bounds IDs instead of sentinel values.
///
/// Uses [`Ordering::Relaxed`] for reads — see [`TEST_STATES`] documentation
/// for the concurrency model rationale.
///
/// # C Equivalence
///
/// Replaces `ossl_get_self_test_state()` from `self_test.c` lines 81–85:
/// ```c
/// int ossl_get_self_test_state(int id) {
///     return tsan_load(&st_all_tests[id].state);
/// }
/// ```
pub fn get_test_state(id: usize) -> Option<TestState> {
    if id >= MAX_TEST_COUNT {
        return None; // Rule R5: Option for out-of-bounds
    }
    TestState::from_u8(TEST_STATES[id].load(Ordering::Relaxed))
}

/// Sets the execution state of a specific test by ID.
///
/// Acquires [`TEST_STATES_LOCK`] to prevent concurrent state corruption.
/// Returns `false` if the test ID is out of bounds (>= [`MAX_TEST_COUNT`]).
///
/// Uses [`Ordering::SeqCst`] for writes to ensure all threads observe
/// the state change immediately (important for dependency resolution
/// in [`crate::kats`]).
///
/// # C Equivalence
///
/// Replaces `ossl_set_self_test_state()` from `self_test.c` lines 87–91:
/// ```c
/// void ossl_set_self_test_state(int id, int state) {
///     CRYPTO_THREAD_write_lock(self_test_states_lock);
///     tsan_store(&st_all_tests[id].state, state);
///     CRYPTO_THREAD_unlock(self_test_states_lock);
/// }
/// ```
pub fn set_test_state(id: usize, state: TestState) -> bool {
    if id >= MAX_TEST_COUNT {
        return false;
    }
    let _lock = TEST_STATES_LOCK.lock();
    TEST_STATES[id].store(state.as_u8(), Ordering::SeqCst);
    tracing::debug!(
        test_id = id,
        state = %state,
        "Test state transition"
    );
    true
}

// ---------------------------------------------------------------------------
// Bulk State Operations
// ---------------------------------------------------------------------------

/// Marks all test states as [`TestState::Deferred`].
///
/// Called during deferred POST setup when the `is_deferred_test` configuration
/// parameter is set. In deferred mode, tests are not executed during POST but
/// instead run lazily on first algorithm use.
///
/// Acquires [`TEST_STATES_LOCK`] for the duration of the bulk update.
///
/// # C Equivalence
///
/// Replaces the deferred marking loop in `self_test.c` `SELF_TEST_post()`
/// (lines 361–372):
/// ```c
/// for (i = 0; i < st_count; ++i)
///     ossl_set_self_test_state(i, SELF_TEST_STATE_DEFER);
/// ```
pub fn mark_all_deferred() {
    let _lock = TEST_STATES_LOCK.lock();
    for state in &TEST_STATES {
        state.store(TestState::Deferred as u8, Ordering::SeqCst);
    }
    tracing::debug!("All {} tests marked as deferred", MAX_TEST_COUNT);
}

/// Resets all test states to [`TestState::Init`].
///
/// Called during module re-initialization to clear all previous test results.
/// After calling this, all tests must be re-executed before the module can
/// be considered operational.
///
/// Acquires [`TEST_STATES_LOCK`] for the duration of the bulk update.
pub fn reset_all_states() {
    let _lock = TEST_STATES_LOCK.lock();
    for state in &TEST_STATES {
        state.store(TestState::Init as u8, Ordering::SeqCst);
    }
    tracing::debug!("All {} test states reset to Init", MAX_TEST_COUNT);
}

/// Checks if all tests in the range `0..count` have passed successfully.
///
/// A test is considered successful if its state is [`TestState::Passed`]
/// or [`TestState::Implicit`] (dependency resolved without explicit
/// execution).
///
/// Returns `true` if all tests in range passed; `false` if any test
/// has not completed successfully or if `count` is zero.
///
/// The `count` parameter is clamped to [`MAX_TEST_COUNT`] to prevent
/// out-of-bounds access.
///
/// # C Equivalence
///
/// Replaces the post-KAT verification in `self_test.c` `SELF_TEST_post()`
/// that checks all test states after execution.
pub fn all_tests_passed(count: usize) -> bool {
    if count == 0 {
        return false;
    }
    let effective_count = count.min(MAX_TEST_COUNT);
    (0..effective_count).all(|id| get_test_state(id).map_or(false, TestState::is_success))
}

// ---------------------------------------------------------------------------
// Error Reporting Rate Limiter (self_test.c line 45, lines 458–469)
// ---------------------------------------------------------------------------

/// Rate limiter for FIPS error state reporting.
///
/// After [`limit`](ErrorRateLimiter::limit) errors are reported, subsequent
/// errors are silently counted. This prevents log flooding when the FIPS
/// module enters the error state and many concurrent operations attempt
/// to report the failure.
///
/// # C Equivalence
///
/// Replaces the rate-limited error reporting pattern in `ossl_prov_is_running()`
/// (`self_test.c` lines 458–469):
/// ```c
/// static TSAN_QUALIFIER int rate_limit = 0;
/// if (tsan_counter(&rate_limit) < FIPS_ERROR_REPORTING_RATE_LIMIT)
///     ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_IN_ERROR_STATE);
/// ```
pub struct ErrorRateLimiter {
    /// Monotonically increasing counter of error occurrences.
    count: AtomicU32,
    /// Maximum number of errors that will be actively reported.
    limit: u32,
}

impl ErrorRateLimiter {
    /// Creates a new rate limiter with the specified reporting limit.
    ///
    /// The first `limit` calls to [`should_report`](Self::should_report)
    /// will return `true`; all subsequent calls return `false`.
    #[inline]
    pub const fn new(limit: u32) -> Self {
        Self {
            count: AtomicU32::new(0),
            limit,
        }
    }

    /// Returns `true` if this error should be reported (under rate limit).
    ///
    /// Atomically increments the error counter and returns `true` if the
    /// previous count was below the limit. Uses [`Ordering::Relaxed`]
    /// because exact ordering is not critical for rate limiting — benign
    /// races may result in at most one extra or one fewer log line, which
    /// is acceptable.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl_fips::state::ErrorRateLimiter;
    ///
    /// let limiter = ErrorRateLimiter::new(2);
    /// assert!(limiter.should_report());  // count 0 < 2
    /// assert!(limiter.should_report());  // count 1 < 2
    /// assert!(!limiter.should_report()); // count 2 >= 2
    /// ```
    #[inline]
    pub fn should_report(&self) -> bool {
        self.count.fetch_add(1, Ordering::Relaxed) < self.limit
    }
}

/// Global FIPS error rate limiter instance.
///
/// Limits error state reporting to [`ERROR_REPORT_LIMIT`] (10) messages
/// to prevent log flooding when the module is in an error state.
///
/// Used by `self_test::is_running()` and other operational guard functions
/// to control how many times the "FIPS module in error state" message
/// is emitted.
pub static FIPS_ERROR_LIMITER: ErrorRateLimiter = ErrorRateLimiter::new(ERROR_REPORT_LIMIT);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- FipsState tests ---

    #[test]
    fn fips_state_from_u8_valid() {
        assert_eq!(FipsState::from_u8(0), Some(FipsState::Init));
        assert_eq!(FipsState::from_u8(1), Some(FipsState::SelfTesting));
        assert_eq!(FipsState::from_u8(2), Some(FipsState::Running));
        assert_eq!(FipsState::from_u8(3), Some(FipsState::Error));
    }

    #[test]
    fn fips_state_from_u8_invalid() {
        assert_eq!(FipsState::from_u8(4), None);
        assert_eq!(FipsState::from_u8(255), None);
    }

    #[test]
    fn fips_state_as_u8_roundtrip() {
        for val in 0..=3u8 {
            let state = FipsState::from_u8(val).expect("valid value");
            assert_eq!(state.as_u8(), val);
        }
    }

    #[test]
    fn fips_state_is_operational() {
        assert!(!FipsState::Init.is_operational());
        assert!(FipsState::SelfTesting.is_operational());
        assert!(FipsState::Running.is_operational());
        assert!(!FipsState::Error.is_operational());
    }

    #[test]
    fn fips_state_display() {
        assert_eq!(format!("{}", FipsState::Init), "init");
        assert_eq!(format!("{}", FipsState::SelfTesting), "self-testing");
        assert_eq!(format!("{}", FipsState::Running), "running");
        assert_eq!(format!("{}", FipsState::Error), "error");
    }

    // --- TestState tests ---

    #[test]
    fn test_state_from_u8_valid() {
        assert_eq!(TestState::from_u8(0), Some(TestState::Init));
        assert_eq!(TestState::from_u8(1), Some(TestState::InProgress));
        assert_eq!(TestState::from_u8(2), Some(TestState::Passed));
        assert_eq!(TestState::from_u8(3), Some(TestState::Failed));
        assert_eq!(TestState::from_u8(4), Some(TestState::Implicit));
        assert_eq!(TestState::from_u8(5), Some(TestState::Deferred));
    }

    #[test]
    fn test_state_from_u8_invalid() {
        assert_eq!(TestState::from_u8(6), None);
        assert_eq!(TestState::from_u8(255), None);
    }

    #[test]
    fn test_state_as_u8_roundtrip() {
        for val in 0..=5u8 {
            let state = TestState::from_u8(val).expect("valid value");
            assert_eq!(state.as_u8(), val);
        }
    }

    #[test]
    fn test_state_is_complete() {
        assert!(!TestState::Init.is_complete());
        assert!(!TestState::InProgress.is_complete());
        assert!(TestState::Passed.is_complete());
        assert!(TestState::Failed.is_complete());
        assert!(TestState::Implicit.is_complete());
        assert!(!TestState::Deferred.is_complete());
    }

    #[test]
    fn test_state_is_success() {
        assert!(!TestState::Init.is_success());
        assert!(!TestState::InProgress.is_success());
        assert!(TestState::Passed.is_success());
        assert!(!TestState::Failed.is_success());
        assert!(TestState::Implicit.is_success());
        assert!(!TestState::Deferred.is_success());
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", TestState::Init), "init");
        assert_eq!(format!("{}", TestState::InProgress), "in-progress");
        assert_eq!(format!("{}", TestState::Passed), "passed");
        assert_eq!(format!("{}", TestState::Failed), "failed");
        assert_eq!(format!("{}", TestState::Implicit), "implicit");
        assert_eq!(format!("{}", TestState::Deferred), "deferred");
    }

    // --- TestCategory tests ---

    #[test]
    fn test_category_display_names() {
        assert_eq!(TestCategory::Integrity.display_name(), "Verify_Integrity");
        assert_eq!(TestCategory::Digest.display_name(), "KAT_Digest");
        assert_eq!(TestCategory::Cipher.display_name(), "KAT_Cipher");
        assert_eq!(TestCategory::Signature.display_name(), "KAT_Signature");
        assert_eq!(TestCategory::Kdf.display_name(), "KAT_KDF");
        assert_eq!(TestCategory::Drbg.display_name(), "DRBG");
        assert_eq!(TestCategory::Kas.display_name(), "KAT_KA");
        assert_eq!(
            TestCategory::AsymKeygen.display_name(),
            "KAT_AsymmetricKeyGen"
        );
        assert_eq!(TestCategory::Kem.display_name(), "KAT_KEM");
        assert_eq!(
            TestCategory::AsymCipher.display_name(),
            "KAT_AsymmetricCipher"
        );
        assert_eq!(TestCategory::Mac.display_name(), "KAT_MAC");
    }

    #[test]
    fn test_category_display_trait() {
        assert_eq!(format!("{}", TestCategory::Integrity), "Verify_Integrity");
        assert_eq!(format!("{}", TestCategory::Mac), "KAT_MAC");
    }

    #[test]
    fn test_category_covers_all_eleven() {
        // Ensure all 11 categories are distinct
        let categories = [
            TestCategory::Integrity,
            TestCategory::Digest,
            TestCategory::Cipher,
            TestCategory::Signature,
            TestCategory::Kdf,
            TestCategory::Drbg,
            TestCategory::Kas,
            TestCategory::AsymKeygen,
            TestCategory::Kem,
            TestCategory::AsymCipher,
            TestCategory::Mac,
        ];
        // Verify all are unique by collecting into a set
        let mut names = std::collections::HashSet::new();
        for cat in &categories {
            assert!(names.insert(cat.display_name()), "duplicate category name");
        }
        assert_eq!(names.len(), 11);
    }

    // --- ErrorRateLimiter tests ---

    #[test]
    fn error_rate_limiter_basic() {
        let limiter = ErrorRateLimiter::new(3);
        assert!(limiter.should_report()); // count 0 < 3
        assert!(limiter.should_report()); // count 1 < 3
        assert!(limiter.should_report()); // count 2 < 3
        assert!(!limiter.should_report()); // count 3 >= 3
        assert!(!limiter.should_report()); // count 4 >= 3
    }

    #[test]
    fn error_rate_limiter_zero_limit() {
        let limiter = ErrorRateLimiter::new(0);
        assert!(!limiter.should_report()); // count 0 >= 0
    }

    #[test]
    fn error_report_limit_matches_c() {
        // C: FIPS_ERROR_REPORTING_RATE_LIMIT = 10 (self_test.c line 45)
        assert_eq!(ERROR_REPORT_LIMIT, 10);
    }

    // --- Global state tests ---
    // Note: These tests must be run serially because they modify global state.
    // In practice, cargo test runs each test binary in a single thread by default,
    // but we reset state after each test to avoid cross-test contamination.

    #[test]
    fn fips_module_state_default_is_init() {
        // After any previous tests, reset to known state
        FIPS_MODULE_STATE.store(FipsState::Init as u8, Ordering::SeqCst);
        assert_eq!(get_fips_state(), FipsState::Init);
    }

    #[test]
    fn set_and_get_fips_state_transitions() {
        set_fips_state(FipsState::SelfTesting);
        assert_eq!(get_fips_state(), FipsState::SelfTesting);

        set_fips_state(FipsState::Running);
        assert_eq!(get_fips_state(), FipsState::Running);

        set_fips_state(FipsState::Error);
        assert_eq!(get_fips_state(), FipsState::Error);

        // Reset for other tests
        set_fips_state(FipsState::Init);
    }

    #[test]
    fn get_fips_state_invalid_defaults_to_error() {
        // Store an invalid value directly
        FIPS_MODULE_STATE.store(99, Ordering::SeqCst);
        assert_eq!(get_fips_state(), FipsState::Error);

        // Restore valid state
        FIPS_MODULE_STATE.store(FipsState::Init as u8, Ordering::SeqCst);
    }

    #[test]
    fn reset_fips_state_restores_init() {
        set_fips_state(FipsState::Running);
        assert_eq!(get_fips_state(), FipsState::Running);

        reset_fips_state();
        assert_eq!(get_fips_state(), FipsState::Init);
    }

    // --- Per-test state tests ---

    #[test]
    fn get_test_state_out_of_bounds() {
        assert_eq!(get_test_state(MAX_TEST_COUNT), None);
        assert_eq!(get_test_state(MAX_TEST_COUNT + 1), None);
        assert_eq!(get_test_state(usize::MAX), None);
    }

    #[test]
    fn set_test_state_out_of_bounds() {
        assert!(!set_test_state(MAX_TEST_COUNT, TestState::Passed));
        assert!(!set_test_state(usize::MAX, TestState::Passed));
    }

    #[test]
    fn set_and_get_test_state() {
        // Reset first
        reset_all_states();

        assert!(set_test_state(0, TestState::InProgress));
        assert_eq!(get_test_state(0), Some(TestState::InProgress));

        assert!(set_test_state(0, TestState::Passed));
        assert_eq!(get_test_state(0), Some(TestState::Passed));

        assert!(set_test_state(MAX_TEST_COUNT - 1, TestState::Failed));
        assert_eq!(get_test_state(MAX_TEST_COUNT - 1), Some(TestState::Failed));

        // Cleanup
        reset_all_states();
    }

    #[test]
    fn mark_all_deferred_sets_all() {
        reset_all_states();
        mark_all_deferred();

        for id in 0..MAX_TEST_COUNT {
            assert_eq!(
                get_test_state(id),
                Some(TestState::Deferred),
                "test {} should be Deferred",
                id
            );
        }

        // Cleanup
        reset_all_states();
    }

    #[test]
    fn reset_all_states_clears_all() {
        mark_all_deferred();
        reset_all_states();

        for id in 0..MAX_TEST_COUNT {
            assert_eq!(
                get_test_state(id),
                Some(TestState::Init),
                "test {} should be Init after reset",
                id
            );
        }
    }

    #[test]
    fn all_tests_passed_with_zero_count() {
        assert!(!all_tests_passed(0));
    }

    #[test]
    fn all_tests_passed_basic() {
        reset_all_states();

        // Set first 3 tests as passed
        assert!(set_test_state(0, TestState::Passed));
        assert!(set_test_state(1, TestState::Implicit));
        assert!(set_test_state(2, TestState::Passed));

        assert!(all_tests_passed(3));
        assert!(!all_tests_passed(4)); // test 3 is still Init

        // Cleanup
        reset_all_states();
    }

    #[test]
    fn all_tests_passed_with_failure() {
        reset_all_states();

        assert!(set_test_state(0, TestState::Passed));
        assert!(set_test_state(1, TestState::Failed));

        assert!(!all_tests_passed(2));

        // Cleanup
        reset_all_states();
    }

    #[test]
    fn all_tests_passed_clamps_to_max() {
        reset_all_states();

        // Set all tests as passed
        let _lock = TEST_STATES_LOCK.lock();
        for state in &TEST_STATES {
            state.store(TestState::Passed as u8, Ordering::SeqCst);
        }
        drop(_lock);

        // Should work even with count > MAX_TEST_COUNT
        assert!(all_tests_passed(MAX_TEST_COUNT + 100));

        // Cleanup
        reset_all_states();
    }

    // --- Constants verification ---

    #[test]
    fn max_test_count_is_sufficient() {
        // The C self_test.h defines categories with at most ~30 tests
        // per the ST_ID enumeration. 64 is a conservative upper bound.
        assert!(MAX_TEST_COUNT >= 32, "MAX_TEST_COUNT should be at least 32");
    }

    #[test]
    fn fips_state_values_match_c() {
        // C defines: INIT=0, SELFTEST=1, RUNNING=2, ERROR=3
        assert_eq!(FipsState::Init as u8, 0);
        assert_eq!(FipsState::SelfTesting as u8, 1);
        assert_eq!(FipsState::Running as u8, 2);
        assert_eq!(FipsState::Error as u8, 3);
    }

    #[test]
    fn test_state_values_match_c() {
        // C defines: INIT=0, IN_PROGRESS=1, PASSED=2, FAILED=3, IMPLICIT=4, DEFER=5
        assert_eq!(TestState::Init as u8, 0);
        assert_eq!(TestState::InProgress as u8, 1);
        assert_eq!(TestState::Passed as u8, 2);
        assert_eq!(TestState::Failed as u8, 3);
        assert_eq!(TestState::Implicit as u8, 4);
        assert_eq!(TestState::Deferred as u8, 5);
    }
}
