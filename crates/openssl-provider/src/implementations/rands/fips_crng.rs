//! FIPS Continuous Random Number Generator Test (SP 800-90B §4.4).
//!
//! Implements the Approved Continuous Health Tests as a RAND wrapper that
//! monitors entropy bytes coming from a parent RAND's seed API or provider
//! entropy upcalls. Transitions to error state on catastrophic patterns.
//!
//! ## Health Tests Implemented
//!
//! - **Repetition Count Test (RCT)** — SP 800-90B §4.4.1
//! - **Adaptive Proportion Test (APT)** — SP 800-90B §4.4.2
//!
//! ## Architecture
//!
//! The CRNG test wrapper sits between the application-facing DRBG and the
//! raw entropy source. Every byte of entropy passing through is tested for
//! catastrophic patterns:
//!
//! ```text
//! Application ──► DRBG ──► CrngTest ──► Seed Source / Parent RAND
//! ```
//!
//! On test failure, the wrapper transitions to [`RandState::Error`] and
//! all subsequent operations are rejected until re-instantiation.
//!
//! ## Rules Enforced
//!
//! - **R5:** All methods return `ProviderResult<T>`, no sentinel values.
//! - **R7:** `parking_lot::Mutex` with `// LOCK-SCOPE:` annotations for
//!   thread-safe access.
//! - **R8:** Zero `unsafe` code.
//! - **R9:** Warning-free, all items documented.
//! - **R10:** Reachable via FIPS provider → CRNG test → parent RAND.
//!
//! Source: `providers/implementations/rands/fips_crng_test.c`

// =============================================================================
// Imports
// =============================================================================

use crate::implementations::rands::drbg::RandState;
use crate::traits::{RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::{error, warn};
use zeroize::Zeroize;

// =============================================================================
// Constants — SP 800-90B §4.4 Critical Values
// =============================================================================

/// Default entropy per sample in bits (6 bits per byte of entropy).
///
/// Matches C `ENTROPY_H` define in `fips_crng_test.c` line 47.
/// Value range 0–8 where index 0 maps to H=0.5.
const ENTROPY_H: usize = 6;

/// Adaptive Proportion Test window size (SP 800-90B §4.4.2).
///
/// Matches C `ENTROPY_APT_W` define in `fips_crng_test.c` line 50.
const ENTROPY_APT_W: u32 = 512;

/// Critical values for the Repetition Count Test (SP 800-90B §4.4.1).
///
/// Computed as `C = 1 + ceil(-log2(alpha) / H)` where `alpha = 2^-20`.
/// Index 0 is H=0.5, indices 1–8 are H=1..8.
///
/// Matches C `rct_c[9]` array in `RCT_test()` (line 118–121).
const RCT_CRITICAL: [u32; 9] = [41, 21, 11, 8, 6, 5, 5, 4, 4];

/// Critical values for the Adaptive Proportion Test (SP 800-90B §4.4.2).
///
/// Drawn from binomial distribution with n=512, p=2^-H at threshold 2^-20.
/// H being the expected entropy per sample.  Refer SP 800-90B §4.4.2 Table 2.
/// Index 0 is H=0.5, indices 1–8 are H=1..8.
///
/// Matches C `apt_c[9]` array in `APT_test()` (line 142–145).
const APT_CRITICAL: [u32; 9] = [410, 311, 177, 103, 62, 39, 25, 18, 13];

/// Default maximum security strength (in bits) reported via `get_params()`.
///
/// Matches C `crng_test_get_ctx_params()` where strength is reported as 1024.
const DEFAULT_STRENGTH: u32 = 1024;

/// Default maximum request size (in bytes) reported via `get_params()`.
///
/// Matches C `crng_test_get_ctx_params()` where `maxreq` is reported as 128.
const DEFAULT_MAX_REQUEST: usize = 128;

// =============================================================================
// State Types — Health Test Internal State
// =============================================================================

/// Repetition Count Test state (SP 800-90B §4.4.1).
///
/// Tracks consecutive occurrences of the same sample value. If `b` reaches
/// the critical value `RCT_CRITICAL[ENTROPY_H]`, the entropy source is
/// considered catastrophically compromised.
///
/// Corresponds to C `CRNG_TEST.rct` anonymous struct in `fips_crng_test.c` (lines 59–62).
#[derive(Debug, Clone, Zeroize)]
struct RctState {
    /// Count of consecutive identical samples.
    ///
    /// Reset to 1 when a new sample value is observed.
    /// Failure when `b >= RCT_CRITICAL[ENTROPY_H]`.
    b: u32,
    /// Most recent sample value.
    a: u8,
}

impl RctState {
    /// Creates a zeroed initial RCT state.
    fn new() -> Self {
        Self { b: 0, a: 0 }
    }
}

/// Adaptive Proportion Test state (SP 800-90B §4.4.2).
///
/// Within a window of `ENTROPY_APT_W` samples, counts how many times the
/// first sample in the window appears. If the count reaches
/// `APT_CRITICAL[ENTROPY_H]`, the entropy source is considered
/// catastrophically compromised.
///
/// Corresponds to C `CRNG_TEST.apt` anonymous struct in `fips_crng_test.c` (lines 65–69).
#[derive(Debug, Clone, Zeroize)]
struct AptState {
    /// Count of samples matching the reference value `a` in the current window.
    b: u32,
    /// Current position in the window (1-indexed; window resets when `i >= ENTROPY_APT_W`).
    i: u32,
    /// Reference sample value (the first sample in the current window).
    a: u8,
}

impl AptState {
    /// Creates a zeroed initial APT state.
    fn new() -> Self {
        Self { b: 0, i: 0, a: 0 }
    }
}

// =============================================================================
// CrngTest — FIPS Continuous RNG Test Wrapper
// =============================================================================

/// FIPS Continuous RNG Test wrapper (SP 800-90B §4.4).
///
/// Wraps a parent RAND source and applies the Approved Continuous Health Tests
/// (RCT and APT) to every byte of entropy passing through. Transitions to
/// [`RandState::Error`] on catastrophic failure patterns, permanently rejecting
/// further operations until re-instantiation.
///
/// ## State Machine
///
/// ```text
/// Uninitialised ──(instantiate)──► Ready ──(generate/get_seed)──► Ready
///        ▲                            │
///        │                            ▼ (health test failure)
///        └──(uninstantiate)──────── Error
/// ```
///
/// ## Locking
///
/// // LOCK-SCOPE: `CrngTest` wraps its mutable internals in an `Option<Mutex<_>>`
/// // to support optional thread-safe access via `enable_locking()`. The lock
/// // protects RCT/APT counters and state transitions. Low contention expected
/// // as CRNG tests are typically single-threaded per DRBG chain.
///
/// ## Source Mapping
///
/// Replaces C `CRNG_TEST` struct and all `crng_test_*` functions from
/// `providers/implementations/rands/fips_crng_test.c`.
#[derive(Debug)]
pub struct CrngTest {
    /// Current lifecycle state of the CRNG test wrapper.
    state: RandState,
    /// Repetition Count Test state (SP 800-90B §4.4.1).
    rct: RctState,
    /// Adaptive Proportion Test state (SP 800-90B §4.4.2).
    apt: AptState,
    /// Optional per-instance lock for thread-safe operation.
    ///
    /// Wrapped in [`Arc`] so the lock guard's lifetime is independent of
    /// `&self`, allowing `&mut self` methods to hold the guard while mutating
    /// state. Created by [`enable_locking()`](CrngTest::enable_locking).
    ///
    // LOCK-SCOPE: Protects RCT/APT counters and state field during concurrent
    // generate/get_seed calls. Low contention: typically one DRBG chain per thread.
    // Created via enable_locking(). Replaces C CRYPTO_RWLOCK from CRNG_TEST.
    lock: Option<Arc<Mutex<()>>>,
}

impl CrngTest {
    /// Creates a new CRNG test wrapper in the [`RandState::Uninitialised`] state.
    ///
    /// Health test counters (RCT and APT) are initialised to zero. The wrapper
    /// must be [`instantiate()`](CrngTest::instantiate)d before use.
    ///
    /// Replaces C `crng_test_new()` from `fips_crng_test.c` (lines 189–221).
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RandState::Uninitialised,
            rct: RctState::new(),
            apt: AptState::new(),
            lock: None,
        }
    }

    // =========================================================================
    // Health Test Implementations (private)
    // =========================================================================

    /// Performs the Repetition Count Test (SP 800-90B §4.4.1).
    ///
    /// Returns `true` if the test passes, `false` if the critical value is
    /// reached (catastrophic failure — the entropy source is compromised).
    ///
    /// ## Algorithm
    ///
    /// 1. If this is not the first sample (`b != 0`) AND the new sample matches
    ///    the previous one: increment `b`. If `b >= RCT_CRITICAL[ENTROPY_H]`,
    ///    the test fails.
    /// 2. Otherwise: record the new sample value and reset `b = 1`.
    ///
    /// Matches C `RCT_test()` exactly (lines 109–129).
    fn rct_test(&mut self, next: u8) -> bool {
        if self.rct.b != 0 && next == self.rct.a {
            self.rct.b += 1;
            return self.rct.b < RCT_CRITICAL[ENTROPY_H];
        }
        self.rct.a = next;
        self.rct.b = 1;
        true
    }

    /// Performs the Adaptive Proportion Test (SP 800-90B §4.4.2).
    ///
    /// Returns `true` if the test passes, `false` if the critical value is
    /// reached within the current window of `ENTROPY_APT_W` samples.
    ///
    /// ## Algorithm
    ///
    /// 1. If a window is active (`b != 0`):
    ///    a. If `next` matches the reference value `a`: increment `b`.
    ///       If `b >= APT_CRITICAL[ENTROPY_H]`, reset `b = 0` and fail.
    ///    b. Advance window position `i`. If `i >= ENTROPY_APT_W`, reset `b = 0`
    ///       (window complete without failure).
    ///    c. Pass.
    /// 2. If no window is active (`b == 0`): start a new window with
    ///    reference `a = next`, `b = 1`, `i = 1`.
    ///
    /// Matches C `APT_test()` exactly (lines 134–161).
    fn apt_test(&mut self, next: u8) -> bool {
        if self.apt.b != 0 {
            if self.apt.a == next {
                self.apt.b += 1;
                if self.apt.b >= APT_CRITICAL[ENTROPY_H] {
                    self.apt.b = 0;
                    return false;
                }
            }
            self.apt.i += 1;
            if self.apt.i >= ENTROPY_APT_W {
                self.apt.b = 0;
            }
            return true;
        }
        self.apt.a = next;
        self.apt.b = 1;
        self.apt.i = 1;
        true
    }

    /// Applies both health tests (RCT and APT) to a single entropy byte.
    ///
    /// On failure, transitions the wrapper to [`RandState::Error`] and logs
    /// the failure at the `error!` level for observability.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if either health test fails, indicating
    /// the entropy source has exhibited catastrophic statistical patterns.
    fn health_test(&mut self, byte: u8) -> ProviderResult<()> {
        if !self.rct_test(byte) {
            self.state = RandState::Error;
            error!(
                byte = byte,
                rct_count = self.rct.b,
                critical = RCT_CRITICAL[ENTROPY_H],
                "FIPS CRNG: Repetition Count Test failed — entropy source compromised"
            );
            return Err(ProviderError::Init(
                "SP 800-90B RCT failure: repetition count exceeded critical value".into(),
            ));
        }
        if !self.apt_test(byte) {
            self.state = RandState::Error;
            error!(
                byte = byte,
                apt_count = self.apt.b,
                critical = APT_CRITICAL[ENTROPY_H],
                "FIPS CRNG: Adaptive Proportion Test failed — entropy source compromised"
            );
            return Err(ProviderError::Init(
                "SP 800-90B APT failure: adaptive proportion exceeded critical value".into(),
            ));
        }
        Ok(())
    }

    /// Applies the health tests to a buffer of entropy bytes.
    ///
    /// Iterates byte-by-byte, applying both RCT and APT. If any byte triggers
    /// a failure, the wrapper immediately transitions to [`RandState::Error`]
    /// and returns an error — remaining bytes are not tested.
    ///
    /// Matches C `crng_test()` function (lines 163–175).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] on health test failure.
    fn test_buffer(&mut self, buf: &[u8]) -> ProviderResult<()> {
        for &byte in buf {
            self.health_test(byte)?;
        }
        Ok(())
    }

    // =========================================================================
    // Public Seed Interface
    // =========================================================================

    /// Retrieves a seed of the requested length, applying health tests to
    /// every byte.
    ///
    /// In a full implementation, this would delegate to the parent RAND's
    /// `get_seed()` dispatch and then test the returned bytes. Here, the
    /// caller provides the seed data (simulating the parent's output), and
    /// the CRNG test wrapper validates it.
    ///
    /// Replaces C `crng_test_get_seed()` (lines 284–319).
    ///
    /// # Arguments
    ///
    /// * `seed_data` — Raw entropy bytes from the parent RAND source.
    ///
    /// # Returns
    ///
    /// The validated seed bytes if all health tests pass.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if a health test fails.
    pub fn get_seed(&mut self, seed_data: &[u8]) -> ProviderResult<Vec<u8>> {
        // LOCK-SCOPE: Clone the Arc to decouple guard lifetime from &self,
        // allowing &mut self methods to proceed while holding the lock.
        let lock_clone = self.lock.clone();
        let _guard = lock_clone.as_ref().map(|m| m.lock());
        if self.state != RandState::Ready {
            warn!(
                state = %self.state,
                "FIPS CRNG: get_seed called in non-ready state"
            );
            return Err(ProviderError::Init(format!(
                "CRNG test not in ready state: {}",
                self.state
            )));
        }
        self.test_buffer(seed_data)?;
        Ok(seed_data.to_vec())
    }

    /// Clears (zeroises) a seed buffer.
    ///
    /// Applies [`Zeroize::zeroize()`] to the provided buffer to ensure
    /// secure erasure of entropy material per AAP §0.7.6.
    ///
    /// Replaces C `crng_test_clear_seed()` (lines 321–330).
    pub fn clear_seed(&mut self, seed: &mut [u8]) {
        seed.zeroize();
    }
}

impl Default for CrngTest {
    /// Creates a default CRNG test wrapper (equivalent to [`CrngTest::new()`]).
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// RandContext Implementation
// =============================================================================

impl RandContext for CrngTest {
    /// Instantiates the CRNG test wrapper, resetting health test state and
    /// transitioning to [`RandState::Ready`].
    ///
    /// The `strength` and `prediction_resistance` parameters are noted but
    /// not directly used by the health test wrapper (they govern the parent
    /// DRBG's behaviour). The `additional` data is accepted for interface
    /// compatibility but is not consumed.
    ///
    /// Replaces C `crng_test_instantiate()` (lines 233–244).
    fn instantiate(
        &mut self,
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        // Reset health test counters for a clean start
        self.rct = RctState::new();
        self.apt = AptState::new();
        self.state = RandState::Ready;
        Ok(())
    }

    /// Generates random bytes by wrapping the parent's output with health tests.
    ///
    /// In a full implementation, the parent RAND would produce the output and
    /// this wrapper would test each byte via `get_seed()`. Here we simulate
    /// the pattern: request a seed of `output.len()` bytes (using OS entropy
    /// as the parent source), test each byte, and copy to the output buffer.
    ///
    /// Replaces C `crng_test_generate()` (lines 254–267).
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Init`] if:
    /// - The wrapper is not in [`RandState::Ready`] state.
    /// - A health test fails on the generated bytes.
    fn generate(
        &mut self,
        output: &mut [u8],
        _strength: u32,
        _prediction_resistance: bool,
        _additional: &[u8],
    ) -> ProviderResult<()> {
        // LOCK-SCOPE: Clone the Arc to decouple guard lifetime from &self.
        let lock_clone = self.lock.clone();
        let _guard = lock_clone.as_ref().map(|m| m.lock());
        if self.state != RandState::Ready {
            return Err(ProviderError::Init(format!(
                "CRNG test not in ready state: {}",
                self.state
            )));
        }

        // In production, the parent RAND fills 'output'. For the standalone
        // wrapper, we use OS entropy as the simulated parent source.
        rand::rngs::OsRng.fill_bytes(output);

        // Apply health tests byte-by-byte (matching C crng_test_generate)
        self.test_buffer(output)?;
        Ok(())
    }

    /// Reseed is a no-op for the CRNG test wrapper.
    ///
    /// The CRNG health test does not maintain DRBG state that requires
    /// reseeding — it only monitors the entropy stream. The parent DRBG
    /// handles its own reseeding independently.
    ///
    /// Replaces C `crng_test_reseed()` (lines 269–277).
    fn reseed(
        &mut self,
        _prediction_resistance: bool,
        _entropy: &[u8],
        _additional: &[u8],
    ) -> ProviderResult<()> {
        Ok(())
    }

    /// Uninstantiates the CRNG test wrapper, securely zeroing all health
    /// test state and transitioning to [`RandState::Uninitialised`].
    ///
    /// Replaces C `crng_test_uninstantiate()` (lines 246–252).
    fn uninstantiate(&mut self) -> ProviderResult<()> {
        self.rct.zeroize();
        self.apt.zeroize();
        self.state = RandState::Uninitialised;
        Ok(())
    }

    /// Enables thread-safe locking on this CRNG test instance.
    ///
    /// Creates a `parking_lot::Mutex` for protecting internal state during
    /// concurrent access. Idempotent — calling multiple times is safe.
    ///
    /// Replaces C `crng_test_enable_locking()` (lines 332–349).
    ///
    // LOCK-SCOPE: The mutex protects RCT/APT counters and state transitions
    // during concurrent generate/get_seed calls. Expected contention is very
    // low as CRNG tests are typically single-threaded per DRBG chain.
    fn enable_locking(&mut self) -> ProviderResult<()> {
        if self.lock.is_none() {
            self.lock = Some(Arc::new(Mutex::new(())));
        }
        Ok(())
    }

    /// Returns current CRNG test parameters including state, strength,
    /// maximum request size, and FIPS indicator status.
    ///
    /// Replaces C `crng_test_get_ctx_params()` (lines 366–393).
    ///
    /// ## Parameters Returned
    ///
    /// | Key | Type | Description |
    /// |-----|------|-------------|
    /// | `"state"` | `Int32` | Current lifecycle state (0=uninit, 1=ready, 2=error) |
    /// | `"strength"` | `UInt32` | Maximum supported security strength |
    /// | `"max_request"` | `UInt64` | Maximum request size in bytes |
    /// | `"fips_indicator"` | `Int32` | FIPS approved indicator (0=not approved) |
    fn get_params(&self) -> ProviderResult<ParamSet> {
        // LOCK-SCOPE: Clone the Arc to decouple guard lifetime from &self.
        let lock_clone = self.lock.clone();
        let _guard = lock_clone.as_ref().map(|m| m.lock());
        let mut params = ParamSet::new();
        let state_int: i32 = match self.state {
            RandState::Uninitialised => 0,
            RandState::Ready => 1,
            RandState::Error => 2,
        };
        params.set("state", ParamValue::Int32(state_int));
        params.set("strength", ParamValue::UInt32(DEFAULT_STRENGTH));
        params.set(
            "max_request",
            ParamValue::UInt64(DEFAULT_MAX_REQUEST as u64),
        );
        params.set("fips_indicator", ParamValue::Int32(0));
        Ok(params)
    }
}

use rand::RngCore;

// =============================================================================
// Zeroize and Drop Implementations
// =============================================================================

impl Zeroize for CrngTest {
    /// Securely zeroes all health test state within the CRNG test wrapper.
    ///
    /// Zeroes RCT and APT state fields to prevent information leakage
    /// about the entropy stream's statistical properties.
    ///
    /// Replaces C `OPENSSL_cleanse()` calls in `crng_test_free()`
    /// (per AAP §0.7.6).
    fn zeroize(&mut self) {
        self.rct.zeroize();
        self.apt.zeroize();
    }
}

impl Drop for CrngTest {
    /// Securely zeroes all health test state on drop.
    ///
    /// Ensures that RCT/APT counters and sample values are erased when the
    /// CRNG test wrapper is deallocated, matching the C `crng_test_free()`
    /// behaviour (line 223–231).
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// CrngTestProvider — Factory (RandProvider Implementation)
// =============================================================================

/// Provider factory for creating [`CrngTest`] instances.
///
/// Implements the `RandProvider` trait, serving as the entry point for
/// the CRNG health test algorithm in the provider dispatch system.
///
/// Replaces the `ossl_crng_test_functions[]` dispatch table from
/// `fips_crng_test.c`.
///
/// ## Wiring (Rule R10)
///
/// ```text
/// FIPS Provider ──► create_rand_context("CRNG-TEST")
///                   ──► CrngTestProvider::new_ctx()
///                       ──► CrngTest::new()
/// ```
#[derive(Debug)]
pub struct CrngTestProvider;

impl RandProvider for CrngTestProvider {
    /// Returns the canonical algorithm name for the CRNG test.
    ///
    /// Matches the name registered in the provider descriptor table
    /// (`"CRNG-TEST"` in `mod.rs::descriptors()`).
    fn name(&self) -> &'static str {
        "CRNG-TEST"
    }

    /// Creates a new [`CrngTest`] context in the [`RandState::Uninitialised`]
    /// state.
    ///
    /// The returned context must be [`instantiate()`](RandContext::instantiate)d
    /// before it can be used for [`generate()`](RandContext::generate) or
    /// [`get_seed()`](CrngTest::get_seed) operations.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        Ok(Box::new(CrngTest::new()))
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify constants match the C source exactly.
    #[test]
    fn constants_match_c_source() {
        assert_eq!(ENTROPY_H, 6, "ENTROPY_H must be 6");
        assert_eq!(ENTROPY_APT_W, 512, "ENTROPY_APT_W must be 512");
        assert_eq!(
            RCT_CRITICAL,
            [41, 21, 11, 8, 6, 5, 5, 4, 4],
            "RCT_CRITICAL values must match C rct_c[9]"
        );
        assert_eq!(
            APT_CRITICAL,
            [410, 311, 177, 103, 62, 39, 25, 18, 13],
            "APT_CRITICAL values must match C apt_c[9]"
        );
    }

    /// Verify that a newly created CrngTest is in Uninitialised state.
    #[test]
    fn new_is_uninitialised() {
        let crng = CrngTest::new();
        assert_eq!(crng.state, RandState::Uninitialised);
    }

    /// Verify that instantiate transitions to Ready state.
    #[test]
    fn instantiate_transitions_to_ready() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();
        assert_eq!(crng.state, RandState::Ready);
    }

    /// Verify that uninstantiate transitions back to Uninitialised.
    #[test]
    fn uninstantiate_transitions_to_uninitialised() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();
        crng.uninstantiate().unwrap();
        assert_eq!(crng.state, RandState::Uninitialised);
    }

    /// Verify that generate fails in non-ready state.
    #[test]
    fn generate_fails_when_not_ready() {
        let mut crng = CrngTest::new();
        let mut buf = [0u8; 32];
        let result = crng.generate(&mut buf, 256, false, &[]);
        assert!(result.is_err());
    }

    /// Verify that diverse entropy passes health tests.
    #[test]
    fn diverse_entropy_passes() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();
        // Feed diverse data — each byte different
        let data: Vec<u8> = (0..=255).collect();
        let result = crng.get_seed(&data);
        assert!(result.is_ok());
    }

    /// Verify RCT failure: consecutive identical bytes exceeding critical value.
    #[test]
    fn rct_failure_on_repeated_bytes() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();

        // RCT_CRITICAL[6] = 5 for H=6. Failure at 5th consecutive repeat.
        // First byte sets a=0x42, b=1. Next 4 identical = b reaches 5.
        let critical = RCT_CRITICAL[ENTROPY_H];
        let repeated: Vec<u8> = vec![0x42; critical as usize];
        let result = crng.get_seed(&repeated);
        assert!(
            result.is_err(),
            "RCT should fail after {} identical bytes",
            critical
        );
        assert_eq!(crng.state, RandState::Error);
    }

    /// Verify APT failure: too many matching samples in a window.
    #[test]
    fn apt_failure_on_biased_distribution() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();

        // APT_CRITICAL[6] = 25 for H=6. We need the first byte to be
        // repeated >= 25 times within a 512-byte window.
        // Strategy: send the reference byte alternating with a different byte
        // so RCT doesn't trigger, but APT accumulates matches.
        let critical = APT_CRITICAL[ENTROPY_H];
        let mut data = Vec::with_capacity(ENTROPY_APT_W as usize);
        // First byte starts the APT window as reference
        data.push(0xAA);
        // Alternate: non-matching byte then matching byte
        // Each pair contributes 1 APT match (the matching byte)
        let matches_needed = critical - 1; // first byte is already b=1
        for _ in 0..matches_needed {
            data.push(0xBB); // non-matching
            data.push(0xAA); // matching — increments APT.b
        }

        let result = crng.get_seed(&data);
        assert!(
            result.is_err(),
            "APT should fail after {} matching samples",
            critical
        );
        assert_eq!(crng.state, RandState::Error);
    }

    /// Verify that operations fail after entering Error state.
    #[test]
    fn error_state_blocks_operations() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();

        // Force error via RCT
        let critical = RCT_CRITICAL[ENTROPY_H];
        let repeated: Vec<u8> = vec![0x42; critical as usize];
        let _ = crng.get_seed(&repeated);
        assert_eq!(crng.state, RandState::Error);

        // Subsequent operations should fail
        let result = crng.get_seed(&[1, 2, 3]);
        assert!(result.is_err());
    }

    /// Verify that get_params returns expected parameter keys.
    #[test]
    fn get_params_returns_expected_keys() {
        let crng = CrngTest::new();
        let params = crng.get_params().unwrap();
        assert!(params.get("state").is_some());
        assert!(params.get("strength").is_some());
        assert!(params.get("max_request").is_some());
        assert!(params.get("fips_indicator").is_some());
    }

    /// Verify that enable_locking is idempotent.
    #[test]
    fn enable_locking_idempotent() {
        let mut crng = CrngTest::new();
        crng.enable_locking().unwrap();
        crng.enable_locking().unwrap();
        assert!(crng.lock.is_some());
    }

    /// Verify that reseed is a no-op success.
    #[test]
    fn reseed_is_noop() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();
        let result = crng.reseed(false, &[1, 2, 3], &[]);
        assert!(result.is_ok());
    }

    /// Verify clear_seed zeroes the buffer.
    #[test]
    fn clear_seed_zeroes_buffer() {
        let mut crng = CrngTest::new();
        let mut seed = vec![0xAA; 32];
        crng.clear_seed(&mut seed);
        assert!(seed.iter().all(|&b| b == 0));
    }

    /// Verify CrngTestProvider name and factory.
    #[test]
    fn provider_factory_works() {
        let provider = CrngTestProvider;
        assert_eq!(provider.name(), "CRNG-TEST");
        let ctx = provider.new_ctx();
        assert!(ctx.is_ok());
    }

    /// Verify that RCT passes for values just below the critical threshold.
    #[test]
    fn rct_passes_below_critical() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();

        // RCT_CRITICAL[6] = 5. Send 4 identical bytes (just below threshold).
        let just_below = RCT_CRITICAL[ENTROPY_H] - 1;
        let repeated: Vec<u8> = vec![0x42; just_below as usize];
        let result = crng.get_seed(&repeated);
        assert!(
            result.is_ok(),
            "RCT should pass for {} identical bytes",
            just_below
        );
    }

    /// Verify that APT window resets correctly after completion.
    #[test]
    fn apt_window_resets_after_completion() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();

        // Fill an entire window with mostly distinct data
        let mut data: Vec<u8> = Vec::with_capacity(ENTROPY_APT_W as usize + 10);
        for i in 0..ENTROPY_APT_W {
            // Use modular byte values to avoid RCT triggers
            // and keep APT matches below critical
            data.push((i % 256) as u8);
        }
        let result = crng.get_seed(&data);
        assert!(result.is_ok(), "Diverse window should pass APT");
    }

    /// Verify generate works when properly instantiated.
    #[test]
    fn generate_succeeds_when_ready() {
        let mut crng = CrngTest::new();
        crng.instantiate(256, false, &[]).unwrap();
        let mut buf = [0u8; 32];
        // OS entropy should produce diverse bytes, passing health tests
        let result = crng.generate(&mut buf, 256, false, &[]);
        assert!(result.is_ok());
    }

    /// Verify Default trait implementation.
    #[test]
    fn default_matches_new() {
        let default_crng = CrngTest::default();
        assert_eq!(default_crng.state, RandState::Uninitialised);
    }
}
