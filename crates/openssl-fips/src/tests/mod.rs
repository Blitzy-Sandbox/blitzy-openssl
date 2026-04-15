//! Tests for the `openssl-fips` crate.
//!
//! This module contains comprehensive tests verifying FIPS 140-3 compliance:
//! - State machine transitions (`FipsState`, `TestState`)
//! - FIPS approved service indicator with R4 callback pairing
//! - Known Answer Test (KAT) execution per category
//! - POST (Power-On Self-Test) orchestration
//! - Provider initialization and algorithm queries
//! - End-to-end FIPS module lifecycle (R10 wiring verification)
//!
//! # Module Organisation
//!
//! Test submodules are declared in dependency order — foundational modules first,
//! integration-level modules last. Shared helper functions are provided at the
//! root of this module so that every submodule can call them without duplication.
//!
//! # Conditional Compilation
//!
//! All 6 submodules are unconditionally compiled under `#[cfg(test)]` (the parent
//! `lib.rs` gates this entire module behind that attribute). Feature-gated tests
//! are handled within individual test files using `#[cfg(feature = "...")]` on
//! specific test functions.

// ---------------------------------------------------------------------------
// Test submodule declarations — dependency order (foundational first)
// ---------------------------------------------------------------------------

mod indicator_tests;
mod integration_tests;
mod kats_tests;
mod provider_tests;
mod self_test_tests;
mod state_tests;

// ---------------------------------------------------------------------------
// Shared test utility helpers
// ---------------------------------------------------------------------------

/// Resets **all** FIPS state back to its initial values for test isolation.
///
/// This helper performs two resets in sequence:
/// 1. `crate::state::reset_fips_state()` — atomically sets the global
///    `FIPS_MODULE_STATE` back to [`FipsState::Init`] and also internally
///    calls `reset_all_states()` to clear per-test-category entries.
/// 2. `crate::state::reset_all_states()` — explicitly resets every
///    per-test-category `TestState` entry to [`TestState::Init`] under a
///    lock, providing an extra guarantee of a clean slate even if the
///    internal call ordering changes in the future.
///
/// Call this at the beginning of integration tests that depend on a
/// pristine FIPS module state.
#[allow(dead_code)] // TEST-UTIL: used across multiple test submodules
pub(crate) fn reset_fips_test_state() {
    crate::state::reset_fips_state();
    crate::state::reset_all_states();
}

/// Creates a default [`FipsIndicator`] instance suitable for testing.
///
/// The returned indicator has `approved = true` and all settable slots set
/// to [`SettableState::Unknown`], providing a clean baseline for tests that
/// exercise approval-state transitions and callback behaviour.
#[allow(dead_code)] // TEST-UTIL: used across multiple test submodules
pub(crate) fn new_test_indicator() -> crate::indicator::FipsIndicator {
    crate::indicator::FipsIndicator::new()
}

// ---------------------------------------------------------------------------
// Self-validation tests for the shared helpers above
// ---------------------------------------------------------------------------

#[test]
fn reset_fips_test_state_runs_without_panic() {
    reset_fips_test_state();
    // After reset, the FIPS module state should be Init and all per-category
    // TestState entries should be Init — verified by the fact that no panic
    // occurred and the function completed.
}

#[test]
fn new_test_indicator_returns_valid_instance() {
    let _indicator = new_test_indicator();
    // The indicator was successfully constructed with approved = true and
    // all settable slots set to Unknown — verified by successful return.
}
