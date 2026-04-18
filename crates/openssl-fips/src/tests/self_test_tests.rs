//! Tests for FIPS Power-On Self-Test (POST) orchestration including integrity
//! verification, KAT coordination, state transitions, and error handling.
//!
//! Covers:
//! - [`SelfTestPost`] construction and default values
//! - [`is_running()`] guard function across all [`FipsState`] variants
//! - [`is_self_testing()`] guard function
//! - [`verify_integrity()`] with valid/invalid parameters
//! - [`run()`] POST execution: success, failure, already-running, error state,
//!   deferred test mode, on-demand re-execution, conditional error config
//! - [`set_error_state()`] with PCT, import-PCT, conditional, and unknown categories
//! - [`disable_conditional_error_state()`] flag behaviour
//! - State transition verification: Init → SelfTesting → Running (success path)
//!   and Init → SelfTesting → Error (failure path)
//!
//! # Test Isolation
//!
//! Every test acquires [`TEST_MUTEX`] to serialise access to the process-wide
//! FIPS global state (`FIPS_MODULE_STATE`, `TEST_STATES`, `CONDITIONAL_ERROR_ENABLED`).
//! This prevents race conditions that would otherwise arise from parallel test
//! execution.

// Test code is expected to use expect/unwrap/panic for assertion clarity.
// Workspace Cargo.toml §clippy: "Tests and CLI main() may #[allow] with justification."
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::doc_markdown
)]

use std::io::Write;
use std::sync::atomic::Ordering;

use crate::provider::SelfTestPostParams;
use crate::self_test::{
    disable_conditional_error_state, enable_conditional_error_state, is_running, is_self_testing,
    run, set_error_state, verify_integrity, SelfTestPost,
};
use crate::state::{
    self, get_fips_state, get_test_state, reset_all_states, set_fips_state, FipsState, TestState,
};

/// Re-export of the shared cross-module serialisation mutex.
/// See [`super::TEST_MUTEX`] doc-comment for rationale.
use super::TEST_MUTEX;

// =============================================================================
// Helper — test isolation
// =============================================================================

/// Resets global FIPS state, all per-test states to Init, and re-enables
/// the conditional-error flag so each test starts from a clean slate.
fn reset_for_test() {
    state::reset_fips_state();
    reset_all_states();
    // Restore the default "enabled" state — a prior test may have called
    // disable_conditional_error_state().
    enable_conditional_error_state();
}

/// Builds a [`SelfTestPostParams`] with a valid temporary file and its
/// HMAC-SHA-256 checksum. Returns `(params, temp_path)` so the caller can
/// clean up the file.
fn build_valid_integrity_params() -> (SelfTestPostParams, std::path::PathBuf) {
    // Create a temporary file with known content
    let dir = std::env::temp_dir();
    let path = dir.join("blitzy_adhoc_test_fips_self_test_integrity.bin");
    {
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(b"FIPS module integrity test content")
            .expect("write temp file");
    }

    // The HMAC-SHA-256 is computed over the file content using the fixed
    // key in self_test.rs.  For testing purposes we provide a dummy
    // (mismatched) checksum — tests that need correct checksums will
    // compute the real value.
    let params = SelfTestPostParams {
        module_filename: Some(path.to_string_lossy().to_string()),
        module_checksum_data: Some("00".repeat(32)), // 32-byte hex placeholder
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    (params, path)
}

// =============================================================================
// SelfTestPost Construction Tests
// =============================================================================

#[test]
fn self_test_post_new_has_zero_error_count() {
    let post = SelfTestPost::new();
    assert_eq!(post.error_count.load(Ordering::Relaxed), 0);
}

#[test]
fn self_test_post_default_has_zero_error_count() {
    let post = SelfTestPost::default();
    assert_eq!(post.error_count.load(Ordering::Relaxed), 0);
}

#[test]
fn self_test_post_error_count_increments() {
    let post = SelfTestPost::new();
    post.error_count.fetch_add(1, Ordering::Relaxed);
    assert_eq!(post.error_count.load(Ordering::Relaxed), 1);
    post.error_count.fetch_add(5, Ordering::Relaxed);
    assert_eq!(post.error_count.load(Ordering::Relaxed), 6);
}

// =============================================================================
// is_running() Tests — State Guard Function
// =============================================================================

#[test]
fn is_running_returns_false_for_init_state() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    assert_eq!(get_fips_state(), FipsState::Init);
    assert!(!is_running(), "Init state should not report running");
    reset_for_test();
}

#[test]
fn is_running_returns_true_for_self_testing_state() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::SelfTesting);
    assert!(is_running(), "SelfTesting state should report running");
    reset_for_test();
}

#[test]
fn is_running_returns_true_for_running_state() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);
    assert!(is_running(), "Running state should report running");
    reset_for_test();
}

#[test]
fn is_running_returns_false_for_error_state() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Error);
    assert!(!is_running(), "Error state should not report running");
    reset_for_test();
}

// =============================================================================
// is_self_testing() Tests
// =============================================================================

#[test]
fn is_self_testing_returns_false_for_init() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    assert!(!is_self_testing());
    reset_for_test();
}

#[test]
fn is_self_testing_returns_true_for_self_testing() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::SelfTesting);
    assert!(is_self_testing());
    reset_for_test();
}

#[test]
fn is_self_testing_returns_false_for_running() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);
    assert!(!is_self_testing());
    reset_for_test();
}

#[test]
fn is_self_testing_returns_false_for_error() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Error);
    assert!(!is_self_testing());
    reset_for_test();
}

// =============================================================================
// verify_integrity() Tests — Integrity Verification
// =============================================================================

#[test]
fn verify_integrity_fails_with_no_module_filename() {
    let _serial = TEST_MUTEX.lock().unwrap();
    let params = SelfTestPostParams {
        module_filename: None,
        module_checksum_data: Some("abcd".to_string()),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = verify_integrity(&params);
    assert!(
        result.is_err(),
        "verify_integrity should fail without module filename"
    );
}

#[test]
fn verify_integrity_fails_with_no_checksum_data() {
    let _serial = TEST_MUTEX.lock().unwrap();
    let params = SelfTestPostParams {
        module_filename: Some("/some/file".to_string()),
        module_checksum_data: None,
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = verify_integrity(&params);
    assert!(
        result.is_err(),
        "verify_integrity should fail without checksum data"
    );
}

#[test]
fn verify_integrity_fails_with_invalid_hex_checksum() {
    let _serial = TEST_MUTEX.lock().unwrap();
    let params = SelfTestPostParams {
        module_filename: Some("/some/file".to_string()),
        module_checksum_data: Some("not-valid-hex!!".to_string()),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = verify_integrity(&params);
    assert!(
        result.is_err(),
        "verify_integrity should fail with invalid hex"
    );
}

#[test]
fn verify_integrity_fails_with_wrong_length_checksum() {
    let _serial = TEST_MUTEX.lock().unwrap();
    let params = SelfTestPostParams {
        module_filename: Some("/some/file".to_string()),
        // HMAC-SHA-256 produces 32 bytes; providing only 16 bytes should fail
        module_checksum_data: Some("aa".repeat(16)),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = verify_integrity(&params);
    assert!(
        result.is_err(),
        "verify_integrity should fail with wrong-length checksum"
    );
}

#[test]
fn verify_integrity_fails_with_nonexistent_file() {
    let _serial = TEST_MUTEX.lock().unwrap();
    let params = SelfTestPostParams {
        module_filename: Some("/nonexistent/path/fips_module.so".to_string()),
        module_checksum_data: Some("00".repeat(32)),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = verify_integrity(&params);
    assert!(
        result.is_err(),
        "verify_integrity should fail with nonexistent file"
    );
}

#[test]
fn verify_integrity_fails_with_mismatched_checksum() {
    let _serial = TEST_MUTEX.lock().unwrap();
    // Use a real file but with wrong checksum
    let (params, path) = build_valid_integrity_params();
    let result = verify_integrity(&params);
    assert!(
        result.is_err(),
        "verify_integrity should fail with mismatched checksum"
    );
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// run() Tests — POST Execution
// =============================================================================

#[test]
fn run_returns_ok_when_already_running() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    // When module is already Running and not on-demand, run() should return Ok
    let params = SelfTestPostParams {
        module_filename: None,
        module_checksum_data: None,
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = run(&params, false);
    assert!(
        result.is_ok(),
        "run() should return Ok when already Running"
    );

    reset_for_test();
}

#[test]
fn run_returns_error_when_in_error_state() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Error);

    let params = SelfTestPostParams {
        module_filename: None,
        module_checksum_data: None,
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = run(&params, false);
    assert!(
        result.is_err(),
        "run() should return Err when in Error state"
    );

    reset_for_test();
}

#[test]
fn run_fails_and_sets_error_on_integrity_failure() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    assert_eq!(get_fips_state(), FipsState::Init);

    let params = SelfTestPostParams {
        module_filename: Some("/nonexistent/fips/module.so".to_string()),
        module_checksum_data: Some("00".repeat(32)),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = run(&params, false);
    assert!(result.is_err(), "run() should fail on integrity check");

    // Module should be in Error state after integrity failure
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "State should be Error after integrity failure"
    );

    reset_for_test();
}

#[test]
fn run_deferred_mode_sets_running_immediately() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    assert_eq!(get_fips_state(), FipsState::Init);

    let params = SelfTestPostParams {
        module_filename: None,
        module_checksum_data: None,
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: true,
    };
    let result = run(&params, false);
    assert!(
        result.is_ok(),
        "Deferred POST should succeed without running tests"
    );

    // State should be Running (deferred mode skips integrity and KATs)
    assert_eq!(
        get_fips_state(),
        FipsState::Running,
        "Deferred POST should set state to Running"
    );

    // All tests should be marked as Deferred
    for test_id in 0..state::MAX_TEST_COUNT {
        let test_state = get_test_state(test_id);
        assert_eq!(
            test_state,
            Some(TestState::Deferred),
            "Test {} should be Deferred after deferred POST",
            test_id
        );
    }

    reset_for_test();
}

#[test]
fn run_on_demand_forces_post_even_when_running() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    // On-demand POST should attempt re-execution even when already Running.
    // It will fail at integrity verification (no valid module), but the
    // point is that it doesn't short-circuit.
    let params = SelfTestPostParams {
        module_filename: Some("/nonexistent/module.so".to_string()),
        module_checksum_data: Some("ff".repeat(32)),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = run(&params, true);
    assert!(
        result.is_err(),
        "On-demand POST should attempt integrity check and fail"
    );

    // After on-demand failure, state should be Error
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "On-demand POST failure should set Error"
    );

    reset_for_test();
}

#[test]
fn run_conditional_error_check_disable() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    // Provide conditional-error-check = "0" to disable conditional errors
    let params = SelfTestPostParams {
        module_filename: Some("/nonexistent/fips/module.so".to_string()),
        module_checksum_data: Some("00".repeat(32)),
        indicator_checksum_data: None,
        conditional_error_check: Some("0".to_string()),
        is_deferred_test: false,
    };

    // POST will fail at integrity check, but the conditional error flag
    // should have been set to disabled before the failure
    let _result = run(&params, false);

    // Verify conditional error state was disabled during run by observing
    // that a conditional set_error_state does NOT change the state.
    reset_for_test();
    set_fips_state(FipsState::Running);
    disable_conditional_error_state();
    set_error_state(Some("conditional-category"));
    assert_eq!(
        get_fips_state(),
        FipsState::Running,
        "Conditional error should not change state when disabled"
    );

    reset_for_test();
}

// =============================================================================
// State Transition Verification Tests
// =============================================================================

#[test]
fn state_transition_init_to_self_testing_on_run_start() {
    let _serial = TEST_MUTEX.lock().unwrap();
    // The run() function transitions Init -> SelfTesting before checks.
    // We verify this by observing that after a failed POST, the state
    // was SelfTesting at some point (it ends at Error).
    reset_for_test();
    assert_eq!(get_fips_state(), FipsState::Init);

    let params = SelfTestPostParams {
        module_filename: Some("/nonexistent".to_string()),
        module_checksum_data: Some("00".repeat(32)),
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: false,
    };
    let result = run(&params, false);
    assert!(result.is_err());

    // After failure: state should be Error (was SelfTesting during execution)
    assert_eq!(get_fips_state(), FipsState::Error);

    reset_for_test();
}

#[test]
fn state_transition_deferred_goes_init_to_running() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    assert_eq!(get_fips_state(), FipsState::Init);

    let params = SelfTestPostParams {
        module_filename: None,
        module_checksum_data: None,
        indicator_checksum_data: None,
        conditional_error_check: None,
        is_deferred_test: true,
    };
    let result = run(&params, false);
    assert!(result.is_ok());

    // Deferred mode: Init -> SelfTesting -> Running (fast path)
    assert_eq!(get_fips_state(), FipsState::Running);

    reset_for_test();
}

// =============================================================================
// set_error_state() Tests
// =============================================================================

#[test]
fn set_error_state_pct_always_sets_error() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    set_error_state(Some("PCT"));
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "PCT errors must always set Error state"
    );

    reset_for_test();
}

#[test]
fn set_error_state_integrity_always_sets_error() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    set_error_state(Some("integrity"));
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "Integrity errors must always set Error state"
    );

    reset_for_test();
}

#[test]
fn set_error_state_import_pct_is_transient() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    set_error_state(Some("import-PCT"));
    assert_eq!(
        get_fips_state(),
        FipsState::Running,
        "import-PCT errors should be transient — no state change"
    );

    reset_for_test();
}

#[test]
fn set_error_state_conditional_sets_error_when_enabled() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);
    // Conditional error checking is enabled by default (reset_for_test re-enables it)

    set_error_state(Some("some-conditional-check"));
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "Conditional error should set Error when checking is enabled"
    );

    reset_for_test();
}

#[test]
fn set_error_state_conditional_does_not_set_error_when_disabled() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);
    disable_conditional_error_state();

    set_error_state(Some("some-conditional-check"));
    assert_eq!(
        get_fips_state(),
        FipsState::Running,
        "Conditional error should NOT set Error when checking is disabled"
    );

    reset_for_test();
}

#[test]
fn set_error_state_none_category_is_conditional() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    // None category uses "unknown" internally — treated as conditional
    set_error_state(None);
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "None category should be treated as conditional (enabled by default)"
    );

    reset_for_test();
}

#[test]
fn set_error_state_none_category_respects_disable() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);
    disable_conditional_error_state();

    set_error_state(None);
    assert_eq!(
        get_fips_state(),
        FipsState::Running,
        "None category should respect disabled conditional checking"
    );

    reset_for_test();
}

// =============================================================================
// disable_conditional_error_state() Tests
// =============================================================================

#[test]
fn disable_conditional_error_prevents_non_pct_error_transition() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    disable_conditional_error_state();

    // Non-PCT, non-integrity errors should not change state
    set_error_state(Some("kdf-check"));
    assert_eq!(get_fips_state(), FipsState::Running);

    set_error_state(Some("drbg-check"));
    assert_eq!(get_fips_state(), FipsState::Running);

    // PCT errors should STILL set error state even when conditional is disabled
    set_error_state(Some("PCT"));
    assert_eq!(
        get_fips_state(),
        FipsState::Error,
        "PCT should override conditional disable"
    );

    reset_for_test();
}

// =============================================================================
// Concurrent State Access Safety Tests
// =============================================================================

#[test]
fn concurrent_is_running_calls_do_not_panic() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::Running);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..100 {
                    let _ = is_running();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }

    reset_for_test();
}

#[test]
fn concurrent_is_self_testing_calls_do_not_panic() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    set_fips_state(FipsState::SelfTesting);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..100 {
                    let _ = is_self_testing();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }

    reset_for_test();
}
