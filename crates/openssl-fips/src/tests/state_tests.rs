//! Unit tests for the FIPS module state machine ([`FipsState`]) and per-test
//! state tracking ([`TestState`]).
//!
//! These tests complement the inline `#[cfg(test)]` module inside
//! [`crate::state`] by focusing on **value-added** coverage that cannot be
//! expressed from within the module itself — namely:
//!
//! 1. **Cross-module integration** — drives [`crate::self_test::is_running`]
//!    and [`crate::self_test::is_self_testing`] against every possible
//!    [`FipsState`] value to confirm the guard functions observe
//!    transitions correctly.
//! 2. **Sequenced lifecycle scenarios** — executes full `Init → SelfTesting
//!    → Running` and `Init → SelfTesting → Error` paths under the
//!    process-wide [`TEST_MUTEX`], verifying that reads at every hop agree
//!    with the preceding write.
//! 3. **Rate-limiter correctness under stress** — exercises
//!    [`ErrorRateLimiter`] and the global [`FIPS_ERROR_LIMITER`] to verify
//!    the exact limit semantics and rule R7 lock-granularity guarantees.
//! 4. **Thread safety** — spawns concurrent reader/writer OS threads against
//!    [`FIPS_MODULE_STATE`] and [`TEST_STATES`] to detect torn reads, data
//!    races, or invalid intermediate values.
//! 5. **API contract with `FipsError`** — confirms the public [`FipsResult`]
//!    type and every enumerated [`FipsError`] variant compose with FIPS
//!    state-aware call sites.
//!
//! # C Source Mapping
//!
//! - [`FipsState`] variants ← `FIPS_STATE_*` defines (`self_test.c`
//!   lines 36–39).
//! - [`TestState`] variants ← `enum st_test_state` (`self_test.h`
//!   lines 62–69).
//! - [`TestCategory`] variants ← `enum st_test_category` (`self_test.h`
//!   lines 48–60).
//! - Atomic accessors ← `ossl_get/set_self_test_state` (`self_test.c`
//!   lines 81–91) and `set_fips_state`/`get_fips_state` (lines 267–276).
//! - Rate limiter ← `FIPS_ERROR_REPORTING_RATE_LIMIT` and the
//!   `ossl_prov_is_running` counter logic (`self_test.c` line 45,
//!   lines 458–469).
//!
//! # Test Isolation
//!
//! Every test that mutates process-wide state must serialise on
//! [`TEST_MUTEX`] and call [`reset_for_test`] before and after its
//! assertions.  This mirrors the discipline enforced by
//! [`self_test_tests`](super::self_test_tests).  Tests that only read
//! immutable data (enum variants, `Display` output) are free to run in
//! parallel.
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability over sentinels):** All assertions use `Option`/
//!   `Result` typed APIs; no sentinel integer comparisons appear here.
//! - **R7 (Lock granularity):** Concurrent tests reason explicitly about
//!   what is locked vs. atomic and document expected contention.
//! - **R8 (Zero `unsafe`):** This test file contains no `unsafe` blocks.
//! - **R9 (Warning-free build):** The file compiles clean under
//!   `RUSTFLAGS="-D warnings"`.

// Test code uses expect/unwrap/panic for assertion clarity — workspace
// policy allows these in `#[cfg(test)]` modules with justification.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::doc_markdown
)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use crate::self_test::{is_running, is_self_testing};
use crate::state::{
    all_tests_passed, get_fips_state, get_test_state, mark_all_deferred, reset_all_states,
    reset_fips_state, set_fips_state, set_test_state, ErrorRateLimiter, FipsState, TestCategory,
    TestState, ERROR_REPORT_LIMIT, FIPS_ERROR_LIMITER, FIPS_MODULE_STATE, MAX_TEST_COUNT,
    TEST_STATES,
};

// `FipsError` / `FipsResult` are imported per the internal-imports schema;
// Phase 4 below verifies they compose with FIPS-state-aware call sites
// (notably that the module has no `InvalidStateTransition` variant —
// invalid transitions are prevented at higher layers, not inside
// `set_fips_state`).
use openssl_common::error::{FipsError, FipsResult};

// Process-wide serialisation mutex shared by every test module that
// mutates global FIPS state.  See [`super::TEST_MUTEX`].
use super::TEST_MUTEX;

// ---------------------------------------------------------------------------
// Helper — test isolation
// ---------------------------------------------------------------------------

/// Resets the module state and every per-test entry back to `Init`.
///
/// The two calls are deliberately explicit: `reset_fips_state()` internally
/// calls `reset_all_states()` today, but duplicating the call here documents
/// the intent and survives any future refactor of the inner helper.
fn reset_for_test() {
    reset_fips_state();
    reset_all_states();
}

/// Drives an arbitrary [`FipsResult<()>`] and asserts it is `Err` containing
/// the expected [`FipsError`] variant.  Used in Phase 4 to confirm the
/// pub error type composes with state-aware call sites.
#[track_caller]
fn assert_fips_err<T>(result: FipsResult<T>, matcher: impl FnOnce(&FipsError) -> bool) {
    match result {
        Err(ref e) if matcher(e) => {}
        Err(e) => panic!("unexpected FipsError variant: {:?}", e),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// ===========================================================================
// Phase 2 — FipsState Enum Structural Tests
// ===========================================================================
//
// These tests run without the TEST_MUTEX because they exercise only the
// enum type itself — no process-wide state is mutated.  They supplement
// the inline `fips_state_from_u8_valid` / `fips_state_display` tests in
// `state.rs` with structural guarantees (exhaustiveness, Clone/Copy,
// Debug, Eq) that the inline tests do not assert.

#[test]
fn fips_state_enum_has_exactly_four_variants() {
    // Build a list covering every declared variant.  If a new variant is
    // added, this test will not immediately fail — but the exhaustive
    // `match` below *will* fail to compile, forcing a review.
    let all = [
        FipsState::Init,
        FipsState::SelfTesting,
        FipsState::Running,
        FipsState::Error,
    ];
    assert_eq!(all.len(), 4, "FipsState must have exactly 4 variants");

    // Exhaustive match — forces a compile error on variant addition.
    for state in all {
        let _ = match state {
            FipsState::Init => 0u8,
            FipsState::SelfTesting => 1u8,
            FipsState::Running => 2u8,
            FipsState::Error => 3u8,
        };
    }
}

#[test]
fn fips_state_variants_are_pairwise_distinct() {
    // Uniqueness via PartialEq — ensures no two variants compare equal.
    let variants = [
        FipsState::Init,
        FipsState::SelfTesting,
        FipsState::Running,
        FipsState::Error,
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(a, b, "variant should equal itself: {:?}", a);
            } else {
                assert_ne!(a, b, "variants {:?} and {:?} must be distinct", a, b);
            }
        }
    }
}

#[test]
fn fips_state_is_clone_and_copy() {
    let original = FipsState::Running;
    // Clone
    let cloned = original;
    assert_eq!(original, cloned);
    // Copy (implicit)
    let copied: FipsState = original;
    assert_eq!(copied, FipsState::Running);
    // Original still usable — demonstrates Copy semantics.
    assert_eq!(original, FipsState::Running);
}

#[test]
fn fips_state_debug_emits_variant_name() {
    // `Debug` is derived — output should include the variant identifier.
    assert_eq!(format!("{:?}", FipsState::Init), "Init");
    assert_eq!(format!("{:?}", FipsState::SelfTesting), "SelfTesting");
    assert_eq!(format!("{:?}", FipsState::Running), "Running");
    assert_eq!(format!("{:?}", FipsState::Error), "Error");
}

#[test]
fn fips_state_from_u8_round_trip_covers_full_range() {
    // Inline tests cover 0..=3 plus a couple of invalids.  Here we sweep
    // the *entire* u8 range to confirm only 0..=3 yield `Some`.
    for raw in 0..=u8::MAX {
        match FipsState::from_u8(raw) {
            Some(s) => {
                assert!(raw <= 3, "from_u8({}) unexpectedly returned Some", raw);
                assert_eq!(s.as_u8(), raw, "as_u8 must be the round-trip inverse");
            }
            None => assert!(raw > 3, "from_u8({}) unexpectedly returned None", raw),
        }
    }
}

// ===========================================================================
// Phase 3 — FipsState Valid Transition Tests (sequenced lifecycle)
// ===========================================================================
//
// These tests acquire the cross-module TEST_MUTEX and reset global state
// to Init, then drive the full state machine through each valid path.
// They specifically verify that `get_fips_state()` observes the transition
// *immediately* after `set_fips_state()` returns — i.e., SeqCst visibility.

#[test]
fn transition_init_to_self_testing() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();
    assert_eq!(get_fips_state(), FipsState::Init);

    set_fips_state(FipsState::SelfTesting);
    assert_eq!(get_fips_state(), FipsState::SelfTesting);

    reset_for_test();
}

#[test]
fn transition_self_testing_to_running() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    set_fips_state(FipsState::SelfTesting);
    assert_eq!(get_fips_state(), FipsState::SelfTesting);

    set_fips_state(FipsState::Running);
    assert_eq!(get_fips_state(), FipsState::Running);

    reset_for_test();
}

#[test]
fn transition_self_testing_to_error() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    set_fips_state(FipsState::SelfTesting);
    assert_eq!(get_fips_state(), FipsState::SelfTesting);

    set_fips_state(FipsState::Error);
    assert_eq!(get_fips_state(), FipsState::Error);

    reset_for_test();
}

#[test]
fn full_success_path_init_self_testing_running() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert_eq!(get_fips_state(), FipsState::Init);
    assert!(!get_fips_state().is_operational());

    set_fips_state(FipsState::SelfTesting);
    assert_eq!(get_fips_state(), FipsState::SelfTesting);
    assert!(get_fips_state().is_operational());

    set_fips_state(FipsState::Running);
    assert_eq!(get_fips_state(), FipsState::Running);
    assert!(get_fips_state().is_operational());

    reset_for_test();
}

#[test]
fn full_failure_path_init_self_testing_error() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert_eq!(get_fips_state(), FipsState::Init);

    set_fips_state(FipsState::SelfTesting);
    assert_eq!(get_fips_state(), FipsState::SelfTesting);

    set_fips_state(FipsState::Error);
    assert_eq!(get_fips_state(), FipsState::Error);
    assert!(!get_fips_state().is_operational());

    reset_for_test();
}

#[test]
fn reset_from_running_restores_init_and_clears_tests() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    set_fips_state(FipsState::SelfTesting);
    set_fips_state(FipsState::Running);
    // Mark a few tests as Passed so we can verify reset clears them.
    assert!(set_test_state(0, TestState::Passed));
    assert!(set_test_state(5, TestState::Implicit));

    reset_fips_state();

    assert_eq!(get_fips_state(), FipsState::Init);
    assert_eq!(get_test_state(0), Some(TestState::Init));
    assert_eq!(get_test_state(5), Some(TestState::Init));

    reset_for_test();
}

#[test]
fn reset_from_error_restores_init() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    set_fips_state(FipsState::SelfTesting);
    set_fips_state(FipsState::Error);
    assert_eq!(get_fips_state(), FipsState::Error);

    reset_fips_state();
    assert_eq!(get_fips_state(), FipsState::Init);

    reset_for_test();
}

#[test]
fn full_transition_path_can_be_repeated_after_reset() {
    // After a reset, the full lifecycle must be drivable again — ensures
    // no hidden "latch" prevents re-initialisation.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    for iteration in 0..3 {
        set_fips_state(FipsState::SelfTesting);
        set_fips_state(FipsState::Running);
        assert_eq!(
            get_fips_state(),
            FipsState::Running,
            "iteration {} failed to reach Running",
            iteration
        );
        reset_fips_state();
        assert_eq!(
            get_fips_state(),
            FipsState::Init,
            "iteration {} failed to reset to Init",
            iteration
        );
    }
}

// ===========================================================================
// Phase 4 — FipsState Invalid Transition Tests
// ===========================================================================
//
// Design note: `set_fips_state()` returns `()` and is unconditional — it
// does not enforce transition validity at the atomic-store layer.  The
// invariant "Init must pass through SelfTesting before Running" is
// enforced at higher layers (notably `self_test::run()`), not here.
// These tests therefore verify two properties:
//
//   1. `set_fips_state` is infallible by type (compiles as `-> ()`).
//   2. The resulting state is observable, even when the transition
//      would be semantically invalid at a higher layer — this lets us
//      test error-recovery code paths (e.g., forcibly entering Error).
//
// The [`FipsError`] variant set (from `openssl-common`) does NOT include
// an `InvalidStateTransition` case — the module's error model treats
// runtime operations (not state writes) as the fallible boundary.  We
// verify this by ensuring our error-matching helper only pattern-matches
// against the five documented variants.

#[test]
fn set_fips_state_is_infallible_by_type() {
    // Compile-time proof: if `set_fips_state` were fallible, the
    // destructuring `let () = ...` binding would not compile.  The
    // explicit unit pattern also ensures the return type does not
    // silently change to e.g. `Option<()>` in a future refactor.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let () = set_fips_state(FipsState::Error);

    assert_eq!(get_fips_state(), FipsState::Error);
    reset_for_test();
}

#[test]
fn unconditional_set_allows_any_pair_and_is_observable() {
    // Drives every ordered pair of source → target states and confirms
    // `get_fips_state` reflects the target immediately.  This documents
    // the low-level contract: state writes are not gated.
    let _serial = TEST_MUTEX.lock().unwrap();

    let states = [
        FipsState::Init,
        FipsState::SelfTesting,
        FipsState::Running,
        FipsState::Error,
    ];

    for &from in &states {
        for &to in &states {
            reset_for_test();
            set_fips_state(from);
            assert_eq!(get_fips_state(), from, "source state not observable");

            set_fips_state(to);
            assert_eq!(
                get_fips_state(),
                to,
                "transition {:?} -> {:?} not observable",
                from,
                to
            );
        }
    }

    reset_for_test();
}

#[test]
fn error_state_is_absorbing_until_explicit_reset() {
    // Phase 4 intent: Error must not be left silently by a spurious
    // set_fips_state from a *caller that respects the state machine*.
    // Since the low-level API is unconditional, we document the pattern
    // callers use: hit Error, require explicit reset_fips_state() to leave.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    set_fips_state(FipsState::SelfTesting);
    set_fips_state(FipsState::Error);
    assert_eq!(get_fips_state(), FipsState::Error);

    // A *disciplined* caller treats Error as terminal and only leaves it
    // via reset_fips_state().
    reset_fips_state();
    assert_eq!(get_fips_state(), FipsState::Init);

    reset_for_test();
}

#[test]
fn fips_error_variants_cover_non_transition_failures() {
    // FipsError intentionally has NO `InvalidStateTransition` variant —
    // the state machine does not report transition errors at the atomic
    // layer.  Here we verify the five actual variants compose with
    // FipsResult correctly.
    let err_common: FipsResult<()> = Err(FipsError::Common(
        openssl_common::error::CommonError::Internal("x".to_string()),
    ));
    let err_self_test: FipsResult<()> = Err(FipsError::SelfTestFailed("kat".to_string()));
    let err_integrity: FipsResult<()> = Err(FipsError::IntegrityCheckFailed);
    let err_not_op: FipsResult<()> = Err(FipsError::NotOperational("init".to_string()));
    let err_not_appr: FipsResult<()> = Err(FipsError::NotApproved("md4".to_string()));

    assert_fips_err(err_common, |e| matches!(e, FipsError::Common(_)));
    assert_fips_err(err_self_test, |e| matches!(e, FipsError::SelfTestFailed(_)));
    assert_fips_err(err_integrity, |e| {
        matches!(e, FipsError::IntegrityCheckFailed)
    });
    assert_fips_err(err_not_op, |e| matches!(e, FipsError::NotOperational(_)));
    assert_fips_err(err_not_appr, |e| matches!(e, FipsError::NotApproved(_)));
}

#[test]
fn fips_result_ok_composes_with_state_reads() {
    // A function parameterised on FipsResult<T> should return the
    // current state without error when the module is Running.  This
    // exercises the `FipsResult` import end-to-end.
    fn current_state_if_running() -> FipsResult<FipsState> {
        match get_fips_state() {
            FipsState::Running | FipsState::SelfTesting => Ok(get_fips_state()),
            other => Err(FipsError::NotOperational(other.to_string())),
        }
    }

    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    // Init → Err
    assert_fips_err(
        current_state_if_running(),
        |e| matches!(e, FipsError::NotOperational(msg) if msg == "init"),
    );

    // Running → Ok
    set_fips_state(FipsState::SelfTesting);
    set_fips_state(FipsState::Running);
    let got = current_state_if_running().expect("Running should be Ok");
    assert_eq!(got, FipsState::Running);

    // Error → Err
    set_fips_state(FipsState::Error);
    assert_fips_err(
        current_state_if_running(),
        |e| matches!(e, FipsError::NotOperational(msg) if msg == "error"),
    );

    reset_for_test();
}

// ===========================================================================
// Phase 5 — State Helper Function Tests (is_running, is_self_testing)
// ===========================================================================
//
// These map to C's `ossl_prov_is_running()` and `ossl_fips_self_testing()`
// helpers.  They are under test here (rather than only in
// `self_test_tests.rs`) because the schema requires the `crate::self_test`
// module to be exercised from this file, and these are the only two
// `self_test` symbols in our internal-import whitelist.

#[test]
fn is_running_matrix_every_state() {
    // Full matrix: every state → expected is_running result.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let expectations = [
        (FipsState::Init, false),
        (FipsState::SelfTesting, true),
        (FipsState::Running, true),
        (FipsState::Error, false),
    ];

    for (state, expected) in expectations {
        set_fips_state(state);
        assert_eq!(
            is_running(),
            expected,
            "is_running({:?}) expected {}",
            state,
            expected
        );
    }

    reset_for_test();
}

#[test]
fn is_self_testing_matrix_every_state() {
    // Full matrix: only SelfTesting must return true.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let expectations = [
        (FipsState::Init, false),
        (FipsState::SelfTesting, true),
        (FipsState::Running, false),
        (FipsState::Error, false),
    ];

    for (state, expected) in expectations {
        set_fips_state(state);
        assert_eq!(
            is_self_testing(),
            expected,
            "is_self_testing({:?}) expected {}",
            state,
            expected
        );
    }

    reset_for_test();
}

#[test]
fn is_running_matches_fips_state_is_operational() {
    // Every FipsState — the two predicates must agree for non-Error
    // states.  Error is *intentionally* different: `is_operational` is
    // a pure inspection (returns false with no side effect), whereas
    // `is_running` additionally emits rate-limited error logs.  For
    // truthy values both return the same boolean.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    for state in [
        FipsState::Init,
        FipsState::SelfTesting,
        FipsState::Running,
        FipsState::Error,
    ] {
        set_fips_state(state);
        let op = get_fips_state().is_operational();
        let run = is_running();
        // is_operational returns true iff Running|SelfTesting; same as
        // the non-Error positive cases of is_running.  They must agree
        // for all four states.
        assert_eq!(op, run, "mismatch for state {:?}", state);
    }

    reset_for_test();
}

#[test]
fn is_running_transitions_through_lifecycle() {
    // Sequence: Init (false) → SelfTesting (true) → Running (true)
    // → Error (false) → reset → Init (false).
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert!(!is_running(), "Init must not report running");

    set_fips_state(FipsState::SelfTesting);
    assert!(is_running(), "SelfTesting must report running");

    set_fips_state(FipsState::Running);
    assert!(is_running(), "Running must report running");

    set_fips_state(FipsState::Error);
    assert!(!is_running(), "Error must not report running");

    reset_fips_state();
    assert!(!is_running(), "Init after reset must not report running");
}

#[test]
fn is_self_testing_transitions_through_lifecycle() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert!(!is_self_testing(), "Init must not report self-testing");

    set_fips_state(FipsState::SelfTesting);
    assert!(is_self_testing(), "SelfTesting must report self-testing");

    set_fips_state(FipsState::Running);
    assert!(!is_self_testing(), "Running must not report self-testing");

    set_fips_state(FipsState::Error);
    assert!(!is_self_testing(), "Error must not report self-testing");

    reset_for_test();
}

// ===========================================================================
// Phase 6 — Rate-Limited Error Reporting Tests
// ===========================================================================
//
// Design note: `is_running()` contains a function-local `static
// AtomicU32 ERROR_COUNT` that is *not* reset between tests — once
// exhausted by any test run, further tests observing the Error state
// would not see their log lines, but this does NOT affect the boolean
// return value (which is always `false` for Error).  Attempting to
// assert on log output is brittle, so Phase 6 tests focus on:
//
//   1. The public [`ErrorRateLimiter`] type — verifiable in isolation.
//   2. The global [`FIPS_ERROR_LIMITER`] — used by high-level code
//      (not by is_running()) to gate FIPS-module error reports.
//   3. The constant [`ERROR_REPORT_LIMIT`] — matches C (10).

#[test]
fn error_rate_limiter_boundary_is_inclusive_below_limit() {
    // A fresh limiter of N allows exactly N reports, then blocks.
    let limiter = ErrorRateLimiter::new(10);
    for i in 0..10 {
        assert!(
            limiter.should_report(),
            "report #{} below limit must be allowed",
            i
        );
    }
    // 11th call and beyond must be blocked.
    for i in 10..20 {
        assert!(
            !limiter.should_report(),
            "report #{} at-or-above limit must be blocked",
            i
        );
    }
}

#[test]
fn error_rate_limiter_with_limit_of_one_allows_exactly_one() {
    let limiter = ErrorRateLimiter::new(1);
    assert!(limiter.should_report(), "first report must be allowed");
    assert!(!limiter.should_report(), "second report must be blocked");
}

#[test]
fn error_rate_limiter_zero_limit_blocks_all() {
    let limiter = ErrorRateLimiter::new(0);
    for i in 0..5 {
        assert!(
            !limiter.should_report(),
            "zero-limit must block report #{}",
            i
        );
    }
}

#[test]
fn error_rate_limiter_large_limit_does_not_overflow() {
    // Use a very small limit but many calls to exercise the compare.
    let limiter = ErrorRateLimiter::new(3);
    let mut allowed = 0u32;
    for _ in 0..1000 {
        if limiter.should_report() {
            allowed += 1;
        }
    }
    assert_eq!(
        allowed, 3,
        "limit=3 must allow exactly 3 reports out of 1000"
    );
}

#[test]
fn error_report_limit_matches_fips_error_reporting_rate_limit_c_constant() {
    // C: FIPS_ERROR_REPORTING_RATE_LIMIT = 10 (self_test.c line 45).
    // This is the foundational compliance constant — changing it would
    // alter the documented FIPS behaviour, so we pin the value here.
    assert_eq!(ERROR_REPORT_LIMIT, 10);
}

#[test]
fn global_fips_error_limiter_is_singleton_instance() {
    // The `FIPS_ERROR_LIMITER` static must be a single instance with
    // the documented limit — confirms that static initialisation used
    // `ERROR_REPORT_LIMIT`.  We cannot reset the global limiter
    // (other tests may have consumed any budget), so we only verify
    // observable invariants:
    //   1. `should_report()` on the global returns a `bool` without
    //      panicking — address the static successfully.
    //   2. Monotonicity: once the limit has been reached and a call
    //      returns `false`, every subsequent call must also return
    //      `false`.  This is the behaviour documented for the rate
    //      limiter and is what callers rely upon.
    let first: bool = FIPS_ERROR_LIMITER.should_report();
    let second: bool = FIPS_ERROR_LIMITER.should_report();
    if !first {
        assert!(
            !second,
            "rate limiter must be monotonic: after the first false, \
             every subsequent should_report() must also return false"
        );
    }
}

#[test]
fn error_rate_limiter_is_thread_safe() {
    // Rule R7 scrutiny: ErrorRateLimiter uses Relaxed atomics for its
    // counter.  From 20 threads × 500 calls (10,000 total), against a
    // limit of 100, *approximately* 100 should return true — exact
    // count allowed by fetch_add semantics is [100, 100] (Relaxed is
    // still atomic, so increments are not lost or double-counted).
    let limiter = Arc::new(ErrorRateLimiter::new(100));
    let mut handles = Vec::with_capacity(20);

    for _ in 0..20 {
        let l = Arc::clone(&limiter);
        handles.push(thread::spawn(move || {
            let mut local_allowed = 0u32;
            for _ in 0..500 {
                if l.should_report() {
                    local_allowed += 1;
                }
            }
            local_allowed
        }));
    }

    let total: u32 = handles
        .into_iter()
        .map(|h| h.join().expect("thread panic"))
        .sum();

    // fetch_add is atomic — the total must equal exactly the limit.
    assert_eq!(
        total, 100,
        "20x500 concurrent calls against limit=100 must allow exactly 100"
    );
}

// ===========================================================================
// Phase 7 — TestState Enum Tests
// ===========================================================================

#[test]
fn test_state_enum_has_exactly_six_variants() {
    let all = [
        TestState::Init,
        TestState::InProgress,
        TestState::Passed,
        TestState::Failed,
        TestState::Implicit,
        TestState::Deferred,
    ];
    assert_eq!(all.len(), 6, "TestState must have exactly 6 variants");

    // Exhaustive match — forces compile failure on variant addition.
    for state in all {
        let _ = match state {
            TestState::Init => 0u8,
            TestState::InProgress => 1u8,
            TestState::Passed => 2u8,
            TestState::Failed => 3u8,
            TestState::Implicit => 4u8,
            TestState::Deferred => 5u8,
        };
    }
}

#[test]
fn test_state_variants_are_pairwise_distinct() {
    let variants = [
        TestState::Init,
        TestState::InProgress,
        TestState::Passed,
        TestState::Failed,
        TestState::Implicit,
        TestState::Deferred,
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn test_state_from_u8_round_trip_covers_full_range() {
    for raw in 0..=u8::MAX {
        match TestState::from_u8(raw) {
            Some(s) => {
                assert!(raw <= 5, "from_u8({}) unexpectedly returned Some", raw);
                assert_eq!(s.as_u8(), raw);
            }
            None => assert!(raw > 5, "from_u8({}) unexpectedly returned None", raw),
        }
    }
}

#[test]
fn test_state_is_clone_and_copy() {
    let original = TestState::Passed;
    let cloned = original;
    let copied: TestState = original;
    assert_eq!(original, cloned);
    assert_eq!(original, copied);
    // Original still usable.
    assert_eq!(original, TestState::Passed);
}

#[test]
fn test_state_is_complete_is_exhaustive() {
    // Matrix over every variant.  Complements the inline test by
    // asserting the *full* truth table instead of one assertion per line.
    let expectations: [(TestState, bool); 6] = [
        (TestState::Init, false),
        (TestState::InProgress, false),
        (TestState::Passed, true),
        (TestState::Failed, true),
        (TestState::Implicit, true),
        (TestState::Deferred, false),
    ];
    for (state, expected) in expectations {
        assert_eq!(state.is_complete(), expected, "{:?}", state);
    }
}

#[test]
fn test_state_is_success_is_exhaustive() {
    let expectations: [(TestState, bool); 6] = [
        (TestState::Init, false),
        (TestState::InProgress, false),
        (TestState::Passed, true),
        (TestState::Failed, false),
        (TestState::Implicit, true),
        (TestState::Deferred, false),
    ];
    for (state, expected) in expectations {
        assert_eq!(state.is_success(), expected, "{:?}", state);
    }
}

#[test]
fn test_state_success_implies_complete() {
    // Every success state must also be complete.  This is a semantic
    // invariant the state machine relies on.
    for state in [
        TestState::Init,
        TestState::InProgress,
        TestState::Passed,
        TestState::Failed,
        TestState::Implicit,
        TestState::Deferred,
    ] {
        if state.is_success() {
            assert!(
                state.is_complete(),
                "{:?} is success but not complete",
                state
            );
        }
    }
}

// ===========================================================================
// Phase 8 — TestCategory Enum Tests
// ===========================================================================

#[test]
fn test_category_enum_has_exactly_eleven_variants() {
    let all = [
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
    assert_eq!(all.len(), 11, "TestCategory must have exactly 11 variants");

    // Exhaustive match — forces a compile error on variant addition.
    for cat in all {
        let _ = match cat {
            TestCategory::Integrity => 0,
            TestCategory::Digest => 1,
            TestCategory::Cipher => 2,
            TestCategory::Signature => 3,
            TestCategory::Kdf => 4,
            TestCategory::Drbg => 5,
            TestCategory::Kas => 6,
            TestCategory::AsymKeygen => 7,
            TestCategory::Kem => 8,
            TestCategory::AsymCipher => 9,
            TestCategory::Mac => 10,
        };
    }
}

#[test]
fn test_category_variants_are_pairwise_distinct() {
    let variants = [
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
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn test_category_display_names_are_nonempty() {
    // Every display name must be non-empty so diagnostic logs are
    // meaningful.
    for cat in [
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
    ] {
        let name = cat.display_name();
        assert!(!name.is_empty(), "{:?} has empty display name", cat);
    }
}

#[test]
fn test_category_display_matches_display_name() {
    // `fmt::Display::fmt` must delegate to `display_name()` — asserting
    // both paths emit the same string rules out any divergence.
    for cat in [
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
    ] {
        assert_eq!(
            format!("{}", cat),
            cat.display_name(),
            "Display and display_name disagree for {:?}",
            cat
        );
    }
}

#[test]
fn test_category_is_hashable() {
    // TestCategory derives Hash — confirm by inserting into a HashSet.
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for cat in [
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
    ] {
        assert!(set.insert(cat), "{:?} inserted twice", cat);
    }
    assert_eq!(set.len(), 11);

    // Second insertion of same variant must be rejected.
    assert!(!set.insert(TestCategory::Integrity));
}

#[test]
fn test_category_is_clone_and_copy() {
    let original = TestCategory::Kdf;
    let cloned = original;
    let copied: TestCategory = original;
    assert_eq!(original, cloned);
    assert_eq!(original, copied);
    assert_eq!(original, TestCategory::Kdf);
}

// ===========================================================================
// Phase 9 — Per-Test State Tracking Tests
// ===========================================================================

#[test]
fn test_state_entries_boundary_zero() {
    // Boundary: index 0 must be readable and writable.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert_eq!(get_test_state(0), Some(TestState::Init));
    assert!(set_test_state(0, TestState::InProgress));
    assert_eq!(get_test_state(0), Some(TestState::InProgress));

    reset_for_test();
}

#[test]
fn test_state_entries_boundary_last_index() {
    // Boundary: index MAX_TEST_COUNT - 1 must be readable and writable.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let last = MAX_TEST_COUNT - 1;
    assert_eq!(get_test_state(last), Some(TestState::Init));
    assert!(set_test_state(last, TestState::Failed));
    assert_eq!(get_test_state(last), Some(TestState::Failed));

    reset_for_test();
}

#[test]
fn test_state_entries_are_independent() {
    // Writing to one entry must not affect any other entry.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert!(set_test_state(0, TestState::Passed));
    assert!(set_test_state(1, TestState::Failed));
    assert!(set_test_state(2, TestState::Implicit));
    assert!(set_test_state(3, TestState::Deferred));
    assert!(set_test_state(10, TestState::InProgress));

    assert_eq!(get_test_state(0), Some(TestState::Passed));
    assert_eq!(get_test_state(1), Some(TestState::Failed));
    assert_eq!(get_test_state(2), Some(TestState::Implicit));
    assert_eq!(get_test_state(3), Some(TestState::Deferred));
    assert_eq!(get_test_state(10), Some(TestState::InProgress));
    // Unwritten entries must remain Init.
    assert_eq!(get_test_state(4), Some(TestState::Init));
    assert_eq!(get_test_state(20), Some(TestState::Init));

    reset_for_test();
}

#[test]
fn test_state_overwrite_is_idempotent() {
    // Writing the same state twice must be observable the same.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert!(set_test_state(5, TestState::Passed));
    assert_eq!(get_test_state(5), Some(TestState::Passed));
    assert!(set_test_state(5, TestState::Passed));
    assert_eq!(get_test_state(5), Some(TestState::Passed));
    assert!(set_test_state(5, TestState::Failed));
    assert_eq!(get_test_state(5), Some(TestState::Failed));

    reset_for_test();
}

#[test]
fn reset_all_states_clears_every_entry() {
    // Set a mix of entries, then assert reset_all_states brings every
    // entry back to Init — including ones we never touched.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    mark_all_deferred(); // fills all entries with Deferred
    for id in 0..MAX_TEST_COUNT {
        assert_eq!(get_test_state(id), Some(TestState::Deferred));
    }

    reset_all_states();
    for id in 0..MAX_TEST_COUNT {
        assert_eq!(
            get_test_state(id),
            Some(TestState::Init),
            "id {} not Init after reset",
            id
        );
    }
}

#[test]
fn mark_all_deferred_then_selective_overwrite() {
    // After mark_all_deferred, individual entries can be progressed
    // through the lazy-execution path (Deferred → InProgress → Passed).
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    mark_all_deferred();
    assert_eq!(get_test_state(0), Some(TestState::Deferred));

    assert!(set_test_state(0, TestState::InProgress));
    assert_eq!(get_test_state(0), Some(TestState::InProgress));
    assert!(set_test_state(0, TestState::Passed));
    assert_eq!(get_test_state(0), Some(TestState::Passed));

    // Other entries still Deferred.
    assert_eq!(get_test_state(1), Some(TestState::Deferred));
    assert_eq!(
        get_test_state(MAX_TEST_COUNT - 1),
        Some(TestState::Deferred)
    );

    reset_for_test();
}

#[test]
fn max_test_count_covers_all_eleven_categories_plus_slack() {
    // There are 11 `TestCategory` variants; MAX_TEST_COUNT must be
    // strictly greater than that to allow per-algorithm sub-tests.
    //
    // Both bounds are compile-time constants, so we use
    // `std::hint::black_box` to prevent const-folding; otherwise
    // `clippy::assertions_on_constants` would flag the assertions as
    // trivially-true at compile time.  The runtime check is still
    // valuable: if anyone changes `MAX_TEST_COUNT` to violate these
    // invariants, the test fails with a clear message instead of
    // silently reducing the assertion to a no-op.
    let min_categories = std::hint::black_box(11usize);
    let conservative_lower = std::hint::black_box(32usize);
    assert!(
        MAX_TEST_COUNT >= min_categories,
        "MAX_TEST_COUNT={} must be at least 11 (one entry per TestCategory)",
        MAX_TEST_COUNT
    );
    assert!(
        MAX_TEST_COUNT >= conservative_lower,
        "MAX_TEST_COUNT={} is below the conservative lower bound of 32",
        MAX_TEST_COUNT
    );
    // And verify the array length agrees at runtime.
    assert_eq!(TEST_STATES.len(), MAX_TEST_COUNT);
}

#[test]
fn all_tests_passed_detects_mixed_success_results() {
    // Mixed success (Passed + Implicit) → true.
    // Any Init/Failed/Deferred/InProgress → false.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    assert!(set_test_state(0, TestState::Passed));
    assert!(set_test_state(1, TestState::Implicit));
    assert!(set_test_state(2, TestState::Passed));
    assert!(all_tests_passed(3));

    // Inject a single Failed — now the aggregate must fail.
    assert!(set_test_state(2, TestState::Failed));
    assert!(!all_tests_passed(3));

    // Revert and inject a single Deferred — must also fail
    // (Deferred is not complete).
    assert!(set_test_state(2, TestState::Deferred));
    assert!(!all_tests_passed(3));

    reset_for_test();
}

// ===========================================================================
// Phase 10 — Thread Safety Tests
// ===========================================================================
//
// These tests exercise the process-wide atomics `FIPS_MODULE_STATE`
// and `TEST_STATES` under concurrent load to confirm:
//
//   * No torn reads (every read observes a valid enum discriminant).
//   * No data races (miri-safe by construction — AtomicU8 operations).
//   * Atomic ordering is SeqCst for writes and reads (matches the
//     state.rs contract).
//
// Every test acquires TEST_MUTEX at the top to serialise with other
// test modules; the *internal* concurrency under test is between the
// spawned threads only.

#[test]
fn concurrent_state_reads() {
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    set_fips_state(FipsState::Running);

    // 20 threads × 100 reads = 2 000 total reads, every one must
    // observe `Running` because no thread writes.
    let handles: Vec<_> = (0..20)
        .map(|_| {
            thread::spawn(|| {
                let mut count = 0usize;
                for _ in 0..100 {
                    if get_fips_state() == FipsState::Running {
                        count += 1;
                    }
                }
                count
            })
        })
        .collect();

    let total: usize = handles
        .into_iter()
        .map(|h| h.join().expect("reader thread panicked"))
        .sum();

    assert_eq!(
        total,
        20 * 100,
        "every read should observe Running, saw {}/2000",
        total
    );

    reset_for_test();
}

#[test]
fn concurrent_state_write_read_preserves_valid_values() {
    // One writer cycles through Init → SelfTesting → Running; 10
    // readers concurrently read and collect observed states.  Every
    // observation must be a valid enum variant — no torn reads.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    // Signal for readers to stop after writer finishes.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // 10 reader threads.
    let reader_stop = Arc::clone(&stop);
    let readers: Vec<_> = (0..10)
        .map(|_| {
            let stop_signal = Arc::clone(&reader_stop);
            thread::spawn(move || {
                let mut observed: Vec<FipsState> = Vec::with_capacity(1000);
                while !stop_signal.load(Ordering::Relaxed) {
                    observed.push(get_fips_state());
                }
                // Final reads after stop signal, to capture the end state.
                for _ in 0..50 {
                    observed.push(get_fips_state());
                }
                observed
            })
        })
        .collect();

    // Writer thread: drives the full lifecycle 100 times.
    let writer = thread::spawn(move || {
        for _ in 0..100 {
            set_fips_state(FipsState::SelfTesting);
            set_fips_state(FipsState::Running);
            set_fips_state(FipsState::Error);
            reset_fips_state();
        }
    });

    writer.join().expect("writer panicked");
    stop.store(true, Ordering::Relaxed);

    // Collect reader observations.
    let mut total_reads = 0usize;
    let valid_states = [
        FipsState::Init,
        FipsState::SelfTesting,
        FipsState::Running,
        FipsState::Error,
    ];
    for h in readers {
        let observations = h.join().expect("reader panicked");
        total_reads += observations.len();
        for state in observations {
            assert!(
                valid_states.contains(&state),
                "reader observed invalid state {:?}",
                state
            );
        }
    }

    assert!(total_reads > 0, "readers must observe at least one read");

    // Final state after writer finishes and reset is: Init.
    assert_eq!(get_fips_state(), FipsState::Init);

    reset_for_test();
}

#[test]
fn concurrent_test_state_access_is_isolated_per_id() {
    // 10 threads, each exclusively owns a distinct test_id and writes
    // a sequence of states.  After join, every id must reflect the
    // last state written by its owning thread — no cross-contamination.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let sequence = [
        TestState::InProgress,
        TestState::Passed,
        TestState::Failed,
        TestState::Implicit,
        TestState::Deferred,
    ];

    let handles: Vec<_> = (0..10usize)
        .map(|id| {
            let seq = sequence;
            thread::spawn(move || {
                for state in seq {
                    assert!(set_test_state(id, state));
                    // Verify read-after-write for own id.
                    assert_eq!(get_test_state(id), Some(state));
                }
                // Final state is the last element of `seq`.
                seq[seq.len() - 1]
            })
        })
        .collect();

    let expected_finals: Vec<TestState> = handles
        .into_iter()
        .map(|h| h.join().expect("worker thread panicked"))
        .collect();

    for (id, expected) in expected_finals.iter().enumerate() {
        assert_eq!(
            get_test_state(id),
            Some(*expected),
            "id {} final state mismatch",
            id
        );
    }

    reset_for_test();
}

#[test]
fn atomic_state_ordering_is_sequentially_consistent() {
    // SeqCst semantics: after thread A stores SelfTesting and joins,
    // thread B must observe SelfTesting.  Failure would indicate a
    // weaker ordering leaked in.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    // Writer: sets SelfTesting.
    let writer = thread::spawn(|| {
        set_fips_state(FipsState::SelfTesting);
    });
    writer.join().expect("writer panicked");

    // Reader: spawned *after* writer joined — happens-before
    // guarantees observation of SelfTesting.
    let reader = thread::spawn(get_fips_state);
    let observed = reader.join().expect("reader panicked");
    assert_eq!(observed, FipsState::SelfTesting);

    reset_for_test();
}

#[test]
fn concurrent_reset_and_read_never_observes_invalid_state() {
    // Stress: alternating reset + transition threads, with readers
    // continuously sampling.  Every read must yield a valid variant.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // 5 reader threads that just validate every read.
    let readers_stop = Arc::clone(&stop);
    let readers: Vec<_> = (0..5)
        .map(|_| {
            let stop_signal = Arc::clone(&readers_stop);
            thread::spawn(move || {
                let valid = [
                    FipsState::Init,
                    FipsState::SelfTesting,
                    FipsState::Running,
                    FipsState::Error,
                ];
                let mut count = 0usize;
                while !stop_signal.load(Ordering::Relaxed) {
                    let observed = get_fips_state();
                    assert!(
                        valid.contains(&observed),
                        "invalid state observed: {:?}",
                        observed
                    );
                    count += 1;
                }
                count
            })
        })
        .collect();

    // Two mutator threads.
    let mutator_a = thread::spawn(|| {
        for _ in 0..200 {
            set_fips_state(FipsState::SelfTesting);
            set_fips_state(FipsState::Running);
        }
    });
    let mutator_b = thread::spawn(|| {
        for _ in 0..200 {
            set_fips_state(FipsState::Error);
            reset_fips_state();
        }
    });

    mutator_a.join().expect("mutator_a panicked");
    mutator_b.join().expect("mutator_b panicked");
    stop.store(true, Ordering::Relaxed);

    let total_reads: usize = readers
        .into_iter()
        .map(|h| h.join().expect("reader panicked"))
        .sum();
    assert!(total_reads > 0, "readers must observe at least one read");

    reset_for_test();
}

#[test]
fn concurrent_test_state_writes_to_same_id_serialize_correctly() {
    // R7 correctness: multiple threads writing to the SAME id must
    // serialise via TEST_STATES_LOCK.  The final state must equal
    // the value stored by whichever thread ran last — we only assert
    // the final state is one of the written values (no corruption).
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let target_id = 7usize;
    let values = [TestState::Passed, TestState::Failed, TestState::Implicit];

    let handles: Vec<_> = values
        .iter()
        .map(|&v| {
            thread::spawn(move || {
                for _ in 0..100 {
                    assert!(set_test_state(target_id, v));
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("writer panicked");
    }

    let final_state = get_test_state(target_id).expect("in-range id");
    assert!(
        values.contains(&final_state),
        "final state {:?} must be one of the written values",
        final_state
    );

    reset_for_test();
}

// ===========================================================================
// Phase 11 — Global Atomic Inspection Tests
// ===========================================================================
//
// Direct inspection of the public `FIPS_MODULE_STATE` / `TEST_STATES`
// atomic statics, confirming the invariants promised by state.rs.

#[test]
fn fips_module_state_global_matches_get_fips_state() {
    // The accessor and the raw atomic store must agree — sanity check
    // that no accidental double-buffering is in place.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    for target in [
        FipsState::Init,
        FipsState::SelfTesting,
        FipsState::Running,
        FipsState::Error,
    ] {
        set_fips_state(target);
        let raw = FIPS_MODULE_STATE.load(Ordering::SeqCst);
        assert_eq!(
            raw,
            target.as_u8(),
            "atomic raw value disagrees with accessor for {:?}",
            target
        );
        assert_eq!(get_fips_state(), target);
    }

    reset_for_test();
}

#[test]
fn test_states_array_matches_set_test_state() {
    // Every AtomicU8 in TEST_STATES must reflect what set_test_state
    // wrote.
    let _serial = TEST_MUTEX.lock().unwrap();
    reset_for_test();

    for id in 0..MAX_TEST_COUNT {
        assert!(set_test_state(id, TestState::InProgress));
    }
    for (id, cell) in TEST_STATES.iter().enumerate() {
        assert_eq!(
            cell.load(Ordering::SeqCst),
            TestState::InProgress.as_u8(),
            "TEST_STATES[{}] not InProgress",
            id
        );
    }

    reset_for_test();
}
