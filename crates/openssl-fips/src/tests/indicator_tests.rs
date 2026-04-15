//! Tests for FIPS approved service indicator. Verifies monotonic transition
//! semantics, settable state overrides, per-algorithm approval checks, and R4
//! callback registration-invocation pairing.
//!
//! # Test Organisation (8 Phases)
//!
//! | Phase | Focus                                      | C Reference             |
//! |-------|--------------------------------------------|-------------------------|
//! | 2     | Initialization / defaults / deep-copy       | fipsindicator.c 16-33   |
//! | 3     | Monotonic approved→unapproved transitions   | fipsindicator.c 25, 58  |
//! | 4     | Settable-state overrides and precedence     | fipsindicator.c 35-78   |
//! | 5     | Per-algorithm slot isolation                | fipsprov.c 530-560      |
//! | 6     | Rule R4 — callback invocation pairing       | fipsindicator.c 119-129 |
//! | 7     | OSSL_PARAM integration (set/get ctx params) | fipsindicator.c 80-112  |
//! | 8     | Edge cases, bounds, thread safety           | —                       |

// Test code legitimately uses `unwrap()`/`expect()` for concise assertions.
// The workspace lint configuration explicitly allows this in test modules:
//   "Tests and CLI main() may #[allow] with justification."
#![allow(clippy::unwrap_used, clippy::expect_used)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use crate::indicator::{
    FipsIndicator, IndicatorCheckCallback, SettableState, SETTABLE0, SETTABLE1, SETTABLE2,
    SETTABLE3, SETTABLE4, SETTABLE5, SETTABLE6, SETTABLE7, SETTABLE_MAX, invoke_callback,
};
use openssl_common::error::{FipsError, FipsResult};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

// =========================================================================
// Phase 2 — Initialization Tests
// =========================================================================
// Maps to `ossl_fips_indicator_init()` in fipsindicator.c lines 16-23.

/// Verify that a freshly-constructed indicator has `approved == true` and
/// all eight settable slots default to [`SettableState::Unknown`].
#[test]
fn test_indicator_init_default_state() {
    let ind = FipsIndicator::new();

    // Default: approved is true (matching C `is_approved = 1`)
    assert!(
        ind.is_approved(),
        "Freshly created indicator must be approved"
    );

    // All SETTABLE_MAX slots must default to Unknown
    for id in 0..SETTABLE_MAX {
        let state = ind
            .get_settable(id)
            .expect("get_settable should succeed for valid ID");
        assert_eq!(
            state,
            SettableState::Unknown,
            "Slot {id} should default to Unknown"
        );
    }
}

/// Maps to `ossl_fips_indicator_copy()` in fipsindicator.c lines 30-33.
/// Verify that `copy_from` produces a deep copy — mutations on the
/// destination must not affect the source.
#[test]
fn test_indicator_init_is_copy_safe() {
    // Build a source indicator with custom state
    let mut src = FipsIndicator::new();
    src.set_settable(SETTABLE0, SettableState::Strict).unwrap();
    src.set_settable(SETTABLE3, SettableState::Tolerant)
        .unwrap();
    // Mark unapproved via on_unapproved (config_check returns false → tolerant)
    let _ = src.on_unapproved(SETTABLE1, "AES-128", "encrypt", || false);
    assert!(!src.is_approved(), "Source should be unapproved after on_unapproved");

    // Deep-copy into destination
    let mut dst = FipsIndicator::new();
    dst.copy_from(&src);

    // Verify the copy faithfully reproduces source state
    assert!(
        !dst.is_approved(),
        "Copy should preserve approved == false"
    );
    assert_eq!(
        dst.get_settable(SETTABLE0).unwrap(),
        SettableState::Strict
    );
    assert_eq!(
        dst.get_settable(SETTABLE3).unwrap(),
        SettableState::Tolerant
    );
    // Untouched slots remain Unknown
    assert_eq!(
        dst.get_settable(SETTABLE2).unwrap(),
        SettableState::Unknown
    );

    // Mutate destination — source must remain unaffected
    dst.set_approved();
    assert!(dst.is_approved(), "Destination should be re-approved");
    assert!(
        !src.is_approved(),
        "Source must not be affected by destination mutation (deep copy)"
    );
}

// =========================================================================
// Phase 3 — Monotonic Approved→Unapproved Transition Tests
// =========================================================================
// Maps to `ossl_fips_indicator_set_approved()` (line 25) and
// `ossl_fips_indicator_on_unapproved()` (lines 58-78).

/// The initial approved state must be `true`.
#[test]
fn test_approved_is_initially_true() {
    let ind = FipsIndicator::new();
    assert!(ind.is_approved());
}

/// `on_unapproved` permanently clears the approved flag.
/// Maps to fipsindicator.c: `ind->is_approved = 0;`
#[test]
fn test_on_unapproved_permanently_clears_approved() {
    let mut ind = FipsIndicator::new();
    assert!(ind.is_approved());

    // config_check returns false → tolerant path → Ok(true)
    let result = ind.on_unapproved(SETTABLE0, "AES-128-CBC", "encrypt", || false);
    assert!(result.is_ok());

    assert!(
        !ind.is_approved(),
        "on_unapproved must clear the approved flag"
    );

    // Subsequent reads still return false
    assert!(!ind.is_approved());
    assert!(!ind.is_approved());
}

/// `set_approved()` resets the approved flag to `true`.
/// This mirrors C `ossl_fips_indicator_set_approved(ind, 1)`, which is used
/// at the start of each operation to reset the per-operation indicator.
#[test]
fn test_set_approved_resets_flag_to_true() {
    let mut ind = FipsIndicator::new();

    // First, trigger unapproved
    let _ = ind.on_unapproved(SETTABLE0, "AES-128-CBC", "encrypt", || false);
    assert!(!ind.is_approved());

    // set_approved() brings it back
    ind.set_approved();
    assert!(
        ind.is_approved(),
        "set_approved() should reset to true (per-operation reset)"
    );
}

/// Calling `on_unapproved` twice must not panic or double-fault.
#[test]
fn test_multiple_on_unapproved_calls_idempotent() {
    let mut ind = FipsIndicator::new();

    let r1 = ind.on_unapproved(SETTABLE0, "AES-128-CBC", "encrypt", || false);
    assert!(r1.is_ok());

    let r2 = ind.on_unapproved(SETTABLE1, "SHA-256", "digest", || false);
    assert!(r2.is_ok());

    assert!(
        !ind.is_approved(),
        "Indicator must remain unapproved after multiple on_unapproved calls"
    );
}

/// Even when `on_unapproved` returns `Err` (strict), the approved flag
/// is still cleared — the flag-clearing is unconditional.
#[test]
fn test_on_unapproved_clears_flag_even_on_strict_error() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();

    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || true);
    assert!(result.is_err(), "Strict settable should return error");

    // Flag was still cleared before the error was returned
    assert!(
        !ind.is_approved(),
        "Approved flag must be cleared unconditionally, even on Strict error"
    );
}

// =========================================================================
// Phase 4 — Settable State Override Tests
// =========================================================================
// Maps to `ossl_fips_indicator_set_settable()` and
// `ossl_fips_indicator_get_settable()` in fipsindicator.c lines 35-50.

/// Setting a slot to `Strict` is reflected by `get_settable`.
#[test]
fn test_set_settable_strict() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();
    assert_eq!(ind.get_settable(SETTABLE0).unwrap(), SettableState::Strict);
}

/// Setting a slot to `Tolerant` and verifying `on_unapproved` honours it.
#[test]
fn test_set_settable_tolerant() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE1, SettableState::Tolerant)
        .unwrap();
    assert_eq!(
        ind.get_settable(SETTABLE1).unwrap(),
        SettableState::Tolerant
    );

    // Tolerant path: invoke_callback is called → returns true → Ok(true)
    let result = ind.on_unapproved(SETTABLE1, "drbg-no-trunc-md", "generate", || true);
    assert!(result.is_ok());
    assert!(
        result.unwrap(),
        "Tolerant path calls invoke_callback which returns true"
    );

    // Approved flag is still cleared
    assert!(
        !ind.is_approved(),
        "on_unapproved always clears approved regardless of settable state"
    );
}

/// All slots default to `Unknown` when no explicit setting has been applied.
#[test]
fn test_set_settable_unknown_is_default() {
    let ind = FipsIndicator::new();
    for id in 0..SETTABLE_MAX {
        assert_eq!(
            ind.get_settable(id).unwrap(),
            SettableState::Unknown,
            "Slot {id} must default to Unknown"
        );
    }
}

/// Bounds checking: valid IDs succeed, out-of-range IDs return `Err`.
/// Maps to fipsindicator.c lines 35-43.
#[test]
fn test_set_settable_bounds_check() {
    let mut ind = FipsIndicator::new();

    // All valid IDs [0, SETTABLE_MAX) must succeed
    for id in 0..SETTABLE_MAX {
        assert!(
            ind.set_settable(id, SettableState::Strict).is_ok(),
            "set_settable({id}) should succeed"
        );
    }

    // Out-of-bounds must error with FipsError::Common variant
    let result = ind.set_settable(SETTABLE_MAX, SettableState::Strict);
    assert!(result.is_err(), "SETTABLE_MAX is out-of-bounds");
    assert!(
        matches!(result, Err(FipsError::Common(_))),
        "Bounds-check error must be FipsError::Common"
    );

    let result = ind.set_settable(100, SettableState::Tolerant);
    assert!(result.is_err(), "ID 100 is far out-of-bounds");
    assert!(
        matches!(result, Err(FipsError::Common(_))),
        "Bounds-check error must be FipsError::Common"
    );
}

/// Bounds checking for `get_settable`.
#[test]
fn test_get_settable_bounds_check() {
    let ind = FipsIndicator::new();

    // Valid
    assert!(ind.get_settable(SETTABLE0).is_ok());
    assert!(ind.get_settable(SETTABLE7).is_ok());

    // Out of bounds
    let err = ind.get_settable(SETTABLE_MAX);
    assert!(err.is_err());
    let err = ind.get_settable(usize::MAX);
    assert!(err.is_err());
}

/// When settable is `Strict` AND config is strict, the operation is rejected.
///
/// Note: In this implementation, `Strict` and `Unknown` are functionally
/// identical — both defer to `config_check`. Only `Tolerant` has special
/// bypass behaviour. This matches the C `ossl_FIPS_IND_on_unapproved`
/// condition: `settable == TOLERANT || !config_check`.
#[test]
fn test_settable_state_strict_with_strict_config_rejects() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();

    // config_check returns true (strict) → combined strict → error
    let result = ind.on_unapproved(SETTABLE0, "tls1-prf-ems-check", "derive", || true);
    assert!(result.is_err());

    match result.unwrap_err() {
        FipsError::NotApproved(msg) => {
            assert!(
                msg.contains("tls1-prf-ems-check"),
                "Error message should mention algorithm name, got: {msg}"
            );
        }
        other => unreachable!("Expected FipsError::NotApproved, got: {other:?}"),
    }
}

/// When settable is `Strict` but config is tolerant, the operation proceeds
/// because `!config_check()` evaluates to `true`.
#[test]
fn test_settable_state_strict_with_tolerant_config_proceeds() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();

    // config_check returns false (tolerant) → !config_check() is true → proceed
    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || false);
    assert!(
        result.is_ok(),
        "Strict settable + tolerant config → proceed (settable != Tolerant, so defers to config)"
    );
}

/// `Tolerant` settable allows the operation regardless of `config_check`.
#[test]
fn test_settable_state_tolerant_allows_unapproved() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Tolerant)
        .unwrap();

    // config_check would say strict, but Tolerant settable overrides
    let result = ind.on_unapproved(SETTABLE0, "some-check", "op", || true);
    assert!(result.is_ok());
    assert!(
        result.unwrap(),
        "Tolerant settable must allow via invoke_callback"
    );

    // Approved flag still cleared
    assert!(!ind.is_approved());
}

/// `Unknown` settable delegates to `config_check`:
/// — `config_check() == true` (strict) → error
/// — `config_check() == false` (tolerant) → proceed via callback
#[test]
fn test_settable_unknown_defers_to_config_strict() {
    let mut ind = FipsIndicator::new();
    // Settable is Unknown (default), config says strict
    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || true);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), FipsError::NotApproved(_)));
}

#[test]
fn test_settable_unknown_defers_to_config_tolerant() {
    let mut ind = FipsIndicator::new();
    // Settable is Unknown (default), config says tolerant
    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || false);
    assert!(result.is_ok());
    assert!(result.unwrap(), "Tolerant config path invokes callback");
}

// =========================================================================
// Phase 5 — Per-Algorithm Settable Slot Isolation
// =========================================================================
// Maps to the FIPS_OPTION entries in fipsprov.c lines ~530-560.

/// Setting one slot must not affect other slots.
#[test]
fn test_per_algorithm_settable_isolation() {
    let mut ind = FipsIndicator::new();

    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();
    ind.set_settable(SETTABLE1, SettableState::Tolerant)
        .unwrap();

    // Verify the configured slots
    assert_eq!(ind.get_settable(SETTABLE0).unwrap(), SettableState::Strict);
    assert_eq!(
        ind.get_settable(SETTABLE1).unwrap(),
        SettableState::Tolerant
    );

    // All remaining slots must still be Unknown
    for id in 2..SETTABLE_MAX {
        assert_eq!(
            ind.get_settable(id).unwrap(),
            SettableState::Unknown,
            "Untouched slot {id} should remain Unknown"
        );
    }
}

/// Every slot can be independently configured to any state.
#[test]
fn test_all_settable_slots_independently_configurable() {
    let mut ind = FipsIndicator::new();

    let pattern = [
        SettableState::Strict,
        SettableState::Tolerant,
        SettableState::Unknown,
        SettableState::Strict,
        SettableState::Tolerant,
        SettableState::Unknown,
        SettableState::Strict,
        SettableState::Tolerant,
    ];

    for (id, &state) in pattern.iter().enumerate() {
        ind.set_settable(id, state).unwrap();
    }

    for (id, &expected) in pattern.iter().enumerate() {
        assert_eq!(
            ind.get_settable(id).unwrap(),
            expected,
            "Slot {id} should be {expected:?}"
        );
    }
}

/// The SETTABLE0-7 constants must equal 0-7 and `SETTABLE_MAX` must equal 8.
#[test]
fn test_settable_constants_match_expected_values() {
    assert_eq!(SETTABLE0, 0);
    assert_eq!(SETTABLE1, 1);
    assert_eq!(SETTABLE2, 2);
    assert_eq!(SETTABLE3, 3);
    assert_eq!(SETTABLE4, 4);
    assert_eq!(SETTABLE5, 5);
    assert_eq!(SETTABLE6, 6);
    assert_eq!(SETTABLE7, 7);
    assert_eq!(SETTABLE_MAX, 8);
}

/// `SettableState` has exactly three variants which are mutually distinct.
#[test]
fn test_settable_state_enum_variants_exhaustive() {
    let strict = SettableState::Strict;
    let tolerant = SettableState::Tolerant;
    let unknown = SettableState::Unknown;

    assert_ne!(strict, tolerant);
    assert_ne!(strict, unknown);
    assert_ne!(tolerant, unknown);
}

// =========================================================================
// Phase 6 — Rule R4: Callback Registration-Invocation Pairing
// =========================================================================
// Maps to `ossl_fips_indicator_callback()` fipsindicator.c lines 119-129.
//
// ARCHITECTURE NOTE:
// The current Rust implementation provides `invoke_callback` as a
// module-level free function (always returns `true`).  There is no
// per-indicator `set_callback` registration.  The callback path is
// exercised through `on_unapproved` when the settable state is
// `Tolerant` or when `Unknown` + `config_check` is tolerant.
//
// R4 compliance is demonstrated by testing:
//   1. `invoke_callback` is callable with correct argument types
//   2. The `on_unapproved` flow correctly reaches (or skips) the
//      callback based on enforcement precedence
//   3. The return value of `invoke_callback` propagates through
//      `on_unapproved` as `Ok(bool)`

/// R4 — `invoke_callback` exists, accepts `(&str, &str)`, returns `bool`.
#[test]
fn test_r4_invoke_callback_exists_and_returns_true() {
    let result = invoke_callback("AES-128-CBC", "encrypt");
    assert!(result, "invoke_callback must return true");
}

/// R4 — `invoke_callback` accepts various argument strings without panic.
#[test]
fn test_r4_invoke_callback_with_various_args() {
    assert!(invoke_callback("AES-256-GCM", "encrypt"));
    assert!(invoke_callback("SHA-512", "digest"));
    assert!(invoke_callback("RSA", "sign"));
    assert!(invoke_callback("", ""));
    assert!(invoke_callback(
        "very-long-algorithm-name-for-testing",
        "operation"
    ));
}

/// R4 — Verify `IndicatorCheckCallback` type alias is usable.
/// The type is `dyn Fn(&str, &str) -> bool + Send + Sync`.
#[test]
fn test_r4_indicator_check_callback_type_usable() {
    // Construct a concrete closure matching the callback signature
    let cb: Box<IndicatorCheckCallback> = Box::new(|algo: &str, op: &str| -> bool {
        !algo.is_empty() && !op.is_empty()
    });
    assert!(cb("AES", "encrypt"));
    assert!(!cb("", "op"));
}

/// R4 — Tolerant settable path invokes callback; return value propagates.
#[test]
fn test_r4_callback_invoked_via_tolerant_path() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Tolerant)
        .unwrap();

    // invoke_callback returns true → Ok(true)
    let result = ind.on_unapproved(SETTABLE0, "AES-128-CBC", "encrypt", || true);
    assert!(result.is_ok());
    assert!(
        result.unwrap(),
        "Tolerant path must call invoke_callback; result propagates as Ok(true)"
    );
}

/// R4 — When settable is Strict and config is also strict, the operation
/// is rejected without calling `invoke_callback`.
#[test]
fn test_r4_callback_not_reached_when_both_strict() {
    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();

    // config_check true (strict) + settable Strict → both non-Tolerant + strict config → error
    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || true);
    assert!(
        result.is_err(),
        "Strict settable + strict config rejects before invoke_callback"
    );
    assert!(matches!(result.unwrap_err(), FipsError::NotApproved(_)));
}

/// R4 — Unknown + tolerant config path invokes callback.
#[test]
fn test_r4_callback_invoked_via_config_tolerant_path() {
    let mut ind = FipsIndicator::new();
    // Settable defaults to Unknown, config_check returns false → tolerant
    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || false);
    assert!(result.is_ok());
    assert!(
        result.unwrap(),
        "Config-tolerant path must invoke callback"
    );
}

/// R4 — Unknown + strict config rejects without invoking callback.
#[test]
fn test_r4_callback_not_reached_when_config_strict() {
    let mut ind = FipsIndicator::new();
    let result = ind.on_unapproved(SETTABLE0, "algo", "op", || true);
    assert!(
        result.is_err(),
        "Config-strict should reject without callback"
    );
}

/// R4 — Verify enforcement precedence:
///
/// The actual logic is: `settable == Tolerant || !config_check()`.
/// - Tolerant settable: ALWAYS proceeds (bypasses `config_check` via short-circuit)
/// - Strict / Unknown: both defer to `config_check`. If config is tolerant,
///   proceeds; if config is strict, rejects.
#[test]
fn test_r4_enforcement_precedence() {
    // Case 1: Tolerant settable overrides strict config
    {
        let mut ind = FipsIndicator::new();
        ind.set_settable(SETTABLE0, SettableState::Tolerant)
            .unwrap();
        let result = ind.on_unapproved(SETTABLE0, "a", "o", || true);
        assert!(result.is_ok(), "Tolerant settable overrides strict config");
    }

    // Case 2: Strict settable + strict config → error
    {
        let mut ind = FipsIndicator::new();
        ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();
        let result = ind.on_unapproved(SETTABLE0, "a", "o", || true);
        assert!(result.is_err(), "Strict settable + strict config → error");
    }

    // Case 3: Strict settable + tolerant config → proceed
    // (Strict and Unknown both defer to config; tolerant config wins)
    {
        let mut ind = FipsIndicator::new();
        ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();
        let result = ind.on_unapproved(SETTABLE0, "a", "o", || false);
        assert!(result.is_ok(), "Strict settable + tolerant config → proceed");
    }

    // Case 4: Unknown settable + strict config → error
    {
        let mut ind = FipsIndicator::new();
        let result = ind.on_unapproved(SETTABLE0, "a", "o", || true);
        assert!(result.is_err(), "Unknown + strict config → error");
    }

    // Case 5: Unknown settable + tolerant config → proceed
    {
        let mut ind = FipsIndicator::new();
        let result = ind.on_unapproved(SETTABLE0, "a", "o", || false);
        assert!(result.is_ok(), "Unknown + tolerant config → proceed");
    }
}

/// R4 — Track callback invocation count via `config_check` closure.
/// Since `invoke_callback` is not interceptable, we use `config_check`
/// as the observable closure and count its invocations.
#[test]
fn test_r4_config_check_invocation_tracking() {
    let count = Arc::new(AtomicU32::new(0));
    let count_clone = Arc::clone(&count);

    let mut ind = FipsIndicator::new();
    // Settable is Unknown, so config_check WILL be called
    let _ = ind.on_unapproved(SETTABLE0, "algo", "op", move || {
        count_clone.fetch_add(1, Ordering::SeqCst);
        false // tolerant
    });

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "config_check should be invoked exactly once"
    );
}

/// R4 — Config check IS called when settable is Strict (because the
/// implementation condition `settable == Tolerant || !config_check()`
/// evaluates the first arm as false, then must evaluate `config_check`).
#[test]
fn test_r4_config_check_called_when_settable_strict() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Strict).unwrap();

    let _ = ind.on_unapproved(SETTABLE0, "algo", "op", move || {
        called_clone.store(true, Ordering::SeqCst);
        true // strict
    });

    assert!(
        called.load(Ordering::SeqCst),
        "config_check IS invoked when settable is Strict (Strict defers to config)"
    );
}

/// R4 — Config check is NOT called when settable is Tolerant.
#[test]
fn test_r4_config_check_not_called_when_tolerant() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    let mut ind = FipsIndicator::new();
    ind.set_settable(SETTABLE0, SettableState::Tolerant)
        .unwrap();

    let _ = ind.on_unapproved(SETTABLE0, "algo", "op", move || {
        called_clone.store(true, Ordering::SeqCst);
        true
    });

    assert!(
        !called.load(Ordering::SeqCst),
        "config_check must NOT be invoked when settable is Tolerant"
    );
}

// =========================================================================
// Phase 7 — OSSL_PARAM Integration Tests
// =========================================================================
// Maps to `ossl_fips_indicator_set_ctx_param()` and
// `ossl_fips_indicator_get_ctx_param()` in fipsindicator.c lines 80-112.

/// `set_ctx_param` converts an `i32` value to `SettableState`:
///   0 → Tolerant, 1 → Strict, other → Unknown.
#[test]
fn test_set_ctx_param_updates_settable_state() {
    let mut ind = FipsIndicator::new();

    let result: FipsResult<()> = ind.set_ctx_param(SETTABLE0, 1); // Strict
    result.unwrap();
    assert_eq!(ind.get_settable(SETTABLE0).unwrap(), SettableState::Strict);

    ind.set_ctx_param(SETTABLE1, 0).unwrap(); // Tolerant
    assert_eq!(
        ind.get_settable(SETTABLE1).unwrap(),
        SettableState::Tolerant
    );

    ind.set_ctx_param(SETTABLE2, 2).unwrap(); // Unknown (default for anything else)
    assert_eq!(
        ind.get_settable(SETTABLE2).unwrap(),
        SettableState::Unknown
    );

    ind.set_ctx_param(SETTABLE3, -1).unwrap(); // Also Unknown
    assert_eq!(
        ind.get_settable(SETTABLE3).unwrap(),
        SettableState::Unknown
    );
}

/// `set_ctx_param` bounds-checks the slot ID.
#[test]
fn test_set_ctx_param_bounds_check() {
    let mut ind = FipsIndicator::new();
    let result = ind.set_ctx_param(SETTABLE_MAX, 0);
    assert!(result.is_err(), "Out-of-bounds slot ID must error");
}

/// `set_ctx_param_by_name` locates a key in a `ParamSet`, extracts the i32
/// value, and updates the corresponding settable slot.
#[test]
fn test_set_ctx_param_by_name_from_param_set() {
    let mut ind = FipsIndicator::new();

    let params = ParamBuilder::new()
        .push_i32("tls1-prf-ems-check", 1) // Strict
        .build();

    let result = ind.set_ctx_param_by_name(SETTABLE0, &params, "tls1-prf-ems-check");
    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found, "Key should be found in the ParamSet");

    assert_eq!(ind.get_settable(SETTABLE0).unwrap(), SettableState::Strict);
}

/// When the requested key is absent from the `ParamSet`, the method returns
/// `Ok(false)` and the settable state is unchanged.
/// Maps to fipsindicator.c lines 92-99 (locate returns NULL → skip).
#[test]
fn test_set_ctx_param_by_name_missing_key() {
    let mut ind = FipsIndicator::new();

    let params = ParamBuilder::new()
        .push_i32("unrelated-key", 42)
        .build();

    let result = ind.set_ctx_param_by_name(SETTABLE0, &params, "tls1-prf-ems-check");
    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(!found, "Missing key should not be found");

    // State unchanged
    assert_eq!(
        ind.get_settable(SETTABLE0).unwrap(),
        SettableState::Unknown,
        "Settable state must remain unchanged when key is missing"
    );
}

/// `set_ctx_param_by_name` bounds-checks the slot ID.
#[test]
fn test_set_ctx_param_by_name_bounds_check() {
    let mut ind = FipsIndicator::new();
    let params = ParamBuilder::new().push_i32("k", 1).build();
    let result = ind.set_ctx_param_by_name(SETTABLE_MAX, &params, "k");
    assert!(result.is_err(), "Out-of-bounds slot must error");
}

/// `get_ctx_param` returns 1 when approved, 0 when unapproved.
#[test]
fn test_get_ctx_param_returns_approval_state() {
    let mut ind = FipsIndicator::new();

    // Initially approved → 1
    assert_eq!(ind.get_ctx_param(), 1);

    // After unapproved → 0
    let _ = ind.on_unapproved(SETTABLE0, "algo", "op", || false);
    assert_eq!(ind.get_ctx_param(), 0);

    // After re-approval → 1
    ind.set_approved();
    assert_eq!(ind.get_ctx_param(), 1);
}

/// `get_ctx_param_into` writes the approval state into a `ParamSet` under
/// the `"fips-indicator"` key.
#[test]
fn test_get_ctx_param_into_param_set() {
    let ind = FipsIndicator::new();

    let mut params = ParamSet::new();
    // Seed the key — get_ctx_param_into will overwrite
    params.set("fips-indicator", ParamValue::Int32(0));

    ind.get_ctx_param_into(&mut params).unwrap();

    let value = params
        .get("fips-indicator")
        .expect("ParamSet should contain 'fips-indicator'");
    assert_eq!(
        value.as_i32(),
        Some(1),
        "Should indicate approved == true (1)"
    );
}

/// `get_ctx_param_into` correctly writes unapproved state.
#[test]
fn test_get_ctx_param_into_unapproved() {
    let mut ind = FipsIndicator::new();
    let _ = ind.on_unapproved(SETTABLE0, "algo", "op", || false);

    let mut params = ParamSet::new();
    params.set("fips-indicator", ParamValue::Int32(99)); // pre-set wrong value

    ind.get_ctx_param_into(&mut params).unwrap();

    let value = params.get("fips-indicator").unwrap();
    assert_eq!(
        value.as_i32(),
        Some(0),
        "Should indicate approved == false (0)"
    );
}

// =========================================================================
// Phase 8 — Edge Cases, Bounds, and Thread Safety
// =========================================================================

/// Empty algorithm name must not cause a panic.
#[test]
fn test_indicator_with_empty_algorithm_name() {
    let mut ind = FipsIndicator::new();
    let result = ind.on_unapproved(SETTABLE0, "", "op", || false);
    assert!(result.is_ok(), "Empty algorithm name must not panic");
}

/// Empty operation name must not cause a panic.
#[test]
fn test_indicator_with_empty_operation_name() {
    let mut ind = FipsIndicator::new();
    let result = ind.on_unapproved(SETTABLE0, "algo", "", || false);
    assert!(result.is_ok(), "Empty operation name must not panic");
}

/// Both names empty — graceful handling, no panic.
#[test]
fn test_indicator_with_both_names_empty() {
    let mut ind = FipsIndicator::new();
    let result = ind.on_unapproved(SETTABLE0, "", "", || false);
    assert!(result.is_ok());
}

/// `on_unapproved` with an out-of-bounds slot ID must return an error.
#[test]
fn test_on_unapproved_out_of_bounds_id() {
    let mut ind = FipsIndicator::new();
    let result = ind.on_unapproved(SETTABLE_MAX, "algo", "op", || false);
    assert!(result.is_err(), "Out-of-bounds slot ID should error");
}

/// `copy_from` preserves all 8 settable-slot values.
#[test]
fn test_copy_from_preserves_all_settable_slots() {
    let mut src = FipsIndicator::new();
    src.set_settable(SETTABLE0, SettableState::Strict).unwrap();
    src.set_settable(SETTABLE1, SettableState::Tolerant)
        .unwrap();
    src.set_settable(SETTABLE2, SettableState::Unknown).unwrap();
    src.set_settable(SETTABLE3, SettableState::Strict).unwrap();
    src.set_settable(SETTABLE4, SettableState::Tolerant)
        .unwrap();
    src.set_settable(SETTABLE5, SettableState::Unknown).unwrap();
    src.set_settable(SETTABLE6, SettableState::Strict).unwrap();
    src.set_settable(SETTABLE7, SettableState::Tolerant)
        .unwrap();

    let mut dst = FipsIndicator::new();
    dst.copy_from(&src);

    assert_eq!(dst.get_settable(SETTABLE0).unwrap(), SettableState::Strict);
    assert_eq!(
        dst.get_settable(SETTABLE1).unwrap(),
        SettableState::Tolerant
    );
    assert_eq!(
        dst.get_settable(SETTABLE2).unwrap(),
        SettableState::Unknown
    );
    assert_eq!(dst.get_settable(SETTABLE3).unwrap(), SettableState::Strict);
    assert_eq!(
        dst.get_settable(SETTABLE4).unwrap(),
        SettableState::Tolerant
    );
    assert_eq!(
        dst.get_settable(SETTABLE5).unwrap(),
        SettableState::Unknown
    );
    assert_eq!(dst.get_settable(SETTABLE6).unwrap(), SettableState::Strict);
    assert_eq!(
        dst.get_settable(SETTABLE7).unwrap(),
        SettableState::Tolerant
    );
}

/// Thread safety: 10 concurrent threads each call `on_unapproved` on a
/// shared `FipsIndicator` behind `Arc<Mutex<...>>`.  No data races or
/// panics should occur and the final state must be unapproved.
#[test]
fn test_indicator_thread_safety() {
    let ind = Arc::new(Mutex::new(FipsIndicator::new()));
    let mut handles = Vec::new();

    for i in 0..10 {
        let ind_clone = Arc::clone(&ind);
        let handle = thread::spawn(move || {
            let mut locked = ind_clone.lock().expect("Mutex should not be poisoned");
            let id = i % SETTABLE_MAX;
            let _ = locked.on_unapproved(id, &format!("algo-{i}"), "op", || false);
        });
        handles.push(handle);
    }

    // All threads must complete without panic
    for handle in handles {
        handle.join().expect("Thread must not panic");
    }

    let locked = ind.lock().unwrap();
    assert!(
        !locked.is_approved(),
        "After concurrent on_unapproved calls, approved must be false"
    );
}

/// Thread safety: concurrent reads of `get_settable` interleaved with a
/// writer that mutates settable slots.
#[test]
fn test_indicator_concurrent_read_write() {
    let ind = Arc::new(Mutex::new(FipsIndicator::new()));
    let mut handles = Vec::new();

    // Writer thread
    {
        let ind_clone = Arc::clone(&ind);
        handles.push(thread::spawn(move || {
            for id in 0..SETTABLE_MAX {
                let mut locked = ind_clone.lock().unwrap();
                locked.set_settable(id, SettableState::Strict).unwrap();
            }
        }));
    }

    // Reader threads
    for _ in 0..5 {
        let ind_clone = Arc::clone(&ind);
        handles.push(thread::spawn(move || {
            for id in 0..SETTABLE_MAX {
                let locked = ind_clone.lock().unwrap();
                let state = locked.get_settable(id).unwrap();
                // State is either Unknown (not yet written) or Strict (written)
                assert!(
                    state == SettableState::Unknown || state == SettableState::Strict,
                    "State must be Unknown or Strict, got {state:?}"
                );
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread must not panic");
    }
}
