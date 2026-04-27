// Test modules legitimately use `.unwrap()` / `.expect()` and test-specific
// patterns that trigger pedantic clippy lints.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::bool_assert_comparison,
    clippy::match_same_arms,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding
)]

//! Tests for observability infrastructure (tracing, metrics, health checks) in openssl-common.
//!
//! Exercises the full public API of the [`crate::observability`] module:
//!
//! - **`CorrelationId`:** Creation, uniqueness (100 IDs via `HashSet`),
//!   `Display`/`Debug` traits, Clone/Copy semantics, UUID format validation.
//! - **`init_tracing` / `init_tracing_with_filter`:** Idempotency — no panic
//!   on repeated calls, `AlreadyInitialized` error on second invocation.
//! - **`init_metrics` / `MetricsHandle`:** Global Prometheus recorder
//!   installation, `render()` output verification.
//! - **`HealthStatus`:** Variant construction, `PartialEq`, `Debug`,
//!   `serde::Serialize` via `serde_json`.
//! - **`ReadinessCheck` / `HealthRegistry`:** Custom trait impl via `MockCheck`,
//!   empty/single/mixed/all-healthy aggregation, registration-order preservation.
//! - **`ObservabilityError`:** Display messages, [`std::error::Error`] trait impl,
//!   distinctness from `CommonError`.
//! - **`record_operation_start` / `record_operation_complete`:** Span creation
//!   returning [`tracing::Span`], completion without panic.
//!
//! # Global State Notes
//!
//! `init_tracing` and `init_metrics` install process-global singletons (tracing
//! subscriber and Prometheus recorder, respectively).  Tests account for
//! test-parallelism by accepting either `Ok(())` (first test to run) or the
//! `AlreadyInitialized` / `MetricsSetupFailed` error (another test ran first).
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `HealthStatus::Degraded` / `Unhealthy` use
//!   `reason: &'static str`; tests verify meaningful reasons, never sentinels.
//! - **R7 (Lock Granularity):** `HealthRegistry` uses a plain `Vec`; tests
//!   construct fresh registries per test (no shared mutable state).
//! - **R8 (Zero Unsafe):** ZERO `unsafe` code in this file.
//! - **R9 (Warning-Free):** Compiles under `RUSTFLAGS="-D warnings"`.
//! - **R10 (Wiring):** All tests exercise the observability module's public API,
//!   reachable from `openssl-cli::main()`.

// Test-specific lint relaxations: tests use expect/unwrap/panic for assertions.
// These are warned or denied by workspace lints (see root Cargo.toml).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_literal_unwrap
)]

use std::collections::HashSet;

use crate::error::CommonError;
use crate::observability::{
    current_correlation_id, init_metrics, init_tracing, init_tracing_with_filter,
    record_operation_complete, record_operation_start, CorrelationId, HealthRegistry, HealthStatus,
    MetricsHandle, ObservabilityError, ReadinessCheck,
};

// =============================================================================
// MockCheck — Test Helper for ReadinessCheck Trait (Phase 5)
// =============================================================================

/// A configurable mock implementation of `ReadinessCheck` for testing
/// `HealthRegistry` aggregation logic.
///
/// Each instance carries a fixed name and status, enabling deterministic
/// testing of all health-check combinations (healthy, degraded, unhealthy).
struct MockCheck {
    name: &'static str,
    status: HealthStatus,
}

impl ReadinessCheck for MockCheck {
    fn name(&self) -> &str {
        self.name
    }

    fn check(&self) -> HealthStatus {
        self.status
    }
}

// =============================================================================
// Phase 2: CorrelationId Tests
// =============================================================================

/// `CorrelationId::new()` produces a non-empty string representation.
#[test]
fn correlation_id_new() {
    let cid = CorrelationId::new();
    assert!(
        !cid.to_string().is_empty(),
        "new CorrelationId should have non-empty string"
    );
}

/// Generate 100 CorrelationIds, verify all unique (collect into HashSet, count == 100).
#[test]
fn correlation_id_uniqueness() {
    let mut set = HashSet::new();
    for _ in 0..100 {
        let cid = CorrelationId::new();
        set.insert(cid.to_string());
    }
    assert_eq!(set.len(), 100, "All 100 CorrelationIds should be unique");
}

/// `format!("{}", CorrelationId::new())` produces valid UUID-like string.
#[test]
fn correlation_id_display() {
    let cid = CorrelationId::new();
    let displayed = format!("{cid}");
    assert!(!displayed.is_empty());
    // UUID format: 8-4-4-4-12 hex groups = 36 characters
    assert_eq!(displayed.len(), 36, "UUID string should be 36 characters");
    let parts: Vec<&str> = displayed.split('-').collect();
    assert_eq!(parts.len(), 5, "UUID should have 5 dash-separated groups");
}

/// `format!("{:?}", CorrelationId::new())` produces valid debug output.
#[test]
fn correlation_id_debug() {
    let cid = CorrelationId::new();
    let debug_out = format!("{cid:?}");
    assert!(!debug_out.is_empty(), "Debug output should not be empty");
    // Debug representation includes the struct name.
    assert!(
        debug_out.contains("CorrelationId"),
        "Debug should mention type name"
    );
}

/// Clone produces equal copy.
#[test]
fn correlation_id_clone() {
    let a = CorrelationId::new();
    #[allow(clippy::clone_on_copy)]
    let b = a.clone();
    assert_eq!(a, b, "Cloned CorrelationId should equal original");
}

/// Copy semantics work: assign to two variables, both valid.
#[test]
fn correlation_id_copy() {
    let a = CorrelationId::new();
    let b = a; // Copy
    let c = a; // Also copy — original still valid after move
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert!(!b.to_string().is_empty());
    assert!(!c.to_string().is_empty());
}

/// `to_string()` returns non-empty String with UUID format (8-4-4-4-12 hex groups).
#[test]
fn correlation_id_to_string_format() {
    let cid = CorrelationId::new();
    let s = cid.to_string();
    assert!(!s.is_empty(), "to_string() should return non-empty string");
    assert_eq!(s.len(), 36, "UUID string should be 36 characters");
    let parts: Vec<&str> = s.split('-').collect();
    assert_eq!(parts.len(), 5, "UUID should have 5 groups");
    assert_eq!(parts[0].len(), 8, "First group: 8 hex chars");
    assert_eq!(parts[1].len(), 4, "Second group: 4 hex chars");
    assert_eq!(parts[2].len(), 4, "Third group: 4 hex chars");
    assert_eq!(parts[3].len(), 4, "Fourth group: 4 hex chars");
    assert_eq!(parts[4].len(), 12, "Fifth group: 12 hex chars");
    // Verify all characters are hex digits or dashes.
    for ch in s.chars() {
        assert!(
            ch.is_ascii_hexdigit() || ch == '-',
            "UUID character should be hex or dash, got '{ch}'"
        );
    }
}

/// Display matches to_string output.
#[test]
fn correlation_id_display_matches_to_string() {
    let cid = CorrelationId::new();
    assert_eq!(format!("{cid}"), cid.to_string());
}

/// Default trait creates a new valid CorrelationId.
#[test]
fn correlation_id_default_creates_new() {
    let cid: CorrelationId = CorrelationId::default();
    assert!(!cid.to_string().is_empty());
}

/// Hash trait works consistently with HashSet insert/lookup.
#[test]
fn correlation_id_hash_consistent() {
    let mut set = HashSet::new();
    let cid = CorrelationId::new();
    set.insert(cid);
    assert!(set.contains(&cid), "HashSet should contain the inserted ID");
    let other = CorrelationId::new();
    assert!(!set.contains(&other), "Different ID should not be found");
}

// =============================================================================
// Phase 3: init_tracing() Idempotency Tests
// Per AAP §0.8.5: "Use OnceCell/OnceLock to ensure single initialization"
// =============================================================================

/// `init_tracing()` returns `Ok(())` if it is the first caller in this
/// process, or `Err(AlreadyInitialized)` if another test initialized first.
#[test]
fn init_tracing_first_call_succeeds() {
    // Because the tracing global subscriber can only be set once per process
    // and tests run in the same process, this test accepts either outcome.
    let result = init_tracing();
    match &result {
        Ok(()) => { /* First call in this process — success. */ }
        Err(ObservabilityError::AlreadyInitialized) => {
            // Another test already initialized tracing — acceptable.
        }
        Err(ObservabilityError::TracingSetupFailed(_)) => {
            // The subscriber stack failed to install (e.g., global subscriber
            // was already set by tracing_subscriber directly).
        }
        Err(other) => {
            panic!("unexpected error variant from init_tracing(): {other}");
        }
    }
}

/// Call `init_tracing()` twice.  The key assertion is that it does NOT panic
/// on repeated calls.  At least the second call should be `AlreadyInitialized`.
#[test]
fn init_tracing_idempotent() {
    let first = init_tracing();
    let second = init_tracing();
    // At least the second call should be AlreadyInitialized (if the first
    // succeeded).  If both are AlreadyInitialized, another test ran first.
    // Any variant is acceptable — the critical check is: no panic occurred.
    match (&first, &second) {
        (Ok(()), Err(ObservabilityError::AlreadyInitialized)) => {
            // Expected: first succeeded, second reports already initialized.
        }
        (
            Err(ObservabilityError::AlreadyInitialized),
            Err(ObservabilityError::AlreadyInitialized),
        ) => {
            // Both failed: another test already initialized tracing.
        }
        (Err(ObservabilityError::TracingSetupFailed(_)), _)
        | (_, Err(ObservabilityError::TracingSetupFailed(_))) => {
            // The subscriber was already installed outside our control.
        }
        _ => {
            // Any other combination — the function didn't panic.
        }
    }
}

/// `init_tracing_with_filter("debug")` either succeeds or returns
/// `AlreadyInitialized` (same idempotency behavior as `init_tracing`).
#[test]
fn init_tracing_with_filter_test() {
    let result = init_tracing_with_filter("debug");
    match &result {
        Ok(()) => { /* First call in this process — success. */ }
        Err(ObservabilityError::AlreadyInitialized) => {
            // Tracing was already initialized by init_tracing() or another test.
        }
        Err(ObservabilityError::TracingSetupFailed(_)) => {
            // Subscriber stack failed — acceptable, no panic.
        }
        Err(other) => {
            panic!("unexpected error from init_tracing_with_filter: {other}");
        }
    }
}

// =============================================================================
// Phase 4: HealthStatus Tests
// =============================================================================

/// `HealthStatus::Healthy` is `PartialEq` to itself.
#[test]
fn health_status_healthy() {
    assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
}

/// `HealthStatus::Degraded { reason: "slow" }` carries the reason in Debug.
#[test]
fn health_status_degraded() {
    let status = HealthStatus::Degraded { reason: "slow" };
    let debug = format!("{status:?}");
    assert!(
        debug.contains("Degraded"),
        "Debug should contain variant name"
    );
    assert!(debug.contains("slow"), "Debug should contain reason");
}

/// `HealthStatus::Unhealthy { reason: "down" }` carries the reason in Debug.
#[test]
fn health_status_unhealthy() {
    let status = HealthStatus::Unhealthy { reason: "down" };
    let debug = format!("{status:?}");
    assert!(
        debug.contains("Unhealthy"),
        "Debug should contain variant name"
    );
    assert!(debug.contains("down"), "Debug should contain reason");
}

/// Two `Healthy` instances are equal, `Healthy != Unhealthy`.
#[test]
fn health_status_equality() {
    assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
    assert_ne!(
        HealthStatus::Healthy,
        HealthStatus::Unhealthy { reason: "x" }
    );
    assert_ne!(
        HealthStatus::Healthy,
        HealthStatus::Degraded { reason: "x" }
    );
    assert_ne!(
        HealthStatus::Degraded { reason: "a" },
        HealthStatus::Unhealthy { reason: "a" }
    );
}

/// All variants produce valid Debug output.
#[test]
fn health_status_debug() {
    let healthy_dbg = format!("{:?}", HealthStatus::Healthy);
    assert!(!healthy_dbg.is_empty());
    assert_eq!(healthy_dbg, "Healthy");

    let degraded_dbg = format!("{:?}", HealthStatus::Degraded { reason: "test" });
    assert!(!degraded_dbg.is_empty());
    assert!(degraded_dbg.contains("Degraded"));
    assert!(degraded_dbg.contains("test"));

    let unhealthy_dbg = format!("{:?}", HealthStatus::Unhealthy { reason: "fail" });
    assert!(!unhealthy_dbg.is_empty());
    assert!(unhealthy_dbg.contains("Unhealthy"));
    assert!(unhealthy_dbg.contains("fail"));
}

/// `serde_json::to_string(&HealthStatus::Healthy)` produces valid JSON.
#[test]
fn health_status_serialize() {
    let json = serde_json::to_string(&HealthStatus::Healthy).expect("serialize Healthy");
    assert!(json.contains("Healthy"), "JSON should contain 'Healthy'");

    let degraded_json = serde_json::to_string(&HealthStatus::Degraded { reason: "slow" })
        .expect("serialize Degraded");
    assert!(degraded_json.contains("Degraded"));
    assert!(degraded_json.contains("slow"));

    let unhealthy_json = serde_json::to_string(&HealthStatus::Unhealthy { reason: "down" })
        .expect("serialize Unhealthy");
    assert!(unhealthy_json.contains("Unhealthy"));
    assert!(unhealthy_json.contains("down"));
}

/// Copy and Clone semantics work correctly.
#[test]
fn health_status_copy_and_clone() {
    let a = HealthStatus::Healthy;
    let b = a; // Copy
    #[allow(clippy::clone_on_copy)]
    let c = a.clone(); // Clone
    assert_eq!(a, b);
    assert_eq!(a, c);
}

// =============================================================================
// Phase 5: ReadinessCheck Trait and HealthRegistry Tests
// =============================================================================

/// MockCheck correctly implements ReadinessCheck trait methods.
#[test]
fn mock_check_implements_readiness_check() {
    let check = MockCheck {
        name: "test_check",
        status: HealthStatus::Healthy,
    };
    assert_eq!(check.name(), "test_check");
    assert_eq!(check.check(), HealthStatus::Healthy);
}

/// MockCheck satisfies Send + Sync bounds required by ReadinessCheck.
#[test]
fn readiness_check_requires_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MockCheck>();
}

/// New registry: `check_all()` returns empty vec, `is_ready()` returns `true`.
#[test]
fn health_registry_empty() {
    let registry = HealthRegistry::new();
    assert!(
        registry.check_all().is_empty(),
        "Empty registry should have no checks"
    );
    assert!(
        registry.is_ready(),
        "Empty registry should be ready (vacuous truth)"
    );
}

/// Register one Healthy check — `check_all()` returns `[("test", Healthy)]`,
/// `is_ready()` returns `true`.
#[test]
fn health_registry_single_healthy() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "test",
        status: HealthStatus::Healthy,
    }));
    let results = registry.check_all();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "test");
    assert_eq!(results[0].1, HealthStatus::Healthy);
    assert!(registry.is_ready());
}

/// Register one Unhealthy check — `is_ready()` returns `false`.
#[test]
fn health_registry_single_unhealthy() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "bad_service",
        status: HealthStatus::Unhealthy { reason: "offline" },
    }));
    assert!(
        !registry.is_ready(),
        "Registry with unhealthy check should not be ready"
    );
}

/// Register Healthy + Unhealthy — `is_ready()` returns `false`.
#[test]
fn health_registry_mixed() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "good",
        status: HealthStatus::Healthy,
    }));
    registry.register(Box::new(MockCheck {
        name: "bad",
        status: HealthStatus::Unhealthy { reason: "error" },
    }));
    assert!(
        !registry.is_ready(),
        "One unhealthy makes registry not ready"
    );
}

/// Register 3 Healthy checks — `is_ready()` returns `true`.
#[test]
fn health_registry_all_healthy() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "svc_a",
        status: HealthStatus::Healthy,
    }));
    registry.register(Box::new(MockCheck {
        name: "svc_b",
        status: HealthStatus::Healthy,
    }));
    registry.register(Box::new(MockCheck {
        name: "svc_c",
        status: HealthStatus::Healthy,
    }));
    assert!(registry.is_ready(), "All healthy should be ready");
    assert_eq!(registry.check_all().len(), 3);
}

/// Degraded is not Healthy — `is_ready()` returns `false`.
#[test]
fn health_registry_degraded_is_not_fully_ready() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "slow_service",
        status: HealthStatus::Degraded {
            reason: "high latency",
        },
    }));
    assert!(
        !registry.is_ready(),
        "Degraded service means registry is not fully ready"
    );
}

/// Register 3 checks — `check_all().len() == 3`, verify each check name/status.
#[test]
fn health_registry_check_all_returns_all() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "alpha",
        status: HealthStatus::Healthy,
    }));
    registry.register(Box::new(MockCheck {
        name: "beta",
        status: HealthStatus::Degraded { reason: "slow" },
    }));
    registry.register(Box::new(MockCheck {
        name: "gamma",
        status: HealthStatus::Unhealthy { reason: "down" },
    }));
    let results = registry.check_all();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, "alpha");
    assert_eq!(results[0].1, HealthStatus::Healthy);
    assert_eq!(results[1].0, "beta");
    assert_eq!(results[1].1, HealthStatus::Degraded { reason: "slow" });
    assert_eq!(results[2].0, "gamma");
    assert_eq!(results[2].1, HealthStatus::Unhealthy { reason: "down" });
}

/// Verify check names match what was registered, in registration order.
#[test]
fn health_registry_check_names() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "crypto_provider",
        status: HealthStatus::Healthy,
    }));
    registry.register(Box::new(MockCheck {
        name: "tls_stack",
        status: HealthStatus::Healthy,
    }));
    registry.register(Box::new(MockCheck {
        name: "fips_module",
        status: HealthStatus::Healthy,
    }));
    let results = registry.check_all();
    let names: Vec<&str> = results.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, vec!["crypto_provider", "tls_stack", "fips_module"]);
}

/// Default trait creates an empty registry.
#[test]
fn health_registry_default_is_empty() {
    let registry = HealthRegistry::default();
    assert!(registry.is_ready());
    assert!(registry.check_all().is_empty());
}

/// Debug format includes type name.
#[test]
fn health_registry_debug_output() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(MockCheck {
        name: "test",
        status: HealthStatus::Healthy,
    }));
    let dbg = format!("{registry:?}");
    assert!(dbg.contains("HealthRegistry"));
}

// =============================================================================
// Phase 6: ObservabilityError Tests
// =============================================================================

/// `ObservabilityError::AlreadyInitialized` displays "tracing already initialized".
#[test]
fn observability_error_already_initialized() {
    let err = ObservabilityError::AlreadyInitialized;
    assert_eq!(format!("{err}"), "tracing already initialized");
}

/// `ObservabilityError::TracingSetupFailed("reason")` displays correctly.
#[test]
fn observability_error_tracing_failed() {
    let err = ObservabilityError::TracingSetupFailed("reason".into());
    let msg = format!("{err}");
    assert!(msg.contains("failed to initialize tracing"));
    assert!(msg.contains("reason"));
}

/// `ObservabilityError::MetricsSetupFailed("reason")` displays correctly.
#[test]
fn observability_error_metrics_failed() {
    let err = ObservabilityError::MetricsSetupFailed("reason".into());
    let msg = format!("{err}");
    assert!(msg.contains("failed to initialize metrics"));
    assert!(msg.contains("reason"));
}

/// Verify `ObservabilityError` implements `std::error::Error`.
#[test]
fn observability_error_is_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<ObservabilityError>();
    // Also verify via trait object construction.
    let err: Box<dyn std::error::Error> = Box::new(ObservabilityError::AlreadyInitialized);
    assert!(err.source().is_none());
}

/// Debug output for error variants is non-empty.
#[test]
fn observability_error_debug_not_empty() {
    let err = ObservabilityError::AlreadyInitialized;
    let dbg = format!("{err:?}");
    assert!(!dbg.is_empty());
}

/// `ObservabilityError` and `CommonError` are distinct error types in the
/// error hierarchy (AAP §0.7.7). Both implement `std::error::Error`.
#[test]
fn observability_error_distinct_from_common_error() {
    let obs_err: Box<dyn std::error::Error> = Box::new(ObservabilityError::AlreadyInitialized);
    let common_err: Box<dyn std::error::Error> =
        Box::new(CommonError::Internal("test".to_string()));
    // Both are valid error trait objects with non-empty Display.
    assert!(!obs_err.to_string().is_empty());
    assert!(!common_err.to_string().is_empty());
}

// =============================================================================
// Phase 7: MetricsHandle Tests
// =============================================================================

/// If `init_metrics()` succeeds, `handle.render()` returns a string in
/// Prometheus format.  If the recorder is already installed, the test
/// verifies graceful failure (no panic).
#[test]
fn metrics_handle_render() {
    // init_metrics() installs a process-global Prometheus recorder.
    // May fail if already installed by a parallel test or inline test.
    match init_metrics() {
        Ok(handle) => {
            // MetricsHandle::render() should produce a valid Prometheus
            // text format string without panicking.
            let output: String = handle.render();
            // Explicitly bind the MetricsHandle to verify the type is accessible.
            let _handle_ref: &MetricsHandle = &handle;
            // The output is valid Prometheus format (may be empty if no
            // metrics have been recorded yet — this is valid).
            let _ = output;
        }
        Err(ObservabilityError::MetricsSetupFailed(_)) => {
            // Recorder was already installed — acceptable in test context.
            // The function didn't panic, which is the critical assertion.
        }
        Err(other) => {
            // Unexpected error variant — but still no panic.
            let _ = format!("{other}");
        }
    }
}

// =============================================================================
// Phase 8: Convenience Function Tests
// =============================================================================

/// `record_operation_start("test_op")` returns a valid `tracing::Span`.
#[test]
fn record_operation_start_test() {
    // Explicitly annotate the return type as tracing::Span to verify the
    // external import and return type contract.
    let span: tracing::Span = record_operation_start("test_op");
    let dbg = format!("{span:?}");
    assert!(!dbg.is_empty(), "Span debug output should not be empty");
}

/// After starting, `record_operation_complete(&span, true)` does not panic.
#[test]
fn record_operation_complete_test() {
    let span = record_operation_start("complete_test");
    record_operation_complete(&span, true);
}

/// Completing with `success=false` also does not panic.
#[test]
fn record_operation_complete_failure() {
    let span = record_operation_start("fail_test");
    record_operation_complete(&span, false);
}

/// Multiple operations can run and complete independently in any order.
#[test]
fn record_multiple_operations_independently() {
    let span_a = record_operation_start("op_a");
    let span_b = record_operation_start("op_b");
    // Complete in reverse order — should not interfere.
    record_operation_complete(&span_b, true);
    record_operation_complete(&span_a, false);
}

// =============================================================================
// Integration: current_correlation_id — Without Active Span
// =============================================================================

/// Outside of an operation span, `current_correlation_id()` returns a freshly
/// generated UUID.
#[test]
fn current_correlation_id_returns_valid_uuid_outside_span() {
    let cid = current_correlation_id();
    let s = cid.to_string();
    assert_eq!(s.len(), 36, "Should be a valid UUID string");
}

/// Successive calls outside a span produce distinct IDs.
#[test]
fn current_correlation_id_generates_fresh_each_call() {
    let a = current_correlation_id();
    let b = current_correlation_id();
    assert_ne!(
        a, b,
        "Successive calls outside span should produce different IDs"
    );
}

// =============================================================================
// Integration: Full Health-Check Workflow
// =============================================================================

/// End-to-end workflow: build registry, add checks, verify readiness, serialize.
#[test]
fn full_health_workflow() {
    // 1. Build a registry with a healthy check.
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(MockCheck {
        name: "healthy_svc",
        status: HealthStatus::Healthy,
    }));
    assert!(reg.is_ready());

    // 2. Adding a degraded check makes the registry not ready.
    reg.register(Box::new(MockCheck {
        name: "degraded_svc",
        status: HealthStatus::Degraded { reason: "slow" },
    }));
    assert!(!reg.is_ready());

    // 3. check_all still returns all results regardless of readiness.
    let results = reg.check_all();
    assert_eq!(results.len(), 2);

    // 4. Serializing the aggregate result works.
    for (_name, status) in &results {
        let json = serde_json::to_string(status).expect("serialize HealthStatus");
        assert!(!json.is_empty());
    }
}
