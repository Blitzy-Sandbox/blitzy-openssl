//! Tests for the `openssl_common::observability` module.
//!
//! Exercises correlation IDs, health checks, readiness registry, operation
//! recording, and error types through the crate's public API.
//!
//! **Note on global state:** [`init_tracing`] and [`init_metrics`] install
//! process-global subscribers/recorders that can only be set once.  Testing
//! them directly would interfere with other test binaries sharing the
//! process.  These tests therefore focus on the *types* and *logic* that do
//! not require global initialization.
#![allow(clippy::expect_used, clippy::panic)]

use crate::observability::{
    current_correlation_id, record_operation_complete, record_operation_start, HealthRegistry,
    HealthStatus, ObservabilityError, ReadinessCheck,
};
use crate::observability::CorrelationId;

// =============================================================================
// ObservabilityError — Display and Debug
// =============================================================================

#[test]
fn error_already_initialized_display() {
    let err = ObservabilityError::AlreadyInitialized;
    assert_eq!(format!("{err}"), "tracing already initialized");
}

#[test]
fn error_tracing_setup_failed_display() {
    let err = ObservabilityError::TracingSetupFailed("bad filter".into());
    let msg = format!("{err}");
    assert!(msg.contains("failed to initialize tracing"));
    assert!(msg.contains("bad filter"));
}

#[test]
fn error_metrics_setup_failed_display() {
    let err = ObservabilityError::MetricsSetupFailed("port in use".into());
    let msg = format!("{err}");
    assert!(msg.contains("failed to initialize metrics"));
    assert!(msg.contains("port in use"));
}

#[test]
fn error_debug_not_empty() {
    let err = ObservabilityError::AlreadyInitialized;
    let dbg = format!("{err:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn error_is_std_error() {
    fn assert_std_error<T: std::error::Error>() {}
    assert_std_error::<ObservabilityError>();
}

// =============================================================================
// CorrelationId — Creation, Display, Traits
// =============================================================================

#[test]
fn correlation_id_unique() {
    let a = CorrelationId::new();
    let b = CorrelationId::new();
    assert_ne!(a, b);
}

#[test]
fn correlation_id_as_str_uuid_format() {
    let cid = CorrelationId::new();
    let s = cid.as_str();
    // v4 UUID: 8-4-4-4-12 = 36 chars
    assert_eq!(s.len(), 36, "UUID should be 36 characters");
    let parts: Vec<&str> = s.split('-').collect();
    assert_eq!(parts.len(), 5, "UUID should have 5 dash-separated groups");
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
}

#[test]
fn correlation_id_display_matches_as_str() {
    let cid = CorrelationId::new();
    assert_eq!(format!("{cid}"), cid.as_str());
}

#[test]
fn correlation_id_default_trait() {
    let cid: CorrelationId = CorrelationId::default();
    assert!(!cid.as_str().is_empty());
}

#[test]
fn correlation_id_copy_and_clone() {
    let a = CorrelationId::new();
    let b = a; // Copy
    let c = a; // Also Copy (Clone delegates to Copy for this type)
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn correlation_id_debug_not_empty() {
    let cid = CorrelationId::new();
    let dbg = format!("{cid:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn correlation_id_hash_consistent() {
    use std::collections::HashSet;
    let cid = CorrelationId::new();
    let mut set = HashSet::new();
    set.insert(cid);
    assert!(set.contains(&cid));
    // A different ID should not collide
    let other = CorrelationId::new();
    assert!(!set.contains(&other));
}

// =============================================================================
// current_correlation_id — Without Active Span
// =============================================================================

#[test]
fn current_correlation_id_returns_valid_uuid_outside_span() {
    // When no operation span is active, current_correlation_id returns
    // a freshly generated CorrelationId (via Default).
    let cid = current_correlation_id();
    let s = cid.as_str();
    assert_eq!(s.len(), 36, "Should be a valid UUID string");
}

#[test]
fn current_correlation_id_generates_fresh_each_call() {
    let a = current_correlation_id();
    let b = current_correlation_id();
    // Outside of a span, each call produces a new default CorrelationId
    assert_ne!(a, b, "Successive calls outside span should produce different IDs");
}

// =============================================================================
// HealthStatus — Variants and Serialization
// =============================================================================

#[test]
fn health_status_healthy() {
    let s = HealthStatus::Healthy;
    assert_eq!(s, HealthStatus::Healthy);
}

#[test]
fn health_status_degraded_carries_reason() {
    let s = HealthStatus::Degraded {
        reason: "high latency",
    };
    match s {
        HealthStatus::Degraded { reason } => assert_eq!(reason, "high latency"),
        _ => panic!("expected Degraded"),
    }
}

#[test]
fn health_status_unhealthy_carries_reason() {
    let s = HealthStatus::Unhealthy {
        reason: "connection refused",
    };
    match s {
        HealthStatus::Unhealthy { reason } => assert_eq!(reason, "connection refused"),
        _ => panic!("expected Unhealthy"),
    }
}

#[test]
fn health_status_copy_and_clone() {
    let a = HealthStatus::Healthy;
    let b = a; // Copy
    let c = a; // Also Copy (Clone delegates to Copy for this type)
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn health_status_debug() {
    assert_eq!(format!("{:?}", HealthStatus::Healthy), "Healthy");
    let degraded = HealthStatus::Degraded { reason: "slow" };
    let dbg = format!("{degraded:?}");
    assert!(dbg.contains("Degraded"));
    assert!(dbg.contains("slow"));
}

#[test]
fn health_status_serialize_healthy() {
    let json = serde_json::to_string(&HealthStatus::Healthy).expect("serialize");
    assert!(json.contains("Healthy"));
}

#[test]
fn health_status_serialize_degraded() {
    let s = HealthStatus::Degraded {
        reason: "high latency",
    };
    let json = serde_json::to_string(&s).expect("serialize");
    assert!(json.contains("Degraded"));
    assert!(json.contains("high latency"));
}

#[test]
fn health_status_serialize_unhealthy() {
    let s = HealthStatus::Unhealthy {
        reason: "out of memory",
    };
    let json = serde_json::to_string(&s).expect("serialize");
    assert!(json.contains("Unhealthy"));
    assert!(json.contains("out of memory"));
}

#[test]
fn health_status_variants_not_equal() {
    assert_ne!(HealthStatus::Healthy, HealthStatus::Degraded { reason: "x" });
    assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy { reason: "x" });
    assert_ne!(
        HealthStatus::Degraded { reason: "a" },
        HealthStatus::Unhealthy { reason: "a" }
    );
}

// =============================================================================
// ReadinessCheck — Custom Implementations
// =============================================================================

struct AlwaysHealthy;
impl ReadinessCheck for AlwaysHealthy {
    fn name(&self) -> &str {
        "always_healthy"
    }
    fn check(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

struct AlwaysDegraded;
impl ReadinessCheck for AlwaysDegraded {
    fn name(&self) -> &str {
        "degraded_check"
    }
    fn check(&self) -> HealthStatus {
        HealthStatus::Degraded {
            reason: "test degraded",
        }
    }
}

struct AlwaysUnhealthy;
impl ReadinessCheck for AlwaysUnhealthy {
    fn name(&self) -> &str {
        "unhealthy_check"
    }
    fn check(&self) -> HealthStatus {
        HealthStatus::Unhealthy {
            reason: "test unhealthy",
        }
    }
}

#[test]
fn readiness_check_custom_impl_healthy() {
    let c = AlwaysHealthy;
    assert_eq!(c.name(), "always_healthy");
    assert_eq!(c.check(), HealthStatus::Healthy);
}

#[test]
fn readiness_check_custom_impl_degraded() {
    let c = AlwaysDegraded;
    assert_eq!(c.name(), "degraded_check");
    assert_eq!(
        c.check(),
        HealthStatus::Degraded {
            reason: "test degraded"
        }
    );
}

#[test]
fn readiness_check_requires_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AlwaysHealthy>();
    assert_send_sync::<AlwaysDegraded>();
    assert_send_sync::<AlwaysUnhealthy>();
}

// =============================================================================
// HealthRegistry — Creation, Registration, Checking
// =============================================================================

#[test]
fn registry_new_is_empty() {
    let reg = HealthRegistry::new();
    assert_eq!(reg.check_all().len(), 0);
    assert!(reg.is_ready(), "empty registry → vacuously ready");
}

#[test]
fn registry_default_matches_new() {
    let a = HealthRegistry::new();
    let b: HealthRegistry = HealthRegistry::default();
    assert_eq!(a.check_all().len(), b.check_all().len());
    assert_eq!(a.is_ready(), b.is_ready());
}

#[test]
fn registry_register_single_healthy() {
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    assert!(reg.is_ready());
    let results = reg.check_all();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "always_healthy");
    assert_eq!(results[0].1, HealthStatus::Healthy);
}

#[test]
fn registry_register_multiple_all_healthy() {
    // Second healthy check with a different name
    struct AnotherHealthy;
    impl ReadinessCheck for AnotherHealthy {
        fn name(&self) -> &str {
            "another_healthy"
        }
        fn check(&self) -> HealthStatus {
            HealthStatus::Healthy
        }
    }

    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    reg.register(Box::new(AnotherHealthy));
    assert!(reg.is_ready());
    assert_eq!(reg.check_all().len(), 2);
}

#[test]
fn registry_unhealthy_check_makes_not_ready() {
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    reg.register(Box::new(AlwaysUnhealthy));
    assert!(!reg.is_ready(), "one unhealthy → not ready");
}

#[test]
fn registry_degraded_check_makes_not_ready() {
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    reg.register(Box::new(AlwaysDegraded));
    assert!(!reg.is_ready(), "degraded ≠ healthy → not ready");
}

#[test]
fn registry_check_all_preserves_registration_order() {
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    reg.register(Box::new(AlwaysDegraded));
    reg.register(Box::new(AlwaysUnhealthy));
    let results = reg.check_all();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, "always_healthy");
    assert_eq!(results[1].0, "degraded_check");
    assert_eq!(results[2].0, "unhealthy_check");
}

#[test]
fn registry_check_all_returns_correct_statuses() {
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    reg.register(Box::new(AlwaysDegraded));
    reg.register(Box::new(AlwaysUnhealthy));
    let results = reg.check_all();
    assert_eq!(results[0].1, HealthStatus::Healthy);
    assert_eq!(
        results[1].1,
        HealthStatus::Degraded {
            reason: "test degraded"
        }
    );
    assert_eq!(
        results[2].1,
        HealthStatus::Unhealthy {
            reason: "test unhealthy"
        }
    );
}

#[test]
fn registry_debug_shows_check_count() {
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    reg.register(Box::new(AlwaysDegraded));
    let dbg = format!("{reg:?}");
    assert!(dbg.contains("HealthRegistry"));
    assert!(dbg.contains('2'), "should show check_count = 2");
}

// =============================================================================
// record_operation_start / record_operation_complete — Smoke Tests
// =============================================================================

#[test]
fn record_operation_start_returns_span() {
    let span = record_operation_start("test_op");
    // The span exists and has a name — we can at least verify it doesn't panic.
    let dbg = format!("{span:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn record_operation_complete_does_not_panic() {
    let span = record_operation_start("complete_test");
    // Completing the operation should not panic even without a global subscriber.
    record_operation_complete(&span, true);
}

#[test]
fn record_operation_complete_failure_does_not_panic() {
    let span = record_operation_start("fail_test");
    record_operation_complete(&span, false);
}

#[test]
fn record_multiple_operations_independently() {
    let span_a = record_operation_start("op_a");
    let span_b = record_operation_start("op_b");
    // Complete in reverse order — should not interfere
    record_operation_complete(&span_b, true);
    record_operation_complete(&span_a, false);
}

// =============================================================================
// Integration: Full Health-Check Workflow
// =============================================================================

#[test]
fn full_health_workflow() {
    // 1. Build a registry with multiple checks.
    let mut reg = HealthRegistry::new();
    reg.register(Box::new(AlwaysHealthy));
    assert!(reg.is_ready());

    // 2. Adding a degraded check makes the registry not ready.
    reg.register(Box::new(AlwaysDegraded));
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
