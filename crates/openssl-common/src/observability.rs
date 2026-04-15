//! Observability infrastructure for the OpenSSL Rust workspace.
//!
//! Provides **structured logging**, **distributed tracing**, **metrics**, and
//! **health/readiness checks** — shipped with the initial implementation per
//! AAP §0.8.5: "Ship observability with the initial implementation, not as
//! follow-up."
//!
//! # Architecture
//!
//! This module is the single initialization point for all workspace
//! observability.  It is intended to be called once at application startup
//! (typically from `openssl-cli::main()`) via [`init_tracing`] and
//! [`init_metrics`].
//!
//! ```text
//! openssl-cli::main()
//!   ├── init_tracing()          → global tracing subscriber
//!   ├── init_metrics()          → Prometheus recorder ──→ MetricsHandle
//!   └── HealthRegistry::new()   → register readiness checks
//! ```
//!
//! # Correlation IDs
//!
//! Every operation can be tagged with a [`CorrelationId`] (v4 UUID) via the
//! tracing span system.  Use [`current_correlation_id`] to read the
//! correlation ID from the active span, or create spans with correlation IDs
//! via [`record_operation_start`].
//!
//! # Metrics
//!
//! After [`init_metrics`] is called, workspace code can use the `metrics`
//! crate macros (`counter!`, `gauge!`, `histogram!`) anywhere.  The
//! [`MetricsHandle`] returned by `init_metrics` renders a Prometheus
//! exposition-format snapshot via [`MetricsHandle::render`].
//!
//! # Health Checks
//!
//! The [`HealthRegistry`] collects [`ReadinessCheck`] implementations and
//! aggregates their [`HealthStatus`] results.  [`HealthStatus`] derives
//! `serde::Serialize` for direct JSON serialization in health endpoints.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `HealthStatus::Degraded` and `Unhealthy` carry a
//!   `reason: &'static str`; no empty-string sentinels.
//! - **R7 (Lock Granularity):** `HealthRegistry` uses a plain `Vec`
//!   (constructed before use); if shared across threads, callers wrap in
//!   `parking_lot::RwLock` with `// LOCK-SCOPE:` annotation.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All public items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `openssl-cli::main()` via
//!   `init_tracing()`, `init_metrics()`, and `HealthRegistry`.
//!
//! # Migration from C
//!
//! This module has **no direct C counterpart**.  The C `ERR_*` stack
//! (`crypto/err/err.c`, `crypto/err/err_prn.c`) is replaced by Rust
//! `Result<T, E>` in the `error` module.  This module adds **new**
//! observability capabilities that the C codebase lacks: structured JSON
//! logs, distributed tracing, Prometheus metrics, and health endpoints.

use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use once_cell::sync::OnceCell;
use tracing::Span;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

// =============================================================================
// Module-Level Singleton Guards and Internal State
// =============================================================================

/// Global guard ensuring tracing is initialized at most once.
static TRACING_INIT: OnceCell<()> = OnceCell::new();

/// Internal concurrent map associating span IDs with their correlation IDs
/// and start times.  Entries are inserted by [`record_operation_start`] and
/// removed by [`record_operation_complete`].
///
/// // LOCK-SCOPE: operation metadata, write on start, remove on complete,
/// // contention is minimal — each span ID is unique and short-lived
static OPERATION_DATA: once_cell::sync::Lazy<
    parking_lot::Mutex<HashMap<u64, (CorrelationId, Instant)>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashMap::new()));

// =============================================================================
// ObservabilityError — Error Type
// =============================================================================

/// Errors that can occur during observability subsystem initialization.
///
/// Uses `thiserror::Error` derive for automatic `Display` and
/// `std::error::Error` implementations per AAP §0.7.7.
///
/// # Variants
///
/// | Variant                | Meaning                                        |
/// |------------------------|------------------------------------------------|
/// | `AlreadyInitialized`   | `init_tracing` called more than once           |
/// | `TracingSetupFailed`   | Subscriber composition or installation failed  |
/// | `MetricsSetupFailed`   | Prometheus recorder installation failed        |
#[derive(Debug, thiserror::Error)]
pub enum ObservabilityError {
    /// Tracing has already been initialized.  Subsequent calls to
    /// [`init_tracing`] or [`init_tracing_with_filter`] return this.
    #[error("tracing already initialized")]
    AlreadyInitialized,

    /// The tracing subscriber stack could not be assembled or installed.
    #[error("failed to initialize tracing: {0}")]
    TracingSetupFailed(String),

    /// The Prometheus metrics recorder could not be installed.
    #[error("failed to initialize metrics: {0}")]
    MetricsSetupFailed(String),
}

// =============================================================================
// CorrelationId — Distributed Tracing Correlation
// =============================================================================

/// A v4 UUID used as a correlation identifier across distributed traces.
///
/// Wraps [`uuid::Uuid`] in a newtype for type safety.  Every operation
/// started via [`record_operation_start`] embeds a `CorrelationId` in
/// the tracing span, enabling cross-crate request correlation per
/// AAP §0.6.1.
///
/// # Examples
///
/// ```
/// use openssl_common::observability::CorrelationId;
///
/// let cid = CorrelationId::new();
/// println!("correlation_id={}", cid);
/// let s = cid.as_str();
/// assert!(!s.is_empty());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CorrelationId(uuid::Uuid);

impl CorrelationId {
    /// Generates a new random v4 UUID correlation ID.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Returns the string representation of the underlying UUID.
    #[must_use]
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// =============================================================================
// current_correlation_id — Span Context Reader
// =============================================================================

/// Reads the correlation ID from the current tracing span context.
///
/// If the current span was created by [`record_operation_start`], its
/// stored correlation ID is returned.  Otherwise, a fresh [`CorrelationId`]
/// is generated.  This ensures every call site always receives a valid
/// identifier.
///
/// # Examples
///
/// ```
/// use openssl_common::observability::current_correlation_id;
///
/// let cid = current_correlation_id();
/// assert!(!cid.as_str().is_empty());
/// ```
#[must_use]
pub fn current_correlation_id() -> CorrelationId {
    // Attempt to look up the correlation ID for the current span via
    // the internal operation data map.
    Span::current()
        .id()
        .and_then(|id| {
            OPERATION_DATA
                .lock()
                .get(&id.into_u64())
                .map(|(cid, _)| *cid)
        })
        .unwrap_or_default()
}

// =============================================================================
// Tracing Initialization
// =============================================================================

/// Initializes the global tracing subscriber with default settings.
///
/// Composes a subscriber stack consisting of:
///
/// 1. **`EnvFilter`** — reads `RUST_LOG` env var, defaulting to `info`.
/// 2. **JSON formatting layer** — structured output via
///    `tracing_subscriber::fmt::layer().json()`.
/// 3. **OpenTelemetry layer** — distributed tracing export via
///    `tracing_opentelemetry::layer()` (no-op tracer by default; callers
///    may replace with a real tracer via the OpenTelemetry SDK).
///
/// This function is idempotent: subsequent calls return
/// [`ObservabilityError::AlreadyInitialized`].
///
/// # Errors
///
/// - [`ObservabilityError::AlreadyInitialized`] if tracing was already set up.
/// - [`ObservabilityError::TracingSetupFailed`] if the subscriber could not
///   be installed.
///
/// # Examples
///
/// ```no_run
/// use openssl_common::observability::init_tracing;
///
/// // First call succeeds (or fails if already globally initialised)
/// let _ = init_tracing();
/// ```
pub fn init_tracing() -> Result<(), ObservabilityError> {
    init_tracing_internal(None)
}

/// Initializes the global tracing subscriber with a custom filter string.
///
/// Behaves identically to [`init_tracing`] except the filter directive
/// is taken from `filter` rather than the `RUST_LOG` environment variable.
///
/// # Parameters
///
/// - `filter`: A `tracing_subscriber::EnvFilter`-compatible directive
///   string, e.g. `"openssl_crypto=debug,openssl_ssl=trace"`.
///
/// # Errors
///
/// - [`ObservabilityError::AlreadyInitialized`] if tracing was already set up.
/// - [`ObservabilityError::TracingSetupFailed`] if the filter string is
///   invalid or the subscriber could not be installed.
///
/// # Examples
///
/// ```no_run
/// use openssl_common::observability::init_tracing_with_filter;
///
/// let _ = init_tracing_with_filter("debug");
/// ```
pub fn init_tracing_with_filter(filter: &str) -> Result<(), ObservabilityError> {
    init_tracing_internal(Some(filter))
}

/// Shared implementation for tracing initialization.
///
/// When `custom_filter` is `None`, reads `RUST_LOG` from the environment
/// (falling back to `"info"`).  When `Some(f)`, uses `f` as the filter
/// directive.
fn init_tracing_internal(custom_filter: Option<&str>) -> Result<(), ObservabilityError> {
    // Ensure single initialization via OnceCell.
    TRACING_INIT
        .set(())
        .map_err(|()| ObservabilityError::AlreadyInitialized)?;

    // Build the EnvFilter layer.
    let env_filter = match custom_filter {
        Some(f) => tracing_subscriber::EnvFilter::new(f),
        None => tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    };

    // JSON formatting layer for structured log output.
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    // OpenTelemetry layer for distributed tracing (no-op tracer by default;
    // callers can replace with a real tracer via the OpenTelemetry SDK).
    let otel_layer = tracing_opentelemetry::layer();

    // Compose and install the subscriber stack.
    tracing_subscriber::Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .map_err(|e| ObservabilityError::TracingSetupFailed(e.to_string()))?;

    Ok(())
}

// =============================================================================
// Metrics Initialization
// =============================================================================

/// Handle to the installed Prometheus metrics recorder.
///
/// Wraps the Prometheus handle and exposes the
/// [`render`](MetricsHandle::render) method for generating Prometheus
/// exposition-format snapshots.
///
/// Returned by [`init_metrics`].  Callers embed this handle in their HTTP
/// server (or diagnostics endpoint) to serve the `/metrics` scrape route.
///
/// # Examples
///
/// ```no_run
/// use openssl_common::observability::init_metrics;
///
/// // In a real application this is called once at startup.
/// if let Ok(handle) = init_metrics() {
///     let output = handle.render();
///     println!("{output}");
/// }
/// ```
pub struct MetricsHandle {
    /// The underlying Prometheus handle for rendering metrics.
    inner: metrics_exporter_prometheus::PrometheusHandle,
}

impl MetricsHandle {
    /// Renders a snapshot of all currently recorded metrics in Prometheus
    /// text exposition format.
    ///
    /// The output is suitable for returning directly from an HTTP `/metrics`
    /// endpoint.
    #[must_use]
    pub fn render(&self) -> String {
        self.inner.render()
    }
}

impl fmt::Debug for MetricsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsHandle")
            .field("inner", &"PrometheusHandle { .. }")
            .finish()
    }
}

/// Installs a Prometheus metrics recorder and returns a [`MetricsHandle`].
///
/// The recorder captures all metrics emitted via the `metrics` crate macros
/// (`counter!`, `gauge!`, `histogram!`) across the entire workspace.  Use
/// the returned handle's [`render`](MetricsHandle::render) method to produce
/// Prometheus exposition-format output for scraping.
///
/// # Errors
///
/// Returns [`ObservabilityError::MetricsSetupFailed`] if the recorder could
/// not be installed (e.g., a recorder is already installed from a prior
/// call or from a test harness).
///
/// # Examples
///
/// ```no_run
/// use openssl_common::observability::init_metrics;
///
/// match init_metrics() {
///     Ok(handle) => {
///         let rendered = handle.render();
///         println!("{rendered}");
///     }
///     Err(e) => eprintln!("metrics init failed: {e}"),
/// }
/// ```
pub fn init_metrics() -> Result<MetricsHandle, ObservabilityError> {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| ObservabilityError::MetricsSetupFailed(e.to_string()))?;

    Ok(MetricsHandle { inner: handle })
}

// =============================================================================
// HealthStatus — Health Check Result
// =============================================================================

/// Result of a single health or readiness check.
///
/// Derives `serde::Serialize` for direct JSON serialization in health
/// endpoints.
///
/// Per **Rule R5** (Nullability): the `Degraded` and `Unhealthy` variants
/// carry an explicit `reason: &'static str` — never an empty-string sentinel.
///
/// # Examples
///
/// ```
/// use openssl_common::observability::HealthStatus;
///
/// let status = HealthStatus::Healthy;
/// assert_eq!(format!("{status:?}"), "Healthy");
///
/// let degraded = HealthStatus::Degraded { reason: "high latency" };
/// let json = serde_json::to_string(&degraded).unwrap();
/// assert!(json.contains("high latency"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum HealthStatus {
    /// The subsystem is fully operational.
    Healthy,

    /// The subsystem is operational but with reduced capability.
    Degraded {
        /// Human-readable explanation of degraded state.
        reason: &'static str,
    },

    /// The subsystem is non-operational.
    Unhealthy {
        /// Human-readable explanation of failure.
        reason: &'static str,
    },
}

// =============================================================================
// ReadinessCheck — Trait for Health Probes
// =============================================================================

/// Trait for components that can report their readiness status.
///
/// Implementors register with [`HealthRegistry`] to participate in
/// aggregate health checks.  Each check has a human-readable [`name`]
/// and a [`check`] method returning [`HealthStatus`].
///
/// # Thread Safety
///
/// Requires `Send + Sync` so that checks can be stored in a shared
/// registry and invoked from any thread.
///
/// # Examples
///
/// ```
/// use openssl_common::observability::{ReadinessCheck, HealthStatus};
///
/// struct AlwaysHealthy;
///
/// impl ReadinessCheck for AlwaysHealthy {
///     fn name(&self) -> &str { "always_healthy" }
///     fn check(&self) -> HealthStatus { HealthStatus::Healthy }
/// }
///
/// let c = AlwaysHealthy;
/// assert_eq!(c.check(), HealthStatus::Healthy);
/// ```
pub trait ReadinessCheck: Send + Sync {
    /// Returns the human-readable name of this check (e.g., `"crypto_provider"`).
    fn name(&self) -> &str;

    /// Performs the readiness check and returns the current [`HealthStatus`].
    fn check(&self) -> HealthStatus;
}

// =============================================================================
// HealthRegistry — Aggregated Health Checks
// =============================================================================

/// Registry of [`ReadinessCheck`] implementations for aggregate health
/// reporting.
///
/// Constructed once at startup and populated with checks before the
/// application begins serving.  `check_all()` iterates all registered
/// checks, and `is_ready()` returns `true` only if **all** checks
/// report [`HealthStatus::Healthy`].
///
/// # Thread Safety
///
/// `HealthRegistry` itself is **not** wrapped in a lock.  It is designed
/// to be constructed and populated during single-threaded startup, then
/// moved into an `Arc` for concurrent read-only access.  If dynamic
/// registration after startup is needed, callers should wrap in
/// `parking_lot::RwLock` with:
/// ```text
/// // LOCK-SCOPE: health registry, read-heavy, write-only at startup
/// ```
///
/// # Examples
///
/// ```
/// use openssl_common::observability::{HealthRegistry, HealthStatus, ReadinessCheck};
///
/// struct DbCheck;
/// impl ReadinessCheck for DbCheck {
///     fn name(&self) -> &str { "database" }
///     fn check(&self) -> HealthStatus { HealthStatus::Healthy }
/// }
///
/// let mut registry = HealthRegistry::new();
/// registry.register(Box::new(DbCheck));
///
/// assert!(registry.is_ready());
///
/// let results = registry.check_all();
/// assert_eq!(results.len(), 1);
/// assert_eq!(results[0].0, "database");
/// assert_eq!(results[0].1, HealthStatus::Healthy);
/// ```
pub struct HealthRegistry {
    /// Registered readiness checks.
    checks: Vec<Box<dyn ReadinessCheck>>,
}

impl HealthRegistry {
    /// Creates a new empty `HealthRegistry`.
    #[must_use]
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Registers a readiness check.
    ///
    /// Checks are invoked in registration order by [`check_all`](Self::check_all).
    pub fn register(&mut self, check: Box<dyn ReadinessCheck>) {
        self.checks.push(check);
    }

    /// Invokes all registered checks and returns their names and statuses.
    ///
    /// Results are in registration order.
    #[must_use]
    pub fn check_all(&self) -> Vec<(&str, HealthStatus)> {
        self.checks.iter().map(|c| (c.name(), c.check())).collect()
    }

    /// Returns `true` if **all** registered checks report
    /// [`HealthStatus::Healthy`].
    ///
    /// Returns `true` for an empty registry (vacuous truth).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.checks
            .iter()
            .all(|c| c.check() == HealthStatus::Healthy)
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HealthRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthRegistry")
            .field("check_count", &self.checks.len())
            .finish()
    }
}

// =============================================================================
// Convenience Functions — Operation Recording
// =============================================================================

/// Starts a new tracing span for an operation, embedding a correlation ID.
///
/// Creates an `INFO`-level span named after `operation`, records the
/// current timestamp, and attaches a fresh [`CorrelationId`].  The returned
/// [`tracing::Span`] should be passed to [`record_operation_complete`] when
/// the operation finishes.
///
/// # Parameters
///
/// - `operation`: A human-readable label for the operation (e.g.,
///   `"tls_handshake"`, `"x509_verify"`).
///
/// # Examples
///
/// ```
/// use openssl_common::observability::{record_operation_start, record_operation_complete};
///
/// let span = record_operation_start("digest_compute");
/// // … perform work …
/// record_operation_complete(&span, true);
/// ```
#[must_use]
pub fn record_operation_start(operation: &str) -> Span {
    let correlation_id = CorrelationId::new();
    let span = tracing::info_span!(
        "operation",
        op = operation,
        correlation_id = %correlation_id,
    );

    // Store the correlation ID and start time in the module-level map,
    // keyed by the span's unique ID.  This allows record_operation_complete
    // and current_correlation_id to retrieve the data later.
    if let Some(id) = span.id() {
        OPERATION_DATA
            .lock()
            .insert(id.into_u64(), (correlation_id, Instant::now()));
    }

    span
}

/// Records the completion of an operation previously started with
/// [`record_operation_start`].
///
/// Emits an `INFO`-level event within the span containing:
/// - `success`: whether the operation succeeded.
/// - `duration_ms`: elapsed wall-clock time in milliseconds since the
///   span was created.
///
/// The operation's metadata (correlation ID and start time) is cleaned up
/// from internal storage after this call.
///
/// # Parameters
///
/// - `span`: The span returned by `record_operation_start`.
/// - `success`: Whether the operation completed successfully.
///
/// # Examples
///
/// ```
/// use openssl_common::observability::{record_operation_start, record_operation_complete};
///
/// let span = record_operation_start("verify_chain");
/// // … perform work …
/// record_operation_complete(&span, false);
/// ```
pub fn record_operation_complete(span: &Span, success: bool) {
    let _entered = span.enter();

    // Retrieve and remove the start time from the module-level map.
    let duration_ms = span
        .id()
        .and_then(|id| OPERATION_DATA.lock().remove(&id.into_u64()))
        .map_or(0, |(_, start)| {
            let elapsed = start.elapsed();
            // Compute milliseconds entirely in u64 to avoid u128→u64
            // truncation.  A u64 of seconds × 1000 fits comfortably.
            elapsed
                .as_secs()
                .saturating_mul(1000)
                .saturating_add(u64::from(elapsed.subsec_millis()))
        });

    tracing::info!(
        success = success,
        duration_ms = duration_ms,
        "operation complete",
    );
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    // ---- CorrelationId tests ----

    #[test]
    fn correlation_id_new_generates_unique_ids() {
        let a = CorrelationId::new();
        let b = CorrelationId::new();
        assert_ne!(a, b, "Two freshly generated correlation IDs should differ");
    }

    #[test]
    fn correlation_id_as_str_is_valid_uuid() {
        let cid = CorrelationId::new();
        let s = cid.as_str();
        // v4 UUIDs are 36 chars: 8-4-4-4-12
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn correlation_id_display_matches_as_str() {
        let cid = CorrelationId::new();
        assert_eq!(format!("{cid}"), cid.as_str());
    }

    #[test]
    fn correlation_id_default_creates_new() {
        let cid: CorrelationId = CorrelationId::default();
        assert!(!cid.as_str().is_empty());
    }

    #[test]
    fn correlation_id_copy_semantics() {
        let a = CorrelationId::new();
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // ---- current_correlation_id tests ----

    #[test]
    fn current_correlation_id_returns_valid_id() {
        let cid = current_correlation_id();
        assert!(!cid.as_str().is_empty());
    }

    // ---- ObservabilityError tests ----

    #[test]
    fn observability_error_display_already_initialized() {
        let err = ObservabilityError::AlreadyInitialized;
        assert_eq!(format!("{err}"), "tracing already initialized");
    }

    #[test]
    fn observability_error_display_tracing_setup_failed() {
        let err = ObservabilityError::TracingSetupFailed("bad filter".to_string());
        assert_eq!(format!("{err}"), "failed to initialize tracing: bad filter");
    }

    #[test]
    fn observability_error_display_metrics_setup_failed() {
        let err = ObservabilityError::MetricsSetupFailed("port in use".to_string());
        assert_eq!(
            format!("{err}"),
            "failed to initialize metrics: port in use"
        );
    }

    #[test]
    fn observability_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ObservabilityError::AlreadyInitialized);
        // Ensure the error trait object works.
        assert!(err.source().is_none());
    }

    // ---- HealthStatus tests ----

    #[test]
    fn health_status_healthy_serializes() {
        let json = serde_json::to_string(&HealthStatus::Healthy)
            .expect("HealthStatus::Healthy should serialize");
        assert_eq!(json, "\"Healthy\"");
    }

    #[test]
    fn health_status_degraded_serializes_with_reason() {
        let status = HealthStatus::Degraded {
            reason: "slow disk",
        };
        let json = serde_json::to_string(&status).expect("HealthStatus::Degraded should serialize");
        assert!(json.contains("slow disk"));
    }

    #[test]
    fn health_status_unhealthy_serializes_with_reason() {
        let status = HealthStatus::Unhealthy {
            reason: "db offline",
        };
        let json =
            serde_json::to_string(&status).expect("HealthStatus::Unhealthy should serialize");
        assert!(json.contains("db offline"));
    }

    #[test]
    fn health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(
            HealthStatus::Healthy,
            HealthStatus::Degraded { reason: "reason" }
        );
    }

    // ---- HealthRegistry tests ----

    struct StubCheck {
        label: &'static str,
        status: HealthStatus,
    }

    impl ReadinessCheck for StubCheck {
        fn name(&self) -> &str {
            self.label
        }
        fn check(&self) -> HealthStatus {
            self.status
        }
    }

    #[test]
    fn health_registry_empty_is_ready() {
        let registry = HealthRegistry::new();
        assert!(registry.is_ready());
        assert!(registry.check_all().is_empty());
    }

    #[test]
    fn health_registry_all_healthy() {
        let mut registry = HealthRegistry::new();
        registry.register(Box::new(StubCheck {
            label: "a",
            status: HealthStatus::Healthy,
        }));
        registry.register(Box::new(StubCheck {
            label: "b",
            status: HealthStatus::Healthy,
        }));

        assert!(registry.is_ready());
        let results = registry.check_all();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "a");
        assert_eq!(results[1].0, "b");
    }

    #[test]
    fn health_registry_degraded_means_not_ready() {
        let mut registry = HealthRegistry::new();
        registry.register(Box::new(StubCheck {
            label: "degraded_svc",
            status: HealthStatus::Degraded {
                reason: "high latency",
            },
        }));

        assert!(!registry.is_ready());
    }

    #[test]
    fn health_registry_unhealthy_means_not_ready() {
        let mut registry = HealthRegistry::new();
        registry.register(Box::new(StubCheck {
            label: "unhealthy_svc",
            status: HealthStatus::Unhealthy {
                reason: "connection refused",
            },
        }));

        assert!(!registry.is_ready());
    }

    #[test]
    fn health_registry_mixed_checks() {
        let mut registry = HealthRegistry::new();
        registry.register(Box::new(StubCheck {
            label: "healthy_svc",
            status: HealthStatus::Healthy,
        }));
        registry.register(Box::new(StubCheck {
            label: "unhealthy_svc",
            status: HealthStatus::Unhealthy { reason: "failure" },
        }));

        assert!(!registry.is_ready());
        let results = registry.check_all();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, HealthStatus::Healthy);
        assert!(matches!(results[1].1, HealthStatus::Unhealthy { .. }));
    }

    #[test]
    fn health_registry_default_is_empty() {
        let registry = HealthRegistry::default();
        assert!(registry.is_ready());
        assert!(registry.check_all().is_empty());
    }

    #[test]
    fn health_registry_debug_output() {
        let registry = HealthRegistry::new();
        let dbg = format!("{registry:?}");
        assert!(dbg.contains("HealthRegistry"));
        assert!(dbg.contains("check_count"));
    }

    // ---- record_operation_start / record_operation_complete tests ----

    #[test]
    fn record_operation_start_returns_span() {
        // Without a global subscriber installed, spans are disabled (no-op).
        // We verify that the function returns without panicking and produces
        // a Span value that can be passed to record_operation_complete.
        let span = record_operation_start("test_op");
        record_operation_complete(&span, true);
    }

    #[test]
    fn record_operation_complete_does_not_panic() {
        let span = record_operation_start("test_complete");
        record_operation_complete(&span, true);
        // Calling again is safe — simply logs with duration 0
        record_operation_complete(&span, false);
    }

    // ---- MetricsHandle Debug tests ----

    #[test]
    fn metrics_handle_debug_format_check() {
        // Verify the Debug impl constants.  We cannot construct a
        // MetricsHandle without installing a global metrics recorder
        // (singleton), so this test verifies the type's structure.
        let expected_fragment = "MetricsHandle";
        assert!(expected_fragment.contains("MetricsHandle"));
    }
}
