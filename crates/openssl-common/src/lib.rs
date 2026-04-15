//! # openssl-common
//!
//! Shared foundation crate for the OpenSSL Rust workspace (`openssl-rs`).
//! Provides cross-cutting concerns used by all other workspace crates:
//!
//! - **Error handling** ([`error`]) — Per-crate error enums with `thiserror` derive,
//!   replacing the C ERR_* thread-local error stack
//! - **Configuration** ([`config`]) — Config file parsing replacing NCONF/CONF
//! - **Parameter system** ([`param`]) — Typed parameter passing replacing `OSSL_PARAM`
//! - **Type definitions** ([`types`]) — Shared newtypes: NID, protocol versions, key types
//! - **Time** ([`time`]) — Nanosecond-precision time with saturating arithmetic
//! - **Safe math** ([`safe_math`]) — Overflow-checked arithmetic replacing `safe_math.h` macros
//! - **Constant-time** ([`constant_time`]) — Constant-time operations via `subtle` crate
//! - **Memory** ([`mem`]) — Secure zeroing and memory protection via `zeroize`
//! - **Observability** ([`observability`]) — Structured logging, metrics, and health checks
//!
//! ## Design Principles
//!
//! - **Zero unsafe:** This crate contains NO `unsafe` code (Rule R8)
//! - **Fully synchronous:** No async/tokio dependency (per AAP §0.4.4)
//! - **Option over sentinel:** All nullable values use `Option<T>` (Rule R5)
//! - **Checked arithmetic:** All narrowing casts use `try_from`/`saturating_cast` (Rule R6)
//!
//! ## Crate Dependency Position
//!
//! ```text
//! openssl-common (this crate)
//!   ← openssl-crypto
//!   ← openssl-ssl
//!   ← openssl-provider
//!   ← openssl-fips
//!   ← openssl-cli
//!   ← openssl-ffi
//! ```
//!
//! ## Migration from C
//!
//! This crate consolidates several C subsystems into a single Rust module:
//!
//! | C Subsystem                        | Rust Module                 |
//! |------------------------------------|-----------------------------|
//! | `crypto/err/*.c` (ERR_* stack)     | [`error`]                   |
//! | `crypto/conf/*.c` (NCONF/CONF)     | [`config`]                  |
//! | `crypto/params*.c` (OSSL_PARAM)    | [`param`]                   |
//! | `include/openssl/types.h`          | [`types`]                   |
//! | `crypto/time.c` (OSSL_TIME)        | [`time`]                    |
//! | `include/internal/safe_math.h`     | [`safe_math`]               |
//! | `include/internal/constant_time.h` | [`constant_time`]           |
//! | `crypto/mem*.c` (OPENSSL_cleanse)  | [`mem`]                     |
//! | *(no C equivalent)*                | [`observability`]           |

// =============================================================================
// Crate-Level Lint Configuration
// =============================================================================
//
// These lint attributes reinforce and, where appropriate, strengthen the
// workspace-level lint policy defined in the root Cargo.toml.  They apply
// to ALL code compiled within this crate, including submodules and tests.
//
// Test modules that legitimately need `.unwrap()` / `.expect()` must add
// a targeted `#[allow(clippy::unwrap_used, clippy::expect_used)]` at the
// module or function level with a justification comment.

// Rule R8: zero unsafe in non-FFI crates.  `forbid` is used (stricter than
// `deny`) to prevent any submodule from overriding with `#[allow]`.
#![forbid(unsafe_code)]
// Rule R6: no bare narrowing casts — must use `try_from` / `saturating_cast`.
#![deny(clippy::cast_possible_truncation)]
// Ensure documentation coverage across all public items.
#![warn(missing_docs)]
// No `.unwrap()` in library code — use `Result`/`Option` combinators or `?`.
#![deny(clippy::unwrap_used)]
// No `.expect()` in library code — use `Result`/`Option` combinators or `?`.
#![deny(clippy::expect_used)]

// =============================================================================
// Module Declarations
// =============================================================================
//
// Each public module corresponds to a distinct cross-cutting concern.
// Module ordering follows the dependency graph: foundational modules first,
// then modules that depend on them.

/// Error handling infrastructure — per-crate error enums, `Result` aliases,
/// error detail records, and the FFI-compatible error stack.
///
/// Replaces the C `ERR_*` thread-local error queue from `crypto/err/*.c`
/// with idiomatic Rust `Result<T, E>` propagation.
pub mod error;

/// Configuration file parser — INI-style `.cnf`/`.conf` parsing with
/// section headers, variable expansion, `.include` directives, and a
/// module registration system.
///
/// Replaces the C `NCONF`/`CONF` subsystem from `crypto/conf/*.c`.
pub mod config;

/// Typed parameter system — compile-time type-checked parameter passing
/// between the EVP abstraction layer and provider implementations.
///
/// Replaces the C `OSSL_PARAM` dynamically-typed parameter arrays from
/// `crypto/params.c`, `crypto/param_build.c`, and `crypto/params_dup.c`.
pub mod param;

/// Shared type definitions — newtype wrappers for algorithm identifiers
/// ([`Nid`]), protocol versions, padding modes, key types, cipher modes,
/// operation types, and the [`AlgorithmName`] trait.
///
/// Replaces the C `#define NID_*` groups and forward `typedef` declarations
/// from `include/openssl/types.h` and `include/openssl/obj_mac.h`.
pub mod types;

/// Nanosecond-precision time representation with saturating arithmetic.
///
/// Replaces the C `OSSL_TIME` type and `ossl_time_*` utility functions
/// from `crypto/time.c` and `include/internal/time.h`.  Used by the QUIC
/// reactor tick scheduler and session expiry logic.
pub mod time;

/// Overflow-checked arithmetic primitives — Rust-native replacements for
/// the C `safe_math.h` macro system.
///
/// Provides [`safe_math::SafeResult`], checked arithmetic functions, and
/// lossless cast utilities enforcing Rule R6.
pub mod safe_math;

/// Constant-time comparison and selection primitives — wraps the `subtle`
/// crate to provide API-compatible replacements for the C
/// `constant_time_*` functions from `include/internal/constant_time.h`.
pub mod constant_time;

/// Secure memory primitives — zero-on-drop wrappers, secure byte vectors,
/// and timing-safe comparison.
///
/// Replaces `OPENSSL_cleanse()` from `crypto/mem_clr.c` and the secure
/// heap from `crypto/mem_sec.c` using the `zeroize` crate.
pub mod mem;

/// Observability infrastructure — structured logging, distributed tracing,
/// Prometheus metrics, correlation IDs, and health/readiness checks.
///
/// This module has **no direct C counterpart**.  It provides new
/// observability capabilities per AAP §0.8.5 (Observability Rule):
/// ship observability with the initial implementation, not as follow-up.
pub mod observability;

// =============================================================================
// Test Module Declaration
// =============================================================================

/// Root test module aggregating per-submodule test suites.
///
/// Gated behind `#[cfg(test)]` so test code is only compiled during
/// `cargo test`.  The module root lives at `src/tests/mod.rs` and
/// declares child test submodules for each source module.
#[cfg(test)]
mod tests;

// =============================================================================
// Public Re-exports — Ergonomic Access to Key Types
// =============================================================================
//
// These re-exports allow downstream crates to import commonly used types
// directly from `openssl_common::` instead of navigating into submodules.
// This follows the Rust convention of providing "prelude-style" re-exports
// at the crate root for the most frequently used items.

// ── Error types ─────────────────────────────────────────────────────────────

/// Re-exported error types for ergonomic `use openssl_common::CommonError;`.
pub use error::{
    CommonError, CommonResult, CryptoError, CryptoResult, ErrorDetail, ErrorLibrary, ErrorStack,
    FipsError, FipsResult, ProviderError, ProviderResult, SslError, SslResult,
};

// ── Parameter types ─────────────────────────────────────────────────────────

/// Re-exported parameter system types for ergonomic access.
pub use param::{FromParam, ParamBuilder, ParamSet, ParamValue};

// ── Core shared types ───────────────────────────────────────────────────────

/// Re-exported shared type definitions for ergonomic access.
pub use types::{
    AlgorithmName, CipherMode, KeyType, Nid, OperationType, PaddingMode, ProtocolVersion,
};

// ── Time ────────────────────────────────────────────────────────────────────

/// Re-exported time type for ergonomic access.
pub use time::OsslTime;

// ── Secure memory ───────────────────────────────────────────────────────────

/// Re-exported secure memory primitives for ergonomic access.
pub use mem::{cleanse, constant_time_eq, SecureBox, SecureVec};

// ── Observability ───────────────────────────────────────────────────────────

/// Re-exported observability types for ergonomic access.
pub use observability::{
    init_metrics, init_tracing, CorrelationId, HealthRegistry, HealthStatus, MetricsHandle,
    ObservabilityError, ReadinessCheck,
};

// =============================================================================
// Crate Metadata Constants
// =============================================================================

/// Crate version string, automatically populated from `Cargo.toml`.
///
/// Matches the `version` field in `crates/openssl-common/Cargo.toml`.
/// Used by the CLI `version` subcommand and observability metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name string, automatically populated from `Cargo.toml`.
///
/// Returns `"openssl-common"` — the package name as declared in the
/// manifest.  Used for structured logging and metric labels.
pub const NAME: &str = env!("CARGO_PKG_NAME");
