//! # openssl-fips
//!
//! FIPS 140-3 compliance module for the OpenSSL Rust workspace (`openssl-rs`).
//! Provides Power-On Self-Test (POST), Known Answer Tests (KATs), integrity
//! verification, and the FIPS approved service indicator mechanism.
//!
//! This crate is a ground-up Rust rewrite of the C FIPS module from
//! `providers/fips/` (~7,600 lines of C across `fipsprov.c`, `self_test.c`,
//! `self_test_kats.c`, `self_test_data.c`, `fipsindicator.c`,
//! and `fips_entry.c`). It maintains strict isolation from non-FIPS
//! components per NIST CMVP requirements (AAP §0.7.3).
//!
//! ## Crate Architecture
//!
//! The crate is organised into five cohesive modules, each mapping to a
//! distinct subsystem of the upstream C implementation.  Modules are declared
//! in dependency order — foundational modules first, integration-level
//! modules last.
//!
//! ### Module Structure
//!
//! | Module          | Source (C)                                                    | Purpose                                                                 |
//! |-----------------|---------------------------------------------------------------|-------------------------------------------------------------------------|
//! | [`state`]       | `providers/fips/self_test.c` (state machine)                  | Module-level and per-test state enums with atomic accessors             |
//! | [`indicator`]   | `providers/fips/fipsindicator.c`                              | FIPS approved service indicator with settable-state overrides           |
//! | [`kats`]        | `providers/fips/self_test_kats.c`, `self_test_data.c`         | KAT execution engine and compiled test-vector catalogue                 |
//! | [`self_test`]   | `providers/fips/self_test.c`                                  | POST orchestration, integrity verification, state transitions           |
//! | [`provider`]    | `providers/fips/fipsprov.c`, `fips_entry.c`                   | Provider entry, algorithm dispatch tables, configuration lifecycle      |
//!
//! ### Migration from C
//!
//! The trivial 20-line `fips_entry.c` trampoline (which forwards
//! `OSSL_provider_init` to `OSSL_provider_init_int`) is replaced in Rust by
//! the direct convenience functions exposed at this crate root
//! ([`is_operational`], [`is_self_testing`], [`current_state`]).  The
//! equivalent dispatch logic lives in [`provider`], and the state accessors
//! live in [`state`] and [`self_test`].
//!
//! ## FIPS Boundary Isolation
//!
//! Per NIST CMVP requirements and AAP §0.7.3, this crate enforces strict
//! architectural isolation:
//!
//! ```text
//! openssl-common (shared foundation)    ← permitted dependency
//! openssl-crypto (selected primitives)  ← permitted dependency
//!
//! openssl-ssl                           ← FORBIDDEN
//! openssl-provider                      ← FORBIDDEN
//! openssl-cli                           ← FORBIDDEN
//! openssl-ffi                           ← FORBIDDEN
//! ```
//!
//! This guarantees the FIPS module is independently compilable and
//! independently certifiable — the compiled artefact's dependency closure
//! contains only CMVP-approved components.
//!
//! ## Safety Guarantees
//!
//! The crate satisfies the project-wide refactoring rules R5, R6, R8, R9
//! through a combination of crate-level lint attributes and design discipline:
//!
//! - **Rule R8 — Zero unsafe code outside FFI:** This crate contains NO
//!   `unsafe` code.  `#![forbid(unsafe_code)]` (stricter than the workspace
//!   default of `deny`) prevents any submodule from introducing `unsafe` via
//!   a `#[allow]` override.  Any raw pointer / FFI work belongs exclusively
//!   in the dedicated `openssl-ffi` crate.
//! - **Rule R6 — No bare narrowing casts:** `#![deny(clippy::cast_possible_truncation)]`
//!   rejects any `as` cast that could silently truncate.  Narrowing must use
//!   `try_from`, `saturating_cast`, or `clamp`.
//! - **Rule R9 — Warning-free build:** `#![warn(missing_docs)]` ensures every
//!   public item is documented, and the workspace-level `RUSTFLAGS="-D warnings"`
//!   promotes all warnings to errors in CI.
//! - **Rule R5 — Nullability over sentinels:** All re-exported types use
//!   `Option<T>` where appropriate; sentinel values (`0`, `-1`, `""`) are
//!   avoided for "unset" states.
//! - **No `.unwrap()` / `.expect()` in library code:** `#![deny(clippy::unwrap_used)]`
//!   and `#![deny(clippy::expect_used)]` keep panicky shortcuts out of
//!   production paths.  Test modules that legitimately need these for
//!   assertion clarity carry a targeted `#[allow(...)]` with justification.
//!
//! ## State Machine
//!
//! The FIPS module enforces a strict state machine to guarantee that no
//! cryptographic operation executes before POST completes successfully:
//!
//! ```text
//! FIPS Module State (process-wide):
//!   Init ──→ SelfTesting ──→ Running   (operational, algorithms callable)
//!                        └──→ Error    (non-operational, module locked out)
//!
//! Per-Test State (one entry per TestCategory):
//!   Init ──→ InProgress ──→ Passed
//!                       ├──→ Failed
//!                       ├──→ Implicit  (skipped, dependency passed)
//!                       └──→ Deferred  (scheduled for lazy execution)
//! ```
//!
//! See [`state::FipsState`] and [`state::TestState`] for the full enum
//! definitions and valid transitions.
//!
//! ## Example
//!
//! The typical lifecycle is: construct a configuration `ParamSet`,
//! call [`provider::initialize`] to run POST and register algorithms,
//! then gate subsequent operations behind [`is_operational`] checks.
//!
//! ```rust,no_run
//! use openssl_fips::provider::{initialize, SelfTestPostParams};
//! use openssl_common::param::ParamSet;
//!
//! // Build a minimal FIPS configuration (real usage populates module /
//! // indicator checksums via ParamSet).
//! let config = ParamSet::new();
//!
//! // Initialise the FIPS provider — runs POST (integrity + KATs), then
//! // transitions the module to `Running` on success.
//! let _fips = initialize(&config)
//!     .unwrap_or_else(|_| panic!("FIPS initialization failed"));
//!
//! // Guard cryptographic operations behind the operational check.
//! assert!(openssl_fips::is_operational());
//! ```
//!
//! ## Re-exports
//!
//! For ergonomic access, the crate re-exports its most frequently used
//! types at the crate root:
//!
//! | Re-export                 | Source Module            | Kind       |
//! |---------------------------|--------------------------|------------|
//! | [`FipsState`]             | [`state::FipsState`]     | `enum`     |
//! | [`TestState`]             | [`state::TestState`]     | `enum`     |
//! | [`TestCategory`]          | [`state::TestCategory`]  | `enum`     |
//! | [`FipsIndicator`]         | [`indicator::FipsIndicator`] | `struct` |
//! | [`SettableState`]         | [`indicator::SettableState`] | `enum`   |
//! | [`FipsGlobal`]            | [`provider::FipsGlobal`] | `struct`   |
//! | [`FipsOption`]            | [`provider::FipsOption`] | `struct`   |
//! | [`SelfTestPostParams`]    | [`provider::SelfTestPostParams`] | `struct` |

// =============================================================================
// Crate-Level Lint Configuration
// =============================================================================
//
// The workspace root `Cargo.toml` sets most lints via `[workspace.lints.*]`
// and each crate inherits them with `[lints] workspace = true`.  The attributes
// below intentionally *strengthen* a subset of those lints to harden the
// FIPS boundary beyond the workspace baseline.

// Rule R8 — Zero unsafe outside FFI.  `forbid` is strictly stronger than the
// workspace default `deny`: `#[allow(unsafe_code)]` on any submodule, item, or
// expression cannot override `forbid`, so this is the non-negotiable
// enforcement mechanism for the FIPS boundary (AAP §0.7.3).
#![forbid(unsafe_code)]
// Rule R6 — No bare narrowing casts; use `try_from`, `saturating_cast`, or
// `clamp`.  Surviving `#[allow]` sites must carry a `// TRUNCATION:`
// justification comment as mandated by the workspace policy.
#![deny(clippy::cast_possible_truncation)]
// Rule R9 — Warning-free build.  `warn(missing_docs)` combined with CI's
// `RUSTFLAGS="-D warnings"` guarantees every public item has a doc comment.
#![warn(missing_docs)]
// No `.unwrap()` in library code — use `Result`/`Option` combinators or `?`.
// Test modules (`#[cfg(test)]`) may `#[allow]` with a rationale.
#![deny(clippy::unwrap_used)]
// No `.expect()` in library code — same rationale as `unwrap_used`.
#![deny(clippy::expect_used)]

// =============================================================================
// Module Declarations
// =============================================================================
//
// Modules are declared in dependency order so that a forward scan of this
// file reflects the compilation / initialization order of the crate:
//
//   1. `state`       — foundational atomics and state enums (no crate deps)
//   2. `indicator`   — FIPS indicator (depends on `openssl-common` only)
//   3. `kats`        — KAT execution engine (depends on `state`)
//   4. `self_test`   — POST orchestration (depends on `state`, `kats`)
//   5. `provider`    — provider entry / dispatch (depends on all above)

/// Module-level and per-test state machine.
///
/// Provides [`state::FipsState`] (Init → SelfTesting → Running | Error) and
/// [`state::TestState`] (Init → InProgress → Passed | Failed | Implicit |
/// Deferred), plus atomic process-wide accessors.
pub mod state;

/// FIPS approved service indicator.
///
/// Tracks per-algorithm-context approved/unapproved status, settable-state
/// overrides, and configurable strict/tolerant enforcement modes.
pub mod indicator;

/// Known Answer Test (KAT) execution engine.
///
/// Contains the compiled FIPS 140-3 IG 10.3.A test-vector catalogue and
/// per-category execution functions (digest, cipher, MAC, KDF, DRBG,
/// signature, KAS, asym keygen, KEM, asym cipher).
pub mod kats;

/// Power-On Self-Test (POST) orchestration.
///
/// Performs module integrity verification (HMAC-SHA256), coordinates KAT
/// execution, drives the module-level state transitions, and exposes the
/// guard functions [`self_test::is_running`] / [`self_test::is_self_testing`].
pub mod self_test;

/// FIPS provider entry point and algorithm dispatch.
///
/// Houses [`provider::FipsGlobal`] (the provider-global state), the
/// compiled algorithm tables ([`provider::FipsAlgorithmEntry`]),
/// [`provider::initialize`] (the main lifecycle entry point), and
/// deferred-test locking primitives.
pub mod provider;

/// Private test submodule — compiled only under `#[cfg(test)]`.
///
/// The parent `tests/` directory contains six submodules covering every
/// public API surface of this crate.  Gating at the crate root prevents
/// any test code from leaking into release builds.
#[cfg(test)]
mod tests;

// =============================================================================
// Public Re-exports
// =============================================================================
//
// Re-export the most frequently used types at the crate root so that downstream
// consumers can write `use openssl_fips::FipsState;` instead of
// `use openssl_fips::state::FipsState;`.  The underlying module paths remain
// fully accessible for consumers that need fine-grained imports.

// State machine types (from [`state`]).
pub use state::{FipsState, TestCategory, TestState};

// Indicator types (from [`indicator`]).
pub use indicator::{FipsIndicator, SettableState};

// Provider types (from [`provider`]).
pub use provider::{FipsGlobal, FipsOption, SelfTestPostParams};

// =============================================================================
// Crate-Level Constants
// =============================================================================

/// Crate version as declared in `Cargo.toml` (e.g. `"0.1.0"`).
///
/// Populated at compile time from the `CARGO_PKG_VERSION` environment
/// variable. Exposed so that the FIPS provider can surface the module
/// version in its parameter table (matches `OSSL_PROV_PARAM_VERSION` from
/// `fipsprov.c:gettable_params()`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-readable FIPS provider name.
///
/// Used in the provider parameter table and diagnostic output. Equivalent
/// to the `"OpenSSL FIPS Provider"` string literal in the upstream
/// `fipsprov.c` `gettable_params()` implementation.
pub const NAME: &str = "OpenSSL FIPS Provider";

/// Concatenated build identifier: `"openssl-fips <version>"`.
///
/// Built at compile time from [`NAME`] and [`VERSION`]. Surfaced by
/// [`provider::FipsGlobal::build_info`] and used as the `OSSL_PROV_PARAM_BUILDINFO`
/// value when the provider is queried. Matches the canonical build-info string
/// format used throughout the OpenSSL codebase.
pub const BUILD_INFO: &str = concat!("openssl-fips ", env!("CARGO_PKG_VERSION"));

// =============================================================================
// Top-Level Convenience Functions
// =============================================================================
//
// These functions provide a flat, ergonomic surface for the two most common
// FIPS state queries — "is the module operational?" and "is the module
// currently self-testing?" — without requiring callers to reach into the
// submodule hierarchy.  They replace the equivalent C preprocessor-macro
// guards (`ossl_prov_is_running()`, `IS_FIPS()`) and form the Rust-side
// equivalent of `fips_entry.c`'s inline state-check trampolines.

/// Returns `true` if the FIPS module has completed POST successfully and
/// is therefore operational.
///
/// This is the canonical gate for every FIPS-approved cryptographic
/// operation: callers MUST check this (or an equivalent state predicate)
/// before invoking any algorithm that requires FIPS compliance. Returns
/// `false` if the module is in [`FipsState::Init`], [`FipsState::SelfTesting`],
/// or [`FipsState::Error`].
///
/// Equivalent to the C `ossl_prov_is_running()` inline check from
/// `providers/fips/fipsprov.c`. Delegates to [`self_test::is_running`] so
/// that the authoritative definition of "running" lives alongside the POST
/// orchestrator.
///
/// # Examples
///
/// ```rust,no_run
/// if openssl_fips::is_operational() {
///     // Safe to invoke FIPS-approved algorithms.
/// } else {
///     // Module is initialising, self-testing, or in error state.
/// }
/// ```
#[must_use]
pub fn is_operational() -> bool {
    self_test::is_running()
}

/// Returns `true` if the FIPS module is currently executing POST
/// (integrity verification or Known Answer Tests).
///
/// Used by reentrancy guards in cryptographic algorithms: while
/// [`is_self_testing`] returns `true`, algorithm implementations must
/// skip their normal indicator / approval checks to avoid recursive
/// self-test invocations (matches the `SELF_TEST_FLAG_PENDING_SETUP`
/// behaviour in `providers/fips/self_test.c`).
///
/// Delegates to [`self_test::is_self_testing`].
///
/// # Examples
///
/// ```rust,no_run
/// if !openssl_fips::is_self_testing() {
///     // Normal indicator check.
/// } else {
///     // Inside POST — skip approval check to avoid recursion.
/// }
/// ```
#[must_use]
pub fn is_self_testing() -> bool {
    self_test::is_self_testing()
}

/// Returns the current process-wide FIPS module state.
///
/// Reads the atomic state machine variable maintained by the [`state`]
/// submodule. Useful for diagnostics and for making fine-grained decisions
/// that depend on more than the binary "operational" question.
///
/// Delegates to [`state::get_fips_state`].
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_fips::FipsState;
///
/// match openssl_fips::current_state() {
///     FipsState::Init        => { /* module not initialised */ }
///     FipsState::SelfTesting => { /* POST in progress */ }
///     FipsState::Running     => { /* operational */ }
///     FipsState::Error       => { /* module locked out */ }
/// }
/// ```
#[must_use]
pub fn current_state() -> FipsState {
    state::get_fips_state()
}
