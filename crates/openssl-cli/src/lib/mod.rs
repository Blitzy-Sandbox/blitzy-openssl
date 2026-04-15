//! Shared CLI infrastructure modules.
//!
//! Consolidates the functionality of `apps/lib/` (21 C source files, 9,881 total lines)
//! into focused Rust modules providing option parsing helpers, passphrase handling,
//! and HTTP server utilities.
//!
//! ## Module Organization
//!
//! | Module | Purpose | C Source |
//! |--------|---------|----------|
//! | [`opts`] | Format enums, verify params, column layout, name printing, param display | opt.c, columns.c, fmt.c, names.c, app\_params.c, apps\_opt\_printf.c |
//! | [`password`] | Secure passphrase prompting and verification | apps\_ui.c |
//! | [`http`] | Basic HTTP/1.x server for OCSP/CMP responders | http\_server.c |
//!
//! ## Design Decisions
//!
//! - The 1,276-line manual C parser (`opt_init`/`opt_next`) is completely replaced by
//!   clap derive macros — `opts` provides only supplementary helpers.
//! - The large `apps.c` (3,828 lines) is NOT replicated as a monolithic module — its
//!   helpers are distributed into `main.rs` initialization and individual command modules.
//! - Platform-specific code (VMS, Windows shims) is not replicated — Rust's `std`
//!   provides cross-platform I/O and argument handling natively.
//! - Logging infrastructure (`log.c`) is replaced by `tracing` subscriber initialized
//!   in `main.rs`.
//!
//! ## Consolidation Summary
//!
//! The following 14 C files from `apps/lib/` are **not** replicated in this module —
//! their functionality has been distributed as follows:
//!
//! | C Source File | Lines | Rust Location |
//! |---------------|-------|---------------|
//! | `apps.c` | 3,828 | `main.rs` initialization + individual `commands/*.rs` |
//! | `app_libctx.c` | 47 | `main.rs` initialization |
//! | `app_provider.c` | 167 | `main.rs` initialization |
//! | `app_rand.c` | 122 | `main.rs` initialization |
//! | `app_x509.c` | 135 | `commands/*.rs` |
//! | `s_cb.c` | 1,667 | `commands/s_client.rs`, `commands/s_server.rs` |
//! | `s_socket.c` | 504 | `commands/s_client.rs`, `commands/s_server.rs` |
//! | `log.c` | 111 | `tracing` subscriber in `main.rs` |
//! | `cmp_mock_srv.c` | 738 | `commands/cmp.rs` |
//! | `tlssrp_depr.c` | 226 | `commands/srp.rs` |
//! | VMS/Win shims | — | Not replicated (Rust `std` handles platform differences) |
//!
//! ## Wiring (Rule R10)
//!
//! Caller chain from entry point:
//!
//! ```text
//! main.rs
//! ├── mod lib;               ← this file
//! │   ├── pub mod opts;      ← opts.rs
//! │   │   └── Used by: commands/*.rs (Format, VerifyParams, DisplayColumns)
//! │   ├── pub mod password;  ← password.rs
//! │   │   └── Used by: commands/*.rs (any -passin/-passout command)
//! │   └── pub mod http;      ← http.rs
//! │       └── Used by: commands/ocsp.rs, commands/cmp.rs (HTTP responder)
//! └── mod commands;
//!     └── Uses lib::{opts, password, http}
//! ```

// ---------------------------------------------------------------------------
// Child Module Declarations
// ---------------------------------------------------------------------------
// Each child module consolidates several C source files into a focused,
// single-responsibility Rust module. All modules are `pub` to allow
// direct access via `crate::lib::opts::*` paths alongside the convenience
// re-exports below.

/// Shared option parsing helpers, format enums, and display utilities.
///
/// Consolidates: `opt.c`, `columns.c`, `fmt.c`, `names.c`, `app_params.c`,
/// `apps_opt_printf.c` (1,573 total C lines).
pub mod opts;

/// Secure passphrase prompting, verification, and callback infrastructure.
///
/// Consolidates: `apps_ui.c` (216 C lines).
pub mod password;

/// Basic HTTP/1.x server for OCSP and CMP responder commands.
///
/// Consolidates: `http_server.c` (547 C lines).
pub mod http;

// ---------------------------------------------------------------------------
// Convenience Re-exports
// ---------------------------------------------------------------------------
// Re-export commonly used types for ergonomic access from command modules.
// This allows: `use crate::lib::{Format, PasswordHandler, HttpServer};`
// instead of: `use crate::lib::opts::Format;`

// From opts module: format handling, verification parameters, column layout
pub use opts::{DisplayColumns, Format, FormatFlags, VerifyParams};

// From password module: passphrase handling
pub use password::{PasswordCallbackData, PasswordError, PasswordHandler};

// From http module: HTTP server for OCSP/CMP responders
pub use http::{HttpMethod, HttpRequest, HttpServer, HttpServerError};
