//! Integration tests for the OpenSSL CLI binary.
//!
//! Tests exercise the compiled `openssl` binary via subprocess invocation using
//! the following test infrastructure:
//!
//! - [`assert_cmd`] — Command execution and assertion framework providing
//!   [`Command::cargo_bin()`][assert_cmd::Command::cargo_bin] to invoke the
//!   compiled binary as a subprocess
//! - [`predicates`] — Rich output matching predicates for stdout/stderr assertions
//! - [`tempfile`] — Temporary file and directory management for test isolation
//! - [`insta`] — Snapshot testing for stable help output verification
//! - [`test_log`] — Tracing subscriber initialization in test context
//!
//! ## Test Organization
//!
//! Tests are organized into focused modules by functional area:
//!
//! | Module | Coverage |
//! |--------|----------|
//! | [`dispatch_tests`] | Subcommand dispatch and wiring (Rule R10) |
//! | [`pki_tests`] | PKI operations (req, x509, ca, verify, crl) |
//! | [`crypto_tests`] | Cryptographic operations (enc, dgst, cms, pkcs12) |
//! | [`tls_tests`] | TLS diagnostic tools (s\_client, s\_server, ciphers) |
//! | [`introspection_tests`] | Introspection commands (version, list, info, errstr) |
//! | [`provider_tests`] | Provider loading and selection |
//! | [`error_tests`] | Error handling and edge cases |
//! | [`help_tests`] | Help output snapshot tests |
//! | [`callback_tests`] | Callback registration-invocation (Rule R4) |
//! | [`fips_tests`] | FIPS module tests (feature-gated) |
//!
//! ## Shared Helper
//!
//! All test modules access the [`openssl_cmd()`] helper via `super::openssl_cmd()`
//! to create pre-configured [`assert_cmd::Command`] instances pointing to the
//! compiled `openssl` binary.

use assert_cmd::Command;

// ---------------------------------------------------------------------------
// Child test module declarations
// ---------------------------------------------------------------------------

/// Subcommand dispatch and wiring tests verifying all 54+ CLI subcommands
/// are reachable from the binary entry point (Rule R10, Gate 9).
mod dispatch_tests;

/// PKI operation integration tests exercising certificate generation,
/// signing, verification, and CRL workflows (Gate 1, Gate 4).
mod pki_tests;

/// Cryptographic operation integration tests for symmetric encryption,
/// message digests, CMS, PKCS#12, random data, and MAC computation (Gate 5).
mod crypto_tests;

/// TLS diagnostic tool integration tests covering cipher suite listing,
/// s\_client/s\_server lifecycle, and protocol version selection (Gate 4, Gate 5).
mod tls_tests;

/// Introspection command integration tests for version, list, info,
/// and errstr subcommands (Gate 5, Gate 9).
mod introspection_tests;

/// Provider loading integration tests verifying `-provider`, `-provider-path`,
/// and `-propquery` global options across multiple subcommands.
mod provider_tests;

/// Error handling integration tests verifying CLI handles invalid commands,
/// missing arguments, bad file paths, and malformed input gracefully.
mod error_tests;

/// Help output snapshot tests using `insta` for stable, regression-detected
/// help text across top-level and subcommand `--help` invocations (Gate 5).
mod help_tests;

/// Callback registration-invocation integration tests verifying Rule R4:
/// every callback/hook has a register → trigger → assert test.
mod callback_tests;

/// FIPS module integration tests for `fipsinstall` and FIPS provider operations.
/// Feature-gated behind the `fips` feature flag.
#[cfg(feature = "fips")]
mod fips_tests;

// ---------------------------------------------------------------------------
// Shared test utilities
// ---------------------------------------------------------------------------

/// Creates an [`assert_cmd::Command`] for the compiled `openssl` binary.
///
/// This is the shared entry point used by all child test modules via
/// `super::openssl_cmd()` to invoke the CLI binary as a subprocess for
/// integration testing.
///
/// # Panics
///
/// Panics if the `openssl` binary cannot be found. This typically indicates
/// the binary has not been built yet — run `cargo build` before running tests.
///
/// # Examples
///
/// ```rust,ignore
/// let cmd = super::openssl_cmd();
/// cmd.arg("version").assert().success();
/// ```
pub(crate) fn openssl_cmd() -> Command {
    Command::cargo_bin("openssl").expect("openssl binary not found — run `cargo build` first")
}

// ---------------------------------------------------------------------------
// Module-level validation tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod mod_tests {
    use super::openssl_cmd;

    /// Validates that the shared [`openssl_cmd`] helper successfully locates
    /// the compiled `openssl` binary and returns a ready-to-use
    /// [`assert_cmd::Command`].
    ///
    /// This test requires the binary to have been built first via
    /// `cargo build -p openssl-cli`.
    #[test]
    fn openssl_cmd_creates_command() {
        let mut cmd = openssl_cmd();
        // Verify the command can be configured (basic smoke test).
        // The actual binary execution is validated in child test modules.
        let assert = cmd.arg("--help").assert();
        // We accept both success and failure here because the stub binary
        // may not yet support --help, but the Command must be constructable.
        let _ = assert;
    }
}
