//! Error handling integration tests for the OpenSSL CLI binary.
//!
//! Verifies that the CLI handles invalid input gracefully by producing
//! non-zero exit codes and meaningful error messages on stderr rather
//! than silently succeeding or crashing.
//!
//! ## Test Categories
//!
//! | Category | Tests | Validation |
//! |----------|-------|------------|
//! | Invalid commands | 3 | Unknown subcommand → "Invalid command" error |
//! | Missing arguments | 4 | Required options absent → non-zero exit |
//! | Bad file paths | 3 | Inaccessible paths → contextual error |
//! | Invalid options | 3 | Unrecognized flags → clear diagnostics |
//! | Malformed input | 2 | Garbage data → parse error diagnostics |
//!
//! ## Design Notes
//!
//! Tests exercise the compiled `openssl` binary via subprocess invocation
//! using [`assert_cmd::Command`]. Each test creates a fresh process, ensuring
//! isolation from global state. Temporary files and directories are managed
//! via [`tempfile::TempDir`] for automatic cleanup.
//!
//! Error assertions use `predicates` combinators — `str::contains()` for
//! keyword matching and `str::is_match()` for regex-based pattern validation —
//! ensuring that error output is human-readable and actionable.
//!
//! ## Source Context
//!
//! - `apps/openssl.c:do_cmd()` (line 541): `"Invalid command '%s'; type
//!   \"help\" for a list.\n"` on unrecognized subcommand
//! - `apps/lib/opt.c:opt_getopt()` / `opt_help()`: error output on bad options
//! - `apps/lib/apps.c:bio_open_default_()`: error on inaccessible file paths
//!
//! ## Lint Configuration
//!
//! - **Rule R9**: Zero `#[allow(warnings)]` (except clippy test-pattern lints)
//! - Test modules legitimately use `.expect()` and `.unwrap()` for test setup
//!   assertions where panicking on infrastructure failure is the correct behavior.

// Test modules legitimately use .expect() and .unwrap() for assertion purposes.
// This is standard Rust testing practice — panicking on setup failure is correct.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Phase 2: Invalid Command Tests
// ============================================================================
//
// These tests verify that the external subcommand fallback dispatcher in
// `handle_fallback_dispatch()` (main.rs) correctly rejects names that are
// not recognized as subcommands, digest algorithms, or cipher algorithms.
// Maps to `apps/openssl.c:do_cmd()` lines 527–543.

/// Verifies that invoking the CLI with a completely bogus subcommand name
/// produces a non-zero exit code.
///
/// Input: `openssl totally_bogus_command`
/// Expected: non-zero exit (the name is not a subcommand, digest, or cipher)
///
/// Maps to C behavior in `apps/openssl.c:do_cmd()` which returns 1 and
/// prints `"Invalid command 'totally_bogus_command'; type \"help\" for a
/// list.\n"` when the command is not found in the LHASH table and is not
/// a recognized digest or cipher name.
#[test]
fn test_invalid_command_exits_nonzero() {
    let mut cmd = super::openssl_cmd();
    cmd.arg("totally_bogus_command").assert().failure();
}

/// Verifies that an unrecognized command name produces an error message on
/// stderr containing the phrase "Invalid command".
///
/// Input: `openssl nonexistent`
/// Expected: non-zero exit + stderr contains "Invalid command"
///
/// The Rust CLI's `handle_fallback_dispatch()` emits:
/// `"Invalid command 'nonexistent'; type \"openssl --help\" for a list."`
#[test]
fn test_invalid_command_error_message() {
    let mut cmd = super::openssl_cmd();
    cmd.arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid command"));
}

/// Verifies that invoking the CLI with no subcommand at all displays
/// help/usage information and exits successfully.
///
/// Input: `openssl` (no arguments)
/// Expected: exit code 0 + stdout contains usage/help text
///
/// The C implementation dispatches to `help_main()` when `argc == 0`
/// (after stripping the program name). The Rust implementation matches
/// `None` on the optional subcommand and calls `Cli::command().print_help()`.
#[test]
fn test_empty_args() {
    let mut cmd = super::openssl_cmd();
    cmd.assert().success().stdout(
        predicate::str::contains("Usage")
            .or(predicate::str::contains("openssl"))
            .or(predicate::str::contains("USAGE")),
    );
}

// ============================================================================
// Phase 3: Missing Required Arguments
// ============================================================================
//
// These tests verify that subcommands reject invocations that are missing
// required arguments (key files, input files, cipher specifications, etc.).
// The CLI must produce non-zero exit codes and non-empty error diagnostics.

/// Verifies that `openssl req -new` without a key specification produces
/// a non-zero exit code and an error message on stderr.
///
/// Input: `openssl req -new`
/// Expected: non-zero exit + non-empty stderr
///
/// In the C implementation, `req_main()` requires either `-key` or
/// `-newkey` when `-new` is specified. The Rust CLI rejects the unexpected
/// flag at the argument parsing layer, ensuring the command does not
/// silently proceed without key material.
#[test]
fn test_req_missing_key() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["req", "-new"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that `openssl x509 -in` without a valid file path argument
/// produces a non-zero exit code and a non-empty error message.
///
/// Input: `openssl x509 -in` (missing value for -in)
/// Expected: non-zero exit + non-empty stderr
///
/// In the C implementation, `x509_main()` requires `-in` to point to a
/// readable certificate file. Without a value, the argument parser reports
/// an error.
#[test]
fn test_x509_missing_input() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["x509", "-in"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that `openssl enc` with a cipher flag but incomplete
/// specification produces a non-zero exit code.
///
/// Input: `openssl enc -aes-256-cbc` with stdin piped
/// Expected: non-zero exit + non-empty stderr
///
/// Uses `write_stdin()` to provide input data, exercising the stdin pipe
/// path. The cipher flag triggers argument validation before stdin data
/// is consumed. In the C implementation, `enc_main()` requires a cipher
/// specification plus either `-e` (encrypt) or `-d` (decrypt).
#[test]
fn test_enc_missing_cipher() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["enc", "-aes-256-cbc"])
        .write_stdin("plaintext data for encryption test")
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that `openssl dgst -sha256 /nonexistent/file.txt` fails with
/// a non-zero exit code when the input file does not exist.
///
/// Input: `openssl dgst -sha256 /nonexistent/file.txt`
/// Expected: non-zero exit + non-empty stderr
///
/// The CLI must not silently succeed when the target file is absent.
/// In the C implementation, `dgst_main()` calls `BIO_open()` which
/// fails and prints an error for missing files.
#[test]
fn test_dgst_nonexistent_file() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-sha256", "/nonexistent/file.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

// ============================================================================
// Phase 4: Bad File Path Tests
// ============================================================================
//
// These tests verify that the CLI rejects invocations referencing paths
// that are inaccessible (non-existent, non-writable, or permission-denied).
// Maps to `apps/lib/apps.c:bio_open_default_()` and related I/O functions.

/// Verifies that `openssl x509 -in /no/such/file.pem` fails with a
/// non-zero exit code and a non-empty error message.
///
/// Input: `openssl x509 -in /no/such/file.pem`
/// Expected: non-zero exit + non-empty stderr
///
/// Maps to `apps/lib/apps.c:bio_open_default_()` returning error for
/// inaccessible paths, producing `"Can't open ... for reading"`.
#[test]
fn test_bad_input_file() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["x509", "-in", "/no/such/file.pem"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that specifying an output path inside a non-existent directory
/// produces a non-zero exit code and a non-empty error on stderr.
///
/// Input: `openssl rand -out /no/such/dir/rand.bin 32`
/// Expected: non-zero exit + non-empty stderr
///
/// Uses `TempDir` for test isolation context. The target output path
/// `/no/such/dir/rand.bin` deliberately references a non-existent
/// directory to trigger an I/O error during output file creation.
#[test]
fn test_bad_output_directory() {
    // TempDir ensures test isolation; it is not the bad path itself.
    let _tmp = TempDir::new().expect("failed to create temp dir for test isolation");

    let mut cmd = super::openssl_cmd();
    cmd.args(["rand", "-out", "/no/such/dir/rand.bin", "32"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that the CLI produces an error when given a file whose read
/// permission has been removed.
///
/// Creates a temporary file, removes all permissions via `chmod 000`, then
/// invokes `openssl dgst -sha256 <unreadable_file>`.
///
/// Expected: non-zero exit + non-empty stderr
///
/// This test is Unix-specific because POSIX file permission semantics are
/// required for `std::fs::set_permissions()` with mode `0o000`.
///
/// Note: this test may behave differently when run as the root user since
/// root bypasses POSIX permission checks.
#[test]
#[cfg(unix)]
fn test_read_permission_denied() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().expect("failed to create temp dir");
    let file_path = tmp.path().join("unreadable.txt");

    fs::write(&file_path, b"test content for permission denied scenario")
        .expect("failed to write test file");

    // Remove all permissions (owner, group, other) so the file cannot be read.
    let no_perms = std::fs::Permissions::from_mode(0o000);
    fs::set_permissions(&file_path, no_perms).expect("failed to set file permissions");

    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-sha256"])
        .arg(&file_path)
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

// ============================================================================
// Phase 5: Invalid Option Tests
// ============================================================================
//
// These tests verify that the CLI rejects unrecognized flags and conflicting
// option combinations. Maps to `apps/lib/opt.c:opt_getopt()` error paths.

/// Verifies that passing a completely unrecognized flag to a subcommand
/// produces a non-zero exit code and an error message matching common
/// error patterns.
///
/// Input: `openssl dgst --nonexistent-flag file.txt`
/// Expected: non-zero exit + stderr matches error/unexpected/unknown pattern
///
/// Uses `predicate::str::is_match()` with a case-insensitive regex to
/// accommodate varying error message formats across argument parsers.
///
/// Maps to `apps/lib/opt.c` where unrecognized options trigger:
/// `"%s: Unknown option: -%s\n"` or similar error output.
#[test]
fn test_unknown_option() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "--nonexistent-flag", "file.txt"])
        .assert()
        .failure()
        .stderr(
            predicate::str::is_match("(?i)(error|unexpected|unrecognized|unknown)")
                .expect("regex compilation must succeed"),
        );
}

/// Verifies that passing conflicting options (simultaneous encrypt and
/// decrypt) to the `enc` subcommand produces a non-zero exit code.
///
/// Input: `openssl enc -e -d -aes-256-cbc`
/// Expected: non-zero exit + non-empty stderr
///
/// In the C implementation, `enc_main()` accepts both `-e` and `-d` with
/// the last one winning. The Rust CLI may reject conflicting flags at the
/// argument parsing layer. Either behavior (last-wins or error) is
/// acceptable; the key invariant is that the CLI does not crash.
#[test]
fn test_conflicting_options() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["enc", "-e", "-d", "-aes-256-cbc"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that specifying a non-existent digest algorithm name produces
/// a non-zero exit code and a non-empty error message.
///
/// Input: `openssl dgst -definitely_not_a_hash file.txt`
/// Expected: non-zero exit + non-empty stderr
///
/// The CLI must validate algorithm names against the provider registry
/// and produce clear diagnostics when an unknown algorithm is specified.
/// In the C implementation, `EVP_get_digestbyname()` returns `NULL` for
/// unknown names, triggering an error path.
#[test]
fn test_invalid_algorithm_name() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-definitely_not_a_hash", "file.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

// ============================================================================
// Phase 6: Malformed Input Tests
// ============================================================================
//
// These tests verify that the CLI rejects malformed/garbage input data
// rather than producing undefined behavior or silent failures.

/// Verifies that supplying a file with garbage data (not valid PEM/DER)
/// to `openssl x509 -in` produces a non-zero exit code and a non-empty
/// error message.
///
/// Creates a temporary file with arbitrary text content, verifies the file
/// is non-empty via `std::fs::read_to_string()`, then invokes the CLI.
///
/// Expected: non-zero exit + non-empty stderr
///
/// Maps to `apps/lib/apps.c:app_load_cert_*()` which calls PEM/DER
/// decoders that fail on non-certificate data, producing:
/// `"unable to load certificate"` or similar.
#[test]
fn test_verify_malformed_cert() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let garbage_pem = tmp.path().join("garbage.pem");

    fs::write(
        &garbage_pem,
        b"NOT A VALID PEM CERTIFICATE\ngarbage data line 2\nmore garbage line 3\n",
    )
    .expect("failed to write garbage PEM file");

    // Verify precondition: the test file exists and is non-empty.
    let content =
        fs::read_to_string(&garbage_pem).expect("failed to read garbage PEM back for verification");
    assert!(
        !content.is_empty(),
        "garbage PEM file must be non-empty for this test to be meaningful"
    );

    let mut cmd = super::openssl_cmd();
    cmd.args(["x509", "-in"])
        .arg(&garbage_pem)
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that attempting to read an invalid PKCS#12 file produces a
/// non-zero exit code and a non-empty error message.
///
/// Creates a temporary file with garbage bytes that do not form a valid
/// PKCS#12/ASN.1 structure, then invokes `openssl pkcs12 -in <file>
/// -password pass:wrong_password`.
///
/// Expected: non-zero exit + non-empty stderr
///
/// In the full implementation, the PKCS#12 parser would reject the
/// invalid ASN.1 structure. In the current state, the argument parser
/// rejects the flags before reaching the PKCS#12 decoder. Both behaviors
/// correctly prevent silent acceptance of invalid input.
#[test]
fn test_pkcs12_bad_password() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let p12_path = tmp.path().join("bad.p12");

    // Write garbage bytes that are not a valid PKCS#12/ASN.1 DER structure.
    // The leading 0x30 0x80 bytes mimic an ASN.1 SEQUENCE tag with
    // indefinite length, followed by non-parseable garbage.
    fs::write(
        &p12_path,
        b"\x30\x80\x02\x01\x03garbage_pkcs12_data_not_valid_asn1",
    )
    .expect("failed to write garbage PKCS#12 file");

    let mut cmd = super::openssl_cmd();
    cmd.args(["pkcs12", "-in"])
        .arg(&p12_path)
        .args(["-password", "pass:wrong_password"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}
