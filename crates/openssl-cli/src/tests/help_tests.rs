//! Help output snapshot tests for the OpenSSL CLI binary.
//!
//! Tests `--help` output of the top-level command and critical subcommands
//! using the `insta` crate for snapshot-based regression detection. Ensures
//! help text is stable, complete, and well-structured across releases.
//!
//! ## Compliance
//!
//! - **Gate 5 (API Contract)**: CLI interface documentation is consistent and
//!   verified against stored snapshots
//! - **Rule R8**: Zero `unsafe` blocks in this file
//! - **Rule R9**: Zero `#[allow(warnings)]` (except clippy test-pattern lints)
//!
//! ## Source Context
//!
//! - `apps/openssl.c`: `help_main()` lists all commands grouped by category
//! - `apps/lib/opt.c`: `opt_help()` prints per-command help based on OPTIONS table
//! - Rust CLI: `openssl --help`, `openssl <command> --help` (clap convention)
//!
//! ## Snapshot Management
//!
//! Snapshot files are stored in `crates/openssl-cli/src/tests/snapshots/`.
//! - First run: creates `.snap.new` files; accept with `cargo insta review`
//!   or run with `INSTA_UPDATE=always` to auto-accept
//! - Subsequent runs: compares output against stored snapshots
//! - Regressions: detected automatically when help text changes unintentionally
//!
//! ## Caller Chain (Rule R10)
//!
//! ```text
//! main() → Cli::parse() → clap --help handler → stdout
//! main() → Cli::parse() → match CliCommand variant → clap --help handler → stdout
//! ```

// Test modules legitimately use .expect() and .unwrap() for assertion purposes.
// These are the standard Rust testing patterns and are not production code paths.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use predicates::prelude::*;

// ===========================================================================
// Helper
// ===========================================================================

/// Captures stdout from running `openssl` with the given arguments.
///
/// Returns the stdout output as a trimmed `String`. Panics if the process
/// fails to execute or if stdout is not valid UTF-8.
fn capture_help_stdout(args: &[&str]) -> String {
    let output = super::openssl_cmd()
        .args(args)
        .output()
        .expect("failed to execute openssl process");

    String::from_utf8(output.stdout).expect("stdout is not valid UTF-8")
}

/// Captures stdout from running `openssl <subcommand> --help`.
///
/// Convenience wrapper around `capture_help_stdout` for subcommand help.
fn capture_subcommand_help(subcommand: &str) -> String {
    capture_help_stdout(&[subcommand, "--help"])
}

// ===========================================================================
// Phase 2: Top-Level Help Tests
// ===========================================================================

/// Captures the top-level `openssl --help` output and validates it against
/// a stored snapshot for regression detection.
///
/// This test ensures that the overall CLI help structure remains stable across
/// code changes. Any modification to the help text (added/removed subcommands,
/// changed descriptions) will cause a snapshot mismatch requiring explicit
/// review via `cargo insta review`.
#[test]
fn test_top_level_help() {
    let stdout = capture_help_stdout(&["--help"]);

    // Snapshot the complete help output. When the version string in
    // Cargo.toml changes, update snapshots with `cargo insta review`.
    insta::assert_snapshot!("top_level_help", stdout);
}

/// Verifies that the top-level help output contains all critical subcommand names.
///
/// These subcommands represent the core CLI surface area that users depend on.
/// Missing any of these from the help output indicates a regression in command
/// registration.
///
/// Checked subcommands: req, x509, ca, enc, dgst, `s_client`, `s_server`, version, list.
#[test]
fn test_top_level_help_contains_subcommands() {
    super::openssl_cmd()
        .arg("--help")
        .assert()
        .success()
        // Core PKI commands
        .stdout(predicate::str::contains("req"))
        .stdout(predicate::str::contains("x509"))
        .stdout(predicate::str::contains("ca"))
        // Crypto operation commands
        .stdout(predicate::str::contains("enc"))
        .stdout(predicate::str::contains("dgst"))
        // TLS diagnostic commands
        .stdout(predicate::str::contains("s_client"))
        .stdout(predicate::str::contains("s_server"))
        // Introspection commands
        .stdout(predicate::str::contains("version"))
        .stdout(predicate::str::contains("list"));
}

/// Verifies that the top-level help output includes commands from all major
/// functional categories, confirming complete CLI surface area coverage.
///
/// The C `help_main()` in `apps/openssl.c` groups commands by category
/// (Standard, Message Digest, Cipher). The Rust CLI organizes subcommands
/// in the `CliCommand` enum with semantic grouping. This test verifies
/// that representative commands from each functional area are present.
///
/// Categories checked:
/// - **PKI**: req, x509, ca, verify, crl
/// - **Key Generation**: genpkey, genrsa
/// - **Crypto Operations**: enc, dgst, rand, pkcs12
/// - **TLS/Network**: `s_client`, `s_server`, ciphers
/// - **Introspection**: version, list, speed
/// - **Utilities**: rehash, asn1parse
#[test]
fn test_top_level_help_categorized() {
    let stdout = capture_help_stdout(&["--help"]);

    // PKI commands
    assert!(
        stdout.contains("req"),
        "help output missing PKI command 'req'"
    );
    assert!(
        stdout.contains("x509"),
        "help output missing PKI command 'x509'"
    );
    assert!(
        stdout.contains("ca"),
        "help output missing PKI command 'ca'"
    );
    assert!(
        stdout.contains("verify"),
        "help output missing PKI command 'verify'"
    );
    assert!(
        stdout.contains("crl"),
        "help output missing PKI command 'crl'"
    );

    // Key generation commands
    assert!(
        stdout.contains("genpkey"),
        "help output missing key generation command 'genpkey'"
    );
    assert!(
        stdout.contains("genrsa"),
        "help output missing key generation command 'genrsa'"
    );

    // Crypto operation commands
    assert!(
        stdout.contains("enc"),
        "help output missing crypto command 'enc'"
    );
    assert!(
        stdout.contains("dgst"),
        "help output missing crypto command 'dgst'"
    );
    assert!(
        stdout.contains("rand"),
        "help output missing crypto command 'rand'"
    );
    assert!(
        stdout.contains("pkcs12"),
        "help output missing crypto command 'pkcs12'"
    );

    // TLS/network commands
    assert!(
        stdout.contains("s_client"),
        "help output missing TLS command 's_client'"
    );
    assert!(
        stdout.contains("s_server"),
        "help output missing TLS command 's_server'"
    );
    assert!(
        stdout.contains("ciphers"),
        "help output missing TLS command 'ciphers'"
    );

    // Introspection commands
    assert!(
        stdout.contains("version"),
        "help output missing introspection command 'version'"
    );
    assert!(
        stdout.contains("list"),
        "help output missing introspection command 'list'"
    );
    assert!(
        stdout.contains("speed"),
        "help output missing introspection command 'speed'"
    );

    // Utility commands
    assert!(
        stdout.contains("rehash"),
        "help output missing utility command 'rehash'"
    );
    assert!(
        stdout.contains("asn1parse"),
        "help output missing utility command 'asn1parse'"
    );
}

// ===========================================================================
// Phase 3: Subcommand Help Snapshot Tests
// ===========================================================================

/// Snapshot test for `openssl req --help`.
///
/// The `req` command handles certificate signing request (CSR) operations,
/// corresponding to `apps/req.c` in the C codebase.
#[test]
fn test_help_req() {
    let stdout = capture_subcommand_help("req");
    insta::assert_snapshot!("help_req", stdout);
}

/// Snapshot test for `openssl x509 --help`.
///
/// The `x509` command handles certificate display, signing, and conversion,
/// corresponding to `apps/x509.c` in the C codebase.
#[test]
fn test_help_x509() {
    let stdout = capture_subcommand_help("x509");
    insta::assert_snapshot!("help_x509", stdout);
}

/// Snapshot test for `openssl ca --help`.
///
/// The `ca` command handles certificate authority management,
/// corresponding to `apps/ca.c` in the C codebase.
#[test]
fn test_help_ca() {
    let stdout = capture_subcommand_help("ca");
    insta::assert_snapshot!("help_ca", stdout);
}

/// Snapshot test for `openssl enc --help`.
///
/// The `enc` command handles symmetric cipher encryption and decryption,
/// corresponding to `apps/enc.c` in the C codebase.
#[test]
fn test_help_enc() {
    let stdout = capture_subcommand_help("enc");
    insta::assert_snapshot!("help_enc", stdout);
}

/// Snapshot test for `openssl dgst --help`.
///
/// The `dgst` command handles message digest computation and verification,
/// corresponding to `apps/dgst.c` in the C codebase.
#[test]
fn test_help_dgst() {
    let stdout = capture_subcommand_help("dgst");
    insta::assert_snapshot!("help_dgst", stdout);
}

/// Snapshot test for `openssl genpkey --help`.
///
/// The `genpkey` command generates private keys (algorithm-generic),
/// corresponding to `apps/genpkey.c` in the C codebase.
#[test]
fn test_help_genpkey() {
    let stdout = capture_subcommand_help("genpkey");
    insta::assert_snapshot!("help_genpkey", stdout);
}

/// Snapshot test for `openssl s_client --help`.
///
/// The `s_client` command is the TLS/SSL client diagnostic tool,
/// corresponding to `apps/s_client.c` in the C codebase. The Rust CLI
/// uses `s_client` (underscore) as the subcommand name per clap convention.
#[test]
fn test_help_s_client() {
    let stdout = capture_subcommand_help("s_client");
    insta::assert_snapshot!("help_s_client", stdout);
}

/// Snapshot test for `openssl version --help`.
///
/// The `version` command displays version information,
/// corresponding to `apps/version.c` in the C codebase.
#[test]
fn test_help_version() {
    let stdout = capture_subcommand_help("version");
    insta::assert_snapshot!("help_version", stdout);
}

/// Snapshot test for `openssl list --help`.
///
/// The `list` command provides algorithm, provider, and capability listing,
/// corresponding to `apps/list.c` in the C codebase.
#[test]
fn test_help_list() {
    let stdout = capture_subcommand_help("list");
    insta::assert_snapshot!("help_list", stdout);
}

/// Snapshot test for `openssl rand --help`.
///
/// The `rand` command generates random byte output,
/// corresponding to `apps/rand.c` in the C codebase.
#[test]
fn test_help_rand() {
    let stdout = capture_subcommand_help("rand");
    insta::assert_snapshot!("help_rand", stdout);
}

// ===========================================================================
// Phase 4: Help Output Quality Tests
// ===========================================================================

/// Verifies that each critical subcommand's `--help` output contains a
/// "Usage:" line, confirming clap generates well-formed help text.
///
/// Clap outputs `Usage:` (capitalized) by default. This test validates
/// the structural quality of help output across all major subcommands.
#[test]
fn test_help_includes_usage_line() {
    let subcommands = [
        "req", "x509", "ca", "enc", "dgst", "genpkey", "s_client", "s_server", "version", "list",
        "rand", "verify", "crl",
    ];

    for subcmd in &subcommands {
        let stdout = capture_subcommand_help(subcmd);
        assert!(
            stdout.contains("Usage:") || stdout.contains("USAGE:"),
            "'{subcmd} --help' output missing 'Usage:' line. Got:\n{stdout}"
        );
    }
}

/// Verifies that each critical subcommand's `--help` output lists at least
/// one option flag (at minimum the `-h, --help` flag from clap).
///
/// This ensures clap's automatic help flag generation is active for every
/// registered subcommand and that help text includes actionable option
/// information.
#[test]
fn test_help_includes_options() {
    let subcommands = [
        "req", "x509", "ca", "enc", "dgst", "genpkey", "s_client", "s_server", "version", "list",
        "rand", "verify", "crl",
    ];

    for subcmd in &subcommands {
        let stdout = capture_subcommand_help(subcmd);
        // Clap always includes at minimum: -h, --help  Print help
        assert!(
            stdout.contains("--help") || stdout.contains("-h"),
            "'{subcmd} --help' output missing option flags. Got:\n{stdout}"
        );
    }
}

/// Verifies that `--help` always returns exit code 0 for the top-level
/// command and all critical subcommands.
///
/// The `--help` flag is a non-error invocation and must exit successfully.
/// A non-zero exit code from `--help` would break tooling that relies on
/// help output for auto-completion or documentation generation.
#[test]
fn test_help_exit_code_zero() {
    // Top-level help
    super::openssl_cmd().arg("--help").assert().success();

    // Subcommand help for all critical commands
    let subcommands = [
        "req",
        "x509",
        "ca",
        "enc",
        "dgst",
        "genpkey",
        "s_client",
        "s_server",
        "version",
        "list",
        "rand",
        "verify",
        "crl",
        "pkey",
        "genrsa",
        "gendsa",
        "dhparam",
        "pkcs12",
        "pkcs7",
        "pkcs8",
        "prime",
        "rehash",
        "asn1parse",
        "speed",
        "info",
        "errstr",
        "ciphers",
    ];

    for subcmd in &subcommands {
        super::openssl_cmd()
            .arg(subcmd)
            .arg("--help")
            .assert()
            .success();
    }
}

// ===========================================================================
// Additional Help Robustness Tests
// ===========================================================================

/// Verifies that the top-level `--help` includes the binary name "openssl"
/// in the usage line, confirming correct program name propagation.
#[test]
fn test_help_shows_program_name() {
    super::openssl_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("openssl"));
}

/// Verifies that the top-level `--help` includes the `help` subcommand
/// itself, which clap adds automatically to list available subcommands.
#[test]
fn test_help_includes_help_subcommand() {
    super::openssl_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("help"));
}

/// Verifies that the short help flag `-h` produces the same successful
/// exit code as `--help` for both top-level and subcommand invocations.
#[test]
fn test_short_help_flag() {
    // Top-level short help
    super::openssl_cmd().arg("-h").assert().success();

    // Subcommand short help
    super::openssl_cmd()
        .arg("version")
        .arg("-h")
        .assert()
        .success();
}

/// Verifies that the top-level help output contains the about text
/// from the clap configuration, ensuring the description is present.
#[test]
fn test_help_contains_about_text() {
    super::openssl_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("OpenSSL command-line tool"));
}
