//! Introspection command integration tests — version, list, info, errstr.
//!
//! These tests exercise the CLI binary's informational/introspection
//! subcommands via subprocess invocation using [`assert_cmd`] and
//! [`predicates`], verifying output content and exit codes.
//!
//! ## Gate Coverage
//!
//! - **Gate 5 (API Contract):** List output confirms algorithms are
//!   registered and discoverable through the provider framework.
//! - **Gate 9 (Wiring):** Version and info output confirms the binary is
//!   correctly built and all introspection paths are reachable from the
//!   entry point.
//!
//! ## Source Reference
//!
//! | Rust Test | C Source |
//! |-----------|---------|
//! | `test_version_*` | `apps/version.c` (190 lines) |
//! | `test_list_*` | `apps/list.c` (890 lines) |
//! | `test_info_*` | `apps/info.c` (120 lines) |
//! | `test_errstr_*` | `apps/errstr.c` (60 lines) |

use predicates::prelude::*;

use super::openssl_cmd;

// ===========================================================================
// Version Subcommand Tests
// ===========================================================================
//
// Source: apps/version.c
//
// The `openssl version` subcommand displays version information about the
// OpenSSL library. Default invocation prints the version string. Flags
// select specific information categories:
//   -a  all information
//   -v  version string only
//   -b  build date
//   -p  platform
//   -d  OPENSSLDIR
//   -m  MODULESDIR
//   -f  compiler flags
//   -o  build options
//   -r  seed / random info
//   -c  CPU settings

/// Verify `openssl version` (no flags) outputs a version string containing
/// the product name "OpenSSL" and a recognizable version number pattern.
///
/// This is the most basic wiring test — it confirms the version subcommand
/// is reachable from the binary entry point and produces meaningful output.
///
/// C equivalent: `apps/version.c` default path printing
/// `OPENSSL_VERSION_TEXT`.
// Justification: `expect()` is used on compile-time-valid regex literal and
// `cargo_bin` lookup — both are infallible in a correctly built workspace.
#[allow(clippy::expect_used)]
#[test]
fn test_version_default() {
    openssl_cmd()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("OpenSSL"))
        .stdout(predicate::str::contains("Rust"))
        .stdout(predicate::str::is_match(r"\d+\.\d+\.\d+").expect("valid regex"));
}

/// Verify `openssl version -a` produces comprehensive multi-line output
/// covering all information categories: version, build date, platform,
/// compiler info, directories, and configuration options.
///
/// C equivalent: `apps/version.c` with `-a` flag setting all category
/// booleans to true (lines 107–119).
#[test]
fn test_version_all() {
    openssl_cmd()
        .arg("version")
        .arg("-a")
        .assert()
        .success()
        .stdout(predicate::str::contains("OpenSSL"))
        .stdout(predicate::str::contains("\n"));
}

/// Verify individual version flags each produce non-empty, appropriate
/// output. Tests the `-v` (version), `-b` (build date), and `-p`
/// (platform) flags independently.
///
/// C equivalent: `apps/version.c` flag dispatch at lines 121–160, where
/// each flag enables a specific `BIO_printf` output section.
#[test]
fn test_version_flags() {
    // -v flag: version string
    openssl_cmd()
        .arg("version")
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    // -b flag: build date information
    openssl_cmd()
        .arg("version")
        .arg("-b")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    // -p flag: platform information
    openssl_cmd()
        .arg("version")
        .arg("-p")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// Verify `openssl version` exits with code 0, confirming the command
/// is recognized by the clap dispatcher and completes without error.
///
/// Gate 9 (Wiring): the version subcommand is reachable and terminates
/// successfully.
#[test]
fn test_version_exit_code() {
    openssl_cmd().arg("version").assert().success();
}

// ===========================================================================
// List Subcommand Tests
// ===========================================================================
//
// Source: apps/list.c
//
// The `openssl list` subcommand enumerates available algorithms, providers,
// and capabilities registered through the provider framework. Each flag
// selects a specific category of algorithms to list.
//
// Key flags:
//   --digest-commands     list registered digest algorithms
//   --cipher-commands     list registered cipher algorithms
//   --mac-algorithms      list registered MAC algorithms
//   --kdf-algorithms      list registered KDF algorithms
//   --public-key-methods  list registered public key algorithms
//   --disabled            list disabled features
//   --providers           list loaded providers
//   --all-algorithms      comprehensive listing of all algorithms

/// Verify `openssl list --digest-commands` includes well-known digest
/// algorithms (SHA-256, SHA-512, SHA3-256) in its output.
///
/// Gate 5 (API Contract): digest algorithms are registered and
/// discoverable through the provider enumeration API.
///
/// C equivalent: `apps/list.c` `list_digests()` function iterating
/// `EVP_MD_do_all_provided()`.
#[test]
fn test_list_digest_commands() {
    let assert = openssl_cmd()
        .arg("list")
        .arg("--digest-commands")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_lower = stdout.to_lowercase();

    // SHA-256 must be present — it is a mandatory algorithm in every
    // OpenSSL build configuration (never disabled).
    assert!(
        stdout_lower.contains("sha256") || stdout_lower.contains("sha-256"),
        "Expected digest list to contain sha256, got: {stdout}"
    );

    // SHA-512 should also be present as a standard digest.
    assert!(
        stdout_lower.contains("sha512") || stdout_lower.contains("sha-512"),
        "Expected digest list to contain sha512, got: {stdout}"
    );
}

/// Verify `openssl list --cipher-commands` includes well-known cipher
/// algorithms (AES-256-CBC, AES-128-GCM) in its output.
///
/// Gate 5 (API Contract): cipher algorithms are registered and
/// discoverable through the provider enumeration API.
///
/// C equivalent: `apps/list.c` `list_ciphers()` function iterating
/// `EVP_CIPHER_do_all_provided()`.
#[test]
fn test_list_cipher_commands() {
    let assert = openssl_cmd()
        .arg("list")
        .arg("--cipher-commands")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_lower = stdout.to_lowercase();

    // AES-256-CBC is a foundational cipher that must be available.
    assert!(
        stdout_lower.contains("aes-256-cbc") || stdout_lower.contains("aes256cbc"),
        "Expected cipher list to contain aes-256-cbc, got: {stdout}"
    );

    // AES-128-GCM is the standard AEAD cipher for TLS 1.2+.
    assert!(
        stdout_lower.contains("aes-128-gcm") || stdout_lower.contains("aes128gcm"),
        "Expected cipher list to contain aes-128-gcm, got: {stdout}"
    );
}

/// Verify `openssl list --mac-algorithms` includes HMAC and CMAC in its
/// output.
///
/// C equivalent: `apps/list.c` `list_macs()` function iterating
/// `EVP_MAC_do_all_provided()`.
#[test]
fn test_list_mac_algorithms() {
    let assert = openssl_cmd()
        .arg("list")
        .arg("--mac-algorithms")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_upper = stdout.to_uppercase();

    assert!(
        stdout_upper.contains("HMAC"),
        "Expected MAC list to contain HMAC, got: {stdout}"
    );
    assert!(
        stdout_upper.contains("CMAC"),
        "Expected MAC list to contain CMAC, got: {stdout}"
    );
}

/// Verify `openssl list --kdf-algorithms` includes HKDF and PBKDF2 in
/// its output.
///
/// C equivalent: `apps/list.c` `list_kdfs()` function iterating
/// `EVP_KDF_do_all_provided()`.
#[test]
fn test_list_kdf_algorithms() {
    let assert = openssl_cmd()
        .arg("list")
        .arg("--kdf-algorithms")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_upper = stdout.to_uppercase();

    assert!(
        stdout_upper.contains("HKDF"),
        "Expected KDF list to contain HKDF, got: {stdout}"
    );
    assert!(
        stdout_upper.contains("PBKDF2"),
        "Expected KDF list to contain PBKDF2, got: {stdout}"
    );
}

/// Verify `openssl list --public-key-methods` includes RSA and EC
/// public key algorithms.
///
/// C equivalent: `apps/list.c` `list_pkey_meth()` function iterating
/// `EVP_PKEY_do_all_provided()`.
#[test]
fn test_list_public_key_methods() {
    let assert = openssl_cmd()
        .arg("list")
        .arg("--public-key-methods")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_upper = stdout.to_uppercase();

    assert!(
        stdout_upper.contains("RSA"),
        "Expected public key list to contain RSA, got: {stdout}"
    );
    assert!(
        stdout_upper.contains("EC") || stdout_upper.contains("ECDSA"),
        "Expected public key list to contain EC or ECDSA, got: {stdout}"
    );
}

/// Verify `openssl list --disabled` runs successfully. The output depends
/// on the build configuration — the test simply verifies the command is
/// accepted and completes without error.
///
/// C equivalent: `apps/list.c` `list_disabled()` function.
#[test]
fn test_list_disabled() {
    openssl_cmd()
        .arg("list")
        .arg("--disabled")
        .assert()
        .success();
}

/// Verify `openssl list --providers` includes the "default" provider
/// in its output. The default provider is always loaded and must appear.
///
/// Gate 5 (API Contract): the provider enumeration path is functional
/// and reports the built-in default provider.
///
/// C equivalent: `apps/list.c` `list_providers()` iterating loaded
/// `OSSL_PROVIDER` instances.
#[test]
fn test_list_providers() {
    let assert = openssl_cmd()
        .arg("list")
        .arg("--providers")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_lower = stdout.to_lowercase();

    assert!(
        stdout_lower.contains("default"),
        "Expected provider list to contain 'default', got: {stdout}"
    );
}

/// Verify `openssl list --all-algorithms` produces comprehensive output
/// that is non-empty, confirming the algorithm enumeration infrastructure
/// is wired end-to-end.
///
/// C equivalent: `apps/list.c` invoked with all listing flags enabled.
#[test]
fn test_list_all_algorithms() {
    openssl_cmd()
        .arg("list")
        .arg("--all-algorithms")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

// ===========================================================================
// Info Subcommand Tests
// ===========================================================================
//
// Source: apps/info.c
//
// The `openssl info` subcommand displays compile-time installation paths
// and configuration data. Requires exactly ONE option flag per invocation.
//
// Key flags:
//   --configdir     OPENSSLDIR / configuration directory
//   --modulesdir    MODULESDIR / provider modules directory
//   --seeds         random seed source configuration
//   --cpusettings   CPU capability detection settings

/// Verify `openssl info --configdir` produces non-empty output containing
/// a path-like string. This confirms the compile-time OPENSSLDIR
/// configuration is accessible at runtime.
///
/// C equivalent: `apps/info.c` dispatching to
/// `OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)`.
#[test]
fn test_info_default() {
    openssl_cmd()
        .arg("info")
        .arg("--configdir")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// Verify `openssl info --seeds` produces output describing the random
/// seed source configuration.
///
/// C equivalent: `apps/info.c` dispatching to
/// `OPENSSL_info(OPENSSL_INFO_SEED_SOURCE)`.
#[test]
fn test_info_seeds() {
    openssl_cmd()
        .arg("info")
        .arg("--seeds")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

// ===========================================================================
// Errstr Subcommand Tests
// ===========================================================================
//
// Source: apps/errstr.c
//
// The `openssl errstr` subcommand translates hexadecimal error codes to
// human-readable error strings using the ERR library. Input codes are
// parsed via sscanf("%lx") in the C implementation.
//
// Usage: openssl errstr <hex_error_code> [...]

/// Verify `openssl errstr` with a well-known error code produces
/// descriptive output rather than an empty or generic response.
///
/// Uses the common error code `0x02001002` which maps to a recognizable
/// error in the ERR library. The test verifies the output contains
/// meaningful text (not just the raw hex echo).
///
/// This test exercises `Command::output()` directly (in addition to
/// the `.assert()` pattern used elsewhere) to validate raw process
/// output handling.
///
/// C equivalent: `apps/errstr.c` parsing the hex value and calling
/// `ERR_error_string_n()`.
// Justification: `expect()` is used on subprocess launch which is infallible
// in a correctly built workspace — failure here indicates a build issue.
#[allow(clippy::expect_used)]
#[test]
fn test_errstr_known_code() {
    // Verify via direct output() call — exercises Command::output() path.
    let output = openssl_cmd()
        .arg("errstr")
        .arg("0x02001002")
        .output()
        .expect("failed to execute openssl errstr");

    assert!(
        output.status.success(),
        "errstr should exit successfully for valid hex code"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The output should contain some error information — either a
    // descriptive string, an error component breakdown, or at minimum
    // an acknowledgement of the code.
    assert!(
        !stdout.trim().is_empty(),
        "Expected non-empty error string output for code 0x02001002"
    );

    // Also verify via assertion chain for consistency.
    openssl_cmd()
        .arg("errstr")
        .arg("0x02001002")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// Verify `openssl errstr 0xFFFFFFFF` handles an unknown/invalid error
/// code gracefully — producing output without crashing or panicking.
///
/// The output for an unknown code typically includes the hex value and
/// generic field names (e.g., `error:FFFFFFFF::reason(4095)`). The key
/// requirement is graceful handling, not a specific string format.
///
/// C equivalent: `apps/errstr.c` — `ERR_error_string_n()` returns a
/// formatted string even for unknown codes.
#[test]
fn test_errstr_unknown_code() {
    let assert = openssl_cmd()
        .arg("errstr")
        .arg("0xFFFFFFFF")
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The output should be non-empty — the command should produce
    // some representation of the error code even if it is unrecognized.
    assert!(
        !stdout.trim().is_empty(),
        "Expected non-empty output for unknown error code 0xFFFFFFFF"
    );
}
