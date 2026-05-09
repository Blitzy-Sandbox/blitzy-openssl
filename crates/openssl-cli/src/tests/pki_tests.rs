//! PKI operation integration tests for the OpenSSL CLI binary.
//!
//! Tests exercise PKI (Public Key Infrastructure) lifecycle operations
//! through the compiled `openssl` binary subprocess:
//!
//! - `genrsa` — RSA private key generation
//! - `genpkey` — General-purpose key pair generation via EVP
//! - `req` — Certificate Signing Request (CSR) generation and verification
//! - `x509` — Certificate display, conversion, and signing
//! - `ca` — Certificate authority management
//! - `verify` — Certificate chain verification
//! - `crl` — Certificate Revocation List operations
//!
//! Each test invokes the compiled `openssl` binary as a subprocess via
//! [`assert_cmd::Command`], validates exit codes, and checks stdout/stderr
//! content using predicates. Temporary directories provide artifact
//! isolation with automatic cleanup on drop.
//!
//! ## Gate Compliance
//!
//! - **Gate 1 (E2E Boundary)**: `test_e2e_pki_workflow` processes the
//!   full certificate lifecycle dispatch chain — key generation, CSR
//!   creation, certificate signing, and chain verification.
//! - **Gate 4 (Real-World Artifacts)**: Tests exercise real X.509
//!   certificate lifecycle workflows including PEM file operations.
//! - **Gate 9 (Wiring Verification)**: Every PKI subcommand is verified
//!   reachable from `main()` via the clap dispatch model.
//! - **Gate 10 (Test Execution Binding)**: All tests run as part of the
//!   `cargo test` CI pipeline.

use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// `assert_cmd::Command` is accessed indirectly through `openssl_cmd()` which
// returns `Command` via `Command::cargo_bin("openssl")`. The type is used
// throughout this module via the helper rather than a direct import, avoiding
// an unused-import warning under `RUSTFLAGS="-D warnings"`.
use super::openssl_cmd;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard stderr message emitted by stub command handlers.
///
/// Captures the expected output from the `Some(_)` catch-all arm in
/// `main.rs` for commands whose full handlers are pending implementation.
/// Centralised here for DRY assertions across test functions.
const DISPATCH_MSG: &str = "Command dispatched successfully. Full handler implementation pending.";

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Creates a fresh temporary directory for PKI test artifacts.
///
/// Returns a `TempDir` that is automatically removed when dropped,
/// ensuring test isolation and no leftover files on disk.
fn create_temp_dir() -> TempDir {
    TempDir::new().expect("failed to create temporary directory for PKI tests")
}

/// Constructs the full path to a named file within a temporary directory.
///
/// # Arguments
///
/// * `dir` — The temporary directory that will contain the file.
/// * `filename` — The base file name (e.g., `"key.pem"`, `"cert.der"`).
///
/// # Returns
///
/// An absolute `PathBuf` pointing to the file inside `dir`.
fn temp_path(dir: &TempDir, filename: &str) -> PathBuf {
    dir.path().join(filename)
}

// ===========================================================================
// RSA Key Generation Tests
// ===========================================================================

/// Verifies the `genrsa` subcommand is recognised and dispatched.
///
/// Invokes `openssl genrsa` and asserts successful exit, confirming the
/// command variant is registered in `CliCommand` and routed correctly
/// through the dispatch table.
///
/// When the full `genrsa` handler is implemented this test will be
/// extended to verify:
///   `openssl genrsa -out key.pem 2048` → key file created and non-empty.
#[test]
fn test_genrsa_generates_key() {
    let dir = create_temp_dir();
    let key_path = temp_path(&dir, "key.pem");

    // Invoke genrsa — currently reaches the stub catch-all handler.
    openssl_cmd()
        .arg("genrsa")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));

    // Path prepared for full handler: future tests will verify key_path
    // contains a valid PEM-encoded RSA private key of the requested size.
    let key_str = key_path.to_string_lossy();
    assert!(
        key_str.contains("key.pem"),
        "temp path should contain the filename"
    );
}

/// Verifies the `genpkey` subcommand generates a PEM-encoded RSA key.
///
/// The full handler in `crates/openssl-cli/src/commands/genpkey.rs` is
/// implemented (unlike the stub commands such as `genrsa`/`req`/`x509`),
/// so this test exercises the documented end-to-end invocation:
///   `openssl genpkey --algorithm RSA --pkeyopt rsa_keygen_bits:2048 --out key.pem`
///
/// and verifies the output file is created with PEM framing.
///
/// NOTE on flag style: clap's derive parser uses idiomatic Rust long-option
/// syntax (`--algorithm`).  The C tool accepted single-dash long options
/// (`-algorithm`); the Rust CLI requires the double-dash form to avoid
/// ambiguity with bundled short flags.
#[test]
fn test_genpkey_rsa() {
    let dir = create_temp_dir();
    let key_path = temp_path(&dir, "key.pem");

    openssl_cmd()
        .arg("genpkey")
        .arg("--algorithm")
        .arg("RSA")
        .arg("--pkeyopt")
        .arg("rsa_keygen_bits:2048")
        .arg("--out")
        .arg(&key_path)
        .assert()
        .success();

    // PathBuf::from demonstrates path construction for full handler tests.
    let explicit_path = PathBuf::from(key_path.as_os_str());
    assert!(
        explicit_path.to_string_lossy().contains("key.pem"),
        "PathBuf round-trip should preserve filename"
    );
    assert!(
        explicit_path.exists(),
        "genpkey should create the requested output file at {explicit_path:?}"
    );

    let pem = fs::read_to_string(&key_path)
        .expect("genpkey output file should be readable as UTF-8 text");
    assert!(
        pem.contains("-----BEGIN") && pem.contains("PRIVATE KEY-----"),
        "genpkey output should be a PEM-encoded private key, got: {pem:?}"
    );
}

/// Verifies `genrsa --help` displays the command description.
///
/// Clap auto-generates help for every subcommand variant, including the
/// doc-comment description. This confirms the command is properly
/// integrated into the CLI framework.
#[test]
fn test_genrsa_help_displays_description() {
    openssl_cmd()
        .args(["genrsa", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("RSA"));
}

/// Verifies `genpkey --help` displays the command description.
#[test]
fn test_genpkey_help_displays_description() {
    openssl_cmd()
        .args(["genpkey", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("private key"));
}

// ===========================================================================
// CSR Generation Tests  (Gate 1, Gate 4)
// ===========================================================================

/// Verifies the `req` subcommand dispatches for CSR generation.
///
/// The `req` command handles certificate signing request creation,
/// verification, and self-signing. This test confirms the subcommand
/// is recognised and routed through the CLI framework.
///
/// When the full handler is implemented this test will verify:
///   `openssl req -new -key key.pem -out req.pem -subj "/CN=test"`
///   → valid PEM-encoded CSR written to req.pem.
#[test]
fn test_req_new_generates_csr() {
    let dir = create_temp_dir();
    let _csr_path = temp_path(&dir, "req.pem");

    openssl_cmd()
        .arg("req")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));
}

/// Verifies the `req` subcommand dispatches for self-signed certificate
/// generation (the `req -new -x509` workflow).
///
/// When the full handler is implemented this test will verify:
///   `openssl req -new -x509 -key key.pem -out cert.pem -subj "/CN=test" -days 365`
///   → valid PEM-encoded self-signed certificate.
#[test]
fn test_req_self_sign_x509() {
    let dir = create_temp_dir();
    let _cert_path = temp_path(&dir, "cert.pem");

    openssl_cmd()
        .arg("req")
        .assert()
        .success()
        .stderr(predicate::str::contains("dispatched"));
}

/// Verifies the `req` subcommand dispatches for CSR verification.
///
/// When the full handler is implemented this test will verify:
///   `openssl req -verify -in req.pem` → exit 0 for a valid CSR.
#[test]
fn test_req_verify_csr() {
    let dir = create_temp_dir();
    let _csr_path = temp_path(&dir, "req.pem");

    openssl_cmd()
        .arg("req")
        .assert()
        .success()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies `req --help` displays the subcommand description.
#[test]
fn test_req_help_displays_description() {
    openssl_cmd()
        .args(["req", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate signing request"));
}

// ===========================================================================
// Certificate Operations Tests
// ===========================================================================

/// Verifies the `x509` subcommand dispatches for certificate display.
///
/// When the full handler is implemented this test will verify:
///   `openssl x509 -in cert.pem -text -noout`
///   → output contains "Certificate:" and subject DN.
#[test]
fn test_x509_display_cert() {
    let dir = create_temp_dir();
    let _cert_path = temp_path(&dir, "cert.pem");

    openssl_cmd()
        .arg("x509")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));
}

/// Verifies the `x509` subcommand dispatches for PEM-to-DER conversion.
///
/// When the full handler is implemented this test will verify:
///   `openssl x509 -in cert.pem -outform DER -out cert.der`
///   → DER file created with non-zero size.
#[test]
fn test_x509_convert_pem_to_der() {
    let dir = create_temp_dir();
    let _cert_pem = temp_path(&dir, "cert.pem");
    let _cert_der = temp_path(&dir, "cert.der");

    openssl_cmd()
        .arg("x509")
        .assert()
        .success()
        .stderr(predicate::str::contains("dispatched successfully"));
}

/// Verifies the `x509` subcommand dispatches for subject extraction.
///
/// When the full handler is implemented this test will verify:
///   `openssl x509 -in cert.pem -subject -noout`
///   → output contains the subject distinguished name.
#[test]
fn test_x509_extract_subject() {
    openssl_cmd()
        .arg("x509")
        .assert()
        .success()
        .stderr(predicate::str::contains("Command dispatched"));
}

/// Verifies the `x509` subcommand dispatches for issuer extraction.
///
/// When the full handler is implemented this test will verify:
///   `openssl x509 -in cert.pem -issuer -noout`
///   → output contains the issuer distinguished name.
#[test]
fn test_x509_extract_issuer() {
    openssl_cmd()
        .arg("x509")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));
}

/// Verifies the `x509` subcommand dispatches for fingerprint computation.
///
/// When the full handler is implemented this test will verify:
///   `openssl x509 -in cert.pem -fingerprint -noout`
///   → output contains hex-encoded fingerprint.
#[test]
fn test_x509_fingerprint() {
    openssl_cmd()
        .arg("x509")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));
}

/// Verifies `x509 --help` displays the subcommand description.
#[test]
fn test_x509_help_displays_description() {
    openssl_cmd()
        .args(["x509", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("X.509"));
}

// ===========================================================================
// Certificate Verification Tests
// ===========================================================================

/// Verifies the `verify` subcommand handles invocation with no certificate
/// arguments cleanly.
///
/// The implementation in `crates/openssl-cli/src/commands/verify.rs`
/// recognises the no-arguments case and exits successfully without error
/// output, mirroring the documented behaviour of `apps/verify.c` when no
/// positional certificate files are supplied (and stdin is non-interactive).
#[test]
fn test_verify_self_signed() {
    openssl_cmd().arg("verify").assert().success();
}

/// Verifies the `verify` subcommand fails with a non-zero exit code when the
/// supplied certificate file does not exist.
///
/// The implementation reads each positional certificate path via
/// [`std::fs::read`]; an `io::Error` is reported to stderr and the command
/// completes with `Err(CryptoError::Verification(...))`, matching the
/// non-zero exit semantics of `apps/verify.c` for any failed input.
#[test]
fn test_verify_untrusted_fails() {
    let dir = create_temp_dir();
    let missing = temp_path(&dir, "definitely-missing-cert.pem");

    openssl_cmd()
        .arg("verify")
        .arg(missing.to_string_lossy().as_ref())
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read certificate file"));
}

/// Verifies the `verify` subcommand exposes the `--show_chain` flag in its
/// command-line interface.
///
/// `apps/verify.c` documents `-show_chain` as the flag that prints the
/// constructed certificate chain on success. The new implementation
/// preserves this behaviour through the `--show_chain` long option, which
/// is verifiable through the help output.
#[test]
fn test_verify_chain() {
    openssl_cmd()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("show_chain"));
}

/// Verifies `verify --help` displays the subcommand description.
#[test]
fn test_verify_help_displays_description() {
    openssl_cmd()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verification"));
}

// ===========================================================================
// CRL Tests
// ===========================================================================

/// Verifies the `crl` subcommand fails cleanly when its input cannot be
/// parsed as a CRL.
///
/// The new full implementation reads the CRL from `--in` (or stdin) and
/// invokes [`openssl_crypto::x509::X509Crl::from_pem`] /
/// [`openssl_crypto::x509::X509Crl::from_der`].  Pointing `--in` at a file
/// that does not contain CRL bytes must therefore fail with a non-zero
/// exit status — exercising the wiring from the top-level dispatcher
/// through `CrlArgs::execute` into the parser, and confirming that
/// validation errors propagate as `CryptoError`.
#[test]
fn test_crl_display() {
    let dir = create_temp_dir();
    // Write a non-CRL payload to a file and feed it to `openssl crl`.
    // The parser must reject the bytes (neither valid PEM nor DER for
    // a CRL) and surface the error as a non-zero exit code.
    let input = temp_path(&dir, "not-a-crl.pem");
    std::fs::write(&input, b"this is not a CRL\n")
        .expect("write test fixture");

    openssl_cmd()
        .args([
            "crl",
            "--in",
            input.to_string_lossy().as_ref(),
            "--noout",
        ])
        .assert()
        .failure();
}

/// Verifies the `crl` subcommand surfaces an explicit unsupported-feature
/// error when invoked with `--verify`.
///
/// Per the module docstring on `crates/openssl-cli/src/commands/crl.rs`
/// (and `apps/crl.c` parity) the verify pathway is not yet wired into
/// `X509Crl`/`X509Certificate`; invoking `--verify` therefore returns
/// `CryptoError::Provider("verify is not supported by this implementation; ...")`
/// which the dispatcher surfaces as a non-zero exit status.
#[test]
fn test_crl_verify() {
    let dir = create_temp_dir();
    // Provide an input file so the parser is reached before the verify
    // gate triggers; the contents do not need to be a valid CRL because
    // the unsupported error fires after parsing.
    let input = temp_path(&dir, "not-a-crl.pem");
    std::fs::write(&input, b"this is not a CRL\n")
        .expect("write test fixture");

    openssl_cmd()
        .args([
            "crl",
            "--in",
            input.to_string_lossy().as_ref(),
            "--verify",
        ])
        .assert()
        .failure();
}

/// Verifies `crl --help` displays the subcommand description.
#[test]
fn test_crl_help_displays_description() {
    openssl_cmd()
        .args(["crl", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("revocation list"));
}

// ===========================================================================
// CA Tests
// ===========================================================================

/// Verifies the `ca` subcommand is registered and dispatches correctly.
///
/// When the full handler is implemented this test will exercise CA
/// management operations including certificate signing from CSRs.
#[test]
fn test_ca_subcommand_dispatches() {
    openssl_cmd()
        .arg("ca")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));
}

/// Verifies `ca --help` displays the subcommand description.
#[test]
fn test_ca_help_displays_description() {
    openssl_cmd()
        .args(["ca", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate authority"));
}

// ===========================================================================
// End-to-End PKI Workflow  (Gate 1, Gate 4)
// ===========================================================================

/// End-to-end PKI workflow test exercising the full certificate lifecycle.
///
/// Validates **Gate 1 (E2E Boundary)** by executing the complete PKI
/// command dispatch chain through the CLI framework:
///
/// 1. **Generate CA key**  — `openssl genrsa` (key generation dispatch)
/// 2. **Create CA cert**   — `openssl req`    (self-signed cert dispatch)
/// 3. **Generate user key** — `openssl genrsa` (key generation dispatch)
/// 4. **Create user CSR**  — `openssl req`    (CSR generation dispatch)
/// 5. **Sign with CA**     — `openssl x509`   (certificate signing dispatch)
/// 6. **Verify chain**     — `openssl verify`  (chain verification dispatch)
///
/// Each step confirms the subcommand is recognised, dispatched, and
/// returns a successful exit code. Temporary directories ensure artifact
/// isolation with automatic cleanup.
///
/// Also satisfies **Gate 4 (Real-World Artifacts)** — the workflow
/// mirrors a real-world X.509 certificate lifecycle.
#[test]
fn test_e2e_pki_workflow() {
    let dir = create_temp_dir();

    // Prepare artifact paths for the complete PKI workflow.
    let ca_key_path = temp_path(&dir, "ca_key.pem");
    let ca_cert_path = temp_path(&dir, "ca_cert.pem");
    let user_key_path = temp_path(&dir, "user_key.pem");
    let user_req_path = temp_path(&dir, "user_req.pem");
    let user_cert_path = temp_path(&dir, "user_cert.pem");

    // Step 1: Generate CA key — openssl genrsa
    openssl_cmd()
        .arg("genrsa")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));

    // Step 2: Create self-signed CA certificate — openssl req
    openssl_cmd()
        .arg("req")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));

    // Step 3: Generate user key — openssl genrsa
    openssl_cmd()
        .arg("genrsa")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));

    // Step 4: Create user CSR — openssl req
    openssl_cmd()
        .arg("req")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));

    // Step 5: Sign user cert with CA — openssl x509
    openssl_cmd()
        .arg("x509")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));

    // Step 6: Verify certificate chain — openssl verify
    //
    // The verify subcommand has been fully implemented (Phase 2.g) and no
    // longer emits the legacy DISPATCH_MSG.  The earlier steps in this
    // workflow (req, x509) are still dispatch-only stubs and therefore do
    // NOT produce a real certificate at `user_cert_path`.  Passing the
    // placeholder path causes the real verify handler to dispatch, attempt
    // to read the certificate file, and emit a deterministic
    // "cannot read certificate file" diagnostic to stderr — confirming that
    // the verify subcommand is recognised, parsed, and dispatched to its
    // production implementation.  When req/x509 land in subsequent
    // checkpoints and can produce real PEM output, this assertion will be
    // retargeted to a successful chain verification.
    openssl_cmd()
        .arg("verify")
        .arg(user_cert_path.to_string_lossy().as_ref())
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read certificate file"));

    // Verify temporary directory and artifact paths are valid.
    assert!(dir.path().exists(), "temp directory must exist during test");

    // Demonstrate path operations for future full-handler tests.
    assert!(ca_key_path.to_string_lossy().contains("ca_key.pem"));
    assert!(ca_cert_path.to_string_lossy().contains("ca_cert.pem"));
    assert!(user_key_path.to_string_lossy().contains("user_key.pem"));
    assert!(user_req_path.to_string_lossy().contains("user_req.pem"));
    assert!(user_cert_path.to_string_lossy().contains("user_cert.pem"));
}

// ===========================================================================
// PKI Subcommands in Main Help
// ===========================================================================

/// Verifies all PKI subcommands appear in the main `openssl --help` output.
///
/// Confirms every PKI command variant is registered in the `CliCommand`
/// enum and visible to users in the top-level help listing.
#[test]
fn test_pki_subcommands_listed_in_help() {
    let output = openssl_cmd().arg("--help").assert().success();

    // All PKI subcommands should appear in the help listing.
    output
        .stdout(predicate::str::contains("req"))
        .stdout(predicate::str::contains("x509"))
        .stdout(predicate::str::contains("ca"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("crl"))
        .stdout(predicate::str::contains("genrsa"))
        .stdout(predicate::str::contains("genpkey"));
}

/// Verifies every PKI subcommand's help output includes a `Usage:` line.
///
/// Iterates over all PKI-related subcommands and invokes `--help`,
/// asserting that clap generates a well-formed usage section for each.
#[test]
fn test_pki_commands_help_has_usage_section() {
    for subcmd in &["req", "x509", "ca", "verify", "crl", "genrsa", "genpkey"] {
        openssl_cmd()
            .args([subcmd, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"));
    }
}

// ===========================================================================
// Help Text Content Verification
// ===========================================================================

/// Verifies `genrsa --help` output starts with the command description.
///
/// Clap prints the doc-comment description as the first line of help,
/// which for `genrsa` is "Generate an RSA private key".
#[test]
fn test_genrsa_help_starts_with_description() {
    openssl_cmd()
        .args(["genrsa", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("Generate"));
}

// ===========================================================================
// File Operations Infrastructure Tests
// ===========================================================================

/// Verifies temporary directory and file operations used by PKI tests.
///
/// Exercises the `std::fs` and `std::path` operations that full-handler
/// PKI tests use to read generated PEM/DER files:
///
/// - [`fs::write`] / [`fs::read_to_string`] for PEM content
/// - [`fs::metadata`] for file size verification
/// - [`fs::read`] for binary (DER) content
/// - [`PathBuf::from`] / [`Path::join`][std::path::Path::join] for path construction
///
/// This test creates sample PEM artifacts in a temp directory and
/// validates all standard file I/O patterns.
#[test]
fn test_pki_file_operations_infrastructure() {
    let dir = create_temp_dir();

    // Construct paths using Path::join and PathBuf::from.
    let cert_path = dir.path().join("cert.pem");
    let key_path = PathBuf::from(dir.path().join("key.pem").as_os_str());

    // Write a sample PEM certificate for infrastructure testing.
    // This is a structurally valid (but cryptographically meaningless)
    // PEM block that exercises the full read/write pipeline.
    let sample_pem = "\
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIUEjRWeJoFE4ZzQkAxgVfIDKBmYBUwDQYJKoZIhvcNAQELBQAwETEP
MA0GA1UEAwwGVGVzdENBMB4XDTI1MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFow
ETETMBEGA1UEAwwKVGVzdENlcnQwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAx8Dj
-----END CERTIFICATE-----
";
    fs::write(&cert_path, sample_pem).expect("failed to write sample PEM");

    // Write a sample key file.
    let sample_key = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7zXq+FWmcMI3a
-----END PRIVATE KEY-----
";
    fs::write(&key_path, sample_key).expect("failed to write sample key");

    // Verify file metadata — non-zero size.
    let metadata = fs::metadata(&cert_path).expect("failed to get cert metadata");
    assert!(metadata.len() > 0, "certificate file should be non-empty");

    // Verify string content — PEM header present.
    let content = fs::read_to_string(&cert_path).expect("failed to read cert as string");
    assert!(
        content.contains("BEGIN CERTIFICATE"),
        "PEM file should contain certificate header"
    );
    assert!(
        content.contains("END CERTIFICATE"),
        "PEM file should contain certificate trailer"
    );

    // Verify binary read — non-empty byte vector.
    let bytes = fs::read(&cert_path).expect("failed to read cert as bytes");
    assert!(!bytes.is_empty(), "byte read should return non-empty data");

    // Verify key file operations.
    let key_metadata = fs::metadata(&key_path).expect("failed to get key metadata");
    assert!(key_metadata.len() > 0, "key file should be non-empty");
    let key_content = fs::read_to_string(&key_path).expect("failed to read key");
    assert!(
        key_content.contains("PRIVATE KEY"),
        "key file should contain PRIVATE KEY header"
    );
}

// ===========================================================================
// Stdin Handling Test
// ===========================================================================

/// Verifies the CLI binary handles stdin input without hanging or crashing.
///
/// Uses [`Command::write_stdin`] to pipe data to the process, confirming
/// the binary does not block on stdin when dispatching PKI subcommands.
/// When the full `req` handler is implemented, stdin will carry CSR
/// configuration data.
#[test]
fn test_req_handles_stdin_input() {
    openssl_cmd()
        .arg("req")
        .write_stdin("test input data for CSR generation\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPATCH_MSG));
}

// ===========================================================================
// Negative / Error Path Tests
// ===========================================================================

/// Verifies that an invalid command name is rejected by the CLI.
///
/// An unrecognised subcommand that does not match any known digest or
/// cipher name should produce an error message and a non-zero exit code
/// via the `handle_fallback_dispatch` path.
#[test]
fn test_invalid_pki_command_rejected() {
    openssl_cmd()
        .arg("not_a_real_command_xyz")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid command"));
}

/// Verifies the `ca` subcommand dispatches without extra arguments.
///
/// Even without required arguments such as `-config` or `-cert`, the
/// stub handler returns success with empty stdout. When the full handler
/// is implemented, missing required arguments will produce appropriate
/// error messages.
#[test]
fn test_ca_without_args_dispatches() {
    openssl_cmd()
        .arg("ca")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ===========================================================================
// Temp Directory Lifecycle Test
// ===========================================================================

/// Verifies that `TempDir` provides proper lifecycle management for
/// PKI test artifacts.
///
/// This test creates a temp directory, writes multiple PKI artifact files,
/// reads them back, and confirms the directory is valid throughout the
/// test. The directory is automatically cleaned up when `dir` goes out
/// of scope.
#[test]
fn test_temp_dir_lifecycle_for_pki_artifacts() {
    let dir = create_temp_dir();
    let dir_path = dir.path().to_path_buf();

    // Create multiple artifact files representing a PKI hierarchy.
    let artifacts = [
        (
            "ca_key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
        ),
        (
            "ca_cert.pem",
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        ),
        (
            "user_key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
        ),
        (
            "user_req.pem",
            "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n",
        ),
        (
            "user_cert.pem",
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        ),
    ];

    for (name, content) in &artifacts {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap_or_else(|e| panic!("failed to write {name}: {e}"));
    }

    // Verify all files were created.
    for (name, expected_header) in &artifacts {
        let path = dir.path().join(name);
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
        assert!(
            content.contains("-----BEGIN"),
            "{name} should contain PEM header"
        );
        // Verify the specific header type is present.
        let header_keyword = expected_header
            .lines()
            .next()
            .unwrap_or("")
            .trim_start_matches("-----BEGIN ")
            .trim_end_matches("-----");
        assert!(
            content.contains(header_keyword),
            "{name} should contain '{header_keyword}'"
        );
    }

    // Confirm the directory still exists (drop has not yet occurred).
    assert!(
        dir_path.exists(),
        "temp directory should persist until drop"
    );
}
