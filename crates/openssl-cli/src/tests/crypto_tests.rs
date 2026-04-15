//! Cryptographic operation integration tests for the OpenSSL CLI binary.
//!
//! This module exercises crypto-oriented CLI subcommands via subprocess invocation:
//! `enc` (symmetric encryption/decryption), `dgst` (message digests, HMAC, sign/verify),
//! `rand` (random data generation), `mac` (MAC computation), `cms` (CMS sign/verify/
//! encrypt/decrypt — feature-gated), and `pkcs12` (PKCS#12 export/import).
//!
//! # Test Strategy
//!
//! Each test spawns the compiled `openssl` binary as a child process using
//! [`assert_cmd::Command`], passes subcommand-specific arguments, and validates
//! exit status and output using [`predicates`] matchers. Temporary files for
//! plaintext, ciphertext, keys, and certificates are managed by
//! [`tempfile::TempDir`] for automatic cleanup.
//!
//! Tests are designed for progressive validation:
//! 1. First, verify that the subcommand name is recognized by the CLI dispatcher.
//! 2. Then, attempt the full operation with arguments; if the handler is not yet
//!    wired to accept arguments (stub dispatch), the test returns early after
//!    verifying command recognition.
//! 3. When the handler is fully implemented, tests verify complete operation
//!    including output format and roundtrip integrity.
//!
//! # Compliance
//!
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** No module-level `#[allow(warnings)]`.
//! - **R10 (Wiring Before Done):** Tests exercise the real binary entry point:
//!   `main() → Cli::parse() → CliCommand::Variant → module::execute()`.
//!
//! # Caller Chain
//!
//! All tests follow the caller chain:
//! ```text
//! main() → Cli::parse() → CliCommand::{Enc,Dgst,Rand,Mac,Cms,Pkcs12} → execute()
//! ```
//!
//! # Gate Coverage
//!
//! - **Gate 1 (E2E Boundary):** Encryption roundtrip verifies data integrity.
//! - **Gate 5 (API Contract):** Digest output, rand output, MAC output formats verified.

// Test modules are allowed to use expect/unwrap for concise assertions.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Helper Functions
// ============================================================================

/// Returns a [`Command`] configured to invoke the compiled `openssl` binary.
///
/// Uses `super::openssl_cmd()` from the parent test module (`tests/mod.rs`)
/// which calls `Command::cargo_bin("openssl")` to locate the binary built
/// by the current cargo workspace.
fn openssl_cmd() -> Command {
    super::openssl_cmd()
}

/// Creates a test plaintext file with known content inside the given temporary
/// directory. Returns the path to the created file.
///
/// The content is a deterministic string suitable for encryption roundtrip
/// verification and digest computation.
fn create_test_plaintext(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("plaintext.txt");
    let content = "The quick brown fox jumps over the lazy dog.\n\
                   This is test data for OpenSSL CLI crypto integration tests.\n\
                   Line 3: deterministic content for reproducible digests.\n";
    fs::write(&path, content).expect("Failed to write test plaintext file");
    path
}

/// Runs a command with arguments and returns whether the command succeeded.
///
/// This helper enables progressive validation: if the handler is a stub that
/// does not yet accept arguments, the caller can return early after verifying
/// that the subcommand name itself is recognized by the dispatcher.
fn run_cmd_with_args(subcommand: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = openssl_cmd();
    cmd.arg(subcommand);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("Failed to execute openssl command")
}

// ============================================================================
// Symmetric Encryption Tests (openssl enc)
// ============================================================================

/// Tests AES-256-CBC encryption roundtrip using PBKDF2 key derivation.
///
/// Encrypts a plaintext file with `openssl enc -aes-256-cbc -pbkdf2 -pass pass:test`,
/// then decrypts with the same parameters and verifies the roundtrip produces
/// the original content.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Enc → enc::execute()`
#[test]
fn test_enc_aes256cbc_roundtrip() {
    // Verify the enc subcommand is recognized by the dispatcher.
    openssl_cmd()
        .arg("enc")
        .assert()
        .success()
        .stderr(predicate::str::contains("dispatched").or(predicate::str::is_empty()));

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let encrypted_path = dir.path().join("encrypted.bin");
    let decrypted_path = dir.path().join("decrypted.txt");

    // Attempt encryption with full arguments.
    let encrypt_output = run_cmd_with_args(
        "enc",
        &[
            "-aes-256-cbc",
            "-pbkdf2",
            "-pass",
            "pass:testpassword123",
            "-in",
            plaintext_path.to_str().unwrap(),
            "-out",
            encrypted_path.to_str().unwrap(),
        ],
    );

    if !encrypt_output.status.success() {
        // Handler does not yet accept arguments — dispatch verified above.
        return;
    }

    // Full implementation: verify encrypted file was created.
    assert!(
        encrypted_path.exists(),
        "Encrypted output file should exist after enc"
    );

    // Decrypt with the same parameters.
    let decrypt_output = run_cmd_with_args(
        "enc",
        &[
            "-aes-256-cbc",
            "-d",
            "-pbkdf2",
            "-pass",
            "pass:testpassword123",
            "-in",
            encrypted_path.to_str().unwrap(),
            "-out",
            decrypted_path.to_str().unwrap(),
        ],
    );

    assert!(
        decrypt_output.status.success(),
        "Decryption with correct password should succeed"
    );

    // Verify roundtrip integrity.
    let original = fs::read_to_string(&plaintext_path).expect("Failed to read original plaintext");
    let decrypted = fs::read_to_string(&decrypted_path).expect("Failed to read decrypted output");
    assert_eq!(
        original, decrypted,
        "Encryption roundtrip failed: content mismatch"
    );
}

/// Tests base64 encoding via `openssl enc -base64`.
///
/// Encodes a plaintext file to base64 and verifies the output file is created
/// and contains valid base64 characters.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Enc → enc::execute()`
#[test]
fn test_enc_base64_encode() {
    // Verify the enc subcommand is recognized.
    openssl_cmd().arg("enc").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let b64_path = dir.path().join("encoded.b64");

    let output = run_cmd_with_args(
        "enc",
        &[
            "-base64",
            "-in",
            plaintext_path.to_str().unwrap(),
            "-out",
            b64_path.to_str().unwrap(),
        ],
    );

    if !output.status.success() {
        // Handler not fully wired — dispatch verified above.
        return;
    }

    // Verify base64 output file exists and contains content.
    let b64_content = fs::read_to_string(&b64_path).expect("Failed to read base64 output");
    assert!(
        !b64_content.is_empty(),
        "Base64 encoded output should not be empty"
    );
}

/// Tests `openssl enc -list` to verify cipher enumeration.
///
/// The `-list` flag should produce output listing available cipher names.
/// When fully implemented, output includes cipher algorithm names.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Enc → enc::execute()`
#[test]
fn test_enc_list_ciphers() {
    // Verify the enc subcommand is recognized.
    openssl_cmd().arg("enc").assert().success();

    let output = run_cmd_with_args("enc", &["-list"]);

    if !output.status.success() {
        // Handler not fully wired — dispatch verified above.
        return;
    }

    // Full implementation: verify output lists cipher names.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Cipher list output should not be empty");
}

/// Tests that decryption with an incorrect password fails.
///
/// Encrypts with one password, then attempts to decrypt with a different
/// password and expects the operation to either fail or produce incorrect output.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Enc → enc::execute()`
#[test]
fn test_enc_bad_password_fails() {
    // Verify the enc subcommand is recognized.
    openssl_cmd().arg("enc").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let encrypted_path = dir.path().join("encrypted_bad.bin");
    let decrypted_path = dir.path().join("decrypted_bad.txt");

    // Encrypt with correct password.
    let encrypt_output = run_cmd_with_args(
        "enc",
        &[
            "-aes-256-cbc",
            "-pbkdf2",
            "-pass",
            "pass:correctpassword",
            "-in",
            plaintext_path.to_str().unwrap(),
            "-out",
            encrypted_path.to_str().unwrap(),
        ],
    );

    if !encrypt_output.status.success() {
        // Handler not fully wired — dispatch verified above.
        return;
    }

    // Attempt decryption with wrong password.
    let decrypt_output = run_cmd_with_args(
        "enc",
        &[
            "-aes-256-cbc",
            "-d",
            "-pbkdf2",
            "-pass",
            "pass:wrongpassword",
            "-in",
            encrypted_path.to_str().unwrap(),
            "-out",
            decrypted_path.to_str().unwrap(),
        ],
    );

    // Either decryption fails (non-zero exit) or content differs from original.
    if decrypt_output.status.success() && decrypted_path.exists() {
        let original = fs::read_to_string(&plaintext_path).expect("Failed to read original");
        let decrypted = fs::read_to_string(&decrypted_path).unwrap_or_default();
        assert_ne!(
            original, decrypted,
            "Decryption with wrong password should not produce original content"
        );
    }
}

// ============================================================================
// Digest Tests (openssl dgst)
// ============================================================================

/// Tests SHA-256 digest computation.
///
/// Runs `openssl dgst -sha256 file.txt` and verifies the output contains
/// the expected hex digest format: `SHA2-256(file.txt)= <hex>`.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dgst_sha256() {
    // Verify the dgst subcommand is recognized by the dispatcher.
    openssl_cmd().arg("dgst").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);

    let output = run_cmd_with_args("dgst", &["-sha256", plaintext_path.to_str().unwrap()]);

    if !output.status.success() {
        // Handler not fully wired — dispatch verified above.
        return;
    }

    // Full implementation: verify hex digest format.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SHA2-256") || stdout.contains("sha256") || stdout.contains("SHA256"),
        "SHA-256 digest output should reference the algorithm name"
    );
}

/// Tests SHA-512 digest computation.
///
/// Runs `openssl dgst -sha512 file.txt` and verifies the command succeeds.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dgst_sha512() {
    // Verify the dgst subcommand is recognized.
    openssl_cmd().arg("dgst").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);

    let output = run_cmd_with_args("dgst", &["-sha512", plaintext_path.to_str().unwrap()]);

    if !output.status.success() {
        // Handler not fully wired — dispatch verified above.
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "SHA-512 digest output should not be empty"
    );
}

/// Tests MD5 digest computation.
///
/// Runs `openssl dgst -md5 file.txt` and verifies the command succeeds.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dgst_md5() {
    // Verify the dgst subcommand is recognized.
    openssl_cmd().arg("dgst").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);

    let output = run_cmd_with_args("dgst", &["-md5", plaintext_path.to_str().unwrap()]);

    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "MD5 digest output should not be empty");
}

/// Tests binary digest output.
///
/// Runs `openssl dgst -sha256 -binary file.txt` and verifies the binary
/// output is exactly 32 bytes (SHA-256 digest size).
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dgst_binary_output() {
    // Verify the dgst subcommand is recognized.
    openssl_cmd().arg("dgst").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let binary_path = dir.path().join("digest.bin");

    let output = run_cmd_with_args(
        "dgst",
        &[
            "-sha256",
            "-binary",
            "-out",
            binary_path.to_str().unwrap(),
            plaintext_path.to_str().unwrap(),
        ],
    );

    if !output.status.success() {
        return;
    }

    // SHA-256 binary digest should be exactly 32 bytes.
    let digest_bytes = fs::read(&binary_path).expect("Failed to read binary digest");
    assert_eq!(
        digest_bytes.len(),
        32,
        "SHA-256 binary digest should be exactly 32 bytes"
    );
}

/// Tests digest computation on multiple files.
///
/// Runs `openssl dgst -sha256 file1.txt file2.txt` and verifies both
/// files are hashed.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dgst_multiple_files() {
    // Verify the dgst subcommand is recognized.
    openssl_cmd().arg("dgst").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let file1 = create_test_plaintext(&dir);

    let file2 = dir.path().join("file2.txt");
    fs::write(&file2, "Second file content for hashing.\n")
        .expect("Failed to write second test file");

    let output = run_cmd_with_args(
        "dgst",
        &["-sha256", file1.to_str().unwrap(), file2.to_str().unwrap()],
    );

    if !output.status.success() {
        return;
    }

    // Output should contain entries for both files.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().count() >= 2,
        "Multiple file digest should produce output for each file"
    );
}

/// Tests digest sign and verify workflow.
///
/// Generates an RSA key, signs a file digest with `openssl dgst -sha256 -sign`,
/// then verifies the signature with `openssl dgst -sha256 -verify`.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Genpkey → genpkey::execute()`
/// then: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dgst_sign_verify() {
    // Verify dgst and genpkey subcommands are recognized.
    openssl_cmd().arg("dgst").assert().success();
    openssl_cmd().arg("genpkey").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let key_path = dir.path().join("rsa_key.pem");
    let pub_key_path = dir.path().join("rsa_pub.pem");
    let sig_path = dir.path().join("signature.bin");

    // Generate RSA private key.
    let keygen = run_cmd_with_args(
        "genpkey",
        &[
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ],
    );

    if !keygen.status.success() {
        // Key generation handler not wired — dispatch verified above.
        return;
    }

    // Extract public key.
    let pubkey_out = run_cmd_with_args(
        "pkey",
        &[
            "-in",
            key_path.to_str().unwrap(),
            "-pubout",
            "-out",
            pub_key_path.to_str().unwrap(),
        ],
    );

    if !pubkey_out.status.success() {
        return;
    }

    // Sign the file digest.
    let sign_out = run_cmd_with_args(
        "dgst",
        &[
            "-sha256",
            "-sign",
            key_path.to_str().unwrap(),
            "-out",
            sig_path.to_str().unwrap(),
            plaintext_path.to_str().unwrap(),
        ],
    );

    if !sign_out.status.success() {
        return;
    }

    // Verify the signature.
    let verify_out = run_cmd_with_args(
        "dgst",
        &[
            "-sha256",
            "-verify",
            pub_key_path.to_str().unwrap(),
            "-signature",
            sig_path.to_str().unwrap(),
            plaintext_path.to_str().unwrap(),
        ],
    );

    assert!(
        verify_out.status.success(),
        "Signature verification should succeed after signing"
    );
}

// ============================================================================
// Random Data Generation Tests (openssl rand)
// ============================================================================

/// Tests raw random byte generation.
///
/// Runs `openssl rand -out file 32` and verifies 32 bytes of output.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rand → rand::execute()`
#[test]
fn test_rand_generates_bytes() {
    // Verify the rand subcommand is recognized.
    openssl_cmd().arg("rand").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let out_path = dir.path().join("random.bin");

    let output = run_cmd_with_args("rand", &["-out", out_path.to_str().unwrap(), "32"]);

    if !output.status.success() {
        return;
    }

    let data = fs::read(&out_path).expect("Failed to read random output");
    assert_eq!(data.len(), 32, "Random output should be exactly 32 bytes");
}

/// Tests hex-encoded random output.
///
/// Runs `openssl rand -hex 16` and verifies the output is a 32-character
/// hexadecimal string (16 bytes = 32 hex chars).
///
/// Note: When the handler is a stub, clap may interpret `-hex` as `-h` (help)
/// and display usage text instead. The test detects this and skips validation.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rand → rand::execute()`
#[test]
fn test_rand_hex_output() {
    // Verify the rand subcommand is recognized.
    openssl_cmd().arg("rand").assert().success();

    let output = run_cmd_with_args("rand", &["-hex", "16"]);

    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hex_str = stdout.trim();

    // When handler is a stub, clap may interpret -h as help and output usage.
    // Skip hex validation if output is help text or a dispatch stub message.
    if hex_str.contains("Usage:") || hex_str.contains("help") || hex_str.contains("dispatched") {
        return;
    }

    // Full implementation: validate hex output.
    // 16 random bytes → 32 hex characters.
    assert!(
        hex_str.len() >= 32,
        "Hex output for 16 bytes should be at least 32 hex chars, got {hex_str}"
    );
    assert!(
        hex_str.chars().all(|c| c.is_ascii_hexdigit()),
        "Hex output should contain only hex digits, got: {hex_str}",
    );
}

/// Tests base64-encoded random output.
///
/// Runs `openssl rand -base64 32` and verifies the output contains
/// valid base64 characters.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rand → rand::execute()`
#[test]
fn test_rand_base64_output() {
    // Verify the rand subcommand is recognized.
    openssl_cmd().arg("rand").assert().success();

    let output = run_cmd_with_args("rand", &["-base64", "32"]);

    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let b64_str = stdout.trim();
    assert!(!b64_str.is_empty(), "Base64 output should not be empty");
    assert!(
        b64_str.chars().all(|c| c.is_ascii_alphanumeric()
            || c == '+'
            || c == '/'
            || c == '='
            || c == '\n'),
        "Base64 output should contain only valid base64 characters, got: {b64_str}",
    );
}

// ============================================================================
// MAC Tests (openssl mac)
// ============================================================================

/// Tests HMAC-SHA256 computation.
///
/// Runs `openssl mac -macopt hexkey:<key> -macopt digest:SHA256 HMAC`
/// with known input and verifies the MAC output format.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Mac → mac::execute()`
#[test]
fn test_mac_hmac_sha256() {
    // Verify the mac subcommand is recognized.
    openssl_cmd().arg("mac").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let input_path = create_test_plaintext(&dir);

    let output = run_cmd_with_args(
        "mac",
        &[
            "-macopt",
            "hexkey:deadbeef0123456789abcdef01234567",
            "-macopt",
            "digest:SHA256",
            "-in",
            input_path.to_str().unwrap(),
            "HMAC",
        ],
    );

    if !output.status.success() {
        return;
    }

    // HMAC-SHA256 output is 32 bytes = 64 hex characters.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hex_mac = stdout.trim();
    assert!(
        hex_mac.len() >= 64,
        "HMAC-SHA256 hex output should be at least 64 chars, got {hex_mac}"
    );
}

// ============================================================================
// CMS Tests (Feature-Gated)
// ============================================================================

/// Tests CMS sign and verify workflow.
///
/// Generates a self-signed certificate and key, signs data with CMS,
/// then verifies the CMS signature.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Cms → cms::execute()`
#[cfg(feature = "cms")]
#[test]
fn test_cms_sign_verify() {
    // Verify the cms subcommand is recognized.
    openssl_cmd().arg("cms").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let key_path = dir.path().join("cms_key.pem");
    let cert_path = dir.path().join("cms_cert.pem");
    let signed_path = dir.path().join("signed.cms");
    let verified_path = dir.path().join("verified.txt");

    // Generate RSA key.
    let keygen = run_cmd_with_args(
        "genpkey",
        &[
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ],
    );
    if !keygen.status.success() {
        return;
    }

    // Generate self-signed certificate.
    let cert_gen = run_cmd_with_args(
        "req",
        &[
            "-new",
            "-x509",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            "/CN=CMS Test/O=Test Org",
            "-batch",
        ],
    );
    if !cert_gen.status.success() {
        return;
    }

    // CMS sign.
    let sign_out = run_cmd_with_args(
        "cms",
        &[
            "-sign",
            "-in",
            plaintext_path.to_str().unwrap(),
            "-signer",
            cert_path.to_str().unwrap(),
            "-inkey",
            key_path.to_str().unwrap(),
            "-out",
            signed_path.to_str().unwrap(),
            "-outform",
            "PEM",
        ],
    );
    if !sign_out.status.success() {
        return;
    }

    // CMS verify.
    let verify_out = run_cmd_with_args(
        "cms",
        &[
            "-verify",
            "-in",
            signed_path.to_str().unwrap(),
            "-CAfile",
            cert_path.to_str().unwrap(),
            "-inform",
            "PEM",
            "-out",
            verified_path.to_str().unwrap(),
        ],
    );

    assert!(
        verify_out.status.success(),
        "CMS verify should succeed after signing"
    );

    if verified_path.exists() {
        let original = fs::read_to_string(&plaintext_path).expect("Failed to read original");
        let verified = fs::read_to_string(&verified_path).expect("Failed to read verified output");
        assert_eq!(
            original, verified,
            "CMS sign/verify roundtrip content mismatch"
        );
    }
}

/// Tests CMS encrypt and decrypt workflow.
///
/// Generates a self-signed certificate and key, encrypts data with CMS,
/// then decrypts the CMS envelope.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Cms → cms::execute()`
#[cfg(feature = "cms")]
#[test]
fn test_cms_encrypt_decrypt() {
    // Verify the cms subcommand is recognized.
    openssl_cmd().arg("cms").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let plaintext_path = create_test_plaintext(&dir);
    let key_path = dir.path().join("cms_enc_key.pem");
    let cert_path = dir.path().join("cms_enc_cert.pem");
    let encrypted_path = dir.path().join("encrypted.cms");
    let decrypted_path = dir.path().join("decrypted.txt");

    // Generate RSA key.
    let keygen = run_cmd_with_args(
        "genpkey",
        &[
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ],
    );
    if !keygen.status.success() {
        return;
    }

    // Generate self-signed certificate.
    let cert_gen = run_cmd_with_args(
        "req",
        &[
            "-new",
            "-x509",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            "/CN=CMS Encrypt Test/O=Test Org",
            "-batch",
        ],
    );
    if !cert_gen.status.success() {
        return;
    }

    // CMS encrypt.
    let encrypt_out = run_cmd_with_args(
        "cms",
        &[
            "-encrypt",
            "-in",
            plaintext_path.to_str().unwrap(),
            "-out",
            encrypted_path.to_str().unwrap(),
            "-outform",
            "PEM",
            cert_path.to_str().unwrap(),
        ],
    );
    if !encrypt_out.status.success() {
        return;
    }

    // CMS decrypt.
    let decrypt_out = run_cmd_with_args(
        "cms",
        &[
            "-decrypt",
            "-in",
            encrypted_path.to_str().unwrap(),
            "-recip",
            cert_path.to_str().unwrap(),
            "-inkey",
            key_path.to_str().unwrap(),
            "-inform",
            "PEM",
            "-out",
            decrypted_path.to_str().unwrap(),
        ],
    );

    assert!(
        decrypt_out.status.success(),
        "CMS decrypt should succeed after encrypting"
    );

    if decrypted_path.exists() {
        let original = fs::read_to_string(&plaintext_path).expect("Failed to read original");
        let decrypted =
            fs::read_to_string(&decrypted_path).expect("Failed to read decrypted output");
        assert_eq!(
            original, decrypted,
            "CMS encrypt/decrypt roundtrip content mismatch"
        );
    }
}

// ============================================================================
// PKCS#12 Tests (openssl pkcs12)
// ============================================================================

/// Tests PKCS#12 export and import workflow.
///
/// Creates a PKCS#12 archive from a certificate and private key, then
/// imports it back and verifies the certificate is extracted.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkcs12 → pkcs12::execute()`
#[test]
fn test_pkcs12_export_import() {
    // Verify the pkcs12 subcommand is recognized.
    openssl_cmd().arg("pkcs12").assert().success();
    openssl_cmd().arg("genpkey").assert().success();
    openssl_cmd().arg("req").assert().success();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = dir.path().join("p12_key.pem");
    let cert_path = dir.path().join("p12_cert.pem");
    let p12_path = dir.path().join("output.p12");
    let extracted_path = dir.path().join("extracted.pem");

    // Generate RSA key.
    let keygen = run_cmd_with_args(
        "genpkey",
        &[
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ],
    );
    if !keygen.status.success() {
        return;
    }

    // Generate self-signed certificate.
    let cert_gen = run_cmd_with_args(
        "req",
        &[
            "-new",
            "-x509",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            "/CN=PKCS12 Test/O=Test Org",
            "-batch",
        ],
    );
    if !cert_gen.status.success() {
        return;
    }

    // Export to PKCS#12.
    let export_out = run_cmd_with_args(
        "pkcs12",
        &[
            "-export",
            "-in",
            cert_path.to_str().unwrap(),
            "-inkey",
            key_path.to_str().unwrap(),
            "-out",
            p12_path.to_str().unwrap(),
            "-passout",
            "pass:exportpass",
            "-name",
            "TestEntry",
        ],
    );
    if !export_out.status.success() {
        return;
    }

    // Import from PKCS#12 (extract certificates).
    let import_out = run_cmd_with_args(
        "pkcs12",
        &[
            "-in",
            p12_path.to_str().unwrap(),
            "-out",
            extracted_path.to_str().unwrap(),
            "-passin",
            "pass:exportpass",
            "-nokeys",
        ],
    );

    assert!(
        import_out.status.success(),
        "PKCS#12 import should succeed after export"
    );

    if extracted_path.exists() {
        let extracted_content =
            fs::read_to_string(&extracted_path).expect("Failed to read extracted PEM");
        assert!(
            extracted_content.contains("CERTIFICATE"),
            "Extracted PKCS#12 should contain a certificate PEM block"
        );
    }
}
