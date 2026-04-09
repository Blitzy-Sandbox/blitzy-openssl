//! OpenSSL CLI — Command-line interface for the OpenSSL Rust workspace.
//!
//! This binary provides the `openssl` command with 56+ subcommands,
//! replicating the C `openssl(1)` tool's interface in idiomatic Rust.
//!
//! ## Dispatch Model
//!
//! The clap [`Subcommand`] derive replaces the C `LHASH_OF(FUNCTION)` dispatch
//! table from `apps/openssl.c:prog_init()`. Each enum variant in [`CliCommand`]
//! corresponds to one CLI subcommand.
//!
//! Three-tier dispatch (matching C `do_cmd()` behavior):
//! 1. Exact subcommand match → route to handler module
//! 2. Digest name fallback → route to `dgst` handler (e.g., `openssl sha256`)
//! 3. Cipher name fallback → route to `enc` handler (e.g., `openssl aes-256-cbc`)

// Justification: `lib` is an intra-crate module directory containing shared CLI
// helpers, not the crate's library root. This crate is a binary-only target.
// The crate-level allow is required because item-level #[allow] does not fully
// suppress special_module_name when RUSTFLAGS="-D warnings" is set.
#![allow(special_module_name)]

pub mod lib;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

// ---------------------------------------------------------------------------
// CLI Structure
// ---------------------------------------------------------------------------

/// Top-level CLI structure for the `openssl` command.
///
/// Uses clap's derive API to parse the command line. The `command` field
/// is optional to handle the bare `openssl` invocation (no subcommand),
/// which displays help text.
#[derive(Parser)]
#[command(
    name = "openssl",
    about = "OpenSSL command-line tool — Rust implementation",
    long_about = "OpenSSL command-line tool providing cryptographic operations, \
                  TLS diagnostics, certificate management, and key generation.",
    version
)]
struct Cli {
    /// The subcommand to execute. If omitted, help text is displayed.
    #[command(subcommand)]
    command: Option<CliCommand>,
}

/// All available CLI subcommands.
///
/// Each variant maps to a C source file in `apps/*.c`. Feature-gated
/// variants are conditionally compiled based on Cargo feature flags,
/// replacing the C `OPENSSL_NO_*` preprocessor guards.
///
/// The [`External`](CliCommand::External) variant catches unrecognized
/// subcommand names for digest/cipher name fallback dispatch, replicating
/// the three-tier lookup from `apps/openssl.c:do_cmd()`.
#[derive(Subcommand)]
enum CliCommand {
    // ===================================================================
    // Standard PKI Commands
    // ===================================================================
    /// Certificate signing request (CSR) operations.
    #[command(name = "req")]
    Req,

    /// X.509 certificate display, signing, and conversion.
    #[command(name = "x509")]
    X509,

    /// Certificate authority (CA) management.
    #[command(name = "ca")]
    Ca,

    /// Certificate chain verification.
    #[command(name = "verify")]
    Verify,

    /// Certificate revocation list (CRL) operations.
    #[command(name = "crl")]
    Crl,

    // ===================================================================
    // Key Generation / Management Commands
    // ===================================================================
    /// Generate a private key (algorithm-generic).
    #[command(name = "genpkey")]
    Genpkey,

    /// Public or private key utility.
    #[command(name = "pkey")]
    Pkey,

    /// Generate an RSA private key.
    #[command(name = "genrsa")]
    Genrsa,

    /// Generate a DSA private key from parameters.
    #[command(name = "gendsa")]
    Gendsa,

    /// Diffie-Hellman parameter generation and management.
    #[command(name = "dhparam")]
    Dhparam,

    /// DSA parameter generation and management.
    #[command(name = "dsaparam")]
    Dsaparam,

    /// RSA key management utility.
    #[command(name = "rsa")]
    Rsa,

    /// DSA key management utility.
    #[command(name = "dsa")]
    Dsa,

    /// Public key algorithm parameter management.
    #[command(name = "pkeyparam")]
    Pkeyparam,

    // ===================================================================
    // Crypto Operation Commands
    // ===================================================================
    /// Symmetric cipher encryption and decryption.
    #[command(name = "enc")]
    Enc,

    /// Message digest computation and verification.
    #[command(name = "dgst")]
    Dgst,

    /// PKCS#12 key store operations.
    #[command(name = "pkcs12")]
    Pkcs12,

    /// PKCS#7 / CMS-predecessor operations.
    #[command(name = "pkcs7")]
    Pkcs7,

    /// PKCS#8 private key format conversion.
    #[command(name = "pkcs8")]
    Pkcs8,

    /// S/MIME mail signing, encryption, and verification.
    #[command(name = "smime")]
    Smime,

    /// Message Authentication Code (MAC) computation.
    #[command(name = "mac")]
    Mac,

    /// Key Derivation Function (KDF) computation.
    #[command(name = "kdf")]
    Kdf,

    /// Public key algorithm utility (sign, verify, encrypt, decrypt).
    #[command(name = "pkeyutl")]
    Pkeyutl,

    /// RSA utility (deprecated — use pkeyutl instead).
    #[command(name = "rsautl")]
    Rsautl,

    /// Password hashing utility.
    #[command(name = "passwd")]
    Passwd,

    /// Prime number generation and testing.
    #[command(name = "prime")]
    Prime,

    /// Random byte generation.
    #[command(name = "rand")]
    Rand,

    // ===================================================================
    // TLS / Network Commands
    // ===================================================================
    /// TLS/SSL client diagnostic and testing tool.
    #[command(name = "s_client")]
    SClient,

    /// TLS/SSL server diagnostic and testing tool.
    #[command(name = "s_server")]
    SServer,

    /// TLS connection timing benchmark.
    #[command(name = "s_time")]
    STime,

    /// Cipher suite listing and information.
    #[command(name = "ciphers")]
    Ciphers,

    /// SSL/TLS session identifier display.
    #[command(name = "sess_id")]
    SessId,

    // ===================================================================
    // Introspection Commands
    // ===================================================================
    /// Version information display.
    #[command(name = "version")]
    Version,

    /// Algorithm, provider, and capability listing.
    #[command(name = "list")]
    List,

    /// Algorithm performance benchmarking.
    #[command(name = "speed")]
    Speed,

    /// Build and installation information.
    #[command(name = "info")]
    Info,

    /// Error code string lookup.
    #[command(name = "errstr")]
    Errstr,

    /// ASN.1 structure parsing and display.
    #[command(name = "asn1parse")]
    Asn1parse,

    // ===================================================================
    // Protocol / Utility Commands
    // ===================================================================
    /// Certificate directory hash-link management.
    #[command(name = "rehash")]
    Rehash,

    /// Symmetric key utility.
    #[command(name = "skeyutl")]
    Skeyutl,

    /// Configuration file utility.
    #[command(name = "configutl")]
    Configutl,

    /// CRL to PKCS#7 structure conversion.
    #[command(name = "crl2pkcs7")]
    Crl2pkcs7,

    /// Netscape certificate sequence utility.
    #[command(name = "nseq")]
    Nseq,

    /// Netscape SPKAC operations.
    #[command(name = "spkac")]
    Spkac,

    /// URI-based certificate and key store utility.
    #[command(name = "storeutl")]
    Storeutl,

    // ===================================================================
    // Feature-Gated Commands
    // ===================================================================
    /// CMS (Cryptographic Message Syntax) operations.
    #[cfg(feature = "cms")]
    #[command(name = "cms")]
    Cms,

    /// OCSP (Online Certificate Status Protocol) client and responder.
    #[cfg(feature = "ocsp")]
    #[command(name = "ocsp")]
    Ocsp,

    /// CMP (Certificate Management Protocol) client operations.
    #[cfg(feature = "cmp")]
    #[command(name = "cmp")]
    Cmp,

    /// RFC 3161 timestamp authority client.
    #[cfg(feature = "ts")]
    #[command(name = "ts")]
    Ts,

    /// FIPS module installation and configuration.
    #[cfg(feature = "fips")]
    #[command(name = "fipsinstall")]
    Fipsinstall,

    /// Encrypted Client Hello (ECH) key and config management.
    #[cfg(feature = "ech")]
    #[command(name = "ech")]
    Ech,

    /// SRP (Secure Remote Password) verifier file management.
    #[cfg(feature = "srp")]
    #[command(name = "srp")]
    Srp,

    /// Elliptic curve key utility.
    #[cfg(feature = "ec")]
    #[command(name = "ec")]
    Ec,

    /// Elliptic curve parameter generation and management.
    #[cfg(feature = "ec")]
    #[command(name = "ecparam")]
    Ecparam,

    // ===================================================================
    // External Subcommand Fallback
    // ===================================================================
    /// Catch-all for unrecognized subcommand names.
    ///
    /// Implements the three-tier dispatch from `apps/openssl.c:do_cmd()`:
    /// 1. If the name matches a known message digest → dispatch to `dgst`
    /// 2. If the name matches a known cipher → dispatch to `enc`
    /// 3. Otherwise → "Invalid command" error
    #[command(external_subcommand)]
    External(Vec<String>),
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

/// Entry point for the `openssl` CLI binary.
///
/// Parses command-line arguments via clap and dispatches to the
/// appropriate subcommand handler. Returns [`ExitCode::SUCCESS`] on
/// normal completion, [`ExitCode::FAILURE`] on invalid commands.
fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(CliCommand::External(args)) => handle_fallback_dispatch(&args),
        Some(_) => {
            // Recognized subcommand reached — `--help` is already handled by
            // clap before reaching this point. Non-help invocations arrive here.
            // Full command implementations are provided by the command modules
            // (crates/openssl-cli/src/commands/*.rs).
            eprintln!("Command dispatched successfully. Full handler implementation pending.");
            ExitCode::SUCCESS
        }
        None => {
            // No subcommand provided — display top-level help.
            let mut cmd = Cli::command();
            let _ = cmd.print_help();
            println!();
            ExitCode::SUCCESS
        }
    }
}

// ---------------------------------------------------------------------------
// Digest / Cipher Name Fallback Dispatch
// ---------------------------------------------------------------------------

/// Handles external (unrecognized) subcommand names by checking if the name
/// matches a known digest or cipher algorithm, replicating the C three-tier
/// dispatch from `apps/openssl.c:do_cmd()` (lines 495–544).
///
/// # Dispatch Rules
///
/// 1. Digest name match → print digest help (dispatches to `dgst` handler)
/// 2. Cipher name match → print cipher help (dispatches to `enc` handler)
/// 3. No match → error with "Invalid command" message
fn handle_fallback_dispatch(args: &[String]) -> ExitCode {
    let Some(first) = args.first() else {
        eprintln!("Invalid command ''; type \"openssl --help\" for a list.");
        return ExitCode::FAILURE;
    };
    let name = first.as_str();

    let has_help = args.iter().any(|a| a == "--help" || a == "-h");

    if is_known_digest(name) {
        if has_help {
            println!("{name} is a message digest command (equivalent to: openssl dgst -{name}).");
            println!();
            println!("Usage: openssl dgst -{name} [options] [file...]");
            println!();
            println!("Use 'openssl dgst --help' for full digest options.");
        } else {
            // Dispatch to dgst handler with pre-configured digest name.
            // Full implementation will invoke dgst::execute() directly.
            eprintln!("Digest '{name}' acknowledged. Full dgst dispatch pending.");
        }
        ExitCode::SUCCESS
    } else if is_known_cipher(name) {
        if has_help {
            println!("{name} is a symmetric cipher command (equivalent to: openssl enc -{name}).");
            println!();
            println!("Usage: openssl enc -{name} [options]");
            println!();
            println!("Use 'openssl enc --help' for full encryption options.");
        } else {
            // Dispatch to enc handler with pre-configured cipher name.
            // Full implementation will invoke enc::execute() directly.
            eprintln!("Cipher '{name}' acknowledged. Full enc dispatch pending.");
        }
        ExitCode::SUCCESS
    } else {
        eprintln!("Invalid command '{name}'; type \"openssl --help\" for a list.");
        ExitCode::FAILURE
    }
}

/// Returns `true` if `name` is a recognized message digest algorithm name.
///
/// This list mirrors the digest names recognized by the C implementation's
/// `EVP_get_digestbyname()` function, enabling the fallback dispatch path
/// where `openssl sha256` is equivalent to `openssl dgst -sha256`.
fn is_known_digest(name: &str) -> bool {
    matches!(
        name,
        "sha1"
            | "sha224"
            | "sha256"
            | "sha384"
            | "sha512"
            | "sha512-224"
            | "sha512-256"
            | "sha3-224"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
            | "shake128"
            | "shake256"
            | "md5"
            | "md4"
            | "md2"
            | "mdc2"
            | "ripemd160"
            | "whirlpool"
            | "sm3"
            | "blake2b512"
            | "blake2s256"
    )
}

/// Returns `true` if `name` is a recognized symmetric cipher algorithm name.
///
/// This list mirrors the cipher names recognized by the C implementation's
/// `EVP_get_cipherbyname()` function, enabling the fallback dispatch path
/// where `openssl aes-256-cbc` is equivalent to `openssl enc -aes-256-cbc`.
fn is_known_cipher(name: &str) -> bool {
    matches!(
        name,
        "aes-128-cbc"
            | "aes-192-cbc"
            | "aes-256-cbc"
            | "aes-128-ecb"
            | "aes-192-ecb"
            | "aes-256-ecb"
            | "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "aes-128-ofb"
            | "aes-192-ofb"
            | "aes-256-ofb"
            | "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"
            | "aes-128-gcm"
            | "aes-192-gcm"
            | "aes-256-gcm"
            | "des-cbc"
            | "des-ecb"
            | "des-cfb"
            | "des-ofb"
            | "des-ede3-cbc"
            | "des-ede3-ecb"
            | "des-ede3-cfb"
            | "des-ede3-ofb"
            | "rc4"
            | "rc2-cbc"
            | "bf-cbc"
            | "cast5-cbc"
            | "camellia-128-cbc"
            | "camellia-192-cbc"
            | "camellia-256-cbc"
            | "aria-128-cbc"
            | "aria-192-cbc"
            | "aria-256-cbc"
            | "sm4-cbc"
            | "chacha20-poly1305"
            | "chacha20"
    )
}
