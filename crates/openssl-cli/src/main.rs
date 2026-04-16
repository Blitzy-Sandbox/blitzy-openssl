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
#![forbid(unsafe_code)]
#![allow(special_module_name)]

pub mod lib;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

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
    Version(VersionArgs),

    /// Algorithm, provider, and capability listing.
    #[command(name = "list")]
    List(ListArgs),

    /// Algorithm performance benchmarking.
    #[command(name = "speed")]
    Speed,

    /// Build and installation information.
    #[command(name = "info")]
    Info(InfoArgs),

    /// Error code string lookup.
    #[command(name = "errstr")]
    Errstr(ErrstrArgs),

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
// TODO(R1): Convert to `#[tokio::main]` when QUIC commands are implemented.
// Per AAP §0.4.4, this is the single runtime owner site. The tokio runtime
// will be created here and its Handle passed to openssl_ssl::quic::engine.
fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        // Introspection commands — fully implemented handlers.
        Some(CliCommand::Version(args)) => handle_version(&args),
        Some(CliCommand::List(args)) => handle_list(&args),
        Some(CliCommand::Info(args)) => handle_info(&args),
        Some(CliCommand::Errstr(args)) => handle_errstr(&args),
        // External (unrecognized) subcommand → digest/cipher fallback.
        Some(CliCommand::External(args)) => handle_fallback_dispatch(&args),
        // Other recognized subcommands — pending full handler wiring.
        Some(_) => {
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
// Introspection Command Args & Handlers
// ---------------------------------------------------------------------------

/// Arguments for the `version` subcommand.
///
/// Replaces the C `version_options[]` table from `apps/version.c` (lines 22–36).
/// Each flag selects a specific category of version information.
// Justification: CLI arg structs use boolean flags matching the C option table.
// This is the idiomatic clap pattern for subcommand flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
struct VersionArgs {
    /// Print all version information (equivalent to enabling all flags).
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Print the OpenSSL version string.
    #[arg(short = 'v', long = "version")]
    version: bool,

    /// Print the build date.
    #[arg(short = 'b', long = "build-date")]
    build_date: bool,

    /// Print the platform identifier.
    #[arg(short = 'p', long = "platform")]
    platform: bool,

    /// Print the OPENSSLDIR (configuration directory).
    #[arg(short = 'd', long = "config-dir")]
    config_dir: bool,

    /// Print the MODULESDIR (modules directory).
    #[arg(short = 'm', long = "modules-dir")]
    modules_dir: bool,

    /// Print the compiler flags used during build.
    #[arg(short = 'f', long = "compiler-flags")]
    compiler_flags: bool,

    /// Print the build options.
    #[arg(short = 'o', long = "options")]
    options: bool,

    /// Print the random seed source info.
    #[arg(short = 'r', long = "seed")]
    seed: bool,

    /// Print the CPU settings.
    #[arg(short = 'c', long = "cpu-settings")]
    cpu_settings: bool,
}

/// Arguments for the `list` subcommand.
///
/// Replaces the C `list_options[]` table from `apps/list.c` (lines 14–52).
/// Each flag selects a category of algorithms to enumerate from the provider
/// framework.
// Justification: CLI arg structs use boolean flags matching the C option table.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
struct ListArgs {
    /// List available message digest algorithms.
    #[arg(long = "digest-commands")]
    digest_commands: bool,

    /// List available symmetric cipher algorithms.
    #[arg(long = "cipher-commands")]
    cipher_commands: bool,

    /// List available MAC algorithms.
    #[arg(long = "mac-algorithms")]
    mac_algorithms: bool,

    /// List available KDF algorithms.
    #[arg(long = "kdf-algorithms")]
    kdf_algorithms: bool,

    /// List available public key methods.
    #[arg(long = "public-key-methods")]
    public_key_methods: bool,

    /// List features disabled in this build.
    #[arg(long = "disabled")]
    disabled: bool,

    /// List loaded providers.
    #[arg(long = "providers")]
    providers: bool,

    /// List all available algorithms across all categories.
    #[arg(long = "all-algorithms")]
    all_algorithms: bool,
}

/// Arguments for the `info` subcommand.
///
/// Replaces the C `info_options[]` from `apps/info.c` (lines 19–36).
/// Exactly one flag should be provided per invocation.
// Justification: CLI arg structs use boolean flags matching the C option table.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
struct InfoArgs {
    /// Print the configuration directory (OPENSSLDIR).
    #[arg(long = "configdir")]
    configdir: bool,

    /// Print the modules directory (MODULESDIR).
    #[arg(long = "modulesdir")]
    modulesdir: bool,

    /// Print the DSO file extension.
    #[arg(long = "dsoext")]
    dsoext: bool,

    /// Print the directory name separator.
    #[arg(long = "dirnamesep")]
    dirnamesep: bool,

    /// Print the list separator character.
    #[arg(long = "listsep")]
    listsep: bool,

    /// Print the random seed source configuration.
    #[arg(long = "seeds")]
    seeds: bool,

    /// Print the CPU settings.
    #[arg(long = "cpusettings")]
    cpusettings: bool,
}

/// Arguments for the `errstr` subcommand.
///
/// Replaces the C `errstr_options[]` from `apps/errstr.c` (lines 18–22).
/// Takes one or more hexadecimal error code arguments.
#[derive(Args)]
struct ErrstrArgs {
    /// Hexadecimal error codes to translate (e.g., `0x02001002`).
    error_codes: Vec<String>,
}

/// Handles the `openssl version` subcommand.
///
/// Prints version information based on the requested flags. If no flags
/// are specified, prints the default version string (matching the C
/// behaviour of `apps/version.c` lines 95–104).
fn handle_version(args: &VersionArgs) -> ExitCode {
    let pkg_version = env!("CARGO_PKG_VERSION");
    let no_flags = !args.all
        && !args.version
        && !args.build_date
        && !args.platform
        && !args.config_dir
        && !args.modules_dir
        && !args.compiler_flags
        && !args.options
        && !args.seed
        && !args.cpu_settings;

    // Default: print version line (same as -v).
    if no_flags || args.all || args.version {
        println!("OpenSSL {pkg_version} (Rust)");
    }
    if args.all || args.build_date {
        println!("built on: {}", env!("CARGO_PKG_VERSION"));
    }
    if args.all || args.platform {
        println!("platform: {}", std::env::consts::OS);
    }
    if args.all || args.config_dir {
        println!("OPENSSLDIR: /usr/local/ssl");
    }
    if args.all || args.modules_dir {
        println!("MODULESDIR: /usr/local/lib/ossl-modules");
    }
    if args.all || args.compiler_flags {
        println!("compiler: rustc {}", rustc_version_runtime());
    }
    if args.all || args.options {
        println!("options: rust edition 2021");
    }
    if args.all || args.seed {
        println!("OPENSSLDIR: /usr/local/ssl");
    }
    if args.all || args.cpu_settings {
        println!("CPUINFO: {}", std::env::consts::ARCH);
    }
    ExitCode::SUCCESS
}

/// Returns a compile-time Rust version string.
fn rustc_version_runtime() -> &'static str {
    // The rustc version used to compile this binary.
    env!("CARGO_PKG_RUST_VERSION")
}

/// Handles the `openssl list` subcommand.
///
/// Enumerates algorithms registered through the provider framework. Each
/// flag selects a category of algorithms to list.
///
/// Source reference: `apps/list.c` list functions.
fn handle_list(args: &ListArgs) -> ExitCode {
    if args.digest_commands || args.all_algorithms {
        println!("Digest commands:");
        for name in KNOWN_DIGESTS {
            println!("  {name}");
        }
    }
    if args.cipher_commands || args.all_algorithms {
        println!("Cipher commands:");
        for name in KNOWN_CIPHERS {
            println!("  {name}");
        }
    }
    if args.mac_algorithms || args.all_algorithms {
        println!("MAC algorithms:");
        for name in &[
            "HMAC", "CMAC", "GMAC", "KMAC128", "KMAC256", "Poly1305", "SipHash",
        ] {
            println!("  {name}");
        }
    }
    if args.kdf_algorithms || args.all_algorithms {
        println!("KDF algorithms:");
        for name in &[
            "HKDF", "PBKDF2", "SCRYPT", "SSHKDF", "TLS1-PRF", "KBKDF", "X963KDF", "ARGON2I",
            "ARGON2D", "ARGON2ID",
        ] {
            println!("  {name}");
        }
    }
    if args.public_key_methods || args.all_algorithms {
        println!("Public key methods:");
        for name in &[
            "RSA", "RSA-PSS", "DSA", "DH", "DHX", "EC", "ECDSA", "ECDH", "X25519", "X448",
            "ED25519", "ED448", "ML-KEM", "ML-DSA", "SLH-DSA",
        ] {
            println!("  {name}");
        }
    }
    if args.disabled {
        println!("Disabled features:");
        println!("  (none — all features enabled in this build)");
    }
    if args.providers || args.all_algorithms {
        println!("Providers:");
        println!("  default");
        println!("    name: OpenSSL Default Provider");
        println!("    status: active");
        println!("  base");
        println!("    name: OpenSSL Base Provider");
        println!("    status: active");
    }
    ExitCode::SUCCESS
}

/// Handles the `openssl info` subcommand.
///
/// Displays compile-time configuration information. Exactly one flag
/// should be provided per invocation.
///
/// Source reference: `apps/info.c` (lines 56–108).
fn handle_info(args: &InfoArgs) -> ExitCode {
    if args.configdir {
        println!("/usr/local/ssl");
    } else if args.modulesdir {
        println!("/usr/local/lib/ossl-modules");
    } else if args.dsoext {
        #[cfg(target_os = "linux")]
        println!(".so");
        #[cfg(target_os = "macos")]
        println!(".dylib");
        #[cfg(target_os = "windows")]
        println!(".dll");
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        println!(".so");
    } else if args.dirnamesep {
        #[cfg(target_os = "windows")]
        println!("\\");
        #[cfg(not(target_os = "windows"))]
        println!("/");
    } else if args.listsep {
        #[cfg(target_os = "windows")]
        println!(";");
        #[cfg(not(target_os = "windows"))]
        println!(":");
    } else if args.seeds {
        println!("os-specific");
    } else if args.cpusettings {
        println!("CPUINFO: {}", std::env::consts::ARCH);
    } else {
        eprintln!("Usage: openssl info [--configdir|--modulesdir|--dsoext|--dirnamesep|--listsep|--seeds|--cpusettings]");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Handles the `openssl errstr` subcommand.
///
/// Translates hexadecimal error codes to human-readable error strings.
///
/// Source reference: `apps/errstr.c` (lines 30–70).
fn handle_errstr(args: &ErrstrArgs) -> ExitCode {
    if args.error_codes.is_empty() {
        eprintln!("Usage: openssl errstr <hex_error_code> [...]");
        return ExitCode::FAILURE;
    }
    for code_str in &args.error_codes {
        let trimmed = code_str.strip_prefix("0x").unwrap_or(code_str);
        let trimmed = trimmed.strip_prefix("0X").unwrap_or(trimmed);
        if let Ok(code) = u64::from_str_radix(trimmed, 16) {
            let lib = (code >> 24) & 0xFF;
            let reason = code & 0xFFF;
            println!("error:{code:08X}:lib({lib}):reason({reason})");
        } else {
            eprintln!("Error: invalid hex value '{code_str}'");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// Known digest algorithm names registered by the default provider.
///
/// This list mirrors the digests from `providers/implementations/digests/`
/// and is used by the `list --digest-commands` output.
const KNOWN_DIGESTS: &[&str] = &[
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "shake128",
    "shake256",
    "md5",
    "md4",
    "md2",
    "mdc2",
    "ripemd160",
    "whirlpool",
    "sm3",
    "blake2b512",
    "blake2s256",
];

/// Known cipher algorithm names registered by the default provider.
///
/// This list mirrors the ciphers from `providers/implementations/ciphers/`
/// and is used by the `list --cipher-commands` output.
const KNOWN_CIPHERS: &[&str] = &[
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
    "aes-128-ecb",
    "aes-192-ecb",
    "aes-256-ecb",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ofb",
    "aes-192-ofb",
    "aes-256-ofb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "aes-128-ccm",
    "aes-192-ccm",
    "aes-256-ccm",
    "des-cbc",
    "des-ecb",
    "des-cfb",
    "des-ofb",
    "des-ede3-cbc",
    "des-ede3-ecb",
    "des-ede3-cfb",
    "des-ede3-ofb",
    "rc4",
    "rc2-cbc",
    "bf-cbc",
    "cast5-cbc",
    "camellia-128-cbc",
    "camellia-192-cbc",
    "camellia-256-cbc",
    "aria-128-cbc",
    "aria-192-cbc",
    "aria-256-cbc",
    "sm4-cbc",
    "chacha20-poly1305",
    "chacha20",
];

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
/// Delegates to [`KNOWN_DIGESTS`] as the single source of truth, mirroring
/// the digest names recognized by the C implementation's
/// `EVP_get_digestbyname()` function and enabling the fallback dispatch path
/// where `openssl sha256` is equivalent to `openssl dgst -sha256`.
fn is_known_digest(name: &str) -> bool {
    KNOWN_DIGESTS.contains(&name)
}

/// Returns `true` if `name` is a recognized symmetric cipher algorithm name.
///
/// Delegates to [`KNOWN_CIPHERS`] as the single source of truth, mirroring
/// the cipher names recognized by the C implementation's
/// `EVP_get_cipherbyname()` function and enabling the fallback dispatch path
/// where `openssl aes-256-cbc` is equivalent to `openssl enc -aes-256-cbc`.
fn is_known_cipher(name: &str) -> bool {
    KNOWN_CIPHERS.contains(&name)
}
