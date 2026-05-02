// Allow deprecated items: the SRP command (and potentially future deprecated
// commands) is intentionally included in the dispatch enum. The `#[deprecated]`
// attribute on `SrpArgs` is required by design to warn external callers, but the
// command dispatch hub must reference it without triggering build failures under
// `RUSTFLAGS="-D warnings"`.
#![allow(deprecated)]

//! CLI subcommand definitions for the OpenSSL command-line tool.
//!
//! This module is the **foundational dispatch hub** for the `openssl` CLI binary,
//! replacing the C `functions[]` dispatch table from `apps/include/function.h` and
//! the `LHASH_OF(FUNCTION)` lookup from `apps/openssl.c:prog_init()`.
//!
//! # Architecture
//!
//! Each public submodule corresponds to a C source file in `apps/*.c` and provides:
//! - A clap-derived `Args` struct for argument parsing (replacing C `opt_init`/`opt_next`)
//! - An `execute()` method for command logic (replacing C `*_main()` entry points)
//!
//! The central [`CliCommand`] enum uses `#[derive(clap::Subcommand)]` to generate
//! automatic argument routing, replacing the manual string-based dispatch in C.
//!
//! # Feature Gates
//!
//! Feature-gated modules use `#[cfg(feature = "...")]` matching Cargo feature flags
//! defined in `Cargo.toml`, replacing the C `OPENSSL_NO_*` preprocessor guards.
//! Feature gates are applied consistently across three sites:
//! 1. Module declaration (`pub mod`)
//! 2. Enum variant
//! 3. Match arm in `execute()`
//!
//! # Rule Compliance
//!
//! - **R5 (Nullability):** `Option<T>` used in Args structs; no sentinel values
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this file or submodules
//! - **R9 (Warning-Free):** All modules used; no dead code; feature gates consistent
//! - **R10 (Wiring Before Done):** Every variant dispatches to `execute()`; reachable
//!   from `main.rs → CliCommand::execute()` via clap subcommand routing

// ============================================================================
// PKI / Certificate Commands
// ============================================================================

/// Certificate Authority management — replaces `apps/ca.c`.
pub mod ca;
/// CRL inspection and generation — replaces `apps/crl.c`.
pub mod crl;
/// Certificate signing request (CSR) operations — replaces `apps/req.c`.
pub mod req;
/// Certificate chain verification — replaces `apps/verify.c`.
pub mod verify;
/// X.509 certificate display, signing, and conversion — replaces `apps/x509.c`.
pub mod x509;

// ============================================================================
// Key Generation / Management Commands
// ============================================================================

/// DH parameter generation and management — replaces `apps/dhparam.c`.
pub mod dhparam;
/// DSA key processing — replaces `apps/dsa.c`.
pub mod dsa;
/// DSA parameter generation — replaces `apps/dsaparam.c`.
pub mod dsaparam;
/// EC key processing — replaces `apps/ec.c`.
#[cfg(feature = "ec")]
pub mod ec;
/// EC parameter generation — replaces `apps/ecparam.c`.
#[cfg(feature = "ec")]
pub mod ecparam;
/// Generate DSA key from parameters — replaces `apps/gendsa.c`.
pub mod gendsa;
/// Generate private keys or key parameters — replaces `apps/genpkey.c`.
pub mod genpkey;
/// Generate RSA private key — replaces `apps/genrsa.c`.
pub mod genrsa;
/// Public/private key processing — replaces `apps/pkey.c`.
pub mod pkey;
/// Algorithm parameter round-trip — replaces `apps/pkeyparam.c`.
pub mod pkeyparam;
/// RSA key processing — replaces `apps/rsa.c`.
pub mod rsa;

// ============================================================================
// Crypto Operation Commands
// ============================================================================

/// CMS (Cryptographic Message Syntax) operations — replaces `apps/cms.c`.
#[cfg(feature = "cms")]
pub mod cms;
/// Message digest/signature generation and verification — replaces `apps/dgst.c`.
pub mod dgst;
/// Symmetric cipher encryption/decryption — replaces `apps/enc.c`.
pub mod enc;
/// Key derivation function execution — replaces `apps/kdf.c`.
pub mod kdf;
/// MAC computation — replaces `apps/mac.c`.
pub mod mac;
/// Password hashing — replaces `apps/passwd.c`.
pub mod passwd;
/// PKCS#12 file operations — replaces `apps/pkcs12.c`.
pub mod pkcs12;
/// PKCS#7 data processing — replaces `apps/pkcs7.c`.
pub mod pkcs7;
/// PKCS#8 private key conversion — replaces `apps/pkcs8.c`.
pub mod pkcs8;
/// Public key algorithm utility — replaces `apps/pkeyutl.c`.
pub mod pkeyutl;
/// Prime number generation and testing — replaces `apps/prime.c`.
pub mod prime;
/// Random data generation — replaces `apps/rand.c`.
pub mod rand;
/// RSA utility (legacy, deprecated) — replaces `apps/rsautl.c`.
pub mod rsautl;
/// S/MIME mail operations — replaces `apps/smime.c`.
pub mod smime;

// ============================================================================
// TLS / Network Test Commands
// ============================================================================

/// Cipher suite listing — replaces `apps/ciphers.c`.
pub mod ciphers;
/// TLS/DTLS/QUIC client — replaces `apps/s_client.c`.
pub mod s_client;
/// TLS/DTLS/QUIC server — replaces `apps/s_server.c`.
pub mod s_server;
/// TLS connection timing benchmark — replaces `apps/s_time.c`.
pub mod s_time;
/// SSL/TLS session data management — replaces `apps/sess_id.c`.
pub mod sess_id;

// ============================================================================
// Introspection / Info Commands
// ============================================================================

/// ASN.1 data parsing and display — replaces `apps/asn1parse.c`.
pub mod asn1parse;
/// Translate error codes to strings — replaces `apps/errstr.c`.
pub mod errstr;
/// Display build information — replaces `apps/info.c`.
pub mod info;
/// List algorithms, providers, and capabilities — replaces `apps/list.c`.
pub mod list;
/// Cryptographic algorithm benchmark — replaces `apps/speed.c`.
pub mod speed;
/// Display version information — replaces `apps/version.c`.
pub mod version;

// ============================================================================
// Protocol-Specific Commands (Feature-Gated)
// ============================================================================

/// Certificate Management Protocol client — replaces `apps/cmp.c`.
#[cfg(feature = "cmp")]
pub mod cmp;
/// OCSP client and responder — replaces `apps/ocsp.c`.
#[cfg(feature = "ocsp")]
pub mod ocsp;
/// RFC 3161 Time Stamp Authority operations — replaces `apps/ts.c`.
#[cfg(feature = "ts")]
pub mod ts;

// ============================================================================
// Utility Commands
// ============================================================================

/// Configuration file expansion — replaces `apps/configutl.c`.
pub mod configutl;
/// ECH configuration management — replaces `apps/ech.c`.
#[cfg(feature = "ech")]
pub mod ech;
/// FIPS module installation and configuration — replaces `apps/fipsinstall.c`.
#[cfg(feature = "fips")]
pub mod fipsinstall;
/// Certificate directory hash link creation — replaces `apps/rehash.c`.
pub mod rehash;
/// Symmetric key generation utility — replaces `apps/skeyutl.c`.
pub mod skeyutl;

// ============================================================================
// Legacy / Miscellaneous Commands
// ============================================================================

/// Package CRL/certs into PKCS#7 — replaces `apps/crl2pkcs7.c`.
pub mod crl2pkcs7;
/// Netscape certificate sequence conversion — replaces `apps/nseq.c`.
pub mod nseq;
/// SPKAC handling — replaces `apps/spkac.c`.
pub mod spkac;
/// SRP verifier database management (deprecated) — replaces `apps/srp.c`.
#[cfg(feature = "srp")]
pub mod srp;
/// OSSL_STORE URI loading utility — replaces `apps/storeutl.c`.
pub mod storeutl;

// ============================================================================
// Imports
// ============================================================================

use clap::Subcommand;
use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;

// ============================================================================
// CliCommand Enum — Central Dispatch
// ============================================================================

/// All CLI subcommands available in the `openssl` tool.
///
/// Each variant wraps the clap-derived `Args` struct from its corresponding
/// module, enabling automatic argument parsing and help generation. This enum
/// replaces the C `FUNCTION` struct array from `apps/include/function.h` and
/// the `LHASH_OF(FUNCTION)` dispatch mechanism from `apps/openssl.c`.
///
/// # Dispatch Flow
///
/// ```text
/// main() → Cli::parse() → CliCommand variant → args.execute(ctx)
/// ```
///
/// # Feature Gates
///
/// Variants guarded by `#[cfg(feature = "...")]` are only compiled when the
/// corresponding Cargo feature is enabled. This mirrors the C preprocessor
/// pattern: `#ifndef OPENSSL_NO_<FEATURE>`.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CliCommand {
    // ===================================================================
    // PKI / Certificate Commands
    // ===================================================================
    /// Certificate signing request (CSR) operations
    #[command(name = "req")]
    Req(req::ReqArgs),

    /// X.509 certificate display, signing, and conversion
    #[command(name = "x509")]
    X509(x509::X509Args),

    /// Certificate authority (CA) management
    #[command(name = "ca")]
    Ca(ca::CaArgs),

    /// Certificate chain verification
    #[command(name = "verify")]
    Verify(verify::VerifyArgs),

    /// Certificate revocation list (CRL) operations
    #[command(name = "crl")]
    Crl(crl::CrlArgs),

    // ===================================================================
    // Key Generation / Management Commands
    // ===================================================================
    /// Generate a private key (algorithm-generic)
    #[command(name = "genpkey")]
    Genpkey(genpkey::GenpkeyArgs),

    /// Public or private key utility
    #[command(name = "pkey")]
    Pkey(pkey::PkeyArgs),

    /// Generate an RSA private key
    #[command(name = "genrsa")]
    Genrsa(genrsa::GenrsaArgs),

    /// Generate a DSA private key from parameters
    #[command(name = "gendsa")]
    Gendsa(gendsa::GendsaArgs),

    /// Diffie-Hellman parameter generation and management
    #[command(name = "dhparam")]
    Dhparam(dhparam::DhparamArgs),

    /// DSA parameter generation and management
    #[command(name = "dsaparam")]
    Dsaparam(dsaparam::DsaparamArgs),

    /// RSA key management utility
    #[command(name = "rsa")]
    Rsa(rsa::RsaArgs),

    /// DSA key management utility
    #[command(name = "dsa")]
    Dsa(dsa::DsaArgs),

    /// Public key algorithm parameter management
    #[command(name = "pkeyparam")]
    Pkeyparam(pkeyparam::PkeyparamArgs),

    // ===================================================================
    // Crypto Operation Commands
    // ===================================================================
    /// Symmetric cipher encryption and decryption
    #[command(name = "enc")]
    Enc(enc::EncArgs),

    /// Message digest computation and verification
    #[command(name = "dgst")]
    Dgst(dgst::DgstArgs),

    /// PKCS#12 key store operations
    #[command(name = "pkcs12")]
    Pkcs12(pkcs12::Pkcs12Args),

    /// PKCS#7 / CMS-predecessor operations
    #[command(name = "pkcs7")]
    Pkcs7(pkcs7::Pkcs7Args),

    /// PKCS#8 private key format conversion
    #[command(name = "pkcs8")]
    Pkcs8(pkcs8::Pkcs8Args),

    /// S/MIME mail signing, encryption, and verification
    #[command(name = "smime")]
    Smime(smime::SmimeArgs),

    /// Message Authentication Code (MAC) computation
    #[command(name = "mac")]
    Mac(mac::MacArgs),

    /// Key Derivation Function (KDF) computation
    #[command(name = "kdf")]
    Kdf(kdf::KdfArgs),

    /// Public key algorithm utility (sign, verify, encrypt, decrypt)
    #[command(name = "pkeyutl")]
    Pkeyutl(pkeyutl::PkeyutlArgs),

    /// RSA utility (deprecated — use pkeyutl instead)
    #[command(name = "rsautl")]
    Rsautl(rsautl::RsautlArgs),

    /// Password hashing utility
    #[command(name = "passwd")]
    Passwd(passwd::PasswdArgs),

    /// Prime number generation and testing
    #[command(name = "prime")]
    Prime(prime::PrimeArgs),

    /// Random byte generation
    #[command(name = "rand")]
    Rand(rand::RandArgs),

    // ===================================================================
    // TLS / Network Test Commands
    // ===================================================================
    /// TLS/SSL client diagnostic and testing tool
    #[command(name = "s_client")]
    SClient(s_client::SClientArgs),

    /// TLS/SSL server diagnostic and testing tool
    #[command(name = "s_server")]
    SServer(s_server::SServerArgs),

    /// TLS connection timing benchmark
    #[command(name = "s_time")]
    STime(s_time::STimeArgs),

    /// Cipher suite listing and information
    #[command(name = "ciphers")]
    Ciphers(ciphers::CiphersArgs),

    /// SSL/TLS session identifier display
    #[command(name = "sess_id")]
    SessId(sess_id::SessIdArgs),

    // ===================================================================
    // Introspection / Info Commands
    // ===================================================================
    /// Version information display
    #[command(name = "version")]
    Version(version::VersionArgs),

    /// Algorithm, provider, and capability listing
    #[command(name = "list")]
    List(list::ListArgs),

    /// Algorithm performance benchmarking
    #[command(name = "speed")]
    Speed(speed::SpeedArgs),

    /// Build and installation information
    #[command(name = "info")]
    Info(info::InfoArgs),

    /// Error code string lookup
    #[command(name = "errstr")]
    Errstr(errstr::ErrstrArgs),

    /// ASN.1 structure parsing and display
    #[command(name = "asn1parse")]
    Asn1parse(asn1parse::Asn1parseArgs),

    // ===================================================================
    // Utility Commands
    // ===================================================================
    /// Certificate directory hash-link management
    #[command(name = "rehash")]
    Rehash(rehash::RehashArgs),

    /// Symmetric key utility
    #[command(name = "skeyutl")]
    Skeyutl(skeyutl::SkeyutlArgs),

    /// Configuration file utility
    #[command(name = "configutl")]
    Configutl(configutl::ConfigutlArgs),

    /// CRL to PKCS#7 structure conversion
    #[command(name = "crl2pkcs7")]
    Crl2pkcs7(crl2pkcs7::Crl2pkcs7Args),

    /// Netscape certificate sequence utility
    #[command(name = "nseq")]
    Nseq(nseq::NseqArgs),

    /// Netscape SPKAC operations
    #[command(name = "spkac")]
    Spkac(spkac::SpkacArgs),

    /// URI-based certificate and key store utility
    #[command(name = "storeutl")]
    Storeutl(storeutl::StoreutlArgs),

    // ===================================================================
    // Protocol-Specific Commands (Feature-Gated)
    // ===================================================================
    /// CMS (Cryptographic Message Syntax) operations
    #[cfg(feature = "cms")]
    #[command(name = "cms")]
    Cms(cms::CmsArgs),

    /// OCSP (Online Certificate Status Protocol) client and responder
    #[cfg(feature = "ocsp")]
    #[command(name = "ocsp")]
    Ocsp(ocsp::OcspArgs),

    /// CMP (Certificate Management Protocol) client operations
    #[cfg(feature = "cmp")]
    #[command(name = "cmp")]
    Cmp(cmp::CmpArgs),

    /// RFC 3161 timestamp authority client
    #[cfg(feature = "ts")]
    #[command(name = "ts")]
    Ts(ts::TsArgs),

    // ===================================================================
    // Specialized / Compliance Commands
    // ===================================================================
    /// FIPS module installation and configuration
    #[cfg(feature = "fips")]
    #[command(name = "fipsinstall")]
    Fipsinstall(fipsinstall::FipsinstallArgs),

    /// Encrypted Client Hello (ECH) key and config management
    #[cfg(feature = "ech")]
    #[command(name = "ech")]
    Ech(ech::EchArgs),

    /// SRP (Secure Remote Password) verifier file management
    #[cfg(feature = "srp")]
    #[command(name = "srp")]
    Srp(Box<srp::SrpArgs>),

    /// Elliptic curve key utility
    #[cfg(feature = "ec")]
    #[command(name = "ec")]
    Ec(ec::EcArgs),

    /// Elliptic curve parameter generation and management
    #[cfg(feature = "ec")]
    #[command(name = "ecparam")]
    Ecparam(ecparam::EcparamArgs),
}

// ============================================================================
// CliCommand Dispatch Implementation
// ============================================================================

impl CliCommand {
    /// Execute the selected subcommand.
    ///
    /// This is the central dispatch point called from `main()` after clap
    /// argument parsing. Each variant delegates to the corresponding module's
    /// `Args::execute()` method, passing the library context for provider
    /// and algorithm access.
    ///
    /// # Arguments
    ///
    /// * `ctx` — The library context ([`LibContext`]) providing access to
    ///   loaded providers, algorithm registries, and configuration. This is
    ///   the Rust equivalent of C's `OSSL_LIB_CTX` passed through the
    ///   entire dispatch chain.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the subcommand execution fails. Each
    /// subcommand propagates its specific errors through the `?` operator,
    /// which are then handled by `main()` for exit code and error display.
    ///
    /// # Async
    ///
    /// The method is `async` to support QUIC-based commands (`s_client`,
    /// `s_server`) that require async I/O via the tokio runtime. Synchronous
    /// commands return immediately from their `.await` point.
    pub async fn execute(&self, ctx: &LibContext) -> Result<(), CryptoError> {
        match self {
            // PKI / Certificate commands
            Self::Req(args) => args.execute(ctx).await,
            Self::X509(args) => args.execute(ctx).await,
            Self::Ca(args) => args.execute(ctx).await,
            Self::Verify(args) => args.execute(ctx).await,
            Self::Crl(args) => args.execute(ctx).await,

            // Key generation / management
            Self::Genpkey(args) => args.execute(ctx).await,
            Self::Pkey(args) => args.execute(ctx).await,
            Self::Genrsa(args) => args.execute(ctx).await,
            Self::Gendsa(args) => args.execute(ctx).await,
            Self::Dhparam(args) => args.execute(ctx).await,
            Self::Dsaparam(args) => args.execute(ctx).await,
            Self::Rsa(args) => args.execute(ctx).await,
            Self::Dsa(args) => args.execute(ctx).await,
            Self::Pkeyparam(args) => args.execute(ctx).await,

            // Crypto operations
            Self::Enc(args) => args.execute(ctx).await,
            Self::Dgst(args) => args.execute(ctx).await,
            Self::Pkcs12(args) => args.execute(ctx).await,
            Self::Pkcs7(args) => args.execute(ctx).await,
            Self::Pkcs8(args) => args.execute(ctx).await,
            Self::Smime(args) => args.execute(ctx).await,
            Self::Mac(args) => args.execute(ctx).await,
            Self::Kdf(args) => args.execute(ctx).await,
            Self::Pkeyutl(args) => args.execute(ctx).await,
            Self::Rsautl(args) => args.execute(ctx).await,
            Self::Passwd(args) => args.execute(ctx).await,
            Self::Prime(args) => args.execute(ctx).await,
            Self::Rand(args) => args.execute(ctx).await,

            // TLS / network test commands
            Self::SClient(args) => args.execute(ctx).await,
            Self::SServer(args) => args.execute(ctx).await,
            Self::STime(args) => args.execute(ctx).await,
            Self::Ciphers(args) => args.execute(ctx).await,
            Self::SessId(args) => args.execute(ctx).await,

            // Introspection / info commands
            Self::Version(args) => args.execute(ctx).await,
            Self::List(args) => args.execute(ctx).await,
            Self::Speed(args) => args.execute(ctx).await,
            Self::Info(args) => args.execute(ctx).await,
            Self::Errstr(args) => args.execute(ctx).await,
            Self::Asn1parse(args) => args.execute(ctx).await,

            // Utility commands
            Self::Rehash(args) => args.execute(ctx).await,
            Self::Skeyutl(args) => args.execute(ctx).await,
            Self::Configutl(args) => args.execute(ctx).await,
            Self::Crl2pkcs7(args) => args.execute(ctx).await,
            Self::Nseq(args) => args.execute(ctx).await,
            Self::Spkac(args) => args.execute(ctx).await,
            Self::Storeutl(args) => args.execute(ctx).await,

            // Protocol-specific (feature-gated)
            #[cfg(feature = "cms")]
            Self::Cms(args) => args.execute(ctx).await,
            #[cfg(feature = "ocsp")]
            Self::Ocsp(args) => args.execute(ctx).await,
            #[cfg(feature = "cmp")]
            Self::Cmp(args) => args.execute(ctx).await,
            #[cfg(feature = "ts")]
            Self::Ts(args) => args.execute(ctx).await,

            // Specialized / compliance commands (feature-gated)
            #[cfg(feature = "fips")]
            Self::Fipsinstall(args) => args.execute(ctx).await,
            #[cfg(feature = "ech")]
            Self::Ech(args) => args.execute(ctx).await,
            #[cfg(feature = "srp")]
            Self::Srp(args) => args.execute(ctx).await,
            #[cfg(feature = "ec")]
            Self::Ec(args) => args.execute(ctx).await,
            #[cfg(feature = "ec")]
            Self::Ecparam(args) => args.execute(ctx).await,
        }
    }
}
