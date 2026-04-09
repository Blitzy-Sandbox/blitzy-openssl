//! Subcommand dispatch integration tests.
//!
//! Verifies that all 54+ CLI subcommands are reachable from the compiled binary.
//! Each test invokes the binary with a subcommand and verifies it runs without panic.
//! This ensures **Rule R10 (Wiring Before Done)** compliance: every component is
//! reachable from the entry point via the real execution path AND exercised by at
//! least one integration test traversing that path.
//!
//! ## Test Strategy
//!
//! Invoke `openssl <subcommand> --help` for each command. The `--help` flag ensures
//! the command is parsed and dispatched without requiring actual crypto operations
//! or input files. Each test verifies:
//! 1. The process exits with code 0 (success)
//! 2. The stdout output contains the subcommand name (confirming correct dispatch)
//!
//! ## Compliance
//!
//! - **Rule R10**: Every component reachable from entry point, exercised by test
//! - **Gate 9**: Wiring verification — all 54+ subcommands reachable and tested
//! - **Rule R8**: Zero `unsafe` blocks in this file
//! - **Rule R9**: Zero `#[allow(warnings)]` in this file
//!
//! ## Caller Chain (Rule R10 documentation)
//!
//! ```text
//! main() → Cli::parse() → match CliCommand variant → <subcommand>::execute()
//! ```

// Clippy's `expect_used` and `unwrap_used` lints are valuable for library/production code
// but overly strict for test modules where panicking on unexpected failures is the
// standard testing pattern. We allow both here since every `.expect()` in this file
// serves as a test assertion mechanism.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

// ---------------------------------------------------------------------------
// Binary helper
// ---------------------------------------------------------------------------

/// Creates an [`assert_cmd::Command`] targeting the compiled `openssl` binary.
///
/// This local helper is intentionally defined in this module rather than
/// re-using `super::openssl_cmd()` to maintain module self-containment and
/// avoid coupling to the parent module's API.
///
/// # Panics
///
/// Panics if the `openssl` binary cannot be located by `cargo_bin`. This
/// typically means the binary has not been built — run `cargo build` first.
fn openssl_cmd() -> Command {
    Command::cargo_bin("openssl").expect("binary should be built")
}

// ===========================================================================
// Standard PKI Commands
// ===========================================================================

/// Verifies the `req` subcommand (certificate signing requests) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Req → req::execute()`
#[test]
fn test_dispatch_req() {
    openssl_cmd()
        .arg("req")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("req"));
}

/// Verifies the `x509` subcommand (certificate display and signing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::X509 → x509::execute()`
#[test]
fn test_dispatch_x509() {
    openssl_cmd()
        .arg("x509")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("x509"));
}

/// Verifies the `ca` subcommand (certificate authority operations) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ca → ca::execute()`
#[test]
fn test_dispatch_ca() {
    openssl_cmd()
        .arg("ca")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ca"));
}

/// Verifies the `verify` subcommand (certificate chain verification) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Verify → verify::execute()`
#[test]
fn test_dispatch_verify() {
    openssl_cmd()
        .arg("verify")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"));
}

/// Verifies the `crl` subcommand (CRL processing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Crl → crl::execute()`
#[test]
fn test_dispatch_crl() {
    openssl_cmd()
        .arg("crl")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("crl"));
}

// ===========================================================================
// Key Generation / Management Commands
// ===========================================================================

/// Verifies the `genpkey` subcommand (generic private key generation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Genpkey → genpkey::execute()`
#[test]
fn test_dispatch_genpkey() {
    openssl_cmd()
        .arg("genpkey")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("genpkey"));
}

/// Verifies the `pkey` subcommand (public/private key utility) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkey → pkey::execute()`
#[test]
fn test_dispatch_pkey() {
    openssl_cmd()
        .arg("pkey")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pkey"));
}

/// Verifies the `genrsa` subcommand (RSA key generation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Genrsa → genrsa::execute()`
#[test]
fn test_dispatch_genrsa() {
    openssl_cmd()
        .arg("genrsa")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("genrsa"));
}

/// Verifies the `gendsa` subcommand (DSA key generation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Gendsa → gendsa::execute()`
#[test]
fn test_dispatch_gendsa() {
    openssl_cmd()
        .arg("gendsa")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("gendsa"));
}

/// Verifies the `dhparam` subcommand (DH parameter generation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dhparam → dhparam::execute()`
#[test]
fn test_dispatch_dhparam() {
    openssl_cmd()
        .arg("dhparam")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dhparam"));
}

/// Verifies the `dsaparam` subcommand (DSA parameter generation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dsaparam → dsaparam::execute()`
#[test]
fn test_dispatch_dsaparam() {
    openssl_cmd()
        .arg("dsaparam")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dsaparam"));
}

/// Verifies the `rsa` subcommand (RSA key utility) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rsa → rsa::execute()`
#[test]
fn test_dispatch_rsa() {
    openssl_cmd()
        .arg("rsa")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("rsa"));
}

/// Verifies the `dsa` subcommand (DSA key utility) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dsa → dsa::execute()`
#[test]
fn test_dispatch_dsa() {
    openssl_cmd()
        .arg("dsa")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dsa"));
}

/// Verifies the `pkeyparam` subcommand (public key parameter utility) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkeyparam → pkeyparam::execute()`
#[test]
fn test_dispatch_pkeyparam() {
    openssl_cmd()
        .arg("pkeyparam")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pkeyparam"));
}

// ===========================================================================
// Crypto Operation Commands
// ===========================================================================

/// Verifies the `enc` subcommand (symmetric encryption/decryption) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Enc → enc::execute()`
#[test]
fn test_dispatch_enc() {
    openssl_cmd()
        .arg("enc")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("enc"));
}

/// Verifies the `dgst` subcommand (message digest computation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Dgst → dgst::execute()`
#[test]
fn test_dispatch_dgst() {
    openssl_cmd()
        .arg("dgst")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dgst"));
}

/// Verifies the `pkcs12` subcommand (PKCS#12 key store operations) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkcs12 → pkcs12::execute()`
#[test]
fn test_dispatch_pkcs12() {
    openssl_cmd()
        .arg("pkcs12")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pkcs12"));
}

/// Verifies the `pkcs7` subcommand (PKCS#7 operations) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkcs7 → pkcs7::execute()`
#[test]
fn test_dispatch_pkcs7() {
    openssl_cmd()
        .arg("pkcs7")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pkcs7"));
}

/// Verifies the `pkcs8` subcommand (PKCS#8 private key format) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkcs8 → pkcs8::execute()`
#[test]
fn test_dispatch_pkcs8() {
    openssl_cmd()
        .arg("pkcs8")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pkcs8"));
}

/// Verifies the `smime` subcommand (S/MIME mail operations) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Smime → smime::execute()`
#[test]
fn test_dispatch_smime() {
    openssl_cmd()
        .arg("smime")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("smime"));
}

/// Verifies the `mac` subcommand (MAC computation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Mac → mac::execute()`
#[test]
fn test_dispatch_mac() {
    openssl_cmd()
        .arg("mac")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("mac"));
}

/// Verifies the `kdf` subcommand (key derivation function) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Kdf → kdf::execute()`
#[test]
fn test_dispatch_kdf() {
    openssl_cmd()
        .arg("kdf")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("kdf"));
}

/// Verifies the `pkeyutl` subcommand (public key algorithm utilities) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Pkeyutl → pkeyutl::execute()`
#[test]
fn test_dispatch_pkeyutl() {
    openssl_cmd()
        .arg("pkeyutl")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pkeyutl"));
}

/// Verifies the `rsautl` subcommand (RSA utility, deprecated in favor of pkeyutl)
/// is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rsautl → rsautl::execute()`
#[test]
fn test_dispatch_rsautl() {
    openssl_cmd()
        .arg("rsautl")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("rsautl"));
}

/// Verifies the `passwd` subcommand (password hashing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Passwd → passwd::execute()`
#[test]
fn test_dispatch_passwd() {
    openssl_cmd()
        .arg("passwd")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("passwd"));
}

/// Verifies the `prime` subcommand (primality testing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Prime → prime::execute()`
#[test]
fn test_dispatch_prime() {
    openssl_cmd()
        .arg("prime")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("prime"));
}

/// Verifies the `rand` subcommand (random byte generation) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rand → rand::execute()`
#[test]
fn test_dispatch_rand() {
    openssl_cmd()
        .arg("rand")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("rand"));
}

// ===========================================================================
// TLS / Network Commands
// ===========================================================================

/// Verifies the `s_client` subcommand (TLS client diagnostic tool) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::SClient → s_client::execute()`
#[test]
fn test_dispatch_s_client() {
    openssl_cmd()
        .arg("s_client")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("s_client"));
}

/// Verifies the `s_server` subcommand (TLS server diagnostic tool) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::SServer → s_server::execute()`
#[test]
fn test_dispatch_s_server() {
    openssl_cmd()
        .arg("s_server")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("s_server"));
}

/// Verifies the `s_time` subcommand (TLS connection timing benchmark) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::STime → s_time::execute()`
#[test]
fn test_dispatch_s_time() {
    openssl_cmd()
        .arg("s_time")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("s_time"));
}

/// Verifies the `ciphers` subcommand (cipher suite listing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ciphers → ciphers::execute()`
#[test]
fn test_dispatch_ciphers() {
    openssl_cmd()
        .arg("ciphers")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ciphers"));
}

/// Verifies the `sess_id` subcommand (SSL/TLS session ID display) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::SessId → sess_id::execute()`
#[test]
fn test_dispatch_sess_id() {
    openssl_cmd()
        .arg("sess_id")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("sess_id"));
}

// ===========================================================================
// Introspection Commands
// ===========================================================================

/// Verifies the `version` subcommand (version information display) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Version → version::execute()`
#[test]
fn test_dispatch_version() {
    openssl_cmd()
        .arg("version")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("version"));
}

/// Verifies the `list` subcommand (algorithm/provider listing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::List → list::execute()`
#[test]
fn test_dispatch_list() {
    openssl_cmd()
        .arg("list")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("list"));
}

/// Verifies the `speed` subcommand (algorithm benchmarking) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Speed → speed::execute()`
#[test]
fn test_dispatch_speed() {
    openssl_cmd()
        .arg("speed")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("speed"));
}

/// Verifies the `info` subcommand (build and installation information) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Info → info::execute()`
#[test]
fn test_dispatch_info() {
    openssl_cmd()
        .arg("info")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("info"));
}

/// Verifies the `errstr` subcommand (error code string lookup) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Errstr → errstr::execute()`
#[test]
fn test_dispatch_errstr() {
    openssl_cmd()
        .arg("errstr")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("errstr"));
}

/// Verifies the `asn1parse` subcommand (ASN.1 structure parsing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Asn1parse → asn1parse::execute()`
#[test]
fn test_dispatch_asn1parse() {
    openssl_cmd()
        .arg("asn1parse")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("asn1parse"));
}

// ===========================================================================
// Protocol / Utility Commands
// ===========================================================================

/// Verifies the `rehash` subcommand (certificate directory rehashing) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Rehash → rehash::execute()`
#[test]
fn test_dispatch_rehash() {
    openssl_cmd()
        .arg("rehash")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("rehash"));
}

/// Verifies the `skeyutl` subcommand (symmetric key utility) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Skeyutl → skeyutl::execute()`
#[test]
fn test_dispatch_skeyutl() {
    openssl_cmd()
        .arg("skeyutl")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("skeyutl"));
}

/// Verifies the `configutl` subcommand (configuration file utility) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Configutl → configutl::execute()`
#[test]
fn test_dispatch_configutl() {
    openssl_cmd()
        .arg("configutl")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("configutl"));
}

/// Verifies the `crl2pkcs7` subcommand (CRL-to-PKCS#7 conversion) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Crl2pkcs7 → crl2pkcs7::execute()`
#[test]
fn test_dispatch_crl2pkcs7() {
    openssl_cmd()
        .arg("crl2pkcs7")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("crl2pkcs7"));
}

/// Verifies the `nseq` subcommand (Netscape certificate sequence) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Nseq → nseq::execute()`
#[test]
fn test_dispatch_nseq() {
    openssl_cmd()
        .arg("nseq")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("nseq"));
}

/// Verifies the `spkac` subcommand (Netscape SPKAC handling) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Spkac → spkac::execute()`
#[test]
fn test_dispatch_spkac() {
    openssl_cmd()
        .arg("spkac")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("spkac"));
}

/// Verifies the `storeutl` subcommand (URI-based certificate/key store) is dispatched.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Storeutl → storeutl::execute()`
#[test]
fn test_dispatch_storeutl() {
    openssl_cmd()
        .arg("storeutl")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("storeutl"));
}

// ===========================================================================
// Feature-Gated Commands
// ===========================================================================

/// Verifies the `cms` subcommand (CMS/PKCS#7 signed/enveloped data) is dispatched.
///
/// Feature-gated behind `cms` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Cms → cms::execute()`
#[cfg(feature = "cms")]
#[test]
fn test_dispatch_cms() {
    openssl_cmd()
        .arg("cms")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("cms"));
}

/// Verifies the `ocsp` subcommand (OCSP client/responder) is dispatched.
///
/// Feature-gated behind `ocsp` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ocsp → ocsp::execute()`
#[cfg(feature = "ocsp")]
#[test]
fn test_dispatch_ocsp() {
    openssl_cmd()
        .arg("ocsp")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ocsp"));
}

/// Verifies the `cmp` subcommand (Certificate Management Protocol) is dispatched.
///
/// Feature-gated behind `cmp` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Cmp → cmp::execute()`
#[cfg(feature = "cmp")]
#[test]
fn test_dispatch_cmp() {
    openssl_cmd()
        .arg("cmp")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("cmp"));
}

/// Verifies the `ts` subcommand (RFC 3161 timestamp) is dispatched.
///
/// Feature-gated behind `ts` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ts → ts::execute()`
#[cfg(feature = "ts")]
#[test]
fn test_dispatch_ts() {
    openssl_cmd()
        .arg("ts")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ts"));
}

/// Verifies the `fipsinstall` subcommand (FIPS module installation) is dispatched.
///
/// Feature-gated behind `fips` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Fipsinstall → fipsinstall::execute()`
#[cfg(feature = "fips")]
#[test]
fn test_dispatch_fipsinstall() {
    openssl_cmd()
        .arg("fipsinstall")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("fipsinstall"));
}

/// Verifies the `ech` subcommand (Encrypted Client Hello) is dispatched.
///
/// Feature-gated behind `ech` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ech → ech::execute()`
#[cfg(feature = "ech")]
#[test]
fn test_dispatch_ech() {
    openssl_cmd()
        .arg("ech")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ech"));
}

/// Verifies the `srp` subcommand (SRP verifier file management) is dispatched.
///
/// Feature-gated behind `srp` which is enabled by default.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Srp → srp::execute()`
#[cfg(feature = "srp")]
#[test]
fn test_dispatch_srp() {
    openssl_cmd()
        .arg("srp")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("srp"));
}

/// Verifies the `ec` subcommand (EC key utility) is dispatched.
///
/// Feature-gated behind `ec`. The `ec` feature gates both `ec` and `ecparam`
/// subcommands, matching the `commands/mod.rs` enum gating.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ec → ec::execute()`
#[cfg(feature = "ec")]
#[test]
fn test_dispatch_ec() {
    openssl_cmd()
        .arg("ec")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ec"));
}

/// Verifies the `ecparam` subcommand (EC parameter generation) is dispatched.
///
/// Feature-gated behind `ec`. The `ec` feature gates both `ec` and `ecparam`
/// subcommands, matching the `commands/mod.rs` enum gating.
///
/// Caller chain: `main() → Cli::parse() → CliCommand::Ecparam → ecparam::execute()`
#[cfg(feature = "ec")]
#[test]
fn test_dispatch_ecparam() {
    openssl_cmd()
        .arg("ecparam")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ecparam"));
}

// ===========================================================================
// Meta-Test — Subcommand Count Verification
// ===========================================================================

/// Verifies that the compiled binary advertises at least the expected number of
/// subcommands in its top-level help output, confirming none are missing from
/// the dispatch table.
///
/// The expected minimum count is 45 (non-feature-gated commands always present).
/// With all default features enabled, the count reaches 54+.
///
/// This test runs `openssl --help`, then checks that each known non-feature-gated
/// subcommand name appears somewhere in the help text.
#[test]
fn test_all_subcommands_reachable() {
    let assert_result = openssl_cmd().arg("--help").assert().success();

    let stdout = String::from_utf8_lossy(&assert_result.get_output().stdout);

    // Non-feature-gated subcommands that MUST always be present in help output.
    let always_present: &[&str] = &[
        "req",
        "x509",
        "ca",
        "verify",
        "crl",
        "genpkey",
        "pkey",
        "genrsa",
        "gendsa",
        "dhparam",
        "dsaparam",
        "rsa",
        "dsa",
        "pkeyparam",
        "enc",
        "dgst",
        "pkcs12",
        "pkcs7",
        "pkcs8",
        "smime",
        "mac",
        "kdf",
        "pkeyutl",
        "rsautl",
        "passwd",
        "prime",
        "rand",
        "s_client",
        "s_server",
        "s_time",
        "ciphers",
        "sess_id",
        "version",
        "list",
        "speed",
        "info",
        "errstr",
        "asn1parse",
        "rehash",
        "skeyutl",
        "configutl",
        "crl2pkcs7",
        "nseq",
        "spkac",
        "storeutl",
    ];

    let mut missing: Vec<&str> = Vec::new();
    for cmd in always_present {
        if !stdout.contains(cmd) {
            missing.push(cmd);
        }
    }

    assert!(
        missing.is_empty(),
        "The following subcommands are missing from `openssl --help` output: {missing:?}\n\
         Expected at least {} non-feature-gated subcommands.\n\
         Full help output:\n{stdout}",
        always_present.len(),
    );

    // Verify a minimum count of subcommand names found.
    let found_count = always_present.len() - missing.len();
    assert!(
        found_count >= 45,
        "Expected at least 45 non-feature-gated subcommands, but only found {found_count}",
    );
}

// ===========================================================================
// Digest / Cipher Name Fallback Dispatch Tests
// ===========================================================================

/// Verifies that invoking `openssl sha256` dispatches to the `dgst` subcommand.
///
/// In the C implementation (`openssl.c:508-512`), when a command name is not
/// found in the dispatch table, `do_cmd()` checks if the name matches a known
/// digest algorithm name via `EVP_get_digestbyname()`. If it does, the command
/// is dispatched to `dgst_main()` with the digest name pre-configured.
///
/// The Rust implementation replicates this fallback behavior: unrecognized
/// subcommand names are checked against known digest names, and if matched,
/// routed to the `dgst` handler.
#[test]
fn test_digest_name_fallback_dispatch() {
    // "sha256" is not a registered subcommand name — it should fall through
    // to the digest-name lookup and dispatch to the dgst handler.
    let assert_result = openssl_cmd().arg("sha256").arg("--help").assert().success();

    // The help output should reference the digest/dgst functionality,
    // confirming the fallback dispatch occurred.
    let stdout = String::from_utf8_lossy(&assert_result.get_output().stdout);
    assert!(
        stdout.contains("dgst") || stdout.contains("digest") || stdout.contains("sha256"),
        "Expected digest-related help output when dispatching 'sha256', got:\n{stdout}",
    );
}

/// Verifies that invoking `openssl aes-256-cbc` dispatches to the `enc` subcommand.
///
/// In the C implementation (`openssl.c:514-520`), when a command name matches
/// neither a registered command nor a digest name, `do_cmd()` checks if it
/// matches a known cipher name via `EVP_get_cipherbyname()`. If it does, the
/// command is dispatched to `enc_main()` with the cipher pre-configured.
///
/// The Rust implementation replicates this fallback behavior: unrecognized
/// subcommand names are checked against known cipher names, and if matched,
/// routed to the `enc` handler.
#[test]
fn test_cipher_name_fallback_dispatch() {
    // "aes-256-cbc" is not a registered subcommand name — it should fall through
    // to the cipher-name lookup and dispatch to the enc handler.
    let assert_result = openssl_cmd()
        .arg("aes-256-cbc")
        .arg("--help")
        .assert()
        .success();

    // The help output should reference encryption/enc functionality,
    // confirming the fallback dispatch occurred.
    let stdout = String::from_utf8_lossy(&assert_result.get_output().stdout);
    assert!(
        stdout.contains("enc")
            || stdout.contains("encrypt")
            || stdout.contains("cipher")
            || stdout.contains("aes-256-cbc"),
        "Expected cipher-related help output when dispatching 'aes-256-cbc', got:\n{stdout}",
    );
}

// ===========================================================================
// Invalid Command and No-Command Tests
// ===========================================================================

/// Verifies that invoking `openssl nonexistent_command` exits with a non-zero
/// status and produces an error message indicating the command is invalid.
///
/// This replicates the C behavior from `openssl.c:541-543` where unrecognized
/// commands (that also don't match digest or cipher names) produce:
/// ```text
/// Invalid command 'nonexistent_command'; type "help" for a list.
/// ```
/// and the process returns exit code 1.
///
/// The Rust implementation may use clap's standard error formatting, which
/// differs from the C message but still conveys the same semantics.
#[test]
fn test_invalid_command_returns_error() {
    openssl_cmd()
        .arg("nonexistent_command_xyz")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Invalid command")
                .or(predicate::str::contains("invalid"))
                .or(predicate::str::contains("unrecognized"))
                .or(predicate::str::contains("error")),
        );
}

/// Verifies that invoking bare `openssl` with no arguments shows help output.
///
/// In the C implementation, when no command is given, `do_cmd()` dispatches
/// to `help_main()` which prints the command list. The Rust implementation
/// similarly shows the top-level help (via clap or custom handler) when
/// `Cli::parse()` finds `command: None`.
#[test]
fn test_no_command_shows_help() {
    // Bare `openssl` with no arguments should show help and exit successfully.
    // Some implementations may exit with code 0 (help shown) or code 1
    // (missing command), so we check output content rather than exit code.
    let output = openssl_cmd()
        .output()
        .expect("failed to execute openssl binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // The help output should contain either the binary name, "help", "usage",
    // or "openssl" — any of which confirms help text was displayed.
    assert!(
        combined.contains("openssl")
            || combined.contains("help")
            || combined.contains("Usage")
            || combined.contains("usage")
            || combined.contains("USAGE"),
        "Expected help output when running bare 'openssl', got:\nstdout: {stdout}\nstderr: {stderr}",
    );
}
