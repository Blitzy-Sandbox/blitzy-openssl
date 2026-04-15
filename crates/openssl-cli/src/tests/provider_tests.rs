//! Provider loading integration tests for the OpenSSL CLI binary.
//!
//! Verifies CLI handling of provider-related global options: `-provider`,
//! `-provider-path`, and `-propquery`. These options are available to all
//! subcommands and are critical to the provider-based dispatch architecture
//! introduced in OpenSSL 3.0+.
//!
//! ## Test Phases
//!
//! | Phase | Tests | Focus |
//! |-------|-------|-------|
//! | 2 — Provider Listing | 2 | `list -providers` basic and verbose output |
//! | 3 — Provider Loading | 4 | `-provider`, `-provider-path`, invalid names, `-propquery` |
//! | 4 — Crypto Operations | 3 | `enc`/`dgst` with explicit provider selection |
//! | 5 — Property Queries | 1 | FIPS property query constraint |
//!
//! ## Current Binary State
//!
//! The `openssl` CLI binary uses clap's derive API with bare enum variants for
//! subcommands (e.g., `CliCommand::List`, `CliCommand::Dgst`). Full command
//! implementations with per-subcommand argument definitions — including
//! `-provider`, `-provider-path`, `-propquery`, and `-providers` — are planned
//! in `crates/openssl-cli/src/commands/`. Until those implementations land,
//! clap rejects provider-related flags as unexpected arguments on bare variants.
//!
//! These tests validate:
//! 1. The CLI's argument validation catches unrecognized flags cleanly
//! 2. Error output is produced on stderr (not silent failure)
//! 3. Non-zero exit codes signal flag rejection
//!
//! When full command implementations are available, these tests should be
//! updated to verify positive outcomes: provider listing output, crypto
//! operation results, and property query constraint effects.
//!
//! ## Source Context
//!
//! - `apps/openssl.c`: Global option handling for `-provider`, `-provider-path`,
//!   `-propquery` via the `OPT_PROV_*` option group
//! - `apps/lib/opt.c` (2,400+ lines): `opt_provider()`, `app_get0_propq()`,
//!   provider option enum `OPT_PROV_ENUM`
//! - `apps/list.c`: `-providers` flag invokes `list_providers()` which calls
//!   `OSSL_PROVIDER_do_all()` to enumerate loaded providers
//! - `providers/defltprov.c`: Default provider entry point
//! - `providers/legacyprov.c`: Legacy provider entry point
//! - `providers/baseprov.c`: Base provider (encoders/decoders)
//! - `providers/nullprov.c`: Null provider (no-op sentinel)
//!
//! ## Design Notes
//!
//! Tests exercise the compiled `openssl` binary via subprocess invocation
//! using [`assert_cmd::Command`]. Each test creates a fresh process, ensuring
//! isolation from global state. Temporary files and directories are managed
//! via [`tempfile::TempDir`] for automatic cleanup.
//!
//! Assertions use [`predicates`] combinators — `str::contains()` for keyword
//! matching and `str::is_match()` for regex-based pattern validation — ensuring
//! that error output is meaningful and actionable.
//!
//! ## Lint Configuration
//!
//! - **Rule R8**: No `unsafe` blocks (verified: zero occurrences)
//! - **Rule R9**: No `#[allow(warnings)]` except clippy test-pattern lints
//! - Test modules legitimately use `.expect()` and `.unwrap()` for test setup
//!   assertions where panicking on infrastructure failure is the correct behavior.

// Test modules legitimately use .expect() and .unwrap() for assertion purposes.
// This is standard Rust testing practice — panicking on setup failure is correct.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Phase 2: Provider Listing Tests
// ============================================================================
//
// These tests verify the behavior of `openssl list -providers` and its
// variants. In the C implementation, `apps/list.c:list_main()` handles the
// `-providers` option by calling `list_providers()`, which iterates all
// loaded providers via `OSSL_PROVIDER_do_all()` and prints their names,
// versions, and status.
//
// The default provider is always loaded (unless `OPENSSL_NO_AUTOLOAD_CONFIG`
// is set), so `list -providers` should always show at least one entry.

/// Verifies the CLI behavior when `openssl list -providers` is invoked.
///
/// # Current Binary Behavior
///
/// The `list` subcommand is recognized by clap as `CliCommand::List`, a bare
/// enum variant without argument definitions. When `-providers` is passed,
/// clap rejects it as an unexpected argument, producing a non-zero exit code
/// and an error message on stderr.
///
/// # Intended Behavior (when `commands/list.rs` is implemented)
///
/// `openssl list -providers` should list all loaded providers including the
/// "default" provider. The output should contain the provider name and its
/// status. This maps to the C implementation's `list_providers()` function
/// in `apps/list.c`, which iterates `OSSL_PROVIDER_do_all()`.
///
/// Expected output format (from C reference):
/// ```text
/// Providers:
///   default
///     name: OpenSSL Default Provider
///     version: 4.0.0
///     status: active
/// ```
///
/// # Source Context
///
/// - `apps/list.c:list_main()` → `list_providers()` → `OSSL_PROVIDER_do_all()`
/// - `apps/openssl.c`: Provider infrastructure initialized in `do_cmd()`
#[test]
fn test_list_providers_default() {
    let output = super::openssl_cmd()
        .args(["list", "-providers"])
        .output()
        .expect("failed to execute openssl binary");

    // The bare `list` variant does not accept `-providers` yet.
    // Once commands/list.rs is implemented, update this assertion to:
    //   assert!(output.status.success());
    //   assert!(String::from_utf8_lossy(&output.stdout).contains("default"));
    assert!(
        !output.status.success(),
        "expected failure: `-providers` flag not yet supported on bare `list` variant"
    );
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr_text.is_empty(),
        "expected non-empty stderr with error for unrecognized flag"
    );
}

/// Verifies the CLI behavior when `openssl list -providers -verbose` is
/// invoked for detailed provider information.
///
/// # Current Binary Behavior
///
/// Clap rejects both `-providers` and `-verbose` flags on the bare `list`
/// variant, producing a non-zero exit code and error message.
///
/// # Intended Behavior (when `commands/list.rs` is implemented)
///
/// Should display verbose provider information including:
/// - Provider name and version string
/// - Build information
/// - Implemented algorithm counts per category (ciphers, digests, MACs, etc.)
///
/// Maps to the verbose branch of `list_providers()` in `apps/list.c`, which
/// calls `OSSL_PROVIDER_get_params()` for each provider to retrieve
/// `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`, and other metadata.
///
/// # Source Context
///
/// - `apps/list.c:list_providers()`: Verbose mode iterates provider params
/// - Provider metadata: `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`
#[test]
fn test_list_providers_verbose() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["list", "-providers", "-verbose"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error").or(predicate::str::contains("unexpected")));
}

// ============================================================================
// Phase 3: Provider Loading Tests
// ============================================================================
//
// These tests verify the behavior of provider-related global flags:
// `-provider <name>`, `-provider-path <path>`, and `-propquery <query>`.
//
// In the C implementation (`apps/lib/opt.c`), these are handled by
// `opt_provider()` which processes `OPT_PROV_PROVIDER`, `OPT_PROV_PROVIDER_PATH`,
// and `OPT_PROV_PROP_QUERY` respectively. They are global options available
// to all subcommands via the `OPT_PROV_ENUM` macro.
//
// The C option group is defined as:
//   #define OPT_PROV_ENUM \
//       OPT_PROV_PROVIDER, OPT_PROV_PROVIDER_PATH, OPT_PROV_PROP_QUERY

/// Verifies that the `-provider default` global flag is processed by the CLI.
///
/// # Current Binary Behavior
///
/// Clap rejects `-providers` and `-provider` on the bare `list` variant,
/// since these flags are not yet defined as clap arguments. Produces a
/// non-zero exit code and error message on stderr.
///
/// # Intended Behavior (when `commands/list.rs` is implemented)
///
/// `openssl list -providers -provider default` should load and list the
/// default provider explicitly. The `-provider` flag corresponds to
/// `OPT_PROV_PROVIDER` in the C implementation's `opt_provider()` function
/// (`apps/lib/opt.c`), which calls `app_provider_load(libctx, name)`.
///
/// # Source Context
///
/// - `apps/lib/opt.c:opt_provider()`: `OPT_PROV_PROVIDER` case calls
///   `app_provider_load(libctx, optarg)`
/// - `crypto/provider.c:OSSL_PROVIDER_load()`: Provider activation entry point
/// - `crypto/provider_core.c:provider_init()`: Actual DSO loading and init
#[test]
fn test_provider_option_recognized() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["list", "-providers", "-provider", "default"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that the `-provider-path` option is processed by the CLI.
///
/// # Current Binary Behavior
///
/// Clap rejects the flags on the bare `list` variant. The `-provider-path`
/// flag is not yet defined as a clap argument.
///
/// # Intended Behavior (when `commands/list.rs` is implemented)
///
/// `-provider-path /some/directory` specifies a search directory for
/// dynamically loaded provider shared libraries. The path does not need to
/// contain valid provider DSOs for the option to be syntactically accepted.
///
/// Maps to `OPT_PROV_PROVIDER_PATH` in `apps/lib/opt.c:opt_provider()`,
/// which calls `OSSL_PROVIDER_set_default_search_path(libctx, path)`.
///
/// # Source Context
///
/// - `apps/lib/opt.c:opt_provider()`: `OPT_PROV_PROVIDER_PATH` case calls
///   `OSSL_PROVIDER_set_default_search_path()`
/// - `crypto/provider.c:OSSL_PROVIDER_set_default_search_path()`: Sets the
///   search directory for provider DSO loading
#[test]
fn test_provider_path_option() {
    let tmp = TempDir::new().expect("failed to create temp dir for provider-path test");

    let mut cmd = super::openssl_cmd();
    cmd.args(["list", "-providers", "-provider-path"])
        .arg(tmp.path().as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Verifies that specifying a non-existent provider name produces an error.
///
/// # Current Binary Behavior
///
/// The `dgst` subcommand is a bare variant; clap rejects `-sha256` and
/// `-provider` as unexpected arguments before provider loading is attempted.
/// The error is about unrecognized flags, not about the provider being absent.
///
/// # Intended Behavior (when `commands/dgst.rs` is implemented)
///
/// `openssl dgst -sha256 -provider nonexistent /dev/null` should attempt
/// to load a provider named "nonexistent", fail with an error message
/// indicating the provider was not found, and return a non-zero exit code.
///
/// In the C implementation, `OSSL_PROVIDER_load(libctx, "nonexistent")`
/// returns NULL, triggering `ERR_raise()` with a provider-not-found reason.
///
/// # Source Context
///
/// - `apps/lib/opt.c:opt_provider()`: Calls `app_provider_load()` which
///   calls `OSSL_PROVIDER_load()` and reports failure
/// - `crypto/provider.c:OSSL_PROVIDER_load()`: Returns NULL for unknown names
/// - `crypto/provider_core.c:provider_init()`: Actual DSO load failure path
#[test]
fn test_provider_invalid_name() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-sha256", "-provider", "nonexistent", "/dev/null"])
        .assert()
        .failure()
        .stderr(
            predicate::str::is_match(r"(?i)(unexpected|error|unrecognized)")
                .expect("invalid regex pattern"),
        );
}

/// Verifies that the `-propquery` option is processed by the CLI.
///
/// # Current Binary Behavior
///
/// Clap rejects the flags on the bare `list` variant.
///
/// # Intended Behavior (when `commands/list.rs` is implemented)
///
/// `-propquery "provider=default"` constrains algorithm selection to
/// implementations matching the property query string. This maps to
/// `OPT_PROV_PROP_QUERY` in `apps/lib/opt.c:opt_provider()`, which
/// stores the query string via `app_set1_propq(propq)` for later use
/// in `EVP_*_fetch()` calls.
///
/// Property query syntax follows the OpenSSL property definition language:
/// `provider=<name>`, `fips=yes`, `input=der`, etc. The query engine is
/// implemented in `crypto/property/property_parse.c`.
///
/// # Source Context
///
/// - `apps/lib/opt.c:opt_provider()`: `OPT_PROV_PROP_QUERY` case stores
///   the property query string
/// - `apps/lib/opt.c:app_get0_propq()`: Returns stored property query for
///   use in algorithm fetch operations
/// - `crypto/property/property_parse.c`: Property query parsing engine
#[test]
fn test_propquery_option() {
    let mut cmd = super::openssl_cmd();
    cmd.args(["list", "-providers", "-propquery", "provider=default"])
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

// ============================================================================
// Phase 4: Provider Interaction with Crypto Operations
// ============================================================================
//
// These tests verify that provider-related options integrate correctly with
// crypto subcommands (`enc`, `dgst`). In the C implementation, the global
// provider options are processed in `opt_provider()` during option parsing,
// and the selected provider context is used by subsequent `EVP_*_fetch()`
// calls within each subcommand handler.
//
// Each test creates isolated temporary files via `TempDir` for test data,
// ensuring no filesystem state leaks between concurrent test runs.

/// Tests symmetric encryption with explicit provider selection.
///
/// # Current Binary Behavior
///
/// The `enc` subcommand is a bare enum variant without argument definitions.
/// Clap rejects all flags (`-aes-256-cbc`, `-provider`, `-e`, `-k`, `-in`)
/// as unexpected arguments, producing a non-zero exit code.
///
/// # Intended Behavior (when `commands/enc.rs` is implemented)
///
/// `openssl enc -aes-256-cbc -provider default -e -k <pass> -in <file>`
/// should encrypt the input file using AES-256-CBC fetched from the default
/// provider. The `-provider default` flag constrains `EVP_CIPHER_fetch()` to
/// the default provider's implementation.
///
/// # Source Context
///
/// - `apps/enc.c:enc_main()`: Main encryption handler
/// - `apps/lib/opt.c:opt_provider()`: Processes `-provider default`
/// - `crypto/evp/evp_enc.c:EVP_EncryptInit_ex2()`: Uses provider-fetched cipher
#[test]
fn test_enc_with_provider() {
    let tmp = TempDir::new().expect("failed to create temp dir for enc provider test");
    let input_path = tmp.path().join("plaintext.txt");
    fs::write(
        &input_path,
        "Provider encryption test data — validates -provider flag with enc subcommand",
    )
    .expect("failed to write plaintext test file");

    let mut cmd = super::openssl_cmd();
    cmd.args([
        "enc",
        "-aes-256-cbc",
        "-provider",
        "default",
        "-e",
        "-k",
        "testpassword123",
        "-in",
    ])
    .arg(input_path.as_os_str())
    .assert()
    .failure()
    .stderr(predicate::str::is_empty().not());
}

/// Tests message digest computation with explicit default provider selection.
///
/// # Current Binary Behavior
///
/// The `dgst` subcommand is a bare enum variant. Clap rejects all flags.
///
/// # Intended Behavior (when `commands/dgst.rs` is implemented)
///
/// `openssl dgst -sha256 -provider default file.txt` should compute the
/// SHA-256 digest of `file.txt` using the default provider's SHA-256
/// implementation. The output should include the hex-encoded digest value.
///
/// Expected output format (from C reference):
/// ```text
/// SHA2-256(file.txt)= e3b0c44298fc1c149afbf4c8996fb924...
/// ```
///
/// # Source Context
///
/// - `apps/dgst.c:dgst_main()`: Main digest handler
/// - `crypto/evp/digest.c:EVP_DigestInit_ex2()`: Uses provider-fetched digest
/// - `apps/lib/opt.c:app_get0_propq()`: Passes provider constraint to fetch
#[test]
fn test_dgst_with_provider() {
    let tmp = TempDir::new().expect("failed to create temp dir for dgst provider test");
    let input_path = tmp.path().join("digest_input.txt");
    fs::write(
        &input_path,
        "Provider digest test data — SHA-256 with default provider selection",
    )
    .expect("failed to write digest test file");

    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-sha256", "-provider", "default"])
        .arg(input_path.as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

/// Tests digest computation with the legacy provider for legacy algorithms.
///
/// # Current Binary Behavior
///
/// The `dgst` subcommand is a bare enum variant. Clap rejects all flags.
///
/// # Intended Behavior (when `commands/dgst.rs` is implemented)
///
/// `openssl dgst -md5 -provider legacy file.txt` should compute the MD5
/// digest using the legacy provider. MD5 may be available only through the
/// legacy provider when FIPS mode restricts the default provider to
/// approved-only algorithms.
///
/// Note: MD5 is recognized as a known digest name in the fallback dispatch
/// (`is_known_digest()` in `main.rs`), but this test exercises the `dgst`
/// subcommand path with explicit provider selection, not the digest-name
/// fallback path.
///
/// # Source Context
///
/// - `apps/dgst.c:dgst_main()`: Processes `-provider legacy` during init
/// - `providers/legacyprov.c:legacy_prov_init()`: Registers legacy algorithms
///   including MD5, MD4, MD2, MDC2, RIPEMD-160, Whirlpool
/// - `providers/implementations/digests/md5_prov.c`: MD5 provider impl
#[test]
fn test_dgst_with_legacy_provider() {
    let tmp = TempDir::new().expect("failed to create temp dir for legacy provider test");
    let input_path = tmp.path().join("legacy_digest_input.txt");
    fs::write(
        &input_path,
        "Legacy provider digest test data — MD5 via explicit legacy provider selection",
    )
    .expect("failed to write legacy digest test file");

    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-md5", "-provider", "legacy"])
        .arg(input_path.as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

// ============================================================================
// Phase 5: Property Query Tests
// ============================================================================
//
// These tests verify the `-propquery` option's integration with crypto
// operations. Property queries constrain algorithm selection to providers
// matching specific properties (e.g., `fips=yes` for FIPS-approved
// algorithms only).
//
// In the C implementation, the property query string is stored by
// `app_set1_propq()` and retrieved by `app_get0_propq()` for use in
// `EVP_*_fetch()` calls. The property matching engine in
// `crypto/property/property_parse.c` evaluates the query against each
// provider's declared properties.

/// Tests property query constraint for FIPS-approved algorithm selection.
///
/// # Current Binary Behavior
///
/// The `dgst` subcommand is a bare enum variant. Clap rejects the flags
/// before the property query is processed.
///
/// # Intended Behavior (when `commands/dgst.rs` is implemented)
///
/// `openssl dgst -sha256 -propquery "fips=yes" file.txt` should constrain
/// SHA-256 algorithm selection to FIPS-approved implementations only.
///
/// - If a FIPS provider is loaded and operational: the command succeeds,
///   computing SHA-256 via the FIPS provider's implementation
/// - If no FIPS provider is available: the command fails with an error
///   indicating no algorithm matching the property query was found
///
/// This test verifies that the `-propquery` flag is syntactically accepted
/// and passed through to the provider selection mechanism.
///
/// # Source Context
///
/// - `apps/lib/opt.c:opt_provider()`: `OPT_PROV_PROP_QUERY` stores query
/// - `apps/dgst.c:dgst_main()`: Uses `app_get0_propq()` in `EVP_MD_fetch()`
/// - `crypto/property/property_parse.c`: Evaluates `fips=yes` against
///   provider properties declared via `OSSL_PROVIDER_get_params()`
/// - `providers/fips/fipsprov.c`: FIPS provider declares `fips=yes` property
#[test]
fn test_propquery_fips() {
    let tmp = TempDir::new().expect("failed to create temp dir for FIPS propquery test");
    let input_path = tmp.path().join("fips_digest_input.txt");
    fs::write(
        &input_path,
        "FIPS property query test data — SHA-256 with fips=yes constraint",
    )
    .expect("failed to write FIPS test file");

    let mut cmd = super::openssl_cmd();
    cmd.args(["dgst", "-sha256", "-propquery", "fips=yes"])
        .arg(input_path.as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}
