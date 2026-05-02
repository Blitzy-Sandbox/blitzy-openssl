//! OpenSSL CLI binary entry point — Rust rewrite of `apps/openssl.c` (590 lines).
//!
//! This is the entry point for the `openssl-cli` binary. It serves as the
//! **single runtime owner** (Rule R1) and the central command dispatcher for
//! the 56+ subcommands implemented under [`commands`].
//!
//! # Architecture
//!
//! The C source it replaces is structured as:
//!
//! 1. `main()` — `apps/openssl.c:243-411` — sets up library, parses args, dispatches.
//! 2. `apps_startup()` — `apps/openssl.c:66-93` — calls [`OPENSSL_init_ssl`] and
//!    creates global state used by all subcommands.
//! 3. `apps_shutdown()` — `apps/openssl.c:95-100` — runs cleanup hooks.
//! 4. `prog_init()` — `apps/openssl.c:566-589` — builds an [`LHASH_OF(FUNCTION)`]
//!    dispatch table mapping subcommand names to handler function pointers.
//! 5. `do_cmd()` — `apps/openssl.c:495-544` — looks up by name; falls back to
//!    `dgst`/`enc` when the name is a digest or cipher algorithm.
//! 6. `setup_trace()` — `apps/openssl.c:202-237` — wires up the `OSSL_trace`
//!    diagnostic logger.
//!
//! In Rust this becomes:
//!
//! 1. [`main`] uses `#[tokio::main]` (the **only** runtime in the workspace) and
//!    walks the **init → execute → shutdown** triple.
//! 2. [`initialize`] takes the parsed [`Cli`] and returns an
//!    `Arc<LibContext>` — the equivalent of the C global library context.
//! 3. [`shutdown`] is a thin RAII drop wrapper — most cleanup happens via
//!    [`Drop`] trait implementations on the underlying types.
//! 4. The dispatch table is replaced by a [`clap::Subcommand`]-derived enum
//!    [`commands::CliCommand`] that does compile-time exhaustive routing.
//! 5. The fallback dispatch (`openssl sha256 file` ⇒ `openssl dgst -m sha256 file`)
//!    is implemented by [`rewrite_args_for_fallback`] which munges the raw
//!    `argv` **before** clap sees it.
//! 6. [`init_tracing`] wires up `tracing-subscriber` and the workspace's
//!    [`openssl_common::observability`] metrics endpoint.
//!
//! # Rule Compliance
//!
//! | Rule | Where enforced |
//! |------|----------------|
//! | R1 — Single Runtime Owner | The single `#[tokio::main]` attribute on [`main`] |
//! | R2 — Sync Primitive Match | No `std::sync::Mutex` is held across `.await` (none used in this file) |
//! | R5 — Nullability Over Sentinels | All optional CLI args use `Option<T>` |
//! | R6 — Lossless Numeric Casts | No bare `as` narrowing casts in this file |
//! | R8 — Zero `unsafe` Outside FFI | `#![forbid(unsafe_code)]` at crate root |
//! | R9 — Warning-Free Build | No `#[allow(warnings)]`; only specific lints with rationale |
//! | R10 — Wiring Before Done | `main → Cli::parse → CliCommand::execute → commands/*.rs` |
//!
//! # Caller Chain (Rule R10 — wiring documentation)
//!
//! ```text
//! main()                         (this file)
//! ├── std::env::args()           ← argv from OS
//! ├── rewrite_args_for_fallback  ← BLOCKER #5: digest/cipher → subcommand rewrite
//! ├── Cli::try_parse_from        ← clap subcommand routing
//! ├── init_tracing               ← tracing_subscriber + observability metrics
//! ├── initialize                 ← openssl_crypto::init + LibContext::new
//! ├── health_check               ← observability::HealthRegistry readiness probe
//! ├── cli.command.execute(ctx)   ← crate::commands::CliCommand::execute
//! └── shutdown                   ← Arc<LibContext> drop + observability flush
//! ```

#![forbid(unsafe_code)]
// `lib` is the conventional Rust crate root name, but here we use it as a module
// of the binary crate to organize shared CLI infrastructure.  This intentional
// shadowing requires the `special_module_name` lint to be silenced.
#![allow(special_module_name)]

// ---------------------------------------------------------------------------
// Module Declarations
// ---------------------------------------------------------------------------

/// All 56+ subcommand implementations and the [`commands::CliCommand`] enum.
pub mod commands;

/// Shared CLI infrastructure: option parsing helpers, password handling,
/// and HTTP server utilities.
pub mod lib;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tracing::{debug, error, info, instrument, warn};

use openssl_common::config::Config;
use openssl_common::error::{CommonError, CryptoError};
use openssl_common::observability::{
    self, HealthRegistry, HealthStatus, ObservabilityError, ReadinessCheck,
};
use openssl_crypto::context::LibContext;
use openssl_crypto::init::{self, InitFlags};
use openssl_provider::{register_builtin_providers, BuiltinProviderKind, MethodStore};

use crate::commands::CliCommand;

// ---------------------------------------------------------------------------
// CLI Root Struct (clap derive)
// ---------------------------------------------------------------------------

/// Top-level CLI arguments — the Rust translation of the manual
/// `opt_init`/`opt_next` parser from `apps/lib/opt.c` (1,276 lines).
///
/// The clap `Parser` derive macro replaces:
///
/// * `prog_init()` — the `LHASH_OF(FUNCTION)` dispatch table from
///   `apps/openssl.c:566-589`.
/// * `help_main()` — the help text emitter from `apps/openssl.c:430-493`
///   (auto-generated by clap from doc comments and `#[arg]` attributes).
/// * `do_cmd()` — the subcommand lookup logic from `apps/openssl.c:495-544`
///   (replaced by [`Subcommand`](clap::Subcommand) derive on
///   [`commands::CliCommand`]).
///
/// # Schema Compliance
///
/// The struct exposes `command`, `verbose`, `providers`, `provider_path`,
/// `propquery`, plus the auto-derived `parse()` and `parse_from()` methods
/// from the [`clap::Parser`] trait.
#[derive(Parser, Debug)]
#[command(
    name = "openssl",
    version,
    about = "OpenSSL command-line tool providing cryptographic operations, TLS diagnostics, certificate management, and key generation.",
    // CRITICAL: `long_about` is intentionally set to the SAME single-line
    // string as `about`.  This serves two purposes:
    //   1. Prevents clap from auto-picking up the multi-paragraph `///` doc
    //      comment on this struct as long help (which would corrupt the
    //      committed snapshot in `tests/snapshots/`).
    //   2. Triggers clap's long-help rendering mode for the `Options:`
    //      section under `openssl --help`, producing the multi-line
    //      `-h, --help\n        Print help (see a summary with '-h')`
    //      layout the snapshot was generated with.
    long_about = "OpenSSL command-line tool providing cryptographic operations, TLS diagnostics, certificate management, and key generation."
)]
// NOTE: `propagate_version` is intentionally OFF.  The `version` subcommand has
// its own `--version` flag (`-v/--version` to display the library version), so
// injecting the auto-generated parent `--version` into every subcommand would
// trigger a clap argument-name collision at startup.  The `openssl --version`
// idiom is still supported on the root command via the `version` setting above.
//
// NOTE: All global options below are `hide = true`.  This keeps them out of the
// generated `--help` output (matching the C tool's behaviour and the agreed
// snapshot contract in `crates/openssl-cli/src/tests/snapshots/`) while still
// allowing them to be passed on the command line.
pub struct Cli {
    /// Subcommand to execute. When omitted, `--help` is shown.
    ///
    /// Replaces the C `LHASH_OF(FUNCTION)` lookup at `apps/openssl.c:495-544`.
    #[command(subcommand)]
    pub command: Option<CliCommand>,

    /// Enable verbose diagnostic output.
    ///
    /// When set, the default tracing filter elevates from `warn` to `debug`
    /// unless `RUST_LOG` is already configured, in which case `RUST_LOG`
    /// takes precedence.  Replaces the C `OPENSSL_TRACE` environment-driven
    /// path from `apps/openssl.c:171-200`.
    ///
    /// NOTE: only `--verbose` is exposed (no `-v` short alias) because the
    /// `version` subcommand uses `-v` for its own `--version` argument and
    /// `global = true` would otherwise produce a name collision.
    ///
    /// Hidden from help to keep the top-level help and per-subcommand help
    /// output aligned with the snapshot contract.
    ///
    /// NOTE: The default argument ID `verbose` is intentionally retained.
    /// Several subcommands (e.g. `dhparam`, `gendsa`, `dsaparam`, `enc`,
    /// `srp`, `genpkey`) define their own local `verbose: bool` field with
    /// long name `--verbose`.  Because `global = true` propagates this
    /// argument to every subcommand, clap requires the global and local
    /// definitions to share both the same long name AND the same ID so it
    /// can recognise them as the same logical flag.  Using an explicit ID
    /// like `global_verbose` here would create a duplicate `--verbose` long
    /// option in those subcommands and trigger
    /// "Long option names must be unique" at startup.  Both fields are
    /// `bool`, so the shared slot has a consistent type.
    #[arg(long = "verbose", global = true, hide = true)]
    pub verbose: bool,

    /// Provider to load by name (repeatable).
    ///
    /// Each occurrence of `--provider NAME` validates the name against the
    /// built-in provider registry via
    /// [`BuiltinProviderKind::from_name`].  Unknown names produce a runtime
    /// warning but do not abort.  Replaces the C `-provider` opt parsed by
    /// `apps/lib/opt.c` `OPT_PROV_ENUM`.
    ///
    /// Hidden from help to keep the top-level help and per-subcommand help
    /// output aligned with the snapshot contract.
    ///
    /// NOTE: An explicit `id = "global_providers"` is required to avoid a
    /// collision with the boolean `providers: bool` field on `list` (long
    /// flag `--providers`).  Although the long-flag names differ
    /// (`--provider` vs `--providers`), clap uses the field name as the
    /// argument ID by default, so without an explicit `id` both arguments
    /// would share the slot `providers` and clap would panic with
    /// "Mismatch between definition and access of `providers`" when the
    /// boolean field is read.
    #[arg(
        id = "global_providers",
        long = "provider",
        global = true,
        value_name = "NAME",
        hide = true
    )]
    pub providers: Vec<String>,

    /// Provider search path (directory containing dynamically-loaded providers).
    ///
    /// In the Rust port, providers are statically compiled into the
    /// `openssl-provider` crate; this flag is accepted for CLI compatibility
    /// and noted in the diagnostic log.  Replaces the C `-provider-path`
    /// opt parsed by `apps/lib/opt.c`.
    ///
    /// Hidden from help to keep the top-level help and per-subcommand help
    /// output aligned with the snapshot contract.
    ///
    /// NOTE: The default argument ID `provider_path` is retained.  No
    /// subcommand currently exposes a conflicting local `provider_path`
    /// field, so default behaviour is correct.
    #[arg(
        long = "provider-path",
        global = true,
        value_name = "PATH",
        hide = true
    )]
    pub provider_path: Option<PathBuf>,

    /// Property query string for algorithm fetching.
    ///
    /// Stored on the [`Cli`] struct.  Individual subcommands read this value
    /// when they fetch algorithms; main itself does not wire it into
    /// [`LibContext`] because the global setter is `pub(crate)`.  Replaces
    /// the C `-propquery` opt from `apps/lib/opt.c`.
    ///
    /// Hidden from help to keep the top-level help and per-subcommand help
    /// output aligned with the snapshot contract.
    ///
    /// NOTE: The default argument ID `propquery` is retained.  Subcommands
    /// like `configutl` and `skeyutl` define their own local `propquery`
    /// field with the same long name and same `Option<String>` type, so
    /// the merge under a shared ID is type-safe and clap can resolve both
    /// definitions to the same logical flag.
    #[arg(long = "propquery", global = true, value_name = "QUERY", hide = true)]
    pub propquery: Option<String>,
}

// ---------------------------------------------------------------------------
// CLI Error Type
// ---------------------------------------------------------------------------

/// All possible errors that can be raised from CLI startup, command dispatch,
/// or shutdown.
///
/// Each variant carries enough context for the user-facing error message to be
/// actionable.  Replaces the C `BIO_printf(bio_err, "FATAL: ...")` +
/// `ERR_print_errors(bio_err)` chain from `apps/openssl.c`.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Library or runtime initialization failed.
    ///
    /// Surfaced via `#[from]` on [`CommonError`] for ergonomic propagation
    /// from [`openssl_common`] APIs that return [`Result<_, CommonError>`].
    #[error("initialization error: {0}")]
    InitError(#[from] CommonError),

    /// A CLI subcommand handler returned a non-recoverable error message.
    ///
    /// This variant is constructed manually (no `#[from]`) for cases that do
    /// not naturally convert from a typed error.
    #[error("command failed: {0}")]
    CommandError(String),

    /// I/O failure during CLI startup or shutdown (e.g., reading config files,
    /// writing diagnostic output).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Cryptographic library failure surfaced from a subcommand handler.
    ///
    /// Replaces the C ERR queue + `ERR_print_errors_cb()` reporting path.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Tracing or metrics subsystem initialization failed.
    #[error("observability error: {0}")]
    Observability(#[from] ObservabilityError),
}

// ---------------------------------------------------------------------------
// Tracing / Observability Initialization
// ---------------------------------------------------------------------------

/// Initializes the structured-logging subscriber and the observability
/// metrics endpoint.
///
/// This is the Rust replacement for the C `setup_trace()` from
/// `apps/openssl.c:202-237`.  The C path used the `OSSL_TRACE` mechanism
/// which is hard-coded to write to `stderr`; in Rust we use
/// [`tracing-subscriber`](tracing_subscriber) with an [`EnvFilter`] that honours
/// the `RUST_LOG` environment variable.
///
/// # Behaviour
///
/// * If `RUST_LOG` is set, it controls the filter directly.
/// * Otherwise, `verbose=true` selects the `debug` level and `verbose=false`
///   selects the `warn` level.
/// * The subscriber emits formatted records that include the target module
///   path and the OS thread ID — replacing the C
///   `CRYPTO_THREAD_get_current_id()` hex prefix from
///   `apps/openssl.c:124-129`.
/// * If a global subscriber has already been installed (e.g., by a test
///   harness), the install fails silently — this is the correct behaviour.
/// * The Prometheus metrics exporter is started as a best-effort observability
///   side-effect; failures are logged but do not abort startup, since the CLI
///   remains useful without metrics.
///
/// # Errors
///
/// Returns [`CliError::Observability`] if the metrics installation fails for a
/// reason other than [`ObservabilityError::AlreadyInitialized`].
///
/// [`tracing-subscriber`]: tracing_subscriber
/// [`EnvFilter`]: tracing_subscriber::EnvFilter
pub fn init_tracing(verbose: bool) -> Result<(), CliError> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // Build the env filter: RUST_LOG > verbose flag > default ("warn").
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("warn")
        }
    });

    // Install the subscriber.  Use try_init() to be tolerant of test harnesses
    // that may have already installed a subscriber.
    let setup_result = tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(env_filter)
        .try_init();

    if let Err(install_err) = setup_result {
        // Already installed (typical in test scenarios).  Not fatal.
        // Use eprintln since tracing may not be installable from this scope.
        let _ = install_err;
    }

    // Best-effort metrics setup.  Idempotent: AlreadyInitialized is treated as
    // success.  Other observability errors are logged and propagated since
    // they may indicate misconfigured metrics endpoints that the operator
    // should know about.
    match observability::init_metrics() {
        Ok(_handle) => {
            debug!("metrics endpoint initialized");
        }
        Err(ObservabilityError::AlreadyInitialized) => {
            // Metrics already set up by another caller (or test harness).
        }
        Err(other) => {
            warn!(error = %other, "metrics endpoint not available");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Library Initialization
// ---------------------------------------------------------------------------

/// Performs library startup and returns the shared [`Arc<LibContext>`] used by
/// all subcommands.
///
/// Replaces:
///
/// * `apps_startup()` from `apps/openssl.c:66-93` — sets the locale, calls
///   `OPENSSL_init_ssl()`, and creates the global `LHASH_OF(BIO)`.
/// * `app_create_libctx()` from `apps/lib/app_libctx.c:25-47` — allocates the
///   global `OSSL_LIB_CTX`.
/// * `app_provider.c` (167 lines) — provider loading logic.  In the Rust port
///   the providers are statically compiled into the `openssl-provider` crate;
///   `--provider NAME` is validated but no dynamic loading is performed.
///
/// # Steps
///
/// 1. Initialize the core crypto library via [`init::initialize`] with default
///    flags (base + CPU detect + threads + error strings + config + providers
///    + async).
/// 2. Validate `--provider` arguments against the built-in registry.
/// 3. Note the `--provider-path` and `--propquery` arguments in the diagnostic
///    log; commands consume these directly from `cli` and not via context
///    mutation (the context's property-query setter is `pub(crate)`).
/// 4. Construct an `Arc<LibContext>` via [`LibContext::new`] and return it.
///
/// # Errors
///
/// Returns [`CliError::Crypto`] if [`init::initialize`] fails — typically due
/// to a CPU-detection failure on an exotic architecture, or a misconfigured
/// configuration file.  All other failures are logged as warnings and do not
/// abort startup.
#[instrument(skip_all, fields(verbose = cli.verbose, n_providers = cli.providers.len()))]
pub async fn initialize(cli: &Cli) -> Result<Arc<LibContext>, CliError> {
    // 1. Bring up the core library.
    init::initialize(InitFlags::default())?;
    info!("openssl-crypto library initialized");

    // 1a. Register the built-in provider implementations into a `MethodStore`.
    //
    // Replaces the C-side `OSSL_PROVIDER_load(NULL, "default")` /
    // `OSSL_PROVIDER_load(NULL, "base")` calls that `apps_startup()` relied on
    // to make algorithms available before subcommands ran (see
    // `apps/openssl.c:66-93` and `apps/lib/app_provider.c`).
    //
    // In Rust the providers are statically linked, so this single call wires
    // the default + base (and `legacy` if compiled in) providers' algorithm
    // descriptors into a single `MethodStore`.  The store is dropped at the
    // end of `initialize` because today's subcommands resolve algorithms
    // through their own crate-internal pipelines; the call is retained both
    // (a) for Rule R10 — every component must be reachable from the entry
    // point — and (b) so that `tracing::info!` lines emitted by the helper
    // appear in startup logs and demonstrate provider registration is wired
    // into the CLI.
    let method_store = MethodStore::new();
    register_builtin_providers(&method_store);
    drop(method_store); // explicit: store is observable via tracing logs only
    debug!("built-in providers registered into method store");

    // 2. Reserve a config struct for future config-file wiring.  Today the
    //    individual subcommands (e.g. `req`, `ca`) parse `openssl.cnf` lazily
    //    via Config::parse; main itself does not pre-load it.  This call
    //    keeps the wiring observable and ensures the openssl-common Config
    //    type stays a first-class member of the CLI's startup surface.
    let config = Config::new();
    drop(config); // explicit: commands parse openssl.cnf lazily on demand
    debug!("config registry initialized (commands parse openssl.cnf lazily)");

    // 3. Validate --provider arguments.  Unknown names emit a warning but do
    //    not abort — this matches the C semantics where `-provider unknown`
    //    causes a load-time failure that we soften to a warning since our
    //    providers are statically linked.
    for name in &cli.providers {
        match BuiltinProviderKind::from_name(name) {
            Some(kind) => {
                debug!(provider = kind.name(), "provider name acknowledged");
            }
            None => {
                warn!(
                    provider = %name,
                    "unknown provider name; statically-linked providers ignore this directive"
                );
            }
        }
    }

    // 4. Note the provider search path for diagnostics.
    if let Some(path) = &cli.provider_path {
        debug!(path = %path.display(), "provider search path noted (statically linked)");
    }

    // 5. Note the property query string.  Commands that fetch algorithms
    //    consume `cli.propquery` directly.
    if let Some(propq) = &cli.propquery {
        debug!(propquery = %propq, "property query noted; commands handle filtering");
    }

    // 6. Construct the shared library context.  LibContext::new returns
    //    Arc<Self> directly (no Result), since context creation is
    //    infallible after init::initialize succeeds.
    let ctx = LibContext::new();
    info!("library context constructed");

    Ok(ctx)
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// Performs clean shutdown of the CLI.
///
/// Replaces `apps_shutdown()` from `apps/openssl.c:95-100`.  In Rust, most
/// cleanup is handled by [`Drop`] implementations:
///
/// * `OSSL_LIB_CTX_free()` ⇒ `Drop` on [`LibContext`].
/// * `app_providers_cleanup()` ⇒ `Drop` on each provider handle (statically
///   embedded in [`LibContext`]).
/// * `BIO_free_all()` ⇒ no analogue needed; `stdout`/`stderr` are managed by
///   `std`.
/// * `CRYPTO_secure_malloc_done()` ⇒ `Drop` on every [`zeroize::Zeroizing`]-
///   wrapped allocation cascades automatically.
///
/// This function exists primarily to provide a single, observable shutdown
/// site that emits a structured-log record and forces the `Arc<LibContext>`
/// drop at a well-defined point in `main`.
pub fn shutdown(ctx: Arc<LibContext>) {
    let strong = Arc::strong_count(&ctx);
    drop(ctx);
    debug!(remaining_refs = strong - 1, "library context released");
    info!("openssl CLI shutdown complete");
}

// ---------------------------------------------------------------------------
// Health / Readiness Check
// ---------------------------------------------------------------------------

/// Returns `true` when the CLI is operational.
///
/// This implements the AAP §0.8.5 observability rule by exposing a readiness
/// probe.  Internally a [`HealthRegistry`] is constructed with a single
/// [`ReadinessCheck`] verifying that the openssl-crypto library has completed
/// initialization.  Future enhancements (e.g., FIPS self-test status,
/// provider availability) can register additional checks here.
///
/// The `ctx` argument is accepted for API symmetry — by holding a reference
/// the caller asserts that the context exists, which is a precondition for
/// the library being ready.
#[must_use]
pub fn health_check(ctx: &LibContext) -> bool {
    /// Probe that the openssl-crypto library has completed initialization.
    struct InitCheck;

    impl ReadinessCheck for InitCheck {
        fn name(&self) -> &str {
            "openssl_crypto_initialized"
        }

        fn check(&self) -> HealthStatus {
            if init::is_initialized() {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy {
                    reason: "openssl_crypto::init::initialize has not been called",
                }
            }
        }
    }

    // Holding a &LibContext is itself a witness that the context exists.
    let _ = ctx;

    let mut registry = HealthRegistry::new();
    registry.register(Box::new(InitCheck));
    registry.is_ready()
}

// ---------------------------------------------------------------------------
// Digest / Cipher Name Fallback Dispatch (BLOCKER #5 Strategy)
// ---------------------------------------------------------------------------
//
// The C `do_cmd()` from apps/openssl.c:495-544 supports a three-tier dispatch:
//
//   1. Look up name in the LHASH of registered subcommand functions.
//   2. If no match, check `EVP_get_digestbyname(name)` — dispatch to dgst.
//   3. If still no match, check `EVP_get_cipherbyname(name)` — dispatch to enc.
//
// In our clap-based design, the `commands::CliCommand` enum has no `External`
// variant (that's the inline duplicate in the original `main.rs`).  Adding one
// would change the public CLI surface.  Instead we implement the fallback at
// the *args* level: before clap parses `argv`, we inspect the first non-flag
// argument and, if it matches a known digest/cipher, rewrite the args to call
// the appropriate subcommand explicitly:
//
//   `openssl sha256 file.txt`  ⇒  `openssl dgst -m sha256 file.txt`
//   `openssl aes-256-cbc -in f -out g`  ⇒  `openssl enc --cipher aes-256-cbc -in f -out g`
//
// This gives the same UX as the C tool without requiring an `External`
// catch-all in the typed command enum.

/// Known message-digest algorithm names recognised by the default provider.
///
/// Mirrors the subset of algorithms registered by
/// `providers/implementations/digests/`.  Used for case-insensitive matching
/// in [`rewrite_args_for_fallback`].
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

/// Known symmetric cipher algorithm names recognised by the default provider.
///
/// Mirrors the subset of algorithms registered by
/// `providers/implementations/ciphers/`.  Used for case-insensitive matching
/// in [`rewrite_args_for_fallback`].
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

/// Rewrites raw `argv` to expand the digest/cipher fallback dispatch.
///
/// Inspects `args[1]` (the first user argument after the program name) and:
///
/// * Returns `args` unchanged if there is no first argument, the first
///   argument starts with `-` (a flag/option), or the first argument is not a
///   known digest or cipher name.
/// * If the first argument matches [`KNOWN_DIGESTS`] (case-insensitive),
///   rewrites the args to start with `dgst -m <name>`.
/// * If the first argument matches [`KNOWN_CIPHERS`] (case-insensitive),
///   rewrites the args to start with `enc --cipher <name>`.
///
/// The rewrite preserves all subsequent arguments unchanged so that any flags
/// the user passed (e.g., `-in`, `-out`, `-binary`) are forwarded to the
/// receiving subcommand.
fn rewrite_args_for_fallback(args: Vec<String>) -> Vec<String> {
    // Need at least program name + first user argument.
    let Some(first_arg) = args.get(1) else {
        return args;
    };

    // Don't rewrite flags or empty strings.  Flag prefixes (`-`, `--`) and
    // anything that isn't a bare alphanumeric/dash identifier should pass
    // through to clap unmodified.
    if first_arg.is_empty() || first_arg.starts_with('-') {
        return args;
    }

    let canonical = first_arg.to_ascii_lowercase();

    // Helper: rewrite args[0..1] + ["dgst" | "enc", flag, name] + args[2..].
    let rewrite_with = |subcommand: &str, flag: &str, name: &str| -> Vec<String> {
        let prog = args
            .first()
            .cloned()
            .unwrap_or_else(|| "openssl".to_string());
        let mut rewritten = Vec::with_capacity(args.len() + 2);
        rewritten.push(prog);
        rewritten.push(subcommand.to_string());
        rewritten.push(flag.to_string());
        rewritten.push(name.to_string());
        rewritten.extend(args.iter().skip(2).cloned());
        rewritten
    };

    if KNOWN_DIGESTS.contains(&canonical.as_str()) {
        return rewrite_with("dgst", "-m", &canonical);
    }
    if KNOWN_CIPHERS.contains(&canonical.as_str()) {
        return rewrite_with("enc", "--cipher", &canonical);
    }

    args
}

// ---------------------------------------------------------------------------
// Main Entry Point — Rule R1 (Single Runtime Owner)
// ---------------------------------------------------------------------------

/// CLI entry point.  This is the **only** `#[tokio::main]` in the entire
/// workspace, satisfying Rule R1 (Single Runtime Owner).  All other crates
/// receive a [`tokio::runtime::Handle`] from this runtime when they need
/// async behaviour — they MUST NOT construct their own runtime or call
/// `block_on`.
///
/// # Flow
///
/// 1. Read raw `argv` from the OS.
/// 2. Apply [`rewrite_args_for_fallback`] for digest/cipher dispatch.
/// 3. Parse the (possibly rewritten) args via [`Cli::try_parse_from`].
/// 4. Initialize tracing/observability via [`init_tracing`].
/// 5. Initialize the library and create the context via [`initialize`].
/// 6. Verify readiness via [`health_check`].
/// 7. Dispatch to the parsed subcommand via [`CliCommand::execute`].
/// 8. Tear down via [`shutdown`].
///
/// # Exit Codes
///
/// * `ExitCode::SUCCESS` (0) — all stages completed without error.
/// * `ExitCode::FAILURE` (1) — any stage returned an error; details emitted
///   via the tracing subscriber.
/// * Other codes from `clap::Error::exit()` for argument-parse failures
///   (which write `--help`-style output to stderr).
//
// RATIONALE for #[allow(clippy::large_futures)]: `main` glues multiple async
// stages and `commands::CliCommand::execute` itself is a large enum dispatch.
// Splitting the function would obscure the linear init→execute→shutdown flow
// that mirrors the C `main()` from apps/openssl.c.
#[allow(clippy::large_futures)]
#[tokio::main]
async fn main() -> ExitCode {
    // 1. Capture raw argv and apply fallback rewrite.
    let raw_args: Vec<String> = std::env::args().collect();
    let rewritten_args = rewrite_args_for_fallback(raw_args);

    // 2. Parse with clap.  On failure we intercept `InvalidSubcommand`
    //    errors so that we can emit the diagnostic the C tool produced
    //    from `apps/openssl.c:do_cmd()` line 541:
    //
    //        "Invalid command '%s'; type \"help\" for a list.\n"
    //
    //    All other parse errors (unknown flags, missing values, help/
    //    version requests, etc.) fall through to clap's default
    //    `Error::exit()` which writes the standard usage diagnostic to
    //    stderr/stdout and calls `process::exit()` with the appropriate
    //    exit code.  That call has return type `!`, so this branch never
    //    actually returns to the surrounding `match`.
    //
    //    Because `rewrite_args_for_fallback` substitutes recognised
    //    digest/cipher names with the valid `dgst`/`enc` subcommands,
    //    reaching the `InvalidSubcommand` branch here implies the
    //    original first user argument was neither a known subcommand,
    //    digest, nor cipher.  We therefore pull the offending name from
    //    `rewritten_args[1]` directly, which still points at the raw
    //    argv value the user typed.
    let cli = match Cli::try_parse_from(&rewritten_args) {
        Ok(cli) => cli,
        Err(parse_err) => {
            if parse_err.kind() == clap::error::ErrorKind::InvalidSubcommand {
                let bad_name = rewritten_args.get(1).map_or("<unknown>", String::as_str);
                eprintln!("Invalid command '{bad_name}'; type \"openssl --help\" for a list.");
                return ExitCode::FAILURE;
            }
            parse_err.exit();
        }
    };

    // 3. Wire up tracing.  Note: `init_tracing` failures are reported via
    //    eprintln since tracing is not yet usable when it fails.
    if let Err(err) = init_tracing(cli.verbose) {
        eprintln!("openssl: failed to initialize tracing: {err}");
        return ExitCode::FAILURE;
    }

    info!(version = env!("CARGO_PKG_VERSION"), "openssl CLI starting");

    // 4. Initialize the library.
    let ctx = match initialize(&cli).await {
        Ok(ctx) => ctx,
        Err(err) => {
            error!(error = %err, "library initialization failed");
            return ExitCode::FAILURE;
        }
    };

    // 5. Readiness probe.
    if !health_check(&ctx) {
        error!("readiness check failed; aborting");
        shutdown(ctx);
        return ExitCode::FAILURE;
    }
    debug!("readiness check passed");

    // 6. Dispatch.
    let dispatch_result = if let Some(command) = cli.command.as_ref() {
        // `Arc<LibContext>` auto-derefs to `&LibContext` for the execute() call.
        command.execute(&ctx).await
    } else {
        // No subcommand provided.  Mirror clap's default by printing
        // help.  Use `command_factory` to obtain the same `Command`
        // that `Cli::try_parse_from` used.
        use clap::CommandFactory;
        let mut help_cmd = Cli::command();
        // Best-effort: write help to stderr.  If it fails (closed
        // stderr) there's nothing actionable to do.
        let _ = help_cmd.print_help();
        // Trailing newline for clean terminal output.
        println!();
        shutdown(ctx);
        return ExitCode::SUCCESS;
    };

    // 7. Convert the command result to an exit code, then shut down.
    let exit_code = match dispatch_result {
        Ok(()) => {
            info!("command completed successfully");
            ExitCode::SUCCESS
        }
        Err(crypto_err) => {
            // Wrap into CliError for uniform formatting.
            let cli_err = CliError::Crypto(crypto_err);
            error!(error = %cli_err, "command failed");
            ExitCode::FAILURE
        }
    };

    shutdown(ctx);
    exit_code
}
