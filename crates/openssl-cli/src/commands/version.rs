//! `version` subcommand implementation — Library/Build Version Information.
//!
//! Rewrite of `apps/version.c` (172 lines in C). Provides the `openssl version`
//! subcommand for querying build and library identification metadata through
//! individual flag toggles. Unlike the `info` subcommand (which requires exactly
//! one flag), the `version` command allows **multiple flags** simultaneously and
//! defaults to showing the library version when no flags are specified.
//!
//! # C Correspondence
//!
//! | C Pattern | Rust Pattern |
//! |-----------|-------------|
//! | `OPTION_CHOICE` enum (10 variants + `OPT_W`) | `VersionArgs` boolean fields (11 flags) |
//! | `opt_next()` loop + `dirty` counter | Boolean fields; if none set → show version |
//! | `OPENSSL_VERSION_TEXT` | `env!("CARGO_PKG_VERSION")` workspace version |
//! | `OpenSSL_version(type)` return value | Per-type compile-time constants |
//! | `BN_options()` | `bn_options()` compile-time string |
//! | `OpenSSL_version(OPENSSL_CPU_INFO)` | [`capabilities()`] from `openssl_crypto::cpu_detect` |
//! | `printf(...)` | `println!(...)` |
//! | `#if defined(_WIN32)` / `OPT_W` | `#[cfg(target_os = "windows")]` on `windows_context` field |
//! | `if (!dirty) version = 1;` | Default to showing version when no flags set |
//!
//! # Differences from C
//!
//! - **Version string:** Uses `env!("CARGO_PKG_VERSION")` (Cargo workspace version)
//!   rather than the C `OPENSSL_VERSION_TEXT` macro. The "Library" portion shows the
//!   runtime crate version.
//! - **Build date:** Uses `env!("OPENSSL_RS_BUILD_DATE")` build-time override if set,
//!   otherwise falls back to a compile-time constant.
//! - **Compiler flags:** Reports `rustc` version and target triple instead of C
//!   compiler flags.
//! - **BN options:** Reports the Rust `num-bigint` backend characteristics.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `Option<T>` replaces sentinel values. Seed source uses
//!   `Option<&str>` instead of the C `src ? src : "N/A"` sentinel pattern.
//! - **R6 (Lossless Casts):** No bare `as` casts in this module.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `main.rs → CliCommand::Version → VersionArgs::execute()`.
//!
//! # Examples
//!
//! ```text
//! $ openssl version
//! OpenSSL-RS 0.1.0 (Library: 0.1.0)
//!
//! $ openssl version -a
//! OpenSSL-RS 0.1.0 (Library: 0.1.0)
//! built on: Thu Jan  1 00:00:00 1970 UTC
//! platform: x86_64-unknown-linux-gnu
//! options: bn(64 bits)
//! compiler: rustc (target: x86_64-unknown-linux-gnu)
//! OPENSSLDIR: "/usr/local/ssl"
//! MODULESDIR: "/usr/local/lib/ossl-modules"
//! Seeding source: os
//! CPUINFO: arch=x86_64 SSE2 AESNI AVX2 ...
//!
//! $ openssl version -v -b
//! OpenSSL-RS 0.1.0 (Library: 0.1.0)
//! built on: Thu Jan  1 00:00:00 1970 UTC
//! ```

use clap::Args;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::cpu_detect::capabilities;

// =============================================================================
// Compile-Time Build Metadata Constants
// =============================================================================
//
// These constants replicate the values returned by C `OpenSSL_version()`.
// In the C codebase, these are set by the build system (Configure script)
// via preprocessor defines. In Rust, they are compile-time constants that
// can be overridden at build time via `option_env!()` environment variables.

/// Crate version string — replaces C `OPENSSL_VERSION_TEXT`.
///
/// Sourced from the workspace `Cargo.toml` version field via
/// `env!("CARGO_PKG_VERSION")`. This is the authoritative version string
/// for the Rust implementation.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Product name for the Rust implementation.
///
/// Distinguishes the Rust rewrite from the original C `OpenSSL` binary
/// in version output. The format mirrors the C pattern:
/// `"OpenSSL 4.0.0-dev"` → `"OpenSSL-RS 0.1.0"`.
const PRODUCT_NAME: &str = "OpenSSL-RS";

/// Default configuration directory — replaces C `OPENSSLDIR` from Configure.
///
/// This is the directory where `openssl.cnf` and other configuration files
/// reside. Can be overridden at build time by setting the `OPENSSL_CONFIG_DIR`
/// environment variable during `cargo build`.
const DEFAULT_CONFIG_DIR: &str = "/usr/local/ssl";

/// Default modules directory — replaces C `MODULESDIR` from Configure.
///
/// This is where provider shared libraries are loaded from at runtime.
/// Can be overridden at build time by setting the `OPENSSL_MODULES_DIR`
/// environment variable during `cargo build`.
const DEFAULT_MODULES_DIR: &str = "/usr/local/lib/ossl-modules";

/// Default build date string — replaces C `OPENSSL_BUILT_ON`.
///
/// In the C implementation, this is set by the build system during compilation.
/// The Rust build can override via the `OPENSSL_RS_BUILD_DATE` environment
/// variable at compile time. Falls back to a placeholder when not set.
const DEFAULT_BUILD_DATE: &str = "reproducible build, date unspecified";

/// Configured random seed sources — replaces C `OPENSSL_INFO_SEED_SOURCE`.
///
/// In the Rust implementation, the primary seed source is the OS random number
/// generator (`getrandom` / `CryptGenRandom`) via the `rand` crate's `OsRng`.
const SEED_SOURCES: &str = "os";

/// Target architecture name — compile-time constant from `std::env::consts`.
///
/// Provides the target CPU architecture (e.g., `"x86_64"`, `"aarch64"`).
/// Combined with [`TARGET_OS`] and [`TARGET_ENV`] to produce the full
/// platform identification string, replacing the C `OPENSSL_PLATFORM`
/// define from the Configure script.
const TARGET_ARCH: &str = std::env::consts::ARCH;

/// Target operating system name — compile-time constant from `std::env::consts`.
///
/// Provides the target OS (e.g., `"linux"`, `"macos"`, `"windows"`).
const TARGET_OS: &str = std::env::consts::OS;

/// `BigNum` options string — replaces C `BN_options()`.
///
/// The C `BN_options()` returns a string like `"bn(64,64)"` indicating the
/// `BN_ULONG` size and internal word size. Since the Rust implementation uses
/// `num-bigint` (arbitrary-precision pure Rust), we report the pointer width
/// as the effective word size.
#[cfg(target_pointer_width = "64")]
const BN_OPTIONS: &str = "bn(64 bits)";
#[cfg(target_pointer_width = "32")]
const BN_OPTIONS: &str = "bn(32 bits)";
#[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
const BN_OPTIONS: &str = "bn(unknown)";

// =============================================================================
// VersionArgs — CLI Argument Struct
// =============================================================================

/// Arguments for the `openssl version` subcommand.
///
/// Each flag toggles display of a specific metadata category. Multiple flags
/// may be specified simultaneously. When no flags are specified, the command
/// defaults to displaying the version string only (matching the C behavior
/// where `if (!dirty) version = 1`).
///
/// # Flag-to-C Mapping
///
/// | Flag | Short | C Equivalent | Description |
/// |------|-------|-------------|-------------|
/// | `--all` | `-a` | `OPT_A` | Show all information |
/// | `--build-date` | `-b` | `OPT_B` | Show build date |
/// | `--config-dir` | `-d` | `OPT_D` | Show configuration directory |
/// | `--modules-dir` | `-m` | `OPT_M` | Show modules directory |
/// | `--compiler-flags` | `-f` | `OPT_F` | Show compiler flags |
/// | `--options` | `-o` | `OPT_O` | Show BN/datatype options |
/// | `--platform` | `-p` | `OPT_P` | Show target platform |
/// | `--seed` | `-r` | `OPT_R` | Show random seed sources |
/// | `--version` | `-v` | `OPT_V` | Show library version |
/// | `--cpu-settings` | `-c` | `OPT_C` | Show detected CPU features |
/// | `--windows-context` | `-w` | `OPT_W` | Show Windows context (Windows only) |
///
/// # Default Behavior
///
/// When no flags are specified (all false), the command displays the version
/// string only, matching the C behavior:
/// ```c
/// if (!dirty)
///     version = 1;
/// ```
// ALLOW: VersionArgs has 11 boolean flags representing independent CLI options.
// This is the idiomatic clap pattern for flag-toggled output sections. The C
// original uses an identical pattern with 11 independent integer flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct VersionArgs {
    /// Show all version/build information at once.
    ///
    /// Equivalent to specifying every other flag simultaneously. In the C
    /// implementation, `OPT_A` sets all individual flag variables to 1.
    #[arg(short = 'a', long = "all", help = "Show all data")]
    pub all: bool,

    /// Show the build date.
    ///
    /// Displays when the library was built. In C, this calls
    /// `OpenSSL_version(OPENSSL_BUILT_ON)`. In Rust, uses the
    /// `OPENSSL_RS_BUILD_DATE` build-time environment variable or a
    /// default placeholder.
    #[arg(short = 'b', long = "build-date", help = "Show build date")]
    pub build_date: bool,

    /// Show the default configuration directory path.
    ///
    /// Displays the `OPENSSLDIR` where `openssl.cnf` and certificate stores
    /// are located. In C, this calls `OpenSSL_version(OPENSSL_DIR)`.
    #[arg(
        short = 'd',
        long = "config-dir",
        help = "Show configuration directory"
    )]
    pub config_dir: bool,

    /// Show the default modules (providers) directory path.
    ///
    /// Displays the `MODULESDIR` where provider shared libraries are loaded
    /// from. In C, this calls `OpenSSL_version(OPENSSL_MODULES_DIR)`.
    #[arg(short = 'm', long = "modules-dir", help = "Show modules directory")]
    pub modules_dir: bool,

    /// Show compiler flags used to build the library.
    ///
    /// In C, this calls `OpenSSL_version(OPENSSL_CFLAGS)` to show the C
    /// compiler command-line flags. In Rust, this reports the `rustc` version
    /// and target triple used during compilation.
    #[arg(
        short = 'f',
        long = "compiler-flags",
        help = "Show compiler flags used"
    )]
    pub compiler_flags: bool,

    /// Show internal datatype options (BN configuration).
    ///
    /// Displays the bignum library configuration. In C, this calls
    /// `BN_options()` which returns the `BN_ULONG` word size. In Rust, this
    /// reports the pointer width (reflecting the `num-bigint` backend).
    #[arg(
        short = 'o',
        long = "options",
        help = "Show some internal datatype options"
    )]
    pub options: bool,

    /// Show the target build platform.
    ///
    /// Displays the platform/target triple the library was compiled for.
    /// In C, this calls `OpenSSL_version(OPENSSL_PLATFORM)`.
    #[arg(short = 'p', long = "platform", help = "Show target build platform")]
    pub platform: bool,

    /// Show random seeding source information.
    ///
    /// Displays the configured entropy seed source(s) for the DRBG.
    /// In C, this calls `OPENSSL_info(OPENSSL_INFO_SEED_SOURCE)`.
    /// The C code uses the pattern `src ? src : "N/A"` which is replaced
    /// by `Option<&str>` per Rule R5.
    #[arg(short = 'r', long = "seed", help = "Show random seeding options")]
    pub seed: bool,

    /// Show the library version string.
    ///
    /// Displays the product name and version number. In C, this prints
    /// `OPENSSL_VERSION_TEXT` and `OpenSSL_version(OPENSSL_VERSION)`.
    #[arg(short = 'v', long = "version", help = "Show library version")]
    pub version: bool,

    /// Show detected CPU capability settings.
    ///
    /// Displays the CPU architecture and detected hardware acceleration
    /// features (AES-NI, SHA extensions, AVX, NEON, etc.). Uses
    /// [`openssl_crypto::cpu_detect::capabilities()`] to query cached
    /// detection results.
    /// C equivalent: `OpenSSL_version(OPENSSL_CPU_INFO)`.
    #[arg(short = 'c', long = "cpu-settings", help = "Show CPU settings info")]
    pub cpu_settings: bool,

    /// Show Windows-specific security context information.
    ///
    /// Only available on Windows platforms. Displays information about the
    /// loaded Windows security context. Matches the C conditional:
    /// ```c
    /// #if defined(_WIN32)
    ///     { "w", OPT_W, '-', "Show Windows install context" },
    /// #endif
    /// ```
    #[cfg(target_os = "windows")]
    #[arg(
        short = 'w',
        long = "windows-context",
        help = "Show Windows install context"
    )]
    pub windows_context: bool,
}

// =============================================================================
// VersionArgs Implementation
// =============================================================================

impl VersionArgs {
    /// Execute the `openssl version` subcommand.
    ///
    /// Evaluates which flags are set and prints the corresponding metadata
    /// sections. When no flags are set, defaults to printing the version
    /// string only (matching the C `if (!dirty) version = 1` behavior).
    ///
    /// # Arguments
    ///
    /// * `_ctx` — Library context ([`LibContext`]). Passed by the uniform
    ///   dispatch interface but unused by this command since all metadata
    ///   is compile-time or CPU-detection data.
    ///
    /// # Errors
    ///
    /// This command is infallible under normal operation. Returns
    /// `Ok(())` on success. The [`CryptoError`] return type is required
    /// by the [`CliCommand::execute()`](super::CliCommand::execute)
    /// dispatch interface.
    ///
    /// # C Correspondence
    ///
    /// Replaces `version_main()` from `apps/version.c` (lines 58–159).
    /// The C function uses a `dirty` flag to track whether any option was
    /// specified. If no options are specified (`!dirty`), it defaults to
    /// showing the version. This Rust implementation uses
    /// [`is_any_flag_set()`](Self::is_any_flag_set) for the same check.
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // Determine effective flags — if `-a` (all) is set, enable everything.
        // If no flags are set, default to showing version only.
        // This matches the C behavior:
        //   case OPT_A: seed = options = cflags = version = date = platform
        //       = dir = moddir = cpuinfo = 1; break;
        //   if (!dirty) version = 1;
        let show_all = self.all;
        let show_version = self.version || show_all || !self.is_any_flag_set();
        let show_build_date = self.build_date || show_all;
        let show_platform = self.platform || show_all;
        let show_options = self.options || show_all;
        let show_compiler_flags = self.compiler_flags || show_all;
        let show_config_dir = self.config_dir || show_all;
        let show_modules_dir = self.modules_dir || show_all;
        let show_seed = self.seed || show_all;
        let show_cpu_settings = self.cpu_settings || show_all;

        #[cfg(target_os = "windows")]
        let show_windows_context = self.windows_context || show_all;

        // Output each section in the same order as the C implementation
        // (version.c lines 128–155): version, date, platform, options,
        // cflags, dir, moddir, seed, cpuinfo, [windows].

        if show_version {
            let version_text = format_version_text();
            tracing::debug!(version = %version_text, "Displaying version");
            println!("{version_text}");
        }

        if show_build_date {
            let build_date = format_build_date();
            tracing::debug!(build_date = %build_date, "Displaying build date");
            println!("{build_date}");
        }

        if show_platform {
            let platform_str = format_platform();
            tracing::debug!(platform = %platform_str, "Displaying platform");
            println!("{platform_str}");
        }

        if show_options {
            let options_str = format_options();
            tracing::debug!(options = %options_str, "Displaying options");
            println!("{options_str}");
        }

        if show_compiler_flags {
            let cflags = format_compiler_flags();
            tracing::debug!(compiler_flags = %cflags, "Displaying compiler flags");
            println!("{cflags}");
        }

        if show_config_dir {
            let dir = format_config_dir();
            tracing::debug!(config_dir = %dir, "Displaying config directory");
            println!("{dir}");
        }

        if show_modules_dir {
            let moddir = format_modules_dir();
            tracing::debug!(modules_dir = %moddir, "Displaying modules directory");
            println!("{moddir}");
        }

        if show_seed {
            let seed_str = format_seed_source();
            tracing::debug!(seed_source = %seed_str, "Displaying seed source");
            println!("{seed_str}");
        }

        if show_cpu_settings {
            let cpu_str = format_cpu_info();
            tracing::debug!(cpu_info = %cpu_str, "Displaying CPU info");
            println!("{cpu_str}");
        }

        #[cfg(target_os = "windows")]
        if show_windows_context {
            let winctx = format_windows_context();
            tracing::debug!(windows_context = %winctx, "Displaying Windows context");
            println!("{winctx}");
        }

        Ok(())
    }

    /// Check whether any individual flag is set.
    ///
    /// Returns `true` if at least one flag (other than the implicit defaults)
    /// is explicitly specified by the user. Used to implement the C
    /// `dirty` counter pattern: when no flags are set, the version command
    /// defaults to showing the version string only.
    ///
    /// # C Correspondence
    ///
    /// Replaces the `dirty` variable from `version_main()`:
    /// ```c
    /// int ret = 1, dirty = 0, seed = 0;
    /// // ... each option sets dirty = 1
    /// if (!dirty) version = 1;
    /// ```
    fn is_any_flag_set(&self) -> bool {
        let base_flags = self.all
            || self.build_date
            || self.config_dir
            || self.modules_dir
            || self.compiler_flags
            || self.options
            || self.platform
            || self.seed
            || self.version
            || self.cpu_settings;

        #[cfg(target_os = "windows")]
        {
            base_flags || self.windows_context
        }

        #[cfg(not(target_os = "windows"))]
        {
            base_flags
        }
    }
}

// =============================================================================
// Formatting Functions — One per Output Section
// =============================================================================
//
// Each function corresponds to a printf() call in the C version_main() function.
// They are separated for clarity, testability, and to match the C output format
// as closely as possible while using Rust-native information sources.

/// Construct the target platform triple string from compile-time constants.
///
/// Combines `TARGET_ARCH`, `TARGET_OS`, and optionally the target environment
/// into a single identifier string (e.g., `"x86_64-linux-gnu"` or
/// `"aarch64-macos"`). The environment suffix is omitted on platforms without
/// a specific ABI designation (macOS, iOS).
fn format_target_triple() -> String {
    // Use cfg! to select the environment suffix at compile time. This avoids
    // the clippy::const_is_empty lint that fires when checking a const &str
    // that is statically known to be non-empty on a given target.
    #[cfg(target_env = "gnu")]
    let env_suffix: &str = "-gnu";
    #[cfg(target_env = "musl")]
    let env_suffix: &str = "-musl";
    #[cfg(target_env = "msvc")]
    let env_suffix: &str = "-msvc";
    #[cfg(target_env = "sgx")]
    let env_suffix: &str = "-sgx";
    #[cfg(not(any(
        target_env = "gnu",
        target_env = "musl",
        target_env = "msvc",
        target_env = "sgx"
    )))]
    let env_suffix: &str = "";

    format!("{TARGET_ARCH}-{TARGET_OS}{env_suffix}")
}

/// Format the version text line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s (Library: %s)\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
/// ```
///
/// Output format: `"OpenSSL-RS 0.1.0 (Library: 0.1.0)"`
fn format_version_text() -> String {
    format!("{PRODUCT_NAME} {VERSION} (Library: {VERSION})")
}

/// Format the build date line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s\n", OpenSSL_version(OPENSSL_BUILT_ON));
/// ```
///
/// Checks the `OPENSSL_RS_BUILD_DATE` compile-time environment variable first,
/// falling back to [`DEFAULT_BUILD_DATE`]. This allows reproducible builds
/// while still supporting build-date embedding via CI.
///
/// Output format: `"built on: <date>"`
fn format_build_date() -> String {
    let date = option_env!("OPENSSL_RS_BUILD_DATE").unwrap_or(DEFAULT_BUILD_DATE);
    format!("built on: {date}")
}

/// Format the platform line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s\n", OpenSSL_version(OPENSSL_PLATFORM));
/// ```
///
/// Constructs the platform identification from Rust compile-time constants
/// (`TARGET_ARCH`, `TARGET_OS`, `TARGET_ENV`). This provides equivalent
/// information to the C `PLATFORM` define set by the `Configure` script.
///
/// Output format: `"platform: x86_64-linux-gnu"` or `"platform: aarch64-macos"`
fn format_platform() -> String {
    format!("platform: {}", format_target_triple())
}

/// Format the internal datatype options line.
///
/// Replaces the C pattern:
/// ```c
/// printf("options: ");
/// printf(" %s", BN_options());
/// printf("\n");
/// ```
///
/// Reports the `BigNum` word size, which reflects the pointer width of the
/// target platform. The `num-bigint` crate uses native-width limbs.
///
/// Output format: `"options:  bn(64 bits)"`
fn format_options() -> String {
    format!("options:  {BN_OPTIONS}")
}

/// Format the compiler flags line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s\n", OpenSSL_version(OPENSSL_CFLAGS));
/// ```
///
/// In the C implementation, this reports the C compiler flags (e.g.,
/// `"-O2 -Wall -fPIC"`). In the Rust implementation, we report the
/// `rustc` compiler and target since these are the meaningful
/// compilation parameters.
///
/// Output format: `"compiler: rustc (target: x86_64-linux-gnu)"`
fn format_compiler_flags() -> String {
    format!("compiler: rustc (target: {})", format_target_triple())
}

/// Format the configuration directory line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s\n", OpenSSL_version(OPENSSL_DIR));
/// ```
///
/// Uses the `OPENSSL_CONFIG_DIR` build-time environment variable if set,
/// otherwise falls back to [`DEFAULT_CONFIG_DIR`].
///
/// Output format: `"OPENSSLDIR: \"/usr/local/ssl\""`
fn format_config_dir() -> String {
    let dir = option_env!("OPENSSL_CONFIG_DIR").unwrap_or(DEFAULT_CONFIG_DIR);
    format!("OPENSSLDIR: \"{dir}\"")
}

/// Format the modules directory line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s\n", OpenSSL_version(OPENSSL_MODULES_DIR));
/// ```
///
/// Uses the `OPENSSL_MODULES_DIR` build-time environment variable if set,
/// otherwise falls back to [`DEFAULT_MODULES_DIR`].
///
/// Output format: `"MODULESDIR: \"/usr/local/lib/ossl-modules\""`
fn format_modules_dir() -> String {
    let dir = option_env!("OPENSSL_MODULES_DIR").unwrap_or(DEFAULT_MODULES_DIR);
    format!("MODULESDIR: \"{dir}\"")
}

/// Format the seed source information line.
///
/// Replaces the C pattern:
/// ```c
/// const char *src = OPENSSL_info(OPENSSL_INFO_SEED_SOURCE);
/// printf("Seeding source: %s\n", src ? src : "N/A");
/// ```
///
/// Per Rule R5 (Nullability Over Sentinels), the C null-check-with-sentinel
/// pattern (`src ? src : "N/A"`) is replaced with an `Option<&str>` and
/// explicit display of "N/A" only when the source is genuinely unknown.
///
/// Output format: `"Seeding source: os"`
fn format_seed_source() -> String {
    // In the Rust implementation, the seed source is always known at compile
    // time (using the OS random number generator). The Option is retained to
    // maintain the R5-compliant pattern for when build-time configuration
    // might set it to None.
    let source: Option<&str> = Some(SEED_SOURCES);
    match source {
        Some(src) => format!("Seeding source: {src}"),
        None => "Seeding source: N/A".to_string(),
    }
}

/// Format the CPU capability information line.
///
/// Replaces the C pattern:
/// ```c
/// printf("%s\n", OpenSSL_version(OPENSSL_CPU_INFO));
/// ```
///
/// Calls [`capabilities()`] from `openssl_crypto::cpu_detect` to obtain the
/// lazily-initialized CPU capability singleton, then formats it as a
/// human-readable string listing the architecture and detected features.
///
/// Output format: `"CPUINFO: arch=x86_64 SSE2 AESNI AVX2 PCLMULQDQ SHA ..."`
fn format_cpu_info() -> String {
    let caps = capabilities();
    let settings = format_cpu_settings(caps);
    format!("CPUINFO: {settings}")
}

/// Format detected CPU capabilities as a human-readable feature list.
///
/// Builds a string of the form `"arch=<arch> [FEATURE1 FEATURE2 ...]"` from
/// the cached [`CpuCapabilities`](openssl_crypto::cpu_detect::CpuCapabilities)
/// struct. Feature names match the conventional nomenclature used in CPU
/// capability reporting.
///
/// This is an internal helper shared between the `format_cpu_info()` function
/// and potential future callers. It uses the same feature name tables as the
/// `info` command's `format_cpu_settings()` for consistency.
fn format_cpu_settings(caps: &openssl_crypto::cpu_detect::CpuCapabilities) -> String {
    // Architecture prefix — always present.
    let mut result = format!("arch={}", caps.arch);

    // Collect and append x86 feature names.
    for name in collect_x86_feature_names(caps) {
        result.push(' ');
        result.push_str(name);
    }

    // Collect and append ARM feature names.
    for name in collect_arm_feature_names(caps) {
        result.push(' ');
        result.push_str(name);
    }

    result
}

/// Collect names of detected `x86/x86_64` hardware features.
///
/// Returns a vector of human-readable feature names for all detected x86 CPU
/// features. Feature names match the conventional nomenclature (e.g., `AESNI`,
/// `AVX2`, `PCLMULQDQ`). Features are ordered consistently with the
/// [`X86Features`](openssl_crypto::cpu_detect::X86Features) bitflags definition.
fn collect_x86_feature_names(
    caps: &openssl_crypto::cpu_detect::CpuCapabilities,
) -> Vec<&'static str> {
    use openssl_crypto::cpu_detect::X86Features;

    /// Static lookup table mapping x86 feature flags to their display names.
    /// Ordered to match the bitflags definition in `cpu_detect.rs`.
    const X86_FEATURE_NAMES: &[(X86Features, &str)] = &[
        (X86Features::SSE2, "SSE2"),
        (X86Features::SSE3, "SSE3"),
        (X86Features::SSSE3, "SSSE3"),
        (X86Features::SSE41, "SSE4.1"),
        (X86Features::SSE42, "SSE4.2"),
        (X86Features::AESNI, "AESNI"),
        (X86Features::AVX, "AVX"),
        (X86Features::AVX2, "AVX2"),
        (X86Features::AVX512F, "AVX512F"),
        (X86Features::PCLMULQDQ, "PCLMULQDQ"),
        (X86Features::SHA, "SHA"),
        (X86Features::BMI1, "BMI1"),
        (X86Features::BMI2, "BMI2"),
        (X86Features::ADX, "ADX"),
        (X86Features::VAES, "VAES"),
        (X86Features::VPCLMULQDQ, "VPCLMULQDQ"),
    ];

    X86_FEATURE_NAMES
        .iter()
        .filter(|(flag, _)| caps.x86.contains(*flag))
        .map(|(_, name)| *name)
        .collect()
}

/// Collect names of detected ARM/AArch64 hardware features.
///
/// Returns a vector of human-readable feature names for all detected ARM CPU
/// features. Feature names match the conventional `ARMv8` extension nomenclature.
/// Features are ordered consistently with the
/// [`ArmFeatures`](openssl_crypto::cpu_detect::ArmFeatures) bitflags definition.
fn collect_arm_feature_names(
    caps: &openssl_crypto::cpu_detect::CpuCapabilities,
) -> Vec<&'static str> {
    use openssl_crypto::cpu_detect::ArmFeatures;

    /// Static lookup table mapping ARM feature flags to their display names.
    const ARM_FEATURE_NAMES: &[(ArmFeatures, &str)] = &[
        (ArmFeatures::NEON, "NEON"),
        (ArmFeatures::AES, "AES"),
        (ArmFeatures::SHA1, "SHA1"),
        (ArmFeatures::SHA256, "SHA256"),
        (ArmFeatures::PMULL, "PMULL"),
        (ArmFeatures::SHA512, "SHA512"),
        (ArmFeatures::SVE, "SVE"),
        (ArmFeatures::SVE2, "SVE2"),
    ];

    ARM_FEATURE_NAMES
        .iter()
        .filter(|(flag, _)| caps.arm.contains(*flag))
        .map(|(_, name)| *name)
        .collect()
}

/// Format Windows-specific context information.
///
/// Only compiled on Windows platforms. Replaces the C pattern:
/// ```c
/// #if defined(_WIN32)
/// if (windows)
///     printf("%s\n", OpenSSL_version(OPENSSL_WINCTX));
/// #endif
/// ```
///
/// Output format: `"Windows install context: <context>"`
#[cfg(target_os = "windows")]
fn format_windows_context() -> String {
    // On Windows, the context describes the installation scope.
    // In the C implementation this comes from a registry or MSI property.
    // For the Rust build, report the detected context or "N/A".
    let context = option_env!("OPENSSL_WINCTX").unwrap_or("N/A");
    format!("Windows install context: {context}")
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the version text formatting matches expected pattern.
    #[test]
    fn test_format_version_text() {
        let text = format_version_text();
        assert!(
            text.starts_with("OpenSSL-RS "),
            "Should start with product name"
        );
        assert!(text.contains("(Library: "), "Should contain Library label");
        assert!(text.contains(VERSION), "Should contain the version string");
    }

    /// Verify the build date formatting.
    #[test]
    fn test_format_build_date() {
        let date = format_build_date();
        assert!(
            date.starts_with("built on: "),
            "Should start with 'built on: '"
        );
    }

    /// Verify the platform formatting contains architecture and OS.
    #[test]
    fn test_format_platform() {
        let platform = format_platform();
        assert!(
            platform.starts_with("platform: "),
            "Should start with 'platform: '"
        );
        assert!(
            platform.contains(TARGET_ARCH),
            "Should contain the target architecture"
        );
        assert!(platform.contains(TARGET_OS), "Should contain the target OS");
    }

    /// Verify the options formatting contains BN info.
    #[test]
    fn test_format_options() {
        let options = format_options();
        assert!(
            options.starts_with("options: "),
            "Should start with 'options: '"
        );
        assert!(options.contains("bn("), "Should contain BN options");
    }

    /// Verify the compiler flags formatting.
    #[test]
    fn test_format_compiler_flags() {
        let flags = format_compiler_flags();
        assert!(
            flags.starts_with("compiler: rustc"),
            "Should start with 'compiler: rustc'"
        );
        assert!(
            flags.contains(TARGET_ARCH),
            "Should contain target architecture"
        );
    }

    /// Verify the config dir formatting.
    #[test]
    fn test_format_config_dir() {
        let dir = format_config_dir();
        assert!(
            dir.starts_with("OPENSSLDIR: "),
            "Should start with 'OPENSSLDIR: '"
        );
        assert!(dir.contains('"'), "Directory path should be quoted");
    }

    /// Verify the modules dir formatting.
    #[test]
    fn test_format_modules_dir() {
        let dir = format_modules_dir();
        assert!(
            dir.starts_with("MODULESDIR: "),
            "Should start with 'MODULESDIR: '"
        );
        assert!(dir.contains('"'), "Directory path should be quoted");
    }

    /// Verify the seed source formatting.
    #[test]
    fn test_format_seed_source() {
        let seed = format_seed_source();
        assert!(
            seed.starts_with("Seeding source: "),
            "Should start with 'Seeding source: '"
        );
        // Should not be "N/A" in default build since SEED_SOURCES is always set
        assert!(!seed.ends_with("N/A"), "Should have a real seed source");
    }

    /// Verify the CPU info formatting contains arch prefix.
    #[test]
    fn test_format_cpu_info() {
        let cpu = format_cpu_info();
        assert!(
            cpu.starts_with("CPUINFO: arch="),
            "Should start with 'CPUINFO: arch='"
        );
    }

    /// Verify `is_any_flag_set` returns false for default (no flags).
    #[test]
    fn test_no_flags_set() {
        let args = VersionArgs {
            all: false,
            build_date: false,
            config_dir: false,
            modules_dir: false,
            compiler_flags: false,
            options: false,
            platform: false,
            seed: false,
            version: false,
            cpu_settings: false,
            #[cfg(target_os = "windows")]
            windows_context: false,
        };
        assert!(!args.is_any_flag_set(), "No flags should be set");
    }

    /// Verify `is_any_flag_set` returns true when `-a` is set.
    #[test]
    fn test_all_flag_set() {
        let args = VersionArgs {
            all: true,
            build_date: false,
            config_dir: false,
            modules_dir: false,
            compiler_flags: false,
            options: false,
            platform: false,
            seed: false,
            version: false,
            cpu_settings: false,
            #[cfg(target_os = "windows")]
            windows_context: false,
        };
        assert!(args.is_any_flag_set(), "all flag should count as set");
    }

    /// Verify `is_any_flag_set` returns true for single flag.
    #[test]
    fn test_single_flag_set() {
        let args = VersionArgs {
            all: false,
            build_date: true,
            config_dir: false,
            modules_dir: false,
            compiler_flags: false,
            options: false,
            platform: false,
            seed: false,
            version: false,
            cpu_settings: false,
            #[cfg(target_os = "windows")]
            windows_context: false,
        };
        assert!(args.is_any_flag_set(), "build_date flag should count");
    }

    /// Verify the CPU settings format for the current platform.
    #[test]
    fn test_format_cpu_settings_contains_arch() {
        let caps = capabilities();
        let settings = format_cpu_settings(caps);
        assert!(
            settings.starts_with("arch="),
            "CPU settings should start with 'arch='"
        );
    }
}
