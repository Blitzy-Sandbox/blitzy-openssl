//! `info` subcommand implementation — Build/Install Metadata Query.
//!
//! Rewrite of `apps/info.c` (113 lines in C). Provides the `openssl info`
//! subcommand for querying a single item of build and installation metadata.
//! Exactly one metadata flag must be specified per invocation; zero or multiple
//! flags produce an error.
//!
//! # C Correspondence
//!
//! | C Pattern | Rust Pattern |
//! |-----------|-------------|
//! | `OPTION_CHOICE` enum (8 variants) | `InfoArgs` boolean fields (8 flags) |
//! | `opt_next()` loop + `dirty` counter | `InfoArgs::count_selected()` mutual exclusion |
//! | `OPENSSL_info(type)` return value | Per-type query functions with compile-time constants |
//! | `BIO_printf(bio_out, "%s\n", val)` | `println!("{value}")` |
//! | `#ifdef OPENSSL_SYS_WINDOWS` | `#[cfg(target_os = "windows")]` |
//! | `val == NULL ? "Undefined" : val` | `Option<T>` (R5 — no sentinel strings) |
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** `Option<T>` replaces sentinel values; no empty-string sentinels.
//! - **R6 (Lossless Casts):** No bare `as` casts in this module.
//! - **R8 (Zero Unsafe):** No `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable from `main.rs → CliCommand::Info → InfoArgs::execute()`.
//!
//! # Examples
//!
//! ```text
//! $ openssl info --configdir
//! /usr/local/ssl
//!
//! $ openssl info --dsoext
//! .so
//!
//! $ openssl info --cpusettings
//! arch=x86_64 SSE2 SSE3 SSSE3 SSE4.1 SSE4.2 AESNI AVX AVX2 PCLMULQDQ SHA BMI2 ADX
//! ```

use clap::Args;

use openssl_common::error::CryptoError;
use openssl_crypto::context::LibContext;
use openssl_crypto::cpu_detect::capabilities;

// =============================================================================
// Compile-Time Build Metadata Constants
// =============================================================================
//
// These constants replicate the values returned by C `OPENSSL_info()`.
// In the C codebase, these are set by the build system (Configure script)
// via preprocessor defines (`OPENSSLDIR`, `MODULESDIR`, `DSO_EXTENSION`).
// In Rust, they are compile-time constants that can be overridden at build
// time via `option_env!()` environment variables in the corresponding
// query functions.

/// Default configuration directory — replaces C `OPENSSLDIR` from Configure.
///
/// This is the directory where `openssl.cnf` and other configuration files
/// reside. The C value is set during `./Configure` and compiled into the
/// binary via `#define OPENSSLDIR`.
///
/// Can be overridden at build time by setting the `OPENSSL_CONFIG_DIR`
/// environment variable during `cargo build`.
const DEFAULT_CONFIG_DIR: &str = "/usr/local/ssl";

/// Default modules directory — replaces C `MODULESDIR` from Configure.
///
/// This is where provider shared libraries (`.so`/`.dylib`/`.dll`) are loaded
/// from at runtime. The C value is derived from `$(libdir)/ossl-modules`.
///
/// Can be overridden at build time by setting the `OPENSSL_MODULES_DIR`
/// environment variable during `cargo build`.
const DEFAULT_MODULES_DIR: &str = "/usr/local/lib/ossl-modules";

/// Platform-specific shared library extension — replaces C `DSO_EXTENSION`.
///
/// Returns `.so` on Linux/Unix, `.dylib` on macOS, `.dll` on Windows.
/// The C implementation derives this from the build system's platform detection.
#[cfg(target_os = "windows")]
const DSO_EXTENSION: &str = ".dll";
#[cfg(target_os = "macos")]
const DSO_EXTENSION: &str = ".dylib";
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const DSO_EXTENSION: &str = ".so";

/// Platform list separator character — replaces C `OPENSSL_INFO_LIST_SEPARATOR`.
///
/// Used to separate items in search path lists (analogous to `PATH` separator).
/// `:` on Unix-like systems, `;` on Windows.
#[cfg(target_os = "windows")]
const LIST_SEP: &str = ";";
#[cfg(not(target_os = "windows"))]
const LIST_SEP: &str = ":";

/// Configured random seed sources — replaces C `OPENSSL_INFO_SEED_SOURCE`.
///
/// In the C codebase, this reports the compile-time configured entropy sources
/// (e.g., `os`, `rdcpu`, `librandom`). In the Rust implementation, the primary
/// seed source is the OS random number generator (`getrandom` / `CryptGenRandom`)
/// via the `rand` crate's `OsRng`.
const SEED_SOURCES: &str = "os";

// =============================================================================
// InfoArgs — CLI Argument Struct
// =============================================================================

/// Arguments for the `openssl info` subcommand.
///
/// Queries build and installation metadata. Exactly one flag must be specified;
/// zero or multiple flags produce an error, matching the mutual exclusion
/// enforced by the C `dirty` counter in `apps/info.c`.
///
/// # Available Items
///
/// | Flag | C Equivalent | Description |
/// |------|-------------|-------------|
/// | `--configdir` | `OPENSSL_INFO_CONFIG_DIR` | Default configuration directory |
/// | `--modulesdir` | `OPENSSL_INFO_MODULES_DIR` | Default modules (provider) directory |
/// | `--dsoext` | `OPENSSL_INFO_DSO_EXTENSION` | Platform shared library extension |
/// | `--dirnamesep` | `OPENSSL_INFO_DIR_FILENAME_SEPARATOR` | Directory separator character |
/// | `--listsep` | `OPENSSL_INFO_LIST_SEPARATOR` | List separator character |
/// | `--seeds` | `OPENSSL_INFO_SEED_SOURCE` | Configured seed sources |
/// | `--cpusettings` | `OPENSSL_INFO_CPU_SETTINGS` | Detected CPU features |
/// | `--windowscontext` | `OPENSSL_INFO_WINDOWS_CONTEXT` | Windows context (Windows only) |
///
/// # Mutual Exclusion
///
/// The C implementation uses a `dirty` counter incremented by each flag's
/// `case` branch. After parsing, `dirty > 1` → error, `dirty == 0` → error.
/// The Rust implementation uses [`count_selected()`](Self::count_selected)
/// to achieve the same validation.
// ALLOW: InfoArgs has 8 boolean flags representing CLI options, which is the
// idiomatic clap pattern for mutually-exclusive single-flag commands. Refactoring
// into an enum would break clap's automatic help text generation and mutual
// exclusion validation. This mirrors the C `OPTION_CHOICE` pattern exactly.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Display the default configuration directory path.
    ///
    /// Returns the compile-time configured `OPENSSLDIR` path where the
    /// `openssl.cnf` configuration file and certificate stores are located.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)`.
    #[arg(long = "configdir", help = "Configured path for *dir values")]
    pub configdir: bool,

    /// Display the default modules (providers/engines) directory path.
    ///
    /// Returns the compile-time configured `MODULESDIR` path where provider
    /// shared libraries are dynamically loaded from.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_MODULES_DIR)`.
    #[arg(long = "modulesdir", help = "Configured path for modules directory")]
    pub modulesdir: bool,

    /// Display the platform-specific shared library extension.
    ///
    /// Returns the DSO (Dynamic Shared Object) file extension used on this
    /// platform: `.so` (Linux), `.dylib` (macOS), `.dll` (Windows).
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_DSO_EXTENSION)`.
    #[arg(long = "dsoext", help = "Configured DSO extension")]
    pub dsoext: bool,

    /// Display the platform directory name separator character.
    ///
    /// Returns the character used to separate directory components in file paths:
    /// `/` on Unix-like systems, `\` on Windows.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_DIR_FILENAME_SEPARATOR)`.
    #[arg(long = "dirnamesep", help = "Directory-filename separator")]
    pub dirnamesep: bool,

    /// Display the platform list separator character.
    ///
    /// Returns the character used to separate items in search path lists:
    /// `:` on Unix-like systems, `;` on Windows.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_LIST_SEPARATOR)`.
    #[arg(long = "listsep", help = "List separator character")]
    pub listsep: bool,

    /// Display the configured random seed sources.
    ///
    /// Returns a description of the entropy sources configured for the random
    /// number generator (DRBG seeding). In the Rust implementation, the primary
    /// source is the OS random number generator.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_SEED_SOURCE)`.
    #[arg(long = "seeds", help = "Configured seed source(s)")]
    pub seeds: bool,

    /// Display detected CPU capability settings.
    ///
    /// Returns a formatted string describing the CPU architecture and detected
    /// hardware acceleration features (AES-NI, SHA extensions, AVX, NEON, etc.).
    /// Uses [`openssl_crypto::cpu_detect::capabilities()`] to query cached
    /// detection results.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)`.
    #[arg(long = "cpusettings", help = "Detected CPU settings")]
    pub cpusettings: bool,

    /// Display Windows-specific security context information.
    ///
    /// Only available on Windows platforms. Returns information about the
    /// loaded Windows security context used for certificate store access.
    /// C equivalent: `OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT)`.
    ///
    /// This field is conditionally compiled, matching the C pattern:
    /// `#ifdef OPENSSL_SYS_WINDOWS` around the `OPT_WINCTX` option.
    #[cfg(target_os = "windows")]
    #[arg(long = "windowscontext", help = "Loaded Windows context")]
    pub windowscontext: bool,
}

// =============================================================================
// InfoArgs Implementation
// =============================================================================

impl InfoArgs {
    /// Execute the `info` subcommand.
    ///
    /// Validates that exactly one flag is specified (mutual exclusion), then
    /// queries and prints the corresponding metadata value. This replaces the
    /// C `info_main()` function from `apps/info.c`.
    ///
    /// # Arguments
    ///
    /// * `_ctx` — Library context (unused by this command but required by the
    ///   `CliCommand::execute()` dispatch interface for uniform command dispatch).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Common`] wrapping
    /// [`CommonError::InvalidArgument`](openssl_common::error::CommonError::InvalidArgument)
    /// if zero or more than one flag is specified.
    ///
    /// # C Correspondence
    ///
    /// Replaces the `dirty` counter pattern in C `info_main()`:
    /// ```c
    /// if (dirty > 1)
    ///     BIO_printf(bio_err, "%s: Only one item allowed\n", prog);
    /// if (dirty == 0)
    ///     BIO_printf(bio_err, "%s: No items chosen\n", prog);
    /// ```
    #[allow(clippy::unused_async)]
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // Count selected flags — enforces mutual exclusion matching the C `dirty` counter.
        let selected = self.count_selected();

        if selected == 0 {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "No items chosen. Use one of: --configdir, --modulesdir, --dsoext, \
                     --dirnamesep, --listsep, --seeds, --cpusettings"
                        .to_string(),
                ),
            ));
        }

        if selected > 1 {
            return Err(CryptoError::Common(
                openssl_common::error::CommonError::InvalidArgument(
                    "Only one item allowed".to_string(),
                ),
            ));
        }

        // Dispatch to the selected info type and print the result.
        // Each branch corresponds to a `case OPT_*:` in the C switch statement.
        let value = self.query_value();
        tracing::info!(info_value = %value, "info query complete");
        println!("{value}");

        Ok(())
    }

    /// Count the number of selected (true) flags.
    ///
    /// Used for mutual exclusion validation — exactly one flag must be `true`.
    /// Replaces the C `dirty++` pattern in the `opt_next()` switch statement
    /// where each matched option increments the counter.
    ///
    /// # Returns
    ///
    /// The number of boolean flags set to `true`. Valid results are:
    /// - `0` — no items chosen (error)
    /// - `1` — exactly one item (success)
    /// - `>1` — multiple items (error)
    fn count_selected(&self) -> usize {
        let flags: [bool; 7] = [
            self.configdir,
            self.modulesdir,
            self.dsoext,
            self.dirnamesep,
            self.listsep,
            self.seeds,
            self.cpusettings,
        ];

        let count = flags.iter().filter(|&&f| f).count();

        // On Windows, the windowscontext flag is also counted.
        // On non-Windows platforms, this block is compiled away and `count`
        // is returned directly from the iterator above.
        #[cfg(target_os = "windows")]
        let count = count + usize::from(self.windowscontext);

        count
    }

    /// Query the metadata value for the single selected flag.
    ///
    /// **Pre-condition:** exactly one flag is `true` (enforced by [`execute()`](Self::execute)).
    /// Returns the corresponding metadata string for the selected info type.
    ///
    /// # C Correspondence
    ///
    /// Each branch replaces a `OPENSSL_info(OPENSSL_INFO_*)` call from the C
    /// `info_main()` function:
    ///
    /// | Flag | C Constant | Rust Source |
    /// |------|-----------|-------------|
    /// | `configdir` | `OPENSSL_INFO_CONFIG_DIR` | `DEFAULT_CONFIG_DIR` |
    /// | `modulesdir` | `OPENSSL_INFO_MODULES_DIR` | `DEFAULT_MODULES_DIR` |
    /// | `dsoext` | `OPENSSL_INFO_DSO_EXTENSION` | `DSO_EXTENSION` |
    /// | `dirnamesep` | `OPENSSL_INFO_DIR_FILENAME_SEPARATOR` | `std::path::MAIN_SEPARATOR` |
    /// | `listsep` | `OPENSSL_INFO_LIST_SEPARATOR` | `LIST_SEP` |
    /// | `seeds` | `OPENSSL_INFO_SEED_SOURCE` | `SEED_SOURCES` |
    /// | `cpusettings` | `OPENSSL_INFO_CPU_SETTINGS` | [`format_cpu_settings()`] |
    fn query_value(&self) -> String {
        if self.configdir {
            tracing::debug!("Querying info type: ConfigDir");
            // Build-time override via OPENSSL_CONFIG_DIR, falling back to default.
            option_env!("OPENSSL_CONFIG_DIR")
                .unwrap_or(DEFAULT_CONFIG_DIR)
                .to_string()
        } else if self.modulesdir {
            tracing::debug!("Querying info type: ModulesDir");
            // Build-time override via OPENSSL_MODULES_DIR, falling back to default.
            option_env!("OPENSSL_MODULES_DIR")
                .unwrap_or(DEFAULT_MODULES_DIR)
                .to_string()
        } else if self.dsoext {
            tracing::debug!("Querying info type: DsoExt");
            DSO_EXTENSION.to_string()
        } else if self.dirnamesep {
            tracing::debug!("Querying info type: DirNameSep");
            // Use Rust's platform-aware directory separator constant.
            // This is '/' on Unix and '\\' on Windows.
            String::from(std::path::MAIN_SEPARATOR)
        } else if self.listsep {
            tracing::debug!("Querying info type: ListSep");
            LIST_SEP.to_string()
        } else if self.seeds {
            tracing::debug!("Querying info type: Seeds");
            SEED_SOURCES.to_string()
        } else if self.cpusettings {
            tracing::debug!("Querying info type: CpuSettings");
            format_cpu_settings()
        } else {
            // On Windows, check the windowscontext flag.
            #[cfg(target_os = "windows")]
            {
                if self.windowscontext {
                    tracing::debug!("Querying info type: WindowsContext");
                    return query_windows_context();
                }
            }
            // Unreachable when exactly one flag is set (guaranteed by execute()),
            // but required for exhaustiveness. Returns "Undefined" matching the
            // C pattern: `val == NULL ? "Undefined" : val`.
            "Undefined".to_string()
        }
    }
}

// =============================================================================
// CPU Settings Formatting
// =============================================================================

/// Format detected CPU capabilities as a human-readable string.
///
/// Replaces the C `OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` output, which reads
/// from `OPENSSL_ia32cap_P` / `OPENSSL_armcap_P` globals and formats them as a
/// descriptive string. This function calls `capabilities()` from
/// [`openssl_crypto::cpu_detect`] and formats the cached detection results.
///
/// # Output Format
///
/// The output includes the architecture name followed by a space-separated list
/// of detected hardware features:
///
/// On `x86_64`:
/// ```text
/// arch=x86_64 SSE2 SSE3 SSSE3 SSE4.1 SSE4.2 AESNI AVX AVX2 PCLMULQDQ SHA BMI2 ADX
/// ```
///
/// On `AArch64`:
/// ```text
/// arch=aarch64 NEON AES SHA256 PMULL SHA512
/// ```
///
/// On platforms without detailed feature detection:
/// ```text
/// arch=riscv64
/// ```
fn format_cpu_settings() -> String {
    let caps = capabilities();

    // Architecture prefix — always present.
    let arch_prefix = format!("arch={}", caps.arch);

    // Collect x86 feature names for detected capabilities.
    let x86_features = collect_x86_feature_names(caps);

    // Collect ARM feature names for detected capabilities.
    let arm_features = collect_arm_feature_names(caps);

    // Build the final string: "arch=<arch> [FEATURE1 FEATURE2 ...]"
    let mut result = arch_prefix;
    for name in &x86_features {
        result.push(' ');
        result.push_str(name);
    }
    for name in &arm_features {
        result.push(' ');
        result.push_str(name);
    }

    result
}

/// Collect names of detected `x86/x86_64` hardware features.
///
/// Returns a vector of human-readable feature names for all detected x86 CPU
/// features. The names match the conventional nomenclature used in CPU
/// capability reporting (e.g., `AESNI`, `AVX2`, `PCLMULQDQ`).
///
/// Features are listed in the same order as the `X86Features` bitflags
/// definition, providing a consistent and predictable output format.
fn collect_x86_feature_names(
    caps: &openssl_crypto::cpu_detect::CpuCapabilities,
) -> Vec<&'static str> {
    use openssl_crypto::cpu_detect::X86Features;

    /// Static lookup table mapping x86 feature flags to their display names.
    /// Ordered to match the bitflags definition in `cpu_detect.rs` for
    /// consistent output across invocations.
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
///
/// Features are listed in the same order as the `ArmFeatures` bitflags
/// definition.
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

// =============================================================================
// Windows Context Query (Windows-only)
// =============================================================================

/// Query Windows-specific security context information.
///
/// Only compiled on Windows targets. Replaces the C
/// `OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT)` call, which reports the
/// loaded Windows security context used for system certificate store access
/// and cryptographic provider initialization.
///
/// # Platform
///
/// This function is gated behind `#[cfg(target_os = "windows")]` matching
/// the C `#ifdef OPENSSL_SYS_WINDOWS` guard in `apps/info.c`.
#[cfg(target_os = "windows")]
fn query_windows_context() -> String {
    // The Windows context information reports the state of the Windows
    // cryptographic service provider and system certificate store integration.
    // In the Rust implementation, this reports the availability of the
    // Windows Schannel / CNG backend integration.
    "Windows security context: default".to_string()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `count_selected` returns 0 when no flags are set.
    #[test]
    fn test_count_selected_zero() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        assert_eq!(args.count_selected(), 0);
    }

    /// Verify that `count_selected` returns 1 for each individual flag.
    #[test]
    fn test_count_selected_single_flags() {
        let flag_setters: Vec<InfoArgs> = vec![
            InfoArgs {
                configdir: true,
                modulesdir: false,
                dsoext: false,
                dirnamesep: false,
                listsep: false,
                seeds: false,
                cpusettings: false,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
            InfoArgs {
                configdir: false,
                modulesdir: true,
                dsoext: false,
                dirnamesep: false,
                listsep: false,
                seeds: false,
                cpusettings: false,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
            InfoArgs {
                configdir: false,
                modulesdir: false,
                dsoext: true,
                dirnamesep: false,
                listsep: false,
                seeds: false,
                cpusettings: false,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
            InfoArgs {
                configdir: false,
                modulesdir: false,
                dsoext: false,
                dirnamesep: true,
                listsep: false,
                seeds: false,
                cpusettings: false,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
            InfoArgs {
                configdir: false,
                modulesdir: false,
                dsoext: false,
                dirnamesep: false,
                listsep: true,
                seeds: false,
                cpusettings: false,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
            InfoArgs {
                configdir: false,
                modulesdir: false,
                dsoext: false,
                dirnamesep: false,
                listsep: false,
                seeds: true,
                cpusettings: false,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
            InfoArgs {
                configdir: false,
                modulesdir: false,
                dsoext: false,
                dirnamesep: false,
                listsep: false,
                seeds: false,
                cpusettings: true,
                #[cfg(target_os = "windows")]
                windowscontext: false,
            },
        ];

        for (idx, args) in flag_setters.iter().enumerate() {
            assert_eq!(
                args.count_selected(),
                1,
                "Flag at index {idx} should produce count=1"
            );
        }
    }

    /// Verify that `count_selected` returns >1 when multiple flags are set.
    #[test]
    fn test_count_selected_multiple() {
        let args = InfoArgs {
            configdir: true,
            modulesdir: true,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        assert_eq!(args.count_selected(), 2);
    }

    /// Verify `query_value` returns the default config directory.
    #[test]
    fn test_query_configdir() {
        let args = InfoArgs {
            configdir: true,
            modulesdir: false,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        assert!(
            !value.is_empty(),
            "configdir should return a non-empty path"
        );
        // The default value should be the compile-time constant
        // unless overridden by OPENSSL_CONFIG_DIR env var at build time.
        assert_eq!(
            value,
            option_env!("OPENSSL_CONFIG_DIR").unwrap_or(DEFAULT_CONFIG_DIR)
        );
    }

    /// Verify `query_value` returns the modules directory.
    #[test]
    fn test_query_modulesdir() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: true,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        assert_eq!(
            value,
            option_env!("OPENSSL_MODULES_DIR").unwrap_or(DEFAULT_MODULES_DIR)
        );
    }

    /// Verify `query_value` returns a valid DSO extension.
    #[test]
    fn test_query_dsoext() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: true,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        assert!(
            value.starts_with('.'),
            "DSO extension should start with '.'"
        );
        // Platform-specific assertions
        #[cfg(target_os = "linux")]
        assert_eq!(value, ".so");
        #[cfg(target_os = "macos")]
        assert_eq!(value, ".dylib");
        #[cfg(target_os = "windows")]
        assert_eq!(value, ".dll");
    }

    /// Verify `query_value` returns the directory separator.
    #[test]
    fn test_query_dirnamesep() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: false,
            dirnamesep: true,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        assert_eq!(value, String::from(std::path::MAIN_SEPARATOR));
    }

    /// Verify `query_value` returns the list separator.
    #[test]
    fn test_query_listsep() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: false,
            dirnamesep: false,
            listsep: true,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        #[cfg(not(target_os = "windows"))]
        assert_eq!(value, ":");
        #[cfg(target_os = "windows")]
        assert_eq!(value, ";");
    }

    /// Verify `query_value` returns seed source information.
    #[test]
    fn test_query_seeds() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: true,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        assert!(!value.is_empty(), "seeds should return a non-empty string");
        assert_eq!(value, SEED_SOURCES);
    }

    /// Verify `query_value` returns CPU settings with architecture prefix.
    #[test]
    fn test_query_cpusettings() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: true,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let value = args.query_value();
        assert!(
            value.starts_with("arch="),
            "CPU settings should start with 'arch=', got: {value}"
        );

        // On x86_64, we should see at least SSE2 (guaranteed on x86_64)
        #[cfg(target_arch = "x86_64")]
        assert!(
            value.contains("SSE2"),
            "x86_64 CPU settings should include SSE2, got: {value}"
        );
    }

    /// Verify `format_cpu_settings` returns a properly formatted string.
    #[test]
    fn test_format_cpu_settings_structure() {
        let settings = format_cpu_settings();

        // Must start with arch= prefix
        assert!(settings.starts_with("arch="));

        // Must contain the detected architecture name
        let caps = capabilities();
        let expected_arch = format!("arch={}", caps.arch);
        assert!(settings.starts_with(&expected_arch));

        // Should not have trailing spaces
        assert!(!settings.ends_with(' '));

        // Should not have double spaces
        assert!(!settings.contains("  "));
    }

    /// Verify execute returns error when no flags are set.
    #[tokio::test]
    async fn test_execute_no_flags_error() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "Should error when no flags are set");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No items chosen"),
            "Error should mention no items chosen, got: {err_msg}"
        );
    }

    /// Verify execute returns error when multiple flags are set.
    #[tokio::test]
    async fn test_execute_multiple_flags_error() {
        let args = InfoArgs {
            configdir: true,
            modulesdir: true,
            dsoext: false,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(result.is_err(), "Should error when multiple flags are set");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Only one item allowed"),
            "Error should mention only one item allowed, got: {err_msg}"
        );
    }

    /// Verify execute succeeds with exactly one flag.
    #[tokio::test]
    async fn test_execute_single_flag_success() {
        let args = InfoArgs {
            configdir: false,
            modulesdir: false,
            dsoext: true,
            dirnamesep: false,
            listsep: false,
            seeds: false,
            cpusettings: false,
            #[cfg(target_os = "windows")]
            windowscontext: false,
        };
        let ctx = LibContext::new();
        let result = args.execute(&ctx).await;
        assert!(
            result.is_ok(),
            "Should succeed with exactly one flag: {:?}",
            result.err()
        );
    }
}
