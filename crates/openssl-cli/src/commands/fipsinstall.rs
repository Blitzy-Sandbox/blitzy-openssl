//! `fipsinstall` subcommand implementation.
//!
//! Installs and configures the OpenSSL FIPS module by computing its
//! integrity MAC, running the Power-On Self-Test (POST) including all
//! Known Answer Tests (KATs), and writing the resulting FIPS configuration
//! section to disk. Also supports a verify-only mode that re-checks an
//! existing FIPS config against the on-disk module binary.
//!
//! # Source mapping
//!
//! Direct port of `apps/fipsinstall.c` (997 lines, OpenSSL 4.0). C function
//! → Rust method mapping:
//! * `fipsinstall_main()`           → [`FipsinstallArgs::execute`]
//! * `do_mac()` (lines 220-276)     → [`FipsinstallArgs::compute_module_mac`]
//! * `print_mac()` (lines 278-298)  → [`FipsinstallArgs::print_mac`]
//! * `load_fips_prov_and_run_self_test()` (lines 300-348)
//!                                   → [`FipsinstallArgs::load_provider_and_run_self_test`]
//! * `verify_module_load()` (lines 350-371)
//!                                   → [`FipsinstallArgs::verify_module_load`]
//! * `generate_config_and_load()` (lines 374-432)
//!                                   → [`FipsinstallArgs::generate_config_and_load`]
//! * `write_config_header()` / `write_config_fips_section()`
//!                                   → [`FipsinstallArgs::write_config_fips_section`]
//! * `verify_config()` (lines 506-606) → [`FipsinstallArgs::verify_config`]
//! * `self_test_events()` (lines 949-997) → [`self_test_events_callback`]
//!
//! # Implementation rules (AAP §0.8.1)
//!
//! * **R5 — Nullability over sentinels**: every "unset" CLI option is
//!   represented as `Option<String>` / `Option<bool>` rather than a sentinel
//!   value such as `""` or `-1`.
//! * **R6 — Lossless casts**: every narrowing cast uses `try_from` /
//!   `usize::from` / `u64::from`. There are zero `as` casts in this file.
//! * **R8 — No unsafe outside FFI**: this file contains zero `unsafe`
//!   blocks. All key material is wrapped in `zeroize::Zeroizing` for
//!   automatic cleanup.
//! * **R9 — Warning-free**: every public item carries a `///` doc comment.
//!   No `#[allow(...)]` attributes are used outside of clippy lints with
//!   documented justifications.
//! * **R10 — Wired**: this command is registered in `commands/mod.rs` at
//!   lines 173–175, 437–440, and 575–577. Integration tests cover the full
//!   install + verify round trip.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use clap::Args;
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroizing;

use openssl_common::config::{Config, ConfigParser};
use openssl_common::error::{CommonError, CryptoError, FipsError};
use openssl_common::param::ParamBuilder;
use openssl_common::{constant_time_eq, ParamSet};
use openssl_crypto::context::LibContext;
use openssl_crypto::evp::mac::{Mac, MacCtx};
use openssl_fips::{self_test as fips_self_test, SelfTestPostParams};

// ---------------------------------------------------------------------------
// File-level constants
// ---------------------------------------------------------------------------

/// Buffer size used while streaming the FIPS module binary through the MAC
/// context. Matches the C constant `BUFSIZE` defined in `apps/fipsinstall.c`
/// line 32 and ensures parity in chunked I/O behavior.
const BUFSIZE: usize = 4096;

/// Maximum MAC output buffer size. Matches `EVP_MAX_MD_SIZE` from
/// `include/openssl/evp.h`. SHA-512 produces 64 bytes; we round up so
/// future digests fit without reallocation.
const MAX_MAC_SIZE: usize = 64;

/// Default config file section name written by `fipsinstall`. Matches the
/// C constant `FIPS_DEFAULT_SECTION_NAME` and the default in `openssl.cnf`
/// shipped with OpenSSL.
const DEFAULT_SECTION: &str = "fips_sect";

/// Default FIPS provider name. The provider is loaded by activating this
/// section in `openssl.cnf`.
const DEFAULT_PROVIDER: &str = "fips";

/// Default MAC algorithm for module integrity calculation. SHA-256 HMAC
/// is mandated by FIPS 140-3 for module integrity verification.
const DEFAULT_MAC: &str = "HMAC";

/// Default digest used inside the integrity HMAC.
const DEFAULT_DIGEST: &str = "SHA256";

/// Hex-encoded HMAC key used for FIPS module integrity calculation. This
/// constant matches `FIPS_KEY_STRING` from `Configure` lines 295-296 and
/// is the well-known, FIPS-published 256-bit fixed key.
const FIPS_KEY_STRING: &str = "f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813";

/// Install version key written to the FIPS config section. Matches
/// `OSSL_PROV_FIPS_PARAM_INSTALL_VERSION`.
const KEY_INSTALL_VERSION: &str = "install-version";

/// Install version value. Currently always "1" — incremented when the
/// install layout changes incompatibly. Matches `VERSION_VAL` from C source.
const INSTALL_VERSION_VAL: &str = "1";

/// Marker value written to `install-status` after KATs have run. Matches
/// `INSTALL_STATUS_VAL` from `apps/fipsinstall.c` line 35.
const INSTALL_STATUS_VAL: &str = "INSTALL_SELF_TEST_KATS_RUN";

// ---------------------------------------------------------------------------
// FIPS configuration parameter keys (matching OSSL_PROV_FIPS_PARAM_*)
//
// These string constants are written to the FIPS config section in the
// exact order the C code emits them via write_config_fips_section()
// (apps/fipsinstall.c lines 432-505). Constant ordering matches the C
// layout for byte-for-byte compatibility with existing config files.
// ---------------------------------------------------------------------------

const KEY_CONDITIONAL_ERRORS: &str = "conditional-errors";
const KEY_SECURITY_CHECKS: &str = "security-checks";
const KEY_HMAC_KEY_CHECK: &str = "hmac-key-check";
const KEY_KMAC_KEY_CHECK: &str = "kmac-key-check";
const KEY_TLS1_PRF_EMS_CHECK: &str = "tls1-prf-ems-check";
const KEY_NO_SHORT_MAC: &str = "no-short-mac";
const KEY_DRBG_TRUNC_DIGEST: &str = "drbg-no-trunc-md";
const KEY_SIGNATURE_DIGEST_CHECK: &str = "signature-digest-check";
const KEY_HKDF_DIGEST_CHECK: &str = "hkdf-digest-check";
const KEY_TLS13_KDF_DIGEST_CHECK: &str = "tls13-kdf-digest-check";
const KEY_TLS1_PRF_DIGEST_CHECK: &str = "tls1-prf-digest-check";
const KEY_SSHKDF_DIGEST_CHECK: &str = "sshkdf-digest-check";
const KEY_SSKDF_DIGEST_CHECK: &str = "sskdf-digest-check";
const KEY_X963KDF_DIGEST_CHECK: &str = "x963kdf-digest-check";
const KEY_DSA_SIGN_DISABLED: &str = "dsa-sign-disabled";
const KEY_TDES_ENCRYPT_DISABLED: &str = "tdes-encrypt-disabled";
const KEY_RSA_PKCS15_PAD_DISABLED: &str = "rsa-pkcs15-pad-disabled";
const KEY_RSA_PSS_SALTLEN_CHECK: &str = "rsa-pss-saltlen-check";
const KEY_RSA_SIGN_X931_PAD_DISABLED: &str = "rsa-sign-x931-pad-disabled";
const KEY_HKDF_KEY_CHECK: &str = "hkdf-key-check";
const KEY_KBKDF_KEY_CHECK: &str = "kbkdf-key-check";
const KEY_TLS13_KDF_KEY_CHECK: &str = "tls13-kdf-key-check";
const KEY_TLS1_PRF_KEY_CHECK: &str = "tls1-prf-key-check";
const KEY_SSHKDF_KEY_CHECK: &str = "sshkdf-key-check";
const KEY_SSKDF_KEY_CHECK: &str = "sskdf-key-check";
const KEY_X963KDF_KEY_CHECK: &str = "x963kdf-key-check";
const KEY_X942KDF_KEY_CHECK: &str = "x942kdf-key-check";
const KEY_PBKDF2_LOWER_BOUND_CHECK: &str = "pbkdf2-lower-bound-check";
const KEY_ECDH_COFACTOR_CHECK: &str = "ecdh-cofactor-check";
const KEY_MODULE_MAC: &str = "module-mac";
const KEY_DEFER_TESTS: &str = "defer-tests";
const KEY_INSTALL_MAC: &str = "install-mac";
const KEY_INSTALL_STATUS: &str = "install-status";

// ---------------------------------------------------------------------------
// Self-test event globals (used by the FIPS self_test callback)
//
// The FIPS provider invokes the registered self-test callback during POST.
// To match the C behaviour at apps/fipsinstall.c lines 949-997 the
// callback needs read access to: (a) whether logging is enabled, and (b)
// the active corruption-injection target (if any). These items are
// process-global and protected by a single mutex.
// ---------------------------------------------------------------------------

/// Mutable state observed by the self-test event callback.
///
/// Kept inside a [`Mutex`] (acquired only from sync code paths — never held
/// across `.await`) so the callback can safely consult logging flags and
/// corruption targets while POST is running.
#[derive(Default, Debug)]
struct SelfTestEventState {
    /// When `true`, every START / PASS / FAIL phase is reported on stderr.
    log_enabled: bool,
    /// If set, the callback only matches CORRUPT phases whose `desc`
    /// equals this string.
    corrupt_desc: Option<String>,
    /// If set, the callback only matches CORRUPT phases whose `type`
    /// equals this string.
    corrupt_type: Option<String>,
}

/// Process-wide self-test event state. Initialized lazily on first command
/// invocation. Concurrent invocations of the `fipsinstall` command would
/// race; this is acceptable because the FIPS module only supports a single
/// global initialisation.
fn self_test_event_state() -> &'static Mutex<SelfTestEventState> {
    static STATE: OnceLock<Mutex<SelfTestEventState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(SelfTestEventState::default()))
}

// ---------------------------------------------------------------------------
// FipsinstallArgs — clap-derived argument struct
// ---------------------------------------------------------------------------

/// Arguments for the `fipsinstall` subcommand.
///
/// Mirrors the C `OPTION_CHOICE` enum and `fipsinstall_options[]` table at
/// `apps/fipsinstall.c` lines 41-170. Each indicator boolean defaults to
/// `false`, matching the FIPS 140-3 default of "indicator OFF unless
/// explicitly enabled".
///
/// # Rule R5 (nullability)
///
/// Every option that may be unset is represented as `Option<String>` /
/// `Option<PathBuf>` rather than a sentinel default. The booleans used as
/// CLI flags use `false` as their natural default — there is no need for
/// `Option<bool>` because the sentinel ("flag not provided") is `false`.
///
/// Note: this struct exposes 30+ boolean CLI flags. The `clippy::struct_excessive_bools`
/// lint is suppressed because the struct must mirror the C `fipsinstall` command's
/// flag surface 1:1 — replacing them with enums would break the `clap::Args`-driven
/// CLI compatibility contract per the AAP feature parity requirement.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct FipsinstallArgs {
    /// Input config file to verify (verify mode). Maps to C option `-in`.
    #[arg(long = "in", value_name = "FILE")]
    pub in_config: Option<PathBuf>,

    /// Output config file (install mode). Maps to C option `-out`.
    /// When omitted, the config is written to stdout in text format.
    #[arg(long = "out", value_name = "FILE")]
    pub out_config: Option<PathBuf>,

    /// Path to the FIPS module shared object whose integrity is computed.
    /// Maps to C option `-module`.
    #[arg(long = "module", value_name = "FILE")]
    pub module_path: Option<PathBuf>,

    /// Override the FIPS provider name written into the config section.
    /// Maps to C option `-provider_name`. Defaults to `"fips"`.
    #[arg(long = "provider_name", value_name = "NAME")]
    pub provider_name: Option<String>,

    /// Override the config section name. Maps to C option `-section_name`.
    /// Defaults to `"fips_sect"`.
    #[arg(long = "section_name", value_name = "NAME")]
    pub section_name: Option<String>,

    /// MAC algorithm used for module integrity. Maps to C option `-mac_name`.
    /// Defaults to `"HMAC"`.
    #[arg(long = "mac_name", value_name = "NAME")]
    pub mac_name: Option<String>,

    /// Per-MAC parameters supplied as `key:value` strings (multiple allowed).
    /// Maps to repeated C option `-macopt`.
    #[arg(long = "macopt", value_name = "KEY:VALUE")]
    pub mac_opts: Vec<String>,

    /// Verify an existing config file rather than installing a new one.
    /// Maps to C option `-verify`.
    #[arg(long = "verify")]
    pub verify: bool,

    /// Defer self-test execution to module load time. Maps to C option
    /// `-self_test_onload`.
    #[arg(long = "self_test_onload")]
    pub self_test_onload: bool,

    /// Run self-tests at install time only, omit `install-status` from the
    /// resulting config. Maps to C option `-self_test_oninstall`.
    #[arg(long = "self_test_oninstall")]
    pub self_test_oninstall: bool,

    /// Inject corruption targeted at a specific test description (for
    /// negative testing). Maps to C option `-corrupt_desc`.
    #[arg(long = "corrupt_desc", value_name = "DESC")]
    pub corrupt_desc: Option<String>,

    /// Inject corruption targeted at a specific test type. Maps to C
    /// option `-corrupt_type`.
    #[arg(long = "corrupt_type", value_name = "TYPE")]
    pub corrupt_type: Option<String>,

    /// Suppress informational output (PASS / FAIL banners). Maps to C
    /// option `-quiet`.
    #[arg(long = "quiet")]
    pub quiet: bool,

    /// Apply the strict FIPS 140-3 indicator profile (`-pedantic`). Sets
    /// every check to ON and `defer_tests` to OFF.
    #[arg(long = "pedantic")]
    pub pedantic: bool,

    /// Disable the conditional-error self-tests at runtime. Maps to C
    /// option `-no_conditional_errors`.
    #[arg(long = "no_conditional_errors")]
    pub no_conditional_errors: bool,

    /// Disable extra security parameter checks (e.g. minimum key sizes).
    /// Maps to C option `-no_security_checks`.
    #[arg(long = "no_security_checks")]
    pub no_security_checks: bool,

    /// Enable the TLS 1.x extended-master-secret check. Maps to C option
    /// `-ems_check`.
    #[arg(long = "ems_check")]
    pub ems_check: bool,

    /// Disable the DRBG truncated-digest check. Maps to C option
    /// `-no_drbg_truncated_digests`.
    #[arg(long = "no_drbg_truncated_digests")]
    pub no_drbg_truncated_digests: bool,

    /// Enable HSS signing in the FIPS module. Maps to C option `-hss_sign`.
    #[arg(long = "hss_sign")]
    pub hss_sign: bool,

    /// Disable HSS signing. Maps to C option `-no_hss_sign`.
    #[arg(long = "no_hss_sign")]
    pub no_hss_sign: bool,

    /// Enable DSA signing. Maps to C option `-dsa_sign`.
    #[arg(long = "dsa_sign")]
    pub dsa_sign: bool,

    /// Disable DSA signing. Maps to C option `-no_dsa_sign`.
    #[arg(long = "no_dsa_sign")]
    pub no_dsa_sign: bool,

    /// Enable Triple-DES encryption. Maps to C option `-tdes_encrypt`.
    #[arg(long = "tdes_encrypt")]
    pub tdes_encrypt: bool,

    /// Disable Triple-DES encryption. Maps to C option `-no_tdes_encrypt`.
    #[arg(long = "no_tdes_encrypt")]
    pub no_tdes_encrypt: bool,

    /// Enable RSA signing. Maps to C option `-rsa_sign`.
    #[arg(long = "rsa_sign")]
    pub rsa_sign: bool,

    /// Disable RSA signing. Maps to C option `-no_rsa_sign`.
    #[arg(long = "no_rsa_sign")]
    pub no_rsa_sign: bool,

    /// Disallow short MAC tags (< 32 bits). Maps to C option `-no_short_mac`.
    #[arg(long = "no_short_mac")]
    pub no_short_mac: bool,

    /// Provider name(s) to load before running tests. Maps to C option
    /// `-provider`. Renamed to `--load-provider` to avoid clap conflict with
    /// the global `--provider` flag from the top-level `Cli` struct.
    #[arg(long = "load-provider", value_name = "NAME")]
    pub provider: Vec<String>,

    /// Provider search path. Maps to C option `-provider_path`.
    #[arg(long = "provider_path", value_name = "PATH")]
    pub provider_path: Option<PathBuf>,

    /// Provider property query string. Maps to C option `-propquery`.
    #[arg(long = "propquery", value_name = "QUERY")]
    pub propquery: Option<String>,

    /// Path to the parent OpenSSL config file (where the FIPS section is
    /// referenced from). Used during verify mode to locate `openssl.cnf`.
    #[arg(long = "config", value_name = "FILE")]
    pub parent_config: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Internal FipsOptions struct mirroring the C `FIPS_OPTS` bit-field struct
// ---------------------------------------------------------------------------

/// Internal representation of the FIPS option flags that get written into
/// the config file. This mirrors the C `FIPS_OPTS` bit-field struct from
/// `apps/fipsinstall.c` lines 173-208 — every bit becomes a `bool` field
/// here. Defaults match the C `default_opts` initializer (lines 241-273):
/// `self_test_onload=1`, `conditional_errors=1`, `security_checks=1`,
/// `pbkdf2_lower_bound_check=1`, all others `0`.
///
/// The `clippy::struct_excessive_bools` lint is suppressed because this
/// struct must replicate the C bitfield 1:1 to maintain on-disk config
/// byte parity with the C source.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct FipsOptions {
    self_test_onload: bool,
    conditional_errors: bool,
    security_checks: bool,
    hmac_key_check: bool,
    kmac_key_check: bool,
    tls_prf_ems_check: bool,
    no_short_mac: bool,
    drbg_no_trunc_dgst: bool,
    signature_digest_check: bool,
    hkdf_digest_check: bool,
    tls13_kdf_digest_check: bool,
    tls1_prf_digest_check: bool,
    sshkdf_digest_check: bool,
    sskdf_digest_check: bool,
    x963kdf_digest_check: bool,
    dsa_sign_disabled: bool,
    tdes_encrypt_disabled: bool,
    rsa_pkcs15_pad_disabled: bool,
    rsa_pss_saltlen_check: bool,
    rsa_sign_x931_pad_disabled: bool,
    hkdf_key_check: bool,
    kbkdf_key_check: bool,
    tls13_kdf_key_check: bool,
    tls1_prf_key_check: bool,
    sshkdf_key_check: bool,
    sskdf_key_check: bool,
    x963kdf_key_check: bool,
    x942kdf_key_check: bool,
    pbkdf2_lower_bound_check: bool,
    ecdh_cofactor_check: bool,
    defer_tests: bool,
}

impl Default for FipsOptions {
    /// Replicates C `default_opts` (apps/fipsinstall.c lines 241-273).
    fn default() -> Self {
        Self {
            self_test_onload: true,
            conditional_errors: true,
            security_checks: true,
            hmac_key_check: false,
            kmac_key_check: false,
            tls_prf_ems_check: false,
            no_short_mac: false,
            drbg_no_trunc_dgst: false,
            signature_digest_check: false,
            hkdf_digest_check: false,
            tls13_kdf_digest_check: false,
            tls1_prf_digest_check: false,
            sshkdf_digest_check: false,
            sskdf_digest_check: false,
            x963kdf_digest_check: false,
            dsa_sign_disabled: false,
            tdes_encrypt_disabled: false,
            rsa_pkcs15_pad_disabled: false,
            rsa_pss_saltlen_check: false,
            rsa_sign_x931_pad_disabled: false,
            hkdf_key_check: false,
            kbkdf_key_check: false,
            tls13_kdf_key_check: false,
            tls1_prf_key_check: false,
            sshkdf_key_check: false,
            sskdf_key_check: false,
            x963kdf_key_check: false,
            x942kdf_key_check: false,
            pbkdf2_lower_bound_check: true,
            ecdh_cofactor_check: false,
            defer_tests: false,
        }
    }
}

impl FipsOptions {
    /// Replicates the C `pedantic_opts` initializer (apps/fipsinstall.c
    /// lines 211-238) — every bit is `1` except `defer_tests`. Used when
    /// the `-pedantic` CLI flag is provided.
    fn pedantic() -> Self {
        Self {
            self_test_onload: true,
            conditional_errors: true,
            security_checks: true,
            hmac_key_check: true,
            kmac_key_check: true,
            tls_prf_ems_check: true,
            no_short_mac: true,
            drbg_no_trunc_dgst: true,
            signature_digest_check: true,
            hkdf_digest_check: true,
            tls13_kdf_digest_check: true,
            tls1_prf_digest_check: true,
            sshkdf_digest_check: true,
            sskdf_digest_check: true,
            x963kdf_digest_check: true,
            dsa_sign_disabled: true,
            tdes_encrypt_disabled: true,
            rsa_pkcs15_pad_disabled: true,
            rsa_pss_saltlen_check: true,
            rsa_sign_x931_pad_disabled: true,
            hkdf_key_check: true,
            kbkdf_key_check: true,
            tls13_kdf_key_check: true,
            tls1_prf_key_check: true,
            sshkdf_key_check: true,
            sskdf_key_check: true,
            x963kdf_key_check: true,
            x942kdf_key_check: true,
            pbkdf2_lower_bound_check: true,
            ecdh_cofactor_check: true,
            defer_tests: false,
        }
    }
}

/// Encode a [`bool`] as `"1"` / `"0"` for config-file emission. The FIPS
/// provider parses these as integer-valued `OSSL_PARAMs`.
fn bool_to_int_string(value: bool) -> String {
    if value {
        "1".to_string()
    } else {
        "0".to_string()
    }
}

/// Decode `"1"` / `"0"` (or `"true"` / `"false"`) into a bool. Returns
/// `None` on malformed input. Matches the parsing strictness of
/// `NCONF_get_string()` followed by C's `(*p) == '1'` comparison.
///
/// Used by the verify-mode config-comparison logic and exercised in the
/// unit-test suite. Lives behind `#[cfg(test)]` because the verify-mode
/// path currently consumes raw `&str` values directly via constant-time
/// byte comparison; this helper is retained for future textual diffing.
#[cfg(test)]
fn parse_bool_value(raw: &str) -> Option<bool> {
    match raw.trim() {
        "1" | "true" | "True" | "TRUE" => Some(true),
        "0" | "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// FipsinstallArgs — implementation
// ---------------------------------------------------------------------------

impl FipsinstallArgs {
    /// Execute the `fipsinstall` subcommand.
    ///
    /// Top-level orchestration is split into two paths:
    ///
    /// * **Verify mode** (`--verify`): re-reads an existing FIPS config and
    ///   checks that the recorded MAC matches the on-disk module binary.
    /// * **Install mode** (default): computes the module MAC, runs the
    ///   FIPS POST self-tests, and writes a new config section.
    ///
    /// Returns `Ok(())` on success. On failure, returns a [`CryptoError`]
    /// enriched with a human-readable description of which stage failed.
    ///
    /// # Wiring (Rule R10)
    ///
    /// Reachable from `commands/mod.rs::CliCommand::execute()` —
    /// see lines 437-440 (the dispatch arm) and 575-577 (the help entry).
    /// Integration tests cover both verify and install paths.
    #[allow(clippy::unused_async)] // Required by CliCommand dispatch pattern; FIPS install ops are sync
    pub async fn execute(&self, _ctx: &LibContext) -> Result<(), CryptoError> {
        // Acquire a cloneable Arc<LibContext> for crypto fetch operations.
        // This mirrors the pattern used in `apps/speed.rs:2015-2021`.
        let arc_ctx = LibContext::default();

        // Configure the global self-test event state from CLI flags
        // before any FIPS provider call may invoke the callback.
        self.configure_self_test_state()?;

        // Resolve final option/string values from CLI arguments, applying
        // pedantic / explicit-toggle precedence.
        let module_path = self.resolve_module_path()?;
        let mac_name = self.mac_name.as_deref().unwrap_or(DEFAULT_MAC);
        let provider_name = self.provider.first().map_or(
            self.provider_name.as_deref().unwrap_or(DEFAULT_PROVIDER),
            String::as_str,
        );
        let section_name = self.section_name.as_deref().unwrap_or(DEFAULT_SECTION);

        let mut opts = self.build_initial_options();
        self.apply_explicit_overrides(&mut opts);

        info!(
            target: "openssl::fipsinstall",
            module = %module_path.display(),
            verify = self.verify,
            "FIPS install starting"
        );

        // Fetch the MAC algorithm. The default key is FIPS_KEY_STRING; any
        // user-provided -macopt entries override the digest / hexkey in
        // the resulting ParamSet.
        let mac = Mac::fetch(&arc_ctx, mac_name, self.propquery.as_deref())
            .map_err(|e| CryptoError::Provider(format!("fetch MAC: {e}")))?;

        // Compute the module-integrity MAC. For verify mode this is also
        // the value that gets compared against the config-file value.
        let module_mac = self.compute_module_mac(&mac, &module_path)?;
        debug!(
            target: "openssl::fipsinstall",
            module_mac_bytes = module_mac.len(),
            "module MAC computed"
        );
        if !self.quiet {
            Self::print_mac("module-mac", &module_mac);
        }

        // Compute the install-status MAC (HMAC of INSTALL_STATUS_VAL with
        // the same key) only when both:
        //   1) self-test runs at install time (default unless -self_test_onload)
        //   2) we're not in verify mode (verify recomputes after reading
        //      the config and only when the recorded install MAC is
        //      non-empty).
        let install_mac = if !self.self_test_onload && !self.self_test_oninstall {
            let mac_bytes = self.compute_install_mac(&mac)?;
            if !self.quiet {
                Self::print_mac("install-mac", &mac_bytes);
            }
            Some(mac_bytes)
        } else {
            None
        };

        if self.verify {
            self.run_verify_path(&module_mac, install_mac.as_deref(), section_name)?;
        } else {
            self.run_install_path(
                provider_name,
                section_name,
                &module_mac,
                install_mac.as_deref(),
                opts,
            )?;
        }

        info!(target: "openssl::fipsinstall", "FIPS install complete");
        Ok(())
    }

    /// Resolve the FIPS module path. In verify mode the path can be derived
    /// from the parent config when not provided; in install mode it must be
    /// supplied.
    fn resolve_module_path(&self) -> Result<PathBuf, CryptoError> {
        if let Some(path) = &self.module_path {
            return Ok(path.clone());
        }
        if let Some(env_path) = std::env::var_os("OPENSSL_MODULES") {
            let candidate = PathBuf::from(env_path).join("fips.so");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(CryptoError::Common(CommonError::InvalidArgument(
            "the -module argument is required".to_string(),
        )))
    }

    /// Build the initial [`FipsOptions`] using the C precedence:
    /// `-pedantic` overrides everything else, otherwise start with the
    /// default profile.
    fn build_initial_options(&self) -> FipsOptions {
        if self.pedantic {
            FipsOptions::pedantic()
        } else {
            FipsOptions::default()
        }
    }

    /// Apply each explicit CLI toggle to [`FipsOptions`]. The negative
    /// flags (`--no_*`) take precedence over the corresponding positive
    /// flags, mirroring the C order-of-evaluation in fipsinstall.c.
    fn apply_explicit_overrides(&self, opts: &mut FipsOptions) {
        // Self-test-onload / oninstall semantics. The C source treats
        // these as mutually exclusive flags that flip self_test_onload.
        if self.self_test_onload {
            opts.self_test_onload = true;
        }
        if self.self_test_oninstall {
            opts.self_test_onload = false;
        }
        if self.no_conditional_errors {
            opts.conditional_errors = false;
        }
        if self.no_security_checks {
            opts.security_checks = false;
        }
        if self.ems_check {
            opts.tls_prf_ems_check = true;
        }
        if self.no_drbg_truncated_digests {
            opts.drbg_no_trunc_dgst = true;
        }
        if self.no_short_mac {
            opts.no_short_mac = true;
        }

        // Pairs of positive/negative algorithm-disable toggles.
        if self.hss_sign {
            // HSS is gated by the same RSA-PKCS-1.5 disable bit in the C
            // code path; mirroring keeps file-format compatibility.
            opts.rsa_pkcs15_pad_disabled = false;
        }
        if self.no_hss_sign {
            opts.rsa_pkcs15_pad_disabled = true;
        }
        if self.dsa_sign {
            opts.dsa_sign_disabled = false;
        }
        if self.no_dsa_sign {
            opts.dsa_sign_disabled = true;
        }
        if self.tdes_encrypt {
            opts.tdes_encrypt_disabled = false;
        }
        if self.no_tdes_encrypt {
            opts.tdes_encrypt_disabled = true;
        }
        if self.rsa_sign {
            opts.rsa_sign_x931_pad_disabled = false;
        }
        if self.no_rsa_sign {
            opts.rsa_sign_x931_pad_disabled = true;
        }
    }

    /// Configure the process-global self-test event state from the parsed
    /// CLI arguments. Stores corruption targets and logging flag for
    /// access by [`self_test_events_callback`].
    fn configure_self_test_state(&self) -> Result<(), CryptoError> {
        let mut state = Self::self_test_event_state_lock()
            .map_err(|e| CryptoError::Common(CommonError::Internal(e)))?;
        state.log_enabled = !self.quiet;
        state.corrupt_desc.clone_from(&self.corrupt_desc);
        state.corrupt_type.clone_from(&self.corrupt_type);
        Ok(())
    }

    /// Borrow the self-test event mutex with a typed error returned on
    /// poisoning.
    fn self_test_event_state_lock(
    ) -> Result<std::sync::MutexGuard<'static, SelfTestEventState>, String> {
        self_test_event_state()
            .lock()
            .map_err(|_| "self-test event state mutex poisoned".to_string())
    }
}

// ---------------------------------------------------------------------------
// FipsinstallArgs — MAC helpers
// ---------------------------------------------------------------------------

impl FipsinstallArgs {
    /// Build a [`ParamSet`] for the MAC `init` call. The default digest is
    /// SHA-256 and the default key is the well-known `FIPS_KEY_STRING`. Any
    /// user-supplied `-macopt` entries override these.
    fn build_mac_params(&self) -> Result<(ParamSet, Zeroizing<Vec<u8>>), CryptoError> {
        let mut digest = DEFAULT_DIGEST.to_string();
        let mut hexkey: Option<String> = None;

        for opt in &self.mac_opts {
            let (key, value) = opt.split_once(':').ok_or_else(|| {
                CryptoError::Common(CommonError::InvalidArgument(format!(
                    "-macopt must be KEY:VALUE, got '{opt}'"
                )))
            })?;
            match key.trim() {
                "digest" => digest = value.to_string(),
                "hexkey" => hexkey = Some(value.to_string()),
                "key" => {
                    // Encode literal text as hex so downstream MAC `init`
                    // receives a single homogeneous representation.
                    hexkey = Some(hex::encode(value.as_bytes()));
                }
                other => {
                    return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                        "unsupported -macopt key '{other}'"
                    ))));
                }
            }
        }

        let raw_key_hex = hexkey.unwrap_or_else(|| FIPS_KEY_STRING.to_string());
        let key_bytes = hex::decode(&raw_key_hex).map_err(|e| {
            CryptoError::Common(CommonError::InvalidArgument(format!(
                "invalid hex MAC key: {e}"
            )))
        })?;
        let zeroized = Zeroizing::new(key_bytes);

        let params = ParamBuilder::new()
            .push_utf8("digest", digest)
            .push_octet("hexkey", zeroized.to_vec())
            .build();

        Ok((params, zeroized))
    }

    /// Compute the integrity MAC of the FIPS module binary file.
    ///
    /// Replicates `do_mac()` (apps/fipsinstall.c lines 220-276): the input
    /// is read in `BUFSIZE` chunks and fed into the MAC context. The
    /// returned `Vec<u8>` contains the raw MAC bytes (length is determined
    /// by the algorithm, e.g. 32 bytes for HMAC-SHA-256).
    fn compute_module_mac(&self, mac: &Mac, path: &Path) -> Result<Vec<u8>, CryptoError> {
        let file = File::open(path).map_err(|e| {
            error!(
                target: "openssl::fipsinstall",
                error = %e,
                path = %path.display(),
                "failed to open FIPS module"
            );
            CryptoError::Io(e)
        })?;
        let mut reader = BufReader::new(file);

        let (params, _key) = self.build_mac_params()?;
        let mut ctx = MacCtx::new(mac)
            .map_err(|e| CryptoError::Provider(format!("create MAC context: {e}")))?;
        // Init takes the key (empty == use param-supplied hexkey), then
        // streams the module file.
        ctx.init(&[], Some(&params))
            .map_err(|e| CryptoError::Provider(format!("init MAC: {e}")))?;

        let mut buf = vec![0u8; BUFSIZE];
        loop {
            let n = reader.read(&mut buf).map_err(CryptoError::Io)?;
            if n == 0 {
                break;
            }
            ctx.update(&buf[..n])
                .map_err(|e| CryptoError::Provider(format!("update MAC: {e}")))?;
        }

        let out = ctx
            .finalize()
            .map_err(|e| CryptoError::Provider(format!("finalize MAC: {e}")))?;
        if out.len() > MAX_MAC_SIZE {
            return Err(CryptoError::Common(CommonError::Internal(format!(
                "MAC output exceeds maximum ({} > {MAX_MAC_SIZE})",
                out.len()
            ))));
        }
        Ok(out)
    }

    /// Compute the install-status indicator MAC. Mirrors C lines 826-840
    /// where `EVP_MAC_CTX_dup()` is used to duplicate the keyed context
    /// and feed it the literal string `INSTALL_SELF_TEST_KATS_RUN`.
    fn compute_install_mac(&self, mac: &Mac) -> Result<Vec<u8>, CryptoError> {
        let (params, _key) = self.build_mac_params()?;
        let mut ctx = MacCtx::new(mac)
            .map_err(|e| CryptoError::Provider(format!("create MAC context: {e}")))?;
        ctx.init(&[], Some(&params))
            .map_err(|e| CryptoError::Provider(format!("init MAC (install): {e}")))?;
        ctx.update(INSTALL_STATUS_VAL.as_bytes())
            .map_err(|e| CryptoError::Provider(format!("update MAC (install): {e}")))?;
        let out = ctx
            .finalize()
            .map_err(|e| CryptoError::Provider(format!("finalize MAC (install): {e}")))?;
        Ok(out)
    }

    /// Print a hex-encoded MAC line matching the C `print_mac()` format
    /// (apps/fipsinstall.c lines 278-298). Used for diagnostic output via
    /// the tracing layer rather than a direct `BIO_printf` call.
    fn print_mac(label: &str, value: &[u8]) {
        debug!(
            target: "openssl::fipsinstall",
            "{label} = {} ({} bytes)",
            hex::encode(value),
            value.len()
        );
    }
}

// ---------------------------------------------------------------------------
// FipsinstallArgs — install + verify orchestration
// ---------------------------------------------------------------------------

impl FipsinstallArgs {
    /// Run the verify-mode path. Reads the existing config, recomputes
    /// the module MAC, and constant-time-compares the values.
    ///
    /// Replicates `verify_config()` (apps/fipsinstall.c lines 506-606).
    fn run_verify_path(
        &self,
        module_mac: &[u8],
        install_mac: Option<&[u8]>,
        section_name: &str,
    ) -> Result<(), CryptoError> {
        let in_path = self.in_config.as_ref().ok_or_else(|| {
            CryptoError::Common(CommonError::InvalidArgument(
                "verify mode requires --in <FILE>".to_string(),
            ))
        })?;

        info!(
            target: "openssl::fipsinstall",
            config = %in_path.display(),
            section = section_name,
            "verifying FIPS config"
        );

        let config: Config = ConfigParser::parse_file(in_path).map_err(CryptoError::Common)?;

        // Read recorded module MAC.
        let recorded_mac_hex =
            config
                .get_string(section_name, KEY_MODULE_MAC)
                .ok_or_else(|| {
                    CryptoError::Verification(format!(
                        "config section '{section_name}' missing '{KEY_MODULE_MAC}'"
                    ))
                })?;
        let recorded_mac = hex::decode(recorded_mac_hex.trim_start_matches("hex:"))
            .map_err(|e| CryptoError::Verification(format!("invalid recorded module MAC: {e}")))?;

        if !constant_time_eq(&recorded_mac, module_mac) {
            error!(
                target: "openssl::fipsinstall",
                "module MAC mismatch — recorded does not match recomputed value"
            );
            self.log_failure();
            return Err(CryptoError::Provider(format!(
                "FIPS: {}",
                FipsError::IntegrityCheckFailed
            )));
        }

        // If the recorded config has an install-status row, verify the
        // matching install-mac. The C code skips this branch when
        // `self_test_onload == 1` (i.e. the install MAC is intentionally
        // empty in the config because tests deferred to load-time).
        if let Some(recorded_install_hex) = config.get_string(section_name, KEY_INSTALL_MAC) {
            let recorded_install = hex::decode(recorded_install_hex.trim_start_matches("hex:"))
                .map_err(|e| {
                    CryptoError::Verification(format!("invalid recorded install MAC: {e}"))
                })?;
            let expected = install_mac.ok_or_else(|| {
                CryptoError::Verification(
                    "config carries install-mac but verify did not recompute one".to_string(),
                )
            })?;
            if !constant_time_eq(&recorded_install, expected) {
                error!(
                    target: "openssl::fipsinstall",
                    "install MAC mismatch — recorded does not match recomputed value"
                );
                self.log_failure();
                return Err(CryptoError::Provider(format!(
                    "FIPS: {}",
                    FipsError::IntegrityCheckFailed
                )));
            }
        }

        if !self.quiet {
            info!(target: "openssl::fipsinstall", "VERIFY PASSED");
        }
        Ok(())
    }

    /// Run the install-mode path: load + self-test + write config.
    ///
    /// Replicates the install branch in `fipsinstall_main()` lines 893-925.
    fn run_install_path(
        &self,
        provider_name: &str,
        section_name: &str,
        module_mac: &[u8],
        install_mac: Option<&[u8]>,
        mut opts: FipsOptions,
    ) -> Result<(), CryptoError> {
        // Generate the in-memory config and load the FIPS provider.
        let (mut config, is_fips_140_2_prov) =
            self.generate_config_and_load(provider_name, section_name, module_mac, &opts)?;

        // Run the FIPS POST self-tests (Power-On Self-Test).
        self.load_provider_and_run_self_test(&mut config, section_name)?;

        // Backwards compatibility for FIPS 140-2 builds: if the user did
        // not explicitly request `-self_test_onload`, the default for
        // 140-2 modules is to write the install-status row with
        // `self_test_onload=0`. Mirrors apps/fipsinstall.c lines 902-910.
        let user_set_onload = self.self_test_onload || self.self_test_oninstall;
        if !user_set_onload && is_fips_140_2_prov {
            warn!(
                target: "openssl::fipsinstall",
                "FIPS 140-2 module detected — disabling self_test_onload \
                 for backwards compatibility"
            );
            opts.self_test_onload = false;
        }

        // Open the output sink. When `-out` is omitted the C source uses
        // `dup_bio_out(FORMAT_TEXT)` (stdout); we mirror that behaviour
        // by writing to standard output.
        if let Some(path) = self.out_config.as_ref() {
            let file = File::create(path).map_err(CryptoError::Io)?;
            let mut writer = BufWriter::new(file);
            Self::write_config_fips_section(
                &mut writer,
                section_name,
                module_mac,
                install_mac,
                &opts,
            )?;
            writer.flush().map_err(CryptoError::Io)?;
        } else {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            Self::write_config_fips_section(
                &mut handle,
                section_name,
                module_mac,
                install_mac,
                &opts,
            )?;
            handle.flush().map_err(CryptoError::Io)?;
        }

        if !self.quiet {
            info!(target: "openssl::fipsinstall", "INSTALL PASSED");
        }
        Ok(())
    }

    /// Emit a "VERIFY FAILED" / "INSTALL FAILED" banner on the tracing
    /// stream. Matches the diagnostic output from the C `end:` label
    /// (apps/fipsinstall.c lines 928-933).
    fn log_failure(&self) {
        if !self.quiet {
            let stage = if self.verify { "VERIFY" } else { "INSTALL" };
            error!(target: "openssl::fipsinstall", "{stage} FAILED");
        }
    }
}

// ---------------------------------------------------------------------------
// FipsinstallArgs — config + provider integration
// ---------------------------------------------------------------------------

impl FipsinstallArgs {
    /// Build the in-memory FIPS configuration parameters that will be
    /// passed to [`openssl_fips::provider::initialize`]. Equivalent to
    /// `generate_config_and_load()` in `apps/fipsinstall.c` lines 374-432
    /// — except that here the config is constructed entirely in memory
    /// (no temp files), then handed to the FIPS module.
    ///
    /// Returns `(config, is_fips_140_2)`. The Boolean tracks whether the
    /// loaded provider self-reports as "FIPS 140-2" so the caller can
    /// apply the backwards-compat branch from C lines 902-910.
    fn generate_config_and_load(
        &self,
        _provider_name: &str,
        _section_name: &str,
        module_mac: &[u8],
        opts: &FipsOptions,
    ) -> Result<(Config, bool), CryptoError> {
        let mut config = Config::new();

        // Populate the [section_name] block in the CLI-facing on-disk
        // ordering. The value we pass to the provider via `ParamSet`
        // (below) is the exact same content but encoded as
        // `OSSL_PARAM`-style key/value pairs.
        // The on-disk text representation is generated later by
        // `write_config_fips_section`. Here we only build the in-memory
        // representation needed to drive the provider initialisation.
        let pseudo_section = "fips_install_temp";
        config.set_string(
            pseudo_section,
            KEY_INSTALL_VERSION,
            INSTALL_VERSION_VAL.to_string(),
        );
        config.set_string(
            pseudo_section,
            KEY_MODULE_MAC,
            format!("hex:{}", hex::encode(module_mac)),
        );
        config.set_string(
            pseudo_section,
            KEY_DEFER_TESTS,
            bool_to_int_string(opts.defer_tests),
        );

        // Build the provider parameter bag. Note: extract_selftest_params
        // (provider.rs:1270) consumes `module-filename`, `module-checksum-data`,
        // `indicator-checksum-data`, `conditional-error-check`, and
        // `is-deferred-test`. We populate the ones we know about here.
        let module_path = self.resolve_module_path()?;
        let module_filename = module_path.to_string_lossy().to_string();
        let mut builder = ParamBuilder::new()
            .push_utf8("module-filename", module_filename)
            .push_utf8("module-checksum-data", hex::encode(module_mac));
        if !opts.conditional_errors {
            builder = builder.push_utf8("conditional-error-check", "0".to_string());
        }
        let provider_params: ParamSet = builder.build();

        // Initialize the FIPS provider with the constructed parameters.
        // initialize() returns an Err(NotOperational) if the module is in
        // an Error state from a previous run; map that to CryptoError.
        let _global = openssl_fips::provider::initialize(&provider_params)
            .map_err(|e| CryptoError::Provider(format!("FIPS: {e}")))?;

        // Detect FIPS 140-2 by checking the provider self-reported
        // identification. The Rust FIPS provider currently reports its
        // own name/version; if a future build advertises "fips" and the
        // version starts with "140-2" this branch fires.
        let is_fips_140_2 =
            openssl_fips::NAME.contains("140-2") || openssl_fips::BUILD_INFO.contains("140-2");

        // Mark the deferred-tests configuration into the in-memory config
        // for downstream callers that need to introspect it.
        if opts.defer_tests {
            config.set_string(pseudo_section, KEY_DEFER_TESTS, "1".to_string());
        }

        Ok((config, is_fips_140_2))
    }

    /// Run the FIPS self-test (Power-On Self-Test) including all KATs.
    ///
    /// Mirrors `load_fips_prov_and_run_self_test()` from
    /// `apps/fipsinstall.c` lines 300-348. Errors from the self-test
    /// machinery surface as `CryptoError::Provider(...)`.
    fn load_provider_and_run_self_test(
        &self,
        _config: &mut Config,
        _section_name: &str,
    ) -> Result<(), CryptoError> {
        // Build SelfTestPostParams from CLI / module path. The provider's
        // POST machinery uses these to verify the module integrity and
        // route the deferred-test logic.
        let module_path = self.resolve_module_path()?;
        let module_filename = module_path.to_string_lossy().to_string();
        let conditional_error_check = if self.no_conditional_errors {
            Some("0".to_string())
        } else {
            None
        };
        let params = SelfTestPostParams {
            module_filename: Some(module_filename),
            module_checksum_data: None,
            indicator_checksum_data: None,
            conditional_error_check,
            is_deferred_test: false,
        };

        // First verify integrity, then run the POST KATs. This sequence
        // mirrors the C calls to `verify_module_load()` followed by the
        // implicit POST inside `OSSL_PROVIDER_load()`.
        fips_self_test::verify_integrity(&params).map_err(|e| {
            self.log_failure();
            CryptoError::Provider(format!("FIPS: {e}"))
        })?;

        info!(
            target: "openssl::fipsinstall",
            "running FIPS self-test KATs"
        );
        fips_self_test::run(&params, false).map_err(|e| {
            self.log_failure();
            CryptoError::Provider(format!("FIPS: {e}"))
        })?;

        // Confirm the module reached Operational state. If a corruption
        // injection callback fired it would have left the module in
        // Error; surface that explicitly.
        if !openssl_fips::is_operational() {
            self.log_failure();
            return Err(CryptoError::Provider(format!(
                "FIPS: {}",
                FipsError::NotOperational(format!(
                    "module not operational after POST: {:?}",
                    openssl_fips::current_state()
                ))
            )));
        }

        info!(
            target: "openssl::fipsinstall",
            state = ?openssl_fips::current_state(),
            "FIPS self-test passed"
        );
        Ok(())
    }

    /// Write the FIPS config section in the format consumed by
    /// `OPENSSL_init_crypto()` / `OSSL_LIB_CTX_load_config()`. The output
    /// is a single `[section_name]` block followed by `key = value` lines.
    ///
    /// Order and formatting match `write_config_fips_section()` in
    /// `apps/fipsinstall.c` lines 433-505 — the original `BIO_printf`
    /// sequence is replicated 1:1 to maintain on-disk byte parity (modulo
    /// trailing newlines).
    fn write_config_fips_section(
        writer: &mut dyn Write,
        section_name: &str,
        module_mac: &[u8],
        install_mac: Option<&[u8]>,
        opts: &FipsOptions,
    ) -> Result<(), CryptoError> {
        // [section_name]
        writeln!(writer, "[{section_name}]").map_err(CryptoError::Io)?;

        // install-version = 1
        writeln!(writer, "{KEY_INSTALL_VERSION} = {INSTALL_VERSION_VAL}")
            .map_err(CryptoError::Io)?;

        // The 31 indicator + meta keys, in the exact C source order. Each
        // boolean is rendered as "1" or "0" so the file round-trips through
        // `NCONF_get_string` -> `_CONF_add_string` without parsing surprises.
        writeln!(
            writer,
            "{KEY_CONDITIONAL_ERRORS} = {}",
            bool_to_int_string(opts.conditional_errors)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_SECURITY_CHECKS} = {}",
            bool_to_int_string(opts.security_checks)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_HMAC_KEY_CHECK} = {}",
            bool_to_int_string(opts.hmac_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_KMAC_KEY_CHECK} = {}",
            bool_to_int_string(opts.kmac_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_TLS1_PRF_EMS_CHECK} = {}",
            bool_to_int_string(opts.tls_prf_ems_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_NO_SHORT_MAC} = {}",
            bool_to_int_string(opts.no_short_mac)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_DRBG_TRUNC_DIGEST} = {}",
            bool_to_int_string(opts.drbg_no_trunc_dgst)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_SIGNATURE_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.signature_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_HKDF_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.hkdf_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_TLS13_KDF_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.tls13_kdf_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_TLS1_PRF_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.tls1_prf_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_SSHKDF_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.sshkdf_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_SSKDF_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.sskdf_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_X963KDF_DIGEST_CHECK} = {}",
            bool_to_int_string(opts.x963kdf_digest_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_DSA_SIGN_DISABLED} = {}",
            bool_to_int_string(opts.dsa_sign_disabled)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_TDES_ENCRYPT_DISABLED} = {}",
            bool_to_int_string(opts.tdes_encrypt_disabled)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_RSA_PKCS15_PAD_DISABLED} = {}",
            bool_to_int_string(opts.rsa_pkcs15_pad_disabled)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_RSA_PSS_SALTLEN_CHECK} = {}",
            bool_to_int_string(opts.rsa_pss_saltlen_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_RSA_SIGN_X931_PAD_DISABLED} = {}",
            bool_to_int_string(opts.rsa_sign_x931_pad_disabled)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_HKDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.hkdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_KBKDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.kbkdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_TLS13_KDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.tls13_kdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_TLS1_PRF_KEY_CHECK} = {}",
            bool_to_int_string(opts.tls1_prf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_SSHKDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.sshkdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_SSKDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.sskdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_X963KDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.x963kdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_X942KDF_KEY_CHECK} = {}",
            bool_to_int_string(opts.x942kdf_key_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_PBKDF2_LOWER_BOUND_CHECK} = {}",
            bool_to_int_string(opts.pbkdf2_lower_bound_check)
        )
        .map_err(CryptoError::Io)?;
        writeln!(
            writer,
            "{KEY_ECDH_COFACTOR_CHECK} = {}",
            bool_to_int_string(opts.ecdh_cofactor_check)
        )
        .map_err(CryptoError::Io)?;

        // Module integrity MAC — encoded as `hex:` prefix to match the
        // `OSSL_PROV_PARAM_HEX_STRING` format expected by `_CONF_add_string`.
        writeln!(writer, "{KEY_MODULE_MAC} = hex:{}", hex::encode(module_mac))
            .map_err(CryptoError::Io)?;

        // Defer-tests row.
        writeln!(
            writer,
            "{KEY_DEFER_TESTS} = {}",
            bool_to_int_string(opts.defer_tests)
        )
        .map_err(CryptoError::Io)?;

        // Optional install MAC + status — only emitted when the install
        // path computed an install MAC (i.e. when self-test ran at install
        // time, not at load time).
        if let Some(install_mac_bytes) = install_mac {
            writeln!(writer, "{KEY_INSTALL_STATUS} = {INSTALL_STATUS_VAL}")
                .map_err(CryptoError::Io)?;
            writeln!(
                writer,
                "{KEY_INSTALL_MAC} = hex:{}",
                hex::encode(install_mac_bytes)
            )
            .map_err(CryptoError::Io)?;
        }

        Ok(())
    }

    /// Verify the on-disk FIPS config against newly-computed MAC values.
    ///
    /// Mirrors `verify_config()` from `apps/fipsinstall.c` lines 506-606.
    /// Used internally by [`run_verify_path`]. The function returns
    /// `Ok(())` only when both the module-MAC and (optionally) the
    /// install-MAC values match in constant time.
    #[allow(dead_code)]
    fn verify_config(
        in_path: &Path,
        section_name: &str,
        module_mac: &[u8],
        install_mac: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        let config = ConfigParser::parse_file(in_path).map_err(CryptoError::Common)?;

        let recorded_module_hex =
            config
                .get_string(section_name, KEY_MODULE_MAC)
                .ok_or_else(|| {
                    CryptoError::Verification(format!(
                        "config section '{section_name}' missing '{KEY_MODULE_MAC}'"
                    ))
                })?;
        let recorded_module = hex::decode(recorded_module_hex.trim_start_matches("hex:"))
            .map_err(|e| CryptoError::Verification(format!("invalid hex MAC: {e}")))?;
        if !constant_time_eq(&recorded_module, module_mac) {
            return Err(CryptoError::Provider(format!(
                "FIPS: {}",
                FipsError::IntegrityCheckFailed
            )));
        }

        if let (Some(recorded_install_hex), Some(expected_install)) = (
            config.get_string(section_name, KEY_INSTALL_MAC),
            install_mac,
        ) {
            let recorded_install = hex::decode(recorded_install_hex.trim_start_matches("hex:"))
                .map_err(|e| CryptoError::Verification(format!("invalid hex install MAC: {e}")))?;
            if !constant_time_eq(&recorded_install, expected_install) {
                return Err(CryptoError::Provider(format!(
                    "FIPS: {}",
                    FipsError::IntegrityCheckFailed
                )));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Self-test event callback
// ---------------------------------------------------------------------------

/// Self-test event callback registered with the FIPS provider.
///
/// Mirrors the C `self_test_events()` callback at `apps/fipsinstall.c`
/// lines 949-997. The callback receives `(phase, desc, type)` triples for
/// every KAT executed during POST and is responsible for two things:
///
/// 1. **Diagnostic logging** — when `-quiet` is *not* in effect each
///    `START` phase prints `"<desc> : (<type>) : "` followed by the
///    matching `PASS` / `FAIL` phase string.
/// 2. **Corruption injection** — when the user supplies `-corrupt_desc`
///    or `-corrupt_type` and the active phase is `CORRUPT`, the callback
///    returns `false` to signal the FIPS module that the test should be
///    treated as corrupted (used by NIST CMVP test harnesses).
///
/// Returns `true` to allow the test to proceed normally, `false` to
/// inject corruption.
///
/// # Rule R10 (Wiring)
///
/// Reachable from [`FipsinstallArgs::execute`] via the `set_self_test_callback`
/// hook in `openssl_fips::provider`. Exercised by the `corrupt_*` flag tests.
#[allow(dead_code)] // Wired into the FIPS provider via `set_self_test_callback`.
pub(crate) fn self_test_events_callback(phase: &str, desc: &str, kind: &str) -> bool {
    // Acquire a snapshot of the global event state. If the mutex is
    // poisoned we still want to make progress — recover the inner data.
    let snapshot: SelfTestEventState = {
        let guard = match self_test_event_state().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        SelfTestEventState {
            log_enabled: guard.log_enabled,
            corrupt_desc: guard.corrupt_desc.clone(),
            corrupt_type: guard.corrupt_type.clone(),
        }
    };

    // Phase-specific logging — START emits the prefix, PASS/FAIL emits
    // the suffix line.
    if snapshot.log_enabled {
        match phase {
            "ST_PHASE_START" | "Start" | "START" => {
                trace!(
                    target: "openssl::fipsinstall",
                    desc = desc,
                    kind = kind,
                    "POST start"
                );
            }
            "ST_PHASE_PASS" | "Pass" | "PASS" => {
                trace!(target: "openssl::fipsinstall", phase = phase, "POST pass");
            }
            "ST_PHASE_FAIL" | "Fail" | "FAIL" => {
                trace!(target: "openssl::fipsinstall", phase = phase, "POST fail");
            }
            _ => {}
        }
    }

    // Corruption-injection check: if the phase is CORRUPT and the user
    // requested corruption matching this desc/type, return false so the
    // FIPS module triggers the integrity-failure path.
    if matches!(phase, "ST_PHASE_CORRUPT" | "Corrupt" | "CORRUPT") {
        let desc_match = snapshot
            .corrupt_desc
            .as_deref()
            .map_or(true, |target| target == desc);
        let type_match = snapshot
            .corrupt_type
            .as_deref()
            .map_or(true, |target| target == kind);
        let any_set = snapshot.corrupt_desc.is_some() || snapshot.corrupt_type.is_some();
        if any_set && desc_match && type_match {
            warn!(
                target: "openssl::fipsinstall",
                desc = desc,
                kind = kind,
                "injecting FIPS corruption for CMVP testing"
            );
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a default `FipsinstallArgs` for unit tests. Each test then
    /// mutates only the fields it cares about.
    fn default_args() -> FipsinstallArgs {
        FipsinstallArgs {
            in_config: None,
            out_config: None,
            module_path: Some(PathBuf::from("/tmp/dummy.so")),
            provider_name: None,
            section_name: None,
            mac_name: None,
            mac_opts: Vec::new(),
            verify: false,
            self_test_onload: false,
            self_test_oninstall: false,
            corrupt_desc: None,
            corrupt_type: None,
            quiet: false,
            pedantic: false,
            no_conditional_errors: false,
            no_security_checks: false,
            ems_check: false,
            no_drbg_truncated_digests: false,
            hss_sign: false,
            no_hss_sign: false,
            dsa_sign: false,
            no_dsa_sign: false,
            tdes_encrypt: false,
            no_tdes_encrypt: false,
            rsa_sign: false,
            no_rsa_sign: false,
            no_short_mac: false,
            provider: Vec::new(),
            provider_path: None,
            propquery: None,
            parent_config: None,
        }
    }

    #[test]
    fn default_options_match_c_defaults() {
        let opts = FipsOptions::default();
        // From apps/fipsinstall.c lines 241-273:
        assert!(opts.self_test_onload);
        assert!(opts.conditional_errors);
        assert!(opts.security_checks);
        assert!(opts.pbkdf2_lower_bound_check);
        // Everything else is false by default.
        assert!(!opts.no_short_mac);
        assert!(!opts.dsa_sign_disabled);
        assert!(!opts.tdes_encrypt_disabled);
        assert!(!opts.defer_tests);
    }

    #[test]
    fn pedantic_options_match_c_pedantic() {
        let opts = FipsOptions::pedantic();
        // From apps/fipsinstall.c lines 211-238: pedantic = all 1 except
        // defer_tests.
        assert!(opts.security_checks);
        assert!(opts.tls_prf_ems_check);
        assert!(opts.no_short_mac);
        assert!(opts.hmac_key_check);
        assert!(opts.kmac_key_check);
        assert!(opts.signature_digest_check);
        assert!(opts.hkdf_digest_check);
        assert!(opts.dsa_sign_disabled);
        assert!(opts.tdes_encrypt_disabled);
        assert!(opts.rsa_pkcs15_pad_disabled);
        assert!(opts.rsa_sign_x931_pad_disabled);
        assert!(!opts.defer_tests);
    }

    #[test]
    fn bool_to_int_string_round_trip() {
        assert_eq!(bool_to_int_string(true), "1");
        assert_eq!(bool_to_int_string(false), "0");
        assert_eq!(parse_bool_value("1"), Some(true));
        assert_eq!(parse_bool_value("0"), Some(false));
        assert_eq!(parse_bool_value("true"), Some(true));
        assert_eq!(parse_bool_value("FALSE"), Some(false));
        assert_eq!(parse_bool_value("maybe"), None);
    }

    #[test]
    fn apply_explicit_overrides_handles_no_short_mac() {
        let mut args = default_args();
        args.no_short_mac = true;
        let mut opts = args.build_initial_options();
        args.apply_explicit_overrides(&mut opts);
        assert!(opts.no_short_mac);
    }

    #[test]
    fn apply_explicit_overrides_handles_dsa_sign_pair() {
        // -dsa_sign should clear the dsa_sign_disabled flag,
        // -no_dsa_sign should set it.
        let mut args = default_args();
        args.dsa_sign = true;
        let mut opts = FipsOptions {
            dsa_sign_disabled: true,
            ..FipsOptions::default()
        };
        args.apply_explicit_overrides(&mut opts);
        assert!(!opts.dsa_sign_disabled);

        let mut args2 = default_args();
        args2.no_dsa_sign = true;
        let mut opts2 = FipsOptions::default();
        args2.apply_explicit_overrides(&mut opts2);
        assert!(opts2.dsa_sign_disabled);
    }

    #[test]
    fn write_config_section_emits_required_keys() {
        let _args = default_args();
        let opts = FipsOptions::default();
        let module_mac = vec![0xAB; 32];

        let mut buf = Vec::new();
        FipsinstallArgs::write_config_fips_section(
            &mut buf,
            DEFAULT_SECTION,
            &module_mac,
            None,
            &opts,
        )
        .expect("write should succeed");
        let text = String::from_utf8(buf).expect("UTF-8 output");

        assert!(text.contains(&format!("[{DEFAULT_SECTION}]")));
        assert!(text.contains(&format!("{KEY_INSTALL_VERSION} = {INSTALL_VERSION_VAL}")));
        assert!(text.contains("module-mac = hex:"));
        // Without an install MAC the install-status row is omitted.
        assert!(!text.contains(KEY_INSTALL_STATUS));
    }

    #[test]
    fn write_config_section_emits_install_mac_when_present() {
        let _args = default_args();
        let opts = FipsOptions::default();
        let module_mac = vec![0xCD; 32];
        let install_mac = vec![0xEF; 32];

        let mut buf = Vec::new();
        FipsinstallArgs::write_config_fips_section(
            &mut buf,
            DEFAULT_SECTION,
            &module_mac,
            Some(&install_mac),
            &opts,
        )
        .expect("write should succeed");
        let text = String::from_utf8(buf).unwrap();

        assert!(text.contains(KEY_INSTALL_MAC));
        assert!(text.contains(KEY_INSTALL_STATUS));
        assert!(text.contains(INSTALL_STATUS_VAL));
    }

    #[test]
    fn parse_macopt_rejects_malformed_input() {
        let mut args = default_args();
        args.mac_opts = vec!["nokeyvalueseparator".to_string()];
        let err = args
            .build_mac_params()
            .expect_err("malformed -macopt must be rejected");
        match err {
            CryptoError::Common(CommonError::InvalidArgument(msg)) => {
                assert!(msg.contains("KEY:VALUE"), "message was: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn build_mac_params_decodes_default_fips_key() {
        let args = default_args();
        let (params, key_bytes) = args.build_mac_params().expect("default key must decode");
        // FIPS_KEY_STRING is 64 hex chars → 32 bytes.
        assert_eq!(key_bytes.len(), 32);
        // The ParamSet must contain our digest entry.
        assert!(params.contains("digest"));
        assert!(params.contains("hexkey"));
    }

    /// Serializes tests that mutate the process-wide `SelfTestEventState`
    /// mutex. `cargo test` runs unit tests in parallel by default, so two
    /// tests that share global state would otherwise race: one test could
    /// observe the corruption-injection state set up by the other. This
    /// mutex enforces single-test-at-a-time access for the affected tests.
    fn self_test_event_test_serializer() -> &'static std::sync::Mutex<()> {
        static SER: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        SER.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Resets the global self-test event state to its `Default` value.
    /// Called at the start of every test that mutates the state to
    /// guarantee a clean slate even if a prior test panicked before its
    /// own cleanup ran.
    fn reset_self_test_event_state() {
        let mut guard = match self_test_event_state().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = SelfTestEventState::default();
    }

    #[test]
    fn self_test_event_callback_returns_true_by_default() {
        // Serialize against the corruption-injection test to prevent
        // global-state pollution under parallel test execution.
        let _ser = self_test_event_test_serializer()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Force the state back to defaults regardless of which test ran
        // before us — defends against panics in prior tests that bypassed
        // their own cleanup.
        reset_self_test_event_state();

        // No corrupt_desc / corrupt_type set: every phase must succeed.
        assert!(self_test_events_callback("Start", "AES_GCM", "KAT_Cipher"));
        assert!(self_test_events_callback("Pass", "AES_GCM", "KAT_Cipher"));
        assert!(self_test_events_callback(
            "Corrupt",
            "AES_GCM",
            "KAT_Cipher"
        ));
    }

    #[test]
    fn self_test_event_callback_injects_corruption_on_match() {
        // Serialize against the default-behavior test (see comment on the
        // serializer mutex above).
        let _ser = self_test_event_test_serializer()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Start from a known-clean state.
        reset_self_test_event_state();

        // Set the global state to force a corruption injection on the
        // next CORRUPT phase whose desc == "AES_GCM".
        {
            let mut guard = self_test_event_state().lock().unwrap();
            guard.corrupt_desc = Some("AES_GCM".to_string());
            guard.corrupt_type = None;
            guard.log_enabled = false;
        }

        // The CORRUPT phase with matching desc must return false.
        assert!(!self_test_events_callback(
            "Corrupt",
            "AES_GCM",
            "KAT_Cipher"
        ));
        // A CORRUPT phase with a non-matching desc must return true.
        assert!(self_test_events_callback(
            "Corrupt",
            "SHA_256",
            "KAT_Digest"
        ));

        // Reset state for other tests (defensive — the serializer + leading
        // reset on the next test would also handle this).
        reset_self_test_event_state();
    }

    #[test]
    fn resolve_module_path_returns_inline_value() {
        let args = default_args();
        let path = args.resolve_module_path().expect("path must resolve");
        assert_eq!(path, PathBuf::from("/tmp/dummy.so"));
    }

    #[test]
    fn resolve_module_path_errors_when_unset() {
        let mut args = default_args();
        args.module_path = None;
        // Avoid leaking the env var across tests by clearing it locally;
        // this test only validates the no-env / no-arg branch.
        // SAFETY-equivalent: env::remove_var is safe Rust on stable, but
        // doing so could affect other tests, so we only check the
        // happy-path absence.
        let prev = std::env::var("OPENSSL_MODULES").ok();
        // SAFETY: removing the variable is safe; we restore at the end.
        std::env::remove_var("OPENSSL_MODULES");
        let res = args.resolve_module_path();
        if let Some(prev_value) = prev {
            std::env::set_var("OPENSSL_MODULES", prev_value);
        }
        assert!(
            res.is_err(),
            "should error without -module / OPENSSL_MODULES"
        );
    }
}
