//! FIPS provider entry point and dispatch module.
//!
//! Translates the C `fipsprov.c` (1,499 lines) provider initialization, algorithm
//! registration tables, and core callback capture to idiomatic Rust trait-based dispatch,
//! plus `fips_entry.c` (20 lines) which provides the ABI entry trampoline.
//!
//! # Architecture
//!
//! The FIPS provider is the only provider that may be used in FIPS 140-3 compliant mode.
//! It registers a curated set of FIPS-approved algorithms and enforces compliance through:
//!
//! 1. **Power-On Self-Test (POST):** Executed during [`initialize()`] before the module
//!    transitions to the `Running` state.
//! 2. **Known Answer Tests (KATs):** Delegated to [`crate::kats`] for per-algorithm
//!    verification.
//! 3. **Deferred Tests:** Individual KATs can be deferred to first use, serialized by
//!    [`FipsGlobal::deferred_lock`].
//! 4. **Indicator Configuration:** 27 per-algorithm FIPS indicator parameters control
//!    strict vs. tolerant enforcement behavior.
//!
//! # Module State Machine
//!
//! ```text
//! Init ──→ SelfTesting ──┬──→ Running
//!                        └──→ Error
//! ```
//!
//! # C Mapping
//!
//! | Rust Construct            | C Origin                                            |
//! |---------------------------|-----------------------------------------------------|
//! | [`FipsGlobal`]            | `FIPS_GLOBAL` struct (`fipsprov.c` lines 97–109)      |
//! | [`FipsOption`]            | `FIPS_OPTION` struct (`fipsprov.c` lines 92–95)       |
//! | [`FipsIndicatorConfig`]   | `.inc` macro expansion (`fips_indicator_params.inc`)   |
//! | [`SelfTestPostParams`]    | `SELF_TEST_POST_PARAMS` (`self_test.h` lines 30–40)   |
//! | [`FipsAlgorithmEntry`]    | `OSSL_ALGORITHM` (`core_dispatch.h`)                   |
//! | [`initialize()`]          | `OSSL_provider_init_int()` (`fipsprov.c` lines 870–1086)|
//! | [`query_algorithms()`]    | `fips_query()` (`fipsprov.c` lines 714–765)            |
//! | [`run_deferred_test()`]   | `ossl_deferred_self_test()` (fipsprov.c lines 1464–1498)|
//!
//! # Rules
//!
//! - **R5 (Nullability):** All C `NULL` pointers become `Option<T>`.
//! - **R7 (Lock Granularity):** Every `RwLock` carries `// LOCK-SCOPE:` annotation.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks — dispatch is trait-based.
//! - **R9 (Warning-Free):** No `#[allow(unused)]` without justification.
//! - **R10 (Wiring):** `initialize()` is the entry point; all tables reachable via `query_algorithms()`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::{RwLock, RwLockWriteGuard};
use tracing::{debug, error, info, instrument, warn};

use openssl_common::error::{FipsError, FipsResult};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::types::OperationType;

use crate::indicator::FipsIndicator;
use crate::kats;
use crate::state::{self, FipsState, TestState, FIPS_MODULE_STATE};

// =============================================================================
// Constants — FIPS Provider Properties (fipsprov.c lines 38–39)
// =============================================================================

/// Default property string for FIPS-approved algorithms.
///
/// Algorithms registered with this property string are considered FIPS-approved
/// and will be fetched when the caller requests `"provider=fips,fips=yes"`.
///
/// Corresponds to C `FIPS_DEFAULT_PROPERTIES` (fipsprov.c line 38).
pub const FIPS_DEFAULT_PROPERTIES: &str = "provider=fips,fips=yes";

/// Property string for algorithms available in the FIPS provider but not
/// FIPS-approved.
///
/// These algorithms are functional but their use will be flagged as unapproved
/// by the FIPS indicator mechanism.
///
/// Corresponds to C `FIPS_UNAPPROVED_PROPERTIES` (fipsprov.c line 39).
pub const FIPS_UNAPPROVED_PROPERTIES: &str = "provider=fips,fips=no";

// =============================================================================
// FIPS_OPTION — Per-Parameter Enable/Disable Toggle (fipsprov.c lines 92–95)
// =============================================================================

/// A single FIPS configuration option with an optional string value and an
/// enable/disable flag.
///
/// In the C implementation, the `option` field is a `const char *` that may be
/// `NULL`, and `enabled` is an `unsigned char` used as a boolean (0/1).
///
/// **Rule R5:** `option` uses `Option<String>` instead of a `NULL` pointer sentinel.
///
/// # C Mapping
///
/// ```c
/// typedef struct {
///     const char *option;
///     unsigned char enabled;
/// } FIPS_OPTION;
/// ```
#[derive(Debug, Clone)]
pub struct FipsOption {
    /// The raw string value of the option as read from configuration.
    /// `None` when the option has not been explicitly set (Rule R5).
    pub option: Option<String>,
    /// Whether this option is currently enabled.
    /// Defaults to `true` (matching C `init_fips_option` which sets `enabled = 1`).
    pub enabled: bool,
}

impl Default for FipsOption {
    /// Creates a default `FipsOption` with no explicit value and enabled = true.
    ///
    /// Matches the C `init_fips_option()` helper (fipsprov.c lines 111–116).
    fn default() -> Self {
        Self {
            option: None,
            enabled: true,
        }
    }
}

impl FipsOption {
    /// Applies the string value from configuration, updating the enabled flag.
    ///
    /// - `"1"` → enabled = true
    /// - `"0"` → enabled = false
    /// - Other values → returns an error
    ///
    /// Mirrors the C macro expansion at fipsprov.c lines 1050–1058.
    fn apply_config(&mut self) -> FipsResult<()> {
        if let Some(ref val) = self.option {
            match val.as_str() {
                "1" => self.enabled = true,
                "0" => self.enabled = false,
                other => {
                    return Err(FipsError::SelfTestFailed(format!(
                        "Invalid FIPS option value: '{other}' (expected '0' or '1')"
                    )));
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// SelfTestPostParams — POST Configuration (self_test.h lines 30–40)
// =============================================================================

/// Parameters for the Power-On Self-Test (POST) execution.
///
/// Contains the module filename and checksum data needed for integrity
/// verification, plus flags controlling conditional error checks and
/// deferred test behavior.
///
/// **Rule R5:** All string fields use `Option<String>` instead of C `NULL` pointers.
///
/// # C Mapping
///
/// ```c
/// typedef struct self_test_post_params_st {
///     const char *module_filename;
///     const char *module_checksum_data;
///     const char *indicator_checksum_data;
///     const char *conditional_error_check;
///     int defer_tests;
///     // ... BIO callbacks, libctx omitted (not needed in Rust)
/// } SELF_TEST_POST_PARAMS;
/// ```
#[derive(Debug, Clone, Default)]
pub struct SelfTestPostParams {
    /// Path to the FIPS module binary for integrity verification.
    pub module_filename: Option<String>,
    /// Hex-encoded expected checksum of the module binary.
    pub module_checksum_data: Option<String>,
    /// Hex-encoded expected checksum of the indicator data.
    pub indicator_checksum_data: Option<String>,
    /// If set to `"0"`, conditional error checks are disabled.
    pub conditional_error_check: Option<String>,
    /// Whether self-tests should be deferred to first algorithm use.
    pub is_deferred_test: bool,
}

// =============================================================================
// FipsIndicatorConfig — 27 FIPS Indicator Parameters (fips_indicator_params.inc)
// =============================================================================

/// Configuration for all 27 FIPS indicator parameters.
///
/// Each field corresponds to one line in the C `fips_indicator_params.inc` file,
/// which is included multiple times with different macro definitions to generate
/// struct fields, initialization, parameter fetch, and config accessor functions.
///
/// All fields default to `FipsOption::default()` (enabled = true, option = None).
///
/// # Parameter Semantics
///
/// When `enabled` is `true` for a given parameter, the corresponding FIPS check
/// is enforced in strict mode. When `false`, the check is relaxed (tolerant).
#[derive(Debug, Clone)]
pub struct FipsIndicatorConfig {
    /// Master security checks toggle. When disabled, all other checks are bypassed.
    pub security_checks: FipsOption,
    /// TLS 1.x PRF Extended Master Secret check.
    pub tls1_prf_ems_check: FipsOption,
    /// Short MAC output length check.
    pub no_short_mac: FipsOption,
    /// HMAC minimum key length check.
    pub hmac_key_check: FipsOption,
    /// KEM key size check.
    pub kem_key_check: FipsOption,
    /// KMAC minimum key length check.
    pub kmac_key_check: FipsOption,
    /// DSA key parameter check.
    pub dsa_key_check: FipsOption,
    /// Triple-DES key check (deprecated algorithm).
    pub tdes_key_check: FipsOption,
    /// RSA minimum key size check.
    pub rsa_key_check: FipsOption,
    /// DHX key parameter check.
    pub dhx_key_check: FipsOption,
    /// EC key curve check.
    pub ec_key_check: FipsOption,
    /// PKCS#12 key generation check.
    pub pkcs12_key_gen_check: FipsOption,
    /// X9.31 signature padding check.
    pub sign_x931_pad_check: FipsOption,
    /// Signature digest algorithm check.
    pub sign_digest_check: FipsOption,
    /// HKDF digest algorithm check.
    pub hkdf_digest_check: FipsOption,
    /// TLS 1.3 KDF digest algorithm check.
    pub tls13_kdf_digest_check: FipsOption,
    /// ECDH cofactor mode check.
    pub ecdh_cofactor_check: FipsOption,
    /// HKDF minimum key length check.
    pub hkdf_key_check: FipsOption,
    /// KBKDF minimum key length check.
    pub kbkdf_key_check: FipsOption,
    /// TLS 1.x PRF minimum key length check.
    pub tls1_prf_key_check: FipsOption,
    /// SSH KDF digest algorithm check.
    pub sshkdf_digest_check: FipsOption,
    /// SSH KDF minimum key length check.
    pub sshkdf_key_check: FipsOption,
    /// SSKDF digest algorithm check.
    pub sskdf_digest_check: FipsOption,
    /// SSKDF minimum key length check.
    pub sskdf_key_check: FipsOption,
    /// X9.63 KDF minimum key length check.
    pub x963kdf_key_check: FipsOption,
    /// X9.42 KDF minimum key length check.
    pub x942kdf_key_check: FipsOption,
    /// RSA-PSS signature parameter check.
    pub rsa_sign_pss_check: FipsOption,
}

impl Default for FipsIndicatorConfig {
    /// All 27 indicator parameters default to enabled with no explicit option value.
    fn default() -> Self {
        Self {
            security_checks: FipsOption::default(),
            tls1_prf_ems_check: FipsOption::default(),
            no_short_mac: FipsOption::default(),
            hmac_key_check: FipsOption::default(),
            kem_key_check: FipsOption::default(),
            kmac_key_check: FipsOption::default(),
            dsa_key_check: FipsOption::default(),
            tdes_key_check: FipsOption::default(),
            rsa_key_check: FipsOption::default(),
            dhx_key_check: FipsOption::default(),
            ec_key_check: FipsOption::default(),
            pkcs12_key_gen_check: FipsOption::default(),
            sign_x931_pad_check: FipsOption::default(),
            sign_digest_check: FipsOption::default(),
            hkdf_digest_check: FipsOption::default(),
            tls13_kdf_digest_check: FipsOption::default(),
            ecdh_cofactor_check: FipsOption::default(),
            hkdf_key_check: FipsOption::default(),
            kbkdf_key_check: FipsOption::default(),
            tls1_prf_key_check: FipsOption::default(),
            sshkdf_digest_check: FipsOption::default(),
            sshkdf_key_check: FipsOption::default(),
            sskdf_digest_check: FipsOption::default(),
            sskdf_key_check: FipsOption::default(),
            x963kdf_key_check: FipsOption::default(),
            x942kdf_key_check: FipsOption::default(),
            rsa_sign_pss_check: FipsOption::default(),
        }
    }
}

// =============================================================================
// FipsGlobal — Provider Global State (fipsprov.c lines 97–109)
// =============================================================================

/// Central state for the FIPS provider module.
///
/// Holds provider metadata, self-test configuration, indicator parameters, and
/// the deferred-test serialization lock. An instance is created during
/// [`initialize()`] and shared (via `Arc`) across all algorithm dispatch contexts.
///
/// **Rule R7:** `deferred_lock` carries a `// LOCK-SCOPE:` annotation.
///
/// # C Mapping
///
/// ```c
/// typedef struct fips_global_st {
///     const OSSL_CORE_HANDLE *handle;
///     SELF_TEST_POST_PARAMS selftest_params;
///     OSSL_FIPS_PARAM(/* 27 fields via .inc */)
///     CRYPTO_RWLOCK *deferred_lock;
/// } FIPS_GLOBAL;
/// ```
#[derive(Debug)]
pub struct FipsGlobal {
    /// Provider display name (e.g., `"OpenSSL FIPS Provider"`).
    pub name: String,
    /// Provider version string (e.g., `"4.0.0"`).
    pub version: String,
    /// Build information string.
    pub build_info: String,
    /// Self-test parameters: module filename, checksums, and deferred flag.
    pub selftest_params: SelfTestPostParams,
    /// All 27 FIPS indicator configuration parameters.
    pub indicator_config: FipsIndicatorConfig,
    // LOCK-SCOPE: deferred_lock guards deferred self-test state to prevent concurrent
    // test execution. Write-locked during test execution in run_deferred_test(),
    // read-locked for state checks. One lock for the entire deferred test queue is
    // appropriate because deferred tests have ordering dependencies and must not run
    // concurrently. Contention is minimal: tests run once on first use and then the
    // lock is only read-checked thereafter.
    /// Read-write lock serializing deferred self-test execution.
    pub deferred_lock: RwLock<()>,
}

impl FipsGlobal {
    /// Creates a new `FipsGlobal` with default values.
    fn new() -> Self {
        Self {
            name: String::from("OpenSSL FIPS Provider"),
            version: String::from("4.0.0"),
            build_info: String::from("OpenSSL FIPS Provider 4.0.0"),
            selftest_params: SelfTestPostParams::default(),
            indicator_config: FipsIndicatorConfig::default(),
            deferred_lock: RwLock::new(()),
        }
    }

    /// Resets the provider to the `Init` state and clears resources.
    ///
    /// Called during provider teardown (fipsprov.c lines 769–775).
    pub fn teardown(&mut self) {
        debug!("FIPS provider teardown initiated");
        state::set_fips_state(FipsState::Init);
        self.selftest_params = SelfTestPostParams::default();
        info!("FIPS provider teardown complete, state reset to Init");
    }

    // =========================================================================
    // Config Accessor Methods — 27 FIPS Indicator Checks (fipsprov.c lines 1267–1275)
    // =========================================================================
    //
    // Each method corresponds to one C `ossl_fips_config_<name>()` function
    // generated by the `.inc` macro expansion.

    /// Returns `true` if the master security-checks switch is enabled.
    pub fn config_security_checks(&self) -> bool {
        self.indicator_config.security_checks.enabled
    }

    /// Returns `true` if the TLS 1.x PRF EMS check is enabled.
    pub fn config_tls1_prf_ems_check(&self) -> bool {
        self.indicator_config.tls1_prf_ems_check.enabled
    }

    /// Returns `true` if the short-MAC output check is enabled.
    pub fn config_no_short_mac(&self) -> bool {
        self.indicator_config.no_short_mac.enabled
    }

    /// Returns `true` if the HMAC key-length check is enabled.
    pub fn config_hmac_key_check(&self) -> bool {
        self.indicator_config.hmac_key_check.enabled
    }

    /// Returns `true` if the KEM key-size check is enabled.
    pub fn config_kem_key_check(&self) -> bool {
        self.indicator_config.kem_key_check.enabled
    }

    /// Returns `true` if the KMAC key-length check is enabled.
    pub fn config_kmac_key_check(&self) -> bool {
        self.indicator_config.kmac_key_check.enabled
    }

    /// Returns `true` if the DSA key-parameter check is enabled.
    pub fn config_dsa_key_check(&self) -> bool {
        self.indicator_config.dsa_key_check.enabled
    }

    /// Returns `true` if the 3DES key check is enabled.
    pub fn config_tdes_key_check(&self) -> bool {
        self.indicator_config.tdes_key_check.enabled
    }

    /// Returns `true` if the RSA minimum key-size check is enabled.
    pub fn config_rsa_key_check(&self) -> bool {
        self.indicator_config.rsa_key_check.enabled
    }

    /// Returns `true` if the DHX key-parameter check is enabled.
    pub fn config_dhx_key_check(&self) -> bool {
        self.indicator_config.dhx_key_check.enabled
    }

    /// Returns `true` if the EC key-curve check is enabled.
    pub fn config_ec_key_check(&self) -> bool {
        self.indicator_config.ec_key_check.enabled
    }

    /// Returns `true` if the PKCS#12 key-generation check is enabled.
    pub fn config_pkcs12_key_gen_check(&self) -> bool {
        self.indicator_config.pkcs12_key_gen_check.enabled
    }

    /// Returns `true` if the X9.31 signature-padding check is enabled.
    pub fn config_sign_x931_pad_check(&self) -> bool {
        self.indicator_config.sign_x931_pad_check.enabled
    }

    /// Returns `true` if the signature-digest algorithm check is enabled.
    pub fn config_sign_digest_check(&self) -> bool {
        self.indicator_config.sign_digest_check.enabled
    }

    /// Returns `true` if the HKDF digest-algorithm check is enabled.
    pub fn config_hkdf_digest_check(&self) -> bool {
        self.indicator_config.hkdf_digest_check.enabled
    }

    /// Returns `true` if the TLS 1.3 KDF digest-algorithm check is enabled.
    pub fn config_tls13_kdf_digest_check(&self) -> bool {
        self.indicator_config.tls13_kdf_digest_check.enabled
    }

    /// Returns `true` if the ECDH cofactor-mode check is enabled.
    pub fn config_ecdh_cofactor_check(&self) -> bool {
        self.indicator_config.ecdh_cofactor_check.enabled
    }

    /// Returns `true` if the HKDF key-length check is enabled.
    pub fn config_hkdf_key_check(&self) -> bool {
        self.indicator_config.hkdf_key_check.enabled
    }

    /// Returns `true` if the KBKDF key-length check is enabled.
    pub fn config_kbkdf_key_check(&self) -> bool {
        self.indicator_config.kbkdf_key_check.enabled
    }

    /// Returns `true` if the TLS 1.x PRF key-length check is enabled.
    pub fn config_tls1_prf_key_check(&self) -> bool {
        self.indicator_config.tls1_prf_key_check.enabled
    }

    /// Returns `true` if the SSH KDF digest-algorithm check is enabled.
    pub fn config_sshkdf_digest_check(&self) -> bool {
        self.indicator_config.sshkdf_digest_check.enabled
    }

    /// Returns `true` if the SSH KDF key-length check is enabled.
    pub fn config_sshkdf_key_check(&self) -> bool {
        self.indicator_config.sshkdf_key_check.enabled
    }

    /// Returns `true` if the SSKDF digest-algorithm check is enabled.
    pub fn config_sskdf_digest_check(&self) -> bool {
        self.indicator_config.sskdf_digest_check.enabled
    }

    /// Returns `true` if the SSKDF key-length check is enabled.
    pub fn config_sskdf_key_check(&self) -> bool {
        self.indicator_config.sskdf_key_check.enabled
    }

    /// Returns `true` if the X9.63 KDF key-length check is enabled.
    pub fn config_x963kdf_key_check(&self) -> bool {
        self.indicator_config.x963kdf_key_check.enabled
    }

    /// Returns `true` if the X9.42 KDF key-length check is enabled.
    pub fn config_x942kdf_key_check(&self) -> bool {
        self.indicator_config.x942kdf_key_check.enabled
    }

    /// Returns `true` if the RSA-PSS signature-parameter check is enabled.
    pub fn config_rsa_sign_pss_check(&self) -> bool {
        self.indicator_config.rsa_sign_pss_check.enabled
    }
}

// =============================================================================
// FipsAlgorithmEntry — Algorithm Registration Record
// =============================================================================

/// A single entry in a FIPS algorithm registration table.
///
/// Corresponds to the C `OSSL_ALGORITHM` struct. Each entry maps a set of
/// algorithm names (colon-separated) to a property string and a human-readable
/// description.
///
/// # C Mapping
///
/// ```c
/// typedef struct ossl_algorithm_st {
///     const char *algorithm_names;
///     const char *property_definition;
///     const OSSL_DISPATCH *implementation;
///     const char *algorithm_description;
/// } OSSL_ALGORITHM;
/// ```
///
/// The `implementation` (dispatch table pointer) is omitted because Rust uses
/// trait-based dispatch instead of function pointer tables.
#[derive(Debug, Clone)]
pub struct FipsAlgorithmEntry {
    /// Colon-separated algorithm names (e.g., `"SHA2-256:SHA-256:SHA256"`).
    pub names: &'static str,
    /// Property query string (e.g., `"provider=fips,fips=yes"`).
    pub properties: &'static str,
    /// Human-readable description of the algorithm.
    pub description: &'static str,
}

// =============================================================================
// Callback Type Aliases (fipsprov.c lines 1277–1305)
// =============================================================================

/// Callback invoked during self-test execution to report test progress.
///
/// Parameters: `(test_type_name, test_description)` → returns `true` to continue.
pub type SelfTestCallback = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Callback invoked when a FIPS indicator check fires.
///
/// Parameters: `(algorithm_name, operation_name)` → returns `true` if approved.
pub type IndicatorCallback = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

// =============================================================================
// Algorithm Registration Tables (fipsprov.c lines 280–760)
// =============================================================================
//
// Each table is a lazily-initialized static slice of `FipsAlgorithmEntry`.
// The C code uses `OSSL_ALGORITHM[]` arrays; Rust uses `Lazy<Vec<...>>` to
// allow conditional compilation via feature flags while remaining `'static`.

/// Helper macro to reduce boilerplate when defining algorithm entries.
macro_rules! fips_alg {
    ($names:expr, $desc:expr) => {
        FipsAlgorithmEntry {
            names: $names,
            properties: FIPS_DEFAULT_PROPERTIES,
            description: $desc,
        }
    };
    ($names:expr, $props:expr, $desc:expr) => {
        FipsAlgorithmEntry {
            names: $names,
            properties: $props,
            description: $desc,
        }
    };
}

// ---------------------------------------------------------------------------
// FIPS Digests (fipsprov.c lines 280–310)
// ---------------------------------------------------------------------------

/// FIPS-approved digest (hash) algorithms.
///
/// Includes SHA-1, SHA-2 family, SHA-3 family, SHAKE, and CSHAKE.
/// SHA-1 is registered with unapproved properties per FIPS 140-3 guidance.
pub static FIPS_DIGESTS: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("SHA1:SHA-1:SSL3-SHA1", FIPS_UNAPPROVED_PROPERTIES, "SHA-1"),
        fips_alg!("SHA2-224:SHA-224:SHA224", "SHA-2 224"),
        fips_alg!("SHA2-256:SHA-256:SHA256", "SHA-2 256"),
        fips_alg!("SHA2-384:SHA-384:SHA384", "SHA-2 384"),
        fips_alg!("SHA2-512:SHA-512:SHA512", "SHA-2 512"),
        fips_alg!("SHA2-512/224:SHA-512/224:SHA512-224", "SHA-2 512/224"),
        fips_alg!("SHA2-512/256:SHA-512/256:SHA512-256", "SHA-2 512/256"),
        fips_alg!("SHA3-224", "SHA-3 224"),
        fips_alg!("SHA3-256", "SHA-3 256"),
        fips_alg!("SHA3-384", "SHA-3 384"),
        fips_alg!("SHA3-512", "SHA-3 512"),
        fips_alg!("SHAKE-128:SHAKE128", "SHAKE 128"),
        fips_alg!("SHAKE-256:SHAKE256", "SHAKE 256"),
        fips_alg!(
            "CSHAKE-128:CSHAKE128",
            FIPS_UNAPPROVED_PROPERTIES,
            "CSHAKE 128"
        ),
        fips_alg!(
            "CSHAKE-256:CSHAKE256",
            FIPS_UNAPPROVED_PROPERTIES,
            "CSHAKE 256"
        ),
    ]
});

// ---------------------------------------------------------------------------
// FIPS Ciphers (fipsprov.c lines 312–440)
// ---------------------------------------------------------------------------

/// FIPS-approved cipher algorithms.
///
/// Covers AES in all approved modes (ECB, CBC, CTS, OFB, CFB, CTR, XTS, GCM,
/// CCM, WRAP, WRAP-PAD, WRAP-INV, WRAP-PAD-INV) at 128/192/256 key sizes,
/// CBC-HMAC-SHA combinations, and 3DES (unapproved).
pub static FIPS_CIPHERS: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        // AES-256
        fips_alg!("AES-256-ECB", "AES-256-ECB"),
        fips_alg!("AES-192-ECB", "AES-192-ECB"),
        fips_alg!("AES-128-ECB", "AES-128-ECB"),
        fips_alg!("AES-256-CBC:AES256", "AES-256-CBC"),
        fips_alg!("AES-192-CBC:AES192", "AES-192-CBC"),
        fips_alg!("AES-128-CBC:AES128", "AES-128-CBC"),
        fips_alg!("AES-256-CBC-CTS", "AES-256-CBC-CTS"),
        fips_alg!("AES-192-CBC-CTS", "AES-192-CBC-CTS"),
        fips_alg!("AES-128-CBC-CTS", "AES-128-CBC-CTS"),
        fips_alg!("AES-256-OFB", "AES-256-OFB"),
        fips_alg!("AES-192-OFB", "AES-192-OFB"),
        fips_alg!("AES-128-OFB", "AES-128-OFB"),
        fips_alg!("AES-256-CFB", "AES-256-CFB"),
        fips_alg!("AES-192-CFB", "AES-192-CFB"),
        fips_alg!("AES-128-CFB", "AES-128-CFB"),
        fips_alg!("AES-256-CFB1", "AES-256-CFB1"),
        fips_alg!("AES-192-CFB1", "AES-192-CFB1"),
        fips_alg!("AES-128-CFB1", "AES-128-CFB1"),
        fips_alg!("AES-256-CFB8", "AES-256-CFB8"),
        fips_alg!("AES-192-CFB8", "AES-192-CFB8"),
        fips_alg!("AES-128-CFB8", "AES-128-CFB8"),
        fips_alg!("AES-256-CTR", "AES-256-CTR"),
        fips_alg!("AES-192-CTR", "AES-192-CTR"),
        fips_alg!("AES-128-CTR", "AES-128-CTR"),
        fips_alg!("AES-256-XTS", "AES-256-XTS"),
        fips_alg!("AES-128-XTS", "AES-128-XTS"),
        fips_alg!("AES-256-GCM:id-aes256-GCM", "AES-256-GCM"),
        fips_alg!("AES-192-GCM:id-aes192-GCM", "AES-192-GCM"),
        fips_alg!("AES-128-GCM:id-aes128-GCM", "AES-128-GCM"),
        fips_alg!("AES-256-CCM:id-aes256-CCM", "AES-256-CCM"),
        fips_alg!("AES-192-CCM:id-aes192-CCM", "AES-192-CCM"),
        fips_alg!("AES-128-CCM:id-aes128-CCM", "AES-128-CCM"),
        fips_alg!("AES-256-WRAP:id-aes256-wrap:AES256-WRAP", "AES-256-WRAP"),
        fips_alg!("AES-192-WRAP:id-aes192-wrap:AES192-WRAP", "AES-192-WRAP"),
        fips_alg!("AES-128-WRAP:id-aes128-wrap:AES128-WRAP", "AES-128-WRAP"),
        fips_alg!(
            "AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD",
            "AES-256-WRAP-PAD"
        ),
        fips_alg!(
            "AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD",
            "AES-192-WRAP-PAD"
        ),
        fips_alg!(
            "AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD",
            "AES-128-WRAP-PAD"
        ),
        fips_alg!("AES-256-WRAP-INV:AES256-WRAP-INV", "AES-256-WRAP-INV"),
        fips_alg!("AES-192-WRAP-INV:AES192-WRAP-INV", "AES-192-WRAP-INV"),
        fips_alg!("AES-128-WRAP-INV:AES128-WRAP-INV", "AES-128-WRAP-INV"),
        fips_alg!(
            "AES-256-WRAP-PAD-INV:AES256-WRAP-PAD-INV",
            "AES-256-WRAP-PAD-INV"
        ),
        fips_alg!(
            "AES-192-WRAP-PAD-INV:AES192-WRAP-PAD-INV",
            "AES-192-WRAP-PAD-INV"
        ),
        fips_alg!(
            "AES-128-WRAP-PAD-INV:AES128-WRAP-PAD-INV",
            "AES-128-WRAP-PAD-INV"
        ),
        fips_alg!(
            "AES-128-CBC-HMAC-SHA1",
            FIPS_UNAPPROVED_PROPERTIES,
            "AES-128-CBC-HMAC-SHA1"
        ),
        fips_alg!(
            "AES-256-CBC-HMAC-SHA1",
            FIPS_UNAPPROVED_PROPERTIES,
            "AES-256-CBC-HMAC-SHA1"
        ),
        fips_alg!("AES-128-CBC-HMAC-SHA256", "AES-128-CBC-HMAC-SHA256"),
        fips_alg!("AES-256-CBC-HMAC-SHA256", "AES-256-CBC-HMAC-SHA256"),
        // Triple DES — unapproved per FIPS 140-3 transition
        fips_alg!(
            "DES-EDE3-ECB:DES-EDE3",
            FIPS_UNAPPROVED_PROPERTIES,
            "DES-EDE3-ECB"
        ),
        fips_alg!(
            "DES-EDE3-CBC:DES3",
            FIPS_UNAPPROVED_PROPERTIES,
            "DES-EDE3-CBC"
        ),
    ]
});

// ---------------------------------------------------------------------------
// FIPS MACs (fipsprov.c lines 442–460)
// ---------------------------------------------------------------------------

/// FIPS-approved MAC algorithms: CMAC, GMAC, HMAC, KMAC-128, KMAC-256.
pub static FIPS_MACS: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("CMAC", "CMAC"),
        fips_alg!("GMAC", "GMAC"),
        fips_alg!("HMAC", "HMAC"),
        fips_alg!("KMAC-128:KMAC128", "KMAC-128"),
        fips_alg!("KMAC-256:KMAC256", "KMAC-256"),
    ]
});

// ---------------------------------------------------------------------------
// FIPS KDFs (fipsprov.c lines 462–502)
// ---------------------------------------------------------------------------

/// FIPS-approved Key Derivation Functions.
pub static FIPS_KDFS: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("HKDF", "HKDF"),
        fips_alg!("TLS13-KDF", "TLS13-KDF"),
        fips_alg!("PBKDF2", "PBKDF2"),
        fips_alg!("TLS1-PRF", "TLS1-PRF"),
        fips_alg!("SSKDF", "SSKDF"),
        fips_alg!("X963KDF:X942KDF-CONCAT", "X963KDF"),
        fips_alg!("X942KDF-ASN1:X942KDF", "X942KDF-ASN1"),
        fips_alg!("SNMPKDF", FIPS_UNAPPROVED_PROPERTIES, "SNMPKDF"),
        fips_alg!("SRTPKDF", FIPS_UNAPPROVED_PROPERTIES, "SRTPKDF"),
        fips_alg!("SSHKDF", "SSHKDF"),
        fips_alg!("KBKDF", "KBKDF"),
        fips_alg!("HMAC-DRBG-KDF", "HMAC-DRBG-KDF"),
    ]
});

// ---------------------------------------------------------------------------
// FIPS RANDs (fipsprov.c lines 504–520)
// ---------------------------------------------------------------------------

/// FIPS-approved random number generators and entropy sources.
pub static FIPS_RANDS: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("CRNG", "CRNG (Continuous Random Number Generator)"),
        fips_alg!("CTR-DRBG", "CTR-DRBG"),
        fips_alg!("HASH-DRBG", "HASH-DRBG"),
        fips_alg!("HMAC-DRBG", "HMAC-DRBG"),
        fips_alg!(
            "JITTER",
            FIPS_UNAPPROVED_PROPERTIES,
            "JITTER Entropy Source"
        ),
        fips_alg!(
            "TEST-RAND",
            FIPS_UNAPPROVED_PROPERTIES,
            "TEST-RAND (testing only)"
        ),
    ]
});

// ---------------------------------------------------------------------------
// FIPS Key Exchange (fipsprov.c lines 522–542)
// ---------------------------------------------------------------------------

/// FIPS-approved key exchange algorithms.
pub static FIPS_KEY_EXCHANGE: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("DH:dhKeyAgreement", "DH Key Exchange"),
        fips_alg!("ECDH", "ECDH Key Exchange"),
        fips_alg!("X25519", "X25519 Key Exchange"),
        fips_alg!("X448", "X448 Key Exchange"),
        fips_alg!(
            "TLS1-PRF",
            FIPS_UNAPPROVED_PROPERTIES,
            "TLS1-PRF Key Exchange"
        ),
        fips_alg!("HKDF", FIPS_UNAPPROVED_PROPERTIES, "HKDF Key Exchange"),
    ]
});

// ---------------------------------------------------------------------------
// FIPS Signatures (fipsprov.c lines 544–620)
// ---------------------------------------------------------------------------

/// FIPS-approved signature algorithms.
///
/// Includes DSA, RSA, `EdDSA`, ECDSA, ML-DSA (FIPS 204), HMAC/CMAC as MACs
/// used in signature context, LMS (SP 800-208), and SLH-DSA (FIPS 205,
/// all 12 parameter sets).
pub static FIPS_SIGNATURES: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("DSA", FIPS_UNAPPROVED_PROPERTIES, "DSA Signature"),
        fips_alg!("RSA:rsaEncryption", "RSA Signature"),
        fips_alg!("ED25519", FIPS_UNAPPROVED_PROPERTIES, "Ed25519 Signature"),
        fips_alg!("ED448", FIPS_UNAPPROVED_PROPERTIES, "Ed448 Signature"),
        fips_alg!("ECDSA", "ECDSA Signature"),
        fips_alg!("ML-DSA-44", "ML-DSA-44 (FIPS 204)"),
        fips_alg!("ML-DSA-65", "ML-DSA-65 (FIPS 204)"),
        fips_alg!("ML-DSA-87", "ML-DSA-87 (FIPS 204)"),
        fips_alg!("HMAC", "HMAC Signature"),
        fips_alg!("CMAC", FIPS_UNAPPROVED_PROPERTIES, "CMAC Signature"),
        fips_alg!("LMS", "LMS Signature (SP 800-208)"),
        // SLH-DSA (FIPS 205) — 12 parameter sets
        fips_alg!("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s (FIPS 205)"),
        fips_alg!("SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f (FIPS 205)"),
        fips_alg!("SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s (FIPS 205)"),
        fips_alg!("SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f (FIPS 205)"),
        fips_alg!("SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s (FIPS 205)"),
        fips_alg!("SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f (FIPS 205)"),
        fips_alg!("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s (FIPS 205)"),
        fips_alg!("SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f (FIPS 205)"),
        fips_alg!("SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s (FIPS 205)"),
        fips_alg!("SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f (FIPS 205)"),
        fips_alg!("SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s (FIPS 205)"),
        fips_alg!("SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f (FIPS 205)"),
    ]
});

// ---------------------------------------------------------------------------
// FIPS Asymmetric Cipher (fipsprov.c line 622)
// ---------------------------------------------------------------------------

/// FIPS-approved asymmetric cipher algorithms.
pub static FIPS_ASYM_CIPHER: Lazy<Vec<FipsAlgorithmEntry>> =
    Lazy::new(|| vec![fips_alg!("RSA:rsaEncryption", "RSA Asymmetric Cipher")]);

// ---------------------------------------------------------------------------
// FIPS Asymmetric KEM (fipsprov.c lines 624–650)
// ---------------------------------------------------------------------------

/// FIPS-approved Key Encapsulation Mechanisms.
///
/// Includes RSA-KEM, ML-KEM (FIPS 203) at three security levels, and
/// hybrid ML-KEM variants.
pub static FIPS_ASYM_KEM: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("RSA:rsaEncryption", "RSA KEM"),
        fips_alg!("ML-KEM-512", "ML-KEM-512 (FIPS 203)"),
        fips_alg!("ML-KEM-768", "ML-KEM-768 (FIPS 203)"),
        fips_alg!("ML-KEM-1024", "ML-KEM-1024 (FIPS 203)"),
        fips_alg!(
            "X25519MLKEM768:X25519-MLKEM768",
            FIPS_UNAPPROVED_PROPERTIES,
            "X25519-MLKEM768 Hybrid KEM"
        ),
        fips_alg!(
            "SecP256r1MLKEM768:P256-MLKEM768",
            FIPS_UNAPPROVED_PROPERTIES,
            "P256-MLKEM768 Hybrid KEM"
        ),
        fips_alg!(
            "SecP384r1MLKEM1024:P384-MLKEM1024",
            FIPS_UNAPPROVED_PROPERTIES,
            "P384-MLKEM1024 Hybrid KEM"
        ),
    ]
});

// ---------------------------------------------------------------------------
// FIPS Key Management (fipsprov.c lines 652–710)
// ---------------------------------------------------------------------------

/// FIPS-approved key management algorithms.
///
/// Each entry corresponds to a key type that the FIPS provider can generate,
/// import, export, and validate.
pub static FIPS_KEYMGMT: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("DH:dhKeyAgreement", "DH Key Management"),
        fips_alg!("DHX:X9.42 DH:dhpublicnumber", "DHX Key Management"),
        fips_alg!("DSA", FIPS_UNAPPROVED_PROPERTIES, "DSA Key Management"),
        fips_alg!("RSA:rsaEncryption", "RSA Key Management"),
        fips_alg!("RSA-PSS:RSASSA-PSS", "RSA-PSS Key Management"),
        fips_alg!("EC:id-ecPublicKey", "EC Key Management"),
        fips_alg!("X25519", "X25519 Key Management"),
        fips_alg!("X448", "X448 Key Management"),
        fips_alg!(
            "ED25519",
            FIPS_UNAPPROVED_PROPERTIES,
            "ED25519 Key Management"
        ),
        fips_alg!("ED448", FIPS_UNAPPROVED_PROPERTIES, "ED448 Key Management"),
        fips_alg!("ML-DSA-44", "ML-DSA-44 Key Management"),
        fips_alg!("ML-DSA-65", "ML-DSA-65 Key Management"),
        fips_alg!("ML-DSA-87", "ML-DSA-87 Key Management"),
        fips_alg!(
            "TLS1-PRF",
            FIPS_UNAPPROVED_PROPERTIES,
            "TLS1-PRF Key Management"
        ),
        fips_alg!("HKDF", FIPS_UNAPPROVED_PROPERTIES, "HKDF Key Management"),
        fips_alg!("HMAC", "HMAC Key Management"),
        fips_alg!("CMAC", FIPS_UNAPPROVED_PROPERTIES, "CMAC Key Management"),
        fips_alg!("LMS", "LMS Key Management"),
        fips_alg!("ML-KEM-512", "ML-KEM-512 Key Management"),
        fips_alg!("ML-KEM-768", "ML-KEM-768 Key Management"),
        fips_alg!("ML-KEM-1024", "ML-KEM-1024 Key Management"),
        fips_alg!(
            "X25519MLKEM768:X25519-MLKEM768",
            FIPS_UNAPPROVED_PROPERTIES,
            "X25519-MLKEM768 Hybrid Key Management"
        ),
        fips_alg!(
            "SecP256r1MLKEM768:P256-MLKEM768",
            FIPS_UNAPPROVED_PROPERTIES,
            "P256-MLKEM768 Hybrid Key Management"
        ),
        fips_alg!(
            "SecP384r1MLKEM1024:P384-MLKEM1024",
            FIPS_UNAPPROVED_PROPERTIES,
            "P384-MLKEM1024 Hybrid Key Management"
        ),
        // SLH-DSA key management — all 12 parameter sets
        fips_alg!("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s Key Management"),
        fips_alg!("SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f Key Management"),
        fips_alg!("SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s Key Management"),
        fips_alg!("SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f Key Management"),
        fips_alg!("SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s Key Management"),
        fips_alg!("SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f Key Management"),
        fips_alg!("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s Key Management"),
        fips_alg!("SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f Key Management"),
        fips_alg!("SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s Key Management"),
        fips_alg!("SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f Key Management"),
        fips_alg!("SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s Key Management"),
        fips_alg!("SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f Key Management"),
    ]
});

// ---------------------------------------------------------------------------
// FIPS Symmetric Key Management (fipsprov.c line 712)
// ---------------------------------------------------------------------------

/// FIPS-approved symmetric key management algorithms.
pub static FIPS_SKEYMGMT: Lazy<Vec<FipsAlgorithmEntry>> = Lazy::new(|| {
    vec![
        fips_alg!("AES", "AES Symmetric Key Management"),
        fips_alg!("GENERIC", "Generic Symmetric Key Management"),
    ]
});

// =============================================================================
// Provider Query — Algorithm Table Lookup (fipsprov.c lines 714–765)
// =============================================================================

/// Returns the FIPS algorithm table for the given operation type.
///
/// This is the central dispatch point called by the provider framework to
/// enumerate available algorithms. Returns an empty slice for operation types
/// that the FIPS provider does not support (e.g., `EncoderDecoder`).
///
/// # C Mapping
///
/// Corresponds to `fips_query()` (fipsprov.c lines 714–765), which switches
/// on `OSSL_OP_*` operation IDs and returns `OSSL_ALGORITHM[]` pointers.
///
/// # Rule R10
///
/// All algorithm table entries are reachable from this function via the
/// `OperationType` enum match. The function itself is reachable from the
/// provider dispatch table returned by [`initialize()`].
#[instrument(skip_all, fields(operation = %operation))]
pub fn query_algorithms(operation: OperationType) -> &'static [FipsAlgorithmEntry] {
    debug!("Querying FIPS algorithms for operation: {}", operation);

    let result: &[FipsAlgorithmEntry] = match operation {
        OperationType::Digest => &FIPS_DIGESTS,
        OperationType::Cipher => &FIPS_CIPHERS,
        OperationType::Mac => &FIPS_MACS,
        OperationType::Kdf => &FIPS_KDFS,
        OperationType::Rand => &FIPS_RANDS,
        OperationType::KeyMgmt => &FIPS_KEYMGMT,
        OperationType::Signature => &FIPS_SIGNATURES,
        OperationType::AsymCipher => &FIPS_ASYM_CIPHER,
        OperationType::Kem => &FIPS_ASYM_KEM,
        OperationType::KeyExch => &FIPS_KEY_EXCHANGE,
        OperationType::SKeyMgmt => &FIPS_SKEYMGMT,
        OperationType::Store | OperationType::EncoderDecoder => {
            debug!("EncoderDecoder not supported by FIPS provider");
            return &[];
        }
    };

    debug!("Returning {} algorithm entries", result.len());
    result
}

// =============================================================================
// Gettable / Get Parameters (fipsprov.c lines 166–222)
// =============================================================================

/// List of parameter names supported by the FIPS provider's `get_params` call.
///
/// This includes provider metadata (name, version, buildinfo, status) and all
/// 27 FIPS indicator configuration parameters.
static GETTABLE_PARAM_NAMES: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "name",
        "version",
        "buildinfo",
        "status",
        "security-checks",
        "tls1-prf-ems-check",
        "no-short-mac",
        "hmac-key-check",
        "kem-key-check",
        "kmac-key-check",
        "dsa-key-check",
        "tdes-key-check",
        "rsa-key-check",
        "dhx-key-check",
        "ec-key-check",
        "pkcs12-key-gen-check",
        "sign-x931-pad-check",
        "sign-digest-check",
        "hkdf-digest-check",
        "tls13-kdf-digest-check",
        "ecdh-cofactor-check",
        "hkdf-key-check",
        "kbkdf-key-check",
        "tls1-prf-key-check",
        "sshkdf-digest-check",
        "sshkdf-key-check",
        "sskdf-digest-check",
        "sskdf-key-check",
        "x963kdf-key-check",
        "x942kdf-key-check",
        "rsa-sign-pss-check",
    ]
});

/// Returns the list of parameter names that can be retrieved from the FIPS provider.
///
/// # C Mapping
///
/// Corresponds to `fips_gettable_params()` (fipsprov.c lines 166–190).
#[instrument(skip_all)]
pub fn gettable_params() -> &'static [&'static str] {
    debug!(
        "Returning {} gettable parameter names",
        GETTABLE_PARAM_NAMES.len()
    );
    &GETTABLE_PARAM_NAMES
}

/// Retrieves the current parameter values from the FIPS provider.
///
/// Returns a [`ParamSet`] containing the provider name, version, build info,
/// operational status, and all 27 indicator configuration values.
///
/// # C Mapping
///
/// Corresponds to `fips_get_params()` (fipsprov.c lines 192–222).
#[instrument(skip_all)]
pub fn get_params(global: &FipsGlobal) -> FipsResult<ParamSet> {
    debug!("Building FIPS provider parameter set");

    let current_state = state::get_fips_state();
    let status_value: i32 = i32::from(current_state.is_operational());

    let ic = &global.indicator_config;

    // ParamBuilder methods consume self and return Self (fluent pattern),
    // so we chain all pushes into one expression.
    let builder = ParamBuilder::new()
        .push_utf8("name", global.name.clone())
        .push_utf8("version", global.version.clone())
        .push_utf8("buildinfo", global.build_info.clone())
        .push_i32("status", status_value)
        // All 27 indicator config values as i32 (1=enabled, 0=disabled)
        .push_i32("security-checks", bool_to_i32(ic.security_checks.enabled))
        .push_i32(
            "tls1-prf-ems-check",
            bool_to_i32(ic.tls1_prf_ems_check.enabled),
        )
        .push_i32("no-short-mac", bool_to_i32(ic.no_short_mac.enabled))
        .push_i32("hmac-key-check", bool_to_i32(ic.hmac_key_check.enabled))
        .push_i32("kem-key-check", bool_to_i32(ic.kem_key_check.enabled))
        .push_i32("kmac-key-check", bool_to_i32(ic.kmac_key_check.enabled))
        .push_i32("dsa-key-check", bool_to_i32(ic.dsa_key_check.enabled))
        .push_i32("tdes-key-check", bool_to_i32(ic.tdes_key_check.enabled))
        .push_i32("rsa-key-check", bool_to_i32(ic.rsa_key_check.enabled))
        .push_i32("dhx-key-check", bool_to_i32(ic.dhx_key_check.enabled))
        .push_i32("ec-key-check", bool_to_i32(ic.ec_key_check.enabled))
        .push_i32(
            "pkcs12-key-gen-check",
            bool_to_i32(ic.pkcs12_key_gen_check.enabled),
        )
        .push_i32(
            "sign-x931-pad-check",
            bool_to_i32(ic.sign_x931_pad_check.enabled),
        )
        .push_i32(
            "sign-digest-check",
            bool_to_i32(ic.sign_digest_check.enabled),
        )
        .push_i32(
            "hkdf-digest-check",
            bool_to_i32(ic.hkdf_digest_check.enabled),
        )
        .push_i32(
            "tls13-kdf-digest-check",
            bool_to_i32(ic.tls13_kdf_digest_check.enabled),
        )
        .push_i32(
            "ecdh-cofactor-check",
            bool_to_i32(ic.ecdh_cofactor_check.enabled),
        )
        .push_i32("hkdf-key-check", bool_to_i32(ic.hkdf_key_check.enabled))
        .push_i32("kbkdf-key-check", bool_to_i32(ic.kbkdf_key_check.enabled))
        .push_i32(
            "tls1-prf-key-check",
            bool_to_i32(ic.tls1_prf_key_check.enabled),
        )
        .push_i32(
            "sshkdf-digest-check",
            bool_to_i32(ic.sshkdf_digest_check.enabled),
        )
        .push_i32("sshkdf-key-check", bool_to_i32(ic.sshkdf_key_check.enabled))
        .push_i32(
            "sskdf-digest-check",
            bool_to_i32(ic.sskdf_digest_check.enabled),
        )
        .push_i32("sskdf-key-check", bool_to_i32(ic.sskdf_key_check.enabled))
        .push_i32(
            "x963kdf-key-check",
            bool_to_i32(ic.x963kdf_key_check.enabled),
        )
        .push_i32(
            "x942kdf-key-check",
            bool_to_i32(ic.x942kdf_key_check.enabled),
        )
        .push_i32(
            "rsa-sign-pss-check",
            bool_to_i32(ic.rsa_sign_pss_check.enabled),
        );

    let params = builder.build();
    debug!("Built parameter set with {} entries", params.len());
    Ok(params)
}

/// Converts a `bool` to an `i32` for parameter encoding (1 = enabled, 0 = disabled).
/// Rule R6: using explicit conversion instead of `as` cast.
#[inline]
fn bool_to_i32(b: bool) -> i32 {
    i32::from(b)
}

// =============================================================================
// Provider Initialization (fipsprov.c lines 870–1086)
// =============================================================================

/// Initializes the FIPS provider module.
///
/// This is the primary entry point, corresponding to `OSSL_provider_init_int()`
/// in the C implementation. It:
///
/// 1. Creates a [`FipsGlobal`] instance with default values.
/// 2. Extracts self-test parameters from the provided config [`ParamSet`].
/// 3. Extracts all 27 indicator configuration parameters.
/// 4. Transitions the module state to `SelfTesting`.
/// 5. Executes the Power-On Self-Test via [`crate::kats::run_all_kats()`].
/// 6. Transitions to `Running` on success or `Error` on failure.
///
/// # Errors
///
/// Returns `FipsError::SelfTestFailed` if the POST fails, or
/// `FipsError::NotOperational` if the module is already in an error state.
///
/// # Rule R10 (Wiring)
///
/// Caller chain: `openssl_fips::lib → provider::initialize()`.
/// All dispatch tables are reachable via `query_algorithms()`.
#[instrument(skip_all)]
pub fn initialize(config: &ParamSet) -> FipsResult<FipsGlobal> {
    info!("FIPS provider initialization starting");

    // Verify module is not already in an error state
    let current_state = state::get_fips_state();
    if current_state == FipsState::Error {
        error!("FIPS provider already in Error state, cannot reinitialize");
        return Err(FipsError::NotOperational(
            "FIPS module is in an error state and cannot be reinitialized".into(),
        ));
    }

    let mut global = FipsGlobal::new();

    // ---- Extract self-test params from config ----
    extract_selftest_params(config, &mut global.selftest_params);

    // ---- Extract indicator config params from config ----
    extract_indicator_config(config, &mut global.indicator_config)?;

    // ---- Integrity verification ----
    // Verify that checksum data is present when module filename is specified.
    // This mirrors the integrity check in C fipsprov.c where module_checksum_data
    // must be non-NULL when module_filename is provided.
    if global.selftest_params.module_filename.is_some()
        && global.selftest_params.module_checksum_data.is_none()
    {
        state::set_fips_state(FipsState::Error);
        error!("FIPS integrity check failed: module filename set but checksum data missing");
        return Err(FipsError::IntegrityCheckFailed);
    }

    // ---- Transition to SelfTesting ----
    state::set_fips_state(FipsState::SelfTesting);
    debug!("FIPS module state: SelfTesting");

    // ---- Execute POST (Power-On Self-Test) ----
    if global.selftest_params.is_deferred_test {
        info!("FIPS self-tests deferred to first algorithm use");
        // Mark all tests as deferred — they will run on first access
        state::set_fips_state(FipsState::Running);
    } else {
        match kats::run_all_kats() {
            Ok(()) => {
                state::set_fips_state(FipsState::Running);
                info!("FIPS provider initialized successfully — POST passed");
            }
            Err(e) => {
                state::set_fips_state(FipsState::Error);
                error!("FIPS provider initialization failed: POST error: {e}");
                return Err(FipsError::SelfTestFailed(format!(
                    "Power-On Self-Test failed: {e}"
                )));
            }
        }
    }

    Ok(global)
}

/// Extracts self-test parameters from the config [`ParamSet`] into
/// [`SelfTestPostParams`].
///
/// Reads optional string values for module filename, checksum data, indicator
/// checksum data, and conditional error check. Missing keys are silently
/// ignored (the fields remain `None` per Rule R5).
///
/// Uses [`ParamSet::contains()`] for existence checks before extraction, and
/// [`ParamValue::as_str()`] / [`ParamValue::as_i32()`] accessors for typed
/// extraction alongside pattern matching.
fn extract_selftest_params(config: &ParamSet, params: &mut SelfTestPostParams) {
    if config.contains("module-filename") {
        if let Some(val) = config.get("module-filename") {
            if let Some(s) = val.as_str() {
                params.module_filename = Some(s.to_owned());
            }
        }
    }
    if config.contains("module-checksum-data") {
        if let Some(val) = config.get("module-checksum-data") {
            if let Some(s) = val.as_str() {
                params.module_checksum_data = Some(s.to_owned());
            }
        }
    }
    if config.contains("indicator-checksum-data") {
        if let Some(val) = config.get("indicator-checksum-data") {
            if let Some(s) = val.as_str() {
                params.indicator_checksum_data = Some(s.to_owned());
            }
        }
    }
    if config.contains("conditional-error-check") {
        if let Some(val) = config.get("conditional-error-check") {
            if let Some(s) = val.as_str() {
                params.conditional_error_check = Some(s.to_owned());
            }
        }
    }
    if config.contains("is-deferred-test") {
        if let Some(val) = config.get("is-deferred-test") {
            if let Some(i) = val.as_i32() {
                params.is_deferred_test = i != 0;
            }
        }
    }
    debug!(
        "Self-test params extracted: filename={:?}, deferred={}",
        params.module_filename, params.is_deferred_test
    );
}

/// Extracts all 27 FIPS indicator configuration parameters from the config
/// [`ParamSet`] into [`FipsIndicatorConfig`].
///
/// For each indicator, if the key is present in the config as a `Utf8String`,
/// its value is stored in the option and `apply_config()` sets the enabled flag.
fn extract_indicator_config(
    config: &ParamSet,
    indicator: &mut FipsIndicatorConfig,
) -> FipsResult<()> {
    extract_single_indicator(config, "security-checks", &mut indicator.security_checks)?;
    extract_single_indicator(
        config,
        "tls1-prf-ems-check",
        &mut indicator.tls1_prf_ems_check,
    )?;
    extract_single_indicator(config, "no-short-mac", &mut indicator.no_short_mac)?;
    extract_single_indicator(config, "hmac-key-check", &mut indicator.hmac_key_check)?;
    extract_single_indicator(config, "kem-key-check", &mut indicator.kem_key_check)?;
    extract_single_indicator(config, "kmac-key-check", &mut indicator.kmac_key_check)?;
    extract_single_indicator(config, "dsa-key-check", &mut indicator.dsa_key_check)?;
    extract_single_indicator(config, "tdes-key-check", &mut indicator.tdes_key_check)?;
    extract_single_indicator(config, "rsa-key-check", &mut indicator.rsa_key_check)?;
    extract_single_indicator(config, "dhx-key-check", &mut indicator.dhx_key_check)?;
    extract_single_indicator(config, "ec-key-check", &mut indicator.ec_key_check)?;
    extract_single_indicator(
        config,
        "pkcs12-key-gen-check",
        &mut indicator.pkcs12_key_gen_check,
    )?;
    extract_single_indicator(
        config,
        "sign-x931-pad-check",
        &mut indicator.sign_x931_pad_check,
    )?;
    extract_single_indicator(
        config,
        "sign-digest-check",
        &mut indicator.sign_digest_check,
    )?;
    extract_single_indicator(
        config,
        "hkdf-digest-check",
        &mut indicator.hkdf_digest_check,
    )?;
    extract_single_indicator(
        config,
        "tls13-kdf-digest-check",
        &mut indicator.tls13_kdf_digest_check,
    )?;
    extract_single_indicator(
        config,
        "ecdh-cofactor-check",
        &mut indicator.ecdh_cofactor_check,
    )?;
    extract_single_indicator(config, "hkdf-key-check", &mut indicator.hkdf_key_check)?;
    extract_single_indicator(config, "kbkdf-key-check", &mut indicator.kbkdf_key_check)?;
    extract_single_indicator(
        config,
        "tls1-prf-key-check",
        &mut indicator.tls1_prf_key_check,
    )?;
    extract_single_indicator(
        config,
        "sshkdf-digest-check",
        &mut indicator.sshkdf_digest_check,
    )?;
    extract_single_indicator(config, "sshkdf-key-check", &mut indicator.sshkdf_key_check)?;
    extract_single_indicator(
        config,
        "sskdf-digest-check",
        &mut indicator.sskdf_digest_check,
    )?;
    extract_single_indicator(config, "sskdf-key-check", &mut indicator.sskdf_key_check)?;
    extract_single_indicator(
        config,
        "x963kdf-key-check",
        &mut indicator.x963kdf_key_check,
    )?;
    extract_single_indicator(
        config,
        "x942kdf-key-check",
        &mut indicator.x942kdf_key_check,
    )?;
    extract_single_indicator(
        config,
        "rsa-sign-pss-check",
        &mut indicator.rsa_sign_pss_check,
    )?;

    debug!("All 27 FIPS indicator config parameters extracted");
    Ok(())
}

/// Extracts a single indicator configuration parameter from the config.
///
/// Accepts `Utf8String` or `Int32` parameter values. For `Int32` values, uses
/// [`ParamValue::as_i32()`] accessor for typed extraction. Unrecognized types
/// produce a `FipsError::Common` error.
fn extract_single_indicator(config: &ParamSet, key: &str, opt: &mut FipsOption) -> FipsResult<()> {
    if let Some(val) = config.get(key) {
        match val {
            ParamValue::Utf8String(s) => {
                opt.option = Some(s.clone());
                opt.apply_config()?;
            }
            _ => {
                // Use the typed accessor as_i32() for numeric params
                if let Some(i) = val.as_i32() {
                    opt.option = Some(i.to_string());
                    opt.enabled = i != 0;
                } else {
                    warn!(
                        "Unexpected parameter type for FIPS indicator '{}': {}",
                        key,
                        val.param_type_name()
                    );
                    return Err(FipsError::Common(
                        openssl_common::error::CommonError::InvalidArgument(format!(
                            "Unsupported parameter type for FIPS indicator config key '{key}'"
                        )),
                    ));
                }
            }
        }
    }
    Ok(())
}

// =============================================================================
// Internal Provider Init (fipsprov.c lines 1088–1130)
// =============================================================================

/// Internal initialization for recursive EVP calls within the FIPS module.
///
/// Unlike [`initialize()`], this does not run the POST or extract configuration
/// parameters. It verifies the module is already operational and returns success,
/// allowing internal algorithm fetches to proceed without re-initialization.
///
/// # C Mapping
///
/// Corresponds to `ossl_fips_intern_provider_init()` (fipsprov.c lines 1096–1130).
///
/// # Errors
///
/// Returns `FipsError::NotOperational` if the module is not in the `Running` state.
#[instrument(skip_all)]
pub fn initialize_internal() -> FipsResult<()> {
    let current_state = state::get_fips_state();
    debug!("Internal FIPS init — current state: {:?}", current_state);

    if current_state.is_operational() {
        debug!("FIPS module is operational — internal init succeeds");
        Ok(())
    } else {
        error!(
            "FIPS module not operational for internal init (state: {:?})",
            current_state
        );
        Err(FipsError::NotOperational(format!(
            "FIPS module in {current_state:?} state, not operational for internal dispatch"
        )))
    }
}

// =============================================================================
// Deferred Test Infrastructure (fipsprov.c lines 1307–1498)
// =============================================================================

/// Acquires the deferred self-test write lock.
///
/// Returns a [`RwLockWriteGuard`] that must be released by calling
/// [`unlock_deferred()`] (or by dropping the guard). While held, no other
/// thread can execute or check deferred tests.
///
/// # LOCK-SCOPE
///
/// The `deferred_lock` serializes deferred self-test execution, preventing
/// concurrent test runs. This write lock is only acquired during actual test
/// execution (not during fast-path state checks).
///
/// # C Mapping
///
/// Corresponds to `SELF_TEST_lock_deferred()` (fipsprov.c lines 1309–1320).
#[instrument(skip_all)]
pub fn lock_deferred(global: &FipsGlobal) -> FipsResult<RwLockWriteGuard<'_, ()>> {
    debug!("Acquiring deferred self-test write lock");
    // LOCK-SCOPE: deferred_lock serializes deferred self-test execution,
    // preventing concurrent test runs that could cause data races on test state.
    let guard = global.deferred_lock.write();
    debug!("Deferred self-test write lock acquired");
    Ok(guard)
}

/// Releases the deferred self-test write lock.
///
/// This is a convenience function for symmetry with [`lock_deferred()`].
/// The guard can also be dropped directly.
///
/// # C Mapping
///
/// Corresponds to `SELF_TEST_unlock_deferred()` (fipsprov.c lines 1322–1337).
pub fn unlock_deferred(guard: RwLockWriteGuard<'_, ()>) {
    drop(guard);
    debug!("Deferred self-test write lock released");
}

/// Executes a deferred self-test for the specified test ID.
///
/// This function implements the double-check locking pattern from the C code:
///
/// 1. **Fast path:** Read the test state. If already passed/implicit, return Ok.
/// 2. **Slow path:** Acquire write lock, re-check state, execute test if needed.
/// 3. **Error handling:** On failure, transition the module to `Error` state.
///
/// Deferred tests enable lazy KAT execution on first algorithm use, improving
/// startup time when `is_deferred_test` is set.
///
/// # Arguments
///
/// - `global` — The FIPS provider global state, used for the deferred lock.
/// - `test_id` — Zero-based index into the test definition array.
///
/// # Errors
///
/// Returns `FipsError::SelfTestFailed` if the test fails, or
/// `FipsError::NotOperational` if the module is in an error state.
///
/// # C Mapping
///
/// Corresponds to `ossl_deferred_self_test()` (fipsprov.c lines 1464–1498) with
/// the inner `FIPS_kat_deferred()` (fipsprov.c lines 1339–1462).
#[instrument(skip(global), fields(test_id = test_id))]
pub fn run_deferred_test(global: &FipsGlobal, test_id: usize) -> FipsResult<()> {
    // TSAN-safe fast path: read module state directly from the atomic
    // (fipsprov.c line 1466: reads FIPS_state without lock first)
    let raw_state = FIPS_MODULE_STATE.load(Ordering::Acquire);
    let module_state = FipsState::from_u8(raw_state);
    if module_state == Some(FipsState::Error) {
        return Err(FipsError::NotOperational(
            "FIPS module in error state, cannot run deferred test".into(),
        ));
    }

    // Acquire a read lock for the fast-path state check to ensure consistency
    // with any concurrent test completion.
    // LOCK-SCOPE: deferred_lock read guard ensures test state reads are
    // consistent with concurrent test executions completing under write lock.
    {
        let _read_guard = global.deferred_lock.read();
        debug!("Fast-path read lock acquired for deferred test {}", test_id);
    }

    // ---- Fast path: check if already completed (no lock) ----
    match state::get_test_state(test_id) {
        Some(ts) if ts.is_complete() && ts.is_success() => {
            debug!("Deferred test {} already passed (fast path)", test_id);
            return Ok(());
        }
        Some(TestState::Failed) => {
            return Err(FipsError::SelfTestFailed(format!(
                "Deferred test {test_id} previously failed"
            )));
        }
        // None (test_id out of range) or not yet started/in progress — proceed to slow path
        _ => {}
    }

    // ---- Slow path: acquire write lock and double-check ----
    // LOCK-SCOPE: deferred_lock serializes deferred self-test execution,
    // preventing concurrent test runs.
    let _guard = lock_deferred(global)?;

    // Re-check under lock (double-check locking pattern)
    match state::get_test_state(test_id) {
        Some(ts) if ts.is_complete() && ts.is_success() => {
            debug!("Deferred test {} already passed (slow path)", test_id);
            return Ok(());
        }
        Some(TestState::Failed) => {
            return Err(FipsError::SelfTestFailed(format!(
                "Deferred test {test_id} previously failed"
            )));
        }
        _ => {}
    }

    debug!("Executing deferred test {test_id}");

    // Mark test as in-progress
    state::set_test_state(test_id, TestState::InProgress);

    // Look up the test definition and execute
    let all_tests = &*kats::ALL_TESTS;
    if test_id >= all_tests.len() {
        let max_len = all_tests.len();
        let msg = format!("Deferred test ID {test_id} out of range (max {max_len})");
        error!("{}", msg);
        state::set_test_state(test_id, TestState::Failed);
        state::set_fips_state(FipsState::Error);
        return Err(FipsError::SelfTestFailed(msg));
    }

    let test_def = &all_tests[test_id];

    match kats::execute_single_test(test_def) {
        Ok(()) => {
            debug!(
                "Deferred test {} ({}) passed",
                test_id, test_def.description
            );

            // Propagate implicit success to dependent tests.
            // In the C code, `FIPS_kat_deferred` marks depended-upon tests
            // as implicitly passed when a higher-level test succeeds.
            propagate_implicit_results(all_tests, test_id);

            Ok(())
        }
        Err(e) => {
            error!(
                "Deferred test {} ({}) FAILED: {}",
                test_id, test_def.description, e
            );
            state::set_test_state(test_id, TestState::Failed);
            state::set_fips_state(FipsState::Error);
            Err(FipsError::SelfTestFailed(format!(
                "Deferred test '{}' failed: {}",
                test_def.description, e
            )))
        }
    }
}

/// Propagates implicit pass results to dependent tests.
///
/// When a test succeeds, any tests that depend on it (via the `depends_on` field
/// in [`kats::TestDefinition`]) and are still in the `Deferred` or `Init` state
/// can be marked as implicitly passed, avoiding redundant execution.
///
/// This mirrors the C `FIPS_kat_deferred()` implicit marking at fipsprov.c
/// lines 1410–1440.
fn propagate_implicit_results(all_tests: &[kats::TestDefinition], passed_id: usize) {
    for (idx, test) in all_tests.iter().enumerate() {
        if idx == passed_id {
            continue;
        }
        // If this test depends on the test that just passed, and it is still
        // waiting (Deferred or Init), mark it as implicitly passed.
        if test.depends_on.contains(&passed_id) {
            if let Some(dep_state) = state::get_test_state(idx) {
                if dep_state == TestState::Deferred || dep_state == TestState::Init {
                    debug!(
                        "Marking test {} ({}) as implicitly passed (dependency on {})",
                        idx, test.description, passed_id
                    );
                    state::set_test_state(idx, TestState::Implicit);
                }
            }
        }
    }
}

// =============================================================================
// Shared Provider Handle (Thread-Safe Reference)
// =============================================================================

/// Creates a thread-safe shared reference to the FIPS global state.
///
/// Returns an `Arc<FipsGlobal>` that can be cloned and distributed to multiple
/// algorithm dispatch contexts running on different threads. This is the
/// recommended way to share the provider state after initialization.
///
/// # C Mapping
///
/// In C, `FIPS_GLOBAL` is stored via `ossl_lib_ctx_get_data()` with
/// reference-counted access. In Rust, `Arc` provides the equivalent
/// thread-safe reference counting.
pub fn make_shared(global: FipsGlobal) -> Arc<FipsGlobal> {
    let shared = Arc::new(global);
    debug!(
        "Created shared FipsGlobal handle (strong_count={})",
        Arc::strong_count(&shared)
    );
    shared
}

/// Clones a shared reference to the FIPS provider state.
///
/// This is a thin wrapper around `Arc::clone()` that adds tracing.
pub fn clone_shared(handle: &Arc<FipsGlobal>) -> Arc<FipsGlobal> {
    let cloned = Arc::clone(handle);
    debug!(
        "Cloned shared FipsGlobal handle (strong_count={})",
        Arc::strong_count(&cloned)
    );
    cloned
}

// =============================================================================
// FIPS Indicator Integration
// =============================================================================

/// Creates a new FIPS indicator instance for use in algorithm contexts.
///
/// The indicator tracks whether the current operation is FIPS-approved and
/// delegates to the global indicator configuration for enforcement behavior.
///
/// # Example
///
/// ```ignore
/// let indicator = create_indicator();
/// if !indicator.is_approved() {
///     indicator.on_unapproved(0, "SHA1", "digest", || global.config_security_checks())?;
/// }
/// ```
pub fn create_indicator() -> FipsIndicator {
    FipsIndicator::new()
}

/// Checks whether the given algorithm operation is FIPS-approved using the
/// provider's indicator configuration.
///
/// Combines the global security-checks flag with the per-algorithm indicator
/// to determine if the operation should proceed.
///
/// # Arguments
///
/// - `global` — FIPS provider global state with indicator configuration.
/// - `indicator` — The per-operation FIPS indicator.
/// - `settable_id` — The settable slot ID for the operation's check category.
/// - `algorithm` — Algorithm name for diagnostic reporting.
/// - `operation` — Operation name for diagnostic reporting.
///
/// # Returns
///
/// `Ok(true)` if approved, `Ok(false)` if unapproved in tolerant mode, or
/// `Err(FipsError::NotApproved)` if unapproved in strict mode.
pub fn check_indicator(
    global: &FipsGlobal,
    indicator: &mut FipsIndicator,
    settable_id: usize,
    algorithm: &str,
    operation: &str,
) -> FipsResult<bool> {
    if indicator.is_approved() {
        return Ok(true);
    }

    // Delegate to the indicator's on_unapproved handler, passing the
    // global security-checks config as the config closure.
    let security_checks_enabled = global.config_security_checks();
    indicator.on_unapproved(settable_id, algorithm, operation, || {
        security_checks_enabled
    })
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::redundant_closure_for_method_calls
)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Coordination lock for tests that modify the global `FipsState`.
    ///
    /// Multiple tests (`test_get_params`, `test_get_params_not_operational`,
    /// `test_initialize_internal_*`) concurrently set the FIPS module state
    /// to conflicting values.  Holding this lock prevents interleaving.
    static FIPS_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_fips_option_default() {
        let opt = FipsOption::default();
        assert!(opt.enabled);
        assert!(opt.option.is_none());
    }

    #[test]
    fn test_fips_option_apply_config_enable() {
        let mut opt = FipsOption {
            option: Some("1".into()),
            enabled: false,
        };
        opt.apply_config().expect("apply_config should succeed");
        assert!(opt.enabled);
    }

    #[test]
    fn test_fips_option_apply_config_disable() {
        let mut opt = FipsOption {
            option: Some("0".into()),
            enabled: true,
        };
        opt.apply_config().expect("apply_config should succeed");
        assert!(!opt.enabled);
    }

    #[test]
    fn test_fips_option_apply_config_invalid() {
        let mut opt = FipsOption {
            option: Some("maybe".into()),
            enabled: true,
        };
        assert!(opt.apply_config().is_err());
    }

    #[test]
    fn test_fips_indicator_config_default() {
        let cfg = FipsIndicatorConfig::default();
        assert!(cfg.security_checks.enabled);
        assert!(cfg.rsa_sign_pss_check.enabled);
        assert!(cfg.tls1_prf_ems_check.enabled);
        assert!(cfg.x942kdf_key_check.enabled);
    }

    #[test]
    fn test_fips_global_new() {
        let g = FipsGlobal::new();
        assert_eq!(g.name, "OpenSSL FIPS Provider");
        assert_eq!(g.version, "4.0.0");
        assert!(g.selftest_params.module_filename.is_none());
        assert!(g.indicator_config.security_checks.enabled);
    }

    #[test]
    fn test_fips_global_config_accessors() {
        let g = FipsGlobal::new();
        assert!(g.config_security_checks());
        assert!(g.config_tls1_prf_ems_check());
        assert!(g.config_no_short_mac());
        assert!(g.config_hmac_key_check());
        assert!(g.config_rsa_key_check());
        assert!(g.config_rsa_sign_pss_check());
    }

    #[test]
    fn test_fips_global_teardown() {
        // Reset state before test
        state::set_fips_state(FipsState::Running);
        let mut g = FipsGlobal::new();
        g.selftest_params.module_filename = Some("/path/to/module".into());
        g.teardown();
        assert_eq!(state::get_fips_state(), FipsState::Init);
        assert!(g.selftest_params.module_filename.is_none());
    }

    #[test]
    fn test_selftest_post_params_default() {
        let p = SelfTestPostParams::default();
        assert!(p.module_filename.is_none());
        assert!(p.module_checksum_data.is_none());
        assert!(p.indicator_checksum_data.is_none());
        assert!(p.conditional_error_check.is_none());
        assert!(!p.is_deferred_test);
    }

    #[test]
    fn test_fips_algorithm_entry_structure() {
        let entry = FipsAlgorithmEntry {
            names: "SHA2-256:SHA-256:SHA256",
            properties: FIPS_DEFAULT_PROPERTIES,
            description: "SHA-2 256",
        };
        assert!(entry.names.contains("SHA256"));
        assert!(entry.properties.contains("fips=yes"));
    }

    #[test]
    fn test_fips_digests_table() {
        let digests = &*FIPS_DIGESTS;
        assert!(digests.len() >= 15, "Expected at least 15 digest entries");
        // SHA-1 should be unapproved
        let sha1 = digests
            .iter()
            .find(|e| e.names.contains("SHA1"))
            .expect("SHA1 entry");
        assert!(sha1.properties.contains("fips=no"));
        // SHA-256 should be approved
        let sha256 = digests
            .iter()
            .find(|e| e.names.contains("SHA2-256"))
            .expect("SHA2-256 entry");
        assert!(sha256.properties.contains("fips=yes"));
    }

    #[test]
    fn test_fips_ciphers_table() {
        let ciphers = &*FIPS_CIPHERS;
        assert!(ciphers.len() >= 40, "Expected at least 40 cipher entries");
        // AES-256-GCM should be approved
        let gcm = ciphers
            .iter()
            .find(|e| e.names.contains("AES-256-GCM"))
            .expect("AES-256-GCM");
        assert!(gcm.properties.contains("fips=yes"));
        // 3DES should be unapproved
        let tdes = ciphers
            .iter()
            .find(|e| e.names.contains("DES-EDE3-ECB"))
            .expect("3DES entry");
        assert!(tdes.properties.contains("fips=no"));
    }

    #[test]
    fn test_fips_macs_table() {
        let macs = &*FIPS_MACS;
        assert_eq!(macs.len(), 5);
        assert!(macs.iter().any(|e| e.names.contains("HMAC")));
    }

    #[test]
    fn test_fips_kdfs_table() {
        let kdfs = &*FIPS_KDFS;
        assert!(kdfs.len() >= 10);
        assert!(kdfs.iter().any(|e| e.names.contains("HKDF")));
        assert!(kdfs.iter().any(|e| e.names.contains("PBKDF2")));
    }

    #[test]
    fn test_fips_rands_table() {
        let rands = &*FIPS_RANDS;
        assert!(rands.len() >= 4);
        assert!(rands.iter().any(|e| e.names.contains("CTR-DRBG")));
    }

    #[test]
    fn test_fips_signatures_table() {
        let sigs = &*FIPS_SIGNATURES;
        assert!(sigs.len() >= 20, "Expected ML-DSA + SLH-DSA entries");
        assert!(sigs.iter().any(|e| e.names.contains("ML-DSA-44")));
        assert!(sigs.iter().any(|e| e.names.contains("SLH-DSA-SHA2-128s")));
    }

    #[test]
    fn test_fips_asym_kem_table() {
        let kems = &*FIPS_ASYM_KEM;
        assert!(kems.len() >= 4);
        assert!(kems.iter().any(|e| e.names.contains("ML-KEM-768")));
    }

    #[test]
    fn test_fips_keymgmt_table() {
        let km = &*FIPS_KEYMGMT;
        assert!(km.len() >= 20);
        assert!(km.iter().any(|e| e.names.contains("RSA")));
        assert!(km.iter().any(|e| e.names.contains("EC")));
        assert!(km.iter().any(|e| e.names.contains("ML-KEM-1024")));
    }

    #[test]
    fn test_fips_skeymgmt_table() {
        let skm = &*FIPS_SKEYMGMT;
        assert_eq!(skm.len(), 2);
        assert!(skm.iter().any(|e| e.names.contains("AES")));
    }

    #[test]
    fn test_query_algorithms_digest() {
        let result = query_algorithms(OperationType::Digest);
        assert!(!result.is_empty());
        assert!(result.iter().any(|e| e.names.contains("SHA2-256")));
    }

    #[test]
    fn test_query_algorithms_cipher() {
        let result = query_algorithms(OperationType::Cipher);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_query_algorithms_encoder_decoder_unsupported() {
        let result = query_algorithms(OperationType::EncoderDecoder);
        assert!(result.is_empty());
    }

    #[test]
    fn test_query_algorithms_all_operations() {
        // Every supported operation should return a non-empty table
        let ops = [
            OperationType::Digest,
            OperationType::Cipher,
            OperationType::Mac,
            OperationType::Kdf,
            OperationType::Rand,
            OperationType::KeyMgmt,
            OperationType::Signature,
            OperationType::AsymCipher,
            OperationType::Kem,
            OperationType::KeyExch,
            OperationType::SKeyMgmt,
        ];
        for op in &ops {
            let result = query_algorithms(*op);
            assert!(
                !result.is_empty(),
                "Expected non-empty results for {:?}",
                op
            );
        }

        // Store and EncoderDecoder should return empty slices for FIPS
        assert!(
            query_algorithms(OperationType::Store).is_empty(),
            "FIPS provider should not supply Store operations"
        );
        assert!(
            query_algorithms(OperationType::EncoderDecoder).is_empty(),
            "FIPS provider should not supply EncoderDecoder operations"
        );
    }

    #[test]
    fn test_gettable_params_length() {
        let params = gettable_params();
        // 4 metadata + 27 indicator params = 31
        assert_eq!(params.len(), 31);
        assert!(params.contains(&"name"));
        assert!(params.contains(&"version"));
        assert!(params.contains(&"security-checks"));
        assert!(params.contains(&"rsa-sign-pss-check"));
    }

    #[test]
    fn test_get_params() {
        let _lock = FIPS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state::set_fips_state(FipsState::Running);
        let g = FipsGlobal::new();
        let params = get_params(&g).expect("get_params should succeed");

        // Check metadata
        assert_eq!(
            params.get("name"),
            Some(&ParamValue::Utf8String("OpenSSL FIPS Provider".into()))
        );
        assert_eq!(
            params.get("version"),
            Some(&ParamValue::Utf8String("4.0.0".into()))
        );
        // Status should be 1 (running)
        assert_eq!(params.get("status"), Some(&ParamValue::Int32(1)));
        // Indicator config should be present
        assert_eq!(params.get("security-checks"), Some(&ParamValue::Int32(1)));
    }

    #[test]
    fn test_get_params_not_operational() {
        let _lock = FIPS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state::set_fips_state(FipsState::Init);
        let g = FipsGlobal::new();
        let params = get_params(&g).expect("get_params should succeed even when not running");
        assert_eq!(params.get("status"), Some(&ParamValue::Int32(0)));
    }

    #[test]
    fn test_initialize_internal_when_running() {
        let _lock = FIPS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state::set_fips_state(FipsState::Running);
        assert!(initialize_internal().is_ok());
    }

    #[test]
    fn test_initialize_internal_when_not_running() {
        let _lock = FIPS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state::set_fips_state(FipsState::Init);
        assert!(initialize_internal().is_err());
    }

    #[test]
    fn test_lock_unlock_deferred() {
        let g = FipsGlobal::new();
        let guard = lock_deferred(&g).expect("lock should succeed");
        unlock_deferred(guard);
    }

    #[test]
    fn test_extract_selftest_params() {
        let mut params = SelfTestPostParams::default();
        let mut config = ParamSet::new();
        config.set("module-filename", ParamValue::Utf8String("/fips.so".into()));
        config.set(
            "module-checksum-data",
            ParamValue::Utf8String("abcdef".into()),
        );
        config.set("is-deferred-test", ParamValue::Int32(1));

        extract_selftest_params(&config, &mut params);
        assert_eq!(params.module_filename, Some("/fips.so".into()));
        assert_eq!(params.module_checksum_data, Some("abcdef".into()));
        assert!(params.is_deferred_test);
    }

    #[test]
    fn test_extract_indicator_config() {
        let mut cfg = FipsIndicatorConfig::default();
        let mut config = ParamSet::new();
        config.set("security-checks", ParamValue::Utf8String("0".into()));
        config.set("rsa-key-check", ParamValue::Int32(0));

        extract_indicator_config(&config, &mut cfg).expect("extraction should succeed");
        assert!(!cfg.security_checks.enabled);
        assert!(!cfg.rsa_key_check.enabled);
        // Unchanged params should remain enabled
        assert!(cfg.hmac_key_check.enabled);
    }

    #[test]
    fn test_properties_constants() {
        assert!(FIPS_DEFAULT_PROPERTIES.contains("fips=yes"));
        assert!(FIPS_UNAPPROVED_PROPERTIES.contains("fips=no"));
        assert!(FIPS_DEFAULT_PROPERTIES.contains("provider=fips"));
        assert!(FIPS_UNAPPROVED_PROPERTIES.contains("provider=fips"));
    }

    #[test]
    fn test_callback_type_aliases() {
        // Verify the type aliases compile and can be constructed
        let _cb: SelfTestCallback = Box::new(|_type_name, _desc| true);
        let _icb: IndicatorCallback = Box::new(|_alg, _op| false);
    }
}
