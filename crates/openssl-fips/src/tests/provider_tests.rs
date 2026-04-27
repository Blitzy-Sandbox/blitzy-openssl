//! Tests for FIPS provider initialization, algorithm query, configuration, and
//! lifecycle management.
//!
//! Covers ten test phases corresponding to the provider module's major features:
//!
//! 1. Module imports (verified by compilation)
//! 2. [`SelfTestPostParams`] default and custom construction
//! 3. [`FipsOption`] default and custom construction
//! 4. `FipsIndicatorConfig` default and individual-disable behaviour
//! 5. Provider `initialize()` — success, missing checksum, already-running
//! 6. Algorithm query via `query_algorithms()` for every `OperationType`
//! 7. Gettable / Get parameters via [`gettable_params()`] and [`get_params()`]
//! 8. Config accessor methods on [`FipsGlobal`]
//! 9. Provider teardown via [`FipsGlobal::teardown()`]
//! 10. Deferred-test lock acquire/release via [`lock_deferred()`] / [`unlock_deferred()`]
//!
//! # Rules Verified
//!
//! - **R5 (Nullability):** Every `Option<T>` field is tested with both `None` and `Some`.
//! - **R7 (Lock Granularity):** `deferred_lock` is independently lockable.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this file.
//! - **R9 (Warning-Free):** All items used; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Tests exercise the full init → query → config → teardown chain.

// Test code is expected to use expect/unwrap/panic for assertion clarity.
// Workspace Cargo.toml §clippy: "Tests and CLI main() may #[allow] with justification."
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::doc_markdown
)]

use crate::provider::{
    self, FipsAlgorithmEntry, FipsGlobal, FipsIndicatorConfig, FipsOption, SelfTestPostParams,
};
use crate::state::{self, get_fips_state, reset_all_states, set_fips_state, FipsState};
use openssl_common::error::{FipsError, FipsResult};
use openssl_common::param::{ParamBuilder, ParamSet, ParamValue};
use openssl_common::types::OperationType;

// =============================================================================
// Helper — test isolation
// =============================================================================

/// Resets global FIPS state to `Init` and clears all per-test KAT states.
///
/// Every test that touches global state should call this first so that results
/// are deterministic and independent of test execution order.
fn reset_for_test() {
    state::reset_fips_state();
    reset_all_states();
}

/// Builds a minimal valid `ParamSet` that can drive a successful
/// `provider::initialize()` call (when integrity checking is stubbed).
fn build_minimal_init_params() -> ParamSet {
    ParamBuilder::new()
        .push_utf8("module-filename", "/dev/null".to_string())
        .push_utf8("module-checksum-data", "00000000".to_string())
        .build()
}

/// Builds a `ParamSet` where the module checksum is deliberately absent.
fn build_params_missing_checksum() -> ParamSet {
    ParamBuilder::new()
        .push_utf8("module-filename", "/dev/null".to_string())
        // Intentionally no "module-mac" key.
        .build()
}

// =============================================================================
// Phase 2 — SelfTestPostParams Tests
// =============================================================================

#[test]
fn test_self_test_post_params_default() {
    let params = SelfTestPostParams::default();

    // Rule R5: Option<T> — not empty-string sentinel
    assert!(
        params.module_filename.is_none(),
        "module_filename should default to None (R5)"
    );
    assert!(
        params.module_checksum_data.is_none(),
        "module_checksum_data should default to None (R5)"
    );
    assert!(
        params.indicator_checksum_data.is_none(),
        "indicator_checksum_data should default to None (R5)"
    );
    assert!(
        params.conditional_error_check.is_none(),
        "conditional_error_check should default to None (R5)"
    );
    assert!(
        !params.is_deferred_test,
        "is_deferred_test should default to false"
    );
}

#[test]
fn test_self_test_post_params_with_values() {
    let params = SelfTestPostParams {
        module_filename: Some("/path/to/fips.so".to_string()),
        module_checksum_data: Some("abcd1234".to_string()),
        indicator_checksum_data: Some("ef560789".to_string()),
        conditional_error_check: Some("1".to_string()),
        is_deferred_test: true,
    };

    // Rule R5: verify Some, NOT empty-string sentinels.
    assert_eq!(params.module_filename.as_deref(), Some("/path/to/fips.so"));
    assert_eq!(params.module_checksum_data.as_deref(), Some("abcd1234"));
    assert_eq!(params.indicator_checksum_data.as_deref(), Some("ef560789"));
    assert_eq!(params.conditional_error_check.as_deref(), Some("1"));
    assert!(params.is_deferred_test);
}

// =============================================================================
// Phase 3 — FipsOption Tests
// =============================================================================

#[test]
fn test_fips_option_default() {
    let opt = FipsOption::default();

    // Rule R5: option uses Option<String>, not empty string.
    assert!(
        opt.option.is_none(),
        "FipsOption::option should default to None (R5)"
    );
    // Matches C `init_fips_option` which sets enabled = 1.
    assert!(opt.enabled, "FipsOption::enabled should default to true");
}

#[test]
fn test_fips_option_custom() {
    let opt = FipsOption {
        option: Some("security_checks".to_string()),
        enabled: false,
    };

    assert_eq!(opt.option.as_deref(), Some("security_checks"));
    assert!(
        !opt.enabled,
        "custom FipsOption should honour enabled=false"
    );
}

// =============================================================================
// Phase 4 — FipsIndicatorConfig Tests
// =============================================================================

#[test]
fn test_fips_indicator_config_default() {
    let cfg = FipsIndicatorConfig::default();

    // Verify all 27 indicator params default to enabled (fipsprov.c lines 92–109).
    assert!(cfg.security_checks.enabled, "security_checks");
    assert!(cfg.tls1_prf_ems_check.enabled, "tls1_prf_ems_check");
    assert!(cfg.no_short_mac.enabled, "no_short_mac");
    assert!(cfg.hmac_key_check.enabled, "hmac_key_check");
    assert!(cfg.kem_key_check.enabled, "kem_key_check");
    assert!(cfg.kmac_key_check.enabled, "kmac_key_check");
    assert!(cfg.dsa_key_check.enabled, "dsa_key_check");
    assert!(cfg.tdes_key_check.enabled, "tdes_key_check");
    assert!(cfg.rsa_key_check.enabled, "rsa_key_check");
    assert!(cfg.dhx_key_check.enabled, "dhx_key_check");
    assert!(cfg.ec_key_check.enabled, "ec_key_check");
    assert!(cfg.pkcs12_key_gen_check.enabled, "pkcs12_key_gen_check");
    assert!(cfg.sign_x931_pad_check.enabled, "sign_x931_pad_check");
    assert!(cfg.sign_digest_check.enabled, "sign_digest_check");
    assert!(cfg.hkdf_digest_check.enabled, "hkdf_digest_check");
    assert!(cfg.tls13_kdf_digest_check.enabled, "tls13_kdf_digest_check");
    assert!(cfg.ecdh_cofactor_check.enabled, "ecdh_cofactor_check");
    assert!(cfg.hkdf_key_check.enabled, "hkdf_key_check");
    assert!(cfg.kbkdf_key_check.enabled, "kbkdf_key_check");
    assert!(cfg.tls1_prf_key_check.enabled, "tls1_prf_key_check");
    assert!(cfg.sshkdf_digest_check.enabled, "sshkdf_digest_check");
    assert!(cfg.sshkdf_key_check.enabled, "sshkdf_key_check");
    assert!(cfg.sskdf_digest_check.enabled, "sskdf_digest_check");
    assert!(cfg.sskdf_key_check.enabled, "sskdf_key_check");
    assert!(cfg.x963kdf_key_check.enabled, "x963kdf_key_check");
    assert!(cfg.x942kdf_key_check.enabled, "x942kdf_key_check");
    assert!(cfg.rsa_sign_pss_check.enabled, "rsa_sign_pss_check");

    // Verify all 27 option fields default to None (Rule R5).
    assert!(cfg.security_checks.option.is_none());
    assert!(cfg.tls1_prf_ems_check.option.is_none());
    assert!(cfg.no_short_mac.option.is_none());
    assert!(cfg.hmac_key_check.option.is_none());
    assert!(cfg.kem_key_check.option.is_none());
    assert!(cfg.kmac_key_check.option.is_none());
    assert!(cfg.dsa_key_check.option.is_none());
    assert!(cfg.tdes_key_check.option.is_none());
    assert!(cfg.rsa_key_check.option.is_none());
    assert!(cfg.dhx_key_check.option.is_none());
    assert!(cfg.ec_key_check.option.is_none());
    assert!(cfg.pkcs12_key_gen_check.option.is_none());
    assert!(cfg.sign_x931_pad_check.option.is_none());
    assert!(cfg.sign_digest_check.option.is_none());
    assert!(cfg.hkdf_digest_check.option.is_none());
    assert!(cfg.tls13_kdf_digest_check.option.is_none());
    assert!(cfg.ecdh_cofactor_check.option.is_none());
    assert!(cfg.hkdf_key_check.option.is_none());
    assert!(cfg.kbkdf_key_check.option.is_none());
    assert!(cfg.tls1_prf_key_check.option.is_none());
    assert!(cfg.sshkdf_digest_check.option.is_none());
    assert!(cfg.sshkdf_key_check.option.is_none());
    assert!(cfg.sskdf_digest_check.option.is_none());
    assert!(cfg.sskdf_key_check.option.is_none());
    assert!(cfg.x963kdf_key_check.option.is_none());
    assert!(cfg.x942kdf_key_check.option.is_none());
    assert!(cfg.rsa_sign_pss_check.option.is_none());
}

#[test]
fn test_fips_indicator_config_individual_disable() {
    let mut cfg = FipsIndicatorConfig::default();

    // Disable only security_checks.
    cfg.security_checks.enabled = false;

    assert!(
        !cfg.security_checks.enabled,
        "security_checks should be disabled"
    );

    // All other 26 indicators remain enabled.
    assert!(cfg.tls1_prf_ems_check.enabled);
    assert!(cfg.no_short_mac.enabled);
    assert!(cfg.hmac_key_check.enabled);
    assert!(cfg.kem_key_check.enabled);
    assert!(cfg.kmac_key_check.enabled);
    assert!(cfg.dsa_key_check.enabled);
    assert!(cfg.tdes_key_check.enabled);
    assert!(cfg.rsa_key_check.enabled);
    assert!(cfg.dhx_key_check.enabled);
    assert!(cfg.ec_key_check.enabled);
    assert!(cfg.pkcs12_key_gen_check.enabled);
    assert!(cfg.sign_x931_pad_check.enabled);
    assert!(cfg.sign_digest_check.enabled);
    assert!(cfg.hkdf_digest_check.enabled);
    assert!(cfg.tls13_kdf_digest_check.enabled);
    assert!(cfg.ecdh_cofactor_check.enabled);
    assert!(cfg.hkdf_key_check.enabled);
    assert!(cfg.kbkdf_key_check.enabled);
    assert!(cfg.tls1_prf_key_check.enabled);
    assert!(cfg.sshkdf_digest_check.enabled);
    assert!(cfg.sshkdf_key_check.enabled);
    assert!(cfg.sskdf_digest_check.enabled);
    assert!(cfg.sskdf_key_check.enabled);
    assert!(cfg.x963kdf_key_check.enabled);
    assert!(cfg.x942kdf_key_check.enabled);
    assert!(cfg.rsa_sign_pss_check.enabled);
}

// =============================================================================
// Phase 5 — Provider Initialization Tests
// =============================================================================

#[test]
fn test_provider_initialize_success() {
    let _serial = super::TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let config = build_minimal_init_params();
    let result = provider::initialize(&config);

    // Successful initialization returns Ok(FipsGlobal).
    assert!(
        result.is_ok(),
        "initialize should succeed: {:?}",
        result.err()
    );
    let global = result.unwrap();

    assert_eq!(global.name, "OpenSSL FIPS Provider");
    assert!(!global.version.is_empty(), "version must be non-empty");

    // After a successful init the module should be Running (or at least not Error).
    let final_state = get_fips_state();
    assert!(
        final_state == FipsState::Running || final_state == FipsState::Init,
        "expected Running or Init after init, got {:?}",
        final_state
    );
}

#[test]
fn test_provider_initialize_missing_checksum() {
    let _serial = super::TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let config = build_params_missing_checksum();
    let result = provider::initialize(&config);

    // Missing checksum data should yield an error (maps to C PROV_R_MISSING_CONFIG_DATA).
    assert!(
        result.is_err(),
        "initialize with missing checksum must return Err"
    );

    // Verify the error is a FIPS-domain error, not some unrelated variant.
    let err = result.unwrap_err();
    let is_fips_domain = matches!(
        err,
        FipsError::SelfTestFailed(_)
            | FipsError::IntegrityCheckFailed
            | FipsError::NotOperational(_)
            | FipsError::NotApproved(_)
            | FipsError::Common(_)
    );
    assert!(is_fips_domain, "expected a FipsError variant, got: {err}");

    // State may transition to Error depending on how far the init got.
    let final_state = get_fips_state();
    assert!(
        final_state == FipsState::Error || final_state == FipsState::Init,
        "expected Error or Init after failed init, got {:?}",
        final_state
    );
}

#[test]
fn test_provider_initialize_already_running() {
    let _serial = super::TEST_MUTEX.lock().unwrap();
    reset_for_test();
    // Pre-set state to Running (simulates an already-initialized module).
    set_fips_state(FipsState::Running);

    let config = build_minimal_init_params();
    let result = provider::initialize(&config);

    // An already-running module should return Ok without re-running POST
    // (C self_test.c lines 301–303).
    assert!(
        result.is_ok(),
        "initialize when already Running should succeed: {:?}",
        result.err()
    );

    // State must remain Running.
    assert_eq!(
        get_fips_state(),
        FipsState::Running,
        "state must remain Running"
    );
}

// =============================================================================
// Phase 6 — Algorithm Query Tests
// =============================================================================

/// Utility: asserts that a static algorithm slice contains at least one entry
/// whose `names` field contains the given substring (case-sensitive).
fn assert_algorithm_present(entries: &[FipsAlgorithmEntry], needle: &str) {
    let found = entries.iter().any(|e| e.names.contains(needle));
    assert!(
        found,
        "expected to find algorithm containing '{needle}' in {:?}",
        entries.iter().map(|e| e.names).collect::<Vec<_>>()
    );
}

/// Utility: checks that every entry in the slice has non-empty fields.
fn assert_entries_well_formed(entries: &[FipsAlgorithmEntry]) {
    for entry in entries {
        assert!(!entry.names.is_empty(), "algorithm name must not be empty");
        assert!(
            !entry.properties.is_empty(),
            "algorithm properties must not be empty for '{}'",
            entry.names
        );
        assert!(
            !entry.description.is_empty(),
            "algorithm description must not be empty for '{}'",
            entry.names
        );
    }
}

#[test]
fn test_query_fips_digests() {
    let entries = provider::query_algorithms(OperationType::Digest);
    assert!(!entries.is_empty(), "FIPS digest table must not be empty");

    // Core FIPS-approved digests.
    assert_algorithm_present(entries, "SHA2-256");
    assert_algorithm_present(entries, "SHA2-384");
    assert_algorithm_present(entries, "SHA2-512");
    assert_algorithm_present(entries, "SHA3-256");

    // Verify property strings contain the FIPS marker.
    for entry in entries {
        assert!(
            entry.properties.contains("provider=fips"),
            "digest '{}' missing 'provider=fips' in properties",
            entry.names
        );
    }

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_ciphers() {
    let entries = provider::query_algorithms(OperationType::Cipher);
    assert!(!entries.is_empty(), "FIPS cipher table must not be empty");

    assert_algorithm_present(entries, "AES-256-GCM");
    assert_algorithm_present(entries, "AES-128-GCM");

    for entry in entries {
        assert!(
            entry.properties.contains("provider=fips"),
            "cipher '{}' missing 'provider=fips'",
            entry.names
        );
    }

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_macs() {
    let entries = provider::query_algorithms(OperationType::Mac);
    assert!(!entries.is_empty(), "FIPS MAC table must not be empty");

    assert_algorithm_present(entries, "HMAC");
    assert_algorithm_present(entries, "CMAC");
    assert_algorithm_present(entries, "GMAC");
    assert_algorithm_present(entries, "KMAC");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_signatures() {
    let entries = provider::query_algorithms(OperationType::Signature);
    assert!(
        !entries.is_empty(),
        "FIPS signature table must not be empty"
    );

    assert_algorithm_present(entries, "RSA");
    assert_algorithm_present(entries, "ECDSA");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_kem() {
    let entries = provider::query_algorithms(OperationType::Kem);
    assert!(!entries.is_empty(), "FIPS KEM table must not be empty");

    // RSA KEM is always present.
    assert_algorithm_present(entries, "RSA");

    // ML-KEM entries are also expected in the FIPS provider.
    assert_algorithm_present(entries, "ML-KEM");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_kdfs() {
    let entries = provider::query_algorithms(OperationType::Kdf);
    assert!(!entries.is_empty(), "FIPS KDF table must not be empty");

    assert_algorithm_present(entries, "HKDF");
    assert_algorithm_present(entries, "PBKDF2");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_rands() {
    let entries = provider::query_algorithms(OperationType::Rand);
    assert!(!entries.is_empty(), "FIPS RAND table must not be empty");

    assert_algorithm_present(entries, "CTR-DRBG");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_keymgmt() {
    let entries = provider::query_algorithms(OperationType::KeyMgmt);
    assert!(!entries.is_empty(), "FIPS KeyMgmt table must not be empty");

    assert_algorithm_present(entries, "RSA");
    assert_algorithm_present(entries, "EC");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_key_exchange() {
    let entries = provider::query_algorithms(OperationType::KeyExch);
    assert!(
        !entries.is_empty(),
        "FIPS KeyExchange table must not be empty"
    );

    assert_algorithm_present(entries, "DH");
    assert_algorithm_present(entries, "ECDH");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_asym_cipher() {
    let entries = provider::query_algorithms(OperationType::AsymCipher);
    assert!(
        !entries.is_empty(),
        "FIPS AsymCipher table must not be empty"
    );

    assert_algorithm_present(entries, "RSA");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_fips_skeymgmt() {
    let entries = provider::query_algorithms(OperationType::SKeyMgmt);
    assert!(!entries.is_empty(), "FIPS SKeyMgmt table must not be empty");

    assert_algorithm_present(entries, "AES");

    assert_entries_well_formed(entries);
}

#[test]
fn test_query_returns_empty_for_unsupported() {
    // Store and EncoderDecoder are not supported by the FIPS provider.
    let store_entries = provider::query_algorithms(OperationType::Store);
    assert!(
        store_entries.is_empty(),
        "Store should return empty for FIPS provider"
    );

    let enc_dec_entries = provider::query_algorithms(OperationType::EncoderDecoder);
    assert!(
        enc_dec_entries.is_empty(),
        "EncoderDecoder should return empty for FIPS provider"
    );
}

// =============================================================================
// Phase 7 — Gettable / Get Parameters Tests
// =============================================================================

#[test]
fn test_gettable_params_list() {
    let names = provider::gettable_params();

    // Core metadata params.
    assert!(names.contains(&"name"), "gettable_params must list 'name'");
    assert!(
        names.contains(&"version"),
        "gettable_params must list 'version'"
    );
    assert!(
        names.contains(&"buildinfo"),
        "gettable_params must list 'buildinfo'"
    );
    assert!(
        names.contains(&"status"),
        "gettable_params must list 'status'"
    );

    // All 27 indicator parameter names must be listed.
    let indicator_names = [
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
    ];
    for ind in &indicator_names {
        assert!(
            names.contains(ind),
            "gettable_params must list indicator '{ind}'"
        );
    }

    // 4 metadata + 27 indicators = at least 31.
    assert!(
        names.len() >= 31,
        "expected >= 31 params, got {}",
        names.len()
    );
}

#[test]
fn test_get_params_after_init() {
    let _serial = super::TEST_MUTEX.lock().unwrap();
    reset_for_test();

    // Create a FipsGlobal via new() — direct construction avoids
    // the full self-test pipeline while still exercising get_params.
    let global = FipsGlobal::new();
    let result: FipsResult<ParamSet> = provider::get_params(&global);
    assert!(result.is_ok(), "get_params failed: {:?}", result.err());

    let ps = result.unwrap();

    // Verify provider name.
    if let Some(val) = ps.get("name") {
        assert_eq!(
            val.as_str(),
            Some("OpenSSL FIPS Provider"),
            "name must be 'OpenSSL FIPS Provider'"
        );
    } else {
        panic!("get_params result missing 'name' key");
    }

    // Verify version is present and non-empty.
    if let Some(val) = ps.get("version") {
        let ver = val.as_str().expect("version should be a string");
        assert!(!ver.is_empty(), "version must be non-empty");
    } else {
        panic!("get_params result missing 'version' key");
    }

    // Verify status is present.
    assert!(ps.contains("status"), "get_params must include 'status'");

    // Verify all 27 indicator parameters are accessible and default to 1 (enabled).
    let indicator_names = [
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
    ];
    for ind in &indicator_names {
        let val = ps
            .get(ind)
            .unwrap_or_else(|| panic!("get_params missing indicator param '{ind}'"));
        assert_eq!(
            val.as_i32(),
            Some(1),
            "indicator '{ind}' should default to 1 (enabled)"
        );
    }
}

// =============================================================================
// Phase 8 — Config Accessor Tests
// =============================================================================

#[test]
fn test_config_security_checks_default() {
    let global = FipsGlobal::new();
    assert!(
        global.config_security_checks(),
        "default security_checks should be true"
    );
}

#[test]
fn test_config_security_checks_disabled() {
    let mut global = FipsGlobal::new();
    global.indicator_config.security_checks.enabled = false;
    assert!(
        !global.config_security_checks(),
        "security_checks should be false after disabling"
    );
}

#[test]
fn test_config_all_27_accessors_default() {
    let g = FipsGlobal::new();

    // All 27 config accessors should return true on a fresh FipsGlobal.
    assert!(g.config_security_checks());
    assert!(g.config_tls1_prf_ems_check());
    assert!(g.config_no_short_mac());
    assert!(g.config_hmac_key_check());
    assert!(g.config_kem_key_check());
    assert!(g.config_kmac_key_check());
    assert!(g.config_dsa_key_check());
    assert!(g.config_tdes_key_check());
    assert!(g.config_rsa_key_check());
    assert!(g.config_dhx_key_check());
    assert!(g.config_ec_key_check());
    assert!(g.config_pkcs12_key_gen_check());
    assert!(g.config_sign_x931_pad_check());
    assert!(g.config_sign_digest_check());
    assert!(g.config_hkdf_digest_check());
    assert!(g.config_tls13_kdf_digest_check());
    assert!(g.config_ecdh_cofactor_check());
    assert!(g.config_hkdf_key_check());
    assert!(g.config_kbkdf_key_check());
    assert!(g.config_tls1_prf_key_check());
    assert!(g.config_sshkdf_digest_check());
    assert!(g.config_sshkdf_key_check());
    assert!(g.config_sskdf_digest_check());
    assert!(g.config_sskdf_key_check());
    assert!(g.config_x963kdf_key_check());
    assert!(g.config_x942kdf_key_check());
    assert!(g.config_rsa_sign_pss_check());
}

#[test]
fn test_config_individual_accessors_after_disable() {
    let mut g = FipsGlobal::new();

    // Disable a few scattered indicators.
    g.indicator_config.tls1_prf_ems_check.enabled = false;
    g.indicator_config.rsa_key_check.enabled = false;
    g.indicator_config.rsa_sign_pss_check.enabled = false;

    assert!(!g.config_tls1_prf_ems_check());
    assert!(!g.config_rsa_key_check());
    assert!(!g.config_rsa_sign_pss_check());

    // The rest remain enabled.
    assert!(g.config_security_checks());
    assert!(g.config_no_short_mac());
    assert!(g.config_hmac_key_check());
    assert!(g.config_kem_key_check());
    assert!(g.config_kmac_key_check());
    assert!(g.config_dsa_key_check());
    assert!(g.config_tdes_key_check());
    assert!(g.config_dhx_key_check());
    assert!(g.config_ec_key_check());
    assert!(g.config_pkcs12_key_gen_check());
    assert!(g.config_sign_x931_pad_check());
    assert!(g.config_sign_digest_check());
    assert!(g.config_hkdf_digest_check());
    assert!(g.config_tls13_kdf_digest_check());
    assert!(g.config_ecdh_cofactor_check());
    assert!(g.config_hkdf_key_check());
    assert!(g.config_kbkdf_key_check());
    assert!(g.config_tls1_prf_key_check());
    assert!(g.config_sshkdf_digest_check());
    assert!(g.config_sshkdf_key_check());
    assert!(g.config_sskdf_digest_check());
    assert!(g.config_sskdf_key_check());
    assert!(g.config_x963kdf_key_check());
    assert!(g.config_x942kdf_key_check());
}

// =============================================================================
// Phase 9 — Provider Teardown Tests
// =============================================================================

#[test]
fn test_provider_teardown() {
    let _serial = super::TEST_MUTEX.lock().unwrap();
    reset_for_test();

    let mut global = FipsGlobal::new();

    // Set up some non-default state to verify teardown clears it.
    global.selftest_params.module_filename = Some("/some/path".to_string());
    global.selftest_params.is_deferred_test = true;
    set_fips_state(FipsState::Running);

    // Teardown.
    global.teardown();

    // State must be reset to Init.
    assert_eq!(
        get_fips_state(),
        FipsState::Init,
        "teardown must reset state to Init"
    );

    // selftest_params are reset to defaults.
    assert!(
        global.selftest_params.module_filename.is_none(),
        "teardown must clear selftest_params.module_filename (R5)"
    );
    assert!(
        !global.selftest_params.is_deferred_test,
        "teardown must reset is_deferred_test to false"
    );
}

// =============================================================================
// Phase 10 — Deferred Test Lock Tests
// =============================================================================

#[test]
fn test_deferred_lock_acquire_release() {
    let global = FipsGlobal::new();

    // Acquire the write lock.
    let guard_result = provider::lock_deferred(&global);
    assert!(
        guard_result.is_ok(),
        "lock_deferred should succeed on a fresh FipsGlobal: {:?}",
        guard_result.err()
    );

    let guard = guard_result.unwrap();

    // Release the lock.
    provider::unlock_deferred(guard);

    // Re-acquire to prove the lock was properly released (no deadlock).
    let guard2 = provider::lock_deferred(&global);
    assert!(
        guard2.is_ok(),
        "second lock_deferred should succeed after unlock"
    );
    provider::unlock_deferred(guard2.unwrap());
}

#[test]
fn test_deferred_lock_is_independent() {
    // Rule R7: the deferred_lock must be independently lockable.
    // We verify it can be locked without any global state contention.
    let g1 = FipsGlobal::new();
    let g2 = FipsGlobal::new();

    // Locking two independent FipsGlobal instances must not interfere.
    let lock1 = provider::lock_deferred(&g1);
    assert!(lock1.is_ok());

    let lock2 = provider::lock_deferred(&g2);
    assert!(lock2.is_ok());

    // Release in reverse order.
    provider::unlock_deferred(lock2.unwrap());
    provider::unlock_deferred(lock1.unwrap());
}

// =============================================================================
// Additional comprehensive tests (cross-cutting concerns)
// =============================================================================

#[test]
fn test_fips_global_new_metadata() {
    let g = FipsGlobal::new();
    assert_eq!(g.name, "OpenSSL FIPS Provider");
    assert_eq!(g.version, "4.0.0");
    assert_eq!(g.build_info, "OpenSSL FIPS Provider 4.0.0");
}

#[test]
fn test_self_test_post_params_clone() {
    let original = SelfTestPostParams {
        module_filename: Some("/path/fips.so".to_string()),
        module_checksum_data: Some("aabb".to_string()),
        indicator_checksum_data: None,
        conditional_error_check: Some("1".to_string()),
        is_deferred_test: false,
    };
    let cloned = original.clone();

    assert_eq!(cloned.module_filename, original.module_filename);
    assert_eq!(cloned.module_checksum_data, original.module_checksum_data);
    assert_eq!(
        cloned.indicator_checksum_data,
        original.indicator_checksum_data
    );
    assert_eq!(
        cloned.conditional_error_check,
        original.conditional_error_check
    );
    assert_eq!(cloned.is_deferred_test, original.is_deferred_test);
}

#[test]
fn test_fips_option_clone() {
    let original = FipsOption {
        option: Some("test".to_string()),
        enabled: false,
    };
    let cloned = original.clone();

    assert_eq!(cloned.option, original.option);
    assert_eq!(cloned.enabled, original.enabled);
}

#[test]
fn test_fips_indicator_config_clone() {
    let mut cfg = FipsIndicatorConfig::default();
    cfg.security_checks.enabled = false;
    cfg.rsa_key_check.option = Some("0".to_string());

    let cloned = cfg.clone();
    assert!(!cloned.security_checks.enabled);
    assert_eq!(cloned.rsa_key_check.option.as_deref(), Some("0"));
    // Unmodified fields still at defaults.
    assert!(cloned.tls1_prf_ems_check.enabled);
    assert!(cloned.tls1_prf_ems_check.option.is_none());
}

#[test]
fn test_algorithm_entry_properties_format() {
    // Verify that the property strings follow the expected "provider=fips,fips=yes"
    // or "provider=fips,fips=no" format across all operation types with non-empty tables.
    let operation_types = [
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

    for op in &operation_types {
        let entries = provider::query_algorithms(*op);
        for entry in entries {
            assert!(
                entry.properties.starts_with("provider=fips"),
                "entry '{}' for {:?} has unexpected properties: '{}'",
                entry.names,
                op,
                entry.properties
            );
        }
    }
}

#[test]
fn test_query_all_operation_types_no_panic() {
    // Exhaustive call — no operation type should panic, even unsupported ones.
    let all_ops = [
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
        OperationType::EncoderDecoder,
        OperationType::Store,
        OperationType::SKeyMgmt,
    ];

    for op in &all_ops {
        // Must not panic — empty slice is a valid return for unsupported types.
        let _entries = provider::query_algorithms(*op);
    }
}

#[test]
fn test_param_builder_round_trip() {
    // Verify that ParamBuilder / ParamSet / ParamValue work correctly for the
    // parameter types used in provider initialization and get_params.
    let ps = ParamBuilder::new()
        .push_utf8("name", "TestProvider".to_string())
        .push_i32("enabled", 1)
        .build();

    assert!(ps.contains("name"));
    assert!(ps.contains("enabled"));
    assert_eq!(ps.get("name").unwrap().as_str(), Some("TestProvider"));
    assert_eq!(ps.get("enabled").unwrap().as_i32(), Some(1));

    // Verify the concrete ParamValue variants match expectations.
    assert!(
        matches!(ps.get("name"), Some(ParamValue::Utf8String(_))),
        "name param must be Utf8String variant"
    );
    assert!(
        matches!(ps.get("enabled"), Some(ParamValue::Int32(1))),
        "enabled param must be Int32(1)"
    );
}
