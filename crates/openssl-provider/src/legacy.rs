//! Legacy provider implementation for the OpenSSL Rust workspace.
//!
//! Provides the **OpenSSL Legacy Provider** — deprecated algorithms maintained
//! for backward compatibility.  All algorithms are tagged with the property
//! string `"provider=legacy"`.
//!
//! # Algorithms Provided
//!
//! | Category | Algorithms                                                  |
//! |----------|-------------------------------------------------------------|
//! | Digests  | MD2, MD4, MDC2, Whirlpool, RIPEMD-160                       |
//! | Ciphers  | Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, DES, DESX       |
//! | KDFs     | PBKDF1, PVK KDF                                             |
//!
//! # Feature Gating
//!
//! The entire module is gated behind `#[cfg(feature = "legacy")]` in the
//! crate root (`lib.rs`).  When disabled, no legacy algorithms are compiled.
//! Individual algorithm families are included unconditionally within the
//! legacy feature — fine-grained per-algorithm feature flags map to the
//! C `OPENSSL_NO_*` guards from `legacyprov.c`.
//!
//! # C Mapping
//!
//! | Rust                          | C Source                          |
//! |-------------------------------|-----------------------------------|
//! | `LegacyProvider::new()`       | `ossl_legacy_provider_init()`     |
//! | `Provider::info()`            | Provider name/version constants   |
//! | `Provider::query_operation()` | `legacy_query()`                  |
//! | `Provider::get_params()`      | `legacy_get_params()`             |
//! | `Provider::gettable_params()` | `legacy_gettable_params`          |
//! | `Provider::is_running()`      | `ossl_prov_is_running()`          |
//! | `Provider::teardown()`        | `legacy_teardown()`               |
//!
//! # Rules Enforced
//!
//! - **R5:** All returns typed via `Option<T>` / `Result<T, E>` — no sentinels
//! - **R7:** No shared mutable state; algorithm tables cached via `once_cell::sync::Lazy`
//! - **R8:** Zero `unsafe` code
//! - **R9:** Warning-free, all public items documented
//! - **R10:** Reachable via provider loading → `LegacyProvider::new()`

use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use once_cell::sync::Lazy;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::types::OperationType;
use openssl_common::ProviderResult;
use tracing::info;

// =============================================================================
// Constants
// =============================================================================

/// Provider name — must match C `legacyprov.c` exactly for interop.
const PROVIDER_NAME: &str = "OpenSSL Legacy Provider";

/// Provider version string.
const PROVIDER_VERSION: &str = "4.0.0";

/// Provider build information string.
const PROVIDER_BUILD_INFO: &str = "openssl-rs 4.0.0";

/// Property query string applied to every algorithm descriptor registered
/// by this provider.  Used by the method store for algorithm fetch/match.
const LEGACY_PROPERTY: &str = "provider=legacy";

// =============================================================================
// Lazy-Initialized Algorithm Tables (Rule R7: no per-query allocation)
// =============================================================================
//
// Each static table is initialized once on first access using `once_cell::sync::Lazy`.
// This avoids repeated `Vec` allocation on every `query_operation()` call while
// remaining thread-safe without requiring a lock on `LegacyProvider` itself.
// LOCK-SCOPE: No lock needed — `Lazy` provides one-shot interior-mutable init.

/// Cached legacy digest algorithm descriptors.
static DIGEST_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_digest_table);

/// Cached legacy cipher algorithm descriptors.
static CIPHER_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_cipher_table);

/// Cached legacy KDF algorithm descriptors.
static KDF_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_kdf_table);

// =============================================================================
// LegacyProvider Struct
// =============================================================================

/// Legacy provider — implements deprecated algorithms for backward compatibility.
///
/// All algorithms are tagged with property `"provider=legacy"`.
///
/// # Algorithms
///
/// - **Digests:** MD2, MD4, MDC2, Whirlpool, RIPEMD-160
/// - **Ciphers:** Blowfish (BF-*), CAST5 (CAST5-*), IDEA (IDEA-*),
///   SEED (SEED-*), RC2 (RC2-*), RC4, RC5 (RC5-*), DES (DES-*), DESX
/// - **KDFs:** PBKDF1, PVK KDF
///
/// # C Equivalent
///
/// Replaces C `ossl_legacy_provider_init()` / `OSSL_provider_init()` from
/// `providers/legacyprov.c`.
///
/// # Examples
///
/// ```
/// use openssl_provider::legacy::LegacyProvider;
/// use openssl_provider::traits::Provider;
/// use openssl_common::types::OperationType;
///
/// let provider = LegacyProvider::new();
/// assert!(provider.is_running());
///
/// let info = provider.info();
/// assert_eq!(info.name, "OpenSSL Legacy Provider");
///
/// let digests = provider.query_operation(OperationType::Digest);
/// assert!(digests.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct LegacyProvider {
    /// Whether this provider instance is currently operational.
    /// Set to `true` on construction; set to `false` by `teardown()`.
    running: bool,
}

impl LegacyProvider {
    /// Creates a new legacy provider instance in the running state.
    ///
    /// The provider is immediately operational after construction —
    /// no separate activation step is needed.  This mirrors the C
    /// `ossl_legacy_provider_init()` which returns `1` (success)
    /// and sets the provider as running.
    ///
    /// Logs an `info!` event for provider lifecycle observability.
    pub fn new() -> Self {
        info!(
            provider = PROVIDER_NAME,
            version = PROVIDER_VERSION,
            "Legacy provider initialized"
        );
        Self { running: true }
    }
}

impl Default for LegacyProvider {
    /// Equivalent to [`LegacyProvider::new()`].
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Provider Trait Implementation
// =============================================================================

impl Provider for LegacyProvider {
    /// Returns metadata about this provider.
    ///
    /// The returned [`ProviderInfo`] contains the provider name, version,
    /// build information, and current running status.  The name string
    /// `"OpenSSL Legacy Provider"` matches the C implementation exactly.
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: PROVIDER_NAME,
            version: PROVIDER_VERSION,
            build_info: PROVIDER_BUILD_INFO,
            status: self.running,
        }
    }

    /// Dispatches an operation type to the corresponding legacy algorithm table.
    ///
    /// Returns `Some(table)` with the full list of [`AlgorithmDescriptor`]s
    /// for the requested operation, or `None` if the provider is not running
    /// or the operation category is not supported by the legacy provider.
    ///
    /// The legacy provider supports three operation categories:
    /// - [`OperationType::Digest`] — MD2, MD4, MDC2, Whirlpool, RIPEMD-160
    /// - [`OperationType::Cipher`] — Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, DES, DESX
    /// - [`OperationType::Kdf`] — PBKDF1, PVK KDF
    ///
    /// All other operation types return `None`.
    ///
    /// Each algorithm descriptor carries the property string
    /// `"provider=legacy"` for method-store matching.
    ///
    /// # C Equivalent
    ///
    /// Replaces `legacy_query()` switch dispatch from `legacyprov.c`.
    fn query_operation(&self, op: OperationType) -> Option<Vec<AlgorithmDescriptor>> {
        if !self.running {
            return None;
        }

        match op {
            OperationType::Digest => Some(DIGEST_TABLE.clone()),
            OperationType::Cipher => Some(CIPHER_TABLE.clone()),
            OperationType::Kdf => Some(KDF_TABLE.clone()),
            // The legacy provider does not supply Mac, Rand, KeyMgmt,
            // Signature, AsymCipher, Kem, KeyExch, EncoderDecoder, or Store.
            // Note: C legacyprov.c also provides OSSL_OP_SKEYMGMT for generic
            // secret key management, but the Rust provider framework handles
            // that through the default provider's keymgmt module instead.
            _ => None,
        }
    }

    /// Returns provider parameters as a typed [`ParamSet`].
    ///
    /// The parameter set contains:
    /// - `"name"` — provider display name (`UTF8`)
    /// - `"version"` — provider version string (`UTF8`)
    /// - `"buildinfo"` — build information string (`UTF8`)
    /// - `"status"` — running status as `i32` (1 = running, 0 = stopped)
    ///
    /// # C Equivalent
    ///
    /// Replaces `legacy_get_params()` from `legacyprov.c`.
    fn get_params(&self) -> ProviderResult<ParamSet> {
        let status_value: i32 = i32::from(self.running);
        let params = ParamBuilder::new()
            .push_utf8("name", PROVIDER_NAME.to_string())
            .push_utf8("version", PROVIDER_VERSION.to_string())
            .push_utf8("buildinfo", PROVIDER_BUILD_INFO.to_string())
            .push_i32("status", status_value)
            .build();
        Ok(params)
    }

    /// Returns the list of parameter names that [`get_params()`](Self::get_params)
    /// can provide.
    ///
    /// # C Equivalent
    ///
    /// Replaces the static `legacy_gettable_params` array from `legacyprov.c`.
    fn gettable_params(&self) -> Vec<&'static str> {
        vec!["name", "version", "buildinfo", "status"]
    }

    /// Returns `true` if this provider instance is currently operational.
    ///
    /// A provider becomes non-operational after [`teardown()`](Self::teardown)
    /// is called.  Non-operational providers return `None` from
    /// [`query_operation()`](Self::query_operation).
    ///
    /// # C Equivalent
    ///
    /// Replaces `ossl_prov_is_running()` from `prov_running.c` (which
    /// unconditionally returns `1` for non-FIPS providers; the Rust
    /// version tracks actual state).
    fn is_running(&self) -> bool {
        self.running
    }

    /// Shuts down this provider instance, marking it as non-operational.
    ///
    /// After teardown, [`is_running()`](Self::is_running) returns `false`
    /// and [`query_operation()`](Self::query_operation) returns `None`.
    ///
    /// Logs an `info!` event for provider lifecycle observability.
    ///
    /// # C Equivalent
    ///
    /// Replaces `legacy_teardown()` from `legacyprov.c`.
    fn teardown(&mut self) -> ProviderResult<()> {
        info!(provider = PROVIDER_NAME, "Legacy provider teardown");
        self.running = false;
        Ok(())
    }
}

// =============================================================================
// Algorithm Table Construction — Digests
// =============================================================================

/// Builds the legacy digest algorithm descriptor table.
///
/// Includes the five deprecated hash algorithms maintained for backward
/// compatibility — matching the `legacy_digests[]` array from
/// `legacyprov.c` lines 42–62.
///
/// | Algorithm   | C Guard                | Names (primary + aliases)        |
/// |-------------|------------------------|----------------------------------|
/// | MD2         | `OPENSSL_NO_MD2`       | `"MD2"`                          |
/// | MD4         | `OPENSSL_NO_MD4`       | `"MD4"`                          |
/// | MDC2        | `OPENSSL_NO_MDC2`      | `"MDC2"`                         |
/// | Whirlpool   | `OPENSSL_NO_WHIRLPOOL` | `"WHIRLPOOL"`                    |
/// | RIPEMD-160  | `OPENSSL_NO_RMD160`    | `"RIPEMD-160"`, `"RIPEMD160"`    |
fn build_digest_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // MD2 — 128-bit hash, severely broken, retained for PKCS#1 v1.5 compat.
        // C guard: OPENSSL_NO_MD2
        AlgorithmDescriptor {
            names: vec!["MD2"],
            property: LEGACY_PROPERTY,
            description: "MD2 128-bit message digest (legacy, deprecated)",
        },
        // MD4 — 128-bit hash, broken, retained for legacy protocol compat.
        // C guard: OPENSSL_NO_MD4
        AlgorithmDescriptor {
            names: vec!["MD4"],
            property: LEGACY_PROPERTY,
            description: "MD4 128-bit message digest (legacy, deprecated)",
        },
        // MDC2 — DES-based hash, rarely used.
        // C guard: OPENSSL_NO_MDC2
        AlgorithmDescriptor {
            names: vec!["MDC2"],
            property: LEGACY_PROPERTY,
            description: "MDC2 128-bit DES-based message digest (legacy)",
        },
        // Whirlpool — 512-bit hash based on AES-derived block cipher.
        // C guard: OPENSSL_NO_WHIRLPOOL
        AlgorithmDescriptor {
            names: vec!["WHIRLPOOL"],
            property: LEGACY_PROPERTY,
            description: "Whirlpool 512-bit message digest (legacy)",
        },
        // RIPEMD-160 — 160-bit hash, used in Bitcoin address generation.
        // C guard: OPENSSL_NO_RMD160
        AlgorithmDescriptor {
            names: vec!["RIPEMD-160", "RIPEMD160", "RMD160"],
            property: LEGACY_PROPERTY,
            description: "RIPEMD-160 160-bit message digest (legacy)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Ciphers
// =============================================================================

/// Builds the legacy cipher algorithm descriptor table.
///
/// Includes all deprecated cipher families and their mode variants —
/// matching the `legacy_ciphers[]` array from `legacyprov.c` lines 64–148.
///
/// Each cipher family provides CBC, ECB, CFB, and OFB modes (where
/// applicable).  RC2 additionally provides 40-bit and 64-bit key variants.
/// RC4 includes the RC4-HMAC-MD5 composite.  DES includes DESX.
///
/// | Family   | C Guard             | Mode Variants                         |
/// |----------|---------------------|---------------------------------------|
/// | CAST5    | `OPENSSL_NO_CAST`   | CBC, ECB, CFB, OFB                    |
/// | Blowfish | `OPENSSL_NO_BF`     | CBC, ECB, CFB, OFB                    |
/// | IDEA     | `OPENSSL_NO_IDEA`   | CBC, ECB, CFB, OFB                    |
/// | SEED     | `OPENSSL_NO_SEED`   | CBC, ECB, CFB, OFB                    |
/// | RC2      | `OPENSSL_NO_RC2`    | CBC, 40-CBC, 64-CBC, ECB, CFB, OFB    |
/// | RC4      | `OPENSSL_NO_RC4`    | RC4, RC4-40, RC4-HMAC-MD5             |
/// | RC5      | `OPENSSL_NO_RC5`    | CBC, ECB, CFB, OFB                    |
/// | DES      | `OPENSSL_NO_DES`    | ECB, CBC, OFB, CFB, CFB1, CFB8, DESX  |
fn build_cipher_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // =====================================================================
        // CAST5 (C guard: OPENSSL_NO_CAST)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["CAST5-CBC"],
            property: LEGACY_PROPERTY,
            description: "CAST5 cipher in CBC mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["CAST5-ECB"],
            property: LEGACY_PROPERTY,
            description: "CAST5 cipher in ECB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["CAST5-CFB"],
            property: LEGACY_PROPERTY,
            description: "CAST5 cipher in CFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["CAST5-OFB"],
            property: LEGACY_PROPERTY,
            description: "CAST5 cipher in OFB mode (legacy)",
        },
        // =====================================================================
        // Blowfish (C guard: OPENSSL_NO_BF)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["BF-CBC", "BLOWFISH-CBC"],
            property: LEGACY_PROPERTY,
            description: "Blowfish cipher in CBC mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["BF-ECB", "BLOWFISH-ECB"],
            property: LEGACY_PROPERTY,
            description: "Blowfish cipher in ECB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["BF-CFB", "BLOWFISH-CFB"],
            property: LEGACY_PROPERTY,
            description: "Blowfish cipher in CFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["BF-OFB", "BLOWFISH-OFB"],
            property: LEGACY_PROPERTY,
            description: "Blowfish cipher in OFB mode (legacy)",
        },
        // =====================================================================
        // IDEA (C guard: OPENSSL_NO_IDEA)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["IDEA-CBC"],
            property: LEGACY_PROPERTY,
            description: "IDEA cipher in CBC mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["IDEA-ECB"],
            property: LEGACY_PROPERTY,
            description: "IDEA cipher in ECB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["IDEA-CFB"],
            property: LEGACY_PROPERTY,
            description: "IDEA cipher in CFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["IDEA-OFB"],
            property: LEGACY_PROPERTY,
            description: "IDEA cipher in OFB mode (legacy)",
        },
        // =====================================================================
        // SEED (C guard: OPENSSL_NO_SEED)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["SEED-CBC"],
            property: LEGACY_PROPERTY,
            description: "SEED cipher in CBC mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["SEED-ECB"],
            property: LEGACY_PROPERTY,
            description: "SEED cipher in ECB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["SEED-CFB"],
            property: LEGACY_PROPERTY,
            description: "SEED cipher in CFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["SEED-OFB"],
            property: LEGACY_PROPERTY,
            description: "SEED cipher in OFB mode (legacy)",
        },
        // =====================================================================
        // RC2 (C guard: OPENSSL_NO_RC2)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["RC2-CBC", "RC2"],
            property: LEGACY_PROPERTY,
            description: "RC2 cipher in CBC mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC2-40-CBC"],
            property: LEGACY_PROPERTY,
            description: "RC2 cipher in CBC mode with 40-bit effective key (legacy, export-grade)",
        },
        AlgorithmDescriptor {
            names: vec!["RC2-64-CBC"],
            property: LEGACY_PROPERTY,
            description: "RC2 cipher in CBC mode with 64-bit effective key (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC2-ECB"],
            property: LEGACY_PROPERTY,
            description: "RC2 cipher in ECB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC2-CFB"],
            property: LEGACY_PROPERTY,
            description: "RC2 cipher in CFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC2-OFB"],
            property: LEGACY_PROPERTY,
            description: "RC2 cipher in OFB mode (legacy)",
        },
        // =====================================================================
        // RC4 (C guard: OPENSSL_NO_RC4)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["RC4"],
            property: LEGACY_PROPERTY,
            description: "RC4 stream cipher (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC4-40"],
            property: LEGACY_PROPERTY,
            description: "RC4 stream cipher with 40-bit key (legacy, export-grade)",
        },
        // RC4-HMAC-MD5: double-gated in C with OPENSSL_NO_RC4 && OPENSSL_NO_MD5.
        // Included here unconditionally as the legacy feature controls availability.
        AlgorithmDescriptor {
            names: vec!["RC4-HMAC-MD5"],
            property: LEGACY_PROPERTY,
            description: "RC4 stream cipher with HMAC-MD5 (legacy, TLS optimization)",
        },
        // =====================================================================
        // RC5 (C guard: OPENSSL_NO_RC5)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["RC5-CBC", "RC5"],
            property: LEGACY_PROPERTY,
            description: "RC5 cipher in CBC mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC5-ECB"],
            property: LEGACY_PROPERTY,
            description: "RC5 cipher in ECB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC5-CFB"],
            property: LEGACY_PROPERTY,
            description: "RC5 cipher in CFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["RC5-OFB"],
            property: LEGACY_PROPERTY,
            description: "RC5 cipher in OFB mode (legacy)",
        },
        // =====================================================================
        // DES (C guard: OPENSSL_NO_DES)
        // =====================================================================
        AlgorithmDescriptor {
            names: vec!["DES-ECB"],
            property: LEGACY_PROPERTY,
            description: "DES cipher in ECB mode (legacy, single-key 56-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-CBC"],
            property: LEGACY_PROPERTY,
            description: "DES cipher in CBC mode (legacy, single-key 56-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-OFB"],
            property: LEGACY_PROPERTY,
            description: "DES cipher in OFB mode (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-CFB"],
            property: LEGACY_PROPERTY,
            description: "DES cipher in CFB mode (legacy, 64-bit feedback)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-CFB1"],
            property: LEGACY_PROPERTY,
            description: "DES cipher in CFB mode with 1-bit feedback (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-CFB8"],
            property: LEGACY_PROPERTY,
            description: "DES cipher in CFB mode with 8-bit feedback (legacy)",
        },
        // DESX — XOR whitening extension of DES.
        AlgorithmDescriptor {
            names: vec!["DESX-CBC"],
            property: LEGACY_PROPERTY,
            description: "DESX cipher in CBC mode — DES with XOR whitening (legacy)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — KDFs
// =============================================================================

/// Builds the legacy KDF algorithm descriptor table.
///
/// Includes two deprecated key derivation functions — matching the
/// `legacy_kdfs[]` array from `legacyprov.c` lines 150–158.
///
/// | Algorithm | C Guard              | Description                       |
/// |-----------|----------------------|-----------------------------------|
/// | PBKDF1    | *(always present)*   | PKCS#5 v1 password-based KDF      |
/// | PVKKDF    | `OPENSSL_NO_PVKKDF`  | PVK (Private Key) file KDF        |
fn build_kdf_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // PBKDF1 — PKCS#5 v1 password-based key derivation.
        // Superseded by PBKDF2 in the default provider; retained for
        // backward compatibility with legacy key stores and protocols.
        AlgorithmDescriptor {
            names: vec!["PBKDF1"],
            property: LEGACY_PROPERTY,
            description: "PKCS#5 v1 password-based key derivation function (legacy)",
        },
        // PVK KDF — key derivation for Microsoft PVK (Private Key) file format.
        // C guard: OPENSSL_NO_PVKKDF
        AlgorithmDescriptor {
            names: vec!["PVKKDF"],
            property: LEGACY_PROPERTY,
            description: "PVK file format key derivation function (legacy)",
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_name_matches_c_exactly() {
        let provider = LegacyProvider::new();
        let info = provider.info();
        assert_eq!(info.name, "OpenSSL Legacy Provider");
    }

    #[test]
    fn test_provider_starts_running() {
        let provider = LegacyProvider::new();
        assert!(provider.is_running());
        assert!(provider.info().status);
    }

    #[test]
    fn test_teardown_stops_provider() {
        let mut provider = LegacyProvider::new();
        assert!(provider.is_running());

        let result = provider.teardown();
        assert!(result.is_ok());
        assert!(!provider.is_running());
        assert!(!provider.info().status);
    }

    #[test]
    fn test_query_digests_returns_table() {
        let provider = LegacyProvider::new();
        let digests = provider.query_operation(OperationType::Digest);
        assert!(digests.is_some());
        let table = digests.unwrap();
        assert_eq!(table.len(), 5);
        // Verify all five legacy digests are present
        let names: Vec<&str> = table.iter().flat_map(|d| d.names.iter().copied()).collect();
        assert!(names.contains(&"MD2"));
        assert!(names.contains(&"MD4"));
        assert!(names.contains(&"MDC2"));
        assert!(names.contains(&"WHIRLPOOL"));
        assert!(names.contains(&"RIPEMD-160"));
    }

    #[test]
    fn test_query_ciphers_returns_table() {
        let provider = LegacyProvider::new();
        let ciphers = provider.query_operation(OperationType::Cipher);
        assert!(ciphers.is_some());
        let table = ciphers.unwrap();
        // CAST5(4) + BF(4) + IDEA(4) + SEED(4) + RC2(6) + RC4(3) + RC5(4) + DES(7) = 36
        assert_eq!(table.len(), 36);
    }

    #[test]
    fn test_query_kdfs_returns_table() {
        let provider = LegacyProvider::new();
        let kdfs = provider.query_operation(OperationType::Kdf);
        assert!(kdfs.is_some());
        let table = kdfs.unwrap();
        assert_eq!(table.len(), 2);
        let names: Vec<&str> = table.iter().flat_map(|d| d.names.iter().copied()).collect();
        assert!(names.contains(&"PBKDF1"));
        assert!(names.contains(&"PVKKDF"));
    }

    #[test]
    fn test_query_unsupported_operations_return_none() {
        let provider = LegacyProvider::new();
        assert!(provider.query_operation(OperationType::Mac).is_none());
        assert!(provider.query_operation(OperationType::Rand).is_none());
        assert!(provider.query_operation(OperationType::KeyMgmt).is_none());
        assert!(provider.query_operation(OperationType::Signature).is_none());
        assert!(provider
            .query_operation(OperationType::AsymCipher)
            .is_none());
        assert!(provider.query_operation(OperationType::Kem).is_none());
        assert!(provider.query_operation(OperationType::KeyExch).is_none());
        assert!(provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none());
        assert!(provider.query_operation(OperationType::Store).is_none());
    }

    #[test]
    fn test_query_returns_none_after_teardown() {
        let mut provider = LegacyProvider::new();
        provider.teardown().unwrap();
        assert!(provider.query_operation(OperationType::Digest).is_none());
        assert!(provider.query_operation(OperationType::Cipher).is_none());
        assert!(provider.query_operation(OperationType::Kdf).is_none());
    }

    #[test]
    fn test_all_algorithms_have_legacy_property() {
        let provider = LegacyProvider::new();
        for op in [
            OperationType::Digest,
            OperationType::Cipher,
            OperationType::Kdf,
        ] {
            if let Some(table) = provider.query_operation(op) {
                for desc in &table {
                    assert_eq!(
                        desc.property, "provider=legacy",
                        "Algorithm {:?} has wrong property: {}",
                        desc.names, desc.property
                    );
                }
            }
        }
    }

    #[test]
    fn test_get_params_returns_correct_values() {
        let provider = LegacyProvider::new();
        let params = provider.get_params().unwrap();

        // Use get_typed::<String> — the correct ParamSet API for UTF-8 param values.
        let name: String = params.get_typed("name").expect("name param missing");
        assert_eq!(name, "OpenSSL Legacy Provider");

        let version: String = params.get_typed("version").expect("version param missing");
        assert_eq!(version, "4.0.0");

        let buildinfo: String = params
            .get_typed("buildinfo")
            .expect("buildinfo param missing");
        assert_eq!(buildinfo, "openssl-rs 4.0.0");

        // Status should be 1 (running).
        let status: i32 = params.get_typed("status").expect("status param missing");
        assert_eq!(status, 1);
    }

    #[test]
    fn test_gettable_params_keys() {
        let provider = LegacyProvider::new();
        let keys = provider.gettable_params();
        assert_eq!(keys, vec!["name", "version", "buildinfo", "status"]);
    }

    #[test]
    fn test_default_trait_produces_running_provider() {
        let provider = LegacyProvider::default();
        assert!(provider.is_running());
    }

    #[test]
    fn test_clone_preserves_state() {
        let mut provider = LegacyProvider::new();
        let cloned = provider.clone();
        assert!(cloned.is_running());

        provider.teardown().unwrap();
        // Clone was taken before teardown, so it should still be running.
        assert!(cloned.is_running());
        assert!(!provider.is_running());
    }

    #[test]
    fn test_cipher_families_present() {
        let provider = LegacyProvider::new();
        let ciphers = provider.query_operation(OperationType::Cipher).unwrap();
        let all_names: Vec<&str> = ciphers
            .iter()
            .flat_map(|d| d.names.iter().copied())
            .collect();

        // Verify at least one representative from each cipher family.
        assert!(all_names.contains(&"CAST5-CBC"), "missing CAST5");
        assert!(all_names.contains(&"BF-CBC"), "missing Blowfish");
        assert!(all_names.contains(&"IDEA-CBC"), "missing IDEA");
        assert!(all_names.contains(&"SEED-CBC"), "missing SEED");
        assert!(all_names.contains(&"RC2-CBC"), "missing RC2");
        assert!(all_names.contains(&"RC4"), "missing RC4");
        assert!(all_names.contains(&"RC5-CBC"), "missing RC5");
        assert!(all_names.contains(&"DES-CBC"), "missing DES");
        assert!(all_names.contains(&"DESX-CBC"), "missing DESX");
    }

    #[test]
    fn test_debug_impl() {
        let provider = LegacyProvider::new();
        let debug_str = format!("{:?}", provider);
        assert!(debug_str.contains("LegacyProvider"));
        assert!(debug_str.contains("running: true"));
    }
}
