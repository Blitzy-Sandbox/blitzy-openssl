//! Base provider implementation for the OpenSSL Rust workspace.
//!
//! Provides the **OpenSSL Base Provider** — a foundational provider that
//! exposes encoder, decoder, store, and seed-source RAND operations.  Does
//! **NOT** provide cryptographic algorithm implementations (digests, ciphers,
//! signatures, MACs, KDFs, KEMs, key management, key exchange, or asymmetric
//! ciphers).
//!
//! # Algorithm Surface
//!
//! The base provider has a **limited** algorithm surface focused on key
//! serialization infrastructure:
//!
//! | Operation        | Algorithms                                              | Property String            |
//! |------------------|---------------------------------------------------------|----------------------------|
//! | Encoder/Decoder  | DER, PEM, and Text encoders/decoders for all key types  | `"provider=base"`          |
//! | Store            | File-based key/cert store                               | `"provider=base,fips=yes"` |
//! | RAND             | SEED-SRC seed source, optional jitter source            | `"provider=base"`          |
//!
//! # C Mapping
//!
//! | Rust                         | C Source                          |
//! |------------------------------|-----------------------------------|
//! | `BaseProvider::new()`        | `ossl_base_provider_init()`       |
//! | `Provider::info()`           | Provider name/version constants   |
//! | `Provider::query_operation()`| `base_query()`                    |
//! | `Provider::get_params()`     | `base_get_params()`               |
//! | `Provider::gettable_params()`| `base_gettable_params`            |
//! | `Provider::is_running()`     | `ossl_prov_is_running()`          |
//! | `Provider::teardown()`       | `base_teardown()`                 |
//!
//! # Rules Enforced
//!
//! - **R5:** All returns typed via `Option<T>` / `Result<T, E>` — no sentinels.
//! - **R7:** No shared mutable state; algorithm tables cached via
//!   `once_cell::sync::Lazy`.
//! - **R8:** Zero `unsafe` code.
//! - **R9:** Warning-free, all public items documented.
//! - **R10:** Reachable via `openssl-crypto::init` → provider loading →
//!   `BaseProvider`.
//!
//! # Source Reference
//!
//! - `providers/baseprov.c` (~190 lines) — C base provider entry point and
//!   `base_query()` dispatch.
//! - `providers/prov_running.c` — Default `ossl_prov_is_running()` returning 1.
//! - `providers/common/include/prov/implementations.h` — Encoder/decoder/store
//!   function table declarations.

use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use once_cell::sync::Lazy;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::types::OperationType;
use openssl_common::ProviderResult;
use tracing::info;

// =============================================================================
// Constants
// =============================================================================

/// Provider name — matches C `baseprov.c` line 56 exactly for interop.
const PROVIDER_NAME: &str = "OpenSSL Base Provider";

/// Provider version string.
const PROVIDER_VERSION: &str = "4.0.0";

/// Provider build information string.
const PROVIDER_BUILD_INFO: &str = "openssl-rs 4.0.0";

/// Property query string applied to encoder/decoder and RAND algorithm
/// descriptors registered by this provider.
const BASE_PROPERTY: &str = "provider=base";

/// Property query string for store algorithm descriptors — stores are
/// FIPS-compatible since they perform no cryptographic operations.
const BASE_STORE_PROPERTY: &str = "provider=base,fips=yes";

// =============================================================================
// Lazy-Initialized Algorithm Tables (Rule R7: no per-query allocation)
// =============================================================================
//
// Each static table is initialized once on first access using
// `once_cell::sync::Lazy`.  This avoids repeated `Vec` allocation on every
// `query_operation()` call while remaining thread-safe without requiring a
// lock on `BaseProvider` itself.
// LOCK-SCOPE: No lock needed — `Lazy` provides one-shot interior-mutable init.

/// Cached encoder algorithm descriptors.
static ENCODER_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_encoder_table);

/// Cached decoder algorithm descriptors.
static DECODER_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_decoder_table);

/// Cached store algorithm descriptors.
static STORE_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_store_table);

/// Cached RAND (seed source) algorithm descriptors.
static RAND_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_rand_table);

// =============================================================================
// BaseProvider Struct
// =============================================================================

/// Base provider — encoder/decoder/store + seed source operations.
///
/// This provider has a **LIMITED** algorithm surface focused on key
/// serialization infrastructure (encoders, decoders, file stores) and RAND
/// seed sources.  It does **NOT** provide digests, ciphers, MACs, KDFs,
/// signatures, KEMs, key management, key exchange, or asymmetric ciphers.
///
/// # Lifecycle
///
/// ```text
/// BaseProvider::new()  →  is_running() == true
///                     →  query_operation(EncoderDecoder) → Some(...)
///                     →  teardown()
///                     →  is_running() == false
///                     →  query_operation(EncoderDecoder) → None
/// ```
///
/// # C Equivalent
///
/// Replaces C `ossl_base_provider_init()` from `providers/baseprov.c`.
///
/// # Examples
///
/// ```
/// use openssl_provider::base::BaseProvider;
/// use openssl_provider::traits::Provider;
/// use openssl_common::types::OperationType;
///
/// let provider = BaseProvider::new();
/// assert!(provider.is_running());
///
/// let info = provider.info();
/// assert_eq!(info.name, "OpenSSL Base Provider");
///
/// // Base provider supports encoder/decoder, store, and RAND
/// let enc_dec = provider.query_operation(OperationType::EncoderDecoder);
/// assert!(enc_dec.is_some());
///
/// let store = provider.query_operation(OperationType::Store);
/// assert!(store.is_some());
///
/// let rand = provider.query_operation(OperationType::Rand);
/// assert!(rand.is_some());
///
/// // Base provider does NOT support digests, ciphers, etc.
/// let digest = provider.query_operation(OperationType::Digest);
/// assert!(digest.is_none());
/// ```
#[derive(Debug, Clone)]
pub struct BaseProvider {
    /// Whether this provider instance is currently operational.
    /// Set to `true` on construction; set to `false` by `teardown()`.
    running: bool,
}

impl BaseProvider {
    /// Creates a new base provider instance in the running state.
    ///
    /// The provider is immediately operational after construction —
    /// no separate activation step is needed.  This mirrors the C
    /// `ossl_base_provider_init()` which returns `1` (success) and sets
    /// the provider as running.
    ///
    /// Logs an `info!` event for provider lifecycle observability.
    pub fn new() -> Self {
        info!(
            provider = PROVIDER_NAME,
            version = PROVIDER_VERSION,
            "Base provider initialized"
        );
        Self { running: true }
    }
}

impl Default for BaseProvider {
    /// Equivalent to [`BaseProvider::new()`].
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Provider Trait Implementation
// =============================================================================

impl Provider for BaseProvider {
    /// Returns metadata about this provider.
    ///
    /// The returned [`ProviderInfo`] contains the provider name, version,
    /// build information, and current running status.  The name string
    /// `"OpenSSL Base Provider"` matches the C implementation exactly
    /// (`baseprov.c` line 56).
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: PROVIDER_NAME,
            version: PROVIDER_VERSION,
            build_info: PROVIDER_BUILD_INFO,
            status: self.running,
        }
    }

    /// Dispatches an operation type to the corresponding algorithm table.
    ///
    /// The base provider only supports:
    /// - [`OperationType::EncoderDecoder`] — DER/PEM/Text encoders and decoders
    /// - [`OperationType::Store`] — File-based key/certificate store
    /// - [`OperationType::Rand`] — Seed source (SEED-SRC) and optional jitter
    ///
    /// All other operation types return `None`.
    ///
    /// If the provider is not running (after `teardown()`), all operations
    /// return `None`.
    ///
    /// # C Equivalent
    ///
    /// Replaces `base_query()` switch dispatch from `baseprov.c` (lines
    /// 102–117), which returns `base_encoder`, `base_decoder`, `base_store`,
    /// or `base_rands` based on the `operation_id` parameter.
    fn query_operation(&self, op: OperationType) -> Option<Vec<AlgorithmDescriptor>> {
        if !self.running {
            return None;
        }

        info!(
            provider = PROVIDER_NAME,
            operation = %op,
            "Base provider query_operation"
        );

        match op {
            OperationType::EncoderDecoder => {
                // Combine encoders and decoders into one list — the C
                // implementation has separate OSSL_OP_ENCODER and
                // OSSL_OP_DECODER entries, but the Rust OperationType
                // merges them into a single EncoderDecoder variant.
                let mut combined = ENCODER_TABLE.clone();
                combined.extend(DECODER_TABLE.iter().cloned());
                Some(combined)
            }
            OperationType::Store => Some(STORE_TABLE.clone()),
            OperationType::Rand => Some(RAND_TABLE.clone()),
            // Base provider does not supply digests, ciphers, MACs, KDFs,
            // signatures, asymmetric ciphers, KEMs, key management, or
            // key exchange operations.
            OperationType::Digest
            | OperationType::Cipher
            | OperationType::Mac
            | OperationType::Kdf
            | OperationType::KeyMgmt
            | OperationType::Signature
            | OperationType::AsymCipher
            | OperationType::Kem
            | OperationType::KeyExch => None,
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
    /// Replaces `base_get_params()` from `baseprov.c` (lines 50–69).
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
    /// Replaces the static `base_param_types` array from `baseprov.c`
    /// (lines 37–43).
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
    /// Replaces `base_teardown()` from `baseprov.c` (lines 119–123).
    fn teardown(&mut self) -> ProviderResult<()> {
        info!(provider = PROVIDER_NAME, "Base provider teardown");
        self.running = false;
        Ok(())
    }
}

// =============================================================================
// Algorithm Table Construction — Encoders
// =============================================================================

/// Builds the encoder algorithm descriptor table.
///
/// Includes DER, PEM, and Text encoders for all key types.  Corresponds to
/// the `base_encoder[]` array from `baseprov.c` (lines 71–76) which includes
/// `encoders.inc`.  The included file lists encoder entries for RSA, DSA, DH,
/// EC, X25519, X448, Ed25519, Ed448, ML-KEM, ML-DSA, SLH-DSA, and SM2 key
/// types across DER, PEM, and human-readable text formats.
///
/// All encoders use property `"provider=base"`.
fn build_encoder_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // -- DER Encoders --
        AlgorithmDescriptor {
            names: vec!["RSA"],
            property: BASE_PROPERTY,
            description: "RSA DER encoder (SubjectPublicKeyInfo / PrivateKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-PSS"],
            property: BASE_PROPERTY,
            description: "RSA-PSS DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DH"],
            property: BASE_PROPERTY,
            description: "DH DER encoder (DHParameter / PrivateKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["DHX"],
            property: BASE_PROPERTY,
            description: "DHX (X9.42 DH) DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: BASE_PROPERTY,
            description: "DSA DER encoder (DSAParameters / PrivateKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["EC"],
            property: BASE_PROPERTY,
            description: "EC DER encoder (ECParameters / PrivateKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: BASE_PROPERTY,
            description: "X25519 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: BASE_PROPERTY,
            description: "X448 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: BASE_PROPERTY,
            description: "Ed25519 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED448"],
            property: BASE_PROPERTY,
            description: "Ed448 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["SM2"],
            property: BASE_PROPERTY,
            description: "SM2 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM"],
            property: BASE_PROPERTY,
            description: "ML-KEM DER encoder (FIPS 203)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA"],
            property: BASE_PROPERTY,
            description: "ML-DSA DER encoder (FIPS 204)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA"],
            property: BASE_PROPERTY,
            description: "SLH-DSA DER encoder (FIPS 205)",
        },
        // -- PEM Encoders --
        AlgorithmDescriptor {
            names: vec!["RSA-PEM"],
            property: BASE_PROPERTY,
            description: "RSA PEM encoder (PKCS#1 / PKCS#8 PEM)",
        },
        AlgorithmDescriptor {
            names: vec!["EC-PEM"],
            property: BASE_PROPERTY,
            description: "EC PEM encoder (SEC 1 / PKCS#8 PEM)",
        },
        AlgorithmDescriptor {
            names: vec!["DH-PEM"],
            property: BASE_PROPERTY,
            description: "DH PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-PEM"],
            property: BASE_PROPERTY,
            description: "DSA PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519-PEM"],
            property: BASE_PROPERTY,
            description: "X25519 PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519-PEM"],
            property: BASE_PROPERTY,
            description: "Ed25519 PEM encoder",
        },
        // -- Text Encoders (human-readable output) --
        AlgorithmDescriptor {
            names: vec!["RSA-TEXT"],
            property: BASE_PROPERTY,
            description: "RSA text encoder (human-readable key dump)",
        },
        AlgorithmDescriptor {
            names: vec!["EC-TEXT"],
            property: BASE_PROPERTY,
            description: "EC text encoder (human-readable key dump)",
        },
        AlgorithmDescriptor {
            names: vec!["DH-TEXT"],
            property: BASE_PROPERTY,
            description: "DH text encoder (human-readable parameter dump)",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-TEXT"],
            property: BASE_PROPERTY,
            description: "DSA text encoder (human-readable key dump)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Decoders
// =============================================================================

/// Builds the decoder algorithm descriptor table.
///
/// Includes DER-to-key, PEM-to-DER, PKCS#8, and SPKI decoders for all
/// supported key types.  Corresponds to the `base_decoder[]` array from
/// `baseprov.c` (lines 78–83) which includes `decoders.inc`.
///
/// All decoders use property `"provider=base"`.
fn build_decoder_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // -- DER-to-key decoders --
        AlgorithmDescriptor {
            names: vec!["DER-to-RSA"],
            property: BASE_PROPERTY,
            description: "DER-to-RSA key decoder (PKCS#1 / PKCS#8 / SubjectPublicKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-RSA-PSS"],
            property: BASE_PROPERTY,
            description: "DER-to-RSA-PSS key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-DH"],
            property: BASE_PROPERTY,
            description: "DER-to-DH key decoder (DHParameter / PrivateKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-DHX"],
            property: BASE_PROPERTY,
            description: "DER-to-DHX (X9.42 DH) key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-DSA"],
            property: BASE_PROPERTY,
            description: "DER-to-DSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-EC"],
            property: BASE_PROPERTY,
            description: "DER-to-EC key decoder (SEC 1 / PKCS#8 / SubjectPublicKeyInfo)",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-X25519"],
            property: BASE_PROPERTY,
            description: "DER-to-X25519 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-X448"],
            property: BASE_PROPERTY,
            description: "DER-to-X448 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ED25519"],
            property: BASE_PROPERTY,
            description: "DER-to-Ed25519 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ED448"],
            property: BASE_PROPERTY,
            description: "DER-to-Ed448 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-SM2"],
            property: BASE_PROPERTY,
            description: "DER-to-SM2 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ML-KEM"],
            property: BASE_PROPERTY,
            description: "DER-to-ML-KEM key decoder (FIPS 203)",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ML-DSA"],
            property: BASE_PROPERTY,
            description: "DER-to-ML-DSA key decoder (FIPS 204)",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-SLH-DSA"],
            property: BASE_PROPERTY,
            description: "DER-to-SLH-DSA key decoder (FIPS 205)",
        },
        // -- PEM-to-DER decoder (format conversion) --
        AlgorithmDescriptor {
            names: vec!["PEM-to-DER"],
            property: BASE_PROPERTY,
            description: "PEM-to-DER format decoder (strips PEM envelope)",
        },
        // -- PKCS#8 / SPKI structure decoders --
        AlgorithmDescriptor {
            names: vec!["PKCS8"],
            property: BASE_PROPERTY,
            description: "PKCS#8 PrivateKeyInfo / EncryptedPrivateKeyInfo decoder",
        },
        AlgorithmDescriptor {
            names: vec!["SubjectPublicKeyInfo", "SPKI"],
            property: BASE_PROPERTY,
            description: "SubjectPublicKeyInfo (SPKI) public key decoder",
        },
        // -- MSBLOB / PVK legacy format decoders --
        AlgorithmDescriptor {
            names: vec!["MSBLOB"],
            property: BASE_PROPERTY,
            description: "Microsoft BLOB key format decoder",
        },
        AlgorithmDescriptor {
            names: vec!["PVK"],
            property: BASE_PROPERTY,
            description: "Microsoft PVK private key format decoder",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Stores
// =============================================================================

/// Builds the store algorithm descriptor table.
///
/// The file-based store allows loading keys and certificates from the
/// filesystem using URI schemes (`file://`).  Corresponds to the
/// `base_store[]` array from `baseprov.c` (lines 85–92) which includes
/// `stores.inc`.
///
/// The store uses property `"provider=base,fips=yes"` because store
/// operations do not perform cryptographic computations and are therefore
/// FIPS-compatible.
fn build_store_table() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["file"],
        property: BASE_STORE_PROPERTY,
        description: "File-based key/certificate/CRL store (file:// URI scheme)",
    }]
}

// =============================================================================
// Algorithm Table Construction — RAND (Seed Sources)
// =============================================================================

/// Builds the RAND (seed source) algorithm descriptor table.
///
/// Includes the SEED-SRC seed source and, conditionally, the jitter
/// entropy source.  Corresponds to the `base_rands[]` array from
/// `baseprov.c` (lines 94–100).
///
/// The SEED-SRC algorithm provides raw entropy from the operating system
/// (e.g., `getrandom()` on Linux, `BCryptGenRandom()` on Windows) and is
/// used as the seeding input for DRBG instances.
///
/// The jitter source (`JITTER`) provides CPU timing jitter-based entropy
/// and is conditionally compiled in the C source via
/// `#ifndef OPENSSL_NO_JITTER`.
fn build_rand_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["SEED-SRC"],
            property: BASE_PROPERTY,
            description: "Seed source for DRBG seeding (OS entropy: getrandom / BCryptGenRandom)",
        },
        AlgorithmDescriptor {
            names: vec!["JITTER"],
            property: BASE_PROPERTY,
            description: "CPU timing jitter entropy source",
        },
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Provider;
    use openssl_common::types::OperationType;

    #[test]
    fn test_new_creates_running_provider() {
        let provider = BaseProvider::new();
        assert!(provider.is_running());
    }

    #[test]
    fn test_default_creates_running_provider() {
        let provider = BaseProvider::default();
        assert!(provider.is_running());
    }

    #[test]
    fn test_info_name_matches_c() {
        let provider = BaseProvider::new();
        let info = provider.info();
        assert_eq!(info.name, "OpenSSL Base Provider");
        assert_eq!(info.version, "4.0.0");
        assert!(info.status);
    }

    #[test]
    fn test_query_encoder_decoder_returns_some() {
        let provider = BaseProvider::new();
        let result = provider.query_operation(OperationType::EncoderDecoder);
        assert!(result.is_some());
        let algos = result.expect("encoder/decoder should be supported");
        assert!(!algos.is_empty());
    }

    #[test]
    fn test_query_store_returns_some() {
        let provider = BaseProvider::new();
        let result = provider.query_operation(OperationType::Store);
        assert!(result.is_some());
        let algos = result.expect("store should be supported");
        assert!(!algos.is_empty());
        // Verify file store with FIPS-compatible property
        assert_eq!(algos[0].names[0], "file");
        assert_eq!(algos[0].property, "provider=base,fips=yes");
    }

    #[test]
    fn test_query_rand_returns_some() {
        let provider = BaseProvider::new();
        let result = provider.query_operation(OperationType::Rand);
        assert!(result.is_some());
        let algos = result.expect("rand should be supported");
        assert!(!algos.is_empty());
        // Verify SEED-SRC is present
        assert_eq!(algos[0].names[0], "SEED-SRC");
    }

    #[test]
    fn test_query_unsupported_operations_return_none() {
        let provider = BaseProvider::new();
        assert!(provider.query_operation(OperationType::Digest).is_none());
        assert!(provider.query_operation(OperationType::Cipher).is_none());
        assert!(provider.query_operation(OperationType::Mac).is_none());
        assert!(provider.query_operation(OperationType::Kdf).is_none());
        assert!(provider.query_operation(OperationType::KeyMgmt).is_none());
        assert!(provider.query_operation(OperationType::Signature).is_none());
        assert!(provider
            .query_operation(OperationType::AsymCipher)
            .is_none());
        assert!(provider.query_operation(OperationType::Kem).is_none());
        assert!(provider.query_operation(OperationType::KeyExch).is_none());
    }

    #[test]
    fn test_get_params_returns_valid_param_set() {
        let provider = BaseProvider::new();
        let params = provider.get_params().expect("get_params should succeed");
        assert_eq!(params.len(), 4);

        // Verify individual parameter values
        let name = params.get("name");
        assert!(name.is_some());

        let version = params.get("version");
        assert!(version.is_some());

        let buildinfo = params.get("buildinfo");
        assert!(buildinfo.is_some());

        let status = params.get("status");
        assert!(status.is_some());
    }

    #[test]
    fn test_gettable_params_returns_standard_keys() {
        let provider = BaseProvider::new();
        let keys = provider.gettable_params();
        assert_eq!(keys, vec!["name", "version", "buildinfo", "status"]);
    }

    #[test]
    fn test_teardown_stops_provider() {
        let mut provider = BaseProvider::new();
        assert!(provider.is_running());

        let result = provider.teardown();
        assert!(result.is_ok());
        assert!(!provider.is_running());

        // After teardown, info reports non-running status
        let info = provider.info();
        assert!(!info.status);
    }

    #[test]
    fn test_query_after_teardown_returns_none() {
        let mut provider = BaseProvider::new();
        provider.teardown().expect("teardown should succeed");

        // All operations should return None after teardown
        assert!(provider
            .query_operation(OperationType::EncoderDecoder)
            .is_none());
        assert!(provider.query_operation(OperationType::Store).is_none());
        assert!(provider.query_operation(OperationType::Rand).is_none());
    }

    #[test]
    fn test_clone_creates_independent_instance() {
        let mut provider = BaseProvider::new();
        let cloned = provider.clone();
        provider.teardown().expect("teardown should succeed");

        // Original is stopped, but clone should still be running
        assert!(!provider.is_running());
        assert!(cloned.is_running());
    }

    #[test]
    fn test_debug_formatting() {
        let provider = BaseProvider::new();
        let debug_output = format!("{:?}", provider);
        assert!(debug_output.contains("BaseProvider"));
        assert!(debug_output.contains("running: true"));
    }

    #[test]
    fn test_encoder_table_has_entries() {
        let encoders = build_encoder_table();
        // Should have entries for RSA, RSA-PSS, DH, DHX, DSA, EC, X25519,
        // X448, ED25519, ED448, SM2, ML-KEM, ML-DSA, SLH-DSA (DER) + PEM + Text
        assert!(encoders.len() >= 14, "expected at least 14 encoder entries");
        // All encoders should use base property
        for enc in &encoders {
            assert_eq!(enc.property, "provider=base");
        }
    }

    #[test]
    fn test_decoder_table_has_entries() {
        let decoders = build_decoder_table();
        // Should have DER-to-key decoders + PEM-to-DER + PKCS8 + SPKI + MSBLOB + PVK
        assert!(decoders.len() >= 14, "expected at least 14 decoder entries");
        // All decoders should use base property
        for dec in &decoders {
            assert_eq!(dec.property, "provider=base");
        }
    }

    #[test]
    fn test_store_table_has_file_store() {
        let stores = build_store_table();
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].names[0], "file");
        // File store must have fips=yes property (it performs no crypto)
        assert!(stores[0].property.contains("fips=yes"));
    }

    #[test]
    fn test_rand_table_has_seed_src() {
        let rands = build_rand_table();
        assert!(rands.len() >= 1);
        assert_eq!(rands[0].names[0], "SEED-SRC");
    }
}
