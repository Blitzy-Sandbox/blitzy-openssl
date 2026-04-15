//! Default provider implementation for the OpenSSL Rust workspace.
//!
//! Provides the **OpenSSL Default Provider** — the standard non-FIPS algorithm
//! catalog covering all twelve operation categories:
//!
//! | Category         | Examples                                               |
//! |------------------|--------------------------------------------------------|
//! | Digests          | SHA-1, SHA-2, SHA-3, SHAKE, BLAKE2, SM3, MD5, RIPEMD   |
//! | Ciphers          | AES (all modes), ChaCha20-Poly1305, 3DES, Camellia     |
//! | MACs             | HMAC, GMAC, KMAC, CMAC, BLAKE2-MAC, SipHash, Poly1305  |
//! | KDFs             | HKDF, PBKDF2, Argon2, scrypt, KBKDF, TLS1-PRF          |
//! | Key Exchange     | DH, ECDH, X25519/X448                                  |
//! | RAND             | CTR/Hash/HMAC DRBG, seed source, jitter, test RNG       |
//! | Signatures       | RSA, DSA, ECDSA, EdDSA, ML-DSA, SLH-DSA, LMS           |
//! | Asymmetric Cipher| RSA, SM2                                                |
//! | KEM              | RSA, EC/ECX DHKEM, ML-KEM, hybrid MLX                   |
//! | Key Management   | RSA, EC, DH, DSA, ECX, PQ, MAC/KDF legacy               |
//! | Encoder/Decoder  | DER/PEM/Text for all key types                          |
//! | Store            | File store, Windows cert store                          |
//!
//! All algorithms are tagged with the property string `"provider=default"`.
//! This is the **primary provider** loaded automatically by `LibContext`.
//!
//! # Feature Gating
//!
//! Category-level features from `Cargo.toml` control whether entire
//! algorithm families are registered in the dispatch table:
//!
//! - `digests`, `ciphers`, `macs`, `kdfs`, `exchange`, `rands`,
//!   `signatures`, `kem`, `keymgmt`, `encode-decode`, `store`
//!
//! All features are enabled by default, matching the full algorithm set
//! of the C `providers/defltprov.c` default provider.
//!
//! # C Mapping
//!
//! | Rust                          | C Source                          |
//! |-------------------------------|-----------------------------------|
//! | `DefaultProvider::new()`      | `ossl_default_provider_init()`    |
//! | `Provider::info()`            | Provider name/version constants   |
//! | `Provider::query_operation()` | `deflt_query()`                   |
//! | `Provider::get_params()`      | `deflt_get_params()`              |
//! | `Provider::gettable_params()` | `deflt_gettable_params`           |
//! | `Provider::is_running()`      | `ossl_prov_is_running()`          |
//! | `Provider::teardown()`        | `deflt_teardown()`                |
//!
//! # Rules Enforced
//!
//! - **R5:** All returns typed via `Option<T>` / `Result<T, E>` — no sentinels
//! - **R7:** No shared mutable state; algorithm tables cached via `once_cell::sync::Lazy`
//! - **R8:** Zero `unsafe` code
//! - **R9:** Warning-free, all public items documented
//! - **R10:** Reachable via `openssl-crypto::init` → provider loading → `DefaultProvider`

use crate::traits::{AlgorithmDescriptor, Provider, ProviderInfo};
use once_cell::sync::Lazy;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::types::OperationType;
use openssl_common::ProviderResult;
use tracing::info;

// =============================================================================
// Constants
// =============================================================================

/// Provider name — must match C `defltprov.c` exactly for interop.
const PROVIDER_NAME: &str = "OpenSSL Default Provider";

/// Provider version string.
const PROVIDER_VERSION: &str = "4.0.0";

/// Provider build information string.
const PROVIDER_BUILD_INFO: &str = "openssl-rs 4.0.0";

/// Property query string applied to every algorithm descriptor registered
/// by this provider. Used by the method store for algorithm fetch/match.
const DEFAULT_PROPERTY: &str = "provider=default";

// =============================================================================
// Lazy-Initialized Algorithm Tables (Rule R7: no per-query allocation)
// =============================================================================
//
// Each static table is initialized once on first access using `once_cell::sync::Lazy`.
// This avoids repeated `Vec` allocation on every `query_operation()` call while
// remaining thread-safe without requiring a lock on `DefaultProvider` itself.
// LOCK-SCOPE: No lock needed — `Lazy` provides one-shot interior-mutable init.

/// Cached digest algorithm descriptors.
static DIGEST_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_digest_table);

/// Cached cipher algorithm descriptors.
static CIPHER_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_cipher_table);

/// Cached MAC algorithm descriptors.
static MAC_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_mac_table);

/// Cached KDF algorithm descriptors.
static KDF_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_kdf_table);

/// Cached key-exchange algorithm descriptors.
static KEYEXCH_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_keyexch_table);

/// Cached RAND/DRBG algorithm descriptors.
static RAND_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_rand_table);

/// Cached signature algorithm descriptors.
static SIGNATURE_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_signature_table);

/// Cached asymmetric cipher algorithm descriptors.
static ASYM_CIPHER_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_asym_cipher_table);

/// Cached KEM algorithm descriptors.
static KEM_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_kem_table);

/// Cached key-management algorithm descriptors.
static KEYMGMT_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_keymgmt_table);

/// Cached encoder/decoder algorithm descriptors.
static ENCODER_DECODER_TABLE: Lazy<Vec<AlgorithmDescriptor>> =
    Lazy::new(build_encoder_decoder_table);

/// Cached store algorithm descriptors.
static STORE_TABLE: Lazy<Vec<AlgorithmDescriptor>> = Lazy::new(build_store_table);

// =============================================================================
// DefaultProvider Struct
// =============================================================================

/// Default provider — implements the standard non-FIPS algorithm catalog.
///
/// This is the primary provider loaded automatically by `LibContext`.
/// It provides all standard algorithm families (digests, ciphers, MACs,
/// KDFs, key exchange, RAND/DRBG, signatures, asymmetric ciphers, KEM,
/// key management, encoders/decoders, and stores).
///
/// All algorithms are tagged with property `"provider=default"`.
///
/// # C Equivalent
///
/// Replaces C `ossl_default_provider_init()` from `providers/defltprov.c`.
///
/// # Examples
///
/// ```
/// use openssl_provider::default::DefaultProvider;
/// use openssl_provider::traits::Provider;
/// use openssl_common::types::OperationType;
///
/// let provider = DefaultProvider::new();
/// assert!(provider.is_running());
///
/// let info = provider.info();
/// assert_eq!(info.name, "OpenSSL Default Provider");
///
/// let digests = provider.query_operation(OperationType::Digest);
/// assert!(digests.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct DefaultProvider {
    /// Whether this provider instance is currently operational.
    /// Set to `true` on construction; set to `false` by `teardown()`.
    running: bool,
}

impl DefaultProvider {
    /// Creates a new default provider instance in the running state.
    ///
    /// The provider is immediately operational after construction —
    /// no separate activation step is needed. This mirrors the C
    /// `ossl_default_provider_init()` which returns `1` (success)
    /// and sets the provider as running.
    ///
    /// Logs an `info!` event for provider lifecycle observability.
    pub fn new() -> Self {
        info!(
            provider = PROVIDER_NAME,
            version = PROVIDER_VERSION,
            "Default provider initialized"
        );
        Self { running: true }
    }
}

impl Default for DefaultProvider {
    /// Equivalent to [`DefaultProvider::new()`].
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Provider Trait Implementation
// =============================================================================

impl Provider for DefaultProvider {
    /// Returns metadata about this provider.
    ///
    /// The returned [`ProviderInfo`] contains the provider name, version,
    /// build information, and current running status. The name string
    /// `"OpenSSL Default Provider"` matches the C implementation exactly.
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
    /// Returns `Some(table)` with the full list of [`AlgorithmDescriptor`]s
    /// for the requested operation, or `None` if the provider is not
    /// running or the operation category feature is disabled.
    ///
    /// Each algorithm descriptor carries the property string
    /// `"provider=default"` for method-store matching.
    ///
    /// # C Equivalent
    ///
    /// Replaces `deflt_query()` switch dispatch from `defltprov.c`.
    fn query_operation(&self, op: OperationType) -> Option<Vec<AlgorithmDescriptor>> {
        if !self.running {
            return None;
        }

        match op {
            #[cfg(feature = "digests")]
            OperationType::Digest => Some(DIGEST_TABLE.clone()),

            #[cfg(feature = "ciphers")]
            OperationType::Cipher => Some(CIPHER_TABLE.clone()),

            #[cfg(feature = "macs")]
            OperationType::Mac => Some(MAC_TABLE.clone()),

            #[cfg(feature = "kdfs")]
            OperationType::Kdf => Some(KDF_TABLE.clone()),

            #[cfg(feature = "rands")]
            OperationType::Rand => Some(RAND_TABLE.clone()),

            #[cfg(feature = "keymgmt")]
            OperationType::KeyMgmt => Some(KEYMGMT_TABLE.clone()),

            #[cfg(feature = "signatures")]
            OperationType::Signature => Some(SIGNATURE_TABLE.clone()),

            OperationType::AsymCipher => Some(ASYM_CIPHER_TABLE.clone()),

            #[cfg(feature = "kem")]
            OperationType::Kem => Some(KEM_TABLE.clone()),

            #[cfg(feature = "exchange")]
            OperationType::KeyExch => Some(KEYEXCH_TABLE.clone()),

            #[cfg(feature = "encode-decode")]
            OperationType::EncoderDecoder => Some(ENCODER_DECODER_TABLE.clone()),

            #[cfg(feature = "store")]
            OperationType::Store => Some(STORE_TABLE.clone()),

            // If the corresponding feature is disabled, the arm is not generated
            // and the match falls through to this wildcard which returns None.
            #[allow(unreachable_patterns)]
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
    /// Replaces `deflt_get_params()` from `defltprov.c`.
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
    /// Replaces the static `deflt_gettable_params` array from `defltprov.c`.
    fn gettable_params(&self) -> Vec<&'static str> {
        vec!["name", "version", "buildinfo", "status"]
    }

    /// Returns `true` if this provider instance is currently operational.
    ///
    /// A provider becomes non-operational after [`teardown()`](Self::teardown)
    /// is called. Non-operational providers return `None` from
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
    /// Replaces `deflt_teardown()` from `defltprov.c`.
    fn teardown(&mut self) -> ProviderResult<()> {
        info!(provider = PROVIDER_NAME, "Default provider teardown");
        self.running = false;
        Ok(())
    }
}

// =============================================================================
// Algorithm Table Construction — Digests
// =============================================================================

/// Builds the digest algorithm descriptor table.
///
/// Includes SHA-1, SHA-2, SHA-3, SHAKE, BLAKE2, SM3, MD5, RIPEMD-160,
/// NULL, KECCAK, and ML-DSA-MU hash variants — matching the
/// `deflt_digests[]` array from `defltprov.c` lines 101–169.
fn build_digest_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["SHA1", "SHA-1", "SSL3-SHA1"],
            property: DEFAULT_PROPERTY,
            description: "SHA-1 message digest (160-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-224", "SHA-224", "SHA224"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 224-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-256", "SHA-256", "SHA256"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 256-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-256/192", "SHA-256/192"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 256-bit digest truncated to 192 bits",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-384", "SHA-384", "SHA384"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 384-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-512", "SHA-512", "SHA512"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 512-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-512/224", "SHA-512/224", "SHA512-224"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 512-bit digest truncated to 224 bits",
        },
        AlgorithmDescriptor {
            names: vec!["SHA2-512/256", "SHA-512/256", "SHA512-256"],
            property: DEFAULT_PROPERTY,
            description: "SHA-2 512-bit digest truncated to 256 bits",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-224"],
            property: DEFAULT_PROPERTY,
            description: "SHA-3 224-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-256"],
            property: DEFAULT_PROPERTY,
            description: "SHA-3 256-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-384"],
            property: DEFAULT_PROPERTY,
            description: "SHA-3 384-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-512"],
            property: DEFAULT_PROPERTY,
            description: "SHA-3 512-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-224"],
            property: DEFAULT_PROPERTY,
            description: "KECCAK 224-bit digest (raw Keccak, pre-SHA-3 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-256"],
            property: DEFAULT_PROPERTY,
            description: "KECCAK 256-bit digest (raw Keccak, pre-SHA-3 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-384"],
            property: DEFAULT_PROPERTY,
            description: "KECCAK 384-bit digest (raw Keccak, pre-SHA-3 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-512"],
            property: DEFAULT_PROPERTY,
            description: "KECCAK 512-bit digest (raw Keccak, pre-SHA-3 padding)",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-KECCAK-128"],
            property: DEFAULT_PROPERTY,
            description: "cSHAKE-KECCAK 128-bit customizable XOF",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-KECCAK-256"],
            property: DEFAULT_PROPERTY,
            description: "cSHAKE-KECCAK 256-bit customizable XOF",
        },
        AlgorithmDescriptor {
            names: vec!["SHAKE-128", "SHAKE128"],
            property: DEFAULT_PROPERTY,
            description: "SHAKE-128 extendable output function",
        },
        AlgorithmDescriptor {
            names: vec!["SHAKE-256", "SHAKE256"],
            property: DEFAULT_PROPERTY,
            description: "SHAKE-256 extendable output function",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-128"],
            property: DEFAULT_PROPERTY,
            description: "cSHAKE-128 customizable extendable output function",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-256"],
            property: DEFAULT_PROPERTY,
            description: "cSHAKE-256 customizable extendable output function",
        },
        // BLAKE2 (C guard: OPENSSL_NO_BLAKE2)
        AlgorithmDescriptor {
            names: vec!["BLAKE2S-256", "BLAKE2s256"],
            property: DEFAULT_PROPERTY,
            description: "BLAKE2s 256-bit message digest",
        },
        AlgorithmDescriptor {
            names: vec!["BLAKE2B-512", "BLAKE2b512"],
            property: DEFAULT_PROPERTY,
            description: "BLAKE2b 512-bit message digest",
        },
        // SM3 (C guard: OPENSSL_NO_SM3)
        AlgorithmDescriptor {
            names: vec!["SM3"],
            property: DEFAULT_PROPERTY,
            description: "SM3 256-bit message digest (Chinese national standard)",
        },
        // MD5 (C guard: OPENSSL_NO_MD5)
        AlgorithmDescriptor {
            names: vec!["MD5", "SSL3-MD5"],
            property: DEFAULT_PROPERTY,
            description: "MD5 128-bit message digest (legacy)",
        },
        AlgorithmDescriptor {
            names: vec!["MD5-SHA1"],
            property: DEFAULT_PROPERTY,
            description: "MD5+SHA1 concatenated digest for SSLv3 compatibility",
        },
        // RIPEMD-160 (C guard: OPENSSL_NO_RMD160)
        AlgorithmDescriptor {
            names: vec!["RIPEMD-160", "RIPEMD160", "RMD160"],
            property: DEFAULT_PROPERTY,
            description: "RIPEMD-160 160-bit message digest",
        },
        // NULL digest
        AlgorithmDescriptor {
            names: vec!["NULL"],
            property: DEFAULT_PROPERTY,
            description: "Null digest — no-op passthrough",
        },
        // ML-DSA-MU (C guard: OPENSSL_NO_ML_DSA)
        AlgorithmDescriptor {
            names: vec!["ML-DSA-MU"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA mu-hash for multi-use signature context",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Ciphers
// =============================================================================

/// Builds the cipher algorithm descriptor table (~100+ entries).
///
/// This is the largest algorithm table, matching `deflt_ciphers[]` from
/// `defltprov.c` lines 171–341. Includes AES (all modes and key sizes),
/// ARIA, Camellia, DES/3DES, SM4, `ChaCha20`, and `ChaCha20-Poly1305`.
fn build_cipher_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // NULL cipher
        AlgorithmDescriptor {
            names: vec!["NULL"],
            property: DEFAULT_PROPERTY,
            description: "Null cipher — no-op passthrough",
        },
        // --- AES-256 ---
        AlgorithmDescriptor {
            names: vec!["AES-256-ECB"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC", "AES256"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-CTS"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit CBC with ciphertext stealing",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-OFB"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CFB"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Cipher Feedback mode (full block)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CTR"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-XTS"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit XEX-based Tweaked-codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-GCM"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CCM"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-WRAP", "AES256WRAP", "id-aes256-wrap"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit key wrap (RFC 3394)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-WRAP-PAD", "AES256WRAPPAD", "id-aes256-wrap-pad"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit key wrap with padding (RFC 5649)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-WRAP-INV"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit key wrap inverse",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-WRAP-PAD-INV"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit key wrap with padding inverse",
        },
        // AES-256 OCB (C guard: OPENSSL_NO_OCB)
        AlgorithmDescriptor {
            names: vec!["AES-256-OCB"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Offset Codebook mode (AEAD)",
        },
        // AES-256 SIV (C guard: OPENSSL_NO_SIV)
        AlgorithmDescriptor {
            names: vec!["AES-256-SIV"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit Synthetic IV (nonce misuse resistant)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-GCM-SIV"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit GCM-SIV (nonce misuse resistant AEAD)",
        },
        // --- AES-192 ---
        AlgorithmDescriptor {
            names: vec!["AES-192-ECB"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CBC", "AES192"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CBC-CTS"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit CBC with ciphertext stealing",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-OFB"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CFB"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Cipher Feedback mode (full block)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CTR"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-GCM"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CCM"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-WRAP", "AES192WRAP", "id-aes192-wrap"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit key wrap (RFC 3394)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-WRAP-PAD", "AES192WRAPPAD", "id-aes192-wrap-pad"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit key wrap with padding (RFC 5649)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-WRAP-INV"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit key wrap inverse",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-WRAP-PAD-INV"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit key wrap with padding inverse",
        },
        // AES-192 OCB
        AlgorithmDescriptor {
            names: vec!["AES-192-OCB"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Offset Codebook mode (AEAD)",
        },
        // AES-192 SIV
        AlgorithmDescriptor {
            names: vec!["AES-192-SIV"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit Synthetic IV (nonce misuse resistant)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-GCM-SIV"],
            property: DEFAULT_PROPERTY,
            description: "AES 192-bit GCM-SIV (nonce misuse resistant AEAD)",
        },
        // --- AES-128 ---
        AlgorithmDescriptor {
            names: vec!["AES-128-ECB"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC", "AES128"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-CTS"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit CBC with ciphertext stealing",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-OFB"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CFB"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Cipher Feedback mode (full block)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CTR"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-XTS"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit XEX-based Tweaked-codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-GCM"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CCM"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-WRAP", "AES128WRAP", "id-aes128-wrap"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit key wrap (RFC 3394)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-WRAP-PAD", "AES128WRAPPAD", "id-aes128-wrap-pad"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit key wrap with padding (RFC 5649)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-WRAP-INV"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit key wrap inverse",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-WRAP-PAD-INV"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit key wrap with padding inverse",
        },
        // AES-128 OCB
        AlgorithmDescriptor {
            names: vec!["AES-128-OCB"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Offset Codebook mode (AEAD)",
        },
        // AES-128 SIV
        AlgorithmDescriptor {
            names: vec!["AES-128-SIV"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit Synthetic IV (nonce misuse resistant)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-GCM-SIV"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit GCM-SIV (nonce misuse resistant AEAD)",
        },
        // AES-CBC-HMAC composite (TLS)
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA1"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit CBC with HMAC-SHA1 (TLS composite)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA1"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit CBC with HMAC-SHA1 (TLS composite)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA256"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit CBC with HMAC-SHA256 (TLS composite)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA256"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit CBC with HMAC-SHA256 (TLS composite)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA256-ETM"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit CBC with HMAC-SHA256 encrypt-then-MAC",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA256-ETM"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit CBC with HMAC-SHA256 encrypt-then-MAC",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA512-ETM"],
            property: DEFAULT_PROPERTY,
            description: "AES 128-bit CBC with HMAC-SHA512 encrypt-then-MAC",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA512-ETM"],
            property: DEFAULT_PROPERTY,
            description: "AES 256-bit CBC with HMAC-SHA512 encrypt-then-MAC",
        },
        // ARIA (C guard: OPENSSL_NO_ARIA)
        AlgorithmDescriptor {
            names: vec!["ARIA-256-GCM"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-GCM"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-GCM"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-CCM"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-CCM"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-CCM"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-ECB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-ECB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-ECB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-CBC", "ARIA256"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-CBC", "ARIA192"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-CBC", "ARIA128"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-OFB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-OFB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-OFB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-CFB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-CFB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-CFB"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-256-CTR"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 256-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-192-CTR"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 192-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["ARIA-128-CTR"],
            property: DEFAULT_PROPERTY,
            description: "ARIA 128-bit Counter mode",
        },
        // Camellia (C guard: OPENSSL_NO_CAMELLIA)
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-ECB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-ECB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-ECB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-CBC", "CAMELLIA256"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-CBC", "CAMELLIA192"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-CBC", "CAMELLIA128"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-OFB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-OFB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-OFB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-CFB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-CFB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-CFB"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-256-CTR"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 256-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-192-CTR"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 192-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["CAMELLIA-128-CTR"],
            property: DEFAULT_PROPERTY,
            description: "Camellia 128-bit Counter mode",
        },
        // DES/3DES (C guard: OPENSSL_NO_DES)
        AlgorithmDescriptor {
            names: vec!["DES-EDE3-ECB", "DES-EDE3"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES (EDE3) Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE3-CBC", "DES3"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES (EDE3) Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE3-OFB"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES (EDE3) Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE3-CFB"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES (EDE3) Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE3-CFB8"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES (EDE3) Cipher Feedback mode (8-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE3-CFB1"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES (EDE3) Cipher Feedback mode (1-bit)",
        },
        AlgorithmDescriptor {
            names: vec!["DES3-WRAP", "id-smime-alg-CMS3DESwrap"],
            property: DEFAULT_PROPERTY,
            description: "Triple DES key wrap (RFC 3217)",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE-ECB", "DES-EDE"],
            property: DEFAULT_PROPERTY,
            description: "Two-key Triple DES (EDE) Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE-CBC"],
            property: DEFAULT_PROPERTY,
            description: "Two-key Triple DES (EDE) Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE-OFB"],
            property: DEFAULT_PROPERTY,
            description: "Two-key Triple DES (EDE) Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["DES-EDE-CFB"],
            property: DEFAULT_PROPERTY,
            description: "Two-key Triple DES (EDE) Cipher Feedback mode",
        },
        // SM4 (C guard: OPENSSL_NO_SM4)
        AlgorithmDescriptor {
            names: vec!["SM4-ECB"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Electronic Codebook mode",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-CBC", "SM4"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Cipher Block Chaining mode",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-CTR"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Counter mode",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-OFB"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Output Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-CFB"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Cipher Feedback mode",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-GCM"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Galois/Counter mode (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-CCM"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit Counter with CBC-MAC (AEAD)",
        },
        AlgorithmDescriptor {
            names: vec!["SM4-XTS"],
            property: DEFAULT_PROPERTY,
            description: "SM4 128-bit XEX-based Tweaked-codebook mode",
        },
        // ChaCha20 (C guard: OPENSSL_NO_CHACHA)
        AlgorithmDescriptor {
            names: vec!["ChaCha20"],
            property: DEFAULT_PROPERTY,
            description: "ChaCha20 stream cipher (RFC 8439)",
        },
        // ChaCha20-Poly1305 (C guard: OPENSSL_NO_CHACHA && OPENSSL_NO_POLY1305)
        AlgorithmDescriptor {
            names: vec!["ChaCha20-Poly1305"],
            property: DEFAULT_PROPERTY,
            description: "ChaCha20-Poly1305 AEAD cipher (RFC 8439)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — MACs
// =============================================================================

/// Builds the MAC algorithm descriptor table.
///
/// Matches `deflt_macs[]` from `defltprov.c` lines 344–363.
fn build_mac_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // BLAKE2 MACs (C guard: OPENSSL_NO_BLAKE2)
        AlgorithmDescriptor {
            names: vec!["BLAKE2BMAC"],
            property: DEFAULT_PROPERTY,
            description: "BLAKE2b-based MAC",
        },
        AlgorithmDescriptor {
            names: vec!["BLAKE2SMAC"],
            property: DEFAULT_PROPERTY,
            description: "BLAKE2s-based MAC",
        },
        // CMAC (C guard: OPENSSL_NO_CMAC)
        AlgorithmDescriptor {
            names: vec!["CMAC"],
            property: DEFAULT_PROPERTY,
            description: "Cipher-based MAC (NIST SP 800-38B)",
        },
        AlgorithmDescriptor {
            names: vec!["GMAC"],
            property: DEFAULT_PROPERTY,
            description: "Galois MAC (derived from AES-GCM)",
        },
        AlgorithmDescriptor {
            names: vec!["HMAC"],
            property: DEFAULT_PROPERTY,
            description: "Keyed-hash MAC (RFC 2104)",
        },
        AlgorithmDescriptor {
            names: vec!["KMAC-128", "KMAC128"],
            property: DEFAULT_PROPERTY,
            description: "KECCAK MAC 128-bit (NIST SP 800-185)",
        },
        AlgorithmDescriptor {
            names: vec!["KMAC-256", "KMAC256"],
            property: DEFAULT_PROPERTY,
            description: "KECCAK MAC 256-bit (NIST SP 800-185)",
        },
        // SipHash (C guard: OPENSSL_NO_SIPHASH)
        AlgorithmDescriptor {
            names: vec!["SIPHASH"],
            property: DEFAULT_PROPERTY,
            description: "SipHash MAC",
        },
        // Poly1305 (C guard: OPENSSL_NO_POLY1305)
        AlgorithmDescriptor {
            names: vec!["POLY1305"],
            property: DEFAULT_PROPERTY,
            description: "Poly1305 one-time MAC",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — KDFs
// =============================================================================

/// Builds the KDF algorithm descriptor table.
///
/// Matches `deflt_kdfs[]` from `defltprov.c` lines 365–412.
fn build_kdf_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["HKDF"],
            property: DEFAULT_PROPERTY,
            description: "HMAC-based Key Derivation Function (RFC 5869)",
        },
        AlgorithmDescriptor {
            names: vec!["HKDF-SHA256", "HKDF-SHA-256"],
            property: DEFAULT_PROPERTY,
            description: "HKDF with SHA-256",
        },
        AlgorithmDescriptor {
            names: vec!["HKDF-SHA384", "HKDF-SHA-384"],
            property: DEFAULT_PROPERTY,
            description: "HKDF with SHA-384",
        },
        AlgorithmDescriptor {
            names: vec!["HKDF-SHA512", "HKDF-SHA-512"],
            property: DEFAULT_PROPERTY,
            description: "HKDF with SHA-512",
        },
        AlgorithmDescriptor {
            names: vec!["TLS13-KDF"],
            property: DEFAULT_PROPERTY,
            description: "TLS 1.3 key schedule KDF",
        },
        AlgorithmDescriptor {
            names: vec!["TLS1-PRF"],
            property: DEFAULT_PROPERTY,
            description: "TLS 1.0/1.1/1.2 pseudo-random function",
        },
        AlgorithmDescriptor {
            names: vec!["PBKDF2"],
            property: DEFAULT_PROPERTY,
            description: "Password-Based KDF 2 (RFC 8018)",
        },
        AlgorithmDescriptor {
            names: vec!["PKCS12KDF"],
            property: DEFAULT_PROPERTY,
            description: "PKCS#12 key derivation",
        },
        // SSKDF (C guard: OPENSSL_NO_SSKDF)
        AlgorithmDescriptor {
            names: vec!["SSKDF"],
            property: DEFAULT_PROPERTY,
            description: "Single-Step KDF (NIST SP 800-56C Rev. 2)",
        },
        // SNMPKDF (C guard: OPENSSL_NO_SNMPKDF)
        AlgorithmDescriptor {
            names: vec!["SNMPKDF"],
            property: DEFAULT_PROPERTY,
            description: "SNMP USM key localization KDF",
        },
        // SRTPKDF (C guard: OPENSSL_NO_SRTPKDF)
        AlgorithmDescriptor {
            names: vec!["SRTPKDF"],
            property: DEFAULT_PROPERTY,
            description: "SRTP key derivation (RFC 3711)",
        },
        // SSHKDF (C guard: OPENSSL_NO_SSHKDF)
        AlgorithmDescriptor {
            names: vec!["SSHKDF"],
            property: DEFAULT_PROPERTY,
            description: "SSH key derivation (RFC 4253)",
        },
        // X963KDF (C guard: OPENSSL_NO_X963KDF)
        AlgorithmDescriptor {
            names: vec!["X963KDF", "X942KDF"],
            property: DEFAULT_PROPERTY,
            description: "ANSI X9.63 / X9.42 KDF",
        },
        // KBKDF (C guard: OPENSSL_NO_KBKDF)
        AlgorithmDescriptor {
            names: vec!["KBKDF"],
            property: DEFAULT_PROPERTY,
            description: "Key-Based KDF (NIST SP 800-108)",
        },
        // X942KDF-ASN1 (C guard: combined)
        AlgorithmDescriptor {
            names: vec!["X942KDF-ASN1"],
            property: DEFAULT_PROPERTY,
            description: "X9.42 KDF with ASN.1 key derivation parameters",
        },
        // SCRYPT (C guard: OPENSSL_NO_SCRYPT)
        AlgorithmDescriptor {
            names: vec!["SCRYPT", "id-scrypt"],
            property: DEFAULT_PROPERTY,
            description: "scrypt password-based KDF (RFC 7914)",
        },
        // KRB5KDF (C guard: OPENSSL_NO_KRB5KDF)
        AlgorithmDescriptor {
            names: vec!["KRB5KDF"],
            property: DEFAULT_PROPERTY,
            description: "Kerberos 5 key derivation",
        },
        // HMAC-DRBG-KDF (C guard: OPENSSL_NO_HMAC_DRBG_KDF)
        AlgorithmDescriptor {
            names: vec!["HMAC-DRBG-KDF"],
            property: DEFAULT_PROPERTY,
            description: "HMAC-DRBG used as a KDF",
        },
        // Argon2 (C guard: OPENSSL_NO_ARGON2)
        AlgorithmDescriptor {
            names: vec!["ARGON2I"],
            property: DEFAULT_PROPERTY,
            description: "Argon2i data-independent password hashing",
        },
        AlgorithmDescriptor {
            names: vec!["ARGON2D"],
            property: DEFAULT_PROPERTY,
            description: "Argon2d data-dependent password hashing",
        },
        AlgorithmDescriptor {
            names: vec!["ARGON2ID"],
            property: DEFAULT_PROPERTY,
            description: "Argon2id hybrid password hashing (RFC 9106)",
        },
        AlgorithmDescriptor {
            names: vec!["PVK-KDF"],
            property: DEFAULT_PROPERTY,
            description: "PVK private key file KDF",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Key Exchange
// =============================================================================

/// Builds the key-exchange algorithm descriptor table.
///
/// Matches `deflt_keyexch[]` from `defltprov.c` lines 414–430.
fn build_keyexch_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // DH (C guard: OPENSSL_NO_DH)
        AlgorithmDescriptor {
            names: vec!["DH"],
            property: DEFAULT_PROPERTY,
            description: "Diffie-Hellman key exchange",
        },
        // ECDH (C guard: OPENSSL_NO_EC)
        AlgorithmDescriptor {
            names: vec!["ECDH"],
            property: DEFAULT_PROPERTY,
            description: "Elliptic Curve Diffie-Hellman key exchange",
        },
        // X25519 / X448 (C guard: OPENSSL_NO_ECX)
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: DEFAULT_PROPERTY,
            description: "X25519 key exchange (RFC 7748)",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: DEFAULT_PROPERTY,
            description: "X448 key exchange (RFC 7748)",
        },
        // KDF-based key exchange adapters
        AlgorithmDescriptor {
            names: vec!["TLS1-PRF"],
            property: DEFAULT_PROPERTY,
            description: "TLS1-PRF key exchange adapter",
        },
        AlgorithmDescriptor {
            names: vec!["HKDF"],
            property: DEFAULT_PROPERTY,
            description: "HKDF key exchange adapter",
        },
        // SCRYPT (C guard: OPENSSL_NO_SCRYPT)
        AlgorithmDescriptor {
            names: vec!["SCRYPT"],
            property: DEFAULT_PROPERTY,
            description: "scrypt key exchange adapter",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — RAND/DRBG
// =============================================================================

/// Builds the RAND/DRBG algorithm descriptor table.
///
/// Matches `deflt_rands[]` from `defltprov.c` lines 432–442.
fn build_rand_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["CTR-DRBG"],
            property: DEFAULT_PROPERTY,
            description: "NIST SP 800-90A CTR_DRBG (AES-based)",
        },
        AlgorithmDescriptor {
            names: vec!["HASH-DRBG"],
            property: DEFAULT_PROPERTY,
            description: "NIST SP 800-90A Hash_DRBG",
        },
        AlgorithmDescriptor {
            names: vec!["HMAC-DRBG"],
            property: DEFAULT_PROPERTY,
            description: "NIST SP 800-90A HMAC_DRBG",
        },
        AlgorithmDescriptor {
            names: vec!["SEED-SRC"],
            property: DEFAULT_PROPERTY,
            description: "OS entropy seed source",
        },
        // JITTER (C guard: OPENSSL_NO_JITTER)
        AlgorithmDescriptor {
            names: vec!["JITTER"],
            property: DEFAULT_PROPERTY,
            description: "CPU jitter entropy source",
        },
        AlgorithmDescriptor {
            names: vec!["TEST-RAND"],
            property: DEFAULT_PROPERTY,
            description: "Deterministic test RNG (testing only)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Signatures
// =============================================================================

/// Builds the signature algorithm descriptor table.
///
/// Matches `deflt_signature[]` from `defltprov.c` lines 444–542.
/// Includes RSA, DSA, ECDSA, `EdDSA`, SM2, ML-DSA, SLH-DSA, LMS,
/// and MAC-as-signature adapters.
fn build_signature_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // DSA family (C guard: OPENSSL_NO_DSA)
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: DEFAULT_PROPERTY,
            description: "DSA signature algorithm",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA1", "DSA-SHA-1"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA-1",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA2-224", "DSA-SHA-224"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA-224",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA2-256", "DSA-SHA-256"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA-256",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA2-384", "DSA-SHA-384"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA-384",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA2-512", "DSA-SHA-512"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA-512",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA3-224"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA3-224",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA3-256"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA3-256",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA3-384"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA3-384",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-SHA3-512"],
            property: DEFAULT_PROPERTY,
            description: "DSA with SHA3-512",
        },
        // RSA family
        AlgorithmDescriptor {
            names: vec!["RSA"],
            property: DEFAULT_PROPERTY,
            description: "RSA signature algorithm",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA1", "RSA-SHA-1"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA-1",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA2-224", "RSA-SHA-224"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA-224",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA2-256", "RSA-SHA-256"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA-256",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA2-384", "RSA-SHA-384"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA-384",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA2-512", "RSA-SHA-512"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA-512",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA3-224"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA3-224",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA3-256"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA3-256",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA3-384"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA3-384",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SHA3-512"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SHA3-512",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-SM3"],
            property: DEFAULT_PROPERTY,
            description: "RSA with SM3 (Chinese national standard)",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-RIPEMD160"],
            property: DEFAULT_PROPERTY,
            description: "RSA with RIPEMD-160",
        },
        // EdDSA (C guard: OPENSSL_NO_ECX)
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 pure signature (RFC 8032)",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519ph"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 pre-hashed signature (RFC 8032)",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519ctx"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 with context signature (RFC 8032)",
        },
        AlgorithmDescriptor {
            names: vec!["ED448"],
            property: DEFAULT_PROPERTY,
            description: "Ed448 signature (RFC 8032)",
        },
        AlgorithmDescriptor {
            names: vec!["ED448ph"],
            property: DEFAULT_PROPERTY,
            description: "Ed448 pre-hashed signature (RFC 8032)",
        },
        // ECDSA (C guard: OPENSSL_NO_EC)
        AlgorithmDescriptor {
            names: vec!["ECDSA"],
            property: DEFAULT_PROPERTY,
            description: "Elliptic Curve DSA",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA1", "ECDSA-SHA-1"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA-1",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA2-224", "ECDSA-SHA-224"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA-224",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA2-256", "ECDSA-SHA-256"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA-256",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA2-384", "ECDSA-SHA-384"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA-384",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA2-512", "ECDSA-SHA-512"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA-512",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA3-224"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA3-224",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA3-256"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA3-256",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA3-384"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA3-384",
        },
        AlgorithmDescriptor {
            names: vec!["ECDSA-SHA3-512"],
            property: DEFAULT_PROPERTY,
            description: "ECDSA with SHA3-512",
        },
        // SM2 (C guard: OPENSSL_NO_SM2)
        AlgorithmDescriptor {
            names: vec!["SM2"],
            property: DEFAULT_PROPERTY,
            description: "SM2 digital signature (Chinese national standard)",
        },
        // ML-DSA (C guard: OPENSSL_NO_ML_DSA)
        AlgorithmDescriptor {
            names: vec!["ML-DSA-44"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA-44 post-quantum signature (FIPS 204)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA-65"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA-65 post-quantum signature (FIPS 204)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA-87"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA-87 post-quantum signature (FIPS 204)",
        },
        // MAC-as-signature adapters
        AlgorithmDescriptor {
            names: vec!["HMAC"],
            property: DEFAULT_PROPERTY,
            description: "HMAC used as signature algorithm",
        },
        AlgorithmDescriptor {
            names: vec!["SIPHASH"],
            property: DEFAULT_PROPERTY,
            description: "SipHash used as signature algorithm",
        },
        AlgorithmDescriptor {
            names: vec!["POLY1305"],
            property: DEFAULT_PROPERTY,
            description: "Poly1305 used as signature algorithm",
        },
        AlgorithmDescriptor {
            names: vec!["CMAC"],
            property: DEFAULT_PROPERTY,
            description: "CMAC used as signature algorithm",
        },
        // LMS (C guard: OPENSSL_NO_LMS)
        AlgorithmDescriptor {
            names: vec!["LMS"],
            property: DEFAULT_PROPERTY,
            description: "Leighton-Micali hash-based signature (SP 800-208)",
        },
        // SLH-DSA (C guard: OPENSSL_NO_SLH_DSA)
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-128S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 128-bit small signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-128F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 128-bit fast signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-192S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 192-bit small signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-192F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 192-bit fast signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-256S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 256-bit small signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-256F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 256-bit fast signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-128S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 128-bit small signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-128F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 128-bit fast signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-192S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 192-bit small signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-192F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 192-bit fast signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-256S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 256-bit small signature (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-256F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 256-bit fast signature (FIPS 205)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Asymmetric Ciphers
// =============================================================================

/// Builds the asymmetric cipher algorithm descriptor table.
///
/// Matches `deflt_asym_cipher[]` from `defltprov.c` lines 544–550.
fn build_asym_cipher_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: DEFAULT_PROPERTY,
            description: "RSA asymmetric encryption (PKCS#1 v1.5/OAEP)",
        },
        // SM2 (C guard: OPENSSL_NO_SM2)
        AlgorithmDescriptor {
            names: vec!["SM2"],
            property: DEFAULT_PROPERTY,
            description: "SM2 asymmetric encryption (Chinese national standard)",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — KEM
// =============================================================================

/// Builds the KEM (Key Encapsulation Mechanism) algorithm descriptor table.
///
/// Matches `deflt_asym_kem[]` from `defltprov.c` lines 552–578.
fn build_kem_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA"],
            property: DEFAULT_PROPERTY,
            description: "RSA key encapsulation mechanism",
        },
        // ECX DHKEM (C guard: OPENSSL_NO_ECX)
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: DEFAULT_PROPERTY,
            description: "X25519 DHKEM (RFC 9180)",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: DEFAULT_PROPERTY,
            description: "X448 DHKEM (RFC 9180)",
        },
        // EC DHKEM (C guard: OPENSSL_NO_EC)
        AlgorithmDescriptor {
            names: vec!["EC"],
            property: DEFAULT_PROPERTY,
            description: "EC DHKEM (RFC 9180)",
        },
        // ML-KEM (C guard: OPENSSL_NO_ML_KEM)
        AlgorithmDescriptor {
            names: vec!["ML-KEM-512"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM-512 post-quantum KEM (FIPS 203)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM-768"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM-768 post-quantum KEM (FIPS 203)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM-1024"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM-1024 post-quantum KEM (FIPS 203)",
        },
        // Hybrid KEM (C guard: OPENSSL_NO_ECX + OPENSSL_NO_ML_KEM)
        AlgorithmDescriptor {
            names: vec!["X25519MLKEM768"],
            property: DEFAULT_PROPERTY,
            description: "X25519 + ML-KEM-768 hybrid KEM",
        },
        AlgorithmDescriptor {
            names: vec!["X448MLKEM1024"],
            property: DEFAULT_PROPERTY,
            description: "X448 + ML-KEM-1024 hybrid KEM",
        },
        // Hybrid KEM (C guard: OPENSSL_NO_EC + OPENSSL_NO_ML_KEM)
        AlgorithmDescriptor {
            names: vec!["SecP256r1MLKEM768"],
            property: DEFAULT_PROPERTY,
            description: "P-256 + ML-KEM-768 hybrid KEM",
        },
        AlgorithmDescriptor {
            names: vec!["SecP384r1MLKEM1024"],
            property: DEFAULT_PROPERTY,
            description: "P-384 + ML-KEM-1024 hybrid KEM",
        },
        // SM2 hybrid (C guard: OPENSSL_NO_SM2 + OPENSSL_NO_ML_KEM)
        AlgorithmDescriptor {
            names: vec!["curveSM2MLKEM768"],
            property: DEFAULT_PROPERTY,
            description: "curveSM2 + ML-KEM-768 hybrid KEM",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Key Management
// =============================================================================

/// Builds the key management algorithm descriptor table.
///
/// Matches `deflt_keymgmt[]` from `defltprov.c` lines 580–696.
fn build_keymgmt_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // DH/DHX (C guard: OPENSSL_NO_DH)
        AlgorithmDescriptor {
            names: vec!["DH", "dhKeyAgreement"],
            property: DEFAULT_PROPERTY,
            description: "Diffie-Hellman key management",
        },
        AlgorithmDescriptor {
            names: vec!["DHX", "X9.42 DH", "dhpublicnumber"],
            property: DEFAULT_PROPERTY,
            description: "X9.42 Diffie-Hellman key management",
        },
        // DSA (C guard: OPENSSL_NO_DSA)
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: DEFAULT_PROPERTY,
            description: "DSA key management",
        },
        // RSA
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: DEFAULT_PROPERTY,
            description: "RSA key management",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-PSS", "RSASSA-PSS"],
            property: DEFAULT_PROPERTY,
            description: "RSA-PSS key management",
        },
        // EC (C guard: OPENSSL_NO_EC)
        AlgorithmDescriptor {
            names: vec!["EC", "id-ecPublicKey"],
            property: DEFAULT_PROPERTY,
            description: "Elliptic Curve key management",
        },
        // ECX (C guard: OPENSSL_NO_ECX)
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: DEFAULT_PROPERTY,
            description: "X25519 key management",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: DEFAULT_PROPERTY,
            description: "X448 key management",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 key management",
        },
        AlgorithmDescriptor {
            names: vec!["ED448"],
            property: DEFAULT_PROPERTY,
            description: "Ed448 key management",
        },
        // ML-DSA (C guard: OPENSSL_NO_ML_DSA)
        AlgorithmDescriptor {
            names: vec!["ML-DSA-44"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA-44 key management (FIPS 204)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA-65"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA-65 key management (FIPS 204)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA-87"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA-87 key management (FIPS 204)",
        },
        // KDF keymgmt
        AlgorithmDescriptor {
            names: vec!["TLS1-PRF"],
            property: DEFAULT_PROPERTY,
            description: "TLS1-PRF pseudo-key management",
        },
        AlgorithmDescriptor {
            names: vec!["HKDF"],
            property: DEFAULT_PROPERTY,
            description: "HKDF pseudo-key management",
        },
        AlgorithmDescriptor {
            names: vec!["SCRYPT"],
            property: DEFAULT_PROPERTY,
            description: "scrypt pseudo-key management",
        },
        // MAC legacy keymgmt
        AlgorithmDescriptor {
            names: vec!["HMAC"],
            property: DEFAULT_PROPERTY,
            description: "HMAC legacy key management",
        },
        AlgorithmDescriptor {
            names: vec!["SIPHASH"],
            property: DEFAULT_PROPERTY,
            description: "SipHash legacy key management",
        },
        AlgorithmDescriptor {
            names: vec!["POLY1305"],
            property: DEFAULT_PROPERTY,
            description: "Poly1305 legacy key management",
        },
        AlgorithmDescriptor {
            names: vec!["CMAC"],
            property: DEFAULT_PROPERTY,
            description: "CMAC legacy key management",
        },
        // SM2 (C guard: OPENSSL_NO_SM2)
        AlgorithmDescriptor {
            names: vec!["SM2"],
            property: DEFAULT_PROPERTY,
            description: "SM2 key management",
        },
        AlgorithmDescriptor {
            names: vec!["curveSM2"],
            property: DEFAULT_PROPERTY,
            description: "curveSM2 key management for hybrid KEM",
        },
        // LMS (C guard: OPENSSL_NO_LMS)
        AlgorithmDescriptor {
            names: vec!["LMS"],
            property: DEFAULT_PROPERTY,
            description: "LMS hash-based key management (SP 800-208)",
        },
        // ML-KEM (C guard: OPENSSL_NO_ML_KEM)
        AlgorithmDescriptor {
            names: vec!["ML-KEM-512"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM-512 key management (FIPS 203)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM-768"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM-768 key management (FIPS 203)",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM-1024"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM-1024 key management (FIPS 203)",
        },
        // Hybrid keymgmt
        AlgorithmDescriptor {
            names: vec!["X25519MLKEM768"],
            property: DEFAULT_PROPERTY,
            description: "X25519+ML-KEM-768 hybrid key management",
        },
        AlgorithmDescriptor {
            names: vec!["X448MLKEM1024"],
            property: DEFAULT_PROPERTY,
            description: "X448+ML-KEM-1024 hybrid key management",
        },
        AlgorithmDescriptor {
            names: vec!["SecP256r1MLKEM768"],
            property: DEFAULT_PROPERTY,
            description: "P-256+ML-KEM-768 hybrid key management",
        },
        AlgorithmDescriptor {
            names: vec!["SecP384r1MLKEM1024"],
            property: DEFAULT_PROPERTY,
            description: "P-384+ML-KEM-1024 hybrid key management",
        },
        AlgorithmDescriptor {
            names: vec!["curveSM2MLKEM768"],
            property: DEFAULT_PROPERTY,
            description: "curveSM2+ML-KEM-768 hybrid key management",
        },
        // SLH-DSA keymgmt (C guard: OPENSSL_NO_SLH_DSA)
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-128S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 128S key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-128F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 128F key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-192S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 192S key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-192F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 192F key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-256S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 256S key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHA2-256F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHA2 256F key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-128S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 128S key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-128F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 128F key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-192S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 192S key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-192F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 192F key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-256S"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 256S key management (FIPS 205)",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-SHAKE-256F"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA SHAKE 256F key management (FIPS 205)",
        },
        // Symmetric keymgmt (SKeyMgmt from C defltprov.c lines 698-704)
        AlgorithmDescriptor {
            names: vec!["AES"],
            property: DEFAULT_PROPERTY,
            description: "AES symmetric key management",
        },
        AlgorithmDescriptor {
            names: vec!["GENERIC"],
            property: DEFAULT_PROPERTY,
            description: "Generic symmetric key management",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Encoder/Decoder
// =============================================================================

/// Builds the encoder/decoder algorithm descriptor table.
///
/// Matches the encoder and decoder tables from `defltprov.c` which
/// include tables via `encoders.inc`, `decoders.inc`. These provide
/// DER, PEM, and text serialization for all key types.
fn build_encoder_decoder_table() -> Vec<AlgorithmDescriptor> {
    vec![
        // Encoders
        AlgorithmDescriptor {
            names: vec!["RSA-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "RSA key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "RSA key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-to-text-encoder"],
            property: DEFAULT_PROPERTY,
            description: "RSA key text encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-PSS-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "RSA-PSS key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-PSS-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "RSA-PSS key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DH-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "DH key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DH-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "DH key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "DSA key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "DSA key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["EC-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "EC key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["EC-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "EC key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "Ed25519 key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED448-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "Ed448 key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED448-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "Ed448 key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "X25519 key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "X25519 key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X448-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "X448 key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X448-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "X448 key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "ML-KEM key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "ML-DSA key PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-to-DER-encoder"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA key DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA-to-PEM-encoder"],
            property: DEFAULT_PROPERTY,
            description: "SLH-DSA key PEM encoder",
        },
        // Decoders
        AlgorithmDescriptor {
            names: vec!["DER-to-RSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["PEM-to-RSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "PEM to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-RSA-PSS-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to RSA-PSS key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-DH-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to DH key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-DSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to DSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-EC-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to EC key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["PEM-to-DER-decoder"],
            property: DEFAULT_PROPERTY,
            description: "PEM to DER decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ED25519-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to Ed25519 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ED448-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to Ed448 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-X25519-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to X25519 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-X448-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to X448 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ML-KEM-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to ML-KEM key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-ML-DSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to ML-DSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DER-to-SLH-DSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "DER to SLH-DSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["MSBLOB-to-RSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "MSBLOB to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["PVK-to-RSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "PVK to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["PVK-to-DSA-decoder"],
            property: DEFAULT_PROPERTY,
            description: "PVK to DSA key decoder",
        },
    ]
}

// =============================================================================
// Algorithm Table Construction — Store
// =============================================================================

/// Builds the store algorithm descriptor table.
///
/// Matches `deflt_store[]` from `defltprov.c` (included via `stores.inc`).
fn build_store_table() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["file"],
            property: DEFAULT_PROPERTY,
            description: "File-based key/certificate store (ossl_store URI scheme)",
        },
        AlgorithmDescriptor {
            names: vec!["winstore"],
            property: DEFAULT_PROPERTY,
            description: "Windows certificate store (Windows platform only)",
        },
    ]
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::types::OperationType;

    #[test]
    fn test_default_provider_new() {
        let provider = DefaultProvider::new();
        assert!(provider.is_running());
    }

    #[test]
    fn test_default_provider_info() {
        let provider = DefaultProvider::new();
        let info = provider.info();
        assert_eq!(info.name, "OpenSSL Default Provider");
        assert_eq!(info.version, "4.0.0");
        assert!(info.status);
    }

    #[test]
    fn test_default_provider_gettable_params() {
        let provider = DefaultProvider::new();
        let params = provider.gettable_params();
        assert!(params.contains(&"name"));
        assert!(params.contains(&"version"));
        assert!(params.contains(&"buildinfo"));
        assert!(params.contains(&"status"));
    }

    #[test]
    fn test_default_provider_get_params() {
        let provider = DefaultProvider::new();
        let params = provider.get_params().expect("get_params should succeed");
        assert_eq!(
            params.get("name").and_then(|v| v.as_str()),
            Some("OpenSSL Default Provider")
        );
        assert_eq!(
            params.get("version").and_then(|v| v.as_str()),
            Some("4.0.0")
        );
        assert_eq!(params.get("status").and_then(|v| v.as_i32()), Some(1));
    }

    #[test]
    fn test_default_provider_teardown() {
        let mut provider = DefaultProvider::new();
        assert!(provider.is_running());
        provider.teardown().expect("teardown should succeed");
        assert!(!provider.is_running());
    }

    #[test]
    fn test_query_operation_after_teardown() {
        let mut provider = DefaultProvider::new();
        provider.teardown().expect("teardown should succeed");
        // After teardown, all queries should return None
        assert!(provider.query_operation(OperationType::Digest).is_none());
        assert!(provider.query_operation(OperationType::Cipher).is_none());
    }

    #[test]
    fn test_query_digests() {
        let provider = DefaultProvider::new();
        let digests = provider
            .query_operation(OperationType::Digest)
            .expect("digests should be available");
        assert!(!digests.is_empty());
        // Check SHA-256 is present
        let sha256 = digests.iter().find(|d| d.names.contains(&"SHA2-256"));
        assert!(sha256.is_some());
        assert_eq!(sha256.expect("found above").property, "provider=default");
    }

    #[test]
    fn test_query_ciphers() {
        let provider = DefaultProvider::new();
        let ciphers = provider
            .query_operation(OperationType::Cipher)
            .expect("ciphers should be available");
        assert!(!ciphers.is_empty());
        // Check AES-256-GCM is present
        let aes_gcm = ciphers.iter().find(|d| d.names.contains(&"AES-256-GCM"));
        assert!(aes_gcm.is_some());
    }

    #[test]
    fn test_query_all_operation_types() {
        let provider = DefaultProvider::new();
        // All categories should return Some when default features are enabled
        let categories = [
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
        ];
        for cat in &categories {
            let result = provider.query_operation(*cat);
            assert!(
                result.is_some(),
                "query_operation({:?}) should return Some",
                cat
            );
            assert!(
                !result.as_ref().expect("checked above").is_empty(),
                "query_operation({:?}) should return non-empty",
                cat
            );
        }
    }

    #[test]
    fn test_all_descriptors_have_default_property() {
        let provider = DefaultProvider::new();
        let categories = [
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
        ];
        for cat in &categories {
            if let Some(algos) = provider.query_operation(*cat) {
                for algo in &algos {
                    assert_eq!(
                        algo.property, "provider=default",
                        "Algorithm {:?} in {:?} has wrong property",
                        algo.names, cat,
                    );
                }
            }
        }
    }

    #[test]
    fn test_default_trait() {
        let provider: DefaultProvider = Default::default();
        assert!(provider.is_running());
    }

    #[test]
    fn test_clone() {
        let provider = DefaultProvider::new();
        let cloned = provider.clone();
        assert!(cloned.is_running());
        assert_eq!(cloned.info().name, provider.info().name);
    }

    #[test]
    fn test_debug() {
        let provider = DefaultProvider::new();
        let debug_str = format!("{:?}", provider);
        assert!(debug_str.contains("DefaultProvider"));
    }

    #[test]
    fn test_get_params_after_teardown() {
        let mut provider = DefaultProvider::new();
        provider.teardown().expect("teardown should succeed");
        let params = provider.get_params().expect("get_params should still work");
        assert_eq!(params.get("status").and_then(|v| v.as_i32()), Some(0));
    }
}
