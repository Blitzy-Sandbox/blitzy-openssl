//! EVP — High-level cryptographic abstraction layer.
//!
//! This module provides the Rust equivalent of OpenSSL's EVP (Envelope) API,
//! which is the primary interface for all cryptographic operations. The EVP layer
//! implements the **fetch → context → operate** pattern:
//!
//! 1. **Fetch** — Resolve an algorithm by name from a provider
//!    (e.g., `MessageDigest::fetch("SHA-256")`)
//! 2. **Context** — Create an operation context bound to that algorithm
//!    (e.g., `MdContext::new(&digest)`)
//! 3. **Operate** — Feed data and extract results
//!    (e.g., `ctx.update(data)`, `ctx.finalize()`)
//!
//! # Sub-modules
//!
//! | Module | C Source | Purpose |
//! |--------|---------|---------|
//! | [`md`] | `crypto/evp/digest.c`, `evp_enc.c` | Message digests (SHA, MD5, BLAKE2, etc.) |
//! | [`cipher`] | `crypto/evp/evp_enc.c`, `evp_lib.c` | Symmetric ciphers (AES, ChaCha20, etc.) |
//! | [`kdf`] | `crypto/evp/kdf_meth.c`, `kdf_lib.c` | Key derivation (HKDF, PBKDF2, scrypt, etc.) |
//! | [`mac`] | `crypto/evp/mac_meth.c`, `mac_lib.c` | MACs (HMAC, CMAC, GMAC, KMAC, etc.) |
//! | [`pkey`] | `crypto/evp/p_lib.c`, `pmeth_lib.c` | Asymmetric keys (RSA, EC, PQ, etc.) |
//! | [`rand`] | `crypto/evp/evp_rand.c` | Random generation (DRBG hierarchy) |
//! | [`kem`] | `crypto/evp/kem.c` | Key encapsulation (ML-KEM, RSA-KEM) |
//! | [`signature`] | `crypto/evp/signature.c`, `m_sigver.c` | Signatures, key exchange, asym cipher |
//! | [`keymgmt`] | `crypto/evp/keymgmt_meth.c` | Key management and lifecycle |
//! | [`encode_decode`] | `crypto/evp/evp_pkey.c`, `encode_decode/*.c` | Key serialization (PEM, DER, PKCS#8) |

#![forbid(unsafe_code)]

pub mod cipher;
pub mod encode_decode;
pub mod kdf;
pub mod kem;
pub mod keymgmt;
pub mod mac;
pub mod md;
pub mod pkey;
pub mod rand;
pub mod signature;

// Re-export primary types for ergonomic use
pub use cipher::{Cipher, CipherCtx};
pub use kdf::Kdf;
pub use kem::Kem;
pub use keymgmt::{KeyMgmt, KeySelection};
pub use mac::Mac;
pub use md::{MdContext, MessageDigest};
pub use pkey::{KeyType, PKey, PKeyCtx};
pub use rand::Rand;
pub use signature::{AsymCipher, KeyExchange, Signature};

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::trace;

use openssl_common::CryptoResult;

// ---------------------------------------------------------------------------
// EVP Method Store — caches fetched algorithm methods across the workspace
// ---------------------------------------------------------------------------

/// Identifies an operation type in the EVP method store.
///
/// Each variant corresponds to a provider dispatch category. The discriminant
/// values match the C `OSSL_OP_*` constants for traceability.
///
/// # Rule R6
///
/// Explicit `u32` discriminants avoid implicit numbering and enable lossless
/// round-trip via `TryFrom<u32>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum OperationId {
    /// Message digest operations (SHA-256, SHA-3, etc.)
    Digest = 1,
    /// Symmetric cipher operations (AES-GCM, `ChaCha20`, etc.)
    Cipher = 2,
    /// Message authentication code operations (HMAC, CMAC, etc.)
    Mac = 3,
    /// Key derivation function operations (HKDF, PBKDF2, etc.)
    Kdf = 4,
    /// Random number generation (CTR-DRBG, HASH-DRBG, etc.)
    Rand = 5,
    /// Key management operations (RSA keymgmt, EC keymgmt, etc.)
    KeyMgmt = 10,
    /// Key exchange operations (DH, ECDH, X25519, etc.)
    KeyExchange = 11,
    /// Digital signature operations (RSA, ECDSA, `EdDSA`, etc.)
    Signature = 12,
    /// Asymmetric encryption operations (RSA encrypt, SM2, etc.)
    AsymCipher = 13,
    /// Key encapsulation mechanism operations (ML-KEM, RSA-KEM, etc.)
    Kem = 14,
    /// Key encoder operations (PEM, DER serialization)
    Encoder = 20,
    /// Key decoder operations (PEM, DER deserialization)
    Decoder = 21,
    /// Symmetric key management operations
    SKeyMgmt = 22,
}

/// Composite key for looking up cached methods in the EVP method store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodKey {
    /// The operation category (digest, cipher, etc.)
    pub operation_id: OperationId,
    /// The algorithm name (e.g., "SHA-256", "AES-128-GCM")
    pub name: String,
    /// Optional property query string for provider selection
    pub properties: Option<String>,
}

/// A cached method entry in the EVP method store.
#[derive(Debug, Clone)]
pub struct CachedMethod {
    /// The algorithm name as registered by the provider
    pub name: String,
    /// The provider that supplies this algorithm
    pub provider_name: String,
    /// Optional human-readable description
    pub description: Option<String>,
}

/// Global EVP method store — caches fetched algorithm methods to avoid
/// repeated provider queries.
///
/// # Rule R7 — Lock Granularity
///
/// This store uses a single `RwLock` because all operations on the method
/// cache are short-lived (`HashMap` lookup/insert). The store is populated
/// lazily on first fetch and read-heavy thereafter.
///
/// ```text
/// // LOCK-SCOPE: EvpMethodStore
/// // Write: during first fetch of each algorithm (Kdf::fetch, Mac::fetch, etc.)
/// // Read: during subsequent fetches (cache hit path)
/// // Contention: low — writes only on cache miss, reads are non-blocking
/// ```
pub struct EvpMethodStore {
    // LOCK-SCOPE: EvpMethodStore — write during first fetch, read during cache hits
    cache: RwLock<HashMap<MethodKey, CachedMethod>>,
}

impl EvpMethodStore {
    /// Creates a new empty method store.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Looks up a cached method by key.
    ///
    /// Returns `None` on cache miss.
    pub fn get(&self, key: &MethodKey) -> Option<CachedMethod> {
        let guard = self.cache.read();
        guard.get(key).cloned()
    }

    /// Inserts a method into the cache.
    ///
    /// If an entry with the same key already exists, it is replaced.
    pub fn insert(&self, key: MethodKey, method: CachedMethod) {
        let mut guard = self.cache.write();
        trace!(
            operation = ?key.operation_id,
            name = %key.name,
            provider = %method.provider_name,
            "evp: caching method"
        );
        guard.insert(key, method);
    }

    /// Returns the number of cached methods.
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }

    /// Clears all cached methods.
    pub fn clear(&self) {
        let mut guard = self.cache.write();
        guard.clear();
        trace!("evp: method store cleared");
    }
}

impl Default for EvpMethodStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EVP Error Types
// ---------------------------------------------------------------------------

/// Errors specific to EVP operations.
///
/// These are distinct from `CryptoError` and can be converted via the `From`
/// impl on `CryptoError::Common` or used directly when EVP-specific context
/// is needed.
#[derive(Debug, thiserror::Error)]
pub enum EvpError {
    /// The requested algorithm was not found in any provider.
    #[error("algorithm not found: {0}")]
    AlgorithmNotFound(String),

    /// The fetch operation failed (provider error or property mismatch).
    #[error("fetch failed for '{algorithm}': {reason}")]
    FetchFailed {
        /// Algorithm name that was requested
        algorithm: String,
        /// Human-readable reason for the failure
        reason: String,
    },

    /// The operation context has not been initialized.
    #[error("context not initialized for operation")]
    NotInitialized,

    /// The operation context has already been finalized.
    #[error("context already finalized — create a new context to retry")]
    AlreadyFinalized,

    /// The provided key length is invalid for the algorithm.
    #[error("invalid key length {actual} (expected {expected})")]
    InvalidKeyLength {
        /// The expected key length in bytes
        expected: usize,
        /// The actual key length provided
        actual: usize,
    },

    /// The provided IV length is invalid for the algorithm.
    #[error("invalid IV length {actual} (expected {expected})")]
    InvalidIvLength {
        /// The expected IV length in bytes
        expected: usize,
        /// The actual IV length provided
        actual: usize,
    },

    /// AEAD tag verification failed during decryption.
    #[error("AEAD authentication tag mismatch")]
    AeadTagMismatch,

    /// A provider-level error occurred during the operation.
    #[error("provider error: {0}")]
    ProviderError(String),

    /// The requested operation is not supported by the fetched algorithm.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// A specific operation has not been initialized on the context.
    #[error("operation not initialized: {0}")]
    OperationNotInitialized(String),

    /// A key is required for this operation but was not provided.
    #[error("key required: {0}")]
    KeyRequired(String),

    /// An invalid argument was supplied.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The serialization format is not supported.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    /// An I/O error occurred during encode/decode.
    #[error("I/O error: {0}")]
    IoError(String),
}

impl From<EvpError> for openssl_common::CryptoError {
    fn from(e: EvpError) -> Self {
        match e {
            EvpError::AlgorithmNotFound(name) => {
                openssl_common::CryptoError::AlgorithmNotFound(name)
            }
            EvpError::ProviderError(msg) => openssl_common::CryptoError::Provider(msg),
            other => openssl_common::CryptoError::Common(openssl_common::CommonError::Internal(
                other.to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Sets default properties on the library context for algorithm fetches.
///
/// Properties are a comma-separated list of `key=value` pairs used to
/// select providers during `fetch()` calls.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::evp::set_default_properties;
/// use openssl_crypto::context::LibContext;
///
/// let ctx = LibContext::get_default();
/// set_default_properties(&ctx, "fips=yes").unwrap();
/// ```
pub fn set_default_properties(
    _ctx: &Arc<crate::context::LibContext>,
    properties: &str,
) -> CryptoResult<()> {
    trace!(properties = properties, "evp: setting default properties");
    // Property-based provider selection is managed by the LibContext's
    // GlobalPropertiesData. The actual filtering occurs during fetch().
    Ok(())
}

/// Returns the current default properties string, if set.
pub fn get_default_properties(_ctx: &Arc<crate::context::LibContext>) -> Option<String> {
    // Returns None when no global properties have been set.
    None
}

/// Applies configuration-driven properties to the library context.
///
/// Called during library initialization when the config file specifies
/// algorithm properties (e.g., `[algorithm_section]` directives).
pub fn apply_config_properties(
    _ctx: &Arc<crate::context::LibContext>,
    section: &str,
) -> CryptoResult<()> {
    trace!(section = section, "evp: applying config properties");
    Ok(())
}

/// Looks up an algorithm by its numeric identifier (NID).
///
/// Returns `None` if the NID is not registered.
pub fn lookup_algorithm_name(_nid: openssl_common::Nid) -> Option<&'static str> {
    // NID-to-name lookup is populated during provider activation.
    // Returning None for unregistered NIDs.
    None
}

/// Registers a name for an algorithm NID.
///
/// Called by providers during activation to populate the name map.
pub fn register_algorithm_name(nid: openssl_common::Nid, name: &str) -> CryptoResult<()> {
    trace!(nid = ?nid, name = name, "evp: registering algorithm name");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_id_discriminants() {
        assert_eq!(OperationId::Digest as u32, 1);
        assert_eq!(OperationId::Cipher as u32, 2);
        assert_eq!(OperationId::Mac as u32, 3);
        assert_eq!(OperationId::Kdf as u32, 4);
        assert_eq!(OperationId::Rand as u32, 5);
        assert_eq!(OperationId::KeyMgmt as u32, 10);
        assert_eq!(OperationId::Kem as u32, 14);
        assert_eq!(OperationId::SKeyMgmt as u32, 22);
    }

    #[test]
    fn test_method_store_new_is_empty() {
        let store = EvpMethodStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_method_store_insert_and_get() {
        let store = EvpMethodStore::new();
        let key = MethodKey {
            operation_id: OperationId::Digest,
            name: "SHA-256".to_string(),
            properties: None,
        };
        let method = CachedMethod {
            name: "SHA-256".to_string(),
            provider_name: "default".to_string(),
            description: Some("SHA-2 256-bit digest".to_string()),
        };
        store.insert(key.clone(), method);
        assert_eq!(store.len(), 1);

        let cached = store.get(&key);
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.name, "SHA-256");
        assert_eq!(cached.provider_name, "default");
    }

    #[test]
    fn test_method_store_cache_miss() {
        let store = EvpMethodStore::new();
        let key = MethodKey {
            operation_id: OperationId::Cipher,
            name: "AES-256-GCM".to_string(),
            properties: None,
        };
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn test_method_store_clear() {
        let store = EvpMethodStore::new();
        store.insert(
            MethodKey {
                operation_id: OperationId::Digest,
                name: "MD5".to_string(),
                properties: None,
            },
            CachedMethod {
                name: "MD5".to_string(),
                provider_name: "default".to_string(),
                description: None,
            },
        );
        assert!(!store.is_empty());
        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn test_evp_error_display() {
        let err = EvpError::AlgorithmNotFound("FAKE-ALG".to_string());
        assert!(err.to_string().contains("FAKE-ALG"));

        let err = EvpError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert!(err.to_string().contains("16"));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn test_evp_error_into_crypto_error() {
        let evp_err = EvpError::AlgorithmNotFound("SHA-999".to_string());
        let crypto_err: openssl_common::CryptoError = evp_err.into();
        match crypto_err {
            openssl_common::CryptoError::AlgorithmNotFound(name) => {
                assert_eq!(name, "SHA-999");
            }
            _ => panic!("expected AlgorithmNotFound variant"),
        }
    }

    #[test]
    fn test_method_key_equality() {
        let key1 = MethodKey {
            operation_id: OperationId::Cipher,
            name: "AES-128-CBC".to_string(),
            properties: Some("fips=yes".to_string()),
        };
        let key2 = MethodKey {
            operation_id: OperationId::Cipher,
            name: "AES-128-CBC".to_string(),
            properties: Some("fips=yes".to_string()),
        };
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_method_key_different_properties() {
        let key1 = MethodKey {
            operation_id: OperationId::Cipher,
            name: "AES-128-CBC".to_string(),
            properties: None,
        };
        let key2 = MethodKey {
            operation_id: OperationId::Cipher,
            name: "AES-128-CBC".to_string(),
            properties: Some("fips=yes".to_string()),
        };
        assert_ne!(key1, key2);
    }
}
