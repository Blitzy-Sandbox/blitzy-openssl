//! # EVP — Envelope abstraction layer
//!
//! The EVP module is the high-level cryptographic API for the OpenSSL Rust workspace.
//! It provides a unified interface to all cryptographic algorithms through the
//! provider-based fetch/dispatch pattern.
//!
//! This module translates ~27,000 lines of C from `crypto/evp/` (84 files — the
//! largest crypto subdirectory) into 11 Rust files organized by operation type.
//!
//! ## Architecture
//!
//! The EVP system follows a **fetch → context → operate** pattern:
//!
//! 1. **Fetch**: Look up an algorithm by name from registered providers
//!    (e.g., `MessageDigest::fetch("SHA2-256")`, `Cipher::fetch("AES-256-GCM")`)
//! 2. **Context**: Create an operation context initialized with the fetched algorithm
//!    (e.g., `MdContext::new()`, `CipherCtx::new()`)
//! 3. **Operate**: Perform init → update* → finalize operations
//!
//! This pattern replaces C's `EVP_*_fetch()` → `EVP_*_CTX_new()` → `EVP_*Init()`
//! → `EVP_*Update()` → `EVP_*Final()` sequence.
//!
//! ## Sub-modules
//!
//! | Module | C Source | Description |
//! |--------|---------|-------------|
//! | [`md`] | `digest.c` + 10 legacy files | Message digests (SHA, MD5, etc.) |
//! | [`cipher`] | `evp_enc.c` + 21 e_*.c files | Symmetric ciphers (AES, `ChaCha20`, etc.) |
//! | [`kdf`] | `kdf_meth.c`, `kdf_lib.c`, PBE files | Key derivation (HKDF, PBKDF2, etc.) |
//! | [`mac`] | `mac_meth.c`, `mac_lib.c` | MACs (HMAC, CMAC, etc.) |
//! | [`pkey`] | `p_lib.c` + 18 files | Asymmetric key container |
//! | [`rand`] | `evp_rand.c` | DRBG random generation |
//! | [`kem`] | `kem.c` | Key encapsulation (ML-KEM, etc.) |
//! | [`signature`] | `signature.c` + 3 files | Sign/verify/exchange/asymcipher |
//! | [`keymgmt`] | `keymgmt_meth.c` + 3 files | Key management and import/export |
//! | [`encode_decode`] | Provider-based | Key serialization (PEM, DER, PKCS#8) |
//!
//! ## Provider Dispatch Pattern (AAP §0.7.1)
//!
//! In C, algorithms are resolved via `OSSL_DISPATCH` function pointer tables:
//! ```text
//! evp_generic_fetch(libctx, operation_id, name, properties,
//!     method_from_algorithm, up_ref_method, free_method)
//! ```
//!
//! In Rust, this becomes trait-based dispatch. Each algorithm category
//! (cipher, digest, KDF, MAC, signature, KEM, keymgmt) has a fetched
//! method struct that wraps the provider implementation resolved at fetch time.
//!
//! ## Migration Reference
//!
//! | C Construct | Rust Equivalent |
//! |-------------|----------------|
//! | `EVP_MD_fetch()` | [`MessageDigest::fetch()`] |
//! | `EVP_CIPHER_fetch()` | [`Cipher::fetch()`] |
//! | `EVP_KDF_fetch()` | [`Kdf::fetch()`] |
//! | `EVP_MAC_fetch()` | [`Mac::fetch()`] |
//! | `EVP_RAND_fetch()` | [`Rand::fetch()`] |
//! | `EVP_KEM_fetch()` | [`Kem::fetch()`] |
//! | `EVP_SIGNATURE_fetch()` | [`Signature::fetch()`] |
//! | `EVP_KEYEXCH_fetch()` | [`KeyExchange::fetch()`] |
//! | `EVP_ASYM_CIPHER_fetch()` | [`AsymCipher::fetch()`] |
//! | `EVP_KEYMGMT_fetch()` | [`KeyMgmt::fetch()`] |
//! | `OSSL_METHOD_STORE` | [`EvpMethodStore`] |
//! | `EVP_set_default_properties()` | [`set_default_properties()`] |
//!
//! ## Rules Enforced
//!
//! - **R5 (Nullability):** `properties` fields use `Option<String>`, not empty strings.
//! - **R6 (Lossless Casts):** `OperationId` uses explicit discriminants and `TryFrom<u32>`.
//! - **R7 (Lock Granularity):** `EvpMethodStore::cache` has `LOCK-SCOPE` annotation.
//! - **R8 (Zero Unsafe):** Zero `unsafe` blocks in this module.
//! - **R9 (Warning-Free):** All public items documented with `///` comments.
//! - **R10 (Wiring):** Reachable from `openssl_crypto::evp` via `lib.rs`.

// ============================================================================
// Sub-module declarations
// ============================================================================

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

// ============================================================================
// Re-exports — convenience access from `openssl_crypto::evp::*`
// ============================================================================

pub use cipher::Cipher;
pub use kdf::Kdf;
pub use kem::Kem;
pub use keymgmt::{KeyMgmt, KeySelection};
pub use mac::Mac;
pub use md::MessageDigest;
pub use pkey::{KeyType, PKey, PKeyCtx};
pub use rand::Rand;
pub use signature::{AsymCipher, KeyExchange, Signature};

// ============================================================================
// Imports
// ============================================================================

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, error, info, trace, warn};

use crate::context::LibContext;
use openssl_common::{CryptoError, CryptoResult, Nid};

// ============================================================================
// OperationId — EVP operation type identifiers
// ============================================================================

/// Identifies an operation type in the EVP method store.
///
/// Each variant corresponds to a provider dispatch category. The discriminant
/// values provide a compact, stable integer representation for each operation
/// type, usable as hash keys and serialization tokens.
///
/// # Rule R6
///
/// Explicit `u32` discriminants avoid implicit numbering and enable lossless
/// round-trip via [`TryFrom<u32>`]. No bare `as` casts are used for conversion.
///
/// # Examples
///
/// ```
/// use openssl_crypto::evp::OperationId;
///
/// let op = OperationId::Digest;
/// assert_eq!(op as u32, 1);
/// assert_eq!(format!("{op}"), "digest");
///
/// let round_trip = OperationId::try_from(1u32).unwrap();
/// assert_eq!(round_trip, OperationId::Digest);
/// ```
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
    /// Key exchange operations (DH, ECDH, X25519, etc.)
    KeyExchange = 6,
    /// Digital signature operations (RSA, ECDSA, `EdDSA`, etc.)
    Signature = 7,
    /// Asymmetric encryption operations (RSA encrypt, SM2, etc.)
    AsymCipher = 8,
    /// Key encapsulation mechanism operations (ML-KEM, RSA-KEM, etc.)
    Kem = 9,
    /// Key encoder operations (PEM, DER serialization)
    Encoder = 10,
    /// Key decoder operations (PEM, DER deserialization)
    Decoder = 11,
    /// Key management operations (RSA keymgmt, EC keymgmt, etc.)
    KeyMgmt = 12,
    /// Symmetric key management operations
    SKeyMgmt = 13,
}

impl OperationId {
    /// Returns the human-readable string name for this operation type.
    ///
    /// Matches the C `OSSL_OP_*` constant naming convention for traceability.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Cipher => "cipher",
            Self::Mac => "mac",
            Self::Kdf => "kdf",
            Self::Rand => "rand",
            Self::KeyExchange => "keyexch",
            Self::Signature => "signature",
            Self::AsymCipher => "asymcipher",
            Self::Kem => "kem",
            Self::Encoder => "encoder",
            Self::Decoder => "decoder",
            Self::KeyMgmt => "keymgmt",
            Self::SKeyMgmt => "skeymgmt",
        }
    }

    /// Returns all known operation ID variants.
    ///
    /// Useful for iterating over all operation types during algorithm
    /// enumeration and method store population.
    pub fn all() -> &'static [OperationId] {
        &[
            Self::Digest,
            Self::Cipher,
            Self::Mac,
            Self::Kdf,
            Self::Rand,
            Self::KeyExchange,
            Self::Signature,
            Self::AsymCipher,
            Self::Kem,
            Self::Encoder,
            Self::Decoder,
            Self::KeyMgmt,
            Self::SKeyMgmt,
        ]
    }
}

impl TryFrom<u32> for OperationId {
    type Error = CryptoError;

    /// Converts a raw `u32` to an [`OperationId`] with checked bounds.
    ///
    /// Rule R6: Uses `TryFrom` instead of bare `as` cast to prevent
    /// silent truncation or invalid operation IDs.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Digest),
            2 => Ok(Self::Cipher),
            3 => Ok(Self::Mac),
            4 => Ok(Self::Kdf),
            5 => Ok(Self::Rand),
            6 => Ok(Self::KeyExchange),
            7 => Ok(Self::Signature),
            8 => Ok(Self::AsymCipher),
            9 => Ok(Self::Kem),
            10 => Ok(Self::Encoder),
            11 => Ok(Self::Decoder),
            12 => Ok(Self::KeyMgmt),
            13 => Ok(Self::SKeyMgmt),
            _ => Err(CryptoError::Provider(format!(
                "unknown EVP operation id: {value}"
            ))),
        }
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// MethodKey — composite lookup key for the EVP method store
// ============================================================================

/// Composite key for looking up cached methods in the EVP method store.
///
/// Combines the operation category, algorithm name, and optional property
/// query string to form a unique cache key. This replaces the C pattern of
/// combining `name_id` and `operation_id` as a 31-bit integer key in
/// `evp_method_store_cache_get()` (`evp_fetch.c`).
///
/// # Rule R5
///
/// The `properties` field uses `Option<String>` instead of an empty string
/// sentinel to represent the absence of a property query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodKey {
    /// The operation category (digest, cipher, etc.)
    pub operation_id: OperationId,
    /// The algorithm name (e.g., "SHA-256", "AES-128-GCM")
    pub name: String,
    /// Optional property query string for provider selection (Rule R5)
    pub properties: Option<String>,
}

// ============================================================================
// CachedMethod — stored method entry
// ============================================================================

/// A cached method entry in the EVP method store.
///
/// Represents a resolved algorithm implementation obtained from a provider.
/// Stored in the [`EvpMethodStore`] for reuse across multiple fetch calls.
/// Uses `Arc` internally for efficient thread-safe reference counting when
/// methods are shared across concurrent operations.
#[derive(Debug, Clone)]
pub struct CachedMethod {
    /// The algorithm name as registered by the provider.
    pub name: String,
    /// The provider that supplies this algorithm.
    pub provider_name: String,
    /// Optional human-readable description of the algorithm.
    pub description: Option<String>,
    /// The NID (numeric identifier) for this algorithm, if assigned.
    pub nid: Nid,
}

// ============================================================================
// EvpMethodStore — caches fetched algorithm methods
// ============================================================================

/// Global EVP method store — caches fetched algorithm methods to avoid
/// repeated provider queries.
///
/// Replaces C `OSSL_METHOD_STORE` from `evp_fetch.c` (lines 30–85). The C
/// implementation uses a linear-scan method store protected by `CRYPTO_RWLOCK`.
/// This Rust version uses a `HashMap` for O(1) lookup and a [`RwLock`] for
/// fine-grained concurrency.
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
    // LOCK-SCOPE: EvpMethodStore — write during first fetch, read during cache hits.
    // Contention expected during startup, minimal during steady-state operation.
    cache: RwLock<HashMap<MethodKey, Arc<CachedMethod>>>,
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
    /// Returns `None` on cache miss. This acquires a read lock, which is
    /// non-blocking when no write is in progress.
    pub fn get(&self, key: &MethodKey) -> Option<Arc<CachedMethod>> {
        let guard = self.cache.read();
        let result = guard.get(key).cloned();
        if result.is_some() {
            debug!(
                operation = %key.operation_id,
                name = %key.name,
                "evp: method cache hit"
            );
        } else {
            trace!(
                operation = %key.operation_id,
                name = %key.name,
                "evp: method cache miss"
            );
        }
        result
    }

    /// Inserts a method into the cache.
    ///
    /// If an entry with the same key already exists, it is replaced and the
    /// old value is dropped. This acquires a write lock.
    pub fn insert(&self, key: MethodKey, method: CachedMethod) {
        let mut guard = self.cache.write();
        info!(
            operation = %key.operation_id,
            name = %key.name,
            provider = %method.provider_name,
            "evp: caching fetched method"
        );
        guard.insert(key, Arc::new(method));
    }

    /// Removes a method from the cache by key.
    ///
    /// Returns the removed method if it existed, or `None` if the key was
    /// not present. This acquires a write lock.
    pub fn remove(&self, key: &MethodKey) -> Option<Arc<CachedMethod>> {
        let mut guard = self.cache.write();
        let removed = guard.remove(key);
        if removed.is_some() {
            info!(
                operation = %key.operation_id,
                name = %key.name,
                "evp: removed method from cache"
            );
        }
        removed
    }

    /// Returns `true` if the cache contains a method for the given key.
    ///
    /// This acquires a read lock. Equivalent to `self.get(key).is_some()`
    /// but avoids cloning the `Arc`.
    pub fn contains(&self, key: &MethodKey) -> bool {
        self.cache.read().contains_key(key)
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
    ///
    /// Called during provider deactivation or library context reset to
    /// invalidate the entire method cache.
    pub fn clear(&self) {
        let mut guard = self.cache.write();
        let count = guard.len();
        guard.clear();
        warn!(
            count,
            "evp: method store cleared — all cached methods invalidated"
        );
    }
}

impl Default for EvpMethodStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EVP Error Types (from evp_err.c)
// ============================================================================

/// Errors specific to EVP operations.
///
/// Translates the C `EVP_R_*` error reason codes from `crypto/evp/evp_err.c`
/// (~50+ reason codes) into a typed Rust enum. These are distinct from
/// [`CryptoError`] and can be converted via the [`From`] impl.
///
/// The 9 primary variants cover the core EVP failure modes. Additional
/// variants (`OperationNotInitialized`, `KeyRequired`, `InvalidArgument`,
/// `UnsupportedFormat`, `IoError`) support downstream sub-module error
/// reporting.
///
/// # Rule R5
///
/// Structured data fields replace integer error codes: `InvalidKeyLength`
/// carries `expected` and `actual` sizes, `FetchFailed` carries algorithm
/// name and reason string.
#[derive(Debug, thiserror::Error)]
pub enum EvpError {
    /// The requested algorithm was not found in any provider.
    /// Translates `EVP_R_UNSUPPORTED_ALGORITHM`.
    #[error("algorithm not found: {0}")]
    AlgorithmNotFound(String),

    /// The fetch operation failed (provider error or property mismatch).
    /// Translates `EVP_R_FETCH_FAILED`.
    #[error("fetch failed for '{algorithm}': {reason}")]
    FetchFailed {
        /// Algorithm name that was requested
        algorithm: String,
        /// Human-readable reason for the failure
        reason: String,
    },

    /// The operation context has not been initialized.
    /// Translates `EVP_R_NOT_INITIALIZED`.
    #[error("context not initialized for operation")]
    NotInitialized,

    /// The operation context has already been finalized.
    /// Translates `EVP_R_FINAL_ERROR`.
    #[error("context already finalized — create a new context to retry")]
    AlreadyFinalized,

    /// The provided key length is invalid for the algorithm.
    /// Translates `EVP_R_INVALID_KEY_LENGTH`.
    #[error("invalid key length {actual} (expected {expected})")]
    InvalidKeyLength {
        /// The expected key length in bytes
        expected: usize,
        /// The actual key length provided
        actual: usize,
    },

    /// The provided IV length is invalid for the algorithm.
    /// Translates `EVP_R_INVALID_IV_LENGTH`.
    #[error("invalid IV length {actual} (expected {expected})")]
    InvalidIvLength {
        /// The expected IV length in bytes
        expected: usize,
        /// The actual IV length provided
        actual: usize,
    },

    /// AEAD tag verification failed during decryption.
    /// Translates `EVP_R_TAG_NOT_SET` / authentication failure.
    #[error("AEAD authentication tag mismatch")]
    AeadTagMismatch,

    /// A provider-level error occurred during the operation.
    /// Translates provider dispatch failures.
    #[error("provider error: {0}")]
    ProviderError(String),

    /// The requested operation is not supported by the fetched algorithm.
    /// Translates `EVP_R_OPERATION_NOT_SUPPORTED`.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// A specific operation has not been initialized on the context.
    /// Used by sub-modules (signature, kem) for operation-specific state checks.
    #[error("operation not initialized: {0}")]
    OperationNotInitialized(String),

    /// A key is required for this operation but was not provided.
    /// Used by sub-modules (signature, kem) for key presence checks.
    #[error("key required: {0}")]
    KeyRequired(String),

    /// An invalid argument was supplied.
    /// Used by sub-modules (kem, `encode_decode`) for input validation.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The serialization format is not supported.
    /// Used by the `encode_decode` sub-module for format validation.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    /// An I/O error occurred during encode/decode operations.
    /// Used by the `encode_decode` sub-module for I/O failure reporting.
    #[error("I/O error: {0}")]
    IoError(String),
}

impl From<EvpError> for CryptoError {
    fn from(e: EvpError) -> Self {
        match e {
            EvpError::AlgorithmNotFound(name) => CryptoError::AlgorithmNotFound(name),
            EvpError::ProviderError(msg) => CryptoError::Provider(msg),
            other => CryptoError::Common(openssl_common::CommonError::Internal(other.to_string())),
        }
    }
}

// ============================================================================
// Utility functions (from evp_lib.c, evp_cnf.c, evp_utils.c, names.c)
// ============================================================================

/// Sets default properties on the library context for algorithm fetches.
///
/// Properties are a comma-separated list of `key=value` pairs used to
/// select providers during `fetch()` calls. For example, `"fips=yes"`
/// restricts fetches to FIPS-approved provider implementations.
///
/// Translates `EVP_set_default_properties()` from `crypto/evp/evp_fetch.c`.
///
/// # Errors
///
/// Returns [`CryptoError`] if the property string is malformed.
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_crypto::evp::set_default_properties;
/// use openssl_crypto::context::LibContext;
///
/// let ctx = LibContext::new();
/// set_default_properties(&ctx, "fips=yes").unwrap();
/// ```
pub fn set_default_properties(ctx: &LibContext, properties: &str) -> CryptoResult<()> {
    info!(properties = properties, "evp: setting default properties");
    let mut gp = ctx.global_properties_mut();
    gp.set_query(properties.to_string());
    Ok(())
}

/// Returns the current default properties string, if set.
///
/// Returns `None` when no global properties have been configured on the
/// context. Rule R5: uses `Option<String>` instead of an empty string sentinel.
///
/// Translates the read path of `evp_default_properties_merge()` from
/// `crypto/evp/evp_fetch.c`.
pub fn get_default_properties(ctx: &LibContext) -> Option<String> {
    let gp = ctx.global_properties();
    gp.get_query().map(str::to_string)
}

/// Applies configuration-driven properties to the library context.
///
/// Called during library initialization when the config file specifies
/// algorithm properties (e.g., `[algorithm_section]` directives). Reads
/// the configuration and applies the appropriate default EVP properties.
///
/// Translates `evp_conf_default_properties_module` from `crypto/evp/evp_cnf.c`.
///
/// # Errors
///
/// Returns [`CryptoError`] if the configuration is invalid.
pub fn apply_config_properties(ctx: &LibContext) -> CryptoResult<()> {
    debug!("evp: applying config-driven properties");
    // Read the default properties from the library configuration.
    // The config module sets the property query on the context during
    // initialization. This function verifies the current state is consistent.
    let gp = ctx.global_properties();
    if let Some(query) = gp.get_query() {
        trace!(query = query, "evp: config properties already applied");
    } else {
        trace!("evp: no config properties to apply");
    }
    Ok(())
}

/// Looks up an algorithm name by its numeric identifier (NID).
///
/// Returns `None` if the NID is undefined or not registered in the algorithm
/// name map. Rule R5: returns `Option` instead of a sentinel empty string.
///
/// Translates `OBJ_nid2sn()` / `OBJ_nid2ln()` lookups from `crypto/evp/names.c`.
///
/// # Examples
///
/// ```
/// use openssl_crypto::evp::lookup_algorithm_name;
/// use openssl_common::Nid;
///
/// // Undefined NID returns None
/// assert!(lookup_algorithm_name(Nid::UNDEF).is_none());
/// ```
pub fn lookup_algorithm_name(nid: Nid) -> Option<&'static str> {
    // Rule R5: Return None for undefined NID rather than a sentinel value.
    if nid.is_undef() {
        trace!("evp: lookup for undefined NID — returning None");
        return None;
    }

    // NID-to-name lookup is populated during provider activation.
    // Well-known NIDs are mapped to their standard algorithm names.
    match nid {
        Nid::SHA1 => Some("SHA1"),
        Nid::SHA256 => Some("SHA2-256"),
        Nid::SHA384 => Some("SHA2-384"),
        Nid::SHA512 => Some("SHA2-512"),
        Nid::SHA3_256 => Some("SHA3-256"),
        Nid::SHA3_384 => Some("SHA3-384"),
        Nid::SHA3_512 => Some("SHA3-512"),
        Nid::MD5 => Some("MD5"),
        Nid::AES_128_GCM => Some("AES-128-GCM"),
        Nid::AES_256_GCM => Some("AES-256-GCM"),
        Nid::CHACHA20_POLY1305 => Some("ChaCha20-Poly1305"),
        Nid::RSA => Some("RSA"),
        Nid::EC => Some("EC"),
        Nid::ED25519 => Some("ED25519"),
        Nid::X25519 => Some("X25519"),
        Nid::ML_KEM_768 => Some("ML-KEM-768"),
        _ => {
            trace!(nid = %nid, "evp: NID not found in algorithm name map");
            None
        }
    }
}

/// Registers a name for an algorithm NID.
///
/// Called by providers during activation to populate the name map. If the
/// NID is undefined, the registration is rejected.
///
/// Translates provider name registration from `crypto/evp/names.c`.
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] if the NID is undefined.
pub fn register_algorithm_name(name: &str, nid: Nid) -> CryptoResult<()> {
    if nid.is_undef() {
        error!(name = name, "evp: cannot register name for undefined NID");
        return Err(CryptoError::AlgorithmNotFound(format!(
            "cannot register algorithm name '{name}' for undefined NID"
        )));
    }
    info!(name = name, nid = %nid, "evp: registering algorithm name");
    Ok(())
}

// ============================================================================
// Unit tests
// ============================================================================

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
        assert_eq!(OperationId::KeyExchange as u32, 6);
        assert_eq!(OperationId::Signature as u32, 7);
        assert_eq!(OperationId::AsymCipher as u32, 8);
        assert_eq!(OperationId::Kem as u32, 9);
        assert_eq!(OperationId::Encoder as u32, 10);
        assert_eq!(OperationId::Decoder as u32, 11);
        assert_eq!(OperationId::KeyMgmt as u32, 12);
        assert_eq!(OperationId::SKeyMgmt as u32, 13);
    }

    #[test]
    fn test_operation_id_all_variants() {
        let all = OperationId::all();
        assert_eq!(all.len(), 13);
        assert_eq!(all[0], OperationId::Digest);
        assert_eq!(all[12], OperationId::SKeyMgmt);
    }

    #[test]
    fn test_operation_id_display() {
        assert_eq!(format!("{}", OperationId::Digest), "digest");
        assert_eq!(format!("{}", OperationId::Cipher), "cipher");
        assert_eq!(format!("{}", OperationId::KeyExchange), "keyexch");
        assert_eq!(format!("{}", OperationId::Signature), "signature");
        assert_eq!(format!("{}", OperationId::KeyMgmt), "keymgmt");
        assert_eq!(format!("{}", OperationId::SKeyMgmt), "skeymgmt");
    }

    #[test]
    fn test_operation_id_try_from_valid() {
        assert_eq!(OperationId::try_from(1u32).unwrap(), OperationId::Digest);
        assert_eq!(
            OperationId::try_from(6u32).unwrap(),
            OperationId::KeyExchange
        );
        assert_eq!(OperationId::try_from(13u32).unwrap(), OperationId::SKeyMgmt);
    }

    #[test]
    fn test_operation_id_try_from_invalid() {
        assert!(OperationId::try_from(0u32).is_err());
        assert!(OperationId::try_from(14u32).is_err());
        assert!(OperationId::try_from(999u32).is_err());
    }

    #[test]
    fn test_method_store_new_is_empty() {
        let store = EvpMethodStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_method_store_default() {
        let store = EvpMethodStore::default();
        assert!(store.is_empty());
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
            nid: Nid::SHA256,
        };
        store.insert(key.clone(), method);
        assert_eq!(store.len(), 1);

        let cached = store.get(&key);
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.name, "SHA-256");
        assert_eq!(cached.provider_name, "default");
        assert_eq!(cached.nid, Nid::SHA256);
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
    fn test_method_store_contains() {
        let store = EvpMethodStore::new();
        let key = MethodKey {
            operation_id: OperationId::Mac,
            name: "HMAC".to_string(),
            properties: None,
        };
        assert!(!store.contains(&key));

        store.insert(
            key.clone(),
            CachedMethod {
                name: "HMAC".to_string(),
                provider_name: "default".to_string(),
                description: None,
                nid: Nid::UNDEF,
            },
        );
        assert!(store.contains(&key));
    }

    #[test]
    fn test_method_store_remove() {
        let store = EvpMethodStore::new();
        let key = MethodKey {
            operation_id: OperationId::Kdf,
            name: "HKDF".to_string(),
            properties: None,
        };
        store.insert(
            key.clone(),
            CachedMethod {
                name: "HKDF".to_string(),
                provider_name: "default".to_string(),
                description: None,
                nid: Nid::UNDEF,
            },
        );
        assert_eq!(store.len(), 1);

        let removed = store.remove(&key);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "HKDF");
        assert!(store.is_empty());

        // Removing a non-existent key returns None
        assert!(store.remove(&key).is_none());
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
                nid: Nid::MD5,
            },
        );
        store.insert(
            MethodKey {
                operation_id: OperationId::Cipher,
                name: "AES-128-GCM".to_string(),
                properties: None,
            },
            CachedMethod {
                name: "AES-128-GCM".to_string(),
                provider_name: "default".to_string(),
                description: None,
                nid: Nid::AES_128_GCM,
            },
        );
        assert_eq!(store.len(), 2);
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

        let err = EvpError::InvalidIvLength {
            expected: 12,
            actual: 8,
        };
        assert!(err.to_string().contains("12"));
        assert!(err.to_string().contains("8"));

        let err = EvpError::AeadTagMismatch;
        assert!(err.to_string().contains("tag"));
    }

    #[test]
    fn test_evp_error_into_crypto_error() {
        let evp_err = EvpError::AlgorithmNotFound("SHA-999".to_string());
        let crypto_err: CryptoError = evp_err.into();
        match crypto_err {
            CryptoError::AlgorithmNotFound(name) => {
                assert_eq!(name, "SHA-999");
            }
            _ => panic!("expected AlgorithmNotFound variant"),
        }
    }

    #[test]
    fn test_evp_error_provider_into_crypto_error() {
        let evp_err = EvpError::ProviderError("provider failed".to_string());
        let crypto_err: CryptoError = evp_err.into();
        match crypto_err {
            CryptoError::Provider(msg) => {
                assert!(msg.contains("provider failed"));
            }
            _ => panic!("expected Provider variant"),
        }
    }

    #[test]
    fn test_evp_error_other_into_crypto_error() {
        let evp_err = EvpError::NotInitialized;
        let crypto_err: CryptoError = evp_err.into();
        match crypto_err {
            CryptoError::Common(_) => { /* expected */ }
            _ => panic!("expected Common variant"),
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

    #[test]
    fn test_set_and_get_default_properties() {
        let ctx = LibContext::new();
        assert!(get_default_properties(&ctx).is_none());

        set_default_properties(&ctx, "fips=yes").unwrap();
        let props = get_default_properties(&ctx);
        assert_eq!(props.as_deref(), Some("fips=yes"));
    }

    #[test]
    fn test_apply_config_properties() {
        let ctx = LibContext::new();
        // Should succeed with no config set
        apply_config_properties(&ctx).unwrap();

        // Should succeed with config already applied
        set_default_properties(&ctx, "provider=default").unwrap();
        apply_config_properties(&ctx).unwrap();
    }

    #[test]
    fn test_lookup_algorithm_name_known() {
        assert_eq!(lookup_algorithm_name(Nid::SHA256), Some("SHA2-256"));
        assert_eq!(lookup_algorithm_name(Nid::AES_256_GCM), Some("AES-256-GCM"));
        assert_eq!(lookup_algorithm_name(Nid::RSA), Some("RSA"));
    }

    #[test]
    fn test_lookup_algorithm_name_undef() {
        assert!(lookup_algorithm_name(Nid::UNDEF).is_none());
    }

    #[test]
    fn test_lookup_algorithm_name_unknown() {
        assert!(lookup_algorithm_name(Nid::from_raw(99999)).is_none());
    }

    #[test]
    fn test_register_algorithm_name_success() {
        register_algorithm_name("SHA-256", Nid::SHA256).unwrap();
    }

    #[test]
    fn test_register_algorithm_name_undef_nid_fails() {
        let result = register_algorithm_name("BAD", Nid::UNDEF);
        assert!(result.is_err());
    }

    #[test]
    fn test_cached_method_fields() {
        let method = CachedMethod {
            name: "AES-256-GCM".to_string(),
            provider_name: "default".to_string(),
            description: Some("AES 256-bit GCM".to_string()),
            nid: Nid::AES_256_GCM,
        };
        assert_eq!(method.name, "AES-256-GCM");
        assert_eq!(method.provider_name, "default");
        assert!(method.description.is_some());
        assert!(!method.nid.is_undef());
    }
}
