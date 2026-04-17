//! # Provider System
//!
//! The provider system is the sole algorithm dispatch mechanism for OpenSSL.
//! Every cryptographic operation — digest, cipher, signature, KEM, KDF, etc. —
//! is discovered and dispatched through the provider framework.
//!
//! ## Architecture (AAP §0.7.1)
//!
//! The C implementation uses `OSSL_DISPATCH` function pointer tables — flat arrays
//! of `{function_id, function_ptr}` pairs that providers register. In Rust, these
//! are replaced by trait objects and dynamic dispatch:
//!
//! ```text
//! C Pattern:              Rust Pattern:
//! OSSL_DISPATCH[]  ───►   trait DigestProvider { ... }
//! function_id      ───►   trait method
//! function_ptr     ───►   trait impl
//! provider_init()  ───►   impl Provider for DefaultProvider { ... }
//! ```
//!
//! ## Module Structure
//!
//! - [`core`] — Provider store, instance lifecycle, activation, algorithm enumeration
//! - [`predefined`] — Built-in provider registry (default, base, null, legacy, fips)
//! - [`property`] — Property query/match system for algorithm selection
//!
//! ## Source Mapping
//!
//! | Module | C Source Files | Total C Lines |
//! |--------|---------------|---------------|
//! | `mod.rs` | `crypto/provider.c` (public API) | ~120 |
//! | `core.rs` | `crypto/provider_core.c`, `core_fetch.c`, `core_algorithm.c`, `provider_conf.c`, `provider_child.c` | ~3,900 |
//! | `predefined.rs` | `crypto/provider_predefined.c`, `provider_local.h` | ~65 |
//! | `property.rs` | `crypto/property/*.c` (7 files) | ~2,800 |
//! | **Total** | **14 C source files** | **~6,885** |
//!
//! ## Provider Traits (replacing `OSSL_DISPATCH`)
//!
//! Each algorithm category becomes a Rust trait:
//! - [`DigestProvider`] — Hash algorithm implementations
//! - [`CipherProvider`] — Symmetric cipher implementations
//! - [`MacProvider`] — Message authentication code implementations
//! - [`KdfProvider`] — Key derivation function implementations
//! - [`SignatureProvider`] — Digital signature implementations
//! - [`KemProvider`] — Key encapsulation mechanism implementations
//! - [`KeyMgmtProvider`] — Key management implementations
//! - [`KeyExchangeProvider`] — Key exchange implementations
//! - [`RandProvider`] — Random number generator implementations
//! - [`EncoderDecoderProvider`] — Key serialization implementations
//! - [`StoreProvider`] — Key/certificate store implementations
//!
//! ## Locking Strategy (Rule R7)
//!
//! The provider store uses `parking_lot::RwLock` with fine-grained locking:
//! - Provider store lock: protects provider list and child callbacks
//! - Default path lock: protects the search path
//! - Per-provider flag lock: protects init/activate flags
//! - Per-provider activatecnt lock: protects activation count
//! - Per-provider opbits lock: protects query cache bits
//! - Method store: sharded with 4 `RwLock`s for algorithm lookup scalability
//!
//! Lock ordering (deadlock prevention, from `provider_core.c` L101-108):
//! 1. Provider store lock (highest precedence)
//! 2. Provider flag\_lock
//! 3. Provider activatecnt\_lock
//!
//! ## Convenience Functions
//!
//! The module provides top-level convenience functions that mirror the C
//! `OSSL_PROVIDER_*()` public API from `crypto/provider.c`:
//!
//! - [`load()`] — Load a provider (disables fallback loading)
//! - [`try_load()`] — Try to load a provider (retains fallbacks)
//! - [`unload()`] — Unload a provider
//! - [`available()`] — Check if a provider is available

use std::sync::Arc;

use openssl_common::{CryptoResult, ParamSet};

// =============================================================================
// Submodule declarations
// =============================================================================

/// Provider core dispatch — store, instance lifecycle, activation, algorithm enumeration.
///
/// Translates `crypto/provider_core.c`, `crypto/core_fetch.c`,
/// `crypto/core_algorithm.c`, `crypto/provider_conf.c`, and
/// `crypto/provider_child.c`.
pub mod core;

/// Built-in provider registry — default, base, null, legacy, fips.
///
/// Translates `crypto/provider_predefined.c` and `crypto/provider_local.h`.
pub mod predefined;

/// Property query/match system for algorithm selection.
///
/// Translates `crypto/property/*.c` (7 files): `property.c`,
/// `property_parse.c`, `property_string.c`, `property_query.c`,
/// `defn_cache.c`, `property_local.h`.
pub mod property;

// =============================================================================
// Re-exports — core types
// =============================================================================

/// Re-exported from [`core`] — the central provider registry managing all
/// loaded providers, their activation state, and the method store.
pub use self::core::ProviderStore;

/// Re-exported from [`core`] — a single provider instance with lifecycle
/// management (init, activate, deactivate, algorithm registration).
pub use self::core::ProviderInstance;

/// Re-exported from [`core`] — algorithm operation identifier enum used
/// in [`Provider::query_operation`] to enumerate supported algorithms.
pub use self::core::OperationId;

/// Re-exported from [`core`] — metadata describing a single algorithm
/// offered by a provider (names, properties, operation ID).
pub use self::core::AlgorithmDescriptor;

/// Re-exported from [`core`] — configuration-driven provider activation
/// state tracking for `openssl.cnf`-based provider loading.
pub use self::core::ProviderConfState;

/// Re-exported from [`core`] — callback set for child library context
/// provider mirroring (on\_create, on\_remove, on\_global\_props).
pub use self::core::ChildProviderCallback;

// =============================================================================
// Re-exports — predefined types
// =============================================================================

/// Re-exported from [`predefined`] — metadata struct for a predefined
/// (built-in) provider: name, path, kind, parameters, fallback flag.
pub use predefined::ProviderInfo;

/// Re-exported from [`predefined`] — enum identifying the five built-in
/// provider implementations: Default, Base, Null, Legacy, Fips.
pub use predefined::ProviderKind;

/// Re-exported from [`predefined`] — name-value configuration parameter
/// pair used in provider info initialization.
pub use predefined::InfoPair;

/// Re-exported from [`predefined`] — returns the list of all built-in
/// providers registered at compile time.
pub use predefined::predefined_providers;

// =============================================================================
// Re-exports — property types
// =============================================================================

/// Re-exported from [`property`] — sorted list of property definitions
/// used for algorithm matching during fetch operations.
pub use property::PropertyList;

/// Re-exported from [`property`] — a single property entry with name,
/// type, comparison operator, optional flag, and value.
pub use property::PropertyDefinition;

/// Re-exported from [`property`] — comparison operator for property
/// matching: Eq, Ne, or Override.
pub use property::PropertyOper;

/// Re-exported from [`property`] — property type discriminator:
/// String, Number, or Unspecified.
pub use property::PropertyType;

/// Re-exported from [`property`] — typed property value: either a
/// numeric literal or an interned string index.
pub use property::PropertyValue;

/// Re-exported from [`property`] — newtype wrapper around `u32` for
/// interned property name/value indices.
pub use property::PropertyIndex;

/// Re-exported from [`property`] — string interning store for property
/// names and values, enabling efficient comparison by index.
pub use property::PropertyStringStore;

/// Re-exported from [`property`] — sharded algorithm implementation store
/// with per-algorithm query caches for efficient fetch operations.
pub use property::MethodStore;

/// Re-exported from [`property`] — a registered algorithm implementation
/// with its provider name, property definitions, and method handle.
pub use property::MethodImplementation;

/// Re-exported from [`property`] — cache of parsed property definition
/// strings, avoiding repeated parsing on algorithm registration.
pub use property::DefinitionCache;

/// Re-exported from [`property`] — reserved property index for the
/// boolean value `true` (interned as `"yes"` in the string store).
pub use property::PROPERTY_TRUE;

/// Re-exported from [`property`] — reserved property index for the
/// boolean value `false` (interned as `"no"` in the string store).
pub use property::PROPERTY_FALSE;

// =============================================================================
// Provider Trait — core provider interface (AAP §0.7.1)
// =============================================================================

/// Core provider trait — implemented by each provider (default, legacy, base,
/// null, fips).
///
/// Replaces the C `OSSL_provider_init_fn` callback and the provider-side
/// dispatch table from `crypto/provider_core.c`. Every provider must implement
/// this trait to participate in the algorithm dispatch system.
///
/// # Thread Safety
///
/// Providers are shared across threads via `Arc<dyn Provider>`, hence the
/// `Send + Sync` bound. All methods must be safe for concurrent invocation.
///
/// # C Source Mapping
///
/// | Method | C Function | Source |
/// |--------|-----------|--------|
/// | `name()` | `OSSL_PROVIDER_get0_name()` | `crypto/provider.c` L147 |
/// | `init()` | `OSSL_provider_init_fn` | `include/openssl/core.h` |
/// | `teardown()` | `OSSL_FUNC_provider_teardown_fn` | `core_dispatch.h` |
/// | `query_operation()` | `OSSL_FUNC_provider_query_operation_fn` | `core_dispatch.h` |
/// | `get_params()` | `OSSL_FUNC_provider_get_params_fn` | `core_dispatch.h` |
/// | `gettable_params()` | `OSSL_FUNC_provider_gettable_params_fn` | `core_dispatch.h` |
/// | `self_test()` | `OSSL_FUNC_provider_self_test_fn` | `core_dispatch.h` |
/// | `get_capabilities()` | `OSSL_FUNC_provider_get_capabilities_fn` | `core_dispatch.h` |
pub trait Provider: Send + Sync {
    /// Returns the provider's identifying name.
    ///
    /// Examples: `"default"`, `"fips"`, `"legacy"`, `"base"`, `"null"`.
    /// Replaces C `OSSL_PROVIDER_get0_name()` from `crypto/provider.c` L147-149.
    fn name(&self) -> &str;

    /// Initializes the provider. Called once during loading.
    ///
    /// Replaces the C `OSSL_provider_init_fn` callback invoked by
    /// `ossl_provider_activate()` in `crypto/provider_core.c`.
    /// Implementations should set up internal state, register algorithms,
    /// and perform any required self-tests.
    ///
    /// # Errors
    ///
    /// Returns `Err` if initialization fails (e.g., self-test failure for FIPS).
    fn init(&self) -> CryptoResult<()>;

    /// Tears down the provider. Called during unloading.
    ///
    /// Replaces C `OSSL_FUNC_provider_teardown_fn`. Implementations should
    /// release internal resources. This is called via the RAII `Drop` pattern
    /// when the last `Arc<ProviderInstance>` reference is released.
    fn teardown(&self);

    /// Queries which algorithms this provider offers for a given operation.
    ///
    /// Replaces C `OSSL_FUNC_provider_query_operation_fn`. Returns a list
    /// of algorithm descriptors (names + properties) for the requested
    /// operation category.
    ///
    /// # Arguments
    ///
    /// * `operation_id` — The algorithm category to query (e.g., `Digest`, `Cipher`).
    fn query_operation(&self, operation_id: OperationId) -> Vec<AlgorithmDescriptor>;

    /// Gets provider-specific parameters.
    ///
    /// Replaces C `OSSL_FUNC_provider_get_params_fn`. The caller passes a
    /// mutable [`ParamSet`] with the parameter names to retrieve; the provider
    /// fills in the corresponding values.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any requested parameter is unknown or cannot be retrieved.
    fn get_params(&self, params: &mut ParamSet) -> CryptoResult<()>;

    /// Lists the parameter names that can be retrieved via [`get_params`](Self::get_params).
    ///
    /// Replaces C `OSSL_FUNC_provider_gettable_params_fn`. Returns the list
    /// of parameter names as strings.
    fn gettable_params(&self) -> Vec<String>;

    /// Runs the provider's self-test.
    ///
    /// Replaces C `OSSL_FUNC_provider_self_test_fn` from `core_dispatch.h`.
    /// Primarily used by the FIPS provider to run Power-On Self-Tests (POST)
    /// and Known Answer Tests (KATs). Non-FIPS providers return `Ok(())` by
    /// default.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any self-test fails.
    fn self_test(&self) -> CryptoResult<()> {
        Ok(())
    }

    /// Gets provider capabilities for a named capability type.
    ///
    /// Replaces C `OSSL_FUNC_provider_get_capabilities_fn`. Returns a list
    /// of parameter sets describing the provider's capabilities for the
    /// requested type (e.g., `"TLS-GROUP"` for supported TLS groups).
    ///
    /// Returns an empty vector by default for providers that do not
    /// advertise capabilities.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the capability query fails.
    fn get_capabilities(&self, _capability: &str) -> CryptoResult<Vec<ParamSet>> {
        Ok(Vec::new())
    }
}

// =============================================================================
// DigestProvider + DigestContext — hash algorithm dispatch (OSSL_OP_DIGEST)
// =============================================================================

/// Digest (hash) provider trait.
///
/// Implemented by providers that offer hash algorithms (SHA-256, SHA-3, MD5, etc.).
/// Replaces C `OSSL_DISPATCH` entries for `OSSL_OP_DIGEST` from
/// `providers/implementations/digests/*.c`.
///
/// # Thread Safety
///
/// The provider itself is shared; individual [`DigestContext`] instances are not.
pub trait DigestProvider: Send + Sync {
    /// Returns the list of digest algorithm names offered by this provider.
    ///
    /// Examples: `["SHA2-256", "SHA2-512", "SHA3-256", "SHAKE256"]`.
    fn digest_names(&self) -> Vec<String>;

    /// Creates a new digest context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_digest_newctx_fn`. The returned context is
    /// used for a single hash computation (update → finalize).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_digest_ctx(&self, name: &str) -> CryptoResult<Box<dyn DigestContext>>;
}

/// Digest operation context — stateful hash computation.
///
/// Replaces the C `OSSL_FUNC_digest_*_fn` family of dispatch entries.
/// Each context holds the intermediate hash state for a single computation.
pub trait DigestContext: Send + Sync {
    /// Feeds data into the hash computation.
    ///
    /// Replaces C `OSSL_FUNC_digest_update_fn`. Can be called multiple times
    /// to process data in chunks.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context is in an invalid state.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()>;

    /// Finalizes the hash computation and returns the digest.
    ///
    /// Replaces C `OSSL_FUNC_digest_final_fn`. After calling this, the
    /// context should not be reused (create a new one or call `clone_ctx()`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if finalization fails.
    fn finalize(&mut self) -> CryptoResult<Vec<u8>>;

    /// Returns the output digest size in bytes.
    ///
    /// Replaces C `OSSL_FUNC_digest_get_params_fn` with `OSSL_DIGEST_PARAM_SIZE`.
    fn digest_size(&self) -> usize;

    /// Returns the internal block size in bytes.
    ///
    /// Replaces C `OSSL_FUNC_digest_get_params_fn` with `OSSL_DIGEST_PARAM_BLOCK_SIZE`.
    fn block_size(&self) -> usize;

    /// Clones this digest context, duplicating the current intermediate state.
    ///
    /// Replaces C `OSSL_FUNC_digest_dupctx_fn`. Useful for computing
    /// multiple digests that share a common prefix.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context cannot be cloned.
    fn clone_ctx(&self) -> CryptoResult<Box<dyn DigestContext>>;
}

// =============================================================================
// CipherProvider + CipherContext — symmetric cipher dispatch (OSSL_OP_CIPHER)
// =============================================================================

/// Cipher provider trait.
///
/// Implemented by providers that offer symmetric cipher algorithms
/// (AES-GCM, ChaCha20-Poly1305, 3DES, etc.). Replaces C `OSSL_DISPATCH`
/// entries for `OSSL_OP_CIPHER` from `providers/implementations/ciphers/*.c`.
pub trait CipherProvider: Send + Sync {
    /// Returns the list of cipher algorithm names offered by this provider.
    ///
    /// Examples: `["AES-256-GCM", "AES-128-CBC", "CHACHA20-POLY1305"]`.
    fn cipher_names(&self) -> Vec<String>;

    /// Creates a new cipher context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_cipher_newctx_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_cipher_ctx(&self, name: &str) -> CryptoResult<Box<dyn CipherContext>>;
}

/// Cipher operation context — stateful encryption/decryption.
///
/// Replaces the C `OSSL_FUNC_cipher_*_fn` family of dispatch entries.
/// Each context holds the cipher state for a single encrypt or decrypt
/// operation.
pub trait CipherContext: Send + Sync {
    /// Initializes the context for encryption with the given key and IV.
    ///
    /// Replaces C `OSSL_FUNC_cipher_encrypt_init_fn`.
    ///
    /// # Arguments
    ///
    /// * `key` — Encryption key bytes.
    /// * `iv` — Initialization vector (optional for ECB mode).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key/IV lengths are invalid.
    fn encrypt_init(&mut self, key: &[u8], iv: Option<&[u8]>) -> CryptoResult<()>;

    /// Initializes the context for decryption with the given key and IV.
    ///
    /// Replaces C `OSSL_FUNC_cipher_decrypt_init_fn`.
    ///
    /// # Arguments
    ///
    /// * `key` — Decryption key bytes.
    /// * `iv` — Initialization vector (optional for ECB mode).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key/IV lengths are invalid.
    fn decrypt_init(&mut self, key: &[u8], iv: Option<&[u8]>) -> CryptoResult<()>;

    /// Processes a chunk of input data.
    ///
    /// Replaces C `OSSL_FUNC_cipher_update_fn`. Appends processed output
    /// to the provided buffer and returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context is not initialized or processing fails.
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<usize>;

    /// Finalizes the cipher operation and writes any remaining output.
    ///
    /// Replaces C `OSSL_FUNC_cipher_final_fn`. Returns the number of bytes
    /// written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if finalization fails (e.g., authentication tag mismatch
    /// for AEAD ciphers).
    fn finalize(&mut self, output: &mut Vec<u8>) -> CryptoResult<usize>;

    /// Returns the key length in bytes.
    ///
    /// Replaces C `OSSL_FUNC_cipher_get_params_fn` with `OSSL_CIPHER_PARAM_KEYLEN`.
    fn key_length(&self) -> usize;

    /// Returns the IV length in bytes.
    ///
    /// Replaces C `OSSL_FUNC_cipher_get_params_fn` with `OSSL_CIPHER_PARAM_IVLEN`.
    fn iv_length(&self) -> usize;

    /// Returns the block size in bytes.
    ///
    /// Replaces C `OSSL_FUNC_cipher_get_params_fn` with `OSSL_CIPHER_PARAM_BLOCK_SIZE`.
    fn block_size(&self) -> usize;
}

// =============================================================================
// MacProvider + MacContext — MAC dispatch (OSSL_OP_MAC)
// =============================================================================

/// MAC (Message Authentication Code) provider trait.
///
/// Implemented by providers that offer MAC algorithms (HMAC, CMAC, GMAC,
/// KMAC, Poly1305, `SipHash`). Replaces C `OSSL_DISPATCH` entries for
/// `OSSL_OP_MAC` from `providers/implementations/macs/*.c`.
pub trait MacProvider: Send + Sync {
    /// Returns the list of MAC algorithm names offered by this provider.
    ///
    /// Examples: `["HMAC", "CMAC", "GMAC", "KMAC-128", "KMAC-256"]`.
    fn mac_names(&self) -> Vec<String>;

    /// Creates a new MAC context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_mac_newctx_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_mac_ctx(&self, name: &str) -> CryptoResult<Box<dyn MacContext>>;
}

/// MAC operation context — stateful message authentication computation.
///
/// Replaces the C `OSSL_FUNC_mac_*_fn` family of dispatch entries.
pub trait MacContext: Send + Sync {
    /// Initializes the MAC context with a key and optional parameters.
    ///
    /// Replaces C `OSSL_FUNC_mac_init_fn`. The optional [`ParamSet`] allows
    /// algorithm-specific configuration (e.g., underlying digest for HMAC).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key length is invalid or parameters are malformed.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> CryptoResult<()>;

    /// Feeds data into the MAC computation.
    ///
    /// Replaces C `OSSL_FUNC_mac_update_fn`. Can be called multiple times.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context is not initialized.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()>;

    /// Finalizes the MAC computation and returns the authentication tag.
    ///
    /// Replaces C `OSSL_FUNC_mac_final_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if finalization fails.
    fn finalize(&mut self) -> CryptoResult<Vec<u8>>;

    /// Returns the MAC output size in bytes.
    ///
    /// Replaces C `OSSL_FUNC_mac_get_params_fn` with `OSSL_MAC_PARAM_SIZE`.
    fn mac_size(&self) -> usize;
}

// =============================================================================
// KdfProvider + KdfContext — KDF dispatch (OSSL_OP_KDF)
// =============================================================================

/// KDF (Key Derivation Function) provider trait.
///
/// Implemented by providers that offer KDF algorithms (HKDF, PBKDF2, Argon2,
/// scrypt, KBKDF). Replaces C `OSSL_DISPATCH` entries for `OSSL_OP_KDF`
/// from `providers/implementations/kdfs/*.c`.
pub trait KdfProvider: Send + Sync {
    /// Returns the list of KDF algorithm names offered by this provider.
    ///
    /// Examples: `["HKDF", "PBKDF2", "ARGON2D", "ARGON2ID", "SCRYPT"]`.
    fn kdf_names(&self) -> Vec<String>;

    /// Creates a new KDF context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_kdf_newctx_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_kdf_ctx(&self, name: &str) -> CryptoResult<Box<dyn KdfContext>>;
}

/// KDF operation context — stateful key derivation.
///
/// Replaces the C `OSSL_FUNC_kdf_*_fn` family of dispatch entries.
pub trait KdfContext: Send + Sync {
    /// Derives key material into the provided buffer.
    ///
    /// Replaces C `OSSL_FUNC_kdf_derive_fn`. The [`ParamSet`] provides
    /// algorithm-specific parameters (salt, info, iterations, etc.).
    ///
    /// # Errors
    ///
    /// Returns `Err` if derivation fails or parameters are invalid.
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> CryptoResult<()>;

    /// Sets parameters on the KDF context.
    ///
    /// Replaces C `OSSL_FUNC_kdf_set_ctx_params_fn`. Allows configuring
    /// the KDF before calling [`derive`](Self::derive).
    ///
    /// # Errors
    ///
    /// Returns `Err` if any parameter is unknown or invalid.
    fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()>;
}

// =============================================================================
// SignatureProvider + SignContext — signature dispatch (OSSL_OP_SIGNATURE)
// =============================================================================

/// Signature provider trait.
///
/// Implemented by providers that offer digital signature algorithms (RSA,
/// ECDSA, `EdDSA`, ML-DSA, SLH-DSA). Replaces C `OSSL_DISPATCH` entries for
/// `OSSL_OP_SIGNATURE` from `providers/implementations/signature/*.c`.
pub trait SignatureProvider: Send + Sync {
    /// Returns the list of signature algorithm names offered by this provider.
    ///
    /// Examples: `["RSA", "ECDSA", "ED25519", "ED448", "ML-DSA-65"]`.
    fn signature_names(&self) -> Vec<String>;

    /// Creates a new signature context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_signature_newctx_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_sign_ctx(&self, name: &str) -> CryptoResult<Box<dyn SignContext>>;
}

/// Signature operation context — stateful sign/verify operations.
///
/// Replaces the C `OSSL_FUNC_signature_*_fn` family of dispatch entries.
pub trait SignContext: Send + Sync {
    /// Initializes the context for signing with the given private key data.
    ///
    /// Replaces C `OSSL_FUNC_signature_sign_init_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key data is invalid or the algorithm does not
    /// support signing.
    fn sign_init(&mut self, key_data: &[u8]) -> CryptoResult<()>;

    /// Signs the given data and returns the signature.
    ///
    /// Replaces C `OSSL_FUNC_signature_sign_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context is not initialized for signing or
    /// the signing operation fails.
    fn sign(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Initializes the context for verification with the given public key data.
    ///
    /// Replaces C `OSSL_FUNC_signature_verify_init_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key data is invalid.
    fn verify_init(&mut self, key_data: &[u8]) -> CryptoResult<()>;

    /// Verifies a signature over the given data.
    ///
    /// Replaces C `OSSL_FUNC_signature_verify_fn`. Returns `true` if the
    /// signature is valid, `false` if it is invalid (not an error — Rule R5).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context is not initialized for verification or
    /// the verification operation encounters a fatal error.
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> CryptoResult<bool>;
}

// =============================================================================
// KemProvider + KemContext — KEM dispatch (OSSL_OP_KEM)
// =============================================================================

/// KEM (Key Encapsulation Mechanism) provider trait.
///
/// Implemented by providers that offer KEM algorithms (RSA-KEM, EC-KEM,
/// ML-KEM). Replaces C `OSSL_DISPATCH` entries for `OSSL_OP_KEM` from
/// `providers/implementations/kem/*.c`.
pub trait KemProvider: Send + Sync {
    /// Returns the list of KEM algorithm names offered by this provider.
    ///
    /// Examples: `["RSA", "ML-KEM-768", "ML-KEM-1024"]`.
    fn kem_names(&self) -> Vec<String>;

    /// Creates a new KEM context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_kem_newctx_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_kem_ctx(&self, name: &str) -> CryptoResult<Box<dyn KemContext>>;
}

/// KEM operation context — stateful encapsulate/decapsulate operations.
///
/// Replaces the C `OSSL_FUNC_kem_*_fn` family of dispatch entries.
pub trait KemContext: Send + Sync {
    /// Encapsulates a shared secret using the given public key.
    ///
    /// Replaces C `OSSL_FUNC_kem_encapsulate_fn`. Returns a tuple of
    /// `(ciphertext, shared_secret)`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if encapsulation fails.
    fn encapsulate(&mut self, public_key: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)>;

    /// Decapsulates a shared secret using the given private key and ciphertext.
    ///
    /// Replaces C `OSSL_FUNC_kem_decapsulate_fn`. Returns the recovered
    /// shared secret.
    ///
    /// # Errors
    ///
    /// Returns `Err` if decapsulation fails.
    fn decapsulate(&mut self, private_key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>>;
}

// =============================================================================
// KeyMgmtProvider — key management dispatch (OSSL_OP_KEYMGMT)
// =============================================================================

/// Key management provider trait.
///
/// Implemented by providers that manage cryptographic keys (generation,
/// import, export). Replaces C `OSSL_DISPATCH` entries for `OSSL_OP_KEYMGMT`
/// from `providers/implementations/keymgmt/*.c`.
pub trait KeyMgmtProvider: Send + Sync {
    /// Returns the list of key management algorithm names.
    ///
    /// Examples: `["RSA", "EC", "X25519", "ED25519", "ML-KEM-768"]`.
    fn keymgmt_names(&self) -> Vec<String>;

    /// Generates a new key pair for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_keymgmt_gen_fn`. The [`ParamSet`] provides
    /// algorithm-specific generation parameters (key size, curve name, etc.).
    ///
    /// Returns the serialized key data.
    ///
    /// # Errors
    ///
    /// Returns `Err` if generation fails or parameters are invalid.
    fn generate_key(&self, algorithm: &str, params: &ParamSet) -> CryptoResult<Vec<u8>>;

    /// Imports key data for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_keymgmt_import_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key data is malformed.
    fn import_key(&self, algorithm: &str, data: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Exports key data from an internal representation.
    ///
    /// Replaces C `OSSL_FUNC_keymgmt_export_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if export fails.
    fn export_key(&self, key_data: &[u8]) -> CryptoResult<Vec<u8>>;
}

// =============================================================================
// KeyExchangeProvider + KeyExchangeContext — key exchange (OSSL_OP_KEYEXCH)
// =============================================================================

/// Key exchange provider trait.
///
/// Implemented by providers that offer key exchange algorithms (DH, ECDH,
/// X25519, X448). Replaces C `OSSL_DISPATCH` entries for `OSSL_OP_KEYEXCH`
/// from `providers/implementations/exchange/*.c`.
pub trait KeyExchangeProvider: Send + Sync {
    /// Returns the list of key exchange algorithm names.
    ///
    /// Examples: `["DH", "ECDH", "X25519", "X448"]`.
    fn exchange_names(&self) -> Vec<String>;

    /// Creates a new key exchange context for the named algorithm.
    ///
    /// Replaces C `OSSL_FUNC_keyexch_newctx_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the algorithm name is not supported.
    fn new_exchange_ctx(&self, name: &str) -> CryptoResult<Box<dyn KeyExchangeContext>>;
}

/// Key exchange operation context — stateful Diffie-Hellman style exchange.
///
/// Replaces the C `OSSL_FUNC_keyexch_*_fn` family of dispatch entries.
pub trait KeyExchangeContext: Send + Sync {
    /// Initializes the context with a private key.
    ///
    /// Replaces C `OSSL_FUNC_keyexch_init_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the key data is invalid.
    fn init(&mut self, private_key: &[u8]) -> CryptoResult<()>;

    /// Sets the peer's public key.
    ///
    /// Replaces C `OSSL_FUNC_keyexch_set_peer_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the peer key data is invalid.
    fn set_peer(&mut self, peer_public_key: &[u8]) -> CryptoResult<()>;

    /// Derives the shared secret.
    ///
    /// Replaces C `OSSL_FUNC_keyexch_derive_fn`. Returns the shared secret
    /// bytes. Both [`init`](Self::init) and [`set_peer`](Self::set_peer) must
    /// be called before derivation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the context is not fully initialized or derivation fails.
    fn derive(&mut self) -> CryptoResult<Vec<u8>>;
}

// =============================================================================
// RandProvider — random number generation dispatch (OSSL_OP_RAND)
// =============================================================================

/// Random number provider trait.
///
/// Implemented by providers that offer random number generation (DRBG,
/// CTR-DRBG, Hash-DRBG, HMAC-DRBG, seed sources). Replaces C `OSSL_DISPATCH`
/// entries for `OSSL_OP_RAND` from `providers/implementations/rands/*.c`.
pub trait RandProvider: Send + Sync {
    /// Generates random bytes into the provided buffer.
    ///
    /// Replaces C `OSSL_FUNC_rand_generate_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the random number generator fails.
    fn generate(&self, buf: &mut [u8]) -> CryptoResult<()>;

    /// Seeds the random number generator with the given data.
    ///
    /// Replaces C `OSSL_FUNC_rand_seed_fn`. Used to provide additional
    /// entropy to the generator.
    ///
    /// # Errors
    ///
    /// Returns `Err` if seeding fails.
    fn seed(&self, data: &[u8]) -> CryptoResult<()>;
}

// =============================================================================
// EncoderDecoderProvider — encode/decode dispatch (OSSL_OP_ENCODER/DECODER)
// =============================================================================

/// Encoder/Decoder provider trait.
///
/// Implemented by providers that offer key serialization and deserialization
/// (PEM, DER, PKCS#8, `SubjectPublicKeyInfo`, etc.). Replaces C `OSSL_DISPATCH`
/// entries for `OSSL_OP_ENCODER` and `OSSL_OP_DECODER` from
/// `providers/implementations/encode_decode/*.c`.
pub trait EncoderDecoderProvider: Send + Sync {
    /// Returns the list of encoder names.
    ///
    /// Examples: `["PEM", "DER", "TEXT"]`.
    fn encoder_names(&self) -> Vec<String>;

    /// Returns the list of decoder names.
    ///
    /// Examples: `["PEM", "DER"]`.
    fn decoder_names(&self) -> Vec<String>;

    /// Encodes data using the named encoder.
    ///
    /// Replaces C `OSSL_FUNC_encoder_encode_fn`. The [`ParamSet`] provides
    /// format-specific parameters (structure type, cipher for encryption, etc.).
    ///
    /// # Errors
    ///
    /// Returns `Err` if encoding fails.
    fn encode(&self, name: &str, data: &[u8], params: &ParamSet) -> CryptoResult<Vec<u8>>;

    /// Decodes data using the named decoder.
    ///
    /// Replaces C `OSSL_FUNC_decoder_decode_fn`. The [`ParamSet`] provides
    /// format-specific parameters (expected structure, passphrase callback, etc.).
    ///
    /// # Errors
    ///
    /// Returns `Err` if decoding fails.
    fn decode(&self, name: &str, data: &[u8], params: &ParamSet) -> CryptoResult<Vec<u8>>;
}

// =============================================================================
// StoreProvider + StoreContext — key/cert store dispatch (OSSL_OP_STORE)
// =============================================================================

/// Store provider trait.
///
/// Implemented by providers that offer URI-based key/certificate storage
/// (file:// scheme, pkcs11:// scheme, etc.). Replaces C `OSSL_DISPATCH`
/// entries for `OSSL_OP_STORE` from `providers/implementations/storemgmt/*.c`.
pub trait StoreProvider: Send + Sync {
    /// Opens a store at the given URI and returns a context for loading objects.
    ///
    /// Replaces C `OSSL_FUNC_store_open_fn`.
    ///
    /// # Arguments
    ///
    /// * `uri` — The store URI (e.g., `"file:///etc/ssl/certs/ca.pem"`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the URI is invalid or the store cannot be opened.
    fn open(&self, uri: &str) -> CryptoResult<Box<dyn StoreContext>>;
}

/// Store operation context — stateful iteration over stored objects.
///
/// Replaces the C `OSSL_FUNC_store_*_fn` family of dispatch entries.
/// Objects are loaded one at a time via [`load`](Self::load) until
/// [`eof`](Self::eof) returns `true`.
pub trait StoreContext: Send + Sync {
    /// Loads the next object from the store.
    ///
    /// Replaces C `OSSL_FUNC_store_load_fn`. Returns `Ok(Some(data))` for
    /// each object, or `Ok(None)` when no more objects are available (Rule R5).
    ///
    /// # Errors
    ///
    /// Returns `Err` if loading fails.
    fn load(&mut self) -> CryptoResult<Option<Vec<u8>>>;

    /// Returns `true` if all objects have been loaded.
    ///
    /// Replaces C `OSSL_FUNC_store_eof_fn`.
    fn eof(&self) -> bool;

    /// Closes the store context and releases resources.
    ///
    /// Replaces C `OSSL_FUNC_store_close_fn`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if closing fails.
    fn close(&mut self) -> CryptoResult<()>;
}

// =============================================================================
// Convenience functions — public API (from crypto/provider.c)
// =============================================================================

/// Loads a provider by name into the given store.
///
/// Replaces C `OSSL_PROVIDER_load()` from `crypto/provider.c` L66-69.
/// Loading a provider disables fallback loading (matching the C behavior
/// where `OSSL_PROVIDER_load()` calls `ossl_provider_disable_fallback_loading()`
/// before delegating to `OSSL_PROVIDER_try_load_ex()` with `retain_fallbacks=0`).
///
/// # Arguments
///
/// * `store` — The provider store to load into.
/// * `name` — The provider name (e.g., `"default"`, `"fips"`, `"legacy"`).
///
/// # Errors
///
/// Returns `Err` if the provider cannot be found or activation fails.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use openssl_crypto::provider::{ProviderStore, PropertyStringStore, load};
/// let strings = Arc::new(PropertyStringStore::new());
/// let store = ProviderStore::new(strings);
/// let provider = load(&store, "default").expect("failed to load default provider");
/// assert!(provider.is_activated());
/// ```
pub fn load(store: &ProviderStore, name: &str) -> CryptoResult<Arc<ProviderInstance>> {
    store.load(name, false)
}

/// Tries to load a provider by name, retaining fallback providers.
///
/// Replaces C `OSSL_PROVIDER_try_load()` from `crypto/provider.c` L52-55.
/// Unlike [`load()`], this function does not disable fallback loading,
/// allowing the default provider to remain active as a fallback.
///
/// # Arguments
///
/// * `store` — The provider store to load into.
/// * `name` — The provider name (e.g., `"fips"`, `"legacy"`).
///
/// # Errors
///
/// Returns `Err` if the provider cannot be found or activation fails.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use openssl_crypto::provider::{ProviderStore, PropertyStringStore, try_load};
/// let strings = Arc::new(PropertyStringStore::new());
/// let store = ProviderStore::new(strings);
/// let provider = try_load(&store, "fips").expect("failed to try-load fips provider");
/// ```
pub fn try_load(store: &ProviderStore, name: &str) -> CryptoResult<Arc<ProviderInstance>> {
    store.try_load(name, true)
}

/// Unloads a provider by name from the given store.
///
/// Replaces C `OSSL_PROVIDER_unload()` from `crypto/provider.c` L71-77.
/// Deactivates the provider and removes its algorithm registrations from
/// the method store.
///
/// # Arguments
///
/// * `store` — The provider store to unload from.
/// * `name` — The provider name to unload.
///
/// # Errors
///
/// Returns `Err` if the provider is not found or deactivation fails.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use openssl_crypto::provider::{ProviderStore, PropertyStringStore, load, unload};
/// let strings = Arc::new(PropertyStringStore::new());
/// let store = ProviderStore::new(strings);
/// load(&store, "legacy").expect("failed to load");
/// unload(&store, "legacy").expect("failed to unload");
/// ```
pub fn unload(store: &ProviderStore, name: &str) -> CryptoResult<()> {
    store.unload(name)
}

/// Checks if a provider is available (loaded and activated) in the store.
///
/// Replaces C `OSSL_PROVIDER_available()` (inferred from the C public API
/// pattern). Returns `true` if the named provider is found and activated.
///
/// # Arguments
///
/// * `store` — The provider store to query.
/// * `name` — The provider name to check.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use openssl_crypto::provider::{ProviderStore, PropertyStringStore, load, available};
/// let strings = Arc::new(PropertyStringStore::new());
/// let store = ProviderStore::new(strings);
/// assert!(!available(&store, "default"));
/// load(&store, "default").expect("failed to load");
/// assert!(available(&store, "default"));
/// ```
pub fn available(store: &ProviderStore, name: &str) -> bool {
    store.available(name)
}
