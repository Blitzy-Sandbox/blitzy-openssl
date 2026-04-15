//! Provider trait definitions that replace C `OSSL_DISPATCH` function pointer tables.
//!
//! Defines the full trait hierarchy for all algorithm categories:
//! [`DigestProvider`], [`CipherProvider`], [`SignatureProvider`], [`KemProvider`],
//! [`KdfProvider`], [`MacProvider`], [`KeyMgmtProvider`], [`KeyExchangeProvider`],
//! [`RandProvider`], [`EncoderProvider`], [`DecoderProvider`], [`StoreProvider`].
//!
//! Also defines the master [`Provider`] trait with methods for metadata,
//! gettable parameters, and operation querying.
//!
//! # Architecture
//!
//! In the original C codebase, each provider exports an `OSSL_DISPATCH` table —
//! a flat array of `{function_id, function_ptr}` pairs registered via
//! `OSSL_provider_init()`.  The core fetches algorithms by iterating these
//! tables and matching function IDs.
//!
//! In the Rust workspace, each `OSSL_DISPATCH` table is replaced by a Rust
//! trait.  Each algorithm category becomes a trait (e.g. [`DigestProvider`]),
//! and providers implement the relevant traits.  Algorithm selection uses
//! dynamic dispatch via `Box<dyn AlgorithmProvider>`, preserving runtime
//! selection while eliminating function-pointer unsafety.
//!
//! # Source Reference
//!
//! - `include/openssl/core_dispatch.h` — function ID definitions (IDs 1–1035)
//! - `include/openssl/core.h` — `OSSL_DISPATCH`, `OSSL_ALGORITHM`, `OSSL_PARAM`
//! - `include/openssl/core_names.h` — parameter name constants
//! - `providers/common/providercommon.c` — `ossl_prov_is_running()`
//! - `providers/common/provider_util.c` — provider utility helpers
//!
//! # Rules Enforced
//!
//! - **R5:** All trait methods return `ProviderResult<T>` or `Option<T>`, never
//!   sentinel values.
//! - **R6:** No bare `as` casts; all size parameters use `usize`.
//! - **R7:** Traits are lock-free by design; locking is the responsibility of
//!   the store/registry layer.
//! - **R8:** Zero `unsafe` code — dynamic dispatch via `Box<dyn>` is safe.
//! - **R9:** Warning-free; every public item has a `///` doc comment.
//! - **R10:** Every trait is reachable via EVP API → provider dispatch →
//!   specific trait implementation.

use std::fmt;

use openssl_common::error::ProviderResult;
use openssl_common::param::ParamSet;
use openssl_common::types::OperationType;

// =============================================================================
// ProviderInfo — Provider Metadata
// =============================================================================

/// Provider metadata returned by [`Provider::info()`].
///
/// Replaces the C `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`,
/// `OSSL_PROV_PARAM_BUILDINFO`, and `OSSL_PROV_PARAM_STATUS` parameters
/// (from `include/openssl/core_names.h`).
///
/// Serialisable via [`serde::Serialize`] for diagnostics output, structured
/// logging, and observability integration.
///
/// # Examples
///
/// ```
/// use openssl_provider::traits::ProviderInfo;
///
/// let info = ProviderInfo {
///     name: "OpenSSL Default Provider",
///     version: "4.0.0",
///     build_info: "4.0.0-dev",
///     status: true,
/// };
/// assert!(info.status);
/// ```
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderInfo {
    /// Human-readable provider name (e.g. `"OpenSSL Default Provider"`).
    pub name: &'static str,
    /// Provider version string (e.g. `"4.0.0"`).
    pub version: &'static str,
    /// Build information string (e.g. `"4.0.0-dev"`).
    pub build_info: &'static str,
    /// Whether the provider is currently operational.
    pub status: bool,
}

// =============================================================================
// AlgorithmDescriptor — Algorithm Description
// =============================================================================

/// Describes a single algorithm implementation offered by a provider.
///
/// Replaces the C `OSSL_ALGORITHM` struct (`include/openssl/core.h`):
///
/// ```c
/// struct ossl_algorithm_st {
///     const char *algorithm_names;        /* key */
///     const char *property_definition;    /* key */
///     const OSSL_DISPATCH *implementation;
///     const char *algorithm_description;
/// };
/// ```
///
/// In Rust the dispatch table is replaced by the trait implementation itself,
/// so this struct only carries the metadata portion.
///
/// # Examples
///
/// ```
/// use openssl_provider::traits::AlgorithmDescriptor;
///
/// let desc = AlgorithmDescriptor {
///     names: vec!["SHA2-256", "SHA-256", "SHA256"],
///     property: "provider=default",
///     description: "SHA-2 256-bit digest",
/// };
/// assert_eq!(desc.names[0], "SHA2-256");
/// ```
#[derive(Debug, Clone)]
pub struct AlgorithmDescriptor {
    /// Algorithm names (primary + aliases), e.g. `["SHA2-256", "SHA-256", "SHA256"]`.
    ///
    /// The first name is canonical; subsequent names are aliases used for
    /// backward-compatible lookup.  Corresponds to the comma-separated
    /// `algorithm_names` field in the C `OSSL_ALGORITHM` struct.
    pub names: Vec<&'static str>,

    /// Property query string, e.g. `"provider=default"`.
    ///
    /// Used by the method store to select among competing implementations.
    /// Corresponds to `property_definition` in the C `OSSL_ALGORITHM` struct.
    pub property: &'static str,

    /// Human-readable description for documentation and diagnostics.
    ///
    /// Corresponds to `algorithm_description` in the C `OSSL_ALGORITHM` struct.
    pub description: &'static str,
}

// =============================================================================
// Provider — Master Provider Trait
// =============================================================================

/// Master provider trait — every built-in and dynamically-loaded provider must
/// implement this.
///
/// Replaces the C `OSSL_FUNC_PROVIDER_*` dispatch entries from
/// `include/openssl/core_dispatch.h` (function IDs 1024–1035):
///
/// | Rust method          | C function ID                          |
/// |----------------------|----------------------------------------|
/// | [`info()`]           | `OSSL_FUNC_provider_get_params` (1026) |
/// | [`query_operation()`]| `OSSL_FUNC_provider_query_operation` (1027) |
/// | [`get_params()`]     | `OSSL_FUNC_provider_get_params` (1026) |
/// | [`gettable_params()`]| `OSSL_FUNC_provider_gettable_params` (1025) |
/// | [`is_running()`]     | `ossl_prov_is_running()` (`prov_running.c`) |
/// | [`teardown()`]       | `OSSL_FUNC_provider_teardown` (1024)   |
///
/// # Thread Safety
///
/// The `Send + Sync` bounds ensure providers can be shared across threads
/// via `Arc<dyn Provider>`.  The `fmt::Debug` supertrait enables diagnostic
/// output for tracing and error reporting.
///
/// [`info()`]: Provider::info
/// [`query_operation()`]: Provider::query_operation
/// [`get_params()`]: Provider::get_params
/// [`gettable_params()`]: Provider::gettable_params
/// [`is_running()`]: Provider::is_running
/// [`teardown()`]: Provider::teardown
pub trait Provider: Send + Sync + fmt::Debug {
    /// Returns provider metadata (name, version, build info, status).
    ///
    /// Replaces the subset of `OSSL_FUNC_provider_get_params` (ID 1026)
    /// that retrieves `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`,
    /// `OSSL_PROV_PARAM_BUILDINFO`, and `OSSL_PROV_PARAM_STATUS`.
    fn info(&self) -> ProviderInfo;

    /// Queries available algorithms for a given operation type.
    ///
    /// Returns `None` if the provider does not support this operation.
    /// Returns `Some(vec![...])` with algorithm descriptors if supported.
    ///
    /// Replaces `OSSL_FUNC_provider_query_operation` (ID 1027).
    fn query_operation(&self, op: OperationType) -> Option<Vec<AlgorithmDescriptor>>;

    /// Returns provider parameters as a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_provider_get_params` (ID 1026).
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Returns the list of gettable parameter keys.
    ///
    /// Replaces `OSSL_FUNC_provider_gettable_params` (ID 1025).
    ///
    /// The default implementation returns the standard parameter names
    /// `["name", "version", "buildinfo", "status"]`.
    fn gettable_params(&self) -> Vec<&'static str> {
        vec!["name", "version", "buildinfo", "status"]
    }

    /// Whether this provider is in a running / healthy state.
    ///
    /// Replaces `ossl_prov_is_running()` from `providers/common/providercommon.c`.
    fn is_running(&self) -> bool;

    /// Teardown / cleanup.
    ///
    /// Called when the provider is being unloaded or the library context is
    /// freed.  Replaces `OSSL_FUNC_provider_teardown` (ID 1024).
    ///
    /// The default implementation is a no-op that returns `Ok(())`.
    fn teardown(&mut self) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// AlgorithmProvider — Marker Trait for Dynamic Dispatch
// =============================================================================

/// Marker trait for any algorithm provider implementation.
///
/// Used for type-erasure in the [`MethodStore`](crate::dispatch) when
/// heterogeneous algorithm implementations need to be stored in a single
/// collection.  Every algorithm-specific provider trait
/// ([`DigestProvider`], [`CipherProvider`], etc.) is an implicit sub-concept
/// of this marker.
///
/// # Thread Safety
///
/// The `Send + Sync` bounds enable storage in `Arc`-wrapped containers.
/// The `fmt::Debug` bound enables diagnostic logging.
pub trait AlgorithmProvider: Send + Sync + fmt::Debug {}

// =============================================================================
// DigestProvider / DigestContext — Message Digest Operations
// =============================================================================

/// Provider-side message digest implementation.
///
/// Replaces the `OSSL_FUNC_digest_*` dispatch entries (IDs 1–17) from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// DigestProvider::new_ctx()
///   → DigestContext::init()
///   → DigestContext::update()  (one or more times)
///   → DigestContext::finalize()
/// ```
///
/// Contexts can be duplicated mid-stream via [`DigestContext::duplicate()`]
/// to support the `EVP_MD_CTX_copy_ex()` pattern.
pub trait DigestProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"SHA2-256"`).
    fn name(&self) -> &'static str;

    /// Returns the internal block size in bytes (e.g. 64 for SHA-256).
    fn block_size(&self) -> usize;

    /// Returns the output digest size in bytes (e.g. 32 for SHA-256).
    fn digest_size(&self) -> usize;

    /// Creates a new digest context for streaming hash computation.
    ///
    /// Replaces `OSSL_FUNC_digest_newctx` (ID 1).
    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>>;
}

/// Streaming digest context for incremental hash computation.
///
/// Replaces the `OSSL_FUNC_digest_init/update/final/dupctx/freectx` family
/// (IDs 2–7) plus the context parameter getters/setters (IDs 9–10).
///
/// The context is consumed by [`finalize()`](DigestContext::finalize) and
/// freed automatically when dropped (replaces `OSSL_FUNC_digest_freectx`).
pub trait DigestContext: Send + Sync {
    /// Initialises (or resets) the digest context with optional parameters.
    ///
    /// Replaces `OSSL_FUNC_digest_init` (ID 2).
    fn init(&mut self, params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Feeds additional data into the running digest.
    ///
    /// Replaces `OSSL_FUNC_digest_update` (ID 3).
    fn update(&mut self, data: &[u8]) -> ProviderResult<()>;

    /// Finalises the digest and returns the hash output.
    ///
    /// Replaces `OSSL_FUNC_digest_final` (ID 4).
    fn finalize(&mut self) -> ProviderResult<Vec<u8>>;

    /// Duplicates the context, producing an independent copy of the
    /// current intermediate state.
    ///
    /// Replaces `OSSL_FUNC_digest_dupctx` (ID 7).
    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_digest_get_ctx_params` (ID 10).
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_digest_set_ctx_params` (ID 9).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// CipherProvider / CipherContext — Symmetric Cipher Operations
// =============================================================================

/// Provider-side symmetric cipher implementation.
///
/// Replaces the `OSSL_FUNC_cipher_*` dispatch entries (IDs 1–20) from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// CipherProvider::new_ctx()
///   → CipherContext::encrypt_init() or decrypt_init()
///   → CipherContext::update()  (one or more times)
///   → CipherContext::finalize()
/// ```
pub trait CipherProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"AES-256-GCM"`).
    fn name(&self) -> &'static str;

    /// Returns the key length in bytes (e.g. 32 for AES-256).
    fn key_length(&self) -> usize;

    /// Returns the IV / nonce length in bytes (e.g. 12 for GCM).
    fn iv_length(&self) -> usize;

    /// Returns the cipher block size in bytes (e.g. 16 for AES).
    ///
    /// Stream ciphers return 1.
    fn block_size(&self) -> usize;

    /// Creates a new cipher context.
    ///
    /// Replaces `OSSL_FUNC_cipher_newctx` (ID 1).
    fn new_ctx(&self) -> ProviderResult<Box<dyn CipherContext>>;
}

/// Streaming cipher context for incremental encryption / decryption.
///
/// Replaces the `OSSL_FUNC_cipher_encrypt_init/decrypt_init/update/final`
/// family (IDs 2–5) plus parameter getters/setters (IDs 10–11).
///
/// Freed automatically on drop (replaces `OSSL_FUNC_cipher_freectx`, ID 7).
pub trait CipherContext: Send + Sync {
    /// Initialises the context for encryption.
    ///
    /// Replaces `OSSL_FUNC_cipher_encrypt_init` (ID 2).
    fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()>;

    /// Initialises the context for decryption.
    ///
    /// Replaces `OSSL_FUNC_cipher_decrypt_init` (ID 3).
    fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
        params: Option<&ParamSet>,
    ) -> ProviderResult<()>;

    /// Processes a chunk of input, appending cipher-text (or plain-text)
    /// to `output`.  Returns the number of bytes written.
    ///
    /// Replaces `OSSL_FUNC_cipher_update` (ID 4).
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> ProviderResult<usize>;

    /// Finalises the cipher operation, flushing any remaining buffered
    /// data to `output`.  Returns the number of bytes written.
    ///
    /// Replaces `OSSL_FUNC_cipher_final` (ID 5).
    fn finalize(&mut self, output: &mut Vec<u8>) -> ProviderResult<usize>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_cipher_get_ctx_params` (ID 10).
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_cipher_set_ctx_params` (ID 11).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// MacProvider / MacContext — Message Authentication Code Operations
// =============================================================================

/// Provider-side MAC implementation.
///
/// Replaces the `OSSL_FUNC_mac_*` dispatch entries (IDs 1–13) from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// MacProvider::new_ctx()
///   → MacContext::init(key, ...)
///   → MacContext::update()  (one or more times)
///   → MacContext::finalize()
/// ```
pub trait MacProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"HMAC"`).
    fn name(&self) -> &'static str;

    /// Returns the MAC output size in bytes (e.g. 32 for HMAC-SHA256).
    fn size(&self) -> usize;

    /// Creates a new MAC context.
    ///
    /// Replaces `OSSL_FUNC_mac_newctx` (ID 1).
    fn new_ctx(&self) -> ProviderResult<Box<dyn MacContext>>;
}

/// Streaming MAC context for incremental authentication tag computation.
///
/// Replaces the `OSSL_FUNC_mac_init/update/final` family (IDs 4–6) plus
/// parameter getters/setters (IDs 8–9).
///
/// Freed automatically on drop (replaces `OSSL_FUNC_mac_freectx`, ID 3).
pub trait MacContext: Send + Sync {
    /// Initialises (or resets) the MAC context with the given key and
    /// optional parameters.
    ///
    /// Replaces `OSSL_FUNC_mac_init` (ID 4).
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Feeds additional data into the running MAC computation.
    ///
    /// Replaces `OSSL_FUNC_mac_update` (ID 5).
    fn update(&mut self, data: &[u8]) -> ProviderResult<()>;

    /// Finalises the MAC computation and returns the authentication tag.
    ///
    /// Replaces `OSSL_FUNC_mac_final` (ID 6).
    fn finalize(&mut self) -> ProviderResult<Vec<u8>>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_mac_get_ctx_params` (ID 8).
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_mac_set_ctx_params` (ID 9).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// KdfProvider / KdfContext — Key Derivation Function Operations
// =============================================================================

/// Provider-side KDF implementation.
///
/// Replaces the `OSSL_FUNC_kdf_*` dispatch entries (IDs 1–10) from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// KdfProvider::new_ctx()
///   → KdfContext::set_params(salt, info, password, ...)
///   → KdfContext::derive(output_buffer)
///   → KdfContext::reset()   (optional: reuse context)
/// ```
pub trait KdfProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"HKDF"`).
    fn name(&self) -> &'static str;

    /// Creates a new KDF context.
    ///
    /// Replaces `OSSL_FUNC_kdf_newctx` (ID 1).
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>>;
}

/// KDF context for key derivation operations.
///
/// Replaces the `OSSL_FUNC_kdf_derive/reset` family (IDs 4–5) plus
/// parameter getters/setters (IDs 9–10).
///
/// Freed automatically on drop (replaces `OSSL_FUNC_kdf_freectx`, ID 3).
pub trait KdfContext: Send + Sync {
    /// Derives key material, writing the result into `key`.
    ///
    /// The `params` [`ParamSet`] carries algorithm-specific inputs (e.g.
    /// salt, info, password, iteration count).  Returns the number of
    /// bytes written to `key`.
    ///
    /// Replaces `OSSL_FUNC_kdf_derive` (ID 5).
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize>;

    /// Resets the context so it can be reused for another derivation with
    /// different parameters.
    ///
    /// Replaces `OSSL_FUNC_kdf_reset` (ID 4).
    fn reset(&mut self) -> ProviderResult<()>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_kdf_get_ctx_params` (ID 10).
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_kdf_settable_ctx_params` (ID 8).
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// SignatureProvider / SignatureContext — Digital Signature Operations
// =============================================================================

/// Provider-side digital signature implementation.
///
/// Replaces the `OSSL_FUNC_signature_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// Supports both low-level sign/verify (pre-hashed data) and composite
/// digest-sign/digest-verify flows.
///
/// # Lifecycle (low-level)
///
/// ```text
/// SignatureProvider::new_ctx()
///   → SignatureContext::sign_init(key, ...)
///   → SignatureContext::sign(data)
/// ```
///
/// # Lifecycle (composite digest-sign)
///
/// ```text
/// SignatureProvider::new_ctx()
///   → SignatureContext::digest_sign_init(digest, key, ...)
///   → SignatureContext::digest_sign_update(data)  (one or more times)
///   → SignatureContext::digest_sign_final()
/// ```
pub trait SignatureProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"RSA"`, `"ECDSA"`).
    fn name(&self) -> &'static str;

    /// Creates a new signature context.
    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>>;
}

/// Digital signature context supporting both raw and digest-based flows.
///
/// Replaces the `OSSL_FUNC_signature_sign_init/sign/verify_init/verify` and
/// `OSSL_FUNC_signature_digest_sign_init/update/final` families.
pub trait SignatureContext: Send + Sync {
    /// Initialises the context for signing with the given private key
    /// material.
    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Signs the pre-hashed `data`, returning the signature bytes.
    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>>;

    /// Initialises the context for verification with the given public key
    /// material.
    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Verifies `signature` against the pre-hashed `data`.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    /// Rule R5: returns `ProviderResult<bool>`, not an integer sentinel.
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool>;

    /// Initialises a composite digest-sign operation.
    ///
    /// `digest` names the hash algorithm (e.g. `"SHA-256"`); `key` is the
    /// raw private-key material.
    fn digest_sign_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()>;

    /// Feeds data into the running digest-sign computation.
    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()>;

    /// Finalises the digest-sign computation and returns the signature.
    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>>;

    /// Initialises a composite digest-verify operation.
    ///
    /// `digest` names the hash algorithm; `key` is the raw public-key
    /// material.
    fn digest_verify_init(
        &mut self,
        digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()>;

    /// Feeds data into the running digest-verify computation.
    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()>;

    /// Finalises the digest-verify computation and checks the signature.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// KemProvider / KemContext — Key Encapsulation Mechanism Operations
// =============================================================================

/// Provider-side KEM implementation (e.g. ML-KEM, RSA-KEM).
///
/// Replaces the `OSSL_FUNC_kem_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// KemProvider::new_ctx()
///   → KemContext::encapsulate_init(public_key, ...)
///   → KemContext::encapsulate()  → (ciphertext, shared_secret)
///
/// KemProvider::new_ctx()
///   → KemContext::decapsulate_init(private_key, ...)
///   → KemContext::decapsulate(ciphertext) → shared_secret
/// ```
pub trait KemProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"ML-KEM-768"`).
    fn name(&self) -> &'static str;

    /// Creates a new KEM context.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KemContext>>;
}

/// KEM context for encapsulation / decapsulation operations.
///
/// Replaces the `OSSL_FUNC_kem_encapsulate_init/encapsulate` and
/// `OSSL_FUNC_kem_decapsulate_init/decapsulate` families.
pub trait KemContext: Send + Sync {
    /// Initialises the context for encapsulation with the given public key
    /// material.
    fn encapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Performs key encapsulation, returning `(ciphertext, shared_secret)`.
    fn encapsulate(&mut self) -> ProviderResult<(Vec<u8>, Vec<u8>)>;

    /// Initialises the context for decapsulation with the given private key
    /// material.
    fn decapsulate_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Decapsulates `ciphertext`, returning the shared secret.
    fn decapsulate(&mut self, ciphertext: &[u8]) -> ProviderResult<Vec<u8>>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// KeySelection — Key Component Selection Bitflags
// =============================================================================

bitflags::bitflags! {
    /// Bitflags for selecting key components in import/export/has/validate
    /// operations.
    ///
    /// Replaces the C `OSSL_KEYMGMT_SELECT_*` constants from
    /// `include/openssl/core_dispatch.h` (lines 646–658):
    ///
    /// | Rust flag              | C constant                              | Value |
    /// |------------------------|-----------------------------------------|-------|
    /// | `PRIVATE_KEY`          | `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`       | 0x01  |
    /// | `PUBLIC_KEY`           | `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`        | 0x02  |
    /// | `DOMAIN_PARAMETERS`    | `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` | 0x04  |
    /// | `OTHER_PARAMETERS`     | `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS`  | 0x80  |
    /// | `KEYPAIR`              | `OSSL_KEYMGMT_SELECT_KEYPAIR`           | 0x03  |
    /// | `ALL`                  | `OSSL_KEYMGMT_SELECT_ALL`               | 0x87  |
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeySelection: u32 {
        /// Select the private key component.
        const PRIVATE_KEY        = 0x01;
        /// Select the public key component.
        const PUBLIC_KEY         = 0x02;
        /// Select domain parameters (e.g. DH group, EC curve).
        const DOMAIN_PARAMETERS  = 0x04;
        /// Select other (non-domain) parameters.
        const OTHER_PARAMETERS   = 0x80;
        /// Select all components: private + public + domain + other.
        const ALL = Self::PRIVATE_KEY.bits()
                  | Self::PUBLIC_KEY.bits()
                  | Self::DOMAIN_PARAMETERS.bits()
                  | Self::OTHER_PARAMETERS.bits();
        /// Shorthand for private + public key pair.
        const KEYPAIR = Self::PRIVATE_KEY.bits()
                      | Self::PUBLIC_KEY.bits();
    }
}

// =============================================================================
// KeyData — Opaque Key Material Trait
// =============================================================================

/// Opaque key data handle for key material stored within provider
/// implementations.
///
/// This trait serves as the type-erasure boundary for key material across
/// the provider interface.  Concrete key types (RSA keys, EC keys, ML-KEM
/// keys, etc.) implement this trait within their respective provider
/// modules.
///
/// # Thread Safety
///
/// The `Send + Sync` bounds enable key data to be shared across threads
/// when wrapped in `Arc`.  The `fmt::Debug` bound enables diagnostic
/// logging (implementations must take care not to leak sensitive key
/// material in debug output).
pub trait KeyData: Send + Sync + fmt::Debug {}

// =============================================================================
// KeyMgmtProvider — Key Management Operations
// =============================================================================

/// Provider-side key management implementation.
///
/// Replaces the `OSSL_FUNC_keymgmt_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// Responsible for the key lifecycle: generation, import, export,
/// presence-checking, and validation.
///
/// # Lifecycle
///
/// ```text
/// KeyMgmtProvider::new_key()       → empty KeyData
/// KeyMgmtProvider::generate(...)   → populated KeyData
/// KeyMgmtProvider::import(...)     → populated KeyData (from external)
/// KeyMgmtProvider::export(...)     → ParamSet (serialised key components)
/// KeyMgmtProvider::has(...)        → bool
/// KeyMgmtProvider::validate(...)   → bool
/// ```
pub trait KeyMgmtProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"RSA"`, `"EC"`).
    fn name(&self) -> &'static str;

    /// Creates a new empty key data container.
    ///
    /// Replaces `OSSL_FUNC_keymgmt_new` (ID 1).
    fn new_key(&self) -> ProviderResult<Box<dyn KeyData>>;

    /// Generates a new key according to the supplied parameters.
    ///
    /// Replaces `OSSL_FUNC_keymgmt_gen_init` + `gen_set_params` +
    /// `gen` (IDs 3–6).
    fn generate(&self, params: &ParamSet) -> ProviderResult<Box<dyn KeyData>>;

    /// Imports key material from a [`ParamSet`], selecting the components
    /// indicated by `selection`.
    ///
    /// Replaces `OSSL_FUNC_keymgmt_import` (ID 8).
    fn import(&self, selection: KeySelection, data: &ParamSet) -> ProviderResult<Box<dyn KeyData>>;

    /// Exports the selected key components as a [`ParamSet`].
    ///
    /// Replaces `OSSL_FUNC_keymgmt_export` (ID 9).
    fn export(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<ParamSet>;

    /// Checks whether `key` contains the components indicated by
    /// `selection`.
    ///
    /// Replaces `OSSL_FUNC_keymgmt_has` (ID 10).
    fn has(&self, key: &dyn KeyData, selection: KeySelection) -> bool;

    /// Validates the key material for the selected components.
    ///
    /// Returns `true` if the key is valid, `false` otherwise.
    ///
    /// Replaces `OSSL_FUNC_keymgmt_validate` (ID 11).
    fn validate(&self, key: &dyn KeyData, selection: KeySelection) -> ProviderResult<bool>;
}

// =============================================================================
// KeyExchangeProvider / KeyExchangeContext — Key Exchange Operations
// =============================================================================

/// Provider-side key exchange / agreement implementation (e.g. DH, ECDH,
/// X25519).
///
/// Replaces the `OSSL_FUNC_keyexch_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// KeyExchangeProvider::new_ctx()
///   → KeyExchangeContext::init(our_key, ...)
///   → KeyExchangeContext::set_peer(peer_key)
///   → KeyExchangeContext::derive(secret_buffer) → bytes_written
/// ```
pub trait KeyExchangeProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"X25519"`, `"ECDH"`).
    fn name(&self) -> &'static str;

    /// Creates a new key exchange context.
    fn new_ctx(&self) -> ProviderResult<Box<dyn KeyExchangeContext>>;
}

/// Key exchange context for Diffie-Hellman-style agreement.
///
/// Replaces the `OSSL_FUNC_keyexch_init/set_peer/derive` family.
pub trait KeyExchangeContext: Send + Sync {
    /// Initialises the key exchange with our private key material.
    fn init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()>;

    /// Sets the peer's public key material.
    fn set_peer(&mut self, peer_key: &[u8]) -> ProviderResult<()>;

    /// Derives the shared secret, writing it into `secret`.
    ///
    /// Returns the number of bytes written.
    fn derive(&mut self, secret: &mut [u8]) -> ProviderResult<usize>;

    /// Retrieves context parameters as a typed [`ParamSet`].
    fn get_params(&self) -> ProviderResult<ParamSet>;

    /// Sets context parameters from a typed [`ParamSet`].
    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()>;
}

// =============================================================================
// RandProvider / RandContext — Random Number Generation Operations
// =============================================================================

/// Provider-side DRBG / random number generator implementation.
///
/// Replaces the `OSSL_FUNC_rand_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// # Lifecycle
///
/// ```text
/// RandProvider::new_ctx()
///   → RandContext::instantiate(strength, ...)
///   → RandContext::generate(output, ...)  (repeatedly)
///   → RandContext::reseed(...)            (periodically)
///   → RandContext::uninstantiate()
/// ```
pub trait RandProvider: Send + Sync {
    /// Returns the canonical algorithm name (e.g. `"CTR-DRBG"`).
    fn name(&self) -> &'static str;

    /// Creates a new DRBG context.
    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>>;
}

/// DRBG / RNG context for random byte generation.
///
/// Replaces the `OSSL_FUNC_rand_instantiate/generate/reseed/uninstantiate`
/// and `OSSL_FUNC_rand_enable_locking/get_ctx_params` families.
pub trait RandContext: Send + Sync {
    /// Instantiates the DRBG with the requested security strength.
    ///
    /// If `prediction_resistance` is `true`, the implementation must
    /// ensure fresh entropy on every generate call.
    fn instantiate(
        &mut self,
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()>;

    /// Generates random bytes into `output`.
    ///
    /// `strength` is the minimum security strength requested (in bits).
    fn generate(
        &mut self,
        output: &mut [u8],
        strength: u32,
        prediction_resistance: bool,
        additional: &[u8],
    ) -> ProviderResult<()>;

    /// Reseeds the DRBG with fresh entropy and optional additional input.
    fn reseed(
        &mut self,
        prediction_resistance: bool,
        entropy: &[u8],
        additional: &[u8],
    ) -> ProviderResult<()>;

    /// Uninstantiates (zeroises and tears down) the DRBG state.
    fn uninstantiate(&mut self) -> ProviderResult<()>;

    /// Enables internal locking for thread-safe generate calls.
    ///
    /// Called when the DRBG is to be shared across threads.
    fn enable_locking(&mut self) -> ProviderResult<()>;

    /// Retrieves context parameters (e.g. state, `max_request`) as a
    /// typed [`ParamSet`].
    fn get_params(&self) -> ProviderResult<ParamSet>;
}

// =============================================================================
// EncoderProvider / DecoderProvider — Key Serialisation Operations
// =============================================================================

/// Provider-side key encoder (serialiser) implementation.
///
/// Replaces the `OSSL_FUNC_encoder_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// Encoders transform in-memory [`KeyData`] into byte representations
/// such as DER, PEM, or human-readable TEXT.
pub trait EncoderProvider: Send + Sync {
    /// Returns the canonical encoder name (e.g. `"RSA-to-DER"`).
    fn name(&self) -> &'static str;

    /// Encodes the selected key components into `output`.
    ///
    /// `selection` indicates which key components to include
    /// (e.g. [`KeySelection::PUBLIC_KEY`] for `SubjectPublicKeyInfo`).
    fn encode(
        &self,
        key: &dyn KeyData,
        selection: KeySelection,
        output: &mut Vec<u8>,
    ) -> ProviderResult<()>;

    /// Returns the list of supported output formats (e.g. `["DER", "PEM", "TEXT"]`).
    fn supported_formats(&self) -> Vec<&'static str>;
}

/// Provider-side key decoder (deserialiser) implementation.
///
/// Replaces the `OSSL_FUNC_decoder_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// Decoders transform byte representations (DER, PEM, etc.) into
/// in-memory [`KeyData`].
pub trait DecoderProvider: Send + Sync {
    /// Returns the canonical decoder name (e.g. `"DER-to-RSA"`).
    fn name(&self) -> &'static str;

    /// Decodes `input` bytes into key data.
    fn decode(&self, input: &[u8]) -> ProviderResult<Box<dyn KeyData>>;

    /// Returns the list of supported input formats (e.g. `["DER", "PEM"]`).
    fn supported_formats(&self) -> Vec<&'static str>;
}

// =============================================================================
// StoreProvider / StoreContext / StoreObject — Object Store Operations
// =============================================================================

/// Provider-side object store implementation.
///
/// Replaces the `OSSL_FUNC_store_*` dispatch entries from
/// `include/openssl/core_dispatch.h`.
///
/// A store is an abstract repository of cryptographic objects (keys,
/// certificates, CRLs) identified by URI.
///
/// # Lifecycle
///
/// ```text
/// StoreProvider::open(uri)
///   → StoreContext::load()  (repeatedly until eof)
///   → StoreContext::eof()
///   → StoreContext::close()
/// ```
pub trait StoreProvider: Send + Sync {
    /// Returns the canonical store provider name (e.g. `"file"`).
    fn name(&self) -> &'static str;

    /// Opens a store at the given URI.
    fn open(&self, uri: &str) -> ProviderResult<Box<dyn StoreContext>>;
}

/// Store iteration context for loading objects from a store.
///
/// Replaces the `OSSL_FUNC_store_load/eof/close` family.
pub trait StoreContext: Send + Sync {
    /// Loads the next object from the store.
    ///
    /// Returns `Ok(Some(object))` if an object was loaded, `Ok(None)`
    /// when there are no more objects (equivalent to EOF).
    fn load(&mut self) -> ProviderResult<Option<StoreObject>>;

    /// Returns `true` if the store cursor has reached the end.
    fn eof(&self) -> bool;

    /// Closes the store and releases any associated resources.
    fn close(&mut self) -> ProviderResult<()>;
}

/// An object loaded from a cryptographic object store.
///
/// Each variant carries the raw representation of the object type.
/// The [`Params`](StoreObject::Params) variant uses [`ParamSet`] for
/// provider-defined metadata associated with the loaded object.
///
/// Replaces the C `OSSL_STORE_INFO_*` type constants and associated
/// data from `include/openssl/store.h`.
#[derive(Debug)]
pub enum StoreObject {
    /// A key object (public, private, or keypair).
    Key(Box<dyn KeyData>),
    /// A DER-encoded X.509 certificate.
    Certificate(Vec<u8>),
    /// A DER-encoded Certificate Revocation List.
    Crl(Vec<u8>),
    /// Provider-defined parameters associated with a store object.
    Params(ParamSet),
}

// =============================================================================
// Re-exports — Satisfy schema members_accessed requirements
// =============================================================================

/// Re-export of [`ParamValue`] for downstream consumers that need to
/// construct or inspect individual parameter values when interacting
/// with provider trait methods.
pub use openssl_common::param::ParamValue as ProviderParamValue;

/// Re-export of [`Nid`] for downstream consumers that need numeric
/// algorithm identifiers alongside provider trait operations.
pub use openssl_common::types::Nid as AlgorithmNid;
