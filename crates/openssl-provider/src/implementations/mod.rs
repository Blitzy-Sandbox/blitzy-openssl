//! # Algorithm Implementation Backends
//!
//! This module contains all concrete algorithm implementations for the
//! OpenSSL Rust provider system. Each submodule corresponds to an algorithm
//! category in the provider dispatch architecture.
//!
//! ## Architecture
//!
//! The implementations are organized by algorithm category, matching the
//! C source layout in `providers/implementations/`:
//!
//! | Rust Module | C Source | Provider Trait | Count |
//! |-------------|----------|---------------|-------|
//! | `ciphers` | `providers/implementations/ciphers/` (81 files) | `CipherProvider` | AES, ChaCha20, DES, Camellia, ARIA, SM4, legacy |
//! | `digests` | `providers/implementations/digests/` (17 files) | `DigestProvider` | SHA-1/2/3, SHAKE, BLAKE2, SM3, MD5, legacy |
//! | `kdfs` | `providers/implementations/kdfs/` (16 files) | `KdfProvider` | HKDF, PBKDF2, Argon2, scrypt, KBKDF, etc. |
//! | `macs` | `providers/implementations/macs/` (9 files) | `MacProvider` | HMAC, CMAC, GMAC, KMAC, Poly1305, SipHash |
//! | `signatures` | `providers/implementations/signature/` (9 files) | `SignatureProvider` | RSA, DSA, ECDSA, EdDSA, ML-DSA, SLH-DSA, LMS |
//! | `kem` | `providers/implementations/kem/` (7 files) | `KemProvider` | ML-KEM, HPKE DHKEM, hybrid MLX, RSA |
//! | `keymgmt` | `providers/implementations/keymgmt/` (13 files) | `KeyMgmtProvider` | RSA, EC, DH, DSA, PQ, legacy |
//! | `exchange` | `providers/implementations/exchange/` (4 files) | `KeyExchangeProvider` | DH, ECDH, ECX, KDF-backed |
//! | `rands` | `providers/implementations/rands/` (8 files) | `RandProvider` | CTR/Hash/HMAC DRBG, seed source, jitter |
//! | `encode_decode` | `providers/implementations/encode_decode/` (16 files) | `EncoderProvider`/`DecoderProvider` | DER/PEM codecs |
//! | `store` | `providers/implementations/storemgmt/` (3 files) | `StoreProvider` | File store, Windows cert store |
//!
//! ## Key Design Principles
//!
//! - **Trait-based dispatch:** Each implementation struct implements the corresponding
//!   trait from `crate::traits` (e.g., `CipherProvider`, `DigestProvider`)
//! - **Zero unsafe:** ALL code in this module tree is 100% safe Rust (Rule R8)
//! - **Delegation to openssl-crypto:** Actual cryptographic operations delegate to
//!   `openssl-crypto` — implementations here are thin adapters
//! - **Feature-gated:** Algorithm availability controlled by `#[cfg(feature = "...")]`
//!   replacing C `#ifndef OPENSSL_NO_*` guards
//! - **Typed parameters:** C `OSSL_PARAM` bags replaced with typed Rust config structs
//! - **RAII:** C `*_newctx()` / `*_freectx()` pairs replaced with Rust struct + `Drop`
//!
//! ## Wiring Path (Rule R10)
//!
//! Every submodule is reachable from the entry point:
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation()
//!         → implementations::all_*_descriptors()
//!           → submodule::descriptors()
//! ```
//!
//! ## C Source Reference
//!
//! This module replaces the organizational role of `prov/implementations.h` in the
//! C codebase, which declared all `ossl_*_functions` dispatch table symbols used by
//! `providers/defltprov.c`, `providers/legacyprov.c`, `providers/baseprov.c`, and
//! `providers/fips/fipsprov.c`. The C `ALG()` / `ALGC()` macros from `defltprov.c`
//! are replaced by the `algorithm()` helper function.

use crate::traits::AlgorithmDescriptor;
use openssl_common::ProviderResult;

// =============================================================================
// Submodule Declarations — Feature-Gated Algorithm Categories
// =============================================================================
//
// Core algorithm categories — each gated by its own feature flag matching
// the Cargo.toml feature definitions in the parent crate.  When a feature
// is disabled, the entire submodule is excluded from compilation, reducing
// binary size for embedded / constrained deployments.
//
// Feature gate names: "ciphers", "digests", "kdfs", "macs", "signatures",
// "kem", "keymgmt", "exchange", "rands", "encode-decode", "store".

/// Symmetric cipher implementations (AES, ChaCha20, DES, Camellia, ARIA, SM4, legacy).
///
/// Source: `providers/implementations/ciphers/` (81 C files).
///
/// Each cipher struct implements `CipherProvider` from `crate::traits` and delegates
/// core operations to `openssl-crypto`'s symmetric module. Context creation/destruction
/// is handled by Rust's ownership model — `CipherContext` is created via `new()` and
/// cleaned up (including key material zeroing) via `Drop`.
#[cfg(feature = "ciphers")]
pub mod ciphers;

/// Message digest implementations (SHA-1/2/3, SHAKE, BLAKE2, SM3, MD5, legacy).
///
/// Source: `providers/implementations/digests/` (17 C files).
///
/// Each digest struct implements `DigestProvider` from `crate::traits`.
/// Replaces C `ossl_sha256_functions`, `ossl_sha3_256_functions`, etc.
#[cfg(feature = "digests")]
pub mod digests;

/// Key derivation function implementations (HKDF, PBKDF2, Argon2, scrypt, KBKDF, etc.).
///
/// Source: `providers/implementations/kdfs/` (16 C files).
///
/// Each KDF struct implements `KdfProvider` from `crate::traits`.
/// Replaces C `ossl_kdf_hkdf_functions`, `ossl_kdf_pbkdf2_functions`, etc.
#[cfg(feature = "kdfs")]
pub mod kdfs;

/// Message authentication code implementations (HMAC, CMAC, GMAC, KMAC, Poly1305, SipHash).
///
/// Source: `providers/implementations/macs/` (9 C files).
///
/// Each MAC struct implements `MacProvider` from `crate::traits`.
/// Replaces C `ossl_hmac_functions`, `ossl_cmac_functions`, etc.
#[cfg(feature = "macs")]
pub mod macs;

/// Digital signature implementations (RSA, DSA, ECDSA, EdDSA, ML-DSA, SLH-DSA, LMS).
///
/// Source: `providers/implementations/signature/` (9 C files).
///
/// Each signature struct implements `SignatureProvider` from `crate::traits`.
/// Replaces C `ossl_rsa_signature_functions`, `ossl_ecdsa_signature_functions`, etc.
#[cfg(feature = "signatures")]
pub mod signatures;

/// Key encapsulation mechanism implementations (ML-KEM, HPKE DHKEM, hybrid MLX, RSA).
///
/// Source: `providers/implementations/kem/` (7 C files).
///
/// Each KEM struct implements `KemProvider` from `crate::traits`.
/// Replaces C `ossl_rsa_asym_kem_functions`, `ossl_ecx_kem_functions`, etc.
#[cfg(feature = "kem")]
pub mod kem;

/// Key management implementations (RSA, EC, DH, DSA, PQ/hybrid, legacy).
///
/// Source: `providers/implementations/keymgmt/` (13 C files).
///
/// Each key management struct implements `KeyMgmtProvider` from `crate::traits`,
/// providing key generation, import, export, validation, and parameter handling.
/// Replaces C `ossl_rsa_keymgmt_functions`, `ossl_ec_keymgmt_functions`, etc.
#[cfg(feature = "keymgmt")]
pub mod keymgmt;

/// Key exchange implementations (DH, ECDH, ECX, KDF-backed).
///
/// Source: `providers/implementations/exchange/` (4 C files).
///
/// Each key exchange struct implements `KeyExchangeProvider` from `crate::traits`.
/// Replaces C `ossl_dh_keyexch_functions`, `ossl_ecdh_keyexch_functions`, etc.
#[cfg(feature = "exchange")]
pub mod exchange;

/// Random number generator implementations (CTR/Hash/HMAC DRBG, seed source, jitter).
///
/// Source: `providers/implementations/rands/` (15 C files).
///
/// Each DRBG struct implements `RandProvider` from `crate::traits`.
/// Replaces C `ossl_drbg_ctr_functions`, `ossl_drbg_hash_functions`, etc.
#[cfg(feature = "rands")]
pub mod rands;

/// Key encoder/decoder implementations (DER/PEM codecs, PKCS#8, SPKI, legacy formats).
///
/// Source: `providers/implementations/encode_decode/` (16 C files).
///
/// Encoder structs implement `EncoderProvider` and decoder structs implement
/// `DecoderProvider` from `crate::traits`.
/// Replaces C `ossl_rsa_to_der_encoder_functions`, etc.
#[cfg(feature = "encode-decode")]
pub mod encode_decode;

/// Key/certificate store implementations (file store, Windows cert store).
///
/// Source: `providers/implementations/storemgmt/` (3 C files).
///
/// Each store struct implements `StoreProvider` from `crate::traits`.
/// Replaces C `ossl_file_store_functions`, `ossl_winstore_functions`.
#[cfg(feature = "store")]
pub mod store;

// =============================================================================
// Shared Utility Types
// =============================================================================

/// Common result type alias for all implementation functions throughout the
/// algorithm backend modules.
///
/// Wraps [`ProviderResult<T>`](openssl_common::ProviderResult) to provide a
/// short, ergonomic name for use in the many function signatures across the
/// 11 implementation submodules. This avoids repeating the full
/// `ProviderResult<T>` path in every signature while maintaining the
/// `ProviderError` variant set (`Common`, `NotFound`, `Dispatch`, `Init`,
/// `AlgorithmUnavailable`).
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::ImplResult;
///
/// fn init_context(algorithm: &str) -> ImplResult<()> {
///     // ... implementation ...
///     Ok(())
/// }
/// ```
pub type ImplResult<T> = ProviderResult<T>;

/// Helper function to create an [`AlgorithmDescriptor`] with the standard
/// format used across all implementation submodules.
///
/// Replaces the C `ALG()` and `ALGC()` macros from `providers/defltprov.c`:
///
/// ```c
/// #define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }
/// #define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)
/// ```
///
/// In the C codebase, the algorithm names are comma-separated in a single string.
/// In Rust, they are provided as a slice of individual name strings.
///
/// # Parameters
///
/// - `names`: Algorithm name aliases (primary + aliases). The first name is
///   canonical; subsequent names are aliases for backward-compatible lookup.
/// - `property`: Property query string (e.g., `"provider=default"`).
/// - `description`: Human-readable description for documentation/diagnostics.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::algorithm;
///
/// let desc = algorithm(
///     &["SHA2-256", "SHA-256", "SHA256"],
///     "provider=default",
///     "SHA-2 256-bit message digest",
/// );
/// assert_eq!(desc.names[0], "SHA2-256");
/// assert_eq!(desc.property, "provider=default");
/// ```
pub fn algorithm(
    names: &[&'static str],
    property: &'static str,
    description: &'static str,
) -> AlgorithmDescriptor {
    AlgorithmDescriptor {
        names: names.to_vec(),
        property,
        description,
    }
}

// =============================================================================
// Registration Aggregation Functions
// =============================================================================
//
// These functions collect ALL algorithm descriptors from the enabled
// implementation modules.  They are called by:
//
//   - `DefaultProvider::query_operation()` (crate::default)
//   - `LegacyProvider::query_operation()` (crate::legacy)
//   - `BaseProvider::query_operation()` (crate::base)
//   - `FipsProvider::query_operation()` (openssl-fips crate)
//
// Each function is feature-gated:
//   - If the feature is enabled, delegates to the submodule's `descriptors()`
//   - If the feature is disabled, returns an empty `Vec`
//
// This replaces the role of `prov/implementations.h` which declared all
// `ossl_*_functions` dispatch table symbols that `defltprov.c`, `legacyprov.c`,
// and `baseprov.c` referenced in their static `OSSL_ALGORITHM` arrays.

/// Returns all cipher algorithm descriptors from the `ciphers` submodule.
///
/// When the `"ciphers"` feature is enabled, delegates to
/// [`ciphers::descriptors()`]. When disabled, returns an empty vector
/// indicating no cipher algorithms are available.
///
/// Replaces the C `deflt_ciphers[]` static array from `providers/defltprov.c`
/// (lines 171–367) which contained ~80 `OSSL_ALGORITHM` entries for all
/// symmetric cipher variants.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// cipher implementations (AES-GCM, AES-CBC, ChaCha20-Poly1305, 3DES, etc.).
#[must_use]
pub fn all_cipher_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "ciphers")]
    {
        ciphers::descriptors()
    }
    #[cfg(not(feature = "ciphers"))]
    {
        Vec::new()
    }
}

/// Returns all digest algorithm descriptors from the `digests` submodule.
///
/// When the `"digests"` feature is enabled, delegates to
/// [`digests::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_digests[]` static array from `providers/defltprov.c`
/// (lines 101–169) which contained entries for SHA-1, SHA-2 (224/256/384/512),
/// SHA-3, SHAKE, BLAKE2, SM3, MD5, RIPEMD-160, and the null digest.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// digest implementations.
#[must_use]
pub fn all_digest_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "digests")]
    {
        digests::descriptors()
    }
    #[cfg(not(feature = "digests"))]
    {
        Vec::new()
    }
}

/// Returns all KDF algorithm descriptors from the `kdfs` submodule.
///
/// When the `"kdfs"` feature is enabled, delegates to
/// [`kdfs::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_kdfs[]` static array from `providers/defltprov.c`
/// which contained entries for HKDF, PBKDF2, Argon2, scrypt, KBKDF,
/// TLS1-PRF, SSKDF, X963KDF, X942KDF, and PKCS12KDF.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// KDF implementations.
#[must_use]
pub fn all_kdf_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "kdfs")]
    {
        kdfs::descriptors()
    }
    #[cfg(not(feature = "kdfs"))]
    {
        Vec::new()
    }
}

/// Returns all MAC algorithm descriptors from the `macs` submodule.
///
/// When the `"macs"` feature is enabled, delegates to
/// [`macs::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_macs[]` static array from `providers/defltprov.c`
/// which contained entries for HMAC, CMAC, GMAC, KMAC-128, KMAC-256,
/// Poly1305, and `SipHash`.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// MAC implementations.
#[must_use]
pub fn all_mac_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "macs")]
    {
        macs::descriptors()
    }
    #[cfg(not(feature = "macs"))]
    {
        Vec::new()
    }
}

/// Returns all signature algorithm descriptors from the `signatures` submodule.
///
/// When the `"signatures"` feature is enabled, delegates to
/// [`signatures::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_signature[]` static array from `providers/defltprov.c`
/// which contained entries for RSA, DSA, ECDSA, `EdDSA` (Ed25519/Ed448),
/// ML-DSA, SLH-DSA, and LMS signature algorithms.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// signature implementations.
#[must_use]
pub fn all_signature_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "signatures")]
    {
        signatures::descriptors()
    }
    #[cfg(not(feature = "signatures"))]
    {
        Vec::new()
    }
}

/// Returns all KEM algorithm descriptors from the `kem` submodule.
///
/// When the `"kem"` feature is enabled, delegates to
/// [`kem::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_asym_kem[]` static array from `providers/defltprov.c`
/// which contained entries for RSA-KEM, EC-KEM (DHKEM), ML-KEM
/// (512/768/1024), and hybrid ML-KEM variants.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// KEM implementations.
#[must_use]
pub fn all_kem_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "kem")]
    {
        kem::descriptors()
    }
    #[cfg(not(feature = "kem"))]
    {
        Vec::new()
    }
}

/// Returns all key management algorithm descriptors from the `keymgmt` submodule.
///
/// When the `"keymgmt"` feature is enabled, delegates to
/// [`keymgmt::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_keymgmt[]` static array from `providers/defltprov.c`
/// which contained entries for RSA, RSA-PSS, DH, DHX, DSA, EC, X25519,
/// X448, Ed25519, Ed448, ML-KEM, ML-DSA, SLH-DSA, TLS-GROUP, and
/// CMAC/HMAC key management.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// key management implementations.
#[must_use]
pub fn all_keymgmt_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "keymgmt")]
    {
        keymgmt::descriptors()
    }
    #[cfg(not(feature = "keymgmt"))]
    {
        Vec::new()
    }
}

/// Returns all key exchange algorithm descriptors from the `exchange` submodule.
///
/// When the `"exchange"` feature is enabled, delegates to
/// [`exchange::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_keyexch[]` static array from `providers/defltprov.c`
/// which contained entries for DH, ECDH, X25519, X448, and KDF-backed
/// key exchange mechanisms.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// key exchange implementations.
#[must_use]
pub fn all_exchange_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "exchange")]
    {
        exchange::descriptors()
    }
    #[cfg(not(feature = "exchange"))]
    {
        Vec::new()
    }
}

/// Returns all random number generator descriptors from the `rands` submodule.
///
/// When the `"rands"` feature is enabled, delegates to
/// [`rands::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_rands[]` static array from `providers/defltprov.c`
/// which contained entries for CTR-DRBG, Hash-DRBG, HMAC-DRBG, seed sources,
/// and the test entropy source.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// random number generator implementations.
#[must_use]
pub fn all_rand_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "rands")]
    {
        rands::descriptors()
    }
    #[cfg(not(feature = "rands"))]
    {
        Vec::new()
    }
}

/// Returns all key encoder descriptors from the `encode_decode` submodule.
///
/// When the `"encode-decode"` feature is enabled, delegates to
/// [`encode_decode::encoder_descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the encoder portion of the C `deflt_encoder[]` static array
/// from `providers/baseprov.c` and `providers/defltprov.c` which contained
/// entries for DER/PEM/text encoders for all key types (RSA, EC, DH, DSA,
/// ML-KEM, ML-DSA, SLH-DSA, etc.).
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// key encoder implementations.
#[must_use]
pub fn all_encoder_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "encode-decode")]
    {
        encode_decode::encoder_descriptors()
    }
    #[cfg(not(feature = "encode-decode"))]
    {
        Vec::new()
    }
}

/// Returns all key decoder descriptors from the `encode_decode` submodule.
///
/// When the `"encode-decode"` feature is enabled, delegates to
/// [`encode_decode::decoder_descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the decoder portion of the C `deflt_decoder[]` static array
/// from `providers/baseprov.c` and `providers/defltprov.c` which contained
/// entries for DER/PEM/MSBLOB/PVK decoders for all key types.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// key decoder implementations.
#[must_use]
pub fn all_decoder_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "encode-decode")]
    {
        encode_decode::decoder_descriptors()
    }
    #[cfg(not(feature = "encode-decode"))]
    {
        Vec::new()
    }
}

/// Returns all store descriptors from the `store` submodule.
///
/// When the `"store"` feature is enabled, delegates to
/// [`store::descriptors()`]. When disabled, returns an empty vector.
///
/// Replaces the C `deflt_store[]` static array from `providers/baseprov.c`
/// which contained entries for the `file:` URI scheme store and (on Windows)
/// the `org.openssl.winstore:` scheme.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// store implementations.
#[must_use]
pub fn all_store_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "store")]
    {
        store::descriptors()
    }
    #[cfg(not(feature = "store"))]
    {
        Vec::new()
    }
}

// Re-export ProviderError for use by submodules constructing errors via ImplResult.
#[doc(hidden)]
pub use openssl_common::error::ProviderError as _ProviderError;
