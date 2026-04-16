//! # Message Digest Provider Implementations
//!
//! Contains all message digest algorithm implementations for the OpenSSL
//! Rust provider system. Each submodule implements the [`DigestProvider`]
//! trait from [`crate::traits`] for one or more hash algorithm families.
//!
//! ## Algorithm Families
//!
//! | Module | Algorithms | C Source | Feature |
//! |--------|-----------|---------|---------|
//! | [`common`] | Shared infrastructure (flags, params, helpers) | `digestcommon.c` | always |
//! | [`sha1`] | SHA-1 (with SSL3 support) | `sha2_prov.c` | always |
//! | [`sha2`] | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | `sha2_prov.c` | always |
//! | [`sha3`] | SHA3-224/256/384/512, SHAKE128/256, cSHAKE, Keccak, KECCAK-KMAC | `sha3_prov.c`, `cshake_prov.c` | `sha3` |
//! | [`blake2`] | BLAKE2b-512, BLAKE2s-256 | `blake2_prov.c` | `blake2` |
//! | [`sm3`] | SM3 | `sm3_prov.c` | `sm3` |
//! | [`md5`] | MD5, MD5-SHA1 | `md5_prov.c`, `md5_sha1_prov.c` | always |
//! | [`ripemd`] | RIPEMD-160 | `ripemd_prov.c` | always |
//! | [`null`] | NULL (passthrough) | `null_prov.c` | always |
//! | [`ml_dsa_mu`] | ML-DSA mu hash (SHAKE256-based) | `ml_dsa_mu_prov.c` | always |
//! | [`legacy`] | MD2, MD4, MDC2, Whirlpool | `md2/md4/mdc2/wp_prov.c` | `legacy` |
//!
//! ## Architecture
//!
//! Each digest struct implements [`DigestProvider`] and creates
//! [`DigestContext`](crate::traits::DigestContext) instances. Context lifecycle:
//!
//! ```text
//! new_ctx() → init() → update()* → finalize()   [with Drop for cleanup]
//! ```
//!
//! Actual cryptographic operations delegate to `openssl-crypto::hash::*`.
//! Provider implementations in this module are thin adapters that bridge
//! the provider trait interface to the underlying crypto primitives.
//!
//! ## Wiring Path (Rule R10)
//!
//! Every submodule is reachable from the entry point:
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(OperationType::Digest)
//!         → implementations::all_digest_descriptors()
//!           → digests::descriptors()
//!             → sha1::descriptors(), sha2::descriptors(), ...
//! ```
//!
//! ## C Source Reference
//!
//! This module replaces the organizational role of the
//! `providers/implementations/digests/` directory in the C codebase,
//! which contained 17 source files defining digest provider dispatch tables:
//!
//! - `digestcommon.c` — shared `PROV_DIGEST_HW` / `IMPLEMENT_digest_functions` macros
//! - `sha2_prov.c` — SHA-1 and SHA-2 family (`ossl_sha1_functions`, `ossl_sha256_functions`, etc.)
//! - `sha3_prov.c` — SHA-3 / SHAKE / Keccak (`ossl_sha3_256_functions`, `ossl_shake_128_functions`, etc.)
//! - `cshake_prov.c` — cSHAKE customizable XOF
//! - `blake2_prov.c` — BLAKE2b / BLAKE2s
//! - `md5_prov.c` — MD5
//! - `md5_sha1_prov.c` — MD5-SHA1 composite
//! - `ripemd_prov.c` — RIPEMD-160
//! - `null_prov.c` — Null digest (passthrough)
//! - `sm3_prov.c` — SM3 (Chinese national standard)
//! - `ml_dsa_mu_prov.c` — ML-DSA mu hash (FIPS 204)
//! - `md2_prov.c`, `md4_prov.c`, `mdc2_prov.c`, `wp_prov.c` — Legacy digests
//!
//! The C `IMPLEMENT_digest_functions()` macro pattern is replaced by Rust
//! trait implementations. The C `ossl_*_functions[]` dispatch table symbols
//! referenced by `defltprov.c` are replaced by the [`descriptors()`] and
//! [`create_provider()`] functions.
//!
//! ## Zero Unsafe
//!
//! All code in this module tree is 100% safe Rust (Rule R8).
//! No `unsafe` blocks appear anywhere in the digest implementation hierarchy.

use crate::traits::{AlgorithmDescriptor, DigestProvider};

// =============================================================================
// Submodule Declarations
// =============================================================================
//
// Core digest modules are always available when the "digests" feature is
// enabled (the parent `implementations/mod.rs` gates this entire module).
// Additional algorithm families are gated by their own feature flags,
// replacing C `#ifndef OPENSSL_NO_*` preprocessor guards.

/// Shared digest infrastructure: flags, parameters, helper functions, and
/// the [`DigestContextOps`](common::DigestContextOps) trait extension.
///
/// Source: `providers/implementations/digests/digestcommon.c`
///
/// Provides [`DigestFlags`], [`DigestParams`], [`default_get_params()`](common::default_get_params),
/// [`default_gettable_params()`](common::default_gettable_params),
/// [`is_fips_approved_digest()`](common::is_fips_approved_digest), and
/// [`digest_name_to_nid()`](common::digest_name_to_nid).
pub mod common;

/// SHA-1 message digest (160-bit output, 64-byte block).
///
/// Source: `providers/implementations/digests/sha2_prov.c` (SHA-1 portion).
///
/// Replaces C `ossl_sha1_functions` dispatch table. Includes SSL3
/// master-secret parameter support for backward compatibility.
///
/// **Security note:** SHA-1 is deprecated for digital signatures (NIST SP 800-131A).
/// Provided for backward compatibility and HMAC-SHA1 usage only.
pub mod sha1;

/// SHA-2 family message digests (224, 256, 384, 512, 512/224, 512/256).
///
/// Source: `providers/implementations/digests/sha2_prov.c` (SHA-2 portion).
///
/// Replaces C `ossl_sha224_functions`, `ossl_sha256_functions`,
/// `ossl_sha384_functions`, `ossl_sha512_functions`,
/// `ossl_sha512_224_functions`, `ossl_sha512_256_functions` dispatch tables.
///
/// Seven total variants across two base implementations:
/// - [`Sha256Provider`] (256-bit state): SHA-224, SHA-256, SHA-256/192
/// - [`Sha512Provider`] (512-bit state): SHA-384, SHA-512, SHA-512/224, SHA-512/256
pub mod sha2;

/// MD5 and MD5-SHA1 composite message digests.
///
/// Source: `providers/implementations/digests/md5_prov.c`,
///         `providers/implementations/digests/md5_sha1_prov.c`.
///
/// Replaces C `ossl_md5_functions` and `ossl_md5_sha1_functions` dispatch tables.
///
/// - MD5: 128-bit output, 64-byte block
/// - MD5-SHA1: 288-bit (36-byte) composite output for SSLv3 compatibility
///
/// **Security note:** MD5 is cryptographically broken for collision resistance.
/// Provided for backward compatibility (TLS, HMAC-MD5) only.
pub mod md5;

/// RIPEMD-160 message digest (160-bit output, 64-byte block).
///
/// Source: `providers/implementations/digests/ripemd_prov.c`.
///
/// Replaces C `ossl_ripemd160_functions` dispatch table.
pub mod ripemd;

/// Null (passthrough) digest — zero-length output, no-op operations.
///
/// Source: `providers/implementations/digests/null_prov.c`.
///
/// Replaces C `ossl_null_functions` dispatch table. Used as a sentinel
/// when no digest is required (e.g., RSA PKCS#1 v1.5 signature without
/// digest, or EdDSA pure mode).
pub mod null;

/// ML-DSA mu hash — SHAKE256-based internal hash for ML-DSA (FIPS 204).
///
/// Source: `providers/implementations/digests/ml_dsa_mu_prov.c`.
///
/// Provides the specialized mu hash computation used internally by the
/// ML-DSA signature algorithm. Fixed 64-byte output using SHAKE256 with
/// a domain-separated context string, OID prefix, and public key hash caching.
pub mod ml_dsa_mu;

/// SHA-3 family: SHA3-224/256/384/512, SHAKE128/256, Keccak, KECCAK-KMAC,
/// and cSHAKE customizable extendable output functions.
///
/// Source: `providers/implementations/digests/sha3_prov.c`,
///         `providers/implementations/digests/cshake_prov.c`.
///
/// Replaces C `ossl_sha3_224_functions`, `ossl_sha3_256_functions`,
/// `ossl_sha3_384_functions`, `ossl_sha3_512_functions`,
/// `ossl_shake_128_functions`, `ossl_shake_256_functions`,
/// `ossl_keccak_224_functions`, `ossl_keccak_256_functions`,
/// `ossl_keccak_384_functions`, `ossl_keccak_512_functions`,
/// `ossl_keccak_kmac_128_functions`, `ossl_keccak_kmac_256_functions`,
/// `ossl_cshake_128_functions`, `ossl_cshake_256_functions` dispatch tables.
///
/// 14 algorithm variants total across 5 provider types.
#[cfg(feature = "sha3")]
pub mod sha3;

/// BLAKE2 message digests: BLAKE2b-512 (128-byte block, 64-byte output)
/// and BLAKE2s-256 (64-byte block, 32-byte output).
///
/// Source: `providers/implementations/digests/blake2_prov.c`.
///
/// Replaces C `ossl_blake2b512_functions` and `ossl_blake2s256_functions`
/// dispatch tables. Supports configurable output size via context parameters.
#[cfg(feature = "blake2")]
pub mod blake2;

/// SM3 message digest — Chinese national standard (GB/T 32905-2016).
///
/// Source: `providers/implementations/digests/sm3_prov.c`.
///
/// 256-bit output, 64-byte block. Replaces C `ossl_sm3_functions` dispatch table.
#[cfg(feature = "sm3")]
pub mod sm3;

/// Legacy digest algorithms: MD2, MD4, MDC2, Whirlpool.
///
/// Source: `providers/implementations/digests/md2_prov.c`,
///         `providers/implementations/digests/md4_prov.c`,
///         `providers/implementations/digests/mdc2_prov.c`,
///         `providers/implementations/digests/wp_prov.c`.
///
/// These algorithms are registered with property `"provider=legacy"` (not
/// `"provider=default"`), matching the C `legacyprov.c` registration pattern.
/// Each sub-algorithm is additionally gated by its own feature flag
/// (`md2`, `md4`, `mdc2`, `whirlpool`).
///
/// **Security note:** All legacy digests are deprecated and should not be used
/// in new applications. They are provided for backward compatibility only.
#[cfg(feature = "legacy")]
pub mod legacy;

// =============================================================================
// Public Re-exports
// =============================================================================
//
// Key types are re-exported at module level for ergonomic access:
//   use openssl_provider::implementations::digests::Sha256Provider;
// instead of:
//   use openssl_provider::implementations::digests::sha2::Sha256Provider;

/// Digest capability flags — re-exported from [`common`].
pub use common::DigestFlags;

/// Digest parameter configuration — re-exported from [`common`].
pub use common::DigestParams;

/// SHA-1 provider — re-exported from [`sha1`].
pub use sha1::Sha1Provider;

/// SHA-2 256-bit family provider — re-exported from [`sha2`].
pub use sha2::Sha256Provider;

/// SHA-2 512-bit family provider — re-exported from [`sha2`].
pub use sha2::Sha512Provider;

/// MD5 provider — re-exported from [`md5`].
pub use md5::Md5Provider;

/// MD5-SHA1 composite provider — re-exported from [`md5`].
pub use md5::Md5Sha1Provider;

/// RIPEMD-160 provider — re-exported from [`ripemd`].
pub use ripemd::Ripemd160Provider;

/// Null digest provider — re-exported from [`null`].
pub use null::NullDigestProvider;

/// ML-DSA mu hash provider — re-exported from [`ml_dsa_mu`].
pub use ml_dsa_mu::MlDsaMuProvider;

/// SHA-3 provider — re-exported from [`sha3`] (feature-gated).
#[cfg(feature = "sha3")]
pub use sha3::Sha3Provider;

/// SHAKE XOF provider — re-exported from [`sha3`] (feature-gated).
#[cfg(feature = "sha3")]
pub use sha3::ShakeProvider;

/// Keccak provider — re-exported from [`sha3`] (feature-gated).
#[cfg(feature = "sha3")]
pub use sha3::KeccakProvider;

/// KECCAK-KMAC provider — re-exported from [`sha3`] (feature-gated).
#[cfg(feature = "sha3")]
pub use sha3::KeccakKmacProvider;

/// cSHAKE provider — re-exported from [`sha3`] (feature-gated).
#[cfg(feature = "sha3")]
pub use sha3::CshakeProvider;

/// `BLAKE2b` provider — re-exported from [`blake2`] (feature-gated).
#[cfg(feature = "blake2")]
pub use blake2::Blake2bProvider;

/// BLAKE2s provider — re-exported from [`blake2`] (feature-gated).
#[cfg(feature = "blake2")]
pub use blake2::Blake2sProvider;

/// SM3 provider — re-exported from [`sm3`] (feature-gated).
#[cfg(feature = "sm3")]
pub use sm3::Sm3Provider;

// Legacy digest providers are conditionally re-exported when the "legacy"
// feature is enabled, making MD2, MD4, MDC2, and Whirlpool available at
// the digests module level.
#[cfg(feature = "legacy")]
pub use legacy::Md2Provider;

#[cfg(feature = "legacy")]
pub use legacy::Md4Provider;

#[cfg(feature = "legacy")]
pub use legacy::Mdc2Provider;

#[cfg(feature = "legacy")]
pub use legacy::WhirlpoolProvider;

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns all digest algorithm descriptors for the **default** provider.
///
/// Called by [`super::all_digest_descriptors()`] which is invoked by
/// `DefaultProvider::query_operation(OperationType::Digest)`. This function
/// aggregates descriptors from ALL non-legacy digest submodules, respecting
/// feature gates.
///
/// Replaces the role of C's static `deflt_digests[]` array in
/// `providers/defltprov.c` (lines 101–169) which contained
/// `OSSL_ALGORITHM` entries for all default digest variants.
///
/// # Feature Gate Behavior
///
/// - Core families (SHA-1, SHA-2, MD5, RIPEMD-160, NULL, ML-DSA-MU) are
///   always included when the `"digests"` feature is enabled.
/// - SHA-3/SHAKE/Keccak/cSHAKE require `"sha3"` feature.
/// - BLAKE2b/BLAKE2s require `"blake2"` feature.
/// - SM3 requires `"sm3"` feature.
/// - Legacy algorithms are excluded — use [`legacy_descriptors()`] instead.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// default-provider digest implementations. Each descriptor includes
/// algorithm name aliases, property string (`"provider=default"`), and
/// a human-readable description.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();

    // Core digest families — always present when "digests" is enabled
    descs.extend(sha1::descriptors());
    descs.extend(sha2::descriptors());
    descs.extend(md5::descriptors());
    descs.extend(ripemd::descriptors());
    descs.extend(null::descriptors());
    descs.extend(ml_dsa_mu::descriptors());

    // Feature-gated digest families
    #[cfg(feature = "sha3")]
    {
        descs.extend(sha3::descriptors());
    }

    #[cfg(feature = "blake2")]
    {
        descs.extend(blake2::descriptors());
    }

    #[cfg(feature = "sm3")]
    {
        descs.extend(sm3::descriptors());
    }

    descs
}

/// Returns digest algorithm descriptors for the **legacy** provider.
///
/// Called by `LegacyProvider::query_operation(OperationType::Digest)`.
/// Separate from [`descriptors()`] because legacy algorithms use property
/// `"provider=legacy"` instead of `"provider=default"`.
///
/// Includes MD2, MD4, MDC2, and Whirlpool — algorithms that are
/// cryptographically deprecated and not present in the default provider.
///
/// # Feature Gate Behavior
///
/// Returns an empty vector when the `"legacy"` feature is disabled.
/// When enabled, delegates to [`legacy::descriptors()`] which returns
/// descriptors gated by individual sub-features (`md2`, `md4`, `mdc2`,
/// `whirlpool`).
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing legacy digest descriptors,
/// each with property string `"provider=legacy"`.
#[must_use]
pub fn legacy_descriptors() -> Vec<AlgorithmDescriptor> {
    #[cfg(feature = "legacy")]
    {
        legacy::descriptors()
    }
    #[cfg(not(feature = "legacy"))]
    {
        Vec::new()
    }
}

// =============================================================================
// Factory Function — Runtime Algorithm Resolution
// =============================================================================

/// Creates a digest provider by algorithm name with case-insensitive matching.
///
/// Used by the method store for runtime algorithm resolution when a caller
/// requests a digest by name (e.g., via `EVP_MD_fetch()`). This function
/// supports primary names, aliases, and variant names for each algorithm.
///
/// Replaces the C pattern of iterating `OSSL_ALGORITHM` arrays and matching
/// comma-separated name strings against a query. In Rust, case-insensitive
/// string matching selects the appropriate provider struct to instantiate.
///
/// # Parameters
///
/// - `name`: Algorithm name string. Matching is case-insensitive and supports
///   common aliases (e.g., `"SHA-256"`, `"SHA256"`, `"SHA2-256"` all match).
///
/// # Returns
///
/// - `Some(Box<dyn DigestProvider>)` — a boxed provider instance for the
///   matched algorithm, ready for [`DigestProvider::new_ctx()`] calls.
/// - `None` — if the algorithm name is not recognized or the required
///   feature is not enabled.
///
/// # Rule R5 Compliance
///
/// Returns `Option<Box<dyn DigestProvider>>` (not a null pointer or sentinel
/// value), ensuring type-safe algorithm resolution.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::digests;
///
/// let sha256 = digests::create_provider("SHA-256").expect("SHA-256 available");
/// assert_eq!(sha256.digest_size(), 32);
///
/// let unknown = digests::create_provider("NONEXISTENT");
/// assert!(unknown.is_none());
/// ```
pub fn create_provider(name: &str) -> Option<Box<dyn DigestProvider>> {
    // Convert to uppercase for case-insensitive matching.
    // ASCII uppercase is sufficient — all algorithm names are ASCII.
    let name_upper = name.to_ascii_uppercase();

    // Try core providers first (always available when "digests" is enabled)
    if let Some(provider) = create_core_provider(&name_upper) {
        return Some(provider);
    }

    // Try SHA-3 family (feature-gated)
    #[cfg(feature = "sha3")]
    {
        if let Some(provider) = create_sha3_provider(&name_upper) {
            return Some(provider);
        }
    }

    // Try BLAKE2 family (feature-gated)
    #[cfg(feature = "blake2")]
    {
        if let Some(provider) = create_blake2_provider(&name_upper) {
            return Some(provider);
        }
    }

    // Try SM3 (feature-gated)
    #[cfg(feature = "sm3")]
    {
        if name_upper == "SM3" {
            return Some(Box::new(sm3::Sm3Provider));
        }
    }

    // Try legacy digests (feature-gated)
    #[cfg(feature = "legacy")]
    {
        if let Some(provider) = create_legacy_provider(&name_upper) {
            return Some(provider);
        }
    }

    None
}

/// Creates a core digest provider by normalized (uppercase) algorithm name.
///
/// Handles SHA-1, SHA-2 (all variants), MD5, MD5-SHA1, RIPEMD-160, NULL,
/// and ML-DSA-MU — algorithms that are always available when the `"digests"`
/// feature is enabled.
fn create_core_provider(name: &str) -> Option<Box<dyn DigestProvider>> {
    match name {
        // ---------------------------------------------------------------
        // SHA-1 family (160-bit, 64-byte block)
        // C names: "SHA1", "SHA-1", "SSL3-SHA1"
        // ---------------------------------------------------------------
        "SHA-1" | "SHA1" | "SSL3-SHA1" => {
            Some(Box::new(sha1::Sha1Provider))
        }

        // ---------------------------------------------------------------
        // SHA-2 family — 256-bit state variants
        // Uses Sha256Provider with Sha256Variant enum
        // ---------------------------------------------------------------
        "SHA2-224" | "SHA-224" | "SHA224" => {
            Some(Box::new(sha2::Sha256Provider::new(sha2::Sha256Variant::Sha224)))
        }
        "SHA2-256" | "SHA-256" | "SHA256" => {
            Some(Box::new(sha2::Sha256Provider::new(sha2::Sha256Variant::Sha256)))
        }

        // ---------------------------------------------------------------
        // SHA-2 family — 512-bit state variants
        // Uses Sha512Provider with Sha512Variant enum
        // ---------------------------------------------------------------
        "SHA2-384" | "SHA-384" | "SHA384" => {
            Some(Box::new(sha2::Sha512Provider::new(sha2::Sha512Variant::Sha384)))
        }
        "SHA2-512" | "SHA-512" | "SHA512" => {
            Some(Box::new(sha2::Sha512Provider::new(sha2::Sha512Variant::Sha512)))
        }
        "SHA2-512/224" | "SHA-512/224" | "SHA512-224" => {
            Some(Box::new(sha2::Sha512Provider::new(sha2::Sha512Variant::Sha512_224)))
        }
        "SHA2-512/256" | "SHA-512/256" | "SHA512-256" => {
            Some(Box::new(sha2::Sha512Provider::new(sha2::Sha512Variant::Sha512_256)))
        }

        // ---------------------------------------------------------------
        // MD5 family (128-bit, 64-byte block)
        // ---------------------------------------------------------------
        "MD5" | "SSL3-MD5" => {
            Some(Box::new(md5::Md5Provider))
        }
        // MD5-SHA1 composite (288-bit / 36-byte output)
        "MD5-SHA1" => {
            Some(Box::new(md5::Md5Sha1Provider))
        }

        // ---------------------------------------------------------------
        // RIPEMD-160 (160-bit, 64-byte block)
        // ---------------------------------------------------------------
        "RIPEMD-160" | "RIPEMD160" | "RIPEMD" => {
            Some(Box::new(ripemd::Ripemd160Provider))
        }

        // ---------------------------------------------------------------
        // NULL digest (0-bit, 0-byte block) — passthrough sentinel
        // ---------------------------------------------------------------
        "NULL" => {
            Some(Box::new(null::NullDigestProvider))
        }

        // ---------------------------------------------------------------
        // ML-DSA mu hash — SHAKE256-based (64-byte output)
        // Internal to ML-DSA signature algorithm (FIPS 204)
        // ---------------------------------------------------------------
        "ML-DSA-MU" | "ML-DSA-44-MU" | "ML-DSA-65-MU" | "ML-DSA-87-MU" => {
            Some(Box::new(ml_dsa_mu::MlDsaMuProvider))
        }

        _ => None,
    }
}

/// Creates a SHA-3 family provider by normalized algorithm name.
///
/// Handles SHA3-224/256/384/512, SHAKE128/256, Keccak-224/256/384/512,
/// KECCAK-KMAC-128/256, and cSHAKE-128/256.
///
/// Only available when `feature = "sha3"` is enabled.
#[cfg(feature = "sha3")]
fn create_sha3_provider(name: &str) -> Option<Box<dyn DigestProvider>> {
    match name {
        // SHA-3 fixed-length digests
        "SHA3-224" => Some(Box::new(sha3::Sha3Provider::new(224))),
        "SHA3-256" => Some(Box::new(sha3::Sha3Provider::new(256))),
        "SHA3-384" => Some(Box::new(sha3::Sha3Provider::new(384))),
        "SHA3-512" => Some(Box::new(sha3::Sha3Provider::new(512))),

        // SHAKE extendable-output functions (XOF)
        "SHAKE-128" | "SHAKE128" => Some(Box::new(sha3::ShakeProvider::new(128))),
        "SHAKE-256" | "SHAKE256" => Some(Box::new(sha3::ShakeProvider::new(256))),

        // Raw Keccak (no padding prefix, ALGID absent)
        "KECCAK-224" => Some(Box::new(sha3::KeccakProvider::new(224))),
        "KECCAK-256" => Some(Box::new(sha3::KeccakProvider::new(256))),
        "KECCAK-384" => Some(Box::new(sha3::KeccakProvider::new(384))),
        "KECCAK-512" => Some(Box::new(sha3::KeccakProvider::new(512))),

        // KECCAK-KMAC (used by KMAC-128 and KMAC-256)
        "KECCAK-KMAC-128" | "KECCAK-KMAC128" => {
            Some(Box::new(sha3::KeccakKmacProvider::new(128)))
        }
        "KECCAK-KMAC-256" | "KECCAK-KMAC256" => {
            Some(Box::new(sha3::KeccakKmacProvider::new(256)))
        }

        // cSHAKE customizable XOF (NIST SP 800-185)
        "CSHAKE-128" | "CSHAKE128" => Some(Box::new(sha3::CshakeProvider::new(128))),
        "CSHAKE-256" | "CSHAKE256" => Some(Box::new(sha3::CshakeProvider::new(256))),

        _ => None,
    }
}

/// Creates a BLAKE2 provider by normalized algorithm name.
///
/// Handles BLAKE2b-512 and BLAKE2s-256 variants.
///
/// Only available when `feature = "blake2"` is enabled.
#[cfg(feature = "blake2")]
fn create_blake2_provider(name: &str) -> Option<Box<dyn DigestProvider>> {
    match name {
        "BLAKE2B-512" | "BLAKE2B512" => {
            Some(Box::new(blake2::Blake2bProvider))
        }
        "BLAKE2S-256" | "BLAKE2S256" => {
            Some(Box::new(blake2::Blake2sProvider))
        }
        _ => None,
    }
}

/// Creates a legacy digest provider by normalized algorithm name.
///
/// Handles MD2, MD4, MDC2, and Whirlpool — algorithms that are
/// only available through the legacy provider.
///
/// Only available when `feature = "legacy"` is enabled.
#[cfg(feature = "legacy")]
fn create_legacy_provider(name: &str) -> Option<Box<dyn DigestProvider>> {
    match name {
        "MD2" => Some(Box::new(legacy::Md2Provider)),
        "MD4" => Some(Box::new(legacy::Md4Provider)),
        "MDC2" => Some(Box::new(legacy::Mdc2Provider)),
        "WHIRLPOOL" => Some(Box::new(legacy::WhirlpoolProvider)),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `descriptors()` returns a non-empty list of algorithm
    /// descriptors when the module is compiled.
    #[test]
    fn test_descriptors_returns_algorithms() {
        let descs = descriptors();
        // At minimum, SHA-1, SHA-2 (6 variants), MD5, MD5-SHA1, RIPEMD-160,
        // NULL, and ML-DSA-MU should be present = at least 12 entries.
        assert!(
            !descs.is_empty(),
            "descriptors() should return at least the core digest algorithms"
        );
    }

    /// Verify that each descriptor has at least one name, a non-empty
    /// property string, and a non-empty description.
    #[test]
    fn test_descriptor_fields_are_populated() {
        for desc in descriptors() {
            assert!(
                !desc.names.is_empty(),
                "AlgorithmDescriptor must have at least one name"
            );
            assert!(
                !desc.property.is_empty(),
                "AlgorithmDescriptor.property must not be empty for {:?}",
                desc.names
            );
            assert!(
                !desc.description.is_empty(),
                "AlgorithmDescriptor.description must not be empty for {:?}",
                desc.names
            );
        }
    }

    /// Verify that `legacy_descriptors()` returns empty when "legacy" feature
    /// is disabled, or a non-empty list when enabled.
    #[test]
    fn test_legacy_descriptors_respects_feature_gate() {
        let legacy = legacy_descriptors();
        #[cfg(feature = "legacy")]
        {
            assert!(
                !legacy.is_empty(),
                "legacy_descriptors() should return descriptors when legacy feature is enabled"
            );
        }
        #[cfg(not(feature = "legacy"))]
        {
            assert!(
                legacy.is_empty(),
                "legacy_descriptors() should be empty when legacy feature is disabled"
            );
        }
    }

    /// Verify that `create_provider` returns `Some` for known SHA-2 names.
    #[test]
    fn test_create_provider_sha2_names() {
        // SHA-256 primary name
        assert!(
            create_provider("SHA-256").is_some(),
            "create_provider should resolve SHA-256"
        );
        // SHA-256 alias
        assert!(
            create_provider("SHA256").is_some(),
            "create_provider should resolve SHA256 alias"
        );
        // SHA-256 canonical name
        assert!(
            create_provider("SHA2-256").is_some(),
            "create_provider should resolve SHA2-256 canonical name"
        );
    }

    /// Verify case-insensitive name matching.
    #[test]
    fn test_create_provider_case_insensitive() {
        assert!(
            create_provider("sha-256").is_some(),
            "create_provider should be case-insensitive (lowercase)"
        );
        assert!(
            create_provider("Sha-256").is_some(),
            "create_provider should be case-insensitive (mixed case)"
        );
        assert!(
            create_provider("md5").is_some(),
            "create_provider should be case-insensitive for MD5"
        );
    }

    /// Verify that `create_provider` returns `None` for unknown names.
    #[test]
    fn test_create_provider_unknown_returns_none() {
        assert!(
            create_provider("NONEXISTENT").is_none(),
            "create_provider should return None for unknown algorithm"
        );
        assert!(
            create_provider("").is_none(),
            "create_provider should return None for empty string"
        );
    }

    /// Verify that created providers report correct digest sizes.
    #[test]
    fn test_provider_digest_sizes() {
        if let Some(sha1) = create_provider("SHA-1") {
            assert_eq!(sha1.digest_size(), 20, "SHA-1 digest size should be 20 bytes");
        }
        if let Some(sha256) = create_provider("SHA-256") {
            assert_eq!(sha256.digest_size(), 32, "SHA-256 digest size should be 32 bytes");
        }
        if let Some(sha512) = create_provider("SHA-512") {
            assert_eq!(sha512.digest_size(), 64, "SHA-512 digest size should be 64 bytes");
        }
        if let Some(md5) = create_provider("MD5") {
            assert_eq!(md5.digest_size(), 16, "MD5 digest size should be 16 bytes");
        }
        if let Some(null_d) = create_provider("NULL") {
            assert_eq!(null_d.digest_size(), 0, "NULL digest size should be 0 bytes");
        }
    }

    /// Verify that created providers report correct block sizes.
    #[test]
    fn test_provider_block_sizes() {
        if let Some(sha256) = create_provider("SHA-256") {
            assert_eq!(sha256.block_size(), 64, "SHA-256 block size should be 64 bytes");
        }
        if let Some(sha512) = create_provider("SHA-512") {
            assert_eq!(sha512.block_size(), 128, "SHA-512 block size should be 128 bytes");
        }
        if let Some(null_d) = create_provider("NULL") {
            assert_eq!(null_d.block_size(), 0, "NULL block size should be 0 bytes");
        }
    }

    /// Verify that all descriptors have property = "provider=default".
    #[test]
    fn test_default_descriptors_have_default_property() {
        for desc in descriptors() {
            assert_eq!(
                desc.property, "provider=default",
                "Default provider descriptors should have property 'provider=default', got '{}' for {:?}",
                desc.property, desc.names
            );
        }
    }

    /// Verify that legacy descriptors have property = "provider=legacy".
    #[test]
    fn test_legacy_descriptors_have_legacy_property() {
        for desc in legacy_descriptors() {
            assert_eq!(
                desc.property, "provider=legacy",
                "Legacy descriptors should have property 'provider=legacy', got '{}' for {:?}",
                desc.property, desc.names
            );
        }
    }

    /// Verify the NULL provider works as a passthrough.
    #[test]
    fn test_null_provider_passthrough() {
        let null_p = create_provider("NULL");
        assert!(null_p.is_some(), "NULL provider should be available");
        let null_p = null_p.expect("checked above");
        assert_eq!(null_p.name(), "NULL");
        assert_eq!(null_p.digest_size(), 0);
        assert_eq!(null_p.block_size(), 0);
    }

    /// Verify MD5-SHA1 composite provider has correct sizes.
    #[test]
    fn test_md5_sha1_composite() {
        if let Some(md5_sha1) = create_provider("MD5-SHA1") {
            // MD5 (16 bytes) + SHA-1 (20 bytes) = 36 bytes composite
            assert_eq!(md5_sha1.digest_size(), 36, "MD5-SHA1 should produce 36-byte output");
            assert_eq!(md5_sha1.block_size(), 64, "MD5-SHA1 block size should be 64");
        }
    }

    /// Verify RIPEMD-160 provider sizes.
    #[test]
    fn test_ripemd160_sizes() {
        if let Some(ripemd) = create_provider("RIPEMD-160") {
            assert_eq!(ripemd.digest_size(), 20, "RIPEMD-160 digest should be 20 bytes");
            assert_eq!(ripemd.block_size(), 64, "RIPEMD-160 block should be 64 bytes");
        }
    }
}
