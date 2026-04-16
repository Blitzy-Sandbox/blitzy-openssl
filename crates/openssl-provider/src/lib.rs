//! OpenSSL Provider - Provider framework with trait-based dispatch.
//!
//! This crate implements the provider system for the OpenSSL Rust workspace,
//! including Default, Legacy, Base, and Null providers.

#![forbid(unsafe_code)]

/// Provider trait definitions that replace C `OSSL_DISPATCH` function pointer
/// tables.  Defines the full trait hierarchy for all algorithm categories.
pub mod traits;

/// Method store and algorithm dispatch infrastructure.  Manages algorithm
/// registration, lookup by name and property query, caching, and provider-based
/// algorithm fetch.  Translates `crypto/core_fetch.c` and `crypto/core_algorithm.c`.
pub mod dispatch;

/// Default provider implementation — the primary provider supplying the
/// standard non-FIPS algorithm catalog across all operation categories.
/// Replaces C `providers/defltprov.c`.
pub mod default;

/// Legacy provider implementation — provides deprecated algorithms (MD2, MD4,
/// MDC2, Whirlpool, Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, DES,
/// PBKDF1, PVK KDF) tagged with `provider=legacy`. Entire module gated
/// behind `#[cfg(feature = "legacy")]`. Replaces C `providers/legacyprov.c`.
#[cfg(feature = "legacy")]
pub mod legacy;

/// Base provider implementation — a foundational provider exposing encoder,
/// decoder, store, and seed-source RAND operations. Does NOT provide
/// cryptographic algorithm implementations. Replaces C `providers/baseprov.c`.
pub mod base;

/// Null provider implementation — a minimal, ABI-valid provider that returns
/// metadata (name, version, status) but advertises zero algorithms for all
/// operation classes.  `query_operation()` always returns `None`.  Used as a
/// sentinel/placeholder when a valid provider handle is needed but no
/// algorithm discovery should succeed.  Replaces C `providers/nullprov.c`.
pub mod null;

/// Algorithm implementation backends (ciphers, digests, KDFs, MACs, KEM, etc.).
pub mod implementations;

#[cfg(test)]
mod tests;
