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

/// Algorithm implementation backends (ciphers, digests, KDFs, MACs, KEM, etc.).
pub mod implementations;
