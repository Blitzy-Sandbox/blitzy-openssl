//! Provider system — trait-based dispatch replacing C `OSSL_DISPATCH` function pointer tables.
//!
//! This module contains the provider framework for the `openssl-crypto` crate,
//! including predefined provider definitions, core dispatch, and property matching.

pub mod predefined;

// Re-export commonly used predefined provider types for convenience.
pub use predefined::{InfoPair, ProviderInfo, ProviderKind};
