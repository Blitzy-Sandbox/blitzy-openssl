//! # Algorithm Implementation Backends
//!
//! This module contains all concrete algorithm implementations for the
//! OpenSSL Rust provider system. Each submodule corresponds to an algorithm
//! category in the provider dispatch architecture.

/// Key encapsulation mechanism implementations (ML-KEM, HPKE DHKEM, hybrid MLX, RSA).
/// Source: `providers/implementations/kem/` (7 C files).
#[cfg(feature = "kem")]
pub mod kem;
