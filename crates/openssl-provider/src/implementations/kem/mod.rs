//! # KEM Implementation Backends
//!
//! Key Encapsulation Mechanism provider implementations including
//! ML-KEM (FIPS 203 — 512/768/1024), HPKE DHKEM (RFC 9180),
//! hybrid MLX (ML-KEM + X25519/X448), and RSA-KEM.
//!
//! Source: `providers/implementations/kem/` (7 C files).
//!
//! Each KEM struct implements `KemProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Shared KEM utilities — mode name mapping and helpers.
pub mod util;

// Re-export commonly used items from util for convenience.
pub use util::{kem_mode_to_name, kem_modename_to_id, KemMode};

/// Returns all KEM algorithm descriptors registered by this module.
///
/// Called by [`super::all_kem_descriptors()`] when the `"kem"` feature
/// is enabled. Returns descriptors for every KEM variant supported
/// by the default provider.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["ML-KEM-512"],
            "provider=default",
            "Module-Lattice KEM 512-bit security (FIPS 203)",
        ),
        algorithm(
            &["ML-KEM-768"],
            "provider=default",
            "Module-Lattice KEM 768-bit security (FIPS 203)",
        ),
        algorithm(
            &["ML-KEM-1024"],
            "provider=default",
            "Module-Lattice KEM 1024-bit security (FIPS 203)",
        ),
        algorithm(
            &["DHKEM"],
            "provider=default",
            "Diffie-Hellman based KEM for HPKE (RFC 9180)",
        ),
        algorithm(
            &["RSA"],
            "provider=default",
            "RSA Key Encapsulation Mechanism",
        ),
    ]
}
