//! # MAC Implementation Backends
//!
//! Message authentication code implementations for the provider system covering
//! HMAC, CMAC, GMAC, KMAC-128/256, Poly1305, SipHash, and BLAKE2-MAC.
//!
//! Source: `providers/implementations/macs/` (9 C files).
//!
//! Each MAC struct implements `MacProvider` from `crate::traits`.

pub mod blake2_mac;
pub mod poly1305;
pub mod siphash;

use super::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns all MAC algorithm descriptors registered by this module.
///
/// Called by [`super::all_mac_descriptors()`] when the `"macs"` feature
/// is enabled. Returns descriptors for every MAC variant supported by the
/// default and legacy providers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = vec![
        algorithm(
            &["HMAC"],
            "provider=default",
            "Hash-based Message Authentication Code",
        ),
        algorithm(
            &["CMAC"],
            "provider=default",
            "Cipher-based Message Authentication Code",
        ),
        algorithm(
            &["GMAC"],
            "provider=default",
            "Galois Message Authentication Code",
        ),
        algorithm(
            &["KMAC-128", "KMAC128"],
            "provider=default",
            "KECCAK Message Authentication Code 128-bit",
        ),
        algorithm(
            &["KMAC-256", "KMAC256"],
            "provider=default",
            "KECCAK Message Authentication Code 256-bit",
        ),
        algorithm(
            &["POLY1305"],
            "provider=default",
            "Poly1305 Message Authentication Code",
        ),
        algorithm(
            &["SIPHASH"],
            "provider=default",
            "SipHash Message Authentication Code",
        ),
    ];
    descs.extend(blake2_mac::Blake2MacProvider::all_descriptors());
    descs
}
