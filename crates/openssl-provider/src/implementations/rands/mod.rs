//! # Random Number Generator Implementation Backends
//!
//! Random number generator implementations for the provider system covering
//! CTR-DRBG (AES-256), Hash-DRBG (SHA-256/512), HMAC-DRBG, seed sources
//! (OS entropy, `/dev/urandom`, `getrandom(2)`), and jitter entropy.
//!
//! Source: `providers/implementations/rands/` (15 C files).
//!
//! Each RNG struct implements `RandProvider` from `crate::traits`.

pub mod drbg;

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all random number generator algorithm descriptors registered by this
/// module.
///
/// Called by [`super::all_rand_descriptors()`] when the `"rands"` feature
/// is enabled. Returns descriptors for every DRBG variant supported
/// by the default provider.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["CTR-DRBG"],
            "provider=default",
            "AES-CTR based Deterministic Random Bit Generator",
        ),
        algorithm(
            &["HASH-DRBG"],
            "provider=default",
            "Hash-based Deterministic Random Bit Generator",
        ),
        algorithm(
            &["HMAC-DRBG"],
            "provider=default",
            "HMAC-based Deterministic Random Bit Generator",
        ),
        algorithm(
            &["SEED-SRC"],
            "provider=default",
            "Operating system seed entropy source",
        ),
    ]
}
