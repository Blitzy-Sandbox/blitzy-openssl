//! # Digest Implementation Backends
//!
//! Message digest implementations for the provider system covering
//! SHA-1, SHA-2 (224/256/384/512), SHA-3 (224/256/384/512), SHAKE (128/256),
//! BLAKE2b-512, BLAKE2s-256, SM3, MD5, and legacy digests (MD2, MD4, MDC2,
//! RIPEMD-160, Whirlpool).
//!
//! Source: `providers/implementations/digests/` (17 C files).
//!
//! Each digest struct implements `DigestProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all digest algorithm descriptors registered by this module.
///
/// Called by [`super::all_digest_descriptors()`] when the `"digests"` feature
/// is enabled. Returns descriptors for every digest variant supported by the
/// default and legacy providers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SHA2-256", "SHA-256", "SHA256"],
            "provider=default",
            "SHA-2 256-bit message digest",
        ),
        algorithm(
            &["SHA2-384", "SHA-384", "SHA384"],
            "provider=default",
            "SHA-2 384-bit message digest",
        ),
        algorithm(
            &["SHA2-512", "SHA-512", "SHA512"],
            "provider=default",
            "SHA-2 512-bit message digest",
        ),
        algorithm(
            &["SHA2-224", "SHA-224", "SHA224"],
            "provider=default",
            "SHA-2 224-bit message digest",
        ),
        algorithm(
            &["SHA1", "SHA-1"],
            "provider=default",
            "SHA-1 message digest (legacy)",
        ),
        algorithm(
            &["SHA3-256"],
            "provider=default",
            "SHA-3 256-bit message digest",
        ),
        algorithm(
            &["SHA3-384"],
            "provider=default",
            "SHA-3 384-bit message digest",
        ),
        algorithm(
            &["SHA3-512"],
            "provider=default",
            "SHA-3 512-bit message digest",
        ),
        algorithm(
            &["SHAKE128"],
            "provider=default",
            "SHAKE-128 extendable output function",
        ),
        algorithm(
            &["SHAKE256"],
            "provider=default",
            "SHAKE-256 extendable output function",
        ),
        algorithm(
            &["MD5"],
            "provider=default",
            "MD5 message digest (legacy)",
        ),
    ]
}
