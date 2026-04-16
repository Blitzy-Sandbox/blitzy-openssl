//! # Signature Implementation Backends
//!
//! Digital signature implementations for the provider system covering
//! RSA (PKCS#1 v1.5, PSS), DSA, ECDSA, EdDSA (Ed25519, Ed448),
//! ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS (SP 800-208), and
//! HMAC-based signatures.
//!
//! Source: `providers/implementations/signature/` (9 C files).
//!
//! Each signature struct implements `SignatureProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all signature algorithm descriptors registered by this module.
///
/// Called by [`super::all_signature_descriptors()`] when the `"signatures"`
/// feature is enabled. Returns descriptors for every signature variant supported
/// by the default and legacy providers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["RSA"],
            "provider=default",
            "RSA PKCS#1 v1.5 / PSS signature scheme",
        ),
        algorithm(
            &["DSA"],
            "provider=default",
            "Digital Signature Algorithm (FIPS 186-4)",
        ),
        algorithm(
            &["ECDSA"],
            "provider=default",
            "Elliptic Curve Digital Signature Algorithm",
        ),
        algorithm(
            &["ED25519"],
            "provider=default",
            "Edwards-curve Digital Signature Algorithm (Ed25519)",
        ),
        algorithm(
            &["ED448"],
            "provider=default",
            "Edwards-curve Digital Signature Algorithm (Ed448)",
        ),
        algorithm(
            &["ML-DSA-44"],
            "provider=default",
            "Module-Lattice Digital Signature Algorithm (FIPS 204, cat 2)",
        ),
        algorithm(
            &["ML-DSA-65"],
            "provider=default",
            "Module-Lattice Digital Signature Algorithm (FIPS 204, cat 3)",
        ),
        algorithm(
            &["ML-DSA-87"],
            "provider=default",
            "Module-Lattice Digital Signature Algorithm (FIPS 204, cat 5)",
        ),
        algorithm(
            &["SLH-DSA-SHA2-128s"],
            "provider=default",
            "Stateless Hash-Based Digital Signature (FIPS 205)",
        ),
        algorithm(
            &["HMAC"],
            "provider=default",
            "HMAC-based signature (for MACs used as signatures)",
        ),
    ]
}
