//! # Key Management Implementation Backends
//!
//! Key management implementations for the provider system covering RSA,
//! EC (P-256, P-384, P-521, secp256k1), DH (named groups, FFDHE), DSA,
//! X25519, X448, Ed25519, Ed448, ML-KEM, ML-DSA, SLH-DSA, LMS, HMAC,
//! and legacy key types.
//!
//! Source: `providers/implementations/keymgmt/` (13 C files).
//!
//! Each key management struct implements `KeyMgmtProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all key management algorithm descriptors registered by this module.
///
/// Called by [`super::all_keymgmt_descriptors()`] when the `"keymgmt"` feature
/// is enabled. Returns descriptors for every key management variant supported
/// by the default and legacy providers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["RSA", "rsaEncryption"],
            "provider=default",
            "RSA key management (keygen, import, export)",
        ),
        algorithm(
            &["RSA-PSS", "RSASSA-PSS"],
            "provider=default",
            "RSA-PSS key management",
        ),
        algorithm(
            &["EC"],
            "provider=default",
            "Elliptic Curve key management (P-256, P-384, P-521)",
        ),
        algorithm(
            &["DH", "dhKeyAgreement"],
            "provider=default",
            "Diffie-Hellman key management",
        ),
        algorithm(
            &["DHX", "X9.42 DH"],
            "provider=default",
            "X9.42 Diffie-Hellman key management",
        ),
        algorithm(
            &["DSA"],
            "provider=default",
            "DSA key management (keygen, import, export)",
        ),
        algorithm(
            &["X25519"],
            "provider=default",
            "X25519 key management (RFC 7748)",
        ),
        algorithm(
            &["X448"],
            "provider=default",
            "X448 key management (RFC 7748)",
        ),
        algorithm(
            &["ED25519"],
            "provider=default",
            "Ed25519 key management (RFC 8032)",
        ),
        algorithm(
            &["ED448"],
            "provider=default",
            "Ed448 key management (RFC 8032)",
        ),
        algorithm(
            &["ML-KEM-768"],
            "provider=default",
            "ML-KEM key management (FIPS 203)",
        ),
        algorithm(
            &["ML-DSA-65"],
            "provider=default",
            "ML-DSA key management (FIPS 204)",
        ),
        algorithm(
            &["HMAC"],
            "provider=default",
            "HMAC key management for MAC keys",
        ),
    ]
}
