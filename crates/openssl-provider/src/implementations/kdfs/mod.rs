//! # Key Derivation Function Implementation Backends
//!
//! KDF implementations for the provider system covering HKDF (RFC 5869),
//! PBKDF2, Argon2id/Argon2i/Argon2d, scrypt, KBKDF (SP 800-108), TLS1-PRF,
//! SSKDF, X963KDF, SSHKDF, and PKCS#12 KDF.
//!
//! Source: `providers/implementations/kdfs/` (16 C files).
//!
//! Each KDF struct implements `KdfProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all KDF algorithm descriptors registered by this module.
///
/// Called by [`super::all_kdf_descriptors()`] when the `"kdfs"` feature
/// is enabled. Returns descriptors for every KDF variant supported by the
/// default and legacy providers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["HKDF"],
            "provider=default",
            "HMAC-based Key Derivation Function (RFC 5869)",
        ),
        algorithm(
            &["PBKDF2"],
            "provider=default",
            "Password-Based Key Derivation Function 2",
        ),
        algorithm(
            &["ARGON2ID"],
            "provider=default",
            "Argon2id password hashing function",
        ),
        algorithm(
            &["SCRYPT"],
            "provider=default",
            "scrypt password-based key derivation",
        ),
        algorithm(
            &["KBKDF"],
            "provider=default",
            "Key-Based Key Derivation Function (SP 800-108)",
        ),
        algorithm(
            &["TLS1-PRF"],
            "provider=default",
            "TLS 1.0/1.1/1.2 pseudo-random function",
        ),
        algorithm(
            &["SSKDF"],
            "provider=default",
            "Single-Step Key Derivation Function (SP 800-56C)",
        ),
        algorithm(
            &["X963KDF"],
            "provider=default",
            "ANSI X9.63 Key Derivation Function",
        ),
        algorithm(
            &["SSHKDF"],
            "provider=default",
            "SSH Key Derivation Function",
        ),
    ]
}
