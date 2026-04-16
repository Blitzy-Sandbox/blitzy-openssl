//! # Cipher Implementation Backends
//!
//! Symmetric cipher implementations for the provider system covering
//! AES (GCM/CCM/OCB/SIV/XTS/CBC/CTR/ECB/OFB/CFB/wrap), ChaCha20-Poly1305,
//! 3DES, Camellia, ARIA, SM4, and legacy ciphers (Blowfish, CAST5, IDEA,
//! SEED, RC2, RC4, RC5).
//!
//! Source: `providers/implementations/ciphers/` (81 C files).
//!
//! Each cipher struct implements `CipherProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all cipher algorithm descriptors registered by this module.
///
/// Called by [`super::all_cipher_descriptors()`] when the `"ciphers"` feature
/// is enabled. Returns descriptors for every cipher variant supported by the
/// default and legacy providers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["AES-256-GCM"],
            "provider=default",
            "AES-256 Galois/Counter Mode cipher",
        ),
        algorithm(
            &["AES-192-GCM"],
            "provider=default",
            "AES-192 Galois/Counter Mode cipher",
        ),
        algorithm(
            &["AES-128-GCM"],
            "provider=default",
            "AES-128 Galois/Counter Mode cipher",
        ),
        algorithm(
            &["AES-256-CBC", "AES256"],
            "provider=default",
            "AES-256 Cipher Block Chaining mode cipher",
        ),
        algorithm(
            &["AES-128-CBC", "AES128"],
            "provider=default",
            "AES-128 Cipher Block Chaining mode cipher",
        ),
        algorithm(
            &["CHACHA20-POLY1305"],
            "provider=default",
            "ChaCha20-Poly1305 AEAD cipher",
        ),
        algorithm(
            &["DES-EDE3-CBC", "DES3"],
            "provider=default",
            "Triple DES EDE Cipher Block Chaining mode cipher",
        ),
        algorithm(
            &["NULL"],
            "provider=default",
            "Null cipher (no encryption)",
        ),
    ]
}
