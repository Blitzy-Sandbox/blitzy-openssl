//! `ChaCha20` stream cipher and `ChaCha20`-Poly1305 AEAD.
//!
//! Key size: 256 bits. Translates C `cipher_chacha20_poly1305.c` (4 files).

use crate::traits::AlgorithmDescriptor;

/// `ChaCha20` stream cipher.
///
/// A 256-bit stream cipher defined in RFC 8439.
#[derive(Debug, Clone)]
pub struct ChaCha20Cipher {
    /// Cipher key (32 bytes).
    _key_size: usize,
}

/// `ChaCha20`-Poly1305 AEAD cipher.
///
/// An AEAD construction combining `ChaCha20` encryption with Poly1305
/// authentication, as defined in RFC 8439 Section 2.8.
#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305Cipher {
    /// Cipher key (32 bytes).
    _key_size: usize,
}

impl ChaCha20Cipher {
    /// Creates a new `ChaCha20` stream cipher.
    #[must_use]
    pub fn new() -> Self {
        Self { _key_size: 32 }
    }
}

impl Default for ChaCha20Cipher {
    fn default() -> Self {
        Self::new()
    }
}

impl ChaCha20Poly1305Cipher {
    /// Creates a new `ChaCha20`-Poly1305 AEAD cipher.
    #[must_use]
    pub fn new() -> Self {
        Self { _key_size: 32 }
    }
}

impl Default for ChaCha20Poly1305Cipher {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns algorithm descriptors for `ChaCha20` ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["ChaCha20"],
            property: "provider=default",
            description: "ChaCha20 stream cipher (RFC 8439)",
        },
        AlgorithmDescriptor {
            names: vec!["ChaCha20-Poly1305"],
            property: "provider=default",
            description: "ChaCha20-Poly1305 AEAD (RFC 8439)",
        },
    ]
}
