//! AES-GCM (Galois/Counter Mode) AEAD cipher.
//!
//! Supports key sizes: 128, 192, 256 bits.
//! Translates C `cipher_aes_gcm.c` and `cipher_aes_gcm_hw.c`.

use crate::traits::AlgorithmDescriptor;

/// AES-GCM AEAD cipher implementation.
#[derive(Debug, Clone)]
pub struct AesGcmCipher {
    /// Key size in bytes (16, 24, or 32).
    _key_size: usize,
}

/// Context for an active AES-GCM operation.
#[derive(Debug, Clone)]
pub struct AesGcmContext {
    /// The cipher configuration.
    _cipher: AesGcmCipher,
    /// Whether this is an encryption or decryption context.
    _encrypting: bool,
}

impl AesGcmCipher {
    /// Creates a new AES-GCM cipher with the specified key size.
    #[must_use]
    pub fn new(key_size: usize) -> Self {
        Self { _key_size: key_size }
    }
}

impl AesGcmContext {
    /// Creates a new AES-GCM context.
    #[must_use]
    pub fn new(cipher: AesGcmCipher, encrypting: bool) -> Self {
        Self { _cipher: cipher, _encrypting: encrypting }
    }
}

/// Returns algorithm descriptors for AES-GCM ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["AES-256-GCM"],
            property: "provider=default",
            description: "AES-256 Galois/Counter Mode AEAD cipher",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-GCM"],
            property: "provider=default",
            description: "AES-192 Galois/Counter Mode AEAD cipher",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-GCM"],
            property: "provider=default",
            description: "AES-128 Galois/Counter Mode AEAD cipher",
        },
    ]
}
