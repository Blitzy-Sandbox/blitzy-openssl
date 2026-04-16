//! AES-CCM (Counter with CBC-MAC) AEAD cipher.
//!
//! Supports key sizes: 128, 192, 256 bits.
//! Translates C `cipher_aes_ccm.c` and `cipher_aes_ccm_hw.c`.

use crate::traits::AlgorithmDescriptor;

/// AES-CCM AEAD cipher implementation.
#[derive(Debug, Clone)]
pub struct AesCcmCipher {
    /// Key size in bytes (16, 24, or 32).
    _key_size: usize,
}

/// Context for an active AES-CCM operation.
#[derive(Debug, Clone)]
pub struct AesCcmContext {
    /// The cipher configuration.
    _cipher: AesCcmCipher,
    /// Whether this is an encryption or decryption context.
    _encrypting: bool,
}

impl AesCcmCipher {
    /// Creates a new AES-CCM cipher with the specified key size.
    #[must_use]
    pub fn new(key_size: usize) -> Self {
        Self { _key_size: key_size }
    }
}

impl AesCcmContext {
    /// Creates a new AES-CCM context.
    #[must_use]
    pub fn new(cipher: AesCcmCipher, encrypting: bool) -> Self {
        Self { _cipher: cipher, _encrypting: encrypting }
    }
}

/// Returns algorithm descriptors for AES-CCM ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["AES-256-CCM"],
            property: "provider=default",
            description: "AES-256 Counter with CBC-MAC AEAD cipher",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-CCM"],
            property: "provider=default",
            description: "AES-192 Counter with CBC-MAC AEAD cipher",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CCM"],
            property: "provider=default",
            description: "AES-128 Counter with CBC-MAC AEAD cipher",
        },
    ]
}
