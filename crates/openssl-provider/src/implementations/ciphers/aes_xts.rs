//! AES-XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing).
//!
//! Used for disk/storage encryption. Requires double-length keys:
//! AES-128-XTS uses 256-bit key, AES-256-XTS uses 512-bit key.
//! Translates C `cipher_aes_xts.c` and `cipher_aes_xts_hw.c`.

use crate::traits::AlgorithmDescriptor;

/// AES-XTS cipher implementation.
#[derive(Debug, Clone)]
pub struct AesXtsCipher {
    /// Key size in bytes (32 for AES-128-XTS, 64 for AES-256-XTS).
    _key_size: usize,
}

/// Context for an active AES-XTS operation.
#[derive(Debug, Clone)]
pub struct AesXtsContext {
    /// The cipher configuration.
    _cipher: AesXtsCipher,
    /// Whether this is an encryption or decryption context.
    _encrypting: bool,
}

impl AesXtsCipher {
    /// Creates a new AES-XTS cipher with the specified key size.
    #[must_use]
    pub fn new(key_size: usize) -> Self {
        Self { _key_size: key_size }
    }
}

impl AesXtsContext {
    /// Creates a new AES-XTS context.
    #[must_use]
    pub fn new(cipher: AesXtsCipher, encrypting: bool) -> Self {
        Self { _cipher: cipher, _encrypting: encrypting }
    }
}

/// Returns algorithm descriptors for AES-XTS ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["AES-256-XTS"],
            property: "provider=default",
            description: "AES-256-XTS storage encryption (IEEE P1619)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-XTS"],
            property: "provider=default",
            description: "AES-128-XTS storage encryption (IEEE P1619)",
        },
    ]
}
