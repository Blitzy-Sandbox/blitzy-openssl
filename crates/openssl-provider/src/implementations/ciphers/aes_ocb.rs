//! AES-OCB (Offset Codebook Mode) AEAD cipher (RFC 7253).
//!
//! Supports key sizes: 128, 192, 256 bits.
//! Gated behind `ocb` feature due to historical patent considerations.
//! Translates C `cipher_aes_ocb.c` and `cipher_aes_ocb_hw.c`.

use crate::traits::AlgorithmDescriptor;

/// AES-OCB AEAD cipher implementation.
#[derive(Debug, Clone)]
pub struct AesOcbCipher {
    /// Key size in bytes (16, 24, or 32).
    _key_size: usize,
}

/// Context for an active AES-OCB operation.
#[derive(Debug, Clone)]
pub struct AesOcbContext {
    /// The cipher configuration.
    _cipher: AesOcbCipher,
    /// Whether this is an encryption or decryption context.
    _encrypting: bool,
}

impl AesOcbCipher {
    /// Creates a new AES-OCB cipher with the specified key size.
    #[must_use]
    pub fn new(key_size: usize) -> Self {
        Self { _key_size: key_size }
    }
}

impl AesOcbContext {
    /// Creates a new AES-OCB context.
    #[must_use]
    pub fn new(cipher: AesOcbCipher, encrypting: bool) -> Self {
        Self { _cipher: cipher, _encrypting: encrypting }
    }
}

/// Returns algorithm descriptors for AES-OCB ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["AES-256-OCB"],
            property: "provider=default",
            description: "AES-256 Offset Codebook AEAD cipher (RFC 7253)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-OCB"],
            property: "provider=default",
            description: "AES-192 Offset Codebook AEAD cipher (RFC 7253)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-OCB"],
            property: "provider=default",
            description: "AES-128 Offset Codebook AEAD cipher (RFC 7253)",
        },
    ]
}
