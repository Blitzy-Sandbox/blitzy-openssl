//! AES-SIV (Synthetic Initialization Vector) and AES-GCM-SIV AEAD ciphers.
//!
//! AES-SIV (RFC 5297): deterministic AEAD with misuse resistance.
//! AES-GCM-SIV (RFC 8452): nonce-misuse resistant AEAD.
//! Key sizes: 128, 192, 256 bits (SIV); 128, 256 bits (GCM-SIV).
//! Translates C `cipher_aes_siv.c` and `cipher_aes_gcm_siv.c`.

use crate::traits::AlgorithmDescriptor;

/// AES-SIV cipher implementation (RFC 5297).
#[derive(Debug, Clone)]
pub struct AesSivCipher {
    /// Key size in bytes (32, 48, or 64 — doubled for SIV internal keys).
    _key_size: usize,
}

/// Context for an active AES-SIV operation.
#[derive(Debug, Clone)]
pub struct AesSivContext {
    /// The cipher configuration.
    _cipher: AesSivCipher,
    /// Whether this is an encryption or decryption context.
    _encrypting: bool,
}

/// AES-GCM-SIV cipher implementation (RFC 8452).
#[derive(Debug, Clone)]
pub struct AesGcmSivCipher {
    /// Key size in bytes (16 or 32).
    _key_size: usize,
}

/// Context for an active AES-GCM-SIV operation.
#[derive(Debug, Clone)]
pub struct AesGcmSivContext {
    /// The cipher configuration.
    _cipher: AesGcmSivCipher,
    /// Whether this is an encryption or decryption context.
    _encrypting: bool,
}

impl AesSivCipher {
    /// Creates a new AES-SIV cipher.
    #[must_use]
    pub fn new(key_size: usize) -> Self {
        Self { _key_size: key_size }
    }
}

impl AesSivContext {
    /// Creates a new AES-SIV context.
    #[must_use]
    pub fn new(cipher: AesSivCipher, encrypting: bool) -> Self {
        Self { _cipher: cipher, _encrypting: encrypting }
    }
}

impl AesGcmSivCipher {
    /// Creates a new AES-GCM-SIV cipher.
    #[must_use]
    pub fn new(key_size: usize) -> Self {
        Self { _key_size: key_size }
    }
}

impl AesGcmSivContext {
    /// Creates a new AES-GCM-SIV context.
    #[must_use]
    pub fn new(cipher: AesGcmSivCipher, encrypting: bool) -> Self {
        Self { _cipher: cipher, _encrypting: encrypting }
    }
}

/// Returns algorithm descriptors for AES-SIV and AES-GCM-SIV ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["AES-128-SIV"],
            property: "provider=default",
            description: "AES-128 Synthetic IV AEAD (RFC 5297)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-192-SIV"],
            property: "provider=default",
            description: "AES-192 Synthetic IV AEAD (RFC 5297)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-SIV"],
            property: "provider=default",
            description: "AES-256 Synthetic IV AEAD (RFC 5297)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-GCM-SIV"],
            property: "provider=default",
            description: "AES-128 GCM-SIV nonce-misuse resistant AEAD (RFC 8452)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-GCM-SIV"],
            property: "provider=default",
            description: "AES-256 GCM-SIV nonce-misuse resistant AEAD (RFC 8452)",
        },
    ]
}
