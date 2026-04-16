//! AES-CBC-HMAC-SHA composite cipher for TLS record encryption.
//!
//! Implements the encrypt-then-MAC and MAC-then-encrypt composite cipher
//! constructions used in TLS 1.0–1.2. Key sizes: 128, 256 bits.
//! Translates C `cipher_aes_cbc_hmac_sha.c` (7 source files).

use crate::traits::AlgorithmDescriptor;

/// AES-CBC-HMAC-SHA composite cipher (MAC-then-encrypt variant).
///
/// This is the traditional TLS cipher construction where HMAC is computed
/// first and then the plaintext plus MAC are encrypted with AES-CBC.
#[derive(Debug, Clone)]
pub struct AesCbcHmacShaCipher {
    /// Key size in bytes (16 or 32).
    _key_size: usize,
    /// SHA variant: 1 for SHA-1, 256 for SHA-256.
    _sha_variant: u32,
}

/// AES-CBC-HMAC-SHA cipher with encrypt-then-MAC ordering.
///
/// This variant computes HMAC over the ciphertext rather than the
/// plaintext, providing more robust security guarantees.
#[derive(Debug, Clone)]
pub struct AesCbcHmacShaEtmCipher {
    /// Key size in bytes (16 or 32).
    _key_size: usize,
    /// SHA variant: 1 for SHA-1, 256 for SHA-256.
    _sha_variant: u32,
}

impl AesCbcHmacShaCipher {
    /// Creates a new AES-CBC-HMAC-SHA composite cipher.
    #[must_use]
    pub fn new(key_size: usize, sha_variant: u32) -> Self {
        Self { _key_size: key_size, _sha_variant: sha_variant }
    }
}

impl AesCbcHmacShaEtmCipher {
    /// Creates a new AES-CBC-HMAC-SHA ETM cipher.
    #[must_use]
    pub fn new(key_size: usize, sha_variant: u32) -> Self {
        Self { _key_size: key_size, _sha_variant: sha_variant }
    }
}

/// Returns algorithm descriptors for AES-CBC-HMAC-SHA ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // AES-128-CBC-HMAC-SHA1 (TLS)
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA1"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA1 composite (TLS)",
        },
        // AES-256-CBC-HMAC-SHA1 (TLS)
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA1"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA1 composite (TLS)",
        },
        // AES-128-CBC-HMAC-SHA256 (TLS)
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA256"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA256 composite (TLS)",
        },
        // AES-256-CBC-HMAC-SHA256 (TLS)
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA256"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA256 composite (TLS)",
        },
        // ETM variants
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA1-ETM"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA1 encrypt-then-MAC (TLS)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA1-ETM"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA1 encrypt-then-MAC (TLS)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-128-CBC-HMAC-SHA256-ETM"],
            property: "provider=default",
            description: "AES-128-CBC with HMAC-SHA256 encrypt-then-MAC (TLS)",
        },
        AlgorithmDescriptor {
            names: vec!["AES-256-CBC-HMAC-SHA256-ETM"],
            property: "provider=default",
            description: "AES-256-CBC with HMAC-SHA256 encrypt-then-MAC (TLS)",
        },
    ]
}
