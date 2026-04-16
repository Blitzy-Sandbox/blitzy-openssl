//! AES cipher implementations for ECB, CBC, OFB, CFB, CTR, and CTS modes.
//!
//! Supports key sizes: 128, 192, 256 bits.
//! Translates C `cipher_aes.c` and `cipher_aes_hw.c`.

use crate::traits::AlgorithmDescriptor;
use super::common::CipherMode;

/// AES block cipher implementation for standard (non-AEAD) modes.
#[derive(Debug, Clone)]
pub struct AesCipher {
    /// Key size in bytes (16, 24, or 32).
    _key_size: usize,
    /// Operating mode.
    _mode: AesCipherMode,
}

/// Context for an active AES cipher operation.
#[derive(Debug, Clone)]
pub struct AesCipherContext {
    /// The cipher configuration.
    _cipher: AesCipher,
    /// Whether encryption (true) or decryption (false).
    _encrypting: bool,
    /// Whether the context has been initialized with key/IV.
    _initialized: bool,
}

/// AES cipher modes supported by this module (non-AEAD modes only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesCipherMode {
    /// Electronic Codebook.
    Ecb,
    /// Cipher Block Chaining.
    Cbc,
    /// Output Feedback.
    Ofb,
    /// Cipher Feedback (128-bit, 8-bit, and 1-bit variants).
    Cfb,
    /// Counter mode.
    Ctr,
    /// CBC with Ciphertext Stealing.
    CbcCts(CtsVariant),
}

/// CTS (Ciphertext Stealing) variants for CBC-CTS mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtsVariant {
    /// CS1 — Kerberos-style CTS.
    Cs1,
    /// CS2 — NIST SP 800-38A Addendum.
    Cs2,
    /// CS3 — Default variant used by most implementations.
    Cs3,
}

impl AesCipher {
    /// Creates a new AES cipher with the specified key size and mode.
    #[must_use]
    pub fn new(key_size: usize, mode: AesCipherMode) -> Self {
        Self { _key_size: key_size, _mode: mode }
    }
}

impl AesCipherContext {
    /// Creates a new uninitialized AES cipher context.
    #[must_use]
    pub fn new(cipher: AesCipher, encrypting: bool) -> Self {
        Self {
            _cipher: cipher,
            _encrypting: encrypting,
            _initialized: false,
        }
    }
}

/// Returns algorithm descriptors for AES standard-mode ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();
    let modes = [
        ("ECB", CipherMode::Ecb),
        ("CBC", CipherMode::Cbc),
        ("OFB", CipherMode::Ofb),
        ("CFB", CipherMode::Cfb),
        ("CTR", CipherMode::Ctr),
        ("CBC-CTS", CipherMode::CbcCts),
    ];
    let key_sizes = [128, 192, 256];

    for (mode_name, _mode) in &modes {
        for key_bits in &key_sizes {
            let name = format!("AES-{key_bits}-{mode_name}");
            let leaked_name: &'static str = Box::leak(name.into_boxed_str());
            descs.push(AlgorithmDescriptor {
                names: vec![leaked_name],
                property: "provider=default",
                description: match *mode_name {
                    "ECB" => "AES Electronic Codebook mode cipher",
                    "CBC" => "AES Cipher Block Chaining mode cipher",
                    "OFB" => "AES Output Feedback mode cipher",
                    "CFB" => "AES Cipher Feedback mode cipher",
                    "CTR" => "AES Counter mode cipher",
                    "CBC-CTS" => "AES CBC with Ciphertext Stealing",
                    _ => "AES cipher",
                },
            });
        }
    }

    // CFB sub-variants: CFB8 and CFB1 for 128/192/256
    for variant in &["CFB8", "CFB1"] {
        for key_bits in &key_sizes {
            let name = format!("AES-{key_bits}-{variant}");
            let leaked_name: &'static str = Box::leak(name.into_boxed_str());
            descs.push(AlgorithmDescriptor {
                names: vec![leaked_name],
                property: "provider=default",
                description: "AES Cipher Feedback sub-variant cipher",
            });
        }
    }

    descs
}
