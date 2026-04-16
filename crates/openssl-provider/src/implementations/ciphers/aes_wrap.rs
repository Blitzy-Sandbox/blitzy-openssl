//! AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649).
//!
//! Supports key sizes: 128, 192, 256 bits.
//! Translates C `cipher_aes_wrp.c`.

use crate::traits::AlgorithmDescriptor;

/// AES Key Wrap cipher implementation.
#[derive(Debug, Clone)]
pub struct AesWrapCipher {
    /// Key size in bytes (16, 24, or 32).
    _key_size: usize,
    /// Whether padding is enabled (RFC 5649) or not (RFC 3394).
    _with_padding: bool,
}

/// Context for an active AES Key Wrap operation.
#[derive(Debug, Clone)]
pub struct AesWrapContext {
    /// The cipher configuration.
    _cipher: AesWrapCipher,
    /// Whether this is a wrap (encrypt) or unwrap (decrypt) context.
    _wrapping: bool,
}

impl AesWrapCipher {
    /// Creates a new AES Key Wrap cipher.
    #[must_use]
    pub fn new(key_size: usize, with_padding: bool) -> Self {
        Self { _key_size: key_size, _with_padding: with_padding }
    }
}

impl AesWrapContext {
    /// Creates a new AES Key Wrap context.
    #[must_use]
    pub fn new(cipher: AesWrapCipher, wrapping: bool) -> Self {
        Self { _cipher: cipher, _wrapping: wrapping }
    }
}

/// Returns algorithm descriptors for AES Key Wrap ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();
    let key_sizes = [128, 192, 256];

    // Standard AES Key Wrap (RFC 3394)
    for key_bits in &key_sizes {
        let name = format!("AES-{key_bits}-WRAP");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "AES Key Wrap (RFC 3394)",
        });
    }

    // AES Key Wrap with Padding (RFC 5649)
    for key_bits in &key_sizes {
        let name = format!("AES-{key_bits}-WRAP-PAD");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "AES Key Wrap with Padding (RFC 5649)",
        });
    }

    // Inverse variants for compatibility
    for key_bits in &key_sizes {
        let name = format!("AES-{key_bits}-WRAP-INV");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "AES Key Wrap inverse (RFC 3394)",
        });
    }

    for key_bits in &key_sizes {
        let name = format!("AES-{key_bits}-WRAP-PAD-INV");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "AES Key Wrap with Padding inverse (RFC 5649)",
        });
    }

    descs
}
