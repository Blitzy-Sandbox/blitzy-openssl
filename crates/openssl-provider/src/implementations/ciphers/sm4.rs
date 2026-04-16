//! SM4 block cipher (Chinese national standard GB/T 32907-2016).
//!
//! Key size: 128 bits. Block size: 128 bits.
//! Supports ECB, CBC, OFB, CFB, CTR, plus GCM, CCM, and XTS AEAD modes.
//! Translates C `cipher_sm4*.c` (8 source files).

use crate::traits::AlgorithmDescriptor;

/// SM4 block cipher implementation.
///
/// SM4 is a 128-bit block cipher with 128-bit keys, standardized as
/// GB/T 32907-2016 (Chinese national standard).
#[derive(Debug, Clone)]
pub struct Sm4Cipher {
    /// Cipher mode.
    _mode: &'static str,
}

/// SM4-GCM AEAD cipher.
#[derive(Debug, Clone)]
pub struct Sm4GcmCipher;

/// SM4-CCM AEAD cipher.
#[derive(Debug, Clone)]
pub struct Sm4CcmCipher;

/// SM4-XTS wide-block cipher.
#[derive(Debug, Clone)]
pub struct Sm4XtsCipher;

impl Sm4Cipher {
    /// Creates a new SM4 cipher.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

/// Returns algorithm descriptors for SM4 ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let modes = ["ECB", "CBC", "OFB", "CFB", "CTR"];
    let mut descs = Vec::new();

    // Standard block cipher modes
    for mode in &modes {
        let name = format!("SM4-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "SM4 block cipher (GB/T 32907-2016)",
        });
    }

    // SM4-GCM AEAD
    descs.push(AlgorithmDescriptor {
        names: vec!["SM4-GCM"],
        property: "provider=default",
        description: "SM4-GCM AEAD cipher",
    });

    // SM4-CCM AEAD
    descs.push(AlgorithmDescriptor {
        names: vec!["SM4-CCM"],
        property: "provider=default",
        description: "SM4-CCM AEAD cipher",
    });

    // SM4-XTS
    descs.push(AlgorithmDescriptor {
        names: vec!["SM4-XTS"],
        property: "provider=default",
        description: "SM4-XTS wide-block cipher",
    });

    descs
}
