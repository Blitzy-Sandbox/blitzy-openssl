//! DES, Triple-DES (3DES/TDES), DESX, and TDES Key Wrap ciphers.
//!
//! Legacy block ciphers maintained for backward compatibility.
//! DES uses 64-bit key (56 effective), 3DES uses 128/192-bit keys.
//! Translates C `cipher_des.c` + `cipher_tdes*.c` (11 source files).

use crate::traits::AlgorithmDescriptor;

/// Single DES block cipher (legacy, insecure).
#[derive(Debug, Clone)]
pub struct DesCipher {
    /// Cipher mode (ECB, CBC, OFB, CFB).
    _mode: &'static str,
}

/// Triple-DES (3DES / TDES) block cipher.
///
/// Applies DES three times with two or three independent keys.
/// Supports EDE2 (2-key, 128-bit) and EDE3 (3-key, 192-bit) variants.
#[derive(Debug, Clone)]
pub struct TdesCipher {
    /// Number of keys: 2 (EDE2) or 3 (EDE3).
    _num_keys: u8,
    /// Cipher mode (ECB, CBC, OFB, CFB).
    _mode: &'static str,
}

/// DESX cipher (DES with XOR whitening, legacy).
#[derive(Debug, Clone)]
pub struct DesxCipher;

/// Triple-DES Key Wrap cipher (RFC 3217).
#[derive(Debug, Clone)]
pub struct TdesWrapCipher;

impl DesCipher {
    /// Creates a new DES cipher for the specified mode.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

impl TdesCipher {
    /// Creates a new Triple-DES cipher.
    #[must_use]
    pub fn new(num_keys: u8, mode: &'static str) -> Self {
        Self { _num_keys: num_keys, _mode: mode }
    }
}

/// Returns algorithm descriptors for DES / 3DES family ciphers.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();

    // Single DES modes (legacy, insecure)
    let des_modes = ["ECB", "CBC", "OFB", "CFB", "CFB1", "CFB8"];
    for mode in &des_modes {
        let name = format!("DES-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "DES block cipher (legacy, insecure)",
        });
    }

    // Triple-DES EDE3 modes
    let tdes_modes = ["ECB", "CBC", "OFB", "CFB", "CFB1", "CFB8"];
    for mode in &tdes_modes {
        let name = format!("DES-EDE3-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=default",
            description: "Triple-DES EDE3 (3-key, 192-bit)",
        });
    }

    // Triple-DES EDE (2-key) CBC
    descs.push(AlgorithmDescriptor {
        names: vec!["DES-EDE-CBC"],
        property: "provider=default",
        description: "Triple-DES EDE (2-key, 128-bit) CBC",
    });

    descs.push(AlgorithmDescriptor {
        names: vec!["DES-EDE-ECB"],
        property: "provider=default",
        description: "Triple-DES EDE (2-key, 128-bit) ECB",
    });

    // DESX
    descs.push(AlgorithmDescriptor {
        names: vec!["DESX-CBC"],
        property: "provider=default",
        description: "DESX (DES with XOR whitening) CBC mode",
    });

    // Triple-DES Key Wrap (RFC 3217)
    descs.push(AlgorithmDescriptor {
        names: vec!["DES-EDE3-WRAP"],
        property: "provider=default",
        description: "Triple-DES Key Wrap (RFC 3217)",
    });

    descs
}
