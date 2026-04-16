//! Legacy cipher implementations: Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5.
//!
//! These ciphers are deprecated and maintained solely for backward compatibility.
//! They are only available through the legacy provider.
//! Translates C `cipher_blowfish.c`, `cipher_cast5.c`, `cipher_idea.c`,
//! `cipher_seed.c`, `cipher_rc2.c`, `cipher_rc4.c`, `cipher_rc5.c` (16+ source files).

use crate::traits::AlgorithmDescriptor;

/// Blowfish block cipher (legacy, variable key 32–448 bits).
#[derive(Debug, Clone)]
pub struct BlowfishCipher {
    /// Cipher mode.
    _mode: &'static str,
}

/// CAST5 (CAST-128) block cipher (legacy, variable key 40–128 bits).
#[derive(Debug, Clone)]
pub struct Cast5Cipher {
    /// Cipher mode.
    _mode: &'static str,
}

/// IDEA block cipher (legacy, 128-bit key).
#[derive(Debug, Clone)]
pub struct IdeaCipher {
    /// Cipher mode.
    _mode: &'static str,
}

/// SEED block cipher (legacy, Korean standard, 128-bit key).
#[derive(Debug, Clone)]
pub struct SeedCipher {
    /// Cipher mode.
    _mode: &'static str,
}

/// RC2 block cipher (legacy, variable key).
#[derive(Debug, Clone)]
pub struct Rc2Cipher {
    /// Cipher mode.
    _mode: &'static str,
    /// Effective key bits.
    _effective_key_bits: usize,
}

/// RC4 stream cipher (legacy, variable key).
#[derive(Debug, Clone)]
pub struct Rc4Cipher {
    /// Key length in bytes.
    _key_len: usize,
}

/// RC5 block cipher (legacy, variable key/rounds/block).
#[derive(Debug, Clone)]
pub struct Rc5Cipher {
    /// Cipher mode.
    _mode: &'static str,
}

impl BlowfishCipher {
    /// Creates a new Blowfish cipher.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

impl Cast5Cipher {
    /// Creates a new CAST5 cipher.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

impl IdeaCipher {
    /// Creates a new IDEA cipher.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

impl SeedCipher {
    /// Creates a new SEED cipher.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

impl Rc2Cipher {
    /// Creates a new RC2 cipher.
    #[must_use]
    pub fn new(mode: &'static str, effective_key_bits: usize) -> Self {
        Self { _mode: mode, _effective_key_bits: effective_key_bits }
    }
}

impl Rc4Cipher {
    /// Creates a new RC4 cipher.
    #[must_use]
    pub fn new(key_len: usize) -> Self {
        Self { _key_len: key_len }
    }
}

impl Rc5Cipher {
    /// Creates a new RC5 cipher.
    #[must_use]
    pub fn new(mode: &'static str) -> Self {
        Self { _mode: mode }
    }
}

/// Returns algorithm descriptors for all legacy ciphers.
///
/// These are only exposed via `LegacyProvider::query_operation`.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();
    let block_modes = ["ECB", "CBC", "OFB", "CFB"];

    // Blowfish (BF) — variable key 32–448 bits, 64-bit block
    for mode in &block_modes {
        let name = format!("BF-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "Blowfish block cipher (legacy)",
        });
    }

    // CAST5 (CAST-128) — variable key 40–128 bits, 64-bit block
    for mode in &block_modes {
        let name = format!("CAST5-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "CAST5 (CAST-128) block cipher (legacy)",
        });
    }

    // IDEA — 128-bit key, 64-bit block
    for mode in &block_modes {
        let name = format!("IDEA-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "IDEA block cipher (legacy)",
        });
    }

    // SEED — 128-bit key, 128-bit block (Korean standard)
    for mode in &block_modes {
        let name = format!("SEED-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "SEED block cipher (legacy, Korean standard)",
        });
    }

    // RC2 — variable key, 64-bit block
    for mode in &block_modes {
        let name = format!("RC2-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "RC2 block cipher (legacy)",
        });
    }

    // RC2 with explicit effective key bits
    descs.push(AlgorithmDescriptor {
        names: vec!["RC2-40-CBC"],
        property: "provider=legacy",
        description: "RC2-40 CBC (legacy, export-grade)",
    });
    descs.push(AlgorithmDescriptor {
        names: vec!["RC2-64-CBC"],
        property: "provider=legacy",
        description: "RC2-64 CBC (legacy)",
    });

    // RC4 stream cipher
    descs.push(AlgorithmDescriptor {
        names: vec!["RC4"],
        property: "provider=legacy",
        description: "RC4 stream cipher (legacy, insecure)",
    });
    descs.push(AlgorithmDescriptor {
        names: vec!["RC4-40"],
        property: "provider=legacy",
        description: "RC4-40 stream cipher (legacy, export-grade)",
    });
    descs.push(AlgorithmDescriptor {
        names: vec!["RC4-HMAC-MD5"],
        property: "provider=legacy",
        description: "RC4-HMAC-MD5 composite (legacy, TLS)",
    });

    // RC5 — variable key/rounds/block
    for mode in &block_modes {
        let name = format!("RC5-{mode}");
        let leaked: &'static str = Box::leak(name.into_boxed_str());
        descs.push(AlgorithmDescriptor {
            names: vec![leaked],
            property: "provider=legacy",
            description: "RC5 block cipher (legacy)",
        });
    }

    descs
}
