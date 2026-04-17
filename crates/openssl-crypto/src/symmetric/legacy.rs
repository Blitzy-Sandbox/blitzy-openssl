//! Legacy symmetric ciphers — stub for compilation.
//!
//! Provides: Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5, Camellia, ARIA, SM4.
//! Full implementations provided by the assigned agent for `legacy.rs`.

use openssl_common::CryptoResult;
use zeroize::Zeroize;

use super::{BlockSize, CipherAlgorithm, StreamCipher, SymmetricCipher};

// =============================================================================
// Helper: Validate Block Length
// =============================================================================

/// Validate that a block slice has the expected length.
fn check_block(block: &[u8], expected: usize, name: &str) -> CryptoResult<()> {
    if block.len() != expected {
        return Err(openssl_common::CryptoError::Common(
            openssl_common::CommonError::InvalidArgument(format!(
                "{name} requires {expected}-byte block, got {}",
                block.len()
            )),
        ));
    }
    Ok(())
}

// =============================================================================
// Blowfish — 64-bit block, up to 448-bit key
// =============================================================================

/// Blowfish block cipher (up to 448-bit key, 64-bit block).
#[derive(Debug, Clone)]
pub struct Blowfish {
    /// Key material.
    key: Vec<u8>,
}

impl Blowfish {
    /// Create a new Blowfish cipher with the given key (4–56 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() < 4 || key.len() > 56 {
            return Err(openssl_common::CryptoError::Key(
                "Blowfish key must be 4–56 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl SymmetricCipher for Blowfish {
    fn block_size(&self) -> BlockSize { BlockSize::Block64 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "Blowfish")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Blowfish }
}

impl Drop for Blowfish {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Cast5 — 64-bit block, 40–128-bit key
// =============================================================================

/// CAST-128 / CAST5 block cipher (40–128-bit key, 64-bit block).
#[derive(Debug, Clone)]
pub struct Cast5 {
    /// Key material.
    key: Vec<u8>,
}

impl Cast5 {
    /// Create a new CAST5 cipher with the given key (5–16 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() < 5 || key.len() > 16 {
            return Err(openssl_common::CryptoError::Key(
                "CAST5 key must be 5–16 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl SymmetricCipher for Cast5 {
    fn block_size(&self) -> BlockSize { BlockSize::Block64 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "CAST5")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Cast5 }
}

impl Drop for Cast5 {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Idea — 64-bit block, 128-bit key
// =============================================================================

/// IDEA block cipher (128-bit key, 64-bit block).
#[derive(Debug, Clone)]
pub struct Idea {
    /// Key material (16 bytes).
    key: [u8; 16],
}

impl Idea {
    /// Create a new IDEA cipher from a 16-byte key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(openssl_common::CryptoError::Key(
                "IDEA requires a 16-byte key".into(),
            ));
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl SymmetricCipher for Idea {
    fn block_size(&self) -> BlockSize { BlockSize::Block64 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "IDEA")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Idea }
}

impl Drop for Idea {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Seed — 128-bit block, 128-bit key
// =============================================================================

/// SEED block cipher (128-bit key, 128-bit block).
#[derive(Debug, Clone)]
pub struct Seed {
    /// Key material (16 bytes).
    key: [u8; 16],
}

impl Seed {
    /// Create a new SEED cipher from a 16-byte key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(openssl_common::CryptoError::Key(
                "SEED requires a 16-byte key".into(),
            ));
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl SymmetricCipher for Seed {
    fn block_size(&self) -> BlockSize { BlockSize::Block128 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 16, "SEED")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Seed }
}

impl Drop for Seed {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Rc2 — 64-bit block, 8–1024-bit key
// =============================================================================

/// RC2 block cipher (8–1024-bit key, 64-bit block).
#[derive(Debug, Clone)]
pub struct Rc2 {
    /// Key material.
    key: Vec<u8>,
}

impl Rc2 {
    /// Create a new RC2 cipher with the given key (1–128 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.is_empty() || key.len() > 128 {
            return Err(openssl_common::CryptoError::Key(
                "RC2 key must be 1–128 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl SymmetricCipher for Rc2 {
    fn block_size(&self) -> BlockSize { BlockSize::Block64 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "RC2")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Rc2 }
}

impl Drop for Rc2 {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Rc4 — Stream Cipher (40–2048-bit key)
// =============================================================================

/// RC4 stream cipher (40–2048-bit key).
///
/// **⚠ BROKEN:** RC4 has known biases and is prohibited in TLS 1.3.
/// Provided for legacy compatibility only.
#[derive(Debug, Clone)]
pub struct Rc4 {
    /// S-box permutation state.
    state: [u8; 256],
    /// Index i.
    i: u8,
    /// Index j.
    j: u8,
}

impl Rc4 {
    /// Create a new RC4 cipher from the given key (5–256 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() < 5 || key.len() > 256 {
            return Err(openssl_common::CryptoError::Key(
                "RC4 key must be 5–256 bytes".into(),
            ));
        }
        // KSA: Key-Scheduling Algorithm
        let mut state = [0u8; 256];
        for (idx, s) in state.iter_mut().enumerate() {
            *s = idx as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }
        Ok(Self { state, i: 0, j: 0 })
    }
}

impl StreamCipher for Rc4 {
    fn process(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        // PRGA: Pseudo-Random Generation Algorithm
        let mut output = Vec::with_capacity(data.len());
        for &byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let k = self.state[usize::from(
                self.state[usize::from(self.i)]
                    .wrapping_add(self.state[usize::from(self.j)]),
            )];
            output.push(byte ^ k);
        }
        Ok(output)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Rc4
    }
}

impl Drop for Rc4 {
    fn drop(&mut self) { self.state.zeroize(); }
}

// =============================================================================
// Rc5 — 64-bit block, variable rounds
// =============================================================================

/// RC5-32/12/16 block cipher (variable key length, 64-bit block).
#[derive(Debug, Clone)]
pub struct Rc5 {
    /// Key material.
    key: Vec<u8>,
}

impl Rc5 {
    /// Create a new RC5 cipher with the given key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.is_empty() || key.len() > 255 {
            return Err(openssl_common::CryptoError::Key(
                "RC5 key must be 1–255 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl SymmetricCipher for Rc5 {
    fn block_size(&self) -> BlockSize { BlockSize::Block64 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 8, "RC5")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Rc5 }
}

impl Drop for Rc5 {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Camellia — 128-bit block, 128/192/256-bit key
// =============================================================================

/// Camellia block cipher (128/192/256-bit key, 128-bit block).
#[derive(Debug, Clone)]
pub struct Camellia {
    /// Key material.
    key: Vec<u8>,
}

impl Camellia {
    /// Create a new Camellia cipher with the given key (16, 24, or 32 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(openssl_common::CryptoError::Key(
                "Camellia key must be 16, 24, or 32 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl SymmetricCipher for Camellia {
    fn block_size(&self) -> BlockSize { BlockSize::Block128 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 16, "Camellia")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm {
        match self.key.len() {
            16 => CipherAlgorithm::Camellia128,
            24 => CipherAlgorithm::Camellia192,
            _ => CipherAlgorithm::Camellia256,
        }
    }
}

impl Drop for Camellia {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Aria — 128-bit block, 128/192/256-bit key
// =============================================================================

/// ARIA block cipher (128/192/256-bit key, 128-bit block).
#[derive(Debug, Clone)]
pub struct Aria {
    /// Key material.
    key: Vec<u8>,
}

impl Aria {
    /// Create a new ARIA cipher with the given key (16, 24, or 32 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(openssl_common::CryptoError::Key(
                "ARIA key must be 16, 24, or 32 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl SymmetricCipher for Aria {
    fn block_size(&self) -> BlockSize { BlockSize::Block128 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 16, "ARIA")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm {
        match self.key.len() {
            16 => CipherAlgorithm::Aria128,
            24 => CipherAlgorithm::Aria192,
            _ => CipherAlgorithm::Aria256,
        }
    }
}

impl Drop for Aria {
    fn drop(&mut self) { self.key.zeroize(); }
}

// =============================================================================
// Sm4 — 128-bit block, 128-bit key (Chinese national standard)
// =============================================================================

/// SM4 block cipher (128-bit key, 128-bit block) — Chinese national standard.
#[derive(Debug, Clone)]
pub struct Sm4 {
    /// Key material (16 bytes).
    key: [u8; 16],
}

impl Sm4 {
    /// Create a new SM4 cipher from a 16-byte key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(openssl_common::CryptoError::Key(
                "SM4 requires a 16-byte key".into(),
            ));
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl SymmetricCipher for Sm4 {
    fn block_size(&self) -> BlockSize { BlockSize::Block128 }
    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        check_block(block, 16, "SM4")?;
        for (b, k) in block.iter_mut().zip(self.key.iter().cycle()) { *b ^= k; }
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> { self.encrypt_block(block) }
    fn algorithm(&self) -> CipherAlgorithm { CipherAlgorithm::Sm4 }
}

impl Drop for Sm4 {
    fn drop(&mut self) { self.key.zeroize(); }
}
