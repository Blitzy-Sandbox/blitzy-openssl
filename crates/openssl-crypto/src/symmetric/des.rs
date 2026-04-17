//! DES and Triple-DES (3DES-EDE) block ciphers — stub for compilation.
//!
//! Full implementation provided by the assigned agent for `des.rs`.
//! Translates `crypto/des/des_enc.c`.

use openssl_common::CryptoResult;
use zeroize::Zeroize;

use super::{BlockSize, CipherAlgorithm, SymmetricCipher};

// =============================================================================
// DesKeySchedule — Expanded DES Key Schedule
// =============================================================================

/// DES key schedule (expanded round keys).
///
/// Holds 16 round subkeys derived from the 64-bit (56-bit effective) DES key.
#[derive(Debug, Clone)]
pub struct DesKeySchedule {
    /// 16 round subkeys (48 bits each, stored in 6-byte arrays).
    round_keys: [[u8; 8]; 16],
}

impl DesKeySchedule {
    /// Create a new key schedule from a raw 8-byte DES key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 8 {
            return Err(openssl_common::CryptoError::Key(
                "DES key must be exactly 8 bytes".into(),
            ));
        }
        let mut round_keys = [[0u8; 8]; 16];
        // Minimal key schedule: XOR key with round index.
        // Full Feistel key expansion to be provided by the des.rs agent.
        for (i, rk) in round_keys.iter_mut().enumerate() {
            for (j, b) in rk.iter_mut().enumerate() {
                // i is 0..16 which always fits in u8; using saturating conversion
                // to satisfy clippy::cast_possible_truncation.
                *b = key[j] ^ u8::try_from(i).unwrap_or(0);
            }
        }
        Ok(Self { round_keys })
    }
}

impl Drop for DesKeySchedule {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            rk.zeroize();
        }
    }
}

// =============================================================================
// Des — Single DES (BROKEN — legacy only)
// =============================================================================

/// Single DES block cipher (56-bit effective key, 64-bit block).
///
/// **⚠ BROKEN:** DES is vulnerable to brute-force attacks due to its 56-bit
/// key space. Provided for legacy compatibility only. Use AES instead.
#[derive(Debug, Clone)]
pub struct Des {
    /// Key schedule.
    schedule: DesKeySchedule,
}

impl Des {
    /// Create a new DES cipher from an 8-byte key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            schedule: DesKeySchedule::new(key)?,
        })
    }
}

impl SymmetricCipher for Des {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        if block.len() != 8 {
            return Err(openssl_common::CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "DES encrypt_block requires 8-byte block".into(),
                ),
            ));
        }
        // Minimal: XOR with first round key.
        for (b, k) in block.iter_mut().zip(self.schedule.round_keys[0].iter()) {
            *b ^= k;
        }
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        // For XOR "cipher", encrypt and decrypt are the same.
        self.encrypt_block(block)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Des
    }
}

// =============================================================================
// TripleDes — 3DES-EDE (Triple-DES)
// =============================================================================

/// Triple-DES EDE block cipher (112/168-bit effective key, 64-bit block).
///
/// Applies DES Encrypt-Decrypt-Encrypt with two or three independent keys.
#[derive(Debug, Clone)]
pub struct TripleDes {
    /// Three DES key schedules for EDE operation.
    schedules: [DesKeySchedule; 3],
}

impl TripleDes {
    /// Create a new 3DES cipher from a 24-byte key (three 8-byte DES keys).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 24 {
            return Err(openssl_common::CryptoError::Key(
                "Triple-DES requires a 24-byte key (three 8-byte DES keys)".into(),
            ));
        }
        let k1 = DesKeySchedule::new(&key[..8])?;
        let k2 = DesKeySchedule::new(&key[8..16])?;
        let k3 = DesKeySchedule::new(&key[16..24])?;
        Ok(Self {
            schedules: [k1, k2, k3],
        })
    }
}

impl SymmetricCipher for TripleDes {
    fn block_size(&self) -> BlockSize {
        BlockSize::Block64
    }

    fn encrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        if block.len() != 8 {
            return Err(openssl_common::CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "Triple-DES encrypt_block requires 8-byte block".into(),
                ),
            ));
        }
        // EDE: encrypt with K1, "decrypt" with K2, encrypt with K3.
        for (b, k) in block.iter_mut().zip(self.schedules[0].round_keys[0].iter()) {
            *b ^= k;
        }
        for (b, k) in block.iter_mut().zip(self.schedules[1].round_keys[0].iter()) {
            *b ^= k;
        }
        for (b, k) in block.iter_mut().zip(self.schedules[2].round_keys[0].iter()) {
            *b ^= k;
        }
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> CryptoResult<()> {
        // For XOR "cipher", same operation.
        self.encrypt_block(block)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::TripleDes
    }
}
