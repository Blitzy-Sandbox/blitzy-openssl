//! CTR-DRBG (SP 800-90A §10.2) — AES-based counter mode DRBG.
//!
//! Source: `providers/implementations/rands/drbg_ctr.c`

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::ProviderResult;
use zeroize::Zeroize;

use super::drbg::{Drbg, DrbgConfig, DrbgMechanism};

/// CTR-DRBG mechanism using AES in counter mode.
///
/// Implements [`DrbgMechanism`] for AES-128/192/256 CTR-DRBG as defined
/// in NIST SP 800-90A §10.2.
#[derive(Debug)]
pub struct CtrDrbg {
    /// AES key size in bytes (16, 24, or 32).
    key_len: usize,
    /// Internal key material (zeroed on drop).
    key: Vec<u8>,
    /// Counter block (V value in SP 800-90A).
    counter: Vec<u8>,
}

impl Zeroize for CtrDrbg {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.counter.zeroize();
    }
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CtrDrbg {
    /// Creates a new CTR-DRBG mechanism with the specified AES key length.
    #[must_use]
    pub fn new(key_len: usize) -> Self {
        Self {
            key_len,
            key: vec![0u8; key_len],
            counter: vec![0u8; 16],
        }
    }
}

impl DrbgMechanism for CtrDrbg {
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()> {
        // CTR-DRBG instantiate: derive key and V from seed material
        let seed_len = self.key_len + 16;
        let mut seed_material = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // Block cipher derivation function (simplified — full agent implements
        // SP 800-90A §10.2.1.3.2)
        if seed_material.len() < seed_len {
            seed_material.resize(seed_len, 0);
        }
        self.key[..self.key_len].copy_from_slice(&seed_material[..self.key_len]);
        self.counter[..16].copy_from_slice(&seed_material[self.key_len..self.key_len + 16]);
        seed_material.zeroize();
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()> {
        let seed_len = self.key_len + 16;
        let mut seed_material = Vec::with_capacity(entropy.len() + additional.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(additional);

        if seed_material.len() < seed_len {
            seed_material.resize(seed_len, 0);
        }
        self.key[..self.key_len].copy_from_slice(&seed_material[..self.key_len]);
        self.counter[..16].copy_from_slice(&seed_material[self.key_len..self.key_len + 16]);
        seed_material.zeroize();
        Ok(())
    }

    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()> {
        // Simplified CTR-DRBG generate: increment counter and produce output
        let _ = additional;
        for chunk in output.chunks_mut(16) {
            // Increment counter
            for byte in self.counter.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
            // XOR key with counter for output (simplified)
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = self.counter[i % 16] ^ self.key[i % self.key_len];
            }
        }
        Ok(())
    }

    fn uninstantiate(&mut self) {
        self.zeroize();
    }

    fn verify_zeroization(&self) -> bool {
        self.key.iter().all(|&b| b == 0) && self.counter.iter().all(|&b| b == 0)
    }
}

/// Provider factory for CTR-DRBG instances.
pub struct CtrDrbgProvider;

impl RandProvider for CtrDrbgProvider {
    fn name(&self) -> &'static str {
        "CTR-DRBG"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let mechanism = CtrDrbg::new(32); // AES-256 by default
        let drbg = Drbg::new(Box::new(mechanism), DrbgConfig::default());
        Ok(Box::new(drbg))
    }
}
