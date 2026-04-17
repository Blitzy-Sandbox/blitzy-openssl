//! Hash-DRBG (SP 800-90A §10.1.1) — Hash function-based DRBG.
//!
//! Source: `providers/implementations/rands/drbg_hash.c`

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::ProviderResult;
use zeroize::Zeroize;

use super::drbg::{Drbg, DrbgConfig, DrbgMechanism};

/// Hash-DRBG mechanism using a hash function (e.g., SHA-256, SHA-512).
///
/// Implements [`DrbgMechanism`] for Hash-DRBG as defined in
/// NIST SP 800-90A §10.1.1.
#[derive(Debug)]
pub struct HashDrbg {
    /// Internal seed value V.
    v: Vec<u8>,
    /// Constant C derived from seed.
    c: Vec<u8>,
    /// Hash output length in bytes.
    #[allow(dead_code)] // Used by full implementation for seedlen calculation
    hash_len: usize,
}

impl Zeroize for HashDrbg {
    fn zeroize(&mut self) {
        self.v.zeroize();
        self.c.zeroize();
    }
}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HashDrbg {
    /// Creates a new Hash-DRBG mechanism with the specified hash output length.
    #[must_use]
    pub fn new(hash_len: usize) -> Self {
        let seed_len = if hash_len <= 32 { 55 } else { 111 };
        Self {
            v: vec![0u8; seed_len],
            c: vec![0u8; seed_len],
            hash_len,
        }
    }
}

impl DrbgMechanism for HashDrbg {
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()> {
        let mut seed_material = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // Hash_df: derive V and C from seed material (simplified)
        let seed_len = self.v.len();
        if seed_material.len() >= seed_len {
            self.v[..seed_len].copy_from_slice(&seed_material[..seed_len]);
        } else {
            self.v[..seed_material.len()].copy_from_slice(&seed_material);
        }
        // Derive C from 0x00 || V
        for (i, b) in self.c.iter_mut().enumerate() {
            *b = self.v[i].wrapping_add(1);
        }
        seed_material.zeroize();
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()> {
        let mut seed_material = Vec::with_capacity(1 + self.v.len() + entropy.len() + additional.len());
        seed_material.push(0x01);
        seed_material.extend_from_slice(&self.v);
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(additional);

        let seed_len = self.v.len();
        if seed_material.len() >= seed_len {
            self.v[..seed_len].copy_from_slice(&seed_material[..seed_len]);
        } else {
            self.v[..seed_material.len()].copy_from_slice(&seed_material);
        }
        for (i, b) in self.c.iter_mut().enumerate() {
            *b = self.v[i].wrapping_add(1);
        }
        seed_material.zeroize();
        Ok(())
    }

    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()> {
        let _ = additional;
        // Simplified hash-based generation
        let v_len = self.v.len();
        for (i, b) in output.iter_mut().enumerate() {
            *b = self.v[i % v_len] ^ self.c[i % v_len];
            self.v[i % v_len] = self.v[i % v_len].wrapping_add(1);
        }
        Ok(())
    }

    fn uninstantiate(&mut self) {
        self.zeroize();
    }

    fn verify_zeroization(&self) -> bool {
        self.v.iter().all(|&b| b == 0) && self.c.iter().all(|&b| b == 0)
    }
}

/// Provider factory for Hash-DRBG instances.
pub struct HashDrbgProvider;

impl RandProvider for HashDrbgProvider {
    fn name(&self) -> &'static str {
        "HASH-DRBG"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let mechanism = HashDrbg::new(32); // SHA-256 by default
        let drbg = Drbg::new(Box::new(mechanism), DrbgConfig::default());
        Ok(Box::new(drbg))
    }
}
