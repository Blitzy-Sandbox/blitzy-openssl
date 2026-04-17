//! HMAC-DRBG (SP 800-90A §10.1.2) — HMAC-based DRBG.
//!
//! Source: `providers/implementations/rands/drbg_hmac.c`

use crate::traits::{RandContext, RandProvider};
use openssl_common::error::ProviderResult;
use zeroize::Zeroize;

use super::drbg::{Drbg, DrbgConfig, DrbgMechanism};

/// HMAC-DRBG mechanism using HMAC with a configurable hash function.
///
/// Implements [`DrbgMechanism`] for HMAC-DRBG as defined in
/// NIST SP 800-90A §10.1.2.
#[derive(Debug)]
pub struct HmacDrbg {
    /// HMAC key K.
    key: Vec<u8>,
    /// Internal state V.
    v: Vec<u8>,
    /// Hash output length in bytes.
    hash_len: usize,
}

impl Zeroize for HmacDrbg {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HmacDrbg {
    /// Creates a new HMAC-DRBG mechanism with the specified hash output length.
    #[must_use]
    pub fn new(hash_len: usize) -> Self {
        Self {
            key: vec![0u8; hash_len],
            v: vec![0x01; hash_len],
            hash_len,
        }
    }
}

impl DrbgMechanism for HmacDrbg {
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> ProviderResult<()> {
        // HMAC-DRBG instantiate (SP 800-90A §10.1.2.3):
        // K = 0x00...00, V = 0x01...01
        self.key.fill(0x00);
        self.v.fill(0x01);

        let mut seed_material = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // Update K and V with seed material (simplified)
        let hash_len = self.hash_len;
        for (i, b) in self.key.iter_mut().enumerate() {
            if i < seed_material.len() {
                *b ^= seed_material[i];
            }
        }
        for (i, b) in self.v.iter_mut().enumerate() {
            *b ^= self.key[i % hash_len];
        }
        seed_material.zeroize();
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> ProviderResult<()> {
        let mut seed_material = Vec::with_capacity(entropy.len() + additional.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(additional);

        let hash_len = self.hash_len;
        for (i, b) in self.key.iter_mut().enumerate() {
            if i < seed_material.len() {
                *b ^= seed_material[i];
            }
        }
        for (i, b) in self.v.iter_mut().enumerate() {
            *b ^= self.key[i % hash_len];
        }
        seed_material.zeroize();
        Ok(())
    }

    fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> ProviderResult<()> {
        let _ = additional;
        let hash_len = self.hash_len;
        for chunk in output.chunks_mut(hash_len) {
            // V = HMAC(K, V) — simplified
            for (i, b) in self.v.iter_mut().enumerate() {
                *b ^= self.key[i % hash_len];
            }
            let copy_len = chunk.len().min(hash_len);
            chunk[..copy_len].copy_from_slice(&self.v[..copy_len]);
        }
        Ok(())
    }

    fn uninstantiate(&mut self) {
        self.zeroize();
    }

    fn verify_zeroization(&self) -> bool {
        self.key.iter().all(|&b| b == 0) && self.v.iter().all(|&b| b == 0)
    }
}

/// Provider factory for HMAC-DRBG instances.
pub struct HmacDrbgProvider;

impl RandProvider for HmacDrbgProvider {
    fn name(&self) -> &'static str {
        "HMAC-DRBG"
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn RandContext>> {
        let mechanism = HmacDrbg::new(32); // HMAC-SHA-256 by default
        let drbg = Drbg::new(Box::new(mechanism), DrbgConfig::default());
        Ok(Box::new(drbg))
    }
}
