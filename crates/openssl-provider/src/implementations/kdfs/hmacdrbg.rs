//! HMAC-DRBG KDF — Key derivation using HMAC-DRBG (NIST SP 800-90A).
//!
//! This KDF wraps the HMAC-DRBG mechanism to produce deterministic key
//! material from entropy and optional personalization data. It is primarily
//! used internally for deterministic random generation in test scenarios and
//! for nonce generation in ECDSA (RFC 6979).
//!
//! Translation of the HMAC-DRBG KDF functionality from OpenSSL providers.
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for optional parameters
//! - **R6:** Checked arithmetic
//! - **R8:** Zero `unsafe` blocks
//! - **R9:** Warning-free

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use hmac::{Hmac, Mac};
use openssl_common::error::ProviderError;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::ProviderResult;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_HMACDRBG_ENTROPY` — entropy input.
const PARAM_ENTROPY: &str = "entropy";
/// `OSSL_KDF_PARAM_HMACDRBG_NONCE` — nonce.
const PARAM_NONCE: &str = "nonce";

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Context
// =============================================================================

/// HMAC-DRBG KDF context implementing SP 800-90A §10.1.2.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct HmacDrbgKdfContext {
    /// Internal HMAC key (K).
    k: Vec<u8>,
    /// Internal chaining value (V).
    v: Vec<u8>,
    /// Whether the DRBG has been seeded.
    #[zeroize(skip)]
    seeded: bool,
}

impl HmacDrbgKdfContext {
    fn new() -> Self {
        let h_len = 32; // SHA-256
        Self {
            k: vec![0x00; h_len],
            v: vec![0x01; h_len],
            seeded: false,
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        let entropy = params
            .get(PARAM_ENTROPY)
            .and_then(|v| v.as_bytes())
            .map(<[u8]>::to_vec);
        let nonce = params
            .get(PARAM_NONCE)
            .and_then(|v| v.as_bytes())
            .map(<[u8]>::to_vec);

        if let Some(entropy_bytes) = entropy {
            let mut seed_material = entropy_bytes;
            if let Some(nonce_bytes) = nonce {
                seed_material.extend_from_slice(&nonce_bytes);
            }
            self.update(&seed_material)?;
            self.seeded = true;
        }
        Ok(())
    }

    /// HMAC-DRBG Update function (SP 800-90A §10.1.2.2).
    ///
    /// ```text
    /// K = HMAC(K, V || 0x00 || provided_data)
    /// V = HMAC(K, V)
    /// If provided_data is not empty:
    ///   K = HMAC(K, V || 0x01 || provided_data)
    ///   V = HMAC(K, V)
    /// ```
    fn update(&mut self, provided_data: &[u8]) -> ProviderResult<()> {
        // K = HMAC(K, V || 0x00 || provided_data)
        self.k = {
            let mut mac = HmacSha256::new_from_slice(&self.k)
                .map_err(|_| ProviderError::Init("HMAC-DRBG: key init failed".into()))?;
            mac.update(&self.v);
            mac.update(&[0x00]);
            mac.update(provided_data);
            mac.finalize().into_bytes().to_vec()
        };
        // V = HMAC(K, V)
        self.v = {
            let mut mac = HmacSha256::new_from_slice(&self.k)
                .map_err(|_| ProviderError::Init("HMAC-DRBG: key init failed".into()))?;
            mac.update(&self.v);
            mac.finalize().into_bytes().to_vec()
        };

        if !provided_data.is_empty() {
            // K = HMAC(K, V || 0x01 || provided_data)
            self.k = {
                let mut mac = HmacSha256::new_from_slice(&self.k)
                    .map_err(|_| ProviderError::Init("HMAC-DRBG: key init failed".into()))?;
                mac.update(&self.v);
                mac.update(&[0x01]);
                mac.update(provided_data);
                mac.finalize().into_bytes().to_vec()
            };
            // V = HMAC(K, V)
            self.v = {
                let mut mac = HmacSha256::new_from_slice(&self.k)
                    .map_err(|_| ProviderError::Init("HMAC-DRBG: key init failed".into()))?;
                mac.update(&self.v);
                mac.finalize().into_bytes().to_vec()
            };
        }
        Ok(())
    }

    /// Generate output bytes (SP 800-90A §10.1.2.5).
    fn generate(&mut self, output: &mut [u8]) -> ProviderResult<usize> {
        if !self.seeded {
            return Err(ProviderError::Init(
                "HMAC-DRBG: must be seeded before generating".into(),
            ));
        }
        let h_len = 32usize;
        let out_len = output.len();
        let mut pos = 0;

        while pos < out_len {
            // V = HMAC(K, V)
            self.v = {
                let mut mac = HmacSha256::new_from_slice(&self.k)
                    .map_err(|_| ProviderError::Init("HMAC-DRBG: key init failed".into()))?;
                mac.update(&self.v);
                mac.finalize().into_bytes().to_vec()
            };
            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&self.v[..copy_len]);
            pos += copy_len;
        }

        // Update with empty additional data
        self.update(&[])?;
        Ok(out_len)
    }
}

impl KdfContext for HmacDrbgKdfContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.generate(key)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        let h_len = 32;
        self.k.zeroize();
        self.k = vec![0x00; h_len];
        self.v = vec![0x01; h_len];
        self.seeded = false;
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new().build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// HMAC-DRBG KDF provider.
pub struct HmacDrbgKdfProvider;

impl KdfProvider for HmacDrbgKdfProvider {
    fn name(&self) -> &'static str {
        "HMAC-DRBG-KDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(HmacDrbgKdfContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for HMAC-DRBG KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["HMAC-DRBG-KDF"],
        "provider=default",
        "HMAC-DRBG based key derivation (NIST SP 800-90A)",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(entropy: &[u8], nonce: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_ENTROPY, ParamValue::OctetString(entropy.to_vec()));
        ps.set(PARAM_NONCE, ParamValue::OctetString(nonce.to_vec()));
        ps
    }

    #[test]
    fn test_hmacdrbg_basic() {
        let provider = HmacDrbgKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(&[0xAA; 32], &[0xBB; 16]);
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_hmacdrbg_deterministic() {
        let provider = HmacDrbgKdfProvider;
        let ps = make_params(&[0x11; 32], &[0x22; 16]);

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 64];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 64];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_hmacdrbg_unseeded() {
        let provider = HmacDrbgKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_hmacdrbg_reset() {
        let provider = HmacDrbgKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(&[0xFF; 32], &[0x00; 16]);
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
