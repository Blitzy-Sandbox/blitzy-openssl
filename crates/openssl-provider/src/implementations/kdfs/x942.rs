//! X9.42 KDF — Key Derivation Function per ANSI X9.42.
//!
//! Used primarily for DH key agreement. The KDF takes a shared secret Z and
//! optional key-derivation data, producing key material using a hash function.
//!
//! `K(i) = H(Z || counter || otherinfo)`
//!
//! Translation of `providers/implementations/kdfs/x942kdf.c`.
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for optional parameters
//! - **R6:** Checked arithmetic
//! - **R8:** Zero `unsafe` blocks
//! - **R9:** Warning-free

use crate::implementations::algorithm;
use crate::traits::{AlgorithmDescriptor, KdfContext, KdfProvider};
use openssl_common::error::ProviderError;
use openssl_common::param::{ParamBuilder, ParamSet};
use openssl_common::ProviderResult;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_KEY` — shared secret (Z).
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_UKM` — user keying material / other info.
const PARAM_UKM: &str = "ukm";
/// `OSSL_KDF_PARAM_CEK_ALG` — target CEK algorithm OID.
const PARAM_CEK_ALG: &str = "cekalg";

// =============================================================================
// Context
// =============================================================================

/// X9.42 KDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct X942Context {
    /// Shared secret Z.
    secret: Vec<u8>,
    /// User keying material (other info).
    #[zeroize(skip)]
    ukm: Vec<u8>,
    /// Target algorithm identifier.
    #[zeroize(skip)]
    cek_alg: String,
}

impl X942Context {
    fn new() -> Self {
        Self {
            secret: Vec::new(),
            ukm: Vec::new(),
            cek_alg: String::new(),
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_KEY) {
            self.secret = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("X942: key must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_UKM) {
            self.ukm = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("X942: ukm must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_CEK_ALG) {
            self.cek_alg = v
                .as_str()
                .ok_or_else(|| ProviderError::Init("X942: cekalg must be string".into()))?
                .to_string();
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.secret.is_empty() {
            return Err(ProviderError::Init("X942: shared secret must be set".into()));
        }
        Ok(())
    }

    /// X9.42 KDF derivation.
    ///
    /// For each counter value `i` from 1:
    ///
    /// `K(i) = SHA-256(Z || counter_be32 || OtherInfo)`
    ///
    /// Where `OtherInfo` is a DER-encoded structure containing the algorithm
    /// OID and optional UKM. In this simplified implementation we concatenate
    /// the raw UKM.
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize; // SHA-256
        let out_len = output.len();
        let reps = (out_len + h_len - 1) / h_len;
        let mut pos = 0;

        for counter in 1..=reps {
            let c = u32::try_from(counter)
                .map_err(|_| ProviderError::Init("X942: counter overflow".into()))?;
            let mut hasher = Sha256::new();
            hasher.update(&self.secret);
            hasher.update(c.to_be_bytes());
            // OtherInfo: algorithm OID encoding (simplified) + UKM
            if !self.cek_alg.is_empty() {
                hasher.update(self.cek_alg.as_bytes());
            }
            if !self.ukm.is_empty() {
                hasher.update(&self.ukm);
            }
            let digest = hasher.finalize();

            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&digest[..copy_len]);
            pos += copy_len;
        }
        Ok(out_len)
    }
}

impl KdfContext for X942Context {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        self.derive_internal(key)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.secret.zeroize();
        self.secret.clear();
        self.ukm.clear();
        self.cek_alg.clear();
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut builder = ParamBuilder::new();
        if !self.cek_alg.is_empty() {
            builder = builder.push_utf8(PARAM_CEK_ALG, self.cek_alg.clone());
        }
        Ok(builder.build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// X9.42 KDF provider.
pub struct X942KdfProvider;

impl KdfProvider for X942KdfProvider {
    fn name(&self) -> &'static str {
        "X942KDF-ASN1"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(X942Context::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for X9.42 KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["X942KDF-ASN1", "X942KDF"],
        "provider=default",
        "X9.42 key derivation function for DH key agreement",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(key: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps
    }

    #[test]
    fn test_x942_basic() {
        let provider = X942KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"shared_secret_dh_value");
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_x942_with_ukm() {
        let provider = X942KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = make_params(b"secret");
        ps.set(PARAM_UKM, ParamValue::OctetString(b"user_keying".to_vec()));
        ps.set(
            PARAM_CEK_ALG,
            ParamValue::Utf8String("2.16.840.1.101.3.4.1.5".to_string()),
        );
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
    }

    #[test]
    fn test_x942_deterministic() {
        let provider = X942KdfProvider;
        let ps = make_params(b"deterministic_key");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 32];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 32];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_x942_missing_key() {
        let provider = X942KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_x942_reset() {
        let provider = X942KdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key");
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
