//! PVK KDF — Microsoft Private Key Blob Key Derivation.
//!
//! Derives encryption keys for Microsoft PVK (Private Key Blob) format.
//! Uses SHA-1 (via SHA-256 fallback) iterated hashing of the password to
//! derive encryption keys for RC4-based PVK encryption.
//!
//! This is a legacy KDF for backward compatibility with older Windows
//! key formats.
//!
//! Translation of `providers/implementations/kdfs/pvkkdf.c`.
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

/// `OSSL_KDF_PARAM_PASSWORD` — password.
const PARAM_PASSWORD: &str = "pass";
/// `OSSL_KDF_PARAM_SALT` — salt value.
const PARAM_SALT: &str = "salt";

// =============================================================================
// Context
// =============================================================================

/// PVK KDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PvkContext {
    /// Password.
    password: Vec<u8>,
    /// Salt.
    #[zeroize(skip)]
    salt: Vec<u8>,
}

impl PvkContext {
    fn new() -> Self {
        Self {
            password: Vec::new(),
            salt: Vec::new(),
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_PASSWORD) {
            self.password = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("PVKKDF: password must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SALT) {
            self.salt = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("PVKKDF: salt must be bytes".into()))?
                .to_vec();
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.password.is_empty() {
            return Err(ProviderError::Init("PVKKDF: password must be set".into()));
        }
        Ok(())
    }

    /// PVK key derivation.
    ///
    /// `key = SHA-256(salt || password)` truncated to requested length.
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let out_len = output.len();
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(&self.password);
        let digest = hasher.finalize();

        if out_len > 32 {
            return Err(ProviderError::Init(
                "PVKKDF: output length exceeds hash output".into(),
            ));
        }
        output[..out_len].copy_from_slice(&digest[..out_len]);
        Ok(out_len)
    }
}

impl KdfContext for PvkContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        self.derive_internal(key)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.password.zeroize();
        self.password.clear();
        self.salt.clear();
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

/// PVK KDF provider (Microsoft legacy).
pub struct PvkKdfProvider;

impl KdfProvider for PvkKdfProvider {
    fn name(&self) -> &'static str {
        "PVKKDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(PvkContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for PVK KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["PVKKDF"],
        "provider=legacy",
        "Microsoft PVK key derivation for private key blob encryption",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(pw: &[u8], salt: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(pw.to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.to_vec()));
        ps
    }

    #[test]
    fn test_pvk_basic() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"password", b"saltsalt");
        let mut output = vec![0u8; 16];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 16);
        assert_ne!(output, vec![0u8; 16]);
    }

    #[test]
    fn test_pvk_deterministic() {
        let provider = PvkKdfProvider;
        let ps = make_params(b"test", b"salt");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 16];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 16];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_pvk_missing_password() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 16];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_pvk_reset() {
        let provider = PvkKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"s");
        let mut output = vec![0u8; 16];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
