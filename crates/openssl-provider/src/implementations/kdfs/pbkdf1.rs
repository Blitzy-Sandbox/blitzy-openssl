//! PBKDF1 — Password-Based Key Derivation Function version 1.
//!
//! Legacy KDF from PKCS#5 v1.5 (RFC 2898 §5.1). Superseded by PBKDF2 but
//! still required for backward compatibility with older PKCS#5 encrypted data.
//!
//! `DK = T_c` where `T_1 = Hash(P || S)`, `T_i = Hash(T_{i-1})`
//!
//! Translation of `providers/implementations/kdfs/pbkdf1.c`.
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
/// `OSSL_KDF_PARAM_SALT` — salt (must be 8 bytes).
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_ITER` — iteration count.
const PARAM_ITER: &str = "iter";

/// SHA-256 output length.
const HASH_LEN: usize = 32;

// =============================================================================
// Context
// =============================================================================

/// PBKDF1 derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Pbkdf1Context {
    /// Password.
    password: Vec<u8>,
    /// Salt (should be 8 bytes per PKCS#5 v1.5).
    #[zeroize(skip)]
    salt: Vec<u8>,
    /// Iteration count.
    #[zeroize(skip)]
    iterations: u64,
}

impl Pbkdf1Context {
    fn new() -> Self {
        Self {
            password: Vec::new(),
            salt: Vec::new(),
            iterations: 1,
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_PASSWORD) {
            self.password = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("PBKDF1: password must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SALT) {
            self.salt = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("PBKDF1: salt must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_ITER) {
            self.iterations = v
                .as_u64()
                .ok_or_else(|| ProviderError::Init("PBKDF1: iter must be uint".into()))?;
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.password.is_empty() {
            return Err(ProviderError::Init("PBKDF1: password must be set".into()));
        }
        if self.salt.is_empty() {
            return Err(ProviderError::Init("PBKDF1: salt must be set".into()));
        }
        if self.iterations == 0 {
            return Err(ProviderError::Init(
                "PBKDF1: iterations must be > 0".into(),
            ));
        }
        Ok(())
    }

    /// PBKDF1 derivation per RFC 2898 §5.1.
    ///
    /// `T_1 = Hash(P || S)`, `T_i = Hash(T_{i-1})`, output = `T_c[0..dkLen]`
    ///
    /// Output length MUST be <= hash output length (32 bytes for SHA-256).
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let out_len = output.len();
        if out_len > HASH_LEN {
            return Err(ProviderError::Init(format!(
                "PBKDF1: output length {out_len} exceeds hash length {HASH_LEN}"
            )));
        }

        // T_1 = Hash(P || S)
        let mut t = {
            let mut hasher = Sha256::new();
            hasher.update(&self.password);
            hasher.update(&self.salt);
            hasher.finalize().to_vec()
        };

        // T_i = Hash(T_{i-1}) for i = 2..c
        for _ in 1..self.iterations {
            t = Sha256::digest(&t).to_vec();
        }

        output[..out_len].copy_from_slice(&t[..out_len]);
        Ok(out_len)
    }
}

impl KdfContext for Pbkdf1Context {
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
        self.iterations = 1;
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_u64(PARAM_ITER, self.iterations)
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// PBKDF1 provider (legacy, PKCS#5 v1.5).
pub struct Pbkdf1Provider;

impl KdfProvider for Pbkdf1Provider {
    fn name(&self) -> &'static str {
        "PBKDF1"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(Pbkdf1Context::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for PBKDF1.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["PBKDF1"],
        "provider=legacy",
        "PBKDF1 legacy password-based KDF (PKCS#5 v1.5, RFC 2898 §5.1)",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(pw: &[u8], salt: &[u8], iter: u64) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(pw.to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(salt.to_vec()));
        ps.set(PARAM_ITER, ParamValue::UInt64(iter));
        ps
    }

    #[test]
    fn test_pbkdf1_basic() {
        let provider = Pbkdf1Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"password", b"saltsalt", 1000);
        let mut output = vec![0u8; 20];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 20);
        assert_ne!(output, vec![0u8; 20]);
    }

    #[test]
    fn test_pbkdf1_deterministic() {
        let provider = Pbkdf1Provider;
        let ps = make_params(b"test", b"12345678", 100);

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 16];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 16];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_pbkdf1_output_too_long() {
        let provider = Pbkdf1Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"saltsalt", 1);
        let mut output = vec![0u8; 64]; // > 32 = SHA-256 output
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_pbkdf1_missing_password() {
        let provider = Pbkdf1Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 16];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_pbkdf1_reset() {
        let provider = Pbkdf1Provider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"salt1234", 1);
        let mut output = vec![0u8; 16];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
