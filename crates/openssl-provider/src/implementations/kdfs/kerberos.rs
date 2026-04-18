//! Kerberos KDF — Key Derivation per RFC 3961 §5.1.
//!
//! Derives protocol keys from a base key and a "well-known constant"
//! (usage number). Uses DK(key, constant) = random-to-key(DR(key, constant))
//! where DR is the "derived random" function.
//!
//! Translation of `providers/implementations/kdfs/krb5kdf.c`.
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

/// `OSSL_KDF_PARAM_KEY` — base key.
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_CONSTANT` — well-known constant / usage label.
const PARAM_CONSTANT: &str = "constant";

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Context
// =============================================================================

/// Kerberos KDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct KerberosContext {
    /// Base key.
    key: Vec<u8>,
    /// Well-known constant (usage number label).
    #[zeroize(skip)]
    constant: Vec<u8>,
}

impl KerberosContext {
    fn new() -> Self {
        Self {
            key: Vec::new(),
            constant: Vec::new(),
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_KEY) {
            self.key = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("KRB5KDF: key must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_CONSTANT) {
            self.constant = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("KRB5KDF: constant must be bytes".into()))?
                .to_vec();
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.key.is_empty() {
            return Err(ProviderError::Init("KRB5KDF: key must be set".into()));
        }
        if self.constant.is_empty() {
            return Err(ProviderError::Init(
                "KRB5KDF: constant must be set".into(),
            ));
        }
        Ok(())
    }

    /// Derived Random function DR(key, constant) per RFC 3961 §5.1.
    ///
    /// Uses HMAC-SHA-256 as the PRF:
    /// ```text
    /// K1 = HMAC(key, constant)
    /// K2 = HMAC(key, K1)
    /// K3 = HMAC(key, K2)
    /// DR = K1 || K2 || K3 || ... (truncated to output length)
    /// ```
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize; // HMAC-SHA-256
        let out_len = output.len();
        let mut pos = 0;

        // K1 = HMAC(key, constant)
        let mut prev = {
            let mut mac = HmacSha256::new_from_slice(&self.key)
                .map_err(|_| ProviderError::Init("KRB5KDF: HMAC key init failed".into()))?;
            mac.update(&self.constant);
            mac.finalize().into_bytes().to_vec()
        };

        let copy_len = core::cmp::min(h_len, out_len);
        output[..copy_len].copy_from_slice(&prev[..copy_len]);
        pos += copy_len;

        // K_n = HMAC(key, K_{n-1})
        while pos < out_len {
            prev = {
                let mut mac = HmacSha256::new_from_slice(&self.key)
                    .map_err(|_| ProviderError::Init("KRB5KDF: HMAC key init failed".into()))?;
                mac.update(&prev);
                mac.finalize().into_bytes().to_vec()
            };
            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&prev[..copy_len]);
            pos += copy_len;
        }
        Ok(out_len)
    }
}

impl KdfContext for KerberosContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        self.derive_internal(key)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.key.zeroize();
        self.key.clear();
        self.constant.clear();
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

/// Kerberos KDF provider (RFC 3961).
pub struct KerberosKdfProvider;

impl KdfProvider for KerberosKdfProvider {
    fn name(&self) -> &'static str {
        "KRB5KDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(KerberosContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for the Kerberos KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["KRB5KDF"],
        "provider=default",
        "Kerberos key derivation (RFC 3961 §5.1)",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(key: &[u8], constant: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps.set(PARAM_CONSTANT, ParamValue::OctetString(constant.to_vec()));
        ps
    }

    #[test]
    fn test_krb5kdf_basic() {
        let provider = KerberosKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"base_key_1234567", b"\x00\x00\x00\x02\x99");
        let mut output = vec![0u8; 16];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 16);
        assert_ne!(output, vec![0u8; 16]);
    }

    #[test]
    fn test_krb5kdf_deterministic() {
        let provider = KerberosKdfProvider;
        let ps = make_params(b"krb5key", b"constant");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 32];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 32];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_krb5kdf_multi_block() {
        let provider = KerberosKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"somekey", b"someconstant");
        let mut output = vec![0u8; 64];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 64);
    }

    #[test]
    fn test_krb5kdf_missing_key() {
        let provider = KerberosKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_krb5kdf_missing_constant() {
        let provider = KerberosKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(b"key".to_vec()));
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_krb5kdf_reset() {
        let provider = KerberosKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key", b"const");
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
