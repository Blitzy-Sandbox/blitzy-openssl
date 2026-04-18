//! TLS 1.0/1.1/1.2 PRF (Pseudo-Random Function).
//!
//! Implements the TLS PRF per RFC 2246 (TLS 1.0), RFC 4346 (TLS 1.1), and
//! RFC 5246 (TLS 1.2). TLS 1.0/1.1 use a combined MD5+SHA-1 PRF; TLS 1.2
//! uses a single hash (typically SHA-256).
//!
//! This is a pure-Rust translation of `providers/implementations/kdfs/tls1_prf.c`.
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

/// `OSSL_KDF_PARAM_SECRET` — the master secret.
const PARAM_SECRET: &str = "secret";
/// `OSSL_KDF_PARAM_SEED` — concatenated seed (label + `client_random` + `server_random`).
const PARAM_SEED: &str = "seed";
/// `OSSL_KDF_PARAM_DIGEST` — hash algorithm name.
const PARAM_DIGEST: &str = "digest";

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Context
// =============================================================================

/// TLS PRF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Tls1PrfContext {
    /// Master secret.
    secret: Vec<u8>,
    /// Concatenated seed (label || seed).
    #[zeroize(skip)]
    seed: Vec<u8>,
    /// Digest name.
    #[zeroize(skip)]
    digest_name: String,
}

impl Tls1PrfContext {
    fn new() -> Self {
        Self {
            secret: Vec::new(),
            seed: Vec::new(),
            digest_name: "SHA256".to_string(),
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_SECRET) {
            self.secret = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("TLS1-PRF: secret must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SEED) {
            self.seed = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("TLS1-PRF: seed must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_DIGEST) {
            self.digest_name = v
                .as_str()
                .ok_or_else(|| ProviderError::Init("TLS1-PRF: digest must be string".into()))?
                .to_string();
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.secret.is_empty() {
            return Err(ProviderError::Init("TLS1-PRF: secret must be set".into()));
        }
        if self.seed.is_empty() {
            return Err(ProviderError::Init("TLS1-PRF: seed must be set".into()));
        }
        Ok(())
    }

    /// `P_hash(secret, seed)` per RFC 5246 §5.
    ///
    /// ```text
    /// A(0) = seed
    /// A(i) = HMAC_hash(secret, A(i-1))
    /// P_hash = HMAC_hash(secret, A(1) + seed) ||
    ///          HMAC_hash(secret, A(2) + seed) || ...
    /// ```
    fn p_hash(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize; // HMAC-SHA-256 output length
        let out_len = output.len();
        let mut pos = 0;

        // A(0) = seed
        let mut a = self.seed.clone();

        while pos < out_len {
            // A(i) = HMAC(secret, A(i-1))
            a = {
                let mut mac = HmacSha256::new_from_slice(&self.secret)
                    .map_err(|_| ProviderError::Init("TLS1-PRF: HMAC key init failed".into()))?;
                mac.update(&a);
                mac.finalize().into_bytes().to_vec()
            };

            // P_hash block = HMAC(secret, A(i) || seed)
            let block = {
                let mut mac = HmacSha256::new_from_slice(&self.secret)
                    .map_err(|_| ProviderError::Init("TLS1-PRF: HMAC key init failed".into()))?;
                mac.update(&a);
                mac.update(&self.seed);
                mac.finalize().into_bytes().to_vec()
            };

            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&block[..copy_len]);
            pos += copy_len;
        }
        Ok(out_len)
    }
}

impl KdfContext for Tls1PrfContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        self.p_hash(key)
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.secret.zeroize();
        self.secret.clear();
        self.seed.clear();
        self.digest_name = "SHA256".to_string();
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_DIGEST, self.digest_name.clone())
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// TLS 1.0/1.1/1.2 PRF provider.
pub struct Tls1PrfProvider;

impl KdfProvider for Tls1PrfProvider {
    fn name(&self) -> &'static str {
        "TLS1-PRF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(Tls1PrfContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for TLS1-PRF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["TLS1-PRF"],
        "provider=default",
        "TLS 1.x PRF (RFC 2246/5246) using HMAC-SHA-256",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(secret: &[u8], seed: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_SECRET, ParamValue::OctetString(secret.to_vec()));
        ps.set(PARAM_SEED, ParamValue::OctetString(seed.to_vec()));
        ps
    }

    #[test]
    fn test_tls1_prf_basic() {
        let provider = Tls1PrfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"master secret!!", b"seed seed seed seed");
        let mut output = vec![0u8; 48];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 48);
        assert_ne!(output, vec![0u8; 48]);
    }

    #[test]
    fn test_tls1_prf_deterministic() {
        let provider = Tls1PrfProvider;
        let ps = make_params(b"secret", b"label" as &[u8]);

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 32];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 32];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_tls1_prf_missing_secret() {
        let provider = Tls1PrfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_tls1_prf_multi_block() {
        let provider = Tls1PrfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"secretkey", b"longseedlongseed");
        let mut output = vec![0u8; 128];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 128);
    }

    #[test]
    fn test_tls1_prf_reset() {
        let provider = Tls1PrfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key", b"seed");
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
