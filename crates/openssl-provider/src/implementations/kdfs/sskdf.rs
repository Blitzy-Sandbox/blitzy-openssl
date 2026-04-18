//! SSKDF — Single-Step Key Derivation Function (NIST SP 800-56C Rev. 2).
//!
//! Implements the hash-based and HMAC-based single-step KDF. This is the
//! KDF used by key agreement schemes (ECDH, DH) to derive keying material
//! from a shared secret.
//!
//! Translation of `providers/implementations/kdfs/sskdf.c`.
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
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Parameter Name Constants
// =============================================================================

/// `OSSL_KDF_PARAM_KEY` — shared secret (Z).
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_INFO` — other info / fixed info (`OtherInfo`).
const PARAM_INFO: &str = "info";
/// `OSSL_KDF_PARAM_SALT` — salt for HMAC variant.
const PARAM_SALT: &str = "salt";
/// `OSSL_KDF_PARAM_PROPERTIES` — MAC name for HMAC variant.
const PARAM_MAC: &str = "mac";

type HmacSha256 = Hmac<Sha256>;

/// SSKDF mode: hash-based or HMAC-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SskdfMode {
    /// `H(counter || Z || OtherInfo)` per SP 800-56C §4.1.
    Hash,
    /// `HMAC(salt, counter || Z || OtherInfo)` per SP 800-56C §4.2.
    HmacBased,
}

// =============================================================================
// Context
// =============================================================================

/// SSKDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SskdfContext {
    /// Shared secret (Z).
    secret: Vec<u8>,
    /// Fixed info / other info.
    #[zeroize(skip)]
    info: Vec<u8>,
    /// Salt for HMAC variant.
    salt: Vec<u8>,
    /// Derivation mode.
    #[zeroize(skip)]
    mode: SskdfMode,
}

impl SskdfContext {
    fn new(mode: SskdfMode) -> Self {
        Self {
            secret: Vec::new(),
            info: Vec::new(),
            salt: Vec::new(),
            mode,
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_KEY) {
            self.secret = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SSKDF: key must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_INFO) {
            self.info = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SSKDF: info must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SALT) {
            self.salt = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SSKDF: salt must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_MAC) {
            let mac_name = v
                .as_str()
                .ok_or_else(|| ProviderError::Init("SSKDF: mac must be string".into()))?;
            if mac_name.to_uppercase().contains("HMAC") {
                self.mode = SskdfMode::HmacBased;
            }
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.secret.is_empty() {
            return Err(ProviderError::Init("SSKDF: shared secret must be set".into()));
        }
        Ok(())
    }

    /// Hash-based single-step KDF (SP 800-56C §4.1).
    ///
    /// `K(i) = H(counter || Z || OtherInfo)`
    fn derive_hash(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize; // SHA-256
        let out_len = output.len();
        let reps = (out_len + h_len - 1) / h_len;
        let mut pos = 0;

        for counter in 1..=reps {
            let c = u32::try_from(counter)
                .map_err(|_| ProviderError::Init("SSKDF: counter overflow".into()))?;
            let mut hasher = Sha256::new();
            hasher.update(c.to_be_bytes());
            hasher.update(&self.secret);
            hasher.update(&self.info);
            let digest = hasher.finalize();

            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&digest[..copy_len]);
            pos += copy_len;
        }
        Ok(out_len)
    }

    /// HMAC-based single-step KDF (SP 800-56C §4.2).
    ///
    /// `K(i) = HMAC(salt, counter || Z || OtherInfo)`
    fn derive_hmac(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize;
        let out_len = output.len();
        let reps = (out_len + h_len - 1) / h_len;
        let salt = if self.salt.is_empty() {
            vec![0u8; h_len]
        } else {
            self.salt.clone()
        };
        let mut pos = 0;

        for counter in 1..=reps {
            let c = u32::try_from(counter)
                .map_err(|_| ProviderError::Init("SSKDF: counter overflow".into()))?;
            let mut mac = HmacSha256::new_from_slice(&salt)
                .map_err(|_| ProviderError::Init("SSKDF: HMAC key init failed".into()))?;
            mac.update(&c.to_be_bytes());
            mac.update(&self.secret);
            mac.update(&self.info);
            let tag = mac.finalize().into_bytes();

            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&tag[..copy_len]);
            pos += copy_len;
        }
        Ok(out_len)
    }
}

impl KdfContext for SskdfContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        match self.mode {
            SskdfMode::Hash => self.derive_hash(key),
            SskdfMode::HmacBased => self.derive_hmac(key),
        }
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.secret.zeroize();
        self.secret.clear();
        self.info.clear();
        self.salt.clear();
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mode_str = match self.mode {
            SskdfMode::Hash => "hash",
            SskdfMode::HmacBased => "hmac",
        };
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_MAC, mode_str.to_string())
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Providers
// =============================================================================

/// SSKDF hash-based provider.
pub struct SskdfHashProvider;

impl KdfProvider for SskdfHashProvider {
    fn name(&self) -> &'static str {
        "SSKDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(SskdfContext::new(SskdfMode::Hash)))
    }
}

/// SSKDF HMAC-based provider.
pub struct SskdfHmacProvider;

impl KdfProvider for SskdfHmacProvider {
    fn name(&self) -> &'static str {
        "SSKDF-HMAC"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(SskdfContext::new(SskdfMode::HmacBased)))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for SSKDF variants.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SSKDF"],
            "provider=default",
            "Single-step hash-based KDF (NIST SP 800-56C §4.1)",
        ),
        algorithm(
            &["SSKDF-HMAC"],
            "provider=default",
            "Single-step HMAC-based KDF (NIST SP 800-56C §4.2)",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_hash_params(key: &[u8], info: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps.set(PARAM_INFO, ParamValue::OctetString(info.to_vec()));
        ps
    }

    #[test]
    fn test_sskdf_hash_basic() {
        let provider = SskdfHashProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_hash_params(b"shared_secret_value", b"otherinfo");
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_sskdf_hash_multi_block() {
        let provider = SskdfHashProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_hash_params(b"secret", b"info");
        let mut output = vec![0u8; 96];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 96);
    }

    #[test]
    fn test_sskdf_hmac_basic() {
        let provider = SskdfHmacProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(b"secret".to_vec()));
        ps.set(PARAM_INFO, ParamValue::OctetString(b"info".to_vec()));
        ps.set(PARAM_SALT, ParamValue::OctetString(b"saltsalt".to_vec()));
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_sskdf_deterministic() {
        let provider = SskdfHashProvider;
        let ps = make_hash_params(b"deterministic_key", b"deterministic_info");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 32];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 32];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_sskdf_missing_secret() {
        let provider = SskdfHashProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_sskdf_reset() {
        let provider = SskdfHashProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_hash_params(b"sec", b"inf");
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
