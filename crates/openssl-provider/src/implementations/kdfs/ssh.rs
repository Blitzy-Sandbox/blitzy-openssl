//! SSH KDF — Key Derivation Function per RFC 4253 §7.2.
//!
//! Derives initial encryption keys, IVs, and integrity keys for the SSH
//! transport layer from the shared secret, exchange hash, and session ID.
//!
//! `K_n = HASH(K || H || X || session_id)` where X is a single letter
//! ('A'..'F') selecting which key to derive.
//!
//! Translation of `providers/implementations/kdfs/sshkdf.c`.
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

/// `OSSL_KDF_PARAM_KEY` — shared secret K (mpint encoding).
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_SSHKDF_XCGHASH` — exchange hash H.
const PARAM_XCGHASH: &str = "xcghash";
/// `OSSL_KDF_PARAM_SSHKDF_SESSION_ID` — session identifier.
const PARAM_SESSION_ID: &str = "session_id";
/// `OSSL_KDF_PARAM_SSHKDF_TYPE` — key type selector ('A'..'F').
const PARAM_TYPE: &str = "type";

// =============================================================================
// Context
// =============================================================================

/// SSH KDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SshKdfContext {
    /// Shared secret K.
    key: Vec<u8>,
    /// Exchange hash H.
    #[zeroize(skip)]
    xcghash: Vec<u8>,
    /// Session identifier.
    #[zeroize(skip)]
    session_id: Vec<u8>,
    /// Key type selector: 'A' through 'F'.
    #[zeroize(skip)]
    key_type: u8,
}

impl SshKdfContext {
    fn new() -> Self {
        Self {
            key: Vec::new(),
            xcghash: Vec::new(),
            session_id: Vec::new(),
            key_type: b'A',
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_KEY) {
            self.key = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SSHKDF: key must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_XCGHASH) {
            self.xcghash = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SSHKDF: xcghash must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SESSION_ID) {
            self.session_id = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SSHKDF: session_id must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_TYPE) {
            let s = v
                .as_str()
                .ok_or_else(|| ProviderError::Init("SSHKDF: type must be string".into()))?;
            if s.len() != 1 {
                return Err(ProviderError::Init(
                    "SSHKDF: type must be a single character A-F".into(),
                ));
            }
            let ch = s.as_bytes()[0];
            if !(b'A'..=b'F').contains(&ch) {
                return Err(ProviderError::Init(
                    "SSHKDF: type must be A, B, C, D, E, or F".into(),
                ));
            }
            self.key_type = ch;
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.key.is_empty() {
            return Err(ProviderError::Init("SSHKDF: key must be set".into()));
        }
        if self.xcghash.is_empty() {
            return Err(ProviderError::Init("SSHKDF: xcghash must be set".into()));
        }
        if self.session_id.is_empty() {
            return Err(ProviderError::Init(
                "SSHKDF: session_id must be set".into(),
            ));
        }
        Ok(())
    }

    /// Derive key material per RFC 4253 §7.2.
    ///
    /// ```text
    /// K1 = HASH(K || H || X || session_id)
    /// K2 = HASH(K || H || K1)
    /// K3 = HASH(K || H || K1 || K2)
    /// Key = K1 || K2 || K3 || ...
    /// ```
    fn derive_internal(&self, output: &mut [u8]) -> usize {
        let out_len = output.len();
        let h_len = 32usize; // SHA-256

        // K1 = HASH(K || H || X || session_id)
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(&self.xcghash);
        hasher.update([self.key_type]);
        hasher.update(&self.session_id);
        let k1 = hasher.finalize().to_vec();

        let copy_len = core::cmp::min(h_len, out_len);
        output[..copy_len].copy_from_slice(&k1[..copy_len]);

        if out_len <= h_len {
            return out_len;
        }

        // Need more key material: K_n = HASH(K || H || K1 || ... || K_{n-1})
        let mut derived = k1;
        let mut pos = copy_len;

        while pos < out_len {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(&self.xcghash);
            hasher.update(&derived);
            let k_n = hasher.finalize().to_vec();

            let copy_len = core::cmp::min(h_len, out_len - pos);
            output[pos..pos + copy_len].copy_from_slice(&k_n[..copy_len]);
            derived.extend_from_slice(&k_n);
            pos += copy_len;
        }
        out_len
    }
}

impl KdfContext for SshKdfContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        Ok(self.derive_internal(key))
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.key.zeroize();
        self.key.clear();
        self.xcghash.clear();
        self.session_id.clear();
        self.key_type = b'A';
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        Ok(ParamBuilder::new()
            .push_utf8(
                PARAM_TYPE,
                String::from(char::from(self.key_type)),
            )
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Provider
// =============================================================================

/// SSH KDF provider per RFC 4253 §7.2.
pub struct SshKdfProvider;

impl KdfProvider for SshKdfProvider {
    fn name(&self) -> &'static str {
        "SSHKDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(SshKdfContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for SSH KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["SSHKDF"],
        "provider=default",
        "SSH key derivation function (RFC 4253 §7.2)",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(key: &[u8], hash: &[u8], sid: &[u8], kt: &str) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps.set(PARAM_XCGHASH, ParamValue::OctetString(hash.to_vec()));
        ps.set(PARAM_SESSION_ID, ParamValue::OctetString(sid.to_vec()));
        ps.set(PARAM_TYPE, ParamValue::Utf8String(kt.to_string()));
        ps
    }

    #[test]
    fn test_sshkdf_basic() {
        let provider = SshKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(
            b"shared_secret_key_material",
            &[0xAA; 32],
            &[0xBB; 32],
            "A",
        );
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_sshkdf_all_key_types() {
        let provider = SshKdfProvider;
        let mut results = Vec::new();
        for t in &["A", "B", "C", "D", "E", "F"] {
            let mut ctx = provider.new_ctx().unwrap();
            let ps = make_params(b"secret", &[1u8; 32], &[2u8; 32], t);
            let mut output = vec![0u8; 16];
            ctx.derive(&mut output, &ps).unwrap();
            results.push(output);
        }
        // All key types should produce different output.
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(results[i], results[j], "Key types should differ");
            }
        }
    }

    #[test]
    fn test_sshkdf_multi_block() {
        let provider = SshKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key", &[0x11; 32], &[0x22; 32], "C");
        let mut output = vec![0u8; 96];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 96);
    }

    #[test]
    fn test_sshkdf_invalid_type() {
        let provider = SshKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key", &[0x11; 32], &[0x22; 32], "Z");
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_sshkdf_missing_key() {
        let provider = SshKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_sshkdf_reset() {
        let provider = SshKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key", &[1; 32], &[2; 32], "A");
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
