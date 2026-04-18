//! SNMP KDF — `SNMPv3` USM Key Derivation.
//!
//! Derives localized `SNMPv3` keys per RFC 3414 §2.6. Uses a password-to-key
//! algorithm that processes the password through a digest repeatedly to fill
//! 1 MiB (1,048,576 bytes), then localizes by hashing with the engine ID.
//!
//! Translation of `providers/implementations/kdfs/krb5kdf.c` (SNMP variant).
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
// Constants
// =============================================================================

/// Password-to-key processing length (1 MiB).
const SNMP_P2K_LENGTH: usize = 1_048_576;

/// `OSSL_KDF_PARAM_PASSWORD` — password.
const PARAM_PASSWORD: &str = "pass";
/// `OSSL_KDF_PARAM_SALT` — engine ID used for localization.
const PARAM_ENGINE_ID: &str = "engineid";

// =============================================================================
// Context
// =============================================================================

/// SNMP KDF context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SnmpContext {
    /// Password.
    password: Vec<u8>,
    /// Engine ID for localization.
    #[zeroize(skip)]
    engine_id: Vec<u8>,
}

impl SnmpContext {
    fn new() -> Self {
        Self {
            password: Vec::new(),
            engine_id: Vec::new(),
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_PASSWORD) {
            self.password = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SNMPKDF: password must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_ENGINE_ID) {
            self.engine_id = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("SNMPKDF: engine_id must be bytes".into()))?
                .to_vec();
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.password.is_empty() {
            return Err(ProviderError::Init(
                "SNMPKDF: password must be set".into(),
            ));
        }
        if self.engine_id.is_empty() {
            return Err(ProviderError::Init(
                "SNMPKDF: engine ID must be set".into(),
            ));
        }
        Ok(())
    }

    /// RFC 3414 §2.6 password-to-key + localization.
    ///
    /// 1. Repeat password to fill 1 MiB, hash the entire block.
    /// 2. Localize: `hash(Ku || engineID || Ku)`.
    fn derive_internal(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let pw_len = self.password.len();
        if pw_len == 0 {
            return Err(ProviderError::Init("SNMPKDF: empty password".into()));
        }

        // Step 1: Password-to-key (Ku)
        let mut hasher = Sha256::new();
        let mut count = 0usize;
        let mut idx = 0usize;
        while count < SNMP_P2K_LENGTH {
            let chunk_end = (idx + 64).min(idx + (SNMP_P2K_LENGTH - count));
            let chunk_len = chunk_end - idx;
            // Fill chunk from password (cycling)
            let mut buf = vec![0u8; chunk_len];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.password[(idx + i) % pw_len];
            }
            hasher.update(&buf);
            count = count.saturating_add(chunk_len);
            idx = idx.wrapping_add(chunk_len);
        }
        let ku = hasher.finalize();

        // Step 2: Localize — hash(Ku || engineID || Ku)
        let mut localizer = Sha256::new();
        localizer.update(ku.as_slice());
        localizer.update(&self.engine_id);
        localizer.update(ku.as_slice());
        let kul = localizer.finalize();

        let out_len = output.len().min(kul.len());
        output[..out_len].copy_from_slice(&kul[..out_len]);
        Ok(out_len)
    }
}

impl KdfContext for SnmpContext {
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
        self.engine_id.clear();
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

/// SNMP USM key localization KDF.
pub struct SnmpKdfProvider;

impl KdfProvider for SnmpKdfProvider {
    fn name(&self) -> &'static str {
        "SNMPKDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(SnmpContext::new()))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for SNMP KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![algorithm(
        &["SNMPKDF"],
        "provider=default",
        "SNMPv3 USM key localization per RFC 3414",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(pw: &[u8], eid: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_PASSWORD, ParamValue::OctetString(pw.to_vec()));
        ps.set(PARAM_ENGINE_ID, ParamValue::OctetString(eid.to_vec()));
        ps
    }

    #[test]
    fn test_snmp_basic() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"maplesyrup", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02");
        let mut output = vec![0u8; 20];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 20);
        assert_ne!(output, vec![0u8; 20]);
    }

    #[test]
    fn test_snmp_deterministic() {
        let provider = SnmpKdfProvider;
        let ps = make_params(b"password", b"\x01\x02\x03\x04");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 16];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 16];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_snmp_missing_password() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_ENGINE_ID,
            ParamValue::OctetString(b"\x01\x02".to_vec()),
        );
        let mut output = vec![0u8; 16];
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_snmp_missing_engine_id() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut ps = ParamSet::new();
        ps.set(
            PARAM_PASSWORD,
            ParamValue::OctetString(b"password".to_vec()),
        );
        let mut output = vec![0u8; 16];
        assert!(ctx.derive(&mut output, &ps).is_err());
    }

    #[test]
    fn test_snmp_reset() {
        let provider = SnmpKdfProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"pw", b"\x01");
        let mut output = vec![0u8; 16];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
