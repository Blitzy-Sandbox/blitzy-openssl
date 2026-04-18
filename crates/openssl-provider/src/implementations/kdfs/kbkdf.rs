//! KBKDF — Key-Based Key Derivation Function (NIST SP 800-108).
//!
//! Implements Counter Mode, Feedback Mode, and Double-Pipeline Iteration Mode
//! KDF using HMAC as the PRF. This is a pure-Rust translation of
//! `providers/implementations/kdfs/kbkdf.c`.
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` for optional parameters
//! - **R6:** Checked arithmetic for all numeric casts
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

/// `OSSL_KDF_PARAM_KEY` — input keying material (KI).
const PARAM_KEY: &str = "key";
/// `OSSL_KDF_PARAM_MODE` — KBKDF mode: counter, feedback, or pipeline.
const PARAM_MODE: &str = "mode";
/// `OSSL_KDF_PARAM_SALT` — label (Label) for counter/feedback modes.
const PARAM_LABEL: &str = "label";
/// `OSSL_KDF_PARAM_INFO` — context data (Context).
const PARAM_CONTEXT: &str = "context";
/// `OSSL_KDF_PARAM_SEED` — IV for feedback mode.
const PARAM_SEED: &str = "seed";

type HmacSha256 = Hmac<Sha256>;

/// KBKDF mode per SP 800-108 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KbkdfMode {
    /// Counter Mode (§5.1).
    Counter,
    /// Feedback Mode (§5.2).
    Feedback,
    /// Double-Pipeline Iteration Mode (§5.3).
    DoublePipeline,
}

impl KbkdfMode {
    fn from_str(s: &str) -> ProviderResult<Self> {
        match s.to_lowercase().as_str() {
            "counter" => Ok(Self::Counter),
            "feedback" => Ok(Self::Feedback),
            "double-pipeline" | "pipeline" | "double_pipeline" => Ok(Self::DoublePipeline),
            _ => Err(ProviderError::Init(format!("KBKDF: unknown mode '{s}'"))),
        }
    }
}

// =============================================================================
// Context
// =============================================================================

/// KBKDF derivation context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct KbkdfContext {
    /// Input key (KI).
    ki: Vec<u8>,
    /// Label bytes.
    #[zeroize(skip)]
    label: Vec<u8>,
    /// Context bytes.
    #[zeroize(skip)]
    context: Vec<u8>,
    /// IV / seed for feedback mode.
    seed: Vec<u8>,
    /// Derivation mode.
    #[zeroize(skip)]
    mode: KbkdfMode,
}

impl KbkdfContext {
    fn new(mode: KbkdfMode) -> Self {
        Self {
            ki: Vec::new(),
            label: Vec::new(),
            context: Vec::new(),
            seed: Vec::new(),
            mode,
        }
    }

    fn apply_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        if let Some(v) = params.get(PARAM_KEY) {
            self.ki = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("KBKDF: key must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_MODE) {
            let s = v
                .as_str()
                .ok_or_else(|| ProviderError::Init("KBKDF: mode must be string".into()))?;
            self.mode = KbkdfMode::from_str(s)?;
        }
        if let Some(v) = params.get(PARAM_LABEL) {
            self.label = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("KBKDF: label must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_CONTEXT) {
            self.context = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("KBKDF: context must be bytes".into()))?
                .to_vec();
        }
        if let Some(v) = params.get(PARAM_SEED) {
            self.seed = v
                .as_bytes()
                .ok_or_else(|| ProviderError::Init("KBKDF: seed must be bytes".into()))?
                .to_vec();
        }
        Ok(())
    }

    fn validate(&self) -> ProviderResult<()> {
        if self.ki.is_empty() {
            return Err(ProviderError::Init("KBKDF: key must be set".into()));
        }
        Ok(())
    }

    /// HMAC-SHA-256 helper. Returns the MAC tag as `Vec<u8>`.
    fn hmac(&self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.ki)
            .map_err(|_| ProviderError::Init("KBKDF: HMAC key init failed".into()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Counter Mode derivation (SP 800-108 §5.1).
    ///
    /// `K(i) = PRF(KI, [i]_2 || Label || 0x00 || Context || [L]_2)`
    fn derive_counter(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize; // HMAC-SHA-256 output
        let l = output.len();
        let n = (l + h_len - 1) / h_len;
        let l_bits = u32::try_from(l.checked_mul(8).ok_or_else(|| {
            ProviderError::Init("KBKDF: output length overflow".into())
        })?)
        .map_err(|_| ProviderError::Init("KBKDF: L exceeds u32 range".into()))?;

        let mut pos = 0;
        for i in 1..=n {
            let counter = u32::try_from(i)
                .map_err(|_| ProviderError::Init("KBKDF: counter overflow".into()))?;
            let mut input = Vec::new();
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(&self.label);
            input.push(0x00);
            input.extend_from_slice(&self.context);
            input.extend_from_slice(&l_bits.to_be_bytes());

            let k_i = self.hmac(&input)?;
            let copy_len = core::cmp::min(h_len, l - pos);
            output[pos..pos + copy_len].copy_from_slice(&k_i[..copy_len]);
            pos += copy_len;
        }
        Ok(l)
    }

    /// Feedback Mode derivation (SP 800-108 §5.2).
    ///
    /// `K(i) = PRF(KI, K(i-1) || [i]_2 || Label || 0x00 || Context || [L]_2)`
    fn derive_feedback(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize;
        let l = output.len();
        let n = (l + h_len - 1) / h_len;
        let l_bits = u32::try_from(l.checked_mul(8).ok_or_else(|| {
            ProviderError::Init("KBKDF: output length overflow".into())
        })?)
        .map_err(|_| ProviderError::Init("KBKDF: L exceeds u32 range".into()))?;

        let mut prev = self.seed.clone();
        let mut pos = 0;
        for i in 1..=n {
            let counter = u32::try_from(i)
                .map_err(|_| ProviderError::Init("KBKDF: counter overflow".into()))?;
            let mut input = Vec::new();
            input.extend_from_slice(&prev);
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(&self.label);
            input.push(0x00);
            input.extend_from_slice(&self.context);
            input.extend_from_slice(&l_bits.to_be_bytes());

            let k_i = self.hmac(&input)?;
            let copy_len = core::cmp::min(h_len, l - pos);
            output[pos..pos + copy_len].copy_from_slice(&k_i[..copy_len]);
            pos += copy_len;
            prev = k_i;
        }
        Ok(l)
    }

    /// Double-Pipeline Iteration Mode (SP 800-108 §5.3).
    ///
    /// `A(0) = Label || 0x00 || Context || [L]_2`
    /// `A(i) = PRF(KI, A(i-1))`
    /// `K(i) = PRF(KI, A(i) || [i]_2 || Label || 0x00 || Context || [L]_2)`
    fn derive_double_pipeline(&self, output: &mut [u8]) -> ProviderResult<usize> {
        let h_len = 32usize;
        let l = output.len();
        let n = (l + h_len - 1) / h_len;
        let l_bits = u32::try_from(l.checked_mul(8).ok_or_else(|| {
            ProviderError::Init("KBKDF: output length overflow".into())
        })?)
        .map_err(|_| ProviderError::Init("KBKDF: L exceeds u32 range".into()))?;

        // Build A(0)
        let mut a0 = Vec::new();
        a0.extend_from_slice(&self.label);
        a0.push(0x00);
        a0.extend_from_slice(&self.context);
        a0.extend_from_slice(&l_bits.to_be_bytes());

        let mut a_prev = a0;
        let mut pos = 0;
        for i in 1..=n {
            let counter = u32::try_from(i)
                .map_err(|_| ProviderError::Init("KBKDF: counter overflow".into()))?;
            // A(i) = PRF(KI, A(i-1))
            let a_i = self.hmac(&a_prev)?;

            // K(i) = PRF(KI, A(i) || [i] || Label || 0x00 || Context || [L])
            let mut input = Vec::new();
            input.extend_from_slice(&a_i);
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(&self.label);
            input.push(0x00);
            input.extend_from_slice(&self.context);
            input.extend_from_slice(&l_bits.to_be_bytes());

            let k_i = self.hmac(&input)?;
            let copy_len = core::cmp::min(h_len, l - pos);
            output[pos..pos + copy_len].copy_from_slice(&k_i[..copy_len]);
            pos += copy_len;
            a_prev = a_i;
        }
        Ok(l)
    }
}

impl KdfContext for KbkdfContext {
    fn derive(&mut self, key: &mut [u8], params: &ParamSet) -> ProviderResult<usize> {
        if !params.is_empty() {
            self.apply_params(params)?;
        }
        self.validate()?;
        match self.mode {
            KbkdfMode::Counter => self.derive_counter(key),
            KbkdfMode::Feedback => self.derive_feedback(key),
            KbkdfMode::DoublePipeline => self.derive_double_pipeline(key),
        }
    }

    fn reset(&mut self) -> ProviderResult<()> {
        self.ki.zeroize();
        self.ki.clear();
        self.label.clear();
        self.context.clear();
        self.seed.clear();
        Ok(())
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mode_str = match self.mode {
            KbkdfMode::Counter => "counter",
            KbkdfMode::Feedback => "feedback",
            KbkdfMode::DoublePipeline => "double-pipeline",
        };
        Ok(ParamBuilder::new()
            .push_utf8(PARAM_MODE, mode_str.to_string())
            .build())
    }

    fn set_params(&mut self, params: &ParamSet) -> ProviderResult<()> {
        self.apply_params(params)
    }
}

// =============================================================================
// Providers
// =============================================================================

/// KBKDF Counter Mode provider.
pub struct KbkdfCounterProvider;

impl KdfProvider for KbkdfCounterProvider {
    fn name(&self) -> &'static str {
        "KBKDF"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(KbkdfContext::new(KbkdfMode::Counter)))
    }
}

/// KBKDF Feedback Mode provider.
pub struct KbkdfFeedbackProvider;

impl KdfProvider for KbkdfFeedbackProvider {
    fn name(&self) -> &'static str {
        "KBKDF-FEEDBACK"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(KbkdfContext::new(KbkdfMode::Feedback)))
    }
}

/// KBKDF Double-Pipeline provider.
pub struct KbkdfPipelineProvider;

impl KdfProvider for KbkdfPipelineProvider {
    fn name(&self) -> &'static str {
        "KBKDF-PIPELINE"
    }
    fn new_ctx(&self) -> ProviderResult<Box<dyn KdfContext>> {
        Ok(Box::new(KbkdfContext::new(KbkdfMode::DoublePipeline)))
    }
}

// =============================================================================
// Descriptors
// =============================================================================

/// Returns algorithm descriptors for KBKDF variants.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["KBKDF"],
            "provider=default",
            "KBKDF counter mode (NIST SP 800-108 §5.1)",
        ),
        algorithm(
            &["KBKDF-FEEDBACK"],
            "provider=default",
            "KBKDF feedback mode (NIST SP 800-108 §5.2)",
        ),
        algorithm(
            &["KBKDF-PIPELINE"],
            "provider=default",
            "KBKDF double-pipeline mode (NIST SP 800-108 §5.3)",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_common::param::ParamValue;

    fn make_params(key: &[u8], label: &[u8], ctx: &[u8]) -> ParamSet {
        let mut ps = ParamSet::new();
        ps.set(PARAM_KEY, ParamValue::OctetString(key.to_vec()));
        ps.set(PARAM_LABEL, ParamValue::OctetString(label.to_vec()));
        ps.set(PARAM_CONTEXT, ParamValue::OctetString(ctx.to_vec()));
        ps
    }

    #[test]
    fn test_kbkdf_counter_basic() {
        let provider = KbkdfCounterProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"secretkey1234567", b"label", b"context");
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_kbkdf_counter_deterministic() {
        let provider = KbkdfCounterProvider;
        let ps = make_params(b"keykeykeykeykeykey", b"myapp", b"myctx");

        let mut ctx1 = provider.new_ctx().unwrap();
        let mut out1 = vec![0u8; 64];
        ctx1.derive(&mut out1, &ps).unwrap();

        let mut ctx2 = provider.new_ctx().unwrap();
        let mut out2 = vec![0u8; 64];
        ctx2.derive(&mut out2, &ps).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_kbkdf_feedback_basic() {
        let provider = KbkdfFeedbackProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"anothersecretkey", b"label", b"context");
        let mut output = vec![0u8; 48];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 48);
        assert_ne!(output, vec![0u8; 48]);
    }

    #[test]
    fn test_kbkdf_pipeline_basic() {
        let provider = KbkdfPipelineProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"yetanothersecret", b"lab", b"ctx");
        let mut output = vec![0u8; 32];
        let n = ctx.derive(&mut output, &ps).unwrap();
        assert_eq!(n, 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_kbkdf_missing_key() {
        let provider = KbkdfCounterProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let mut output = vec![0u8; 32];
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }

    #[test]
    fn test_kbkdf_reset() {
        let provider = KbkdfCounterProvider;
        let mut ctx = provider.new_ctx().unwrap();
        let ps = make_params(b"key1234567890123", b"l", b"c");
        let mut output = vec![0u8; 32];
        ctx.derive(&mut output, &ps).unwrap();
        ctx.reset().unwrap();
        assert!(ctx.derive(&mut output, &ParamSet::default()).is_err());
    }
}
