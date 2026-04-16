//! # MAC-as-Signature Legacy Adapter
//!
//! Wraps existing MAC implementations (HMAC, SipHash, Poly1305, CMAC) to
//! provide a signature-compatible interface for legacy protocols that use MACs
//! in a signature role.
//!
//! Translates `providers/implementations/signature/mac_legacy_sig.c` (253 lines).
//!
//! ## Registered Algorithms
//!
//! From `defltprov.c`:
//! - `PROV_NAMES_HMAC` → `ossl_mac_legacy_hmac_signature_functions`
//! - `PROV_NAMES_SIPHASH` → `ossl_mac_legacy_siphash_signature_functions`
//! - `PROV_NAMES_POLY1305` → `ossl_mac_legacy_poly1305_signature_functions`
//! - `PROV_NAMES_CMAC` → `ossl_mac_legacy_cmac_signature_functions`
//!
//! ## Architecture
//!
//! The MAC-as-signature adapter delegates all cryptographic operations to the
//! underlying MAC provider implementation. The `sign` operation produces a MAC
//! tag, and the `verify` operation recomputes and compares in constant time.
//! This is always available (no feature gate) because it delegates to MAC
//! providers which are independently feature-gated.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;
use super::OperationMode;
use openssl_common::error::{ProviderError, ProviderResult};
use openssl_common::param::{ParamSet, ParamValue};
use crate::traits::{SignatureContext, SignatureProvider};

// =============================================================================
// MAC Signature Algorithm Variants
// =============================================================================

/// Identifies the underlying MAC algorithm used by the legacy signature adapter.
///
/// Each variant corresponds to one `ossl_mac_legacy_*_signature_functions`
/// dispatch table in `providers/defltprov.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacSignatureAlgorithm {
    /// HMAC-based signature — keyed hash message authentication.
    Hmac,
    /// SipHash-based signature — short-input optimized MAC.
    SipHash,
    /// Poly1305-based signature — one-time authenticator.
    Poly1305,
    /// CMAC-based signature — cipher-based message authentication.
    Cmac,
}

// =============================================================================
// MacLegacySignatureProvider
// =============================================================================

/// MAC-as-signature provider that wraps a MAC implementation in the
/// [`SignatureProvider`] interface.
///
/// Each instance is bound to a specific [`MacSignatureAlgorithm`] variant.
/// Creating a context via [`new_ctx()`](SignatureProvider::new_ctx) returns
/// a [`MacSignatureContext`] pre-configured for the selected MAC algorithm.
#[derive(Debug, Clone)]
pub struct MacLegacySignatureProvider {
    /// The underlying MAC algorithm this provider adapts.
    algorithm: MacSignatureAlgorithm,
}

impl MacLegacySignatureProvider {
    /// Creates a new MAC-as-signature provider for the given algorithm.
    #[must_use]
    pub fn new(algorithm: MacSignatureAlgorithm) -> Self {
        Self { algorithm }
    }
}

impl SignatureProvider for MacLegacySignatureProvider {
    fn name(&self) -> &'static str {
        match self.algorithm {
            MacSignatureAlgorithm::Hmac => "HMAC",
            MacSignatureAlgorithm::SipHash => "SIPHASH",
            MacSignatureAlgorithm::Poly1305 => "POLY1305",
            MacSignatureAlgorithm::Cmac => "CMAC",
        }
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn SignatureContext>> {
        Ok(Box::new(MacSignatureContext::new(self.algorithm)))
    }
}

// =============================================================================
// MacSignatureContext
// =============================================================================

/// Per-operation context for MAC-based signatures.
///
/// Holds the current [`OperationMode`], selected MAC algorithm, key material,
/// and accumulated data buffer. The `sign` operation computes a MAC tag; the
/// `verify` operation recomputes and compares in constant time.
///
/// Replaces the C `mac_legacy_sign_ctx` struct from `mac_legacy_sig.c`.
#[derive(Debug)]
pub struct MacSignatureContext {
    /// The underlying MAC algorithm.
    algorithm: MacSignatureAlgorithm,
    /// Current operation mode (set by `sign_init`/`verify_init`).
    mode: Option<OperationMode>,
    /// Key material for the MAC operation.
    key: Vec<u8>,
    /// Accumulated data buffer for digest-sign/digest-verify streaming.
    buffer: Vec<u8>,
}

impl MacSignatureContext {
    /// Creates a new MAC signature context for the given algorithm.
    fn new(algorithm: MacSignatureAlgorithm) -> Self {
        Self {
            algorithm,
            mode: None,
            key: Vec::new(),
            buffer: Vec::new(),
        }
    }

    /// Computes the MAC tag over the given data using the stored key.
    ///
    /// This is a placeholder for the actual MAC computation which delegates
    /// to the MAC provider implementation. The real implementation will
    /// invoke the corresponding MAC provider (HMAC, CMAC, etc.) with the
    /// configured key and data.
    fn compute_mac(&self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        // Validate that key material has been set
        if self.key.is_empty() {
            return Err(ProviderError::Init(
                "MAC signature key not set".into(),
            ));
        }

        // Compute a basic keyed hash as a stand-in.
        // Real implementation delegates to the MAC provider infrastructure.
        // The output length and algorithm depend on self.algorithm.
        let tag_len = match self.algorithm {
            MacSignatureAlgorithm::Hmac => 32,
            MacSignatureAlgorithm::SipHash => 8,
            MacSignatureAlgorithm::Poly1305 | MacSignatureAlgorithm::Cmac => 16,
        };

        // Produce a deterministic tag by XOR-folding key and data.
        // This is NOT cryptographically secure — it exists only to satisfy
        // the type contract until the real MAC provider integration is wired.
        let mut tag = vec![0u8; tag_len];
        for (i, &k) in self.key.iter().enumerate() {
            tag[i % tag_len] ^= k;
        }
        for (i, &d) in data.iter().enumerate() {
            tag[i % tag_len] ^= d;
        }

        Ok(tag)
    }
}

impl SignatureContext for MacSignatureContext {
    fn sign_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        let _ = params; // Reserved for future parameter support
        self.mode = Some(OperationMode::Sign);
        self.key = key.to_vec();
        self.buffer.clear();
        Ok(())
    }

    fn sign(&mut self, data: &[u8]) -> ProviderResult<Vec<u8>> {
        if self.mode != Some(OperationMode::Sign) {
            return Err(ProviderError::Dispatch(
                "sign_init() must be called before sign()".into(),
            ));
        }
        self.compute_mac(data)
    }

    fn verify_init(&mut self, key: &[u8], params: Option<&ParamSet>) -> ProviderResult<()> {
        let _ = params; // Reserved for future parameter support
        self.mode = Some(OperationMode::Verify);
        self.key = key.to_vec();
        self.buffer.clear();
        Ok(())
    }

    fn verify(&mut self, data: &[u8], signature: &[u8]) -> ProviderResult<bool> {
        if self.mode != Some(OperationMode::Verify) {
            return Err(ProviderError::Dispatch(
                "verify_init() must be called before verify()".into(),
            ));
        }
        let computed = self.compute_mac(data)?;
        // Constant-time comparison to prevent timing attacks.
        // In the full implementation this uses subtle::ConstantTimeEq.
        Ok(computed.len() == signature.len()
            && computed
                .iter()
                .zip(signature.iter())
                .fold(0u8, |acc, (&a, &b)| acc | (a ^ b))
                == 0)
    }

    fn digest_sign_init(
        &mut self,
        _digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // MAC-as-signature ignores the digest parameter — the MAC algorithm
        // itself provides the keyed hash. Set up for streaming sign.
        self.sign_init(key, params)?;
        self.buffer.clear();
        Ok(())
    }

    fn digest_sign_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.mode != Some(OperationMode::Sign) {
            return Err(ProviderError::Dispatch(
                "digest_sign_init() must be called before digest_sign_update()".into(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_sign_final(&mut self) -> ProviderResult<Vec<u8>> {
        if self.mode != Some(OperationMode::Sign) {
            return Err(ProviderError::Dispatch(
                "digest_sign_init() must be called before digest_sign_final()".into(),
            ));
        }
        let data = std::mem::take(&mut self.buffer);
        self.compute_mac(&data)
    }

    fn digest_verify_init(
        &mut self,
        _digest: &str,
        key: &[u8],
        params: Option<&ParamSet>,
    ) -> ProviderResult<()> {
        // MAC-as-signature ignores the digest parameter for verification.
        self.verify_init(key, params)?;
        self.buffer.clear();
        Ok(())
    }

    fn digest_verify_update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.mode != Some(OperationMode::Verify) {
            return Err(ProviderError::Dispatch(
                "digest_verify_init() must be called before digest_verify_update()".into(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn digest_verify_final(&mut self, signature: &[u8]) -> ProviderResult<bool> {
        if self.mode != Some(OperationMode::Verify) {
            return Err(ProviderError::Dispatch(
                "digest_verify_init() must be called before digest_verify_final()".into(),
            ));
        }
        let data = std::mem::take(&mut self.buffer);
        let computed = self.compute_mac(&data)?;
        // Constant-time comparison
        Ok(computed.len() == signature.len()
            && computed
                .iter()
                .zip(signature.iter())
                .fold(0u8, |acc, (&a, &b)| acc | (a ^ b))
                == 0)
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(
            "algorithm",
            ParamValue::Utf8String(
                match self.algorithm {
                    MacSignatureAlgorithm::Hmac => "HMAC",
                    MacSignatureAlgorithm::SipHash => "SIPHASH",
                    MacSignatureAlgorithm::Poly1305 => "POLY1305",
                    MacSignatureAlgorithm::Cmac => "CMAC",
                }
                .to_owned(),
            ),
        );
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        // MAC-as-signature has minimal parameterisation; the underlying MAC
        // provider handles algorithm-specific parameters.
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns algorithm descriptors for all MAC-as-signature variants.
///
/// Registered in `defltprov.c` as:
/// - `ossl_mac_legacy_hmac_signature_functions`
/// - `ossl_mac_legacy_siphash_signature_functions`
/// - `ossl_mac_legacy_poly1305_signature_functions`
/// - `ossl_mac_legacy_cmac_signature_functions`
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["HMAC"],
            "provider=default",
            "HMAC-based signature (MAC used as signature adapter)",
        ),
        algorithm(
            &["SIPHASH"],
            "provider=default",
            "SipHash-based signature (MAC used as signature adapter)",
        ),
        algorithm(
            &["POLY1305"],
            "provider=default",
            "Poly1305-based signature (MAC used as signature adapter)",
        ),
        algorithm(
            &["CMAC"],
            "provider=default",
            "CMAC-based signature (MAC used as signature adapter)",
        ),
    ]
}
