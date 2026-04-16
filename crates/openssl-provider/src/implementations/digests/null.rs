//! # NULL Digest Provider
//!
//! Implements the NULL (passthrough) digest algorithm as a provider.
//! Translates `providers/implementations/digests/null_prov.c`.
//!
//! The NULL digest is a zero-length digest that produces no output.
//! It serves as a sentinel/placeholder when a digest algorithm is
//! required by the API but no actual hashing should occur (e.g.,
//! RSA-PSS with no hash, or for testing infrastructure).
//!
//! ## Properties
//!
//! - Block size: 0 bytes
//! - Digest size: 0 bytes
//! - Flags: `ALGID_ABSENT` (no AlgorithmIdentifier OID)
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestProvider, DigestContext};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

// =============================================================================
// NullDigestProvider
// =============================================================================

/// NULL (zero-length) digest provider — passthrough sentinel.
///
/// Produces a 0-byte digest regardless of input. `update()` accepts
/// data but discards it. `finalize()` returns an empty vector.
///
/// # C Mapping
///
/// Replaces `ossl_nullmd_functions` dispatch table from `null_prov.c`.
#[derive(Debug, Clone)]
pub struct NullDigestProvider;

impl Default for NullDigestProvider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for NullDigestProvider {
    fn name(&self) -> &'static str {
        "NULL"
    }

    fn block_size(&self) -> usize {
        0
    }

    fn digest_size(&self) -> usize {
        0
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(NullDigestContext))
    }
}

// =============================================================================
// NullDigestContext
// =============================================================================

/// NULL digest context — all operations are no-ops.
#[derive(Debug, Clone)]
struct NullDigestContext;

impl DigestContext for NullDigestContext {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        Ok(())
    }

    fn update(&mut self, _data: &[u8]) -> ProviderResult<()> {
        // Passthrough — data is discarded.
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        // Zero-length digest.
        Ok(Vec::new())
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(0));
        params.set("digest_size", ParamValue::UInt64(0));
        params.set("algid_absent", ParamValue::UInt64(1));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for the NULL digest.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["NULL"],
        property: "provider=default",
        description: "NULL digest (0-bit output, passthrough sentinel)",
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_provider_sizes() {
        let p = NullDigestProvider::default();
        assert_eq!(p.name(), "NULL");
        assert_eq!(p.block_size(), 0);
        assert_eq!(p.digest_size(), 0);
    }

    #[test]
    fn test_null_context_finalize_empty() {
        let p = NullDigestProvider::default();
        let mut ctx = p.new_ctx().expect("new_ctx should succeed");
        ctx.init(None).expect("init should succeed");
        ctx.update(b"ignored data").expect("update should succeed");
        let digest = ctx.finalize().expect("finalize should succeed");
        assert!(digest.is_empty(), "NULL digest should produce empty output");
    }

    #[test]
    fn test_null_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"NULL"));
    }
}
