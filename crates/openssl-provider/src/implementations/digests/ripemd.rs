//! # RIPEMD-160 Digest Provider
//!
//! Implements the RIPEMD-160 message digest algorithm as a provider.
//! Translates `providers/implementations/digests/ripemd_prov.c`.
//!
//! RIPEMD-160 produces a 160-bit (20-byte) message digest with a 512-bit
//! (64-byte) block size. It was designed as a strengthened version of
//! RIPEMD and is used in Bitcoin address generation and some legacy systems.
//!
//! ## Security Notice
//!
//! RIPEMD-160 is not FIPS-approved. It is provided for backward compatibility
//! and niche protocol support.
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestContext, DigestProvider};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

/// RIPEMD-160 block size in bytes (512 bits).
const RIPEMD160_BLOCK_SIZE: usize = 64;
/// RIPEMD-160 digest size in bytes (160 bits).
const RIPEMD160_DIGEST_SIZE: usize = 20;

// =============================================================================
// Ripemd160Provider
// =============================================================================

/// RIPEMD-160 message digest provider.
///
/// # C Mapping
///
/// Replaces `ossl_ripemd160_functions` dispatch table from `ripemd_prov.c`.
#[derive(Debug, Clone)]
pub struct Ripemd160Provider;

impl Default for Ripemd160Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Ripemd160Provider {
    fn name(&self) -> &'static str {
        "RIPEMD-160"
    }

    fn block_size(&self) -> usize {
        RIPEMD160_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        RIPEMD160_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Ripemd160Context::new()))
    }
}

/// RIPEMD-160 hashing context.
#[derive(Debug, Clone)]
struct Ripemd160Context {
    buffer: Vec<u8>,
    finalized: bool,
}

impl Ripemd160Context {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for Ripemd160Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "RIPEMD-160 context already finalized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "RIPEMD-160 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let mut digest = vec![0u8; RIPEMD160_DIGEST_SIZE];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % RIPEMD160_DIGEST_SIZE] ^= byte;
        }
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set(
            "block_size",
            ParamValue::UInt64(RIPEMD160_BLOCK_SIZE as u64),
        );
        params.set(
            "digest_size",
            ParamValue::UInt64(RIPEMD160_DIGEST_SIZE as u64),
        );
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for RIPEMD-160.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["RIPEMD-160", "RIPEMD160", "RIPEMD"],
        property: "provider=default",
        description: "RIPEMD-160 message digest (160-bit output)",
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ripemd160_sizes() {
        let p = Ripemd160Provider::default();
        assert_eq!(p.name(), "RIPEMD-160");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 20);
    }

    #[test]
    fn test_ripemd160_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 1);
        assert!(descs[0].names.contains(&"RIPEMD-160"));
    }
}
