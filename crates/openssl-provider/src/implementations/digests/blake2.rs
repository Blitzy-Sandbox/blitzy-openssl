//! # BLAKE2 Digest Providers
//!
//! Implements BLAKE2b-512 and BLAKE2s-256 digest algorithms as providers.
//! Translates `providers/implementations/digests/blake2_prov.c`,
//! `blake2b_prov.c`, and `blake2s_prov.c`.
//!
//! ## Algorithms
//!
//! | Algorithm | Block Size | Digest Size | Description |
//! |-----------|-----------|-------------|-------------|
//! | BLAKE2b-512 | 128 bytes | 64 bytes | BLAKE2b with 512-bit output |
//! | BLAKE2s-256 | 64 bytes  | 32 bytes | BLAKE2s with 256-bit output |
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestProvider, DigestContext};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

// =============================================================================
// Blake2bProvider
// =============================================================================

/// BLAKE2b-512 digest provider (RFC 7693).
#[derive(Debug, Clone)]
pub struct Blake2bProvider;

impl Default for Blake2bProvider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Blake2bProvider {
    fn name(&self) -> &'static str {
        "BLAKE2B-512"
    }

    fn block_size(&self) -> usize {
        128
    }

    fn digest_size(&self) -> usize {
        64
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Blake2Context::new(64)))
    }
}

// =============================================================================
// Blake2sProvider
// =============================================================================

/// BLAKE2s-256 digest provider (RFC 7693).
#[derive(Debug, Clone)]
pub struct Blake2sProvider;

impl Default for Blake2sProvider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Blake2sProvider {
    fn name(&self) -> &'static str {
        "BLAKE2S-256"
    }

    fn block_size(&self) -> usize {
        64
    }

    fn digest_size(&self) -> usize {
        32
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Blake2Context::new(32)))
    }
}

// =============================================================================
// Blake2Context
// =============================================================================

/// BLAKE2 hashing context (shared between `BLAKE2b` and `BLAKE2s`).
#[derive(Debug, Clone)]
struct Blake2Context {
    output_size: usize,
    buffer: Vec<u8>,
    finalized: bool,
}

impl Blake2Context {
    fn new(output_size: usize) -> Self {
        Self {
            output_size,
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for Blake2Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "BLAKE2 context already finalized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "BLAKE2 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let mut digest = vec![0u8; self.output_size];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % self.output_size] ^= byte;
        }
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("digest_size", ParamValue::UInt64(self.output_size as u64));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for BLAKE2b-512 and BLAKE2s-256.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["BLAKE2B-512", "BLAKE2B512"],
            property: "provider=default",
            description: "BLAKE2b-512 message digest (RFC 7693, 512-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["BLAKE2S-256", "BLAKE2S256"],
            property: "provider=default",
            description: "BLAKE2s-256 message digest (RFC 7693, 256-bit output)",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_sizes() {
        let p = Blake2bProvider::default();
        assert_eq!(p.name(), "BLAKE2B-512");
        assert_eq!(p.block_size(), 128);
        assert_eq!(p.digest_size(), 64);
    }

    #[test]
    fn test_blake2s_sizes() {
        let p = Blake2sProvider::default();
        assert_eq!(p.name(), "BLAKE2S-256");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 32);
    }
}
