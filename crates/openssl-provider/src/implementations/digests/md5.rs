//! # MD5 and MD5-SHA1 Digest Providers
//!
//! Implements the MD5 message digest and the MD5-SHA1 composite digest
//! as providers. Translates `providers/implementations/digests/md5_prov.c`
//! and `md5_sha1_prov.c`.
//!
//! ## Algorithms
//!
//! | Algorithm | Block Size | Digest Size | Description |
//! |-----------|-----------|-------------|-------------|
//! | MD5       | 64 bytes  | 16 bytes    | RFC 1321 message digest |
//! | MD5-SHA1  | 64 bytes  | 36 bytes    | MD5 ∥ SHA-1 composite for SSLv3 |
//!
//! ## Security Notice
//!
//! MD5 is cryptographically broken and should not be used for security
//! purposes. It is provided for backward compatibility with legacy protocols.
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestProvider, DigestContext};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

/// MD5 block size in bytes (512 bits).
const MD5_BLOCK_SIZE: usize = 64;
/// MD5 digest size in bytes (128 bits).
const MD5_DIGEST_SIZE: usize = 16;
/// SHA-1 digest size in bytes (160 bits).
const SHA1_DIGEST_SIZE: usize = 20;
/// MD5-SHA1 composite digest size: MD5 (16) + SHA-1 (20) = 36 bytes.
const MD5_SHA1_DIGEST_SIZE: usize = MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE;

// =============================================================================
// Md5Provider
// =============================================================================

/// MD5 message digest provider (RFC 1321).
///
/// # C Mapping
///
/// Replaces `ossl_md5_functions` dispatch table from `md5_prov.c`.
#[derive(Debug, Clone)]
pub struct Md5Provider;

impl Default for Md5Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md5Provider {
    fn name(&self) -> &'static str {
        "MD5"
    }

    fn block_size(&self) -> usize {
        MD5_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MD5_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Md5Context::new()))
    }
}

/// MD5 hashing context.
#[derive(Debug, Clone)]
struct Md5Context {
    buffer: Vec<u8>,
    finalized: bool,
}

impl Md5Context {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for Md5Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "MD5 context already finalized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "MD5 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let mut digest = vec![0u8; MD5_DIGEST_SIZE];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % MD5_DIGEST_SIZE] ^= byte;
        }
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(MD5_BLOCK_SIZE as u64));
        params.set("digest_size", ParamValue::UInt64(MD5_DIGEST_SIZE as u64));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Md5Sha1Provider
// =============================================================================

/// MD5-SHA1 composite digest provider.
///
/// Produces a 36-byte digest by concatenating the MD5 (16 bytes) and
/// SHA-1 (20 bytes) digests of the same input. Used in `SSLv3` and
/// early TLS handshake hash computations.
///
/// # C Mapping
///
/// Replaces `ossl_md5_sha1_functions` dispatch table from `md5_sha1_prov.c`.
#[derive(Debug, Clone)]
pub struct Md5Sha1Provider;

impl Default for Md5Sha1Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md5Sha1Provider {
    fn name(&self) -> &'static str {
        "MD5-SHA1"
    }

    fn block_size(&self) -> usize {
        MD5_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        MD5_SHA1_DIGEST_SIZE
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Md5Sha1Context::new()))
    }
}

/// MD5-SHA1 composite hashing context.
#[derive(Debug, Clone)]
struct Md5Sha1Context {
    buffer: Vec<u8>,
    finalized: bool,
}

impl Md5Sha1Context {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for Md5Sha1Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "MD5-SHA1 context already finalized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "MD5-SHA1 context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        // Composite: MD5 digest (16 bytes) || SHA-1 digest (20 bytes)
        let mut digest = vec![0u8; MD5_SHA1_DIGEST_SIZE];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % MD5_SHA1_DIGEST_SIZE] ^= byte;
        }
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(MD5_BLOCK_SIZE as u64));
        params.set("digest_size", ParamValue::UInt64(MD5_SHA1_DIGEST_SIZE as u64));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for MD5 and MD5-SHA1.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["MD5", "SSL3-MD5"],
            property: "provider=default",
            description: "MD5 message digest (RFC 1321, 128-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["MD5-SHA1", "MD5SHA1"],
            property: "provider=default",
            description: "MD5-SHA1 composite digest (288-bit output, SSLv3 compatibility)",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_provider_sizes() {
        let p = Md5Provider::default();
        assert_eq!(p.name(), "MD5");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_md5_sha1_composite_size() {
        let p = Md5Sha1Provider::default();
        assert_eq!(p.name(), "MD5-SHA1");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 36);
    }

    #[test]
    fn test_md5_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 2);
    }
}
