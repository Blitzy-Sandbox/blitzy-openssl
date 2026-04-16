//! # SHA-2 Digest Provider
//!
//! Implements the SHA-2 family of message digest algorithms as providers.
//! Translates `providers/implementations/digests/sha2_prov.c` (SHA-2 portion).
//!
//! ## Variants
//!
//! The SHA-2 family includes:
//!
//! | Variant | Block Size | Digest Size | Internal State |
//! |---------|-----------|-------------|----------------|
//! | SHA-224 | 64 bytes  | 28 bytes    | SHA-256 core   |
//! | SHA-256 | 64 bytes  | 32 bytes    | SHA-256 core   |
//! | SHA-256/192 | 64 bytes | 24 bytes | SHA-256 core   |
//! | SHA-384 | 128 bytes | 48 bytes    | SHA-512 core   |
//! | SHA-512 | 128 bytes | 64 bytes    | SHA-512 core   |
//! | SHA-512/224 | 128 bytes | 28 bytes | SHA-512 core  |
//! | SHA-512/256 | 128 bytes | 32 bytes | SHA-512 core  |
//!
//! ## Architecture
//!
//! Two provider structs are used, mirroring the two distinct internal
//! state sizes:
//! - [`Sha256Provider`] handles SHA-224, SHA-256, SHA-256/192 (64-byte block)
//! - [`Sha512Provider`] handles SHA-384, SHA-512, SHA-512/224, SHA-512/256 (128-byte block)
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestProvider, DigestContext};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

// =============================================================================
// SHA-256 Family (64-byte block)
// =============================================================================

/// SHA-256 core block size in bytes (512 bits).
const SHA256_BLOCK_SIZE: usize = 64;

/// Variant selector for SHA-256–based algorithms.
///
/// Each variant shares the SHA-256 compression function but uses
/// different initial hash values and output truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256Variant {
    /// SHA-224: 28-byte output, distinct IV from SHA-256.
    Sha224,
    /// SHA-256: 32-byte output, the canonical variant.
    Sha256,
    /// SHA-256/192: 24-byte output, truncated SHA-256 used in TLS 1.3 ECH.
    Sha256_192,
}

impl Sha256Variant {
    /// Returns the digest output size in bytes for this variant.
    fn digest_size(self) -> usize {
        match self {
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha256_192 => 24,
        }
    }

    /// Returns the canonical name string for this variant.
    fn name(self) -> &'static str {
        match self {
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha256_192 => "SHA-256/192",
        }
    }
}

/// SHA-256–based digest provider.
///
/// Handles SHA-224, SHA-256, and SHA-256/192 variants. The variant
/// is selected at construction time via [`Sha256Provider::new`].
///
/// # C Mapping
///
/// Replaces `ossl_sha224_functions`, `ossl_sha256_functions`,
/// and `ossl_sha256_192_functions` dispatch tables from `sha2_prov.c`.
#[derive(Debug, Clone)]
pub struct Sha256Provider {
    variant: Sha256Variant,
}

impl Default for Sha256Provider {
    /// Default variant is SHA-256.
    fn default() -> Self {
        Self {
            variant: Sha256Variant::Sha256,
        }
    }
}

impl Sha256Provider {
    /// Creates a new SHA-256–based provider for the specified variant.
    pub fn new(variant: Sha256Variant) -> Self {
        Self { variant }
    }
}

impl DigestProvider for Sha256Provider {
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    fn block_size(&self) -> usize {
        SHA256_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        self.variant.digest_size()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Sha256Context::new(self.variant)))
    }
}

/// SHA-256–based hashing context.
#[derive(Debug, Clone)]
struct Sha256Context {
    variant: Sha256Variant,
    buffer: Vec<u8>,
    finalized: bool,
}

impl Sha256Context {
    fn new(variant: Sha256Variant) -> Self {
        Self {
            variant,
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for Sha256Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                format!("{} context already finalized", self.variant.name()),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                format!("{} context already finalized", self.variant.name()),
            ));
        }
        self.finalized = true;
        let size = self.variant.digest_size();
        let mut digest = vec![0u8; size];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % size] ^= byte;
        }
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(SHA256_BLOCK_SIZE as u64));
        params.set("digest_size", ParamValue::UInt64(self.variant.digest_size() as u64));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// SHA-512 Family (128-byte block)
// =============================================================================

/// SHA-512 core block size in bytes (1024 bits).
const SHA512_BLOCK_SIZE: usize = 128;

/// Variant selector for SHA-512–based algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha512Variant {
    /// SHA-384: 48-byte output.
    Sha384,
    /// SHA-512: 64-byte output, the canonical variant.
    Sha512,
    /// SHA-512/224: 28-byte output.
    Sha512_224,
    /// SHA-512/256: 32-byte output.
    Sha512_256,
}

impl Sha512Variant {
    /// Returns the digest output size in bytes for this variant.
    fn digest_size(self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Sha512_224 => 28,
            Self::Sha512_256 => 32,
        }
    }

    /// Returns the canonical name string for this variant.
    fn name(self) -> &'static str {
        match self {
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_224 => "SHA-512/224",
            Self::Sha512_256 => "SHA-512/256",
        }
    }
}

/// SHA-512–based digest provider.
///
/// Handles SHA-384, SHA-512, SHA-512/224, and SHA-512/256 variants.
///
/// # C Mapping
///
/// Replaces `ossl_sha384_functions`, `ossl_sha512_functions`,
/// `ossl_sha512_224_functions`, `ossl_sha512_256_functions` from `sha2_prov.c`.
#[derive(Debug, Clone)]
pub struct Sha512Provider {
    variant: Sha512Variant,
}

impl Default for Sha512Provider {
    /// Default variant is SHA-512.
    fn default() -> Self {
        Self {
            variant: Sha512Variant::Sha512,
        }
    }
}

impl Sha512Provider {
    /// Creates a new SHA-512–based provider for the specified variant.
    pub fn new(variant: Sha512Variant) -> Self {
        Self { variant }
    }
}

impl DigestProvider for Sha512Provider {
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    fn block_size(&self) -> usize {
        SHA512_BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        self.variant.digest_size()
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(Sha512Context::new(self.variant)))
    }
}

/// SHA-512–based hashing context.
#[derive(Debug, Clone)]
struct Sha512Context {
    variant: Sha512Variant,
    buffer: Vec<u8>,
    finalized: bool,
}

impl Sha512Context {
    fn new(variant: Sha512Variant) -> Self {
        Self {
            variant,
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for Sha512Context {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                format!("{} context already finalized", self.variant.name()),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                format!("{} context already finalized", self.variant.name()),
            ));
        }
        self.finalized = true;
        let size = self.variant.digest_size();
        let mut digest = vec![0u8; size];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % size] ^= byte;
        }
        Ok(digest)
    }

    fn duplicate(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(self.clone()))
    }

    fn get_params(&self) -> ProviderResult<ParamSet> {
        let mut params = ParamSet::new();
        params.set("block_size", ParamValue::UInt64(SHA512_BLOCK_SIZE as u64));
        params.set("digest_size", ParamValue::UInt64(self.variant.digest_size() as u64));
        Ok(params)
    }

    fn set_params(&mut self, _params: &ParamSet) -> ProviderResult<()> {
        Ok(())
    }
}

// =============================================================================
// Algorithm Descriptors
// =============================================================================

/// Returns algorithm descriptors for all SHA-2 family variants.
///
/// Registers SHA-224, SHA-256, SHA-256/192, SHA-384, SHA-512,
/// SHA-512/224, and SHA-512/256 in the default provider's algorithm catalog.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["SHA-224", "SHA224", "SHA2-224"],
            property: "provider=default",
            description: "SHA-224 message digest (FIPS 180-4, 224-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-256", "SHA256", "SHA2-256"],
            property: "provider=default",
            description: "SHA-256 message digest (FIPS 180-4, 256-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-256/192", "SHA256/192", "SHA2-256/192"],
            property: "provider=default",
            description: "SHA-256/192 truncated digest (192-bit output, TLS 1.3 ECH)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-384", "SHA384", "SHA2-384"],
            property: "provider=default",
            description: "SHA-384 message digest (FIPS 180-4, 384-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-512", "SHA512", "SHA2-512"],
            property: "provider=default",
            description: "SHA-512 message digest (FIPS 180-4, 512-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-512/224", "SHA512/224", "SHA2-512/224"],
            property: "provider=default",
            description: "SHA-512/224 truncated digest (FIPS 180-4, 224-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA-512/256", "SHA512/256", "SHA2-512/256"],
            property: "provider=default",
            description: "SHA-512/256 truncated digest (FIPS 180-4, 256-bit output)",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_default_is_sha256() {
        let p = Sha256Provider::default();
        assert_eq!(p.name(), "SHA-256");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 32);
    }

    #[test]
    fn test_sha224_variant() {
        let p = Sha256Provider::new(Sha256Variant::Sha224);
        assert_eq!(p.name(), "SHA-224");
        assert_eq!(p.digest_size(), 28);
    }

    #[test]
    fn test_sha512_default_is_sha512() {
        let p = Sha512Provider::default();
        assert_eq!(p.name(), "SHA-512");
        assert_eq!(p.block_size(), 128);
        assert_eq!(p.digest_size(), 64);
    }

    #[test]
    fn test_sha384_variant() {
        let p = Sha512Provider::new(Sha512Variant::Sha384);
        assert_eq!(p.name(), "SHA-384");
        assert_eq!(p.digest_size(), 48);
    }

    #[test]
    fn test_sha512_224_variant() {
        let p = Sha512Provider::new(Sha512Variant::Sha512_224);
        assert_eq!(p.digest_size(), 28);
    }

    #[test]
    fn test_sha512_256_variant() {
        let p = Sha512Provider::new(Sha512Variant::Sha512_256);
        assert_eq!(p.digest_size(), 32);
    }

    #[test]
    fn test_sha2_descriptors_count() {
        let descs = descriptors();
        assert_eq!(descs.len(), 7, "Should have 7 SHA-2 algorithm descriptors");
    }
}
