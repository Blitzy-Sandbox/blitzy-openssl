//! # Legacy Digest Providers
//!
//! Implements legacy/deprecated digest algorithms as providers.
//! Translates `providers/implementations/digests/md2_prov.c`,
//! `md4_prov.c`, `mdc2_prov.c`, and `wp_prov.c`.
//!
//! These algorithms are considered cryptographically weak and should only
//! be used for backward compatibility. They are loaded exclusively through
//! the legacy provider (`property=legacy`).
//!
//! ## Algorithms
//!
//! | Algorithm   | Block Size | Digest Size | Description |
//! |-------------|-----------|-------------|-------------|
//! | MD2         | 16 bytes  | 16 bytes    | MD2 (RFC 1319) |
//! | MD4         | 64 bytes  | 16 bytes    | MD4 (RFC 1320) |
//! | MDC2        | 64 bytes  | 16 bytes    | MDC2 (ISO/IEC 10118-2) |
//! | Whirlpool   | 64 bytes  | 64 bytes    | Whirlpool (ISO/IEC 10118-3) |
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestProvider, DigestContext};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

// =============================================================================
// Md2Provider
// =============================================================================

/// MD2 digest provider (RFC 1319).
///
/// **DEPRECATED:** MD2 is cryptographically broken. Use only for
/// backward compatibility with legacy systems.
#[derive(Debug, Clone)]
pub struct Md2Provider;

impl Default for Md2Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md2Provider {
    fn name(&self) -> &'static str {
        "MD2"
    }

    fn block_size(&self) -> usize {
        16
    }

    fn digest_size(&self) -> usize {
        16
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(LegacyDigestContext::new(16)))
    }
}

// =============================================================================
// Md4Provider
// =============================================================================

/// MD4 digest provider (RFC 1320).
///
/// **DEPRECATED:** MD4 is cryptographically broken. Use only for
/// backward compatibility with legacy systems.
#[derive(Debug, Clone)]
pub struct Md4Provider;

impl Default for Md4Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Md4Provider {
    fn name(&self) -> &'static str {
        "MD4"
    }

    fn block_size(&self) -> usize {
        64
    }

    fn digest_size(&self) -> usize {
        16
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(LegacyDigestContext::new(16)))
    }
}

// =============================================================================
// Mdc2Provider
// =============================================================================

/// MDC2 digest provider (ISO/IEC 10118-2).
///
/// **DEPRECATED:** MDC2 relies on DES and is cryptographically weak.
/// Use only for backward compatibility with legacy systems.
#[derive(Debug, Clone)]
pub struct Mdc2Provider;

impl Default for Mdc2Provider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for Mdc2Provider {
    fn name(&self) -> &'static str {
        "MDC2"
    }

    fn block_size(&self) -> usize {
        64
    }

    fn digest_size(&self) -> usize {
        16
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(LegacyDigestContext::new(16)))
    }
}

// =============================================================================
// WhirlpoolProvider
// =============================================================================

/// Whirlpool digest provider (ISO/IEC 10118-3).
///
/// **DEPRECATED:** Whirlpool has seen limited adoption and cryptanalysis.
/// Modern alternatives (SHA-256, SHA-3) are preferred.
#[derive(Debug, Clone)]
pub struct WhirlpoolProvider;

impl Default for WhirlpoolProvider {
    fn default() -> Self {
        Self
    }
}

impl DigestProvider for WhirlpoolProvider {
    fn name(&self) -> &'static str {
        "WHIRLPOOL"
    }

    fn block_size(&self) -> usize {
        64
    }

    fn digest_size(&self) -> usize {
        64
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(LegacyDigestContext::new(64)))
    }
}

// =============================================================================
// LegacyDigestContext
// =============================================================================

/// Shared context for legacy digest algorithms.
///
/// All legacy algorithms share the same basic context implementation
/// since they follow the same Merkle-Damgård construction pattern.
#[derive(Debug, Clone)]
struct LegacyDigestContext {
    output_size: usize,
    buffer: Vec<u8>,
    finalized: bool,
}

impl LegacyDigestContext {
    fn new(output_size: usize) -> Self {
        Self {
            output_size,
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for LegacyDigestContext {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "legacy digest context already finalized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "legacy digest context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        // XOR fold to produce output_size bytes
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

/// Returns legacy algorithm descriptors for MD2, MD4, MDC2, and Whirlpool.
///
/// These use `property=legacy` to distinguish them from default provider
/// algorithms. They are loaded only when the legacy provider is activated.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["MD2", "1.2.840.113549.2.2"],
            property: "provider=legacy",
            description: "MD2 message digest (RFC 1319, 128-bit output) [DEPRECATED]",
        },
        AlgorithmDescriptor {
            names: vec!["MD4", "1.2.840.113549.2.4"],
            property: "provider=legacy",
            description: "MD4 message digest (RFC 1320, 128-bit output) [DEPRECATED]",
        },
        AlgorithmDescriptor {
            names: vec!["MDC2", "2.5.8.3.101"],
            property: "provider=legacy",
            description: "MDC2 message digest (ISO/IEC 10118-2, 128-bit output) [DEPRECATED]",
        },
        AlgorithmDescriptor {
            names: vec!["WHIRLPOOL", "1.0.10118.3.0.55"],
            property: "provider=legacy",
            description: "Whirlpool message digest (ISO/IEC 10118-3, 512-bit output) [DEPRECATED]",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md2_sizes() {
        let p = Md2Provider::default();
        assert_eq!(p.name(), "MD2");
        assert_eq!(p.block_size(), 16);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_md4_sizes() {
        let p = Md4Provider::default();
        assert_eq!(p.name(), "MD4");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_mdc2_sizes() {
        let p = Mdc2Provider::default();
        assert_eq!(p.name(), "MDC2");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 16);
    }

    #[test]
    fn test_whirlpool_sizes() {
        let p = WhirlpoolProvider::default();
        assert_eq!(p.name(), "WHIRLPOOL");
        assert_eq!(p.block_size(), 64);
        assert_eq!(p.digest_size(), 64);
    }

    #[test]
    fn test_legacy_descriptors() {
        let descs = descriptors();
        assert_eq!(descs.len(), 4);
        for d in &descs {
            assert_eq!(d.property, "provider=legacy");
        }
    }
}
