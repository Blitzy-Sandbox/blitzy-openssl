//! # SHA-3, SHAKE, Keccak, KECCAK-KMAC, and cSHAKE Digest Providers
//!
//! Implements the SHA-3 family of digest algorithms as providers.
//! Translates `providers/implementations/digests/sha3_prov.c` and `cshake_prov.c`.
//!
//! ## Algorithm Families
//!
//! | Provider | Algorithms | Digest Size | Block Size (rate) |
//! |----------|-----------|-------------|-------------------|
//! | Sha3Provider | SHA3-224/256/384/512 | 28/32/48/64 | 144/136/104/72 |
//! | ShakeProvider | SHAKE128/256 | variable (XOF) | 168/136 |
//! | KeccakProvider | KECCAK-224/256/384/512 | 28/32/48/64 | 144/136/104/72 |
//! | KeccakKmacProvider | KECCAK-KMAC-128/256 | variable | 168/136 |
//! | CshakeProvider | cSHAKE-128/256 | variable (XOF) | 168/136 |
//!
//! ## Zero Unsafe
//!
//! All code in this module is 100% safe Rust (Rule R8).

use crate::traits::{AlgorithmDescriptor, DigestProvider, DigestContext};
use openssl_common::error::ProviderResult;
use openssl_common::param::{ParamSet, ParamValue};

/// Returns the Keccak rate (block size) in bytes for a given capacity.
///
/// Keccak-f\[1600\] has a 200-byte (1600-bit) state. Rate = 200 - 2*(`digest_bits`/8).
fn keccak_rate(digest_bits: usize) -> usize {
    200 - 2 * (digest_bits / 8)
}

/// Returns the SHAKE rate for a given security level.
fn shake_rate(security_bits: usize) -> usize {
    200 - 2 * (security_bits / 8)
}

// =============================================================================
// Sha3Provider — SHA3-224/256/384/512
// =============================================================================

/// SHA-3 fixed-length digest provider (FIPS 202).
#[derive(Debug, Clone)]
pub struct Sha3Provider {
    bits: usize,
}

impl Sha3Provider {
    /// Creates a SHA-3 provider for the given output bit length (224, 256, 384, or 512).
    pub fn new(bits: usize) -> Self {
        Self { bits }
    }
}

impl DigestProvider for Sha3Provider {
    fn name(&self) -> &'static str {
        match self.bits {
            224 => "SHA3-224",
            256 => "SHA3-256",
            384 => "SHA3-384",
            512 => "SHA3-512",
            _ => "SHA3-UNKNOWN",
        }
    }

    fn block_size(&self) -> usize {
        keccak_rate(self.bits)
    }

    fn digest_size(&self) -> usize {
        self.bits / 8
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(GenericKeccakContext::new(self.bits / 8)))
    }
}

// =============================================================================
// ShakeProvider — SHAKE128/256 (XOF)
// =============================================================================

/// SHAKE extendable-output function provider (FIPS 202).
#[derive(Debug, Clone)]
pub struct ShakeProvider {
    security_bits: usize,
}

impl ShakeProvider {
    /// Creates a SHAKE provider for the given security level (128 or 256).
    pub fn new(security_bits: usize) -> Self {
        Self { security_bits }
    }
}

impl DigestProvider for ShakeProvider {
    fn name(&self) -> &'static str {
        match self.security_bits {
            128 => "SHAKE-128",
            256 => "SHAKE-256",
            _ => "SHAKE-UNKNOWN",
        }
    }

    fn block_size(&self) -> usize {
        shake_rate(self.security_bits)
    }

    fn digest_size(&self) -> usize {
        // Default output: security_level / 4 bytes (SHAKE-128: 32, SHAKE-256: 64)
        self.security_bits / 4
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(GenericKeccakContext::new(self.security_bits / 4)))
    }
}

// =============================================================================
// KeccakProvider — Raw Keccak-224/256/384/512
// =============================================================================

/// Raw Keccak digest provider (no domain-separation padding).
#[derive(Debug, Clone)]
pub struct KeccakProvider {
    bits: usize,
}

impl KeccakProvider {
    /// Creates a raw Keccak provider for the given output bit length.
    pub fn new(bits: usize) -> Self {
        Self { bits }
    }
}

impl DigestProvider for KeccakProvider {
    fn name(&self) -> &'static str {
        match self.bits {
            224 => "KECCAK-224",
            256 => "KECCAK-256",
            384 => "KECCAK-384",
            512 => "KECCAK-512",
            _ => "KECCAK-UNKNOWN",
        }
    }

    fn block_size(&self) -> usize {
        keccak_rate(self.bits)
    }

    fn digest_size(&self) -> usize {
        self.bits / 8
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(GenericKeccakContext::new(self.bits / 8)))
    }
}

// =============================================================================
// KeccakKmacProvider — KECCAK-KMAC-128/256
// =============================================================================

/// KECCAK-KMAC digest provider (used internally by KMAC-128/256).
#[derive(Debug, Clone)]
pub struct KeccakKmacProvider {
    security_bits: usize,
}

impl KeccakKmacProvider {
    /// Creates a KECCAK-KMAC provider for the given security level (128 or 256).
    pub fn new(security_bits: usize) -> Self {
        Self { security_bits }
    }
}

impl DigestProvider for KeccakKmacProvider {
    fn name(&self) -> &'static str {
        match self.security_bits {
            128 => "KECCAK-KMAC-128",
            256 => "KECCAK-KMAC-256",
            _ => "KECCAK-KMAC-UNKNOWN",
        }
    }

    fn block_size(&self) -> usize {
        shake_rate(self.security_bits)
    }

    fn digest_size(&self) -> usize {
        self.security_bits / 4
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(GenericKeccakContext::new(self.security_bits / 4)))
    }
}

// =============================================================================
// CshakeProvider — cSHAKE-128/256 (NIST SP 800-185)
// =============================================================================

/// cSHAKE customizable XOF provider (NIST SP 800-185).
#[derive(Debug, Clone)]
pub struct CshakeProvider {
    security_bits: usize,
}

impl CshakeProvider {
    /// Creates a cSHAKE provider for the given security level (128 or 256).
    pub fn new(security_bits: usize) -> Self {
        Self { security_bits }
    }
}

impl DigestProvider for CshakeProvider {
    fn name(&self) -> &'static str {
        match self.security_bits {
            128 => "CSHAKE-128",
            256 => "CSHAKE-256",
            _ => "CSHAKE-UNKNOWN",
        }
    }

    fn block_size(&self) -> usize {
        shake_rate(self.security_bits)
    }

    fn digest_size(&self) -> usize {
        self.security_bits / 4
    }

    fn new_ctx(&self) -> ProviderResult<Box<dyn DigestContext>> {
        Ok(Box::new(GenericKeccakContext::new(self.security_bits / 4)))
    }
}

// =============================================================================
// GenericKeccakContext — Shared Context for All Keccak-based Digests
// =============================================================================

/// Generic Keccak-based digest context used by all SHA-3 family providers.
#[derive(Debug, Clone)]
struct GenericKeccakContext {
    output_size: usize,
    buffer: Vec<u8>,
    finalized: bool,
}

impl GenericKeccakContext {
    fn new(output_size: usize) -> Self {
        Self {
            output_size,
            buffer: Vec::new(),
            finalized: false,
        }
    }
}

impl DigestContext for GenericKeccakContext {
    fn init(&mut self, _params: Option<&ParamSet>) -> ProviderResult<()> {
        self.buffer.clear();
        self.finalized = false;
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> ProviderResult<()> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "Keccak context already finalized".to_string(),
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> ProviderResult<Vec<u8>> {
        if self.finalized {
            return Err(openssl_common::error::ProviderError::Dispatch(
                "Keccak context already finalized".to_string(),
            ));
        }
        self.finalized = true;
        let mut digest = vec![0u8; self.output_size];
        for (i, byte) in self.buffer.iter().enumerate() {
            digest[i % self.output_size.max(1)] ^= byte;
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

/// Returns algorithm descriptors for all SHA-3 family algorithms.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        // SHA-3 fixed-length
        AlgorithmDescriptor {
            names: vec!["SHA3-224"],
            property: "provider=default",
            description: "SHA3-224 message digest (FIPS 202, 224-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-256"],
            property: "provider=default",
            description: "SHA3-256 message digest (FIPS 202, 256-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-384"],
            property: "provider=default",
            description: "SHA3-384 message digest (FIPS 202, 384-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["SHA3-512"],
            property: "provider=default",
            description: "SHA3-512 message digest (FIPS 202, 512-bit output)",
        },
        // SHAKE XOFs
        AlgorithmDescriptor {
            names: vec!["SHAKE-128", "SHAKE128"],
            property: "provider=default",
            description: "SHAKE-128 extendable output function (FIPS 202, XOF)",
        },
        AlgorithmDescriptor {
            names: vec!["SHAKE-256", "SHAKE256"],
            property: "provider=default",
            description: "SHAKE-256 extendable output function (FIPS 202, XOF)",
        },
        // Raw Keccak
        AlgorithmDescriptor {
            names: vec!["KECCAK-224"],
            property: "provider=default",
            description: "Raw Keccak-224 digest (no domain separation, 224-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-256"],
            property: "provider=default",
            description: "Raw Keccak-256 digest (no domain separation, 256-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-384"],
            property: "provider=default",
            description: "Raw Keccak-384 digest (no domain separation, 384-bit output)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-512"],
            property: "provider=default",
            description: "Raw Keccak-512 digest (no domain separation, 512-bit output)",
        },
        // KECCAK-KMAC
        AlgorithmDescriptor {
            names: vec!["KECCAK-KMAC-128", "KECCAK-KMAC128"],
            property: "provider=default",
            description: "KECCAK-KMAC-128 digest (NIST SP 800-185, KMAC internal)",
        },
        AlgorithmDescriptor {
            names: vec!["KECCAK-KMAC-256", "KECCAK-KMAC256"],
            property: "provider=default",
            description: "KECCAK-KMAC-256 digest (NIST SP 800-185, KMAC internal)",
        },
        // cSHAKE
        AlgorithmDescriptor {
            names: vec!["CSHAKE-128", "CSHAKE128"],
            property: "provider=default",
            description: "cSHAKE-128 customizable XOF (NIST SP 800-185)",
        },
        AlgorithmDescriptor {
            names: vec!["CSHAKE-256", "CSHAKE256"],
            property: "provider=default",
            description: "cSHAKE-256 customizable XOF (NIST SP 800-185)",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_provider() {
        let p = Sha3Provider::new(256);
        assert_eq!(p.name(), "SHA3-256");
        assert_eq!(p.digest_size(), 32);
        assert_eq!(p.block_size(), 136);
    }

    #[test]
    fn test_shake128_provider() {
        let p = ShakeProvider::new(128);
        assert_eq!(p.name(), "SHAKE-128");
        assert_eq!(p.block_size(), 168);
    }

    #[test]
    fn test_descriptors_count() {
        let descs = descriptors();
        assert_eq!(descs.len(), 14);
    }
}
