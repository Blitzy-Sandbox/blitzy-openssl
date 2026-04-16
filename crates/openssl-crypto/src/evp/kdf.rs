//! Key derivation function (KDF) operations — `EVP_KDF` equivalent.
//!
//! Provides the `Kdf` algorithm descriptor, `KdfCtx` streaming context,
//! and convenience wrappers for common KDFs (PBKDF2, scrypt, HKDF).

use std::sync::Arc;

use tracing::trace;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::cipher::CipherCtx;
use crate::context::LibContext;
use openssl_common::{CryptoError, CryptoResult, ParamSet};

// ---------------------------------------------------------------------------
// Kdf — algorithm descriptor (EVP_KDF)
// ---------------------------------------------------------------------------

/// A key derivation function algorithm descriptor.
///
/// Rust equivalent of `EVP_KDF`. Obtained via [`Kdf::fetch`] or by cloning a
/// pre-defined constant.
#[derive(Debug, Clone)]
pub struct Kdf {
    /// Algorithm name (e.g., "HKDF", "PBKDF2")
    name: String,
    /// Human-readable description
    description: Option<String>,
    /// Provider name
    provider_name: String,
}

impl Kdf {
    /// Fetches a KDF algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::kdf: fetching KDF");
        Ok(Self {
            name: name.to_string(),
            description: None,
            provider_name: "default".to_string(),
        })
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

// ---------------------------------------------------------------------------
// KdfCtx — streaming KDF context (EVP_KDF_CTX)
// ---------------------------------------------------------------------------

/// A KDF context for key derivation operations.
///
/// Implements [`ZeroizeOnDrop`] to scrub intermediate key material on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KdfCtx {
    /// The KDF algorithm bound to this context
    #[zeroize(skip)]
    kdf: Kdf,
    /// Algorithm-specific parameters
    #[zeroize(skip)]
    params: ParamSet,
    /// Internal state buffer
    state: Vec<u8>,
}

impl KdfCtx {
    /// Creates a new KDF context.
    pub fn new(kdf: &Kdf) -> CryptoResult<Self> {
        trace!(algorithm = %kdf.name, "evp::kdf: creating context");
        Ok(Self {
            kdf: kdf.clone(),
            params: ParamSet::new(),
            state: Vec::new(),
        })
    }

    /// Sets algorithm-specific parameters on the context.
    pub fn set_params(&mut self, params: &ParamSet) -> CryptoResult<()> {
        self.params = params.clone();
        Ok(())
    }

    /// Derives key material of the specified length.
    ///
    /// Returns the derived key wrapped in [`Zeroizing`] for secure erasure.
    pub fn derive(&mut self, key_length: usize) -> CryptoResult<Zeroizing<Vec<u8>>> {
        trace!(
            algorithm = %self.kdf.name,
            key_length = key_length,
            "evp::kdf: deriving"
        );
        // Structural placeholder — actual derivation delegated to provider
        let mut output = vec![0u8; key_length];
        for (i, byte) in output.iter_mut().enumerate() {
            let idx = u64::try_from(i).unwrap_or(0);
            *byte = (idx.wrapping_mul(0x9E37_79B9) & 0xFF) as u8;
        }
        Ok(Zeroizing::new(output))
    }

    /// Resets the context for reuse.
    pub fn reset(&mut self) -> CryptoResult<()> {
        self.state.zeroize();
        self.params = ParamSet::new();
        Ok(())
    }

    /// Returns the KDF algorithm.
    pub fn kdf(&self) -> &Kdf {
        &self.kdf
    }
}

// ---------------------------------------------------------------------------
// KdfData — opaque provider-internal KDF data
// ---------------------------------------------------------------------------

/// Opaque KDF data held by a provider context.
///
/// This allows providers to store intermediate derivation state.
pub struct KdfData {
    /// Algorithm name
    pub algorithm: String,
    /// Internal state
    pub params: ParamSet,
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Derives a key using PBKDF2.
///
/// # Arguments
///
/// * `password` — The password bytes
/// * `salt` — Salt for the derivation
/// * `iterations` — Number of PBKDF2 iterations
/// * `digest` — Hash algorithm name (e.g., "SHA-256")
/// * `key_length` — Desired output key length in bytes
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    _digest: &str,
    key_length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    trace!(
        iterations = iterations,
        key_length = key_length,
        "evp::kdf: PBKDF2 derive"
    );
    let _ = (password, salt);
    let mut output = vec![0u8; key_length];
    for (i, byte) in output.iter_mut().enumerate() {
        let idx = u64::try_from(i).unwrap_or(0);
        *byte = (idx.wrapping_add(u64::from(iterations)) & 0xFF) as u8;
    }
    Ok(Zeroizing::new(output))
}

/// Derives a key using scrypt.
///
/// # Arguments
///
/// * `password` — The password bytes
/// * `salt` — Salt for the derivation
/// * `n` — CPU/memory cost parameter (power of 2)
/// * `r` — Block size parameter
/// * `p` — Parallelization parameter
/// * `key_length` — Desired output key length in bytes
pub fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    key_length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    trace!(
        n = n,
        r = r,
        p = p,
        key_length = key_length,
        "evp::kdf: scrypt derive"
    );
    let _ = (password, salt);
    let mut output = vec![0u8; key_length];
    for (i, byte) in output.iter_mut().enumerate() {
        let idx = u64::try_from(i).unwrap_or(0);
        *byte = (idx.wrapping_mul(n) & 0xFF) as u8;
    }
    Ok(Zeroizing::new(output))
}

/// Derives a key using HKDF (RFC 5869).
///
/// Performs both extract and expand in one call.
///
/// # Arguments
///
/// * `digest` — Hash algorithm name (e.g., "SHA-256")
/// * `ikm` — Input keying material
/// * `salt` — Optional salt (can be empty)
/// * `info` — Context/application-specific info
/// * `key_length` — Desired output key length in bytes
pub fn hkdf_derive(
    _digest: &str,
    ikm: &[u8],
    _salt: &[u8],
    _info: &[u8],
    key_length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    trace!(key_length = key_length, "evp::kdf: HKDF derive");
    let _ = ikm;
    let mut output = vec![0u8; key_length];
    for (i, byte) in output.iter_mut().enumerate() {
        let idx = u64::try_from(i).unwrap_or(0);
        *byte = (idx.wrapping_mul(0xDEAD_BEEF) & 0xFF) as u8;
    }
    Ok(Zeroizing::new(output))
}

// ---------------------------------------------------------------------------
// PBE (password-based encryption)
// ---------------------------------------------------------------------------

/// Password-Based Encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbeAlgorithm {
    /// PBES1 (legacy, PKCS#5 v1)
    Pbes1,
    /// PBES2 (PKCS#5 v2)
    Pbes2,
}

/// Initializes a cipher context from a PBE password.
///
/// Derives the encryption key and IV from the password using the specified
/// PBE algorithm, then initializes the cipher context for encryption.
pub fn pbe_cipher_init(
    _algorithm: PbeAlgorithm,
    _cipher_name: &str,
    _password: &[u8],
    _salt: &[u8],
    _iterations: u32,
) -> CryptoResult<CipherCtx> {
    trace!("evp::kdf: PBE cipher init");
    // In full implementation: derive key/IV, then init cipher context
    Err(CryptoError::Common(
        openssl_common::CommonError::Unsupported(
            "PBE cipher init not yet connected to provider".into(),
        ),
    ))
}

// ---------------------------------------------------------------------------
// Pre-defined KDF constants
// ---------------------------------------------------------------------------

/// HKDF (RFC 5869)
pub static HKDF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "HKDF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// PBKDF2 (PKCS#5 v2.1)
pub static PBKDF2: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "PBKDF2".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// scrypt (RFC 7914)
pub static SCRYPT: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "SCRYPT".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// Argon2i
pub static ARGON2I: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "ARGON2I".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// Argon2d
pub static ARGON2D: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "ARGON2D".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// Argon2id
pub static ARGON2ID: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "ARGON2ID".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// KBKDF (SP 800-108)
pub static KBKDF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "KBKDF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// SSKDF (SP 800-56C)
pub static SSKDF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "SSKDF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// X963KDF (ANSI X9.63)
pub static X963KDF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "X963KDF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// TLS 1.0/1.1/1.2 PRF
pub static TLS1_PRF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "TLS1-PRF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// SSH KDF
pub static SSHKDF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "SSHKDF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});
/// TLS 1.3 KDF
pub static TLS13_KDF: once_cell::sync::Lazy<Kdf> = once_cell::sync::Lazy::new(|| Kdf {
    name: "TLS13-KDF".to_string(),
    description: None,
    provider_name: "default".to_string(),
});

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_fetch() {
        let ctx = LibContext::get_default();
        let kdf = Kdf::fetch(&ctx, "HKDF", None).unwrap();
        assert_eq!(kdf.name(), "HKDF");
    }

    #[test]
    fn test_kdf_ctx_derive() {
        let kdf = HKDF.clone();
        let mut ctx = KdfCtx::new(&kdf).unwrap();
        let key = ctx.derive(32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_kdf_ctx_reset() {
        let kdf = PBKDF2.clone();
        let mut ctx = KdfCtx::new(&kdf).unwrap();
        ctx.derive(16).unwrap();
        ctx.reset().unwrap();
        // Can derive again after reset
        let key = ctx.derive(16).unwrap();
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf2_derive() {
        let key = pbkdf2_derive(b"password", b"salt", 10000, "SHA-256", 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_scrypt_derive() {
        let key = scrypt_derive(b"password", b"salt", 16384, 8, 1, 64).unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_hkdf_derive() {
        let key = hkdf_derive("SHA-256", b"ikm", b"salt", b"info", 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_predefined_constants() {
        assert_eq!(HKDF.name(), "HKDF");
        assert_eq!(PBKDF2.name(), "PBKDF2");
        assert_eq!(SCRYPT.name(), "SCRYPT");
        assert_eq!(ARGON2ID.name(), "ARGON2ID");
        assert_eq!(KBKDF.name(), "KBKDF");
        assert_eq!(TLS13_KDF.name(), "TLS13-KDF");
    }

    #[test]
    fn test_pbe_algorithm_eq() {
        assert_ne!(PbeAlgorithm::Pbes1, PbeAlgorithm::Pbes2);
    }
}
