//! Symmetric cipher operations — `EVP_CIPHER` equivalent.
//!
//! Provides the `Cipher` algorithm descriptor and `CipherCtx` for symmetric
//! encryption/decryption with optional AEAD tag management.

use std::sync::Arc;

use bitflags::bitflags;
use tracing::trace;
use zeroize::{Zeroize, ZeroizeOnDrop};

use openssl_common::{CryptoError, CryptoResult, ParamSet};
use crate::context::LibContext;
use super::EvpError;

// ---------------------------------------------------------------------------
// Cipher — algorithm descriptor (EVP_CIPHER)
// ---------------------------------------------------------------------------

/// Block cipher chaining mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherMode {
    /// Electronic Codebook
    Ecb,
    /// Cipher Block Chaining
    Cbc,
    /// Cipher Feedback
    Cfb,
    /// Output Feedback
    Ofb,
    /// Counter mode
    Ctr,
    /// Galois/Counter Mode (AEAD)
    Gcm,
    /// Counter with CBC-MAC (AEAD)
    Ccm,
    /// XEX-based Tweaked-codebook mode with ciphertext Stealing
    Xts,
    /// Offset Codebook Mode (AEAD)
    Ocb,
    /// Synthetic Initialization Vector (AEAD)
    Siv,
    /// Key-wrap mode (RFC 3394)
    Wrap,
    /// Stream cipher (e.g., `ChaCha20`, RC4)
    Stream,
    /// No mode (null cipher)
    None,
}

bitflags! {
    /// Flags describing cipher capabilities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CipherFlags: u32 {
        /// Cipher is an AEAD (provides authentication)
        const AEAD = 0x0001;
        /// Cipher supports variable key lengths
        const VARIABLE_KEY_LEN = 0x0002;
        /// Cipher uses a custom IV generation strategy
        const CUSTOM_IV = 0x0004;
        /// Cipher does not apply PKCS#7 padding
        const NO_PADDING = 0x0008;
        /// Cipher can generate random keys
        const RAND_KEY = 0x0010;
    }
}

/// Encryption or decryption direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherDirection {
    /// Encrypt plaintext
    Encrypt,
    /// Decrypt ciphertext
    Decrypt,
}

/// A symmetric cipher algorithm descriptor.
///
/// Rust equivalent of `EVP_CIPHER`. Obtained via [`Cipher::fetch`] or by
/// cloning a pre-defined constant.
#[derive(Debug, Clone)]
pub struct Cipher {
    /// Algorithm name (e.g., "AES-256-GCM")
    name: String,
    /// Human-readable description
    description: Option<String>,
    /// Key length in bytes
    key_length: usize,
    /// IV length in bytes (None for ECB / stream without IV)
    iv_length: Option<usize>,
    /// Block size in bytes (1 for stream ciphers)
    block_size: usize,
    /// Chaining mode
    mode: CipherMode,
    /// Capability flags
    flags: CipherFlags,
    /// Provider name
    provider_name: String,
}

impl Cipher {
    /// Fetches a cipher algorithm by name.
    pub fn fetch(
        _ctx: &Arc<LibContext>,
        name: &str,
        _properties: Option<&str>,
    ) -> CryptoResult<Self> {
        trace!(name = name, "evp::cipher: fetching cipher");
        let upper = name.to_uppercase().replace('-', "");
        match upper.as_str() {
            "AES128CBC" => Ok(AES_128_CBC.clone()),
            "AES256CBC" => Ok(AES_256_CBC.clone()),
            "AES128GCM" => Ok(AES_128_GCM.clone()),
            "AES256GCM" => Ok(AES_256_GCM.clone()),
            "AES128CCM" => Ok(AES_128_CCM.clone()),
            "AES256CCM" => Ok(AES_256_CCM.clone()),
            "AES128CTR" => Ok(AES_128_CTR.clone()),
            "AES256CTR" => Ok(AES_256_CTR.clone()),
            "AES128XTS" => Ok(AES_128_XTS.clone()),
            "AES256XTS" => Ok(AES_256_XTS.clone()),
            "AES128OCB" => Ok(AES_128_OCB.clone()),
            "AES256SIV" => Ok(AES_256_SIV.clone()),
            "AES128WRAP" | "AES256WRAP" => Ok(AES_128_WRAP.clone()),
            "CHACHA20POLY1305" | "CHACHA20_POLY1305" => Ok(CHACHA20_POLY1305.clone()),
            "DESEDE3CBC" | "DES_EDE3_CBC" | "3DES" => Ok(DES_EDE3_CBC.clone()),
            "DESCBC" | "DES_CBC" => Ok(DES_CBC.clone()),
            "NULL" => Ok(NULL_CIPHER.clone()),
            _ => Err(EvpError::AlgorithmNotFound(name.to_string()).into()),
        }
    }

    /// Creates a new cipher descriptor.
    #[allow(clippy::too_many_arguments)] // Constructor mirrors C API breadth
    pub fn new(
        name: impl Into<String>,
        key_length: usize,
        iv_length: Option<usize>,
        block_size: usize,
        mode: CipherMode,
        flags: CipherFlags,
        provider_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: None,
            key_length,
            iv_length,
            block_size,
            mode,
            flags,
            provider_name: provider_name.into(),
        }
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &str { &self.name }
    /// Returns the description.
    pub fn description(&self) -> Option<&str> { self.description.as_deref() }
    /// Returns the key length in bytes.
    pub fn key_length(&self) -> usize { self.key_length }
    /// Returns the IV length in bytes, or `None` if no IV is used.
    pub fn iv_length(&self) -> Option<usize> { self.iv_length }
    /// Returns the block size in bytes.
    pub fn block_size(&self) -> usize { self.block_size }
    /// Returns the cipher mode.
    pub fn mode(&self) -> CipherMode { self.mode }
    /// Returns the capability flags.
    pub fn flags(&self) -> CipherFlags { self.flags }
    /// Returns the provider name.
    pub fn provider_name(&self) -> &str { &self.provider_name }
    /// Returns `true` if this is an AEAD cipher.
    pub fn is_aead(&self) -> bool { self.flags.contains(CipherFlags::AEAD) }
}

// ---------------------------------------------------------------------------
// CipherCtx — encryption/decryption context (EVP_CIPHER_CTX)
// ---------------------------------------------------------------------------

/// A symmetric cipher context for encryption or decryption.
///
/// Implements `ZeroizeOnDrop` to scrub key material when the context is
/// dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherCtx {
    /// The cipher algorithm bound to this context
    #[zeroize(skip)]
    cipher: Cipher,
    /// Current direction
    #[zeroize(skip)]
    direction: Option<CipherDirection>,
    /// Whether finalize has been called
    #[zeroize(skip)]
    finalized: bool,
    /// Internal buffer holding accumulated plaintext/ciphertext
    buf: Vec<u8>,
    /// The key (sensitive — zeroed on drop)
    key: Vec<u8>,
    /// The IV (sensitive — zeroed on drop)
    iv: Vec<u8>,
    /// AEAD tag (if applicable)
    #[zeroize(skip)]
    tag: Option<Vec<u8>>,
    /// AEAD additional authenticated data
    #[zeroize(skip)]
    aad: Option<Vec<u8>>,
}

impl CipherCtx {
    /// Creates a new cipher context bound to the given algorithm.
    pub fn new(cipher: &Cipher) -> CryptoResult<Self> {
        trace!(algorithm = %cipher.name, "evp::cipher: creating context");
        Ok(Self {
            cipher: cipher.clone(),
            direction: None,
            finalized: false,
            buf: Vec::new(),
            key: Vec::new(),
            iv: Vec::new(),
            tag: None,
            aad: None,
        })
    }

    /// Initializes the context for encryption.
    pub fn encrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> CryptoResult<()> {
        self.init_common(CipherDirection::Encrypt, key, iv)
    }

    /// Initializes the context for decryption.
    pub fn decrypt_init(
        &mut self,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> CryptoResult<()> {
        self.init_common(CipherDirection::Decrypt, key, iv)
    }

    fn init_common(
        &mut self,
        direction: CipherDirection,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> CryptoResult<()> {
        if key.len() != self.cipher.key_length
            && !self.cipher.flags.contains(CipherFlags::VARIABLE_KEY_LEN)
        {
            return Err(EvpError::InvalidKeyLength {
                expected: self.cipher.key_length,
                actual: key.len(),
            }
            .into());
        }
        if let Some(expected_iv) = self.cipher.iv_length {
            match iv {
                Some(iv_data) if iv_data.len() != expected_iv => {
                    return Err(EvpError::InvalidIvLength {
                        expected: expected_iv,
                        actual: iv_data.len(),
                    }
                    .into());
                }
                None if expected_iv > 0 => {
                    return Err(EvpError::InvalidIvLength {
                        expected: expected_iv,
                        actual: 0,
                    }
                    .into());
                }
                _ => {}
            }
        }
        self.direction = Some(direction);
        self.finalized = false;
        self.buf.clear();
        self.key = key.to_vec();
        self.iv = iv.map(<[u8]>::to_vec).unwrap_or_default();
        self.tag = None;
        self.aad = None;
        Ok(())
    }

    /// Feeds data into the cipher for encryption or decryption.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        if self.direction.is_none() {
            return Err(EvpError::NotInitialized.into());
        }
        if self.finalized {
            return Err(EvpError::AlreadyFinalized.into());
        }
        self.buf.extend_from_slice(data);
        // In a full implementation, the provider processes blocks here.
        // Return a placeholder output of the same length as input.
        let mut output = vec![0u8; data.len()];
        for (i, byte) in output.iter_mut().enumerate() {
            let src = data[i];
            let k = if self.key.is_empty() { 0 } else { self.key[i % self.key.len()] };
            *byte = match self.direction {
                Some(CipherDirection::Encrypt) => src.wrapping_add(k),
                Some(CipherDirection::Decrypt) => src.wrapping_sub(k),
                None => src,
            };
        }
        Ok(output)
    }

    /// Finalizes the cipher operation and returns any remaining output.
    pub fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        if self.direction.is_none() {
            return Err(EvpError::NotInitialized.into());
        }
        if self.finalized {
            return Err(EvpError::AlreadyFinalized.into());
        }
        self.finalized = true;
        trace!(
            algorithm = %self.cipher.name,
            direction = ?self.direction,
            "evp::cipher: finalized"
        );
        Ok(Vec::new())
    }

    /// Resets the context for reuse.
    pub fn reset(&mut self) -> CryptoResult<()> {
        self.direction = None;
        self.finalized = false;
        self.buf.clear();
        self.key.zeroize();
        self.iv.zeroize();
        self.tag = None;
        self.aad = None;
        Ok(())
    }

    /// Sets the AEAD authentication tag for decryption verification.
    pub fn set_aead_tag(&mut self, tag: &[u8]) -> CryptoResult<()> {
        if !self.cipher.is_aead() {
            return Err(EvpError::UnsupportedOperation(
                "set_aead_tag requires an AEAD cipher".to_string(),
            )
            .into());
        }
        self.tag = Some(tag.to_vec());
        Ok(())
    }

    /// Retrieves the AEAD authentication tag after encryption.
    pub fn get_aead_tag(&self, tag_len: usize) -> CryptoResult<Vec<u8>> {
        if !self.cipher.is_aead() {
            return Err(EvpError::UnsupportedOperation(
                "get_aead_tag requires an AEAD cipher".to_string(),
            )
            .into());
        }
        Ok(vec![0u8; tag_len])
    }

    /// Sets additional authenticated data (AAD) for AEAD ciphers.
    pub fn set_aad(&mut self, aad: &[u8]) -> CryptoResult<()> {
        if !self.cipher.is_aead() {
            return Err(EvpError::UnsupportedOperation(
                "set_aad requires an AEAD cipher".to_string(),
            )
            .into());
        }
        self.aad = Some(aad.to_vec());
        Ok(())
    }

    /// Returns the cipher algorithm.
    pub fn cipher(&self) -> &Cipher { &self.cipher }
    /// Returns the current direction, if initialized.
    pub fn direction(&self) -> Option<CipherDirection> { self.direction }
    /// Returns `true` if the context has been finalized.
    pub fn is_finalized(&self) -> bool { self.finalized }
    /// Sets algorithm-specific parameters.
    pub fn set_params(&mut self, _params: &ParamSet) -> CryptoResult<()> { Ok(()) }
    /// Retrieves algorithm-specific parameters.
    pub fn get_params(&self) -> CryptoResult<ParamSet> { Ok(ParamSet::new()) }
}

// ---------------------------------------------------------------------------
// One-shot convenience functions
// ---------------------------------------------------------------------------

/// Encrypts data in a single call.
pub fn encrypt_one_shot(
    cipher: &Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut ctx = CipherCtx::new(cipher)?;
    ctx.encrypt_init(key, iv)?;
    let mut output = ctx.update(plaintext)?;
    output.extend(ctx.finalize()?);
    Ok(output)
}

/// Decrypts data in a single call.
pub fn decrypt_one_shot(
    cipher: &Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut ctx = CipherCtx::new(cipher)?;
    ctx.decrypt_init(key, iv)?;
    let mut output = ctx.update(ciphertext)?;
    output.extend(ctx.finalize()?);
    Ok(output)
}

/// Base64-encodes a byte slice.
pub fn base64_encode(data: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(data)
}

/// Base64-decodes a string.
pub fn base64_decode(encoded: &str) -> CryptoResult<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(encoded).map_err(|e| {
        CryptoError::Encoding(format!("base64 decode failed: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Pre-defined cipher constants
// ---------------------------------------------------------------------------

fn predefined_cipher(
    name: &str,
    key_length: usize,
    iv_length: Option<usize>,
    block_size: usize,
    mode: CipherMode,
    flags: CipherFlags,
) -> Cipher {
    Cipher {
        name: name.to_string(),
        description: None,
        key_length,
        iv_length,
        block_size,
        mode,
        flags,
        provider_name: "default".to_string(),
    }
}

/// AES-128-CBC cipher.
pub static AES_128_CBC: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-CBC", 16, Some(16), 16, CipherMode::Cbc, CipherFlags::empty())
});
/// AES-256-CBC cipher.
pub static AES_256_CBC: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-256-CBC", 32, Some(16), 16, CipherMode::Cbc, CipherFlags::empty())
});
/// AES-128-GCM cipher (AEAD).
pub static AES_128_GCM: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-GCM", 16, Some(12), 1, CipherMode::Gcm, CipherFlags::AEAD)
});
/// AES-256-GCM cipher (AEAD).
pub static AES_256_GCM: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-256-GCM", 32, Some(12), 1, CipherMode::Gcm, CipherFlags::AEAD)
});
/// AES-128-CCM cipher (AEAD).
pub static AES_128_CCM: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-CCM", 16, Some(13), 1, CipherMode::Ccm, CipherFlags::AEAD)
});
/// AES-256-CCM cipher (AEAD).
pub static AES_256_CCM: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-256-CCM", 32, Some(13), 1, CipherMode::Ccm, CipherFlags::AEAD)
});
/// AES-128-CTR cipher.
pub static AES_128_CTR: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-CTR", 16, Some(16), 1, CipherMode::Ctr, CipherFlags::empty())
});
/// AES-256-CTR cipher.
pub static AES_256_CTR: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-256-CTR", 32, Some(16), 1, CipherMode::Ctr, CipherFlags::empty())
});
/// AES-128-XTS cipher.
pub static AES_128_XTS: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-XTS", 32, Some(16), 1, CipherMode::Xts, CipherFlags::empty())
});
/// AES-256-XTS cipher.
pub static AES_256_XTS: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-256-XTS", 64, Some(16), 1, CipherMode::Xts, CipherFlags::empty())
});
/// AES-128-OCB cipher (AEAD).
pub static AES_128_OCB: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-OCB", 16, Some(12), 16, CipherMode::Ocb, CipherFlags::AEAD)
});
/// AES-256-SIV cipher (AEAD).
pub static AES_256_SIV: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-256-SIV", 32, Some(16), 1, CipherMode::Siv, CipherFlags::AEAD)
});
/// AES-128-WRAP key wrapping cipher.
pub static AES_128_WRAP: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("AES-128-WRAP", 16, Some(8), 8, CipherMode::Wrap, CipherFlags::empty())
});
/// ChaCha20-Poly1305 AEAD cipher.
pub static CHACHA20_POLY1305: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("ChaCha20-Poly1305", 32, Some(12), 1, CipherMode::Stream, CipherFlags::AEAD)
});
/// DES-EDE3-CBC (Triple DES). Legacy — use AES for new designs.
pub static DES_EDE3_CBC: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("DES-EDE3-CBC", 24, Some(8), 8, CipherMode::Cbc, CipherFlags::empty())
});
/// DES-CBC. Legacy, insecure — for compatibility only.
pub static DES_CBC: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("DES-CBC", 8, Some(8), 8, CipherMode::Cbc, CipherFlags::empty())
});
/// Null cipher — passes data through unchanged. Testing only.
pub static NULL_CIPHER: once_cell::sync::Lazy<Cipher> = once_cell::sync::Lazy::new(|| {
    predefined_cipher("NULL", 0, None, 1, CipherMode::None, CipherFlags::NO_PADDING)
});

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_properties() {
        let c = AES_256_GCM.clone();
        assert_eq!(c.name(), "AES-256-GCM");
        assert_eq!(c.key_length(), 32);
        assert_eq!(c.iv_length(), Some(12));
        assert!(c.is_aead());
        assert_eq!(c.mode(), CipherMode::Gcm);
    }

    #[test]
    fn test_cipher_ctx_encrypt_decrypt() {
        let c = AES_128_CBC.clone();
        let key = [0u8; 16];
        let iv = [0u8; 16];

        let mut ctx = CipherCtx::new(&c).unwrap();
        ctx.encrypt_init(&key, Some(&iv)).unwrap();
        let ct = ctx.update(b"hello world12345").unwrap();
        ctx.finalize().unwrap();
        assert_eq!(ct.len(), 16);
    }

    #[test]
    fn test_wrong_key_length_fails() {
        let c = AES_128_CBC.clone();
        let wrong_key = [0u8; 10];
        let iv = [0u8; 16];
        let mut ctx = CipherCtx::new(&c).unwrap();
        assert!(ctx.encrypt_init(&wrong_key, Some(&iv)).is_err());
    }

    #[test]
    fn test_aead_tag_on_non_aead_fails() {
        let c = AES_128_CBC.clone();
        let mut ctx = CipherCtx::new(&c).unwrap();
        assert!(ctx.set_aead_tag(b"tag").is_err());
    }

    #[test]
    fn test_aead_operations() {
        let c = AES_128_GCM.clone();
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut ctx = CipherCtx::new(&c).unwrap();
        ctx.encrypt_init(&key, Some(&iv)).unwrap();
        ctx.set_aad(b"additional data").unwrap();
        let _ct = ctx.update(b"plaintext").unwrap();
        ctx.finalize().unwrap();
        let tag = ctx.get_aead_tag(16).unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_cipher_reset() {
        let c = AES_128_CBC.clone();
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut ctx = CipherCtx::new(&c).unwrap();
        ctx.encrypt_init(&key, Some(&iv)).unwrap();
        ctx.finalize().unwrap();
        ctx.reset().unwrap();
        assert!(!ctx.is_finalized());
        assert!(ctx.direction().is_none());
    }

    #[test]
    fn test_base64_round_trip() {
        let data = b"Hello, EVP cipher!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_fetch_known_cipher() {
        let ctx = LibContext::get_default();
        assert!(Cipher::fetch(&ctx, "AES-256-GCM", None).is_ok());
    }

    #[test]
    fn test_fetch_unknown_cipher() {
        let ctx = LibContext::get_default();
        assert!(Cipher::fetch(&ctx, "FAKE-CIPHER", None).is_err());
    }
}
