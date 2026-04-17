//! ChaCha20 stream cipher and ChaCha20-Poly1305 AEAD — stub for compilation.
//!
//! Full implementation provided by the assigned agent for `chacha20.rs`.
//! Translates `crypto/chacha/chacha_enc.c`.

use openssl_common::CryptoResult;
use zeroize::Zeroize;

use super::{AeadCipher, CipherAlgorithm, StreamCipher};

// =============================================================================
// ChaCha20 — 256-bit Stream Cipher
// =============================================================================

/// `ChaCha20` stream cipher (256-bit key, 96-bit nonce, 32-bit counter).
///
/// Translates `ChaCha20_ctr32` from `crypto/chacha/chacha_enc.c`.
///
/// Implements [`StreamCipher`] — the same `process` function handles both
/// encryption and decryption (XOR with keystream).
#[derive(Debug, Clone)]
pub struct ChaCha20 {
    /// 256-bit key (32 bytes).
    key: [u8; 32],
    /// 96-bit nonce (12 bytes).
    nonce: [u8; 12],
    /// Block counter.
    counter: u32,
}

impl ChaCha20 {
    /// Create a new `ChaCha20` stream cipher instance.
    ///
    /// # Arguments
    ///
    /// * `key` — 32-byte key.
    /// * `nonce` — 12-byte nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if key or nonce lengths are incorrect.
    pub fn new(key: &[u8], nonce: &[u8]) -> CryptoResult<Self> {
        if key.len() != 32 {
            return Err(openssl_common::CryptoError::Key(
                "ChaCha20 requires a 32-byte key".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(openssl_common::CryptoError::Common(
                openssl_common::CommonError::InvalidArgument(
                    "ChaCha20 requires a 12-byte nonce".into(),
                ),
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        let mut n = [0u8; 12];
        n.copy_from_slice(nonce);
        Ok(Self {
            key: k,
            nonce: n,
            counter: 0,
        })
    }
}

impl StreamCipher for ChaCha20 {
    fn process(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        // Minimal keystream generation: XOR data with key-derived bytes.
        // Full ChaCha20 quarter-round implementation to be provided by the
        // chacha20.rs agent.
        let mut output = data.to_vec();
        for (i, b) in output.iter_mut().enumerate() {
            *b ^= self.key[i % 32] ^ self.nonce[i % 12];
        }
        self.counter = self.counter.wrapping_add(1);
        Ok(output)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::ChaCha20
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

// =============================================================================
// ChaCha20Poly1305 — AEAD Stream Cipher
// =============================================================================

/// ChaCha20-Poly1305 AEAD cipher (256-bit key, 96-bit nonce, 128-bit tag).
///
/// Provides authenticated encryption per RFC 8439.
#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305 {
    /// 256-bit key (32 bytes).
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 AEAD cipher.
    ///
    /// # Arguments
    ///
    /// * `key` — 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is not 32 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 32 {
            return Err(openssl_common::CryptoError::Key(
                "ChaCha20-Poly1305 requires a 32-byte key".into(),
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl AeadCipher for ChaCha20Poly1305 {
    fn seal(&self, _nonce: &[u8], _aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Minimal: return plaintext || 16-byte zero tag.
        let mut out = plaintext.to_vec();
        out.extend_from_slice(&[0u8; 16]);
        Ok(out)
    }

    fn open(
        &self,
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return Err(openssl_common::CryptoError::Verification(
                "ChaCha20-Poly1305: ciphertext too short for tag".into(),
            ));
        }
        let ct_len = ciphertext_with_tag.len() - 16;
        Ok(ciphertext_with_tag[..ct_len].to_vec())
    }

    fn nonce_length(&self) -> usize {
        12
    }

    fn tag_length(&self) -> usize {
        16
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::ChaCha20Poly1305
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
