//! Galois/Counter Mode (GCM) — NIST SP 800-38D, RFC 5288.
//!
//! Translates `crypto/modes/gcm128.c`.  GCM combines CTR-mode encryption
//! with the GHASH universal hash to provide authenticated encryption
//! with associated data (AEAD).  It is the default TLS 1.2/1.3 AEAD for
//! AES cipher suites.
//!
//! This module re-exports the cipher-specific construction
//! [`AesGcm`](super::super::symmetric::aes::AesGcm) on the stable
//! `openssl_crypto::modes::gcm::` path mandated by the AAP §0.4.1
//! layout.  Additional AEAD variants (ChaCha20-Poly1305, AES-GCM-SIV)
//! are available under [`super`].
//!
//! ## Usage
//!
//! ```rust,no_run
//! use openssl_crypto::modes::gcm::AesGcm;
//! # fn main() -> Result<(), openssl_common::CryptoError> {
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let aad = b"associated data";
//! let plaintext = b"secret message";
//! let gcm = AesGcm::new(&key)?;
//! let ciphertext_and_tag = gcm.seal(&nonce, aad, plaintext)?;
//! let recovered = gcm.open(&nonce, aad, &ciphertext_and_tag)?;
//! assert_eq!(recovered, plaintext);
//! # Ok(()) }
//! ```
//!
//! ## Security note
//!
//! GCM's authentication is built on GHASH, whose key `H = AES_K(0)` must
//! be secret and whose nonce `(key, iv)` pair must never repeat —
//! **nonce reuse destroys both confidentiality and authenticity**.  The
//! standard recommends a random 96-bit nonce for high volumes; at
//! 2⁻³² nonce-collision risk callers must rekey.

pub use super::super::symmetric::aes::AesGcm;

/// Default AES-GCM authentication tag length in bytes (128 bits) as
/// specified by NIST SP 800-38D.  Shorter tags (96, 104, 112, 120
/// bits) are permitted by the standard but discouraged for new
/// applications.
pub const GCM_DEFAULT_TAG_LEN: usize = 16;

/// Default AES-GCM nonce length in bytes (96 bits) as specified by NIST
/// SP 800-38D §8.2.1 and RFC 5288.  Other lengths are supported by the
/// algorithm but disabled in the high-level AEAD API of [`AesGcm`].
pub const GCM_DEFAULT_NONCE_LEN: usize = 12;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_constants_match_nist_sp_800_38d() {
        assert_eq!(GCM_DEFAULT_TAG_LEN, 16);
        assert_eq!(GCM_DEFAULT_NONCE_LEN, 12);
    }

    #[test]
    fn aes_gcm_round_trip_through_modes_gcm_path() {
        // Wire test: verifies the re-export surfaces a working construction
        // via `openssl_crypto::modes::gcm::AesGcm` per Rule R10.
        let key = [0x42u8; 32];
        let nonce = [0x13u8; GCM_DEFAULT_NONCE_LEN];
        let aad = b"header";
        let plaintext = b"hello, gcm";

        let gcm = AesGcm::new(&key).unwrap_or_else(|e| panic!("gcm new: {e:?}"));
        let ct = gcm
            .seal(&nonce, aad, plaintext)
            .unwrap_or_else(|e| panic!("gcm seal: {e:?}"));
        let recovered = gcm
            .open(&nonce, aad, &ct)
            .unwrap_or_else(|e| panic!("gcm open: {e:?}"));
        assert_eq!(recovered, plaintext);
    }
}
