//! XEX Tweakable Block Cipher with Ciphertext Stealing (XTS) mode.
//!
//! This module provides a thin re-export facade for the XTS disk-encryption
//! mode. The canonical implementation lives in [`crate::symmetric::aes::AesXts`]
//! and this module exposes it under the per-mode crate layout mandated by
//! AAP §0.4.1.
//!
//! # Standards
//!
//! * IEEE Std 1619-2007 — *Standard for Cryptographic Protection of Data on
//!   Block-Oriented Storage Devices*
//! * NIST SP 800-38E — *Recommendation for Block Cipher Modes of Operation:
//!   The XTS-AES Mode for Confidentiality on Storage Devices*
//!
//! # Provenance
//!
//! Translated from `crypto/modes/xts128.c` and `providers/implementations/
//! ciphers/cipher_aes_xts*.c` in the upstream OpenSSL 4.0 source tree.
//!
//! # Security considerations
//!
//! * XTS is designed for disk-sector-level encryption, not general
//!   confidentiality. It provides confidentiality but NO authenticity —
//!   callers that require integrity MUST layer a MAC on top.
//! * Each sector MUST be encrypted with a unique tweak (typically the
//!   sector index encoded as a 128-bit little-endian integer).
//! * Plaintext shorter than one cipher block is rejected by the standard.
//!   `AesXts::encrypt`/`decrypt` handle ciphertext stealing for inputs
//!   larger than one block but not a multiple of the block size.
//! * XTS-AES requires a *double-length* key: XTS-AES-128 uses a 32-byte key
//!   (two AES-128 keys concatenated), XTS-AES-256 uses a 64-byte key.
//! * The two halves of the key MUST differ — identical halves are rejected
//!   per NIST SP 800-38E §5.1.
//!
//! # Examples
//!
//! ```no_run
//! use openssl_crypto::modes::xts::AesXts;
//!
//! // 32-byte key = two AES-128 keys concatenated.
//! let key = [0x11u8; 32];
//! // 16-byte tweak (sector index or similar).
//! let tweak = [0u8; 16];
//! // Plaintext must be at least one block (16 bytes).
//! let plaintext = b"sector data .....";
//!
//! let xts = AesXts::new(&key).expect("valid key");
//! let ciphertext = xts.encrypt(&tweak, plaintext).expect("encrypt");
//! let recovered = xts.decrypt(&tweak, &ciphertext).expect("decrypt");
//! assert_eq!(recovered, plaintext);
//! ```

// Re-export the canonical XTS type. The `pub use` preserves all methods
// (`new`, `encrypt`, `decrypt`) and their documentation.
pub use super::super::symmetric::aes::AesXts;

/// XTS-AES block size in bytes. Per IEEE Std 1619-2007 §5.1, this is fixed
/// at 16 (the AES block size).
pub const XTS_BLOCK_SIZE: usize = 16;

/// XTS-AES tweak size in bytes. Per IEEE Std 1619-2007 §5.1, the tweak is a
/// 128-bit value encoded in little-endian byte order.
pub const XTS_TWEAK_LEN: usize = 16;

/// XTS-AES-128 key length in bytes (two concatenated AES-128 keys).
pub const XTS_AES_128_KEY_LEN: usize = 32;

/// XTS-AES-256 key length in bytes (two concatenated AES-256 keys).
pub const XTS_AES_256_KEY_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xts_constants_match_ieee_1619() {
        // Per IEEE Std 1619-2007 §5.1 — XTS operates on AES blocks.
        assert_eq!(XTS_BLOCK_SIZE, 16);
        assert_eq!(XTS_TWEAK_LEN, 16);
        // Per IEEE Std 1619-2007 §5.1 — XTS uses double-length keys.
        assert_eq!(XTS_AES_128_KEY_LEN, 32);
        assert_eq!(XTS_AES_256_KEY_LEN, 64);
    }

    #[test]
    fn aes_xts_round_trip_through_modes_xts_path() {
        // Verify the re-exported type is reachable and functional from this
        // module path. This exercises the §0.4.1 crate layout requirement.
        let mut key = [0u8; XTS_AES_128_KEY_LEN];
        // Two halves must differ (NIST SP 800-38E §5.1).
        for (i, b) in key.iter_mut().enumerate().take(16) {
            *b = i as u8;
        }
        for (i, b) in key.iter_mut().enumerate().skip(16) {
            *b = 0x80 | (i as u8);
        }
        let tweak = [0xABu8; XTS_TWEAK_LEN];
        // Plaintext: exactly one block (tight lower bound).
        let plaintext: [u8; 16] = *b"xts sector data!";

        let xts = AesXts::new(&key).expect("XTS-AES-128 key install");
        let ct = xts.encrypt(&tweak, &plaintext).expect("encrypt");
        let pt = xts.decrypt(&tweak, &ct).expect("decrypt");
        assert_eq!(pt, plaintext.to_vec());
        // Sanity: ciphertext must differ from plaintext.
        assert_ne!(ct, plaintext.to_vec());
    }

    #[test]
    fn aes_xts_identical_key_halves_rejected() {
        // Per NIST SP 800-38E §5.1 — K1 == K2 is forbidden to prevent
        // trivial distinguishing attacks.
        let key = [0x42u8; XTS_AES_128_KEY_LEN];
        assert!(
            AesXts::new(&key).is_err(),
            "XTS must reject identical key halves"
        );
    }
}
