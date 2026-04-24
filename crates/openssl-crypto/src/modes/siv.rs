//! Synthetic Initialization Vector (SIV) AEAD mode.
//!
//! This module provides a thin re-export facade for the SIV nonce-misuse-
//! resistant AEAD mode. The canonical implementation lives in
//! [`crate::symmetric::aes::AesSiv`] and this module exposes it under the
//! per-mode crate layout mandated by AAP §0.4.1.
//!
//! # Standards
//!
//! * RFC 5297 — *Synthetic Initialization Vector (SIV) Authenticated
//!   Encryption Using the Advanced Encryption Standard (AES)*
//! * RFC 8452 — *AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption*
//!
//! # Provenance
//!
//! Translated from `providers/implementations/ciphers/cipher_aes_siv*.c` in
//! the upstream OpenSSL 4.0 source tree.
//!
//! # Security considerations
//!
//! * SIV is the premier *nonce-misuse-resistant* AEAD mode: accidentally
//!   reusing a nonce with SIV leaks only message equality, NOT the plaintext
//!   or the key. This property makes SIV the correct choice when nonce
//!   uniqueness cannot be guaranteed (e.g., stateless deterministic
//!   encryption).
//! * Callers still SHOULD use fresh, unique nonces whenever possible —
//!   misuse resistance is a safety net, not a license for sloppy nonce
//!   management.
//! * SIV is a two-pass construction requiring buffering of the complete
//!   plaintext before the synthetic IV can be computed. It is NOT suitable
//!   for streaming encryption with bounded memory.
//! * SIV uses a *double-length* key: AES-128-SIV uses a 32-byte key
//!   (two AES-128 keys concatenated), AES-256-SIV uses a 64-byte key.
//!
//! # Examples
//!
//! ```no_run
//! use openssl_crypto::modes::siv::AesSiv;
//!
//! // 32-byte key = two AES-128 keys concatenated (RFC 5297 §2.6).
//! let key = [0x11u8; 32];
//! let nonce = b"unique nonce";
//! let aad = b"associated data";
//! let plaintext = b"secret message";
//!
//! let siv = AesSiv::new(&key).expect("valid key");
//! let ciphertext = siv.seal(nonce, aad, plaintext).expect("seal");
//! let recovered = siv.open(nonce, aad, &ciphertext).expect("open");
//! assert_eq!(recovered, plaintext);
//! ```

// Re-export the canonical SIV type. The `pub use` preserves all methods
// (`new`, `seal`, `open`, `tag_length`) and their documentation.
pub use super::super::symmetric::aes::AesSiv;

/// AES-SIV synthetic IV (tag) length in bytes. Per RFC 5297 §2.4, the SIV
/// length is fixed at 16 bytes (the AES block size).
pub const SIV_TAG_LEN: usize = 16;

/// AES-128-SIV key length in bytes. Per RFC 5297 §2.6, the SIV key is the
/// concatenation of an AES-CMAC key (K1) and an AES-CTR key (K2).
pub const SIV_AES_128_KEY_LEN: usize = 32;

/// AES-256-SIV key length in bytes.
pub const SIV_AES_256_KEY_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siv_constants_match_rfc_5297() {
        // Per RFC 5297 §2.4 — synthetic IV is one AES block.
        assert_eq!(SIV_TAG_LEN, 16);
        // Per RFC 5297 §2.6 — SIV uses double-length keys.
        assert_eq!(SIV_AES_128_KEY_LEN, 32);
        assert_eq!(SIV_AES_256_KEY_LEN, 64);
    }

    #[test]
    fn aes_siv_round_trip_through_modes_siv_path() {
        // Verify the re-exported type is reachable and functional from this
        // module path. This exercises the §0.4.1 crate layout requirement.
        let key = [0x42u8; SIV_AES_128_KEY_LEN];
        let nonce = b"unique nonce 001";
        let aad: &[u8] = b"header";
        let plaintext: &[u8] = b"hello siv";

        let siv = AesSiv::new(&key).expect("AES-128-SIV key install");
        let ct = siv.seal(nonce, aad, plaintext).expect("seal");
        let pt = siv.open(nonce, aad, &ct).expect("open");
        assert_eq!(pt, plaintext);
        // Tag length accessor must report SIV_TAG_LEN.
        assert_eq!(siv.tag_length(), SIV_TAG_LEN);
    }

    #[test]
    fn aes_siv_nonce_reuse_preserves_authenticity() {
        // Classic SIV misuse-resistance property: a deterministic encryption
        // with the same nonce/aad/plaintext produces the same ciphertext,
        // but the construction is still authenticated — tampering fails.
        let key = [0x42u8; SIV_AES_128_KEY_LEN];
        let nonce = b"reused..........";
        let aad: &[u8] = b"header";
        let plaintext: &[u8] = b"hello siv";

        let siv = AesSiv::new(&key).expect("key install");
        let ct1 = siv.seal(nonce, aad, plaintext).expect("seal #1");
        let ct2 = siv.seal(nonce, aad, plaintext).expect("seal #2");
        assert_eq!(
            ct1, ct2,
            "SIV is deterministic for (key, nonce, aad, plaintext)"
        );

        // Tamper with the first byte; `open` must reject.
        let mut bad = ct1.clone();
        bad[0] ^= 0x01;
        assert!(
            siv.open(nonce, aad, &bad).is_err(),
            "SIV must reject tampered ciphertext"
        );
    }
}
