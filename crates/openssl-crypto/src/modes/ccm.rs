//! Counter with CBC-MAC (CCM) AEAD mode.
//!
//! This module provides a thin re-export facade for the CCM authenticated
//! encryption mode. The canonical implementation lives in
//! [`crate::symmetric::aes::AesCcm`] and this module exposes it under the
//! per-mode crate layout mandated by AAP §0.4.1.
//!
//! # Standards
//!
//! * NIST SP 800-38C — *Recommendation for Block Cipher Modes of Operation:
//!   The CCM Mode for Authentication and Confidentiality*
//! * RFC 3610 — *Counter with CBC-MAC (CCM)*
//! * RFC 7905 — *ChaCha20-Poly1305 Cipher Suites for TLS* (for context on
//!   why modern deployments prefer GCM/ChaCha20-Poly1305 to CCM)
//!
//! # Provenance
//!
//! Translated from `crypto/modes/ccm128.c` and `providers/implementations/
//! ciphers/cipher_aes_ccm*.c` in the upstream OpenSSL 4.0 source tree. The
//! Rust implementation in [`crate::symmetric::aes`] replaces the upstream C
//! implementation and the thin re-export here preserves the AAP §0.4.1
//! directory layout.
//!
//! # Security considerations
//!
//! * CCM is an authenticated-encryption-with-associated-data (AEAD) mode.
//!   All plaintext MUST be validated by the tag before being treated as
//!   trusted — `AesCcm::open()` returns an error on tag-mismatch and the
//!   caller MUST propagate that error.
//! * Nonces MUST be unique for a given key. Reuse breaks both confidentiality
//!   and authenticity. CCM nonces are 7–13 bytes per NIST SP 800-38C.
//! * Tag length is configurable (4, 6, 8, 10, 12, 14, or 16 bytes per
//!   SP 800-38C Table 2); shorter tags increase forgery probability and MUST
//!   only be used with documented justification.
//! * CCM is a two-pass construction and therefore incompatible with
//!   streaming decryption. The entire ciphertext must be buffered before
//!   tag verification completes — callers handling adversarial inputs
//!   should bound buffer sizes to avoid denial-of-service.
//!
//! # Examples
//!
//! ```no_run
//! use openssl_crypto::modes::ccm::AesCcm;
//!
//! let key = [0u8; 16];
//! let nonce = [0u8; 12];
//! let aad = b"associated data";
//! let plaintext = b"secret message";
//!
//! // 16-byte tag, 12-byte nonce.
//! let ccm = AesCcm::new(&key, 16, 12).expect("valid parameters");
//! let ciphertext = ccm.seal(&nonce, aad, plaintext).expect("seal");
//! let recovered = ccm.open(&nonce, aad, &ciphertext).expect("open");
//! assert_eq!(recovered, plaintext);
//! ```

// Re-export the canonical CCM type. The `pub use` preserves all methods
// (`new`, `seal`, `open`) and their documentation.
pub use super::super::symmetric::aes::AesCcm;

/// Maximum tag length (in bytes) supported by the NIST SP 800-38C variant of
/// CCM. The full set of permitted tag lengths is {4, 6, 8, 10, 12, 14, 16}.
pub const CCM_MAX_TAG_LEN: usize = 16;

/// Minimum tag length (in bytes) permitted by NIST SP 800-38C §6.3.
pub const CCM_MIN_TAG_LEN: usize = 4;

/// Minimum nonce length (in bytes) permitted by NIST SP 800-38C §6.1.
pub const CCM_MIN_NONCE_LEN: usize = 7;

/// Maximum nonce length (in bytes) permitted by NIST SP 800-38C §6.1.
pub const CCM_MAX_NONCE_LEN: usize = 13;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccm_constants_match_nist_sp_800_38c() {
        // Per NIST SP 800-38C Table 2 — permitted tag lengths.
        assert_eq!(CCM_MAX_TAG_LEN, 16);
        assert_eq!(CCM_MIN_TAG_LEN, 4);
        // Per NIST SP 800-38C §6.1 — permitted nonce lengths.
        assert_eq!(CCM_MIN_NONCE_LEN, 7);
        assert_eq!(CCM_MAX_NONCE_LEN, 13);
    }

    #[test]
    fn aes_ccm_round_trip_through_modes_ccm_path() {
        // Verify the re-exported type is reachable and functional from this
        // module path. This exercises the §0.4.1 crate layout requirement.
        let key = [0x42u8; 16];
        let nonce = [0x11u8; 12];
        let aad: &[u8] = b"header";
        let plaintext: &[u8] = b"hello ccm";

        let ccm = AesCcm::new(&key, 16, 12).expect("AES-128-CCM key install");
        let ct = ccm.seal(&nonce, aad, plaintext).expect("seal");
        let pt = ccm.open(&nonce, aad, &ct).expect("open");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aes_ccm_tag_tamper_rejected() {
        let key = [0x42u8; 16];
        let nonce = [0x11u8; 12];
        let aad: &[u8] = b"header";
        let plaintext: &[u8] = b"hello ccm";

        let ccm = AesCcm::new(&key, 16, 12).expect("AES-128-CCM key install");
        let mut ct = ccm.seal(&nonce, aad, plaintext).expect("seal");
        // Flip the last byte of the tag; `open` must reject.
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(
            ccm.open(&nonce, aad, &ct).is_err(),
            "CCM must reject tampered tag"
        );
    }
}
