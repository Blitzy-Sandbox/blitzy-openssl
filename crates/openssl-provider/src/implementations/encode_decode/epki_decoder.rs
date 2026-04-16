//! EncryptedPrivateKeyInfo → PrivateKeyInfo decryption bridge.
//!
//! Source: `decode_epki2pki.c` (206 lines).

/// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`) to `PrivateKeyInfo` decoder.
///
/// Decrypts PKCS#8 encrypted private keys using password-based
/// encryption (PBES2, PBES1).
#[derive(Debug, Clone)]
pub struct EpkiDecoder;

impl EpkiDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        "epki2pki"
    }

    /// Decrypt an `EncryptedPrivateKeyInfo` to `PrivateKeyInfo`.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn decode(&self, _input: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::DecryptionFailed(
            "EPKI decoder not yet wired".to_string(),
        ))
    }

    /// Returns the list of supported input formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec![super::common::FORMAT_DER]
    }
}
