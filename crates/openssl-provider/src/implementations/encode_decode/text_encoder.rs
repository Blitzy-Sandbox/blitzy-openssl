//! Text format encoder for human-readable key dumps.
//!
//! Source: `encode_key2text.c` (758 lines).

use crate::traits::AlgorithmDescriptor;

/// Text format encoder for human-readable key representation.
///
/// Produces human-readable text output similar to `openssl rsa -text`.
#[derive(Debug, Clone)]
pub struct TextEncoder {
    /// Algorithm name.
    algorithm: &'static str,
}

impl TextEncoder {
    /// Returns the encoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Encode key data to human-readable text.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn encode(&self, _key_data: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedAlgorithm(
            format!("Text encoder for {} not yet wired", self.algorithm),
        ))
    }

    /// Returns the list of supported output formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec![super::common::FORMAT_TEXT]
    }
}

/// Returns algorithm descriptors for all text encoders.
pub fn all_text_encoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=text",
            description: "RSA key to text encoder",
        },
        AlgorithmDescriptor {
            names: vec!["EC", "id-ecPublicKey"],
            property: "provider=default,output=text",
            description: "EC key to text encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: "provider=default,output=text",
            description: "X25519 key to text encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: "provider=default,output=text",
            description: "Ed25519 key to text encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DH"],
            property: "provider=default,output=text",
            description: "DH key to text encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,output=text",
            description: "DSA key to text encoder",
        },
    ]
}
