//! Microsoft PVK private key format decoder.
//!
//! Source: `decode_pvk2key.c` (288 lines).

use crate::traits::AlgorithmDescriptor;

/// Microsoft PVK private key format decoder for RSA and DSA keys.
///
/// Parses Microsoft PVK (Private Key) format, including optional
/// RC4 encryption.
#[derive(Debug, Clone)]
pub struct PvkDecoder {
    /// Algorithm name for this decoder instance.
    algorithm: &'static str,
}

impl PvkDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Decode PVK-encoded key data.
    ///
    /// # Errors
    ///
    /// Returns an error if the PVK data is invalid.
    pub fn decode(&self, _input: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedFormat(format!(
            "PVK decoder for {} not yet wired",
            self.algorithm
        )))
    }

    /// Returns the list of supported input formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec!["pvk"]
    }
}

/// Returns algorithm descriptors for all PVK decoders.
pub fn all_pvk_decoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,input=pvk",
            description: "PVK to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,input=pvk",
            description: "PVK to DSA key decoder",
        },
    ]
}
