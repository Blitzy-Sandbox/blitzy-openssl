//! Microsoft MSBLOB key format decoder.
//!
//! Source: `decode_msblob2key.c` (284 lines).

use crate::traits::AlgorithmDescriptor;

/// Microsoft MSBLOB key format decoder for RSA and DSA keys.
///
/// Parses Microsoft `PUBLICKEYBLOB` and `PRIVATEKEYBLOB` formats.
#[derive(Debug, Clone)]
pub struct MsBlobDecoder {
    /// Algorithm name for this decoder instance.
    algorithm: &'static str,
}

impl MsBlobDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Decode MSBLOB-encoded key data.
    ///
    /// # Errors
    ///
    /// Returns an error if the MSBLOB data is invalid.
    pub fn decode(&self, _input: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedFormat(format!(
            "MSBLOB decoder for {} not yet wired",
            self.algorithm
        )))
    }

    /// Returns the list of supported input formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec!["msblob"]
    }
}

/// Returns algorithm descriptors for all MSBLOB decoders.
pub fn all_msblob_decoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,input=msblob",
            description: "MSBLOB to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,input=msblob",
            description: "MSBLOB to DSA key decoder",
        },
    ]
}
