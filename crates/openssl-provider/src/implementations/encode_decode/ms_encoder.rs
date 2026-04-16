//! Microsoft MSBLOB/PVK key encoders.
//!
//! Source: `encode_key2ms.c` (233 lines).

use crate::traits::AlgorithmDescriptor;

/// Microsoft MSBLOB key format encoder for RSA and DSA keys.
///
/// Encodes keys in Microsoft `PUBLICKEYBLOB`/`PRIVATEKEYBLOB` format.
#[derive(Debug, Clone)]
pub struct MsBlobEncoder {
    /// Algorithm name.
    algorithm: &'static str,
}

impl MsBlobEncoder {
    /// Create a new MSBLOB encoder for the given algorithm.
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }

    /// Returns the encoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Encode key data to MSBLOB format.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn encode(&self, _key_data: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedAlgorithm(
            format!("MSBLOB encoder for {} not yet wired", self.algorithm),
        ))
    }

    /// Returns the list of supported output formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec!["msblob"]
    }

    /// Returns the key type this encoder handles.
    pub fn key_type(&self) -> &'static str {
        self.algorithm
    }
}

/// Microsoft PVK private key format encoder for RSA and DSA keys.
///
/// Encodes keys in Microsoft PVK format.
#[derive(Debug, Clone)]
pub struct PvkEncoder {
    /// Algorithm name.
    algorithm: &'static str,
}

impl PvkEncoder {
    /// Create a new PVK encoder for the given algorithm.
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }

    /// Returns the encoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Encode key data to PVK format.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn encode(&self, _key_data: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedAlgorithm(
            format!("PVK encoder for {} not yet wired", self.algorithm),
        ))
    }

    /// Returns the list of supported output formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec!["pvk"]
    }

    /// Returns the key type this encoder handles.
    pub fn key_type(&self) -> &'static str {
        self.algorithm
    }
}

/// Returns algorithm descriptors for all Microsoft format encoders.
pub fn all_ms_encoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=msblob",
            description: "RSA key to MSBLOB encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,output=msblob",
            description: "DSA key to MSBLOB encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=pvk",
            description: "RSA key to PVK encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,output=pvk",
            description: "DSA key to PVK encoder",
        },
    ]
}
