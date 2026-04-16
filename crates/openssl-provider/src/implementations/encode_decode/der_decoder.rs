//! DER-to-key decoder for PKCS#8, SPKI, and legacy formats.
//!
//! Source: `decode_der2key.c` (1,329 lines).

use crate::traits::AlgorithmDescriptor;

/// DER-to-key decoder supporting PKCS#8, SPKI, and legacy formats.
///
/// Each instance handles a specific algorithm type (RSA, EC, DH, DSA,
/// X25519, Ed25519, ML-KEM, ML-DSA, SLH-DSA) with a dedicated
/// `KeyTypeDescriptor` entry that specifies key import and format
/// detection logic.
#[derive(Debug, Clone)]
pub struct DerDecoder {
    /// Algorithm name for this decoder instance.
    algorithm: &'static str,
}

impl DerDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Decode DER-encoded key data.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER data is invalid or the algorithm
    /// is not supported by this decoder instance.
    pub fn decode(&self, _input: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedAlgorithm(
            format!("DER decoder for {} not yet wired", self.algorithm),
        ))
    }

    /// Returns the list of supported input formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec![super::common::FORMAT_DER]
    }

    /// Check if this decoder handles the given selection type.
    pub fn does_selection(&self, _object_type: super::common::ObjectType) -> bool {
        true
    }
}

/// Returns algorithm descriptors for all DER-to-key decoders.
///
/// Covers RSA, EC, DH, DSA, X25519/X448, Ed25519/Ed448,
/// ML-KEM, ML-DSA, and SLH-DSA key types in DER format.
pub fn all_der_decoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,input=der",
            description: "DER to RSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["EC", "id-ecPublicKey"],
            property: "provider=default,input=der",
            description: "DER to EC key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: "provider=default,input=der",
            description: "DER to X25519 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: "provider=default,input=der",
            description: "DER to X448 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: "provider=default,input=der",
            description: "DER to Ed25519 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED448"],
            property: "provider=default,input=der",
            description: "DER to Ed448 key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DH"],
            property: "provider=default,input=der",
            description: "DER to DH key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,input=der",
            description: "DER to DSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA-PSS"],
            property: "provider=default,input=der",
            description: "DER to RSA-PSS key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-KEM"],
            property: "provider=default,input=der",
            description: "DER to ML-KEM key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["ML-DSA"],
            property: "provider=default,input=der",
            description: "DER to ML-DSA key decoder",
        },
        AlgorithmDescriptor {
            names: vec!["SLH-DSA"],
            property: "provider=default,input=der",
            description: "DER to SLH-DSA key decoder",
        },
    ]
}
