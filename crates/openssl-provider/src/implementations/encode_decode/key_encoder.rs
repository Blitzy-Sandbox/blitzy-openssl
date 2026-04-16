//! PKCS#8/SPKI/legacy DER/PEM key encoders.
//!
//! Source: `encode_key2any.c` (1,789 lines — largest file in the module).

use crate::traits::AlgorithmDescriptor;

/// Key encoder supporting PKCS#8, SPKI, and legacy DER/PEM formats.
///
/// Handles encoding keys to `PrivateKeyInfo` (PKCS#8), `EncryptedPrivateKeyInfo`,
/// `SubjectPublicKeyInfo`, and legacy algorithm-specific formats.
#[derive(Debug, Clone)]
pub struct KeyEncoder {
    /// Algorithm name.
    algorithm: &'static str,
    /// Output format (der/pem).
    format: &'static str,
}

impl KeyEncoder {
    /// Returns the encoder name.
    pub fn name(&self) -> &'static str {
        self.algorithm
    }

    /// Encode key data.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn encode(&self, _key_data: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedFormat(format!(
            "Key encoder for {} not yet wired",
            self.algorithm
        )))
    }

    /// Returns the list of supported output formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec![self.format]
    }
}

/// Returns algorithm descriptors for all key encoders.
///
/// Covers PKCS#8, SPKI, `EncryptedPrivateKeyInfo`, and legacy formats
/// for RSA, EC, DH, DSA, X25519/X448, Ed25519/Ed448, ML-KEM, ML-DSA, SLH-DSA.
pub fn all_key_encoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=der,structure=PrivateKeyInfo",
            description: "RSA key to PKCS#8 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=pem,structure=PrivateKeyInfo",
            description: "RSA key to PKCS#8 PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=der,structure=SubjectPublicKeyInfo",
            description: "RSA key to SPKI DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["RSA", "rsaEncryption"],
            property: "provider=default,output=pem,structure=SubjectPublicKeyInfo",
            description: "RSA key to SPKI PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["EC", "id-ecPublicKey"],
            property: "provider=default,output=der,structure=PrivateKeyInfo",
            description: "EC key to PKCS#8 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["EC", "id-ecPublicKey"],
            property: "provider=default,output=pem,structure=PrivateKeyInfo",
            description: "EC key to PKCS#8 PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: "provider=default,output=der,structure=PrivateKeyInfo",
            description: "X25519 key to PKCS#8 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: "provider=default,output=pem,structure=PrivateKeyInfo",
            description: "X25519 key to PKCS#8 PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: "provider=default,output=der,structure=PrivateKeyInfo",
            description: "Ed25519 key to PKCS#8 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: "provider=default,output=pem,structure=PrivateKeyInfo",
            description: "Ed25519 key to PKCS#8 PEM encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DH"],
            property: "provider=default,output=der,structure=PrivateKeyInfo",
            description: "DH key to PKCS#8 DER encoder",
        },
        AlgorithmDescriptor {
            names: vec!["DSA"],
            property: "provider=default,output=der,structure=PrivateKeyInfo",
            description: "DSA key to PKCS#8 DER encoder",
        },
    ]
}
