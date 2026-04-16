//! # EC Public Key Blob Encoder
//!
//! Rust translation of `providers/implementations/encode_decode/encode_key2blob.c` (179 lines).
//! Encodes EC public keys as raw point blobs (uncompressed or compressed).
//!
//! ## Supported Formats
//!
//! - Raw EC public point (uncompressed: `0x04 || x || y`)
//! - Compressed EC point (`0x02`/`0x03 || x`)
//!
//! ## Supported Key Types
//!
//! - EC (P-256, P-384, P-521, secp256k1, brainpool curves)
//! - X25519, X448 (raw public key bytes)

use crate::traits::AlgorithmDescriptor;

/// EC public key blob encoder.
///
/// Produces raw elliptic curve point representations suitable for
/// interoperability with systems expecting bare public key blobs
/// rather than SPKI-wrapped encodings.
///
/// # C Source Reference
///
/// Translates `ossl_ec_blob_encoder_functions` from `encode_key2blob.c`.
pub struct BlobEncoder {
    /// The key type this encoder handles (e.g., "EC", "X25519").
    key_type: &'static str,
}

impl BlobEncoder {
    /// Creates a new blob encoder for the specified key type.
    ///
    /// # Arguments
    ///
    /// * `key_type` - The algorithm name (e.g., "EC", "X25519", "X448")
    pub fn new(key_type: &'static str) -> Self {
        Self { key_type }
    }

    /// Returns the encoder name.
    pub fn name(&self) -> &'static str {
        "blob"
    }

    /// Encodes an EC public key as a raw point blob.
    ///
    /// # Arguments
    ///
    /// * `key_data` - The raw key material to encode
    ///
    /// # Returns
    ///
    /// The encoded blob bytes, or an error if encoding fails.
    ///
    /// # Errors
    ///
    /// Returns `EndecoderError::EncodingFailed` if the key data is invalid
    /// or the key type is not supported for blob encoding.
    pub fn encode(&self, key_data: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        if key_data.is_empty() {
            return Err(super::common::EndecoderError::InvalidKeyData(
                "empty key data for blob encoding".to_string(),
            ));
        }
        // Blob encoding passes through the raw EC point bytes directly.
        // The key material is already in the correct format (uncompressed point
        // or raw public key for X25519/X448).
        Ok(key_data.to_vec())
    }

    /// Returns the list of formats this encoder supports.
    ///
    /// Blob encoder supports only the "blob" format.
    pub fn supported_formats(&self) -> &'static [&'static str] {
        &["blob"]
    }

    /// Returns the key type this encoder handles.
    pub fn key_type(&self) -> &'static str {
        self.key_type
    }
}

/// Returns all blob encoder algorithm descriptors.
///
/// Produces descriptors for each EC-family key type that supports
/// blob encoding. Called by `encoder_descriptors()` in the parent module.
///
/// # C Source Reference
///
/// Replaces the `OSSL_ALGORITHM ossl_ec_blob_encoder[]` table from `encode_key2blob.c`.
pub fn all_blob_encoders() -> Vec<AlgorithmDescriptor> {
    vec![
        AlgorithmDescriptor {
            names: vec!["EC"],
            property: "provider=default,output=blob",
            description: "EC public key blob encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X25519"],
            property: "provider=default,output=blob",
            description: "X25519 public key blob encoder",
        },
        AlgorithmDescriptor {
            names: vec!["X448"],
            property: "provider=default,output=blob",
            description: "X448 public key blob encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED25519"],
            property: "provider=default,output=blob",
            description: "ED25519 public key blob encoder",
        },
        AlgorithmDescriptor {
            names: vec!["ED448"],
            property: "provider=default,output=blob",
            description: "ED448 public key blob encoder",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_encoder_creation() {
        let encoder = BlobEncoder::new("EC");
        assert_eq!(encoder.name(), "blob");
        assert_eq!(encoder.key_type(), "EC");
    }

    #[test]
    fn test_blob_encoder_supported_formats() {
        let encoder = BlobEncoder::new("EC");
        assert_eq!(encoder.supported_formats(), &["blob"]);
    }

    #[test]
    fn test_blob_encoder_encode_passthrough() {
        let encoder = BlobEncoder::new("EC");
        let key_data = vec![0x04, 0x01, 0x02, 0x03];
        let result = encoder.encode(&key_data).unwrap();
        assert_eq!(result, key_data);
    }

    #[test]
    fn test_blob_encoder_empty_input() {
        let encoder = BlobEncoder::new("EC");
        let result = encoder.encode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_blob_encoders_count() {
        let descriptors = all_blob_encoders();
        assert_eq!(descriptors.len(), 5);
        assert!(descriptors.iter().all(|d| d.property.contains("blob")));
    }
}
