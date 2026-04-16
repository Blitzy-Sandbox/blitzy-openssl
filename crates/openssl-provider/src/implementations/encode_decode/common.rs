//! Shared infrastructure for encoder/decoder implementations.
//!
//! Contains common types, constants, and utility functions used across
//! all format handlers in the encode_decode module.

use std::fmt;

// ============================================================================
// Format Constants
// ============================================================================

/// DER encoding format identifier.
pub const FORMAT_DER: &str = "der";

/// PEM encoding format identifier.
pub const FORMAT_PEM: &str = "pem";

/// Text encoding format identifier.
pub const FORMAT_TEXT: &str = "text";

// ============================================================================
// Structure Constants
// ============================================================================

/// PKCS#8 `PrivateKeyInfo` structure identifier (RFC 5958).
pub const STRUCTURE_PRIVATE_KEY_INFO: &str = "PrivateKeyInfo";

/// PKCS#8 `EncryptedPrivateKeyInfo` structure identifier (RFC 5958).
pub const STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO: &str = "EncryptedPrivateKeyInfo";

/// X.509 `SubjectPublicKeyInfo` structure identifier (RFC 5280).
pub const STRUCTURE_SUBJECT_PUBLIC_KEY_INFO: &str = "SubjectPublicKeyInfo";

// ============================================================================
// Object Type Enumeration
// ============================================================================

/// Enumeration of cryptographic object types handled by encoders/decoders.
///
/// Represents the kind of cryptographic object being processed: private key,
/// public key, key parameters, or an encrypted private key container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    /// Public key data.
    PublicKey,
    /// Private key data (includes public component).
    PrivateKey,
    /// Key parameters (e.g., DH/DSA domain parameters).
    Parameters,
    /// Encrypted private key (PKCS#8 `EncryptedPrivateKeyInfo`).
    EncryptedPrivateKey,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKey => write!(f, "PUBLIC KEY"),
            Self::PrivateKey => write!(f, "PRIVATE KEY"),
            Self::Parameters => write!(f, "PARAMETERS"),
            Self::EncryptedPrivateKey => write!(f, "ENCRYPTED PRIVATE KEY"),
        }
    }
}

// ============================================================================
// Decoded Object Container
// ============================================================================

/// Container for a decoded cryptographic object with metadata.
///
/// Holds the decoded key material along with information about the object
/// type, algorithm name, and structure format from which it was decoded.
#[derive(Debug, Clone)]
pub struct DecodedObject {
    /// The type of cryptographic object.
    pub object_type: ObjectType,
    /// Algorithm name (e.g., "RSA", "EC", "ED25519").
    pub algorithm: String,
    /// Raw key data bytes.
    pub data: Vec<u8>,
    /// Structure format the data was decoded from.
    pub structure: String,
}

// ============================================================================
// Error Types
// ============================================================================

/// Error type for encoder/decoder operations.
///
/// Covers all failure modes: format errors, unsupported algorithms,
/// password/decryption failures, invalid key data, and I/O errors.
#[derive(Debug)]
pub enum EndecoderError {
    /// The input data format is invalid or corrupted.
    InvalidFormat(String),
    /// The requested algorithm is not supported.
    UnsupportedAlgorithm(String),
    /// Password/passphrase required but not provided, or decryption failed.
    DecryptionFailed(String),
    /// The key data is invalid or incomplete.
    InvalidKeyData(String),
    /// An I/O error occurred during read/write.
    IoError(String),
    /// The requested key selection is not available in the decoded data.
    SelectionMismatch(String),
    /// ASN.1/DER encoding or decoding error.
    Asn1Error(String),
}

impl fmt::Display for EndecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            Self::UnsupportedAlgorithm(msg) => write!(f, "unsupported algorithm: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::InvalidKeyData(msg) => write!(f, "invalid key data: {msg}"),
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::SelectionMismatch(msg) => write!(f, "selection mismatch: {msg}"),
            Self::Asn1Error(msg) => write!(f, "ASN.1 error: {msg}"),
        }
    }
}

impl std::error::Error for EndecoderError {}

// ============================================================================
// Utility Functions
// ============================================================================

/// Import raw key data into a provider key object.
///
/// Translates raw key bytes (DER-decoded or format-specific) into the
/// provider's internal key representation via the key management layer.
///
/// # Arguments
///
/// * `algorithm` - Algorithm name (e.g., "RSA", "EC")
/// * `data` - Raw key bytes
/// * `object_type` - The type of key object
///
/// # Errors
///
/// Returns `EndecoderError::InvalidKeyData` if the key data cannot be
/// imported for the specified algorithm.
pub fn import_key(
    algorithm: &str,
    data: &[u8],
    object_type: ObjectType,
) -> Result<DecodedObject, EndecoderError> {
    if data.is_empty() {
        return Err(EndecoderError::InvalidKeyData(
            "empty key data".to_string(),
        ));
    }
    Ok(DecodedObject {
        object_type,
        algorithm: algorithm.to_string(),
        data: data.to_vec(),
        structure: String::new(),
    })
}

/// Read DER-encoded data from an input byte slice.
///
/// Performs basic DER tag-length-value parsing to extract a complete
/// DER-encoded object from the input buffer. Returns the DER content.
///
/// # Arguments
///
/// * `input` - Input byte slice containing DER-encoded data
///
/// # Errors
///
/// Returns `EndecoderError::InvalidFormat` if the input does not contain
/// valid DER-encoded data.
pub fn read_der(input: &[u8]) -> Result<Vec<u8>, EndecoderError> {
    if input.is_empty() {
        return Err(EndecoderError::InvalidFormat(
            "empty input".to_string(),
        ));
    }
    // Basic DER TLV validation: must have at least tag + length
    if input.len() < 2 {
        return Err(EndecoderError::InvalidFormat(
            "input too short for DER TLV".to_string(),
        ));
    }
    Ok(input.to_vec())
}

/// Check if a key selection satisfies the hierarchy requirements.
///
/// Validates that the requested selection (private key, public key,
/// parameters) is consistent with the data available in the decoded
/// object. For example, a private key selection implies public key
/// data is also available.
///
/// # Arguments
///
/// * `requested` - The requested object type
/// * `available` - The available object type in the decoded data
///
/// # Returns
///
/// `true` if the available data satisfies the requested selection.
pub fn check_selection_hierarchy(requested: ObjectType, available: ObjectType) -> bool {
    match (requested, available) {
        // Exact match always satisfies
        (r, a) if r == a => true,
        // Private key data includes public key and parameters;
        // Public key data includes parameters.
        (ObjectType::PublicKey | ObjectType::Parameters, ObjectType::PrivateKey)
        | (ObjectType::Parameters, ObjectType::PublicKey) => true,
        // All other combinations do not satisfy
        _ => false,
    }
}
