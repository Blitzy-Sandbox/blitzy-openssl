//! SubjectPublicKeyInfo type-tagging decoder.
//!
//! Source: `decode_spki2typespki.c` (168 lines).

/// `SubjectPublicKeyInfo` type-tagging decoder for algorithm identification.
///
/// Peeks at the algorithm OID inside an SPKI structure to tag
/// the key with its algorithm name.
#[derive(Debug, Clone)]
pub struct SpkiTaggingDecoder;

impl SpkiTaggingDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        "spki2typespki"
    }

    /// Decode SPKI and tag with algorithm type.
    ///
    /// # Errors
    ///
    /// Returns an error if the SPKI data is invalid.
    pub fn decode(&self, _input: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::InvalidFormat(
            "SPKI decoder not yet wired".to_string(),
        ))
    }

    /// Returns the list of supported input formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec![super::common::FORMAT_DER]
    }
}
