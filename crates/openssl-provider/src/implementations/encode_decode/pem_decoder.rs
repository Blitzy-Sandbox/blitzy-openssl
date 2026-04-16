//! PEM-to-DER decoder (PEM armor stripping and Base64 decoding).
//!
//! Source: `decode_pem2der.c` (277 lines).

/// PEM-to-DER decoder for PEM armor stripping and Base64 decoding.
///
/// Strips PEM headers/footers and Base64-decodes the content,
/// identifying key type from the PEM label.
#[derive(Debug, Clone)]
pub struct PemDecoder;

impl PemDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        "pem"
    }

    /// Decode PEM-encoded data to DER.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM data is invalid.
    pub fn decode(&self, _input: &[u8]) -> Result<Vec<u8>, super::common::EndecoderError> {
        Err(super::common::EndecoderError::UnsupportedFormat(
            "PEM decoder not yet wired".to_string(),
        ))
    }

    /// Returns the list of supported input formats.
    pub fn supported_formats(&self) -> Vec<&'static str> {
        vec![super::common::FORMAT_PEM]
    }
}
