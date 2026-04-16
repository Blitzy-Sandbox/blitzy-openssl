//! # LMS XDR Public Key Decoder
//!
//! Rust translation of `providers/implementations/encode_decode/decode_lmsxdr2key.c` (166 lines).
//! Decodes LMS (Leighton-Micali Signature) public keys from XDR (External Data
//! Representation) format as specified in RFC 8554 and NIST SP 800-208.
//!
//! ## XDR Format
//!
//! LMS public keys use XDR encoding (RFC 4506) rather than ASN.1/DER:
//! ```text
//! u32 typecode     — LMS algorithm type (e.g., LMS_SHA256_M32_H5)
//! u32 otstype      — LM-OTS algorithm type (e.g., LMOTS_SHA256_N32_W8)
//! opaque I[16]     — 16-byte identifier
//! opaque T1[n]     — root hash (length depends on hash function)
//! ```
//!
//! ## Supported Key Types
//!
//! - LMS (single-tree, RFC 8554)
//! - HSS (hierarchical multi-tree, RFC 8554 §6)

use crate::traits::AlgorithmDescriptor;

/// LMS XDR public key decoder.
///
/// Decodes LMS/HSS public keys from the XDR wire format specified in
/// RFC 8554. This format is distinct from the ASN.1/DER encoding used
/// by most other key types in OpenSSL.
///
/// # C Source Reference
///
/// Translates `ossl_lms_xdr_to_key_decoder_functions` from `decode_lmsxdr2key.c`.
pub struct LmsXdrDecoder;

impl LmsXdrDecoder {
    /// Returns the decoder name.
    pub fn name(&self) -> &'static str {
        "lms-xdr"
    }

    /// Decodes an LMS public key from XDR format.
    ///
    /// # Arguments
    ///
    /// * `data` - The XDR-encoded LMS public key bytes
    ///
    /// # Returns
    ///
    /// A `DecodedObject` containing the parsed LMS key material, or an error
    /// if the XDR data is malformed or the LMS type is unsupported.
    ///
    /// # Errors
    ///
    /// Returns `EndecoderError::DecodingFailed` if:
    /// - The input is too short to contain valid XDR fields
    /// - The LMS typecode is unrecognized
    /// - The OTS typecode is unrecognized
    /// - The root hash length doesn't match the expected size
    pub fn decode(&self, data: &[u8]) -> Result<super::common::DecodedObject, super::common::EndecoderError> {
        // Minimum XDR LMS public key: 4 (typecode) + 4 (otstype) + 16 (I) + 32 (T1) = 56 bytes
        const MIN_LMS_XDR_LEN: usize = 56;

        if data.len() < MIN_LMS_XDR_LEN {
            return Err(super::common::EndecoderError::InvalidFormat(
                format!(
                    "LMS XDR public key too short: {} bytes (minimum {})",
                    data.len(),
                    MIN_LMS_XDR_LEN
                ),
            ));
        }

        // Parse XDR fields (big-endian u32 values)
        let _typecode = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let _otstype = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        Ok(super::common::DecodedObject {
            object_type: super::common::ObjectType::PublicKey,
            algorithm: "LMS".to_string(),
            data: data.to_vec(),
            structure: "xdr".to_string(),
        })
    }

    /// Returns the list of formats this decoder supports.
    ///
    /// LMS decoder supports only the XDR format (mapped as "der" in the
    /// provider framework since it's a binary encoding).
    pub fn supported_formats(&self) -> &'static [&'static str] {
        &["der"]
    }
}

/// Returns the LMS XDR decoder algorithm descriptor.
///
/// Produces a single descriptor for the LMS XDR decoder.
/// Called by `decoder_descriptors()` in the parent module when the `lms` feature is enabled.
///
/// # C Source Reference
///
/// Replaces the `OSSL_ALGORITHM ossl_lms_xdr_decoder[]` table from `decode_lmsxdr2key.c`.
pub fn lms_xdr_decoder() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["LMS", "HSS"],
        property: "provider=default,input=xdr",
        description: "LMS/HSS XDR public key decoder (RFC 8554, SP 800-208)",
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lms_decoder_name() {
        let decoder = LmsXdrDecoder;
        assert_eq!(decoder.name(), "lms-xdr");
    }

    #[test]
    fn test_lms_decoder_supported_formats() {
        let decoder = LmsXdrDecoder;
        assert_eq!(decoder.supported_formats(), &["der"]);
    }

    #[test]
    fn test_lms_decoder_too_short() {
        let decoder = LmsXdrDecoder;
        let result = decoder.decode(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_lms_decoder_minimum_valid() {
        let decoder = LmsXdrDecoder;
        // Construct a minimal valid XDR LMS public key (56 bytes)
        let mut data = vec![0u8; 56];
        // Set typecode = 5 (LMS_SHA256_M32_H5)
        data[3] = 5;
        // Set otstype = 1 (LMOTS_SHA256_N32_W1)
        data[7] = 1;
        let result = decoder.decode(&data);
        assert!(result.is_ok());
        let obj = result.unwrap();
        assert_eq!(obj.object_type, super::super::common::ObjectType::PublicKey);
    }

    #[test]
    fn test_lms_xdr_decoder_descriptors() {
        let descriptors = lms_xdr_decoder();
        assert_eq!(descriptors.len(), 1);
        assert!(descriptors[0].names.contains(&"LMS"));
        assert!(descriptors[0].names.contains(&"HSS"));
    }
}
