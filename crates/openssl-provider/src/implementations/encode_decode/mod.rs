//! # Key Encoder/Decoder Provider Implementations
//!
//! Rust translation of `providers/implementations/encode_decode/` (16 C source files,
//! ~7,400 lines of C). Contains all encoder and decoder implementations that participate
//! in the OpenSSL key serialization pipeline.
//!
//! ## Decoding Pipeline
//!
//! ```text
//! PEM input → PemDecoder → DER bytes
//!                            ↓
//! DER input → EpkiDecoder → PrivateKeyInfo DER (if encrypted)
//!                            ↓
//!             SpkiDecoder → algorithm-tagged SPKI DER (if public)
//!                            ↓
//!             DerDecoder  → KeyData trait object
//! ```
//!
//! ## Encoding Pipeline
//!
//! ```text
//! KeyData → KeyEncoder → PKCS#8/SPKI/Legacy DER/PEM output
//!         → TextEncoder → Human-readable text output
//!         → BlobEncoder → Raw EC public point blob
//!         → MsEncoder   → MSBLOB/PVK Microsoft formats
//! ```
//!
//! ## Post-Quantum Codecs
//!
//! Table-driven codecs for ML-KEM, ML-DSA, LMS, and SLH-DSA supporting multiple
//! PKCS#8 payload layouts including OQS interoperability formats.
//!
//! ## Architecture
//!
//! - Encoders implement [`EncoderProvider`](crate::traits::EncoderProvider) trait
//!   from `crate::traits`
//! - Decoders implement [`DecoderProvider`](crate::traits::DecoderProvider) trait
//!   from `crate::traits`
//! - Uses `der`, `pem-rfc7468`, `pkcs8`, `spki` crates from RustCrypto
//! - Zero unsafe code (Rule R8)
//! - All functions return `ProviderResult<T>` (Rule R5)
//!
//! ## Module Organization
//!
//! | Module | Source C File | Purpose |
//! |--------|--------------|---------|
//! | [`common`] | `endecoder_common.c` | Shared types, constants, utilities |
//! | [`pq_codecs`] | *(new)* | Post-quantum key codec tables |
//! | [`der_decoder`] | `decode_der2key.c` | DER-to-key decoder |
//! | [`pem_decoder`] | `decode_pem2der.c` | PEM-to-DER decoder |
//! | [`epki_decoder`] | `decode_epki2pki.c` | Encrypted PKCS#8 decryptor |
//! | [`spki_decoder`] | `decode_spki2typespki.c` | SPKI type tagging |
//! | [`msblob_decoder`] | `decode_msblob2key.c` | Microsoft MSBLOB decoder |
//! | [`pvk_decoder`] | `decode_pvk2key.c` | Microsoft PVK decoder |
//! | [`lms_decoder`] | `decode_lmsxdr2key.c` | LMS XDR decoder |
//! | [`key_encoder`] | `encode_key2any.c` | PKCS#8/SPKI/legacy encoder |
//! | [`text_encoder`] | `encode_key2text.c` | Human-readable text encoder |
//! | [`blob_encoder`] | `encode_key2blob.c` | EC public key blob encoder |
//! | [`ms_encoder`] | `encode_key2ms.c` | Microsoft MSBLOB/PVK encoder |

use crate::traits::AlgorithmDescriptor;

// ============================================================================
// Submodule Declarations — Shared Infrastructure
// ============================================================================

/// Shared infrastructure used by all encoder/decoder modules.
///
/// Contains common types (`ObjectType`, `DecodedObject`, `EndecoderError`),
/// format and structure constants (`FORMAT_DER`, `FORMAT_PEM`, `FORMAT_TEXT`,
/// `STRUCTURE_PRIVATE_KEY_INFO`, etc.), and utility functions (`import_key`,
/// `read_der`, `check_selection_hierarchy`).
///
/// Source: `endecoder_common.c` (103 lines) — provides key import/free
/// helpers and DER reading utilities used across all format handlers.
pub(crate) mod common;

/// Post-quantum key codecs for ML-KEM, ML-DSA, LMS, and SLH-DSA.
///
/// Table-driven codecs supporting multiple PKCS#8 payload layouts
/// including OQS interoperability formats. Each codec defines the
/// expected OID, key sizes, and serialization strategy for its
/// algorithm family.
pub(crate) mod pq_codecs;

// ============================================================================
// Submodule Declarations — Decoders
// ============================================================================

/// DER-to-key decoder for PKCS#8, SPKI, and legacy formats.
///
/// Source: `decode_der2key.c` (1,329 lines). Supports per-algorithm
/// key type descriptors that specify key import functions and
/// PKCS#8 versus legacy format detection. Each key type (RSA, EC,
/// DH, DSA, X25519, Ed25519, ML-KEM, ML-DSA, SLH-DSA) has a
/// dedicated `KeyTypeDescriptor` entry.
pub mod der_decoder;

/// PEM-to-DER decoder (PEM armor stripping and Base64 decoding).
///
/// Source: `decode_pem2der.c` (277 lines). Strips PEM headers/footers
/// and Base64-decodes the content, identifying key type from the
/// PEM label (e.g., `"PRIVATE KEY"`, `"PUBLIC KEY"`,
/// `"RSA PRIVATE KEY"`). Maps PEM labels to object types via a
/// static lookup table.
pub mod pem_decoder;

/// `EncryptedPrivateKeyInfo` → `PrivateKeyInfo` decryption bridge.
///
/// Source: `decode_epki2pki.c` (206 lines). Decrypts PKCS#8 encrypted
/// private keys using password-based encryption schemes (PBES2 with
/// PBKDF2, or legacy PBES1). Requires a passphrase callback.
pub mod epki_decoder;

/// `SubjectPublicKeyInfo` type-tagging decoder.
///
/// Source: `decode_spki2typespki.c` (168 lines). Peeks at the
/// algorithm OID inside a `SubjectPublicKeyInfo` structure to tag
/// the key with its algorithm name for downstream processing by
/// algorithm-specific DER decoders.
pub mod spki_decoder;

/// Microsoft MSBLOB key format decoder.
///
/// Source: `decode_msblob2key.c` (284 lines). Parses Microsoft
/// `PUBLICKEYBLOB` and `PRIVATEKEYBLOB` formats for RSA and DSA
/// keys. Supports both key import and selection filtering.
pub mod msblob_decoder;

/// Microsoft PVK private key format decoder.
///
/// Source: `decode_pvk2key.c` (288 lines). Parses Microsoft PVK
/// (Private Key) format, including optional RC4 encryption with
/// a password-derived key. Supports RSA and DSA private keys.
pub mod pvk_decoder;

/// LMS/HSS XDR public key decoder.
///
/// Source: `decode_lmsxdr2key.c` (166 lines). Decodes LMS (Leighton-
/// Micali Signature) and HSS (Hierarchical Signature System) public
/// keys from XDR wire format per RFC 8554 / SP 800-208.
#[cfg(feature = "lms")]
pub mod lms_decoder;

// ============================================================================
// Submodule Declarations — Encoders
// ============================================================================

/// PKCS#8/SPKI/legacy DER/PEM key encoders.
///
/// Source: `encode_key2any.c` (1,789 lines — largest file in the module).
/// Handles encoding keys to `PrivateKeyInfo` (PKCS#8 unencrypted),
/// `EncryptedPrivateKeyInfo` (PKCS#8 encrypted), `SubjectPublicKeyInfo`,
/// and legacy algorithm-specific formats (PKCS#1 for RSA, SEC1 for EC).
/// Supports DER and PEM output.
pub mod key_encoder;

/// Text format encoder for human-readable key dumps.
///
/// Source: `encode_key2text.c` (758 lines). Produces human-readable
/// text output similar to `openssl rsa -text` or `openssl ec -text`,
/// displaying key parameters, public point coordinates, and modulus
/// in labeled hexadecimal format.
pub mod text_encoder;

/// EC public key blob encoder.
///
/// Source: `encode_key2blob.c` (179 lines). Encodes EC public keys
/// as uncompressed point blobs (`0x04 || x || y`) for use in
/// contexts requiring raw public key bytes.
#[cfg(feature = "ec")]
pub mod blob_encoder;

/// Microsoft MSBLOB/PVK key encoders.
///
/// Source: `encode_key2ms.c` (233 lines). Encodes RSA and DSA keys
/// in Microsoft `PUBLICKEYBLOB`/`PRIVATEKEYBLOB` and PVK formats
/// for interoperability with Windows CryptoAPI consumers.
pub mod ms_encoder;

// ============================================================================
// Public Re-exports — Decoder Types
// ============================================================================

/// DER-to-key decoder supporting PKCS#8, SPKI, and legacy formats.
pub use der_decoder::DerDecoder;

/// PEM-to-DER decoder for PEM armor stripping and Base64 decoding.
pub use pem_decoder::PemDecoder;

/// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`) to `PrivateKeyInfo` decoder.
pub use epki_decoder::EpkiDecoder;

/// `SubjectPublicKeyInfo` type-tagging decoder for algorithm identification.
pub use spki_decoder::SpkiTaggingDecoder;

/// Microsoft MSBLOB key format decoder for RSA and DSA keys.
pub use msblob_decoder::MsBlobDecoder;

/// Microsoft PVK private key format decoder for RSA and DSA keys.
pub use pvk_decoder::PvkDecoder;

/// LMS/HSS XDR public key decoder per RFC 8554.
#[cfg(feature = "lms")]
pub use lms_decoder::LmsXdrDecoder;

// ============================================================================
// Public Re-exports — Encoder Types
// ============================================================================

/// Key encoder supporting PKCS#8, SPKI, and legacy DER/PEM formats.
pub use key_encoder::KeyEncoder;

/// Text format encoder for human-readable key representation.
pub use text_encoder::TextEncoder;

/// EC public key blob encoder for uncompressed point format.
#[cfg(feature = "ec")]
pub use blob_encoder::BlobEncoder;

/// Microsoft MSBLOB key format encoder for RSA and DSA keys.
pub use ms_encoder::MsBlobEncoder;

/// Microsoft PVK private key format encoder for RSA and DSA keys.
pub use ms_encoder::PvkEncoder;

// ============================================================================
// Public Re-exports — Common Types, Constants, and Utilities
// ============================================================================

/// Enumeration of cryptographic object types handled by encoders/decoders.
///
/// Represents the kind of cryptographic object being processed: private key,
/// public key, key parameters, or an encrypted private key container.
pub use common::ObjectType;

/// Container for a decoded cryptographic object with metadata.
///
/// Holds the decoded key material along with information about the object
/// type, algorithm name, and structure format from which it was decoded.
pub use common::DecodedObject;

/// Error type for encoder/decoder operations.
///
/// Covers all failure modes: format errors, unsupported algorithms,
/// password/decryption failures, invalid key data, and I/O errors.
pub use common::EndecoderError;

/// Import raw key data into a provider key object.
///
/// Translates raw key bytes (DER-decoded or format-specific) into the
/// provider's internal key representation via the key management layer.
/// Source: `ossl_prov_import_key()` in `endecoder_common.c`.
pub use common::import_key;

/// Read DER-encoded data from an input byte slice.
///
/// Performs basic DER tag-length-value parsing to extract a complete
/// DER-encoded object from the input buffer. Returns the consumed
/// bytes and the DER content.
/// Source: `ossl_read_der()` in `endecoder_common.c`.
pub use common::read_der;

/// Check if a key selection satisfies the hierarchy requirements.
///
/// Validates that the requested selection (private key, public key,
/// parameters) is consistent with the data available in the decoded
/// object. For example, a private key selection implies public key
/// data is also available.
pub use common::check_selection_hierarchy;

/// DER encoding format constant identifier.
///
/// Used by encoders and decoders to indicate DER (Distinguished
/// Encoding Rules) binary format.
pub use common::FORMAT_DER;

/// PEM encoding format constant identifier.
///
/// Used by encoders and decoders to indicate PEM (Privacy-Enhanced
/// Mail) Base64-armored text format per RFC 7468.
pub use common::FORMAT_PEM;

/// Text encoding format constant identifier.
///
/// Used by text encoders to indicate human-readable text output
/// format (e.g., `openssl rsa -text` style output).
pub use common::FORMAT_TEXT;

/// PKCS#8 `PrivateKeyInfo` structure identifier.
///
/// Identifies the `PrivateKeyInfo` ASN.1 structure (RFC 5958) used
/// for unencrypted private key serialization.
pub use common::STRUCTURE_PRIVATE_KEY_INFO;

/// PKCS#8 `EncryptedPrivateKeyInfo` structure identifier.
///
/// Identifies the `EncryptedPrivateKeyInfo` ASN.1 structure (RFC 5958)
/// used for password-encrypted private key serialization.
pub use common::STRUCTURE_ENCRYPTED_PRIVATE_KEY_INFO;

/// X.509 `SubjectPublicKeyInfo` structure identifier.
///
/// Identifies the `SubjectPublicKeyInfo` ASN.1 structure (RFC 5280)
/// used for public key serialization.
pub use common::STRUCTURE_SUBJECT_PUBLIC_KEY_INFO;

// ============================================================================
// Algorithm Descriptor Registration Functions
// ============================================================================

/// Returns all encoder algorithm descriptors registered by this module.
///
/// Aggregates encoder descriptors from all encoder submodules:
///
/// - [`key_encoder`] — PKCS#8, SPKI, and legacy DER/PEM key encoders
/// - [`text_encoder`] — Human-readable text format encoders
/// - [`blob_encoder`] — EC public key blob encoders (requires feature `"ec"`)
/// - [`ms_encoder`] — Microsoft MSBLOB and PVK format encoders
///
/// Called by [`super::all_encoder_descriptors()`] when the `"encode-decode"`
/// feature is enabled. The returned descriptors are used by
/// `DefaultProvider::query_operation()` and `BaseProvider::query_operation()`
/// for `OperationType::Encoder`.
///
/// Replaces C `ossl_*_encoder_functions` dispatch table references from
/// `providers/defltprov.c` and `providers/baseprov.c`.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::encode_decode;
///
/// let encoders = encode_decode::encoder_descriptors();
/// for desc in &encoders {
///     println!("{}: {} ({})", desc.names.join("/"), desc.description, desc.property);
/// }
/// ```
#[must_use]
pub fn encoder_descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descriptors = Vec::new();

    // PKCS#8/SPKI/legacy DER/PEM key encoders (largest set)
    descriptors.extend(key_encoder::all_key_encoders());

    // Human-readable text format encoders
    descriptors.extend(text_encoder::all_text_encoders());

    // EC public key blob encoders (feature-gated)
    #[cfg(feature = "ec")]
    {
        descriptors.extend(blob_encoder::all_blob_encoders());
    }

    // Microsoft MSBLOB and PVK format encoders
    descriptors.extend(ms_encoder::all_ms_encoders());

    descriptors
}

/// Returns all decoder algorithm descriptors registered by this module.
///
/// Aggregates decoder descriptors from all decoder submodules:
///
/// - [`der_decoder`] — DER-to-key decoders for all algorithm types
/// - PEM-to-DER decoder (single instance, handles all PEM labels)
/// - `EncryptedPrivateKeyInfo` decryption bridge (single instance)
/// - `SubjectPublicKeyInfo` type-tagging decoder (single instance)
/// - [`msblob_decoder`] — Microsoft MSBLOB format decoders
/// - [`pvk_decoder`] — Microsoft PVK format decoders
/// - [`lms_decoder`] — LMS XDR key decoder (requires feature `"lms"`)
///
/// Called by [`super::all_decoder_descriptors()`] when the `"encode-decode"`
/// feature is enabled. The returned descriptors are used by
/// `DefaultProvider::query_operation()` and `BaseProvider::query_operation()`
/// for `OperationType::Decoder`.
///
/// Replaces C `ossl_*_decoder_functions` dispatch table references from
/// `providers/defltprov.c` and `providers/baseprov.c`.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::encode_decode;
///
/// let decoders = encode_decode::decoder_descriptors();
/// for desc in &decoders {
///     println!("{}: {} ({})", desc.names.join("/"), desc.description, desc.property);
/// }
/// ```
#[must_use]
pub fn decoder_descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descriptors = Vec::new();

    // DER-to-key decoders — per-algorithm type descriptors
    // Source: decode_der2key.c key type descriptor table
    descriptors.extend(der_decoder::all_der_decoders());

    // PEM-to-DER decoder — single instance handling all PEM labels.
    // Source: decode_pem2der.c pem_name_map[] label table.
    // Strips PEM armor (-----BEGIN/END-----) and Base64-decodes the body,
    // identifying the object type from the PEM label.
    descriptors.push(AlgorithmDescriptor {
        names: vec!["pem"],
        property: "provider=default,input=pem",
        description: "PEM-to-DER decoder (RFC 7468 armor stripping)",
    });

    // `EncryptedPrivateKeyInfo` → `PrivateKeyInfo` decryption bridge.
    // Source: decode_epki2pki.c — single instance.
    // Decrypts PKCS#8 encrypted private keys using PBES2/PBES1
    // password-based encryption. Requires a passphrase callback.
    descriptors.push(AlgorithmDescriptor {
        names: vec!["epki2pki"],
        property: "provider=default,input=der,structure=EncryptedPrivateKeyInfo",
        description: "Encrypted PKCS#8 `PrivateKeyInfo` decryptor (PBES2/PBES1)",
    });

    // `SubjectPublicKeyInfo` type-tagging decoder — single instance.
    // Source: decode_spki2typespki.c — single instance.
    // Peeks at the algorithm OID inside an SPKI structure to tag the key
    // with its algorithm name for downstream per-algorithm processing.
    descriptors.push(AlgorithmDescriptor {
        names: vec!["spki2typespki"],
        property: "provider=default,input=der,structure=SubjectPublicKeyInfo",
        description: "SPKI algorithm OID type-tagging decoder",
    });

    // Microsoft MSBLOB format decoders — per-algorithm type descriptors.
    // Source: decode_msblob2key.c MSBLOB format parser.
    descriptors.extend(msblob_decoder::all_msblob_decoders());

    // Microsoft PVK format decoders — per-algorithm type descriptors.
    // Source: decode_pvk2key.c PVK format parser with optional RC4 decryption.
    descriptors.extend(pvk_decoder::all_pvk_decoders());

    // LMS XDR public key decoder (feature-gated).
    // Source: decode_lmsxdr2key.c XDR wire format per RFC 8554.
    #[cfg(feature = "lms")]
    {
        descriptors.extend(lms_decoder::lms_xdr_decoder());
    }

    descriptors
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that encoder_descriptors returns a non-empty list and
    /// all descriptors have valid fields (Rule R10 — wiring verification).
    #[test]
    fn test_encoder_descriptors_non_empty() {
        let descs = encoder_descriptors();
        assert!(
            !descs.is_empty(),
            "encoder_descriptors() must return at least one descriptor"
        );
        for desc in &descs {
            assert!(
                !desc.names.is_empty(),
                "AlgorithmDescriptor.names must not be empty"
            );
            assert!(
                !desc.property.is_empty(),
                "AlgorithmDescriptor.property must not be empty"
            );
            assert!(
                !desc.description.is_empty(),
                "AlgorithmDescriptor.description must not be empty"
            );
        }
    }

    /// Verify that decoder_descriptors returns a non-empty list with
    /// the expected inline decoders (PEM, EPKI, SPKI) always present.
    #[test]
    fn test_decoder_descriptors_non_empty() {
        let descs = decoder_descriptors();
        assert!(
            !descs.is_empty(),
            "decoder_descriptors() must return at least one descriptor"
        );
        for desc in &descs {
            assert!(
                !desc.names.is_empty(),
                "AlgorithmDescriptor.names must not be empty"
            );
            assert!(
                !desc.property.is_empty(),
                "AlgorithmDescriptor.property must not be empty"
            );
            assert!(
                !desc.description.is_empty(),
                "AlgorithmDescriptor.description must not be empty"
            );
        }
    }

    /// Verify that the PEM decoder descriptor is present in decoder_descriptors.
    #[test]
    fn test_decoder_descriptors_contains_pem() {
        let descs = decoder_descriptors();
        let pem_found = descs.iter().any(|d| d.names.contains(&"pem"));
        assert!(pem_found, "decoder_descriptors() must include PEM decoder");
    }

    /// Verify that the EPKI decoder descriptor is present in decoder_descriptors.
    #[test]
    fn test_decoder_descriptors_contains_epki() {
        let descs = decoder_descriptors();
        let epki_found = descs.iter().any(|d| d.names.contains(&"epki2pki"));
        assert!(
            epki_found,
            "decoder_descriptors() must include EPKI-to-PKI decoder"
        );
    }

    /// Verify that the SPKI type-tagging decoder is present.
    #[test]
    fn test_decoder_descriptors_contains_spki() {
        let descs = decoder_descriptors();
        let spki_found = descs.iter().any(|d| d.names.contains(&"spki2typespki"));
        assert!(
            spki_found,
            "decoder_descriptors() must include SPKI type-tagging decoder"
        );
    }

    /// Verify all AlgorithmDescriptor fields are accessed correctly
    /// (validates internal import members_accessed: names, property, description).
    #[test]
    fn test_algorithm_descriptor_field_access() {
        let desc = AlgorithmDescriptor {
            names: vec!["test-algo", "alias"],
            property: "provider=test,input=der",
            description: "Test algorithm descriptor",
        };
        assert_eq!(desc.names.len(), 2);
        assert_eq!(desc.property, "provider=test,input=der");
        assert_eq!(desc.description, "Test algorithm descriptor");
    }
}
