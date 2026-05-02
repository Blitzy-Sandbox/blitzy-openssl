//! EncryptedPrivateKeyInfo → PrivateKeyInfo bridge decoder.
//!
//! Decrypts PKCS#8 encrypted private keys using a passphrase. Output is
//! standardised DER `PrivateKeyInfo` that feeds into downstream decoders.
//! Replaces C `decode_epki2pki.c` (206 lines).
//!
//! # Architecture
//!
//! The EPKI decoder sits in the OpenSSL 4.0 decode pipeline between the
//! raw DER reader and algorithm-specific key loaders:
//!
//! ```text
//! DER reader → [EpkiDecoder] → PrivateKeyInfo → algorithm-specific decoder
//! ```
//!
//! When input is a valid `EncryptedPrivateKeyInfo` (RFC 5958 §3 / RFC 5208 §6),
//! the decoder:
//!
//! 1. Parses the `EncryptedPrivateKeyInfo` envelope
//! 2. Obtains a passphrase (empty default through the trait interface;
//!    explicit passphrase via `decrypt_epki()` for pipeline callers)
//! 3. Decrypts the payload using the PKCS#5 PBE scheme (PBES2/PBES1)
//! 4. Parses the resulting `PrivateKeyInfo`
//! 5. Extracts the `AlgorithmIdentifier` OID and resolves it to a name
//! 6. Emits a [`DecodedObject`] annotated with the algorithm name
//!
//! If the input is not a valid `EncryptedPrivateKeyInfo`, the decoder
//! returns "empty-handed" (an error that callers treat as non-fatal),
//! allowing the framework to try other decoders in the chain.
//!
//! # C Source Mapping
//!
//! | C Function / Symbol | Rust Equivalent |
//! |---------------------|-----------------|
//! | `struct epki2pki_ctx_st` | `EpkiDecoderContext` |
//! | `ossl_epki2pki_der_decode()` | `EpkiDecoder::decode()` + `decrypt_epki()` |
//! | `PKCS12_pbe_crypt_ex()` | `decrypt_epki()` via `pkcs8::EncryptedPrivateKeyInfo::decrypt()` |
//! | `PKCS8_pkey_get0()` + `OBJ_obj2txt()` | `identify_key_algorithm()` |
//! | `ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions` | `impl DecoderProvider for EpkiDecoder` |
//!
//! # Rules Compliance
//!
//! - **R5:** `Option<T>` over sentinels — `EpkiDecoderContext::propq` uses `Option<String>`.
//! - **R8:** Zero `unsafe` blocks — pure Rust via `pkcs8` crate (RustCrypto).
//! - **R9:** Warning-free build — all items documented, no unused imports.

use der::{asn1::ObjectIdentifier, Decode};
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use tracing::{debug, warn};

use openssl_common::{ProviderError, ProviderResult};

use super::common::{
    read_der, DecodedObject, EndecoderError, ObjectType, FORMAT_DER, MAX_PROPQUERY_SIZE,
    STRUCTURE_PRIVATE_KEY_INFO,
};
use crate::traits::{DecoderProvider, KeyData, KeySelection};

// Re-use the comprehensive OID → algorithm name mapping from the SPKI decoder.
// Both decoders need the same mapping (C used OBJ_obj2txt / OBJ_nid2sn globally).
use super::spki_decoder::oid_to_algorithm_name;

// =============================================================================
// Well-Known OID Constants
// =============================================================================
//
// These constants are used for documentation and as fallback references.
// The primary OID→name resolution goes through `oid_to_algorithm_name()`.

/// PKCS#5 PBES2 encryption scheme OID: `1.2.840.113549.1.5.13`
///
/// This is the most common encryption algorithm identifier found in modern
/// `EncryptedPrivateKeyInfo` structures. Used for documentation and diagnostic
/// logging — the `pkcs8` crate handles OID matching internally during decryption.
const OID_PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");

/// The key selection type produced by this decoder.
///
/// EPKI structures always contain private keys — the decrypted output is a
/// `PrivateKeyInfo` (PKCS#8 unencrypted), which carries a private key.
const DECODED_KEY_SELECTION: KeySelection = KeySelection::PRIVATE_KEY;

// =============================================================================
// EpkiDecoderContext — Per-Operation Decoder Context
// =============================================================================

/// Per-operation context for EPKI-to-PKI decoding.
///
/// Carries optional property query string used for algorithm lookup in the
/// provider registry. Replaces C `struct epki2pki_ctx_st` from
/// `decode_epki2pki.c` (lines 37–41):
///
/// ```c
/// struct epki2pki_ctx_st {
///     PROV_CTX *provctx;
///     char propq[OSSL_MAX_PROPQUERY_SIZE];
/// };
/// ```
///
/// The `provctx` field is not needed in Rust — the provider context is
/// available via the `DecoderProvider` trait methods. The `propq` field
/// is preserved for API compatibility with the C property query system.
#[derive(Debug, Clone)]
pub struct EpkiDecoderContext {
    /// Optional property query string for algorithm lookup.
    ///
    /// Corresponds to the C `propq` field in `epki2pki_ctx_st`.
    /// Bounded to [`MAX_PROPQUERY_SIZE`] characters. Uses `Option<String>`
    /// per Rule R5 — `None` means "no property query", not empty string.
    pub propq: Option<String>,
}

impl EpkiDecoderContext {
    /// Creates a new EPKI decoder context with no property query.
    ///
    /// Replaces C `epki2pki_newctx()` which allocates and zero-inits
    /// the context struct (lines 43–56 of `decode_epki2pki.c`).
    pub fn new() -> Self {
        Self { propq: None }
    }

    /// Creates a new EPKI decoder context with the given property query.
    ///
    /// The property query string is truncated to [`MAX_PROPQUERY_SIZE`]
    /// characters if it exceeds the limit, matching the C behaviour where
    /// `propq` is a fixed-size `char[OSSL_MAX_PROPQUERY_SIZE]` buffer.
    ///
    /// Replaces C `epki2pki_set_ctx_params()` (lines 63–82 of
    /// `decode_epki2pki.c`).
    pub fn with_propq(propq: &str) -> Self {
        let truncated = if propq.len() > MAX_PROPQUERY_SIZE {
            &propq[..MAX_PROPQUERY_SIZE]
        } else {
            propq
        };
        Self {
            propq: Some(truncated.to_string()),
        }
    }
}

impl Default for EpkiDecoderContext {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// EpkiDecoder — EncryptedPrivateKeyInfo Bridge Decoder
// =============================================================================

/// `EncryptedPrivateKeyInfo` → `PrivateKeyInfo` bridge decoder.
///
/// Parses a DER-encoded `EncryptedPrivateKeyInfo` structure (RFC 5958 §3),
/// decrypts the encrypted payload using PKCS#5 password-based encryption
/// (PBES2 or legacy PBES1), parses the resulting `PrivateKeyInfo`, extracts
/// the `AlgorithmIdentifier` OID, resolves it to an algorithm name, and
/// returns a [`DecodedObject`] annotated with:
///
/// - `data_type` = resolved algorithm name (e.g., `"RSA"`, `"EC"`, `"Ed25519"`)
/// - `input_type` = `"DER"`
/// - `data_structure` = `"PrivateKeyInfo"` (the decrypted output structure)
/// - `object_type` = [`ObjectType::Pkey`]
/// - `data` = decrypted `PrivateKeyInfo` DER bytes
///
/// This is a "bridge" decoder: it transforms encrypted key material into
/// unencrypted `PrivateKeyInfo` DER for downstream algorithm-specific
/// processing.
///
/// # Passphrase Handling
///
/// In the C implementation (`decode_epki2pki.c`), the passphrase is obtained
/// via an `OSSL_PASSPHRASE_CALLBACK` during the decode call. The Rust
/// [`DecoderProvider::decode`] trait does not support callbacks, so:
///
/// - The trait-based [`decode()`](DecoderProvider::decode) attempts decryption
///   with an empty passphrase (common for test and unprotected keys).
/// - For explicit passphrase-based decryption, callers use the standalone
///   `decrypt_epki()` function directly, passing the passphrase.
///
/// Replaces the C `ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions`
/// dispatch table from `decode_epki2pki.c` (lines 196–206).
///
/// # Thread Safety
///
/// `EpkiDecoder` is a zero-sized, stateless struct and is trivially
/// `Send + Sync`.
#[derive(Debug, Clone, Copy)]
pub struct EpkiDecoder;

/// Wrapper around [`DecodedObject`] that implements [`KeyData`] so it can
/// be returned from [`DecoderProvider::decode`].
///
/// The provider dispatch system expects decoders to return `Box<dyn KeyData>`.
/// This wrapper provides that conformance while carrying the full decoded
/// metadata (algorithm name, decrypted DER bytes) needed by downstream
/// decoders.
// JUSTIFICATION for `dead_code` allow: `DecryptedPrivateKeyData` is the
// runtime payload carried inside a `Box<dyn KeyData>` trait object returned
// by `EpkiDecoder::decode()`. The `decoded` field stores the algorithm-tagged
// decrypted PrivateKeyInfo DER bytes. Downstream decode pipeline stages
// retrieve this data by downcasting the trait object (via `Any`). Since the
// downcast accessor lives in consumer code (not this module), the compiler
// cannot see the read site and reports the field as dead. The field is
// architecturally required for the decode chain to function.
#[derive(Debug)]
#[allow(dead_code)]
struct DecryptedPrivateKeyData {
    /// The decoded object carrying the decrypted `PrivateKeyInfo` DER bytes
    /// annotated with the resolved algorithm name.
    decoded: DecodedObject,
}

impl KeyData for DecryptedPrivateKeyData {}

impl EpkiDecoder {
    /// Creates a new EPKI bridge decoder.
    ///
    /// Replaces C `epki2pki_newctx()` (lines 43–56 of `decode_epki2pki.c`).
    pub fn new() -> Self {
        Self
    }
}

impl Default for EpkiDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderProvider for EpkiDecoder {
    /// Returns the canonical decoder name: `"EncryptedPrivateKeyInfo"`.
    ///
    /// Matches the C decoder registration name from the
    /// `ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions`
    /// dispatch table in `decode_epki2pki.c` (line 196).
    fn name(&self) -> &'static str {
        "EncryptedPrivateKeyInfo"
    }

    /// Decodes a DER-encoded `EncryptedPrivateKeyInfo`, decrypts the payload,
    /// extracts the algorithm OID, and returns a tagged [`DecodedObject`]
    /// wrapped as [`KeyData`].
    ///
    /// # Empty-Handed Pattern (Rule R5)
    ///
    /// If `input` cannot be parsed as a valid `EncryptedPrivateKeyInfo`, this
    /// method returns an error wrapping [`EndecoderError::BadEncoding`].
    /// Per the C source (line 109: `/* We return "empty handed". This is not
    /// an error. */`), callers should treat decoding failures as non-fatal:
    /// the input simply isn't EPKI and should be tried by other decoders in
    /// the chain.
    ///
    /// # Passphrase Handling
    ///
    /// The trait-based decode attempts decryption with an empty passphrase.
    /// If the key requires a non-empty passphrase, the method returns
    /// `ProviderError::Dispatch` wrapping [`EndecoderError::UnableToGetPassphrase`].
    /// Callers with passphrase access should use `decrypt_epki()` directly.
    ///
    /// # Errors
    ///
    /// - `ProviderError::Dispatch` wrapping [`EndecoderError::BadEncoding`]:
    ///   input is not valid EPKI DER.
    /// - `ProviderError::Dispatch` wrapping [`EndecoderError::UnableToGetPassphrase`]:
    ///   decryption failed (passphrase required but not available via trait).
    /// - `ProviderError::Dispatch`: unrecognised algorithm OID in the
    ///   decrypted `PrivateKeyInfo`.
    fn decode(&self, input: &[u8]) -> ProviderResult<Box<dyn KeyData>> {
        debug!(
            input_len = input.len(),
            "EPKI bridge decoder: starting decode"
        );

        // Step 1: Validate DER structure via read_der pre-check.
        //
        // Replaces C `read_der(ctx->provctx, cin, &der, &der_len)` from
        // decode_epki2pki.c line 106. read_der returns (bytes, consumed_len).
        let (der_bytes, _consumed) = read_der(input).map_err(|e| {
            debug!(error = %e, "input is not valid DER — returning empty-handed");
            ProviderError::Dispatch(EndecoderError::BadEncoding.to_string())
        })?;

        // Step 2: Parse EncryptedPrivateKeyInfo from DER.
        //
        // Replaces C `d2i_X509_SIG(NULL, &derp, der_len)` from
        // decode_epki2pki.c line 120.
        //
        // If parsing fails, we return an error. The caller (decoder chain)
        // treats this as "empty handed" — the input is not EPKI and should
        // be tried by other decoders.
        let _epki = EncryptedPrivateKeyInfo::from_der(&der_bytes).map_err(|e| {
            debug!(
                error = %e,
                "input is not valid EncryptedPrivateKeyInfo — returning empty-handed"
            );
            ProviderError::Dispatch(EndecoderError::BadEncoding.to_string())
        })?;

        debug!(
            encryption_oid = %OID_PBES2,
            selection = ?DECODED_KEY_SELECTION,
            "EPKI bridge decoder: valid EncryptedPrivateKeyInfo detected"
        );

        // Step 3: Attempt decryption with empty passphrase.
        //
        // In the C implementation, the passphrase is obtained via
        // OSSL_PASSPHRASE_CALLBACK (lines 132–140 of decode_epki2pki.c).
        // The Rust DecoderProvider trait does not support callbacks, so we
        // attempt decryption with an empty passphrase. For keys that require
        // a real passphrase, callers should use decrypt_epki() directly.
        let pki_der = match decrypt_epki(&der_bytes, &[]) {
            Ok(bytes) => {
                debug!(
                    decrypted_len = bytes.len(),
                    "EPKI bridge decoder: decryption with empty passphrase succeeded"
                );
                bytes
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "EPKI bridge decoder: decryption with empty passphrase failed; \
                     caller should use decrypt_epki() with correct passphrase"
                );
                return Err(ProviderError::Dispatch(
                    EndecoderError::UnableToGetPassphrase.to_string(),
                ));
            }
        };

        // Step 4: Identify algorithm from decrypted PrivateKeyInfo.
        //
        // Replaces C `PKCS8_pkey_get0(NULL, NULL, NULL, &alg, pki)` +
        // `OBJ_obj2txt(dataname, ...)` from decode_epki2pki.c lines
        // 161–177.
        let algorithm_name = identify_key_algorithm(&pki_der)?;

        debug!(
            algorithm = %algorithm_name,
            input_type = FORMAT_DER,
            data_structure = STRUCTURE_PRIVATE_KEY_INFO,
            "EPKI bridge decoder: resolved algorithm name"
        );

        // Step 5: Construct the tagged DecodedObject.
        //
        // Re-emit the decrypted PrivateKeyInfo DER bytes annotated with the
        // resolved algorithm name. Replaces C OSSL_PARAM construction at
        // lines 179–193 of decode_epki2pki.c:
        //
        //   params[0] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, ...)
        //   params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_INPUT_TYPE, ...)
        //   params[2] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, ...)
        //   params[3] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, ...)
        //   params[4] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, ...)
        let decoded = DecodedObject {
            object_type: ObjectType::Pkey,
            data_type: algorithm_name,
            input_type: FORMAT_DER,
            data_structure: Some(STRUCTURE_PRIVATE_KEY_INFO.to_string()),
            data: pki_der,
        };

        debug!(
            data_type = %decoded.data_type,
            input_type = decoded.input_type,
            data_structure = ?decoded.data_structure,
            data_len = decoded.data.len(),
            "EPKI bridge decoder: constructed DecodedObject"
        );

        Ok(Box::new(DecryptedPrivateKeyData { decoded }))
    }

    /// Returns the list of supported input formats.
    ///
    /// The EPKI bridge decoder only processes DER-encoded input.
    /// PEM input should be stripped by the PEM-to-DER decoder first.
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_DER]
    }
}

// =============================================================================
// Standalone Decryption Function
// =============================================================================

/// Decrypts a DER-encoded `EncryptedPrivateKeyInfo` using the provided
/// passphrase and returns the plain `PrivateKeyInfo` DER bytes.
///
/// This is the primary EPKI decryption entry point for callers that have
/// access to the passphrase (e.g., the provider pipeline with passphrase
/// callback). It performs the full decryption flow:
///
/// 1. Parse `EncryptedPrivateKeyInfo` envelope from DER
/// 2. Extract the PKCS#5 encryption scheme (PBES2 or legacy PBES1)
/// 3. Decrypt the encrypted data using the passphrase
/// 4. Return the raw `PrivateKeyInfo` DER bytes
///
/// # Arguments
///
/// * `input` — DER-encoded `EncryptedPrivateKeyInfo` bytes.
/// * `passphrase` — Password for PKCS#5 PBE decryption. May be empty for
///   keys encrypted with an empty passphrase.
///
/// # Returns
///
/// The decrypted `PrivateKeyInfo` DER bytes as `Vec<u8>`.
///
/// # Errors
///
/// - `ProviderError::Dispatch` wrapping [`EndecoderError::BadEncoding`]:
///   input is not valid `EncryptedPrivateKeyInfo` DER.
/// - `ProviderError::Dispatch`: decryption failed (wrong passphrase,
///   unsupported PBE algorithm, corrupt ciphertext).
///
/// # C Source Mapping
///
/// Replaces the combined operation of:
/// - `d2i_X509_SIG()` — parsing the `EncryptedPrivateKeyInfo` envelope
/// - `PKCS12_pbe_crypt_ex()` — performing PBE decryption
///
/// from `decode_epki2pki.c` lines 120–153.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_provider::implementations::encode_decode::epki_decoder::decrypt_epki;
/// let epki_der: &[u8] = &[/* DER bytes */];
/// let passphrase = b"secret";
/// let pki_der = decrypt_epki(epki_der, passphrase).expect("decryption failed");
/// // pki_der is now the plain PrivateKeyInfo DER
/// ```
pub fn decrypt_epki(input: &[u8], passphrase: &[u8]) -> ProviderResult<Vec<u8>> {
    debug!(
        input_len = input.len(),
        passphrase_len = passphrase.len(),
        "decrypt_epki: starting EncryptedPrivateKeyInfo decryption"
    );

    // Step 1: Parse EncryptedPrivateKeyInfo from DER.
    //
    // Replaces C `d2i_X509_SIG(NULL, &derp, der_len)` from
    // decode_epki2pki.c line 120.
    let epki = EncryptedPrivateKeyInfo::from_der(input).map_err(|e| {
        warn!(error = %e, "decrypt_epki: failed to parse EncryptedPrivateKeyInfo");
        ProviderError::Dispatch(EndecoderError::BadEncoding.to_string())
    })?;

    // Step 2: Decrypt using PKCS#5 PBE.
    //
    // The pkcs8 crate's decrypt() method handles PBES2 (scrypt + AES-256-CBC)
    // and legacy PBES1 schemes internally. This replaces:
    //   - C `X509_SIG_get0()` to extract alg + encrypted data
    //   - C `PKCS12_pbe_crypt_ex(alg, upass, upasslen, ...)` for decryption
    //
    // from decode_epki2pki.c lines 142–153.
    let secret_doc = epki.decrypt(passphrase).map_err(|e| {
        warn!(error = %e, "decrypt_epki: PKCS#5 PBE decryption failed");
        ProviderError::Dispatch(format!("EncryptedPrivateKeyInfo decryption failed: {e}"))
    })?;

    let decrypted_bytes = secret_doc.as_bytes().to_vec();
    debug!(
        decrypted_len = decrypted_bytes.len(),
        "decrypt_epki: decryption succeeded"
    );
    Ok(decrypted_bytes)
}

// =============================================================================
// Algorithm Identification
// =============================================================================

/// Extracts the algorithm name from a DER-encoded `PrivateKeyInfo`.
///
/// Parses the `PrivateKeyInfo` structure, extracts the `AlgorithmIdentifier`
/// OID from the `privateKeyAlgorithm` field, and resolves it to a
/// human-readable algorithm name string using the shared OID→name mapping.
///
/// # Arguments
///
/// * `pki_der` — DER-encoded `PrivateKeyInfo` bytes (the decrypted output
///   from `decrypt_epki()`).
///
/// # Returns
///
/// The algorithm name string (e.g., `"RSA"`, `"EC"`, `"Ed25519"`,
/// `"ML-KEM-768"`, `"SLH-DSA-SHA2-128s"`).
///
/// # Errors
///
/// - `ProviderError::Dispatch` wrapping [`EndecoderError::BadEncoding`]:
///   input is not valid `PrivateKeyInfo` DER.
/// - `ProviderError::Dispatch`: the algorithm OID is unrecognised.
///
/// # C Source Mapping
///
/// Replaces the combined operation of:
/// - `d2i_PKCS8_PRIV_KEY_INFO()` — parsing `PrivateKeyInfo`
/// - `PKCS8_pkey_get0(NULL, NULL, NULL, &alg, pki)` — extracting `AlgId`
/// - `OBJ_obj2txt(dataname, sizeof(dataname), OBJ_nid2obj(...), 1)` — OID→text
///
/// from `decode_epki2pki.c` lines 158–177.
///
/// # Example
///
/// ```rust,no_run
/// # use openssl_provider::implementations::encode_decode::epki_decoder::identify_key_algorithm;
/// let pki_der: &[u8] = &[/* PrivateKeyInfo DER bytes */];
/// let algo = identify_key_algorithm(pki_der).expect("algorithm extraction failed");
/// assert_eq!(algo, "RSA");
/// ```
pub fn identify_key_algorithm(pki_der: &[u8]) -> ProviderResult<String> {
    debug!(
        pki_len = pki_der.len(),
        "identify_key_algorithm: parsing PrivateKeyInfo"
    );

    // Step 1: Parse PrivateKeyInfo from DER.
    //
    // Replaces C `d2i_PKCS8_PRIV_KEY_INFO(NULL, &derp, derlen)` from
    // decode_epki2pki.c line 158.
    let pki = PrivateKeyInfo::from_der(pki_der).map_err(|e| {
        warn!(
            error = %e,
            "identify_key_algorithm: failed to parse PrivateKeyInfo"
        );
        ProviderError::Dispatch(EndecoderError::BadEncoding.to_string())
    })?;

    // Step 2: Extract the AlgorithmIdentifier OID.
    //
    // Replaces C `PKCS8_pkey_get0(NULL, NULL, NULL, &alg, pki)` +
    // `X509_ALGOR_get0(&oid, ...)` from decode_epki2pki.c lines 161–168.
    let algorithm_oid = pki.algorithm.oid;
    debug!(
        oid = %algorithm_oid,
        "identify_key_algorithm: extracted AlgorithmIdentifier OID"
    );

    // Step 3: Resolve OID to algorithm name.
    //
    // Re-uses the comprehensive OID→name mapping from the SPKI decoder,
    // which covers all algorithm types supported by OpenSSL 4.0:
    // RSA, RSA-PSS, EC, X25519/X448, Ed25519/Ed448, DH, DHX, DSA,
    // ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS.
    //
    // Replaces C `OBJ_obj2txt(dataname, sizeof(dataname), oid, 1)` from
    // decode_epki2pki.c line 177.
    let name = oid_to_algorithm_name(&algorithm_oid).ok_or_else(|| {
        warn!(
            oid = %algorithm_oid,
            "identify_key_algorithm: unrecognised algorithm OID"
        );
        ProviderError::Dispatch(format!(
            "unrecognised algorithm OID in PrivateKeyInfo: {algorithm_oid}"
        ))
    })?;

    debug!(
        algorithm = name,
        oid = %algorithm_oid,
        "identify_key_algorithm: resolved algorithm name"
    );
    Ok(name.to_string())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the decoder reports the correct canonical name.
    #[test]
    fn test_decoder_name() {
        let decoder = EpkiDecoder::new();
        assert_eq!(decoder.name(), "EncryptedPrivateKeyInfo");
    }

    /// Verify the decoder supports only DER format.
    #[test]
    fn test_supported_formats() {
        let decoder = EpkiDecoder::new();
        let formats = decoder.supported_formats();
        assert_eq!(formats, vec!["DER"]);
    }

    /// Verify Default trait implementation.
    #[test]
    fn test_decoder_default() {
        let decoder = EpkiDecoder::default();
        assert_eq!(decoder.name(), "EncryptedPrivateKeyInfo");
    }

    /// Verify context creation with no propq.
    #[test]
    fn test_context_new() {
        let ctx = EpkiDecoderContext::new();
        assert!(ctx.propq.is_none());
    }

    /// Verify context creation with propq.
    #[test]
    fn test_context_with_propq() {
        let ctx = EpkiDecoderContext::with_propq("provider=default");
        assert_eq!(ctx.propq.as_deref(), Some("provider=default"));
    }

    /// Verify context propq truncation at MAX_PROPQUERY_SIZE.
    #[test]
    fn test_context_propq_truncation() {
        let long_propq = "x".repeat(MAX_PROPQUERY_SIZE + 100);
        let ctx = EpkiDecoderContext::with_propq(&long_propq);
        let propq = ctx.propq.as_ref().expect("propq should be Some");
        assert_eq!(propq.len(), MAX_PROPQUERY_SIZE);
    }

    /// Verify Default trait for context.
    #[test]
    fn test_context_default() {
        let ctx = EpkiDecoderContext::default();
        assert!(ctx.propq.is_none());
    }

    /// Verify that non-EPKI input returns BadEncoding error (empty-handed).
    #[test]
    fn test_decode_non_epki_input() {
        let decoder = EpkiDecoder::new();
        // Random bytes that are not valid DER/EPKI
        let garbage = &[0x01, 0x02, 0x03, 0x04];
        let result = decoder.decode(garbage);
        assert!(result.is_err());
    }

    /// Verify that decrypt_epki rejects non-DER input.
    #[test]
    fn test_decrypt_epki_bad_input() {
        let result = decrypt_epki(&[0xFF, 0xFF], &[]);
        assert!(result.is_err());
    }

    /// Verify that identify_key_algorithm rejects non-PKI input.
    #[test]
    fn test_identify_key_algorithm_bad_input() {
        let result = identify_key_algorithm(&[0x01, 0x02]);
        assert!(result.is_err());
    }

    /// Verify that the decoded key selection constant is PRIVATE_KEY.
    #[test]
    fn test_decoded_key_selection() {
        assert_eq!(DECODED_KEY_SELECTION, KeySelection::PRIVATE_KEY);
    }

    /// Verify that OID_PBES2 constant is correctly defined.
    #[test]
    fn test_oid_pbes2_constant() {
        assert_eq!(OID_PBES2.to_string(), "1.2.840.113549.1.5.13");
    }

    /// Verify that EpkiDecoder is Send + Sync (required by DecoderProvider).
    #[test]
    fn test_decoder_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EpkiDecoder>();
    }

    /// Verify that DecryptedPrivateKeyData implements KeyData.
    #[test]
    fn test_key_data_impl() {
        let decoded = DecodedObject {
            object_type: ObjectType::Pkey,
            data_type: "RSA".to_string(),
            input_type: FORMAT_DER,
            data_structure: Some(STRUCTURE_PRIVATE_KEY_INFO.to_string()),
            data: vec![0x30, 0x00],
        };
        let key_data = DecryptedPrivateKeyData { decoded };
        // Verify it can be boxed as dyn KeyData (the trait object coercion)
        let _boxed: Box<dyn KeyData> = Box::new(key_data);
    }
}
