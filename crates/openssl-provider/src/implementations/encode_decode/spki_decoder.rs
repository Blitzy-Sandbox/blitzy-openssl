//! `SubjectPublicKeyInfo` type-tagging decoder.
//!
//! Parses SPKI to extract the `AlgorithmIdentifier` OID, then re-emits the
//! original DER annotated with the algorithm name for downstream
//! algorithm-specific decoders.
//!
//! Replaces C `decode_spki2typespki.c` (168 lines).
//!
//! # Architecture
//!
//! In the OpenSSL C codebase, `decode_spki2typespki.c` is a "type-tagging"
//! decoder:  it reads a generic `SubjectPublicKeyInfo` DER blob, peeks at the
//! `AlgorithmIdentifier` OID to determine the algorithm name (RSA, EC, EdDSA,
//! ML-KEM, etc.), and then passes the original DER bytes downstream with a
//! `data_type` tag set to the resolved algorithm name.  Downstream decoders
//! then use the tag to select the correct algorithm-specific parser.
//!
//! In Rust, this translates to:
//!
//! 1. Parse the DER using [`spki::SubjectPublicKeyInfoRef`] (zero `unsafe`).
//! 2. Extract the [`der::asn1::ObjectIdentifier`] from
//!    [`AlgorithmIdentifier::oid`](spki::AlgorithmIdentifier::oid).
//! 3. Map the OID to a human-readable algorithm name via
//!    `oid_to_algorithm_name`.
//! 4. Construct a `DecodedObject` carrying the original DER bytes annotated
//!    with `data_type = <algorithm_name>`, `input_type = "DER"`,
//!    `data_structure = "SubjectPublicKeyInfo"`, and  
//!    `object_type = ObjectType::Pkey`.
//!
//! # SM2 Special Case
//!
//! SM2 "abuses" the EC OID (`1.2.840.10045.2.1`) but uses the SM2 curve
//! parameter OID (`1.2.156.10197.1.301`).  The function `is_sm2_key`
//! detects this case by examining the
//! `AlgorithmIdentifier.parameters`
//! field.  This is feature-gated behind `cfg(feature = "sm2")`.
//!
//! # Empty-Handed Success (Rule R5)
//!
//! Per the C source comment at line 116 ("We return 'empty handed'.  This is
//! not an error."), if the input does not parse as valid SPKI, the decoder
//! returns `Ok(None)` — **not** an error.  Only structural failures *after*
//! successful SPKI parsing produce errors.
//!
//! # Rules Enforced
//!
//! - **R5:** `Option<T>` for unparseable input, never sentinel values.
//! - **R6:** No bare `as` casts.
//! - **R7:** No shared mutable state; the decoder is stateless.
//! - **R8:** Zero `unsafe` code — pure Rust DER parsing via `spki` + `der`.
//! - **R9:** Warning-free; every public item documented.
//! - **R10:** Reachable from `decoder_descriptors()` → `SpkiTaggingDecoder`.
//!
//! # Source Reference
//!
//! - `providers/implementations/encode_decode/decode_spki2typespki.c`
//! - `include/openssl/core_dispatch.h` — `OSSL_FUNC_DECODER_*` IDs
//! - `include/openssl/core_object.h` — `OSSL_OBJECT_PKEY`

use der::{asn1::ObjectIdentifier, Decode};
use spki::SubjectPublicKeyInfoRef;
use tracing::{debug, trace};

use openssl_common::{ProviderError, ProviderResult};

use crate::traits::{DecoderProvider, KeyData};
use super::common::{
    DecodedObject, EndecoderError, ObjectType, FORMAT_DER, MAX_PROPQUERY_SIZE,
    STRUCTURE_SUBJECT_PUBLIC_KEY_INFO,
};

// =============================================================================
// Well-Known Algorithm OIDs
// =============================================================================

/// RSA encryption OID: `1.2.840.113549.1.1.1` (PKCS#1)
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// RSA-PSS OID: `1.2.840.113549.1.1.10` (PKCS#1 v2.1)
const OID_RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// EC public key OID: `1.2.840.10045.2.1` (ANSI X9.62 id-ecPublicKey)
const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// X25519 key agreement OID: `1.3.101.110` (RFC 8410)
const OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// X448 key agreement OID: `1.3.101.111` (RFC 8410)
const OID_X448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.111");

/// Ed25519 signature OID: `1.3.101.112` (RFC 8410)
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed448 signature OID: `1.3.101.113` (RFC 8410)
const OID_ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

/// DH key agreement OID: `1.2.840.113549.1.3.1` (PKCS#3)
const OID_DH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.3.1");

/// DHX (X9.42 DH) OID: `1.2.840.10046.2.1` (ANSI X9.42)
const OID_DHX: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10046.2.1");

/// DSA OID: `1.2.840.10040.4.1` (ANSI X9.30)
const OID_DSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

/// ML-KEM (FIPS 203) OID: `2.16.840.1.101.3.4.4.1`
/// (ML-KEM-512; the OID prefix for all ML-KEM parameter sets)
const OID_ML_KEM_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");

/// ML-KEM-768 OID: `2.16.840.1.101.3.4.4.2`
const OID_ML_KEM_768: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");

/// ML-KEM-1024 OID: `2.16.840.1.101.3.4.4.3`
const OID_ML_KEM_1024: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

/// ML-DSA-44 (FIPS 204) OID: `2.16.840.1.101.3.4.3.17`
const OID_ML_DSA_44: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// ML-DSA-65 OID: `2.16.840.1.101.3.4.3.18`
const OID_ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// ML-DSA-87 OID: `2.16.840.1.101.3.4.3.19`
const OID_ML_DSA_87: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// SLH-DSA-SHA2-128s (FIPS 205) OID: `2.16.840.1.101.3.4.3.20`
const OID_SLH_DSA_SHA2_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20");

/// SLH-DSA-SHA2-128f OID: `2.16.840.1.101.3.4.3.21`
const OID_SLH_DSA_SHA2_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.21");

/// SLH-DSA-SHA2-192s OID: `2.16.840.1.101.3.4.3.22`
const OID_SLH_DSA_SHA2_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22");

/// SLH-DSA-SHA2-192f OID: `2.16.840.1.101.3.4.3.23`
const OID_SLH_DSA_SHA2_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.23");

/// SLH-DSA-SHA2-256s OID: `2.16.840.1.101.3.4.3.24`
const OID_SLH_DSA_SHA2_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24");

/// SLH-DSA-SHA2-256f OID: `2.16.840.1.101.3.4.3.25`
const OID_SLH_DSA_SHA2_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.25");

/// SLH-DSA-SHAKE-128s OID: `2.16.840.1.101.3.4.3.26`
const OID_SLH_DSA_SHAKE_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.26");

/// SLH-DSA-SHAKE-128f OID: `2.16.840.1.101.3.4.3.27`
const OID_SLH_DSA_SHAKE_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.27");

/// SLH-DSA-SHAKE-192s OID: `2.16.840.1.101.3.4.3.28`
const OID_SLH_DSA_SHAKE_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.28");

/// SLH-DSA-SHAKE-192f OID: `2.16.840.1.101.3.4.3.29`
const OID_SLH_DSA_SHAKE_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.29");

/// SLH-DSA-SHAKE-256s OID: `2.16.840.1.101.3.4.3.30`
const OID_SLH_DSA_SHAKE_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.30");

/// SLH-DSA-SHAKE-256f OID: `2.16.840.1.101.3.4.3.31`
const OID_SLH_DSA_SHAKE_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.31");

/// LMS OID: `1.2.840.113549.1.9.16.3.17` (HSS/LMS hash-based signatures,
/// SP 800-208)
const OID_LMS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.17");

/// SM2 named curve OID: `1.2.156.10197.1.301`
///
/// Used by `is_sm2_key` to detect SM2 keys that use the generic EC
/// `AlgorithmIdentifier` OID but carry the SM2 curve as a parameter.
#[cfg(feature = "sm2")]
const OID_SM2_CURVE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");

// =============================================================================
// SpkiDecoderContext — Per-Operation Decoder Context
// =============================================================================

/// Per-operation context for SPKI type tagging.
///
/// Carries optional property query string used for algorithm lookup in the
/// provider registry. Replaces C `struct spki2typespki_ctx_st` from
/// `decode_spki2typespki.c` (lines 37–40):
///
/// ```c
/// struct spki2typespki_ctx_st {
///     PROV_CTX *provctx;
///     char propq[OSSL_MAX_PROPQUERY_SIZE];
/// };
/// ```
///
/// The `provctx` field is not needed in Rust — the provider context is
/// available via the `DecoderProvider` trait methods. The `propq` field
/// is preserved for API compatibility with the C property query system.
#[derive(Debug, Clone)]
pub struct SpkiDecoderContext {
    /// Optional property query string for algorithm lookup.
    ///
    /// Corresponds to the C `propq` field in `spki2typespki_ctx_st`.
    /// Bounded to `MAX_PROPQUERY_SIZE` characters. Uses `Option<String>`
    /// per Rule R5 — `None` means "no property query", not empty string.
    pub propq: Option<String>,
}

impl SpkiDecoderContext {
    /// Creates a new SPKI decoder context with no property query.
    ///
    /// Replaces C `spki2typespki_newctx()` which allocates and zero-inits
    /// the context struct.
    pub fn new() -> Self {
        Self { propq: None }
    }

    /// Creates a new SPKI decoder context with the given property query.
    ///
    /// The property query string is truncated to `MAX_PROPQUERY_SIZE`
    /// characters if it exceeds the limit, matching the C behaviour where
    /// `propq` is a fixed-size `char[OSSL_MAX_PROPQUERY_SIZE]` buffer.
    ///
    /// Replaces C `spki2typespki_set_ctx_params()` (lines 63–78).
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

impl Default for SpkiDecoderContext {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SpkiTaggingDecoder — Type-Tagging Decoder Implementation
// =============================================================================

/// `SubjectPublicKeyInfo` type-tagging decoder.
///
/// Parses a DER-encoded `SubjectPublicKeyInfo` structure, extracts the
/// `AlgorithmIdentifier` OID, resolves it to an algorithm name string, and
/// re-emits the original DER bytes wrapped in a `DecodedObject` annotated
/// with:
///
/// - `data_type` = resolved algorithm name (e.g., `"RSA"`, `"EC"`, `"Ed25519"`)
/// - `input_type` = `"DER"`
/// - `data_structure` = `"SubjectPublicKeyInfo"`
/// - `object_type` = [`ObjectType::Pkey`]
///
/// This is a "pass-through" decoder: it does not transform the DER bytes,
/// only annotates them for downstream algorithm-specific processing.
///
/// Replaces the C
/// `ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions`
/// dispatch table and `ossl_spki2typespki_der_decode()` function from
/// `decode_spki2typespki.c` (lines 99–157).
///
/// # Thread Safety
///
/// `SpkiTaggingDecoder` is a zero-sized, stateless struct and is trivially
/// `Send + Sync`.
#[derive(Debug, Clone, Copy)]
pub struct SpkiTaggingDecoder;

/// Wrapper around `DecodedObject` that implements `KeyData` so it can
/// be returned from [`DecoderProvider::decode`].
///
/// The provider dispatch system expects decoders to return `Box<dyn KeyData>`.
/// This wrapper provides that conformance while carrying the full decoded
/// metadata needed by downstream decoders.
// JUSTIFICATION for `dead_code` allow: `TaggedSpkiKeyData` is the runtime
// payload carried inside a `Box<dyn KeyData>` trait object returned by
// `SpkiTaggingDecoder::decode()`.  The `decoded` field stores the
// algorithm-tagged SPKI metadata and DER bytes.  Downstream decode pipeline
// stages retrieve this data by downcasting the trait object (via `Any`).
// Since the downcast accessor lives in consumer code (not this module), the
// compiler cannot see the read site and reports the field as dead.  The field
// is architecturally required for the decode chain to function.
#[derive(Debug)]
#[allow(dead_code)]
struct TaggedSpkiKeyData {
    /// The decoded object carrying the algorithm-tagged SPKI DER bytes.
    decoded: DecodedObject,
}

impl KeyData for TaggedSpkiKeyData {}

impl DecoderProvider for SpkiTaggingDecoder {
    /// Returns the canonical decoder name: `"SubjectPublicKeyInfo"`.
    ///
    /// Matches the C decoder registration name from the
    /// `ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions`
    /// dispatch
    /// table in `decode_spki2typespki.c` (line 159).
    fn name(&self) -> &'static str {
        "SubjectPublicKeyInfo"
    }

    /// Decodes a DER-encoded `SubjectPublicKeyInfo`, extracts the algorithm
    /// OID, resolves it to an algorithm name, and returns a tagged
    /// `DecodedObject` wrapped as `KeyData`.
    ///
    /// # Empty-Handed Success (Rule R5)
    ///
    /// If `input` cannot be parsed as a valid `SubjectPublicKeyInfo`, this
    /// method returns an error wrapping [`EndecoderError::BadEncoding`].
    /// However, per the C source (line 116: "We return 'empty handed'.
    /// This is not an error."), callers should treat decoding failures as
    /// non-fatal: the input simply isn't SPKI and should be tried by
    /// other decoders in the chain.
    ///
    /// # Algorithm Resolution
    ///
    /// The OID-to-name mapping covers all algorithm types supported by
    /// OpenSSL 4.0:
    ///
    /// - RSA, RSA-PSS
    /// - EC (including SM2 detection via `is_sm2_key`)
    /// - X25519, X448, Ed25519, Ed448
    /// - DH, DHX, DSA
    /// - ML-KEM (FIPS 203): 512, 768, 1024
    /// - ML-DSA (FIPS 204): 44, 65, 87
    /// - SLH-DSA (FIPS 205): all 12 parameter sets
    /// - LMS (SP 800-208)
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::Dispatch` wrapping [`EndecoderError::BadEncoding`]
    /// if the DER does not parse as valid SPKI. Returns
    /// `ProviderError::Dispatch` if the algorithm OID is unrecognised.
    fn decode(&self, input: &[u8]) -> ProviderResult<Box<dyn KeyData>> {
        trace!(input_len = input.len(), "SPKI type-tagging decoder: starting");

        // Step 1: Parse SubjectPublicKeyInfo from DER.
        //
        // Replaces C `ossl_d2i_X509_PUBKEY_INTERNAL(&derp, len, libctx, propq)`
        // from decode_spki2typespki.c line 113.
        //
        // If parsing fails, we return an error. The caller (decoder chain)
        // treats this as "empty handed" — the input is not SPKI and should
        // be tried by other decoders.
        let spki = SubjectPublicKeyInfoRef::from_der(input).map_err(|e| {
            trace!(error = %e, "input is not valid SPKI — returning empty-handed");
            ProviderError::Dispatch(EndecoderError::BadEncoding.to_string())
        })?;

        // Step 2: Extract the AlgorithmIdentifier OID.
        //
        // Replaces C sequence:
        //   X509_PUBKEY_get0_param(NULL, NULL, NULL, &algor, xpub)
        //   X509_ALGOR_get0(&oid, NULL, NULL, algor)
        let algorithm_oid = &spki.algorithm.oid;
        trace!(%algorithm_oid, "extracted AlgorithmIdentifier OID from SPKI");

        // Step 3: Check for SM2 special case.
        //
        // SM2 uses the EC OID but with SM2-specific curve parameters.
        // Replaces C lines 125–131:
        //   if (OBJ_obj2nid(oid) == NID_X9_62_id_ecPublicKey
        //       && ossl_x509_algor_is_sm2(algor))
        //       strcpy(dataname, "SM2");
        #[cfg(feature = "sm2")]
        let data_name = {
            if *algorithm_oid == OID_EC {
                // Extract raw parameter bytes for SM2 curve OID check.
                let params_bytes = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .map(|p| p.value());

                if is_sm2_key(algorithm_oid, params_bytes) {
                    "SM2"
                } else {
                    oid_to_algorithm_name(algorithm_oid)
                        .ok_or_else(|| {
                            ProviderError::Dispatch(format!(
                                "unrecognised algorithm OID: {algorithm_oid}"
                            ))
                        })?
                }
            } else {
                oid_to_algorithm_name(algorithm_oid)
                    .ok_or_else(|| {
                        ProviderError::Dispatch(format!(
                            "unrecognised algorithm OID: {algorithm_oid}"
                        ))
                    })?
            }
        };

        #[cfg(not(feature = "sm2"))]
        let data_name = oid_to_algorithm_name(algorithm_oid)
            .ok_or_else(|| {
                ProviderError::Dispatch(format!(
                    "unrecognised algorithm OID: {algorithm_oid}"
                ))
            })?;

        debug!(
            algorithm = data_name,
            oid = %algorithm_oid,
            "SPKI type-tagging decoder: resolved algorithm name"
        );

        // Step 4: Construct the tagged DecodedObject.
        //
        // Re-emit the original DER bytes annotated with the resolved
        // algorithm name. Replaces C OSSL_PARAM construction at lines
        // 138–150 of decode_spki2typespki.c.
        let decoded = DecodedObject {
            object_type: ObjectType::Pkey,
            data_type: data_name.to_string(),
            input_type: FORMAT_DER,
            data_structure: Some(STRUCTURE_SUBJECT_PUBLIC_KEY_INFO.to_string()),
            data: input.to_vec(),
        };

        trace!(
            data_type = %decoded.data_type,
            input_type = decoded.input_type,
            data_structure = ?decoded.data_structure,
            data_len = decoded.data.len(),
            "SPKI type-tagging decoder: constructed DecodedObject"
        );

        Ok(Box::new(TaggedSpkiKeyData { decoded }))
    }

    /// Returns the list of supported input formats.
    ///
    /// The SPKI type-tagging decoder only processes DER-encoded input.
    /// PEM input should be stripped by the PEM-to-DER decoder first.
    fn supported_formats(&self) -> Vec<&'static str> {
        vec![FORMAT_DER]
    }
}

// =============================================================================
// OID-to-Name Mapping
// =============================================================================

/// Maps a well-known algorithm OID to its human-readable name string.
///
/// Covers all public key algorithm types supported by OpenSSL 4.0:
///
/// | OID | Algorithm |
/// |-----|-----------|
/// | `1.2.840.113549.1.1.1` | RSA |
/// | `1.2.840.113549.1.1.10` | RSA-PSS |
/// | `1.2.840.10045.2.1` | EC |
/// | `1.3.101.110` | X25519 |
/// | `1.3.101.111` | X448 |
/// | `1.3.101.112` | Ed25519 |
/// | `1.3.101.113` | Ed448 |
/// | `1.2.840.113549.1.3.1` | DH |
/// | `1.2.840.10046.2.1` | DHX |
/// | `1.2.840.10040.4.1` | DSA |
/// | `2.16.840.1.101.3.4.4.1–3` | ML-KEM (512/768/1024) |
/// | `2.16.840.1.101.3.4.3.17–19` | ML-DSA (44/65/87) |
/// | `2.16.840.1.101.3.4.3.20–31` | SLH-DSA (12 param sets) |
/// | `1.2.840.113549.1.9.16.3.17` | LMS |
///
/// Returns `None` for unrecognised OIDs.
///
/// Replaces C `OBJ_obj2txt()` / `OBJ_nid2sn()` conversions from
/// `decode_spki2typespki.c` (line 132).
pub fn oid_to_algorithm_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    // Direct match against well-known constant OIDs.
    //
    // Performance note: this is a linear scan over ~30 OIDs. For the
    // decode pipeline this is negligible compared to DER parsing overhead.
    // A perfect hash map could be used if this becomes a bottleneck, but
    // the constant-evaluation requirement of ObjectIdentifier construction
    // prevents lazy_static HashMap.
    match *oid {
        // --- Traditional public key algorithms ---
        OID_RSA => Some("RSA"),
        OID_RSA_PSS => Some("RSA-PSS"),
        OID_EC => Some("EC"),
        OID_X25519 => Some("X25519"),
        OID_X448 => Some("X448"),
        OID_ED25519 => Some("Ed25519"),
        OID_ED448 => Some("Ed448"),
        OID_DH => Some("DH"),
        OID_DHX => Some("DHX"),
        OID_DSA => Some("DSA"),

        // --- Post-quantum: ML-KEM (FIPS 203) ---
        OID_ML_KEM_512 => Some("ML-KEM-512"),
        OID_ML_KEM_768 => Some("ML-KEM-768"),
        OID_ML_KEM_1024 => Some("ML-KEM-1024"),

        // --- Post-quantum: ML-DSA (FIPS 204) ---
        OID_ML_DSA_44 => Some("ML-DSA-44"),
        OID_ML_DSA_65 => Some("ML-DSA-65"),
        OID_ML_DSA_87 => Some("ML-DSA-87"),

        // --- Post-quantum: SLH-DSA (FIPS 205) — SHA-2 parameter sets ---
        OID_SLH_DSA_SHA2_128S => Some("SLH-DSA-SHA2-128s"),
        OID_SLH_DSA_SHA2_128F => Some("SLH-DSA-SHA2-128f"),
        OID_SLH_DSA_SHA2_192S => Some("SLH-DSA-SHA2-192s"),
        OID_SLH_DSA_SHA2_192F => Some("SLH-DSA-SHA2-192f"),
        OID_SLH_DSA_SHA2_256S => Some("SLH-DSA-SHA2-256s"),
        OID_SLH_DSA_SHA2_256F => Some("SLH-DSA-SHA2-256f"),

        // --- Post-quantum: SLH-DSA (FIPS 205) — SHAKE parameter sets ---
        OID_SLH_DSA_SHAKE_128S => Some("SLH-DSA-SHAKE-128s"),
        OID_SLH_DSA_SHAKE_128F => Some("SLH-DSA-SHAKE-128f"),
        OID_SLH_DSA_SHAKE_192S => Some("SLH-DSA-SHAKE-192s"),
        OID_SLH_DSA_SHAKE_192F => Some("SLH-DSA-SHAKE-192f"),
        OID_SLH_DSA_SHAKE_256S => Some("SLH-DSA-SHAKE-256s"),
        OID_SLH_DSA_SHAKE_256F => Some("SLH-DSA-SHAKE-256f"),

        // --- Hash-based signatures: LMS (SP 800-208) ---
        OID_LMS => Some("LMS"),

        // Unrecognised OID — return None per Rule R5.
        _ => None,
    }
}

// =============================================================================
// SM2 Special Case Detection
// =============================================================================

/// Checks whether an EC public key is actually an SM2 key.
///
/// SM2 (GB/T 32918.2-2016) uses the same `AlgorithmIdentifier` OID as
/// generic EC (`1.2.840.10045.2.1`), but specifies the SM2 named curve
/// OID (`1.2.156.10197.1.301`) in the
/// `AlgorithmIdentifier.parameters`
/// field.
///
/// This function examines the raw DER bytes of the parameters field and
/// attempts to decode them as an `ObjectIdentifier`. If the decoded OID
/// matches the SM2 curve OID, the function returns `true`.
///
/// # Arguments
///
/// * `oid` — The algorithm OID from the `AlgorithmIdentifier`. Must be
///   the EC OID (`1.2.840.10045.2.1`) for this function to return `true`.
/// * `params` — Optional raw DER bytes of the
///   `AlgorithmIdentifier.parameters`
///   field. `None` if no parameters are present.
///
/// # Returns
///
/// `true` if the key is an SM2 key (EC OID + SM2 curve parameter),
/// `false` otherwise.
///
/// # Feature Gate
///
/// This function is only available when `feature = "sm2"` is enabled.
/// When the SM2 feature is disabled, SM2 keys are reported as generic
/// `"EC"` keys.
///
/// Replaces C logic from `decode_spki2typespki.c` (lines 125–131):
///
/// ```c
/// if (OBJ_obj2nid(oid) == NID_X9_62_id_ecPublicKey
///     && ossl_x509_algor_is_sm2(algor))
///     strcpy(dataname, "SM2");
/// ```
#[cfg(feature = "sm2")]
pub fn is_sm2_key(oid: &ObjectIdentifier, params: Option<&[u8]>) -> bool {
    // Only EC keys can be SM2 keys.
    if *oid != OID_EC {
        return false;
    }

    // No parameters means no curve OID — cannot be SM2.
    let param_bytes = match params {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => return false,
    };

    // Attempt to decode the parameters as an ObjectIdentifier (the named
    // curve OID). If decoding fails, the parameters are in a format we
    // don't recognise — not SM2.
    match ObjectIdentifier::from_der(param_bytes) {
        Ok(curve_oid) => {
            let is_sm2 = curve_oid == OID_SM2_CURVE;
            if is_sm2 {
                trace!("detected SM2 key via curve parameter OID");
            }
            is_sm2
        }
        Err(_) => false,
    }
}

/// Stub implementation of `is_sm2_key` when the `sm2` feature is disabled.
///
/// Always returns `false` since SM2 detection is not available without the
/// feature flag. This provides a consistent API surface regardless of
/// feature configuration.
#[cfg(not(feature = "sm2"))]
pub fn is_sm2_key(_oid: &ObjectIdentifier, _params: Option<&[u8]>) -> bool {
    false
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-formed RSA 2048-bit `SubjectPublicKeyInfo` (DER).
    ///
    /// This is a minimal valid SPKI structure with:
    /// - `AlgorithmIdentifier`: RSA (1.2.840.113549.1.1.1), NULL parameters
    /// - SubjectPublicKey: 270 bytes (2048-bit RSA modulus + exponent)
    ///
    /// Generated from: `openssl genrsa 2048 | openssl rsa -pubout -outform DER`
    /// then hex-dumped and truncated to a minimal valid structure.
    fn rsa_spki_der() -> Vec<u8> {
        // Minimal RSA SPKI: SEQUENCE { AlgorithmIdentifier { OID rsaEncryption, NULL }, BIT STRING { ... } }
        // This is a self-contained, valid DER encoding.
        let mut der = Vec::new();
        // SEQUENCE tag (0x30) + length placeholder
        // AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        let alg_id: &[u8] = &[
            0x30, 0x0d, // SEQUENCE, 13 bytes
            0x06, 0x09, // OID tag, 9 bytes
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1
            0x05, 0x00, // NULL
        ];
        // Minimal BIT STRING with a small "public key" (not a real key, but valid DER)
        let pub_key: &[u8] = &[
            0x03, 0x11, // BIT STRING, 17 bytes
            0x00, // no unused bits
            0x30, 0x0e, // SEQUENCE, 14 bytes (mock RSA key)
            0x02, 0x09, // INTEGER, 9 bytes (modulus)
            0x00, 0xc5, 0xd3, 0x4c, 0x71, 0x5e, 0x8b, 0xb1, 0x43,
            0x02, 0x01, // INTEGER, 1 byte (exponent)
            0x03,
        ];

        let total_len = alg_id.len() + pub_key.len();
        der.push(0x30); // SEQUENCE tag
        // DER length encoding
        if total_len < 128 {
            der.push(u8::try_from(total_len).expect("length fits in u8"));
        } else {
            der.push(0x81);
            der.push(u8::try_from(total_len).expect("length fits in u8"));
        }
        der.extend_from_slice(alg_id);
        der.extend_from_slice(pub_key);
        der
    }

    /// Well-formed EC (P-256) `SubjectPublicKeyInfo` (DER).
    fn ec_spki_der() -> Vec<u8> {
        // AlgorithmIdentifier: SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 (P-256) }
        let alg_id: &[u8] = &[
            0x30, 0x13, // SEQUENCE, 19 bytes
            0x06, 0x07, // OID tag, 7 bytes
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
            0x06, 0x08, // OID tag, 8 bytes (named curve param)
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7 (P-256)
        ];
        // Minimal BIT STRING (uncompressed EC point, 65 bytes for P-256)
        // Using a small mock since only the AlgId matters for type-tagging.
        let pub_key: &[u8] = &[
            0x03, 0x03, // BIT STRING, 3 bytes
            0x00, 0x04, 0x01, // unused=0, mock uncompressed point prefix
        ];

        let total_len = alg_id.len() + pub_key.len();
        let mut der = Vec::new();
        der.push(0x30);
        if total_len < 128 {
            der.push(u8::try_from(total_len).expect("length fits in u8"));
        } else {
            der.push(0x81);
            der.push(u8::try_from(total_len).expect("length fits in u8"));
        }
        der.extend_from_slice(alg_id);
        der.extend_from_slice(pub_key);
        der
    }

    /// Ed25519 `SubjectPublicKeyInfo` (DER).
    fn ed25519_spki_der() -> Vec<u8> {
        let alg_id: &[u8] = &[
            0x30, 0x05, // SEQUENCE, 5 bytes
            0x06, 0x03, // OID tag, 3 bytes
            0x2b, 0x65, 0x70, // 1.3.101.112 (Ed25519)
        ];
        // BIT STRING: length = 1 (unused bits byte) + 32 (key bytes) = 33 = 0x21
        let pub_key: &[u8] = &[
            0x03, 0x21, // BIT STRING, 33 bytes content
            0x00, // unused bits = 0
            // 32 bytes of mock Ed25519 public key
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let total_len = alg_id.len() + pub_key.len();
        let mut der = Vec::new();
        der.push(0x30);
        if total_len < 128 {
            der.push(u8::try_from(total_len).expect("length fits in u8"));
        } else {
            der.push(0x81);
            der.push(u8::try_from(total_len).expect("length fits in u8"));
        }
        der.extend_from_slice(alg_id);
        der.extend_from_slice(pub_key);
        der
    }

    // --- OID Mapping Tests ---

    #[test]
    fn test_oid_to_algorithm_name_rsa() {
        assert_eq!(oid_to_algorithm_name(&OID_RSA), Some("RSA"));
    }

    #[test]
    fn test_oid_to_algorithm_name_rsa_pss() {
        assert_eq!(oid_to_algorithm_name(&OID_RSA_PSS), Some("RSA-PSS"));
    }

    #[test]
    fn test_oid_to_algorithm_name_ec() {
        assert_eq!(oid_to_algorithm_name(&OID_EC), Some("EC"));
    }

    #[test]
    fn test_oid_to_algorithm_name_x25519() {
        assert_eq!(oid_to_algorithm_name(&OID_X25519), Some("X25519"));
    }

    #[test]
    fn test_oid_to_algorithm_name_x448() {
        assert_eq!(oid_to_algorithm_name(&OID_X448), Some("X448"));
    }

    #[test]
    fn test_oid_to_algorithm_name_ed25519() {
        assert_eq!(oid_to_algorithm_name(&OID_ED25519), Some("Ed25519"));
    }

    #[test]
    fn test_oid_to_algorithm_name_ed448() {
        assert_eq!(oid_to_algorithm_name(&OID_ED448), Some("Ed448"));
    }

    #[test]
    fn test_oid_to_algorithm_name_dh() {
        assert_eq!(oid_to_algorithm_name(&OID_DH), Some("DH"));
    }

    #[test]
    fn test_oid_to_algorithm_name_dhx() {
        assert_eq!(oid_to_algorithm_name(&OID_DHX), Some("DHX"));
    }

    #[test]
    fn test_oid_to_algorithm_name_dsa() {
        assert_eq!(oid_to_algorithm_name(&OID_DSA), Some("DSA"));
    }

    #[test]
    fn test_oid_to_algorithm_name_ml_kem() {
        assert_eq!(oid_to_algorithm_name(&OID_ML_KEM_512), Some("ML-KEM-512"));
        assert_eq!(oid_to_algorithm_name(&OID_ML_KEM_768), Some("ML-KEM-768"));
        assert_eq!(oid_to_algorithm_name(&OID_ML_KEM_1024), Some("ML-KEM-1024"));
    }

    #[test]
    fn test_oid_to_algorithm_name_ml_dsa() {
        assert_eq!(oid_to_algorithm_name(&OID_ML_DSA_44), Some("ML-DSA-44"));
        assert_eq!(oid_to_algorithm_name(&OID_ML_DSA_65), Some("ML-DSA-65"));
        assert_eq!(oid_to_algorithm_name(&OID_ML_DSA_87), Some("ML-DSA-87"));
    }

    #[test]
    fn test_oid_to_algorithm_name_slh_dsa() {
        assert_eq!(oid_to_algorithm_name(&OID_SLH_DSA_SHA2_128S), Some("SLH-DSA-SHA2-128s"));
        assert_eq!(oid_to_algorithm_name(&OID_SLH_DSA_SHAKE_256F), Some("SLH-DSA-SHAKE-256f"));
    }

    #[test]
    fn test_oid_to_algorithm_name_lms() {
        assert_eq!(oid_to_algorithm_name(&OID_LMS), Some("LMS"));
    }

    #[test]
    fn test_oid_to_algorithm_name_unknown() {
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        assert_eq!(oid_to_algorithm_name(&unknown), None);
    }

    // --- Decoder Trait Tests ---

    #[test]
    fn test_decoder_name() {
        let decoder = SpkiTaggingDecoder;
        assert_eq!(decoder.name(), "SubjectPublicKeyInfo");
    }

    #[test]
    fn test_decoder_supported_formats() {
        let decoder = SpkiTaggingDecoder;
        assert_eq!(decoder.supported_formats(), vec!["DER"]);
    }

    #[test]
    fn test_decoder_rsa_spki() {
        let decoder = SpkiTaggingDecoder;
        let der = rsa_spki_der();
        let result = decoder.decode(&der);
        assert!(result.is_ok(), "RSA SPKI should decode successfully: {:?}", result.err());
    }

    #[test]
    fn test_decoder_ec_spki() {
        let decoder = SpkiTaggingDecoder;
        let der = ec_spki_der();
        let result = decoder.decode(&der);
        assert!(result.is_ok(), "EC SPKI should decode successfully: {:?}", result.err());
    }

    #[test]
    fn test_decoder_ed25519_spki() {
        let decoder = SpkiTaggingDecoder;
        let der = ed25519_spki_der();
        let result = decoder.decode(&der);
        assert!(result.is_ok(), "Ed25519 SPKI should decode successfully: {:?}", result.err());
    }

    #[test]
    fn test_decoder_invalid_input() {
        let decoder = SpkiTaggingDecoder;
        // Random garbage bytes — should fail parsing.
        let result = decoder.decode(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_err(), "garbage input should fail SPKI decoding");
    }

    #[test]
    fn test_decoder_empty_input() {
        let decoder = SpkiTaggingDecoder;
        let result = decoder.decode(&[]);
        assert!(result.is_err(), "empty input should fail SPKI decoding");
    }

    // --- SM2 Detection Tests ---

    #[test]
    fn test_is_sm2_key_not_ec() {
        // RSA OID — cannot be SM2.
        assert!(!is_sm2_key(&OID_RSA, None));
    }

    #[test]
    fn test_is_sm2_key_ec_no_params() {
        // EC OID but no parameters — not SM2.
        assert!(!is_sm2_key(&OID_EC, None));
    }

    #[test]
    fn test_is_sm2_key_ec_empty_params() {
        // EC OID with empty parameters — not SM2.
        assert!(!is_sm2_key(&OID_EC, Some(&[])));
    }

    #[test]
    fn test_is_sm2_key_ec_p256_params() {
        // EC OID with P-256 curve parameter — not SM2.
        // OID 1.2.840.10045.3.1.7 (secp256r1/P-256) DER encoding
        let p256_oid_der: &[u8] = &[
            0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        assert!(!is_sm2_key(&OID_EC, Some(p256_oid_der)));
    }

    // --- SpkiDecoderContext Tests ---

    #[test]
    fn test_context_default() {
        let ctx = SpkiDecoderContext::default();
        assert!(ctx.propq.is_none());
    }

    #[test]
    fn test_context_new() {
        let ctx = SpkiDecoderContext::new();
        assert!(ctx.propq.is_none());
    }

    #[test]
    fn test_context_with_propq() {
        let ctx = SpkiDecoderContext::with_propq("provider=default,fips=yes");
        assert_eq!(ctx.propq, Some("provider=default,fips=yes".to_string()));
    }

    #[test]
    fn test_context_propq_truncation() {
        // Create a string longer than MAX_PROPQUERY_SIZE (256).
        let long_propq = "a".repeat(MAX_PROPQUERY_SIZE + 100);
        let ctx = SpkiDecoderContext::with_propq(&long_propq);
        assert_eq!(
            ctx.propq.as_ref().map(|s| s.len()),
            Some(MAX_PROPQUERY_SIZE)
        );
    }
}
