//! # Encoder/Decoder Implementation Backends
//!
//! Key encoder and decoder implementations for the provider system covering
//! DER/PEM codecs for all key types (RSA, EC, DH, DSA, X25519/X448,
//! Ed25519/Ed448, ML-KEM, ML-DSA), PKCS#8, SubjectPublicKeyInfo (SPKI),
//! PKCS#1, SEC1, EncryptedPrivateKeyInfo, and legacy PVK/MSBLOB formats.
//!
//! Source: `providers/implementations/encode_decode/` (16 C files).
//!
//! Encoder structs implement `EncoderProvider` from `crate::traits`.
//! Decoder structs implement `DecoderProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all encoder algorithm descriptors registered by this module.
///
/// Called by [`super::all_encoder_descriptors()`] when the `"encode-decode"`
/// feature is enabled. Returns descriptors for every encoder variant supported
/// by the base and default providers.
#[must_use]
pub fn encoder_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["RSA", "rsaEncryption"],
            "provider=default,output=der",
            "RSA key to DER encoder",
        ),
        algorithm(
            &["RSA", "rsaEncryption"],
            "provider=default,output=pem",
            "RSA key to PEM encoder",
        ),
        algorithm(
            &["EC"],
            "provider=default,output=der",
            "EC key to DER encoder",
        ),
        algorithm(
            &["EC"],
            "provider=default,output=pem",
            "EC key to PEM encoder",
        ),
        algorithm(
            &["X25519"],
            "provider=default,output=der",
            "X25519 key to DER encoder",
        ),
        algorithm(
            &["X25519"],
            "provider=default,output=pem",
            "X25519 key to PEM encoder",
        ),
        algorithm(
            &["ED25519"],
            "provider=default,output=der",
            "Ed25519 key to DER encoder",
        ),
        algorithm(
            &["ED25519"],
            "provider=default,output=pem",
            "Ed25519 key to PEM encoder",
        ),
    ]
}

/// Returns all decoder algorithm descriptors registered by this module.
///
/// Called by [`super::all_decoder_descriptors()`] when the `"encode-decode"`
/// feature is enabled. Returns descriptors for every decoder variant supported
/// by the base and default providers.
#[must_use]
pub fn decoder_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["RSA", "rsaEncryption"],
            "provider=default,input=der",
            "DER to RSA key decoder",
        ),
        algorithm(
            &["RSA", "rsaEncryption"],
            "provider=default,input=pem",
            "PEM to RSA key decoder",
        ),
        algorithm(
            &["EC"],
            "provider=default,input=der",
            "DER to EC key decoder",
        ),
        algorithm(
            &["EC"],
            "provider=default,input=pem",
            "PEM to EC key decoder",
        ),
        algorithm(
            &["X25519"],
            "provider=default,input=der",
            "DER to X25519 key decoder",
        ),
        algorithm(
            &["X25519"],
            "provider=default,input=pem",
            "PEM to X25519 key decoder",
        ),
        algorithm(
            &["ED25519"],
            "provider=default,input=der",
            "DER to Ed25519 key decoder",
        ),
        algorithm(
            &["ED25519"],
            "provider=default,input=pem",
            "PEM to Ed25519 key decoder",
        ),
    ]
}
