//! # Key Exchange Implementation Backends
//!
//! Key exchange implementations for the provider system covering DH,
//! ECDH (P-256, P-384, P-521, secp256k1), X25519, X448, and KDF-backed
//! key exchange schemes.
//!
//! Source: `providers/implementations/exchange/` (4 C files).
//!
//! Each key exchange struct implements `KeyExchangeProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all key exchange algorithm descriptors registered by this module.
///
/// Called by [`super::all_exchange_descriptors()`] when the `"exchange"` feature
/// is enabled. Returns descriptors for every key exchange variant supported
/// by the default provider.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["DH", "dhKeyAgreement"],
            "provider=default",
            "Diffie-Hellman key exchange",
        ),
        algorithm(
            &["ECDH"],
            "provider=default",
            "Elliptic Curve Diffie-Hellman key exchange",
        ),
        algorithm(
            &["X25519"],
            "provider=default",
            "X25519 key exchange (RFC 7748)",
        ),
        algorithm(
            &["X448"],
            "provider=default",
            "X448 key exchange (RFC 7748)",
        ),
    ]
}
