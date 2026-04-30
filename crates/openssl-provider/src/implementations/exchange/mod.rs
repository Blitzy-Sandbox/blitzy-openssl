//! # Key Exchange Implementation Backends
//!
//! Key exchange implementations for the provider system covering DH,
//! ECDH (P-256, P-384, P-521, secp256k1), X25519, X448, and KDF-backed
//! key exchange schemes.
//!
//! Source: `providers/implementations/exchange/` (4 C files).
//!
//! Each key exchange struct implements `KeyExchangeProvider` from `crate::traits`.
//!
//! # Submodules
//!
//! | Module    | Algorithm                                                    | RFC / Standard           |
//! |-----------|--------------------------------------------------------------|--------------------------|
//! | `dh`      | Finite-field Diffie-Hellman                                  | RFC 7919                 |
//! | `ecdh`    | Elliptic-curve Diffie-Hellman (NIST curves)                  | SEC 1, FIPS 186-4        |
//! | `x25519`  | X25519 / X448 Montgomery DH (legacy provider façade)         | RFC 7748                 |
//! | `ecx`     | X25519 / X448 Montgomery DH (ECX provider — AAP §0.5 mapping)| RFC 7748                 |
//! | `kdf`     | TLS1-PRF / HKDF / SCRYPT key-exchange adapters               | RFC 5246, 5869, 7914     |

pub mod dh;
pub mod ecdh;
pub mod ecx;
pub mod kdf;
pub mod x25519;

use super::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Returns all key exchange algorithm descriptors registered by this module.
///
/// Called by [`super::all_exchange_descriptors()`] when the `"exchange"` feature
/// is enabled. Returns descriptors for every key exchange variant supported
/// by the default provider, including the KDF-backed exchange adapters
/// (TLS1-PRF, HKDF, SCRYPT) wired in by [`kdf::descriptors`].
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = vec![
        algorithm(
            &["DH", "dhKeyAgreement"],
            "provider=default",
            "Diffie-Hellman key exchange (RFC 7919)",
        ),
        algorithm(
            &["ECDH"],
            "provider=default",
            "Elliptic Curve Diffie-Hellman key exchange (NIST curves)",
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
    ];

    // Wire the KDF-backed key-exchange adapters (TLS1-PRF, HKDF, SCRYPT)
    // into the default provider's algorithm directory. Mirrors the C
    // dispatch tables in `providers/implementations/exchange/kdf_exch.c`
    // and satisfies Rule R10 — `kdf::descriptors()` is the only path that
    // makes [`kdf::Tls1PrfExchange`], [`kdf::HkdfExchange`], and
    // [`kdf::ScryptExchange`] reachable from the provider entry point.
    descs.extend(kdf::descriptors());
    descs
}
