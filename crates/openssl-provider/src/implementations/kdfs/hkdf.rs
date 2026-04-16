//! HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
//!
//! Source: `providers/implementations/kdfs/hkdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for HKDF and TLS13-KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["HKDF"],
            "provider=default",
            "HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)",
        ),
        algorithm(
            &["TLS13-KDF"],
            "provider=default",
            "TLS 1.3 Key Derivation Function (RFC 8446)",
        ),
    ]
}
