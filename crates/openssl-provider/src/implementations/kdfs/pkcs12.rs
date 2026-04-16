//! PKCS#12 Key Derivation Function (RFC 7292).
//!
//! Source: `providers/implementations/kdfs/pkcs12kdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for PKCS12KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["PKCS12KDF"],
            "provider=default",
            "PKCS#12 Key Derivation Function (RFC 7292)",
        ),
    ]
}
