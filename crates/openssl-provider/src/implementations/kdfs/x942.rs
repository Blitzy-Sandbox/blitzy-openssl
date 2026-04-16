//! ANSI X9.42 Key Derivation Function.
//!
//! Source: `providers/implementations/kdfs/x942kdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for X942KDF-ASN1.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["X942KDF-ASN1"],
            "provider=default",
            "ANSI X9.42 Key Derivation Function (ASN.1 format)",
        ),
    ]
}
