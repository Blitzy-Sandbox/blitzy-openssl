//! SRTP Key Derivation Function (RFC 3711, Section 4.3).
//!
//! Source: `providers/implementations/kdfs/srtpkdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for SRTPKDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SRTPKDF"],
            "provider=default",
            "SRTP Key Derivation Function (RFC 3711)",
        ),
    ]
}
