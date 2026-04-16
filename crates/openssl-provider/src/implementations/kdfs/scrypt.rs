//! scrypt password-based key derivation function (RFC 7914).
//!
//! Source: `providers/implementations/kdfs/scrypt.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for scrypt.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SCRYPT"],
            "provider=default",
            "scrypt password-based key derivation (RFC 7914)",
        ),
    ]
}
