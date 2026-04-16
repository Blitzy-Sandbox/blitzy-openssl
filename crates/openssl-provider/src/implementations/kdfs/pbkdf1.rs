//! Password-Based Key Derivation Function 1 (RFC 8018, legacy).
//!
//! Source: `providers/implementations/kdfs/pbkdf1.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for PBKDF1.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["PBKDF1"],
            "provider=legacy",
            "Password-Based Key Derivation Function 1 (legacy)",
        ),
    ]
}
