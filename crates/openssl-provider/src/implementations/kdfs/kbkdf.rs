//! Key-Based Key Derivation Function (NIST SP 800-108).
//!
//! Source: `providers/implementations/kdfs/kbkdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for KBKDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["KBKDF"],
            "provider=default",
            "Key-Based Key Derivation Function (SP 800-108)",
        ),
    ]
}
