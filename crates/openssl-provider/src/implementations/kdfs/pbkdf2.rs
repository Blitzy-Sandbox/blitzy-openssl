//! Password-Based Key Derivation Function 2 (PKCS#5 v2.1, SP 800-132).
//!
//! Source: `providers/implementations/kdfs/pbkdf2.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for PBKDF2.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["PBKDF2"],
            "provider=default",
            "Password-Based Key Derivation Function 2 (PKCS#5 v2.1)",
        ),
    ]
}
