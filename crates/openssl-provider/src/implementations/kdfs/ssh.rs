//! SSH Key Derivation Function (RFC 4253, Section 7.2).
//!
//! Source: `providers/implementations/kdfs/sshkdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for SSHKDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SSHKDF"],
            "provider=default",
            "SSH Key Derivation Function (RFC 4253)",
        ),
    ]
}
