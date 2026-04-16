//! TLS 1.0/1.1/1.2 Pseudo-Random Function (RFC 2246, RFC 5246).
//!
//! Source: `providers/implementations/kdfs/tls1_prf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for TLS1-PRF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["TLS1-PRF"],
            "provider=default",
            "TLS 1.0/1.1/1.2 Pseudo-Random Function",
        ),
    ]
}
