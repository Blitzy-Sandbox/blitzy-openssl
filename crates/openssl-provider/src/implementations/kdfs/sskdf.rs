//! Single-Step KDF (SP 800-56C) and X9.63 KDF.
//!
//! Source: `providers/implementations/kdfs/sskdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for SSKDF and X963KDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SSKDF"],
            "provider=default",
            "Single-Step Key Derivation Function (SP 800-56C)",
        ),
        algorithm(
            &["X963KDF"],
            "provider=default",
            "ANSI X9.63 Key Derivation Function",
        ),
    ]
}
