//! Microsoft PVK Key Derivation Function.
//!
//! Source: `providers/implementations/kdfs/pvkkdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for PVKKDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["PVKKDF"],
            "provider=default",
            "Microsoft PVK Key Derivation Function",
        ),
    ]
}
