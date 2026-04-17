//! ECDSA signature provider implementation.
//!
//! Placeholder module — full implementation pending.
//! Provides the `descriptors()` function required by the signatures module hub.

use crate::traits::AlgorithmDescriptor;

/// Returns ECDSA algorithm descriptors for provider registration.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["ECDSA"],
        property: "provider=default",
        description: "ECDSA signature algorithm",
    }]
}
