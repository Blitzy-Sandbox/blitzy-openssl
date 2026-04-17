//! EC key management provider implementation.
//!
//! Placeholder module — full implementation pending.
//! Provides the `ec_descriptors()` function required by the keymgmt module hub.

use crate::traits::AlgorithmDescriptor;

/// Returns EC key management algorithm descriptors for provider registration.
pub fn ec_descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["EC"],
        property: "provider=default",
        description: "EC key management",
    }]
}
