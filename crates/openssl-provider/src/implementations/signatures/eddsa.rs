//! EdDSA signature provider implementation.
//!
//! Placeholder module — full implementation pending.
//! Provides the `descriptors()` function required by the signatures module hub.

use crate::traits::AlgorithmDescriptor;

/// Returns `EdDSA` algorithm descriptors for provider registration.
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["EdDSA"],
        property: "provider=default",
        description: "EdDSA signature algorithm (Ed25519, Ed448)",
    }]
}
