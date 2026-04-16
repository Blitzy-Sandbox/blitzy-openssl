//! # Key/Certificate Store Implementation Backends
//!
//! Store management implementations for the provider system covering
//! file-based key/certificate stores (PEM/DER directory scanning), and
//! platform-specific stores (Windows certificate store).
//!
//! Source: `providers/implementations/storemgmt/` (3 C files).
//!
//! Each store struct implements `StoreProvider` from `crate::traits`.

use crate::traits::AlgorithmDescriptor;
use super::algorithm;

/// Returns all store algorithm descriptors registered by this module.
///
/// Called by [`super::all_store_descriptors()`] when the `"store"` feature
/// is enabled. Returns descriptors for every store backend supported
/// by the default provider.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["file"],
            "provider=default",
            "File-based key and certificate store (PEM/DER directory)",
        ),
    ]
}
