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

/// Windows certificate store adapter.
///
/// Provides access to the Windows system "ROOT" certificate store via
/// the `org.openssl.winstore:` URI scheme.  The module compiles on all
/// platforms but its algorithm descriptor is only advertised on Windows
/// targets (gated via `#[cfg(target_os = "windows")]`).
///
/// See [`winstore`] module documentation for details.
pub mod winstore;

/// Returns all store algorithm descriptors registered by this module.
///
/// Called by [`super::all_store_descriptors()`] when the `"store"` feature
/// is enabled. Returns descriptors for every store backend supported
/// by the default provider.
///
/// On Windows targets this includes the `org.openssl.winstore` store.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    // `mut` is conditionally required — used by the `#[cfg(target_os = "windows")]` block.
    #[allow(unused_mut)]
    let mut descs = vec![
        algorithm(
            &["file"],
            "provider=default",
            "File-based key and certificate store (PEM/DER directory)",
        ),
    ];

    // Windows certificate store — only advertised on Windows targets.
    #[cfg(target_os = "windows")]
    descs.extend(winstore::descriptors());

    descs
}
