//! NULL cipher — a pass-through cipher that performs no encryption.
//!
//! Used as a diagnostic tool and for TLS connections that require
//! authentication without confidentiality. Translates C `cipher_null.c`.

use crate::traits::AlgorithmDescriptor;
use super::common::{CipherMode, CipherFlags};

/// NULL cipher implementation — passes data through unchanged.
///
/// This cipher performs no encryption or decryption. Input data is
/// copied directly to the output buffer. It is used for testing,
/// benchmarking overhead, and TLS null-cipher suites.
#[derive(Debug, Clone)]
pub struct NullCipher;

/// Context for an active NULL cipher operation.
///
/// Since no encryption occurs, the context merely tracks whether
/// the cipher has been initialized.
#[derive(Debug, Clone)]
pub struct NullCipherContext {
    /// Whether the context has been initialized.
    initialized: bool,
}

impl NullCipherContext {
    /// Creates a new uninitialized NULL cipher context.
    #[must_use]
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Returns whether the context is initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initializes the context. For the NULL cipher, this is a no-op
    /// that simply marks the context as ready.
    pub fn init(&mut self) {
        self.initialized = true;
    }
}

impl Default for NullCipherContext {
    fn default() -> Self {
        Self::new()
    }
}

impl NullCipher {
    /// Returns the cipher mode (Stream, since NULL has no block structure).
    #[must_use]
    pub fn mode() -> CipherMode {
        CipherMode::Stream
    }

    /// Returns the cipher flags (no special capabilities).
    #[must_use]
    pub fn flags() -> CipherFlags {
        CipherFlags::empty()
    }

    /// Returns the key length (0 — no key required).
    #[must_use]
    pub fn key_len() -> usize {
        0
    }

    /// Returns the IV length (0 — no IV required).
    #[must_use]
    pub fn iv_len() -> usize {
        0
    }

    /// Returns the block size (1 — stream cipher semantics).
    #[must_use]
    pub fn block_size() -> usize {
        1
    }
}

/// Returns algorithm descriptors for the NULL cipher.
///
/// The NULL cipher is always available (no feature gate) and is registered
/// with the default provider.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![AlgorithmDescriptor {
        names: vec!["NULL"],
        property: "provider=default",
        description: "NULL cipher (no encryption)",
    }]
}
