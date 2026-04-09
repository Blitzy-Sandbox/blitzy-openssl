//! # KEM Implementation Backends
//!
//! Key Encapsulation Mechanism provider implementations including
//! ML-KEM, HPKE DHKEM, hybrid MLX, and RSA-KEM.
//!
//! Source: `providers/implementations/kem/` (7 C files).

/// Shared KEM utilities — mode name mapping and helpers.
pub mod util;

// Re-export commonly used items from util for convenience.
pub use util::{KemMode, kem_mode_to_name, kem_modename_to_id};
