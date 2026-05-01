//! # KEM Implementation Backends
//!
//! Key Encapsulation Mechanism provider implementations including
//! ML-KEM (FIPS 203 — 512/768/1024), HPKE DHKEM (RFC 9180),
//! hybrid MLX (ML-KEM + X25519/X448), and RSA-KEM.
//!
//! Source: `providers/implementations/kem/` (7 C files).
//!
//! Each KEM struct implements `KemProvider` from `crate::traits`.

use super::algorithm;
use crate::traits::AlgorithmDescriptor;

/// Shared KEM utilities — mode name mapping and helpers.
pub mod util;

/// HPKE DHKEM over ECX curves (X25519, X448) — RFC 9180.
pub mod ecx;

/// ML-KEM (Module-Lattice KEM) — FIPS 203, security levels 512/768/1024.
pub mod ml_kem;

/// Hybrid MLX (ML-KEM + ECDH) — composite post-quantum/classical KEM.
///
/// Combines ML-KEM-768 / ML-KEM-1024 with classical ECDH (P-256, P-384,
/// X25519, X448) using a "classical-first" composite layout for both
/// keys, ciphertexts, and shared secrets. The construction follows
/// `providers/implementations/kem/mlx_kem.c` from the C reference.
pub mod mlx;

// Re-export commonly used items from util for convenience.
pub use util::{kem_mode_to_name, kem_modename_to_id, KemMode};

/// Returns all KEM algorithm descriptors registered by this module.
///
/// Called by [`super::all_kem_descriptors()`] when the `"kem"` feature
/// is enabled. Returns descriptors for every KEM variant supported
/// by the default provider.
///
/// The ML-KEM suites (`ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`) are
/// obtained from [`ml_kem::descriptors()`] — the canonical FIPS 203
/// names registered under `provider=default`.
///
/// The ECX DHKEM suites (X25519-HKDF-SHA256 and X448-HKDF-SHA512) are
/// obtained from [`ecx::descriptors()`] and registered under their RFC 9180
/// canonical names `"X25519"` and `"X448"`. The generic `"DHKEM"` entry is
/// retained as a lookup alias for non-specific DHKEM queries.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut out = vec![
        algorithm(
            &["DHKEM"],
            "provider=default",
            "Diffie-Hellman based KEM for HPKE (RFC 9180)",
        ),
        algorithm(
            &["RSA"],
            "provider=default",
            "RSA Key Encapsulation Mechanism",
        ),
    ];
    // ML-KEM-512/768/1024 are owned by `ml_kem.rs` per the FIPS 203
    // implementation crate.  Routing through `ml_kem::descriptors()`
    // (instead of inline `algorithm(...)` entries) prevents duplicate
    // registrations and ensures every descriptor’s lifecycle is
    // reachable from the real implementation module — satisfying
    // Rule R10 (wiring before done).
    out.extend(ml_kem::descriptors());
    // Append the concrete ECX DHKEM suites (X25519, X448) to the generic
    // dispatch table so that `OSSL_PROVIDER` lookups by canonical curve
    // name succeed. R10: ensures `ecx.rs` is reachable from the provider
    // entry point via `implementations::all_kem_descriptors()`.
    out.extend(ecx::descriptors());
    // Append the hybrid MLX KEM suites (ML-KEM-768 + {P-256, X25519},
    // ML-KEM-1024 + {P-384, X448}, ML-KEM-768 + SM2). R10: ensures
    // `mlx.rs` is reachable from the provider entry point via
    // `implementations::all_kem_descriptors()`.
    out.extend(mlx::descriptors());
    out
}
