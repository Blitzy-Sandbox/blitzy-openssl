//! # MAC Provider Implementations
//!
//! Message Authentication Code algorithm implementations for the OpenSSL
//! Rust provider system. Each submodule implements the `MacProvider` trait
//! from `crate::traits` and provides `MacContext` instances for streaming
//! MAC computation.
//!
//! ## Algorithm Inventory
//!
//! | Rust Module | C Source | Algorithm | Standard |
//! |-------------|----------|-----------|----------|
//! | `hmac` | `hmac_prov.c` (389 lines) | HMAC | RFC 2104 |
//! | `cmac` | `cmac_prov.c` (298 lines) | CMAC | SP 800-38B |
//! | `gmac` | `gmac_prov.c` (256 lines) | GMAC | GCM auth tag |
//! | `kmac` | `kmac_prov.c` (547 lines) | KMAC-128/256 | SP 800-185 |
//! | `poly1305` | `poly1305_prov.c` (190 lines) | Poly1305 | RFC 8439 §2.5 |
//! | `siphash` | `siphash_prov.c` (222 lines) | SipHash | SipHash-2-4 |
//! | `blake2_mac` | `blake2_mac_impl.c` + variants (321 lines) | BLAKE2b/s-MAC | RFC 7693 |
//!
//! ## Architecture
//!
//! Each MAC implementation follows this pattern:
//! - `*Provider` struct: Implements `MacProvider` trait, creates contexts
//! - `*Context` struct: Implements `MacContext` trait with lifecycle:
//!   `new_ctx()` → `init(key)` → `update(data)` → `finalize()` → tag
//! - `*Params` struct: Typed parameter configuration (replaces C OSSL_PARAM bags)
//! - `descriptors()` function: Returns `Vec<AlgorithmDescriptor>` for registration
//!
//! ## Design Principles
//!
//! - **Zero unsafe:** All implementations are 100% safe Rust (Rule R8)
//! - **Secure key erasure:** Key material uses `zeroize::Zeroizing<Vec<u8>>` (replaces OPENSSL_cleanse)
//! - **RAII:** Context Drop replaces C `*_freectx()` manual cleanup
//! - **Typed params:** C `OSSL_PARAM` bags replaced with typed Rust config structs
//! - **FIPS-aware:** HMAC, CMAC, KMAC enforce FIPS key-size constraints when applicable
//!
//! ## Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(Mac)
//!         → implementations::macs::descriptors()
//!           → HmacProvider::descriptors()
//!           → CmacProvider::descriptors()
//!           → GmacProvider::descriptors()
//!           → KmacProvider::descriptors()
//!           → Poly1305Provider::descriptors()
//!           → SipHashProvider::descriptors()
//!           → Blake2MacProvider::all_descriptors()
//! ```
//!
//! ## C Equivalent
//!
//! In C, the default provider's `deflt_query()` function returns a static
//! `OSSL_ALGORITHM deflt_macs[]` array containing dispatch table references:
//!
//! ```c
//! static const OSSL_ALGORITHM deflt_macs[] = {
//!     { "HMAC", "provider=default", ossl_hmac_functions },
//!     { "CMAC", "provider=default", ossl_cmac_functions },
//!     { "GMAC", "provider=default", ossl_gmac_functions },
//!     { "KMAC-128:KMAC128", "provider=default", ossl_kmac128_functions },
//!     { "KMAC-256:KMAC256", "provider=default", ossl_kmac256_functions },
//!     { "BLAKE2BMAC", "provider=default", ossl_blake2bmac_functions },
//!     { "BLAKE2SMAC", "provider=default", ossl_blake2smac_functions },
//!     { "SIPHASH", "provider=default", ossl_siphash_functions },
//!     { "POLY1305", "provider=default", ossl_poly1305_functions },
//!     { NULL, NULL, NULL }
//! };
//! ```

// =============================================================================
// Submodule Declarations
// =============================================================================

/// HMAC — Hash-based MAC (RFC 2104). Supports all registered digest algorithms.
/// Includes TLS record MAC optimization path.
/// Source: `providers/implementations/macs/hmac_prov.c`.
pub mod hmac;

/// CMAC — Cipher-based MAC (SP 800-38B). Supports AES-CMAC and other block ciphers.
/// In FIPS mode: restricted to AES-CBC and 3DES-CBC.
/// Source: `providers/implementations/macs/cmac_prov.c`.
pub mod cmac;

/// GMAC — Galois MAC. Authentication tag from AES-GCM AEAD (no ciphertext).
/// Source: `providers/implementations/macs/gmac_prov.c`.
pub mod gmac;

/// KMAC-128/256 — Keccak-based MAC (SP 800-185). Variable output, XOF mode support.
/// Source: `providers/implementations/macs/kmac_prov.c`.
pub mod kmac;

/// Poly1305 — One-time MAC for ChaCha20-Poly1305 AEAD. Exact 32-byte key, 16-byte output.
/// Source: `providers/implementations/macs/poly1305_prov.c`.
pub mod poly1305;

/// SipHash — Fast short-input MAC. Configurable output (8/16 bytes) and rounds.
/// Source: `providers/implementations/macs/siphash_prov.c`.
pub mod siphash;

/// BLAKE2b-MAC / BLAKE2s-MAC — BLAKE2 in keyed/MAC mode.
/// Configurable output, salt, personalization.
/// Source: `blake2_mac_impl.c`, `blake2b_mac.c`, `blake2s_mac.c`.
pub mod blake2_mac;

// =============================================================================
// Re-exports — convenient access to provider types at the macs:: level
// =============================================================================

/// Re-export HMAC provider for convenient access via `macs::HmacProvider`.
pub use hmac::HmacProvider;

/// Re-export CMAC provider for convenient access via `macs::CmacProvider`.
pub use cmac::CmacProvider;

/// Re-export GMAC provider for convenient access via `macs::GmacProvider`.
pub use gmac::GmacProvider;

/// Re-export KMAC provider for convenient access via `macs::KmacProvider`.
pub use kmac::KmacProvider;

/// Re-export Poly1305 provider for convenient access via `macs::Poly1305Provider`.
pub use poly1305::Poly1305Provider;

/// Re-export `SipHash` provider for convenient access via `macs::SipHashProvider`.
pub use siphash::SipHashProvider;

/// Re-export BLAKE2 MAC provider for convenient access via `macs::Blake2MacProvider`.
pub use blake2_mac::Blake2MacProvider;

// =============================================================================
// Algorithm Descriptor Aggregation
// =============================================================================

use crate::traits::AlgorithmDescriptor;

/// Returns all MAC algorithm descriptors for provider registration.
///
/// This function is called by `implementations::all_mac_descriptors()` which is
/// invoked by `DefaultProvider::query_operation(OperationType::Mac)`.
///
/// Returns descriptors for all 9 MAC algorithms: HMAC, CMAC, GMAC,
/// KMAC-128, KMAC-256, Poly1305, `SipHash`, BLAKE2BMAC, BLAKE2SMAC.
///
/// Each provider's `descriptors()` method returns its own
/// [`AlgorithmDescriptor`] entries, ensuring that algorithm names,
/// property strings, and descriptions stay co-located with their
/// implementation (single source of truth).
///
/// ## C Equivalent
///
/// In C, the default provider's `deflt_query()` function returns a static
/// `OSSL_ALGORITHM deflt_macs[]` array containing dispatch table references:
///
/// ```c
/// static const OSSL_ALGORITHM deflt_macs[] = {
///     { "HMAC", "provider=default", ossl_hmac_functions },
///     { "CMAC", "provider=default", ossl_cmac_functions },
///     { "GMAC", "provider=default", ossl_gmac_functions },
///     { "KMAC-128:KMAC128", "provider=default", ossl_kmac128_functions },
///     { "KMAC-256:KMAC256", "provider=default", ossl_kmac256_functions },
///     { "BLAKE2BMAC", "provider=default", ossl_blake2bmac_functions },
///     { "BLAKE2SMAC", "provider=default", ossl_blake2smac_functions },
///     { "SIPHASH", "provider=default", ossl_siphash_functions },
///     { "POLY1305", "provider=default", ossl_poly1305_functions },
///     { NULL, NULL, NULL }
/// };
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();
    descs.extend(HmacProvider::descriptors());
    descs.extend(CmacProvider::descriptors());
    descs.extend(GmacProvider::descriptors());
    descs.extend(KmacProvider::descriptors());
    descs.extend(Poly1305Provider::descriptors());
    descs.extend(SipHashProvider::descriptors());
    descs.extend(Blake2MacProvider::all_descriptors());
    descs
}

/// Returns MAC algorithm descriptors approved for FIPS operation.
///
/// Only HMAC, CMAC, GMAC, and KMAC are FIPS-approved MACs per
/// NIST SP 800-140C (CMVP-approved services). Poly1305, `SipHash`,
/// and BLAKE2-MAC are **not** FIPS-approved and are excluded.
///
/// Called by the FIPS provider's `query_operation(Mac)` to restrict
/// the algorithm set to approved-only services.
///
/// ## FIPS-Approved MACs
///
/// | Algorithm | Standard | Approval |
/// |-----------|----------|----------|
/// | HMAC | RFC 2104 / FIPS 198-1 | Approved |
/// | CMAC | SP 800-38B | Approved |
/// | GMAC | SP 800-38D | Approved |
/// | KMAC-128 | SP 800-185 | Approved |
/// | KMAC-256 | SP 800-185 | Approved |
///
/// ## Excluded MACs
///
/// | Algorithm | Reason |
/// |-----------|--------|
/// | Poly1305 | Not NIST-approved |
/// | SipHash | Not NIST-approved |
/// | BLAKE2b/s-MAC | Not NIST-approved |
#[must_use]
pub fn fips_descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();
    descs.extend(HmacProvider::descriptors());
    descs.extend(CmacProvider::descriptors());
    descs.extend(GmacProvider::descriptors());
    descs.extend(KmacProvider::descriptors());
    // Poly1305, SipHash, BLAKE2-MAC are NOT FIPS approved
    descs
}
