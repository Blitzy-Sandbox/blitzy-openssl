//! # Key Management Provider Implementations
//!
//! Contains all key management algorithm implementations that implement the
//! [`KeyMgmtProvider`] trait from [`crate::traits`]. Each submodule corresponds
//! to one or more C keymgmt implementation files from
//! `providers/implementations/keymgmt/` (13 C files, ~9,400 total lines).
//!
//! ## Algorithm Families
//!
//! ### Classical Key Types
//! - [`dh`] — DH/DHX key management (RFC 3526/7919, X9.42)
//! - [`dsa`] — DSA key management (FIPS 186-2/186-4)
//! - [`ec`] — EC key management (NIST P-curves, Brainpool, SM2)
//! - [`ecx`] — ECX key management (X25519, X448, Ed25519, Ed448)
//! - [`rsa`] — RSA/RSA-PSS key management
//!
//! ### Post-Quantum Key Types
//! - [`ml_dsa`] — ML-DSA key management (FIPS 204)
//! - [`ml_kem`] — ML-KEM key management (FIPS 203)
//! - [`mlx`] — Hybrid ML-KEM + ECDH/XDH key management
//! - [`slh_dsa`] — SLH-DSA key management (FIPS 205)
//! - [`lms`] — LMS key management (SP 800-208)
//!
//! ### Legacy Key Types
//! - [`legacy`] — KDF/MAC/CMAC legacy key management shims
//!
//! ## Operations
//!
//! Each keymgmt implementation provides the following operations through
//! the [`KeyMgmtProvider`] trait:
//!
//! - `name()` — Canonical algorithm name
//! - `new_key()` — Allocate empty key data
//! - `generate(params)` — Generate key material
//! - `import(selection, data)` — Import key components from [`ParamSet`]
//! - `export(key, selection)` — Export key components to [`ParamSet`]
//! - `has(key, selection)` — Check which components are present
//! - `validate(key, selection)` — Validate key correctness
//!
//! ## Architecture
//!
//! - Each keymgmt struct implements [`KeyMgmtProvider`] from [`crate::traits`]
//! - [`KeySelection`] bitflags control which components to import/export
//! - [`KeyData`] is the type-erasure boundary for key material
//! - FIPS restrictions enforced via feature gates
//! - Zero unsafe code (Rule R8)
//!
//! ## Feature Gating
//!
//! Each submodule (except [`legacy`]) is wrapped in `#[cfg(feature = "...")]`
//! replacing the C `OPENSSL_NO_*` preprocessor guards:
//!
//! | Rust feature | C guard | Submodule |
//! |-------------|---------|-----------|
//! | `dh` | `OPENSSL_NO_DH` | [`dh`] |
//! | `dsa` | `OPENSSL_NO_DSA` | [`dsa`] |
//! | `ec` | `OPENSSL_NO_EC` | [`ec`] |
//! | `ecx` | `OPENSSL_NO_ECX` | [`ecx`] |
//! | `rsa` | (always enabled in C) | [`rsa`] |
//! | `ml-dsa` | `OPENSSL_NO_ML_DSA` | [`ml_dsa`] |
//! | `ml-kem` | `OPENSSL_NO_ML_KEM` | [`ml_kem`] |
//! | `mlx` | (depends on ML-KEM + EC/ECX) | [`mlx`] |
//! | `slh-dsa` | `OPENSSL_NO_SLH_DSA` | [`slh_dsa`] |
//! | `lms` | `OPENSSL_NO_LMS` | [`lms`] |
//! | (always on) | (always compiled) | [`legacy`] |
//!
//! ## Wiring Path (Rule R10)
//!
//! Every submodule is reachable from the entry point:
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyMgmt)
//!         → implementations::all_keymgmt_descriptors()
//!           → keymgmt::descriptors()
//!             → submodule::*_descriptors()
//! ```
//!
//! ## C Source Mapping
//!
//! | Rust submodule | C source file | Lines |
//! |---------------|---------------|-------|
//! | `dh` | `dh_kmgmt.c` | ~960 |
//! | `dsa` | `dsa_kmgmt.c` | ~766 |
//! | `ec` | `ec_kmgmt.c` | ~1,524 |
//! | `ecx` | `ecx_kmgmt.c` | ~1,311 |
//! | `rsa` | `rsa_kmgmt.c` | ~823 |
//! | `ml_dsa` | `ml_dsa_kmgmt.c` | ~594 |
//! | `ml_kem` | `ml_kem_kmgmt.c` | ~859 |
//! | `mlx` | `mlx_kmgmt.c` | ~807 |
//! | `slh_dsa` | `slh_dsa_kmgmt.c` | ~481 |
//! | `lms` | `lms_kmgmt.c` | ~213 |
//! | `legacy` | `kdf_legacy_kmgmt.c` + `mac_legacy_kmgmt.c` | ~680 |
//!
//! [`ParamSet`]: openssl_common::param::ParamSet

use crate::traits::AlgorithmDescriptor;

// =============================================================================
// Re-exports — Core keymgmt types from crate::traits
// =============================================================================
//
// These re-exports provide convenient access to the key management trait
// hierarchy for all submodules and external consumers. Every submodule
// imports these types via `use super::{KeyMgmtProvider, KeyData, KeySelection};`
// rather than reaching through `crate::traits::*` directly.

/// The core key management provider trait. All keymgmt implementations
/// (DH, DSA, EC, RSA, PQ, legacy) implement this trait.
///
/// Re-exported from [`crate::traits::KeyMgmtProvider`].
pub use crate::traits::KeyMgmtProvider;

/// Opaque key data handle — the type-erasure boundary for key material.
/// Concrete key types implement this marker trait.
///
/// Re-exported from [`crate::traits::KeyData`].
pub use crate::traits::KeyData;

/// Bitflags for selecting key components in import/export/has/validate
/// operations (private key, public key, domain parameters, etc.).
///
/// Re-exported from [`crate::traits::KeySelection`].
pub use crate::traits::KeySelection;

// =============================================================================
// Submodule Declarations — Algorithm-Specific Key Management
// =============================================================================
//
// Each submodule is gated by a feature flag (except `legacy` which is always
// available, matching the C precedent where KDF/MAC keymgmt shims are
// unconditionally compiled).
//
// Feature gate names use hyphens (e.g., "ml-dsa") while module names use
// underscores (e.g., `ml_dsa`), following Rust/Cargo conventions.

// ---- Classical Key Types ----

/// DH/DHX key management (RFC 3526/7919, X9.42).
///
/// Provides `DhKeyMgmt` and `DhxKeyMgmt` implementing [`KeyMgmtProvider`]
/// for Diffie-Hellman named groups and custom parameters.
///
/// Source: `providers/implementations/keymgmt/dh_kmgmt.c` (~960 lines).
///
/// C guards: `#ifndef OPENSSL_NO_DH`
#[cfg(feature = "dh")]
pub mod dh;

/// DSA key management (FIPS 186-2/186-4).
///
/// Provides `DsaKeyMgmt` implementing [`KeyMgmtProvider`] for DSA
/// key generation, parameter handling, and sign/verify key lifecycle.
///
/// Source: `providers/implementations/keymgmt/dsa_kmgmt.c` (~766 lines).
///
/// C guards: `#ifndef OPENSSL_NO_DSA`
#[cfg(feature = "dsa")]
pub mod dsa;

/// EC/SM2 key management (NIST P-curves, Brainpool, SM2).
///
/// Provides `EcKeyMgmt` and `Sm2KeyMgmt` implementing [`KeyMgmtProvider`]
/// for elliptic curve key operations on named curves (P-256, P-384, P-521,
/// secp256k1, Brainpool, SM2).
///
/// Source: `providers/implementations/keymgmt/ec_kmgmt.c` (~1,524 lines).
///
/// C guards: `#ifndef OPENSSL_NO_EC`
#[cfg(feature = "ec")]
pub mod ec;

/// ECX key management (X25519, X448, Ed25519, Ed448).
///
/// Provides `EcxKeyMgmt` implementing [`KeyMgmtProvider`] for Montgomery
/// and Edwards curve key types defined in RFC 7748 and RFC 8032.
///
/// Source: `providers/implementations/keymgmt/ecx_kmgmt.c` (~1,311 lines).
///
/// C guards: `#ifndef OPENSSL_NO_ECX`
#[cfg(feature = "ecx")]
pub mod ecx;

/// RSA/RSA-PSS key management.
///
/// Provides `RsaKeyMgmt` and `RsaPssKeyMgmt` implementing
/// [`KeyMgmtProvider`] for RSA key generation, import/export with CRT
/// parameters, and PSS-restricted keys.
///
/// Source: `providers/implementations/keymgmt/rsa_kmgmt.c` (~823 lines).
///
/// C guards: RSA is always compiled in C; feature-gated in Rust for
/// flexibility in constrained builds.
#[cfg(feature = "rsa")]
pub mod rsa;

// ---- Post-Quantum Key Types ----

/// ML-DSA key management (FIPS 204).
///
/// Provides `MlDsaKeyMgmt` implementing [`KeyMgmtProvider`] for
/// ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets.
///
/// Source: `providers/implementations/keymgmt/ml_dsa_kmgmt.c` (~594 lines).
///
/// C guards: `#ifndef OPENSSL_NO_ML_DSA`
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

/// ML-KEM key management (FIPS 203).
///
/// Provides `MlKemKeyMgmt` implementing [`KeyMgmtProvider`] for
/// ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameter sets.
///
/// Source: `providers/implementations/keymgmt/ml_kem_kmgmt.c` (~859 lines).
///
/// C guards: `#ifndef OPENSSL_NO_ML_KEM`
#[cfg(feature = "ml-kem")]
pub mod ml_kem;

/// Hybrid ML-KEM + ECDH/XDH key management.
///
/// Provides `MlxKeyMgmt` implementing [`KeyMgmtProvider`] for hybrid
/// post-quantum/classical key exchange combinations:
/// - X25519MLKEM768 (X25519 + ML-KEM-768)
/// - X448MLKEM1024 (X448 + ML-KEM-1024)
/// - SecP256r1MLKEM768 (P-256 + ML-KEM-768)
/// - SecP384r1MLKEM1024 (P-384 + ML-KEM-1024)
///
/// Source: `providers/implementations/keymgmt/mlx_kmgmt.c` (~807 lines).
///
/// C guards: depends on `OPENSSL_NO_ML_KEM`, `OPENSSL_NO_ECX`, `OPENSSL_NO_EC`
#[cfg(feature = "mlx")]
pub mod mlx;

/// SLH-DSA key management (FIPS 205).
///
/// Provides `SlhDsaKeyMgmt` implementing [`KeyMgmtProvider`] for all
/// 12 SLH-DSA parameter sets (SHA2/SHAKE × 128/192/256 × s/f).
///
/// Source: `providers/implementations/keymgmt/slh_dsa_kmgmt.c` (~481 lines).
///
/// C guards: `#ifndef OPENSSL_NO_SLH_DSA`
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

/// LMS key management (SP 800-208).
///
/// Provides `LmsKeyMgmt` implementing [`KeyMgmtProvider`] for
/// Leighton-Micali Signature (LMS) hash-based signature verification keys.
/// Note: LMS is verification-only; key generation is out of scope per
/// SP 800-208 guidance.
///
/// Source: `providers/implementations/keymgmt/lms_kmgmt.c` (~213 lines).
///
/// C guards: `#ifndef OPENSSL_NO_LMS`
#[cfg(feature = "lms")]
pub mod lms;

// ---- Legacy Key Types ----

/// KDF/MAC/CMAC legacy key management shims.
///
/// Provides `KdfLegacyKeyMgmt`, `MacLegacyKeyMgmt`, and `CmacLegacyKeyMgmt`
/// implementing [`KeyMgmtProvider`] as thin wrappers that allow KDF and MAC
/// algorithms to participate in the key management dispatch system.
///
/// These shims are always available (no feature gate) because KDF-backed
/// signature operations (TLS1-PRF, HKDF, scrypt) and MAC-based signing
/// (HMAC, SipHash, Poly1305, CMAC) are unconditionally compiled in the
/// C source.
///
/// Source: `providers/implementations/keymgmt/kdf_legacy_kmgmt.c` (~102 lines)
///         + `providers/implementations/keymgmt/mac_legacy_kmgmt.c` (~578 lines).
pub mod legacy;

// =============================================================================
// Algorithm Descriptor Aggregation
// =============================================================================

/// Collects all keymgmt algorithm descriptors from enabled submodules.
///
/// Called by the parent [`super::all_keymgmt_descriptors()`] to enumerate
/// available key management algorithms for provider registration.
///
/// This replaces the role of the static `deflt_keymgmt[]` array in
/// `providers/defltprov.c` (lines 580–696) that listed all keymgmt dispatch
/// tables. In the C codebase, that array contained ~40 entries gated by
/// `#ifndef OPENSSL_NO_*` preprocessor guards.
///
/// # Feature Gating
///
/// Each submodule's descriptors are only included when the corresponding
/// feature is enabled, matching the C `#ifndef OPENSSL_NO_*` pattern:
///
/// - `"dh"` → `dh::dh_descriptors()`
/// - `"dsa"` → `dsa::dsa_descriptors()`
/// - `"ec"` → `ec::ec_descriptors()`
/// - `"ecx"` → `ecx::ecx_descriptors()`
/// - `"rsa"` → `rsa::rsa_descriptors()`
/// - `"ml-dsa"` → `ml_dsa::ml_dsa_descriptors()`
/// - `"ml-kem"` → `ml_kem::ml_kem_descriptors()`
/// - `"mlx"` → `mlx::mlx_descriptors()`
/// - `"slh-dsa"` → `slh_dsa::slh_dsa_descriptors()`
/// - `"lms"` → `lms::lms_descriptors()`
/// - (always) → `legacy::legacy_descriptors()`
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled
/// key management implementations. Returns only legacy descriptors when
/// no algorithm-specific features are enabled.
///
/// # Rule R5
///
/// Returns `Vec<AlgorithmDescriptor>`, never a sentinel value or NULL pointer.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut result = Vec::new();

    // Classical key types

    #[cfg(feature = "dh")]
    result.extend(dh::dh_descriptors());

    #[cfg(feature = "dsa")]
    result.extend(dsa::dsa_descriptors());

    #[cfg(feature = "ec")]
    result.extend(ec::ec_descriptors());

    #[cfg(feature = "ecx")]
    result.extend(ecx::ecx_descriptors());

    #[cfg(feature = "rsa")]
    result.extend(rsa::rsa_descriptors());

    // Post-quantum key types

    #[cfg(feature = "ml-dsa")]
    result.extend(ml_dsa::ml_dsa_descriptors());

    #[cfg(feature = "ml-kem")]
    result.extend(ml_kem::ml_kem_descriptors());

    #[cfg(feature = "mlx")]
    result.extend(mlx::mlx_descriptors());

    #[cfg(feature = "slh-dsa")]
    result.extend(slh_dsa::slh_dsa_descriptors());

    #[cfg(feature = "lms")]
    result.extend(lms::lms_descriptors());

    // Legacy key types (always available — no feature gate)
    result.extend(legacy::legacy_descriptors());

    result
}

// =============================================================================
// Shared Constants
// =============================================================================

/// Default property query string for algorithms registered by the default
/// provider.
///
/// Replaces the C pattern where every `OSSL_ALGORITHM` entry in
/// `deflt_keymgmt[]` used the literal `"provider=default"` string.
/// Centralised here to avoid duplication across submodules.
pub(crate) const DEFAULT_PROPERTY: &str = "provider=default";

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the `descriptors()` function returns a non-empty vector
    /// when at least the legacy module contributes descriptors.
    #[test]
    fn descriptors_includes_legacy() {
        let descs = descriptors();
        // Legacy descriptors are always included (no feature gate),
        // so the result should never be empty.
        assert!(
            !descs.is_empty(),
            "descriptors() must return at least legacy descriptors"
        );
    }

    /// Verify that all returned descriptors have non-empty names.
    #[test]
    fn descriptors_have_valid_names() {
        let descs = descriptors();
        for desc in &descs {
            assert!(
                !desc.names.is_empty(),
                "Every descriptor must have at least one algorithm name"
            );
            for name in &desc.names {
                assert!(
                    !name.is_empty(),
                    "Algorithm names must not be empty strings"
                );
            }
        }
    }

    /// Verify that all returned descriptors have non-empty property strings.
    #[test]
    fn descriptors_have_valid_properties() {
        let descs = descriptors();
        for desc in &descs {
            assert!(
                !desc.property.is_empty(),
                "Descriptor for {:?} must have a non-empty property string",
                desc.names
            );
        }
    }

    /// Verify that all returned descriptors have non-empty descriptions.
    #[test]
    fn descriptors_have_valid_descriptions() {
        let descs = descriptors();
        for desc in &descs {
            assert!(
                !desc.description.is_empty(),
                "Descriptor for {:?} must have a non-empty description",
                desc.names
            );
        }
    }

    /// Verify re-exported types are accessible and usable.
    #[test]
    fn reexported_types_accessible() {
        // KeySelection bitflags must be constructible
        let sel = KeySelection::PRIVATE_KEY | KeySelection::PUBLIC_KEY;
        assert_eq!(sel, KeySelection::KEYPAIR);
        assert!(KeySelection::ALL.contains(KeySelection::DOMAIN_PARAMETERS));
        assert!(KeySelection::ALL.contains(KeySelection::OTHER_PARAMETERS));
        assert!(KeySelection::ALL.contains(KeySelection::KEYPAIR));
    }

    /// Verify that `DEFAULT_PROPERTY` matches the expected value used
    /// throughout the provider system.
    #[test]
    fn default_property_value() {
        assert_eq!(DEFAULT_PROPERTY, "provider=default");
    }

}
