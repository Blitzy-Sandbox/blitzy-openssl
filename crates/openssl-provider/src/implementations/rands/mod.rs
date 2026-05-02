//! # Random Number Generator Provider Implementations
//!
//! Rust translations of `providers/implementations/rands/` (8 C source files).
//! Implements all DRBG and seed source providers that implement the
//! [`RandProvider`](crate::traits::RandProvider) and
//! [`RandContext`](crate::traits::RandContext) traits from `crate::traits`.
//!
//! ## Algorithm Families
//!
//! ### SP 800-90A DRBG Implementations
//! - **CTR-DRBG** (`ctr_drbg`) — AES-based counter mode DRBG (SP 800-90A §10.2)
//! - **Hash-DRBG** (`hash_drbg`) — Hash function-based DRBG (SP 800-90A §10.1.1)
//! - **HMAC-DRBG** (`hmac_drbg`) — HMAC-based DRBG (SP 800-90A §10.1.2)
//!
//! ### Seed Sources
//! - **Seed Source** (`seed_src`) — OS entropy via `getrandom`/`CryptGenRandom`
//! - **Jitter** (`jitter`) — CPU timing jitter entropy (conditional on
//!   `jitter` feature flag)
//!
//! ### Test and Compliance
//! - **FIPS CRNG Test** (`fips_crng`) — SP 800-90B continuous RNG health
//!   test wrapper
//! - **Test RNG** (`test_rng`) — Deterministic test RNG (xorshift32) for
//!   reproducible test scenarios
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                   Drbg (framework)               │
//! │  entropy/nonce acquisition, reseed policy,       │
//! │  locking, fork detection, state machine          │
//! ├──────────┬──────────────┬───────────────────────┤
//! │ CtrDrbg  │  HashDrbg    │  HmacDrbg             │
//! │ (AES)    │  (SHA-*)     │  (HMAC-SHA-*)         │
//! └──────┬───┴──────┬───────┴───────────┬───────────┘
//!        │          │                   │
//!   SeedSource   JitterSource    FIPS CrngTest
//!   (OS entropy)  (CPU jitter)   (health wrapper)
//! ```
//!
//! All DRBG implementations use the common `Drbg` framework which wraps
//! mechanism-specific types via the `DrbgMechanism` trait. The `Drbg`
//! struct manages entropy acquisition, reseed policy enforcement, optional
//! locking, and fork detection around the mechanism-specific core.
//!
//! ## Provider Registration
//!
//! The `descriptors()` function returns algorithm descriptors for all RNG
//! algorithms, matching the C `default_rands[]` array in `defltprov.c`.
//! The `create_rand_context()` factory function creates the appropriate
//! [`RandContext`](crate::traits::RandContext) for a given algorithm name.
//!
//! ## Source Mapping
//!
//! | Rust Module | C Source File | Description |
//! |-------------|---------------|-------------|
//! | `drbg` | `drbg.c` | Core DRBG framework, state machine |
//! | `ctr_drbg` | `drbg_ctr.c` | AES-CTR mechanism |
//! | `hash_drbg` | `drbg_hash.c` | Hash-based mechanism |
//! | `hmac_drbg` | `drbg_hmac.c` | HMAC-based mechanism |
//! | `seed_src` | `seed_src.c` | OS entropy source |
//! | `jitter` | `seed_src_jitter.c` | CPU jitter entropy |
//! | `fips_crng` | `fips_crng_test.c` | FIPS health test wrapper |
//! | `test_rng` | `test_rng.c` | Deterministic test RNG |

// =============================================================================
// Submodule Declarations
// =============================================================================

/// Core DRBG framework: state machine, entropy acquisition, reseed policy,
/// optional locking, and fork detection.
///
/// Provides the `Drbg` wrapper struct that delegates to mechanism-specific
/// implementations via the `DrbgMechanism` trait.
///
/// Source: `providers/implementations/rands/drbg.c`
pub mod drbg;

/// CTR-DRBG (SP 800-90A §10.2) — AES-based counter mode DRBG.
///
/// Implements the `DrbgMechanism` trait using AES in counter mode for the
/// internal state update and output generation functions.
///
/// Source: `providers/implementations/rands/drbg_ctr.c`
pub mod ctr_drbg;

/// Hash-DRBG (SP 800-90A §10.1.1) — Hash function-based DRBG.
///
/// Implements the `DrbgMechanism` trait using a hash function (e.g., SHA-256,
/// SHA-512) for the internal state update and output generation.
///
/// Source: `providers/implementations/rands/drbg_hash.c`
pub mod hash_drbg;

/// HMAC-DRBG (SP 800-90A §10.1.2) — HMAC-based DRBG.
///
/// Implements the `DrbgMechanism` trait using HMAC for the internal state
/// update and output generation. Widely used due to its simplicity and
/// proven security properties.
///
/// Source: `providers/implementations/rands/drbg_hmac.c`
pub mod hmac_drbg;

/// OS entropy seed source (`getrandom`/`CryptGenRandom`).
///
/// Provides direct access to operating system entropy for seeding DRBGs and
/// for applications requiring true randomness. Implements
/// [`RandContext`](crate::traits::RandContext) directly (not wrapped by
/// `Drbg`).
///
/// Source: `providers/implementations/rands/seed_src.c`
pub mod seed_src;

/// CPU jitter entropy source (conditional on platform support).
///
/// Harvests entropy from CPU execution time variations. Requires the
/// `jitter` feature flag to be enabled. When unavailable, the
/// `descriptors()` function omits the JITTER algorithm and the
/// `create_rand_context()` factory returns
/// [`ProviderError::AlgorithmUnavailable`](openssl_common::error::ProviderError::AlgorithmUnavailable).
///
/// Source: `providers/implementations/rands/seed_src_jitter.c`
#[cfg(feature = "jitter")]
pub mod jitter;

/// FIPS SP 800-90B continuous RNG health test wrapper.
///
/// Wraps an underlying RNG and applies continuous health tests to detect
/// entropy source degradation. Required for FIPS 140-3 compliance.
/// Implements [`RandContext`](crate::traits::RandContext) directly.
///
/// Source: `providers/implementations/rands/fips_crng_test.c`
pub mod fips_crng;

/// Deterministic test RNG for reproducible testing (xorshift32).
///
/// Produces deterministic output from a fixed seed, allowing test
/// reproducibility. **Must never be used in production.** Implements
/// [`RandContext`](crate::traits::RandContext) directly.
///
/// Source: `providers/implementations/rands/test_rng.c`
pub mod test_rng;

// =============================================================================
// Re-exports — Convenient Access for Parent Modules
// =============================================================================

// Core DRBG framework types
pub use drbg::{Drbg, DrbgConfig, DrbgMechanism, RandState};

// DRBG mechanism implementations
pub use ctr_drbg::{CtrDrbg, CtrDrbgProvider};
pub use hash_drbg::{HashDrbg, HashDrbgProvider};
pub use hmac_drbg::{HmacDrbg, HmacDrbgProvider};

// Seed sources
pub use seed_src::{SeedSource, SeedSourceProvider};

#[cfg(feature = "jitter")]
pub use jitter::{JitterProvider, JitterSource};

// Test and compliance
pub use fips_crng::{CrngTest, CrngTestProvider};
pub use test_rng::{TestRng, TestRngProvider};

// =============================================================================
// Imports
// =============================================================================

use crate::traits::{AlgorithmDescriptor, RandContext, RandProvider};
use openssl_common::error::{ProviderError, ProviderResult};

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns all random number generator algorithm descriptors for provider
/// registration.
///
/// These correspond to the C `default_rands[]` array in `defltprov.c` and
/// are collected by [`super::all_rand_descriptors()`] when the `rands`
/// feature is enabled. Each entry describes a supported RNG algorithm
/// with its canonical name(s), property query string, and human-readable
/// description.
///
/// # Algorithms Registered
///
/// | Name | Standard | Description |
/// |------|----------|-------------|
/// | `CTR-DRBG` | SP 800-90A §10.2 | AES counter-mode DRBG |
/// | `HASH-DRBG` | SP 800-90A §10.1.1 | Hash-based DRBG |
/// | `HMAC-DRBG` | SP 800-90A §10.1.2 | HMAC-based DRBG |
/// | `SEED-SRC` | — | OS entropy seed source |
/// | `TEST-RAND` | — | Deterministic test RNG |
/// | `CRNG-TEST` | SP 800-90B | FIPS continuous health test |
/// | `JITTER` | — | CPU jitter entropy (feature-gated) |
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_provider::implementations::rands::descriptors;
///
/// let descs = descriptors();
/// assert!(descs.len() >= 6); // At least 6 unconditional algorithms
/// assert!(descs.iter().any(|d| d.names.contains(&"CTR-DRBG")));
/// assert!(descs.iter().any(|d| d.names.contains(&"SEED-SRC")));
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    // `mut` is needed when the `jitter` feature is enabled (conditional push below).
    #[allow(unused_mut)]
    let mut descs = vec![
        super::algorithm(
            &["CTR-DRBG"],
            "provider=default",
            "AES Counter-mode DRBG (SP 800-90A §10.2)",
        ),
        super::algorithm(
            &["HASH-DRBG"],
            "provider=default",
            "Hash-based DRBG (SP 800-90A §10.1.1)",
        ),
        super::algorithm(
            &["HMAC-DRBG"],
            "provider=default",
            "HMAC-based DRBG (SP 800-90A §10.1.2)",
        ),
        super::algorithm(&["SEED-SRC"], "provider=default", "OS Entropy Seed Source"),
        super::algorithm(&["TEST-RAND"], "provider=default", "Deterministic Test RNG"),
        super::algorithm(
            &["CRNG-TEST"],
            "provider=default",
            "FIPS Continuous RNG Health Test (SP 800-90B)",
        ),
    ];

    #[cfg(feature = "jitter")]
    descs.push(super::algorithm(
        &["JITTER"],
        "provider=default",
        "CPU Jitter Entropy Source",
    ));

    descs
}

// =============================================================================
// Factory Function — Algorithm Context Creation
// =============================================================================

/// Creates a random number generator context for the given algorithm name.
///
/// This factory function dispatches to the appropriate RNG implementation
/// based on the algorithm name, replacing the C `OSSL_FUNC_rand_newctx`
/// dispatch table lookup. Each algorithm name is matched case-sensitively
/// against the canonical names registered by `descriptors()`.
///
/// # Algorithm Dispatch
///
/// | Name | Context Type | Wrapped By |
/// |------|-------------|------------|
/// | `"CTR-DRBG"` | `CtrDrbg` | `Drbg` framework |
/// | `"HASH-DRBG"` | `HashDrbg` | `Drbg` framework |
/// | `"HMAC-DRBG"` | `HmacDrbg` | `Drbg` framework |
/// | `"SEED-SRC"` | `SeedSource` | Direct |
/// | `"TEST-RAND"` | `TestRng` | Direct |
/// | `"CRNG-TEST"` | `CrngTest` | Direct |
/// | `"JITTER"` | `JitterSource` | Direct (feature-gated) |
///
/// # Errors
///
/// Returns `ProviderError::AlgorithmUnavailable` if the algorithm name
/// is not recognised or if the required feature flag is not enabled (e.g.,
/// `"JITTER"` without the `jitter` feature).
///
/// # Examples
///
/// ```rust,no_run
/// use openssl_provider::implementations::rands::create_rand_context;
///
/// let ctx = create_rand_context("CTR-DRBG")
///     .expect("CTR-DRBG should be available");
/// ```
pub fn create_rand_context(name: &str) -> ProviderResult<Box<dyn RandContext>> {
    match name {
        "CTR-DRBG" => {
            let provider = CtrDrbgProvider;
            provider.new_ctx()
        }
        "HASH-DRBG" => {
            let provider = HashDrbgProvider;
            provider.new_ctx()
        }
        "HMAC-DRBG" => {
            let provider = HmacDrbgProvider;
            provider.new_ctx()
        }
        "SEED-SRC" => {
            let provider = SeedSourceProvider;
            provider.new_ctx()
        }
        "TEST-RAND" => {
            let provider = TestRngProvider;
            provider.new_ctx()
        }
        "CRNG-TEST" => {
            let provider = CrngTestProvider;
            provider.new_ctx()
        }
        #[cfg(feature = "jitter")]
        "JITTER" => {
            let provider = JitterProvider;
            provider.new_ctx()
        }
        _ => Err(ProviderError::AlgorithmUnavailable(format!(
            "Unknown RAND algorithm: '{name}'"
        ))),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `descriptors()` returns at least 6 unconditional algorithms.
    #[test]
    fn descriptors_returns_all_unconditional_algorithms() {
        let descs = descriptors();
        // At least 6 unconditional entries: CTR-DRBG, HASH-DRBG, HMAC-DRBG,
        // SEED-SRC, TEST-RAND, CRNG-TEST
        assert!(
            descs.len() >= 6,
            "Expected at least 6 descriptors, got {}",
            descs.len()
        );
    }

    /// Verify CTR-DRBG descriptor is present and correctly formed.
    #[test]
    fn descriptors_contains_ctr_drbg() {
        let descs = descriptors();
        let ctr = descs
            .iter()
            .find(|d| d.names.contains(&"CTR-DRBG"))
            .expect("CTR-DRBG descriptor missing");
        assert_eq!(ctr.property, "provider=default");
        assert!(!ctr.description.is_empty());
    }

    /// Verify HASH-DRBG descriptor is present and correctly formed.
    #[test]
    fn descriptors_contains_hash_drbg() {
        let descs = descriptors();
        let hash = descs
            .iter()
            .find(|d| d.names.contains(&"HASH-DRBG"))
            .expect("HASH-DRBG descriptor missing");
        assert_eq!(hash.property, "provider=default");
        assert!(!hash.description.is_empty());
    }

    /// Verify HMAC-DRBG descriptor is present and correctly formed.
    #[test]
    fn descriptors_contains_hmac_drbg() {
        let descs = descriptors();
        let hmac = descs
            .iter()
            .find(|d| d.names.contains(&"HMAC-DRBG"))
            .expect("HMAC-DRBG descriptor missing");
        assert_eq!(hmac.property, "provider=default");
        assert!(!hmac.description.is_empty());
    }

    /// Verify SEED-SRC descriptor is present.
    #[test]
    fn descriptors_contains_seed_src() {
        let descs = descriptors();
        let seed = descs
            .iter()
            .find(|d| d.names.contains(&"SEED-SRC"))
            .expect("SEED-SRC descriptor missing");
        assert_eq!(seed.property, "provider=default");
    }

    /// Verify TEST-RAND descriptor is present.
    #[test]
    fn descriptors_contains_test_rand() {
        let descs = descriptors();
        let test_rng_desc = descs
            .iter()
            .find(|d| d.names.contains(&"TEST-RAND"))
            .expect("TEST-RAND descriptor missing");
        assert_eq!(test_rng_desc.property, "provider=default");
    }

    /// Verify CRNG-TEST descriptor is present.
    #[test]
    fn descriptors_contains_crng_test() {
        let descs = descriptors();
        let crng = descs
            .iter()
            .find(|d| d.names.contains(&"CRNG-TEST"))
            .expect("CRNG-TEST descriptor missing");
        assert_eq!(crng.property, "provider=default");
    }

    /// Verify JITTER descriptor is present only when the feature is enabled.
    #[test]
    fn descriptors_jitter_conditional() {
        let descs = descriptors();
        let has_jitter = descs.iter().any(|d| d.names.contains(&"JITTER"));
        if cfg!(feature = "jitter") {
            assert!(
                has_jitter,
                "JITTER descriptor should be present with jitter feature"
            );
        } else {
            assert!(
                !has_jitter,
                "JITTER descriptor should NOT be present without jitter feature"
            );
        }
    }

    /// Verify all descriptor names are unique.
    #[test]
    fn descriptors_names_are_unique() {
        let descs = descriptors();
        let mut seen = std::collections::HashSet::new();
        for desc in &descs {
            for name in &desc.names {
                assert!(seen.insert(*name), "Duplicate algorithm name: {name}");
            }
        }
    }

    /// Verify all descriptors have non-empty description fields.
    #[test]
    fn descriptors_all_have_descriptions() {
        let descs = descriptors();
        for desc in &descs {
            assert!(
                !desc.description.is_empty(),
                "Empty description for {:?}",
                desc.names
            );
        }
    }

    /// Verify that `create_rand_context` returns an error for unknown algorithms.
    #[test]
    fn create_rand_context_unknown_algorithm() {
        let result = create_rand_context("NONEXISTENT-RNG");
        assert!(result.is_err());
        match result {
            Err(ProviderError::AlgorithmUnavailable(msg)) => {
                assert!(
                    msg.contains("NONEXISTENT-RNG"),
                    "Error message should contain the algorithm name"
                );
            }
            Err(other) => panic!("Expected AlgorithmUnavailable, got: {other:?}"),
            Ok(_) => panic!("Expected error for unknown algorithm"),
        }
    }

    /// Verify that `create_rand_context` returns an error for empty name.
    #[test]
    fn create_rand_context_empty_name() {
        let result = create_rand_context("");
        assert!(result.is_err());
    }

    /// Verify that `create_rand_context` is case-sensitive.
    #[test]
    fn create_rand_context_case_sensitive() {
        // Lower-case should not match the upper-case canonical names
        let result = create_rand_context("ctr-drbg");
        assert!(result.is_err(), "Algorithm lookup should be case-sensitive");
    }
}
