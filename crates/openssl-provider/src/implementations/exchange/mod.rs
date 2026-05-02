//! Key exchange provider implementations.
//!
//! This module contains all key exchange algorithm implementations that
//! implement the [`KeyExchangeProvider`](crate::traits::KeyExchangeProvider)
//! trait from `crate::traits`. Each submodule translates a C source file from
//! `providers/implementations/exchange/`.
//!
//! ## Algorithm Families
//!
//! | Rust Module | C Source        | Algorithms                | Description                                     |
//! |-------------|-----------------|---------------------------|-------------------------------------------------|
//! | [`dh`]      | `dh_exch.c`     | DH                        | Finite-field Diffie-Hellman (RFC 3526 / 7919)   |
//! | [`ecdh`]    | `ecdh_exch.c`   | ECDH                      | Elliptic Curve DH (NIST P-curves, Brainpool)    |
//! | [`ecx`]     | `ecx_exch.c`    | X25519, X448              | Montgomery curve key exchange (RFC 7748)        |
//! | [`kdf`]     | `kdf_exch.c`    | TLS1-PRF, HKDF, SCRYPT    | KDF-backed exchange adapters                    |
//!
//! ## Architecture
//!
//! - Each exchange struct implements
//!   [`KeyExchangeProvider`](crate::traits::KeyExchangeProvider) and creates
//!   [`KeyExchangeContext`](crate::traits::KeyExchangeContext) instances via
//!   `new_ctx()`.
//! - Context lifecycle: `new_ctx()` → `init(key)` → `set_peer(peer_key)` →
//!   `derive(secret)` with `Drop` performing constant-time secure zeroing of
//!   private/peer key material via `zeroize`.
//! - Both raw shared-secret output and KDF-derived key material are supported
//!   (DH X9.42 KDF, ECDH X9.63 KDF, KDF-adapter `derive`).
//! - DH/ECDH support configurable padding (`pad`) and cofactor (`cofactor-mode`)
//!   parameters via [`ParamSet`](openssl_common::param::ParamSet).
//! - Per-algorithm Cargo feature flags gate availability, replacing the C
//!   `OPENSSL_NO_DH` / `OPENSSL_NO_EC` / `OPENSSL_NO_ECX` preprocessor guards.
//! - **Zero unsafe code** — all primitive math is delegated to the
//!   [`openssl_crypto`] safe-Rust layer (Rule R8).
//!
//! ## C Dispatch Table Mapping
//!
//! The C code exports seven dispatch tables from
//! `providers/implementations/exchange/`. Each maps to a single Rust provider
//! type implementing [`KeyExchangeProvider`](crate::traits::KeyExchangeProvider):
//!
//! | C dispatch table                        | Rust provider type                |
//! |-----------------------------------------|-----------------------------------|
//! | `ossl_dh_keyexch_functions`             | [`DhExchange`]                    |
//! | `ossl_ecdh_keyexch_functions`           | [`EcdhExchange`]                  |
//! | `ossl_x25519_keyexch_functions`         | [`X25519Exchange`]                |
//! | `ossl_x448_keyexch_functions`           | [`X448Exchange`]                  |
//! | `ossl_kdf_tls1_prf_keyexch_functions`   | [`Tls1PrfExchange`]               |
//! | `ossl_kdf_hkdf_keyexch_functions`       | [`HkdfExchange`]                  |
//! | `ossl_kdf_scrypt_keyexch_functions`     | [`ScryptExchange`]                |
//!
//! Replaces the organizational structure of
//! `providers/implementations/exchange/` and the dispatch entries enumerated
//! in the `deflt_keyexch[]` static array of `providers/defltprov.c`.
//!
//! ## Wiring Path (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KeyExch)
//!         → implementations::all_exchange_descriptors()
//!           → implementations::exchange::descriptors()  (this module)
//!             ├── dh::descriptors()      (if feature "dh")
//!             ├── ecdh::descriptors()    (if feature "ec")
//!             ├── ecx::descriptors()     (if feature "ec")
//!             └── kdf::descriptors()     (always)
//! ```
//!
//! Each per-algorithm `descriptors()` returns the
//! [`AlgorithmDescriptor`](crate::traits::AlgorithmDescriptor) entries
//! consumed by the provider's algorithm registry to expose the corresponding
//! key-exchange algorithm through the EVP fetch path.

// ============================================================================
// Submodule declarations
// ============================================================================

/// DH (Diffie-Hellman) key exchange implementation.
///
/// Provides the [`DhExchange`] provider type registering classical
/// Finite-Field Diffie-Hellman key agreement under the canonical names
/// `"DH"` and `"dhKeyAgreement"` (RFC 3526 MODP groups, RFC 7919 FFDHE
/// groups, ANSI X9.42 KDF support).
///
/// Replaces C `providers/implementations/exchange/dh_exch.c` (529 lines).
///
/// Gated by Cargo feature `"dh"`, replacing the C preprocessor guard
/// `#ifndef OPENSSL_NO_DH` from `dh_exch.c:11`.
#[cfg(feature = "dh")]
pub mod dh;

/// ECDH (Elliptic Curve Diffie-Hellman) key exchange implementation.
///
/// Provides the [`EcdhExchange`] provider type registering ECDH key
/// agreement under the canonical name `"ECDH"` for Weierstrass curves
/// (NIST P-256/P-384/P-521 and the Koblitz curve secp256k1) with optional
/// cofactor mode (SP 800-56A r3 §5.7.1.2) and ANSI X9.63 KDF support.
///
/// Replaces C `providers/implementations/exchange/ecdh_exch.c` (639 lines).
///
/// Gated by Cargo feature `"ec"`, replacing the C preprocessor guard
/// `#ifndef OPENSSL_NO_EC` from `ecdh_exch.c:11`.
#[cfg(feature = "ec")]
pub mod ecdh;

/// ECX key exchange implementation (X25519, X448).
///
/// Provides the [`X25519Exchange`] and [`X448Exchange`] provider types
/// registering Montgomery-curve key exchange under the canonical names
/// `"X25519"` and `"X448"` (RFC 7748). The actual Montgomery-ladder
/// arithmetic lives in [`openssl_crypto::ec::curve25519`]; this module
/// merely wires it into the provider framework.
///
/// Replaces C `providers/implementations/exchange/ecx_exch.c` (240 lines).
///
/// Gated by Cargo feature `"ec"` (ECX is part of EC), replacing the C
/// preprocessor guard pair `#ifndef OPENSSL_NO_EC` /
/// `#ifndef OPENSSL_NO_ECX` from `ecx_exch.c`.
#[cfg(feature = "ec")]
pub mod ecx;

/// KDF-backed key exchange adapters (TLS1-PRF, HKDF, SCRYPT).
///
/// Provides the [`Tls1PrfExchange`], [`HkdfExchange`], and
/// [`ScryptExchange`] provider types registering Key Derivation Function
/// operations through the `KEYEXCH` provider interface for backward
/// compatibility with the TLS stack and the legacy EVP key derivation API.
///
/// Replaces C `providers/implementations/exchange/kdf_exch.c` (258 lines).
///
/// **Not feature-gated** — the TLS stack always requires the PRF and HKDF
/// adapters for handshake key schedule derivation. This mirrors the C
/// `kdf_exch.c` source file which has no `#ifndef OPENSSL_NO_*` outer
/// guard and is unconditionally compiled into the default provider.
pub mod kdf;

// ============================================================================
// Provider type re-exports
// ============================================================================
//
// Re-export the seven `KeyExchangeProvider` types at the module root for
// ergonomic access by `default.rs`, `legacy.rs`, the FIPS provider, and any
// downstream consumer that needs to instantiate a specific exchange
// algorithm without addressing the per-algorithm submodule directly.
//
// Each re-export carries the same feature gate as its source submodule so
// that the visibility surface tracks compilation availability — when an
// algorithm submodule is excluded by Cargo features, the corresponding
// re-export is also excluded, preventing compile-time references to
// items that do not exist.

/// Re-exported [`DhExchange`] provider type from the [`dh`] submodule.
///
/// Available only when the `"dh"` Cargo feature is enabled.
#[cfg(feature = "dh")]
pub use dh::DhExchange;

/// Re-exported [`EcdhExchange`] provider type from the [`ecdh`] submodule.
///
/// Available only when the `"ec"` Cargo feature is enabled.
#[cfg(feature = "ec")]
pub use ecdh::EcdhExchange;

/// Re-exported [`X25519Exchange`] and [`X448Exchange`] provider types from
/// the [`ecx`] submodule.
///
/// Available only when the `"ec"` Cargo feature is enabled.
#[cfg(feature = "ec")]
pub use ecx::{X25519Exchange, X448Exchange};

/// Re-exported [`Tls1PrfExchange`], [`HkdfExchange`], and [`ScryptExchange`]
/// provider types from the [`kdf`] submodule.
///
/// Always available (no feature gate) — the TLS stack relies on these
/// KDF adapters for handshake key schedule operations.
pub use kdf::{HkdfExchange, ScryptExchange, Tls1PrfExchange};

// ============================================================================
// Algorithm descriptor aggregation
// ============================================================================

use crate::traits::AlgorithmDescriptor;

/// Collects all key exchange algorithm descriptors from enabled submodules.
///
/// Called by
/// [`super::all_exchange_descriptors()`](super::all_exchange_descriptors)
/// — itself invoked from
/// `DefaultProvider::query_operation(OperationType::KeyExch)` — to enumerate
/// the available key exchange algorithms registered with the default
/// provider's algorithm registry. Replaces the C `deflt_keyexch[]` static
/// array from `providers/defltprov.c:414-430`.
///
/// # Aggregation Scheme
///
/// The function delegates to each per-algorithm submodule's `descriptors()`
/// helper rather than constructing entries inline. This guarantees that
/// every [`AlgorithmDescriptor`] tuple originates from the module whose
/// implementation it advertises (Rule R10 — wiring before done):
///
/// - [`dh::descriptors()`] — 1 entry (`"DH"` / `"dhKeyAgreement"`)
/// - [`ecdh::descriptors()`] — 1 entry (`"ECDH"`)
/// - [`ecx::descriptors()`] — 2 entries (`"X25519"`, `"X448"`)
/// - [`kdf::descriptors()`] — 3 entries (`"TLS1-PRF"`, `"HKDF"`, `"SCRYPT"`)
///
/// # Feature-Gated Composition
///
/// Each contribution is `#[cfg(feature = …)]`-gated to mirror the C
/// preprocessor guards in `defltprov.c`:
///
/// - DH descriptors are included only when feature `"dh"` is enabled
///   (replaces `#ifndef OPENSSL_NO_DH`).
/// - ECDH and ECX descriptors are included only when feature `"ec"` is
///   enabled (replaces the nested `#ifndef OPENSSL_NO_EC` /
///   `#ifndef OPENSSL_NO_ECX` guards).
/// - KDF descriptors are always included — the TLS handshake requires
///   PRF/HKDF unconditionally.
///
/// # Returns
///
/// A [`Vec<AlgorithmDescriptor>`] containing descriptors for every enabled
/// key exchange algorithm. The vector is non-empty whenever the workspace
/// is built with any default-on feature set; it is empty only in the
/// degenerate configuration where every category feature is disabled.
///
/// # Rule R5 (Nullability over Sentinels)
///
/// Returns an empty [`Vec`] rather than `None`/`null`/`-1` when no
/// algorithms are enabled. The empty-vector case is observable but never
/// signalled via a sentinel value.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_provider::implementations::exchange;
///
/// // Default features expose ECDH, X25519, X448, TLS1-PRF, HKDF, SCRYPT.
/// let descs = exchange::descriptors();
/// assert!(!descs.is_empty());
/// assert!(descs.iter().any(|d| d.names.contains(&"X25519")));
/// assert!(descs.iter().any(|d| d.names.contains(&"HKDF")));
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs: Vec<AlgorithmDescriptor> = Vec::new();

    // DH — `#ifndef OPENSSL_NO_DH` (`defltprov.c:415-417`).
    #[cfg(feature = "dh")]
    descs.extend(dh::descriptors());

    // ECDH — outer `#ifndef OPENSSL_NO_EC` (`defltprov.c:418-419`).
    #[cfg(feature = "ec")]
    descs.extend(ecdh::descriptors());

    // X25519 / X448 — nested `#ifndef OPENSSL_NO_ECX`
    // (`defltprov.c:420-423`). ECX is part of EC.
    #[cfg(feature = "ec")]
    descs.extend(ecx::descriptors());

    // TLS1-PRF / HKDF / SCRYPT — unconditional in `defltprov.c:425-428`.
    descs.extend(kdf::descriptors());

    descs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code may unwrap on infallible invariants"
)]
mod tests {
    use super::*;

    /// `descriptors()` returns at least the unconditional KDF adapters.
    ///
    /// The KDF-backed exchanges (TLS1-PRF, HKDF, SCRYPT) are not
    /// feature-gated and therefore always present in the aggregate set
    /// regardless of which classical/EC features are enabled.
    #[test]
    fn descriptors_includes_kdf_adapters() {
        let descs = descriptors();
        assert!(
            descs.iter().any(|d| d.names.contains(&"TLS1-PRF")),
            "TLS1-PRF descriptor must always be present"
        );
        assert!(
            descs.iter().any(|d| d.names.contains(&"HKDF")),
            "HKDF descriptor must always be present"
        );
        assert!(
            descs.iter().any(|d| d.names.contains(&"SCRYPT")),
            "SCRYPT descriptor must always be present"
        );
    }

    /// `descriptors()` includes DH only when feature `"dh"` is enabled.
    #[cfg(feature = "dh")]
    #[test]
    fn descriptors_includes_dh_when_feature_enabled() {
        let descs = descriptors();
        assert!(
            descs.iter().any(|d| d.names.contains(&"DH")),
            "DH descriptor must be present when `dh` feature is enabled"
        );
    }

    /// `descriptors()` includes ECDH and ECX entries when feature `"ec"` is
    /// enabled.
    #[cfg(feature = "ec")]
    #[test]
    fn descriptors_includes_ecdh_and_ecx_when_ec_enabled() {
        let descs = descriptors();
        assert!(
            descs.iter().any(|d| d.names.contains(&"ECDH")),
            "ECDH descriptor must be present when `ec` feature is enabled"
        );
        assert!(
            descs.iter().any(|d| d.names.contains(&"X25519")),
            "X25519 descriptor must be present when `ec` feature is enabled"
        );
        assert!(
            descs.iter().any(|d| d.names.contains(&"X448")),
            "X448 descriptor must be present when `ec` feature is enabled"
        );
    }

    /// All descriptor entries advertise the default-provider property
    /// query string (`"provider=default"`), matching the C dispatch table
    /// rows in `providers/defltprov.c`.
    #[test]
    fn all_descriptors_advertise_default_provider_property() {
        for d in descriptors() {
            assert_eq!(
                d.property, "provider=default",
                "every exchange descriptor must declare provider=default"
            );
            assert!(
                !d.names.is_empty(),
                "every descriptor must register at least one canonical name"
            );
            assert!(
                !d.description.is_empty(),
                "every descriptor must carry a non-empty human description"
            );
        }
    }

    /// With the default feature set (`exchange`, `ec`, kdf-always-on but
    /// **not** `dh`), `descriptors()` returns six entries: ECDH + X25519 +
    /// X448 + TLS1-PRF + HKDF + SCRYPT.
    ///
    /// When the `"dh"` feature is additionally enabled, the aggregate
    /// expands to seven entries (the AAP §0.5.1 / §0.7.1 reference count).
    #[test]
    fn descriptor_count_matches_enabled_feature_set() {
        let descs = descriptors();

        // KDF adapters — 3 entries, always present.
        let mut expected = 3_usize;

        // ECDH + ECX — 1 + 2 = 3 entries when `ec` is enabled.
        #[cfg(feature = "ec")]
        {
            expected += 3;
        }

        // DH — 1 entry when `dh` is enabled.
        #[cfg(feature = "dh")]
        {
            expected += 1;
        }

        assert_eq!(
            descs.len(),
            expected,
            "descriptor aggregate count must match the enabled feature set"
        );
    }
}
