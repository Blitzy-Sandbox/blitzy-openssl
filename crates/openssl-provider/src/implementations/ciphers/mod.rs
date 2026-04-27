//! # Symmetric Cipher Provider Implementations
//!
//! Rust translation of `providers/implementations/ciphers/` (81 C source files).
//! Contains all symmetric cipher algorithm implementations that implement the
//! `CipherProvider` trait from `crate::traits`.
//!
//! ## Module Organization
//!
//! | Module | Algorithm | C Source Files | Key Sizes |
//! |--------|-----------|---------------|-----------|
//! | `common` | Shared infrastructure | `ciphercommon*.c` (8 files) | — |
//! | `aes` | AES ECB/CBC/OFB/CFB/CTR/CTS | `cipher_aes*.c` (4 files) | 128/192/256 |
//! | `aes_gcm` | AES-GCM AEAD | `cipher_aes_gcm*.c` + `ciphercommon_gcm*.c` | 128/192/256 |
//! | `aes_ccm` | AES-CCM AEAD | `cipher_aes_ccm*.c` + `ciphercommon_ccm*.c` | 128/192/256 |
//! | `aes_ocb` | AES-OCB AEAD | `cipher_aes_ocb*.c` | 128/192/256 |
//! | `aes_siv` | AES-SIV / AES-GCM-SIV | `cipher_aes_siv*.c` + `cipher_aes_gcm_siv*.c` | 128/192/256 |
//! | `aes_xts` | AES-XTS | `cipher_aes_xts*.c` | 128/256 |
//! | `aes_wrap` | AES Key Wrap | `cipher_aes_wrp.c` | 128/192/256 |
//! | `aes_cbc_hmac` | AES-CBC-HMAC composite | `cipher_aes_cbc_hmac*.c` (7 files) | 128/256 |
//! | `chacha20` | ChaCha20 / ChaCha20-Poly1305 | `cipher_chacha20*.c` (4 files) | 256 |
//! | `des` | DES / 3DES / DESX / TDES Wrap | `cipher_des*.c` + `cipher_tdes*.c` (11 files) | 64/128/192 |
//! | `camellia` | Camellia | `cipher_camellia*.c` (3 files) | 128/192/256 |
//! | `aria` | ARIA + GCM/CCM | `cipher_aria*.c` (6 files) | 128/192/256 |
//! | `sm4` | SM4 + GCM/CCM/XTS | `cipher_sm4*.c` (8 files) | 128 |
//! | `null` | NULL cipher | `cipher_null.c` | 0 |
//! | `legacy` | BF/CAST5/IDEA/SEED/RC2/RC4/RC5 | 16+ C files | variable |
//!
//! ## Architecture
//!
//! - Each cipher struct implements `CipherProvider` from `crate::traits`
//! - Actual crypto operations delegate to `openssl-crypto::symmetric::*`
//! - Zero unsafe code — all operations through safe Rust APIs (Rule R8)
//! - Feature flags gate algorithm availability (replacing C `OPENSSL_NO_*`)
//!
//! ## Wiring Path (Rule R10)
//!
//! Every implementation is reachable from the entry point:
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(OperationType::Cipher)
//!         → implementations::all_cipher_descriptors()
//!           → ciphers::descriptors()
//!             → [aes|aes_gcm|aes_ccm|...|null]::descriptors()
//! ```
//!
//! ## Expected Algorithm Count (~154 total)
//!
//! - AES core modes (ECB/CBC/OFB/CFB/CTR/CTS): 24 (8 modes × 3 key sizes)
//! - AES-GCM: 3 (128/192/256)
//! - AES-CCM: 3 (128/192/256)
//! - AES-OCB: 3 (128/192/256)
//! - AES-SIV + GCM-SIV: 5
//! - AES-XTS: 2 (128/256)
//! - AES Key Wrap: 12 (4 variants × 3 key sizes)
//! - AES-CBC-HMAC-SHA: ~10
//! - ChaCha20 / ChaCha20-Poly1305: 2
//! - DES/3DES/DESX/TDES-Wrap: ~17
//! - Camellia: 18
//! - ARIA + GCM/CCM: 21
//! - SM4 + GCM/CCM/XTS: 8
//! - NULL: 1
//! - Legacy (BF/CAST5/IDEA/SEED/RC2/RC4/RC5): ~25
//!
//! ## Feature Flags
//!
//! Per-cipher feature flags replace C `OPENSSL_NO_*` compile-time guards:
//!
//! | Feature | Modules Gated | C Equivalent |
//! |---------|--------------|--------------|
//! | `aes` | `aes`, `aes_gcm`, `aes_ccm`, `aes_xts`, `aes_wrap`, `aes_cbc_hmac`, `aes_siv` | `OPENSSL_NO_AES` |
//! | `ocb` | `aes_ocb` | `OPENSSL_NO_OCB` |
//! | `chacha` | `chacha20` | `OPENSSL_NO_CHACHA` |
//! | `des` | `des` | `OPENSSL_NO_DES` |
//! | `camellia` | `camellia` | `OPENSSL_NO_CAMELLIA` |
//! | `aria` | `aria` | `OPENSSL_NO_ARIA` |
//! | `sm4` | `sm4` | `OPENSSL_NO_SM4` |
//! | `legacy` | `legacy` | `OPENSSL_NO_DEPRECATED` |
//!
//! The `common` and `null` modules are always available (no feature gate).
//! All per-cipher features are enabled by default when `ciphers` is active.

use crate::traits::AlgorithmDescriptor;

// =============================================================================
// Submodule Declarations
// =============================================================================
//
// Each submodule corresponds to a cipher family or shared infrastructure.
// Feature gates match the per-cipher features defined in the parent crate's
// Cargo.toml, mirroring the C preprocessor OPENSSL_NO_* guards.

/// Shared cipher infrastructure: modes, flags, IV generation, padding,
/// AEAD state machines, parameter keys, and helper functions.
///
/// This module is always available (not feature-gated) because all cipher
/// implementations depend on its types and utilities. Translates the C
/// `ciphercommon.c`, `ciphercommon_hw.c`, `ciphercommon_block.c`,
/// `ciphercommon_gcm.c`, `ciphercommon_ccm.c`, and related files.
pub mod common;

/// AES cipher implementations for ECB, CBC, OFB, CFB, CTR, and CTS modes.
///
/// Supports key sizes: 128, 192, 256 bits.
/// Translates C `cipher_aes.c` and `cipher_aes_hw.c`.
///
/// **Feature gate:** `aes` (replaces `OPENSSL_NO_AES`)
#[cfg(feature = "aes")]
pub mod aes;

/// AES-GCM (Galois/Counter Mode) AEAD cipher.
///
/// Supports key sizes: 128, 192, 256 bits.
/// Translates C `cipher_aes_gcm.c` and `cipher_aes_gcm_hw.c`.
///
/// **Feature gate:** `aes` (GCM depends on AES availability)
#[cfg(feature = "aes")]
pub mod aes_gcm;

/// AES-CCM (Counter with CBC-MAC) AEAD cipher.
///
/// Supports key sizes: 128, 192, 256 bits.
/// Translates C `cipher_aes_ccm.c` and `cipher_aes_ccm_hw.c`.
///
/// **Feature gate:** `aes` (CCM depends on AES availability)
#[cfg(feature = "aes")]
pub mod aes_ccm;

/// AES-OCB (Offset Codebook Mode) AEAD cipher.
///
/// Supports key sizes: 128, 192, 256 bits.
/// Translates C `cipher_aes_ocb.c` and `cipher_aes_ocb_hw.c`.
///
/// **Feature gate:** `ocb` (separate from `aes` due to patent considerations)
#[cfg(feature = "ocb")]
pub mod aes_ocb;

/// AES-SIV (Synthetic Initialization Vector) and AES-GCM-SIV ciphers.
///
/// AES-SIV provides nonce-misuse resistance. AES-GCM-SIV provides
/// nonce-misuse resistant authenticated encryption with faster performance
/// than standard AES-SIV. Supports key sizes: 128, 192, 256 bits.
/// Translates C `cipher_aes_siv.c` and `cipher_aes_gcm_siv.c`.
///
/// **Feature gate:** `aes` (SIV/GCM-SIV depend on AES availability)
#[cfg(feature = "aes")]
pub mod aes_siv;

/// AES-XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing).
///
/// Designed for disk encryption. Supports key sizes: 128, 256 bits
/// (using 256 or 512 bit combined keys for tweak + encryption).
/// Translates C `cipher_aes_xts.c` and `cipher_aes_xts_hw.c`.
///
/// **Feature gate:** `aes` (XTS depends on AES availability)
#[cfg(feature = "aes")]
pub mod aes_xts;

/// AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649).
///
/// Supports key sizes: 128, 192, 256 bits for wrapping and unwrapping.
/// Translates C `cipher_aes_wrp.c`.
///
/// **Feature gate:** `aes` (Key Wrap depends on AES availability)
#[cfg(feature = "aes")]
pub mod aes_wrap;

/// AES-CBC-HMAC-SHA composite cipher for TLS record encryption.
///
/// Provides encrypt-then-MAC or MAC-then-encrypt (legacy) authenticated
/// encryption combining AES-CBC with HMAC-SHA1 or HMAC-SHA256.
/// Supports key sizes: 128, 256 bits.
/// Translates C `cipher_aes_cbc_hmac_sha.c` and related files.
///
/// **Feature gate:** `aes` (depends on AES availability)
#[cfg(feature = "aes")]
pub mod aes_cbc_hmac;

/// ChaCha20 stream cipher and ChaCha20-Poly1305 AEAD.
///
/// ChaCha20 uses a 256-bit key. ChaCha20-Poly1305 combines the ChaCha20
/// stream cipher with Poly1305 MAC for authenticated encryption (RFC 8439).
/// Translates C `cipher_chacha20.c` and `cipher_chacha20_poly1305.c`.
///
/// **Feature gate:** `chacha` (replaces `OPENSSL_NO_CHACHA`)
#[cfg(feature = "chacha")]
pub mod chacha20;

/// DES, Triple DES (3DES/TDES), DESX, and TDES Key Wrap ciphers.
///
/// DES: 64-bit key (56 effective). 3DES: 128/192-bit keys (112/168 effective).
/// DESX: DES with additional whitening keys. TDES Wrap: RFC 3217 key wrapping.
/// Translates C `cipher_des.c`, `cipher_tdes_*.c`, `cipher_desx.c`,
/// and `cipher_tdes_wrap.c`.
///
/// **Feature gate:** `des` (replaces `OPENSSL_NO_DES`)
#[cfg(feature = "des")]
pub mod des;

/// Camellia block cipher in ECB, CBC, OFB, CFB, CTR, and CTS modes.
///
/// Supports key sizes: 128, 192, 256 bits. Camellia is a NESSIE and
/// CRYPTREC recommended cipher. Translates C `cipher_camellia.c`
/// and `cipher_camellia_hw.c`.
///
/// **Feature gate:** `camellia` (replaces `OPENSSL_NO_CAMELLIA`)
#[cfg(feature = "camellia")]
pub mod camellia;

/// ARIA block cipher in ECB, CBC, OFB, CFB, CTR modes, plus ARIA-GCM
/// and ARIA-CCM AEAD modes.
///
/// ARIA is a South Korean national standard (KS X 1213 / RFC 5794).
/// Supports key sizes: 128, 192, 256 bits.
/// Translates C `cipher_aria.c`, `cipher_aria_gcm.c`, `cipher_aria_ccm.c`,
/// and related hardware acceleration files.
///
/// **Feature gate:** `aria` (replaces `OPENSSL_NO_ARIA`)
#[cfg(feature = "aria")]
pub mod aria;

/// SM4 block cipher in ECB, CBC, OFB, CFB, CTR modes, plus SM4-GCM,
/// SM4-CCM, and SM4-XTS modes.
///
/// SM4 is a Chinese national standard (GB/T 32907-2016). Uses a fixed
/// 128-bit key size. Translates C `cipher_sm4.c`, `cipher_sm4_gcm.c`,
/// `cipher_sm4_ccm.c`, `cipher_sm4_xts.c`, and related files.
///
/// **Feature gate:** `sm4` (replaces `OPENSSL_NO_SM4`)
#[cfg(feature = "sm4")]
pub mod sm4;

/// NULL cipher — a pass-through cipher that performs no encryption.
///
/// Used as a diagnostic tool and for TLS connections that require
/// authentication without confidentiality. Always available (no feature gate).
/// Translates C `cipher_null.c`.
pub mod null;

/// Legacy cipher implementations: Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5.
///
/// These ciphers are deprecated and provided only for backward compatibility
/// with legacy applications. They are registered with `provider=legacy`
/// property and require explicit legacy provider activation.
/// Translates C `cipher_blowfish.c`, `cipher_cast5.c`, `cipher_idea.c`,
/// `cipher_seed.c`, `cipher_rc2.c`, `cipher_rc4.c`, `cipher_rc5.c`,
/// and related files.
///
/// **Feature gate:** `legacy` (replaces `OPENSSL_NO_DEPRECATED`)
#[cfg(feature = "legacy")]
pub mod legacy;

// =============================================================================
// Re-exports from common module
// =============================================================================
//
// Re-export the most commonly used types from the `common` submodule at the
// `ciphers` module level for ergonomic access. Users can access these types
// as both `ciphers::CipherMode` and `ciphers::common::CipherMode`.

/// Symmetric cipher operating modes — re-exported from [`common::CipherMode`].
pub use common::CipherMode;

/// Cipher capability flags — re-exported from [`common::CipherFlags`].
pub use common::CipherFlags;

/// IV generation strategies — re-exported from [`common::IvGeneration`].
pub use common::IvGeneration;

/// Cipher parameter key constants — re-exported from [`common::param_keys`].
pub use common::param_keys;

// =============================================================================
// Aggregate Descriptor Functions
// =============================================================================
//
// These functions collect cipher algorithm descriptors from ALL enabled
// cipher submodules. They are called by the parent module's
// `all_cipher_descriptors()` function, which is in turn called by
// `DefaultProvider::query_operation(OperationType::Cipher)`.
//
// The separation into `descriptors()` (default provider) and
// `legacy_descriptors()` (legacy provider) mirrors the C codebase where
// `defltprov.c` and `legacyprov.c` maintain separate `OSSL_ALGORITHM[]`
// dispatch tables.

/// Returns all cipher algorithm descriptors from enabled cipher modules.
///
/// Called during provider registration to enumerate all available cipher
/// algorithms for the **default provider**. Feature flags control which
/// algorithm families are included, matching C `OPENSSL_NO_*` compile-time
/// guards.
///
/// This function aggregates descriptors from every feature-enabled cipher
/// submodule into a single flat list suitable for provider dispatch table
/// registration.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all cipher
/// implementations enabled by the current feature configuration. With all
/// features enabled, this returns approximately 129 descriptors (all
/// ciphers excluding legacy).
///
/// # Wiring Path (Rule R10)
///
/// ```text
/// DefaultProvider::query_operation(OperationType::Cipher)
///   → implementations::all_cipher_descriptors()
///     → ciphers::descriptors()  // this function
///       → null::descriptors()
///       → aes::descriptors()         [if feature = "aes"]
///       → aes_gcm::descriptors()     [if feature = "aes"]
///       → aes_ccm::descriptors()     [if feature = "aes"]
///       → aes_ocb::descriptors()     [if feature = "ocb"]
///       → aes_siv::descriptors()     [if feature = "aes"]
///       → aes_xts::descriptors()     [if feature = "aes"]
///       → aes_wrap::descriptors()    [if feature = "aes"]
///       → aes_cbc_hmac::descriptors()[if feature = "aes"]
///       → chacha20::descriptors()    [if feature = "chacha"]
///       → des::descriptors()         [if feature = "des"]
///       → camellia::descriptors()    [if feature = "camellia"]
///       → aria::descriptors()        [if feature = "aria"]
///       → sm4::descriptors()         [if feature = "sm4"]
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();

    // NULL cipher — always available, no feature gate
    descs.extend(null::descriptors());

    // AES family — gated behind "aes" feature
    #[cfg(feature = "aes")]
    {
        descs.extend(aes::descriptors());
        descs.extend(aes_gcm::descriptors());
        descs.extend(aes_ccm::descriptors());
        descs.extend(aes_siv::descriptors());
        descs.extend(aes_xts::descriptors());
        descs.extend(aes_wrap::descriptors());
        descs.extend(aes_cbc_hmac::descriptors());
    }

    // AES-OCB — separate feature due to patent considerations
    #[cfg(feature = "ocb")]
    descs.extend(aes_ocb::descriptors());

    // ChaCha20 / ChaCha20-Poly1305
    #[cfg(feature = "chacha")]
    descs.extend(chacha20::descriptors());

    // DES / 3DES / DESX / TDES Wrap
    #[cfg(feature = "des")]
    descs.extend(des::descriptors());

    // Camellia (ECB/CBC/OFB/CFB/CTR/CTS)
    #[cfg(feature = "camellia")]
    descs.extend(camellia::descriptors());

    // ARIA (ECB/CBC/OFB/CFB/CTR + GCM/CCM)
    #[cfg(feature = "aria")]
    descs.extend(aria::descriptors());

    // SM4 (ECB/CBC/OFB/CFB/CTR + GCM/CCM/XTS)
    #[cfg(feature = "sm4")]
    descs.extend(sm4::descriptors());

    descs
}

/// Returns cipher descriptors for the **legacy provider** only.
///
/// These are deprecated ciphers maintained solely for backward compatibility
/// with legacy applications. They are NOT included in the default provider's
/// cipher list. Legacy ciphers are tagged with `property = "provider=legacy"`
/// and require explicit activation of the legacy provider.
///
/// Legacy ciphers include: Blowfish, CAST5, IDEA, SEED, RC2, RC4, RC5.
///
/// # Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all legacy cipher
/// implementations (approximately 25 descriptors covering all mode/key-size
/// variants).
///
/// # Wiring Path (Rule R10)
///
/// ```text
/// LegacyProvider::query_operation(OperationType::Cipher)
///   → implementations::all_legacy_cipher_descriptors()
///     → ciphers::legacy_descriptors()  // this function
///       → legacy::descriptors()
/// ```
#[cfg(feature = "legacy")]
#[must_use]
pub fn legacy_descriptors() -> Vec<AlgorithmDescriptor> {
    legacy::descriptors()
}

// =============================================================================
// Module-Level Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `descriptors()` returns a non-empty list when at least
    /// the null cipher is available (which is always the case since `null`
    /// has no feature gate).
    #[test]
    fn descriptors_includes_null_cipher() {
        let descs = descriptors();
        // The null cipher is always present since it has no feature gate
        assert!(
            descs.iter().any(|d| d.names.contains(&"NULL")),
            "NULL cipher must always be present in descriptors"
        );
    }

    /// Verify that `descriptors()` returns non-empty results.
    #[test]
    fn descriptors_returns_non_empty() {
        let descs = descriptors();
        // At minimum, the null cipher is always included
        assert!(!descs.is_empty(), "descriptors() must return at least the NULL cipher");
    }

    /// Verify that all descriptors have non-empty names.
    #[test]
    fn all_descriptors_have_valid_names() {
        let descs = descriptors();
        for desc in &descs {
            assert!(!desc.names.is_empty(), "Every descriptor must have at least one name");
            for name in &desc.names {
                assert!(!name.is_empty(), "Algorithm names must not be empty strings");
            }
        }
    }

    /// Verify that all descriptors have non-empty property strings.
    #[test]
    fn all_descriptors_have_valid_properties() {
        let descs = descriptors();
        for desc in &descs {
            assert!(
                !desc.property.is_empty(),
                "Descriptor for {:?} must have a non-empty property string",
                desc.names
            );
        }
    }

    /// Verify that all descriptors have non-empty description strings.
    #[test]
    fn all_descriptors_have_valid_descriptions() {
        let descs = descriptors();
        for desc in &descs {
            assert!(
                !desc.description.is_empty(),
                "Descriptor for {:?} must have a non-empty description",
                desc.names
            );
        }
    }

    /// Verify that no duplicate algorithm names appear across all descriptors.
    #[test]
    fn no_duplicate_algorithm_names() {
        let descs = descriptors();
        let mut seen_names = std::collections::HashSet::new();
        for desc in &descs {
            for name in &desc.names {
                assert!(
                    seen_names.insert(*name),
                    "Duplicate algorithm name found: {name}"
                );
            }
        }
    }

    /// Verify that legacy descriptors are separate from default descriptors.
    #[cfg(feature = "legacy")]
    #[test]
    fn legacy_descriptors_are_separate() {
        let default_descs = descriptors();
        let legacy_descs = legacy_descriptors();

        // Legacy descriptors should not be empty when feature is enabled
        assert!(
            !legacy_descs.is_empty(),
            "legacy_descriptors() should return non-empty list when 'legacy' feature is enabled"
        );

        // Legacy descriptors should use "provider=legacy" property
        for desc in &legacy_descs {
            assert_eq!(
                desc.property, "provider=legacy",
                "Legacy descriptor {:?} must use 'provider=legacy' property",
                desc.names
            );
        }

        // Default and legacy names should not overlap
        let default_names: std::collections::HashSet<&str> = default_descs
            .iter()
            .flat_map(|d| d.names.iter().copied())
            .collect();
        for desc in &legacy_descs {
            for name in &desc.names {
                assert!(
                    !default_names.contains(name),
                    "Legacy algorithm name '{name}' must not overlap with default descriptors"
                );
            }
        }
    }
}
