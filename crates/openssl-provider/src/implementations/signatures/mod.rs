//! # Digital Signature Provider Implementations
//!
//! Contains all concrete digital signature algorithm implementations for the
//! OpenSSL Rust provider system. Each submodule implements one signature algorithm
//! family, translating from the corresponding C source in
//! `providers/implementations/signature/`.
//!
//! ## Algorithm Families
//!
//! | Module | C Source | Algorithm | Standards |
//! |--------|----------|-----------|-----------|
//! | `rsa` | `rsa_sig.c` (2,087 lines) | RSA PKCS#1 v1.5, PSS | PKCS#1, RFC 8017 |
//! | `dsa` | `dsa_sig.c` (1,069 lines) | DSA | FIPS 186-4 |
//! | `ecdsa` | `ecdsa_sig.c` (1,083 lines) | ECDSA | FIPS 186-4, ANSI X9.62 |
//! | `eddsa` | `eddsa_sig.c` (1,187 lines) | Ed25519, Ed448 | RFC 8032 |
//! | `sm2` | `sm2_sig.c` (593 lines) | SM2 | GB/T 32918.2-2016 |
//! | `ml_dsa` | `ml_dsa_sig.c` (510 lines) | ML-DSA-44/65/87 | FIPS 204 |
//! | `slh_dsa` | `slh_dsa_sig.c` (390 lines) | SLH-DSA (12 variants) | FIPS 205 |
//! | `lms` | `lms_signature.c` (168 lines) | LMS (verify only) | SP 800-208 |
//! | `mac_legacy` | `mac_legacy_sig.c` (253 lines) | MAC-as-signature adapter | — |
//!
//! ## Architecture
//!
//! Each algorithm struct implements `SignatureProvider` from `crate::traits` and
//! creates `SignatureContext` instances for per-operation state. The pattern
//! matches the C `OSSL_FUNC_signature_*` dispatch interface:
//!
//! - `newctx()` → `SignatureProvider::new_ctx()` → owns `SignatureContext`
//! - `sign_init()`/`verify_init()` → `SignatureContext::sign_init()`/`SignatureContext::verify_init()`
//! - `sign()`/`verify()` → one-shot operations
//! - `digest_sign_init/update/final()` → streaming digest-sign
//! - `digest_verify_init/update/final()` → streaming digest-verify
//! - `freectx()` → Rust `Drop` trait (RAII)
//! - `dupctx()` → `Clone` equivalent on the context
//!
//! ## Feature Gating
//!
//! Algorithm availability is controlled by Cargo feature flags, replacing C
//! `OPENSSL_NO_*` preprocessor guards:
//!
//! - `#[cfg(feature = "rsa")]` — RSA signatures (PKCS#1 v1.5, PSS)
//! - `#[cfg(feature = "dsa")]` — DSA signatures (FIPS 186-4)
//! - `#[cfg(feature = "ec")]` — ECDSA and EdDSA (P-curves, Ed25519, Ed448)
//! - `#[cfg(feature = "sm2")]` — SM2 (non-FIPS, GB/T 32918.2-2016)
//! - `#[cfg(feature = "ml-dsa")]` — ML-DSA post-quantum (FIPS 204)
//! - `#[cfg(feature = "slh-dsa")]` — SLH-DSA post-quantum (FIPS 205)
//! - `#[cfg(feature = "lms")]` — LMS hash-based verification (SP 800-208)
//! - MAC legacy adapter: always available (wraps existing MAC implementations)
//!
//! ## Entry Point Reachability (Rule R10)
//!
//! ```text
//! openssl_cli::main()
//!   → provider loading
//!   → DefaultProvider::query_operation(OperationType::Signature)
//!   → implementations::all_signature_descriptors()
//!   → signatures::descriptors()
//! ```

// Re-export commonly used types from crate::traits for convenience access
// by consumer modules and downstream crates.
pub use crate::traits::{AlgorithmDescriptor, SignatureContext, SignatureProvider};

// Import the helper function for constructing AlgorithmDescriptor instances.
use super::algorithm;

// =============================================================================
// Submodule Declarations
// =============================================================================
//
// Each submodule corresponds to one C source file in
// `providers/implementations/signature/` and is feature-gated to replace
// the C `OPENSSL_NO_*` preprocessor guards.

/// RSA PKCS#1 v1.5 and PSS signatures.
///
/// Translates `providers/implementations/signature/rsa_sig.c` (2,087 lines).
/// Supports both raw sign/verify and composite digest-sign/digest-verify flows
/// with configurable padding mode (PKCS#1 v1.5, PSS) and salt length.
///
/// Registered names in `defltprov.c`: `PROV_NAMES_RSA` with fixed sigalg
/// tables (RSA-SHA1, RSA-SHA256, RSA-SHA384, RSA-SHA512, etc.).
#[cfg(feature = "rsa")]
pub mod rsa;

/// DSA digital signatures (FIPS 186-4).
///
/// Translates `providers/implementations/signature/dsa_sig.c` (1,069 lines).
/// Implements sign/verify with configurable hash algorithm. Supports both
/// pre-hashed data and composite digest-sign/digest-verify flows.
///
/// Registered names in `defltprov.c`: `PROV_NAMES_DSA` with fixed sigalg tables.
#[cfg(feature = "dsa")]
pub mod dsa;

/// ECDSA digital signatures for NIST P-curves and Brainpool curves.
///
/// Translates `providers/implementations/signature/ecdsa_sig.c` (1,083 lines).
/// Supports configurable hash algorithm and curve selection for sign/verify
/// operations on elliptic curve keys.
///
/// Registered names in `defltprov.c`: `PROV_NAMES_ECDSA` with fixed sigalg
/// tables for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-* variants.
#[cfg(feature = "ec")]
pub mod ecdsa;

/// EdDSA signatures (Ed25519, Ed448, with pure/prehash/context variants).
///
/// Translates `providers/implementations/signature/eddsa_sig.c` (1,187 lines).
/// Supports five distinct EdDSA instances:
/// - Ed25519 (pure), Ed25519ph (prehash), Ed25519ctx (with context)
/// - Ed448 (pure), Ed448ph (prehash)
///
/// Registered names in `defltprov.c`: `PROV_NAMES_ED25519`, `PROV_NAMES_ED25519ph`,
/// `PROV_NAMES_ED25519ctx`, `PROV_NAMES_ED448`, `PROV_NAMES_ED448ph`.
#[cfg(feature = "ec")]
pub mod eddsa;

/// SM2 Chinese national standard signatures (GB/T 32918.2-2016).
///
/// Translates `providers/implementations/signature/sm2_sig.c` (593 lines).
/// Implements the SM2 digital signature algorithm using SM3 hash by default.
/// Feature-gated as non-FIPS algorithm.
///
/// Registered names in `defltprov.c`: `PROV_NAMES_SM2`.
#[cfg(feature = "sm2")]
pub mod sm2;

/// ML-DSA (FIPS 204) post-quantum lattice-based digital signatures.
///
/// Translates `providers/implementations/signature/ml_dsa_sig.c` (510 lines).
/// Supports three security levels: ML-DSA-44 (cat 2), ML-DSA-65 (cat 3),
/// ML-DSA-87 (cat 5).
///
/// Registered names in `defltprov.c`: `PROV_NAMES_ML_DSA_44`,
/// `PROV_NAMES_ML_DSA_65`, `PROV_NAMES_ML_DSA_87`.
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

/// SLH-DSA (FIPS 205) post-quantum hash-based digital signatures.
///
/// Translates `providers/implementations/signature/slh_dsa_sig.c` (390 lines).
/// Supports 12 parameter set variants across SHA-2 and SHAKE hash families,
/// each with small (s) and fast (f) signing modes at three security levels
/// (128, 192, 256 bits).
///
/// Registered names in `defltprov.c`: `PROV_NAMES_SLH_DSA_SHA2_128S`,
/// `PROV_NAMES_SLH_DSA_SHA2_128F`, through `PROV_NAMES_SLH_DSA_SHAKE_256F`.
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

/// LMS hash-based signature verification (SP 800-208, verify-only).
///
/// Translates `providers/implementations/signature/lms_signature.c` (168 lines).
/// LMS is a stateful hash-based signature scheme; this provider implementation
/// supports **verification only** — signing is handled externally.
///
/// Registered names in `defltprov.c`: `PROV_NAMES_LMS`.
#[cfg(feature = "lms")]
pub mod lms;

/// MAC-as-signature legacy adapter (HMAC, SipHash, Poly1305, CMAC).
///
/// Translates `providers/implementations/signature/mac_legacy_sig.c` (253 lines).
/// Wraps existing MAC implementations to provide a signature-compatible
/// interface for legacy protocols that use MACs in a signature role.
///
/// Always available (no feature gate) because it delegates to the MAC provider
/// implementations which are independently gated.
///
/// Registered names in `defltprov.c`: `PROV_NAMES_HMAC`, `PROV_NAMES_SIPHASH`,
/// `PROV_NAMES_POLY1305`, `PROV_NAMES_CMAC`.
pub mod mac_legacy;

// =============================================================================
// Shared Types
// =============================================================================

/// Operation mode for signature contexts.
///
/// Identifies whether a signature context is performing a sign, verify, or
/// verify-recover operation. Set during `sign_init()`/`verify_init()` and
/// used by the context to enforce correct method sequencing.
///
/// Replaces the C `operation` field from signature context structs which used
/// `EVP_PKEY_OP_SIGN`, `EVP_PKEY_OP_VERIFY`, `EVP_PKEY_OP_VERIFYRECOVER`
/// integer constants from `include/openssl/evp.h`.
///
/// Rule R5: Uses an enum instead of integer sentinel values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMode {
    /// Signing operation — produces a digital signature from input data
    /// using a private key.
    Sign,
    /// Verification operation — validates a digital signature against input
    /// data using a public key.
    Verify,
    /// Verify-recover operation — recovers the original message from the
    /// signature (RSA PKCS#1 v1.5 only). Not supported by all algorithms.
    VerifyRecover,
}

// =============================================================================
// Algorithm Descriptor Registration
// =============================================================================

/// Returns all available signature algorithm descriptors for provider
/// registration.
///
/// Called by [`super::all_signature_descriptors()`] (which is invoked by
/// `DefaultProvider::query_operation(OperationType::Signature)`) to enumerate
/// all signature algorithms. Each algorithm family contributes its descriptors
/// conditionally based on enabled features.
///
/// This replaces the role of the `deflt_signature[]` static array in
/// `providers/defltprov.c` (lines 444–540) which enumerated all
/// `ossl_*_signature_functions` dispatch tables.
///
/// # Returns
///
/// A [`Vec<AlgorithmDescriptor>`] containing descriptors for every enabled
/// signature algorithm variant. The vector may be empty if all signature
/// features are disabled.
///
/// # Example
///
/// ```rust,ignore
/// use openssl_provider::implementations::signatures;
///
/// let descs = signatures::descriptors();
/// // At minimum, mac_legacy descriptors are always present
/// assert!(!descs.is_empty());
/// ```
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();

    // --- Classical signatures ---

    #[cfg(feature = "rsa")]
    descs.extend(rsa::descriptors());

    #[cfg(feature = "dsa")]
    descs.extend(dsa::descriptors());

    #[cfg(feature = "ec")]
    descs.extend(ecdsa::descriptors());

    #[cfg(feature = "ec")]
    descs.extend(eddsa::descriptors());

    #[cfg(feature = "sm2")]
    descs.extend(sm2::descriptors());

    // --- Post-quantum signatures ---

    #[cfg(feature = "ml-dsa")]
    descs.extend(ml_dsa::descriptors());

    #[cfg(feature = "slh-dsa")]
    descs.extend(slh_dsa::descriptors());

    #[cfg(feature = "lms")]
    descs.extend(lms::descriptors());

    // --- Legacy adapter (always available) ---

    descs.extend(mac_legacy::descriptors());

    descs
}
