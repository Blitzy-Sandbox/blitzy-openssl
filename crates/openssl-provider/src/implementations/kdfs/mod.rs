//! # Key Derivation Function (KDF) Provider Implementations
//!
//! This module contains all KDF algorithm implementations for the OpenSSL
//! Rust provider system. Each submodule translates one C source file from
//! `providers/implementations/kdfs/` into idiomatic Rust implementing the
//! `KdfProvider` trait from `crate::traits`.
//!
//! ## Algorithm Inventory
//!
//! ### Standard KDFs
//!
//! | Algorithm | Module | RFC/Standard | C Source |
//! |-----------|--------|-------------|----------|
//! | HKDF | [`hkdf`] | RFC 5869, RFC 8446 | `hkdf.c` |
//! | PBKDF2 | [`pbkdf2`] | PKCS#5 v2.1, SP 800-132 | `pbkdf2.c` |
//! | Argon2 | [`argon2`] | RFC 9106 | `argon2.c` |
//! | scrypt | [`scrypt`] | RFC 7914 | `scrypt.c` |
//! | KBKDF | [`kbkdf`] | SP 800-108 | `kbkdf.c` |
//! | SSKDF | [`sskdf`] | SP 800-56C, X9.63 | `sskdf.c` |
//!
//! ### Protocol-Specific KDFs
//!
//! | Algorithm | Module | RFC/Standard | C Source |
//! |-----------|--------|-------------|----------|
//! | SSH KDF | [`ssh`] | RFC 4253 | `sshkdf.c` |
//! | Kerberos KDF | [`kerberos`] | RFC 3961 | `krb5kdf.c` |
//! | SRTP KDF | [`srtp`] | RFC 3711 | `srtpkdf.c` |
//! | SNMP KDF | [`snmp`] | RFC 3414 | `snmpkdf.c` |
//! | X9.42 KDF | [`x942`] | ANSI X9.42 | `x942kdf.c` |
//! | TLS1-PRF | [`tls1_prf`] | RFC 2246/5246 | `tls1_prf.c` |
//!
//! ### Other KDFs
//!
//! | Algorithm | Module | Standard | C Source |
//! |-----------|--------|----------|----------|
//! | HMAC-DRBG KDF | [`hmacdrbg`] | SP 800-90A | `hmacdrbg_kdf.c` |
//! | PKCS#12 KDF | [`pkcs12`] | RFC 7292 | `pkcs12kdf.c` |
//! | PVK KDF | [`pvk`] | Microsoft PVK | `pvkkdf.c` |
//! | PBKDF1 | [`pbkdf1`] | RFC 8018 (legacy) | `pbkdf1.c` |
//!
//! ## Architecture
//!
//! Each KDF module follows a common pattern:
//!
//! 1. Define a context struct implementing `KdfContext` trait — holds
//!    algorithm-specific state and key material.
//! 2. Define a provider struct implementing `KdfProvider` trait — exposes
//!    `new_ctx()`, `derive()`, `set_params()`, `get_params()`.
//! 3. Export a `descriptors()` function returning `Vec<AlgorithmDescriptor>`
//!    for provider registration.
//!
//! Context lifecycle: `new_ctx()` → `set_params()` → `derive()` → `Drop`
//!
//! All key material in context structs derives `Zeroize` + `ZeroizeOnDrop`
//! for automatic secure erasure when the context is dropped, replacing
//! C `OPENSSL_cleanse()` calls in `*_freectx()` functions.
//!
//! ## Wiring Path (Rule R10)
//!
//! This module is reachable from the entry point:
//!
//! ```text
//! openssl_cli::main()
//!   → openssl_crypto::init()
//!     → provider loading
//!       → DefaultProvider::query_operation(KDF)
//!         → implementations::all_kdf_descriptors()
//!           → kdfs::descriptors()
//!             → each submodule::descriptors()
//! ```
//!
//! ## C Source Reference
//!
//! This module replaces the organizational role of the KDF-related entries in
//! `prov/implementations.h` and the `deflt_kdfs[]` static array from
//! `providers/defltprov.c`. The C `OSSL_ALGORITHM` struct is replaced by
//! [`AlgorithmDescriptor`](crate::traits::AlgorithmDescriptor).

use crate::traits::AlgorithmDescriptor;

// =============================================================================
// Shared Constants
// =============================================================================
//
// These constants are used across multiple KDF submodules to enforce
// consistent input validation and prevent allocation-based denial-of-service
// attacks. Submodules access them via `super::MAX_INPUT_LEN` and
// `super::MAX_INFO_SEGMENTS`.

/// Maximum allowed input length (key, salt, info, password) across all KDF
/// implementations, in bytes.
///
/// Set to 1 GiB (2^30 bytes) to prevent allocation-based denial-of-service
/// while allowing all legitimate cryptographic use cases. This mirrors the
/// implicit limits in the C implementation where `OSSL_PARAM` size fields
/// are bounded by `size_t`.
///
/// Used by [`sskdf`], [`kbkdf`], [`hkdf`], and other submodules during
/// parameter validation in their `set_params()` implementations.
pub const MAX_INPUT_LEN: usize = 1 << 30;

/// Maximum number of info segments that can be concatenated in KDF
/// implementations that support multi-part info parameters.
///
/// The C HKDF implementation allows up to 5 separate `info` parameter
/// segments that are concatenated before use (see `OSSL_KDF_PARAM_INFO`
/// handling in `hkdf.c`). This constant enforces the same limit in the
/// Rust implementation.
///
/// Used by [`hkdf`], [`sskdf`], and [`kbkdf`] submodules.
pub const MAX_INFO_SEGMENTS: usize = 5;

// =============================================================================
// Submodule Declarations — KDF Algorithm Implementations
// =============================================================================
//
// Standard KDFs — always available when the parent `kdfs` feature is enabled.
// These map 1:1 to the C source files in `providers/implementations/kdfs/`.

/// HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
///
/// Implements HKDF in both one-shot and extract-then-expand modes, plus the
/// TLS 1.3 specific variant (TLS13-KDF). Supports all HMAC-capable hash
/// algorithms (SHA-256, SHA-384, SHA-512, etc.).
///
/// Source: `providers/implementations/kdfs/hkdf.c`
///
/// Algorithm names: `HKDF`, `TLS13-KDF`
pub mod hkdf;

/// Password-Based Key Derivation Function 2 (PKCS#5 v2.1 / SP 800-132).
///
/// The most widely deployed password hashing KDF. Supports configurable
/// iteration count and all HMAC-capable hash algorithms.
///
/// Source: `providers/implementations/kdfs/pbkdf2.c`
///
/// Algorithm name: `PBKDF2`
pub mod pbkdf2;

/// Key-Based Key Derivation Function (NIST SP 800-108).
///
/// Supports counter mode, feedback mode, and double-pipeline iteration mode
/// for deriving keying material from a shared secret using HMAC or CMAC
/// as the pseudorandom function.
///
/// Source: `providers/implementations/kdfs/kbkdf.c`
///
/// Algorithm name: `KBKDF`
pub mod kbkdf;

/// Single-Step Key Derivation Function (NIST SP 800-56C Rev. 2) and
/// ANSI X9.63 Key Derivation Function.
///
/// Used in key agreement protocols (DH, ECDH) to derive symmetric keys
/// from shared secrets. The X9.63 variant uses a hash function directly;
/// the SP 800-56C variant can use HMAC or KMAC.
///
/// Source: `providers/implementations/kdfs/sskdf.c`
///
/// Algorithm names: `SSKDF`, `X963KDF`
pub mod sskdf;

/// TLS 1.0/1.1/1.2 Pseudo-Random Function (RFC 2246, RFC 5246).
///
/// Used to derive master secrets and key material in TLS pre-1.3 handshakes.
/// Combines MD5 and SHA-1 PRFs for TLS 1.0/1.1, uses SHA-256/SHA-384 for
/// TLS 1.2.
///
/// Source: `providers/implementations/kdfs/tls1_prf.c`
///
/// Algorithm name: `TLS1-PRF`
pub mod tls1_prf;

/// HMAC-DRBG based Key Derivation Function (NIST SP 800-90A).
///
/// Uses the HMAC-DRBG construction to derive keying material. Primarily
/// used internally for deterministic key generation scenarios.
///
/// Source: `providers/implementations/kdfs/hmacdrbg_kdf.c`
///
/// Algorithm name: `HMAC-DRBG-KDF`
pub mod hmacdrbg;

/// PKCS#12 Key Derivation Function (RFC 7292, Appendix B).
///
/// Used to derive encryption keys, IV values, and MAC keys from passwords
/// during PKCS#12 (PFX) file processing. Implements the iterative hash-based
/// KDF specified in the PKCS#12 standard.
///
/// Source: `providers/implementations/kdfs/pkcs12kdf.c`
///
/// Algorithm name: `PKCS12KDF`
pub mod pkcs12;

/// Password-Based Key Derivation Function 1 (RFC 8018, legacy).
///
/// The original PKCS#5 v1 password-based KDF. Superseded by PBKDF2 but
/// retained for backward compatibility with legacy systems. Uses a single
/// hash function (MD2, MD5, or SHA-1) with iteration.
///
/// Source: `providers/implementations/kdfs/pbkdf1.c`
///
/// Algorithm name: `PBKDF1`
pub mod pbkdf1;

/// Microsoft PVK (Private Key) Key Derivation Function.
///
/// A proprietary KDF used by Microsoft's PVK private key file format.
/// Derives encryption keys from passwords for PVK file protection.
/// Retained for interoperability with Windows-originated key files.
///
/// Source: `providers/implementations/kdfs/pvkkdf.c`
///
/// Algorithm name: `PVKKDF`
pub mod pvk;

// =============================================================================
// Protocol-Specific KDFs
// =============================================================================

/// SSH Key Derivation Function (RFC 4253, Section 7.2).
///
/// Derives encryption keys, integrity keys, and IVs for SSH transport layer
/// from the shared secret and exchange hash produced during SSH key exchange.
///
/// Source: `providers/implementations/kdfs/sshkdf.c`
///
/// Algorithm name: `SSHKDF`
pub mod ssh;

/// Kerberos Key Derivation Function (RFC 3961).
///
/// Derives protocol keys for Kerberos V5 from base keys and usage constants.
/// Uses the DK(Base-Key, Well-Known-Constant) construction.
///
/// Source: `providers/implementations/kdfs/krb5kdf.c`
///
/// Algorithm name: `KRB5KDF`
pub mod kerberos;

/// SRTP Key Derivation Function (RFC 3711, Section 4.3).
///
/// Derives session keys for Secure Real-time Transport Protocol from a
/// master key and master salt using AES in counter mode.
///
/// Source: `providers/implementations/kdfs/srtpkdf.c`
///
/// Algorithm name: `SRTPKDF`
pub mod srtp;

/// SNMP Key Derivation Function (RFC 3414, Section A.2).
///
/// Derives localized keys for SNMPv3 User-based Security Model (USM)
/// from user passwords and engine IDs.
///
/// Source: `providers/implementations/kdfs/snmpkdf.c`
///
/// Algorithm name: `SNMPKDF`
pub mod snmp;

/// ANSI X9.42 Key Derivation Function (ANSI X9.42-2003).
///
/// Derives keying material for CMS (Cryptographic Message Syntax) key
/// agreement using the ASN.1-encoded OtherInfo structure. Used in S/MIME
/// and CMS EnvelopedData with Diffie-Hellman key agreement.
///
/// Source: `providers/implementations/kdfs/x942kdf.c`
///
/// Algorithm name: `X942KDF-ASN1`
pub mod x942;

// =============================================================================
// Feature-Gated KDFs
// =============================================================================
//
// These KDFs have significant additional dependencies or computational
// requirements and are gated behind dedicated feature flags, matching the
// C `#ifndef OPENSSL_NO_ARGON2` / `#ifndef OPENSSL_NO_SCRYPT` guards.

/// Argon2 password hashing function (RFC 9106).
///
/// Implements all three Argon2 variants: Argon2d (data-dependent addressing),
/// Argon2i (data-independent addressing), and Argon2id (hybrid). Winner of
/// the Password Hashing Competition (PHC). Supports configurable memory cost,
/// time cost, and parallelism parameters.
///
/// Source: `providers/implementations/kdfs/argon2.c`
///
/// Algorithm names: `ARGON2D`, `ARGON2I`, `ARGON2ID`
///
/// Feature gate: `argon2` — matches C `#ifndef OPENSSL_NO_ARGON2`
#[cfg(feature = "argon2")]
pub mod argon2;

/// scrypt password-based key derivation function (RFC 7914).
///
/// A memory-hard KDF designed to be costly in both time and memory,
/// making large-scale brute-force attacks expensive. Uses Salsa20/8
/// core as a mixing function. Supports configurable N (CPU/memory cost),
/// r (block size), and p (parallelism) parameters.
///
/// Source: `providers/implementations/kdfs/scrypt.c`
///
/// Algorithm name: `SCRYPT`
///
/// Feature gate: `scrypt` — matches C `#ifndef OPENSSL_NO_SCRYPT`
#[cfg(feature = "scrypt")]
pub mod scrypt;

// =============================================================================
// Descriptor Aggregation
// =============================================================================

/// Returns all registered KDF algorithm descriptors.
///
/// This aggregates descriptors from all 16 KDF implementation submodules,
/// respecting feature gates for `argon2` and `scrypt`. Called by
/// [`super::all_kdf_descriptors()`] when the `"kdfs"` feature is enabled,
/// which in turn is called by `DefaultProvider::query_operation()` during
/// provider algorithm discovery.
///
/// ## C Source Equivalent
///
/// Replaces the `deflt_kdfs[]` static `OSSL_ALGORITHM` array from
/// `providers/defltprov.c` and the corresponding dispatch table declarations
/// (`ossl_kdf_hkdf_functions`, `ossl_kdf_pbkdf2_functions`, etc.) from
/// `prov/implementations.h`.
///
/// ## Returns
///
/// A `Vec<AlgorithmDescriptor>` containing descriptors for all enabled KDF
/// implementations. The vector is freshly allocated on each call; callers
/// are expected to cache the result if repeated queries are anticipated.
///
/// ## Feature Gating
///
/// - Standard KDFs (`hkdf`, `pbkdf2`, `kbkdf`, `sskdf`, `tls1_prf`, `hmacdrbg`,
///   `pkcs12`, `pbkdf1`, `pvk`, `ssh`, `kerberos`, `srtp`, `snmp`, `x942`) are always
///   included when this module is compiled.
/// - `argon2` descriptors are included only when the `"argon2"` feature
///   is enabled.
/// - `scrypt` descriptors are included only when the `"scrypt"` feature
///   is enabled.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    let mut descs = Vec::new();

    // Standard KDFs — always available
    descs.extend(hkdf::descriptors());
    descs.extend(pbkdf2::descriptors());
    descs.extend(kbkdf::descriptors());
    descs.extend(sskdf::descriptors());
    descs.extend(tls1_prf::descriptors());
    descs.extend(hmacdrbg::descriptors());
    descs.extend(pkcs12::descriptors());
    descs.extend(pbkdf1::descriptors());
    descs.extend(pvk::descriptors());

    // Protocol-specific KDFs
    descs.extend(ssh::descriptors());
    descs.extend(kerberos::descriptors());
    descs.extend(srtp::descriptors());
    descs.extend(snmp::descriptors());
    descs.extend(x942::descriptors());

    // Feature-gated KDFs
    #[cfg(feature = "argon2")]
    descs.extend(argon2::descriptors());

    #[cfg(feature = "scrypt")]
    descs.extend(scrypt::descriptors());

    descs
}

