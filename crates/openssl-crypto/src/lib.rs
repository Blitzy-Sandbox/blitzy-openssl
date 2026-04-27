//! # openssl-crypto
//!
//! Rust rewrite of OpenSSL's `libcrypto` library — the core cryptographic
//! engine of the OpenSSL Rust workspace.  Provides symmetric and asymmetric
//! algorithms, hash functions, key derivation, random number generation,
//! X.509 PKI, ASN.1/DER encoding, BIO I/O abstraction, and the EVP high-level
//! API.
//!
//! ## Crate Architecture
//!
//! This crate translates ~327,616 lines of C across 70+ top-level files and
//! 50+ algorithm subdirectories from the upstream OpenSSL `crypto/` tree into
//! idiomatic Rust modules.  The translation preserves feature parity, API
//! semantics, and behavioral correctness while eliminating the C codebase's
//! reliance on unsafe memory operations, sentinel-value error handling, and
//! coarse-grained global state.
//!
//! ### Core Infrastructure
//!
//! | Module          | Source (C)                                                | Purpose                                                      |
//! |-----------------|-----------------------------------------------------------|--------------------------------------------------------------|
//! | [`context`]     | `crypto/context.c`                                        | Library context ([`LibContext`], replaces `OSSL_LIB_CTX`)    |
//! | [`init`]        | `crypto/init.c`, `crypto/cryptlib.c`                      | Staged library initialization (replaces `OPENSSL_init_crypto`) |
//! | [`thread`]      | `crypto/threads_pthread.c`, `crypto/thread/*.c`           | Threading primitives (locks, once, thread-local, atomics)    |
//! | [`cpu_detect`]  | `crypto/cpuid.c`, `crypto/armcap.c`, `crypto/ppccap.c`    | Runtime CPU capability detection                             |
//! | [`provider`]    | `crypto/provider.c`, `crypto/provider_core.c`             | Provider loading, activation, dispatch                       |
//!
//! ### High-Level Algorithm API
//!
//! | Module          | Source (C)                                                | Purpose                                                      |
//! |-----------------|-----------------------------------------------------------|--------------------------------------------------------------|
//! | [`evp`]         | `crypto/evp/*.c` (84 files)                               | High-level algorithm API (`EVP_MD`, `EVP_CIPHER`, `EVP_KDF`, …) |
//!
//! ### Asymmetric Algorithms
//!
//! | Module          | Source (C)                     | Feature Gate        |
//! |-----------------|--------------------------------|---------------------|
//! | [`bn`]          | `crypto/bn/*.c` (39 files)     | *(always enabled)*  |
//! | [`ec`]          | `crypto/ec/*.c` (49 files)     | `feature = "ec"`    |
//! | [`dh`]          | `crypto/dh/*.c` (14 files)     | `feature = "dh"`    |
//! | [`dsa`]         | `crypto/dsa/*.c` (14 files)    | `feature = "dsa"`   |
//! | [`pqc`]         | `crypto/ml_kem/`, `ml_dsa/`, `slh_dsa/`, `lms/` | `feature = "pqc"`   |
//!
//! ### Symmetric Algorithms
//!
//! | Module          | Source (C)                                                | Purpose                                                      |
//! |-----------------|-----------------------------------------------------------|--------------------------------------------------------------|
//! | [`symmetric`]   | `crypto/aes/`, `chacha/`, `des/`, `camellia/`, `aria/`    | Block and stream ciphers                                     |
//! | [`hash`]        | `crypto/sha/`, `md5/`, `ripemd/`, `sm3/`                  | Hash functions (SHA, MD5, legacy, SM3)                       |
//! | [`mac`]         | `crypto/hmac/`, `cmac/`, `poly1305/`, `siphash/`          | Message authentication codes                                 |
//! | [`kdf`]         | `crypto/kdf/*.c`                                          | Key derivation (HKDF, PBKDF2, Argon2, scrypt, KBKDF)         |
//! | [`rand`]        | `crypto/rand/*.c` (9 files)                               | DRBG, entropy seeding                                        |
//!
//! ### I/O and Encoding
//!
//! | Module          | Source (C)                                                | Purpose                                                      |
//! |-----------------|-----------------------------------------------------------|--------------------------------------------------------------|
//! | [`bio`]         | `crypto/bio/*.c` (28 files)                               | Trait-based I/O abstraction (Read/Write/AsyncRead)           |
//! | [`asn1`]        | `crypto/asn1/*.c` (65 files)                              | ASN.1/DER encoding and decoding                              |
//! | [`pem`]         | `crypto/pem/*.c` (11 files)                               | PEM encoding per RFC 7468                                    |
//!
//! ### Protocol Extensions
//!
//! | Module          | Source (C)                                                | Feature Gate        |
//! |-----------------|-----------------------------------------------------------|---------------------|
//! | [`hpke`]        | `crypto/hpke/*.c` (6 files)                               | `feature = "hpke"`  |
//! | [`ocsp`]        | `crypto/ocsp/*.c` (10 files)                              | `feature = "ocsp"`  |
//! | [`ts`]          | `crypto/ts/*.c` (11 files)                                | `feature = "ts"`    |
//!
//! ## Design Principles
//!
//! This crate strictly adheres to the project's implementation rules:
//!
//! - **Rule R8 — Zero unsafe outside FFI:** This crate contains NO `unsafe`
//!   code.  `#![forbid(unsafe_code)]` prevents any submodule from introducing
//!   unsafe via `#[allow]` override.  Any raw pointer / FFI work belongs in
//!   the dedicated `openssl-ffi` crate.
//! - **Fully synchronous:** This crate does NOT depend on `tokio` or any async
//!   runtime.  All APIs are synchronous.  Async is confined to the
//!   `openssl-ssl::quic` module (AAP §0.4.4).
//! - **Rule R5 — Option over sentinel:** All nullable values use `Option<T>`
//!   rather than C-style sentinels (`NULL`, `0`, `-1`, `""`).
//! - **Rule R6 — Lossless numeric casts:** All narrowing conversions go
//!   through `TryFrom` or checked/saturating helpers.
//!   `#![deny(clippy::cast_possible_truncation)]` is enforced crate-wide.
//! - **Rule R7 — Fine-grained locking:** Shared mutable state uses per-subsystem
//!   locks (see [`context::LibContext`]'s per-subsystem `RwLock` fields),
//!   never a single coarse lock.
//! - **Rule R9 — Warning-free build:** No module-level `#[allow(warnings)]`
//!   permitted; workspace `RUSTFLAGS="-D warnings"` is honored.
//! - **Secure erasure:** All key material derives `ZeroizeOnDrop` via the
//!   `zeroize` crate (AAP §0.7.6).
//!
//! ## Public Re-exports
//!
//! The most commonly used types are re-exported at the crate root for
//! ergonomic `use openssl_crypto::*;` access:
//!
//! - [`LibContext`] — the library context (re-exported from [`context`])
//! - [`initialize`] / [`cleanup`] — library init / cleanup (re-exported from [`init`])
//! - [`CryptoError`] / [`CryptoResult`] — error types (re-exported from
//!   [`openssl_common`] for cross-crate consistency)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use openssl_crypto::{initialize, cleanup, LibContext, CryptoResult};
//! use openssl_crypto::init::InitFlags;
//!
//! fn main() -> CryptoResult<()> {
//!     // Initialize all library stages.
//!     initialize(InitFlags::all())?;
//!
//!     // Acquire the default library context.
//!     let _ctx = LibContext::default();
//!
//!     // ... perform crypto operations ...
//!
//!     // Shutdown on exit.
//!     cleanup();
//!     Ok(())
//! }
//! ```
//!
//! ## Crate Dependency Position
//!
//! ```text
//! openssl-common    (foundation — error, config, param, observability)
//!     ▲
//!     │
//! openssl-crypto    (this crate — libcrypto equivalent)
//!     ▲
//!     │
//!     ├── openssl-ssl
//!     ├── openssl-provider
//!     ├── openssl-fips
//!     ├── openssl-cli
//!     └── openssl-ffi
//! ```
//!
//! This crate depends ONLY on `openssl-common` from the workspace.  It MUST
//! NOT depend on any other workspace crate to preserve the dependency
//! hierarchy.

// =============================================================================
// Crate-Level Lint Configuration
// =============================================================================
//
// These lint attributes reinforce and, where appropriate, strengthen the
// workspace-level lint policy defined in the root `Cargo.toml`.  They apply
// to every source file compiled as part of this crate, including submodules
// and integration tests.
//
// Test modules that legitimately need `.unwrap()` / `.expect()` / `panic!()`
// must add a targeted `#[allow(clippy::unwrap_used, clippy::expect_used,
// clippy::panic)]` at the module or function level with a justification
// comment — NOT at the crate root.

// Rule R8: zero unsafe in non-FFI crates.  `forbid` is used (stricter than
// `deny`) to prevent any submodule from overriding with `#[allow(unsafe_code)]`.
#![forbid(unsafe_code)]
// Rule R6: no bare narrowing casts — must use `try_from` or saturating helpers.
#![deny(clippy::cast_possible_truncation)]
// Ensure documentation coverage across all public items.
#![warn(missing_docs)]
// No `.unwrap()` in library code — use `Result` / `Option` combinators or `?`.
#![deny(clippy::unwrap_used)]
// No `.expect()` in library code — use `Result` / `Option` combinators or `?`.
#![deny(clippy::expect_used)]

// =============================================================================
// Module Declarations — Core Infrastructure
// =============================================================================
//
// These modules are always compiled and provide the foundational types and
// entry points used by all other modules.  Ordering reflects the dependency
// graph: foundational modules first, then modules that build on them.

/// Library context — central hub for per-library configuration and state.
///
/// Provides [`LibContext`], the Rust equivalent of the C `OSSL_LIB_CTX`.
/// A [`LibContext`] owns the provider store, EVP method cache, name map,
/// property store, global properties, and DRBG state, each protected by a
/// fine-grained lock per Rule R7.
///
/// Source: `crypto/context.c`.
pub mod context;

/// Library initialization — staged setup via `std::sync::Once`.
///
/// Provides [`initialize`] and [`cleanup`], the Rust equivalents of the C
/// `OPENSSL_init_crypto()` / `OPENSSL_cleanup()` API.  Initialization is
/// staged (base, CPU detect, threads, error strings, config, providers,
/// async) with each stage guarded by `std::sync::Once` for thread safety.
///
/// Source: `crypto/init.c`, `crypto/cryptlib.c`.
pub mod init;

/// Threading primitives — locks, once, thread-local storage, atomics.
///
/// Replaces the C `CRYPTO_THREAD_*` API (per-platform `threads_pthread.c`,
/// `threads_win.c`, `threads_common.c`) with idiomatic Rust abstractions
/// built on `parking_lot` and `std::sync`.
pub mod thread;

/// CPU capability detection — runtime probe for hardware acceleration.
///
/// Replaces the C `cpuid.c`, `armcap.c`, `ppccap.c`, `riscvcap.c`, and
/// `s390xcap.c` per-architecture detection code with a unified Rust API
/// built on `std::arch::is_x86_feature_detected!` and equivalents.
pub mod cpu_detect;

/// Provider system — algorithm dispatch, loading, and property matching.
///
/// Replaces the C `OSSL_DISPATCH` function pointer table with Rust trait
/// objects.  Each provider implements algorithm-category traits
/// (`DigestProvider`, `CipherProvider`, `SignatureProvider`, …) that are
/// resolved at runtime through the provider store.
///
/// Source: `crypto/provider.c`, `crypto/provider_core.c`,
/// `crypto/provider_conf.c`, `crypto/provider_child.c`,
/// `crypto/provider_predefined.c`.
pub mod provider;

// =============================================================================
// Module Declarations — High-Level API
// =============================================================================

/// EVP high-level algorithm API — the primary user-facing interface.
///
/// Provides the Rust equivalents of `EVP_MD_*`, `EVP_CIPHER_*`, `EVP_KDF_*`,
/// `EVP_MAC_*`, `EVP_RAND_*`, `EVP_PKEY_*`, `EVP_KEM_*`, and
/// `EVP_SIGNATURE_*` from the C `crypto/evp/` directory (84 files).
/// All algorithms are accessed via a typed fetch / set-params / update /
/// finalize flow that mirrors the C API while gaining Rust's type safety.
pub mod evp;

// =============================================================================
// Module Declarations — Asymmetric Algorithms
// =============================================================================

/// Big-number arithmetic — arbitrary-precision integers for RSA, DSA, DH, EC.
///
/// Translates `crypto/bn/*.c` (39 files) into a Rust module built on the
/// `num-bigint` crate.  Provides add/sub/mul/div/mod, Montgomery
/// multiplication, modular exponentiation, GCD, and primality testing.
pub mod bn;

/// Elliptic curve operations — ECDSA, ECDH, EdDSA, X25519/X448.
///
/// Translates `crypto/ec/*.c` (49 files) with support for NIST, Brainpool,
/// SECP, and curve25519/448 families.
#[cfg(feature = "ec")]
pub mod ec;

/// RSA public-key cryptosystem — encryption (OAEP), signatures (PSS,
/// PKCS#1 v1.5), and key derivation.
///
/// Translates `crypto/rsa/*.c` (26 files) per RFC 8017 (PKCS #1 v2.2),
/// FIPS 186-5 §A.1 (RSA key generation), and NIST SP 800-56B Rev. 2.
/// RSA functionality is dispersed across the EVP layer (`pkey`,
/// `signature`, `keymgmt`, `encode_decode`, `kem`) and the BigNum
/// prime-derivation helper ([`crate::bn::prime::rsa_fips186_5_derive_prime`]);
/// this module re-exports the relevant types for ergonomic RSA-focused
/// access (the AAP §0.4.1 / §0.5.1 directory pattern).
#[cfg(feature = "rsa")]
pub mod rsa;

/// Diffie-Hellman key exchange and finite-field parameter validation.
///
/// Translates `crypto/dh/*.c` (14 files) including RFC 7919 named groups
/// and FFC parameter validation (FIPS 186-4, SP 800-56A).
#[cfg(feature = "dh")]
pub mod dh;

/// DSA signature algorithm — parameter generation, sign, verify.
///
/// Translates `crypto/dsa/*.c` (14 files) per FIPS 186-4.
#[cfg(feature = "dsa")]
pub mod dsa;

/// Post-quantum cryptography — ML-KEM, ML-DSA, SLH-DSA, LMS.
///
/// Provides NIST-standardized post-quantum algorithms:
/// - **ML-KEM** (FIPS 203) — 512, 768, 1024 parameter sets
/// - **ML-DSA** (FIPS 204) — 44, 65, 87 parameter sets
/// - **SLH-DSA** (FIPS 205) — 12 hash-based signature parameter sets
/// - **LMS** (SP 800-208) — Leighton-Micali hash-based signatures
#[cfg(feature = "pqc")]
pub mod pqc;

// =============================================================================
// Module Declarations — Symmetric Algorithms
// =============================================================================

/// Symmetric ciphers — AES, ChaCha20, DES/3DES, Camellia, ARIA, SM4, legacy.
///
/// Consolidates `crypto/aes/`, `crypto/chacha/`, `crypto/des/`,
/// `crypto/camellia/`, `crypto/aria/`, `crypto/sm4/`, and the legacy ciphers
/// (`crypto/bf/`, `crypto/cast/`, `crypto/idea/`, `crypto/seed/`,
/// `crypto/rc2/`, `crypto/rc4/`, `crypto/rc5/`).  Supports AEAD modes
/// (GCM, CCM, OCB, SIV, GCM-SIV) and legacy modes (CBC, CTR, CFB, OFB, XTS).
pub mod symmetric;

/// Block cipher modes of operation — GCM, CCM, CTR, CFB, OFB, XTS, SIV,
/// GCM-SIV, CBC, ECB.
///
/// Thin re-export facade over [`symmetric`] that surfaces each mode under
/// a dedicated submodule, matching the layout mandated by AAP §0.4.1.
/// Consolidates `crypto/modes/*.c` (12 files) into named submodules that
/// forward to the canonical cipher-aware implementations.
pub mod modes;

/// Hash functions — SHA-1/2/3, MD5, legacy, and SM3.
///
/// Consolidates `crypto/sha/`, `crypto/md5/`, `crypto/md2/`, `crypto/md4/`,
/// `crypto/mdc2/`, `crypto/ripemd/`, `crypto/whrlpool/`, `crypto/sm3/`, and
/// `crypto/blake2/` into a unified hash interface.
pub mod hash;

/// Message authentication codes — HMAC, CMAC, GMAC, KMAC, Poly1305, SipHash.
///
/// Translates `crypto/hmac/*.c` (4 files), `crypto/cmac/*.c`,
/// `crypto/poly1305/*.c`, and `crypto/siphash/*.c` into a MAC trait
/// hierarchy exposed via [`evp::mac`].
pub mod mac;

/// Key derivation functions — HKDF, PBKDF2, Argon2, scrypt, KBKDF, TLS1-PRF.
///
/// Translates `crypto/kdf/*.c` (5 files) plus the provider-side KDF
/// implementations into a unified KDF interface.
pub mod kdf;

/// Random number generation — DRBG (CTR, Hash, HMAC), entropy, seeding.
///
/// Translates `crypto/rand/*.c` (9 files) into a hierarchical DRBG scheme
/// (primary / public / private) per SP 800-90A, with `OsRng`-seeded entropy
/// collection and per-thread DRBG isolation.
pub mod rand;

// =============================================================================
// Module Declarations — I/O and Encoding
// =============================================================================

/// BIO I/O abstraction — memory, file, socket, filter-chain BIOs.
///
/// Translates `crypto/bio/*.c` (28 files) from the C abstract-I/O API into
/// Rust's `Read` / `Write` trait hierarchy.  Provides `MemBio`, `FileBio`,
/// `SocketBio`, and filter chain composition for encoding pipelines.
pub mod bio;

/// ASN.1/DER encoding and decoding — templates, types, and utilities.
///
/// Translates `crypto/asn1/*.c` (65 files), the largest subsystem outside
/// `crypto/evp/`, into a Rust module built on the RustCrypto `der` crate.
/// Provides encode/decode for all primitive ASN.1 types plus the template
/// system used for X.509, CMS, PKCS#7, PKCS#12, etc.
pub mod asn1;

/// PEM encoding and decoding per RFC 7468.
///
/// Translates `crypto/pem/*.c` (11 files) into PEM read/write functions
/// layered on top of the `pem-rfc7468` crate.
pub mod pem;

/// X.509 certificate and Certificate Revocation List (CRL) processing.
///
/// Translates `crypto/x509/*.c` (98 files) into idiomatic Rust,
/// starting with CRL processing (`crl.rs`) per RFC 5280 §5.
pub mod x509;

// =============================================================================
// Module Declarations — Protocol Extensions (feature-gated)
// =============================================================================

/// Hybrid Public Key Encryption per RFC 9180.
///
/// Translates `crypto/hpke/*.c` (6 files).  Supports all KEM/KDF/AEAD
/// combinations from the RFC 9180 ciphersuite registry.
#[cfg(feature = "hpke")]
pub mod hpke;

/// Online Certificate Status Protocol client per RFC 6960.
///
/// Translates `crypto/ocsp/*.c` (10 files).  Supports OCSP request
/// construction, response parsing, signature verification, and stapling.
#[cfg(feature = "ocsp")]
pub mod ocsp;

/// Timestamping per RFC 3161.
///
/// Translates `crypto/ts/*.c` (11 files).  Supports timestamp request
/// generation, response parsing, and token signature verification.
#[cfg(feature = "ts")]
pub mod ts;

/// Certificate Management Protocol per RFC 4210 / RFC 9480.
///
/// Translates the foundational types from `crypto/cmp/*.c` (13 files):
/// [`PkiVersion`](cmp::PkiVersion), [`PkiStatus`](cmp::PkiStatus),
/// [`PkiFailureInfo`](cmp::PkiFailureInfo),
/// [`FailureInfoBits`](cmp::FailureInfoBits),
/// [`PkiStatusInfo`](cmp::PkiStatusInfo),
/// [`PkiHeader`](cmp::PkiHeader), and
/// [`PkiHeaderBuilder`](cmp::PkiHeaderBuilder).  Higher-level message
/// dispatch and CRMF integration are deferred to a follow-up checkpoint;
/// the types delivered here form the foundation on which they are built.
///
/// # Scope at this checkpoint
///
/// * **In scope:** Protocol-version enum, PKI status / failure-info enums,
///   bitmap of failure-info bits, status-info container, PKIHeader subset
///   (pvno, sender, recipient, messageTime, transactionID, senderNonce,
///   recipNonce), RFC 4210 §5.1.1 transaction-ID and nonce length checks,
///   builder API, helper accessors.
/// * **Out of scope:** Full PKIMessage encode/decode, CertReqMsg /
///   CertReqMessages, certificate-confirm flows, polling, protection
///   algorithms, freeText, generalInfo, HTTP transport, CRMF detail.
#[cfg(feature = "cmp")]
pub mod cmp;

/// Certificate Transparency per RFC 6962.
///
/// Translates the foundational types from `crypto/ct/*.c` (10 files):
/// [`LogEntryType`](ct::LogEntryType), [`SctVersion`](ct::SctVersion),
/// [`SctSource`](ct::SctSource), [`SctValidationStatus`](ct::SctValidationStatus),
/// [`SignedCertificateTimestamp`](ct::SignedCertificateTimestamp), and
/// [`SignedCertificateTimestampBuilder`](ct::SignedCertificateTimestampBuilder).
/// Higher-level SCT validation against CT log Merkle trees, BIO printing,
/// CT_POLICY_EVAL_CTX state machine, and base64 log fetching are deferred
/// to a follow-up checkpoint; the types delivered here form the foundation
/// on which they are built.
///
/// # Scope at this checkpoint
///
/// * **In scope:** Log entry type / SCT version / SCT source / validation
///   status enums, `SCT_MIN_RSA_BITS` / `CT_V1_HASHLEN` constants,
///   [`SignedCertificateTimestamp`](ct::SignedCertificateTimestamp) type with
///   builder, RFC 6962 length validations, helper accessors.
/// * **Out of scope:** Full SCT validation against CT log Merkle tree, BIO
///   printing, `CT_POLICY_EVAL_CTX` state machine, log fetching from URL,
///   base64 log decoding.
#[cfg(feature = "ct")]
pub mod ct;

// =============================================================================
// Test Module Declaration
// =============================================================================

// Root test module aggregating per-subsystem test suites.  Gated behind
// `#[cfg(test)]` so test code is only compiled during `cargo test`.  The
// module root lives at `src/tests/mod.rs` and declares child test
// submodules for each source module.
#[cfg(test)]
mod tests;

// =============================================================================
// Public Re-exports — Ergonomic Access to Key Types
// =============================================================================
//
// These re-exports allow downstream crates and applications to import the
// most frequently used types directly from `openssl_crypto::` without
// navigating into submodules.  Only types that are universally relevant
// to callers are re-exported here; subsystem-specific types remain inside
// their originating modules.

// ── Error types (re-exported from openssl_common for cross-crate consistency) ──

/// Re-exported crypto error enum.
///
/// Mirrors [`openssl_common::CryptoError`] so callers can write
/// `use openssl_crypto::CryptoError;` without also importing `openssl_common`.
///
/// Variants include: `Common`, `Provider`, `AlgorithmNotFound`, `Key`,
/// `Encoding`, `Verification`, `Rand`, `Io` (see the source enum for the
/// full list and documentation).
pub use openssl_common::CryptoError;

/// Re-exported `Result` alias for crypto operations.
///
/// Equivalent to `Result<T, CryptoError>`.  This is the primary return
/// type for fallible functions throughout the crate.
pub use openssl_common::CryptoResult;

// ── Library context ───────────────────────────────────────────────────────────

/// Re-exported library context type for ergonomic access.
///
/// See [`context::LibContext`] for the full API.
pub use context::LibContext;

// ── Initialization functions ──────────────────────────────────────────────────

/// Re-exported library initialization function.
///
/// See [`init::initialize`] for the full documentation.  The [`init`]
/// module exposes additional helpers (`init_default`, `is_initialized`,
/// `is_stopped`, `InitFlags`, `completed_stages`) that remain accessible
/// via the [`init`] module path.
pub use init::initialize;

/// Re-exported library cleanup function.
///
/// See [`init::cleanup`] for the full documentation.
pub use init::cleanup;

// =============================================================================
// Crate Metadata Constants
// =============================================================================

/// Crate version string, automatically populated from `Cargo.toml`.
///
/// Matches the `version` field in `crates/openssl-crypto/Cargo.toml` at
/// build time.  Used by the CLI `version` subcommand, observability
/// metadata, and FIPS indicator reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name string, automatically populated from `Cargo.toml`.
///
/// Returns `"openssl-crypto"` — the package name as declared in the
/// manifest.  Used for structured logging spans and metric labels.
pub const NAME: &str = env!("CARGO_PKG_NAME");
