//! # Hash Functions Module
//!
//! Provides a unified trait-based interface for all message digest algorithms
//! in the OpenSSL Rust workspace.  This module is the *root* of the hash
//! subsystem — it declares the three submodules ([`sha`], [`md5`], [`legacy`]),
//! defines the [`DigestAlgorithm`] enumeration that names every supported
//! algorithm, exposes the [`DigestContext`] type alias for runtime-dispatched
//! hashing, and implements the [`create_digest`] factory that converts an
//! enum variant into a concrete boxed digest implementation.  The actual
//! per-algorithm logic (compression functions, padding, sponge state, etc.)
//! lives in the submodules.
//!
//! ## Submodules
//!
//! | Submodule    | Algorithms                                                                       | C Source                                                       |
//! |--------------|----------------------------------------------------------------------------------|----------------------------------------------------------------|
//! | [`sha`]      | SHA-1 (legacy), SHA-2 (224/256/384/512, 512/224, 512/256), SHA-3, SHAKE XOF      | `crypto/sha/*.c` (9 files)                                     |
//! | [`md5`]      | MD5 (legacy), MD5-SHA1 composite (legacy TLS)                                    | `crypto/md5/*.c` (5 files)                                     |
//! | [`legacy`]   | MD2, MD4, MDC-2, RIPEMD-160, SM3, Whirlpool, BLAKE2 type markers                 | `crypto/{md2,md4,mdc2,ripemd,sm3,whrlpool}/*.c` (≈ 18 files)   |
//!
//! ## Trait-Based Dispatch (Replaces C `EVP_MD` Function Pointers)
//!
//! The C implementation routes every hash call through a `EVP_MD_CTX` that
//! holds a vtable of function pointers (`Init`, `Update`, `Final`, ...).  In
//! Rust, the same dispatch is provided by the [`Digest`] trait: each concrete
//! context type implements the trait, and runtime polymorphism is achieved by
//! returning `Box<dyn Digest>` (aliased here as [`DigestContext`]).  The
//! [`create_digest`] factory takes a [`DigestAlgorithm`] enum value and
//! produces the matching boxed context, replacing the `EVP_get_digestbyname`
//! / `EVP_MD_CTX_init` C pattern with a single safe constructor call.
//!
//! ## Algorithm Identification
//!
//! Three identification mechanisms are provided:
//!
//! 1. The [`DigestAlgorithm`] enum — a strongly-typed identifier with 24
//!    variants covering every supported algorithm.  Methods on the enum
//!    return the [output size](DigestAlgorithm::digest_size), [block
//!    size](DigestAlgorithm::block_size), [canonical
//!    name](DigestAlgorithm::name), and [legacy
//!    classification](DigestAlgorithm::is_legacy).
//! 2. The [`Digest::algorithm_name`](sha::Digest::algorithm_name) trait
//!    method — returns the canonical name from a live context, used by
//!    provider dispatch and by `OSSL_PARAM` reporting.
//! 3. The [`algorithm_from_name`] function — converts a canonical-or-alias
//!    string back into a [`DigestAlgorithm`] variant, mirroring
//!    `EVP_get_digestbyname` from the C API.
//!
//! ## Usage
//!
//! ```no_run
//! use openssl_crypto::hash::{create_digest, sha::sha256, Digest, DigestAlgorithm};
//!
//! // One-shot convenience function (synchronous, returns Vec<u8>).
//! let h1 = sha256(b"hello world").expect("SHA-256 of 11 bytes never fails");
//! assert_eq!(h1.len(), 32);
//!
//! // Streaming via the trait object — algorithm chosen at runtime.
//! let mut ctx = create_digest(DigestAlgorithm::Sha256)
//!     .expect("SHA-256 is always supported");
//! ctx.update(b"hello ").unwrap();
//! ctx.update(b"world").unwrap();
//! let h2 = ctx.finalize().unwrap();
//! assert_eq!(h1, h2);
//! ```
//!
//! ## Design Principles
//!
//! - **Rule R5 (no sentinels):** every fallible API returns
//!   [`CryptoResult<T>`](openssl_common::CryptoResult); algorithm-name lookup
//!   returns `Option<DigestAlgorithm>` instead of a sentinel `0`/`-1` like the
//!   C `EVP_get_digestbynid()` returning `NULL`.
//! - **Rule R6 (no narrowing casts):** [`DigestAlgorithm::digest_size`] and
//!   [`DigestAlgorithm::block_size`] return `usize` directly; no `as` casts.
//! - **Rule R8 (zero `unsafe`):** this file contains no `unsafe` blocks; the
//!   workspace lint `unsafe_code = "deny"` enforces this transitively for
//!   every submodule.
//! - **Rule R9 (warning-free build):** every public item carries a `///` doc
//!   comment; no `#[allow(unused)]` or module-level lint suppressions.
//! - **Rule R10 (wiring before done):** [`create_digest`] is reachable from
//!   `openssl-cli`, the EVP layer in [`crate::evp::md`], the provider layer
//!   in `openssl-provider::implementations::digests`, and the test module in
//!   [`crate::tests::test_hash`] — all of which exercise the factory through
//!   integration tests.
//! - **Observability (AAP §0.8.5):** [`create_digest`] emits a
//!   `tracing::trace!` event tagged with the algorithm name on every
//!   invocation, enabling correlation with HMAC, KDF, signature, and TLS
//!   handshake spans through the unified `tracing` subscriber configured by
//!   [`openssl_common::observability`].

// Submodule declarations.
//
// Each submodule contains the actual algorithm implementations: state types,
// compression functions, padding logic, and a `Digest` trait implementation.
// The submodules are declared `pub` so callers may reference algorithm-
// specific types directly (e.g. `hash::sha::Sha256Context`,
// `hash::legacy::Blake2Context`) without going through the trait object.
pub mod legacy;
pub mod md5;
pub mod sha;

// =============================================================================
// Crate-internal imports
// =============================================================================

// `CryptoError` and `CryptoResult` are sourced from the foundation crate
// `openssl-common`.  `CryptoError::AlgorithmNotFound(String)` is the variant
// used in `create_digest` to signal that a `DigestAlgorithm` variant has no
// concrete factory mapping in this module — for example, the `Shake128` and
// `Shake256` XOFs require an explicit output length and therefore cannot be
// constructed via the fixed-output `create_digest` API; the `Blake2*`
// variants are dispatched by `openssl-provider::implementations::digests::
// blake2` per AAP §0.5.1 and are not directly constructible from this module.
use openssl_common::{CryptoError, CryptoResult};

// `tracing::trace!` is the structured-logging entry point used by the
// `create_digest` factory.  Each invocation emits a `trace`-level event with
// the canonical algorithm name as a span attribute, enabling operators to
// audit algorithm selection and correlate digest creation with the broader
// request-flow spans configured by the observability subsystem (AAP §0.8.5).
use tracing::trace;

// =============================================================================
// DigestAlgorithm Enumeration
// =============================================================================

/// Strongly-typed identifier for every message digest algorithm supported by
/// the OpenSSL Rust workspace.
///
/// This enumeration replaces the C `NID_*` integer constants used by
/// `EVP_MD_get_type()` / `EVP_get_digestbynid()` with a closed Rust enum.
/// Closing the enum at the language level eliminates the entire class of
/// "unrecognized algorithm ID" bugs that the C codebase guards against with
/// runtime checks: callers must enumerate every variant or use a wildcard
/// arm, and the compiler enforces exhaustiveness for any subsequent
/// additions.
///
/// Twenty-four variants cover the full set of algorithms translated from
/// `crypto/{sha,md5,md2,md4,mdc2,ripemd,whrlpool,sm3}/*.c`, plus the
/// BLAKE2 type markers from RFC 7693 and the SHAKE XOFs from FIPS 202.
///
/// # Categories
///
/// | Category               | Variants                                                               |
/// |------------------------|------------------------------------------------------------------------|
/// | SHA-1 (legacy)         | [`Sha1`]                                                               |
/// | SHA-2 (FIPS 180-4)     | [`Sha224`], [`Sha256`], [`Sha384`], [`Sha512`], [`Sha512_224`], [`Sha512_256`] |
/// | SHA-3 (FIPS 202)       | [`Sha3_224`], [`Sha3_256`], [`Sha3_384`], [`Sha3_512`]                 |
/// | SHAKE XOF (FIPS 202)   | [`Shake128`], [`Shake256`]                                             |
/// | MD-family (legacy)     | [`Md2`], [`Md4`], [`Md5`], [`Md5Sha1`], [`Mdc2`]                       |
/// | RIPEMD / Whirlpool     | [`Ripemd160`], [`Whirlpool`]                                           |
/// | Chinese national       | [`Sm3`]                                                                |
/// | BLAKE2 (RFC 7693)      | [`Blake2b256`], [`Blake2b512`], [`Blake2s256`]                         |
///
/// [`Sha1`]: DigestAlgorithm::Sha1
/// [`Sha224`]: DigestAlgorithm::Sha224
/// [`Sha256`]: DigestAlgorithm::Sha256
/// [`Sha384`]: DigestAlgorithm::Sha384
/// [`Sha512`]: DigestAlgorithm::Sha512
/// [`Sha512_224`]: DigestAlgorithm::Sha512_224
/// [`Sha512_256`]: DigestAlgorithm::Sha512_256
/// [`Sha3_224`]: DigestAlgorithm::Sha3_224
/// [`Sha3_256`]: DigestAlgorithm::Sha3_256
/// [`Sha3_384`]: DigestAlgorithm::Sha3_384
/// [`Sha3_512`]: DigestAlgorithm::Sha3_512
/// [`Shake128`]: DigestAlgorithm::Shake128
/// [`Shake256`]: DigestAlgorithm::Shake256
/// [`Md2`]: DigestAlgorithm::Md2
/// [`Md4`]: DigestAlgorithm::Md4
/// [`Md5`]: DigestAlgorithm::Md5
/// [`Md5Sha1`]: DigestAlgorithm::Md5Sha1
/// [`Mdc2`]: DigestAlgorithm::Mdc2
/// [`Ripemd160`]: DigestAlgorithm::Ripemd160
/// [`Whirlpool`]: DigestAlgorithm::Whirlpool
/// [`Sm3`]: DigestAlgorithm::Sm3
/// [`Blake2b256`]: DigestAlgorithm::Blake2b256
/// [`Blake2b512`]: DigestAlgorithm::Blake2b512
/// [`Blake2s256`]: DigestAlgorithm::Blake2s256
///
/// # Rule compliance
///
/// * **R5** — every variant carries a distinct discriminant; no sentinel
///   values overlap.
/// * **R6** — methods on the enum return `usize` and `&'static str`; no
///   narrowing casts are performed.
/// * **R8** — construction is entirely safe Rust; no `unsafe` blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    // ---- SHA-1 (legacy — retained for TLS 1.0/1.1 + DTLS 1.0 compatibility) ----
    /// SHA-1 — 160-bit hash from FIPS 180-4 §6.1.  Cryptographically
    /// broken (Wang 2005, Stevens `SHAttered` 2017); retained only for
    /// legacy TLS, X.509 certificate hashes, and HMAC-SHA1 in OTP/2FA.
    Sha1,

    // ---- SHA-2 family (FIPS 180-4) ----
    /// SHA-224 — 224-bit truncation of SHA-256 (FIPS 180-4 §6.3).
    Sha224,
    /// SHA-256 — 256-bit; the workhorse of modern PKI, TLS, and
    /// blockchain (FIPS 180-4 §6.2).
    Sha256,
    /// SHA-384 — 384-bit truncation of SHA-512 (FIPS 180-4 §6.5).
    Sha384,
    /// SHA-512 — 512-bit; uses 64-bit words, faster than SHA-256 on
    /// 64-bit CPUs without SHA-NI (FIPS 180-4 §6.4).
    Sha512,
    /// SHA-512/224 — 224-bit truncation of SHA-512 with a distinct IV
    /// (FIPS 180-4 §5.3.6.1).
    Sha512_224,
    /// SHA-512/256 — 256-bit truncation of SHA-512 with a distinct IV
    /// (FIPS 180-4 §5.3.6.2).
    Sha512_256,

    // ---- SHA-3 family (FIPS 202, Keccak-based sponge) ----
    /// SHA3-224 — 224-bit Keccak sponge with capacity 448 (FIPS 202 §6.1).
    Sha3_224,
    /// SHA3-256 — 256-bit Keccak sponge with capacity 512 (FIPS 202 §6.1).
    Sha3_256,
    /// SHA3-384 — 384-bit Keccak sponge with capacity 768 (FIPS 202 §6.1).
    Sha3_384,
    /// SHA3-512 — 512-bit Keccak sponge with capacity 1024 (FIPS 202 §6.1).
    Sha3_512,

    // ---- SHAKE XOFs (FIPS 202 §6.2) ----
    /// SHAKE128 — extendable-output function with capacity 256.  Used by
    /// post-quantum schemes (ML-DSA, ML-KEM, SLH-DSA) for arbitrary-length
    /// pseudorandom output.  Has no fixed digest size; output length is
    /// supplied at finalization.
    Shake128,
    /// SHAKE256 — extendable-output function with capacity 512.  Used by
    /// SLH-DSA, certain ML-DSA parameter sets, and ML-KEM `H/G` derivation.
    /// Has no fixed digest size; output length is supplied at finalization.
    Shake256,

    // ---- MD-family hashes (legacy / deprecated) ----
    /// MD5 — 128-bit (RFC 1321).  Cryptographically broken; retained for
    /// HMAC-MD5 in legacy TLS PRFs, PKCS#12 MAC, and tools/log integration.
    Md5,
    /// MD5-SHA1 composite — produces 36-byte output by concatenating MD5
    /// (16 bytes) with SHA-1 (20 bytes).  Used by TLS 1.0 / 1.1 and `SSLv3`
    /// for the Finished MAC and `CertificateVerify` hash.
    Md5Sha1,
    /// MD2 — 128-bit (RFC 1319).  Designed for 8-bit CPUs;
    /// cryptographically broken.  Retained only for decoding legacy
    /// certificates and PGP key rings.
    Md2,
    /// MD4 — 128-bit (RFC 1320).  Cryptographically broken; encountered
    /// inside NTLM, S/MIME compatibility chains, and `NetNTLMv1` HMAC.
    Md4,
    /// MDC-2 — 128-bit DES-based Modification Detection Code (ISO/IEC
    /// 10118-2).  Retained for legacy banking and government protocols
    /// that require DES-derived integrity tags.
    Mdc2,

    // ---- RIPEMD / Whirlpool ----
    /// RIPEMD-160 — 160-bit (Bosselaers / Dobbertin / Preneel 1996; RFC
    /// 4231 reference).  Used by Bitcoin address derivation and some GPG
    /// key-ID calculations.
    Ripemd160,
    /// Whirlpool — 512-bit (NESSIE 2003, ISO/IEC 10118-3:2018).  Built
    /// from a dedicated 10-round block cipher with the Miyaguchi-Preneel
    /// construction.
    Whirlpool,

    // ---- Chinese national standard ----
    /// SM3 — 256-bit (GB/T 32905-2016).  Mandatory for GM-compliant TLS
    /// suites, SM2 signatures, and Chinese government PKI.
    Sm3,

    // ---- BLAKE2 (RFC 7693) ----
    /// BLAKE2b-256 — `BLAKE2b` configured for 256-bit output (RFC 7693
    /// §2.1).  Streaming compression and finalization live in
    /// `openssl-provider::implementations::digests::blake2` per AAP
    /// §0.5.1; the variant exists here so callers can name the algorithm
    /// without depending on the provider crate.
    Blake2b256,
    /// BLAKE2b-512 — `BLAKE2b` configured for 512-bit output (RFC 7693
    /// §2.1).  See [`Blake2b256`](DigestAlgorithm::Blake2b256) for the
    /// streaming-vs-naming dispatch note.
    Blake2b512,
    /// BLAKE2s-256 — `BLAKE2s` configured for 256-bit output (RFC 7693
    /// §2.2).  32-bit word-size variant optimized for embedded devices
    /// and hardware without 64-bit ALUs.
    Blake2s256,
}

impl DigestAlgorithm {
    /// Returns the output digest size in bytes.
    ///
    /// For the [`Shake128`](DigestAlgorithm::Shake128) and
    /// [`Shake256`](DigestAlgorithm::Shake256) extendable-output functions
    /// this method returns `0` to signal that the size is determined at
    /// finalization rather than at algorithm-selection time — callers that
    /// need a fixed XOF output length should use the
    /// [`shake128`]/[`shake256`] one-shot functions, which take an
    /// explicit `output_len` argument.
    ///
    /// # R9 justification for `match_same_arms`
    ///
    /// Several distinct algorithms produce the same output size (e.g.
    /// SHA-256, SM3, and BLAKE2s-256 all produce 32 bytes).  Merging arms
    /// with `|` would obscure the per-algorithm semantics and complicate
    /// future divergence (e.g. adding a hardware variant whose digest
    /// length differs from its software counterpart).  Each variant is
    /// listed individually for clarity and maintainability.
    #[must_use]
    pub fn digest_size(&self) -> usize {
        match self {
            // 20-byte hashes (SHA-1, RIPEMD-160).
            Self::Sha1 | Self::Ripemd160 => 20,
            // 28-byte hashes (224-bit family).
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            // 32-byte hashes (256-bit family).
            Self::Sha256
            | Self::Sha512_256
            | Self::Sha3_256
            | Self::Sm3
            | Self::Blake2b256
            | Self::Blake2s256 => 32,
            // 36-byte composite (TLS legacy MD5 || SHA-1).
            Self::Md5Sha1 => 36,
            // 48-byte hashes (384-bit family).
            Self::Sha384 | Self::Sha3_384 => 48,
            // 64-byte hashes (512-bit family).
            Self::Sha512 | Self::Sha3_512 | Self::Whirlpool | Self::Blake2b512 => 64,
            // 16-byte hashes (legacy MD-family).
            Self::Md5 | Self::Md2 | Self::Md4 | Self::Mdc2 => 16,
            // XOFs — output length is supplied at finalization, not at
            // algorithm selection.  Reporting `0` mirrors the upstream C
            // `EVP_MD_get_size()` semantics for SHAKE registrations.
            Self::Shake128 | Self::Shake256 => 0,
        }
    }

    /// Returns the internal compression-function block size in bytes.
    ///
    /// This is the rate (`r = b - c`) for sponge-based constructions and
    /// the message-schedule input width for Merkle-Damgård constructions.
    /// HMAC and HKDF use this value as the inner/outer pad length per
    /// RFC 2104 §2.
    ///
    /// # R9 justification for `match_same_arms`
    ///
    /// Many algorithms share a 64-byte block size by historical accident
    /// (MD5, SHA-1, SHA-256, SM3, RIPEMD-160, Whirlpool, Blake2s-256), but
    /// each has independent semantic meaning.  Merging arms with `|`
    /// would obscure the per-algorithm dispatch and complicate future
    /// changes (e.g. adding a hardware variant with a different block
    /// size).  Each variant is listed individually for clarity.
    #[must_use]
    pub fn block_size(&self) -> usize {
        match self {
            // 64-byte block — Merkle-Damgård 32-bit-word family + Whirlpool
            // (which uses a 64-byte block over 64-bit words) + Blake2s.
            Self::Sha1
            | Self::Sha224
            | Self::Sha256
            | Self::Md5
            | Self::Md4
            | Self::Md5Sha1
            | Self::Ripemd160
            | Self::Sm3
            | Self::Whirlpool
            | Self::Blake2s256 => 64,
            // 128-byte block — SHA-2 64-bit-word family + Blake2b.
            Self::Sha384
            | Self::Sha512
            | Self::Sha512_224
            | Self::Sha512_256
            | Self::Blake2b256
            | Self::Blake2b512 => 128,
            // SHA-3 / SHAKE rates per FIPS 202 Table 3 (rate = b - c, b = 1600).
            // SHA3-224: c = 448 → r = 1152 bits = 144 bytes.
            Self::Sha3_224 => 144,
            // SHA3-256 / SHAKE256: c = 512 → r = 1088 bits = 136 bytes.
            Self::Sha3_256 | Self::Shake256 => 136,
            // SHA3-384: c = 768 → r = 832 bits = 104 bytes.
            Self::Sha3_384 => 104,
            // SHA3-512: c = 1024 → r = 576 bits = 72 bytes.
            Self::Sha3_512 => 72,
            // SHAKE128: c = 256 → r = 1344 bits = 168 bytes.
            Self::Shake128 => 168,
            // 16-byte block — MD2 (16-byte messages, AES-S-box-based) and
            // MDC-2 (DES-block-derived: 8 bytes per DES half + 8 bytes
            // for the second pass, packed as a 16-byte effective block).
            Self::Md2 | Self::Mdc2 => 16,
        }
    }

    /// Returns the canonical algorithm name string.
    ///
    /// The strings returned here are the names used by the upstream
    /// OpenSSL `OSSL_DIGEST_NAME_*` macros and reported by
    /// `EVP_MD_get0_name()`.  They are used as `OSSL_PARAM` dispatch keys
    /// by the provider layer (`openssl-provider::implementations::digests`)
    /// and as `tracing` span attributes for observability per AAP §0.8.5.
    ///
    /// The inverse direction — string → enum — is provided by the
    /// [`algorithm_from_name`] helper, which accepts both these canonical
    /// names and several common aliases.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha224 => "SHA2-224",
            Self::Sha256 => "SHA2-256",
            Self::Sha384 => "SHA2-384",
            Self::Sha512 => "SHA2-512",
            Self::Sha512_224 => "SHA2-512/224",
            Self::Sha512_256 => "SHA2-512/256",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Shake128 => "SHAKE128",
            Self::Shake256 => "SHAKE256",
            Self::Md5 => "MD5",
            Self::Md5Sha1 => "MD5-SHA1",
            Self::Md2 => "MD2",
            Self::Md4 => "MD4",
            Self::Mdc2 => "MDC2",
            Self::Ripemd160 => "RIPEMD160",
            Self::Whirlpool => "WHIRLPOOL",
            Self::Sm3 => "SM3",
            Self::Blake2b256 => "BLAKE2B-256",
            Self::Blake2b512 => "BLAKE2B-512",
            Self::Blake2s256 => "BLAKE2S-256",
        }
    }

    /// Returns `true` if this algorithm is considered legacy or
    /// cryptographically broken and should not be used for new designs.
    ///
    /// The legacy classification corresponds to algorithms that have
    /// either been published with practical collision attacks (MD2, MD4,
    /// MD5, SHA-1) or that are retained solely for protocol
    /// interoperability with deprecated standards (MD5-SHA1 for TLS
    /// 1.0/1.1, MDC-2 for legacy banking).  Callers can use this method
    /// to surface deprecation warnings or to reject algorithm selection
    /// in security-sensitive contexts (e.g. new certificate issuance).
    ///
    /// Note that this is *advisory* and does not gate access to the
    /// algorithm — the underlying implementations remain available for
    /// legitimate use cases like decoding existing data or running
    /// compatibility-suite tests.  RIPEMD-160 is *not* classified as
    /// legacy here because it remains in active use by Bitcoin address
    /// derivation; SM3 is not legacy because it is the current Chinese
    /// national standard; BLAKE2 variants are modern.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        matches!(
            self,
            Self::Sha1 | Self::Md5 | Self::Md5Sha1 | Self::Md2 | Self::Md4 | Self::Mdc2
        )
    }
}

// =============================================================================
// DigestContext type alias
// =============================================================================

/// Runtime-dispatched digest context — a boxed implementation of the
/// [`Digest`] trait.
///
/// Returning `Box<dyn Digest>` from [`create_digest`] enables algorithm
/// selection at *runtime* without the caller needing to know the concrete
/// context type.  This mirrors the C `EVP_MD_CTX *` pattern: callers hold a
/// pointer to an opaque context and dispatch through a vtable
/// (function-pointer table in C, trait object vtable in Rust).
///
/// `dyn Digest` is `Send + Sync` because the trait inherits those bounds —
/// every concrete context type in this module derives `Zeroize` /
/// `ZeroizeOnDrop` and contains only owned plain-data state, so they are
/// safely transferable across thread boundaries.
pub type DigestContext = Box<dyn Digest>;

// =============================================================================
// Factory function
// =============================================================================

/// Construct a new digest context for the requested algorithm.
///
/// This is the algorithm-dispatch entry point for the hash module — it
/// converts a [`DigestAlgorithm`] enum value into a concrete boxed digest
/// implementation, replacing the C `EVP_get_digestbyname()` +
/// `EVP_MD_CTX_new()` two-step with a single safe constructor.  Callers
/// receive a [`DigestContext`] (`Box<dyn Digest>`) ready for `update` /
/// `finalize`.
///
/// # Algorithm coverage
///
/// All fixed-output algorithms in [`DigestAlgorithm`] are constructible
/// through this factory.  Two categories are *not* dispatched here:
///
/// * **SHAKE XOFs** — [`Shake128`](DigestAlgorithm::Shake128) and
///   [`Shake256`](DigestAlgorithm::Shake256) require an explicit
///   `output_len` argument that this fixed-output factory cannot supply.
///   Callers should construct a [`ShakeContext`](sha::ShakeContext)
///   directly via [`sha::ShakeContext::shake128`] /
///   [`sha::ShakeContext::shake256`] or use the [`shake128`] / [`shake256`]
///   one-shot helpers.
/// * **BLAKE2 variants** — [`Blake2b256`](DigestAlgorithm::Blake2b256),
///   [`Blake2b512`](DigestAlgorithm::Blake2b512), and
///   [`Blake2s256`](DigestAlgorithm::Blake2s256) have their streaming
///   compression / finalization implemented in
///   `openssl-provider::implementations::digests::blake2` per AAP §0.5.1;
///   only the [`Blake2Algorithm`](legacy::Blake2Algorithm) /
///   [`Blake2Context`](legacy::Blake2Context) type markers live here.
///   Callers should fetch BLAKE2 through the provider layer.
/// * **MDC-2** — depends on the DES symmetric engine and is therefore
///   gated behind the `des` Cargo feature.  When the feature is
///   disabled, requesting [`Mdc2`](DigestAlgorithm::Mdc2) returns
///   [`CryptoError::AlgorithmNotFound`].
///
/// # Errors
///
/// Returns [`CryptoError::AlgorithmNotFound`] when the requested algorithm
/// is one of the categories listed above (SHAKE XOFs, BLAKE2 variants,
/// or MDC-2 without the `des` feature).  All other variants always
/// succeed — every fixed-output context constructor in this module is
/// infallible.
///
/// # Observability
///
/// Emits a `tracing::trace!` event named with the canonical algorithm
/// name on every invocation, enabling operators to audit algorithm
/// selection and correlate digest creation with broader request-flow
/// spans (HMAC, KDF, signature, TLS handshake).  See AAP §0.8.5 for the
/// observability rule.
///
/// # Examples
///
/// ```no_run
/// use openssl_crypto::hash::{create_digest, DigestAlgorithm};
///
/// let mut ctx = create_digest(DigestAlgorithm::Sha256)
///     .expect("SHA-256 is always available");
/// ctx.update(b"hello world").unwrap();
/// let digest = ctx.finalize().unwrap();
/// assert_eq!(digest.len(), 32);
/// ```
#[allow(deprecated)] // Legacy context constructors carry #[deprecated] attributes; this allow propagates to all match arms so callers do not need a local allow at each call site.
pub fn create_digest(algorithm: DigestAlgorithm) -> CryptoResult<DigestContext> {
    trace!(algorithm = %algorithm.name(), "Creating digest context");
    match algorithm {
        // ---- SHA family — see `sha` submodule for the implementations ----
        DigestAlgorithm::Sha1 => Ok(Box::new(sha::Sha1Context::new())),
        DigestAlgorithm::Sha224 => Ok(Box::new(sha::Sha256Context::sha224())),
        DigestAlgorithm::Sha256 => Ok(Box::new(sha::Sha256Context::sha256())),
        DigestAlgorithm::Sha384 => Ok(Box::new(sha::Sha512Context::sha384())),
        DigestAlgorithm::Sha512 => Ok(Box::new(sha::Sha512Context::sha512())),
        DigestAlgorithm::Sha512_224 => Ok(Box::new(sha::Sha512Context::sha512_224())),
        DigestAlgorithm::Sha512_256 => Ok(Box::new(sha::Sha512Context::sha512_256())),
        DigestAlgorithm::Sha3_224 => Ok(Box::new(sha::Sha3Context::sha3_224())),
        DigestAlgorithm::Sha3_256 => Ok(Box::new(sha::Sha3Context::sha3_256())),
        DigestAlgorithm::Sha3_384 => Ok(Box::new(sha::Sha3Context::sha3_384())),
        DigestAlgorithm::Sha3_512 => Ok(Box::new(sha::Sha3Context::sha3_512())),

        // ---- MD-family — `md5` submodule ----
        DigestAlgorithm::Md5 => Ok(Box::new(md5::Md5Context::new())),
        DigestAlgorithm::Md5Sha1 => Ok(Box::new(md5::Md5Sha1Context::new())),

        // ---- Legacy / regional / specialized — `legacy` submodule ----
        DigestAlgorithm::Md2 => Ok(Box::new(legacy::Md2Context::new())),
        DigestAlgorithm::Md4 => Ok(Box::new(legacy::Md4Context::new())),
        DigestAlgorithm::Ripemd160 => Ok(Box::new(legacy::Ripemd160Context::new())),
        DigestAlgorithm::Whirlpool => Ok(Box::new(legacy::WhirlpoolContext::new())),
        DigestAlgorithm::Sm3 => Ok(Box::new(legacy::Sm3Context::new())),

        // ---- MDC-2 — only available with the `des` feature ----
        #[cfg(feature = "des")]
        DigestAlgorithm::Mdc2 => Ok(Box::new(legacy::Mdc2Context::new())),

        // ---- Algorithms not constructible via this fixed-output factory ----
        //
        // SHAKE XOFs need an explicit output length; BLAKE2 lives in the
        // provider crate per AAP §0.5.1; MDC-2 is unavailable when the
        // `des` feature is disabled.  Returning AlgorithmNotFound mirrors
        // the upstream C `EVP_MD_fetch()` returning `NULL` for an
        // unrecognized name, which is the closest semantic match.
        DigestAlgorithm::Shake128
        | DigestAlgorithm::Shake256
        | DigestAlgorithm::Blake2b256
        | DigestAlgorithm::Blake2b512
        | DigestAlgorithm::Blake2s256 => {
            Err(CryptoError::AlgorithmNotFound(algorithm.name().to_string()))
        }

        // MDC-2 without the `des` feature — same error path as above.
        #[cfg(not(feature = "des"))]
        DigestAlgorithm::Mdc2 => Err(CryptoError::AlgorithmNotFound(algorithm.name().to_string())),
    }
}

// =============================================================================
// Lookup by name
// =============================================================================

/// Resolve a [`DigestAlgorithm`] from its canonical name or a common alias.
///
/// This is the Rust-idiomatic equivalent of `EVP_get_digestbyname()` from
/// the C API — it converts a textual algorithm identifier (as found in
/// configuration files, CLI arguments, X.509 signature algorithm OIDs,
/// `OSSL_PARAM` dispatch keys, etc.) into the strongly-typed enum variant.
///
/// Comparison is case-insensitive: the input is uppercased before
/// matching, so callers can pass the name in any case.  Several common
/// aliases are recognized for each algorithm to match the names used by
/// IANA cipher-suite registrations, RFC text, X.509 OID descriptions, and
/// upstream OpenSSL `EVP_*` aliases.
///
/// # Recognized aliases
///
/// | Variant              | Names accepted                                                                |
/// |----------------------|-------------------------------------------------------------------------------|
/// | `Sha1`               | `"SHA1"`, `"SHA-1"`                                                           |
/// | `Sha224`             | `"SHA224"`, `"SHA-224"`, `"SHA2-224"`                                         |
/// | `Sha256`             | `"SHA256"`, `"SHA-256"`, `"SHA2-256"`                                         |
/// | `Sha384`             | `"SHA384"`, `"SHA-384"`, `"SHA2-384"`                                         |
/// | `Sha512`             | `"SHA512"`, `"SHA-512"`, `"SHA2-512"`                                         |
/// | `Sha512_224`         | `"SHA512-224"`, `"SHA-512/224"`, `"SHA2-512/224"`                             |
/// | `Sha512_256`         | `"SHA512-256"`, `"SHA-512/256"`, `"SHA2-512/256"`                             |
/// | `Sha3_224`           | `"SHA3-224"`                                                                  |
/// | `Sha3_256`           | `"SHA3-256"`                                                                  |
/// | `Sha3_384`           | `"SHA3-384"`                                                                  |
/// | `Sha3_512`           | `"SHA3-512"`                                                                  |
/// | `Shake128`           | `"SHAKE128"`, `"SHAKE-128"`                                                   |
/// | `Shake256`           | `"SHAKE256"`, `"SHAKE-256"`                                                   |
/// | `Md5`                | `"MD5"`                                                                       |
/// | `Md5Sha1`            | `"MD5-SHA1"`, `"MD5SHA1"`                                                     |
/// | `Md2`                | `"MD2"`                                                                       |
/// | `Md4`                | `"MD4"`                                                                       |
/// | `Mdc2`               | `"MDC2"`, `"MDC-2"`                                                           |
/// | `Ripemd160`          | `"RIPEMD160"`, `"RIPEMD-160"`, `"RMD160"`                                     |
/// | `Whirlpool`          | `"WHIRLPOOL"`                                                                 |
/// | `Sm3`                | `"SM3"`                                                                       |
/// | `Blake2b256`         | `"BLAKE2B-256"`, `"BLAKE2B256"`                                               |
/// | `Blake2b512`         | `"BLAKE2B-512"`, `"BLAKE2B512"`, `"BLAKE2B"`                                  |
/// | `Blake2s256`         | `"BLAKE2S-256"`, `"BLAKE2S256"`, `"BLAKE2S"`                                  |
///
/// # Returns
///
/// `Some(DigestAlgorithm)` if `name` matches any recognized form;
/// `None` if the name is not recognized.  Returning `Option<T>` rather
/// than a sentinel value follows Rule R5.
///
/// # Examples
///
/// ```no_run
/// use openssl_crypto::hash::{algorithm_from_name, DigestAlgorithm};
///
/// assert_eq!(algorithm_from_name("sha256"), Some(DigestAlgorithm::Sha256));
/// assert_eq!(algorithm_from_name("SHA-256"), Some(DigestAlgorithm::Sha256));
/// assert_eq!(algorithm_from_name("not-a-hash"), None);
/// ```
#[must_use]
pub fn algorithm_from_name(name: &str) -> Option<DigestAlgorithm> {
    // Case-insensitive matching: uppercase the input so callers can pass
    // the name in any case (lowercase from CLI arguments, mixed case from
    // config files, uppercase from X.509 algorithm-OID descriptions).
    match name.to_uppercase().as_str() {
        // SHA-1 / SHA-2 family — accept both modern (SHA2-*) and legacy
        // (SHA-* / SHA*) spellings used by various upstream callers.
        "SHA1" | "SHA-1" => Some(DigestAlgorithm::Sha1),
        "SHA224" | "SHA-224" | "SHA2-224" => Some(DigestAlgorithm::Sha224),
        "SHA256" | "SHA-256" | "SHA2-256" => Some(DigestAlgorithm::Sha256),
        "SHA384" | "SHA-384" | "SHA2-384" => Some(DigestAlgorithm::Sha384),
        "SHA512" | "SHA-512" | "SHA2-512" => Some(DigestAlgorithm::Sha512),
        "SHA512-224" | "SHA-512/224" | "SHA2-512/224" => Some(DigestAlgorithm::Sha512_224),
        "SHA512-256" | "SHA-512/256" | "SHA2-512/256" => Some(DigestAlgorithm::Sha512_256),

        // SHA-3 family — single canonical spelling.
        "SHA3-224" => Some(DigestAlgorithm::Sha3_224),
        "SHA3-256" => Some(DigestAlgorithm::Sha3_256),
        "SHA3-384" => Some(DigestAlgorithm::Sha3_384),
        "SHA3-512" => Some(DigestAlgorithm::Sha3_512),

        // SHAKE XOFs — accept both with and without separator.
        "SHAKE128" | "SHAKE-128" => Some(DigestAlgorithm::Shake128),
        "SHAKE256" | "SHAKE-256" => Some(DigestAlgorithm::Shake256),

        // MD-family.
        "MD5" => Some(DigestAlgorithm::Md5),
        "MD5-SHA1" | "MD5SHA1" => Some(DigestAlgorithm::Md5Sha1),
        "MD2" => Some(DigestAlgorithm::Md2),
        "MD4" => Some(DigestAlgorithm::Md4),
        "MDC2" | "MDC-2" => Some(DigestAlgorithm::Mdc2),

        // RIPEMD / Whirlpool / SM3.
        "RIPEMD160" | "RIPEMD-160" | "RMD160" => Some(DigestAlgorithm::Ripemd160),
        "WHIRLPOOL" => Some(DigestAlgorithm::Whirlpool),
        "SM3" => Some(DigestAlgorithm::Sm3),

        // BLAKE2 — accept the bare names ("BLAKE2B" / "BLAKE2S") as
        // synonyms for the 512/256-bit variants respectively, matching
        // RFC 7693 §4 default-output conventions.
        "BLAKE2B-256" | "BLAKE2B256" => Some(DigestAlgorithm::Blake2b256),
        "BLAKE2B-512" | "BLAKE2B512" | "BLAKE2B" => Some(DigestAlgorithm::Blake2b512),
        "BLAKE2S-256" | "BLAKE2S256" | "BLAKE2S" => Some(DigestAlgorithm::Blake2s256),

        _ => None,
    }
}

// =============================================================================
// Re-exports
// =============================================================================
//
// These re-exports preserve the existing public surface of the `hash`
// module so that downstream crates (openssl-provider, openssl-cli,
// openssl-crypto::evp, openssl-crypto::mac, openssl-crypto::pqc, the
// X.509 verifier, and the test suite) continue to import their dependencies
// from the same paths as before.  Adding the new types above is purely
// additive — none of the names below has been removed or renamed.

// SHA family — core trait + concrete contexts + the `ShaAlgorithm`-based
// factory used by HMAC and the X.509 chain verifier.  `Digest`, `KeccakState`,
// and the `Sha*Context` types are also re-exported here so that callers can
// say `use crate::hash::Digest;` rather than the more verbose
// `use crate::hash::sha::Digest;`.
pub use sha::{
    create_sha_digest, Digest, KeccakState, Sha1Context, Sha256Context, Sha3Context, Sha512Context,
    ShaAlgorithm, ShakeContext,
};

// SHA convenience one-shot functions — these accept a byte slice and return
// the digest as `CryptoResult<Vec<u8>>`.  They are the most common entry
// point for callers that just need a fixed-output hash without configuring
// a streaming context.
//
// R9 justification for `#[allow(deprecated)]`:
//   `sha::sha1` carries `#[deprecated]` because SHA-1 is cryptographically
//   broken.  The deprecation still fires at *call sites* outside this module,
//   so callers receive the warning when they invoke `sha1`.  This `allow`
//   silences the warning *only* at the re-export boundary, which would
//   otherwise produce a useless warning on every consumer of
//   `crate::hash::*`.
#[allow(deprecated)]
pub use sha::{sha1, sha224, sha256, sha384, sha512, shake128, shake256};

// MD5 types — kept behind `#[allow(deprecated)]` because both the
// `Md5Context::new` constructor and the `md5` one-shot function carry
// `#[deprecated]` attributes (MD5 is cryptographically broken; the
// re-exports exist solely for AAP §0.5.1 parity with `crypto/md5/*.c`).
//
// R9 justification for `#[allow(deprecated)]`:
//   The deprecated attributes still fire at *call sites* outside this
//   module, so callers receive the deprecation warning when they invoke
//   these symbols.  This `allow` silences the warning *only* at the
//   re-export boundary, which would otherwise produce a useless warning
//   on every consumer of `crate::hash::*`.
#[allow(deprecated)]
pub use md5::{md5, Md5Context, Md5Sha1Context};

// Legacy hash family — MD2/MD4/RIPEMD-160/SM3/Whirlpool plus the
// `LegacyAlgorithm`-based factory.  The same `#[allow(deprecated)]`
// rationale applies as for the MD5 re-exports above.  MDC-2 is gated
// separately below because it depends on DES.
#[allow(deprecated)]
pub use legacy::{
    create_legacy_digest, md2, md4, ripemd160, sm3, whirlpool, LegacyAlgorithm, Md2Context,
    Md4Context, Ripemd160Context, Sm3Context, WhirlpoolContext,
};

// MDC-2 — constructed from DES; gate its re-exports behind the `des`
// feature so that builds with `--no-default-features` (or with `des`
// explicitly disabled) do not reference the DES symmetric module.
#[cfg(feature = "des")]
#[allow(deprecated)]
pub use legacy::{mdc2, Mdc2Context};

// BLAKE2 type markers (RFC 7693).  These are public type-level identifiers
// used by downstream crates (openssl-ffi, openssl-cli `dgst`, future TLS
// suites) to refer to BLAKE2 variants without depending on the
// `openssl-provider` crate.  The streaming compression and finalization
// for BLAKE2 reside in `openssl-provider::implementations::digests::blake2`
// per AAP §0.5.1 — this is a deliberate architectural separation that
// allows downstream code to *name* the algorithm without pulling in the
// full provider stack.
pub use legacy::{Blake2Algorithm, Blake2Context};

// =============================================================================
// Unit tests for the module-level types and functions
// =============================================================================

#[cfg(test)]
mod tests {
    //! Tests for the `mod.rs`-defined types: [`DigestAlgorithm`],
    //! [`create_digest`], and [`algorithm_from_name`].
    //!
    //! Per-algorithm correctness is exercised by the tests inside each
    //! submodule (`sha::tests`, `md5::tests`, `legacy::tests`) and by the
    //! integration test in [`crate::tests::test_hash`].  These tests
    //! complement those by verifying the module-level dispatch and
    //! lookup logic.

    #![allow(clippy::expect_used)] // Tests call .expect() on known-good Results.
    #![allow(clippy::unwrap_used)] // Tests call .unwrap() on values guaranteed to be Some/Ok.

    use super::*;

    /// All 24 enum variants enumerate without duplicates and the
    /// `name()` method is a bijection (no two variants share a name).
    #[test]
    fn digest_algorithm_names_are_unique() {
        let all = [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha512_224,
            DigestAlgorithm::Sha512_256,
            DigestAlgorithm::Sha3_224,
            DigestAlgorithm::Sha3_256,
            DigestAlgorithm::Sha3_384,
            DigestAlgorithm::Sha3_512,
            DigestAlgorithm::Shake128,
            DigestAlgorithm::Shake256,
            DigestAlgorithm::Md5,
            DigestAlgorithm::Md5Sha1,
            DigestAlgorithm::Md2,
            DigestAlgorithm::Md4,
            DigestAlgorithm::Mdc2,
            DigestAlgorithm::Ripemd160,
            DigestAlgorithm::Whirlpool,
            DigestAlgorithm::Sm3,
            DigestAlgorithm::Blake2b256,
            DigestAlgorithm::Blake2b512,
            DigestAlgorithm::Blake2s256,
        ];
        assert_eq!(all.len(), 24, "DigestAlgorithm must have 24 variants");
        let mut names: Vec<&'static str> = all.iter().map(|a| a.name()).collect();
        names.sort_unstable();
        let original_len = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            original_len,
            "DigestAlgorithm::name() must be injective (no two variants share a name)"
        );
    }

    /// `digest_size` returns the FIPS / RFC-specified output sizes.
    #[test]
    fn digest_size_matches_specifications() {
        assert_eq!(DigestAlgorithm::Sha1.digest_size(), 20);
        assert_eq!(DigestAlgorithm::Sha224.digest_size(), 28);
        assert_eq!(DigestAlgorithm::Sha256.digest_size(), 32);
        assert_eq!(DigestAlgorithm::Sha384.digest_size(), 48);
        assert_eq!(DigestAlgorithm::Sha512.digest_size(), 64);
        assert_eq!(DigestAlgorithm::Sha512_224.digest_size(), 28);
        assert_eq!(DigestAlgorithm::Sha512_256.digest_size(), 32);
        assert_eq!(DigestAlgorithm::Sha3_224.digest_size(), 28);
        assert_eq!(DigestAlgorithm::Sha3_256.digest_size(), 32);
        assert_eq!(DigestAlgorithm::Sha3_384.digest_size(), 48);
        assert_eq!(DigestAlgorithm::Sha3_512.digest_size(), 64);
        // XOFs report 0 (output length supplied at finalization).
        assert_eq!(DigestAlgorithm::Shake128.digest_size(), 0);
        assert_eq!(DigestAlgorithm::Shake256.digest_size(), 0);
        assert_eq!(DigestAlgorithm::Md5.digest_size(), 16);
        assert_eq!(DigestAlgorithm::Md5Sha1.digest_size(), 36);
        assert_eq!(DigestAlgorithm::Md2.digest_size(), 16);
        assert_eq!(DigestAlgorithm::Md4.digest_size(), 16);
        assert_eq!(DigestAlgorithm::Mdc2.digest_size(), 16);
        assert_eq!(DigestAlgorithm::Ripemd160.digest_size(), 20);
        assert_eq!(DigestAlgorithm::Whirlpool.digest_size(), 64);
        assert_eq!(DigestAlgorithm::Sm3.digest_size(), 32);
        assert_eq!(DigestAlgorithm::Blake2b256.digest_size(), 32);
        assert_eq!(DigestAlgorithm::Blake2b512.digest_size(), 64);
        assert_eq!(DigestAlgorithm::Blake2s256.digest_size(), 32);
    }

    /// `block_size` returns the compression-function block sizes per the
    /// upstream specifications.
    #[test]
    fn block_size_matches_specifications() {
        // 64-byte block — Merkle-Damgård 32-bit-word family.
        assert_eq!(DigestAlgorithm::Sha1.block_size(), 64);
        assert_eq!(DigestAlgorithm::Sha224.block_size(), 64);
        assert_eq!(DigestAlgorithm::Sha256.block_size(), 64);
        assert_eq!(DigestAlgorithm::Md5.block_size(), 64);
        assert_eq!(DigestAlgorithm::Md4.block_size(), 64);
        assert_eq!(DigestAlgorithm::Md5Sha1.block_size(), 64);
        assert_eq!(DigestAlgorithm::Ripemd160.block_size(), 64);
        assert_eq!(DigestAlgorithm::Sm3.block_size(), 64);
        assert_eq!(DigestAlgorithm::Whirlpool.block_size(), 64);
        assert_eq!(DigestAlgorithm::Blake2s256.block_size(), 64);
        // 128-byte block — SHA-2 64-bit-word family + Blake2b.
        assert_eq!(DigestAlgorithm::Sha384.block_size(), 128);
        assert_eq!(DigestAlgorithm::Sha512.block_size(), 128);
        assert_eq!(DigestAlgorithm::Sha512_224.block_size(), 128);
        assert_eq!(DigestAlgorithm::Sha512_256.block_size(), 128);
        assert_eq!(DigestAlgorithm::Blake2b256.block_size(), 128);
        assert_eq!(DigestAlgorithm::Blake2b512.block_size(), 128);
        // SHA-3 / SHAKE rates per FIPS 202.
        assert_eq!(DigestAlgorithm::Sha3_224.block_size(), 144);
        assert_eq!(DigestAlgorithm::Sha3_256.block_size(), 136);
        assert_eq!(DigestAlgorithm::Sha3_384.block_size(), 104);
        assert_eq!(DigestAlgorithm::Sha3_512.block_size(), 72);
        assert_eq!(DigestAlgorithm::Shake128.block_size(), 168);
        assert_eq!(DigestAlgorithm::Shake256.block_size(), 136);
        // 16-byte block — MD2 / MDC-2.
        assert_eq!(DigestAlgorithm::Md2.block_size(), 16);
        assert_eq!(DigestAlgorithm::Mdc2.block_size(), 16);
    }

    /// `is_legacy` flags broken / deprecated algorithms.
    #[test]
    fn is_legacy_classification() {
        // Broken or deprecated: SHA-1, MD-family, MDC-2, MD5-SHA1.
        assert!(DigestAlgorithm::Sha1.is_legacy());
        assert!(DigestAlgorithm::Md5.is_legacy());
        assert!(DigestAlgorithm::Md5Sha1.is_legacy());
        assert!(DigestAlgorithm::Md2.is_legacy());
        assert!(DigestAlgorithm::Md4.is_legacy());
        assert!(DigestAlgorithm::Mdc2.is_legacy());
        // Modern / national / regional standards: not legacy.
        assert!(!DigestAlgorithm::Sha256.is_legacy());
        assert!(!DigestAlgorithm::Sha3_256.is_legacy());
        assert!(!DigestAlgorithm::Sm3.is_legacy());
        assert!(!DigestAlgorithm::Ripemd160.is_legacy());
        assert!(!DigestAlgorithm::Blake2b256.is_legacy());
    }

    /// `create_digest` produces a valid context for every fixed-output
    /// algorithm, and the produced digest matches the expected length.
    #[test]
    fn create_digest_produces_expected_length() {
        let fixed_output = [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha512_224,
            DigestAlgorithm::Sha512_256,
            DigestAlgorithm::Sha3_224,
            DigestAlgorithm::Sha3_256,
            DigestAlgorithm::Sha3_384,
            DigestAlgorithm::Sha3_512,
            DigestAlgorithm::Md5,
            DigestAlgorithm::Md5Sha1,
            DigestAlgorithm::Md2,
            DigestAlgorithm::Md4,
            DigestAlgorithm::Ripemd160,
            DigestAlgorithm::Whirlpool,
            DigestAlgorithm::Sm3,
        ];
        for alg in fixed_output {
            let mut ctx = create_digest(alg)
                .unwrap_or_else(|e| panic!("create_digest({}) failed: {e}", alg.name()));
            ctx.update(b"abc").unwrap();
            let digest = ctx.finalize().unwrap();
            assert_eq!(
                digest.len(),
                alg.digest_size(),
                "digest length for {} must match algorithm digest_size",
                alg.name()
            );
        }
    }

    /// `create_digest` for MDC-2 succeeds when the `des` feature is on.
    #[cfg(feature = "des")]
    #[test]
    fn create_digest_mdc2_with_des_feature() {
        let mut ctx = create_digest(DigestAlgorithm::Mdc2).expect("MDC-2 with des feature");
        ctx.update(b"abc").unwrap();
        let digest = ctx.finalize().unwrap();
        assert_eq!(digest.len(), 16, "MDC-2 produces 128-bit output");
    }

    /// `create_digest` returns `AlgorithmNotFound` for SHAKE XOFs and
    /// BLAKE2 variants (these route through specialized constructors).
    #[test]
    fn create_digest_returns_not_found_for_unsupported() {
        for alg in [
            DigestAlgorithm::Shake128,
            DigestAlgorithm::Shake256,
            DigestAlgorithm::Blake2b256,
            DigestAlgorithm::Blake2b512,
            DigestAlgorithm::Blake2s256,
        ] {
            let result = create_digest(alg);
            assert!(
                matches!(result, Err(CryptoError::AlgorithmNotFound(_))),
                "expected AlgorithmNotFound for {}, got {:?}",
                alg.name(),
                result.as_ref().map(|_| "Ok"),
            );
        }
    }

    /// `algorithm_from_name` round-trips canonical names.
    #[test]
    fn algorithm_from_name_round_trip_canonical() {
        let all = [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha512_224,
            DigestAlgorithm::Sha512_256,
            DigestAlgorithm::Sha3_224,
            DigestAlgorithm::Sha3_256,
            DigestAlgorithm::Sha3_384,
            DigestAlgorithm::Sha3_512,
            DigestAlgorithm::Shake128,
            DigestAlgorithm::Shake256,
            DigestAlgorithm::Md5,
            DigestAlgorithm::Md5Sha1,
            DigestAlgorithm::Md2,
            DigestAlgorithm::Md4,
            DigestAlgorithm::Mdc2,
            DigestAlgorithm::Ripemd160,
            DigestAlgorithm::Whirlpool,
            DigestAlgorithm::Sm3,
            DigestAlgorithm::Blake2b256,
            DigestAlgorithm::Blake2b512,
            DigestAlgorithm::Blake2s256,
        ];
        for alg in all {
            let name = alg.name();
            assert_eq!(
                algorithm_from_name(name),
                Some(alg),
                "round-trip failed for canonical name '{name}'"
            );
        }
    }

    /// `algorithm_from_name` accepts case-insensitive input.
    #[test]
    fn algorithm_from_name_is_case_insensitive() {
        assert_eq!(algorithm_from_name("sha256"), Some(DigestAlgorithm::Sha256));
        assert_eq!(algorithm_from_name("Sha256"), Some(DigestAlgorithm::Sha256));
        assert_eq!(algorithm_from_name("SHA256"), Some(DigestAlgorithm::Sha256));
        assert_eq!(algorithm_from_name("sM3"), Some(DigestAlgorithm::Sm3));
    }

    /// `algorithm_from_name` accepts common aliases.
    #[test]
    fn algorithm_from_name_accepts_aliases() {
        assert_eq!(
            algorithm_from_name("SHA-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            algorithm_from_name("SHA-512/256"),
            Some(DigestAlgorithm::Sha512_256)
        );
        assert_eq!(
            algorithm_from_name("RIPEMD-160"),
            Some(DigestAlgorithm::Ripemd160)
        );
        assert_eq!(
            algorithm_from_name("RMD160"),
            Some(DigestAlgorithm::Ripemd160)
        );
        assert_eq!(algorithm_from_name("MDC-2"), Some(DigestAlgorithm::Mdc2));
        assert_eq!(
            algorithm_from_name("MD5SHA1"),
            Some(DigestAlgorithm::Md5Sha1)
        );
        assert_eq!(
            algorithm_from_name("BLAKE2B"),
            Some(DigestAlgorithm::Blake2b512)
        );
        assert_eq!(
            algorithm_from_name("BLAKE2S"),
            Some(DigestAlgorithm::Blake2s256)
        );
    }

    /// `algorithm_from_name` returns `None` for unrecognized input.
    #[test]
    fn algorithm_from_name_returns_none_for_unknown() {
        assert_eq!(algorithm_from_name(""), None);
        assert_eq!(algorithm_from_name("not-a-hash"), None);
        assert_eq!(algorithm_from_name("SHA999"), None);
        assert_eq!(algorithm_from_name("AES-256"), None); // Cipher, not hash.
    }

    /// The trait's `algorithm_name()` method on a context produced by
    /// `create_digest` returns a string compatible with
    /// `algorithm_from_name`.  This verifies the round-trip
    /// runtime-context → name → enum → context.
    #[test]
    fn create_digest_name_round_trip() {
        let alg = DigestAlgorithm::Sha256;
        let ctx = create_digest(alg).unwrap();
        // `algorithm_name()` returns the upstream OpenSSL canonical name
        // (e.g. "SHA-256"), which `algorithm_from_name` accepts as an alias.
        let name = ctx.algorithm_name();
        let parsed = algorithm_from_name(name)
            .unwrap_or_else(|| panic!("algorithm_from_name('{name}') returned None"));
        assert_eq!(parsed, alg);
    }
}
