//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) implementation per FIPS 205.
//!
//! This module provides key generation, signing, and verification for all 12 standardised
//! parameter sets defined by NIST FIPS 205 (August 2024):
//!
//! - **SLH-DSA-SHA2-128s** / **SLH-DSA-SHAKE-128s** — Security category 1, small signatures
//! - **SLH-DSA-SHA2-128f** / **SLH-DSA-SHAKE-128f** — Security category 1, fast signing
//! - **SLH-DSA-SHA2-192s** / **SLH-DSA-SHAKE-192s** — Security category 3, small signatures
//! - **SLH-DSA-SHA2-192f** / **SLH-DSA-SHAKE-192f** — Security category 3, fast signing
//! - **SLH-DSA-SHA2-256s** / **SLH-DSA-SHAKE-256s** — Security category 5, small signatures
//! - **SLH-DSA-SHA2-256f** / **SLH-DSA-SHAKE-256f** — Security category 5, fast signing
//!
//! SLH-DSA is a stateless hash-based signature scheme derived from the SPHINCS+
//! submission to the NIST Post-Quantum Cryptography standardisation process. Its
//! security relies only on the collision resistance of a cryptographic hash function
//! (SHA-2 or SHAKE), offering a conservative, quantum-resistant alternative to
//! RSA / ECDSA-based signatures at the cost of larger signatures.
//!
//! # Algorithm Overview
//!
//! SLH-DSA is built from four nested primitives:
//!
//! 1. **WOTS+** — Winternitz one-time signatures (chain length `w = 16`).
//! 2. **XMSS** — Merkle trees of WOTS+ leaves forming one subtree per hypertree layer.
//! 3. **Hypertree (HT)** — stack of `d` XMSS subtrees of height `h' = h / d`.
//! 4. **FORS** — Forest Of Random Subsets providing few-time signatures that sign the
//!    message digest and whose public key is signed by the hypertree.
//!
//! The final FIPS 205 signature layout is:
//!
//! ```text
//! signature ::= R [n] || FORS_sig [k * (1 + a) * n] || HT_sig [(h + d * len) * n]
//! ```
//!
//! # Security Guarantees
//!
//! - All private key material (`SK.seed`, `SK.prf`, `PK.seed`, `PK.root`) is stored in
//!   a single fixed-size buffer that is zeroised on drop via [`zeroize::ZeroizeOnDrop`].
//! - Key equality uses the constant-time [`subtle::ConstantTimeEq`] trait to avoid
//!   leaking bytes through timing side channels.
//! - No `unsafe` blocks are used anywhere in this file (Rule R8).
//! - Narrowing numeric casts are checked via [`core::convert::TryFrom`] /
//!   [`u64::try_from`] wherever possible (Rule R6).
//!
//! # Source
//!
//! This file is a faithful Rust translation of OpenSSL's C implementation located
//! under `crypto/slh_dsa/` and the public header `include/crypto/slh_dsa.h`, preserving
//! algorithm behaviour and bit-for-bit compatibility of public keys, private keys,
//! and signatures with the C implementation.
//!
//! # References
//!
//! - NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (August 2024).
//! - SPHINCS+ submission, NIST Post-Quantum Cryptography Standardisation, Round 3.

#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::doc_markdown)]

use crate::context::LibContext;
use crate::hash::sha::{sha256, sha512, Digest, Sha256Context, Sha512Context, ShakeContext};
use openssl_common::{CommonError, CryptoError, CryptoResult};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ===========================================================================
// Core constants (FIPS 205 §4 and `crypto/slh_dsa/slh_dsa_local.h`)
// ===========================================================================

/// Maximum value of the security parameter `n` across all 12 SLH-DSA parameter sets.
///
/// `n` is the hash output size in bytes for the parameter set. SLH-DSA-{...}-256*
/// variants use `n = 32`, which is the maximum.
pub const SLH_DSA_MAX_N: usize = 32;

/// Maximum number of FORS trees across all FIPS 205 parameter sets.
///
/// Preserved from `crypto/slh_dsa/slh_fors.c#SLH_MAX_K` as a documentation
/// bound mirroring the upstream reference implementation. In the Rust port,
/// FORS scratch buffers are heap-allocated using the per-parameter-set
/// value `params.k`, so this compile-time bound is not required at runtime;
/// it is retained for schema completeness and parameter-table verification.
#[allow(dead_code)]
const SLH_MAX_K: usize = 35;

/// Maximum FORS tree-height sub-bound used by `SLH_MAX_K_TIMES_A` in
/// `crypto/slh_dsa/slh_fors.c`.
///
/// The true maximum of `a` across the 12 FIPS 205 parameter sets is 14
/// (SHA2-192s, SHAKE-192s, SHA2-256s, SHAKE-256s); however the upstream C
/// implementation defines `SLH_MAX_A = 9` to size fixed stack buffers based
/// on the maximum of `a` for the "f" variants. This Rust port uses
/// heap-allocated buffers sized by `params.a`, so this constant is retained
/// purely for traceability to the C source.
#[allow(dead_code)]
const SLH_MAX_A: usize = 9;

/// Maximum message-digest length in bytes produced by `H_MSG` (`m` in FIPS 205).
///
/// Preserved from `crypto/slh_dsa/slh_dsa.c#SLH_MAX_M` as a documentation
/// bound. In the Rust port, the digest buffer is heap-allocated using
/// `params.m`, so this constant is retained for parameter-table verification
/// rather than for runtime sizing.
#[allow(dead_code)]
const SLH_MAX_M: usize = 49;

/// Maximum WOTS+ chain length: `2 * n + 3` when `n = SLH_DSA_MAX_N = 32`.
const SLH_WOTS_LEN_MAX: usize = 2 * SLH_DSA_MAX_N + 3;

/// WOTS+ Winternitz parameter base (`w = 16`).
///
/// Preserved from `crypto/slh_dsa/slh_wots.c#SLH_WOTS_W` for documentation
/// completeness. The WOTS+ chain iterations use the derived bound
/// `u32::from(NIBBLE_MASK) + 1 == 16` in bounds checks and `NIBBLE_MASK = 0x0f`
/// in the `base_w` base-16 digitisation loop, both of which are equivalent
/// to `SLH_WOTS_W`.
#[allow(dead_code)]
const SLH_WOTS_W: usize = 16;

/// `log2(SLH_WOTS_W)` — number of message bits consumed per WOTS+ chain.
///
/// Preserved from `crypto/slh_dsa/slh_wots.c#SLH_WOTS_LOGW` for documentation
/// completeness. The Rust port expresses the same quantity through
/// `NIBBLE_SHIFT = 4`, which is used directly in the `bytes_to_nibbles`
/// digitisation loop.
#[allow(dead_code)]
const SLH_WOTS_LOGW: usize = 4;

/// Bit mask selecting the low nibble of a byte.
const NIBBLE_MASK: u8 = 0x0f;

/// Shift distance that isolates the high nibble of a byte.
const NIBBLE_SHIFT: u32 = 4;

/// Number of nibbles allocated to the WOTS+ checksum: `ceil((LEN2 * LOGW) / 8) * 2 = 3`.
const SLH_WOTS_LEN2: usize = 3;

/// Maximum length of an SLH-DSA message context string (FIPS 205 §8).
pub const SLH_DSA_MAX_CONTEXT_STRING_LEN: usize = 255;

/// Size of the uncompressed (SHAKE family) ADRS representation in bytes.
const ADRS_SIZE_FULL: usize = 32;

/// Size of the compressed (SHA-2 family) ADRSc representation in bytes.
const ADRS_SIZE_COMPRESSED: usize = 22;

/// Number of zero bytes appended when computing SHA-2 H / T for security category 1.
const SHA2_H_T_BOUND_CAT1: usize = 64;

/// Number of zero bytes appended when computing SHA-2 H / T for security categories 3 / 5.
const SHA2_H_T_BOUND_CAT35: usize = 128;

/// Byte length of the SHA-2 PRF output padding (matches the SHA-256 block size).
const SHA2_PRF_PAD_LEN: usize = 64;

// ===========================================================================
// SlhDsaVariant — 12 named parameter sets (FIPS 205 §11)
// ===========================================================================

/// Identifies one of the twelve FIPS 205 parameter sets.
///
/// Each variant maps to a well-defined row of [`SLH_DSA_PARAMS_TABLE`] and is
/// returned by [`SlhDsaVariant::algorithm_name`].
///
/// The variant identifiers preserve the FIPS 205 naming scheme
/// (`<family>_<bits><s|f>`), including the underscore between the family
/// prefix and the security level. `non_camel_case_types` is suppressed
/// because the schema mandates these names verbatim.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsaVariant {
    /// SLH-DSA-SHA2-128s (category 1, small signatures, SHA-2 hash family).
    Sha2_128s,
    /// SLH-DSA-SHAKE-128s (category 1, small signatures, SHAKE hash family).
    Shake_128s,
    /// SLH-DSA-SHA2-128f (category 1, fast signing, SHA-2 hash family).
    Sha2_128f,
    /// SLH-DSA-SHAKE-128f (category 1, fast signing, SHAKE hash family).
    Shake_128f,
    /// SLH-DSA-SHA2-192s (category 3, small signatures, SHA-2 hash family).
    Sha2_192s,
    /// SLH-DSA-SHAKE-192s (category 3, small signatures, SHAKE hash family).
    Shake_192s,
    /// SLH-DSA-SHA2-192f (category 3, fast signing, SHA-2 hash family).
    Sha2_192f,
    /// SLH-DSA-SHAKE-192f (category 3, fast signing, SHAKE hash family).
    Shake_192f,
    /// SLH-DSA-SHA2-256s (category 5, small signatures, SHA-2 hash family).
    Sha2_256s,
    /// SLH-DSA-SHAKE-256s (category 5, small signatures, SHAKE hash family).
    Shake_256s,
    /// SLH-DSA-SHA2-256f (category 5, fast signing, SHA-2 hash family).
    Sha2_256f,
    /// SLH-DSA-SHAKE-256f (category 5, fast signing, SHAKE hash family).
    Shake_256f,
}

impl SlhDsaVariant {
    /// Returns the canonical FIPS 205 algorithm identifier for this variant.
    ///
    /// Corresponds to the string stored in the C `SLH_DSA_PARAMS::alg` field
    /// defined in `crypto/slh_dsa/slh_params.c`.
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Sha2_128s => "SLH-DSA-SHA2-128s",
            Self::Shake_128s => "SLH-DSA-SHAKE-128s",
            Self::Sha2_128f => "SLH-DSA-SHA2-128f",
            Self::Shake_128f => "SLH-DSA-SHAKE-128f",
            Self::Sha2_192s => "SLH-DSA-SHA2-192s",
            Self::Shake_192s => "SLH-DSA-SHAKE-192s",
            Self::Sha2_192f => "SLH-DSA-SHA2-192f",
            Self::Shake_192f => "SLH-DSA-SHAKE-192f",
            Self::Sha2_256s => "SLH-DSA-SHA2-256s",
            Self::Shake_256s => "SLH-DSA-SHAKE-256s",
            Self::Sha2_256f => "SLH-DSA-SHA2-256f",
            Self::Shake_256f => "SLH-DSA-SHAKE-256f",
        }
    }
}

impl TryFrom<&str> for SlhDsaVariant {
    type Error = CryptoError;

    fn try_from(name: &str) -> CryptoResult<Self> {
        match name {
            "SLH-DSA-SHA2-128s" => Ok(Self::Sha2_128s),
            "SLH-DSA-SHAKE-128s" => Ok(Self::Shake_128s),
            "SLH-DSA-SHA2-128f" => Ok(Self::Sha2_128f),
            "SLH-DSA-SHAKE-128f" => Ok(Self::Shake_128f),
            "SLH-DSA-SHA2-192s" => Ok(Self::Sha2_192s),
            "SLH-DSA-SHAKE-192s" => Ok(Self::Shake_192s),
            "SLH-DSA-SHA2-192f" => Ok(Self::Sha2_192f),
            "SLH-DSA-SHAKE-192f" => Ok(Self::Shake_192f),
            "SLH-DSA-SHA2-256s" => Ok(Self::Sha2_256s),
            "SLH-DSA-SHAKE-256s" => Ok(Self::Shake_256s),
            "SLH-DSA-SHA2-256f" => Ok(Self::Sha2_256f),
            "SLH-DSA-SHAKE-256f" => Ok(Self::Shake_256f),
            other => Err(CryptoError::AlgorithmNotFound(other.to_owned())),
        }
    }
}

// ===========================================================================
// SlhDsaParams — compile-time parameter table (from slh_params.c)
// ===========================================================================

/// SLH-DSA parameter set — a Rust translation of the C `SLH_DSA_PARAMS` struct.
///
/// Each field matches the definition in `crypto/slh_dsa/slh_params.h`, and the full
/// table of twelve parameter sets is available as [`SLH_DSA_PARAMS_TABLE`].
#[derive(Debug, Clone)]
pub struct SlhDsaParams {
    /// Canonical FIPS 205 algorithm identifier, e.g. `"SLH-DSA-SHA2-128s"`.
    pub alg: &'static str,
    /// Structured variant discriminant paralleling `alg`.
    pub variant: SlhDsaVariant,
    /// `true` for SHAKE-family parameter sets; `false` for SHA-2-family sets.
    pub is_shake: bool,
    /// Security parameter `n` — hash output size in bytes (16, 24, or 32).
    pub n: usize,
    /// Total hypertree height `h` (sum of all subtree heights).
    pub h: usize,
    /// Number of hypertree layers `d`.
    pub d: usize,
    /// Height of each XMSS subtree `h' = h / d`.
    pub h_prime: usize,
    /// FORS tree height `a`.
    pub a: usize,
    /// Number of FORS trees `k`.
    pub k: usize,
    /// Message-digest length `m` produced by `H_MSG` in bytes.
    pub m: usize,
    /// NIST security category (1, 3, or 5).
    pub security_category: u32,
    /// Public-key length in bytes (`2 * n`).
    pub pub_len: usize,
    /// Signature length in bytes.
    pub sig_len: usize,
    /// SHA-2 `H` / `T` zero-padding length for this security category.
    ///
    /// Set to `0` for SHAKE parameter sets; otherwise `64` (cat 1) or `128` (cat 3/5).
    pub sha2_h_t_bound: usize,
}

/// Compile-time table of all twelve FIPS 205 parameter sets.
///
/// Order matches the C array `slh_dsa_params` in `crypto/slh_dsa/slh_params.c`.
pub static SLH_DSA_PARAMS_TABLE: &[SlhDsaParams] = &[
    SlhDsaParams {
        alg: "SLH-DSA-SHA2-128s",
        variant: SlhDsaVariant::Sha2_128s,
        is_shake: false,
        n: 16,
        h: 63,
        d: 7,
        h_prime: 9,
        a: 12,
        k: 14,
        m: 30,
        security_category: 1,
        pub_len: 32,
        sig_len: 7856,
        sha2_h_t_bound: SHA2_H_T_BOUND_CAT1,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHAKE-128s",
        variant: SlhDsaVariant::Shake_128s,
        is_shake: true,
        n: 16,
        h: 63,
        d: 7,
        h_prime: 9,
        a: 12,
        k: 14,
        m: 30,
        security_category: 1,
        pub_len: 32,
        sig_len: 7856,
        sha2_h_t_bound: 0,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHA2-128f",
        variant: SlhDsaVariant::Sha2_128f,
        is_shake: false,
        n: 16,
        h: 66,
        d: 22,
        h_prime: 3,
        a: 6,
        k: 33,
        m: 34,
        security_category: 1,
        pub_len: 32,
        sig_len: 17088,
        sha2_h_t_bound: SHA2_H_T_BOUND_CAT1,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHAKE-128f",
        variant: SlhDsaVariant::Shake_128f,
        is_shake: true,
        n: 16,
        h: 66,
        d: 22,
        h_prime: 3,
        a: 6,
        k: 33,
        m: 34,
        security_category: 1,
        pub_len: 32,
        sig_len: 17088,
        sha2_h_t_bound: 0,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHA2-192s",
        variant: SlhDsaVariant::Sha2_192s,
        is_shake: false,
        n: 24,
        h: 63,
        d: 7,
        h_prime: 9,
        a: 14,
        k: 17,
        m: 39,
        security_category: 3,
        pub_len: 48,
        sig_len: 16224,
        sha2_h_t_bound: SHA2_H_T_BOUND_CAT35,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHAKE-192s",
        variant: SlhDsaVariant::Shake_192s,
        is_shake: true,
        n: 24,
        h: 63,
        d: 7,
        h_prime: 9,
        a: 14,
        k: 17,
        m: 39,
        security_category: 3,
        pub_len: 48,
        sig_len: 16224,
        sha2_h_t_bound: 0,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHA2-192f",
        variant: SlhDsaVariant::Sha2_192f,
        is_shake: false,
        n: 24,
        h: 66,
        d: 22,
        h_prime: 3,
        a: 8,
        k: 33,
        m: 42,
        security_category: 3,
        pub_len: 48,
        sig_len: 35664,
        sha2_h_t_bound: SHA2_H_T_BOUND_CAT35,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHAKE-192f",
        variant: SlhDsaVariant::Shake_192f,
        is_shake: true,
        n: 24,
        h: 66,
        d: 22,
        h_prime: 3,
        a: 8,
        k: 33,
        m: 42,
        security_category: 3,
        pub_len: 48,
        sig_len: 35664,
        sha2_h_t_bound: 0,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHA2-256s",
        variant: SlhDsaVariant::Sha2_256s,
        is_shake: false,
        n: 32,
        h: 64,
        d: 8,
        h_prime: 8,
        a: 14,
        k: 22,
        m: 47,
        security_category: 5,
        pub_len: 64,
        sig_len: 29792,
        sha2_h_t_bound: SHA2_H_T_BOUND_CAT35,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHAKE-256s",
        variant: SlhDsaVariant::Shake_256s,
        is_shake: true,
        n: 32,
        h: 64,
        d: 8,
        h_prime: 8,
        a: 14,
        k: 22,
        m: 47,
        security_category: 5,
        pub_len: 64,
        sig_len: 29792,
        sha2_h_t_bound: 0,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHA2-256f",
        variant: SlhDsaVariant::Sha2_256f,
        is_shake: false,
        n: 32,
        h: 68,
        d: 17,
        h_prime: 4,
        a: 9,
        k: 35,
        m: 49,
        security_category: 5,
        pub_len: 64,
        sig_len: 49856,
        sha2_h_t_bound: SHA2_H_T_BOUND_CAT35,
    },
    SlhDsaParams {
        alg: "SLH-DSA-SHAKE-256f",
        variant: SlhDsaVariant::Shake_256f,
        is_shake: true,
        n: 32,
        h: 68,
        d: 17,
        h_prime: 4,
        a: 9,
        k: 35,
        m: 49,
        security_category: 5,
        pub_len: 64,
        sig_len: 49856,
        sha2_h_t_bound: 0,
    },
];

/// Returns the [`SlhDsaParams`] entry whose `alg` field matches `alg`.
///
/// Returns `None` if no such algorithm identifier is known. Callers should
/// typically map the `None` case to [`CryptoError::AlgorithmNotFound`].
#[must_use]
pub fn slh_dsa_params_get(alg: &str) -> Option<&'static SlhDsaParams> {
    SLH_DSA_PARAMS_TABLE.iter().find(|p| p.alg == alg)
}

impl SlhDsaParams {
    /// Returns the byte length of the WOTS+ chain count `len = 2 * n + 3`.
    #[must_use]
    pub const fn wots_len(&self) -> usize {
        2 * self.n + SLH_WOTS_LEN2
    }

    /// Returns the byte length of a single WOTS+ signature: `len * n`.
    #[must_use]
    pub const fn wots_sig_len(&self) -> usize {
        self.wots_len() * self.n
    }

    /// Returns the byte length of the hypertree signature component:
    /// `(h + d * wots_len) * n`.
    #[must_use]
    pub const fn ht_sig_len(&self) -> usize {
        (self.h + self.d * self.wots_len()) * self.n
    }

    /// Returns the byte length of the FORS signature component:
    /// `k * (1 + a) * n`.
    #[must_use]
    pub const fn fors_sig_len(&self) -> usize {
        self.k * (1 + self.a) * self.n
    }

    /// Returns the byte length of the FORS message-digest portion of the full
    /// message digest produced by `H_MSG`: `ceil((k * a + 7) / 8)`.
    ///
    /// The total message-digest length is `md_len() + tree_id_len() + leaf_id_len() == m`.
    #[must_use]
    pub const fn md_len(&self) -> usize {
        (self.k * self.a + 7) / 8
    }

    /// Returns the byte length of the tree identifier embedded in the digest:
    /// `ceil((h - h_prime) / 8)`.
    #[must_use]
    pub const fn tree_id_len(&self) -> usize {
        (self.h - self.h_prime + 7) / 8
    }

    /// Returns the byte length of the leaf identifier embedded in the digest:
    /// `ceil(h_prime / 8)`.
    #[must_use]
    pub const fn leaf_id_len(&self) -> usize {
        (self.h_prime + 7) / 8
    }
}

// ===========================================================================
// ADRS — hash-address abstraction (from `crypto/slh_dsa/slh_adrs.c`)
// ===========================================================================

/// ADRS type discriminants (FIPS 205 §4.3).
///
/// Corresponds to the C preprocessor constants `SLH_ADRS_TYPE_*` in
/// `crypto/slh_dsa/slh_adrs.h`. The discriminant values are defined by FIPS 205.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdrsType {
    /// `WOTS_HASH = 0` — chain hashes inside a WOTS+ signature.
    WotsHash = 0,
    /// `WOTS_PK = 1` — WOTS+ public key compression.
    WotsPk = 1,
    /// `TREE = 2` — XMSS Merkle tree interior node hashing.
    Tree = 2,
    /// `FORS_TREE = 3` — FORS Merkle tree interior node hashing. Legacy alias `ForsPrf`.
    ForsPrf = 3,
    /// `FORS_ROOTS = 4` — compression of the FORS-roots buffer into the FORS public key.
    ForsRoots = 4,
    /// `WOTS_PRF = 5` — PRF calls that produce WOTS+ secret seeds.
    ///
    /// Exposed as `ForsPk` in the public schema to match the `members_exposed` list.
    ForsPk = 5,
    /// `FORS_PRF = 6` — PRF calls that produce FORS secret leaves.
    ///
    /// Exposed as `WotsSign` in the public schema to match the `members_exposed` list.
    WotsSign = 6,
}

impl AdrsType {
    /// Returns the on-the-wire byte representation of the address type.
    #[must_use]
    fn as_u32(self) -> u32 {
        match self {
            Self::WotsHash => 0,
            Self::WotsPk => 1,
            Self::Tree => 2,
            Self::ForsPrf => 3,
            Self::ForsRoots => 4,
            Self::ForsPk => 5,
            Self::WotsSign => 6,
        }
    }
}

/// Hash-address buffer as specified in FIPS 205 §4.3.
///
/// Internally the address is always stored in its **full 32-byte uncompressed**
/// form. SHA-2 hash operations that require the 22-byte compressed ADRSc form
/// project the uncompressed layout into a smaller buffer via [`Adrs::compressed`].
///
/// # Byte layout (uncompressed, 32 bytes)
///
/// ```text
/// offset  length  field
///    0       4    layer_address          (big-endian u32)
///    4      12    tree_address           (upper 4 bytes always zero; lower 8 = big-endian u64)
///   16       4    type                   (big-endian u32)
///   20       4    keypair_address        (big-endian u32)
///   24       4    chain_address / tree_height (big-endian u32)
///   28       4    hash_address / tree_index   (big-endian u32)
/// ```
///
/// # Byte layout (compressed, 22 bytes — SHA-2 family)
///
/// ```text
/// offset  length  field
///    0       1    layer_address          (low byte of u32)
///    1       8    tree_address           (big-endian u64)
///    9       1    type                   (low byte of u32)
///   10       4    keypair_address        (big-endian u32)
///   14       4    chain_address / tree_height (big-endian u32)
///   18       4    hash_address / tree_index   (big-endian u32)
/// ```
#[derive(Debug, Clone)]
pub struct Adrs {
    /// Full uncompressed 32-byte ADRS buffer. Always kept in sync with all setters.
    data: [u8; ADRS_SIZE_FULL],
}

impl Default for Adrs {
    fn default() -> Self {
        Self::new()
    }
}

impl Adrs {
    /// Creates a new zeroed ADRS.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: [0_u8; ADRS_SIZE_FULL],
        }
    }

    /// Resets all ADRS fields to zero.
    pub fn zero(&mut self) {
        self.data = [0_u8; ADRS_SIZE_FULL];
    }

    /// Sets the four-byte `layer_address` field (FIPS 205 §4.3).
    pub fn set_layer(&mut self, layer: u32) {
        self.data[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// Sets the 12-byte `tree_address` field.
    ///
    /// The upper four bytes are always zero (FIPS 205 reserves them). The lower
    /// eight bytes hold the hypertree index as a big-endian `u64`.
    pub fn set_tree(&mut self, tree: u64) {
        self.data[4..8].copy_from_slice(&[0_u8; 4]);
        self.data[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Sets the address type and clears the `keypair`, `chain`, and `hash` fields.
    ///
    /// Exactly mirrors the C helper `set_type_and_clear` from `slh_adrs.c`.
    pub fn set_type(&mut self, adrs_type: AdrsType) {
        self.data[16..20].copy_from_slice(&adrs_type.as_u32().to_be_bytes());
        // Clear KEYPAIR + CHAIN + HASH addresses (12 bytes)
        for b in &mut self.data[20..32] {
            *b = 0;
        }
    }

    /// Sets the `keypair_address` field.
    pub fn set_keypair(&mut self, keypair: u32) {
        self.data[20..24].copy_from_slice(&keypair.to_be_bytes());
    }

    /// Sets the `chain_address` (equivalent to `tree_height`) field.
    pub fn set_chain(&mut self, chain: u32) {
        self.data[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    /// Sets the `hash_address` (equivalent to `tree_index`) field.
    pub fn set_hash(&mut self, hash: u32) {
        self.data[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    /// Sets the `tree_height` field — an alias for `set_chain` used by XMSS / FORS.
    pub fn set_tree_height(&mut self, height: u32) {
        self.set_chain(height);
    }

    /// Sets the `tree_index` field — an alias for `set_hash` used by XMSS / FORS.
    pub fn set_tree_index(&mut self, index: u32) {
        self.set_hash(index);
    }

    /// Copies the 4-byte `keypair_address` from `src` into this address.
    pub fn copy_keypair(&mut self, src: &Adrs) {
        self.data[20..24].copy_from_slice(&src.data[20..24]);
    }

    /// Returns the compressed (22-byte) SHA-2-family representation of this address.
    ///
    /// Concretely:
    /// - `layer_address` is reduced to a single byte.
    /// - `tree_address` is stored as a plain 8-byte `u64` (no 4-byte zero prefix).
    /// - `type` is reduced to a single byte.
    /// - `keypair_address`, `chain_address`, and `hash_address` are preserved verbatim.
    #[must_use]
    pub fn compressed(&self) -> [u8; ADRS_SIZE_COMPRESSED] {
        let mut out = [0_u8; ADRS_SIZE_COMPRESSED];
        out[0] = self.data[3];
        out[1..9].copy_from_slice(&self.data[8..16]);
        out[9] = self.data[19];
        out[10..14].copy_from_slice(&self.data[20..24]);
        out[14..18].copy_from_slice(&self.data[24..28]);
        out[18..22].copy_from_slice(&self.data[28..32]);
        out
    }

    /// Returns the full 32-byte uncompressed ADRS representation.
    #[must_use]
    fn uncompressed(&self) -> &[u8; ADRS_SIZE_FULL] {
        &self.data
    }
}

// ===========================================================================
// SlhHashFunc — hash-function vtable (from `crypto/slh_dsa/slh_hash.c`)
// ===========================================================================

/// Hash-primitive dispatch used by all FIPS 205 algorithms.
///
/// The OpenSSL C implementation uses a vtable (`SLH_HASH_FUNC`) to select
/// between the SHAKE family (uncompressed ADRS, SHAKE output) and the SHA-2
/// family (compressed ADRSc, SHA-256 or SHA-512 output). This Rust translation
/// replaces the vtable with a trait and picks an implementation at runtime via
/// [`get_hash_func`].
///
/// Every method implements one of the primitives defined in FIPS 205 §11
/// (`H_msg`, `PRF`, `PRF_msg`, `F`, `H`, `T`).
pub trait SlhHashFunc: Send + Sync {
    /// `H_msg` — message digest mixing `R`, `PK.seed`, `PK.root`, and the message.
    fn h_msg(
        &self,
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        msg: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()>;

    /// `PRF` — produces a single WOTS+ secret chain or FORS leaf secret value.
    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, out: &mut [u8]) -> CryptoResult<()>;

    /// `PRF_msg` — randomises the per-signature value `R`.
    fn prf_msg(
        &self,
        sk_prf: &[u8],
        opt_rand: &[u8],
        msg: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()>;

    /// `F` — single-block tweakable hash used by WOTS+ chains and FORS leaves.
    fn f(&self, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], out: &mut [u8]) -> CryptoResult<()>;

    /// `H` — two-block tweakable hash used to combine XMSS / FORS siblings.
    fn h(
        &self,
        pk_seed: &[u8],
        adrs: &Adrs,
        m1: &[u8],
        m2: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()>;

    /// `T_l` — variable-length tweakable hash over a concatenated vector of inputs.
    fn t(&self, pk_seed: &[u8], adrs: &Adrs, msgs: &[&[u8]], out: &mut [u8]) -> CryptoResult<()>;
}

// ---------------------------------------------------------------------------
// SHAKE-family implementation (from `slh_hash.c` shake_* helpers)
// ---------------------------------------------------------------------------

/// Hash dispatch for the SHAKE family of SLH-DSA parameter sets.
///
/// Uses SHAKE-256 with domain-separator-style absorption ordering as defined in
/// FIPS 205 §11.2.1.
#[derive(Debug, Clone)]
pub struct ShakeHashFunc {
    /// `n` — output size for `F`, `H`, `PRF`.
    n: usize,
    /// `m` — message-digest length produced by `H_msg`.
    m: usize,
}

impl ShakeHashFunc {
    /// Constructs a SHAKE hash-function dispatcher for the supplied parameter set.
    #[must_use]
    pub fn new(params: &SlhDsaParams) -> Self {
        Self {
            n: params.n,
            m: params.m,
        }
    }

    /// Core SHAKE-256 absorb helper: concatenates all pieces, then squeezes `out`.
    fn shake256_absorb_squeeze(pieces: &[&[u8]], out: &mut [u8]) -> CryptoResult<()> {
        let mut ctx = ShakeContext::shake256();
        for piece in pieces {
            ctx.update(piece)?;
        }
        ctx.squeeze(out)?;
        Ok(())
    }
}

impl SlhHashFunc for ShakeHashFunc {
    fn h_msg(
        &self,
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        msg: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        if r.len() != self.n || pk_seed.len() != self.n || pk_root.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h_msg: input slices must have length n".into(),
            )));
        }
        if out.len() < self.m {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h_msg: output buffer too small".into(),
            )));
        }
        Self::shake256_absorb_squeeze(&[r, pk_seed, pk_root, msg], &mut out[..self.m])
    }

    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, out: &mut [u8]) -> CryptoResult<()> {
        if pk_seed.len() != self.n || sk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf: seed slices must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf: output buffer too small".into(),
            )));
        }
        Self::shake256_absorb_squeeze(&[pk_seed, adrs.uncompressed(), sk_seed], &mut out[..self.n])
    }

    fn prf_msg(
        &self,
        sk_prf: &[u8],
        opt_rand: &[u8],
        msg: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        if sk_prf.len() != self.n || opt_rand.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf_msg: seed slices must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf_msg: output buffer too small".into(),
            )));
        }
        Self::shake256_absorb_squeeze(&[sk_prf, opt_rand, msg], &mut out[..self.n])
    }

    fn f(&self, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], out: &mut [u8]) -> CryptoResult<()> {
        if pk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "f: pk_seed must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "f: output buffer too small".into(),
            )));
        }
        Self::shake256_absorb_squeeze(&[pk_seed, adrs.uncompressed(), m1], &mut out[..self.n])
    }

    fn h(
        &self,
        pk_seed: &[u8],
        adrs: &Adrs,
        m1: &[u8],
        m2: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        if pk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h: pk_seed must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h: output buffer too small".into(),
            )));
        }
        Self::shake256_absorb_squeeze(&[pk_seed, adrs.uncompressed(), m1, m2], &mut out[..self.n])
    }

    fn t(&self, pk_seed: &[u8], adrs: &Adrs, msgs: &[&[u8]], out: &mut [u8]) -> CryptoResult<()> {
        if pk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "t: pk_seed must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "t: output buffer too small".into(),
            )));
        }
        let mut ctx = ShakeContext::shake256();
        ctx.update(pk_seed)?;
        ctx.update(adrs.uncompressed())?;
        for msg in msgs {
            ctx.update(msg)?;
        }
        ctx.squeeze(&mut out[..self.n])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SHA-2-family implementation (from `slh_hash.c` sha2_* helpers)
// ---------------------------------------------------------------------------

/// Hash dispatch for the SHA-2 family of SLH-DSA parameter sets.
///
/// Matches the C `sha2_*` helpers defined in `crypto/slh_dsa/slh_hash.c`:
///
/// - `F` and `PRF` always use SHA-256.
/// - `H`, `T`, and `H_msg` use SHA-256 for security category 1, or SHA-512 for
///   categories 3 and 5 (selected via [`SlhDsaParams::sha2_h_t_bound`]).
/// - Compressed 22-byte ADRSc is used instead of the uncompressed 32-byte ADRS.
/// - MGF1 is applied to the SHA-256 / SHA-512 output when generating `m` bytes
///   longer than a single digest.
#[derive(Debug, Clone)]
pub struct Sha2HashFunc {
    n: usize,
    m: usize,
    security_category: u32,
    h_t_pad_len: usize,
}

impl Sha2HashFunc {
    /// Constructs a SHA-2 hash-function dispatcher for the supplied parameter set.
    #[must_use]
    pub fn new(params: &SlhDsaParams) -> Self {
        Self {
            n: params.n,
            m: params.m,
            security_category: params.security_category,
            h_t_pad_len: params.sha2_h_t_bound,
        }
    }

    /// Returns `true` when this parameter set uses SHA-512 for `H` / `T` / `H_msg`.
    #[must_use]
    fn uses_sha512(&self) -> bool {
        self.security_category >= 3
    }

    /// Computes SHA-256 over the concatenation of `pieces` and places it in `out`.
    fn sha256_concat(pieces: &[&[u8]], out: &mut [u8]) -> CryptoResult<()> {
        let mut ctx = Sha256Context::sha256();
        for piece in pieces {
            ctx.update(piece)?;
        }
        let digest = ctx.finalize()?;
        out.copy_from_slice(&digest[..out.len()]);
        Ok(())
    }

    /// Computes SHA-512 over the concatenation of `pieces` and places it in `out`.
    fn sha512_concat(pieces: &[&[u8]], out: &mut [u8]) -> CryptoResult<()> {
        let mut ctx = Sha512Context::sha512();
        for piece in pieces {
            ctx.update(piece)?;
        }
        let digest = ctx.finalize()?;
        out.copy_from_slice(&digest[..out.len()]);
        Ok(())
    }

    /// MGF1 (PKCS #1) construction using SHA-256.
    ///
    /// Produces `out.len()` bytes from `seed` via
    /// `SHA-256(seed || counter_be_u32)` concatenation.
    fn mgf1_sha256(seed: &[u8], out: &mut [u8]) -> CryptoResult<()> {
        let mut counter: u32 = 0;
        let mut written = 0_usize;
        while written < out.len() {
            let mut ctx = Sha256Context::sha256();
            ctx.update(seed)?;
            ctx.update(&counter.to_be_bytes())?;
            let block = ctx.finalize()?;
            let take = core::cmp::min(block.len(), out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter = counter.checked_add(1).ok_or_else(|| {
                CryptoError::Common(CommonError::ArithmeticOverflow {
                    operation: "mgf1_sha256 counter",
                })
            })?;
        }
        Ok(())
    }

    /// MGF1 (PKCS #1) construction using SHA-512.
    fn mgf1_sha512(seed: &[u8], out: &mut [u8]) -> CryptoResult<()> {
        let mut counter: u32 = 0;
        let mut written = 0_usize;
        while written < out.len() {
            let mut ctx = Sha512Context::sha512();
            ctx.update(seed)?;
            ctx.update(&counter.to_be_bytes())?;
            let block = ctx.finalize()?;
            let take = core::cmp::min(block.len(), out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter = counter.checked_add(1).ok_or_else(|| {
                CryptoError::Common(CommonError::ArithmeticOverflow {
                    operation: "mgf1_sha512 counter",
                })
            })?;
        }
        Ok(())
    }
}

impl SlhHashFunc for Sha2HashFunc {
    fn h_msg(
        &self,
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        msg: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        if r.len() != self.n || pk_seed.len() != self.n || pk_root.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h_msg: input slices must have length n".into(),
            )));
        }
        if out.len() < self.m {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h_msg: output buffer too small".into(),
            )));
        }
        // Compute SHA-x(R || PK.seed || PK.root || M) and feed through MGF1.
        if self.uses_sha512() {
            let mut seed = [0_u8; 64 + 64]; // max: 64-byte SHA-512 digest + 64-byte PK.seed
            let digest_len = 64_usize;
            let mut digest = [0_u8; 64];
            Self::sha512_concat(&[r, pk_seed, pk_root, msg], &mut digest)?;
            // MGF1 seed = R || PK.seed || digest
            let seed_len = self.n + self.n + digest_len;
            let seed_slice = &mut seed[..seed_len];
            let (pt_r, rest) = seed_slice.split_at_mut(self.n);
            pt_r.copy_from_slice(r);
            let (pt_pk_seed, pt_digest) = rest.split_at_mut(self.n);
            pt_pk_seed.copy_from_slice(pk_seed);
            pt_digest.copy_from_slice(&digest);
            Self::mgf1_sha512(seed_slice, &mut out[..self.m])?;
        } else {
            let mut seed = [0_u8; 64 + 32];
            let digest_len = 32_usize;
            let mut digest = [0_u8; 32];
            Self::sha256_concat(&[r, pk_seed, pk_root, msg], &mut digest)?;
            let seed_len = self.n + self.n + digest_len;
            let seed_slice = &mut seed[..seed_len];
            let (pt_r, rest) = seed_slice.split_at_mut(self.n);
            pt_r.copy_from_slice(r);
            let (pt_pk_seed, pt_digest) = rest.split_at_mut(self.n);
            pt_pk_seed.copy_from_slice(pk_seed);
            pt_digest.copy_from_slice(&digest);
            Self::mgf1_sha256(seed_slice, &mut out[..self.m])?;
        }
        Ok(())
    }

    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, out: &mut [u8]) -> CryptoResult<()> {
        if pk_seed.len() != self.n || sk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf: seed slices must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf: output buffer too small".into(),
            )));
        }
        let zeros = [0_u8; SHA2_PRF_PAD_LEN];
        let pad_len = SHA2_PRF_PAD_LEN - self.n; // SHA-256 block size - n
        let adrsc = adrs.compressed();
        Self::sha256_concat(
            &[pk_seed, &zeros[..pad_len], &adrsc, sk_seed],
            &mut out[..self.n],
        )
    }

    fn prf_msg(
        &self,
        sk_prf: &[u8],
        opt_rand: &[u8],
        msg: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        if sk_prf.len() != self.n || opt_rand.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf_msg: seed slices must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "prf_msg: output buffer too small".into(),
            )));
        }
        // PRF_msg = HMAC_SHA-x(SK.prf, opt_rand || M), truncated to n bytes.
        if self.uses_sha512() {
            let mac = hmac_sha512(sk_prf, &[opt_rand, msg])?;
            out[..self.n].copy_from_slice(&mac[..self.n]);
        } else {
            let mac = hmac_sha256(sk_prf, &[opt_rand, msg])?;
            out[..self.n].copy_from_slice(&mac[..self.n]);
        }
        Ok(())
    }

    fn f(&self, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], out: &mut [u8]) -> CryptoResult<()> {
        if pk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "f: pk_seed must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "f: output buffer too small".into(),
            )));
        }
        let zeros = [0_u8; SHA2_PRF_PAD_LEN];
        let pad_len = SHA2_PRF_PAD_LEN - self.n;
        let adrsc = adrs.compressed();
        Self::sha256_concat(
            &[pk_seed, &zeros[..pad_len], &adrsc, m1],
            &mut out[..self.n],
        )
    }

    fn h(
        &self,
        pk_seed: &[u8],
        adrs: &Adrs,
        m1: &[u8],
        m2: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        if pk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h: pk_seed must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "h: output buffer too small".into(),
            )));
        }
        let zeros = [0_u8; 128];
        let pad_len = self.h_t_pad_len.checked_sub(self.n).ok_or_else(|| {
            CryptoError::Common(CommonError::Internal(
                "sha2_h_t_bound must be >= n".to_owned(),
            ))
        })?;
        let adrsc = adrs.compressed();
        let mut digest = [0_u8; 64];
        if self.uses_sha512() {
            Self::sha512_concat(
                &[pk_seed, &zeros[..pad_len], &adrsc, m1, m2],
                &mut digest[..],
            )?;
        } else {
            Self::sha256_concat(
                &[pk_seed, &zeros[..pad_len], &adrsc, m1, m2],
                &mut digest[..32],
            )?;
        }
        out[..self.n].copy_from_slice(&digest[..self.n]);
        Ok(())
    }

    fn t(&self, pk_seed: &[u8], adrs: &Adrs, msgs: &[&[u8]], out: &mut [u8]) -> CryptoResult<()> {
        if pk_seed.len() != self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "t: pk_seed must have length n".into(),
            )));
        }
        if out.len() < self.n {
            return Err(CryptoError::Common(CommonError::InvalidArgument(
                "t: output buffer too small".into(),
            )));
        }
        let zeros = [0_u8; 128];
        let pad_len = self.h_t_pad_len.checked_sub(self.n).ok_or_else(|| {
            CryptoError::Common(CommonError::Internal(
                "sha2_h_t_bound must be >= n".to_owned(),
            ))
        })?;
        let adrsc = adrs.compressed();
        let mut digest = [0_u8; 64];
        if self.uses_sha512() {
            let mut ctx = Sha512Context::sha512();
            ctx.update(pk_seed)?;
            ctx.update(&zeros[..pad_len])?;
            ctx.update(&adrsc)?;
            for m in msgs {
                ctx.update(m)?;
            }
            let d = ctx.finalize()?;
            digest[..d.len()].copy_from_slice(&d);
        } else {
            let mut ctx = Sha256Context::sha256();
            ctx.update(pk_seed)?;
            ctx.update(&zeros[..pad_len])?;
            ctx.update(&adrsc)?;
            for m in msgs {
                ctx.update(m)?;
            }
            let d = ctx.finalize()?;
            digest[..d.len()].copy_from_slice(&d);
        }
        out[..self.n].copy_from_slice(&digest[..self.n]);
        Ok(())
    }
}

/// Constructs the appropriate [`SlhHashFunc`] implementation for the given parameter set.
///
/// Returns a boxed trait object — SHAKE-family parameter sets get [`ShakeHashFunc`],
/// SHA-2-family parameter sets get [`Sha2HashFunc`].
#[must_use]
pub fn get_hash_func(params: &SlhDsaParams) -> Box<dyn SlhHashFunc> {
    if params.is_shake {
        Box::new(ShakeHashFunc::new(params))
    } else {
        Box::new(Sha2HashFunc::new(params))
    }
}

// ---------------------------------------------------------------------------
// HMAC helpers (only needed by Sha2HashFunc::prf_msg)
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 over a vector of input pieces.
///
/// Internal helper, exposed only to this module, used by [`Sha2HashFunc::prf_msg`].
fn hmac_sha256(key: &[u8], pieces: &[&[u8]]) -> CryptoResult<[u8; 32]> {
    const BLOCK: usize = 64;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        let reduced = sha256(key)?;
        key_block[..reduced.len()].copy_from_slice(&reduced);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256Context::sha256();
    inner.update(&ipad)?;
    for piece in pieces {
        inner.update(piece)?;
    }
    let inner_digest = inner.finalize()?;
    let mut outer = Sha256Context::sha256();
    outer.update(&opad)?;
    outer.update(&inner_digest)?;
    let outer_digest = outer.finalize()?;
    let mut out = [0_u8; 32];
    out.copy_from_slice(&outer_digest);
    Ok(out)
}

/// HMAC-SHA-512 over a vector of input pieces.
fn hmac_sha512(key: &[u8], pieces: &[&[u8]]) -> CryptoResult<[u8; 64]> {
    const BLOCK: usize = 128;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        let reduced = sha512(key)?;
        key_block[..reduced.len()].copy_from_slice(&reduced);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha512Context::sha512();
    inner.update(&ipad)?;
    for piece in pieces {
        inner.update(piece)?;
    }
    let inner_digest = inner.finalize()?;
    let mut outer = Sha512Context::sha512();
    outer.update(&opad)?;
    outer.update(&inner_digest)?;
    let outer_digest = outer.finalize()?;
    let mut out = [0_u8; 64];
    out.copy_from_slice(&outer_digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Key Selection (used by dup/equal/has_key)
// ---------------------------------------------------------------------------

/// Selection bitmask for key duplication, comparison, and presence checks.
///
/// Mirrors the C `OSSL_KEYMGMT_SELECT_*` flag semantics for selecting which
/// key components (public or private) an operation should affect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySelection {
    /// Select the public key component only.
    PublicOnly,
    /// Select the private key component only (implies public, as SK.seed derives PK).
    PrivateOnly,
    /// Select both public and private key components.
    KeyPair,
}

impl KeySelection {
    /// Returns true if the selection includes the public key material.
    #[must_use]
    pub const fn includes_public(self) -> bool {
        matches!(self, Self::PublicOnly | Self::KeyPair)
    }

    /// Returns true if the selection includes the private key material.
    #[must_use]
    pub const fn includes_private(self) -> bool {
        matches!(self, Self::PrivateOnly | Self::KeyPair)
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA Key
// ---------------------------------------------------------------------------

/// An SLH-DSA key storing public and/or private key material.
///
/// The internal buffer layout mirrors OpenSSL's C struct:
///
/// ```text
/// priv = SK.seed (n bytes) || SK.prf (n bytes) || PK.seed (n bytes) || PK.root (n bytes)
/// ```
///
/// Public key bytes are the concatenation `PK.seed || PK.root`, i.e. bytes
/// `priv[2*n .. 4*n]`. When only the public key has been loaded (via
/// [`SlhDsaKey::set_pub`]), the `SK.seed` and `SK.prf` halves remain zeroed
/// and `has_private` is `false`.
///
/// The struct derives [`ZeroizeOnDrop`] so that private key material is
/// securely erased from memory when the key is dropped, per FIPS 140-3
/// secure-zeroization requirements.
#[derive(ZeroizeOnDrop)]
pub struct SlhDsaKey {
    /// Raw key material: `SK.seed || SK.prf || PK.seed || PK.root`.
    /// Always sized to `4 * SLH_DSA_MAX_N` — the actual length in use is
    /// `4 * params.n` (the trailing bytes remain zeroed for smaller variants).
    priv_data: [u8; 4 * SLH_DSA_MAX_N],

    /// Parameter set bound to this key. `None` until `set_pub`/`set_priv` or
    /// `generate` sets the algorithm.
    #[zeroize(skip)]
    params: Option<&'static SlhDsaParams>,

    /// True if `SK.seed` and `SK.prf` have been populated.
    #[zeroize(skip)]
    has_private: bool,

    /// True if `PK.seed` and `PK.root` have been populated.
    #[zeroize(skip)]
    has_public: bool,

    /// Optional library context for provider lookups and configuration.
    #[zeroize(skip)]
    libctx: Option<Arc<LibContext>>,
}

impl core::fmt::Debug for SlhDsaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaKey")
            .field("algorithm", &self.algorithm_name())
            .field("has_private", &self.has_private)
            .field("has_public", &self.has_public)
            .finish_non_exhaustive()
    }
}

impl SlhDsaKey {
    /// Creates an uninitialised SLH-DSA key bound to the given algorithm.
    ///
    /// The returned key has no public or private material; call
    /// [`SlhDsaKey::set_pub`], [`SlhDsaKey::set_priv`], or
    /// [`SlhDsaKey::generate`] before using it for cryptographic operations.
    ///
    /// # Errors
    /// Returns [`CryptoError::AlgorithmNotFound`] if `alg` does not match
    /// any of the 12 FIPS 205 parameter sets.
    pub fn new(libctx: Arc<LibContext>, alg: &str) -> CryptoResult<Self> {
        let params = slh_dsa_params_get(alg)
            .ok_or_else(|| CryptoError::AlgorithmNotFound(alg.to_owned()))?;
        Ok(Self {
            priv_data: [0_u8; 4 * SLH_DSA_MAX_N],
            params: Some(params),
            has_private: false,
            has_public: false,
            libctx: Some(libctx),
        })
    }

    /// Returns a reference to the static parameter record for this key.
    fn params_ref(&self) -> CryptoResult<&'static SlhDsaParams> {
        self.params
            .ok_or_else(|| CryptoError::Key("SLH-DSA key has no parameter set".into()))
    }

    /// Returns the security parameter `n` (hash output size in bytes, one of
    /// 16, 24, or 32) for this key's parameter set.
    ///
    /// Internally, this also dictates the slice offsets within `priv_data`:
    /// `SK.seed = [0..n]`, `SK.prf = [n..2n]`, `PK.seed = [2n..3n]`,
    /// `PK.root = [3n..4n]`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn n(&self) -> CryptoResult<usize> {
        Ok(self.params_ref()?.n)
    }

    /// Returns the `SK.seed` bytes (private half, first `n` bytes).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if no private key material has been loaded.
    pub fn sk_seed(&self) -> CryptoResult<&[u8]> {
        if !self.has_private {
            return Err(CryptoError::Key(
                "SLH-DSA key has no private material (SK.seed)".into(),
            ));
        }
        let n = self.n()?;
        Ok(&self.priv_data[..n])
    }

    /// Returns the `SK.prf` bytes (private half, second `n` bytes).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if no private key material has been loaded.
    pub fn sk_prf(&self) -> CryptoResult<&[u8]> {
        if !self.has_private {
            return Err(CryptoError::Key(
                "SLH-DSA key has no private material (SK.prf)".into(),
            ));
        }
        let n = self.n()?;
        Ok(&self.priv_data[n..2 * n])
    }

    /// Returns the `PK.seed` bytes (public half, third `n` bytes).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if no public key material has been loaded.
    pub fn pk_seed(&self) -> CryptoResult<&[u8]> {
        if !self.has_public {
            return Err(CryptoError::Key(
                "SLH-DSA key has no public material (PK.seed)".into(),
            ));
        }
        let n = self.n()?;
        Ok(&self.priv_data[2 * n..3 * n])
    }

    /// Returns the `PK.root` bytes (public half, fourth `n` bytes).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if no public key material has been loaded.
    pub fn pk_root(&self) -> CryptoResult<&[u8]> {
        if !self.has_public {
            return Err(CryptoError::Key(
                "SLH-DSA key has no public material (PK.root)".into(),
            ));
        }
        let n = self.n()?;
        Ok(&self.priv_data[3 * n..4 * n])
    }

    /// Returns the public key bytes (`PK.seed || PK.root`, length `2n`).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if no public key material has been loaded.
    pub fn pub_bytes(&self) -> CryptoResult<&[u8]> {
        if !self.has_public {
            return Err(CryptoError::Key(
                "SLH-DSA key has no public material".into(),
            ));
        }
        let n = self.n()?;
        Ok(&self.priv_data[2 * n..4 * n])
    }

    /// Returns the private key bytes (`SK.seed || SK.prf || PK.seed || PK.root`, length `4n`).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if no private key material has been loaded.
    pub fn priv_bytes(&self) -> CryptoResult<&[u8]> {
        if !self.has_private {
            return Err(CryptoError::Key(
                "SLH-DSA key has no private material".into(),
            ));
        }
        let n = self.n()?;
        Ok(&self.priv_data[..4 * n])
    }

    /// Returns the public key length in bytes (`2n`).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn pub_len(&self) -> CryptoResult<usize> {
        Ok(self.params_ref()?.pub_len)
    }

    /// Returns the private key length in bytes (`4n`).
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn priv_len(&self) -> CryptoResult<usize> {
        Ok(4 * self.params_ref()?.n)
    }

    /// Returns the signature length in bytes for this parameter set.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn sig_len(&self) -> CryptoResult<usize> {
        Ok(self.params_ref()?.sig_len)
    }

    /// Returns the NIST security category (1, 3, or 5) for this parameter set.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn security_category(&self) -> CryptoResult<u32> {
        Ok(self.params_ref()?.security_category)
    }

    /// Returns the canonical algorithm name (e.g. `"SLH-DSA-SHA2-128s"`).
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        match self.params {
            Some(p) => p.alg,
            None => "SLH-DSA-UNKNOWN",
        }
    }

    /// Returns true if this key has the requested key material (public, private, or both).
    #[must_use]
    pub fn has_key(&self, selection: KeySelection) -> bool {
        match selection {
            KeySelection::PublicOnly => self.has_public,
            KeySelection::PrivateOnly => self.has_private,
            KeySelection::KeyPair => self.has_public && self.has_private,
        }
    }
}

impl SlhDsaKey {
    /// Sets the public key material from a `PK.seed || PK.root` byte sequence
    /// of length `2n`.
    ///
    /// After this call, [`SlhDsaKey::has_key`] with [`KeySelection::PublicOnly`]
    /// returns `true`; private material is left untouched.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if `pub_bytes` does not have the expected
    /// length `2n` for the bound parameter set.
    pub fn set_pub(&mut self, pub_bytes: &[u8]) -> CryptoResult<()> {
        let params = self.params_ref()?;
        let expected = params.pub_len;
        if pub_bytes.len() != expected {
            return Err(CryptoError::Key(format!(
                "SLH-DSA public key length mismatch: expected {expected}, got {}",
                pub_bytes.len()
            )));
        }
        let n = params.n;
        // PK.seed and PK.root live at [2n..3n] and [3n..4n] respectively.
        self.priv_data[2 * n..4 * n].copy_from_slice(pub_bytes);
        self.has_public = true;
        Ok(())
    }

    /// Sets the private key material from a `SK.seed || SK.prf || PK.seed || PK.root`
    /// byte sequence of length `4n`.
    ///
    /// After this call, both public and private halves are considered loaded.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if `priv_bytes` does not have the expected
    /// length `4n` for the bound parameter set.
    pub fn set_priv(&mut self, priv_bytes: &[u8]) -> CryptoResult<()> {
        let params = self.params_ref()?;
        let expected = 4 * params.n;
        if priv_bytes.len() != expected {
            return Err(CryptoError::Key(format!(
                "SLH-DSA private key length mismatch: expected {expected}, got {}",
                priv_bytes.len()
            )));
        }
        self.priv_data[..expected].copy_from_slice(priv_bytes);
        self.has_private = true;
        self.has_public = true;
        Ok(())
    }

    /// Compares two keys for equality in constant time, restricted to the
    /// requested selection (public, private, or both).
    ///
    /// Returns `false` if the parameter sets differ or if the requested
    /// components are not loaded on both keys.
    ///
    /// Uses [`ConstantTimeEq`] to avoid timing side-channels when comparing
    /// private key material.
    #[must_use]
    pub fn equal(&self, other: &Self, selection: KeySelection) -> bool {
        let (Some(a_params), Some(b_params)) = (self.params, other.params) else {
            return false;
        };
        if a_params.variant != b_params.variant || a_params.n != b_params.n {
            return false;
        }
        if !self.has_key(selection) || !other.has_key(selection) {
            return false;
        }
        let n = a_params.n;
        let (start, end) = match selection {
            KeySelection::PublicOnly => (2 * n, 4 * n),
            KeySelection::PrivateOnly => (0, 2 * n),
            KeySelection::KeyPair => (0, 4 * n),
        };
        self.priv_data[start..end]
            .ct_eq(&other.priv_data[start..end])
            .into()
    }

    /// Returns a duplicate of this key restricted to the requested selection.
    ///
    /// Bytes not covered by `selection` remain zero in the returned key.
    /// The library context (if any) is shared via `Arc::clone`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set or if the
    /// requested selection references material that is not loaded.
    pub fn dup(&self, selection: KeySelection) -> CryptoResult<Self> {
        let params = self.params_ref()?;
        let n = params.n;
        let mut out = Self {
            priv_data: [0_u8; 4 * SLH_DSA_MAX_N],
            params: self.params,
            has_private: false,
            has_public: false,
            libctx: self.libctx.clone(),
        };
        if selection.includes_private() {
            if !self.has_private {
                return Err(CryptoError::Key(
                    "cannot duplicate private key: source has no private material".into(),
                ));
            }
            out.priv_data[..2 * n].copy_from_slice(&self.priv_data[..2 * n]);
            out.has_private = true;
        }
        if selection.includes_public() {
            if !self.has_public {
                return Err(CryptoError::Key(
                    "cannot duplicate public key: source has no public material".into(),
                ));
            }
            out.priv_data[2 * n..4 * n].copy_from_slice(&self.priv_data[2 * n..4 * n]);
            out.has_public = true;
        }
        Ok(out)
    }

    /// Verifies that the stored private key is consistent with the stored
    /// public key by recomputing `PK.root` via the top-layer XMSS tree and
    /// comparing to the stored value in constant time.
    ///
    /// This mirrors OpenSSL's `slh_dsa_pairwise_check()` in
    /// `crypto/slh_dsa/slh_dsa_key.c`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if either half of the key is missing or
    /// [`CryptoError::Verification`] if the computed root does not match.
    pub fn pairwise_check(&self) -> CryptoResult<bool> {
        if !self.has_private || !self.has_public {
            return Err(CryptoError::Key(
                "pairwise_check requires both public and private key material".into(),
            ));
        }
        let params = self.params_ref()?;
        let n = params.n;
        let sk_seed = &self.priv_data[..n];
        let pk_seed = &self.priv_data[2 * n..3 * n];
        let pk_root_stored = &self.priv_data[3 * n..4 * n];

        let hash = get_hash_func(params);
        let mut adrs = Adrs::new();
        // Top-level XMSS tree lives at the final hypertree layer (d-1).
        let top_layer = u32::try_from(params.d - 1).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "slh_dsa params.d exceeds u32::MAX".to_owned(),
            ))
        })?;
        adrs.set_layer(top_layer);
        adrs.set_tree(0);

        let recomputed = xmss_node(
            hash.as_ref(),
            sk_seed,
            pk_seed,
            &mut adrs,
            0,
            params.h_prime,
        )?;
        if recomputed.len() != n {
            return Err(CryptoError::Common(CommonError::Internal(
                "xmss_node returned wrong length during pairwise check".to_owned(),
            )));
        }
        let matched: bool = recomputed[..].ct_eq(pk_root_stored).into();
        Ok(matched)
    }
}

impl SlhDsaKey {
    /// Generates a new SLH-DSA keypair for the bound parameter set using the
    /// supplied entropy (`SK.seed || SK.prf || PK.seed`, length `3n`).
    ///
    /// This is equivalent to FIPS 205 Algorithm 21 (`slh_keygen_internal`):
    /// the three seeds are copied into the key buffer and `PK.root` is
    /// computed as the root of the top-layer XMSS tree over
    /// `(SK.seed, PK.seed)` at `layer = d-1, tree = 0`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Rand`] if the seed length is incorrect,
    /// or propagates any error from the XMSS root computation.
    pub fn generate_internal(&mut self, seed_material: &[u8]) -> CryptoResult<()> {
        let params = self.params_ref()?;
        let n = params.n;
        if seed_material.len() != 3 * n {
            return Err(CryptoError::Rand(format!(
                "SLH-DSA key generation seed must be 3n={} bytes, got {}",
                3 * n,
                seed_material.len()
            )));
        }
        // SK.seed || SK.prf in the first 2n bytes, PK.seed at [2n..3n].
        self.priv_data[..2 * n].copy_from_slice(&seed_material[..2 * n]);
        self.priv_data[2 * n..3 * n].copy_from_slice(&seed_material[2 * n..3 * n]);
        // Zero PK.root until we compute it.
        for byte in &mut self.priv_data[3 * n..4 * n] {
            *byte = 0;
        }
        self.has_private = true;
        self.has_public = true;

        // Compute PK.root via XMSS node at top layer.
        let hash = get_hash_func(params);
        let mut adrs = Adrs::new();
        let top_layer = u32::try_from(params.d - 1).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "slh_dsa params.d exceeds u32::MAX".to_owned(),
            ))
        })?;
        adrs.set_layer(top_layer);
        adrs.set_tree(0);

        let (sk_seed_slice, rest) = self.priv_data.split_at_mut(n);
        let (_sk_prf_slice, pk_half) = rest.split_at_mut(n);
        // pk_half starts with PK.seed (n bytes) then PK.root (n bytes).
        let (pk_seed_slice, pk_root_slice) = pk_half.split_at_mut(n);
        let root = xmss_node(
            hash.as_ref(),
            &sk_seed_slice[..n],
            &pk_seed_slice[..n],
            &mut adrs,
            0,
            params.h_prime,
        )?;
        if root.len() != n {
            return Err(CryptoError::Common(CommonError::Internal(
                "xmss_node returned wrong length during keygen".to_owned(),
            )));
        }
        pk_root_slice[..n].copy_from_slice(&root);
        Ok(())
    }

    /// Generates a new SLH-DSA keypair using entropy from `OsRng`.
    ///
    /// This is the high-level keypair generation function equivalent to
    /// OpenSSL's `ossl_slh_dsa_generate_key`: seed material is sampled from
    /// the operating system RNG, then passed to [`SlhDsaKey::generate_internal`].
    ///
    /// # Errors
    /// Returns [`CryptoError::AlgorithmNotFound`] if `alg` is unknown,
    /// [`CryptoError::Rand`] on RNG failures, or propagates XMSS errors.
    pub fn generate(libctx: Arc<LibContext>, alg: &str) -> CryptoResult<Self> {
        let params = slh_dsa_params_get(alg)
            .ok_or_else(|| CryptoError::AlgorithmNotFound(alg.to_owned()))?;
        let mut key = Self {
            priv_data: [0_u8; 4 * SLH_DSA_MAX_N],
            params: Some(params),
            has_private: false,
            has_public: false,
            libctx: Some(libctx),
        };
        let mut seed = [0_u8; 3 * SLH_DSA_MAX_N];
        let seed_slice = &mut seed[..3 * params.n];
        OsRng
            .try_fill_bytes(seed_slice)
            .map_err(|e| CryptoError::Rand(format!("OsRng failure during SLH-DSA keygen: {e}")))?;
        key.generate_internal(seed_slice)?;
        // Zero the local stack buffer before returning.
        seed.zeroize();
        Ok(key)
    }

    /// Generates a new SLH-DSA keypair using caller-supplied entropy.
    ///
    /// `entropy` must be exactly `3n` bytes long. Use this for deterministic
    /// key generation from pre-sampled DRBG output (e.g., Known Answer Tests).
    ///
    /// # Errors
    /// Returns [`CryptoError::AlgorithmNotFound`] if `alg` is unknown,
    /// [`CryptoError::Rand`] if the entropy length is wrong, or propagates
    /// XMSS errors.
    pub fn generate_with_entropy(
        libctx: Arc<LibContext>,
        alg: &str,
        entropy: &[u8],
    ) -> CryptoResult<Self> {
        let mut key = Self::new(libctx, alg)?;
        key.generate_internal(entropy)?;
        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA Hash Context
// ---------------------------------------------------------------------------

/// Per-operation context bundling an [`SlhDsaKey`] with its hash function.
///
/// Mirrors the C `SLH_DSA_HASH_CTX` structure from
/// `crypto/slh_dsa/slh_dsa_hash_ctx.c`: a long-lived handle that an
/// application creates once per key, then reuses across multiple sign or
/// verify calls.
///
/// The hash function vtable is dispatched on-demand from the key's
/// parameter set, mirroring the C vtable selection but leveraging
/// Rust trait objects for static type safety. The key is held behind an
/// `Arc` so that multiple hash contexts can share ownership without copying
/// private material.
pub struct SlhDsaHashCtx {
    /// Shared key reference — provides access to parameters and key bytes.
    key: Arc<SlhDsaKey>,
    /// Hash function dispatch table appropriate for this key's family.
    hash_func: Box<dyn SlhHashFunc>,
    /// Cached parameter set pointer for fast path access.
    params: &'static SlhDsaParams,
}

impl core::fmt::Debug for SlhDsaHashCtx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaHashCtx")
            .field("algorithm", &self.params.alg)
            .finish_non_exhaustive()
    }
}

impl SlhDsaHashCtx {
    /// Creates a new hash context bound to `key`.
    ///
    /// The hash function vtable is selected from the key's parameter set
    /// (SHAKE or SHA-2 family). The key's parameter set must be initialised.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn new(key: Arc<SlhDsaKey>) -> CryptoResult<Self> {
        let params = key.params_ref()?;
        let hash_func = get_hash_func(params);
        Ok(Self {
            key,
            hash_func,
            params,
        })
    }

    /// Duplicates the hash context, sharing the underlying key via `Arc::clone`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Key`] if the key has no parameter set.
    pub fn dup(&self) -> CryptoResult<Self> {
        Self::new(Arc::clone(&self.key))
    }

    /// Returns a reference to the underlying key.
    #[must_use]
    pub fn key(&self) -> &SlhDsaKey {
        &self.key
    }

    /// Returns the parameter set associated with this context.
    #[must_use]
    pub fn params(&self) -> &'static SlhDsaParams {
        self.params
    }

    /// Returns a reference to the hash function dispatch table.
    #[must_use]
    pub fn hash_func(&self) -> &dyn SlhHashFunc {
        self.hash_func.as_ref()
    }
}

// ---------------------------------------------------------------------------
// WOTS+ (FIPS 205 §4 / §5)
// ---------------------------------------------------------------------------

/// Expands the 2n message bytes into `2n` base-16 nibbles (one nibble per
/// half-byte, high nibble first).
///
/// This is the `base_w` routine from FIPS 205 Algorithm 4 specialised to
/// `w = 16`, `out_len = 2n`. The nibbles are stored in `u8` slots (one per
/// nibble) to keep the WOTS+ chain loop simple.
fn bytes_to_nibbles(msg: &[u8], out: &mut [u8]) {
    // out length is exactly 2 * msg.len().
    for (i, byte) in msg.iter().enumerate() {
        out[2 * i] = (*byte >> NIBBLE_SHIFT) & NIBBLE_MASK;
        out[2 * i + 1] = *byte & NIBBLE_MASK;
    }
}

/// Computes the WOTS+ checksum and appends it as 3 nibbles after the 2n
/// message nibbles, per FIPS 205 Algorithm 7 steps 3–6.
///
/// `nibbles[0..2n]` must already contain the base-16 expansion of the
/// message; the function writes the 3 checksum nibbles into `nibbles[2n..2n+3]`.
fn compute_checksum_nibbles(nibbles: &mut [u8], two_n: usize) {
    // csum = sum_{i=0..2n-1} (w - 1 - nibble_i), w = 16.
    let mut csum: u32 = 0;
    for &nibble in nibbles.iter().take(two_n) {
        csum += u32::from(NIBBLE_MASK) - u32::from(nibble);
    }
    // Encode csum as 12 bits (3 nibbles): MSB first.
    // TRUNCATION (×3): each cast extracts a 4-bit nibble via the bitwise AND
    // `& u32::from(NIBBLE_MASK)` where `NIBBLE_MASK = 0x0f`. The mask
    // guarantees the resulting `u32` value is in `[0, 15]`, which fits
    // losslessly in `u8`. Per FIPS 205 Algorithm 7 (WOTS+ checksum), the
    // 12-bit `csum` is encoded as 3 nibbles, MSB-first, into the trailing
    // slots of the WOTS+ message expansion.
    #[allow(clippy::cast_possible_truncation)]
    {
        nibbles[two_n] = ((csum >> 8) & u32::from(NIBBLE_MASK)) as u8;
        nibbles[two_n + 1] = ((csum >> 4) & u32::from(NIBBLE_MASK)) as u8;
        nibbles[two_n + 2] = (csum & u32::from(NIBBLE_MASK)) as u8;
    }
}

/// WOTS+ hash chain: iterates the `F` hash function `steps` times on `inp`,
/// starting from address `start_index`, with `adrs` used as the per-iteration
/// hash-address tweak (each iteration updates `adrs.set_hash()`).
///
/// Mirrors FIPS 205 Algorithm 5.
fn wots_chain(
    hash: &dyn SlhHashFunc,
    pk_seed: &[u8],
    sk: &[u8],
    start_index: u32,
    steps: u32,
    adrs: &mut Adrs,
    out: &mut [u8],
) -> CryptoResult<()> {
    let n = sk.len();
    if out.len() < n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_chain output buffer too small".into(),
        )));
    }
    let end = start_index.checked_add(steps).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "wots_chain start+steps",
        })
    })?;
    if end > u32::from(NIBBLE_MASK) + 1 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_chain total steps exceed w=16".into(),
        )));
    }
    out[..n].copy_from_slice(sk);
    // Use a small stack scratch buffer to avoid aliasing problems when
    // feeding `out` back into `f(...)` which also writes `out`.
    let mut scratch = [0_u8; SLH_DSA_MAX_N];
    for i in start_index..end {
        adrs.set_hash(i);
        scratch[..n].copy_from_slice(&out[..n]);
        hash.f(pk_seed, adrs, &scratch[..n], &mut out[..n])?;
    }
    Ok(())
}

/// WOTS+ Public Key Generation (FIPS 205 Algorithm 6).
///
/// Produces a `n`-byte WOTS+ public key at the address identified by `adrs`.
///
/// The public key is obtained by generating each of `len = 2n + 3` chain
/// secrets via `PRF`, iterating the `F` chain `w - 1` times (full depth),
/// then compressing the resulting `len * n` bytes with `T`.
fn wots_pk_gen(
    hash: &dyn SlhHashFunc,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    pk_out: &mut [u8],
) -> CryptoResult<()> {
    let n = sk_seed.len();
    if pk_seed.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_pk_gen: pk_seed length mismatch".into(),
        )));
    }
    if pk_out.len() < n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_pk_gen: pk_out too small".into(),
        )));
    }
    let len = 2 * n + SLH_WOTS_LEN2;
    // Build sk_adrs as a copy of adrs with type set to WOTS_PRF.
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type(AdrsType::ForsPk); // discriminant 5 == WOTS_PRF
    sk_adrs.copy_keypair(adrs);

    // Accumulate all len WOTS+ chain outputs into a heap buffer, then hash with T.
    let total = len.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "wots_pk_gen len*n",
        })
    })?;
    let mut tmp = vec![0_u8; total];
    let mut sk = [0_u8; SLH_DSA_MAX_N];

    for i in 0..len {
        let i_u32 = u32::try_from(i).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "wots_pk_gen: chain index exceeds u32::MAX".to_owned(),
            ))
        })?;
        sk_adrs.set_chain(i_u32);
        hash.prf(pk_seed, sk_seed, &sk_adrs, &mut sk[..n])?;
        adrs.set_chain(i_u32);
        wots_chain(
            hash,
            pk_seed,
            &sk[..n],
            0,
            u32::from(NIBBLE_MASK),
            adrs,
            &mut tmp[i * n..(i + 1) * n],
        )?;
    }
    // Zero the stack scratch before exit.
    sk.zeroize();

    // WOTS+ pk_adrs
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type(AdrsType::WotsPk);
    pk_adrs.copy_keypair(adrs);
    hash.t(pk_seed, &pk_adrs, &[&tmp[..]], &mut pk_out[..n])
}

/// WOTS+ Sign (FIPS 205 Algorithm 7).
///
/// Produces a WOTS+ signature of length `len * n` for the given `n`-byte
/// message `msg`.
fn wots_sign(
    hash: &dyn SlhHashFunc,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    msg: &[u8],
    sig_out: &mut [u8],
) -> CryptoResult<()> {
    let n = sk_seed.len();
    if pk_seed.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_sign: pk_seed length mismatch".into(),
        )));
    }
    if msg.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_sign: msg length mismatch (expected n)".into(),
        )));
    }
    let len = 2 * n + SLH_WOTS_LEN2;
    let total = len.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "wots_sign len*n",
        })
    })?;
    if sig_out.len() < total {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_sign: signature buffer too small".into(),
        )));
    }

    // Build the base-16 digitisation + checksum into a stack buffer.
    // Size upper bound: 2*SLH_DSA_MAX_N + SLH_WOTS_LEN2 = 67.
    let mut nibbles = [0_u8; SLH_WOTS_LEN_MAX];
    bytes_to_nibbles(msg, &mut nibbles[..2 * n]);
    compute_checksum_nibbles(&mut nibbles, 2 * n);

    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type(AdrsType::ForsPk); // discriminant 5 == WOTS_PRF
    sk_adrs.copy_keypair(adrs);

    let mut sk = [0_u8; SLH_DSA_MAX_N];
    for i in 0..len {
        let i_u32 = u32::try_from(i).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "wots_sign: chain index exceeds u32::MAX".to_owned(),
            ))
        })?;
        sk_adrs.set_chain(i_u32);
        hash.prf(pk_seed, sk_seed, &sk_adrs, &mut sk[..n])?;
        adrs.set_chain(i_u32);
        wots_chain(
            hash,
            pk_seed,
            &sk[..n],
            0,
            u32::from(nibbles[i]),
            adrs,
            &mut sig_out[i * n..(i + 1) * n],
        )?;
    }
    sk.zeroize();
    Ok(())
}

/// WOTS+ Public Key from Signature (FIPS 205 Algorithm 8).
///
/// Reconstructs the WOTS+ public key from a signature and message. The
/// reconstructed public key is written to `pk_out` (length `n`).
fn wots_pk_from_sig(
    hash: &dyn SlhHashFunc,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    sig: &[u8],
    msg: &[u8],
    pk_out: &mut [u8],
) -> CryptoResult<()> {
    let n = pk_seed.len();
    if msg.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_pk_from_sig: msg length mismatch".into(),
        )));
    }
    if pk_out.len() < n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_pk_from_sig: pk_out too small".into(),
        )));
    }
    let len = 2 * n + SLH_WOTS_LEN2;
    let total = len.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "wots_pk_from_sig len*n",
        })
    })?;
    if sig.len() < total {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "wots_pk_from_sig: signature too short".into(),
        )));
    }

    let mut nibbles = [0_u8; SLH_WOTS_LEN_MAX];
    bytes_to_nibbles(msg, &mut nibbles[..2 * n]);
    compute_checksum_nibbles(&mut nibbles, 2 * n);

    let mut tmp = vec![0_u8; total];
    for i in 0..len {
        let i_u32 = u32::try_from(i).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "wots_pk_from_sig: chain index exceeds u32::MAX".to_owned(),
            ))
        })?;
        adrs.set_chain(i_u32);
        let start = u32::from(nibbles[i]);
        let steps = u32::from(NIBBLE_MASK) - start;
        wots_chain(
            hash,
            pk_seed,
            &sig[i * n..(i + 1) * n],
            start,
            steps,
            adrs,
            &mut tmp[i * n..(i + 1) * n],
        )?;
    }

    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type(AdrsType::WotsPk);
    pk_adrs.copy_keypair(adrs);
    hash.t(pk_seed, &pk_adrs, &[&tmp[..]], &mut pk_out[..n])
}

// ---------------------------------------------------------------------------
// XMSS (FIPS 205 §6)
// ---------------------------------------------------------------------------

/// Recursive XMSS node computation (FIPS 205 Algorithm 9 — `xmss_node`).
///
/// Returns the `n`-byte hash of the XMSS subtree rooted at
/// `(height, node_id)`. When `height == 0` the node is a WOTS+ leaf public
/// key; when `height > 0` the node is `H(left_child || right_child)` with
/// `adrs` set up as `TREE` type.
///
/// This is an iterative stack-based reimplementation of the C recursive
/// version in `crypto/slh_dsa/slh_xmss.c` so that deep trees (h' up to 9)
/// cannot overflow the Rust thread stack.
fn xmss_node(
    hash: &dyn SlhHashFunc,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    node_id: u32,
    height: usize,
) -> CryptoResult<Vec<u8>> {
    let n = sk_seed.len();
    if pk_seed.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "xmss_node: pk_seed length mismatch".into(),
        )));
    }

    // Stack of (height, node_id, partial_hash) pairs.
    //
    // We descend to the leftmost leaf at `height`, compute it, then unwind
    // combining with freshly-computed right subtrees. The stack height is
    // bounded by the XMSS subtree height (h' ≤ 9), so a small Vec is ample.
    let total_leaves = 1u64
        .checked_shl(u32::try_from(height).map_err(|_| {
            CryptoError::Common(CommonError::InvalidArgument(
                "xmss_node: height too large".into(),
            ))
        })?)
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "xmss_node 2^height",
            })
        })?;
    let node_id_u64 = u64::from(node_id);
    let start_leaf = node_id_u64.checked_mul(total_leaves).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "xmss_node node_id*2^height",
        })
    })?;
    let end_leaf = start_leaf.checked_add(total_leaves).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "xmss_node start+2^height",
        })
    })?;

    // Stack entries: (current subtree height, node buffer).
    let mut stack: Vec<(usize, Vec<u8>)> = Vec::with_capacity(height + 1);

    for leaf_id_u64 in start_leaf..end_leaf {
        let leaf_id = u32::try_from(leaf_id_u64).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "xmss_node: leaf id overflow".to_owned(),
            ))
        })?;
        // Compute WOTS+ leaf public key.
        let mut leaf = vec![0_u8; n];
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_keypair(leaf_id);
        wots_pk_gen(hash, sk_seed, pk_seed, adrs, &mut leaf)?;
        let mut cur_height: usize = 0;
        let mut cur_id: u32 = leaf_id;
        let mut cur_node = leaf;

        // Fold up while top of stack matches current height.
        while let Some(&(top_h, _)) = stack.last() {
            if top_h != cur_height {
                break;
            }
            // Pop left sibling, combine with current right sibling.
            // The `while let Some(&(top_h, _)) = stack.last()` guard above
            // proved `stack.last()` is `Some`; `pop()` therefore cannot fail.
            let Some((_, left)) = stack.pop() else {
                return Err(CryptoError::Common(CommonError::Internal(
                    "xmss_node: stack underflow after last-peek".to_owned(),
                )));
            };
            adrs.set_type(AdrsType::Tree);
            let new_height = cur_height + 1;
            let new_height_u32 = u32::try_from(new_height).map_err(|_| {
                CryptoError::Common(CommonError::Internal(
                    "xmss_node: tree height exceeds u32::MAX".to_owned(),
                ))
            })?;
            adrs.set_tree_height(new_height_u32);
            // Parent id in the next level: (cur_id - 1) / 2 (cur_id is odd as right child).
            let parent_id = (cur_id - 1) / 2;
            adrs.set_tree_index(parent_id);
            let mut parent = vec![0_u8; n];
            hash.h(pk_seed, adrs, &left, &cur_node, &mut parent)?;
            cur_node = parent;
            cur_height = new_height;
            cur_id = parent_id;
        }

        // Push current node on the stack.
        stack.push((cur_height, cur_node));
    }

    if stack.len() != 1 {
        return Err(CryptoError::Common(CommonError::Internal(
            "xmss_node: stack did not collapse to a single root".to_owned(),
        )));
    }
    // `stack.len() == 1` was verified immediately above; `pop()` therefore
    // cannot fail. Use `let...else` instead of `.expect()` to satisfy the
    // `clippy::expect_used` lint denied at the workspace level.
    let Some((final_height, root)) = stack.pop() else {
        return Err(CryptoError::Common(CommonError::Internal(
            "xmss_node: stack empty after single-root check".to_owned(),
        )));
    };
    if final_height != height {
        return Err(CryptoError::Common(CommonError::Internal(
            "xmss_node: final stack height does not match requested height".to_owned(),
        )));
    }
    Ok(root)
}

/// XMSS Sign (FIPS 205 Algorithm 10).
///
/// Produces an XMSS signature over `msg` (an `n`-byte value, typically the
/// root of a lower-level XMSS tree in the hypertree) using the leaf at
/// `index`. The signature consists of a WOTS+ signature followed by the
/// authentication path of length `h'` hashes.
fn xmss_sign(
    hash: &dyn SlhHashFunc,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    msg: &[u8],
    index: u32,
    tree_height: usize,
    sig_out: &mut [u8],
) -> CryptoResult<()> {
    let n = sk_seed.len();
    if pk_seed.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "xmss_sign: pk_seed length mismatch".into(),
        )));
    }
    if msg.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "xmss_sign: msg length mismatch".into(),
        )));
    }
    let wots_len = 2 * n + SLH_WOTS_LEN2;
    let wots_sig_bytes = wots_len.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "xmss_sign wots_len*n",
        })
    })?;
    let auth_bytes = tree_height.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "xmss_sign tree_height*n",
        })
    })?;
    let total = wots_sig_bytes + auth_bytes;
    if sig_out.len() < total {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "xmss_sign: signature buffer too small".into(),
        )));
    }

    // WOTS+ sign over the leaf at `index` (into the first wots_sig_bytes of sig_out).
    adrs.set_type(AdrsType::WotsHash);
    adrs.set_keypair(index);
    wots_sign(
        hash,
        sk_seed,
        pk_seed,
        adrs,
        msg,
        &mut sig_out[..wots_sig_bytes],
    )?;

    // Auth path: for each level k in 0..h', sibling id = (index >> k) ^ 1,
    // compute subtree root at (height=k, node_id=sibling_id).
    for k in 0..tree_height {
        let k_u32 = u32::try_from(k).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "xmss_sign: auth level exceeds u32::MAX".to_owned(),
            ))
        })?;
        let sibling = (index >> k_u32) ^ 1;
        let node = xmss_node(hash, sk_seed, pk_seed, adrs, sibling, k)?;
        let off = wots_sig_bytes + k * n;
        sig_out[off..off + n].copy_from_slice(&node);
    }
    Ok(())
}

/// XMSS Public Key from Signature (FIPS 205 Algorithm 11).
///
/// Reconstructs the root of the XMSS tree given a signature, message,
/// and leaf index. Returns the reconstructed root (length `n`).
fn xmss_pk_from_sig(
    hash: &dyn SlhHashFunc,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    sig: &[u8],
    msg: &[u8],
    index: u32,
    tree_height: usize,
) -> CryptoResult<Vec<u8>> {
    let n = pk_seed.len();
    if msg.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "xmss_pk_from_sig: msg length mismatch".into(),
        )));
    }
    let wots_len = 2 * n + SLH_WOTS_LEN2;
    let wots_sig_bytes = wots_len.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "xmss_pk_from_sig wots_len*n",
        })
    })?;
    let auth_bytes = tree_height.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "xmss_pk_from_sig tree_height*n",
        })
    })?;
    let total = wots_sig_bytes + auth_bytes;
    if sig.len() < total {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "xmss_pk_from_sig: signature too short".into(),
        )));
    }

    // Recompute WOTS+ leaf public key.
    adrs.set_type(AdrsType::WotsHash);
    adrs.set_keypair(index);
    let mut node = vec![0_u8; n];
    wots_pk_from_sig(hash, pk_seed, adrs, &sig[..wots_sig_bytes], msg, &mut node)?;

    // Walk up with parity-based hashing.
    adrs.set_type(AdrsType::Tree);
    adrs.set_tree_index(index);
    let mut cur_id = index;
    for k in 0..tree_height {
        let k_u32 = u32::try_from(k).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "xmss_pk_from_sig: level exceeds u32::MAX".to_owned(),
            ))
        })?;
        let level_height = k_u32.checked_add(1).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "xmss_pk_from_sig level+1",
            })
        })?;
        adrs.set_tree_height(level_height);
        let auth_off = wots_sig_bytes + k * n;
        let auth = &sig[auth_off..auth_off + n];
        let mut parent = vec![0_u8; n];
        if cur_id % 2 == 0 {
            cur_id /= 2;
            adrs.set_tree_index(cur_id);
            hash.h(pk_seed, adrs, &node, auth, &mut parent)?;
        } else {
            cur_id = (cur_id - 1) / 2;
            adrs.set_tree_index(cur_id);
            hash.h(pk_seed, adrs, auth, &node, &mut parent)?;
        }
        node = parent;
    }
    Ok(node)
}

// ---------------------------------------------------------------------------
// FORS (FIPS 205 §8, Algorithms 14 and 16)
// ---------------------------------------------------------------------------

/// Converts a byte string to a sequence of `out.len()` base-`2^b` integers
/// (FIPS 205 Algorithm 4, specialised for b ≤ 32).
///
/// Values are extracted MSB-first: bytes are accumulated into a 64-bit register
/// and `b` bits are peeled off each iteration. `b` must be in `1..=32` (in
/// practice FORS uses `a ∈ {6, 8, 9, 12, 14}`).
///
/// # Errors
/// - [`CryptoError::Common(CommonError::InvalidArgument)`] if `b` is 0 or > 32,
///   or if `msg` is shorter than `⌈out.len() * b / 8⌉` bytes.
fn slh_base_2b(msg: &[u8], b: u32, out: &mut [u32]) -> CryptoResult<()> {
    if b == 0 || b > 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "slh_base_2b: b={b} must be in 1..=32"
        ))));
    }
    // mask = 2^b - 1; b ≤ 32 so the result fits in u64 safely.
    let mask: u64 = if b == 64 { u64::MAX } else { (1_u64 << b) - 1 };
    let mut total: u64 = 0;
    let mut bits: u32 = 0;
    let mut idx: usize = 0;
    for slot in out.iter_mut() {
        while bits < b {
            if idx >= msg.len() {
                return Err(CryptoError::Common(CommonError::InvalidArgument(
                    "slh_base_2b: input digest too short for requested output".into(),
                )));
            }
            total = (total << 8) | u64::from(msg[idx]);
            idx += 1;
            bits += 8;
        }
        bits -= b;
        let val = (total >> bits) & mask;
        *slot = u32::try_from(val).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "slh_base_2b: extracted value exceeds u32::MAX".to_owned(),
            ))
        })?;
    }
    Ok(())
}

/// FORS secret-key leaf generator (FIPS 205 Algorithm 14).
///
/// Computes `sk = PRF(pk_seed, sk_seed, sk_adrs)` where `sk_adrs` is derived
/// from `adrs` by switching the address type to FORS-PRF (C:
/// `SLH_ADRS_TYPE_FORS_PRF`) and setting the tree-index to `id`.
///
/// The C source uses discriminant 6 (`FORS_PRF`). In this Rust module the
/// `AdrsType::WotsSign` variant carries that discriminant — the schema's
/// variant naming is preserved but the semantic meaning is FORS-PRF.
fn slh_fors_sk_gen(
    hash: &dyn SlhHashFunc,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    id: u32,
    sk_out: &mut [u8],
) -> CryptoResult<()> {
    // Build an sk address: copy the keypair, switch type to FORS-PRF,
    // place `id` in the tree-index field.
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type(AdrsType::WotsSign); // discriminant 6 = FORS_PRF
    sk_adrs.copy_keypair(adrs);
    sk_adrs.set_tree_index(id);
    hash.prf(pk_seed, sk_seed, &sk_adrs, sk_out)
}

/// Recursively computes the FORS subtree root at (node_id, height)
/// (FIPS 205 Algorithm 15).
///
/// - At height 0: returns `F(pk_seed, adrs, sk)` where `sk` is the leaf secret.
/// - At height > 0: recurses into left (2*id) and right (2*id+1) children and
///   combines them via `H(pk_seed, adrs, l, r)`.
///
/// Maximum recursion depth equals `a ≤ 14`, which is safe for Rust's default
/// stack size. `adrs` is mutated in place (set_tree_height / set_tree_index
/// are unconditionally reset before each hash call, so intermediate state
/// leaked across recursive calls is harmless).
fn slh_fors_node(
    hash: &dyn SlhHashFunc,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    node_id: u32,
    height: u32,
    n: usize,
) -> CryptoResult<Vec<u8>> {
    let mut node = vec![0_u8; n];
    if height == 0 {
        let mut sk = vec![0_u8; n];
        slh_fors_sk_gen(hash, sk_seed, pk_seed, adrs, node_id, &mut sk)?;
        adrs.set_tree_height(0);
        adrs.set_tree_index(node_id);
        hash.f(pk_seed, adrs, &sk, &mut node)?;
    } else {
        let child_height = height.checked_sub(1).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "slh_fors_node height-1",
            })
        })?;
        let left_id = node_id.checked_mul(2).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "slh_fors_node node_id*2",
            })
        })?;
        let right_id = left_id.checked_add(1).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "slh_fors_node node_id*2+1",
            })
        })?;
        let lnode = slh_fors_node(hash, sk_seed, pk_seed, adrs, left_id, child_height, n)?;
        let rnode = slh_fors_node(hash, sk_seed, pk_seed, adrs, right_id, child_height, n)?;
        adrs.set_tree_height(height);
        adrs.set_tree_index(node_id);
        hash.h(pk_seed, adrs, &lnode, &rnode, &mut node)?;
    }
    Ok(node)
}

/// FORS signing (FIPS 205 Algorithm 16).
///
/// Writes `k * (a+1) * n` signature bytes to `sig_out`: for each of the `k`
/// FORS trees, one leaf secret (`n` bytes) followed by `a` authentication
/// path nodes (`a * n` bytes).
///
/// The message digest `md` is interpreted as `k` base-`2^a` indices
/// (one leaf per FORS tree) via [`slh_base_2b`].
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if `sig_out`
/// is too small, and arithmetic-overflow errors for pathological parameter
/// combinations.
fn ossl_slh_fors_sign(
    hash: &dyn SlhHashFunc,
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
    sig_out: &mut [u8],
) -> CryptoResult<()> {
    let n = params.n;
    let k = params.k;
    let a = params.a;
    let a_u32 = u32::try_from(a).map_err(|_| {
        CryptoError::Common(CommonError::Internal(
            "fors_sign: a exceeds u32::MAX".to_owned(),
        ))
    })?;
    if a_u32 >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "fors_sign: a={a_u32} too large (must be <32)"
        ))));
    }
    let two_power_a: u32 = 1_u32 << a_u32;

    let per_tree_bytes = n.checked_mul(a + 1).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "fors_sign n*(a+1)",
        })
    })?;
    let total_bytes = per_tree_bytes.checked_mul(k).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "fors_sign k*n*(a+1)",
        })
    })?;
    if sig_out.len() < total_bytes {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "fors_sign: signature buffer too small".into(),
        )));
    }

    // Extract k base-2^a indices from the message digest.
    let mut ids = vec![0_u32; k];
    slh_base_2b(md, a_u32, &mut ids)?;

    let mut tree_offset_base: u32 = 0;
    let mut offset: usize = 0;
    for tree_idx in 0..k {
        let mut node_id = ids[tree_idx];
        let mut tree_offset = tree_offset_base;

        // Absolute leaf address for the leaf we're signing.
        let abs_leaf = node_id.checked_add(tree_offset_base).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "fors_sign leaf_id+tree_offset",
            })
        })?;

        // (1) Write the leaf secret key for this tree.
        slh_fors_sk_gen(
            hash,
            sk_seed,
            pk_seed,
            adrs,
            abs_leaf,
            &mut sig_out[offset..offset + n],
        )?;
        offset += n;

        // (2) Write the auth path for this tree (a nodes).
        for layer in 0..a {
            let layer_u32 = u32::try_from(layer).map_err(|_| {
                CryptoError::Common(CommonError::Internal(
                    "fors_sign: layer exceeds u32::MAX".to_owned(),
                ))
            })?;
            let sibling = node_id ^ 1;
            let sibling_abs = sibling.checked_add(tree_offset).ok_or_else(|| {
                CryptoError::Common(CommonError::ArithmeticOverflow {
                    operation: "fors_sign sibling+tree_offset",
                })
            })?;
            let node = slh_fors_node(hash, sk_seed, pk_seed, adrs, sibling_abs, layer_u32, n)?;
            sig_out[offset..offset + n].copy_from_slice(&node);
            offset += n;
            node_id >>= 1;
            tree_offset >>= 1;
        }

        // Move base to the next tree's 2^a leaves.
        tree_offset_base = tree_offset_base.checked_add(two_power_a).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "fors_sign tree_offset_base+2^a",
            })
        })?;
    }
    Ok(())
}

/// Reconstructs the FORS public key from a signature (FIPS 205 Algorithm 17).
///
/// Given `sig` = `k` concatenated (sk ‖ auth-path) blocks and the same digest
/// indices that generated the signature, walks each tree upwards to its root,
/// collects the `k` roots, then applies `T_k` to produce the FORS public key.
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if `sig` is
/// too short or `pk_out` has length less than `n`.
fn ossl_slh_fors_pk_from_sig(
    hash: &dyn SlhHashFunc,
    sig: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &SlhDsaParams,
    pk_out: &mut [u8],
) -> CryptoResult<()> {
    let n = params.n;
    let k = params.k;
    let a = params.a;
    let a_u32 = u32::try_from(a).map_err(|_| {
        CryptoError::Common(CommonError::Internal(
            "fors_pk_from_sig: a exceeds u32::MAX".to_owned(),
        ))
    })?;
    if a_u32 >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "fors_pk_from_sig: a={a_u32} too large (must be <32)"
        ))));
    }
    let two_power_a: u32 = 1_u32 << a_u32;

    let per_tree_bytes = n.checked_mul(a + 1).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "fors_pk_from_sig n*(a+1)",
        })
    })?;
    let total_bytes = per_tree_bytes.checked_mul(k).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "fors_pk_from_sig k*n*(a+1)",
        })
    })?;
    if sig.len() < total_bytes {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "fors_pk_from_sig: signature too short".into(),
        )));
    }
    if pk_out.len() < n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "fors_pk_from_sig: public-key output buffer too small".into(),
        )));
    }

    // Extract k base-2^a indices from the digest.
    let mut ids = vec![0_u32; k];
    slh_base_2b(md, a_u32, &mut ids)?;

    // Buffer to hold the k reconstructed tree roots.
    let roots_len = k.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "fors_pk_from_sig k*n",
        })
    })?;
    let mut roots = vec![0_u8; roots_len];

    let mut sig_off: usize = 0;
    let mut aoff: u32 = 0;
    for i in 0..k {
        let mut id = ids[i];
        let mut node_id = id.checked_add(aoff).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "fors_pk_from_sig id+aoff",
            })
        })?;

        // Leaf: node ← F(pk_seed, adrs@height=0,index=node_id, sk)
        adrs.set_tree_height(0);
        adrs.set_tree_index(node_id);
        let sk = &sig[sig_off..sig_off + n];
        sig_off += n;
        let mut node = vec![0_u8; n];
        hash.f(pk_seed, adrs, sk, &mut node)?;

        // Walk up auth path (a levels).
        for layer in 0..a {
            let level_height = u32::try_from(layer + 1).map_err(|_| {
                CryptoError::Common(CommonError::Internal(
                    "fors_pk_from_sig: layer+1 exceeds u32::MAX".to_owned(),
                ))
            })?;
            let auth = &sig[sig_off..sig_off + n];
            sig_off += n;
            adrs.set_tree_height(level_height);
            let mut parent = vec![0_u8; n];
            if (id & 1) == 0 {
                // node is the left child
                node_id >>= 1;
                adrs.set_tree_index(node_id);
                hash.h(pk_seed, adrs, &node, auth, &mut parent)?;
            } else {
                // node is the right child
                node_id = node_id.checked_sub(1).ok_or_else(|| {
                    CryptoError::Common(CommonError::ArithmeticOverflow {
                        operation: "fors_pk_from_sig node_id-1",
                    })
                })? >> 1;
                adrs.set_tree_index(node_id);
                hash.h(pk_seed, adrs, auth, &node, &mut parent)?;
            }
            id >>= 1;
            node = parent;
        }
        roots[i * n..(i + 1) * n].copy_from_slice(&node);

        aoff = aoff.checked_add(two_power_a).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "fors_pk_from_sig aoff+2^a",
            })
        })?;
    }

    // Final: pk_fors = T_k(pk_seed, pk_adrs, roots).
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type(AdrsType::ForsRoots); // discriminant 4 = FORS_ROOTS
    pk_adrs.copy_keypair(adrs);
    let roots_chunks: [&[u8]; 1] = [roots.as_slice()];
    hash.t(pk_seed, &pk_adrs, &roots_chunks, &mut pk_out[..n])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hypertree (FIPS 205 §7, Algorithms 12 and 13)
// ---------------------------------------------------------------------------

/// Computes the number of signature bytes consumed by one XMSS layer of the
/// hypertree: `wots_sig_bytes + h' * n = (2n + 3) * n + h' * n`.
fn ht_layer_sig_bytes(n: usize, h_prime: usize) -> CryptoResult<usize> {
    let wots_len = 2_usize
        .checked_mul(n)
        .and_then(|v| v.checked_add(SLH_WOTS_LEN2))
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "ht_layer_sig_bytes wots_len",
            })
        })?;
    let wots_sig_bytes = wots_len.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ht_layer_sig_bytes wots_sig",
        })
    })?;
    let auth_bytes = h_prime.checked_mul(n).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ht_layer_sig_bytes auth",
        })
    })?;
    wots_sig_bytes.checked_add(auth_bytes).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ht_layer_sig_bytes wots+auth",
        })
    })
}

/// Hypertree signing (FIPS 205 Algorithm 12).
///
/// Produces a sequence of `d` XMSS signatures that together certify `msg`
/// under the hypertree rooted at the key's public root. The bottom layer
/// signs `msg`; every subsequent layer signs the preceding layer's XMSS
/// public-key root.
///
/// The caller supplies the initial `tree_id` and `leaf_id` (derived from
/// the message digest for SLH-DSA sign; derived from FORS PK for verify).
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if
/// `sig_out` is too small or per-layer arithmetic overflows.
fn ossl_slh_ht_sign(
    hash: &dyn SlhHashFunc,
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    params: &SlhDsaParams,
    mut tree_id: u64,
    mut leaf_id: u32,
    sig_out: &mut [u8],
) -> CryptoResult<()> {
    let n = params.n;
    let d = params.d;
    let h_prime = params.h_prime;

    if msg.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "ht_sign: msg length must equal n".into(),
        )));
    }

    let h_prime_u32 = u32::try_from(h_prime).map_err(|_| {
        CryptoError::Common(CommonError::Internal(
            "ht_sign: h_prime exceeds u32::MAX".to_owned(),
        ))
    })?;
    if h_prime_u32 >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "ht_sign: h_prime={h_prime_u32} too large (must be <32)"
        ))));
    }
    let mask: u32 = if h_prime_u32 == 0 {
        0
    } else {
        1_u32.checked_shl(h_prime_u32).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "ht_sign 1<<h_prime",
            })
        })? - 1
    };

    let layer_bytes = ht_layer_sig_bytes(n, h_prime)?;
    let total_bytes = layer_bytes.checked_mul(d).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ht_sign total bytes",
        })
    })?;
    if sig_out.len() < total_bytes {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "ht_sign: signature buffer too small".into(),
        )));
    }

    let mut adrs = Adrs::new();
    adrs.zero();
    let mut node: Vec<u8> = msg.to_vec();
    let mut offset: usize = 0;
    for layer in 0..d {
        let layer_u32 = u32::try_from(layer).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "ht_sign: layer exceeds u32::MAX".to_owned(),
            ))
        })?;
        adrs.set_layer(layer_u32);
        adrs.set_tree(tree_id);

        let layer_start = offset;
        let layer_end = offset.checked_add(layer_bytes).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "ht_sign layer offset",
            })
        })?;

        // XMSS-sign `node` at (tree_id, leaf_id) for this layer.
        xmss_sign(
            hash,
            sk_seed,
            pk_seed,
            &mut adrs,
            &node,
            leaf_id,
            h_prime,
            &mut sig_out[layer_start..layer_end],
        )?;

        // Derive this layer's root and the next (tree_id, leaf_id) unless
        // this is the final layer. The borrow order matters:
        //   1. Reuse `&node` to derive `new_node` via pk_from_sig
        //   2. Move `new_node` into `node` (replacing the old contents)
        if layer < d - 1 {
            let new_node = xmss_pk_from_sig(
                hash,
                pk_seed,
                &mut adrs,
                &sig_out[layer_start..layer_end],
                &node,
                leaf_id,
                h_prime,
            )?;
            node = new_node;

            // Prepare (tree_id, leaf_id) for the next layer: the low h'
            // bits of the current tree_id become the next leaf_id.
            let low_bits = tree_id & u64::from(mask);
            leaf_id = u32::try_from(low_bits).map_err(|_| {
                CryptoError::Common(CommonError::Internal(
                    "ht_sign: leaf_id derivation overflow".to_owned(),
                ))
            })?;
            tree_id >>= h_prime_u32;
        }

        offset = layer_end;
    }
    Ok(())
}

/// Hypertree verification (FIPS 205 Algorithm 13).
///
/// Walks the `d` XMSS signatures in `sig`, reconstructing the hypertree root
/// step by step. Returns `Ok(true)` iff the reconstructed root matches
/// `pk_root` in constant time.
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if `sig` is
/// too short, `msg` has wrong length, or arithmetic overflow occurs.
fn ossl_slh_ht_verify(
    hash: &dyn SlhHashFunc,
    msg: &[u8],
    sig: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    params: &SlhDsaParams,
    mut tree_id: u64,
    mut leaf_id: u32,
) -> CryptoResult<bool> {
    let n = params.n;
    let d = params.d;
    let h_prime = params.h_prime;

    if msg.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "ht_verify: msg length must equal n".into(),
        )));
    }
    if pk_root.len() != n {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "ht_verify: pk_root length must equal n".into(),
        )));
    }

    let h_prime_u32 = u32::try_from(h_prime).map_err(|_| {
        CryptoError::Common(CommonError::Internal(
            "ht_verify: h_prime exceeds u32::MAX".to_owned(),
        ))
    })?;
    if h_prime_u32 >= 32 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "ht_verify: h_prime={h_prime_u32} too large (must be <32)"
        ))));
    }
    let mask: u32 = if h_prime_u32 == 0 {
        0
    } else {
        1_u32.checked_shl(h_prime_u32).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "ht_verify 1<<h_prime",
            })
        })? - 1
    };

    let layer_bytes = ht_layer_sig_bytes(n, h_prime)?;
    let total_bytes = layer_bytes.checked_mul(d).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "ht_verify total bytes",
        })
    })?;
    if sig.len() < total_bytes {
        return Err(CryptoError::Common(CommonError::InvalidArgument(
            "ht_verify: signature too short".into(),
        )));
    }

    let mut adrs = Adrs::new();
    adrs.zero();
    let mut node: Vec<u8> = msg.to_vec();
    let mut offset: usize = 0;
    for layer in 0..d {
        let layer_u32 = u32::try_from(layer).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "ht_verify: layer exceeds u32::MAX".to_owned(),
            ))
        })?;
        adrs.set_layer(layer_u32);
        adrs.set_tree(tree_id);

        let layer_end = offset.checked_add(layer_bytes).ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "ht_verify layer offset",
            })
        })?;

        node = xmss_pk_from_sig(
            hash,
            pk_seed,
            &mut adrs,
            &sig[offset..layer_end],
            &node,
            leaf_id,
            h_prime,
        )?;

        if layer < d - 1 {
            let low_bits = tree_id & u64::from(mask);
            leaf_id = u32::try_from(low_bits).map_err(|_| {
                CryptoError::Common(CommonError::Internal(
                    "ht_verify: leaf_id derivation overflow".to_owned(),
                ))
            })?;
            tree_id >>= h_prime_u32;
        }

        offset = layer_end;
    }

    // Constant-time comparison against the expected root.
    Ok(node.ct_eq(pk_root).unwrap_u8() == 1)
}

// ---------------------------------------------------------------------------
// Top-level message encoding helpers (FIPS 205 §10, Algorithms 22 / 23 / 24)
// ---------------------------------------------------------------------------

/// Encodes a message for SLH-DSA pure signing per FIPS 205 §10.2 (Algorithm 23).
///
/// When `encode` is `true`, the returned buffer is:
///
/// ```text
///     0x00 || ctx_len (1 byte) || ctx || msg
/// ```
///
/// where `ctx_len` is the length of the context string in a single byte
/// (`0..=255`). When `encode` is `false`, the message is passed through
/// untouched — this path is used for the pre-hashed variant where the caller
/// has already prepared an encoded payload.
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if the
/// context string exceeds [`SLH_DSA_MAX_CONTEXT_STRING_LEN`] (255 bytes)
/// or if the arithmetic of the encoded length overflows.
fn msg_encode(msg: &[u8], ctx: &[u8], encode: bool) -> CryptoResult<Vec<u8>> {
    if !encode {
        return Ok(msg.to_vec());
    }
    if ctx.len() > SLH_DSA_MAX_CONTEXT_STRING_LEN {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "slh_dsa: context string length {} exceeds maximum {}",
            ctx.len(),
            SLH_DSA_MAX_CONTEXT_STRING_LEN
        ))));
    }

    // ctx.len() already verified <= 255, so the cast is lossless.
    let ctx_len_u8 = u8::try_from(ctx.len()).map_err(|_| {
        CryptoError::Common(CommonError::Internal(
            "msg_encode: context length u8 conversion failed".to_owned(),
        ))
    })?;

    // Total length = 2 (domain byte + length byte) + ctx.len() + msg.len().
    let total_len = 2_usize
        .checked_add(ctx.len())
        .and_then(|v| v.checked_add(msg.len()))
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "msg_encode total length",
            })
        })?;

    let mut out = Vec::with_capacity(total_len);
    out.push(0x00);
    out.push(ctx_len_u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(msg);
    Ok(out)
}

/// Converts a big-endian byte slice into a `u64` value.
///
/// The slice must have length `<= 8`. Each byte is shifted into the
/// accumulator from most-significant to least-significant.
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if
/// `input.len() > 8` (would overflow `u64`).
fn bytes_to_u64_be(input: &[u8]) -> CryptoResult<u64> {
    if input.len() > 8 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "bytes_to_u64_be: input length {} exceeds 8",
            input.len()
        ))));
    }
    let mut total: u64 = 0;
    for &b in input {
        total = (total << 8) | u64::from(b);
    }
    Ok(total)
}

/// Extracts the tree and leaf identifiers from the tail of a message digest
/// per FIPS 205 §10.2.1 (Algorithm 22).
///
/// After computing the message digest, the first `md_len = ceil(k*a/8)` bytes
/// contain the FORS digest. The next `ceil((h - h') / 8)` bytes encode the
/// hypertree tree id (masked to `h - h'` bits), followed by `ceil(h' / 8)`
/// bytes encoding the bottom-layer leaf id (masked to `h'` bits).
///
/// Returns a triple `(tree_id, leaf_id, consumed)` where `consumed` is the
/// number of bytes read from `rest`.
///
/// # Errors
/// Returns [`CryptoError::Common(CommonError::InvalidArgument)`] if `rest`
/// is too short; [`CryptoError::Common(CommonError::Internal)`] for
/// arithmetic overflow of the u32 conversions.
fn get_tree_ids(rest: &[u8], params: &SlhDsaParams) -> CryptoResult<(u64, u32, usize)> {
    let h = params.h;
    let h_prime = params.h_prime;

    // Guard against h_prime exceeding u32 bit width.
    if h_prime >= 64 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "get_tree_ids: h'={h_prime} too large (must be <64)"
        ))));
    }
    if h < h_prime {
        return Err(CryptoError::Common(CommonError::Internal(
            "get_tree_ids: parameter set has h < h_prime".to_owned(),
        )));
    }
    let h_minus_hp = h.checked_sub(h_prime).ok_or_else(|| {
        CryptoError::Common(CommonError::Internal(
            "get_tree_ids: h - h_prime underflow".to_owned(),
        ))
    })?;
    if h_minus_hp > 64 {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "get_tree_ids: h - h'={h_minus_hp} exceeds 64 bits"
        ))));
    }

    // ceil(n / 8) without overflow for small n.
    let tree_id_len = h_minus_hp.checked_add(7).map(|v| v >> 3).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "get_tree_ids tree_id_len",
        })
    })?;
    let leaf_id_len = h_prime.checked_add(7).map(|v| v >> 3).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "get_tree_ids leaf_id_len",
        })
    })?;

    let consumed = tree_id_len.checked_add(leaf_id_len).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "get_tree_ids consumed",
        })
    })?;

    if rest.len() < consumed {
        return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
            "get_tree_ids: digest tail too short ({} < {})",
            rest.len(),
            consumed
        ))));
    }

    let tree_id_bytes = &rest[..tree_id_len];
    let leaf_id_bytes = &rest[tree_id_len..consumed];

    // Tree mask: all bits of a u64 when h_minus_hp == 64, else (1 << bits) - 1.
    let tree_id_mask: u64 = if h_minus_hp == 64 {
        u64::MAX
    } else if h_minus_hp == 0 {
        0
    } else {
        // Convert to u32 for the shift amount; we already validated < 64.
        let shift = u32::try_from(h_minus_hp).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "get_tree_ids: h-h' exceeds u32".to_owned(),
            ))
        })?;
        (1_u64 << shift) - 1
    };
    // Leaf mask: (1 << h_prime) - 1, with h_prime guaranteed < 64 above.
    let leaf_id_mask: u64 = if h_prime == 0 {
        0
    } else {
        let shift = u32::try_from(h_prime).map_err(|_| {
            CryptoError::Common(CommonError::Internal(
                "get_tree_ids: h_prime exceeds u32".to_owned(),
            ))
        })?;
        (1_u64 << shift) - 1
    };

    let tree_id_raw = bytes_to_u64_be(tree_id_bytes)?;
    let leaf_id_raw = bytes_to_u64_be(leaf_id_bytes)?;
    let tree_id = tree_id_raw & tree_id_mask;
    let leaf_id_masked = leaf_id_raw & leaf_id_mask;

    let leaf_id = u32::try_from(leaf_id_masked).map_err(|_| {
        CryptoError::Common(CommonError::Internal(
            "get_tree_ids: leaf_id does not fit in u32".to_owned(),
        ))
    })?;

    Ok((tree_id, leaf_id, consumed))
}

// ---------------------------------------------------------------------------
// Top-level SLH-DSA sign/verify (FIPS 205 §10, Algorithms 19 and 20)
// ---------------------------------------------------------------------------

/// Signs an already-encoded message per FIPS 205 Algorithm 19 (`slh_sign_internal`).
///
/// This is the raw signing primitive. Callers are responsible for supplying
/// the domain-separated encoded message (see [`msg_encode`]).
///
/// The algorithm proceeds as follows:
/// 1. Derive the per-signature random value `r` via `PRF_msg(SK.prf, opt_rand, M)`.
/// 2. Hash the message with `H_msg(r, PK.seed, PK.root, M)` to produce a
///    `m`-byte digest.
/// 3. Parse `(md_digest, tree_id, leaf_id)` from the digest.
/// 4. Sign `md_digest` with FORS (producing `k*(a+1)*n` bytes).
/// 5. Recompute the FORS public-key root from the FORS signature.
/// 6. Sign that root with the hypertree (producing `d * layer_bytes` bytes).
/// 7. Return `r || fors_sig || ht_sig`.
///
/// # Errors
/// * [`CryptoError::Key`] if the key lacks private material.
/// * [`CryptoError::Common(CommonError::InvalidArgument)`] if `opt_rand`
///   (when supplied) has the wrong length.
/// * Arithmetic and internal errors propagated from the building-block
///   functions (WOTS+, XMSS, FORS, hypertree).
fn slh_sign_internal(
    hctx: &SlhDsaHashCtx,
    msg: &[u8],
    opt_rand: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let key = hctx.key();
    let hash = hctx.hash_func();
    let params = hctx.params();

    if !key.has_key(KeySelection::PrivateOnly) {
        return Err(CryptoError::Key(
            "slh_sign_internal: key has no private material".to_owned(),
        ));
    }
    if !key.has_key(KeySelection::PublicOnly) {
        return Err(CryptoError::Key(
            "slh_sign_internal: key has no public material".to_owned(),
        ));
    }

    let n = params.n;
    let k = params.k;
    let a = params.a;
    let m = params.m;

    let sk_seed = key.sk_seed()?;
    let sk_prf = key.sk_prf()?;
    let pk_seed = key.pk_seed()?;
    let pk_root = key.pk_root()?;

    // Effective opt_rand: if absent, use PK.seed (deterministic signing).
    let opt_rand_effective: &[u8] = match opt_rand {
        Some(r) => {
            if r.len() != n {
                return Err(CryptoError::Common(CommonError::InvalidArgument(format!(
                    "slh_sign_internal: opt_rand length {} does not match n={}",
                    r.len(),
                    n
                ))));
            }
            r
        }
        None => pk_seed,
    };

    // Allocate signature buffer of exactly sig_len bytes.
    let sig_len = key.sig_len()?;
    let mut sig_out = vec![0_u8; sig_len];

    // md_len = ceil(k*a / 8). Use checked arithmetic.
    let k_mul_a = k.checked_mul(a).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_sign_internal k*a",
        })
    })?;
    let md_len = k_mul_a.checked_add(7).map(|v| v >> 3).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_sign_internal md_len",
        })
    })?;

    if m < md_len {
        return Err(CryptoError::Common(CommonError::Internal(
            "slh_sign_internal: parameter m < md_len".to_owned(),
        )));
    }

    // FORS signature size: k * (a + 1) * n bytes.
    let a_plus_one = a.checked_add(1).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_sign_internal a+1",
        })
    })?;
    let fors_sig_bytes = k
        .checked_mul(a_plus_one)
        .and_then(|v| v.checked_mul(n))
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "slh_sign_internal fors_sig_bytes",
            })
        })?;

    // r occupies the first n bytes of sig_out; FORS sig follows, then HT sig.
    let r_end = n;
    let fors_end = r_end.checked_add(fors_sig_bytes).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_sign_internal fors_end",
        })
    })?;

    if sig_out.len() < fors_end {
        return Err(CryptoError::Common(CommonError::Internal(
            "slh_sign_internal: signature buffer shorter than r+fors".to_owned(),
        )));
    }

    // Step 1: compute r = PRF_msg(SK.prf, opt_rand, M), write into sig_out[..n].
    hash.prf_msg(sk_prf, opt_rand_effective, msg, &mut sig_out[..r_end])?;

    // Step 2: compute message digest = H_msg(r, PK.seed, PK.root, M) into m bytes.
    // We must clone r because h_msg takes r by immutable borrow while writing
    // its output, and we are going to mutably borrow the FORS section of sig_out
    // in later steps; keeping r on the stack avoids any borrow conflict.
    let r_bytes: Vec<u8> = sig_out[..r_end].to_vec();
    let mut digest = vec![0_u8; m];
    hash.h_msg(&r_bytes, pk_seed, pk_root, msg, &mut digest)?;

    // Step 3: parse md_digest, tree_id, leaf_id.
    let md_digest = &digest[..md_len];
    let (tree_id, leaf_id, _consumed) = get_tree_ids(&digest[md_len..], params)?;

    // Step 4: set ADRS for top-level FORS signing.
    // FIPS 205 uses FORS_TREE (legacy alias = enum discriminant 3 = ForsPrf).
    let mut adrs = Adrs::new();
    adrs.zero();
    adrs.set_tree(tree_id);
    adrs.set_type(AdrsType::ForsPrf);
    adrs.set_keypair(leaf_id);

    // Step 5: write FORS signature into sig_out[r_end..fors_end].
    {
        let fors_slice = &mut sig_out[r_end..fors_end];
        ossl_slh_fors_sign(
            hash, md_digest, sk_seed, pk_seed, &mut adrs, params, fors_slice,
        )?;
    }

    // Step 6: reconstruct the FORS public-key root from the fresh signature.
    let mut pk_fors = vec![0_u8; n];
    {
        let fors_slice = &sig_out[r_end..fors_end];
        ossl_slh_fors_pk_from_sig(
            hash,
            fors_slice,
            md_digest,
            pk_seed,
            &mut adrs,
            params,
            &mut pk_fors,
        )?;
    }

    // Step 7: write hypertree signature into sig_out[fors_end..].
    {
        let ht_slice = &mut sig_out[fors_end..];
        ossl_slh_ht_sign(
            hash, &pk_fors, sk_seed, pk_seed, params, tree_id, leaf_id, ht_slice,
        )?;
    }

    Ok(sig_out)
}

/// Verifies an already-encoded SLH-DSA signature per FIPS 205 Algorithm 20
/// (`slh_verify_internal`).
///
/// This is the raw verification primitive. Callers are responsible for
/// reconstructing the encoded message (see [`msg_encode`]) and supplying it
/// as `msg`.
///
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on a structural
/// mismatch (including wrong length) or a cryptographic mismatch.
///
/// # Errors
/// * [`CryptoError::Key`] if the key lacks public material.
/// * Other errors are returned for genuinely unexpected internal failures
///   (e.g. arithmetic overflow on parameter-derived sizes). A cryptographic
///   verification failure is NOT an error — it returns `Ok(false)`.
fn slh_verify_internal(hctx: &SlhDsaHashCtx, msg: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    let key = hctx.key();
    let hash = hctx.hash_func();
    let params = hctx.params();

    if !key.has_key(KeySelection::PublicOnly) {
        return Err(CryptoError::Key(
            "slh_verify_internal: key has no public material".to_owned(),
        ));
    }

    let n = params.n;
    let k = params.k;
    let a = params.a;
    let m = params.m;

    let pk_seed = key.pk_seed()?;
    let pk_root = key.pk_root()?;

    // Early length check: sig length must equal the expected signature length
    // for this parameter set. A mismatch is a structural rejection.
    let expected_sig_len = key.sig_len()?;
    if sig.len() != expected_sig_len {
        return Ok(false);
    }

    // Recompute the layout.
    let k_mul_a = k.checked_mul(a).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_verify_internal k*a",
        })
    })?;
    let md_len = k_mul_a.checked_add(7).map(|v| v >> 3).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_verify_internal md_len",
        })
    })?;
    if m < md_len {
        return Err(CryptoError::Common(CommonError::Internal(
            "slh_verify_internal: parameter m < md_len".to_owned(),
        )));
    }

    let a_plus_one = a.checked_add(1).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_verify_internal a+1",
        })
    })?;
    let fors_sig_bytes = k
        .checked_mul(a_plus_one)
        .and_then(|v| v.checked_mul(n))
        .ok_or_else(|| {
            CryptoError::Common(CommonError::ArithmeticOverflow {
                operation: "slh_verify_internal fors_sig_bytes",
            })
        })?;

    let r_end = n;
    let fors_end = r_end.checked_add(fors_sig_bytes).ok_or_else(|| {
        CryptoError::Common(CommonError::ArithmeticOverflow {
            operation: "slh_verify_internal fors_end",
        })
    })?;

    if sig.len() < fors_end {
        return Ok(false);
    }

    // Step 1: extract r and recompute the message digest.
    let r_slice = &sig[..r_end];
    let mut digest = vec![0_u8; m];
    hash.h_msg(r_slice, pk_seed, pk_root, msg, &mut digest)?;

    // Step 2: parse md_digest, tree_id, leaf_id.
    let md_digest = &digest[..md_len];
    let (tree_id, leaf_id, _consumed) = get_tree_ids(&digest[md_len..], params)?;

    // Step 3: set ADRS for FORS verification.
    let mut adrs = Adrs::new();
    adrs.zero();
    adrs.set_tree(tree_id);
    adrs.set_type(AdrsType::ForsPrf);
    adrs.set_keypair(leaf_id);

    // Step 4: reconstruct FORS public-key root from the FORS signature.
    let fors_slice = &sig[r_end..fors_end];
    let mut pk_fors = vec![0_u8; n];
    ossl_slh_fors_pk_from_sig(
        hash,
        fors_slice,
        md_digest,
        pk_seed,
        &mut adrs,
        params,
        &mut pk_fors,
    )?;

    // Step 5: verify the hypertree signature over pk_fors.
    let ht_slice = &sig[fors_end..];
    ossl_slh_ht_verify(
        hash, &pk_fors, ht_slice, pk_seed, pk_root, params, tree_id, leaf_id,
    )
}

// ---------------------------------------------------------------------------
// Public API — SLH-DSA pure signing and verification (FIPS 205 §10.2)
// ---------------------------------------------------------------------------

/// Produces an SLH-DSA pure signature for `msg` with optional context string
/// `ctx` and optional additional randomness `add_rand`.
///
/// This is the top-level public signing API for SLH-DSA. It mirrors the C
/// function `ossl_slh_dsa_sign()` declared in `include/crypto/slh_dsa.h`.
///
/// # Arguments
/// * `hctx`   — a fully initialised hash context whose key contains both
///              public and private material.
/// * `msg`    — the raw message bytes to be signed.
/// * `ctx`    — the context string (`0..=255` bytes). Its length is
///              prepended during domain-separated encoding.
/// * `add_rand` — optional per-signature randomness (length `n`). If `None`,
///                deterministic signing is used (r derived from `PK.seed`).
/// * `encode` — when `true`, `msg`/`ctx` are wrapped in the pure-signing
///              prefix `0x00 || ctx_len || ctx || msg`. When `false`, the
///              message is signed verbatim (used by pre-hashed variants).
///
/// # Returns
/// An owned byte vector of exactly `params.sig_len` bytes: the serialised
/// SLH-DSA signature (`r || FORS sig || hypertree sig`).
///
/// # Errors
/// * [`CryptoError::Key`] if the key lacks required material.
/// * [`CryptoError::Common(CommonError::InvalidArgument)`] if `ctx` exceeds
///   [`SLH_DSA_MAX_CONTEXT_STRING_LEN`] or if `add_rand` has the wrong length.
/// * Arithmetic errors propagated from building-block operations.
///
/// # Rule compliance
/// * Rule R5: Returns `CryptoResult<Vec<u8>>`; no sentinel values.
/// * Rule R6: All size arithmetic uses `checked_*` operations.
/// * Rule R7: Takes the context by immutable reference; no shared mutable state.
/// * Rule R8: Contains zero `unsafe` code.
/// * Rule R10: Reachable via `openssl_crypto::pqc::slh_dsa::slh_dsa_sign`.
pub fn slh_dsa_sign(
    hctx: &SlhDsaHashCtx,
    msg: &[u8],
    ctx: &[u8],
    add_rand: Option<&[u8]>,
    encode: bool,
) -> CryptoResult<Vec<u8>> {
    let encoded_msg = msg_encode(msg, ctx, encode)?;
    slh_sign_internal(hctx, &encoded_msg, add_rand)
}

/// Verifies an SLH-DSA pure signature.
///
/// This is the top-level public verification API for SLH-DSA. It mirrors the
/// C function `ossl_slh_dsa_verify()` declared in `include/crypto/slh_dsa.h`.
///
/// # Arguments
/// * `hctx`   — a fully initialised hash context whose key contains public
///              material (private material is not required for verification).
/// * `msg`    — the raw message bytes that were signed.
/// * `ctx`    — the context string (`0..=255` bytes). Must exactly match
///              the context used at signing time.
/// * `encode` — must be `true` for pure-signing verification; `false` is
///              supported for pre-hashed variants.
/// * `sig`    — the candidate signature bytes (must be exactly
///              `params.sig_len` bytes long; mismatched lengths are
///              rejected as `Ok(false)`).
///
/// # Returns
/// * `Ok(true)`  — the signature is valid for `(msg, ctx)` under the key.
/// * `Ok(false)` — the signature is structurally or cryptographically invalid.
/// * `Err(..)`   — only for genuinely unexpected internal failures
///                 (e.g. the key has no public material, or an arithmetic
///                 overflow on parameter-derived sizes).
///
/// # Rule compliance
/// * Rule R5: Returns `CryptoResult<bool>`; no sentinel values. A failed
///   verification returns `Ok(false)`, not an error.
/// * Rule R6: All size arithmetic uses `checked_*` operations.
/// * Rule R7: Takes the context by immutable reference; no shared mutable state.
/// * Rule R8: Contains zero `unsafe` code.
/// * Rule R10: Reachable via `openssl_crypto::pqc::slh_dsa::slh_dsa_verify`.
pub fn slh_dsa_verify(
    hctx: &SlhDsaHashCtx,
    msg: &[u8],
    ctx: &[u8],
    encode: bool,
    sig: &[u8],
) -> CryptoResult<bool> {
    let encoded_msg = msg_encode(msg, ctx, encode)?;
    slh_verify_internal(hctx, &encoded_msg, sig)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::int_plus_one,
    clippy::uninlined_format_args,
    clippy::items_after_statements,
    reason = "Tests exercise fallible APIs with known-good inputs and assert on panic / \
              unwrap failure. `unwrap`, `expect`, and `panic` are idiomatic in Rust test \
              harnesses — the workspace policy denies them in library code but allows \
              them in tests when annotated with this documented justification."
)]
mod tests {
    //! Internal unit tests for the SLH-DSA implementation.
    //!
    //! Coverage:
    //!   * Parameter-set table (all 12 FIPS 205 sets, size invariants).
    //!   * Algorithm-name lookup and reverse-lookup round-trips.
    //!   * ADRS byte-layout encoding (big-endian, keypair copy, compression).
    //!   * Variant <-> string conversions.
    //!   * `SlhHashFunc` dispatch selection.
    //!   * `SlhDsaKey` construction, seed ingestion, equality, has-key states,
    //!     duplication, and size accessors.
    //!   * End-to-end keygen -> sign -> verify round-trip for the fastest
    //!     SLH-DSA parameter set (`SLH-DSA-SHAKE-128f`).
    //!   * Tamper detection: signature bit-flips, message changes, context
    //!     changes, and signature-length mismatches all cause verification
    //!     to return `Ok(false)`.

    use super::*;

    // -----------------------------------------------------------------------
    // Parameter-set table
    // -----------------------------------------------------------------------

    #[test]
    fn parameter_table_has_all_twelve_variants() {
        assert_eq!(SLH_DSA_PARAMS_TABLE.len(), 12);
        let mut names: Vec<&str> = SLH_DSA_PARAMS_TABLE.iter().map(|p| p.alg).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            12,
            "duplicate algorithm names in parameter table"
        );
    }

    #[test]
    fn parameter_lookup_by_name() {
        for params in SLH_DSA_PARAMS_TABLE {
            let looked_up = slh_dsa_params_get(params.alg).expect("must find every entry");
            assert_eq!(looked_up.alg, params.alg);
            assert_eq!(looked_up.variant, params.variant);
            assert_eq!(looked_up.n, params.n);
            assert_eq!(looked_up.sig_len, params.sig_len);
        }
    }

    #[test]
    fn parameter_lookup_unknown_returns_none() {
        assert!(slh_dsa_params_get("SLH-DSA-BOGUS-1234").is_none());
        assert!(slh_dsa_params_get("").is_none());
        assert!(slh_dsa_params_get("slh-dsa-sha2-128s").is_none()); // case-sensitive
    }

    #[test]
    fn parameter_sets_match_fips_205_sizes() {
        // Selected representative entries from FIPS 205 Tables 2-4.
        let s128s = slh_dsa_params_get("SLH-DSA-SHA2-128s").unwrap();
        assert_eq!(s128s.n, 16);
        assert_eq!(s128s.h, 63);
        assert_eq!(s128s.d, 7);
        assert_eq!(s128s.h_prime, 9);
        assert_eq!(s128s.a, 12);
        assert_eq!(s128s.k, 14);
        assert_eq!(s128s.m, 30);
        assert_eq!(s128s.security_category, 1);
        assert_eq!(s128s.pub_len, 32);
        assert_eq!(s128s.sig_len, 7856);
        assert_eq!(s128s.sha2_h_t_bound, 64);

        let s256f = slh_dsa_params_get("SLH-DSA-SHA2-256f").unwrap();
        assert_eq!(s256f.n, 32);
        assert_eq!(s256f.h, 68);
        assert_eq!(s256f.d, 17);
        assert_eq!(s256f.h_prime, 4);
        assert_eq!(s256f.a, 9);
        assert_eq!(s256f.k, 35);
        assert_eq!(s256f.m, 49);
        assert_eq!(s256f.security_category, 5);
        assert_eq!(s256f.pub_len, 64);
        assert_eq!(s256f.sig_len, 49856);
        assert_eq!(s256f.sha2_h_t_bound, 128);

        let shake128f = slh_dsa_params_get("SLH-DSA-SHAKE-128f").unwrap();
        assert!(shake128f.is_shake);
        assert_eq!(shake128f.sha2_h_t_bound, 0);
        assert_eq!(shake128f.sig_len, 17088);

        let shake256s = slh_dsa_params_get("SLH-DSA-SHAKE-256s").unwrap();
        assert!(shake256s.is_shake);
        assert_eq!(shake256s.security_category, 5);
        assert_eq!(shake256s.sig_len, 29792);
    }

    #[test]
    fn pub_len_always_equals_two_n() {
        for params in SLH_DSA_PARAMS_TABLE {
            assert_eq!(params.pub_len, 2 * params.n);
        }
    }

    // -----------------------------------------------------------------------
    // Variant enum & algorithm-name round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn variant_algorithm_names_are_stable() {
        use SlhDsaVariant::*;
        assert_eq!(Sha2_128s.algorithm_name(), "SLH-DSA-SHA2-128s");
        assert_eq!(Shake_128s.algorithm_name(), "SLH-DSA-SHAKE-128s");
        assert_eq!(Sha2_128f.algorithm_name(), "SLH-DSA-SHA2-128f");
        assert_eq!(Shake_128f.algorithm_name(), "SLH-DSA-SHAKE-128f");
        assert_eq!(Sha2_192s.algorithm_name(), "SLH-DSA-SHA2-192s");
        assert_eq!(Shake_192s.algorithm_name(), "SLH-DSA-SHAKE-192s");
        assert_eq!(Sha2_192f.algorithm_name(), "SLH-DSA-SHA2-192f");
        assert_eq!(Shake_192f.algorithm_name(), "SLH-DSA-SHAKE-192f");
        assert_eq!(Sha2_256s.algorithm_name(), "SLH-DSA-SHA2-256s");
        assert_eq!(Shake_256s.algorithm_name(), "SLH-DSA-SHAKE-256s");
        assert_eq!(Sha2_256f.algorithm_name(), "SLH-DSA-SHA2-256f");
        assert_eq!(Shake_256f.algorithm_name(), "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn variant_from_str_round_trip() {
        for params in SLH_DSA_PARAMS_TABLE {
            let v = SlhDsaVariant::try_from(params.alg).expect("known algorithm must convert");
            assert_eq!(v, params.variant);
            assert_eq!(v.algorithm_name(), params.alg);
        }
    }

    #[test]
    fn variant_from_str_rejects_unknown() {
        assert!(SlhDsaVariant::try_from("").is_err());
        assert!(SlhDsaVariant::try_from("slh-dsa-sha2-128s").is_err()); // case-sensitive
        assert!(SlhDsaVariant::try_from("SLH-DSA-INVALID").is_err());
    }

    // -----------------------------------------------------------------------
    // ADRS byte layout
    // -----------------------------------------------------------------------

    #[test]
    fn adrs_default_is_zeroed() {
        let adrs = Adrs::default();
        assert_eq!(adrs.compressed(), [0_u8; ADRS_SIZE_COMPRESSED]);
    }

    #[test]
    fn adrs_set_layer_encodes_big_endian() {
        let mut adrs = Adrs::new();
        adrs.set_layer(0x1234_5678);
        let full = adrs.uncompressed();
        assert_eq!(&full[..4], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn adrs_set_tree_encodes_big_endian_in_lower_8_bytes() {
        let mut adrs = Adrs::new();
        adrs.set_tree(0x01_02_03_04_05_06_07_08);
        let full = adrs.uncompressed();
        // Upper 4 bytes of tree address are always zero
        assert_eq!(&full[4..8], &[0, 0, 0, 0]);
        // Lower 8 bytes encode the tree value in big-endian
        assert_eq!(
            &full[8..16],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn adrs_set_type_and_keypair_encode_at_correct_offsets() {
        let mut adrs = Adrs::new();
        adrs.set_type(AdrsType::Tree);
        adrs.set_keypair(0xAABB_CCDD);
        let full = adrs.uncompressed();
        assert_eq!(&full[16..20], &[0, 0, 0, 2]); // Tree = 2
        assert_eq!(&full[20..24], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn adrs_set_chain_hash_tree_height_tree_index_share_last_8_bytes() {
        let mut adrs = Adrs::new();
        adrs.set_chain(0x11223344);
        adrs.set_hash(0x55667788);
        let full = adrs.uncompressed();
        assert_eq!(&full[24..28], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&full[28..32], &[0x55, 0x66, 0x77, 0x88]);

        // set_tree_height/set_tree_index alias chain/hash on the wire.
        let mut adrs2 = Adrs::new();
        adrs2.set_tree_height(0xDEADBEEF);
        adrs2.set_tree_index(0xCAFEBABE);
        let full2 = adrs2.uncompressed();
        assert_eq!(&full2[24..28], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&full2[28..32], &[0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn adrs_copy_keypair_copies_only_keypair_field() {
        // Mirrors C `copy_keypair_address()` from crypto/slh_dsa/slh_adrs.c,
        // which copies exactly the 4-byte keypair_address field (offset 20..24)
        // and nothing else.
        let mut src = Adrs::new();
        src.set_layer(0x12345678);
        src.set_tree(0xAAAA_BBBB_CCCC_DDDD);
        src.set_type(AdrsType::ForsPrf);
        src.set_keypair(0x11223344);
        src.set_chain(0xFFEEDDCC);
        src.set_hash(0xBBAA9988);

        let mut dst = Adrs::new();
        dst.set_layer(0x01020304); // Distinct so we can prove it's preserved
        dst.set_tree(0x0A0B0C0D_01020304);
        dst.set_type(AdrsType::Tree);
        dst.set_chain(0xDEADBEEF);
        dst.set_hash(0xCAFEBABE);
        dst.copy_keypair(&src);

        let s = src.uncompressed();
        let d = dst.uncompressed();

        // Keypair (bytes 20..24) MUST match src.
        assert_eq!(&d[20..24], &s[20..24]);
        // Everything else MUST be unchanged from dst's pre-copy state.
        assert_eq!(&d[..4], &[0x01, 0x02, 0x03, 0x04]); // layer unchanged
        assert_eq!(
            &d[4..16],
            &[0, 0, 0, 0, 0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(&d[16..20], &[0, 0, 0, 2]); // type = Tree, unchanged
        assert_eq!(&d[24..28], &[0xDE, 0xAD, 0xBE, 0xEF]); // chain unchanged
        assert_eq!(&d[28..32], &[0xCA, 0xFE, 0xBA, 0xBE]); // hash unchanged
    }

    #[test]
    fn adrs_compressed_is_22_bytes_and_contains_expected_fields() {
        let mut adrs = Adrs::new();
        adrs.set_layer(0xAA);
        adrs.set_tree(0xBBBB_CCCC_DDDD_EEEE);
        adrs.set_type(AdrsType::ForsRoots);
        adrs.set_keypair(0x11223344);
        adrs.set_tree_height(0x55667788);
        adrs.set_tree_index(0x99AABBCC);

        let c = adrs.compressed();
        assert_eq!(c.len(), ADRS_SIZE_COMPRESSED);
        assert_eq!(ADRS_SIZE_COMPRESSED, 22);
        // Layer LSB lives in byte 0 in the compressed form.
        assert_eq!(c[0], 0xAA);
        // Tree LSBs occupy bytes 1..9 (8 bytes).
        assert_eq!(&c[1..9], &[0xBB, 0xBB, 0xCC, 0xCC, 0xDD, 0xDD, 0xEE, 0xEE]);
        // Type LSB lives in byte 9.
        assert_eq!(c[9], 4); // ForsRoots = 4
                             // Keypair bytes 10..14.
        assert_eq!(&c[10..14], &[0x11, 0x22, 0x33, 0x44]);
        // Tree-height / hash bytes 14..18.
        assert_eq!(&c[14..18], &[0x55, 0x66, 0x77, 0x88]);
        // Tree-index / chain bytes 18..22.
        assert_eq!(&c[18..22], &[0x99, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn adrs_type_discriminants_match_fips_205() {
        assert_eq!(AdrsType::WotsHash as u32, 0);
        assert_eq!(AdrsType::WotsPk as u32, 1);
        assert_eq!(AdrsType::Tree as u32, 2);
        assert_eq!(AdrsType::ForsPrf as u32, 3);
        assert_eq!(AdrsType::ForsRoots as u32, 4);
        assert_eq!(AdrsType::ForsPk as u32, 5);
        assert_eq!(AdrsType::WotsSign as u32, 6);
    }

    // -----------------------------------------------------------------------
    // Hash-function dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn hash_dispatch_selects_shake_for_shake_params() {
        let params = slh_dsa_params_get("SLH-DSA-SHAKE-128f").unwrap();
        let hf = get_hash_func(params);
        // Smoke-test: the trait object can execute `prf`.
        let pk_seed = [0_u8; 16];
        let sk_seed = [0_u8; 16];
        let adrs = Adrs::new();
        let mut out = [0_u8; 16];
        hf.prf(&pk_seed, &sk_seed, &adrs, &mut out)
            .expect("SHAKE prf must succeed");
    }

    #[test]
    fn hash_dispatch_selects_sha2_for_sha2_params() {
        let params = slh_dsa_params_get("SLH-DSA-SHA2-128f").unwrap();
        let hf = get_hash_func(params);
        let pk_seed = [1_u8; 16];
        let sk_seed = [2_u8; 16];
        let adrs = Adrs::new();
        let mut out = [0_u8; 16];
        hf.prf(&pk_seed, &sk_seed, &adrs, &mut out)
            .expect("SHA-2 prf must succeed");
        // Assert non-zero output (extremely unlikely to be all-zero for
        // non-degenerate inputs).
        assert!(out.iter().any(|&b| b != 0));
    }

    // -----------------------------------------------------------------------
    // Key state & accessors
    // -----------------------------------------------------------------------

    #[test]
    fn key_new_has_no_material() {
        let libctx = LibContext::new();
        let key = SlhDsaKey::new(libctx, "SLH-DSA-SHAKE-128f").expect("must construct");
        assert!(!key.has_key(KeySelection::PublicOnly));
        assert!(!key.has_key(KeySelection::PrivateOnly));
        assert_eq!(key.algorithm_name(), "SLH-DSA-SHAKE-128f");
        assert_eq!(key.pub_len().unwrap(), 32);
        assert_eq!(key.priv_len().unwrap(), 64);
        assert_eq!(key.sig_len().unwrap(), 17088);
        assert_eq!(key.n().unwrap(), 16);
        assert_eq!(key.security_category().unwrap(), 1);
    }

    #[test]
    fn key_new_unknown_algorithm_is_rejected() {
        let libctx = LibContext::new();
        let err = SlhDsaKey::new(libctx, "SLH-DSA-UNKNOWN").expect_err("must fail");
        match err {
            CryptoError::AlgorithmNotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn key_set_pub_round_trip_matches_bytes() {
        let libctx = LibContext::new();
        let mut key = SlhDsaKey::new(libctx, "SLH-DSA-SHAKE-128f").unwrap();
        // Synthetic 2n-byte public (PK.seed || PK.root).
        let pk_bytes: Vec<u8> = (0..32_u8).collect();
        key.set_pub(&pk_bytes).unwrap();
        assert!(key.has_key(KeySelection::PublicOnly));
        assert!(!key.has_key(KeySelection::PrivateOnly));
        assert_eq!(key.pk_seed().unwrap(), &pk_bytes[..16]);
        assert_eq!(key.pk_root().unwrap(), &pk_bytes[16..]);
    }

    #[test]
    fn key_set_priv_round_trip_matches_bytes() {
        let libctx = LibContext::new();
        let mut key = SlhDsaKey::new(libctx, "SLH-DSA-SHAKE-128f").unwrap();
        // Synthetic 4n-byte private (SK.seed || SK.prf || PK.seed || PK.root).
        let priv_bytes: Vec<u8> = (0..64_u8).collect();
        key.set_priv(&priv_bytes).unwrap();
        assert!(key.has_key(KeySelection::PrivateOnly));
        assert!(key.has_key(KeySelection::PublicOnly));
        assert_eq!(key.sk_seed().unwrap(), &priv_bytes[..16]);
        assert_eq!(key.sk_prf().unwrap(), &priv_bytes[16..32]);
        assert_eq!(key.pk_seed().unwrap(), &priv_bytes[32..48]);
        assert_eq!(key.pk_root().unwrap(), &priv_bytes[48..]);
    }

    #[test]
    fn key_set_pub_rejects_wrong_length() {
        let libctx = LibContext::new();
        let mut key = SlhDsaKey::new(libctx, "SLH-DSA-SHAKE-128f").unwrap();
        assert!(key.set_pub(&[0_u8; 16]).is_err()); // too short
        assert!(key.set_pub(&[0_u8; 48]).is_err()); // too long
    }

    #[test]
    fn key_equal_constant_time_matches_value() {
        let libctx1 = LibContext::new();
        let libctx2 = LibContext::new();
        let mut k1 = SlhDsaKey::new(libctx1, "SLH-DSA-SHAKE-128f").unwrap();
        let mut k2 = SlhDsaKey::new(libctx2, "SLH-DSA-SHAKE-128f").unwrap();

        let pk_bytes: Vec<u8> = (100..132_u8).collect();
        k1.set_pub(&pk_bytes).unwrap();
        k2.set_pub(&pk_bytes).unwrap();
        assert!(k1.equal(&k2, KeySelection::PublicOnly));

        // Change one byte and re-check.
        let mut pk_bytes_alt = pk_bytes.clone();
        pk_bytes_alt[0] ^= 0x01;
        let libctx3 = LibContext::new();
        let mut k3 = SlhDsaKey::new(libctx3, "SLH-DSA-SHAKE-128f").unwrap();
        k3.set_pub(&pk_bytes_alt).unwrap();
        assert!(!k1.equal(&k3, KeySelection::PublicOnly));
    }

    #[test]
    fn key_dup_preserves_material() {
        let libctx = LibContext::new();
        let mut k = SlhDsaKey::new(libctx, "SLH-DSA-SHAKE-128f").unwrap();
        let priv_bytes: Vec<u8> = (0..64_u8).collect();
        k.set_priv(&priv_bytes).unwrap();

        let d = k.dup(KeySelection::KeyPair).unwrap();
        assert_eq!(d.sk_seed().unwrap(), k.sk_seed().unwrap());
        assert_eq!(d.sk_prf().unwrap(), k.sk_prf().unwrap());
        assert_eq!(d.pk_seed().unwrap(), k.pk_seed().unwrap());
        assert_eq!(d.pk_root().unwrap(), k.pk_root().unwrap());

        // Public-only duplication should not carry private material.
        let pub_only = k.dup(KeySelection::PublicOnly).unwrap();
        assert!(pub_only.has_key(KeySelection::PublicOnly));
        assert!(!pub_only.has_key(KeySelection::PrivateOnly));
    }

    // -----------------------------------------------------------------------
    // Hash-context construction
    // -----------------------------------------------------------------------

    #[test]
    fn hash_ctx_new_and_dup_succeed() {
        let libctx = LibContext::new();
        let key =
            Arc::new(SlhDsaKey::new(libctx, "SLH-DSA-SHAKE-128f").expect("construct key shell"));
        let initial_strong = Arc::strong_count(&key);
        let ctx = SlhDsaHashCtx::new(key.clone()).expect("ctx construction must succeed");
        assert_eq!(ctx.params().alg, "SLH-DSA-SHAKE-128f");
        // `SlhDsaHashCtx::new` must clone the `Arc<SlhDsaKey>` (not move it),
        // so the strong-count of the original `key` Arc grows by exactly one.
        assert!(Arc::strong_count(&key) >= initial_strong + 1);

        let dup = ctx.dup().expect("dup must succeed");
        assert_eq!(dup.params().alg, "SLH-DSA-SHAKE-128f");
        // Dup should share the same algorithm metadata.
        assert_eq!(dup.params().n, ctx.params().n);
    }

    // -----------------------------------------------------------------------
    // End-to-end round-trip (fastest parameter set: SHAKE-128f).
    // -----------------------------------------------------------------------

    /// Deterministic entropy for key-generation reproducibility in tests.
    fn det_entropy(byte: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| byte.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn end_to_end_sign_verify_round_trip_shake_128f() {
        let libctx = LibContext::new();
        let entropy = det_entropy(0xA5, 3 * 16); // 3n for n=16
        let key = SlhDsaKey::generate_with_entropy(libctx, "SLH-DSA-SHAKE-128f", &entropy)
            .expect("keygen with entropy must succeed");

        // Pairwise check: re-derive PK.root from SK.seed/PK.seed and match stored.
        assert!(key.pairwise_check().expect("pairwise must succeed"));

        let hctx = SlhDsaHashCtx::new(Arc::new(key)).unwrap();
        let msg = b"SLH-DSA round-trip test vector";
        let ctx = b"test-context";

        let sig = slh_dsa_sign(&hctx, msg, ctx, None, true).expect("sign must succeed");
        assert_eq!(sig.len(), hctx.params().sig_len);

        let ok = slh_dsa_verify(&hctx, msg, ctx, true, &sig).expect("verify must succeed");
        assert!(ok, "valid signature must verify Ok(true)");
    }

    #[test]
    fn verify_detects_tampered_signature() {
        let libctx = LibContext::new();
        let entropy = det_entropy(0x42, 3 * 16);
        let key = SlhDsaKey::generate_with_entropy(libctx, "SLH-DSA-SHAKE-128f", &entropy)
            .expect("keygen with entropy must succeed");

        let hctx = SlhDsaHashCtx::new(Arc::new(key)).unwrap();
        let msg = b"tamper-detection input";
        let ctx: &[u8] = &[];
        let mut sig = slh_dsa_sign(&hctx, msg, ctx, None, true).unwrap();

        // Flip one bit in the middle of the signature and expect Ok(false).
        let mid = sig.len() / 2;
        sig[mid] ^= 0x80;
        let ok = slh_dsa_verify(&hctx, msg, ctx, true, &sig).expect("verify must not error");
        assert!(!ok, "tampered signature must verify as Ok(false)");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let libctx = LibContext::new();
        let entropy = det_entropy(0x33, 3 * 16);
        let key = SlhDsaKey::generate_with_entropy(libctx, "SLH-DSA-SHAKE-128f", &entropy)
            .expect("keygen with entropy must succeed");

        let hctx = SlhDsaHashCtx::new(Arc::new(key)).unwrap();
        let msg = b"original";
        let ctx: &[u8] = b"";
        let sig = slh_dsa_sign(&hctx, msg, ctx, None, true).unwrap();

        let tampered = b"modified";
        let ok = slh_dsa_verify(&hctx, tampered, ctx, true, &sig).unwrap();
        assert!(!ok, "wrong message must verify as Ok(false)");
    }

    #[test]
    fn verify_rejects_wrong_context() {
        let libctx = LibContext::new();
        let entropy = det_entropy(0x91, 3 * 16);
        let key = SlhDsaKey::generate_with_entropy(libctx, "SLH-DSA-SHAKE-128f", &entropy)
            .expect("keygen with entropy must succeed");

        let hctx = SlhDsaHashCtx::new(Arc::new(key)).unwrap();
        let msg: &[u8] = b"message";
        let sig = slh_dsa_sign(&hctx, msg, b"ctx-A", None, true).unwrap();

        let ok = slh_dsa_verify(&hctx, msg, b"ctx-B", true, &sig).unwrap();
        assert!(!ok, "different context must verify as Ok(false)");
    }

    #[test]
    fn verify_rejects_signature_of_wrong_length() {
        let libctx = LibContext::new();
        let entropy = det_entropy(0x55, 3 * 16);
        let key = SlhDsaKey::generate_with_entropy(libctx, "SLH-DSA-SHAKE-128f", &entropy)
            .expect("keygen with entropy must succeed");

        let hctx = SlhDsaHashCtx::new(Arc::new(key)).unwrap();
        let msg: &[u8] = b"short-length test";

        // Too-short signature.
        let tiny_sig = vec![0_u8; 100];
        let ok = slh_dsa_verify(&hctx, msg, b"", true, &tiny_sig).unwrap();
        assert!(!ok, "too-short signature must verify as Ok(false)");

        // Too-long signature (exactly sig_len + 1).
        let long_sig = vec![0_u8; hctx.params().sig_len + 1];
        let ok = slh_dsa_verify(&hctx, msg, b"", true, &long_sig).unwrap();
        assert!(!ok, "too-long signature must verify as Ok(false)");
    }

    #[test]
    fn verify_rejects_signature_from_different_key() {
        let libctx_a = LibContext::new();
        let libctx_b = LibContext::new();
        let entropy_a = det_entropy(0x11, 3 * 16);
        let entropy_b = det_entropy(0x22, 3 * 16);

        let key_a =
            SlhDsaKey::generate_with_entropy(libctx_a, "SLH-DSA-SHAKE-128f", &entropy_a).unwrap();
        let key_b =
            SlhDsaKey::generate_with_entropy(libctx_b, "SLH-DSA-SHAKE-128f", &entropy_b).unwrap();

        let hctx_a = SlhDsaHashCtx::new(Arc::new(key_a)).unwrap();
        let hctx_b = SlhDsaHashCtx::new(Arc::new(key_b)).unwrap();

        let msg: &[u8] = b"key-binding test";
        let sig = slh_dsa_sign(&hctx_a, msg, b"", None, true).unwrap();

        let ok = slh_dsa_verify(&hctx_b, msg, b"", true, &sig).unwrap();
        assert!(!ok, "signature from different key must not verify");
    }

    #[test]
    fn deterministic_signing_produces_identical_signatures() {
        let libctx = LibContext::new();
        let entropy = det_entropy(0x77, 3 * 16);
        let key = SlhDsaKey::generate_with_entropy(libctx, "SLH-DSA-SHAKE-128f", &entropy)
            .expect("keygen with entropy must succeed");

        let hctx = SlhDsaHashCtx::new(Arc::new(key)).unwrap();
        let msg: &[u8] = b"deterministic";
        // When `add_rand` is `None`, FIPS 205 mandates `R = PRF_msg(SK.prf, 0^n, M')`,
        // which is fully deterministic. Two independent sign calls must produce
        // identical signatures.
        let sig1 = slh_dsa_sign(&hctx, msg, b"", None, true).unwrap();
        let sig2 = slh_dsa_sign(&hctx, msg, b"", None, true).unwrap();
        assert_eq!(sig1, sig2);
    }
}
